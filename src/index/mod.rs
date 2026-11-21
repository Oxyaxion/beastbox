//! In-memory search index, per user (§0.4, §0.5, §8 item 4).
//!
//! - **Built on first use** (first search), never at startup; **evicted** after inactivity.
//! - **Compact**: names are stored per folder (one name per entry, no full path); each folder is a
//!   slot of an arena, and its name is read from its parent's entry.
//! - **Kept up to date by the server's writes**: `journaled` (every write goes through it) only rereads the touched
//!   parent folders. A moved folder is found again by its identity (`fileid`): its contents are not reread.
//! - **Safety net**: the index remembers the root's ETag after each update; if it differs at search time
//!   (`rescan`, change outside the application, concurrent write), the index is rebuilt.
//! - **Bounded**: at most 1,000,000 entries per tenant (all users combined); beyond that, incomplete index flagged.

use crate::fs::{FileId, Root, SafePath};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Maximum entries indexed per tenant (≈ 88 bytes each: ~80 MB for the 1 million file target, §0.5).
pub const TENANT_MAX: usize = 1_000_000;
/// Maximum results returned per search.
pub const LIMIT: usize = 200;
/// Inactivity after which a user's index is freed.
pub const IDLE: Duration = Duration::from_secs(15 * 60);

const NONE: u32 = u32::MAX;

struct Entry {
    name: Box<str>,
    size: u64,
    mtime: i64,
    /// Last activity (`Meta::ctime`).
    ctime: i64,
    /// `oc:fileid` (`etag::fileid`), for the clients' thumbnails (`core/preview?fileId=`).
    fileid: u64,
    /// Slot of the folder, or `NONE` for a file.
    dir: u32,
    tags: Box<[Box<str>]>,
    favorite: bool,
}

struct Dir {
    parent: u32,
    entries: Vec<Entry>,
    live: bool,
}

struct UserIndex {
    /// Slot 0: the user's root.
    dirs: Vec<Dir>,
    free: Vec<u32>,
    by_id: HashMap<FileId, u32>,
    root_etag: Option<[u8; 16]>,
    entries: usize,
    cap: usize,
    truncated: bool,
}

/// A search result.
#[derive(Debug, Clone)]
pub struct Hit {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: i64,
    /// Last activity (`Meta::ctime`).
    pub ctime: i64,
    pub tags: Vec<String>,
    pub favorite: bool,
}

#[derive(Debug, Default)]
pub struct Found {
    pub hits: Vec<Hit>,
    /// More than `LIMIT` results: only the first ones are returned.
    pub more: bool,
    /// Index stopped at the tenant's cap: files are missing.
    pub incomplete: bool,
}

/// Query: every word in the name (case, accents and punctuation ignored), every pattern (`*.md`), every `tag:x`, the
/// filters `type:`, `is:fav`,
/// `after:` and `before:`, and those of the Nextcloud clients' WebDAV search (`dav::search`).
#[derive(Debug, Default)]
pub struct Query {
    /// Folded (`fold`), letters and digits only.
    pub words: Vec<String>,
    /// Folded, matched against the whole name: `*` any run of characters, `?` one (`glob`).
    pub globs: Vec<String>,
    /// Folded.
    pub tags: Vec<String>,
    /// Favorites only.
    pub favorites: bool,
    /// Modified strictly after / before (Unix seconds).
    pub after: Option<i64>,
    pub before: Option<i64>,
    pub dirs_only: bool,
    /// Files whose name passes this filter (type deduced from the extension, by the caller).
    pub files_named: Option<Named>,
    /// Newest first: the `LIMIT` newest of the whole space, not the first ones found.
    pub newest: bool,
    /// "Newest" by last activity (`ctime`: added, changed, moved, tagged) instead of the modification date.
    pub by_activity: bool,
    /// Only inside this folder (its subfolders included).
    pub under: Option<SafePath>,
    /// Only the entry with this `oc:fileid`.
    /// shortcut: a full scan of the user's index per lookup (a few ms at 1 M entries); add a map if it shows up in the metrics.
    pub fileid: Option<u64>,
}

/// Filter on file names.
pub type Named = fn(&str) -> bool;

/// `type:` values. `folder` is handled apart (`dirs_only`).
pub const TYPES: [(&str, Named); 7] = [
    ("image", |n| crate::web::render::icon(n, false) == "image"),
    ("video", |n| crate::web::render::icon(n, false) == "video"),
    ("audio", |n| crate::web::render::icon(n, false) == "audio"),
    ("pdf", |n| crate::web::render::icon(n, false) == "pdf"),
    ("doc", |n| {
        matches!(crate::web::render::icon(n, false), "doc" | "sheet" | "md" | "text")
    }),
    ("archive", |n| crate::web::render::icon(n, false) == "archive"),
    ("code", |n| {
        matches!(crate::web::render::icon(n, false), "code" | "json")
    }),
];

impl Query {
    /// Unknown or invalid operators (`after:hier`, `12:30`) are searched as words.
    pub fn parse(q: &str) -> Self {
        let mut out = Self::default();
        for w in q.split_whitespace().take(16) {
            let (op, v) = w.split_once(':').unwrap_or(("", w));
            let date = || crate::web::render::period_start(v);
            match op {
                "tag" => out.tags.extend(crate::fs::normalize_tag(v).map(|t| fold(&t))),
                "type" if v == "folder" => out.dirs_only = true,
                "type" if TYPES.iter().any(|t| t.0 == v) => {
                    out.files_named = TYPES.iter().find(|t| t.0 == v).map(|t| t.1)
                }
                "is" if v == "fav" => out.favorites = true,
                "after" if date().is_some() => out.after = date().map(|t| t - 1),
                "before" if date().is_some() => out.before = date(),
                _ if let Some(g) = pattern(w) => out.globs.push(g),
                _ => out.words.extend(
                    fold(w)
                        .split(|c: char| !c.is_alphanumeric())
                        .filter(|x| !x.is_empty())
                        .map(str::to_owned),
                ),
            }
        }
        out
    }
    /// All of the user's favorites.
    pub fn favorites() -> Self {
        Self {
            favorites: true,
            ..Self::default()
        }
    }
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
            && self.globs.is_empty()
            && self.tags.is_empty()
            && !self.favorites
            && self.after.is_none()
            && self.before.is_none()
            && !self.dirs_only
            && self.files_named.is_none()
            && self.fileid.is_none()
    }
    /// `None`: `e` does not pass. Otherwise its rank: 0, the name without its extension is exactly the words; 1, every
    /// word starts a word of the name; 2, elsewhere. The name is folded once, and only if the cheap filters pass.
    fn score(&self, e: &Entry) -> Option<u8> {
        let pass = self.fileid.is_none_or(|f| e.fileid == f)
            && (!self.favorites || e.favorite)
            && self.after.is_none_or(|a| e.mtime > a)
            && self.before.is_none_or(|b| e.mtime < b)
            && (!self.dirs_only || e.dir != NONE)
            && self.files_named.is_none_or(|f| e.dir == NONE && f(&e.name))
            && self.tags.iter().all(|t| e.tags.iter().any(|x| folded_eq(x, t)));
        if !pass {
            return None;
        }
        if self.words.is_empty() && self.globs.is_empty() {
            return Some(0);
        }
        // Words, and the fixed parts of the patterns (".md" of "*.md"): a cheap first filter.
        let mut parts = self
            .words
            .iter()
            .map(String::as_str)
            .chain(self.globs.iter().flat_map(|g| g.split(['*', '?'])))
            .filter(|p| !p.is_empty());
        let n = if e.name.is_ascii() {
            // No allocation for an ASCII name that does not match (the common case).
            if !parts.all(|w| contains_ci(&e.name, w)) {
                return None;
            }
            e.name.to_ascii_lowercase()
        } else {
            let n = fold(&e.name);
            if !parts.all(|w| n.contains(w)) {
                return None;
            }
            n
        };
        if !self.globs.iter().all(|g| glob(g, &n)) {
            return None;
        }
        if self.newest || self.words.is_empty() {
            return Some(0);
        }
        fn words(s: &str) -> Vec<&str> {
            s.split(|c: char| !c.is_alphanumeric())
                .filter(|x| !x.is_empty())
                .collect()
        }
        let stem = match n.rsplit_once('.') {
            Some((s, _)) if e.dir == NONE && !s.is_empty() => s,
            _ => &n,
        };
        let all = words(&n);
        Some(if words(stem) == self.words {
            0
        } else if self.words.iter().all(|w| all.iter().any(|x| x.starts_with(w.as_str()))) {
            1
        } else {
            2
        })
    }
}

/// Longest pattern, in characters (longer: searched as words). With a name of at most 255 characters, `glob` stays
/// below 64 × 255 steps per name, and only for the names that hold every fixed part.
const GLOB_MAX: usize = 64;

/// A word with `*` or `?`, as a pattern: folded, `**` merged. `None`: no wildcard, or longer than `GLOB_MAX` once
/// folded (then searched as words).
fn pattern(w: &str) -> Option<String> {
    if !w.contains(['*', '?']) {
        return None;
    }
    let mut g = String::new();
    for c in fold(w).chars() {
        if !(c == '*' && g.ends_with('*')) {
            g.push(c);
        }
    }
    (g.chars().count() <= GLOB_MAX).then_some(g)
}

/// `p` (`*` any run of characters, `?` one) matches the whole of `n`; both folded. One backtrack point, the last `*`:
/// at most len(p) × len(n) steps, never exponential.
fn glob(p: &str, n: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (p.chars().collect(), n.chars().collect());
    let (mut i, mut j) = (0, 0);
    // After the last `*`: where the pattern resumes, and the first name position not yet given to that `*`.
    let mut back: Option<(usize, usize)> = None;
    while j < n.len() {
        match (p.get(i), n.get(j)) {
            (Some('*'), _) => {
                back = Some((i + 1, j));
                i += 1;
            }
            (Some(&c), Some(&x)) if c == '?' || c == x => {
                i += 1;
                j += 1;
            }
            _ => match back {
                Some((bi, bj)) => {
                    back = Some((bi, bj + 1));
                    (i, j) = (bi, bj + 1);
                }
                None => return false,
            },
        }
    }
    p.get(i..).is_some_and(|rest| rest.iter().all(|&c| c == '*'))
}

/// `Query::files_named` filter that keeps every file (and no folder).
pub fn any_file(_: &str) -> bool {
    true
}

/// Appends the search form of `c`: lowercase, accents removed (canonical decomposition without its combining marks),
/// œ æ ß spelled out. One character at a time, so that a match can be traced back to the name (highlighting).
pub fn fold_into(c: char, out: &mut String) {
    use unicode_normalization::char::{decompose_canonical, is_combining_mark};
    if c.is_ascii() {
        return out.push(c.to_ascii_lowercase());
    }
    // Decomposed, lowercased, decomposed again (a lowercase can be precomposed): `fold` gives back the same text twice.
    decompose_canonical(c, |d| {
        for l in d.to_lowercase() {
            decompose_canonical(l, |x| match x {
                _ if is_combining_mark(x) => {}
                'œ' => out.push_str("oe"),
                'æ' => out.push_str("ae"),
                'ß' => out.push_str("ss"),
                _ => out.push(x),
            })
        }
    })
}

/// Search form of a text (`fold_into`).
pub fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    s.chars().for_each(|c| fold_into(c, &mut out));
    out
}

/// `t` is already folded. No allocation for ASCII (tags are stored lowercase).
fn folded_eq(x: &str, t: &str) -> bool {
    if x.is_ascii() { x == t } else { fold(x) == t }
}

/// `needle` is already folded. No allocation for ASCII (the common case).
fn contains_ci(hay: &str, needle: &str) -> bool {
    if hay.is_ascii() && needle.is_ascii() {
        let (h, n) = (hay.as_bytes(), needle.as_bytes());
        n.is_empty() || h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
    } else {
        fold(hay).contains(needle)
    }
}

fn join(dir: Option<&SafePath>, name: &str) -> Option<SafePath> {
    SafePath::new(&match dir {
        Some(d) => format!("{}/{name}", d.as_str()),
        None => name.to_owned(),
    })
    .ok()
}

impl UserIndex {
    /// Panic-free access (`indexing_slicing` forbidden): an invalid slot behaves like a dead folder.
    fn dir(&self, s: u32) -> Option<&Dir> {
        self.dirs.get(s as usize)
    }
    fn dir_mut(&mut self, s: u32) -> Option<&mut Dir> {
        self.dirs.get_mut(s as usize)
    }
    fn live(&self, s: u32) -> bool {
        self.dir(s).is_some_and(|d| d.live)
    }
    fn take_entries(&mut self, s: u32) -> Vec<Entry> {
        self.dir_mut(s)
            .map(|d| std::mem::take(&mut d.entries))
            .unwrap_or_default()
    }

    fn build(root: &Root, cap: usize) -> io::Result<Self> {
        let mut ix = Self {
            dirs: vec![Dir {
                parent: NONE,
                entries: Vec::new(),
                live: true,
            }],
            free: Vec::new(),
            by_id: HashMap::new(),
            // Read before the walk: a write during the build will cause a rebuild (never the opposite).
            root_etag: root.meta(None)?.dir_etag,
            entries: 0,
            cap,
            truncated: false,
        };
        let mut dropped = Vec::new();
        ix.fill(root, 0, None, &[], &mut dropped)?;
        Ok(ix)
    }

    fn alloc(&mut self, parent: u32, id: Option<FileId>) -> u32 {
        let d = Dir {
            parent,
            entries: Vec::new(),
            live: true,
        };
        let s = match self
            .free
            .pop()
            .and_then(|s| self.dirs.get_mut(s as usize).map(|slot| (s, slot)))
        {
            Some((s, slot)) => {
                *slot = d;
                s
            }
            None => {
                self.dirs.push(d);
                (self.dirs.len() - 1) as u32
            }
        };
        if let Some(id) = id {
            self.by_id.insert(id, s);
        }
        s
    }

    fn free_tree(&mut self, s: u32) {
        let entries = self.take_entries(s);
        self.entries -= entries.len();
        for e in &entries {
            if e.dir != NONE {
                self.free_tree(e.dir);
            }
        }
        if let Some(d) = self.dir_mut(s) {
            d.live = false;
        }
        self.by_id.retain(|_, v| *v != s);
        self.free.push(s);
    }

    /// (Re)reads the folder `slot`. An already indexed subfolder whose parent is part of `batch` is taken over as is
    /// (move); a new one is indexed recursively. Vanished subfolders go into `dropped` (folder, old parent).
    fn fill(
        &mut self,
        root: &Root,
        slot: u32,
        path: Option<&SafePath>,
        batch: &[u32],
        dropped: &mut Vec<(u32, u32)>,
    ) -> io::Result<()> {
        let old = self.take_entries(slot);
        self.entries -= old.len();
        let mut new = Vec::new();
        for e in root.read_dir(path)? {
            let (name, meta) = e?;
            if self.entries >= self.cap {
                self.truncated = true;
                break;
            }
            let Some(p) = join(path, &name) else { continue };
            let (tags, favorite) = root.labels(Some(&p)).unwrap_or_default();
            let dir = if meta.is_dir {
                let known = meta.id.and_then(|id| self.by_id.get(&id).copied()).filter(|&s| {
                    self.dir(s)
                        .is_some_and(|d| d.live && s != slot && (d.parent == slot || batch.contains(&d.parent)))
                });
                match known.and_then(|s| self.dir_mut(s).map(|d| (s, d))) {
                    Some((s, d)) => {
                        d.parent = slot;
                        s
                    }
                    None => {
                        let s = self.alloc(slot, meta.id);
                        // Unreadable subfolder: kept empty rather than failing the whole index.
                        let _ = self.fill(root, s, Some(&p), batch, dropped);
                        s
                    }
                }
            } else {
                NONE
            };
            self.entries += 1;
            new.push(Entry {
                name: name.into(),
                size: meta.size,
                mtime: meta.mtime,
                ctime: meta.ctime,
                fileid: crate::etag::fileid(&meta),
                dir,
                tags: tags.into_iter().map(Into::into).collect(),
                favorite,
            });
        }
        for e in &old {
            if e.dir != NONE && !new.iter().any(|n| n.dir == e.dir) {
                dropped.push((e.dir, slot));
            }
        }
        if let Some(d) = self.dir_mut(slot) {
            d.entries = new;
        }
        Ok(())
    }

    /// Deepest indexed slot on the path of `dir`, and its path.
    fn resolve(&self, dir: Option<&SafePath>) -> (u32, Option<SafePath>) {
        let (mut slot, mut at) = (0u32, None::<SafePath>);
        let Some(d) = dir else { return (0, None) };
        for comp in d.as_str().split('/') {
            let next = self
                .dir(slot)
                .and_then(|d| d.entries.iter().find(|e| e.dir != NONE && &*e.name == comp));
            match (next, join(at.as_ref(), comp)) {
                (Some(e), Some(p)) => {
                    slot = e.dir;
                    at = Some(p);
                }
                _ => break,
            }
        }
        (slot, at)
    }

    fn refresh(&mut self, root: &Root, dirs: &[Option<&SafePath>]) -> io::Result<()> {
        let targets: Vec<(u32, Option<SafePath>)> = dirs.iter().map(|d| self.resolve(*d)).collect();
        let batch: Vec<u32> = targets.iter().map(|t| t.0).collect();
        let mut dropped = Vec::new();
        for (slot, path) in &targets {
            if self.live(*slot) {
                self.fill(root, *slot, path.as_ref(), &batch, &mut dropped)?;
            }
        }
        // Gone from a folder without reappearing elsewhere (its parent did not change): deleted or out of the space.
        for (s, from) in dropped {
            if self.dir(s).is_some_and(|d| d.live && d.parent == from) {
                self.free_tree(s);
            }
        }
        self.root_etag = root.meta(None)?.dir_etag;
        Ok(())
    }

    /// Path of an indexed folder, from the root down to it.
    fn dir_path(&self, mut s: u32) -> String {
        let mut parts = Vec::new();
        // Bounded by the number of slots: never an infinite loop, even on an inconsistent index.
        for _ in 0..self.dirs.len() {
            let Some(p) = self.dir(s).map(|d| d.parent).filter(|&p| s != 0 && p != NONE) else {
                break;
            };
            if let Some(e) = self.dir(p).and_then(|d| d.entries.iter().find(|e| e.dir == s)) {
                parts.push(&*e.name);
            }
            s = p;
        }
        parts.reverse();
        parts.join("/")
    }

    fn hit(&self, s: usize, e: &Entry) -> Hit {
        let b = self.dir_path(s as u32);
        Hit {
            path: if b.is_empty() {
                e.name.to_string()
            } else {
                format!("{b}/{}", e.name)
            },
            name: e.name.to_string(),
            is_dir: e.dir != NONE,
            size: e.size,
            mtime: e.mtime,
            ctime: e.ctime,
            tags: e.tags.iter().map(|t| t.to_string()).collect(),
            favorite: e.favorite,
        }
    }

    /// Is slot `s` the folder `top` or one of its subfolders? Bounded like `dir_path`.
    fn within(&self, mut s: u32, top: u32) -> bool {
        for _ in 0..=self.dirs.len() {
            if s == top {
                return true;
            }
            match self.dir(s).map(|d| d.parent) {
                Some(p) if s != 0 && p != NONE => s = p,
                _ => return false,
            }
        }
        false
    }

    /// The `LIMIT` best entries that pass `q`: best rank (`Query::rank`), then newest (bounded heap: constant
    /// memory, the whole space is considered, not the first ones found).
    fn search(&self, q: &Query) -> Found {
        use std::cmp::Reverse;
        let top = match &q.under {
            None => 0,
            Some(p) => match self.resolve(Some(p)) {
                (s, Some(at)) if at == *p => s,
                // Folder missing (or not indexed): nothing under it.
                _ => {
                    return Found {
                        incomplete: self.truncated,
                        ..Found::default()
                    };
                }
            },
        };
        let mut heap = std::collections::BinaryHeap::with_capacity(LIMIT + 1);
        let mut more = false;
        for (s, d) in self
            .dirs
            .iter()
            .enumerate()
            .filter(|(s, d)| d.live && (top == 0 || self.within(*s as u32, top)))
        {
            for (i, e, rank) in d
                .entries
                .iter()
                .enumerate()
                .filter_map(|(i, e)| Some((i, e, q.score(e)?)))
            {
                heap.push(Reverse((
                    (Reverse(rank), if q.by_activity { e.ctime } else { e.mtime }),
                    s,
                    i,
                )));
                if heap.len() > LIMIT {
                    heap.pop();
                    more = true;
                }
            }
        }
        let mut v: Vec<_> = heap
            .into_iter()
            .filter_map(|Reverse((key, s, i))| Some((key, self.dirs.get(s)?.entries.get(i)?, s)))
            .map(|(key, e, s)| (key, fold(&e.name), e, s))
            .collect();
        // Same rank and same time (a copied batch): by name.
        v.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        Found {
            hits: v.into_iter().map(|(_, _, e, s)| self.hit(s, e)).collect(),
            more,
            incomplete: self.truncated,
        }
    }
}

struct Slot {
    ix: Mutex<Option<UserIndex>>,
    entries: AtomicUsize,
    /// Last use, in seconds since `Indexes::epoch`.
    last: AtomicU64,
}

/// Indexes of a tenant's users.
pub struct Indexes {
    users: Mutex<HashMap<String, Arc<Slot>>>,
    epoch: Instant,
}

impl Default for Indexes {
    fn default() -> Self {
        Self {
            users: Mutex::new(HashMap::new()),
            epoch: Instant::now(),
        }
    }
}

impl std::fmt::Debug for Indexes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Indexes")
    }
}

/// An index's lock; if it was poisoned (panic during an update), the index is thrown away.
fn lock(m: &Mutex<Option<UserIndex>>) -> MutexGuard<'_, Option<UserIndex>> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => {
            m.clear_poison();
            let mut g = p.into_inner();
            *g = None;
            g
        }
    }
}

impl Indexes {
    fn now(&self) -> u64 {
        self.epoch.elapsed().as_secs()
    }

    fn users(&self) -> MutexGuard<'_, HashMap<String, Arc<Slot>>> {
        self.users.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn slot(&self, user: &str) -> Arc<Slot> {
        self.users()
            .entry(user.to_owned())
            .or_insert_with(|| {
                Arc::new(Slot {
                    ix: Mutex::new(None),
                    entries: AtomicUsize::new(0),
                    last: AtomicU64::new(0),
                })
            })
            .clone()
    }

    /// Search in `user`'s space (builds the index if needed). Blocking.
    pub fn search(&self, user: &str, root: &Root, q: &Query) -> io::Result<Found> {
        if q.is_empty() {
            return Ok(Found::default());
        }
        let slot = self.slot(user);
        slot.last.store(self.now(), Ordering::Relaxed);
        let mut g = lock(&slot.ix);
        let current = root.meta(None)?.dir_etag;
        if g.as_ref().is_none_or(|ix| ix.root_etag != current) {
            *g = None;
            slot.entries.store(0, Ordering::Relaxed);
            let others: usize = self.users().values().map(|s| s.entries.load(Ordering::Relaxed)).sum();
            let ix = UserIndex::build(root, TENANT_MAX.saturating_sub(others))?;
            slot.entries.store(ix.entries, Ordering::Relaxed);
            *g = Some(ix);
        }
        Ok(g.as_ref().map(|ix| ix.search(q)).unwrap_or_default())
    }

    /// After a server write: rereads the touched folders, if `user`'s index exists. Blocking.
    /// On error, the index is thrown away (rebuilt at the next search): never a wrong result kept.
    pub fn refresh(&self, user: &str, root: &Root, dirs: &[Option<&SafePath>]) {
        let Some(slot) = self.users().get(user).cloned() else {
            return;
        };
        let mut g = lock(&slot.ix);
        let Some(ix) = g.as_mut() else { return };
        if ix.refresh(root, dirs).is_err() {
            *g = None;
        }
        slot.entries
            .store(g.as_ref().map_or(0, |ix| ix.entries), Ordering::Relaxed);
    }

    /// Frees the indexes inactive since `idle`.
    pub fn sweep(&self, idle: Duration) {
        let now = self.now();
        self.users().retain(|_, s| {
            let keep = now.saturating_sub(s.last.load(Ordering::Relaxed)) < idle.as_secs();
            if !keep {
                *lock(&s.ix) = None;
            }
            keep
        });
    }

    /// Indexed entries (all users), for measurements.
    pub fn entries(&self) -> usize {
        self.users().values().map(|s| s.entries.load(Ordering::Relaxed)).sum()
    }
}

/// Fuzzing (`fuzz/fuzz_targets/query.rs`): arbitrary web search text. No crash, words folded and non-empty, and the
/// highlighting of any name gives back exactly that name.
pub fn fuzz_query(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let q = Query::parse(text);
    assert!(q.words.iter().all(|w| !w.is_empty() && fold(w) == *w), "{text:?}");
    // Patterns: folded, bounded, no `**`; matching any name ends (and `*` alone takes everything).
    for g in &q.globs {
        assert!(g.contains(['*', '?']) && fold(g) == *g && !g.contains("**"), "{text:?}");
        assert!(g.chars().count() <= GLOB_MAX, "{text:?}");
        let _ = glob(g, &fold(text));
    }
    assert!(glob("*", &fold(text)));
    let parts = crate::web::render::marks(text, &q.words);
    assert_eq!(parts.iter().map(|p| p.0.as_str()).collect::<String>(), text);
    assert!(parts.windows(2).all(|w| matches!(w, [a, b] if a.1 != b.1)), "{text:?}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn tree() -> (tempfile::TempDir, Root) {
        let t = tempfile::tempdir().unwrap();
        let root = Root::open_dir(t.path()).unwrap();
        root.ensure_layout().unwrap();
        (t, root)
    }
    fn sp(s: &str) -> SafePath {
        SafePath::new(s).unwrap()
    }
    fn names(f: &Found) -> Vec<&str> {
        f.hits.iter().map(|h| h.path.as_str()).collect()
    }

    #[test]
    fn query_parse() {
        let q = Query::parse("Facture  tag:Impôts 2024");
        assert_eq!(q.words, ["facture", "2024"]);
        assert_eq!(q.tags, ["impots"]);
        assert!(Query::parse("   ").is_empty());
        // Accents, case and punctuation: words of letters and digits only.
        assert_eq!(
            Query::parse("ÉTÉ rapport_final-v2 l'œuvre").words,
            ["ete", "rapport", "final", "v2", "l", "oeuvre"]
        );
        assert!(Query::parse("--- ()").is_empty());
        // Filters.
        let q = Query::parse("type:pdf is:fav after:2024 before:2025-03-15");
        assert!(q.words.is_empty() && q.favorites && q.files_named.is_some_and(|f| f("a.PDF") && !f("a.txt")));
        let (a, b) = (q.after.unwrap(), q.before.unwrap());
        assert!(b - a > 400 * 86_400 && b - a < 440 * 86_400, "{a} {b}");
        assert!(Query::parse("type:folder").dirs_only);
        assert!(
            Query::parse("type:doc")
                .files_named
                .is_some_and(|f| f("a.odt") && f("b.xlsx") && f("c.md"))
        );
        // Unknown or invalid operator: searched as words.
        let q = Query::parse("type:exe after:hier 12:30 is:x");
        assert_eq!(q.words, ["type", "exe", "after", "hier", "12", "30", "is", "x"]);
        assert!(q.files_named.is_none() && q.after.is_none() && !q.favorites);
        assert!(
            contains_ci("Rapport-FINAL.pdf", "final") && contains_ci("Été.txt", "ete") && !contains_ci("abc", "abd")
        );
        assert_eq!(fold("Œuvre Straße ÅNGSTRÖM Ça ﬁ"), "oeuvre strasse angstrom ca ﬁ");
        assert!(folded_eq("impôts", "impots") && folded_eq("rh", "rh") && !folded_eq("rh", "r"));
    }

    /// Patterns: `*` any run (empty included), `?` exactly one character, anchored at both ends, folded like words.
    #[test]
    fn glob_patterns() {
        for (p, n, want) in [
            ("*.md", "index.md", true),
            ("*.md", ".md", true),
            ("*.md", "index.mdx", false),
            ("*.md", "index.m", false),
            ("index.*", "index.md", true),
            ("index.*", "index.", true),
            ("index.*", "index", false),
            ("?.txt", "a.txt", true),
            ("?.txt", ".txt", false),
            ("?.txt", "ab.txt", false),
            ("*", "", true),
            ("?", "", false),
            ("a*b*c", "aXbYc", true),
            ("a*b*c", "aXcYb", false),
            (
                "*a*a*a*b",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                false,
            ),
            ("ete?.txt", "ete1.txt", true),
            ("?", "é", true),
        ] {
            assert_eq!(glob(p, n), want, "{p} {n}");
        }
        let q = Query::parse("*.MD rapport ÉTÉ*  ***.txt");
        assert_eq!(q.globs, ["*.md", "ete*", "*.txt"]);
        assert_eq!(q.words, ["rapport"]);
        assert!(!Query::parse("*").is_empty());
        // Too long once folded ("œ" → "oe"): searched as words.
        let long = format!("*{}", "œ".repeat(GLOB_MAX - 1));
        assert!(pattern(&format!("*{}", "a".repeat(GLOB_MAX - 1))).is_some());
        assert!(pattern(&long).is_none());
        assert!(Query::parse(&long).globs.is_empty());

        let (t, root) = tree();
        let ix = Indexes::default();
        root.mkdir(&sp("Livres")).unwrap();
        root.mkdir(&sp("notes.md")).unwrap();
        for f in [
            "Livres/index.md",
            "Livres/Été.MD",
            "Livres/index.mdx",
            "lisez-moi.txt",
            "plan.md.bak",
        ] {
            root.atomic_write(&sp(f), &mut &b"x"[..]).unwrap();
        }
        let find = |q: &str| {
            let mut v: Vec<String> = ix
                .search("u", &root, &Query::parse(q))
                .unwrap()
                .hits
                .into_iter()
                .map(|h| h.path)
                .collect();
            v.sort();
            v
        };
        assert_eq!(find("*.md"), ["Livres/index.md", "Livres/Été.MD", "notes.md"]);
        assert_eq!(find("*.md type:doc"), ["Livres/index.md", "Livres/Été.MD"]);
        assert_eq!(find("ete*"), ["Livres/Été.MD"]);
        assert_eq!(find("index *.md"), ["Livres/index.md"]);
        assert_eq!(find("*.txt"), ["lisez-moi.txt"]);
        assert!(find("*.pdf").is_empty());
        // Patterns alone, like filters alone: newest first, whatever the names (one with no letter included).
        for (f, mtime) in [("_.md", 1_000), ("zz.md", 2_000_000_000)] {
            root.atomic_write(&sp(f), &mut &b"x"[..]).unwrap();
            let file = std::fs::File::options().write(true).open(t.path().join(f)).unwrap();
            file.set_modified(UNIX_EPOCH + Duration::from_secs(mtime)).unwrap();
        }
        let fresh = Indexes::default();
        let order: Vec<String> = fresh
            .search("v", &root, &Query::parse("*.md"))
            .unwrap()
            .hits
            .into_iter()
            .map(|h| h.path)
            .collect();
        assert_eq!(order.first().map(String::as_str), Some("zz.md"), "{order:?}");
        assert_eq!(order.last().map(String::as_str), Some("_.md"), "{order:?}");
    }

    proptest::proptest! {
        /// `glob` agrees with the obvious recursive definition, on texts where `*` and `?` collide with the letters.
        #[test]
        fn glob_is_the_recursive_definition(p in "[ab*?]{0,8}", n in "[ab]{0,10}") {
            fn slow(p: &[char], n: &[char]) -> bool {
                match (p.split_first(), n.split_first()) {
                    (None, _) => n.is_empty(),
                    (Some(('*', pr)), _) => slow(pr, n) || n.split_first().is_some_and(|(_, nr)| slow(p, nr)),
                    (Some((c, pr)), Some((x, nr))) => (*c == '?' || c == x) && slow(pr, nr),
                    (Some(_), None) => false,
                }
            }
            let (pc, nc): (Vec<char>, Vec<char>) = (p.chars().collect(), n.chars().collect());
            proptest::prop_assert_eq!(glob(&p, &n), slow(&pc, &nc), "{} {}", p, n);
        }
    }

    /// Accents ignored, ranking (exact name, then start of word, then elsewhere; newest first within a rank), a
    /// folder's scope, `type:` and dates.
    #[test]
    fn rank_scope_and_filters() {
        let (t, root) = tree();
        let ix = Indexes::default();
        for d in ["Compta", "Compta/2024", "Archives"] {
            root.mkdir(&sp(d)).unwrap();
        }
        let files = [
            ("Archives/vieux rapport final.pdf", 3_000),
            ("Archives/rapports finals.txt", 4_000),
            ("Compta/rapport_final.docx", 1_000),
            ("Compta/2024/prérapport final.pdf", 5_000),
            ("Compta/2024/Impôts.pdf", 1_700_000_000),
        ];
        for (p, mtime) in files {
            root.atomic_write(&sp(p), &mut &b"x"[..]).unwrap();
            let f = std::fs::File::options().write(true).open(t.path().join(p)).unwrap();
            f.set_modified(UNIX_EPOCH + Duration::from_secs(mtime)).unwrap();
        }
        let find = |q: &str, under: Option<&str>| {
            let mut q = Query::parse(q);
            q.under = under.map(sp);
            ix.search("u", &root, &q).unwrap()
        };
        assert_eq!(
            names(&find("RAPPORT final", None)),
            [
                "Compta/rapport_final.docx",
                "Archives/rapports finals.txt",
                "Archives/vieux rapport final.pdf",
                "Compta/2024/prérapport final.pdf"
            ]
        );
        assert_eq!(names(&find("impots", None)), ["Compta/2024/Impôts.pdf"]);
        assert_eq!(names(&find("IMPÔT", None)), ["Compta/2024/Impôts.pdf"]);
        // Scope: the folder and its subfolders; a missing folder, nothing.
        assert_eq!(
            names(&find("rapport", Some("Compta"))),
            ["Compta/rapport_final.docx", "Compta/2024/prérapport final.pdf"]
        );
        assert_eq!(
            names(&find("rapport", Some("Compta/2024"))),
            ["Compta/2024/prérapport final.pdf"]
        );
        assert!(find("rapport", Some("Nulle/part")).hits.is_empty());
        assert!(find("rapport", Some("Compta/rapport_final.docx")).hits.is_empty());
        // Filters alone: newest first.
        assert_eq!(
            names(&find("type:pdf", None)),
            [
                "Compta/2024/Impôts.pdf",
                "Compta/2024/prérapport final.pdf",
                "Archives/vieux rapport final.pdf"
            ]
        );
        assert_eq!(names(&find("type:pdf after:2020", None)), ["Compta/2024/Impôts.pdf"]);
        assert_eq!(names(&find("rapport before:1990", Some("Archives"))).len(), 2);
        assert_eq!(names(&find("type:folder compta", None)), ["Compta"]);
    }

    /// WebDAV search filters (`dav::search`): dates, folders only, file type, and "newest first" which keeps the
    /// `LIMIT` newest of the whole space (not the first ones found).
    #[test]
    fn dav_filters_and_newest_first() {
        let (t, root) = tree();
        let ix = Indexes::default();
        root.mkdir(&sp("Photos")).unwrap();
        root.mkdir(&sp("lot")).unwrap();
        let mut files: Vec<(String, u64)> = vec![
            ("Photos/a.jpg".into(), 1_000),
            ("Photos/b.mp4".into(), 2_000),
            ("notes.txt".into(), 3_000),
            ("old.txt".into(), 500),
        ];
        files.extend((0..LIMIT as u64 + 50).map(|i| (format!("lot/f{i:03}.txt"), 10_000 + i)));
        for (p, mtime) in &files {
            root.atomic_write(&sp(p), &mut &b"x"[..]).unwrap();
            let f = std::fs::File::options().write(true).open(t.path().join(p)).unwrap();
            f.set_modified(UNIX_EPOCH + Duration::from_secs(*mtime)).unwrap();
        }
        // Folders dated too (otherwise "now", after their files): they count as entries.
        for d in ["Photos", "lot"] {
            std::fs::File::open(t.path().join(d))
                .unwrap()
                .set_modified(UNIX_EPOCH + Duration::from_secs(100))
                .unwrap();
        }
        let q = |q: Query| ix.search("alice", &root, &q).unwrap();
        let newest = |after| Query {
            after: Some(after),
            newest: true,
            ..Query::default()
        };

        // More than LIMIT candidates: the LIMIT newest, from newest to oldest.
        let f = q(newest(0));
        assert_eq!((f.hits.len(), f.more), (LIMIT, true));
        assert_eq!(f.hits[0].path, format!("lot/f{:03}.txt", LIMIT + 49));
        assert!(f.hits.windows(2).all(|w| w[0].mtime >= w[1].mtime));
        assert!(!names(&f).contains(&"old.txt"));

        // Strict bounds, and filter by file name (never a folder).
        let f = q(Query {
            after: Some(1_000),
            before: Some(10_000),
            newest: true,
            ..Query::default()
        });
        assert_eq!(names(&f), ["notes.txt", "Photos/b.mp4"]);
        let media = |n: &str| n.ends_with(".jpg") || n.ends_with(".mp4") || n == "Photos";
        let f = q(Query {
            files_named: Some(media),
            newest: true,
            ..Query::default()
        });
        assert_eq!(names(&f), ["Photos/b.mp4", "Photos/a.jpg"]);

        // Folders only.
        let f = q(Query {
            words: vec!["o".into()],
            dirs_only: true,
            ..Query::default()
        });
        assert_eq!(names(&f), ["lot", "Photos"]);
        assert!(Query::default().is_empty() && !newest(0).is_empty());
    }

    #[test]
    fn search_follows_server_writes() {
        let (_t, root) = tree();
        let ix = Indexes::default();
        root.mkdir(&sp("Docs")).unwrap();
        root.mkdir(&sp("Docs/Impots")).unwrap();
        for p in ["Docs/Impots/facture-2024.pdf", "Docs/note.txt", "Facture-old.pdf"] {
            root.atomic_write(&sp(p), &mut &b"x"[..]).unwrap();
        }
        root.set_tags(Some(&sp("Docs/note.txt")), &["urgent".into()]).unwrap();
        let ok = |q: &str| ix.search("alice", &root, &Query::parse(q)).unwrap();
        assert_eq!(
            names(&ok("facture")),
            ["Docs/Impots/facture-2024.pdf", "Facture-old.pdf"]
        );
        assert_eq!(names(&ok("tag:urgent")), ["Docs/note.txt"]);
        assert_eq!(names(&ok("facture 2024")), ["Docs/Impots/facture-2024.pdf"]);
        root.set_favorite(Some(&sp("Docs")), true).unwrap();
        ix.refresh("alice", &root, &[None]);
        let fav = ix.search("alice", &root, &Query::favorites()).unwrap();
        assert_eq!((names(&fav), fav.hits[0].is_dir), (vec!["Docs"], true));
        let built = ix.entries();
        assert_eq!(built, 5);

        // Server writes, as `journaled` does them: operation, ETags renewed, then index refreshed.
        let write = |dirs: &[Option<&SafePath>], op: &dyn Fn()| {
            op();
            for d in dirs {
                root.renew_etags_lenient(*d).unwrap();
            }
            ix.refresh("alice", &root, dirs);
        };
        // Moving a folder: found again by its identity, path up to date.
        root.mkdir(&sp("Archives")).unwrap();
        root.renew_etags_lenient(None).unwrap();
        ix.refresh("alice", &root, &[None]);
        let (docs, archives) = (sp("Docs"), sp("Archives"));
        write(&[Some(&docs), Some(&archives)], &|| {
            root.rename(&sp("Docs/Impots"), &sp("Archives/Impots"), false, "alice")
                .unwrap();
        });
        assert_eq!(names(&ok("2024")), ["Archives/Impots/facture-2024.pdf"]);
        // Trash: disappears from the search.
        write(&[Some(&docs)], &|| root.trash(&sp("Docs/note.txt"), "alice").unwrap());
        assert!(ok("tag:urgent").hits.is_empty());
        write(&[Some(&archives)], &|| {
            root.trash(&sp("Archives/Impots"), "alice").unwrap()
        });
        assert!(ok("2024").hits.is_empty());
        assert!(!ok("Archives").hits.is_empty());
        // No hidden rebuild: the root's ETag tracked step by step (otherwise, `entries` would be recounted the same,
        // so we also check that a change outside the application is seen thanks to the safety net).
        std::fs::write(root_path(&_t).join("Docs/hors-appli.txt"), b"x").unwrap();
        assert!(ok("hors-appli").hits.is_empty(), "no disk watching");
        root.renew_etags_lenient(Some(&docs)).unwrap(); // what `rescan` does
        assert_eq!(names(&ok("hors-appli")), ["Docs/hors-appli.txt"]);
    }

    fn root_path(t: &tempfile::TempDir) -> std::path::PathBuf {
        t.path().to_path_buf()
    }

    #[test]
    fn bounded_and_evicted() {
        let (_t, root) = tree();
        for i in 0..(LIMIT + 10) {
            std::fs::write(_t.path().join(format!("f{i}.txt")), b"x").unwrap();
        }
        let ix = Indexes::default();
        let f = ix.search("bob", &root, &Query::parse("txt")).unwrap();
        assert_eq!((f.hits.len(), f.more, f.incomplete), (LIMIT, true, false));
        assert_eq!(ix.entries(), LIMIT + 10);
        ix.sweep(Duration::ZERO);
        assert_eq!(ix.entries(), 0);
        // Cap: incomplete index flagged, no growth beyond it.
        let mut small = UserIndex::build(&root, 5).unwrap();
        assert!(small.truncated && small.entries == 5);
        // A truncated index says so, also when the folder searched in is not in it (maybe never indexed): "nothing
        // found" alone would mislead.
        assert!(small.search(&Query::parse("txt")).incomplete);
        let mut q = Query::parse("txt");
        q.under = Some(sp("Absent"));
        let f = small.search(&q);
        assert!(f.hits.is_empty() && f.incomplete);
        small.refresh(&root, &[None]).unwrap();
        assert_eq!(small.entries, 5);
    }
}
