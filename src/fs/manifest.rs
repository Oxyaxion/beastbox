//! Identity manifest (§6, plan J4): a snapshot, taken at backup time, of what a **file copy** loses
//! (rclone to a cloud, `rsync` without `-X`, `cp`): each item's identity, its tags, its favorite, and the trash
//! metadata. `beastbox manifest` writes it into the user's dataset, under a reserved name (invisible to
//! clients): it leaves with the copy and comes back with it. On `rescan`, an item **without identity** gets back the
//! manifest's one if nothing contradicts it; share links, tags, favorites and trash are then recovered.
//!
//! Recovery rules, in order:
//! - only an item **without identity** is concerned: an existing xattr always wins over the manifest;
//! - an identity already held by another item (moved since the snapshot, xattrs kept) is **never** reused:
//!   it is collected in a first pass, before any change;
//! - file: same path, **same size and same time to the second** (rclone to pCloud only keeps the second);
//!   otherwise it is a different content: new identity;
//! - file whose SHA-1 the manifest holds (written by the server): its content is read and hashed. Same sum: the
//!   content is proven identical, so the sum record and the time to the nanosecond are put back too, and the ETag is
//!   the one from before: clients re-download nothing and see no conflict. Different sum: different content, new
//!   identity. No sum (file arrived outside the application): identity only, the ETag changes;
//! - folder: same path (its time necessarily changes when its contents are restored); the user's root included.
//!
//! The file is read with suspicion (it comes back from external storage): versioned header required, bounded size,
//! invalid line ignored and counted. It creates, moves and deletes nothing: it only sets xattrs on items
//! already present, at paths already validated by `SafePath`.
//!
//! Format: UTF-8 text, one entry per line, fields separated by a tab, free text encoded as `%XX` (no tab
//! or line ending can appear in a field):
//! `zone  kind  path  size  time  identity  favorite  tags  trash.path  trash.date  trash.author  nsec  sha1`
//! (format 1, still read: without the last two fields)
//! - zone: `m` (the user's space, empty path = root) or `t` (in `.trash/`, path relative to `.trash`);
//! - kind: `f` file, `d` folder, `s` trash slot (only carries the three `trash.*` fields);
//! - identity: 32 hexadecimal characters, or empty; favorite: `1` or empty; tags: separated by a line ending;
//! - nsec: nanoseconds of the time (0 to 999,999,999); sha1: 40 lowercase hexadecimal characters, or empty.

use super::dir::meta_of;
use super::write::{
    MAX_TAGS, XATTR_FAVORITE, XATTR_TAGS, XATTR_TRASH_BY, XATTR_TRASH_PATH, XATTR_TRASH_TIME, normalize_tag,
    record_sha1, set_mtime, sha1_of,
};
use super::{
    FileId, Root, SafePath, TMP_DIR, TRASH_DIR, XATTR_ID, cstr, fsync, openat, renameat, xattr_get, xattr_set,
};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Name of the manifest at the user's root (reserved: refused by `SafePath`, hidden from listings).
pub const MANIFEST: &str = ".beastbox-manifest";
const HEADER: &str = "beastbox-manifest 2";
/// Previous format (0.3.0 to 0.12.0): no nanoseconds nor sum; identities are recovered, ETags are not.
const HEADER_V1: &str = "beastbox-manifest 1";
/// Maximum size read: ~150 bytes per entry, i.e. several million entries.
const MANIFEST_MAX: u64 = 1 << 30;
/// Longest `trash.*` field kept (a path, a date, a user name): a longer one makes the line invalid.
const TRASH_FIELD_MAX: usize = 4096;
/// Readers hashing the restored files at `rescan` by default and at most (`beastbox rescan --readers N`): measured best
/// on NVMe and hard disks; 16 is slower on both (`VALIDATION.md`).
pub const RESCAN_READERS: usize = 8;

/// SHA-1 of each file, read by `readers` threads at once; the first error stops them and is returned.
fn sums_in_parallel(jobs: &[(&Root, &SafePath)], readers: usize) -> io::Result<Vec<String>> {
    let (next, stop) = (AtomicUsize::new(0), AtomicBool::new(false));
    let out = Mutex::new(vec![String::new(); jobs.len()]);
    let first_err: Mutex<Option<io::Error>> = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..readers.clamp(1, RESCAN_READERS).min(jobs.len()) {
            s.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((root, p)) = jobs.get(i) else { break };
                    match root.open_file(p).and_then(|(mut f, _)| sha1_of(&mut f)) {
                        Ok(h) => {
                            if let Ok(mut o) = out.lock()
                                && let Some(slot) = o.get_mut(i)
                            {
                                *slot = h;
                            }
                        }
                        Err(e) => {
                            stop.store(true, Ordering::Relaxed);
                            if let Ok(mut g) = first_err.lock() {
                                g.get_or_insert(e);
                            }
                        }
                    }
                }
            });
        }
    });
    if let Some(e) = first_err
        .into_inner()
        .map_err(|_| io::Error::other("reader thread panicked"))?
    {
        return Err(e);
    }
    out.into_inner().map_err(|_| io::Error::other("reader thread panicked"))
}

/// Text fields: every control character (tabs and line endings included) and `%` are encoded.
const FIELD: &AsciiSet = &CONTROLS.add(b'%');

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Zone {
    Main,
    Trash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sort {
    File,
    Dir,
    Slot,
}

/// A manifest entry.
#[derive(Debug, Clone, PartialEq, Default)]
struct Entry {
    sort: Option<Sort>,
    size: u64,
    mtime: i64,
    /// Nanoseconds of the time (format 2; 0 in format 1).
    nsec: i64,
    /// SHA-1 recorded at write time, still valid when the manifest was written; empty if none (format 1 included).
    sha1: String,
    id: Option<[u8; 16]>,
    favorite: bool,
    tags: Vec<String>,
    /// Trash slot: (original path, date, author), as in the xattrs.
    trash: [String; 3],
}

/// What `beastbox manifest` wrote.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ManifestReport {
    pub files: u64,
    pub dirs: u64,
    /// Items in the trash (files and folders).
    pub trashed: u64,
}

/// What the manifest gave back at `rescan`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ManifestApplied {
    /// Identities recovered (with their tags and favorite).
    pub ids: u64,
    /// Files among them whose content was proven identical (same SHA-1): ETag kept, clients see no change.
    pub etags_kept: u64,
    /// Files with the same size and time but another SHA-1: different content, identity not recovered.
    pub content_changed: u64,
    /// Trash slots whose original path, date and author were put back.
    pub trash_slots: u64,
    /// Unreadable lines ignored.
    pub bad_lines: u64,
}

fn enc(s: &str) -> String {
    utf8_percent_encode(s, FIELD).to_string()
}

fn dec(s: &str) -> Option<String> {
    percent_decode_str(s).decode_utf8().ok().map(|c| c.into_owned())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn text(fd: BorrowedFd<'_>, name: &CStr) -> io::Result<String> {
    Ok(xattr_get(fd, name)?
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default())
}

fn line(zone: Zone, path: &str, e: &Entry) -> String {
    let sort = match e.sort {
        Some(Sort::File) => "f",
        Some(Sort::Dir) => "d",
        Some(Sort::Slot) => "s",
        None => "?",
    };
    format!(
        "{}\t{sort}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
        if zone == Zone::Main { "m" } else { "t" },
        enc(path),
        e.size,
        e.mtime,
        e.id.map(|i| hex(&i)).unwrap_or_default(),
        if e.favorite { "1" } else { "" },
        enc(&e.tags.join("\n")),
        enc(&e.trash[0]),
        enc(&e.trash[1]),
        enc(&e.trash[2]),
        e.nsec,
        e.sha1,
    )
}

type Parsed = HashMap<(Zone, String), Entry>;

/// Reads a manifest. `Err`: header missing or of another version (nothing is guessed). Invalid line: ignored, counted.
fn parse(s: &str) -> io::Result<(Parsed, u64)> {
    let mut lines = s.split('\n');
    let v2 = match lines.next() {
        Some(HEADER) => true,
        Some(HEADER_V1) => false,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "manifest of an unknown format",
            ));
        }
    };
    let (mut out, mut bad) = (HashMap::new(), 0u64);
    for l in lines.filter(|l| !l.is_empty()) {
        match parse_line(l, v2) {
            Some((k, e)) => {
                out.insert(k, e);
            }
            None => bad += 1,
        }
    }
    Ok((out, bad))
}

fn parse_line(l: &str, v2: bool) -> Option<((Zone, String), Entry)> {
    let f: Vec<&str> = l.split('\t').collect();
    let (fields, nsec, sha1) = match (v2, f.as_slice()) {
        (true, [fields @ .., nsec, sha1]) => (fields, *nsec, *sha1),
        (false, fields) => (fields, "0", ""),
        _ => return None,
    };
    let [zone, sort, path, size, mtime, id, fav, tags, tp, tt, tb] = fields else {
        return None;
    };
    let nsec: i64 = nsec.parse().ok().filter(|n| (0..1_000_000_000).contains(n))?;
    if !sha1.is_empty() && (sha1.len() != 40 || !sha1.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))) {
        return None;
    }
    let zone = match *zone {
        "m" => Zone::Main,
        "t" => Zone::Trash,
        _ => return None,
    };
    let sort = match *sort {
        "f" => Sort::File,
        "d" => Sort::Dir,
        "s" if zone == Zone::Trash => Sort::Slot,
        _ => return None,
    };
    let path = dec(path)?;
    // The path must be one that `SafePath` accepts (empty = root of the space): nothing else will be touched.
    if !path.is_empty() && SafePath::new(&path).is_err() {
        return None;
    }
    let tags = dec(tags)?;
    let e = Entry {
        sort: Some(sort),
        size: size.parse().ok()?,
        mtime: mtime.parse().ok()?,
        nsec,
        sha1: sha1.to_owned(),
        id: if id.is_empty() { None } else { Some(unhex(id)?) },
        favorite: match *fav {
            "1" => true,
            "" => false,
            _ => return None,
        },
        // Same bounds as a write (§8): the manifest comes back from external storage, never trusted. Bounding them
        // here keeps an attribute under what `xattr_get` accepts, whatever the manifest holds.
        tags: tags.split('\n').filter_map(normalize_tag).take(MAX_TAGS).collect(),
        trash: {
            let f = [dec(tp)?, dec(tt)?, dec(tb)?];
            if f.iter().any(|v| v.len() > TRASH_FIELD_MAX) {
                return None;
            }
            f
        },
    };
    Some(((zone, path), e))
}

/// Every item of a tree (the root `None` first), with its metadata. Names refused by `SafePath` ignored.
/// Items of a tree: path (`None` = root) and metadata.
type Items = Vec<(Option<SafePath>, super::Meta)>;

fn walk(root: &Root) -> io::Result<Items> {
    let mut out = vec![(None, root.meta(None)?)];
    let mut stack: Vec<Option<SafePath>> = vec![None];
    while let Some(dir) = stack.pop() {
        for e in root.read_dir(dir.as_ref())? {
            let (name, m) = e?;
            let Ok(p) = SafePath::new(&match &dir {
                Some(d) => format!("{}/{name}", d.as_str()),
                None => name,
            }) else {
                continue;
            };
            if m.is_dir {
                stack.push(Some(p.clone()));
            }
            out.push((Some(p), m));
        }
    }
    Ok(out)
}

fn key(p: &Option<SafePath>) -> String {
    p.as_ref().map_or_else(String::new, |p| p.as_str().to_owned())
}

impl Root {
    fn trash_root(&self) -> io::Result<Root> {
        self.open_dir_raw(&cstr(TRASH_DIR)?)
    }

    /// `beastbox manifest`: writes `.beastbox-manifest` at the user's root, atomically (temporary in
    /// `.beastbox-tmp/`, `fsync`, then `rename`). Run it right before a backup by file copy.
    pub fn write_manifest(&self) -> io::Result<ManifestReport> {
        let mut rep = ManifestReport::default();
        let mut out = format!("{HEADER}\n");
        let entry = |fd: BorrowedFd<'_>, m: &super::Meta| -> io::Result<Entry> {
            let tags = text(fd, XATTR_TAGS)?;
            Ok(Entry {
                sort: Some(if m.is_dir { Sort::Dir } else { Sort::File }),
                size: if m.is_dir { 0 } else { m.size },
                mtime: m.mtime,
                nsec: if m.is_dir { 0 } else { m.mtime_nsec },
                sha1: m.sha1.clone().unwrap_or_default(),
                id: m.id.map(|i| i.0),
                favorite: m.favorite,
                tags: tags.split('\n').filter(|t| !t.is_empty()).map(str::to_owned).collect(),
                trash: Default::default(),
            })
        };
        for (p, m) in walk(self)? {
            if !m.is_dir && !m.is_file {
                continue;
            }
            let fd = self.open_any(p.as_ref())?;
            out.push_str(&line(Zone::Main, &key(&p), &entry(fd.as_fd(), &m)?));
            if m.is_dir { rep.dirs += 1 } else { rep.files += 1 }
        }
        let trash = self.trash_root()?;
        for (p, m) in walk(&trash)?.into_iter().skip(1) {
            if !m.is_dir && !m.is_file {
                continue;
            }
            let fd = trash.open_any(p.as_ref())?;
            let k = key(&p);
            if !k.contains('/') {
                // Trash slot: only its three xattrs.
                let e = Entry {
                    sort: Some(Sort::Slot),
                    trash: [
                        text(fd.as_fd(), XATTR_TRASH_PATH)?,
                        text(fd.as_fd(), XATTR_TRASH_TIME)?,
                        text(fd.as_fd(), XATTR_TRASH_BY)?,
                    ],
                    ..Entry::default()
                };
                out.push_str(&line(Zone::Trash, &k, &e));
                continue;
            }
            out.push_str(&line(Zone::Trash, &k, &entry(fd.as_fd(), &m)?));
            rep.trashed += 1;
        }
        // Atomic write: never a half-written manifest in place of the previous one.
        let tmp = self.open_dir_raw(&cstr(TMP_DIR)?)?;
        let name = cstr(&format!("manifest.{}", hex(&FileId::random()?.0)))?;
        let fd = openat(
            tmp.fd.as_fd(),
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let mut f = std::fs::File::from(fd);
        f.write_all(out.as_bytes())?;
        f.sync_all()?;
        renameat(tmp.fd.as_fd(), &name, self.fd.as_fd(), &cstr(MANIFEST)?)?;
        fsync(self.fd.as_fd())?;
        Ok(rep)
    }

    /// Manifest present at the user's root, read and parsed; `None` if there is none.
    fn read_manifest(&self) -> io::Result<Option<(Parsed, u64)>> {
        let fd = match openat(self.fd.as_fd(), &cstr(MANIFEST)?, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(e) => return Err(e),
        };
        let m = meta_of(fd.as_fd())?;
        if !m.is_file || m.size > MANIFEST_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unreadable manifest (not a file, or too large)",
            ));
        }
        let mut s = String::new();
        std::fs::File::from(fd).take(MANIFEST_MAX).read_to_string(&mut s)?;
        parse(&s).map(Some)
    }

    /// At `rescan`: puts back, from the manifest, the identity (and tags, favorite) of the items that lost it, and
    /// the metadata of the trash slots. `start`: only this subtree (trash included if it is
    /// missing). Without a manifest: does nothing.
    pub(super) fn apply_manifest(&self, start: Option<&SafePath>, readers: usize) -> io::Result<ManifestApplied> {
        let Some((man, bad_lines)) = self.read_manifest()? else {
            return Ok(ManifestApplied::default());
        };
        let mut rep = ManifestApplied {
            bad_lines,
            ..ManifestApplied::default()
        };
        let trash = self.trash_root()?;
        let (main, inside) = (walk(self)?, walk(&trash)?);
        // 1st pass: every identity present, everywhere, before changing anything.
        let mut taken: HashSet<[u8; 16]> = main
            .iter()
            .chain(inside.iter())
            .filter_map(|(_, m)| m.id.map(|i| i.0))
            .collect();
        let under = |p: &str| match start {
            None => true,
            Some(s) => p == s.as_str() || p.strip_prefix(s.as_str()).is_some_and(|r| r.starts_with('/')),
        };
        // Outside the rescanned subtree (the trash is part of a whole rescan only): left as it is, and never read.
        let skip = |zone: Zone, p: &str| (zone == Zone::Trash && start.is_some()) || (zone == Zone::Main && !under(p));
        let zones: [(Zone, &Root, &Items); 2] = [(Zone::Main, self, &main), (Zone::Trash, &trash, &inside)];
        // Contents to prove (file without identity, same size and second, sum known), read in parallel up front.
        let mut jobs: Vec<(&Root, &SafePath)> = Vec::new();
        let mut job_of: HashMap<(Zone, String), usize> = HashMap::new();
        for (zone, root, items) in zones {
            for (p, m) in items.iter() {
                let (Some(p), true, None) = (p, m.is_file, m.id) else {
                    continue;
                };
                if skip(zone, p.as_str()) {
                    continue;
                }
                let k = (zone, p.as_str().to_owned());
                if let Some(e) = man.get(&k)
                    && e.sort == Some(Sort::File)
                    && !e.sha1.is_empty()
                    && (e.size, e.mtime) == (m.size, m.mtime)
                {
                    job_of.insert(k, jobs.len());
                    jobs.push((root, p));
                }
            }
        }
        let sums = sums_in_parallel(&jobs, readers)?;
        // 2nd pass: items without identity, in order (an identity is never given twice).
        for (zone, root, items) in zones {
            for (p, m) in items.iter().filter(|(_, m)| m.is_dir || m.is_file) {
                let k = key(p);
                if skip(zone, &k) {
                    continue;
                }
                let Some(e) = man.get(&(zone, k.clone())) else { continue };
                let fd = root.open_any(p.as_ref())?;
                if e.sort == Some(Sort::Slot) {
                    if m.is_dir && xattr_get(fd.as_fd(), XATTR_TRASH_PATH)?.is_none() && !e.trash[0].is_empty() {
                        for (name, v) in [
                            (XATTR_TRASH_PATH, &e.trash[0]),
                            (XATTR_TRASH_TIME, &e.trash[1]),
                            (XATTR_TRASH_BY, &e.trash[2]),
                        ] {
                            if !v.is_empty() {
                                xattr_set(fd.as_fd(), name, v.as_bytes())?;
                            }
                        }
                        rep.trash_slots += 1;
                    }
                    continue;
                }
                let same = match e.sort {
                    Some(Sort::Dir) => m.is_dir,
                    Some(Sort::File) => m.is_file && m.size == e.size && m.mtime == e.mtime,
                    _ => false,
                };
                let Some(id) = e.id.filter(|_| m.id.is_none() && same) else {
                    continue;
                };
                if taken.contains(&id) {
                    continue; // held by another item (moved, xattrs kept): never stolen
                }
                // Sum known: the content decides (read above, before any change: a refusal changes nothing).
                let f = std::fs::File::from(fd);
                let proven = if m.is_file && !e.sha1.is_empty() {
                    let actual = job_of.get(&(zone, k.clone())).and_then(|&i| sums.get(i));
                    if actual != Some(&e.sha1) {
                        rep.content_changed += 1;
                        continue; // same size and second, other content: new identity (assigned by rescan)
                    }
                    true
                } else {
                    false
                };
                let fd = f.as_fd();
                if proven {
                    // Same content: the time to the nanosecond and the sum record, hence the same ETag as before.
                    set_mtime(fd, e.mtime, e.nsec)?;
                    record_sha1(fd, &e.sha1)?;
                    rep.etags_kept += 1;
                }
                if !e.tags.is_empty() {
                    xattr_set(fd, XATTR_TAGS, e.tags.join("\n").as_bytes())?;
                }
                if e.favorite {
                    xattr_set(fd, XATTR_FAVORITE, b"1")?;
                }
                // Identity last: this pass only visits items without one, so an error above must leave the item
                // retryable by the next `rescan` (a written identity would take it out of reach for good).
                taken.insert(id);
                xattr_set(fd, XATTR_ID, &id)?;
                rep.ids += 1;
            }
        }
        Ok(rep)
    }
}

/// Fuzzing entry point (`fuzzing` feature): an arbitrary manifest never crashes the parser, and every
/// retained entry is rewritten then reread identically.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn fuzz(data: &[u8]) {
    let Ok((man, _)) = parse(&String::from_utf8_lossy(data)) else {
        return;
    };
    for ((zone, path), e) in &man {
        let again = parse_line(line(*zone, path, e).trim_end_matches('\n'), true);
        if again.as_ref() != Some(&((*zone, path.clone()), e.clone())) {
            panic!("entry not reread identically: {e:?}");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

    fn sp(s: &str) -> SafePath {
        SafePath::new(s).unwrap()
    }

    /// Tree copy like a backup by file copy (rclone to pCloud, `cp`, `rsync` without `-X`): contents
    /// and names only, **no xattrs**, times truncated to the second. Everything goes, reserved names included.
    pub(crate) fn copy_without_xattrs(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for e in std::fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            let (from, to) = (e.path(), dst.join(e.file_name()));
            let md = e.metadata().unwrap();
            if md.is_dir() {
                copy_without_xattrs(&from, &to);
            } else {
                std::fs::write(&to, std::fs::read(&from).unwrap()).unwrap();
            }
            let secs = md.modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs();
            std::fs::File::open(&to)
                .unwrap()
                .set_modified(UNIX_EPOCH + Duration::from_secs(secs))
                .unwrap();
        }
    }

    /// Everything the manifest must give back: each item's identity (root included), tags, favorite; and the trash.
    type Snapshot = (
        Vec<(String, Option<[u8; 16]>, Vec<String>, bool)>,
        Vec<(String, Option<String>, i64, String)>,
    );

    fn snapshot(r: &Root) -> Snapshot {
        let mut main: Vec<_> = walk(r)
            .unwrap()
            .into_iter()
            .map(|(p, m)| {
                let (tags, fav) = r.labels(p.as_ref()).unwrap();
                (key(&p), m.id.map(|i| i.0), tags, fav)
            })
            .collect();
        main.sort();
        let mut trash: Vec<_> = r
            .trash_list()
            .unwrap()
            .into_iter()
            .map(|t| (t.name, t.origin.map(|o| o.as_str().to_owned()), t.deleted, t.by))
            .collect();
        trash.sort();
        (main, trash)
    }

    /// ETag of every file of the space, as clients see it.
    fn etags(r: &Root) -> Vec<(String, String)> {
        let mut v: Vec<_> = walk(r)
            .unwrap()
            .into_iter()
            .filter(|(_, m)| m.is_file)
            .map(|(p, m)| (key(&p), crate::etag::of(&m)))
            .collect();
        v.sort();
        v
    }

    fn tree(dir: &Path) -> Root {
        let r = Root::open_dir(dir).unwrap();
        r.ensure_layout().unwrap();
        r
    }

    /// A realistic tree: nested folders, names with spaces, accents and `%`, tags, favorites, a tag on the root, a
    /// file and a folder (with its contents) in the trash.
    fn sample(dir: &Path) -> Root {
        let r = tree(dir);
        r.mkdir(&sp("Docs")).unwrap();
        r.mkdir(&sp("Docs/Sous dossier")).unwrap();
        for (p, body) in [
            ("Docs/facture été 2026 %.pdf", &b"pdf"[..]),
            ("Docs/Sous dossier/b.txt", b"b"),
            ("Docs/Sous dossier/c.txt", b"c"),
            ("racine.txt", b"r"),
            ("jeté.txt", b"j"),
        ] {
            r.atomic_write(&sp(p), &mut &body[..]).unwrap();
        }
        r.set_tags(
            Some(&sp("Docs/facture été 2026 %.pdf")),
            &["facture".into(), "impôts".into()],
        )
        .unwrap();
        r.set_favorite(Some(&sp("Docs")), true).unwrap();
        r.set_tags(None, &["perso".into()]).unwrap();
        r.trash(&sp("jeté.txt"), "alice").unwrap();
        r.trash(&sp("Docs/Sous dossier"), "bob").unwrap();
        // As in production: the user's root has an identity (assigned by `rescan`).
        assert_eq!(r.rescan(None).unwrap().ids_assigned, 1);
        r
    }

    #[test]
    fn copy_restore_brings_everything_back() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ra = sample(a.path());
        let (before, etags_before) = (snapshot(&ra), etags(&ra));
        let rep = ra.write_manifest().unwrap();
        assert_eq!((rep.files, rep.dirs, rep.trashed), (2, 2, 4)); // root and Docs; jeté.txt, Sous dossier, b, c
        let rep = ra.write_manifest().unwrap(); // rewritten in place, no temporary left behind
        assert_eq!(rep.trashed, 4);
        assert_eq!(std::fs::read_dir(a.path().join(TMP_DIR)).unwrap().count(), 0);

        // Copy without xattrs: everything is lost, the trash included.
        copy_without_xattrs(a.path(), b.path());
        let rb = tree(b.path());
        let lost = rb.verify(None).unwrap();
        assert_eq!(lost.missing_id.len(), 4, "root, Docs and two files without identity");
        assert_ne!(
            etags(&rb),
            etags_before,
            "the copy loses the ETags (time to the second, no sum)"
        );
        assert!(rb.trash_list().unwrap().iter().all(|t| t.origin.is_none()));

        let r = rb.rescan(None).unwrap();
        assert_eq!(
            (r.manifest.ids, r.manifest.trash_slots, r.manifest.bad_lines),
            (8, 2, 0)
        ); // root, Docs, 2 files; 4 in the trash
        assert_eq!((r.ids_assigned, r.duplicates), (0, 0), "no new identity: all recovered");
        assert_eq!(
            (r.manifest.etags_kept, r.manifest.content_changed),
            (5, 0),
            "every file written by the server (2 in the space, 3 in the trash): content proven identical"
        );
        assert_eq!(
            etags(&rb),
            etags_before,
            "same ETags: clients re-download nothing, no conflict"
        );
        assert!(
            rb.verify(None).unwrap().modified.is_empty(),
            "the sum records match the restored files"
        );
        assert_eq!(
            snapshot(&rb),
            before,
            "identities, tags, favorites and trash identical to the original"
        );
        assert!(rb.verify(None).unwrap().missing_id.is_empty());
        // The trash restores as before, with its identity.
        let slot = rb
            .trash_list()
            .unwrap()
            .into_iter()
            .find(|t| t.name == "jeté.txt")
            .unwrap()
            .slot;
        assert_eq!(rb.trash_restore(&slot).unwrap().as_str(), "jeté.txt");
    }

    #[test]
    fn manifest_never_steals_overrides_or_guesses() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ra = sample(a.path());
        let id_of = |r: &Root, p: &str| r.meta(Some(&sp(p))).unwrap().id.map(|i| i.0);
        let facture = "Docs/facture été 2026 %.pdf";
        let (orig_facture, orig_racine) = (id_of(&ra, facture), id_of(&ra, "racine.txt"));
        ra.write_manifest().unwrap();
        copy_without_xattrs(a.path(), b.path());
        let rb = tree(b.path());

        // Content changed since the snapshot: different size, or same size but different time → different content.
        std::fs::write(b.path().join("racine.txt"), b"plus long").unwrap();
        let d = b.path().join("Docs");
        std::fs::File::open(&d)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(1))
            .unwrap(); // folder: time ignored
        // Moved after the snapshot, xattrs kept: the identity is held elsewhere, it must not be reused here.
        rb.atomic_write(&sp("déplacé.pdf"), &mut &b"pdf"[..]).unwrap();
        let moved = openat(rb.fd.as_fd(), c"d\xc3\xa9plac\xc3\xa9.pdf", libc::O_RDONLY, 0).unwrap();
        xattr_set(moved.as_fd(), XATTR_ID, &orig_facture.unwrap()).unwrap();

        let r = rb.rescan(None).unwrap();
        assert_eq!(
            id_of(&rb, "déplacé.pdf"),
            orig_facture,
            "the item that kept its xattrs keeps its identity"
        );
        assert_ne!(id_of(&rb, facture), orig_facture, "never stolen");
        assert_ne!(id_of(&rb, "racine.txt"), orig_racine, "size changed: new identity");
        assert_eq!(
            id_of(&rb, "Docs"),
            id_of(&ra, "Docs"),
            "folder recovered despite its time"
        );
        assert!(r.ids_assigned >= 2 && r.duplicates == 0);
        let v = rb.verify(None).unwrap();
        assert!(v.missing_id.is_empty() && v.duplicates.is_empty());

        // Same size, different time (to the second): different content, new identity.
        let c = tempfile::tempdir().unwrap();
        copy_without_xattrs(a.path(), c.path());
        let rc = tree(c.path());
        std::fs::File::open(c.path().join("racine.txt"))
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(5))
            .unwrap();
        // An existing xattr always wins: identity set by hand before the rescan, kept.
        let own = [0x42; 16];
        let f = openat(rc.fd.as_fd(), c"Docs", libc::O_RDONLY, 0).unwrap();
        xattr_set(f.as_fd(), XATTR_ID, &own).unwrap();
        rc.rescan(None).unwrap();
        assert_ne!(id_of(&rc, "racine.txt"), orig_racine);
        assert_eq!(id_of(&rc, "Docs"), Some(own));
        assert_eq!(id_of(&rc, facture), orig_facture);

        // `rescan --path`: only this subtree, neither the rest nor the trash.
        let e = tempfile::tempdir().unwrap();
        copy_without_xattrs(a.path(), e.path());
        let re = tree(e.path());
        let r = re.rescan(Some(&sp("Docs"))).unwrap();
        assert_eq!((r.manifest.ids, r.manifest.trash_slots), (2, 0));
        assert_eq!(id_of(&re, facture), orig_facture);
        assert_eq!(id_of(&re, "racine.txt"), None);
    }

    #[test]
    fn manifest_is_reserved_and_read_with_suspicion() {
        let a = tempfile::tempdir().unwrap();
        let ra = sample(a.path());
        ra.write_manifest().unwrap();
        // Reserved: refused as a path, absent from listings; 0600 file.
        assert!(SafePath::new(MANIFEST).is_err());
        assert!(ra.read_dir(None).unwrap().all(|e| e.unwrap().0 != MANIFEST));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(a.path().join(MANIFEST)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        // Unknown header: rescan refuses (nothing is guessed, no identity silently lost).
        std::fs::write(a.path().join(MANIFEST), "beastbox-manifest 9\n").unwrap();
        assert_eq!(ra.rescan(None).unwrap_err().kind(), io::ErrorKind::InvalidData);
        std::fs::write(a.path().join(MANIFEST), [0xff, 0xfe]).unwrap();
        assert!(ra.rescan(None).is_err());
        // Not a file: refused too.
        std::fs::remove_file(a.path().join(MANIFEST)).unwrap();
        std::fs::create_dir(a.path().join(MANIFEST)).unwrap();
        assert!(ra.rescan(None).is_err());
    }

    /// The sum decides when the manifest holds one: same content → ETag kept; same size and second but another
    /// content → new identity (a link must not follow another content). Without a sum (file arrived outside the
    /// application, or format 1 manifest): identity recovered, ETag changed (clients re-download, nothing else).
    #[test]
    fn content_decides_when_the_sum_is_known() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ra = sample(a.path());
        std::fs::write(a.path().join("dehors.txt"), b"arrived over SSH").unwrap();
        ra.rescan(None).unwrap(); // identity, but no sum: not written by the server
        let id_of = |r: &Root, p: &str| r.meta(Some(&sp(p))).unwrap().id.map(|i| i.0);
        let etag_of = |r: &Root, p: &str| crate::etag::of(&r.meta(Some(&sp(p))).unwrap());
        let (racine, dehors) = (id_of(&ra, "racine.txt"), id_of(&ra, "dehors.txt"));
        let facture = "Docs/facture été 2026 %.pdf";
        let facture_etag = etag_of(&ra, facture);
        ra.write_manifest().unwrap();
        copy_without_xattrs(a.path(), b.path());
        let rb = tree(b.path());
        // Same size, same second, another content: only the sum can tell.
        let path = b.path().join("racine.txt");
        let secs = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::fs::write(&path, b"R").unwrap();
        std::fs::File::open(&path).unwrap().set_modified(secs).unwrap();

        let r = rb.rescan(None).unwrap();
        assert_eq!((r.manifest.etags_kept, r.manifest.content_changed), (4, 1));
        assert_ne!(id_of(&rb, "racine.txt"), racine, "another content: new identity");
        assert!(id_of(&rb, "racine.txt").is_some());
        assert_eq!(std::fs::read(&path).unwrap(), b"R", "rescan never touches a content");
        assert_eq!(etag_of(&rb, facture), facture_etag);
        assert_eq!(
            id_of(&rb, "dehors.txt"),
            dehors,
            "no sum: identity recovered on size and time"
        );
        assert_eq!(r.ids_assigned, 1, "racine.txt only");

        // Format 1 manifest (before 0.13.0): identities recovered, ETags not.
        let c = tempfile::tempdir().unwrap();
        copy_without_xattrs(a.path(), c.path());
        let v2 = std::fs::read_to_string(c.path().join(MANIFEST)).unwrap();
        let mut v1 = format!("{HEADER_V1}\n");
        for l in v2.lines().skip(1) {
            v1.push_str(l.rsplitn(3, '\t').nth(2).unwrap());
            v1.push('\n');
        }
        std::fs::write(c.path().join(MANIFEST), v1).unwrap();
        let rc = tree(c.path());
        let r = rc.rescan(None).unwrap();
        assert_eq!(
            (r.manifest.etags_kept, r.manifest.content_changed, r.ids_assigned),
            (0, 0, 0)
        );
        assert_eq!(id_of(&rc, facture), id_of(&ra, facture));
        assert_ne!(etag_of(&rc, facture), facture_etag);
    }

    /// A manifest coming back from external storage is untrusted: its tags and `trash.*` fields are bounded on read,
    /// so a hostile one cannot plant an attribute that `labels` or `trash_list` then refuses to read.
    #[test]
    fn hostile_manifest_cannot_plant_oversized_attributes() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ra = sample(a.path());
        let facture = "Docs/facture été 2026 %.pdf";
        let (id, m) = {
            let m = ra.meta(Some(&sp(facture))).unwrap();
            (m.id.map(|i| i.0), m)
        };
        copy_without_xattrs(a.path(), b.path());
        let rb = tree(b.path());
        let mut tags: Vec<String> = (0..25).map(|i| format!("t{i}")).collect();
        tags.push("z".repeat(70_000));
        let e = Entry {
            sort: Some(Sort::File),
            size: m.size,
            mtime: m.mtime,
            nsec: m.mtime_nsec,
            id,
            tags,
            ..Entry::default()
        };
        let slot = rb.trash_list().unwrap().first().unwrap().name.clone();
        let over = Entry {
            sort: Some(Sort::Slot),
            trash: ["p".repeat(70_000), String::new(), String::new()],
            ..Entry::default()
        };
        std::fs::write(
            b.path().join(MANIFEST),
            format!(
                "{HEADER}\n{}\n{}\n",
                line(Zone::Main, facture, &e),
                line(Zone::Trash, &slot, &over)
            ),
        )
        .unwrap();

        let r = rb.rescan(None).unwrap();
        assert_eq!(
            (r.manifest.ids, r.manifest.trash_slots, r.manifest.bad_lines),
            (1, 0, 1),
            "the file still gets its identity, the oversized trash line is refused and counted"
        );
        let (tags, _) = rb.labels(Some(&sp(facture))).unwrap();
        assert_eq!(tags.len(), MAX_TAGS, "at most 20 tags written: {tags:?}");
        assert!(tags.iter().all(|t| normalize_tag(t).as_deref() == Some(t.as_str())));
        // Every attribute stays readable (a 70 KB one would make `labels`/`trash_list` fail for the whole tree).
        assert_eq!(rb.trash_list().unwrap().len(), 2);
        assert!(rb.verify(None).unwrap().duplicates.is_empty());
    }

    /// `rescan` interrupted after the time and the sum but before the identity (the order the code writes them in):
    /// the next run still recovers the identity, the ETag and the tags — nothing is out of reach.
    #[test]
    fn rescan_replays_a_half_applied_item() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ra = sample(a.path());
        let facture = "Docs/facture été 2026 %.pdf";
        let before = ra.meta(Some(&sp(facture))).unwrap();
        ra.write_manifest().unwrap();
        copy_without_xattrs(a.path(), b.path());
        let rb = tree(b.path());
        let fd = rb.open_any(Some(&sp(facture))).unwrap();
        set_mtime(fd.as_fd(), before.mtime, before.mtime_nsec).unwrap();
        record_sha1(fd.as_fd(), before.sha1.as_deref().unwrap()).unwrap();
        drop(fd);
        assert!(rb.meta(Some(&sp(facture))).unwrap().id.is_none());

        let r = rb.rescan(None).unwrap();
        assert_eq!(r.ids_assigned, 0, "every identity came back from the manifest");
        let after = rb.meta(Some(&sp(facture))).unwrap();
        assert_eq!(after.id, before.id, "the second run recovers it");
        assert_eq!(crate::etag::of(&after), crate::etag::of(&before), "same ETag");
        assert_eq!(rb.labels(Some(&sp(facture))).unwrap().0, ["facture", "impôts"]);
    }

    /// `rescan --path` stops at its folder: a neighbour whose name starts the same (`Docs` / `Docsx`) is left alone,
    /// even though the manifest holds an entry for it.
    #[test]
    fn rescan_path_stops_at_its_folder_boundary() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ra = tree(a.path());
        for d in ["Docs", "Docsx"] {
            ra.mkdir(&sp(d)).unwrap();
        }
        for p in ["Docs/a.txt", "Docsx/a.txt"] {
            ra.atomic_write(&sp(p), &mut &b"x"[..]).unwrap();
        }
        ra.rescan(None).unwrap();
        let ids = |r: &Root| ["Docs/a.txt", "Docsx/a.txt"].map(|p| r.meta(Some(&sp(p))).unwrap().id);
        let before = ids(&ra);
        ra.write_manifest().unwrap();
        copy_without_xattrs(a.path(), b.path());
        let rb = tree(b.path());

        let r = rb.rescan(Some(&sp("Docs"))).unwrap();
        assert_eq!(r.manifest.ids, 2, "Docs and Docs/a.txt only");
        assert_eq!(ids(&rb)[0], before[0]);
        assert_eq!(ids(&rb)[1], None, "Docsx is outside the subtree");
        // The entry was there all along: a whole rescan gives the neighbour its identity back.
        rb.rescan(None).unwrap();
        assert_eq!(ids(&rb)[1], before[1]);
    }

    /// One identity on two paths in the manifest: it is given once (never twice), and `verify` sees no duplicate.
    #[test]
    fn a_manifest_never_gives_one_identity_twice() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ra = sample(a.path());
        let facture = "Docs/facture été 2026 %.pdf";
        let id = ra.meta(Some(&sp(facture))).unwrap().id.unwrap();
        let other = ra.meta(Some(&sp("racine.txt"))).unwrap().id.unwrap();
        let hex = |i: [u8; 16]| i.iter().map(|b| format!("{b:02x}")).collect::<String>();
        ra.write_manifest().unwrap();
        copy_without_xattrs(a.path(), b.path());
        // As a manifest edited by hand could carry it: the same identity on `racine.txt` and on the invoice.
        let text = std::fs::read_to_string(b.path().join(MANIFEST)).unwrap();
        let forged: String = text
            .lines()
            .map(|l| {
                if l.split('\t').nth(2) == Some("racine.txt") {
                    l.replacen(&hex(other.0), &hex(id.0), 1)
                } else {
                    l.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(b.path().join(MANIFEST), format!("{forged}\n")).unwrap();

        let rb = tree(b.path());
        let r = rb.rescan(None).unwrap();
        let held = ["racine.txt", facture].map(|p| rb.meta(Some(&sp(p))).unwrap().id);
        assert_eq!(r.duplicates, 0, "never handed twice, so nothing to reassign");
        assert_eq!(
            held.iter().filter(|i| **i == Some(id)).count(),
            1,
            "given once: {held:?}"
        );
        assert!(
            held.iter().all(Option::is_some) && rb.verify(None).unwrap().duplicates.is_empty(),
            "both end with an identity, no duplicate"
        );
    }

    /// Parallel reading of the contents: many more files than readers, one in seven changed after the backup (same
    /// size and second): every decision falls on the right file. An unreadable file fails the rescan before any change.
    #[test]
    fn contents_read_in_parallel_decide_file_by_file() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ra = tree(a.path());
        ra.mkdir(&sp("P")).unwrap();
        let n = RESCAN_READERS * 6 + 3;
        for i in 0..n {
            ra.atomic_write(&sp(&format!("P/f{i}.bin")), &mut format!("{i:04}").as_bytes())
                .unwrap();
        }
        ra.rescan(None).unwrap();
        let ids: Vec<_> = (0..n)
            .map(|i| ra.meta(Some(&sp(&format!("P/f{i}.bin")))).unwrap().id)
            .collect();
        ra.write_manifest().unwrap();
        copy_without_xattrs(a.path(), b.path());
        let changed: Vec<usize> = (0..n).filter(|i| i % 7 == 3).collect();
        for &i in &changed {
            let path = b.path().join(format!("P/f{i}.bin"));
            let secs = std::fs::metadata(&path).unwrap().modified().unwrap();
            std::fs::write(&path, format!("{:04}", i + 5000)).unwrap(); // same size
            std::fs::File::open(&path).unwrap().set_modified(secs).unwrap();
        }
        let rb = tree(b.path());

        // SAFETY: plain getter. Unreadable file: the rescan fails, and no identity was set before the failure.
        if unsafe { libc::geteuid() } != 0 {
            let locked = b.path().join("P/f1.bin");
            std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
            assert!(rb.rescan(None).is_err());
            assert!((0..n).all(|i| i == 1 || rb.meta(Some(&sp(&format!("P/f{i}.bin")))).unwrap().id.is_none()));
            std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        }

        // The same restore read by a single reader decides exactly the same.
        let c = tempfile::tempdir().unwrap();
        copy_without_xattrs(b.path(), c.path());
        let rc = tree(c.path());
        let one = rc.rescan_with(None, 1).unwrap();
        let r = rb.rescan(None).unwrap();
        assert_eq!(
            (r.manifest.content_changed, r.manifest.etags_kept),
            (changed.len() as u64, (n - changed.len()) as u64)
        );
        assert_eq!(one.manifest, r.manifest);
        for i in (0..n).filter(|i| !changed.contains(i)) {
            let p = sp(&format!("P/f{i}.bin"));
            assert_eq!(rc.meta(Some(&p)).unwrap().id, rb.meta(Some(&p)).unwrap().id, "file {i}");
        }
        for (i, id) in ids.iter().enumerate() {
            let now = rb.meta(Some(&sp(&format!("P/f{i}.bin")))).unwrap().id;
            assert_eq!(now == *id, !changed.contains(&i), "file {i}");
        }
    }

    /// Property: for any content and any change made between the backup and the restore, the identity follows the
    /// content (never given to another content when the sum is known), the ETag is kept exactly when the content is
    /// the same, and the restored content is never altered.
    #[test]
    fn identity_and_etag_follow_the_content() {
        use proptest::prelude::*;
        use proptest::test_runner::{Config, TestRunner};
        #[derive(Debug, Clone, Copy)]
        enum Change {
            None,
            SameSizeOther,
            OtherSize,
            OtherSecond,
        }
        let change = prop_oneof![
            Just(Change::None),
            Just(Change::SameSizeOther),
            Just(Change::OtherSize),
            Just(Change::OtherSecond)
        ];
        let cases = std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(32);
        let mut runner = TestRunner::new(Config::with_cases(cases));
        let strategy = (prop::collection::vec(any::<u8>(), 1..256), change, any::<bool>());
        let r = runner.run(&strategy, |(body, change, by_server)| {
            let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let ra = tree(a.path());
            if by_server {
                ra.atomic_write(&sp("f.bin"), &mut body.as_slice()).unwrap();
            } else {
                std::fs::write(a.path().join("f.bin"), &body).unwrap();
            }
            ra.rescan(None).unwrap();
            let m = ra.meta(Some(&sp("f.bin"))).unwrap();
            prop_assert_eq!(m.sha1.is_some(), by_server);
            ra.write_manifest().unwrap();
            copy_without_xattrs(a.path(), b.path());
            let path = b.path().join("f.bin");
            let secs = std::fs::metadata(&path).unwrap().modified().unwrap();
            let mut other = body.clone();
            match change {
                Change::None => {}
                Change::SameSizeOther => {
                    if let Some(x) = other.first_mut() {
                        *x = x.wrapping_add(1);
                    }
                }
                Change::OtherSize => other.push(0),
                Change::OtherSecond => {}
            }
            std::fs::write(&path, &other).unwrap();
            let when = match change {
                Change::OtherSecond => secs + Duration::from_secs(1),
                _ => secs,
            };
            std::fs::File::open(&path).unwrap().set_modified(when).unwrap();
            let rb = tree(b.path());
            rb.rescan(None).unwrap();
            let after = rb.meta(Some(&sp("f.bin"))).unwrap();
            prop_assert_eq!(std::fs::read(&path).unwrap(), other.clone(), "content never altered");
            let same_content = other == body;
            let kept = after.id == m.id;
            let expect_kept = match change {
                Change::None => true,
                Change::SameSizeOther => !by_server, // no sum: size and second only (accepted limit)
                Change::OtherSize | Change::OtherSecond => false,
            };
            prop_assert_eq!(kept, expect_kept, "identity");
            let etag_kept = crate::etag::of(&after) == crate::etag::of(&m);
            prop_assert_eq!(etag_kept, by_server && same_content && kept, "ETag");
            Ok(())
        });
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn format_roundtrip_and_bad_lines() {
        let e = Entry {
            sort: Some(Sort::File),
            size: 42,
            mtime: -3,
            nsec: 999_999_999,
            sha1: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d".into(),
            id: Some([0xab; 16]),
            favorite: true,
            tags: vec!["impôts".into(), "a b".into()],
            trash: Default::default(),
        };
        for path in ["a b/é%c.txt", "x", "nom 100%"] {
            let l = line(Zone::Main, path, &e);
            assert_eq!(l.matches('\t').count(), 12);
            assert!(l.ends_with('\n') && !l.trim_end_matches('\n').contains('\n'));
            assert_eq!(
                parse_line(l.trim_end_matches('\n'), true),
                Some(((Zone::Main, path.to_owned()), e.clone()))
            );
        }
        let slot = Entry {
            sort: Some(Sort::Slot),
            trash: ["Docs/a\tb".into(), "1700000000".into(), "alice".into()],
            ..Entry::default()
        };
        let l = line(Zone::Trash, "0123abcd", &slot);
        assert_eq!(
            parse_line(l.trim_end_matches('\n'), true),
            Some(((Zone::Trash, "0123abcd".to_owned()), slot))
        );

        let good = line(Zone::Main, "a", &e);
        let good = good.trim_end_matches('\n');
        let sum = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
        // Bounds of the two format 2 fields: nanoseconds 0 and 999,999,999 accepted, sum empty or 40 lowercase hex.
        for (from, to) in [("\t999999999\t", "\t0\t"), (sum, "")] {
            let l = good.replacen(from, to, 1);
            assert!(parse_line(&l, true).is_some(), "{l:?}");
        }
        // Format 1: the same line without the last two fields; neither nanoseconds nor sum.
        let v1 = good.rsplitn(3, '\t').nth(2).unwrap();
        let (_, old) = parse_line(v1, false).unwrap();
        assert_eq!((old.nsec, old.sha1.as_str(), old.id), (0, "", e.id));
        assert_eq!(parse_line(good, false), None, "format 2 line in a format 1 file");
        assert_eq!(parse_line(v1, true), None, "format 1 line in a format 2 file");
        // Tags and `trash.*` are bounded on read, as a write bounds them: a manifest from external storage must not
        // plant an attribute that `labels` or `trash_list` then refuses to read.
        let many = Entry {
            tags: (0..25).map(|i| format!("t{i}")).collect(),
            ..e.clone()
        };
        let (_, kept) = parse_line(line(Zone::Main, "a", &many).trim_end_matches('\n'), true).unwrap();
        assert_eq!(kept.tags.len(), MAX_TAGS);
        let mixed = Entry {
            tags: vec!["x".repeat(33), " B  c ".into()],
            ..e.clone()
        };
        let (_, kept) = parse_line(line(Zone::Main, "a", &mixed).trim_end_matches('\n'), true).unwrap();
        assert_eq!(kept.tags, ["b c"], "too long dropped, the others normalized on read");
        let over = line(
            Zone::Trash,
            "0123abcd",
            &Entry {
                sort: Some(Sort::Slot),
                trash: ["p".repeat(TRASH_FIELD_MAX + 1), String::new(), String::new()],
                ..Entry::default()
            },
        );
        assert_eq!(
            parse_line(over.trim_end_matches('\n'), true),
            None,
            "trash field over the bound"
        );
        // At the bound: kept, every byte.
        let at = line(
            Zone::Trash,
            "0123abcd",
            &Entry {
                sort: Some(Sort::Slot),
                trash: ["p".repeat(TRASH_FIELD_MAX), String::new(), String::new()],
                ..Entry::default()
            },
        );
        let (_, kept) = parse_line(at.trim_end_matches('\n'), true).expect("trash field at the bound");
        assert_eq!(kept.trash[0].len(), TRASH_FIELD_MAX);
        let bad = [
            "",
            "m\tf\ta",                                  // too few fields
            &good.replacen("m\t", "x\t", 1),            // unknown zone
            &good.replacen("\tf\t", "\ts\t", 1),        // trash slot outside the trash
            &good.replacen("\t42\t", "\t-1\t", 1),      // negative size
            &good.replacen(&"ab".repeat(16), "zz", 1),  // invalid identity
            &good.replacen("\t1\t", "\toui\t", 1),      // invalid favorite
            &good.replacen("\ta\t", "\t..%2Fetc\t", 1), // path refused by SafePath
            &good.replacen("\ta\t", "\t.trash%2Fx\t", 1),
            &good.replacen("\ta\t", "\t%FF\t", 1),                // invalid UTF-8
            &good.replacen("\t999999999\t", "\t1000000000\t", 1), // nanoseconds: one above the bound
            &good.replacen("\t999999999\t", "\t-1\t", 1),
            &good.replacen("\t999999999\t", "\t\t", 1),
            &good.replacen(sum, &sum[1..], 1),                  // 39 characters
            &good.replacen(sum, &format!("{sum}0"), 1),         // 41
            &good.replacen(sum, &sum.to_uppercase(), 1),        // uppercase: not what the server records
            &good.replacen(sum, &format!("{}g", &sum[1..]), 1), // not hexadecimal
            &format!("{good}\textra"),                          // one field too many
        ];
        for l in bad {
            assert_eq!(parse_line(l, true), None, "{l:?}");
        }
        let text = format!("{HEADER}\n{good}\nn'importe quoi\n\n{good}\n");
        let (m, bad) = parse(&text).unwrap();
        assert_eq!((m.len(), bad), (1, 1));
        assert!(
            parse("").is_err() && parse("beastbox-manifest 3\n").is_err() && parse("beastbox-manifest 0\n").is_err()
        );
        assert_eq!(
            parse(&format!("{HEADER_V1}\n{v1}\n")).unwrap().0.len(),
            1,
            "format 1 still read"
        );
    }
}
