//! Writes (§0.2, §6): staged atomic writer, folders, trash, move, copy, ETag journal.
//! No operation overwrites or permanently deletes: whatever is replaced or deleted goes to `.trash/`.

use super::dir::meta_of;
use super::{
    FileId, Meta, Root, SafePath, TMP_DIR, TRASH_DIR, XATTR_CKSUM_PREFIX, XATTR_ID, cstr, cvt, fsync, openat, read_id,
    renameat, unlinkat, xattr_get, xattr_list, xattr_set,
};
use sha1::{Digest, Sha1};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, BufRead, Read, Seek, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::Path;
use std::sync::Mutex;

/// SHA-1 digest of the content, with the size and time at the moment of computing (so `verify` detects a
/// change outside the application): `<sha1 hex> <size> <mtime> <mtime_nsec>`.
pub(super) const XATTR_CKSUM_SHA1: &CStr = c"beastbox.cksum.sha1";
pub(super) const XATTR_TRASH_PATH: &CStr = c"beastbox.trash.path";
pub(super) const XATTR_TRASH_TIME: &CStr = c"beastbox.trash.time";
pub(super) const XATTR_TRASH_BY: &CStr = c"beastbox.trash.by";

/// Business errors carried in an `io::Error` (kind `Other`): the HTTP layer recognizes them with [`is`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Unsatisfied `If-Match` / `If-None-Match` / `Overwrite: F` → 412.
    Precondition,
    /// Checksum announced by the client differs from the received content → 400.
    Checksum,
    /// Moving a folder into its own subtree → 409.
    IntoItself,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Refused {}

/// One path inside the other: the destination in the source (a folder into itself), or the source in the
/// destination (an overwrite would first trash the destination, source included; found by the WebDAV model test).
fn nested(from: &SafePath, to: &SafePath) -> bool {
    let inside = |a: &SafePath, b: &SafePath| a.as_str().starts_with(&format!("{}/", b.as_str()));
    inside(to, from) || inside(from, to)
}

fn refused(r: Refused) -> io::Error {
    io::Error::other(r)
}

/// Is the error this business refusal?
pub fn is(e: &io::Error, r: Refused) -> bool {
    e.get_ref().and_then(|x| x.downcast_ref::<Refused>()) == Some(&r)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Result of a committed write.
#[derive(Debug)]
pub struct Written {
    pub id: FileId,
    /// True if the file did not exist (201), false if it was replaced (204).
    pub created: bool,
    pub meta: Meta,
    pub sha1: String,
}

/// Staged atomic write: the content goes into `.beastbox-tmp/`, the target is only replaced on `commit`
/// (`rename`), after `fsync`. Abandoned (drop without commit, error, client gone): the temporary is deleted.
pub struct AtomicWriter {
    tmpdir: Root,
    tmp_name: CString,
    file: File,
    parent: Root,
    name: CString,
    sha1: Sha1,
    len: u64,
    done: bool,
}

impl Drop for AtomicWriter {
    fn drop(&mut self) {
        if !self.done {
            // Cleanup failed: picked up again at startup (§0.2).
            let _ = unlinkat(self.tmpdir.fd.as_fd(), &self.tmp_name, 0);
        }
    }
}

impl AtomicWriter {
    pub fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf)?;
        self.sha1.update(buf);
        self.len += buf.len() as u64;
        Ok(())
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Commit: checks the announced sum and the precondition (on the target's state at that instant), copies the
    /// old file's xattrs (identity, tags, favorites; not the sums), sets the time, `fsync`, `rename`,
    /// `fsync` of the folder. shortcut: the precondition is checked right before the `rename`, without a lock: two
    /// simultaneous PUTs on the same file keep the last one (a window of a few µs); per-path lock if needed.
    pub fn commit(
        mut self,
        mtime: Option<i64>,
        expect_sha1: Option<&str>,
        precondition: impl FnOnce(Option<&Meta>) -> bool,
    ) -> io::Result<Written> {
        let sha1 = hex(&std::mem::take(&mut self.sha1).finalize());
        if expect_sha1.is_some_and(|e| !e.eq_ignore_ascii_case(&sha1)) {
            return Err(refused(Refused::Checksum));
        }
        let old = match openat(self.parent.fd.as_fd(), &self.name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
            Ok(fd) => Some(fd),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => None,
            Err(e) => return Err(e),
        };
        let old_meta = old.as_ref().map(|fd| meta_of(fd.as_fd())).transpose()?;
        if old_meta.as_ref().is_some_and(|m| !m.is_file) {
            return Err(io::Error::from(io::ErrorKind::IsADirectory));
        }
        if !precondition(old_meta.as_ref()) {
            return Err(refused(Refused::Precondition));
        }
        let fd = self.file.as_fd();
        let mut id = None;
        if let Some(old) = &old {
            for attr in xattr_list(old.as_fd())? {
                if attr.as_bytes().starts_with(XATTR_CKSUM_PREFIX) {
                    continue;
                }
                if let Some(v) = xattr_get(old.as_fd(), &attr)? {
                    xattr_set(fd, &attr, &v)?;
                }
            }
            id = read_id(old.as_fd())?;
        }
        let id = match id {
            Some(id) => id,
            None => {
                // Identity assigned at creation, by the server (§6).
                let id = FileId::random()?;
                xattr_set(fd, XATTR_ID, &id.0)?;
                id
            }
        };
        if let Some(t) = mtime {
            // Modification time: the one announced by the client (X-OC-Mtime).
            set_mtime(fd, t, 0)?;
        }
        let meta = record_sha1(fd, &sha1)?;
        self.file.sync_all()?;
        renameat(
            self.tmpdir.fd.as_fd(),
            &self.tmp_name,
            self.parent.fd.as_fd(),
            &self.name,
        )?;
        self.done = true;
        fsync(self.parent.fd.as_fd())?;
        Ok(Written {
            id,
            created: old.is_none(),
            meta: Meta {
                id: Some(id),
                sha1: Some(sha1.clone()),
                ..meta
            },
            sha1,
        })
    }
}

/// Sets the modification time (access time unchanged).
pub(super) fn set_mtime(fd: BorrowedFd<'_>, sec: i64, nsec: i64) -> io::Result<()> {
    let omit = libc::timespec {
        tv_sec: 0,
        tv_nsec: libc::UTIME_OMIT,
    };
    let times = [
        omit,
        libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        },
    ];
    // SAFETY: valid descriptor, array of two timespecs as futimens expects.
    cvt(unsafe { libc::futimens(fd.as_raw_fd(), times.as_ptr()) }).map(drop)
}

/// Records `sha1` as the sum of the current content, tied to its size and time (see [`recorded_sha1`]).
pub(super) fn record_sha1(fd: BorrowedFd<'_>, sha1: &str) -> io::Result<Meta> {
    let meta = meta_of(fd)?;
    let record = format!("{sha1} {} {} {}", meta.size, meta.mtime, meta.mtime_nsec);
    xattr_set(fd, XATTR_CKSUM_SHA1, record.as_bytes())?;
    Ok(meta)
}

/// SHA-1 of a whole file, read from its start (lowercase hexadecimal, as recorded at write time).
pub(super) fn sha1_of(f: &mut File) -> io::Result<String> {
    f.seek(io::SeekFrom::Start(0))?;
    let mut h = Sha1::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
    Ok(hex(&h.finalize()))
}

/// What a tree copy did: items written, and items of the source passed over (link, special file, name refused).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CopyReport {
    pub files: u64,
    pub dirs: u64,
    pub skipped: u64,
}

/// Recorded SHA-1 sum, if it still matches the content (size and time unchanged since the computation).
pub fn recorded_sha1(fd: BorrowedFd<'_>, m: &Meta) -> io::Result<Option<String>> {
    let Some(v) = xattr_get(fd, XATTR_CKSUM_SHA1)? else {
        return Ok(None);
    };
    let s = String::from_utf8_lossy(&v);
    let mut it = s.split(' ');
    let (sum, size, mt, ns) = (it.next(), it.next(), it.next(), it.next());
    let fresh =
        size == Some(&m.size.to_string()) && mt == Some(&m.mtime.to_string()) && ns == Some(&m.mtime_nsec.to_string());
    Ok(fresh.then(|| sum.unwrap_or_default().to_owned()))
}

impl Root {
    /// Prepares the write of `path`. The parent folder must exist (otherwise ENOENT → 409 on the HTTP side).
    pub fn writer(&self, path: &SafePath) -> io::Result<AtomicWriter> {
        let (parent, name) = path.split_parent();
        let parent = match parent {
            Some(p) => self.open_subdir(&p)?,
            None => self.try_clone()?,
        };
        let tmpdir = self.open_dir_raw(&cstr(TMP_DIR)?)?;
        let tmp_name = cstr(&FileId::random()?.to_string())?;
        let fd = openat(
            tmpdir.fd.as_fd(),
            &tmp_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        Ok(AtomicWriter {
            tmpdir,
            tmp_name,
            file: File::from(fd),
            parent,
            name: cstr(name)?,
            sha1: Sha1::new(),
            len: 0,
            done: false,
        })
    }

    /// Creates a folder (0700) with its identity and ETag. Already exists → EEXIST; parent missing → ENOENT.
    pub fn mkdir(&self, path: &SafePath) -> io::Result<Meta> {
        let (parent, name) = path.split_parent();
        let parent = match parent {
            Some(p) => self.open_subdir(&p)?,
            None => self.try_clone()?,
        };
        let c = cstr(name)?;
        // SAFETY: valid borrowed descriptor, NUL-terminated C string.
        cvt(unsafe { libc::mkdirat(parent.fd.as_raw_fd(), c.as_ptr(), 0o700) })?;
        let d = parent.open_dir_raw(&c)?;
        xattr_set(d.fd.as_fd(), XATTR_ID, &FileId::random()?.0)?;
        xattr_set(d.fd.as_fd(), super::dir::XATTR_ETAG, &FileId::random()?.0)?;
        fsync(parent.fd.as_fd())?;
        meta_of(d.fd.as_fd())
    }

    fn exists(&self, path: &SafePath) -> io::Result<bool> {
        match openat(
            self.fd.as_fd(),
            &cstr(path.as_str())?,
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        ) {
            Ok(_) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Deletes to the trash (§6): atomic `rename` into `.trash/<id>/<name>`, with the original path, date and
    /// author in the xattrs of the deletion folder. Identity and tags follow the item.
    pub fn trash(&self, path: &SafePath, by: &str) -> io::Result<()> {
        let (parent, name) = path.split_parent();
        let parent = match parent {
            Some(p) => self.open_subdir(&p)?,
            None => self.try_clone()?,
        };
        let trash = self.open_dir_raw(&cstr(TRASH_DIR)?)?;
        let slot = cstr(&FileId::random()?.to_string())?;
        // SAFETY: valid borrowed descriptor, NUL-terminated C string.
        cvt(unsafe { libc::mkdirat(trash.fd.as_raw_fd(), slot.as_ptr(), 0o700) })?;
        let r = (|| {
            let d = trash.open_dir_raw(&slot)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            xattr_set(d.fd.as_fd(), XATTR_TRASH_PATH, path.as_str().as_bytes())?;
            xattr_set(d.fd.as_fd(), XATTR_TRASH_TIME, now.to_string().as_bytes())?;
            xattr_set(d.fd.as_fd(), XATTR_TRASH_BY, by.as_bytes())?;
            let n = cstr(name)?;
            renameat(parent.fd.as_fd(), &n, d.fd.as_fd(), &n)?;
            fsync(d.fd.as_fd())?;
            fsync(parent.fd.as_fd())
        })();
        if r.is_err() {
            // SAFETY: valid borrowed descriptor, NUL-terminated C string; rmdir of an empty folder (or harmless failure).
            unsafe { libc::unlinkat(trash.fd.as_raw_fd(), slot.as_ptr(), libc::AT_REMOVEDIR) };
        }
        r
    }

    /// Moves or renames (atomic `rename`, identity kept). Existing destination: refused if
    /// `!overwrite`, otherwise it goes to the trash first (never a permanent overwrite). Returns true if
    /// a destination was replaced.
    pub fn rename(&self, from: &SafePath, to: &SafePath, overwrite: bool, by: &str) -> io::Result<bool> {
        if nested(from, to) {
            return Err(refused(Refused::IntoItself));
        }
        if from == to {
            return Ok(true);
        }
        // Source missing: error before touching the destination.
        if !self.exists(from)? {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        let replaced = self.exists(to)?;
        if replaced {
            if !overwrite {
                return Err(refused(Refused::Precondition));
            }
            self.trash(to, by)?;
        }
        let (fp, fname) = from.split_parent();
        let (tp, tname) = to.split_parent();
        let open = |p: Option<SafePath>| match p {
            Some(p) => self.open_subdir(&p),
            None => self.try_clone(),
        };
        let (fdir, tdir) = (open(fp)?, open(tp)?);
        renameat(fdir.fd.as_fd(), &cstr(fname)?, tdir.fd.as_fd(), &cstr(tname)?)?;
        fsync(tdir.fd.as_fd())?;
        fsync(fdir.fd.as_fd())?;
        Ok(replaced)
    }

    /// Copies a file or a folder (recursively). Copies are new items: new
    /// identities. Existing destination: like [`Root::rename`]. On a failure midway (quota, disk full, unreadable
    /// item), the partial copy goes to the trash, as for [`Root::restore_from`]: never half a folder left behind.
    /// shortcut: byte-by-byte copy (no copy_file_range / ZFS block cloning); optimize if measured slow.
    pub fn copy(&self, from: &SafePath, to: &SafePath, overwrite: bool, by: &str) -> io::Result<bool> {
        if nested(from, to) || from == to {
            return Err(refused(Refused::IntoItself));
        }
        let src = self.meta(Some(from))?;
        let replaced = self.exists(to)?;
        if replaced {
            if !overwrite {
                return Err(refused(Refused::Precondition));
            }
            self.trash(to, by)?;
        }
        let mut rep = CopyReport::default();
        if let Err(e) = self.copy_tree(self, from, src.is_dir, to, &mut rep) {
            if rep.files + rep.dirs > 0
                && let Err(t) = self.trash(to, by)
            {
                return Err(io::Error::other(format!(
                    "{e}; partial copy left at {}: {t}",
                    to.as_str()
                )));
            }
            return Err(e);
        }
        Ok(replaced)
    }

    /// Copies `from` of the tree `src` (this one or another: a snapshot, a restore folder) to `to` in this one, as
    /// new items written by the server (identity, SHA-1, time to the second kept). Neither files nor folders
    /// (links, devices…) and names refused by `SafePath` are skipped, and counted.
    fn copy_tree(
        &self,
        src: &Root,
        from: &SafePath,
        is_dir: bool,
        to: &SafePath,
        rep: &mut CopyReport,
    ) -> io::Result<()> {
        // Inside the copy, a name already taken (two source names with the same NFC form, or a client writing there
        // meanwhile) is passed over and counted; at the top of the copy, it fails the copy.
        let taken = |e: &io::Error, t: &SafePath| {
            t != to && (e.kind() == io::ErrorKind::AlreadyExists || is(e, Refused::Precondition))
        };
        let mut stack = vec![(from.clone(), to.clone(), is_dir)];
        while let Some((f, t, is_dir)) = stack.pop() {
            if is_dir {
                match self.mkdir(&t) {
                    Err(e) if taken(&e, &t) => {
                        rep.skipped += 1;
                        continue;
                    }
                    r => r?,
                };
                rep.dirs += 1;
                let mut entries = src.read_dir(Some(&f))?;
                for e in &mut entries {
                    let (name, m) = e?;
                    // Source read by its exact name (accents decomposed by a Mac included), written in NFC.
                    let (Ok(cf), Ok(ct)) = (
                        SafePath::exact(format!("{}/{name}", f.as_str())),
                        SafePath::new(&format!("{}/{name}", t.as_str())),
                    ) else {
                        rep.skipped += 1;
                        continue;
                    };
                    stack.push((cf, ct, m.is_dir));
                }
                rep.skipped += entries.skipped;
            } else {
                let (mut file, m) = src.open_file(&f)?;
                let mut w = self.writer(&t)?;
                let mut r = io::BufReader::with_capacity(64 * 1024, &mut file);
                loop {
                    let buf = r.fill_buf()?;
                    if buf.is_empty() {
                        break;
                    }
                    let n = buf.len();
                    w.write(buf)?;
                    r.consume(n);
                }
                match w.commit(Some(m.mtime), None, |old| old.is_none()) {
                    Err(e) if taken(&e, &t) => rep.skipped += 1,
                    r => {
                        r?;
                        rep.files += 1;
                    }
                }
            }
        }
        Ok(())
    }

    /// `beastbox restore`: copies `path` of `src` (a snapshot or a restore folder, outside this tree) to `to`, as
    /// new items: the current version is never touched, the copy gets new identities (no duplicate of the original's)
    /// and the clients see a new item. Missing parent folders are created; existing `to`: refused. On a failure midway
    /// (quota, disk full, unreadable source, a client writing the same name), the partial copy goes to the trash:
    /// recoverable, and never a deletion of what a client may have put in it meanwhile.
    pub fn restore_from(&self, src: &Root, path: &SafePath, to: &SafePath) -> io::Result<CopyReport> {
        let m = src.meta(Some(path))?;
        if !m.is_dir && !m.is_file {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        if self.exists(to)? {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        let parent = to.split_parent().0;
        // A folder never copied into itself (`--from` naming this very space): the copy would read what it writes.
        if m.is_dir {
            let mut ancestor = parent.clone();
            loop {
                match self.meta(ancestor.as_ref()) {
                    Ok(a) if (a.dev, a.ino) == (m.dev, m.ino) => return Err(refused(Refused::IntoItself)),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
                let Some(a) = ancestor else { break };
                ancestor = a.split_parent().0;
            }
        }
        let mut acc: Option<SafePath> = None;
        for c in parent
            .as_ref()
            .map_or("", |p| p.as_str())
            .split('/')
            .filter(|c| !c.is_empty())
        {
            let next = SafePath::new(&match &acc {
                Some(a) => format!("{}/{c}", a.as_str()),
                None => c.to_owned(),
            })
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?; // prefix of a valid path: never
            if !self.exists(&next)? {
                self.mkdir(&next)?;
            }
            acc = Some(next);
        }
        let mut rep = CopyReport::default();
        if let Err(e) = self.copy_tree(src, path, m.is_dir, to, &mut rep) {
            if rep.files + rep.dirs > 0
                && let Err(t) = self.trash(to, "beastbox restore")
            {
                return Err(io::Error::other(format!(
                    "{e}; partial copy left at {}: {t}",
                    to.as_str()
                )));
            }
            self.renew_etags(parent.as_ref())?;
            return Err(e);
        }
        self.renew_etags(parent.as_ref())?;
        Ok(rep)
    }

    /// Lenient variant of [`Root::renew_etags`] for journal replay: if the folder no longer exists,
    /// renews from its nearest existing ancestor.
    pub fn renew_etags_lenient(&self, dir: Option<&SafePath>) -> io::Result<()> {
        let mut cur = dir.cloned();
        loop {
            match self.renew_etags(cur.as_ref()) {
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) || e.raw_os_error() == Some(libc::ENOTDIR) => {
                    cur = match cur {
                        Some(p) => p.split_parent().0,
                        None => return Err(e),
                    };
                }
                r => return r,
            }
        }
    }
}

// ---------------------------------------------------------------- tags and favorites (§6, §8)

pub(super) const XATTR_TAGS: &CStr = c"beastbox.tags";
pub(super) const XATTR_FAVORITE: &CStr = c"beastbox.favorite";
/// Tags per item and length of a tag (§8: bounded count and length).
pub const MAX_TAGS: usize = 20;
pub const MAX_TAG_LEN: usize = 32;

/// Normalized tag: NFC, lowercase, inner spaces collapsed, letters, digits, space, `-`, `_`; 1 to 32 characters.
pub fn normalize_tag(raw: &str) -> Option<String> {
    use unicode_normalization::UnicodeNormalization;
    let t: String = raw.nfc().collect::<String>().to_lowercase();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    let ok = (1..=MAX_TAG_LEN).contains(&t.chars().count())
        && t.chars().all(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_'));
    ok.then_some(t)
}

fn xattr_clear(fd: BorrowedFd<'_>, name: &CStr) -> io::Result<()> {
    match super::xattr_del(fd, name) {
        Err(e) if e.raw_os_error() == Some(libc::ENOATTR) => Ok(()),
        r => r,
    }
}

impl Root {
    /// (tags, favorite) of an item.
    pub fn labels(&self, path: Option<&SafePath>) -> io::Result<(Vec<String>, bool)> {
        let fd = self.open_any(path)?;
        let tags = xattr_get(fd.as_fd(), XATTR_TAGS)?
            .map(|v| {
                String::from_utf8_lossy(&v)
                    .split('\n')
                    .filter_map(normalize_tag)
                    .take(MAX_TAGS)
                    .collect()
            })
            .unwrap_or_default();
        Ok((tags, xattr_get(fd.as_fd(), XATTR_FAVORITE)?.is_some()))
    }

    /// Replaces the tags (already normalized, at most `MAX_TAGS`); empty list → attribute removed.
    pub fn set_tags(&self, path: Option<&SafePath>, tags: &[String]) -> io::Result<()> {
        let fd = self.open_any(path)?;
        if tags.is_empty() {
            return xattr_clear(fd.as_fd(), XATTR_TAGS);
        }
        xattr_set(fd.as_fd(), XATTR_TAGS, tags.join("\n").as_bytes())
    }

    pub fn set_favorite(&self, path: Option<&SafePath>, on: bool) -> io::Result<()> {
        let fd = self.open_any(path)?;
        if on {
            xattr_set(fd.as_fd(), XATTR_FAVORITE, b"1")
        } else {
            xattr_clear(fd.as_fd(), XATTR_FAVORITE)
        }
    }
}

// ---------------------------------------------------------------- chunked upload v2 (§7)

/// Chunks of an upload: `n` from 1 to 10,000 (§7).
pub const MAX_CHUNKS: u32 = 10_000;

impl Root {
    /// Folder of this user's uploads in progress (`.beastbox-uploads/`, reserved name).
    pub fn uploads(&self) -> io::Result<Root> {
        self.open_dir_raw(&cstr(super::UPLOADS_DIR)?)
    }

    /// Creates (or truncates) chunk `n` of upload `id` (in the uploads root).
    pub fn create_chunk(&self, id: &SafePath, n: u32) -> io::Result<File> {
        let dir = self.open_subdir(id)?;
        let fd = openat(
            dir.fd.as_fd(),
            &cstr(&format!("{n:05}"))?,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )?;
        Ok(File::from(fd))
    }

    /// Chunks present, sorted: (number, size). Any unexpected name is an error (no dubious assembly).
    pub fn chunks(&self, id: &SafePath) -> io::Result<Vec<(u32, u64)>> {
        let mut v = Vec::new();
        for e in self.read_dir(Some(id))? {
            let (name, m) = e?;
            let n = name
                .parse::<u32>()
                .ok()
                .filter(|n| (1..=MAX_CHUNKS).contains(n) && m.is_file);
            let n = n.ok_or_else(|| io::Error::other(format!("unexpected entry in an upload: {name}")))?;
            v.push((n, m.size));
        }
        v.sort_unstable();
        Ok(v)
    }

    pub fn open_chunk(&self, id: &SafePath, n: u32) -> io::Result<File> {
        let dir = self.open_subdir(id)?;
        Ok(File::from(openat(
            dir.fd.as_fd(),
            &cstr(&format!("{n:05}"))?,
            libc::O_RDONLY,
            0,
        )?))
    }

    /// Deletes an upload (temporary data, never user files): its chunks then its folder.
    pub fn remove_upload(&self, id: &SafePath) -> io::Result<()> {
        let dir = self.open_subdir(id)?;
        loop {
            let names = super::read_dir_names(dir.fd.as_fd(), 1024)?;
            if names.is_empty() {
                break;
            }
            for n in &names {
                unlinkat(dir.fd.as_fd(), n, 0)?;
            }
        }
        unlinkat(self.fd.as_fd(), &cstr(id.as_str())?, libc::AT_REMOVEDIR)
    }

    /// Deletes the uploads abandoned for longer than `max_age` (called when an upload is created:
    /// no background walk, §0.4). Returns the number deleted.
    pub fn expire_uploads(&self, max_age: std::time::Duration) -> io::Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let limit = i64::try_from(now.saturating_sub(max_age.as_secs())).unwrap_or(0);
        let old: Vec<String> = self
            .read_dir(None)?
            .filter_map(Result::ok)
            .filter(|(_, m)| m.is_dir && m.mtime < limit)
            .map(|(n, _)| n)
            .collect();
        let mut n = 0;
        for name in old {
            if let Ok(id) = SafePath::new(&name) {
                self.remove_upload(&id)?;
                n += 1;
            }
        }
        Ok(n)
    }
}

// ---------------------------------------------------------------- ETag intent journal (§6)

/// A tenant's append-only journal: before a write that modifies the tree, the folders whose ETag must
/// be renewed are written and `fsync`ed; after propagation, the intent is marked done. At startup,
/// unfinished intents are replayed (idempotent renewal). Transient state, not an index.
/// Closed (CLI): every write is refused (fail closed).
/// shortcut: one `fsync` per intent (no batching); batch them if write latency demands it (docs/dev/VALIDATION.md §7).
#[derive(Debug, Default)]
pub struct Journal(Mutex<Option<JState>>);

#[derive(Debug)]
struct JState {
    file: File,
    seq: u64,
    open: usize,
}

/// Beyond this size, the journal is emptied as soon as no intent is in progress.
const JOURNAL_COMPACT: u64 = 1 << 20;

/// Pending intent: (user, folder — `None` = the user's root).
pub type Pending = (String, Option<SafePath>);

impl Journal {
    /// Opens (creates) the journal, locks it (a single instance per state, §0.5), returns the pending
    /// intents to replay. The journal is only emptied after the replay ([`Journal::replayed`]).
    pub fn open(&self, path: &Path) -> io::Result<Vec<Pending>> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        // SAFETY: valid descriptor owned by `file`.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::other(format!(
                "{} locked: another instance is running",
                path.display()
            )));
        }
        let mut text = String::new();
        file.rewind()?;
        file.read_to_string(&mut text)?;
        let mut begun: Vec<(u64, Pending)> = Vec::new();
        let mut done = std::collections::HashSet::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            match f.as_slice() {
                ["B", seq, user, dir] => {
                    let (Ok(seq), true) = (seq.parse::<u64>(), crate::admin::valid_username(user)) else {
                        continue;
                    };
                    let dir = if dir.is_empty() { None } else { SafePath::new(dir).ok() };
                    begun.push((seq, ((*user).to_owned(), dir)));
                }
                ["D", seq] => {
                    if let Ok(s) = seq.parse::<u64>() {
                        done.insert(s);
                    }
                }
                // Line truncated by a crash during the write: ignored (the operation had not started).
                _ => {}
            }
        }
        let pending = begun
            .into_iter()
            .filter(|(s, _)| !done.contains(s))
            .map(|(_, p)| p)
            .collect();
        let mut g = self.0.lock().map_err(|_| io::Error::other("journal poisoned"))?;
        *g = Some(JState { file, seq: 0, open: 0 });
        Ok(pending)
    }

    /// Replay done: empties the journal.
    pub fn replayed(&self) -> io::Result<()> {
        let mut g = self.0.lock().map_err(|_| io::Error::other("journal poisoned"))?;
        let st = g.as_mut().ok_or_else(|| io::Error::other("journal closed"))?;
        st.file.set_len(0)?;
        st.file.sync_all()
    }

    /// Records the intent to renew the ETag of `dirs` (and their ancestors) for `user`. Durable on return.
    pub fn begin(&self, user: &str, dirs: &[Option<&SafePath>]) -> io::Result<u64> {
        let mut g = self.0.lock().map_err(|_| io::Error::other("journal poisoned"))?;
        let st = g
            .as_mut()
            .ok_or_else(|| io::Error::other("journal closed: write refused"))?;
        st.seq += 1;
        let mut lines = String::new();
        for d in dirs {
            lines.push_str(&format!(
                "B\t{}\t{user}\t{}\n",
                st.seq,
                d.map(SafePath::as_str).unwrap_or("")
            ));
        }
        st.file.write_all(lines.as_bytes())?;
        st.file.sync_data()?;
        st.open += 1;
        Ok(st.seq)
    }

    /// Propagation done. No `fsync`: losing this line only replays a propagation (no harmful effect).
    pub fn done(&self, seq: u64) {
        let Ok(mut g) = self.0.lock() else { return };
        let Some(st) = g.as_mut() else { return };
        let _ = writeln!(st.file, "D\t{seq}");
        st.open = st.open.saturating_sub(1);
        if st.open == 0 && st.file.metadata().is_ok_and(|m| m.len() > JOURNAL_COMPACT) {
            let _ = st.file.set_len(0);
        }
    }
}

/// Fuzzing entry point (`fuzzing` feature): a source tree built from arbitrary bytes (any name: invalid UTF-8,
/// control characters, `\\`, forms of Unicode; folders; links out of the tree) is restored into a space holding one
/// file. Never a crash; the existing file untouched (content and identity); nothing written outside the target; every
/// file copied equal to its source; no identity held twice.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
pub fn fuzz_restore(data: &[u8], src_dir: &Path, live_dir: &Path) {
    use std::os::unix::ffi::OsStrExt;
    use unicode_normalization::UnicodeNormalization;
    let top = src_dir.join("T");
    std::fs::create_dir(&top).unwrap();
    let mut cur = top.clone();
    // One entry per line: first byte = what (0 file, 1 folder entered, 2 back up, 3 link), the rest = the name.
    for l in data.split(|b| *b == b'\n').take(32) {
        let Some((&what, name)) = l.split_first() else { continue };
        let name: Vec<u8> = name
            .iter()
            .copied()
            .filter(|b| *b != b'/' && *b != 0)
            .take(200)
            .collect();
        let n = std::ffi::OsStr::from_bytes(&name);
        if what % 4 == 2 {
            if cur != top {
                cur.pop();
            }
            continue;
        }
        if name.is_empty() || name == b"." || name == b".." || cur.join(n).symlink_metadata().is_ok() {
            continue;
        }
        // Budget on the part below `T`: `PATH_MAX` is 1024 on FreeBSD, and NFC can lengthen a name, so a deeper
        // source would panic in this builder (plain `std::fs`) instead of exercising `restore_from`.
        if cur.strip_prefix(&top).unwrap_or(top.as_path()).as_os_str().len() + name.len() > 300 {
            continue;
        }
        match what % 4 {
            0 => std::fs::write(cur.join(n), &name).unwrap(),
            1 => {
                std::fs::create_dir(cur.join(n)).unwrap();
                cur.push(n);
            }
            _ => std::os::unix::fs::symlink(
                if name.len().is_multiple_of(2) {
                    "/etc/passwd"
                } else {
                    ".."
                },
                cur.join(n),
            )
            .unwrap(),
        }
    }
    let src = Root::open_dir(src_dir).unwrap();
    let live = Root::open_dir(live_dir).unwrap();
    live.ensure_layout().unwrap();
    let keep = SafePath::new("keep.txt").unwrap();
    live.atomic_write(&keep, &mut &b"current"[..]).unwrap();
    let id = live.meta(Some(&keep)).unwrap().id;
    let to = SafePath::new("R").unwrap();

    let res = live.restore_from(&src, &SafePath::new("T").unwrap(), &to);

    assert_eq!(std::fs::read(live_dir.join("keep.txt")).unwrap(), b"current");
    assert_eq!(live.meta(Some(&keep)).unwrap().id, id);
    for e in std::fs::read_dir(live_dir).unwrap() {
        let n = e.unwrap().file_name();
        assert!(
            n == "keep.txt" || n == "R" || super::RESERVED.iter().any(|r| n == *r),
            "written outside the target: {n:?}"
        );
    }
    // The source was built here, hence readable: whatever its names, the restore must succeed (passing over what it
    // cannot copy) rather than fail as a whole.
    assert!(res.is_ok(), "{res:?}");
    // Source regular files (never links) by their NFC path: a decomposed name comes back in NFC.
    let mut regular: Vec<(String, Vec<u8>)> = Vec::new();
    let mut stack = vec![top.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let t = p.symlink_metadata().unwrap().file_type();
            if t.is_dir() {
                stack.push(p);
            } else if t.is_file()
                && let Some(rel) = p.strip_prefix(&top).unwrap().to_str()
            {
                regular.push((rel.nfc().collect(), std::fs::read(&p).unwrap()));
            }
        }
    }
    let mut stack = vec![live_dir.join("R")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p.strip_prefix(live_dir.join("R")).unwrap().to_str().unwrap().to_owned();
            let body = std::fs::read(&p).unwrap();
            // Equal to a regular source file of the same NFC path (a followed link would match none).
            assert!(
                regular.iter().any(|(r, b)| *r == rel && *b == body),
                "{rel:?}: not a copy of its source"
            );
        }
    }
    assert!(live.verify(None).unwrap().duplicates.is_empty());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(s: &str) -> SafePath {
        SafePath::new(s).unwrap()
    }

    fn setup() -> (tempfile::TempDir, Root) {
        let d = tempfile::tempdir().unwrap();
        let r = Root::open_dir(d.path()).unwrap();
        r.ensure_layout().unwrap();
        (d, r)
    }

    fn put(r: &Root, p: &str, data: &[u8]) -> Written {
        let mut w = r.writer(&sp(p)).unwrap();
        w.write(data).unwrap();
        w.commit(None, None, |_| true).unwrap()
    }

    #[test]
    fn writer_checksum_mtime_precondition_and_abort() {
        let (d, r) = setup();
        let w1 = put(&r, "a.txt", b"hello");
        assert!(w1.created);
        assert_eq!(w1.sha1, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
        let f = std::fs::File::open(d.path().join("a.txt")).unwrap();
        assert_eq!(
            recorded_sha1(f.as_fd(), &r.meta(Some(&sp("a.txt"))).unwrap())
                .unwrap()
                .as_deref(),
            Some(w1.sha1.as_str())
        );
        // Wrong announced sum: refused, old content intact, no temporary.
        let mut w = r.writer(&sp("a.txt")).unwrap();
        w.write(b"other").unwrap();
        let e = w.commit(None, Some("00"), |_| true).unwrap_err();
        assert!(is(&e, Refused::Checksum));
        assert_eq!(std::fs::read(d.path().join("a.txt")).unwrap(), b"hello");
        // Unsatisfied precondition (If-Match): refused.
        let mut w = r.writer(&sp("a.txt")).unwrap();
        w.write(b"x").unwrap();
        assert!(is(&w.commit(None, None, |_| false).unwrap_err(), Refused::Precondition));
        // Abandon (drop): nothing is written.
        let mut w = r.writer(&sp("a.txt")).unwrap();
        w.write(b"never").unwrap();
        drop(w);
        assert_eq!(std::fs::read(d.path().join("a.txt")).unwrap(), b"hello");
        // Replacement with a client time: identity kept, mtime set, 204.
        let mut w = r.writer(&sp("a.txt")).unwrap();
        w.write(b"v2").unwrap();
        let w2 = w
            .commit(
                Some(1_000_000_000),
                Some("AA9A4CEE3F2D2B5D9A0D9D0E5C2C8C8C8C8C8C8C").filter(|_| false),
                |old| old.is_some(),
            )
            .unwrap();
        assert!(!w2.created && w2.id == w1.id && w2.meta.mtime == 1_000_000_000);
        // File changed outside the application: the recorded sum is no longer considered valid.
        std::fs::write(d.path().join("a.txt"), b"changed outside").unwrap();
        let f = std::fs::File::open(d.path().join("a.txt")).unwrap();
        assert_eq!(
            recorded_sha1(f.as_fd(), &r.meta(Some(&sp("a.txt"))).unwrap()).unwrap(),
            None
        );
        assert_eq!(r.clean_tmp().unwrap(), 0);
        // Parent missing: ENOENT.
        assert_eq!(
            r.writer(&sp("nope/x")).err().unwrap().raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    /// `restore`: the snapshot's version comes back **next to** the current one, never over it; the copy gets new
    /// identities even when the snapshot kept the original's (no duplicate, the original keeps its links); links,
    /// special files and refused names in the source are skipped; missing parents created; existing target refused.
    #[test]
    fn restore_from_copies_next_to_the_current_version() {
        let (d, live) = setup();
        live.mkdir(&sp("Docs")).unwrap();
        let orig = put(&live, "Docs/a.txt", b"today");
        let (s, snap) = setup();
        snap.mkdir(&sp("Docs")).unwrap();
        snap.mkdir(&sp("Docs/Sub")).unwrap();
        put(&snap, "Docs/a.txt", b"ten days ago");
        put(&snap, "Docs/Sub/b.txt", b"b");
        // A snapshot keeps the xattrs: the old version carries the current file's identity.
        let f = openat(snap.fd.as_fd(), c"Docs/a.txt", libc::O_RDONLY, 0).unwrap();
        xattr_set(f.as_fd(), XATTR_ID, &orig.id.0).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", s.path().join("Docs/link")).unwrap();
        std::fs::write(s.path().join("Docs/back\\slash"), b"x").unwrap(); // name refused by SafePath
        let not_utf8 = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b"bad\xff.txt");
        std::fs::write(s.path().join("Docs").join(not_utf8), b"x").unwrap(); // passed over by the folder reader
        let read = |p: &str| std::fs::read(d.path().join(p)).unwrap();
        let root_etag = live.meta(None).unwrap().dir_etag;

        let rep = live.restore_from(&snap, &sp("Docs"), &sp("Docs (restored)")).unwrap();
        assert_eq!(
            rep,
            CopyReport {
                files: 2,
                dirs: 2,
                skipped: 3
            },
            "the link, the refused name and the name not in UTF-8, counted"
        );
        assert_eq!(read("Docs/a.txt"), b"today", "current version untouched");
        assert_eq!(live.meta(Some(&sp("Docs/a.txt"))).unwrap().id, Some(orig.id));
        assert_eq!(read("Docs (restored)/a.txt"), b"ten days ago");
        assert_eq!(read("Docs (restored)/Sub/b.txt"), b"b");
        let copy = live.meta(Some(&sp("Docs (restored)/a.txt"))).unwrap();
        assert!(
            copy.id.is_some() && copy.id != Some(orig.id),
            "new identity, never the original's"
        );
        assert!(copy.sha1.is_some(), "written by the server: sum recorded");
        let names: Vec<String> = live
            .read_dir(Some(&sp("Docs (restored)")))
            .unwrap()
            .map(|e| e.unwrap().0)
            .collect();
        assert_eq!(names.len(), 2, "link and refused names skipped: {names:?}");
        let v = live.verify(None).unwrap();
        // The root only: in production it gets its identity from the first `rescan`.
        assert!(v.duplicates.is_empty() && v.missing_id == ["/"], "{v:?}");
        assert_ne!(
            live.meta(None).unwrap().dir_etag,
            root_etag,
            "clients see the new folder"
        );

        // Existing target: refused, nothing changed.
        let e = live
            .restore_from(&snap, &sp("Docs/a.txt"), &sp("Docs/a.txt"))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(read("Docs/a.txt"), b"today");
        // One file, into folders that no longer exist.
        live.restore_from(&snap, &sp("Docs/Sub/b.txt"), &sp("Gone/Deeper/b (restored).txt"))
            .unwrap();
        assert_eq!(read("Gone/Deeper/b (restored).txt"), b"b");
        // Missing from the snapshot; a link in the source is never followed.
        let missing = live.restore_from(&snap, &sp("Docs/none.txt"), &sp("x")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        assert!(live.restore_from(&snap, &sp("Docs/link"), &sp("y")).is_err());
        assert!(!d.path().join("y").exists() && !d.path().join("x").exists());
        // `--from` naming this very space: a folder is never copied into itself (here or below), nothing created.
        let itself = Root::open_dir(d.path()).unwrap();
        for to in ["Docs/old", "Docs/Sub/deeper/old"] {
            let e = live.restore_from(&itself, &sp("Docs"), &sp(to)).unwrap_err();
            assert!(is(&e, Refused::IntoItself), "{to}: {e}");
        }
        assert!(!d.path().join("Docs/Sub/deeper").exists());
        live.restore_from(&itself, &sp("Docs (restored)/Sub"), &sp("Sub copy"))
            .unwrap(); // beside: allowed

        // Failure midway (here an unreadable source file; the same for a full quota): the partial copy goes to the
        // trash, nothing is left half-restored in the space, the current version is untouched.
        // SAFETY: plain getter.
        if unsafe { libc::geteuid() } != 0 {
            std::fs::write(s.path().join("Docs/Sub/z.txt"), b"z").unwrap();
            let z = s.path().join("Docs/Sub/z.txt");
            std::fs::set_permissions(&z, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
            let trashed = live.trash_list().unwrap().len();
            assert!(live.restore_from(&snap, &sp("Docs"), &sp("Partial")).is_err());
            assert!(
                !d.path().join("Partial").exists(),
                "no half-restored folder left in the space"
            );
            assert_eq!(
                live.trash_list().unwrap().len(),
                trashed + 1,
                "partial copy recoverable from the trash"
            );
            assert_eq!(read("Docs/a.txt"), b"today");
            std::fs::set_permissions(&z, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
            // Failure before anything was copied (target folder not writable): nothing to trash, the cause as it is.
            live.mkdir(&sp("Ro")).unwrap();
            let ro = d.path().join("Ro");
            std::fs::set_permissions(&ro, std::os::unix::fs::PermissionsExt::from_mode(0o500)).unwrap();
            let e = live.restore_from(&snap, &sp("Docs/Sub"), &sp("Ro/x")).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
            assert_eq!(live.trash_list().unwrap().len(), trashed + 1);
            std::fs::set_permissions(&ro, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        }
    }

    /// Property: for any snapshot, any current tree (overlapping names, identities kept by the snapshot) and any
    /// target, restoring any item either refuses (target taken in the space, item missing from the snapshot) or copies
    /// it faithfully; every existing item keeps its content and its identity, and no identity is held twice.
    #[test]
    fn restore_never_touches_the_current_tree() {
        use proptest::prelude::*;
        use proptest::test_runner::{Config, TestRunner};
        const NAMES: [&str; 5] = ["a.txt", "b.txt", "D/a.txt", "D/c.txt", "D/E/f.txt"];
        let cases = std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(32);
        let tree = prop::collection::btree_map(
            prop::sample::select(NAMES.to_vec()),
            prop::collection::vec(any::<u8>(), 0..64),
            1..5,
        );
        let strategy = (
            tree.clone(),
            tree,
            prop::sample::select(vec!["a.txt", "D", "D/E", "D/c.txt"]),
            prop::sample::select(vec!["R", "a.txt", "D", "D/E"]),
        );
        let r = TestRunner::new(Config::with_cases(cases)).run(&strategy, |(snap_files, live_files, pick, to)| {
            let (d, live) = setup();
            let (s, snap) = setup();
            let fill = |r: &Root, files: &std::collections::BTreeMap<&str, Vec<u8>>| {
                for (p, body) in files {
                    for dir in ["D", "D/E"] {
                        if p.starts_with(&format!("{dir}/")) && !r.exists(&sp(dir)).unwrap() {
                            r.mkdir(&sp(dir)).unwrap();
                        }
                    }
                    put(r, p, body);
                }
            };
            fill(&live, &live_files);
            fill(&snap, &snap_files);
            // The snapshot kept the identities of the current items of the same name.
            for p in snap_files.keys().filter(|p| live_files.contains_key(*p)) {
                let id = live.meta(Some(&sp(p))).unwrap().id.unwrap();
                let f = openat(snap.fd.as_fd(), &cstr(p).unwrap(), libc::O_RDONLY, 0).unwrap();
                xattr_set(f.as_fd(), XATTR_ID, &id.0).unwrap();
            }
            let state = |r: &Root, files: &std::collections::BTreeMap<&str, Vec<u8>>, base: &Path| {
                files
                    .keys()
                    .map(|p| (std::fs::read(base.join(p)).unwrap(), r.meta(Some(&sp(p))).unwrap().id))
                    .collect::<Vec<_>>()
            };
            let before = state(&live, &live_files, d.path());
            let res = live.restore_from(&snap, &sp(pick), &sp(to));
            prop_assert_eq!(state(&live, &live_files, d.path()), before, "existing items unchanged");
            let in_snap = |p: &str| snap_files.keys().any(|f| *f == p || f.starts_with(&format!("{p}/")));
            // Never over an existing item: the target itself, or a folder it would be written into.
            let taken = live_files.keys().any(|f| *f == to || f.starts_with(&format!("{to}/")));
            prop_assert_eq!(res.is_ok(), in_snap(pick) && !taken, "{}: {:?}", to, res);
            if res.is_ok() && to == "R" {
                for f in snap_files.keys() {
                    let rel = if *f == pick {
                        Some(String::new())
                    } else {
                        f.strip_prefix(&format!("{pick}/")).map(|r| format!("/{r}"))
                    };
                    if let Some(rel) = rel {
                        prop_assert_eq!(
                            std::fs::read(d.path().join(format!("R{rel}"))).unwrap(),
                            std::fs::read(s.path().join(f)).unwrap()
                        );
                    }
                }
            }
            prop_assert!(
                live.verify(None).unwrap().duplicates.is_empty(),
                "an identity held twice"
            );
            Ok(())
        });
        assert!(r.is_ok(), "{r:?}");
    }

    /// Edge cases of `restore`: empty file and folder, a file larger than the copy buffer (content and recorded sum
    /// exact), a deep tree, a single file at the top of the source, names in any script (Chinese, accents, emoji),
    /// a decomposed name (macOS: copied in NFC), two names with the same NFC form (one passed over and counted), a
    /// target under a file (refused).
    #[test]
    fn restore_edge_cases() {
        let (d, live) = setup();
        let (s, snap) = setup();
        let p = s.path();
        std::fs::create_dir_all(p.join("T/vide")).unwrap();
        std::fs::write(p.join("T/zero.txt"), b"").unwrap();
        let big: Vec<u8> = (0..3_000_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        std::fs::write(p.join("T/big.bin"), &big).unwrap();
        let deep: String = (0..40).map(|i| format!("/n{i}")).collect();
        std::fs::create_dir_all(p.join(format!("T{deep}"))).unwrap();
        std::fs::write(p.join(format!("T{deep}/leaf.txt")), b"leaf").unwrap();
        std::fs::write(p.join("T/e\u{301}t\u{e9}.txt"), b"nfd").unwrap(); // "été" with a decomposed first é
        for (n, body) in [
            ("报告 2026.txt", &b"zh"[..]),
            ("Facture été — n°3 🧾.pdf", b"fr"),
            ("Ölçü ß ñ.md", b"x"),
        ] {
            std::fs::write(p.join("T").join(n), body).unwrap();
        }
        // Two source names with the same NFC form: one is copied, the other passed over and counted.
        std::fs::create_dir(p.join("T/dup")).unwrap();
        std::fs::write(p.join("T/dup/\u{e9}.txt"), b"nfc").unwrap();
        std::fs::write(p.join("T/dup/e\u{301}.txt"), b"nfd").unwrap();
        // The same for two folders: the second is passed over with its contents.
        for d in ["T/dupd/\u{e9}", "T/dupd/e\u{301}"] {
            std::fs::create_dir_all(p.join(d)).unwrap();
            std::fs::write(p.join(d).join("x.txt"), d).unwrap();
        }
        std::fs::write(p.join("top.txt"), b"top").unwrap();

        let rep = live.restore_from(&snap, &sp("T"), &sp("R")).unwrap();
        let read = |q: &str| std::fs::read(d.path().join(q)).unwrap();
        // zero, big, leaf, été, 3 names, one of dup, dupd's x.txt; R, vide, dup, dupd and one of it, 40 levels; the
        // other of dup, the other of dupd.
        assert_eq!((rep.files, rep.dirs, rep.skipped), (9, 45, 2), "{rep:?}");
        assert_eq!(std::fs::read_dir(d.path().join("R/dupd")).unwrap().count(), 1);
        assert_eq!(
            read("R/\u{e9}t\u{e9}.txt"),
            b"nfd",
            "decomposed name copied under its NFC form"
        );
        assert_eq!(read("R/报告 2026.txt"), b"zh");
        assert_eq!(read("R/Facture été — n°3 🧾.pdf"), b"fr");
        assert_eq!(read("R/Ölçü ß ñ.md"), b"x");
        assert_eq!(std::fs::read_dir(d.path().join("R/dup")).unwrap().count(), 1);
        assert!(read("R/zero.txt").is_empty() && d.path().join("R/vide").is_dir());
        assert_eq!(read("R/big.bin"), big);
        let m = live.meta(Some(&sp("R/big.bin"))).unwrap();
        assert_eq!(
            m.sha1.as_deref(),
            Some(hex(&Sha1::digest(&big)).as_str()),
            "sum of the real content"
        );
        assert_eq!(read(&format!("R{deep}/leaf.txt")), b"leaf");
        assert!(live.verify(None).unwrap().modified.is_empty());

        assert_eq!(
            live.restore_from(&snap, &sp("top.txt"), &sp("top.txt")).unwrap().files,
            1
        );
        assert_eq!(read("top.txt"), b"top");
        // Target under a file: refused, nothing created.
        assert!(live.restore_from(&snap, &sp("top.txt"), &sp("top.txt/x")).is_err());
        assert!(live.restore_from(&snap, &sp("T"), &sp("top.txt/R")).is_err());
        assert_eq!(read("top.txt"), b"top");
    }

    /// A write error inside the copy (here a target path over the system limit, as a full quota) fails the restore
    /// and sends the partial copy to the trash: never passed over like a name already taken.
    #[test]
    fn restore_write_error_midway_fails_the_copy() {
        let (d, live) = setup();
        let (s, snap) = setup();
        let seg = "d".repeat(50);
        let deep: String = (0..(libc::PATH_MAX as usize - 100) / 51)
            .map(|_| format!("/{seg}"))
            .collect();
        std::fs::create_dir_all(s.path().join(format!("T{deep}"))).unwrap();
        let to = "R".repeat(200);
        let e = live.restore_from(&snap, &sp("T"), &sp(&to)).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENAMETOOLONG), "{e}");
        assert!(!d.path().join(&to).exists());
        assert_eq!(live.trash_list().unwrap().len(), 1, "partial copy in the trash");
    }

    /// A copy failing before anything is written reports its own error: there is nothing to put in the trash.
    #[test]
    fn copy_failing_at_once_reports_its_cause() {
        let (d, r) = setup();
        std::fs::write(d.path().join("f.txt"), b"x").unwrap();
        let e = r
            .copy(&sp("f.txt"), &sp("no/such/folder/f.txt"), false, "alice")
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
        assert!(r.trash_list().unwrap().is_empty());
    }

    /// A copy that fails midway (WebDAV `COPY`, the web's "Copy here" and "Duplicate") leaves no half folder: the
    /// partial copy goes to the trash, the source is untouched; a copy that fails before writing anything trashes
    /// nothing.
    #[test]
    fn copy_failing_midway_goes_to_the_trash() {
        let (d, r) = setup();
        // A path too long below the copy's name: the deepest folder fails once the others are written.
        let seg = "d".repeat(50);
        let deep: String = (0..(libc::PATH_MAX as usize - 100) / 51)
            .map(|_| format!("/{seg}"))
            .collect();
        std::fs::create_dir_all(d.path().join(format!("T{deep}"))).unwrap();
        let to = "R".repeat(200);
        let e = r.copy(&sp("T"), &sp(&to), false, "alice").unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENAMETOOLONG), "{e}");
        assert!(!d.path().join(&to).exists(), "no half copy left");
        assert_eq!(r.trash_list().unwrap().len(), 1, "partial copy in the trash");
        assert!(d.path().join(format!("T{deep}")).is_dir(), "source untouched");
        // An unreadable file inside (a full quota fails the same way): same outcome.
        // SAFETY: plain getter.
        if unsafe { libc::geteuid() } != 0 {
            r.mkdir(&sp("Docs")).unwrap();
            put(&r, "Docs/a.txt", b"a");
            put(&r, "Docs/z.txt", b"z");
            let z = d.path().join("Docs/z.txt");
            std::fs::set_permissions(&z, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
            assert!(r.copy(&sp("Docs"), &sp("Docs copy"), false, "alice").is_err());
            assert!(!d.path().join("Docs copy").exists());
            assert_eq!(r.trash_list().unwrap().len(), 2);
            // One file that cannot be read: nothing was written, nothing to trash.
            assert!(r.copy(&sp("Docs/z.txt"), &sp("z copy.txt"), false, "alice").is_err());
            assert!(!d.path().join("z copy.txt").exists());
            assert_eq!(r.trash_list().unwrap().len(), 2);
            std::fs::set_permissions(&z, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn mkdir_trash_rename_copy() {
        let (d, r) = setup();
        let m = r.mkdir(&sp("docs")).unwrap();
        assert!(m.is_dir && m.id.is_some() && m.dir_etag.is_some());
        assert_eq!(r.mkdir(&sp("docs")).unwrap_err().raw_os_error(), Some(libc::EEXIST));
        let id = put(&r, "docs/a.txt", b"A").id;
        // Rename: identity kept.
        assert!(!r.rename(&sp("docs/a.txt"), &sp("docs/b.txt"), false, "alice").unwrap());
        assert_eq!(r.meta(Some(&sp("docs/b.txt"))).unwrap().id, Some(id));
        // Existing destination without Overwrite: refused; with it: the old one goes to the trash.
        put(&r, "docs/c.txt", b"C");
        assert!(is(
            &r.rename(&sp("docs/b.txt"), &sp("docs/c.txt"), false, "alice")
                .unwrap_err(),
            Refused::Precondition
        ));
        assert!(r.rename(&sp("docs/b.txt"), &sp("docs/c.txt"), true, "alice").unwrap());
        assert_eq!(std::fs::read(d.path().join("docs/c.txt")).unwrap(), b"A");
        let trashed: Vec<_> = std::fs::read_dir(d.path().join(".trash"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(trashed.len(), 1);
        assert_eq!(std::fs::read(trashed[0].join("c.txt")).unwrap(), b"C");
        // Folder into itself: refused.
        r.mkdir(&sp("docs/sub")).unwrap();
        assert!(is(
            &r.rename(&sp("docs"), &sp("docs/sub/x"), false, "a").unwrap_err(),
            Refused::IntoItself
        ));
        // Onto its own ancestor, even with overwrite: refused before the ancestor (source included) goes to the trash.
        for e in [
            r.rename(&sp("docs/sub"), &sp("docs"), true, "a").unwrap_err(),
            r.copy(&sp("docs/sub"), &sp("docs"), true, "a").unwrap_err(),
        ] {
            assert!(is(&e, Refused::IntoItself));
        }
        assert!(r.meta(Some(&sp("docs/sub"))).unwrap().is_dir);
        assert_eq!(std::fs::read_dir(d.path().join(".trash")).unwrap().count(), 1);
        // Recursive copy: new identities, identical content.
        assert!(!r.copy(&sp("docs"), &sp("copie"), false, "alice").unwrap());
        assert_eq!(std::fs::read(d.path().join("copie/c.txt")).unwrap(), b"A");
        assert_ne!(r.meta(Some(&sp("copie/c.txt"))).unwrap().id, Some(id));
        assert!(r.meta(Some(&sp("copie/sub"))).unwrap().is_dir);
        // Delete: to the trash, original path recorded, identity kept.
        r.trash(&sp("docs"), "alice").unwrap();
        assert!(!d.path().join("docs").exists());
        let slots: Vec<_> = std::fs::read_dir(d.path().join(".trash"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        let slot = slots.iter().find(|p| p.join("docs").exists()).unwrap();
        let f = std::fs::File::open(slot).unwrap();
        assert_eq!(
            xattr_get(f.as_fd(), XATTR_TRASH_PATH).unwrap().as_deref(),
            Some(&b"docs"[..])
        );
        assert!(r.meta(Some(&sp("copie"))).unwrap().is_dir);
        // Source missing: ENOENT, destination intact.
        assert_eq!(
            r.rename(&sp("ghost"), &sp("copie"), true, "a")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
        assert!(d.path().join("copie").exists());
    }

    #[test]
    fn journal_replays_unfinished_intents() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.log");
        let j = Journal::default();
        assert!(j.begin("alice", &[None]).is_err()); // closed: write refused
        assert!(j.open(&p).unwrap().is_empty());
        let s1 = j.begin("alice", &[Some(&sp("a/b")), Some(&sp("c"))]).unwrap();
        let s2 = j.begin("bob", &[None]).unwrap();
        j.done(s2);
        // Second instance on the same journal: refused.
        assert!(Journal::default().open(&p).is_err());
        drop(j); // "crash": s1 never done
        let j = Journal::default();
        let pending = j.open(&p).unwrap();
        assert_eq!(
            pending,
            vec![
                ("alice".to_owned(), Some(sp("a/b"))),
                ("alice".to_owned(), Some(sp("c")))
            ]
        );
        let _ = s1;
        j.replayed().unwrap();
        drop(j);
        assert!(Journal::default().open(&p).unwrap().is_empty());
        // Truncated line at the end of the file: ignored.
        std::fs::write(&p, "B\t1\talice\tx\nB\t2\tal").unwrap();
        assert_eq!(
            Journal::default().open(&p).unwrap(),
            vec![("alice".to_owned(), Some(sp("x")))]
        );
    }

    #[test]
    fn tags_and_favorites() {
        let (_d, r) = setup();
        put(&r, "f.txt", b"x");
        assert_eq!(normalize_tag("  Facture  2026 ").as_deref(), Some("facture 2026"));
        assert_eq!(normalize_tag("E\u{301}TÉ").as_deref(), Some("\u{e9}t\u{e9}")); // NFC then lowercase
        for bad in ["", "<script>", "a/b", "x".repeat(33).as_str()] {
            assert_eq!(normalize_tag(bad), None, "{bad:?}");
        }
        let p = sp("f.txt");
        r.set_tags(Some(&p), &["a".into(), "b c".into()]).unwrap();
        r.set_favorite(Some(&p), true).unwrap();
        assert_eq!(r.labels(Some(&p)).unwrap(), (vec!["a".into(), "b c".into()], true));
        // Follow an atomic replacement (§6).
        put(&r, "f.txt", b"y");
        assert_eq!(r.labels(Some(&p)).unwrap(), (vec!["a".into(), "b c".into()], true));
        r.set_tags(Some(&p), &[]).unwrap();
        r.set_favorite(Some(&p), false).unwrap();
        r.set_favorite(Some(&p), false).unwrap(); // idempotent
        assert_eq!(r.labels(Some(&p)).unwrap(), (vec![], false));
    }

    #[test]
    fn uploads_chunks_and_expiry() {
        let (_d, r) = setup();
        let up = r.uploads().unwrap();
        let id = sp("up-1");
        up.mkdir(&id).unwrap();
        for (n, data) in [(2u32, &b"BB"[..]), (1, &b"A"[..]), (10, &b"CCC"[..])] {
            up.create_chunk(&id, n).unwrap().write_all(data).unwrap();
        }
        assert_eq!(up.chunks(&id).unwrap(), vec![(1, 1), (2, 2), (10, 3)]);
        let mut s = String::new();
        up.open_chunk(&id, 10).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "CCC");
        assert_eq!(up.expire_uploads(std::time::Duration::from_secs(3600)).unwrap(), 0);
        assert_eq!(up.expire_uploads(std::time::Duration::ZERO).unwrap(), 0); // mtime == now: not "older"
        up.remove_upload(&id).unwrap();
        assert!(up.chunks(&id).is_err());
        // Reserved names: never reachable through a SafePath, and the uploads root not listed.
        assert!(SafePath::new(".beastbox-uploads/x").is_err());
        assert!(r.read_dir(None).unwrap().all(|e| e.unwrap().0 != ".beastbox-uploads"));
    }

    #[test]
    fn renew_lenient_falls_back_to_ancestor() {
        let (_d, r) = setup();
        r.mkdir(&sp("a")).unwrap();
        let before = r.meta(Some(&sp("a"))).unwrap().dir_etag;
        r.renew_etags_lenient(Some(&sp("a/gone/deeper"))).unwrap();
        assert_ne!(r.meta(Some(&sp("a"))).unwrap().dir_etag, before);
    }
}

#[cfg(all(test, feature = "fuzzing"))]
mod fuzz_seeds {
    /// The corpus seeds must be replayable: they are the input the fuzz target receives.
    #[test]
    fn seeds_do_not_panic() {
        for name in [
            "seed-deep-200",
            "seed-nfc-expansion",
            "seed-nfc-nfd-collision",
            "seed-nfd-folder",
        ] {
            let data = std::fs::read(format!("fuzz/corpus/restore/{name}")).unwrap();
            let (src, live) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            crate::dav::fuzz::restore(&data, src.path(), live.path());
        }
    }
}
