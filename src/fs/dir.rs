//! Reading folders and metadata, folder ETags, rescan, keys. Always by descriptor (Capsicum).

use super::{FileId, RESERVED, Root, SafePath, cstr, cvt, fstat, openat, read_id, xattr_get, xattr_set};
use std::collections::HashSet;
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd};

pub(super) const XATTR_ETAG: &CStr = c"beastbox.etag";

/// An entry's metadata, read with one `fstat` and a few xattrs.
#[derive(Clone, Debug)]
pub struct Meta {
    pub is_dir: bool,
    /// Regular file (not a folder, FIFO or device).
    pub is_file: bool,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    /// Last change of the item (content, move, tags, star): when it last had activity. Not its modification date, which
    /// clients keep from the original (`X-OC-Mtime`).
    pub ctime: i64,
    pub ino: u64,
    pub dev: u64,
    /// Persistent identity, missing for an item that arrived outside the application before `rescan` (§6).
    pub id: Option<FileId>,
    /// Folder ETag (xattr), missing before the first `rescan` or the first write.
    pub dir_etag: Option<[u8; 16]>,
    /// SHA-1 recorded at write time, only if it still matches the content (size and time unchanged).
    pub sha1: Option<String>,
    /// The user's favorite (clients' `oc:favorite`, the web interface's star).
    pub favorite: bool,
}

pub(super) fn meta_of(fd: BorrowedFd<'_>) -> io::Result<Meta> {
    let st = fstat(fd)?;
    let is_dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
    let is_file = st.st_mode & libc::S_IFMT == libc::S_IFREG;
    let dir_etag = if is_dir {
        xattr_get(fd, XATTR_ETAG)?.and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok())
    } else {
        None
    };
    let mut m = Meta {
        is_dir,
        is_file,
        size: u64::try_from(st.st_size).unwrap_or(0),
        mtime: st.st_mtime,
        mtime_nsec: st.st_mtime_nsec,
        ctime: st.st_ctime,
        ino: st.st_ino,
        dev: st.st_dev,
        id: read_id(fd)?,
        dir_etag,
        sha1: None,
        favorite: xattr_get(fd, super::write::XATTR_FAVORITE)?.is_some(),
    };
    if is_file {
        m.sha1 = super::recorded_sha1(fd, &m)?;
    }
    Ok(m)
}

/// Type of an entry without following or opening it (a FIFO would block an `open`).
fn kind_at(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<libc::mode_t> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid descriptor, NUL-terminated name, buffer of the right size.
    cvt(unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_RESOLVE_BENEATH,
        )
    })?;
    // SAFETY: fstatat succeeded.
    Ok(unsafe { st.assume_init() }.st_mode & libc::S_IFMT)
}

/// Iterator over a folder: (name, metadata) of files and folders only (links, FIFOs… ignored),
/// non-UTF-8 names ignored, reserved names hidden at the user's root.
pub struct DirReader {
    dirp: *mut libc::DIR,
    fd: BorrowedFd<'static>,
    hide_reserved: bool,
    /// Entries passed over: name not UTF-8, neither file nor folder (link, device…).
    pub skipped: u64,
}

// SAFETY: the DIR* and its descriptor belong exclusively to this DirReader; it can change threads
// (successive spawn_blocking steps) as long as it is never used by two threads at once, which
// `&mut self` on `next` guarantees.
unsafe impl Send for DirReader {}

impl Drop for DirReader {
    fn drop(&mut self) {
        // SAFETY: `dirp` is valid (checked at construction) and closed only once.
        unsafe { libc::closedir(self.dirp) };
    }
}

impl Iterator for DirReader {
    type Item = io::Result<(String, Meta)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // SAFETY: `dirp` is valid; readdir returns null at the end of the folder.
            let ent = unsafe { libc::readdir(self.dirp) };
            if ent.is_null() {
                return None;
            }
            // SAFETY: `ent` is valid until the next readdir; d_name is NUL-terminated.
            let cname = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }.to_owned();
            let Ok(name) = cname.to_str() else {
                self.skipped += 1;
                continue;
            };
            if name == "." || name == ".." || (self.hide_reserved && RESERVED.contains(&name)) {
                continue;
            }
            let kind = match kind_at(self.fd, &cname) {
                Ok(k) => k,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue, // deleted in the meantime
                Err(e) => return Some(Err(e)),
            };
            if kind != libc::S_IFREG && kind != libc::S_IFDIR {
                self.skipped += 1;
                continue;
            }
            let r = openat(self.fd, &cname, libc::O_RDONLY | libc::O_NONBLOCK, 0).and_then(|f| meta_of(f.as_fd()));
            match r {
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                r => return Some(r.map(|m| (name.to_owned(), m))),
            }
        }
    }
}

/// Dataset space (reflects the ZFS quota): (available, used) in bytes.
pub struct Space {
    pub available: u64,
    pub used: u64,
}

impl Root {
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone()?,
        })
    }

    pub(super) fn open_any(&self, path: Option<&SafePath>) -> io::Result<OwnedFd> {
        match path {
            Some(p) => openat(
                self.fd.as_fd(),
                &cstr(p.as_str())?,
                libc::O_RDONLY | libc::O_NONBLOCK,
                0,
            ),
            None => self.fd.try_clone(),
        }
    }

    /// Metadata of `path` (or of the root if `None`).
    pub fn meta(&self, path: Option<&SafePath>) -> io::Result<Meta> {
        meta_of(self.open_any(path)?.as_fd())
    }

    /// Opens a regular file for reading (refuses folders and special files).
    pub fn open_file(&self, path: &SafePath) -> io::Result<(File, Meta)> {
        let fd = self.open_any(Some(path))?;
        let m = meta_of(fd.as_fd())?;
        if !m.is_file {
            return Err(io::Error::from(io::ErrorKind::IsADirectory));
        }
        Ok((File::from(fd), m))
    }

    /// Opens the folder `path` (or this root) to iterate over its entries.
    pub fn read_dir(&self, path: Option<&SafePath>) -> io::Result<DirReader> {
        let dir = match path {
            Some(p) => self.open_subdir(p)?,
            None => self.try_clone()?,
        };
        let raw = dir.fd.into_raw_fd();
        // SAFETY: `raw` is a valid folder descriptor which fdopendir takes ownership of.
        let dirp = unsafe { libc::fdopendir(raw) };
        if dirp.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: fdopendir failed, the descriptor still belongs to us.
            unsafe { libc::close(raw) };
            return Err(e);
        }
        // A duplicate shares the read position with the original: start again from the beginning.
        // SAFETY: `dirp` is valid (non-null).
        unsafe { libc::rewinddir(dirp) };
        // SAFETY: `raw` stays open as long as `dirp` lives (closed by closedir in Drop).
        let fd = unsafe { BorrowedFd::borrow_raw(raw) };
        Ok(DirReader {
            dirp,
            fd,
            hide_reserved: path.is_none(),
            skipped: 0,
        })
    }

    pub fn space(&self) -> io::Result<Space> {
        let sf = self.statfs()?;
        let bs = sf.f_bsize;
        let avail = u64::try_from(sf.f_bavail).unwrap_or(0);
        Ok(Space {
            available: avail.saturating_mul(bs),
            used: (sf.f_blocks.saturating_sub(sf.f_bfree)).saturating_mul(bs),
        })
    }

    /// §6: renews the ETag (128 random bits) of the folder `dir` and of all its ancestors up to this root.
    /// Idempotent: replaying simply gives new values.
    pub fn renew_etags(&self, dir: Option<&SafePath>) -> io::Result<()> {
        let mut chain: Vec<Option<SafePath>> = vec![None];
        if let Some(d) = dir {
            let mut acc = String::new();
            for c in d.as_str().split('/') {
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(c);
                chain.push(Some(
                    SafePath::new(&acc).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
                ));
            }
        }
        // From deepest to root: a client comparing the root sees the change last.
        for p in chain.iter().rev() {
            let fd = self.open_any(p.as_ref())?;
            xattr_set(fd.as_fd(), XATTR_ETAG, &FileId::random()?.0)?;
        }
        Ok(())
    }

    /// `beastbox rescan` (§6): first recovers identities from the manifest (`beastbox manifest`) for the items that
    /// lost them, then assigns those still missing, reassigns duplicates, renews the ETag of every
    /// folder of the subtree then of its ancestors.
    /// shortcut: no I/O throttling and no pause; add them before using rescan online on large trees.
    /// shortcut: the set of identities seen is in memory (16 B/entry), acceptable for the CLI up to a few million.
    pub fn rescan(&self, start: Option<&SafePath>) -> io::Result<RescanReport> {
        self.rescan_with(start, super::RESCAN_READERS)
    }

    /// [`Root::rescan`] with `readers` threads proving the restored contents (1 to [`super::RESCAN_READERS`]).
    pub fn rescan_with(&self, start: Option<&SafePath>, readers: usize) -> io::Result<RescanReport> {
        let mut rep = RescanReport {
            manifest: self.apply_manifest(start, readers)?,
            ..RescanReport::default()
        };
        let mut seen = HashSet::new();
        let mut stack = vec![start.cloned()];
        let fix =
            |fd: BorrowedFd<'_>, m: &Meta, seen: &mut HashSet<[u8; 16]>, rep: &mut RescanReport| -> io::Result<()> {
                match m.id {
                    Some(id) if seen.insert(id.0) => {}
                    had => {
                        let id = FileId::random()?;
                        xattr_set(fd, super::XATTR_ID, &id.0)?;
                        seen.insert(id.0);
                        if had.is_some() {
                            rep.duplicates += 1
                        } else {
                            rep.ids_assigned += 1
                        }
                    }
                }
                Ok(())
            };
        while let Some(dir) = stack.pop() {
            let fd = self.open_any(dir.as_ref())?;
            let m = meta_of(fd.as_fd())?;
            fix(fd.as_fd(), &m, &mut seen, &mut rep)?;
            if !m.is_dir {
                continue;
            }
            xattr_set(fd.as_fd(), XATTR_ETAG, &FileId::random()?.0)?;
            rep.dirs += 1;
            for e in self.read_dir(dir.as_ref())? {
                let (name, m) = e?;
                let child = SafePath::new(&match &dir {
                    Some(d) => format!("{}/{name}", d.as_str()),
                    None => name,
                });
                let Ok(child) = child else {
                    rep.skipped += 1; // name refused by SafePath (control, `\`…): reported, never changed
                    continue;
                };
                if m.is_dir {
                    stack.push(Some(child));
                } else {
                    let f = self.open_any(Some(&child))?;
                    fix(f.as_fd(), &m, &mut seen, &mut rep)?;
                    rep.files += 1;
                }
            }
        }
        if let Some((parent, _)) = start.map(SafePath::split_parent) {
            self.renew_etags(parent.as_ref())?;
        }
        Ok(rep)
    }
}

/// `beastbox verify` report: deviations from the write contract (§6), without changing anything. Bounded lists.
#[derive(Debug, Default)]
pub struct VerifyReport {
    pub files: u64,
    pub dirs: u64,
    /// Without identity: added outside the application.
    pub missing_id: Vec<String>,
    /// Same identity as an item already seen: an external copy that preserved the xattrs.
    pub duplicates: Vec<String>,
    /// Sum recorded at write time, but size or time changed since: changed outside the application.
    pub modified: Vec<String>,
    /// True if a list was truncated to [`VERIFY_MAX`].
    pub truncated: bool,
}

pub const VERIFY_MAX: usize = 1000;

impl Root {
    /// `beastbox verify` (§6): read-only.
    pub fn verify(&self, start: Option<&SafePath>) -> io::Result<VerifyReport> {
        let mut rep = VerifyReport::default();
        let mut seen = HashSet::new();
        let mut stack = vec![start.cloned()];
        let push = |v: &mut Vec<String>, t: &mut bool, p: &Option<SafePath>| {
            if v.len() < VERIFY_MAX {
                v.push(p.as_ref().map_or("/".to_owned(), |p| p.as_str().to_owned()));
            } else {
                *t = true;
            }
        };
        while let Some(path) = stack.pop() {
            let fd = self.open_any(path.as_ref())?;
            let m = meta_of(fd.as_fd())?;
            match m.id {
                None => push(&mut rep.missing_id, &mut rep.truncated, &path),
                Some(id) if !seen.insert(id.0) => push(&mut rep.duplicates, &mut rep.truncated, &path),
                Some(_) => {}
            }
            if m.is_file {
                rep.files += 1;
                if m.sha1.is_none() && xattr_get(fd.as_fd(), super::write::XATTR_CKSUM_SHA1)?.is_some() {
                    push(&mut rep.modified, &mut rep.truncated, &path);
                }
                continue;
            }
            rep.dirs += 1;
            for e in self.read_dir(path.as_ref())? {
                let (name, _) = e?;
                let child = match &path {
                    Some(d) => format!("{}/{name}", d.as_str()),
                    None => name,
                };
                if let Ok(c) = SafePath::new(&child) {
                    stack.push(Some(c));
                }
            }
        }
        Ok(rep)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RescanReport {
    pub files: u64,
    pub dirs: u64,
    pub ids_assigned: u64,
    pub duplicates: u64,
    pub skipped: u64,
    /// Recovered from the manifest before anything else.
    pub manifest: super::ManifestApplied,
}

/// A tenant's HMAC key (§5: 0600 file outside the database). Created if missing (O_EXCL, fsync), otherwise reread.
pub fn load_or_create_key(path: &std::path::Path) -> io::Result<[u8; 32]> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::read(path) {
        Ok(v) => <[u8; 32]>::try_from(v.as_slice()).map_err(|_| io::Error::other("tenant key of invalid size")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut k = [0u8; 32];
            getrandom::fill(&mut k).map_err(io::Error::other)?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(&k)?;
            f.sync_all()?;
            Ok(k)
        }
        Err(e) => Err(e),
    }
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

    #[test]
    fn read_dir_hides_reserved_and_specials() {
        let (d, r) = setup();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/.trash"), b"x").unwrap(); // not hidden outside the root
        r.atomic_write(&sp("f.txt"), &mut &b"abc"[..]).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("link")).unwrap();
        let st = std::process::Command::new("mkfifo")
            .arg(d.path().join("fifo"))
            .status()
            .unwrap();
        assert!(st.success());
        let mut names: Vec<_> = r.read_dir(None).unwrap().map(|e| e.unwrap()).collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(names.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["f.txt", "sub"]);
        assert_eq!(names[0].1.size, 3);
        assert!(names[0].1.id.is_some());
        assert!(names[1].1.is_dir);
        let sub: Vec<_> = r.read_dir(Some(&sp("sub"))).unwrap().map(|e| e.unwrap().0).collect();
        assert_eq!(sub, [".trash"]);
        assert!(r.open_file(&sp("sub")).is_err());
        assert!(r.open_file(&sp("fifo")).is_err());
        assert!(r.open_file(&sp("link")).is_err());
    }

    #[test]
    fn rescan_assigns_ids_and_renews_ancestors() {
        let (d, r) = setup();
        std::fs::create_dir_all(d.path().join("a/b/c")).unwrap();
        std::fs::write(d.path().join("a/b/c/new.txt"), b"x").unwrap(); // added "over SSH"
        std::fs::write(d.path().join("a/other.txt"), b"y").unwrap();
        let rep = r.rescan(None).unwrap();
        assert_eq!((rep.files, rep.dirs, rep.ids_assigned, rep.duplicates), (2, 4, 6, 0));
        let before = |p: Option<&str>| r.meta(p.map(sp).as_ref()).unwrap().dir_etag.unwrap();
        let (root0, a0, b0, c0) = (
            before(None),
            before(Some("a")),
            before(Some("a/b")),
            before(Some("a/b/c")),
        );
        // Deep change outside the application, then targeted rescan: ancestors and subtree renewed, neighbors not.
        std::fs::write(d.path().join("a/b/c/new.txt"), b"modified").unwrap();
        let id = r.meta(Some(&sp("a/b/c/new.txt"))).unwrap().id;
        r.rescan(Some(&sp("a/b/c"))).unwrap();
        assert_ne!(before(None), root0);
        assert_ne!(before(Some("a")), a0);
        assert_ne!(before(Some("a/b")), b0);
        assert_ne!(before(Some("a/b/c")), c0);
        assert_eq!(r.meta(Some(&sp("a/b/c/new.txt"))).unwrap().id, id); // identity kept
        // Identity duplicate (a copy that preserves the xattrs): the second one is reassigned.
        let f = r.open_any(Some(&sp("a/other.txt"))).unwrap();
        xattr_set(f.as_fd(), super::super::XATTR_ID, &id.unwrap().0).unwrap();
        let rep = r.rescan(None).unwrap();
        assert_eq!((rep.ids_assigned, rep.duplicates), (0, 1));
        assert_ne!(
            r.meta(Some(&sp("a/other.txt"))).unwrap().id,
            r.meta(Some(&sp("a/b/c/new.txt"))).unwrap().id
        );
    }

    #[test]
    fn verify_reports_without_modifying() {
        let (d, r) = setup();
        r.atomic_write(&sp("ok.txt"), &mut &b"ok"[..]).unwrap();
        r.atomic_write(&sp("touched.txt"), &mut &b"v1"[..]).unwrap();
        std::fs::write(d.path().join("touched.txt"), b"edited outside").unwrap(); // changed outside the application
        std::fs::write(d.path().join("added.txt"), b"x").unwrap(); // added outside the application
        std::fs::create_dir(d.path().join("sub")).unwrap();
        let rep = r.verify(None).unwrap();
        let mut missing = rep.missing_id.clone();
        missing.sort();
        assert_eq!(missing, ["/", "added.txt", "sub"]);
        assert_eq!(rep.modified, ["touched.txt"]);
        assert!(rep.duplicates.is_empty());
        assert_eq!((rep.files, rep.dirs), (3, 2));
        // Read-only: nothing was assigned.
        assert_eq!(r.verify(None).unwrap().missing_id.len(), 3);
    }

    #[test]
    fn key_is_created_once() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.key");
        let k = load_or_create_key(&p).unwrap();
        assert_eq!(load_or_create_key(&p).unwrap(), k);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
