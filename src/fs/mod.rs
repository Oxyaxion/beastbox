//! File layer: the only module that touches the disk (§3) and the only one allowed to use `unsafe` (FreeBSD FFI).
//!
//! Capsicum-compatible design (§0.3): after the roots are opened at startup, **every** access is an
//! `openat` relative to a descriptor, with `O_RESOLVE_BENEATH` (the kernel forbids leaving the root)
//! and `O_NOFOLLOW` on the last component. No absolute-path call outside `Root::open_dir`.
#![allow(unsafe_code)]

mod casper;
mod dir;
mod manifest;
mod safepath;
mod trash;
mod write;

pub use casper::CasperNet;

/// `cap_init()` forks a service child that inherits **every** open descriptor, a neighbour test's file locks
/// included. A test that opens the channel therefore re-executes its own binary and forks there: Rust opens files
/// with `O_CLOEXEC`, so the exec drops them and only that child process carries the service. Returns `true` in
/// the parent, which is then done (`false`: we are the child, run the body).
#[cfg(test)]
pub(crate) fn forked_elsewhere(test_name: &str) -> bool {
    const MARKER: &str = "BEASTBOX_CAP_INIT_CHILD";
    if std::env::var_os(MARKER).is_some() {
        return false;
    }
    let exe = std::env::current_exe().expect("current_exe");
    let status = std::process::Command::new(exe)
        .args(["--exact", test_name, "--nocapture"])
        .env(MARKER, "1")
        .status()
        .expect("re-run the test in its own process");
    assert!(status.success(), "{test_name} failed in its own process: {status}");
    true
}

pub use dir::{DirReader, Meta, RescanReport, Space, VERIFY_MAX, VerifyReport, load_or_create_key};
pub use write::{
    AtomicWriter, CopyReport, Journal, MAX_CHUNKS, MAX_TAG_LEN, MAX_TAGS, Pending, Refused, Written, is as is_refused,
    normalize_tag, recorded_sha1,
};

#[cfg(feature = "fuzzing")]
pub use manifest::fuzz as fuzz_manifest;
#[cfg(test)]
pub(crate) use manifest::tests::copy_without_xattrs;
pub use manifest::{MANIFEST, ManifestApplied, ManifestReport, RESCAN_READERS};
pub use safepath::SafePath;
pub use trash::{TRASH_LIST_MAX, Trashed};
#[cfg(feature = "fuzzing")]
pub use write::fuzz_restore;

use std::ffi::{CStr, CString};

use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Folder for atomic-write temporaries, at the root of the user's dataset (§0.2).
pub const TMP_DIR: &str = ".beastbox-tmp";
/// The user's trash (§6).
pub const TRASH_DIR: &str = ".trash";
/// Reserved names at a user's root: invisible and refused by WebDAV.
/// Chunks of uploads in progress (upload v2, §7), same dataset as the target.
pub const UPLOADS_DIR: &str = ".beastbox-uploads";
/// Reserved folders, created by `ensure_layout`.
const RESERVED_DIRS: [&str; 3] = [TMP_DIR, TRASH_DIR, UPLOADS_DIR];
/// Reserved names at a user's root: refused by `SafePath`, hidden from listings (clients, index, verify).
pub const RESERVED: [&str; 4] = [TMP_DIR, TRASH_DIR, UPLOADS_DIR, manifest::MANIFEST];

const XATTR_ID: &CStr = c"beastbox.id";
/// Prefix of checksum xattrs: never copied over on replacement, they are recomputed (§6).
const XATTR_CKSUM_PREFIX: &[u8] = b"beastbox.cksum";
const XATTR_PROBE: &CStr = c"beastbox.probe";
/// Size cap for an xattr read: our attributes are small, nothing must grow the memory.
const XATTR_MAX: usize = 64 * 1024;
/// Accepted local filesystems (§2: never NFS, SMB, FUSE).
const ALLOWED_FS: [&str; 2] = ["zfs", "ufs"];

/// A file's persistent identity (§6): 128 random bits in the `user.beastbox.id` xattr.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FileId(pub [u8; 16]);

impl FileId {
    pub fn random() -> io::Result<Self> {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).map_err(io::Error::other)?;
        Ok(Self(b))
    }
}

impl std::fmt::Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// Owned folder descriptor: root of a tenant, of a user, or a subfolder.
#[derive(Debug)]
pub struct Root {
    fd: OwnedFd,
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn openat(dir: BorrowedFd<'_>, name: &CStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<OwnedFd> {
    let flags = flags | libc::O_RESOLVE_BENEATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `dir` is a valid borrowed descriptor, `name` a NUL-terminated C string; the descriptor
    // returned (if >= 0) belongs to us and is immediately wrapped in an OwnedFd.
    let fd = cvt(unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, libc::c_uint::from(mode)) })?;
    // SAFETY: `fd` was just opened and is owned by no one else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fsync(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: valid borrowed descriptor.
    cvt(unsafe { libc::fsync(fd.as_raw_fd()) }).map(drop)
}

fn renameat(from_dir: BorrowedFd<'_>, from: &CStr, to_dir: BorrowedFd<'_>, to: &CStr) -> io::Result<()> {
    // SAFETY: valid borrowed descriptors, NUL-terminated C strings.
    cvt(unsafe { libc::renameat(from_dir.as_raw_fd(), from.as_ptr(), to_dir.as_raw_fd(), to.as_ptr()) }).map(drop)
}

fn unlinkat(dir: BorrowedFd<'_>, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: valid borrowed descriptor, NUL-terminated C string.
    cvt(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) }).map(drop)
}

fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is a buffer of the right size, filled by the kernel if the call succeeds.
    cvt(unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) })?;
    // SAFETY: fstat succeeded, the structure is initialized.
    Ok(unsafe { st.assume_init() })
}

// ---------- xattr (user namespace), by descriptor only: Capsicum-compatible ----------

fn xattr_get(fd: BorrowedFd<'_>, name: &CStr) -> io::Result<Option<Vec<u8>>> {
    // SAFETY: null pointer + size 0: the kernel only returns the attribute's size.
    let len = unsafe {
        libc::extattr_get_fd(
            fd.as_raw_fd(),
            libc::EXTATTR_NAMESPACE_USER,
            name.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if len < 0 {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::ENOATTR) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    let len = usize::try_from(len).map_err(io::Error::other)?;
    if len > XATTR_MAX {
        return Err(io::Error::other("xattr trop gros"));
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` has exactly `len` writable bytes.
    let n = unsafe {
        libc::extattr_get_fd(
            fd.as_raw_fd(),
            libc::EXTATTR_NAMESPACE_USER,
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            len,
        )
    };
    let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
    buf.truncate(n);
    Ok(Some(buf))
}

fn xattr_set(fd: BorrowedFd<'_>, name: &CStr, val: &[u8]) -> io::Result<()> {
    // SAFETY: `val` is a valid slice of `val.len()` bytes.
    let n = unsafe {
        libc::extattr_set_fd(
            fd.as_raw_fd(),
            libc::EXTATTR_NAMESPACE_USER,
            name.as_ptr(),
            val.as_ptr().cast(),
            val.len(),
        )
    };
    if usize::try_from(n).ok() == Some(val.len()) {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn xattr_del(fd: BorrowedFd<'_>, name: &CStr) -> io::Result<()> {
    // SAFETY: valid borrowed descriptor, NUL-terminated C string.
    cvt(unsafe { libc::extattr_delete_fd(fd.as_raw_fd(), libc::EXTATTR_NAMESPACE_USER, name.as_ptr()) }).map(drop)
}

/// Tests elsewhere in the crate: every user xattr of a file or folder, by path, sorted (a fingerprint of a tree).
#[cfg(test)]
pub(crate) fn xattrs_of(path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let Ok(f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut v: Vec<_> = xattr_list(f.as_fd())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|n| Some((n.to_string_lossy().into_owned(), xattr_get(f.as_fd(), &n).ok()??)))
        .collect();
    v.sort();
    v
}

/// Names of the user-namespace xattrs. Kernel format: a sequence of (1-byte length, name without NUL).
fn xattr_list(fd: BorrowedFd<'_>) -> io::Result<Vec<CString>> {
    // SAFETY: null pointer + size 0: the kernel only returns the list's size.
    let len = unsafe { libc::extattr_list_fd(fd.as_raw_fd(), libc::EXTATTR_NAMESPACE_USER, std::ptr::null_mut(), 0) };
    let len = usize::try_from(len).map_err(|_| io::Error::last_os_error())?;
    if len > XATTR_MAX {
        return Err(io::Error::other("liste de xattr trop grande"));
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` has exactly `len` writable bytes.
    let n = unsafe {
        libc::extattr_list_fd(
            fd.as_raw_fd(),
            libc::EXTATTR_NAMESPACE_USER,
            buf.as_mut_ptr().cast(),
            len,
        )
    };
    let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
    buf.truncate(n);
    let mut out = Vec::new();
    let mut rest = buf.as_slice();
    while let Some((&l, tail)) = rest.split_first() {
        let (name, tail) = tail
            .split_at_checked(usize::from(l))
            .ok_or_else(|| io::Error::other("truncated xattr list"))?;
        out.push(CString::new(name).map_err(io::Error::other)?);
        rest = tail;
    }
    Ok(out)
}

impl Root {
    /// Opens a root by absolute path. **Only at startup** (before Capsicum, J5).
    pub fn open_dir(path: &Path) -> io::Result<Self> {
        let c = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
        // SAFETY: valid C string; the returned descriptor belongs to us.
        let fd = cvt(unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
        // SAFETY: `fd` was just opened and is owned by no one else.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Opens a subfolder, never leaving this root.
    pub fn open_subdir(&self, path: &SafePath) -> io::Result<Self> {
        self.open_dir_raw(&cstr(path.as_str())?)
    }

    fn open_dir_raw(&self, name: &CStr) -> io::Result<Self> {
        Ok(Self {
            fd: openat(self.fd.as_fd(), name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?,
        })
    }

    /// Identifier of the mounted filesystem (`st_dev`): used to check that a root is a distinct dataset.
    pub fn dev(&self) -> io::Result<u64> {
        Ok(fstat(self.fd.as_fd())?.st_dev)
    }

    fn statfs(&self) -> io::Result<libc::statfs> {
        let mut sf = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `sf` is a buffer of the right size, filled by the kernel if the call succeeds.
        cvt(unsafe { libc::fstatfs(self.fd.as_raw_fd(), sf.as_mut_ptr()) })?;
        // SAFETY: fstatfs succeeded, the structure is initialized.
        Ok(unsafe { sf.assume_init() })
    }

    fn fs_type(&self) -> io::Result<String> {
        let sf = self.statfs()?;
        // SAFETY: f_fstypename is a NUL-terminated array filled by the kernel.
        let name = unsafe { CStr::from_ptr(sf.f_fstypename.as_ptr()) };
        Ok(name.to_string_lossy().into_owned())
    }

    /// §2: refuses a root that is not on a local FS accepting xattrs (write, read, delete).
    pub fn check_storage(&self) -> crate::Result<()> {
        let t = self.fs_type()?;
        if !ALLOWED_FS.contains(&t.as_str()) {
            return Err(crate::Error::Config(format!(
                "filesystem \"{t}\" refused (local ZFS or UFS required)"
            )));
        }
        let probe = FileId::random()?;
        let fd = self.fd.as_fd();
        let ok = xattr_set(fd, XATTR_PROBE, &probe.0)
            .and_then(|()| xattr_get(fd, XATTR_PROBE))
            .map(|v| v.as_deref() == Some(&probe.0[..]));
        let del = xattr_del(fd, XATTR_PROBE);
        match (ok, del) {
            (Ok(true), Ok(())) => Ok(()),
            (Err(e), _) | (_, Err(e)) => Err(crate::Error::Config(format!("xattrs unusable on the root: {e}"))),
            (Ok(false), _) => Err(crate::Error::Config(
                "xattr read back differs from what was written".into(),
            )),
        }
    }

    /// Creates `.beastbox-tmp/` and `.trash/` (0700) at a user's root if missing.
    pub fn ensure_layout(&self) -> io::Result<()> {
        for d in RESERVED_DIRS {
            let c = cstr(d)?;
            // SAFETY: valid borrowed descriptor, NUL-terminated C string.
            let r = unsafe { libc::mkdirat(self.fd.as_raw_fd(), c.as_ptr(), 0o700) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// §0.2: empties `.beastbox-tmp/` at startup (temporaries of interrupted writes). Returns the number deleted.
    pub fn clean_tmp(&self) -> io::Result<usize> {
        let tmp = self.open_dir_raw(&cstr(TMP_DIR)?)?;
        let mut removed = 0;
        loop {
            // In bounded batches so as not to accumulate names in memory.
            let names = read_dir_names(tmp.fd.as_fd(), 1024)?;
            if names.is_empty() {
                return Ok(removed);
            }
            for n in &names {
                // Only files are created here; an unexpected folder is reported and not deleted (no rm -r).
                if let Err(e) = unlinkat(tmp.fd.as_fd(), n, 0) {
                    return Err(io::Error::new(e.kind(), format!("nettoyage de {TMP_DIR} : {e}")));
                }
                removed += 1;
            }
        }
    }

    /// Reads a file's persistent identity (never assigning it: §6, assignment at creation only).
    pub fn file_id(&self, path: &SafePath) -> io::Result<Option<FileId>> {
        let f = openat(self.fd.as_fd(), &cstr(path.as_str())?, libc::O_RDONLY, 0)?;
        read_id(f.as_fd())
    }

    /// Atomic write (§0.2): temporary in `.beastbox-tmp/`, copy of the old file's xattrs
    /// (identity, tags, favorites; not the checksums), `fsync`, `rename`, `fsync` of the parent folder.
    /// A crash at any instant leaves the old or the new version, never a mix.
    pub fn atomic_write(&self, path: &SafePath, data: &mut dyn Read) -> io::Result<FileId> {
        let mut w = self.writer(path)?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = data.read(&mut buf)?;
            if n == 0 {
                break;
            }
            w.write(buf.get(..n).unwrap_or_default())?;
        }
        Ok(w.commit(None, None, |_| true)?.id)
    }
}

fn read_id(fd: BorrowedFd<'_>) -> io::Result<Option<FileId>> {
    Ok(xattr_get(fd, XATTR_ID)?
        .and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok())
        .map(FileId))
}

/// Reads at most `max` names of a folder (excluding `.` and `..`) from a descriptor, without consuming it.
pub(super) fn read_dir_names(dir: BorrowedFd<'_>, max: usize) -> io::Result<Vec<CString>> {
    // fdopendir takes ownership of the descriptor: we give it a duplicate.
    let dup = dir.try_clone_to_owned()?;
    // SAFETY: `dup` is a valid folder descriptor whose ownership we hand over to fdopendir.
    let dirp = unsafe { libc::fdopendir(std::os::fd::IntoRawFd::into_raw_fd(dup)) };
    if dirp.is_null() {
        return Err(io::Error::last_os_error());
    }
    // A duplicate shares the read position: start again from the beginning.
    // SAFETY: `dirp` is valid (non-null).
    unsafe { libc::rewinddir(dirp) };
    let mut out = Vec::new();
    while out.len() < max {
        // SAFETY: `dirp` is valid; readdir returns null at the end of the folder.
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        // SAFETY: `ent` points to a valid entry until the next readdir; d_name is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        if name != c"." && name != c".." {
            out.push(name.to_owned());
        }
    }
    // SAFETY: `dirp` is valid and no longer used afterwards.
    unsafe { libc::closedir(dirp) };
    Ok(out)
}

/// Creation mask: folders 0700, files 0600 (§6). Call it at the very start of `main`.
pub fn set_umask() {
    // SAFETY: umask only changes the process mask.
    unsafe { libc::umask(0o077) };
}

/// Reads the system time zone (`TZ`, otherwise `/etc/localtime`); call it once at startup, before the threads.
pub fn init_timezone() {
    // Missing from the libc crate for FreeBSD; a POSIX function of the system libc.
    unsafe extern "C" {
        fn tzset();
    }
    // SAFETY: tzset only loads the time zone rules into libc; called before any other thread.
    unsafe { tzset() };
}

/// Capsicum capability mode (§0.3): from here on the process can only use descriptors it already holds; any path,
/// outgoing connection or new process is refused by the kernel (`ECAPMODE`). Irreversible, for every thread.
pub fn enter_capability_mode() -> io::Result<()> {
    // SAFETY: cap_enter takes no argument and only changes the mode of the process.
    cvt(unsafe { libc::cap_enter() }).map(drop)
}

/// Offset of the server's local time from UTC at instant `ts`, in seconds (DST included); 0 if unknown.
pub fn utc_offset(ts: i64) -> i64 {
    let t: libc::time_t = ts;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::zeroed();
    // SAFETY: valid pointers to buffers of the right size; localtime_r is reentrant.
    let r = unsafe { libc::localtime_r(&t, tm.as_mut_ptr()) };
    if r.is_null() {
        return 0;
    }
    // SAFETY: localtime_r succeeded and filled `tm`.
    unsafe { tm.assume_init() }.tm_gmtoff
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::Duration;

    fn root(dir: &Path) -> Root {
        let r = Root::open_dir(dir).unwrap();
        r.ensure_layout().unwrap();
        r
    }

    fn sp(s: &str) -> SafePath {
        SafePath::new(s).unwrap()
    }

    #[test]
    fn storage_check_accepts_local_zfs() {
        let d = tempfile::tempdir().unwrap();
        root(d.path()).check_storage().unwrap();
    }

    /// Restore simulated on real files (what restic does, or a copy that keeps xattrs): a new file,
    /// hence a new inode, with the same content, the same xattrs and the same time to the nanosecond. The ETag does
    /// not change: clients re-download nothing. A real server write, on the other hand, changes it.
    #[test]
    fn file_etag_survives_a_restore_by_copy() {
        let d = tempfile::tempdir().unwrap();
        let r = root(d.path());
        r.atomic_write(&sp("doc.txt"), &mut &b"contenu"[..]).unwrap();
        let before = r.meta(Some(&sp("doc.txt"))).unwrap();
        assert!(
            before.id.is_some() && before.sha1.is_some(),
            "written by the server: identity and SHA-1"
        );

        // Copy alongside (new inode), xattrs and time copied, then put back in place of the original.
        std::fs::write(d.path().join("copie.tmp"), b"contenu").unwrap();
        let src = openat(r.fd.as_fd(), c"doc.txt", libc::O_RDONLY, 0).unwrap();
        let dst = openat(r.fd.as_fd(), c"copie.tmp", libc::O_RDWR, 0).unwrap();
        for name in xattr_list(src.as_fd()).unwrap() {
            let v = xattr_get(src.as_fd(), &name).unwrap().unwrap();
            xattr_set(dst.as_fd(), &name, &v).unwrap();
        }
        let when = std::time::UNIX_EPOCH
            + Duration::new(
                u64::try_from(before.mtime).unwrap(),
                u32::try_from(before.mtime_nsec).unwrap(),
            );
        std::fs::File::from(dst).set_modified(when).unwrap();
        drop(src);
        std::fs::rename(d.path().join("copie.tmp"), d.path().join("doc.txt")).unwrap();

        let after = r.meta(Some(&sp("doc.txt"))).unwrap();
        assert_ne!(before.ino, after.ino, "the copy does have another inode");
        assert_eq!((after.id, after.sha1.as_deref()), (before.id, before.sha1.as_deref()));
        assert_eq!(
            crate::etag::of(&before),
            crate::etag::of(&after),
            "same ETag after the restore"
        );

        // Two server writes of the same size and the same announced time (`X-OC-Mtime`), different contents: the
        // recorded SHA-1 (valid, the time is that of the write) tells them apart, the ETag changes.
        let put = |body: &[u8]| {
            let mut w = r.writer(&sp("doc.txt")).unwrap();
            w.write(body).unwrap();
            w.commit(Some(1_600_000_000), None, |_| true).unwrap();
            r.meta(Some(&sp("doc.txt"))).unwrap()
        };
        let (v1, v2, v2_again) = (put(b"contenu"), put(b"CONTENU"), put(b"CONTENU"));
        assert_eq!((v1.size, v1.mtime, v1.mtime_nsec), (v2.size, v2.mtime, v2.mtime_nsec));
        assert!(v1.sha1.is_some() && v2.sha1.is_some() && v1.sha1 != v2.sha1);
        assert_eq!(v1.id, v2.id, "same identity (atomic replacement)");
        assert_ne!(
            crate::etag::of(&v1),
            crate::etag::of(&v2),
            "content changed: ETag changed"
        );
        assert_eq!(
            crate::etag::of(&v2),
            crate::etag::of(&v2_again),
            "same content rewritten: same ETag"
        );
    }

    #[test]
    fn identity_and_xattrs_survive_replacement() {
        let d = tempfile::tempdir().unwrap();
        let r = root(d.path());
        let id = r.atomic_write(&sp("a.txt"), &mut &b"v1"[..]).unwrap();
        // A tag (any xattr) and a checksum on the old file.
        let f = openat(r.fd.as_fd(), c"a.txt", libc::O_RDONLY, 0).unwrap();
        xattr_set(f.as_fd(), c"beastbox.tags", b"facture").unwrap();
        xattr_set(f.as_fd(), c"beastbox.cksum.sha1", b"old").unwrap();
        drop(f);
        let id2 = r.atomic_write(&sp("a.txt"), &mut &b"v2"[..]).unwrap();
        assert_eq!(id, id2);
        assert_eq!(std::fs::read(d.path().join("a.txt")).unwrap(), b"v2");
        let f = openat(r.fd.as_fd(), c"a.txt", libc::O_RDONLY, 0).unwrap();
        assert_eq!(
            xattr_get(f.as_fd(), c"beastbox.tags").unwrap().as_deref(),
            Some(&b"facture"[..])
        );
        // The old sum is not copied over: the new content's ("v2") replaces it.
        let sum = xattr_get(f.as_fd(), c"beastbox.cksum.sha1").unwrap().unwrap();
        assert!(
            sum.starts_with(b"a1047eab1035d58682a53557e0b2a75edbfd15fd "),
            "{:?}",
            String::from_utf8_lossy(&sum)
        );
        assert_eq!(r.file_id(&sp("a.txt")).unwrap(), Some(id));
        // Deleted then re-created (inode possibly reused): new identity.
        std::fs::remove_file(d.path().join("a.txt")).unwrap();
        let id3 = r.atomic_write(&sp("a.txt"), &mut &b"v3"[..]).unwrap();
        assert_ne!(id, id3);
        assert_eq!(r.clean_tmp().unwrap(), 0);
    }

    #[test]
    fn write_in_subdir_and_no_escape() {
        let d = tempfile::tempdir().unwrap();
        let r = root(d.path());
        std::fs::create_dir(d.path().join("sub")).unwrap();
        r.atomic_write(&sp("sub/x"), &mut &b"x"[..]).unwrap();
        assert_eq!(std::fs::read(d.path().join("sub/x")).unwrap(), b"x");
        // Outgoing symlink: the kernel refuses (O_RESOLVE_BENEATH / O_NOFOLLOW).
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), d.path().join("evil")).unwrap();
        assert!(r.atomic_write(&sp("evil/x"), &mut &b"x"[..]).is_err());
        assert!(r.open_subdir(&sp("evil")).is_err());
        assert!(!outside.path().join("x").exists());
        // Internal symlink to ..: refused too.
        std::os::unix::fs::symlink("..", d.path().join("up")).unwrap();
        assert!(r.open_subdir(&sp("up")).is_err());
        assert_eq!(r.clean_tmp().unwrap(), 0);
    }

    #[test]
    fn clean_tmp_removes_orphans() {
        let d = tempfile::tempdir().unwrap();
        let r = root(d.path());
        for i in 0..1500 {
            std::fs::write(d.path().join(TMP_DIR).join(i.to_string()), b"").unwrap();
        }
        assert_eq!(r.clean_tmp().unwrap(), 1500);
        assert_eq!(std::fs::read_dir(d.path().join(TMP_DIR)).unwrap().count(), 0);
    }

    const CRASH_SIZE: usize = 4 * 1024 * 1024;
    const CRASH_ENV: &str = "BEASTBOX_CRASH_CHILD";

    /// §0.2: `kill -9` during atomic writes in a loop. After each kill, the file is
    /// entirely the old or the new version, the identity is kept and cleanup empties the temporary.
    /// Limit: does not simulate a power cut (the kernel cache survives a kill -9).
    #[test]
    fn crash_during_atomic_write() {
        if let Ok(dir) = std::env::var(CRASH_ENV) {
            let r = Root::open_dir(Path::new(&dir)).unwrap();
            for v in 0u8.. {
                let byte = v % 250 + 1;
                r.atomic_write(&sp("f"), &mut io::repeat(byte).take(CRASH_SIZE as u64))
                    .unwrap();
            }
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let r = root(d.path());
        let id = r
            .atomic_write(&sp("f"), &mut io::repeat(0).take(CRASH_SIZE as u64))
            .unwrap();
        let (mut orphans, mut versions) = (0, std::collections::HashSet::new());
        for _ in 0..20 {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "fs::tests::crash_during_atomic_write", "--nocapture"])
                .env(CRASH_ENV, d.path())
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let ms = 5 + u64::from(getrandom::u32().unwrap() % 200);
            std::thread::sleep(Duration::from_millis(ms));
            child.kill().unwrap(); // SIGKILL
            child.wait().unwrap();
            let content = std::fs::read(d.path().join("f")).unwrap();
            assert_eq!(content.len(), CRASH_SIZE);
            let first = content[0];
            assert!(content.iter().all(|&b| b == first), "mixed file");
            assert_eq!(r.file_id(&sp("f")).unwrap(), Some(id));
            versions.insert(first);
            orphans += r.clean_tmp().unwrap();
            assert_eq!(std::fs::read_dir(d.path().join(TMP_DIR)).unwrap().count(), 0);
        }
        // The test is only meaningful if kills happened mid-write and between two writes.
        assert!(orphans > 0, "no kill mid-write");
        assert!(versions.len() > 1, "no write completed");
    }
}
