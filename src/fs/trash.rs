//! The user's trash (§6): listing, restore, permanent delete, expiry.
//! Layout (written by `Root::trash`): `.trash/<slot>/<name>`, the slot carrying in xattrs the original path, the
//! deletion date and the author. Nothing here walks the user's tree outside `.trash/`.

use super::dir::meta_of;
use super::write::{XATTR_TRASH_BY, XATTR_TRASH_PATH, XATTR_TRASH_TIME};
use super::{Root, SafePath, TRASH_DIR, cstr, fsync, openat, read_dir_names, renameat, unlinkat, xattr_get, xattr_set};
use std::ffi::CStr;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};

/// Maximum number of items listed (beyond that, the list is truncated; deletes remain possible).
pub const TRASH_LIST_MAX: usize = 10_000;

/// A trash item.
#[derive(Debug, Clone, PartialEq)]
pub struct Trashed {
    /// Slot in `.trash/` (32 hexadecimal characters): the item's identifier for restoring or deleting.
    pub slot: String,
    pub name: String,
    /// Original path (validated: an unreadable or hostile xattr gives an item restored at the root).
    pub origin: Option<SafePath>,
    pub deleted: i64,
    pub by: String,
    pub is_dir: bool,
    pub size: u64,
}

fn valid_slot(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn text(fd: BorrowedFd<'_>, name: &CStr) -> Option<String> {
    xattr_get(fd, name)
        .ok()
        .flatten()
        .and_then(|v| String::from_utf8(v).ok())
}

/// Permanently deletes `name` in `dir`, recursively, never following a link (`openat` refuses links).
fn remove_tree(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<()> {
    match openat(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
        Ok(sub) => {
            loop {
                let names = read_dir_names(sub.as_fd(), 1024)?;
                if names.is_empty() {
                    break;
                }
                for n in &names {
                    remove_tree(sub.as_fd(), n)?;
                }
            }
            unlinkat(dir, name, libc::AT_REMOVEDIR)
        }
        // File, link or special: remove the entry itself.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP | libc::EMLINK)) => {
            unlinkat(dir, name, 0)
        }
        Err(e) => Err(e),
    }
}

impl Root {
    fn trash_dir(&self) -> io::Result<Root> {
        self.open_dir_raw(&cstr(TRASH_DIR)?)
    }

    /// Reads a slot: (slot folder, item name).
    fn slot(&self, trash: &Root, slot: &str) -> io::Result<(Root, std::ffi::CString)> {
        if !valid_slot(slot) {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        let d = trash.open_dir_raw(&cstr(slot)?)?;
        let names = read_dir_names(d.fd.as_fd(), 2)?;
        match names.as_slice() {
            [one] => {
                let n = one.clone();
                Ok((d, n))
            }
            _ => Err(io::Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    /// A slot's folder and the name of the item it holds (to read inside an item).
    pub fn trash_item(&self, slot: &str) -> io::Result<(Root, String)> {
        let (d, n) = self.slot(&self.trash_dir()?, slot)?;
        let n = n
            .into_string()
            .map_err(|_| io::Error::from_raw_os_error(libc::ENOENT))?;
        Ok((d, n))
    }

    /// Trash items, newest first (at most `TRASH_LIST_MAX`).
    pub fn trash_list(&self) -> io::Result<Vec<Trashed>> {
        let trash = self.trash_dir()?;
        let mut out = Vec::new();
        for s in read_dir_names(trash.fd.as_fd(), TRASH_LIST_MAX)? {
            let Ok(slot) = s.into_string() else { continue };
            let Ok((d, n)) = self.slot(&trash, &slot) else { continue };
            let Ok(meta) =
                openat(d.fd.as_fd(), &n, libc::O_RDONLY | libc::O_NONBLOCK, 0).and_then(|f| meta_of(f.as_fd()))
            else {
                continue;
            };
            let fd = d.fd.as_fd();
            // Date lost (restore without xattrs): dated from its discovery, otherwise the next purge would take it (1970).
            let deleted = text(fd, XATTR_TRASH_TIME)
                .and_then(|t| t.parse().ok())
                .unwrap_or_else(|| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs() as i64);
                    if let Err(e) = xattr_set(fd, XATTR_TRASH_TIME, now.to_string().as_bytes()) {
                        tracing::warn!("trash: date of {slot} not written: {e}");
                    }
                    now
                });
            out.push(Trashed {
                origin: text(fd, XATTR_TRASH_PATH).and_then(|p| SafePath::new(&p).ok()),
                deleted,
                by: text(fd, XATTR_TRASH_BY).unwrap_or_default(),
                name: n.to_string_lossy().into_owned(),
                is_dir: meta.is_dir,
                size: meta.size,
                slot,
            });
        }
        out.sort_by_key(|t| std::cmp::Reverse(t.deleted));
        Ok(out)
    }

    /// Restores an item to its original path (parent folders re-created if needed); name already taken → suffix
    /// "(restored)", "(restored 2)"… Parent impossible to re-create (a file occupies the path) → root.
    /// Returns the path where the item was put back. Identity, tags and favorites come back with it.
    /// shortcut: existence checked then `renameat` (no non-overwriting renameat): a concurrent creation with the same
    /// name in the same millisecond would be overwritten; acceptable for a manual action, revisit with a per-path lock.
    pub fn trash_restore(&self, slot: &str) -> io::Result<SafePath> {
        let trash = self.trash_dir()?;
        let (d, n) = self.slot(&trash, slot)?;
        let name = n
            .to_str()
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?
            .to_owned();
        let origin = text(d.fd.as_fd(), XATTR_TRASH_PATH).and_then(|p| SafePath::new(&p).ok());
        let parent = origin.as_ref().and_then(|o| o.split_parent().0);
        let parent = match parent {
            Some(p) if self.make_parents(&p).is_ok() => Some(p),
            _ => None,
        };
        let target = |suffix: usize| -> io::Result<SafePath> {
            let n = match suffix {
                0 => name.clone(),
                _ => {
                    let (stem, ext) = match name.rsplit_once('.') {
                        Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
                        _ => (name.as_str(), String::new()),
                    };
                    let tag = if suffix == 1 {
                        "restored".to_owned()
                    } else {
                        format!("restored {suffix}")
                    };
                    format!("{stem} ({tag}){ext}")
                }
            };
            SafePath::new(&match &parent {
                Some(p) => format!("{}/{n}", p.as_str()),
                None => n,
            })
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
        };
        let mut to = target(0)?;
        let mut i = 1;
        while self.meta(Some(&to)).is_ok() {
            if i > 100 {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            to = target(i)?;
            i += 1;
        }
        let dest = match &parent {
            Some(p) => self.open_subdir(p)?,
            None => self.try_clone()?,
        };
        let (_, tname) = to.split_parent();
        renameat(d.fd.as_fd(), &n, dest.fd.as_fd(), &cstr(tname)?)?;
        fsync(dest.fd.as_fd())?;
        unlinkat(trash.fd.as_fd(), &cstr(slot)?, libc::AT_REMOVEDIR)?;
        fsync(trash.fd.as_fd())?;
        Ok(to)
    }

    /// Re-creates the missing folders of `dir` (each with its identity, like `mkdir`).
    fn make_parents(&self, dir: &SafePath) -> io::Result<()> {
        let mut at = String::new();
        for comp in dir.as_str().split('/') {
            if !at.is_empty() {
                at.push('/');
            }
            at.push_str(comp);
            let p = SafePath::new(&at).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
            match self.meta(Some(&p)) {
                Ok(m) if m.is_dir => {}
                Ok(_) => return Err(io::Error::from_raw_os_error(libc::ENOTDIR)),
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    self.mkdir(&p)?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Permanently deletes a trash item.
    pub fn trash_purge(&self, slot: &str) -> io::Result<()> {
        if !valid_slot(slot) {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        let trash = self.trash_dir()?;
        remove_tree(trash.fd.as_fd(), &cstr(slot)?)?;
        fsync(trash.fd.as_fd())
    }

    /// Empties the trash (every slot, even those the listing cannot display). Returns their number.
    pub fn trash_empty(&self) -> io::Result<usize> {
        let trash = self.trash_dir()?;
        let mut n = 0;
        loop {
            let slots = read_dir_names(trash.fd.as_fd(), 1024)?;
            if slots.is_empty() {
                break;
            }
            for s in &slots {
                remove_tree(trash.fd.as_fd(), s)?;
                n += 1;
            }
        }
        fsync(trash.fd.as_fd())?;
        Ok(n)
    }

    /// Permanently deletes the items trashed before `before` (Unix seconds). Returns their number.
    /// Only walks `.trash/` (§0.4).
    pub fn trash_expire(&self, before: i64) -> io::Result<usize> {
        let mut n = 0;
        for t in self.trash_list()? {
            if t.deleted < before && self.trash_purge(&t.slot).is_ok() {
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Root) {
        let d = tempfile::tempdir().unwrap();
        let r = Root::open_dir(d.path()).unwrap();
        r.ensure_layout().unwrap();
        (d, r)
    }
    fn sp(s: &str) -> SafePath {
        SafePath::new(s).unwrap()
    }

    #[test]
    fn restore_keeps_identity_and_tags() {
        let (d, r) = setup();
        r.mkdir(&sp("Docs")).unwrap();
        let id = r.atomic_write(&sp("Docs/a.txt"), &mut &b"A"[..]).unwrap();
        r.set_tags(Some(&sp("Docs/a.txt")), &["urgent".into()]).unwrap();
        r.trash(&sp("Docs/a.txt"), "alice").unwrap();
        let l = r.trash_list().unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(
            (
                l[0].name.as_str(),
                l[0].origin.as_ref().map(|p| p.as_str()),
                l[0].by.as_str()
            ),
            ("a.txt", Some("Docs/a.txt"), "alice")
        );
        assert!(l[0].deleted > 0 && !l[0].is_dir && l[0].size == 1);
        assert_eq!(r.trash_restore(&l[0].slot).unwrap().as_str(), "Docs/a.txt");
        assert_eq!(r.file_id(&sp("Docs/a.txt")).unwrap(), Some(id));
        assert_eq!(r.labels(Some(&sp("Docs/a.txt"))).unwrap().0, ["urgent"]);
        assert!(r.trash_list().unwrap().is_empty());
        assert_eq!(std::fs::read_dir(d.path().join(TRASH_DIR)).unwrap().count(), 0);
    }

    #[test]
    fn restore_recreates_parents_and_never_overwrites() {
        let (_d, r) = setup();
        r.mkdir(&sp("A")).unwrap();
        r.mkdir(&sp("A/B")).unwrap();
        r.atomic_write(&sp("A/B/n.txt"), &mut &b"old"[..]).unwrap();
        r.trash(&sp("A/B/n.txt"), "alice").unwrap();
        r.trash(&sp("A"), "alice").unwrap();
        // The parent folder is gone: re-created. The name is taken: suffix, the existing one stays intact.
        let slot = |name: &str| {
            r.trash_list()
                .unwrap()
                .into_iter()
                .find(|t| t.name == name)
                .unwrap()
                .slot
        };
        let s = slot("n.txt");
        assert_eq!(r.trash_restore(&s).unwrap().as_str(), "A/B/n.txt");
        r.trash(&sp("A/B/n.txt"), "alice").unwrap();
        r.atomic_write(&sp("A/B/n.txt"), &mut &b"new"[..]).unwrap();
        assert_eq!(
            r.trash_restore(&slot("n.txt")).unwrap().as_str(),
            "A/B/n (restored).txt"
        );
        assert_eq!(std::fs::read(_d.path().join("A/B/n.txt")).unwrap(), b"new");
        // The original folder A (emptied of n.txt) comes back next to the one that was re-created.
        assert_eq!(r.trash_restore(&slot("A")).unwrap().as_str(), "A (restored)");
    }

    #[test]
    fn purge_and_expire_stay_inside_trash() {
        let (d, r) = setup();
        r.mkdir(&sp("D")).unwrap();
        r.mkdir(&sp("D/sous")).unwrap();
        r.atomic_write(&sp("D/sous/x"), &mut &b"x"[..]).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("D/lien")).unwrap();
        std::fs::write(d.path().join("garde.txt"), b"g").unwrap();
        r.trash(&sp("D"), "alice").unwrap();
        let s = r.trash_list().unwrap()[0].slot.clone();
        // Hostile slots refused.
        for bad in ["..", "../garde.txt", "ABCDEF0123456789ABCDEF0123456789", "x"] {
            assert!(r.trash_purge(bad).is_err() && r.trash_restore(bad).is_err(), "{bad}");
        }
        r.trash_purge(&s).unwrap();
        assert!(r.trash_list().unwrap().is_empty());
        assert!(std::path::Path::new("/etc/passwd").exists() && d.path().join("garde.txt").exists());
        r.atomic_write(&sp("y"), &mut &b"y"[..]).unwrap();
        r.trash(&sp("y"), "alice").unwrap();
        assert_eq!(r.trash_expire(0).unwrap(), 0);
        assert_eq!(r.trash_expire(i64::MAX).unwrap(), 1);
        assert!(r.trash_list().unwrap().is_empty());
        std::os::unix::fs::symlink("/etc", d.path().join("lien2")).unwrap();
        r.trash(&sp("lien2"), "alice").unwrap();
        assert!(r.trash_list().unwrap().is_empty(), "a link is not listed");
        assert_eq!(r.trash_empty().unwrap(), 1);
        assert!(std::path::Path::new("/etc/passwd").exists());
    }

    #[test]
    fn undated_item_is_dated_on_discovery_not_purged() {
        let (d, r) = setup();
        r.atomic_write(&sp("z"), &mut &b"z"[..]).unwrap();
        r.trash(&sp("z"), "alice").unwrap();
        let slot = r.trash_list().unwrap()[0].slot.clone();
        // Unreadable date, as after a restore that lost the xattrs.
        let f = std::fs::File::open(d.path().join(TRASH_DIR).join(&slot)).unwrap();
        super::super::xattr_set(f.as_fd(), XATTR_TRASH_TIME, b"").unwrap();
        let hour_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 3600;
        assert_eq!(r.trash_expire(hour_ago).unwrap(), 0);
        // The discovery date is written: it holds from one read to the next.
        let t = r.trash_list().unwrap()[0].deleted;
        assert!(t > hour_ago);
        assert_eq!(super::text(f.as_fd(), XATTR_TRASH_TIME), Some(t.to_string()));
    }
}
