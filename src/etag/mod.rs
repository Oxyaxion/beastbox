//! ETags and identifiers exposed to clients (§6). Propagation (renewing the ancestors) lives in `fs/`.

use crate::fs::Meta;
use sha2::{Digest, Sha256};

/// Nextcloud clients handle `oc:fileid` in JSON/JS: at most 53 bits.
const MASK53: u64 = (1 << 53) - 1;

fn hash16(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// ETag (without quotes), recomputed on every read. Opaque to clients: they compare it, without decoding it.
///
/// - **File with an identity**: digest of (identity, mtime in ns, size, SHA-1 recorded at write time). Nothing tied
///   to the physical location (neither inode nor dataset): a restore (restic, a copy that keeps xattrs) or a
///   migration keeps it, and clients only re-download what really changed. The SHA-1 distinguishes two contents
///   of the same size written by the server with the same time announced by the client (`X-OC-Mtime`).
/// - **File without an identity** (arrived outside the application, before `rescan`): (mtime in ns, size, inode).
/// - **Folder**: random value in an xattr, renewed on every write or `rescan`; fallback to (mtime, inode) as long
///   as no xattr has been set.
///
/// Fixed-length parts come first, the only variable-length one (SHA-1) last, and a different prefix per case
/// (`F`, `f`, `d`): two different inputs never give the same hashed byte sequence.
pub fn of(m: &Meta) -> String {
    if m.is_dir {
        if let Some(e) = m.dir_etag {
            return hex(&e);
        }
        return hex(&hash16(&[
            b"d",
            &m.mtime.to_le_bytes(),
            &m.mtime_nsec.to_le_bytes(),
            &m.ino.to_le_bytes(),
        ]));
    }
    let (mtime, nsec, size) = (m.mtime.to_le_bytes(), m.mtime_nsec.to_le_bytes(), m.size.to_le_bytes());
    match m.id {
        Some(id) => {
            let sha1 = m.sha1.as_deref().unwrap_or("");
            hex(&hash16(&[b"F", &id.0, &mtime, &nsec, &size, sha1.as_bytes()]))
        }
        None => hex(&hash16(&[b"f", &mtime, &nsec, &size, &m.ino.to_le_bytes()])),
    }
}

/// `oc:fileid`: derived from the persistent identity; degraded fallback (dataset, inode) before `rescan`.
/// shortcut: no collision detection on the 53 bits (probability ~5e-5 at 1 M files); add it with the index (J4).
pub fn fileid(m: &Meta) -> u64 {
    let b = match m.id {
        Some(id) => id.0,
        None => hash16(&[b"i", &m.dev.to_le_bytes(), &m.ino.to_le_bytes()]),
    };
    let mut first = [0u8; 8];
    first.copy_from_slice(b.get(..8).unwrap_or(&[0; 8]));
    u64::from_be_bytes(first) & MASK53
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FileId;

    fn meta(is_dir: bool) -> Meta {
        Meta {
            is_dir,
            is_file: !is_dir,
            size: 10,
            mtime: 1,
            mtime_nsec: 2,
            ctime: 1,
            ino: 3,
            dev: 4,
            id: None,
            dir_etag: None,
            sha1: None,
            favorite: false,
        }
    }

    #[test]
    fn etags_change_with_content_and_identity_is_stable() {
        let m = meta(false);
        let mut m2 = m.clone();
        m2.mtime_nsec = 3;
        assert_ne!(of(&m), of(&m2));
        m2.size = 11;
        assert_ne!(of(&m), of(&m2));
        let mut d = meta(true);
        let fallback = of(&d);
        d.dir_etag = Some([7; 16]);
        assert_eq!(of(&d), "07".repeat(16));
        assert_ne!(of(&d), fallback);
        // fileid: follows the identity, not the inode; fits in 53 bits.
        let mut a = meta(false);
        a.id = Some(FileId([0xff; 16]));
        let mut b = a.clone();
        b.ino = 99;
        assert_eq!(fileid(&a), fileid(&b));
        assert!(fileid(&a) <= MASK53);
        assert_ne!(fileid(&meta(false)), fileid(&a));
    }

    fn with_identity() -> Meta {
        let mut m = meta(false);
        m.id = Some(FileId([0xab; 16]));
        m.sha1 = Some("a".repeat(40));
        m
    }

    /// ETag of a file with an identity: it depends on no physical location (a restore or a migration keeps it),
    /// and changes as soon as the identity, time, size or recorded content change.
    #[test]
    fn file_etag_survives_restore_and_follows_content() {
        let m = with_identity();
        let mut restored = m.clone();
        restored.ino = 123_456;
        restored.dev = 789;
        assert_eq!(of(&m), of(&restored), "new inode, new dataset: same ETag");
        type Change = (&'static str, fn(&mut Meta));
        let changes: [Change; 6] = [
            ("identity", |m| m.id = Some(FileId([0xac; 16]))),
            ("mtime", |m| m.mtime += 1),
            ("mtime_ns", |m| m.mtime_nsec += 1),
            ("taille", |m| m.size += 1),
            ("contenu (SHA-1)", |m| m.sha1 = Some("b".repeat(40))),
            ("SHA-1 inconnue", |m| m.sha1 = None),
        ];
        for (what, change) in changes {
            let mut c = m.clone();
            change(&mut c);
            assert_ne!(of(&m), of(&c), "{what} change, l'ETag doit changer");
        }
        // Without identity: fallback to the inode (file arrived outside the application, before `rescan`).
        let mut bare = m.clone();
        bare.id = None;
        assert_ne!(of(&bare), of(&m));
        let mut moved = bare.clone();
        moved.ino += 1;
        assert_ne!(of(&bare), of(&moved));
    }

    /// Reference values, computed independently (Python, truncated SHA-256): any change to the formula, even
    /// unintended, changes every ETag and makes every client re-download everything. It must be intended, announced
    /// and noted here.
    #[test]
    fn etag_reference_values() {
        assert_eq!(of(&meta(false)), "898d39f031567204625601ba4531d8a1"); // without identity: pre-0.2.0 formula
        assert_eq!(of(&with_identity()), "2daabaa8868f02d9663a8fa873017560"); // with identity: since 0.2.0
    }
}
