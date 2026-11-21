//! Downloading a folder as a streamed ZIP (§8.3). Minimal writer in "stored" mode (no compression),
//! data descriptors after each file (CRC computed on the fly): constant memory, nothing is parsed.
//! Limits (no ZIP64): at most 65,535 entries and a 4 GiB archive, checked before sending the first byte.

use crate::fs::{Root, SafePath};
use axum::body::Bytes;
use std::fs::File;
use std::io::{self, Read};

pub const MAX_ENTRIES: u64 = 65_535;
/// Headroom for headers: the whole archive must fit under 4 GiB (32-bit offsets).
pub const MAX_BYTES: u64 = u32::MAX as u64 - 64 * 1024 * 1024;
const STEP: usize = 256 * 1024;

/// Pre-walk of a selection (folders walked, files counted): (entries, bytes).
/// `FileTooLarge` error beyond the limits.
pub fn precheck_items(root: &Root, items: &[SafePath]) -> io::Result<(u64, u64)> {
    let (mut entries, mut bytes) = (0u64, 0u64);
    for it in items {
        let m = root.meta(Some(it))?;
        entries += 1;
        bytes += m.size + 200 + 2 * it.as_str().len() as u64;
        if m.is_dir {
            let (e, b) = precheck(root, Some(it))?;
            entries += e;
            bytes += b;
        }
        if entries > MAX_ENTRIES || bytes > MAX_BYTES {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
    }
    Ok((entries, bytes))
}

/// Pre-walk: (entries, content bytes). `FileTooLarge` error beyond the limits.
pub fn precheck(root: &Root, dir: Option<&SafePath>) -> io::Result<(u64, u64)> {
    let (mut entries, mut bytes) = (0u64, 0u64);
    let mut stack = vec![dir.cloned()];
    while let Some(d) = stack.pop() {
        for e in root.read_dir(d.as_ref())? {
            let (name, m) = e?;
            entries += 1;
            bytes += m.size + 200 + 2 * name.len() as u64;
            if entries > MAX_ENTRIES || bytes > MAX_BYTES {
                return Err(io::Error::from(io::ErrorKind::FileTooLarge));
            }
            if m.is_dir {
                stack.push(Some(join(d.as_ref(), &name)?));
            }
        }
    }
    Ok((entries, bytes))
}

fn join(dir: Option<&SafePath>, name: &str) -> io::Result<SafePath> {
    let s = match dir {
        Some(d) => format!("{}/{name}", d.as_str()),
        None => name.to_owned(),
    };
    SafePath::new(&s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// MS-DOS date and time (UTC; before 1980 → 1980-01-01).
fn dos_time(ts: i64) -> (u16, u16) {
    let s = super::render::date(ts.max(315_532_800)); // "YYYY-MM-DD HH:MM"
    let n = |a: usize, b: usize| s.get(a..b).and_then(|x| x.parse::<u16>().ok()).unwrap_or(0);
    let (y, mo, d, h, mi) = (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16));
    let sec = u16::try_from(ts.rem_euclid(60) / 2).unwrap_or(0);
    (
        (h << 11) | (mi << 5) | sec,
        ((y.saturating_sub(1980)) << 9) | (mo << 5) | d,
    )
}

struct Current {
    file: File,
    crc: crc32fast::Hasher,
    size: u64,
    name: String,
    time: (u16, u16),
    offset: u32,
}

/// ZIP stream state, advanced in short steps (`crate::dav::blocking_stream`).
pub struct Zip {
    root: Root,
    /// (path on disk, name in the archive, is a folder)
    stack: Vec<(Option<SafePath>, String, bool)>,
    current: Option<Current>,
    central: Vec<u8>,
    entries: u16,
    offset: u64,
    done: bool,
}

const FLAGS_FILE: u16 = 0x0808; // bit 3: data descriptor; bit 11: UTF-8 names
const FLAGS_DIR: u16 = 0x0800;

impl Zip {
    /// `top`: name of the root folder in the archive.
    pub fn new(root: Root, dir: Option<SafePath>, top: &str) -> Self {
        Self {
            root,
            stack: vec![(dir, format!("{top}/"), true)],
            current: None,
            central: Vec::new(),
            entries: 0,
            offset: 0,
            done: false,
        }
    }

    /// Archive of a selection: each item under `top/`.
    pub fn selection(root: Root, items: Vec<(SafePath, bool)>, top: &str) -> Self {
        let mut stack: Vec<(Option<SafePath>, String, bool)> = items
            .into_iter()
            .map(|(p, is_dir)| {
                let name = p.split_parent().1.to_owned();
                let n = if is_dir {
                    format!("{top}/{name}/")
                } else {
                    format!("{top}/{name}")
                };
                (Some(p), n, is_dir)
            })
            .collect();
        stack.sort_by(|a, b| b.1.cmp(&a.1));
        Self {
            root,
            stack,
            current: None,
            central: Vec::new(),
            entries: 0,
            offset: 0,
            done: false,
        }
    }

    fn header(&mut self, out: &mut Vec<u8>, name: &str, time: (u16, u16), dir: bool) -> io::Result<u32> {
        let offset = u32::try_from(self.offset).map_err(|_| io::Error::from(io::ErrorKind::FileTooLarge))?;
        let nlen = u16::try_from(name.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&(if dir { FLAGS_DIR } else { FLAGS_FILE }).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&time.0.to_le_bytes());
        out.extend_from_slice(&time.1.to_le_bytes());
        out.extend_from_slice(&[0u8; 12]); // CRC and sizes: in the descriptor (files) or zero (folders)
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        Ok(offset)
    }

    fn central_entry(&mut self, name: &str, time: (u16, u16), crc: u32, size: u32, offset: u32, dir: bool) {
        let c = &mut self.central;
        c.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        c.extend_from_slice(&(0x0300u16 | 20).to_le_bytes()); // made on Unix
        c.extend_from_slice(&20u16.to_le_bytes());
        c.extend_from_slice(&(if dir { FLAGS_DIR } else { FLAGS_FILE }).to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes());
        c.extend_from_slice(&time.0.to_le_bytes());
        c.extend_from_slice(&time.1.to_le_bytes());
        c.extend_from_slice(&crc.to_le_bytes());
        c.extend_from_slice(&size.to_le_bytes());
        c.extend_from_slice(&size.to_le_bytes());
        c.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_le_bytes());
        c.extend_from_slice(&[0u8; 8]); // extra, comment, disk, internal attributes
        let mode: u32 = if dir { 0o40755 } else { 0o100644 };
        c.extend_from_slice(&((mode << 16) | (u32::from(dir) * 0x10)).to_le_bytes());
        c.extend_from_slice(&offset.to_le_bytes());
        c.extend_from_slice(name.as_bytes());
        self.entries = self.entries.saturating_add(1);
    }

    /// Produces the next chunk of the archive, or `None` at the end.
    pub fn step(&mut self) -> io::Result<Option<Bytes>> {
        if self.done {
            return Ok(None);
        }
        let mut out = Vec::with_capacity(STEP + 512);
        while out.len() < STEP {
            if let Some(cur) = self.current.as_mut() {
                let mut buf = vec![0u8; STEP - out.len().min(STEP - 4096)];
                let n = cur.file.read(&mut buf)?;
                if n > 0 {
                    let data = buf.get(..n).unwrap_or_default();
                    cur.crc.update(data);
                    cur.size += n as u64;
                    out.extend_from_slice(data);
                    self.offset += n as u64;
                    continue;
                }
                let Some(cur) = self.current.take() else { break };
                let size = u32::try_from(cur.size).map_err(|_| io::Error::from(io::ErrorKind::FileTooLarge))?;
                let crc = cur.crc.finalize();
                out.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
                out.extend_from_slice(&crc.to_le_bytes());
                out.extend_from_slice(&size.to_le_bytes());
                out.extend_from_slice(&size.to_le_bytes());
                self.offset += 16;
                self.central_entry(&cur.name, cur.time, crc, size, cur.offset, false);
                continue;
            }
            let Some((path, name, is_dir)) = self.stack.pop() else {
                // End: central directory then end record.
                let cd_off = u32::try_from(self.offset).map_err(|_| io::Error::from(io::ErrorKind::FileTooLarge))?;
                let cd_len =
                    u32::try_from(self.central.len()).map_err(|_| io::Error::from(io::ErrorKind::FileTooLarge))?;
                out.append(&mut self.central);
                out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
                out.extend_from_slice(&[0u8; 4]);
                out.extend_from_slice(&self.entries.to_le_bytes());
                out.extend_from_slice(&self.entries.to_le_bytes());
                out.extend_from_slice(&cd_len.to_le_bytes());
                out.extend_from_slice(&cd_off.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes());
                self.done = true;
                break;
            };
            if u64::from(self.entries) >= MAX_ENTRIES {
                return Err(io::Error::from(io::ErrorKind::FileTooLarge));
            }
            let m = self.root.meta(path.as_ref())?;
            let time = dos_time(m.mtime);
            let before = out.len();
            if is_dir {
                let off = self.header(&mut out, &name, time, true)?;
                self.offset += (out.len() - before) as u64;
                self.central_entry(&name, time, 0, 0, off, true);
                let mut children: Vec<_> = self.root.read_dir(path.as_ref())?.collect::<io::Result<_>>()?;
                children.sort_by(|a, b| b.0.cmp(&a.0)); // stack: alphabetical order on output
                for (child, cm) in children {
                    let p = join(path.as_ref(), &child)?;
                    let n = if cm.is_dir {
                        format!("{name}{child}/")
                    } else {
                        format!("{name}{child}")
                    };
                    self.stack.push((Some(p), n, cm.is_dir));
                }
            } else if let Some(p) = &path {
                let (file, _) = self.root.open_file(p)?;
                let off = self.header(&mut out, &name, time, false)?;
                self.offset += (out.len() - before) as u64;
                self.current = Some(Current {
                    file,
                    crc: crc32fast::Hasher::new(),
                    size: 0,
                    name,
                    time,
                    offset: off,
                });
            }
        }
        Ok(Some(Bytes::from(out)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_roundtrip_with_unzip() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        std::fs::create_dir_all(src.join("sous dossier/vide")).unwrap();
        std::fs::write(src.join("a.txt"), b"bonjour").unwrap();
        std::fs::write(src.join("sous dossier/é.bin"), vec![7u8; 300_000]).unwrap();
        let root = Root::open_dir(&src).unwrap();
        assert_eq!(precheck(&root, None).unwrap().0, 4);
        let mut z = Zip::new(root, None, "Mes fichiers");
        let mut out = Vec::new();
        while let Some(b) = z.step().unwrap() {
            out.extend_from_slice(&b);
        }
        let zf = d.path().join("t.zip");
        std::fs::write(&zf, &out).unwrap();
        // Checked by an independent tool: unzip -t (integrity, CRC) then extraction.
        let t = std::process::Command::new("unzip")
            .arg("-tq")
            .arg(&zf)
            .output()
            .unwrap();
        assert!(t.status.success(), "{}", String::from_utf8_lossy(&t.stdout));
        let x = d.path().join("x");
        let st = std::process::Command::new("unzip")
            .arg("-q")
            .arg(&zf)
            .arg("-d")
            .arg(&x)
            .status()
            .unwrap();
        assert!(st.success());
        assert_eq!(std::fs::read(x.join("Mes fichiers/a.txt")).unwrap(), b"bonjour");
        assert_eq!(
            std::fs::read(x.join("Mes fichiers/sous dossier/é.bin")).unwrap(),
            vec![7u8; 300_000]
        );
        assert!(x.join("Mes fichiers/sous dossier/vide").is_dir());
    }
}
