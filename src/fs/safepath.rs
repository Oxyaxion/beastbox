//! `SafePath`: the only path type accepted by `fs/` (§9). Built by validation, never by concatenation.

use unicode_normalization::UnicodeNormalization;

const MAX_PATH: usize = 4096;
const MAX_NAME: usize = 255;

/// Validated relative path, in NFC: non-empty components, no `.` or `..`, no NUL, no control character, no `\`,
/// first component different from the reserved names (`.beastbox-tmp`, `.trash`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafePath(String);

impl SafePath {
    pub fn new(raw: &str) -> crate::Result<Self> {
        Self::exact(raw.nfc().collect())
    }

    /// Same checks, without the NFC conversion: names exactly as on a disk Beastbox did not write (a snapshot of
    /// files put there over SSH, a restored backup), to **read** them. Never for a path written by the server.
    pub(super) fn exact(s: String) -> crate::Result<Self> {
        if s.is_empty() || s.len() > MAX_PATH {
            return Err(crate::Error::InvalidPath);
        }
        for (i, c) in s.split('/').enumerate() {
            let bad = c.is_empty()
                || c == "."
                || c == ".."
                || c.len() > MAX_NAME
                || c.chars().any(|ch| ch.is_control() || ch == '\\')
                || (i == 0 && super::RESERVED.contains(&c));
            if bad {
                return Err(crate::Error::InvalidPath);
            }
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// (optional parent folder, last component).
    pub fn split_parent(&self) -> (Option<SafePath>, &str) {
        match self.0.rsplit_once('/') {
            Some((p, n)) => (Some(Self(p.to_owned())), n),
            None => (None, &self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SafePath;

    #[test]
    fn rejects_hostile_paths() {
        for p in [
            "",
            "/",
            "/etc/passwd",
            "a/../b",
            "..",
            ".",
            "a//b",
            "a/",
            "a\0b",
            "a\\..\\b",
            ".trash",
            ".trash/x",
            ".beastbox-tmp/x",
            "a\nb",
            "%2e%2e/x/..",
        ] {
            assert!(SafePath::new(p).is_err(), "{p:?} accepted");
        }
        assert!(SafePath::new(&"a".repeat(256)).is_err());
        assert!(SafePath::new(&"a/".repeat(2100)).is_err());
    }

    #[test]
    fn accepts_and_normalizes() {
        // No URL decoding here: "%2e%2e" is a literal name (decoding happens once, upstream).
        assert_eq!(SafePath::new("%2e%2e").unwrap().as_str(), "%2e%2e");
        assert_eq!(SafePath::new("sub/.trash").unwrap().as_str(), "sub/.trash");
        // NFD -> NFC
        assert_eq!(SafePath::new("e\u{301}t\u{e9}").unwrap().as_str(), "\u{e9}t\u{e9}");
        let p = SafePath::new("a/b/c.txt").unwrap();
        let (parent, name) = p.split_parent();
        assert_eq!((parent.unwrap().as_str(), name), ("a/b", "c.txt"));
    }
}
