//! Beastbox: a file server compatible with Nextcloud clients, for FreeBSD.
//! See `docs/dev/beastbox-plan.md`. This crate is split into a library (testable) and a thin binary (`main.rs`).

pub mod admin;
pub mod auth;
pub mod config;
pub mod dav;
pub mod db;
pub mod etag;
pub mod fs;
pub mod http;
pub mod i18n;
pub mod index;
pub mod nc;
pub mod tenant;
pub mod web;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration : {0}")]
    Config(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("chemin invalide")]
    InvalidPath,
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// CI rule (§4.1): no global state outside an allow list.
#[cfg(test)]
mod global_state_audit {
    #[test]
    fn no_global_state() {
        let forbidden = ["static ", "lazy_static", "OnceCell", "OnceLock", "thread_local"];
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let text = std::fs::read_to_string(&p).unwrap();
                for (n, line) in text.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or("");
                    // `&'static str` and this test's strings are not state.
                    if code.contains("'static") || code.contains("let forbidden") {
                        continue;
                    }
                    for f in forbidden {
                        assert!(
                            !code.contains(f),
                            "global state forbidden: {}:{}: {line}",
                            p.display(),
                            n + 1
                        );
                    }
                }
            }
        }
    }
}
