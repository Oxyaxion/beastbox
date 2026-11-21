//! Model-based test of WebDAV (proptest): random sequences of MKCOL, PUT, DELETE, MOVE and COPY are applied to the
//! server and to an in-memory model. After each step: same answer (success or refusal), same tree, same contents,
//! identities that follow a move and a rewrite but never a copy, and a folder ETag renewed whenever its subtree
//! changed. A failure prints the shortest sequence that breaks a rule.

use crate::http::tests::{A, Env, basic, call, env, send, token};
use axum::http::StatusCode;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use std::collections::{BTreeMap, BTreeSet};

/// Few names, two levels: sequences keep colliding (overwrites, moves into oneself, missing parents).
const NAMES: [&str; 3] = ["a", "b", "é c"];
const HOST: &str = "http://files.alpha.example";

#[derive(Clone, Debug)]
enum Op {
    Mkcol(String),
    Put(String, u8),
    Delete(String),
    /// Source, destination, `Overwrite: T`.
    Move(String, String, bool),
    Copy(String, String, bool),
}

fn path() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(NAMES.to_vec()), 1..=2).prop_map(|v| v.join("/"))
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        path().prop_map(Op::Mkcol),
        (path(), any::<u8>()).prop_map(|(p, c)| Op::Put(p, c)),
        path().prop_map(Op::Delete),
        (path(), path(), any::<bool>()).prop_map(|(s, d, o)| Op::Move(s, d, o)),
        (path(), path(), any::<bool>()).prop_map(|(s, d, o)| Op::Copy(s, d, o)),
    ]
}

/// Letters (the test reads files back as text); empty files included.
fn content(c: u8) -> Vec<u8> {
    vec![b'a' + c % 26; usize::from(c % 5)]
}

#[derive(Clone, Debug, PartialEq)]
enum Node {
    Dir,
    File(Vec<u8>),
}

/// Expected state: path → node, and the identity seen for a path (recorded the first time it is listed).
#[derive(Default)]
struct Model {
    nodes: BTreeMap<String, Node>,
    ids: BTreeMap<String, String>,
}

fn parent(p: &str) -> &str {
    p.rsplit_once('/').map_or("", |(d, _)| d)
}

/// `p` is `root` or inside it.
fn under(p: &str, root: &str) -> bool {
    p == root || p.strip_prefix(root).is_some_and(|r| r.starts_with('/'))
}

impl Model {
    fn is_dir(&self, p: &str) -> bool {
        p.is_empty() || self.nodes.get(p) == Some(&Node::Dir)
    }

    fn remove(&mut self, p: &str) {
        self.nodes.retain(|k, _| !under(k, p));
        self.ids.retain(|k, _| !under(k, p));
    }

    /// Applies `op` if it must succeed, and says whether it must.
    fn apply(&mut self, op: &Op) -> bool {
        match op {
            Op::Mkcol(p) => {
                if !self.is_dir(parent(p)) || self.nodes.contains_key(p) {
                    return false;
                }
                self.nodes.insert(p.clone(), Node::Dir);
            }
            // A rewrite keeps the file's identity.
            Op::Put(p, c) => {
                if !self.is_dir(parent(p)) || self.is_dir(p) {
                    return false;
                }
                self.nodes.insert(p.clone(), Node::File(content(*c)));
            }
            Op::Delete(p) => {
                if !self.nodes.contains_key(p) {
                    return false;
                }
                self.remove(p);
            }
            Op::Move(s, d, o) | Op::Copy(s, d, o) => {
                if !self.nodes.contains_key(s) || !self.is_dir(parent(d)) || under(d, s) || under(s, d) {
                    return false;
                }
                if self.nodes.contains_key(d) {
                    if !o {
                        return false;
                    }
                    self.remove(d);
                }
                let rebase = |k: &String| format!("{d}{}", k.get(s.len()..).unwrap_or_default());
                let nodes: Vec<_> = self
                    .nodes
                    .iter()
                    .filter(|(k, _)| under(k, s))
                    .map(|(k, v)| (rebase(k), v.clone()))
                    .collect();
                // A move keeps identities; a copy gets new ones.
                let ids: Vec<_> = match op {
                    Op::Move(..) => self
                        .ids
                        .iter()
                        .filter(|(k, _)| under(k, s))
                        .map(|(k, v)| (rebase(k), v.clone()))
                        .collect(),
                    _ => Vec::new(),
                };
                if matches!(op, Op::Move(..)) {
                    self.remove(s);
                }
                self.nodes.extend(nodes);
                self.ids.extend(ids);
            }
        }
        true
    }
}

struct Server<'a> {
    e: &'a Env,
    auth: String,
    /// `/remote.php/dav/files/alice/<case folder>`.
    base: String,
}

fn url(base: &str, p: &str) -> String {
    let enc: Vec<String> = p
        .split('/')
        .map(|s| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string())
        .collect();
    format!("{base}/{}", enc.join("/"))
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    s.split(open).nth(1)?.split(close).next()
}

impl Server<'_> {
    async fn run(&self, op: &Op) -> StatusCode {
        let auth = self.auth.as_str();
        let a = [A, ("authorization", auth)];
        let app = &self.e.app;
        match op {
            Op::Mkcol(p) => send(app, "MKCOL", &url(&self.base, p), &a, b"").await.0,
            Op::Put(p, c) => send(app, "PUT", &url(&self.base, p), &a, &content(*c)).await.0,
            Op::Delete(p) => send(app, "DELETE", &url(&self.base, p), &a, b"").await.0,
            Op::Move(s, d, o) | Op::Copy(s, d, o) => {
                let dest = format!("{HOST}{}", url(&self.base, d));
                let h = [
                    A,
                    ("authorization", auth),
                    ("destination", dest.as_str()),
                    ("overwrite", if *o { "T" } else { "F" }),
                ];
                let m = if matches!(op, Op::Move(..)) { "MOVE" } else { "COPY" };
                send(app, m, &url(&self.base, s), &h, b"").await.0
            }
        }
    }

    /// The case folder's ETag, and its whole tree: path → (node, identity).
    async fn tree(&self) -> (String, BTreeMap<String, (Node, String)>) {
        let props = r#"<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><d:getetag/><d:resourcetype/><oc:fileid/></d:prop></d:propfind>"#;
        let h = [A, ("authorization", self.auth.as_str()), ("depth", "1")];
        let g = [A, ("authorization", self.auth.as_str())];
        let (mut etag, mut out, mut todo) = (String::new(), BTreeMap::new(), vec![String::new()]);
        while let Some(dir) = todo.pop() {
            let at = if dir.is_empty() {
                self.base.clone()
            } else {
                url(&self.base, &dir)
            };
            let (s, _, body) = call(&self.e.app, "PROPFIND", &at, &h, props).await;
            assert_eq!(s, StatusCode::MULTI_STATUS, "{at}");
            for r in body.split("<d:response>").skip(1) {
                let href = between(r, "<d:href>", "</d:href>").unwrap_or_default();
                let rel = href.strip_prefix(&self.base).unwrap_or_default().trim_matches('/');
                let rel = percent_decode_str(rel).decode_utf8().unwrap().into_owned();
                if rel == dir {
                    if dir.is_empty() {
                        etag = between(r, "<d:getetag>", "</d:getetag>").unwrap_or_default().to_owned();
                    }
                    continue;
                }
                let id = between(r, "<oc:fileid>", "</oc:fileid>").unwrap_or_default().to_owned();
                let node = if r.contains("<d:collection/>") {
                    todo.push(rel.clone());
                    Node::Dir
                } else {
                    let (s, _, body) = call(&self.e.app, "GET", &url(&self.base, &rel), &g, "").await;
                    assert_eq!(s, StatusCode::OK);
                    Node::File(body.into_bytes())
                };
                out.insert(rel, (node, id));
            }
        }
        (etag, out)
    }
}

async fn check(srv: &Server<'_>, ops: &[Op]) -> Result<(), TestCaseError> {
    let mut m = Model::default();
    let (mut etag, _) = srv.tree().await;
    for (i, op) in ops.iter().enumerate() {
        let s = srv.run(op).await;
        prop_assert!(!s.is_server_error(), "step {i} {op:?}: {s}");
        let must = m.apply(op);
        prop_assert_eq!(s.is_success(), must, "step {} {:?}: answered {}", i, op, s);
        let (now, tree) = srv.tree().await;
        let got: BTreeMap<_, _> = tree.iter().map(|(k, (n, _))| (k.clone(), n.clone())).collect();
        prop_assert_eq!(&got, &m.nodes, "step {} {:?}: tree", i, op);
        // ETag of the case folder: renewed by every change below it. A refusal may renew it too (on purpose: a
        // failed overwrite may already have trashed the destination; a needless resync beats a missed change).
        prop_assert!(!must || now != etag, "step {} {:?}: folder ETag not renewed", i, op);
        etag = now;
        // Identities: stable for what stayed, followed by a move, all distinct (a copy never reuses one).
        let mut seen = BTreeSet::new();
        for (p, (_, id)) in &tree {
            prop_assert!(
                !id.is_empty() && seen.insert(id.clone()),
                "step {} {:?}: identity of {}",
                i,
                op,
                p
            );
            match m.ids.get(p) {
                Some(old) => prop_assert_eq!(old, id, "step {} {:?}: identity of {} changed", i, op, p),
                None => {
                    m.ids.insert(p.clone(), id.clone());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn webdav_follows_the_model() {
    let e = env();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let auth = basic("alice", &token(&e, "alpha"));
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48);
    let mut runner = TestRunner::new(Config::with_cases(cases));
    let n = std::sync::atomic::AtomicU32::new(0);
    let r = runner.run(&prop::collection::vec(op(), 1..16), |ops| {
        // Each case (and each shrinking attempt) in a fresh folder of the same account.
        let k = n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base = format!("/remote.php/dav/files/alice/case-{k}");
        rt.block_on(async {
            let a = [A, ("authorization", auth.as_str())];
            assert_eq!(send(&e.app, "MKCOL", &base, &a, b"").await.0, StatusCode::CREATED);
            check(
                &Server {
                    e: &e,
                    auth: auth.clone(),
                    base,
                },
                &ops,
            )
            .await
        })
    });
    if let Err(err) = r {
        panic!("{err}");
    }
}
