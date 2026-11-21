//! Tenant isolation as a property (plan §4.1, §10): random sequences of what alice of tenant `alpha` can send — WebDAV
//! writes and reads, links, favorites, including hostile ones (her `alpha` credentials sent to `beta`'s host, a
//! `Destination` on `beta`, traversal paths) — change **no byte, xattr or database row** of tenant `beta`. Requests sent
//! to `beta` with `alpha`'s credentials are never a success. A failure prints the shortest sequence that breaks it.

use crate::http::tests::{A, Env, basic, call, env, send, token};
use axum::http::StatusCode;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use std::collections::BTreeMap;
use std::path::Path;

const B_HOST: (&str, &str) = ("host", "files.beta.example");
const DAV: &str = "/remote.php/dav/files/alice/";

/// Plain names, and what an attacker tries: traversal, encoded slashes and dots, the other tenant's folder name.
const PATHS: [&str; 9] = [
    "a",
    "b",
    "a/b",
    "Secret",
    "..",
    "../x",
    "%2e%2e/x",
    "a/%2e%2e/%2e%2e/x",
    "x%2Fy",
];
const METHODS: [&str; 8] = ["MKCOL", "PUT", "DELETE", "MOVE", "COPY", "PROPPATCH", "GET", "PROPFIND"];

#[derive(Clone, Debug)]
enum Op {
    /// Method, path, `Destination` (on `beta`'s host if true), request sent to `beta`'s host.
    Dav(&'static str, &'static str, Option<(bool, &'static str)>, bool),
    /// A public link on this path, through the clients' API, to `alpha` or `beta`.
    Link(&'static str, bool),
}

fn op() -> impl Strategy<Value = Op> {
    let path = prop::sample::select(PATHS.to_vec());
    prop_oneof![
        (
            prop::sample::select(METHODS.to_vec()),
            path.clone(),
            prop::option::of((any::<bool>(), path.clone())),
            any::<bool>()
        )
            .prop_map(|(m, p, d, b)| Op::Dav(m, p, d, b)),
        (path, any::<bool>()).prop_map(|(p, b)| Op::Link(p, b)),
    ]
}

/// Everything of a tenant: each entry under its root (type, content, modification time, xattrs) and each database row.
fn fingerprint(e: &Env, root: &Path, tenant: &str) -> (BTreeMap<String, String>, Vec<String>) {
    let mut files = BTreeMap::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let content = if m.is_dir() {
                todo.push(p.clone());
                String::from("dir")
            } else {
                format!("{:?}", std::fs::read(&p).unwrap())
            };
            let mtime = m.modified().ok();
            files.insert(rel, format!("{content} {mtime:?} {:?}", crate::fs::xattrs_of(&p)));
        }
    }
    (files, e.state.db.tenant_rows(tenant))
}

#[test]
fn alpha_never_touches_beta() {
    let e = env();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let a_auth = basic("alice", &token(&e, "alpha"));
    // `beta` is not empty: files, a folder named like a target, a link, an app password.
    let b_auth = basic("alice", &token(&e, "beta"));
    rt.block_on(async {
        let b = [B_HOST, ("authorization", b_auth.as_str())];
        send(&e.app, "MKCOL", &format!("{DAV}Secret"), &b, b"").await;
        send(&e.app, "PUT", &format!("{DAV}Secret/x"), &b, b"beta's").await;
        send(&e.app, "PUT", &format!("{DAV}a"), &b, b"beta a").await;
        let form = [
            B_HOST,
            ("authorization", b_auth.as_str()),
            ("content-type", "application/x-www-form-urlencoded"),
        ];
        let (s, _, _) = call(
            &e.app,
            "POST",
            "/ocs/v2.php/apps/files_sharing/api/v1/shares",
            &form,
            "path=/Secret&shareType=3",
        )
        .await;
        assert_eq!(s, StatusCode::OK);
    });
    let b_root = e._b_root.path().to_path_buf();
    // The fingerprint sees a change of xattr (a favorite) and of database row (a link): otherwise the test proves nothing.
    let check = fingerprint(&e, &b_root, "beta");
    rt.block_on(async {
        let b = [B_HOST, ("authorization", b_auth.as_str())];
        let fav = r#"<d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:favorite>1</oc:favorite></d:prop></d:set></d:propertyupdate>"#;
        call(&e.app, "PROPPATCH", &format!("{DAV}a"), &b, fav).await;
    });
    let fav = fingerprint(&e, &b_root, "beta");
    assert!(
        fav.0 != check.0 && fav.1 == check.1,
        "a favorite is an xattr change only"
    );
    rt.block_on(async {
        let form = [
            B_HOST,
            ("authorization", b_auth.as_str()),
            ("content-type", "application/x-www-form-urlencoded"),
        ];
        call(
            &e.app,
            "POST",
            "/ocs/v2.php/apps/files_sharing/api/v1/shares",
            &form,
            "path=/a&shareType=3",
        )
        .await;
    });
    assert!(
        fingerprint(&e, &b_root, "beta").1 != fav.1,
        "a link is a database change"
    );
    let before = fingerprint(&e, &b_root, "beta");
    assert!(
        before.0.len() > 2 && before.1.len() > 3,
        "beta must hold something: {before:?}"
    );

    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    let mut runner = TestRunner::new(Config::with_cases(cases));
    let r = runner.run(&prop::collection::vec(op(), 1..12), |ops| {
        rt.block_on(async {
            for (i, op) in ops.iter().enumerate() {
                let (s, to_beta) = match op {
                    Op::Dav(m, p, dest, to_beta) => {
                        let host = if *to_beta { B_HOST } else { A };
                        let dest = dest.map(|(on_b, d)| {
                            let h = if on_b { B_HOST.1 } else { A.1 };
                            format!("http://{h}{DAV}{d}")
                        });
                        let mut h = vec![host, ("authorization", a_auth.as_str())];
                        if let Some(d) = &dest {
                            h.push(("destination", d.as_str()));
                        }
                        let body: &[u8] = match *m {
                            "PUT" => b"alpha writes",
                            "PROPPATCH" => br#"<d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:favorite>1</oc:favorite></d:prop></d:set></d:propertyupdate>"#,
                            _ => b"",
                        };
                        let Ok(uri) = format!("{DAV}{p}").parse::<axum::http::Uri>() else { continue };
                        (send(&e.app, m, &uri.to_string(), &h, body).await.0, *to_beta)
                    }
                    Op::Link(p, to_beta) => {
                        let host = if *to_beta { B_HOST } else { A };
                        let h = [host, ("authorization", a_auth.as_str()), ("content-type", "application/x-www-form-urlencoded")];
                        let body = format!("path=/{p}&shareType=3&permissions=4");
                        (call(&e.app, "POST", "/ocs/v2.php/apps/files_sharing/api/v1/shares", &h, &body).await.0, *to_beta)
                    }
                };
                // A Destination on another server is refused with 502 (RFC 4918 §9.9.4); no other server error.
                let cross = matches!(op, Op::Dav(_, _, Some((true, _)), _));
                prop_assert!(!s.is_server_error() || (cross && s == StatusCode::BAD_GATEWAY), "step {} {:?}: {}", i, op, s);
                prop_assert!(!(to_beta && s.is_success()), "step {} {:?}: alpha's credentials accepted by beta ({})", i, op, s);
            }
            let after = fingerprint(&e, &b_root, "beta");
            prop_assert!(after == before, "beta changed after {:?}:\nbefore {:?}\nafter  {:?}", ops, before, after);
            Ok(())
        })
    });
    if let Err(err) = r {
        panic!("{err}");
    }
}

/// What alice tries against bob, an account of the **same** tenant (same key, same database, sibling folder).
const BOB_PATHS: [&str; 10] = [
    "a",
    "Secret",
    "Secret/bob-only-name.txt",
    "..",
    "../bob/a",
    "%2e%2e/bob/a",
    "a/%2e%2e/%2e%2e/bob/a",
    "..%2fbob%2fa",
    "x%2Fy",
    "../bob",
];

#[derive(Clone, Debug)]
enum UserOp {
    /// Method, path, `Destination` (in bob's space if true), URL in bob's space (`/files/bob/…`) if true.
    Dav(&'static str, &'static str, Option<(bool, &'static str)>, bool),
    /// A public link on this path of alice's space, through the clients' API.
    Link(&'static str),
    /// One of bob's file identifiers: thumbnail (app password) or "open in the browser" (web session).
    ById(bool, usize),
    /// A web or OCS request aimed at bob (traversal, his link, his file names), by number.
    Hostile(usize),
}

fn user_op() -> impl Strategy<Value = UserOp> {
    let path = prop::sample::select(BOB_PATHS.to_vec());
    prop_oneof![
        (
            prop::sample::select(METHODS.to_vec()),
            path.clone(),
            prop::option::of((any::<bool>(), path.clone())),
            any::<bool>()
        )
            .prop_map(|(m, p, d, b)| UserOp::Dav(m, p, d, b)),
        path.prop_map(UserOp::Link),
        (any::<bool>(), 0usize..8).prop_map(|(w, i)| UserOp::ById(w, i)),
        (0usize..12).prop_map(UserOp::Hostile),
    ]
}

/// Marker found only in bob's file names and contents: a response that carries it leaks bob's space.
const MARK: [&str; 2] = ["BOB-MARKER", "bob-only"];

/// User isolation inside a tenant, as a property: random sequences of what alice can send — WebDAV on her space and
/// on `/files/bob/`, traversal paths, `Destination` into bob's space, links, bob's file identifiers (thumbnails, "open
/// in the browser"), bob's link through the web page and the clients' API, web pages with traversal — change **no
/// byte, xattr or database row of bob**, never succeed on bob's space, and never return bob's names or contents.
#[test]
fn alice_never_touches_bob() {
    let e = env();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let t = e.state.registry.by_name("alpha").unwrap();
    let bob_root = e.a_root.path().join("bob");
    std::fs::create_dir(&bob_root).unwrap();
    crate::fs::Root::open_dir(&bob_root).unwrap().ensure_layout().unwrap();
    let h = crate::auth::hash_password("pw-de-bob-123").unwrap();
    e.state.db.user_add(&t, "bob", &h, false).unwrap();
    e.state.db.user_set_password_hash(&t, "bob", &h, false).unwrap();
    let b_auth = basic(
        "bob",
        &crate::auth::new_app_password(&e.state.db, &t, "bob", "test").unwrap(),
    );
    let a_auth = basic("alice", &token(&e, "alpha"));
    const BOB: &str = "/remote.php/dav/files/bob/";
    // bob is not empty: a folder, files whose names and contents carry the marker, a favorite, a link, a trashed file.
    let ids: Vec<u64> = rt.block_on(async {
        let b = [A, ("authorization", b_auth.as_str())];
        send(&e.app, "MKCOL", &format!("{BOB}Secret"), &b, b"").await;
        send(&e.app, "PUT", &format!("{BOB}Secret/bob-only-name.txt"), &b, b"BOB-MARKER secret").await;
        send(&e.app, "PUT", &format!("{BOB}a"), &b, b"BOB-MARKER a").await;
        send(&e.app, "PUT", &format!("{BOB}old.txt"), &b, b"BOB-MARKER old").await;
        send(&e.app, "DELETE", &format!("{BOB}old.txt"), &b, b"").await;
        let fav = r#"<d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:favorite>1</oc:favorite></d:prop></d:set></d:propertyupdate>"#;
        call(&e.app, "PROPPATCH", &format!("{BOB}a"), &b, fav).await;
        let form = [A, ("authorization", b_auth.as_str()), ("content-type", "application/x-www-form-urlencoded")];
        let (s, _, _) = call(&e.app, "POST", "/ocs/v2.php/apps/files_sharing/api/v1/shares", &form, "path=/Secret&shareType=3").await;
        assert_eq!(s, StatusCode::OK);
        let pf = r#"<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>"#;
        let depth = [A, ("authorization", b_auth.as_str()), ("depth", "1")];
        let (_, _, body) = call(&e.app, "PROPFIND", BOB, &depth, pf).await;
        let (_, _, sub) = call(&e.app, "PROPFIND", &format!("{BOB}Secret"), &depth, pf).await;
        format!("{body}{sub}")
            .split("<oc:fileid>")
            .skip(1)
            .filter_map(|x| x.split('<').next()?.parse().ok())
            .collect()
    });
    assert!(ids.len() >= 3, "bob's file identifiers: {ids:?}");
    let share = e
        .state
        .db
        .share_list(&t, "bob")
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .share_id;
    let ocs = crate::nc::share::ocs_id(&share);
    // alice's web session.
    let (cookie, csrf) = rt.block_on(async {
        let (s, h, _) = call(&e.app, "POST", "/login", &[A], "user=alice&password=pw-alice").await;
        assert_eq!(s, StatusCode::SEE_OTHER);
        let c = h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
        let csrf = crate::auth::csrf_token(&t, c.split_once('=').unwrap().1);
        (c, csrf)
    });
    let print = || {
        (
            fingerprint(&e, &bob_root, "alpha").0,
            e.state.db.user_rows("alpha", "bob"),
        )
    };
    let before = print();
    assert!(
        before.0.values().filter(|v| v.contains("66, 79, 66")).count() >= 2, // "BOB" in the files' bytes
        "bob must hold marked files: {before:?}"
    );
    assert!(before.1.iter().any(|r| r.starts_with("share:")) && before.1.iter().any(|r| r.starts_with("app_token:")));
    // Hostile web and OCS requests: (method, path, body, with the web session).
    let hostile: Vec<(&str, String, String, bool)> = vec![
        ("GET", "/web/files/%2e%2e/bob/".into(), String::new(), true),
        ("GET", "/web/raw/%2e%2e/bob/a".into(), String::new(), true),
        ("GET", "/web/view/%2e%2e/bob/a".into(), String::new(), true),
        ("GET", "/web/zip/%2e%2e/bob/Secret".into(), String::new(), true),
        ("GET", "/web/search?q=only-name".into(), String::new(), true),
        (
            "POST",
            "/web/shares/revoke".into(),
            format!("csrf={csrf}&id={share}"),
            true,
        ),
        (
            "POST",
            "/web/shares".into(),
            format!("csrf={csrf}&path=../bob/a&perms=read"),
            true,
        ),
        (
            "POST",
            "/web/tags".into(),
            format!("csrf={csrf}&path=../bob/a&op=add&tag=x"),
            true,
        ),
        (
            "POST",
            "/web/favorite".into(),
            format!("csrf={csrf}&path=../bob/a"),
            true,
        ),
        (
            "GET",
            format!("/ocs/v2.php/apps/files_sharing/api/v1/shares/{ocs}"),
            String::new(),
            false,
        ),
        (
            "DELETE",
            format!("/ocs/v2.php/apps/files_sharing/api/v1/shares/{ocs}"),
            String::new(),
            false,
        ),
        (
            "PUT",
            format!("/ocs/v2.php/apps/files_sharing/api/v1/shares/{ocs}"),
            "permissions=1&password=x".into(),
            false,
        ),
    ];
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    let mut runner = TestRunner::new(Config::with_cases(cases));
    let r = runner.run(&prop::collection::vec(user_op(), 1..12), |ops| {
        rt.block_on(async {
            for (i, op) in ops.iter().enumerate() {
                let session = [A, ("cookie", cookie.as_str()), ("content-type", "application/x-www-form-urlencoded")];
                let app = [A, ("authorization", a_auth.as_str()), ("content-type", "application/x-www-form-urlencoded")];
                let (s, body, at_bob) = match op {
                    UserOp::Dav(m, p, dest, in_bob) => {
                        // bob's marked name only as a target in his space: alice may name her own files as she likes,
                        // and her own search would then rightly show it.
                        let marked = |p: &str| MARK.iter().any(|m| p.contains(m));
                        if (!in_bob && marked(p)) || dest.is_some_and(|(to_bob, d)| !to_bob && marked(d)) {
                            continue;
                        }
                        let base = if *in_bob { BOB } else { DAV };
                        let dest = dest.map(|(to_bob, d)| format!("http://{}{}{d}", A.1, if to_bob { BOB } else { DAV }));
                        let mut h = vec![A, ("authorization", a_auth.as_str())];
                        if let Some(d) = &dest {
                            h.push(("destination", d.as_str()));
                        }
                        let body = match *m {
                            "PUT" => "alice writes",
                            "PROPPATCH" => r#"<d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:favorite>1</oc:favorite></d:prop></d:set></d:propertyupdate>"#,
                            _ => "",
                        };
                        let Ok(uri) = format!("{base}{p}").parse::<axum::http::Uri>() else { continue };
                        let (s, _, b) = call(&e.app, m, &uri.to_string(), &h, body).await;
                        (s, b, *in_bob)
                    }
                    UserOp::Link(p) => {
                        let body = format!("path=/{p}&shareType=3&permissions=1");
                        let (s, _, b) = call(&e.app, "POST", "/ocs/v2.php/apps/files_sharing/api/v1/shares", &app, &body).await;
                        (s, b, false)
                    }
                    UserOp::ById(web, n) => {
                        let id = ids[n % ids.len()];
                        let (s, _, b) = if *web {
                            call(&e.app, "GET", &format!("/index.php/f/{id}"), &session, "").await
                        } else {
                            call(&e.app, "GET", &format!("/index.php/core/preview?fileId={id}&x=32&y=32"), &app, "").await
                        };
                        (s, b, true)
                    }
                    UserOp::Hostile(n) => {
                        let (m, p, body, web) = &hostile[n % hostile.len()];
                        let (s, _, b) = call(&e.app, m, p, if *web { &session } else { &app }, body).await;
                        (s, b, !p.starts_with("/web/search") && !p.starts_with("/web/shares"))
                    }
                };
                prop_assert!(!s.is_server_error(), "step {} {:?}: {}", i, op, s);
                prop_assert!(!(at_bob && s.is_success()), "step {} {:?}: alice reached bob's space ({})", i, op, s);
                prop_assert!(!MARK.iter().any(|m| body.contains(m)), "step {} {:?}: bob's data in the answer: {}", i, op, body);
            }
            let after = print();
            prop_assert!(after == before, "bob changed after {:?}:\nbefore {:?}\nafter  {:?}", ops, before, after);
            Ok(())
        })
    });
    if let Err(err) = r {
        panic!("{err}");
    }
}
