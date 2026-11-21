//! Model-based test of links created by the clients (proptest): random sequences of creations, changes and revocations
//! through the OCS API, applied to the server and to a model. After each step: the same answer, the same list of
//! links (access, label, note, hidden download, password), and what a guest can really do with each link (open it,
//! drop into it, download an archive). A failure prints the shortest sequence that breaks a rule.

use crate::http::tests::{A, Env, basic, call, env, send, status, token};
use axum::http::StatusCode;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};

const API: &str = "/ocs/v2.php/apps/files_sharing/api/v1/shares";
const JSON: (&str, &str) = ("accept", "application/json");

#[derive(Clone, Copy, Debug, PartialEq)]
enum Access {
    Read,
    Drop,
    Upload,
}

impl Access {
    fn perms(self) -> u32 {
        match self {
            Access::Read => 1,
            Access::Drop => 4,
            Access::Upload => 15,
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    /// On the folder (`true`) or on the file inside it; access, password, label, hidden download.
    Create(bool, Access, Option<&'static str>, &'static str, bool),
    /// Link number (modulo the live ones); new access, password, label, hidden download (`None` = unchanged).
    Change(
        usize,
        Option<Access>,
        Option<&'static str>,
        Option<&'static str>,
        Option<bool>,
    ),
    Revoke(usize),
}

fn access() -> impl Strategy<Value = Access> {
    prop_oneof![Just(Access::Read), Just(Access::Drop), Just(Access::Upload)]
}

/// Empty (no password or removed), too short, valid.
fn password() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["", "court", "assez-long-1"])
}

/// No label, a plain one, one with a control character (refused).
fn label() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["", "Pour X", "a%0Ab"])
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (
            any::<bool>(),
            access(),
            prop::option::of(password()),
            label(),
            any::<bool>()
        )
            .prop_map(|(d, a, p, l, h)| Op::Create(d, a, p, l, h)),
        (
            0..4usize,
            prop::option::of(access()),
            prop::option::of(password()),
            prop::option::of(label()),
            prop::option::of(any::<bool>())
        )
            .prop_map(|(i, a, p, l, h)| Op::Change(i, a, p, l, h)),
        (0..4usize).prop_map(Op::Revoke),
    ]
}

#[derive(Clone, Debug)]
struct Link {
    id: String,
    token: String,
    on_dir: bool,
    access: Access,
    password: bool,
    label: String,
    hidden: bool,
}

/// `%0A` → `\n`: what the server receives.
fn decoded(l: &str) -> String {
    l.replace("%0A", "\n")
}

/// Same rules as the server: a password of 8 characters at least, no control character in a label, drop only on a
/// folder. Upload asked on a file gives read only (never refused: the desktop client would stay stuck).
fn valid(on_dir: bool, a: Access, pw: Option<&str>, label: &str) -> bool {
    (on_dir || a != Access::Drop) && pw.is_none_or(|p| p.is_empty() || p.len() >= 8) && !label.contains("%0A")
}

/// What the server grants: upload on a file is read only.
fn granted(on_dir: bool, a: Access) -> Access {
    if !on_dir && a == Access::Upload {
        Access::Read
    } else {
        a
    }
}

fn between<'a>(s: &'a str, k: &str) -> Option<&'a str> {
    let rest = s.split(&format!("\"{k}\":")).nth(1)?;
    rest.split([',', '}']).next().map(|v| v.trim_matches('"'))
}

async fn check(e: &Env, auth: &str, dir: &str, ops: &[Op]) -> Result<(), TestCaseError> {
    let app = &e.app;
    let form = [
        A,
        ("authorization", auth),
        ("content-type", "application/x-www-form-urlencoded"),
        JSON,
    ];
    let mut links: Vec<Link> = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        let (s, _, body) = match op {
            Op::Create(on_dir, a, pw, l, h) => {
                let path = if *on_dir {
                    format!("/{dir}")
                } else {
                    format!("/{dir}/f.txt")
                };
                let mut b = format!(
                    "path={path}&shareType=3&permissions={}&label={l}&hideDownload={h}",
                    a.perms()
                );
                if let Some(p) = pw {
                    b.push_str(&format!("&password={p}"));
                }
                let r = call(app, "POST", API, &form, &b).await;
                let must = valid(*on_dir, *a, *pw, l);
                prop_assert_eq!(r.0.is_success(), must, "step {} {:?}: {}", i, op, r.2);
                if must {
                    links.push(Link {
                        id: between(&r.2, "id").unwrap_or_default().to_owned(),
                        token: between(&r.2, "token").unwrap_or_default().to_owned(),
                        on_dir: *on_dir,
                        access: granted(*on_dir, *a),
                        password: pw.is_some_and(|p| !p.is_empty()),
                        label: decoded(l),
                        // A drop link shows no file: the server drops the flag.
                        hidden: *h && *a != Access::Drop,
                    });
                }
                r
            }
            Op::Change(k, a, pw, l, h) => {
                if links.is_empty() {
                    continue;
                }
                let n = k % links.len();
                let mut b = Vec::new();
                if let Some(a) = a {
                    b.push(format!("permissions={}", a.perms()));
                }
                if let Some(p) = pw {
                    b.push(format!("password={p}"));
                }
                if let Some(l) = l {
                    b.push(format!("label={l}"));
                }
                if let Some(h) = h {
                    b.push(format!("hideDownload={h}"));
                }
                let r = call(app, "PUT", &format!("{API}/{}", links[n].id), &form, &b.join("&")).await;
                let x = &mut links[n];
                let must = valid(x.on_dir, a.unwrap_or(x.access), *pw, l.unwrap_or(""));
                prop_assert_eq!(r.0.is_success(), must, "step {} {:?}: {}", i, op, r.2);
                if must {
                    x.access = granted(x.on_dir, a.unwrap_or(x.access));
                    x.password = pw.map_or(x.password, |p| !p.is_empty());
                    x.label = l.map_or(x.label.clone(), decoded);
                    x.hidden = x.access != Access::Drop && h.unwrap_or(x.hidden);
                }
                r
            }
            Op::Revoke(k) => {
                if links.is_empty() {
                    continue;
                }
                let x = links.remove(k % links.len());
                let r = call(
                    app,
                    "DELETE",
                    &format!("{API}/{}", x.id),
                    &[A, ("authorization", auth), JSON],
                    "",
                )
                .await;
                prop_assert_eq!(r.0, StatusCode::OK, "step {} {:?}", i, op);
                prop_assert_eq!(
                    status(app, "GET", &format!("/s/{}", x.token), &[A]).await,
                    StatusCode::NOT_FOUND
                );
                r
            }
        };
        prop_assert!(!s.is_server_error(), "step {} {:?}: {} {}", i, op, s, body);

        // The clients' list of the folder and its file: exactly the live links, as the model has them.
        let mut listed = 0;
        for q in [format!("?path=/{dir}"), format!("?path=/{dir}/f.txt")] {
            let (_, _, b) = call(
                app,
                "GET",
                &format!("{API}{q}"),
                &[A, ("authorization", auth), JSON],
                "",
            )
            .await;
            listed += b.matches("\"share_type\":3").count();
        }
        prop_assert_eq!(listed, links.len(), "step {} {:?}: listed links", i, op);
        for x in &links {
            let (_, _, b) = call(
                app,
                "GET",
                &format!("{API}/{}", x.id),
                &[A, ("authorization", auth), JSON],
                "",
            )
            .await;
            let perms = x.access.perms().to_string();
            let hide = if x.hidden { "1" } else { "0" };
            let with = if x.password { "***redacted***" } else { "null" };
            prop_assert_eq!(
                between(&b, "permissions"),
                Some(perms.as_str()),
                "step {} {:?}: {}",
                i,
                op,
                b
            );
            prop_assert_eq!(between(&b, "hide_download"), Some(hide), "step {} {:?}: {}", i, op, b);
            prop_assert_eq!(between(&b, "share_with"), Some(with), "step {} {:?}: {}", i, op, b);
            let label = between(&b, "label").unwrap_or_default().replace("\\u000a", "\n");
            prop_assert_eq!(&label, &x.label, "step {} {:?}: label", i, op);

            // What the guest can do: open the link; drop only on drop and upload links; an archive only on a
            // readable folder whose download is not hidden. A password closes everything but the page.
            let open = !x.password;
            let drop_url = format!("/s/{}/drop/g{i}.txt", x.token);
            let dropped = send(app, "PUT", &drop_url, &[A, ("content-length", "1")], b"g").await.0;
            let may_drop = open && x.on_dir && x.access != Access::Read;
            prop_assert_eq!(
                dropped == StatusCode::CREATED,
                may_drop,
                "step {} {:?}: drop {}",
                i,
                op,
                dropped
            );
            let zip = status(app, "GET", &format!("/s/{}/zip/", x.token), &[A]).await;
            let may_zip = open && x.on_dir && x.access != Access::Drop && !x.hidden;
            prop_assert_eq!(zip == StatusCode::OK, may_zip, "step {} {:?}: zip {}", i, op, zip);
        }
    }
    Ok(())
}

#[test]
fn client_links_follow_the_model() {
    let e = env();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let auth = basic("alice", &token(&e, "alpha"));
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    let mut runner = TestRunner::new(Config::with_cases(cases));
    let n = std::sync::atomic::AtomicU32::new(0);
    let r = runner.run(&prop::collection::vec(op(), 1..10), |ops| {
        // Each case on a fresh folder holding one file.
        let dir = format!("case-{}", n.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        rt.block_on(async {
            let a = [A, ("authorization", auth.as_str())];
            let f = format!("/remote.php/dav/files/alice/{dir}");
            assert_eq!(send(&e.app, "MKCOL", &f, &a, b"").await.0, StatusCode::CREATED);
            assert_eq!(
                send(&e.app, "PUT", &format!("{f}/f.txt"), &a, b"x").await.0,
                StatusCode::CREATED
            );
            check(&e, &auth, &dir, &ops).await
        })
    });
    if let Err(err) = r {
        panic!("{err}");
    }
}
