//! The behaviours the main scenarios pass by: refusals and limits of the forms, notices, the life of a link whose target
//! changes, the corners of WebDAV. Each one was found unexecuted by the coverage report.

use super::tests::{login, make_share};
use crate::auth::tests::{code_at, enable_totp};
use crate::dav::io_status;
use crate::fs::{Root, SafePath};
use crate::http::tests::{A, Env, basic, call, env, env_with, send, status, token};
use crate::tenant::TenantCtx;
use axum::http::{HeaderMap, StatusCode};
use std::io;

const B: (&str, &str) = ("host", "x.beta.example");
const FR: (&str, &str) = ("accept-language", "fr");
const DAV: &str = "/remote.php/dav/files/alice";

fn alpha(e: &Env) -> TenantCtx {
    e.state.registry.by_name("alpha").unwrap()
}

fn root(e: &Env) -> Root {
    Root::open_dir(&e.a_root.path().join("alice")).unwrap()
}

/// A file written through the application: it has its identity.
fn file(e: &Env, name: &str, content: &[u8]) {
    let mut c = content;
    root(e).atomic_write(&SafePath::new(name).unwrap(), &mut c).unwrap();
}

fn location(h: &HeaderMap) -> &str {
    h.get("location").and_then(|v| v.to_str().ok()).unwrap_or("")
}

#[tokio::test]
async fn signed_in_login_page_and_client_links() {
    let e = env();
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let (s, h, _) = call(&e.app, "GET", "/login", &c, "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/files/"));
    let (s, h, _) = call(&e.app, "GET", "/login?next=/index.php/f/42", &c, "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/index.php/f/42"));
    assert_eq!(
        status(&e.app, "GET", "/index.php/f/abc", &c).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(&e.app, "GET", "/index.php/f/999999", &c).await,
        StatusCode::NOT_FOUND
    );
    let id = crate::etag::fileid(&root(&e).meta(None).unwrap());
    let (s, h, _) = call(&e.app, "GET", &format!("/index.php/f/{id}"), &c, "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/files/"));
}

/// An address that used up its attempts is stopped before any password or code is checked, on every form that takes
/// one; another address goes on.
#[tokio::test]
async fn blocked_address_is_refused_everywhere() {
    let e = env();
    let t = alpha(&e);
    file(&e, "note.txt", b"x");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let link = make_share(&e, &cookie, &csrf, "note.txt", "&perms=read&password=secret-du-lien").await;
    let ip = "192.0.2.77";
    for _ in 0..10 {
        t.failures().record_ip(ip.parse().unwrap());
    }
    let web = [A, ("cookie", cookie.as_str()), ("x-real-ip", ip)];
    let forms = [
        (
            "/web/account/password",
            format!("csrf={csrf}&current=pw-alice&new=un-nouveau-secret"),
        ),
        ("/web/account/2fa/confirm", format!("csrf={csrf}&code=000000")),
    ];
    for (p, body) in &forms {
        assert_eq!(
            call(&e.app, "POST", p, &web, body).await.0,
            StatusCode::TOO_MANY_REQUESTS,
            "{p}"
        );
    }
    enable_totp(&e.state.db, &t, "alice");
    let body = format!("csrf={csrf}&op=codes&password=pw-alice&code={}", code_at(0));
    assert_eq!(
        call(&e.app, "POST", "/web/account/2fa", &web, &body).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let guest = [A, ("x-real-ip", ip)];
    let (s, _, _) = call(&e.app, "POST", "/login", &guest, "user=alice&password=pw-alice").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let (s, _, _) = call(&e.app, "POST", &format!("/s/{link}"), &guest, "password=secret-du-lien").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let other = [A, ("x-real-ip", "192.0.2.78")];
    let (s, _, _) = call(&e.app, "POST", "/login", &other, "user=alice&password=faux").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bulk_notices_and_refusals() {
    let e = env();
    file(&e, "note.txt", b"x");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let f = [A, ("cookie", cookie.as_str()), FR];
    let page = async |h: &[(&str, &str)], q: &str| call(&e.app, "GET", &format!("/web/files/?{q}"), h, "").await.2;
    assert!(page(&c, "op=move&ok=1").await.contains("1 item moved."));
    let p = page(&c, "op=copy&ok=2&ko=1").await;
    assert!(p.contains("2 items copied. 1 item not processed"), "{p}");
    assert!(page(&f, "op=move&ok=1").await.contains("1 élément déplacé."));
    let p = page(&f, "op=duplicate&ok=1&ko=2").await;
    assert!(p.contains("1 élément copié. 2 éléments non traités"), "{p}");
    assert!(!page(&c, "op=other&ok=3").await.contains("3 items"));
    let bulk = async |rest: &str| call(&e.app, "POST", "/web/bulk", &c, &format!("csrf={csrf}&dir=&{rest}")).await;
    let (s, _, p) = bulk("op=nope&item=note.txt").await;
    assert!(s == StatusCode::BAD_REQUEST && p.contains("Unknown action"), "{p}");
    let (s, h, _) = bulk("op=delete&item=absent.txt").await;
    assert_eq!(
        (s, location(&h)),
        (StatusCode::SEE_OTHER, "/web/files/?op=delete&ok=0&ko=1")
    );
    let (s, _, _) = bulk("op=move&item=note.txt&dest=note.txt").await;
    assert_eq!(s, StatusCode::NOT_FOUND); // the destination is a file
    assert!(e.a_root.path().join("alice/note.txt").is_file());
}

#[tokio::test]
async fn a_file_is_not_a_folder() {
    let e = env();
    file(&e, "note.txt", b"x");
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    for p in ["/web/files/note.txt", "/web/zip/note.txt"] {
        assert_eq!(status(&e.app, "GET", p, &c).await, StatusCode::NOT_FOUND, "{p}");
    }
}

/// 20 tags per item (at the limit, above it); a tag already there may still be set again.
#[tokio::test]
async fn tag_limit() {
    let e = env();
    file(&e, "note.txt", b"x");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let add = async |tag: String| {
        let body = format!("csrf={csrf}&path=note.txt&op=add&tag={tag}");
        call(&e.app, "POST", "/web/tags", &c, &body).await
    };
    for i in 0..crate::fs::MAX_TAGS {
        assert_eq!(add(format!("t{i}")).await.0, StatusCode::SEE_OTHER, "{i}");
    }
    let (s, _, p) = add("encore".into()).await;
    assert!(s == StatusCode::BAD_REQUEST && p.contains("Too many tags"), "{p}");
    assert_eq!(add("t0".into()).await.0, StatusCode::SEE_OTHER);
    let (tags, _) = root(&e).labels(Some(&SafePath::new("note.txt").unwrap())).unwrap();
    assert_eq!(tags.len(), crate::fs::MAX_TAGS);
}

/// The link form: each limit at its value and just past it; a refusal creates nothing.
#[tokio::test]
async fn link_form_limits() {
    let e = env();
    let t = alpha(&e);
    file(&e, "note.txt", b"x");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let post = async |extra: String| {
        let body = format!("csrf={csrf}&path=note.txt&perms=read{extra}");
        call(&e.app, "POST", "/web/shares", &c, &body).await
    };
    for (extra, msg) in [
        ("&expires=pas-une-date".to_owned(), "Invalid or past expiry date"),
        ("&expires=2000-01-01".to_owned(), "expiry"),
        ("&max=0".to_owned(), "Invalid number of downloads"),
        ("&max=100001".to_owned(), "Invalid number of downloads"),
        ("&max=x".to_owned(), "Invalid number of downloads"),
        (format!("&label={}", "a".repeat(101)), "Label too long"),
        (format!("&note={}", "a".repeat(1001)), "Note too long"),
    ] {
        let (s, _, p) = post(extra.clone()).await;
        assert!(s == StatusCode::BAD_REQUEST && p.contains(msg), "{extra}: {s} {p}");
    }
    assert!(e.state.db.share_list(&t, "alice").unwrap().is_empty());
    for extra in [
        "&max=1".to_owned(),
        "&max=100000".to_owned(),
        format!("&label={}", "a".repeat(100)),
        format!("&note={}", "a".repeat(1000)),
    ] {
        assert_eq!(post(extra.clone()).await.0, StatusCode::SEE_OTHER, "{extra}");
    }
    assert_eq!(e.state.db.share_list(&t, "alice").unwrap().len(), 4);
}

#[tokio::test]
async fn trash_notices() {
    let e = env();
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let f = [A, ("cookie", cookie.as_str()), FR];
    let page = async |h: &[(&str, &str)], q: &str| call(&e.app, "GET", &format!("/web/trash?{q}"), h, "").await.2;
    let p = page(&c, "ok=restored&to=Docs/a.txt").await;
    assert!(
        p.contains("Restored: Docs/a.txt") && p.contains("/web/view/Docs/a.txt"),
        "{p}"
    );
    assert!(page(&f, "ok=restored&to=a.txt").await.contains("Restauré : a.txt"));
    assert!(page(&c, "ok=purged").await.contains("Permanently deleted."));
    assert!(page(&c, "ok=emptied").await.contains("Trash emptied."));
    assert!(page(&c, "ok=gone").await.contains("no longer in the trash"));
}

/// Account page: a password form without its fields; a device id unknown here, or another tenant's, revokes nothing; a
/// QR code waiting for its first use says until when, in French too.
#[tokio::test]
async fn account_refusals() {
    let e = env();
    let t = alpha(&e);
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let (b_cookie, b_csrf) = login(&e, B, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let (s, _, p) = call(&e.app, "POST", "/web/account/password", &c, &format!("csrf={csrf}")).await;
    assert!(s == StatusCode::BAD_REQUEST && p.contains("Missing fields"), "{p}");
    token(&e, "alpha");
    let id = e.state.db.token_list(&t, "alice").unwrap()[0].token_id.clone();
    let (s, _, p) = call(
        &e.app,
        "POST",
        "/web/account/tokens/revoke",
        &c,
        &format!("csrf={csrf}&id=absent"),
    )
    .await;
    assert!(
        s == StatusCode::NOT_FOUND && p.contains("App password not found"),
        "{p}"
    );
    let other = [B, ("cookie", b_cookie.as_str())];
    let (s, _, _) = call(
        &e.app,
        "POST",
        "/web/account/tokens/revoke",
        &other,
        &format!("csrf={b_csrf}&id={id}"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(e.state.db.token_list(&t, "alice").unwrap().len(), 1);
    assert_eq!(
        call(&e.app, "POST", "/web/account/qr", &c, &format!("csrf={csrf}"))
            .await
            .0,
        StatusCode::OK
    );
    let fr = [A, ("cookie", cookie.as_str()), FR];
    let p = call(&e.app, "GET", "/web/account", &fr, "").await.2;
    assert!(p.contains("jamais, expire à"), "{p}");
}

/// A link follows its target: in the trash it stops answering and stays suspended; gone, it ends; replaced outside the
/// application (no identity to compare), it stops answering but is never ended on that doubt.
#[tokio::test]
async fn link_and_the_fate_of_its_target() {
    let e = env();
    let t = alpha(&e);
    for n in ["trashed.txt", "gone.txt", "doubt.txt"] {
        file(&e, n, b"x");
    }
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let auth = basic("alice", &token(&e, "alpha"));
    let a = [A, ("authorization", auth.as_str())];
    let mut links = Vec::new();
    for n in ["trashed.txt", "gone.txt", "doubt.txt"] {
        links.push(format!("/s/{}", make_share(&e, &cookie, &csrf, n, "&perms=read").await));
    }
    send(&e.app, "DELETE", &format!("{DAV}/trashed.txt"), &a, b"").await;
    for _ in 0..2 {
        assert_eq!(status(&e.app, "GET", &links[0], &[A]).await, StatusCode::NOT_FOUND);
    }
    let d = e.a_root.path().join("alice");
    std::fs::remove_file(d.join("gone.txt")).unwrap();
    std::fs::write(d.join("new"), b"y").unwrap();
    std::fs::rename(d.join("new"), d.join("doubt.txt")).unwrap();
    assert_eq!(status(&e.app, "GET", &links[2], &[A]).await, StatusCode::NOT_FOUND);
    let page = call(&e.app, "GET", "/web/shares", &c, "").await.2;
    assert!(page.contains("doubt.txt") && !page.contains(">gone.txt<"), "{page}");
    let live: Vec<_> = e
        .state
        .db
        .share_list(&t, "alice")
        .unwrap()
        .into_iter()
        .map(|s| s.path_hint)
        .collect();
    assert_eq!(live, ["doubt.txt"]);
}

/// A public page: posting to a link without password just shows it; a hidden download that a browser cannot display is
/// not served.
#[tokio::test]
async fn public_link_corners() {
    let e = env();
    file(&e, "a.txt", b"x");
    file(&e, "data.bin", b"x");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let open = make_share(&e, &cookie, &csrf, "a.txt", "&perms=read").await;
    let (s, _, p) = call(&e.app, "POST", &format!("/s/{open}"), &[A], "password=x").await;
    assert!(s == StatusCode::OK && p.contains("a.txt"), "{p}");
    let hidden = make_share(&e, &cookie, &csrf, "data.bin", "&perms=read&hide=1").await;
    assert_eq!(
        status(&e.app, "GET", &format!("/s/{hidden}/dl"), &[A]).await,
        StatusCode::NOT_FOUND
    );
}

/// The clients' API on a link: a past expiry is refused and changes nothing, a note is kept.
#[tokio::test]
async fn client_link_changes() {
    let e = env();
    let t = alpha(&e);
    file(&e, "a.txt", b"x");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    make_share(&e, &cookie, &csrf, "a.txt", "&perms=read").await;
    let share = e.state.db.share_list(&t, "alice").unwrap().remove(0);
    let auth = basic("alice", &token(&e, "alpha"));
    let h = [
        A,
        ("authorization", auth.as_str()),
        ("content-type", "application/x-www-form-urlencoded"),
        ("accept", "application/json"),
    ];
    let url = format!(
        "/ocs/v2.php/apps/files_sharing/api/v1/shares/{}",
        crate::nc::share::ocs_id(&share.share_id)
    );
    let (s, _, b) = call(&e.app, "PUT", &url, &h, "expireDate=2000-01-01").await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    assert_eq!(e.state.db.share_list(&t, "alice").unwrap()[0].expires_at, None);
    let (s, _, b) = call(&e.app, "PUT", &url, &h, "note=bonjour").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(e.state.db.share_list(&t, "alice").unwrap()[0].opts.note, "bonjour");
}

/// A drop larger than the free space is refused before anything is written.
#[tokio::test]
async fn drop_beyond_free_space() {
    let e = env_with(crate::http::Settings {
        drop_max_file_bytes: u64::MAX / 4,
        drop_max_total_bytes: u64::MAX / 2,
        ..Default::default()
    });
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let auth = basic("alice", &token(&e, "alpha"));
    send(
        &e.app,
        "MKCOL",
        &format!("{DAV}/Depot"),
        &[A, ("authorization", auth.as_str())],
        b"",
    )
    .await;
    let link = make_share(&e, &cookie, &csrf, "Depot", "&perms=drop").await;
    let h = [A, ("content-length", "1152921504606846976")];
    let s = send(&e.app, "PUT", &format!("/s/{link}/drop/gros.bin"), &h, b"")
        .await
        .0;
    assert_eq!(s, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(
        std::fs::read_dir(e.a_root.path().join("alice/Depot")).unwrap().count(),
        0
    );
}

/// Link history and list in French: repeated downloads, drops, an ended target, the expiry date.
#[tokio::test]
async fn link_history_in_french() {
    let e = env();
    let t = alpha(&e);
    file(&e, "a.txt", b"x");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let auth = basic("alice", &token(&e, "alpha"));
    send(
        &e.app,
        "MKCOL",
        &format!("{DAV}/Depot"),
        &[A, ("authorization", auth.as_str())],
        b"",
    )
    .await;
    let link = make_share(&e, &cookie, &csrf, "a.txt", "&perms=read&expires=2099-01-01").await;
    let drop = make_share(&e, &cookie, &csrf, "Depot", "&perms=drop").await;
    for _ in 0..2 {
        assert_eq!(
            status(&e.app, "GET", &format!("/s/{link}/dl"), &[A]).await,
            StatusCode::OK
        );
    }
    for n in ["1.txt", "2.txt", "3.txt"] {
        assert_eq!(
            send(
                &e.app,
                "PUT",
                &format!("/s/{drop}/drop/{n}"),
                &[A, ("content-length", "1")],
                b"x"
            )
            .await
            .0,
            StatusCode::CREATED
        );
    }
    let fr = [A, ("cookie", cookie.as_str()), FR];
    let list = call(&e.app, "GET", "/web/shares", &fr, "").await.2;
    assert!(list.contains("expire le"), "{list}");
    let shares = e.state.db.share_list(&t, "alice").unwrap();
    let id = |p: &str| shares.iter().find(|s| s.path_hint == p).unwrap().share_id.clone();
    let page = call(&e.app, "GET", &format!("/web/shares?lien={}", id("a.txt")), &fr, "")
        .await
        .2;
    assert!(page.contains("(2 fois)") && page.contains("via « "), "{page}");
    let page = call(&e.app, "GET", &format!("/web/shares?lien={}", id("Depot")), &fr, "")
        .await
        .2;
    assert!(
        page.contains("et 2 autres fichiers déposés") && page.contains("dans « "),
        "{page}"
    );
}

#[tokio::test]
async fn search_finds_a_folder() {
    let e = env();
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let auth = basic("alice", &token(&e, "alpha"));
    send(
        &e.app,
        "MKCOL",
        &format!("{DAV}/Factures"),
        &[A, ("authorization", auth.as_str())],
        b"",
    )
    .await;
    let p = call(
        &e.app,
        "GET",
        "/web/search?q=factures",
        &[A, ("cookie", cookie.as_str())],
        "",
    )
    .await
    .2;
    assert!(p.contains("href=\"/web/files/Factures/\""), "{p}");
}

/// WebDAV corners: the old root, OPTIONS, methods a resource does not have, what lies outside the tree.
#[tokio::test]
async fn dav_roots_and_methods() {
    let e = env();
    file(&e, "a.txt", b"x");
    let auth = basic("alice", &token(&e, "alpha"));
    let a = [A, ("authorization", auth.as_str())];
    let d0 = [A, ("authorization", auth.as_str()), ("depth", "0")];
    assert_eq!(
        status(&e.app, "PROPFIND", "/remote.php/webdav", &d0).await,
        StatusCode::MULTI_STATUS
    );
    assert_eq!(
        status(&e.app, "PROPFIND", "/remote.php/webdav", &[A]).await,
        StatusCode::UNAUTHORIZED
    );
    let (s, h, _) = call(&e.app, "OPTIONS", &format!("{DAV}/"), &a, "").await;
    assert!(s == StatusCode::OK && h["dav"] == "1, 3" && h["allow"].to_str().unwrap().contains("PROPFIND"));
    assert_eq!(
        status(&e.app, "GET", &format!("{DAV}/"), &a).await,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(status(&e.app, "HEAD", &format!("{DAV}/"), &a).await, StatusCode::OK);
    assert_eq!(
        status(&e.app, "LOCK", &format!("{DAV}/a.txt"), &a).await,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        status(&e.app, "GET", "/remote.php/dav/avatars/alice/128.png", &a).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(&e.app, "GET", "/remote.php/dav/avatars/alice/128.png", &[A]).await,
        StatusCode::UNAUTHORIZED
    );
}

/// PROPFIND: the quota is a folder's property, a property without namespace comes back as unknown, and a prefix bound
/// to no namespace makes the document invalid.
#[tokio::test]
async fn propfind_quota_and_namespaces() {
    let e = env();
    file(&e, "a.txt", b"x");
    let auth = basic("alice", &token(&e, "alpha"));
    let d0 = [A, ("authorization", auth.as_str()), ("depth", "0")];
    let body = r#"<d:propfind xmlns:d="DAV:"><d:prop><d:quota-available-bytes/><d:quota-used-bytes/><foo xmlns=""/></d:prop></d:propfind>"#;
    let (s, _, dir) = call(&e.app, "PROPFIND", &format!("{DAV}/"), &d0, body).await;
    assert_eq!(s, StatusCode::MULTI_STATUS);
    assert!(
        dir.contains("<d:quota-available-bytes>") && dir.contains("<d:quota-used-bytes>"),
        "{dir}"
    );
    assert!(
        dir.contains(r#"<foo xmlns=""/>"#) && dir.contains("404 Not Found"),
        "{dir}"
    );
    let (_, _, f) = call(&e.app, "PROPFIND", &format!("{DAV}/a.txt"), &d0, body).await;
    assert!(
        !f.contains("<d:quota-used-bytes>") && f.contains("quota-used-bytes"),
        "{f}"
    );
    let bad = r#"<d:propfind xmlns:d="DAV:" xmlns:x=""><d:prop><x:a/></d:prop></d:propfind>"#;
    assert_eq!(
        call(&e.app, "PROPFIND", &format!("{DAV}/"), &d0, bad).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn disk_errors_become_http_statuses() {
    for (errno, code) in [
        (libc::ENOENT, StatusCode::NOT_FOUND),
        (libc::ELOOP, StatusCode::NOT_FOUND),
        (libc::ENOTDIR, StatusCode::NOT_FOUND),
        (libc::EACCES, StatusCode::FORBIDDEN),
        (libc::EPERM, StatusCode::FORBIDDEN),
        (libc::ENOTCAPABLE, StatusCode::FORBIDDEN),
        (libc::EISDIR, StatusCode::METHOD_NOT_ALLOWED),
        (libc::EIO, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        assert_eq!(io_status(&io::Error::from_raw_os_error(errno)), code, "{errno}");
    }
}

#[test]
fn form_values_of_a_body_that_is_not_text() {
    assert!(crate::http::form_values(&[0xff, b'a', b'=', b'1'], "a", 10).is_empty());
}

/// Saving under a new name at the root; an address that names no file.
#[tokio::test]
async fn editor_rename_at_the_root_and_empty_paths() {
    let e = env();
    file(&e, "a.txt", b"x");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let body = format!("csrf={csrf}&text=y&force=1&name=b.txt");
    let (s, h, p) = call(&e.app, "POST", "/web/edit/a.txt", &c, &body).await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/view/b.txt"), "{p}");
    assert_eq!(std::fs::read(e.a_root.path().join("alice/b.txt")).unwrap(), b"y");
    assert_eq!(status(&e.app, "GET", "/web/edit/%2F", &c).await, StatusCode::NOT_FOUND);
    for rest in ["text=y&force=1", "create=1"] {
        let body = format!("csrf={csrf}&{rest}");
        assert_eq!(
            call(&e.app, "POST", "/web/edit/%2F", &c, &body).await.0,
            StatusCode::NOT_FOUND,
            "{rest}"
        );
    }
}

/// How a link's history tells drops (one, two, more) and how the link ended, in both languages.
#[tokio::test]
async fn link_history_counts_and_endings() {
    let e = env();
    let t = alpha(&e);
    file(&e, "gone.txt", b"x");
    file(&e, "ended.txt", b"x");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let auth = basic("alice", &token(&e, "alpha"));
    let a = [A, ("authorization", auth.as_str())];
    let c = [A, ("cookie", cookie.as_str())];
    let f = [A, ("cookie", cookie.as_str()), FR];
    let one = [A, ("content-length", "1")];
    for (dir, drops) in [("Un", 1), ("Deux", 2)] {
        send(&e.app, "MKCOL", &format!("{DAV}/{dir}"), &a, b"").await;
        let link = make_share(&e, &cookie, &csrf, dir, "&perms=drop").await;
        for i in 0..drops {
            let url = format!("/s/{link}/drop/{i}.txt");
            assert_eq!(send(&e.app, "PUT", &url, &one, b"x").await.0, StatusCode::CREATED);
        }
    }
    let gone = make_share(&e, &cookie, &csrf, "gone.txt", "&perms=read").await;
    let ended = make_share(&e, &cookie, &csrf, "ended.txt", "&perms=read").await;
    for l in [&gone, &ended] {
        assert_eq!(status(&e.app, "GET", &format!("/s/{l}/dl"), &[A]).await, StatusCode::OK);
    }
    let shares = e.state.db.share_list(&t, "alice").unwrap();
    let id = |p: &str| shares.iter().find(|s| s.path_hint == p).unwrap().share_id.clone();
    let body = format!("csrf={csrf}&id={}", id("ended.txt"));
    assert_eq!(
        call(&e.app, "POST", "/web/shares/revoke", &c, &body).await.0,
        StatusCode::OK
    );
    std::fs::remove_file(e.a_root.path().join("alice/gone.txt")).unwrap();
    assert_eq!(
        status(&e.app, "GET", &format!("/s/{gone}"), &[A]).await,
        StatusCode::NOT_FOUND
    );
    let page = async |h: &[(&str, &str)], p: &str| {
        let url = format!("/web/shares?lien={}", id(p));
        call(&e.app, "GET", &url, h, "").await.2
    };
    assert!(page(&f, "Un").await.contains("déposé ("));
    assert!(page(&f, "Deux").await.contains("et 1 autre fichier déposé"));
    assert!(page(&c, "Deux").await.contains("and 1 other file uploaded"));
    assert!(page(&f, "gone.txt").await.contains("source supprimée ou déplacée"));
    assert!(page(&f, "ended.txt").await.contains(", lien "));
}

/// `type:` keeps what it names, and only that.
#[tokio::test]
async fn search_by_type() {
    let e = env();
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let auth = basic("alice", &token(&e, "alpha"));
    let a = [A, ("authorization", auth.as_str()), ("content-length", "1")];
    let names = ["photo.jpg", "film.mp4", "son.mp3", "lot.zip", "main.rs"];
    for n in names {
        let s = send(&e.app, "PUT", &format!("{DAV}/{n}"), &a, b"x").await.0;
        assert_eq!(s, StatusCode::CREATED, "{n}");
    }
    let c = [A, ("cookie", cookie.as_str())];
    for (kind, want) in [
        ("image", "photo.jpg"),
        ("video", "film.mp4"),
        ("audio", "son.mp3"),
        ("archive", "lot.zip"),
        ("code", "main.rs"),
    ] {
        let p = call(&e.app, "GET", &format!("/web/search?q=type%3A{kind}"), &c, "")
            .await
            .2;
        for n in names {
            assert_eq!(p.contains(&format!("/web/view/{n}")), n == want, "{kind} {n}");
        }
    }
    crate::index::fuzz_query("cæsar *.md type:pdf".as_bytes());
    crate::index::fuzz_query(&[0xff]);
}

/// A ZIP of a selection holding a folder and a file.
#[tokio::test]
async fn zip_of_a_selection_with_a_folder() {
    let e = env();
    file(&e, "a.txt", b"x");
    let root = root(&e);
    root.mkdir(&SafePath::new("Dos").unwrap()).unwrap();
    root.atomic_write(&SafePath::new("Dos/b.txt").unwrap(), &mut &b"y"[..])
        .unwrap();
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let body = format!("csrf={csrf}&dir=&op=zip&item=a.txt&item=Dos");
    let (s, h, _) = call(&e.app, "POST", "/web/bulk", &c, &body).await;
    assert_eq!(
        (s, h["content-type"].to_str().unwrap()),
        (StatusCode::OK, "application/zip")
    );
}

/// What WebDAV refuses: a body on MKCOL, moving the root or onto it, a property without namespace, a trash path that
/// means nothing, another user's trash.
#[tokio::test]
async fn dav_refusals() {
    let e = env();
    file(&e, "a.txt", b"x");
    let auth = basic("alice", &token(&e, "alpha"));
    let a = [A, ("authorization", auth.as_str())];
    let h = [A, ("authorization", auth.as_str()), ("content-length", "1")];
    assert_eq!(
        send(&e.app, "MKCOL", &format!("{DAV}/d"), &h, b"x").await.0,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let to = format!("http://files.alpha.example{DAV}/b.txt");
    let m = [A, ("authorization", auth.as_str()), ("destination", to.as_str())];
    assert_eq!(
        status(&e.app, "MOVE", &format!("{DAV}/"), &m).await,
        StatusCode::FORBIDDEN
    );
    let to = format!("http://files.alpha.example{DAV}/");
    let m = [A, ("authorization", auth.as_str()), ("destination", to.as_str())];
    assert_eq!(
        status(&e.app, "MOVE", &format!("{DAV}/a.txt"), &m).await,
        StatusCode::FORBIDDEN
    );
    assert!(e.a_root.path().join("alice/a.txt").is_file());
    let body =
        r#"<d:propertyupdate xmlns:d="DAV:"><d:set><d:prop><foo xmlns="">1</foo></d:prop></d:set></d:propertyupdate>"#;
    let (s, _, p) = call(&e.app, "PROPPATCH", &format!("{DAV}/a.txt"), &a, body).await;
    assert!(
        s == StatusCode::MULTI_STATUS && p.contains(r#"<foo xmlns=""/>"#),
        "{s} {p}"
    );
    let d = [A, ("authorization", auth.as_str()), ("depth", "1")];
    for p in [
        "/remote.php/dav/trashbin/alice/autre",
        "/remote.php/dav/trashbin/bob/trash",
    ] {
        assert_eq!(status(&e.app, "PROPFIND", p, &d).await, StatusCode::NOT_FOUND, "{p}");
    }
}

/// The clients' sharing API: what it refuses, with the envelope each version expects; another user's link does not
/// exist.
#[tokio::test]
async fn sharing_api_refusals() {
    let e = env();
    let t = alpha(&e);
    file(&e, "a.txt", b"x");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    make_share(&e, &cookie, &csrf, "a.txt", "&perms=read").await;
    let share = e.state.db.share_list(&t, "alice").unwrap().remove(0);
    let id = crate::nc::share::ocs_id(&share.share_id);
    let auth = basic("alice", &token(&e, "alpha"));
    let h = [A, ("authorization", auth.as_str()), ("accept", "application/json")];
    let api = "/ocs/v2.php/apps/files_sharing/api/v1/shares";
    assert_eq!(
        status(&e.app, "GET", &format!("{api}?path=../x"), &h).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(&e.app, "GET", &format!("{api}/999999"), &h).await,
        StatusCode::NOT_FOUND
    );
    // v1 always answers 200: the refusal is in the envelope.
    let v1 = "/ocs/v1.php/apps/files_sharing/api/v1/shares/999999";
    let (s, _, b) = call(&e.app, "GET", v1, &h, "").await;
    assert!(s == StatusCode::OK && b.contains("\"statuscode\":400"), "{s} {b}");
    std::fs::create_dir(e.a_root.path().join("bob")).unwrap();
    e.state.db.user_add(&t, "bob", "unused", false).unwrap();
    let auth_b = basic(
        "bob",
        &crate::auth::new_app_password(&e.state.db, &t, "bob", "t").unwrap(),
    );
    let b = [A, ("authorization", auth_b.as_str()), ("accept", "application/json")];
    for m in ["GET", "DELETE"] {
        assert_eq!(
            status(&e.app, m, &format!("{api}/{id}"), &b).await,
            StatusCode::NOT_FOUND,
            "{m}"
        );
    }
    assert_eq!(e.state.db.share_list(&t, "alice").unwrap().len(), 1);
}
