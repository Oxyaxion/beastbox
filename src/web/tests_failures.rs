//! When something underneath fails: the database, the disk, the password workers, a full or read-only server. The
//! client gets a clean refusal, the session stays closed rather than open, and nothing is left half done.

use super::tests::{login, make_share};
use crate::auth::tests::{code_at, enable_totp};
use crate::auth::totp;
use crate::fs::{Root, SafePath};
use crate::http::Settings;
use crate::http::tests::{A, Env, basic, call, env, env_with, send, status, token};
use crate::tenant::TenantCtx;
use axum::http::{HeaderMap, StatusCode};
use std::os::unix::fs::PermissionsExt;

const DAV: &str = "/remote.php/dav/files/alice";
const BUSY: StatusCode = StatusCode::SERVICE_UNAVAILABLE;

fn alpha(e: &Env) -> TenantCtx {
    e.state.registry.by_name("alpha").unwrap()
}

fn file(e: &Env, name: &str) {
    let root = Root::open_dir(&e.a_root.path().join("alice")).unwrap();
    root.atomic_write(&SafePath::new(name).unwrap(), &mut &b"x"[..])
        .unwrap();
}

fn location(h: &HeaderMap) -> &str {
    h.get("location").and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// Every `op` (INSERT, UPDATE, DELETE) on `table` fails from now on; reads go on working.
fn refuse(e: &Env, op: &str, table: &str) {
    e.state.db.exec_for_test(&format!(
        "CREATE TRIGGER refuse_{op}_{table} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT, 'test'); END;"
    ));
}

fn allow(e: &Env, op: &str, table: &str) {
    e.state.db.exec_for_test(&format!("DROP TRIGGER refuse_{op}_{table};"));
}

/// The table disappears (reads fail too) until `restore`.
fn hide(e: &Env, table: &str) {
    e.state
        .db
        .exec_for_test(&format!("ALTER TABLE {table} RENAME TO hidden_{table};"));
}

fn restore(e: &Env, table: &str) {
    e.state
        .db
        .exec_for_test(&format!("ALTER TABLE hidden_{table} RENAME TO {table};"));
}

#[tokio::test]
async fn unreadable_tables_close_the_door() {
    let e = env();
    file(&e, "a.txt");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let link = make_share(&e, &cookie, &csrf, "a.txt", "&perms=read").await;
    let auth = basic("alice", &token(&e, "alpha"));
    let c = [A, ("cookie", cookie.as_str())];
    let d = [A, ("authorization", auth.as_str()), ("depth", "0")];

    hide(&e, "session");
    let (s, h, _) = call(&e.app, "GET", "/web/files/", &c, "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login"));
    restore(&e, "session");

    hide(&e, "app_token");
    assert_eq!(status(&e.app, "PROPFIND", &format!("{DAV}/"), &d).await, BUSY);
    assert_eq!(status(&e.app, "GET", "/web/account", &c).await, BUSY);
    restore(&e, "app_token");

    hide(&e, "share");
    assert_eq!(status(&e.app, "GET", "/web/shares", &c).await, BUSY);
    assert_eq!(
        status(&e.app, "GET", &format!("/s/{link}"), &[A]).await,
        StatusCode::NOT_FOUND
    );
    // The "shared" icon is an extra: the listing still answers.
    assert_eq!(
        status(&e.app, "PROPFIND", &format!("{DAV}/"), &d).await,
        StatusCode::MULTI_STATUS
    );
    restore(&e, "share");

    hide(&e, "share_event");
    assert_eq!(status(&e.app, "GET", "/web/activity", &c).await, BUSY);
    restore(&e, "share_event");

    assert_eq!(status(&e.app, "GET", "/web/shares", &c).await, StatusCode::OK);
    assert_eq!(status(&e.app, "GET", &format!("/s/{link}"), &[A]).await, StatusCode::OK);
}

#[tokio::test]
async fn refused_writes_change_nothing() {
    let e = env();
    let t = alpha(&e);
    file(&e, "a.txt");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let link = make_share(&e, &cookie, &csrf, "a.txt", "&perms=read").await;
    let id = e.state.db.share_list(&t, "alice").unwrap()[0].share_id.clone();
    let c = [A, ("cookie", cookie.as_str())];
    let post = async |p: &str, rest: String| call(&e.app, "POST", p, &c, &format!("csrf={csrf}{rest}")).await;

    // The history must not cost the guest the download.
    refuse(&e, "INSERT", "share_event");
    assert_eq!(
        status(&e.app, "GET", &format!("/s/{link}/dl"), &[A]).await,
        StatusCode::OK
    );
    allow(&e, "INSERT", "share_event");

    refuse(&e, "INSERT", "app_token");
    assert_eq!(
        post("/web/account/tokens", "&label=x&password=pw-alice".into()).await.0,
        BUSY
    );
    assert_eq!(post("/web/account/qr", "&password=pw-alice".into()).await.0, BUSY);
    assert!(e.state.db.token_list(&t, "alice").unwrap().is_empty());

    refuse(&e, "INSERT", "share");
    let (s, h, _) = post("/web/shares", "&path=a.txt&perms=read".into()).await;
    assert_eq!((s, h.contains_key("retry-after")), (BUSY, true));
    assert_eq!(e.state.db.share_list(&t, "alice").unwrap().len(), 1);

    refuse(&e, "UPDATE", "share");
    refuse(&e, "DELETE", "share");
    assert_eq!(post("/web/shares/revoke", format!("&id={id}")).await.0, BUSY);
    allow(&e, "UPDATE", "share");
    allow(&e, "DELETE", "share");
    assert_eq!(status(&e.app, "GET", &format!("/s/{link}"), &[A]).await, StatusCode::OK);

    refuse(&e, "UPDATE", "user");
    let new = "un-nouveau-secret-42";
    let (s, _, p) = post(
        "/web/account/password",
        format!("&current=pw-alice&new={new}&again={new}"),
    )
    .await;
    assert!(s == BUSY && p.contains("nothing was changed"), "{s} {p}");
    allow(&e, "UPDATE", "user");

    // No session could be stored: no cookie, and the old password is still the one.
    refuse(&e, "INSERT", "session");
    let (s, h, _) = call(&e.app, "POST", "/login", &[A], "user=alice&password=pw-alice").await;
    assert_eq!((s, h.contains_key("set-cookie")), (BUSY, false));
    allow(&e, "INSERT", "session");
    login(&e, A, "pw-alice").await;
}

#[tokio::test]
async fn second_step_when_the_database_refuses() {
    let e = env();
    let t = alpha(&e);
    // Turning it on: the secret cannot be stored.
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    assert_eq!(
        call(&e.app, "POST", "/web/account/2fa/start", &c, &format!("csrf={csrf}"))
            .await
            .0,
        StatusCode::OK
    );
    let secret = totp::setup_secret(&t, cookie.split_once('=').unwrap().1);
    let code = format!("{:06}", totp::hotp(&secret, totp::step(totp::now())));
    refuse(&e, "UPDATE", "user");
    let body = format!("csrf={csrf}&password=pw-alice&code={code}");
    assert_eq!(
        call(&e.app, "POST", "/web/account/2fa/confirm", &c, &body).await.0,
        BUSY
    );
    allow(&e, "UPDATE", "user");
    assert_eq!(e.state.db.totp_get(&t, "alice").unwrap(), Some((None, 0)));

    // Renewing the recovery codes: the old ones stay.
    enable_totp(&e.state.db, &t, "alice");
    let before = e.state.db.recovery_count(&t, "alice").unwrap();
    refuse(&e, "INSERT", "recovery_code");
    let body = format!("csrf={csrf}&op=codes&password=pw-alice&code={}", code_at(0));
    let (s, _, _) = call(
        &e.app,
        "POST",
        "/web/account/2fa",
        &[A, ("cookie", login_after(&e).await.as_str())],
        &body,
    )
    .await;
    assert_ne!(s, StatusCode::OK);
    allow(&e, "INSERT", "recovery_code");
    assert_eq!(e.state.db.recovery_count(&t, "alice").unwrap(), before);

    // Signing in: the code cannot be marked as used, so it does not open a session.
    let (s, h, _) = call(&e.app, "POST", "/login", &[A], "user=alice&password=pw-alice").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login/code"));
    let pending = h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
    let page = call(&e.app, "GET", "/login/code", &[A, ("cookie", pending.as_str())], "")
        .await
        .2;
    let c = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    refuse(&e, "UPDATE", "user");
    let body = format!("csrf={c}&code={}", code_at(0));
    let (s, h, _) = call(&e.app, "POST", "/login/code", &[A, ("cookie", pending.as_str())], &body).await;
    assert_eq!((s, h.contains_key("set-cookie")), (BUSY, false));
}

/// With two-step verification on, the first session was ended: a stale cookie is enough to prove the form is refused.
async fn login_after(e: &Env) -> String {
    let (s, h, _) = call(&e.app, "POST", "/login", &[A], "user=alice&password=pw-alice").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned()
}

/// The password workers are gone (shutdown, overload): nothing that checks or hashes a password goes through.
#[tokio::test]
async fn no_password_worker() {
    let e = env();
    let t = alpha(&e);
    file(&e, "a.txt");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let link = make_share(&e, &cookie, &csrf, "a.txt", "&perms=read&password=secret-du-lien").await;
    enable_totp(&e.state.db, &t, "alice");
    e.state.argon.close();
    let c = [A, ("cookie", cookie.as_str())];
    for (path, h, body) in [
        ("/login".to_owned(), &[A][..], "user=alice&password=pw-alice".to_owned()),
        (format!("/s/{link}"), &[A][..], "password=secret-du-lien".to_owned()),
        (
            "/web/account/password".to_owned(),
            &c[..],
            format!("csrf={csrf}&current=pw-alice&new=un-nouveau-secret-42"),
        ),
        (
            "/web/account/2fa".to_owned(),
            &c[..],
            format!("csrf={csrf}&op=off&password=pw-alice&code=000000"),
        ),
        (
            "/web/shares".to_owned(),
            &c[..],
            format!("csrf={csrf}&path=a.txt&perms=read&password=un-secret-assez-long"),
        ),
    ] {
        let (s, h, b) = call(&e.app, "POST", &path, h, &body).await;
        assert!(s == BUSY && h.contains_key("retry-after"), "{path}: {s} {b}");
    }
    assert_eq!(e.state.db.share_list(&t, "alice").unwrap().len(), 1);
}

/// The user's folder cannot be opened: every page refuses, none answers with an empty success or a server error, and
/// no write gets through.
#[tokio::test]
async fn unreadable_home() {
    let e = env();
    file(&e, "a.txt");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let link = make_share(&e, &cookie, &csrf, "a.txt", "&perms=read").await;
    let auth = basic("alice", &token(&e, "alpha"));
    let c = [A, ("cookie", cookie.as_str())];
    let a = [A, ("authorization", auth.as_str())];
    let d = [A, ("authorization", auth.as_str()), ("depth", "0")];
    let home = e.a_root.path().join("alice");
    std::fs::set_permissions(&home, PermissionsExt::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&home).is_ok() {
        std::fs::set_permissions(&home, PermissionsExt::from_mode(0o700)).unwrap();
        return; // root ignores the permissions
    }
    let mut got = Vec::new();
    for p in [
        "/web/files/",
        "/web/view/a.txt",
        "/web/edit/a.txt",
        "/web/raw/a.txt",
        "/web/zip/",
        "/web/tree/",
        "/web/search?q=a",
        "/web/favorites",
        "/web/trash",
    ] {
        got.push((p.to_owned(), status(&e.app, "GET", p, &c).await, StatusCode::FORBIDDEN));
    }
    for p in ["/web/activity", "/web/shares", "/web/account"] {
        got.push((p.to_owned(), status(&e.app, "GET", p, &c).await, BUSY));
    }
    for (p, rest) in [
        ("/web/tags", "&path=a.txt&op=add&tag=x"),
        ("/web/favorite", "&path=a.txt&on=1"),
        ("/web/trash/restore", "&slot=x"),
        ("/web/trash/purge", "&slot=x&confirm=1"),
        ("/web/trash/empty", "&confirm=1"),
        ("/web/bulk", "&dir=&op=delete&item=a.txt"),
        ("/web/shares", "&path=a.txt&perms=read"),
    ] {
        let s = call(&e.app, "POST", p, &c, &format!("csrf={csrf}{rest}")).await.0;
        got.push((p.to_owned(), s, StatusCode::FORBIDDEN));
    }
    got.push((
        "PROPFIND".into(),
        status(&e.app, "PROPFIND", &format!("{DAV}/"), &d).await,
        StatusCode::FORBIDDEN,
    ));
    got.push((
        "PUT".into(),
        send(&e.app, "PUT", &format!("{DAV}/b.txt"), &a, b"y").await.0,
        StatusCode::FORBIDDEN,
    ));
    got.push((
        "cloud/user".into(),
        status(&e.app, "GET", "/ocs/v2.php/cloud/user", &a).await,
        BUSY,
    ));
    got.push((
        "link".into(),
        status(&e.app, "GET", &format!("/s/{link}"), &[A]).await,
        StatusCode::NOT_FOUND,
    ));
    std::fs::set_permissions(&home, PermissionsExt::from_mode(0o700)).unwrap();
    let wrong: Vec<_> = got.iter().filter(|(_, s, want)| s != want).collect();
    assert!(wrong.is_empty(), "{wrong:?}");
    let names: Vec<_> = std::fs::read_dir(&home)
        .unwrap()
        .map(|x| x.unwrap().file_name())
        .collect();
    assert!(
        names.contains(&"a.txt".into()) && !names.contains(&"b.txt".into()),
        "{names:?}"
    );
    assert_eq!(status(&e.app, "GET", &format!("/s/{link}"), &[A]).await, StatusCode::OK);
}

/// A full disk and a read-only server, seen from the editor and from a drop link: the reason is given, nothing is
/// written.
#[tokio::test]
async fn editor_and_drop_on_a_full_or_read_only_server() {
    for (settings, code, text) in [
        (
            Settings {
                min_free_bytes: u64::MAX,
                ..Default::default()
            },
            BUSY,
            "read-only",
        ),
        (
            Settings {
                read_only: true,
                ..Default::default()
            },
            BUSY,
            "read-only",
        ),
    ] {
        let e = env_with(settings);
        file(&e, "a.txt");
        Root::open_dir(&e.a_root.path().join("alice"))
            .unwrap()
            .mkdir(&SafePath::new("Depot").unwrap())
            .unwrap();
        let (cookie, csrf) = login(&e, A, "pw-alice").await;
        let c = [A, ("cookie", cookie.as_str())];
        let body = format!("csrf={csrf}&text=nouveau&force=1");
        let (s, _, p) = call(&e.app, "POST", "/web/edit/a.txt", &c, &body).await;
        assert!(s == code && p.contains(text), "{s} {p}");
        let (s, _, p) = call(
            &e.app,
            "POST",
            "/web/edit/neuf.txt",
            &c,
            &format!("csrf={csrf}&create=1"),
        )
        .await;
        assert!(s == code && p.contains(text), "{s} {p}");
        let home = e.a_root.path().join("alice");
        assert_eq!(std::fs::read(home.join("a.txt")).unwrap(), b"x");
        assert!(!home.join("neuf.txt").exists());
        // The same refusal for a guest dropping a file.
        let link = make_share(&e, &cookie, &csrf, "Depot", "&perms=drop").await;
        let h = [A, ("content-length", "1")];
        let s = send(&e.app, "PUT", &format!("/s/{link}/drop/b.txt"), &h, b"y").await.0;
        assert_eq!(s, code);
        assert_eq!(std::fs::read_dir(home.join("Depot")).unwrap().count(), 0);
    }
}

/// Plain HTTP deployments (`insecure_cookies`): the cookie loses the `__Host-` prefix and still signs in.
#[tokio::test]
async fn cookie_without_the_host_prefix() {
    let e = env_with(Settings {
        insecure_cookies: true,
        ..Default::default()
    });
    let (s, h, _) = call(&e.app, "POST", "/login", &[A], "user=alice&password=pw-alice").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let cookie = h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
    assert!(cookie.starts_with("bb"), "{cookie}");
    assert_eq!(
        status(&e.app, "GET", "/web/files/", &[A, ("cookie", cookie.as_str())]).await,
        StatusCode::OK
    );
}

/// The clients' API when the database or the password workers fail: a refusal, and the link is untouched.
#[tokio::test]
async fn sharing_api_when_things_fail() {
    let e = env();
    let t = alpha(&e);
    file(&e, "a.txt");
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    make_share(&e, &cookie, &csrf, "a.txt", "&perms=read").await;
    let share = e.state.db.share_list(&t, "alice").unwrap().remove(0);
    let auth = basic("alice", &token(&e, "alpha"));
    let h = [
        A,
        ("authorization", auth.as_str()),
        ("accept", "application/json"),
        ("content-type", "application/x-www-form-urlencoded"),
    ];
    let api = "/ocs/v2.php/apps/files_sharing/api/v1/shares";
    let one = format!("{api}/{}", crate::nc::share::ocs_id(&share.share_id));
    refuse(&e, "UPDATE", "share");
    refuse(&e, "DELETE", "share");
    assert_eq!(status(&e.app, "DELETE", &one, &h).await, BUSY);
    allow(&e, "UPDATE", "share");
    allow(&e, "DELETE", "share");
    e.state.argon.close();
    let body = "path=/a.txt&shareType=3&password=un-secret-assez-long";
    assert_eq!(call(&e.app, "POST", api, &h, body).await.0, BUSY);
    hide(&e, "share");
    assert_eq!(status(&e.app, "GET", api, &h).await, BUSY);
    restore(&e, "share");
    assert_eq!(e.state.db.share_list(&t, "alice").unwrap().len(), 1);
}

/// The Login Flow confirmation: an anonymous request creates nothing and goes to the login; a signed-in one
/// creates the app password, and a database that refuses the row leaves nothing behind.
#[tokio::test]
async fn login_flow_refusals() {
    let e = env();
    let proto = ("x-forwarded-proto", "http");
    let (_, _, body) = call(&e.app, "POST", "/index.php/login/v2", &[A, proto], "").await;
    let flow = body
        .split("/index.php/login/v2/flow/")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let form = format!("/index.php/login/v2/flow/{flow}");
    let t = alpha(&e);
    assert_eq!(
        call(&e.app, "POST", &form, &[A, proto], "").await.0,
        StatusCode::SEE_OTHER
    );
    assert!(e.state.db.token_list(&t, "alice").unwrap().is_empty());
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, proto, ("cookie", cookie.as_str())];
    let body = format!("csrf={csrf}&password=pw-alice");
    refuse(&e, "INSERT", "app_token");
    assert_eq!(call(&e.app, "POST", &form, &c, &body).await.0, BUSY);
    allow(&e, "INSERT", "app_token");
    assert!(e.state.db.token_list(&t, "alice").unwrap().is_empty());
    assert_eq!(call(&e.app, "POST", &form, &c, &body).await.0, StatusCode::OK);
    assert_eq!(e.state.db.token_list(&t, "alice").unwrap().len(), 1);
}
