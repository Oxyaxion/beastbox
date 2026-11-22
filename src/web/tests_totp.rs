//! Two-step verification through the router: set up, sign-in, recovery codes, limits, tenant modes, gate order,
//! Login Flow, administrator reset. Each test checks the other user and the other tenant where they could be touched.

use super::tests::login;
use crate::auth::tests::{code_at, enable_totp};
use crate::auth::{self, totp};
use crate::config::TwoFactor;
use crate::http::tests::{A, Env, call, env, env_with, status};
use crate::tenant::TenantCtx;
use axum::http::{HeaderMap, StatusCode};

const B: (&str, &str) = ("host", "x.beta.example");

fn alpha(e: &Env) -> TenantCtx {
    e.state.registry.by_name("alpha").unwrap()
}

fn env_mode(mode: TwoFactor) -> Env {
    env_with(crate::http::Settings {
        two_factor: vec![("alpha".into(), mode)],
        ..Default::default()
    })
}

fn location(h: &HeaderMap) -> &str {
    h.get("location").and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// `name=value` of the session cookie set by a response, and its `Max-Age`.
fn set_session(h: &HeaderMap) -> (String, String) {
    let set = h["set-cookie"].to_str().unwrap();
    let age = set
        .split("Max-Age=")
        .nth(1)
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    (set.split(';').next().unwrap().to_owned(), age)
}

fn csrf(e: &Env, host: (&str, &str), cookie: &str) -> String {
    let t = e.state.registry.resolve(host.1).unwrap();
    auth::csrf_token(&t, cookie.split_once('=').unwrap().1)
}

/// Password step of an account with two-step verification: the waiting session (cookie, csrf).
async fn login_pending(e: &Env, host: (&'static str, &'static str), user: &str, pw: &str) -> (String, String) {
    let (s, h, _) = call(&e.app, "POST", "/login", &[host], &format!("user={user}&password={pw}")).await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login/code"));
    let (cookie, age) = set_session(&h);
    assert_eq!(age, auth::PENDING_TTL.to_string()); // the password alone lasts 5 minutes
    let c = csrf(e, host, &cookie);
    (cookie, c)
}

/// Both steps; the full session (cookie, csrf).
async fn login2(e: &Env, host: (&'static str, &'static str), pw: &str, code: &str) -> (String, String) {
    let (pending, c) = login_pending(e, host, "alice", pw).await;
    let (s, h, page) = call(
        &e.app,
        "POST",
        "/login/code",
        &[host, ("cookie", &pending)],
        &format!("csrf={c}&code={code}"),
    )
    .await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/files/"), "{page}");
    let (cookie, age) = set_session(&h);
    assert_ne!(
        cookie, pending,
        "a new session after the code (the waiting one is not promoted)"
    );
    assert_eq!(age, auth::SESSION_TTL.to_string());
    let c = csrf(e, host, &cookie);
    (cookie, c)
}

async fn code_post(e: &Env, cookie: &str, body: &str) -> (StatusCode, HeaderMap, String) {
    call(&e.app, "POST", "/login/code", &[A, ("cookie", cookie)], body).await
}

/// Turning it on from the account page: QR code and key, a wrong code stores nothing, the right one turns it on and
/// shows 10 recovery codes once; the other tenant's alice stays off.
#[tokio::test]
async fn account_turns_it_on() {
    let e = env();
    let t = alpha(&e);
    let (other, _) = login(&e, A, "pw-alice").await; // another browser
    let (b_cookie, _) = login(&e, B, "pw-alice").await;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let page = call(&e.app, "GET", "/web/account", &c, "").await.2;
    assert!(page.contains("action=\"/web/account/2fa/start#double\""), "{page}");
    assert_eq!(
        call(&e.app, "POST", "/web/account/2fa/start", &c, "csrf=faux").await.0,
        StatusCode::FORBIDDEN
    );
    let (s, _, page) = call(&e.app, "POST", "/web/account/2fa/start", &c, &format!("csrf={csrf}")).await;
    let secret = totp::setup_secret(&t, cookie.split_once('=').unwrap().1);
    let key = totp::grouped(&totp::base32(&secret));
    assert!(
        s == StatusCode::OK && page.contains("<svg") && page.contains(&key),
        "{page}"
    );
    // The same QR code if the page is shown again (nothing stored until confirmed).
    assert!(
        call(&e.app, "POST", "/web/account/2fa/start", &c, &format!("csrf={csrf}"))
            .await
            .2
            .contains(&key)
    );
    assert_eq!(e.state.db.totp_get(&t, "alice").unwrap(), Some((None, 0)));
    let st = totp::step(totp::now());
    let wrong = format!("{:06}", (totp::hotp(&secret, st) + 1) % 1_000_000);
    for bad in [wrong.as_str(), "", "12345", "abcdef"] {
        let (s, _, page) = call(
            &e.app,
            "POST",
            "/web/account/2fa/confirm",
            &c,
            &format!("csrf={csrf}&code={bad}"),
        )
        .await;
        assert!(
            s == StatusCode::BAD_REQUEST && page.contains("Wrong code") && page.contains(&key),
            "{bad}: {page}"
        );
    }
    assert_eq!(e.state.db.totp_get(&t, "alice").unwrap(), Some((None, 0)));
    let right = format!("{:06}", totp::hotp(&secret, st));
    let (s, h, page) = call(
        &e.app,
        "POST",
        "/web/account/2fa/confirm",
        &c,
        &format!("csrf={csrf}&code={right}"),
    )
    .await;
    assert!(
        s == StatusCode::OK && page.contains("Two-step verification is on."),
        "{page}"
    );
    assert_eq!(h["cache-control"], "no-store"); // recovery codes never cached
    let shown: Vec<&str> = page
        .split("<li><code>")
        .skip(1)
        .map(|x| x.split('<').next().unwrap())
        .collect();
    assert_eq!(shown.len(), 10, "{page}");
    assert!(shown.iter().all(|x| totp::parse_recovery(x).is_some()));
    // Shown once: the account page now gives the count only, and refuses a second setup.
    let page = call(&e.app, "GET", "/web/account", &c, "").await.2;
    assert!(
        page.contains("10 recovery codes left") && !page.contains(shown[0]),
        "{page}"
    );
    let (s, _, _) = call(&e.app, "POST", "/web/account/2fa/start", &c, &format!("csrf={csrf}")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, _) = call(
        &e.app,
        "POST",
        "/web/account/2fa/confirm",
        &c,
        &format!("csrf={csrf}&code={right}"),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Turning it on ended alice's other web sessions, not this one (nor the other tenant's).
    assert_eq!(
        status(&e.app, "GET", "/web/files/", &[A, ("cookie", other.as_str())]).await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(status(&e.app, "GET", "/web/files/", &c).await, StatusCode::OK);
    assert_eq!(
        status(&e.app, "GET", "/web/files/", &[B, ("cookie", b_cookie.as_str())]).await,
        StatusCode::OK
    );
    // The other tenant's alice: still off, signs in with her password alone.
    assert_eq!(
        e.state
            .db
            .totp_get(&e.state.registry.by_name("beta").unwrap(), "alice")
            .unwrap(),
        Some((None, 0))
    );
    login(&e, B, "pw-alice").await;
}

/// Sign-in with a code: the password opens only the code page (5 minutes); the code replaces that session with a full
/// one; a used code, a wrong one, a missing one or a forged form token do not pass.
#[tokio::test]
async fn sign_in_needs_the_code() {
    let e = env();
    enable_totp(&e.state.db, &alpha(&e), "alice");
    let (pending, c) = login_pending(&e, A, "alice", "pw-alice").await;
    let p = [A, ("cookie", pending.as_str())];
    for path in [
        "/web/files/",
        "/web/account",
        "/web/shares",
        "/web/welcome",
        "/web/2fa-setup",
        "/login",
    ] {
        let (s, h, _) = call(&e.app, "GET", path, &p, "").await;
        assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login/code"), "{path}");
    }
    for path in [
        "/web/account/tokens",
        "/web/account/qr",
        "/web/account/2fa/start",
        "/web/account/password",
    ] {
        let (s, h, _) = call(&e.app, "POST", path, &p, &format!("csrf={c}&label=x")).await;
        assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login/code"), "{path}");
    }
    assert!(e.state.db.token_list(&alpha(&e), "alice").unwrap().is_empty());
    let dav = [
        A,
        ("cookie", pending.as_str()),
        ("x-csrf-token", c.as_str()),
        ("depth", "0"),
    ];
    assert_eq!(
        status(&e.app, "PROPFIND", "/web/dav/", &dav).await,
        StatusCode::UNAUTHORIZED
    );
    let (s, page) = (
        call(&e.app, "GET", "/login/code", &p, "").await.0,
        call(&e.app, "GET", "/login/code", &p, "").await.2,
    );
    assert!(
        s == StatusCode::OK && page.contains("one-time-code") && page.contains(&c),
        "{page}"
    );
    for (body, code) in [
        (format!("csrf=faux&code={}", code_at(0)), StatusCode::FORBIDDEN),
        (format!("csrf={c}"), StatusCode::BAD_REQUEST),
        (format!("csrf={c}&code={}", code_at(-1)), StatusCode::UNAUTHORIZED), // the setup step: already used
        (format!("csrf={c}&code={}", code_at(2)), StatusCode::UNAUTHORIZED),
        (format!("csrf={c}&code=000000x"), StatusCode::UNAUTHORIZED),
    ] {
        let (s, _, page) = code_post(&e, &pending, &body).await;
        assert_eq!(s, code, "{body}: {page}");
    }
    let (s, h, _) = code_post(&e, &pending, &format!("csrf={c}&code={}", code_at(0))).await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/files/"));
    let (full, _) = set_session(&h);
    assert_eq!(
        status(&e.app, "GET", "/web/files/", &[A, ("cookie", full.as_str())]).await,
        StatusCode::OK
    );
    let (s, h, _) = call(&e.app, "GET", "/login/code", &p, "").await; // the waiting session is gone
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login"));
    // The same code again (another sign-in): refused.
    let (pending, c) = login_pending(&e, A, "alice", "pw-alice").await;
    let (s, _, _) = code_post(&e, &pending, &format!("csrf={c}&code={}", code_at(0))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // A code typed with a space passes.
    let k = code_at(1);
    let (s, _, _) = code_post(&e, &pending, &format!("csrf={c}&code={}+{}", &k[..3], &k[3..])).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
}

/// The "open in the browser" link of a client survives the second step.
#[tokio::test]
async fn sign_in_keeps_the_client_link() {
    let e = env();
    enable_totp(&e.state.db, &alpha(&e), "alice");
    let (s, h, _) = call(
        &e.app,
        "POST",
        "/login",
        &[A],
        "user=alice&password=pw-alice&next=/index.php/f/42",
    )
    .await;
    assert_eq!(
        (s, location(&h)),
        (StatusCode::SEE_OTHER, "/login/code?next=/index.php/f/42")
    );
    let (pending, _) = set_session(&h);
    let c = csrf(&e, A, &pending);
    let page = call(
        &e.app,
        "GET",
        "/login/code?next=/index.php/f/42",
        &[A, ("cookie", pending.as_str())],
        "",
    )
    .await
    .2;
    assert!(page.contains("name=\"next\" value=\"/index.php/f/42\""), "{page}");
    let body = format!("csrf={c}&code={}&next=/index.php/f/42", code_at(0));
    let (s, h, _) = code_post(&e, &pending, &body).await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/index.php/f/42"));
    // Anything else than a client link is ignored (never another site).
    let (pending, c) = login_pending(&e, A, "alice", "pw-alice").await;
    let body = format!("csrf={c}&code={}&next=https://evil.test/", code_at(1));
    let (s, h, _) = code_post(&e, &pending, &body).await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/files/"));
}

/// Recovery codes: each works once, typed loosely; a made-up one or another tenant's never.
#[tokio::test]
async fn recovery_code_signs_in_once() {
    let e = env();
    let codes = enable_totp(&e.state.db, &alpha(&e), "alice");
    let beta = enable_totp(&e.state.db, &e.state.registry.by_name("beta").unwrap(), "alice");
    let (pending, c) = login_pending(&e, A, "alice", "pw-alice").await;
    for bad in ["zzzz-zzzz", beta[0].as_str(), ""] {
        let (s, _, _) = code_post(&e, &pending, &format!("csrf={c}&recovery={bad}")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{bad}");
    }
    let loose = codes[3].to_uppercase().replace('-', "+");
    let (s, _, _) = code_post(&e, &pending, &format!("csrf={c}&recovery={loose}")).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (pending, c) = login_pending(&e, A, "alice", "pw-alice").await;
    let (s, _, _) = code_post(&e, &pending, &format!("csrf={c}&recovery={}", codes[3])).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED); // used up
    assert_eq!(e.state.db.recovery_count(&alpha(&e), "alice").unwrap(), 9);
    assert_eq!(
        e.state
            .db
            .recovery_count(&e.state.registry.by_name("beta").unwrap(), "alice")
            .unwrap(),
        10
    );
}

/// Guessing codes: 5 wrong per account in 15 minutes, all IPs combined; then even the right code is refused (429).
/// Another account of the tenant is not blocked; the Login Flow goes through the login, which carries the limit.
#[tokio::test]
async fn wrong_codes_block_the_account() {
    let e = env();
    let t = alpha(&e);
    enable_totp(&e.state.db, &t, "alice");
    std::fs::create_dir(e.a_root.path().join("bob")).unwrap();
    let h = auth::hash_password("pw-de-bob-123").unwrap();
    e.state.db.user_add(&t, "bob", &h, false).unwrap();
    e.state.db.user_set_password_hash(&t, "bob", &h, false).unwrap();
    enable_totp(&e.state.db, &t, "bob");
    let wrong = format!("{:06}", (code_at(0).parse::<u32>().unwrap() + 500_000) % 1_000_000);
    for i in 0..5 {
        let ip = format!("192.0.2.{i}"); // a new IP each time: the per-IP limit is not what stops it
        let (pending, c) = login_pending(&e, A, "alice", "pw-alice").await;
        let (s, _, _) = call(
            &e.app,
            "POST",
            "/login/code",
            &[A, ("cookie", &pending), ("x-real-ip", &ip)],
            &format!("csrf={c}&code={wrong}"),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{i}");
    }
    let (pending, c) = login_pending(&e, A, "alice", "pw-alice").await;
    let (s, _, _) = call(
        &e.app,
        "POST",
        "/login/code",
        &[A, ("cookie", &pending), ("x-real-ip", "198.51.100.9")],
        &format!("csrf={c}&code={}", code_at(0)),
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let (_, _, body) = call(
        &e.app,
        "POST",
        "/index.php/login/v2",
        &[A, ("x-forwarded-proto", "http")],
        "",
    )
    .await;
    let flow = body
        .split("/index.php/login/v2/flow/")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let form = format!("/index.php/login/v2/flow/{flow}");
    // The Login Flow asks nothing itself: it sends the browser to the login, which is what refuses (429 above).
    let (s, h, _) = call(&e.app, "GET", &form, &[A], "").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h["location"].to_str().unwrap(), format!("/login?next={form}"));
    assert_eq!(call(&e.app, "POST", &form, &[A], "").await.0, StatusCode::SEE_OTHER);
    assert!(e.state.db.token_list(&t, "alice").unwrap().is_empty());
    // bob is not blocked.
    let (pending, c) = login_pending(&e, A, "bob", "pw-de-bob-123").await;
    let (s, _, _) = code_post(&e, &pending, &format!("csrf={c}&code={}", code_at(0))).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
}

/// New recovery codes and turning off need the password and a code; a wrong one changes nothing.
#[tokio::test]
async fn renew_and_turn_off_need_password_and_code() {
    let e = env();
    let t = alpha(&e);
    let old = enable_totp(&e.state.db, &t, "alice");
    let (cookie, csrf) = login2(&e, A, "pw-alice", &code_at(0)).await;
    let c = [A, ("cookie", cookie.as_str())];
    let app = &e.app;
    let post = async |body: String| call(app, "POST", "/web/account/2fa", &c, &body).await;
    for (body, code, msg) in [
        (
            format!("csrf={csrf}&op=codes&password=faux&code={}", code_at(1)),
            StatusCode::UNAUTHORIZED,
            "Wrong password",
        ),
        (
            format!("csrf={csrf}&op=codes&password=pw-alice&code=000000"),
            StatusCode::UNAUTHORIZED,
            "Wrong code",
        ),
        (
            format!("csrf={csrf}&op=codes&password=pw-alice&code={}", code_at(0)),
            StatusCode::UNAUTHORIZED,
            "Wrong code",
        ), // used
        (
            format!("csrf={csrf}&op=codes&password=pw-alice"),
            StatusCode::BAD_REQUEST,
            "Missing",
        ),
        (
            format!("csrf={csrf}&op=nope&password=pw-alice&code={}", code_at(1)),
            StatusCode::BAD_REQUEST,
            "Missing",
        ),
    ] {
        let (s, _, page) = post(body.clone()).await;
        assert!(s == code && page.contains(msg), "{body}: {s} {page}");
    }
    assert_eq!(e.state.db.recovery_count(&t, "alice").unwrap(), 10);
    let (s, _, page) = post(format!("csrf={csrf}&op=codes&password=pw-alice&code={}", code_at(1))).await;
    assert!(
        s == StatusCode::OK && page.contains("the old ones no longer work"),
        "{page}"
    );
    let new: Vec<String> = page
        .split("<li><code>")
        .skip(1)
        .map(|x| x.split('<').next().unwrap().to_owned())
        .collect();
    assert_eq!(new.len(), 10);
    let (pending, pc) = login_pending(&e, A, "alice", "pw-alice").await;
    assert_eq!(
        code_post(&e, &pending, &format!("csrf={pc}&recovery={}", old[0]))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        code_post(&e, &pending, &format!("csrf={pc}&recovery={}", new[0]))
            .await
            .0,
        StatusCode::SEE_OTHER
    );
    // Off, with a recovery code (phone lost): the next sign-in asks the password only.
    let (s, _, page) = post(format!("csrf={csrf}&op=off&password=pw-alice&code={}", new[1])).await;
    assert!(
        s == StatusCode::OK && page.contains("Two-step verification is off."),
        "{page}"
    );
    assert_eq!(e.state.db.totp_get(&t, "alice").unwrap(), Some((None, 0)));
    assert_eq!(e.state.db.recovery_count(&t, "alice").unwrap(), 0);
    login(&e, A, "pw-alice").await;
    let (s, _, _) = post(format!("csrf={csrf}&op=off&password=pw-alice&code={}", new[2])).await;
    assert_eq!(s, StatusCode::CONFLICT); // already off
}

/// Few recovery codes left: the account page says so.
#[tokio::test]
async fn few_recovery_codes_left_is_flagged() {
    let e = env();
    let t = alpha(&e);
    let codes = enable_totp(&e.state.db, &t, "alice");
    let (cookie, _) = login2(&e, A, "pw-alice", &code_at(0)).await;
    for (i, c) in codes.iter().take(7).enumerate() {
        let m = totp::recovery_mac(&t, "alice", &totp::parse_recovery(c).unwrap());
        assert!(e.state.db.recovery_use(&t, "alice", &m).unwrap(), "{i}");
    }
    let page = call(&e.app, "GET", "/web/account", &[A, ("cookie", cookie.as_str())], "")
        .await
        .2;
    assert!(!page.contains("Few recovery codes left"), "3 left: {page}");
    let m = totp::recovery_mac(&t, "alice", &totp::parse_recovery(&codes[7]).unwrap());
    e.state.db.recovery_use(&t, "alice", &m).unwrap();
    let page = call(&e.app, "GET", "/web/account", &[A, ("cookie", cookie.as_str())], "")
        .await
        .2;
    assert!(
        page.contains("Few recovery codes left") && page.contains("2 recovery codes left"),
        "{page}"
    );
}

/// Tenant `required`: an account without it is held on the setup page (every page, form, WebDAV, Login Flow), sets
/// it up there, sees its recovery codes once, then the application opens; it cannot be turned off. The other tenant
/// (optional) is untouched.
#[tokio::test]
async fn required_tenant_holds_until_set_up() {
    let e = env_mode(TwoFactor::Required);
    let t = alpha(&e);
    let (b_cookie, _) = login(&e, B, "pw-alice").await;
    assert_eq!(
        status(&e.app, "GET", "/web/files/", &[B, ("cookie", b_cookie.as_str())]).await,
        StatusCode::OK
    );
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    for path in ["/web/files/", "/web/account", "/web/welcome", "/login", "/login/code"] {
        let (s, h, _) = call(&e.app, "GET", path, &c, "").await;
        assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/2fa-setup"), "{path}");
    }
    let (s, h, _) = call(
        &e.app,
        "POST",
        "/web/account/tokens",
        &c,
        &format!("csrf={csrf}&label=x"),
    )
    .await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/2fa-setup"));
    let dav = [
        A,
        ("cookie", cookie.as_str()),
        ("x-csrf-token", csrf.as_str()),
        ("depth", "0"),
    ];
    assert_eq!(
        status(&e.app, "PROPFIND", "/web/dav/", &dav).await,
        StatusCode::UNAUTHORIZED
    );
    let (_, _, body) = call(
        &e.app,
        "POST",
        "/index.php/login/v2",
        &[A, ("x-forwarded-proto", "http")],
        "",
    )
    .await;
    let flow = body
        .split("/index.php/login/v2/flow/")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    // The Login Flow sends the browser to the setup page: no device before it.
    let (s, h, _) = call(&e.app, "GET", &format!("/index.php/login/v2/flow/{flow}"), &c, "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/2fa-setup"));
    assert_eq!(
        call(&e.app, "POST", &format!("/index.php/login/v2/flow/{flow}"), &c, "")
            .await
            .0,
        StatusCode::SEE_OTHER
    );
    assert!(e.state.db.token_list(&t, "alice").unwrap().is_empty());
    // The setup page.
    let secret = totp::setup_secret(&t, cookie.split_once('=').unwrap().1);
    let (s, _, page) = call(&e.app, "GET", "/web/2fa-setup", &c, "").await;
    assert!(s == StatusCode::OK && page.contains("<svg") && page.contains(&totp::grouped(&totp::base32(&secret))));
    let right = format!("{:06}", totp::hotp(&secret, totp::step(totp::now())));
    let (s, _, _) = call(&e.app, "POST", "/web/2fa-setup", &c, &format!("csrf=faux&code={right}")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, page) = call(
        &e.app,
        "POST",
        "/web/2fa-setup",
        &c,
        &format!("csrf={csrf}&code=000000"),
    )
    .await;
    assert!(s == StatusCode::BAD_REQUEST && page.contains("Wrong code"), "{page}");
    assert_eq!(e.state.db.totp_get(&t, "alice").unwrap(), Some((None, 0)));
    let (s, _, page) = call(
        &e.app,
        "POST",
        "/web/2fa-setup",
        &c,
        &format!("csrf={csrf}&code={right}"),
    )
    .await;
    assert!(
        s == StatusCode::OK && page.matches("<li><code>").count() == 10 && page.contains("href=\"/web/files/\""),
        "{page}"
    );
    assert_eq!(status(&e.app, "GET", "/web/files/", &c).await, StatusCode::OK);
    let (s, h, _) = call(&e.app, "GET", "/web/2fa-setup", &c, "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/files/"));
    // Cannot be turned off; the account page says why.
    let page = call(&e.app, "GET", "/web/account", &c, "").await.2;
    assert!(
        page.contains("cannot be turned off") && !page.contains("value=\"off\""),
        "{page}"
    );
    e.state.db.totp_rewind(&t, "alice"); // the setup used the current step
    let now_code = format!("{:06}", totp::hotp(&secret, totp::step(totp::now())));
    let body = format!("csrf={csrf}&op=off&password=pw-alice&code={now_code}");
    let (s, _, page) = call(&e.app, "POST", "/web/account/2fa", &c, &body).await;
    assert!(
        s == StatusCode::FORBIDDEN && page.contains("cannot be turned off"),
        "{page}"
    );
    assert!(e.state.db.totp_get(&t, "alice").unwrap().unwrap().0.is_some());
    assert_eq!(
        status(&e.app, "GET", "/web/files/", &[B, ("cookie", b_cookie.as_str())]).await,
        StatusCode::OK
    );
}

/// Gates in order: the code first, then the password set by the administrator; with a required tenant, the
/// password first, then the setup.
#[tokio::test]
async fn gates_come_in_order() {
    let e = env();
    let t = alpha(&e);
    enable_totp(&e.state.db, &t, "alice");
    crate::admin::user_passwd(&e.state.db, &t, "alice", Some("donne-par-l-admin"), 12, true)
        .unwrap()
        .unwrap();
    // The administrator's reset kept two-step verification: the code is asked first.
    let (cookie, _) = login2(&e, A, "donne-par-l-admin", &code_at(0)).await;
    let (s, h, _) = call(&e.app, "GET", "/web/files/", &[A, ("cookie", cookie.as_str())], "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/welcome"));
    let e = env_mode(TwoFactor::Required);
    let t = alpha(&e);
    crate::admin::user_passwd(&e.state.db, &t, "alice", Some("donne-par-l-admin"), 12, true)
        .unwrap()
        .unwrap();
    let (cookie, csrf) = login(&e, A, "donne-par-l-admin").await;
    let c = [A, ("cookie", cookie.as_str())];
    let (s, h, _) = call(&e.app, "GET", "/web/files/", &c, "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/welcome"));
    let (s, h, _) = call(&e.app, "GET", "/web/2fa-setup", &c, "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/welcome")); // not the setup yet
    let body = format!("csrf={csrf}&current=donne-par-l-admin&new=mon-secret-a-moi&again=mon-secret-a-moi");
    assert_eq!(call(&e.app, "POST", "/web/welcome", &c, &body).await.0, StatusCode::OK);
    let (cookie, _) = login(&e, A, "mon-secret-a-moi").await;
    let (s, h, _) = call(&e.app, "GET", "/web/files/", &[A, ("cookie", cookie.as_str())], "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/2fa-setup"));
}

/// Login Flow (desktop and mobile clients) with two-step verification: the code is asked by the **login** page, not
/// by the flow page; a pending session is sent back to the code page, a full one connects the device without
/// asking anything else. This is what makes the flow usable by an account that signed in through a provider.
#[tokio::test]
async fn login_flow_goes_through_the_login() {
    let e = env();
    let t = alpha(&e);
    enable_totp(&e.state.db, &t, "alice");
    let flow = || async {
        let (_, _, body) = call(
            &e.app,
            "POST",
            "/index.php/login/v2",
            &[A, ("x-forwarded-proto", "http")],
            "",
        )
        .await;
        let f = body
            .split("/index.php/login/v2/flow/")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned();
        format!("/index.php/login/v2/flow/{f}")
    };
    let f = flow().await;
    // No session: to the login, with the flow as the return address (allowed by `after_login`).
    let (s, h, _) = call(&e.app, "GET", &f, &[A], "").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(location(&h), format!("/login?next={f}"));
    // A pending session (password given, code not yet) goes to the code page, which brings it back here.
    let (pending, _) = login_pending(&e, A, "alice", "pw-alice").await;
    let (s, h, _) = call(&e.app, "GET", &f, &[A, ("cookie", &pending)], "").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(location(&h), format!("/login/code?next={f}"));
    assert_eq!(
        call(&e.app, "POST", &f, &[A, ("cookie", &pending)], "").await.0,
        StatusCode::SEE_OTHER
    );
    assert!(e.state.db.token_list(&t, "alice").unwrap().is_empty());
    // Full session (code given): the password is asked again; one device; a second flow gives a second device.
    let (cookie, _) = login2(&e, A, "pw-alice", &code_at(0)).await;
    let c = [A, ("cookie", cookie.as_str())];
    let (s, _, page) = call(&e.app, "GET", &f, &c, "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains("Authorize this client") && page.contains("name=\"password\""),
        "{page}"
    );
    assert_eq!(call(&e.app, "POST", &f, &c, "").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        call(&e.app, "POST", &f, &c, "password=pw-alice").await.0,
        StatusCode::OK
    );
    let g = flow().await;
    assert_eq!(
        call(&e.app, "POST", &g, &c, "password=pw-alice").await.0,
        StatusCode::OK
    );
    assert_eq!(e.state.db.token_list(&t, "alice").unwrap().len(), 2);
    // A confirmed flow is single use: the same URL answers 404.
    assert_eq!(status(&e.app, "GET", &f, &c).await, StatusCode::NOT_FOUND);
}

/// Tenant `required`, account without two-step verification: the login holds it on the setup page, and the Login
/// Flow sends the browser there instead of connecting the device.
#[tokio::test]
async fn required_tenant_login_flow_waits_for_the_setup() {
    let e = env_mode(TwoFactor::Required);
    let t = alpha(&e);
    let (_, _, body) = call(
        &e.app,
        "POST",
        "/index.php/login/v2",
        &[A, ("x-forwarded-proto", "http")],
        "",
    )
    .await;
    let f = body
        .split("/index.php/login/v2/flow/")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let f = format!("/index.php/login/v2/flow/{f}");
    // alice has no second step yet and the tenant requires it: her session waits on the setup page.
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let (s, h, _) = call(&e.app, "GET", &f, &[A, ("cookie", &cookie)], "").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(location(&h), "/web/2fa-setup");
    assert_eq!(
        call(&e.app, "POST", &f, &[A, ("cookie", &cookie)], "").await.0,
        StatusCode::SEE_OTHER
    );
    assert!(e.state.db.token_list(&t, "alice").unwrap().is_empty());
}

/// Tenant `off`: not offered (no section, no setup); an account that already has it keeps it, is asked the code, and
/// may turn it off.
#[tokio::test]
async fn off_tenant_offers_nothing_but_keeps_existing() {
    let e = env_mode(TwoFactor::Off);
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let page = call(&e.app, "GET", "/web/account", &c, "").await.2;
    assert!(!page.contains("id=\"double\""), "{page}");
    for p in ["/web/account/2fa/start", "/web/account/2fa/confirm"] {
        assert_eq!(
            call(&e.app, "POST", p, &c, &format!("csrf={csrf}&code=123456")).await.0,
            StatusCode::FORBIDDEN,
            "{p}"
        );
    }
    enable_totp(&e.state.db, &alpha(&e), "alice");
    let (cookie, csrf) = login2(&e, A, "pw-alice", &code_at(0)).await;
    let c = [A, ("cookie", cookie.as_str())];
    let page = call(&e.app, "GET", "/web/account", &c, "").await.2;
    assert!(
        page.contains("id=\"double\"") && page.contains("value=\"off\""),
        "{page}"
    );
    let body = format!("csrf={csrf}&op=off&password=pw-alice&code={}", code_at(1));
    assert_eq!(
        call(&e.app, "POST", "/web/account/2fa", &c, &body).await.0,
        StatusCode::OK
    );
    login(&e, A, "pw-alice").await;
}

/// `beastbox user 2fa-reset`: two-step verification gone and sessions ended; signing in asks the password only
/// (optional tenant) or the setup again (required tenant). The other tenant's alice keeps hers.
#[tokio::test]
async fn admin_reset() {
    let e = env();
    let (t, b) = (alpha(&e), e.state.registry.by_name("beta").unwrap());
    enable_totp(&e.state.db, &t, "alice");
    enable_totp(&e.state.db, &b, "alice");
    let (cookie, _) = login2(&e, A, "pw-alice", &code_at(0)).await;
    assert!(crate::admin::user_totp_reset(&e.state.db, &t, "alice").unwrap());
    assert!(!crate::admin::user_totp_reset(&e.state.db, &t, "alice").unwrap()); // already off
    assert!(crate::admin::user_totp_reset(&e.state.db, &t, "nobody").is_err());
    let (s, h, _) = call(&e.app, "GET", "/web/files/", &[A, ("cookie", cookie.as_str())], "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login"));
    login(&e, A, "pw-alice").await;
    assert!(e.state.db.totp_get(&b, "alice").unwrap().unwrap().0.is_some());
    login_pending(&e, B, "alice", "pw-alice").await;
    let e = env_mode(TwoFactor::Required);
    let t = alpha(&e);
    enable_totp(&e.state.db, &t, "alice");
    crate::admin::user_totp_reset(&e.state.db, &t, "alice").unwrap();
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let (s, h, _) = call(&e.app, "GET", "/web/files/", &[A, ("cookie", cookie.as_str())], "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/2fa-setup"));
}

/// A waiting session can cancel (sign out): its row is gone, and a forged token cancels nothing.
#[tokio::test]
async fn waiting_session_can_cancel() {
    let e = env();
    enable_totp(&e.state.db, &alpha(&e), "alice");
    let (pending, c) = login_pending(&e, A, "alice", "pw-alice").await;
    let p = [A, ("cookie", pending.as_str())];
    let page = call(&e.app, "GET", "/login/code", &p, "").await.2;
    assert!(page.contains("action=\"/logout\""), "{page}");
    call(&e.app, "POST", "/logout", &p, "csrf=faux").await;
    assert_eq!(status(&e.app, "GET", "/login/code", &p).await, StatusCode::OK);
    call(&e.app, "POST", "/logout", &p, &format!("csrf={c}")).await;
    let (s, h, _) = call(&e.app, "GET", "/login/code", &p, "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login"));
}

/// Without any session, the new pages send to the login and change nothing.
#[tokio::test]
async fn new_pages_without_session() {
    let e = env();
    for (m, p) in [
        ("GET", "/login/code"),
        ("POST", "/login/code"),
        ("GET", "/web/2fa-setup"),
        ("POST", "/web/2fa-setup"),
        ("POST", "/web/account/2fa"),
        ("POST", "/web/account/2fa/start"),
        ("POST", "/web/account/2fa/confirm"),
    ] {
        let (s, h, _) = call(&e.app, m, p, &[A], "csrf=x&code=123456").await;
        assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login"), "{m} {p}");
    }
    assert_eq!(e.state.db.totp_get(&alpha(&e), "alice").unwrap(), Some((None, 0)));
}
