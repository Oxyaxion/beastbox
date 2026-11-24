//! Activation links (`/activate/<token>`, `auth::activation_issue`): an account gets its password and, on a tenant that
//! requires it, its phone, from a single-use link the administrator gives (`user add`, `user passwd`, `user 2fa-reset`)
//! — never from a password sent to it, and never from its password alone. Each test checks the other tenant and the
//! cases a real link meets: a messaging app opening it for a preview, two submissions at once, a link used, expired,
//! replaced, from another tenant, an account disabled meanwhile.

use super::tests::login;
use crate::auth::{self, totp};
use crate::config::TwoFactor;
use crate::http::tests::{A, Env, call, env_with};
use crate::tenant::TenantCtx;
use axum::http::{HeaderMap, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

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

/// A new account without a password (as `user add` now makes it), its folder ready.
fn new_account(e: &Env, name: &str) {
    let dir = e.a_root.path().join(name);
    std::fs::create_dir(&dir).unwrap();
    crate::fs::Root::open_dir(&dir).unwrap().ensure_layout().unwrap();
    e.state.db.user_add_oidc(&alpha(e), name, false).unwrap();
}

/// A fresh link for `name` in alpha: (path, token).
fn link(e: &Env, name: &str) -> (String, String) {
    let token = auth::activation_issue(&e.state.db, &alpha(e), name, crate::db::now_secs()).unwrap();
    (format!("/activate/{token}"), token)
}

fn form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{k}={}", utf8_percent_encode(v, NON_ALPHANUMERIC)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The TOTP code the activation page shows for this link (its secret is derived from the link), at the current step.
fn code_for(e: &Env, token: &str) -> String {
    let s = totp::setup_secret(&alpha(e), token);
    format!("{:06}", totp::hotp(&s, totp::step(totp::now())))
}

/// A messaging app opens the link for its preview, the person opens it again: nothing is consumed by reading it. The
/// page is private (no cache, not indexed, strict CSP) and asks a new password twice, nothing else.
#[tokio::test]
async fn opening_the_link_consumes_nothing() {
    let e = env_with(Default::default());
    new_account(&e, "carol");
    let (path, _) = link(&e, "carol");
    for _ in 0..3 {
        let (s, h, page) = call(&e.app, "GET", &path, &[A], "").await;
        assert_eq!(s, StatusCode::OK, "{page}");
        assert_eq!(h["cache-control"], "no-store");
        assert_eq!(h["x-robots-tag"], "noindex, nofollow");
        assert!(
            h["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("default-src 'none'")
        );
        assert!(page.contains("name=\"new\"") && page.contains("name=\"again\""));
        assert!(!page.contains("name=\"current\"") && !page.contains("name=\"code\""));
    }
    let body = form(&[("new", "mon-propre-secret-9"), ("again", "mon-propre-secret-9")]);
    let (s, h, _) = call(&e.app, "POST", &path, &[A], &body).await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login"));
}

/// A new account: nothing opens it before the link (no password to try); the link sets the password once — a mismatch
/// or a weak one changes nothing and keeps the link; then the link is spent and the password signs in.
#[tokio::test]
async fn new_account_chooses_its_password_once() {
    let e = env_with(Default::default());
    new_account(&e, "carol");
    let (s, _, _) = call(&e.app, "POST", "/login", &[A], "user=carol&password=").await;
    assert_ne!(s, StatusCode::SEE_OTHER, "an account to activate signs in with nothing");
    let (path, _) = link(&e, "carol");
    for (new, again) in [
        ("mon-propre-secret-9", "autre-secret-9999"),
        ("court", "court"),
        ("carol-secret-123", "carol-secret-123"),
        ("", ""),
    ] {
        let (s, _, _) = call(&e.app, "POST", &path, &[A], &form(&[("new", new), ("again", again)])).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{new}/{again}");
    }
    assert_eq!(e.state.db.user_password_hash(&alpha(&e), "carol").unwrap(), None);
    let body = form(&[("new", "mon-propre-secret-9"), ("again", "mon-propre-secret-9")]);
    let (s, h, _) = call(&e.app, "POST", &path, &[A], &body).await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login"));
    let (s, h, _) = call(
        &e.app,
        "POST",
        "/login",
        &[A],
        "user=carol&password=mon-propre-secret-9",
    )
    .await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/files/"));
    // Spent: reading or posting it again finds nothing, the password stays.
    assert_eq!(call(&e.app, "GET", &path, &[A], "").await.0, StatusCode::NOT_FOUND);
    let other = form(&[("new", "pirate-secret-777"), ("again", "pirate-secret-777")]);
    assert_eq!(call(&e.app, "POST", &path, &[A], &other).await.0, StatusCode::NOT_FOUND);
    let (s, _, _) = call(&e.app, "POST", "/login", &[A], "user=carol&password=pirate-secret-777").await;
    assert_ne!(s, StatusCode::SEE_OTHER);
}

/// A tenant that requires two-step verification: the link binds the phone with the password, in one go. The key is the
/// same on every opening of the link (a reload does not change what the phone scanned); a wrong code changes nothing
/// and keeps the link; the right one shows the recovery codes once; the sign-in then asks the code.
#[tokio::test]
async fn required_tenant_binds_the_phone_with_the_link() {
    let e = env_mode(TwoFactor::Required);
    new_account(&e, "carol");
    let (path, token) = link(&e, "carol");
    let key = |p: &str| {
        p.split("class=\"cle-totp\">")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned()
    };
    let (_, _, first) = call(&e.app, "GET", &path, &[A], "").await;
    let (_, _, again) = call(&e.app, "GET", &path, &[A], "").await;
    assert!(first.contains("<svg role=\"img\"") && first.contains("name=\"code\"") && first.contains("name=\"new\""));
    assert_eq!(key(&first), key(&again));
    let pw = [("new", "mon-propre-secret-9"), ("again", "mon-propre-secret-9")];
    let wrong = (totp::parse_code(&code_for(&e, &token)).unwrap() + 1) % 1_000_000;
    let mut body = pw.to_vec();
    let wrong = format!("{wrong:06}");
    body.push(("code", &wrong));
    let (s, _, _) = call(&e.app, "POST", &path, &[A], &form(&body)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(e.state.db.totp_get(&alpha(&e), "carol").unwrap(), Some((None, 0)));
    let mut body = pw.to_vec();
    let right = code_for(&e, &token);
    body.push(("code", &right));
    let (s, _, page) = call(&e.app, "POST", &path, &[A], &form(&body)).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert_eq!(page.matches("<li><code>").count(), 10, "the recovery codes, once");
    assert!(page.contains("href=\"/login\""));
    // Sign-in: password, then the code page.
    let (s, h, _) = call(
        &e.app,
        "POST",
        "/login",
        &[A],
        "user=carol&password=mon-propre-secret-9",
    )
    .await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/login/code"));
}

/// The cause of the hole, closed: on a tenant that requires two-step verification, an account with a password and no
/// phone yet can no longer bind one with its password alone — the gate page asks for an activation link and the form
/// is refused.
#[tokio::test]
async fn the_password_alone_no_longer_binds_a_phone() {
    let e = env_mode(TwoFactor::Required);
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let (s, _, page) = call(&e.app, "GET", "/web/2fa-setup", &c, "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains("activation link") && !page.contains("name=\"code\""),
        "{page}"
    );
    let s = totp::setup_secret(&alpha(&e), cookie.split_once('=').unwrap().1);
    let code = format!("{:06}", totp::hotp(&s, totp::step(totp::now())));
    let (s, _, _) = call(
        &e.app,
        "POST",
        "/web/2fa-setup",
        &c,
        &format!("csrf={csrf}&code={code}"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(e.state.db.totp_get(&alpha(&e), "alice").unwrap(), Some((None, 0)));
    // Everything else still waits behind the gate.
    let (s, h, _) = call(&e.app, "GET", "/web/files/", &c, "").await;
    assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, "/web/2fa-setup"));
}

/// An account that already has a password (`2fa-reset`, an account from before): the link alone is not enough, it asks
/// An account that already has a password (`user 2fa-reset` on a required tenant): the link is not enough, it asks
/// the current password too — a wrong one changes nothing, keeps the link and counts per address AND per account
/// (10 wrong passwords across addresses lock the account even from a fresh IP, while another account/tenant stays
/// open); right, the phone is bound and the account signs in with password and code.
#[tokio::test]
async fn an_account_with_a_password_proves_it_with_the_link() {
    let e = env_mode(TwoFactor::Required);
    let (path, token) = link(&e, "alice");
    let (_, _, page) = call(&e.app, "GET", &path, &[A], "").await;
    assert!(page.contains("name=\"current\"") && page.contains("name=\"code\"") && !page.contains("name=\"new\""));
    let code = code_for(&e, &token);
    for i in 0..10u32 {
        let ip = format!("192.0.2.{}", i + 1);
        let h = [A, ("x-forwarded-proto", "http"), ("x-real-ip", ip.as_str())];
        let (s, _, _) = call(
            &e.app,
            "POST",
            &path,
            &h,
            &form(&[("current", "faux"), ("code", &code)]),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(e.state.db.totp_get(&alpha(&e), "alice").unwrap(), Some((None, 0)));
    let right = form(&[("current", "pw-alice"), ("code", &code)]);
    // AUTH-04: even from a fresh IP, the account's password lockout refuses the 11th try.
    let fresh = [A, ("x-forwarded-proto", "http"), ("x-real-ip", "198.51.100.9")];
    assert_eq!(
        call(&e.app, "POST", &path, &fresh, &right).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Another account (clean environment for alice) with the right password binds the phone cleanly.
    let e2 = env_mode(TwoFactor::Required);
    let (path2, token2) = link(&e2, "alice");
    let code2 = code_for(&e2, &token2);
    let right2 = form(&[("current", "pw-alice"), ("code", &code2)]);
    let (s, _, _) = call(&e2.app, "POST", &path2, &fresh, &right2).await;
    assert_eq!(s, StatusCode::OK);
    assert!(matches!(
        e2.state.db.totp_get(&alpha(&e2), "alice").unwrap(),
        Some((Some(_), _))
    ));
    assert!(
        e2.state.db.user_password_hash(&alpha(&e2), "alice").unwrap().is_some(),
        "password kept"
    );
}

/// An account bound to single sign-on (no password): the link binds only the phone.
#[tokio::test]
async fn a_single_sign_on_account_binds_only_its_phone() {
    let e = env_mode(TwoFactor::Required);
    new_account(&e, "bob");
    e.state
        .db
        .user_oidc_link(&alpha(&e), "bob", "https://idp.example", "sub-bob")
        .unwrap();
    let (path, token) = link(&e, "bob");
    let (_, _, page) = call(&e.app, "GET", &path, &[A], "").await;
    assert!(page.contains("name=\"code\"") && !page.contains("name=\"new\"") && !page.contains("name=\"current\""));
    let (s, _, _) = call(&e.app, "POST", &path, &[A], &form(&[("code", &code_for(&e, &token))])).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        e.state.db.user_password_hash(&alpha(&e), "bob").unwrap(),
        None,
        "still no password"
    );
    assert!(
        e.state
            .db
            .user_by_oidc(&alpha(&e), "https://idp.example", "sub-bob")
            .unwrap()
            .is_some()
    );
}

/// A link unknown, malformed, used, expired, replaced, or from the other tenant: the same answer, byte for byte (no
/// oracle on what exists).
#[tokio::test]
async fn dead_links_all_look_the_same() {
    let e = env_with(Default::default());
    for n in ["carol", "dave"] {
        new_account(&e, n);
    }
    let (replaced, _) = link(&e, "carol");
    let (live, _) = link(&e, "carol");
    let (expired, _) = link(&e, "dave");
    e.state
        .db
        .exec_for_test("UPDATE activation SET expires_at = 1 WHERE user_id = 'dave';");
    let (_, _, reference) = call(&e.app, "GET", &format!("/activate/{}", "0".repeat(64)), &[A], "").await;
    for (what, path, host) in [
        ("malformed", "/activate/zz".to_owned(), A),
        ("too long", format!("/activate/{}", "a".repeat(65)), A),
        ("replaced", replaced.clone(), A),
        ("expired", expired, A),
        ("other tenant", live.clone(), B),
    ] {
        let (s, _, page) = call(&e.app, "GET", &path, &[host], "").await;
        assert_eq!(
            (s, page.as_str()),
            (StatusCode::NOT_FOUND, reference.as_str()),
            "{what}"
        );
        let body = form(&[("new", "mon-propre-secret-9"), ("again", "mon-propre-secret-9")]);
        let (s, _, page) = call(&e.app, "POST", &path, &[host], &body).await;
        assert_eq!(
            (s, page.as_str()),
            (StatusCode::NOT_FOUND, reference.as_str()),
            "{what}"
        );
    }
    assert_eq!(
        call(&e.app, "GET", &live, &[A], "").await.0,
        StatusCode::OK,
        "the live one still works"
    );
}

/// Two submissions of the same link at once: one account activation, the other finds the link spent.
#[tokio::test]
async fn two_submissions_at_once_activate_once() {
    let e = env_with(Default::default());
    new_account(&e, "carol");
    let (path, _) = link(&e, "carol");
    let one = form(&[("new", "premier-secret-111"), ("again", "premier-secret-111")]);
    let two = form(&[("new", "second-secret-2222"), ("again", "second-secret-2222")]);
    let (a, b) = tokio::join!(
        call(&e.app, "POST", &path, &[A], &one),
        call(&e.app, "POST", &path, &[A], &two)
    );
    let ok = [&a, &b].iter().filter(|r| r.0 == StatusCode::SEE_OTHER).count();
    assert_eq!(ok, 1, "{} {}", a.0, b.0);
    assert!([&a, &b].iter().any(|r| r.0 == StatusCode::NOT_FOUND));
}

/// Activating ends every web session of the account (one opened by whoever knew the old password); a disabled account's
/// link waits (not found) and works again once the account is enabled.
#[tokio::test]
async fn activation_ends_sessions_and_waits_for_a_disabled_account() {
    let e = env_with(Default::default());
    let t = alpha(&e);
    let (old, _) = login(&e, A, "pw-alice").await;
    assert!(e.state.db.user_reset_for_activation(&t, "alice").unwrap());
    let c = [A, ("cookie", old.as_str())];
    let (s, h, _) = call(&e.app, "GET", "/web/files/", &c, "").await;
    assert_eq!(
        (s, location(&h)),
        (StatusCode::SEE_OTHER, "/login"),
        "the reset ends the sessions"
    );
    let (path, _) = link(&e, "alice");
    e.state.db.user_set_active(&t, "alice", false).unwrap();
    assert_eq!(call(&e.app, "GET", &path, &[A], "").await.0, StatusCode::NOT_FOUND);
    e.state.db.user_set_active(&t, "alice", true).unwrap();
    // A session that exists when the link is used (none can be opened without a password: one put in the table
    // stands for it) ends with the activation.
    let secret = "ab".repeat(32);
    e.state
        .db
        .session_add(&t, "alice", &t.mac(secret.as_bytes()), 3600)
        .unwrap();
    let cookie = format!("{}={secret}", crate::web::cookie_name(&e.state, "sess"));
    let c = [A, ("cookie", cookie.as_str())];
    assert_eq!(call(&e.app, "GET", "/web/files/", &c, "").await.0, StatusCode::OK);
    let body = form(&[("new", "mon-propre-secret-9"), ("again", "mon-propre-secret-9")]);
    let (s, _, _) = call(&e.app, "POST", &path, &[A], &body).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (s, h, _) = call(&e.app, "GET", "/web/files/", &c, "").await;
    assert_eq!(
        (s, location(&h)),
        (StatusCode::SEE_OTHER, "/login"),
        "the activation ends it"
    );
    // The other tenant's alice: untouched.
    let (s, _, _) = call(&e.app, "POST", "/login", &[B], "user=alice&password=pw-alice").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
}
