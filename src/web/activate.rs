//! Activation links (`/activate/<token>`, SURFACE.md): the only way an account gets its password from the
//! administrator (`user add`, `user passwd`) and, on a tenant that requires it, binds its first phone (`user add`,
//! `user passwd`, `user 2fa-reset`). The link is the administrator's proof; an account that already has a password
//! must give it too. Reading the page consumes nothing (a messaging app may open the link for a preview); a submission
//! is checked first, then one transaction consumes the link and applies everything (`db::activate`).

use super::{App, Base, ClientIp, blocking, form_field, html, lang, not_found, too_many, totp_qr};
use crate::auth::{self, totp};
use crate::i18n::Lang;
use crate::tenant::TenantCtx;
use askama::Template;
use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use std::time::Duration;

/// What the link asks, from the account's state and the tenant's rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Needs {
    /// No password yet (new or reset account, not bound to a provider): choose one.
    choose: bool,
    /// A password already: give it (the link alone does not prove the owner).
    current: bool,
    /// The tenant requires two-step verification and the account has none: bind the phone.
    phone: bool,
}

fn needs(t: &TenantCtx, app: &App, row: &crate::db::ActivationRow) -> Needs {
    let required = app.settings.two_factor(t.name()) == crate::config::TwoFactor::Required;
    Needs {
        choose: !row.has_password && !row.linked,
        current: row.has_password,
        phone: required && !row.totp && !t.provider_second_factor(),
    }
}

#[derive(Template)]
#[template(path = "activate.html")]
struct Page<'a> {
    lang: Lang,
    /// The link's token (64 hexadecimal characters, checked): where the form posts.
    token: &'a str,
    user: &'a str,
    choose: bool,
    current: bool,
    phone: bool,
    /// QR code (inline SVG, nothing from the user in it) and the key in groups of 4.
    qr: String,
    key: String,
    min_password: usize,
    message: &'a str,
    /// Recovery codes, shown once after a successful activation.
    recovery: Vec<String>,
}

/// Private page: no cache (`html`), not indexed.
fn private(mut r: Response) -> Response {
    r.headers_mut()
        .insert("x-robots-tag", HeaderValue::from_static("noindex, nofollow"));
    r
}

/// Every dead link (malformed, unknown, used, expired, replaced, other tenant, account disabled): the same answer.
fn dead(lang: Lang) -> Response {
    private(not_found(lang))
}

/// The live link `token` names, if any. Malformed: none, without a lookup.
async fn find(app: &Arc<App>, t: &TenantCtx, token: &str) -> Option<crate::db::ActivationRow> {
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let (app2, t2, mac) = (app.clone(), t.clone(), t.mac(token.as_bytes()));
    blocking(move || app2.db.activation_find(&t2, &mac, crate::db::now_secs()))
        .await
        .ok()?
        .ok()?
}

fn render(code: StatusCode, p: &Page<'_>) -> Response {
    private(html(code, p))
}

fn page_for<'a>(
    app: &App,
    t: &TenantCtx,
    lang: Lang,
    origin: &Base,
    (row, n, token): (&'a crate::db::ActivationRow, Needs, &'a str),
    message: &'a str,
) -> Page<'a> {
    let (qr, key) = if n.phone {
        totp_qr(lang, origin, &row.user, &totp::setup_secret(t, token))
    } else {
        Default::default()
    };
    Page {
        lang,
        token,
        user: &row.user,
        choose: n.choose,
        current: n.current,
        phone: n.phone,
        qr,
        key,
        min_password: app.settings.min_password,
        message,
        recovery: Vec::new(),
    }
}

/// `GET /activate/{token}`: what the link asks. Consumes nothing.
pub(super) async fn show(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(origin): Extension<Base>,
    Path(token): Path<String>,
    h: HeaderMap,
) -> Response {
    let lang = lang(&app, &h);
    let Some(row) = find(&app, &t, &token).await else {
        return dead(lang);
    };
    let n = needs(&t, &app, &row);
    render(
        StatusCode::OK,
        &page_for(&app, &t, lang, &origin, (&row, n, &token), ""),
    )
}

/// `POST /activate/{token}`: checks everything the link asks (wrong current password or code: a failure counted per
/// address, the link kept), then consumes it and applies it in one transaction. Without a phone to show the recovery
/// codes for: to the sign-in page.
pub(super) async fn submit(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(origin): Extension<Base>,
    Extension(ip): Extension<ClientIp>,
    Path(token): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = lang(&app, &h);
    if super::from_another_site(&h, &origin) {
        return private(super::other_site_refused(lang));
    }
    let Some(row) = find(&app, &t, &token).await else {
        return dead(lang);
    };
    let n = needs(&t, &app, &row);
    let mac = t.mac(token.as_bytes());
    let link_key = {
        use std::fmt::Write;
        let mut s = String::with_capacity(4 + 64);
        s.push_str("act:");
        for b in mac {
            let _ = write!(s, "{b:02x}");
        }
        s
    };
    let again = |code: StatusCode, m: &str| render(code, &page_for(&app, &t, lang, &origin, (&row, n, &token), m));
    // Per-link (not per-account) password limit: an anonymous /login spammer cannot lock out an admin activation link,
    // while someone holding the 256-bit link still cannot brute-force the current password across IPs.
    if t.failures().ip_blocked(ip.0) || (n.current && t.failures().link_blocked(&link_key)) {
        return too_many();
    }
    let field = |k: &str| form_field(&body, k).unwrap_or_default();
    let new = field("new");
    if n.choose {
        if new != field("again") {
            return again(
                StatusCode::BAD_REQUEST,
                lang.t("The two new passwords differ: nothing was changed."),
            );
        }
        let min = app.settings.min_password;
        if let Some(w) = crate::admin::weakness(&new, &row.user, t.name(), min) {
            return again(StatusCode::BAD_REQUEST, lang.t(w.message()));
        }
    }
    let now = crate::db::now_secs();
    let secret = totp::setup_secret(&t, &token);
    let step = if n.phone {
        let ok = totp::parse_code(&field("code"))
            .and_then(|c| totp::check(&secret, c, totp::step(u64::try_from(now).unwrap_or(0)), 0));
        let Some(step) = ok else {
            t.failures().record_ip(ip.0);
            return again(
                StatusCode::BAD_REQUEST,
                lang.t("Wrong code: check that the phone is on time and try again."),
            );
        };
        Some(step)
    } else {
        None
    };
    let Ok(Ok(_permit)) = tokio::time::timeout(Duration::from_secs(2), app.argon.acquire()).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "5")]).into_response();
    };
    let (app2, t2, user) = (app.clone(), t.clone(), row.user.clone());
    let current = field("current");
    let done = blocking(move || -> crate::Result<Result<Option<Vec<String>>, ()>> {
        let (db, t) = (&app2.db, &t2);
        if n.current && auth::verify_human(db, t, &user, &current, &app2.dummy_hash)?.is_none() {
            return Ok(Err(()));
        }
        let hash = if n.choose {
            Some(auth::hash_password(&new)?)
        } else {
            None
        };
        let codes = if n.phone {
            totp::new_recovery_codes()?
        } else {
            Vec::new()
        };
        let macs: Vec<[u8; 32]> = codes
            .iter()
            .filter_map(|c| totp::parse_recovery(c))
            .map(|c| totp::recovery_mac(t, &user, &c))
            .collect();
        let sealed = if n.phone {
            totp::seal(t, &user, &secret)?
        } else {
            Vec::new()
        };
        let what = crate::db::Activate {
            password_hash: hash.as_deref(),
            totp: step.map(|st| (sealed.as_slice(), st, macs.as_slice())),
        };
        Ok(Ok(db.activate(t, &mac, now, &what)?.map(|_| codes)))
    })
    .await;
    match done {
        Ok(Ok(Ok(Some(codes)))) => {
            tracing::info!(tenant = t.name(), user = row.user, "account activated");
            if codes.is_empty() {
                return private(super::see_other("/login"));
            }
            let mut p = page_for(&app, &t, lang, &origin, (&row, n, &token), "");
            p.recovery = codes;
            render(StatusCode::OK, &p)
        }
        // Spent meanwhile (another submission won), or disabled meanwhile.
        Ok(Ok(Ok(None))) => dead(lang),
        Ok(Ok(Err(()))) => {
            tracing::warn!(tenant = t.name(), ip = %ip.0, user = row.user, "activation: wrong current password");
            t.failures().record_ip(ip.0);
            t.failures().record_link(&link_key);
            again(
                StatusCode::UNAUTHORIZED,
                lang.t("Wrong current password: nothing was changed."),
            )
        }
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
