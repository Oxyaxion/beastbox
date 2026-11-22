//! Web interface (§8): server-rendered HTML (askama, automatic escaping), native JavaScript served by the
//! binary, strict CSP without `unsafe-inline`, CSRF on every modifying action, session via a `__Host-` cookie.
//! Surfaces (§0.3): `/login`, `/static/*` and `/s/*` (shares, `share.rs`) are public; every `/web/*` requires a session.

// axum handlers return a ready-made `Response` as the error (redirect, error page): intended idiom.
#![allow(clippy::result_large_err)]

mod activate;
#[cfg(test)]
mod audit;
pub(crate) mod oidc;
pub(crate) mod render;
pub(crate) mod share;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_activation;
#[cfg(test)]
mod tests_edges;
#[cfg(test)]
mod tests_failures;
#[cfg(test)]
mod tests_oidc;
#[cfg(test)]
mod tests_totp;
mod zip;

use crate::auth::{self, UserCtx};
use crate::dav::{self, Serve};
use crate::fs::{Meta, SafePath, normalize_tag};
use crate::http::{App, Base, ClientIp, blocking, form_field, too_many};
use crate::i18n::Lang;
use crate::tenant::TenantCtx;
use askama::Template;
use axum::Extension;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;

/// CSP of the application's pages: no inline script or style, nothing outside the origin.
pub(crate) const APP_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
     media-src 'self'; frame-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
/// Maximum entries shown in a web list (sorted in memory, §0.4).
const LIST_MAX: usize = 10_000;

const APP_CSS: &str = include_str!("../../static/app.css");
const APP_JS: &str = include_str!("../../static/app.js");
/// Chosen theme (local storage), applied before the first render: the only script loaded without `defer`.
const THEME_JS: &str = include_str!("../../static/theme.js");
/// Text files (colouring; editor: Ctrl+S, Markdown preview): loaded only by the pages that show or edit one.
const TEXT_JS: &str = include_str!("../../static/text.js");
/// A form of the edit page: the text (≤ `PREVIEW_MAX`), each byte percent-encoded at worst, and the other fields.
const EDIT_BODY: usize = 3 * render::PREVIEW_MAX + 4096;

/// Icons served by the binary (closed list). File-type icons: one Tabler set (`g-*.svg`) for every view.
fn icon_file(name: &str) -> Option<&'static str> {
    Some(match name {
        "logo.svg" => include_str!("../../static/icons/logo.svg"),
        "g-folder.svg" => include_str!("../../static/icons/g-folder.svg"),
        "g-file.svg" => include_str!("../../static/icons/g-file.svg"),
        "g-text.svg" => include_str!("../../static/icons/g-text.svg"),
        "g-code.svg" => include_str!("../../static/icons/g-code.svg"),
        "g-image.svg" => include_str!("../../static/icons/g-image.svg"),
        "g-video.svg" => include_str!("../../static/icons/g-video.svg"),
        "g-audio.svg" => include_str!("../../static/icons/g-audio.svg"),
        "g-pdf.svg" => include_str!("../../static/icons/g-pdf.svg"),
        "g-archive.svg" => include_str!("../../static/icons/g-archive.svg"),
        "g-doc.svg" => include_str!("../../static/icons/g-doc.svg"),
        "doc.svg" => include_str!("../../static/icons/g-doc.svg"),
        "sheet.svg" => include_str!("../../static/icons/g-sheet.svg"),
        "g-sheet.svg" => include_str!("../../static/icons/g-sheet.svg"),
        "md.svg" => include_str!("../../static/icons/g-md.svg"),
        "g-md.svg" => include_str!("../../static/icons/g-md.svg"),
        "json.svg" => include_str!("../../static/icons/g-json.svg"),
        "g-json.svg" => include_str!("../../static/icons/g-json.svg"),
        "folder.svg" => include_str!("../../static/icons/g-folder.svg"),
        "file.svg" => include_str!("../../static/icons/g-file.svg"),
        "text.svg" => include_str!("../../static/icons/g-text.svg"),
        "code.svg" => include_str!("../../static/icons/g-code.svg"),
        "image.svg" => include_str!("../../static/icons/g-image.svg"),
        "video.svg" => include_str!("../../static/icons/g-video.svg"),
        "audio.svg" => include_str!("../../static/icons/g-audio.svg"),
        "pdf.svg" => include_str!("../../static/icons/g-pdf.svg"),
        "archive.svg" => include_str!("../../static/icons/g-archive.svg"),
        "a-eye.svg" => include_str!("../../static/icons/a-eye.svg"),
        "a-edit.svg" => include_str!("../../static/icons/a-edit.svg"),
        "a-move.svg" => include_str!("../../static/icons/a-move.svg"),
        "a-trash.svg" => include_str!("../../static/icons/a-trash.svg"),
        "a-info.svg" => include_str!("../../static/icons/a-info.svg"),
        "a-warn.svg" => include_str!("../../static/icons/a-warn.svg"),
        "a-chevron.svg" => include_str!("../../static/icons/a-chevron.svg"),
        "a-download.svg" => include_str!("../../static/icons/a-download.svg"),
        "a-plus.svg" => include_str!("../../static/icons/a-plus.svg"),
        "a-upload.svg" => include_str!("../../static/icons/a-upload.svg"),
        "a-copy.svg" => include_str!("../../static/icons/a-copy.svg"),
        "a-check.svg" => include_str!("../../static/icons/a-check.svg"),
        "a-search.svg" => include_str!("../../static/icons/a-search.svg"),
        "a-menu.svg" => include_str!("../../static/icons/a-menu.svg"),
        "d-phone.svg" => include_str!("../../static/icons/d-phone.svg"),
        "d-desktop.svg" => include_str!("../../static/icons/d-desktop.svg"),
        "d-key.svg" => include_str!("../../static/icons/d-key.svg"),
        _ => return None,
    })
}

/// Selection from a list: maximum items per bulk action.
const BULK_MAX: usize = 1000;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/", get(|| async { see_other("/web/files/") }))
        .route("/login", get(login_page).post(login))
        .route(oidc::LOGIN_OIDC, get(oidc::start))
        .route(oidc::CALLBACK, get(oidc::callback))
        .route(LOGIN_CODE, get(login_code).post(login_code_post))
        .route("/logout", post(logout))
        .route(
            "/static/app.css",
            get(|h: HeaderMap| async move { asset("text/css; charset=utf-8", APP_CSS, &h) }),
        )
        .route(
            "/static/app.js",
            get(|h: HeaderMap| async move { asset("text/javascript; charset=utf-8", APP_JS, &h) }),
        )
        .route(
            "/static/theme.js",
            get(|h: HeaderMap| async move { asset("text/javascript; charset=utf-8", THEME_JS, &h) }),
        )
        .route(
            "/static/text.js",
            get(|h: HeaderMap| async move { asset("text/javascript; charset=utf-8", TEXT_JS, &h) }),
        )
        .route(
            "/static/icons/{name}",
            get(|Path(n): Path<String>, h: HeaderMap| async move {
                icon_file(&n).map_or_else(
                    || StatusCode::NOT_FOUND.into_response(),
                    |svg| asset("image/svg+xml", svg, &h),
                )
            }),
        )
        .route("/web/bulk", post(bulk))
        .route("/web/files", get(files_root))
        .route("/web/files/", get(files_root))
        .route("/web/files/{*path}", get(files))
        .route("/web/search", get(search))
        .route("/web/favorites", get(favorites))
        .route("/web/activity", get(activity))
        .route("/web/tree/", get(tree_root))
        .route("/web/tree/{*path}", get(tree))
        .route("/web/view/{*path}", get(view))
        .route(
            "/web/edit/{*path}",
            // The body (a raw `Body`, outside the global 64 KiB limit) is read by `edit_save` itself, after the
            // session, up to `EDIT_BODY`.
            get(edit_page).post(edit_save),
        )
        .route("/web/view", get(view_root))
        .route("/web/view/", get(view_root))
        .route("/web/raw/{*path}", get(raw))
        .route("/web/zip", get(zip_root))
        .route("/web/zip/", get(zip_root))
        .route("/web/zip/{*path}", get(zip))
        .route("/web/dav", any(web_dav_root))
        .route("/web/dav/", any(web_dav_root))
        .route("/web/dav/{*path}", any(web_dav))
        .route("/web/tags", post(tags))
        .route("/web/favorite", post(favorite))
        .route("/web/shares", get(shares_page).post(share_create))
        .route("/web/shares/revoke", post(share_revoke))
        .route("/web/trash", get(trash_page))
        .route("/web/trash/restore", post(trash_restore))
        .route("/web/trash/purge", post(trash_purge))
        .route("/web/trash/empty", post(trash_empty))
        .route(WELCOME, get(welcome).post(welcome_post))
        .route(TOTP_SETUP, get(totp_setup).post(totp_setup_post))
        .route("/activate/{token}", get(activate::show).post(activate::submit))
        .route("/web/account/2fa", post(totp_manage))
        .route("/web/account/2fa/start", post(totp_start))
        .route("/web/account/2fa/confirm", post(totp_confirm))
        .route("/web/account", get(account_page))
        .route("/web/account/language", post(account_language))
        .route("/web/account/password", post(account_password))
        .route("/web/account/tokens", post(token_create))
        .route("/web/account/qr", post(qr_create))
        .route("/web/account/tokens/revoke", post(token_revoke))
        .route("/s/{token}", get(share::page).post(share::password))
        .route("/s/{token}/{*rest}", any(share::rest))
}

// ---------------------------------------------------------------- common responses

pub(crate) fn see_other(to: &str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, to.to_owned())]).into_response()
}

/// Static file, with an ETag of its contents. Scripts and stylesheet: revalidated on every load (`no-cache`), so a new
/// version shows at once after an upgrade (an hour of cache hid a fix), an unchanged one costs a 304. Icons: kept a
/// day without asking, as an icon drawn as a CSS mask is invisible until its answer comes (the logo blinked at every
/// click); a changed icon may show a day late, a new one has a new name.
fn asset(mime: &'static str, body: &'static str, h: &HeaderMap) -> Response {
    // FNV-1a: stable across builds, enough to tell two versions of a file apart (not a security check).
    let hash = body.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |a, b| {
        (a ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    let etag = format!("\"{hash:016x}\"");
    let cache = [
        (
            header::CACHE_CONTROL,
            if mime == "image/svg+xml" {
                "public, max-age=86400"
            } else {
                "no-cache"
            }
            .to_owned(),
        ),
        (header::ETAG, etag.clone()),
    ];
    let seen = h
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim().trim_start_matches("W/") == etag));
    if seen {
        return (StatusCode::NOT_MODIFIED, cache).into_response();
    }
    (StatusCode::OK, [(header::CONTENT_TYPE, mime.to_owned())], cache, body).into_response()
}

/// HTML page: strict CSP, never cached (private content).
pub(crate) fn html(code: StatusCode, t: &impl Template) -> Response {
    match t.render() {
        Ok(body) => (
            code,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CONTENT_SECURITY_POLICY, APP_CSP),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!("template: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "message.html")]
pub(crate) struct Message<'a> {
    lang: Lang,
    title: &'a str,
    text: &'a str,
    back: &'a str,
}

pub(crate) fn message(lang: Lang, code: StatusCode, title: &str, text: &str, back: &str) -> Response {
    html(
        code,
        &Message {
            lang,
            title,
            text,
            back,
        },
    )
}

/// Language of the request (account cookie, then browser), for the pages of this handler.
pub(crate) fn lang(app: &App, h: &HeaderMap) -> Lang {
    Lang::from(h, cookie(h, &cookie_name(app, "lang")))
}

fn not_found(lang: Lang) -> Response {
    message(
        lang,
        StatusCode::NOT_FOUND,
        lang.t("Not found"),
        lang.t("This item does not exist or is no longer accessible."),
        "/web/files/",
    )
}

fn io_page(lang: Lang, e: &io::Error) -> Response {
    match dav::io_status(e) {
        StatusCode::NOT_FOUND => not_found(lang),
        s => message(
            lang,
            s,
            lang.t("Error"),
            lang.t("The operation could not be completed."),
            "/web/files/",
        ),
    }
}

/// Query string parameter (same format as a form).
pub(crate) fn param(q: &Uri, key: &str) -> Option<String> {
    form_field(q.query().unwrap_or("").as_bytes(), key)
}

/// URL path (decoded once by the router) → safe path; `Err` → 404.
fn safe(raw: &str, lang: Lang) -> Result<Option<SafePath>, Response> {
    let t = raw.trim_matches('/');
    if t.is_empty() {
        Ok(None)
    } else {
        SafePath::new(t).map(Some).map_err(|_| not_found(lang))
    }
}

/// Names to try for a new item, first free one wins (never an overwrite, §8): `name`, then `name (2).ext`,
/// `name (3).ext`… up to 99. A file keeps its extension last, and only a real one (`.env`, `a.` and folders keep their
/// whole name before the number: `v1.2 (2)`); a name that no longer fits is refused by `SafePath` and passed over.
pub(crate) fn free_names(name: &str, is_dir: bool) -> impl Iterator<Item = String> + '_ {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !is_dir && !s.is_empty() && !e.is_empty() => (s, format!(".{e}")),
        _ => (name, String::new()),
    };
    std::iter::once(name.to_owned()).chain((2..=99).map(move |i| format!("{stem} ({i}){ext}")))
}

/// Copies or moves `from` (`op`: `Root::copy` or `Root::rename`, never over anything) to the first of `names` that is
/// free, and returns where it went; the source's own name is passed over. `None` if none fits (taken up to 99, too long), or the operation failed
/// (folder into itself, missing source, quota: a partial copy is then in the trash, see `Root::copy`).
fn to_free_name<E>(
    from: &SafePath,
    names: impl Iterator<Item = Result<SafePath, E>>,
    mut op: impl FnMut(&SafePath) -> io::Result<bool>,
) -> Option<SafePath> {
    for t in names {
        let Ok(t) = t else { return None };
        if t == *from {
            continue;
        }
        match op(&t) {
            Ok(_) => return Some(t),
            Err(e) if crate::fs::is_refused(&e, crate::fs::Refused::Precondition) => {}
            Err(_) => return None,
        }
    }
    None
}

/// Page of a folder ("" = root) of the user's space; with `item`, the page holding it, marked and scrolled to.
fn folder_link(folder: &str, item: Option<&str>) -> String {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    let dir = if folder.is_empty() {
        "/web/files/".to_owned()
    } else {
        format!("/web/files/{}/", dav::href("", Some(folder), false))
    };
    match item {
        Some(n) => format!("{dir}?voir={}#vise", utf8_percent_encode(n, NON_ALPHANUMERIC)),
        None => dir,
    }
}

fn enc(p: Option<&SafePath>) -> String {
    dav::href("", p.map(SafePath::as_str), false)
}

// ---------------------------------------------------------------- sessions

pub(crate) fn cookie<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name).then_some(v)
        })
}

/// A cookie's name: `__Host-` prefix (exact host, `Secure`, `Path=/`, §4.1) except on the HTTP test bench (`insecure_cookies`).
pub(crate) fn cookie_name(app: &App, base: &str) -> String {
    if app.settings.insecure_cookies {
        format!("bb{base}")
    } else {
        format!("__Host-bb{base}")
    }
}

pub(crate) fn set_cookie(app: &App, name: &str, value: &str, max_age: i64) -> String {
    let secure = if app.settings.insecure_cookies { "" } else { "; Secure" };
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}")
}

/// User logged in through a web session.
pub(crate) struct WebUser {
    pub u: UserCtx,
    pub csrf: String,
    secret: String,
    /// Where the session must go before anything else (`None`: it opens the application). Only that page and
    /// `/logout` accept it.
    pub(crate) gate: Option<&'static str>,
    /// Two-step verification on for the account.
    totp: bool,
    /// Hidden files (name starting with `.`) shown in the web pages: the `hidden` cookie (`1`), hidden by default.
    pub(crate) show_hidden: bool,
    /// The account has a password, and when this session was opened: what `Reproof` asks again.
    pub(crate) has_password: bool,
    pub(crate) signed_in: i64,
}

/// Second step of the sign-in (two-step verification).
pub(crate) const LOGIN_CODE: &str = "/login/code";
/// Setting up two-step verification required by the tenant.
const TOTP_SETUP: &str = "/web/2fa-setup";

/// The page a session must go through first, in this order: the code (password alone is not enough), then the
/// password set by the administrator, then two-step verification required by the tenant.
fn gate(app: &App, t: &TenantCtx, row: &crate::db::SessionRow) -> Option<&'static str> {
    if row.pending {
        Some(LOGIN_CODE)
    } else if row.must_change {
        Some(WELCOME)
    } else if !row.totp
        && app.settings.two_factor(t.name()) == crate::config::TwoFactor::Required
        && !t.provider_second_factor()
    {
        Some(TOTP_SETUP)
    } else {
        None
    }
}

/// The session, whatever its state: only for the pages behind a gate (code, welcome, setup) and `/logout`.
pub(crate) async fn session_any(app: &Arc<App>, t: &TenantCtx, h: &HeaderMap) -> Option<WebUser> {
    let secret = cookie(h, &cookie_name(app, "sess"))?.to_owned();
    let (app2, t2, s2) = (app.clone(), t.clone(), secret.clone());
    match blocking(move || auth::session_user(&app2.db, &t2, &s2)).await {
        Ok(Ok(Some((u, row)))) => Some(WebUser {
            csrf: auth::csrf_token(t, &secret),
            u,
            secret,
            gate: gate(app, t, &row),
            totp: row.totp,
            show_hidden: cookie(h, &cookie_name(app, "hidden")) == Some("1"),
            has_password: row.has_password,
            signed_in: row.created,
        }),
        Ok(Err(e)) => {
            tracing::error!(tenant = t.name(), "session illisible : {e}");
            None
        }
        _ => None,
    }
}

/// A session that opens the application (no gate left).
async fn session(app: &Arc<App>, t: &TenantCtx, h: &HeaderMap) -> Option<WebUser> {
    session_any(app, t, h).await.filter(|w| w.gate.is_none())
}

/// Session required: otherwise redirect to the login (pages) — the caller chooses — or to its gate.
async fn need(app: &Arc<App>, t: &TenantCtx, h: &HeaderMap) -> Result<WebUser, Response> {
    match session_any(app, t, h).await {
        Some(WebUser { gate: Some(g), .. }) => Err(see_other(g)),
        Some(w) => Ok(w),
        None => Err(see_other("/login")),
    }
}

/// The session behind gate `g`: the session itself, or where to send it (its own gate, the files, the login).
async fn need_gate(app: &Arc<App>, t: &TenantCtx, h: &HeaderMap, g: &str) -> Result<WebUser, Response> {
    match session_any(app, t, h).await {
        Some(w) if w.gate == Some(g) => Ok(w),
        Some(WebUser { gate: Some(other), .. }) => Err(see_other(other)),
        Some(_) => Err(see_other("/web/files/")),
        None => Err(see_other("/login")),
    }
}

/// Modifying form: session and CSRF token required (§8).
/// What an action that hands out lasting access (an app password: Login Flow, the mobile app's QR code, the Account page)
/// asks again besides the session, so that a stolen or borrowed session, or a phished click, is not enough: the
/// password when the account has one; otherwise (single sign-on) a code when two-step verification is on; otherwise a
/// sign-in of less than `FRESH_SIGN_IN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reproof {
    Password,
    Code,
    FreshSignIn,
}

/// How recent a sign-in must be when the account has neither a password nor two-step verification.
pub(crate) const FRESH_SIGN_IN: i64 = 5 * 60;

impl WebUser {
    /// What this session's account is asked again (`Reproof`).
    pub(crate) fn reproof(&self) -> Reproof {
        Reproof::of(self.has_password, self.totp)
    }
}

impl Reproof {
    pub(crate) fn of(has_password: bool, totp: bool) -> Self {
        match (has_password, totp) {
            (true, _) => Reproof::Password,
            (false, true) => Reproof::Code,
            (false, false) => Reproof::FreshSignIn,
        }
    }

    /// The form field it reads ("" when nothing is typed).
    pub(crate) fn field(self) -> &'static str {
        match self {
            Reproof::Password => "password",
            Reproof::Code => "code",
            Reproof::FreshSignIn => "",
        }
    }
}

/// Why a `Reproof` was not given.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unproven {
    /// Missing or wrong (a wrong one counts as an authentication failure).
    Wrong,
    TooMany,
    /// The sign-in is too old: sign in again (`sign_in_again`).
    Stale,
    Busy,
}

/// Checks the `Reproof` of `w` against the form `body` (`now`: Unix time). Failures count like a sign-in's: per IP, and
/// per account for a code.
pub(crate) async fn reproof(app: &Arc<App>, w: &WebUser, ip: ClientIp, body: &[u8], now: i64) -> Result<(), Unproven> {
    let t = w.u.tenant().clone();
    let kind = w.reproof();
    if kind == Reproof::FreshSignIn {
        return if now.saturating_sub(w.signed_in) <= FRESH_SIGN_IN {
            Ok(())
        } else {
            Err(Unproven::Stale)
        };
    }
    let Some(given) = form_field(body, kind.field()).filter(|g| !g.is_empty()) else {
        return Err(Unproven::Wrong);
    };
    if t.failures().ip_blocked(ip.0) || (kind == Reproof::Code && t.failures().code_blocked(w.u.user())) {
        return Err(Unproven::TooMany);
    }
    let _permit = match kind {
        Reproof::Password => match tokio::time::timeout(Duration::from_secs(2), app.argon.acquire()).await {
            Ok(Ok(p)) => Some(p),
            _ => return Err(Unproven::Busy),
        },
        _ => None,
    };
    let (app2, u) = (app.clone(), w.u.clone());
    let ok = blocking(move || -> crate::Result<bool> {
        let (db, t, user) = (&app2.db, u.tenant(), u.user());
        Ok(match kind {
            Reproof::Password => auth::verify_human(db, t, user, &given, &app2.dummy_hash)?.is_some(),
            _ => auth::verify_second(db, t, user, &given, u64::try_from(now).unwrap_or(0))? != auth::Second::Wrong,
        })
    })
    .await;
    match ok {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => {
            tracing::warn!(tenant = t.name(), ip = %ip.0, user = w.u.user(), "proof asked again: wrong");
            t.failures().record_ip(ip.0);
            if kind == Reproof::Code {
                t.failures().record_code(w.u.user());
            }
            Err(Unproven::Wrong)
        }
        _ => Err(Unproven::Busy),
    }
}

/// The sign-in is too old for what was asked: this session ends, and the sign-in page comes back to `next`.
pub(crate) async fn sign_in_again(app: &Arc<App>, w: &WebUser, next: &str) -> Response {
    let (app2, t, secret) = (app.clone(), w.u.tenant().clone(), w.secret.clone());
    let _ = blocking(move || auth::end_session(&app2.db, &t, &secret)).await;
    let c = set_cookie(app, &cookie_name(app, "sess"), "", 0);
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, format!("/login?next={next}")),
            (header::SET_COOKIE, c),
        ],
    )
        .into_response()
}

/// The CSRF token received (form field or header) is the session's, compared in constant time.
pub(crate) fn csrf_ok(given: Option<&str>, expected: &str) -> bool {
    given.is_some_and(|g| auth::constant_time_eq(g.as_bytes(), expected.as_bytes()))
}

async fn need_form(app: &Arc<App>, t: &TenantCtx, h: &HeaderMap, body: &[u8]) -> Result<WebUser, Response> {
    let w = need(app, t, h).await?;
    if !csrf_ok(form_field(body, "csrf").as_deref(), &w.csrf) {
        let lang = lang(app, h);
        return Err(message(
            lang,
            StatusCode::FORBIDDEN,
            lang.t("Refused"),
            lang.t("Invalid form token: reload the page."),
            "/web/files/",
        ));
    }
    Ok(w)
}

/// Version shown in the footer.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub(crate) struct Nav {
    user: String,
    csrf: String,
    /// Folder shown ("" = none or root): the search bar searches in it (`in=`).
    dir: String,
}

fn nav(w: &WebUser) -> Nav {
    Nav {
        user: w.u.user().to_owned(),
        csrf: w.csrf.clone(),
        dir: String::new(),
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage<'a> {
    lang: Lang,
    message: &'a str,
    /// Where to go once signed in ("" = the files), already checked by `after_login`.
    next: String,
    /// The tenant has `[tenant.oidc]`: show the single sign-on button.
    sso: bool,
    /// The tenant lets a Beastbox password open the web interface: show the form (not on a tenant that
    /// delegates its sign-in to a provider, unless `password_login = true`).
    pw_form: bool,
}

/// The only page a login may lead back to: a client's "open in the browser" link (`/index.php/f/<digits>`). Anything
/// else is ignored, so that the login page never sends anyone to another site.
pub(crate) fn after_login(v: Option<String>) -> String {
    // One allowlist for every path that returns from a sign-in (password, Login Flow, provider): `auth::oidc::after_login`.
    v.and_then(|v| crate::auth::oidc::after_login(&v)).unwrap_or_default()
}

async fn login_page(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, q: Uri, h: HeaderMap) -> Response {
    let next = after_login(form_field(q.query().unwrap_or("").as_bytes(), "next"));
    match session_any(&app, &t, &h).await {
        Some(WebUser { gate: Some(g), .. }) => return see_other(g),
        Some(_) => return see_other(if next.is_empty() { "/web/files/" } else { &next }),
        None => {}
    }
    html(
        StatusCode::OK,
        &LoginPage {
            lang: lang(&app, &h),
            message: "",
            next,
            sso: t.oidc().is_some(),
            pw_form: t.password_login_allowed(),
        },
    )
}

/// `GET /index.php/f/<fileid>`: the clients' "open in the browser". The item is looked up by its identifier among the
/// signed-in user's own files, then shown in the web interface (a folder's listing, a file's page).
pub(crate) async fn private_link(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Response {
    let lang = lang(&app, &h);
    let Ok(n) = id.parse::<u64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let w = match session(&app, &t, &h).await {
        Some(w) => w,
        None => return see_other(&format!("/login?next=/index.php/f/{n}")),
    };
    let u = w.u.clone();
    let found = blocking(move || -> io::Result<Option<String>> {
        let root = u.root()?;
        if crate::etag::fileid(&root.meta(None)?) == n {
            return Ok(Some("/web/files/".into()));
        }
        let q = crate::index::Query {
            fileid: Some(n),
            ..Default::default()
        };
        let hits = u.tenant().index().search(u.user(), &root, &q)?.hits;
        let Some(p) = hits.first().and_then(|h| SafePath::new(&h.path).ok()) else {
            return Ok(None);
        };
        // Replaced since indexing: never another item.
        let m = root.meta(Some(&p))?;
        if crate::etag::fileid(&m) != n {
            return Ok(None);
        }
        Ok(Some(if m.is_dir {
            format!("/web/files/{}", dav::href("", Some(p.as_str()), true))
        } else {
            format!("/web/view/{}", dav::href("", Some(p.as_str()), false))
        }))
    })
    .await;
    match found {
        Ok(Ok(Some(to))) => see_other(&to),
        _ => message(
            lang,
            StatusCode::NOT_FOUND,
            lang.t("Item not found"),
            lang.t("This file or folder no longer exists, or it was moved outside your space."),
            "/web/files/",
        ),
    }
}

/// Web login: human password (argon2id, bounded concurrency, failures limited per IP and per tenant, §0.4).
async fn login(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = lang(&app, &h);
    let next = after_login(form_field(&body, "next"));
    if !t.password_login_allowed() {
        // Nothing to guess here: no argon2, no failure counted, the provider is the way in.
        return html(
            StatusCode::FORBIDDEN,
            &LoginPage {
                lang,
                message: lang.t("This server signs in through its identity provider."),
                next,
                sso: t.oidc().is_some(),
                pw_form: false,
            },
        );
    }
    let (Some(user), Some(pw)) = (form_field(&body, "user"), form_field(&body, "password")) else {
        return html(
            StatusCode::BAD_REQUEST,
            &LoginPage {
                lang,
                message: lang.t("Missing fields."),
                next,
                sso: t.oidc().is_some(),
                pw_form: true,
            },
        );
    };
    if t.failures().ip_blocked(ip.0) || t.failures().human_blocked() {
        return too_many();
    }
    let Ok(Ok(_permit)) = tokio::time::timeout(Duration::from_secs(2), app.argon.acquire()).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "5")]).into_response();
    };
    // With two-step verification, the password opens only a waiting session (5 minutes) for the code page.
    let r = blocking({
        let (app, t) = (app.clone(), t.clone());
        move || -> crate::Result<Option<(String, bool)>> {
            let Some(u) = auth::verify_human(&app.db, &t, &user, &pw, &app.dummy_hash)? else {
                return Ok(None);
            };
            if matches!(app.db.totp_get(&t, u.user())?, Some((Some(_), _))) {
                return Ok(Some((auth::new_pending_session(&app.db, &u)?, true)));
            }
            Ok(Some((auth::new_session(&app.db, &u)?, false)))
        }
    })
    .await;
    match r {
        Ok(Ok(Some((secret, pending)))) => {
            let ttl = if pending { auth::PENDING_TTL } else { auth::SESSION_TTL };
            let c = set_cookie(&app, &cookie_name(&app, "sess"), &secret, ttl);
            let to = match (pending, next.is_empty()) {
                (true, true) => LOGIN_CODE.to_owned(),
                (true, false) => format!("{LOGIN_CODE}?next={next}"),
                (false, true) => "/web/files/".to_owned(),
                (false, false) => next,
            };
            (StatusCode::SEE_OTHER, [(header::LOCATION, to), (header::SET_COOKIE, c)]).into_response()
        }
        Ok(Ok(None)) => {
            tracing::warn!(tenant = t.name(), ip = %ip.0, "web login: failure");
            t.failures().record_ip(ip.0);
            t.failures().record_human();
            html(
                StatusCode::UNAUTHORIZED,
                &LoginPage {
                    lang,
                    message: lang.t("Wrong username or password."),
                    next,
                    sso: t.oidc().is_some(),
                    pw_form: true,
                },
            )
        }
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn logout(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    // Any session, including one that must still choose its password.
    let w = session_any(&app, &t, &h).await;
    if let Some(w) = w.filter(|w| csrf_ok(form_field(&body, "csrf").as_deref(), &w.csrf)) {
        let (app2, t2) = (app.clone(), t.clone());
        let _ = blocking(move || auth::end_session(&app2.db, &t2, &w.secret)).await;
    }
    let c = set_cookie(&app, &cookie_name(&app, "sess"), "", 0);
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/login".to_owned()), (header::SET_COOKIE, c)],
    )
        .into_response()
}

// ---------------------------------------------------------------- listing and details

pub(crate) struct Crumb {
    name: String,
    url: String,
}

pub(crate) fn crumbs(prefix: &str, root_name: &str, path: Option<&SafePath>) -> Vec<Crumb> {
    let mut v = vec![Crumb {
        name: root_name.to_owned(),
        url: prefix.to_owned(),
    }];
    let mut acc = String::new();
    for c in path
        .map(SafePath::as_str)
        .unwrap_or("")
        .split('/')
        .filter(|c| !c.is_empty())
    {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(c);
        v.push(Crumb {
            name: c.to_owned(),
            url: format!("{prefix}{}/", dav::href("", Some(&acc), false)),
        });
    }
    v
}

pub(crate) struct Entry {
    pub name: String,
    pub meta: Meta,
    pub tags: Vec<String>,
    pub favorite: bool,
}

/// Entries rendered per HTML page (default): only the displayed page is built and its tags read (§0.4: no
/// large response built in memory). Sizes offered to the user: `PAGE_SIZES`.
pub(crate) const PAGE: usize = 50;
pub(crate) const PAGE_SIZES: [usize; 5] = [20, 50, 100, 500, 1000];

pub(crate) struct Listing {
    pub entries: Vec<Entry>,
    pub truncated: bool,
    pub pages: usize,
    /// Page shown: the one asked for, or the one holding `find`.
    pub page: usize,
    /// Total number of entries in the folder (all pages).
    pub total: usize,
    /// Names of all subfolders (not just those of the page), for the tree.
    pub folders: Vec<String>,
}

/// Reads a folder (at most `LIST_MAX` entries), sorts it (folders first), keeps page `page` of `per` entries, or the
/// page holding the entry named `find` if there is one.
/// Sorting by tags: the tags of the whole folder are read (otherwise only those of the page); untagged last.
/// `show_hidden` false: names starting with `.` are left out (counts and tree included), unless `find` is one.
/// Blocking.
pub(crate) fn list(
    root: &crate::fs::Root,
    dir: Option<&SafePath>,
    sort: &str,
    desc: bool,
    (page, per): (usize, usize),
    (labels, show_hidden): (bool, bool),
    find: Option<&str>,
) -> io::Result<Listing> {
    let show_hidden = show_hidden || find.is_some_and(is_hidden);
    let read_labels = |name: &str| -> (Vec<String>, bool) {
        let p = SafePath::new(&match dir {
            Some(d) => format!("{}/{name}", d.as_str()),
            None => name.to_owned(),
        });
        p.ok().and_then(|p| root.labels(Some(&p)).ok()).unwrap_or_default()
    };
    let mut v = Vec::new();
    let mut truncated = false;
    for e in root.read_dir(dir)? {
        let (name, meta) = e?;
        if !show_hidden && is_hidden(&name) {
            continue;
        }
        if v.len() >= LIST_MAX {
            truncated = true;
            break;
        }
        v.push((name, meta, None::<(Vec<String>, bool)>, Vec::<String>::new()));
    }
    // Sorting by tags: key = lowercase tags, sorted; computed once per entry.
    if labels && sort == "tags" {
        for e in &mut v {
            let l = read_labels(&e.0);
            e.3 = l.0.iter().map(|t| t.to_lowercase()).collect();
            e.3.sort_unstable();
            e.2 = Some(l);
        }
    }
    v.sort_by(|a, b| {
        order(
            sort,
            desc,
            &SortKey::of(&a.0, &a.1, &a.3),
            &SortKey::of(&b.0, &b.1, &b.3),
        )
    });
    let per = per.max(1);
    let total = v.len();
    let pages = total.div_ceil(per).max(1);
    let page = find
        .and_then(|f| v.iter().position(|e| e.0 == f))
        .map_or(page, |i| i / per);
    let folders = v.iter().filter(|e| e.1.is_dir).map(|e| e.0.clone()).collect();
    let entries = v
        .into_iter()
        .skip(page.saturating_mul(per))
        .take(per)
        .map(|(name, meta, l, _)| {
            let (tags, favorite) = match l {
                Some(l) => l,
                None if labels => read_labels(&name),
                None => (Vec::new(), false),
            };
            Entry {
                name,
                meta,
                tags,
                favorite,
            }
        })
        .collect();
    Ok(Listing {
        folders,
        entries,
        truncated,
        pages,
        page,
        total,
    })
}

/// Hidden file or folder (Unix convention): its name starts with `.`.
pub(crate) fn is_hidden(name: &str) -> bool {
    name.starts_with('.')
}

/// What a row is sorted by (folder, favorite); `tags`: lowercase and sorted, empty if not sorting by tags.
pub(crate) struct SortKey<'a> {
    pub is_dir: bool,
    pub name: &'a str,
    pub size: u64,
    pub mtime: i64,
    pub tags: &'a [String],
}

impl<'a> SortKey<'a> {
    fn of(name: &'a str, m: &Meta, tags: &'a [String]) -> Self {
        SortKey {
            is_dir: m.is_dir,
            name,
            size: m.size,
            mtime: m.mtime,
            tags,
        }
    }

    fn hit(h: &'a crate::index::Hit, tags: &'a [String]) -> Self {
        SortKey {
            is_dir: h.is_dir,
            name: &h.name,
            size: h.size,
            mtime: h.mtime,
            tags,
        }
    }
}

/// Sort key (`name`, `size`, `date`, `type`, `tags`) from a `sort` parameter; by name by default.
fn sort_param(q: &Uri) -> &'static str {
    match param(q, "sort").as_deref() {
        Some("size") => "size",
        Some("date") => "date",
        Some("type") => "type",
        Some("tags") => "tags",
        _ => "name",
    }
}

/// List order: folders first, then the chosen column in the chosen direction; untagged always last
/// when sorting by tags; on a tie, by name.
pub(crate) fn order(sort: &str, desc: bool, a: &SortKey<'_>, b: &SortKey<'_>) -> std::cmp::Ordering {
    let name = || a.name.to_lowercase().cmp(&b.name.to_lowercase());
    let o = match sort {
        "size" => a.size.cmp(&b.size),
        "date" => a.mtime.cmp(&b.mtime),
        "type" => type_key(a.name, a.is_dir).cmp(&type_key(b.name, b.is_dir)),
        "tags" => a.tags.cmp(b.tags),
        _ => name(),
    };
    let untagged_last = if sort == "tags" {
        a.tags.is_empty().cmp(&b.tags.is_empty())
    } else {
        std::cmp::Ordering::Equal
    };
    b.is_dir
        .cmp(&a.is_dir)
        .then(untagged_last)
        .then(if desc { o.reverse() } else { o })
        .then_with(name)
}

/// Order of the Type sort: the icons of `render::icon`; anything else last.
const TYPE_ORDER: [&str; 12] = [
    "image", "video", "audio", "pdf", "doc", "sheet", "md", "text", "json", "code", "archive", "file",
];

/// Type sort key: rank of the icon in `TYPE_ORDER`, then the lowercase extension; folders all equal (sorted by name).
pub(crate) fn type_key(name: &str, is_dir: bool) -> (usize, String) {
    if is_dir {
        return (0, String::new());
    }
    let icon = render::icon(name, false);
    let rank = TYPE_ORDER.iter().position(|&t| t == icon).unwrap_or(TYPE_ORDER.len());
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_lowercase()).unwrap_or_default();
    (rank, ext)
}

/// Entry of the "Sort" menu (list and grid): a link, checked when it is the current choice.
struct SortItem {
    label: &'static str,
    href: String,
    on: bool,
}

/// "Sort" menu: the keys (a new key starts ascending), then both directions of the current key; `extra` as `sort_heads`.
fn sort_menu(lang: Lang, sort: &str, desc: bool, extra: &str) -> (Vec<SortItem>, Vec<SortItem>) {
    let keys = [
        ("name", lang.t("Name")),
        ("size", lang.t("Size")),
        ("date", lang.t("Modified")),
        ("type", lang.t("Type")),
        ("tags", lang.t("Tags")),
    ]
    .into_iter()
    .map(|(key, label)| SortItem {
        label,
        href: format!("?sort={key}&desc=0{extra}"),
        on: sort == key,
    })
    .collect();
    let dirs = [(false, lang.t("Ascending")), (true, lang.t("Descending"))]
        .into_iter()
        .map(|(d, label)| SortItem {
            label,
            href: format!("?sort={sort}&desc={}{extra}", u8::from(d)),
            on: desc == d,
        })
        .collect();
    (keys, dirs)
}

/// Sortable column header: a link that sorts by this column (or reverses the direction if it already does).
struct SortHead {
    label: &'static str,
    href: String,
    /// Class of the cell (`num`, `date`, `tags-cell`) or empty.
    class: &'static str,
    /// `ascending`, `descending`, or empty if the column is not the sort column.
    aria: &'static str,
}

/// Name, Size, Modified, Tags headers; `extra`: parameters kept in the links (`&view=grid&n=100`…).
fn sort_heads(lang: Lang, sort: &str, desc: bool, extra: &str) -> Vec<SortHead> {
    [
        ("name", lang.t("Name"), ""),
        ("size", lang.t("Size"), "num"),
        ("date", lang.t("Modified"), "date"),
        ("tags", lang.t("Tags"), "tags-cell"),
    ]
    .into_iter()
    .map(|(key, label, class)| {
        let on = sort == key;
        SortHead {
            label,
            href: format!("?sort={key}&desc={}{extra}", u8::from(on && !desc)),
            class,
            aria: match (on, desc) {
                (false, _) => "",
                (true, false) => "ascending",
                (true, true) => "descending",
            },
        }
    })
    .collect()
}

/// Requested page size: parameter `n` (and then to be remembered), otherwise the `bbn` cookie (last choice), otherwise
/// `PAGE`; bounded to `PAGE_SIZES`.
fn page_size(app: &App, q: &Uri, h: &HeaderMap) -> (usize, bool) {
    let ok = |n: Option<&str>| {
        n.and_then(|n| n.parse::<usize>().ok())
            .filter(|n| PAGE_SIZES.contains(n))
    };
    match ok(param(q, "n").as_deref()) {
        Some(n) => (n, true),
        None => (ok(cookie(h, &cookie_name(app, "n"))).unwrap_or(PAGE), false),
    }
}

/// "Previous / next page" links (empty if there are none), keeping the other parameters.
pub(crate) fn pager(base_query: &str, page: usize, pages: usize) -> (String, String) {
    let link = |n: usize| format!("?{base_query}page={n}");
    (
        if page > 0 { link(page - 1) } else { String::new() },
        if page + 1 < pages {
            link(page + 1)
        } else {
            String::new()
        },
    )
}

struct Row {
    /// The item named by `?voir=`: marked, and the page scrolls to it.
    target: bool,
    name: String,
    url: String,
    details: String,
    dav: String,
    is_dir: bool,
    icon: &'static str,
    /// Thumbnail: the image itself, lazy-loaded by the browser (grid view; never computed on the server, §0.3).
    thumb: String,
    previewable: bool,
    size: String,
    date: String,
    tags: Vec<String>,
    favorite: bool,
}

#[derive(Template)]
#[template(path = "files.html")]
struct FilesPage {
    nav: Nav,
    lang: Lang,
    title: String,
    crumbs: Vec<Crumb>,
    dav: String,
    zip: String,
    details: String,
    rows: Vec<Row>,
    truncated: bool,
    heads: Vec<SortHead>,
    /// "Sort" menu: keys, then directions.
    sort_keys: Vec<SortItem>,
    sort_dirs: Vec<SortItem>,
    /// Sorted column and direction (kept by the page size choice).
    sort: &'static str,
    desc: bool,
    page_no: usize,
    pages: usize,
    prev: String,
    next: String,
    /// First and last item shown, folder total; page size and sizes offered.
    first: usize,
    last: usize,
    total: usize,
    /// Page sizes offered, and which one is chosen.
    sizes: Vec<(usize, bool)>,
    /// Parameters kept by the page size choice (GET form).
    view_param: &'static str,
    /// Current folder (hidden field of the selection form).
    dir: String,
    /// Sidebar; its tree also serves to choose the destination of a move.
    side: Side,
    grid: bool,
    view_list: String,
    view_grid: String,
    /// Link that shows or hides the hidden files, and whether they are shown.
    hidden_toggle: String,
    show_hidden: bool,
    notice: BulkNotice,
}

async fn files_root(s: State<Arc<App>>, t: Extension<TenantCtx>, q: Uri, h: HeaderMap) -> Response {
    files_at(s, t, String::new(), q, h).await
}

async fn files(s: State<Arc<App>>, t: Extension<TenantCtx>, Path(p): Path<String>, q: Uri, h: HeaderMap) -> Response {
    files_at(s, t, p, q, h).await
}

/// A link of the message after a bulk action.
struct NoticeLink {
    label: String,
    url: String,
}

/// Message after a bulk action (`?op=…&ok=N&ko=M`, and for a move or a copy `&to=<folder>`, plus `&name=<name>` when a
/// single item went there): `item` (its new name, opening the destination with it marked), `text`, `dest` (the
/// destination folder), `end` (the failures); `error` for a partial failure. `to` and `name` are checked like any path.
#[derive(Default)]
struct BulkNotice {
    item: Option<NoticeLink>,
    text: String,
    dest: Option<NoticeLink>,
    end: String,
    error: bool,
}

fn bulk_notice(lang: Lang, q: &Uri) -> BulkNotice {
    let n = |k: &str| param(q, k).and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    let (ok, ko) = (n("ok"), n("ko"));
    let op = param(q, "op");
    let (en, fr) = match op.as_deref() {
        Some("delete") => ("moved to the trash", "mis à la corbeille"),
        Some("move") if ok > 1 => ("moved", "déplacés"),
        Some("move") => ("moved", "déplacé"),
        Some("copy" | "duplicate") if ok > 1 => ("copied", "copiés"),
        Some("copy" | "duplicate") => ("copied", "copié"),
        _ => return BulkNotice::default(),
    };
    // Destination: a folder path ("" = root) that `SafePath` accepts; only for a move or a copy that did something.
    let to = match (op.as_deref(), param(q, "to")) {
        (Some("delete"), _) | (_, None) => None,
        _ if ok == 0 => None,
        (_, Some(t)) if t.is_empty() => Some(String::new()),
        (_, Some(t)) => SafePath::new(&t).ok().map(|p| p.as_str().to_owned()),
    };
    let name = param(q, "name").filter(|n| ok == 1 && !n.contains('/') && SafePath::new(n).is_ok());
    let s = |n: usize| if n > 1 { "s" } else { "" };
    let (item, dest, text) = match &to {
        Some(to) => (
            name.map(|n| NoticeLink {
                url: folder_link(to, Some(&n)),
                label: n,
            }),
            Some(NoticeLink {
                label: to
                    .rsplit('/')
                    .next()
                    .filter(|l| !l.is_empty())
                    .unwrap_or(lang.t("My files"))
                    .to_owned(),
                url: folder_link(to, None),
            }),
            None,
        ),
        None => (None, None, Some(())),
    };
    let text = match (lang, &item, text) {
        (Lang::En, Some(_), None) => format!("{en} to"),
        (Lang::Fr, Some(_), None) => format!("{fr} vers"),
        (Lang::En, None, None) => format!("{ok} item{} {en} to", s(ok)),
        (Lang::Fr, None, None) => format!("{ok} élément{} {fr} vers", s(ok)),
        (Lang::En, _, Some(())) => format!("{ok} item{} {en}", s(ok)),
        (Lang::Fr, _, Some(())) => format!("{ok} élément{} {fr}", s(ok)),
    };
    let mut end = ".".to_owned();
    if ko > 0 {
        end.push_str(&match lang {
            Lang::En => format!(
                " {ko} item{} not processed: name already taken at the destination, or item not found.",
                s(ko)
            ),
            Lang::Fr => format!(
                " {ko} élément{} non traité{} : nom déjà pris à destination, ou élément introuvable.",
                s(ko),
                s(ko)
            ),
        });
    }
    BulkNotice {
        item,
        text,
        dest,
        end,
        error: ko > 0,
    }
}

async fn files_at(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    raw: String,
    q: Uri,
    h: HeaderMap,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need(&app, &t, &h).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let path = match safe(&raw, lang) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let sort = sort_param(&q);
    let desc = param(&q, "desc").as_deref() == Some("1");
    let (per, remember) = page_size(&app, &q, &h);
    let page = param(&q, "page")
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(0)
        .min(LIST_MAX / per);
    // List or grid: parameter `view` (and then remembered, like the page size), otherwise the last choice.
    let (grid, remember_view) = match param(&q, "view").as_deref() {
        Some(v @ ("grid" | "list")) => (v == "grid", true),
        _ => (cookie(&h, &cookie_name(&app, "view")) == Some("grid"), false),
    };
    // Hidden files: parameter `hidden` (and then remembered, like the view), otherwise the last choice.
    let (show_hidden, remember_hidden) = match param(&q, "hidden").as_deref() {
        Some(v @ ("0" | "1")) => (v == "1", true),
        _ => (w.show_hidden, false),
    };
    // `?voir=<name>`: the page holding that item, marked and scrolled to (`#vise`): a folder link from a search result.
    let find = param(&q, "voir");
    let (u, p, find2) = (w.u.clone(), path.clone(), find.clone());
    let listed = blocking(move || {
        let find = find2;
        let root = u.root()?;
        if !root.meta(p.as_ref())?.is_dir {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        let mut l = list(
            &root,
            p.as_ref(),
            sort,
            desc,
            (page, per),
            (true, show_hidden),
            find.as_deref(),
        )?;
        let side = side_of(
            lang,
            &u,
            &root,
            (p.as_ref(), show_hidden),
            Some(std::mem::take(&mut l.folders)),
            "files",
        )?;
        Ok((l, side))
    })
    .await;
    let (
        Listing {
            entries,
            truncated,
            pages,
            page,
            total,
            ..
        },
        side,
    ) = match listed {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => return io_page(lang, &e),
        Err(r) => return r,
    };
    let here = enc(path.as_ref());
    let sub = |name: &str| match &path {
        Some(p) => format!("{}/{name}", p.as_str()),
        None => name.to_owned(),
    };
    let rows: Vec<Row> = entries
        .into_iter()
        .map(|e| {
            let full = sub(&e.name);
            let rel = dav::href("", Some(&full), false);
            let kind = render::kind(&e.name);
            Row {
                target: find.as_deref() == Some(e.name.as_str()),
                url: if e.meta.is_dir {
                    format!("/web/files/{rel}/")
                } else {
                    format!("/web/view/{rel}")
                },
                details: format!("/web/view/{rel}"),
                dav: format!("/web/dav/{rel}"),
                is_dir: e.meta.is_dir,
                icon: render::icon(&e.name, e.meta.is_dir),
                thumb: if grid && matches!(kind, render::Kind::Image(_)) {
                    format!("/web/raw/{rel}?inline=1")
                } else {
                    String::new()
                },
                previewable: !e.meta.is_dir && kind != render::Kind::None,
                size: if e.meta.is_dir {
                    String::new()
                } else {
                    render::size(lang, e.meta.size)
                },
                date: render::date(e.meta.mtime),
                tags: e.tags,
                favorite: e.favorite,
                name: e.name,
            }
        })
        .collect();
    let view = if grid { "&view=grid" } else { "" };
    let n = if per == PAGE {
        String::new()
    } else {
        format!("&n={per}")
    };
    let (prev, next) = pager(&format!("sort={sort}&desc={}{view}{n}&", u8::from(desc)), page, pages);
    let first = if total == 0 { 0 } else { page * per + 1 };
    let last = (first + rows.len()).saturating_sub(1).max(first);
    let notice = bulk_notice(lang, &q);
    let (sort_keys, sort_dirs) = sort_menu(lang, sort, desc, &format!("{view}{n}"));
    let page = FilesPage {
        title: path
            .as_ref()
            .map_or(lang.t("Files").to_owned(), |p| p.split_parent().1.to_owned()),
        crumbs: crumbs("/web/files/", lang.t("Files"), path.as_ref()),
        dav: if here.is_empty() {
            "/web/dav/".into()
        } else {
            format!("/web/dav/{here}/")
        },
        zip: format!("/web/zip/{here}"),
        details: format!("/web/view/{here}"),
        rows,
        truncated,
        heads: sort_heads(lang, sort, desc, &format!("{view}{n}")),
        sort_keys,
        sort_dirs,
        sort,
        desc,
        page_no: page + 1,
        pages,
        prev,
        next,
        first,
        last,
        total,
        // Choice offered only if the folder exceeds the smallest size.
        sizes: if total > PAGE_SIZES[0] {
            PAGE_SIZES.iter().map(|&s| (s, s == per)).collect()
        } else {
            Vec::new()
        },
        view_param: if grid { "grid" } else { "" },
        dir: path.as_ref().map(|p| p.as_str().to_owned()).unwrap_or_default(),
        side,
        grid,
        hidden_toggle: format!(
            "?sort={sort}&desc={}{view}{n}&hidden={}",
            u8::from(desc),
            u8::from(!show_hidden)
        ),
        show_hidden,
        view_list: format!("?sort={sort}&desc={}&view=list{n}", u8::from(desc)),
        view_grid: format!("?sort={sort}&desc={}&view=grid{n}", u8::from(desc)),
        notice,
        nav: Nav {
            dir: path.as_ref().map(|p| p.as_str().to_owned()).unwrap_or_default(),
            ..nav(&w)
        },
        lang,
    };
    let mut r = html(StatusCode::OK, &page);
    if remember {
        // Page size choice kept for a year for the other folders.
        if let Ok(v) = set_cookie(&app, &cookie_name(&app, "n"), &per.to_string(), 31_536_000).parse() {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    if remember_hidden {
        // Hidden files shown or not, kept for a year for the other folders.
        let v = if show_hidden { "1" } else { "0" };
        if let Ok(v) = set_cookie(&app, &cookie_name(&app, "hidden"), v, 31_536_000).parse() {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    if remember_view {
        // List or grid kept for a year for the other folders.
        let v = if grid { "grid" } else { "list" };
        if let Ok(v) = set_cookie(&app, &cookie_name(&app, "view"), v, 31_536_000).parse() {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}

// ---------------------------------------------------------------- search (§8 item 4)

struct HitRow {
    name: String,
    /// The name in runs of (text, found by the search): highlighting.
    parts: Vec<(String, bool)>,
    url: String,
    /// Folder that holds the result ("" = root) and its link.
    folder: String,
    folder_url: String,
    icon: &'static str,
    size: String,
    date: String,
    tags: Vec<String>,
    favorite: bool,
}

#[derive(Template)]
#[template(path = "search.html")]
struct SearchPage {
    nav: Nav,
    lang: Lang,
    side: Side,
    q: String,
    hits: Vec<HitRow>,
    searched: bool,
    more: bool,
    incomplete: bool,
    /// Filter chips, by group.
    chips: Vec<Vec<Chip>>,
    /// Folder searched ("" = the whole space), the same search everywhere, and `in` for the form.
    scope: String,
    everywhere: String,
}

/// A filter of the search page: a link that adds it to the query, or removes it (`on`).
struct Chip {
    label: &'static str,
    href: String,
    on: bool,
}

fn search_href(q: &str, scope: Option<&SafePath>) -> String {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    let mut s = format!("/web/search?q={}", utf8_percent_encode(q.trim(), NON_ALPHANUMERIC));
    if let Some(p) = scope {
        s.push_str(&format!("&in={}", utf8_percent_encode(p.as_str(), NON_ALPHANUMERIC)));
    }
    s
}

/// `text` with `token` added, every other one of its `family` (`type:`…) removed; or without it if it was there.
fn toggled(text: &str, family: &str, token: &str) -> (String, bool) {
    let on = text.split_whitespace().any(|w| w == token);
    let mut v: Vec<&str> = text.split_whitespace().filter(|w| !w.starts_with(family)).collect();
    if !on {
        v.push(token);
    }
    (v.join(" "), on)
}

/// Filter chips: types, favorites, dates (local days, from `now`).
fn chips(lang: Lang, text: &str, scope: Option<&SafePath>, now: i64) -> Vec<Vec<Chip>> {
    let day = |ts: i64| render::date(ts).get(..10).unwrap_or("").to_owned();
    let year = day(now).get(..4).unwrap_or("").to_owned();
    let group = |family: &str, items: Vec<(&'static str, String)>| {
        items
            .into_iter()
            .map(|(label, token)| {
                let (q, on) = toggled(text, family, &token);
                Chip {
                    label: lang.t(label),
                    href: search_href(&q, scope),
                    on,
                }
            })
            .collect()
    };
    let types = [
        ("Folders", "folder"),
        ("Images", "image"),
        ("Videos", "video"),
        ("Audio", "audio"),
        ("PDF", "pdf"),
        ("Documents", "doc"),
    ];
    vec![
        group("type:", types.iter().map(|(l, t)| (*l, format!("type:{t}"))).collect()),
        group(
            "after:",
            vec![
                ("Last 7 days", format!("after:{}", day(now - 7 * 86_400))),
                ("Last 30 days", format!("after:{}", day(now - 30 * 86_400))),
                ("This year", format!("after:{year}")),
            ],
        ),
        group("is:", vec![("Starred", "is:fav".to_owned())]),
    ]
}

/// Result rows (search, favorites). `words`: folded words to highlight.
fn hit_rows(lang: Lang, hits: Vec<crate::index::Hit>, words: &[String]) -> Vec<HitRow> {
    hits.into_iter()
        .map(|hit| {
            let rel = dav::href("", Some(&hit.path), false);
            let folder = hit.path.rsplit_once('/').map_or("", |(d, _)| d).to_owned();
            HitRow {
                url: if hit.is_dir {
                    format!("/web/files/{rel}/")
                } else {
                    format!("/web/view/{rel}")
                },
                folder_url: folder_link(&folder, Some(&hit.name)),
                folder,
                icon: render::icon(&hit.name, hit.is_dir),
                size: if hit.is_dir {
                    String::new()
                } else {
                    render::size(lang, hit.size)
                },
                date: render::date(hit.mtime),
                tags: hit.tags,
                favorite: hit.favorite,
                parts: render::marks(&hit.name, words),
                name: hit.name,
            }
        })
        .collect()
}

/// `GET /web/search?q=…&in=…`: by name (every word), tag and filters (`index::Query::parse`), in the logged-in user's
/// space or one of its folders (`in`; an invalid path is ignored).
async fn search(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, q: Uri, h: HeaderMap) -> Response {
    let lang = lang(&app, &h);
    let w = match need(&app, &t, &h).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let text: String = param(&q, "q").unwrap_or_default().chars().take(200).collect();
    let scope = param(&q, "in").and_then(|p| SafePath::new(p.trim_matches('/')).ok());
    let mut query = crate::index::Query::parse(&text);
    query.under = scope.clone();
    let (searched, words) = (!query.is_empty(), query.words.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let u = w.u.clone();
    let found = match blocking(move || u.tenant().index().search(u.user(), &u.root()?, &query)).await {
        Ok(Ok(f)) => f,
        Ok(Err(e)) => return io_page(lang, &e),
        Err(r) => return r,
    };
    let hits = hit_rows(lang, found.hits, &words);
    html(
        StatusCode::OK,
        &SearchPage {
            nav: nav(&w),
            lang,
            side: side(lang, &w, "").await,
            q: text.clone(),
            hits,
            searched,
            more: found.more,
            incomplete: found.incomplete,
            chips: chips(lang, &text, scope.as_ref(), now),
            scope: scope.as_ref().map(|p| p.as_str().to_owned()).unwrap_or_default(),
            everywhere: search_href(&text, None),
        },
    )
}

// ---------------------------------------------------------------- sidebar

/// Sidebar: My files (tree), Favorites (favorite folders as an accordion), Shared links, Trash.
#[derive(Default)]
struct Side {
    tree: Vec<Node>,
    favs: Vec<Node>,
    /// Current section: "files", "favorites", "shares", "trash" or "" (none).
    active: &'static str,
}

/// Builds the sidebar. `here_kids`: subfolders of `here` if they have already been read (a folder's page), hidden
/// ones already left out unless `show_hidden`. Blocking. Favorites come from the search index (no extra disk walk).
fn side_of(
    lang: Lang,
    u: &UserCtx,
    root: &crate::fs::Root,
    (here, show_hidden): (Option<&SafePath>, bool),
    here_kids: Option<Vec<String>>,
    active: &'static str,
) -> io::Result<Side> {
    let kids = match here_kids {
        Some(k) => k,
        None => subfolders(root, here, show_hidden)?
            .into_iter()
            .map(|n| n.name)
            .collect(),
    };
    let mut tree = tree_around(lang, root, here, kids, show_hidden)?;
    if active != "files" {
        tree.iter_mut().for_each(|n| n.current = false);
    }
    let here_s = here.map(SafePath::as_str);
    let mut favs: Vec<Node> = u
        .tenant()
        .index()
        .search(u.user(), root, &crate::index::Query::favorites())
        .map(|f| f.hits)
        .unwrap_or_default()
        .into_iter()
        .filter(|h| h.is_dir)
        .map(|h| Node {
            href: dav::href("", Some(&h.path), true),
            current: active == "files" && here_s == Some(h.path.as_str()),
            name: h.name,
            path: h.path,
            open: false,
            close: 0,
        })
        .collect();
    // The index returns the newest first.
    favs.sort_by_cached_key(|n| n.name.to_lowercase());
    Ok(Side { tree, favs, active })
}

/// Sidebar of a page without a current folder (favorites, links, trash, search).
async fn side(lang: Lang, w: &WebUser, active: &'static str) -> Side {
    let (u, show) = (w.u.clone(), w.show_hidden);
    match blocking(move || side_of(lang, &u, &u.root()?, (None, show), None, active)).await {
        Ok(Ok(s)) => s,
        _ => Side::default(),
    }
}

// ---------------------------------------------------------------- favorites

#[derive(Template)]
#[template(path = "favorites.html")]
struct FavoritesPage {
    nav: Nav,
    lang: Lang,
    side: Side,
    heads: Vec<SortHead>,
    rows: Vec<FavRow>,
    more: bool,
}

/// Row of the Favorites page: a folder's row (`Row`), plus the folder that holds the item.
struct FavRow {
    row: Row,
    folder: String,
    folder_url: String,
}

fn fav_row(lang: Lang, h: crate::index::Hit) -> FavRow {
    let rel = dav::href("", Some(&h.path), false);
    let folder = h.path.rsplit_once('/').map_or("", |(d, _)| d).to_owned();
    let kind = render::kind(&h.name);
    FavRow {
        folder_url: folder_link(&folder, Some(&h.name)),
        folder,
        row: Row {
            target: false,
            url: if h.is_dir {
                format!("/web/files/{rel}/")
            } else {
                format!("/web/view/{rel}")
            },
            details: format!("/web/view/{rel}"),
            dav: format!("/web/dav/{rel}"),
            is_dir: h.is_dir,
            icon: render::icon(&h.name, h.is_dir),
            thumb: String::new(),
            previewable: !h.is_dir && kind != render::Kind::None,
            size: if h.is_dir {
                String::new()
            } else {
                render::size(lang, h.size)
            },
            date: render::date(h.mtime),
            tags: h.tags,
            favorite: true,
            name: h.name,
        },
    }
}

/// `GET /web/favorites`: all of the user's favorites, folders first, sorted like a folder (`sort`, `desc`).
async fn favorites(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, q: Uri, h: HeaderMap) -> Response {
    let lang = lang(&app, &h);
    let w = match need(&app, &t, &h).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let (u, show) = (w.u.clone(), w.show_hidden);
    let found = blocking(move || {
        let root = u.root()?;
        let found = u
            .tenant()
            .index()
            .search(u.user(), &root, &crate::index::Query::favorites())?;
        Ok::<_, io::Error>((found, side_of(lang, &u, &root, (None, show), None, "favorites")?))
    })
    .await;
    let (mut found, side) = match found {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => return io_page(lang, &e),
        Err(r) => return r,
    };
    let (sort, desc) = (sort_param(&q), param(&q, "desc").as_deref() == Some("1"));
    let mut hits: Vec<_> = std::mem::take(&mut found.hits)
        .into_iter()
        .map(|h| {
            let mut k: Vec<String> = h.tags.iter().map(|t| t.to_lowercase()).collect();
            k.sort_unstable();
            (h, k)
        })
        .collect();
    hits.sort_by(|(a, ka), (b, kb)| order(sort, desc, &SortKey::hit(a, ka), &SortKey::hit(b, kb)));
    html(
        StatusCode::OK,
        &FavoritesPage {
            nav: nav(&w),
            lang,
            side,
            heads: sort_heads(lang, sort, desc, ""),
            more: found.more,
            rows: hits.into_iter().map(|(h, _)| fav_row(lang, h)).collect(),
        },
    )
}

// ---------------------------------------------------------------- folder tree

/// A folder of the tree, rendered flat in prefix order: `open` opens the list of its children (which follow it),
/// `close` then closes that many lists (askama without recursion).
struct Node {
    name: String,
    /// Raw path ("" = root), value of the `dest` field.
    path: String,
    /// Path encoded for a URL, with a trailing `/` ("" = root).
    href: String,
    open: bool,
    current: bool,
    close: usize,
}

/// Subfolders of a folder, sorted. shortcut: at most 1,000 subfolders and 10,000 entries read per folder
/// (beyond that, the sync client); an index (J4) would do better.
/// `show_hidden` false: folders whose name starts with `.` are left out.
fn subfolders(root: &crate::fs::Root, dir: Option<&SafePath>, show_hidden: bool) -> io::Result<Vec<Node>> {
    let mut v = Vec::new();
    for e in root.read_dir(dir)?.take(LIST_MAX) {
        let (name, meta) = e?;
        if meta.is_dir && (show_hidden || !is_hidden(&name)) {
            v.push(name);
        }
    }
    Ok(nodes(dir, v))
}

fn nodes(dir: Option<&SafePath>, mut v: Vec<String>) -> Vec<Node> {
    v.sort_by_key(|n| n.to_lowercase());
    v.truncate(1000);
    v.into_iter()
        .map(|name| {
            let path = dir.map_or(name.clone(), |d| format!("{}/{name}", d.as_str()));
            Node {
                href: dav::href("", Some(&path), true),
                name,
                path,
                open: false,
                current: false,
                close: 0,
            }
        })
        .collect()
}

/// Root, then the subfolders of each ancestor of the current folder and of the current folder itself
/// (the latter, `here_kids`, come from the listing already read: no second read of a large folder).
fn tree_around(
    lang: Lang,
    root: &crate::fs::Root,
    here: Option<&SafePath>,
    mut here_kids: Vec<String>,
    show_hidden: bool,
) -> io::Result<Vec<Node>> {
    let mut out = vec![Node {
        name: lang.t("My files").into(),
        path: String::new(),
        href: String::new(),
        open: true,
        current: here.is_none(),
        close: 0,
    }];
    let here = here.map_or("", SafePath::as_str);
    branch(root, None, (here, show_hidden), &mut here_kids, &mut out)?;
    Ok(out)
}

/// A hidden folder stays in the tree when it is on the way to the current folder (opened by its address).
fn branch(
    root: &crate::fs::Root,
    dir: Option<&SafePath>,
    (here, show_hidden): (&str, bool),
    here_kids: &mut Vec<String>,
    out: &mut Vec<Node>,
) -> io::Result<()> {
    let kids = if dir.map_or("", SafePath::as_str) == here {
        nodes(dir, std::mem::take(here_kids))
    } else {
        subfolders(root, dir, true)?
    };
    for mut k in kids {
        k.open = here == k.path || here.starts_with(&format!("{}/", k.path));
        if !show_hidden && !k.open && is_hidden(&k.name) {
            continue;
        }
        k.current = here == k.path;
        let next = if k.open { SafePath::new(&k.path).ok() } else { None };
        out.push(k);
        if let Some(p) = next {
            branch(root, Some(&p), (here, show_hidden), here_kids, out)?;
        }
    }
    // Closes the list of `dir`'s children (if `dir` has no child, it is the last node).
    if let Some(n) = out.last_mut() {
        n.close += 1;
    }
    Ok(())
}

#[derive(Template)]
#[template(path = "tree_fragment.html")]
struct TreeFragment {
    lang: Lang,
    nodes: Vec<Node>,
    pick: bool,
}

async fn tree_root(s: State<Arc<App>>, t: Extension<TenantCtx>, q: Uri, h: HeaderMap) -> Response {
    tree_at(s, t, String::new(), q, h).await
}

async fn tree(s: State<Arc<App>>, t: Extension<TenantCtx>, Path(p): Path<String>, q: Uri, h: HeaderMap) -> Response {
    tree_at(s, t, p, q, h).await
}

/// `GET /web/tree/{folder}/`: a folder's subfolders as an HTML fragment, loaded when a node is opened.
async fn tree_at(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    raw: String,
    q: Uri,
    h: HeaderMap,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need(&app, &t, &h).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let path = match safe(&raw, lang) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let (u, show) = (w.u.clone(), w.show_hidden);
    match blocking(move || subfolders(&u.root()?, path.as_ref(), show)).await {
        Ok(Ok(nodes)) => html(
            StatusCode::OK,
            &TreeFragment {
                lang,
                nodes,
                pick: param(&q, "pick").as_deref() == Some("1"),
            },
        ),
        Ok(Err(e)) => io_page(lang, &e),
        Err(r) => r,
    }
}

/// `POST /web/bulk`: bulk action on a selection (works without JavaScript): trash, move, copy, duplicate, ZIP.
async fn bulk(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, h: HeaderMap, body: Bytes) -> Response {
    let lang = lang(&app, &h);
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let dir = match safe(&form_field(&body, "dir").unwrap_or_default(), lang) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let back = format!("/web/files/{}", enc(dir.as_ref()));
    let back = if back.ends_with('/') { back } else { format!("{back}/") };
    // Each item is a name in the current folder (not a path): nothing outside this folder.
    let mut items = Vec::new();
    for name in crate::http::form_values(&body, "item", BULK_MAX) {
        let full = match &dir {
            Some(d) => format!("{}/{name}", d.as_str()),
            None => name.clone(),
        };
        match SafePath::new(&full) {
            Ok(p) if !name.contains('/') => items.push(p),
            _ => return not_found(lang),
        }
    }
    if items.is_empty() {
        return message(
            lang,
            StatusCode::BAD_REQUEST,
            lang.t("Nothing selected"),
            lang.t("Tick at least one item."),
            &back,
        );
    }
    let op = form_field(&body, "op").unwrap_or_default();
    if op == "zip" {
        let top = dir
            .as_ref()
            .map_or(lang.t("Selection").to_owned(), |p| p.split_parent().1.to_owned());
        let u = w.u.clone();
        return zip_response(lang, move || u.root(), ZipOf::Items(items), top).await;
    }
    // Copies and moves: never over anything, the first free name (see `free_names`); "duplicate" is a copy in this very
    // folder.
    let copy = matches!(op.as_str(), "copy" | "duplicate");
    let dest = match op.as_str() {
        "delete" => None,
        "duplicate" => Some(dir.clone()),
        // No default destination: an oversight must not move everything to the root.
        "move" | "copy" => match form_field(&body, "dest").map(|d| safe(&d, lang)) {
            Some(Ok(d)) => Some(d),
            Some(Err(r)) => return r,
            None => {
                return message(
                    lang,
                    StatusCode::BAD_REQUEST,
                    lang.t("No destination"),
                    lang.t("Choose the destination folder."),
                    &back,
                );
            }
        },
        _ => {
            return message(lang, StatusCode::BAD_REQUEST, lang.t("Unknown action"), "", &back);
        }
    };
    // Moving into the folder the selection is already in: nothing to do (the dialog offers "Duplicate" there).
    if op == "move" && dest.as_ref() == Some(&dir) {
        return message(
            lang,
            StatusCode::BAD_REQUEST,
            lang.t("Already in this folder"),
            lang.t("Choose another folder, or duplicate the selection."),
            &back,
        );
    }
    let (u, d2) = (w.u.clone(), dir.clone());
    let to_q = dest
        .as_ref()
        .map(|d| d.as_ref().map_or(String::new(), |p| p.as_str().to_owned()));
    let r = blocking(move || -> io::Result<(usize, usize, Option<String>)> {
        let root = u.root()?;
        let (mut ok, mut ko, mut last) = (0, 0, None);
        match dest {
            None => {
                let done = dav::write::journaled(&u, &root, &[d2.as_ref()], || {
                    for p in &items {
                        if root.trash(p, u.user()).is_ok() {
                            ok += 1
                        } else {
                            ko += 1
                        }
                    }
                    Ok(())
                });
                done?;
            }
            Some(to) => {
                if !root.meta(to.as_ref())?.is_dir {
                    return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
                }
                let done = dav::write::journaled(&u, &root, &[d2.as_ref(), to.as_ref()], || {
                    for p in &items {
                        let name = p.split_parent().1;
                        let at = |n: &str| match &to {
                            Some(t) => SafePath::new(&format!("{}/{n}", t.as_str())),
                            None => SafePath::new(n),
                        };
                        let is_dir = root.meta(Some(p)).is_ok_and(|m| m.is_dir);
                        let names = free_names(name, is_dir).map(|n| at(&n));
                        let done = if copy {
                            to_free_name(p, names, |t| root.copy(p, t, false, u.user()))
                        } else {
                            to_free_name(p, names, |t| root.rename(p, t, false, u.user()))
                        };
                        match done {
                            Some(t) => {
                                ok += 1;
                                last = Some(t.split_parent().1.to_owned());
                            }
                            None => ko += 1,
                        }
                    }
                    Ok(())
                });
                done?;
            }
        }
        Ok((ok, ko, last))
    })
    .await;
    match r {
        Ok(Ok((ok, ko, last))) => {
            tracing::info!(tenant = t.name(), user = w.u.user(), op, ok, ko, "bulk action");
            // Where it went, for the message's links (`bulk_notice`): the folder, and the new name of a single item.
            use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
            let q = |v: &str| utf8_percent_encode(v, NON_ALPHANUMERIC).to_string();
            let mut extra = match to_q {
                Some(d) if ok > 0 => format!("&to={}", q(&d)),
                _ => String::new(),
            };
            if let (1, Some(n), false) = (ok, &last, extra.is_empty()) {
                extra.push_str(&format!("&name={}", q(n)));
            }
            see_other(&format!("{back}?op={op}&ok={ok}&ko={ko}{extra}"))
        }
        Ok(Err(e)) => io_page(lang, &e),
        Err(r) => r,
    }
}

#[derive(Template)]
#[template(path = "view.html")]
struct ViewPage {
    nav: Nav,
    lang: Lang,
    crumbs: Vec<Crumb>,
    name: String,
    icon: &'static str,
    path: String,
    is_dir: bool,
    size: String,
    date: String,
    open: String,
    download: String,
    tags: Vec<String>,
    favorite: bool,
    text: Option<String>,
    markdown: Option<String>,
    image: Option<String>,
    pdf: Option<String>,
    audio: Option<String>,
    video: Option<String>,
    /// Gallery: previous and next image of the same folder (by name), empty at the ends.
    prev: String,
    next: String,
    side: Side,
    /// Edit page of a text file (`editable`), or "".
    edit: String,
    /// Colouring of the text shown (`syntax`).
    syntax: &'static str,
    /// Raw file to copy to the clipboard (text or Markdown shown in full), or "".
    copy: String,
}

/// A text file the web interface can edit: text or Markdown, ≤ `PREVIEW_MAX`, valid UTF-8.
/// Editable here: a text file by its extension, or a file with no extension whose content is plain text (`README`,
/// `hosts`); at most `PREVIEW_MAX`, in UTF-8. Checked again on save: a binary file is never replaced by text.
fn editable(name: &str, m: &Meta, content: &[u8]) -> bool {
    let text = match render::kind(name) {
        render::Kind::Text | render::Kind::Markdown => true,
        render::Kind::None => render::no_extension(name) && render::looks_text(content),
        _ => false,
    };
    m.is_file && text && m.size <= render::PREVIEW_MAX as u64 && std::str::from_utf8(content).is_ok()
}

#[derive(Template)]
#[template(path = "edit.html")]
struct EditPage {
    nav: Nav,
    lang: Lang,
    side: Side,
    crumbs: Vec<Crumb>,
    name: String,
    icon: &'static str,
    size: String,
    date: String,
    /// Where the form is sent, and the details page (cancel).
    action: String,
    view: String,
    /// ETag of the version opened: a save is refused if the file changed since.
    etag: String,
    text: String,
    /// Long lines wrapped (prose: Markdown, txt, log); not for code and data.
    wrap: bool,
    /// The file changed elsewhere since it was opened: the text typed is shown again, with the date of the other version.
    conflict: String,
    /// Colouring by `static/editor.js`: `json`, `sh`, `md` or "" (none).
    syntax: &'static str,
    /// Markdown: "Preview" button; `preview`: the text rendered (sanitized), not saved.
    markdown: bool,
    preview: Option<String>,
    /// Name field (the file's, or the one typed), why it was refused, and whether an active share link ends on a rename.
    /// `types`: extension → [icon, colouring] of the text kinds, for the icon of the name being typed (JSON).
    types: String,
    new_name: String,
    name_error: &'static str,
    linked: bool,
}

/// `{"md":["md","md"],"json":["json","json"],…}`: icon and colouring of each text extension, computed by the same
/// functions as the server's pages (one source of truth for the editor's script).
fn text_types() -> String {
    let items: Vec<String> = render::TEXT_EXTENSIONS
        .iter()
        .map(|e| {
            let n = format!("x.{e}");
            format!("\"{e}\":[\"{}\",\"{}\"]", render::icon(&n, false), syntax(&n))
        })
        .collect();
    format!("{{{}}}", items.join(","))
}

/// Language coloured by the editor, from the extension.
fn syntax(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).as_deref() {
        Some("json") => "json",
        Some("sh" | "bash" | "zsh" | "ksh") => "sh",
        Some("md" | "markdown") => "md",
        _ => "",
    }
}

/// What the edit page shows besides the file itself.
#[derive(Default)]
struct Typed {
    /// Text typed (`None`: the file's contents), ETag of the version it started from.
    text: Option<String>,
    etag: Option<String>,
    conflict: bool,
    preview: bool,
    /// Name typed (`None`: the file's name), and why it was refused ("" = it was not).
    name: Option<String>,
    name_error: &'static str,
}

/// `GET /web/edit/…`: a text file in a form (`<textarea>`, works without JavaScript).
async fn edit_page(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Path(raw): Path<String>,
    h: HeaderMap,
) -> Response {
    let lang = lang(&app, &h);
    match need(&app, &t, &h).await {
        Ok(w) => edit_render(lang, &app, &w, &raw, StatusCode::OK, Typed::default()).await,
        Err(r) => r,
    }
}

async fn edit_render(lang: Lang, app: &Arc<App>, w: &WebUser, raw: &str, status: StatusCode, typed: Typed) -> Response {
    let path = match safe(raw, lang) {
        Ok(Some(p)) => p,
        Ok(None) => return not_found(lang),
        Err(r) => return r,
    };
    let (u, p, app2, show) = (w.u.clone(), path.clone(), app.clone(), w.show_hidden);
    let read = blocking(move || -> crate::Result<(Meta, Vec<u8>, Side, bool)> {
        let root = u.root()?;
        let m = root.meta(Some(&p))?;
        // An active share link on this file: renaming it ends the link (§8.6, links do not follow a rename).
        let linked = m.id.is_some_and(|id| {
            app2.db
                .share_list(u.tenant(), u.user())
                .is_ok_and(|l| l.iter().any(|s| s.fileid.as_slice() == id.0.as_slice()))
        });
        let mut buf = Vec::new();
        if m.is_file && m.size <= render::PREVIEW_MAX as u64 {
            root.open_file(&p)?
                .0
                .take(render::PREVIEW_MAX as u64 + 1)
                .read_to_end(&mut buf)?;
        }
        let side = side_of(lang, &u, &root, (p.split_parent().0.as_ref(), show), None, "files")?;
        Ok((m, buf, side, linked))
    })
    .await;
    let (m, buf, side, linked) = match read {
        Ok(Ok(x)) => x,
        Ok(Err(crate::Error::Io(e))) => return io_page(lang, &e),
        Ok(Err(_)) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(r) => return r,
    };
    let name = path.split_parent().1.to_owned();
    let rel = enc(Some(&path));
    if !editable(&name, &m, &buf) {
        return message(
            lang,
            StatusCode::UNPROCESSABLE_ENTITY,
            lang.t("Cannot edit this file"),
            lang.t("Only text files of 512 KiB at most, in UTF-8, can be edited here."),
            &format!("/web/view/{rel}"),
        );
    }
    let markdown = render::kind(&name) == render::Kind::Markdown;
    let text = typed.text.unwrap_or_else(|| String::from_utf8(buf).unwrap_or_default());
    let page = EditPage {
        crumbs: crumbs("/web/files/", lang.t("Files"), Some(&path)),
        icon: render::icon(&name, false),
        size: render::size(lang, m.size),
        date: render::date(m.mtime),
        action: format!("/web/edit/{rel}"),
        view: format!("/web/view/{rel}"),
        etag: typed.etag.unwrap_or_else(|| crate::etag::of(&m)),
        preview: (markdown && typed.preview).then(|| render::markdown(&text)),
        text,
        wrap: markdown
            || name
                .rsplit_once('.')
                .is_some_and(|(_, e)| matches!(e.to_ascii_lowercase().as_str(), "txt" | "log")),
        conflict: if typed.conflict {
            render::date(m.mtime)
        } else {
            String::new()
        },
        syntax: syntax(&name),
        markdown,
        types: text_types(),
        new_name: typed.name.unwrap_or_else(|| name.clone()),
        name_error: typed.name_error,
        linked,
        name,
        side,
        nav: nav(w),
        lang,
    };
    html(status, &page)
}

/// A new name for a file being edited, in its folder: `Err` = why it is refused (nothing is saved then).
fn rename_target(path: &SafePath, typed: &str) -> Result<Option<SafePath>, &'static str> {
    let name = typed.trim();
    if name == path.split_parent().1 {
        return Ok(None);
    }
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return Err("A name, without “/”: the file stays in its folder.");
    }
    if !matches!(render::kind(name), render::Kind::Text | render::Kind::Markdown) {
        return Err("Keep the name of a text file: .txt, .md, .json, .sh, .yaml, .csv…");
    }
    let full = match path.split_parent().0 {
        Some(d) => format!("{}/{name}", d.as_str()),
        None => name.to_owned(),
    };
    SafePath::new(&full).map(Some).map_err(|_| "This name is not allowed.")
}

/// `POST /web/edit/…`: saves the text through the WebDAV `PUT` (read-only, space reserve, quota, atomic write, ETags,
/// journal, index), with `If-Match` on the version opened: changed elsewhere since → the page again, the text typed kept
/// (409), unless "Replace it with my text" (`force`). `apercu`: Markdown preview, nothing saved.
async fn edit_save(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(origin): Extension<Base>,
    Path(raw): Path<String>,
    h: HeaderMap,
    body: Body,
) -> Response {
    let lang = lang(&app, &h);
    // The session first, the body after: only a logged-in user can make the server hold a large form in memory.
    if let Err(r) = need(&app, &t, &h).await {
        return r;
    }
    let Ok(body) = axum::body::to_bytes(body, EDIT_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if form_field(&body, "create").is_some() {
        return edit_create(lang, &app, &w, origin, &raw).await;
    }
    let Some(mut text) = form_field(&body, "text") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // Only an ETag the server could have given (it goes into a header).
    let etag = form_field(&body, "etag")
        .filter(|e| !e.is_empty() && e.len() <= 64 && e.bytes().all(|b| b.is_ascii_hexdigit()));
    let typed_name = form_field(&body, "name").map(|n| n.chars().take(512).collect::<String>());
    let typed = |text: Option<String>, conflict, preview, name_error| Typed {
        text,
        etag: etag.clone(),
        conflict,
        preview,
        name: typed_name.clone(),
        name_error,
    };
    if form_field(&body, "apercu").is_some() {
        return edit_render(lang, &app, &w, &raw, StatusCode::OK, typed(Some(text), false, true, "")).await;
    }
    if text.len() > render::PREVIEW_MAX {
        return message(
            lang,
            StatusCode::PAYLOAD_TOO_LARGE,
            lang.t("Cannot edit this file"),
            lang.t("Only text files of 512 KiB at most, in UTF-8, can be edited here."),
            &format!("/web/edit/{}", raw.trim_start_matches('/')),
        );
    }
    // The browser sends a textarea with CRLF line ends: back to LF unless the file already used CRLF.
    let path = match safe(&raw, lang) {
        Ok(Some(p)) => p,
        Ok(None) => return not_found(lang),
        Err(r) => return r,
    };
    // New name refused: nothing saved, the page again with what was typed.
    let target = match typed_name.as_deref().map(|n| rename_target(&path, n)) {
        None | Some(Ok(None)) => None,
        Some(Ok(Some(t))) => Some(t),
        Some(Err(why)) => {
            return edit_render(
                lang,
                &app,
                &w,
                &raw,
                StatusCode::UNPROCESSABLE_ENTITY,
                typed(Some(text), false, false, why),
            )
            .await;
        }
    };
    let (u, p) = (w.u.clone(), path.clone());
    // Same rule as the edit page (an image or a binary file is not replaced by text), and the line ends in use.
    let current = blocking(move || -> io::Result<(bool, bool)> {
        let root = u.root()?;
        let m = root.meta(Some(&p))?;
        let mut buf = Vec::new();
        if m.is_file {
            root.open_file(&p)?
                .0
                .take(render::PREVIEW_MAX as u64 + 1)
                .read_to_end(&mut buf)?;
        }
        Ok((
            editable(p.split_parent().1, &m, &buf),
            buf.windows(2).any(|w| w == b"\r\n"),
        ))
    })
    .await;
    match current {
        Ok(Ok((false, _))) => {
            return message(
                lang,
                StatusCode::UNPROCESSABLE_ENTITY,
                lang.t("Cannot edit this file"),
                lang.t("Only text files of 512 KiB at most, in UTF-8, can be edited here."),
                &format!("/web/view/{}", enc(Some(&path))),
            );
        }
        Ok(Ok((true, true))) => {}
        Ok(Ok((true, false))) => text = text.replace("\r\n", "\n"),
        Ok(Err(e)) => return io_page(lang, &e),
        Err(r) => return r,
    }
    let mut req = Request::builder()
        .method("PUT")
        .header(header::CONTENT_LENGTH, text.len());
    if form_field(&body, "force").is_none() {
        // No valid ETag: never matches, so the page comes back (nothing overwritten blindly).
        req = req.header(header::IF_MATCH, format!("\"{}\"", etag.as_deref().unwrap_or("0")));
    }
    let Ok(req) = req.body(Body::from(text.clone())) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let origin2 = origin.clone();
    let r = dav::web_dav(app.clone(), w.u.clone(), origin, &raw, req).await;
    match r.status() {
        StatusCode::CREATED | StatusCode::NO_CONTENT | StatusCode::OK => match target {
            None => see_other(&format!("/web/view/{}", enc(Some(&path)))),
            Some(to) => edit_rename(lang, &app, &w, origin2, &raw, &path, &to, typed(None, false, false, "")).await,
        },
        StatusCode::PRECONDITION_FAILED => {
            edit_render(
                lang,
                &app,
                &w,
                &raw,
                StatusCode::CONFLICT,
                typed(Some(text), true, false, ""),
            )
            .await
        }
        StatusCode::INSUFFICIENT_STORAGE => message(
            lang,
            StatusCode::INSUFFICIENT_STORAGE,
            lang.t("Not saved"),
            lang.t("Not enough space left (quota or disk)."),
            &format!("/web/edit/{}", enc(Some(&path))),
        ),
        StatusCode::SERVICE_UNAVAILABLE => message(
            lang,
            StatusCode::SERVICE_UNAVAILABLE,
            lang.t("Not saved"),
            lang.t("The server is read-only for now."),
            &format!("/web/view/{}", enc(Some(&path))),
        ),
        s => message(
            lang,
            s,
            lang.t("Not saved"),
            lang.t("The operation could not be completed."),
            &format!("/web/view/{}", enc(Some(&path))),
        ),
    }
}

/// After the contents are saved: the rename (WebDAV `MOVE`, same folder, never over an existing item; identity, tags and
/// star kept). Refused (name taken, folder gone…): the contents stay saved, the page again with the name typed.
#[allow(clippy::too_many_arguments)]
async fn edit_rename(
    lang: Lang,
    app: &Arc<App>,
    w: &WebUser,
    origin: Base,
    raw: &str,
    from: &SafePath,
    to: &SafePath,
    mut typed: Typed,
) -> Response {
    let req = Request::builder()
        .method("MOVE")
        .header("destination", format!("/web/dav/{}", enc(Some(to))))
        .header("overwrite", "F")
        .body(Body::empty());
    let Ok(req) = req else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let status = dav::web_dav(app.clone(), w.u.clone(), origin, &enc(Some(from)), req)
        .await
        .status();
    if matches!(status, StatusCode::CREATED | StatusCode::NO_CONTENT) {
        return see_other(&format!("/web/view/{}", enc(Some(to))));
    }
    typed.name_error = match status {
        StatusCode::PRECONDITION_FAILED => {
            "Saved, but not renamed: an item with this name already exists in this folder."
        }
        StatusCode::SERVICE_UNAVAILABLE => "Saved, but not renamed: the server is read-only for now.",
        _ => "Saved, but not renamed: the operation could not be completed.",
    };
    edit_render(lang, app, w, raw, StatusCode::CONFLICT, typed).await
}

/// `POST /web/edit/…` with `create`: a new empty text file (name of a text kind), never over an existing item, then
/// its edit page. Created through the WebDAV `PUT` with `If-None-Match: *` (same checks as any write).
async fn edit_create(lang: Lang, app: &Arc<App>, w: &WebUser, origin: Base, raw: &str) -> Response {
    let path = match safe(raw, lang) {
        Ok(Some(p)) => p,
        Ok(None) => return not_found(lang),
        Err(r) => return r,
    };
    let folder = format!(
        "/web/files/{}",
        path.split_parent()
            .0
            .map(|p| format!("{}/", enc(Some(&p))))
            .unwrap_or_default()
    );
    let refused = |status, text: &'static str| message(lang, status, lang.t("File not created"), lang.t(text), &folder);
    if !matches!(
        render::kind(path.split_parent().1),
        render::Kind::Text | render::Kind::Markdown
    ) {
        return refused(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Choose the name of a text file: .txt, .md, .json, .sh, .yaml, .csv…",
        );
    }
    let req = Request::builder()
        .method("PUT")
        .header(header::IF_NONE_MATCH, "*")
        .header(header::CONTENT_LENGTH, 0)
        .body(Body::empty());
    let Ok(req) = req else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match dav::web_dav(app.clone(), w.u.clone(), origin, raw, req).await.status() {
        StatusCode::CREATED | StatusCode::NO_CONTENT => see_other(&format!("/web/edit/{}", enc(Some(&path)))),
        // Same name (file, or folder: the writer refuses to replace it).
        StatusCode::PRECONDITION_FAILED | StatusCode::METHOD_NOT_ALLOWED => refused(
            StatusCode::CONFLICT,
            "An item with this name already exists in this folder.",
        ),
        StatusCode::CONFLICT => refused(StatusCode::CONFLICT, "This folder does not exist (any more)."),
        StatusCode::SERVICE_UNAVAILABLE => refused(StatusCode::SERVICE_UNAVAILABLE, "The server is read-only for now."),
        StatusCode::INSUFFICIENT_STORAGE => refused(
            StatusCode::INSUFFICIENT_STORAGE,
            "Not enough space left (quota or disk).",
        ),
        s => refused(s, "The operation could not be completed."),
    }
}

/// Images next to `path` in its folder, by name order: (previous, next). Blocking.
fn gallery(root: &crate::fs::Root, path: &SafePath) -> io::Result<(Option<String>, Option<String>)> {
    let (parent, name) = path.split_parent();
    let mut names: Vec<String> = root
        .read_dir(parent.as_ref())?
        .filter_map(Result::ok)
        .filter(|(n, m)| m.is_file && matches!(render::kind(n), render::Kind::Image(_)))
        .map(|(n, _)| n)
        .take(LIST_MAX)
        .collect();
    names.sort_by_key(|n| n.to_lowercase());
    let Some(i) = names.iter().position(|n| n == name) else {
        return Ok((None, None));
    };
    let full = |n: &String| match &parent {
        Some(p) => format!("{}/{n}", p.as_str()),
        None => n.clone(),
    };
    Ok((
        i.checked_sub(1).and_then(|j| names.get(j)).map(full),
        names.get(i + 1).map(full),
    ))
}

async fn view_root(s: State<Arc<App>>, t: Extension<TenantCtx>, h: HeaderMap) -> Response {
    view_at(s, t, String::new(), h).await
}

async fn view(s: State<Arc<App>>, t: Extension<TenantCtx>, Path(p): Path<String>, h: HeaderMap) -> Response {
    view_at(s, t, p, h).await
}

async fn view_at(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    raw: String,
    h: HeaderMap,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need(&app, &t, &h).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let path = match safe(&raw, lang) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let name = path
        .as_ref()
        .map_or(lang.t("Files").to_owned(), |p| p.split_parent().1.to_owned());
    let kind = render::kind(&name);
    let (u, p, show) = (w.u.clone(), path.clone(), w.show_hidden);
    let maybe = render::no_extension(&name) && kind == render::Kind::None;
    type Read = (
        Meta,
        Vec<String>,
        bool,
        (Option<String>, bool),
        (Option<String>, Option<String>),
        Side,
    );
    let read = blocking(move || -> io::Result<Read> {
        let root = u.root()?;
        let m = root.meta(p.as_ref())?;
        let neighbours = match (&p, kind) {
            (Some(p), render::Kind::Image(_)) if m.is_file => gallery(&root, p)?,
            _ => (None, None),
        };
        let (tags, fav) = root.labels(p.as_ref())?;
        let (mut text, mut edit) = (None, false);
        // Text by its extension, or a file with no extension whose content turns out to be text.
        if let (true, Some(p), render::Kind::Text | render::Kind::Markdown | render::Kind::None) = (m.is_file, &p, kind)
            && (kind != render::Kind::None || maybe)
        {
            let (f, _) = root.open_file(p)?;
            let mut buf = Vec::new();
            f.take(render::PREVIEW_MAX as u64).read_to_end(&mut buf)?;
            // Read whole: it must be valid UTF-8 to the end (a cut character is only allowed when the read stopped).
            let whole = m.size <= render::PREVIEW_MAX as u64;
            if kind != render::Kind::None || (render::looks_text(&buf) && (!whole || std::str::from_utf8(&buf).is_ok()))
            {
                edit = editable(p.split_parent().1, &m, &buf);
                text = Some(String::from_utf8_lossy(&buf).into_owned());
            }
        }
        // Sidebar opened on the folder being viewed, or on the one holding the file.
        let here = match &p {
            Some(p) if !m.is_dir => p.split_parent().0,
            _ => p.clone(),
        };
        let side = side_of(lang, &u, &root, (here.as_ref(), show), None, "files")?;
        Ok((m, tags, fav, (text, edit), neighbours, side))
    })
    .await;
    let (m, tags, favorite, (text, edit), (prev, next), side) = match read {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => return io_page(lang, &e),
        Err(r) => return r,
    };
    let rel = enc(path.as_ref());
    let inline = format!("/web/raw/{rel}?inline=1");
    // The file itself (Markdown: its source), only when the page shows it in full.
    let copy = if text.is_some() && m.size <= render::PREVIEW_MAX as u64 {
        format!("/web/raw/{rel}")
    } else {
        String::new()
    };
    let media = |want: bool| (want && m.is_file).then(|| inline.clone());
    let page = ViewPage {
        crumbs: crumbs("/web/files/", lang.t("Files"), path.as_ref()),
        path: path.as_ref().map(|p| p.as_str().to_owned()).unwrap_or_default(),
        is_dir: m.is_dir,
        size: render::size(lang, m.size),
        date: render::date(m.mtime),
        open: if rel.is_empty() {
            "/web/files/".into()
        } else {
            format!("/web/files/{rel}/")
        },
        download: if m.is_dir {
            format!("/web/zip/{rel}")
        } else {
            format!("/web/raw/{rel}")
        },
        tags,
        favorite,
        markdown: if kind == render::Kind::Markdown {
            text.as_deref().map(render::markdown)
        } else {
            None
        },
        text: if matches!(kind, render::Kind::Text | render::Kind::None) {
            text
        } else {
            None
        },
        image: media(matches!(kind, render::Kind::Image(_))),
        pdf: media(kind == render::Kind::Pdf),
        audio: media(matches!(kind, render::Kind::Audio(_))),
        video: media(matches!(kind, render::Kind::Video(_))),
        prev: prev
            .map(|p| format!("/web/view/{}", dav::href("", Some(&p), false)))
            .unwrap_or_default(),
        next: next
            .map(|p| format!("/web/view/{}", dav::href("", Some(&p), false)))
            .unwrap_or_default(),
        icon: render::icon(&name, m.is_dir),
        edit: if edit {
            format!("/web/edit/{rel}")
        } else {
            String::new()
        },
        syntax: syntax(&name),
        copy,
        name,
        side,
        nav: nav(&w),
        lang,
    };
    html(StatusCode::OK, &page)
}

/// Download (attachment) or display for the closed list of safe types (`?inline=1`).
async fn raw(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Path(raw): Path<String>,
    q: Uri,
    h: HeaderMap,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need(&app, &t, &h).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let Ok(Some(path)) = safe(&raw, lang) else {
        return not_found(lang);
    };
    let name = path.split_parent().1.to_owned();
    let mode = match (param(&q, "inline").is_some(), render::inline_mime(&name)) {
        (true, Some(mime)) => Serve::Inline(mime),
        _ => Serve::Attachment(name),
    };
    let u = w.u.clone();
    dav::serve_file(move || u.root(), path, false, &h, mode).await
}

async fn zip_root(s: State<Arc<App>>, t: Extension<TenantCtx>, h: HeaderMap) -> Response {
    zip_at(s, t, String::new(), h).await
}

async fn zip(s: State<Arc<App>>, t: Extension<TenantCtx>, Path(p): Path<String>, h: HeaderMap) -> Response {
    zip_at(s, t, p, h).await
}

async fn zip_at(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    raw: String,
    h: HeaderMap,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need(&app, &t, &h).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let path = match safe(&raw, lang) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let top = path
        .as_ref()
        .map_or(lang.t("Files").to_owned(), |p| p.split_parent().1.to_owned());
    let u = w.u.clone();
    zip_response(lang, move || u.root(), ZipOf::Dir(path), top).await
}

/// What an archive holds: a whole folder, or a selection of items.
pub(crate) enum ZipOf {
    Dir(Option<SafePath>),
    Items(Vec<SafePath>),
}

/// Streamed ZIP response, after checking the limits (413 beyond).
pub(crate) async fn zip_response(
    lang: Lang,
    open: impl FnOnce() -> io::Result<crate::fs::Root> + Send + 'static,
    what: ZipOf,
    top: String,
) -> Response {
    let t2 = top.clone();
    let prepared = blocking(move || -> io::Result<zip::Zip> {
        let root = open()?;
        match what {
            ZipOf::Dir(dir) => {
                if !root.meta(dir.as_ref())?.is_dir {
                    return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
                }
                zip::precheck(&root, dir.as_ref())?;
                Ok(zip::Zip::new(root, dir, &t2))
            }
            ZipOf::Items(items) => {
                zip::precheck_items(&root, &items)?;
                let typed = items
                    .into_iter()
                    .map(|p| root.meta(Some(&p)).map(|m| (p, m.is_dir)))
                    .collect::<io::Result<Vec<_>>>()?;
                Ok(zip::Zip::selection(root, typed, &t2))
            }
        }
    })
    .await;
    let z = match prepared {
        Ok(Ok(z)) => z,
        Ok(Err(e)) if e.kind() == io::ErrorKind::FileTooLarge => {
            return message(
                lang,
                StatusCode::PAYLOAD_TOO_LARGE,
                lang.t("Folder too large"),
                lang.t("Beyond 4 GiB or 65,535 items: use a sync client."),
                "/web/files/",
            );
        }
        Ok(Err(e)) => return io_page(lang, &e),
        Err(r) => return r,
    };
    let name = format!("{top}.zip");
    let disp = format!("attachment; filename*=UTF-8''{}", dav::href("", Some(&name), false));
    let stream = dav::blocking_stream(z, zip::Zip::step);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/zip".to_owned()),
            (header::CONTENT_DISPOSITION, disp),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

// ---------------------------------------------------------------- browser WebDAV

async fn web_dav_root(s: State<Arc<App>>, t: Extension<TenantCtx>, o: Extension<Base>, req: Request) -> Response {
    web_dav_at(s, t, o, String::new(), req).await
}

async fn web_dav(
    s: State<Arc<App>>,
    t: Extension<TenantCtx>,
    o: Extension<Base>,
    Path(p): Path<String>,
    req: Request,
) -> Response {
    web_dav_at(s, t, o, p, req).await
}

/// Same operations as `/remote.php/dav` (upload, MKCOL, MOVE, DELETE…), authenticated by the session **and** the
/// `X-CSRF-Token` header (required for every method: a third-party site can neither read nor send it).
async fn web_dav_at(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(origin): Extension<Base>,
    raw: String,
    req: Request,
) -> Response {
    let Some(w) = session(&app, &t, req.headers()).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !csrf_ok(req.headers().get("x-csrf-token").and_then(|v| v.to_str().ok()), &w.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    dav::web_dav(app, w.u, origin, &raw, req).await
}

// ---------------------------------------------------------------- tags and favorites

fn back_to(path: &Option<SafePath>) -> String {
    format!("/web/view/{}", enc(path.as_ref()))
}

async fn tags(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, h: HeaderMap, body: Bytes) -> Response {
    let lang = lang(&app, &h);
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let path = match safe(&form_field(&body, "path").unwrap_or_default(), lang) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Some(tag) = form_field(&body, "tag").as_deref().and_then(normalize_tag) else {
        return message(
            lang,
            StatusCode::BAD_REQUEST,
            lang.t("Tag refused"),
            lang.t("1 to 32 letters, digits, spaces, - or _."),
            &back_to(&path),
        );
    };
    let add = form_field(&body, "op").as_deref() == Some("add");
    let (u, p) = (w.u.clone(), path.clone());
    let r = blocking(move || -> io::Result<bool> {
        let root = u.root()?;
        let (mut tags, _) = root.labels(p.as_ref())?;
        tags.retain(|x| *x != tag);
        if add {
            if tags.len() >= crate::fs::MAX_TAGS {
                return Ok(false);
            }
            tags.push(tag);
        }
        root.set_tags(p.as_ref(), &tags)?;
        reindex(&u, &root, p.as_ref());
        Ok(true)
    })
    .await;
    match r {
        Ok(Ok(true)) => see_other(&back_to(&path)),
        Ok(Ok(false)) => message(
            lang,
            StatusCode::BAD_REQUEST,
            lang.t("Too many tags"),
            lang.t("20 tags at most per item."),
            &back_to(&path),
        ),
        Ok(Err(e)) => io_page(lang, &e),
        Err(r) => r,
    }
}

/// Tags and favorites do not go through `journaled` (no ETag changed): the index rereads the parent folder.
fn reindex(u: &UserCtx, root: &crate::fs::Root, p: Option<&SafePath>) {
    if let Some(p) = p {
        let parent = p.split_parent().0;
        u.tenant().index().refresh(u.user(), root, &[parent.as_ref()]);
    }
}

async fn favorite(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let path = match safe(&form_field(&body, "path").unwrap_or_default(), lang) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let on = form_field(&body, "on").as_deref() == Some("1");
    let (u, p) = (w.u.clone(), path.clone());
    match blocking(move || {
        let root = u.root()?;
        root.set_favorite(p.as_ref(), on)?;
        reindex(&u, &root, p.as_ref());
        Ok(())
    })
    .await
    {
        Ok(Ok(())) => see_other(&back_to(&path)),
        Ok(Err(e)) => io_page(lang, &e),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------- public link history

/// A link event, ready to display: "<name> <what happened>", then "via "link"".
struct EventLine {
    /// Icon: `download`, `upload` or `info` (refusal).
    icon: &'static str,
    name: String,
    /// The file as it is now in the owner's space ("" = gone, or no file).
    url: String,
    what: String,
    /// "via “", the link's name, then "”, link revoked": the name links to the link's target ("" = gone).
    pre: String,
    link: String,
    link_url: String,
    post: String,
    at: i64,
    time: String,
}

/// Page of an item of the owner's space: the folder or the details page; "" if it is not there (any more).
fn item_url(root: &crate::fs::Root, path: &str) -> String {
    let p = if path.is_empty() {
        None
    } else {
        match SafePath::new(path) {
            Ok(p) => Some(p),
            Err(_) => return String::new(),
        }
    };
    let rel = dav::href("", p.as_ref().map(SafePath::as_str), false);
    match root.meta(p.as_ref()) {
        Ok(_) if p.is_none() => "/web/files/".to_owned(),
        Ok(m) if m.is_dir => format!("/web/files/{rel}/"),
        Ok(_) => format!("/web/view/{rel}"),
        Err(_) => String::new(),
    }
}

/// A link's name as the owner recognizes it: the last component of its target.
fn share_label(lang: Lang, path_hint: &str) -> String {
    match path_hint.rsplit_once('/') {
        Some((_, n)) => n.to_owned(),
        None if path_hint.is_empty() => lang.t("My files").to_owned(),
        None => path_hint.to_owned(),
    }
}

fn event_line(lang: Lang, e: crate::db::ShareEvent, root: &crate::fs::Root) -> EventLine {
    use crate::db::ShareEventKind::*;
    let bytes = render::size(lang, e.bytes.max(0).unsigned_abs());
    let times = |w: &str| match lang {
        Lang::En => {
            if e.count > 1 {
                format!("{w} ({} times)", e.count)
            } else {
                w.to_owned()
            }
        }
        Lang::Fr => {
            if e.count > 1 {
                format!("{w} ({} fois)", e.count)
            } else {
                w.to_owned()
            }
        }
    };
    let what = match e.kind {
        Download => times(lang.t("downloaded")),
        Zip => times(lang.t("downloaded as a ZIP archive")),
        Drop => match (lang, e.count) {
            (Lang::En, 1) => format!("uploaded ({bytes})"),
            (Lang::En, 2) => format!("and 1 other file uploaded ({bytes})"),
            (Lang::En, n) => format!("and {} other files uploaded ({bytes})", n - 1),
            (Lang::Fr, 1) => format!("déposé ({bytes})"),
            (Lang::Fr, 2) => format!("et 1 autre fichier déposé ({bytes})"),
            (Lang::Fr, n) => format!("et {} autres fichiers déposés ({bytes})", n - 1),
        },
        Denied => times(lang.t("Access refused: wrong password")),
        Created => lang.t("Link created").to_owned(),
        Revoked => lang.t("Link revoked").to_owned(),
    };
    let link = share_label(lang, &e.share_path);
    let revoked = match e.share_end {
        Some(crate::db::ShareEnd::Gone) => match lang {
            Lang::En => ", deleted or moved target".to_owned(),
            Lang::Fr => ", source supprimée ou déplacée".to_owned(),
        },
        Some(end) => match lang {
            Lang::En => format!(", link {}", end.label()),
            Lang::Fr => format!(", lien {}", lang.t(end.label())),
        },
        None => String::new(),
    };
    let link_url = item_url(root, &e.share_path);
    // `path` is relative to the link; a file link, or a ZIP of the whole folder, records the target's own name.
    let url = match e.path.as_str() {
        "" => String::new(),
        p if e.share_path.is_empty() => item_url(root, p),
        p => match item_url(root, &format!("{}/{p}", e.share_path)) {
            u if u.is_empty() && e.share_path.rsplit('/').next() == Some(p) => link_url.clone(),
            u => u,
        },
    };
    // A file right inside a folder link: the folder opened at that file (as from a search).
    let link_url = if !url.is_empty() && url != link_url && link_url.ends_with('/') && !e.path.contains('/') {
        folder_link(&e.share_path, Some(&e.path))
    } else {
        link_url
    };
    // The owner's actions: the link's own state would only repeat the event ("revoked").
    let (pre, post) = match (lang, e.kind == Drop) {
        _ if matches!(e.kind, Created | Revoked) => match lang {
            Lang::En => ("“", "”".to_owned()),
            Lang::Fr => ("« ", " »".to_owned()),
        },
        (Lang::En, true) => ("into “", format!("”{revoked}")),
        (Lang::En, false) => ("via “", format!("”{revoked}")),
        (Lang::Fr, true) => ("dans « ", format!(" »{revoked}")),
        (Lang::Fr, false) => ("via « ", format!(" »{revoked}")),
    };
    EventLine {
        icon: match e.kind {
            Drop => "upload",
            Denied => "info",
            Created => "plus",
            Revoked => "trash",
            _ => "download",
        },
        name: e.path,
        url,
        what,
        pre: pre.to_owned(),
        link,
        link_url,
        post,
        time: render::hm(e.at),
        at: e.at,
    }
}

/// Recent files shown in the "Recent activity" box, and link events.
const RECENT_FILES: usize = 8;
const RECENT_EVENTS: u32 = 4;
/// Items most recently moved to the trash, in the same box.
const RECENT_DELETED: usize = 4;

struct RecentCard {
    name: String,
    url: String,
    folder: String,
    /// The folder, opened at the item (`folder_link`).
    folder_url: String,
    icon: &'static str,
    ago: String,
}

#[derive(Template)]
#[template(path = "activity.html")]
struct ActivityFragment {
    lang: Lang,
    recents: Vec<RecentCard>,
    /// Latest trash items: `url` is unused, `folder` is where they were (`folder_url`), `ago` when they were deleted.
    deleted: Vec<RecentCard>,
    events: Vec<EventLine>,
}

/// `GET /web/activity`: the "Recent activity" box at the root of "My files", as an HTML fragment loaded after
/// the page (the index may need building): the 8 newest files of the whole space, and the 4 latest
/// public link events. Nothing to show → 204 (the box disappears).
async fn activity(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, h: HeaderMap) -> Response {
    let lang = lang(&app, &h);
    let w = match need(&app, &t, &h).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let (app2, u) = (app.clone(), w.u.clone());
    let r = blocking(move || -> crate::Result<_> {
        let root = u.root()?;
        let q = crate::index::Query {
            files_named: Some(crate::index::any_file),
            newest: true,
            // An upload keeps the file's own date (X-OC-Mtime): its arrival is the last activity, not that date.
            by_activity: true,
            ..Default::default()
        };
        let found = u.tenant().index().search(u.user(), &root, &q)?;
        let keep = app2.settings.share_history_days;
        let events: Vec<EventLine> = app2
            .db
            .guest_events(u.tenant(), u.user(), keep, RECENT_EVENTS)?
            .into_iter()
            .map(|e| event_line(lang, e, &root))
            .collect();
        // Newest first; permanently deleted items are gone and cannot be shown.
        let mut deleted = root.trash_list()?;
        deleted.truncate(RECENT_DELETED);
        Ok((found.hits, events, deleted))
    })
    .await;
    let Ok(Ok((hits, events, deleted))) = r else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if hits.is_empty() && events.is_empty() && deleted.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }
    let now = crate::db::now_secs();
    let hits: Vec<_> = hits.into_iter().take(RECENT_FILES).collect();
    let agos: Vec<String> = hits.iter().map(|h| render::ago(lang, h.ctime, now)).collect();
    let recents = hit_rows(lang, hits, &[])
        .into_iter()
        .zip(agos)
        .map(|(r, ago)| RecentCard {
            name: r.name,
            url: r.url,
            folder_url: r.folder_url,
            folder: r.folder,
            icon: r.icon,
            ago,
        })
        .collect();
    let events = events
        .into_iter()
        .map(|mut l| {
            l.time = render::ago(lang, l.at, now);
            l
        })
        .collect();
    let deleted = deleted
        .into_iter()
        .map(|d| {
            let folder = d
                .origin
                .as_ref()
                .and_then(|o| o.split_parent().0)
                .map(|p| p.as_str().to_owned())
                .unwrap_or_default();
            RecentCard {
                icon: render::icon(&d.name, d.is_dir),
                url: String::new(),
                folder_url: folder_link(&folder, None),
                folder,
                ago: render::ago(lang, d.deleted, now),
                name: d.name,
            }
        })
        .collect();
    html(
        StatusCode::OK,
        &ActivityFragment {
            lang,
            recents,
            deleted,
            events,
        },
    )
}

/// History events on one page.
const HISTORY_PAGE: u32 = 50;

struct DayGroup {
    label: String,
    events: Vec<EventLine>,
}

/// History shown under the links: filter (`?lien=`) and page (`?page=`).
struct History {
    days: Vec<DayGroup>,
    /// Label of the link the history is filtered on ("" = every link), with its state if it has ended.
    filter: String,
    lien: String,
    page_no: u32,
    pages: u32,
    prev: String,
    next: String,
    keep_days: u32,
}

/// Plausible link identifier (hexadecimal, bounded); anything else = no filter.
fn link_param(q: Option<&Uri>) -> String {
    hex_param(q, "lien")
}

/// Link identifier in the query string (hexadecimal ≤ 64), or "".
fn hex_param(q: Option<&Uri>, key: &str) -> String {
    q.and_then(|q| param(q, key))
        .filter(|s| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_default()
}

fn history(lang: Lang, app: &App, u: &UserCtx, q: Option<&Uri>) -> crate::Result<History> {
    let lien = link_param(q);
    let keep = app.settings.share_history_days;
    let page = q
        .and_then(|q| param(q, "page"))
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(1)
        .clamp(1, 10_000);
    let (events, total) = app.db.share_events(
        u.tenant(),
        u.user(),
        &lien,
        keep,
        HISTORY_PAGE,
        (page - 1) * HISTORY_PAGE,
    )?;
    let pages = u32::try_from(total).unwrap_or(u32::MAX).div_ceil(HISTORY_PAGE).max(1);
    let now = crate::db::now_secs();
    let mut days: Vec<DayGroup> = Vec::new();
    let root = u.root()?;
    for e in events.into_iter().map(|e| event_line(lang, e, &root)) {
        let label = render::day_label(lang, e.at, now);
        match days.last_mut() {
            Some(d) if d.label == label => d.events.push(e),
            _ => days.push(DayGroup { label, events: vec![e] }),
        }
    }
    let filter = if lien.is_empty() {
        String::new()
    } else {
        app.db
            .event_shares(u.tenant(), u.user(), keep)?
            .into_iter()
            .find(|s| s.share_id == lien)
            .map(|s| {
                let end = s.end.map(|e| format!(" ({})", lang.t(e.label()))).unwrap_or_default();
                format!("{}{end}", share_label(lang, &s.path_hint))
            })
            .unwrap_or_default()
    };
    let at = |p: u32| {
        let l = if lien.is_empty() {
            String::new()
        } else {
            format!("lien={lien}&")
        };
        format!("/web/shares?{l}page={p}#historique")
    };
    Ok(History {
        prev: if page > 1 { at(page - 1) } else { String::new() },
        next: if page < pages { at(page + 1) } else { String::new() },
        days,
        filter,
        lien,
        page_no: page,
        pages,
        keep_days: keep,
    })
}

// ---------------------------------------------------------------- share links (management)

struct ShareLine {
    id: String,
    /// Item name, and the folder that holds it ("" = root), opened at the item.
    name: String,
    folder: String,
    folder_url: String,
    icon: &'static str,
    url: String,
    perms: &'static str,
    /// The owner's label for the link ("" = none).
    label: String,
    /// Download hidden (view only).
    hidden: bool,
    password: bool,
    /// "expires on …" / "expired on …" ("" = no expiry).
    expiry: String,
    expired: bool,
    downloads: String,
    last_access: String,
    /// "Downloads at most" limit ("" = none), for the card of the link just created.
    limit: String,
    /// Details page of the shared item ("" = the root).
    item_url: String,
    /// Link just created (`?nouveau=`): shown in a card at the top and marked in the list.
    fresh: bool,
}

#[derive(Template)]
#[template(path = "shares.html")]
struct SharesPage {
    nav: Nav,
    lang: Lang,
    side: Side,
    message: String,
    rows: Vec<ShareLine>,
    hist: History,
}

async fn shares_list(lang: Lang, app: &Arc<App>, w: &WebUser, origin: &Base, msg: String, q: Option<Uri>) -> Response {
    // Only one of the user's own links can be marked (the list is theirs).
    let fresh = hex_param(q.as_ref(), "nouveau");
    let (app2, u) = (app.clone(), w.u.clone());
    let r = blocking(move || -> crate::Result<_> {
        // Each link's target checked again: in the trash → suspended (removed from the list); restored → resumed;
        // renamed, moved or permanently deleted → ended. Unreadable recorded path: left as is.
        let (root, t) = (u.root()?, u.tenant());
        let mut trash = share::TrashScan::default();
        let mut rows = Vec::new();
        for s in app2
            .db
            .share_list(t, u.user())?
            .into_iter()
            .chain(app2.db.share_suspended(t, u.user())?)
        {
            // Folder or file (for the icon); undetermined: a drop link always targets a folder.
            let guess = s.perms == "drop";
            let Ok(p) = share::target_path(&s.path_hint) else {
                rows.extend((!s.suspended).then_some((s, guess)));
                continue;
            };
            match share::target(&root, p.as_ref(), &s.fileid, &mut trash) {
                share::Target::Here(m) if s.suspended => {
                    app2.db.share_resume(t, &s.share_id)?;
                    rows.push((s, m.is_dir));
                }
                // Unreadable identity: a suspended link stays so, an active one too (never ended on a doubt).
                share::Target::Unknown if s.suspended => {}
                share::Target::Here(m) => rows.push((s, m.is_dir)),
                share::Target::Unknown => rows.push((s, guess)),
                share::Target::Trashed => app2.db.share_suspend(t, &s.share_id)?,
                share::Target::Gone => app2.db.share_gone(t, &s.share_id)?,
            }
        }
        rows.sort_by_key(|(s, _)| std::cmp::Reverse(s.created_at));
        Ok((rows, history(lang, &app2, &u, q.as_ref())?))
    })
    .await;
    let Ok(Ok((rows, hist))) = r else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let t = w.u.tenant();
    let now = crate::db::now_secs();
    let rows = rows
        .into_iter()
        .map(|(s, is_dir)| {
            let expired = s.expires_at.is_some_and(|e| e <= now);
            let (folder, name) = match s.path_hint.rsplit_once('/') {
                Some((f, n)) => (f.to_owned(), n.to_owned()),
                None => (String::new(), share_label(lang, &s.path_hint)),
            };
            ShareLine {
                fresh: !fresh.is_empty() && s.share_id == fresh,
                limit: s.max_downloads.map(|m| m.to_string()).unwrap_or_default(),
                item_url: if s.path_hint.is_empty() {
                    String::new()
                } else {
                    format!("/web/view/{}", dav::href("", Some(&s.path_hint), false))
                },
                url: format!("{}/s/{}", origin.0, auth::share_token(t, &s.share_id)),
                icon: render::icon(&name, is_dir),
                folder_url: folder_link(&folder, Some(&name)),
                name,
                folder,
                perms: match share::access(&s) {
                    "drop" => lang.t("drop only"),
                    "upload" => lang.t("read and upload"),
                    _ => lang.t("read only"),
                },
                label: s.opts.label.clone(),
                hidden: s.opts.hide_download,
                password: s.password_hash.is_some(),
                expiry: s
                    .expires_at
                    .map(|e| match (lang, expired) {
                        (Lang::En, false) => format!("expires on {}", render::date(e)),
                        (Lang::En, true) => format!("expired on {}", render::date(e)),
                        (Lang::Fr, false) => format!("expire le {}", render::date(e)),
                        (Lang::Fr, true) => format!("expiré le {}", render::date(e)),
                    })
                    .unwrap_or_default(),
                expired,
                downloads: match s.max_downloads {
                    Some(m) => format!("{} / {m}", s.download_count),
                    None => s.download_count.to_string(),
                },
                last_access: s
                    .last_access_at
                    .map(render::date)
                    .unwrap_or_else(|| lang.t("never").into()),
                id: s.share_id,
            }
        })
        .collect();
    html(
        StatusCode::OK,
        &SharesPage {
            nav: nav(w),
            lang,
            side: side(lang, w, "shares").await,
            message: msg,
            rows,
            hist,
        },
    )
}

async fn shares_page(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(origin): Extension<Base>,
    q: Uri,
    h: HeaderMap,
) -> Response {
    match need(&app, &t, &h).await {
        Ok(w) => shares_list(lang(&app, &h), &app, &w, &origin, String::new(), Some(q)).await,
        Err(r) => r,
    }
}

/// Creating a link (§8.6): read-only or drop only (folders), password (argon2id), expiry, limit.
async fn share_create(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let path = match safe(&form_field(&body, "path").unwrap_or_default(), lang) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let back = back_to(&path);
    let bad = |m: &str| message(lang, StatusCode::BAD_REQUEST, lang.t("Link refused"), m, &back);
    let perms = match form_field(&body, "perms").as_deref() {
        Some("drop") => "drop",
        Some("upload") => "upload",
        _ => "read",
    };
    let password = form_field(&body, "password").filter(|p| !p.is_empty());
    let expires = match form_field(&body, "expires").filter(|e| !e.is_empty()) {
        Some(e) => match render::parse_day_end(&e) {
            Some(ts) => Some(ts),
            None => return bad(lang.t("Invalid or past expiry date.")),
        },
        None => None,
    };
    let max = match form_field(&body, "max").filter(|m| !m.is_empty()) {
        Some(m) => match m.parse::<i64>() {
            Ok(n) if (1..=100_000).contains(&n) => Some(n),
            _ => return bad(lang.t("Invalid number of downloads.")),
        },
        None => None,
    };
    let link = share::NewLink {
        path,
        perms,
        password,
        expires,
        max,
        label: form_field(&body, "label").unwrap_or_default(),
        note: form_field(&body, "note").unwrap_or_default(),
        hide_download: form_field(&body, "hide").as_deref() == Some("1"),
    };
    match share::create_link(&app, &w.u, link).await {
        // Redirect (a reload does not create a second link), to the list with this link at the top.
        Ok(id) => see_other(&format!("/web/shares?nouveau={id}#nouveau")),
        Err(share::LinkError::Refused(m)) => bad(lang.t(m)),
        Err(share::LinkError::Io(e)) => io_page(lang, &e),
        Err(share::LinkError::Busy) => (StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "5")]).into_response(),
    }
}

async fn share_revoke(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(origin): Extension<Base>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let id = form_field(&body, "id").unwrap_or_default();
    let (app2, u) = (app.clone(), w.u.clone());
    let done = blocking(move || app2.db.share_revoke(u.tenant(), u.user(), &id)).await;
    match done {
        Ok(Ok(true)) => {
            tracing::info!(tenant = t.name(), user = w.u.user(), "share link revoked");
            shares_list(lang, &app, &w, &origin, lang.t("Link revoked.").into(), None).await
        }
        Ok(Ok(false)) => shares_list(lang, &app, &w, &origin, lang.t("Link not found.").into(), None).await,
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

// ---------------------------------------------------------------- trash (§6)

struct TrashLine {
    slot: String,
    name: String,
    icon: &'static str,
    /// Original folder shown ("" = root) and its link.
    folder: String,
    folder_url: String,
    deleted: String,
    size: String,
}

#[derive(Template)]
#[template(path = "trash.html")]
struct TrashPage {
    nav: Nav,
    lang: Lang,
    side: Side,
    items: Vec<TrashLine>,
    truncated: bool,
    notice: String,
    notice_url: String,
    notice_error: bool,
    days: u32,
}

async fn trash_page(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, q: Uri, h: HeaderMap) -> Response {
    let lang = lang(&app, &h);
    let w = match need(&app, &t, &h).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let u = w.u.clone();
    let list = match blocking(move || u.root()?.trash_list()).await {
        Ok(Ok(l)) => l,
        Ok(Err(e)) => return io_page(lang, &e),
        Err(r) => return r,
    };
    let truncated = list.len() >= crate::fs::TRASH_LIST_MAX;
    let items = list
        .into_iter()
        .map(|it| {
            let folder = it
                .origin
                .as_ref()
                .and_then(|o| o.split_parent().0)
                .map(|f| f.as_str().to_owned())
                .unwrap_or_default();
            TrashLine {
                icon: render::icon(&it.name, it.is_dir),
                // The item is no longer there: the folder itself.
                folder_url: folder_link(&folder, None),
                folder,
                deleted: render::date(it.deleted),
                size: if it.is_dir {
                    String::new()
                } else {
                    render::size(lang, it.size)
                },
                name: it.name,
                slot: it.slot,
            }
        })
        .collect();
    let to = param(&q, "to").unwrap_or_default();
    let (notice, notice_url, notice_error) = match param(&q, "ok").as_deref() {
        Some("restored") => (
            match lang {
                Lang::En => format!("Restored: {to}"),
                Lang::Fr => format!("Restauré : {to}"),
            },
            format!("/web/view/{}", dav::href("", Some(&to), false)),
            false,
        ),
        Some("purged") => (lang.t("Permanently deleted.").to_owned(), String::new(), false),
        Some("emptied") => (lang.t("Trash emptied.").to_owned(), String::new(), false),
        Some("gone") => (
            lang.t("This item is no longer in the trash.").to_owned(),
            String::new(),
            true,
        ),
        _ => (String::new(), String::new(), false),
    };
    html(
        StatusCode::OK,
        &TrashPage {
            nav: nav(&w),
            lang,
            side: side(lang, &w, "trash").await,
            items,
            truncated,
            notice,
            notice_url,
            notice_error,
            days: app.settings.trash_days,
        },
    )
}

async fn trash_restore(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let slot = form_field(&body, "slot").unwrap_or_default();
    let u = w.u.clone();
    let r = blocking(move || dav::write::restore(&u, &slot)).await;
    match r {
        Ok(Ok(to)) => {
            tracing::info!(tenant = t.name(), user = w.u.user(), "item restored from the trash");
            let mut v = String::new();
            for b in to.as_str().bytes() {
                v.push_str(&format!("%{b:02X}"));
            }
            see_other(&format!("/web/trash?ok=restored&to={v}"))
        }
        Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOENT) => see_other("/web/trash?ok=gone"),
        Ok(Err(e)) => io_page(lang, &e),
        Err(r) => r,
    }
}

/// Permanent delete: explicit confirmation required (box checked, or checked by the script after the dialog).
fn unconfirmed(lang: Lang, body: &[u8]) -> Option<Response> {
    (form_field(body, "confirm").as_deref() != Some("1")).then(|| {
        message(
            lang,
            StatusCode::BAD_REQUEST,
            lang.t("Confirmation required"),
            lang.t("Tick “I confirm” to delete permanently."),
            "/web/trash",
        )
    })
}

async fn trash_purge(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Some(r) = unconfirmed(lang, &body) {
        return r;
    }
    let slot = form_field(&body, "slot").unwrap_or_default();
    let u = w.u.clone();
    match blocking(move || u.root()?.trash_purge(&slot)).await {
        Ok(Ok(())) => {
            tracing::info!(
                tenant = t.name(),
                user = w.u.user(),
                "item permanently deleted from the trash"
            );
            see_other("/web/trash?ok=purged")
        }
        Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOENT) => see_other("/web/trash?ok=gone"),
        Ok(Err(e)) => io_page(lang, &e),
        Err(r) => r,
    }
}

async fn trash_empty(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Some(r) = unconfirmed(lang, &body) {
        return r;
    }
    let u = w.u.clone();
    match blocking(move || u.root()?.trash_empty()).await {
        Ok(Ok(n)) => {
            tracing::info!(tenant = t.name(), user = w.u.user(), items = n, "trash emptied");
            see_other("/web/trash?ok=emptied")
        }
        Ok(Err(e)) => io_page(lang, &e),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------- account

struct TokenLine {
    id: String,
    /// Icon: `phone`, `desktop` or `key` (other software), from the name given by the Login Flow.
    kind: &'static str,
    label: String,
    created: String,
    used: String,
}

/// Result of an account action, shown in the section concerned: error in red (`role="alert"`) with an HTTP
/// error code, success in green (a failure must never look like a mere piece of information).
enum Notice {
    None,
    Password(StatusCode, &'static str),
    Tokens(StatusCode, &'static str),
    TwoFa(StatusCode, &'static str),
}

/// Two-step verification block, as the templates `twofa.html`, `twofa-qr.html` and `twofa-setup.html` read it.
#[derive(Default)]
struct TwoFaView {
    /// "hidden" (tenant `off`, not on), "off", "setup" (QR code shown), "on".
    state: &'static str,
    /// The account has a password: asked with the code to manage two-step verification.
    ask_password: bool,
    required: bool,
    /// QR code (inline SVG, nothing from the user in it) and the same key in groups of 4.
    qr: String,
    secret: String,
    /// Where the setup form posts its code.
    action: &'static str,
    csrf: String,
    left: u32,
    /// Recovery codes, shown once.
    recovery: Vec<String>,
    msg: &'static str,
    error: bool,
}

/// What a two-step verification action shows beyond the state: the QR code being set up, or new recovery codes.
#[derive(Default)]
struct TwoFaExtra {
    setup: Option<(String, String)>,
    recovery: Vec<String>,
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage {
    nav: Nav,
    lang: Lang,
    pw_msg: &'static str,
    pw_error: bool,
    token_msg: &'static str,
    token_error: bool,
    secret: String,
    /// QR code to connect the mobile app (inline SVG drawn by `qr_svg`, nothing from the user in it), shown once.
    qr: String,
    admin: bool,
    min_password: usize,
    twofa: TwoFaView,
    used: String,
    total: String,
    free: String,
    used_bytes: u64,
    total_bytes: u64,
    tokens: Vec<TokenLine>,
    /// What a new app password asks again (`Reproof::field`: "password", "code", or "" for a recent sign-in).
    reproof: &'static str,
}

async fn account(app: &Arc<App>, w: &WebUser, lang: Lang, notice: Notice, extra: (String, String)) -> Response {
    account_tf(app, w, lang, notice, extra, TwoFaExtra::default()).await
}

async fn account_tf(
    app: &Arc<App>,
    w: &WebUser,
    lang: Lang,
    notice: Notice,
    (secret, qr): (String, String),
    tf: TwoFaExtra,
) -> Response {
    let (app2, u) = (app.clone(), w.u.clone());
    let r = blocking(move || -> crate::Result<_> {
        Ok((
            u.root()?.space()?,
            app2.db.token_list(u.tenant(), u.user())?,
            app2.db.user_role(u.tenant(), u.user())?,
            app2.db.recovery_count(u.tenant(), u.user())?,
        ))
    })
    .await;
    let Ok(Ok((space, tokens, role, left))) = r else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (code, pw, tok, two) = match notice {
        Notice::None => (StatusCode::OK, None, None, None),
        Notice::Password(c, m) => (c, Some((m, !c.is_success())), None, None),
        Notice::Tokens(c, m) => (c, None, Some((m, !c.is_success())), None),
        Notice::TwoFa(c, m) => (c, None, None, Some((m, !c.is_success()))),
    };
    let mode = app.settings.two_factor(w.u.tenant().name());
    let mut twofa = TwoFaView {
        state: match (&tf.setup, w.totp) {
            (Some(_), _) => "setup",
            (None, true) => "on",
            (None, false) if mode == crate::config::TwoFactor::Off => "hidden",
            (None, false) => "off",
        },
        required: mode == crate::config::TwoFactor::Required,
        ask_password: w.has_password,
        action: "/web/account/2fa/confirm#double",
        csrf: w.csrf.clone(),
        left,
        msg: two.map_or("", |x| lang.t(x.0)),
        error: two.is_some_and(|x| x.1),
        recovery: tf.recovery,
        ..Default::default()
    };
    if let Some((q, s)) = tf.setup {
        (twofa.qr, twofa.secret) = (q, s);
    }
    if twofa.state == "on" && twofa.msg.is_empty() && twofa.recovery.is_empty() && left <= 2 {
        twofa.msg = lang.t("Few recovery codes left: create new ones.");
        twofa.error = true;
    }
    let page = AccountPage {
        nav: nav(w),
        lang,
        pw_msg: pw.map_or("", |x| lang.t(x.0)),
        pw_error: pw.is_some_and(|x| x.1),
        token_msg: tok.map_or("", |x| lang.t(x.0)),
        token_error: tok.is_some_and(|x| x.1),
        secret,
        qr,
        admin: role.as_deref() == Some("admin"),
        min_password: app.settings.min_password,
        twofa,
        used: render::size(lang, space.used),
        total: render::size(lang, space.used.saturating_add(space.available)),
        free: render::size(lang, space.available),
        used_bytes: space.used,
        total_bytes: space.used.saturating_add(space.available),
        reproof: w.reproof().field(),
        tokens: tokens
            .into_iter()
            .map(|t| TokenLine {
                id: t.token_id,
                kind: match t.label.as_str() {
                    l if l.contains("Android") || l.contains("iOS") || l.contains("QR") => "phone",
                    l if l.contains("desktop") || l.contains("bureau") => "desktop",
                    _ => "key",
                },
                label: t.label,
                created: render::date(t.created_at),
                used: match (t.last_used_at, t.expires_at) {
                    (None, Some(e)) => match lang {
                        Lang::En => format!("never, expires at {} if unused", render::hm(e)),
                        Lang::Fr => format!("jamais, expire à {} s'il ne sert pas", render::hm(e)),
                    },
                    (None, None) => lang.t("never").into(),
                    (Some(u), _) => render::date(u),
                },
            })
            .collect(),
    };
    html(code, &page)
}

async fn account_page(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, h: HeaderMap) -> Response {
    match need(&app, &t, &h).await {
        Ok(w) => account(&app, &w, lang(&app, &h), Notice::None, Default::default()).await,
        Err(r) => r,
    }
}

/// Language chosen in the account page: a plain cookie, so the login page and the public links follow it too.
async fn account_language(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = need_form(&app, &t, &h, &body).await {
        return r;
    }
    let code = form_field(&body, "lang").unwrap_or_default();
    let value = if code == "fr" { "fr" } else { "en" };
    let mut r = see_other("/web/account#langue");
    if let Ok(v) = set_cookie(&app, &cookie_name(&app, "lang"), value, 31_536_000).parse() {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    r
}

async fn account_password(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let lang = lang(&app, &h);
    let (Some(cur), Some(new)) = (form_field(&body, "current"), form_field(&body, "new")) else {
        return account(
            &app,
            &w,
            lang,
            Notice::Password(StatusCode::BAD_REQUEST, "Missing fields."),
            Default::default(),
        )
        .await;
    };
    match change_password(&app, &t, ip, &w, cur, new).await {
        Ok((code, msg)) => account(&app, &w, lang, Notice::Password(code, msg), Default::default()).await,
        Err(r) => r,
    }
}

/// The user replaces their password, giving the current one (account page, `/web/welcome`): failures limited per IP,
/// argon2id bounded, rules of `admin::weakness`. Success ends the account's web sessions, this one included.
/// `Err`: a response to send as is (too many failures, server busy).
async fn change_password(
    app: &Arc<App>,
    t: &TenantCtx,
    ip: ClientIp,
    w: &WebUser,
    cur: String,
    new: String,
) -> Result<(StatusCode, &'static str), Response> {
    if t.failures().ip_blocked(ip.0) {
        return Err(too_many());
    }
    let Ok(Ok(_permit)) = tokio::time::timeout(Duration::from_secs(2), app.argon.acquire()).await else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "5")]).into_response());
    };
    let (app2, u) = (app.clone(), w.u.clone());
    let r = blocking(move || -> crate::Result<Option<Result<String, crate::admin::Weak>>> {
        if auth::verify_human(&app2.db, u.tenant(), u.user(), &cur, &app2.dummy_hash)?.is_none() {
            return Ok(None);
        }
        let min = app2.settings.min_password;
        crate::admin::user_passwd(&app2.db, u.tenant(), u.user(), Some(&new), min, false).map(Some)
    })
    .await;
    Ok(match r {
        Ok(Ok(Some(Ok(_)))) => {
            tracing::info!(tenant = t.name(), user = w.u.user(), "password changed");
            (StatusCode::OK, "Password changed. Use it the next time you sign in.")
        }
        Ok(Ok(None)) => {
            t.failures().record_ip(ip.0);
            (StatusCode::UNAUTHORIZED, "Wrong current password: nothing was changed.")
        }
        Ok(Ok(Some(Err(weak)))) => (StatusCode::BAD_REQUEST, weak.message()),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Cannot change it right now: nothing was changed.",
        ),
    })
}

// ---------------------------------------------------------------- two-step verification

use crate::auth::totp;

/// QR code and key (groups of 4) for `secret`; the issuer is the host name the user signs in to.
fn totp_qr(lang: Lang, origin: &Base, user: &str, secret: &[u8]) -> (String, String) {
    let host = origin.0.split_once("://").map_or(origin.0.as_str(), |x| x.1);
    let qr = qr_svg(lang, &totp::uri(host, user, secret)).unwrap_or_default();
    (qr, totp::grouped(&totp::base32(secret)))
}

/// Refusal when the tenant does not offer two-step verification.
fn totp_not_offered(lang: Lang) -> Response {
    message(
        lang,
        StatusCode::FORBIDDEN,
        lang.t("Refused"),
        lang.t("Two-step verification is not offered in this space."),
        "/web/account",
    )
}

/// `POST /web/account/2fa/start`: shows the QR code to scan (its secret is derived from the session: nothing stored
/// until a code confirms it).
async fn totp_start(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(origin): Extension<Base>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let lang = lang(&app, &h);
    if app.settings.two_factor(t.name()) == crate::config::TwoFactor::Off {
        return totp_not_offered(lang);
    }
    if w.totp {
        let n = Notice::TwoFa(StatusCode::CONFLICT, "Two-step verification is already on.");
        return account(&app, &w, lang, n, Default::default()).await;
    }
    let setup = totp_qr(lang, &origin, w.u.user(), &totp::setup_secret(&t, &w.secret));
    let tf = TwoFaExtra {
        setup: Some(setup),
        ..Default::default()
    };
    account_tf(&app, &w, lang, Notice::None, Default::default(), tf).await
}

/// Confirms a setup with a code from the app: stores the secret and returns the recovery codes, shown once. Wrong
/// code: nothing stored, failure counted for the IP. `Err`: a response to send as is.
async fn totp_setup_confirm(
    app: &Arc<App>,
    t: &TenantCtx,
    ip: ClientIp,
    w: &WebUser,
    body: &[u8],
) -> Result<Option<Vec<String>>, Response> {
    if t.failures().ip_blocked(ip.0) {
        return Err(too_many());
    }
    let code = form_field(body, "code").unwrap_or_default();
    let secret = totp::setup_secret(t, &w.secret);
    let (app2, u) = (app.clone(), w.u.clone());
    let now = totp::now();
    let keep = t.mac(w.secret.as_bytes());
    // Turned on: the account's other web sessions end (one opened with a stolen password must not outlive it).
    let r = blocking(move || -> crate::Result<Option<Vec<String>>> {
        let codes = auth::totp_enable(&app2.db, u.tenant(), u.user(), &secret, &code, now)?;
        if codes.is_some() {
            app2.db.session_delete_others(u.tenant(), u.user(), &keep)?;
        }
        Ok(codes)
    });
    match r.await {
        Ok(Ok(Some(codes))) => {
            tracing::info!(tenant = t.name(), user = w.u.user(), "two-step verification on");
            Ok(Some(codes))
        }
        Ok(Ok(None)) => {
            t.failures().record_ip(ip.0);
            Ok(None)
        }
        _ => Err(StatusCode::SERVICE_UNAVAILABLE.into_response()),
    }
}

/// `POST /web/account/2fa/confirm`: the code from the app turns it on.
async fn totp_confirm(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(origin): Extension<Base>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let mut w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let lang = lang(&app, &h);
    if app.settings.two_factor(t.name()) == crate::config::TwoFactor::Off {
        return totp_not_offered(lang);
    }
    if w.totp {
        let n = Notice::TwoFa(StatusCode::CONFLICT, "Two-step verification is already on.");
        return account(&app, &w, lang, n, Default::default()).await;
    }
    match totp_setup_confirm(&app, &t, ip, &w, &body).await {
        Ok(Some(codes)) => {
            w.totp = true;
            let n = Notice::TwoFa(StatusCode::OK, "Two-step verification is on.");
            let tf = TwoFaExtra {
                recovery: codes,
                ..Default::default()
            };
            account_tf(&app, &w, lang, n, Default::default(), tf).await
        }
        Ok(None) => {
            let n = Notice::TwoFa(
                StatusCode::BAD_REQUEST,
                "Wrong code: check that the phone is on time and try again.",
            );
            let setup = totp_qr(lang, &origin, w.u.user(), &totp::setup_secret(&t, &w.secret));
            let tf = TwoFaExtra {
                setup: Some(setup),
                ..Default::default()
            };
            account_tf(&app, &w, lang, n, Default::default(), tf).await
        }
        Err(r) => r,
    }
}

/// What a password-and-code action got wrong.
enum Proof {
    Password,
    Code,
}

/// `POST /web/account/2fa`: new recovery codes (`op=codes`) or turn off (`op=off`, refused when the tenant requires
/// it). Both need the password and a code (TOTP or recovery): a stolen session alone is not enough.
async fn totp_manage(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let mut w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let lang = lang(&app, &h);
    let notice = |c, m| Notice::TwoFa(c, m);
    if !w.totp {
        let n = notice(StatusCode::CONFLICT, "Two-step verification is off.");
        return account(&app, &w, lang, n, Default::default()).await;
    }
    let op = form_field(&body, "op").unwrap_or_default();
    // The password when the account has one; an account bound to single sign-on has none, its code is the proof.
    let pw = if w.has_password {
        form_field(&body, "password")
    } else {
        Some(String::new())
    };
    let (Some(pw), Some(code), true) = (pw, form_field(&body, "code"), op == "codes" || op == "off") else {
        let n = notice(StatusCode::BAD_REQUEST, "Missing fields.");
        return account(&app, &w, lang, n, Default::default()).await;
    };
    if op == "off" && app.settings.two_factor(t.name()) == crate::config::TwoFactor::Required {
        let n = notice(
            StatusCode::FORBIDDEN,
            "Required for this space by the administrator: it cannot be turned off.",
        );
        return account(&app, &w, lang, n, Default::default()).await;
    }
    if t.failures().ip_blocked(ip.0) || t.failures().code_blocked(w.u.user()) {
        return too_many();
    }
    let Ok(Ok(_permit)) = tokio::time::timeout(Duration::from_secs(2), app.argon.acquire()).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "5")]).into_response();
    };
    let (app2, u, has_password) = (app.clone(), w.u.clone(), w.has_password);
    let off = op == "off";
    let now = totp::now();
    let r = blocking(move || -> crate::Result<Result<Option<Vec<String>>, Proof>> {
        let (db, t, user) = (&app2.db, u.tenant(), u.user());
        if has_password && auth::verify_human(db, t, user, &pw, &app2.dummy_hash)?.is_none() {
            return Ok(Err(Proof::Password));
        }
        if auth::verify_second(db, t, user, &code, now)? == auth::Second::Wrong {
            return Ok(Err(Proof::Code));
        }
        if off {
            db.totp_disable(t, user)?;
            return Ok(Ok(None));
        }
        auth::recovery_renew(db, t, user).map(|c| Ok(Some(c)))
    })
    .await;
    match r {
        Ok(Ok(Ok(None))) => {
            tracing::info!(tenant = t.name(), user = w.u.user(), "two-step verification off");
            w.totp = false;
            let n = notice(StatusCode::OK, "Two-step verification is off.");
            account(&app, &w, lang, n, Default::default()).await
        }
        Ok(Ok(Ok(Some(codes)))) => {
            tracing::info!(tenant = t.name(), user = w.u.user(), "new recovery codes");
            let n = notice(StatusCode::OK, "New recovery codes: the old ones no longer work.");
            let tf = TwoFaExtra {
                recovery: codes,
                ..Default::default()
            };
            account_tf(&app, &w, lang, n, Default::default(), tf).await
        }
        Ok(Ok(Err(Proof::Password))) => {
            t.failures().record_ip(ip.0);
            let n = notice(StatusCode::UNAUTHORIZED, "Wrong password: nothing was changed.");
            account(&app, &w, lang, n, Default::default()).await
        }
        Ok(Ok(Err(Proof::Code))) => {
            t.failures().record_ip(ip.0);
            t.failures().record_code(w.u.user());
            let n = notice(StatusCode::UNAUTHORIZED, "Wrong code: nothing was changed.");
            account(&app, &w, lang, n, Default::default()).await
        }
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[derive(Template)]
#[template(path = "twofa-setup.html")]
struct TwoFaSetupPage {
    lang: Lang,
    csrf: String,
}

/// The page a session of a `required` tenant without two-step verification is held on. Binding a first phone with the
/// password alone would let whoever has the password bind theirs: it is done only from an activation link the
/// administrator gives (`web::activate`); this page says so, and offers to sign out.
fn totp_setup_page(lang: Lang, code: StatusCode, w: &WebUser) -> Response {
    html(
        code,
        &TwoFaSetupPage {
            lang,
            csrf: w.csrf.clone(),
        },
    )
}

/// `GET /web/2fa-setup`: the tenant requires two-step verification and the account has none yet.
async fn totp_setup(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, h: HeaderMap) -> Response {
    match need_gate(&app, &t, &h, TOTP_SETUP).await {
        Ok(w) => totp_setup_page(lang(&app, &h), StatusCode::OK, &w),
        Err(r) => r,
    }
}

/// `POST /web/2fa-setup`: refused — a first phone is bound only through an activation link.
async fn totp_setup_post(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, h: HeaderMap) -> Response {
    match need_gate(&app, &t, &h, TOTP_SETUP).await {
        Ok(w) => {
            tracing::warn!(
                tenant = t.name(),
                user = w.u.user(),
                "two-step setup without an activation link: refused"
            );
            totp_setup_page(lang(&app, &h), StatusCode::FORBIDDEN, &w)
        }
        Err(r) => r,
    }
}

#[derive(Template)]
#[template(path = "login-code.html")]
struct LoginCodePage<'a> {
    lang: Lang,
    message: &'a str,
    csrf: &'a str,
    next: String,
}

/// `GET /login/code`: second step of the sign-in.
async fn login_code(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, q: Uri, h: HeaderMap) -> Response {
    let next = after_login(form_field(q.query().unwrap_or("").as_bytes(), "next"));
    match need_gate(&app, &t, &h, LOGIN_CODE).await {
        Ok(w) => {
            let page = LoginCodePage {
                lang: lang(&app, &h),
                message: "",
                csrf: &w.csrf,
                next,
            };
            html(StatusCode::OK, &page)
        }
        Err(r) => r,
    }
}

/// `POST /login/code`: a TOTP code or a recovery code. Success replaces the waiting session with a full one (new
/// secret); failures are counted per IP and per account (5 per 15 minutes, all IPs combined).
async fn login_code_post(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let w = match need_gate(&app, &t, &h, LOGIN_CODE).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let lang = lang(&app, &h);
    let next = after_login(form_field(&body, "next"));
    let page = |code, message: &str| {
        let p = LoginCodePage {
            lang,
            message,
            csrf: &w.csrf,
            next: next.clone(),
        };
        html(code, &p)
    };
    if !csrf_ok(form_field(&body, "csrf").as_deref(), &w.csrf) {
        return page(StatusCode::FORBIDDEN, lang.t("Invalid form token: reload the page."));
    }
    let Some(input) = form_field(&body, "code").or_else(|| form_field(&body, "recovery")) else {
        return page(StatusCode::BAD_REQUEST, lang.t("Missing fields."));
    };
    if t.failures().ip_blocked(ip.0) || t.failures().code_blocked(w.u.user()) {
        return too_many();
    }
    let (app2, u, old) = (app.clone(), w.u.clone(), w.secret.clone());
    let now = totp::now();
    let r = blocking(move || -> crate::Result<Option<(auth::Second, String)>> {
        let s = auth::verify_second(&app2.db, u.tenant(), u.user(), &input, now)?;
        if s == auth::Second::Wrong {
            return Ok(None);
        }
        auth::end_session(&app2.db, u.tenant(), &old)?;
        Ok(Some((s, auth::new_session(&app2.db, &u)?)))
    })
    .await;
    match r {
        Ok(Ok(Some((s, secret)))) => {
            if s == auth::Second::Recovery {
                tracing::warn!(tenant = t.name(), user = w.u.user(), "sign-in with a recovery code");
            }
            let c = set_cookie(&app, &cookie_name(&app, "sess"), &secret, auth::SESSION_TTL);
            let to = if next.is_empty() {
                "/web/files/".to_owned()
            } else {
                next
            };
            (StatusCode::SEE_OTHER, [(header::LOCATION, to), (header::SET_COOKIE, c)]).into_response()
        }
        Ok(Ok(None)) => {
            tracing::warn!(tenant = t.name(), ip = %ip.0, user = w.u.user(), "second step: wrong code");
            t.failures().record_ip(ip.0);
            t.failures().record_code(w.u.user());
            page(StatusCode::UNAUTHORIZED, lang.t("Wrong or already used code."))
        }
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// The only page of a session whose password was set by the administrator (account created, `user passwd`).
const WELCOME: &str = "/web/welcome";

#[derive(Template)]
#[template(path = "welcome.html")]
struct WelcomePage<'a> {
    lang: Lang,
    user: &'a str,
    csrf: &'a str,
    message: &'a str,
    min_password: usize,
}

fn welcome_page(app: &App, lang: Lang, w: &WebUser, code: StatusCode, message: &str) -> Response {
    let page = WelcomePage {
        lang,
        user: w.u.user(),
        csrf: &w.csrf,
        message,
        min_password: app.settings.min_password,
    };
    html(code, &page)
}

/// `GET /web/welcome`: choose one's password; a session that already has its own goes to the files.
async fn welcome(State(app): State<Arc<App>>, Extension(t): Extension<TenantCtx>, h: HeaderMap) -> Response {
    match need_gate(&app, &t, &h, WELCOME).await {
        Ok(w) => welcome_page(&app, lang(&app, &h), &w, StatusCode::OK, ""),
        Err(r) => r,
    }
}

/// `POST /web/welcome`: the password received, the new one twice. Success: every session ends, sign in again.
async fn welcome_post(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = lang(&app, &h);
    let w = match need_gate(&app, &t, &h, WELCOME).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if !csrf_ok(form_field(&body, "csrf").as_deref(), &w.csrf) {
        return welcome_page(
            &app,
            lang,
            &w,
            StatusCode::FORBIDDEN,
            lang.t("Invalid form token: reload the page."),
        );
    }
    let (Some(cur), Some(new), Some(again)) = (
        form_field(&body, "current"),
        form_field(&body, "new"),
        form_field(&body, "again"),
    ) else {
        return welcome_page(&app, lang, &w, StatusCode::BAD_REQUEST, lang.t("Missing fields."));
    };
    if new != again {
        let m = lang.t("The two new passwords differ: nothing was changed.");
        return welcome_page(&app, lang, &w, StatusCode::BAD_REQUEST, m);
    }
    match change_password(&app, &t, ip, &w, cur, new).await {
        Ok((StatusCode::OK, _)) => {
            let c = set_cookie(&app, &cookie_name(&app, "sess"), "", 0);
            let page = message(
                lang,
                StatusCode::OK,
                lang.t("Password chosen"),
                lang.t("Sign in again with your new password."),
                "/login",
            );
            ([(header::SET_COOKIE, c)], page).into_response()
        }
        Ok((code, msg)) => welcome_page(&app, lang, &w, code, lang.t(msg)),
        Err(r) => r,
    }
}

/// The Account page after a refused `Reproof`: nothing created.
async fn unproven(app: &Arc<App>, w: &WebUser, lang: Lang, e: Unproven) -> Response {
    match e {
        Unproven::Wrong => {
            let n = Notice::Tokens(StatusCode::UNAUTHORIZED, "Wrong password or code: nothing was created.");
            account(app, w, lang, n, Default::default()).await
        }
        Unproven::TooMany => too_many(),
        Unproven::Stale => sign_in_again(app, w, "/web/account").await,
        Unproven::Busy => (StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "5")]).into_response(),
    }
}

/// `POST /web/account/tokens`: a new app password, after the `Reproof`.
async fn token_create(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let lang = lang(&app, &h);
    if let Err(e) = reproof(&app, &w, ip, &body, crate::db::now_secs()).await {
        return unproven(&app, &w, lang, e).await;
    }
    let label: String = form_field(&body, "label")
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    let (app2, u) = (app.clone(), w.u.clone());
    match blocking(move || auth::new_app_password(&app2.db, u.tenant(), u.user(), &label)).await {
        Ok(Ok(secret)) => {
            account(
                &app,
                &w,
                lang,
                Notice::Tokens(StatusCode::OK, "App password created."),
                (secret, String::new()),
            )
            .await
        }
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// The QR code of a login: dark on light (scanners need it), drawn as inline SVG.
pub(crate) fn qr_svg(lang: Lang, content: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::with_error_correction_level(content, qrcode::EcLevel::M).ok()?;
    let img = code.render::<svg::Color>().quiet_zone(false).build();
    let start = img.find("<svg ")?;
    Some(img.get(start..)?.replacen(
        "<svg ",
        &format!("<svg role=\"img\" aria-label=\"{}\" ", lang.t("Login QR code")),
        1,
    ))
}

/// `POST /web/account/qr`: a QR code to connect the Nextcloud mobile app, holding a new app password that is gone
/// after 10 minutes if unused; a new one cancels the previous one not used yet. After the `Reproof`.
async fn qr_create(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(origin): Extension<Base>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let lang = lang(&app, &h);
    if let Err(e) = reproof(&app, &w, ip, &body, crate::db::now_secs()).await {
        return unproven(&app, &w, lang, e).await;
    }
    let label = lang.t("Mobile app (QR code)");
    let (app2, u) = (app.clone(), w.u.clone());
    let Ok(Ok(secret)) = blocking(move || auth::new_qr_password(&app2.db, u.tenant(), u.user(), label)).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(qr) = qr_svg(lang, &auth::qr_login(w.u.user(), &secret, &origin.0)) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    tracing::info!(tenant = t.name(), user = w.u.user(), "mobile app QR code shown");
    account(&app, &w, lang, Notice::None, (String::new(), qr)).await
}

async fn token_revoke(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let w = match need_form(&app, &t, &h, &body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let lang = lang(&app, &h);
    let id = form_field(&body, "id").unwrap_or_default();
    let (app2, u) = (app.clone(), w.u.clone());
    let r = blocking(move || app2.db.token_delete(u.tenant(), u.user(), &id)).await;
    let notice = if matches!(r, Ok(Ok(true))) {
        Notice::Tokens(StatusCode::OK, "App password revoked.")
    } else {
        Notice::Tokens(StatusCode::NOT_FOUND, "App password not found.")
    };
    account(&app, &w, lang, notice, Default::default()).await
}
