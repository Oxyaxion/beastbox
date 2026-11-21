//! OIDC sign-in (§2, §9, phases 4-5): `GET /login/oidc` starts a flow — a MAC'd, stateless cookie
//! (`auth::oidc::Flow`) and a redirect to the provider's authorization endpoint — and
//! `GET /login/oidc/callback` finishes it: `state` in constant time, the code exchanged over the back
//! channel (`auth::oidc_net`), the `id_token` checked (`auth::oidc::check_id_token`), the account found by
//! its linked identity, then a session and a redirect to the flow's `next` (the `after_login` allowlist).
//!
//! The callback inherits the login's rate limit (§0.4): `ip_blocked`/`human_blocked` before anything, and
//! every refusal recorded. `redirect_uri` is built from the configuration (`OidcRuntime::base`), never from
//! the request's `Host` header. With `second_factor = "provider"`, an `amr` of `required_amr` is required in
//! the `id_token` and the account's own TOTP is not asked; with `"beastbox"`, the account's TOTP gate applies
//! (as for the password login).

use super::{LOGIN_CODE, after_login, cookie, cookie_name, param, see_other, set_cookie};
use crate::auth::{self, oidc, oidc_net};
use crate::config::{OidcRuntime, SecondFactor};
use crate::http::{App, Base, ClientIp, blocking, too_many};
use crate::tenant::TenantCtx;
use axum::Extension;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `GET /login/oidc?next=…`: start of the flow.
pub const LOGIN_OIDC: &str = "/login/oidc";
/// `GET /login/oidc/callback?code=…&state=…`: the provider sends the browser back here.
pub const CALLBACK: &str = "/login/oidc/callback";
/// Name (suffix) of the flow cookie.
const FLOW_COOKIE: &str = "oidc";
/// Longest accepted authorization `code` (bounded before any use).
const MAX_CODE: usize = 512;
/// After a failed discovery fetch, the routes answer 503 without a new fetch for this long (the `Retry-After`): an
/// anonymous request must not open a back-channel connection each time the provider is down.
const DISCOVERY_RETRY: Duration = Duration::from_secs(30);

fn unavailable() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "30")]).into_response()
}

/// A refusal: logged with its reason, answered without any detail (a redirect to the login page), and
/// counted in the tenant's failure limits (the login's rate limit, §0.4). A missing or forged flow cookie or `state`
/// costs the sender nothing and guesses nothing (both are keyed): it counts against its address only, never in the
/// tenant-wide limit, which a few addresses could otherwise fill to close every sign-in.
fn refuse(t: &TenantCtx, ip: ClientIp, why: oidc::Refusal) -> Response {
    tracing::warn!(tenant = t.name(), ip = %ip.0, "oidc callback refused: {why}");
    t.failures().record_ip(ip.0);
    if !matches!(why, oidc::Refusal::Cookie | oidc::Refusal::State) {
        t.failures().record_human();
    }
    see_other("/login")
}

/// The discovery document, fetched once over the back channel and kept for the process's life. A failed fetch is
/// remembered for `DISCOVERY_RETRY`: until then both routes answer 503 without reaching the provider. Fail closed on a
/// poisoned lock.
async fn discovery(app: &Arc<App>, o: &OidcRuntime) -> Result<oidc::Discovery, Response> {
    match o.discovery.lock().map(|g| g.clone()) {
        Ok(Some(Ok(d))) => return Ok(d),
        Ok(Some(Err(failed))) if failed.elapsed() < DISCOVERY_RETRY => return Err(unavailable()),
        Ok(_) => {}
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    }
    let r = oidc_net::fetch_discovery(&app.net, o).await;
    if let Err(why) = &r {
        tracing::warn!("oidc: discovery refused: {why}");
    }
    let Ok(mut g) = o.discovery.lock() else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };
    *g = Some(r.clone().map_err(|_| Instant::now()));
    r.map_err(|_| unavailable())
}

/// `GET /login/oidc?next=…`: the tenant has `[tenant.oidc]` (otherwise 404, like any unknown route), the
/// `next` goes through the same allowlist as the password login, a flow cookie is set, and the browser is
/// sent to the provider's authorization URL (`redirect_uri` = the configured base, never the `Host` header).
/// On another host of the tenant, the browser is first sent to the same route on the base host: the flow cookie
/// (`__Host-`) must be set on the host the provider sends the browser back to.
pub async fn start(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(here): Extension<Base>,
    q: Uri,
) -> Response {
    let Some(o) = t.oidc() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let next = after_login(param(&q, "next"));
    // Cookies ignore the scheme and the port: the host name alone decides.
    let host = |b: &str| b.split_once("://").and_then(|(_, h)| crate::tenant::normalize_host(h));
    if host(&here.0).is_none() || host(&here.0) != host(&o.base) {
        // `next` passed the allowlist: digits, hex and `/` only, safe in a query as is.
        let q = if next.is_empty() {
            String::new()
        } else {
            format!("?next={next}")
        };
        return see_other(&format!("{}{LOGIN_OIDC}{q}", o.base));
    }
    let now = crate::db::now_secs();
    let Ok(f) = oidc::new_flow(&t, &next, now) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let d = match discovery(&app, o).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    let url = oidc::authorize_url(&d, &o.client, &o.base, &f);
    let c = set_cookie(&app, &cookie_name(&app, FLOW_COOKIE), &f.cookie, oidc::FLOW_TTL);
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, url), (header::SET_COOKIE, c)],
    )
        .into_response()
}

/// `GET /login/oidc/callback?code=…&state=…[&iss=…]`: see the module doc. Success: a session cookie and a
/// redirect to the flow's `next` (the files page when empty); the flow cookie is cleared. Any refusal: the
/// login's rate limit records it and the browser goes back to `/login`, without any detail.
pub async fn callback(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    q: Uri,
    h: HeaderMap,
) -> Response {
    let Some(o) = t.oidc() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if t.failures().ip_blocked(ip.0) || t.failures().human_blocked() {
        return too_many();
    }
    let now = crate::db::now_secs();
    let flow_cookie = cookie(&h, &cookie_name(&app, FLOW_COOKIE)).unwrap_or("");
    let Some(flow) = oidc::read_flow(&t, flow_cookie, now) else {
        return refuse(&t, ip, oidc::Refusal::Cookie);
    };
    if !oidc::state_ok(&flow, param(&q, "state").unwrap_or_default().as_str()) {
        return refuse(&t, ip, oidc::Refusal::State);
    }
    let code = param(&q, "code")
        .filter(|c| (1..=MAX_CODE).contains(&c.len()) && c.bytes().all(|b| (0x21..=0x7e).contains(&b)));
    let Some(code) = code else {
        return refuse(&t, ip, oidc::Refusal::TokenResponse);
    };
    let d = match discovery(&app, o).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    // RFC 9207: when the provider says it echoes `iss`, the callback requires it.
    if d.iss_parameter && param(&q, "iss").as_deref() != Some(o.client.issuer.raw.as_str()) {
        return refuse(&t, ip, oidc::Refusal::Issuer);
    }
    let id_token = match oidc_net::exchange_code(&app.net, o, &d, &code, &flow).await {
        Ok(t) => t,
        Err(r) => return refuse(&t, ip, r),
    };
    let v = match oidc::check_id_token(&id_token, &o.client, &flow, now) {
        Ok(v) => v,
        Err(r) => return refuse(&t, ip, r),
    };
    // `second_factor = "provider"`: the provider's `amr` must carry a required method.
    if o.second_factor == SecondFactor::Provider
        && !o.required_amr.is_empty()
        && !o.required_amr.iter().any(|a| v.amr().contains(a))
    {
        return refuse(&t, ip, oidc::Refusal::Subject);
    }
    let (app2, t2, v2) = (app.clone(), t.clone(), v);
    let found = blocking(move || auth::user_by_oidc(&app2.db, &t2, &v2)).await;
    let user = match found {
        Ok(Ok(Some(u))) => u,
        Ok(Ok(None)) => return refuse(&t, ip, oidc::Refusal::Subject),
        _ => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    // Session, with the account's own TOTP gate when Beastbox holds the second factor (pending session → the
    // code page). With `second_factor = "provider"` the provider already did both: no second step here, the
    // `amr` check above is the second factor.
    let totp_gate = o.second_factor == SecondFactor::Beastbox;
    let r = blocking({
        let (app, t, user) = (app.clone(), t.clone(), user.clone());
        move || -> crate::Result<(String, bool)> {
            let pending = totp_gate && matches!(app.db.totp_get(&t, user.user())?, Some((Some(_), _)));
            let secret = if pending {
                auth::new_pending_session(&app.db, &user)?
            } else {
                auth::new_session(&app.db, &user)?
            };
            Ok((secret, pending))
        }
    })
    .await;
    let Ok(Ok((secret, pending))) = r else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let ttl = if pending { auth::PENDING_TTL } else { auth::SESSION_TTL };
    let to = match (pending, flow.next.is_empty()) {
        (true, true) => LOGIN_CODE.to_owned(),
        (true, false) => format!("{LOGIN_CODE}?next={}", flow.next),
        (false, true) => "/web/files/".to_owned(),
        (false, false) => flow.next.clone(),
    };
    let sess = set_cookie(&app, &cookie_name(&app, "sess"), &secret, ttl);
    let clear = set_cookie(&app, &cookie_name(&app, FLOW_COOKIE), "", 0);
    let mut res = see_other(&to);
    for c in [sess, clear] {
        if let Ok(v) = HeaderValue::from_str(&c) {
            res.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    res
}
