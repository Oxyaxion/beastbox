//! Nextcloud endpoints (§7): status, capabilities, cloud/user, Login Flow v2, unimplemented OCS.

use crate::auth;
use crate::http::{App, Base, ClientIp, blocking, form_field, require_user, too_many};
use crate::i18n::Lang;
use crate::tenant::TenantCtx;
use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `GET /status.php`, unauthenticated. Announced version: `nextcloud_version` from the configuration.
pub async fn status(State(app): State<Arc<App>>) -> Response {
    let [ma, mi, mc] = app.settings.nc_version;
    json(
        StatusCode::OK,
        format!(
            r#"{{"installed":true,"maintenance":false,"needsDbUpgrade":false,"version":"{ma}.{mi}.{mc}.0","versionstring":"{ma}.{mi}.{mc}","edition":"","productname":"Nextcloud","extendedSupport":false}}"#
        ),
    )
}

pub mod share;
#[cfg(test)]
mod share_model;
pub mod thumb;

/// `GET /index.php/core/preview?fileId=…&x=…&y=…` (desktop and Android clients): a thumbnail of a JPEG photo, computed
/// on request and never stored (`thumb`), found by `oc:fileid` in the user's own index. At most `THUMB_CONCURRENCY`
/// decodings at once; beyond 10 s of waiting, 503 (the client asks again later). Anything else (other type, unknown
/// or stale `fileId`, corrupt or too big image): 404, the client keeps its icon.
pub async fn preview(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    uri: Uri,
    h: HeaderMap,
) -> Response {
    let u = match require_user(&app, &t, ip, &h).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let q = uri.query().unwrap_or("");
    let arg = |k: &str| q.split('&').find_map(|kv| kv.strip_prefix(k)?.strip_prefix('='));
    // `<fileid>ocbeastbox` (`oc:id`) or the bare number (`oc:fileid`).
    let id = arg("fileId").and_then(|v| {
        let digits = v
            .find(|c: char| !c.is_ascii_digit())
            .map_or(v, |n| v.get(..n).unwrap_or(""));
        digits.parse::<u64>().ok()
    });
    let side = |k| arg(k).and_then(|v| v.parse::<u16>().ok()).unwrap_or(0);
    let side = side("x").max(side("y"));
    let Some(id) = id.filter(|_| side > 0) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(Ok(_permit)) = tokio::time::timeout(Duration::from_secs(10), app.thumbs.acquire()).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let found = blocking(move || -> std::io::Result<Option<(Vec<u8>, String)>> {
        let root = u.root()?;
        let q = crate::index::Query {
            fileid: Some(id),
            files_named: Some(|n| {
                let n = n.to_ascii_lowercase();
                n.ends_with(".jpg") || n.ends_with(".jpeg")
            }),
            ..Default::default()
        };
        let hits = u.tenant().index().search(u.user(), &root, &q)?.hits;
        let Some(p) = hits.first().and_then(|h| crate::fs::SafePath::new(&h.path).ok()) else {
            return Ok(None);
        };
        let (f, m) = root.open_file(&p)?;
        // Replaced since indexing: never another file's thumbnail.
        if crate::etag::fileid(&m) != id {
            return Ok(None);
        }
        Ok(thumb::make(f, side).map(|t| (t, crate::etag::of(&m))))
    })
    .await;
    match found {
        Ok(Ok(Some((jpeg, etag)))) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "image/jpeg".to_owned()),
                (header::ETAG, format!("\"{etag}\"")),
                (header::CACHE_CONTROL, "private, max-age=3600".to_owned()),
            ],
            jpeg,
        )
            .into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::warn!(tenant = t.name(), "preview: {e}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(r) => r,
    }
}

/// `GET /index.php/204`: the clients' connectivity test.
pub async fn no_content() -> StatusCode {
    StatusCode::NO_CONTENT
}

fn json(code: StatusCode, body: String) -> Response {
    (code, [(header::CONTENT_TYPE, "application/json; charset=utf-8")], body).into_response()
}

/// OCS envelope; v1 returns 100, v2 the HTTP code. Always JSON.
/// shortcut: OCS's XML format (without `?format=json`) is not produced; observed clients ask for JSON.
fn ocs(v2: bool, code: StatusCode, data: &str) -> Response {
    let (status, sc, msg) = match (code.is_success(), v2) {
        (true, true) => ("ok", 200, "OK"),
        (true, false) => ("ok", 100, "OK"),
        (false, _) => ("failure", 998, "Invalid query"),
    };
    json(
        code,
        format!(
            r#"{{"ocs":{{"meta":{{"status":"{status}","statuscode":{sc},"message":"{msg}","totalitems":"","itemsperpage":""}},"data":{data}}}}}"#
        ),
    )
}

fn is_v2(uri: &Uri) -> bool {
    uri.path().starts_with("/ocs/v2.php/")
}

/// Capabilities: only what is really implemented (§7): chunked upload v2, SHA-1 sums.
pub async fn capabilities(State(app): State<Arc<App>>, uri: Uri) -> Response {
    let [ma, mi, mc] = app.settings.nc_version;
    ocs(
        is_v2(&uri),
        StatusCode::OK,
        &format!(
            r#"{{"version":{{"major":{ma},"minor":{mi},"micro":{mc},"string":"{ma}.{mi}.{mc}","edition":"","extendedSupport":false}},"capabilities":{{"core":{{"pollinterval":60,"webdav-root":"remote.php/webdav"}},"dav":{{"chunking":"1.0"}},"files":{{"undelete":true}},"checksums":{{"supportedTypes":["SHA1"],"preferredUpdateType":"SHA1"}},{sharing}}}}}"#,
            sharing = share::CAPABILITIES
        ),
    )
}

/// `cloud/user`: identity and quota (read from the user's dataset, which reflects the ZFS quota).
pub async fn cloud_user(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    uri: Uri,
    h: HeaderMap,
) -> Response {
    let u = match require_user(&app, &t, ip, &h).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let space = blocking({
        let u = u.clone();
        move || u.root().and_then(|r| r.space())
    })
    .await;
    let Ok(Ok(s)) = space else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let total = s.available.saturating_add(s.used);
    let rel = if total == 0 {
        0.0
    } else {
        s.used as f64 * 100.0 / total as f64
    };
    // Validated user name ([a-z0-9_.-]): nothing to escape in JSON.
    let id = u.user();
    let language = crate::i18n::Lang::from(&h, None).code();
    ocs(
        is_v2(&uri),
        StatusCode::OK,
        &format!(
            r#"{{"enabled":true,"id":"{id}","display-name":"{id}","displayname":"{id}","email":null,"backend":"Database","groups":[],"subadmin":[],"language":"{language}","locale":"","quota":{{"free":{},"used":{},"total":{total},"relative":{rel:.2},"quota":{total}}}}}"#,
            s.available, s.used
        ),
    )
}

/// Unimplemented OCS (notifications, user_status, …): 404 in the right format, never a 500, logged (§7).
pub async fn ocs_unknown(Extension(t): Extension<TenantCtx>, uri: Uri) -> Response {
    tracing::info!(tenant = t.name(), path = uri.path(), "OCS not implemented");
    ocs(is_v2(&uri), StatusCode::NOT_FOUND, "[]")
}

// ---------------------------------------------------------------- Login Flow v2

const FLOW_TTL: Duration = Duration::from_secs(20 * 60);
/// Flows per tenant: bounded (§0.4); full, the oldest one still waiting for its confirmation makes room (503 only when
/// every flow is confirmed and waits for its poll).
pub(crate) const MAX_FLOWS: usize = 256;
/// Pending flows per address (an IPv6 /64), 429 beyond: one address cannot churn the tenant's table by itself.
const FLOWS_PER_IP: usize = 4;

#[derive(Debug)]
struct Flow {
    login_mac: [u8; 32],
    poll_mac: [u8; 32],
    expires: Instant,
    /// IP that opened the flow (per-IP limit).
    ip: std::net::IpAddr,
    /// Name of the app password created, from the User-Agent of the client that opened the flow.
    label: String,
    /// (user, app password) once confirmed, until the poll (single use).
    done: Option<(String, String)>,
    /// A confirmation is creating its app password: another one at the same time creates nothing.
    claimed: bool,
}

/// Login Flow state of a tenant (in memory: a restart cancels pending flows).
#[derive(Debug, Default)]
pub struct Flows(Mutex<Vec<Flow>>);

impl Flows {
    fn with<R>(&self, f: impl FnOnce(&mut Vec<Flow>) -> R) -> Option<R> {
        let mut v = self.0.lock().ok()?;
        let now = Instant::now();
        v.retain(|x| x.expires > now);
        Some(f(&mut v))
    }
}

#[cfg(test)]
impl Flows {
    /// Tests: marks every pending flow as being confirmed (the moment between the claim and the app password);
    /// returns how many.
    pub(crate) fn claim_pending(&self) -> usize {
        self.with(|v| {
            v.iter_mut()
                .filter(|f| f.done.is_none())
                .map(|f| f.claimed = true)
                .count()
        })
        .unwrap_or(0)
    }

    /// Tests: how many flows are being confirmed, and the shortest life left.
    pub(crate) fn claimed_and_shortest_life(&self) -> (usize, Option<Duration>) {
        self.with(|v| {
            let now = Instant::now();
            (
                v.iter().filter(|f| f.claimed && f.done.is_none()).count(),
                v.iter().map(|f| f.expires - now).min(),
            )
        })
        .unwrap_or((0, None))
    }
}

/// `POST /index.php/login/v2` (anonymous).
pub async fn flow_start(
    Extension(t): Extension<TenantCtx>,
    Extension(base): Extension<Base>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
) -> Response {
    let (Ok(poll), Ok(login)) = (auth::random_hex::<32>(), auth::random_hex::<32>()) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let flow = Flow {
        login_mac: t.mac(login.as_bytes()),
        poll_mac: t.mac(poll.as_bytes()),
        expires: Instant::now() + FLOW_TTL,
        ip: ip.0,
        label: client_label(h.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("")),
        done: None,
        claimed: false,
    };
    // Flows of this IP still pending (not yet confirmed); a confirmed flow only waits for its poll.
    let added = t.flows().with(|v| {
        let key = auth::ip_key(ip.0);
        if v.iter()
            .filter(|f| auth::ip_key(f.ip) == key && f.done.is_none())
            .count()
            >= FLOWS_PER_IP
        {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        // Full (M5): the oldest flow still waiting for its confirmation makes room — never one already confirmed (its
        // client is about to poll), so a crowd of abandoned flows cannot keep a new client out.
        if v.len() >= MAX_FLOWS {
            let Some(oldest) = v.iter().position(|f| f.done.is_none() && !f.claimed) else {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            };
            v.remove(oldest);
        }
        v.push(flow);
        Ok(())
    });
    match added {
        Some(Ok(())) => {}
        Some(Err(StatusCode::TOO_MANY_REQUESTS)) => {
            tracing::warn!(tenant = t.name(), ip = %ip.0, "login flow: too many pending flows for this IP");
            return too_many();
        }
        _ => return (StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "60")]).into_response(),
    }
    let b = &base.0;
    json(
        StatusCode::OK,
        format!(
            r#"{{"poll":{{"token":"{poll}","endpoint":"{b}/index.php/login/v2/poll"}},"login":"{b}/index.php/login/v2/flow/{login}"}}"#
        ),
    )
}

/// Readable name of a client from its User-Agent, to recognize its app passwords (Account page).
/// `Mozilla/5.0 (Android) Nextcloud-android/35.0.2` → "Nextcloud Android 35.0.2";
/// `Mozilla/5.0 (Linux) mirall/3.11.0 (Nextcloud, linuxmint-7.0.0-43-generic …)` → "Nextcloud desktop 3.11.0 (linuxmint)".
/// Other client: its User-Agent, cleaned and truncated (shown escaped by the template).
fn client_label(ua: &str) -> String {
    let version = |after: &str| -> Option<String> {
        let v = ua.split(after).nth(1)?.split_whitespace().next()?;
        Some(
            v.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
                .take(24)
                .collect(),
        )
    };
    if let Some(v) = version("Nextcloud-android/") {
        return format!("Nextcloud Android {v}");
    }
    if let Some(v) = version("Nextcloud-iOS/") {
        return format!("Nextcloud iOS {v}");
    }
    if let Some(v) = version("mirall/") {
        let os: String = ua
            .split("(Nextcloud, ")
            .nth(1)
            .map(|s| {
                s.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
                    .take(24)
                    .collect()
            })
            .unwrap_or_default();
        return match os.is_empty() {
            true => format!("Nextcloud desktop {v}"),
            false => format!("Nextcloud desktop {v} ({os})"),
        };
    }
    let clean: String = ua.chars().filter(|c| !c.is_control()).take(64).collect();
    match clean.trim() {
        "" => "Login Flow v2".into(),
        s => s.to_owned(),
    }
}

/// `POST /index.php/login/v2/poll`: 404 until confirmed, then 200 only once.
pub async fn flow_poll(Extension(t): Extension<TenantCtx>, Extension(base): Extension<Base>, body: Bytes) -> Response {
    let Some(token) = form_field(&body, "token") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mac = t.mac(token.as_bytes());
    let got = t.flows().with(|v| {
        let i = v.iter().position(|f| f.poll_mac == mac && f.done.is_some())?;
        v.swap_remove(i).done
    });
    match got.flatten() {
        Some((user, pw)) => json(
            StatusCode::OK,
            format!(r#"{{"server":"{}","loginName":"{user}","appPassword":"{pw}"}}"#, base.0),
        ),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The client a pending flow was opened by: its label (from its User-Agent) and its IP, shown before authorizing.
fn flow_origin(t: &TenantCtx, login: &str) -> Option<(String, std::net::IpAddr)> {
    let mac = t.mac(login.as_bytes());
    t.flows()
        .with(|v| {
            v.iter()
                .find(|f| f.login_mac == mac && f.done.is_none())
                .map(|f| (f.label.clone(), f.ip))
        })
        .flatten()
}

/// Text for an HTML page built by hand (`page`): `& < > " '` escaped.
fn esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            c => c.to_string(),
        })
        .collect()
}

fn page(lang: Lang, code: StatusCode, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <title>Beastbox</title></head><body>{body}<footer><small>Powered by Beastbox</small></footer></body></html>",
        lang.code()
    );
    (
        code,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        html,
    )
        .into_response()
}

/// The confirmation form: who asks (the client's label and IP, escaped), a warning against links received from
/// someone else, the session's CSRF token, and the `Reproof` (password, code, or nothing when the sign-in is recent)
/// — a session and one click are not enough to hand out a permanent app password.
fn flow_form(lang: Lang, (label, ip): (&str, std::net::IpAddr), csrf: &str, field: &str, message: &str) -> String {
    let proof = match field {
        "password" => format!(
            "<p><label>{} <input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label></p>",
            lang.t("Your password")
        ),
        "code" => format!(
            "<p><label>{} <input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" maxlength=\"6\" required></label></p>",
            lang.t("Code from the app")
        ),
        _ => String::new(),
    };
    let message = if message.is_empty() {
        String::new()
    } else {
        format!("<p role=\"alert\"><strong>{}</strong></p>", esc(message))
    };
    format!(
        "<h1>{}</h1>{message}<p>{}</p><ul><li>{} <strong>{}</strong></li><li>{} <strong>{}</strong></li></ul>\
         <p><strong>{}</strong></p><form method=\"post\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">{proof}\
         <p><button type=\"submit\">{}</button></p></form>",
        lang.t("Connect a client"),
        lang.t("A client requests access to your files."),
        lang.t("Software:"),
        esc(label),
        lang.t("Requested from the address:"),
        esc(&ip.to_string()),
        lang.t("Only authorize it if you started this connection yourself, a moment ago, from this software. Otherwise close this page: whoever sent you this link would get access to all your files."),
        esc(csrf),
        lang.t("Authorize this client"),
    )
}

/// The web session behind a Login Flow page, or where to send the browser: `/login` (with the flow as `next`,
/// which `after_login` allows) when there is none — this is how an account without a password, signed in through
/// a provider, confirms a client — or the session's own gate.
async fn flow_session(
    app: &Arc<App>,
    t: &TenantCtx,
    h: &HeaderMap,
    next: &str,
) -> std::result::Result<crate::web::WebUser, Response> {
    match crate::web::session_any(app, t, h).await {
        None => Err(crate::web::see_other(&format!("/login?next={next}"))),
        Some(w) => match w.gate {
            None => Ok(w),
            Some(g) if g == crate::web::LOGIN_CODE => Err(crate::web::see_other(&format!("{g}?next={next}"))),
            Some(g) => Err(crate::web::see_other(g)),
        },
    }
}

/// `GET /index.php/login/v2/flow/{token}`: the confirmation page of a signed-in browser, otherwise the login
/// page (which also carries single sign-on).
pub async fn flow_page(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Path(login): Path<String>,
    h: HeaderMap,
) -> Response {
    let lang = Lang::from(&h, None);
    let Some((label, ip)) = flow_origin(&t, &login) else {
        return page(
            lang,
            StatusCode::NOT_FOUND,
            &format!("<p>{}</p>", lang.t("Unknown or expired login link.")),
        );
    };
    let next = format!("/index.php/login/v2/flow/{login}");
    match flow_session(&app, &t, &h, &next).await {
        Ok(w) => {
            let field = w.reproof().field();
            page(lang, StatusCode::OK, &flow_form(lang, (&label, ip), &w.csrf, field, ""))
        }
        Err(r) => r,
    }
}

/// `POST /index.php/login/v2/flow/{token}`: creates the app password of the signed-in account and hands it to the
/// flow, after CSRF (`from_another_site` + session `csrf`) and the `Reproof` — the URL token comes from the public
/// `/index.php/login/v2` endpoint, so an attacker can obtain one and it cannot serve as CSRF protection.
pub async fn flow_submit(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(origin_base): Extension<Base>,
    Extension(ip): Extension<ClientIp>,
    Path(login): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = Lang::from(&h, None);
    if crate::web::from_another_site(&h, &origin_base) {
        return page(
            lang,
            StatusCode::FORBIDDEN,
            &format!(
                "<p role=\"alert\"><strong>{}</strong></p>",
                esc(lang.t("This form must be sent from this site's own page."))
            ),
        );
    }
    let Some(origin) = flow_origin(&t, &login) else {
        return page(
            lang,
            StatusCode::NOT_FOUND,
            &format!("<p>{}</p>", lang.t("Unknown or expired login link.")),
        );
    };
    let next = format!("/index.php/login/v2/flow/{login}");
    let w = match flow_session(&app, &t, &h, &next).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if !crate::web::csrf_ok(form_field(&body, "csrf").as_deref(), &w.csrf) {
        let field = w.reproof().field();
        let m = lang.t("Invalid form token: reload the page.");
        let form = flow_form(lang, (&origin.0, origin.1), &w.csrf, field, m);
        return page(lang, StatusCode::FORBIDDEN, &form);
    }
    match crate::web::reproof(&app, &w, &h, ip, &body, crate::db::now_secs()).await {
        Ok(()) => {}
        Err(crate::web::Unproven::Wrong) => {
            let field = w.reproof().field();
            let m = lang.t("Wrong password or code: nothing was created.");
            let form = flow_form(lang, (&origin.0, origin.1), &w.csrf, field, m);
            return page(lang, StatusCode::UNAUTHORIZED, &form);
        }
        Err(crate::web::Unproven::TooMany) => return too_many(),
        Err(crate::web::Unproven::Stale) => return crate::web::sign_in_again(&app, &w, &next).await,
        Err(crate::web::Unproven::Busy) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    let user = w.u;
    let lmac = t.mac(login.as_bytes());
    // One confirmation per flow: the first takes it under the lock; another at the same time (double click, two tabs)
    // finds it taken and creates nothing.
    let taken = t.flows().with(|v| {
        v.iter_mut()
            .find(|f| f.login_mac == lmac && f.done.is_none() && !f.claimed)
            .map(|f| f.claimed = true)
            .is_some()
    });
    if taken != Some(true) {
        return page(
            lang,
            StatusCode::NOT_FOUND,
            &format!("<p>{}</p>", lang.t("Unknown or expired login link.")),
        );
    }
    let label = t
        .flows()
        .with(|v| v.iter().find(|f| f.login_mac == lmac).map(|f| f.label.clone()))
        .flatten()
        .unwrap_or_else(|| client_label(""));
    let r = blocking({
        let (app, t, user) = (app.clone(), t.clone(), user.clone());
        move || auth::new_app_password(&app.db, &t, user.user(), &label)
    })
    .await;
    let Ok(Ok(secret)) = r else {
        // Nothing created: the flow can be confirmed again.
        t.flows().with(|v| {
            v.iter_mut()
                .filter(|f| f.login_mac == lmac)
                .for_each(|f| f.claimed = false)
        });
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let name = user.user().to_owned();
    tracing::info!(tenant = t.name(), user = %name, "login flow: app password created");
    t.flows().with(|v| {
        if let Some(f) = v.iter_mut().find(|f| f.login_mac == lmac && f.done.is_none()) {
            f.done = Some((name, secret));
        }
    });
    page(
        lang,
        StatusCode::OK,
        &format!(
            "<h1>{}</h1><p>{}</p>",
            lang.t("Client connected"),
            lang.t("You can close this page.")
        ),
    )
}

#[cfg(test)]
mod label_tests {
    use super::client_label;

    #[test]
    fn labels_from_real_user_agents() {
        assert_eq!(
            client_label("Mozilla/5.0 (Android) Nextcloud-android/35.0.2"),
            "Nextcloud Android 35.0.2"
        );
        assert_eq!(
            client_label(
                "Mozilla/5.0 (Linux) mirall/3.11.0git (Nextcloud, linuxmint-7.0.0-43-generic ClientArchitecture: x86_64 OsArchitecture: x86_64)"
            ),
            "Nextcloud desktop 3.11.0git (linuxmint)"
        );
        assert_eq!(
            client_label(
                "Mozilla/5.0 (Linux) mirall/35.0.2daily (Nextcloud, org.kde.Platform-7.3.3-300.fc45.x86_64 ClientArchitecture: x86_64)"
            ),
            "Nextcloud desktop 35.0.2daily (org.kde.Platform)"
        );
        assert_eq!(client_label("rclone/v1.68\u{7}"), "rclone/v1.68");
        assert_eq!(client_label(""), "Login Flow v2");
        assert_eq!(client_label(&"x".repeat(500)).len(), 64);
    }
}
