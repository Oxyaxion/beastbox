//! HTTP listener and deny-by-default route table (§0.3).
//!
//! Processing order: connection refused if the peer is not in `trusted_proxies` → security
//! headers → tenant resolution (400 / 421) → explicit route, otherwise 404 (405 if the method is not listed).

use crate::auth::{self, UserCtx};
use crate::db::Db;
use crate::tenant::{HostError, Registry, TenantCtx};
use crate::{dav, nc};
use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Concurrent argon2id hashes (§0.4): ~19 MiB each.
const ARGON_CONCURRENCY: usize = 2;
/// Thumbnails decoded at the same time (CPU and memory bounded, `nc::thumb`).
const THUMB_CONCURRENCY: usize = 2;
/// Buffered bodies (PROPFIND, forms): small by construction. File transfers are streamed.
const BODY_LIMIT: usize = 64 * 1024;

/// Shared server state.
pub struct App {
    pub registry: Registry,
    pub db: Db,
    pub argon: Semaphore,
    pub thumbs: Semaphore,
    pub drop_slots: crate::web::share::DropSlots,
    pub dummy_hash: String,
    pub settings: Settings,
    /// Outgoing channel of the OIDC back channel: direct in tests, Casper in production (`serve` sets it
    /// from the registry before Capsicum).
    pub net: crate::auth::oidc_net::Net,
}

/// Configuration settings needed by requests.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Announced Nextcloud version (status.php, capabilities).
    pub nc_version: [u16; 3],
    pub read_only: bool,
    pub min_free_bytes: u64,
    pub insecure_cookies: bool,
    pub drop_max_file_bytes: u64,
    pub drop_max_total_bytes: u64,
    pub drop_max_files: u32,
    pub trash_days: u32,
    pub share_history_days: u32,
    /// Minimum length of a chosen human password (≥ `admin::MIN_PASSWORD`).
    pub min_password: usize,
    /// Two-step verification per tenant name (absent: `optional`).
    pub two_factor: Vec<(String, crate::config::TwoFactor)>,
}

impl Settings {
    pub fn two_factor(&self, tenant: &str) -> crate::config::TwoFactor {
        self.two_factor
            .iter()
            .find(|(n, _)| n == tenant)
            .map_or(crate::config::TwoFactor::Optional, |x| x.1)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            nc_version: [35, 0, 0],
            read_only: false,
            min_free_bytes: 0,
            insecure_cookies: false,
            drop_max_file_bytes: 1 << 20,
            drop_max_total_bytes: 4 << 20,
            drop_max_files: 500,
            trash_days: 30,
            share_history_days: 365,
            min_password: 12,
            two_factor: Vec::new(),
        }
    }
}

impl App {
    pub fn new(registry: Registry, db: Db, settings: Settings) -> crate::Result<Self> {
        Ok(Self {
            registry,
            db,
            argon: Semaphore::new(ARGON_CONCURRENCY),
            thumbs: Semaphore::new(THUMB_CONCURRENCY),
            drop_slots: Default::default(),
            dummy_hash: auth::dummy_hash()?,
            settings,
            net: crate::auth::oidc_net::Net::Direct,
        })
    }
}

/// Address of the TCP peer (the proxy), set by the accept loop.
#[derive(Clone, Copy, Debug)]
struct Peer(IpAddr);

/// IP of the end client: `X-Real-IP` set by the trusted proxy, otherwise the peer. Used by the failure limits.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

/// `scheme://host[:port]` of the request, for every generated URL (§4): never another domain.
#[derive(Clone, Debug)]
pub struct Base(pub String);

/// Route table, by group (§0.3). Every entry is covered by the test audit (requires a tenant).
/// (a) public: status, 204, login flow, capabilities. (b) authenticated: OCS cloud/user, WebDAV.
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/status.php"),
    ("GET", "/index.php/204"),
    ("POST", "/index.php/login/v2"),
    ("POST", "/index.php/login/v2/poll"),
    ("GET", "/index.php/login/v2/flow/x"),
    ("POST", "/index.php/login/v2/flow/x"),
    ("GET", "/index.php/core/preview"),
    ("GET", "/index.php/f/1"),
    ("GET", "/ocs/v1.php/cloud/capabilities"),
    ("GET", "/ocs/v2.php/cloud/capabilities"),
    ("GET", "/ocs/v1.php/cloud/user"),
    ("GET", "/ocs/v2.php/cloud/user"),
    ("GET", "/ocs/v2.php/apps/notifications/api/v2/notifications"),
    ("GET", "/ocs/v2.php/apps/files_sharing/api/v1/shares"),
    ("POST", "/ocs/v1.php/apps/files_sharing/api/v1/shares"),
    ("PUT", "/ocs/v2.php/apps/files_sharing/api/v1/shares/1"),
    ("DELETE", "/ocs/v1.php/apps/files_sharing/api/v1/shares/1"),
    ("PROPFIND", "/remote.php/dav/files/alice"),
    ("PROPFIND", "/remote.php/dav/files/alice/"),
    ("GET", "/remote.php/dav/files/alice/x"),
    ("PROPFIND", "/remote.php/webdav"),
    ("PROPFIND", "/remote.php/webdav/"),
    ("GET", "/remote.php/webdav/x"),
    ("GET", "/remote.php/dav/avatars/alice/128.png"),
    ("MKCOL", "/remote.php/dav/uploads/alice/123"),
    ("PROPFIND", "/remote.php/dav/uploads/alice/123"),
    ("PROPFIND", "/remote.php/dav/trashbin/alice/trash"),
    ("SEARCH", "/remote.php/dav"),
    ("OPTIONS", "/remote.php/dav/"),
    // Web interface (J3): public (login, static files, links) and authenticated by session.
    ("GET", "/"),
    ("GET", "/login"),
    ("POST", "/login"),
    ("GET", "/login/oidc"),
    ("GET", "/login/oidc/callback"),
    ("POST", "/logout"),
    ("GET", "/static/app.css"),
    ("GET", "/static/app.js"),
    ("GET", "/static/theme.js"),
    ("GET", "/static/text.js"),
    ("GET", "/static/icons/folder.svg"),
    ("POST", "/web/bulk"),
    ("GET", "/web/files/"),
    ("GET", "/web/files/x/"),
    ("GET", "/web/search"),
    ("GET", "/web/favorites"),
    ("GET", "/web/activity"),
    ("GET", "/web/trash"),
    ("POST", "/web/trash/restore"),
    ("POST", "/web/trash/purge"),
    ("POST", "/web/trash/empty"),
    ("GET", "/web/tree/"),
    ("GET", "/web/tree/x/"),
    ("GET", "/web/view/x"),
    ("GET", "/web/edit/x"),
    ("POST", "/web/edit/x"),
    ("GET", "/web/raw/x"),
    ("GET", "/web/zip/"),
    ("PROPFIND", "/web/dav/"),
    ("POST", "/web/tags"),
    ("POST", "/web/favorite"),
    ("GET", "/web/shares"),
    ("POST", "/web/shares"),
    ("POST", "/web/shares/revoke"),
    ("GET", "/web/account"),
    ("POST", "/web/account/password"),
    ("POST", "/web/account/tokens"),
    ("POST", "/web/account/tokens/revoke"),
    ("GET", "/s/00000000000000000000000000000000"),
    ("POST", "/s/00000000000000000000000000000000"),
    ("GET", "/s/00000000000000000000000000000000/dl"),
    ("PUT", "/s/00000000000000000000000000000000/drop/x"),
];

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/status.php", get(nc::status))
        .route("/index.php/204", get(nc::no_content))
        .route("/index.php/login/v2", post(nc::flow_start))
        .route("/index.php/login/v2/poll", post(nc::flow_poll))
        .route(
            "/index.php/login/v2/flow/{token}",
            get(nc::flow_page).post(nc::flow_submit),
        )
        .route("/index.php/core/preview", get(nc::preview))
        .route("/index.php/f/{id}", get(crate::web::private_link))
        .route("/ocs/v1.php/cloud/capabilities", get(nc::capabilities))
        .route("/ocs/v2.php/cloud/capabilities", get(nc::capabilities))
        .route("/ocs/v1.php/cloud/user", get(nc::cloud_user))
        .route("/ocs/v2.php/cloud/user", get(nc::cloud_user))
        .route(
            "/ocs/v1.php/apps/files_sharing/api/v1/shares",
            get(nc::share::shares).post(nc::share::shares),
        )
        .route(
            "/ocs/v2.php/apps/files_sharing/api/v1/shares",
            get(nc::share::shares).post(nc::share::shares),
        )
        .route(
            "/ocs/v1.php/apps/files_sharing/api/v1/shares/{id}",
            get(nc::share::share).put(nc::share::share).delete(nc::share::share),
        )
        .route(
            "/ocs/v2.php/apps/files_sharing/api/v1/shares/{id}",
            get(nc::share::share).put(nc::share::share).delete(nc::share::share),
        )
        .route("/ocs/v1.php/{*rest}", any(nc::ocs_unknown))
        .route("/ocs/v2.php/{*rest}", any(nc::ocs_unknown))
        .route("/remote.php/dav/files/{user}", any(dav::files))
        .route("/remote.php/dav/files/{user}/", any(dav::files))
        .route("/remote.php/dav/files/{user}/{*path}", any(dav::files))
        .route("/remote.php/webdav", any(dav::webdav_root))
        .route("/remote.php/webdav/", any(dav::webdav_root))
        .route("/remote.php/webdav/{*path}", any(dav::webdav))
        .route("/remote.php/dav/uploads/{user}/{*path}", any(dav::uploads))
        .route("/remote.php/dav", any(dav::dav_root))
        .route("/remote.php/dav/", any(dav::dav_root))
        .route("/remote.php/dav/trashbin/{user}", any(dav::trashbin))
        .route("/remote.php/dav/trashbin/{user}/", any(dav::trashbin))
        .route("/remote.php/dav/trashbin/{user}/{*path}", any(dav::trashbin))
        .route("/remote.php/{*rest}", any(dav::remote_other))
        .merge(crate::web::routes())
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn(body_idle))
        .layer(middleware::from_fn_with_state(app.clone(), resolve_tenant))
        .layer(middleware::from_fn(security_headers))
        .with_state(app)
}

/// Runs a blocking call (disk, SQLite, argon2) off the async executor (§0.4).
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// App password required (§2). Database unavailable → 503 (fail closed, §0.3).
/// Repeated failures from an IP: 429 before any check (§2, §4).
pub fn too_many() -> Response {
    (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "300")]).into_response()
}

pub async fn require_user(app: &Arc<App>, t: &TenantCtx, ip: ClientIp, h: &HeaderMap) -> Result<UserCtx, Response> {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"Beastbox\", charset=\"UTF-8\"")],
            "App password required: connect the client through the Login Flow.",
        )
            .into_response()
    };
    let Some(v) = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return Err(unauthorized());
    };
    // Only failures are limited (§2): a valid app password goes through even from a blocked IP, otherwise
    // an old device with a revoked token, or typos, would cut off every device behind the same IP.
    // Safe: an app password is a 256-bit random secret (HMAC checked in microseconds,
    // never argon2), which no number of attempts can guess.
    let (app, t2, v) = (app.clone(), t.clone(), v.to_owned());
    match blocking(move || auth::verify_basic(&app.db, &t2, &v)).await? {
        Ok(Some(u)) => Ok(u),
        Ok(None) if t.failures().ip_blocked(ip.0) => Err(too_many()),
        Ok(None) => {
            tracing::warn!(tenant = t.name(), ip = %ip.0, "authentication refused");
            t.failures().record_ip(ip.0);
            Err(unauthorized())
        }
        Err(e) => {
            tracing::error!(tenant = t.name(), "authentification impossible : {e}");
            Err(StatusCode::SERVICE_UNAVAILABLE.into_response())
        }
    }
}

/// All the values of a repeated field (checkboxes of a selection), at most `max`.
pub fn form_values(body: &[u8], key: &str, max: usize) -> Vec<String> {
    let Ok(s) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    s.split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k != key {
                return None;
            }
            percent_encoding::percent_decode_str(&v.replace('+', " "))
                .decode_utf8()
                .ok()
                .map(|c| c.into_owned())
        })
        .take(max)
        .collect()
}

/// Field of an `application/x-www-form-urlencoded` body.
pub fn form_field(body: &[u8], key: &str) -> Option<String> {
    std::str::from_utf8(body).ok()?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k != key {
            return None;
        }
        percent_encoding::percent_decode_str(&v.replace('+', " "))
            .decode_utf8()
            .ok()
            .map(|c| c.into_owned())
    })
}

/// No byte of a request body for this long: the body ends in error, the reader stops (the write in progress is
/// thrown away, §0.2) and the connection is freed. Against slow uploads that hold connections (`max_connections`).
pub const BODY_IDLE: Duration = Duration::from_secs(60);

/// Every request body goes through `BODY_IDLE`, whatever reads it (uploads, chunks, forms, XML bodies).
async fn body_idle(req: Request, next: Next) -> Response {
    use futures_util::StreamExt;
    let (parts, body) = req.into_parts();
    let s = futures_util::stream::unfold(Some(body.into_data_stream()), |s| async move {
        let mut s = s?;
        match tokio::time::timeout(BODY_IDLE, s.next()).await {
            Ok(Some(chunk)) => Some((chunk, Some(s))),
            Ok(None) => None,
            Err(_) => Some((
                Err(axum::Error::new(std::io::Error::from(std::io::ErrorKind::TimedOut))),
                None,
            )),
        }
    });
    next.run(Request::from_parts(parts, axum::body::Body::from_stream(s)))
        .await
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::VARY, HeaderValue::from_static("Host"));
    res
}

/// At most exactly one value for the header, in ASCII.
fn single<'a>(h: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, HostError> {
    let mut it = h.get_all(name).iter();
    match (it.next(), it.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => v.to_str().map(Some).map_err(|_| HostError::Invalid),
        _ => Err(HostError::Invalid),
    }
}

/// §4.1: the connection necessarily comes from a trusted proxy (filtered at accept time), so
/// `X-Forwarded-Host` is read; if it contradicts `Host`, the request is refused.
fn host_of(h: &HeaderMap) -> Result<&str, HostError> {
    let host = single(h, "host")?;
    let fwd = single(h, "x-forwarded-host")?;
    match (host, fwd) {
        (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b) => Err(HostError::Invalid),
        (_, Some(v)) | (Some(v), None) => Ok(v),
        (None, None) => Err(HostError::Invalid),
    }
}

async fn resolve_tenant(State(app): State<Arc<App>>, mut req: Request, next: Next) -> Response {
    let h = req.headers();
    let resolved = host_of(h).and_then(|host| Ok((app.registry.resolve(host)?, host.to_ascii_lowercase())));
    match resolved {
        Ok((t, host)) => {
            // The host passed normalization: only [a-z0-9.-] and a port, safe in a URL, JSON or HTML.
            let scheme = match single(h, "x-forwarded-proto") {
                Ok(Some("http")) => "http",
                _ => "https",
            };
            let base = Base(format!("{scheme}://{host}"));
            let peer = req.extensions().get::<Peer>().map(|p| p.0);
            let real = single(h, "x-real-ip")
                .ok()
                .flatten()
                .and_then(|v| v.trim().parse::<IpAddr>().ok());
            let ip = ClientIp(real.or(peer).unwrap_or(IpAddr::from([0, 0, 0, 0])));
            req.extensions_mut().insert(base);
            req.extensions_mut().insert(ip);
            req.extensions_mut().insert(t);
            next.run(req).await
        }
        Err(HostError::Invalid) => StatusCode::BAD_REQUEST.into_response(),
        Err(HostError::Unknown) => StatusCode::MISDIRECTED_REQUEST.into_response(),
    }
}

/// Maximum time to receive a request's headers (anti-slowloris, §9).
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(20);
/// On shutdown: time left to in-flight requests before exiting anyway (Nextcloud clients keep
/// requests open). Safe: atomic write (§0.2), temporaries cleaned up at startup.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Accept loop: only the `trusted_proxies` (application check, doubled by pf), at most
/// `max_connections` concurrent connections (beyond that: closed right away), header read timeout.
pub async fn serve(
    listener: TcpListener,
    trusted: Vec<IpAddr>,
    max_connections: usize,
    header_timeout: Duration,
    router: Router,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let slots = Arc::new(Semaphore::new(max_connections));
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (io, addr) = tokio::select! {
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    // EMFILE/ENFILE: do not spin.
                    tracing::error!("accept : {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        if !trusted.contains(&addr.ip().to_canonical()) {
            tracing::warn!(peer = %addr.ip(), "connection refused: peer outside trusted_proxies");
            continue;
        }
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            tracing::warn!(max_connections, "connection refused: limit reached");
            continue;
        };
        // Streamed chunked responses: without NODELAY, Nagle + delayed ACK add ~40 ms to the last chunk.
        if let Err(e) = io.set_nodelay(true) {
            tracing::warn!("TCP_NODELAY : {e}");
        }
        let (router, peer) = (router.clone(), Peer(addr.ip().to_canonical()));
        let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
            req.extensions_mut().insert(peer);
            // Router is always ready (immediate poll_ready): direct call.
            tower_service::Service::call(&mut router.clone(), req)
        });
        let conn = hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(header_timeout)
            .serve_connection(hyper_util::rt::TokioIo::new(io), svc);
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("connection: {e}");
            }
            drop(slot);
        });
    }
    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => tracing::info!("clean shutdown"),
        () = tokio::time::sleep(SHUTDOWN_GRACE) => {
            tracing::warn!("forced shutdown: connections still open after {SHUTDOWN_GRACE:?}");
        }
    }
}

/// HTTP fuzzing (`fuzz/fuzz_targets/http.rs`, `fuzzing` feature, never in the shipped binary): arbitrary requests on
/// the real router, over a bench built once by the target (two tenants, alice with an app password and a web session,
/// a drop link and a read link). Checked: no panic, never a 500, and nothing appears outside the data roots. The bench
/// is kept by the fuzz target (`fuzz/`), not here: no global state in the server (§4.1).
/// shortcut: the bench keeps its state between inputs (files written, links used): a crash may need the
/// preceding inputs to replay; libFuzzer keeps them in its corpus.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
pub mod fuzz {
    use super::*;
    use crate::fs::{Root, SafePath};
    use axum::body::Body;
    use std::path::PathBuf;

    /// One request on the router (`tower-service`, already a dependency: no `tower` in the fuzzing build).
    async fn send(app: &Router, req: Request) -> Response {
        use tower_service::Service;
        let mut s = app.clone();
        std::future::poll_fn(|cx| <Router as Service<Request>>::poll_ready(&mut s, cx))
            .await
            .unwrap();
        s.call(req).await.unwrap()
    }

    pub struct Bench {
        rt: tokio::runtime::Runtime,
        app: Router,
        base: PathBuf,
        top: Vec<std::ffi::OsString>,
        auth: String,
        cookie: String,
        csrf: String,
        /// Session of carol, whose password was set by the administrator: opens nothing but `/web/welcome`.
        forced: (String, String),
        /// Session of dave, whose password is right but who has not given his code yet: opens no `/web/` page.
        waiting: (String, String),
        drop: String,
        read: String,
    }

    const HOST: &str = "files.alpha.example";
    const METHODS: [&str; 13] = [
        "GET",
        "HEAD",
        "PUT",
        "POST",
        "DELETE",
        "MKCOL",
        "MOVE",
        "COPY",
        "PROPFIND",
        "PROPPATCH",
        "SEARCH",
        "OPTIONS",
        "PATCH",
    ];

    fn top(base: &std::path::Path) -> Vec<std::ffi::OsString> {
        let mut v: Vec<_> = std::fs::read_dir(base)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        v.sort();
        v
    }

    impl Default for Bench {
        fn default() -> Self {
            let mut r = [0u8; 8];
            getrandom::fill(&mut r).unwrap();
            let base = std::env::temp_dir().join(format!("beastbox-fuzz-{}", u64::from_le_bytes(r)));
            for d in ["a/alice", "b/alice", "db"] {
                std::fs::create_dir_all(base.join(d)).unwrap();
            }
            for d in ["a/alice", "b/alice"] {
                Root::open_dir(&base.join(d)).unwrap().ensure_layout().unwrap();
            }
            let reg = crate::tenant::Registry::from_parts(vec![
                (
                    "alpha".into(),
                    vec![HOST.into()],
                    Root::open_dir(&base.join("a")).unwrap(),
                    [1; 32],
                    [11; 32],
                    None,
                ),
                (
                    "beta".into(),
                    vec!["files.beta.example".into()],
                    Root::open_dir(&base.join("b")).unwrap(),
                    [2; 32],
                    [12; 32],
                    None,
                ),
            ])
            .unwrap();
            let db = Db::open(&base.join("db/app.db")).unwrap();
            db.sync_tenants(reg.all()).unwrap();
            let h = auth::hash_password("pw-alice").unwrap();
            for t in reg.all() {
                db.user_add(t, "alice", &h, false).unwrap();
                db.user_set_password_hash(t, "alice", &h, false).unwrap(); // alice chose it
                t.journal().open(&base.join(format!("db/{}.log", t.name()))).unwrap();
            }
            let alpha = reg.by_name("alpha").unwrap();
            db.user_add(&alpha, "carol", &auth::hash_password("pw-de-carol").unwrap(), false)
                .unwrap();
            let h = auth::hash_password("pw-de-dave").unwrap();
            db.user_add(&alpha, "dave", &h, false).unwrap();
            db.user_set_password_hash(&alpha, "dave", &h, false).unwrap();
            let s = [7u8; auth::totp::SECRET_LEN];
            let now = auth::totp::now();
            let code = format!("{:06}", auth::totp::hotp(&s, auth::totp::step(now)));
            auth::totp_enable(&db, &alpha, "dave", &s, &code, now).unwrap().unwrap();
            let t = reg.by_name("alpha").unwrap();
            let root = Root::open_dir(&base.join("a/alice")).unwrap();
            let sp = |s: &str| SafePath::new(s).unwrap();
            root.mkdir(&sp("Boite")).unwrap();
            root.mkdir(&sp("Docs")).unwrap();
            root.atomic_write(&sp("Docs/a.txt"), &mut &b"hello"[..]).unwrap();
            let link = |path: &str, perms: &str| {
                let id = auth::random_hex::<16>().unwrap();
                let token = auth::share_token(&t, &id);
                let fileid = root.file_id(&sp(path)).unwrap().unwrap();
                db.share_add(
                    &t,
                    &crate::db::NewShare {
                        share_id: &id,
                        user: "alice",
                        mac: &t.mac(token.as_bytes()),
                        fileid: &fileid.0,
                        path_hint: path,
                        perms,
                        password_hash: None,
                        expires_at: None,
                        max_downloads: None,
                        opts: &Default::default(),
                    },
                )
                .unwrap();
                token
            };
            let (drop, read) = (link("Boite", "drop"), link("Docs", "read"));
            let auth = format!(
                "Basic {}",
                base64ct::Base64::encode_string(
                    format!("alice:{}", auth::new_app_password(&db, &t, "alice", "fuzz").unwrap()).as_bytes()
                )
            );
            let state = Arc::new(App::new(reg, db, Settings::default()).unwrap());
            let app = router(state);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let login = axum::http::Request::post("/login")
                .header("host", HOST)
                .body(Body::from("user=alice&password=pw-alice"))
                .unwrap();
            let res = rt.block_on(send(&app, login));
            let set = res.headers()["set-cookie"].to_str().unwrap();
            let cookie = set.split(';').next().unwrap().to_owned();
            let csrf = auth::csrf_token(&t, cookie.split_once('=').unwrap().1);
            let login = axum::http::Request::post("/login")
                .header("host", HOST)
                .body(Body::from("user=carol&password=pw-de-carol"))
                .unwrap();
            let res = rt.block_on(send(&app, login));
            let set = res.headers()["set-cookie"].to_str().unwrap();
            let forced = set.split(';').next().unwrap().to_owned();
            let forced = (forced.clone(), auth::csrf_token(&t, forced.split_once('=').unwrap().1));
            let login = axum::http::Request::post("/login")
                .header("host", HOST)
                .body(Body::from("user=dave&password=pw-de-dave"))
                .unwrap();
            let res = rt.block_on(send(&app, login));
            let set = res.headers()["set-cookie"].to_str().unwrap();
            let waiting = set.split(';').next().unwrap().to_owned();
            let waiting = (
                waiting.clone(),
                auth::csrf_token(&t, waiting.split_once('=').unwrap().1),
            );
            let top = top(&base);
            Bench {
                rt,
                app,
                base,
                top,
                auth,
                cookie,
                csrf,
                forced,
                waiting,
                drop,
                read,
            }
        }
    }

    use base64ct::Encoding;

    /// `data`: method, route, flags, then up to three parts separated by 0: path suffix, header value, body.
    pub fn request(b: &Bench, data: &[u8]) {
        let [m, route, flags, rest @ ..] = data else { return };
        let mut parts = rest.splitn(3, |&c| c == 0);
        let (suffix, value, body) = (
            String::from_utf8_lossy(parts.next().unwrap_or_default()),
            String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned(),
            parts.next().unwrap_or_default().to_vec(),
        );
        let prefixes = [
            "/remote.php/dav/files/alice/".to_owned(),
            "/remote.php/webdav/".to_owned(),
            "/remote.php/dav/uploads/alice/".to_owned(),
            "/remote.php/dav/trashbin/alice/".to_owned(),
            "/remote.php/dav".to_owned(),
            format!("/s/{}/drop/", b.drop),
            format!("/s/{}", b.drop),
            format!("/s/{}/", b.read),
            "/s/".to_owned(),
            "/index.php/core/preview?fileId=".to_owned(),
            "/index.php/f/".to_owned(),
            "/index.php/login/v2".to_owned(),
            "/ocs/v2.php/".to_owned(),
            "/ocs/v2.php/apps/files_sharing/api/v1/shares".to_owned(),
            "/ocs/v1.php/apps/files_sharing/api/v1/shares/".to_owned(),
            "/web/".to_owned(),
            "/web/welcome".to_owned(),
            "/web/account/password".to_owned(),
            "/web/account/2fa".to_owned(),
            "/web/2fa-setup".to_owned(),
            "/login/code".to_owned(),
            "/login".to_owned(),
            "/".to_owned(),
        ];
        let prefix = &prefixes[usize::from(*route) % prefixes.len()];
        // Keep `%`, `/`, `?`, `&`, `=` (the fuzzer forges its own encodings); encode what a URI cannot hold.
        const KEEP: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
            .add(b' ')
            .add(b'"')
            .add(b'#')
            .add(b'<')
            .add(b'>')
            .add(b'`')
            .add(b'{')
            .add(b'}')
            .add(b'|')
            .add(b'\\')
            .add(b'^')
            .add(b'[')
            .add(b']');
        let uri = format!("{prefix}{}", percent_encoding::utf8_percent_encode(&suffix, KEEP));
        let mut req = axum::http::Request::builder()
            .method(METHODS[usize::from(*m) % METHODS.len()])
            .uri(uri)
            .header("host", if flags & 0x80 != 0 { "files.beta.example" } else { HOST });
        if flags & 1 != 0 {
            req = req.header("authorization", b.auth.as_str());
        }
        // Method byte, high bits: carol's session (0x80) or dave's (0x40) and form token, instead of alice's.
        let forced = flags & 2 != 0 && m & 0x80 != 0;
        let waiting = flags & 2 != 0 && m & 0xc0 == 0x40;
        let (cookie, csrf) = match (forced, waiting) {
            (true, _) => (&b.forced.0, &b.forced.1),
            (_, true) => (&b.waiting.0, &b.waiting.1),
            _ => (&b.cookie, &b.csrf),
        };
        if flags & 2 != 0 {
            req = req.header("cookie", cookie.as_str());
        }
        let name = [
            "destination",
            "range",
            "if-match",
            "depth",
            "x-oc-mtime",
            "oc-checksum",
            "content-type",
        ][usize::from(flags >> 2 & 7) % 7];
        if !value.is_empty()
            && let Ok(v) = HeaderValue::from_str(&value)
        {
            req = req.header(name, v);
        }
        let mut body = body;
        if flags & 0x20 != 0 {
            body.extend_from_slice(format!("&csrf={csrf}").as_bytes());
        }
        if flags & 0x40 != 0 {
            req = req.header("content-length", body.len().to_string());
        }
        let Ok(req) = req.body(Body::from(body)) else { return };
        // Oracle "never access without credentials" (TESTING.md): the surface a path needs, and whether this request
        // carries valid credentials for it (the bench's app password and session are alpha's: worthless on beta).
        let path = req.uri().path().to_owned();
        let alpha = flags & 0x80 == 0;
        let ocs_public = ["/ocs/v1.php/cloud/capabilities", "/ocs/v2.php/cloud/capabilities"];
        let needs = if path.starts_with("/remote.php/")
            || path.starts_with("/index.php/core/preview")
            || ((path.starts_with("/ocs/v1.php/") || path.starts_with("/ocs/v2.php/"))
                && !ocs_public.contains(&path.as_str()))
        {
            Some(("app password", alpha && flags & 1 != 0))
        } else if path.starts_with("/web/") || path.starts_with("/index.php/f/") {
            // carol's session is valid only for the welcome page until she chooses her password; dave's for no
            // `/web/` page until he gives his code.
            let valid = alpha && flags & 2 != 0 && !waiting && (!forced || path == "/web/welcome");
            Some(("session", valid))
        } else {
            None // public: links, login, status, Login Flow, capabilities, static files
        };
        let res = b.rt.block_on(async {
            let res = send(&b.app, req).await;
            let status = res.status();
            // Streamed bodies (files, archives, listings) are read to the end: their errors count too.
            let _ = axum::body::to_bytes(res.into_body(), 64 << 20).await;
            status
        });
        assert_ne!(res, StatusCode::INTERNAL_SERVER_ERROR, "500");
        assert_eq!(top(&b.base), b.top, "something written outside the data roots");
        if let Some((what, false)) = needs {
            assert!(!res.is_success(), "{res} on {path} without a valid {what}");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::auth::tests::db_with_users;
    use crate::fs::SafePath;
    use crate::tenant::tests::two_tenants;
    use axum::body::Body;
    use base64ct::Encoding;
    use tower::ServiceExt;

    pub(crate) struct Env {
        pub(crate) app: Router,
        pub(crate) state: Arc<App>,
        pub(crate) a_root: tempfile::TempDir,
        pub(crate) _b_root: tempfile::TempDir,
        pub(crate) _db: tempfile::TempDir,
    }

    pub(crate) fn env() -> Env {
        env_with(Settings::default())
    }

    pub(crate) fn env_with(settings: Settings) -> Env {
        let (reg, a, b) = two_tenants();
        for d in [a.path(), b.path()] {
            std::fs::create_dir(d.join("alice")).unwrap();
            crate::fs::Root::open_dir(&d.join("alice"))
                .unwrap()
                .ensure_layout()
                .unwrap();
        }
        let dbd = tempfile::tempdir().unwrap();
        let db = db_with_users(&reg, dbd.path());
        for t in reg.all() {
            t.journal().open(&dbd.path().join(format!("{}.log", t.name()))).unwrap();
        }
        let state = Arc::new(App::new(reg, db, settings).unwrap());
        Env {
            app: router(state.clone()),
            state,
            a_root: a,
            _b_root: b,
            _db: dbd,
        }
    }

    pub(crate) async fn call(
        app: &Router,
        method: &str,
        path: &str,
        hs: &[(&str, &str)],
        body: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let mut b = axum::http::Request::builder().method(method).uri(path);
        for (k, v) in hs {
            b = b.header(*k, *v);
        }
        let res = app
            .clone()
            .oneshot(b.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let (parts, body) = res.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        (
            parts.status,
            parts.headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    pub(crate) async fn status(app: &Router, method: &str, path: &str, hs: &[(&str, &str)]) -> StatusCode {
        call(app, method, path, hs, "").await.0
    }

    pub(crate) fn basic(u: &str, p: &str) -> String {
        format!(
            "Basic {}",
            base64ct::Base64::encode_string(format!("{u}:{p}").as_bytes())
        )
    }

    pub(crate) fn token(e: &Env, tenant: &str) -> String {
        let t = e.state.registry.by_name(tenant).unwrap();
        auth::new_app_password(&e.state.db, &t, "alice", "test").unwrap()
    }

    pub(crate) const A: (&str, &str) = ("host", "files.alpha.example");

    #[tokio::test]
    async fn tenant_resolution_and_default_deny() {
        let e = env();
        let app = &e.app;
        assert_eq!(status(app, "GET", "/status.php", &[A]).await, StatusCode::OK);
        assert_eq!(
            status(app, "GET", "/status.php", &[("host", "cloud.beta.example:443")]).await,
            StatusCode::OK
        );
        assert_eq!(
            status(app, "GET", "/status.php", &[("host", "evil.org")]).await,
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(status(app, "GET", "/status.php", &[]).await, StatusCode::BAD_REQUEST);
        assert_eq!(status(app, "GET", "/nope", &[A]).await, StatusCode::NOT_FOUND);
        assert_eq!(status(app, "GET", "/", &[A]).await, StatusCode::SEE_OTHER); // to the web interface
        assert_eq!(
            status(app, "POST", "/status.php", &[A]).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(status(app, "GET", "/../status.php", &[A]).await, StatusCode::NOT_FOUND);
        assert_eq!(
            status(app, "GET", "/nope", &[("host", "evil.org")]).await,
            StatusCode::MISDIRECTED_REQUEST
        );
        let xfh = [A, ("x-forwarded-host", "cloud.beta.example")];
        assert_eq!(status(app, "GET", "/status.php", &xfh).await, StatusCode::BAD_REQUEST);
        assert_eq!(
            status(app, "GET", "/status.php", &[A, A]).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(app, "GET", "/status.php", &[("x-forwarded-host", "x.beta.example")]).await,
            StatusCode::OK
        );
    }

    /// Route audit (§10): every route of the table requires a tenant (421 on an unknown host), and none crashes.
    #[tokio::test]
    async fn every_route_requires_tenant() {
        let e = env();
        for (m, r) in ROUTES {
            let s = status(&e.app, m, r, &[A, ("depth", "0")]).await;
            assert!(
                s != StatusCode::MISDIRECTED_REQUEST && !s.is_server_error(),
                "{m} {r} : {s}"
            );
            assert_eq!(
                status(&e.app, m, r, &[("host", "unknown.example")]).await,
                StatusCode::MISDIRECTED_REQUEST
            );
        }
    }

    #[tokio::test]
    async fn security_headers_present() {
        let e = env();
        let (_, h, body) = call(&e.app, "GET", "/status.php", &[A], "").await;
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["vary"], "Host");
        assert!(body.contains("\"installed\":true"));
        assert!(body.contains("\"versionstring\":\"35.0.0\""));
    }

    /// Login Flow: at most 4 pending flows per IP (otherwise 64 anonymous requests would block every new client
    /// login of the tenant); another IP is not affected; a confirmed flow frees its slot; tenant cap kept.
    #[tokio::test]
    async fn login_flows_limited_per_ip() {
        let e = env();
        let app = &e.app;
        let start = |ip: String| async move {
            let h = [A, ("x-forwarded-proto", "http"), ("x-real-ip", ip.as_str())];
            let (s, _, body) = call(app, "POST", "/index.php/login/v2", &h, "").await;
            let login = body
                .split("/index.php/login/v2/flow/")
                .nth(1)
                .map(|x| x.split('"').next().unwrap().to_owned());
            (s, login)
        };
        let ip7 = || "192.0.2.7".to_owned();
        let mut logins = Vec::new();
        for _ in 0..4 {
            let (s, l) = start(ip7()).await;
            assert_eq!(s, StatusCode::OK);
            logins.push(l.unwrap());
        }
        assert_eq!(start(ip7()).await.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(start("192.0.2.8".into()).await.0, StatusCode::OK);

        // A confirmed flow no longer counts: the IP can open another one.
        let session = alice_session(app).await;
        let form = format!("/index.php/login/v2/flow/{}", logins[0]);
        assert_eq!(
            call(
                app,
                "POST",
                &form,
                &[A, ("cookie", session.as_str())],
                "password=pw-alice"
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(start(ip7()).await.0, StatusCode::OK);
        assert_eq!(start(ip7()).await.0, StatusCode::TOO_MANY_REQUESTS);

        // A full tenant table no longer refuses a new client (M5): `login_flows_full_drop_the_oldest_pending`.
    }

    /// A field of the Login Flow JSON (`"key":"value"`).
    fn grab(body: &str, k: &str) -> String {
        body.split(&format!("\"{k}\":\""))
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned()
    }

    /// A full web session of `alice` (cookie pair to replay), through the real login form.
    async fn alice_session(app: &Router) -> String {
        let (s, h, _) = call(app, "POST", "/login", &[A], "user=alice&password=pw-alice").await;
        assert_eq!(s, StatusCode::SEE_OTHER, "login refused");
        h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned()
    }

    /// The Login Flow page shows the client's label escaped (it comes from a User-Agent anyone can write); wrong
    /// passwords there count like a sign-in's: the 11th try from the IP is a 429, even with the right password.
    #[tokio::test]
    async fn login_flow_page_escapes_and_limits() {
        let e = env();
        let app = &e.app;
        let proto = ("x-forwarded-proto", "http");
        let ua = ("user-agent", "evil<script>\"x'&");
        let (_, _, body) = call(app, "POST", "/index.php/login/v2", &[A, proto, ua], "").await;
        let login = grab(&body, "login");
        let path = login.strip_prefix("http://files.alpha.example").unwrap().to_owned();
        let session = alice_session(app).await;
        let c = [A, ("cookie", session.as_str())];
        let (_, _, page) = call(app, "GET", &path, &c, "").await;
        assert!(
            page.contains("<strong>evil&lt;script&gt;&quot;x&#39;&amp;</strong>") && !page.contains("<script>"),
            "{page}"
        );
        for _ in 0..10 {
            assert_eq!(
                call(app, "POST", &path, &c, "password=faux").await.0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            call(app, "POST", &path, &c, "password=pw-alice").await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
        let alpha = e.state.registry.by_name("alpha").unwrap();
        assert!(e.state.db.token_list(&alpha, "alice").unwrap().is_empty());
    }

    /// M5: a full table of pending Login Flows (many addresses opening flows and leaving them) does not refuse the next
    /// client: the oldest pending flow is dropped. A flow already confirmed (waiting for its client's poll) is never the
    /// one dropped.
    #[tokio::test]
    async fn login_flows_full_drop_the_oldest_pending() {
        let e = env();
        let app = &e.app;
        let proto = ("x-forwarded-proto", "http");
        let start = |ip: String| async move {
            let (s, _, body) = call(
                app,
                "POST",
                "/index.php/login/v2",
                &[A, proto, ("x-real-ip", ip.as_str())],
                "",
            )
            .await;
            (s, body)
        };
        // A flow confirmed first: it must survive.
        let (_, body) = start("203.0.113.1".into()).await;
        let path = grab(&body, "login")
            .strip_prefix("http://files.alpha.example")
            .unwrap()
            .to_owned();
        let poll = format!("token={}", grab(&body, "token"));
        let session = alice_session(app).await;
        let c = [A, ("cookie", session.as_str())];
        assert_eq!(
            call(app, "POST", &path, &c, "password=pw-alice").await.0,
            StatusCode::OK
        );
        // Then the table filled with pending flows, one address each.
        let (_, oldest) = start("198.51.100.1".into()).await;
        let oldest = grab(&oldest, "login")
            .strip_prefix("http://files.alpha.example")
            .unwrap()
            .to_owned();
        for i in 0..crate::nc::MAX_FLOWS as u32 {
            let (s, _) = start(format!("2001:db8:{i:x}::1")).await;
            assert_eq!(s, StatusCode::OK, "flow {i}: a new client is never refused");
        }
        assert_eq!(
            status(app, "GET", &oldest, &[A]).await,
            StatusCode::NOT_FOUND,
            "the oldest pending one dropped"
        );
        let (s, _, body) = call(app, "POST", "/index.php/login/v2/poll", &[A, proto], &poll).await;
        assert!(
            s == StatusCode::OK && body.contains("appPassword"),
            "the confirmed one kept"
        );
    }

    /// Two confirmations of one Login Flow at once (double click, two tabs): one app password, handed to the client;
    /// the other confirmation finds the flow taken and creates nothing.
    #[tokio::test]
    async fn login_flow_confirmed_twice_at_once_makes_one_password() {
        let e = env();
        let app = &e.app;
        let proto = ("x-forwarded-proto", "http");
        let (_, _, body) = call(app, "POST", "/index.php/login/v2", &[A, proto], "").await;
        let path = grab(&body, "login")
            .strip_prefix("http://files.alpha.example")
            .unwrap()
            .to_owned();
        let session = alice_session(app).await;
        let c = [A, ("cookie", session.as_str())];
        let (a, b) = tokio::join!(
            call(app, "POST", &path, &c, "password=pw-alice"),
            call(app, "POST", &path, &c, "password=pw-alice")
        );
        let alpha = e.state.registry.by_name("alpha").unwrap();
        assert_eq!(
            e.state.db.token_list(&alpha, "alice").unwrap().len(),
            1,
            "{} {}",
            a.0,
            b.0
        );
        assert_eq!(
            u8::from(a.0 == StatusCode::OK) + u8::from(b.0 == StatusCode::OK),
            1,
            "{} {}",
            a.0,
            b.0
        );
    }

    /// A flow being confirmed (claimed, its app password not made yet): a second confirmation finds it taken and makes
    /// nothing; a full table never drops it to make room; a flow lives 20 minutes.
    #[tokio::test]
    async fn login_flow_being_confirmed_is_neither_confirmed_again_nor_dropped() {
        let e = env();
        let app = &e.app;
        let proto = ("x-forwarded-proto", "http");
        let alpha = e.state.registry.by_name("alpha").unwrap();
        let (_, _, body) = call(app, "POST", "/index.php/login/v2", &[A, proto], "").await;
        let path = grab(&body, "login")
            .strip_prefix("http://files.alpha.example")
            .unwrap()
            .to_owned();
        let (n, life) = alpha.flows().claimed_and_shortest_life();
        let life = life.unwrap();
        assert!(
            n == 0
                && life > std::time::Duration::from_secs(20 * 60 - 5)
                && life <= std::time::Duration::from_secs(20 * 60),
            "{life:?}"
        );
        assert_eq!(alpha.flows().claim_pending(), 1);
        let session = alice_session(app).await;
        let c = [A, ("cookie", session.as_str())];
        assert_eq!(
            call(app, "POST", &path, &c, "password=pw-alice").await.0,
            StatusCode::NOT_FOUND
        );
        assert!(e.state.db.token_list(&alpha, "alice").unwrap().is_empty());
        for i in 0..crate::nc::MAX_FLOWS as u32 {
            let ip = format!("2001:db8:{i:x}::1");
            let (s, _, _) = call(
                app,
                "POST",
                "/index.php/login/v2",
                &[A, proto, ("x-real-ip", ip.as_str())],
                "",
            )
            .await;
            assert_eq!(s, StatusCode::OK, "flow {i}");
        }
        assert_eq!(alpha.flows().claimed_and_shortest_life().0, 1, "the claimed flow kept");
    }

    #[tokio::test]
    async fn login_flow_v2() {
        let e = env();
        let app = &e.app;
        let proto = ("x-forwarded-proto", "http");
        let ua = ("user-agent", "Mozilla/5.0 (Android) Nextcloud-android/35.0.2");
        // A first flow stays pending: confirming the one below must mark that one, not this decoy (a wrong match
        // would leave the confirmed flow polling 404 for ever).
        let (_, _, decoy_body) = call(app, "POST", "/index.php/login/v2", &[A, proto, ua], "").await;
        let decoy = grab(&decoy_body, "token");
        let (s, _, body) = call(app, "POST", "/index.php/login/v2", &[A, proto, ua], "").await;
        assert_eq!(s, StatusCode::OK);
        let (poll, login) = (grab(&body, "token"), grab(&body, "login"));
        assert_eq!(
            grab(&body, "endpoint"),
            "http://files.alpha.example/index.php/login/v2/poll"
        );
        let login_path = login.strip_prefix("http://files.alpha.example").unwrap().to_owned();
        let poll_body = format!("token={poll}");
        let alpha = e.state.registry.by_name("alpha").unwrap();
        let tokens_before = e.state.db.token_list(&alpha, "alice").unwrap().len();
        // Before confirmation: 404.
        assert_eq!(
            call(app, "POST", "/index.php/login/v2/poll", &[A], &poll_body).await.0,
            StatusCode::NOT_FOUND
        );
        // No session: the page sends the browser to the login (which carries single sign-on too), and the POST
        // creates nothing; the login return address is allowed by the same allowlist.
        let (s, h, _) = call(app, "GET", &login_path, &[A], "").await;
        assert_eq!(s, StatusCode::SEE_OTHER);
        assert_eq!(
            h["location"].to_str().unwrap(),
            format!("/login?next={login_path}"),
            "the flow page must send an anonymous browser to the login"
        );
        assert_eq!(call(app, "POST", &login_path, &[A], "").await.0, StatusCode::SEE_OTHER);
        assert_eq!(e.state.db.token_list(&alpha, "alice").unwrap().len(), tokens_before);
        // Other tenant: the flow token does not exist there.
        let b = ("host", "x.beta.example");
        assert_eq!(status(app, "GET", &login_path, &[b]).await, StatusCode::NOT_FOUND);
        // Signed in: the page says who asks (client label, address) and warns; the password is asked again (a phished
        // click with a live session is not enough).
        let session = alice_session(app).await;
        let c = [A, ("cookie", session.as_str())];
        let (s, h, page_body) = call(app, "GET", &login_path, &c, "").await;
        assert_eq!(s, StatusCode::OK);
        assert!(
            h["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("default-src 'none'")
        );
        assert!(
            page_body.contains("Authorize this client")
                && page_body.contains("name=\"password\"")
                && page_body.contains("Software: <strong>Nextcloud Android 35.0.2</strong>")
                && page_body.contains("Requested from the address: <strong>")
                && page_body.contains("whoever sent you this link would get access to all your files"),
            "{page_body}"
        );
        // Without the password, or a wrong one: nothing created, the page again.
        for body in ["", "password=", "password=faux"] {
            let (s, _, p) = call(app, "POST", &login_path, &c, body).await;
            assert!(
                s == StatusCode::UNAUTHORIZED && p.contains("Wrong password or code"),
                "{body}"
            );
        }
        assert_eq!(e.state.db.token_list(&alpha, "alice").unwrap().len(), tokens_before);
        let good = call(app, "POST", &login_path, &c, "password=pw-alice").await.0;
        assert_eq!(good, StatusCode::OK);
        // Poll on the other tenant: 404; on the right one: 200 only once.
        assert_eq!(
            call(app, "POST", "/index.php/login/v2/poll", &[b], &poll_body).await.0,
            StatusCode::NOT_FOUND
        );
        let (s, _, body) = call(app, "POST", "/index.php/login/v2/poll", &[A, proto], &poll_body).await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.contains("\"server\":\"http://files.alpha.example\"") && body.contains("\"loginName\":\"alice\""));
        let pw = body
            .split("\"appPassword\":\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert_eq!(
            call(app, "POST", "/index.php/login/v2/poll", &[A], &poll_body).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(status(app, "GET", &login_path, &[A]).await, StatusCode::NOT_FOUND); // single use
        // The app password opens OCS and WebDAV; the human password does not (§2).
        let ok = basic("alice", pw);
        let user = "/ocs/v1.php/cloud/user?format=json";
        assert_eq!(
            status(app, "GET", user, &[A, ("authorization", &ok)]).await,
            StatusCode::OK
        );
        let human = basic("alice", "pw-alice");
        assert_eq!(
            status(app, "GET", user, &[A, ("authorization", &human)]).await,
            StatusCode::UNAUTHORIZED
        );
        // The decoy flow was not marked by that confirmation: it still polls 404.
        assert_eq!(
            call(
                app,
                "POST",
                "/index.php/login/v2/poll",
                &[A, proto],
                &format!("token={decoy}")
            )
            .await
            .0,
            StatusCode::NOT_FOUND,
            "the wrong flow was marked by the confirmation"
        );
        // Named after the client that opened the flow (not the browser), last use recorded.
        let tokens = e.state.db.token_list(&alpha, "alice").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].label, "Nextcloud Android 35.0.2");
        assert!(tokens[0].last_used_at.is_some());
    }

    #[tokio::test]
    async fn webdav_read_only() {
        let e = env();
        let app = &e.app;
        let alpha = e.state.registry.by_name("alpha").unwrap();
        let root = alpha.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
        std::fs::create_dir_all(e.a_root.path().join("alice/Docs/sous dossier")).unwrap();
        root.atomic_write(&SafePath::new("Docs/a b é.txt").unwrap(), &mut &b"0123456789"[..])
            .unwrap();
        let auth = basic("alice", &token(&e, "alpha"));
        let h = [A, ("authorization", auth.as_str()), ("depth", "1")];
        let props = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><d:getetag/><oc:fileid/><oc:size/><d:resourcetype/><x:nope xmlns:x="urn:x"/></d:prop></d:propfind>"#;
        let (s, _, body) = call(app, "PROPFIND", "/remote.php/dav/files/alice/", &h, props).await;
        assert_eq!(s, StatusCode::MULTI_STATUS);
        assert!(body.contains("<d:href>/remote.php/dav/files/alice/</d:href>"));
        assert!(body.contains("<d:href>/remote.php/dav/files/alice/Docs/</d:href>"));
        assert!(!body.contains(".beastbox-tmp") && !body.contains(".trash"));
        assert!(body.contains("<x:nope xmlns:x=\"urn:x\"/>") && body.contains("404 Not Found"));
        let (_, _, body) = call(app, "PROPFIND", "/remote.php/dav/files/alice/Docs", &h, "").await;
        assert!(
            body.contains("/remote.php/dav/files/alice/Docs/a%20b%20%C3%A9.txt</d:href>"),
            "{body}"
        );
        assert!(body.contains("/remote.php/dav/files/alice/Docs/sous%20dossier/</d:href>"));
        // Same tree through the old root.
        assert_eq!(
            status(app, "PROPFIND", "/remote.php/webdav/Docs/", &h).await,
            StatusCode::MULTI_STATUS
        );
        // GET and Range.
        let f = "/remote.php/dav/files/alice/Docs/a%20b%20%C3%A9.txt";
        let (s, hd, body) = call(app, "GET", f, &h, "").await;
        assert_eq!((s, body.as_str()), (StatusCode::OK, "0123456789"));
        assert_eq!(hd["content-security-policy"], "sandbox");
        let r = [A, ("authorization", auth.as_str()), ("range", "bytes=2-4")];
        let (s, hd, body) = call(app, "GET", f, &r, "").await;
        assert_eq!((s, body.as_str()), (StatusCode::PARTIAL_CONTENT, "234"));
        assert_eq!(hd["content-range"], "bytes 2-4/10");
        let r = [A, ("authorization", auth.as_str()), ("range", "bytes=50-")];
        assert_eq!(status(app, "GET", f, &r).await, StatusCode::RANGE_NOT_SATISFIABLE);
        let (s, hd, body) = call(app, "HEAD", f, &h, "").await;
        assert_eq!(
            (s, body.as_str(), hd["content-length"].to_str().unwrap()),
            (StatusCode::OK, "", "10")
        );
        // HEAD on a folder (root or not): 200 like Nextcloud; GET on a folder: 405.
        assert_eq!(
            status(app, "HEAD", "/remote.php/dav/files/alice/", &h).await,
            StatusCode::OK
        );
        assert_eq!(
            status(app, "HEAD", "/remote.php/dav/files/alice/Docs/", &h).await,
            StatusCode::OK
        );
        assert_eq!(
            status(app, "GET", "/remote.php/dav/files/alice/Docs/", &h).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            status(app, "HEAD", "/remote.php/dav/files/alice/missing/", &h).await,
            StatusCode::NOT_FOUND
        );
        // Refused: Depth infinity, write (J1), traversal, reserved names, other user, no auth.
        let inf = [A, ("authorization", auth.as_str()), ("depth", "infinity")];
        assert_eq!(
            status(app, "PROPFIND", "/remote.php/dav/files/alice/", &inf).await,
            StatusCode::FORBIDDEN
        );
        for p in [
            "/remote.php/dav/files/alice/..%2f..%2fetc/passwd",
            "/remote.php/dav/files/alice/%2e%2e/bob",
            "/remote.php/dav/files/alice/.beastbox-tmp/",
            "/remote.php/dav/files/alice/.trash",
            "/remote.php/dav/files/bob/",
            "/remote.php/dav/files/alice/Docs/missing",
        ] {
            assert_eq!(status(app, "PROPFIND", p, &h).await, StatusCode::NOT_FOUND, "{p}");
        }
        let noauth = [A, ("depth", "1")];
        assert_eq!(
            status(app, "PROPFIND", "/remote.php/dav/files/alice/", &noauth).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(app, "PROPFIND", "/remote.php/dav/files/", &noauth).await,
            StatusCode::UNAUTHORIZED
        );
    }

    /// Folder of 2,000 entries: response produced in several chunks, no entry lost or duplicated.
    #[tokio::test]
    async fn propfind_large_dir_streams() {
        let e = env();
        let dir = e.a_root.path().join("alice/big");
        std::fs::create_dir(&dir).unwrap();
        for i in 0..2000 {
            std::fs::write(dir.join(format!("fichier-{i:05}.txt")), b"x").unwrap();
        }
        let auth = basic("alice", &token(&e, "alpha"));
        let h = [A, ("authorization", auth.as_str()), ("depth", "1")];
        let (s, _, body) = call(&e.app, "PROPFIND", "/remote.php/dav/files/alice/big/", &h, "").await;
        assert_eq!(s, StatusCode::MULTI_STATUS);
        assert!(body.len() > 2 * 64 * 1024);
        assert_eq!(body.matches("<d:response>").count(), 2001);
        assert!(body.contains("fichier-01999.txt") && body.ends_with("</d:multistatus>"));
    }

    /// §2: after 10 failures from an IP, its wrong passwords get 429; a valid password from the same IP
    /// goes through (a device with a revoked token does not cut off the others); another IP (X-Real-IP) is unaffected.
    #[tokio::test]
    async fn auth_failures_are_rate_limited() {
        let e = env();
        let bad = basic("alice", "mauvais");
        let good = basic("alice", &token(&e, "alpha"));
        let from = |ip: &'static str, auth: &str| {
            [A, ("authorization", auth), ("depth", "0"), ("x-real-ip", ip)].map(|(k, v)| (k, v.to_owned()))
        };
        let call_as = |hs: [(&'static str, String); 4]| {
            let app = e.app.clone();
            async move {
                let v: Vec<(&str, &str)> = hs.iter().map(|(k, v)| (*k, v.as_str())).collect();
                status(&app, "PROPFIND", "/remote.php/dav/files/alice/", &v).await
            }
        };
        for _ in 0..10 {
            assert_eq!(call_as(from("192.0.2.7", &bad)).await, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(call_as(from("192.0.2.7", &bad)).await, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(call_as(from("192.0.2.7", &good)).await, StatusCode::MULTI_STATUS);
        assert_eq!(call_as(from("192.0.2.7", &bad)).await, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(call_as(from("192.0.2.8", &good)).await, StatusCode::MULTI_STATUS);
        assert_eq!(call_as(from("192.0.2.8", &bad)).await, StatusCode::UNAUTHORIZED);
        // The login form (human password, guessable) stays blocked for this IP, before argon2.
        let (s, _, body) = call(
            &e.app,
            "POST",
            "/index.php/login/v2",
            &[A, ("x-forwarded-proto", "http")],
            "",
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let login = body
            .split("/index.php/login/v2/flow/")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        // The Login Flow asks nothing itself: it sends the browser to the login, where the limit applies.
        let (s, h, _) = call(
            &e.app,
            "GET",
            &format!("/index.php/login/v2/flow/{login}"),
            &[A, ("x-real-ip", "192.0.2.7")],
            "",
        )
        .await;
        assert_eq!(s, StatusCode::SEE_OTHER);
        assert_eq!(
            h["location"].to_str().unwrap(),
            format!("/login?next=/index.php/login/v2/flow/{login}")
        );
    }

    /// Isolation (§4.1): a token of one tenant is worthless on the other, even for a same-named user.
    #[tokio::test]
    async fn cross_tenant_token_refused() {
        let e = env();
        let auth = basic("alice", &token(&e, "alpha"));
        let b = [
            ("host", "x.beta.example"),
            ("authorization", auth.as_str()),
            ("depth", "0"),
        ];
        assert_eq!(
            status(&e.app, "PROPFIND", "/remote.php/dav/files/alice/", &b).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&e.app, "GET", "/ocs/v2.php/cloud/user", &b).await,
            StatusCode::UNAUTHORIZED
        );
        let a = [A, ("authorization", auth.as_str()), ("depth", "0")];
        assert_eq!(
            status(&e.app, "PROPFIND", "/remote.php/dav/files/alice/", &a).await,
            StatusCode::MULTI_STATUS
        );
    }

    #[tokio::test]
    async fn ocs_endpoints() {
        let e = env();
        let (s, _, body) = call(&e.app, "GET", "/ocs/v1.php/cloud/capabilities?format=json", &[A], "").await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.contains("\"statuscode\":100") && body.contains("\"chunking\":\"1.0\""));
        assert!(body.contains("\"major\":35") && body.contains("\"string\":\"35.0.0\""));
        let notif = "/ocs/v2.php/apps/notifications/api/v2/notifications";
        let (s, _, body) = call(&e.app, "GET", notif, &[A], "").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert!(body.contains("\"statuscode\":998"));
        assert_eq!(
            status(&e.app, "GET", "/index.php/204", &[A]).await,
            StatusCode::NO_CONTENT
        );
    }

    /// Real accept loop (TCP): unlisted peer closed, connection limit, too-slow headers cut.
    #[tokio::test]
    async fn accept_loop_limits() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let e = env();
        let start = |trusted: Vec<IpAddr>, max: usize| {
            let router = e.app.clone();
            async move {
                let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = l.local_addr().unwrap();
                let stop = std::future::pending::<()>();
                tokio::spawn(serve(l, trusted, max, Duration::from_millis(500), router, stop));
                addr
            }
        };
        let req = b"GET /status.php HTTP/1.1\r\nHost: files.alpha.example\r\nConnection: close\r\n\r\n";
        let read_all = |mut c: tokio::net::TcpStream| async move {
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut out)).await;
            String::from_utf8_lossy(&out).into_owned()
        };
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        // Trusted peer: normal response.
        let addr = start(vec![local], 4).await;
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(req).await.unwrap();
        assert!(read_all(c).await.starts_with("HTTP/1.1 200"));
        // Headers never finished: connection cut after the timeout (no 200 response).
        let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /status.php HTTP/1.1\r\nHost: files.alpha.example\r\n")
            .await
            .unwrap();
        let t = std::time::Instant::now();
        let got = read_all(slow).await;
        assert!(t.elapsed() < Duration::from_secs(2) && !got.contains("200"), "{got:?}");
        // Unlisted peer: closed without a response.
        let addr = start(vec!["10.9.9.9".parse().unwrap()], 4).await;
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = c.write_all(req).await;
        assert_eq!(read_all(c).await, "");
        // Connection limit: the second one, while the first is open, is closed without a response.
        let addr = start(vec![local], 1).await;
        let _first = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = second.write_all(req).await;
        assert_eq!(read_all(second).await, "");
    }

    pub(crate) async fn send(
        app: &Router,
        method: &str,
        path: &str,
        hs: &[(&str, &str)],
        body: &[u8],
    ) -> (StatusCode, HeaderMap) {
        let mut b = axum::http::Request::builder().method(method).uri(path);
        for (k, v) in hs {
            b = b.header(*k, *v);
        }
        let res = app
            .clone()
            .oneshot(b.body(Body::from(body.to_vec())).unwrap())
            .await
            .unwrap();
        (res.status(), res.headers().clone())
    }

    fn root_etag(body: &str) -> String {
        body.split("<d:getetag>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned()
    }

    /// J2: PUT (creation, replacement, If-Match, OC-Checksum, X-OC-Mtime, quota), MKCOL, MOVE, COPY, DELETE,
    /// ETag propagation up to the root, trash.
    #[tokio::test]
    async fn webdav_writes() {
        let e = env();
        let app = &e.app;
        let auth = basic("alice", &token(&e, "alpha"));
        let a = [A, ("authorization", auth.as_str())];
        let d0 = [A, ("authorization", auth.as_str()), ("depth", "0")];
        let disk = e.a_root.path().join("alice");
        let f = "/remote.php/dav/files/alice";
        let etag0 = root_etag(&call(app, "PROPFIND", &format!("{f}/"), &d0, "").await.2);

        assert_eq!(
            send(app, "MKCOL", &format!("{f}/Docs"), &a, b"").await.0,
            StatusCode::CREATED
        );
        assert_eq!(
            send(app, "MKCOL", &format!("{f}/Docs"), &a, b"").await.0,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            send(app, "MKCOL", &format!("{f}/nope/x"), &a, b"").await.0,
            StatusCode::CONFLICT
        );
        let etag1 = root_etag(&call(app, "PROPFIND", &format!("{f}/"), &d0, "").await.2);
        assert_ne!(etag0, etag1, "MKCOL must renew the root's ETag");

        // PUT: creation (201), identity, client time, sum checked.
        let sha = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"; // sha1("hello")
        let ck = format!("SHA1:{sha}");
        let put_h = [
            A,
            ("authorization", auth.as_str()),
            ("x-oc-mtime", "1600000000"),
            ("oc-checksum", ck.as_str()),
        ];
        let (s, h) = send(app, "PUT", &format!("{f}/Docs/a%20b.txt"), &put_h, b"hello").await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(h["x-oc-mtime"], "accepted");
        let fileid = h["oc-fileid"].to_str().unwrap().to_owned();
        let etag_a = h["etag"].to_str().unwrap().to_owned();
        assert_eq!(std::fs::read(disk.join("Docs/a b.txt")).unwrap(), b"hello");
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(disk.join("Docs/a b.txt")).unwrap().mtime(),
            1_600_000_000
        );
        let (_, _, body) = call(app, "PROPFIND", &format!("{f}/Docs/a%20b.txt"), &d0,
            r#"<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:checksums/><oc:permissions/></d:prop></d:propfind>"#).await;
        assert!(
            body.contains(&format!("SHA1:{sha}")) && body.contains("RGDNVW"),
            "{body}"
        );
        let etag2 = root_etag(&call(app, "PROPFIND", &format!("{f}/"), &d0, "").await.2);
        assert_ne!(etag1, etag2);
        // Wrong sum: 400, content intact.
        let bad = [A, ("authorization", auth.as_str()), ("oc-checksum", "SHA1:0000")];
        assert_eq!(
            send(app, "PUT", &format!("{f}/Docs/a%20b.txt"), &bad, b"corrupted")
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(std::fs::read(disk.join("Docs/a b.txt")).unwrap(), b"hello");
        // Stale If-Match: 412; correct: 204, same identity.
        let stale = [A, ("authorization", auth.as_str()), ("if-match", "\"perime\"")];
        assert_eq!(
            send(app, "PUT", &format!("{f}/Docs/a%20b.txt"), &stale, b"v2").await.0,
            StatusCode::PRECONDITION_FAILED
        );
        let fresh = [A, ("authorization", auth.as_str()), ("if-match", etag_a.as_str())];
        let (s, h) = send(app, "PUT", &format!("{f}/Docs/a%20b.txt"), &fresh, b"v2").await;
        assert_eq!(
            (s, h["oc-fileid"].to_str().unwrap()),
            (StatusCode::NO_CONTENT, fileid.as_str())
        );
        let none = [A, ("authorization", auth.as_str()), ("if-none-match", "*")];
        assert_eq!(
            send(app, "PUT", &format!("{f}/Docs/a%20b.txt"), &none, b"v3").await.0,
            StatusCode::PRECONDITION_FAILED
        );
        // Parent missing: 409; root: 405; reserved name: 404; announced quota too large: 507.
        assert_eq!(
            send(app, "PUT", &format!("{f}/nope/x"), &a, b"x").await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(app, "PUT", &format!("{f}/"), &a, b"x").await.0,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            send(app, "PUT", &format!("{f}/.trash/x"), &a, b"x").await.0,
            StatusCode::NOT_FOUND
        );
        let huge = [
            A,
            ("authorization", auth.as_str()),
            ("oc-total-length", "999999999999999999"),
        ];
        assert_eq!(
            send(app, "PUT", &format!("{f}/big"), &huge, b"x").await.0,
            StatusCode::INSUFFICIENT_STORAGE
        );
        assert!(!disk.join("big").exists());

        // MOVE: identity kept; Overwrite: F → 412; into itself → 409; other host → 502.
        let dest = |p: &str| format!("http://files.alpha.example{f}/{p}");
        let mv = |m: &'static str, src: &str, to: String, extra: Option<(&'static str, &'static str)>| {
            let (app, auth, src) = (app.clone(), auth.clone(), format!("{f}/{src}"));
            async move {
                let mut h = vec![A, ("authorization", auth.as_str()), ("destination", to.as_str())];
                h.extend(extra);
                send(&app, m, &src, &h, b"").await.0
            }
        };
        assert_eq!(
            mv("MOVE", "Docs/a%20b.txt", dest("Docs/renomm%C3%A9.txt"), None).await,
            StatusCode::CREATED
        );
        // Destination in raw UTF-8 (not encoded): accepted.
        let raw = "http://files.alpha.example/remote.php/dav/files/alice/Docs/brut é.txt";
        let mut req = axum::http::Request::builder()
            .method("COPY")
            .uri(format!("{f}/Docs/renomm%C3%A9.txt"))
            .header("host", "files.alpha.example")
            .header("authorization", auth.as_str())
            .body(Body::empty())
            .unwrap();
        req.headers_mut()
            .insert("destination", HeaderValue::from_bytes(raw.as_bytes()).unwrap());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::CREATED);
        assert!(disk.join("Docs/brut é.txt").exists());
        assert!(disk.join("Docs/renommé.txt").exists() && !disk.join("Docs/a b.txt").exists());
        let (_, h) = send(app, "PUT", &format!("{f}/Docs/renomm%C3%A9.txt"), &a, b"v4").await;
        assert_eq!(h["oc-fileid"].to_str().unwrap(), fileid);
        send(app, "PUT", &format!("{f}/Docs/other.txt"), &a, b"other").await;
        let no_overwrite = Some(("overwrite", "F"));
        assert_eq!(
            mv("MOVE", "Docs/renomm%C3%A9.txt", dest("Docs/other.txt"), no_overwrite).await,
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(mv("MOVE", "Docs", dest("Docs/sub"), None).await, StatusCode::CONFLICT);
        assert_eq!(
            mv("MOVE", "Docs/other.txt", "http://evil.example/x".into(), None).await,
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            mv("MOVE", "Docs/other.txt", dest(".trash/x"), None).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(mv("MOVE", "ghost", dest("x"), None).await, StatusCode::NOT_FOUND);
        // Overwrite by MOVE: 204, the old destination goes to the trash.
        assert_eq!(
            mv("MOVE", "Docs/renomm%C3%A9.txt", dest("Docs/other.txt"), None).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(std::fs::read(disk.join("Docs/other.txt")).unwrap(), b"v4");
        // COPY: new identity.
        assert_eq!(mv("COPY", "Docs", dest("Copie"), None).await, StatusCode::CREATED);
        assert_eq!(std::fs::read(disk.join("Copie/other.txt")).unwrap(), b"v4");

        // DELETE: to the trash, no longer visible; root forbidden.
        assert_eq!(
            send(app, "DELETE", &format!("{f}/Docs"), &a, b"").await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            send(app, "DELETE", &format!("{f}/Docs"), &a, b"").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(app, "DELETE", &format!("{f}/"), &a, b"").await.0,
            StatusCode::FORBIDDEN
        );
        assert!(!disk.join("Docs").exists());
        let in_trash = std::fs::read_dir(disk.join(".trash"))
            .unwrap()
            .any(|s| s.unwrap().path().join("Docs/other.txt").exists());
        assert!(in_trash);
        assert_eq!(std::fs::read_dir(disk.join(".beastbox-tmp")).unwrap().count(), 0);
    }

    /// SEARCH body as the Android app sends it (`NcSearchMethod`): wanted properties, scope, clause, limit.
    fn search_body(scope: &str, clause: &str, limit: usize) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><d:searchrequest xmlns:d="DAV:" xmlns:oc="http://nextcloud.com/ns"><d:basicsearch><d:select><d:prop><d:displayname/><d:getcontenttype/><d:resourcetype/><d:getetag/><oc:fileid xmlns:oc="http://owncloud.org/ns"/><oc:favorite xmlns:oc="http://owncloud.org/ns"/></d:prop></d:select><d:from><d:scope><d:href>{scope}</d:href><d:depth>infinity</d:depth></d:scope></d:from><d:where>{clause}</d:where><d:orderby/><d:limit><d:nresults>{limit}</d:nresults></d:limit></d:basicsearch></d:searchrequest>"#
        )
    }

    /// The clients' WebDAV search (Favorites, Recent, Photos tabs and the Android app's search): `OPTIONS` announces
    /// `SEARCH`, each query returns the right items, another user's or tenant's space is never read.
    #[tokio::test]
    async fn dav_search_for_clients() {
        let e = env();
        let app = &e.app;
        let auth = basic("alice", &token(&e, "alpha"));
        let a = [A, ("authorization", auth.as_str())];
        let f = "/remote.php/dav/files/alice";

        // Unauthenticated: 401; OPTIONS announces SEARCH (otherwise the app gives up).
        assert_eq!(
            status(app, "OPTIONS", "/remote.php/dav", &[A]).await,
            StatusCode::UNAUTHORIZED
        );
        let (s, h, _) = call(app, "OPTIONS", "/remote.php/dav", &a, "").await;
        assert_eq!(s, StatusCode::OK);
        assert!(h["allow"].to_str().unwrap().split(", ").any(|m| m == "SEARCH"));
        assert_eq!(
            status(app, "PROPFIND", "/remote.php/dav/", &a).await,
            StatusCode::NOT_FOUND
        );

        for p in ["Photos", "Docs"] {
            send(app, "MKCOL", &format!("{f}/{p}"), &a, b"").await;
        }
        for p in [
            "Photos/plage.jpg",
            "Photos/film.mp4",
            "Docs/facture-mars.pdf",
            "Docs/notes.txt",
        ] {
            assert_eq!(
                send(app, "PUT", &format!("{f}/{p}"), &a, b"x").await.0,
                StatusCode::CREATED
            );
        }
        let root = crate::fs::Root::open_dir(&e.a_root.path().join("alice")).unwrap();
        root.set_favorite(Some(&SafePath::new("Docs/notes.txt").unwrap()), true)
            .unwrap();
        let hrefs = |b: &str| -> Vec<String> {
            let mut v: Vec<String> = b
                .split("<d:href>")
                .skip(1)
                .map(|x| {
                    x.split('<')
                        .next()
                        .unwrap()
                        .trim_start_matches(&format!("{f}/"))
                        .to_owned()
                })
                .collect();
            v.sort();
            v
        };
        let search = |clause: &str, limit: usize| search_body("/files/alice", clause, limit);
        let run = |body: String| async move { call(app, "SEARCH", "/remote.php/dav", &a, &body).await };

        // Favorites.
        let fav = r#"<d:eq><d:prop><oc:favorite xmlns:oc="http://owncloud.org/ns"/></d:prop><d:literal>yes</d:literal></d:eq>"#;
        let (s, _, body) = run(search(fav, 100)).await;
        assert_eq!(s, StatusCode::MULTI_STATUS);
        assert_eq!(hrefs(&body), ["Docs/notes.txt"]);
        assert!(
            body.contains("<oc:favorite>1</oc:favorite>")
                && body.contains("<d:getcontenttype>text/plain</d:getcontenttype>")
        );
        assert!(body.contains("<oc:fileid>") && body.contains("<d:getetag>"));

        // Recent (last 7 days), limit respected.
        let week = r#"<d:gt><d:prop><d:getlastmodified/></d:prop><d:literal>2000-01-01T00:00:00Z</d:literal></d:gt>"#;
        // Files only: a folder changes date as soon as something is written in it.
        let (_, _, body) = run(search(week, 100)).await;
        assert_eq!(
            hrefs(&body),
            [
                "Docs/facture-mars.pdf",
                "Docs/notes.txt",
                "Photos/film.mp4",
                "Photos/plage.jpg"
            ]
        );
        let (_, _, body) = run(search(week, 2)).await;
        assert_eq!(body.matches("<d:response>").count(), 2);
        let future = week.replace("2000-01-01", "2999-01-01");
        assert_eq!(run(search(&future, 100)).await.2.matches("<d:response>").count(), 0);

        // Photos (images and videos, never a folder), with their real type.
        let gallery = r#"<d:or><d:like><d:prop><d:getcontenttype/></d:prop><d:literal>image/%</d:literal></d:like><d:like><d:prop><d:getcontenttype/></d:prop><d:literal>video/%</d:literal></d:like></d:or>"#;
        let (_, _, body) = run(search(gallery, 100)).await;
        assert_eq!(hrefs(&body), ["Photos/film.mp4", "Photos/plage.jpg"]);
        assert!(body.contains("<d:getcontenttype>image/jpeg</d:getcontenttype>"));

        // By name.
        let name = r#"<d:like><d:prop><d:displayname/></d:prop><d:literal>%FACTURE%</d:literal></d:like>"#;
        assert_eq!(hrefs(&run(search(name, 100)).await.2), ["Docs/facture-mars.pdf"]);

        // Another user's scope, unknown criterion: empty list, never the whole space.
        let (s, _, body) = call(
            app,
            "SEARCH",
            "/remote.php/dav",
            &a,
            &search_body("/files/bob", fav, 100),
        )
        .await;
        assert_eq!((s, body.matches("<d:response>").count()), (StatusCode::MULTI_STATUS, 0));
        let other =
            r#"<d:eq><d:prop><oc:fileid xmlns:oc="http://owncloud.org/ns"/></d:prop><d:literal>1</d:literal></d:eq>"#;
        assert_eq!(run(search(other, 100)).await.2.matches("<d:response>").count(), 0);

        // Other tenant: its alice does not see this one's files.
        let b_auth = basic("alice", &token(&e, "beta"));
        let b = [("host", "x.beta.example"), ("authorization", b_auth.as_str())];
        let (s, _, body) = call(app, "SEARCH", "/remote.php/dav", &b, &search(week, 100)).await;
        assert_eq!((s, body.matches("<d:response>").count()), (StatusCode::MULTI_STATUS, 0));
        // A tenant's token is worthless in the other.
        let cross = [("host", "x.beta.example"), ("authorization", auth.as_str())];
        assert_eq!(
            status(app, "SEARCH", "/remote.php/dav", &cross).await,
            StatusCode::UNAUTHORIZED
        );

        // Images alone, videos alone (the app's two filters), each never the other nor a folder.
        let only =
            |t: &str| format!(r#"<d:like><d:prop><d:getcontenttype/></d:prop><d:literal>{t}/%</d:literal></d:like>"#);
        assert_eq!(hrefs(&run(search(&only("image"), 100)).await.2), ["Photos/plage.jpg"]);
        assert_eq!(hrefs(&run(search(&only("video"), 100)).await.2), ["Photos/film.mp4"]);
        // Before a date (lt, lte), as Unix seconds or a date; nothing before 2000.
        for (op, date) in [
            ("lt", "2999-01-01T00:00:00Z"),
            ("lte", "32503680000"),
            ("lt", "2000-01-01T00:00:00Z"),
        ] {
            let c = format!(r#"<d:{op}><d:prop><d:getlastmodified/></d:prop><d:literal>{date}</d:literal></d:{op}>"#);
            let n = run(search(&c, 100)).await.2.matches("<d:response>").count();
            assert_eq!(n, if date.starts_with("2000") { 0 } else { 4 }, "{op} {date}");
        }
        let bad_date = r#"<d:lt><d:prop><d:getlastmodified/></d:prop><d:literal>2999-13-01</d:literal></d:lt>"#;
        assert_eq!(run(search(bad_date, 100)).await.0, StatusCode::BAD_REQUEST);
        // Entities in a literal: named and numeric, resolved before matching.
        send(app, "PUT", &format!("{f}/Docs/r&d.txt"), &a, b"x").await;
        let ent = r#"<d:like><d:prop><d:displayname/></d:prop><d:literal>%r&amp;&#x64;%</d:literal></d:like>"#;
        assert_eq!(hrefs(&run(search(ent, 100)).await.2), ["Docs/r%26d.txt"]);
        // Folders only (is-collection), and every property when the select is empty.
        let dirs = r#"<d:is-collection/>"#;
        assert_eq!(hrefs(&run(search(dirs, 100)).await.2), ["Docs/", "Photos/"]);
        let all = search(fav, 100).replace(
            r#"<d:select><d:prop><d:displayname/><d:getcontenttype/><d:resourcetype/><d:getetag/><oc:fileid xmlns:oc="http://owncloud.org/ns"/><oc:favorite xmlns:oc="http://owncloud.org/ns"/></d:prop></d:select>"#,
            "<d:select><d:allprop/></d:select>",
        );
        let body = run(all).await.2;
        assert!(
            body.contains("<d:getcontentlength>") && body.contains("<d:getlastmodified>"), // DAV allprop set
            "{body}"
        );
        let preview = search(fav, 100).replace(
            "<d:displayname/>",
            r#"<nc:has-preview xmlns:nc="http://nextcloud.org/ns"/>"#,
        );
        assert!(run(preview).await.2.contains("has-preview>false<"));

        // Malformed: 400; oversized body: 413.
        assert_eq!(
            run("<d:searchrequest xmlns:d=\"DAV:\">".into()).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(run("x".repeat(70 * 1024)).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// `core/preview`: a thumbnail computed from a JPEG found by `fileId`, upright, announced by `nc:has-preview`;
    /// 404 otherwise, never another user's or tenant's file.
    /// Links from the clients (OCS `files_sharing`): create, list, change, revoke; the same links as the web page.
    #[tokio::test]
    async fn client_share_links() {
        let e = env();
        let app = &e.app;
        let auth = basic("alice", &token(&e, "alpha"));
        // JSON, as the desktop client asks; the Android app's XML is checked below.
        let json = ("accept", "application/json");
        let a = [A, ("authorization", auth.as_str()), json];
        let form = [
            A,
            ("authorization", auth.as_str()),
            ("content-type", "application/x-www-form-urlencoded"),
            json,
        ];
        let f = "/remote.php/dav/files/alice";
        let api = "/ocs/v2.php/apps/files_sharing/api/v1/shares";
        let field = |body: &str, k: &str| {
            let rest = body.split(&format!("\"{k}\":")).nth(1).unwrap();
            rest.split([',', '}']).next().unwrap().trim_matches('"').to_owned()
        };
        send(app, "MKCOL", &format!("{f}/Docs"), &a, b"").await;
        send(app, "PUT", &format!("{f}/Docs/a%20b.txt"), &a, b"hello").await;
        let (_, _, caps) = call(app, "GET", "/ocs/v2.php/cloud/capabilities?format=json", &a, "").await;
        assert!(caps.contains(r#""files_sharing":{"api_enabled":true"#));

        // Creation: read-only link on a file, usable at once.
        let (s, _, body) = call(
            app,
            "POST",
            api,
            &form,
            "path=%2FDocs%2Fa+b.txt&shareType=3&permissions=1",
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{body}");
        let (id, tok) = (field(&body, "id"), field(&body, "token"));
        assert_eq!(field(&body, "url"), format!("https://files.alpha.example/s/{tok}"));
        assert_eq!(field(&body, "path"), "/Docs/a b.txt");
        assert_eq!(
            (field(&body, "item_type").as_str(), field(&body, "share_with").as_str()),
            ("file", "null")
        );
        assert_eq!(status(app, "GET", &format!("/s/{tok}/dl"), &[A]).await, StatusCode::OK);

        // The Android app asks without a format: XML, as Nextcloud answers by default.
        // Android reads the identifier as a 32-bit integer: a larger one made it reject the whole list.
        assert!(id.parse::<i32>().is_ok_and(|n| n >= 0), "{id}");
        let android = [A, ("authorization", auth.as_str()), ("ocs-apirequest", "true")];
        let (s, h, x) = call(app, "GET", &format!("{api}?include_tags=true"), &android, "").await;
        assert!(s == StatusCode::OK && h[header::CONTENT_TYPE].to_str().unwrap().starts_with("application/xml"));
        assert!(
            x.starts_with("<?xml") && x.contains("<statuscode>200</statuscode>"),
            "{x}"
        );
        assert!(
            x.contains(&format!("<element><id>{id}</id><share_type>3</share_type>")),
            "{x}"
        );
        assert!(
            x.contains(&format!("<token>{tok}</token>"))
                && x.contains("<path>/Docs/a b.txt</path>")
                && x.contains("<expiration/>")
        );
        let (_, _, x) = call(app, "GET", &format!("{api}?path=/nope&format=xml"), &a, "").await;
        assert!(x.contains("<data/>"), "{x}");

        // Listing: by path, the folder's children, all; nothing elsewhere nor "shared with me".
        for q in [
            "?path=%2FDocs%2Fa%20b.txt&reshares=true&subfiles=false",
            "?path=/Docs/&subfiles=true",
            "?include_tags=true",
        ] {
            let (_, _, b) = call(app, "GET", &format!("{api}{q}"), &a, "").await;
            assert!(b.contains(&tok), "{q}: {b}");
        }
        for q in ["?path=/Docs", "?shared_with_me=true", "?path=/nope"] {
            let (_, _, b) = call(app, "GET", &format!("{api}{q}"), &a, "").await;
            assert!(!b.contains(&tok), "{q}: {b}");
        }

        // Refused: other kinds of share, other permissions, drop or upload on a file, short password; v1 envelope.
        for (b, why) in [
            ("path=/Docs&shareType=0&shareWith=bob", "user share"),
            ("path=/Docs&shareType=3&permissions=2", "neither read nor create"),
            ("path=/Docs/a+b.txt&shareType=3&permissions=4", "drop on a file"),
            ("path=/Docs&shareType=3&label=a%0Ab", "control character in the label"),
            ("path=/Docs&shareType=3&password=court", "short password"),
            ("path=/Docs&shareType=3&expireDate=2001-01-01", "past expiry"),
        ] {
            assert_eq!(
                call(app, "POST", api, &form, b).await.0,
                StatusCode::BAD_REQUEST,
                "{why}"
            );
        }
        // A file's "editing" (3) and "upload" on a file: read only, never refused (the desktop client would stay stuck).
        for b in [
            "path=/Docs/a+b.txt&shareType=3&permissions=3",
            "path=/Docs/a+b.txt&shareType=3&permissions=15",
        ] {
            let (s, _, r) = call(app, "POST", api, &form, b).await;
            assert!(s == StatusCode::OK && field(&r, "permissions") == "1", "{b}: {r}");
            assert_eq!(
                call(app, "DELETE", &format!("{api}/{}", field(&r, "id")), &a, "")
                    .await
                    .0,
                StatusCode::OK
            );
        }
        let v1 = "/ocs/v1.php/apps/files_sharing/api/v1/shares";
        let (s, _, b) = call(app, "POST", v1, &form, "path=/Docs&shareType=3&permissions=4").await;
        assert!(s == StatusCode::OK && b.contains(r#""statuscode":100"#), "{b}");
        assert_eq!(
            (field(&b, "item_type").as_str(), field(&b, "permissions").as_str()),
            ("folder", "4")
        );

        // Changes: password (the address stays, the guest is asked for it), expiry, then removed.
        let one = format!("{api}/{id}");
        assert_eq!(
            call(app, "PUT", &one, &form, "password=court").await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(app, "PUT", &one, &form, "permissions=4").await.0,
            StatusCode::BAD_REQUEST
        );
        let (s, _, b) = call(app, "PUT", &one, &form, "password=secret-du-lien").await;
        assert!(s == StatusCode::OK && field(&b, "token") == tok && field(&b, "share_with") == "***redacted***");
        assert!(!b.contains("argon2"));
        assert_ne!(status(app, "GET", &format!("/s/{tok}/dl"), &[A]).await, StatusCode::OK);
        let (_, _, b) = call(app, "PUT", &one, &form, "expireDate=2099-01-31").await;
        assert_eq!(field(&b, "expiration"), "2099-01-31 00:00:00");
        let (_, _, b) = call(app, "PUT", &one, &form, "password=&expireDate=").await;
        assert_eq!(
            (field(&b, "share_with").as_str(), field(&b, "expiration").as_str()),
            ("null", "null")
        );
        assert_eq!(status(app, "GET", &format!("/s/{tok}/dl"), &[A]).await, StatusCode::OK);

        // Another tenant's alice does not see it, cannot change or revoke it.
        let other = basic("alice", &token(&e, "beta"));
        let b_h = [("host", "files.beta.example"), ("authorization", other.as_str())];
        for m in ["GET", "PUT", "DELETE"] {
            assert_eq!(call(app, m, &one, &b_h, "").await.0, StatusCode::NOT_FOUND, "{m}");
        }

        // Revocation: the link ends, the list forgets it.
        assert_eq!(call(app, "DELETE", &one, &a, "").await.0, StatusCode::OK);
        assert_eq!(
            status(app, "GET", &format!("/s/{tok}"), &[A]).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(call(app, "DELETE", &one, &a, "").await.0, StatusCode::NOT_FOUND);
        assert!(!call(app, "GET", api, &a, "").await.2.contains(&tok));

        // "Upload and editing" (15) = read and upload: the guest sees the folder and adds files, never replaces one.
        // Label (`name` from the desktop client) and note round-trip; the note is shown escaped to the guest.
        let (s, _, b) = call(
            app,
            "POST",
            api,
            &form,
            "path=/Docs&shareType=3&permissions=15&name=Pour+X&note=%3Cb%3Ebonjour",
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(
            (field(&b, "permissions").as_str(), field(&b, "label").as_str()),
            ("15", "Pour X")
        );
        let (up_id, up) = (field(&b, "id"), field(&b, "token"));
        let (_, _, page) = call(app, "GET", &format!("/s/{up}"), &[A], "").await;
        assert!(
            page.contains("&#60;b&#62;bonjour") && !page.contains("<b>bonjour") && page.contains("data-upload"),
            "{page}"
        );
        let drop = |name: &'static str| {
            let url = format!("/s/{up}/drop/{name}");
            async move { send(app, "PUT", &url, &[A, ("content-length", "3")], b"new").await.0 }
        };
        assert_eq!(drop("ajout.txt").await, StatusCode::CREATED);
        assert_eq!(drop("a%20b.txt").await, StatusCode::CREATED);
        assert_eq!(
            std::fs::read(e.a_root.path().join("alice/Docs/a b.txt")).unwrap(),
            b"hello"
        );
        // Download hidden: text opens in the browser, no archive; the flag round-trips as 0/1.
        let up_one = format!("{api}/{up_id}");
        let (_, _, b) = call(app, "PUT", &up_one, &form, "hideDownload=true&label=").await;
        assert_eq!(
            (field(&b, "hide_download").as_str(), field(&b, "label").as_str()),
            ("1", "")
        );
        let (s, h, _) = call(app, "GET", &format!("/s/{up}/dl/ajout.txt"), &[A], "").await;
        let disposition = h.get(header::CONTENT_DISPOSITION).and_then(|v| v.to_str().ok());
        assert!(s == StatusCode::OK && !disposition.is_some_and(|d| d.starts_with("attachment")));
        assert_eq!(
            status(app, "GET", &format!("/s/{up}/zip/"), &[A]).await,
            StatusCode::NOT_FOUND
        );
        let (_, _, b) = call(app, "PUT", &up_one, &form, "permissions=1&hideDownload=false").await;
        assert_eq!(
            (field(&b, "permissions").as_str(), field(&b, "hide_download").as_str()),
            ("1", "0")
        );
        assert_ne!(drop("refuse.txt").await, StatusCode::CREATED);

        // The desktop client's dialog: what a link may give.
        let props = r#"<d:propfind xmlns:d="DAV:" xmlns:ocs="http://open-collaboration-services.org/ns"><d:prop><ocs:share-permissions/></d:prop></d:propfind>"#;
        let d0 = [A, ("authorization", auth.as_str()), ("depth", "0")];
        let (_, _, b) = call(app, "PROPFIND", &format!("{f}/Docs"), &d0, props).await;
        assert!(b.contains(">21</x1:share-permissions>"), "{b}");

        // The "shared" icon: the folder keeps its drop link, the file's link was revoked.
        let props = r#"<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:share-types/></d:prop></d:propfind>"#;
        let d1 = [A, ("authorization", auth.as_str()), ("depth", "1")];
        let (_, _, b) = call(app, "PROPFIND", &format!("{f}/Docs"), &d1, props).await;
        let (folder, file) = b.split_once("a%20b.txt").unwrap();
        assert!(folder.contains("<oc:share-type>3</oc:share-type>"), "{b}");
        assert!(
            file.contains("<oc:share-types/>") && !file.contains("share-type>3"),
            "{b}"
        );
    }

    /// Capsicum: once set up, the whole server works in capability mode (SQLite included, past a WAL checkpoint).
    /// `cap_enter` is irreversible, so the scenario runs in a child process of the test binary.
    #[test]
    fn serves_in_capability_mode() {
        const CHILD: &str = "BEASTBOX_TEST_CAPMODE";
        if std::env::var_os(CHILD).is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "http::tests::serves_in_capability_mode", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let log = String::from_utf8_lossy(&out.stdout) + String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success() && log.contains("capability mode: ok"), "{log}");
            return;
        }
        let e = env();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        crate::fs::enter_capability_mode().unwrap();
        let err = std::fs::File::open("/etc/passwd").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ECAPMODE));
        rt.block_on(async {
            use crate::nc::thumb::tests::photo;
            let app = &e.app;
            let auth = basic("alice", &token(&e, "alpha"));
            let a = [A, ("authorization", auth.as_str())];
            let d1 = [A, ("authorization", auth.as_str()), ("depth", "1")];
            let f = "/remote.php/dav/files/alice";
            assert_eq!(
                send(app, "MKCOL", &format!("{f}/Docs"), &a, b"").await.0,
                StatusCode::CREATED
            );
            let (s, h) = send(app, "PUT", &format!("{f}/Docs/p.jpg"), &a, &photo(64, 32, 1)).await;
            assert_eq!(s, StatusCode::CREATED);
            let id = h["oc-fileid"].to_str().unwrap().to_owned();
            assert_eq!(
                call(app, "GET", &format!("{f}/Docs/p.jpg"), &a, "").await.0,
                StatusCode::OK
            );
            let (s, _, body) = call(app, "PROPFIND", &format!("{f}/Docs"), &d1, "").await;
            assert_eq!(s, StatusCode::MULTI_STATUS);
            assert!(body.contains("p.jpg"));
            let preview = format!("/index.php/core/preview?fileId={id}&x=32&y=32");
            assert_eq!(status(app, "GET", &preview, &a).await, StatusCode::OK);
            let dest = format!("http://files.alpha.example{f}/Docs/q.jpg");
            let mv = [A, ("authorization", auth.as_str()), ("destination", dest.as_str())];
            assert_eq!(
                send(app, "MOVE", &format!("{f}/Docs/p.jpg"), &mv, b"").await.0,
                StatusCode::CREATED
            );
            assert_eq!(
                send(app, "DELETE", &format!("{f}/Docs/q.jpg"), &a, b"").await.0,
                StatusCode::NO_CONTENT
            );
            let trash = "/remote.php/dav/trashbin/alice/trash";
            let (_, _, body) = call(app, "PROPFIND", trash, &d1, "").await;
            assert!(body.contains("q.jpg"));
        });
        // Enough small transactions to pass SQLite's automatic WAL checkpoint (1000 pages).
        let t = e.state.registry.by_name("alpha").unwrap();
        for i in 0..3000u32 {
            let mut mac = [0u8; 32];
            mac[..4].copy_from_slice(&i.to_le_bytes());
            e.state.db.session_add(&t, "alice", &mac, 60).unwrap();
            assert_eq!(
                e.state.db.session_user(&t, &mac).unwrap().map(|r| r.user).as_deref(),
                Some("alice")
            );
        }
        println!("capability mode: ok");
    }

    #[tokio::test]
    async fn client_thumbnails() {
        use crate::nc::thumb::tests::{photo, size};
        let e = env();
        let app = &e.app;
        let auth = basic("alice", &token(&e, "alpha"));
        let a = [A, ("authorization", auth.as_str())];
        let f = "/remote.php/dav/files/alice";
        send(app, "PUT", &format!("{f}/plage.JPG"), &a, &photo(800, 400, 6)).await;
        send(app, "PUT", &format!("{f}/notes.txt"), &a, b"x").await;
        let props = r#"<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns"><d:prop><oc:fileid/><nc:has-preview/></d:prop></d:propfind>"#;
        let auth = auth.as_str();
        let find = |name: &'static str| async move {
            let h = [A, ("authorization", auth), ("depth", "0")];
            let (_, _, b) = call(app, "PROPFIND", &format!("{f}/{name}"), &h, props).await;
            let id = b
                .split("<oc:fileid>")
                .nth(1)
                .unwrap()
                .split('<')
                .next()
                .unwrap()
                .to_owned();
            (id, b.contains("<nc:has-preview>true</nc:has-preview>"))
        };
        let (jpg, yes) = find("plage.JPG").await;
        assert!(yes);
        let (txt, no) = find("notes.txt").await;
        assert!(!no);
        let url =
            |id: &str, side: u32| format!("/index.php/core/preview?fileId={id}ocbeastbox&x={side}&y={side}&a=true");

        let get = |u: String| async move {
            let req = axum::http::Request::get(u)
                .header(A.0, A.1)
                .header("authorization", auth);
            let res = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
            let ct = res.headers().get("content-type").cloned();
            (
                res.status(),
                ct,
                axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
            )
        };
        let (s, ct, body) = get(url(&jpg, 96)).await;
        assert_eq!((s, ct.unwrap()), (StatusCode::OK, "image/jpeg".parse().unwrap()));
        // Short side 96, turned upright (taken in portrait).
        let (w, h, _) = size(&body);
        assert_eq!((w, h), (96, 192));
        // Side above the cap: capped, still served.
        let (_, _, big) = get(url(&jpg, 5000)).await;
        assert_eq!(size(&big).0, 400);
        assert_eq!(status(app, "GET", &url(&jpg, 96), &[A]).await, StatusCode::UNAUTHORIZED);
        // Not a JPEG, unknown, malformed, no size: 404.
        for u in [
            url(&jpg, 0),
            url(&txt, 96),
            url("123", 96),
            "/index.php/core/preview?fileId=x".into(),
        ] {
            assert_eq!(status(app, "GET", &u, &a).await, StatusCode::NOT_FOUND, "{u}");
        }
        // Another tenant's alice does not see this file.
        let other = basic("alice", &token(&e, "beta"));
        let b = [("host", "cloud.beta.example"), ("authorization", other.as_str())];
        assert_eq!(status(app, "GET", &url(&jpg, 96), &b).await, StatusCode::NOT_FOUND);
        // Overwritten by something that is not a JPEG (same identity): no stale thumbnail.
        send(app, "PUT", &format!("{f}/plage.JPG"), &a, b"\xFF\xD8\xFF\xDAxx").await;
        assert_eq!(status(app, "GET", &url(&jpg, 96), &a).await, StatusCode::NOT_FOUND);
    }

    /// A client that stops sending its body is cut after `BODY_IDLE` (virtual time): answer given, nothing written.
    #[tokio::test]
    async fn stalled_upload_is_cut() {
        use futures_util::StreamExt;
        let e = env();
        let auth = basic("alice", &token(&e, "alpha"));
        let stalled = futures_util::stream::iter([Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"abc"))])
            .chain(futures_util::stream::pending());
        let req = axum::http::Request::put("/remote.php/dav/files/alice/lent.bin")
            .header(A.0, A.1)
            .header("authorization", auth)
            .body(Body::from_stream(stalled))
            .unwrap();
        tokio::time::pause();
        let r = e.app.clone().oneshot(req).await.unwrap();
        tokio::time::resume();
        assert!(r.status().is_client_error(), "{}", r.status());
        let disk = e.a_root.path().join("alice");
        assert!(!disk.join("lent.bin").exists());
        assert_eq!(std::fs::read_dir(disk.join(".beastbox-tmp")).unwrap().count(), 0);
    }

    /// ETag as seen by a client: two uploads of the same size and the same `X-OC-Mtime` but different contents change
    /// the ETag; an identical re-upload keeps it; the ETag announced by the PUT is the one of the next PROPFIND.
    #[tokio::test]
    async fn file_etag_follows_content_not_storage() {
        let e = env();
        let app = &e.app;
        let auth = basic("alice", &token(&e, "alpha"));
        let file = "/remote.php/dav/files/alice/note.txt";
        let put = |body: &'static [u8]| {
            let auth = auth.clone();
            async move {
                let h = [A, ("authorization", auth.as_str()), ("x-oc-mtime", "1600000000")];
                let (s, h) = send(app, "PUT", file, &h, body).await;
                assert!(s.is_success(), "{s}");
                h["etag"].to_str().unwrap().to_owned()
            }
        };
        let propfind = || {
            let auth = auth.clone();
            async move {
                let h = [A, ("authorization", auth.as_str()), ("depth", "0")];
                let (_, _, b) = call(app, "PROPFIND", file, &h, "").await;
                format!(
                    "\"{}\"",
                    b.split("<d:getetag>\"").nth(1).unwrap().split('"').next().unwrap()
                )
            }
        };
        let v1 = put(b"version-1").await;
        assert_eq!(v1, propfind().await);
        let v2 = put(b"version-2").await; // same size, same announced time
        assert_ne!(v1, v2);
        assert_eq!(v2, propfind().await);
        assert_eq!(put(b"version-2").await, v2, "same content sent again: same ETag");
    }

    /// Favorites set from the clients (PROPPATCH `oc:favorite`, Android app requests): visible in PROPFIND,
    /// in the Favorites search and in the web interface; all or nothing; root, missing and read-only refused.
    #[tokio::test]
    async fn favorites_from_clients() {
        let e = env();
        let app = &e.app;
        let auth = basic("alice", &token(&e, "alpha"));
        let a = [A, ("authorization", auth.as_str())];
        let f = "/remote.php/dav/files/alice";
        send(app, "MKCOL", &format!("{f}/Docs"), &a, b"").await;
        send(app, "PUT", &format!("{f}/Docs/plan.pdf"), &a, b"x").await;
        let set = r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><oc:favorite xmlns:oc="http://owncloud.org/ns">1</oc:favorite></D:prop></D:set></D:propertyupdate>"#;
        let remove = r#"<D:propertyupdate xmlns:D="DAV:"><D:remove><D:prop><oc:favorite xmlns:oc="http://owncloud.org/ns"/></D:prop></D:remove></D:propertyupdate>"#;
        let ask = r#"<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:favorite/><d:getetag/></d:prop></d:propfind>"#;
        let d0 = [A, ("authorization", auth.as_str()), ("depth", "0")];
        let star = |b: &str| b.split("<oc:favorite>").nth(1).and_then(|x| x.chars().next());
        let file = format!("{f}/Docs/plan.pdf");

        let (_, _, before) = call(app, "PROPFIND", &file, &d0, ask).await;
        assert_eq!(star(&before), Some('0'));
        let etag = before
            .split("<d:getetag>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned();

        // Setting the star: 207, visible everywhere, ETag unchanged (a tag, not a content change).
        let (s, _, body) = call(app, "PROPPATCH", &file, &a, set).await;
        assert_eq!(s, StatusCode::MULTI_STATUS);
        assert!(body.contains("HTTP/1.1 200 OK") && body.contains(&format!("<d:href>{file}</d:href>")));
        let (_, _, after) = call(app, "PROPFIND", &file, &d0, ask).await;
        assert_eq!(star(&after), Some('1'));
        assert!(after.contains(&etag));
        let fav = r#"<d:eq><d:prop><oc:favorite xmlns:oc="http://owncloud.org/ns"/></d:prop><d:literal>yes</d:literal></d:eq>"#;
        let (_, _, found) = call(
            app,
            "SEARCH",
            "/remote.php/dav",
            &a,
            &search_body("/files/alice", fav, 50),
        )
        .await;
        assert!(found.contains(&format!("<d:href>{file}</d:href>")));
        let root = crate::fs::Root::open_dir(&e.a_root.path().join("alice")).unwrap();
        assert!(root.labels(Some(&SafePath::new("Docs/plan.pdf").unwrap())).unwrap().1);

        // Removing the star.
        assert_eq!(
            call(app, "PROPPATCH", &file, &a, remove).await.0,
            StatusCode::MULTI_STATUS
        );
        assert_eq!(star(&call(app, "PROPFIND", &file, &d0, ask).await.2), Some('0'));

        // Another property in the same request: nothing is applied (403 and 424).
        let mixed = set.replace(
            "</D:prop></D:set>",
            "<D:displayname>autre</D:displayname></D:prop></D:set>",
        );
        let (s, _, body) = call(app, "PROPPATCH", &file, &a, &mixed).await;
        assert!(s == StatusCode::MULTI_STATUS && body.contains("424") && body.contains("403"));
        assert_eq!(star(&call(app, "PROPFIND", &file, &d0, ask).await.2), Some('0'));

        // Refused: root, missing item, reserved path, malformed document, unauthenticated.
        assert_eq!(
            call(app, "PROPPATCH", &format!("{f}/"), &a, set).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(app, "PROPPATCH", &format!("{f}/absent.txt"), &a, set).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(app, "PROPPATCH", &format!("{f}/.trash"), &a, set).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(app, "PROPPATCH", &file, &a, "<D:propertyupdate").await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(app, "PROPPATCH", &file, &[A], set).await.0,
            StatusCode::UNAUTHORIZED
        );

        // Read-only: 503, nothing is written.
        let ro = env_with(Settings {
            read_only: true,
            ..Settings::default()
        });
        let ro_auth = basic("alice", &token(&ro, "alpha"));
        std::fs::write(ro.a_root.path().join("alice/x.txt"), b"x").unwrap();
        let ro_h = [A, ("authorization", ro_auth.as_str())];
        let (s, _, _) = call(&ro.app, "PROPPATCH", "/remote.php/dav/files/alice/x.txt", &ro_h, set).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Trash as seen by Nextcloud clients (Android app requests): listing, contents of a deleted folder,
    /// restore with the same identity, permanent delete, trash emptied.
    #[tokio::test]
    async fn nextcloud_trashbin() {
        let e = env();
        let app = &e.app;
        let auth = basic("alice", &token(&e, "alpha"));
        let a = [A, ("authorization", auth.as_str())];
        let d1 = [A, ("authorization", auth.as_str()), ("depth", "1")];
        let f = "/remote.php/dav/files/alice";
        let tb = "/remote.php/dav/trashbin/alice";
        let disk = e.a_root.path().join("alice");

        let (_, _, caps) = call(app, "GET", "/ocs/v2.php/cloud/capabilities", &[A], "").await;
        assert!(caps.contains(r#""files":{"undelete":true}"#));

        assert_eq!(
            send(app, "MKCOL", &format!("{f}/d"), &a, b"").await.0,
            StatusCode::CREATED
        );
        let (_, h) = send(app, "PUT", &format!("{f}/d/a.txt"), &a, b"a").await;
        let id = h["oc-fileid"]
            .to_str()
            .unwrap()
            .trim_end_matches("ocbeastbox")
            .trim_start_matches('0')
            .to_owned();
        send(app, "PUT", &format!("{f}/d/b.txt"), &a, b"b").await;
        send(app, "DELETE", &format!("{f}/d/a.txt"), &a, b"").await;
        send(app, "DELETE", &format!("{f}/d"), &a, b"").await;

        // Android app request (WebdavUtils.getTrashbinPropSet).
        let props = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns"><d:prop><d:resourcetype/><d:getcontenttype/><d:getcontentlength/><oc:size/><oc:id/><nc:trashbin-filename/><nc:trashbin-original-location/><nc:trashbin-deletion-time/><oc:fileid/></d:prop></d:propfind>"#;
        let (s, _, body) = call(app, "PROPFIND", &format!("{tb}/trash"), &d1, props).await;
        assert_eq!(s, StatusCode::MULTI_STATUS);
        assert!(body.contains("<nc:trashbin-original-location>d/a.txt</nc:trashbin-original-location>"));
        assert!(body.contains("<nc:trashbin-filename>d</nc:trashbin-filename>"));
        assert!(
            body.contains(&format!("<oc:fileid>{id}</oc:fileid>")),
            "identity kept: {body}"
        );
        let hrefs: Vec<&str> = body
            .split("<d:href>")
            .skip(2)
            .map(|x| x.split('<').next().unwrap())
            .collect();
        assert_eq!(hrefs.len(), 2);
        // Deleted in the same second: order not guaranteed, the folder is recognized by its trailing `/`.
        let (slot_d, slot_a) = match hrefs[0].ends_with('/') {
            true => (hrefs[0], hrefs[1]),
            false => (hrefs[1], hrefs[0]),
        };
        assert!(slot_d.starts_with(&format!("{tb}/trash/")) && slot_d.ends_with('/'));

        let (_, _, inner) = call(app, "PROPFIND", slot_d, &d1, props).await;
        assert!(inner.contains("<nc:trashbin-original-location>d/b.txt</nc:trashbin-original-location>"));
        assert!(inner.contains(&format!("{slot_d}b.txt</d:href>")));

        // Restore (RestoreTrashbinFileRemoteOperation): parent folder re-created, same identity.
        let dest = format!("http://files.alpha.example{tb}/restore/a.txt");
        let mv = [
            A,
            ("authorization", auth.as_str()),
            ("destination", dest.as_str()),
            ("overwrite", "T"),
        ];
        assert_eq!(send(app, "MOVE", slot_a, &mv, b"").await.0, StatusCode::CREATED);
        assert_eq!(std::fs::read(disk.join("d/a.txt")).unwrap(), b"a");
        let (_, _, back) = call(
            app,
            "PROPFIND",
            &format!("{f}/d/a.txt"),
            &[A, ("authorization", auth.as_str()), ("depth", "0")],
            props,
        )
        .await;
        assert!(back.contains(&format!("<oc:fileid>{id}</oc:fileid>")));
        assert_eq!(send(app, "MOVE", slot_a, &mv, b"").await.0, StatusCode::NOT_FOUND);
        let elsewhere = [
            A,
            ("authorization", auth.as_str()),
            ("destination", "/remote.php/dav/files/alice/x"),
        ];
        assert_eq!(
            send(app, "MOVE", slot_d, &elsewhere, b"").await.0,
            StatusCode::FORBIDDEN
        );

        // Deletes: inside a folder refused, an item, then trash emptied.
        assert_eq!(
            send(app, "DELETE", &format!("{slot_d}b.txt"), &a, b"").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(send(app, "DELETE", slot_d, &a, b"").await.0, StatusCode::NO_CONTENT);
        send(app, "DELETE", &format!("{f}/d"), &a, b"").await;
        assert_eq!(
            send(app, "DELETE", &format!("{tb}/trash"), &a, b"").await.0,
            StatusCode::NO_CONTENT
        );
        let (_, _, empty) = call(app, "PROPFIND", &format!("{tb}/trash"), &d1, props).await;
        assert_eq!(empty.matches("<d:response>").count(), 1);
        assert_eq!(std::fs::read_dir(disk.join(".trash")).unwrap().count(), 0);

        // Root and other user.
        let (_, _, home) = call(app, "PROPFIND", &format!("{tb}/"), &d1, "").await;
        assert!(home.contains(&format!("{tb}/restore/")) && home.contains(&format!("{tb}/trash/")));
        assert_eq!(
            status(app, "PROPFIND", "/remote.php/dav/trashbin/bob/trash", &d1).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(app, "PROPFIND", &format!("{tb}/trash/../x"), &d1).await,
            StatusCode::NOT_FOUND
        );
    }

    /// Chunked upload v2: chunks out of order, assembly, consistency check, cleanup.
    #[tokio::test]
    async fn chunked_upload_v2() {
        let e = env();
        let app = &e.app;
        let auth = basic("alice", &token(&e, "alpha"));
        let disk = e.a_root.path().join("alice");
        let up = "/remote.php/dav/uploads/alice/web-123";
        let dest = "http://files.alpha.example/remote.php/dav/files/alice/gros.bin";
        let h = [
            A,
            ("authorization", auth.as_str()),
            ("destination", dest),
            ("oc-total-length", "11"),
        ];
        assert_eq!(send(app, "MKCOL", up, &h, b"").await.0, StatusCode::CREATED);
        assert_eq!(
            send(app, "PUT", &format!("{up}/00002"), &h, b"world").await.0,
            StatusCode::CREATED
        );
        assert_eq!(
            send(app, "PUT", &format!("{up}/00001"), &h, b"hello ").await.0,
            StatusCode::CREATED
        );
        assert_eq!(
            send(app, "PUT", &format!("{up}/0"), &h, b"x").await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(app, "PUT", &format!("{up}/10001"), &h, b"x").await.0,
            StatusCode::BAD_REQUEST
        );
        // Resume: PROPFIND lists the chunks received.
        let dp = [A, ("authorization", auth.as_str()), ("depth", "1")];
        let (s, _, body) = call(app, "PROPFIND", up, &dp, "").await;
        assert_eq!(s, StatusCode::MULTI_STATUS);
        assert!(
            body.contains("/remote.php/dav/uploads/alice/web-123/00001</d:href>"),
            "{body}"
        );
        // Inconsistent announced total: 400, nothing written, chunks kept for a new attempt.
        let wrong = [
            A,
            ("authorization", auth.as_str()),
            ("destination", dest),
            ("oc-total-length", "12"),
        ];
        assert_eq!(
            send(app, "MOVE", &format!("{up}/.file"), &wrong, b"").await.0,
            StatusCode::BAD_REQUEST
        );
        assert!(!disk.join("gros.bin").exists());
        let mv = [
            A,
            ("authorization", auth.as_str()),
            ("destination", dest),
            ("oc-total-length", "11"),
            ("x-oc-mtime", "1600000000"),
        ];
        let (s, hd) = send(app, "MOVE", &format!("{up}/.file"), &mv, b"").await;
        assert_eq!(s, StatusCode::CREATED);
        assert!(hd.contains_key("oc-fileid") && hd.contains_key("oc-etag"));
        assert_eq!(std::fs::read(disk.join("gros.bin")).unwrap(), b"hello world");
        assert_eq!(std::fs::read_dir(disk.join(".beastbox-uploads")).unwrap().count(), 0);
        // Missing chunk: 400.
        let up2 = "/remote.php/dav/uploads/alice/web-456";
        send(app, "MKCOL", up2, &h, b"").await;
        send(app, "PUT", &format!("{up2}/00001"), &h, b"a").await;
        send(app, "PUT", &format!("{up2}/00003"), &h, b"c").await;
        let mv2 = [A, ("authorization", auth.as_str()), ("destination", dest)];
        assert_eq!(
            send(app, "MOVE", &format!("{up2}/.file"), &mv2, b"").await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(send(app, "DELETE", up2, &mv2, b"").await.0, StatusCode::NO_CONTENT);
        // Unknown upload, another user's, hostile id: 404.
        assert_eq!(
            send(app, "PUT", "/remote.php/dav/uploads/alice/ghost/00001", &h, b"x")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(app, "MKCOL", "/remote.php/dav/uploads/bob/x", &h, b"").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(app, "MKCOL", "/remote.php/dav/uploads/alice/..", &h, b"").await.0,
            StatusCode::NOT_FOUND
        );
    }

    /// §0.2: read-only (configuration) → 503 on every write, reads intact.
    #[tokio::test]
    async fn read_only_mode() {
        let e = env_with(Settings {
            read_only: true,
            ..Settings::default()
        });
        let auth = basic("alice", &token(&e, "alpha"));
        let h = [A, ("authorization", auth.as_str()), ("depth", "0")];
        for m in ["MKCOL", "PUT", "DELETE"] {
            assert_eq!(
                send(&e.app, m, "/remote.php/dav/files/alice/x", &h, b"").await.0,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        assert_eq!(
            send(&e.app, "PROPFIND", "/remote.php/dav/files/alice/", &h, b"")
                .await
                .0,
            StatusCode::MULTI_STATUS
        );
    }

    #[test]
    fn form_parsing() {
        assert_eq!(
            form_field(b"a=1&user=al%C3%A9+x&b=", "user").as_deref(),
            Some("al\u{e9} x")
        );
        assert_eq!(form_field(b"a=1", "user"), None);
        assert_eq!(form_field(b"\xff", "user"), None);
    }
}
