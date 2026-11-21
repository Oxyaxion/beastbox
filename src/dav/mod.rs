//! File WebDAV (§7): OPTIONS, PROPFIND (Depth 0/1), GET/HEAD with Range, PUT, MKCOL, MOVE, COPY, DELETE
//! (to the trash), and chunked upload v2 (`upload`). Streamed reads and writes: constant memory
//! whatever the size of the folder or file (§0.4).

pub(crate) mod search;
mod trashbin;
mod upload;
pub(crate) mod write;

pub use search::dav_root;
pub use trashbin::trashbin;
pub use upload::uploads;

use crate::auth::UserCtx;
use crate::etag;
use crate::fs::{Meta, Root, SafePath, Space};
use crate::http::{App, Base, ClientIp, blocking, require_user};
use crate::tenant::TenantCtx;
use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

const ALLOW: &str = "OPTIONS, GET, HEAD, PROPFIND, PROPPATCH, PUT, MKCOL, MOVE, COPY, DELETE";
/// Size of a chunk sent (PROPFIND and GET).
const CHUNK: usize = 64 * 1024;
/// PROPFIND body: small by construction (§9).
const PROPFIND_BODY_MAX: usize = 64 * 1024;
const MAX_PROPS: usize = 64;
const NS_DAV: &str = "DAV:";
const NS_OC: &str = "http://owncloud.org/ns";
const NS_NC: &str = "http://nextcloud.org/ns";
const NS_OCS: &str = "http://open-collaboration-services.org/ns";
/// URL segments: everything except unreserved characters is encoded.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// Authenticated WebDAV request, ready to be dispatched.
struct Dav {
    app: Arc<App>,
    u: UserCtx,
    /// Prefix of `href`s and `Destination`s: `/remote.php/dav/files/<user>/` or `/remote.php/webdav/`.
    base: String,
    /// `scheme://host` of the request (to recognize a `Destination` given as an absolute URL).
    origin: Base,
}

/// `/remote.php/dav/files/{user}/{*path}`: the user in the URL must be the authenticated one, otherwise 404.
pub async fn files(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    Extension(origin): Extension<Base>,
    Path(params): Path<HashMap<String, String>>,
    req: Request,
) -> Response {
    let u = match require_user(&app, &t, ip, req.headers()).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    if params.get("user").map(String::as_str) != Some(u.user()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let base = format!("/remote.php/dav/files/{}/", u.user());
    let raw = params.get("path").cloned().unwrap_or_default();
    dispatch(Dav { app, u, base, origin }, &raw, req).await
}

/// Old root `/remote.php/webdav/{*path}`: same tree, implicit user.
pub async fn webdav(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    Extension(origin): Extension<Base>,
    Path(p): Path<String>,
    req: Request,
) -> Response {
    match require_user(&app, &t, ip, req.headers()).await {
        Ok(u) => {
            dispatch(
                Dav {
                    app,
                    u,
                    base: "/remote.php/webdav/".into(),
                    origin,
                },
                &p,
                req,
            )
            .await
        }
        Err(r) => r,
    }
}

pub async fn webdav_root(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    Extension(origin): Extension<Base>,
    req: Request,
) -> Response {
    match require_user(&app, &t, ip, req.headers()).await {
        Ok(u) => {
            dispatch(
                Dav {
                    app,
                    u,
                    base: "/remote.php/webdav/".into(),
                    origin,
                },
                "",
                req,
            )
            .await
        }
        Err(r) => r,
    }
}

/// The rest of `/remote.php/` (avatars, versions, DAV roots…): authenticated, then 404.
pub async fn remote_other(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
) -> Response {
    match require_user(&app, &t, ip, &h).await {
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(r) => r,
    }
}

/// URL path (already decoded once by the router) → `SafePath`; empty = the user's root.
/// `Err`: path refused (`..`, NUL, reserved names…) → 404.
fn safe(raw: &str) -> Result<Option<SafePath>, ()> {
    let trimmed = raw.trim_matches('/');
    if trimmed.is_empty() {
        Ok(None)
    } else {
        SafePath::new(trimmed).map(Some).map_err(|_| ())
    }
}

/// Reads a whole small body (PROPFIND), bounded.
async fn small_body(body: Body) -> Result<Bytes, Response> {
    axum::body::to_bytes(body, PROPFIND_BODY_MAX)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE.into_response())
}

/// The web interface's WebDAV (`/web/dav/…`): same operations, authenticated by the session (CSRF check done by the caller).
pub(crate) async fn web_dav(app: Arc<App>, u: UserCtx, origin: Base, raw: &str, req: Request) -> Response {
    dispatch(
        Dav {
            app,
            u,
            base: "/web/dav/".into(),
            origin,
        },
        raw,
        req,
    )
    .await
}

async fn dispatch(d: Dav, raw: &str, req: Request) -> Response {
    let Ok(path) = safe(raw) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (parts, body) = req.into_parts();
    let h = &parts.headers;
    match parts.method.as_str() {
        "OPTIONS" => (
            StatusCode::OK,
            [(header::ALLOW, ALLOW), (header::HeaderName::from_static("dav"), "1, 3")],
        )
            .into_response(),
        "PROPFIND" => {
            let body = match small_body(body).await {
                Ok(b) => b,
                Err(r) => return r,
            };
            let (u, app, u2) = (d.u.clone(), d.app.clone(), d.u.clone());
            // Persistent identities with a live link (the clients' "shared" icon).
            let links = move || {
                let v = app.db.share_list(u2.tenant(), u2.user()).unwrap_or_default();
                v.into_iter().map(|s| s.fileid).collect()
            };
            propfind(move || u.root(), links, d.base, path, h, &body).await
        }
        "GET" | "HEAD" => match path {
            Some(p) => get(d.u, p, parts.method == Method::HEAD, h).await,
            // Like sabre/dav: HEAD on a folder → 200 without body (the desktop client uses it to test the connection).
            None if parts.method == Method::HEAD => StatusCode::OK.into_response(),
            None => (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, ALLOW)]).into_response(),
        },
        "PROPPATCH" => match small_body(body).await {
            Ok(b) => write::proppatch(&d, path, &b).await,
            Err(r) => r,
        },
        "PUT" => write::put(&d, path, h, body).await,
        "MKCOL" => write::mkcol(&d, path, h).await,
        "DELETE" => write::delete(&d, path).await,
        "MOVE" | "COPY" => write::move_copy(&d, path, h, parts.method.as_str() == "MOVE").await,
        _ => (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, ALLOW)]).into_response(),
    }
}

pub(crate) fn io_status(e: &io::Error) -> StatusCode {
    match e.raw_os_error() {
        Some(libc::ENOENT | libc::ELOOP | libc::ENOTDIR | libc::EMLINK) => StatusCode::NOT_FOUND,
        Some(libc::EACCES | libc::EPERM | libc::ENOTCAPABLE) => StatusCode::FORBIDDEN,
        _ if e.kind() == io::ErrorKind::IsADirectory => StatusCode::METHOD_NOT_ALLOWED,
        _ => {
            tracing::error!("disk error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------- PROPFIND

#[derive(Debug, PartialEq)]
enum Want {
    All,
    Props(Vec<(String, String)>),
}

/// XML local name (simplified NCName): a letter or `_` first, then letters, digits, `-`, `.`, `_`. quick-xml does not
/// validate names: without this check, a hostile name (spaces, quotes) would be echoed in the 404 response and break it.
/// Namespaces reserved by XML: cannot be bound to any other prefix (found by fuzzing) → 400.
const RESERVED_NS: [&str; 2] = ["http://www.w3.org/XML/1998/namespace", "http://www.w3.org/2000/xmlns/"];

fn valid_name(s: &str) -> bool {
    let mut it = s.chars();
    it.next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && it.all(|c| c.is_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// Property name requested by a client (PROPFIND, SEARCH, PROPPATCH), which will be echoed in the response: valid
/// local name, prefix bound to a non-empty namespace, namespace without control characters and not reserved by XML.
/// A single rule for the three parsers: fuzzing found a parser that had forgotten it.
fn prop_name_ok(prefixed: bool, bound: bool, ns: &str, local: &str) -> bool {
    valid_name(local)
        && !(prefixed && (!bound || ns.is_empty()))
        && !ns.chars().any(char::is_control)
        && !RESERVED_NS.contains(&ns)
}

/// PROPFIND body (empty = allprop). quick-xml loads no external entity or DTD (§9).
fn parse_propfind(body: &[u8]) -> Option<Want> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Some(Want::All);
    }
    let mut r = quick_xml::reader::NsReader::from_reader(body);
    r.config_mut().trim_text(true);
    let (mut depth, mut prop_depth, mut props, mut all) = (0usize, None, Vec::new(), false);
    loop {
        let (ns, ev) = r.read_resolved_event().ok()?;
        let (bound, ns) = match ns {
            ResolveResult::Bound(n) => (true, n.0.to_owned()),
            ResolveResult::Unbound => (false, String::new()),
            // Prefix never declared: invalid document (RFC 4918 §8.3, litmus test propfind_invalid2).
            ResolveResult::Unknown(_) => return None,
        };
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let local: String = e.local_name().as_ref().to_owned();
                // A prefixed name must point to a non-empty namespace (`xmlns:x=""` is forbidden in XML 1.0).
                if e.name().prefix().is_some() && (!bound || ns.is_empty()) {
                    return None;
                }
                if prop_depth.is_some_and(|d| depth == d + 1) {
                    if props.len() >= MAX_PROPS {
                        return None;
                    }
                    if !prop_name_ok(e.name().prefix().is_some(), bound, &ns, &local) {
                        return None;
                    }
                    props.push((ns.clone(), local.clone()));
                }
                if ns == NS_DAV && (local == "allprop" || local == "propname") {
                    all = true; // shortcut: propname treated as allprop (no observed client uses it)
                }
                if matches!(ev, Event::Start(_)) {
                    if ns == NS_DAV && local == "prop" && prop_depth.is_none() {
                        prop_depth = Some(depth);
                    }
                    depth += 1;
                }
            }
            Event::End(_) => depth = depth.checked_sub(1)?,
            // Unclosed tags: malformed document → 400 (litmus test propfind_invalid).
            Event::Eof if depth != 0 => return None,
            Event::Eof => break,
            _ => {}
        }
    }
    Some(if all || props.is_empty() {
        Want::All
    } else {
        Want::Props(props)
    })
}

fn xml_attr_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Last year an HTTP date can hold (`httpdate` panics beyond): 9999-12-31 23:59:59 UTC.
pub(crate) const MAX_MTIME: i64 = 253_402_300_799;

/// HTTP date of a modification time, clamped to 1970..=9999: a file can carry any date (`touch`, copy from
/// elsewhere), and a panic would make its whole folder unlistable (found by fuzzing).
fn http_date(mtime: i64) -> String {
    let secs = u64::try_from(mtime.clamp(0, MAX_MTIME)).unwrap_or(0);
    httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(secs))
}

/// Value of a known property for this entry, or `None` (→ 404 in the response).
fn prop(ns: &str, local: &str, m: &Meta, space: Option<&Space>) -> Option<String> {
    Some(match (ns, local) {
        (NS_DAV, "getetag") => format!("<d:getetag>\"{}\"</d:getetag>", etag::of(m)),
        (NS_DAV, "getlastmodified") => {
            format!("<d:getlastmodified>{}</d:getlastmodified>", http_date(m.mtime))
        }
        (NS_DAV, "getcontentlength") if m.is_file => format!("<d:getcontentlength>{}</d:getcontentlength>", m.size),
        (NS_DAV, "getcontenttype") if m.is_file => {
            "<d:getcontenttype>application/octet-stream</d:getcontenttype>".into()
        }
        (NS_DAV, "resourcetype") if m.is_dir => "<d:resourcetype><d:collection/></d:resourcetype>".into(),
        (NS_DAV, "resourcetype") => "<d:resourcetype/>".into(),
        (NS_DAV, "quota-available-bytes") if m.is_dir => {
            format!(
                "<d:quota-available-bytes>{}</d:quota-available-bytes>",
                space?.available
            )
        }
        (NS_DAV, "quota-used-bytes") if m.is_dir => {
            format!("<d:quota-used-bytes>{}</d:quota-used-bytes>", space?.used)
        }
        (NS_OC, "fileid") => format!("<oc:fileid>{}</oc:fileid>", etag::fileid(m)),
        (NS_OC, "id") => format!("<oc:id>{:08}ocbeastbox</oc:id>", etag::fileid(m)),
        // Readable, renamable, movable, deletable; file: writable; folder: files and folders can be created in it.
        (NS_OC, "permissions") if m.is_dir => "<oc:permissions>RGDNVCK</oc:permissions>".into(),
        (NS_OC, "permissions") => "<oc:permissions>RGDNVW</oc:permissions>".into(),
        (NS_OC, "checksums") if m.is_file => {
            format!(
                "<oc:checksums><oc:checksum>SHA1:{}</oc:checksum></oc:checksums>",
                m.sha1.as_deref()?
            )
        }
        // What a link may give (§8): read (1) and share (16); a folder also drop (create, 4). Desktop client's dialog.
        (NS_OCS, "share-permissions") => format!(
            "<x1:share-permissions xmlns:x1=\"{NS_OCS}\">{}</x1:share-permissions>",
            if m.is_dir { 21 } else { 17 }
        ),
        (NS_OC, "size") if m.is_file => format!("<oc:size>{}</oc:size>", m.size),
        (NS_NC, "has-preview") => "<nc:has-preview>false</nc:has-preview>".into(),
        (NS_OC, "favorite") => format!("<oc:favorite>{}</oc:favorite>", u8::from(m.favorite)),
        _ => return None,
    })
}

const MULTISTATUS: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<d:multistatus xmlns:d=\"DAV:\" \
                           xmlns:oc=\"http://owncloud.org/ns\" xmlns:nc=\"http://nextcloud.org/ns\">";

const ALLPROP: [(&str, &str); 5] = [
    (NS_DAV, "getetag"),
    (NS_DAV, "getlastmodified"),
    (NS_DAV, "getcontentlength"),
    (NS_DAV, "getcontenttype"),
    (NS_DAV, "resourcetype"),
];

/// Identities of the items with a live public link (`oc:share-types`).
type Shared = HashSet<Vec<u8>>;

fn render(out: &mut String, href: &str, m: &Meta, want: &Want, space: Option<&Space>, shared: &Shared) {
    render_with(out, href, want, &ALLPROP, |n, l| match (n, l) {
        // The href ends with the (encoded) name: the extension is readable as is.
        (NS_NC, "has-preview") => Some(has_preview(href, m)),
        // shortcut: by identity only; a link whose target moved keeps the icon until it is used (then it ends).
        (NS_OC, "share-types") => Some(
            if m.id.as_ref().is_some_and(|id| shared.contains(id.0.as_slice())) {
                "<oc:share-types><oc:share-type>3</oc:share-type></oc:share-types>"
            } else {
                "<oc:share-types/>"
            }
            .into(),
        ),
        _ => prop(n, l, m, space),
    });
}

/// `nc:has-preview`: JPEG files get a thumbnail (`nc::thumb`); a corrupt one gives a 404 and the client's icon.
pub(crate) fn has_preview(name: &str, m: &Meta) -> String {
    let n = name.to_ascii_lowercase();
    let yes = m.is_file && (n.ends_with(".jpg") || n.ends_with(".jpeg"));
    format!("<nc:has-preview>{yes}</nc:has-preview>")
}

/// A `<d:response>`: `all` = allprop properties, `prop` = value of a property (`None` → 404).
fn render_with(
    out: &mut String,
    href: &str,
    want: &Want,
    all: &[(&str, &str)],
    prop: impl Fn(&str, &str) -> Option<String>,
) {
    out.push_str("<d:response><d:href>");
    out.push_str(href);
    out.push_str("</d:href><d:propstat><d:prop>");
    let mut missing = Vec::new();
    match want {
        Want::All => all
            .iter()
            .filter_map(|(n, l)| prop(n, l))
            .for_each(|v| out.push_str(&v)),
        Want::Props(ps) => {
            for (n, l) in ps {
                match prop(n, l) {
                    Some(v) => out.push_str(&v),
                    None => missing.push((n, l)),
                }
            }
        }
    }
    out.push_str("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>");
    if !missing.is_empty() {
        out.push_str("<d:propstat><d:prop>");
        for (n, l) in missing {
            // Local name from the XML parser (already a valid name); namespace escaped.
            if n.is_empty() {
                // Without namespace: `xmlns:x=""` would be invalid, so we reset the default namespace.
                out.push_str(&format!("<{l} xmlns=\"\"/>"));
            } else {
                out.push_str(&format!("<x:{l} xmlns:x=\"{}\"/>", xml_attr_escape(n)));
            }
        }
        out.push_str("</d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>");
    }
    out.push_str("</d:response>");
}

pub(crate) fn href(base: &str, path: Option<&str>, is_dir: bool) -> String {
    let mut s = base.to_owned();
    if let Some(p) = path {
        let enc: Vec<String> = p
            .split('/')
            .map(|seg| utf8_percent_encode(seg, SEGMENT).to_string())
            .collect();
        s.push_str(&enc.join("/"));
        if is_dir {
            s.push('/');
        }
    }
    s
}

/// Stream produced chunk by chunk: each step is a short `spawn_blocking`, the thread is released between two
/// chunks. A slow client therefore ties up no blocking thread (§0.4); memory stays bounded to one chunk.
pub(crate) fn blocking_stream<S: Send + 'static>(
    state: S,
    step: fn(&mut S) -> io::Result<Option<Bytes>>,
) -> impl futures_util::Stream<Item = io::Result<Bytes>> {
    futures_util::stream::unfold(Some(state), move |st| async move {
        let mut st = st?;
        match tokio::task::spawn_blocking(move || (step(&mut st), st)).await {
            Ok((Ok(Some(b)), st)) => Some((Ok(b), Some(st))),
            Ok((Ok(None), _)) => None,
            // Error mid-stream: we cut (truncated response, never a false success).
            Ok((Err(e), _)) => Some((Err(e), None)),
            Err(e) => Some((Err(io::Error::other(e)), None)),
        }
    })
}

struct Listing {
    reader: Option<crate::fs::DirReader>,
    base: String,
    path: Option<SafePath>,
    want: Want,
    space: Option<Space>,
    shared: Shared,
    done: bool,
}

fn listing_step(l: &mut Listing) -> io::Result<Option<Bytes>> {
    if l.done {
        return Ok(None);
    }
    let mut out = String::new();
    let p = l.path.as_ref().map(SafePath::as_str);
    if let Some(reader) = l.reader.as_mut() {
        for e in reader.by_ref() {
            let (name, cm) = e?;
            let child = match p {
                Some(p) => format!("{p}/{name}"),
                None => name,
            };
            render(
                &mut out,
                &href(&l.base, Some(&child), cm.is_dir),
                &cm,
                &l.want,
                l.space.as_ref(),
                &l.shared,
            );
            if out.len() >= CHUNK {
                return Ok(Some(Bytes::from(out)));
            }
        }
    }
    out.push_str("</d:multistatus>");
    l.done = true;
    Ok(Some(Bytes::from(out)))
}

async fn propfind(
    open: impl FnOnce() -> io::Result<Root> + Send + 'static,
    links: impl FnOnce() -> Shared + Send + 'static,
    base: String,
    path: Option<SafePath>,
    h: &HeaderMap,
    body: &[u8],
) -> Response {
    // §9: Depth infinity refused; a missing Depth means infinity (RFC 4918).
    let depth1 = match h.get("depth").and_then(|v| v.to_str().ok()) {
        Some("0") => false,
        Some("1") => true,
        _ => return (StatusCode::FORBIDDEN, "Depth 0 or 1 required").into_response(),
    };
    let Some(want) = parse_propfind(body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // First step: the target itself, so that an error gives a real HTTP code.
    let first = blocking(move || -> io::Result<(Bytes, Listing)> {
        let root = open()?;
        let m = root.meta(path.as_ref())?;
        if !m.is_dir && !m.is_file {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        let space = if m.is_dir { root.space().ok() } else { None };
        // Read only if asked: most PROPFINDs do not touch the database.
        let shared = match &want {
            Want::Props(p) if p.iter().any(|(n, l)| n == NS_OC && l == "share-types") => links(),
            _ => Shared::new(),
        };
        let mut out = String::from(MULTISTATUS);
        render(
            &mut out,
            &href(&base, path.as_ref().map(SafePath::as_str), m.is_dir),
            &m,
            &want,
            space.as_ref(),
            &shared,
        );
        let reader = if depth1 && m.is_dir {
            Some(root.read_dir(path.as_ref())?)
        } else {
            None
        };
        Ok((
            Bytes::from(out),
            Listing {
                reader,
                base,
                path,
                want,
                space,
                shared,
                done: false,
            },
        ))
    })
    .await;
    let (head, listing) = match first {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => return io_status(&e).into_response(),
        Err(r) => return r,
    };
    let stream = futures_util::stream::once(async move { Ok::<_, io::Error>(head) })
        .chain(blocking_stream(listing, listing_step));
    (
        StatusCode::MULTI_STATUS,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        Body::from_stream(stream),
    )
        .into_response()
}

// ---------------------------------------------------------------- GET / HEAD

/// `Range: bytes=…`: `None` = ignore (full response), `Some(Err)` = 416, `Some(Ok((start, inclusive end)))`.
/// A single range; several ranges → full response (allowed by RFC 9110).
fn parse_range(h: &str, size: u64) -> Option<Result<(u64, u64), ()>> {
    let spec = h.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        return Some(if n == 0 || size == 0 {
            Err(())
        } else {
            Ok((size - n.min(size), size - 1))
        });
    }
    let start: u64 = a.parse().ok()?;
    let end: u64 = if b.is_empty() { u64::MAX } else { b.parse().ok()? };
    if start > end {
        return None;
    }
    Some(if start >= size {
        Err(())
    } else {
        Ok((start, end.min(size - 1)))
    })
}

/// How to serve a file.
#[derive(Clone, Debug)]
pub(crate) enum Serve {
    /// WebDAV: raw bytes, no interpretation.
    Dav,
    /// Download: attachment with its name.
    Attachment(String),
    /// Preview in the browser, for a closed list of safe types (images, PDF, audio, video, text).
    Inline(&'static str),
}

async fn get(u: UserCtx, path: SafePath, head: bool, h: &HeaderMap) -> Response {
    serve_file(move || u.root(), path, head, h, Serve::Dav).await
}

/// Serves a file as a stream (Range, ETag). Always `nosniff`; `Content-Security-Policy: sandbox` except for a
/// displayed PDF (the browser's PDF viewer refuses a sandboxed document, and the PDF has its own sandbox).
pub(crate) async fn serve_file(
    open: impl FnOnce() -> io::Result<Root> + Send + 'static,
    path: SafePath,
    head: bool,
    h: &HeaderMap,
    mode: Serve,
) -> Response {
    let opened = blocking(move || open().and_then(|r| r.open_file(&path))).await;
    let (mut file, m) = match opened {
        Ok(Ok(x)) => x,
        Ok(Err(e)) if head && e.kind() == io::ErrorKind::IsADirectory => return StatusCode::OK.into_response(),
        Ok(Err(e)) => return io_status(&e).into_response(),
        Err(r) => return r,
    };
    let tag = format!("\"{}\"", etag::of(&m));
    let range = h
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_range(v, m.size));
    let (code, start, len) = match range {
        Some(Err(())) => {
            return (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, format!("bytes */{}", m.size))],
            )
                .into_response();
        }
        Some(Ok((s, e))) => (StatusCode::PARTIAL_CONTENT, s, e - s + 1),
        None => (StatusCode::OK, 0, m.size),
    };
    let mut res = Response::builder()
        .status(code)
        .header(
            header::CONTENT_TYPE,
            match &mode {
                Serve::Inline(mime) => mime,
                _ => "application/octet-stream",
            },
        )
        .header(header::CONTENT_LENGTH, len)
        .header(header::ETAG, &tag)
        .header("oc-etag", &tag)
        .header(header::LAST_MODIFIED, http_date(m.mtime))
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "private, no-cache");
    // §8: no served content is interpreted in the application's origin.
    if !matches!(mode, Serve::Inline("application/pdf")) {
        res = res.header(header::CONTENT_SECURITY_POLICY, "sandbox");
    }
    if let Serve::Attachment(name) = &mode {
        let enc = utf8_percent_encode(name, SEGMENT);
        res = res.header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename*=UTF-8''{enc}"),
        );
    }
    if code == StatusCode::PARTIAL_CONTENT {
        res = res.header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{}/{}", start + len - 1, m.size),
        );
    }
    if head {
        return res
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    // shortcut: streamed reads in 64 KiB chunks, not sendfile(2); switch to sendfile if throughput caps (docs/dev/VALIDATION.md §7).
    // lseek does no disk I/O: acceptable on the executor.
    if let Err(e) = file.seek(SeekFrom::Start(start)) {
        return io_status(&e).into_response();
    }
    let stream = blocking_stream((file, len), |(file, left)| {
        if *left == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u8; usize::try_from(*left).unwrap_or(CHUNK).min(CHUNK)];
        let n = file.read(&mut buf)?;
        if n == 0 {
            // File shortened during the read: cut rather than lie about the announced length.
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        buf.truncate(n);
        *left -= n as u64;
        Ok(Some(Bytes::from(buf)))
    });
    res.body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Fuzzing entry points (`fuzzing` feature, never compiled into the shipped binary; see `fuzz/`).
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
#[allow(clippy::panic, clippy::unwrap_used)]
pub mod fuzz {
    use super::*;
    use axum::http::HeaderValue;

    /// Arbitrary PROPFIND body: parsing does not crash, and the response produced for the requested properties
    /// (including hostile namespaces) is always well-formed XML.
    pub use super::search::fuzz as search;
    pub use crate::fs::fuzz_manifest as manifest;
    pub use crate::fs::fuzz_restore as restore;

    /// Arbitrary PROPPATCH body: parsing does not crash, and the response (which echoes the names) is well-formed XML.
    pub fn proppatch(data: &[u8]) {
        let Some(u) = write::parse_proppatch(data) else { return };
        let out = write::proppatch_xml(&href("/b/", Some("a b/é"), false), &u);
        let mut r = quick_xml::reader::NsReader::from_reader(out.as_bytes());
        loop {
            match r.read_resolved_event() {
                Ok((_, Event::Eof)) => break,
                Ok(_) => {}
                Err(e) => panic!("invalid XML response ({e}): {out}"),
            }
        }
    }

    pub fn propfind(data: &[u8]) {
        let Some(want) = parse_propfind(data) else { return };
        let m = Meta {
            is_dir: false,
            is_file: true,
            size: 3,
            mtime: 1,
            mtime_nsec: 0,
            ctime: 1,
            ino: 2,
            dev: 3,
            id: None,
            dir_etag: None,
            sha1: Some("00".into()),
            favorite: false,
        };
        let mut out = String::from(
            "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" xmlns:nc=\"http://nextcloud.org/ns\">",
        );
        render(
            &mut out,
            &href("/b/", Some("a b/é"), false),
            &m,
            &want,
            None,
            &Shared::new(),
        );
        out.push_str("</d:multistatus>");
        let mut r = quick_xml::reader::NsReader::from_reader(out.as_bytes());
        loop {
            match r.read_resolved_event() {
                Ok((_, Event::Eof)) => break,
                Ok(_) => {}
                Err(e) => panic!("invalid XML response ({e}): {out}"),
            }
        }
    }

    fn assert_safe(p: &SafePath) {
        let s = p.as_str();
        assert!(
            !s.is_empty() && !s.starts_with('/') && !s.contains('\0') && !s.contains('\\'),
            "{s:?}"
        );
        assert!(s.split('/').all(|c| !c.is_empty() && c != "." && c != ".."), "{s:?}");
        assert!(
            !crate::fs::RESERVED.contains(&s.split('/').next().unwrap_or("")),
            "{s:?}"
        );
    }

    /// Arbitrary header values and paths: no parser crashes, and every accepted path stays under the root.
    pub fn headers(s: &str) {
        let _ = parse_range(s, 1000);
        let _ = parse_range(s, 0);
        if let Ok(p) = SafePath::new(s) {
            assert_safe(&p);
        }
        if let Ok(Some(p)) = write::dest_path("files.example", "/remote.php/dav/files/alice/", s) {
            assert_safe(&p);
        }
        if let Some(h) = crate::tenant::normalize_host(s) {
            assert!(
                h.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'),
                "{h:?}"
            );
        }
        let _ = crate::http::form_field(s.as_bytes(), "user");
        crate::web::share::fuzz_drop_name(s);
        if let Ok(v) = HeaderValue::from_str(s) {
            let mut h = HeaderMap::new();
            for k in ["if-match", "if-none-match", "oc-checksum", "x-oc-mtime"] {
                h.insert(k, v.clone());
            }
            let _ = write::Pre::from(&h).ok(None);
            let _ = write::oc_sha1(&h);
            let _ = write::oc_mtime(&h);
        }
    }
}

#[cfg(test)]
mod isolation;
#[cfg(test)]
mod model;

#[cfg(test)]
mod tests {
    use super::*;

    /// Any modification time gives an HTTP date, never a panic (fuzzing: `X-OC-Mtime` in year 10000 made the
    /// folder unlistable); a client's out-of-range time is ignored.
    #[test]
    fn far_dates_never_panic() {
        assert_eq!(http_date(MAX_MTIME), "Fri, 31 Dec 9999 23:59:59 GMT");
        assert_eq!(http_date(i64::MAX), http_date(MAX_MTIME));
        assert_eq!(http_date(-5), "Thu, 01 Jan 1970 00:00:00 GMT");
        let h = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert("x-oc-mtime", v.parse().unwrap());
            write::oc_mtime(&m)
        };
        assert_eq!(h("1600000000.5"), Some(1_600_000_000));
        assert_eq!(h("253402300799"), Some(MAX_MTIME));
        assert_eq!((h("253402300800"), h("0"), h("-1")), (None, None, None));
    }

    /// A single rule for property names echoed in responses, and the three parsers (PROPFIND, SEARCH,
    /// PROPPATCH) refuse exactly the same hostile names.
    #[test]
    fn prop_names_same_rule_everywhere() {
        assert!(prop_name_ok(true, true, "urn:x", "ok-1.a_b"));
        assert!(prop_name_ok(false, false, "", "nu")); // without namespace
        assert!(!prop_name_ok(false, true, "urn:x", "1abc")); // invalid local name
        assert!(!prop_name_ok(true, false, "", "a")); // unbound prefix
        assert!(!prop_name_ok(true, true, "", "a")); // prefix bound to an empty namespace
        assert!(!prop_name_ok(true, true, "urn:\u{7}", "a")); // control character
        assert!(!prop_name_ok(true, true, "http://www.w3.org/2000/xmlns/", "a")); // reserved

        let propfind = |p: &str| {
            parse_propfind(format!(r#"<d:propfind xmlns:d="DAV:"><d:prop>{p}</d:prop></d:propfind>"#).as_bytes())
                .is_some()
        };
        let search = |p: &str| {
            search::parse(
                format!(
                    r#"<d:searchrequest xmlns:d="DAV:"><d:basicsearch><d:select><d:prop>{p}</d:prop></d:select><d:from><d:scope><d:href>/files/alice</d:href></d:scope></d:from><d:where><d:eq><d:prop><d:favorite/></d:prop><d:literal>yes</d:literal></d:eq></d:where></d:basicsearch></d:searchrequest>"#
                )
                .as_bytes(),
                "alice",
            )
            .is_some()
        };
        let proppatch = |p: &str| {
            write::parse_proppatch(
                format!(r#"<d:propertyupdate xmlns:d="DAV:"><d:set><d:prop>{p}</d:prop></d:set></d:propertyupdate>"#)
                    .as_bytes(),
            )
            .is_some()
        };
        let ok = r#"<x:ok xmlns:x="urn:x"/>"#;
        assert!(propfind(ok) && search(ok) && proppatch(ok));
        for bad in [
            "<zz:nom/>",
            "<x:a xmlns:x=\"urn:\u{7}\"/>",
            "<x:a xmlns:x=\"http://www.w3.org/2000/xmlns/\"/>",
            "<x:a xmlns:x=\"http://www.w3.org/XML/1998/namespace\"/>",
            "<d:x\u{1}y/>",
        ] {
            assert_eq!(
                (propfind(bad), search(bad), proppatch(bad)),
                (false, false, false),
                "{bad:?} accepted by at least one parser"
            );
        }
    }

    #[test]
    fn propfind_parsing() {
        assert_eq!(parse_propfind(b""), Some(Want::All));
        assert_eq!(
            parse_propfind(b"<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:allprop/></d:propfind>"),
            Some(Want::All)
        );
        let body = br#"<?xml version="1.0"?>
            <d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
              <d:prop><d:getetag/><oc:fileid/><x:foo xmlns:x="urn:x"/><d:resourcetype></d:resourcetype></d:prop>
            </d:propfind>"#;
        assert_eq!(
            parse_propfind(body),
            Some(Want::Props(vec![
                (NS_DAV.into(), "getetag".into()),
                (NS_OC.into(), "fileid".into()),
                ("urn:x".into(), "foo".into()),
                (NS_DAV.into(), "resourcetype".into()),
            ]))
        );
        // External entity / bomb: not expanded, and no invented property.
        let xxe = br#"<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><d:propfind xmlns:d="DAV:"><d:prop><d:getetag>&x;</d:getetag></d:prop></d:propfind>"#;
        assert!(matches!(parse_propfind(xxe), None | Some(Want::Props(_))));
        assert_eq!(parse_propfind(b"</a>"), None);
        // litmus: malformed document and invalid namespace declaration → 400.
        assert_eq!(parse_propfind(b"<d:propfind xmlns:d=\"DAV:\"><d:prop>"), None);
        // Fuzzing: reserved `xml:` namespace requested as a property → 400.
        assert_eq!(
            parse_propfind(b"<d:propfind xmlns:d=\"DAV:\"><d:prop><xml:a/></d:prop></d:propfind>"),
            None
        );
        // Property without namespace: accepted, rendered with xmlns="" (tested by the propfind fuzzing target).
        assert!(
            matches!(parse_propfind(b"<d:propfind xmlns:d=\"DAV:\"><d:prop><nons/></d:prop></d:propfind>"), Some(Want::Props(p)) if p == [(String::new(), "nons".to_owned())])
        );
        assert_eq!(
            parse_propfind(b"<d:propfind xmlns:d=\"DAV:\"><d:prop><x:a/></d:prop></d:propfind>"),
            None
        );
        assert_eq!(
            parse_propfind(b"<d:propfind xmlns:d=\"DAV:\"><d:prop><x:a xmlns:x=\"\"/></d:prop></d:propfind>"),
            None
        );
        // Found by fuzzing: invalid element names (spaces, quote) → 400, never echoed in the response.
        for bad in [
            &b"<d:propfind xmlns:d=\"DAV:\"><d:prop><d:a\"b/></d:prop></d:propfind>"[..],
            b"<d:propfind xmlns:d=\"DAV:\"><d:prop><d:1a/></d:prop></d:propfind>",
        ] {
            assert_eq!(parse_propfind(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        let many: String = (0..100).map(|i| format!("<d:p{i}/>")).collect();
        assert_eq!(
            parse_propfind(format!("<d:propfind xmlns:d=\"DAV:\"><d:prop>{many}</d:prop></d:propfind>").as_bytes()),
            None
        );
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-9", 100), Some(Ok((0, 9))));
        assert_eq!(parse_range("bytes=90-", 100), Some(Ok((90, 99))));
        assert_eq!(parse_range("bytes=-10", 100), Some(Ok((90, 99))));
        assert_eq!(parse_range("bytes=-1000", 100), Some(Ok((0, 99))));
        assert_eq!(parse_range("bytes=50-1000", 100), Some(Ok((50, 99))));
        assert_eq!(parse_range("bytes=100-", 100), Some(Err(())));
        assert_eq!(parse_range("bytes=-0", 100), Some(Err(())));
        assert_eq!(parse_range("bytes=0-1,5-6", 100), None);
        assert_eq!(parse_range("bytes=9-1", 100), None);
        assert_eq!(parse_range("items=0-1", 100), None);
        assert_eq!(parse_range("bytes=x-1", 100), None);
        assert_eq!(parse_range("bytes=0-", 0), Some(Err(())));
    }

    #[test]
    fn hrefs_are_encoded() {
        assert_eq!(href("/b/", Some("a b/é#?.txt"), false), "/b/a%20b/%C3%A9%23%3F.txt");
        assert_eq!(href("/b/", Some("d"), true), "/b/d/");
        assert_eq!(href("/b/", None, true), "/b/");
        assert_eq!(xml_attr_escape("\"><x"), "&quot;&gt;&lt;x");
    }
}
