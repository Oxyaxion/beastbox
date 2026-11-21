//! Public links from the clients (§8): the `files_sharing` OCS API, on the same links as the web page.
//! Only link shares (type 3): read-only (permissions 1) or drop only on a folder (4). No sharing between users,
//! no federation: the other kinds are refused. Identifier: 31 bits of the link identifier, in decimal (Android reads
//! it as a 32-bit integer).
//! shortcut: form bodies only (what the Android and desktop clients send); add JSON bodies if a client needs them.

use super::{is_v2, json};
use crate::auth::UserCtx;
use crate::db::ShareRow;
use crate::fs::{Meta, SafePath};
use crate::http::{App, Base, ClientIp, blocking, form_field, require_user};
use crate::i18n::Lang;
use crate::tenant::TenantCtx;
use crate::web::share::{LinkChange, LinkError, NewLink, change_link, create_link};
use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// OCS link permissions: read (1, possibly with the share bit 16), create (4).
const READ: u32 = 1;
const CREATE: u32 = 4;
/// Read, update, create, delete: the clients' "upload and editing", answered for a read-and-upload link.
const EDIT: u32 = 15;

/// Capabilities announced to the clients: public links, optional password and expiry, file drop.
pub(super) const CAPABILITIES: &str = r#""files_sharing":{"api_enabled":true,"public":{"enabled":true,"password":{"enforced":false,"askForOptionalPassword":false},"expire_date":{"enabled":false},"multiple_links":true,"send_mail":false,"upload":true,"upload_files_drop":true},"resharing":false,"user":{"send_mail":false},"group_sharing":false,"federation":{"outgoing":false,"incoming":false},"sharebymail":{"enabled":false},"default_permissions":1}"#;

/// OCS identifier of a link: the Android app reads it as a 32-bit integer (a larger one makes it reject the whole
/// list); unique among the owner's live links (`web::share::client_id`).
pub(crate) fn ocs_id(share_id: &str) -> u64 {
    u64::from(crate::web::share::client_id(share_id))
}

/// JSON string, quoted and escaped.
fn js(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if u32::from(c) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                o.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// How the client wants the answer: OCS v1 or v2, JSON (`format=json` or `Accept: application/json`, the desktop
/// client) or XML (the default, the Android app).
pub(super) struct Out {
    v2: bool,
    json: bool,
}

impl Out {
    fn of(uri: &Uri, h: &HeaderMap) -> Self {
        let q = uri.query().unwrap_or("").as_bytes();
        let accept = h.get(header::ACCEPT).and_then(|v| v.to_str().ok()).unwrap_or("");
        Self {
            v2: is_v2(uri),
            json: form_field(q, "format").as_deref() == Some("json")
                || (form_field(q, "format").is_none() && accept.contains("application/json")),
        }
    }
}

/// A value of an OCS answer, written in JSON or XML.
enum V {
    S(String),
    I(i64),
    B(bool),
    Null,
}

type Fields = Vec<(&'static str, V)>;

/// The `data` of an OCS answer.
enum Data {
    Empty,
    One(Fields),
    List(Vec<Fields>),
}

fn json_obj(f: &Fields) -> String {
    let items: Vec<String> = f
        .iter()
        .map(|(k, v)| {
            let v = match v {
                V::S(s) => js(s),
                V::I(n) => n.to_string(),
                V::B(b) => b.to_string(),
                V::Null => "null".into(),
            };
            format!("\"{k}\":{v}")
        })
        .collect();
    format!("{{{}}}", items.join(","))
}

/// XML text, escaped.
fn xt(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// As Nextcloud writes it: `true` → 1, `false` and `null` → an empty element.
fn xml_obj(f: &Fields) -> String {
    f.iter()
        .map(|(k, v)| match v {
            V::S(s) => format!("<{k}>{}</{k}>", xt(s)),
            V::I(n) => format!("<{k}>{n}</{k}>"),
            V::B(true) => format!("<{k}>1</{k}>"),
            V::B(false) | V::Null => format!("<{k}/>"),
        })
        .collect()
}

fn reply(out: &Out, code: StatusCode, msg: &str, data: Data) -> Response {
    let (status, sc) = match (code.is_success(), out.v2) {
        (true, true) => ("ok", 200),
        (true, false) => ("ok", 100),
        (false, true) => ("failure", code.as_u16()),
        (false, false) => ("failure", 400),
    };
    // OCS v1 always answers 200, the status is in the envelope.
    let http = if out.v2 { code } else { StatusCode::OK };
    if out.json {
        let data = match &data {
            Data::Empty => "[]".to_owned(),
            Data::One(f) => json_obj(f),
            Data::List(l) => format!("[{}]", l.iter().map(json_obj).collect::<Vec<_>>().join(",")),
        };
        return json(
            http,
            format!(
                r#"{{"ocs":{{"meta":{{"status":"{status}","statuscode":{sc},"message":{},"totalitems":"","itemsperpage":""}},"data":{data}}}}}"#,
                js(msg)
            ),
        );
    }
    let data = match &data {
        Data::Empty => "<data/>".to_owned(),
        Data::List(l) if l.is_empty() => "<data/>".to_owned(),
        Data::One(f) => format!("<data>{}</data>", xml_obj(f)),
        Data::List(l) => format!(
            "<data>{}</data>",
            l.iter()
                .map(|f| format!("<element>{}</element>", xml_obj(f)))
                .collect::<String>()
        ),
    };
    (
        http,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        format!(
            "<?xml version=\"1.0\"?>\n<ocs><meta><status>{status}</status><statuscode>{sc}</statuscode><message>{}</message><totalitems></totalitems><itemsperpage></itemsperpage></meta>{data}</ocs>",
            xt(msg)
        ),
    )
        .into_response()
}

fn refused(out: &Out, lang: Lang, e: LinkError) -> Response {
    match e {
        LinkError::Refused(m) => reply(out, StatusCode::BAD_REQUEST, lang.t(m), Data::Empty),
        LinkError::Busy => reply(out, StatusCode::SERVICE_UNAVAILABLE, "", Data::Empty),
        LinkError::Io(e) => reply(out, StatusCode::NOT_FOUND, &e.to_string(), Data::Empty),
    }
}

/// `/Docs/a b.txt` or `Docs/` → the user's path (`None` = the root).
fn client_path(p: &str) -> Option<Option<SafePath>> {
    let p = p.trim_matches('/');
    if p.is_empty() {
        return Some(None);
    }
    SafePath::new(p).ok().map(Some)
}

/// A request parameter: the form body, then the query string.
fn param(body: &[u8], uri: &Uri, k: &str) -> Option<String> {
    form_field(body, k).or_else(|| form_field(uri.query().unwrap_or("").as_bytes(), k))
}

/// `YYYY-MM-DD` (possibly followed by a time, ignored) → end of that day; empty → no expiry.
fn expiry(v: &str) -> Result<Option<i64>, LinkError> {
    let day = v.split([' ', 'T']).next().unwrap_or("");
    if day.is_empty() {
        return Ok(None);
    }
    crate::web::render::parse_day_end(day)
        .map(Some)
        .ok_or(LinkError::Refused("Invalid or past expiry date."))
}

/// Link permissions → access, never more than asked and never refused (a refusal leaves the desktop client stuck):
/// read and create (the clients' "upload and editing", 15) → read and upload, the guest adds files but never changes
/// nor deletes one; create alone (4) → drop; read with update or delete but no create (a file's "editing", 3) →
/// read only. Without read nor create: refused.
fn perms_of(v: &str) -> Result<&'static str, LinkError> {
    let p = v.trim().parse::<u32>().unwrap_or(0);
    match (p & READ != 0, p & CREATE != 0) {
        (true, true) => Ok("upload"),
        (false, true) => Ok("drop"),
        (true, false) => Ok("read"),
        (false, false) => Err(LinkError::Refused(
            "Only read-only, read-and-upload and drop-only links are offered.",
        )),
    }
}

/// `hideDownload`: `"true"`/`"false"` (desktop client), `1`/`0` tolerated.
fn flag(v: &str) -> bool {
    matches!(v.trim(), "true" | "1")
}

/// A share as the clients read it.
fn share_fields(base: &Base, u: &UserCtx, s: &ShareRow, m: &Meta) -> Fields {
    let user = || V::S(u.user().to_owned());
    let path = || V::S(format!("/{}", s.path_hint));
    let token = crate::auth::share_token(u.tenant(), &s.share_id);
    let (item, mime) = if m.is_dir {
        ("folder", "httpd/unix-directory")
    } else {
        ("file", crate::web::render::mime(&s.path_hint))
    };
    // Clients only check that this field is set to show "password protected"; the digest never leaves.
    let with = || {
        if s.password_hash.is_some() {
            V::S("***redacted***".into())
        } else {
            V::Null
        }
    };
    let perms = match crate::web::share::access(s) {
        "drop" => CREATE,
        "upload" => EDIT,
        _ => READ,
    };
    let fileid = i64::try_from(crate::etag::fileid(m)).unwrap_or(0);
    let i = |n: u64| V::I(i64::try_from(n).unwrap_or(0));
    vec![
        ("id", V::S(ocs_id(&s.share_id).to_string())),
        ("share_type", V::I(3)),
        ("uid_owner", user()),
        ("displayname_owner", user()),
        ("permissions", V::I(i64::from(perms))),
        ("can_edit", V::B(true)),
        ("can_delete", V::B(true)),
        ("stime", V::I(s.created_at)),
        ("parent", V::Null),
        (
            "expiration",
            s.expires_at.map_or(V::Null, |e| V::S(format!("{} 00:00:00", day(e)))),
        ),
        ("token", V::S(token.clone())),
        ("uid_file_owner", user()),
        ("displayname_file_owner", user()),
        ("note", V::S(s.opts.note.clone())),
        ("label", V::S(s.opts.label.clone())),
        ("path", path()),
        ("item_type", V::S(item.into())),
        ("mimetype", V::S(mime.into())),
        ("has_preview", V::B(false)),
        ("storage_id", V::S(format!("home::{}", u.user()))),
        ("storage", V::I(1)),
        ("item_source", V::I(fileid)),
        ("file_source", V::I(fileid)),
        ("file_parent", V::I(0)),
        ("file_target", path()),
        ("item_size", i(m.size)),
        ("item_mtime", V::I(m.mtime)),
        ("share_with", with()),
        ("share_with_displayname", with()),
        ("password", with()),
        ("send_password_by_talk", V::B(false)),
        ("url", V::S(format!("{}/s/{token}", base.0))),
        ("mail_send", V::I(0)),
        ("hide_download", V::I(i64::from(s.opts.hide_download))),
        ("attributes", V::Null),
    ]
}

/// The local day of a timestamp, `YYYY-MM-DD`.
fn day(ts: i64) -> String {
    crate::web::render::date(ts).chars().take(10).collect()
}

/// The owner's live links whose target is still in place, with it.
fn live(app: &App, u: &UserCtx) -> crate::Result<Vec<(ShareRow, Meta)>> {
    let root = u.root()?;
    let mut out = Vec::new();
    for s in app.db.share_list(u.tenant(), u.user())? {
        let Ok(p) = client_path(&s.path_hint).ok_or(()) else {
            continue;
        };
        // Same rule as the link itself: found by its path, checked by its identity.
        if let Ok(m) = root.meta(p.as_ref())
            && m.id.as_ref().is_some_and(|id| s.fileid == id.0)
        {
            out.push((s, m));
        }
    }
    Ok(out)
}

/// `GET|POST /ocs/v{1,2}.php/apps/files_sharing/api/v1/shares`.
#[allow(clippy::too_many_arguments)]
pub async fn shares(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    Extension(base): Extension<Base>,
    method: Method,
    uri: Uri,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let u = match require_user(&app, &t, ip, &h).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let lang = Lang::from(&h, None);
    let out = Out::of(&uri, &h);
    match method {
        Method::GET => list(&app, &u, &base, &uri, &out).await,
        Method::POST => create(&app, &u, &base, &uri, &out, lang, &body).await,
        _ => reply(&out, StatusCode::METHOD_NOT_ALLOWED, "", Data::Empty),
    }
}

async fn list(app: &Arc<App>, u: &UserCtx, base: &Base, uri: &Uri, out: &Out) -> Response {
    let q = uri.query().unwrap_or("").as_bytes();
    // Nothing is ever shared with this user (no sharing between users).
    if form_field(q, "shared_with_me").as_deref() == Some("true") {
        return reply(out, StatusCode::OK, "", Data::Empty);
    }
    let path = match form_field(q, "path").map(|p| client_path(&p)) {
        None => None,
        Some(Some(p)) => Some(p.map(|p| p.as_str().to_owned()).unwrap_or_default()),
        Some(None) => return reply(out, StatusCode::NOT_FOUND, "", Data::Empty),
    };
    let subfiles = form_field(q, "subfiles").as_deref() == Some("true");
    let (app2, u2) = (app.clone(), u.clone());
    let Ok(Ok(rows)) = blocking(move || live(&app2, &u2)).await else {
        return reply(out, StatusCode::SERVICE_UNAVAILABLE, "", Data::Empty);
    };
    let keep = |hint: &str| match &path {
        None => true,
        Some(p) if subfiles => hint.rsplit_once('/').map_or("", |(d, _)| d) == p && !hint.is_empty(),
        Some(p) => hint == p,
    };
    let items = rows
        .iter()
        .filter(|(s, _)| keep(&s.path_hint))
        .map(|(s, m)| share_fields(base, u, s, m))
        .collect();
    reply(out, StatusCode::OK, "", Data::List(items))
}

#[allow(clippy::too_many_arguments)]
async fn create(app: &Arc<App>, u: &UserCtx, base: &Base, uri: &Uri, out: &Out, lang: Lang, body: &[u8]) -> Response {
    let arg = |k| param(body, uri, k);
    if arg("shareType").as_deref() != Some("3") {
        return refused(out, lang, LinkError::Refused("Only public links are offered."));
    }
    let Some(path) = arg("path").and_then(|p| client_path(&p)) else {
        return reply(out, StatusCode::NOT_FOUND, "", Data::Empty);
    };
    let made = async {
        let perms = match arg("permissions") {
            Some(p) => perms_of(&p)?,
            // Legacy "upload" switch: upload and editing.
            None if arg("publicUpload").as_deref() == Some("true") => "upload",
            None => "read",
        };
        let expires = match arg("expireDate") {
            Some(e) => expiry(&e)?,
            None => None,
        };
        let password = arg("password").filter(|p| !p.is_empty());
        create_link(
            app,
            u,
            NewLink {
                path,
                perms,
                password,
                expires,
                max: None,
                // The desktop client names a new link `name`.
                label: arg("label").or_else(|| arg("name")).unwrap_or_default(),
                note: arg("note").unwrap_or_default(),
                hide_download: arg("hideDownload").is_some_and(|v| flag(&v)),
            },
        )
        .await
    };
    match made.await {
        Ok(id) => one(app, u, base, out, &id).await,
        Err(e) => refused(out, lang, e),
    }
}

/// The reply with one link, found by its identifier.
async fn one(app: &Arc<App>, u: &UserCtx, base: &Base, out: &Out, share_id: &str) -> Response {
    let (app2, u2) = (app.clone(), u.clone());
    let Ok(Ok(rows)) = blocking(move || live(&app2, &u2)).await else {
        return reply(out, StatusCode::SERVICE_UNAVAILABLE, "", Data::Empty);
    };
    match rows.iter().find(|(s, _)| s.share_id == share_id) {
        Some((s, m)) => reply(out, StatusCode::OK, "", Data::One(share_fields(base, u, s, m))),
        None => reply(out, StatusCode::NOT_FOUND, "", Data::Empty),
    }
}

/// `GET|PUT|DELETE /ocs/v{1,2}.php/apps/files_sharing/api/v1/shares/<id>`.
#[allow(clippy::too_many_arguments)]
pub async fn share(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    Extension(base): Extension<Base>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let u = match require_user(&app, &t, ip, &h).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let lang = Lang::from(&h, None);
    let out = Out::of(&uri, &h);
    let (app2, u2) = (app.clone(), u.clone());
    let Ok(Ok(rows)) = blocking(move || app2.db.share_list(u2.tenant(), u2.user())).await else {
        return reply(&out, StatusCode::SERVICE_UNAVAILABLE, "", Data::Empty);
    };
    let Some(s) = id
        .parse::<u64>()
        .ok()
        .and_then(|n| rows.into_iter().find(|s| ocs_id(&s.share_id) == n))
    else {
        return reply(&out, StatusCode::NOT_FOUND, "", Data::Empty);
    };
    match method {
        Method::GET => one(&app, &u, &base, &out, &s.share_id).await,
        Method::DELETE => {
            let (app2, u2, sid) = (app.clone(), u.clone(), s.share_id.clone());
            match blocking(move || app2.db.share_revoke(u2.tenant(), u2.user(), &sid)).await {
                Ok(Ok(true)) => {
                    tracing::info!(tenant = t.name(), user = u.user(), "share link revoked");
                    reply(&out, StatusCode::OK, "", Data::Empty)
                }
                Ok(Ok(false)) => reply(&out, StatusCode::NOT_FOUND, "", Data::Empty),
                _ => reply(&out, StatusCode::SERVICE_UNAVAILABLE, "", Data::Empty),
            }
        }
        Method::PUT => {
            let arg = |k| param(&body, &uri, k);
            let change = (|| {
                Ok(LinkChange {
                    perms: arg("permissions").map(|p| perms_of(&p)).transpose()?,
                    password: arg("password").map(|p| Some(p).filter(|p| !p.is_empty())),
                    expires: arg("expireDate").map(|e| expiry(&e)).transpose()?,
                    label: arg("label"),
                    note: arg("note"),
                    hide_download: arg("hideDownload").map(|v| flag(&v)),
                })
            })();
            let done = match change {
                Ok(c) => change_link(&app, &u, &s, c).await,
                Err(e) => Err(e),
            };
            match done {
                Ok(true) => one(&app, &u, &base, &out, &s.share_id).await,
                Ok(false) => reply(&out, StatusCode::NOT_FOUND, "", Data::Empty),
                Err(e) => refused(&out, lang, e),
            }
        }
        _ => reply(&out, StatusCode::METHOD_NOT_ALLOWED, "", Data::Empty),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(js("a\"b\\c\n\u{1}é"), r#""a\"b\\c\u000a\u0001é""#);
        assert_eq!(ocs_id("00000002000000000000000000000000"), 1);
        assert_eq!(ocs_id("ffffffffffffffffffffffffffffffff"), (1 << 31) - 1);
        assert!(matches!(perms_of("1"), Ok("read")));
        assert!(matches!(perms_of("17"), Ok("read")));
        assert!(matches!(perms_of("4"), Ok("drop")));
        assert!(matches!(perms_of("15"), Ok("upload")) && matches!(perms_of("31"), Ok("upload")));
        assert!(matches!(perms_of("7"), Ok("upload")) && matches!(perms_of("5"), Ok("upload")));
        // A file's "editing" (read + update), with or without delete and share: read only.
        assert!(
            matches!(perms_of("3"), Ok("read"))
                && matches!(perms_of("19"), Ok("read"))
                && matches!(perms_of("11"), Ok("read"))
        );
        assert!(perms_of("2").is_err() && perms_of("16").is_err() && perms_of("x").is_err());
        assert!(flag("true") && flag("1") && !flag("false") && !flag(""));
        assert!(matches!(expiry(""), Ok(None)));
        assert!(matches!(expiry("2099-01-31 00:00:00"), Ok(Some(_))));
        assert!(expiry("demain").is_err());
        assert_eq!(client_path("/").map(|p| p.is_none()), Some(true));
        assert_eq!(client_path("/Docs/a b.txt/").unwrap().unwrap().as_str(), "Docs/a b.txt");
        assert!(client_path("/../etc").is_none());
    }
}
