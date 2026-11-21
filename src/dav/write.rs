//! WebDAV writes (§6, §7): streamed PUT, MKCOL, DELETE (trash), MOVE and COPY.
//! Every write that modifies the tree is wrapped by the ETag intent journal (§6): durable intent,
//! operation, renewal of the ETags of the touched folders and their ancestors, intent done.

use super::{ALLOW, Dav, io_status, safe};
use crate::auth::UserCtx;
use crate::etag;
use crate::fs::{AtomicWriter, Meta, Refused, Root, SafePath, Written, is_refused};
use crate::http::{App, blocking};
use crate::tenant::TenantCtx;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use std::io;

/// Received data grouped before each disk write (one `spawn_blocking` per batch): bounded memory per upload.
const WRITE_BATCH: usize = 256 * 1024;

/// Read-only (configuration) or tenant space reserve reached: 503 (§0.2).
pub(super) async fn writable(d: &Dav) -> Result<(), Response> {
    writable_tenant(&d.app, d.u.tenant()).await
}

/// The same rule for what writes without a signed-in user (drop links).
pub(crate) async fn writable_tenant(app: &App, tenant: &TenantCtx) -> Result<(), Response> {
    let unavailable = || {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "300")],
            "Serveur en lecture seule",
        )
            .into_response()
    };
    if app.settings.read_only {
        return Err(unavailable());
    }
    let min = app.settings.min_free_bytes;
    if min > 0 {
        let t = tenant.clone();
        let space = blocking(move || t.data_root().space()).await?;
        match space {
            Ok(s) if s.available >= min => {}
            Ok(s) => {
                tracing::warn!(
                    tenant = tenant.name(),
                    available = s.available,
                    "space reserve reached: read-only"
                );
                return Err(unavailable());
            }
            Err(e) => {
                tracing::error!("espace disque illisible : {e}");
                return Err(unavailable());
            }
        }
    }
    Ok(())
}

/// HTTP status of a write error.
pub(crate) fn write_status(e: &io::Error) -> StatusCode {
    if is_refused(e, Refused::Precondition) {
        return StatusCode::PRECONDITION_FAILED;
    }
    if is_refused(e, Refused::Checksum) {
        return StatusCode::BAD_REQUEST;
    }
    if is_refused(e, Refused::IntoItself) {
        return StatusCode::CONFLICT;
    }
    match e.raw_os_error() {
        // ZFS quota or full disk: the temporary has already been deleted (§0.2).
        Some(libc::ENOSPC | libc::EDQUOT | libc::EFBIG) => StatusCode::INSUFFICIENT_STORAGE,
        Some(libc::EEXIST) => StatusCode::METHOD_NOT_ALLOWED,
        // Parent folder missing or not a folder.
        Some(libc::ENOENT | libc::ENOTDIR) => StatusCode::CONFLICT,
        _ if e.kind() == io::ErrorKind::IsADirectory => StatusCode::CONFLICT,
        _ => io_status(e),
    }
}

/// Wraps an operation with the ETag journal (§6). ETags are renewed even if the operation failed
/// midway (harmless); if the renewal fails, the intent stays open and will be replayed.
pub(crate) fn journaled<T>(
    u: &UserCtx,
    root: &Root,
    dirs: &[Option<&SafePath>],
    op: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let j = u.tenant().journal();
    let seq = j.begin(u.user(), dirs)?;
    let r = op();
    for d in dirs {
        root.renew_etags_lenient(*d)?;
    }
    j.done(seq);
    u.tenant().index().refresh(u.user(), root, dirs);
    r
}

/// Restores a trash item (web interface and WebDAV). The original folder and the root (in case of fallback)
/// change: ETags renewed and index kept up to date.
pub(crate) fn restore(u: &UserCtx, slot: &str) -> io::Result<SafePath> {
    let root = u.root()?;
    let origin = root
        .trash_list()?
        .into_iter()
        .find(|x| x.slot == slot)
        .and_then(|x| x.origin);
    let parent = origin.as_ref().and_then(|o| o.split_parent().0);
    journaled(u, &root, &[parent.as_ref(), None], || root.trash_restore(slot))
}

/// A change requested by `PROPPATCH`: (namespace, local name, value; `None` = `<d:remove>`).
type PropUpdate = (String, String, Option<String>);

/// `propertyupdate` body → changes, in order. `None`: malformed document or invalid property name (400).
/// Same name checks as PROPFIND: they are echoed in the response. quick-xml loads neither DTD nor entity.
pub(super) fn parse_proppatch(body: &[u8]) -> Option<Vec<PropUpdate>> {
    use quick_xml::events::Event;
    use quick_xml::name::ResolveResult;
    let mut r = quick_xml::reader::NsReader::from_reader(body);
    r.config_mut().trim_text(true);
    let (mut stack, mut out): (Vec<String>, Vec<PropUpdate>) = (Vec::new(), Vec::new());
    // Current property (in set/prop or remove/prop): index in `out`.
    let mut cur: Option<usize> = None;
    loop {
        let (ns, ev) = r.read_resolved_event().ok()?;
        let (bound, ns) = match ns {
            ResolveResult::Bound(n) => (true, n.0.to_owned()),
            ResolveResult::Unbound => (false, String::new()),
            ResolveResult::Unknown(_) => return None,
        };
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let local = e.local_name().as_ref().to_owned();
                let n = stack.len();
                let action = n.checked_sub(2).and_then(|i| stack.get(i)).map(String::as_str);
                if stack.last().map(String::as_str) == Some("prop") && matches!(action, Some("set" | "remove")) {
                    if out.len() >= super::MAX_PROPS
                        || !super::prop_name_ok(e.name().prefix().is_some(), bound, &ns, &local)
                    {
                        return None;
                    }
                    let value = (action == Some("set")).then(String::new);
                    out.push((ns, local.clone(), value));
                    cur = matches!(ev, Event::Start(_)).then_some(out.len() - 1);
                }
                if matches!(ev, Event::Start(_)) {
                    stack.push(local);
                }
            }
            Event::Text(ref t) => {
                if let Some(Some((_, _, Some(v)))) = cur.map(|i| out.get_mut(i)) {
                    v.push_str(&t.xml10_content());
                }
            }
            Event::End(_) => {
                stack.pop()?;
                if stack.last().map(String::as_str) == Some("prop") {
                    cur = None;
                }
            }
            Event::Eof if !stack.is_empty() => return None,
            Event::Eof => break,
            _ => {}
        }
    }
    Some(out)
}

fn favorite_update((ns, l, _): &PropUpdate) -> bool {
    ns == super::NS_OC && l == "favorite"
}

/// `PROPPATCH` response: 200 for each property if all are modifiable, otherwise 403 for the others and 424 for
/// `oc:favorite` (nothing was applied).
pub(super) fn proppatch_xml(href: &str, updates: &[PropUpdate]) -> String {
    let all_ok = updates.iter().all(favorite_update);
    let mut out = String::from(super::MULTISTATUS);
    out.push_str("<d:response><d:href>");
    out.push_str(href);
    out.push_str("</d:href>");
    for u in updates {
        let status = match (all_ok, favorite_update(u)) {
            (true, _) => "200 OK",
            (false, true) => "424 Failed Dependency",
            (false, false) => "403 Forbidden",
        };
        let (ns, l, _) = u;
        // Local name validated by the parser; namespace escaped.
        let name = if ns.is_empty() {
            format!("<{l} xmlns=\"\"/>")
        } else {
            format!("<x:{l} xmlns:x=\"{}\"/>", super::xml_attr_escape(ns))
        };
        out.push_str(&format!(
            "<d:propstat><d:prop>{name}</d:prop><d:status>HTTP/1.1 {status}</d:status></d:propstat>"
        ));
    }
    out.push_str("</d:response></d:multistatus>");
    out
}

/// `PROPPATCH`: only `oc:favorite` can be changed (the Nextcloud clients' star). All or nothing (RFC 4918 §9.2):
/// another property → 403 for it, 424 for the others, and nothing is applied. The favorite does not change the ETag
/// (like Nextcloud, where it is a tag); the search index is kept up to date.
pub(super) async fn proppatch(d: &Dav, path: Option<SafePath>, body: &[u8]) -> Response {
    let Some(updates) = parse_proppatch(body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // The user's root is not an item one marks as a favorite.
    let Some(path) = path else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if let Err(r) = writable(d).await {
        return r;
    }
    let all_ok = updates.iter().all(favorite_update);
    // The last change to `oc:favorite` wins.
    let fav = updates
        .iter()
        .rev()
        .find(|u| favorite_update(u))
        .map(|(_, _, v)| v.as_deref().is_some_and(|v| matches!(v.trim(), "1" | "true")));
    let (u, p) = (d.u.clone(), path.clone());
    let r = blocking(move || -> io::Result<Meta> {
        let root = u.root()?;
        let m = root.meta(Some(&p))?;
        if let (true, Some(on)) = (all_ok, fav) {
            root.set_favorite(Some(&p), on)?;
            u.tenant()
                .index()
                .refresh(u.user(), &root, &[p.split_parent().0.as_ref()]);
        }
        Ok(m)
    })
    .await;
    let m = match r {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => return io_status(&e).into_response(),
        Err(r) => return r,
    };
    let out = proppatch_xml(&super::href(&d.base, Some(path.as_str()), m.is_dir), &updates);
    (
        StatusCode::MULTI_STATUS,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        out,
    )
        .into_response()
}

/// `If-Match` / `If-None-Match` (§0.2: no lost update).
pub(super) enum Pre {
    Any,
    IfMatch(Vec<String>),
    IfNoneMatch(Vec<String>),
}

fn etag_list(v: &HeaderValue) -> Vec<String> {
    v.to_str()
        .unwrap_or_default()
        .split(',')
        .map(|e| e.trim().trim_start_matches("W/").trim_matches('"').to_owned())
        .filter(|e| !e.is_empty())
        .collect()
}

impl Pre {
    pub(super) fn from(h: &HeaderMap) -> Self {
        if let Some(v) = h.get(header::IF_MATCH) {
            return Self::IfMatch(etag_list(v));
        }
        if let Some(v) = h.get(header::IF_NONE_MATCH) {
            return Self::IfNoneMatch(etag_list(v));
        }
        Self::Any
    }

    pub(super) fn ok(&self, old: Option<&Meta>) -> bool {
        let hit = |l: &[String], m: &Meta| l.iter().any(|e| e == "*" || *e == etag::of(m));
        match self {
            Self::Any => true,
            Self::IfMatch(l) => old.is_some_and(|m| hit(l, m)),
            Self::IfNoneMatch(l) => old.is_none_or(|m| !hit(l, m)),
        }
    }
}

/// `OC-Checksum: SHA1:<hex>` (other algorithms may follow, separated by spaces: ignored).
pub(super) fn oc_sha1(h: &HeaderMap) -> Option<String> {
    let v = h.get("oc-checksum")?.to_str().ok()?;
    v.split_whitespace().find_map(|t| {
        let (alg, sum) = t.split_once(':')?;
        alg.eq_ignore_ascii_case("SHA1").then(|| sum.to_owned())
    })
}

/// `X-OC-Mtime`: modification time (Unix seconds; a decimal part is tolerated and truncated), until year 9999.
pub(super) fn oc_mtime(h: &HeaderMap) -> Option<i64> {
    let v = h.get("x-oc-mtime")?.to_str().ok()?;
    v.split('.')
        .next()?
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|t| (1..=super::MAX_MTIME).contains(t))
}

fn header_u64(h: &HeaderMap, name: &str) -> Option<u64> {
    h.get(name)?.to_str().ok()?.trim().parse().ok()
}

/// Announced size (`OC-Total-Length`, otherwise `Content-Length`): 507 right away if it exceeds the quota (§7).
pub(super) async fn check_space(u: &UserCtx, h: &HeaderMap) -> Result<(), Response> {
    let Some(len) = header_u64(h, "oc-total-length").or_else(|| header_u64(h, "content-length")) else {
        return Ok(());
    };
    let u = u.clone();
    match blocking(move || u.root().and_then(|r| r.space())).await? {
        Ok(s) if s.available < len => Err(StatusCode::INSUFFICIENT_STORAGE.into_response()),
        Ok(_) => Ok(()),
        Err(e) => Err(io_status(&e).into_response()),
    }
}

/// Copies a request body into the writer, in batches, each batch in a short `spawn_blocking` (a slow
/// client ties up no thread). Client gone or disk error: the writer is abandoned (temporary deleted).
pub(crate) async fn stream_into(mut w: AtomicWriter, body: Body) -> Result<AtomicWriter, Response> {
    let mut s = body.into_data_stream();
    let mut buf = Vec::with_capacity(WRITE_BATCH);
    loop {
        let next = s.next().await;
        let end = next.is_none();
        match next {
            Some(Ok(b)) => buf.extend_from_slice(&b),
            Some(Err(_)) => return Err(StatusCode::BAD_REQUEST.into_response()),
            None => {}
        }
        if buf.len() >= WRITE_BATCH || (end && !buf.is_empty()) {
            let data = std::mem::take(&mut buf);
            w = match blocking(move || w.write(&data).map(|()| w)).await? {
                Ok(w) => w,
                Err(e) => return Err(write_status(&e).into_response()),
            };
            buf.reserve(WRITE_BATCH);
        }
        if end {
            return Ok(w);
        }
    }
}

/// Response of a file write: 201 (created) or 204 (replaced), ETag and identity for the client.
pub(super) fn written(w: &Written, mtime_accepted: bool) -> Response {
    let tag = format!("\"{}\"", etag::of(&w.meta));
    let mut r = (if w.created {
        StatusCode::CREATED
    } else {
        StatusCode::NO_CONTENT
    })
    .into_response();
    let h = r.headers_mut();
    for (k, v) in [
        ("etag", tag.clone()),
        ("oc-etag", tag),
        ("oc-fileid", format!("{:08}ocbeastbox", etag::fileid(&w.meta))),
    ] {
        if let Ok(v) = HeaderValue::from_str(&v) {
            h.insert(k, v);
        }
    }
    if mtime_accepted {
        h.insert("x-oc-mtime", HeaderValue::from_static("accepted"));
    }
    r
}

fn not_allowed() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, ALLOW)]).into_response()
}

/// `PUT`: streamed upload, atomic write (§0.2), `If-Match`, `OC-Checksum`, `X-OC-Mtime`, quota.
pub(super) async fn put(d: &Dav, path: Option<SafePath>, h: &HeaderMap, body: Body) -> Response {
    let Some(path) = path else { return not_allowed() };
    if let Err(r) = writable(d).await {
        return r;
    }
    if let Err(r) = check_space(&d.u, h).await {
        return r;
    }
    let (pre, sha1, mtime) = (Pre::from(h), oc_sha1(h), oc_mtime(h));
    let (u, p) = (d.u.clone(), path.clone());
    let w = match blocking(move || u.root().and_then(|r| r.writer(&p))).await {
        Ok(Ok(w)) => w,
        Ok(Err(e)) => return write_status(&e).into_response(),
        Err(r) => return r,
    };
    let w = match stream_into(w, body).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let u = d.u.clone();
    let r = blocking(move || {
        let root = u.root()?;
        let (parent, _) = path.split_parent();
        journaled(&u, &root, &[parent.as_ref()], || {
            w.commit(mtime, sha1.as_deref(), |old| pre.ok(old))
        })
    })
    .await;
    match r {
        Ok(Ok(w)) => written(&w, mtime.is_some()),
        Ok(Err(e)) => write_status(&e).into_response(),
        Err(r) => r,
    }
}

/// `MKCOL`: creates a folder (body forbidden). Already exists → 405; parent missing → 409.
pub(super) async fn mkcol(d: &Dav, path: Option<SafePath>, h: &HeaderMap) -> Response {
    let Some(path) = path else { return not_allowed() };
    if header_u64(h, "content-length").is_some_and(|n| n > 0) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    if let Err(r) = writable(d).await {
        return r;
    }
    let u = d.u.clone();
    let r = blocking(move || {
        let root = u.root()?;
        let (parent, _) = path.split_parent();
        journaled(&u, &root, &[parent.as_ref()], || root.mkdir(&path))
    })
    .await;
    match r {
        Ok(Ok(_)) => StatusCode::CREATED.into_response(),
        Ok(Err(e)) => write_status(&e).into_response(),
        Err(r) => r,
    }
}

/// `DELETE`: to the user's trash, never a permanent delete (§0.2, §6).
pub(super) async fn delete(d: &Dav, path: Option<SafePath>) -> Response {
    let Some(path) = path else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if let Err(r) = writable(d).await {
        return r;
    }
    let u = d.u.clone();
    let r = blocking(move || {
        let root = u.root()?;
        root.meta(Some(&path))?; // missing → 404 (ENOENT before any intent)
        let (parent, _) = path.split_parent();
        journaled(&u, &root, &[parent.as_ref()], || root.trash(&path, u.user()))
    })
    .await;
    match r {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => io_status(&e).into_response(),
        Err(r) => r,
    }
}

/// `Destination` header (absolute URL of the same host, or a path) → path under the same WebDAV root.
pub(super) fn destination(d: &Dav, base: &str, h: &HeaderMap) -> Result<Option<SafePath>, StatusCode> {
    // Raw UTF-8 tolerated (some clients do not encode non-ASCII characters), then %XX decoding.
    let v = h
        .get("destination")
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let ours = d.origin.0.split_once("://").map_or("", |(_, h)| h);
    dest_path(ours, base, v)
}

/// Parsing a `Destination` (pure function, fuzzed): `ours` = the request's host, `base` = WebDAV root.
pub(super) fn dest_path(ours: &str, base: &str, v: &str) -> Result<Option<SafePath>, StatusCode> {
    let path = match v.split_once("://") {
        // Absolute URL: only the host matters (the scheme depends on the proxy); other host → 502 (RFC 4918 §9.9.4).
        Some((_, rest)) => {
            let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            if !host.eq_ignore_ascii_case(ours) {
                return Err(StatusCode::BAD_GATEWAY);
            }
            path
        }
        None => v,
    };
    let rest = path
        .strip_prefix(base)
        .or_else(|| path.strip_prefix(base.trim_end_matches('/')))
        .ok_or(StatusCode::FORBIDDEN)?;
    // A single decoding, then the same checks as for a URL path.
    let decoded = percent_encoding::percent_decode_str(rest)
        .decode_utf8()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    safe(&decoded).map_err(|()| StatusCode::FORBIDDEN)
}

/// `MOVE` (identity kept) and `COPY` (new identities). `Overwrite: F` → 412 if the destination exists;
/// otherwise the replaced destination goes to the trash (§0.2).
pub(super) async fn move_copy(d: &Dav, from: Option<SafePath>, h: &HeaderMap, is_move: bool) -> Response {
    let Some(from) = from else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let to = match destination(d, &d.base, h) {
        Ok(Some(t)) => t,
        Ok(None) => return StatusCode::FORBIDDEN.into_response(),
        Err(s) => return s.into_response(),
    };
    // RFC 4918 §9.8.5 / 9.9.4: source and destination identical → 403, as sabre/dav (before: 204 "replaced").
    if from == to {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Err(r) = writable(d).await {
        return r;
    }
    let overwrite = !h
        .get("overwrite")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"F"));
    let u = d.u.clone();
    let r = blocking(move || -> io::Result<Result<bool, StatusCode>> {
        let root = u.root()?;
        match root.meta(Some(&from)) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(Err(StatusCode::NOT_FOUND)),
            r => r?,
        };
        let (fp, tp) = (from.split_parent().0, to.split_parent().0);
        let done = if is_move {
            journaled(&u, &root, &[fp.as_ref(), tp.as_ref()], || {
                root.rename(&from, &to, overwrite, u.user())
            })
        } else {
            journaled(&u, &root, &[tp.as_ref()], || root.copy(&from, &to, overwrite, u.user()))
        };
        // Source checked: an ENOENT here comes from the destination's parent folder → 409 (write_status).
        Ok(Ok(done?))
    })
    .await;
    match r {
        Ok(Ok(Ok(replaced))) => (if replaced {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::CREATED
        })
        .into_response(),
        Ok(Ok(Err(s))) => s.into_response(),
        Ok(Err(e)) => write_status(&e).into_response(),
        Err(r) => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bodies sent by the Android app (`ToggleFavoriteRemoteOperation`, jackrabbit's PropPatchMethod).
    const FAV_ON: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><oc:favorite xmlns:oc="http://owncloud.org/ns">1</oc:favorite></D:prop></D:set></D:propertyupdate>"#;
    const FAV_OFF: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><D:propertyupdate xmlns:D="DAV:"><D:remove><D:prop><oc:favorite xmlns:oc="http://owncloud.org/ns"/></D:prop></D:remove></D:propertyupdate>"#;

    #[test]
    fn proppatch_parse_and_answer() {
        let oc = super::super::NS_OC.to_owned();
        let on = parse_proppatch(FAV_ON.as_bytes()).unwrap();
        assert_eq!(on, [(oc.clone(), "favorite".to_owned(), Some("1".to_owned()))]);
        let off = parse_proppatch(FAV_OFF.as_bytes()).unwrap();
        assert_eq!(off, [(oc.clone(), "favorite".to_owned(), None)]);
        let x = proppatch_xml("/h", &on);
        assert!(x.contains("http://owncloud.org/ns") && x.contains("HTTP/1.1 200 OK") && !x.contains("403"));

        // With another property: nothing is applied, 403 for it, 424 for the favorite.
        let mixed = FAV_ON.replace("</D:prop></D:set>", "<D:displayname>x</D:displayname></D:prop></D:set>");
        let u = parse_proppatch(mixed.as_bytes()).unwrap();
        let x = proppatch_xml("/h", &u);
        assert!(
            x.contains("HTTP/1.1 424 Failed Dependency")
                && x.contains("HTTP/1.1 403 Forbidden")
                && !x.contains("200 OK")
        );

        // Hostile names (echoed in the response), undeclared prefix, truncated document: 400.
        assert!(parse_proppatch(FAV_ON.replace("oc:favorite", "oc:fa\u{1}v").as_bytes()).is_none());
        assert!(parse_proppatch(FAV_ON.replace(" xmlns:oc=\"http://owncloud.org/ns\"", "").as_bytes()).is_none());
        assert!(parse_proppatch(&FAV_ON.as_bytes()[..60]).is_none());
        let reserved = FAV_ON.replace("http://owncloud.org/ns", "http://www.w3.org/2000/xmlns/");
        assert!(parse_proppatch(reserved.as_bytes()).is_none());
        // Too many properties: 400.
        let many = format!(
            r#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>{}</D:prop></D:set></D:propertyupdate>"#,
            "<D:p/>".repeat(super::super::MAX_PROPS + 1)
        );
        assert!(parse_proppatch(many.as_bytes()).is_none());
    }

    fn hm(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn headers() {
        assert_eq!(
            oc_sha1(&hm(&[("oc-checksum", "MD5:x SHA1:abc ADLER32:y")])).as_deref(),
            Some("abc")
        );
        assert_eq!(oc_sha1(&hm(&[("oc-checksum", "MD5:x")])), None);
        assert_eq!(oc_mtime(&hm(&[("x-oc-mtime", "1700000000")])), Some(1_700_000_000));
        assert_eq!(oc_mtime(&hm(&[("x-oc-mtime", "1700000000.5")])), Some(1_700_000_000));
        assert_eq!(oc_mtime(&hm(&[("x-oc-mtime", "-5")])), None);
        assert!(matches!(Pre::from(&hm(&[("if-match", "\"a\", W/\"b\"")])), Pre::IfMatch(l) if l == ["a", "b"]));
        assert!(matches!(Pre::from(&hm(&[("if-none-match", "*")])), Pre::IfNoneMatch(l) if l == ["*"]));
        assert!(Pre::IfNoneMatch(vec!["*".into()]).ok(None));
        assert!(!Pre::IfMatch(vec!["*".into()]).ok(None));
    }
}
