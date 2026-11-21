//! WebDAV search (RFC 5323, `basicsearch`) on `/remote.php/dav`, as the Android app sends it
//! (`NcSearchMethod`): Favorites, Recent, Photos, search by name. The app first queries `OPTIONS /remote.php/dav` and
//! gives up if `SEARCH` is not in `Allow`. Response: the same properties as a PROPFIND, plus `oc:favorite` and
//! a MIME type deduced from the extension. Served by the in-memory index (`crate::index`): at most `index::LIMIT` results.
//! shortcut: only the `/files/<user>` scope (the whole space) is served; a narrower scope or a search by
//! `oc:fileid` returns an empty list. Extend it if a client uses them.

use super::{MULTISTATUS, NS_DAV, NS_NC, NS_OC, Want, href, io_status, prop, render_with, small_body};
use crate::fs::{Meta, SafePath};
use crate::http::{App, ClientIp, blocking, require_user};
use crate::index::{LIMIT, Query};
use crate::tenant::TenantCtx;
use crate::web::render;
use axum::Extension;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use std::io;
use std::sync::Arc;

const ALLOW: &str = "OPTIONS, SEARCH";

/// `/remote.php/dav`: `OPTIONS` (announces `SEARCH`) and `SEARCH`; the rest as before (authenticated, then 404).
pub async fn dav_root(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    req: Request,
) -> Response {
    let u = match require_user(&app, &t, ip, req.headers()).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let (parts, body) = req.into_parts();
    match parts.method.as_str() {
        "OPTIONS" => (
            StatusCode::OK,
            [
                (header::ALLOW, ALLOW),
                (header::HeaderName::from_static("dav"), "1, 3"),
                (header::HeaderName::from_static("dasl"), "<DAV:basicsearch>"),
            ],
        )
            .into_response(),
        "SEARCH" => {
            let body = match small_body(body).await {
                Ok(b) => b,
                Err(r) => return r,
            };
            let Some(s) = parse(&body, u.user()) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let base = format!("/remote.php/dav/files/{}/", u.user());
            let r = blocking(move || run(&u, &base, s)).await;
            match r {
                Ok(Ok(xml)) => (
                    StatusCode::MULTI_STATUS,
                    [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
                    xml,
                )
                    .into_response(),
                Ok(Err(e)) => io_status(&e).into_response(),
                Err(r) => r,
            }
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// An understood search: the index query, the wanted properties, the number of results.
#[derive(Debug)]
pub(super) struct Search {
    /// `None`: nothing the index knows how to search (narrow scope, `oc:fileid`…) → empty list.
    query: Option<Query>,
    want: Want,
    limit: usize,
}

/// A comparison of the `where` clause: operator, property (local name), literal.
#[derive(Debug, Default)]
struct Cond {
    op: String,
    prop: String,
    lit: String,
}

fn is_image(n: &str) -> bool {
    render::mime(n).starts_with("image/")
}
fn is_video(n: &str) -> bool {
    render::mime(n).starts_with("video/")
}
fn is_media(n: &str) -> bool {
    is_image(n) || is_video(n)
}

/// Days since 1970-01-01 of a civil date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Date literal: Unix seconds, or `YYYY-MM-DDTHH:MM:SS` (`Z` suffix or offset ignored: the app sends local time
/// followed by `Z`, a few hours off make no difference to "modified in the last 7 days").
fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (h, mi, se) = (n(11..13).unwrap_or(0), n(14..16).unwrap_or(0), n(17..19).unwrap_or(0));
    ((1..=12).contains(&mo) && (1..=31).contains(&d))
        .then(|| days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

/// `searchrequest` body → search. `None`: malformed document (400). quick-xml loads neither DTD nor external entity.
pub(super) fn parse(body: &[u8], user: &str) -> Option<Search> {
    let mut r = quick_xml::reader::NsReader::from_reader(body);
    r.config_mut().trim_text(true);
    let mut stack: Vec<String> = Vec::new();
    let (mut select, mut conds, mut cur) = (Vec::new(), Vec::new(), None::<Cond>);
    let (mut scope, mut limit, mut dirs_only) = (String::new(), LIMIT, false);
    loop {
        let (ns, ev) = r.read_resolved_event().ok()?;
        let (bound, ns) = match ns {
            ResolveResult::Bound(n) => (true, n.0.to_owned()),
            ResolveResult::Unbound => (false, String::new()),
            // Prefix never declared: invalid document, as for PROPFIND.
            ResolveResult::Unknown(_) => return None,
        };
        let open = |e: &quick_xml::events::BytesStart<'_>| e.local_name().as_ref().to_owned();
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let local = open(e);
                let parent = stack.last().map(String::as_str);
                let grand = stack
                    .len()
                    .checked_sub(2)
                    .and_then(|i| stack.get(i))
                    .map(String::as_str);
                if parent == Some("prop") && grand == Some("select") {
                    // Same checks as PROPFIND: these names are echoed in the response (found by fuzzing).
                    if select.len() >= super::MAX_PROPS
                        || !super::prop_name_ok(e.name().prefix().is_some(), bound, &ns, &local)
                    {
                        return None;
                    }
                    select.push((ns, local.clone()));
                } else if parent == Some("prop") && cur.is_some() {
                    if let Some(c) = cur.as_mut() {
                        c.prop = local.clone();
                    }
                } else if matches!(local.as_str(), "eq" | "gt" | "gte" | "lt" | "lte" | "like") {
                    cur = Some(Cond {
                        op: local.clone(),
                        ..Cond::default()
                    });
                } else if local == "is-collection" && stack.iter().any(|s| s == "where") {
                    dirs_only = true;
                }
                if matches!(ev, Event::Start(_)) {
                    stack.push(local);
                } else if matches!(local.as_str(), "eq" | "gt" | "gte" | "lt" | "lte" | "like") {
                    conds.extend(cur.take());
                }
            }
            Event::Text(ref t) => {
                let text = t.xml10_content();
                text_into(&stack, &text, &mut cur, &mut scope, &mut limit);
            }
            Event::GeneralRef(ref g) => {
                let c = match g.resolve_char_ref() {
                    Ok(Some(c)) => c.to_string(),
                    _ => quick_xml::escape::resolve_predefined_entity(&g.xml10_content())?.to_owned(),
                };
                text_into(&stack, &c, &mut cur, &mut scope, &mut limit);
            }
            Event::End(_) => {
                let local = stack.pop()?;
                if matches!(local.as_str(), "eq" | "gt" | "gte" | "lt" | "lte" | "like") {
                    conds.extend(cur.take());
                }
            }
            Event::Eof if !stack.is_empty() => return None,
            Event::Eof => break,
            _ => {}
        }
    }
    let want = if select.is_empty() {
        Want::All
    } else {
        Want::Props(select)
    };
    // Scope: the user's whole space only.
    let whole = scope.trim_matches('/') == format!("files/{user}");
    let mut q = Query {
        dirs_only,
        ..Query::default()
    };
    let mut understood = whole;
    let (mut images, mut videos) = (false, false);
    for c in &conds {
        match (c.op.as_str(), c.prop.as_str()) {
            ("eq", "favorite") => q.favorites = matches!(c.lit.trim(), "yes" | "1" | "true"),
            ("gt" | "gte", "getlastmodified") => q.after = Some(parse_time(&c.lit)? - i64::from(c.op == "gte")),
            ("lt" | "lte", "getlastmodified") => q.before = Some(parse_time(&c.lit)? + i64::from(c.op == "lte")),
            ("like", "displayname") => {
                q.words = c
                    .lit
                    .split(['%', '_', ' '])
                    .filter(|w| !w.is_empty())
                    .take(16)
                    .map(str::to_lowercase)
                    .collect();
            }
            ("like", "getcontenttype") => {
                images |= c.lit.starts_with("image/");
                videos |= c.lit.starts_with("video/");
                understood &= c.lit.starts_with("image/") || c.lit.starts_with("video/");
            }
            // The user is the only owner of their space.
            ("eq", "owner-id") => {}
            _ => understood = false,
        }
    }
    q.files_named = match (images, videos) {
        (true, true) => Some(is_media),
        (true, false) => Some(is_image),
        (false, true) => Some(is_video),
        // Recent (date criterion only): files. A folder changes date as soon as something is written in it; folders
        // at the top of the list made "Recent" look like the root folder.
        _ if (q.after.is_some() || q.before.is_some()) && !q.dirs_only && !q.favorites && q.words.is_empty() => {
            Some(crate::index::any_file)
        }
        _ => None,
    };
    // Recent and photos: sorted newest to oldest, as the app asks.
    q.newest = q.after.is_some() || q.before.is_some() || q.files_named.is_some();
    Some(Search {
        query: (understood && !q.is_empty()).then_some(q),
        want,
        limit: limit.min(LIMIT),
    })
}

fn text_into(stack: &[String], text: &str, cur: &mut Option<Cond>, scope: &mut String, limit: &mut usize) {
    match stack.last().map(String::as_str) {
        Some("literal") => {
            if let Some(c) = cur.as_mut() {
                c.lit.push_str(text);
            }
        }
        Some("href") if stack.iter().any(|s| s == "scope") => scope.push_str(text),
        Some("nresults") => {
            if let Ok(n) = text.trim().parse::<usize>() {
                *limit = n.max(1);
            }
        }
        _ => {}
    }
}

/// Runs the search and renders the multistatus (at most `LIMIT` entries, each reread from disk for its ETag and identity).
fn run(u: &crate::auth::UserCtx, base: &str, s: Search) -> io::Result<String> {
    let mut out = String::from(MULTISTATUS);
    if let Some(q) = &s.query {
        let root = u.root()?;
        let found = u.tenant().index().search(u.user(), &root, q)?;
        for h in found.hits.iter().take(s.limit) {
            let Ok(p) = SafePath::new(&h.path) else { continue };
            // Gone since indexing: ignored.
            let Ok(m) = root.meta(Some(&p)) else { continue };
            entry(&mut out, base, &h.path, &h.name, &m, &s.want);
        }
    }
    out.push_str("</d:multistatus>");
    Ok(out)
}

/// A result `<d:response>`: PROPFIND properties (including `oc:favorite`), plus `d:displayname` and the MIME type.
fn entry(out: &mut String, base: &str, path: &str, name: &str, m: &Meta, want: &Want) {
    let mime = if m.is_dir {
        "httpd/unix-directory"
    } else {
        render::mime(name)
    };
    render_with(out, &href(base, Some(path), m.is_dir), want, &super::ALLPROP, |n, l| {
        Some(match (n, l) {
            (NS_DAV, "displayname") => format!("<d:displayname>{}</d:displayname>", super::xml_attr_escape(name)),
            (NS_DAV, "getcontenttype") => format!("<d:getcontenttype>{mime}</d:getcontenttype>"),
            (NS_OC, "size") if m.is_dir => format!("<oc:size>{}</oc:size>", m.size),
            (NS_NC, "has-preview") => super::has_preview(name, m),
            _ => return prop(n, l, m, None),
        })
    });
}

/// Fuzzing entry point (`fuzzing` feature, never in the shipped binary; see `fuzz/`): an arbitrary SEARCH body
/// never crashes the parser, and the response rendered for the requested properties, with a hostile name,
/// is always well-formed XML.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn fuzz(data: &[u8]) {
    let Some(s) = parse(data, "alice") else { return };
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
        sha1: None,
        favorite: true,
    };
    let mut out = String::from(MULTISTATUS);
    entry(&mut out, "/b/", "d/<&\"'>.jpg", "<&\"'>.jpg", &m, &s.want);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The Android app's Favorites query (`NcSearchMethod`, FAVORITE_SEARCH), abridged.
    const FAV: &str = r#"<?xml version="1.0" encoding="UTF-8"?><d:searchrequest xmlns:d="DAV:" xmlns:oc="http://nextcloud.com/ns"><d:basicsearch><d:select><d:prop><d:displayname/><d:getcontenttype/><d:resourcetype/><oc:favorite xmlns:oc="http://owncloud.org/ns"/></d:prop></d:select><d:from><d:scope><d:href>/files/alice</d:href><d:depth>infinity</d:depth></d:scope></d:from><d:where><d:eq><d:prop><oc:favorite xmlns:oc="http://owncloud.org/ns"/></d:prop><d:literal>yes</d:literal></d:eq></d:where><d:orderby/></d:basicsearch></d:searchrequest>"#;

    #[test]
    fn android_queries() {
        let s = parse(FAV.as_bytes(), "alice").unwrap();
        let q = s.query.unwrap();
        assert!(q.favorites && !q.newest && q.after.is_none());
        assert!(
            matches!(s.want, Want::Props(ref p) if p.len() == 4 && p[3] == (NS_OC.to_owned(), "favorite".to_owned()))
        );

        let recent = FAV
            .replace("<d:eq><d:prop><oc:favorite xmlns:oc=\"http://owncloud.org/ns\"/></d:prop><d:literal>yes</d:literal></d:eq>",
                "<d:gt><d:prop><d:getlastmodified/></d:prop><d:literal>2026-11-08T14:57:07Z</d:literal></d:gt>")
            .replace("<d:orderby/>", "<d:orderby/><d:limit><d:nresults>50</d:nresults></d:limit>");
        let s = parse(recent.as_bytes(), "alice").unwrap();
        assert_eq!(s.limit, 50);
        let q = s.query.unwrap();
        assert_eq!(
            q.after,
            Some(days_from_civil(2026, 11, 8) * 86_400 + 14 * 3600 + 57 * 60 + 7)
        );
        assert!(q.newest && !q.favorites && q.files_named.is_some_and(|f| f("x")));

        let name = FAV.replace("<d:eq><d:prop><oc:favorite xmlns:oc=\"http://owncloud.org/ns\"/></d:prop><d:literal>yes</d:literal></d:eq>",
            "<d:like><d:prop><d:displayname/></d:prop><d:literal>%Facture Mars%</d:literal></d:like>");
        assert_eq!(
            parse(name.as_bytes(), "alice").unwrap().query.unwrap().words,
            ["facture", "mars"]
        );

        let gallery = FAV.replace("<d:eq><d:prop><oc:favorite xmlns:oc=\"http://owncloud.org/ns\"/></d:prop><d:literal>yes</d:literal></d:eq>",
            "<d:or><d:like><d:prop><d:getcontenttype/></d:prop><d:literal>image/%</d:literal></d:like><d:like><d:prop><d:getcontenttype/></d:prop><d:literal>video/%</d:literal></d:like></d:or>");
        let q = parse(gallery.as_bytes(), "alice").unwrap().query.unwrap();
        assert!(q.newest && q.files_named.is_some_and(|f| f("a.JPG") && f("b.mp4") && !f("c.txt")));

        // Other user, unknown scope, unhandled criterion: empty list, never the whole space.
        assert!(parse(FAV.as_bytes(), "bob").unwrap().query.is_none());
        let fileid = FAV.replace(
            "<oc:favorite xmlns:oc=\"http://owncloud.org/ns\"/></d:prop><d:literal>yes",
            "<oc:fileid/></d:prop><d:literal>42",
        );
        assert!(parse(fileid.as_bytes(), "alice").unwrap().query.is_none());
        // Hostile property name or undeclared prefix in select: 400 (otherwise echoed in the response).
        let bad = FAV.replace("<d:displayname/>", "<d:x\u{1}y/>");
        assert!(parse(bad.as_bytes(), "alice").is_none());
        let bad = FAV.replace("<d:displayname/>", "<zz:nom/>");
        assert!(parse(bad.as_bytes(), "alice").is_none());
        // Malformed: 400.
        assert!(parse(b"<d:searchrequest xmlns:d=\"DAV:\"><d:basicsearch>", "alice").is_none());
        assert_eq!(parse_time("1700000000"), Some(1_700_000_000));
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }
}
