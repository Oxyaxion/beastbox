//! Public links `/s/<token>` (§8, public surface §0.3). 128-bit token with no information about the path or
//! the user; **identical (404)** response for a link that is nonexistent, expired, revoked, from another tenant, or
//! whose target is gone. Access limited to the shared subtree (validated paths, opened relative to the owner's
//! root with `O_RESOLVE_BENEATH`).

use super::{Crumb, crumbs, render};
use crate::auth::{self, UserCtx};
use crate::dav::{self, Serve};
use crate::db::{ShareEventKind, ShareRow};
use crate::fs::{Meta, Refused, SafePath, is_refused};
use crate::http::{App, ClientIp, blocking, form_field, too_many};
use crate::i18n::Lang;
use crate::tenant::TenantCtx;
use askama::Template;
use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::io;
use std::sync::Arc;
use std::time::Duration;

/// Duration of the access granted after a link's password.
const PASS_TTL: i64 = 3600;

#[derive(Template)]
#[template(path = "share.html")]
struct SharePage {
    lang: Lang,
    name: String,
    message: String,
    password_form: bool,
    self_url: String,
    drop: bool,
    drop_url: String,
    /// The owner's note to the guest ("" = none), shown escaped.
    note: String,
    /// Read-and-upload folder: the upload area under the listing (top folder only).
    upload: bool,
    /// Download hidden: files open in the browser ("Open"), no archive.
    hidden: bool,
    /// Icon of a shared file.
    icon: &'static str,
    is_dir: bool,
    crumbs: Vec<Crumb>,
    zip: String,
    rows: Vec<PubRow>,
    size: String,
    date: String,
    download: String,
    page_no: usize,
    pages: usize,
    prev: String,
    next: String,
}

struct PubRow {
    icon: &'static str,
    name: String,
    url: String,
    size: String,
    date: String,
}

impl SharePage {
    fn blank(lang: Lang, name: String, self_url: String) -> Self {
        Self {
            lang,
            name,
            message: String::new(),
            password_form: false,
            self_url,
            drop: false,
            drop_url: String::new(),
            note: String::new(),
            upload: false,
            hidden: false,
            icon: "file",
            is_dir: false,
            crumbs: Vec::new(),
            zip: String::new(),
            rows: Vec::new(),
            size: String::new(),
            date: String::new(),
            download: String::new(),
            page_no: 1,
            pages: 1,
            prev: String::new(),
            next: String::new(),
        }
    }
}

/// Headers of every public response: not indexed, never cached.
fn public(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert("x-robots-tag", HeaderValue::from_static("noindex, nofollow"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn gone(lang: Lang) -> Response {
    public(super::message(
        lang,
        StatusCode::NOT_FOUND,
        lang.t("Link unavailable"),
        lang.t("This link does not exist or is no longer valid."),
        "",
    ))
}

/// Valid link and its target: owner, path, metadata. Any failure → `None` (identical 404).
struct Opened {
    s: ShareRow,
    owner: UserCtx,
    target: Option<SafePath>,
    meta: Meta,
    /// Download limit reached: only the rest of an already counted download is still served.
    exhausted: bool,
}

/// Time during which a guest continues a counted download without it being counted again (signed cookie).
const RESUME_TTL: i64 = 6 * 3600;

fn download_cookie(app: &App, share_id: &str) -> String {
    super::cookie_name(app, &format!("d{share_id}"))
}

/// Where a link's target stands.
pub(super) enum Target {
    /// Present, same identity.
    Here(Meta),
    /// In the trash (itself, or inside a folder that is): the link is suspended, and resumed if it is restored
    /// to its place.
    Trashed,
    /// Renamed, moved, permanently deleted, or replaced by another item with the same name: the link does not follow
    /// it, it ends.
    Gone,
    /// Undetermined: item without identity (restore without xattrs, `rescan` to run) or disk error. The link does
    /// not answer, but is not ended: a failed restore must not destroy every link.
    Unknown,
}

/// Trash listing, read on first need then kept: a single read for a whole page of links.
#[derive(Default)]
pub(super) struct TrashScan {
    items: Option<Vec<crate::fs::Trashed>>,
    /// Trash reads done (at most one).
    pub(super) reads: usize,
}

/// Is the target in its place, with the same identity? Never reads the trash.
fn here(root: &crate::fs::Root, path: Option<&SafePath>, fileid: &[u8]) -> Option<Meta> {
    root.meta(path)
        .ok()
        .filter(|m| m.id.is_some_and(|id| id.0.as_slice() == fileid))
}

pub(super) fn target(root: &crate::fs::Root, path: Option<&SafePath>, fileid: &[u8], trash: &mut TrashScan) -> Target {
    let mut missing = || match path {
        Some(p) if in_trash(root, p.as_str(), fileid, trash) => Target::Trashed,
        _ => Target::Gone,
    };
    match root.meta(path) {
        Ok(m) => match m.id {
            Some(id) if id.0.as_slice() == fileid => Target::Here(m),
            Some(_) => missing(),
            None => Target::Unknown,
        },
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => missing(),
        Err(_) => Target::Unknown,
    }
}

/// Is the target (original path `path`, identity `fileid`) in the trash, itself or inside a folder deleted
/// with it? Only walks `.trash/` (at most `TRASH_LIST_MAX` items), only when the target is missing.
fn in_trash(root: &crate::fs::Root, path: &str, fileid: &[u8], trash: &mut TrashScan) -> bool {
    if trash.items.is_none() {
        trash.reads += 1;
        trash.items = Some(root.trash_list().unwrap_or_default());
    }
    trash.items.iter().flatten().any(|t| {
        let Some(origin) = &t.origin else { return false };
        let o = origin.as_str();
        let rest = if path == o {
            None
        } else {
            match path.strip_prefix(o).and_then(|r| r.strip_prefix('/')) {
                Some(r) => Some(r.to_owned()),
                None => return false,
            }
        };
        let Ok((slot, name)) = root.trash_item(&t.slot) else {
            return false;
        };
        let inner = rest.map_or(name.clone(), |r| format!("{name}/{r}"));
        SafePath::new(&inner)
            .ok()
            .and_then(|p| slot.meta(Some(&p)).ok())
            .and_then(|m| m.id)
            .is_some_and(|id| id.0.as_slice() == fileid)
    })
}

/// A link's target as a safe path (empty = the owner's whole space).
pub(super) fn target_path(path_hint: &str) -> crate::Result<Option<SafePath>> {
    Ok(if path_hint.is_empty() {
        None
    } else {
        Some(SafePath::new(path_hint)?)
    })
}

async fn open(app: &Arc<App>, t: &TenantCtx, token: &str) -> Option<Opened> {
    if !auth::valid_share_token(token) {
        return None;
    }
    let (app2, t2, mac, token) = (app.clone(), t.clone(), t.mac(token.as_bytes()), token.to_owned());
    let r = blocking(move || -> crate::Result<Option<Opened>> {
        let Some(s) = app2.db.share_by_mac(&t2, &mac)? else {
            return Ok(None);
        };
        // Only a token derived from the current link key: renewing the key ends every link given out before.
        if auth::share_token(&t2, &s.share_id) != token {
            return Ok(None);
        }
        let now = crate::db::now_secs();
        // Revoked or expired: the same response as an unknown link (§8). Exhausted: refused by the caller, except the
        // rest of an already counted download.
        if s.revoked_at.is_some() || s.expires_at.is_some_and(|e| e <= now) {
            return Ok(None);
        }
        let exhausted = s.max_downloads.is_some_and(|m| s.download_count >= m);
        let owner = UserCtx::share_owner(&t2, &s.user_id)?;
        let path = target_path(&s.path_hint)?;
        // The target is found by its path, checked by its persistent identity. Deleted, moved or renamed:
        // the link ends (the owner's choice, it does not follow the target).
        let root = owner.root()?;
        // Suspended link: only "has it come back?", without rereading the trash on every visit (which a guest
        // could repeat); its possible end (trash emptied) is noticed on the owner's page.
        if s.suspended {
            let Some(meta) = here(&root, path.as_ref(), &s.fileid) else {
                return Ok(None);
            };
            app2.db.share_resume(&t2, &s.share_id)?;
            let exhausted = s.max_downloads.is_some_and(|m| s.download_count >= m);
            return Ok(Some(Opened {
                s,
                owner,
                target: path,
                meta,
                exhausted,
            }));
        }
        let meta = match target(&root, path.as_ref(), &s.fileid, &mut TrashScan::default()) {
            Target::Here(m) => m,
            Target::Trashed => {
                app2.db.share_suspend(&t2, &s.share_id)?;
                return Ok(None);
            }
            Target::Gone => {
                app2.db.share_gone(&t2, &s.share_id)?;
                return Ok(None);
            }
            Target::Unknown => return Ok(None),
        };
        Ok(Some(Opened {
            s,
            owner,
            target: path,
            meta,
            exhausted,
        }))
    })
    .await;
    match r {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            tracing::warn!(tenant = t.name(), "share link: {e}");
            None
        }
        Err(_) => None,
    }
}

fn pass_cookie(app: &App, share_id: &str) -> String {
    super::cookie_name(app, &format!("s{share_id}"))
}

/// Access granted: no password, or a valid password cookie for this link.
fn allowed(app: &App, t: &TenantCtx, o: &Opened, h: &HeaderMap) -> bool {
    o.s.password_hash.is_none()
        || super::cookie(h, &pass_cookie(app, &o.s.share_id))
            .is_some_and(|v| auth::share_pass_ok(t, &o.s.share_id, v, crate::db::now_secs()))
}

fn name_of(lang: Lang, o: &Opened) -> String {
    o.target
        .as_ref()
        .map_or(lang.t("Files").to_owned(), |p| p.split_parent().1.to_owned())
}

/// `GET /s/<token>`: the link's page (password, file, folder or drop).
pub async fn page(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Path(token): Path<String>,
    h: HeaderMap,
) -> Response {
    let lang = super::lang(&app, &h);
    let Some(o) = open(&app, &t, &token).await.filter(|o| !o.exhausted) else {
        return gone(lang);
    };
    show(lang, &app, &t, &token, o, (None, 0), &h, String::new()).await
}

#[allow(clippy::too_many_arguments)]
async fn show(
    lang: Lang,
    app: &Arc<App>,
    t: &TenantCtx,
    token: &str,
    o: Opened,
    (sub, pnum): (Option<SafePath>, usize),
    h: &HeaderMap,
    message: String,
) -> Response {
    let base = format!("/s/{token}");
    let mut page = SharePage::blank(lang, name_of(lang, &o), base.clone());
    if !allowed(app, t, &o, h) {
        page.password_form = true;
        page.message = message;
        return public(super::html(StatusCode::OK, &page));
    }
    {
        let (app2, t2, id) = (app.clone(), t.clone(), o.s.share_id.clone());
        let _ = blocking(move || app2.db.share_seen(&t2, &id)).await;
    }
    page.note = o.s.opts.note.clone();
    // Download hidden: only what the browser shows by itself (images, PDF, text…), opened in it, never an archive.
    let hidden = o.s.opts.hide_download;
    page.hidden = hidden;
    let reachable = |name: &str| !hidden || render::inline_mime(name).is_some();
    if o.s.perms == "drop" {
        page.drop = true;
        page.drop_url = format!("{base}/drop/");
        return public(super::html(StatusCode::OK, &page));
    }
    if !o.meta.is_dir {
        page.icon = render::icon(&page.name, false);
        page.size = render::size(lang, o.meta.size);
        page.date = render::date(o.meta.mtime);
        if reachable(&page.name) {
            page.download = format!("{base}/dl");
        }
        return public(super::html(StatusCode::OK, &page));
    }
    if o.s.opts.upload && sub.is_none() {
        page.upload = true;
        page.drop_url = format!("{base}/drop/");
    }
    // Folder for reading: subfolder `sub` relative to the target.
    let dir = join(o.target.as_ref(), sub.as_ref());
    let (owner, d2) = (o.owner.clone(), dir.clone());
    let page_n = pnum;
    let listed = blocking(move || {
        let page = page_n;
        let root = owner.root()?;
        if !root.meta(d2.as_ref())?.is_dir {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        super::list(
            &root,
            d2.as_ref(),
            "name",
            false,
            (page, super::PAGE),
            (false, true),
            None,
        )
    })
    .await;
    let (entries, pages) = match listed {
        Ok(Ok(l)) => (l.entries, l.pages),
        _ => return gone(lang),
    };
    (page.prev, page.next) = super::pager("", pnum, pages);
    page.page_no = pnum + 1;
    page.pages = pages;
    let rel = |name: &str| {
        let s = match &sub {
            Some(p) => format!("{}/{name}", p.as_str()),
            None => name.to_owned(),
        };
        dav::href("", Some(&s), false)
    };
    page.is_dir = true;
    page.crumbs = crumbs(&format!("{base}/f/"), &page.name, sub.as_ref());
    if !hidden {
        page.zip = format!("{base}/zip/{}", super::enc(sub.as_ref()));
    }
    page.rows = entries
        .into_iter()
        .map(|e| PubRow {
            icon: super::render::icon(&e.name, e.meta.is_dir),
            url: if e.meta.is_dir {
                format!("{base}/f/{}/", rel(&e.name))
            } else if reachable(&e.name) {
                format!("{base}/dl/{}", rel(&e.name))
            } else {
                String::new()
            },
            size: if e.meta.is_dir {
                String::new()
            } else {
                render::size(lang, e.meta.size)
            },
            date: render::date(e.meta.mtime),
            name: e.name,
        })
        .collect();
    public(super::html(StatusCode::OK, &page))
}

fn join(base: Option<&SafePath>, sub: Option<&SafePath>) -> Option<SafePath> {
    match (base, sub) {
        (b, None) => b.cloned(),
        (None, s) => s.cloned(),
        // Two already validated paths: their concatenation is too (no `..`, no reserved name at the start of `b`).
        (Some(b), Some(s)) => SafePath::new(&format!("{}/{}", b.as_str(), s.as_str())).ok(),
    }
}

/// Rate-limiting key for a link's password attempts (§8: per link and per IP).
fn link_key(share_id: &str) -> std::net::IpAddr {
    // Counters are keyed by address; a link gets an IPv6 address reserved for documentation, derived
    // from its identifier (2001:db8::/32), which cannot match any real client.
    let mut b = [0u8; 16];
    b[0] = 0x20;
    b[1] = 0x01;
    b[2] = 0x0d;
    b[3] = 0xb8;
    for (i, c) in share_id.bytes().take(12).enumerate() {
        if let Some(x) = b.get_mut(4 + i) {
            *x = c;
        }
    }
    std::net::IpAddr::from(b)
}

/// `POST /s/<token>`: password (form, never in the URL). Attempts limited per IP and per link, bounded argon2id.
pub async fn password(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Extension(ip): Extension<ClientIp>,
    Path(token): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = super::lang(&app, &h);
    let Some(o) = open(&app, &t, &token).await.filter(|o| !o.exhausted) else {
        return gone(lang);
    };
    let Some(hash) = o.s.password_hash.clone() else {
        return show(lang, &app, &t, &token, o, (None, 0), &h, String::new()).await;
    };
    let link = link_key(&o.s.share_id);
    if t.failures().ip_blocked(ip.0) || t.failures().ip_blocked(link) {
        return public(too_many());
    }
    let pw = form_field(&body, "password").unwrap_or_default();
    let Ok(Ok(_permit)) = tokio::time::timeout(Duration::from_secs(2), app.argon.acquire()).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "5")]).into_response();
    };
    let ok = blocking(move || auth::check_password(&hash, &pw))
        .await
        .unwrap_or(false);
    if !ok {
        tracing::warn!(tenant = t.name(), ip = %ip.0, share = o.s.share_id, "share link: wrong password");
        t.failures().record_ip(ip.0);
        t.failures().record_ip(link);
        note(&app, &t, &o, ShareEventKind::Denied, String::new(), 0).await;
        return show(
            lang,
            &app,
            &t,
            &token,
            o,
            (None, 0),
            &HeaderMap::new(),
            lang.t("Wrong password.").into(),
        )
        .await;
    }
    let until = crate::db::now_secs() + PASS_TTL;
    let c = super::set_cookie(
        &app,
        &pass_cookie(&app, &o.s.share_id),
        &auth::share_pass(&t, &o.s.share_id, until),
        PASS_TTL,
    );
    public(
        (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, format!("/s/{token}")), (header::SET_COOKIE, c)],
        )
            .into_response(),
    )
}

/// `/s/<token>/f/<subfolder>`, `/dl[/<file>]`, `/zip[/<subfolder>]`, `PUT /drop/<name>`.
pub async fn rest(
    State(app): State<Arc<App>>,
    Extension(t): Extension<TenantCtx>,
    Path((token, rest)): Path<(String, String)>,
    req: Request,
) -> Response {
    let lang = super::lang(&app, req.headers());
    let Some(o) = open(&app, &t, &token).await else {
        return gone(lang);
    };
    if !allowed(&app, &t, &o, req.headers()) {
        return gone(lang);
    }
    let (verb, sub) = match rest.split_once('/') {
        Some((v, s)) => (v, s.trim_matches('/')),
        None => (rest.as_str(), ""),
    };
    let sub = if sub.is_empty() {
        None
    } else {
        match SafePath::new(sub) {
            Ok(p) => Some(p),
            Err(_) => return gone(lang),
        }
    };
    let method = req.method().as_str().to_owned();
    match (method.as_str(), verb, o.s.perms.as_str(), o.meta.is_dir) {
        ("GET", "f", "read", true) if !o.exhausted => {
            let h = req.headers().clone();
            let pnum = req
                .uri()
                .query()
                .and_then(|q| form_field(q.as_bytes(), "page"))
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0);
            show(lang, &app, &t, &token, o, (sub, pnum.min(100)), &h, String::new()).await
        }
        ("GET", "dl", "read", is_dir) if is_dir == sub.is_some() => {
            let path = join(o.target.as_ref(), sub.as_ref());
            let Some(path) = path else { return gone(lang) };
            let name = path.split_parent().1.to_owned();
            let shown = sub
                .as_ref()
                .map_or_else(|| name_of(lang, &o), |s| s.as_str().to_owned());
            // Rest of an already counted download (same guest, same file): served without counting again, even if the
            // limit has just been reached. Otherwise, counted (refused if the limit is reached).
            let cname = download_cookie(&app, &o.s.share_id);
            let now = crate::db::now_secs();
            let resumed = super::cookie(req.headers(), &cname)
                .is_some_and(|v| auth::share_download_ok(&t, &o.s.share_id, &shown, v, now));
            if !resumed && !hit(&app, &t, &o).await {
                return gone(lang);
            }
            // Download hidden: opened in the browser if it can show it, otherwise not served.
            let mode = match (o.s.opts.hide_download, render::inline_mime(&name)) {
                (false, _) => Serve::Attachment(name),
                (true, Some(mime)) => Serve::Inline(mime),
                (true, None) => return gone(lang),
            };
            let owner = o.owner.clone();
            tracing::info!(tenant = t.name(), share = o.s.share_id, "share link: download");
            let r = dav::serve_file(move || owner.root(), path, false, req.headers(), mode).await;
            // Folder, missing item, refusal: the same response as for an invalid link (§8).
            if r.status().is_client_error() && r.status() != StatusCode::RANGE_NOT_SATISFIABLE {
                return gone(lang);
            }
            let mut r = r;
            if r.status().is_success() && !resumed {
                let pass = auth::share_download_pass(&t, &o.s.share_id, &shown, now + RESUME_TTL);
                if let Ok(c) = HeaderValue::from_str(&super::set_cookie(&app, &cname, &pass, RESUME_TTL)) {
                    r.headers_mut().append(header::SET_COOKIE, c);
                }
                note(&app, &t, &o, ShareEventKind::Download, shown, 0).await;
            }
            public(r)
        }
        ("GET", "zip", "read", true) => {
            if o.exhausted || o.s.opts.hide_download || !hit(&app, &t, &o).await {
                return gone(lang);
            }
            let dir = join(o.target.as_ref(), sub.as_ref());
            let top = dir
                .as_ref()
                .map_or(name_of(lang, &o), |p| p.split_parent().1.to_owned());
            let owner = o.owner.clone();
            tracing::info!(tenant = t.name(), share = o.s.share_id, "share link: ZIP archive");
            let shown = sub
                .as_ref()
                .map_or_else(|| name_of(lang, &o), |s| s.as_str().to_owned());
            note(&app, &t, &o, ShareEventKind::Zip, shown, 0).await;
            public(super::zip_response(lang, move || owner.root(), super::ZipOf::Dir(dir), top).await)
        }
        // Drop link, or read-and-upload folder (the guest adds, never replaces: taken names get a suffix).
        ("PUT", "drop", p, true) if !o.exhausted && (p == "drop" || o.s.opts.upload) => {
            drop_file(&app, &t, o, sub, req).await
        }
        _ => gone(lang),
    }
}

/// Records an event in the link's history (the owner's Shared links page). `path`: relative to the link.
/// An error is logged, never returned to the guest: the history must not prevent a download.
async fn note(app: &Arc<App>, t: &TenantCtx, o: &Opened, kind: ShareEventKind, path: String, bytes: i64) {
    let (app2, t2, id, owner) = (app.clone(), t.clone(), o.s.share_id.clone(), o.s.user_id.clone());
    if let Ok(Err(e)) = blocking(move || app2.db.share_event(&t2, &id, &owner, kind, &path, bytes)).await {
        tracing::warn!(tenant = t.name(), share = o.s.share_id, "link history not written: {e}");
    }
}

/// Counts a download; false if the limit is reached (the link then becomes unavailable).
async fn hit(app: &Arc<App>, t: &TenantCtx, o: &Opened) -> bool {
    let (app2, t2, id) = (app.clone(), t.clone(), o.s.share_id.clone());
    matches!(blocking(move || app2.db.share_hit(&t2, &id)).await, Ok(Ok(true)))
}

/// Bytes reserved on a drop link's total volume, given back if the drop does not complete: error, name taken, quota,
/// wrong size, or guest gone mid-upload (the request is then dropped without returning, hence a `Drop`).
struct DropReservation {
    app: Arc<App>,
    t: TenantCtx,
    share_id: String,
    bytes: i64,
    kept: bool,
}

impl Drop for DropReservation {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        let (app, t, id, n) = (
            self.app.clone(),
            self.t.clone(),
            std::mem::take(&mut self.share_id),
            self.bytes,
        );
        // Outside the runtime (server shutdown): the reservation stays, a few bytes on a link, no other effect.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn_blocking(move || {
                if let Err(e) = app.db.share_drop_release(&t, &id, n) {
                    tracing::warn!(
                        tenant = t.name(),
                        share = id,
                        "drop link: reservation not given back: {e}"
                    );
                }
            });
        }
    }
}

/// Drops in progress at most per link, and in all: an anonymous guest holds a connection for the whole upload.
const DROPS_PER_LINK: usize = 4;
const DROPS_ALL: usize = 16;

/// Drops in progress, per link (`DROPS_PER_LINK`, `DROPS_ALL`).
#[derive(Debug, Default)]
pub struct DropSlots(std::sync::Mutex<std::collections::HashMap<String, usize>>);

/// A drop in progress; its slot is given back when it ends, however it ends.
struct DropSlot<'a> {
    slots: &'a DropSlots,
    id: String,
}

impl DropSlots {
    fn map(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, usize>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn take(&self, id: &str) -> Option<DropSlot<'_>> {
        let mut m = self.map();
        let n = m.get(id).copied().unwrap_or(0);
        if n >= DROPS_PER_LINK || m.values().sum::<usize>() >= DROPS_ALL {
            return None;
        }
        m.insert(id.to_owned(), n + 1);
        Some(DropSlot {
            slots: self,
            id: id.to_owned(),
        })
    }
}

impl Drop for DropSlot<'_> {
    fn drop(&mut self) {
        let mut m = self.slots.map();
        if let Some(n) = m.get_mut(&self.id) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.id);
            }
        }
    }
}

/// Dropped name, cleaned rather than refused so that every client of the owner can sync it and nobody is deceived:
/// a single component; bidirectional controls removed (`facture\u{202E}fdp.exe` displayed as `facture.pdf`…);
/// characters forbidden on Windows replaced by `_`; trailing dots and spaces removed; Windows device names (`CON`,
/// `nul.txt`, `COM1`…) prefixed with `_`. `None`: a path, a hidden name (also once cleaned), or nothing left.
fn drop_name(p: Option<&SafePath>) -> Option<String> {
    let raw = p?.as_str();
    if raw.contains('/') {
        return None;
    }
    let n: String = raw
        .chars()
        .filter(
            |c| !matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'),
        )
        .map(|c| {
            if matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let n = n.trim_start_matches(' ').trim_end_matches(['.', ' ']);
    let stem = n
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.ends_with(|c: char| c.is_ascii_digit() && c != '0'));
    // Hidden once cleaned (`.htaccess`, ` .x`, `\u{200E}.x`): refused, as before.
    if n.is_empty() || n.starts_with('.') {
        return None;
    }
    let n = if device { format!("_{n}") } else { n.to_owned() };
    // Still a valid single name (a prefix may have taken it past 255 bytes), in NFC again: removing a control between
    // combining marks can change their canonical order (found by fuzzing).
    SafePath::new(&n)
        .ok()
        .map(|p| p.as_str().to_owned())
        .filter(|p| !p.contains('/'))
}

// ---------------------------------------------------------------- creating and changing links (web page, clients' OCS)

/// Why a link was not created or changed.
pub(crate) enum LinkError {
    /// The owner's mistake: a message to translate.
    Refused(&'static str),
    Busy,
    Io(io::Error),
}

/// What a new link gives: read-only, or drop only (folders); optional password, expiry and download limit.
pub(crate) struct NewLink {
    pub path: Option<SafePath>,
    /// `read`, `drop` (folders) or `upload` (read and upload, folders).
    pub perms: &'static str,
    pub password: Option<String>,
    pub expires: Option<i64>,
    pub max: Option<i64>,
    pub label: String,
    pub note: String,
    pub hide_download: bool,
}

/// Changes to a live link; `None` = unchanged, `Some(None)` = removed.
#[derive(Default)]
pub(crate) struct LinkChange {
    pub perms: Option<&'static str>,
    pub password: Option<Option<String>>,
    pub expires: Option<Option<i64>>,
    pub label: Option<String>,
    pub note: Option<String>,
    pub hide_download: Option<bool>,
}

/// A link's access as the owner chooses it: `read`, `drop`, or `upload` (read and upload, stored as `read` + flag).
pub(crate) fn access(s: &ShareRow) -> &'static str {
    match (s.perms.as_str(), s.opts.upload) {
        ("drop", _) => "drop",
        (_, true) => "upload",
        _ => "read",
    }
}

const LABEL_MAX: usize = 100;
const NOTE_MAX: usize = 1000;

/// Label (one line) or note (lines kept): trimmed, bounded, no control character. Shown escaped, never interpreted.
fn link_text(s: &str, max: usize, lines: bool) -> Result<String, &'static str> {
    let s = s.replace("\r\n", "\n");
    let s = s.trim();
    if s.chars().any(|c| c.is_control() && !(lines && c == '\n')) {
        return Err("Invalid characters in the label or the note.");
    }
    if s.chars().count() > max {
        return Err(if lines {
            "Note too long (1,000 characters at most)."
        } else {
            "Label too long (100 characters at most)."
        });
    }
    Ok(s.to_owned())
}

const PAST_EXPIRY: &str = "Invalid or past expiry date.";
const DROP_ON_FILE: &str = "Drop and upload only apply to a folder.";

/// A link password, hashed (argon2id, bounded concurrency, §0.4). 8 characters at least.
async fn link_password(app: &Arc<App>, pw: String) -> Result<String, LinkError> {
    if pw.chars().count() < 8 {
        return Err(LinkError::Refused("Password too short (8 characters at least)."));
    }
    let Ok(Ok(_permit)) = tokio::time::timeout(Duration::from_secs(2), app.argon.acquire()).await else {
        return Err(LinkError::Busy);
    };
    match blocking(move || auth::hash_password(&pw)).await {
        Ok(Ok(h)) => Ok(h),
        _ => Err(LinkError::Busy),
    }
}

fn link_result<T>(r: Result<crate::Result<Result<T, &'static str>>, impl Sized>) -> Result<T, LinkError> {
    match r {
        Ok(Ok(Ok(v))) => Ok(v),
        Ok(Ok(Err(m))) => Err(LinkError::Refused(m)),
        Ok(Err(crate::Error::Io(e))) => Err(LinkError::Io(e)),
        _ => Err(LinkError::Busy),
    }
}

/// Creates a link (§8.6) on the item's persistent identity; returns its identifier.
pub(crate) async fn create_link(app: &Arc<App>, u: &UserCtx, l: NewLink) -> Result<String, LinkError> {
    if l.expires.is_some_and(|e| e <= crate::db::now_secs()) {
        return Err(LinkError::Refused(PAST_EXPIRY));
    }
    let mut opts = crate::db::LinkOptions {
        upload: l.perms == "upload",
        label: link_text(&l.label, LABEL_MAX, false).map_err(LinkError::Refused)?,
        note: link_text(&l.note, NOTE_MAX, true).map_err(LinkError::Refused)?,
        // A drop link shows no file: nothing to hide.
        hide_download: l.hide_download && l.perms != "drop",
    };
    let hash = match l.password {
        Some(pw) => Some(link_password(app, pw).await?),
        None => None,
    };
    let (app2, u) = (app.clone(), u.clone());
    let made = blocking(move || -> crate::Result<Result<String, &'static str>> {
        let m = u.root()?.meta(l.path.as_ref())?;
        if l.perms == "drop" && !m.is_dir {
            return Ok(Err(DROP_ON_FILE));
        }
        // Upload asked on a file (a client's "editing"): read only, never more than asked.
        opts.upload &= m.is_dir;
        // The link follows the persistent identity (§6); an item that arrived outside the application must go through rescan first.
        let Some(id) = m.id else {
            return Ok(Err("Item without identity: run “beastbox rescan” first."));
        };
        // The clients' short identifier must point to this link only, among the owner's live links.
        let taken: Vec<u32> = app2
            .db
            .share_list(u.tenant(), u.user())?
            .iter()
            .map(|s| client_id(&s.share_id))
            .collect();
        let mut share_id = auth::random_hex::<16>()?;
        while taken.contains(&client_id(&share_id)) {
            share_id = auth::random_hex::<16>()?;
        }
        let mac = u.tenant().mac(auth::share_token(u.tenant(), &share_id).as_bytes());
        app2.db.share_add(
            u.tenant(),
            &crate::db::NewShare {
                share_id: &share_id,
                user: u.user(),
                mac: &mac,
                fileid: &id.0,
                path_hint: l.path.as_ref().map_or("", SafePath::as_str),
                perms: if l.perms == "drop" { "drop" } else { "read" },
                password_hash: hash.as_deref(),
                expires_at: l.expires,
                max_downloads: l.max,
                opts: &opts,
            },
        )?;
        tracing::info!(
            tenant = u.tenant().name(),
            user = u.user(),
            perms = l.perms,
            "share link created"
        );
        Ok(Ok(share_id))
    })
    .await;
    link_result(made)
}

/// Changes one of the owner's live links (the address stays). `Ok(false)`: no such live link.
pub(crate) async fn change_link(app: &Arc<App>, u: &UserCtx, s: &ShareRow, c: LinkChange) -> Result<bool, LinkError> {
    let expires = c.expires.unwrap_or(s.expires_at);
    if c.expires.flatten().is_some_and(|e| e <= crate::db::now_secs()) {
        return Err(LinkError::Refused(PAST_EXPIRY));
    }
    let hash = match c.password {
        None => s.password_hash.clone(),
        Some(None) => None,
        Some(Some(pw)) => Some(link_password(app, pw).await?),
    };
    let perms = c.perms.unwrap_or(access(s));
    let mut opts = crate::db::LinkOptions {
        upload: perms == "upload",
        label: match c.label {
            Some(l) => link_text(&l, LABEL_MAX, false).map_err(LinkError::Refused)?,
            None => s.opts.label.clone(),
        },
        note: match c.note {
            Some(n) => link_text(&n, NOTE_MAX, true).map_err(LinkError::Refused)?,
            None => s.opts.note.clone(),
        },
        hide_download: perms != "drop" && c.hide_download.unwrap_or(s.opts.hide_download),
    };
    let (app2, u, id, path) = (app.clone(), u.clone(), s.share_id.clone(), s.path_hint.clone());
    let done = blocking(move || -> crate::Result<Result<bool, &'static str>> {
        if perms != "read" {
            let p = (!path.is_empty()).then(|| SafePath::new(&path)).transpose()?;
            let is_dir = u.root()?.meta(p.as_ref())?.is_dir;
            if perms == "drop" && !is_dir {
                return Ok(Err(DROP_ON_FILE));
            }
            // Upload asked on a file: read only, as on creation.
            opts.upload &= is_dir;
        }
        let ok = app2.db.share_update(
            u.tenant(),
            u.user(),
            &id,
            if perms == "drop" { "drop" } else { "read" },
            hash.as_deref(),
            expires,
            &opts,
        )?;
        if ok {
            tracing::info!(tenant = u.tenant().name(), user = u.user(), perms, "share link changed");
        }
        Ok(Ok(ok))
    })
    .await;
    link_result(done)
}

/// A link's short identifier for the clients (OCS `id`): the first 31 bits of its identifier, so that it fits the
/// Android app's 32-bit integer. Kept unique among the owner's live links when the link is created.
pub(crate) fn client_id(share_id: &str) -> u32 {
    share_id
        .get(..8)
        .and_then(|h| u32::from_str_radix(h, 16).ok())
        .unwrap_or(0)
        >> 1
}

/// Fuzzing (`headers` target): a cleaned drop name is always one valid component, never hidden, without a
/// character forbidden on Windows, a bidirectional control, a trailing dot or space, or a bare device name.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn fuzz_drop_name(raw: &str) {
    let Ok(p) = SafePath::new(raw) else { return };
    let Some(n) = drop_name(Some(&p)) else { return };
    let ok = SafePath::new(&n).is_ok_and(|q| q.as_str() == n)
        && !n.contains('/')
        && !n.starts_with('.')
        && !n.ends_with(['.', ' '])
        && !n.contains([':', '*', '?', '"', '<', '>', '|'])
        && !n.contains(
            |c| matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'),
        )
        && !matches!(
            n.split('.').next().map(str::to_ascii_uppercase).as_deref(),
            Some("CON" | "PRN" | "AUX" | "NUL")
        );
    if !ok {
        panic!("bad drop name {n:?} from {raw:?}");
    }
}

/// `PUT /s/<token>/drop/<name>`: drop into the shared folder. Announced size required, bounded per file, in total
/// and in number of files per link, few drops at once, owner's quota respected, name cleaned, no overwrite; the
/// response reveals no name.
async fn drop_file(app: &Arc<App>, t: &TenantCtx, o: Opened, sub: Option<SafePath>, req: Request) -> Response {
    let Some(name) = drop_name(sub.as_ref()) else {
        return public(StatusCode::BAD_REQUEST.into_response());
    };
    if let Err(r) = dav::write::writable_tenant(app, t).await {
        return public(r);
    }
    let Some(len) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    else {
        return public(StatusCode::LENGTH_REQUIRED.into_response());
    };
    if len > app.settings.drop_max_file_bytes {
        return public(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    // Busy (this link or every drop link): refused at once, the connection is freed; the page retries later.
    let Some(_slot) = app.drop_slots.take(&o.s.share_id) else {
        return public((StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "10")]).into_response());
    };
    let (app2, t2, id) = (app.clone(), t.clone(), o.s.share_id.clone());
    let max = i64::try_from(app.settings.drop_max_total_bytes).unwrap_or(i64::MAX);
    let files = i64::from(app.settings.drop_max_files);
    let ilen = i64::try_from(len).unwrap_or(i64::MAX);
    if !matches!(
        blocking(move || app2.db.share_drop(&t2, &id, ilen, max, files)).await,
        Ok(Ok(true))
    ) {
        return public(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let mut reserved = DropReservation {
        app: app.clone(),
        t: t.clone(),
        share_id: o.s.share_id.clone(),
        bytes: ilen,
        kept: false,
    };
    let (owner, dir) = (o.owner.clone(), o.target.clone());
    let w = blocking(move || -> io::Result<(crate::fs::AtomicWriter, SafePath)> {
        let root = owner.root()?;
        if root.space()?.available < len {
            return Err(io::Error::from_raw_os_error(libc::EDQUOT));
        }
        for n in super::free_names(&name, false) {
            let Some(p) = join(dir.as_ref(), SafePath::new(&n).ok().as_ref()) else {
                continue;
            };
            if matches!(root.meta(Some(&p)), Err(ref e) if e.raw_os_error() == Some(libc::ENOENT)) {
                return Ok((root.writer(&p)?, p));
            }
        }
        Err(io::Error::from_raw_os_error(libc::EEXIST))
    })
    .await;
    let (w, path) = match w {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => return public(dav::write::write_status(&e).into_response()),
        Err(r) => return public(r),
    };
    let w = match dav::write::stream_into(w, req.into_body()).await {
        Ok(w) => w,
        Err(r) => return public(r),
    };
    if w.len() != len {
        return public(StatusCode::BAD_REQUEST.into_response());
    }
    let owner = o.owner.clone();
    let shown = path.split_parent().1.to_owned();
    let r = blocking(move || {
        let root = owner.root()?;
        let parent = path.split_parent().0;
        dav::write::journaled(&owner, &root, &[parent.as_ref()], || {
            w.commit(None, None, |old| old.is_none())
        })
    })
    .await;
    match r {
        Ok(Ok(_)) => {
            reserved.kept = true;
            tracing::info!(
                tenant = t.name(),
                share = o.s.share_id,
                bytes = len,
                "drop link: file received"
            );
            note(app, t, &o, ShareEventKind::Drop, shown, ilen).await;
            public(StatusCode::CREATED.into_response())
        }
        // Another drop took this name in the meantime: refused rather than overwritten.
        Ok(Err(e)) if is_refused(&e, Refused::Precondition) => public(StatusCode::CONFLICT.into_response()),
        Ok(Err(e)) => public(dav::write::write_status(&e).into_response()),
        Err(r) => public(r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// State of a link's target: present; in the trash (itself or inside a deleted folder, even if a same-named
    /// item took its place); gone (missing, renamed, permanently deleted); undetermined (item without
    /// identity: the link must not end, a restore without xattrs allows it).
    #[test]
    fn link_target_states() {
        let t = tempfile::tempdir().unwrap();
        let root = crate::fs::Root::open_dir(t.path()).unwrap();
        root.ensure_layout().unwrap();
        let sp = |s: &str| SafePath::new(s).unwrap();
        root.mkdir(&sp("dossier")).unwrap();
        root.atomic_write(&sp("dossier/f.txt"), &mut &b"f"[..]).unwrap();
        let id_of = |p: &str| root.meta(Some(&sp(p))).unwrap().id.unwrap().0.to_vec();
        let (dir, file) = (id_of("dossier"), id_of("dossier/f.txt"));
        std::fs::create_dir(t.path().join("sans-identite")).unwrap();
        let state = |p: &str, id: &[u8]| match target(&root, Some(&sp(p)), id, &mut TrashScan::default()) {
            Target::Here(_) => "ici",
            Target::Trashed => "corbeille",
            Target::Gone => "disparu",
            Target::Unknown => "indéterminé",
        };
        assert_eq!(state("dossier", &dir), "ici");
        assert_eq!(state("dossier", &[0; 16]), "disparu"); // another item with the same name, original not found
        assert_eq!(state("absent", &dir), "disparu");
        assert_eq!(state("dossier/absent/x", &dir), "disparu");
        assert_eq!(state("sans-identite", &dir), "indéterminé");

        // In the trash, with what it contains; a re-created same-named item changes nothing while the original is there.
        root.trash(&sp("dossier"), "alice").unwrap();
        assert_eq!(state("dossier", &dir), "corbeille");
        assert_eq!(state("dossier/f.txt", &file), "corbeille");
        root.mkdir(&sp("dossier")).unwrap();
        assert_eq!(state("dossier", &dir), "corbeille");
        // A page of links: the trash is read only once, whatever the number of missing targets; a present
        // target does not read it; a suspended link (`here`) does not either.
        let mut scan = TrashScan::default();
        for p in ["dossier/f.txt", "absent", "dossier/f.txt"] {
            let _ = target(&root, Some(&sp(p)), &file, &mut scan);
        }
        assert_eq!(scan.reads, 1);
        let mut none = TrashScan::default();
        assert!(matches!(
            target(&root, Some(&sp("dossier")), &id_of("dossier"), &mut none),
            Target::Here(_)
        ));
        assert_eq!(none.reads, 0);
        assert!(here(&root, Some(&sp("dossier")), &dir).is_none()); // the original is in the trash: not "back"

        // Emptied: gone for good.
        root.trash_empty().unwrap();
        assert_eq!(state("dossier", &dir), "disparu");
        assert_eq!(state("dossier/f.txt", &file), "disparu");
        assert!(target_path("").unwrap().is_none() && target_path("../x").is_err());
    }

    #[test]
    fn drop_names_and_suffixes() {
        let p = |s: &str| SafePath::new(s).ok();
        assert_eq!(drop_name(p("rapport.pdf").as_ref()).as_deref(), Some("rapport.pdf"));
        for bad in [".htaccess", "a/b", "../x", ".trash", " .x", "\u{200E}.x", "...", " "] {
            assert_eq!(drop_name(p(bad).as_ref()), None, "{bad:?}");
        }
        // Cleaned so that the owner's Windows client can sync it, and so that nothing is disguised.
        for (raw, clean) in [
            ("facture\u{202E}fdp.exe", "facturefdp.exe"),
            ("a:b*c?.txt", "a_b_c_.txt"),
            ("\"<x|y>\".doc", "__x_y__.doc"),
            ("note. . ", "note"),
            ("  espace.txt", "espace.txt"),
            ("CON", "_CON"),
            ("nul.txt", "_nul.txt"),
            ("com1.tar.gz", "_com1.tar.gz"),
            ("LPT9", "_LPT9"),
            ("COM0", "COM0"),
            ("CONSOLE.txt", "CONSOLE.txt"),
            ("été 2026.jpg", "été 2026.jpg"),
        ] {
            assert_eq!(drop_name(p(raw).as_ref()).as_deref(), Some(clean), "{raw:?}");
        }
        // Fuzzing: a control removed between combining marks leaves a name to put back in NFC.
        let marks = "\u{35c}\u{5bc}\u{59c}\u{59c}\u{59c}\u{5bc}\u{59c}\u{59c}\u{59c}\u{35c}\u{5bc}\u{59c}\u{59c}\u{61c}\u{5bc}\u{59c}\u{59c}\u{59c}\u{59c}";
        let n = drop_name(p(marks).as_ref()).unwrap();
        assert_eq!(SafePath::new(&n).unwrap().as_str(), n);
        // A device name at the length limit: the prefix would exceed 255 bytes, refused.
        let long = format!("con.{}", "x".repeat(251));
        assert_eq!(drop_name(p(&long).as_ref()), None);
        assert_ne!(link_key("abc"), link_key("abd"));
    }

    #[test]
    fn drop_slots_are_bounded_and_given_back() {
        let slots = DropSlots::default();
        let a: Vec<_> = (0..DROPS_PER_LINK).map(|_| slots.take("a").unwrap()).collect();
        assert!(slots.take("a").is_none(), "per link");
        let others: Vec<_> = (0..DROPS_ALL - DROPS_PER_LINK)
            .map(|i| slots.take(&format!("l{i}")).unwrap())
            .collect();
        assert!(slots.take("z").is_none(), "in all");
        drop(a);
        assert!(slots.take("a").is_some() && slots.take("z").is_some());
        drop(others);
        assert!(slots.map().is_empty());
    }
}
