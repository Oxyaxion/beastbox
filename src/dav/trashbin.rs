//! Trash as seen by Nextcloud clients (§6): `/remote.php/dav/trashbin/<user>/` with `trash/` and `restore/`, based on
//! Nextcloud's `apps/files_trashbin/lib/Sabre` and the Android app (`android-library/…/resources/trashbin`).
//! An item is addressed by its slot (`trash/<slot>`): clients display `nc:trashbin-filename` and send the `href` back
//! as is. List (Depth 0/1, including inside a deleted folder), restore (`MOVE` to `restore/…`), delete one item or
//! empty everything (`DELETE`).
//! shortcut: no GET and no restore/delete of an entry inside a deleted folder (403); the Android app does not do it,
//! add it if a client asks for it.

use super::write::{self, writable};
use super::{
    ALLPROP, Dav, MULTISTATUS, NS_DAV, NS_NC, NS_OC, Want, href, io_status, parse_propfind, prop, render_with,
    small_body, xml_attr_escape,
};
use crate::fs::{Meta, SafePath, TRASH_LIST_MAX};
use crate::http::{App, Base, ClientIp, blocking, require_user};
use crate::tenant::TenantCtx;
use axum::Extension;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

const ALLOW: &str = "OPTIONS, PROPFIND, MOVE, DELETE";

const TRASH_ALL: [(&str, &str); 9] = [
    ALLPROP[0],
    ALLPROP[1],
    ALLPROP[2],
    ALLPROP[3],
    ALLPROP[4],
    (NS_NC, "trashbin-filename"),
    (NS_NC, "trashbin-original-location"),
    (NS_NC, "trashbin-deletion-time"),
    (NS_OC, "fileid"),
];

/// What the path under `trashbin/<user>/` points to.
enum At {
    Home,
    Restore,
    Trash,
    /// An item, or an entry inside a deleted folder (`rest`).
    Item {
        slot: String,
        rest: Option<SafePath>,
    },
}

fn parse(raw: &str) -> Option<At> {
    let mut it = raw.trim_matches('/').splitn(3, '/');
    Some(match (it.next().unwrap_or(""), it.next(), it.next()) {
        ("", None, None) => At::Home,
        ("restore", None, None) => At::Restore,
        ("trash", None, None) => At::Trash,
        ("trash", Some(slot), rest) => At::Item {
            slot: slot.to_owned(),
            rest: match rest {
                Some(r) => Some(SafePath::new(r).ok()?),
                None => None,
            },
        },
        _ => return None,
    })
}

/// `/remote.php/dav/trashbin/{user}[/{*path}]`: the user in the URL must be the authenticated one, otherwise 404.
pub async fn trashbin(
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
    let Some(at) = parse(params.get("path").map_or("", String::as_str)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let base = format!("/remote.php/dav/trashbin/{}/", u.user());
    let d = Dav { app, u, base, origin };
    let (parts, body) = req.into_parts();
    let h = &parts.headers;
    let r = match parts.method.as_str() {
        "OPTIONS" => {
            return (
                StatusCode::OK,
                [(header::ALLOW, ALLOW), (header::HeaderName::from_static("dav"), "1, 3")],
            )
                .into_response();
        }
        "PROPFIND" => {
            return match small_body(body).await {
                Ok(b) => propfind(d, at, h, &b).await,
                Err(r) => r,
            };
        }
        "MOVE" => restore(&d, at, h).await,
        "DELETE" => delete(&d, at).await,
        _ => return (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, ALLOW)]).into_response(),
    };
    if r.status().is_success() {
        tracing::info!(
            tenant = t.name(),
            user = d.u.user(),
            method = parts.method.as_str(),
            "trash (WebDAV)"
        );
    }
    r
}

/// What an item shows of its past: name, original path, deletion date.
struct Info<'a> {
    filename: &'a str,
    location: &'a str,
    deleted: i64,
}

fn trash_prop(ns: &str, local: &str, m: &Meta, i: &Info<'_>) -> Option<String> {
    let esc = xml_attr_escape;
    Some(match (ns, local) {
        (NS_NC, "trashbin-filename") => format!("<nc:trashbin-filename>{}</nc:trashbin-filename>", esc(i.filename)),
        (NS_NC, "trashbin-original-location" | "trashbin-title") => {
            format!("<nc:{local}>{}</nc:{local}>", esc(i.location))
        }
        (NS_NC, "trashbin-deletion-time") => {
            format!("<nc:trashbin-deletion-time>{}</nc:trashbin-deletion-time>", i.deleted)
        }
        (NS_DAV, "displayname") => format!("<d:displayname>{}</d:displayname>", esc(i.filename)),
        // Like Nextcloud: readable and deletable, nothing else.
        (NS_OC, "permissions") => "<oc:permissions>GD</oc:permissions>".into(),
        _ => return prop(ns, local, m, None),
    })
}

fn collection(out: &mut String, href: &str, want: &Want) {
    render_with(out, href, want, &ALLPROP, |n, l| {
        (n == NS_DAV && l == "resourcetype").then(|| "<d:resourcetype><d:collection/></d:resourcetype>".to_owned())
    });
}

fn enoent() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}

/// shortcut: response built in memory (at most `TRASH_LIST_MAX` items or entries, a few MB);
/// switch to streaming like the files PROPFIND if bigger trashes show up.
async fn propfind(d: Dav, at: At, h: &HeaderMap, body: &[u8]) -> Response {
    let depth1 = match h.get("depth").and_then(|v| v.to_str().ok()) {
        Some("0") => false,
        Some("1") => true,
        _ => return (StatusCode::FORBIDDEN, "Depth 0 or 1 required").into_response(),
    };
    let Some(want) = parse_propfind(body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (u, base) = (d.u, d.base);
    let r = blocking(move || -> io::Result<String> {
        let tbase = format!("{base}trash/");
        let mut out = String::from(MULTISTATUS);
        let item = |out: &mut String, path: &str, m: &Meta, i: &Info<'_>| {
            render_with(out, &href(&tbase, Some(path), m.is_dir), &want, &TRASH_ALL, |n, l| {
                trash_prop(n, l, m, i)
            });
        };
        match at {
            At::Home => {
                collection(&mut out, &base, &want);
                if depth1 {
                    collection(&mut out, &format!("{base}restore/"), &want);
                    collection(&mut out, &tbase, &want);
                }
            }
            At::Restore => collection(&mut out, &format!("{base}restore/"), &want),
            At::Trash => {
                collection(&mut out, &tbase, &want);
                if depth1 {
                    let root = u.root()?;
                    for t in root.trash_list()? {
                        // Item gone between the listing and the read: ignored.
                        let Ok((sr, name)) = root.trash_item(&t.slot) else {
                            continue;
                        };
                        let Some(m) = SafePath::new(&name).ok().and_then(|p| sr.meta(Some(&p)).ok()) else {
                            continue;
                        };
                        let loc = t.origin.as_ref().map_or(t.name.as_str(), SafePath::as_str);
                        item(
                            &mut out,
                            &t.slot,
                            &m,
                            &Info {
                                filename: &t.name,
                                location: loc,
                                deleted: t.deleted,
                            },
                        );
                    }
                }
            }
            At::Item { slot, rest } => {
                let root = u.root()?;
                let t = root
                    .trash_list()?
                    .into_iter()
                    .find(|t| t.slot == slot)
                    .ok_or_else(enoent)?;
                let (sr, name) = root.trash_item(&slot)?;
                let top = t.origin.as_ref().map_or(t.name.clone(), |o| o.as_str().to_owned());
                let (inner, loc, hpath, filename) = match &rest {
                    None => (name, top, slot.clone(), t.name.clone()),
                    Some(r) => (
                        format!("{name}/{}", r.as_str()),
                        format!("{top}/{}", r.as_str()),
                        format!("{slot}/{}", r.as_str()),
                        r.split_parent().1.to_owned(),
                    ),
                };
                let p = SafePath::new(&inner).map_err(|_| enoent())?;
                let m = sr.meta(Some(&p))?;
                item(
                    &mut out,
                    &hpath,
                    &m,
                    &Info {
                        filename: &filename,
                        location: &loc,
                        deleted: t.deleted,
                    },
                );
                if depth1 && m.is_dir {
                    for e in sr.read_dir(Some(&p))?.take(TRASH_LIST_MAX) {
                        let (cn, cm) = e?;
                        let cloc = format!("{loc}/{cn}");
                        let cpath = format!("{hpath}/{cn}");
                        item(
                            &mut out,
                            &cpath,
                            &cm,
                            &Info {
                                filename: &cn,
                                location: &cloc,
                                deleted: t.deleted,
                            },
                        );
                    }
                }
            }
        }
        out.push_str("</d:multistatus>");
        Ok(out)
    })
    .await;
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

/// `MOVE trash/<slot>` to `restore/<name>`: put back at its original path (the destination name is ignored, like
/// Nextcloud). 201 like sabre/dav.
async fn restore(d: &Dav, at: At, h: &HeaderMap) -> Response {
    let At::Item { slot, rest: None } = at else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if let Err(s) = write::destination(d, &format!("{}restore/", d.base), h) {
        return s.into_response();
    }
    if let Err(r) = writable(d).await {
        return r;
    }
    let u = d.u.clone();
    match blocking(move || write::restore(&u, &slot)).await {
        Ok(Ok(_)) => StatusCode::CREATED.into_response(),
        Ok(Err(e)) => io_status(&e).into_response(),
        Err(r) => r,
    }
}

/// `DELETE trash/<slot>`: permanent delete; `DELETE trash`: trash emptied. 204.
async fn delete(d: &Dav, at: At) -> Response {
    let slot = match at {
        At::Trash => None,
        At::Item { slot, rest: None } => Some(slot),
        _ => return StatusCode::FORBIDDEN.into_response(),
    };
    if let Err(r) = writable(d).await {
        return r;
    }
    let u = d.u.clone();
    let r = blocking(move || {
        let root = u.root()?;
        match slot {
            Some(s) => root.trash_purge(&s),
            None => root.trash_empty().map(drop),
        }
    })
    .await;
    match r {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => io_status(&e).into_response(),
        Err(r) => r,
    }
}

#[cfg(test)]
mod router_tests {
    use crate::http::tests::{A, basic, call, env, env_with, send, token};
    use axum::http::StatusCode;

    const TB: &str = "/remote.php/dav/trashbin/alice";
    const F: &str = "/remote.php/dav/files/alice";

    /// A deleted folder holding a subfolder; returns the folder's slot `href`.
    async fn deleted_tree(e: &crate::http::tests::Env, auth: &str) -> String {
        let a = [A, ("authorization", auth)];
        send(&e.app, "MKCOL", &format!("{F}/d"), &a, b"").await;
        send(&e.app, "MKCOL", &format!("{F}/d/sub"), &a, b"").await;
        send(&e.app, "PUT", &format!("{F}/d/sub/deep.txt"), &a, b"deep").await;
        assert_eq!(
            send(&e.app, "DELETE", &format!("{F}/d"), &a, b"").await.0,
            StatusCode::NO_CONTENT
        );
        let (_, _, body) = call(
            &e.app,
            "PROPFIND",
            &format!("{TB}/trash"),
            &[A, ("authorization", auth), ("depth", "1")],
            "",
        )
        .await;
        body.split("<d:href>")
            .nth(2)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned()
    }

    /// OPTIONS; Depth infinity and a malformed body refused; the restore collection listed; unknown methods 405; a
    /// subfolder of a deleted folder listed with its own content and original location.
    #[tokio::test]
    async fn trash_protocol_edges() {
        let e = env();
        let auth = basic("alice", &token(&e, "alpha"));
        let a = [A, ("authorization", auth.as_str())];
        let slot = deleted_tree(&e, &auth).await;
        let (s, h, _) = call(&e.app, "OPTIONS", &format!("{TB}/trash"), &a, "").await;
        assert!(s == StatusCode::OK && h["allow"].to_str().unwrap().contains("PROPFIND") && h["dav"] == "1, 3");
        let inf = [A, ("authorization", auth.as_str()), ("depth", "infinity")];
        assert_eq!(
            send(&e.app, "PROPFIND", &format!("{TB}/trash"), &inf, b"").await.0,
            StatusCode::FORBIDDEN
        );
        let d1 = [A, ("authorization", auth.as_str()), ("depth", "1")];
        assert_eq!(
            call(&e.app, "PROPFIND", &format!("{TB}/trash"), &d1, "<d:propfind")
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let (s, _, body) = call(&e.app, "PROPFIND", &format!("{TB}/restore"), &d1, "").await;
        assert!(
            s == StatusCode::MULTI_STATUS && body.contains(&format!("{TB}/restore/")),
            "{body}"
        );
        for m in ["GET", "PUT", "POST", "MKCOL", "COPY"] {
            assert_eq!(
                send(&e.app, m, &slot, &a, b"").await.0,
                StatusCode::METHOD_NOT_ALLOWED,
                "{m}"
            );
        }
        let (s, _, inner) = call(&e.app, "PROPFIND", &format!("{slot}sub/"), &d1, "").await;
        assert!(s == StatusCode::MULTI_STATUS, "{s}");
        assert!(inner.contains(&format!("{slot}sub/deep.txt</d:href>")), "{inner}");
        assert!(
            inner.contains("d/sub/deep.txt</nc:trashbin-original-location>"),
            "{inner}"
        );
        // Another tenant's alice sees an empty trash, and cannot reach this slot.
        let b = basic("alice", &token(&e, "beta"));
        let bd = [
            ("host", "x.beta.example"),
            ("authorization", b.as_str()),
            ("depth", "1"),
        ];
        let (_, _, theirs) = call(&e.app, "PROPFIND", &format!("{TB}/trash"), &bd, "").await;
        assert_eq!(theirs.matches("<d:response>").count(), 1, "{theirs}");
        let path = slot.split("/trash/").nth(1).unwrap();
        assert_eq!(
            send(&e.app, "PROPFIND", &format!("{TB}/trash/{path}"), &bd, b"")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }

    /// Restore refusals: the trash collection itself and an entry inside a deleted folder (403), no Destination
    /// (400), a destination outside `restore/` (403); nothing restored. Then `restore/` without a name restores to the
    /// original place (the name is ignored, like Nextcloud). Read-only mode: restore and delete answer 503 and the
    /// item stays in the trash.
    #[tokio::test]
    async fn trash_restore_refusals_and_read_only() {
        let e = env();
        let auth = basic("alice", &token(&e, "alpha"));
        let slot = deleted_tree(&e, &auth).await;
        let mv = |d: &'static str| [A, ("authorization", auth.as_str()), ("destination", d)];
        let restore = mv("/remote.php/dav/trashbin/alice/restore/d");
        assert_eq!(
            send(&e.app, "MOVE", &format!("{TB}/trash"), &restore, b"").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(&e.app, "MOVE", &format!("{slot}sub/"), &restore, b"").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(&e.app, "MOVE", &slot, &[A, ("authorization", auth.as_str())], b"")
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(&e.app, "MOVE", &slot, &mv("/remote.php/dav/files/alice/d"), b"")
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert!(!e.a_root.path().join("alice/d").exists());
        assert_eq!(
            send(
                &e.app,
                "MOVE",
                &slot,
                &mv("/remote.php/dav/trashbin/alice/restore/"),
                b""
            )
            .await
            .0,
            StatusCode::CREATED
        );
        assert_eq!(
            std::fs::read(e.a_root.path().join("alice/d/sub/deep.txt")).unwrap(),
            b"deep"
        );
        let ro = env_with(crate::http::Settings {
            read_only: true,
            ..Default::default()
        });
        let auth = basic("alice", &token(&ro, "alpha"));
        // The trash of the read-only server is built on disk directly (its WebDAV refuses writes).
        let root = ro
            .state
            .registry
            .by_name("alpha")
            .unwrap()
            .data_root()
            .open_subdir(&crate::fs::SafePath::new("alice").unwrap())
            .unwrap();
        root.atomic_write(&crate::fs::SafePath::new("x.txt").unwrap(), &mut &b"x"[..])
            .unwrap();
        root.trash(&crate::fs::SafePath::new("x.txt").unwrap(), "alice")
            .unwrap();
        let d1 = [A, ("authorization", auth.as_str()), ("depth", "1")];
        let (_, _, body) = call(&ro.app, "PROPFIND", &format!("{TB}/trash"), &d1, "").await;
        let slot = body
            .split("<d:href>")
            .nth(2)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned();
        let mv = [
            A,
            ("authorization", auth.as_str()),
            ("destination", "/remote.php/dav/trashbin/alice/restore/x.txt"),
        ];
        assert_eq!(
            send(&ro.app, "MOVE", &slot, &mv, b"").await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            send(&ro.app, "DELETE", &slot, &[A, ("authorization", auth.as_str())], b"")
                .await
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let (_, _, after) = call(&ro.app, "PROPFIND", &format!("{TB}/trash"), &d1, "").await;
        assert_eq!(after.matches("<d:response>").count(), 2, "{after}");
    }
}
