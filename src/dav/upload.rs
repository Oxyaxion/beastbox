//! Chunked upload v2 (§7): `/remote.php/dav/uploads/<user>/<id>/…`.
//! MKCOL `<id>` → PUT `<id>/<n>` (1 to 10,000) → MOVE `<id>/.file` to the destination (atomic assembly);
//! DELETE `<id>` abandons; PROPFIND lists the chunks received (resume). Chunks live in
//! `.beastbox-uploads/` of the user's dataset: they count against their quota and assembly stays a `rename`.

use super::write::{Pre, check_space, destination, journaled, oc_mtime, oc_sha1, writable, write_status, written};
use super::{Dav, io_status, propfind, small_body};
use crate::fs::{MAX_CHUNKS, SafePath};
use crate::http::{App, Base, ClientIp, blocking, require_user};
use crate::tenant::TenantCtx;
use axum::Extension;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

/// Abandoned upload: deleted beyond this delay (checked on every creation, §7).
const UPLOAD_MAX_AGE: Duration = Duration::from_secs(24 * 3600);

/// Upload identifier chosen by the client: `[A-Za-z0-9_.-]{1,128}`, does not start with `.`.
fn upload_id(s: &str) -> Option<SafePath> {
    let ok = (1..=128).contains(&s.len())
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if ok { SafePath::new(s).ok() } else { None }
}

pub async fn uploads(
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
    let rest = params
        .get("path")
        .map(|p| p.trim_matches('/').to_owned())
        .unwrap_or_default();
    let (id, sub) = match rest.split_once('/') {
        Some((i, s)) => (i, Some(s)),
        None => (rest.as_str(), None),
    };
    let Some(id) = upload_id(id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let files_base = format!("/remote.php/dav/files/{}/", u.user());
    let d = Dav {
        app,
        u,
        base: files_base,
        origin,
    };
    let (parts, body) = req.into_parts();
    let h = &parts.headers;
    match (parts.method.as_str(), sub) {
        ("MKCOL", None) => create(&d, id, h).await,
        ("PUT", Some(n)) => match n.parse::<u32>().ok().filter(|n| (1..=MAX_CHUNKS).contains(n)) {
            Some(n) => chunk(&d, id, n, h, body).await,
            None => StatusCode::BAD_REQUEST.into_response(),
        },
        ("MOVE", Some(".file")) => assemble(&d, id, h).await,
        ("DELETE", None) => {
            let u = d.u.clone();
            match blocking(move || u.root()?.uploads()?.remove_upload(&id)).await {
                Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
                Ok(Err(e)) => io_status(&e).into_response(),
                Err(r) => r,
            }
        }
        ("PROPFIND", None) => {
            let body = match small_body(body).await {
                Ok(b) => b,
                Err(r) => return r,
            };
            let u = d.u.clone();
            let base = format!("/remote.php/dav/uploads/{}/", d.u.user());
            propfind(move || u.root()?.uploads(), Default::default, base, Some(id), h, &body).await
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// MKCOL: creates the upload folder (507 right away if `OC-Total-Length` exceeds the quota),
/// and purges this user's abandoned uploads.
async fn create(d: &Dav, id: SafePath, h: &HeaderMap) -> Response {
    if let Err(r) = writable(d).await {
        return r;
    }
    if let Err(r) = check_space(&d.u, h).await {
        return r;
    }
    let u = d.u.clone();
    let r = blocking(move || {
        let up = u.root()?.uploads()?;
        match up.expire_uploads(UPLOAD_MAX_AGE) {
            Ok(0) => {}
            Ok(n) => tracing::info!(
                tenant = u.tenant().name(),
                user = u.user(),
                n,
                "abandoned uploads removed"
            ),
            Err(e) => tracing::warn!("upload purge: {e}"),
        }
        up.mkdir(&id).map(drop)
    })
    .await;
    match r {
        Ok(Ok(())) => StatusCode::CREATED.into_response(),
        Ok(Err(e)) => write_status(&e).into_response(),
        Err(r) => r,
    }
}

/// PUT of a chunk: streamed, in batches (like a file PUT). Quota checked against `Content-Length`.
async fn chunk(d: &Dav, id: SafePath, n: u32, h: &HeaderMap, body: axum::body::Body) -> Response {
    if let Err(r) = writable(d).await {
        return r;
    }
    let len = h
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if let Some(len) = len {
        let u = d.u.clone();
        match blocking(move || u.root().and_then(|r| r.space())).await {
            Ok(Ok(s)) if s.available < len => return StatusCode::INSUFFICIENT_STORAGE.into_response(),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return io_status(&e).into_response(),
            Err(r) => return r,
        }
    }
    let u = d.u.clone();
    // Upload folder missing (no MKCOL, or purged): 404.
    let mut file = match blocking(move || u.root()?.uploads()?.create_chunk(&id, n)).await {
        Ok(Ok(f)) => f,
        Ok(Err(e)) => return io_status(&e).into_response(),
        Err(r) => return r,
    };
    let mut s = body.into_data_stream();
    let mut buf = Vec::new();
    loop {
        let next = s.next().await;
        let end = next.is_none();
        match next {
            Some(Ok(b)) => buf.extend_from_slice(&b),
            Some(Err(_)) => return StatusCode::BAD_REQUEST.into_response(),
            None => {}
        }
        if buf.len() >= 256 * 1024 || (end && !buf.is_empty()) {
            let data = std::mem::take(&mut buf);
            file = match blocking(move || file.write_all(&data).map(|()| file)).await {
                Ok(Ok(f)) => f,
                Ok(Err(e)) => return write_status(&e).into_response(),
                Err(r) => return r,
            };
        }
        if end {
            return StatusCode::CREATED.into_response();
        }
    }
}

/// MOVE `.file`: checks the chunks (1..k contiguous, total = `OC-Total-Length`), assembles them in an
/// atomic writer to the destination, validates (`If-Match`, `OC-Checksum`, `X-OC-Mtime`), then deletes the
/// upload. A failure leaves the destination intact and the chunks in place (the client can retry).
/// shortcut: assembly holds a blocking thread for the whole copy (possibly several GB) and the
/// chunks stay until the rename (space peak = 2 × file); revisit if quota or latency demands it.
async fn assemble(d: &Dav, id: SafePath, h: &HeaderMap) -> Response {
    let to = match destination(d, &d.base, h) {
        Ok(Some(t)) => t,
        Ok(None) => return StatusCode::FORBIDDEN.into_response(),
        Err(s) => return s.into_response(),
    };
    if let Err(r) = writable(d).await {
        return r;
    }
    let total = h
        .get("oc-total-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let (pre, sha1, mtime) = (Pre::from(h), oc_sha1(h), oc_mtime(h));
    let u = d.u.clone();
    let r = blocking(move || -> io::Result<Result<crate::fs::Written, StatusCode>> {
        let root = u.root()?;
        let up = root.uploads()?;
        let chunks = up.chunks(&id)?;
        let contiguous = chunks
            .iter()
            .enumerate()
            .all(|(i, (n, _))| usize::try_from(*n).ok() == Some(i + 1));
        let size: u64 = chunks.iter().map(|(_, s)| s).sum();
        if chunks.is_empty() || !contiguous || total.is_some_and(|t| t != size) {
            tracing::warn!(
                user = u.user(),
                chunks = chunks.len(),
                size,
                ?total,
                "upload incomplete or inconsistent"
            );
            return Ok(Err(StatusCode::BAD_REQUEST));
        }
        let mut w = root.writer(&to)?;
        let mut buf = vec![0u8; 256 * 1024];
        for (n, _) in &chunks {
            let mut f = up.open_chunk(&id, *n)?;
            loop {
                let k = f.read(&mut buf)?;
                if k == 0 {
                    break;
                }
                w.write(buf.get(..k).unwrap_or_default())?;
            }
        }
        let parent = to.split_parent().0;
        let written = journaled(&u, &root, &[parent.as_ref()], || {
            w.commit(mtime, sha1.as_deref(), |old| pre.ok(old))
        })?;
        up.remove_upload(&id)?;
        Ok(Ok(written))
    })
    .await;
    match r {
        Ok(Ok(Ok(w))) => written(&w, mtime.is_some()),
        Ok(Ok(Err(s))) => s.into_response(),
        Ok(Err(e)) => write_status(&e).into_response(),
        Err(r) => r,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn upload_ids() {
        for ok in ["1234567890", "web-file-upload-ab_12", "a.b"] {
            assert!(super::upload_id(ok).is_some(), "{ok}");
        }
        for bad in ["", ".file", "..", "a/b", "a b", "é", &"a".repeat(129)] {
            assert!(super::upload_id(bad).is_none(), "{bad}");
        }
    }
}

#[cfg(test)]
mod router_tests {
    use crate::http::tests::{A, basic, call, env, env_with, send, token};
    use axum::http::StatusCode;

    const UP: &str = "/remote.php/dav/uploads/alice/up-1";

    /// What the router refuses on an upload: unknown methods (405), chunk numbers out of 1..=10,000 (400, bounds at,
    /// below, above), a chunk announced larger than the free space (507, before any byte is read), an assembly to the
    /// root, to another user's space or without a destination (nothing written anywhere).
    #[tokio::test]
    async fn upload_refusals() {
        let e = env();
        let auth = basic("alice", &token(&e, "alpha"));
        let h = [A, ("authorization", auth.as_str())];
        assert_eq!(send(&e.app, "MKCOL", UP, &h, b"").await.0, StatusCode::CREATED);
        for (m, p) in [
            ("POST", UP.to_owned()),
            ("GET", UP.to_owned()),
            ("PUT", UP.to_owned()),
            ("MKCOL", format!("{UP}/1")),
            ("MOVE", format!("{UP}/1")),
        ] {
            assert_eq!(
                send(&e.app, m, &p, &h, b"").await.0,
                StatusCode::METHOD_NOT_ALLOWED,
                "{m} {p}"
            );
        }
        for (n, code) in [
            ("0", StatusCode::BAD_REQUEST),
            ("1", StatusCode::CREATED),
            ("10000", StatusCode::CREATED),
            ("10001", StatusCode::BAD_REQUEST),
            ("x", StatusCode::BAD_REQUEST),
            ("-1", StatusCode::BAD_REQUEST),
        ] {
            assert_eq!(
                send(&e.app, "PUT", &format!("{UP}/{n}"), &h, b"abc").await.0,
                code,
                "chunk {n}"
            );
        }
        let huge = [
            A,
            ("authorization", auth.as_str()),
            ("content-length", "18446744073709551615"),
        ];
        assert_eq!(
            send(&e.app, "PUT", &format!("{UP}/2"), &huge, b"").await.0,
            StatusCode::INSUFFICIENT_STORAGE
        );
        // Assembly: to the root (403), elsewhere than alice's files (refused), without Destination (400).
        let dest = |d: &'static str| [A, ("authorization", auth.as_str()), ("destination", d)];
        let mv = format!("{UP}/.file");
        assert_eq!(
            send(&e.app, "MOVE", &mv, &dest("/remote.php/dav/files/alice/"), b"")
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        for d in [
            "/remote.php/dav/files/bob/x",
            "/remote.php/dav/uploads/alice/y",
            "http://files.beta.example/remote.php/dav/files/alice/x",
        ] {
            let s = send(&e.app, "MOVE", &mv, &dest(d), b"").await.0;
            assert!(s.is_client_error() || s == StatusCode::BAD_GATEWAY, "{d}: {s}");
        }
        assert_eq!(send(&e.app, "MOVE", &mv, &h, b"").await.0, StatusCode::BAD_REQUEST);
        assert!(!e.a_root.path().join("alice/x").exists() && !e.a_root.path().join("bob").exists());
        // The chunks are still there: the client can retry.
        let (s, _, body) = call(
            &e.app,
            "PROPFIND",
            UP,
            &[A, ("authorization", auth.as_str()), ("depth", "1")],
            "",
        )
        .await;
        assert!(
            s == StatusCode::MULTI_STATUS && body.contains("up-1/1") && body.contains("up-1/10000"),
            "{body}"
        );
        // Another tenant's alice cannot see or touch it.
        let b = basic("alice", &token(&e, "beta"));
        let bh = [("host", "x.beta.example"), ("authorization", b.as_str())];
        assert_eq!(
            send(&e.app, "PUT", &format!("{UP}/3"), &bh, b"x").await.0,
            StatusCode::NOT_FOUND
        );
    }

    /// Read-only mode (maintenance): every write of an upload answers 503, nothing is written.
    #[tokio::test]
    async fn uploads_are_writes() {
        let ro = env_with(crate::http::Settings {
            read_only: true,
            ..Default::default()
        });
        let auth = basic("alice", &token(&ro, "alpha"));
        let h = [A, ("authorization", auth.as_str())];
        let d = [
            A,
            ("authorization", auth.as_str()),
            ("destination", "/remote.php/dav/files/alice/f"),
        ];
        assert_eq!(
            send(&ro.app, "MKCOL", UP, &h, b"").await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            send(&ro.app, "PUT", &format!("{UP}/1"), &h, b"abc").await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            send(&ro.app, "MOVE", &format!("{UP}/.file"), &d, b"").await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(!ro.a_root.path().join("alice/f").exists());
    }
}
