//! End-to-end tests of the web interface and public links (J3): real requests on the whole router.
//! Covers the J3 exit criteria (§11) and the separation of the public / authenticated surfaces (§0.3).

use crate::auth;
use crate::fs::SafePath;
use crate::http::tests::{A, Env, basic, call, env, send, status, token};
use axum::http::{HeaderMap, StatusCode};

const B: (&str, &str) = ("host", "x.beta.example");

/// Web login: returns the `Cookie` header to replay and the session's CSRF token.
pub(super) async fn login(e: &Env, host: (&'static str, &'static str), pw: &str) -> (String, String) {
    let body = format!("user=alice&password={pw}");
    let (s, h, _) = call(&e.app, "POST", "/login", &[host], &body).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "login refused");
    let set = h["set-cookie"].to_str().unwrap();
    assert!(
        set.contains("HttpOnly")
            && set.contains("Secure")
            && set.contains("SameSite=Lax")
            && set.starts_with("__Host-")
    );
    assert!(!set.contains("Domain"), "cookie bound to the exact host (§4.1)");
    let pair = set.split(';').next().unwrap().to_owned();
    let secret = pair.split_once('=').unwrap().1.to_owned();
    let tenant = if host.1.ends_with("alpha.example") {
        "alpha"
    } else {
        "beta"
    };
    let t = e.state.registry.by_name(tenant).unwrap();
    (pair, auth::csrf_token(&t, &secret))
}

fn disk(e: &Env) -> std::path::PathBuf {
    e.a_root.path().join("alice")
}

/// §0.3: separated surfaces. No session: pages → login, browser WebDAV → 401. Session and app
/// password are not interchangeable. CSRF required on every action.
#[tokio::test]
async fn surfaces_are_separated() {
    let e = env();
    let app = &e.app;
    for p in [
        "/web/files/",
        "/web/account",
        "/web/shares",
        "/web/view/x",
        "/web/raw/x",
        "/web/zip/",
    ] {
        let (s, h, _) = call(app, "GET", p, &[A], "").await;
        assert_eq!(
            (s, h["location"].to_str().unwrap()),
            (StatusCode::SEE_OTHER, "/login"),
            "{p}"
        );
    }
    assert_eq!(
        status(app, "PROPFIND", "/web/dav/", &[A, ("depth", "1")]).await,
        StatusCode::UNAUTHORIZED
    );
    // An app password does not open the web interface.
    let app_pw = basic("alice", &token(&e, "alpha"));
    assert_eq!(
        status(app, "GET", "/web/files/", &[A, ("authorization", &app_pw)]).await,
        StatusCode::SEE_OTHER
    );
    // A session does not open WebDAV/OCS (§2: app passwords only).
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str()), ("depth", "0")];
    assert_eq!(
        status(app, "PROPFIND", "/remote.php/dav/files/alice/", &c).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(app, "GET", "/ocs/v2.php/cloud/user", &c).await,
        StatusCode::UNAUTHORIZED
    );
    // Browser WebDAV: session **and** CSRF token.
    assert_eq!(status(app, "PROPFIND", "/web/dav/", &c).await, StatusCode::FORBIDDEN);
    let ok = [
        A,
        ("cookie", cookie.as_str()),
        ("depth", "0"),
        ("x-csrf-token", csrf.as_str()),
    ];
    assert_eq!(
        status(app, "PROPFIND", "/web/dav/", &ok).await,
        StatusCode::MULTI_STATUS
    );
    // Form without CSRF token: refused.
    let (s, _, _) = call(
        app,
        "POST",
        "/web/tags",
        &[A, ("cookie", cookie.as_str())],
        "path=&op=add&tag=x",
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // A tenant's session is worthless on the other (cookie replayed on another domain).
    assert_eq!(
        status(app, "GET", "/web/files/", &[B, ("cookie", cookie.as_str())]).await,
        StatusCode::SEE_OTHER
    );
    // Pages: strict CSP, no cache.
    let (s, h, body) = call(app, "GET", "/web/files/", &[A, ("cookie", cookie.as_str())], "").await;
    assert_eq!(s, StatusCode::OK);
    let csp = h["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("script-src 'self'") && !csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"));
    assert_eq!(h["cache-control"], "no-store");
    assert!(!body.contains("<script>") && body.contains("<script src=\"/static/app.js\""));
    // Wrong password: 401, no cookie.
    let (s, h, _) = call(app, "POST", "/login", &[A], "user=alice&password=nope").await;
    assert!(s == StatusCode::UNAUTHORIZED && !h.contains_key("set-cookie"));
    // Logout: the session is worthless afterwards.
    let (s, _, _) = call(
        app,
        "POST",
        "/logout",
        &[A, ("cookie", cookie.as_str())],
        &format!("csrf={csrf}"),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(
        status(app, "GET", "/web/files/", &[A, ("cookie", cookie.as_str())]).await,
        StatusCode::SEE_OTHER
    );
}

/// J3 exit criterion: upload of a folder of 100 files (as the browser's drag and drop does it:
/// MKCOL then PUT with the CSRF token), then listing, rename, move, trash, ZIP.
#[tokio::test]
async fn upload_folder_of_100_files_and_actions() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    assert_eq!(
        send(app, "MKCOL", "/web/dav/Lot%20photo", &h, b"").await.0,
        StatusCode::CREATED
    );
    for i in 0..100 {
        let p = format!("/web/dav/Lot%20photo/img-{i:03}.jpg");
        assert_eq!(
            send(app, "PUT", &p, &h, format!("contenu {i}").as_bytes()).await.0,
            StatusCode::CREATED
        );
    }
    assert_eq!(std::fs::read_dir(disk(&e).join("Lot photo")).unwrap().count(), 100);
    let (s, _, body) = call(
        app,
        "GET",
        "/web/files/Lot%20photo/?n=100",
        &[A, ("cookie", cookie.as_str())],
        "",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body.matches("data-dav=\"/web/dav/Lot%20photo/img-").count(), 100);
    // Sort by descending size: the first file listed is the longest (img-099 → "contenu 99" equals the
    // others with 2 digits; img-000 is the shortest).
    let (_, _, sorted) = call(
        app,
        "GET",
        "/web/files/Lot%20photo/?sort=size&desc=0",
        &[A, ("cookie", cookie.as_str())],
        "",
    )
    .await;
    let first = sorted.split("data-name=\"").nth(1).unwrap().split('"').next().unwrap();
    assert!(first.starts_with("img-00"), "{first}");
    // Rename, move (MOVE with a Destination relative to the browser WebDAV), delete to the trash.
    let mv = [
        A,
        ("cookie", cookie.as_str()),
        ("x-csrf-token", csrf.as_str()),
        ("destination", "/web/dav/Lot%20photo/renomm%C3%A9.jpg"),
        ("overwrite", "F"),
    ];
    assert_eq!(
        send(app, "MOVE", "/web/dav/Lot%20photo/img-000.jpg", &mv, b"").await.0,
        StatusCode::CREATED
    );
    assert!(disk(&e).join("Lot photo/renommé.jpg").exists());
    assert_eq!(
        send(app, "DELETE", "/web/dav/Lot%20photo/img-001.jpg", &h, b"").await.0,
        StatusCode::NO_CONTENT
    );
    assert!(!disk(&e).join("Lot photo/img-001.jpg").exists());
    // ZIP of the folder, streamed, readable by unzip.
    let (s, hd, zipped) = {
        let mut b = axum::http::Request::builder().method("GET").uri("/web/zip/Lot%20photo");
        for (k, v) in [A, ("cookie", cookie.as_str())] {
            b = b.header(k, v);
        }
        use tower::ServiceExt;
        let res = app
            .clone()
            .oneshot(b.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        let (p, body) = res.into_parts();
        (
            p.status,
            p.headers,
            axum::body::to_bytes(body, usize::MAX).await.unwrap(),
        )
    };
    assert_eq!(
        (s, hd["content-type"].to_str().unwrap()),
        (StatusCode::OK, "application/zip")
    );
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("a.zip"), &zipped).unwrap();
    let t = std::process::Command::new("unzip")
        .arg("-l")
        .arg(d.path().join("a.zip"))
        .output()
        .unwrap();
    assert!(t.status.success());
    assert!(String::from_utf8_lossy(&t.stdout).contains("Lot photo/renommé.jpg"));
}

/// Escaping and previews (§8): a hostile name or `.md` never executes; SVG/HTML as attachments.
#[tokio::test]
async fn hostile_content_is_neutralized() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let root = e
        .state
        .registry
        .by_name("alpha")
        .unwrap()
        .data_root()
        .open_subdir(&SafePath::new("alice").unwrap())
        .unwrap();
    let put = |name: &str, data: &[u8]| {
        root.atomic_write(&SafePath::new(name).unwrap(), &mut &data[..])
            .unwrap()
    };
    put("<img src=x onerror=alert(1)>.txt", b"x");
    put(
        "piege.md",
        b"# Titre\n<script>alert(1)</script>\n[x](javascript:alert(1))",
    );
    put("image.svg", b"<svg onload=alert(1)/>");
    put("page.html", b"<script>alert(1)</script>");
    put("photo.png", b"\x89PNG");
    let c = [A, ("cookie", cookie.as_str())];
    let (_, _, list) = call(app, "GET", "/web/files/", &c, "").await;
    assert!(
        !list.contains("<img src=x") && list.contains("img src=x onerror=alert(1)") && list.contains("&#60;img"),
        "{list}"
    );
    // J3 exit criterion: a .md containing <script> does not execute.
    let (s, h, view) = call(app, "GET", "/web/view/piege.md", &c, "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(!view.contains("<script>alert") && !view.contains("javascript:") && view.contains("<h1>Titre</h1>"));
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'self'")
    );
    // Active types: never displayed, always as attachments, even with ?inline=1.
    for f in ["image.svg", "page.html"] {
        let (s, h, _) = call(app, "GET", &format!("/web/raw/{f}?inline=1"), &c, "").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h["content-type"], "application/octet-stream", "{f}");
        assert!(
            h["content-disposition"].to_str().unwrap().starts_with("attachment"),
            "{f}"
        );
        assert_eq!(h["content-security-policy"], "sandbox");
        assert_eq!(h["x-content-type-options"], "nosniff");
    }
    let (_, h, _) = call(app, "GET", "/web/raw/photo.png?inline=1", &c, "").await;
    assert_eq!(h["content-type"], "image/png");
    assert!(!h.contains_key("content-disposition"));
    // Tags: HTML refused, normal tag accepted and shown.
    let form = |tag: &str| format!("csrf={csrf}&path=photo.png&op=add&tag={tag}");
    assert_eq!(
        call(app, "POST", "/web/tags", &c, &form("%3Cscript%3E")).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(app, "POST", "/web/tags", &c, &form("Vacances+2026")).await.0,
        StatusCode::SEE_OTHER
    );
    let (_, _, list) = call(app, "GET", "/web/files/", &c, "").await;
    assert!(list.contains("<a class=\"tag\" href=\"/web/search?q=tag%3Avacances%202026\">vacances 2026</a>"));
    // Traversal through the URL path or a form field: refused.
    for p in [
        "/web/view/..%2f..%2fetc%2fpasswd",
        "/web/raw/.trash/x",
        "/web/files/../",
    ] {
        assert_eq!(status(app, "GET", p, &c).await, StatusCode::NOT_FOUND, "{p}");
    }
    let bad = format!("csrf={csrf}&path=..%2F..%2Fetc&op=add&tag=x");
    assert_eq!(call(app, "POST", "/web/tags", &c, &bad).await.0, StatusCode::NOT_FOUND);
}

pub(super) async fn make_share(e: &Env, cookie: &str, csrf: &str, path: &str, extra: &str) -> String {
    let body = format!("csrf={csrf}&path={path}{extra}");
    let (s, h, page) = call(&e.app, "POST", "/web/shares", &[A, ("cookie", cookie)], &body).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{page}");
    // The list with the new link at the top: its card comes first.
    let to = h
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .split('#')
        .next()
        .unwrap()
        .to_owned();
    let page = call(&e.app, "GET", &to, &[A, ("cookie", cookie)], "").await.2;
    let url = page.split("value=\"http").nth(1).unwrap().split('"').next().unwrap();
    url.split("/s/").nth(1).unwrap().to_owned()
}

/// A created link: redirect (a reload creates nothing), card at the top with the link, its options and the way back,
/// row marked "New" in the list; a `nouveau` that is not one of the user's links marks nothing.
#[tokio::test]
async fn share_created_is_shown_first() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    send(app, "MKCOL", "/web/dav/Clients", &h, b"").await;
    for f in ["a.pdf", "Clients/devis%20v3.pdf"] {
        send(app, "PUT", &format!("/web/dav/{f}"), &h, b"x").await;
    }
    let first = make_share(&e, &cookie, &csrf, "a.pdf", "&perms=read").await;
    let body = format!("csrf={csrf}&path=Clients%2Fdevis%20v3.pdf&perms=read&max=3&expires=2099-12-31");
    let (s, hd, _) = call(app, "POST", "/web/shares", &c, &body).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let loc = hd.get("location").unwrap().to_str().unwrap().to_owned();
    let id = loc
        .strip_prefix("/web/shares?nouveau=")
        .unwrap()
        .strip_suffix("#nouveau")
        .unwrap()
        .to_owned();
    assert!(id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()), "{loc}");
    let page = call(app, "GET", &format!("/web/shares?nouveau={id}"), &c, "").await.2;
    let card = page
        .split("<section class=\"lien-cree\" id=\"nouveau\"")
        .nth(1)
        .unwrap()
        .split("</section>")
        .next()
        .unwrap();
    assert!(
        card.contains("devis v3.pdf")
            && card
                .contains("· <a href=\"/web/files/Clients/?voir=devis%20v3%2Epdf#vise\" title=\"Clients\">Clients</a>")
            && card.contains("3 downloads at most"),
        "{card}"
    );
    assert!(card.contains("expires on 2099-12-31") && card.contains("href=\"/web/view/Clients/devis%20v3.pdf\""));
    assert!(!card.contains(&first) && card.contains("autofocus"));
    let tok = card.split("/s/").nth(1).unwrap().split('"').next().unwrap();
    assert_eq!(status(app, "GET", &format!("/s/{tok}"), &[A]).await, StatusCode::OK);
    assert_eq!(page.matches("class=\"nouveau\"").count(), 1);
    assert_eq!(page.matches("class=\"puce-l neuf\"").count(), 1);
    // Reload: still two links.
    let again = call(app, "GET", &format!("/web/shares?nouveau={id}"), &c, "").await.2;
    assert!(again.contains("<span class=\"compteur\">2</span>"));
    // Plain list, unknown or hostile identifier, another user's link: no card, nothing marked.
    // Other tenant's user (same name): never sees it.
    let (bc, _) = login(&e, B, "pw-alice").await;
    let bh = [B, ("cookie", bc.as_str())];
    let list: [(&[(&str, &str)], String); 4] = [
        (&c, String::new()),
        (&c, "?nouveau=00000000000000000000000000000000".into()),
        (&c, "?nouveau=%3Cscript%3E".into()),
        (&bh, format!("?nouveau={id}")),
    ];
    for (who, q) in list {
        let p = call(app, "GET", &format!("/web/shares{q}"), who, "").await.2;
        assert!(!p.contains("lien-cree") && !p.contains("class=\"nouveau\""), "{q}");
    }
}

/// J3 exit criterion: link with password, expiry and limit; revocation; other domain → 404.
#[tokio::test]
async fn share_password_limit_revoke_and_tenant() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let root = e
        .state
        .registry
        .by_name("alpha")
        .unwrap()
        .data_root()
        .open_subdir(&SafePath::new("alice").unwrap())
        .unwrap();
    root.atomic_write(&SafePath::new("rapport.pdf").unwrap(), &mut &b"%PDF-contenu"[..])
        .unwrap();
    let tok = make_share(
        &e,
        &cookie,
        &csrf,
        "rapport.pdf",
        "&perms=read&password=secret-du-lien&max=1&expires=2099-01-01",
    )
    .await;
    let link = format!("/s/{tok}");
    // Password asked; no access to the download without it.
    let (s, h, page) = call(app, "GET", &link, &[A], "").await;
    assert!(s == StatusCode::OK && page.contains("type=\"password\""));
    assert_eq!(h["x-robots-tag"], "noindex, nofollow");
    assert_eq!(
        status(app, "GET", &format!("{link}/dl"), &[A]).await,
        StatusCode::NOT_FOUND
    );
    // Wrong password then the right one.
    let (_, h, page) = call(app, "POST", &link, &[A], "password=faux").await;
    assert!(!h.contains_key("set-cookie") && page.contains("Wrong password"));
    let (s, h, _) = call(app, "POST", &link, &[A], "password=secret-du-lien").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let pass = h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
    // On another domain (other tenant), the same link does not exist.
    assert_eq!(status(app, "GET", &link, &[B]).await, StatusCode::NOT_FOUND);
    assert_eq!(
        status(app, "GET", &format!("{link}/dl"), &[B, ("cookie", pass.as_str())]).await,
        StatusCode::NOT_FOUND
    );
    // One download allowed (limit 1), the next one not.
    let (s, h, body) = call(app, "GET", &format!("{link}/dl"), &[A, ("cookie", pass.as_str())], "").await;
    assert_eq!((s, body.as_str()), (StatusCode::OK, "%PDF-contenu"));
    assert!(h["content-disposition"].to_str().unwrap().starts_with("attachment"));
    assert_eq!(
        status(app, "GET", &format!("{link}/dl"), &[A, ("cookie", pass.as_str())]).await,
        StatusCode::NOT_FOUND
    );
    // Forged or truncated token: same response.
    let other = if tok.ends_with('0') { '1' } else { '0' };
    for bad in [
        format!("/s/{}", &tok[..31]),
        format!("/s/{}{other}", &tok[..31]),
        "/s/../web".into(),
        "/s/".into(),
    ] {
        assert_eq!(status(app, "GET", &bad, &[A]).await, StatusCode::NOT_FOUND, "{bad}");
    }
    // Revoked link: 404.
    let tok2 = make_share(&e, &cookie, &csrf, "rapport.pdf", "&perms=read").await;
    assert_eq!(status(app, "GET", &format!("/s/{tok2}/dl"), &[A]).await, StatusCode::OK);
    let t = e.state.registry.by_name("alpha").unwrap();
    let id = e
        .state
        .db
        .share_list(&t, "alice")
        .unwrap()
        .into_iter()
        .find(|s| auth::share_token(&t, &s.share_id) == tok2)
        .unwrap()
        .share_id;
    let (s, _, _) = call(
        app,
        "POST",
        "/web/shares/revoke",
        &[A, ("cookie", cookie.as_str())],
        &format!("csrf={csrf}&id={id}"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        status(app, "GET", &format!("/s/{tok2}"), &[A]).await,
        StatusCode::NOT_FOUND
    );
    // Expired link: 404; past date refused at creation.
    let m = root.meta(Some(&SafePath::new("rapport.pdf").unwrap())).unwrap();
    let sid = auth::random_hex::<16>().unwrap();
    let tok3 = auth::share_token(&t, &sid);
    e.state
        .db
        .share_add(
            &t,
            &crate::db::NewShare {
                share_id: &sid,
                user: "alice",
                mac: &t.mac(tok3.as_bytes()),
                fileid: &m.id.unwrap().0,
                path_hint: "rapport.pdf",
                perms: "read",
                password_hash: None,
                expires_at: Some(1),
                max_downloads: None,
                opts: &Default::default(),
            },
        )
        .unwrap();
    assert_eq!(
        status(app, "GET", &format!("/s/{tok3}"), &[A]).await,
        StatusCode::NOT_FOUND
    );
    let past = format!("csrf={csrf}&path=rapport.pdf&perms=read&expires=2001-01-01");
    assert_eq!(
        call(app, "POST", "/web/shares", &[A, ("cookie", cookie.as_str())], &past)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    // Target deleted (in the trash): 404.
    let tok4 = make_share(&e, &cookie, &csrf, "rapport.pdf", "&perms=read").await;
    root.trash(&SafePath::new("rapport.pdf").unwrap(), "alice").unwrap();
    assert_eq!(
        status(app, "GET", &format!("/s/{tok4}"), &[A]).await,
        StatusCode::NOT_FOUND
    );
}

/// J3 exit criterion: drop only reveals no name; hostile names, size, total volume, no overwrite.
#[tokio::test]
async fn drop_only_reveals_nothing() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    assert_eq!(
        send(app, "MKCOL", "/web/dav/Boite", &h, b"").await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        send(app, "PUT", "/web/dav/Boite/secret-existant.txt", &h, b"confidentiel")
            .await
            .0,
        StatusCode::CREATED
    );
    let tok = make_share(&e, &cookie, &csrf, "Boite", "&perms=drop").await;
    let link = format!("/s/{tok}");
    let (s, _, page) = call(app, "GET", &link, &[A], "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(!page.contains("secret-existant"), "drop only must reveal no name");
    for p in ["/f/", "/dl/secret-existant.txt", "/zip"] {
        assert_eq!(
            status(app, "GET", &format!("{link}{p}"), &[A]).await,
            StatusCode::NOT_FOUND,
            "{p}"
        );
    }
    let put = |name: &str, body: Vec<u8>| {
        let (app, link, name) = (app.clone(), link.clone(), name.to_owned());
        async move {
            send(
                &app,
                "PUT",
                &format!("{link}/drop/{name}"),
                &[A, ("content-length", &body.len().to_string())],
                &body,
            )
            .await
            .0
        }
    };
    assert_eq!(put("depot.txt", b"un".to_vec()).await, StatusCode::CREATED);
    // Same name: no overwrite, suffix; the response says nothing about the name kept.
    assert_eq!(put("depot.txt", b"deux".to_vec()).await, StatusCode::CREATED);
    assert_eq!(
        put("secret-existant.txt", b"tentative".to_vec()).await,
        StatusCode::CREATED
    );
    let d = disk(&e).join("Boite");
    assert_eq!(std::fs::read(d.join("depot.txt")).unwrap(), b"un");
    assert_eq!(std::fs::read(d.join("depot (2).txt")).unwrap(), b"deux");
    assert_eq!(std::fs::read(d.join("secret-existant.txt")).unwrap(), b"confidentiel");
    assert_eq!(std::fs::read(d.join("secret-existant (2).txt")).unwrap(), b"tentative");
    // Hostile names.
    for bad in [".htaccess", "..%2Fx", "a%2Fb", "%2E%2E", ".trash"] {
        let s = put(bad, b"x".to_vec()).await;
        assert!(
            s == StatusCode::BAD_REQUEST || s == StatusCode::NOT_FOUND,
            "{bad} : {s}"
        );
    }
    // Per-file size (1 MiB in tests) and total volume (4 MiB in tests).
    assert_eq!(
        put("gros.bin", vec![0; (1 << 20) + 1]).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for i in 0..3 {
        assert_eq!(put(&format!("m{i}.bin"), vec![0; 1 << 20]).await, StatusCode::CREATED);
    }
    assert_eq!(put("m3.bin", vec![0; 1 << 20]).await, StatusCode::PAYLOAD_TOO_LARGE);
    // Without an announced size: refused.
    let (s, _) = send(app, "PUT", &format!("{link}/drop/sans.txt"), &[A], b"").await;
    assert!(s == StatusCode::LENGTH_REQUIRED || s == StatusCode::CREATED, "{s}");
}

/// Folder link for reading: listing, download, ZIP; never outside the shared subtree.
#[tokio::test]
async fn folder_share_is_confined() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    for d in ["/web/dav/Public", "/web/dav/Public/Sous", "/web/dav/Prive"] {
        assert_eq!(send(app, "MKCOL", d, &h, b"").await.0, StatusCode::CREATED);
    }
    send(app, "PUT", "/web/dav/Public/a.txt", &h, b"A").await;
    send(app, "PUT", "/web/dav/Public/Sous/b.txt", &h, b"B").await;
    send(app, "PUT", "/web/dav/Prive/c.txt", &h, b"C").await;
    let tok = make_share(&e, &cookie, &csrf, "Public", "&perms=read").await;
    let link = format!("/s/{tok}");
    let (_, _, page) = call(app, "GET", &link, &[A], "").await;
    assert!(page.contains("a.txt") && page.contains("Sous") && !page.contains("Prive"));
    assert_eq!(
        call(app, "GET", &format!("{link}/dl/Sous/b.txt"), &[A], "").await.2,
        "B"
    );
    assert_eq!(
        status(app, "GET", &format!("{link}/f/Sous/"), &[A]).await,
        StatusCode::OK
    );
    assert_eq!(status(app, "GET", &format!("{link}/zip"), &[A]).await, StatusCode::OK);
    for p in [
        "/dl/../Prive/c.txt",
        "/dl/..%2FPrive%2Fc.txt",
        "/f/..%2F",
        "/dl/.trash/x",
        "/dl/Sous",
        "/drop/x",
    ] {
        let s = status(app, "GET", &format!("{link}{p}"), &[A]).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{p}");
    }
    // A session does not widen a link: the link stays confined, the session gives nothing more there.
    assert_eq!(
        status(
            app,
            "GET",
            &format!("{link}/dl/../Prive/c.txt"),
            &[A, ("cookie", cookie.as_str())]
        )
        .await,
        StatusCode::NOT_FOUND
    );
    let _ = HeaderMap::new();
}

/// Account (§8.8): app passwords created and revoked, human password changed.
#[tokio::test]
async fn account_tokens_and_password() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let (s, _, page) = call(app, "GET", "/web/account", &c, "").await;
    assert!(s == StatusCode::OK && page.contains("used out of"));
    assert!(page.contains(&format!("Powered by Beastbox {}", env!("CARGO_PKG_VERSION"))));
    let (_, _, page) = call(
        app,
        "POST",
        "/web/account/tokens",
        &c,
        &format!("csrf={csrf}&label=T%C3%A9l%C3%A9phone"),
    )
    .await;
    let secret = page
        .split("<code>")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(secret.len(), 64);
    let dav = basic("alice", &secret);
    assert_eq!(
        status(
            app,
            "PROPFIND",
            "/remote.php/dav/files/alice/",
            &[A, ("authorization", &dav), ("depth", "0")]
        )
        .await,
        StatusCode::MULTI_STATUS
    );
    let t = e.state.registry.by_name("alpha").unwrap();
    let id = e
        .state
        .db
        .token_list(&t, "alice")
        .unwrap()
        .into_iter()
        .find(|x| x.label == "Téléphone")
        .unwrap()
        .token_id;
    call(
        app,
        "POST",
        "/web/account/tokens/revoke",
        &c,
        &format!("csrf={csrf}&id={id}"),
    )
    .await;
    assert_eq!(
        status(
            app,
            "PROPFIND",
            "/remote.php/dav/files/alice/",
            &[A, ("authorization", &dav), ("depth", "0")]
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    // Password change: the current one is required.
    let (_, _, page) = call(
        app,
        "POST",
        "/web/account/password",
        &c,
        &format!("csrf={csrf}&current=faux&new=nouveau-mot-de-passe"),
    )
    .await;
    // Failure visible as such (alert in the section) and nothing is changed (defect seen in the real trial of 2026-11-15).
    assert!(
        page.contains("class=\"alerte\" role=\"alert\">Wrong current password"),
        "{page}"
    );
    let (s, _, page) = call(
        app,
        "POST",
        "/web/account/password",
        &c,
        &format!("csrf={csrf}&current=faux&new=nouveau-mot-de-passe"),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, page2) = call(
        app,
        "POST",
        "/web/account/password",
        &c,
        &format!("csrf={csrf}&current=pw-alice&new=court"),
    )
    .await;
    assert!(
        s == StatusCode::BAD_REQUEST && page2.contains("role=\"alert\">New password too short"),
        "{page2}"
    );
    assert!(page.contains("was changed") && page.contains("nothing"));
    // Each rule is applied by the server (a form edited by hand changes nothing), with its own message.
    for (new, msg) in [
        ("x7kq2m!vb", "New password too short"), // 9 < min_password (12)
        ("azertyuiopqs", "too easy to guess"),
        ("alice-et-bob-2026", "must not contain the account"),
        ("pw-alice", "too short"),
    ] {
        let (s, _, p) = call(
            app,
            "POST",
            "/web/account/password",
            &c,
            &format!("csrf={csrf}&current=pw-alice&new={new}"),
        )
        .await;
        assert!(
            s == StatusCode::BAD_REQUEST && p.contains(msg) && p.contains("role=\"alert\""),
            "{new}: {p}"
        );
    }
    assert!(page2.contains(">12 characters at least<"), "{page2}"); // the setting is shown
    login(&e, A, "pw-alice").await; // still the old password
    let (_, _, page) = call(
        app,
        "POST",
        "/web/account/password",
        &c,
        &format!("csrf={csrf}&current=pw-alice&new=nouveau-mot-de-passe"),
    )
    .await;
    assert!(
        page.contains("class=\"info\" role=\"status\">Password changed"),
        "{page}"
    );
    login(&e, A, "nouveau-mot-de-passe").await;
}

/// §0.4: a large list is never rendered in one go: pages of 50 entries by default.
#[tokio::test]
async fn large_folder_is_paginated() {
    let e = env();
    let app = &e.app;
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let dir = disk(&e).join("Gros");
    std::fs::create_dir(&dir).unwrap();
    for i in 0..1200 {
        std::fs::write(dir.join(format!("f{i:04}.txt")), b"").unwrap();
    }
    let c = [A, ("cookie", cookie.as_str())];
    let rows = |b: &str| b.matches("data-dav=\"/web/dav/Gros/").count();
    let (_, _, p0) = call(app, "GET", "/web/files/Gros/", &c, "").await;
    assert_eq!(rows(&p0), 50);
    assert!(p0.contains("Page 1 of 24") && p0.contains("page=1") && !p0.contains("rel=\"prev\""));
    let (_, _, p2) = call(app, "GET", "/web/files/Gros/?sort=name&desc=0&page=23", &c, "").await;
    assert_eq!(rows(&p2), 50);
    assert!(p2.contains("Page 24 of 24") && p2.contains("f1199.txt") && !p2.contains("rel=\"next\""));
    let (s, _, _) = call(app, "GET", "/web/files/Gros/?page=999999999999", &c, "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(p0.contains("1–50 of 1200 items") && p0.contains("<option value=\"50\" selected>"));
    let offered: Vec<&str> = p0
        .split("<option value=\"")
        .skip(1)
        .filter_map(|o| o.split('"').next())
        .collect();
    assert_eq!(offered, ["20", "50", "100", "500", "1000"]);
    // Chosen page size: applied, kept in the links and remembered (cookie); size outside the list ignored.
    let (_, h, p) = call(app, "GET", "/web/files/Gros/?sort=name&desc=0&n=100&page=11", &c, "").await;
    assert_eq!(rows(&p), 100);
    assert!(p.contains("1101–1200 of 1200") && p.contains("Page 12 of 12") && p.contains("n=100&#38;page=10"));
    let set = h["set-cookie"].to_str().unwrap();
    assert!(set.starts_with("__Host-bbn=100;"), "{set}");
    let remembered = format!("{cookie}; __Host-bbn=100");
    let c2 = [A, ("cookie", remembered.as_str())];
    let (_, h, p) = call(app, "GET", "/web/files/Gros/", &c2, "").await;
    assert!(rows(&p) == 100 && !h.contains_key("set-cookie"));
    for n in ["7", "200", "0", "10000"] {
        let (_, _, p) = call(app, "GET", &format!("/web/files/Gros/?n={n}"), &c, "").await;
        assert_eq!(rows(&p), 50, "{n}");
    }
    let (_, _, p) = call(app, "GET", "/web/files/Gros/?n=1000", &c, "").await;
    assert_eq!(rows(&p), 1000);
}

/// The page size choice appears above the smallest size: not at 20 entries, at 21.
#[tokio::test]
async fn page_size_choice_from_21_entries() {
    let e = env();
    let app = &e.app;
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let dir = disk(&e).join("P");
    std::fs::create_dir(&dir).unwrap();
    for i in 0..19 {
        std::fs::write(dir.join(format!("f{i:02}.txt")), b"").unwrap();
    }
    for (name, offered) in [("f19.txt", false), ("f20.txt", true)] {
        std::fs::write(dir.join(name), b"").unwrap();
        let (_, _, p) = call(app, "GET", "/web/files/P/", &c, "").await;
        assert_eq!(p.contains("data-par-page"), offered, "{name}");
    }
}

/// Sorting by the Tags column: folders first, then by tags (untagged last, in both directions), then by name.
#[tokio::test]
async fn sort_by_tags() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let dir = disk(&e).join("T");
    std::fs::create_dir_all(dir.join("sous")).unwrap();
    for f in ["a.txt", "b.txt", "c.txt", "d.txt"] {
        std::fs::write(dir.join(f), b"").unwrap();
    }
    let c = [A, ("cookie", cookie.as_str())];
    for (f, t) in [("a.txt", "zoo"), ("b.txt", "alpha"), ("d.txt", "alpha")] {
        let body = format!("csrf={csrf}&path=T%2F{f}&op=add&tag={t}");
        assert_eq!(call(app, "POST", "/web/tags", &c, &body).await.0, StatusCode::SEE_OTHER);
    }
    let order = |b: &str| {
        let mut v: Vec<(usize, &str)> = ["sous", "a.txt", "b.txt", "c.txt", "d.txt"]
            .into_iter()
            .map(|n| (b.find(&format!("data-name=\"{n}\"")).unwrap(), n))
            .collect();
        v.sort_unstable();
        v.into_iter().map(|x| x.1).collect::<Vec<_>>()
    };
    let (_, _, p) = call(app, "GET", "/web/files/T/?sort=tags&desc=0", &c, "").await;
    assert_eq!(order(&p), ["sous", "b.txt", "d.txt", "a.txt", "c.txt"]);
    assert!(p.contains("aria-sort=\"ascending\"") && p.contains("?sort=tags&#38;desc=1"));
    let (_, _, p) = call(app, "GET", "/web/files/T/?sort=tags&desc=1", &c, "").await;
    assert_eq!(order(&p), ["sous", "a.txt", "b.txt", "d.txt", "c.txt"]);
}

/// Sorting by type (Sort menu), in the list and in the grid: folders first, then by kind (image, …, unknown last), then
/// by extension, then by name; the menu marks the choice and its links keep the view; an unknown key sorts by name; the
/// other tenant's user of the same name sees nothing of it.
#[tokio::test]
async fn sort_by_type_in_both_views() {
    let e = env();
    let app = &e.app;
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let dir = disk(&e).join("T");
    std::fs::create_dir_all(dir.join("sous.pdf")).unwrap();
    for f in ["z.pdf", "a.jpg", "B.PNG", "notes.md", "x.bin", "Readme"] {
        std::fs::write(dir.join(f), b"").unwrap();
    }
    let c = [A, ("cookie", cookie.as_str())];
    let order = |b: &str| {
        let mut v: Vec<(usize, &str)> = ["sous.pdf", "z.pdf", "a.jpg", "B.PNG", "notes.md", "x.bin", "Readme"]
            .into_iter()
            .map(|n| (b.find(&format!("data-name=\"{n}\"")).unwrap(), n))
            .collect();
        v.sort_unstable();
        v.into_iter().map(|x| x.1).collect::<Vec<_>>()
    };
    let asc = ["sous.pdf", "a.jpg", "B.PNG", "z.pdf", "notes.md", "Readme", "x.bin"];
    let desc = ["sous.pdf", "x.bin", "Readme", "notes.md", "z.pdf", "B.PNG", "a.jpg"];
    for view in ["", "&view=grid"] {
        let (_, _, p) = call(app, "GET", &format!("/web/files/T/?sort=type&desc=0{view}"), &c, "").await;
        assert_eq!(order(&p), asc, "{view}");
        assert!(
            p.contains("<strong>Type</strong> <span aria-hidden=\"true\">↑</span>"),
            "{view}"
        );
        let v = view.replace('&', "&#38;");
        assert!(
            p.contains(&format!("aria-checked=\"true\" href=\"?sort=type&#38;desc=0{v}\">Type")),
            "{view}"
        );
        assert!(
            p.contains(&format!(
                "aria-checked=\"false\" href=\"?sort=name&#38;desc=0{v}\">Name"
            )),
            "{view}"
        );
        assert!(
            p.contains(&format!("aria-checked=\"false\" href=\"?sort=type&#38;desc=1{v}\">↓")),
            "{view}"
        );
        let (_, _, p) = call(app, "GET", &format!("/web/files/T/?sort=type&desc=1{view}"), &c, "").await;
        assert_eq!(order(&p), desc, "{view}");
        assert!(
            p.contains("<strong>Type</strong> <span aria-hidden=\"true\">↓</span>"),
            "{view}"
        );
    }
    // Unknown or hostile key: by name, and the menu says so.
    let (_, _, p) = call(app, "GET", "/web/files/T/?sort=%3Cscript%3E&desc=0", &c, "").await;
    assert_eq!(
        order(&p),
        ["sous.pdf", "a.jpg", "B.PNG", "notes.md", "Readme", "x.bin", "z.pdf"]
    );
    assert!(p.contains("<strong>Name</strong>") && !p.contains("<script>"));
    // Other tenant: alpha's session is worthless there; beta's alice has no such folder.
    let b = [B, ("cookie", cookie.as_str())];
    assert_eq!(
        status(app, "GET", "/web/files/T/?sort=type", &b,).await,
        StatusCode::SEE_OTHER
    );
    let (bc, _) = login(&e, B, "pw-alice").await;
    let (s, _, p) = call(
        app,
        "GET",
        "/web/files/T/?sort=type&view=grid",
        &[B, ("cookie", bc.as_str())],
        "",
    )
    .await;
    assert!(s != StatusCode::OK && !p.contains("a.jpg"));
}

/// Hidden files (name starting with `.`): left out by default from the list, the grid, the counts and the tree (page,
/// lazy branches); `?hidden=1` shows them and is remembered (cookie), `?hidden=0` hides them again, any other value is
/// ignored; an item named by `?voir=` and a hidden folder opened by its address are still shown; the other tenant's
/// session gets nothing.
#[tokio::test]
async fn hidden_files_toggle() {
    let e = env();
    let app = &e.app;
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let dir = disk(&e).join("H");
    std::fs::create_dir_all(dir.join(".git/objects")).unwrap();
    std::fs::create_dir_all(dir.join("sous")).unwrap();
    std::fs::create_dir_all(disk(&e).join(".cache")).unwrap();
    for f in [".env", "a.txt", "a."] {
        std::fs::write(dir.join(f), b"").unwrap();
    }
    let c = [A, ("cookie", cookie.as_str())];
    let shown = |p: &str, n: &str| p.contains(&format!("data-name=\"{n}\""));
    // Default: hidden, in both views; "a." is not hidden.
    for view in ["", "?view=grid"] {
        let (_, h, p) = call(app, "GET", &format!("/web/files/H/{view}"), &c, "").await;
        assert!(!shown(&p, ".env") && !shown(&p, ".git") && shown(&p, "a.txt") && shown(&p, "a.") && shown(&p, "sous"));
        assert!(
            p.contains("3 items") && p.contains("Show hidden files") && !p.contains(">.git</a>"),
            "{view}"
        );
        let set = h
            .get("set-cookie")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        assert!(p.contains("&#38;hidden=1\"") && !set.contains("bbhidden"), "{view}");
    }
    let (_, _, p) = call(app, "GET", "/web/files/", &c, "").await;
    assert!(!shown(&p, ".cache") && !p.contains(">.cache</a>"));
    let (_, _, t) = call(app, "GET", "/web/tree/H/", &c, "").await;
    assert!(t.contains(">sous<") && !t.contains(".git"));
    // Any other value: ignored, nothing remembered.
    let (_, h, p) = call(app, "GET", "/web/files/H/?hidden=2", &c, "").await;
    assert!(!shown(&p, ".env") && !h.contains_key("set-cookie"));
    // Shown: list, grid, counts, tree; remembered.
    let (_, h, p) = call(app, "GET", "/web/files/H/?hidden=1", &c, "").await;
    assert!(shown(&p, ".env") && shown(&p, ".git") && p.contains("5 items") && p.contains(">.git</a>"));
    assert!(p.contains("Hide hidden files") && p.contains("&#38;hidden=0\""));
    let set = h["set-cookie"].to_str().unwrap();
    assert!(set.starts_with("__Host-bbhidden=1;"), "{set}");
    let remembered = format!("{cookie}; __Host-bbhidden=1");
    let c2 = [A, ("cookie", remembered.as_str())];
    let (_, h, p) = call(app, "GET", "/web/files/H/?view=grid", &c2, "").await;
    assert!(
        shown(&p, ".env")
            && shown(&p, ".git")
            && h.get("set-cookie")
                .is_none_or(|v| !v.to_str().unwrap().contains("bbhidden"))
    );
    let (_, _, p) = call(app, "GET", "/web/files/", &c2, "").await;
    assert!(shown(&p, ".cache") && p.contains(">.cache</a>"));
    let (_, _, t) = call(app, "GET", "/web/tree/H/", &c2, "").await;
    assert!(t.contains(">.git<"));
    let (_, h, p) = call(app, "GET", "/web/files/H/?hidden=0", &c2, "").await;
    assert!(!shown(&p, ".env") && h["set-cookie"].to_str().unwrap().starts_with("__Host-bbhidden=0;"));
    // Hidden, but named by `?voir=` (a search result): shown and marked.
    let (_, _, p) = call(app, "GET", "/web/files/H/?voir=.env", &c, "").await;
    assert!(shown(&p, ".env") && p.contains("id=\"vise\""));
    // A hidden folder opened by its address: its content, and its branch in the tree; its hidden siblings left out.
    let (s, _, p) = call(app, "GET", "/web/files/H/.git/", &c, "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(shown(&p, "objects") && p.contains(">.git</a>") && !p.contains(">.cache</a>"));
    // Other tenant: alpha's session (with the cookie) opens nothing there.
    let b = [B, ("cookie", remembered.as_str())];
    assert_eq!(
        status(app, "GET", "/web/files/H/?hidden=1", &b).await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(status(app, "GET", "/web/tree/H/", &b).await, StatusCode::SEE_OTHER);
}

/// Hidden name: starts with `.`, nothing else.
#[test]
fn is_hidden_bounds() {
    use super::is_hidden;
    assert!(is_hidden(".env") && is_hidden(".") && is_hidden(".."));
    assert!(!is_hidden("") && !is_hidden("a.") && !is_hidden("a.b") && !is_hidden(" .env"));
}

proptest::proptest! {
    /// Hidden files left out: exactly the full listing without the names starting with `.`, same order and counts.
    #[test]
    fn hiding_removes_exactly_the_hidden(names in proptest::collection::btree_set("\\.?[a-z]{1,4}", 0..20)) {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::fs::Root::open_dir(dir.path()).unwrap();
        root.ensure_layout().unwrap();
        for n in &names {
            root.atomic_write(&SafePath::new(n).unwrap(), &mut &b"x"[..]).unwrap();
        }
        let all = super::list(&root, None, "name", false, (0, 100), (false, true), None).unwrap();
        let some = super::list(&root, None, "name", false, (0, 100), (false, false), None).unwrap();
        let expected: Vec<&str> = all.entries.iter().map(|e| e.name.as_str()).filter(|n| !n.starts_with('.')).collect();
        let got: Vec<&str> = some.entries.iter().map(|e| e.name.as_str()).collect();
        proptest::prop_assert_eq!(&got, &expected);
        proptest::prop_assert_eq!(some.total, expected.len());
        proptest::prop_assert_eq!(all.total, names.len());
    }
}

/// Type sort key: folders all equal; rank of the kind (first, last known, unknown after it); extension lowercased.
#[test]
fn type_key_bounds() {
    use super::type_key;
    assert_eq!(type_key("photo.pdf", true), (0, String::new()));
    assert_eq!(type_key("a.jpg", false), (0, "jpg".into()));
    assert_eq!(type_key("a.JPG", false), (0, "jpg".into()));
    assert_eq!(type_key("a.zip", false), (10, "zip".into()));
    assert_eq!(type_key("a.bin", false), (11, "bin".into()));
    assert_eq!(type_key("Readme", false), (11, String::new()));
    assert!(type_key("a.png", false) < type_key("a.pdf", false));
    assert!(type_key("a.zip", false) < type_key("a.bin", false));
}

proptest::proptest! {
    /// The Type order is a total order: antisymmetric, reversed by `desc` except for folders, which always come first.
    #[test]
    fn type_order_is_total(
        a in "[A-Za-z]{0,4}(\\.(jpg|PNG|mp4|pdf|md|txt|csv|json|rs|zip|bin|docx))?", ad: bool,
        b in "[A-Za-z]{0,4}(\\.(jpg|PNG|mp4|pdf|md|txt|csv|json|rs|zip|bin|docx))?", bd: bool,
        desc: bool,
    ) {
        use super::{SortKey, order};
        use std::cmp::Ordering::{Greater, Less};
        let k = |name, is_dir| SortKey { is_dir, name, size: 0, mtime: 0, tags: &[] };
        let (x, y) = (k(a.as_str(), ad), k(b.as_str(), bd));
        let o = order("type", desc, &x, &y);
        proptest::prop_assert_eq!(o, order("type", desc, &y, &x).reverse());
        if ad != bd {
            proptest::prop_assert_eq!(o, if ad { Less } else { Greater });
        } else if !ad && super::type_key(&a, false) != super::type_key(&b, false) {
            proptest::prop_assert_eq!(o, order("type", !desc, &x, &y).reverse());
        }
    }
}

/// J3b exit criterion: selecting and deleting 50 items in one action, **without JavaScript** (classic
/// form); bulk move without overwrite; ZIP of a selection; hostile selection refused.
#[tokio::test]
async fn bulk_actions_without_javascript() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let d = disk(&e).join("Lot");
    std::fs::create_dir_all(d.join("Archive")).unwrap();
    for i in 0..60 {
        std::fs::write(d.join(format!("f{i:02}.txt")), format!("{i}")).unwrap();
    }
    let items = |r: std::ops::Range<usize>| r.map(|i| format!("&item=f{i:02}.txt")).collect::<String>();
    // Deleting 50 items in a single request.
    let (s, h, _) = call(
        app,
        "POST",
        "/web/bulk",
        &c,
        &format!("csrf={csrf}&dir=Lot&op=delete{}", items(0..50)),
    )
    .await;
    assert_eq!(
        (s, h["location"].to_str().unwrap()),
        (StatusCode::SEE_OTHER, "/web/files/Lot/?op=delete&ok=50&ko=0")
    );
    assert_eq!(std::fs::read_dir(&d).unwrap().count(), 11); // 10 files + Archive
    assert!(std::fs::read_dir(disk(&e).join(".trash")).unwrap().count() >= 50);
    let (_, _, page) = call(app, "GET", "/web/files/Lot/?op=delete&ok=50&ko=0", &c, "").await;
    assert!(page.contains("50 items moved to the trash."));
    // Bulk move: a name already taken at the destination is not overwritten, the item takes the first free name.
    std::fs::write(d.join("Archive/f55.txt"), b"deja la").unwrap();
    let (_, h, _) = call(
        app,
        "POST",
        "/web/bulk",
        &c,
        &format!("csrf={csrf}&dir=Lot&op=move&dest=Lot%2FArchive{}", items(50..60)),
    )
    .await;
    assert_eq!(
        h["location"].to_str().unwrap(),
        "/web/files/Lot/?op=move&ok=10&ko=0&to=Lot%2FArchive"
    );
    assert_eq!(std::fs::read(d.join("Archive/f55.txt")).unwrap(), b"deja la");
    assert_eq!(std::fs::read(d.join("Archive/f55 (2).txt")).unwrap(), b"55");
    assert!(!d.join("f55.txt").exists() && d.join("Archive/f59.txt").exists());
    // ZIP of the selection only.
    let body = format!("csrf={csrf}&dir=Lot%2FArchive&op=zip&item=f50.txt&item=f51.txt");
    let (s, h, zipped) = {
        use tower::ServiceExt;
        let mut b = axum::http::Request::builder().method("POST").uri("/web/bulk");
        for (k, v) in c {
            b = b.header(k, v);
        }
        let res = app
            .clone()
            .oneshot(b.body(axum::body::Body::from(body)).unwrap())
            .await
            .unwrap();
        let (p, b) = res.into_parts();
        (p.status, p.headers, axum::body::to_bytes(b, usize::MAX).await.unwrap())
    };
    assert_eq!(
        (s, h["content-type"].to_str().unwrap()),
        (StatusCode::OK, "application/zip")
    );
    let t = tempfile::tempdir().unwrap();
    std::fs::write(t.path().join("s.zip"), &zipped).unwrap();
    let out = std::process::Command::new("unzip")
        .arg("-Z1")
        .arg(t.path().join("s.zip"))
        .output()
        .unwrap();
    let names = String::from_utf8_lossy(&out.stdout);
    assert!(
        names.contains("Archive/f50.txt") && names.contains("Archive/f51.txt") && !names.contains("f52"),
        "{names}"
    );
    // Refused: without token, empty selection, name containing a path, traversal, destination outside the root.
    assert_eq!(
        call(app, "POST", "/web/bulk", &c, "dir=Lot&op=delete&item=f50.txt")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(app, "POST", "/web/bulk", &c, &format!("csrf={csrf}&dir=Lot&op=delete"))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    for bad in [
        "dir=Lot&item=..%2F..%2Fx",
        "dir=Lot&item=Archive%2Ff50.txt",
        "dir=&item=.trash",
    ] {
        let (s, _, _) = call(app, "POST", "/web/bulk", &c, &format!("csrf={csrf}&op=delete&{bad}")).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{bad}");
    }
    let (s, _, _) = call(
        app,
        "POST",
        "/web/bulk",
        &c,
        &format!("csrf={csrf}&dir=Lot&op=move&dest=..%2Fx&item=Archive"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(d.join("Archive/f55 (2).txt").exists());
}

/// J3b exit criterion: gallery (previous / next image, keyboard-usable links), grid and icons.
#[tokio::test]
async fn gallery_grid_and_icons() {
    let e = env();
    let app = &e.app;
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let d = disk(&e).join("Photos");
    std::fs::create_dir(&d).unwrap();
    for n in ["b.png", "a.jpg", "c.webp", "notes.txt"] {
        std::fs::write(d.join(n), b"x").unwrap();
    }
    let (_, _, mid) = call(app, "GET", "/web/view/Photos/b.png", &c, "").await;
    assert!(
        mid.contains("href=\"/web/view/Photos/a.jpg\" rel=\"prev\" data-key=\"ArrowLeft\""),
        "{mid}"
    );
    // Details page: tags and sharing live in popovers opened from the toolbar.
    assert!(mid.contains("popovertarget=\"fiche-tags\"") && mid.contains("popovertarget=\"fiche-partage\""));
    assert!(mid.contains("id=\"fiche-tags\" popover") && mid.contains("id=\"fiche-partage\" popover"));
    assert!(mid.contains("href=\"/web/view/Photos/c.webp\" rel=\"next\" data-key=\"ArrowRight\""));
    let (_, _, first) = call(app, "GET", "/web/view/Photos/a.jpg", &c, "").await;
    // The sidebar stays while viewing a file, opened on its folder.
    assert!(
        first.contains("class=\"cote\"")
            && first.contains("href=\"/web/files/Photos/\" aria-current=\"page\">Photos</a>")
    );
    assert!(!first.contains("rel=\"prev\"") && first.contains("rel=\"next\""));
    let (_, _, txt) = call(app, "GET", "/web/view/Photos/notes.txt", &c, "").await;
    assert!(!txt.contains("data-gallery"));
    // Grid: thumbnails = the image itself, lazy-loaded (no thumbnail computed on the server); icons otherwise.
    let (_, h, grid) = call(app, "GET", "/web/files/Photos/?view=grid", &c, "").await;
    let set = h["set-cookie"].to_str().unwrap();
    assert!(set.starts_with("__Host-bbview=grid;"), "{set}");
    // Grid remembered: another folder without `view` stays in the grid; "List" (view=list) goes back.
    let remembered = format!("{cookie}; __Host-bbview=grid");
    let c2 = [A, ("cookie", remembered.as_str())];
    let (_, h, other) = call(app, "GET", "/web/files/", &c2, "").await;
    assert!(other.contains("class=\"grille-fichiers\"") && !h.contains_key("set-cookie"));
    let (_, h, back) = call(app, "GET", "/web/files/?view=list", &c2, "").await;
    assert!(
        back.contains("<table class=\"liste\"") && h["set-cookie"].to_str().unwrap().starts_with("__Host-bbview=list;")
    );
    assert!(grid.contains("loading=\"lazy\" decoding=\"async\" src=\"/web/raw/Photos/a.jpg?inline=1\""));
    assert!(
        grid.contains("src=\"/static/icons/g-text.svg\""),
        "grid uses the illustration set"
    );
    assert!(
        grid.contains("data-etoile aria-pressed=\"false\""),
        "favorite star in the grid"
    );
    // "Tags and sharing" button on the root (regression: /web/view/ answered 404).
    let (_, _, root) = call(app, "GET", "/web/files/", &c, "").await;
    assert!(root.contains("href=\"/web/view/\""));
    // A folder row has an empty slot instead of the preview button (not the `.vide` empty-state class).
    assert!(
        root.contains("<span class=\"sans-apercu js\" aria-hidden=\"true\"></span>")
            && !root.contains("class=\"vide js\"")
    );
    assert_eq!(status(app, "GET", "/web/view/", &c).await, StatusCode::OK);
    let (_, _, list) = call(app, "GET", "/web/files/Photos/", &c, "").await;
    assert!(list.contains("/static/icons/image.svg") && !list.contains("loading=\"lazy\""));
    assert!(
        list.contains("data-etoile aria-pressed=\"false\""),
        "favorite star in the list"
    );
    // Icons: closed list, SVG without script, cached (revalidated by ETag).
    let (s, h, svg) = call(app, "GET", "/static/icons/folder.svg", &[A], "").await;
    assert_eq!(
        (s, h["content-type"].to_str().unwrap()),
        (StatusCode::OK, "image/svg+xml")
    );
    assert!(!svg.contains("<script") && h.contains_key("etag"));
    // One icon set everywhere: the list, recents and favorites get the grid's (Tabler) shapes.
    assert_eq!(svg, call(app, "GET", "/static/icons/g-folder.svg", &[A], "").await.2);
    // Logo: served by the binary, in the header and the footer (the same mask).
    let (s, h, logo) = call(app, "GET", "/static/icons/logo.svg", &[A], "").await;
    assert_eq!(
        (s, h["content-type"].to_str().unwrap()),
        (StatusCode::OK, "image/svg+xml")
    );
    assert!(!logo.contains("<script"));
    assert_eq!(list.matches("class=\"marque\"").count(), 2, "header and footer logo");
    for n in [
        "sheet.svg",
        "doc.svg",
        "md.svg",
        "json.svg",
        "g-pdf.svg",
        "g-doc.svg",
        "g-sheet.svg",
        "g-md.svg",
        "g-json.svg",
        "g-archive.svg",
    ] {
        assert_eq!(
            status(app, "GET", &format!("/static/icons/{n}"), &[A]).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        status(app, "GET", "/static/icons/..%2Fapp.js", &[A]).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(app, "GET", "/static/icons/autre.svg", &[A]).await,
        StatusCode::NOT_FOUND
    );
}

/// Server-rendered tree (expanded down to the current folder, balanced markup), fragment loaded when a node
/// is opened, move dialog (radio buttons) and move without destination refused.
#[tokio::test]
async fn folder_tree_and_move_picker() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let root = disk(&e);
    for d in ["A/B/C", "A/D", "E <x>"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("A/f.txt"), b"x").unwrap();
    let (_, _, page) = call(app, "GET", "/web/files/A/B/", &c, "").await;
    assert!(
        page.contains("href=\"/web/files/A/B/\" aria-current=\"page\">B</a>"),
        "{page}"
    );
    for link in [
        "/web/files/A/",
        "/web/files/A/D/",
        "/web/files/A/B/C/",
        "/web/files/E%20%3Cx%3E/",
    ] {
        assert!(page.contains(&format!("href=\"{link}\"")), "{link}");
    }
    assert!(page.contains("E &#60;x&#62;") && !page.contains("E <x>"));
    assert!(!page.contains("/web/files/A/f.txt"));
    assert_eq!(page.matches("<details").count(), page.matches("</details>").count());
    assert_eq!(page.matches("<ul").count(), page.matches("</ul>").count());
    assert!(page.contains("name=\"dest\" value=\"/A/D\" form=\"selection\""));
    assert!(page.contains("name=\"dest\" value=\"/\" form=\"selection\""));
    // Fragment: direct children only.
    let (s, _, frag) = call(app, "GET", "/web/tree/A/", &c, "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(frag.contains("/web/files/A/B/") && frag.contains("/web/files/A/D/") && !frag.contains("A/B/C"));
    let (_, _, pick) = call(app, "GET", "/web/tree/A/B/C/?pick=1", &c, "").await;
    assert!(pick.contains("No subfolder") && !pick.contains("<details"));
    let (_, _, pick) = call(app, "GET", "/web/tree/A/?pick=1", &c, "").await;
    assert!(pick.contains("value=\"/A/B\"") && !pick.contains("href="));
    assert_eq!(
        status(app, "GET", "/web/tree/..%2F..%2F", &c).await,
        StatusCode::NOT_FOUND
    );
    assert!(!status(app, "GET", "/web/tree/A/f.txt/", &c).await.is_success());
    assert_ne!(status(app, "GET", "/web/tree/", &[A]).await, StatusCode::OK);
    // Move: without destination → 400 (nothing to the root by accident); "/" = root.
    let (s, _, _) = call(
        app,
        "POST",
        "/web/bulk",
        &c,
        &format!("csrf={csrf}&dir=A&op=move&item=f.txt"),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(root.join("A/f.txt").exists());
    let (_, h, _) = call(
        app,
        "POST",
        "/web/bulk",
        &c,
        &format!("csrf={csrf}&dir=A&op=move&dest=%2F&item=f.txt"),
    )
    .await;
    assert_eq!(
        h["location"].to_str().unwrap(),
        "/web/files/A/?op=move&ok=1&ko=0&to=&name=f%2Etxt"
    );
    assert!(root.join("f.txt").exists());
}

/// J4: search by name and by tag, kept up to date by the writes (WebDAV, tags, bulk trash), limited to
/// the user's space, query escaped in the page.
#[tokio::test]
async fn search_by_name_and_tag() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    let find = |q: &'static str| async move { call(app, "GET", &format!("/web/search?q={q}"), &c, "").await.2 };
    // Nothing to search: no index build.
    assert!(find("").await.contains("Search"));
    assert_eq!(e.state.registry.by_name("alpha").unwrap().index().entries(), 0);
    send(app, "MKCOL", "/web/dav/Compta", &h, b"").await;
    send(app, "PUT", "/web/dav/Compta/Facture%20EDF%202024.pdf", &h, b"x").await;
    let page = find("facture+edf").await;
    assert!(
        page.contains("<mark>Facture</mark> <mark>EDF</mark> 2024.pdf") && page.contains("href=\"/web/files/Compta/\""),
        "{page}"
    );
    // Writes after the index build: seen without a rebuild.
    send(app, "PUT", "/web/dav/Compta/Facture%20gaz.pdf", &h, b"x").await;
    assert!(find("facture").await.contains("<mark>Facture</mark> gaz.pdf"));
    let body = format!("csrf={csrf}&path=Compta%2FFacture%20gaz.pdf&op=add&tag=Imp%C3%B4ts");
    assert_eq!(call(app, "POST", "/web/tags", &c, &body).await.0, StatusCode::SEE_OTHER);
    let page = find("tag%3Aimp%C3%B4ts").await;
    assert!(page.contains("Facture gaz.pdf") && !page.contains("EDF"), "{page}");
    assert!(page.contains("href=\"/web/search?q=tag%3Aimp%C3%B4ts\""));
    let body = format!("csrf={csrf}&dir=Compta&op=delete&item=Facture%20gaz.pdf");
    call(app, "POST", "/web/bulk", &c, &body).await;
    assert!(find("tag%3Aimp%C3%B4ts").await.contains("No results for"));
    // File added outside the application: invisible (no disk watching)... until `rescan`, which renews
    // the root's ETag: the index rebuilds itself.
    std::fs::write(disk(&e).join("Compta/hors-appli.txt"), b"x").unwrap();
    assert!(find("hors-appli").await.contains("No results for"));
    let t = e.state.registry.by_name("alpha").unwrap();
    crate::fs::Root::open_dir(&disk(&e)).unwrap().rescan(None).unwrap();
    assert!(
        find("hors-appli")
            .await
            .contains("<mark>hors</mark>-<mark>appli</mark>.txt")
    );
    // Isolation: a file of another tenant is never found; hostile query escaped.
    std::fs::write(e._b_root.path().join("alice/Facture-beta.pdf"), b"x").unwrap();
    assert!(!find("facture").await.contains("beta"));
    let page = find("%3Cscript%3E").await;
    assert!(!page.contains("<script>") && page.contains("&#60;script&#62;"));
    assert!(t.index().entries() > 0);
}

/// Search: accents ignored, a folder's scope (`in`, carried by the bar of a folder's page), filter chips that add
/// or remove their filter, hostile or missing scope.
#[tokio::test]
async fn search_scope_and_filters() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    let get = |u: String| async move { call(app, "GET", &u, &c, "").await.2 };
    for d in ["Compta", "Compta/2024", "Notes"] {
        send(app, "MKCOL", &format!("/web/dav/{d}"), &h, b"").await;
    }
    send(app, "PUT", "/web/dav/Compta/2024/Imp%C3%B4ts.pdf", &h, b"x").await;
    send(app, "PUT", "/web/dav/Notes/impots.txt", &h, b"x").await;
    // The bar of a folder's page searches in it; the root's, everywhere.
    assert!(
        get("/web/files/Compta/".into())
            .await
            .contains("<input type=\"hidden\" name=\"in\" value=\"Compta\">")
    );
    assert!(!get("/web/files/".into()).await.contains("name=\"in\""));
    let page = get("/web/search?q=IMPOTS".into()).await;
    assert!(
        page.contains("<mark>Impôts</mark>.pdf") && page.contains("<mark>impots</mark>.txt"),
        "{page}"
    );
    let page = get("/web/search?q=impots&in=Compta".into()).await;
    assert!(
        page.contains("Impôts</mark>.pdf") && !page.contains("impots</mark>.txt"),
        "{page}"
    );
    assert!(page.contains("class=\"filtre-actif\"") && page.contains("href=\"/web/search?q=impots\""));
    // The chips keep the scope; a chip adds its filter, or removes it when active.
    assert!(
        page.contains("href=\"/web/search?q=impots%20type%3Apdf&#38;in=Compta\""),
        "{page}"
    );
    let page = get("/web/search?q=impots+type%3Apdf".into()).await;
    assert!(page.contains("Impôts</mark>.pdf") && !page.contains("impots</mark>.txt"));
    assert!(
        page.contains("class=\"filtre actif\" href=\"/web/search?q=impots\""),
        "{page}"
    );
    assert!(page.contains("href=\"/web/search?q=impots%20type%3Aimage\""));
    // Filter alone: listed.
    assert!(get("/web/search?q=type%3Apdf".into()).await.contains("Impôts.pdf"));
    // Missing folder: nothing, and a way out. Path escaping the space: ignored (searched everywhere).
    let page = get("/web/search?q=impots&in=Nulle".into()).await;
    assert!(page.contains("No results for") && page.contains("Search everywhere"));
    let page = get("/web/search?q=impots&in=..%2F..%2Fetc".into()).await;
    assert!(page.contains("Impôts</mark>.pdf") && !page.contains("filtre-actif"));
    let page = get("/web/search?q=x&in=%3Cscript%3E".into()).await;
    assert!(!page.contains("<script>") && page.contains("&#60;script&#62;"));
}

/// A file with no extension (`README`, `.bashrc`, `a.`) is shown and edited when its content is plain text; a binary
/// one (NUL, control character, invalid UTF-8) is neither shown as text nor editable, and a save never replaces it;
/// a file with an unknown extension stays as before; the other tenant's session edits nothing.
#[tokio::test]
async fn edit_a_text_file_without_extension() {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let d = disk(&e).join("N");
    std::fs::create_dir_all(&d).unwrap();
    let files: [(&str, &[u8]); 8] = [
        ("README", b"Bonjour \xc3\xa9t\xc3\xa9\n\tind\xc3\xa9nt\r\n"),
        (".bashrc", b"alias ll='ls -l'\n"),
        ("a.", b"x\n"),
        ("vide", b""),
        ("binaire", b"MZ\x00\x01\x02"),
        ("controle", b"texte\x1b[31m rouge"),
        ("latin1", b"caf\xe9"),
        ("notes.xyz", b"du texte\n"),
    ];
    for (n, b) in files {
        std::fs::write(d.join(n), b).unwrap();
    }
    for (n, text) in [
        ("README", true),
        (".bashrc", true),
        ("a.", true),
        ("vide", true),
        ("binaire", false),
        ("controle", false),
        ("latin1", false),
        ("notes.xyz", false),
    ] {
        let (_, _, v) = call(
            app,
            "GET",
            &format!("/web/view/N/{}", utf8_percent_encode(n, NON_ALPHANUMERIC)),
            &c,
            "",
        )
        .await;
        let edit = format!("href=\"/web/edit/N/{}\"", crate::dav::href("", Some(n), false));
        assert_eq!(v.contains(&edit), text, "{n}: edit button");
        let (s, _, _) = call(
            app,
            "GET",
            &format!("/web/edit/N/{}", utf8_percent_encode(n, NON_ALPHANUMERIC)),
            &c,
            "",
        )
        .await;
        assert_eq!(s == StatusCode::OK, text, "{n}: edit page");
    }
    let (_, _, v) = call(app, "GET", "/web/view/N/README", &c, "").await;
    assert!(v.contains("Bonjour été"), "the text shown");
    // Latin-1 ending with a cut-looking byte: read whole, so not text (the copy button marks a text shown in full).
    let (_, _, v) = call(app, "GET", "/web/view/N/latin1", &c, "").await;
    assert!(!v.contains("data-copier") && !v.contains(">caf"));
    let (_, _, v) = call(app, "GET", "/web/view/N/vide", &c, "").await;
    assert!(v.contains("data-copier=\"/web/raw/N/vide\""));
    // Save: written, line ends kept.
    let (_, _, page) = call(app, "GET", "/web/edit/N/README", &c, "").await;
    let etag = page
        .split("name=\"etag\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let body = format!(
        "csrf={csrf}&etag={etag}&text={}",
        utf8_percent_encode("Salut\r\n", NON_ALPHANUMERIC)
    );
    let (s, h, _) = call(app, "POST", "/web/edit/N/README", &c, &body).await;
    assert_eq!(
        (s, h["location"].to_str().unwrap()),
        (StatusCode::SEE_OTHER, "/web/view/N/README")
    );
    assert_eq!(std::fs::read(d.join("README")).unwrap(), b"Salut\r\n");
    // A binary file is never replaced by text, whatever is posted.
    let (s, _, _) = call(
        app,
        "POST",
        "/web/edit/N/binaire",
        &c,
        &format!("csrf={csrf}&etag=x&text=oops"),
    )
    .await;
    assert_ne!(s, StatusCode::SEE_OTHER);
    assert_eq!(std::fs::read(d.join("binaire")).unwrap(), b"MZ\x00\x01\x02");
    // Other tenant: alpha's session edits nothing there.
    let (_, h, _) = call(
        app,
        "POST",
        "/web/edit/N/README",
        &[B, ("cookie", cookie.as_str())],
        &body,
    )
    .await;
    assert_eq!(h["location"].to_str().unwrap(), "/login");
    assert_eq!(std::fs::read(d.join("README")).unwrap(), b"Salut\r\n");
}

/// No extension: no dot, a leading one only, a trailing one; anything else has one.
#[test]
fn no_extension_bounds() {
    use super::render::no_extension;
    for n in ["README", ".bashrc", "a.", ".", ""] {
        assert!(no_extension(n), "{n}");
    }
    for n in ["a.txt", ".env.local", "archive.tar.gz", "a.b"] {
        assert!(!no_extension(n), "{n}");
    }
}

/// Plain text: tab, LF, CR, FF accepted, any other control character or NUL refused, invalid UTF-8 refused, a
/// character cut at the end of a bounded read accepted.
#[test]
fn looks_text_bounds() {
    use super::render::looks_text;
    for b in [&b""[..], b"a\tb\nc\r\n\x0c", "été".as_bytes(), b"caf\xc3"] {
        assert!(looks_text(b), "{b:?}");
    }
    for b in [
        &b"\x00"[..],
        b"a\x1bb",
        b"\x7f",
        b"\x08",
        b"caf\xe9 x",
        b"\xc3\x28",
        "a\u{85}b".as_bytes(),
    ] {
        assert!(!looks_text(b), "{b:?}");
    }
}

proptest::proptest! {
    /// Any text without control characters is text; adding a NUL anywhere makes it not; cutting it anywhere keeps it.
    #[test]
    fn looks_text_holds(t in "[^\\p{Cc}]{0,40}", at in 0usize..41) {
        use super::render::looks_text;
        let b = t.as_bytes();
        proptest::prop_assert!(looks_text(b));
        let i = at.min(b.len());
        proptest::prop_assert!(looks_text(b.get(..i).unwrap()));
        let mut z = b.to_vec();
        z.insert(i, 0);
        proptest::prop_assert!(!looks_text(&z));
    }
}

/// Editing a text file from the web: through the WebDAV PUT (identity kept, ETag renewed), line ends kept, conflict
/// with a change made elsewhere (text typed kept, replace on request), Markdown preview without saving, refusals.
#[tokio::test]
async fn text_edit_save_conflict_and_limits() {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    let disk = disk(&e);
    let get = |u: &'static str| async move { call(app, "GET", u, &c, "").await };
    let etag_of = |page: &str| {
        page.split("name=\"etag\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned()
    };
    let form = |text: &str, etag: &str, extra: &str| {
        format!(
            "csrf={csrf}&etag={etag}&text={}{extra}",
            utf8_percent_encode(text, NON_ALPHANUMERIC)
        )
    };
    send(app, "MKCOL", "/web/dav/Notes", &h, b"").await;
    send(app, "PUT", "/web/dav/Notes/a.md", &h, b"# A\n").await;
    send(app, "PUT", "/web/dav/Notes/c.txt", &h, b"x\r\ny\r\n").await;
    send(app, "PUT", "/web/dav/Notes/conf.json", &h, b"{\"a\": 1}\n").await;
    let root = crate::fs::Root::open_dir(&disk).unwrap();
    let id = |p: &str| root.meta(Some(&SafePath::new(p).unwrap())).unwrap().id;
    let id_before = id("Notes/a.md");
    assert!(id_before.is_some());

    // Reading: Edit button, colouring script and language.
    let view = get("/web/view/Notes/conf.json").await.2;
    assert!(
        view.contains("href=\"/web/edit/Notes/conf.json\"")
            && view.contains("/static/text.js")
            && view.contains("data-lang=\"json\"")
    );
    assert_eq!(status(app, "GET", "/static/text.js", &[A]).await, StatusCode::OK);
    // Copy button: the raw file, for any text shown in full (Markdown: its source); icons served.
    assert!(view.contains("data-copier=\"/web/raw/Notes/conf.json\""));
    assert!(
        get("/web/view/Notes/a.md")
            .await
            .2
            .contains("data-copier=\"/web/raw/Notes/a.md\"")
    );
    for i in ["a-copy.svg", "a-check.svg"] {
        assert_eq!(
            status(app, "GET", &format!("/static/icons/{i}"), &[A]).await,
            StatusCode::OK
        );
    }

    // Save: LF kept (the browser sends CRLF), same identity, new ETag, back to the details page.
    let (s, _, page) = get("/web/edit/Notes/a.md").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains("data-lang=\"md\"") && page.contains("name=\"apercu\"") && page.contains("# A\n</textarea>"),
        "{page}"
    );
    let e1 = etag_of(&page);
    let (s, hd, _) = call(
        app,
        "POST",
        "/web/edit/Notes/a.md",
        &c,
        &form("# A\r\nété <b>\r\n", &e1, ""),
    )
    .await;
    assert_eq!(
        (s, hd.get("location").unwrap().to_str().unwrap()),
        (StatusCode::SEE_OTHER, "/web/view/Notes/a.md")
    );
    assert_eq!(
        std::fs::read_to_string(disk.join("Notes/a.md")).unwrap(),
        "# A\nété <b>\n"
    );
    assert_eq!(id("Notes/a.md"), id_before);
    let e2 = etag_of(&get("/web/edit/Notes/a.md").await.2);
    assert_ne!(e1, e2);
    // CRLF file: kept CRLF.
    let ec = etag_of(&get("/web/edit/Notes/c.txt").await.2);
    call(app, "POST", "/web/edit/Notes/c.txt", &c, &form("x\r\nz\r\n", &ec, "")).await;
    assert_eq!(std::fs::read(disk.join("Notes/c.txt")).unwrap(), b"x\r\nz\r\n");

    // Conflict: changed elsewhere (WebDAV) since opened → 409, the text typed shown again, nothing written.
    send(app, "PUT", "/web/dav/Notes/a.md", &h, b"# Ailleurs\n").await;
    let (s, _, page) = call(app, "POST", "/web/edit/Notes/a.md", &c, &form("# Mon texte\n", &e2, "")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(
        page.contains("class=\"alerte conflit\"") && page.contains("# Mon texte") && page.contains(&e2),
        "{page}"
    );
    assert_eq!(
        std::fs::read_to_string(disk.join("Notes/a.md")).unwrap(),
        "# Ailleurs\n"
    );
    // No or forged ETag: never written blindly either.
    for bad in ["", "%22%2C%20*"] {
        let (s, _, _) = call(app, "POST", "/web/edit/Notes/a.md", &c, &form("# X\n", bad, "")).await;
        assert_eq!(s, StatusCode::CONFLICT, "{bad}");
    }
    // Replace on request.
    let (s, _, _) = call(
        app,
        "POST",
        "/web/edit/Notes/a.md",
        &c,
        &form("# Mon texte\n", &e2, "&force=1"),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(
        std::fs::read_to_string(disk.join("Notes/a.md")).unwrap(),
        "# Mon texte\n"
    );

    // Markdown preview: rendered and sanitized, nothing saved.
    let (s, _, page) = call(
        app,
        "POST",
        "/web/edit/Notes/a.md",
        &c,
        &form("**gras** <script>x</script>", "0", "&apercu=1"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let pv = page.split("data-apercu").nth(1).unwrap();
    assert!(pv.contains("<strong>gras</strong>") && !pv.contains("<script>"), "{pv}");
    assert_eq!(
        std::fs::read_to_string(disk.join("Notes/a.md")).unwrap(),
        "# Mon texte\n"
    );

    // Refusals: not text, not UTF-8, too large, folder, hostile path, no CSRF, text too large.
    std::fs::write(disk.join("Notes/bin.txt"), b"\xff\xfe\x00x").unwrap();
    std::fs::write(disk.join("Notes/big.txt"), vec![b'a'; 512 * 1024 + 1]).unwrap();
    send(app, "PUT", "/web/dav/Notes/p.png", &h, b"x").await;
    root.rescan(None).unwrap();
    for (u, want) in [
        ("/web/edit/Notes/bin.txt", StatusCode::UNPROCESSABLE_ENTITY),
        ("/web/edit/Notes/big.txt", StatusCode::UNPROCESSABLE_ENTITY),
        ("/web/edit/Notes/p.png", StatusCode::UNPROCESSABLE_ENTITY),
        ("/web/edit/Notes", StatusCode::UNPROCESSABLE_ENTITY),
        ("/web/edit/../etc/passwd", StatusCode::NOT_FOUND),
        ("/web/edit/Notes/absent.txt", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(get(u).await.0, want, "{u}");
    }
    assert!(!get("/web/view/Notes/bin.txt").await.2.contains("/web/edit/"));
    for p in ["/web/view/Notes/big.txt", "/web/view/Notes/p.png"] {
        assert!(!get(p).await.2.contains("data-copier"), "{p}");
    }
    let no_csrf = format!("etag={e2}&text=x");
    assert_eq!(
        call(app, "POST", "/web/edit/Notes/a.md", &c, &no_csrf).await.0,
        StatusCode::FORBIDDEN
    );
    let huge = form(&"a".repeat(512 * 1024 + 1), &e2, "&force=1");
    assert_eq!(
        call(app, "POST", "/web/edit/Notes/a.md", &c, &huge).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // Saving onto a binary, an image or a missing file: refused, nothing written or created.
    for p in ["Notes/bin.txt", "Notes/p.png"] {
        let (s, _, _) = call(app, "POST", &format!("/web/edit/{p}"), &c, &form("x", "0", "&force=1")).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{p}");
    }
    assert_eq!(std::fs::read(disk.join("Notes/bin.txt")).unwrap(), b"\xff\xfe\x00x");
    let (s, _, _) = call(
        app,
        "POST",
        "/web/edit/Notes/absent.txt",
        &c,
        &form("x", "0", "&force=1"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(!disk.join("Notes/absent.txt").exists());
    // Without a session: to the login page.
    let (s, hd, _) = call(app, "POST", "/web/edit/Notes/a.md", &[A], &form("x", "0", "&force=1")).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(hd.get("location").unwrap().to_str().unwrap().starts_with("/login"));
    assert_eq!(
        std::fs::read_to_string(disk.join("Notes/a.md")).unwrap(),
        "# Mon texte\n"
    );
}

/// Security of text editing: CSRF on save **and** preview, paths (traversal, reserved names, symlinks out of the
/// space), HTML injected through the contents, the typed text, the name or the preview, forged ETag and encoding, body
/// limit of this route only, CSP unchanged, share link still serving the file after an edit, other tenant.
#[tokio::test]
async fn text_edit_security() {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    let disk = disk(&e);
    let enc = |t: &str| utf8_percent_encode(t, NON_ALPHANUMERIC).to_string();
    let post = |u: String, body: String| async move { call(app, "POST", &u, &c, &body).await };
    send(app, "PUT", "/web/dav/a.md", &h, b"# A\n").await;
    let etag = |page: &str| {
        page.split("name=\"etag\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned()
    };
    let e1 = etag(&call(app, "GET", "/web/edit/a.md", &c, "").await.2);

    // CSRF: missing, wrong, or from another session: neither save nor preview.
    let (other, _) = login(&e, A, "pw-alice").await;
    let other_csrf = auth::csrf_token(
        &e.state.registry.by_name("alpha").unwrap(),
        other.split_once('=').unwrap().1,
    );
    for bad in [String::new(), "csrf=x&".into(), format!("csrf={other_csrf}&")] {
        for extra in ["&force=1", "&apercu=1"] {
            let (s, _, _) = post("/web/edit/a.md".into(), format!("{bad}etag={e1}&text=pwned{extra}")).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{bad} {extra}");
        }
    }
    assert_eq!(std::fs::read(disk.join("a.md")).unwrap(), b"# A\n");

    // Paths: traversal (also encoded), reserved names, symlink to a file outside the space.
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), b"secret\n").unwrap();
    std::os::unix::fs::symlink(outside.path(), disk.join("lien.txt")).unwrap();
    std::fs::create_dir_all(disk.join(".trash")).unwrap();
    for p in [
        "../alice/a.md",
        "%2e%2e/a.md",
        "a.md/..",
        ".trash/x",
        ".beastbox-tmp/x",
        ".beastbox-manifest",
        "lien.txt",
        "/etc/passwd",
    ] {
        let (s, _, page) = call(app, "GET", &format!("/web/edit/{p}"), &c, "").await;
        assert!(matches!(s.as_u16(), 404 | 422), "{p}: {s}");
        assert!(!page.contains("secret"), "{p}");
        let (s, _, _) = post(
            format!("/web/edit/{p}"),
            format!("csrf={csrf}&etag=0&text=pwned&force=1"),
        )
        .await;
        assert!(matches!(s.as_u16(), 404 | 409 | 422), "{p}: {s}");
    }
    assert_eq!(std::fs::read(outside.path()).unwrap(), b"secret\n");
    assert!(
        std::fs::symlink_metadata(disk.join("lien.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // HTML in the contents, the typed text (conflict page) and the name: escaped; preview sanitized.
    let evil = "</textarea><script>alert(1)</script><img src=x onerror=alert(2)>";
    send(app, "PUT", "/web/dav/x.md", &h, evil.as_bytes()).await;
    let name = "%3Cimg%20src%3Dx%20onerror%3Dalert(3)%3E.txt";
    send(app, "PUT", &format!("/web/dav/{name}"), &h, b"t\n").await;
    let page = call(app, "GET", "/web/edit/x.md", &c, "").await.2;
    assert!(
        !page.contains("<script>alert") && !page.contains("<img src=x") && page.contains("&#60;/textarea&#62;"),
        "{page}"
    );
    let page = call(app, "GET", &format!("/web/edit/{name}"), &c, "").await.2;
    assert!(!page.contains("<img src=x onerror=alert(3)>") && page.contains("&#60;img"));
    let page = call(app, "GET", &format!("/web/view/{name}"), &c, "").await.2;
    assert!(page.contains("data-copier") && !page.contains("<img src=x onerror=alert(3)>"));
    let (s, _, page) = post(
        "/web/edit/x.md".into(),
        format!("csrf={csrf}&etag=0&text={}", enc(evil)),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(!page.contains("<script>alert") && !page.contains("</textarea><script>"));
    let md = "[a](javascript:alert(1)) <iframe src=x></iframe> ![i](https://evil.example/p.png) <a href=\"x\" onclick=\"y\">b</a>";
    let page = post(
        "/web/edit/x.md".into(),
        format!("csrf={csrf}&etag=0&text={}&apercu=1", enc(md)),
    )
    .await
    .2;
    let pv = page
        .split("data-apercu")
        .nth(1)
        .unwrap()
        .split("</section>")
        .next()
        .unwrap();
    // Raw HTML is shown as text (escaped), never as an element or attribute.
    for bad in ["javascript:", "<iframe", "<img", "<a href=\"x\" onclick"] {
        assert!(!pv.contains(bad), "{bad}: {pv}");
    }

    // Forged ETag (header injection attempt) or invalid UTF-8: refused cleanly, nothing written.
    for (etag, text) in [
        ("%0d%0aX-Evil%3a%201", "y"),
        ("*", "y"),
        ("%22*%22", "y"),
        (e1.as_str(), "%FF%FE"),
    ] {
        let (s, _, _) = post("/web/edit/a.md".into(), format!("csrf={csrf}&etag={etag}&text={text}")).await;
        assert!(matches!(s.as_u16(), 400 | 409), "{etag} {text}: {s}");
    }
    assert_eq!(std::fs::read(disk.join("a.md")).unwrap(), b"# A\n");

    // Larger body allowed on this route only; beyond it, refused before reading.
    let big = "x".repeat(100 * 1024);
    assert_eq!(
        post("/web/tags".into(), format!("csrf={csrf}&path=a.md&op=add&tag={big}"))
            .await
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let over = "%41".repeat(super::EDIT_BODY / 3 + 10);
    assert_eq!(
        post("/web/edit/a.md".into(), format!("csrf={csrf}&etag={e1}&text={over}"))
            .await
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    // Without a session, a large body is not even read: the login page, not "too large".
    let (s, hd, _) = call(app, "POST", "/web/edit/a.md", &[A], &"x".repeat(2 * super::EDIT_BODY)).await;
    assert!(
        s == StatusCode::SEE_OTHER && hd["location"].to_str().unwrap().starts_with("/login"),
        "{s}"
    );

    // CSP unchanged on the edit page; the script served is the closed-list one.
    let (_, hd, _) = call(app, "GET", "/web/edit/a.md", &c, "").await;
    let csp = hd["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("script-src 'self'") && !csp.contains("unsafe"), "{csp}");

    // A share link follows the file through an edit (same identity) and serves the new contents.
    let tok = make_share(&e, &cookie, &csrf, "a.md", "&perms=read").await;
    let (s, _, _) = post(
        "/web/edit/a.md".into(),
        format!("csrf={csrf}&etag={e1}&text=%23%20B%0A"),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (s, _, body) = call(app, "GET", &format!("/s/{tok}/dl"), &[A], "").await;
    assert!(s == StatusCode::OK && body.contains("# B"), "{s} {body}");
    // The guest of the link has no edit page.
    assert_eq!(
        call(app, "GET", "/web/edit/a.md", &[A], "").await.0,
        StatusCode::SEE_OTHER
    );

    // Other tenant: its session does not open this tenant's file, even with the same user name.
    let (bc, bcsrf) = login(&e, B, "pw-alice").await;
    let bh = [B, ("cookie", bc.as_str())];
    let (s, _, _) = call(
        app,
        "POST",
        "/web/edit/a.md",
        &bh,
        &format!("csrf={bcsrf}&etag=0&text=x&force=1"),
    )
    .await;
    assert_ne!(s, StatusCode::SEE_OTHER);
    let ah = [A, ("cookie", bc.as_str())];
    let (s, hd, _) = call(
        app,
        "POST",
        "/web/edit/a.md",
        &ah,
        &format!("csrf={bcsrf}&etag=0&text=x&force=1"),
    )
    .await;
    assert!(s == StatusCode::SEE_OTHER && hd["location"].to_str().unwrap().starts_with("/login"));
    assert_eq!(std::fs::read_to_string(disk.join("a.md")).unwrap(), "# B\n");
}

/// "+ New" → text file: created empty by the server (text name only, never over an existing item), then its editor.
#[tokio::test]
async fn text_file_create() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    let disk = disk(&e);
    send(app, "MKCOL", "/web/dav/Notes", &h, b"").await;
    // The menu on a folder's page.
    let page = call(app, "GET", "/web/files/Notes/", &c, "").await.2;
    assert!(
        page.contains("popovertarget=\"menu-nouveau\"")
            && page.contains("data-action=\"mkfile\"")
            && page.contains("data-action=\"mkdir\"")
    );
    let create = |p: &'static str| {
        let body = format!("csrf={csrf}&create=1");
        async move { call(app, "POST", &format!("/web/edit/{p}"), &c, &body).await }
    };
    // Created empty, identity given, editor opened; seen by search and WebDAV.
    let (s, hd, _) = create("Notes/id%C3%A9es.md").await;
    assert_eq!(
        (s, hd["location"].to_str().unwrap()),
        (StatusCode::SEE_OTHER, "/web/edit/Notes/id%C3%A9es.md")
    );
    assert_eq!(std::fs::read(disk.join("Notes/idées.md")).unwrap(), b"");
    let root = crate::fs::Root::open_dir(&disk).unwrap();
    assert!(
        root.meta(Some(&SafePath::new("Notes/idées.md").unwrap()))
            .unwrap()
            .id
            .is_some()
    );
    assert_eq!(
        call(app, "GET", "/web/edit/Notes/id%C3%A9es.md", &c, "").await.0,
        StatusCode::OK
    );
    assert!(
        call(app, "GET", "/web/search?q=idees", &c, "")
            .await
            .2
            .contains("<mark>idées</mark>.md")
    );
    // Never over an existing file (contents kept) or folder.
    send(app, "PUT", "/web/dav/Notes/a.txt", &h, b"garde\n").await;
    for p in ["Notes/a.txt", "Notes"] {
        let (s, _, page) = create(p).await;
        assert!(
            s == StatusCode::CONFLICT || (p == "Notes" && s == StatusCode::UNPROCESSABLE_ENTITY),
            "{p}: {s} {page}"
        );
    }
    assert_eq!(std::fs::read(disk.join("Notes/a.txt")).unwrap(), b"garde\n");
    // Not a text name, missing folder, hostile path, no CSRF: nothing created.
    for (p, want) in [
        ("Notes/x.docx", StatusCode::UNPROCESSABLE_ENTITY),
        ("Notes/x.svg", StatusCode::UNPROCESSABLE_ENTITY),
        ("Notes/sans-extension", StatusCode::UNPROCESSABLE_ENTITY),
        ("Absent/x.txt", StatusCode::CONFLICT),
        ("../x.txt", StatusCode::NOT_FOUND),
        (".trash/x.txt", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(create(p).await.0, want, "{p}");
    }
    assert!(!disk.join("Notes/x.docx").exists() && !disk.join("Absent").exists());
    let (s, _, _) = call(app, "POST", "/web/edit/Notes/b.txt", &c, "create=1").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(!disk.join("Notes/b.txt").exists());
    // Symlink with that name (to a file outside the space): not followed, not replaced.
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), b"secret\n").unwrap();
    std::os::unix::fs::symlink(outside.path(), disk.join("Notes/lien.txt")).unwrap();
    assert_ne!(create("Notes/lien.txt").await.0, StatusCode::SEE_OTHER);
    assert!(
        std::fs::symlink_metadata(disk.join("Notes/lien.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(outside.path()).unwrap(), b"secret\n");
    // Hostile name: escaped in the refusal page.
    let (_, _, page) = create("Notes/%3Cscript%3Ex.docx").await;
    assert!(!page.contains("<script>"));
}

/// "Recent activity": an uploaded file is listed even when it keeps an old date of its own (`X-OC-Mtime`, as the web
/// upload and the clients send it), shown as just arrived; its modification date stays the original one.
#[tokio::test]
async fn upload_with_old_date_is_recent_activity() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    // More recent files than the box shows, modified now.
    for i in 0..10 {
        send(app, "PUT", &format!("/web/dav/note{i}.txt"), &h, b"x").await;
    }
    // One second later: a photo taken in 2001, uploaded now.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let old = [
        A,
        ("cookie", cookie.as_str()),
        ("x-csrf-token", csrf.as_str()),
        ("x-oc-mtime", "1000000000"),
    ];
    send(app, "PUT", "/web/dav/photo-2001.jpg", &old, b"jpeg").await;
    let frag = call(app, "GET", "/web/activity", &c, "").await.2;
    let first = frag.split("<li>").nth(1).unwrap();
    assert!(first.contains("photo-2001.jpg") && first.contains("just now"), "{frag}");
    // Its own date is kept (details page, WebDAV "Recent" by modification date).
    let page = call(app, "GET", "/web/view/photo-2001.jpg", &c, "").await.2;
    assert!(page.contains("2001-09-"), "{page}");
    assert!(!frag.contains("Recently deleted"));

    // Deleted items: the latest ones (at most 4), where they were, when; a link to the trash; hostile name escaped.
    send(app, "MKCOL", "/web/dav/Compta", &h, b"").await;
    send(app, "PUT", "/web/dav/Compta/%3Cb%3Efacture.pdf", &h, b"x").await;
    send(app, "DELETE", "/web/dav/Compta/%3Cb%3Efacture.pdf", &h, b"").await;
    for i in 0..5 {
        send(app, "DELETE", &format!("/web/dav/note{i}.txt"), &h, b"").await;
    }
    let frag = call(app, "GET", "/web/activity", &c, "").await.2;
    let del = frag.split("Recently deleted").nth(1).unwrap();
    assert_eq!(del.matches("<li>").count(), 4, "{del}");
    // Where it was: a link to that folder (the item is no longer there: no `voir`).
    assert!(
        del.contains("<span class=\"meta\"><a href=\"/web/files/\">My files</a>, just now"),
        "{del}"
    );
    assert!(
        del.contains("href=\"/web/trash\"")
            && del.contains("just now")
            && !frag.contains("<a class=\"nom\" href=\"/web/view/note0.txt\">")
    );
    // Gone from "Recent files" once deleted; permanently deleted: gone from both.
    let recents = frag.split("Recently deleted").next().unwrap();
    assert!(!recents.contains("note0.txt"));
    let frag = call(app, "POST", "/web/trash/empty", &c, &format!("csrf={csrf}&confirm=1")).await;
    assert!(frag.0.is_redirection() || frag.0.is_success(), "{}", frag.0);
    let frag = call(app, "GET", "/web/activity", &c, "").await.2;
    assert!(!frag.contains("Recently deleted"), "{frag}");
    // Escaping (deleted again after emptying).
    send(app, "PUT", "/web/dav/%3Cb%3Ex.txt", &h, b"x").await;
    send(app, "DELETE", "/web/dav/%3Cb%3Ex.txt", &h, b"").await;
    let frag = call(app, "GET", "/web/activity", &c, "").await.2;
    assert!(frag.contains("&#60;b&#62;x.txt") && !frag.contains("<b>x.txt"));
}

/// Renaming from the edit page: contents saved first, then a MOVE in the same folder (identity, tags kept; a share
/// link ends, as for any rename). Name refused → nothing saved; name taken → saved, not renamed; conflict → neither.
#[tokio::test]
async fn text_edit_rename() {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    let disk = disk(&e);
    let enc = |t: &str| utf8_percent_encode(t, NON_ALPHANUMERIC).to_string();
    send(app, "MKCOL", "/web/dav/Notes", &h, b"").await;
    send(app, "PUT", "/web/dav/Notes/a.md", &h, b"# A\n").await;
    send(app, "PUT", "/web/dav/Notes/pris.md", &h, b"autre\n").await;
    let body = format!("csrf={csrf}&path=Notes%2Fa.md&op=add&tag=projet");
    call(app, "POST", "/web/tags", &c, &body).await;
    let tok = make_share(&e, &cookie, &csrf, "Notes%2Fa.md", "&perms=read").await;
    let root = crate::fs::Root::open_dir(&disk).unwrap();
    let meta = |p: &str| root.meta(Some(&SafePath::new(p).unwrap()));
    let id = meta("Notes/a.md").unwrap().id;
    let page_of = |p: &'static str| async move { call(app, "GET", p, &c, "").await.2 };
    let etag = |page: &str| {
        page.split("name=\"etag\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned()
    };
    let save = |p: &'static str, etag: String, name: &str, text: &str| {
        let body = format!("csrf={csrf}&etag={etag}&name={}&text={}", enc(name), enc(text));
        async move { call(app, "POST", p, &c, &body).await }
    };

    // The page: name field, link warning, icon/colouring map (one source: the server's functions).
    let page = page_of("/web/edit/Notes/a.md").await;
    assert!(
        page.contains("name=\"name\"") && page.contains("value=\"a.md\"") && page.contains("renaming it ends the link")
    );
    assert!(
        page.contains("&#34;md&#34;:[&#34;md&#34;,&#34;md&#34;]") && page.contains("data-icone-nom"),
        "{page}"
    );

    // Name refused: nothing saved, typed text and name kept.
    let e1 = etag(&page);
    for (bad, why) in [
        ("a.docx", "Keep the name of a text file"),
        ("x/a.md", "without “/”"),
        ("../a.md", "without “/”"),
        ("", "without “/”"),
        ("..", "Keep the name of a text file"),
        (".trash", "Keep the name of a text file"),
    ] {
        let (s, _, p) = save("/web/edit/Notes/a.md", e1.clone(), bad, "# Tapé\n").await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
        assert!(p.contains(why) && p.contains("# Tapé"), "{bad}: {p}");
    }
    for bad in ["a\u{1}.md".to_owned(), format!("{}.md", "x".repeat(300))] {
        let (s, _, p) = save("/web/edit/Notes/a.md", e1.clone(), &bad, "# Tapé\n").await;
        assert!(
            s == StatusCode::UNPROCESSABLE_ENTITY && p.contains("This name is not allowed"),
            "{s}"
        );
    }
    assert_eq!(std::fs::read(disk.join("Notes/a.md")).unwrap(), b"# A\n");
    // Hostile name: refused by the text rule, escaped in the field.
    let (_, _, p) = save("/web/edit/Notes/a.md", e1.clone(), "<img src=x onerror=1>", "x").await;
    assert!(!p.contains("<img src=x") && p.contains("&#60;img"));

    // Name taken: contents saved, not renamed, the name typed kept; the other file untouched.
    let (s, _, p) = save("/web/edit/Notes/a.md", e1.clone(), "pris.md", "# B\n").await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(
        p.contains("Saved, but not renamed") && p.contains("value=\"pris.md\""),
        "{p}"
    );
    assert_eq!(std::fs::read(disk.join("Notes/a.md")).unwrap(), b"# B\n");
    assert_eq!(std::fs::read(disk.join("Notes/pris.md")).unwrap(), b"autre\n");

    // Conflict (changed elsewhere) with a new name: neither saved nor renamed.
    send(app, "PUT", "/web/dav/Notes/a.md", &h, b"# Ailleurs\n").await;
    let (s, _, _) = save("/web/edit/Notes/a.md", e1, "nouveau.md", "# C\n").await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(meta("Notes/nouveau.md").is_err());
    assert_eq!(std::fs::read(disk.join("Notes/a.md")).unwrap(), b"# Ailleurs\n");

    // Same name (spaces around ignored): a plain save.
    let e2 = etag(&page_of("/web/edit/Notes/a.md").await);
    let (s, hd, _) = save("/web/edit/Notes/a.md", e2, "  a.md ", "# D\n").await;
    assert_eq!(
        (s, hd["location"].to_str().unwrap()),
        (StatusCode::SEE_OTHER, "/web/view/Notes/a.md")
    );

    // Rename: saved, moved, same identity and tags, the link ends; WebDAV sees the new name only.
    let e3 = etag(&page_of("/web/edit/Notes/a.md").await);
    let (s, hd, _) = save("/web/edit/Notes/a.md", e3, "Idées été.md", "# E\n").await;
    assert_eq!(
        (s, hd["location"].to_str().unwrap()),
        (StatusCode::SEE_OTHER, "/web/view/Notes/Id%C3%A9es%20%C3%A9t%C3%A9.md")
    );
    assert_eq!(std::fs::read(disk.join("Notes/Idées été.md")).unwrap(), b"# E\n");
    assert!(!disk.join("Notes/a.md").exists());
    assert_eq!(meta("Notes/Idées été.md").unwrap().id, id);
    assert!(
        page_of("/web/view/Notes/Id%C3%A9es%20%C3%A9t%C3%A9.md")
            .await
            .contains("projet")
    );
    assert_eq!(
        status(app, "GET", &format!("/s/{tok}"), &[A]).await,
        StatusCode::NOT_FOUND
    );

    // No CSRF: neither.
    let (s, _, _) = call(
        app,
        "POST",
        "/web/edit/Notes/pris.md",
        &c,
        "etag=0&name=z.md&text=x&force=1",
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(meta("Notes/z.md").is_err());
}

/// Read-only server or space reserve reached: nothing saved, a clear page.
#[tokio::test]
async fn text_edit_read_only() {
    for settings in [
        crate::http::Settings {
            read_only: true,
            ..Default::default()
        },
        crate::http::Settings {
            min_free_bytes: u64::MAX,
            ..Default::default()
        },
    ] {
        let e = crate::http::tests::env_with(settings);
        let app = &e.app;
        let (cookie, csrf) = login(&e, A, "pw-alice").await;
        let c = [A, ("cookie", cookie.as_str())];
        std::fs::write(disk(&e).join("a.txt"), b"x\n").unwrap();
        crate::fs::Root::open_dir(&disk(&e)).unwrap().rescan(None).unwrap();
        let (s, _, page) = call(
            app,
            "POST",
            "/web/edit/a.txt",
            &c,
            &format!("csrf={csrf}&etag=0&text=y&force=1"),
        )
        .await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{page}");
        assert!(page.contains("read-only"));
        assert_eq!(std::fs::read(disk(&e).join("a.txt")).unwrap(), b"x\n");
    }
}

/// J4: web trash. A deleted item is listed, its share link answers 404, then the restore puts it back in
/// its place with its identity, its tags and its link; search finds it again. Confirmed permanent delete.
#[tokio::test]
async fn trash_restore_from_web() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    send(app, "MKCOL", "/web/dav/Docs", &h, b"").await;
    send(app, "PUT", "/web/dav/Docs/contrat.pdf", &h, b"PDF").await;
    let body = format!("csrf={csrf}&path=Docs%2Fcontrat.pdf&op=add&tag=important");
    call(app, "POST", "/web/tags", &c, &body).await;
    let tok = make_share(&e, &cookie, &csrf, "Docs/contrat.pdf", "&perms=read").await;
    assert_eq!(status(app, "GET", &format!("/s/{tok}/dl"), &[A]).await, StatusCode::OK);
    assert!(
        call(app, "GET", "/web/search?q=contrat", &c, "")
            .await
            .2
            .contains("contrat.pdf")
    );
    // Delete (trash), then the parent folder deleted too: the restore will have to re-create it.
    send(app, "DELETE", "/web/dav/Docs/contrat.pdf", &h, b"").await;
    send(app, "DELETE", "/web/dav/Docs", &h, b"").await;
    assert_eq!(
        status(app, "GET", &format!("/s/{tok}/dl"), &[A]).await,
        StatusCode::NOT_FOUND
    );
    assert!(
        call(app, "GET", "/web/search?q=contrat", &c, "")
            .await
            .2
            .contains("No results for")
    );
    let (s, _, page) = call(app, "GET", "/web/trash", &c, "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains("contrat.pdf") && page.contains("<a href=\"/web/files/Docs/\" title=\"Docs\">Docs</a>"),
        "{page}"
    );
    let slot = |page: &str, name: &str| -> String {
        let i = page.find(&format!(">{name}<")).unwrap();
        let rest = &page[i..];
        let j = rest.find("name=\"slot\" value=\"").unwrap() + 19;
        rest[j..j + 32].to_owned()
    };
    let s1 = slot(&page, "contrat.pdf");
    let (s, hd, _) = call(app, "POST", "/web/trash/restore", &c, &format!("csrf={csrf}&slot={s1}")).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(
        hd["location"]
            .to_str()
            .unwrap()
            .starts_with("/web/trash?ok=restored&to=")
    );
    assert_eq!(std::fs::read(disk(&e).join("Docs/contrat.pdf")).unwrap(), b"PDF");
    assert_eq!(
        status(app, "GET", &format!("/s/{tok}/dl"), &[A]).await,
        StatusCode::OK,
        "link recovered"
    );
    let found = call(app, "GET", "/web/search?q=tag%3Aimportant", &c, "").await.2;
    assert!(found.contains("contrat.pdf"), "tags et index : {found}");
    // Already restored: "no longer in the trash". Without CSRF token: refused. Hostile slot: nothing.
    let (_, hd, _) = call(app, "POST", "/web/trash/restore", &c, &format!("csrf={csrf}&slot={s1}")).await;
    assert_eq!(hd["location"], "/web/trash?ok=gone");
    let s2 = slot(&call(app, "GET", "/web/trash", &c, "").await.2, "Docs");
    assert_eq!(
        call(app, "POST", "/web/trash/purge", &c, &format!("slot={s2}&confirm=1"))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (_, hd, _) = call(
        app,
        "POST",
        "/web/trash/purge",
        &c,
        &format!("csrf={csrf}&slot=..%2F..&confirm=1"),
    )
    .await;
    assert_eq!(hd["location"], "/web/trash?ok=gone");
    // Permanent delete: confirmation required.
    let (s, _, _) = call(app, "POST", "/web/trash/purge", &c, &format!("csrf={csrf}&slot={s2}")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (_, hd, _) = call(
        app,
        "POST",
        "/web/trash/purge",
        &c,
        &format!("csrf={csrf}&slot={s2}&confirm=1"),
    )
    .await;
    assert_eq!(hd["location"], "/web/trash?ok=purged");
    send(app, "DELETE", "/web/dav/Docs/contrat.pdf", &h, b"").await;
    assert_eq!(
        call(app, "POST", "/web/trash/empty", &c, &format!("csrf={csrf}"))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (_, hd, _) = call(app, "POST", "/web/trash/empty", &c, &format!("csrf={csrf}&confirm=1")).await;
    assert_eq!(hd["location"], "/web/trash?ok=emptied");
    assert!(
        call(app, "GET", "/web/trash", &c, "")
            .await
            .2
            .contains("The trash is empty.")
    );
    assert_eq!(std::fs::read_dir(disk(&e).join(".trash")).unwrap().count(), 0);
}

/// Sidebar: My files, Favorites (favorite folders as an accordion), Shared links, Trash, on every listing
/// page; Favorites page: folders first, then files.
#[tokio::test]
async fn favorites_and_sidebar() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    for d in ["/web/dav/Projets", "/web/dav/Projets/Zeta", "/web/dav/Autre"] {
        send(app, "MKCOL", d, &h, b"").await;
    }
    send(app, "PUT", "/web/dav/Projets/aaa-plan.pdf", &h, b"x").await;
    let (_, _, page) = call(app, "GET", "/web/favorites", &c, "").await;
    assert!(page.contains("Nothing starred yet.") && page.contains("No starred folder"));
    for p in ["Projets%2FZeta", "Projets%2Faaa-plan.pdf"] {
        let (s, _, _) = call(app, "POST", "/web/favorite", &c, &format!("csrf={csrf}&path={p}&on=1")).await;
        assert_eq!(s, StatusCode::SEE_OTHER);
    }
    let (_, _, page) = call(app, "GET", "/web/favorites", &c, "").await;
    let (dir, file) = (page.find(">Zeta</a>").unwrap(), page.find(">aaa-plan.pdf</a>").unwrap());
    assert!(
        dir < file,
        "folders before files (even if \"aaa\" comes before \"Zeta\")"
    );
    assert!(page.contains("<table class=\"liste\" data-contenu>"));
    assert_eq!(
        page.matches("data-etoile aria-pressed=\"true\"").count(),
        2,
        "star on every favorite"
    );
    // "From": the folder, at the favorite's place (page holding it, marked, scrolled to).
    assert!(page.contains(
        "<span class=\"lieu\">From: <a href=\"/web/files/Projets/?voir=Zeta#vise\" title=\"Projets\">Projets</a>"
    ));
    assert!(page.contains("<a href=\"/web/files/Projets/?voir=aaa%2Dplan%2Epdf#vise\" title=\"Projets\">Projets</a>"));
    assert!(page.contains("href=\"/web/favorites\" aria-current=\"page\">Starred</a>"));
    // Sortable like a folder: by descending size, the biggest file first (folders always on top).
    send(app, "PUT", "/web/dav/Autre/zzz-gros.bin", &h, &[0u8; 64]).await;
    let (s, _, _) = call(
        app,
        "POST",
        "/web/favorite",
        &c,
        &format!("csrf={csrf}&path=Autre%2Fzzz-gros.bin&on=1"),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_, _, p) = call(app, "GET", "/web/favorites?sort=size&desc=1", &c, "").await;
    let at = |n: &str| p.find(&format!(">{n}</a>")).unwrap();
    assert!(
        at("Zeta") < at("zzz-gros.bin") && at("zzz-gros.bin") < at("aaa-plan.pdf"),
        "{p}"
    );
    assert!(p.contains("aria-sort=\"descending\"") && p.contains("href=\"?sort=size&#38;desc=0\""));
    let (_, _, p) = call(app, "GET", "/web/favorites?sort=name&desc=1", &c, "").await;
    assert!(p.find(">zzz-gros.bin</a>").unwrap() < p.find(">aaa-plan.pdf</a>").unwrap());
    call(
        app,
        "POST",
        "/web/favorite",
        &c,
        &format!("csrf={csrf}&path=Autre%2Fzzz-gros.bin&on=0"),
    )
    .await;
    // Favorite folder in the sidebar, expandable (fragment of its subfolders).
    assert!(page.contains("data-src=\"/web/tree/Projets/Zeta/\""));
    // Sidebar on the other pages, current section marked; balanced markup.
    for (url, active) in [
        ("/web/trash", "/web/trash"),
        ("/web/shares", "/web/shares"),
        ("/web/files/Projets/", "/web/files/Projets/"),
    ] {
        let (_, _, p) = call(app, "GET", url, &c, "").await;
        assert!(p.contains(&format!("href=\"{active}\" aria-current=\"page\"")), "{url}");
        assert!(p.contains(">Starred</a>") && p.contains(">Trash</a>") && p.contains("/web/tree/Projets/Zeta/"));
        assert_eq!(p.matches("<details").count(), p.matches("</details>").count(), "{url}");
        assert_eq!(p.matches("<ul").count(), p.matches("</ul>").count(), "{url}");
    }
    // Removed from favorites: disappears.
    call(
        app,
        "POST",
        "/web/favorite",
        &c,
        &format!("csrf={csrf}&path=Projets%2FZeta&on=0"),
    )
    .await;
    assert!(!call(app, "GET", "/web/favorites", &c, "").await.2.contains("Zeta"));
}

/// Public link history and "Recent activity" box: every guest action (refused password,
/// download, archive, drop) shows up for the owner, grouped; filter by link, survival after revocation,
/// pagination, hostile parameter ignored; nothing of one tenant shows up in the other.
#[tokio::test]
async fn share_history_and_recent_activity() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    let sp = |s: &str| SafePath::new(s).unwrap();
    root.mkdir(&sp("Factures")).unwrap();
    root.mkdir(&sp("Boite")).unwrap();
    for f in ["Factures/facture-01.pdf", "Factures/facture-02.pdf"] {
        root.atomic_write(&sp(f), &mut &b"%PDF"[..]).unwrap();
    }
    // `make_share` returns the page's first link: with two links, we find them by their target.
    make_share(&e, &cookie, &csrf, "Factures", "&perms=read&password=motdepasse1").await;
    make_share(&e, &cookie, &csrf, "Boite", "&perms=drop").await;
    let id_of = |target: &str| {
        e.state
            .db
            .share_list(&t, "alice")
            .unwrap()
            .into_iter()
            .find(|s| s.path_hint == target)
            .unwrap()
            .share_id
    };
    let (read_id, drop_id) = (id_of("Factures"), id_of("Boite"));
    let (read, drop) = (auth::share_token(&t, &read_id), auth::share_token(&t, &drop_id));

    // Before any activity: box with no links, but recent files.
    let (s, _, frag) = call(app, "GET", "/web/activity", &c, "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(frag.contains("Recent files") && frag.contains("facture-02.pdf") && !frag.contains("Your shared links"));

    // The guest: two wrong passwords, the right one, two downloads of the same file, an archive, two drops.
    let link = format!("/s/{read}");
    for _ in 0..2 {
        call(app, "POST", &link, &[A], "password=faux").await;
    }
    let (_, h, _) = call(app, "POST", &link, &[A], "password=motdepasse1").await;
    let pass = h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
    let g = [A, ("cookie", pass.as_str())];
    for _ in 0..2 {
        assert_eq!(
            status(app, "GET", &format!("{link}/dl/facture-01.pdf"), &g).await,
            StatusCode::OK
        );
    }
    assert_eq!(status(app, "GET", &format!("{link}/zip"), &g).await, StatusCode::OK);
    for (n, body) in [("scan.pdf", &b"0123456789"[..]), ("photo.jpg", &b"01234"[..])] {
        let len = body.len().to_string();
        let r = send(
            app,
            "PUT",
            &format!("/s/{drop}/drop/{n}"),
            &[A, ("content-length", len.as_str())],
            body,
        )
        .await;
        assert_eq!(r.0, StatusCode::CREATED);
    }

    // For the owner: grouped, newest to oldest, no IP.
    let (_, _, page) = call(app, "GET", "/web/shares", &c, "").await;
    let hist = &page[page.find("id=\"historique\"").unwrap()..];
    assert!(hist.contains("<h3>Today</h3>"), "{hist}");
    for want in [
        "<a href=\"/web/view/Boite/scan.pdf\"><strong>scan.pdf</strong></a> and 1 other file uploaded (15 B)",
        "into “<a href=\"/web/files/Boite/?voir=scan%2Epdf#vise\">Boite</a>”",
        "<a href=\"/web/files/Factures/\"><strong>Factures</strong></a> downloaded as a ZIP archive",
        "<a href=\"/web/view/Factures/facture-01.pdf\"><strong>facture-01.pdf</strong></a> downloaded (2 times)",
        "via “<a href=\"/web/files/Factures/?voir=facture%2D01%2Epdf#vise\">Factures</a>”",
        "Access refused: wrong password (2 times)",
    ] {
        assert!(hist.contains(want), "{want} absent : {hist}");
    }
    let pos = |s: &str| hist.find(s).unwrap();
    assert!(pos("scan.pdf") < pos("ZIP archive") && pos("ZIP archive") < pos("facture-01.pdf"));
    assert!(pos("facture-01.pdf") < pos("Access refused"));
    assert!(!hist.contains("127.0.0.1") && !hist.contains("192.0.2."));
    assert!(page.contains(&format!("/web/shares?lien={read_id}#historique")));
    // One row per link: folder icon, copy button tied to the bubble that shows the URL; no link selector.
    let row = &page[page.find(&format!("data-url=\"url-{drop_id}\"")).expect("copy button")..];
    assert!(
        row.contains(&format!("popovertarget=\"url-{drop_id}\""))
            && row.contains(&format!("id=\"url-{drop_id}\" popover"))
    );
    assert!(row.contains(&format!("/s/{drop}\"")), "the URL is in the bubble");
    assert!(page.contains("/static/icons/folder.svg") && !page.contains("<select id=\"lien\""));

    // Filter by link; hostile parameter ignored (the whole history, nothing echoed).
    let (_, _, only) = call(app, "GET", &format!("/web/shares?lien={drop_id}"), &c, "").await;
    let only = &only[only.find("id=\"historique\"").unwrap()..];
    assert!(only.contains("scan.pdf") && !only.contains("facture-01.pdf"));
    assert!(only.contains("Link: <strong>Boite</strong>"), "filter chip");
    let (_, _, bad) = call(app, "GET", "/web/shares?lien=%3Cscript%3Ex", &c, "").await;
    assert!(bad.contains("facture-01.pdf") && !bad.contains("<script>x"));

    // The "Recent activity" box: dropped files on top, latest events.
    let (_, _, frag) = call(app, "GET", "/web/activity", &c, "").await;
    assert!(frag.contains("Your shared links") && frag.contains("/web/shares#historique"));
    let recents = &frag[..frag.find("Your shared links").unwrap()];
    // A card: the file's link (covering the card), and its folder's, opened at the file; never a link in a link.
    assert!(
        recents.contains("<a class=\"nom\" href=\"/web/view/Boite/photo.jpg\">photo.jpg</a>")
            && recents
                .contains("<a href=\"/web/files/Boite/?voir=photo%2Ejpg#vise\" title=\"Boite\">Boite</a>, just now"),
        "{recents}"
    );
    // No nesting: between two closings, at most one opening.
    assert!(
        recents.split("</a>").all(|seg| seg.matches("<a ").count() <= 1),
        "{recents}"
    );
    assert!(
        !recents.contains("<a href=\"/web/view/Boite/photo.jpg\"><img"),
        "the card itself is no longer a link"
    );
    assert_eq!(frag.matches("<li><span class=\"ico").count(), 4);
    // Same links as the history: the dropped file, and the folder it went into.
    assert!(
        frag.contains("<a href=\"/web/view/Boite/scan.pdf\">")
            && frag.contains("“<a href=\"/web/files/Boite/?voir=scan%2Epdf#vise\">Boite</a>”")
    );
    // The file gone: its name stays, no longer a link (never to a stale place); the folder still is one.
    root.trash(&sp("Boite/scan.pdf"), "alice").unwrap();
    let (_, _, frag) = call(app, "GET", "/web/activity", &c, "").await;
    let links = &frag[frag.find("Your shared links").unwrap()..];
    assert!(links.contains("<p><strong>scan.pdf</strong> and 1 other"), "{links}");
    assert!(!links.contains("/web/view/Boite/scan.pdf") && links.contains("“<a href=\"/web/files/Boite/\">Boite</a>”"));

    // Revoked link: its history stays, flagged.
    let r = call(
        app,
        "POST",
        "/web/shares/revoke",
        &c,
        &format!("csrf={csrf}&id={read_id}"),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK);
    let (_, _, page) = call(app, "GET", "/web/shares", &c, "").await;
    assert!(
        page.contains("facture-01.pdf")
            && page.contains(
                "via “<a href=\"/web/files/Factures/?voir=facture%2D01%2Epdf#vise\">Factures</a>”, link revoked"
            )
    );
    let (_, _, only) = call(app, "GET", &format!("/web/shares?lien={read_id}"), &c, "").await;
    assert!(only.contains("Link: <strong>Factures (revoked)</strong>"));

    // Pagination: 50 per page, filter kept in the links.
    for i in 0..60 {
        e.state
            .db
            .share_event(
                &t,
                &drop_id,
                "alice",
                crate::db::ShareEventKind::Download,
                &format!("p{i}"),
                0,
            )
            .unwrap();
    }
    let (_, _, p1) = call(app, "GET", &format!("/web/shares?lien={drop_id}"), &c, "").await;
    assert!(p1.contains("Page 1 of 2") && p1.contains(&format!("/web/shares?lien={drop_id}&#38;page=2#historique")));
    let (_, _, p2) = call(app, "GET", &format!("/web/shares?lien={drop_id}&page=2"), &c, "").await;
    assert!(p2.contains("Page 2 of 2") && p2.contains("scan.pdf") && !p2.contains("<strong>p59</strong>"));

    // Other tenant: its alice sees none of this; empty space → 204, the box disappears.
    let (bc, _) = login(&e, B, "pw-alice").await;
    let bh = [B, ("cookie", bc.as_str())];
    let (_, _, bpage) = call(app, "GET", "/web/shares", &bh, "").await;
    assert!(!bpage.contains("facture-01.pdf") && bpage.contains("Nothing yet."));
    assert_eq!(status(app, "GET", "/web/activity", &bh).await, StatusCode::NO_CONTENT);
}

/// A link leaves the list when it no longer serves: limit reached; target renamed, or permanently deleted then
/// replaced by a same-named item (ended); target in the trash (suspended, resumed on restore). The history says
/// why; the guest gets the same response as for an unknown link.
#[tokio::test]
async fn shares_end_with_their_target() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    let sp = |s: &str| SafePath::new(s).unwrap();
    for d in ["Renomme", "Supprime", "Remplace", "Intact"] {
        root.mkdir(&sp(d)).unwrap();
        root.atomic_write(&sp(&format!("{d}/a.txt")), &mut &b"a"[..]).unwrap();
    }
    root.atomic_write(&sp("seul.txt"), &mut &b"s"[..]).unwrap();
    for (p, extra) in [
        ("Renomme", "&perms=read"),
        ("Supprime", "&perms=read"),
        ("Remplace", "&perms=read"),
        ("Intact", "&perms=read"),
        ("seul.txt", "&perms=read&max=1"),
    ] {
        make_share(&e, &cookie, &csrf, p, extra).await;
    }
    let id_of = |target: &str| {
        e.state
            .db
            .share_list(&t, "alice")
            .unwrap()
            .into_iter()
            .find(|s| s.path_hint == target)
            .unwrap()
            .share_id
    };
    let ids: Vec<(&str, String)> = ["Renomme", "Supprime", "Remplace", "Intact", "seul.txt"]
        .into_iter()
        .map(|p| (p, id_of(p)))
        .collect();
    let toks: Vec<(&str, String)> = ids.iter().map(|(p, id)| (*p, auth::share_token(&t, id))).collect();
    // The history filtered on one link names it, with its state once it has ended.
    let chip = |p: &str| {
        let id = &ids.iter().find(|x| x.0 == p).unwrap().1;
        async move {
            let (_, _, page) = call(app, "GET", &format!("/web/shares?lien={id}"), &c, "").await;
            let at = page.find("class=\"filtre-actif\"").expect("filter chip");
            page[at..]
                .split("<strong>")
                .nth(1)
                .unwrap()
                .split("</strong>")
                .next()
                .unwrap()
                .to_owned()
        }
    };
    let link = |p: &str| format!("/s/{}", toks.iter().find(|x| x.0 == p).unwrap().1);
    // One download per link, so that they have a history.
    for (p, _) in &toks {
        let url = if *p == "seul.txt" {
            format!("{}/dl", link(p))
        } else {
            format!("{}/dl/a.txt", link(p))
        };
        assert_eq!(status(app, "GET", &url, &[A]).await, StatusCode::OK, "{p}");
    }

    // Renamed; moved to the trash; permanently deleted then replaced by a folder with the same name.
    let mv = [
        A,
        ("cookie", cookie.as_str()),
        ("x-csrf-token", csrf.as_str()),
        ("destination", "/web/dav/Renomme-2"),
    ];
    assert_eq!(
        send(app, "MOVE", "/web/dav/Renomme", &mv, b"").await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        send(app, "DELETE", "/web/dav/Supprime", &h, b"").await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(app, "DELETE", "/web/dav/Remplace", &h, b"").await.0,
        StatusCode::NO_CONTENT
    );
    let slot_of = |n: &str| {
        root.trash_list()
            .unwrap()
            .into_iter()
            .find(|x| x.name == n)
            .unwrap()
            .slot
    };
    root.trash_purge(&slot_of("Remplace")).unwrap();
    assert_eq!(
        send(app, "MKCOL", "/web/dav/Remplace", &h, b"").await.0,
        StatusCode::CREATED
    );

    // The guest: the same response as an unknown link, and the link ends at this first access.
    for p in ["Renomme", "Remplace", "seul.txt"] {
        assert_eq!(status(app, "GET", &link(p), &[A]).await, StatusCode::NOT_FOUND, "{p}");
    }
    assert_eq!(status(app, "GET", &link("Intact"), &[A]).await, StatusCode::OK);

    // The owner: only the intact link remains; "Supprime", never reopened, is noticed on display.
    assert_eq!(status(app, "GET", &link("Supprime"), &[A]).await, StatusCode::NOT_FOUND);
    let (_, _, page) = call(app, "GET", "/web/shares", &c, "").await;
    let liste = &page[page.find("class=\"liens\"").unwrap()..page.find("id=\"historique\"").unwrap()];
    assert!(liste.contains("<strong>Intact</strong>"), "{liste}");
    for gone in ["Renomme", "Supprime", "Remplace", "seul.txt"] {
        assert!(
            !liste.contains(&format!("<strong>{gone}</strong>")),
            "{gone} encore listé"
        );
    }
    let hist = &page[page.find("id=\"historique\"").unwrap()..];
    for (p, want) in [
        ("Renomme", "Renomme (deleted or moved target)"),
        ("Supprime", "Supprime (suspended: in the trash)"),
        ("Remplace", "Remplace (deleted or moved target)"),
        ("seul.txt", "seul.txt (exhausted)"),
        ("Intact", "Intact"),
    ] {
        assert_eq!(chip(p).await, want);
    }
    for want in [
        "via “Renomme”, deleted or moved target",
        "via “<a href=\"/web/view/seul.txt\">seul.txt</a>”, link exhausted",
    ] {
        assert!(hist.contains(want), "{want} absent : {hist}");
    }
    // Restored, the target gets its link back (J4 criterion: shares recovered); ended links do not.
    root.trash_restore(&slot_of("Supprime")).unwrap();
    assert_eq!(status(app, "GET", &link("Supprime"), &[A]).await, StatusCode::OK);
    let (_, _, page) = call(app, "GET", "/web/shares", &c, "").await;
    let liste = &page[page.find("class=\"liens\"").unwrap()..page.find("id=\"historique\"").unwrap()];
    assert!(liste.contains("<strong>Supprime</strong>") && !liste.contains("<strong>Renomme</strong>"));
    assert_eq!(chip("Supprime").await, "Supprime");
    // A suspended link is also resumed by the owner's page alone (without a guest visit).
    assert_eq!(
        send(app, "DELETE", "/web/dav/Intact", &h, b"").await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(chip("Intact").await, "Intact (suspended: in the trash)");
    root.trash_restore(&slot_of("Intact")).unwrap();
    let (_, _, page) = call(app, "GET", "/web/shares", &c, "").await;
    assert!(page.contains("<strong>Intact</strong>"));
    assert_eq!(chip("Intact").await, "Intact");
    for gone in ["Renomme", "Remplace"] {
        assert_eq!(
            status(app, "GET", &link(gone), &[A]).await,
            StatusCode::NOT_FOUND,
            "{gone}"
        );
    }
}

/// A download counts once, even in several ranges (video playback, resume, Safari's `bytes=0-1`
/// probe): the first one sets a signed cookie (link, file, duration); the rest is served without counting again, even
/// once the limit is reached. Without this cookie, or with a forged one or one from another file, every download counts.
#[tokio::test]
async fn ranged_download_counts_once() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    let sp = |s: &str| SafePath::new(s).unwrap();
    let film: Vec<u8> = (0..100u8).collect();
    root.atomic_write(&sp("film.mp4"), &mut film.as_slice()).unwrap();
    root.mkdir(&sp("Dossier")).unwrap();
    for f in ["Dossier/a.txt", "Dossier/b.txt"] {
        root.atomic_write(&sp(f), &mut &b"ab"[..]).unwrap();
    }
    make_share(&e, &cookie, &csrf, "film.mp4", "&perms=read&max=1").await;
    make_share(&e, &cookie, &csrf, "Dossier", "&perms=read&max=2").await;
    let tok = |target: &str| {
        let id = e
            .state
            .db
            .share_list(&t, "alice")
            .unwrap()
            .into_iter()
            .find(|s| s.path_hint == target)
            .unwrap()
            .share_id;
        auth::share_token(&t, &id)
    };
    let film_id = e
        .state
        .db
        .share_list(&t, "alice")
        .unwrap()
        .into_iter()
        .find(|s| s.path_hint == "film.mp4")
        .unwrap()
        .share_id;
    let (film_link, dir_link) = (format!("/s/{}", tok("film.mp4")), format!("/s/{}", tok("Dossier")));
    let dl = format!("{film_link}/dl");
    let pass_of = |h: &HeaderMap| h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();

    // Safari: two-byte probe, then the rest as a range, then everything: a single download counted.
    let (s, h, body) = call(app, "GET", &dl, &[A, ("range", "bytes=0-1")], "").await;
    assert_eq!((s, body.as_bytes()), (StatusCode::PARTIAL_CONTENT, &film[..2]));
    let pass = pass_of(&h);
    let (s, h, body) = call(
        app,
        "GET",
        &dl,
        &[A, ("cookie", pass.as_str()), ("range", "bytes=2-")],
        "",
    )
    .await;
    assert_eq!((s, body.len()), (StatusCode::PARTIAL_CONTENT, 98));
    assert!(!h.contains_key("set-cookie"), "la suite ne repose pas de cookie");
    let (s, _, body) = call(app, "GET", &dl, &[A, ("cookie", pass.as_str())], "").await;
    assert_eq!((s, body.len()), (StatusCode::OK, 100));

    // Limit reached: without the cookie, neither download nor page; forged or expired cookie refused.
    assert_eq!(status(app, "GET", &dl, &[A]).await, StatusCode::NOT_FOUND);
    assert_eq!(status(app, "GET", &film_link, &[A]).await, StatusCode::NOT_FOUND);
    let forged = format!("{}0", &pass[..pass.len() - 1]);
    let forged = if forged == pass {
        format!("{}1", &pass[..pass.len() - 1])
    } else {
        forged
    };
    assert_eq!(
        status(app, "GET", &dl, &[A, ("cookie", forged.as_str())]).await,
        StatusCode::NOT_FOUND
    );
    let (name, _) = pass.split_once('=').unwrap();
    assert_eq!(e.state.db.share_list(&t, "alice").unwrap().len(), 1); // film.mp4 n'est plus listé (épuisé)
    let old = format!("{name}={}", auth::share_download_pass(&t, "x", "film.mp4", 1));
    assert_eq!(
        status(app, "GET", &dl, &[A, ("cookie", old.as_str())]).await,
        StatusCode::NOT_FOUND
    );

    // Folder limited to 2: a.txt's cookie is not valid for b.txt (counted); it is still valid for a.txt.
    let (s, h, _) = call(app, "GET", &format!("{dir_link}/dl/a.txt"), &[A], "").await;
    assert_eq!(s, StatusCode::OK);
    let pass_a = pass_of(&h);
    let (s, h, _) = call(
        app,
        "GET",
        &format!("{dir_link}/dl/b.txt"),
        &[A, ("cookie", pass_a.as_str())],
        "",
    )
    .await;
    assert!(s == StatusCode::OK && h.contains_key("set-cookie"), "b.txt compté");
    assert_eq!(
        status(app, "GET", &format!("{dir_link}/dl/a.txt"), &[A]).await,
        StatusCode::NOT_FOUND
    );
    let a = [A, ("cookie", pass_a.as_str()), ("range", "bytes=1-")];
    assert_eq!(
        status(app, "GET", &format!("{dir_link}/dl/a.txt"), &a).await,
        StatusCode::PARTIAL_CONTENT
    );
    // Exhausted: no more archive or browsing, even with a cookie.
    let zc = [A, ("cookie", pass_a.as_str())];
    assert_eq!(
        status(app, "GET", &format!("{dir_link}/zip"), &zc).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(app, "GET", &format!("{dir_link}/f/"), &zc).await,
        StatusCode::NOT_FOUND
    );

    // History: one line per real download, not one per range.
    let (_, _, page) = call(app, "GET", "/web/shares", &[A, ("cookie", cookie.as_str())], "").await;
    let hist = &page[page.find("id=\"historique\"").unwrap()..];
    assert!(hist.contains("<strong>film.mp4</strong></a> downloaded<br>"), "{hist}");
    assert!(!hist.contains("times)"));
    let (_, _, only) = call(
        app,
        "GET",
        &format!("/web/shares?lien={film_id}"),
        &[A, ("cookie", cookie.as_str())],
        "",
    )
    .await;
    assert!(only.contains("Link: <strong>film.mp4 (exhausted)</strong>"), "{only}");
}

/// Drop link: the bytes reserved on its total volume are given back when the drop does not complete (wrong size,
/// guest gone mid-upload, request abandoned), kept when it succeeds; repeated failures no longer fill up the
/// link.
#[tokio::test]
async fn failed_drops_release_their_reservation() {
    use axum::body::{Body, Bytes};
    use futures_util::StreamExt;
    use std::time::Duration;
    use tower::ServiceExt;
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    root.mkdir(&SafePath::new("Boite").unwrap()).unwrap();
    let tok = make_share(&e, &cookie, &csrf, "Boite", "&perms=drop").await;
    let used = || {
        e.state
            .db
            .share_list(&t, "alice")
            .unwrap()
            .into_iter()
            .find(|s| s.path_hint == "Boite")
            .unwrap()
            .drop_bytes
    };
    // The reservation is given back in the background: wait for it (2 s at most).
    let settled = |want: i64| async move {
        for _ in 0..100 {
            if used() == want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    };
    let put = |name: &str, declared: usize, body: Body| {
        axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/s/{tok}/drop/{name}"))
            .header("host", "files.alpha.example")
            .header("content-length", declared.to_string())
            .body(body)
            .unwrap()
    };

    // Wrong announced size: 400, nothing kept.
    let r = app
        .clone()
        .oneshot(put("court.txt", 10, Body::from("12345")))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(settled(0).await, "réservation gardée : {}", used());

    // Guest gone mid-upload: the request is abandoned (no error returned), the reservation given back anyway.
    let stalled = futures_util::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"abc"))])
        .chain(futures_util::stream::pending());
    let r = tokio::time::timeout(
        Duration::from_millis(300),
        app.clone().oneshot(put("coupe.bin", 1000, Body::from_stream(stalled))),
    )
    .await;
    assert!(r.is_err(), "la requête devait rester en attente");
    assert!(settled(0).await, "réservation gardée après abandon : {}", used());
    let left: Vec<_> = std::fs::read_dir(disk(&e).join("Boite")).unwrap().collect();
    assert!(left.is_empty(), "rien ne doit rester du dépôt coupé");

    // Repeated failures of 1 MB (the link accepts 4 in total): they no longer fill up the link.
    let mega = 1 << 20;
    for i in 0..6 {
        let r = app
            .clone()
            .oneshot(put(&format!("x{i}.bin"), mega, Body::from(vec![0u8; 10])))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
    assert!(settled(0).await);
    let r = app
        .clone()
        .oneshot(put("vrai.bin", mega, Body::from(vec![7u8; mega])))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    // Success: the reservation stays, counted on the link.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(used(), i64::try_from(mega).unwrap());
    assert_eq!(std::fs::read(disk(&e).join("Boite/vrai.bin")).unwrap().len(), mega);
}

/// Restore by **file copy** (rclone to pCloud: no xattrs, times to the second): with the manifest written
/// before the backup, `rescan` gives back the identities, hence the share link, the tag and the favorite, and the
/// ETag a client reads over WebDAV (content proven identical: no re-download, no conflict); without a manifest, the
/// link is lost (new identity), and so are the tag and the ETag.
#[tokio::test]
async fn copy_restore_keeps_links_with_manifest() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    root.mkdir(&SafePath::new("Docs").unwrap()).unwrap();
    root.atomic_write(&SafePath::new("Docs/contrat.pdf").unwrap(), &mut &b"%PDF"[..])
        .unwrap();
    root.rescan(None).unwrap(); // root with an identity, as in production
    let tok = make_share(&e, &cookie, &csrf, "Docs/contrat.pdf", "&perms=read").await;
    let tag = format!("csrf={csrf}&path=Docs%2Fcontrat.pdf&op=add&tag=signé");
    call(app, "POST", "/web/tags", &c, &tag).await;
    call(app, "POST", "/web/favorite", &c, &format!("csrf={csrf}&path=Docs&on=1")).await;
    let link = format!("/s/{tok}/dl");
    assert_eq!(status(app, "GET", &link, &[A]).await, StatusCode::OK);
    let device = basic("alice", &token(&e, "alpha"));
    let etag = || async {
        let h = [A, ("authorization", device.as_str()), ("depth", "0")];
        let (s, _, body) = call(app, "PROPFIND", "/remote.php/dav/files/alice/Docs/contrat.pdf", &h, "").await;
        assert_eq!(s, StatusCode::MULTI_STATUS, "{body}");
        body.split("<d:getetag>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned()
    };
    let before = etag().await;

    let alice = disk(&e);
    let restore = |with_manifest: bool| {
        if with_manifest {
            crate::admin::manifest(&t, "alice").unwrap();
        } else {
            let _ = std::fs::remove_file(alice.join(crate::fs::MANIFEST));
        }
        // The backup is a copy without xattrs; the "restore" puts this copy back in place of the original.
        let backup = tempfile::tempdir().unwrap();
        crate::fs::copy_without_xattrs(&alice, backup.path());
        std::fs::remove_dir_all(&alice).unwrap();
        crate::fs::copy_without_xattrs(backup.path(), &alice);
        // Like rclone: empty folders (the reserved ones included) do not come back.
        for d in [".trash", ".beastbox-tmp"] {
            std::fs::remove_dir(alice.join(d)).unwrap();
        }
        crate::admin::rescan(&t, "alice", None, crate::fs::RESCAN_READERS).unwrap()
    };

    let r = restore(true);
    assert_eq!(
        (r.manifest.ids, r.ids_assigned),
        (3, 0),
        "racine, Docs, contrat.pdf : toutes reprises"
    );
    assert_eq!(status(app, "GET", &link, &[A]).await, StatusCode::OK, "lien retrouvé");
    assert_eq!(etag().await, before, "même ETag pour le client : rien à retélécharger");
    let found = call(app, "GET", "/web/search?q=tag%3Asign%C3%A9", &c, "").await.2;
    assert!(found.contains("contrat.pdf"), "tag retrouvé");
    let favs = call(app, "GET", "/web/favorites", &c, "").await.2;
    assert!(favs.contains(">Docs</a>"), "favori retrouvé");

    let r = restore(false);
    assert_eq!(
        (r.manifest.ids, r.ids_assigned),
        (0, 3),
        "sans manifeste : nouvelles identités"
    );
    assert_eq!(
        status(app, "GET", &link, &[A]).await,
        StatusCode::NOT_FOUND,
        "lien perdu"
    );
    let found = call(app, "GET", "/web/search?q=tag%3Asign%C3%A9", &c, "").await.2;
    assert!(!found.contains("contrat.pdf"), "tag perdu");
    assert_ne!(
        etag().await,
        before,
        "sans manifeste : l'ETag change (le client retélécharge)"
    );
    // `manifest` on a dataset whose empty reserved folders are gone (after such a copy): recreated, no error.
    for d in [".trash", ".beastbox-tmp"] {
        std::fs::remove_dir(alice.join(d)).unwrap();
    }
    crate::admin::manifest(&t, "alice").unwrap();
    assert!(alice.join(crate::fs::MANIFEST).is_file() && alice.join(".trash").is_dir());
}

/// `beastbox restore` (admin layer) seen by the clients: the old version comes back **next to** the current one, as a
/// new file; the current one, its ETag and its link are untouched. Alice of the other tenant (same name) sees nothing;
/// a path out of the space, a reserved name, a missing source and a second restore of the same day are refused.
#[tokio::test]
async fn restore_brings_back_a_copy_next_to_the_current_version() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    root.mkdir(&SafePath::new("Docs").unwrap()).unwrap();
    let file = SafePath::new("Docs/contrat.pdf").unwrap();
    root.atomic_write(&file, &mut &b"version J-10"[..]).unwrap();
    let snapshot = tempfile::tempdir().unwrap(); // stands for .zfs/snapshot/<J-10>
    crate::fs::copy_without_xattrs(&disk(&e), snapshot.path());
    root.atomic_write(&file, &mut &b"version du jour"[..]).unwrap();
    let tok = make_share(&e, &cookie, &csrf, "Docs/contrat.pdf", "&perms=read").await;
    let device = basic("alice", &token(&e, "alpha"));
    let dav = |path: &'static str| {
        let h = [A, ("authorization", device.as_str()), ("depth", "0")];
        async move { call(app, "PROPFIND", path, &h, "").await }
    };
    let etag = |body: &str| {
        body.split("<d:getetag>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned()
    };
    let before = etag(&dav("/remote.php/dav/files/alice/Docs/contrat.pdf").await.2);

    let (to, rep) = crate::admin::restore(&t, "alice", snapshot.path(), "Docs/contrat.pdf", None).unwrap();
    assert_eq!((rep.files, rep.dirs, rep.skipped), (1, 0, 0));
    assert!(
        to.as_str().starts_with("Docs/contrat (restored ") && to.as_str().ends_with(").pdf"),
        "{to:?}"
    );
    let url = format!("/remote.php/dav/files/alice/{}", to.as_str().replace(' ', "%20"));
    let h = [A, ("authorization", device.as_str())];
    let (s, _, body) = call(app, "GET", &url, &h, "").await;
    assert_eq!(
        (s, body.as_str()),
        (StatusCode::OK, "version J-10"),
        "the old version, next to the current one"
    );
    let (s, _, body) = call(app, "GET", "/remote.php/dav/files/alice/Docs/contrat.pdf", &h, "").await;
    assert_eq!(
        (s, body.as_str()),
        (StatusCode::OK, "version du jour"),
        "current version untouched"
    );
    assert_eq!(
        etag(&dav("/remote.php/dav/files/alice/Docs/contrat.pdf").await.2),
        before,
        "same ETag: nothing to re-download"
    );
    let (s, _, body) = call(app, "GET", &format!("/s/{tok}/dl"), &[A], "").await;
    assert_eq!(
        (s, body.as_str()),
        (StatusCode::OK, "version du jour"),
        "the link still serves the current version"
    );

    // Other tenant, same user name: nothing restored there, and alpha's app password opens nothing on beta.
    let beta = basic("alice", &token(&e, "beta"));
    let b = [
        ("host", "files.beta.example"),
        ("authorization", beta.as_str()),
        ("depth", "1"),
    ];
    let (s, _, body) = call(app, "PROPFIND", "/remote.php/dav/files/alice/", &b, "").await;
    assert!(s == StatusCode::MULTI_STATUS && !body.contains("contrat"), "{s} {body}");
    let cross = [("host", "files.beta.example"), ("authorization", device.as_str())];
    assert_eq!(status(app, "GET", &url, &cross).await, StatusCode::UNAUTHORIZED);

    // A file that no longer exists comes back at its own place (the clients see it reappear).
    root.atomic_write(&SafePath::new("Docs/annexe.txt").unwrap(), &mut &b"annexe"[..])
        .unwrap();
    crate::fs::copy_without_xattrs(&disk(&e), snapshot.path());
    std::fs::remove_file(disk(&e).join("Docs/annexe.txt")).unwrap();
    let (back, _) = crate::admin::restore(&t, "alice", snapshot.path(), "Docs/annexe.txt", None).unwrap();
    // A chosen target, in a folder that does not exist yet.
    let (named, _) = crate::admin::restore(
        &t,
        "alice",
        snapshot.path(),
        "Docs/annexe.txt",
        Some("Archives/annexe J-10.txt"),
    )
    .unwrap();
    assert_eq!(named.as_str(), "Archives/annexe J-10.txt");
    assert_eq!(
        std::fs::read(disk(&e).join("Archives/annexe J-10.txt")).unwrap(),
        b"annexe"
    );
    std::fs::remove_dir_all(disk(&e).join("Archives")).unwrap();
    assert_eq!(back.as_str(), "Docs/annexe.txt");
    let (s, _, body) = call(app, "GET", "/remote.php/dav/files/alice/Docs/annexe.txt", &h, "").await;
    assert_eq!((s, body.as_str()), (StatusCode::OK, "annexe"));
    std::fs::remove_file(disk(&e).join("Docs/annexe.txt")).unwrap();

    // Default name: a file keeps its extension last; a folder name, a name without extension and a dot file whole.
    let tag = to
        .as_str()
        .strip_prefix("Docs/contrat ")
        .and_then(|s| s.strip_suffix(".pdf"))
        .unwrap()
        .to_owned();
    root.mkdir(&SafePath::new("v1.2").unwrap()).unwrap();
    for p in ["v1.2/notes", "v1.2/.env", "v1.2/a.b.txt"] {
        root.atomic_write(&SafePath::new(p).unwrap(), &mut &b"x"[..]).unwrap();
    }
    crate::fs::copy_without_xattrs(&disk(&e), snapshot.path());
    for (p, want) in [
        ("v1.2", format!("v1.2 {tag}")),
        ("v1.2/notes", format!("v1.2/notes {tag}")),
        ("v1.2/.env", format!("v1.2/.env {tag}")),
        ("v1.2/a.b.txt", format!("v1.2/a.b {tag}.txt")),
    ] {
        let (got, _) = crate::admin::restore(&t, "alice", snapshot.path(), p, None).unwrap();
        assert_eq!(got.as_str(), want);
    }
    // The administrator reads what went wrong.
    let msg = |p: &str| {
        crate::admin::restore(&t, "alice", snapshot.path(), p, None)
            .unwrap_err()
            .to_string()
    };
    assert!(msg("Docs/absent.pdf").contains("Docs/absent.pdf not found in"));
    assert!(msg("Docs/contrat.pdf").contains(&format!("Docs/contrat {tag}.pdf already exists")));

    // An unknown user is refused, and alpha's restores never land in beta's space.
    assert!(crate::admin::restore(&t, "bob", snapshot.path(), "Docs/contrat.pdf", None).is_err());
    assert!(!e._b_root.path().join("alice/Docs/contrat.pdf").exists());

    // Refusals, each for its own reason (the path check, the missing source, the existing target): nothing written.
    for (from, path, why) in [
        (snapshot.path(), "../alice/Docs", "chemin invalide"),
        (snapshot.path(), ".trash", "chemin invalide"),
        (snapshot.path(), "Docs/absent.pdf", "not found in"),
        (
            std::path::Path::new("/nonexistent/snapshot"),
            "Docs",
            "/nonexistent/snapshot",
        ),
        (snapshot.path(), "Docs/contrat.pdf", "already exists"), // already restored today
    ] {
        let e = crate::admin::restore(&t, "alice", from, path, None)
            .unwrap_err()
            .to_string();
        assert!(e.contains(why), "{from:?} {path}: {e}");
    }
    // Chosen target: never over an existing item, never out of the space, never a reserved name.
    for (to, why) in [
        ("Docs/contrat.pdf", "already exists"),
        ("Docs", "already exists"),
        ("../beta/x", "chemin invalide"),
        (".trash/x", "chemin invalide"),
        (".beastbox-manifest", "chemin invalide"),
        ("a\\b", "chemin invalide"),
    ] {
        let e = crate::admin::restore(&t, "alice", snapshot.path(), "Docs/annexe.txt", Some(to))
            .unwrap_err()
            .to_string();
        assert!(e.contains(why), "{to}: {e}");
    }
    let names: Vec<String> = std::fs::read_dir(disk(&e).join("Docs"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
}

/// Language: English by default, the browser's `Accept-Language` when it asks for French, and the
/// account's choice (cookie) above both.
#[tokio::test]
async fn language_follows_browser_then_account_choice() {
    let e = env();
    let app = &e.app;
    let (s, _, page) = call(app, "GET", "/login", &[A], "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains(">Sign in<") && page.contains("<html lang=\"en\">"),
        "{page}"
    );
    let fr = [A, ("accept-language", "fr-CH,fr;q=0.9,en;q=0.8")];
    let (_, _, page) = call(app, "GET", "/login", &fr, "").await;
    assert!(
        page.contains(">Connexion<") && page.contains("<html lang=\"fr\">"),
        "{page}"
    );

    // The account page stores the choice for this browser, whatever the browser asks.
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let (s, _, page) = call(app, "GET", "/web/account", &c, "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("name=\"lang\"") && page.contains(">Language<"));
    assert!(page.contains("<option value=\"fr\">Français</option>"));
    let (s, h, _) = call(
        app,
        "POST",
        "/web/account/language",
        &c,
        &format!("csrf={csrf}&lang=fr"),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let lang = h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
    assert!(lang.ends_with("=fr"), "{lang}");
    let c = [A, ("cookie", cookie.as_str()), ("cookie", lang.as_str())];
    let (_, _, page) = call(app, "GET", "/web/files/", &c, "").await;
    assert!(
        page.contains("<html lang=\"fr\">") && page.contains(">Fichiers<"),
        "{page}"
    );
}

/// Drop link hardening (0.9): at most `drop_max_files` files (a failed drop gives its file back), names cleaned on
/// disk, a guest who stops sending is cut after `BODY_IDLE` (answer given, temporary removed, file given back).
#[tokio::test]
async fn drop_links_are_bounded() {
    use axum::body::{Body, Bytes};
    use futures_util::StreamExt;
    use tower::ServiceExt;
    let e = crate::http::tests::env_with(crate::http::Settings {
        drop_max_files: 3,
        ..Default::default()
    });
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    root.mkdir(&SafePath::new("Boite").unwrap()).unwrap();
    let tok = make_share(&e, &cookie, &csrf, "Boite", "&perms=drop").await;
    let put = |name: &str, declared: usize, body: Body| {
        axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/s/{tok}/drop/{name}"))
            .header("host", "files.alpha.example")
            .header("content-length", declared.to_string())
            .body(body)
            .unwrap()
    };
    let send = |name: &'static str| async move {
        app.clone()
            .oneshot(put(name, 2, Body::from("ok")))
            .await
            .unwrap()
            .status()
    };
    let disk = disk(&e);

    // Names cleaned for every client of the owner.
    assert_eq!(send("a%3Ab%3F.txt").await, StatusCode::CREATED);
    assert_eq!(send("nul.txt").await, StatusCode::CREATED);
    let mut names: Vec<_> = std::fs::read_dir(disk.join("Boite"))
        .unwrap()
        .map(|d| d.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["_nul.txt", "a_b_.txt"]);

    // A guest who stops sending: cut after BODY_IDLE (virtual time), nothing kept, its file given back.
    tokio::time::pause();
    let stalled = futures_util::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"abc"))])
        .chain(futures_util::stream::pending());
    let r = app
        .clone()
        .oneshot(put("lent.bin", 1000, Body::from_stream(stalled)))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    tokio::time::resume();
    assert_eq!(std::fs::read_dir(disk.join(".beastbox-tmp")).unwrap().count(), 0);
    // The reservation is given back in the background.
    for _ in 0..100 {
        if send("trois.txt").await == StatusCode::CREATED {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(disk.join("Boite/trois.txt").exists(), "file count not given back");

    // Fourth file: over the limit.
    assert_eq!(send("quatre.txt").await, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!disk.join("Boite/quatre.txt").exists());
}

/// Renewing the link key ends the links given out before (their digest is still in the database), without touching
/// the rest: a token is only accepted if it derives from the current link key.
#[tokio::test]
async fn renewed_link_key_ends_old_links() {
    let e = env();
    let app = &e.app;
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    let p = SafePath::new("a.txt").unwrap();
    root.atomic_write(&p, &mut &b"a"[..]).unwrap();
    let id = root.file_id(&p).unwrap().unwrap();
    // The same tenant (same main key) before the renewal: another link key.
    let d = tempfile::tempdir().unwrap();
    let before = crate::tenant::Registry::from_parts(vec![(
        "alpha".into(),
        vec!["files.alpha.example".into()],
        crate::fs::Root::open_dir(d.path()).unwrap(),
        [1; 32],
        [99; 32],
        None,
    )])
    .unwrap();
    let add = |share_id: &str, token: &str| {
        e.state
            .db
            .share_add(
                &t,
                &crate::db::NewShare {
                    share_id,
                    user: "alice",
                    mac: &t.mac(token.as_bytes()),
                    fileid: &id.0,
                    path_hint: "a.txt",
                    perms: "read",
                    password_hash: None,
                    expires_at: None,
                    max_downloads: None,
                    opts: &Default::default(),
                },
            )
            .unwrap();
    };
    let old = auth::share_token(&before.by_name("alpha").unwrap(), "s-old");
    let new = auth::share_token(&t, "s-new");
    add("s-old", &old);
    add("s-new", &new);
    assert_eq!(
        status(app, "GET", &format!("/s/{old}"), &[A]).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(status(app, "GET", &format!("/s/{new}"), &[A]).await, StatusCode::OK);
}

/// Changing the password ends the account's web sessions (a stolen session does not survive it); the devices' app
/// passwords stay, and the other tenant's alice keeps her session.
#[tokio::test]
async fn password_change_ends_web_sessions() {
    let e = env();
    let app = &e.app;
    let (a_cookie, _) = login(&e, A, "pw-alice").await;
    let (b_cookie, _) = login(&e, B, "pw-alice").await;
    let device = basic("alice", &token(&e, "alpha"));
    let files = |host: (&'static str, &'static str), cookie: String| async move {
        status(app, "GET", "/web/files/", &[host, ("cookie", cookie.as_str())]).await
    };
    assert_eq!(files(A, a_cookie.clone()).await, StatusCode::OK);
    let t = e.state.registry.by_name("alpha").unwrap();
    crate::admin::user_passwd(&e.state.db, &t, "alice", Some("nouveau-mot-de-passe"), 12, false)
        .unwrap()
        .unwrap();
    assert_eq!(files(A, a_cookie.clone()).await, StatusCode::SEE_OTHER);
    assert_eq!(files(B, b_cookie.clone()).await, StatusCode::OK);
    let dav = [A, ("authorization", device.as_str()), ("depth", "0")];
    assert_eq!(
        status(app, "PROPFIND", "/remote.php/dav/files/alice/", &dav).await,
        StatusCode::MULTI_STATUS
    );
    login(&e, A, "nouveau-mot-de-passe").await;
}

/// alpha's alice gets a password from the administrator and signs in with it: (cookie, csrf).
async fn forced_login(e: &Env) -> (String, String) {
    let t = e.state.registry.by_name("alpha").unwrap();
    crate::admin::user_passwd(&e.state.db, &t, "alice", Some("donne-par-l-admin"), 12, true)
        .unwrap()
        .unwrap();
    login(e, A, "donne-par-l-admin").await
}

fn to_welcome(s: StatusCode, h: &HeaderMap) -> bool {
    s == StatusCode::SEE_OTHER && h.get("location").and_then(|v| v.to_str().ok()) == Some("/web/welcome")
}

fn welcome_form(csrf: &str, cur: &str, new: &str, again: &str) -> String {
    format!("csrf={csrf}&current={cur}&new={new}&again={again}")
}

/// Every page sends a session whose password was set by the administrator to `/web/welcome`, the login page too.
#[tokio::test]
async fn forced_session_pages_lead_to_welcome() {
    let e = env();
    let (cookie, _) = forced_login(&e).await;
    let c = [A, ("cookie", cookie.as_str())];
    for p in [
        "/web/files/",
        "/web/files/?q=x",
        "/web/account",
        "/web/shares",
        "/web/trash",
        "/web/favorites",
        "/web/search?q=x",
        "/login",
    ] {
        let (s, h, _) = call(&e.app, "GET", p, &c, "").await;
        assert!(to_welcome(s, &h), "{p}: {s}");
    }
}

/// No action from such a session, even with a valid CSRF token: no device, no QR code, no link, no password change
/// through the account page (which would skip the confirmation), no tag.
#[tokio::test]
async fn forced_session_actions_are_refused() {
    let e = env();
    let t = e.state.registry.by_name("alpha").unwrap();
    std::fs::write(disk(&e).join("note.txt"), b"x").unwrap();
    let (cookie, csrf) = forced_login(&e).await;
    let c = [A, ("cookie", cookie.as_str())];
    for (p, extra) in [
        ("/web/account/tokens", "&label=x"),
        ("/web/account/qr", ""),
        (
            "/web/account/password",
            "&current=donne-par-l-admin&new=autre-secret-123",
        ),
        ("/web/shares", "&path=note.txt&perms=read"),
        ("/web/tags", "&path=note.txt&op=add&tag=x"),
        ("/web/account/language", "&lang=fr"),
    ] {
        let (s, h, _) = call(&e.app, "POST", p, &c, &format!("csrf={csrf}{extra}")).await;
        assert!(to_welcome(s, &h), "{p}: {s}");
    }
    assert!(e.state.db.token_list(&t, "alice").unwrap().is_empty());
    assert!(e.state.db.share_list(&t, "alice").unwrap().is_empty());
    assert_eq!(e.state.db.user_must_change(&t, "alice").unwrap(), Some(true));
}

/// The browser's WebDAV and a client's "open in the browser" link do not open either.
#[tokio::test]
async fn forced_session_opens_no_dav_nor_private_link() {
    let e = env();
    let (cookie, csrf) = forced_login(&e).await;
    let dav = [
        A,
        ("cookie", cookie.as_str()),
        ("x-csrf-token", csrf.as_str()),
        ("depth", "0"),
    ];
    for m in ["PROPFIND", "GET", "PUT", "MKCOL", "DELETE"] {
        assert_eq!(
            status(&e.app, m, "/web/dav/x", &dav).await,
            StatusCode::UNAUTHORIZED,
            "{m}"
        );
    }
    assert_eq!(
        status(&e.app, "PROPFIND", "/web/dav/", &dav).await,
        StatusCode::UNAUTHORIZED
    );
    let (s, h, _) = call(&e.app, "GET", "/index.php/f/1", &[A, ("cookie", cookie.as_str())], "").await;
    assert!(s == StatusCode::SEE_OTHER && h["location"].to_str().unwrap().starts_with("/login"));
}

/// Login Flow (desktop and mobile clients): the right password set by the administrator connects no device; once
/// replaced, the same flow goes through.
#[tokio::test]
async fn forced_account_cannot_connect_a_device() {
    let e = env();
    let t = e.state.registry.by_name("alpha").unwrap();
    let (cookie, csrf) = forced_login(&e).await;
    let (_, _, body) = call(
        &e.app,
        "POST",
        "/index.php/login/v2",
        &[A, ("x-forwarded-proto", "http")],
        "",
    )
    .await;
    let flow = body
        .split("/index.php/login/v2/flow/")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let form = format!("/index.php/login/v2/flow/{flow}");
    // Not signed in: to the login; no device before the password is the account's own.
    assert_eq!(call(&e.app, "POST", &form, &[A], "").await.0, StatusCode::SEE_OTHER);
    assert!(e.state.db.token_list(&t, "alice").unwrap().is_empty());
    let c = [A, ("cookie", cookie.as_str())];
    let body = welcome_form(&csrf, "donne-par-l-admin", "mon-secret-a-moi", "mon-secret-a-moi");
    assert_eq!(call(&e.app, "POST", "/web/welcome", &c, &body).await.0, StatusCode::OK);
    // The session is closed by the change: sign in with the new password, then confirm the flow.
    let (cookie, _) = login(&e, A, "mon-secret-a-moi").await;
    let (s, _, _) = call(&e.app, "POST", &form, &[A, ("cookie", cookie.as_str())], "").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(e.state.db.token_list(&t, "alice").unwrap().len(), 1);
}

/// Each refusal of the welcome form is shown as an alert with its code, and changes nothing: the state stays, the
/// session stays, the password received still works.
#[tokio::test]
async fn welcome_refusals_change_nothing() {
    let e = env();
    let t = e.state.registry.by_name("alpha").unwrap();
    let (cookie, csrf) = forced_login(&e).await;
    let c = [A, ("cookie", cookie.as_str())];
    let (s, _, page) = call(&e.app, "GET", "/web/welcome", &c, "").await;
    assert!(
        s == StatusCode::OK && page.contains("name=\"again\"") && page.contains(">12 characters"),
        "{page}"
    );
    let f = |cur: &str, new: &str, again: &str| welcome_form(&csrf, cur, new, again);
    let cases = [
        (
            welcome_form("faux", "donne-par-l-admin", "mon-secret-a-moi", "mon-secret-a-moi"),
            StatusCode::FORBIDDEN,
            "Invalid form token",
        ),
        (
            f("donne-par-l-admin", "mon-secret-a-moi", "mon-secret-a-mo1"),
            StatusCode::BAD_REQUEST,
            "differ:",
        ),
        (
            f("donne-par-l-admin", "mon-secret-a-moi", ""),
            StatusCode::BAD_REQUEST,
            "differ:",
        ),
        (
            f("donne-par-l-admin", "x7kq2m!vbzw", "x7kq2m!vbzw"),
            StatusCode::BAD_REQUEST,
            "too short",
        ), // 11 < 12
        (
            f("donne-par-l-admin", "azertyuiopqs", "azertyuiopqs"),
            StatusCode::BAD_REQUEST,
            "too easy",
        ),
        (
            f("donne-par-l-admin", "alice-a-la-plage", "alice-a-la-plage"),
            StatusCode::BAD_REQUEST,
            "account or tenant name",
        ),
        (
            f("donne-par-l-admin", "donne-par-l-admin", "donne-par-l-admin"),
            StatusCode::BAD_REQUEST,
            "differ from the current",
        ),
        (
            f("faux-mot-de-passe", "mon-secret-a-moi", "mon-secret-a-moi"),
            StatusCode::UNAUTHORIZED,
            "Wrong current",
        ),
        (
            format!("csrf={csrf}&current=donne-par-l-admin&new=mon-secret-a-moi"),
            StatusCode::BAD_REQUEST,
            "Missing",
        ),
    ];
    for (body, code, msg) in cases {
        let (s, _, page) = call(&e.app, "POST", "/web/welcome", &c, &body).await;
        assert!(
            s == code && page.contains(msg) && page.contains("role=\"alert\""),
            "{body}: {s} {page}"
        );
        assert_eq!(e.state.db.user_must_change(&t, "alice").unwrap(), Some(true), "{body}");
        assert_eq!(
            status(&e.app, "GET", "/web/welcome", &c).await,
            StatusCode::OK,
            "{body}"
        );
    }
    login(&e, A, "donne-par-l-admin").await;
}

/// Exactly 12 characters (the setting) is accepted on the welcome form; success ends the session (cookie cleared and
/// row gone), the new password opens the application and the welcome page is gone.
#[tokio::test]
async fn welcome_success_at_the_minimum_length() {
    let e = env();
    let (cookie, csrf) = forced_login(&e).await;
    let c = [A, ("cookie", cookie.as_str())];
    let body = welcome_form(&csrf, "donne-par-l-admin", "x7kq2m!vbzwy", "x7kq2m!vbzwy");
    let (s, h, page) = call(&e.app, "POST", "/web/welcome", &c, &body).await;
    assert!(s == StatusCode::OK && page.contains("Sign in again"), "{page}");
    assert!(h["set-cookie"].to_str().unwrap().contains("Max-Age=0"));
    let (s, h, _) = call(&e.app, "GET", "/web/welcome", &c, "").await;
    assert!(s == StatusCode::SEE_OTHER && h["location"] == "/login"); // the old session is gone
    let (s, _, _) = call(&e.app, "POST", "/login", &[A], "user=alice&password=donne-par-l-admin").await;
    assert_ne!(s, StatusCode::SEE_OTHER, "the password received still signs in");
    let (cookie, _) = login(&e, A, "x7kq2m!vbzwy").await;
    let c = [A, ("cookie", cookie.as_str())];
    assert_eq!(status(&e.app, "GET", "/web/files/", &c).await, StatusCode::OK);
    let (s, h, _) = call(&e.app, "GET", "/web/welcome", &c, "").await;
    assert!(s == StatusCode::SEE_OTHER && h["location"] == "/web/files/");
    assert_eq!(
        call(&e.app, "POST", "/web/welcome", &c, &body).await.0,
        StatusCode::SEE_OTHER
    ); // nothing to do
}

/// Without a session, the welcome page sends to the login and changes nothing.
#[tokio::test]
async fn welcome_without_session() {
    let e = env();
    let body = welcome_form("x", "pw-alice", "mon-secret-a-moi", "mon-secret-a-moi");
    for m in ["GET", "POST"] {
        let (s, h, _) = call(&e.app, m, "/web/welcome", &[A], &body).await;
        assert!(s == StatusCode::SEE_OTHER && h["location"] == "/login", "{m}");
    }
    login(&e, A, "pw-alice").await;
}

/// Another account of the same tenant (bob) and the same name in the other tenant keep working while alpha's alice
/// must choose her password; their own pages never mention the welcome page.
#[tokio::test]
async fn forced_account_leaves_the_others_alone() {
    let e = env();
    let t = e.state.registry.by_name("alpha").unwrap();
    std::fs::create_dir(e.a_root.path().join("bob")).unwrap();
    t.data_root()
        .open_subdir(&SafePath::new("bob").unwrap())
        .unwrap()
        .ensure_layout()
        .unwrap();
    let h = auth::hash_password("pw-de-bob-123").unwrap();
    e.state.db.user_add(&t, "bob", &h, false).unwrap();
    e.state.db.user_set_password_hash(&t, "bob", &h, false).unwrap();
    let (b_cookie, _) = login(&e, B, "pw-alice").await;
    forced_login(&e).await;
    let (s, hd, _) = call(&e.app, "POST", "/login", &[A], "user=bob&password=pw-de-bob-123").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let bob = hd["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
    for (host, cookie) in [(A, bob.as_str()), (B, b_cookie.as_str())] {
        assert_eq!(
            status(&e.app, "GET", "/web/files/", &[host, ("cookie", cookie)]).await,
            StatusCode::OK
        );
        let (s, hd, _) = call(&e.app, "GET", "/web/welcome", &[host, ("cookie", cookie)], "").await;
        assert!(s == StatusCode::SEE_OTHER && hd["location"] == "/web/files/");
    }
    assert_eq!(e.state.db.user_must_change(&t, "bob").unwrap(), Some(false));
}

/// A session that must choose its password can still sign out: the session row is gone, not only the cookie.
#[tokio::test]
async fn welcome_session_can_sign_out() {
    let e = env();
    let (cookie, csrf) = forced_login(&e).await;
    let c = [A, ("cookie", cookie.as_str())];
    // A wrong token signs nobody out (logout is a form like the others).
    call(&e.app, "POST", "/logout", &c, "csrf=faux").await;
    assert_eq!(status(&e.app, "GET", "/web/welcome", &c).await, StatusCode::OK);
    assert_eq!(
        call(&e.app, "POST", "/logout", &c, &format!("csrf={csrf}")).await.0,
        StatusCode::SEE_OTHER
    );
    let (s, h, _) = call(&e.app, "GET", "/web/welcome", &c, "").await;
    assert!(s == StatusCode::SEE_OTHER && h["location"] == "/login");
}

/// A disabled account: sign-in refused, session ended, devices and public links blocked (a link answers like an unknown
/// one); the other tenant's alice is untouched. Enabled again: devices and links answer, the old session stays ended.
#[tokio::test]
async fn disabled_account_is_shut_out_until_enabled() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let (b_cookie, _) = login(&e, B, "pw-alice").await;
    let t = e.state.registry.by_name("alpha").unwrap();
    t.data_root()
        .open_subdir(&SafePath::new("alice").unwrap())
        .unwrap()
        .atomic_write(&SafePath::new("note.txt").unwrap(), &mut &b"x"[..])
        .unwrap();
    let link = format!("/s/{}", make_share(&e, &cookie, &csrf, "note.txt", "&perms=read").await);
    let device = basic("alice", &token(&e, "alpha"));
    let dav = [A, ("authorization", device.as_str()), ("depth", "0")];
    let files = |host: (&'static str, &'static str), cookie: String| async move {
        status(app, "GET", "/web/files/", &[host, ("cookie", cookie.as_str())]).await
    };
    let propfind = || status(app, "PROPFIND", "/remote.php/dav/files/alice/", &dav);
    crate::admin::user_set_active(&e.state.db, &t, "alice", false).unwrap();
    assert_eq!(files(A, cookie.clone()).await, StatusCode::SEE_OTHER);
    let (s, _, _) = call(app, "POST", "/login", &[A], "user=alice&password=pw-alice").await;
    assert_ne!(s, StatusCode::SEE_OTHER, "a disabled account signed in");
    assert_eq!(propfind().await, StatusCode::UNAUTHORIZED);
    assert_eq!(status(app, "GET", &link, &[A]).await, StatusCode::NOT_FOUND);
    assert_eq!(files(B, b_cookie.clone()).await, StatusCode::OK); // other tenant untouched
    crate::admin::user_set_active(&e.state.db, &t, "alice", false).unwrap(); // twice: no error
    crate::admin::user_set_active(&e.state.db, &t, "alice", true).unwrap();
    assert_eq!(propfind().await, StatusCode::MULTI_STATUS);
    assert_eq!(status(app, "GET", &link, &[A]).await, StatusCode::OK);
    assert_eq!(files(A, cookie).await, StatusCode::SEE_OTHER); // the old session does not come back
    login(&e, A, "pw-alice").await;
    assert!(crate::admin::user_set_active(&e.state.db, &t, "nobody", false).is_err());
}

/// Public pages (login, guest link, unknown link, device login) never tell a stranger which version runs; the
/// signed-in pages do.
#[tokio::test]
async fn public_pages_hide_the_version() {
    let e = env();
    let app = &e.app;
    let v = format!("Beastbox {}", env!("CARGO_PKG_VERSION"));
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let root = e
        .state
        .registry
        .by_name("alpha")
        .unwrap()
        .data_root()
        .open_subdir(&SafePath::new("alice").unwrap())
        .unwrap();
    root.atomic_write(&SafePath::new("a.txt").unwrap(), &mut &b"a"[..])
        .unwrap();
    let tok = make_share(&e, &cookie, &csrf, "a.txt", "&perms=read").await;
    let (_, _, json) = call(app, "POST", "/index.php/login/v2", &[A], "").await;
    let flow = json.split("\"login\":\"").nth(1).unwrap().split('"').next().unwrap();
    let flow = format!("/index.php{}", flow.split("/index.php").nth(1).unwrap());
    for url in [
        "/login".to_owned(),
        format!("/s/{tok}"),
        format!("/s/{}", "0".repeat(32)),
    ] {
        let (_, _, page) = call(app, "GET", &url, &[A], "").await;
        assert!(page.contains("Powered by Beastbox") && !page.contains(&v), "{url}");
    }
    // The Login Flow page of an anonymous browser is a redirect, not a page: nothing to leak there.
    let (s, h, _) = call(app, "GET", &flow, &[A], "").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(h["location"].to_str().unwrap().starts_with("/login?next="));
    let (_, _, page) = call(app, "GET", "/web/account", &[A, ("cookie", cookie.as_str())], "").await;
    assert!(page.contains(&v));
}

/// The clients' "open in the browser" (`/index.php/f/<fileid>`): login first if needed, then back to that item; only
/// the user's own items; the login page never leads anywhere else.
#[tokio::test]
async fn open_in_browser_from_a_client() {
    let e = env();
    let app = &e.app;
    let device = basic("alice", &token(&e, "alpha"));
    let a = [A, ("authorization", device.as_str())];
    let f = "/remote.php/dav/files/alice";
    send(app, "MKCOL", &format!("{f}/Mes%20docs"), &a, b"").await;
    send(app, "PUT", &format!("{f}/Mes%20docs/a.txt"), &a, b"a").await;
    let fileid = |p: &str| {
        let p = format!("{f}/{p}");
        let h = [A, ("authorization", device.as_str()), ("depth", "0")];
        async move {
            let props = r#"<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>"#;
            let (_, _, body) = call(app, "PROPFIND", &p, &h, props).await;
            body.split("<oc:fileid>")
                .nth(1)
                .unwrap()
                .split('<')
                .next()
                .unwrap()
                .to_owned()
        }
    };
    let (file, dir) = (fileid("Mes%20docs/a.txt").await, fileid("Mes%20docs").await);
    let loc = |h: &HeaderMap| h["location"].to_str().unwrap().to_owned();

    // Not signed in: to the login, which brings the user back.
    let (s, h, _) = call(app, "GET", &format!("/index.php/f/{file}"), &[A], "").await;
    assert_eq!(
        (s, loc(&h)),
        (StatusCode::SEE_OTHER, format!("/login?next=/index.php/f/{file}"))
    );
    let (_, _, page) = call(app, "GET", &format!("/login?next=/index.php/f/{file}"), &[A], "").await;
    assert!(page.contains(&format!("name=\"next\" value=\"/index.php/f/{file}\"")));
    let (s, h, _) = call(
        app,
        "POST",
        "/login",
        &[A],
        &format!("user=alice&password=pw-alice&next=/index.php/f/{file}"),
    )
    .await;
    assert_eq!((s, loc(&h)), (StatusCode::SEE_OTHER, format!("/index.php/f/{file}")));
    let cookie = h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
    let c = [A, ("cookie", cookie.as_str())];

    // Signed in: a file's page, a folder's listing; nothing for an unknown identifier or another tenant's alice.
    let (_, h, _) = call(app, "GET", &format!("/index.php/f/{file}"), &c, "").await;
    assert_eq!(loc(&h), "/web/view/Mes%20docs/a.txt");
    let (_, h, _) = call(app, "GET", &format!("/index.php/f/{dir}"), &c, "").await;
    assert_eq!(loc(&h), "/web/files/Mes%20docs/");
    assert_eq!(status(app, "GET", "/index.php/f/123", &c).await, StatusCode::NOT_FOUND);
    let (b_cookie, _) = login(&e, B, "pw-alice").await;
    assert_eq!(
        status(
            app,
            "GET",
            &format!("/index.php/f/{file}"),
            &[B, ("cookie", b_cookie.as_str())]
        )
        .await,
        StatusCode::NOT_FOUND
    );

    // The login never sends anyone elsewhere.
    for next in [
        "https://evil.example/",
        "//evil.example",
        "/index.php/f/1/../../x",
        "/web/files/",
        "/index.php/f/",
    ] {
        let (_, h, _) = call(
            app,
            "POST",
            "/login",
            &[A],
            &format!("user=alice&password=pw-alice&next={next}"),
        )
        .await;
        assert_eq!(loc(&h), "/web/files/", "{next}");
    }
}

proptest::proptest! {
    /// Whatever it is given, the login's return address is empty or one of the three local targets of the
    /// allowlist (`auth::oidc::after_login`): nothing that could leave the site.
    #[test]
    fn login_return_is_always_local(v in "\\PC{0,40}") {
        let r = super::after_login(Some(v));
        let digits = r.strip_prefix("/index.php/f/").map(|d| !d.is_empty() && d.len() <= 20 && d.bytes().all(|b| b.is_ascii_digit()));
        let flow = r.strip_prefix("/index.php/login/v2/flow/").map(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        proptest::prop_assert!(
            r.is_empty() || r == "/web/account" || digits == Some(true) || flow == Some(true),
            "not local: {:?}", r
        );
        // A client link always survives the trip.
        let ok = "/index.php/f/12345";
        proptest::prop_assert_eq!(super::after_login(Some(ok.into())), ok);
        proptest::prop_assert_eq!(super::after_login(Some("/web/account".into())), "/web/account");
    }
}

/// Account page: the mobile app's QR code is only made by the form (CSRF), shown once, never cached, drawn inline; a
/// second one replaces the first one not used yet.
#[tokio::test]
async fn qr_code_for_the_mobile_app() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    assert_eq!(
        call(app, "POST", "/web/account/qr", &c, "csrf=faux").await.0,
        StatusCode::FORBIDDEN
    );
    let (s, h, page) = call(app, "POST", "/web/account/qr", &c, &format!("csrf={csrf}")).await;
    assert_eq!((s, h["cache-control"].to_str().unwrap()), (StatusCode::OK, "no-store"));
    assert!(page.contains(r#"<div class="qr-code"><svg role="img""#) && page.contains("Done"));
    assert!(page.contains("Mobile app (QR code)") && page.contains("expires at"));
    call(app, "POST", "/web/account/qr", &c, &format!("csrf={csrf}")).await;
    let (_, _, page) = call(app, "GET", "/web/account", &c, "").await;
    assert_eq!(page.matches("<strong>Mobile app (QR code)</strong>").count(), 1);
    assert!(!page.contains("<svg role=\"img\"")); // never shown again
}

proptest::proptest! {
    /// The login QR code reads back, as the Nextcloud apps read it (`nc://login/`, `&`-separated `key:value`, split at
    /// the first `:`), into exactly the user, password and server given.
    #[test]
    fn qr_login_reads_back(
        user in "[a-z0-9_.-]{1,32}",
        password in "[0-9a-f]{64}",
        server in "https?://[a-z0-9-]{1,20}(\\.[a-z0-9-]{1,20}){0,3}(:[0-9]{1,5})?",
    ) {
        let qr = auth::qr_login(&user, &password, &server);
        let data = qr.strip_prefix("nc://login/").unwrap();
        let parts: Vec<&str> = data.split('&').collect();
        proptest::prop_assert_eq!(parts.len(), 3);
        let get = |k: &str| parts.iter().find_map(|p| p.strip_prefix(k)).map(str::to_owned);
        proptest::prop_assert_eq!(get("user:"), Some(user));
        proptest::prop_assert_eq!(get("password:"), Some(password));
        proptest::prop_assert_eq!(get("server:"), Some(server));
    }
}

/// Links of a history line: the item where it is now in the owner's space, never a guess nor a path out of it.
#[test]
fn event_links_follow_the_owner_space() {
    use crate::db::{ShareEvent, ShareEventKind};
    let e = env();
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    root.mkdir(&SafePath::new("Dossier").unwrap()).unwrap();
    for f in ["Dossier/a.txt", "seul.txt"] {
        root.atomic_write(&SafePath::new(f).unwrap(), &mut &b"x"[..]).unwrap();
    }
    let line = |kind, share_path: &str, path: &str| {
        let ev = ShareEvent {
            share_id: "1".into(),
            at: 0,
            kind,
            path: path.into(),
            count: 1,
            bytes: 0,
            share_path: share_path.into(),
            share_end: None,
        };
        let l = super::event_line(crate::i18n::Lang::En, ev, &root);
        (l.url, l.link_url)
    };
    let s = |a: &str, b: &str| (a.to_owned(), b.to_owned());
    use ShareEventKind::{Created, Download, Drop, Zip};
    // Whole space: the root folder, items by their full path.
    assert_eq!(
        line(Download, "", "Dossier/a.txt"),
        s("/web/view/Dossier/a.txt", "/web/files/")
    );
    // Folder link: the item inside; a ZIP of the whole folder records its own name → the folder.
    assert_eq!(
        line(Drop, "Dossier", "a.txt"),
        s("/web/view/Dossier/a.txt", "/web/files/Dossier/?voir=a%2Etxt#vise")
    );
    // A file right at the root of a whole-space link: the root opened at it; deeper, the link's own folder.
    assert_eq!(
        line(Download, "", "seul.txt"),
        s("/web/view/seul.txt", "/web/files/?voir=seul%2Etxt#vise")
    );
    assert_eq!(
        line(Zip, "Dossier", "Dossier"),
        s("/web/files/Dossier/", "/web/files/Dossier/")
    );
    // File link: the name of the file itself.
    assert_eq!(
        line(Download, "seul.txt", "seul.txt"),
        s("/web/view/seul.txt", "/web/view/seul.txt")
    );
    // Gone, another name, no file, or a path out of the link: no link.
    assert_eq!(line(Download, "Absent", "a.txt"), s("", ""));
    assert_eq!(line(Download, "Dossier", "b.txt"), s("", "/web/files/Dossier/"));
    assert_eq!(line(Created, "Dossier", ""), s("", "/web/files/Dossier/"));
    assert_eq!(line(Download, "Dossier", "../seul.txt"), s("", "/web/files/Dossier/"));
}

/// Static files: revalidated on every load, so an upgrade shows at once (an old `text.js` kept an hour hid a fix);
/// unchanged → 304 with no body, whatever the list or weak form of the browser's tag.
#[tokio::test]
async fn static_files_revalidate_by_etag() {
    let e = env();
    let app = &e.app;
    // Code: revalidated every time; icons (CSS masks, invisible until answered): kept a day.
    for (path, cache) in [
        ("/static/text.js", "no-cache"),
        ("/static/app.js", "no-cache"),
        ("/static/theme.js", "no-cache"),
        ("/static/app.css", "no-cache"),
        ("/static/icons/logo.svg", "public, max-age=86400"),
        ("/static/icons/a-menu.svg", "public, max-age=86400"),
    ] {
        let (s, h, body) = call(app, "GET", path, &[A], "").await;
        assert_eq!(s, StatusCode::OK);
        assert!(!body.is_empty());
        assert_eq!(h["cache-control"], cache, "{path}");
        let tag = h["etag"].to_str().unwrap().to_owned();
        assert!(tag.len() == 18 && tag.starts_with('"') && tag.ends_with('"'), "{tag}");
        for sent in [tag.clone(), format!("W/{tag}"), format!("\"0\", {tag}")] {
            let (s, h, body) = call(app, "GET", path, &[A, ("if-none-match", sent.as_str())], "").await;
            assert_eq!((s, body.as_str()), (StatusCode::NOT_MODIFIED, ""), "{sent}");
            assert_eq!(h["etag"], tag.as_str());
        }
        for other in ["\"0\"", "*x", ""] {
            let (s, _, _) = call(app, "GET", path, &[A, ("if-none-match", other)], "").await;
            assert_eq!(s, StatusCode::OK, "{other}");
        }
    }
    // Two different files never share a tag.
    let tag = |p: &'static str| async move { call(app, "GET", p, &[A], "").await.1["etag"].clone() };
    assert_ne!(tag("/static/app.js").await, tag("/static/text.js").await);
}

/// A folder link from a search or a favorite (`?voir=<name>#vise`): the page holding the item, that item marked once
/// and scrolled to; an unknown name changes nothing; another tenant's folder of the same name shows its own items.
#[tokio::test]
async fn folder_link_opens_at_the_item() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    root.mkdir(&SafePath::new("Livres").unwrap()).unwrap();
    for i in 0..120 {
        let f = SafePath::new(&format!("Livres/f{i:03}.md")).unwrap();
        root.atomic_write(&f, &mut &b"x"[..]).unwrap();
    }
    let at = |voir: &str, extra: &str| {
        let uri = format!("/web/files/Livres/?n=50&voir={voir}{extra}");
        async move { call(app, "GET", &uri, &c, "").await.2 }
    };
    let marked = |page: &str| page.matches("id=\"vise\"").count();
    // Boundaries of the 50-item pages: last of page 1, first of page 2, last item.
    for (name, page_no) in [("f000.md", 1), ("f049.md", 1), ("f050.md", 2), ("f119.md", 3)] {
        let page = at(name, "").await;
        assert!(page.contains(&format!("Page {page_no} of 3")), "{name}");
        assert_eq!(marked(&page), 1, "{name}");
        let row = &page[page.find("id=\"vise\"").unwrap()..];
        assert!(row.contains(&format!("data-name=\"{name}\"")), "{name}");
    }
    // The item wins over `page`; an unknown or hostile name: the page asked for, nothing marked, nothing echoed.
    assert!(at("f075.md", "&page=0").await.contains("Page 2 of 3"));
    let none = at("absent.md", "&page=1").await;
    assert!(none.contains("Page 2 of 3") && marked(&none) == 0);
    let bad = at("%3Cscript%3Ex", "").await;
    assert!(marked(&bad) == 0 && !bad.contains("<script>x"));
    // Grid view: the card is marked the same way.
    let grid = at("f010.md", "&view=grid").await;
    assert!(grid.contains("class=\"carte-fichier vise\" id=\"vise\""));
    // Another tenant: same user name, same folder name, only its own item.
    let (bc, _) = login(&e, B, "pw-alice").await;
    let tb = e.state.registry.by_name("beta").unwrap();
    let rb = tb.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    rb.mkdir(&SafePath::new("Livres").unwrap()).unwrap();
    let (_, _, other) = call(
        app,
        "GET",
        "/web/files/Livres/?voir=f050.md",
        &[B, ("cookie", bc.as_str())],
        "",
    )
    .await;
    assert!(marked(&other) == 0 && !other.contains("f050.md"));
    // The search result links its folder that way.
    let (_, _, found) = call(app, "GET", "/web/search?q=f050", &c, "").await;
    assert!(
        found.contains("<a href=\"/web/files/Livres/?voir=f050%2Emd#vise\" title=\"Livres\">Livres</a>"),
        "{found}"
    );
    // Deep in the tree, long parent name: only the parent, cut at 25 characters; the whole path as a tooltip.
    let deep = "Archives/2024/Bibliotheque municipale de Rennes";
    let h = [A, ("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    for d in ["Archives", "Archives/2024", deep] {
        send(app, "MKCOL", &format!("/web/dav/{}", d.replace(' ', "%20")), &h, b"").await;
    }
    send(
        app,
        "PUT",
        &format!("/web/dav/{}/note-unique.md", deep.replace(' ', "%20")),
        &h,
        b"x",
    )
    .await;
    let (_, _, found) = call(app, "GET", "/web/search?q=note-unique", &c, "").await;
    assert!(
        found.contains(&format!("title=\"{deep}\">Bibliotheque municipale d…</a>, ")),
        "{found}"
    );
    assert!(!found.contains(">Archives/2024/"), "no full path shown");
}

proptest::proptest! {
    /// Whatever the folder size and page size, the page chosen for `find` holds it.
    #[test]
    fn the_page_chosen_holds_the_item(n in 1usize..40, per in 1usize..12, k in 0usize..40) {
        let k = k % n;
        let dir = tempfile::tempdir().unwrap();
        let root = crate::fs::Root::open_dir(dir.path()).unwrap();
        root.ensure_layout().unwrap();
        for i in 0..n {
            root.atomic_write(&SafePath::new(&format!("f{i:03}")).unwrap(), &mut &b"x"[..]).unwrap();
        }
        let name = format!("f{k:03}");
        let l = super::list(&root, None, "name", false, (0, per), (false, true), Some(&name)).unwrap();
        proptest::prop_assert_eq!(l.page, k / per);
        proptest::prop_assert!(l.entries.iter().any(|e| e.name == name));
        // Without `find`, or an absent one: the page asked for.
        let l = super::list(&root, None, "name", false, (1, per), (false, true), Some("absent")).unwrap();
        proptest::prop_assert_eq!(l.page, 1);
    }
}

/// Text size (Account › Appearance): three choices, normal checked, translated. How theme.js applies them:
/// tests/js/theme.test.mjs; the layout itself: previews.
#[tokio::test]
async fn text_size_choice() {
    let e = env();
    let app = &e.app;
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let page = call(app, "GET", "/web/account", &[A, ("cookie", cookie.as_str())], "")
        .await
        .2;
    let sizes = &page[page.find("data-tailles").expect("text size choice")..];
    let sizes = &sizes[..sizes.find("</fieldset>").unwrap()];
    for v in ["normal\" checked", "grand\"", "tres-grand\""] {
        assert!(sizes.contains(&format!("name=\"taille\" value=\"{v}")), "{v}: {sizes}");
    }
    let fr = [A, ("cookie", cookie.as_str()), ("accept-language", "fr")];
    let page = call(app, "GET", "/web/account", &fr, "").await.2;
    assert!(page.contains("Taille du texte") && page.contains("Très grande"));
}

/// Phones: the top bar gets a search link and a menu (native popover) holding every link; the listing carries size and
/// date under the name; the two new icons are in the closed list.
#[tokio::test]
async fn phone_layout_is_pared_down() {
    let e = env();
    let app = &e.app;
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    root.atomic_write(&SafePath::new("devis.pdf").unwrap(), &mut &b"12345"[..])
        .unwrap();
    let page = call(app, "GET", "/web/files/?view=list", &c, "").await.2;
    assert!(page.contains("class=\"bouton-icone tel-seul\" href=\"/web/search\""));
    assert!(page.contains("popovertarget=\"menu-principal\""));
    let menu = &page[page.find("<nav id=\"menu-principal\" popover").expect("menu")..];
    let menu = &menu[..menu.find("</nav>").unwrap()];
    for href in [
        "/web/files/",
        "/web/favorites",
        "/web/shares",
        "/web/trash",
        "/web/account",
        "/logout",
    ] {
        assert!(menu.contains(href), "{href} in the menu");
    }
    assert!(
        page.contains("<span class=\"lieu tel-seul\">5 B · <time>"),
        "size and date under the name"
    );
    for i in ["a-search.svg", "a-menu.svg"] {
        assert_eq!(
            status(app, "GET", &format!("/static/icons/{i}"), &[A]).await,
            StatusCode::OK
        );
    }
}

/// The selection bar offers "Rename", hidden at first (app.js shows it for exactly one checked item and reuses the
/// row's handler: a WebDAV MOVE the server checks).
#[tokio::test]
async fn selection_bar_offers_rename() {
    let e = env();
    let app = &e.app;
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let page = call(app, "GET", "/web/files/", &[A, ("cookie", cookie.as_str())], "")
        .await
        .2;
    let bar = &page[page.find("data-bulkbar>").expect("selection bar")..];
    let bar = &bar[..bar.find("</div>").unwrap()];
    assert!(
        bar.contains("<button type=\"button\" class=\"js\" data-action=\"rename\" data-renommer-un hidden>"),
        "{bar}"
    );
}

/// White first among the themes offered (it is the default: no theme set); Green still offered. How theme.js picks
/// the theme: tests/js/theme.test.mjs.
#[tokio::test]
async fn white_is_the_default_theme() {
    let e = env();
    let app = &e.app;
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let page = call(app, "GET", "/web/account", &[A, ("cookie", cookie.as_str())], "")
        .await
        .2;
    let select = &page[page.find("<select id=\"theme\" data-themes>").expect("theme choice")..];
    assert!(
        select
            .trim_start_matches("<select id=\"theme\" data-themes>")
            .trim_start()
            .starts_with("<option value=\"blanc\">")
    );
    assert!(select.contains("<option value=\"vert\">"));
}

/// theme.js is loaded in <head> without `defer`, so what it sets (script mode, theme, text size) is there before the
/// first paint; what it sets: tests/js/theme.test.mjs.
#[tokio::test]
async fn theme_script_runs_before_the_first_paint() {
    let e = env();
    let app = &e.app;
    let (cookie, _) = login(&e, A, "pw-alice").await;
    let page = call(app, "GET", "/web/files/", &[A, ("cookie", cookie.as_str())], "")
        .await
        .2;
    let head = &page[..page.find("</head>").unwrap()];
    assert!(
        head.contains("<script src=\"/static/theme.js\"></script>"),
        "not deferred"
    );
}

/// Copy and duplicate from the web (selection bar, "Move or copy to…" dialog): a copy never replaces anything (first
/// free name, numbered), keeps the content under a new identity, copies folders whole; duplicate copies beside; moving
/// into the folder the selection is in is refused with a message; a folder never goes into itself; CSRF required;
/// another tenant reaches nothing of alpha's.
#[tokio::test]
async fn copy_and_duplicate_from_the_web() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let d = disk(&e);
    std::fs::create_dir_all(d.join("Docs/Sub")).unwrap();
    std::fs::create_dir_all(d.join("Dest")).unwrap();
    std::fs::write(d.join("Docs/a.txt"), b"A").unwrap();
    std::fs::write(d.join("Docs/v1.2"), b"no extension: a file named v1.2").unwrap();
    std::fs::write(d.join("Docs/Sub/b.txt"), b"B").unwrap();
    std::fs::write(d.join("Dest/a.txt"), b"already here").unwrap();
    let bulk = |body: String| async move { call(app, "POST", "/web/bulk", &c, &body).await };
    let t = e.state.registry.by_name("alpha").unwrap();
    let root = t.data_root().open_subdir(&SafePath::new("alice").unwrap()).unwrap();
    let id = |p: &str| root.meta(Some(&SafePath::new(p).unwrap())).unwrap().id;

    // Copy to another folder: the name taken there gets a number, nothing replaced; a folder copied whole.
    let (s, h, _) = bulk(format!("csrf={csrf}&dir=Docs&op=copy&dest=%2FDest&item=a.txt&item=Sub")).await;
    assert_eq!(
        (s, h["location"].to_str().unwrap()),
        (StatusCode::SEE_OTHER, "/web/files/Docs/?op=copy&ok=2&ko=0&to=Dest")
    );
    assert_eq!(std::fs::read(d.join("Dest/a.txt")).unwrap(), b"already here");
    assert_eq!(std::fs::read(d.join("Dest/a (2).txt")).unwrap(), b"A");
    assert_eq!(std::fs::read(d.join("Dest/Sub/b.txt")).unwrap(), b"B");
    assert_eq!(std::fs::read(d.join("Docs/a.txt")).unwrap(), b"A", "the source stays");
    assert_ne!(id("Dest/a (2).txt"), id("Docs/a.txt"), "a copy is a new item");

    // Duplicate: beside, numbered, again and again; a dotted name with no real extension keeps it whole.
    for _ in 0..2 {
        let (s, h, _) = bulk(format!(
            "csrf={csrf}&dir=Docs&op=duplicate&item=a.txt&item=Sub&item=v1.2"
        ))
        .await;
        assert_eq!(
            (s, h["location"].to_str().unwrap()),
            (StatusCode::SEE_OTHER, "/web/files/Docs/?op=duplicate&ok=3&ko=0&to=Docs")
        );
    }
    for p in [
        "Docs/a (2).txt",
        "Docs/a (3).txt",
        "Docs/Sub (2)/b.txt",
        "Docs/Sub (3)/b.txt",
        "Docs/v1 (2).2",
    ] {
        assert!(d.join(p).exists(), "{p}");
    }
    // A folder never has an extension: `v2.0` gives `v2.0 (2)`.
    std::fs::create_dir_all(d.join("Docs/v2.0")).unwrap();
    bulk(format!("csrf={csrf}&dir=Docs&op=duplicate&item=v2.0")).await;
    assert!(d.join("Docs/v2.0 (2)").is_dir() && !d.join("Docs/v2 (2).0").exists());
    let (_, _, page) = call(app, "GET", "/web/files/Docs/?op=duplicate&ok=3&ko=0", &c, "").await;
    assert!(page.contains("3 items copied."), "notice");
    // "Copy here" to the folder the selection is in: the same as duplicate.
    let (_, h, _) = bulk(format!("csrf={csrf}&dir=Docs&op=copy&dest=%2FDocs&item=a.txt")).await;
    assert_eq!(
        h["location"].to_str().unwrap(),
        "/web/files/Docs/?op=copy&ok=1&ko=0&to=Docs&name=a%20%284%29%2Etxt"
    );
    assert!(d.join("Docs/a (4).txt").exists());

    // Move into the folder it is already in: refused, said so, nothing moved.
    let (s, _, page) = bulk(format!("csrf={csrf}&dir=Docs&op=move&dest=%2FDocs&item=a.txt")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(page.contains("Already in this folder"));
    assert!(d.join("Docs/a.txt").exists());
    // A folder into itself: counted as a failure, nothing created.
    let (_, h, _) = bulk(format!("csrf={csrf}&dir=Docs&op=copy&dest=%2FDocs%2FSub&item=Sub")).await;
    assert_eq!(h["location"].to_str().unwrap(), "/web/files/Docs/?op=copy&ok=0&ko=1");
    assert!(!d.join("Docs/Sub/Sub").exists());
    // No destination, a missing one, no CSRF token: nothing copied.
    let (s, _, _) = bulk(format!("csrf={csrf}&dir=Docs&op=copy&item=a.txt")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = bulk(format!("csrf={csrf}&dir=Docs&op=copy&dest=%2FNowhere&item=a.txt")).await;
    assert_ne!(s, StatusCode::SEE_OTHER);
    assert!(!d.join("Nowhere").exists());
    let (s, _, _) = bulk("dir=Docs&op=duplicate&item=a.txt".to_owned()).await;
    assert_ne!(s, StatusCode::SEE_OTHER);
    assert!(!d.join("Docs/a (5).txt").exists());

    // Another tenant: its own (empty) space only; alpha's files untouched.
    let before = std::fs::read_dir(d.join("Docs")).unwrap().count();
    let (bc, bcsrf) = login(&e, B, "pw-alice").await;
    let (s, _, _) = call(
        app,
        "POST",
        "/web/bulk",
        &[B, ("cookie", bc.as_str())],
        &format!("csrf={bcsrf}&dir=Docs&op=duplicate&item=a.txt"),
    )
    .await;
    assert_ne!(s, StatusCode::SEE_OTHER);
    assert_eq!(std::fs::read_dir(d.join("Docs")).unwrap().count(), before);

    // The dialog marks the folder the selection is in (only "Duplicate" there), at the root too; the bar offers it.
    let (_, _, page) = call(app, "GET", "/web/files/Docs/", &c, "").await;
    assert!(
        page.contains("value=\"/Docs\" form=\"selection\" data-ici>"),
        "current folder marked"
    );
    assert!(page.contains("name=\"op\" value=\"duplicate\""));
    assert!(page.contains("value=\"copy\" class=\"copier-ici\" data-move>Copy here"));
    // The row's button opens the same dialog: named for both.
    assert!(page.contains("title=\"Move or copy\" aria-label=\"Move or copy a.txt\""));
    let (_, _, home) = call(app, "GET", "/web/files/", &c, "").await;
    assert!(
        home.contains("value=\"/\" form=\"selection\" data-ici>"),
        "root marked at the root"
    );
    assert!(!home.contains("value=\"/Docs\" form=\"selection\" data-ici>"));
}

/// Moving onto a taken name: the item keeps its content and identity under the first free name (`Photos (2)`, then
/// `(3)`; a file keeps its extension last), what was there is untouched; nothing free up to 99, a folder into itself,
/// a missing item: refused, nothing moved; the other tenant's session moves nothing.
#[tokio::test]
async fn move_onto_a_taken_name_takes_the_next_free_one() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let d = disk(&e).join("M");
    for p in ["Photos", "B/Photos", "C/Photos", "Plein"] {
        std::fs::create_dir_all(d.join(p)).unwrap();
    }
    std::fs::write(d.join("Photos/x.jpg"), b"moi").unwrap();
    std::fs::write(d.join("B/Photos/x.jpg"), b"deja la").unwrap();
    std::fs::write(d.join("a.txt"), b"a").unwrap();
    std::fs::write(d.join("B/a.txt"), b"autre").unwrap();
    let ino = |p: &str| std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(d.join(p)).unwrap());
    let before = ino("Photos/x.jpg");
    let mv = |dir: &str, dest: &str, item: &str| {
        let body = format!("csrf={csrf}&dir={dir}&op=move&dest={dest}&item={item}");
        async move {
            call(app, "POST", "/web/bulk", &c, &body).await.1["location"]
                .to_str()
                .unwrap()
                .to_owned()
        }
    };
    assert_eq!(
        mv("M", "M%2FB", "Photos").await,
        "/web/files/M/?op=move&ok=1&ko=0&to=M%2FB&name=Photos%20%282%29"
    );
    assert_eq!(std::fs::read(d.join("B/Photos (2)/x.jpg")).unwrap(), b"moi");
    assert_eq!(ino("B/Photos (2)/x.jpg"), before, "moved, not copied");
    assert_eq!(std::fs::read(d.join("B/Photos/x.jpg")).unwrap(), b"deja la");
    assert!(!d.join("Photos").exists());
    // The message: the new name opens the destination with the item marked, the destination is a link too.
    let (_, _, p) = call(
        app,
        "GET",
        "/web/files/M/?op=move&ok=1&ko=0&to=M%2FB&name=Photos%20%282%29",
        &c,
        "",
    )
    .await;
    assert!(p.contains("« <a href=\"/web/files/M/B/?voir=Photos%20%282%29#vise\">Photos (2)</a> » moved to <a href=\"/web/files/M/B/\">B</a>."), "{p}");
    let (_, _, p) = call(app, "GET", "/web/files/M/B/?voir=Photos%20%282%29", &c, "").await;
    assert!(p.contains("id=\"vise\"") && p.contains("data-name=\"Photos (2)\""));
    // Several items: the count and the destination; the root is named; failures said after.
    let (_, _, p) = call(app, "GET", "/web/files/M/?op=copy&ok=2&ko=1&to=", &c, "").await;
    assert!(
        p.contains("2 items copied to <a href=\"/web/files/\">My files</a>. 1 item not processed"),
        "{p}"
    );
    // Hostile or meaningless values: no link, the plain count (only the message is looked at).
    let banner = |p: &str| {
        p.split("role=\"status\">")
            .nth(1)
            .and_then(|b| b.split("</p>").next())
            .unwrap_or("")
            .to_owned()
    };
    for q in [
        "to=..%2Fbeta&name=x",
        "to=.trash&name=x",
        "to=B&name=..%2Fx",
        "to=B&name=a%2Fb",
    ] {
        let (_, _, p) = call(app, "GET", &format!("/web/files/M/?op=move&ok=1&ko=0&{q}"), &c, "").await;
        assert!(
            !p.contains("..%2F") && !p.contains("/web/files/.trash") && !p.contains("voir=a%2Fb"),
            "{q}"
        );
    }
    let (_, _, p) = call(app, "GET", "/web/files/M/?op=move&ok=1&ko=0&to=..%2Fbeta", &c, "").await;
    assert_eq!(banner(&p), "1 item moved.");
    let (_, _, p) = call(app, "GET", "/web/files/M/?op=delete&ok=1&ko=0&to=B&name=x", &c, "").await;
    assert_eq!(banner(&p), "1 item moved to the trash.");
    // Next one: (3); a file: before its extension.
    assert_eq!(
        mv("M%2FC", "M%2FB", "Photos").await,
        "/web/files/M/C/?op=move&ok=1&ko=0&to=M%2FB&name=Photos%20%283%29"
    );
    assert!(d.join("B/Photos (3)").is_dir());
    assert_eq!(
        mv("M", "M%2FB", "a.txt").await,
        "/web/files/M/?op=move&ok=1&ko=0&to=M%2FB&name=a%20%282%29%2Etxt"
    );
    assert_eq!(std::fs::read(d.join("B/a (2).txt")).unwrap(), b"a");
    assert_eq!(std::fs::read(d.join("B/a.txt")).unwrap(), b"autre");
    // Every name taken up to 99: refused, nothing moved, nothing overwritten.
    std::fs::write(d.join("n.txt"), b"n").unwrap();
    std::fs::write(d.join("Plein/n.txt"), b"0").unwrap();
    for i in 2..=99 {
        std::fs::write(d.join(format!("Plein/n ({i}).txt")), b"0").unwrap();
    }
    assert_eq!(mv("M", "M%2FPlein", "n.txt").await, "/web/files/M/?op=move&ok=0&ko=1");
    assert!(d.join("n.txt").exists() && std::fs::read_dir(d.join("Plein")).unwrap().count() == 99);
    // A folder into itself, a missing item: refused (no numbered attempt makes them work).
    assert_eq!(mv("M", "M%2FB%2FPhotos", "B").await, "/web/files/M/?op=move&ok=0&ko=1");
    assert_eq!(mv("M", "M%2FB", "absent").await, "/web/files/M/?op=move&ok=0&ko=1");
    assert!(d.join("B/Photos").is_dir() && !d.join("B/absent").exists() && !d.join("B/absent (2)").exists());
    // Other tenant: alpha's session moves nothing there.
    let body = format!("csrf={csrf}&dir=M&op=move&dest=M%2FB&item=n.txt");
    let (_, h, _) = call(app, "POST", "/web/bulk", &[B, ("cookie", cookie.as_str())], &body).await;
    assert!(
        h.get("location")
            .is_none_or(|l| !l.to_str().unwrap().contains("op=move"))
    );
    assert!(d.join("n.txt").exists() && !d.join("B/n.txt").exists());
}

proptest::proptest! {
    /// Moving onto any set of taken names: never an overwrite; the item lands at the first free name of `free_names`
    /// (or stays put if none), with its content; what was there is unchanged.
    #[test]
    fn move_takes_the_first_free_name(taken in proptest::collection::btree_set(0usize..6, 0..6), dir: bool) {
        let tmp = tempfile::tempdir().unwrap();
        let root = crate::fs::Root::open_dir(tmp.path()).unwrap();
        root.ensure_layout().unwrap();
        let name = if dir { "Photos" } else { "a.txt" };
        let all: Vec<String> = super::free_names(name, dir).take(6).collect();
        let p = |s: &str| SafePath::new(s).unwrap();
        root.mkdir(&p("dest")).unwrap();
        for &i in &taken {
            root.atomic_write(&p(&format!("dest/{}", all[i])), &mut &b"deja"[..]).unwrap();
        }
        if dir {
            root.mkdir(&p(name)).unwrap();
            root.atomic_write(&p(&format!("{name}/x")), &mut &b"moi"[..]).unwrap();
        } else {
            root.atomic_write(&p(name), &mut &b"moi"[..]).unwrap();
        }
        let names = all.iter().map(|n| SafePath::new(&format!("dest/{n}")));
        let moved = super::to_free_name(&p(name), names, |t| root.rename(&p(name), t, false, "alice"));
        let free = (0..6).find(|i| !taken.contains(i));
        proptest::prop_assert_eq!(moved.map(|t| t.as_str().to_owned()), free.map(|i| format!("dest/{}", all[i])));
        for &i in &taken {
            proptest::prop_assert_eq!(std::fs::read(tmp.path().join("dest").join(&all[i])).unwrap(), b"deja");
        }
        if let Some(i) = free {
            let at = tmp.path().join("dest").join(&all[i]);
            let got = std::fs::read(if dir { at.join("x") } else { at }).unwrap();
            proptest::prop_assert_eq!(got, b"moi");
            proptest::prop_assert!(!tmp.path().join(name).exists());
        } else {
            proptest::prop_assert!(tmp.path().join(name).exists());
        }
    }
}

/// Drag and drop posts the "Move" form as `dnd.bulkMove` writes it (tests/js/dnd.test.mjs): every name encoded,
/// slashes of the paths as `%2F`; a taken name gives the next free one, and the answer says where it went.
#[tokio::test]
async fn drag_and_drop_form_moves_to_a_free_name() {
    let e = env();
    let app = &e.app;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let d = disk(&e);
    std::fs::create_dir_all(d.join("Mes docs")).unwrap();
    std::fs::create_dir_all(d.join("Dest/B B/a&b=c")).unwrap();
    std::fs::write(d.join("Mes docs/a&b=c"), b"moi").unwrap();
    std::fs::write(d.join("Mes docs/café.txt"), b"cafe").unwrap();
    let tok: String = csrf.bytes().map(|b| format!("%{b:02X}")).collect();
    let body = format!("csrf={tok}&dir=Mes%20docs&op=move&dest=Dest%2FB%20B&item=caf%C3%A9.txt&item=a%26b%3Dc");
    let (s, h, _) = call(app, "POST", "/web/bulk", &c, &body).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(
        h["location"].to_str().unwrap(),
        "/web/files/Mes%20docs/?op=move&ok=2&ko=0&to=Dest%2FB%20B"
    );
    assert_eq!(std::fs::read(d.join("Dest/B B/café.txt")).unwrap(), b"cafe");
    assert_eq!(std::fs::read(d.join("Dest/B B/a&b=c (2)")).unwrap(), b"moi");
    assert!(d.join("Dest/B B/a&b=c").is_dir());
    // A tree folder dropped on another, from the root to the root's child; without the token: refused.
    std::fs::create_dir_all(d.join("T")).unwrap();
    let (_, h, _) = call(
        app,
        "POST",
        "/web/bulk",
        &c,
        &format!("csrf={tok}&dir=&op=move&dest=Dest&item=T"),
    )
    .await;
    assert_eq!(
        h["location"].to_str().unwrap(),
        "/web/files/?op=move&ok=1&ko=0&to=Dest&name=T"
    );
    let (s, _, _) = call(app, "POST", "/web/bulk", &c, "csrf=&dir=Dest&op=move&dest=&item=T").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(d.join("Dest/T").is_dir());
}

/// Names a copy tries: the name first, then numbered up to 99; a file keeps a real extension last, a folder or a name
/// with no real extension keeps its whole name before the number.
#[test]
fn copy_names() {
    let names = |n: &str, dir: bool| super::free_names(n, dir).collect::<Vec<_>>();
    for (n, dir, second) in [
        ("photo.jpg", false, "photo (2).jpg"),
        ("archive.tar.gz", false, "archive.tar (2).gz"),
        ("README", false, "README (2)"),
        (".env", false, ".env (2)"),
        ("a.", false, "a. (2)"),
        ("v1.2", true, "v1.2 (2)"),
        ("Photos", true, "Photos (2)"),
    ] {
        let all = names(n, dir);
        assert_eq!((all[0].as_str(), all[1].as_str()), (n, second), "{n}");
        assert_eq!(all.len(), 99, "{n}: the name, then 2 to 99");
    }
    assert_eq!(
        names("photo.jpg", false).last().map(String::as_str),
        Some("photo (99).jpg")
    );
}

proptest::proptest! {
    /// For any name: the name itself first, then all different from it and from each other, each a legal name when the
    /// source is (short enough), the extension of a file kept last.
    #[test]
    fn copy_names_are_new_and_legal(raw in "[a-zé .-]{1,20}", dir in proptest::bool::ANY) {
        let Ok(p) = SafePath::new(&raw) else { return Ok(()) };
        let name = p.as_str().to_owned();
        let all: Vec<String> = super::free_names(&name, dir).collect();
        proptest::prop_assert_eq!(&all[0], &name);
        let set: std::collections::HashSet<&String> = all.iter().collect();
        proptest::prop_assert_eq!(set.len(), all.len(), "all different");
        for n in &all[1..] {
            proptest::prop_assert!(SafePath::new(n).is_ok(), "{:?} from {:?}", n, name);
            if let (false, Some((s, e))) = (dir, name.rsplit_once('.'))
                && !s.is_empty()
                && !e.is_empty()
            {
                let ext = format!(".{e}");
                proptest::prop_assert!(n.ends_with(&ext), "{:?} keeps {:?}", n, ext);
            }
        }
    }
}
