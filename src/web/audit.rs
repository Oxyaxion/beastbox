//! Front end audit (TESTING.md step 7): every page the server renders, with real data, is checked for well-formed HTML,
//! accessibility basics and the security rules the CSP and CSRF depend on; the stylesheet has no class nobody uses and
//! the pages use no class it lacks; the scripts never build HTML from strings nor evaluate code.

use super::tests::{login, make_share};
use crate::fs::SafePath;
use crate::http::tests::{A, basic, call, env, send, token};
use std::collections::{BTreeMap, BTreeSet};

/// Elements without an end tag.
const VOID: [&str; 14] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr", "!doctype",
];

struct Tag {
    name: String,
    closing: bool,
    self_closing: bool,
    attrs: BTreeMap<String, String>,
}

/// The tags of a page, in order (comments skipped). Attribute values are quoted with `"`, as the templates write them.
fn tags(html: &str) -> Result<Vec<Tag>, String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        rest = rest.get(i + 1..).unwrap_or_default();
        if let Some(r) = rest.strip_prefix("!--") {
            let end = r.find("-->").ok_or("unclosed comment")?;
            rest = r.get(end + 3..).unwrap_or_default();
            continue;
        }
        let (closing, r) = match rest.strip_prefix('/') {
            Some(r) => (true, r),
            None => (false, rest),
        };
        let name_len = r
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .ok_or("unclosed tag")?;
        let name = r.get(..name_len).unwrap_or_default().to_ascii_lowercase();
        let mut r = r.get(name_len..).unwrap_or_default();
        let mut attrs = BTreeMap::new();
        loop {
            r = r.trim_start();
            if let Some(after) = r.strip_prefix("/>") {
                out.push(Tag {
                    name: name.clone(),
                    closing,
                    self_closing: true,
                    attrs,
                });
                rest = after;
                break;
            }
            if let Some(after) = r.strip_prefix('>') {
                out.push(Tag {
                    name: name.clone(),
                    closing,
                    self_closing: false,
                    attrs,
                });
                rest = after;
                break;
            }
            let k_len = r
                .find(|c: char| c.is_whitespace() || c == '=' || c == '>' || c == '/')
                .ok_or("bad attribute")?;
            let key = r.get(..k_len).unwrap_or_default().to_ascii_lowercase();
            r = r.get(k_len..).unwrap_or_default();
            let mut value = String::new();
            if let Some(after) = r.strip_prefix("=\"") {
                let end = after.find('"').ok_or("unclosed attribute value")?;
                value = after.get(..end).unwrap_or_default().to_owned();
                r = after.get(end + 1..).unwrap_or_default();
            } else if r.starts_with('=') {
                return Err(format!("unquoted value for {key} in <{name}>"));
            }
            if attrs.insert(key.clone(), value).is_some() {
                return Err(format!("duplicate attribute {key} in <{name}>"));
            }
        }
        // Raw text: skip to its end tag.
        if !closing
            && (name == "script" || name == "style" || name == "textarea")
            && !out.last().is_some_and(|t| t.self_closing)
        {
            let end = rest.find(&format!("</{name}>")).ok_or(format!("unclosed <{name}>"))?;
            if name == "script" && !rest.get(..end).unwrap_or_default().trim().is_empty() {
                return Err("inline script".into());
            }
            rest = rest.get(end..).unwrap_or_default();
        }
    }
    Ok(out)
}

/// The rules for one page; `Err` lists every breach.
fn audit(url: &str, html: &str) -> Result<BTreeSet<String>, Vec<String>> {
    let mut bad = Vec::new();
    let all = match tags(html) {
        Ok(t) => t,
        Err(e) => return Err(vec![format!("{url}: {e}")]),
    };
    // Well-formed: every element closed, in order.
    let mut stack: Vec<&str> = Vec::new();
    for t in &all {
        if t.closing {
            match stack.pop() {
                Some(open) if open == t.name => {}
                other => bad.push(format!("{url}: </{}> closes <{}>", t.name, other.unwrap_or("nothing"))),
            }
        } else if !t.self_closing && !VOID.contains(&t.name.as_str()) {
            stack.push(&t.name);
        }
    }
    if !stack.is_empty() {
        bad.push(format!("{url}: left open {stack:?}"));
    }
    // A field inside `.nojs` (hidden once the script runs) is never `required`: the browser would block the submit
    // before the script's own confirmation, without showing why (the trash buttons did nothing).
    let mut nojs: Vec<bool> = Vec::new();
    for t in &all {
        if t.closing {
            nojs.pop();
            continue;
        }
        let here = t
            .attrs
            .get("class")
            .is_some_and(|c| c.split_whitespace().any(|w| w == "nojs"));
        if (here || nojs.contains(&true)) && t.attrs.contains_key("required") {
            bad.push(format!(
                "{url}: required <{}> inside .nojs (hidden with the script on)",
                t.name
            ));
        }
        if !t.self_closing && !VOID.contains(&t.name.as_str()) {
            nojs.push(here);
        }
    }
    let opens: Vec<&Tag> = all.iter().filter(|t| !t.closing).collect();
    let attr = |t: &Tag, k: &str| t.attrs.get(k).cloned();
    // Unique ids, labels pointing at a field.
    let mut ids = BTreeSet::new();
    for t in &opens {
        if let Some(id) = attr(t, "id")
            && !ids.insert(id.clone())
        {
            bad.push(format!("{url}: duplicate id {id}"));
        }
    }
    let label_for: BTreeSet<String> = opens
        .iter()
        .filter(|t| t.name == "label")
        .filter_map(|t| attr(t, "for"))
        .collect();
    for f in &label_for {
        if !ids.contains(f) {
            bad.push(format!("{url}: <label for={f}> without such id"));
        }
    }
    // Fields have a name for assistive technologies: a label (for= or around it) or an aria label.
    let mut in_label = 0usize;
    let mut in_form_post = None::<bool>; // has csrf so far
    let mut form_action = String::new();
    let mut classes = BTreeSet::new();
    for t in &all {
        if let Some(c) = t.attrs.get("class") {
            classes.extend(c.split_whitespace().filter(|c| !c.contains("{{")).map(str::to_owned));
        }
        match (t.name.as_str(), t.closing) {
            ("label", false) => in_label += 1,
            ("label", true) => in_label = in_label.saturating_sub(1),
            ("form", false) => {
                form_action = attr(t, "action").unwrap_or_default();
                in_form_post = (attr(t, "method").as_deref() == Some("post")).then_some(false);
            }
            ("form", true) => {
                // CSRF on every POST form, except those without a session: login, a link's password, an activation
                // link (its 256-bit token in the address is what a forged request would lack).
                let public =
                    form_action == "/login" || form_action.starts_with("/s/") || form_action.starts_with("/activate/");
                if in_form_post == Some(false) && !public {
                    bad.push(format!("{url}: POST form to {form_action} without csrf"));
                }
                in_form_post = None;
            }
            ("input", false) if attr(t, "name").as_deref() == Some("csrf") && in_form_post.is_some() => {
                in_form_post = Some(true)
            }
            ("input", false) if attr(t, "name").as_deref() == Some("csrf") => {}
            ("input" | "select" | "textarea", false) => {
                let kind = attr(t, "type").unwrap_or_default();
                let named = in_label > 0
                    || attr(t, "id").is_some_and(|i| label_for.contains(&i))
                    || t.attrs.contains_key("aria-label")
                    || t.attrs.contains_key("aria-labelledby");
                if !matches!(kind.as_str(), "hidden" | "submit" | "button") && !named {
                    bad.push(format!(
                        "{url}: <{} name={:?}> without a label",
                        t.name,
                        attr(t, "name")
                    ));
                }
            }
            ("img", false) if !t.attrs.contains_key("alt") => bad.push(format!("{url}: <img> without alt")),
            ("button", false) if !t.attrs.contains_key("type") => {
                bad.push(format!("{url}: <button> without type ({:?})", attr(t, "class")))
            }
            ("script", false) if !t.attrs.contains_key("src") => bad.push(format!("{url}: inline <script>")),
            ("style", false) => bad.push(format!("{url}: inline <style>")),
            ("a", false)
                if attr(t, "target").as_deref() == Some("_blank")
                    && !attr(t, "rel").is_some_and(|r| r.contains("noopener")) =>
            {
                bad.push(format!("{url}: target=_blank without rel=noopener"))
            }
            _ => {}
        }
        // The CSP forbids inline styles and handlers: none at all, so nothing depends on them.
        for (k, v) in &t.attrs {
            if k == "style" || k.starts_with("on") {
                bad.push(format!("{url}: attribute {k} on <{}>", t.name));
            }
            if (k == "href" || k == "src" || k == "action")
                && v.trim_start().to_ascii_lowercase().starts_with("javascript:")
            {
                bad.push(format!("{url}: javascript: URL"));
            }
        }
    }
    if bad.is_empty() { Ok(classes) } else { Err(bad) }
}

/// Classes defined by the stylesheet (`.name` in selectors, outside property values).
fn css_classes(css: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut depth = 0i32;
    let mut selector = String::new();
    for c in css.chars() {
        match c {
            '{' => {
                if depth == 0 || selector.trim_start().starts_with('@') || depth == 1 && !selector.trim().is_empty() {
                    collect(&selector, &mut out);
                }
                selector.clear();
                depth += 1;
            }
            '}' => {
                selector.clear();
                depth -= 1;
            }
            ';' => selector.clear(),
            _ => selector.push(c),
        }
    }
    fn collect(sel: &str, out: &mut BTreeSet<String>) {
        let sel = strip_comments(sel);
        for (i, c) in sel.char_indices() {
            if c == '.'
                && sel
                    .get(i + 1..)
                    .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_alphabetic()))
            {
                let name: String = sel
                    .get(i + 1..)
                    .unwrap_or_default()
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                    .collect();
                out.insert(name);
            }
        }
    }
    fn strip_comments(s: &str) -> String {
        let mut out = String::new();
        let mut rest = s;
        while let Some(i) = rest.find("/*") {
            out.push_str(rest.get(..i).unwrap_or_default());
            rest = rest
                .get(i..)
                .and_then(|r| r.find("*/").map(|e| r.get(e + 2..).unwrap_or_default()))
                .unwrap_or_default();
        }
        out.push_str(rest);
        out
    }
    out
}

#[tokio::test]
async fn every_page_passes_the_audit() {
    let e = env();
    let app = &e.app;
    let device = basic("alice", &token(&e, "alpha"));
    let a = [A, ("authorization", device.as_str())];
    let f = "/remote.php/dav/files/alice";
    send(app, "MKCOL", &format!("{f}/Docs"), &a, b"").await;
    send(app, "PUT", &format!("{f}/Docs/a.txt"), &a, b"texte").await;
    send(app, "PUT", &format!("{f}/Docs/note.md"), &a, b"# Titre").await;
    send(
        app,
        "PUT",
        &format!("{f}/photo.jpg"),
        &a,
        &crate::nc::thumb::tests::photo(64, 32, 1),
    )
    .await;
    send(app, "PUT", &format!("{f}/jete.txt"), &a, b"x").await;
    send(app, "DELETE", &format!("{f}/jete.txt"), &a, b"").await;
    let (cookie, csrf) = login(&e, A, "pw-alice").await;
    let c = [A, ("cookie", cookie.as_str())];
    let root = e
        .state
        .registry
        .by_name("alpha")
        .unwrap()
        .data_root()
        .open_subdir(&SafePath::new("alice").unwrap())
        .unwrap();
    root.mkdir(&SafePath::new("Boite").unwrap()).unwrap();
    let read = make_share(&e, &cookie, &csrf, "Docs", "&perms=upload&label=L&note=Bonjour").await;
    let file = make_share(&e, &cookie, &csrf, "Docs/a.txt", "&perms=read&hide=1").await;
    let drop = make_share(&e, &cookie, &csrf, "Boite", "&perms=drop").await;
    let pw = make_share(&e, &cookie, &csrf, "photo.jpg", "&perms=read&password=motdepasse1").await;

    let mut pages: Vec<(String, String)> = Vec::new();
    for u in [
        "/web/files/",
        "/web/files/Docs/",
        "/web/files/?view=grid",
        "/web/view/Docs/a.txt",
        "/web/view/Docs/note.md",
        "/web/view/photo.jpg",
        "/web/view/Docs/",
        "/web/shares",
        "/web/account",
        "/web/trash",
        "/web/search?q=a",
        "/web/favorites",
        "/web/edit/Docs/a.txt",
        "/web/edit/Docs/note.md",
    ] {
        pages.push((u.into(), call(app, "GET", u, &c, "").await.2));
    }
    let qr = call(
        app,
        "POST",
        "/web/account/qr",
        &c,
        &format!("csrf={csrf}&password=pw-alice"),
    )
    .await
    .2;
    assert!(qr.contains("<svg role=\"img\""), "the QR code page itself is audited");
    pages.push(("/web/account/qr".into(), qr));
    // Activation pages: an account with a password (asked again); one without (to choose); on a tenant that requires
    // two-step verification, the phone, then the recovery codes; and the page a session is held on there.
    let alpha = e.state.registry.by_name("alpha").unwrap();
    let now = crate::db::now_secs();
    let tok = crate::auth::activation_issue(&e.state.db, &alpha, "alice", now).unwrap();
    pages.push((
        "/activate (current)".into(),
        call(app, "GET", &format!("/activate/{tok}"), &[A], "").await.2,
    ));
    let r = crate::http::tests::env_with(crate::http::Settings {
        two_factor: vec![("alpha".into(), crate::config::TwoFactor::Required)],
        ..Default::default()
    });
    let ra = r.state.registry.by_name("alpha").unwrap();
    std::fs::create_dir(r.a_root.path().join("carol")).unwrap();
    crate::fs::Root::open_dir(&r.a_root.path().join("carol"))
        .unwrap()
        .ensure_layout()
        .unwrap();
    r.state.db.user_add_oidc(&ra, "carol", false).unwrap();
    let tok = crate::auth::activation_issue(&r.state.db, &ra, "carol", now).unwrap();
    let link = format!("/activate/{tok}");
    pages.push((
        "/activate (choose, phone)".into(),
        call(&r.app, "GET", &link, &[A], "").await.2,
    ));
    let s = crate::auth::totp::setup_secret(&ra, &tok);
    let code = format!(
        "{:06}",
        crate::auth::totp::hotp(&s, crate::auth::totp::step(crate::auth::totp::now()))
    );
    let body = format!("new=mon-propre-secret-9&again=mon-propre-secret-9&code={code}");
    let done = call(&r.app, "POST", &link, &[A], &body).await.2;
    assert!(done.contains("<li><code>"), "the recovery codes page itself is audited");
    pages.push(("/activate (recovery codes)".into(), done));
    let (rc, _) = login(&r, A, "pw-alice").await;
    pages.push((
        "/web/2fa-setup".into(),
        call(&r.app, "GET", "/web/2fa-setup", &[A, ("cookie", rc.as_str())], "")
            .await
            .2,
    ));
    for u in [
        "/login".to_owned(),
        format!("/s/{read}"),
        format!("/s/{read}/f/"),
        format!("/s/{file}"),
        format!("/s/{drop}"),
        format!("/s/{pw}"),
        format!("/s/{}", "0".repeat(32)),
    ] {
        pages.push((u.clone(), call(app, "GET", &u, &[A], "").await.2));
    }

    let mut bad = Vec::new();
    let mut used = BTreeSet::new();
    for (u, html) in &pages {
        assert!(html.len() > 200, "{u}: no page");
        match audit(u, html) {
            Ok(c) => used.extend(c),
            Err(b) => bad.extend(b),
        }
    }

    // Stylesheet and scripts: no unused class, no class missing; no HTML built from strings, no evaluated code.
    let css = css_classes(&std::fs::read_to_string("static/app.css").unwrap());
    let mut scripts = String::new();
    for js in ["static/app.js", "static/text.js", "static/theme.js"] {
        let src = std::fs::read_to_string(js).unwrap();
        for danger in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
        ] {
            if src.contains(danger) {
                bad.push(format!("{js}: {danger}"));
            }
        }
        scripts.push_str(&src);
    }
    let mut templates = String::new();
    for entry in std::fs::read_dir("templates").unwrap() {
        templates.push_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap());
    }
    let rust = ["src/web/mod.rs", "src/web/share.rs", "src/web/render.rs"]
        .map(|p| std::fs::read_to_string(p).unwrap())
        .join("");
    // A class is used if a rendered page has it, or a template, script or the Rust code writes it literally (states
    // reached by the scripts, icons chosen by the code).
    let written = |c: &str| {
        // As a whole word between quotes, spaces or template tags (`{% if x %}replie{% else %}brut{% endif %}`).
        let word = |text: &str| {
            text.match_indices(c).any(|(i, _)| {
                let before = text.get(..i).and_then(|b| b.chars().last());
                let after = text.get(i + c.len()..).and_then(|a| a.chars().next());
                matches!(before, Some('"' | '\'' | ' ' | '}')) && matches!(after, Some('"' | '\'' | ' ' | '{'))
            })
        };
        word(&templates) || word(&scripts) || word(&rust) || scripts.contains(&format!(".{c}"))
    };
    // Dynamic families written by the templates, such as `ico-{{ … }}`.
    let families = ["ico-"];
    for c in &css {
        if !used.contains(c) && !written(c) && !families.iter().any(|f| c.starts_with(f)) {
            bad.push(format!("app.css: .{c} is used nowhere"));
        }
    }
    for c in &used {
        if !css.contains(c) && !scripts.contains(c.as_str()) {
            bad.push(format!("page class {c} has no style and no script"));
        }
    }
    assert!(bad.is_empty(), "{} breaches:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn the_audit_catches_what_it_should() {
    let page = |body: &str| format!("<!doctype html><html><head><title>t</title></head><body>{body}</body></html>");
    let caught = |body: &str| audit("t", &page(body)).is_err();
    assert!(audit("t", &page(r#"<form method="post" action="/x"><input type="hidden" name="csrf" value="v"><label for="n">N</label><input id="n" name="n"><button type="submit">ok</button></form>"#)).is_ok());
    for body in [
        "<div><p>unclosed</div>",
        r#"<form method="post" action="/x"><button type="submit">ok</button></form>"#,
        r#"<input name="q">"#,
        r#"<img src="/a.png">"#,
        "<button>ok</button>",
        r#"<p id="a"></p><p id="a"></p>"#,
        r#"<label for="nope">x</label>"#,
        r#"<p style="color:red">x</p>"#,
        r#"<a href="/x" onclick="f()">x</a>"#,
        r#"<a href="javascript:alert(1)">x</a>"#,
        "<script>alert(1)</script>",
        r#"<a href="https://x.example" target="_blank">x</a>"#,
        r#"<label class="enligne nojs"><input type="checkbox" name="c" value="1" required> x</label>"#,
    ] {
        assert!(caught(body), "not caught: {body}");
    }
    assert_eq!(
        css_classes(".a, .b > .c:hover { color: red } @media (x) { .d { x: y } } /* .e */"),
        ["a", "b", "c", "d"].map(String::from).into()
    );
}
