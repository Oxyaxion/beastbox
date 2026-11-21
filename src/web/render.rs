//! Pure functions of the web interface: previews (§8.7), sanitized Markdown, size and date formats.

use crate::i18n::Lang;
use pulldown_cmark::{CowStr, Event, Options, Parser, Tag, TagEnd, html};

/// Maximum size read for a text or Markdown preview.
pub const PREVIEW_MAX: usize = 512 * 1024;

/// Possible preview of a file, from its extension. Everything else is only downloadable.
/// SVG, HTML, XML are **never** displayed (§8: active types served as attachments).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Kind {
    Text,
    Markdown,
    Image(&'static str),
    Pdf,
    Audio(&'static str),
    Video(&'static str),
    None,
}

pub fn kind(name: &str) -> Kind {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "md" | "markdown" => Kind::Markdown,
        "txt" | "log" | "csv" | "tsv" | "json" | "toml" | "yaml" | "yml" | "ini" | "conf" | "cfg" | "rs" | "py"
        | "sh" | "c" | "h" | "go" | "java" | "sql" | "diff" | "patch" => Kind::Text,
        "png" => Kind::Image("image/png"),
        "jpg" | "jpeg" => Kind::Image("image/jpeg"),
        "gif" => Kind::Image("image/gif"),
        "webp" => Kind::Image("image/webp"),
        "avif" => Kind::Image("image/avif"),
        "pdf" => Kind::Pdf,
        "mp3" => Kind::Audio("audio/mpeg"),
        "ogg" | "oga" | "opus" => Kind::Audio("audio/ogg"),
        "flac" => Kind::Audio("audio/flac"),
        "wav" => Kind::Audio("audio/wav"),
        "m4a" => Kind::Audio("audio/mp4"),
        "mp4" | "m4v" => Kind::Video("video/mp4"),
        "webm" => Kind::Video("video/webm"),
        "mov" => Kind::Video("video/quicktime"),
        _ => Kind::None,
    }
}

/// MIME type from the extension (clients' WebDAV search: thumbnails, Photos tab, opening with the right app).
pub fn mime(name: &str) -> &'static str {
    match kind(name) {
        Kind::Image(m) | Kind::Audio(m) | Kind::Video(m) => m,
        Kind::Pdf => "application/pdf",
        Kind::Markdown => "text/markdown",
        Kind::Text => "text/plain",
        Kind::None => "application/octet-stream",
    }
}

/// Extensions of the text files the web interface edits (`Kind::Text` or `Kind::Markdown`, checked by a test): the
/// editor shows the icon and colouring of the name being typed.
pub const TEXT_EXTENSIONS: &[&str] = &[
    "txt", "log", "md", "markdown", "csv", "tsv", "json", "toml", "yaml", "yml", "ini", "conf", "cfg", "rs", "py",
    "sh", "c", "h", "go", "java", "sql", "diff", "patch",
];

/// An item's icon (file in `static/icons/`).
pub fn icon(name: &str, is_dir: bool) -> &'static str {
    if is_dir {
        return "folder";
    }
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match kind(name) {
        Kind::Image(_) => "image",
        Kind::Video(_) => "video",
        Kind::Audio(_) => "audio",
        Kind::Pdf => "pdf",
        Kind::Markdown => "md",
        Kind::Text if matches!(ext.as_str(), "txt" | "log") => "text",
        Kind::Text if matches!(ext.as_str(), "csv" | "tsv") => "sheet",
        Kind::Text if matches!(ext.as_str(), "json" | "toml" | "yaml" | "yml" | "ini" | "conf" | "cfg") => "json",
        Kind::Text => "code",
        Kind::None
            if matches!(
                ext.as_str(),
                "zip" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "zst" | "7z" | "rar"
            ) =>
        {
            "archive"
        }
        Kind::None
            if matches!(
                ext.as_str(),
                "svg" | "heic" | "tif" | "tiff" | "bmp" | "raw" | "cr2" | "nef"
            ) =>
        {
            "image"
        }
        Kind::None if matches!(ext.as_str(), "html" | "htm" | "xml" | "js" | "css" | "ts") => "code",
        Kind::None if matches!(ext.as_str(), "doc" | "docx" | "odt" | "rtf" | "ppt" | "pptx" | "odp") => "doc",
        Kind::None if matches!(ext.as_str(), "xls" | "xlsx" | "ods") => "sheet",
        Kind::None => "file",
    }
}

/// Type to announce for display in the browser, or `None` (attachment).
pub fn inline_mime(name: &str) -> Option<&'static str> {
    match kind(name) {
        Kind::Text | Kind::Markdown => Some("text/plain; charset=utf-8"),
        Kind::Image(m) | Kind::Audio(m) | Kind::Video(m) => Some(m),
        Kind::Pdf => Some("application/pdf"),
        Kind::None => None,
    }
}

fn safe_url(u: &str) -> bool {
    let l = u.trim().to_ascii_lowercase();
    // Relative (no scheme) or http(s)/mailto; `javascript:`, `data:`, `vbscript:`… refused.
    let scheme_free = l
        .find(':')
        .is_none_or(|c| l.find(['/', '?', '#']).is_some_and(|s| s < c));
    l.starts_with("http://") || l.starts_with("https://") || l.starts_with("mailto:") || scheme_free
}

/// Markdown → sanitized HTML: raw HTML is shown as text (escaped), unsafe links point to `#`,
/// images become their alt text (nothing is loaded). Defense in depth: the page has a strict CSP.
pub fn markdown(src: &str) -> String {
    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    let events = Parser::new_ext(src, opts).map(|ev| match ev {
        Event::Html(t) | Event::InlineHtml(t) => Event::Text(t),
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => {
            let dest_url = if safe_url(&dest_url) {
                dest_url
            } else {
                CowStr::Borrowed("#")
            };
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                title,
                id,
            })
        }
        Event::Start(Tag::Image { .. }) => Event::Start(Tag::Emphasis),
        Event::End(TagEnd::Image) => Event::End(TagEnd::Emphasis),
        Event::Start(Tag::HtmlBlock) => Event::Start(Tag::Paragraph),
        Event::End(TagEnd::HtmlBlock) => Event::End(TagEnd::Paragraph),
        ev => ev,
    });
    let mut out = String::new();
    html::push_html(&mut out, events);
    out
}

/// Readable size (binary units), in the language's notation.
pub fn size(lang: Lang, n: u64) -> String {
    const EN: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    const FR: [&str; 5] = ["o", "Kio", "Mio", "Gio", "Tio"];
    let units = match lang {
        Lang::En => &EN,
        Lang::Fr => &FR,
    };
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < units.len() {
        v /= 1024.0;
        i += 1;
    }
    let unit = units.get(i).copied().unwrap_or("B");
    if i == 0 {
        format!("{n} {unit}")
    } else {
        let s = format!("{v:.1} {unit}");
        match lang {
            Lang::En => s,
            Lang::Fr => s.replace('.', ","),
        }
    }
}

/// (year, month, day) from a number of days since 1970-01-01 (H. Hinnant's "civil_from_days" algorithm).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Days since 1970-01-01 of a civil date (inverse of `civil`).
fn days(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Wall time: the timestamp shifted by the server's local time (system time zone, DST included). Day and
/// hour computations are done on it, as on UTC; they are tested with explicit offsets.
fn wall(ts: i64) -> i64 {
    ts.saturating_add(crate::fs::utc_offset(ts))
}

/// Local date and time of a Unix timestamp: `2026-11-15 01:23`.
pub fn date(ts: i64) -> String {
    date_wall(wall(ts))
}

fn date_wall(w: i64) -> String {
    let (y, m, d) = civil(w.div_euclid(86_400));
    let s = w.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", s / 3600, (s % 3600) / 60)
}

const MONTHS: [(&str, &str); 12] = [
    ("January", "janvier"),
    ("February", "février"),
    ("March", "mars"),
    ("April", "avril"),
    ("May", "mai"),
    ("June", "juin"),
    ("July", "juillet"),
    ("August", "août"),
    ("September", "septembre"),
    ("October", "octobre"),
    ("November", "novembre"),
    ("December", "décembre"),
];
const MONTHS_SHORT: [(&str, &str); 12] = [
    ("Jan", "janv."),
    ("Feb", "févr."),
    ("Mar", "mars"),
    ("Apr", "avr."),
    ("May", "mai"),
    ("Jun", "juin"),
    ("Jul", "juil."),
    ("Aug", "août"),
    ("Sep", "sept."),
    ("Oct", "oct."),
    ("Nov", "nov."),
    ("Dec", "déc."),
];

/// Local time: `14:02`.
pub fn hm(ts: i64) -> String {
    hm_wall(wall(ts))
}

fn hm_wall(w: i64) -> String {
    let s = w.rem_euclid(86_400);
    format!("{:02}:{:02}", s / 3600, (s % 3600) / 60)
}

/// Day and month spelled out, the year only if it is not that of `now` (wall times).
fn day_month(lang: Lang, w: i64, wnow: i64, short: bool) -> String {
    let (y, m, d) = civil(w.div_euclid(86_400));
    let (ny, _, _) = civil(wnow.div_euclid(86_400));
    let names = if short { &MONTHS_SHORT } else { &MONTHS };
    let month = usize::try_from(m - 1)
        .ok()
        .and_then(|i| names.get(i))
        .map(|(en, fr)| match lang {
            Lang::En => *en,
            Lang::Fr => *fr,
        })
        .unwrap_or("");
    if y == ny {
        format!("{d} {month}")
    } else {
        format!("{d} {month} {y}")
    }
}

/// Title of a history day: "Today", "Yesterday", "13 November" (local days).
pub fn day_label(lang: Lang, ts: i64, now: i64) -> String {
    day_label_wall(lang, wall(ts), wall(now))
}

fn day_label_wall(lang: Lang, w: i64, wnow: i64) -> String {
    match wnow.div_euclid(86_400) - w.div_euclid(86_400) {
        0 => lang.t("Today").into(),
        1 => lang.t("Yesterday").into(),
        _ => day_month(lang, w, wnow, false),
    }
}

/// Relative moment: "just now", "12 min ago", "3 h ago" (same day), "yesterday at 18:05", "12 Nov".
pub fn ago(lang: Lang, ts: i64, now: i64) -> String {
    ago_wall(lang, now.saturating_sub(ts), wall(ts), wall(now))
}

/// `dt`: (real) seconds elapsed; `w`, `wnow`: wall times, for the days and the time shown.
fn ago_wall(lang: Lang, dt: i64, w: i64, wnow: i64) -> String {
    let days = wnow.div_euclid(86_400) - w.div_euclid(86_400);
    match lang {
        Lang::En => match () {
            _ if dt < 60 => "just now".into(),
            _ if dt < 3600 => format!("{} min ago", dt / 60),
            _ if days == 0 => format!("{} h ago", dt / 3600),
            _ if days == 1 => format!("yesterday at {}", hm_wall(w)),
            _ => day_month(lang, w, wnow, true),
        },
        Lang::Fr => match () {
            _ if dt < 60 => "à l'instant".into(),
            _ if dt < 3600 => format!("il y a {} min", dt / 60),
            _ if days == 0 => format!("il y a {} h", dt / 3600),
            _ if days == 1 => format!("hier à {}", hm_wall(w)),
            _ => format!("le {}", day_month(lang, w, wnow, true)),
        },
    }
}

/// `YYYY-MM-DD` (`<input type="date">` field) → end of that day in local time (Unix timestamp), or `None` if invalid.
pub fn parse_day_end(s: &str) -> Option<i64> {
    let w = parse_day_end_wall(s)?;
    Some(local(w))
}

/// Unix timestamp of a local wall time. Offset taken at the targeted instant (two passes: also right on a DST change day).
fn local(w: i64) -> i64 {
    w - crate::fs::utc_offset(w - crate::fs::utc_offset(w))
}

fn parse_day_end_wall(s: &str) -> Option<i64> {
    (s.split('-').count() == 3)
        .then(|| period_start_wall(s))?
        .map(|w| w + 86_399)
}

/// `YYYY`, `YYYY-MM` or `YYYY-MM-DD` (search `after:` / `before:`) → start of that period in local time.
pub fn period_start(s: &str) -> Option<i64> {
    period_start_wall(s).map(local)
}

fn period_start_wall(s: &str) -> Option<i64> {
    let mut it = s.split('-');
    let mut part = |def: Option<i64>| match it.next() {
        Some(p) if (1..=4).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()) => p.parse().ok(),
        Some(_) => None,
        None => def,
    };
    let (y, m, d) = (part(None)?, part(Some(1))?, part(Some(1))?);
    if it.next().is_some() || !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let n = days(y, m, d);
    // Refuses February 31st & co.: the date must read back identically.
    (civil(n) == (y, m, d)).then_some(n * 86_400)
}

/// Words found highlighted in a name: runs of (text, found). `words` are folded (`index::fold`).
pub fn marks(name: &str, words: &[String]) -> Vec<(String, bool)> {
    let orig: Vec<char> = name.chars().collect();
    // Folded name, and for each of its characters the name's character it comes from.
    let (mut folded, mut from, mut buf) = (Vec::new(), Vec::new(), String::new());
    for (i, c) in orig.iter().enumerate() {
        buf.clear();
        crate::index::fold_into(*c, &mut buf);
        folded.extend(buf.chars());
        from.extend(buf.chars().map(|_| i));
    }
    let mut hit = vec![false; orig.len()];
    for w in words
        .iter()
        .map(|w| w.chars().collect::<Vec<_>>())
        .filter(|w| !w.is_empty())
    {
        for (k, win) in folded.windows(w.len()).enumerate() {
            if win == w.as_slice() {
                for &i in from.iter().skip(k).take(w.len()) {
                    if let Some(h) = hit.get_mut(i) {
                        *h = true;
                    }
                }
            }
        }
    }
    let mut out: Vec<(String, bool)> = Vec::new();
    for (c, h) in orig.into_iter().zip(hit) {
        match out.last_mut() {
            Some((s, last)) if *last == h => s.push(c),
            _ => out.push((c.to_string(), h)),
        }
    }
    out
}

/// Longest folder name shown beside an item, in characters (longer: cut, with "…").
pub const FOLDER_LABEL: usize = 25;

/// A folder as shown beside an item (search, favorites, trash, recent activity): its own name only, the last
/// component of `path`, cut at `FOLDER_LABEL` characters so that the size and date stay in view.
pub fn folder_label(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.char_indices().nth(FOLDER_LABEL) {
        Some((cut, _)) => format!("{}…", name.get(..cut).unwrap_or(name)),
        None => name.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the parent folder's own name; cut after `FOLDER_LABEL` characters (not bytes), never in the middle of one.
    #[test]
    fn folder_label_is_the_parent_cut() {
        let n = |k: usize| "é".repeat(k);
        assert_eq!(folder_label(""), "");
        assert_eq!(folder_label("Livres"), "Livres");
        assert_eq!(folder_label("Archives/2024/Compta/Livres"), "Livres");
        assert_eq!(folder_label(&n(FOLDER_LABEL - 1)), n(FOLDER_LABEL - 1));
        assert_eq!(folder_label(&n(FOLDER_LABEL)), n(FOLDER_LABEL));
        assert_eq!(
            folder_label(&format!("a/{}", n(FOLDER_LABEL + 1))),
            format!("{}…", n(FOLDER_LABEL))
        );
        assert_eq!(folder_label(&"x".repeat(255)).chars().count(), FOLDER_LABEL + 1);
    }

    /// A file can carry any date (`touch`, copy from elsewhere): the pages show something, never panic.
    #[test]
    fn absurd_dates_never_panic() {
        let now = 1_800_000_000;
        for ts in [i64::MIN, -1, 0, 253_402_300_800, i64::MAX] {
            let _ = (date(ts), day_label(Lang::Fr, ts, now), ago(Lang::En, ts, now));
        }
    }

    #[test]
    fn relative_dates() {
        let now = 1_794_754_000; // 2026-11-15 14:46:40 UTC
        // Wall times in UTC (zero offset).
        let ago0 = |ts: i64| ago_wall(Lang::En, now - ts, ts, now);
        let ago0_fr = |ts: i64| ago_wall(Lang::Fr, now - ts, ts, now);
        assert_eq!(ago0(now - 20), "just now");
        assert_eq!(ago0(now - 12 * 60), "12 min ago");
        assert_eq!(ago0(now - 3 * 3600), "3 h ago");
        assert_eq!(ago0(now - 86_400), "yesterday at 14:46");
        assert_eq!(ago0(now - 3 * 86_400), "12 Nov");
        assert_eq!(ago0(now - 400 * 86_400), "11 Oct 2025");
        assert_eq!(ago0_fr(now - 20), "à l'instant");
        assert_eq!(ago0_fr(now - 12 * 60), "il y a 12 min");
        assert_eq!(ago0_fr(now - 3 * 3600), "il y a 3 h");
        assert_eq!(ago0_fr(now - 86_400), "hier à 14:46");
        assert_eq!(ago0_fr(now - 3 * 86_400), "le 12 nov.");
        assert_eq!(ago0_fr(now - 400 * 86_400), "le 11 oct. 2025");
        assert_eq!(day_label_wall(Lang::En, now - 60, now), "Today");
        assert_eq!(day_label_wall(Lang::En, now - 86_400, now), "Yesterday");
        assert_eq!(day_label_wall(Lang::En, now - 2 * 86_400, now), "13 November");
        assert_eq!(day_label_wall(Lang::Fr, now - 60, now), "Aujourd'hui");
        assert_eq!(day_label_wall(Lang::Fr, now - 86_400, now), "Hier");
        assert_eq!(day_label_wall(Lang::Fr, now - 2 * 86_400, now), "13 novembre");
        assert_eq!(
            (hm_wall(now), date_wall(now)),
            ("14:46".into(), "2026-11-15 14:46".into())
        );

        // Paris in winter (UTC+1): 23:30 UTC on the 14th is already the 15th at 00:30, so "today" for the 15th at noon.
        let off = 3600;
        let (late, noon) = (1_794_699_000, 1_794_744_000); // 2026-11-14 23:30 and 2026-11-15 12:00 UTC
        assert_eq!(day_label_wall(Lang::En, late, noon), "Yesterday"); // in UTC
        assert_eq!(day_label_wall(Lang::En, late + off, noon + off), "Today");
        assert_eq!(hm_wall(late + off), "00:30");
        assert_eq!(ago_wall(Lang::En, noon - late, late + off, noon + off), "12 h ago");
        assert_eq!(ago_wall(Lang::Fr, noon - late, late + off, noon + off), "il y a 12 h");

        // Public functions follow the system time zone, whatever it is.
        let o = crate::fs::utc_offset(now);
        assert!(o % 60 == 0 && o.abs() <= 14 * 3600);
        assert_eq!(hm(now), hm_wall(now + o));
        assert_eq!(date(now), date_wall(now + o));
        let end = parse_day_end("2026-11-15").unwrap();
        assert_eq!(
            end + crate::fs::utc_offset(end),
            parse_day_end_wall("2026-11-15").unwrap()
        );
    }

    #[test]
    fn markdown_is_sanitized() {
        let h = markdown(
            "# Titre\n\n<script>alert(1)</script>\n\n[a](javascript:alert(1)) [b](https://x.org) [c](doc.md)\n\n![x](https://evil/p.png) <img src=x onerror=alert(1)>",
        );
        assert!(!h.contains("<script") && h.contains("&lt;script&gt;"), "{h}");
        assert!(!h.contains("<img") && h.contains("&lt;img"), "{h}");
        assert!(!h.contains("javascript:"), "{h}");
        assert!(h.contains("href=\"https://x.org\"") && h.contains("href=\"doc.md\"") && h.contains("<h1>Titre</h1>"));
        for bad in ["JavaScript:alert(1)", " data:text/html,x", "vbscript:x"] {
            assert!(!safe_url(bad), "{bad}");
        }
        assert!(safe_url("a/b:c") && safe_url("?q=1:2") && safe_url("#ancre"));
    }

    #[test]
    fn kinds_and_mimes() {
        assert_eq!(kind("a.PNG"), Kind::Image("image/png"));
        assert_eq!(kind("note.md"), Kind::Markdown);
        for active in ["x.svg", "x.html", "x.htm", "x.xml", "x.xhtml", "x.js", "noext"] {
            assert_eq!(inline_mime(active), None, "{active}");
        }
        assert_eq!(inline_mime("doc.pdf"), Some("application/pdf"));
        assert_eq!(inline_mime("a.json"), Some("text/plain; charset=utf-8"));
    }

    #[test]
    fn formats() {
        assert_eq!(size(Lang::En, 0), "0 B");
        assert_eq!(size(Lang::En, 1536), "1.5 KiB");
        assert_eq!(size(Lang::En, 3 << 30), "3.0 GiB");
        assert_eq!(size(Lang::Fr, 0), "0 o");
        assert_eq!(size(Lang::Fr, 1536), "1,5 Kio");
        assert_eq!(size(Lang::Fr, 3 << 30), "3,0 Gio");
        assert_eq!(date_wall(0), "1970-01-01 00:00");
        assert_eq!(date_wall(1_794_700_800), "2026-11-15 00:00");
        assert_eq!(parse_day_end_wall("2026-11-15"), Some(1_794_700_800 + 86_399));
        assert_eq!(
            parse_day_end_wall("2024-02-29").map(date_wall).as_deref(),
            Some("2024-02-29 23:59")
        );
        for bad in [
            "2026-02-31",
            "2026-13-01",
            "26-1-1",
            "2026-11",
            "x",
            "2026-11-15-1",
            "1969-12-31",
        ] {
            assert_eq!(parse_day_end_wall(bad), None, "{bad}");
        }
    }

    /// The editor's map covers editable kinds only (a name it shows as text is one the server accepts).
    #[test]
    fn text_extensions_are_text() {
        for e in TEXT_EXTENSIONS {
            assert!(matches!(kind(&format!("a.{e}")), Kind::Text | Kind::Markdown), "{e}");
        }
    }

    #[test]
    fn periods_and_highlights() {
        assert_eq!(period_start_wall("2026-11-15"), Some(1_794_700_800));
        assert_eq!(period_start_wall("2026-11"), period_start_wall("2026-11-01"));
        assert_eq!(period_start_wall("2026"), period_start_wall("2026-01-01"));
        for bad in [
            "",
            "2026-",
            "2026-02-30",
            "+2026",
            "2026-1x",
            "99999",
            "2026-11-15-1",
            "1969",
            "2026--1",
        ] {
            assert_eq!(period_start_wall(bad), None, "{bad}");
        }
        let o = crate::fs::utc_offset(1_794_700_800);
        assert_eq!(period_start("2026-11-15"), Some(1_794_700_800 - o));

        let w = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let m = |name: &str, words: &[&str]| -> String {
            marks(name, &w(words))
                .into_iter()
                .map(|(t, on)| if on { format!("[{t}]") } else { t })
                .collect()
        };
        assert_eq!(m("Impôts 2024.pdf", &["impot", "24"]), "[Impôt]s 20[24].pdf");
        assert_eq!(
            m("Rapport_FINAL rapport.odt", &["rapport", "final"]),
            "[Rapport]_[FINAL] [rapport].odt"
        );
        // A spelled-out ligature lights its source character; overlapping words merge.
        assert_eq!(m("Œuvre", &["oeu"]), "[Œu]vre");
        assert_eq!(m("abcd", &["abc", "bcd"]), "[abcd]");
        assert_eq!(m("abc", &[]), "abc");
        assert_eq!(m("", &["a"]), "");
    }
}
