#!/usr/bin/env python3
"""Beastbox test bench report: the data behind the "Banc d'essai" page (docs/dev/TESTING.md).

Measured each time it runs: test count and result (cargo test), coverage (cargo llvm-cov), fuzz corpora, and that every
test the report names exists. Read from VALIDATION.md (one source): performance, real clients, what is not tested.
Recorded after each long campaign, by this script, from the tools' own output, into docs/dev/bench-runs.json (versioned):
fuzz runs, long property runs, mutation testing.

  scripts/bench-report.py report [--reuse] [OUT]        # writes OUT/*.json (default target/bench); --reuse takes the
                                                        # tests and coverage scripts/check.sh just ran (seconds)
  scripts/bench-report.py record-fuzz TARGET LOG...     # libFuzzer logs of a run (fuzz-0.log …)
  scripts/bench-report.py record-models CASES           # after PROPTEST_CASES=CASES cargo test passed
  scripts/bench-report.py record-mutants DIR...         # cargo-mutants output directories, oldest first (merged)
  scripts/bench-report.py check-names                   # every test the report names exists (scripts/check.sh)
  scripts/bench-report.py snapshot [SRC]                # at a tag: SRC/*.json (default target/bench) → docs/bench/vX.Y.Z.json
  scripts/bench-report.py site [OUT] [SNAPSHOT...]      # static pages, one per version and index.html = latest
                                                        # (default target/bench-site); then rclone sync OUT $BEASTBOX_REPORT_REMOTE

Run from the repository root.
"""
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REUSE = "--reuse" in sys.argv
RUNS = ROOT / "docs/dev/bench-runs.json"
SELF = pathlib.Path(__file__).read_text()

# Property tests (proptest): what each checks.
MODELS = {
    "dav::model::webdav_follows_the_model": "Model-based: random MKCOL, PUT, DELETE, MOVE, COPY sequences vs an in-memory model; tree, contents, file identities, folder ETags after every step",
    "nc::share_model::client_links_follow_the_model": "Model-based: random link creations, changes, revocations through the OCS API; what clients list and what a guest can actually do",
    "dav::isolation::alice_never_touches_bob": "User isolation: random requests from one user, aimed at another user of the same tenant (his WebDAV path, traversal, Destination, file ids, his link), never succeed on his space, never return his names or contents, change no byte, xattr or database row of his",
    "admin::tests::weakness_is_monotonic": "Password policy: below the length always refused; a password accepted at a minimum stays accepted at a lower one and never contains the account name",
    "admin::tests::must_change_follows_who_set_the_password": "Password set by the administrator: random sets, refusals, disable/enable, sign-ins on 4 accounts in 2 tenants; must change exactly when the administrator set it, any change ends that account's sessions only",
    "auth::tests::second_step_model": "Two-step verification: random setups, codes, recovery codes, renewals, turn-offs and clock moves against a model; a code passes once inside ±1 step, a recovery code once and only from the latest set",
    "auth::totp::tests::a_code_is_accepted_once": "TOTP: any secret and time, a code is accepted only inside the window and never twice",
    "dav::isolation::alpha_never_touches_beta": "Tenant isolation: random requests from one tenant's user, hostile ones included, change no byte, xattr or database row of another tenant",
    "web::tests::login_return_is_always_local": "No open redirect: whatever the input, the post-login return address stays on the same site",
    "web::tests::qr_login_reads_back": "The mobile login QR code parses back, as the Nextcloud apps parse it, into exactly the user, password and server",
    "fs::manifest::tests::identity_and_etag_follow_the_content": "Restore by file copy with the manifest: for any content and any change since the backup, identity and ETag follow the content, contents never altered",
    "fs::write::tests::restore_never_touches_the_current_tree": "beastbox restore: for any snapshot and current tree, existing items unchanged, copy equal to the source, no identity held twice",
    "admin::tests::restored_name_is_legal_and_keeps_the_extension": "beastbox restore: the name given to a copy is always a legal name, keeps the extension and fits the length bound",
    "index::tests::glob_is_the_recursive_definition": "Search wildcards: the linear matcher agrees with the obvious recursive definition of * and ?, on texts where they collide with letters",
    "web::tests::the_page_chosen_holds_the_item": "Folder link at an item: whatever the folder and page sizes, the page chosen holds the item",
    "web::tests::copy_names_are_new_and_legal": "Copy and duplicate: for any name, the names tried are the name first, then all different, legal, a file's extension kept last",
}
# Fuzz targets: what each checks.
FUZZ = {
    "http": "Arbitrary requests on the full router; oracles: no panic, no 500, no write outside the data roots, never a success without valid credentials",
    "propfind": "Arbitrary PROPFIND bodies; the XML response is always well-formed",
    "proppatch": "Arbitrary PROPPATCH bodies; the XML response is always well-formed",
    "search": "Arbitrary SEARCH (RFC 5323) bodies; the XML response is always well-formed",
    "headers": "Paths, Destination, Range, If-Match, checksums, mtimes, Host, forms, uploaded file names",
    "query": "Web search syntax; folding is stable and highlighting is exact; wildcard patterns folded, bounded, and their matching always ends",
    "manifest": "Identity manifests read back from external storage; what is kept rereads identically",
    "thumb": "Arbitrary images through the JPEG decoder and thumbnailer; bounded memory, valid output",
    "restore": "Arbitrary source trees (any name, links) restored; always succeeds, existing items untouched, nothing written outside the target, faithful copies",
    "oidc_url": "Arbitrary text as an `https` URL (issuer, discovery endpoints, back-channel hosts); never a panic, an accepted URL keeps its bytes and a lowercase host, port 1-65535",
    "oidc_provider": "Arbitrary provider responses (discovery document, token response, `id_token`); refused or parsed, never a panic",
}
# Security rules (plan §0.3, §4.1, §10) and the tests that hold them; a missing test shows in the report.
SECURITY = [
    ("User isolation", "Nothing a user sends touches or reveals another user's files, xattrs, links or database rows in the same tenant",
     ["dav::isolation::alice_never_touches_bob", "auth::tests::app_password_of_another_user_is_refused", "web::tests_totp::wrong_codes_block_the_account", "web::tests::forced_account_leaves_the_others_alone"]),
    ("Tenant isolation", "Nothing a tenant's user sends touches another tenant's files, xattrs or database rows",
     ["dav::isolation::alpha_never_touches_beta", "http::tests::cross_tenant_token_refused", "web::tests::share_password_limit_revoke_and_tenant", "db::tests::tenants_are_isolated_in_db"]),
    ("Single sign-on (OIDC)", "Only the account an administrator bound to the provider identity signs in; the flow is bound to its tenant and to the browser session, and nothing the provider returns is trusted beyond the verified TLS channel",
     ["web::tests_oidc::oidc_full_flow_and_next", "web::tests_oidc::oidc_flow_cookie_is_bound_to_the_tenant", "web::tests_oidc::oidc_cross_tenant_flow_is_refused", "auth::oidc::tests::cookie_bytes_and_tenants_are_bound"]),
    ("Deny by default", "Unknown host refused; every route of the table requires a tenant (route audit)", ["http::tests::every_route_requires_tenant", "http::tests::tenant_resolution_and_default_deny"]),
    ("Tenant-scoped SQL", "Every SQL query filters by tenant (query audit)", ["db::tests::every_query_filters_by_tenant"]),
    ("Authentication required", "No success on a protected route without valid credentials (also a fuzz oracle)", ["http::tests::auth_failures_are_rate_limited", "web::tests::surfaces_are_separated"]),
    ("App passwords bound to their account", "Another user's app password, hostile user names, malformed Authorization headers refused", ["auth::tests::app_password_of_another_user_is_refused"]),
    ("Brute-force limits", "Failures limited per IP and per tenant; windows expire exactly", ["auth::tests::failures_are_limited_per_ip_and_bounded", "auth::tests::failure_windows_expire_exactly", "http::tests::login_flows_limited_per_ip"]),
    ("Session revocation", "Changing a password ends the account's web sessions; turning on two-step verification ends the other ones", ["web::tests::password_change_ends_web_sessions", "web::tests_totp::account_turns_it_on"]),
    ("Password policy", "Minimum length (setting, never below 10), no account or tenant name, no repeated characters, sequences or keyboard rows, not the current one", ["admin::tests::weakness_rules", "admin::tests::weakness_is_monotonic", "web::tests::account_tokens_and_password"]),
    ("Password set by the administrator", "Replaced at the first sign-in; until then the session opens nothing else and no device connects", ["web::tests::forced_session_pages_lead_to_welcome", "web::tests::forced_session_actions_are_refused", "web::tests::forced_account_cannot_connect_a_device", "admin::tests::must_change_follows_who_set_the_password"]),
    ("Disabled accounts", "No sign-in, sessions ended, devices and public links blocked while disabled", ["web::tests::disabled_account_is_shut_out_until_enabled", "cli::user_disable_enable"]),
    ("Administration CLI", "Every command run as the real binary on real ZFS datasets: exit code, output and effect; the other user and the other tenant untouched", ["cli::usage_and_version", "cli::check_config_and_unknown_tenant", "cli::user_add_refusals", "cli::user_add_on_a_dataset", "cli::user_list_columns", "cli::user_passwd", "cli::user_disable_enable", "cli::user_2fa_reset", "cli::verify_and_rescan", "cli::manifest_and_restore", "cli::serve_answers"]),
    ("Two-step verification", "TOTP (RFC 6238) after the password, web and Login Flow; each code once (in SQL too); 5 wrong codes per account per 15 minutes; recovery codes single use; required tenants hold the session until set up", ["auth::totp::tests::rfc6238_vectors", "auth::tests::second_step_model", "db::tests::totp_step_is_used_once_in_sql", "web::tests_totp::sign_in_needs_the_code", "web::tests_totp::wrong_codes_block_the_account", "web::tests_totp::login_flow_goes_through_the_login", "web::tests_totp::required_tenant_holds_until_set_up", "web::tests_totp::gates_come_in_order"]),
    ("Public links", "Wrong password, expiry, revocation, download limit, other tenant, rotated link key", ["web::tests::share_password_limit_revoke_and_tenant", "web::tests::renewed_link_key_ends_old_links", "nc::share_model::client_links_follow_the_model"]),
    ("Bounded uploads", "Concurrency caps, file count, sizes, slow-body timeout (slowloris), sanitized file names", ["web::tests::drop_links_are_bounded", "web::share::tests::drop_slots_are_bounded_and_given_back", "http::tests::stalled_upload_is_cut"]),
    ("Path confinement", "Traversal, symlinks, reserved names refused (SafePath, openat with O_RESOLVE_BENEATH)", ["fs::tests::write_in_subdir_and_no_escape", "fs::safepath::tests::rejects_hostile_paths"]),
    ("Crash safety", "Atomic writes under a real kill -9: never a torn file, identity kept", ["fs::tests::crash_during_atomic_write"]),
    ("Capsicum sandbox", "The whole server runs in capability mode; global namespace access refused (ECAPMODE)", ["http::tests::serves_in_capability_mode"]),
    ("Front-end hygiene", "CSRF token on every POST form; no inline script, style or handler (strict CSP); no innerHTML/eval; no dead CSS", ["web::audit::every_page_passes_the_audit", "web::audit::the_audit_catches_what_it_should"]),
    ("No open redirect", "The post-login return address only accepts same-site client links", ["web::tests::login_return_is_always_local", "web::tests::open_in_browser_from_a_client"]),
    ("No version disclosure", "Public pages (login, links, errors, device login) never show the version", ["web::tests::public_pages_hide_the_version"]),
    ("Mobile QR login", "One-time display, CSRF, app password expires after 10 minutes if unused", ["auth::tests::qr_password_waits_ten_minutes_for_its_first_use", "web::tests::qr_code_for_the_mobile_app"]),
    ("Restore never overwrites", "A past version comes back beside the current one, as new items; links never followed; a failure leaves the partial copy in the trash", ["fs::write::tests::restore_from_copies_next_to_the_current_version", "fs::write::tests::restore_never_touches_the_current_tree", "web::tests::restore_brings_back_a_copy_next_to_the_current_version"]),
    ("Backup manifest proves contents", "An identity and an ETag come back only to a file whose content is proven identical (SHA-1)", ["fs::manifest::tests::content_decides_when_the_sum_is_known", "fs::manifest::tests::identity_and_etag_follow_the_content", "fs::manifest::tests::contents_read_in_parallel_decide_file_by_file"]),
    ("Bounded search patterns", "Wildcards: 64 characters at most, matching bounded by the pattern and name lengths (never exponential)", ["index::tests::glob_patterns", "index::tests::glob_is_the_recursive_definition"]),
]
# Plain names, for readers who do not read Rust.
MODULE_NAMES = {
    "admin/mod.rs": "Administration (CLI)", "auth/mod.rs": "Authentication", "config.rs": "Configuration",
    "auth/totp.rs": "Two-step verification (TOTP)",
    "dav/mod.rs": "WebDAV: reads and listings", "dav/write.rs": "WebDAV: writes", "dav/search.rs": "WebDAV: client search",
    "dav/trashbin.rs": "Trash, as clients see it", "dav/upload.rs": "Chunked uploads", "db/mod.rs": "Database",
    "etag/mod.rs": "Change detection (ETags)", "fs/dir.rs": "Disk: folders and metadata", "fs/manifest.rs": "Disk: backup manifest",
    "fs/mod.rs": "Disk: confined access", "fs/safepath.rs": "Disk: safe paths", "fs/trash.rs": "Disk: trash",
    "fs/write.rs": "Disk: atomic writes", "http.rs": "HTTP server and routes", "i18n.rs": "Translations",
    "index/mod.rs": "Search index", "lib.rs": "Core", "nc/mod.rs": "Nextcloud protocol (login, thumbnails)",
    "nc/share.rs": "Sharing from the clients", "nc/thumb.rs": "Thumbnails", "tenant/mod.rs": "Tenant separation",
    "web/mod.rs": "Web interface", "web/render.rs": "Web interface: rendering", "web/share.rs": "Public links and drops",
    "web/zip.rs": "ZIP downloads",
}
FUZZ_NAMES = {
    "http": "Full HTTP surface", "propfind": "WebDAV listings", "proppatch": "WebDAV property updates",
    "search": "WebDAV search", "headers": "Headers and file names", "query": "Web search",
    "manifest": "Backup manifest", "thumb": "Images (thumbnails)", "restore": "Restore from a snapshot",
    "oidc_url": "OIDC destination grammar", "oidc_provider": "OIDC provider responses",
}
MODEL_NAMES = {
    "dav::model::webdav_follows_the_model": "File operations", "nc::share_model::client_links_follow_the_model": "Sharing links",
    "dav::isolation::alpha_never_touches_beta": "Tenant isolation", "web::tests::login_return_is_always_local": "Post-login redirect",
    "dav::isolation::alice_never_touches_bob": "User isolation",
    "admin::tests::weakness_is_monotonic": "Password policy",
    "admin::tests::must_change_follows_who_set_the_password": "Password set by the administrator",
    "auth::tests::second_step_model": "Two-step verification",
    "auth::totp::tests::a_code_is_accepted_once": "TOTP codes",
    "web::tests::qr_login_reads_back": "Mobile QR login",
    "fs::manifest::tests::identity_and_etag_follow_the_content": "Restore by file copy",
    "fs::write::tests::restore_never_touches_the_current_tree": "Restore from a snapshot",
    "admin::tests::restored_name_is_legal_and_keeps_the_extension": "Name of a restored copy",
    "index::tests::glob_is_the_recursive_definition": "Search wildcards",
    "web::tests::the_page_chosen_holds_the_item": "Folder link at an item",
    "web::tests::copy_names_are_new_and_legal": "Names of copies",
}
SECURITY_MODULES = {"auth/mod.rs", "auth/totp.rs", "tenant/mod.rs", "fs/safepath.rs", "fs/write.rs", "fs/mod.rs", "fs/trash.rs", "web/share.rs", "nc/share.rs", "db/mod.rs"}


def sh(*cmd, check=True):
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"{' '.join(cmd)} failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
    return r


def now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def runs():
    return json.loads(RUNS.read_text()) if RUNS.exists() else {"fuzz": {}, "models": {}, "mutants": {}}


def save_runs(r):
    RUNS.write_text(json.dumps(r, indent=2, ensure_ascii=False) + "\n")


def commit():
    # BEASTBOX_COMMIT: set by scripts/release.sh on the bench host, whose copy of the sources is synced without .git.
    return os.environ.get("BEASTBOX_COMMIT") or sh("git", "rev-parse", "--short", "HEAD").stdout.strip()


def test_names():
    out = sh("cargo", "test", "--lib", "--", "--list").stdout
    names = [l[: -len(": test")] for l in out.splitlines() if l.endswith(": test")]
    # The administration CLI, run as the real binary (tests/cli.rs).
    cli = sh("cargo", "test", "--test", "cli", "--", "--list", check=False).stdout
    return names + ["cli::" + l[: -len(": test")] for l in cli.splitlines() if l.endswith(": test")]


def kind(name):
    if name.startswith("cli::"):
        return "Administration CLI (real binary)"
    if name in MODELS:
        return "Property-based (proptest)"
    if name.startswith(("web::audit::", "global_state_audit::")) or name.endswith(("every_query_filters_by_tenant", "every_route_requires_tenant")):
        return "Audit"
    if name.startswith(("http::tests::", "web::tests::", "web::tests_totp::")):
        return "End-to-end"
    return "Unit"


def table(md, heading):
    """Rows of the first Markdown table under `heading` (a `## ` line starting with it)."""
    text = (ROOT / md).read_text()
    part = text.split("\n## " + heading, 1)[1].split("\n## ", 1)[0]
    lines = []
    for l in part.splitlines():
        if l.startswith("|"):
            lines.append(l)
        elif lines:
            break  # the first table only
    head = [c.strip() for c in lines[0].strip("|").split("|")]
    return [dict(zip(head, (c.strip() for c in l.strip("|").split("|")))) for l in lines[2:] if not l.startswith("|---")]


def bullets(md, heading):
    text = (ROOT / md).read_text()
    part = text.split("\n## " + heading, 1)[1].split("\n## ", 1)[0]
    items, cur = [], None
    for l in part.splitlines():
        if l.startswith("- "):
            cur = l[2:].strip()
            items.append(cur)
        elif l.startswith("  ") and items:
            items[-1] += " " + l.strip()
    return items


def report(out):
    out.mkdir(parents=True, exist_ok=True)
    gen = [{"label": "bench-report.py", "value": SELF, "type": "code", "lang": "python"},
           {"label": "Generated", "value": now()}, {"label": "Commit", "value": commit()}]

    def write(name, rows, source):
        (out / f"{name}.json").write_text(json.dumps({"rows": rows, "meta": gen + [{"label": "Input", "value": source}]}, ensure_ascii=False))

    names = test_names()
    # Reuse what scripts/check.sh just measured (seconds), or measure again (minutes).
    saved = ROOT / "target/test-output.txt"
    full = type("R", (), {"stdout": saved.read_text()})() if REUSE and saved.exists() else sh("cargo", "test", check=False)
    passed = sum(int(m) for m in re.findall(r"test result: \w+\. (\d+) passed", full.stdout))
    failed = sum(int(m) for m in re.findall(r"(\d+) failed", " ".join(re.findall(r"test result:.*", full.stdout))))
    counts = {}
    for n in names:
        counts[kind(n)] = counts.get(kind(n), 0) + 1
    write("tests", [{"kind": k, "tests": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]
          + [], "cargo test --lib -- --list")
    failing = ", ".join(re.findall(r"^test (\S+) \.\.\. FAILED$", full.stdout, re.M))
    write("summary", [{"tests": passed + failed, "passed": passed, "failed": failed, "failing": failing, "commit": commit(), "date": now()}],
          "cargo test (every suite)")

    saved_cov = ROOT / "target/coverage.json"
    cov = json.loads(saved_cov.read_text() if REUSE and saved_cov.exists() else sh("cargo", "llvm-cov", "--lib", "--json", "--summary-only", "--ignore-filename-regex", COVERAGE_IGNORE).stdout)
    rows = []
    for f in cov["data"][0]["files"]:
        rel = f["filename"].split("/src/", 1)[1]
        s = f["summary"]
        rows.append({"module": rel, "name": MODULE_NAMES.get(rel, rel), "regions": round(s["regions"]["percent"], 1), "lines": round(s["lines"]["percent"], 1),
                     "functions": round(s["functions"]["percent"], 1), "security": rel in SECURITY_MODULES})
    t = cov["data"][0]["totals"]
    rows.sort(key=lambda r: r["regions"])
    write("coverage", rows, "cargo llvm-cov --lib --json --summary-only")
    write("coverage_total", [{"regions": round(t["regions"]["percent"], 1), "lines": round(t["lines"]["percent"], 1),
                              "functions": round(t["functions"]["percent"], 1)}], "cargo llvm-cov --lib --json --summary-only")

    r = runs()
    write("fuzz", [{"target": k, "name": FUZZ_NAMES[k], "checks": v, "corpus": len(list((ROOT / "fuzz/corpus" / k).iterdir())),
                    **{f: r["fuzz"].get(k, {}).get(f) for f in ("requests", "seconds", "crashes", "date")}}
                   for k, v in FUZZ.items()], "fuzz/corpus/*, docs/dev/bench-runs.json")
    write("models", [{"test": k, "name": MODEL_NAMES[k], "checks": v, "exists": k in names,
                      "cases": r["models"].get(k, {}).get("cases"), "date": r["models"].get(k, {}).get("date")}
                     for k, v in MODELS.items()], "docs/dev/bench-runs.json")
    write("security", [{"rule": a, "what": b, "count": len(t), "tests": ", ".join(t), "missing": ", ".join(x for x in t if x not in names)}
                       for a, b, t in SECURITY], "bench-report.py SECURITY, checked against cargo test --list")
    write("mutants", [{"module": k, "name": MODULE_NAMES.get(k, k), **v} for k, v in sorted(r["mutants"].items())], "docs/dev/bench-runs.json")
    lit = ROOT / "target/litmus.txt"  # written by check.sh --long
    if lit.exists():
        text = lit.read_text()
        rows = [{"suite": m.group(1), "passed": int(m.group(3)), "total": int(m.group(2))}
                for m in re.finditer(r"^<- summary for .(\w+).: of (\d+) tests run: (\d+) passed", text, re.M)]
        fails = sorted(set(re.findall(r"(\w+)\.+ FAIL", text)))
        write("litmus", [{**r, "failed": ", ".join(f for f in fails if r["suite"] == "props")} for r in rows],
              "litmus 0.13 -k against the test bench (target/litmus.txt)")
    write("performance", [{"measure": x.get("Measurement"), "value": x.get("Value"), "budget": x.get("Budget (§0.4)"),
                            "machine": x.get("Machine", "")}
                          for x in table("docs/dev/VALIDATION.md", "7. Performance")], "docs/dev/VALIDATION.md §7")
    write("clients", [{"client": x.get("Client"), "shown": x.get("What was demonstrated")}
                      for x in table("docs/dev/VALIDATION.md", "6. Real clients")], "docs/dev/VALIDATION.md §6")
    # A bullet may start with its weight: "[Before production]", "[Minor]"…
    write("not_tested", [{"weight": m.group(1) if (m := re.match(r"\[([^\]]+)\]\s*", b)) else "", "item": b[m.end():] if m else b}
                         for b in bullets("docs/dev/VALIDATION.md", "9. What is not tested")], "docs/dev/VALIDATION.md §9")
    print(f"{len(names)} tests ({passed} passed, {failed} failed), coverage {t['regions']['percent']:.1f} % → {out}")


def record_fuzz(target, logs):
    requests = seconds = crashes = 0
    for log in logs:
        text = pathlib.Path(log).read_text(errors="replace")
        for n, s in re.findall(r"Done (\d+) runs in (\d+) second", text):
            requests += int(n)
            seconds = max(seconds, int(s))
        crashes += len(re.findall(r"Test unit written to .*/(crash|timeout|oom)-", text))
    r = runs()
    r["fuzz"][target] = {"requests": requests, "seconds": seconds, "crashes": crashes, "date": now(), "commit": commit()}
    save_runs(r)
    print(target, r["fuzz"][target])


def record_models(cases):
    r = runs()
    for k in MODELS:
        r["models"][k] = {"cases": int(cases), "date": now(), "commit": commit()}
    save_runs(r)


def record_mutants(dirs):
    """Merges cargo-mutants runs mutant by mutant, the later directory winning (a recheck of a few mutants updates the
    module's figures instead of replacing them)."""
    latest = {}
    for d in dirs:
        if not (pathlib.Path(d) / "mutants.out/outcomes.json").exists():
            continue  # no mutant of that kind in the diff
        for o in json.loads((pathlib.Path(d) / "mutants.out/outcomes.json").read_text())["outcomes"]:
            sc = o.get("scenario")
            if isinstance(sc, dict) and "Mutant" in sc:
                m = sc["Mutant"]
                latest[(m["file"], m["name"])] = o["summary"]  # name = file:line:col and the change
    per = {}
    for (f, name), summary in sorted(latest.items()):
        s = per.setdefault(f.split("src/", 1)[1], {"caught": 0, "missed": 0, "timeout": 0, "unviable": 0, "survivors": []})
        s[{"CaughtMutant": "caught", "MissedMutant": "missed", "Timeout": "timeout"}.get(summary, "unviable")] += 1
        if summary == "MissedMutant":
            s["survivors"].append(name)  # file:line:col and the change: explained in VALIDATION.md
    r = runs()
    for f, s in per.items():
        r["mutants"][f] = {**s, "date": now(), "commit": commit()}
    save_runs(r)
    print(per)


# ---------------------------------------------------------------- versioned snapshots and the static site

BENCH = ROOT / "docs/bench"
# Same filter as scripts/check.sh: the product only, not the files made of tests.
COVERAGE_IGNORE = r"src/(main|.*/(audit|model|isolation|tests(_[a-z]+)?))\.rs$"

SECTIONS = ["summary", "tests", "coverage_total", "coverage", "fuzz", "models", "security", "mutants", "litmus",
            "performance", "clients", "not_tested"]


def version():
    return re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)


def snapshot(src):
    """docs/bench/vX.Y.Z.json: the rows `report` wrote in SRC, with the version, commit and date. Run at the tag."""
    data = {"version": version(), "commit": commit(), "date": now()}
    for n in SECTIONS:
        f = src / f"{n}.json"
        data[n] = json.loads(f.read_text())["rows"] if f.exists() else []  # litmus: only after check.sh --long
    BENCH.mkdir(parents=True, exist_ok=True)
    out = BENCH / f"v{data['version']}.json"
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(f"→ {out.relative_to(ROOT)}")


def key(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


CSS = """
:root { color-scheme: light dark; --fond: light-dark(#f3f5f4, #141716); --surface: light-dark(#fff, #1b1f1d);
  --texte: light-dark(#1c2321, #e4e9e7); --doux: light-dark(#5f6c68, #96a19c); --bord: light-dark(#dde3e0, #2c3330);
  --accent: light-dark(#2f6b4f, #7fc3a0); --accent-fond: light-dark(#e2eee7, #1f2c26); --alerte: light-dark(#b3261e, #ff9a8f);
  --alerte-fond: light-dark(#fbeae8, #3a1f1c); --rayon: 6px; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--fond); color: var(--texte); font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 64rem; margin: 0 auto; padding: 2.5rem 1rem 4rem; }
header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: .5rem 2rem; }
h1 { font-size: 1.5rem; margin: 0; letter-spacing: -.01em; } h1 span { color: var(--doux); font-weight: 400; }
h2 { font-size: 1.05rem; margin: 3rem 0 .4rem; } .aide { color: var(--doux); margin: 0 0 1rem; max-width: 46rem; }
.meta { color: var(--doux); font-size: .9em; } code { font: .88em ui-monospace, "SF Mono", Menlo, monospace; }
nav.versions { display: flex; flex-wrap: wrap; gap: .4rem; margin: 1.25rem 0 0; }
nav.versions a { padding: .15rem .6rem; border: 1px solid var(--bord); border-radius: 999px; color: var(--doux);
  text-decoration: none; font-size: .88em; } nav.versions a[aria-current] { color: var(--accent); border-color: var(--accent); }
.tuiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); gap: .75rem; margin-top: 2rem; }
.tuile { background: var(--surface); border: 1px solid var(--bord); border-radius: var(--rayon); padding: .9rem 1rem; }
.tuile b { display: block; font-size: 1.6rem; font-weight: 600; letter-spacing: -.02em; }
.tuile span { color: var(--doux); font-size: .88em; }
table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--bord);
  border-radius: var(--rayon); overflow: hidden; font-size: .93em; }
th, td { text-align: left; padding: .5rem .75rem; border-top: 1px solid var(--bord); vertical-align: top; }
thead th { border-top: 0; color: var(--doux); font-weight: 500; font-size: .9em; } td.n, th.n { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
.barre { display: inline-block; width: 5rem; height: 4px; border-radius: 2px; background: var(--bord); vertical-align: middle; margin-right: .5rem; }
.barre i { display: block; height: 100%; border-radius: 2px; background: var(--accent); }
.etiquette { display: inline-block; padding: 0 .45rem; border-radius: 999px; font-size: .8em; background: var(--accent-fond); color: var(--accent); white-space: nowrap; }
.etiquette.alerte { background: var(--alerte-fond); color: var(--alerte); }
details summary { cursor: pointer; color: var(--accent); } details ul { margin: .4rem 0 0; padding-left: 1.1rem; color: var(--doux); }
ul.liste { background: var(--surface); border: 1px solid var(--bord); border-radius: var(--rayon); margin: 0; padding: .4rem 1rem .4rem 2rem; }
ul.liste li { padding: .35rem 0; } td.machine { white-space: nowrap; } footer { margin-top: 3rem; color: var(--doux); font-size: .85em; }
@media (max-width: 40rem) { th, td { padding: .45rem .5rem; } .masque { display: none; } }
"""


def esc(x):
    return str(x if x is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def md(x):
    """The little Markdown VALIDATION.md uses: `code` and **bold**, escaped first."""
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", esc(x))
    return re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)


def page(d, versions):
    v = d["version"]
    s = d["summary"][0]
    cov = d["coverage_total"][0]
    caught = sum(m["caught"] + m["timeout"] for m in d["mutants"])
    missed = sum(m["missed"] for m in d["mutants"])
    fuzz = sum(f.get("requests") or 0 for f in d["fuzz"])
    out = [f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
           f'<title>Beastbox {esc(v)} test report</title><style>{CSS}</style><main>',
           f'<header><h1>Beastbox <span>test report</span></h1><p class="meta">v{esc(v)} · commit <code>{esc(d["commit"])}</code> · {esc(d["date"][:10])}</p></header>',
           '<nav class="versions" aria-label="Versions">' + "".join(
               f'<a href="v{esc(x)}.html"{" aria-current=page" if x == v else ""}>v{esc(x)}</a>' for x in versions) + "</nav>",
           '<section class="tuiles">',
           f'<div class="tuile"><b>{s["passed"]}/{s["tests"]}</b><span>tests passed</span></div>',
           f'<div class="tuile"><b>{cov["regions"]} %</b><span>code regions covered</span></div>',
           f'<div class="tuile"><b>{cov["lines"]} %</b><span>lines covered</span></div>',
           f'<div class="tuile"><b>{caught}/{caught + missed}</b><span>mutants caught</span></div>',
           f'<div class="tuile"><b>{fuzz:,}</b>'.replace(",", " ") + '<span>fuzz inputs, no crash</span></div>',
           f'<div class="tuile"><b>{len(d["security"])}</b><span>security rules, each tested</span></div>',
           "</section>"]
    if s.get("failing"):
        out.append(f'<p><span class="etiquette alerte">Failing</span> {esc(s["failing"])}</p>')
    # Trend across versions (same measures, one table: never two scales on one chart).
    if len(versions) > 1:
        out.append('<h2>Across versions</h2><table><thead><tr><th>Version</th><th class="n">Tests</th><th class="n">Regions covered</th><th class="n">Mutants caught</th></tr></thead><tbody>')
        for x in reversed(versions):
            o = json.loads((BENCH / f"v{x}.json").read_text())
            oc = sum(m["caught"] + m["timeout"] for m in o["mutants"]); om = sum(m["missed"] for m in o["mutants"])
            out.append(f'<tr><td><a href="v{esc(x)}.html">v{esc(x)}</a></td><td class="n">{o["summary"][0]["tests"]}</td>'
                       f'<td class="n">{o["coverage_total"][0]["regions"]} %</td><td class="n">{oc}/{oc + om}</td></tr>')
        out.append("</tbody></table>")
    out.append('<h2>Security rules</h2><p class="aide">Each rule is held by the tests named; the report checks they exist.</p>'
               '<table><thead><tr><th>Rule</th><th class="masque">What is checked</th><th class="n">Tests</th></tr></thead><tbody>')
    for r in d["security"]:
        miss = f' <span class="etiquette alerte">missing: {esc(r["missing"])}</span>' if r.get("missing") else ""
        tests = "".join(f"<li><code>{esc(t)}</code></li>" for t in r["tests"].split(", "))
        out.append(f'<tr><td><b>{esc(r["rule"])}</b>{miss}<details><summary>tests</summary><ul>{tests}</ul></details></td>'
                   f'<td class="masque">{esc(r["what"])}</td><td class="n">{r["count"]}</td></tr>')
    out.append("</tbody></table>")
    out.append('<h2>Tests by kind</h2><table><tbody>' + "".join(
        f'<tr><td>{esc(t["kind"])}</td><td class="n">{t["tests"]}</td></tr>' for t in d["tests"]) + "</tbody></table>")
    out.append('<h2>Property-based tests</h2><p class="aide">Random sequences checked against a model or a rule; a failure prints the shortest sequence that breaks it.</p>'
               '<table><thead><tr><th>Subject</th><th class="masque">What is checked</th><th class="n">Long run</th></tr></thead><tbody>')
    for m in d["models"]:
        run = f'{m["cases"]:,} cases'.replace(",", " ") if m.get("cases") else "per commit"
        out.append(f'<tr><td><b>{esc(m["name"])}</b></td><td class="masque">{esc(m["checks"])}</td><td class="n">{run}</td></tr>')
    out.append("</tbody></table>")
    out.append('<h2>Fuzzing</h2><table><thead><tr><th>Target</th><th class="masque">Oracles</th><th class="n">Inputs</th><th class="n">Crashes</th></tr></thead><tbody>')
    for f in d["fuzz"]:
        req = f'{f["requests"]:,}'.replace(",", " ") if f.get("requests") else "–"
        cr = f.get("crashes")
        crash = "–" if cr is None else (f'<span class="etiquette alerte">{cr}</span>' if cr else "0")
        out.append(f'<tr><td><b>{esc(f["name"])}</b> <code>{esc(f["target"])}</code></td><td class="masque">{esc(f["checks"])}</td><td class="n">{req}</td><td class="n">{crash}</td></tr>')
    out.append("</tbody></table>")
    out.append('<h2>Mutation testing</h2><p class="aide">Each mutant is a small deliberate bug; a caught one fails a test. '
               'Survivors in the fuzz harnesses are expected; every other one is explained in VALIDATION.md (missing test since added, or equivalent).</p>'
               '<table><thead><tr><th>Module</th><th class="n">Caught</th><th class="n">Survived</th></tr></thead><tbody>')
    for m in sorted(d["mutants"], key=lambda m: m["name"]):
        surv = m.get("survivors") or []
        harness = [x for x in surv if "fuzz_" in x or " fuzz::" in x]
        other = [x for x in surv if x not in harness]
        detail = ""
        if surv:
            detail = "<details><summary>survivors</summary><ul>" + "".join(
                f'<li><code>{esc(x)}</code>{" (fuzz harness)" if x in harness else ""}</li>' for x in harness + other) + "</ul></details>"
        elif m["missed"]:
            detail = '<p class="meta">Names not recorded by this run: see VALIDATION.md.</p>'
        out.append(f'<tr><td><b>{esc(m["name"])}</b> <code>{esc(m["module"])}</code>{detail}</td><td class="n">{m["caught"] + m["timeout"]}</td><td class="n">{m["missed"]}</td></tr>')
    out.append("</tbody></table>")
    if d.get("litmus"):
        out.append('<h2>WebDAV compliance</h2><p class="aide"><code>litmus</code> 0.13, the reference WebDAV test suite, against the test bench. '
                   'Locks are not offered (Nextcloud clients do not need them); free-form properties are refused on purpose (only '
                   '<code>oc:favorite</code> is stored), hence the 3 expected failures in <code>props</code>.</p>'
                   '<table><thead><tr><th>Suite</th><th class="n">Passed</th><th>Expected failures</th></tr></thead><tbody>' + "".join(
            f'<tr><td><code>{esc(r["suite"])}</code></td><td class="n">{r["passed"]}/{r["total"]}</td><td>{esc(r.get("failed", ""))}</td></tr>'
            for r in d["litmus"]) + "</tbody></table>")
    out.append('<h2>Coverage</h2><p class="aide">Product code reached by the tests (files made of tests are not counted), by module, least covered first. '
               'What stays uncovered is mostly what a test cannot provoke without breaking the machine: a disk error in the middle '
               'of an operation, the pool of blocking threads exhausted; each answers an error and writes nothing. <span class="etiquette">security</span>: a security-critical module.</p>'
               '<table><thead><tr><th>Module</th><th class="n">Regions</th><th class="n masque">Lines</th><th class="n masque">Functions</th></tr></thead><tbody>')
    for c in d["coverage"]:
        sec = ' <span class="etiquette">security</span>' if c.get("security") else ""
        out.append(f'<tr><td>{esc(c["name"])}{sec} <code class="masque">{esc(c["module"])}</code></td>'
                   f'<td class="n"><span class="barre" aria-hidden="true"><i style="width:{c["regions"]}%"></i></span>{c["regions"]} %</td>'
                   f'<td class="n masque">{c["lines"]} %</td><td class="n masque">{c["functions"]} %</td></tr>')
    out.append("</tbody></table>")
    out.append('<h2>Performance</h2><p class="aide">Measured on modest hardware: <b>N100</b>, a mini PC with an Intel N100 (4 cores) '
               'and an NVMe SSD; <b>HDD</b>, a NAS with a ZFS RAIDZ1 of 3 hard disks. FreeBSD 15.1, ZFS.</p>'
               '<table><thead><tr><th>Measure</th><th>Value</th><th class="masque">Budget</th><th>Machine</th></tr></thead><tbody>' + "".join(
        f'<tr><td>{md(p["measure"])}</td><td>{md(p["value"])}</td><td class="masque">{md(p["budget"])}</td><td class="machine">{esc(p.get("machine", ""))}</td></tr>'
        for p in d["performance"]) + "</tbody></table>")
    out.append('<h2>Real clients</h2><table><tbody>' + "".join(
        f'<tr><td><b>{md(c["client"])}</b></td><td>{md(c["shown"])}</td></tr>' for c in d["clients"]) + "</tbody></table>")
    out.append('<h2>Not tested yet</h2><p class="aide">Known gaps, said plainly.</p><ul class="liste">')
    for n in d["not_tested"]:
        w = n.get("weight", "")
        tag = f'<span class="etiquette{" alerte" if w.lower().startswith("before") else ""}">{esc(w)}</span> ' if w else ""
        out.append(f"<li>{tag}{md(n['item'])}</li>")
    out.append(f'</ul><footer>Generated by <code>scripts/bench-report.py</code> from the tools\' own output (cargo test, cargo llvm-cov, libFuzzer, cargo-mutants, proptest).</footer></main></html>')
    return "\n".join(out)


def site(out, files=None):
    """OUT/vX.Y.Z.html for every snapshot of docs/bench (or the FILES given), OUT/index.html = the latest."""
    snaps = [pathlib.Path(f) for f in files] if files else sorted(BENCH.glob("v*.json"))
    data = {json.loads(p.read_text())["version"]: json.loads(p.read_text()) for p in snaps}
    versions = sorted(data, key=key)
    out.mkdir(parents=True, exist_ok=True)
    for v, d in data.items():
        (out / f"v{v}.html").write_text(page(d, versions))
    (out / "index.html").write_text(page(data[versions[-1]], versions))
    print(f"{len(versions)} versions → {out}")


def check_names():
    """A renamed or removed test must not leave a security rule or a model without its proof: fail at once."""
    names = set(test_names())
    missing = sorted(({t for _, _, ts in SECURITY for t in ts} | set(MODELS)) - names)
    if missing:
        sys.exit("tests named by the report but not found (renamed? update SECURITY/MODELS):\n" + "\n".join(missing))
    print(f"ok ({sum(len(ts) for _, _, ts in SECURITY)} security tests, {len(MODELS)} models)")


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a or a[0] == "report":
        rest = [x for x in a[1:] if x != "--reuse"]
        report(ROOT / (rest[0] if rest else "target/bench"))
    elif a[0] == "record-fuzz":
        record_fuzz(a[1], a[2:])
    elif a[0] == "record-models":
        record_models(a[1])
    elif a[0] == "record-mutants":
        record_mutants(a[1:])
    elif a[0] == "check-names":
        check_names()
    elif a[0] == "snapshot":
        snapshot(ROOT / (a[1] if len(a) > 1 else "target/bench"))
    elif a[0] == "site":
        site(ROOT / (a[1] if len(a) > 1 else "target/bench-site"), a[2:])
    else:
        sys.exit(__doc__)
