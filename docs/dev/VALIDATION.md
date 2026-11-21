# Beastbox validation — summary of the tests carried out

Goal: keep track of **everything** that has been tested, to justify the product's soundness and robustness, and to know what
**is not yet**. Kept up to date at every release (`CHANGELOG.md`): this file and `CHANGELOG.md` serve as milestone reports
(plan, §12). Details are in the documents cited.

State as of **2026-11-17**, version 0.12.0 plus the manifest's format 2 (not released yet): J4 coded, the demonstrations
with the devices remain (Android app). Bench: N100 host (FreeBSD 15.1-RELEASE-p6, amd64), jail `beastbox`, local ZFS
datasets (`xattr=sa`), test nginx in front of the server. **168 automated tests**, 9 fuzzing targets.

## 1. Overview

| Area | Means | Result | Detail |
|---|---|---|---|
| Automated tests | `cargo test` (179 tests: 177 in the library, 2 in the binary, including real HTTP requests on the whole router and a real `kill -9`), `node --test` (13 JavaScript rules) | 179/179, 13/13 (2026-11-17) | §2 below |
| Quality and dependencies | `cargo fmt`, `clippy -D warnings`, `cargo audit`, `cargo deny` | all green | `DEPS.md` |
| Fuzzing | cargo-fuzz (libFuzzer + AddressSanitizer), 9 targets | **4 defects found and fixed**, then no crash (last campaign 2026-11-17) | §3 |
| WebDAV compliance | `litmus` 0.13 | 47/50 (run of 2026-11-14, before PROPPATCH) | §4 |
| Hard kills | real `kill -9` mid-upload and mid-assembly | no loss or corruption | §5 |
| Backup and restore | restic (local and pCloud), `zfs rollback`, total loss of the instance | everything came back (identities, tags, links, sessions) | §5b, `../admin/backup.md` |
| Real clients | desktop client 34/35, Android app 35.0.2, `rclone` | sync, search, favorites | §6, `CLIENTS.md` |
| Performance and memory | measurements on 1,000, 10,000 and 100,000 files | within the §0.4 budgets | §7 |

## 2. Automated tests (`cargo test`)

Grouped by the plan's categories (§10). Each test checks a behavior, not just the absence of a crash.

**Multi-tenant isolation (§4.1)**
- `tenant::resolution`, `tenant::config_refusals`, `tenant::roots_must_be_distinct_datasets`: exact then wildcard resolution,
  hostile host names refused (userinfo, IPv6, raw IDN, multiple values, invalid ports), startup refused for a name claimed
  twice, a wildcard too broad, nested roots or roots on the same dataset.
- `db::every_query_filters_by_tenant`, `db::every_table_has_tenant_in_primary_key`, `db::tenants_are_isolated_in_db`: audit of
  every SQL query and of the schema; composite foreign keys (a token cannot target a user of another tenant).
- `http::every_route_requires_tenant`: audit of the whole route table (unknown host → 421, no route crashes).
- `http::cross_tenant_token_refused`, `auth::app_passwords_are_bound_to_tenant_and_user`: a token from one tenant is refused on
  the other, even for a same-named user.
- `global_state_audit::no_global_state`: no global state in the code (CI rule from §4.1).

**Paths and filesystem (§4.1, §9)**
- `fs::safepath::rejects_hostile_paths`, `accepts_and_normalizes`: `..`, NUL, `\`, control characters, absolute paths, reserved
  names, too-long names refused; NFC.
- `fs::write_in_subdir_and_no_escape`: outgoing symlinks and `..` refused by the kernel (`O_RESOLVE_BENEATH`).
- `fs::dir::read_dir_hides_reserved_and_specials`: reserved names hidden, links and FIFOs ignored, a FIFO never opened.
- `fs::storage_check_accepts_local_zfs`: storage check at startup (local FS + xattr).

**Data safety (§0.2, §6)**
- `fs::crash_during_atomic_write`: **20 real `kill -9`** of a process in the middle of a 4 MiB write; every time the file is
  entirely the old or the new version, the identity is kept, cleanup empties the temporary; the test fails if it did not
  actually cut mid-write.
- `fs::identity_and_xattrs_survive_replacement`: identity and tags kept on replacement; sums not copied over; new identity
  after delete then re-create.
- `fs::write::writer_checksum_mtime_precondition_and_abort`: wrong sum, failed precondition, abort → nothing written.
- `fs::write::mkdir_trash_rename_copy`: trash (original path in xattr), no permanent overwrite, folder into itself refused.
- `fs::write::journal_replays_unfinished_intents`: unfinished ETag intents replayed after a "crash", truncated line ignored,
  second instance refused (lock).
- `fs::write::renew_lenient_falls_back_to_ancestor`, `fs::dir::rescan_assigns_ids_and_renews_ancestors`,
  `fs::dir::verify_reports_without_modifying`: ETag propagation, duplicate identities reassigned, `verify` read-only.
- `fs::clean_tmp_removes_orphans`, `fs::write::uploads_chunks_and_expiry`: bounded cleanup (batches of 1,024), upload chunks.

**Protocol and clients (§7)**
- `http::login_flow_v2`: 404 before confirmation, 200 only once, single use, other tenant refused, human password refused on
  OCS/WebDAV.
- `http::webdav_read_only`, `http::webdav_writes`, `http::chunked_upload_v2`, `http::propfind_large_dir_streams`: PROPFIND,
  GET/Range/HEAD, PUT (201/204, `If-Match` 412, wrong `OC-Checksum` 400, `X-OC-Mtime`), MKCOL, MOVE, COPY, DELETE,
  `Destination` (other host 502, reserved name 403, raw UTF-8), quota 507, chunked upload (out of order, inconsistent total,
  missing chunk, resume via PROPFIND), 2,000-entry response in several chunks.
- `http::ocs_endpoints`, `http::read_only_mode`: capabilities, unknown OCS as 404 in the right format, read-only → 503.
- `http::nextcloud_trashbin` (Android app requests): trash listing, contents of a deleted folder, restore with the same
  identity, permanent delete, emptying, other user refused.
- `http::dav_search_for_clients`, `dav::search::tests::android_queries`, `index::tests::dav_filters_and_newest_first`: `SEARCH`
  for the Favorites, Recent (files only, the newest of the whole space), Photos tabs and by name; limit; another user's scope
  or unknown criterion → empty list; tenant isolation; 400 and 413.
- `http::favorites_from_clients`, `dav::write::tests::proppatch_parse_and_answer`: `PROPPATCH oc:favorite` (set, unset),
  visible in PROPFIND, search and the web; all or nothing (403 and 424); root, missing, reserved name, read-only refused.
- `dav::tests::prop_names_same_rule_everywhere`: the three XML parsers (PROPFIND, SEARCH, PROPPATCH) refuse exactly the same
  hostile property names.
- `http::file_etag_follows_content_not_storage`, `etag::tests::*`, `fs::tests::file_etag_survives_a_restore_by_copy`: a file's
  ETag unchanged by a restore (new inode, same xattrs), changed by two uploads of the same size and same `X-OC-Mtime`;
  independently computed reference values.
- `nc::label_tests::labels_from_real_user_agents`: app passwords named after the client.
- `dav::propfind_parsing`, `dav::ranges`, `dav::hrefs_are_encoded`, `dav::write::headers`, `dav::upload::upload_ids`,
  `http::form_parsing`: parsers (including XXE external entity, property bomb, invalid names and namespaces).

**Negative security (§10)**
- `http::tenant_resolution_and_default_deny`: unknown routes 404, unlisted method 405, contradictory or multiple
  `Host`/`X-Forwarded-Host` 400.
- `http::accept_loop_limits`: on a real TCP socket, peer outside `trusted_proxies` closed, connection limit, too-slow headers
  cut (slowloris).
- `http::auth_failures_are_rate_limited`, `auth::failures_are_limited_per_ip_and_bounded`: 10 failures per IP → **wrong**
  passwords get 429, a **valid** app password from the same IP goes through, the form (human password) stays blocked before
  argon2; other IP not penalized, bounded table (fails closed when full).
- `http::login_flows_limited_per_ip`: at most 4 pending Login Flows per IP (429), another IP unaffected, a confirmed flow frees
  its slot, cap of 64 per tenant (503).
- `http::security_headers_present`, `auth::human_password` (equal cost for a nonexistent account),
  `config::defaults_and_refusals` (listening on `0.0.0.0` refused), `admin::*` (distinct dataset required, password ≥ 10
  characters, user names).

**Web interface and links (J3)** — `web::tests`, real requests on the whole router
- `surfaces_are_separated`: without a session, pages → login and `/web/dav` → 401; an app password does not open the web, a
  session opens neither WebDAV nor OCS; CSRF required (header and form); a tenant's session refused on the other domain;
  cookie `__Host-…; HttpOnly; Secure; SameSite=Lax` without `Domain`; CSP without `unsafe-inline` or `unsafe-eval`; logout
  effective.
- `upload_folder_of_100_files_and_actions` (**J3 exit criterion**): folder of 100 files uploaded the way the browser does it,
  listing, sorting, renaming, trash, ZIP reread by `unzip`.
- `hostile_content_is_neutralized` (**J3 exit criterion**): `.md` with `<script>` and a `javascript:` link never executable;
  HTML file name escaped; SVG and HTML as attachments even with `?inline=1`; HTML tag refused; traversal refused.
- `share_password_limit_revoke_and_tenant` (**J3 exit criterion**): password (wrong then right, cookie bound to the link),
  download limit, forged or truncated token, revocation, expiry, deleted target → 404; **a tenant's link opened on another
  domain → 404**.
- `drop_only_reveals_nothing` (**J3 exit criterion**): no name revealed (page, listing, download, ZIP refused), no overwrite
  (suffixes, existing file intact), hostile names, per-file size, total volume.
- `folder_share_is_confined`, `account_tokens_and_password`, `large_folder_is_paginated`: confinement to the subtree, app
  passwords created and revoked, password change, pagination.
- `bulk_actions_without_javascript` (**J3b exit criterion**): 50 items moved to the trash in a single request by the form
  alone (no JavaScript); bulk move without overwrite (failure counted, existing file intact); ZIP of the selection only reread
  by `unzip`; refused without CSRF, empty selection, name containing a path, traversal, reserved name, destination outside the
  root.
- `gallery_grid_and_icons` (**J3b exit criterion**): previous / next image links (`rel`, arrow keys), absent outside the
  gallery; lazy-loaded grid; icons as a closed list (traversal and unknown name → 404), no script, cached.
- `folder_tree_and_move_picker`: tree expanded down to the current folder, balanced markup, escaped names, no file listed;
  fragment of direct children; radio buttons of the move dialog; traversal → 404; refused without a session; move without a
  destination → 400 (nothing is moved to the root by accident).
- `search_by_name_and_tag` (**J4**): search by name and by tag kept up to date by real writes (WebDAV PUT, tag, bulk trash);
  file added outside the application invisible until `rescan`, then found; other tenant never found; hostile query escaped.
  `index::tests`: moved folder found again by its identity (path updated), trash, entry cap respected, eviction.
- `text_edit_save_conflict_and_limits`, `text_edit_security`, `text_edit_read_only` (0.7.0): save through the WebDAV PUT
  (same identity, new ETag, share link serving the new contents), LF / CRLF kept, conflict (text typed kept, nothing
  written; missing or forged ETag never overwrites), replace on request, Markdown preview sanitized and not saved;
  refusals (binary, > 512 KiB, image, folder, missing, invalid UTF-8, body over the route limit, other routes still 64 KiB);
  CSRF missing, wrong or of another session (save **and** preview); traversal, encoded traversal, reserved names, symlink
  to a file outside the space (untouched); HTML in the contents, the typed text, the name; CSP unchanged; other tenant;
  read-only server and space reserve.
- `text_edit_rename` (0.7.3): name refused (not text, `/`, `..`, empty, reserved, control character, > 255) saves nothing
  and keeps what was typed; hostile name escaped; name taken: saved, not renamed, other file untouched; conflict with a
  new name: neither; same name with spaces: a plain save; rename: same identity and tags, share link ended, old name gone;
  no CSRF: neither. `render::tests::text_extensions_are_text`: the editor's icon map covers editable kinds only.
- `upload_with_old_date_is_recent_activity` (0.7.1): a file uploaded with an old `X-OC-Mtime` comes first in "Recent
  activity" ("just now"), its own date kept on the details page; (0.7.2) "Recently deleted": the latest 4 trash items, gone once the trash
  is emptied, hostile name escaped.
- `text_file_create` (0.7.0): "+ New" menu; text file created empty with an identity, then its editor; found by search
  without accents; never over a file, a folder or a symlink to a file outside the space; not a text name, missing
  folder, traversal, reserved name, no CSRF: nothing created; hostile name escaped. `text_edit_security` also checks that
  a large body without a session gets the login page (the body is not read).
- `share_created_is_shown_first` (0.6.1): creation answers a redirect (a reload creates nothing), card at the top with
  the link, its options and the way back, row marked "New"; unknown, hostile or other tenant's identifier marks nothing.
- `search_scope_and_filters` (0.6.0): accents ignored, folder scope carried by the bar of a folder's page, filter chips
  that add or remove their filter, missing scope (way out), path escaping the space ignored, hostile scope escaped.
  `index::tests::rank_scope_and_filters`, `query_parse`: ranking (exact, word start, elsewhere, then newest), `type:`,
  `is:fav`, `after:`/`before:`, invalid operators searched as words; `render::tests::periods_and_highlights`.
- `trash_restore_from_web` (**J4**): deleted item listed, share link 404 while in the trash; restore with parent folder
  re-created: content, link, tags and search recovered; double restore, hostile slot, missing CSRF and confirmation refused;
  permanent delete and emptying. `fs::trash::tests`: identity and tags kept, never an overwrite (suffix), symlink never
  followed, nothing deleted outside `.trash/`, expiry by date.
- `favorites_and_sidebar`: Favorites page (folders before files), favorite folder expandable in the sidebar, sidebar (My files,
  Favorites, Shared links, Trash) on every page with the current section marked, balanced markup, removing a favorite.
- `share_history_and_recent_activity`, `db::share_events_grouped_bounded_and_isolated`: link history (refused password,
  downloads, archive, drops) for the owner, grouped, no IP; filter by link, hostile parameter ignored, pagination,
  revocation; "Recent activity" box; retention and per-user cap (hourly purge); tenants isolated.
- `shares_end_with_their_target`, `db::share_list_only_usable_and_end_reasons`, `web::share::tests::link_target_states`: a link
  leaves the list when it no longer serves; target in the trash → suspended then resumed on restore; renamed, emptied or
  replaced → ended; item without identity → neither.
- `ranged_download_counts_once`, `auth::tests::download_pass_is_bound`: a download in several ranges (Safari probe, video
  playback, resume) counts once; forged or expired cookie, or one from another file or tenant, refused; exhausted link closed.
- `failed_drops_release_their_reservation`: a failed drop (wrong size, guest gone mid-upload) gives back its reservation.
- `copy_restore_keeps_links_with_manifest`, `fs::manifest::tests::*`: identity manifest: after an xattr-less copy (times to the
  second), link, tag, favorite and trash recovered, and the **ETag a WebDAV client reads is unchanged** (content proven by
  its SHA-1, time put back to the nanosecond); lost without a manifest; identity never stolen, existing xattr wins; same
  size and second but another content → new identity; file without a sum and format 1 manifest → identity only; format,
  bounds (nanoseconds, sum) and hostile lines. `identity_and_etag_follow_the_content` (proptest, 2,000 cases run): for any
  content and change between backup and restore, identity and ETag follow the content, never altered.
  `contents_read_in_parallel_decide_file_by_file`: contents proven by several readers at once (more files than readers,
  one in seven changed): every decision on the right file, the same as with one reader; an unreadable file fails the
  rescan before any change.
- `restore_from_copies_next_to_the_current_version`, `restore_edge_cases`, `restore_never_touches_the_current_tree`
  (proptest, 2,000 cases run), `restore_brings_back_a_copy_next_to_the_current_version` (end to end): `beastbox restore`
  puts a past version beside the current one (or back at its place if gone, or at `--to`), as new items (new identity
  even when the snapshot kept the original's); current item, its ETag and its link untouched; links, special files and
  refused names skipped and counted; decomposed names copied in NFC (Chinese, accents, emoji tried); missing parents
  created; existing target, target out of the space or reserved, copy into itself refused; failure midway (unreadable
  source, write error: `restore_write_error_midway_fails_the_copy`): partial copy to the trash, failure before any copy:
  its cause, nothing trashed; default names (extension kept last, folder and dot file whole); other tenant sees nothing.
  `command_line`: `restore`, `--to`, `--readers` (1 and 8 accepted, 0, 9 and a word refused, options of other commands
  refused); `restore_report_lines`: what `restore` prints.
- `sort_by_tags`, `web::render::tests::relative_dates`: sorting by tags; local times and relative dates (explicit offsets).
- `web::zip::zip_roundtrip_with_unzip`, `web::render::*`, `web::share::tests`: archive checked by `unzip -t`, sanitized
  Markdown, preview types, date formats, drop names.

## 2b. Model-based WebDAV test (proptest)

`dav::model::webdav_follows_the_model`: random sequences (1 to 15 steps) of MKCOL, PUT, DELETE, MOVE and COPY (with or
without `Overwrite`) on a few colliding names (`a`, `b`, `é c`, two levels), applied to the real router and to an
in-memory model. After each step: the same answer (success or refusal, never a 5xx), the same tree and contents, identities
kept by a move and a rewrite, new for a copy, all distinct, and the folder ETag renewed by every change. 48 sequences on
each `cargo test`; `PROPTEST_CASES=3000` for a long run (about 1 min).

| Finding | Fix |
|---|---|
| `MOVE`/`COPY` of a subfolder **onto its own parent** with `Overwrite: T` trashed the whole parent, source included, then failed (nothing lost: everything was in the trash) | refused (409) before touching anything, in `fs` for MOVE and COPY |
| `MOVE` of an item onto itself answered 204 "replaced" | 403, as RFC 4918 and sabre/dav |
| A refused operation may renew the folder ETag | kept on purpose: a failed overwrite may already have trashed the destination; a needless resync beats a missed change |

After the fixes: 3,000 sequences, no divergence.

`nc::share_model::client_links_follow_the_model`: random sequences (1 to 9 steps) of link creations, changes and
revocations through the clients' OCS API (access read, drop or upload; password empty, too short or valid; label with or
without a control character; hidden download), on a folder and on a file. After each step: the same answer, the list the
clients see (access, label, hidden download, password flag), and what a guest can really do with each link (open it, drop
into it, download the archive). 32 sequences on each `cargo test`; 1,500 before 0.11.0, no divergence. Checked that it
catches a defect: archive left available despite a hidden download → caught on the first sequence, shrunk to one step.

## 2c. Paranoid program (`TESTING.md`), started 2026-11-16

**Coverage baseline** (`cargo llvm-cov --lib`, 0.12.0): 92.5 % of regions, 94.5 % of lines, 95.0 % of functions. 100 %:
`etag/`, `fs/safepath.rs`. Security modules: `auth/` 95.4 % → gaps closed below; `tenant/` 95.8 % (the two lines left are
unreachable by construction: an HMAC key of any length). Lowest: `admin/` 78.7 %, `dav/upload.rs` 79.6 %, `dav/trashbin.rs`
84.0 % (next).

| Addition | What it checks | Proof that it bites |
|---|---|---|
| `http` fuzz oracle "never access without credentials" | no 2xx on a protected route without valid credentials for that surface (app password: WebDAV, OCS, previews; session: `/web/`, `/index.php/f/`), nor with alpha's credentials on beta's host | a deliberate hole (no credentials = alice) planted in a copy: caught in seconds, input of 3 bytes ("200 on the sharing API without a valid app password"); then 72,600 requests on the real code, no violation |
| `dav::isolation::alpha_never_touches_beta` (proptest) | random sequences from alpha's user, hostile ones included (alpha's credentials to beta's host, `Destination` on beta, traversal and encoded paths, links): beta's tree (content, mtime, xattrs) and every beta database row unchanged; never a success on beta's host | the fingerprint is checked to see a favorite (xattr) and a link (row) before the run; 500 sequences, no change |
| `auth::failure_windows_expire_exactly` | a blocked IP and a blocked tenant get their attempts back exactly at the end of the window, not 1 ms before; counters restart from zero; a full table frees expired entries | (the limiter now takes the time as a parameter: no real 5-minute wait) |
| `auth::app_password_of_another_user_is_refused` | bob's app password with alice's name refused; hostile user name, malformed `Authorization` headers, malformed link cookie | — |
| `tenant::roots_must_be_distinct_datasets` (extended) | a missing data root refuses startup and names the tenant and folder | — |

| `web::audit::every_page_passes_the_audit` | 21 real pages (files, details, editor, links, account, QR, trash, search, favorites, login, every guest page, an unknown link): well-formed HTML, unique ids, labels, `alt`, button types, CSRF on every POST form, no inline script, style or handler, no `javascript:` URL, `rel="noopener"`; no CSS class unused, no page class without style or script; no `innerHTML`, `eval`, `document.write` in the scripts | `the_audit_catches_what_it_should`: 12 faulty samples, each caught. First run: 5 dead classes and an unused CSS rule removed, dialog buttons given their implicit `type="submit"` |

**Mutation testing** (`cargo mutants`, `auth/` and `tenant/`, 169 mutants): `tenant/` 40/40 caught; `auth/` 106 caught,
4 timeouts (caught), 2 survivors, both equivalent (kept on purpose: a session cookie of the wrong format is refused by the
database lookup anyway; purging expired IP entries more often than needed changes no outcome). The first run left 7
survivors, each a missing test, now added: the policy durations (5-minute attempt window, 10-minute QR wait, 12-hour
session) were only used symbolically; the 1,024-character `Authorization` bound was not tested at the bound; the
full-table purge on the recording path was not reached; **the dummy argon2 digest for nonexistent accounts was not
checked to be a real argon2id digest** (without it, response time would tell which accounts exist).

**Mutation testing of manifest format 2, `restore` and `--readers`** (2026-11-17, `cargo mutants --in-diff`, 150 mutants,
2 h, then `--iterate` on the 39 left, 29 min, the last one checked by hand): 118 caught, 16 unviable, 15 not reached by
the unit tests because they sit in the fuzz harnesses (`fuzz_restore`, `manifest::fuzz`: checked by `cargo fuzz`
instead), 1 survivor, equivalent: in `restore_from`, an error
other than "not found" while looking for the folder among the target's ancestors is reported by the next step anyway
(creating the missing parents) with the same error. The first run left 20 real survivors, each a missing test, now added:
the `--to` option and the lines `restore` prints (`restore_report`); default names (folder with a dot, no extension, dot
file, several dots); the error messages read by the administrator; two folders with the same NFC name; a name not in
UTF-8 counted as skipped; a write error midway fails the copy (never passed over as a name already taken); a failure
before anything is copied reports its cause and sends nothing to the trash. Two survivors in `apply_manifest` showed a
filter written twice (which files are re-read, and which are changed): now one, already covered.

Finding: a `MOVE` whose `Destination` is on another host answers 502 (RFC 4918 §9.9.4): kept, the only 5xx allowed.

**Second review of the same change** (cross-review, 2026-11-17), one defect and seven tests added. **Defect:** the manifest
is read with suspicion but its `tags` and `trash.*` fields were unbounded, so a manifest planted in the dataset could ask for
a 70 KB attribute: `xattr_set` then fails on the file (`rescan` dies after writing identities on the earlier items) or
succeeds and `xattr_get` (`XATTR_MAX`, 64 KiB) refuses it for good, breaking `labels`/`trash_list` for the whole tree. Tags
and `trash.*` are now bounded at parse time, as a write bounds them (`hostile_manifest_cannot_plant_oversized_attributes`,
bounds in `format_roundtrip_and_bad_lines`). `apply_manifest` now writes `beastbox.id` **last**: this pass only visits
items without one, so an error after it used to leave the item out of reach for every later `rescan` (ETag, tags and
favorite lost for good); `rescan_replays_a_half_applied_item` starts from that half-applied state and gets everything back.
The order itself cannot be asserted without a fault-injection point: left as is, noted here. The fuzz harness built its own
input with `std::fs` and panicked on a source path over `PATH_MAX` (`create_dir(...).unwrap()`), a fake crash that would
have stopped the `--long` campaign: budget on the path, two seeds for it (`seed-deep-200`, `seed-nfc-expansion`), and
`check.sh` now replays the seeds so a harness panic shows up without a 60 s campaign. Also found by this review: a restored
file whose name ends with a dot got the dot after the suffix (`a.` → `a (restored …).`, refused by Windows clients): a file
keeps its extension last only when it has one. `restored_names` (and the proptest
`restored_name_is_legal_and_keeps_the_extension`) pin the naming rule, the 233/234-byte bound included.

Other tests added, each checked to fail on the mutant it targets: `rescan_path_stops_at_its_folder_boundary` (`Docs` vs
`Docsx`; the boundary of `under` was never exercised), `a_manifest_never_gives_one_identity_twice` (a hand-edited manifest
with one identity on two paths: `rescan`'s later dedup hides the bug, so the test checks `duplicates == 0`),
`restore_never_touches_the_current_tree` now draws the target too (`R`, an existing file, an existing folder): never over an
existing item. The e2e `restore_brings_back_a_copy_next_to_the_current_version` now asserts **why** each refusal happens
(`chemin invalide` / `not found in` / `already exists`, from `SafePath`, not from the kernel by accident), refuses an
unknown user, and checks that alpha's restores never land in beta's space. Equivalent survivor found by hand: the
`exists(to)` pre-check in `restore_from` (the write path refuses the same target with the same error); kept as a cheap
early exit. Coverage on the N100 (FreeBSD, 2026-11-17, `check.sh`): `admin/mod.rs` 85.4 %, `fs/manifest.rs` 96.7 %,
the same as on Linux.

**Release 0.12.5 campaign** (2026-11-17, on the N100). Long property runs: the 10 proptests at 3,000 cases, all
passed (12 min 30, the sharing model taking most of it). Fuzz 60 s per target: no crash, about 4.5 million inputs
(`query`, which now covers search patterns: 115,000). Mutation testing **of the core only** (rule set at this release:
page rendering, `web/mod.rs` and `web/render.rs`, is held by end to end tests and the front end audit, and its layout by
the owner's previews), on what no earlier run covered: the bounds of the manifest and `restore` (`c3b34c87`) and the
search patterns, 75 mutants in 2 runs (49 min for the second): 55 caught, 2 timeouts (an endless loop in `glob`, caught),
7 unviable, 11 survivors. 7 sit in the fuzz harnesses (`fuzz_query`, `fuzz_restore`), as expected. 2 are equivalent, both
in `glob`'s backtracking: resuming at the `*` itself instead of just after it re-registers the same backtrack point, and
retrying the position the `*` already failed at fails again the same way; each costs one step, never another answer
(`glob_is_the_recursive_definition` checks the answers). 2 were missing tests, now added and checked to fail on their
mutant: patterns alone rank newest first like filters alone (a name with no letter, `_.md`, was ranked first),
`glob_patterns`; a `trash.*` field of exactly 4 KiB is kept, one byte more refused, `format_roundtrip_and_bad_lines`. A
recheck of those two by `cargo mutants` (the tool's field-deletion mutants of the same files came along) found one more,
older: a truncated index searched in a folder it lacks answered "nothing found" without saying it is incomplete untested,
now in `bounded_and_evicted`.
Front end tests no longer match CSS or JS text; `theme.js` is now run by `tests/js/theme.test.mjs` (stored theme, mode and
size, hostile values never put on the page, script mode set even when storage is refused).

**Accounts and two-step verification** (2026-11-18, `ea3fdb28` to `b57418fe`, on the N100). Password policy, `user
enable|disable`, password set by the administrator replaced at first sign-in, TOTP. Each security check was broken by hand
and rerun (26 mutants: session gates, Login Flow refusals, anti-replay, window, per-account limit, sealing, recovery code
parsing, setup check, ending other sessions): all caught, each by the test aimed at it. One survivor on the first pass,
a missing test, now added: the anti-replay in SQL (`totp_last < ?3`) is only reached by two requests racing with the same
code, `totp_step_is_used_once_in_sql`. `http` fuzz with a session that must choose its password and one waiting for its
code (oracle: neither opens a `/web/` page but its own): 9,961 runs in 69 s, clean.
**User isolation inside a tenant** (2026-11-18): there was no counterpart of `alpha_never_touches_beta` for two users of
the same tenant (same key, same database), only separate checks. `alice_never_touches_bob` sends random hostile
sequences (WebDAV on `/files/bob/`, traversal, `Destination` into bob's space, his file ids as thumbnail and "open in the
browser", his link through the web page and OCS, web pages with traversal); bob holds marked names and contents, a
favorite, a link and a trashed file. 512 cases clean. Checked on two hand mutants: without the `{user}` check, a `MKCOL`
on bob's path succeeds; serving the URL's user, bob's fingerprint changes. Two false alarms of the test itself were
fixed on the way (the search page shows the query back; alice may name her own files like bob's).

**Coverage of the weakest modules** (2026-11-18). Total 93.9 → **94.3 %** of regions. `dav/upload.rs` 79.6 → 89.9 %,
`dav/trashbin.rs` 84.0 → 94.4 %, `config.rs` 85.8 → 99.2 %, `dav/search.rs` 88.8 → 95.3 %: the behaviours that had no
test now have one (upload: unknown methods, chunk numbers at the bounds, size announced beyond the free space, assembly
to the root or outside the user's files, read-only mode; trash: OPTIONS, Depth infinity, malformed body, the restore
collection, a subfolder of a deleted folder, restore refusals, read-only mode, the other tenant; search: images or videos
alone, dates before, a bad date, entities in a literal, folders only, `allprop`, `has-preview`; configuration: every
bound and refusal, loading). What stays uncovered is a disk error in the middle of an operation or the blocking pool
exhausted (each answers an error, writes nothing). Floors raised in `check.sh` (total 94 %) and set for the modules above
and `auth/totp.rs` (97 %). Three expectations of the new tests were wrong, not the code: `&` comes back as `%26` in an
`href`, `allprop` is the DAV set, and restoring to `restore/` without a name is accepted on purpose (like Nextcloud).

**Release 0.13.0 campaign** (2026-11-18, code `9a5a81b4`, local CI: throwaway FreeBSD 15.1 VM on a Ryzen 7 8745H, 10 vCPU,
22 GiB, builds in a 16 GiB ZFS pool in RAM, tests' files on a ZFS disk). 132 min in all. Quick gates 3 min (249 tests:
236 library, 2 binary, 11 CLI on real datasets; coverage 94.4 % of regions); the 16 property tests at 3,000 cases 16 min;
fuzz 20 min, 10.3 million inputs, no crash (`http` 425,114 in 10 min on 3 workers); litmus 18 s against a server of the code
(`props` 11/14 by design, all else complete); mutation testing about 93 min: 249 mutants of the diff since 0.12.5, 239
caught, 8 unviable, 2 survivors accepted in `mutants-accepted.txt` (`base32`: `|` and `^` are equal on zeroed bits;
`record_code_at`: only when a log line is written). About 23 s per mutant, against 42 to 60 s on the N100.
The first full run (285 mutants, 60 survivors) had found: 34 in the fuzz harnesses, which tests do not build (now excluded),
10 in `main.rs`, run without its own tests (now against them and `tests/cli.rs`), and 15 real gaps, now tested or removed: the
Login Flow of a required tenant for an account with two-step verification on, the full per-account failure table, the
policy values, 4 distinct characters in a password, the account list's state columns, a copy failing before writing,
`serve`, the parser's refusals, and a dead function. No functional defect. The VM also exposed a flaky test (a second-step
test crossing a 30-second step) and a test frozen in `zil_commit` in the VM, fixed by `sync=disabled` on the test dataset
and a run timeout. The workstation's SSD received 14 GiB during the run, everything else on it included.

## 3. Fuzzing

cargo-fuzz 0.13.2, libFuzzer with AddressSanitizer, on FreeBSD 15.1. Targets in `fuzz/fuzz_targets/`, corpus committed in
`fuzz/corpus/` (seeds taken from real client requests, minimized with `cargo fuzz cmin`; inputs that crashed are kept in the
corpus). Rerun: `cargo +nightly fuzz run <target> -- -max_total_time=300`.

| Target | Property checked | Result |
|---|---|---|
| `propfind` | an arbitrary PROPFIND body does not crash the parser, **and the response produced is always well-formed XML** | 2 defects found and fixed (§8); final run on the fixed code: **5.2 M executions in 301 s, no crash** |
| `headers` | `SafePath` (no accepted path leaves the root or targets a reserved name), `Destination`, `Range`, `If-Match`, `OC-Checksum`, `X-OC-Mtime`, `Host` normalization, forms; since 0.9 the cleaned drop name (one NFC component, not hidden, nothing forbidden on Windows, no bidirectional control, no bare device name) | 5.5 M executions in 301 s, no crash; 0.9: 1 defect found and fixed (§8), then 1.34 M in 121 s, no crash |
| `search` | arbitrary SEARCH (`basicsearch`) body: no crash, rendered response (hostile name) always well-formed XML | 1 defect found and fixed (§8); then 5.9 M in 300 s and 1.1 M in 60 s after the common rule, no crash |
| `proppatch` | arbitrary PROPPATCH body: no crash, response (which echoes the names) always well-formed XML | 4.6 M in 180 s, 1.3 M in 60 s, no crash |
| `manifest` | arbitrary identity manifest (file back from external storage): no crash, every retained entry is rewritten and reread identically | 542,000 in 60 s, no crash |
| `restore` | arbitrary source tree (snapshot or restored backup: names in raw bytes, control characters, `\`, folders, links to `/etc/passwd` and `..`) restored into a space: no crash, **always succeeds** (a readable source never fails as a whole), existing item untouched, nothing written outside the target, every copy equal to the source file of the same NFC path, no identity held twice; seeds with Chinese, emoji, composed and decomposed accents, NFC collisions | ~310,000 in 10 min over 3 runs (3 workers), no crash; it found nothing, but its strengthened rule would have caught the decomposed-name defect fixed the same day |
| `query` | arbitrary web search text: no crash, words folded and non-empty, folding stable, highlighting gives back exactly the name | 1 defect found and fixed (§8: `ǣ` folded to `æ`, not `ae`); then 682,000 in 180 s, no crash |
| `thumb` | arbitrary file through `jpeg-decoder` and Beastbox's code (EXIF orientation, shrink, rotation, encoding): no crash, RSS ≤ 1 GiB, a result is always a readable JPEG no bigger than asked | 193,307 executions in 1,200 s on 3 workers (≈ 55/s: real decoding under ASan), no crash; corpus minimized to 662 files |
| `http` | arbitrary requests on the real router (method, route among WebDAV, chunked uploads, trash, SEARCH, drop and read links, previews, Login Flow, OCS, web; optional app password, session, CSRF, `Destination`/`Range`/`If-Match`/`Depth`/`X-OC-Mtime`/`OC-Checksum`/`Content-Type`, `Content-Length`; another tenant's host): no panic, never a 500, nothing written outside the data roots; the bench keeps its state between inputs | 280,990 requests in 1,200 s on 3 workers, no crash; corpus minimized to 1,656 requests |

## 4. WebDAV compliance (litmus 0.13, `litmus -k`)

Rerun 2026-11-18 on the test bench (0.12.5, with PROPPATCH limited to `oc:favorite` and SEARCH): the same result, in
0.4 s. Now a gate of `scripts/check.sh --long` (account `litmus` on the bench, compared with this table). SEARCH (RFC 5323)
is outside litmus: held by `dav::search` tests and the `search` fuzz target.

| Suite | Result | Justified failures and warnings |
|---|---|---|
| `basic` | 16/16 | "no class 2" warning (no WebDAV locks, intentional, not announced); `delete_fragment`: the `#fragment` is ignored, like Nextcloud |
| `copymove` | 13/13 | — |
| `props` | 11/14 | `propset`, `propmanyns`, `propget` no. 27: no free-form properties: PROPPATCH accepts `oc:favorite` only (any other property → 403, as intended) |
| `locks` | 3/3 | lock tests skipped (no class 2) |
| `http` | 4/4 | — |

## 5. Real hard kills (§0.2)

| Scenario | Result |
|---|---|
| 20 `kill -9` mid atomic write (automated test) | never a mixed file; identity kept |
| `kill -9` of the server mid-PUT of 300 MB replacing an existing file | old file intact; temporary deleted at restart (log: "orphan temporaries removed n=1") |
| `kill -9` mid **assembly** of a 2 GB chunked upload replacing an existing file | destination intact; 20 chunks kept; new attempt → 204, **identical SHA-1** to the original |
| Normal shutdown with a stuck request (headers never finished) | shutdown in 10 s instead of hanging forever (defect found with the desktop client, fixed) |

## 5b. Real backup and restore (procedures: `../admin/backup.md`)

| Trial | Result |
|---|---|
| restic 0.19.1: backup of a ZFS snapshot (100,000 files), restore, comparison of **all** xattrs | 8 Beastbox attributes identical on 100,327 entries; times, sizes, permissions identical; `verify`: no discrepancy |
| Control: restic restore without xattrs (`--exclude-xattr '*'`) | `verify` reports every file as "without identity" (the check does detect a loss) |
| restic: contents restored into a new dataset, then `rescan` | file identities kept (same `fileid`); only the root folder gets a new one |
| `zfs rollback` after a delete and an emptied trash | file back with the same identity, 0 identities to assign |
| **Total loss of the instance** (jail and data destroyed): jail via `bastille export --tgz` (NFS), data via restic to **pCloud** | data identical entry by entry (except the root folder's attributes); `verify` without discrepancy; app password, share link, **web session from before the loss** valid; desktop clients: everything re-downloaded without conflict (ETags tied to the inode, fixed in 0.2.0) |
| xattr-less file copy (simulated: times to the second) + identity manifest | identities, tags, favorites, trash and links recovered, ETags kept (automated tests); *real `rclone` to pCloud not yet tried* |
| Identities erased on a folder synced by two desktop clients (2026-11-17, `CLIENTS.md`) | without manifest: full re-download, link ended for good, tag and favorite lost; with the format 1 manifest: identities back but full re-download and a conflict; **format 2: no re-download, no conflict**, everything back |

Findings from the trials:
- restic backed up from inside the folder (`backup .`): the root loses its xattrs; back up the snapshot folder instead.
- Restoring "the contents of" does not put back the root's xattrs: new identity on `rescan` (link to the whole space lost).
- `bastille export --tgz` archives the jail folder file by file, **mounted data and xattrs included** (8.8 GB); `--gz`/`--xz`
  on ZFS only send the jail's dataset. Data datasets stay mounted with the jail stopped; jail "dying" after stopping:
  `zfs unmount -f`.
- Durations (total loss, alice 8.4 GB + bob 100,000 files): export 7 min, restic → pCloud 5 min (5.5 GB stored), import
  1 min 36, restic ← pCloud 1 min 26.
- To compare two trees: `getextattr -f` (without `-f`, it stops at the first file lacking the attribute, giving a wrong
  reading).

## 6. Real clients (detail: `CLIENTS.md`)

| Client | What was demonstrated |
|---|---|
| Nextcloud desktop client 34.0.x and 35.0.2 (Windows, Linux) | Login Flow; tree displayed; change made over SSH then `rescan` detected in 26 s (only the changed branch reread); photo upload; 2.9 GB ISO in 30 chunks of 100 MiB, SHA-1 checked; renames (MOVE, identity kept); deletes to `.trash/` |
| Android app 35.0.2 | Login Flow; browsing; upload of a photo and a PDF; folder creation (409 then parent created by the app); Favorites, Recent and Photos tabs (`SEARCH`); star set from the app (`PROPPATCH`); *"Deleted files" not yet tried* |
| `rclone` (`nextcloud` provider) | import of 4 files including an accented name, times kept, `rclone check`: 0 differences (SHA-1), second pass with no transfer |
| `curl` | every WebDAV operation, chunked upload of 12 MB and 2 GB |

## 7. Performance and memory

Machines: **N100**: mini PC Intel N100 (4 cores), SanDisk Extreme Pro 1 TB **NVMe**, FreeBSD 15.1, ZFS;
**HDD**: Xeon E3-1260L, ZFS RAIDZ1 of 3 hard disks (5,400 to 5,900 rpm). Details below.

| Measurement | Value | Budget (§0.4) | Machine |
|---|---|---|---|
| RSS at rest | 6 MB; 27-34 MB after use (argon2 kept by the allocator) | < 50 MB | N100, NVMe |
| RSS under load (20 PROPFIND of 10,000 entries in parallel) | 33.8 MB | < 150 MB | N100, NVMe |
| PROPFIND 1,000 entries (xattrs included) | 7.7 ms direct, 13 ms via nginx | < 50 ms | N100, NVMe |
| PROPFIND 10,000 entries | 120 ms (12 ms / 1,000) | proportional | N100, NVMe |
| PUT small file | 2.2 ms | < 20 ms | N100, NVMe |
| Upload / read throughput | 246 MB/s / ~1 GB/s | local network | N100, NVMe |
| 100,000 files: `rescan` / `verify` | 1.85 s / 1.29 s, ~11 MB | — | N100, NVMe |
| Cost at rest (60 s) | 0 CPU, 0 I/O, 0 context switches | zero | N100, NVMe |
| Search over 100,000 files | index build 1.9 s, then 1 to 4 ms per search, +6 MB | < 100 ms | N100, NVMe |
| Identity manifest, 100,000 files | 1.2 s, 7.3 MB; `rescan` with manifest 1.9 s | — | N100, NVMe |
| 100,000 files (98.7 GB): `manifest` | 1.4 s warm, 2.4 s cold | — | N100, NVMe |
| 100,000 files (98.7 GB): restore, every content reread to prove it | 137 s with 8 readers (~725 MB/s); 306 s with 1 | — | N100, NVMe |
| 100,000 files (20.3 GB): `manifest` | 2.6 s warm, 2.9 s with no cache | — | HDD |
| 100,000 files (20.3 GB): restore, every content reread to prove it | 1,181 s with 8 readers (~17 MB/s); 1,788 s with 1 | — | HDD |

### Measurement details (formerly `PERF.md`)

### Budgets (§0.4, to confirm on real hardware)
| Measurement | Budget |
|---|---|
| RSS at rest (100,000 files) | < 50 MB |
| RSS under load (20 transfers, search) | < 150 MB |
| PROPFIND 1,000 entries, p95, warm cache | < 50 ms |
| PUT/GET small file, p95, excluding network | < 20 ms |
| Search over 100,000 files | < 100 ms |
| App password check, p95 | < 1 ms |
| Tolerated regression from one milestone to the next | 15 % |

### J0 — 2026-11-14
Machine: N100 (FreeBSD 15.1-RELEASE-p5, amd64), thin jail `beastbox`, release binary (fat lto), 2 tokio
workers, 4 blocking threads.

| Measurement | Value | Method |
|---|---|---|
| Binary size | 3.8 MB (stripped, dynamically linked to libc) | `ls -l` |
| RSS at rest, 2 tenants | 6.1 MB | `ps -o rss` |
| RSS after 20,000 `GET /status.php` (20 connections) | 8.5 MB | same |
| `GET /status.php` throughput via test nginx | ~2,600 req/s, p50 2.7 ms, p95 31 ms | Python client, 20 threads (**the client is the bottleneck**, indicative measurement) |
| Open descriptors | 17 | `procstat -f` |
| I/O at rest | no background task | by construction (no timer, no walk) |

To do: load tool (`oha`/`wrk`) missing from the host — reproducible benches to install at J1; cost of reading one xattr per
entry over 1,000 entries (J1).

### J1 — 2026-11-14
Same machine and jail. Folder of 1,000 files (identities in xattr, `xattr=sa`), 7 properties requested like the desktop client.

| Measurement | Direct (jail → :8080) | Via test nginx | Budget |
|---|---|---|---|
| PROPFIND Depth 0 | 0.4 ms | 0.7 ms | — |
| PROPFIND Depth 1, 1,000 entries (xattr reads included) | 7.7 ms (p50) | 13 ms (p50) | < 50 ms |
| GET 17 B | — | 0.8 ms (p50) | < 20 ms |
| RSS at rest | 6 MB | | < 50 MB |
| RSS after Login Flow + repeated PROPFIND | 27.5 MB | | < 150 MB under load |
| Cost at rest over 60 s | 0 CPU, 0 I/O, 0 context switches | | zero |

Findings:
- **`proxy_buffering off` is required on the proxy**: with nginx's response buffer, every streamed (chunked) response takes
  ~40 ms more (42 ms instead of 0.7 ms for a PROPFIND Depth 0). Fixed in `rc/nginx-test.conf`; to carry over to the
  production proxy.
- `TCP_NODELAY` enabled on accepted connections (responses in several chunks).
- RSS rises by ~20 MB after a Login Flow connection: argon2id memory (19 MiB) kept by the allocator after use. Bounded by the
  argon2 concurrency (2): expected cap ~45 MB. To watch with a real load test.
- Streamed responses release the blocking thread between two chunks: a slow client ties up no thread.

### J2 — 2026-11-14 (writes)
Same machine and jail, via the test nginx. Every write does an `fsync` of the file, the folder and the ETag journal.

| Measurement | Value | Budget |
|---|---|---|
| PUT 5 B (30 trials) | p50 2.2 ms, p95 2.8 ms | < 20 ms |
| PUT 500 MB (one stream) | 246 MB/s | local network |
| GET 500 MB | ~1 GB/s | local network |
| Chunked upload 12 MB (3 chunks) + assembly | reread identical (SHA-1) | — |
| RSS after these trials | 31 MB | < 150 MB under load |

Memory of an upload: at most 256 KiB buffered per request (batch written by a short `spawn_blocking`).
The per-intent `fsync` of the journal does not weigh (2.2 ms per PUT): no batching needed for now.

### J2 — 100,000-file reference set (2026-11-15)
Test account `bob` (tenant `beta`): 10 folders of 10,000 empty files (`ref/d0` … `ref/d9`), identities assigned by `rescan`.
Direct measurements (jail → :8080), 10 properties requested like the desktop client.

| Measurement | Value | Budget |
|---|---|---|
| `rescan` of 100,012 items (identity assignment, ETag) | 1.85 s, max RSS 10.6 MB | — |
| `verify` of 100,000 files | 1.29 s, max RSS 11.7 MB | — |
| PROPFIND Depth 1, folder of 10,000 entries (6.6 MB response) | p50 120 ms, p95 157 ms | 50 ms for 1,000 entries (→ 12 ms / 1,000) |
| PROPFIND of a folder with 10 subfolders | p50 0.7 ms | — |
| Server RSS before / after / after 20 PROPFIND of 10,000 entries in parallel | 31.1 / 31.8 / 33.8 MB | < 50 MB at rest, < 150 MB under load |

No in-memory index before J4: server memory depends neither on the number nor on the size of files.

### J3 — web interface (2026-11-15)
| Measurement | Value | Budget |
|---|---|---|
| Web page of a folder of 10,000 entries (sorting, the page's tags) | p50 60 ms, 251 KB of HTML (page of 500) | — |
| Web page of a small folder | 0.8 ms | — |
| RSS after web login / after 10 pages of 10,000 entries in parallel | 27 / 46 MB | < 50 / < 150 MB |

Defect fixed by measuring: the first version rendered the whole page (5 MB of HTML, RSS at 61 MB); paginated by 500.

### 0.7.0 — `static/text.js` (colouring, editor)
Raw 6.4 KB, gzip 2.8 KB, loaded only by the pages that show or edit a text file (`app.js` 24.9 / 7.9 KB, `app.css`
41.9 / 9.9 KB). Regular expressions measured on adversarial 512 KiB texts (Node 22, one pass): every case ≤ 62 ms except
Markdown links on lines of `[` (≤ 208 ms, bounded lengths). The first version was quadratic (`"\"\"…` in JSON did not finish
in 2 minutes): see §8.

### J3b — interface weight (2026-11-15)
| Resource | Raw | gzip -9 |
|---|---|---|
| `app.js` (native JavaScript, no library) | 16.5 KB | 5.4 KB |
| `app.css` | 16.0 KB | 4.5 KB |
| 18 SVG icons | 5.0 KB | — |
| **Total** | **37.5 KB** | **~13 KB** |

Tree (rendered by the server around the current folder, subfolders of the current folder taken from the listing): page of a
folder of 10,000 entries p50 77 ms (60 ms without); `/web/tree/` fragment of such a folder 62 ms; small folder 0.6 ms.

Served by the binary with caching; compression is left to the proxy. Grid thumbnails: the original image with
`loading="lazy"` (no server computation). shortcut: large photos heavy in the grid on mobile, server thumbnails if usage
justifies it.

### J4 — search index (2026-11-15)
Account `bob` (100,000 files, 10 folders of 10,000), test bench, warm cache.
| Measurement | Value | Budget |
|---|---|---|
| Index build (first search: walk + identity and tag xattrs) | 1.9 s | — (on first use only) |
| Search by name (`f5000`, `999`, `ref`) | p50 2.8 to 3.9 ms, max 4.2 ms | < 100 ms over 100,000 files |
| Search by tag | p50 1.0 ms | < 100 ms |
| RSS before / after build | 32.4 / 38.6 MB (≈ 60 bytes per entry) | < 50 MB at rest |

0.6.0 (accents ignored, ranking over the whole space instead of the first 200 found): worst case measured locally,
release build, 100,000 names of which half are non-ASCII and every one matches (`e`, `f`): p50 33 to 36 ms; no match
(`zzz`) 10 ms; `type:pdf` 10 ms. Bench measurement on `bob` below.

Sidebar (favorites read from the index): the **first page** after 15 min of inactivity builds the index (1.5 s for `bob`,
57 ms for `alice`), the following ones ≈ 1 ms.

Update on a write: only the touched parent folders are reread (one `readdir` each). Projection for the 1 million file target
(§0.5): ≈ 60 MB of index, build ≈ 20 s; cap of 1,000,000 entries per tenant, eviction after 15 min of inactivity.

### Identity manifest (2026-11-15, N100 bench, ZFS `xattr=sa`)
- `beastbox manifest`: 100,001 files, 13 folders, 213 items in the trash → **1.2 s**, 7.3 MB file (~73 B/entry); 1,461 files:
  instant.
- `beastbox rescan` with a 100,000-entry manifest to read (nothing to recover): **1.9 s**. Memory: the manifest and the list
  of items are held in memory during the command (~20 MB for 100,000 entries), CLI only.

### Manifest (format 2) and restore on hard disks (2026-11-17, HDD host)
Machine: Xeon E3-1260L (4 cores, 8 threads, 2.4 GHz), 16 GB RAM, ARC up to 16 GB (default; 12 GB in use), FreeBSD
15.1-RELEASE-p6, OpenZFS 2.4.2. Pool: **one RAIDZ1 vdev of 3 hard disks** (Seagate IronWolf ST2000VN004 and
ST2000VN000 2 TB at 5,900 rpm, ST4000VN006 4 TB at 5,400 rpm, limited to 2 TB by the vdev), `ashift=12`, 42 % full, 32 %
fragmented. Throwaway dataset `<pool>/beastbox-bench/alpha/alice`: `recordsize=128K`, `compression=lz4`, `xattr=sa`,
`atime=off`, `sync=standard`. Data: **100,000 files of 50 to 350 KB** of random data (20.3 GB) in 101 folders, each with
an identity and a sum record, as written by the server.
- `beastbox manifest`: **2.6 s** (warm cache), **2.9 s** with `primarycache=none` (every metadata read from the disks);
  file of **12.4 MB** (~124 B/entry); peak RSS 60 MB. The cost follows the number of files, not their size.
- `rescan` of a restore (every `beastbox.*` xattr erased, manifest present): 100,101 identities and **100,000 ETags**
  recovered, `verify` without discrepancy.
  - `primarycache=metadata` (no data cache): **1,289 s (21.5 min) for 20.3 GB, ~16 MB/s**, peak RSS 87 MB.
  - Normal cache (`primarycache=all`): **1,788 s (29.8 min), ~11 MB/s**, peak RSS 87 MB; prefetch never started (files of
    1 or 2 records), ~191,000 data reads from the disks (~2 per file). The gap with the run above is not explained
    (other activity on the NAS at night, not checked).
  - Reading: bound by the disks' operations per second, not their throughput. Small files on a RAIDZ1 of hard disks:
    ~11 to 17 MB/s, i.e. ~5 to 8 h for 300 GB of such files; larger files (photos, videos) read faster, not measured.
- Several readers at once (`rescan --readers N`, same data, every xattr erased before each run):

  | Readers | `primarycache=all` | `primarycache=metadata` |
  |---|---|---|
  | 1 | 1,788 s | 1,289 s |
  | 2 | | 1,852 s |
  | 4 | | 1,935 s |
  | 8 | **1,181 s** | 1,328 s |
  | 16 | | 1,469 s |

  Noisy (runs of 20 to 30 min on a NAS in service, nights of 2026-11-16/17): with the normal cache, 8 readers saved a
  third; without the data cache, no gain. 2 and 4 never beat 8, 16 is slower than 8.

### Manifest and rescan on NVMe (2026-11-17, N100)
SanDisk Extreme Pro 1 TB NVMe, pool `zroot`, `recordsize=128K`, `compression=lz4`, `xattr=sa`; **98.7 GB**, 100,000
generated files in 101 folders (~1 MB each); dataset destroyed after the runs.
- `beastbox manifest`: **1.4 s** warm, **2.4 s** cold.
- `rescan` of a restore (every xattr erased), by readers: 1 → **306 s** (~330 MB/s), 2 → 189 s, 4 → 156 s, **8 → 137 s**
  (~725 MB/s), 16 → 152 s.
- Hence `--readers` defaults to 8 and is capped at 8: best on both machines, more is slower.
- Not measured: a pool of mirrors.

### Alert thresholds
To define with the metrics (J7).

## 8. Defects found by the tests and fixed

| Found by | Defect | Fix |
|---|---|---|
| Desktop client | `HEAD` on a folder → 405 (Nextcloud answers 200) | 200 without body |
| Desktop client | server shutdown blocked forever by a request left open (502 on the proxy) | shutdown bounded to 10 s |
| Measurement | ~40 ms added to every streamed response | `TCP_NODELAY`, and `proxy_buffering off` required on the proxy |
| Measurement (J3) | web page of a folder of 10,000 entries built in one go (5 MB of HTML, RSS 61 MB) | paginated by 500 |
| Automated test (J3) | downloading a folder through a public link answered 405 (the path betrayed its nature) | identical 404 |
| Real trial (J3) | the result of a password change (success or failure) was shown the same way, in green at the top of the page, with a 200 code (no functional defect: the change in the trial had succeeded) | error in red (`role="alert"`) in the section, code 401/400, "nothing was changed"; success confirmed in the section; test strengthened |
| restic test (J4) | restic backup made from inside the folder (`backup .`): the root folder lost its xattrs and its time | procedure: back up the snapshot folder as one item (`../admin/backup.md`) |
| restic test (J4) | `verify` returned 0 even with discrepancies (a backup script could not detect them) | exit code 1 if there are discrepancies |
| Real trial with two desktop clients (J4) | after a restore by file copy with the manifest, every ETag changed (neither SHA-1 nor nanoseconds kept): each client re-downloaded everything, and a file changed locally meanwhile became a conflict | manifest format 2: SHA-1 and nanoseconds; on `rescan`, content reread, same SHA-1 → same ETag |
| Measurement on hard disks (HDD host) | `rescan` and `manifest` failed ("No such file or directory") on a dataset without `.trash`/`.beastbox-tmp`: what a copy that drops empty folders (rclone, any object storage) brings back | both recreate the reserved folders; regression test (`copy_restore_keeps_links_with_manifest`) |
| Edge-case test (`restore`) | a name with decomposed accents (macOS) in the source failed the whole restore (`SafePath` looked for its NFC form) | source read by its exact name, written in NFC; a collision of two NFC forms is passed over and counted |
| Code review (`restore`) | `--from` naming the space itself could copy a folder into itself (endless copy) | refused (`IntoItself`), like WebDAV COPY |
| Real trial (J3b) | "Tags and sharing" button on the root → 404 (`/web/view/` with a trailing slash not routed) | route added, regression test |
| `curl` | raw UTF-8 `Destination` refused | accepted then decoded |
| Automated test | `read_dir` on a duplicated descriptor started from the end of the folder | `rewinddir` |
| Fuzzing `headers` (0.9) | a drop name whose bidirectional control sat between combining marks came out of the cleaning out of NFC (the name used was not the one written) | the cleaned name is the `SafePath`'s (NFC); input kept in the corpus |
| Fuzzing | invalid property name echoed in the response (invalid XML, injection) | names validated, 400 |
| Fuzzing | reserved `xml:` namespace bound to another prefix in the response | reserved namespaces refused, 400 |
| Review of the fuzzing fix | property without a namespace rendered with `xmlns:x=""` (invalid) | rendered with `xmlns=""` |
| litmus | malformed PROPFIND body accepted | 400 |
| litmus | invalid namespace declaration accepted | 400 |
| Fuzzing (SEARCH) | hostile property name in `select` echoed in the response (invalid XML, injection) | a single rule for the three parsers (`prop_name_ok`) |
| Fuzzing (web search) | `ǣ` folded to `æ` (decomposition then lowercase), `ae` on a second pass: folding unstable | decompose again after the lowercase, ligatures spelled out last |
| Measurement (0.7.0) | colouring quadratic on a crafted text (unterminated strings on one line): a dropped file could freeze the owner's page | unterminated strings run to the end of the line, every other scan bounded |
| Security review (0.7.0) | edit form body (≤ 1.5 MiB) read by the extractor **before** the session check: a visitor could make the server hold 1.5 MiB per connection | raw `Body`, read by the handler after the session, up to the route limit |
| Android app | Favorites, Recent, Photos tabs failing ("Unable to fetch sharees"): `OPTIONS /remote.php/dav` 404, `SEARCH` missing | WebDAV search implemented |
| Android app | star impossible to set (`PROPPATCH` 405); `oc:favorite` missing from PROPFIND | PROPPATCH `oc:favorite`, favorite read with the metadata |
| Real trial | Recent showing "everything" or "recent" depending on the refresh: folders, always dated now, came first | Recent without folders |
| Real trial | expired link still shown in the list; exhausted link still showing its page | list limited to usable links, same response as an unknown link |
| Logs | app passwords revoked "blindly" (all named "Login Flow v2", no last-use date); valid tokens blocked by another source's failures from the same IP | client name and last use; only failures are limited |
| Audit | Login Flow: 64 anonymous requests blocked every new client login | 4 pending flows per IP |
| Audit | a video played by ranges exhausted a link's download limit | signed cookie: a download counts once |
| Audit | a failed drop (or one abandoned mid-upload) kept its reservation on the link's volume | reservation given back on every unsuccessful exit |
| Audit | a suspended link reread the whole trash on every visit | only "has the target come back?" |
| Real restore | 3.3 GB re-downloaded by clients after a restore (ETags tied to the inode) | ETag: identity, time, size, SHA-1 (0.2.0) |
| Test (trash) | trash item without a date (lost xattr) purged right away (dated 1970) | dated from its discovery |
| Test (failures) | a drop link ignored `min_free_bytes`: a guest could fill the space reserve every signed-in write respects | same check as WebDAV writes (503) |

## 9. What is not tested yet

Weight first: [Before production] blocks an exposure to the Internet, [Important] should come soon, [Minor] is nice to have.

- [Before production] **Power** loss (a `kill -9` leaves the kernel cache intact); real full pool (only the quota was tested).
- [Minor] `kill -9` mid ETag propagation under real conditions (covered by a unit test of the journal).
- [Important] Resuming an interrupted upload **by the clients**; chunked upload and download from the Android app (the desktop client's
  chunked upload works: 1 GB in 10 chunks, 2026-11-16).
- [Important] Two domains with real clients at the same time. The desktop client's virtual files mode works (browsing, download on
  open); "Always keep on this device" only fetches the content after a sync, on the client's side.
- [Minor] Link sharing from the iOS app and the macOS client (same API as Windows and Android, not tried).
- [Before production] Memory abuse test: many slow clients, 1 hour of repeated load (§10 Memory).
- [Important] Copying a file from a snapshot with its xattrs; backup with a real `rclone` to pCloud with the manifest.
- [Minor] Deliberate loss of identities on a synced folder with the Android app (done with two desktop clients, `CLIENTS.md`).
- [Important] JavaScript in an automated browser; screen readers; Safari; keyboard accessibility (manual trial to do).
- [Before production] External scan behind the proxy, **human security review** (required before exposure, §12.5; guide in `SURFACE.md`).
- [Important] Two-step verification with a real authenticator app on a phone, and the Login Flow code field with the real
  desktop and mobile clients (covered by end to end tests with RFC 6238 codes).

Coverage left on purpose (product, about 95 % of regions, 97 % of lines): `?` on errors no test can provoke without breaking
the machine, `Err` of a blocking task (only if it panics), code run only by `tests/cli.rs` (`--lib` does not count it), the child
of the capability-mode test (it cannot write its profile). A real full disk in the editor (507) is not provoked either.

## 10. Known limits and deliberate shortcuts

Decisions, not oversights: each has its reason, and most a `shortcut:` comment in the code (list: `grep -rn 'shortcut:'
src`). To revisit if a measurement or usage justifies it.
- **Writes**: streamed reads in 64 KiB chunks (no `sendfile`); `If-Match` checked right before the `rename`, without a
  per-path lock (two simultaneous PUTs: the last one wins); upload assembly: one blocking thread during the copy, peak space =
  2 × the size; byte-by-byte copy (no ZFS clone), tags not copied by COPY; one `fsync` per journal intent; a single SQLite
  connection behind a lock.
- **Maintenance**: `rescan` and index build without I/O throttling; no collision detection on 53-bit `fileid`s; global trash
  retention (not per tenant yet); restore: existence checked then `renameat` (no per-path lock).
- **Web**: thumbnails = original image (no computed thumbnails); clients' `/index.php/core/preview`: JPEG only (none for PNG, HEIC, screenshots or videos),
  computed on every request (no cache: the clients keep theirs), CMYK and 16-bit JPEGs refused;
  above 128×128 px, `jpeg-decoder` decodes each colour component in its own short-lived thread (≤ 2 × 4 threads);
  a file whose header announces more pixels than it holds is decoded padded with zeros: measured 0.55 s for a
  689-byte file announcing 100 Mpx (the cap), the user's own file only, 2 decodings at once; `fileId` found by a full
  scan of the user's index; right after an upload, the Android app asks once with the first 8 digits of `oc:id` (404),
  then with `oc:fileid`; tree limited to 1,000 subfolders per folder; without
  JavaScript, the move dialog only shows the folders around the current folder; times displayed in the server's time zone.
- **Links**: a link does not follow its renamed or moved target (it ends); a restore that must rename to "(restored)" → link
  ended; a link's state is observed when it is opened or the list is displayed, not instantly.
- **WebDAV search**: scope limited to the whole space (`/files/<user>`); search by `oc:fileid` → empty list.
- **Test bench**: `insecure_cookies` (cleartext HTTP), never in production (warning at startup); no `Remote-User` header (SSO
  through the proxy), to decide.
