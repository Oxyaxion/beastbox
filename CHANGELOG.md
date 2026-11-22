# Release notes

One entry per release, newest first. Each release is a `vX.Y.Z` tag; the tag annotation repeats its entry. Sections:
**Before upgrading** (anything that needs action or that clients will notice), then Changed, Added, Fixed, Security. Details are
in `git log vX.Y.Z-1..vX.Y.Z`.

## 0.16.1 — 2026-11-22

### Before upgrading
- **A new app password asks your password again** (Account page, mobile QR code, Login Flow confirmation). An account
  bound to single sign-on without a password gives its two-step code instead, or signs in again if it has none.
- **The Login Flow confirmation page** now shows which software asks and from which address, with a warning: only
  authorize a connection you started yourself, a moment ago.
- **No more passwords from the administrator: activation links.** `user add` creates an account **without a password**
  and prints an activation link (single use, 24 hours) where the person chooses one; `user passwd` removes the
  password and prints such a link (standard input is no longer read); on a tenant that requires two-step
  verification, the phone is bound from that link too, and `user 2fa-reset` prints one. Send each link to its person
  only.
- **On a `required` tenant, an account without two-step verification can no longer set it up with its password
  alone**: it waits for a link (`user 2fa-reset --tenant T NAME`), which asks its current password and the phone's
  code. Accounts that already have it are not affected.
- The links use the tenant's `public_base_url` (new, in `[[tenant]]`), otherwise `https://` + its first exact host;
  a tenant with wildcard hosts only needs `public_base_url`.
- The project is now on Codeberg (https://codeberg.org/Modulus/beastbox), under the **AGPL-3.0-or-later** license; the
  test report is at https://modulus.codeberg.page/beastbox/.

### Changed
- Sign-in failures from IPv6 are counted per /64 (one subscriber or machine), also for the Login Flow's per-address
  limit.
- An account bound to single sign-on manages its two-step verification with its code alone (it has no password).

### Security
- **Login Flow consent phishing**: a link received from someone else, opened while signed in, could hand a permanent app
  password to the sender's client in one click, past the second step. The page now names the client and its address,
  warns, and asks the password (or code) again.
- **Session to permanent access**: a stolen web session could create an app password; it now needs the password again.
- **Tenant-wide lockout**: one IPv6 /64 could fill the failure limits of a whole tenant; an OIDC flow cookie could be
  replayed for 10 minutes (one back-channel call each). Failures are now counted per /64 and each flow signs in once.
- Share link cookies and CSRF tokens are compared in constant time.
- **First phone bound by whoever has the password** (two-step verification required): the setup page let the first
  person signing in with the password bind their own phone. A first phone is now bound only from an activation link.
- **Login Flow confirmed twice at once** (double click, two tabs): two app passwords were created, one of them handed
  to nobody. The first confirmation now takes the flow; the other creates nothing.

### Tests
- The reproof rule; app passwords refused without or with a wrong password, the address limit, the other tenant; the
  Login Flow page (origin, warning, escaping, limit); single sign-on accounts (recent sign-in, code, two-step
  verification without a password); an OIDC flow used once; IPv6 per /64 (property test); constant-time equality
  (property test); revoking an app password: own only, with the form token, refused at once on WebDAV and OCS;
  a Login Flow confirmed twice at once gives one app password; wrong passwords on a share link never count against
  another link; a link limited to one download serves exactly one of 16 simultaneous requests (checked to fail when
  the limit is not enforced by the database); activation links: reading consumes nothing, single use (and two
  submissions at once), dead links all answer the same, a weak or mismatched password or a wrong code keeps the link,
  an account with a password must give it (limited per address), single sign-on accounts bind only a phone, sessions
  end, a disabled account's link waits; the setup page no longer binds a phone; the CLI prints the links with the
  tenant's address and refuses before creating anything when there is none.

## 0.16.0 — 2026-11-22

### Before upgrading
- **Hidden files** (name starting with `.`) are **no longer shown** in the web list, grid and tree by default; the new
  "Show hidden files" link shows them (remembered a year per browser). WebDAV, sync clients, search and public share
  links still see everything.
- **Page size**: 50 entries per page by default (was 500); sizes offered 20, 50, 100, 500, 1000, from 21 entries. A
  remembered 200 falls back to 50. Public share listings keep 500.
- **Moving onto a taken name** (Move dialog and drag and drop) now succeeds under the next free name (`Photos (2)`,
  `a (2).txt`) instead of failing; nothing is ever overwritten.

### Added
- **Sort by type**, and a **Sort menu** in both the list and the grid (the grid had no sort): name, size, modified,
  type, tags, both directions. Type: folders, then image, video, audio, pdf, doc, sheet, md, text, json, code, archive,
  others; then extension, then name.
- After a move or a copy, the message says where it went: `« Photos (2) » moved to B.` — the name opens the
  destination with the item marked, the destination is a link.
- **Spring-loaded tree folders**: while dragging, a closed folder of the tree held 0.7 s opens.
- **Files with no extension** (`README`, `hosts`, `.bashrc`) are shown and edited when their content is plain text
  (UTF-8, no control character but tab and line ends).

### Changed
- Drag and drop moves through the Move dialog's form (one rule, the same message); the page reloads to show it.

### Fixed
- Dragging a folder or a file towards the tree no longer makes Chrome offer a split view (the drag carried the link's
  URL).

### Security
- Saving a file with no extension checks its current content again: a binary file is never replaced by text.
- The move/copy message's `to` and `name` parameters are checked like any path: a hostile value gives no link.

### Tests
- End to end: sort by type in both views (menu state, links keeping the view, unknown key), hidden files (list, grid,
  tree, cookie, `voir=`, a hidden folder by its address), page sizes and the 20/21 boundary, a move onto a taken name
  (numbering, identity kept, refusals, the message and its links, hostile values), the drag-and-drop form, text files
  with no extension (eight kinds of content, a binary never replaced); each with the other tenant.
- Property tests: the type order is total with folders first; hiding removes exactly the dot names; a move lands at the
  first free name and overwrites nothing; plain-text detection.
- JavaScript (`node --test`): the drag-and-drop form, following a folder moved under a new name, spring-loaded timers.

## 0.15.0 — 2026-11-20

### Before upgrading
- **Single sign-on may now be used in production**: the owner's human security review is done (plan §12.5).
- On a tenant with `second_factor = "provider"`, `two_factor = "required"` and no password door (`password_login`
  off), accounts without a Beastbox TOTP are **no longer sent to the TOTP setup**: the provider's `amr` is the second
  factor. With `password_login = true` the setup is still required (a password session stays possible).
- A tenant answering on several hosts: `GET /login/oidc` on a host other than the `redirect_uri` base first redirects
  to the base host.
- Calendar and contacts (CalDAV/CardDAV) are out of scope: Radicale runs beside Beastbox (plan §14, J6 dropped).

### Fixed
- **Trash**: "Empty the trash" and the per-item "Delete permanently" buttons did nothing with JavaScript on. A hidden
  `required` "I confirm" box blocked the submit before the confirmation dialog, without any message. The server
  still refuses an unconfirmed purge.
- **OIDC**: `client_secret_basic` form-encodes the client id and secret before base64 (RFC 6749 §2.3.1); a secret with
  `: % + & =` was refused by the provider.
- **OIDC**: on a tenant with several hosts, a sign-in started on another host always failed (the `__Host-` flow
  cookie lived on the host the provider does not return to).
- **OIDC**: `second_factor = "provider"` on a required tenant sent accounts without a local TOTP to its setup.

### Security
- The Casper back channel connects without blocking: the channel's lock is no longer held while an unreachable
  provider address times out (every OIDC sign-in waited behind it); the connection is awaited with its own timeout.
- A missing or forged OIDC flow cookie or `state` counts against the sender's address only, no longer in the
  tenant-wide limit, which a few addresses could fill to close every sign-in of the tenant.
- A failed discovery fetch is remembered 30 s (the `Retry-After`): an anonymous request no longer opens a
  back-channel connection each time the provider is down.

### Tests
- Every commit now also runs `cargo machete` (unused dependencies), `cargo vet --locked` (supply chain: imported
  audits, 29 audited and 118 exempted at the baseline), `cargo geiger` (crates using `unsafe` must be listed in
  `docs/dev/unsafe-crates.txt`), and `cargo deny` refuses a new duplicate crate. About 25 s more.
- `bench-report.py check-names`: a test named as the proof of a security rule or a model must exist (the 0.14.0
  report listed `login_flow_asks_the_code`, renamed, as missing).
- The front-end audit refuses a `required` field inside `.nojs` on every page.
- Regression tests: provider second factor on a required tenant, start on another host, discovery failure kept,
  forged cookies and the tenant limit, Basic encoding (the mock provider decodes as RFC 6749 says), Casper
  connection awaited (success and closed port).
- `scripts/vm.sh rebuild` works again (old host keys forgotten, `ram` after the `ztest` pool).

## 0.14.0 — 2026-11-19

### Before upgrading
- **Single sign-on** is new and stays **disabled in production until the human security review** (plan §12.5):
  a tenant only changes by adding `[tenant.oidc]`. On such a tenant the web sign-in form is **gone** — the
  provider is the only way in — unless `password_login = true` keeps a local form for a break-glass account.
  An account is bound to a provider identity by the administrator (`user add --oidc`, then `user oidc-link`),
  never by name or at first sign-in; linking clears that account's password and ends its sessions, and
  `beastbox user passwd` is the way back (identity removed).
- **Clients** (desktop, mobile) now confirm a Login Flow through the browser's login page, which carries the
  single sign-on button: an account without a password can connect a device. The confirmation page no longer
  asks for a username and a password.
- Coverage floors are measured on the product only (test-only files no longer count) and include the new
  modules, `fs/casper.rs` among them.

### Added
- **Single sign-on (OIDC)** per tenant, optional (`[tenant.oidc]` in the configuration; design
  `docs/dev/oidc-proposal.md`, plan `docs/dev/oidc-implementation-plan.md`). Authorization code flow + PKCE
  S256, `id_token` checked (TLS is the trust anchor, ADR-5), identities bound to accounts by the
  administrator only (`user add --oidc`, `user oidc-link`). The back channel goes through the Casper
  `system.net` service of the base system (`libcasper`, a forked child, nothing to install), limited to the
  configured destinations (ADR-6).
  Routes `GET /login/oidc` and `GET /login/oidc/callback` (public, the callback inherits the login's rate
  limit), SSO button on the login page. On a tenant with a provider the Beastbox password form is gone
  (`password_login = true` keeps it for a break-glass account): the provider is the only way in, and the
  account's own TOTP, when it has one, is asked after. Disabled in production until the human security review.
  `[tenant.oidc] public_base_url` sets the base of `redirect_uri` when TLS does not end on 443 (its host
  must be one of the tenant's hosts; the base still comes from the configuration only). The CA bundle and
  the client secret are read once at startup, before Capsicum.

### Fixed
- The **Login Flow v2** confirmation page works for an account without a password (single sign-on): an anonymous
  browser is sent to `/login` with the flow as its return address (`/index.php/login/v2/flow/<token>` joins the login
  allowlist), and a signed-in browser only has to authorize, which creates the app password. It used to ask for a
  username, a password and a code, which a linked account can never give — the desktop client could not connect.

### Security
- A drop link now respects `min_free_bytes`: a guest could fill the space reserve that every signed-in write keeps free.
  Below the reserve the drop is refused with 503, as WebDAV writes are.

### Tests
- Coverage is measured on the product only (files made of tests no longer count; the capability-mode glue
  `isolation`, which needs `cap_enter()`, is excluded too), in regions and lines; floors
  raised, including `auth/oidc.rs` ≥ 98 %, `auth/oidc_net.rs` ≥ 82 %, `web/oidc.rs` ≥ 95 %.
- New end-to-end tests: refusals and limits of the forms and client APIs, database, disk and password-worker failures, clean
  stop on SIGTERM. OIDC: the full flow against a mock provider (real TLS), every refusal, the rate limit,
  the back-channel failures (broken discovery, unreachable or non-TLS endpoint, oversized body), RFC 9207
  `iss`, `client_secret_post`, TOTP pending session; the real Casper service (channel, limits, allowlist, a local
  connection); a property for the one-door rule (no credential opens a tenant that delegates its sign-in); two
  tenants with a provider sharing an issuer; the Login Flow through the login page.

## 0.13.0 — 2026-11-18

### Before upgrading
- **Two-step verification** is per tenant: `two_factor = "off" | "optional" | "required"` (default `optional`). Nothing
  changes for an account that never turned it on; in an `off` tenant the pages offer nothing, but a user who has it may
  keep or drop it.
- A password set by the administrator (`user add`, `user passwd`) must be replaced at the first sign-in; accounts created
  before this release are not marked.
- **Password policy**: a chosen password is refused below `min_password` (default 12, never under 10) and when it is weak
  (see Added). Generated passwords are never refused.
- `beastbox user list` gains two columns (2fa, active/disabled) and speaks English.

### Added
- **Two-step verification (TOTP, RFC 6238)**: QR code and key to enroll, 10 single-use recovery codes shown once, new
  codes or turn off from the account page (password and code required; turning off is refused when the tenant requires
  it). `beastbox user 2fa-reset` removes it for an account.
- **Copy and duplicate**: "Duplicate" in the selection bar, "Copy here" in the "Move or copy…" dialog; a copy never
  replaces anything (`name (2).ext`), gets its own identity, and a copy failing midway goes to the trash; WebDAV `COPY`
  gets both.
- **`beastbox user disable` / `enable`**: a disabled account cannot sign in and its web sessions end; its devices and
  public links stop (a link answers 404) while its files stay.
- **Password policy** (`min_password`, default 12): a chosen password is refused when shorter, when it holds the account
  or tenant name, has fewer than 4 distinct characters, is a run of the alphabet, digits or a keyboard row, or equals
  the current one; each refusal has its own message.
- First sign-in with a password received from the administrator opens only the welcome page: the received password and
  the new one twice; success ends every session of the account.

### Changed
- The row's button opens the move **or copy** dialog and is named so.

### Security
- The waiting session of a sign-in that needs a code reaches `/login/code` only; a time step works once (enforced in
  SQL); wrong codes are limited to 5 per account per 15 minutes, all addresses combined; the secret is sealed with the
  tenant key and the recovery codes are stored as digests.
- The gates come in the same order everywhere the owner reaches a page (web, Login Flow, `/web/welcome`): code, password
  change, setup required by the tenant. Until they are passed, the Login Flow connects no device (403) and the browser
  WebDAV answers 401.
- Public links and devices require an active account.

### Tests
- `tests/cli.rs`: the real `beastbox` binary on real ZFS datasets, judging every command by its exit code, its output
  and its effect, with the other user and the other tenant untouched.
- Copy and duplicate end to end (taken names, folders, repeated duplicates, a move into the same folder, a folder into
  itself, no or missing destination, no CSRF, another tenant); a copy failing midway; name generator unit test and
  proptest.
- The untested behaviours of chunked uploads, client trash, client search and the configuration; user isolation inside a
  tenant as a property (`alice_never_touches_bob`: WebDAV, traversal, pages, OCS, links, thumbnails); two-step
  verification and the forced password change (`src/web/tests_totp.rs`).
- Coverage 93.9 → 94.3 %; floors raised (total 94 %) and set for the modules above.
- Release gates: `scripts/release.sh` measures everything before tagging (the version change undone on failure);
  `check.sh --long` gives the HTTP fuzz target 10 minutes on 3 workers, keeps its logs and stops on a crash, and
  mutation testing sees new files. This campaign's numbers are in `VALIDATION.md`.

## 0.12.5 — 2026-11-17

### Before upgrading
- **White is the default theme**: everyone who never chose a theme sees it (also without JavaScript and on the public
  link pages). Green stays available in Account › Appearance.
- Scripts and the stylesheet are now revalidated on every load (ETag, `no-cache`): a new version shows at once after an
  upgrade, no hard refresh needed from now on. Icons are kept a day.
- Manifest **format 2** (SHA-1 and nanoseconds of each file); format 1 is still read.

### Added
- **`beastbox restore --from DIR --path P [--to Q]`**: copies a file or folder back from a snapshot or any folder, at its
  place if gone, otherwise next to it; never overwrites; a partial copy goes to the trash. **`rescan --readers N`**
  (1 to 8): contents proven by several readers. After a restore by file copy, rescan proves the content and keeps
  identity and ETag, so desktop clients neither re-download nor create conflicts.
- **Search with wildcards** on the whole name: `*.md`, `rapport-202?.pdf`, combined with words and filters.
- **Folder links open at the item**: from a search result, a favorite, a recent file card, a shared link or the link
  history, the folder opens at the page holding the item, marked and scrolled to (`?voir=<name>#vise`, no script).
- **Drag and drop**: a checked item carries the whole selection; every folder of the left tree is a target, and tree
  folders can be dragged; a compact label (stacked, "+N") beside the pointer keeps the target visible.
- **Rename in the selection bar** when exactly one item is checked.
- **Text size** in Account › Appearance: Normal, Large, Larger (100, 112.5, 125 %), the whole page growing with it.
- **Phones**: one-line top bar (search and menu buttons, the links in a native popover), size and date under each name,
  44 px touch targets, 16 px text and form fields (no iOS zoom on focus), recent files as a carousel.
- Key **P** opens the preview panel on the focused, selected or first file; Markdown editor: "Preview" toggles; links in
  the recent activity and link history (file and folder, only while they exist).

### Changed
- Wider pages (132rem), no width cap on the details page and the editor; left tree 19rem; preview panel 40 % of the
  screen on large screens.
- One folder link everywhere (search, starred, trash, recent activity, shared links): the parent's own name, cut at 25
  characters, the full path as a tooltip, styled like the links of "Your shared links".

### Fixed
- Recent activity ran off the screen on phones (the carousel's column grew to every card side by side).
- A hidden button stayed visible (`hidden` lost to `button { display: inline-flex }`); the selection bar wrapped its
  last button (fixed at `left: 50%` with no width).
- The selection bar and the logo flashed at every page change (script mode set late; icons revalidated each time).
- Back to an untouched editor reopened it instead of the details page; an upgraded script stayed hidden an hour behind
  the cache.
- Manifest apply writes the identity last (an error no longer leaves an item out of reach of later rescans); restored
  names ending with a dot keep it.

### Security
- Manifest fields are bounded when parsed (tags normalized and capped, trash fields 4 KiB): a manifest planted in the
  dataset can no longer make an attribute too large to read back, which broke labels and the trash for the whole tree.
- Search patterns are bounded (64 characters, linear matching with one backtrack point, fixed parts filtered first).

### Tests
- New: front end audit of every rendered page (HTML, accessibility, CSP, CSRF, unused CSS, dangerous JS); fuzz oracle
  "never access without credentials" and tenant isolation property test; glob boundaries and a proptest against the
  recursive definition (fuzz `query` covers patterns); `?voir` end to end (page bounds, grid, hostile name, other
  tenant) and a proptest of the page chosen; folder label cut; drag and drop rules under `node --test` (optional in
  `check.sh`) and `theme.js` run on a fake page; static cache policy.
- Front end tests check behavior, never CSS or JS text (layout is checked on previews); mutation testing covers the core
  (not page rendering), on the diff since the last tag.
- Release campaign on the bench host: 179 tests and 13 JavaScript rules pass; the 10 proptests at 3,000 cases; fuzz 60 s per
  target, no crash (about 4.5 million inputs); 75 core mutants: 3 missing tests found and added, the other survivors in
  the fuzz harnesses or equivalent (`VALIDATION.md`).

## 0.12.0 — 2026-11-16

### Before upgrading
- New dependency `qrcode` 0.14.1 (MIT or Apache-2.0, `svg` feature only: no dependency, no `unsafe`).

### Added
- **Connect the mobile app with a QR code** (Account page, "Connect the mobile app (QR code)"): the Nextcloud Android and
  iOS apps scan it from their login screen ("Scan QR code") and connect without typing a password. Each QR code holds a
  new app password that is **gone after 10 minutes if unused**, kept once used (then revocable like any device); a new
  QR code cancels the previous one not used yet, so it can be shown again to reconnect a phone. Shown once, never cached.

### Tests
- `qr_password_waits_ten_minutes_for_its_first_use`, `qr_code_for_the_mobile_app` (CSRF, `no-store`, shown once, one
  pending code), `qr_login_reads_back` (proptest: the code reads back as the apps read it). Checked with the Android app
  on the bench. Fuzz `http` with the new route: about 186,000 requests in 10 minutes, no crash.

## 0.11.1 — 2026-11-16

### Added
- **"Open in the browser" from the clients** (`/index.php/f/<fileid>`): the item is looked up among the signed-in user's
  own files and shown in the web interface (a file's page, a folder's listing). Without a session, through the login,
  which brings the user back to it.

### Security
- The login's return address only accepts `/index.php/f/<digits>`: it can never send anyone to another site
  (property-tested).

### Tests
- `open_in_browser_from_a_client` (login and back, file, folder, unknown item, other tenant, five hostile return
  addresses), `login_return_is_always_local` (proptest); fuzz `http` with the new route (about 195,000 requests in
  10 minutes, no crash); long runs before the release: 3,000 sequences for each of the three proptest tests (WebDAV model,
  client links model, login return), no divergence.

## 0.11.0 — 2026-11-16

### Before upgrading
- Two database migrations (automatic at startup, backup copy first): link options (read and upload, label, note, hidden
  download) and the owner's actions in the link history.
- New key file per tenant, `keys/<tenant>.links.key`, created at startup: **links created before 0.11 stop working**
  (recreate them). Back it up with the rest of `state_dir`; a copy of `state_dir` gives access to every live link
  (`docs/admin/backup.md`).
- `beastbox user passwd` now ends the account's web sessions (devices stay connected).
- WebDAV `MOVE`/`COPY` onto the same path answers 403 (was 204), as RFC 4918 and Nextcloud.

### Added
- **Links from the clients** (Windows, macOS, Android; iOS untested): create, list, change and revoke public links through
  Nextcloud's sharing API, the same links as the web page; "shared" icon in the clients (`oc:share-types`).
- **Link options**, from the clients and the web page: **read and upload** for a folder (the guest sees it and adds files,
  never changes nor deletes one; taken names get a suffix), **label**, **note to the guest** (shown on the link's page),
  **hidden download** (files the browser can show open in it, no archive, the rest is not served; a deterrent only).
- Link history: **link created** and **link revoked**, from the web page or a client.
- `proptest` model-based tests, now required for every feature (plan §10): WebDAV and client links.

### Changed
- Sharing window: the options that let visitors send files are folded under a warning; wider window.
- Guest pages: one centered column, the name first, "Powered by Beastbox" at the bottom; public pages (login, links,
  errors, device login) no longer show the version.
- A permission a client asks for is never refused: it is mapped to the closest access, never above what was asked (a
  file's "editing" gives read only).

### Fixed
- `MOVE`/`COPY` of a subfolder **onto its own parent** with `Overwrite: T` trashed the whole parent, source included, then
  failed (found by the WebDAV model test; nothing was lost, everything was in the trash).
- A client sending a modification time beyond year 9999 (`X-OC-Mtime`) made its folder unlistable (found by fuzzing); web
  date rendering also bounded.
- Android could not read the sharing answers (it expects XML, and a 32-bit link identifier).

### Security
- Dedicated link key (renewable alone, `docs/admin/backup.md`); a token is only accepted if it derives from the current key.
- Changing a password ends the account's web sessions: a stolen session does not survive it.

### Tests
- `client_share_links` (OCS end to end, JSON and XML), `client_links_follow_the_model`, `webdav_follows_the_model`,
  `renewed_link_key_ends_old_links`, `password_change_ends_web_sessions`, `public_pages_hide_the_version`,
  `far_dates_never_panic`, `absurd_dates_never_panic`, an ancestor overwrite case in `fs`.
- Fuzz `http`: 3 runs of 10 minutes (about 145,000, 145,000 and 120,000 requests), no crash after the date fix; the 3 inputs
  that crashed are kept in the corpus.

## 0.10.0 — 2026-11-16

### Before upgrading
- The server now runs in Capsicum capability mode (FreeBSD): the kernel must have `CAPABILITY_MODE` (in `GENERIC` by
  default; `sysctl kern.features.security_capability_mode` gives 1). Nothing to configure.
- On shutdown, SQLite can no longer delete `app.db-wal` and `app.db-shm`: they stay next to the database and are
  reused at the next start.

### Security
- **Capsicum capability mode**: once the data roots, database, journals and listening socket are open, `serve` calls
  `cap_enter()`. From then on the kernel refuses any path, outgoing connection, new process or access to other
  processes (`ECAPMODE`), even if the server is compromised (e.g. through the JPEG decoder or the XML parser). The
  data the process already holds (every tenant's root, the database) stays reachable: Capsicum limits the escape, not
  a logic flaw. Rights per descriptor (`cap_rights_limit`) come next.

### Tests
- `serves_in_capability_mode`: in a child process in capability mode, opening `/etc/passwd` is refused, and MKCOL,
  PUT, GET, PROPFIND, thumbnail, MOVE, DELETE, trash listing and 3000 SQLite transactions (past the WAL checkpoint)
  work. Checked on the bench: phone photo and its thumbnail, 1 GB chunked upload from the Windows client.

## 0.9.0 — 2026-11-16

### Before upgrading
- Database migration (automatic at startup): drop links count their files (`drop_files`). Files dropped before the
  upgrade are not counted.
- New setting `drop_max_files` (500 per link by default).
- A client that sends nothing for 60 s in the middle of a request body is now cut (the write in progress is thrown
  away, as for any interrupted upload). Sync clients resume their uploads.

### Security
- **Slow uploads**: every request body must send a byte at least every 60 s, whatever reads it (WebDAV, chunked
  uploads, drop links, forms). Before, a client trickling bytes held a connection forever, and 256 of them blocked the
  server for every tenant.
- **Drop links**: at most 4 drops at once per link and 16 in all (beyond: 503 at once, the connection is freed); at
  most `drop_max_files` files per link (a failed drop gives its file back), so empty files cannot flood the folder.
- **Dropped names cleaned** so that every client of the owner can sync them and nothing is disguised: characters
  forbidden on Windows (`: * ? " < > |`) replaced by `_`, bidirectional controls removed (`facture‮fdp.exe` displayed
  as `facture.pdf`…), trailing dots and spaces removed, Windows device names (`CON`, `nul.txt`, `COM1`…) prefixed
  with `_`. Hidden names stay refused.

### Tests
- `drop_links_are_bounded` (names on disk, guest cut after 60 s in virtual time, file count given back, limit),
  `stalled_upload_is_cut` (WebDAV), `drop_slots_are_bounded_and_given_back`, `drop_names_and_suffixes` extended.
- New fuzz target **`http`**: arbitrary requests on the real router (WebDAV, chunked uploads, trash, search, drop and
  read links, previews, Login Flow, web pages with session and CSRF): no panic, never a 500, nothing written outside
  the data roots. The `headers` target also checks the cleaned drop names: it found one defect, fixed
  (`docs/dev/VALIDATION.md` §8).

## 0.8.0 — 2026-11-16

### Before upgrading
- Behind an SSO, also exempt `/index.php/core/preview` on the proxy (the clients authenticate it with their app password).
- Sync clients now see `nc:has-preview` true on `.jpg`/`.jpeg` files and ask for their thumbnails.

### Added
- Thumbnails for the Nextcloud clients (`/index.php/core/preview?fileId=`), for JPEG photos: decoded directly at 1/2,
  1/4 or 1/8 of the size, reduced to the size asked (at most 1,280 px), **turned upright** according to the photo's EXIF
  orientation, computed on every request and **never written to disk** (the clients keep their own cache). At most 2
  decodings at once; dimensions checked before decoding (≤ 100 Mpx, progressive ≤ 12 Mpx), ≤ 64 MiB read. No thumbnail
  for PNG, HEIC, screenshots or videos: 404, the client keeps its icon, as before.
- The search index keeps each file's `oc:fileid` (+8 bytes per entry) to find a file from its `fileId`.
- Dependencies: `jpeg-decoder` 0.3.2 (image-rs) and `jpeg-encoder` 0.7.1, both built without any `unsafe` code
  (`forbid(unsafe_code)`) and without dependencies of their own (`docs/dev/DEPS.md`). `jpeg-encoder` carries the IJG
  licence: allowed for this crate only in `deny.toml`, attribution at the bottom of the README.

### Tests
- `client_thumbnails` (end to end: has-preview, size and upright result, cap, 401, 404 cases, other tenant, overwritten
  file); `nc::thumb::tests` (orientation in both byte orders, the 8 rotations, averaging, real photos, truncations,
  oversized dimensions refused before decoding); fuzz target `thumb` (decoder included).

## 0.7.3 — 2026-11-16

### Before upgrading
- Nothing to migrate. A rename from the edit page is an ordinary rename for the sync clients; like any rename, it ends
  the file's share links (they do not follow a rename, §8.6).

### Added
- Rename from the edit page: the name is a field in the header. The contents are saved first, then the file is renamed
  in its folder (identity, tags and star kept; never over an existing item). A name refused (not a text name, "/",
  reserved, invalid) saves nothing; a name taken saves the contents and says it was not renamed. A warning shows when the
  file has a share link. The icon and colouring follow the name being typed (.txt → .md → .json).

### Tests
- `text_edit_rename`; `render::tests::text_extensions_are_text`.

### Fixed
- Name dialog (new folder, new text file, rename): pressing **Enter** after typing the name cancelled silently, since the
  dialog's first button is "Cancel" and Enter triggers a form's first button (since J3b). Enter now confirms a non-empty
  name; only the "Confirm" button worked before.

## 0.7.2 — 2026-11-16

### Before upgrading
- Nothing to migrate, no change visible to sync clients (web interface only).

### Added
- "Recent activity": a **Recently deleted** section, the 4 items most recently moved to the trash (where they were,
  when), with a link to the trash to restore them. Permanently deleted items are gone and are not shown.

### Changed
- "Recently modified" renamed **Recent files** (since 0.7.1 it lists the last activity: added, changed, moved, tagged).

### Tests
- `upload_with_old_date_is_recent_activity` also covers the deleted items (at most 4, gone once the trash is emptied,
  hostile name escaped).

## 0.7.1 — 2026-11-16

### Before upgrading
- Nothing to migrate. The search index takes 8 more bytes per entry (rebuilt by itself on first use).

### Fixed
- Uploaded files missing from "Recent activity": an upload keeps the file's own date (`X-OC-Mtime`, sent by the web
  interface and the clients), so a photo taken in 2023 and uploaded today was not "recent". The box now orders files by
  their **last activity** (the inode's change time: added, changed, moved, tagged or starred) and shows when it happened;
  the modification date shown elsewhere stays the original one, and the clients' "Recent" tab (WebDAV) is unchanged.
  After a `rescan` that gives identities, or a restore from backup, the files concerned count as recent activity.

### Tests
- `upload_with_old_date_is_recent_activity` (fails without the fix).

## 0.7.0 — 2026-11-16

### Before upgrading
- Nothing to migrate. A file saved from the web is an ordinary write: sync clients download the new version.

### Added
- **Text editing** from the web interface: "Edit" on a text file (txt, md, json, sh, yaml, csv…) of 512 KiB at most in
  UTF-8. Plain form (works without JavaScript); Ctrl+S saves; warning before leaving with unsaved changes. Identity, tags,
  favorite and share links kept; line ends (LF or CRLF) kept.
- Conflict: if the file changed elsewhere since it was opened, nothing is saved; the text typed comes back with
  "Replace it with my text" or "Discard my changes and reload".
- Markdown: "Preview" rendered by the server (same sanitizing as the details page), next to the text on wide screens.
- Syntax colouring of JSON, shell and Markdown, when reading (details page, and code blocks of a Markdown file) and
  editing: `static/text.js`, 2.8 KB gzip, loaded only by these pages.
- "+ New" menu in a folder (replaces "New folder"): **Folder** or **Text file**. The text file is created empty by the
  server (a text name: .txt, .md, .json, .sh…; ".txt" added when there is no extension; never over an existing item),
  then opens in the editor.
- "Copy the contents" button in the top right corner of a text file shown in full (txt, md, json, sh, yaml…): copies
  the file itself (Markdown: its source, line ends kept).

### Fixed
- Creating a folder, renaming, moving to the trash or moving by drag and drop from a folder's page did the action, then
  opened `/web/files/[object Response]` ("Not found") instead of refreshing the list (since 0.5.0: the refresh received
  the server's answer as its address).

### Security
- Editing goes through the same WebDAV write path (read-only, space reserve, quota, atomic write); larger form body
  (1.5 MiB) on this route only, **read only after the session is checked** (a visitor cannot make the server hold it in
  memory); colouring linear on any text (a crafted file from a drop link cannot freeze the page).

### Tests
- `text_edit_save_conflict_and_limits`, `text_edit_security`, `text_edit_read_only`, `text_file_create`.

## 0.6.1 — 2026-11-16

### Before upgrading
- Nothing to migrate, no change visible to sync clients (web interface only).

### Changed
- After "Create the link", the "Shared links" page opens on a "Link created" card: the item, the full link ready to copy
  (the Copy button has the focus), its options, and a way back to the item. Its row in the list is marked "New".

### Fixed
- Reloading the page after creating a link created a second one: creation now answers a redirect.

### Tests
- `share_created_is_shown_first`.

## 0.6.0 — 2026-11-16

### Before upgrading
- Nothing to migrate, no change visible to sync clients (their WebDAV search keeps its behaviour, newest first).
- The search bar of a folder's page now searches **in that folder** (and its subfolders); the results page shows
  "In « folder » ✕" and, when nothing is found, "Search everywhere".

### Changed
- Search ignores accents, case and punctuation: `impots` finds "Impôts.pdf", `rapport final` finds
  "rapport_final-v2.docx"; same for tags (`tag:impots`).
- Results ranked over the whole space (the 200 best, no longer the first 200 found): exact name, then words that start a
  word of the name, then elsewhere; within a rank, newest first, then by name.
- Words found highlighted in the names.

### Added
- Filters: `type:` (`folder`, `image`, `video`, `audio`, `pdf`, `doc`, `archive`, `code`), `is:fav`, `after:` and
  `before:` (`2024`, `2024-03`, `2024-03-15`, local time). An unknown or invalid operator is searched as words.
- Filter chips on the search page (types, last 7 / 30 days, this year, starred): plain links, without JavaScript.

### Fixed
- Found by fuzzing before release: some letters (`ǣ`) folded differently on a second pass.

### Tests
- `search_scope_and_filters`, `index::tests::rank_scope_and_filters`, `render::tests::periods_and_highlights`; new fuzz
  target `query` (682,000 runs, no crash). Worst case over 100,000 files: 36 ms (`VALIDATION.md` §7).

## 0.5.5 — 2026-11-15

### Before upgrading
- Nothing to migrate, no change visible to sync clients (web interface only).

### Changed
- Preview panel: ← → go to the previous / next document, ↑ ↓ scroll the document shown (long text and Markdown);
  text scrolls with the panel, which goes back to the top on each new document.

### Fixed
- "…" before the delete button on every row: with a monospace font, the spaces between the buttons made them wider
  than the column. The buttons are now a flex row with a fixed gap (width independent of the font), and the
  actions column never shows an ellipsis. On phones, the column no longer cuts its two buttons.

## 0.5.4 — 2026-11-15

### Before upgrading
- Nothing to migrate, no change visible to sync clients (web interface only).

### Fixed
- Folder rows twice as tall and "…" in the actions column (0.5.3): the empty slot replacing the preview button
  reused the `.vide` class of the empty-folder message and inherited its padding. Renamed; actions column 13rem.

### Tests
- A folder row carries the empty slot, not the empty-state class.

## 0.5.3 — 2026-11-15

### Before upgrading
- Nothing to migrate, no change visible to sync clients (web interface only). The English interface says
  **Starred** where it said Favorites (URLs unchanged).

### Changed
- English interface: **Starred** instead of Favorites (star button: Star; French unchanged: Favoris).
- Starred page: the folder an item comes from is left-aligned under its name, after "From:" ("Depuis :").
- Preview panel: ↑ ↓ ← → show the previous / next previewable item of the list, the row shown is highlighted.
- Row actions always in the same place: an empty slot where there is no preview (folders, other files).
- The details page of a file or folder keeps the sidebar tree, opened on its folder.

### Fixed
- Tables without a checkbox column (Starred page, public link page) no longer center their first column.
- File rows: the delete button was cut off and replaced by "…" (actions column too narrow for five buttons).

## 0.5.2 — 2026-11-15

### Before upgrading
- Nothing to migrate, no change visible to sync clients (web interface only).

### Changed
- **Shared links** page redone: one compact row per link (type icon, name and folder, chips for access, password and
  expiry, usage), actions on the right (Copy link, URL, Revoke), "History" as a quiet link. The URL is no longer shown in
  a field: **URL** opens a bubble with the link selected (native popover, works without JavaScript).
- The history no longer has a link selector (unreadable with many links): a row's History filters it, and a chip
  names the link (with its state once ended) with ✕ to show every link again.

### Fixed
- **Copy link** did nothing on plain HTTP (the clipboard API exists only on HTTPS): it falls back to the older copy
  command, and if that fails too, the bubble opens with the URL selected.

### Tests
- Link row (folder icon, copy button tied to its bubble, no selector); ended, suspended and exhausted links checked
  through the filter chip.

## 0.5.1 — 2026-11-15

### Before upgrading
- Nothing to migrate, no change visible to sync clients (web interface only).

### Changed
- List or grid is remembered (cookie, a year, per browser): moving to another folder from the tree, the breadcrumbs
  or a folder keeps the view chosen last, until **List** is clicked.
- Icon colours: text files slate blue, videos raspberry; only unknown files stay grey.

### Tests
- The grid choice sets the cookie, another folder opens in the grid, `view=list` goes back and is remembered.

## 0.5.0 — 2026-11-15

### Before upgrading
- Nothing to migrate, no change visible to sync clients (web interface only).

### Added
- One-click favorite (star) from a listing; tags and sharing in popovers.
- Logo (the daemon in its box) in the header, the footer, the sign-in page and the favicon.

### Changed
- File-type icons from Tabler Icons (MIT, see `static/icons/NOTICE`), one colour per type, and **the same set in every
  view**: list, grid, recent activity, favorites, search, trash and details. The old hand-drawn set is removed.
- Sorting the file list (Name, Size, Modified, Tags) replaces only the list: no page reload, the recent activity box
  and the scroll position stay put; the address and the browser's Back button still follow the sort.
- Sidebar tree text slightly larger.

### Fixed
- Account → Language: the Save button no longer stretches to the height of the label and the list.

### Tests
- `folder.svg` and `g-folder.svg` serve the same icon.

## 0.4.0 — 2026-11-15

### Before upgrading
- Nothing to migrate, no change visible to clients. The interface is now in English by default (French browsers
  keep French).

### Added
- **Interface language**: English by default, French when the browser asks for it (`Accept-Language`), and a
  **Language** choice in the account page (cookie, a year, per browser). Public links, the Nextcloud login flow
  pages and the messages written by the JavaScript follow the same choice.

### Changed
- Every user-facing string (pages, error pages, notices, dates, sizes, link history, trash, account) is written in
  English in the code and translated by `src/i18n.rs`: the French table is keyed by the English text, an unknown
  string falls back to English.
- Sizes in English notation (`1.5 KiB`) and French one (`1,5 Kio`); CLI and log messages are English.

### Tests
- Language detection (browser, cookie priority), English and French pages end to end, the account switch, and a
  test that every `lang.t("…")` of the templates and the code has a French entry.

## 0.3.0 — 2026-11-15

### Before upgrading
- Nothing to migrate, no change visible to clients.
- If you back up by **file copy** (rclone, `rsync` without `-X`), add `beastbox manifest` right before the copy
  (`docs/admin/backup.md`): without it, a restore loses share links, tags and favorites.
- `rescan` now reads `.beastbox-manifest` if it exists, and stops on an unreadable manifest (without changing anything).
- Documentation reorganized: `docs/admin/` (install, upgrade, back up) and `docs/dev/`.

### Added
- **Identity manifest** (`beastbox manifest --tenant T [--user U]`): makes a backup by **file copy** safe (rclone to a cloud,
  `rsync` without `-X`, `cp`), which loses xattrs. Written into the user's dataset before the copy (`.beastbox-manifest`,
  reserved name, invisible to clients), it travels out and back with it; `rescan` then gives every item without an identity
  its original one, with its tags and favorite, and restores the trash metadata: share links, tags, favorites and trash
  recovered. Rules: a file is matched only at the same path, same size and same time to the second; a folder at the same
  path; an identity already held elsewhere is never reused; an existing xattr always wins. Cost: 1.2 s and 7.3 MB for 100,000
  files.

### Changed
- `rescan` reads the manifest if present, and **fails** if its format is unknown (rather than silently assigning new
  identities). Its output counts the recovered identities.

### Tests
- xattr-less copy of a full tree (accented names, `%`, tags, favorites, trash with a folder), times truncated to the second:
  everything comes back identical. Identity never stolen, existing xattr wins, changed size or time → new identity,
  `rescan --path` scoped. End to end: link, tag and favorite recovered with the manifest, lost without. Format: round trip and
  hostile lines. New fuzzing target (`manifest`). Defects reintroduced to check the tests.

## 0.2.0 — 2026-11-15

### Before upgrading
- **All file ETags change once** (new formula, below): on the first pass after the upgrade, each Nextcloud client rechecks and
  re-downloads the files it syncs. No loss or conflict, but it is the volume of a full sync per device. Preferably do it when
  devices are on a good network.
- Nothing to migrate: no change to the database, configuration or disk.

### Changed
- **File ETags stable across a restore.** They are now computed from the file's persistent identity, its time (to the
  nanosecond), its size and the SHA-1 recorded at write time, no longer from its inode. A restore (restic, a copy that keeps
  xattrs) or a migration to another server therefore no longer re-downloads everything: only files that really differ from
  the backup are. Measured on the bench before this change: 3.3 GB re-downloaded by two desktop clients after a full restore.
  A file without an identity (arrived outside the application, before `rescan`) keeps the old formula.

### Tests
- Restore simulated on real files (new inode, same xattrs and time): same ETag. Two writes of the same size and the same
  `X-OC-Mtime`, different contents: different ETag, end to end over WebDAV. One invariant per field of the formula, and
  independently computed reference values, so that no formula change goes unnoticed. Each test checked by reintroducing the
  defect (SHA-1 removed, inode put back).

## 0.1.0 — 2026-11-15

First tagged release: the state of the test bench at the end of milestone J4 (code done, demonstrations remaining). Never
publicly exposed: the human security review from J3 is still to be done before any exposure.

### Added
- **Nextcloud-client-compatible server** (desktop, Android, `rclone`): WebDAV (PROPFIND, GET with ranges, PUT, MKCOL, MOVE,
  COPY, DELETE to the trash, PROPPATCH `oc:favorite`), chunked upload v2, Login Flow v2, OCS (capabilities, user), WebDAV
  `SEARCH` (the app's Favorites, Recent, Photos tabs), `trashbin`.
- **Multi-tenant**: one tenant per host name, one ZFS dataset per user (quota), isolation verified by tests.
- **Data**: atomic write (§0.2), persistent file identity in xattrs, folder ETags propagated and logged, `verify` and
  `rescan`, trash with retention (`trash_days`).
- **Web interface**: files (list, grid, multi-select, preview, tree, move), search (name, tags), Favorites, trash, Account
  page (connected devices named after the client, last use), themes (Green, Nord, Catppuccin, Gruvbox, Graphite, White) and
  light, dark or system mode, local times, footer with the version.
- **Share links**: read or drop, password, expiry, download limit (counted once per download, even with ranges), history
  (downloads, drops, refused passwords; no IP), "Recent activity" box; a link is suspended while its target is in the trash,
  resumed on restore, ended when it is renamed or deleted.
- **Backup and restore** documented and tested (`RESTORE.md`): ZFS snapshot, restic (including to pCloud), total loss of the
  instance recovered from `bastille export` and restic.

### Security
- Authentication failures limited per IP and per tenant; a valid app password is never blocked by another source's failures.
  Login Flow limited to 4 pending flows per IP. XML parsers (PROPFIND, SEARCH, PROPPATCH) fuzzed, a single validation rule for
  names echoed in responses. Attack surface described in `SURFACE.md`.
