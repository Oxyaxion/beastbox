# Attack surface — J3 state (in progress)

A security review starts here (§0.3). Update at every milestone; reread the diff.

## Process and privileges
- Dedicated unprivileged user `beastbox` (uid 873 in the test jail), never root. Supervisor `daemon(8)` (root) restarts the child.
- `umask 077` at startup: folders 0700, files 0600.
- Capsicum: `serve` enters **capability mode** (`cap_enter`) once the roots, database, journals and socket are open:
  no path, outgoing connection or new process afterwards (`ECAPMODE`). Every access is a relative `openat`
  (`O_RESOLVE_BENEATH | O_NOFOLLOW`) and descriptor-based xattr (`extattr_*_fd`). Test: `http::serves_in_capability_mode`.
  **Not yet**: `cap_rights_limit` per descriptor (J5, second step).
- No `std::process` outside tests. `unsafe` restricted to `src/fs/` (each block has a `// SAFETY:`).
- No ZFS operation by the application.

## Network
| Listener | Default | Access |
|---|---|---|
| Cleartext HTTP | `127.0.0.1:8080` (config `listen`, `0.0.0.0`/`::` refused) | connections accepted **only** from `trusted_proxies` (closed otherwise, logged as `WARN`); pf must double this check; at most `max_connections` (256) at once, the next one is closed; headers must arrive within 20 s, otherwise the connection is dropped; **every request body** must send a byte at least every 60 s (`BODY_IDLE`), otherwise it ends in error and the write in progress is thrown away |

No TLS (terminated by the reverse proxy). No admin listener (the CLI is a local executable).

## Routes (deny by default)
Order: trusted peer → security headers → **tenant resolution** (400 invalid/multiple/contradictory header, 421 unknown host,
before any routing) → explicit route, otherwise 404; unlisted method 405.

| Group | Method | Route | Auth |
|---|---|---|---|
| (a) public | GET | `/status.php` | none |
| (a) public | GET | `/index.php/204` | none |
| (a) public | POST | `/index.php/login/v2` | none (≤ 4 pending flows per address, 429 beyond; ≤ 256 per tenant: full, the oldest pending flow makes room, a confirmed one never) |
| (a) public | POST | `/index.php/login/v2/poll` | poll token (256 bits) |
| (a) public | GET, POST | `/index.php/login/v2/flow/{token}` | token (256 bits). No web session: 303 to `/login?next=/index.php/login/v2/flow/{token}` (that target is in the login allowlist), so the password, single sign-on, the second step and the other gates happen on the login page; with a session whose gates are passed, the page shows who asks (the client's label from its User-Agent, escaped, and the address that opened the flow) with a warning against links received from someone else, and the POST requires same-site origin (`web::from_another_site`), the session's `csrf` token, and the **reproof** (`web::Reproof`: the password when the account has one, otherwise its code, otherwise a sign-in under 5 minutes — an older session is ended and sent to sign in again); wrong passwords count per IP and per account like a sign-in's. A session still behind a gate is sent to it |
| (a) public | GET | `/ocs/v{1,2}.php/cloud/capabilities` | none |
| (b) authenticated | GET | `/ocs/v{1,2}.php/cloud/user` | app password |
| (b) authenticated | POST | `/web/account/qr` (connect the mobile app) | web session + CSRF + **reproof** (as the Login Flow); creates an app password **waiting for its first use**: gone after 10 minutes if unused, kept once used, a new QR code cancels the previous one not used yet; shown once in the page (`no-store`), never again; QR content `nc://login/user:…&password:…&server:…` (property-tested) |
| (b) authenticated | GET | `/index.php/f/<fileid>` (clients' "open in the browser") | web session, otherwise to `/login?next=`; the identifier is looked up in the user's own index only, then checked on disk; redirect to the item's web page. The login's return address only accepts `/index.php/f/<digits>` (never another site: **property-tested**) |
| (b) authenticated | GET | `/index.php/core/preview?fileId=&x=&y=` (client thumbnails) | app password; `fileId` looked up in the user's own index only; `.jpg`/`.jpeg` only; thumbnail decoded on request, never stored: side capped at 1,280 px, ≤ 64 MiB read, ≤ 100 Mpx (progressive ≤ 12 Mpx) checked **before** decoding, 2 decodings at once (10 s wait, then 503); decoder and our code **fuzzed** (`fuzz/fuzz_targets/thumb.rs`) |
| (b) authenticated | OPTIONS, PROPFIND (Depth 0/1), PROPPATCH (`oc:favorite` only, all or nothing), GET, HEAD, PUT, MKCOL, MOVE, COPY, DELETE | `/remote.php/dav/files/{user}/…`, `/remote.php/webdav/…` | app password; `{user}` = the authenticated one, otherwise 404; PROPPATCH body ≤ 64 KiB, **fuzzed** (`fuzz/fuzz_targets/proppatch.rs`) |
| (b) authenticated | MKCOL, PUT, MOVE (`.file`), DELETE, PROPFIND | `/remote.php/dav/uploads/{user}/{id}/…` (upload v2) | same; `id` = `[A-Za-z0-9_.-]{1,128}`; chunks 1 to 10,000 |
| (b) authenticated | GET, POST | `/ocs/v{1,2}.php/apps/files_sharing/api/v1/shares` (client links) | app password; only public links (type 3); permissions mapped to the closest access **never above what is asked and never refused** (a refusal leaves the desktop client stuck): read+create → read and upload (folders; a file gets read only), create → drop (folders), read without create → read only; same rules as the web page (`web::share::create_link`): password ≥ 8 (argon2id, bounded), future expiry, label ≤ 100 and note ≤ 1,000 characters without control characters (shown escaped), persistent identity; listing limited to the user's own live links whose target is still in place; answer in JSON (`format=json` or `Accept`, desktop client) or XML (default, Android app), every value escaped; **fuzzed** (`http` target), **model-based test** (`nc::share_model`). PROPFIND: `oc:share-types` (the user's own live links, read only when asked) and `ocs:share-permissions` (17 file, 21 folder) |
| (b) authenticated | GET, PUT, DELETE | `/ocs/v{1,2}.php/apps/files_sharing/api/v1/shares/<id>` | app password; `<id>` = 31 bits of the link identifier (Android reads a 32-bit integer), unique among the owner's live links, looked up among them only (another user or tenant: 404); PUT changes access, password, expiry, label, note, hidden download (the address stays) |
| — | all | other `/ocs/v{1,2}.php/*` | none; 404 in OCS format, logged |
| (b) authenticated | OPTIONS, PROPFIND (Depth 0/1), MOVE (to `restore/`), DELETE | `/remote.php/dav/trashbin/{user}/{trash,restore}/…` (client trash bin) | same; item addressed by its slot (32 hex); no GET; nothing inside a deleted folder can be restored or deleted on its own |
| (b) authenticated | OPTIONS, SEARCH (`basicsearch`, RFC 5323) | `/remote.php/dav` (Favorites, Recent, Photos, client search) | same; body ≤ 64 KiB, parsed by quick-xml and **fuzzed** (`fuzz/fuzz_targets/search.rs`); scope limited to `/files/{user}`; at most 200 results, served by the index; unknown criterion → empty list |
| — | all | other `/remote.php/*` | app password, then 404 |

**Web interface and links (J3)**

| Group | Method | Route | Auth |
|---|---|---|---|
| (a) public | GET | `/`, `/login` (no password form on a tenant with `[tenant.oidc]` unless `password_login = true`; its POST is then 403); `/static/app.css`, `/static/app.js`, `/static/theme.js`, `/static/icons/{name}.svg` (closed list, compiled into the binary) | none |
| (a) public | POST | `/login` | refused (403) on a tenant that signs in through its provider, unless `password_login = true`. Otherwise: human password (bounded argon2id, 10 failures / IP / 5 min — an IPv6 address counted by its /64, `auth::ip_key` —, 10 / account / 15 min all addresses, mirrored for unknown valid-syntax names in a separate evicting table so 429 vs 401 is not an existence oracle and fake names cannot lock real accounts, except on a device that already signed in to it: the `__Host-bbknown` mark, an HMAC of the account; no tenant-wide limit); refused (403) when posted from another site (`Sec-Fetch-Site`, `Origin`: `web::from_another_site`, also on `/activate`, Login Flow and a link's password); two-step verification on: opens only a waiting session (5 min) → `/login/code` |
| (a) public | GET | `/login/oidc?next=…`, `/login/oidc/callback?code&state` | none; only when the tenant has `[tenant.oidc]` (otherwise 404). Start: a MAC'd stateless flow cookie (600 s) + 303 to the provider's authorization endpoint (`redirect_uri` built from the configured host, never the `Host` header). Start on another host of the tenant: 303 to the same route on the base host first (the `__Host-` flow cookie must live where the provider returns). Callback: inherits `/login`'s rate limit (429, refusals recorded per IP and per tenant; a missing or forged flow cookie or `state` per IP only); a failed discovery answers 503 for 30 s without a new fetch, flow cookie + `state` (constant time) + `iss` when advertised, **each flow once** (`oidc::UsedFlows`: a replayed cookie is refused before any back-channel call), code exchanged over the back channel (Casper `system.net`, allowlisted; ADR-5/ADR-6), `id_token` checks, `required_amr` when `second_factor = "provider"`, account by `(issuer, sub)`, session as the password login; refusals → 303 `/login` without detail. Design: `oidc-proposal.md`; tests: `web/tests_oidc.rs` |
| (b) waiting session | GET, POST | `/login/code` | waiting session **and** `csrf`; TOTP code (±1 step of 30 s, each step once: atomic `totp_last`) or recovery code (single use, digest); failures: 10 / IP / 5 min and **5 / account / 15 min, all IPs** (then 429 even for the right code); success replaces the waiting session with a new one; `next` limited to a client link like `/login`. A waiting session opens nothing else (303 `/login/code`, `/web/dav` → 401) |
| (a) public | GET, POST | `/s/{token}` | 128-bit token; owner account active (disabled: 404); link password by POST (attempts limited per IP and per link) |
| (a) public | GET | `/s/{token}/f/…`, `/dl[/…]`, `/zip[/…]` | token (+ password cookie); read-only; confined to the subtree; atomic download limit |
| (a) public | PUT | `/s/{token}/drop/{name}` | token; drop only; `Content-Length` required, ≤ `drop_max_file_bytes`, total ≤ `drop_max_total_bytes`, ≤ `drop_max_files` files per link (500); ≤ 4 drops at once per link and 16 in all (otherwise 503 at once); name cleaned (Windows-forbidden characters, bidirectional controls, trailing dots and spaces, device names; hidden names refused), **fuzzed**; no overwrite; no name revealed |
| (b) session | GET | `/web/files/…`, `/web/tree/…` (subfolders as an HTML fragment), `/web/search?q=&in=` (the user's space only; `q` ≤ 200 characters, ≤ 16 words, parsed by `index::Query::parse` and **fuzzed** (`fuzz/fuzz_targets/query.rs`); `in` validated by `SafePath`, ignored if invalid), `/web/favorites`, `/web/trash`, `/web/view/…`, `/web/edit/…` (text file in a form), `/web/raw/…`, `/web/zip/…`, `/web/shares` (and `?lien=` hexadecimal ≤ 64, bounded `?page=`: link history; `?nouveau=` hexadecimal ≤ 64: link just created, marked only if it is one of the user's), `/web/activity` ("Recent activity" fragment), `/web/account` | session cookie |
| (b) session | POST | `/logout`, `/web/tags`, `/web/favorite`, `/web/shares`, `/web/shares/revoke`, `/web/account/password`, `/web/account/tokens`, `/web/account/tokens/revoke`, `/web/account/language` (sets the `lang` cookie only), `/web/bulk`, `/web/trash/restore`, `/web/trash/purge`, `/web/trash/empty`, `/web/edit/…` | session **and** `csrf` field (and `confirm=1` for a permanent delete); `/web/account/tokens` (a new app password) also the **reproof** |
| (b) session | all WebDAV methods | `/web/dav/…` | session **and** `X-CSRF-Token` header |
| (b) session (tenant `required`, not set up) | GET, POST | `/web/2fa-setup` | the page the session is held on: it says to ask the administrator for an activation link; **no enrollment here** (POST → 403): the password alone never binds a phone. Opens nothing else; Login Flow → 403 |
| (a) public | GET, POST | `/activate/{token}` | token (256 bits; only its HMAC digest stored; one live link per account, a new one replaces it; 24 h; single use). Printed by `user add`, `user passwd`, `user 2fa-reset` (required tenant), with the tenant's `public_base_url` or `https://` + its first exact host. GET consumes nothing (link previews). POST: what the account lacks — a password chosen twice (`admin::weakness`) when it has none; **its current password** when it has one (failures per IP and per account); the phone's code (secret derived from the link) where the tenant requires it; checked first, then **one transaction** consumes the link and sets it all, ends every web session (`db::activate`, audited). Dead link (malformed, unknown, used, expired, replaced, other tenant, disabled account): one same 404. `no-store`, `noindex` |
| (b) session | POST | `/web/account/2fa/start`, `/web/account/2fa/confirm` (setup, refused when the tenant is `off` or already on; `/confirm` requires the **reproof** — password or recent sign-in — and ends other sessions in the same transaction), `/web/account/2fa` (`op=codes`: new recovery codes; `op=off`: refused when `required`) | session **and** `csrf`; `/web/account/2fa` also needs the password **and** a code (TOTP or recovery), same IP/account/code limits as `/login` and `/login/code` |
| (b) session (password set by the administrator) | GET, POST | `/web/welcome` | session **and** `csrf`; password received + new one twice (`admin::weakness`, failures limited per IP, argon2id bounded); success ends every session of the account. Such a session opens nothing else: every page and form → 303 `/web/welcome`, `/web/dav` → 401, Login Flow → 403; `/logout` allowed |

- **Session**: 256-bit secret in a `__Host-bbsess` cookie (`HttpOnly; Secure; SameSite=Lax; Path=/`, no `Domain`), only its
  HMAC digest is in the database, 12 h. A session does not open `/remote.php` or `/ocs`; an app password does not open `/web`.
  `insecure_cookies = true` drops `Secure` and the `__Host-` prefix: **HTTP test bench only**, warning at startup.
- **Text editing** (`/web/edit/…`, 0.7.0): body ≤ 1.5 MiB on this route only (64 KiB elsewhere), read by the handler
  **after** the session check (a raw `Body`, never buffered for a visitor); text ≤ 512 KiB, valid
  UTF-8, only onto an existing text file that passes the same rule as the page (`editable`: kind, size, UTF-8); saved by
  the internal WebDAV `PUT` (read-only, space reserve, quota, atomic write, journal), with `If-Match` on the ETag of the
  version opened (hexadecimal only, otherwise never matches: no blind overwrite) unless `force=1`; `apercu=1` renders the
  Markdown (sanitized) and saves nothing; `create=1` creates an empty file, only for a text name, by the WebDAV `PUT`
  with `If-None-Match: *` (never over a file, a folder or a symlink); `name` renames after the save, in the same folder
  only (`rename_target`: no `/` or `\`, a text name, `SafePath`; checked **before** anything is saved), by the WebDAV
  `MOVE` with `Overwrite: F`. `static/text.js` colours with text nodes only, own-key lookups, and bounded or
  total regular expressions (linear: a guest's dropped file cannot freeze the owner's page).
- **Bulk actions** (`/web/bulk`, J3b): at most 1,000 items, each a **name** in the current folder (a `/` → 404); reserved names
  refused at the root; delete to the trash; move without overwrite, destination required (no default root), never into the
  folder the selection is in; copy (destination required) and duplicate (this folder): never over anything (first free
  name, `name (2).ext` up to 99, taken by the copy itself), new identities, a folder never into itself, a copy failing
  midway sent whole to the trash (`Root::copy`, also WebDAV `COPY`); ZIP within the same limits as `/web/zip`. A large
  folder copy runs in the request (no background job): bounded by the quota, like a WebDAV `COPY`.
- **CSRF**: token derived from the session secret (HMAC), required on every POST and on `/web/dav`.
- **Pages**: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; media-src 'self';
  frame-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, `Cache-Control: no-store`,
  automatic escaping (askama). No inline script or style.
- **Served content**: `nosniff` always; `Content-Security-Policy: sandbox` except for a displayed PDF; inline display in the
  browser only for a closed list (PNG/JPEG/GIF/WebP/AVIF images, PDF, audio, video, text as `text/plain`); SVG, HTML, XML and
  everything else as an attachment. Markdown: raw HTML shown as text, non-http(s)/mailto/relative links neutralized, images not
  loaded.
- **Links**: token = HMAC(tenant key, link identifier), not stored (digest in the database); identical 404 for a nonexistent,
  expired, revoked, exhausted, other-tenant link, or a moved or deleted target; `X-Robots-Tag: noindex, nofollow`, `no-store`.
  shortcut: a moved target gives 404 (lookup by `fileid` with the J4 index).
- **Limits**: HTML lists in pages of 500 (folder read up to 10,000 entries); ZIP ≤ 4 GiB and 65,535 entries (413 beyond).

Writes: never an overwrite or a permanent delete. DELETE and any replaced destination (MOVE/COPY with `Overwrite: T`) go to
`.trash/<id>/` (original path, date, author in xattr). `If-Match`/`If-None-Match` → 412. `OC-Checksum: SHA1:…` checked
against the received content (400 otherwise, nothing is replaced). Quota: 507 as soon as announced
(`OC-Total-Length`/`Content-Length`) or on `EDQUOT`/`ENOSPC` (temporary deleted). `Destination`: same host (502 otherwise),
same root, same checks as a URL path (reserved names refused). Read-only (`read_only`) or tenant space reserve reached
(`min_free_bytes`): 503, drop links included. LOCK, UNLOCK, PROPPATCH: 405.

**Authentication**: WebDAV and OCS accept only app passwords (256 bits, HMAC-SHA-256 digest with the tenant key and the tenant
name, never stored in clear). The human password is refused there without any argon2 computation. The Login Flow form is the
only place where argon2id runs (nonexistent accounts: same cost, dummy digest).
Login page: `Content-Security-Policy: default-src 'none'; form-action 'self'; frame-ancestors 'none'`, `Cache-Control: no-store`.
Content served by GET: `application/octet-stream`, `Content-Security-Policy: sandbox`, `nosniff`.

Headers set everywhere: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Vary: Host`.
`X-Forwarded-Host` is read (the peer is necessarily a trusted proxy); if it contradicts `Host` → 400.

**End of a link**: the link list shows only those still serving. Revoked, expired or exhausted: same response as an unknown
link, including its landing page. The target is checked by its persistent identity at every opening and when the list is
displayed: **in the trash** → link suspended, resumed if it is restored to its place (J4 criterion); **renamed, moved,
permanently deleted or replaced by a same-named item** → link ended, never resurrected; **no readable identity** (restore
without xattr) → the link does not answer but is not ended. A suspended link does not reread the trash on every visit (only
"has its target come back?"); the owner's page reads it once for all their links.

**Counting a link's downloads**: the first download of a file counts and sets a signed cookie (HMAC of the tenant key: link,
file, 6 h); the rest of the same download (video ranges, resume, `bytes=0-1` probe) does not count again, even once the limit
is reached. Without that cookie, every download counts; exhausted link: no page, no archive, no browsing. **Drops**: the
announced size is reserved on the link's volume and given back if the drop does not complete (error, wrong size, guest left
mid-upload).

**Public link history** (`share_event` table): downloads, archives, drops and refused passwords, **without the guest's IP
address or headers**; grouped (same file, same drop, repeated attempts, over 10 min); kept `share_history_days` (365 by
default) and at most 20,000 per user (hourly purge of the whole tenant, independent of traffic); kept after the link is
revoked, deleted with the account. Visible only to the link's owner.

**Paths to exempt from the SSO on the proxy** (§4): `/status.php`, `/index.php/204`, `/index.php/login/v2` and
`/index.php/login/v2/poll`, `/index.php/core/preview`, `/remote.php/`, `/ocs/`, `/s/`. The `/index.php/login/v2/flow/…` page can stay behind the SSO.

**Required proxy settings**: `proxy_request_buffering off; proxy_buffering off;` (measured: `VALIDATION.md` §7);
`proxy_set_header X-Real-IP $remote_addr;` (overwrites the client's value: it is the IP used by the failure limits; without
it, every request counts against the proxy's IP).

## Files read and written
| Path | Access | Note |
|---|---|---|
| `/usr/local/etc/beastbox.toml` | read | root:beastbox 0640 |
| `<state_dir>/app.db` (+ `-wal`, `-shm`, `*.bak` before migration) | read/write | application state only |
| `<state_dir>/keys/<tenant>.key` | read, created 0600 if missing | tenant HMAC key (32 bytes) |
| `<state_dir>/keys/<tenant>.links.key` | read, created 0600 if missing | public link tokens and their password cookies (renewable alone) |
| `<data_root>/` of each tenant | read + probe xattr (`beastbox.probe`, set then removed at startup) | must be local ZFS/UFS |
| `<data_root>/<user>/.beastbox-tmp/`, `.trash/`, `.beastbox-uploads/` | created; `.beastbox-tmp` emptied at startup; uploads abandoned > 24 h deleted when a new one is created | reserved names, refused by `SafePath` |
| `<data_root>/<user>/.beastbox-manifest` | written by `beastbox manifest` (atomic, 0600); read by `rescan` (≤ 1 GiB, versioned header required, invalid line ignored, paths validated by `SafePath`, tags and `trash.*` bounded as a write bounds them, only sets xattrs on existing items, and the time of a file whose content it rereads and finds identical by SHA-1); **fuzzed** (`fuzz/fuzz_targets/manifest.rs`) | reserved name, refused by `SafePath`, hidden from listings |
| `<state_dir>/journal/<tenant>.log` | append + `fsync` before each write, replayed then emptied at startup; `flock` lock (single instance) | ETag propagation intents |
| `<data_root>/<user>/**` | read and write (regular files and folders only; links and FIFOs ignored); xattrs `beastbox.id`, `beastbox.etag`, `beastbox.cksum.sha1`, `beastbox.trash.*` | `beastbox verify`: read-only; `beastbox rescan`: sets identities and ETags |
| `beastbox restore --from DIR` (local admin CLI) | reads any folder the administrator names (snapshot, restored backup, files never seen before): no check of its origin, by decision; names filtered like any write (`SafePath`, `O_RESOLVE_BENEATH \| O_NOFOLLOW`: links never followed, not UTF-8 or refused names skipped and counted; decomposed names read as they are and written in NFC, two names of the same NFC form: one skipped and counted); writes only under the target, as server writes, never over an existing item; partial copy to the trash on failure; **fuzzed** (`fuzz/fuzz_targets/restore.rs`) | the CLI runs locally only |
| `/var/log/beastbox/beastbox.log` | write (via `daemon -o`) | no secret logged |

## Risky dependencies (parse an external format)
- `hyper` (HTTP/1, via axum) — exposed area, on the path of every request.
- `toml` — local configuration (not exposed to the network).
- `rusqlite` / embedded SQLite — parameterized queries only.
- `quick-xml` — **risk area**: PROPFIND, SEARCH and PROPPATCH bodies (≤ 64 KiB, ≤ 64 properties, no external entity or DTD
  expanded), fuzzed (`fuzz/fuzz_targets/{propfind,search,proppatch}.rs`).
- `base64ct` — `Authorization` header (≤ 1,024 characters).
- `rustls` / `rustls-webpki` — **risk area** (OIDC back channel): the TLS certificate chain of the provider, verified against
  the configured `ca_file` (read once at startup), ALPN `http/1.1` only, no redirect and no way to disable verification.
  `ring` provides the primitives.
- `serde_json` — **risk area** (OIDC): the provider's discovery document (≤ 256 KiB) and the `id_token` payload (≤ 64 KiB), both
  size-bounded **before** parsing. Fuzzed: `fuzz/fuzz_targets/oidc_url.rs` (destination grammar) and `oidc_provider.rs`
  (arbitrary bytes as a discovery document, a token response and an `id_token`).
- `jpeg-decoder` — **risk area**: decodes the user's own JPEG files for thumbnails (`platform_independent`:
  `forbid(unsafe_code)`, no dependency). Its size limit is checked after decoding: Beastbox checks the dimensions before.
  `jpeg-encoder` writes the thumbnail (`forbid(unsafe_code)` without `simd`, no dependency). EXIF orientation read by
  Beastbox (`orientation`). All fuzzed (`fuzz/fuzz_targets/thumb.rs`).

## Known limits (J1)
- Header timeout (20 s) and connection count bounded; a request body that stops arriving is cut after 60 s of silence
  (`http::BODY_IDLE`, test `stalled_upload_is_cut`). **No** limit yet on concurrent requests per user.
- Authentication failures: 10 per address per 5 min (app passwords and form), 10 per existing account per 15 min for the
  form (not on a device known to the account). Beyond that: form gets 429 **before** argon2; a **wrong** app password gets
  429, but a **valid** app password goes through (256 random bits, HMAC in microseconds: nothing to guess; a device with
  a revoked token no longer locks out the other devices on the same IP). A table of addresses full of live ones lets an
  unknown address through (the per-account, per-link and per-code limits still bound it). In memory: reset on restart.
- Pending Login Flow flows are in memory: a restart cancels them (the client starts over). At most 4 pending per address
  (429 beyond) and 256 per tenant, the oldest pending one dropped when full: no crowd of abandoned flows keeps a client out.
- The "registrable domain" wildcard is approximated by ≥ 2 labels: `*.co.uk` would be accepted (no Public Suffix List).
- Multi-tenant mode in one process: isolation relies on the code (§4.1, honest limits).

## Fixed after the first exposure (review of 2026-11-21, fixed 2026-11-22)
- **Login Flow consent**: the confirmation page names the client and the address it came from, warns, and asks the
  reproof; a phished click with a live session no longer hands out an app password.
- **Session to permanent access**: a new app password (Account page, QR code) asks the reproof.
- **Tenant-wide lockout**: failures counted per IPv6 /64 and per account (a device known to the account still opens), no
  tenant-wide limit any more; a full address table no longer refuses new addresses; a full Login Flow table drops its
  oldest pending flow; an OIDC flow signs in once.
- **Login CSRF**: a sign-in, an activation or a link's password posted from another site is refused.
- **Constant-time compares**: CSRF token and link cookies (`auth::constant_time_eq`).
- **Single sign-on account without a password**: manages its two-step verification with its code alone.

## Human security review (mandatory before any exposure, plan §11 and §12.5)

Suggested reading order, from most to least exposed:
1. **This file**: public and session routes, cookies, CSRF, CSP, files written, known limits.
2. **Public link path** — `src/web/share.rs`: `open` (token, tenant, expiry, revocation, limit, target identity, suspension
   and end), `password` (limited attempts), `rest` (confinement, counted download cookie, archive), `drop_file` (name, sizes,
   quota, no overwrite, reservation given back).
3. **Authentication** — `src/http.rs` (`require_user`: only failures are limited); `src/auth/mod.rs` (app passwords,
   sessions, `csrf_token`, `share_token`, `share_pass`, `share_download_pass`); `src/nc/mod.rs` (Login Flow, per-IP limit).
4. **Client input parsers** (all fuzzed) — `src/dav/mod.rs` (`parse_propfind`, `prop_name_ok`), `src/dav/search.rs`,
   `src/dav/write.rs` (`destination`, `parse_proppatch`), `src/dav/upload.rs` (through the `http` target only), `src/fs/manifest.rs` (`parse`),
   `src/index/mod.rs` (`Query::parse`, `fold`), `src/web/render.rs` (`marks`, `period_start`) and `src/nc/thumb.rs`
   (`make`, `orientation`).
5. **Writes** — `src/fs/write.rs` (atomic writer, trash, ETag journal), `src/dav/write.rs`, `src/fs/trash.rs`.
6. **Web interface** — `src/web/mod.rs` (`session`, `need_form`, `login`, `web_dav_at`, `raw`, `edit_save`, `editable`); `static/text.js` (`RULES`); `src/web/render.rs`
   (`markdown` and `safe_url`, `kind` and `inline_mime` as a closed list); `templates/`: no unescaped output except
   `{{ h|safe }}` (sanitized Markdown) in `view.html`.
7. **Isolation** — every SQL query filters by `tenant_id` (test `db::every_query_filters_by_tenant`); no global state
   (`global_state_audit`).
