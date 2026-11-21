# Beastbox: a file server in Rust, compatible with Nextcloud clients, for FreeBSD

## 0. Priorities (they override any other choice in case of conflict)

### 0.1 Order of priorities
1. **Data integrity and durability**: never lose or corrupt a file.
2. **Security**: a minimal attack surface, known and under control.
3. **Performance and memory footprint**: speed and RAM use are design constraints, with budgets that are numbered and
   measured, not end-of-project optimizations.
4. Features: last. When in doubt, **do not add** the feature.

Security, performance and memory are **blocking criteria**: a feature, a dependency or an implementation choice that degrades
one of them beyond the budgets of §0.3 and §0.4 is refused or postponed, even if it brings a feature.

### 0.2 Data safety
- **Atomic write**: everything is written to a temporary file located in a **hidden folder dedicated to it at the root of the
  user's dataset** (`.beastbox-tmp/`, same filesystem, hence an atomic `rename`), **the old file's xattrs are copied to the
  temporary** (identifier, tags, favorites; checksums are recomputed, §6), `fsync` of the file, `rename` onto the target,
  then `fsync` of the parent folder. This folder, like `.trash/`, is **excluded** from WebDAV listings, search, ETag
  computation and shares. Never an in-place write on an existing file. A crash at any instant leaves either the old version or
  the new one, never a mixed state.
- **No silent loss**: every delete goes through the **user's trash** (§6); an ETag conflict (`If-Match`) refuses the write
  instead of overwriting. No permanent `DELETE` without a trash step (separate purge, logged).
- **Integrity check**: checksum computed at write time (xattr, §6) and checked on demand; a file whose checksum no longer
  matches is reported in the logs and flagged, never silently fixed. Rely on the ZFS `scrub` for disk corruption.
- **ZFS snapshots: the administrator's job, on the host.** The application neither creates, destroys nor restores any
  snapshot and never calls `zfs`. The administrator schedules snapshots (frequency, retention, off-machine copy) and takes one
  before any heavy operation. The application's destructive bulk operations (emptying a tenant's trash, deleting an account)
  require explicit confirmation (`--yes`) and the CLI reminds you to take a snapshot; before a schema migration, the SQLite
  database is copied (`VACUUM INTO`). `../admin/backup.md` documents the restore on the administrator side (`zfs rollback` or
  recovery from `.zfs/snapshot`), **followed by a `beastbox rescan`** (§6).
- **File-based backup (restic): xattrs are part of the data.** Identity (`fileid`), folder ETag, sums, tags, favorites and
  trash metadata live in xattrs (§6): a backup or restore that loses them makes every file look new to the clients (full
  resync, shares and tags lost). `zfs send` keeps them (`xattr=sa`); for **restic on FreeBSD**, one must **check with a real
  restore** that extended attributes of the `user` namespace are backed up and restored (restic version and required options
  to record in `../admin/backup.md`). If restic does not keep them: document it, do not use it as the main backup, or accept a
  `rescan` (new identities).
- **Startup and shutdown**: at startup, cleanup of the `.beastbox-tmp/` folder and of abandoned uploads (without touching user
  files), **replay of the ETag intent journal** (§6); on shutdown (SIGTERM), finish or cleanly cancel the writes in progress,
  flush the logs, close SQLite.
- **Quota and full disk**: check space **before** writing (read with `fstatfs` on the descriptor of the user's dataset, which
  must reflect their ZFS quota: to check at J1); on `ENOSPC`, cancel cleanly (delete the temporary) and answer 507. Provide a
  reserve threshold: below it, the server switches to **read-only** instead of failing at random.
- **Read-only mode** that can be switched on (config or signal) for maintenance and incidents.
- **SQLite**: never the source of truth for files (§5); backed up separately; losing the database loses no file data.
- **Tests**: hard kill (`kill -9`) during a PUT, a MOVE, a chunked upload and an ETag propagation, then restart: no corrupted
  file, no orphan temporary after cleanup, consistent ETags.

### 0.3 Minimal, controlled attack surface
- **Deny by default**: explicit table of allowed routes and methods; everything else returns 404/405. No debug route, no
  directory listing by the HTTP server, no static files outside the list.
- **Separation of surfaces**: three groups of routes with distinct rules, documented:
  (a) **public** (`/s/<token>`, `status.php`, login flow): the most restricted, strict rate limits;
  (b) **authenticated** (WebDAV, web, OCS);
  (c) **administration**: **not exposed over HTTP** at first; local CLI through a Unix socket or an executable, 0600
  permissions. Any administration interface or API (J7) is optional, disabled by default, on a separate loopback listener.
- **Listening**: **configurable** address (loopback by default; in practice the jail's address, for example `10.0.0.x`,
  when the reverse proxy is in another jail), never `0.0.0.0` by default. The application **only accepts connections from the
  `trusted_proxies` addresses** (application-level check) and pf restricts the port to these addresses. It does not handle
  TLS: the **load balancer or reverse proxy** (nginx, HAProxy, Caddy or other) terminates HTTPS and SNI and is the single entry
  point.
- **No risky content processing**: no thumbnail, no image/video/PDF/archive decoding on the server, no SVG rendering, no
  execution of an external command from a request (`std::process` forbidden except documented local supervision), no
  `unsafe` outside `fs/` (§9). Previews are delegated to the browser, with CSP and `nosniff`.
- **Dependencies**: justification, audit and cap (**≤ 85 transitive production crates**, decided on 2026-11-15: raised from
  60 in light of the J2 audit; any overrun requires a written decision in `DEPS.md`); a commented `cargo tree` in `DEPS.md`.
  Any crate that parses an external format (XML, Markdown, ZIP) is identified as a **risk area**, fuzzed and isolated.
- **Least privilege**: process under a dedicated unprivileged user, in a jail; never root; Capsicum (`cap_enter()`,
  `cap_rights_limit()` per descriptor: read-only on what is not written) delivered at J5, but **designed from J0** so as not to
  cost a rewrite. Jail filesystems `noexec` where possible for the data.
- **No ZFS operation by the application**: datasets (tenant, user), quotas and snapshots are created and managed **by the
  administrator on the host**. The daemon **never runs as root** and needs no privileged helper process. `beastbox user add`
  checks that the user's dataset exists and is mounted, without calling `zfs`. Available space is read with `fstatfs` (§0.2).
- **Bounded resources**: `rctl` or jail limits (memory, number of descriptors, processes), internal limits (connections,
  concurrent requests per user, body size, number of entries).
- **Fail closed**: if a security check fails or cannot be done (unknown tenant, unreadable token, database unavailable), the
  request is refused.
- **Security observability**: audit log (logins, failures, shares created/revoked, access through links, tenant refusals),
  authentication error metrics; metrics endpoint **never behind the public proxy** (loopback, or the jail's address restricted
  by pf, see J7).
- **Surface inventory**: a `SURFACE.md` file kept up to date at every milestone: ports, sockets, routes (by group), risky
  dependencies, file paths read and written, process privileges. A security review starts with this file.

### 0.4 Performance and memory (budgets to measure, not to assume)
Initial budgets, to confirm or adjust after the first measurements on the real hardware:
- p95 latency: PROPFIND of a folder of 1,000 entries < 50 ms (warm cache); PUT/GET of small files < 20 ms excluding network;
  search < 100 ms over 100,000 files.
- Throughput: a large file saturates the local network (sendfile, no copy in memory).
- **Bounded memory (priority)**:
  - Initial budgets to confirm by measurement, for a **reference set of 100,000 files**: resident memory (RSS) **at rest
    < 50 MB**, **under load** (20 parallel transfers, search in progress) **< 150 MB**, search index included.
  - The 1 million file target (§0.5) has its **own index budget**, to measure at J4: a path costs about a hundred bytes once
    the structures are counted, so the index must be **compact** (names stored per folder and not as full paths) and **evicted
    per tenant** when inactive. If the budget does not hold, reduce the target rather than exceed the RAM.
  - No file loaded entirely into memory; uploads and downloads streamed with back-pressure; fixed-size buffers per connection
    (around 64 KB, to adjust).
  - **No unbounded structure**: no `Vec`, `HashMap`, cache or channel that grows without limit; every queue, cache and index
    has a configured maximum size and an eviction policy. Large responses (PROPFIND, listings, ZIP) are produced as streams,
    never built entirely in memory.
  - Number of threads of the tokio runtime and the blocking pool **fixed and small** (around 2 to 4 workers, to adjust), not
    the default.
  - Dependencies judged on their memory footprint too (no crate that loads large tables or embedded runtimes).
  - Measurement: RSS and max RSS recorded at every milestone (`/usr/bin/time -l`, `procstat`, and a load test), recorded in
    `VALIDATION.md` (§7); a budget overrun blocks the milestone like a performance regression.
  - Abuse test: many slow clients or giant requests do **not** grow memory beyond the limit (rejection or back-pressure, never
    accumulation).
- **Nothing blocking on the async executor**: disk, SQLite and xattr go through `spawn_blocking` or a dedicated, sized pool.
- **Limited concurrency**: maximum number of requests in flight and upload chunks per user, bounded queues.
- **Bounded authentication**: checking an app password, done on **every request** from Nextcloud clients, must cost on the
  order of a microsecond to a millisecond and allocate no notable memory (§2). **argon2id** hashes (human passwords: web
  login, password-protected links) are slow and memory-hungry by design: their **concurrency is bounded** (semaphore, around 2
  at once) and their parameters are chosen so that `concurrency × memory of one hash` stays within the RSS budget (around
  19 MB per hash, t=2, p=1; to confirm against the OWASP recommendations of the day). Beyond that: a short queue, then `503`.
- The cost of reading the identity xattr per entry (§6) is included in the PROPFIND latency budget.
- Release build: `lto = "fat"`, `codegen-units = 1`, `opt-level = 3`, symbols stripped; static binary.
- **Measurement**: reproducible benches (`criterion` for functions, `oha` or `wrk` for HTTP), results recorded in
  `VALIDATION.md` (§7) at every milestone; a **regression of more than 15 %** on a budget blocks the milestone.
- **No disk watching**: neither kqueue nor periodic rescan (write contract, §6). No descriptor per folder, no background tree
  walk: the CPU and I/O cost at rest is **zero** (except the trash purge, bounded to `.trash/`). Tree walks only happen on
  demand (`beastbox rescan`, `beastbox verify`, index build) and are **rate-limited** (configurable I/O budget).
- Recommended ZFS settings, documented in the README: `xattr=sa`, `compression=lz4` or `zstd`, `atime=off`, `recordsize`
  suited to the content.

### 0.5 Scalability (as far as possible, without sacrificing §0.1 to §0.4)
**Principle**: scale **vertically** first on a single server, and plan for a **simple horizontal** scale-out **by splitting
tenants** (sharding), with no cluster and no shared state. No distribution complexity is shipped before a measured need
demands it.

- **Sizing targets per instance** (starting values to confirm by measurement): 10 tenants, 100 users, 1 million files in
  total, 200 concurrent connections, while staying within the performance and memory budgets of §0.4.
- **Vertical**:
  - everything costly is **per tenant** and loaded on demand: search index, ETag caches, root descriptors; an inactive tenant
    is unloaded (eviction), memory does not grow with the number of declared tenants;
  - limits **per tenant and per user** (rate, connections, concurrent requests, quota) so that one user or tenant cannot
    starve the others (fairness);
  - no global lock on the request path: shared state kept to a minimum (limit tables, sessions), structures segmented by
    tenant; SQLite on a pool or a dedicated thread, short writes;
  - end-to-end **back-pressure**: under overload, the server refuses cleanly (`503` with `Retry-After`) instead of collapsing.
- **Horizontal by tenant**: a tenant = one or more host names = a ZFS dataset with its own data root (§4). Tenants can
  therefore be spread over **several independent instances** (another jail or another machine), the reverse proxy routing
  **by domain** (SNI/Host) to the right instance.
  - Each instance has its own data, its own SQLite database and its own index: **no state shared between instances**.
  - **Forbidden**: two instances writing the same data (consistency of the ETag and of the in-memory index not guaranteed,
    SQLite not shareable); no network storage (NFS ruled out, §2).
  - Migration tool: `beastbox tenant export|import` (data, accounts, shares, tokens) to move a tenant from one instance to
    another; database schema **keyed by tenant** from J0 so that export stays simple.
  - Availability: no active/active high availability; backup and recovery (ZFS snapshots, `zfs send` to another machine) are
    the administrator's job.
- **Observability to decide when to scale**: metrics (loopback, §0.3) per tenant: requests, p50/p95/p99 latencies, RSS, open
  descriptors, index size, 503 rejections; alert thresholds documented in `VALIDATION.md` (§7).
- **Out of scope**: orchestration, consensus, external message queue, distributed cache, distributed database.

## 1. Goal
A minimal personal file storage server, in **Rust**, whose **source of truth is the filesystem** (ZFS on FreeBSD 15).
Multi-user and multi-domain in a single binary. It must work with **the Nextcloud mobile app and the Nextcloud desktop
client** (WebDAV + Nextcloud/OCS endpoints) and offer a minimal web interface: drag and drop, search, tags, sharing through
external links. Calendar and contacts (CalDAV/CardDAV): **out of scope**, served by Radicale on its own, beside Beastbox
(appendix §14).

Out of scope: automatic photo backup, collaborative editing, end-to-end encryption, third-party Nextcloud apps.

## 2. Technical constraints
- Platform: **FreeBSD** (not Linux): `sendfile(2)`, `extattr`, Capsicum, no systemd or `/proc`. The server **does not watch
  the disk** (neither kqueue nor inotify): see the write contract in §6.
- Stable Rust, `tokio`, `axum`/`hyper`. WebDAV: start from the `dav-server` crate *only if* it allows custom ETags and `oc:`
  properties; otherwise implement PROPFIND/PUT/MOVE/COPY/DELETE by hand (XML via `quick-xml`).
- **File data = filesystem.** File-related metadata (folder ETag, checksums, favorites, tags) in **xattrs** (`extattr`, user
  namespace). No file index in the database.
- **Storage: local ZFS dataset required.** Neither NFS nor iSCSI. NFSv3 has no xattrs (a neighboring project, OpenCloud,
  crash-loops on it); NFSv4.2 has them but turned out about 10 times slower; iSCSI+UFS froze the jail during an outage of the
  storage server. On a network mount, moreover, neither atomicity (`rename`, `fsync`) nor the reliability of identity xattrs
  (`fileid`, §6) is guaranteed the way it is on local ZFS. **At startup, Beastbox checks** that every data root is on a local
  filesystem that accepts xattrs (write, read, delete of a test attribute); otherwise it **refuses to start** with an explicit
  message (fail closed, §0.3). To expose files located elsewhere (e.g. on the NAS), **copy** them into a local dataset rather
  than mounting them.
- **SQLite allowed only for application state** (§5), never to describe files.
- Frontend: server-rendered HTML (`askama`) + htmx + minimal native JS; no JS build. A **small framework** is only allowed
  under the rule of §8 (decision of 2026-11-15: htmx + native JS first, Preact conceivable).
- Deployment: FreeBSD jail, static binary, `rc.d` script supervised by `daemon -r`, behind **any load balancer or reverse
  proxy** (nginx, HAProxy, Caddy…) that handles **HTTPS and SNI**. The app speaks plain HTTP, listens on a configurable
  address and is never exposed directly to the Internet (§0.3).
- Authentication: two kinds of credentials, with **separate** uses (Nextcloud clients do not handle a redirect-based SSO):
  - **App passwords**: 256-bit random tokens generated by the server, shown only once (for example via the Login Flow). They
    are the **only ones accepted by WebDAV and OCS** (the clients' Basic header, sent on **every request**). Stored as an
    **HMAC-SHA-256 digest with the tenant key**, and **not with argon2**: the token already has high entropy, and argon2 would
    cost tens of ms and tens of MB on every request. Constant-time check, with failures limited per tenant and per IP.
  - **Human password** (argon2id): reserved for **logging into the web interface** and confirming the Login Flow. WebDAV and
    OCS **refuse** it (401 with a message inviting the user to create an app password), so that a misconfigured client does
    not trigger argon2 on every request.
  - Web interface: its own session (cookie, §8) or a `Remote-User` header set by the proxy (SSO), accepted only from a trusted
    proxy.
  - **Two-step verification** (TOTP, RFC 6238), per tenant `off` / `optional` / `required`: after the human password (web
    login and Login Flow). The secret is sealed with the tenant key, recovery codes are stored as digests; each code works
    once. App passwords are not concerned (one random token per device, revocable).
  - **Account gates**, in this order: second step, password set by the administrator (`must_change`), setup required by the
    tenant. A session behind a gate opens only that page and `/logout`; the Login Flow refuses until the gates are passed.

## 3. Architecture
- `main.rs`: config, startup, logging.
- `fs/`: file layer (openat, atomic write, stat, xattr, sendfile, quota). **The only module that touches the disk.**
- `dav/`: WebDAV and chunked upload.
- `nc/`: Nextcloud endpoints (status, login flow, OCS, capabilities).
- `web/`: HTML pages, public shares.
- `auth/`: tokens, sessions, share tokens.
- `etag/`: computing and propagating ETags.
- `index/`: in-memory index (names, tags) kept up to date by the server's writes.
- `db/`: SQLite (migrations, access).
- `tenant/`: tenant resolution.
- `admin/`: **a single administration service layer** (accounts, tenants, quotas, shares, `verify`, `rescan`, export/import).
  The CLI is its only client at first; an HTTP administration API can plug into it later (J7) **without duplicating the
  logic**.
- `cli`: local administration, a thin adapter over `admin/` (`beastbox user add|del|passwd|list --tenant X`,
  `beastbox verify`, `beastbox rescan`, `beastbox manifest`, `beastbox restore`, `beastbox tenant export|import`).
- `metrics/`: counters and histograms **collected from J0** (requests, latencies, authentication errors, RSS, descriptors,
  503 rejections, per tenant); exposing them through an API is postponed to J7.

## 4. Multi-user and multi-domain
- **Tenant = one or more host names** (e.g. `files.alpha.example`, or the pattern `*.alpha.example`). A tenant has its users, quotas,
  shares, options and **its own configurable data root**. `alice` @ alpha.example and `alice` @ beta.example are two unrelated
  accounts. Example configuration (the data root is a tenant parameter, not an imposed convention):
  ```toml
  [[tenant]]
  name      = "alpha"
  hosts     = ["files.alpha.example", "*.alpha.example"]
  data_root = "/mnt/data/beastbox-alpha"

  [[tenant]]
  name      = "beta"
  hosts     = ["*.beta.example"]
  data_root = "/mnt/data/beastbox-beta"
  ```
  Resolution rules: **exact** match first, then the most specific wildcard pattern; a host name belongs to **a single
  tenant**, any ambiguity (two tenants claiming the same name) **prevents startup**. The data roots of two tenants must
  **neither overlap nor nest** (checked at startup) and each one passes the storage check of §2. Should multi-domain in a
  single process turn out too complex, the planned fallback is **one instance per domain** (§0.5), with the same configuration
  reduced to a single tenant; the code must therefore assume nothing about the number of tenants.
- The tenant is determined by the request's domain. The proxy forwards `Host` (or `X-Forwarded-Host`) and
  `X-Forwarded-Proto`; the app only accepts these headers from an IP listed in `trusted_proxies`. Unknown domain: `421` or
  `404`, revealing nothing about the other tenants.
- Every generated URL (Login Flow v2, share links, `Location`, WebDAV XML) uses the domain **of the request**.
- Storage: `<tenant data_root>/<user>/`; on ZFS **one dataset per tenant (mounted on its `data_root`) and one child dataset
  per user**, with a ZFS quota per user (that is what makes quotas exact without walking the tree; a single dataset per tenant
  would require application-level accounting). A `MOVE` between users is refused; `rename`s stay within one dataset. Datasets,
  their quotas and snapshots are created and managed **by the administrator on the host** (§0.2, §0.3); the application never
  runs `zfs`. Root folder descriptors are opened at startup; **every disk access is an `openat` relative to the user's
  descriptor**, so a request from one tenant physically cannot touch another.
- Tokens, sessions, share links and HMAC keys are **per tenant**; a token from one tenant is refused on another.
- Rate limiting of login failures per tenant and per IP.
- Proxy: `proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme;`, `client_max_body_size 0`,
  `proxy_request_buffering off`. Per-domain certificates managed by the proxy.
- **SSO in front of the application** (e.g. Authelia): the paths used by machine clients must be **exempted from the SSO** on
  the proxy (`/status.php`, `/index.php/login/v2` and its poll, `/remote.php/`, `/ocs/`, `/s/`), because they authenticate
  themselves (app token, share token). The rest (web interface, Login Flow confirmation page) stays protected. The list is
  kept in `SURFACE.md`.

### 4.1 Tenant isolation: soundness requirements
Goal: a leak between tenants must be **structurally impossible**, not just "tested absent". Mechanisms, from strongest to
weakest:

**Through the code structure (the compiler forbids the mistake)**
- `TenantCtx` can be constructed **only** by the `tenant/` module (private constructor), after resolving and validating the
  host name. `UserCtx` can only be constructed from a `TenantCtx` **and** a successful authentication in that tenant.
- Every function that touches files, the database, the index or caches takes `&TenantCtx` or `&UserCtx` as a parameter. No
  API takes a tenant name or a path as a `String`. The root handle (`UserRoot`, an owned descriptor) can only be obtained from
  a `UserCtx`.
- **No shared global state** (`static`, `lazy_static`, `OnceCell`) holding tenant data. State lives in a
  `Tenant { index, caches, limits, root }` structure obtained **only** through the registry, never in a single table keyed by
  a string. Checked by review and by a CI rule that fails if global state is added outside an allow list.

**Through the database**
- Every table carries `tenant_id` in its **primary key**, and foreign keys are **composite** (`tenant_id`, `id`): a row of one
  tenant cannot reference a row of another (e.g. a share whose user belongs to another tenant is rejected by the database).
- All SQL lives in `db/`, behind functions that require a `TenantCtx`; no query without a tenant filter (automated test that
  walks the prepared statements and fails if one does not contain `tenant_id`).

**Through the filesystem**
- Each root is a **descriptor opened at startup**; every access is an `openat` with **`O_RESOLVE_BENEATH`** (FreeBSD 13 and
  later: the kernel forbids leaving the root through `..` or a symlink) and `O_NOFOLLOW` on the last component. To check on
  FreeBSD 15.1 that the behavior matches the need, including at mount points.
- Roots on **distinct datasets**: no hard link possible between tenants.

**Through authentication and the browser**
- A token, session or share token is **cryptographically bound to the tenant** (the tenant is part of the signed or hashed
  data); it is only evaluated within the tenant resolved from the request's host name.
- Cookies **without a `Domain` attribute** (cookie bound to the exact host) and the `__Host-` prefix: never shared between
  subdomains or tenants.
- No open CORS; `Vary: Host` on every cacheable response; no response caching shared between tenants in the application.

**Through host name validation**
- Normalization before any comparison: lowercase, port and trailing dot removed, IDNA conversion, rejection of forbidden
  characters, userinfo and multiple or contradictory values (`Host` vs `X-Forwarded-Host`).
- `X-Forwarded-Host` is only read from a trusted proxy (§4). Otherwise `Host` is authoritative.
- Wildcard patterns must contain **at least one registrable domain** (`*.alpha.example` accepted, `*.fr` or `*` refused at
  startup).

**Honest limits**
- In **one process for several tenants** mode, isolation relies on the code and on Capsicum, not on the Unix user: a code
  execution bug in the process would expose every tenant. In **one instance per tenant** mode, a distinct Unix account and
  confinement per tenant add an operating system barrier. That is why the recommended default deployment is one instance per
  tenant (§0.5).
- Noisy neighbor: quotas, rate and connection limits **per tenant** (§0.5).

**Logging and errors**: every log line and every audit event carries the tenant; an error message never exposes the name,
existence or contents of another tenant.

## 5. SQLite: what goes in, what does not
A single database `/var/db/beastbox/app.db`. Deleting it must never corrupt or lose a user file.
- **In**: tenants (domains, aliases, default quota, options); users (argon2id hash of the human password, quota, role,
  active); app tokens and sessions (HMAC-SHA-256 digests with the tenant key, expiry, last use); share links (id, tenant,
  user, `fileid` + indicative path, rights, password hash, expiry, download limit, access counter, last access, revoked);
  minimal audit log with purge; rate-limiting counters.
- **Out**: ETags, checksums, favorites, tags (xattr); HMAC keys (0600 files in `/var/db/beastbox/`); any file index.
- Implementation: `rusqlite` (`bundled` feature); access via `spawn_blocking` or a dedicated thread, never on the async
  executor; `PRAGMA journal_mode=WAL; foreign_keys=ON; busy_timeout=5000;`; numbered SQL migrations (`PRAGMA user_version`)
  applied at startup; parameterized queries only; backup with `VACUUM INTO` or a ZFS snapshot of the folder.

## 6. Data rules
- **A file's identity (`fileid`)**: a **persistent random 128-bit identifier** stored in an xattr (`user.beastbox.id`),
  assigned **at creation by the server** (never on read). A file that arrived outside the application has no identifier until
  a `rescan` has run; meanwhile it uses the degraded fallback below.
  - It is **copied over on every atomic replacement** (§0.2): otherwise, the `rename` of a temporary file would give a new
    inode, hence a new identity, on every save, and would lose tags, favorites and shares. A `MOVE` or a rename within the same
    dataset keeps the identifier (the xattr follows the file).
  - **An inode number alone is ruled out**: it is reused after deletion and changes on replacement. Same for `st_dev`, which
    can change after a remount or a restore.
  - The integer `fileid` exposed to Nextcloud clients (at most 53 bits, safe for JSON and JavaScript) is derived from this
    identifier by a truncated hash, with **collision detection** at assignment (reassignment on conflict).
  - **Degraded fallback**: if writing the xattr is impossible (read-only file, non-compliant filesystem), the identity is (ZFS
    dataset identifier, inode), reported in the logs as unstable across replacement.
  - An **external copy** of a file (`cp`, `rsync` without `-X`) creates a new identity. If a copy preserves xattrs and
    duplicates the identifier, **duplicate detection** (same identifier on two paths, at indexing and on `rescan`) reassigns
    the second one.
  - To check at J1: the cost of reading one xattr per entry on a PROPFIND of 1,000 entries (with `xattr=sa`), measured in
    `VALIDATION.md` (§7).
- **Owner and permissions**: data owned by the daemon's system user, folders `0700` and files `0600` (no write access for the
  group or others), so that nobody changes files by mistake outside the application (write contract below). Reading by `root`
  (backups, `zfs send`) stays possible.
- **File ETag** (since 0.2.0) = hash of `(identity, mtime_ns, size, SHA-1 recorded at write time)`; fallback to
  `(mtime_ns, size, inode)` for a file without an identity (before `rescan`). Nothing tied to the physical location: a restore
  (restic, a copy that keeps xattrs) or a migration keeps the ETags, and clients only re-download what changed (before 0.2.0,
  the inode was part of it: a restore re-downloaded everything, 3.3 GB measured on the bench). The SHA-1 distinguishes two
  writes of the same size and the same `X-OC-Mtime`. Changing this formula changes every ETag (full resync of every client):
  reference values frozen in `etag::tests`.
- **Folder ETag**: stored in an xattr. On every write done by the server (PUT, MKCOL, MOVE, COPY, DELETE), the new ETag is
  propagated from the parent up to the root (cost = depth). The desktop client assumes, to confirm by observation (§7), that a
  change at any depth changes the ETag of every ancestor.
- **Propagation safety (crashes, shutdowns)**:
  - A folder ETag is a **random 128-bit value renewed on every change** (never computed from the content, hence never
    reused).
  - Before every write that modifies the tree, the server appends an **intent** (tenant, parent folder) to an **append-only
    journal** (a file in `/var/db/beastbox/<tenant>/`, with a **batched** `fsync` so as not to pay one `fsync` per request),
    performs the operation, propagates the ETags, then marks the intent done. At startup, unfinished intents are **replayed**:
    propagation is idempotent (renew the ETag of the whole chain of ancestors). The journal is transient state, not a file
    index (compatible with §5).
- **Write contract: files are only modified by the application.** Every add, change or delete goes through the server:
  WebDAV, the web interface, or **import by `rclone` over the WebDAV API**. The server **does not watch the disk**: neither
  kqueue nor periodic rescan. Consequences: ETags, identities and index are kept up to date **at the time of each write** by
  the server; the CPU and I/O cost at rest is zero; no descriptor is consumed per folder.
- **Changes outside the application** (SSH, direct `rsync`, backup restore, `zfs rollback`, `zfs recv`, `tenant import`): not
  detected automatically. Two local CLI commands, run by the administrator:
  - `beastbox verify --tenant T [--user U] [--path P]`: **read-only**. Reports deviations from the contract: files **without
    an identifier** (added outside the application), files whose **mtime or size no longer match** those recorded with their
    checksum (changed outside the application), duplicate identifiers.
  - `beastbox rescan --tenant T [--user U] [--path P]`: **reconciles**. Assigns missing identities, renews the ETags of the
    whole subtree concerned and of its ancestors (clients resync), recomputes checksums and index. Usable online, with I/O
    throttling; to run **after any restore or migration**.
  - Until a `rescan` has run, Nextcloud clients do not see changes made outside the application in the folder ETags. A file's
    ETag, on the other hand, is recomputed on every PROPFIND.
- Checksums: in an xattr with the mtime, recomputed only if the mtime changed.
- Tags and favorites: xattr on the file. They follow a move and a **replacement** done by the server (copied during the atomic
  write, §0.2) but are lost by an external copy that ignores xattrs (e.g. `rsync` without `-X`): to document.
- Shares: in the database, referencing the `fileid` (the persistent identifier of §6; the indicative path serves as a fallback
  if the identifier is lost, for example after an external copy).
- **Trash (per user, managed by the application)**: a `.trash/` folder at the root of the user's dataset (same filesystem: a
  delete is an atomic `rename`, fast and without copying).
  - `DELETE` moves the item into `.trash/<deletion-identifier>/` keeping its structure, with the **original path**, the
    **deletion date** and the author in xattrs. The file identifier is kept: tags and favorites come back on restore.
  - **Restore** by the user (web interface) to the original path, or to a suffixed name if the spot is taken. **Emptying the
    trash** is a separate action, confirmed and logged.
  - **Retention** configurable per tenant (default to confirm: 30 days). An internal task purges expired items by walking
    only `.trash/`, never the rest of the tree.
  - The trash contents **count against the user's quota**. If a write fails for quota (507), the interface offers to empty
    the trash; automatic purge under quota pressure is a per-tenant option, disabled by default.
  - `.trash/` and `.beastbox-tmp/` are **reserved names**: invisible in listings, refused on creation, rename and move over
    WebDAV. A share link to a deleted item returns 404 while it is in the trash.
  - Overwrite: a `PUT` on an existing file is protected by `If-Match` (no lost update). Per-tenant option
    `keep_previous_version` (default to confirm): the old version is kept in `.trash/` through a hard link before the `rename`.
  - **Trash visible and restorable by Nextcloud clients** (J4): endpoint `/remote.php/dav/trashbin/<user>/trash/` (PROPFIND:
    deleted items with name, original path, deletion date and size, from the `.trash/` xattrs; `MOVE` to
    `/remote.php/dav/trashbin/<user>/restore/<item>` to restore; `DELETE` to delete permanently, logged). Exact properties and
    paths to **observe on a real client** (desktop and Android) against a reference Nextcloud before implementing (§7). The
    matching capability is only announced once the endpoint is implemented.
- **Quota**: ZFS properties of the user's dataset, never `du`. Use `referenced` or `usedbydataset` (not `used`, which includes
  snapshots and would skew the quota).

## 7. Nextcloud endpoints to emulate (checked in the docs, to confirm by observation)

**Main rule (first task of J1)**: before implementing, **record every request** (method, path, headers, body, responses) of
the Nextcloud desktop client and mobile app against a real Nextcloud server, and use it as the specification. This list is a
starting point, not the reference. The documentation consulted corresponds to Nextcloud 35.

**`GET /status.php`** (JSON, unauthenticated)
- Expected fields: `installed` (true), `maintenance` (false), `needsDbUpgrade` (false), `version` (e.g. `35.0.0.0`),
  `versionstring` (e.g. `35.0.0`), `edition` (empty string), `productname` (`Nextcloud`), `extendedSupport` (false).
- Maintenance mode: **503** response with the `x-nextcloud-maintenance-mode: 1` header.
- To check: the minimum version accepted without a warning by current clients, and whether clients require all these fields.

**Login Flow v2**
- `POST /index.php/login/v2` (anonymous) → JSON with the **poll token**, the **poll URL** and the **login URL**. The server
  picks the poll path (the docs give `/login/v2/poll` as an example: compare with what the client calls).
- The client opens the login URL in the browser; the user authenticates on the app's web page and confirms.
- The client `POST`s the token to the poll URL, about once per second, for up to **20 minutes**. Response **404** as long as
  the user has not confirmed; then **200** with `{server, loginName, appPassword}`. The poll token is single-use and expires
  (20 min); the `appPassword` is an app password bound to the tenant and the user.
- Every returned URL uses the request's domain (§4).

**OCS**
- `GET /ocs/v1.php/cloud/capabilities` and `/ocs/v2.php/cloud/user` (not checked: observe the client).
- Capabilities to announce at a minimum: a `dav` block with `chunking` (`1.0`) and a `checksums` block (`supportedTypes` and
  `preferredUpdateType`: `SHA1` in the documented example). Declare **only** what is really implemented.
- OCS responses in the format the clients expect (`ocs.meta` / `ocs.data` envelope); `?format=json` handled.

**File WebDAV**: `/remote.php/dav/files/<user>/…`
- Methods: PROPFIND, GET (with `Range`), PUT, MKCOL, MOVE, COPY, DELETE, OPTIONS.
- Authentication: **app passwords only** (Basic); the human password is refused by WebDAV and OCS (§2).
- Properties requested by clients: `d:getetag`, `d:getlastmodified`, `d:getcontentlength`, `d:getcontenttype`,
  `d:resourcetype`, `oc:fileid`, `oc:permissions`, `oc:size`, `oc:checksums`.
- To check: whether the client also expects `oc:id` (identifier namespaced by the instance) in addition to `oc:fileid`.
- ETag: the client compares each item's ETag with the one in its local database. **Propagation of a folder's ETag to all its
  ancestors is not confirmed by the docs consulted: validate it first at J1 with the real client.**
- Checksums: `OC-Checksum` header accepted on PUT (algorithm announced in the capabilities); stored in xattr (§6).
- Insufficient quota: **507 Insufficient Storage**.

**Chunked upload v2**: `/remote.php/dav/uploads/<user>/…` (v1 and `OC-Chunked` are obsolete: do not implement)
1. `MKCOL /remote.php/dav/uploads/<user>/<unique-id>` with the **`Destination`** header (final path of the file).
2. `PUT /remote.php/dav/uploads/<user>/<unique-id>/<n>` with `n` between **1 and 10000**, chunks of **5 MB to 5 GB** (the
   last one can be smaller), headers `Destination` and **`OC-Total-Length`** (total size of the file). If the quota is
   insufficient: **507** as soon as the chunk is received.
3. `MOVE /remote.php/dav/uploads/<user>/<unique-id>/.file` to the destination, with `Destination`, `OC-Total-Length` and
   optionally **`X-OC-Mtime`** (Unix modification time; otherwise the time of assembly).
4. After the MOVE, the chunks and the upload folder are deleted. Abandoned upload folders expire (periodic cleanup,
   configurable duration). Without `OC-Total-Length`, the failure only shows at the MOVE.
- Atomic assembly (§0.2): write to a temporary file in the same dataset then `rename`, never directly onto the target.

**Unimplemented endpoints** (activity, dashboard, notifications, avatars, etc.): a valid, empty response in the right format,
never a 500, and the call logged so we know what clients ask for.

**Tests for this section**
- Replay the client's recorded session against the server: same sequence of requests, no unexpected response (unplanned
  4xx/5xx).
- Login Flow: 404 before confirmation, 200 after, reused or expired token refused, token from another tenant refused.
- Upload: chunks sent out of order, chunk replayed, inconsistent `OC-Total-Length`, quota exceeded (507), MOVE without all the
  chunks, cleanup of abandoned folders.

## 8. Web interface (minimum scope)
**Features**
1. **Browsing**: folder listing (name, size, date, tags, favorite), breadcrumb, sorting by name/date/size.
2. **Drag and drop**: uploading files (and folders if the browser allows it) by `fetch` PUT to WebDAV, per-file progress,
   cancel, retry; clean refusal if the quota is exceeded. Moving a file onto a folder in the list by drag and drop (MOVE).
3. **Basic actions**: create a folder, rename, move, delete (to the trash), download. Folder downloaded as a streamed ZIP,
   with size and entry-count limits.
4. **Search**: a single field, results as you type (htmx), by name and by tag (`tag:invoice`), limited to the logged-in
   user's space.
5. **Tags**: add/remove on a file or folder, filter by tag. Bounded count and length, normalized characters.
6. **Sharing through an external link** (file or folder), with per link: optional password (argon2id, bounded concurrency
   §0.4), optional expiry, rights (read-only, or **drop only**: the guest does not see the contents and can only upload),
   optional download limit, immediate revocation, list of active links per user, access counter and last access.
7. **Previews**: txt, json, md (sanitized rendering), images, PDF, native audio/video (rendered by the browser, §0.3).
8. **Account**: change one's password, create/revoke one's app passwords (Nextcloud clients), see one's quota.
9. **Text editing** (added 2026-11-16, 0.7.0; single user, not collaborative §1): text files (txt, md, json, sh…) of
   512 KiB at most, in UTF-8, edited in a `<textarea>` (works without JavaScript) and saved through the WebDAV `PUT`
   (identity, tags and links kept, ETag renewed, quota, read-only); conflict detected by the ETag of the version opened;
   Markdown preview rendered by the server; new empty text file from the "+ New" menu of a folder; rename from the edit page. Syntax colouring of JSON, shell and Markdown, when reading and editing, by a
   small script of our own (`static/text.js`, ~3 KB gzip, loaded only by these pages), linear on any text.

**Public links**
- URL `/s/<token>`, random token ≥ 128 bits, with no information about the path or the user.
- With a password: form by **POST** (never in the URL), then a short-lived `HttpOnly; Secure; SameSite=Lax` cookie limited to
  that link. Constant-time comparison.
- Rate limiting of attempts **per link and per IP**; identical response (404) for a nonexistent, expired or revoked link.
- Headers: `X-Robots-Tag: noindex`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on password pages.
- A link is bound to its tenant: opened on another domain, it returns 404.
- Access limited to the shared subtree (`openat` relative to the shared folder); a moved target is found again by `fileid`.
- **Drop only**: sanitized names, per-file and total size limited, owner's quota respected, no listing of the contents, no
  overwrite (automatic suffix).
- Active types (HTML, SVG, XML) always served as attachments, never executed in the application's origin.

**Interface constraints**
- Server-rendered pages; htmx for search and partial refresh; native JS for drag and drop, progress and small interactions.
  No front-end dependency loaded from outside: everything is served from the binary.
- **Rule for small front-end frameworks** (decision of 2026-11-15): a framework (e.g. Preact + `htm`, Lit) is only allowed if
  justified by a specific feature and if it meets **all** these conditions: less than ~30 KB compressed; **no build step**;
  compatible with the strict CSP, **without `unsafe-inline` or `unsafe-eval`** (which rules out standard Alpine.js and
  petite-vue, which evaluate their expressions); served by the binary, pinned version; justified in `DEPS.md` like a crate
  (role, maintainer, last release, size, rejected alternative). Server-side rendering stays the base: browsing, downloading
  and opening links always work without JavaScript. React, full Vue, Angular, Svelte and anything that requires a build are
  excluded.
- Browsing, downloading and opening links work without JS (uploading requires JS).
- Responsive (phone), keyboard accessible, labels in French and a structure ready for other languages.
- Strict CSP without `unsafe-inline`, CSRF on every modifying action, systematic escaping of file names and tags.

## 9. Security and dependencies (complementing §0)
**Technical choices: 2026 practices and proven crates**
- **Never reinvent** what a mature library does better: HTTP, XML parsing, cryptography (password hashing, HMAC, randomness),
  rate limiting, HTML/Markdown sanitizing, Unicode normalization, SQLite, Capsicum, xattr, file watching. Never in-house
  cryptography or format parsers when a proven crate exists. Single exception: the **WebDAV protocol**, if no crate accepts
  the necessary ETags and `oc:` properties (§2, §7); we then write the bare minimum, fuzzed, on top of `quick-xml` and
  `hyper`.
- **Criteria for adopting a crate** (all to check **at the time of the choice** on crates.io, docs.rs and RustSec, not from
  memory): widely used (number of dependents), backed by an organization or identified maintainers, **release less than
  12 months old** (or a stable and complete library whose maintainers fix vulnerabilities), no unfixed RustSec advisory,
  little `unsafe`, compatible license, **builds and passes its tests on FreeBSD 15**. An obscure crate or one without an active
  maintainer is **refused**: prefer a heavier-weight crate, or failing that minimal in-house code, **fuzzed**, for that single
  need. If no solid solution exists, **stop and report it**.
- **Documented decision** (short ADR in `DEPS.md`) for every complex point: problem, candidates compared, choice, reason,
  risk, version kept. Check the APIs against the **documentation of the version kept**: they change, and a model's memory can
  be out of date.
- **Baseline 2026 practices**: Rust edition 2024, documented MSRV, `Cargo.lock` committed, `cargo audit` + `cargo deny`
  continuously (`cargo vet` for critical dependencies if practical), SBOM generated at every release, structured logs with
  `tracing`, typed errors (`thiserror`), no `panic` on external input, reproducible builds as far as possible.
- **Starting candidates** (to confirm or rule out by the criteria above):
  - HTTP and runtime: `tokio`, `hyper`/`axum`, `tower`/`tower-http`. Serialization: `serde`. Logs: `tracing`. CLI: `clap`.
  - WebDAV protocol: `dav-server` (a 0.11.0 version exists on docs.rs, Debian package updated in 2026, `messense`'s
    repository; real activity to confirm on the repository). The critical point remains being able to inject custom ETags
    and `oc:` properties (§7).
  - XML: `quick-xml` (external entities and expansion disabled).
  - Database: `rusqlite` (`bundled` feature). Passwords: `argon2` (RustCrypto). HMAC and hashing: `hmac`, `sha2`.
    Randomness: `getrandom`. Constant-time comparison: `subtle`. Rate limiting: `governor`.
  - Web: `askama` or `maud`, `pulldown-cmark` + `ammonia`, `unicode-normalization`. ZIP: **creation only, streamed**, never
    parsing an archive (reduces the surface); compare `zip`/`async_zip` or a minimal "stored" mode writer.
  - FreeBSD: the `capsicum` crate (author Alan Somers, version 0.4.5 on docs.rs, exposes `enter()`, `RightsBuilder` and
    `CapRights`; **to check**: coverage of `cap_rights_limit`, and compatibility with tokio). Xattr: `xattr` (supports FreeBSD)
    or `extattr` (FreeBSD native, 1.0.0). **Constraint**: in capability mode (Capsicum) **path**-based calls fail, one needs
    **descriptor**-based operations (`fextattr`/`extattr_*_fd`); check that the chosen crate offers them, otherwise a thin
    `libc` wrapper in `fs/`.
  - Tests and quality: `proptest`, `criterion`, `cargo-fuzz` if available.

**Dependencies and build**
- Minimal dependencies; each addition justified in one line in `DEPS.md` (role, maintainer, last release, rejected
  alternative). The adoption criteria above (including release freshness) apply to every addition.
- `Cargo.lock` committed, `cargo build --locked`. At every milestone, attach the output of: `cargo fmt --check`,
  `cargo clippy -- -D warnings`, `cargo audit`, `cargo deny check`, `cargo test`.
- `#![forbid(unsafe_code)]` everywhere **except** in `fs/` (FFI: `extattr`, `sendfile`, Capsicum); each `unsafe` carries a
  `// SAFETY:` comment and a test. `unwrap`, `expect` and direct indexing forbidden outside tests (clippy lints at `deny`).

**Code rules**
- **Paths**: a `SafePath` type built by validation (no `..`, NUL bytes, absolute path; Unicode normalization), the only one
  accepted by `fs/`.
- **Limits**: body size, PROPFIND depth (`Depth: infinity` refused), number of entries per response, size of incoming XML (no
  external entities or expansion), read/write/idle timeouts, connections per IP, number of chunks per upload.
- **Secrets**: constant-time comparison (`subtle`), tokens ≥ 128 bits from the OS CSPRNG, argon2id **reserved for human
  passwords** (documented parameters, bounded concurrency, §0.4), never a secret in logs, errors or URLs.
- **Web**: `HttpOnly; Secure; SameSite=Lax` cookies, CSRF on every modifying action, strict CSP,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, sanitized Markdown previews (`pulldown-cmark` +
  `ammonia`).
- **Errors**: generic message for the client, details in the logs, never an absolute disk path.
- **Tenant**: resolved once, early, carried in a `TenantCtx` type required by every access function.
- **Logs**: IP, tenant, user, action, result; rotation; never file contents.

## 10. Tests
**Policy (since 0.12): paranoid and security-first, as SQLite.** Every branch that matters is run by a test, every defect
leaves a test, every feature ships with unit, end-to-end, property (`proptest`) and, for client input, fuzz tests; coverage
and mutation testing measure what the tests really check. Method, commands and the program in progress:
`docs/dev/TESTING.md`; results: `VALIDATION.md`.
- **Unit**: `SafePath`, ETag and propagation, share tokens, quotas, tenant resolution.
- **Properties** (`proptest`), **mandatory for every feature** from 0.11 on: each new feature states its rules as properties
  (what must always hold, whatever the input or the sequence of actions) and ships with a `proptest` test in the same commit;
  a feature without one is not finished. For anything with state (files, links, trash, sessions), a **model-based test**: random
  sequences of operations applied to the server and to an in-memory model, compared after each step (reference:
  `dav::model`, WebDAV MKCOL/PUT/DELETE/MOVE/COPY). 48 cases on each `cargo test`; a long run (`PROPTEST_CASES=3000`) before
  each release. Divergences found are fixed, or kept on purpose and written in the test and in `VALIDATION.md`. Examples:
  every generated path stays under the user's root; MOVE then reverse MOVE = initial state.
- **Fuzzing** (`cargo-fuzz` if available, otherwise intensive `proptest`): PROPFIND XML parser, `SafePath`, `Range`,
  `If-Match`, `Destination` headers, Unicode names. Corpus committed, no crash.
- **Integration**: real server on a temporary folder; PROPFIND/PUT/MOVE/DELETE scenarios, chunked upload, `Range`, ETag
  conflicts, exceeded quotas.
- **Durability** (§0.2): `kill -9` during PUT, MOVE, chunked upload and ETag propagation; full disk; switch to read-only.
- **File identity** (§6): repeated PUTs of the same file → `fileid`, tags, favorites and shares unchanged; MOVE and rename →
  identity kept; delete then create a file (inode reused) → new identity; external copy → new identity; two paths carrying
  the same identifier → the second one is reassigned; non-writable xattr → degraded fallback reported.
- **ETag propagation and crash** (§6): `kill -9` between the `rename` and the propagation → after restart, the ancestors'
  ETags are renewed (journal replay); repeated replay without side effects (idempotence).
- **Authentication** (§0.4): 1,000 requests per second with an app token without RSS growth and with a p95 check latency
  < 1 ms; human password on WebDAV or OCS → 401 without calling argon2; 50 simultaneous web logins → at most N argon2 hashes
  in parallel (N bounded), RSS under budget, excess as `503`; token from another tenant refused; failures limited per tenant
  and per IP.
- **Write contract** (§6): at rest, the server opens no watch descriptor and starts no background walk (measured: zero I/O);
  `verify` reports, without changing anything, a file added, a file changed and an identifier duplicated outside the
  application; `rescan` assigns identities, renews the ETags of the subtree and ancestors and rebuilds the index; after
  `zfs rollback` then `rescan`, the desktop client resyncs correctly; an import by `rclone` over WebDAV keeps ETags and
  identities; the `.beastbox-tmp/` folder never shows up on the client side.
- **WebDAV compliance**: `litmus` suite (failures listed and justified).
- **Real clients** (manual, documented): Nextcloud desktop client, mobile app, `rclone`; replay of the recorded session (§7).
- **Automated negative security**:
  - traversal: `../`, `%2e%2e`, `..%2f`, double encoding, outgoing symlink, `\`, NUL bytes;
  - isolation: cross access between tenants and users by path, token, share link, forged `Host` or `X-Forwarded-Host` from an
    unlisted IP;
  - surfaces: unknown routes and unlisted methods refused; no administration route on the public listener;
  - XSS: malicious `.md`, `.html`, `.svg` served and previewed; a tag containing `<script>`;
  - denial of service: giant bodies, XML bomb, `Depth: infinity`, huge headers, slow connections;
  - brute force: slowdown or lockout after N failures (login and link password).
- **Multi-tenant isolation** (§4.1), to write **from J0** and to replay at every milestone:
  - test bench with **two tenants**: every integration test is run with crossed actions (A tries to read, write, list, share,
    move, delete, search in B's space, by path, `fileid`, token, session, share token, `Host` and `X-Forwarded-Host`);
  - **property**: a random sequence of tenant A's operations changes **no byte, xattr or database row** of tenant B
    (fingerprints compared before and after);
  - **concurrency**: A's and B's requests interleaved under heavy load: no response, header, cookie or cache of one shows up
    in the other;
  - **route audit**: a test that enumerates the route table and fails if a handler does not require a tenant context;
  - **SQL query audit**: fails if a query does not filter by `tenant_id`;
  - **fuzzing of host headers** (case, port, trailing dot, IDNA, duplicates, userinfo, conflicting values);
  - **configuration**: startup refused for ambiguous host names, patterns too broad, nested roots or roots on the same
    dataset;
  - **`O_RESOLVE_BENEATH`**: escape attempts via `..`, symlink, hard link and mount point from a tenant's root.
- **Share links**: wrong password, expired, revoked link, limit reached, wrong tenant, forged or truncated token; drop only with
  hostile names (`../x`, `.htaccess`, NUL bytes, very long), file too large, full quota, overwrite attempt.
- **Tags and search**: HTML injection, exotic Unicode, count limit, case; search never returns a result from another user or
  tenant.
- **Browser**: minimal automated walkthrough (upload, search, tag, share, revocation).
- **Storage**: startup refused if the data root is on NFS or on a filesystem without xattrs; startup accepted on a local ZFS
  dataset.
- **Database**: delete `app.db` → the server restarts, files are intact, only accounts and shares need re-creating.
- **restic backup** (§0.2): back up a user's dataset with restic, restore into an empty dataset, then `beastbox verify`: no
  file without an identity, no duplicate; `fileid` and ETag identical before and after; a synced client re-downloads nothing.
- **Client-side trash** (§6): delete from the client, see the item in the client's trash, restore it from the client (desktop
  and Android); identity kept, suffixed name if the spot is taken.
- **Performance** (§0.4): 100,000 files, PROPFIND on a folder of 10,000 entries, 20 parallel uploads, number of open
  descriptors; time and memory in `VALIDATION.md` (§7), compared with the budgets.
- **Scalability** (§0.5): 10 tenants and 100 users simulated in parallel without exceeding the budgets; a noisy tenant (limits
  reached) does not degrade the others' latency; overload → clean `503`; eviction of an inactive tenant without losing state;
  `tenant export` then `tenant import` on another instance gives back data, accounts and shares identically.
- **Memory** (§0.4): RSS at rest and under load below budgets; slow clients, giant bodies and listings of 100,000 entries
  without unbounded growth; no leak over 1 hour of repeated load (stable RSS).
- **FreeBSD**: tests run on FreeBSD; after `cap_enter()`, opening an absolute path fails.

## 11. Milestones (in order; do not move to the next without the exit criterion)
**J0: Skeleton and model.** Cargo, config, logs, `rc.d`, test vhost; initial SQLite schema and migrations; tenant resolution;
database schema keyed by tenant (§0.5); bootstrap CLI (first admin); loopback/socket listener; deny-by-default route table;
atomic write in `fs/` **with xattr copy and persistent identifier (§6)**; Capsicum-compatible descriptor design; initial
`SURFACE.md` and `VALIDATION.md` (§7) (budgets §0.4).
*Exit: request through the proxy → 200 for a known domain, 421 for an unknown one; unknown route → 404; hard-kill test on the
atomic write; two-tenant test bench and route and SQL query audits in place (§4.1, §10).*
**Human review of the isolation design (`tenant/`, `db/`, `fs/`) at the end of J0**, before writing the rest.

**J1: Go/no-go spike (the riskiest).** Recording the sessions of real clients (§7), read-only WebDAV, `status.php`, Login Flow
v2, capabilities, folder ETag with propagation on write, URLs based on the request's domain.
*Prerequisite: a reference Nextcloud server reachable to record the sessions (to be provided by the owner).*
*Exit: the Nextcloud desktop client connects, shows the tree, and, after an add, a rename, a delete or an in-place change made
over SSH **followed by `beastbox rescan`** (§6), detects the change in a deep subfolder; test with two domains on the same
binary, each with its own data root; cost at rest measured (no background I/O); cost of a PROPFIND with xattr reads measured.
If impossible, stop and report why.*

**J2: Full write.** PUT, MKCOL, MOVE, COPY, DELETE (through the trash), chunked upload v2, conflicts via `If-Match`, **ETag
intent journal and replay at startup (§6)**, import by `rclone` over WebDAV, `beastbox verify` and `beastbox rescan` commands,
authentication by app tokens and refusal of the human password on WebDAV/OCS (§2), per-user quotas, per-user descriptors,
read-only mode under a space threshold.
*Exit: two-way sync of the desktop client on a test folder, then the mobile app (upload and download); `kill -9` tests green.*

**J3: Web and sharing** (§8, items 1, 2, 3, 5 without filter, 6, 7, 8); separation of the public/authenticated surfaces
checked by tests.
*Exit: drag and drop of a folder of 100 files OK; a link with password, expiry and limit works and can be revoked; drop only
reveals no name; a `.md` containing `<script>` does not execute; a tenant's link opened on another domain returns 404.*
**Human security review (starting from `SURFACE.md`) mandatory before exposure.**

**J3b: Interface polish (after the J3 security review, before or with J4).** The J3 interface is deliberately minimal; J3b
makes it pleasant without touching security or the no-JavaScript operation. Tools: htmx (already planned) and native JS;
Preact only if a specific feature justifies it, under the rule of §8.
- **Multi-select**: checkboxes in a form and bulk actions (delete, move to…, download as ZIP), usable without JavaScript;
  "select all" and Shift+click in native JS.
- **Preview panel** loaded without reloading the page (htmx); **gallery** (next or previous item, keyboard) for images.
- **Presentation**: icons per file type (SVG files served by the binary), thumbnails rendered **by the browser** (never on
  the server, §0.3), layout and typography, persistent upload bar, confirmations without `alert()`.
- **Partial refresh** of the list after an action (htmx).
*Exit: selecting and deleting 50 items in one action, with or without JavaScript; previewing an image and moving to the next
with the keyboard; CSP unchanged (no `unsafe-inline` or `unsafe-eval`); keyboard accessibility checked; total weight of the
JavaScript and CSS served recorded in `VALIDATION.md` (§7).*

**J4: Search and trash.** In-memory index of names and tags **built on the tenant's first use** (budgeted, with the rebuild
cost measured since an inactive tenant can be evicted), then kept up to date by the server's writes and rebuilt by `rescan`;
search (§8 item 4), filter by tag, trash with restore, retention and purge (§6), **trash exposed to Nextcloud clients
(`/remote.php/dav/trashbin/`, §6)**; **restic backup and restore test with the xattrs (§0.2)**.

- **Additions of 2026-11-15 (to do before closing J4)**:
  1. **Defect fixed** (2026-11-15): a trash item without a deletion date (lost xattr) counted as dated 1970, so the hourly
     purge **emptied the whole trash** right after a restore without xattrs. Missing date = date of discovery (retention
     starts from zero).
  2. **Done with the desktop client (2026-11-17)** — identities deliberately erased on a synced folder, `rescan`, client
     observed (`CLIENTS.md`): no loss, but the client re-downloads every file whose ETag changed and turns a local change
     made meanwhile into a conflict. Hence the manifest's format 2 (below): the ETag is kept when the content is proven
     identical (SHA-1). Still to do: the Android app.
  3. **Done (2026-11-15, 0.3.0)** — **Identity manifest**, so that a backup by **file copy** (rclone sync to a cloud such as
     pCloud, `rsync` without `-X`, `cp`) keeps the identities: `beastbox manifest --tenant T --user U` writes into the user's
     dataset an ordinary file with a reserved name (invisible to clients): path, `fileid`, size, time, tags, favorite, trash
     metadata. Run at the start of the backup script. On `rescan`, an item **without an identity** at the same path, with the
     same size and the same time, gets back its original `fileid`, its tags, its favorite and its trash metadata (share links
     and clients find the same identities); a different size or time → new identity. It is a snapshot taken at backup time,
     not an index in the database (§5). Measured cost: 1.2 s and 7.3 MB for 100,000 files (`VALIDATION.md` (§7)).
     Implementation details: time compared **to the second** (rclone to pCloud only keeps the second), folder matched at the
     same path (its time necessarily changes), an identity already held elsewhere never reused, an existing xattr always wins;
     see `../admin/backup.md`. Without xattrs or a manifest, the impact is documented in `../admin/backup.md` (identities,
     links, tags and favorites lost). restic is not affected: it keeps the xattrs in its repository whatever the storage
     (pCloud included).
     **Format 2 (2026-11-17, not released yet)**: each file also carries the nanoseconds of its time and the SHA-1 recorded
     at write time. On `rescan`, a matching file whose sum is known is reread: same SHA-1 → sum record and exact time put
     back, hence the **same ETag** (no re-download, no conflict); another SHA-1 → different content, new identity. A file
     without a sum (put on disk outside the application) keeps the format 1 behavior. Format 1 still read.
*Exit: search by name or tag < 100 ms over 100,000 files; restoring a deleted file from the trash demonstrated **from the web
interface and from the desktop client and the Android app** (identity, tags and shares recovered); `../admin/backup.md`
describes the snapshot restore on the administrator side, followed by a `rescan`, **and the restic backup: a real restore on
FreeBSD keeps `fileid`, ETag, sums and tags (checked by `beastbox verify`: no file without an identity)**.*

**J4b: Push notifications (candidate, after J4, to decide).** Implement on the server side the client protocol of
[`nextcloud/notify_push`](https://github.com/nextcloud/notify_push) to replace the clients' polling (PROPFIND every 10 to 30 s)
with an immediate notification. No Redis or separate daemon: thanks to the write contract (§6), Beastbox already knows when a
file changes; `notify_file` is emitted when ETags are renewed (server write or `rescan`).
- Protocol (the project's README and `DEVELOPING.md`, v1.4.2, to confirm by observation §7): capability
  `notify_push.endpoints.websocket` (and `pre_auth`); a WebSocket where the client sends the user name then the app password,
  the server answers `authenticated`; text messages `notify_file` (option `listen notify_file_id` → `notify_file_id` + JSON
  list of identifiers), `notify_activity`, `notify_notification`. Only the protocol is reused, not the code (AGPL-3.0).
- **To check before deciding**: which versions of the desktop client and the mobile app use it, and how much they space out
  their polling when push is available (observe a real client, §7); cost of the WebSocket dependencies (axum's `ws` feature,
  ~5 to 8 crates) with regard to §9.
- Constraints: permanent connections counted in `max_connections` and memory (§0.4), bounded per-user connection registry,
  authentication and failure limiting like WebDAV, a new public route in `SURFACE.md`. "Best effort" notification: the client
  keeps a spaced-out fallback poll.
*Exit: a change made from one device shows up on another in less than a second; the number of polling PROPFINDs per client
drops by a measured factor (`VALIDATION.md` (§7)); no memory growth with 200 open push connections.*

**J5: Hardening and scaling.** Capsicum with `cap_rights_limit` per descriptor, the jail's `rctl` limits, eviction of inactive
tenants, per-tenant limits, `beastbox tenant export|import` (§0.5), per-tenant OIDC (optional), full-text search with
`tantivy` (optional).
*Exit: the process can no longer open an absolute path.* **Human review mandatory.**

**J6: dropped (2026-11-20).** Calendar and contacts stay out of Beastbox (§14).

**J7: Administration and monitoring API (optional, later).** An HTTP adapter over the `admin/` layer and exposure of the
`metrics/` metrics, with no new business logic.
- **Separate surface** (§0.3, group c): a listener distinct from the public API, **never behind the public reverse proxy**;
  by default loopback or a Unix socket, with an administration token (HMAC, revocable) and an audit log of every call.
  Disabled by default.
- **Versioned administration API** (`/admin/v1/…`): accounts, tenants, quotas, shares, app tokens, `verify`, `rescan`,
  instance state; every destructive operation requires explicit confirmation (snapshots remain the administrator's job,
  §0.2).
- **Monitoring**: metrics in the standard text format (Prometheus/VictoriaMetrics compatible) and a health probe (`/healthz`:
  process alive, `/readyz`: data roots mounted and xattrs working). For a monitoring jail to read them, plan a listener on
  the jail's address **restricted by pf** to the monitoring host, rather than loopback only.
- **Tests**: the API refuses any call without a token; a token from one tenant cannot administer another (§4.1); no
  administration route is reachable from the public listener; every call leaves an audit trace; metrics expose neither file
  names nor secrets.
*Exit: the API replaces the CLI for everyday operations without changing behavior; surface audit (`SURFACE.md`) reread.*
**Human security review mandatory** before any activation.

## 12. Definition of "done" for a milestone
1. Exit criterion demonstrated.
2. §9 checks green.
3. Relevant §10 tests added, no test disabled or relaxed without saying so.
4. Report: what works, what is worked around, what is **not tested**, new dependencies — kept in `CHANGELOG.md` (one entry
   per release) and `VALIDATION.md` (tests, defects, not tested, accepted limits), which replace `JALONS.md`.
5. Human review before J3 and J5; before any public exposure: full code review (paths, auth, sharing, multi-tenant), clean
   `cargo audit`, fuzzing without a crash over a defined duration, external scan behind the proxy.
6. `SURFACE.md` updated and its diff reread.
6b. `VALIDATION.md` (summary of all the tests carried out, defects found, what is not tested) updated: it is the document that
   justifies the product's soundness.
7. Performance **and memory** budgets measured, with no regression > 15 % and no RSS budget overrun (§0.4).
8. Durability tests (hard kill) green (§0.2).
9. Every new dependency or complex technical choice has its decision documented in `DEPS.md` (§9), and the crate meets the
   adoption criteria.

## 13. Working rules for the agent
- One milestone at a time. No feature, dependency or abstraction that was not asked for.
- When in doubt about the Nextcloud protocol, **observe a real client** rather than assume.
- The priorities of §0 win: in case of conflict, choose data integrity, then security, then performance and memory.
- **Required environment** (to be provided by the owner): a **FreeBSD 15 machine or jail with ZFS** and a test dataset (the
  tests of this plan, xattr and Capsicum in particular, are only meaningful there), a **reference Nextcloud server**, and the
  real clients (desktop, mobile). Without this environment, the agent says so and does not declare the milestones concerned
  "done".
- Never self-validate milestones marked "human review". Explicitly list everything that could not be tested.

## 14. Appendix: calendar and contacts (out of scope, decided 2026-11-20)
**Decision**: Beastbox does not serve, proxy or authenticate CalDAV/CardDAV. Radicale runs on its own, beside it; nothing
of it enters this repository. The earlier plan (a `caldav/` reverse proxy, identity passed in `X-Remote-User`, milestone J6)
is dropped: it added a proxy rewriting hostile XML and headers, an identity header to strip, and a Python dependency to the
attack surface, for one benefit only (one credential per device). DAVx5 and the iOS account cannot use OIDC anyway.

Deployment note (not code):
- Radicale (FreeBSD package `py312-radicale`) in its own jail, its own host name behind the reverse proxy, its own accounts
  (`htpasswd`, bcrypt) and `rights`; one instance per tenant, or per-user rights in one.
- Discovery from a Beastbox host, if wanted: the reverse proxy answers `/.well-known/caldav` and `/.well-known/carddav`
  with a 301 to Radicale. Beastbox itself keeps answering 404 there.
- Backup: Radicale's storage is a ZFS dataset of its jail, in the usual snapshots.
