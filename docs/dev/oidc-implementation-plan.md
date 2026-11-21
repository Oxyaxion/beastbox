# OIDC single sign-on — implementation plan

Referenced from `src/auth/oidc.rs`. Design and reasons: `oidc-proposal.md`. ADRs: `DEPS.md` (ADR-5, ADR-6).
Each phase is one commit, with its tests; the gates are `scripts/check.sh` (TESTING.md).

## Phases

| Phase | Content | Commit |
|---|---|---|
| 1 | Dependencies (rustls/ring/tokio-rustls/serde_json/subtle), `[tenant.oidc]` configuration with `deny_unknown_fields` and cross-tenant `(issuer, client_id)` unicity, the `https` URL grammar (`HttpsUrl`, `parse_host_port`), fuzz target `oidc_url` | `e42e061a` |
| 3 | Database migration (`user.oidc_issuer`/`oidc_subject` + unique partial index, backup `VACUUM INTO` before), `user oidc-link` / unlink (transactional, audited), CLI (`user add --oidc`), `user_by_oidc` (active accounts only) | `aa1f24d0` |
| 4 | The pure protocol core in `auth/oidc.rs`: flow values (MAC'd stateless cookie), `authorize_url`, `parse_discovery`, `parse_token_response`, `check_id_token`, the `after_login` allowlist; ~24 dedicated tests incl. 4 proptest and the RFC 7636 PKCE vector | `5c282318` |
| 5 | The back channel and the wiring (this plan's last row): `fs/casper.rs` (Casper `system.net` channel, ADR-6), `auth/oidc_net.rs` (TLS, discovery, token exchange, bounded and timed out), `web/oidc.rs` (`GET /login/oidc`, `GET /login/oidc/callback`), the SSO button on the login page, `redirect_uri` base from the configuration only, the callback's rate limit (the login's), `second_factor`/`required_amr` enforced, end-to-end tests with a mock provider (`web/tests_oidc.rs`) | this change |

Note on the numbering: the log goes 1 → 3 → 4. Checked 2026-11-18 (`git log --all`, `git reflog`,
`git fsck --lost-found`): the dangling commits are unrelated work (a mutation WIP, the administrator-set
password, a fuzz bench session, a changelog test) — **no phase-2 commit was lost**; phase 2 was folded
into phase 3 (the migration and the admin link).

## Phase 5 in detail

1. `src/fs/casper.rs` — the only `unsafe` outside `fs/`'s existing FFI is here (with `fs/`): `cap_init`,
   `cap_service_open("system.net")`, limits set with `cap_net_limit_*` on the **service** channel (`name2addr`
   = issuer + backchannel hosts, `connect` = `connect_addr` only, mode `NAME2ADDR | CONNECTDNS`, plus
   `CONNECT` only when a fixed endpoint is declared) and read back with `cap_limit_get`. Then
   `resolve` (`cap_getaddrinfo`) and `connect` (`cap_connect`), one socket per connection. Nothing to install
   (libcasper is in the base system and forks the service itself); fail closed when the channel or its limits
   cannot be had.
2. `src/auth/oidc_net.rs` — `Net` (direct in tests, Casper in production via `App.net`, opened in `serve`
   before `cap_enter()`), rustls client from `ca_file`, hyper HTTP/1.1 over TLS, whole-call timeout;
   `fetch_discovery` and `exchange_code` (Basic or Post per the discovery document), bodies bounded
   (`MAX_PROVIDER_JSON_BYTES`), status checked; the protocol checks stay in `oidc.rs`.
3. `src/web/oidc.rs` — the two public routes (added to `ROUTES` and `SURFACE.md`): `start` (flow cookie +
   303 to `authorize_url`, `base` = `https://<first exact host>` from the config, never the `Host` header)
   and `callback` (rate limit, cookie, state in constant time, `iss` when advertised, back channel,
   `check_id_token`, `required_amr` when `second_factor = "provider"`, `user_by_oidc`, session with the same
   TOTP gate as the password login, 303 to `next`, flow cookie cleared; refusals redirect to `/login`
   without detail and are recorded). The login page shows the SSO button when the tenant has OIDC.
4. Configuration → runtime: `OidcRuntime` (secret read once at startup, `base` derived from the hosts)
   carried by `TenantCtx`; `Net::for_tenants` in `serve`.
5. Tests: `web/tests_oidc.rs` (mock provider = real TLS server on 127.0.0.1 with an openssl-generated
   self-signed certificate; full flow through the real router, `next` handling, every refusal, the rate
   limit, tenant binding of the flow cookie, the SSO button present only with OIDC, plus the back-channel
   failure paths: broken/oversized discovery, unreachable or non-TLS endpoint, malformed `code`, RFC 9207
   `iss`, `client_secret_post`, TOTP pending session); `fs/casper.rs` unit tests (the real service: the
   channel opens with its limits, an allowed name resolves, an undeclared name and an undeclared address are
   refused, and a connection to a local listener goes through; sockaddr round-trip);
   `oidc_net.rs` unit tests (`tls_config` CA checks, `Net::for_tenants`); the `oidc.rs` unit/prop tests
   from phase 4. `check.sh`: coverage floors `auth/oidc.rs` ≥ 98 %, `auth/oidc_net.rs` ≥ 82 %,
   `web/oidc.rs` ≥ 95 %; `isolation` alone stays out of the denominator (`cap_enter` is irreversible).

## Tester sur le banc (jail `beastbox` of the bench host)

Verified on 2026-11-19 against the prod Authelia (`https://auth.example`, issuer and CA bundle taken from the
jail): one client `beastbox-banc` (pbkdf2-hashed secret, PKCE S256, `client_secret_basic`, redirect_uri
`https://files.alpha.test:8443/login/oidc/callback`), the jail's nginx terminating TLS on 8443 with a
self-signed certificate (one pf `rdr` on the LAN), tenant `alpha`, `alice` linked by `user oidc-link` (the
provider's opaque identifier for `openid`, since this Authelia build refuses `subject_type`). Observed working:
the SSO sign-in, both second-factor arrangements (`provider` with `required_amr = []` — 2FA and its TOTP at
Authelia — and `beastbox` — the account's own TOTP asked after the provider's password), and the **Login Flow
v2**: the desktop client (mirall 35) obtained an app password through the browser and synced (PROPFIND 207,
download 200). An account bound to a provider has no password, so the confirmation page had to go through
`/login` first — that was a real defect, fixed in `8aedab6f`.

Trap for the next bench run: a client retrying with a refused credential (a stale human password) arms the
per-IP failure limit (10 failures / 5 min) and then **every** request from that IP answers 429, the browser's
`/login` included; stop the client first, or wait five minutes, or restart `serve` (the counters are in memory).

## Open items (from the 2026-11-18 audit)

- The four production blockers found in review are fixed: CA bundle and secret read once at startup; every
  socket handed to the service keeps `CAP_CONNECT`; `cap_connect` replaces the hand-rolled nvlist (the moved
  descriptor was closed twice); the limits are set on the service channel with the right `libnv` prototype and
  `CAPNET_CONNECT` only for declared endpoints; `second_factor = "provider"` no longer asks Beastbox's TOTP.
  `fs/casper.rs` is exercised by the CI now (libcasper is in the base system).
- Mutation testing (`check.sh --long`) has not run on these commits yet: run it before the release.
- Cosmetic, fixed in phase 5: `now + FLOW_TTL` → `saturating_add`; a leading `+` in a port
  (`https://host:+80`) is now refused (digits only); `iat` optional is recorded in ADR-5.
- Human security review done by the owner (2026-11-20, plan §12.5): the feature is allowed in production.
