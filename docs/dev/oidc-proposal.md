# OIDC single sign-on — proposal (design)

Referenced from `src/auth/oidc.rs` and `src/config.rs`. Decisions ADR-5 (TLS is the trust anchor, no JWT
signature library) and ADR-6 (the Casper channel for the back channel) are in `DEPS.md`. The implementation
steps are in `oidc-implementation-plan.md`. Plan sections: §2 (constraints), §4.1 (host names), §0.3 (attack
surface), §9 (security), §10 (tests).

## Goal and scope

A tenant may delegate the sign-in of its accounts to an external OpenID provider (OIDC), so that accounts
created without a password (`beastbox user add --oidc`) sign in through the provider. Beastbox is a
**confidential client**: authorization code flow + PKCE S256, over verified TLS, no refresh token and no
access token use (the `id_token` alone identifies the user).

Out of scope: provider-initiated logout propagation (only a local logout), SCIM/user provisioning, dynamic
client registration.

## Configuration (`[tenant.oidc]`, one per tenant)

| Key | Meaning |
|---|---|
| `issuer` | The provider's issuer **byte for byte** (trailing slash and path included, e.g. authentik's `https://host/application/o/app/`): compared exactly with the `iss` claim. Strict `https` URL grammar (`HttpsUrl`, fuzzed) |
| `client_id` | 1–255 visible ASCII |
| `client_secret_file` | Absolute path; read **once at startup**, before Capsicum (1–255 visible ASCII, no `:` so the Basic header stays unambiguous); never printed (tested) |
| `second_factor` | `beastbox` (default): the provider authenticates, Beastbox asks its own TOTP when the account has one; `provider`: the provider does both, and `required_amr` is enforced on the `amr` claim |
| `required_amr` | `amr` values accepted as a second factor (default `["mfa"]`); empty + `provider` + tenant `two_factor = "required"` is accepted but warned at startup (the provider's policy is then trusted) |
| `connect_addr` | Fixed `ip:port` the TLS connection goes to instead of resolving the host (split DNS, LAN provider); the certificate is still checked against the configured host name |
| `backchannel_hosts` | Other `host[:port]` (max 8) the token endpoint may live on, besides the issuer's own |
| `ca_file` | Root CA bundle (system bundle by default, or a private CA) |
| `password_login` | **Off by default**: the web sign-in goes through the provider only (the Beastbox password form is not rendered and `POST /login` is refused without argon2). `true` keeps the local form for a break-glass account |

Two tenants may share an issuer or a client id, **never both** (they would accept each other's tokens):
refused at startup. No `oidc` table: `oidc` absent means password-only sign-in.

The public base URL of `redirect_uri` is `https://<first exact host of the tenant>` — **from the
configuration only, never from the request's `Host` header** (§4.1), so a forged header cannot reopen
`redirect_uri`.

## The flow

```
browser          Beastbox                     provider
   |  GET /login/oidc?next=…  |                       |
   |------------------------>|                       |
   |  flow cookie (MAC'd) +  |                       |
   |  303 → authorize_url    |                       |
   |------------------------>|  GET authorize_url    |
   |                         |---------------------->|
   |                         |  303 → /login/oidc/callback?code&state  |
   |  GET callback (+cookie) |<----------------------|
   |------------------------>|                       |
   |  back channel: discovery + POST token -------->|
   |  id_token checks, account lookup, session     |
   |  303 → next (+ session cookie)                |
   |---------------------------------------------->|
```

1. `GET /login/oidc?next=…` (`web::oidc::start`): `next` goes through the same allowlist as the password
   login (`auth::oidc::after_login`: `/index.php/f/<digits>`, `/web/account`, a Login Flow token; `""` = the
   files page). A **stateless flow** is created: the cookie carries `until.random.next.mac`, an
   HMAC-SHA256 keyed by the tenant over `until.random.next` (anti-stretch of the TTL, 600 s); `state`,
   `nonce` and the PKCE verifier are derived from the cookie value with the tenant key and never leave the
   server. The browser is redirected to `authorize_url` (all parameters of the code flow + PKCE S256;
   `redirect_uri` = configured base + `/login/oidc/callback`).
2. The provider redirects to `GET /login/oidc/callback?code&state` (`web::oidc::callback`), which inherits
   the login's rate limit (429 when the IP or the tenant is blocked; every refusal recorded, per IP and per
   tenant). The cookie is read back (`read_flow`, MAC in constant time, expiry and shape checked), `state`
   compared in constant time (`subtle`), `iss` required when the discovery document says the provider echoes
   it (RFC 9207). `code` is bounded (≤ 512 visible ASCII).
3. Back channel (`auth::oidc_net`, through the `Net` channel — ADR-6): `GET <issuer>/.well-known/openid-configuration`
   (bounded, parsed and checked by `parse_discovery`: issuer byte for byte, `https` endpoints only, token
   endpoint on the issuer's host:port or a declared `backchannel_host`, `code` offered, PKCE refused only
   when methods are listed without S256, a client authentication method), then `POST` the token endpoint
   (`grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`; Basic or Post per
   the discovery document). Only the `id_token` of the response is read (`parse_token_response`: a provider
   `error`, a missing/oversized/duplicated field are refused).
4. `check_id_token`: three segments, bounded payload, `iss` exact, `aud`/`azp`, `exp`/`iat` finite with 60 s
   of skew (`1e999` refused), `nonce` in constant time, `sub` 1–255 visible ASCII, `amr` bounded. **The
   signature is not verified** (ADR-5): the token comes directly from the token endpoint over verified TLS
   (OIDC Core §3.1.3.7), so there is no JWKS dependency and no « key ID not found in the JWKS » failure mode.
   One deliberate deviation from OIDC Core, recorded in ADR-5: `iat` is optional (a token without it is
   accepted; `exp` still bounds its life).
5. Account lookup: `user_by_oidc(tenant, issuer, subject)` — active accounts only, one identity per account
   (unique partial index `(tenant_id, oidc_issuer, oidc_subject)`). With `second_factor = "provider"`, an
   `amr` of `required_amr` is required. A session is then created exactly as for the password login: pending
   session (→ `/login/code`) when the account has TOTP on, full session otherwise; the usual gates apply
   (`must_change`, required TOTP setup). The flow cookie is cleared; the browser goes to `next`.

## Account linking (administrator only)

An identity is bound to an account by `beastbox user oidc-link --tenant T NAME --subject S` **only** —
never by name or by the first sign-in. The link is transactional: the account's password is cleared (it can
no longer sign in with it), its sessions end, the `audit` table records it; the identity must be free
(unique index). `user oidc-unlink` (or `user passwd`) is the recovery path: identity removed, a human
password set, sessions ended, audited. A linked account has no password of its own
(`password_hash IS NULL`).

## Security properties

- Flow cookie: HMAC-SHA256 keyed by the tenant, covers `until.random.next`; one changed byte, the other
  tenant's key, an expired or stretched value → refused, never a partial answer (property-tested).
- `state` and `nonce` compared in constant time; PKCE S256 (RFC 7636 appendix B vector tested).
- `after_login` allowlist: no open redirect / login CSRF; the same allowlist for the password, Login Flow
  and provider returns.
- Discovery: size bounded before parsing, issuer byte for byte, `https` endpoints only, token endpoint
  restricted to the issuer's host:port or `backchannel_hosts` (max 8) — the client secret and the code only
  go there. `connect_addr` for split DNS (anticipates the Cloudflare-Tunnel back-channel 403).
- Token response: `id_token` only (avoids the Authelia `refresh_token` grant trap); error responses refused.
- `id_token`: see ADR-5; every numeric claim finite and in range; `sub`/`amr` bounded and visible ASCII.
- Back channel in capability mode goes through the Casper `system.net` service (ADR-6), **limited at
  startup to the configured destinations** (`name2addr` = issuer + backchannel hosts, `connect` =
  `connect_addr` only, `CONNECTDNS` for addresses the service itself resolved), the limits being read back
  with `cap_limit_get` before anything runs. Fail closed when the service cannot be opened or the limits are
  not those set. Measured on FreeBSD 15.1: without a fixed endpoint `CAPNET_CONNECT` must **not** be set (an
  empty connect list allows every address), and `socket(2)` is allowed in capability mode — only `connect(2)`
  is not, so each connection opens its own socket and no pool is needed.
- One door: on a tenant with a provider, `/login` renders no password form and refuses `POST /login` (403, no
  argon2, no failure counted) unless `password_login = true`. The account's own TOTP, when it has one, is asked
  after the provider (`second_factor = "beastbox"`).
- Rate limit: the callback inherits the login's (per-IP and per-tenant), success is not counted.
- The client secret and the CA bundle are read once at startup, before `cap_enter()` (an absolute path cannot
  be opened afterwards), and the secret is never logged or printed (tested).

## Tests (see `oidc-implementation-plan.md` and TESTING.md)

Unit: one valid fixture + one change per refusal class, bounds at/below/above, property tests (no panic,
URL round-trip, cookie/tenant binding, closed allowlist). End to end: a mock provider (real TLS server on
127.0.0.1, self-signed certificate generated by `openssl` in the test) driven through the real router —
start, authorize, callback, session, plus every refusal and the rate limit (`web/tests_oidc.rs`). The URL
grammar is fuzzed (`fuzz/fuzz_targets/oidc_url.rs`). Coverage floor for `auth/oidc.rs` in `scripts/check.sh`.
