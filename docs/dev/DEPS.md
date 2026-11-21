# Dependencies

Checked on crates.io on 2026-11-14 (version, last release, downloads). All build and pass the tests on FreeBSD 15.1.
MSRV: Rust 1.95 (edition 2024, `let` chains). `Cargo.lock` committed.

## Direct
| Crate | Version | Released | Role | Maintainers | Rejected alternative |
|---|---|---|---|---|---|
| tokio | 1.54.1 | 2026-10 | async runtime (minimal features, fixed threads) | tokio-rs | — |
| axum | 0.8.9 | 2026-04 | HTTP routing on hyper (features `http1`, `tokio` only) | tokio-rs | bare hyper: more in-house code |
| rusqlite | 0.42.0 | 2026-11 | embedded SQLite (`bundled`) | rusqlite org | sqlx: async not needed, heavier |
| serde | 1.0.229 | 2026-07 | config deserialization | serde-rs | — |
| toml | 1.2.1 | 2026-11 | config (`parse`, `serde`) | toml-rs | — |
| tracing / tracing-subscriber | 0.1.44 / 0.3.23 | 2025-12 / 2026-03 | structured logs (`fmt` only, no `env-filter` or regex) | tokio-rs | log + env_logger |
| thiserror | 2.0.21 | 2026-09 | typed errors | dtolnay | — |
| argon2 | 0.6.0 | 2026-08 | hashing of human passwords (argon2id m=19 MiB t=2 p=1) | RustCrypto | rust-argon2 |
| getrandom | 0.4.3 | 2026-06 | kernel randomness (identities, passwords) | rust-random | rand: not needed |
| libc | 0.2.191 | 2026-10 | FreeBSD FFI in `fs/` | rust-lang | `xattr` (no descriptor-based API on FreeBSD), `extattr`, `rustix` (no extattr) |
| unicode-normalization | 0.1.26 | — | NFC of paths (`SafePath`) | unicode-rs | — |
| quick-xml | 0.42.0 | 2026-08 | parsing PROPFIND bodies (**risk area**, to fuzz) | tafia/Mingun | dav-server (see ADR-4), xml-rs |
| hmac / sha2 | 0.13.0 / 0.11.1 | 2026-03 / 2026-10 | app password digests; file ETag | RustCrypto (share `digest` with argon2) | ring |
| base64ct | 1.8.3 | 2026-01 | decoding the Basic header (constant time) | RustCrypto (already pulled by argon2) | base64 |
| httpdate | 1.0.3 | 2023-08 | HTTP dates (`getlastmodified`, `Last-Modified`); old but complete, already pulled by hyper | pyfisch | — |
| futures-util | 0.3.34 | 2026-11 | response streams (`unfold`, `chain`); already pulled by axum | rust-lang | tokio-stream |
| percent-encoding | 2.3.2 | — | form decoding, `href` encoding; already pulled by axum | servo | — |
| sha1 | 0.11.0 | 2026-07 | `OC-Checksum` sums (checked on upload, `oc:checksums`) | RustCrypto (same `digest`) | — |
| hyper / hyper-util | 1.12 / 0.1.21 | 2026-10 | accept loop: header timeout, connection limit, bounded shutdown (already pulled by axum); `client` added for the OIDC back channel | hyperium | `axum::serve` (exposes none of these settings) |
| tower-service | 0.3 | — | calling the axum router from the accept loop (already pulled by axum) | tower-rs | — |
| askama | 0.16.1 | 2026-09 | HTML templates of the web interface (J3), automatic escaping at compile time | askama-rs | maud (last release 2025-02, 9 M downloads: less solid) |
| jpeg-decoder | 0.3.2 | 2025-06 | client thumbnails: JPEG decoded at 1/2, 1/4 or 1/8 of the size (scaled IDCT); `platform_independent` = `forbid(unsafe_code)`, no dependency; maintenance mode but 99 M downloads | image-rs | `image` (pulls zune-jpeg with SIMD `unsafe`, no scaled decoding: 36 MB for a 12 Mpx photo); zune-jpeg alone (same) |
| jpeg-encoder | 0.7.1 | 2026-07 | client thumbnails: writing the JPEG; without `simd` = `forbid(unsafe_code)`, no dependency; the JPEG encoder of `image` | vstroebel | — |
| pulldown-cmark | 0.13.6 | 2026-10 | Markdown preview (§8.7), no options; raw HTML and non-http(s)/mailto links dropped by Beastbox | raphlinus | + ammonia (~20 crates of html5ever): rejected, CSP and filtering are enough |
| qrcode | 0.14.1 | 2024 | QR code to connect the mobile app (account page), drawn as inline SVG; without default features (`svg` only): no dependency, no `unsafe` (checked) | kennytm | fast_qr (younger, less used) |
| crc32fast | 1.5.5 | 2026-11 | CRC-32 of ZIP archives (streamed folder download, §8.3) | srijs | `zip` crate (heavier, poorly suited to streaming) |
| rustls | 0.23.46 | — | TLS client of the OIDC back channel (token endpoint), `ring` provider, `std`, `tls12` | rustls-org | OpenSSL bindings (not in the base system, C build), `ureq` (own stack) |
| tokio-rustls | 0.26.6 | — | that TLS stack on tokio | rustls-org | handling `TlsStream` by hand |
| rustls-pki-types | 1.16 | — | certificate and key types of rustls; `std` reads the CA file | rustls-org | webpki-roots (the configured CA file replaces it) |
| serde_json | 1.0.154 | — | **risk area**: provider discovery document and `id_token` payload (size-bounded before parsing, fuzzed) | dtolnay | simd-json (`unsafe`), `json` (unmaintained) |
| subtle | 2.6.1 | — | constant-time comparison of `state` and `nonce` | dalek-cryptography | a hand-written compare (optimized away) |
| http-body-util | 0.1.5 | — | collecting the bounded response body of the back channel (already in the tree through axum) | hyperium | matching `Frame` by hand |
| bytes | 1.12.1 | — | buffers of that exchange (already in the tree through axum/hyper) | tokio-rs | `Vec<u8>` copies |
| tempfile (dev) | 3.27 | — | test folders | Stebalien | — |
| tower (dev) | 0.5 | 2026-01 | `oneshot` in HTTP tests | tower-rs | — |
| proptest (dev) | 1.12 | 2026 | model-based WebDAV test (`dav::model`): random operation sequences, shrunk to the shortest failing one; without default features | proptest-rs | quickcheck (no shrinking of structured sequences as good) |

## Supply chain gates (every commit, `scripts/check.sh`)
- `cargo deny`: RustSec advisories (yanked refused), licence allowlist, crates.io only, no wildcard, **no second version
  of a crate** except the two listed in `deny.toml` (`getrandom` 0.2 from `ring`, `syn` 2 from `tracing-attributes`).
- `cargo machete`: no declared dependency left unused (main crate and `fuzz/`).
- `cargo vet --locked` (`supply-chain/`): every crate is audited by an imported party (Bytecode Alliance, Google, ISRG,
  Mozilla, Zcash) or exempted. Baseline 2026-11-20: 29 audited, 118 exempted. A new crate or version fails until it is
  audited (`cargo vet certify`, after reading the diff: `cargo vet diff`) or exempted with the owner's decision;
  `cargo vet regenerate imports` (network) refreshes the imported audits, `cargo vet prune` drops what they now cover.
- `cargo geiger`: the crates whose code uses `unsafe`, or that geiger cannot read, must be listed in
  `docs/dev/unsafe-crates.txt` (baseline 2026-11-20: 80). A new one is a review, not an update that slips through.

## Assets (not crates)
- `/static/icons/g-*.svg` (the file-type icons, every view: `X.svg` is served from `g-X.svg`) are derived from **Tabler Icons**, MIT licence
  (https://github.com/tabler/tabler-icons): the geometry is kept, the stroke colour is replaced by one colour per file
  type (`render::icon`); `md` and `json` reuse the text/code shapes with their own colour. `static/icons/NOTICE` carries the attribution. Everything else in `/static` is original.

## Decisions (short ADRs)

**ADR-1 — No IDNA crate.** Problem: normalizing IDN host names (§4.1). `idna` pulls in ICU4X (dozens of crates).
Choice: refuse any non-ASCII name; HTTP clients send A-labels (punycode) and the config must spell them that way.
Risk: an administrator must write `xn--…` in the config. Reversible.

**ADR-2 — xattr and openat through `libc` directly.** `xattr` goes through paths (unusable under Capsicum); `extattr` (1.0.0) is
little used. Choice: a minimal wrapper in `fs/` (`extattr_{get,set,delete,list}_fd`, `openat` with `O_RESOLVE_BENEATH`,
`renameat`, `fdopendir`), each `unsafe` block commented and covered by the `fs/` tests.

**ADR-3 — "Registrable domain" wildcard without the Public Suffix List.** Rule: at least two labels after `*.`. Refuses `*.fr`,
`*`, wrongly accepts `*.co.uk`. Switch to the PSL if a tenant needs it.

**ADR-4 — Hand-written WebDAV, not `dav-server`.** We need persistent folder ETags (xattr), `oc:`/`nc:` properties, refusal of
`Depth: infinity`, hidden reserved names and bounded streamed responses. Read-side PROPFIND/GET is ~300 lines on `quick-xml`
and `hyper`. Risk: WebDAV compliance to check with `litmus` (J2, once writes are in place).

**ADR-5 — OIDC client: rustls and verified TLS, no JWT signature library (decided by the owner, 2026-11-18).** The `id_token` comes
directly from the token endpoint over verified TLS (OIDC Core §3.1.3.7). Choice: `rustls` + `ring` + `tokio-rustls` + `serde_json`
(+13 crates). `ISC` is allowed only as a per-crate exception for `ring`, `rustls-webpki` and `untrusted`. Rejected: `openidconnect` (+93,
fails `cargo deny`), `jsonwebtoken` 11 (fails `cargo deny`), `jsonwebtoken` 12 (+29 on top of TLS, very recent). Design:
`oidc-proposal.md`. Measured at implementation (2026-11-18, `cargo tree -e normal,no-proc-macro --target x86_64-unknown-freebsd`):
**99 runtime crates**, `cargo deny check` green (advisories, bans, licences, sources); only new duplicate entry: `getrandom` 0.2
(through `ring`) beside 0.4, warned by `multiple-versions = "warn"`. One deliberate deviation from OIDC Core: `iat` is
**optional** in the `id_token` (the core makes it required); a token without it is accepted, `exp` still bounds its life.
Recorded here (audit 2026-11-18, gap 6) so the choice is explicit, not an oversight.

**ADR-6 — Capsicum exception for OIDC (decided by the owner, 2026-11-18).** Capability mode forbids outgoing connections. Choice: one Casper
`system.net` service, limited to the configured destinations, FFI in `src/fs/`, started only when a tenant has OIDC, with a startup check
that its limits are the ones set. Nothing to install: libcasper ships in the base system and forks the service itself (no
`casperd` daemon since 13.x). Requires a system whose `system.net` has the destination limits (15.0-p9+, measured on 15.1). Risk: the service runs outside Beastbox under the same
user, so a flaw reachable through its channel could allow an escape from capability mode.

**OIDC milestone (decided by the owner, 2026-11-18).** J5 item, implementation may start before the rest of J5. Human security review done by the
owner (2026-11-20): allowed in production.

## Crate cap (§0.3) — decided: 100 (2026-11-18)
**2026-11-18**: cap raised from 85 to **100** by the owner for OIDC. Measured before the feature: **86 runtime crates** (FreeBSD target).
With the OIDC dependencies in place (end of phase 1): **99 runtime crates**, `cargo deny check` green. The earlier figures below are history.

### Earlier decision: 85 (2026-11-15)
`cargo tree -e normal,no-proc-macro`: **83 runtime crates** at J2 (82 at J1, 78 at J0). Cap raised from 60 to **85** by the
owner after an audit (2026-11-15): every crate exceeds 170 M downloads, comes from identified organizations (RustCrypto 16,
tokio-rs 9, rust-lang 7, hyperium 6, toml-rs, tower-rs, clap-rs, serde-rs, rusqlite…), no RustSec advisory, no yanked
version. 12 crates with no release in over 12 months: small, stable and complete building blocks (`httpdate`, `httparse`,
`percent-encoding`, `tower-service`, `tower-layer`, `atomic-waker`, `sync_wrapper`, `sharded-slab`, `fallible-iterator`,
`fallible-streaming-iterator`, `foldhash`, `nu-ansi-term`). Going below 60 would mean rewriting HTTP or cryptography
(forbidden by §9). Risk areas (network input): `hyper`/`httparse`, `quick-xml` (fuzzing required), and SQLite's C
(`libsqlite3-sys`, parameterized queries only).

**J3 (2026-11-15)**: `clap` removed (replaced by a ~90-line argument parser, tested), in favor of `askama`, `pulldown-cmark`
and `crc32fast`: **83 runtime crates**, under the cap of 85. Owner's choice.

## Milestone checks
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`: green. `cargo audit`: no advisory (RustSec
database, 1,509 advisories, 2026-11-14). `cargo deny check`: advisories, bans, licenses and sources OK (`deny.toml`: FreeBSD
target, MIT/Apache-2.0/BSD-3-Clause/Unicode-3.0/Unlicense/Zlib licenses); only warning: `syn` 2 and 3 duplicated
(proc-macros, build time only).
