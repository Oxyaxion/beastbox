# Working on Beastbox

Rules for anyone (people and coding agents) changing this repository. The owner speaks French: answer in French; code,
comments, commits and docs stay in English.

## Read first
- `docs/dev/beastbox-plan.md` (the plan; when a request contradicts it, say so and let the owner decide),
  `docs/dev/TESTING.md` (testing policy and commands), `docs/dev/SURFACE.md` (attack surface), `docs/dev/VALIDATION.md`
  (results). Docs: `docs/admin/` is short (commands and one line each), `docs/dev/` holds the rest; no long prose.

## Code
- Smallest complete change; reuse what exists. `unsafe` only in `src/fs/`; clippy denies `unwrap`, `expect`, `panic`,
  indexing; no global state in `src/` (audited by a test).
- Format only the files you touched (`rustfmt --edition 2024 <file>`), or a separate formatting-only commit.
- New dependency: well-known crates only, checked for `unsafe` and dependencies, listed in `docs/dev/DEPS.md`, `cargo deny`
  green.

## Tests (paranoid, security first: `docs/dev/TESTING.md`)
- Every change ships with unit tests (boundaries: at, below, above), end-to-end tests through the router (refusals, other
  user, **other tenant**), a `proptest` test for any rule or state, and a fuzz target for any new parser of client input;
  every defect found leaves a regression test.
- Test fixtures use reserved names only: tenants `alpha`/`beta`, hosts `*.example` / `*.test`; never the owner's real
  domains or tenant names.
- Before a release: `scripts/release.sh X.Y.Z` (runs `scripts/vm.sh ci --long` in a throwaway VM, deploys the binary
  built there on the bench, records the runs, writes the test report; commits and tags only if every gate passed).
  **The heavy chain (tests, fuzz, mutants, long property runs) runs in the VM only** — the bench host only hosts the bench, it is
  never used to compile or measure. Long campaigns are announced with their expected duration **before** starting, run
  one at a time, and their filters checked first (`cargo test -- --list`); reuse results instead of rerunning
  (`scripts/release.sh X.Y.Z --reuse`).
- Each commit: `cargo clippy --all-targets` and `cargo test` only. Long campaigns run once, just before a tag, on the
  diff since the last tag.
- Mutation testing before a tag, on the core only (`-e src/web/mod.rs -e src/web/render.rs`: page rendering is held by end to
  end tests and the audit): `cargo mutants --in-diff <diff since last tag> -j 2 -o <dir>` (~1 min per mutant), then only the
  survivors again: `--iterate -o <same dir>`. A survivor is a missing test, a rule written twice, or equivalent (say why
  in `VALIDATION.md`). Survivors in fuzz harnesses (`#[cfg(feature = "fuzzing")]`) are expected.
- A test must reach the path it targets: a mutant that survives a new test often means an earlier step failed first
  (check by applying the mutant by hand).
- Front end: security by the audit, the CSP and server-side checks; JavaScript rules by behavior (`node --test`); layout
  by the owner's preview. No test that matches CSS or JS text.

## Build and bench from Linux
- Cross build: `source ~/.local/opt/freebsd-cross/env.sh`, then `cargo clippy --all-targets` / `cargo test --no-run`.
- Tests and campaigns run in the local CI: a throwaway FreeBSD VM started clean for each run (`scripts/vm.sh ci`,
  `ci --long`; `docs/dev/TESTING.md`, "Local CI"). The bench host stays the reference for performance and the test bench.
- Machines, addresses and test bench: `CLAUDE.local.md` (not tracked; the scripts read `scripts/local.env`).

## Web interface
- Server-rendered HTML (askama) and native elements (`<details>`, `popover`, `<dialog>`); JavaScript only where nothing
  native does it. Strict CSP: no inline script, style or handler (the front-end audit test enforces it).
- Any visible change: show the owner a preview built from the real rendered templates (with the real CSS) and wait for
  approval before committing or deploying. Keep sizes moderate and spacing generous.

## Releases and deployment
- One release = an entry at the top of `CHANGELOG.md` (Before upgrading, Changed, Added, Fixed, Security, Tests), the
  version in `Cargo.toml` (and both `Cargo.lock`), an annotated tag `vX.Y.Z` repeating the entry. Push only when asked.
- Test bench: see `CLAUDE.local.md`. Never pipe `bastille service … start` (daemon(8) keeps the pipe open and the
  command hangs); start it, then check with `curl`.
