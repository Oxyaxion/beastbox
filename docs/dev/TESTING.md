# Testing policy and how to run it

Stance, as SQLite's: tests are the product's proof. Every branch that matters is run by a test, every defect found leaves
a test that reproduces it, and a feature without its tests is not finished. Tests are **security-first** (plan §0.3, §4.1,
§10): before "does it work", "can it be abused, can it leak, can it lose data". Results go to `VALIDATION.md`; this file
says what is required and how to run it.

## What every change ships with

| Layer | Required | Where |
|---|---|---|
| Unit | the logic, its limits (at, below, above every bound) and its refusals | next to the code (`#[cfg(test)]`) |
| End to end | through the real router: success, refusal, **other user and other tenant**, read-only mode, hostile input | `src/http.rs`, `src/web/tests.rs` |
| Property (`proptest`) | the feature's rules as properties; a **model-based test** for anything with state | `dav::model`, `nc::share_model` |
| Fuzzing | a target for every parser of client input; new routes added to the `http` target | `fuzz/fuzz_targets/` |
| Regression | every defect: the crashing input kept in the corpus and a unit test | corpus `regress-*`, tests named after the defect |
| Front end | every page rendered and audited (HTML, CSP, CSRF, labels, unused CSS, dangerous JS); a new page is added to the audit. JavaScript rules tested by behavior (`node --test`); layout checked on the owner's preview, never by tests matching CSS or JS text | `web::audit`, `tests/js/` |
| Docs | `SURFACE.md` for any new surface; `VALIDATION.md` with the numbers; `CHANGELOG.md` | `docs/dev/` |

## Security checks every relevant test covers (plan §10)

- **Isolation**: the same action from the other tenant's user, by path, `fileid`, token, session, link token, `Host`.
- **Authentication**: no credentials, wrong ones, the human password where an app password is expected, a session where
  an app password is expected and the reverse, an expired or revoked credential.
- **Traversal and names**: `..`, `%2e%2e`, double encoding, NUL, `\`, reserved names, outgoing symlinks, Unicode forms.
- **Limits and denial of service**: sizes, counts, slow bodies, concurrency caps, `Depth`, huge headers.
- **Durability**: a failure in the middle never leaves a mixed file, a lost identity or a stale ETag.
- **Output**: what a user wrote is escaped in HTML, XML and JSON; nothing from a client reaches a header unchecked.

## Commands

```sh
cargo test                                         # everything, 48 model sequences each (a few minutes)
PROPTEST_CASES=3000 cargo test --lib -- _the_model alpha_never_touches_beta login_return qr_login \
  identity_and_etag_follow_the_content restore_never_touches_the_current_tree   # long property runs, before a release
cargo +nightly fuzz run http -- -timeout=10 -max_total_time=600 -jobs=3 -workers=3
cargo +nightly fuzz cmin http                      # then put back the regress-* inputs cmin dropped
cargo llvm-cov --lib --html                        # coverage, report in target/llvm-cov/html/index.html
cargo llvm-cov --lib --summary-only                # coverage per file, in the terminal
# Floors and report count the product only: --ignore-filename-regex 'src/(main|.*/(audit|model|isolation|tests(_[a-z]+)?))\.rs$'
cargo mutants --in-place -f src/fs/write.rs        # mutation testing of one file (long: one test run per mutant)
node --test 'tests/js/*.test.mjs'                  # rules of static/app.js without a browser (optional: needs node)
```

Tools (developer machine only, never in the product; pinned in `scripts/vm.sh`): `cargo-machete` 0.9.1, `cargo-vet` 0.10.3,
`cargo-geiger` 0.13.0 (the newest releases need a newer rustc than 1.95), `cargo-fuzz` (nightly), `cargo-llvm-cov` 0.9.1 with the
`llvm-tools` component, `cargo-mutants` 27.1.0, optionally `node` (JavaScript rules; `check.sh` skips them without it). Fuzzing: `-jobs`/`-workers`, not `-j` (fork mode hangs on FreeBSD), and
always `-timeout=10` (the default of 20 minutes per input hides a hang).

## How much, when

| When | What | Time |
|---|---|---|
| Every commit | `scripts/check.sh`: format, lint, `cargo deny` (licenses, advisories, sources, no new duplicate), `cargo machete` (unused dependencies), `cargo vet --locked` (supply chain), `cargo geiger` (crates using `unsafe` ⊆ `unsafe-crates.txt`), every test (32 to 48 property scenarios per model), coverage floors | 3–5 min |
| Every release | `scripts/vm.sh ci --long` in the throwaway VM (nothing is compiled or measured on the bench host, it hosts the bench): + long property runs, fuzz 60 s per target, `litmus` against a server of the code started inside the VM, mutation testing of the **core** changed since the last tag (not page rendering: `web/mod.rs`, `web/render.rs`, held by end to end tests and the audit), and the release binary the bench then runs | a few hours |
| Now and then, overnight | long fuzz of every target, mutation testing of whole modules; then `scripts/bench-report.py record-…` | idle machine |

The test report is versioned: at each tag, after `scripts/vm.sh ci --long` (results and run records copied back from the VM):
`bench-report.py report --reuse`, `bench-report.py snapshot` (→ `docs/bench/vX.Y.Z.json`, committed with the release),
`bench-report.py site` (one page per version, `index.html` = the latest), and when the owner asks for it,
`scripts/report-pages.sh` → https://modulus.codeberg.page/beastbox/ (the `pages` branch, one commit, pushed by force). Weights of the "not tested yet" items (`[Before production]`, `[Important]`, `[Minor]`) are the owner's.

## Local CI: a throwaway FreeBSD VM (`scripts/vm.sh`)

The code is FreeBSD-only (ZFS xattrs, Capsicum, `openat`): its tests cannot run on the Linux workstation. They run in a
FreeBSD VM on that workstation (QEMU/KVM, no display), **started clean for every run**, so a result never depends on what
a previous run left behind.

- **Golden image**, built once by `scripts/vm.sh create` (~20-30 min): the official FreeBSD 15.1 cloud-init image
  (checked against `CHECKSUM.SHA256`), configured at its first boot (user `dev`, its own SSH key, `doas`), Rust stable
  and nightly, the tool versions of the bench host (cargo-mutants, cargo-llvm-cov, cargo-deny, cargo-fuzz), `litmus`, the
  dependencies already fetched, a ZFS pool `ztest` on a second disk with the CLI test datasets. Then frozen, read-only.
  Rebuilt only for a new FreeBSD, Rust or tool version (`scripts/vm.sh rebuild`); the downloaded image is then deleted.
- **One run = one throwaway VM**: two qcow2 overlays on the golden disks (created in a fraction of a second), boot
  (~30 s), sources synced, `scripts/check.sh` or `check.sh --long`, results copied back to `target/`, VM stopped,
  overlays deleted. The golden image is never written.
- **Where things are written**: the tests' files on the ZFS disk (`ztest/tmp`, `xattr=sa`, as in production) and the
  CLI datasets beside them; the builds and the mutants' copies (the whole project rebuilt per copy: gigabytes) in
  `/ram`, a ZFS pool in RAM of fixed size (10 GiB), so they never reach the workstation's SSD and cannot grow past it.
  The ZFS cache of the VM is capped at 1 GiB; `ztest/tmp` has `sync=disabled` (an fsync once hung in the VM; no test
  checks durability across a power loss). A run that hangs fails after `BEASTBOX_CI_TIMEOUT` (8 h). The price: the dependencies are rebuilt at each CI run (the dev VM,
  `up`/`test`, keeps its builds while it is up).
- **litmus** runs against a server of the code under test, started by `check.sh --long` itself (`localhost:18080`).
- **Size**: 8 cores, 14 GiB of RAM by default; more for a long night run (`BEASTBOX_VM_CPUS`, `BEASTBOX_VM_MEM`,
  `BEASTBOX_VM_RAMDISK`, `--jobs` for the mutants). Disk: ~8-10 GiB for the golden image, an overlay of a few tens of MiB
  while a run lasts. Files in `~/.local/share/beastbox-vm`, outside the repository.
- **The bench host** stays the reference for performance (N100, the published figures), the test bench (jail `beastbox`, for
  trying a version by hand) and hard disk measurements on the HDD host.

```sh
scripts/vm.sh create          # once: the golden image
scripts/vm.sh ci              # check.sh in a clean VM (minutes)
scripts/vm.sh ci --long       # the whole campaign, litmus included (hours: mutants)
scripts/vm.sh ci --mutants    # mutation testing alone (~25 min): a fix to a failed campaign checked before the whole one
scripts/vm.sh test            # cargo test in a dev VM, started for it and gone after it
scripts/vm.sh up | down       # keep the dev VM (and its builds) between commands
scripts/vm.sh rebuild         # a new golden image
```

No VM outlives its command, except after `up`.

## Administration CLI (`tests/cli.rs`)

The real `beastbox` binary, a real configuration, two tenants: exit code, output and effect of every command. The binary
refuses two tenants on one dataset and a user folder that is not its own dataset, so the tests need real ZFS datasets,
created once on the bench host (their content is emptied before each test; the tests take turns):

```sh
doas zfs create -o mountpoint=/var/tmp/beastbox-ci -o xattr=sa zroot/beastbox-ci
doas zfs create zroot/beastbox-ci/alpha; doas zfs create zroot/beastbox-ci/beta; doas zfs create zroot/beastbox-ci/alpha/carol
doas chown -R "$USER" /var/tmp/beastbox-ci        # elsewhere: BEASTBOX_CI_ROOT=<mount point>
```
Cross build: copy `target/x86_64-unknown-freebsd/debug/beastbox` to the same path on the bench host with the test binary.

## Before a release

`scripts/release.sh X.Y.Z [--publish]` does all of it, in order, and tags only if every gate passed (45 to 90 min): the
CHANGELOG entry must be written first; a surviving mutant stops it unless it sits in a fuzz harness or is listed, with
its reason, in `docs/dev/mutants-accepted.txt`. Without `--publish` it prints the push and upload commands. The steps:

1. `cargo fmt`, `cargo clippy --all-targets` (and `--features fuzzing`), `cargo deny check`, `cargo test`.
2. Long property runs (3,000 sequences each).
3. `http` fuzz, 10 minutes, on the release code; any crash → fixed, input kept, rerun.
4. Coverage of the files changed: every new branch run by a test, or the reason written down.
5. Numbers in `VALIDATION.md` and `CHANGELOG.md`.

## Paranoid program (in progress)

Ordered; each step lands with its numbers in `VALIDATION.md`.
1. `http` fuzz oracle "never access without credentials": no 2xx on a protected route without valid credentials for that
   surface (app password for WebDAV/OCS/previews, session for `/web/` and `/index.php/f/`), nor with the other tenant's
   `Host`. Public: `/s/`, `/login`, `/status.php`, capabilities, Login Flow.
2. Coverage baseline per module; then 100 % of the branches of `fs/`, `auth/`, `tenant/`, links, or the reason.
3. Mutation testing baseline (`cargo mutants`), starting with `fs/`, `auth/`, `tenant/`, `web/share.rs`; every surviving
   mutant gets a test or a written reason. Done: `auth/`, `tenant/`, and the diff of manifest format 2 and `restore`.
   **Next**: why the modules under 90 % are there (regions, 2026-11-17: `dav/upload.rs` 79.6, `admin/mod.rs` 82.5,
   `config.rs` 83.3, `dav/trashbin.rs` 84.0, `dav/search.rs` 88.8, `db/mod.rs` 89.4): `cargo llvm-cov --lib --text` on
   these files, each uncovered region sorted into to test, unreachable, or system error hard to cause; then a mutation
   score per module (covered is not checked), and tests that kill no mutant of their own merged or removed.
   **Which test kills what**: run whole modules, not a diff (a test of an unmutated module would seem useless), with
   `--no-fail-fast` passed to `cargo test` (every failing test seen, not only the first binary), and keep the run's
   `mutants.out/log/`. Then `bench-report.py record-mutants` reads the failed test names in each caught mutant's log and
   records test → mutants killed; the report lists each test as killing nothing, only mutants others kill too
   (redundant), or some no other test kills (needed). Audit and isolation tests guard code not written yet (a new route,
   query or page): no mutant models it, so "kills nothing" is judged by hand there, never removed on that alone.
4. Model tests: tenant isolation (A's random operations change no byte, xattr or row of B), trash (delete, restore,
   restore onto a taken name).
5. Disk fault injection in `fs/` (test builds only): fail the Nth system call of each operation (full disk, I/O error,
   failed `fsync`) and check the old content, identities, ETags and trash.
6. Internal invariants (`debug_assert!`) after a write, an ETag propagation, a restore.
7. Front end audit (`web::audit`): every page rendered and checked (well-formed HTML, unique ids, labels, `alt`, button
   types, CSRF on every POST form, no inline script, style or handler, `rel="noopener"`, no class missing from the CSS and
   no CSS class unused, no `innerHTML`/`eval`/`document.write` in the scripts); ESLint if approved.
8. Overnight fuzz campaigns; later, differential tests against a reference Nextcloud.
