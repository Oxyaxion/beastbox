#!/bin/sh
# Every gate a change must pass (docs/dev/TESTING.md). Same script for a developer and for CI.
#   scripts/check.sh           quick gates: format, lint, licenses, unused deps, supply chain, unsafe crates, tests,
#                              coverage floors (a few minutes)
#   scripts/check.sh --long    + long property runs, fuzz (http 10 min on 3 workers, others 60 s), litmus, mutation testing
#   scripts/check.sh --mutants mutation testing only (the diff since the last tag)
# Exit status 0 = every gate passed. Run from the repository root, on FreeBSD (xattrs, Capsicum, ZFS).
set -eu
long=${1:-}
step() { printf '\n== %s (%s)\n' "$*" "$(date +%H:%M:%S)"; }

# Mutation testing, alone with --mutants (after a failed campaign: a new test or an accepted survivor checked in
# ~20 min, before the whole campaign again).
mutation_step() {
    step "mutation testing of the core changed since the last tag (not page rendering)"
    # scripts/release.sh sends the diff computed where the code is committed (on the bench host, new files are untracked).
    [ -n "${BEASTBOX_COMMIT:-}" ] || git diff "$(git describe --tags --abbrev=0)" -- src > target/changes.diff
    rm -rf target/mutants-release target/mutants-cli
    # Each copy builds in its own target (a shared CARGO_TARGET_DIR would make the parallel copies wait on each other).
    # The test VM frees its RAM disk first (BEASTBOX_RAM_TARGET: the target dir of the steps above).
    # The trim gives the freed pages back to the RAM disk now, before the copies are written (scripts/vm.sh, ram).
    if [ -n "${BEASTBOX_RAM_TARGET:-}" ]; then
        rm -rf "${BEASTBOX_RAM_TARGET:?}"/*
        doas zpool trim -w "$(zfs list -H -o name "$BEASTBOX_RAM_TARGET" | cut -d/ -f1)"
    fi
    # The fuzz harnesses are not built by the tests: nothing could catch their mutants. Their exit status says "some
    # survived": judged below instead, survivor by survivor.
    # A stall (a frozen copy, a hung child) fails after BEASTBOX_MUTANTS_TIMEOUT, instead of holding the run to its end.
    mutants() {
        s=0
        env -u CARGO_TARGET_DIR TMPDIR="${BEASTBOX_MUTANTS_TMP:-${TMPDIR:-/tmp}}" timeout "${BEASTBOX_MUTANTS_TIMEOUT:-90m}" \
            cargo mutants --in-diff target/changes.diff --exclude-re 'fuzz(::|_)' "$@" || s=$?
        [ "$s" != 124 ] || { echo "mutants: stopped after ${BEASTBOX_MUTANTS_TIMEOUT:-90m} (timeout)"; exit 1; }
    }
    mutants -e src/web/mod.rs -e src/web/render.rs -e src/main.rs -j "${BEASTBOX_MUTANTS_JOBS:-2}" \
        -o target/mutants-release -- --lib
    # The binary is held by its own tests and tests/cli.rs (one at a time: they share the CI datasets).
    mutants -f src/main.rs -j 1 -o target/mutants-cli -- --bins --test cli
    python3 - <<'EOF'
import json, pathlib, re, sys
# A survivor is a missing test, unless accepted as equivalent, with its reason, in docs/dev/mutants-accepted.txt
# ("file: change  # why", without line and column).
ok = {l.split("  #")[0].strip() for l in pathlib.Path("docs/dev/mutants-accepted.txt").read_text().splitlines()
      if l.strip() and not l.startswith("#")}
bad = []
for d in ("target/mutants-release", "target/mutants-cli"):
    f = pathlib.Path(d, "mutants.out/outcomes.json")
    if not f.exists():  # no mutant in the diff for this run
        continue
    for o in json.loads(f.read_text())["outcomes"]:
        sc = o.get("scenario")
        if o["summary"] == "MissedMutant" and isinstance(sc, dict) and "Mutant" in sc:
            n = sc["Mutant"]["name"]
            if re.sub(r":\d+:\d+:", ":", n, count=1) not in ok:
                bad.append(n)
        # A build or test killed by a signal (the OOM killer) or an unclassified failure tested nothing: a missing result,
        # never a pass (0.15.0: 19 of 29 mutants "unviable" were rustc killed for memory).
        # cargo reports a rustc killed by a signal as its own exit 101: the log says it.
        log = pathlib.Path(d, "mutants.out", o.get("log_path") or "-")
        killed = any("Signalled" in r.get("process_status", {}) for r in o.get("phase_results", [])) or (
            o["summary"] == "Unviable" and log.is_file() and "(signal: " in log.read_text(errors="replace"))
        if o["summary"] == "Failure" or killed:
            bad.append(f"{sc['Mutant']['name'] if isinstance(sc, dict) and 'Mutant' in sc else sc}: not tested ({o['summary']}, see {d}/mutants.out/{o.get('log_path')})")
print("\n".join(["unexplained survivors or mutants not tested (add a test, accept with a reason, or rerun):"] + bad)
      if bad else "no unexplained survivor, every mutant tested")
sys.exit(1 if bad else 0)
EOF
}
if [ "$long" = "--mutants" ]; then
    mutation_step
    step "mutation testing passed"
    exit 0
fi

step "format"
cargo fmt --check
step "lint (warnings are errors), with and without fuzzing"
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features fuzzing -- -D warnings
step "licenses, advisories, sources, duplicates"
cargo deny check
step "unused dependencies"
cargo machete
(cd fuzz && cargo machete)
step "supply chain: every crate audited by a trusted party or explicitly exempted (supply-chain/)"
cargo vet --locked
step "unsafe in the dependencies: only the crates listed in docs/dev/unsafe-crates.txt"
cargo geiger --output-format Json > target/geiger.json 2> target/geiger.log
python3 - <<'EOF'
import json, pathlib, re, sys
# A crate whose code uses `unsafe` (or that geiger could not read) must be listed, with its reason: a new one is a
# decision, not an update that slips through (docs/dev/DEPS.md).
listed = {l.split("#")[0].strip() for l in pathlib.Path("docs/dev/unsafe-crates.txt").read_text().splitlines()
          if l.strip() and not l.startswith("#")}
d = json.load(open("target/geiger.json"))
found = {p["package"]["id"]["name"] for p in d["packages"]
         if any(v["unsafe_"] for v in p["unsafety"]["used"].values())}
for f in d["used_but_not_scanned_files"]:
    m = re.search(r"/registry/src/[^/]+/(.+?)-\d+\.\d+[^/]*/", f)
    if m:
        found.add(m.group(1))
new = sorted(found - listed)
print("\n".join(["crates using unsafe, not listed (review, then add to docs/dev/unsafe-crates.txt):"] + new)
      if new else f"ok ({len(found)} crates with unsafe, all listed)")
sys.exit(1 if new else 0)
EOF
step "tests"
cargo test 2>&1 | tee target/test-output.txt
# The pipe hides cargo's exit status (and `set -e` ignores `!`): judge the output.
if grep -q 'test result: FAILED' target/test-output.txt || ! grep -q 'test result: ok' target/test-output.txt; then
    echo "tests failed"; exit 1
fi
step "every test the report names exists (security rules, models)"
python3 scripts/bench-report.py check-names
step "JavaScript rules (optional: skipped without node)"
if command -v node >/dev/null 2>&1; then
    node --test 'tests/js/*.test.mjs'
else
    echo "node not installed: skipped"
fi
step "fuzz harnesses replay their corpus seeds (a harness that panics on its own input, not in the code)"
cargo test --features fuzzing --lib -- fuzz_seeds 2>&1 | tee target/fuzz-seeds.txt
if grep -q 'test result: FAILED' target/fuzz-seeds.txt; then
    echo "fuzz seeds failed"; exit 1
fi

step "coverage floors of the security modules (never lower; raise them as tests are added)"
# The product only: the files made of tests would raise the figure by being run, and `isolation` cannot run under
# `cargo test` (cap_enter is irreversible). `casper` is measured: the service opens without any daemon and its
# allowlist is exercised against the real thing in the test VM.
cargo llvm-cov --lib --json --summary-only --ignore-filename-regex 'src/(main|.*/(audit|model|isolation|tests(_[a-z]+)?))\.rs$' > target/coverage.json
python3 - <<'EOF'
import json, sys
# Regions covered, in percent: the level reached, rounded down, with a point of margin when it sits on the integer
# (the figure moves by a few tenths from one machine or run to another). A change may only keep or raise them.
FLOORS = {
    "auth/mod.rs": 96, "auth/oidc.rs": 98, "auth/oidc_net.rs": 82, "auth/totp.rs": 97, "tenant/mod.rs": 96,
    "fs/safepath.rs": 100, "fs/write.rs": 93, "fs/mod.rs": 91, "fs/trash.rs": 92, "fs/casper.rs": 87,
    "web/share.rs": 93,
    "nc/share.rs": 94, "db/mod.rs": 91, "etag/mod.rs": 100, "config.rs": 99, "dav/upload.rs": 89,
    "dav/trashbin.rs": 93, "dav/search.rs": 94, "admin/mod.rs": 89, "web/mod.rs": 95, "web/oidc.rs": 95,
    "http.rs": 94, "dav/mod.rs": 94, "dav/write.rs": 94, "nc/mod.rs": 93,
}
TOTAL = 94.5
TOTAL_LINES = 96.5
cov = json.load(open("target/coverage.json"))["data"][0]
got = {f["filename"].split("/src/", 1)[1]: f["summary"]["regions"]["percent"] for f in cov["files"]}
bad = [f"{m}: {got.get(m, 0):.1f} % < {floor} %" for m, floor in FLOORS.items() if got.get(m, 0) < floor]
total, lines = cov["totals"]["regions"]["percent"], cov["totals"]["lines"]["percent"]
if total < TOTAL:
    bad.append(f"total: {total:.1f} % < {TOTAL} %")
if lines < TOTAL_LINES:
    bad.append(f"total lines: {lines:.1f} % < {TOTAL_LINES} %")
print("\n".join(bad) if bad else f"ok (regions {total:.1f} %, lines {lines:.1f} %)")
sys.exit(1 if bad else 0)
EOF

if [ "$long" = "--long" ]; then
    step "long property runs (3,000 scenarios each)"
    PROPTEST_CASES=3000 cargo test --lib -- _the_model alpha_never_touches_beta login_return qr_login \
        identity_and_etag_follow_the_content restore_never_touches_the_current_tree \
        restored_name_is_legal_and_keeps_the_extension glob_is_the_recursive_definition the_page_chosen_holds_the_item \
        copy_names_are_new_and_legal alice_never_touches_bob weakness_is_monotonic must_change_follows_who_set_the_password \
        second_step_model a_code_is_accepted_once
    step "fuzz: http 10 minutes on 3 workers, the others 60 s each"
    # The whole HTTP surface is slow per input (router, SQLite, disk): 10 minutes on 3 workers (TESTING.md); the
    # parsers 60 s each. -jobs/-workers, not -fork (it hangs on FreeBSD); the workers write fuzz-N.log.
    for t in http propfind proppatch search headers query manifest thumb restore oidc_url oidc_provider; do
        rm -f fuzz-*.log
        if [ "$t" = http ]; then
            cargo +nightly fuzz run http -- -timeout=10 -max_total_time=600 -jobs=3 -workers=3 > target/fuzz-http.log 2>&1 || true
            cat fuzz-*.log >> target/fuzz-http.log
        else
            cargo +nightly fuzz run "$t" -- -timeout=10 -max_total_time=60 > "target/fuzz-$t.log" 2>&1 || true
        fi
        rm -f fuzz-*.log
        # The log is kept for `bench-report.py record-fuzz` (scripts/release.sh).
        if grep -qE 'Test unit written to .*/(crash|timeout|oom)-|ERROR: libFuzzer' "target/fuzz-$t.log"; then
            echo "fuzz $t: crash (target/fuzz-$t.log)"; exit 1
        fi
        grep -h '^Done ' "target/fuzz-$t.log" || { echo "fuzz $t: no run"; exit 1; }
    done
    step "WebDAV compliance: litmus against a server of this code, started here (under a minute)"
    # A temporary server on the CI datasets (TESTING.md): tenant alpha, account carol (a real dataset, as user add wants).
    # Its app password is obtained as a user would: sign-in, the welcome page (password set by the administrator),
    # sign-in again, account page; so this also walks the first sign-in end to end.
    ci=${BEASTBOX_CI_ROOT:-/var/tmp/beastbox-ci}
    cargo build --locked -q
    bin=${CARGO_TARGET_DIR:-target}/debug/beastbox
    lt=$(mktemp -d)
    find "$ci/alpha/carol" -mindepth 1 -delete
    printf 'listen = "127.0.0.1:18080"\ntrusted_proxies = ["127.0.0.1"]\nstate_dir = "%s"\nlog_level = "warn"\ninsecure_cookies = true\n[[tenant]]\nname = "alpha"\nhosts = ["localhost"]\ndata_root = "%s/alpha"\n' \
        "$lt" "$ci" > "$lt/b.toml"
    pw=$("$bin" -c "$lt/b.toml" user add --tenant alpha carol | awk '{print $NF}')
    "$bin" -c "$lt/b.toml" serve > target/litmus-server.log 2>&1 &
    srv=$!
    trap 'kill $srv 2>/dev/null' EXIT
    web() { curl -sf -c "$lt/jar" -b "$lt/jar" "$@"; }
    csrf() { web "http://localhost:18080$1" | grep -oE 'name="csrf" value="[0-9a-f]+"' | head -1 | cut -d'"' -f4; }
    i=0; until web -o /dev/null http://localhost:18080/status.php; do i=$((i + 1)); [ $i -lt 30 ] || { echo "server down"; exit 1; }; sleep 1; done
    new=litmus-pass-$$-ok
    web -o /dev/null --data-urlencode user=carol --data-urlencode "password=$pw" http://localhost:18080/login
    c=$(csrf /web/welcome)
    web -o /dev/null --data-urlencode "csrf=$c" --data-urlencode "current=$pw" --data-urlencode "new=$new" \
        --data-urlencode "again=$new" http://localhost:18080/web/welcome
    web -o /dev/null --data-urlencode user=carol --data-urlencode "password=$new" http://localhost:18080/login
    c=$(csrf /web/account)
    # A new app password asks the password again (`web::Reproof`), as for a person.
    token=$(web --data-urlencode "csrf=$c" --data-urlencode label=litmus --data-urlencode "password=$new" \
        http://localhost:18080/web/account/tokens |
        grep -oE '<code>[0-9a-f]{64}</code>' | grep -oE '[0-9a-f]{64}')
    [ -n "$token" ] || { echo "no app password for litmus (first sign-in failed, see target/litmus-server.log)"; exit 1; }
    # No proxy: litmus opens its own connections to the URL's host (expect100), so the host must resolve.
    litmus -k http://localhost:18080/remote.php/dav/files/carol/ carol "$token" \
        > target/litmus.txt 2>&1 || true
    kill $srv; trap - EXIT; rm -rf "$lt"
    # Expected: everything passes but 3 props tests (no free-form properties: only oc:favorite, by design).
    got=$(awk '/^<- summary for/ { n = $4; gsub(/[^a-z]/, "", n); printf "%s %s/%s ", n, $9, $6 }' target/litmus.txt)
    got="$got$(grep -oE '[a-z_]+\.+ FAIL' target/litmus.txt | sed 's/\.* FAIL//' | sort -u | tr '\n' ' ')"
    want="basic 16/16 copymove 13/13 props 11/14 locks 3/3 http 4/4 propget propmanyns propset "
    echo "$got"
    if [ "$got" != "$want" ]; then
        echo "litmus differs from the expected result: $want"; exit 1
    fi
    mutation_step
fi
step "all gates passed"
