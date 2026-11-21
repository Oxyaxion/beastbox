#!/bin/sh
# A release, measured before it exists: nothing is committed or tagged unless every gate passed.
#   scripts/release.sh X.Y.Z             from the Linux machine, at the root of the repository, on main, tree clean,
#                                        with the CHANGELOG.md entry "## X.Y.Z — date" written at the top
#   scripts/release.sh X.Y.Z --publish   the same, then git push and the test report sent to the bucket
#   scripts/release.sh X.Y.Z --reuse     skip the campaign, reuse the last green one (target/ci, docs/dev/bench-runs.json)
# Steps: version in Cargo.toml and both Cargo.lock; scripts/vm.sh ci --long in a throwaway FreeBSD VM (tests, coverage
# floors, long property runs, fuzz, litmus, mutants) which also records the runs and builds the release binary;
# that binary is deployed on the test bench; the report and its snapshot docs/bench/vX.Y.Z.json; then the
# "Release X.Y.Z" commit and the annotated tag repeating the entry. Nothing is compiled or measured on the front: it
# only hosts the bench. Takes a few hours (mutants: the diff since the last tag). On failure the version change is undone.
set -eu
# Machine-specific values (bench host, jail address, test host, report remote): scripts/local.env, not tracked.
[ -f scripts/local.env ] && . scripts/local.env
v=${1:-}
publish=
reuse=
shift || true
while [ $# -gt 0 ]; do
    case $1 in
        --publish) publish=--publish ;;
        --reuse) reuse=1 ;;
        *) die "unknown option $1" ;;
    esac
    shift
done
H=${BEASTBOX_HOST:-bench}
J=${BEASTBOX_JAIL_IP:?set BEASTBOX_JAIL_IP in scripts/local.env}
TH=${BEASTBOX_TEST_HOST:-files.alpha.test}
RR=${BEASTBOX_REPORT_REMOTE:-}
R='~/git/beastbox'
die() { echo "release: $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

echo "$v" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || die "usage: scripts/release.sh X.Y.Z [--publish]"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "not on main"
[ -z "$(git status --porcelain)" ] || die "the tree is not clean"
! git rev-parse -q --verify "refs/tags/v$v" >/dev/null || die "tag v$v exists"
grep -m1 '^## ' CHANGELOG.md | grep -q "^## $v " || die "the first CHANGELOG.md entry is not \"## $v — date\""

# Undo the version change if anything below fails.
finished=0
trap '[ "$finished" = 1 ] || { git checkout -- Cargo.toml Cargo.lock fuzz/Cargo.lock 2>/dev/null; echo "release: stopped, nothing committed"; }' EXIT

step "version $v"
python3 - "$v" <<'EOF'
import pathlib, re, sys
v = sys.argv[1]
t = pathlib.Path("Cargo.toml")
t.write_text(re.sub(r'(?m)^version = "[^"]+"', f'version = "{v}"', t.read_text(), count=1))
for lock in ("Cargo.lock", "fuzz/Cargo.lock"):
    p = pathlib.Path(lock)
    p.write_text(re.sub(r'(name = "beastbox"\nversion = )"[^"]+"', rf'\1"{v}"', p.read_text()))
EOF
git diff --stat

c=$(git rev-parse --short HEAD)
if [ -z "$reuse" ]; then
    step "every gate, long campaign in a throwaway VM (nothing runs on $H)"
    scripts/vm.sh ci --long --jobs "${BEASTBOX_MUTANTS_JOBS:-2}" || die "a gate failed (see above)"
else
    step "campaign reused (target/ci, docs/dev/bench-runs.json)"
    [ -f target/ci/target/test-output.txt ] || [ -f target/ci/test-output.txt ] || die "--reuse: no result in target/ci"
    # `report` needs a FreeBSD host (`cargo test --list`): the campaign in the VM wrote it, and vm.sh copied the
    # report data back (target/bench, docs/dev/bench-runs.json).
    ls target/bench/*.json >/dev/null 2>&1 || die "--reuse: no report data in target/bench"
fi

step "release binary (built in the VM, with the version above)"
scripts/vm.sh release-binary || die "the release binary could not be built"
[ -x target/ci/beastbox ] || die "no release binary in target/ci/beastbox"
scp -q target/ci/beastbox "$H:/tmp/beastbox.new"
ssh "$H" "doas install -m 0555 -o root -g wheel /tmp/beastbox.new /usr/local/bastille/jails/beastbox/root/usr/local/bin/beastbox && rm -f /tmp/beastbox.new"
ssh "$H" "doas jexec beastbox service beastbox stop >/dev/null 2>&1 || true"
# Never pipe a daemon start: daemon(8) keeps the pipe open.
ssh "$H" "doas jexec beastbox sh -c 'nohup service beastbox start > /tmp/bb-start.log 2>&1 < /dev/null &'"
ssh "$H" "for i in 1 2 3 4 5 6 7 8 9 10; do curl -sf -H 'Host: $TH' http://$J/status.php >/dev/null && exit 0; sleep 1; done; exit 1" ||
    die "the bench does not answer after the deployment"
ssh "$H" "doas jexec beastbox /usr/local/bin/beastbox --version" | grep -q "beastbox $v" || die "the bench does not run $v"

step "report"
scripts/bench-report.py snapshot
scripts/bench-report.py site

step "commit and tag v$v"
entry=$(awk -v v="$v" '$0 ~ "^## "v" " {on=1; next} on && /^## / {exit} on' CHANGELOG.md)
git add Cargo.toml Cargo.lock fuzz/Cargo.lock "docs/bench/v$v.json" docs/dev/bench-runs.json
git commit -q -m "Release $v"
printf 'Beastbox %s\n%s\n' "$v" "$entry" | git tag -a --cleanup=verbatim "v$v" -F - # keeps the "### …" headings
finished=1
git log --oneline -1

if [ "$publish" = "--publish" ]; then
    step "publish"
    git push origin main "v$v"
    [ -n "$RR" ] || die "set BEASTBOX_REPORT_REMOTE in scripts/local.env"
    rclone sync target/bench-site "$RR"
else
    printf '\nNot published. When ready:\n  git push origin main v%s\n  rclone sync target/bench-site %s\n' "$v" "${RR:-<report remote>}"
fi
