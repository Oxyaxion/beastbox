#!/bin/sh
# The test report on Codeberg Pages: target/bench-site (scripts/bench-report.py site) as the only commit of the `pages`
# branch of origin, pushed by force (the branch never grows; main never sees it) → https://modulus.codeberg.page/beastbox/
#   scripts/report-pages.sh    from the root of the repository
set -eu
die() { echo "report-pages: $*" >&2; exit 1; }
[ -f target/bench-site/index.html ] || die "no report in target/bench-site (scripts/bench-report.py site)"
to=$(git remote get-url --push origin)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -R target/bench-site/. "$tmp/"
git -C "$tmp" init -q -b pages
git -C "$tmp" add -A
git -C "$tmp" -c user.name="$(git config user.name)" -c user.email="$(git config user.email)" \
    commit -q -m "Test report, $(git describe --tags --always)"
git -C "$tmp" push -q -f "$to" pages
echo "report published: https://modulus.codeberg.page/beastbox/"
