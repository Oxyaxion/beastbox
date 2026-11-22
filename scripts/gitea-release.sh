#!/bin/sh
# The Gitea release of version X.Y.Z: the FreeBSD archive (binary built in the VM, rc.d script, example configuration,
# admin docs) and its SHA-256, attached to the existing tag vX.Y.Z, the CHANGELOG.md entry as text.
#   scripts/gitea-release.sh X.Y.Z    from the root of the repository, tag vX.Y.Z already pushed,
#                                     binary in target/ci/beastbox (scripts/vm.sh release-binary)
# Needs BEASTBOX_GITEA_TOKEN (write access to the repository) in scripts/local.env; the API is the origin's host.
set -eu
[ -f scripts/local.env ] && . scripts/local.env
v=${1:-}
die() { echo "gitea-release: $*" >&2; exit 1; }
echo "$v" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || die "usage: scripts/gitea-release.sh X.Y.Z"
[ -n "${BEASTBOX_GITEA_TOKEN:-}" ] || die "set BEASTBOX_GITEA_TOKEN in scripts/local.env"
bin=target/ci/beastbox
[ -x "$bin" ] || die "no release binary in $bin"
file "$bin" | grep -q 'FreeBSD' || die "$bin is not a FreeBSD binary"
strings "$bin" | grep -qE "beastbox/$v([^0-9.]|\$)" || die "$bin is not version $v"
# Through the push address (SSH, authenticated): the check also works while the repository is private.
git ls-remote --exit-code --tags "$(git remote get-url --push origin)" "refs/tags/v$v" >/dev/null || die "tag v$v is not on origin"

# https://host/owner/repo(.git) → https://host/api/v1/repos/owner/repo
url=$(git remote get-url origin | sed -E 's#\.git$##')
api=$(echo "$url" | sed -E 's#^(https://[^/]+)/(.+)$#\1/api/v1/repos/\2#')
echo "$api" | grep -qE '^https://[^/]+/api/v1/repos/[^/]+/[^/]+$' || die "origin is not an https Gitea URL: $url"
# The token goes on curl's standard input, never on its command line (visible in ps).
call() { printf 'Authorization: token %s\n' "$BEASTBOX_GITEA_TOKEN" | curl -sS -H @- "$@"; }

code=$(call -o /dev/null -w '%{http_code}' "$api/releases/tags/v$v")
[ "$code" = 404 ] || die "a release for v$v already exists (or the API answered $code)"

# The archive: one folder, root-owned files, the binary executable.
name=beastbox-$v-freebsd15-amd64
out=target/release-assets
rm -rf "$out/$name" && mkdir -p "$out/$name/rc.d" "$out/$name/docs"
install -m 0555 "$bin" "$out/$name/beastbox"
install -m 0555 rc/beastbox "$out/$name/rc.d/beastbox"
install -m 0644 beastbox.example.toml README.md CHANGELOG.md "$out/$name/"
install -m 0644 docs/admin/*.md "$out/$name/docs/"
tar -C "$out" --owner=0 --group=0 --numeric-owner --sort=name -cJf "$out/$name.tar.xz" "$name"
(cd "$out" && sha256sum "$name.tar.xz" > "$name.tar.xz.sha256")

entry=$(awk -v v="$v" '$0 ~ "^## "v" " {on=1; next} on && /^## / {exit} on' CHANGELOG.md)
[ -n "$entry" ] || die "no CHANGELOG.md entry for $v"
body=$(printf '%s\n\n### FreeBSD build\n`%s.tar.xz`: FreeBSD 15 amd64, built in a clean VM. Check it with `sha256sum -c %s.tar.xz.sha256`, then [install](%s/src/tag/v%s/docs/admin/installation.md).\n' \
    "$entry" "$name" "$name" "$url" "$v")
# The JSON goes through a file: curl's standard input carries the token header.
V="$v" B="$body" python3 -c 'import json, os; v = os.environ["V"]; print(json.dumps({"tag_name": "v" + v, "name": "Beastbox " + v, "body": os.environ["B"], "draft": False, "prerelease": False}))' > "$out/release.json"
id=$(call -f -X POST -H 'Content-Type: application/json' --data-binary "@$out/release.json" "$api/releases" |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])') || die "release not created"
for f in "$name.tar.xz" "$name.tar.xz.sha256"; do
    call -f -o /dev/null -X POST -F "attachment=@$out/$f" "$api/releases/$id/assets?name=$f" || die "upload of $f failed"
done
echo "release v$v: $url/releases/tag/v$v"
