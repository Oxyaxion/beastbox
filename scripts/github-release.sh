#!/bin/sh
# The GitHub release of version X.Y.Z: the FreeBSD archive (binary built in the VM, rc.d script, example configuration,
# admin docs) and its SHA-256, attached to the existing tag vX.Y.Z, the CHANGELOG.md entry as text.
#   scripts/github-release.sh X.Y.Z    from the root of the repository, tag vX.Y.Z already pushed,
#                                     binary in target/ci/beastbox (scripts/vm.sh release-binary)
# Needs `gh` logged in with write access to the repository.
set -eu
[ -f scripts/local.env ] && . scripts/local.env
v=${1:-}
die() { echo "github-release: $*" >&2; exit 1; }
echo "$v" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || die "usage: scripts/github-release.sh X.Y.Z"
bin=target/ci/beastbox
[ -x "$bin" ] || die "no release binary in $bin"
file "$bin" | grep -q 'FreeBSD' || die "$bin is not a FreeBSD binary"
strings "$bin" | grep -qE "beastbox/$v([^0-9.]|\$)" || die "$bin is not version $v"
git ls-remote --exit-code --tags origin "refs/tags/v$v" >/dev/null || die "tag v$v is not on origin"

url=https://github.com/$(git remote get-url origin | sed -E 's#^.*github\.com[:/](.+)$#\1#; s#\.git$##')
gh release view "v$v" >/dev/null 2>&1 && die "a release for v$v already exists"

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
body=$(printf '%s\n\n### FreeBSD build\n`%s.tar.xz`: FreeBSD 15 amd64, built in a clean VM. Check it with `sha256sum -c %s.tar.xz.sha256`, then [install](%s/blob/v%s/docs/admin/installation.md).\n' \
    "$entry" "$name" "$name" "$url" "$v")
printf '%s\n' "$body" > "$out/notes.md"
gh release create "v$v" --verify-tag --title "Beastbox $v" --notes-file "$out/notes.md" "$out/$name.tar.xz" "$out/$name.tar.xz.sha256"
