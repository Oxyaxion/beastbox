#!/bin/sh
# Local CI: a FreeBSD 15.1 VM on the Linux workstation (QEMU/KVM, no display), started clean for every run.
# docs/dev/TESTING.md, "Local CI". The bench host stays the reference for performance and the test bench.
#
#   scripts/vm.sh create          once: the golden image (official image, packages, Rust, tools, ZFS pool; ~30 min)
#   scripts/vm.sh rebuild         a new golden image (new FreeBSD, Rust or tool version)
#   scripts/vm.sh ci              scripts/check.sh in a throwaway VM (overlays deleted at the end)
#   scripts/vm.sh ci --long [--jobs N]   the whole campaign (litmus, fuzz, mutants); results and report copied back
#   scripts/vm.sh ci --mutants [--jobs N]  the mutation testing alone (~25 min): checks a fix before a new campaign
#   scripts/vm.sh release-binary         the release binary, built in the VM (the bench installs that one)
#   scripts/vm.sh up | down       a dev VM kept between commands, builds warm (its overlay deleted by `down`)
#   scripts/vm.sh test            cargo test in the dev VM
#   scripts/vm.sh ssh [CMD]       a shell or a command in the dev VM, as `dev` (doas without password)
#                                 test, ssh: without `up`, the VM is started for the command and gone after it
#   scripts/vm.sh status
#
# Resources: BEASTBOX_VM_CPUS (8), BEASTBOX_VM_MEM (14G), BEASTBOX_VM_RAMDISK (10g: /ram, a ZFS pool in RAM for the
# builds; the tests' files are on the ZFS disk). Files: BEASTBOX_VM_DIR
# (~/.local/share/beastbox-vm): golden disks base-system.qcow2 and base-zfs.qcow2 (read-only), the SSH key, runs/.
set -eu
D=${BEASTBOX_VM_DIR:-$HOME/.local/share/beastbox-vm}
REL=15.1-RELEASE
IMG=FreeBSD-$REL-amd64-BASIC-CLOUDINIT-ufs.qcow2
URL=https://download.freebsd.org/releases/VM-IMAGES/$REL/amd64/Latest
CPUS=${BEASTBOX_VM_CPUS:-8}
MEM=${BEASTBOX_VM_MEM:-14G}
RAMDISK=${BEASTBOX_VM_RAMDISK:-10g}
# The versions of the bench host (TESTING.md): the same lints, the same tools.
RUST=1.95.0
TOOLS="cargo-mutants@27.1.0 cargo-llvm-cov@0.9.1 cargo-deny@0.20.2 cargo-fuzz@0.13.2 cargo-machete@0.9.1 cargo-vet@0.10.3 cargo-geiger@0.13.0"
# Inside the VM: builds and test files in RAM, the CLI tests on the ZFS datasets.
# Inside the VM: builds in RAM (/ram/target), the tests' files on the ZFS disk (/ztest/tmp), the CLI tests on its
# datasets; the mutants' copies (whole project and its build, per copy) in RAM too (BEASTBOX_MUTANTS_TMP).
ENV='. ~/.cargo/env && export CARGO_TARGET_DIR=/ram/target TMPDIR=/ztest/tmp BEASTBOX_MUTANTS_TMP=/ram/tmp BEASTBOX_CI_ROOT=/var/tmp/beastbox-ci && cd ~/beastbox'

die() { echo "vm: $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

# A VM instance: its name gives its folder and its SSH port (dev 2223, ci 2224, build 2225).
use() {
    NAME=$1
    R=$D/runs/$NAME
    case $NAME in dev) PORT=2223 ;; ci) PORT=2224 ;; *) PORT=2225 ;; esac
}
vssh() {
    ssh -q -p "$PORT" -i "$D/id_ed25519" -o UserKnownHostsFile="$D/known_hosts" -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=5 dev@127.0.0.1 "$@"
}
vscp() {
    scp -q -P "$PORT" -i "$D/id_ed25519" -o UserKnownHostsFile="$D/known_hosts" -o StrictHostKeyChecking=accept-new "$@"
}
running() { [ -f "$R/vm.pid" ] && kill -0 "$(cat "$R/vm.pid")" 2>/dev/null; }

# Boots instance $NAME on its disks ($R/system.qcow2, $R/zfs.qcow2), waits for SSH.
boot() {
    running && return
    qemu-system-x86_64 -name "beastbox-$NAME" -machine q35,accel=kvm -cpu host -smp "$CPUS" -m "$MEM" \
        -drive file="$R/system.qcow2",if=virtio,discard=unmap \
        -drive file="$R/zfs.qcow2",if=virtio,discard=unmap \
        ${SEED:+-drive file="$SEED",media=cdrom,readonly=on} \
        -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22 -device virtio-net-pci,netdev=n0 \
        -display none -serial file:"$R/console.log" -daemonize -pidfile "$R/vm.pid"
    printf 'waiting for SSH (%s)' "$NAME"
    i=0
    until vssh true 2>/dev/null; do
        i=$((i + 1)); [ $i -lt 120 ] || die "no SSH after 10 minutes (see $R/console.log)"
        printf .; sleep 5
    done
    echo " up"
}

# /ram: a ZFS pool in RAM (an md device of fixed size: it cannot grow past it) for the builds and the mutants' copies,
# which would otherwise write gigabytes to the workstation's SSD. Swap-backed, not malloc: a malloc md fails a write
# when the kernel has no free page at once, and ZFS then suspends the pool (the 0.15.0 runs froze in the mutants so). Made at each boot (RAM is empty), at the size asked
# for this boot; the ZFS cache is capped so that it does not hold the same data a second time. autotrim: a deleted file
# gives its pages back to the md (without it, all that was ever written stays in RAM). The tests' files go to
# ztest/tmp, on the ZFS disk, as in production, with sync=disabled: an fsync there once waited forever in zil_commit
# (a lost wakeup in the VM, nothing queued on the disk), freezing a whole night run; no test checks durability across
# a power loss (the crash test uses kill -9, which the kernel cache survives), so nothing tested is lost.
ram() {
    vssh "doas sh -c 'sysctl -q vfs.zfs.arc.max=1073741824 >/dev/null; zpool list ram >/dev/null 2>&1 || {
        u=\$(mdconfig -a -t swap -s $RAMDISK) && zpool create -f -o autotrim=on -m /ram -O xattr=sa -O compression=off -O atime=off \
            -O sync=disabled ram /dev/\$u; } && mkdir -p /ram/tmp /ram/target && chmod 1777 /ram/tmp && chown dev /ram/target &&
        { zfs list ztest/tmp >/dev/null 2>&1 || zfs create -o mountpoint=/ztest/tmp -o sync=disabled ztest/tmp; } &&
        chmod 1777 /ztest/tmp'"
}

halt() {
    running || return 0
    vssh 'doas shutdown -p now' >/dev/null 2>&1 || true
    i=0
    while running; do i=$((i + 1)); [ $i -lt 60 ] || { kill "$(cat "$R/vm.pid")"; break; }; sleep 1; done
    rm -f "$R/vm.pid"
}

# Fresh overlays on the golden disks.
overlay() {
    [ -f "$D/base-system.qcow2" ] || die "no golden image: scripts/vm.sh create"
    mkdir -p "$R"
    rm -f "$R/system.qcow2" "$R/zfs.qcow2"
    qemu-img create -q -f qcow2 -b "$D/base-system.qcow2" -F qcow2 "$R/system.qcow2"
    qemu-img create -q -f qcow2 -b "$D/base-zfs.qcow2" -F qcow2 "$R/zfs.qcow2"
}

discard() {
    halt
    if [ -f "$R/console.log" ]; then mv "$R/console.log" "$D/last-$NAME-console.log"; fi
    rm -rf "$R"
}

sync() {
    top=$(git rev-parse --show-toplevel)
    rsync -a --delete --exclude target/ --exclude .git/ --exclude fuzz/target/ \
        -e "ssh -q -p $PORT -i $D/id_ed25519 -o UserKnownHostsFile=$D/known_hosts" "$top/" dev@127.0.0.1:beastbox/
}

create() {
    [ ! -f "$D/base-system.qcow2" ] || die "the golden image exists: scripts/vm.sh rebuild"
    command -v qemu-system-x86_64 >/dev/null && command -v qemu-img >/dev/null && command -v xorriso >/dev/null ||
        die "needs qemu-system-x86-core, qemu-img and xorriso"
    [ -w /dev/kvm ] || die "/dev/kvm is not writable"
    use build
    mkdir -p "$R"
    step "official image $IMG, checked against CHECKSUM.SHA256"
    if [ ! -f "$D/$IMG" ]; then
        curl -fL --progress-bar -o "$D/$IMG.xz" "$URL/$IMG.xz"
        curl -fsSL -o "$D/CHECKSUM.SHA256" "$URL/CHECKSUM.SHA256"
        want=$(grep "($IMG.xz)" "$D/CHECKSUM.SHA256" | awk '{print $NF}')
        got=$(sha256sum "$D/$IMG.xz" | awk '{print $1}')
        [ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for $IMG.xz"
        xz -d "$D/$IMG.xz"
    fi
    step "disks: system 12 GiB (growfs touches all of it: no larger), ZFS 10 GiB"
    cp "$D/$IMG" "$R/system.qcow2"
    qemu-img resize -q "$R/system.qcow2" 12G
    qemu-img create -q -f qcow2 "$R/zfs.qcow2" 10G
    step "first-boot configuration (nuageinit): user dev, its key, doas, packages"
    [ -f "$D/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C beastbox-vm -f "$D/id_ed25519"
    mkdir -p "$R/seed"
    printf 'instance-id: beastbox-vm\nlocal-hostname: beastbox-vm\n' > "$R/seed/meta-data"
    # No fstab line: a missing mount point aborts a FreeBSD boot; the RAM disk is made by `ram` at each boot.
    cat > "$R/seed/user-data" <<EOF
#cloud-config
users:
  - name: dev
    groups: wheel
    shell: /bin/sh
    doas: "permit nopass dev"
    ssh_authorized_keys:
      - $(cat "$D/id_ed25519.pub")
ssh_pwauth: false
packages: [doas, git, rsync, python3, curl, litmus]
runcmd:
  - sysrc zfs_enable=YES
  - mkdir -p /ram
EOF
    xorriso -as mkisofs -quiet -o "$R/seed.iso" -V cidata -J -r "$R/seed"
    step "first boot (nuageinit installs the packages: a few minutes; it may reboot once)"
    SEED=$R/seed.iso boot
    printf 'waiting for the first-boot configuration'
    i=0
    until vssh 'command -v doas && command -v rsync && command -v litmus && test -d /ram' >/dev/null 2>&1; do
        i=$((i + 1)); [ $i -lt 120 ] || die "first-boot configuration not done after 10 minutes (see $R/console.log)"
        printf .; sleep 5
    done
    echo " done"
    step "ZFS pool ztest on the second disk, CLI test datasets"
    vssh 'doas sh -c "zpool create -O xattr=sa -O compression=lz4 -O atime=off ztest vtbd1 &&
        zfs create -o mountpoint=/var/tmp/beastbox-ci ztest/beastbox-ci &&
        zfs create ztest/beastbox-ci/alpha && zfs create ztest/beastbox-ci/beta && zfs create ztest/beastbox-ci/alpha/carol &&
        chown -R dev /var/tmp/beastbox-ci"'
    # After the pool: `ram` also makes ztest/tmp, the tests' files.
    ram
    step "Rust $RUST and nightly, then $TOOLS (built in RAM)"
    vssh "curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain $RUST \
        --component clippy,rustfmt,llvm-tools && . ~/.cargo/env && rustup -q toolchain install nightly --profile minimal"
    vssh ". ~/.cargo/env && CARGO_TARGET_DIR=/ram/target/install cargo install -q --locked $TOOLS"
    seal
}

# The dependencies fetched once into the golden image, then the build VM stopped and frozen.
seal() {
    step "dependencies fetched (no download at each run), golden image frozen"
    sync
    vssh "$ENV && cargo fetch -q --locked && (cd fuzz && cargo fetch -q --locked) && rm -rf ~/beastbox"
    vssh '. ~/.cargo/env && rustc --version && cargo mutants --version && zfs list -H -o name -r ztest'
    halt
    mv "$R/system.qcow2" "$D/base-system.qcow2"
    mv "$R/zfs.qcow2" "$D/base-zfs.qcow2"
    chmod 444 "$D/base-system.qcow2" "$D/base-zfs.qcow2"
    discard
    rm -f "$D/$IMG" "$D/CHECKSUM.SHA256"
    du -sh "$D"
    echo "golden image ready: scripts/vm.sh ci"
}

# check.sh [--long] in a throwaway VM; results copied back into target/ci (and the run records for the report).
ci() {
    long=
    jobs=2
    while [ $# -gt 0 ]; do
        case $1 in --long) long=--long ;; --mutants) long=--mutants ;; --jobs) jobs=$2; shift ;; *) die "ci: unknown option $1" ;; esac
        shift
    done
    use dev
    if running; then die "the dev VM is up: scripts/vm.sh down first (RAM)"; fi
    use ci
    discard
    overlay
    trap 'discard' EXIT
    boot
    ram
    sync
    commit=$(git rev-parse --short HEAD)
    [ -z "$(git status --porcelain)" ] || echo "note: uncommitted changes are tested but are not in the mutants' diff"
    git diff "$(git describe --tags --abbrev=0)" HEAD -- src |
        vssh 'mkdir -p ~/beastbox/target && cat > ~/beastbox/target/changes.diff'
    started=$(date +%s)
    status=0
    # A hang must fail the run, not freeze it until morning (BEASTBOX_CI_TIMEOUT, default 8 h).
    timeout "${BEASTBOX_CI_TIMEOUT:-8h}" ssh -q -p "$PORT" -i "$D/id_ed25519" -o UserKnownHostsFile="$D/known_hosts" \
        dev@127.0.0.1 "$ENV && BEASTBOX_COMMIT=$commit BEASTBOX_RAM_TARGET=/ram/target BEASTBOX_MUTANTS_JOBS=$jobs scripts/check.sh $long" ||
        status=$?
    [ "$status" != 124 ] || echo "check.sh $long: stopped after ${BEASTBOX_CI_TIMEOUT:-8h} (timeout)"
    echo "check.sh $long: exit $status after $(( ($(date +%s) - started) / 60 )) min"
    top=$(git rev-parse --show-toplevel)
    rm -rf "$top/target/ci"
    mkdir -p "$top/target/ci"
    vssh 'cd ~/beastbox && tar -cf - target/*.txt target/*.json target/*.log target/mutants-release/mutants.out target/mutants-cli/mutants.out 2>/dev/null' |
        tar -xf - -C "$top/target/ci" 2>/dev/null || true
    if [ "$long" = --long ] && [ "$status" = 0 ]; then
        step "runs recorded, report"
        vssh "$ENV && export BEASTBOX_COMMIT=$commit && for t in http propfind proppatch search headers query manifest thumb restore oidc_url oidc_provider; do
            scripts/bench-report.py record-fuzz \$t target/fuzz-\$t.log; done &&
            scripts/bench-report.py record-models 3000 && scripts/bench-report.py record-mutants target/mutants-release target/mutants-cli &&
            scripts/bench-report.py report --reuse" >/dev/null
        vssh 'cd ~/beastbox && tar -cf - target/bench docs/dev/bench-runs.json' | tar -xf - -C "$top"
        echo "report data in target/bench, run records in docs/dev/bench-runs.json"
    fi
    echo "logs in target/ci"
    return "$status"
}

# The release binary, built in the VM (never on the front), with the version the tree carries: a short run.
binary() {
    top=$(git rev-parse --show-toplevel)
    dev
    sync
    step "release binary (built in the VM)"
    vssh "$ENV && cargo build --release --locked" >/dev/null
    mkdir -p "$top/target/ci"
    vscp dev@127.0.0.1:/ram/target/release/beastbox "$top/target/ci/beastbox"
    echo "release binary: target/ci/beastbox"
}

# The dev VM for one command: already up (`up`), it stays; otherwise it is started now and gone when the command ends.
dev() {
    use dev
    running && return 0
    [ -f "$R/system.qcow2" ] || overlay
    trap discard EXIT
    trap 'exit 130' INT TERM
    boot
    ram
}

case ${1:-} in
create) create ;;
rebuild)
    for n in dev ci build; do use $n; discard; done
    rm -f "$D/base-system.qcow2" "$D/base-zfs.qcow2"
    # The new image has new host keys: the old ones would make `accept-new` refuse every VM made from it.
    rm -f "$D/known_hosts"
    create
    ;;
seal) use build; [ -f "$R/system.qcow2" ] || die "no build VM"; boot; ram; seal ;; # used by create
ci) shift; ci "$@" ;;
release-binary) binary ;;
up) use dev; [ -f "$R/system.qcow2" ] || overlay; boot; ram ;;
down) use dev; discard; echo "dev VM gone" ;;
test) dev; sync; vssh "$ENV && cargo test" ;;
ssh) shift; dev; vssh "$@" ;;
status)
    for n in dev ci build; do use $n; if running; then echo "$n: up (ssh 127.0.0.1:$PORT)"; else echo "$n: down"; fi; done
    du -sh "$D" 2>/dev/null || true
    ;;
*) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
