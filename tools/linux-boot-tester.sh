#!/bin/bash
#
# Differential test: run boot_tester as init on a real Linux kernel in QEMU.
#
# Same initramfs layout and QEMU machine as hk, but booting Ubuntu's generic
# kernel. Tests whose expectations disagree with real Linux FAIL here.
# Needs no root: the kernel .deb is fetched with `apt-get download` and
# cached under target/linux-kernel/. Defaults to the native architecture;
# `-a` selects the other one (emulated; kernel fetched from Ubuntu ports).
#
# A PASS is cached (see linux_cache_key): a rerun with the same inputs
# skips the boot. The cache is shared by all worktrees and off on CI.
#
# Usage: tools/linux-boot-tester.sh [-a x86_64|aarch64] [-T timeout_seconds]
# Env:   LINUX_KERNEL=/path/to/vmlinuz  use this kernel instead of Ubuntu's
#        NO_KVM=1          force TCG even if /dev/kvm works (as on CI)
#        LINUX_NOCACHE=1   boot even if this PASS is cached
#        LINUX_CACHE_DIR   cache (default ~/.cache/hk-linux-check)
#        QEMU_LOG_DIR      serial log directory (default target/qemu)

set -euo pipefail

cd "$(dirname "$0")/.."
TOP=$PWD

TIMEOUT=120
ARCH=$(uname -m)
while getopts "a:T:" opt; do
    case $opt in
        a) ARCH=$OPTARG ;;
        T) TIMEOUT=$OPTARG ;;
        *) echo "Usage: $0 [-a x86_64|aarch64] [-T seconds]"; exit 1 ;;
    esac
done
NATIVE=false
[ "$ARCH" = "$(uname -m)" ] && NATIVE=true

case "$ARCH" in
    x86_64)
        ARCH=x86_64; DEB_ARCH=amd64; QEMU_BIN=qemu-system-x86_64
        QEMU_MACHINE=(-cpu max)
        CONSOLE=ttyS0
        ;;
    aarch64)
        ARCH=aarch64; DEB_ARCH=arm64; QEMU_BIN=qemu-system-aarch64
        QEMU_MACHINE=(-machine virt,gic-version=3 -cpu max)
        CONSOLE=ttyAMA0
        ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Verified .deb downloads (native apt or Ubuntu archive/ports)
. tools/fetch-deb.sh

WORK=target/linux-test-$ARCH
QEMU_LOG_DIR=${QEMU_LOG_DIR:-$TOP/target/qemu}
SERIAL_LOG=$QEMU_LOG_DIR/serial_linux_$ARCH.log
mkdir -p "$WORK" "$QEMU_LOG_DIR"

# Kernel: Ubuntu generic, fetched once per version
if [ -z "${LINUX_KERNEL:-}" ]; then
    KVER=$(apt-cache depends linux-image-generic | grep -o 'linux-image-[0-9][^ ]*-generic' | head -1)
    KVER=${KVER#linux-image-}
    KDIR=target/linux-kernel/$DEB_ARCH/$KVER
    PKGVER=$(apt-cache show "linux-image-$KVER" | sed -n 's/^Version: //p' | head -1)
    LINUX_KERNEL=$KDIR/boot/vmlinuz-$KVER
    if [ ! -f "$LINUX_KERNEL" ]; then
        echo "Fetching Linux $KVER ($DEB_ARCH)..."
        mkdir -p "$KDIR"
        if $NATIVE; then
            (cd "$KDIR" && apt-get download "linux-image-$KVER" >/dev/null)
        else
            # Foreign arch: same version from the ports archive (no multiarch needed)
            fetch_deb "linux-image-unsigned-$KVER" "$DEB_ARCH" "$KDIR/linux-image.deb" "$PKGVER"
        fi
        dpkg-deb -x "$KDIR"/linux-image*.deb "$KDIR"
    fi
fi
echo "Kernel: $LINUX_KERNEL"

# The tests need these built in (no modules in the initramfs): check the
# kernel's config from its linux-buildinfo package (small; fetched once)
if [ -n "${KDIR:-}" ]; then
    CONFIG=$KDIR/usr/lib/linux/$KVER/config
    if [ ! -f "$CONFIG" ]; then
        if $NATIVE; then
            (cd "$KDIR" && apt-get download "linux-buildinfo-$KVER" >/dev/null)
        else
            fetch_deb "linux-buildinfo-$KVER" "$DEB_ARCH" "$KDIR/linux-buildinfo.deb" "$PKGVER"
        fi
        dpkg-deb -x "$KDIR"/linux-buildinfo*.deb "$KDIR"
    fi
    for opt in VIRTIO_BLK EFI_PARTITION DEVTMPFS VFAT_FS NLS_CODEPAGE_437; do
        if ! grep -qx "CONFIG_$opt=y" "$CONFIG"; then
            echo "Linux $KVER ($DEB_ARCH): CONFIG_$opt is not =y ($CONFIG);"
            echo "the boot tests need it built in"
            exit 1
        fi
    done
fi

# Initramfs: host build of boot_tester, same layout as user/Makefile
# (busybox and /etc from tools/busybox-root.sh)
make -s -C user host ARCH=$ARCH
BIN=user/target-host/$ARCH-unknown-linux-gnu/release
ROOT=$WORK/root
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/mnt"
tools/busybox-root.sh "$ROOT" "$ARCH"
cp "$BIN/boot_tester" "$BIN/boot_tester2" "$ROOT/bin/"
ln -sf boot_tester "$ROOT/bin/init"
echo -n "Hello from ramfs!" > "$ROOT/test.txt"
(cd "$ROOT" && find . | cpio -o -H newc --quiet) > "$WORK/initramfs.cpio"

# KVM whenever the host can run this arch natively (x86_64 on x86_64,
# aarch64 on an arm64 host such as CI's ubuntu-24.04-arm if it exposes
# /dev/kvm); TCG otherwise
KVM=()
if [ -w /dev/kvm ] && $NATIVE && [ "${NO_KVM:-}" != 1 ]; then
    KVM=(-accel kvm)
    case $ARCH in
        x86_64) QEMU_MACHINE=(-cpu host) ;;
        aarch64) QEMU_MACHINE=(-machine virt,gic-version=host -cpu host) ;;
    esac
fi

# The virtio test disk, attached like run-qemu.sh does (make disk-image)
DISK=()
if [ -f target/disk.img ]; then
    DISK=(-drive file=target/disk.img,if=none,id=vd0,format=raw,snapshot=on
        -device virtio-blk-pci,drive=vd0,num-queues=2,serial=hk0,disable-legacy=on)
fi

# Network: same slirp network as hk (tools/qemu-net.sh); virtio-net is
# built into Ubuntu's generic kernel (CONFIG_VIRTIO_NET=y, VIRTIO_PCI=y on
# amd64 and arm64), so it comes up as eth0 without modules
. tools/qemu-net.sh
qemu_net_args virtio

# Hash of everything that decides the result, hk's kernel/ excluded:
# the sources (user/ workspace, these scripts, Makefile, toolchain pin),
# what gets booted (kernel, its config, initramfs tree; the disk image by
# mkdisk.sh and its tools, as its FAT timestamps differ per build) and
# how (QEMU version, machine/KVM, network, timeout, host kernel)
linux_cache_key() {
    local f files
    files=$(git ls-files -co --exclude-standard -- user Makefile rust-toolchain.toml \
        tools/linux-boot-tester.sh tools/mkdisk.sh tools/busybox-root.sh \
        tools/fetch-deb.sh tools/qemu-net.sh tools/netpeer | LC_ALL=C sort -u) || return 1
    {
        echo "$ARCH $TIMEOUT ${KVM[*]} ${QEMU_MACHINE[*]} ${DISK[*]}" &&
            echo "${QEMU_NET[*]//"$TOP"/}" &&
            "$QEMU_BIN" --version &&
            uname -r &&
            for f in $files; do [ ! -f "$f" ] || sha256sum "$f" || return 1; done &&
            sha256sum "$LINUX_KERNEL" ${CONFIG:+"$CONFIG"} &&
            dpkg-query -W fdisk dosfstools mtools util-linux perl &&
            (cd "$ROOT" && find . -printf '%p %y %m %l\n' | LC_ALL=C sort &&
                find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum)
    } > "$WORK/cache-key" || return 1
    sha256sum < "$WORK/cache-key" | cut -c1-32
}

rm -f "$SERIAL_LOG"
CACHE=
if [ -z "${CI:-}" ] && KEY=$(linux_cache_key); then
    CACHE=${LINUX_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/hk-linux-check}/$ARCH/$KEY
    if [ -f "$CACHE" ] && [ "${LINUX_NOCACHE:-}" != 1 ]; then
        echo "check-linux: cached PASS ($ARCH $KEY)"
        exit 0
    fi
fi

echo "Booting boot_tester on Linux ($([ ${#KVM[@]} = 0 ] && echo TCG || echo KVM), ${TIMEOUT}s timeout)..."
timeout "$TIMEOUT" "$QEMU_BIN" "${KVM[@]}" "${QEMU_MACHINE[@]}" \
    -m 512M -smp 4 -nographic -no-reboot -monitor none "${QEMU_NET[@]}" "${DISK[@]}" \
    -kernel "$LINUX_KERNEL" -initrd "$WORK/initramfs.cpio" \
    -append "console=$CONSOLE rdinit=/bin/init panic=-1 quiet" \
    -serial file:"$SERIAL_LOG" </dev/null || true

if ! grep -aq "^Host mode: " "$SERIAL_LOG"; then
    echo "Linux boot test FAILED - boot_tester did not finish:"
    tail -20 "$SERIAL_LOG"
    exit 1
fi
FAILS=$(grep -ac FAIL "$SERIAL_LOG" || true)
echo "OK=$(grep -ac ':OK' "$SERIAL_LOG") FAIL=$FAILS SKIP=$(grep -ac ':SKIP' "$SERIAL_LOG")"
if [ "$FAILS" != 0 ]; then
    echo "Linux boot test FAILED - tests disagree with Linux:"
    grep -a FAIL "$SERIAL_LOG"
    exit 1
fi
echo "Linux boot test PASSED"
if [ -n "$CACHE" ]; then
    mkdir -p "${CACHE%/*}"
    grep -ac ':OK' "$SERIAL_LOG" > "$CACHE.$$"
    mv "$CACHE.$$" "$CACHE"
fi
