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
# Usage: tools/linux-boot-tester.sh [-a x86_64|aarch64] [-T timeout_seconds]
# Env:   LINUX_KERNEL=/path/to/vmlinuz  use this kernel instead of Ubuntu's

set -euo pipefail

cd "$(dirname "$0")/.."

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
SERIAL_LOG=/tmp/qemu_serial_linux.log
mkdir -p "$WORK"

# Kernel: Ubuntu generic, fetched once per version
if [ -z "${LINUX_KERNEL:-}" ]; then
    KVER=$(apt-cache depends linux-image-generic | grep -o 'linux-image-[0-9][^ ]*-generic' | head -1)
    KVER=${KVER#linux-image-}
    KDIR=target/linux-kernel/$DEB_ARCH/$KVER
    LINUX_KERNEL=$KDIR/boot/vmlinuz-$KVER
    if [ ! -f "$LINUX_KERNEL" ]; then
        echo "Fetching Linux $KVER ($DEB_ARCH)..."
        mkdir -p "$KDIR"
        if $NATIVE; then
            (cd "$KDIR" && apt-get download "linux-image-$KVER" >/dev/null)
        else
            # Foreign arch: same version from the ports archive (no multiarch needed)
            PKGVER=$(apt-cache show "linux-image-$KVER" | sed -n 's/^Version: //p' | head -1)
            fetch_deb "linux-image-unsigned-$KVER" "$DEB_ARCH" "$KDIR/linux-image.deb" "$PKGVER"
        fi
        dpkg-deb -x "$KDIR"/linux-image*.deb "$KDIR"
    fi
fi
echo "Kernel: $LINUX_KERNEL"

# Initramfs: host build of boot_tester, same layout as user/Makefile
make -s -C user host ARCH=$ARCH
BIN=user/target-host/$ARCH-unknown-linux-gnu/release
ROOT=$WORK/root
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/mnt"
cp "$BIN/boot_tester" "$BIN/boot_tester2" "$ROOT/bin/"
ln -sf boot_tester "$ROOT/bin/init"
echo -n "Hello from ramfs!" > "$ROOT/test.txt"
(cd "$ROOT" && find . | cpio -o -H newc --quiet) > "$WORK/initramfs.cpio"

KVM=()
if [ -w /dev/kvm ] && $NATIVE && [ "$ARCH" = x86_64 ]; then
    KVM=(-enable-kvm)
    QEMU_MACHINE=(-cpu host)
fi

# Network: same slirp network as hk (tools/qemu-net.sh); virtio-net is
# built into Ubuntu's generic kernel (CONFIG_VIRTIO_NET=y, VIRTIO_PCI=y on
# amd64 and arm64), so it comes up as eth0 without modules
. tools/qemu-net.sh
qemu_net_args virtio-net-pci

echo "Booting boot_tester on Linux (${TIMEOUT}s timeout)..."
rm -f "$SERIAL_LOG"
timeout "$TIMEOUT" "$QEMU_BIN" "${KVM[@]}" "${QEMU_MACHINE[@]}" \
    -m 512M -smp 4 -nographic -no-reboot -monitor none "${QEMU_NET[@]}" \
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
