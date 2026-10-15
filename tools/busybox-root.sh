#!/bin/bash
#
# Install busybox (Ubuntu busybox-static, verified download, cached under
# target/busybox/) plus applet links and user/rootfs/ (/etc files) into an
# initramfs root. Shared by user/Makefile (hk) and
# tools/linux-boot-tester.sh (Linux), so both kernels run the same binary.
#
# Usage: tools/busybox-root.sh <root-dir> <x86_64|aarch64>

set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
ROOT=$1
case $2 in
    x86_64) DEB_ARCH=amd64 ;;
    aarch64) DEB_ARCH=arm64 ;;
    *) echo "busybox-root: unsupported arch $2" >&2; exit 1 ;;
esac

# Applets the tests and /etc/udhcpc.sh use (the rest via `busybox <applet>`)
APPLETS="sh ash ip udhcpc nslookup wget ping nc ifconfig route ls cat echo
true false sleep mkdir rm mv cp ln sed grep head tail tr wc test [ printf
env uname id hostname ps kill readlink touch"

CACHE=$TOP/target/busybox/$DEB_ARCH
BB=$CACHE/usr/bin/busybox
if [ ! -x "$BB" ]; then
    echo "Fetching busybox-static ($DEB_ARCH)..."
    . "$TOP/tools/fetch-deb.sh"
    mkdir -p "$CACHE"
    fetch_deb busybox-static "$DEB_ARCH" "$CACHE/busybox-static.deb"
    dpkg-deb -x "$CACHE/busybox-static.deb" "$CACHE"
fi

mkdir -p "$ROOT/bin" "$ROOT/etc"
cp "$BB" "$ROOT/bin/busybox"
for a in $APPLETS; do
    ln -sf busybox "$ROOT/bin/$a"
done
cp -a "$TOP/user/rootfs/." "$ROOT/"
