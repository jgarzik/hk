#!/bin/bash
#
# Install glibc's dynamic linker, bash and a few coreutils programs
# (Ubuntu debs, verified downloads cached under target/glibc/) into an
# initramfs root, for the DYN_* boot tests. Shared by user/Makefile (hk)
# and tools/linux-boot-tester.sh (Linux), so both kernels run the same
# dynamically linked programs.
#
# Programs go to /usr/bin, shared libraries to /usr/lib/<triplet> (one of
# glibc's default search directories, so no ld.so.cache is needed), and
# the dynamic linker to the path the programs' PT_INTERP names. The
# library set is the NEEDED closure of the programs, found with readelf;
# a missing library stops the build.
#
# Usage: tools/dyn-root.sh <root-dir> <x86_64|aarch64>

set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
ROOT=$1
case $2 in
    x86_64) DEB_ARCH=amd64 TRIPLET=x86_64-linux-gnu ;;
    aarch64) DEB_ARCH=arm64 TRIPLET=aarch64-linux-gnu ;;
    *) echo "dyn-root: unsupported arch $2" >&2; exit 1 ;;
esac

# Ubuntu 25.10 and later: coreutils is a meta package (uutils by
# default); gnu-coreutils holds GNU's programs, as /usr/bin/gnu<prog>
COREUTILS=coreutils
apt-cache show gnu-coreutils > /dev/null 2>&1 && COREUTILS=gnu-coreutils
PACKAGES="libc6 libtinfo6 bash $COREUTILS"
# coreutils programs that need nothing but libc
PROGRAMS="echo cat head tail seq wc tr env true false tac printf uname basename cut"

CACHE=$TOP/target/glibc/$DEB_ARCH
TREE=$CACHE/root
if [ "$(cat "$CACHE/.done" 2> /dev/null)" != "$PACKAGES" ]; then
    echo "Fetching glibc, bash, coreutils ($DEB_ARCH)..."
    . "$TOP/tools/fetch-deb.sh"
    rm -rf "$CACHE"
    mkdir -p "$TREE"
    for p in $PACKAGES; do
        fetch_deb "$p" "$DEB_ARCH" "$CACHE/$p.deb"
        dpkg-deb -x "$CACHE/$p.deb" "$TREE"
    done
    echo "$PACKAGES" > "$CACHE/.done"
fi

LIBDIR=$ROOT/usr/lib/$TRIPLET
mkdir -p "$ROOT/usr/bin" "$LIBDIR"
cp -L "$TREE/usr/bin/bash" "$ROOT/usr/bin/bash"
for p in $PROGRAMS; do
    src=$TREE/usr/bin/$p
    [ -e "$src" ] || src=$TREE/usr/bin/gnu$p
    cp -L "$src" "$ROOT/usr/bin/$p"
done

# The dynamic linker, at the path the programs ask for
interp=$(readelf -l "$ROOT/usr/bin/bash" | sed -n 's/.*program interpreter: \(.*\)]/\1/p')
[ -n "$interp" ] || { echo "dyn-root: bash has no PT_INTERP" >&2; exit 1; }
mkdir -p "$ROOT$(dirname "$interp")"
cp -L "$TREE/usr/lib/$TRIPLET/$(basename "$interp")" "$ROOT$interp"

# The NEEDED closure
needed() {
    readelf -d "$1" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p'
}
todo=$(for f in "$ROOT"/usr/bin/*; do needed "$f"; done | sort -u)
while [ -n "$todo" ]; do
    next=
    for so in $todo; do
        [ -e "$LIBDIR/$so" ] && continue
        src=
        for d in "$TREE/usr/lib/$TRIPLET" "$TREE/lib/$TRIPLET"; do
            [ -e "$d/$so" ] && src=$d/$so && break
        done
        [ -n "$src" ] || { echo "dyn-root: $so not in $PACKAGES" >&2; exit 1; }
        cp -L "$src" "$LIBDIR/$so"
        next="$next $(needed "$LIBDIR/$so")"
    done
    todo=$(echo "$next" | tr ' ' '\n' | sort -u | grep -v '^$' || true)
done
