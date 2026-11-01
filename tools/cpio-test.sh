#!/bin/bash
#
# Initramfs entries for the CPIO_* boot tests, shared by user/Makefile (hk)
# and tools/linux-boot-tester.sh (Linux), so both kernels unpack the same.
#
#   tools/cpio-test.sh tree <root-dir>
#       /cpio_test/: an empty file, two hard links to one file, a FIFO,
#       and /cpio_test/overlay holding "base"
#   tools/cpio-test.sh append <archive>
#       Append a second newc archive (what a concatenated initramfs
#       looks like) holding /cpio_test/null, character device 1:3,
#       which needs root to create in a tree, and a new
#       /cpio_test/overlay ("overlay") that replaces the first
#
# Linux init/initramfs.c unpacks all of these.

set -euo pipefail

case $1 in
tree)
    d=$2/cpio_test
    mkdir -p "$d"
    : > "$d/empty"
    printf 'linked\n' > "$d/link1"
    ln -f "$d/link1" "$d/link2"
    rm -f "$d/fifo"
    mkfifo -m 0644 "$d/fifo"
    printf 'base\n' > "$d/overlay"
    ;;
append)
    python3 -I - "$2" <<'EOF'
import sys

def entry(name, mode, nlink=1, rdev=(0, 0), body=b""):
    name = name.encode() + b"\0"
    fields = [1, mode, 0, 0, nlink, 0, len(body), 0, 0, rdev[0], rdev[1], len(name), 0]
    hdr = b"070701" + b"".join(b"%08x" % f for f in fields)
    out = hdr + name
    out += b"\0" * (-len(out) % 4)
    out += body + b"\0" * (-len(body) % 4)
    return out

data = entry("cpio_test/null", 0o020666, rdev=(1, 3))
data += entry("cpio_test/overlay", 0o100644, body=b"overlay\n")
data += entry("TRAILER!!!", 0)
data += b"\0" * (-len(data) % 512)
with open(sys.argv[1], "ab") as f:
    f.write(data)
EOF
    ;;
*)
    echo "usage: $0 tree <root> | append <archive>" >&2
    exit 1
    ;;
esac
