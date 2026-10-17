#!/bin/bash
#
# Build the boot tests' virtio disk image (rootless, deterministic).
#
# 128 MiB, GPT (sfdisk):
#   p1  32 MiB  vfat, label HKDISK, file HKDISK.TXT   (sectors 2048..)
#   p2  64 MiB  swap (mkswap, label hkswap)
#   p3  16 MiB  pattern: 32-bit LE word i = i * 1103515245 + 12345 (mod 2^32)
#   rest        unallocated (reserved for later filesystems)
# The boot tests attach it read-write with snapshot=on: every run sees
# this pristine image. Needs sfdisk (fdisk), mkfs.vfat (dosfstools),
# mcopy (mtools), mkswap (util-linux), perl.
#
# Usage: tools/mkdisk.sh [out.img]   (default target/disk.img)

set -euo pipefail

OUT=${1:-target/disk.img}
TMP=$OUT.tmp
P1=1     # MiB offsets
P2=33
P3=97

mkdir -p "$(dirname "$OUT")"
rm -f "$TMP" "$TMP.swap"
truncate -s 128M "$TMP"

sfdisk --quiet --no-reread --no-tell-kernel "$TMP" <<EOF
label: gpt
label-id: 6B4D2E10-0000-4000-8000-00000000AB01
unit: sectors
start=2048, size=65536, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, name="HKDISK", uuid=6B4D2E10-0000-4000-8000-000000000001
start=67584, size=131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, name="hkswap", uuid=6B4D2E10-0000-4000-8000-000000000002
start=198656, size=32768, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="hkpattern", uuid=6B4D2E10-0000-4000-8000-000000000003
EOF

# p1: FAT32 with 512-byte clusters (hk's vfat is FAT32-only)
mkfs.vfat -F 32 -s 1 -S 512 -n HKDISK -i 484b4431 --offset $((P1 * 2048)) "$TMP" 32768 >/dev/null 2>&1
echo "hk virtio disk" | mcopy -i "$TMP@@${P1}M" - ::HKDISK.TXT

# p2: swap, made in a file and copied in
truncate -s 64M "$TMP.swap"
mkswap -L hkswap -U 6b4d2e10-0000-4000-8000-0000000000aa "$TMP.swap" >/dev/null 2>&1
dd if="$TMP.swap" of="$TMP" bs=1M seek=$P2 conv=notrunc status=none
rm -f "$TMP.swap"

# p3: the LCG pattern
perl -e 'use integer; binmode STDOUT;
    my $buf = ""; for my $i (0 .. 16 * 1024 * 1024 / 4 - 1) {
        $buf .= pack("V", ($i * 1103515245 + 12345) & 0xffffffff);
        if (length($buf) >= 65536) { print $buf; $buf = ""; }
    } print $buf;' |
    dd of="$TMP" bs=1M seek=$P3 conv=notrunc status=none

mv "$TMP" "$OUT"
echo "Created $OUT"
