#!/bin/bash
#
# unsafe use per kernel source directory (the repo root's .rs tree;
# doc/UNSAFE.md): unsafe blocks, unsafe
# fns, unsafe impls, and how many blocks and impls have a `// SAFETY:`
# comment within the three lines above them.
#
# Usage: tools/unsafe-stats.sh   (or make unsafe-stats)

cd "$(dirname "$0")/.." || exit 1

out=$(find . -name '*.rs' -not -path './user/*' -not -path './tools/*' -not -path './target/*' |
    sort | xargs awk '
    FNR == 1 { p1 = p2 = p3 = "" }
    {
        d = FILENAME
        sub(/^\.\//, "", d)
        if (d ~ /\//) {
            split(d, a, "/")
            d = a[1]
            if (d == "arch" && a[2] !~ /\.rs$/) d = d "/" a[2]
        } else {
            d = "(top)"
        }
        line = $0
        sub(/\/\/.*/, "", line)
        ctx = p1 p2 p3 $0
        n = gsub(/unsafe[ \t]*\{/, "&", line)
        blk[d] += n
        if (n && ctx ~ /SAFETY/) doc[d] += n
        if (line ~ /unsafe[ \t]+(extern[ \t]+"[^"]*"[ \t]+)?fn[ \t]/) fn_[d]++
        if (line ~ /unsafe[ \t]+impl/) {
            imp[d]++
            if (ctx ~ /SAFETY/) doc[d]++
        }
        dirs[d] = 1
        p1 = p2; p2 = p3; p3 = $0
    }
    END {
        for (d in dirs) {
            if (!(blk[d] + fn_[d] + imp[d])) continue
            t = blk[d] + imp[d]
            printf "%-16s %7d %7d %7d %8d%%\n", d, blk[d], fn_[d], imp[d], t ? 100 * doc[d] / t : 100
            B += blk[d]; F += fn_[d]; I += imp[d]; D += doc[d]
        }
        printf "%-16s %7d %7d %7d %8d%%\n", "TOTAL", B, F, I, (B + I) ? 100 * D / (B + I) : 100
    }')

printf "%-16s %7s %7s %7s %9s\n" dir blocks fns impls SAFETY%
grep -v '^TOTAL' <<< "$out" | sort -k2 -rn
grep '^TOTAL' <<< "$out"
printf "static mut: %d\n" "$(grep -rn --include=*.rs --exclude-dir=user --exclude-dir=tools \
    --exclude-dir=target -E '^[^/]*\bstatic mut\b' . | wc -l)"
