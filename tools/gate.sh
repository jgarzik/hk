#!/bin/bash
#
# The full per-commit gate (CLAUDE.md), boots in parallel:
#   1. fmt-check, clippy and clippy-arm (-D warnings), test: fail fast
#   2. build everything the boots need, serially (shared target dirs)
#   3. check, check-arm, check-linux, check-linux-arm concurrently
#      (NOBUILD=1; each boot has its own serial log in $QEMU_LOG_DIR)
# Prints one line per boot, then GATE-OK or GATE-FAILED. Output of each
# step: $QEMU_LOG_DIR/gate/<step>.out. Make variables pass through the
# environment, e.g. NO_KVM=1 LINUX_NOCACHE=1 tools/gate.sh
#
# Usage: tools/gate.sh   (or make gate)

set -uo pipefail
cd "$(dirname "$0")/.."

export QEMU_LOG_DIR=${QEMU_LOG_DIR:-$PWD/target/qemu}
OUT=$QEMU_LOG_DIR/gate
rm -rf "$OUT"
mkdir -p "$OUT"

# step <name> <make args...>: make, output to $OUT/<name>.out
step() {
    local name=$1
    shift
    make --no-print-directory "$@" > "$OUT/$name.out" 2>&1
}

fail() {
    tail -30 "$OUT/$1.out"
    echo "GATE-FAILED: $1 ($OUT/$1.out, ${SECONDS}s)"
    exit 1
}

serial() {
    local name=$1
    echo "gate: $name"
    step "$@" || fail "$name"
}

serial fmt-check fmt-check
serial clippy clippy "CLIPPY_FLAGS=-D warnings"
serial clippy-arm clippy-arm "CLIPPY_FLAGS=-D warnings"
serial test test
serial build iso build-arm disk-image
serial build-host-x86_64 -C user host ARCH=x86_64
serial build-host-aarch64 -C user host ARCH=aarch64

# On an arm64 host check-linux is aarch64 already
BOOTS="check check-arm check-linux check-linux-arm"
[ "$(uname -m)" = x86_64 ] || BOOTS="check check-arm check-linux"

echo "gate: $BOOTS (parallel, ${SECONDS}s so far)"
for b in $BOOTS; do
    (
        t=$SECONDS
        step "$b" "$b" NOBUILD=1
        echo "$? $((SECONDS - t))" > "$OUT/$b.rc"
    ) &
done
wait

ok=true
for b in $BOOTS; do
    read -r rc secs < "$OUT/$b.rc"
    res=PASS
    [ "$rc" = 0 ] || { res=FAIL; ok=false; }
    line=$(grep -aE 'PASSED|FAILED|cached PASS' "$OUT/$b.out" | tail -1)
    printf '%-16s %s %4ss  %s\n' "$b" "$res" "$secs" "$line"
    if [ "$res" = FAIL ]; then
        # Where it stopped: the last serial lines and any failure lines
        log=$QEMU_LOG_DIR/serial.log
        case $b in check-arm) log=$QEMU_LOG_DIR/serial_arm.log ;; check-linux*) log=$OUT/$b.out ;; esac
        grep -aE 'FAIL|panic|PANIC|abort|EXCEPTION' "$log" 2>/dev/null | tail -5 | sed 's/^/    /'
        echo "    (last lines of $log)"
        tail -3 "$log" 2>/dev/null | sed 's/^/    /'
    fi
done
if $ok; then
    echo "GATE-OK (${SECONDS}s)"
else
    echo "GATE-FAILED (${SECONDS}s, logs in $OUT)"
    exit 1
fi
