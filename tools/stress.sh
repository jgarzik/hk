#!/bin/bash
#
# Flake sweep (make check-stress): the hk boot test, repeated.
#   1. build everything the boots need, once
#   2. STRESS_N boots per arch, at most STRESS_JOBS at a time, each with
#      its own serial log ($QEMU_LOG_DIR/stress/<arch>-<n>/)
# Prints one line per failed boot (with its FAIL lines), then
# STRESS-OK or STRESS-FAILED with the counts. Make variables pass
# through the environment, e.g. NO_KVM=1 LOCKDEP=1 tools/stress.sh
#
# Environment: STRESS_N (10), STRESS_JOBS (3), STRESS_ARCHS ("x86 arm"),
# QEMU_SMP (guest CPUs, 4)

set -uo pipefail
cd "$(dirname "$0")/.."

N=${STRESS_N:-10}
JOBS=${STRESS_JOBS:-3}
ARCHS=${STRESS_ARCHS:-x86 arm}
export QEMU_LOG_DIR=${QEMU_LOG_DIR:-$PWD/target/qemu}
OUT=$QEMU_LOG_DIR/stress
rm -rf "$OUT"
mkdir -p "$OUT"

targets=()
for a in $ARCHS; do
    case $a in
        x86) targets+=(iso) ;;
        arm) targets+=(build-arm) ;;
        *) echo "stress: unknown arch '$a' (x86 or arm)"; exit 2 ;;
    esac
done
echo "stress: build"
if ! make --no-print-directory "${targets[@]}" vfat-image disk-image > "$OUT/build.out" 2>&1; then
    tail -30 "$OUT/build.out"
    echo "STRESS-FAILED: build ($OUT/build.out)"
    exit 1
fi

# boot <arch> <n>: one boot test, its result in <dir>/rc
boot() {
    local dir=$OUT/$1-$2 target=check log=serial.log
    [ "$1" = arm ] && target=check-arm log=serial_arm.log
    mkdir -p "$dir"
    QEMU_LOG_DIR=$dir make --no-print-directory "$target" NOBUILD=1 > "$dir/make.out" 2>&1
    echo $? > "$dir/rc"
    [ -f "$dir/$log" ] || cp "$dir/make.out" "$dir/$log"
}

echo "stress: $N boots each of $ARCHS, $JOBS at a time"
for i in $(seq 1 "$N"); do
    for a in $ARCHS; do
        while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do
            wait -n
        done
        boot "$a" "$i" &
    done
done
wait

fails=0
total=0
for dir in "$OUT"/*-*/; do
    total=$((total + 1))
    name=$(basename "$dir")
    [ "$(cat "$dir/rc")" = 0 ] && continue
    fails=$((fails + 1))
    echo "$name FAIL ($dir)"
    grep -ahE 'FAIL|panic|PANIC|EXCEPTION' "$dir"/serial*.log 2>/dev/null | head -5 | sed 's/^/    /'
done
if [ "$fails" = 0 ]; then
    echo "STRESS-OK ($total boots, ${SECONDS}s)"
else
    echo "STRESS-FAILED ($fails of $total boots, ${SECONDS}s, logs in $OUT)"
    exit 1
fi
