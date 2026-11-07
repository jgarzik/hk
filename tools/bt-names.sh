#!/bin/bash
#
# Boot test verdict names, in order (a refactoring aid, not in the gate)
#
#   tools/bt-names.sh LOG          print LOG's NAME:OK|SKIP|FAIL verdicts
#   tools/bt-names.sh OLD NEW      diff the two logs' verdict sequences
#
# LOG is a serial log: target/qemu/serial{,_arm}.log (hk) or
# target/linux-test-<arch>/serial.clean (Linux). Matches are not
# anchored at line start: some verdicts follow debug output on one line.
# hk logs can show a verdict torn by a concurrent writer (BUGS.md, TTY
# gaps), so compare Linux logs for an exact sequence, made by a run with
# LINUX_NOCACHE=1: a cached check-linux PASS leaves serial.clean as it was.

set -euo pipefail

# A name starts uppercase; some carry a device name (BLK_RDEV_vda1)
names() {
    grep -aoE '[A-Z][A-Za-z0-9_]*:(OK|SKIP|FAIL)' "$1"
}

# A missing or verdict-less log is an error, never "same sequence"
check() {
    [ -r "$1" ] || { echo "$0: cannot read $1" >&2; exit 2; }
    names "$1" > /dev/null || { echo "$0: no verdicts in $1" >&2; exit 2; }
}

case $# in
    1) check "$1"; names "$1" ;;
    2) check "$1"; check "$2"
       diff <(names "$1") <(names "$2") && echo "same sequence ($(names "$2" | wc -l) verdicts)" ;;
    *) echo "usage: $0 LOG | $0 OLD NEW" >&2; exit 2 ;;
esac
