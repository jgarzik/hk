//! Setting the clock needs CAP_SYS_TIME (Linux kernel/time/time.c
//! do_sys_settimeofday64 -> security_settime64, timekeeping.c
//! timekeeping_validate_timex)
//!
//! Tests:
//! - SETTIME_PERM: as nobody, clock_settime(CLOCK_REALTIME),
//!   settimeofday and adjtimex with a mode bit set are EPERM;
//!   clock_settime of a clock that cannot be set is EINVAL first;
//!   adjtimex with no mode (a read) works; the read-only old-adjtime
//!   query (ADJ_OFFSET_SS_READ) is allowed but sets nothing else it
//!   carries (Linux __do_adjtimex ignores the other bits there)

use crate::tests::harness::fail_num;
use crate::tests::helpers::{print, println};
use hk_syscall::{
    CLOCK_MONOTONIC, CLOCK_REALTIME, Timespec, Timeval, Timex, sys_adjtimex, sys_clock_gettime,
    sys_clock_settime, sys_exit, sys_fork, sys_setresuid, sys_settimeofday, sys_wait4,
};

const EPERM: i64 = -1;
const EINVAL: i64 = -22;
const ADJ_MAXERROR: u32 = 0x0004;
const ADJ_OFFSET_SS_READ: u32 = 0xa001;
const NOBODY: u32 = 65534;

pub fn run_tests() {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(child());
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    print(b"SETTIME_PERM");
    if st == 0 {
        println(b":OK");
    } else {
        fail_num(b":FAIL status ", st as i64);
    }
}

/// The first failed step (0: all passed)
fn child() -> u64 {
    if sys_setresuid(NOBODY, NOBODY, NOBODY) != 0 {
        return 1;
    }
    let mut now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_REALTIME, &mut now);
    if sys_clock_settime(CLOCK_REALTIME, &now) != EPERM {
        return 2;
    }
    if sys_clock_settime(CLOCK_MONOTONIC, &now) != EINVAL {
        return 3;
    }
    let tv = Timeval {
        tv_sec: now.tv_sec,
        tv_usec: 0,
    };
    if sys_settimeofday(&tv, core::ptr::null()) != EPERM {
        return 4;
    }
    // SAFETY: plain integers
    let mut tx: Timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_MAXERROR;
    tx.maxerror = 1000;
    if sys_adjtimex(&mut tx) != EPERM {
        return 5;
    }
    // SAFETY: plain integers
    let mut rd: Timex = unsafe { core::mem::zeroed() };
    if sys_adjtimex(&mut rd) < 0 {
        return 6;
    }
    // SAFETY: plain integers
    let mut ss: Timex = unsafe { core::mem::zeroed() };
    ss.modes = ADJ_OFFSET_SS_READ | ADJ_MAXERROR;
    ss.maxerror = rd.maxerror + 12345;
    if sys_adjtimex(&mut ss) < 0 {
        return 7;
    }
    // SAFETY: plain integers
    let mut after: Timex = unsafe { core::mem::zeroed() };
    sys_adjtimex(&mut after);
    // maxerror grows by itself over time; a jump by the value given is
    // the bypass
    if after.maxerror >= rd.maxerror + 12345 {
        return 8;
    }
    0
}
