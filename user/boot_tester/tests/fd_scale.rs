//! Picking the lowest free descriptor (Linux fs/file.c alloc_fd,
//! find_next_fd: two-level bitmap) costs about the same however many
//! descriptors are open
//!
//! Tests:
//! - FD_ALLOC_SCALE: with ~33000 descriptors open, a batch of dup()s
//!   takes less than 4x what the same batch takes with ~2000 open (a
//!   scan from fd 0 per allocation is ~16x)

use super::helpers::{print, print_num, println};
use hk_syscall::{
    CLOCK_MONOTONIC, O_RDONLY, RLIMIT_NOFILE, RLimit, Timespec, sys_clock_gettime,
    sys_close_range, sys_dup, sys_open, sys_setrlimit,
};

const LOW: i64 = 1000;
const HIGH: i64 = 32000;
const BATCH: i64 = 2000;
const TRIES: usize = 3;

pub fn run_tests() {
    let r = scale();
    print(b"FD_ALLOC_SCALE");
    if r == 0 {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(r);
        println(b"");
    }
}

fn now_ns() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec * 1_000_000_000 + ts.tv_nsec
}

/// dup `fd` until the newest descriptor is at least `top`; false on error
fn fill(fd: i64, top: i64) -> bool {
    loop {
        let n = sys_dup(fd as i32);
        if n < 0 {
            return false;
        }
        if n >= top {
            return true;
        }
    }
}

/// Fastest of TRIES timings of BATCH dup()s above `top` (-1 on error)
fn batch_ns(fd: i64, top: i64) -> i64 {
    let mut best = i64::MAX;
    for _ in 0..TRIES {
        let t = now_ns();
        for _ in 0..BATCH {
            if sys_dup(fd as i32) < 0 {
                return -1;
            }
        }
        best = best.min(now_ns() - t);
        sys_close_range(top as u32 + 1, u32::MAX, 0);
    }
    best
}

fn scale() -> i64 {
    let lim = RLimit {
        rlim_cur: (HIGH + BATCH + 64) as u64,
        rlim_max: (HIGH + BATCH + 64) as u64,
    };
    if sys_setrlimit(RLIMIT_NOFILE, &lim) != 0 {
        return 1;
    }
    let fd = sys_open(b"/\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 || !fill(fd, LOW) {
        return 2;
    }
    let low = batch_ns(fd, LOW);
    if low <= 0 || !fill(fd, HIGH) {
        return 3;
    }
    let high = batch_ns(fd, HIGH);
    sys_close_range(fd as u32, u32::MAX, 0);
    if high < 0 {
        return 4;
    }
    if high >= 4 * low {
        print(b"FD_ALLOC_SCALE: batch ns at ~2000 fds ");
        print_num(low);
        print(b", at ~33000 fds ");
        print_num(high);
        println(b"");
        return 5;
    }
    0
}
