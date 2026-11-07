//! adjtimex syscall tests
//!
//! Tests:
//! - Test adjtimex read-only query (modes=0)
//! - Test adjtimex returns TIME_ERROR when unsynchronized
//! - Test adjtimex setting maxerror/esterror
//! - Test adjtimex returns EINVAL for invalid tick
//! - ADJTIMEX_OFFSET: two processes inject +1 s with ADJ_SETOFFSET at
//!   once; realtime moves 2 s against monotonic (Linux
//!   timekeeping_inject_offset adds inside the lock: no offset is lost)

use crate::tests::helpers::{print, print_num, println};
use hk_syscall::{
    ADJ_ESTERROR, ADJ_MAXERROR, ADJ_TICK, STA_UNSYNC, TIME_ERROR, Timex, sys_adjtimex,
};

/// Run all adjtimex tests
pub fn run_tests() {
    test_adjtimex_query();
    test_adjtimex_unsync();
    test_adjtimex_set_errors();
    test_adjtimex_invalid_tick();
    test_adjtimex_offset();
    test_adjtimex_freq_constant();
}

/// ADJ_FREQUENCY reads back (clamped at 500 ppm); ADJ_TIMECONST is
/// clamped to 0..MAXTC with +4 in microsecond mode; errors clamp to
/// NTP_PHASE_LIMIT (Linux process_adjtimex_modes)
fn test_adjtimex_freq_constant() {
    const ADJ_FREQUENCY: u32 = 0x0002;
    const ADJ_TIMECONST: u32 = 0x0020;
    const ADJ_MICRO: u32 = 0x1000;
    const ADJ_NANO: u32 = 0x2000;
    let set = |modes: u32, f: &dyn Fn(&mut Timex)| {
        let mut t = Timex::default();
        t.modes = modes;
        f(&mut t);
        sys_adjtimex(&mut t);
        let mut r = Timex::default();
        sys_adjtimex(&mut r);
        r
    };
    let mut step = 0;
    if set(ADJ_FREQUENCY, &|t| t.freq = 65536).freq != 65536 {
        step = 1;
    } else if set(ADJ_FREQUENCY, &|t| t.freq = 600 << 16).freq != 500 << 16 {
        step = 2;
    } else if set(ADJ_TIMECONST | ADJ_MICRO, &|t| t.constant = 3).constant != 7 {
        step = 3;
    } else if set(ADJ_TIMECONST | ADJ_MICRO, &|t| t.constant = 20).constant != 10 {
        step = 4;
    } else if set(ADJ_MAXERROR, &|t| t.maxerror = i64::MAX).maxerror != 16_000_000 {
        step = 5;
    }
    // Restore: no frequency offset, Linux's default constant 2
    set(ADJ_FREQUENCY, &|t| t.freq = 0);
    set(ADJ_TIMECONST | ADJ_NANO, &|t| t.constant = 2);
    set(ADJ_MICRO, &|_| {});
    print(b"ADJTIMEX_FREQ_CONSTANT");
    if step == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(step);
        println(b"");
    }
}

/// Test adjtimex read-only query (modes=0)
fn test_adjtimex_query() {
    let mut txc = Timex::default();
    let ret = sys_adjtimex(&mut txc);

    if ret < 0 {
        print(b"ADJTIMEX_QUERY:FAIL: returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Check that time was returned (should be > 0 since kernel has been running)
    // Note: time.tv_sec could be 0 if RTC was not available, so check if it's >= 0
    if txc.time.tv_sec >= 0 {
        println(b"ADJTIMEX_QUERY:OK");
    } else {
        print(b"ADJTIMEX_QUERY:FAIL: time.tv_sec=");
        print_num(txc.time.tv_sec);
        println(b"");
    }
}

/// Test adjtimex returns TIME_ERROR when unsynchronized
fn test_adjtimex_unsync() {
    let mut txc = Timex::default();
    let ret = sys_adjtimex(&mut txc);

    // Initially clock should be unsynchronized
    if ret == TIME_ERROR as i64 && (txc.status & STA_UNSYNC != 0) {
        println(b"ADJTIMEX_UNSYNC:OK");
    } else {
        print(b"ADJTIMEX_UNSYNC:FAIL: ret=");
        print_num(ret);
        print(b" status=");
        print_num(txc.status as i64);
        println(b"");
    }
}

/// Test setting maxerror/esterror
fn test_adjtimex_set_errors() {
    let mut txc = Timex::default();
    txc.modes = ADJ_MAXERROR | ADJ_ESTERROR;
    txc.maxerror = 100000; // 0.1 sec
    txc.esterror = 50000; // 0.05 sec

    let ret = sys_adjtimex(&mut txc);

    // Should succeed (we allow modifications in our simplified implementation)
    if ret >= 0 {
        // Verify values were set
        let mut txc2 = Timex::default();
        sys_adjtimex(&mut txc2);

        if txc2.maxerror == 100000 && txc2.esterror == 50000 {
            println(b"ADJTIMEX_SET_ERRORS:OK");
        } else {
            print(b"ADJTIMEX_SET_ERRORS:FAIL: maxerror=");
            print_num(txc2.maxerror);
            print(b" esterror=");
            print_num(txc2.esterror);
            println(b"");
        }
    } else {
        print(b"ADJTIMEX_SET_ERRORS:FAIL: ret=");
        print_num(ret);
        println(b"");
    }
}

/// Test adjtimex returns EINVAL for invalid tick value
fn test_adjtimex_invalid_tick() {
    let mut txc = Timex::default();
    txc.modes = ADJ_TICK;
    txc.tick = 1000; // Way too small (should be ~10000 +/- 10%)

    let ret = sys_adjtimex(&mut txc);

    // Should return EINVAL (-22)
    if ret == -22 {
        println(b"ADJTIMEX_INVALID_TICK:OK");
    } else {
        print(b"ADJTIMEX_INVALID_TICK:FAIL: expected EINVAL(-22), got ");
        print_num(ret);
        println(b"");
    }
}

fn clock_ns(id: i32) -> i64 {
    let mut ts = hk_syscall::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    hk_syscall::sys_clock_gettime(id, &mut ts);
    ts.tv_sec * 1_000_000_000 + ts.tv_nsec
}

/// REALTIME - MONOTONIC, ns
fn real_minus_mono() -> i64 {
    clock_ns(0) - clock_ns(1)
}

fn set_offset(sec: i64) -> i64 {
    let mut txc = Timex::default();
    txc.modes = hk_syscall::ADJ_SETOFFSET;
    txc.time.tv_sec = sec;
    txc.time.tv_usec = 0;
    sys_adjtimex(&mut txc)
}

fn test_adjtimex_offset() {
    let before = real_minus_mono();
    let kids: [i64; 2] = core::array::from_fn(|_| {
        let pid = hk_syscall::sys_fork();
        if pid == 0 {
            let r = set_offset(1);
            hk_syscall::sys_exit((r < 0) as u64);
        }
        pid
    });
    let mut ok = true;
    for pid in kids {
        let mut ws = 0;
        ok &= hk_syscall::sys_wait4(pid, &mut ws, 0, 0) == pid && ws == 0;
    }
    let moved = real_minus_mono() - before;
    set_offset(-2);
    let off = moved - 2_000_000_000;
    if ok && off.abs() < 50_000_000 {
        println(b"ADJTIMEX_OFFSET:OK");
    } else {
        print(b"ADJTIMEX_OFFSET:FAIL moved ns ");
        print_num(moved);
        println(b"");
    }
}
