//! adjtimex syscall tests
//!
//! Tests:
//! - Test adjtimex read-only query (modes=0)
//! - Test adjtimex returns TIME_ERROR when unsynchronized
//! - Test adjtimex setting maxerror/esterror
//! - Test adjtimex returns EINVAL for invalid tick

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_adjtimex, Timex, ADJ_MAXERROR, ADJ_ESTERROR, ADJ_TICK,
    TIME_ERROR, STA_UNSYNC,
};

/// Run all adjtimex tests
pub fn run_tests() {
    test_adjtimex_query();
    test_adjtimex_unsync();
    test_adjtimex_set_errors();
    test_adjtimex_invalid_tick();
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
    txc.esterror = 50000;  // 0.05 sec

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
