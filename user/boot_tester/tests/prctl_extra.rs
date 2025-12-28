//! Additional prctl tests
//!
//! Tests for PR_SET/GET_KEEPCAPS and PR_SET/GET_CHILD_SUBREAPER

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_prctl, PR_GET_CHILD_SUBREAPER, PR_GET_KEEPCAPS, PR_SET_CHILD_SUBREAPER, PR_SET_KEEPCAPS,
};

/// Run all prctl extra tests
pub fn run_tests() {
    test_keepcaps_default();
    test_keepcaps_set_get();
    test_keepcaps_invalid();
    test_child_subreaper_default();
    test_child_subreaper_set_get();
}

/// Test: KEEPCAPS defaults to 0
fn test_keepcaps_default() {
    let ret = sys_prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
    if ret == 0 {
        println(b"PRCTL_KEEPCAPS_DEFAULT:OK");
    } else {
        print(b"PRCTL_KEEPCAPS_DEFAULT:FAIL: expected 0, got ");
        print_num(ret);
        println(b"");
    }
}

/// Test: Set and get KEEPCAPS
fn test_keepcaps_set_get() {
    // Set to 1
    let ret = sys_prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_KEEPCAPS_SET:FAIL: set returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Get - should be 1
    let ret = sys_prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
    if ret != 1 {
        print(b"PRCTL_KEEPCAPS_SET:FAIL: get returned ");
        print_num(ret);
        println(b" expected 1");
        return;
    }

    // Set back to 0
    let ret = sys_prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_KEEPCAPS_SET:FAIL: clear returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Get - should be 0
    let ret = sys_prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_KEEPCAPS_SET:FAIL: get after clear returned ");
        print_num(ret);
        println(b"");
        return;
    }

    println(b"PRCTL_KEEPCAPS_SET:OK");
}

/// Test: KEEPCAPS with invalid value returns EINVAL
fn test_keepcaps_invalid() {
    // Value > 1 should fail
    let ret = sys_prctl(PR_SET_KEEPCAPS, 2, 0, 0, 0);
    if ret == -22 {
        // EINVAL
        println(b"PRCTL_KEEPCAPS_INVALID:OK");
    } else {
        print(b"PRCTL_KEEPCAPS_INVALID:FAIL: expected -22, got ");
        print_num(ret);
        println(b"");
    }
}

/// Test: CHILD_SUBREAPER defaults to 0
fn test_child_subreaper_default() {
    // PR_GET_CHILD_SUBREAPER returns value via pointer
    let mut value: i32 = -1;
    let ret = sys_prctl(
        PR_GET_CHILD_SUBREAPER,
        &mut value as *mut i32 as u64,
        0,
        0,
        0,
    );
    if ret != 0 {
        print(b"PRCTL_SUBREAPER_DEFAULT:FAIL: get returned ");
        print_num(ret);
        println(b"");
        return;
    }
    if value == 0 {
        println(b"PRCTL_SUBREAPER_DEFAULT:OK");
    } else {
        print(b"PRCTL_SUBREAPER_DEFAULT:FAIL: expected 0, got ");
        print_num(value as i64);
        println(b"");
    }
}

/// Test: Set and get CHILD_SUBREAPER
fn test_child_subreaper_set_get() {
    // Set to 1
    let ret = sys_prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_SUBREAPER_SET:FAIL: set returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Get - should be 1
    let mut value: i32 = -1;
    let ret = sys_prctl(
        PR_GET_CHILD_SUBREAPER,
        &mut value as *mut i32 as u64,
        0,
        0,
        0,
    );
    if ret != 0 {
        print(b"PRCTL_SUBREAPER_SET:FAIL: get returned ");
        print_num(ret);
        println(b"");
        return;
    }
    if value != 1 {
        print(b"PRCTL_SUBREAPER_SET:FAIL: expected 1, got ");
        print_num(value as i64);
        println(b"");
        return;
    }

    // Set back to 0
    let ret = sys_prctl(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_SUBREAPER_SET:FAIL: clear returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Get - should be 0
    let mut value: i32 = -1;
    let ret = sys_prctl(
        PR_GET_CHILD_SUBREAPER,
        &mut value as *mut i32 as u64,
        0,
        0,
        0,
    );
    if ret != 0 || value != 0 {
        print(b"PRCTL_SUBREAPER_SET:FAIL: after clear, got ");
        print_num(value as i64);
        println(b"");
        return;
    }

    println(b"PRCTL_SUBREAPER_SET:OK");
}
