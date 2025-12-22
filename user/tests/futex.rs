//! Futex tests
//!
//! Tests for fast userspace mutex (futex) syscalls.
//!
//! Tests:
//! - FUTEX_WAKE with no waiters returns 0
//! - FUTEX_WAIT with wrong value returns -EAGAIN
//! - set_robust_list with correct size returns 0
//! - set_robust_list with wrong size returns -EINVAL
//! - get_robust_list returns 0

use super::helpers::{print, print_num, println};
use crate::syscall::{
    sys_futex, sys_get_robust_list, sys_set_robust_list, RobustListHead, Timespec,
    FUTEX_PRIVATE_FLAG, FUTEX_WAIT, FUTEX_WAKE,
};
use core::ptr;

/// Run all futex tests
pub fn run_tests() {
    test_futex_wake_no_waiters();
    test_futex_wait_wrong_value();
    test_set_robust_list();
    test_set_robust_list_einval();
    test_get_robust_list();
}

/// Test: FUTEX_WAKE with no waiters should return 0
fn test_futex_wake_no_waiters() {
    let mut futex_val: u32 = 0;
    let ret = sys_futex(
        &mut futex_val as *mut u32,
        FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
        1,                    // wake up to 1 waiter
        ptr::null(),          // no timeout
        ptr::null_mut(),      // no uaddr2
        0,                    // no val3
    );

    if ret == 0 {
        println(b"FUTEX_WAKE_NONE:OK");
    } else {
        print(b"FUTEX_WAKE_NONE:FAIL: expected 0, got ");
        print_num(ret);
    }
}

/// Test: FUTEX_WAIT with wrong value should return -EAGAIN (-11)
fn test_futex_wait_wrong_value() {
    let mut futex_val: u32 = 42;
    let ret = sys_futex(
        &mut futex_val as *mut u32,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        0,                    // expected value (different from actual)
        ptr::null(),          // no timeout
        ptr::null_mut(),      // no uaddr2
        0,                    // no val3
    );

    if ret == -11 {
        // EAGAIN
        println(b"FUTEX_WAIT_EAGAIN:OK");
    } else {
        print(b"FUTEX_WAIT_EAGAIN:FAIL: expected -11 (EAGAIN), got ");
        print_num(ret);
    }
}

/// Test: set_robust_list with correct size should return 0
fn test_set_robust_list() {
    let robust_head = RobustListHead {
        list: 0,
        futex_offset: 0,
        list_op_pending: 0,
    };

    let ret = sys_set_robust_list(&robust_head, RobustListHead::SIZE);

    if ret == 0 {
        println(b"SET_ROBUST_LIST:OK");
    } else {
        print(b"SET_ROBUST_LIST:FAIL: expected 0, got ");
        print_num(ret);
    }

    // Clear it by setting null
    let _ = sys_set_robust_list(ptr::null(), RobustListHead::SIZE);
}

/// Test: set_robust_list with wrong size should return -EINVAL (-22)
fn test_set_robust_list_einval() {
    let robust_head = RobustListHead {
        list: 0,
        futex_offset: 0,
        list_op_pending: 0,
    };

    // Use wrong size
    let ret = sys_set_robust_list(&robust_head, 1);

    if ret == -22 {
        // EINVAL
        println(b"SET_ROBUST_LIST_EINVAL:OK");
    } else {
        print(b"SET_ROBUST_LIST_EINVAL:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test: get_robust_list for current task should return 0
fn test_get_robust_list() {
    // First set a robust list so we can get it
    let robust_head = RobustListHead {
        list: 0,
        futex_offset: 0,
        list_op_pending: 0,
    };
    let _ = sys_set_robust_list(&robust_head, RobustListHead::SIZE);

    // Now get it
    let mut head_ptr: *const RobustListHead = ptr::null();
    let mut len: usize = 0;

    let ret = sys_get_robust_list(
        0, // current task
        &mut head_ptr as *mut *const RobustListHead,
        &mut len,
    );

    if ret == 0 {
        println(b"GET_ROBUST_LIST:OK");
    } else {
        print(b"GET_ROBUST_LIST:FAIL: expected 0, got ");
        print_num(ret);
    }

    // Clear it
    let _ = sys_set_robust_list(ptr::null(), RobustListHead::SIZE);
}
