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
//! - futex_waitv tests (error cases and basic operation)

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_futex, sys_futex_waitv, sys_get_robust_list, sys_set_robust_list,
    FutexWaitv, RobustListHead, FUTEX2_PRIVATE, FUTEX2_SIZE_U32,
    FUTEX_PRIVATE_FLAG, FUTEX_WAIT, FUTEX_WAKE, CLOCK_MONOTONIC,
};
use core::ptr;

/// Run all futex tests
pub fn run_tests() {
    test_futex_wake_no_waiters();
    test_futex_wait_wrong_value();
    test_set_robust_list();
    test_set_robust_list_einval();
    test_get_robust_list();
    // futex_waitv tests
    test_futex_waitv_invalid_flags();
    test_futex_waitv_invalid_count_zero();
    test_futex_waitv_invalid_count_too_large();
    test_futex_waitv_null_waiters();
    test_futex_waitv_reserved_nonzero();
    test_futex_waitv_wrong_value();
    test_futex_waitv_invalid_size();
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

// =============================================================================
// futex_waitv tests
// =============================================================================

/// Test: futex_waitv with non-zero flags should return -EINVAL (-22)
fn test_futex_waitv_invalid_flags() {
    let futex_val: u32 = 0;
    let waitv = [FutexWaitv::new(
        &futex_val as *const u32 as u64,
        0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
    )];

    let ret = sys_futex_waitv(
        waitv.as_ptr(),
        1,                   // nr_futexes
        1,                   // flags (non-zero = invalid)
        ptr::null(),         // no timeout
        CLOCK_MONOTONIC,
    );

    if ret == -22 {
        // EINVAL
        println(b"FUTEX_WAITV_FLAGS:OK");
    } else {
        print(b"FUTEX_WAITV_FLAGS:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test: futex_waitv with nr_futexes=0 should return -EINVAL (-22)
fn test_futex_waitv_invalid_count_zero() {
    let futex_val: u32 = 0;
    let waitv = [FutexWaitv::new(
        &futex_val as *const u32 as u64,
        0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
    )];

    let ret = sys_futex_waitv(
        waitv.as_ptr(),
        0,                   // nr_futexes = 0 (invalid)
        0,
        ptr::null(),
        CLOCK_MONOTONIC,
    );

    if ret == -22 {
        // EINVAL
        println(b"FUTEX_WAITV_COUNT_ZERO:OK");
    } else {
        print(b"FUTEX_WAITV_COUNT_ZERO:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test: futex_waitv with nr_futexes > 128 should return -EINVAL (-22)
fn test_futex_waitv_invalid_count_too_large() {
    let futex_val: u32 = 0;
    let waitv = [FutexWaitv::new(
        &futex_val as *const u32 as u64,
        0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
    )];

    let ret = sys_futex_waitv(
        waitv.as_ptr(),
        129,                 // nr_futexes > 128 (invalid)
        0,
        ptr::null(),
        CLOCK_MONOTONIC,
    );

    if ret == -22 {
        // EINVAL
        println(b"FUTEX_WAITV_COUNT_LARGE:OK");
    } else {
        print(b"FUTEX_WAITV_COUNT_LARGE:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test: futex_waitv with null waiters should return -EINVAL (-22)
fn test_futex_waitv_null_waiters() {
    let ret = sys_futex_waitv(
        ptr::null(),         // null waiters (invalid)
        1,
        0,
        ptr::null(),
        CLOCK_MONOTONIC,
    );

    if ret == -22 {
        // EINVAL
        println(b"FUTEX_WAITV_NULL:OK");
    } else {
        print(b"FUTEX_WAITV_NULL:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test: futex_waitv with non-zero __reserved should return -EINVAL (-22)
fn test_futex_waitv_reserved_nonzero() {
    let futex_val: u32 = 0;
    // Create a waitv with non-zero reserved field
    let waitv = [FutexWaitv {
        val: 0,
        uaddr: &futex_val as *const u32 as u64,
        flags: FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
        __reserved: 1,  // non-zero (invalid)
    }];

    let ret = sys_futex_waitv(
        waitv.as_ptr(),
        1,
        0,
        ptr::null(),
        CLOCK_MONOTONIC,
    );

    if ret == -22 {
        // EINVAL
        println(b"FUTEX_WAITV_RESERVED:OK");
    } else {
        print(b"FUTEX_WAITV_RESERVED:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test: futex_waitv with wrong value should return -EAGAIN (-11)
fn test_futex_waitv_wrong_value() {
    let futex_val: u32 = 42;  // actual value
    let waitv = [FutexWaitv::new(
        &futex_val as *const u32 as u64,
        0,                   // expected value (different from actual)
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
    )];

    let ret = sys_futex_waitv(
        waitv.as_ptr(),
        1,
        0,
        ptr::null(),
        CLOCK_MONOTONIC,
    );

    if ret == -11 {
        // EAGAIN
        println(b"FUTEX_WAITV_WRONG_VAL:OK");
    } else {
        print(b"FUTEX_WAITV_WRONG_VAL:FAIL: expected -11 (EAGAIN), got ");
        print_num(ret);
    }
}

/// Test: futex_waitv with invalid size (not U32) should return -EINVAL (-22)
fn test_futex_waitv_invalid_size() {
    let futex_val: u32 = 0;
    // Try with SIZE_U64 which is not supported
    let waitv = [FutexWaitv::new(
        &futex_val as *const u32 as u64,
        0,
        0x03 | FUTEX2_PRIVATE,  // SIZE_U64 = 0x03
    )];

    let ret = sys_futex_waitv(
        waitv.as_ptr(),
        1,
        0,
        ptr::null(),
        CLOCK_MONOTONIC,
    );

    if ret == -22 {
        // EINVAL
        println(b"FUTEX_WAITV_SIZE:OK");
    } else {
        print(b"FUTEX_WAITV_SIZE:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}
