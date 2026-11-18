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
//! - FUTEX_UNALIGNED: a futex word not 4-byte aligned is EINVAL for
//!   wait, wake and a requeue target (Linux get_futex_key)

use crate::harness::pass;
use crate::helpers::{linux_at_least, print, print_num, println, skip};
use core::ptr;
use hk_syscall::{
    CLOCK_MONOTONIC, FUTEX_PRIVATE_FLAG, FUTEX_WAIT, FUTEX_WAKE, FUTEX2_MPOL, FUTEX2_NUMA,
    FUTEX2_PRIVATE, FUTEX2_SIZE_U32, FutexWaitv, RobustListHead, sys_futex, sys_futex_waitv,
    sys_get_robust_list, sys_getcpu, sys_set_robust_list,
};

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
    test_futex_waitv_val_range();
    test_futex_waitv_numa();
    test_futex_unaligned();
}

fn test_futex_unaligned() {
    const EINVAL: i64 = -22;
    let mut words = [0u32; 3];
    let base = words.as_mut_ptr();
    // SAFETY: byte 1 of `words`, inside the array
    let odd = unsafe { (base as *mut u8).add(1) } as *mut u32;
    // A short timeout: should the wait be accepted, it ends
    let ts = hk_syscall::Timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    let pf = FUTEX_PRIVATE_FLAG;
    let r = [
        sys_futex(odd, FUTEX_WAIT | pf, 0, &ts, ptr::null_mut(), 0),
        sys_futex(odd, FUTEX_WAKE | pf, 1, ptr::null(), ptr::null_mut(), 0),
        sys_futex(
            base,
            hk_syscall::FUTEX_CMP_REQUEUE | pf,
            1,
            1 as *const hk_syscall::Timespec,
            odd,
            0,
        ),
    ];
    match r.iter().position(|&x| x != EINVAL) {
        None => println(b"FUTEX_UNALIGNED:OK"),
        Some(i) => {
            print(b"FUTEX_UNALIGNED:FAIL op ");
            print_num(i as i64);
            print(b" got ");
            print_num(r[i]);
            println(b"");
        }
    }
}

/// Test: FUTEX_WAKE with no waiters should return 0
fn test_futex_wake_no_waiters() {
    let mut futex_val: u32 = 0;
    let ret = sys_futex(
        &mut futex_val as *mut u32,
        FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
        1,               // wake up to 1 waiter
        ptr::null(),     // no timeout
        ptr::null_mut(), // no uaddr2
        0,               // no val3
    );

    if ret == 0 {
        pass(b"FUTEX_WAKE_NONE");
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
        0,               // expected value (different from actual)
        ptr::null(),     // no timeout
        ptr::null_mut(), // no uaddr2
        0,               // no val3
    );

    if ret == -11 {
        // EAGAIN
        pass(b"FUTEX_WAIT_EAGAIN");
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
        pass(b"SET_ROBUST_LIST");
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
        pass(b"SET_ROBUST_LIST_EINVAL");
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
        pass(b"GET_ROBUST_LIST");
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
        1,           // nr_futexes
        1,           // flags (non-zero = invalid)
        ptr::null(), // no timeout
        CLOCK_MONOTONIC,
    );

    if ret == -22 {
        // EINVAL
        pass(b"FUTEX_WAITV_FLAGS");
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
        0, // nr_futexes = 0 (invalid)
        0,
        ptr::null(),
        CLOCK_MONOTONIC,
    );

    if ret == -22 {
        // EINVAL
        pass(b"FUTEX_WAITV_COUNT_ZERO");
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
        129, // nr_futexes > 128 (invalid)
        0,
        ptr::null(),
        CLOCK_MONOTONIC,
    );

    if ret == -22 {
        // EINVAL
        pass(b"FUTEX_WAITV_COUNT_LARGE");
    } else {
        print(b"FUTEX_WAITV_COUNT_LARGE:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test: futex_waitv with null waiters should return -EINVAL (-22)
fn test_futex_waitv_null_waiters() {
    let ret = sys_futex_waitv(
        ptr::null(), // null waiters (invalid)
        1,
        0,
        ptr::null(),
        CLOCK_MONOTONIC,
    );

    if ret == -22 {
        // EINVAL
        pass(b"FUTEX_WAITV_NULL");
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
        __reserved: 1, // non-zero (invalid)
    }];

    let ret = sys_futex_waitv(waitv.as_ptr(), 1, 0, ptr::null(), CLOCK_MONOTONIC);

    if ret == -22 {
        // EINVAL
        pass(b"FUTEX_WAITV_RESERVED");
    } else {
        print(b"FUTEX_WAITV_RESERVED:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test: futex_waitv with wrong value should return -EAGAIN (-11)
fn test_futex_waitv_wrong_value() {
    let futex_val: u32 = 42; // actual value
    let waitv = [FutexWaitv::new(
        &futex_val as *const u32 as u64,
        0, // expected value (different from actual)
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
    )];

    let ret = sys_futex_waitv(waitv.as_ptr(), 1, 0, ptr::null(), CLOCK_MONOTONIC);

    if ret == -11 {
        // EAGAIN
        pass(b"FUTEX_WAITV_WRONG_VAL");
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
        0x03 | FUTEX2_PRIVATE, // SIZE_U64 = 0x03
    )];

    let ret = sys_futex_waitv(waitv.as_ptr(), 1, 0, ptr::null(), CLOCK_MONOTONIC);

    if ret == -22 {
        // EINVAL
        pass(b"FUTEX_WAITV_SIZE");
    } else {
        print(b"FUTEX_WAITV_SIZE:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test: a value wider than the 32-bit word is EINVAL (Linux
/// futex_validate_input)
fn test_futex_waitv_val_range() {
    // Not the truncated value: a kernel that truncates says EAGAIN
    let futex_val: u32 = 1;
    let mut w = FutexWaitv::new(
        &futex_val as *const u32 as u64,
        0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
    );
    w.val = 1 << 32;
    let ret = sys_futex_waitv(&w, 1, 0, ptr::null(), CLOCK_MONOTONIC);
    if ret == -22 {
        pass(b"FUTEX_WAITV_VAL_RANGE");
    } else {
        print(b"FUTEX_WAITV_VAL_RANGE:FAIL: expected -22, got ");
        print_num(ret);
        println(b"");
    }
}

/// A FUTEX2_NUMA futex: the word and its node word
#[repr(C, align(8))]
struct NumaFutex([u32; 2]);

/// futex_waitv on a NUMA futex holding 42, expecting 0
fn waitv_numa(addr: u64, flags: u32) -> i64 {
    let w = FutexWaitv::new(addr, 0, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE | flags);
    sys_futex_waitv(&w, 1, 0, ptr::null(), CLOCK_MONOTONIC)
}

/// Test: FUTEX2_NUMA and FUTEX2_MPOL (Linux 6.16): an unset node word
/// gets this CPU's node (no policy set), a set one must name a node,
/// and the pair is 8-byte aligned
fn test_futex_waitv_numa() {
    if !linux_at_least(6, 16) {
        skip(b"FUTEX_WAITV_NUMA", b"Linux < 6.16");
        return;
    }
    let set = |flags: u32, name: &[u8]| {
        // The node of the CPU before and after: the task may migrate
        let (mut before, mut after) = (0u32, 0u32);
        let mut f = NumaFutex([42, u32::MAX]);
        sys_getcpu(ptr::null_mut(), &mut before);
        let ret = waitv_numa(f.0.as_mut_ptr() as u64, flags);
        sys_getcpu(ptr::null_mut(), &mut after);
        // SAFETY: the kernel wrote the node word during the call
        let got = unsafe { ptr::read_volatile(&f.0[1]) };
        if ret == -11 && (got == before || got == after) {
            pass(name);
        } else {
            print(name);
            print(b":FAIL: ret ");
            print_num(ret);
            print(b" node ");
            print_num(got as i64);
            println(b"");
        }
    };
    set(FUTEX2_NUMA, b"FUTEX_WAITV_NUMA_SET");
    set(FUTEX2_NUMA | FUTEX2_MPOL, b"FUTEX_WAITV_NUMA_MPOL");

    let f = NumaFutex([42, 4000]);
    let bad = waitv_numa(f.0.as_ptr() as u64, FUTEX2_NUMA);
    let mut pair = [NumaFutex([42, u32::MAX]), NumaFutex([42, u32::MAX])];
    let odd = waitv_numa(pair[0].0.as_mut_ptr() as u64 + 4, FUTEX2_NUMA);
    if bad == -22 && odd == -22 {
        pass(b"FUTEX_WAITV_NUMA_EINVAL");
    } else {
        print(b"FUTEX_WAITV_NUMA_EINVAL:FAIL: bad node ");
        print_num(bad);
        print(b" unaligned ");
        print_num(odd);
        println(b"");
    }
}
