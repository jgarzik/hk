//! io_uring_setup: sizes rounded up to powers of two (CLAMP past the
//! limits), the CQ twice the SQ, features and ring offsets filled in
//! (Linux io_uring_fill_params, io_prepare_config)

use crate::harness::{fail_num, pass};
use crate::helpers::{print, print_num, println};
use hk_syscall::{IORING_SETUP_CLAMP, IoUringParams, sys_close, sys_io_uring_setup};

pub fn run_tests() {
    test_io_uring_setup_basic();
    test_io_uring_setup_einval_zero();
    test_io_uring_setup_round_non_pow2();
    test_io_uring_setup_clamp();
    test_io_uring_setup_params_filled();
}

/// Test io_uring_setup with valid parameters
fn test_io_uring_setup_basic() {
    let mut params = IoUringParams::default();
    let fd = sys_io_uring_setup(8, &mut params as *mut IoUringParams);
    if fd < 0 {
        fail_num(b"IO_URING_SETUP:FAIL: returned ", fd);
        return;
    }

    // Close the fd
    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        fail_num(b"IO_URING_SETUP:FAIL: close returned ", close_ret);
        return;
    }

    pass(b"IO_URING_SETUP");
}

/// Test io_uring_setup rejects 0 entries
fn test_io_uring_setup_einval_zero() {
    let mut params = IoUringParams::default();
    let fd = sys_io_uring_setup(0, &mut params as *mut IoUringParams);

    // Should return -EINVAL (-22)
    if fd == -22 {
        pass(b"IO_URING_SETUP_EINVAL_ZERO");
    } else {
        fail_num(b"IO_URING_SETUP_EINVAL_ZERO:FAIL: expected -22, got ", fd);
        if fd >= 0 {
            sys_close(fd as u64);
        }
    }
}

/// Test io_uring_setup rounds non-power-of-2 entries up even without CLAMP
/// (Linux io_uring_fill_params: roundup_pow_of_two)
fn test_io_uring_setup_round_non_pow2() {
    let mut params = IoUringParams::default();
    let fd = sys_io_uring_setup(5, &mut params as *mut IoUringParams);
    if fd >= 0 && params.sq_entries == 8 && params.cq_entries == 16 {
        pass(b"IO_URING_SETUP_ROUND_POW2");
    } else {
        print(b"IO_URING_SETUP_ROUND_POW2:FAIL: expected fd>=0 sq=8, got fd=");
        print_num(fd);
        print(b" sq=");
        print_num(params.sq_entries as i64);
        println(b"");
    }
    if fd >= 0 {
        sys_close(fd as u64);
    }
}

/// Test io_uring_setup with IORING_SETUP_CLAMP rounds up to power of 2
fn test_io_uring_setup_clamp() {
    let mut params = IoUringParams::default();
    params.flags = IORING_SETUP_CLAMP;

    // 5 should be rounded up to 8 with CLAMP flag
    let fd = sys_io_uring_setup(5, &mut params as *mut IoUringParams);
    if fd < 0 {
        fail_num(b"IO_URING_SETUP_CLAMP:FAIL: returned ", fd);
        return;
    }

    // Check that sq_entries was rounded up to 8
    if params.sq_entries != 8 {
        fail_num(
            b"IO_URING_SETUP_CLAMP:FAIL: sq_entries expected 8, got ",
            params.sq_entries as i64,
        );
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"IO_URING_SETUP_CLAMP");
}

/// Test io_uring_setup fills in params correctly
fn test_io_uring_setup_params_filled() {
    let mut params = IoUringParams::default();
    let fd = sys_io_uring_setup(16, &mut params as *mut IoUringParams);
    if fd < 0 {
        fail_num(b"IO_URING_PARAMS:FAIL: setup returned ", fd);
        return;
    }

    // Check sq_entries
    if params.sq_entries != 16 {
        fail_num(
            b"IO_URING_PARAMS:FAIL: sq_entries expected 16, got ",
            params.sq_entries as i64,
        );
        sys_close(fd as u64);
        return;
    }

    // Check cq_entries (should be 2x sq_entries by default, capped at max)
    if params.cq_entries != 32 {
        fail_num(
            b"IO_URING_PARAMS:FAIL: cq_entries expected 32, got ",
            params.cq_entries as i64,
        );
        sys_close(fd as u64);
        return;
    }

    // Check features has at least IORING_FEAT_SINGLE_MMAP
    if params.features == 0 {
        print(b"IO_URING_PARAMS:FAIL: features is 0");
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Check sq_off has reasonable values
    if params.sq_off.array == 0 {
        print(b"IO_URING_PARAMS:FAIL: sq_off.array is 0");
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Check cq_off has reasonable values
    if params.cq_off.cqes == 0 {
        print(b"IO_URING_PARAMS:FAIL: cq_off.cqes is 0");
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"IO_URING_PARAMS");
}
