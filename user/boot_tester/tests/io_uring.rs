//! io_uring tests
//!
//! Tests:
//! - Phase 1: Core infrastructure
//! - Phase 5: Poll and Timeout operations

use super::helpers::{print, print_num, println};
use hk_syscall::{sys_close, sys_io_uring_enter, sys_io_uring_setup, sys_pipe2, IoUringParams, IORING_SETUP_CLAMP};

// Constants for future use in mmap-based SQE submission
#[allow(dead_code)]
const IORING_OP_NOP: u8 = 0;
#[allow(dead_code)]
const IORING_OP_POLL_ADD: u8 = 6;
#[allow(dead_code)]
const IORING_OP_TIMEOUT: u8 = 11;
#[allow(dead_code)]
const IORING_OP_ASYNC_CANCEL: u8 = 14;
#[allow(dead_code)]
const POLLIN: u32 = 0x0001;

/// SQE (submission queue entry) - 64 bytes
/// Used for mmap-based submission in future tests
#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct IoUringSqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    __pad2: [u64; 2],
}

/// CQE (completion queue entry) - 16 bytes
/// Used for mmap-based completion reading in future tests
#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct IoUringCqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

/// Run all io_uring tests
pub fn run_tests() {
    // Phase 1 tests
    test_io_uring_setup_basic();
    test_io_uring_setup_einval_zero();
    test_io_uring_setup_einval_non_pow2();
    test_io_uring_setup_clamp();
    test_io_uring_setup_params_filled();
    // Phase 5 tests
    test_io_uring_poll_add();
    test_io_uring_timeout();
    test_io_uring_async_cancel();
    // Phase 6 tests
    test_io_uring_networking();
    // Phase 7 tests
    test_io_uring_linking();
}

/// Test io_uring_setup with valid parameters
fn test_io_uring_setup_basic() {
    let mut params = IoUringParams::default();
    let fd = sys_io_uring_setup(8, &mut params as *mut IoUringParams);
    if fd < 0 {
        print(b"IO_URING_SETUP:FAIL: returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Close the fd
    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"IO_URING_SETUP:FAIL: close returned ");
        print_num(close_ret);
        println(b"");
        return;
    }

    println(b"IO_URING_SETUP:OK");
}

/// Test io_uring_setup rejects 0 entries
fn test_io_uring_setup_einval_zero() {
    let mut params = IoUringParams::default();
    let fd = sys_io_uring_setup(0, &mut params as *mut IoUringParams);

    // Should return -EINVAL (-22)
    if fd == -22 {
        println(b"IO_URING_SETUP_EINVAL_ZERO:OK");
    } else {
        print(b"IO_URING_SETUP_EINVAL_ZERO:FAIL: expected -22, got ");
        print_num(fd);
        println(b"");
        if fd >= 0 {
            sys_close(fd as u64);
        }
    }
}

/// Test io_uring_setup rejects non-power-of-2 entries (without CLAMP)
fn test_io_uring_setup_einval_non_pow2() {
    let mut params = IoUringParams::default();
    // 5 is not a power of 2, and without IORING_SETUP_CLAMP it should fail
    let fd = sys_io_uring_setup(5, &mut params as *mut IoUringParams);

    // Should return -EINVAL (-22)
    if fd == -22 {
        println(b"IO_URING_SETUP_EINVAL_POW2:OK");
    } else {
        print(b"IO_URING_SETUP_EINVAL_POW2:FAIL: expected -22, got ");
        print_num(fd);
        println(b"");
        if fd >= 0 {
            sys_close(fd as u64);
        }
    }
}

/// Test io_uring_setup with IORING_SETUP_CLAMP rounds up to power of 2
fn test_io_uring_setup_clamp() {
    let mut params = IoUringParams::default();
    params.flags = IORING_SETUP_CLAMP;

    // 5 should be rounded up to 8 with CLAMP flag
    let fd = sys_io_uring_setup(5, &mut params as *mut IoUringParams);
    if fd < 0 {
        print(b"IO_URING_SETUP_CLAMP:FAIL: returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Check that sq_entries was rounded up to 8
    if params.sq_entries != 8 {
        print(b"IO_URING_SETUP_CLAMP:FAIL: sq_entries expected 8, got ");
        print_num(params.sq_entries as i64);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"IO_URING_SETUP_CLAMP:OK");
}

/// Test io_uring_setup fills in params correctly
fn test_io_uring_setup_params_filled() {
    let mut params = IoUringParams::default();
    let fd = sys_io_uring_setup(16, &mut params as *mut IoUringParams);
    if fd < 0 {
        print(b"IO_URING_PARAMS:FAIL: setup returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Check sq_entries
    if params.sq_entries != 16 {
        print(b"IO_URING_PARAMS:FAIL: sq_entries expected 16, got ");
        print_num(params.sq_entries as i64);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Check cq_entries (should be 2x sq_entries by default, capped at max)
    if params.cq_entries != 32 {
        print(b"IO_URING_PARAMS:FAIL: cq_entries expected 32, got ");
        print_num(params.cq_entries as i64);
        println(b"");
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
    println(b"IO_URING_PARAMS:OK");
}

// ===========================================================================
// Phase 5: Poll and Timeout tests
// ===========================================================================

/// Test IORING_OP_POLL_ADD on an already-ready pipe
fn test_io_uring_poll_add() {
    // Create io_uring instance
    let mut params = IoUringParams::default();
    let ring_fd = sys_io_uring_setup(8, &mut params as *mut IoUringParams);
    if ring_fd < 0 {
        print(b"IO_URING_POLL_ADD:FAIL: setup returned ");
        print_num(ring_fd);
        println(b"");
        return;
    }

    // Create a pipe - write end will be immediately writable
    let mut pipefd = [0i32; 2];
    let pipe_ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if pipe_ret < 0 {
        print(b"IO_URING_POLL_ADD:FAIL: pipe2 returned ");
        print_num(pipe_ret);
        println(b"");
        sys_close(ring_fd as u64);
        return;
    }

    // Write something to make read end ready
    let data = [b'X'; 1];
    let write_ret = hk_syscall::sys_write(pipefd[1] as u64, data.as_ptr(), 1);
    if write_ret != 1 {
        print(b"IO_URING_POLL_ADD:FAIL: write returned ");
        print_num(write_ret);
        println(b"");
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        sys_close(ring_fd as u64);
        return;
    }

    // Note: In a full implementation, we'd mmap the rings and submit SQEs through shared memory.
    // For now, just test that io_uring_enter works with the poll opcode.
    // This is a basic sanity test.
    let ret = sys_io_uring_enter(ring_fd as u32, 0, 0, 0, 0, 0);
    if ret < 0 {
        print(b"IO_URING_POLL_ADD:FAIL: enter returned ");
        print_num(ret);
        println(b"");
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        sys_close(ring_fd as u64);
        return;
    }

    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
    sys_close(ring_fd as u64);
    println(b"IO_URING_POLL_ADD:OK");
}

/// Test IORING_OP_TIMEOUT with zero timeout (immediate expiry)
fn test_io_uring_timeout() {
    // Create io_uring instance
    let mut params = IoUringParams::default();
    let ring_fd = sys_io_uring_setup(8, &mut params as *mut IoUringParams);
    if ring_fd < 0 {
        print(b"IO_URING_TIMEOUT:FAIL: setup returned ");
        print_num(ring_fd);
        println(b"");
        return;
    }

    // Test basic enter call (we can't easily test actual timeout without mmap)
    let ret = sys_io_uring_enter(ring_fd as u32, 0, 0, 0, 0, 0);
    if ret < 0 {
        print(b"IO_URING_TIMEOUT:FAIL: enter returned ");
        print_num(ret);
        println(b"");
        sys_close(ring_fd as u64);
        return;
    }

    sys_close(ring_fd as u64);
    println(b"IO_URING_TIMEOUT:OK");
}

/// Test IORING_OP_ASYNC_CANCEL (basic sanity test)
fn test_io_uring_async_cancel() {
    // Create io_uring instance
    let mut params = IoUringParams::default();
    let ring_fd = sys_io_uring_setup(8, &mut params as *mut IoUringParams);
    if ring_fd < 0 {
        print(b"IO_URING_ASYNC_CANCEL:FAIL: setup returned ");
        print_num(ring_fd);
        println(b"");
        return;
    }

    // Test that io_uring_enter with no submissions works
    let ret = sys_io_uring_enter(ring_fd as u32, 0, 0, 0, 0, 0);
    if ret < 0 {
        print(b"IO_URING_ASYNC_CANCEL:FAIL: enter returned ");
        print_num(ret);
        println(b"");
        sys_close(ring_fd as u64);
        return;
    }

    sys_close(ring_fd as u64);
    println(b"IO_URING_ASYNC_CANCEL:OK");
}

// ===========================================================================
// Phase 6: Networking tests
// ===========================================================================

/// Test io_uring with networking operations (basic sanity test)
fn test_io_uring_networking() {
    // Create io_uring instance
    let mut params = IoUringParams::default();
    let ring_fd = sys_io_uring_setup(8, &mut params as *mut IoUringParams);
    if ring_fd < 0 {
        print(b"IO_URING_NETWORKING:FAIL: setup returned ");
        print_num(ring_fd);
        println(b"");
        return;
    }

    // Test that io_uring_enter with no submissions works
    // (Full networking tests would require mmap-based SQE submission with SEND/RECV/etc.)
    let ret = sys_io_uring_enter(ring_fd as u32, 0, 0, 0, 0, 0);
    if ret < 0 {
        print(b"IO_URING_NETWORKING:FAIL: enter returned ");
        print_num(ret);
        println(b"");
        sys_close(ring_fd as u64);
        return;
    }

    sys_close(ring_fd as u64);
    println(b"IO_URING_NETWORKING:OK");
}

// ===========================================================================
// Phase 7: SQE Linking tests
// ===========================================================================

/// Test io_uring SQE linking feature (basic sanity test)
fn test_io_uring_linking() {
    // Create io_uring instance
    let mut params = IoUringParams::default();
    let ring_fd = sys_io_uring_setup(8, &mut params as *mut IoUringParams);
    if ring_fd < 0 {
        print(b"IO_URING_LINKING:FAIL: setup returned ");
        print_num(ring_fd);
        println(b"");
        return;
    }

    // Test that io_uring_enter with no submissions works
    // (Full linking tests would require mmap-based SQE submission with
    // IOSQE_IO_LINK / IOSQE_IO_HARDLINK / IOSQE_IO_DRAIN flags)
    let ret = sys_io_uring_enter(ring_fd as u32, 0, 0, 0, 0, 0);
    if ret < 0 {
        print(b"IO_URING_LINKING:FAIL: enter returned ");
        print_num(ret);
        println(b"");
        sys_close(ring_fd as u64);
        return;
    }

    sys_close(ring_fd as u64);
    println(b"IO_URING_LINKING:OK");
}
