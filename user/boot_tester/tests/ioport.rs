//! I/O port permission tests (x86-64 only)
//!
//! Tests:
//! - Test iopl set level 0 (always allowed)
//! - Test iopl set level 3 (requires CAP_SYS_RAWIO, which boot_tester has)
//! - Test iopl set invalid level (should return EINVAL)
//! - Test iopl lower privilege (always allowed)
//! - Test ioperm returns ENOSYS (not yet implemented)

use super::helpers::{print, println, print_num};
use hk_syscall::{sys_iopl, sys_ioperm};

// Error codes
const EINVAL: i64 = 22;
const ENOSYS: i64 = 38;

/// Run all I/O port tests
pub fn run_tests() {
    test_iopl_level_zero();
    test_iopl_level_three();
    test_iopl_invalid_level();
    test_iopl_lower_privilege();
    test_ioperm_enosys();
}

/// Test iopl set level 0 (initial state, always allowed)
fn test_iopl_level_zero() {
    let ret = sys_iopl(0);
    if ret == 0 {
        println(b"IOPL_LEVEL_ZERO:OK");
    } else {
        print(b"IOPL_LEVEL_ZERO:FAIL: returned ");
        print_num(ret);
        println(b"");
    }
}

/// Test iopl set level 3 (should succeed with CAP_SYS_RAWIO)
fn test_iopl_level_three() {
    let ret = sys_iopl(3);
    if ret == 0 {
        println(b"IOPL_LEVEL_THREE:OK");
    } else {
        print(b"IOPL_LEVEL_THREE:FAIL: returned ");
        print_num(ret);
        println(b"");
    }
}

/// Test iopl with invalid level (> 3 should return EINVAL)
fn test_iopl_invalid_level() {
    let ret = sys_iopl(4);
    if ret == -EINVAL {
        println(b"IOPL_INVALID_LEVEL:OK");
    } else {
        print(b"IOPL_INVALID_LEVEL:FAIL: expected -22, got ");
        print_num(ret);
        println(b"");
    }
}

/// Test iopl lowering privilege (always allowed)
fn test_iopl_lower_privilege() {
    // First set to level 3 (should succeed)
    let ret = sys_iopl(3);
    if ret != 0 {
        print(b"IOPL_LOWER:FAIL: setup to level 3 returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Now lower to level 0 (should always succeed)
    let ret = sys_iopl(0);
    if ret == 0 {
        println(b"IOPL_LOWER:OK");
    } else {
        print(b"IOPL_LOWER:FAIL: lowering returned ");
        print_num(ret);
        println(b"");
    }
}

/// Test ioperm returns ENOSYS (not implemented)
fn test_ioperm_enosys() {
    // Try to enable access to port 0x80 (POST diagnostic port)
    let ret = sys_ioperm(0x80, 1, 1);
    if ret == -ENOSYS {
        println(b"IOPERM_ENOSYS:OK");
    } else {
        print(b"IOPERM_ENOSYS:FAIL: expected -38, got ");
        print_num(ret);
        println(b"");
    }
}
