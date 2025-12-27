//! Process accounting (acct) tests
//!
//! Tests:
//! - Test acct enable/disable
//! - Test acct with invalid path
//! - Test acct capability requirement

use super::helpers::{print, print_num, println};
use core::ptr;
use hk_syscall::sys_acct;

/// Run all acct tests
pub fn run_tests() {
    test_acct_disable();
    test_acct_invalid_path();
}

/// Test acct disable (NULL filename)
fn test_acct_disable() {
    // Disable accounting (should work if already disabled)
    let ret = sys_acct(ptr::null());
    // This might return EPERM (-1) if we don't have CAP_SYS_PACCT
    // or 0 if we have the capability
    if ret != 0 && ret != -1 {
        print(b"ACCT_DISABLE:FAIL: expected 0 or -1 (EPERM), got ");
        print_num(ret);
        println(b"");
        return;
    }

    println(b"ACCT_DISABLE:OK");
}

/// Test acct with non-existent file (needs capability)
fn test_acct_invalid_path() {
    let path = b"/nonexistent/acct/file\0";
    let ret = sys_acct(path.as_ptr());

    // This should return either:
    // -1 (EPERM) if we don't have CAP_SYS_PACCT
    // -2 (ENOENT) if file doesn't exist and we have capability
    if ret != -1 && ret != -2 {
        print(b"ACCT_INVALID_PATH:FAIL: expected -1 (EPERM) or -2 (ENOENT), got ");
        print_num(ret);
        println(b"");
        return;
    }

    println(b"ACCT_INVALID_PATH:OK");
}
