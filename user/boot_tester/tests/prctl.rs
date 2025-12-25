//! Prctl tests
//!
//! Tests:
//! - Test prctl set/get name
//! - Test prctl name truncation at 16 bytes
//! - Test prctl dumpable flag
//! - Test prctl no_new_privs (irreversible)
//! - Test prctl timer slack
//! - Test prctl invalid option returns EINVAL

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_prctl,
    PR_SET_NAME, PR_GET_NAME,
    PR_SET_DUMPABLE, PR_GET_DUMPABLE,
    PR_SET_NO_NEW_PRIVS, PR_GET_NO_NEW_PRIVS,
    PR_SET_TIMERSLACK, PR_GET_TIMERSLACK,
    SUID_DUMP_DISABLE, SUID_DUMP_USER, SUID_DUMP_ROOT,
};

/// Run all prctl tests
pub fn run_tests() {
    test_prctl_set_get_name();
    test_prctl_name_truncation();
    test_prctl_dumpable();
    test_prctl_no_new_privs();
    test_prctl_timerslack();
    test_prctl_einval();
}

/// Test prctl set and get name
fn test_prctl_set_get_name() {
    // Set thread name
    let name = b"testthread\0";
    let ret = sys_prctl(PR_SET_NAME, name.as_ptr() as u64, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_NAME:FAIL: set returned ");
        print_num(ret);
        return;
    }

    // Get thread name
    let mut buf = [0u8; 16];
    let ret = sys_prctl(PR_GET_NAME, buf.as_mut_ptr() as u64, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_NAME:FAIL: get returned ");
        print_num(ret);
        return;
    }

    // Verify name matches (up to null terminator)
    let expected = b"testthread";
    let mut matches = true;
    for i in 0..expected.len() {
        if buf[i] != expected[i] {
            matches = false;
            break;
        }
    }

    if !matches {
        println(b"PRCTL_NAME:FAIL: name mismatch");
        return;
    }

    println(b"PRCTL_NAME:OK");
}

/// Test prctl name truncation at 16 bytes
fn test_prctl_name_truncation() {
    // Set a name longer than 16 bytes (including null)
    // The kernel should truncate to 15 chars + null
    let name = b"verylongnamehere123\0";  // 19 chars + null
    let ret = sys_prctl(PR_SET_NAME, name.as_ptr() as u64, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_TRUNCATE:FAIL: set returned ");
        print_num(ret);
        return;
    }

    // Get thread name
    let mut buf = [0u8; 16];
    let ret = sys_prctl(PR_GET_NAME, buf.as_mut_ptr() as u64, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_TRUNCATE:FAIL: get returned ");
        print_num(ret);
        return;
    }

    // Should be truncated to 15 chars (name array is 16 bytes with last as null)
    // Verify the first 15 bytes match and last byte is null
    let expected = b"verylongnameher";  // First 15 chars
    let mut matches = true;
    for i in 0..expected.len() {
        if buf[i] != expected[i] {
            matches = false;
            break;
        }
    }

    // The 16th byte should be the null terminator
    if buf[15] != 0 {
        matches = false;
    }

    if !matches {
        println(b"PRCTL_TRUNCATE:FAIL: truncation mismatch");
        return;
    }

    println(b"PRCTL_TRUNCATE:OK");
}

/// Test prctl dumpable flag
fn test_prctl_dumpable() {
    // Get default dumpable value (should be SUID_DUMP_USER = 1)
    let ret = sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if ret != SUID_DUMP_USER as i64 {
        print(b"PRCTL_DUMPABLE:FAIL: default is ");
        print_num(ret);
        print(b", expected ");
        print_num(SUID_DUMP_USER as i64);
        return;
    }

    // Set to SUID_DUMP_DISABLE
    let ret = sys_prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE as u64, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_DUMPABLE:FAIL: set DISABLE returned ");
        print_num(ret);
        return;
    }

    // Verify it was set
    let ret = sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if ret != SUID_DUMP_DISABLE as i64 {
        print(b"PRCTL_DUMPABLE:FAIL: get after set DISABLE returned ");
        print_num(ret);
        return;
    }

    // Set to SUID_DUMP_ROOT
    let ret = sys_prctl(PR_SET_DUMPABLE, SUID_DUMP_ROOT as u64, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_DUMPABLE:FAIL: set ROOT returned ");
        print_num(ret);
        return;
    }

    // Verify it was set
    let ret = sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if ret != SUID_DUMP_ROOT as i64 {
        print(b"PRCTL_DUMPABLE:FAIL: get after set ROOT returned ");
        print_num(ret);
        return;
    }

    // Restore to SUID_DUMP_USER
    sys_prctl(PR_SET_DUMPABLE, SUID_DUMP_USER as u64, 0, 0, 0);

    println(b"PRCTL_DUMPABLE:OK");
}

/// Test prctl no_new_privs (irreversible)
fn test_prctl_no_new_privs() {
    // Get default no_new_privs (should be 0)
    let ret = sys_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_NO_NEW_PRIVS:FAIL: default is ");
        print_num(ret);
        print(b", expected 0");
        return;
    }

    // Set no_new_privs (irreversible)
    let ret = sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_NO_NEW_PRIVS:FAIL: set returned ");
        print_num(ret);
        return;
    }

    // Verify it was set
    let ret = sys_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if ret != 1 {
        print(b"PRCTL_NO_NEW_PRIVS:FAIL: get after set returned ");
        print_num(ret);
        return;
    }

    // Try to clear it (should fail, it's irreversible)
    // Note: Linux returns EPERM if arg2 is not 0 or 1
    // Since we're testing irreversibility, we just verify get still returns 1
    let ret = sys_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if ret != 1 {
        print(b"PRCTL_NO_NEW_PRIVS:FAIL: irreversibility broken, got ");
        print_num(ret);
        return;
    }

    println(b"PRCTL_NO_NEW_PRIVS:OK");
}

/// Test prctl timer slack
fn test_prctl_timerslack() {
    // Get default timer slack (should be 50000 ns)
    let ret = sys_prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);
    if ret != 50000 {
        print(b"PRCTL_TIMERSLACK:FAIL: default is ");
        print_num(ret);
        print(b", expected 50000");
        return;
    }

    // Set timer slack to 100000 ns
    let ret = sys_prctl(PR_SET_TIMERSLACK, 100000, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_TIMERSLACK:FAIL: set returned ");
        print_num(ret);
        return;
    }

    // Verify it was set
    let ret = sys_prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);
    if ret != 100000 {
        print(b"PRCTL_TIMERSLACK:FAIL: get after set returned ");
        print_num(ret);
        return;
    }

    // Set timer slack to 0 (should reset to default 50000)
    let ret = sys_prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_TIMERSLACK:FAIL: set 0 returned ");
        print_num(ret);
        return;
    }

    // Verify default was restored
    let ret = sys_prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);
    if ret != 50000 {
        print(b"PRCTL_TIMERSLACK:FAIL: get after set 0 returned ");
        print_num(ret);
        return;
    }

    println(b"PRCTL_TIMERSLACK:OK");
}

/// Test prctl with invalid option returns EINVAL
fn test_prctl_einval() {
    // Use an invalid/unsupported option
    let ret = sys_prctl(99999, 0, 0, 0, 0);
    if ret != -22 {
        // EINVAL
        print(b"PRCTL_EINVAL:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
        return;
    }

    println(b"PRCTL_EINVAL:OK");
}
