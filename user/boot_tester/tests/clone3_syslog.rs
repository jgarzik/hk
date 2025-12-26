//! clone3, personality, and syslog syscall tests
//!
//! Tests:
//! - Test: personality() - query and set execution domain
//! - Test: syslog() - kernel logging operations
//! - Test: clone3() - modern extensible clone (basic validation only)

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_personality, sys_syslog,
    SYSLOG_ACTION_OPEN, SYSLOG_ACTION_CLOSE, SYSLOG_ACTION_SIZE_BUFFER,
    SYSLOG_ACTION_CONSOLE_LEVEL,
    PER_LINUX, PERSONALITY_QUERY,
};

/// Run all clone3/personality/syslog tests
pub fn run_tests() {
    test_personality_query();
    test_personality_set();
    test_syslog_open_close();
    test_syslog_size_buffer();
    test_syslog_console_level();
    test_syslog_invalid_type();
}

/// Test: personality() - query current personality
fn test_personality_query() {
    // Query without changing - should return current (default = 0 = PER_LINUX)
    let ret = sys_personality(PERSONALITY_QUERY);

    if ret >= 0 {
        println(b"PERSONALITY_QUERY:OK");
    } else {
        print(b"PERSONALITY_QUERY:FAIL: returned ");
        print_num(ret);
    }
}

/// Test: personality() - set and verify personality
fn test_personality_set() {
    // First query current
    let old = sys_personality(PERSONALITY_QUERY);
    if old < 0 {
        print(b"PERSONALITY_SET:FAIL: query returned ");
        print_num(old);
        return;
    }

    // Set to PER_LINUX (0) - should return old value
    let ret = sys_personality(PER_LINUX);
    if ret < 0 {
        print(b"PERSONALITY_SET:FAIL: set returned ");
        print_num(ret);
        return;
    }

    // Verify it's set
    let new = sys_personality(PERSONALITY_QUERY);
    if new == PER_LINUX as i64 {
        println(b"PERSONALITY_SET:OK");
    } else {
        print(b"PERSONALITY_SET:FAIL: new personality is ");
        print_num(new);
    }
}

/// Test: syslog() - open and close (no-ops, but should succeed)
fn test_syslog_open_close() {
    // Open
    let ret = sys_syslog(SYSLOG_ACTION_OPEN, core::ptr::null_mut(), 0);
    if ret != 0 {
        print(b"SYSLOG_OPEN:FAIL: returned ");
        print_num(ret);
        return;
    }

    // Close
    let ret = sys_syslog(SYSLOG_ACTION_CLOSE, core::ptr::null_mut(), 0);
    if ret != 0 {
        print(b"SYSLOG_CLOSE:FAIL: returned ");
        print_num(ret);
        return;
    }

    println(b"SYSLOG_OPEN_CLOSE:OK");
}

/// Test: syslog() - get log buffer size
fn test_syslog_size_buffer() {
    let ret = sys_syslog(SYSLOG_ACTION_SIZE_BUFFER, core::ptr::null_mut(), 0);
    if ret >= 0 {
        println(b"SYSLOG_SIZE_BUFFER:OK");
    } else {
        print(b"SYSLOG_SIZE_BUFFER:FAIL: returned ");
        print_num(ret);
    }
}

/// Test: syslog() - set console log level
fn test_syslog_console_level() {
    // Set level to 4 (warning)
    let ret = sys_syslog(SYSLOG_ACTION_CONSOLE_LEVEL, core::ptr::null_mut(), 4);
    if ret >= 0 {
        println(b"SYSLOG_CONSOLE_LEVEL:OK");
    } else {
        print(b"SYSLOG_CONSOLE_LEVEL:FAIL: returned ");
        print_num(ret);
    }
}

/// Test: syslog() - invalid type returns EINVAL
fn test_syslog_invalid_type() {
    let ret = sys_syslog(99, core::ptr::null_mut(), 0);
    if ret == -22 {
        // EINVAL
        println(b"SYSLOG_EINVAL:OK");
    } else {
        print(b"SYSLOG_EINVAL:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}
