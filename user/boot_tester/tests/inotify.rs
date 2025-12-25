//! Inotify tests
//!
//! Tests:
//! - Test inotify_init1 creation
//! - Test inotify_add_watch
//! - Test inotify_rm_watch
//! - Test inotify close

use super::helpers::{print, print_num, println};
use hk_syscall::{sys_close, sys_inotify_init1, sys_inotify_add_watch, sys_inotify_rm_watch};
use hk_syscall::{IN_CLOEXEC, IN_NONBLOCK, IN_CREATE, IN_DELETE, IN_MODIFY};

/// Run all inotify tests
pub fn run_tests() {
    test_inotify_init1();
    test_inotify_init1_flags();
    test_inotify_add_watch();
    test_inotify_rm_watch();
    test_inotify_invalid_fd();
}

/// Test basic inotify_init1 creation
fn test_inotify_init1() {
    let fd = sys_inotify_init1(0);
    if fd < 0 {
        print(b"INOTIFY_INIT1:FAIL: returned ");
        print_num(fd);
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"INOTIFY_INIT1:FAIL: close returned ");
        print_num(close_ret);
        return;
    }

    println(b"INOTIFY_INIT1:OK");
}

/// Test inotify_init1 with flags
fn test_inotify_init1_flags() {
    // Test with IN_NONBLOCK
    let fd = sys_inotify_init1(IN_NONBLOCK);
    if fd < 0 {
        print(b"INOTIFY_INIT1_FLAGS:FAIL: NONBLOCK returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Test with IN_CLOEXEC
    let fd = sys_inotify_init1(IN_CLOEXEC);
    if fd < 0 {
        print(b"INOTIFY_INIT1_FLAGS:FAIL: CLOEXEC returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Test with both flags
    let fd = sys_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if fd < 0 {
        print(b"INOTIFY_INIT1_FLAGS:FAIL: both flags returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Test with invalid flags (should fail)
    let fd = sys_inotify_init1(0x12345678);
    if fd >= 0 {
        sys_close(fd as u64);
        println(b"INOTIFY_INIT1_FLAGS:FAIL: invalid flags should fail");
        return;
    }

    println(b"INOTIFY_INIT1_FLAGS:OK");
}

/// Test inotify_add_watch
fn test_inotify_add_watch() {
    let fd = sys_inotify_init1(0);
    if fd < 0 {
        print(b"INOTIFY_ADD_WATCH:FAIL: init1 returned ");
        print_num(fd);
        return;
    }

    // Watch /tmp directory
    let path = b"/tmp\0";
    let wd = sys_inotify_add_watch(fd as i32, path.as_ptr(), IN_CREATE | IN_DELETE | IN_MODIFY);
    if wd < 0 {
        print(b"INOTIFY_ADD_WATCH:FAIL: add_watch returned ");
        print_num(wd);
        sys_close(fd as u64);
        return;
    }

    // Watch descriptor should be positive
    if wd <= 0 {
        print(b"INOTIFY_ADD_WATCH:FAIL: expected positive wd, got ");
        print_num(wd);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"INOTIFY_ADD_WATCH:OK");
}

/// Test inotify_rm_watch
fn test_inotify_rm_watch() {
    let fd = sys_inotify_init1(0);
    if fd < 0 {
        print(b"INOTIFY_RM_WATCH:FAIL: init1 returned ");
        print_num(fd);
        return;
    }

    // Add a watch first
    let path = b"/tmp\0";
    let wd = sys_inotify_add_watch(fd as i32, path.as_ptr(), IN_CREATE);
    if wd < 0 {
        print(b"INOTIFY_RM_WATCH:FAIL: add_watch returned ");
        print_num(wd);
        sys_close(fd as u64);
        return;
    }

    // Remove the watch
    let ret = sys_inotify_rm_watch(fd as i32, wd as i32);
    if ret != 0 {
        print(b"INOTIFY_RM_WATCH:FAIL: rm_watch returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Try to remove again - should fail with EINVAL
    let ret = sys_inotify_rm_watch(fd as i32, wd as i32);
    if ret != -22 {
        // EINVAL
        print(b"INOTIFY_RM_WATCH:FAIL: double rm_watch returned ");
        print_num(ret);
        print(b", expected -22");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"INOTIFY_RM_WATCH:OK");
}

/// Test inotify operations with invalid fd
fn test_inotify_invalid_fd() {
    // Try add_watch with invalid fd
    let path = b"/tmp\0";
    let ret = sys_inotify_add_watch(9999, path.as_ptr(), IN_CREATE);
    if ret != -9 {
        // EBADF
        print(b"INOTIFY_INVALID_FD:FAIL: add_watch bad fd returned ");
        print_num(ret);
        print(b", expected -9");
        return;
    }

    // Try rm_watch with invalid fd
    let ret = sys_inotify_rm_watch(9999, 1);
    if ret != -9 {
        // EBADF
        print(b"INOTIFY_INVALID_FD:FAIL: rm_watch bad fd returned ");
        print_num(ret);
        print(b", expected -9");
        return;
    }

    println(b"INOTIFY_INVALID_FD:OK");
}
