//! Fanotify tests
//!
//! Tests:
//! - Test fanotify_init creation
//! - Test fanotify_init with flags
//! - Test fanotify_mark operations
//! - Test invalid fd handling

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_fanotify_init, sys_fanotify_mark, FAN_CLOEXEC, FAN_MARK_ADD, FAN_NONBLOCK,
    FAN_OPEN, O_RDONLY,
};

/// AT_FDCWD constant
const AT_FDCWD: i32 = -100;

/// Run all fanotify tests
pub fn run_tests() {
    test_fanotify_init();
    test_fanotify_init_flags();
    test_fanotify_mark_inode();
    test_fanotify_mark_invalid_fd();
    test_fanotify_init_invalid_flags();
}

/// Test basic fanotify_init creation
fn test_fanotify_init() {
    let fd = sys_fanotify_init(0, O_RDONLY as u32);
    if fd < 0 {
        print(b"FANOTIFY_INIT:FAIL: returned ");
        print_num(fd);
        println(b"");
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"FANOTIFY_INIT:FAIL: close returned ");
        print_num(close_ret);
        println(b"");
        return;
    }

    println(b"FANOTIFY_INIT:OK");
}

/// Test fanotify_init with flags
fn test_fanotify_init_flags() {
    // Test with FAN_NONBLOCK
    let fd = sys_fanotify_init(FAN_NONBLOCK, O_RDONLY as u32);
    if fd < 0 {
        print(b"FANOTIFY_INIT_FLAGS:FAIL: NONBLOCK returned ");
        print_num(fd);
        println(b"");
        return;
    }
    sys_close(fd as u64);

    // Test with FAN_CLOEXEC
    let fd = sys_fanotify_init(FAN_CLOEXEC, O_RDONLY as u32);
    if fd < 0 {
        print(b"FANOTIFY_INIT_FLAGS:FAIL: CLOEXEC returned ");
        print_num(fd);
        println(b"");
        return;
    }
    sys_close(fd as u64);

    // Test with both flags
    let fd = sys_fanotify_init(FAN_NONBLOCK | FAN_CLOEXEC, O_RDONLY as u32);
    if fd < 0 {
        print(b"FANOTIFY_INIT_FLAGS:FAIL: both flags returned ");
        print_num(fd);
        println(b"");
        return;
    }
    sys_close(fd as u64);

    println(b"FANOTIFY_INIT_FLAGS:OK");
}

/// Test fanotify_mark on an inode
fn test_fanotify_mark_inode() {
    let fd = sys_fanotify_init(0, O_RDONLY as u32);
    if fd < 0 {
        print(b"FANOTIFY_MARK_INODE:FAIL: init returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Mark /tmp directory for FAN_OPEN events
    let path = b"/tmp\0";
    let ret = sys_fanotify_mark(fd as i32, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, path.as_ptr());
    if ret < 0 {
        print(b"FANOTIFY_MARK_INODE:FAIL: mark returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"FANOTIFY_MARK_INODE:OK");
}

/// Test fanotify_mark with invalid fd
fn test_fanotify_mark_invalid_fd() {
    let path = b"/tmp\0";
    let ret = sys_fanotify_mark(9999, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, path.as_ptr());
    if ret != -9 {
        // EBADF
        print(b"FANOTIFY_MARK_INVALID_FD:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
        println(b"");
        return;
    }

    println(b"FANOTIFY_MARK_INVALID_FD:OK");
}

/// Test fanotify_init with invalid flags
fn test_fanotify_init_invalid_flags() {
    // Test with completely invalid flags (should fail)
    let fd = sys_fanotify_init(0x80000000, O_RDONLY as u32);
    if fd >= 0 {
        sys_close(fd as u64);
        println(b"FANOTIFY_INIT_INVALID:FAIL: invalid flags should fail");
        return;
    }

    // Should return EINVAL (-22)
    if fd != -22 {
        print(b"FANOTIFY_INIT_INVALID:FAIL: expected -22 (EINVAL), got ");
        print_num(fd);
        println(b"");
        return;
    }

    println(b"FANOTIFY_INIT_INVALID:OK");
}
