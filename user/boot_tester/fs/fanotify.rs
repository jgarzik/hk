//! Fanotify tests
//!
//! Tests:
//! - Test fanotify_init creation
//! - Test fanotify_init with flags
//! - Test fanotify_mark operations
//! - Test invalid fd handling

use crate::harness::{fail_num, pass};
use crate::helpers::println;
use hk_syscall::sys_open;
use hk_syscall::{
    FAN_CLOEXEC, FAN_MARK_ADD, FAN_NONBLOCK, FAN_OPEN, O_RDONLY, sys_close, sys_fanotify_init,
    sys_fanotify_mark,
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
    test_fanotify_mark_args();
}

/// fanotify_mark's request checks and a NULL pathname (Linux
/// fanotify_mark, fanotify_find_path): no command, two commands, ADD or
/// REMOVE with no mask, FLUSH with another flag are EINVAL before the
/// fanotify fd is looked at; a NULL pathname marks dirfd's own file,
/// ENOTDIR with FAN_MARK_ONLYDIR on a file, EBADF for an O_PATH fd or
/// AT_FDCWD
fn test_fanotify_mark_args() {
    const FAN_MARK_REMOVE: u32 = 2;
    const FAN_MARK_ONLYDIR: u32 = 8;
    const FAN_MARK_FLUSH: u32 = 0x80;
    const O_PATH: u32 = 0o10000000;
    const EINVAL: i64 = -22;
    const EBADF: i64 = -9;
    const ENOTDIR: i64 = -20;
    let mut t = crate::harness::T::new(b"FANOTIFY_MARK_ARGS");
    let null = core::ptr::null();
    let path = b"/test.txt\0";
    let mark = |fd: i64, flags: u32, mask: u64, dfd: i32, p: *const u8| {
        sys_fanotify_mark(fd as i32, flags, mask, dfd, p)
    };
    t.eq(
        b"no command",
        mark(9999, 0, FAN_OPEN, AT_FDCWD, path.as_ptr()),
        EINVAL,
    );
    let both = FAN_MARK_ADD | FAN_MARK_REMOVE;
    t.eq(
        b"two commands",
        mark(9999, both, FAN_OPEN, AT_FDCWD, path.as_ptr()),
        EINVAL,
    );
    t.eq(
        b"remove no mask",
        mark(9999, FAN_MARK_REMOVE, 0, AT_FDCWD, path.as_ptr()),
        EINVAL,
    );
    let fo = FAN_MARK_FLUSH | FAN_MARK_ONLYDIR;
    t.eq(b"flush flags", mark(9999, fo, 0, AT_FDCWD, null), EINVAL);
    let fd = sys_fanotify_init(0, O_RDONLY as u32);
    if !t.ok(b"init", fd >= 0, fd) {
        t.done();
        return;
    }
    let dir = sys_open(b"/\0".as_ptr(), O_RDONLY, 0);
    let file = sys_open(path.as_ptr(), O_RDONLY, 0);
    let opath = sys_open(path.as_ptr(), O_PATH, 0);
    t.eq(
        b"dir fd",
        mark(fd, FAN_MARK_ADD, FAN_OPEN, dir as i32, null),
        0,
    );
    t.eq(
        b"file fd",
        mark(fd, FAN_MARK_ADD, FAN_OPEN, file as i32, null),
        0,
    );
    let od = FAN_MARK_ADD | FAN_MARK_ONLYDIR;
    t.eq(
        b"onlydir",
        mark(fd, od, FAN_OPEN, file as i32, null),
        ENOTDIR,
    );
    t.eq(
        b"o_path",
        mark(fd, FAN_MARK_ADD, FAN_OPEN, opath as i32, null),
        EBADF,
    );
    t.eq(
        b"cwd",
        mark(fd, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, null),
        EBADF,
    );
    for f in [dir, file, opath, fd] {
        sys_close(f as u64);
    }
    t.done();
}

/// Test basic fanotify_init creation
fn test_fanotify_init() {
    let fd = sys_fanotify_init(0, O_RDONLY as u32);
    if fd < 0 {
        fail_num(b"FANOTIFY_INIT:FAIL: returned ", fd);
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        fail_num(b"FANOTIFY_INIT:FAIL: close returned ", close_ret);
        return;
    }

    pass(b"FANOTIFY_INIT");
}

/// Test fanotify_init with flags
fn test_fanotify_init_flags() {
    // Test with FAN_NONBLOCK
    let fd = sys_fanotify_init(FAN_NONBLOCK, O_RDONLY as u32);
    if fd < 0 {
        fail_num(b"FANOTIFY_INIT_FLAGS:FAIL: NONBLOCK returned ", fd);
        return;
    }
    sys_close(fd as u64);

    // Test with FAN_CLOEXEC
    let fd = sys_fanotify_init(FAN_CLOEXEC, O_RDONLY as u32);
    if fd < 0 {
        fail_num(b"FANOTIFY_INIT_FLAGS:FAIL: CLOEXEC returned ", fd);
        return;
    }
    sys_close(fd as u64);

    // Test with both flags
    let fd = sys_fanotify_init(FAN_NONBLOCK | FAN_CLOEXEC, O_RDONLY as u32);
    if fd < 0 {
        fail_num(b"FANOTIFY_INIT_FLAGS:FAIL: both flags returned ", fd);
        return;
    }
    sys_close(fd as u64);

    pass(b"FANOTIFY_INIT_FLAGS");
}

/// Test fanotify_mark on an inode
fn test_fanotify_mark_inode() {
    let fd = sys_fanotify_init(0, O_RDONLY as u32);
    if fd < 0 {
        fail_num(b"FANOTIFY_MARK_INODE:FAIL: init returned ", fd);
        return;
    }

    // Mark /tmp directory for FAN_OPEN events
    let path = b"/tmp\0";
    let ret = sys_fanotify_mark(fd as i32, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, path.as_ptr());
    if ret < 0 {
        fail_num(b"FANOTIFY_MARK_INODE:FAIL: mark returned ", ret);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"FANOTIFY_MARK_INODE");
}

/// Test fanotify_mark with invalid fd
fn test_fanotify_mark_invalid_fd() {
    let path = b"/tmp\0";
    let ret = sys_fanotify_mark(9999, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, path.as_ptr());
    if ret != -9 {
        // EBADF
        fail_num(
            b"FANOTIFY_MARK_INVALID_FD:FAIL: expected -9 (EBADF), got ",
            ret,
        );
        return;
    }

    pass(b"FANOTIFY_MARK_INVALID_FD");
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
        fail_num(
            b"FANOTIFY_INIT_INVALID:FAIL: expected -22 (EINVAL), got ",
            fd,
        );
        return;
    }

    pass(b"FANOTIFY_INIT_INVALID");
}
