//! Inotify tests
//!
//! Tests:
//! - Test inotify_init1 creation
//! - Test inotify_add_watch
//! - Test inotify_rm_watch
//! - Test inotify close
//! - INOTIFY_MAX_USER_WATCHES: a user's watches stop at
//!   fs.inotify.max_user_watches (ENOSPC), and a removed watch frees
//!   its charge (Linux inc_inotify_watches)

use crate::harness::pass;
use crate::helpers::{print, print_num, println};
use hk_syscall::{IN_CLOEXEC, IN_CREATE, IN_DELETE, IN_MODIFY, IN_NONBLOCK};
use hk_syscall::{sys_close, sys_inotify_add_watch, sys_inotify_init1, sys_inotify_rm_watch};

/// Run all inotify tests
pub fn run_tests() {
    test_inotify_init1();
    test_inotify_init1_flags();
    test_inotify_add_watch();
    test_inotify_rm_watch();
    test_inotify_invalid_fd();
    test_inotify_max_user_watches();
}

const MAX_WATCHES: &[u8] = b"/proc/sys/fs/inotify/max_user_watches\0";

fn write_str(path: &[u8], s: &[u8]) -> i64 {
    let fd = hk_syscall::sys_open(path.as_ptr(), hk_syscall::O_WRONLY, 0);
    if fd < 0 {
        return fd;
    }
    let r = hk_syscall::sys_write(fd as u64, s.as_ptr(), s.len() as u64);
    sys_close(fd as u64);
    r
}

/// Directories to watch, one file system (distinct inodes)
const WDIRS: [&[u8]; 4] = [b"/iw_a\0", b"/iw_b\0", b"/iw_c\0", b"/iw_d\0"];

/// As uid 4243 with a limit of 3: 3 watches, the 4th, then the 4th
/// again after one is removed
fn max_watches_child() -> i32 {
    const ENOSPC: i64 = -28;
    if hk_syscall::sys_setresuid(4243, 4243, 4243) != 0 {
        return 1;
    }
    let fd = sys_inotify_init1(0) as i32;
    let w = |p: &[u8]| sys_inotify_add_watch(fd, p.as_ptr(), IN_CREATE);
    let a = w(WDIRS[0]);
    if a < 0 || w(WDIRS[1]) < 0 || w(WDIRS[2]) < 0 {
        return 2;
    }
    if w(WDIRS[3]) != ENOSPC {
        return 3;
    }
    if sys_inotify_rm_watch(fd, a as i32) != 0 || w(WDIRS[3]) < 0 {
        return 4;
    }
    sys_close(fd as u64);
    0
}

fn test_inotify_max_user_watches() {
    let mut old = [0u8; 32];
    let n = crate::helpers::read_file(MAX_WATCHES, &mut old);
    if n <= 0 || write_str(MAX_WATCHES, b"3") < 0 {
        crate::harness::fail_why(b"INOTIFY_MAX_USER_WATCHES", b"sysctl", n);
        return;
    }
    for d in WDIRS {
        hk_syscall::sys_mkdir(d.as_ptr(), 0o755);
    }
    let pid = hk_syscall::sys_fork();
    if pid == 0 {
        hk_syscall::sys_exit(max_watches_child() as u64);
    }
    let mut st = 0i32;
    hk_syscall::sys_wait4(pid, &mut st, 0, 0);
    write_str(MAX_WATCHES, &old[..n as usize]);
    for d in WDIRS {
        hk_syscall::sys_rmdir(d.as_ptr());
    }
    crate::harness::report_step(
        b"INOTIFY_MAX_USER_WATCHES",
        i64::from(st >> 8) + i64::from(st & 0x7f) * 100,
    );
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

    pass(b"INOTIFY_INIT1");
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

    pass(b"INOTIFY_INIT1_FLAGS");
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
    pass(b"INOTIFY_ADD_WATCH");
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
    pass(b"INOTIFY_RM_WATCH");
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

    pass(b"INOTIFY_INVALID_FD");
}
