//! kcmp syscall tests
//!
//! Tests for comparing kernel resources between processes.

use super::helpers::{print, print_num, println};
use hk_syscall::{sys_getpid, sys_kcmp, KCMP_FILE, KCMP_FILES, KCMP_FS, KCMP_SIGHAND, KCMP_VM};

const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;
const EOPNOTSUPP: i64 = -95;

// KCMP_EPOLL_TFD is not supported
const KCMP_EPOLL_TFD: i32 = 7;

/// Run all kcmp tests
pub fn run_tests() {
    println(b"=== kcmp Tests ===");

    test_kcmp_self_vm();
    test_kcmp_self_files();
    test_kcmp_self_fs();
    test_kcmp_self_sighand();
    test_kcmp_self_file();
    test_kcmp_invalid_pid();
    test_kcmp_invalid_type();
    test_kcmp_invalid_fd();
    test_kcmp_epoll_tfd_unsupported();
}

/// Test: Comparing own VM should return 0 (equal)
fn test_kcmp_self_vm() {
    print(b"  kcmp self VM: ");
    let pid = sys_getpid() as u64;
    let ret = sys_kcmp(pid, pid, KCMP_VM, 0, 0);
    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (expected 0, got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: Comparing own file descriptor table should return 0 (equal)
fn test_kcmp_self_files() {
    print(b"  kcmp self FILES: ");
    let pid = sys_getpid() as u64;
    let ret = sys_kcmp(pid, pid, KCMP_FILES, 0, 0);
    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (expected 0, got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: Comparing own filesystem context should return 0 (equal)
fn test_kcmp_self_fs() {
    print(b"  kcmp self FS: ");
    let pid = sys_getpid() as u64;
    let ret = sys_kcmp(pid, pid, KCMP_FS, 0, 0);
    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (expected 0, got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: Comparing own signal handlers should return 0 (equal)
fn test_kcmp_self_sighand() {
    print(b"  kcmp self SIGHAND: ");
    let pid = sys_getpid() as u64;
    let ret = sys_kcmp(pid, pid, KCMP_SIGHAND, 0, 0);
    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (expected 0, got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: Comparing same fd in same process should return 0
fn test_kcmp_self_file() {
    print(b"  kcmp self FILE (stdin): ");
    let pid = sys_getpid() as u64;
    // Compare stdin (fd 0) with itself
    let ret = sys_kcmp(pid, pid, KCMP_FILE, 0, 0);
    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (expected 0, got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: Invalid PID should return ESRCH
fn test_kcmp_invalid_pid() {
    print(b"  kcmp invalid PID: ");
    let pid = sys_getpid() as u64;
    // Use an absurdly high PID that shouldn't exist
    let ret = sys_kcmp(pid, 99999999, KCMP_VM, 0, 0);
    if ret == ESRCH {
        println(b"PASS");
    } else {
        print(b"FAIL (expected ESRCH=");
        print_num(ESRCH);
        print(b", got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: Invalid type should return EINVAL
fn test_kcmp_invalid_type() {
    print(b"  kcmp invalid type: ");
    let pid = sys_getpid() as u64;
    let ret = sys_kcmp(pid, pid, 999, 0, 0);
    if ret == EINVAL {
        println(b"PASS");
    } else {
        print(b"FAIL (expected EINVAL=");
        print_num(EINVAL);
        print(b", got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: Invalid fd should return EBADF
fn test_kcmp_invalid_fd() {
    print(b"  kcmp invalid fd: ");
    let pid = sys_getpid() as u64;
    // Use invalid fd 9999
    let ret = sys_kcmp(pid, pid, KCMP_FILE, 9999, 0);
    if ret == EBADF {
        println(b"PASS");
    } else {
        print(b"FAIL (expected EBADF=");
        print_num(EBADF);
        print(b", got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: KCMP_EPOLL_TFD should return EOPNOTSUPP
fn test_kcmp_epoll_tfd_unsupported() {
    print(b"  kcmp EPOLL_TFD unsupported: ");
    let pid = sys_getpid() as u64;
    let ret = sys_kcmp(pid, pid, KCMP_EPOLL_TFD, 0, 0);
    if ret == EOPNOTSUPP {
        println(b"PASS");
    } else {
        print(b"FAIL (expected EOPNOTSUPP=");
        print_num(EOPNOTSUPP);
        print(b", got ");
        print_num(ret);
        println(b")");
    }
}
