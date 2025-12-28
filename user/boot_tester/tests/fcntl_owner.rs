//! fcntl F_GETOWN/F_SETOWN/F_GETSIG/F_SETSIG tests
//!
//! Tests for async I/O owner tracking:
//! - F_SETOWN/F_GETOWN: Set/get owner PID/PGID for signal delivery
//! - F_SETSIG/F_GETSIG: Set/get signal number for async I/O

use super::helpers::{print, print_num, println};
use hk_syscall::{sys_close, sys_fcntl, sys_mkdir, sys_open, O_CREAT, O_RDWR};

// fcntl commands
const F_SETOWN: i32 = 8;
const F_GETOWN: i32 = 9;
const F_SETSIG: i32 = 10;
const F_GETSIG: i32 = 11;

// Error codes
const EBADF: i64 = -9;

/// Run all fcntl owner tests
pub fn run_tests() {
    // Create /tmp directory for test files (ignore error if exists)
    let _ = sys_mkdir(b"/tmp\0".as_ptr(), 0o755);

    test_setown_getown();
    test_setown_negative();
    test_setsig_getsig();
    test_getown_unset();
    test_setown_ebadf();
}

/// Test F_SETOWN and F_GETOWN with positive PID
fn test_setown_getown() {
    let path = b"/tmp/fcntl_owner_test\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        print(b"FCNTL_OWNER_SETOWN:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Set owner to PID 42
    let ret = sys_fcntl(fd as i32, F_SETOWN, 42);
    if ret != 0 {
        print(b"FCNTL_OWNER_SETOWN:FAIL: F_SETOWN returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Get owner back
    let owner = sys_fcntl(fd as i32, F_GETOWN, 0);
    if owner != 42 {
        print(b"FCNTL_OWNER_SETOWN:FAIL: F_GETOWN returned ");
        print_num(owner);
        println(b" expected 42");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"FCNTL_OWNER_SETOWN:OK");
}

/// Test F_SETOWN with negative value (PGID)
fn test_setown_negative() {
    let path = b"/tmp/fcntl_owner_pgid\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        print(b"FCNTL_OWNER_PGID:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Set owner to PGID -100 (process group 100)
    let ret = sys_fcntl(fd as i32, F_SETOWN, (-100i32) as u64);
    if ret != 0 {
        print(b"FCNTL_OWNER_PGID:FAIL: F_SETOWN returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Get owner back - should be -100
    let owner = sys_fcntl(fd as i32, F_GETOWN, 0);
    if owner != -100 {
        print(b"FCNTL_OWNER_PGID:FAIL: F_GETOWN returned ");
        print_num(owner);
        println(b" expected -100");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"FCNTL_OWNER_PGID:OK");
}

/// Test F_SETSIG and F_GETSIG
fn test_setsig_getsig() {
    let path = b"/tmp/fcntl_sig_test\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        print(b"FCNTL_OWNER_SIG:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Set signal to SIGUSR1 (10)
    let ret = sys_fcntl(fd as i32, F_SETSIG, 10);
    if ret != 0 {
        print(b"FCNTL_OWNER_SIG:FAIL: F_SETSIG returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Get signal back
    let sig = sys_fcntl(fd as i32, F_GETSIG, 0);
    if sig != 10 {
        print(b"FCNTL_OWNER_SIG:FAIL: F_GETSIG returned ");
        print_num(sig);
        println(b" expected 10");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"FCNTL_OWNER_SIG:OK");
}

/// Test F_GETOWN returns 0 for unset owner
fn test_getown_unset() {
    let path = b"/tmp/fcntl_owner_unset\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        print(b"FCNTL_OWNER_UNSET:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Get owner without setting - should be 0
    let owner = sys_fcntl(fd as i32, F_GETOWN, 0);
    if owner != 0 {
        print(b"FCNTL_OWNER_UNSET:FAIL: F_GETOWN returned ");
        print_num(owner);
        println(b" expected 0");
        sys_close(fd as u64);
        return;
    }

    // Get signal without setting - should be 0
    let sig = sys_fcntl(fd as i32, F_GETSIG, 0);
    if sig != 0 {
        print(b"FCNTL_OWNER_UNSET:FAIL: F_GETSIG returned ");
        print_num(sig);
        println(b" expected 0");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"FCNTL_OWNER_UNSET:OK");
}

/// Test F_SETOWN returns EBADF for invalid fd
fn test_setown_ebadf() {
    let ret = sys_fcntl(9999, F_SETOWN, 42);
    if ret == EBADF {
        println(b"FCNTL_OWNER_EBADF:OK");
    } else {
        print(b"FCNTL_OWNER_EBADF:FAIL: expected -9, got ");
        print_num(ret);
        println(b"");
    }
}
