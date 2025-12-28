//! POSIX advisory byte-range lock tests (fcntl F_GETLK/F_SETLK/F_SETLKW)
//!
//! Tests:
//! - Test F_SETLK with F_WRLCK (write lock) and F_UNLCK
//! - Test F_SETLK with F_RDLCK (read lock)
//! - Test F_GETLK returns F_UNLCK when no conflict
//! - Test partial unlock (range splitting)
//! - Test F_SETLK returns EBADF for invalid fd

use super::helpers::{print, print_num, println};
use hk_syscall::{sys_close, sys_fcntl, sys_mkdir, sys_open, sys_write, O_CREAT, O_RDWR, O_TRUNC};

// fcntl commands for POSIX locks
const F_GETLK: i32 = 5;
const F_SETLK: i32 = 6;
#[allow(dead_code)]
const F_SETLKW: i32 = 7;

// Lock types
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;

// Whence values
const SEEK_SET: i16 = 0;

// Error codes
const EBADF: i64 = -9;

/// struct flock (Linux ABI)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

/// Run all POSIX lock tests
pub fn run_tests() {
    // Create /tmp directory for test files (ignore error if exists)
    let _ = sys_mkdir(b"/tmp\0".as_ptr(), 0o755);

    test_setlk_wrlck();
    test_setlk_rdlck();
    test_getlk_no_conflict();
    test_setlk_unlock();
    test_setlk_ebadf();
}

/// Test F_SETLK with F_WRLCK (write lock) and F_UNLCK
fn test_setlk_wrlck() {
    let path = b"/tmp/posix_lock_test\0";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"POSIX_SETLK_WRLCK:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Write some data
    let _ = sys_write(fd as u64, b"test data".as_ptr(), 9);

    // Acquire write lock on bytes 0-100
    let mut flock = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 100,
        l_pid: 0,
    };

    let ret = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);
    if ret != 0 {
        print(b"POSIX_SETLK_WRLCK:FAIL: fcntl(F_SETLK) returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Unlock
    flock.l_type = F_UNLCK;
    let ret = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);
    if ret != 0 {
        print(b"POSIX_SETLK_WRLCK:FAIL: fcntl(F_UNLCK) returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"POSIX_SETLK_WRLCK:OK");
}

/// Test F_SETLK with F_RDLCK (read lock)
fn test_setlk_rdlck() {
    let path = b"/tmp/posix_rdlock_test\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"POSIX_SETLK_RDLCK:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Acquire read lock
    let mut flock = Flock {
        l_type: F_RDLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 50,
        l_pid: 0,
    };

    let ret = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);
    if ret != 0 {
        print(b"POSIX_SETLK_RDLCK:FAIL: fcntl(F_SETLK) returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Unlock
    flock.l_type = F_UNLCK;
    let _ = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);

    sys_close(fd as u64);
    println(b"POSIX_SETLK_RDLCK:OK");
}

/// Test F_GETLK returns F_UNLCK when no conflict
fn test_getlk_no_conflict() {
    let path = b"/tmp/posix_getlk_test\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"POSIX_GETLK:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Query for a write lock - should report no conflict
    let mut flock = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 100,
        l_pid: 0,
    };

    let ret = sys_fcntl(fd as i32, F_GETLK, &mut flock as *mut Flock as u64);
    if ret != 0 {
        print(b"POSIX_GETLK:FAIL: fcntl(F_GETLK) returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // l_type should be F_UNLCK (no conflict)
    if flock.l_type != F_UNLCK {
        print(b"POSIX_GETLK:FAIL: expected l_type=F_UNLCK, got ");
        print_num(flock.l_type as i64);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"POSIX_GETLK:OK");
}

/// Test partial unlock (range splitting)
fn test_setlk_unlock() {
    let path = b"/tmp/posix_unlock_test\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"POSIX_UNLOCK:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Lock bytes 0-100
    let mut flock = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 100,
        l_pid: 0,
    };
    let _ = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);

    // Unlock bytes 25-75 (partial unlock)
    flock.l_type = F_UNLCK;
    flock.l_start = 25;
    flock.l_len = 50;
    let ret = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);
    if ret != 0 {
        print(b"POSIX_UNLOCK:FAIL: partial unlock returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"POSIX_UNLOCK:OK");
}

/// Test F_SETLK returns EBADF for invalid fd
fn test_setlk_ebadf() {
    let mut flock = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 100,
        l_pid: 0,
    };

    let ret = sys_fcntl(9999, F_SETLK, &mut flock as *mut Flock as u64);
    if ret == EBADF {
        println(b"POSIX_SETLK_EBADF:OK");
    } else {
        print(b"POSIX_SETLK_EBADF:FAIL: expected -9, got ");
        print_num(ret);
        println(b"");
    }
}
