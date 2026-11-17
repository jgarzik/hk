//! fcntl F_GETOWN/F_SETOWN/F_GETSIG/F_SETSIG tests
//!
//! Tests for async I/O owner tracking:
//! - F_SETOWN/F_GETOWN: Set/get owner PID/PGID for signal delivery
//!   (ESRCH for a process or group that does not exist)
//! - F_SETSIG/F_GETSIG: Set/get signal number for async I/O

use crate::harness::{fail_num, pass};
use crate::helpers::{print, print_num, println, reap};
use hk_syscall::{
    O_CREAT, O_RDWR, sys_close, sys_exit, sys_fcntl, sys_fork, sys_getpgid, sys_getpid, sys_mkdir,
    sys_open, sys_pause, sys_pipe2, sys_read, sys_setpgid, sys_setsid, sys_wait4, sys_write,
};

// fcntl commands
const F_SETOWN: i32 = 8;
const F_GETOWN: i32 = 9;
const F_SETSIG: i32 = 10;
const F_GETSIG: i32 = 11;

// Error codes
const EBADF: i64 = -9;
const ESRCH: i64 = -3;

/// Run all fcntl owner tests
pub fn run_tests() {
    // Create /tmp directory for test files (ignore error if exists)
    let _ = sys_mkdir(b"/tmp\0".as_ptr(), 0o755);

    test_setown_getown();
    test_setown_negative();
    test_setsig_getsig();
    test_getown_unset();
    test_setown_ebadf();
    test_setown_session_pid();
}

/// Test F_SETOWN and F_GETOWN with positive PID
fn test_setown_getown() {
    let path = b"/tmp/fcntl_owner_test\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        fail_num(b"FCNTL_OWNER_SETOWN:FAIL: open returned ", fd);
        return;
    }

    // Set owner to our own pid (an existing process)
    let me = sys_getpid();
    let ret = sys_fcntl(fd as i32, F_SETOWN, me as u64);
    if ret != 0 {
        fail_num(b"FCNTL_OWNER_SETOWN:FAIL: F_SETOWN returned ", ret);
        sys_close(fd as u64);
        return;
    }

    // Get owner back
    let owner = sys_fcntl(fd as i32, F_GETOWN, 0);
    if owner != me {
        print(b"FCNTL_OWNER_SETOWN:FAIL: F_GETOWN returned ");
        print_num(owner);
        println(b" expected own pid");
        sys_close(fd as u64);
        return;
    }
    // No such process: ESRCH, owner unchanged
    let ret = sys_fcntl(fd as i32, F_SETOWN, 0x3f_fff0);
    if ret != ESRCH || sys_fcntl(fd as i32, F_GETOWN, 0) != me {
        fail_num(b"FCNTL_OWNER_SETOWN:FAIL: unknown pid returned ", ret);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"FCNTL_OWNER_SETOWN");
}

/// Test F_SETOWN with negative value (PGID)
fn test_setown_negative() {
    let path = b"/tmp/fcntl_owner_pgid\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        fail_num(b"FCNTL_OWNER_PGID:FAIL: open returned ", fd);
        return;
    }

    // Unknown process group: ESRCH
    let ret = sys_fcntl(fd as i32, F_SETOWN, (-0x3f_fff0i32) as u64);
    if ret != ESRCH {
        fail_num(b"FCNTL_OWNER_PGID:FAIL: unknown pgid returned ", ret);
        sys_close(fd as u64);
        return;
    }
    // Our own process group
    let pg = -(sys_getpgid(0) as i32);
    let ret = sys_fcntl(fd as i32, F_SETOWN, pg as u64);
    if ret != 0 {
        fail_num(b"FCNTL_OWNER_PGID:FAIL: F_SETOWN returned ", ret);
        sys_close(fd as u64);
        return;
    }

    // Get owner back: -pgid
    let owner = sys_fcntl(fd as i32, F_GETOWN, 0);
    if owner != pg as i64 {
        print(b"FCNTL_OWNER_PGID:FAIL: F_GETOWN returned ");
        print_num(owner);
        println(b" expected -pgid");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"FCNTL_OWNER_PGID");
}

/// Test F_SETSIG and F_GETSIG
fn test_setsig_getsig() {
    let path = b"/tmp/fcntl_sig_test\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        fail_num(b"FCNTL_OWNER_SIG:FAIL: open returned ", fd);
        return;
    }

    // Set signal to SIGUSR1 (10)
    let ret = sys_fcntl(fd as i32, F_SETSIG, 10);
    if ret != 0 {
        fail_num(b"FCNTL_OWNER_SIG:FAIL: F_SETSIG returned ", ret);
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
    pass(b"FCNTL_OWNER_SIG");
}

/// Test F_GETOWN returns 0 for unset owner
fn test_getown_unset() {
    let path = b"/tmp/fcntl_owner_unset\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        fail_num(b"FCNTL_OWNER_UNSET:FAIL: open returned ", fd);
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
    pass(b"FCNTL_OWNER_UNSET");
}

/// F_SETOWN takes any pid a task still uses, here only as its session
/// (Linux f_setown: find_vpid, no other check): session leader P reaped,
/// its child C in a group of its own; F_GETOWN then reads 0 (no task
/// is P's process or in group P: pid_task NULL)
fn test_setown_session_pid() {
    const NAME: &[u8] = b"FCNTL_OWNER_SESSION_PID";
    let mut ready = [0i32; 2];
    if sys_pipe2(ready.as_mut_ptr(), 0) != 0 {
        fail_num(b"FCNTL_OWNER_SESSION_PID:FAIL: pipe2 ", -1);
        return;
    }
    let p = sys_fork();
    if p == 0 {
        sys_setsid();
        if sys_fork() == 0 {
            // C: a group of its own in P's session, then its pid out
            sys_setpgid(0, 0);
            let me = sys_getpid() as i32;
            sys_write(ready[1] as u64, (&me as *const i32).cast(), 4);
            loop {
                sys_pause();
            }
        }
        sys_exit(0);
    }
    let mut c = 0i32;
    let got = sys_read(ready[0] as u64, (&mut c as *mut i32).cast(), 4);
    let mut st = 0;
    sys_wait4(p, &mut st, 0, 0);
    sys_close(ready[0] as u64);
    sys_close(ready[1] as u64);
    if got != 4 {
        fail_num(b"FCNTL_OWNER_SESSION_PID:FAIL: child pid read ", got);
        return;
    }
    let fd = sys_open(b"/tmp/fcntl_owner_sess\0".as_ptr(), O_RDWR | O_CREAT, 0o644);
    let r = if fd < 0 {
        Err(fd)
    } else {
        let r = [
            sys_fcntl(fd as i32, F_SETOWN, p as u64),
            sys_fcntl(fd as i32, F_GETOWN, 0),
            sys_fcntl(fd as i32, F_SETOWN, (-(p as i32)) as u64),
            sys_fcntl(fd as i32, F_GETOWN, 0),
        ];
        sys_close(fd as u64);
        match r.iter().position(|&x| x != 0) {
            None => Ok(()),
            Some(i) => Err(i as i64 * 1000 + r[i]),
        }
    };
    reap(c as i64);
    match r {
        Ok(()) => pass(NAME),
        Err(v) => fail_num(b"FCNTL_OWNER_SESSION_PID:FAIL: step*1000+ret ", v),
    }
}

/// Test F_SETOWN returns EBADF for invalid fd
fn test_setown_ebadf() {
    let ret = sys_fcntl(9999, F_SETOWN, 42);
    if ret == EBADF {
        pass(b"FCNTL_OWNER_EBADF");
    } else {
        fail_num(b"FCNTL_OWNER_EBADF:FAIL: expected -9, got ", ret);
    }
}
