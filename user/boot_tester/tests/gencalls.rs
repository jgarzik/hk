//! Syscalls in the generic table that aarch64 once left undispatched
//! (ENOSYS there): dup, getcwd, execveat (gettimeofday and
//! settimeofday are in sysinfo.rs)
//!
//! Tests:
//! - GEN_DUP: dup returns the lowest free fd, sharing the open file
//! - GEN_GETCWD: getcwd returns "/" with its length (NUL included), and
//!   ERANGE for a buffer too small
//! - GEN_EXECVEAT: execveat(AT_FDCWD, path) runs the program

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_RDONLY, sys_close, sys_dup, sys_execveat, sys_exit, sys_fork, sys_getcwd, sys_lseek,
    sys_open, sys_wait4,
};

const AT_FDCWD: i32 = -100;
const ERANGE: i64 = -34;

pub fn run_tests() {
    dup();
    getcwd();
    execveat();
}

fn report(name: &[u8], ok: bool, detail: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(detail);
        println(b"");
    }
}

fn dup() {
    let fd = sys_open(b"/test.txt\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        report(b"GEN_DUP", false, fd);
        return;
    }
    let d = sys_dup(fd as i32);
    // The duplicate shares the file offset
    let shared = d > fd && sys_lseek(fd as i32, 3, 0) == 3 && sys_lseek(d as i32, 0, 1) == 3;
    sys_close(fd as u64);
    if d >= 0 {
        sys_close(d as u64);
    }
    report(b"GEN_DUP", shared, d);
}

fn getcwd() {
    let mut buf = [0u8; 64];
    let n = sys_getcwd(buf.as_mut_ptr(), buf.len());
    let ok = n == 2 && &buf[..2] == b"/\0";
    let small = sys_getcwd(buf.as_mut_ptr(), 1);
    report(b"GEN_GETCWD", ok && small == ERANGE, if ok { small } else { n });
}

fn execveat() {
    let pid = sys_fork();
    if pid == 0 {
        let argv = [b"true\0".as_ptr(), core::ptr::null()];
        let envp = [core::ptr::null()];
        let r = sys_execveat(
            AT_FDCWD,
            b"/bin/busybox\0".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            0,
        );
        sys_exit((-r) as u64 & 0x7f | 0x80);
    }
    let mut st = 0i32;
    if pid < 0 || sys_wait4(pid, &mut st, 0, 0) != pid {
        report(b"GEN_EXECVEAT", false, pid);
        return;
    }
    report(b"GEN_EXECVEAT", st == 0, st as i64);
}
