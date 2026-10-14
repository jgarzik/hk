//! Standard descriptors are ordinary fd-table entries (Linux): init
//! starts with /dev/console on 0/1/2 (console_on_rootfs); dup2/close
//! on 0/1/2 behave like on any other descriptor

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_dup3, sys_exit, sys_fork, sys_fstat, sys_getpid, sys_pipe, sys_read, sys_wait4,
    sys_write, Stat,
};

const EBADF: i64 = -9;
const S_IFMT: u32 = 0o170000;
const S_IFCHR: u32 = 0o020000;

pub fn run_tests() {
    test_console_fds();
    test_stdout_pipe();
    test_stdin_pipe();
    test_close_stdout();
}

fn verdict(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(got);
        println(b"");
    }
}

/// Run `f` in a child and report its exit status (0 = pass)
fn in_child(name: &[u8], f: fn() -> u64) {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f());
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    verdict(name, st == 0, st as i64);
}

/// init's 0/1/2 are the console character device
fn test_console_fds() {
    if sys_getpid() != 1 {
        return; // run by hand on a host: stdio is whatever the shell gave
    }
    let mut ok = true;
    let mut got = 0;
    for fd in 0..3 {
        let mut st: Stat = unsafe { core::mem::zeroed() };
        let r = sys_fstat(fd, &mut st);
        if r != 0 || st.st_mode & S_IFMT != S_IFCHR {
            ok = false;
            got = if r != 0 { r } else { st.st_mode as i64 };
        }
    }
    verdict(b"STDIO_CONSOLE_FDS", ok, got);
}

/// write(1) after dup2(pipe, 1) lands in the pipe, not on the console
fn test_stdout_pipe() {
    let mut p = [0i32; 2];
    if sys_pipe(p.as_mut_ptr()) != 0 {
        verdict(b"STDIO_STDOUT_PIPE", false, -1);
        return;
    }
    let pid = sys_fork();
    if pid == 0 {
        sys_close(p[0] as u64);
        if sys_dup3(p[1], 1, 0) != 1 {
            sys_exit(2);
        }
        sys_close(p[1] as u64);
        let n = sys_write(1, b"to-pipe".as_ptr(), 7);
        sys_exit(if n == 7 { 0 } else { 3 });
    }
    sys_close(p[1] as u64);
    let mut buf = [0u8; 16];
    let mut len = 0usize;
    loop {
        let n = sys_read(p[0] as u64, buf[len..].as_mut_ptr(), (buf.len() - len) as u64);
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    sys_close(p[0] as u64);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    verdict(b"STDIO_STDOUT_PIPE", st == 0 && &buf[..len] == b"to-pipe", len as i64);
}

/// read(0) after dup2(pipe, 0) returns the pipe's data
fn test_stdin_pipe() {
    in_child(b"STDIO_STDIN_PIPE", || {
        let mut p = [0i32; 2];
        if sys_pipe(p.as_mut_ptr()) != 0 {
            return 2;
        }
        sys_write(p[1] as u64, b"abc".as_ptr(), 3);
        sys_close(p[1] as u64);
        if sys_dup3(p[0], 0, 0) != 0 {
            return 3;
        }
        let mut buf = [0u8; 8];
        let n = sys_read(0, buf.as_mut_ptr(), buf.len() as u64);
        if n != 3 || &buf[..3] != b"abc" {
            return 4;
        }
        // Write end closed: EOF next
        if sys_read(0, buf.as_mut_ptr(), buf.len() as u64) != 0 {
            return 5;
        }
        0
    });
}

/// close(1) really closes it: write(1) is EBADF afterwards
fn test_close_stdout() {
    in_child(b"STDIO_CLOSE_STDOUT", || {
        if sys_close(1) != 0 {
            return 2;
        }
        if sys_write(1, b"x".as_ptr(), 1) != EBADF {
            return 3;
        }
        // A second close of the same fd fails too
        if sys_close(1) != EBADF {
            return 4;
        }
        0
    });
}
