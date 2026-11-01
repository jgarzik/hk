//! `#!` scripts (Linux fs/binfmt_script.c); the scripts are written here
//! and run busybox's echo, whose output goes to a file
//!
//! Tests:
//! - SCRIPT_EXEC: `#!/bin/echo -n` runs echo with argv [interpreter,
//!   argument, script path, original argv[1..]]
//! - SCRIPT_ARG_SPACES: the argument is the rest of the line, inner
//!   spaces kept
//! - SCRIPT_NESTED: a script whose interpreter is a script works five
//!   levels deep; six is ELOOP
//! - SCRIPT_BAD: a missing interpreter is ENOENT, an empty `#!` line
//!   ENOEXEC
//! - SCRIPT_FD: a script run through execveat(fd, "", AT_EMPTY_PATH)
//!   gets /dev/fd/N as its path; through a close-on-exec fd it is ENOENT

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_CLOEXEC, O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY, sys_close, sys_dup3, sys_execve,
    sys_execveat, sys_exit, sys_fork, sys_open, sys_read, sys_unlink, sys_wait4, sys_write,
};

const OUT: &[u8] = b"/scr_out\0";
const ENOENT: i64 = 2;
const ENOEXEC: i64 = 8;
const ELOOP: i64 = 40;
const AT_EMPTY_PATH: i32 = 0x1000;

pub fn run_tests() {
    exec();
    arg_spaces();
    nested();
    bad();
    by_fd();
    for p in [
        &b"/scr_a\0"[..],
        b"/scr_b\0",
        b"/scr_x\0",
        b"/scr_y\0",
        b"/scr_1\0",
        b"/scr_2\0",
        b"/scr_3\0",
        b"/scr_4\0",
        b"/scr_5\0",
        b"/scr_6\0",
    ] {
        sys_unlink(p.as_ptr());
    }
    sys_unlink(OUT.as_ptr());
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

/// Write an executable file
fn script(path: &[u8], body: &[u8]) {
    let fd = sys_open(path.as_ptr(), O_CREAT | O_WRONLY | O_TRUNC, 0o755);
    sys_write(fd as u64, body.as_ptr(), body.len() as u64);
    sys_close(fd as u64);
}

/// Child: stdout to OUT, then execve(path, [path, "x"]) or, with `fd`,
/// execveat(fd, "", AT_EMPTY_PATH); returns the exit status (the exec
/// errno + 0x80 if it failed)
fn run(path: &[u8], fd: i32) -> i32 {
    let pid = sys_fork();
    if pid == 0 {
        let o = sys_open(OUT.as_ptr(), O_CREAT | O_WRONLY | O_TRUNC, 0o644);
        sys_dup3(o as i32, 1, 0);
        let argv = [path.as_ptr(), b"x\0".as_ptr(), core::ptr::null()];
        let envp = [core::ptr::null()];
        let r = if fd >= 0 {
            sys_execveat(fd, b"\0".as_ptr(), argv.as_ptr(), envp.as_ptr(), AT_EMPTY_PATH)
        } else {
            sys_execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        };
        sys_exit(0x80 | (-r) as u64 & 0x7f);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f == 0 { (st >> 8) & 0xff } else { -1 }
}

fn output(buf: &mut [u8]) -> &[u8] {
    let fd = sys_open(OUT.as_ptr(), O_RDONLY, 0);
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    sys_close(fd as u64);
    &buf[..n.max(0) as usize]
}

fn exec() {
    script(b"/scr_a\0", b"#!/bin/echo -n\nignored\n");
    let st = run(b"/scr_a\0", -1);
    let mut b = [0u8; 64];
    report(b"SCRIPT_EXEC", st == 0 && output(&mut b) == b"/scr_a x", st as i64);
}

fn arg_spaces() {
    script(b"/scr_b\0", b"#! /bin/echo  a  b \t\n");
    let st = run(b"/scr_b\0", -1);
    let mut b = [0u8; 64];
    report(
        b"SCRIPT_ARG_SPACES",
        st == 0 && output(&mut b) == b"a  b /scr_b x\n",
        st as i64,
    );
}

fn nested() {
    script(b"/scr_1\0", b"#!/bin/echo -n\n");
    script(b"/scr_2\0", b"#!/scr_1\n");
    script(b"/scr_3\0", b"#!/scr_2\n");
    script(b"/scr_4\0", b"#!/scr_3\n");
    script(b"/scr_5\0", b"#!/scr_4\n");
    script(b"/scr_6\0", b"#!/scr_5\n");
    let five = run(b"/scr_5\0", -1);
    let mut b = [0u8; 128];
    let out = output(&mut b);
    // echo -n /scr_1 /scr_2 /scr_3 /scr_4 /scr_5 x
    let ok5 = five == 0 && out == b"/scr_1 /scr_2 /scr_3 /scr_4 /scr_5 x";
    let six = run(b"/scr_6\0", -1);
    let ok6 = six == 0x80 | ELOOP as i32;
    report(
        b"SCRIPT_NESTED",
        ok5 && ok6,
        if ok5 { six as i64 } else { five as i64 },
    );
}

fn bad() {
    script(b"/scr_x\0", b"#!/no/such/interp\n");
    script(b"/scr_y\0", b"#!\n");
    let missing = run(b"/scr_x\0", -1);
    let empty = run(b"/scr_y\0", -1);
    report(
        b"SCRIPT_BAD",
        missing == 0x80 | ENOENT as i32 && empty == 0x80 | ENOEXEC as i32,
        (missing << 8 | empty) as i64,
    );
}

fn by_fd() {
    let fd = sys_open(b"/scr_a\0".as_ptr(), O_RDONLY, 0) as i32;
    let st = run(b"/scr_a\0", fd);
    sys_close(fd as u64);
    let mut b = [0u8; 64];
    let mut want = [0u8; 16];
    let w = b"/dev/fd/";
    want[..w.len()].copy_from_slice(w);
    let mut n = w.len();
    let mut digits = [0u8; 4];
    let mut d = 0;
    let mut v = fd;
    loop {
        digits[d] = b'0' + (v % 10) as u8;
        d += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while d > 0 {
        d -= 1;
        want[n] = digits[d];
        n += 1;
    }
    want[n..n + 2].copy_from_slice(b" x");
    let ok = st == 0 && output(&mut b) == &want[..n + 2];
    let cfd = sys_open(b"/scr_a\0".as_ptr(), O_RDONLY | O_CLOEXEC, 0) as i32;
    let cst = run(b"/scr_a\0", cfd);
    sys_close(cfd as u64);
    report(
        b"SCRIPT_FD",
        ok && cst == 0x80 | ENOENT as i32,
        if ok { cst as i64 } else { st as i64 },
    );
}
