//! ETXTBSY (Linux deny_write_access / get_write_access, S_SWAPFILE)
//!
//! Tests:
//! - ETXTBSY_OPEN: the running program cannot be opened for writing,
//!   nor opened O_TRUNC; reading it works
//! - ETXTBSY_TRUNC: nor truncated by path
//! - ETXTBSY_EXEC: a file open for writing cannot be executed

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, sys_close, sys_execve, sys_exit, sys_fork,
    sys_open, sys_pwrite64, sys_truncate, sys_unlink, sys_wait4,
};

const ETXTBSY: i64 = -26;

pub fn run_tests() {
    open_exe();
    exec_writer();
}

fn verdict(name: &[u8], ok: bool, got: [i64; 4]) {
    print(name);
    if ok {
        println(b":OK");
        return;
    }
    print(b":FAIL");
    for g in got {
        print(b" ");
        print_num(g);
    }
    println(b"");
}

fn open_exe() {
    let exe = b"/proc/self/exe\0";
    let w = sys_open(exe.as_ptr(), O_WRONLY, 0);
    let t = sys_open(exe.as_ptr(), O_RDONLY | O_TRUNC, 0);
    let r = sys_open(exe.as_ptr(), O_RDONLY, 0);
    if r >= 0 {
        sys_close(r as u64);
    }
    verdict(b"ETXTBSY_OPEN", w == ETXTBSY && t == ETXTBSY && r >= 0, [w, t, r, 0]);
    let tr = sys_truncate(exe.as_ptr(), 0);
    verdict(b"ETXTBSY_TRUNC", tr == ETXTBSY, [tr, 0, 0, 0]);
}

/// Exec of a file someone has open for writing is ETXTBSY: a copy of
/// /bin/true kept open O_WRONLY by the parent
fn exec_writer() {
    let path = b"/tmp/txtbsy_true\0";
    let src = sys_open(b"/bin/true\0".as_ptr(), O_RDONLY, 0);
    let dst = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o755);
    let mut buf = [0u8; 4096];
    let mut off = 0i64;
    loop {
        let n = hk_syscall::sys_read(src as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n <= 0 {
            break;
        }
        sys_pwrite64(dst as i32, buf.as_ptr(), n as u64, off);
        off += n;
    }
    sys_close(src as u64);
    let pid = sys_fork();
    if pid == 0 {
        let argv = [path.as_ptr(), core::ptr::null()];
        let envp = [core::ptr::null::<u8>()];
        let r = sys_execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(if r == ETXTBSY { 42 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    sys_close(dst as u64);
    sys_unlink(path.as_ptr());
    let code = (st >> 8) & 0xff;
    verdict(b"ETXTBSY_EXEC", src >= 0 && off > 0 && code == 42, [src, off, code as i64, 0]);
}
