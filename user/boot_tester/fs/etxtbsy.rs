//! ETXTBSY (Linux deny_write_access / get_write_access, S_SWAPFILE)
//!
//! Tests:
//! - ETXTBSY_OPEN: the running program cannot be opened for writing,
//!   nor opened O_TRUNC; reading it works
//! - ETXTBSY_TRUNC: nor truncated by path
//! - ETXTBSY_EXEC: a file open for writing cannot be executed
//! - ETXTBSY_EXIT: an exited program's file opens for writing while
//!   its address space is still held (an open /proc/<pid>/maps)
//! - EXE_EXIT_UMOUNT: then its filesystem unmounts

use crate::helpers::{print, print_num, println};
use hk_syscall::{
    O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, SIGKILL, sys_close, sys_dup3, sys_execve,
    sys_exit, sys_fork, sys_kill, sys_link, sys_mkdir, sys_mount, sys_open, sys_pipe2,
    sys_pwrite64, sys_read, sys_rmdir, sys_truncate, sys_umount2, sys_unlink, sys_wait4, sys_write,
};

const ETXTBSY: i64 = -26;

pub fn run_tests() {
    open_exe();
    exec_writer();
    exe_exit();
}

const MNT_DETACH: u64 = 2;

/// The executable's write denial and its mount go with the last user of
/// the address space (Linux __mmput: set_mm_exe_file(mm, NULL)), not
/// with the address space itself, which an open /proc/<pid>/maps keeps
/// (Linux proc_mem_open: mmgrab): a program on a tmpfs mount, run
/// through one name and unlinked, exits; its other name opens for
/// writing, and once that is unlinked too the mount unmounts
fn exe_exit() {
    let dir = b"/tmp/exe_exit\0";
    let exe = b"/tmp/exe_exit/bt2\0";
    let alias = b"/tmp/exe_exit/bt2b\0";
    sys_mkdir(dir.as_ptr(), 0o755);
    let tmpfs = b"tmpfs\0".as_ptr();
    let m = sys_mount(tmpfs, dir.as_ptr(), tmpfs, 0, 0);
    let copied =
        m == 0 && copy(b"/bin/boot_tester2\0", exe) && sys_link(exe.as_ptr(), alias.as_ptr()) == 0;
    let (mut w, mut u, mut maps) = (-1000, -1000, -1000);
    if copied {
        let pid = spawn_sleeper(exe);
        let mut buf = [0u8; 32];
        maps = sys_open(proc_maps(pid, &mut buf).as_ptr(), O_RDONLY, 0);
        sys_unlink(exe.as_ptr());
        sys_kill(pid, SIGKILL);
        let mut st = 0i32;
        sys_wait4(pid, &mut st, 0, 0);
        w = sys_open(alias.as_ptr(), O_WRONLY, 0);
        if w >= 0 {
            sys_close(w as u64);
        }
        sys_unlink(alias.as_ptr());
        u = sys_umount2(dir.as_ptr(), 0);
        if maps >= 0 {
            sys_close(maps as u64);
        }
    }
    if m == 0 && u != 0 {
        sys_umount2(dir.as_ptr(), MNT_DETACH);
    }
    sys_rmdir(dir.as_ptr());
    verdict(
        b"ETXTBSY_EXIT",
        copied && maps >= 0 && w >= 0,
        [m, maps, w, 0],
    );
    verdict(b"EXE_EXIT_UMOUNT", copied && u == 0, [m, u, 0, 0]);
}

/// Copy `src` to a new executable `dst`
fn copy(src: &[u8], dst: &[u8]) -> bool {
    let s = sys_open(src.as_ptr(), O_RDONLY, 0);
    let d = sys_open(dst.as_ptr(), O_CREAT | O_WRONLY | O_TRUNC, 0o755);
    let mut ok = s >= 0 && d >= 0;
    let mut buf = [0u8; 4096];
    while ok {
        let n = sys_read(s as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n <= 0 {
            ok = n == 0;
            break;
        }
        ok = sys_write(d as u64, buf.as_ptr(), n as u64) == n;
    }
    for fd in [s, d] {
        if fd >= 0 {
            sys_close(fd as u64);
        }
    }
    ok
}

/// A child running `path` as `boot_tester2 sleep`, ready (it wrote to
/// fd 3) when this returns
fn spawn_sleeper(path: &[u8]) -> i64 {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        sys_dup3(p[1], 3, 0);
        let argv = [
            b"boot_tester2\0".as_ptr(),
            b"sleep\0".as_ptr(),
            core::ptr::null(),
        ];
        let envp = [core::ptr::null::<u8>()];
        sys_execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(99);
    }
    let mut b = [0u8; 1];
    sys_read(p[0] as u64, b.as_mut_ptr(), 1);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    pid
}

/// "/proc/<pid>/maps\0" in `buf`
fn proc_maps(pid: i64, buf: &mut [u8; 32]) -> &[u8] {
    let mut n = 0;
    let mut put = |c: u8| {
        buf[n] = c;
        n += 1;
    };
    b"/proc/".iter().for_each(|&c| put(c));
    let mut digits = [0u8; 20];
    let (mut v, mut k) = (pid as u64, 0);
    loop {
        digits[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    digits[..k].iter().rev().for_each(|&c| put(c));
    b"/maps\0".iter().for_each(|&c| put(c));
    &buf[..n]
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
    verdict(
        b"ETXTBSY_OPEN",
        w == ETXTBSY && t == ETXTBSY && r >= 0,
        [w, t, r, 0],
    );
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
    verdict(
        b"ETXTBSY_EXEC",
        src >= 0 && off > 0 && code == 42,
        [src, off, code as i64, 0],
    );
}
