//! /proc entries follow their tasks and fds (Linux pid_revalidate,
//! tid_fd_revalidate, proc_flush_pid): a reaped process's directory and
//! a closed fd's link are gone even after being looked up, the owner of
//! a process's files follows its dumpability, and inode numbers do not
//! collide

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_RDONLY, PR_SET_DUMPABLE, Stat, sys_close, sys_exit, sys_fork, sys_kill, sys_open,
    sys_pipe2, sys_prctl, sys_read, sys_readlink, sys_setgid, sys_setuid, sys_stat, sys_wait4,
    sys_write,
};

const ENOENT: i64 = -2;
const SIGKILL: u32 = 9;

pub fn run_tests() {
    report(b"PROC_PID_GONE", pid_gone());
    report(b"PROC_FD_CLOSED", fd_closed());
    report(b"PROC_OWNER_REFRESH", owner_refresh());
    report(b"PROC_INO_UNIQUE", ino_unique());
}

type R = Result<(), (&'static [u8], i64)>;

fn report(name: &[u8], r: R) {
    print(name);
    match r {
        Ok(()) => println(b":OK"),
        Err((why, got)) => {
            print(b":FAIL ");
            print(why);
            print(b" got ");
            print_num(got);
            println(b"");
        }
    }
}

fn check(what: &'static [u8], ok: bool, got: i64) -> R {
    if ok { Ok(()) } else { Err((what, got)) }
}

fn stat(p: &[u8]) -> Result<Stat, i64> {
    // SAFETY: Stat is plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    match sys_stat(p.as_ptr(), &mut st) {
        0 => Ok(st),
        e => Err(e),
    }
}

/// "/proc/<n>/<rest>" NUL-terminated in `buf`
fn proc_path<'a>(buf: &'a mut [u8; 64], n: i64, rest: &[u8]) -> &'a [u8] {
    let mut d = [0u8; 20];
    let (mut v, mut k) = (n as u64, 0);
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut i = 0;
    for &c in b"/proc/".iter().chain(d[..k].iter().rev()).chain(rest) {
        buf[i] = c;
        i += 1;
    }
    buf[i] = 0;
    &buf[..=i]
}

/// A child that waits until its stdin pipe closes or it is killed
fn waiting_child() -> (i64, i32) {
    let mut fds = [0i32; 2];
    sys_pipe2(fds.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        sys_close(fds[1] as u64);
        let mut b = [0u8; 1];
        sys_read(fds[0] as u64, b.as_mut_ptr(), 1);
        sys_exit(0);
    }
    sys_close(fds[0] as u64);
    (pid, fds[1])
}

/// Looked up while the process lived, gone once it is reaped
fn pid_gone() -> R {
    let (pid, w) = waiting_child();
    let mut b = [0u8; 64];
    let dir = proc_path(&mut b, pid, b"");
    let mut b2 = [0u8; 64];
    let status = proc_path(&mut b2, pid, b"/status");
    let alive = stat(&dir).is_ok() && stat(&status).is_ok();
    sys_kill(pid, SIGKILL);
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    sys_close(w as u64);
    check(b"alive", alive, -1)?;
    check(b"dir gone", stat(&dir).err() == Some(ENOENT), -1)?;
    check(b"file gone", stat(&status).err() == Some(ENOENT), -1)
}

/// /proc/self/fd/N and fdinfo/N go with the fd
fn fd_closed() -> R {
    let fd = sys_open(b"/proc/self/status\0".as_ptr(), O_RDONLY, 0);
    check(b"open", fd >= 0, fd)?;
    let me = hk_syscall::sys_getpid();
    let mut b = [0u8; 64];
    let mut rest = *b"/fd/\0\0\0\0";
    let mut rest2 = *b"/fdinfo/\0\0\0\0";
    let (mut v, mut d, mut k) = (fd as u32, [0u8; 4], 0);
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..k {
        rest[4 + i] = d[k - 1 - i];
        rest2[8 + i] = d[k - 1 - i];
    }
    let link = proc_path(&mut b, me, &rest[..4 + k]);
    let mut b2 = [0u8; 64];
    let info = proc_path(&mut b2, me, &rest2[..8 + k]);
    let open = stat(&link).is_ok() && stat(&info).is_ok();
    sys_close(fd as u64);
    check(b"open entries", open, -1)?;
    check(b"link gone", stat(&link).err() == Some(ENOENT), -1)?;
    let mut t = [0u8; 32];
    let r = sys_readlink(link.as_ptr(), t.as_mut_ptr(), t.len() as u64);
    check(b"readlink gone", r == ENOENT, r)?;
    check(b"fdinfo gone", stat(&info).err() == Some(ENOENT), -1)
}

/// A process's files belong to its euid while it is dumpable, to root
/// once it is not, checked afresh on every lookup
fn owner_refresh() -> R {
    let (mut go, mut done) = ([0i32; 2], [0i32; 2]);
    sys_pipe2(go.as_mut_ptr(), 0);
    sys_pipe2(done.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        let mut b = [0u8; 1];
        sys_setgid(1000);
        sys_setuid(1000);
        sys_prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
        sys_write(done[1] as u64, b"r".as_ptr(), 1);
        sys_read(go[0] as u64, b.as_mut_ptr(), 1);
        sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        sys_write(done[1] as u64, b"d".as_ptr(), 1);
        sys_read(go[0] as u64, b.as_mut_ptr(), 1);
        sys_exit(0);
    }
    let mut b = [0u8; 1];
    let mut pb = [0u8; 64];
    let env = proc_path(&mut pb, pid, b"/environ");
    sys_read(done[0] as u64, b.as_mut_ptr(), 1);
    let before = stat(&env).map_or(-1, |s| s.st_uid as i64);
    sys_write(go[1] as u64, b"g".as_ptr(), 1);
    sys_read(done[0] as u64, b.as_mut_ptr(), 1);
    let after = stat(&env).map_or(-1, |s| s.st_uid as i64);
    sys_write(go[1] as u64, b"g".as_ptr(), 1);
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    for f in [go[0], go[1], done[0], done[1]] {
        sys_close(f as u64);
    }
    check(b"dumpable owner", before == 1000, before)?;
    check(b"non-dumpable owner", after == 0, after)
}

/// Distinct entries have distinct inode numbers
fn ino_unique() -> R {
    let ino = |p: &[u8]| stat(p).map_or(0, |s| s.st_ino);
    let task = ino(b"/proc/self/task\0");
    let status = ino(b"/proc/self/status\0");
    check(b"task vs status", task != 0 && task != status, task as i64)?;
    let fd0 = ino(b"/proc/self/fd/0\0");
    let info0 = ino(b"/proc/self/fdinfo/0\0");
    check(b"fd vs fdinfo", fd0 != 0 && fd0 != info0, fd0 as i64)?;
    let init = ino(b"/proc/1\0");
    let me = ino(b"/proc/self/\0");
    check(b"pid dirs", init != 0 && (init != me || hk_syscall::sys_getpid() == 1), init as i64)
}
