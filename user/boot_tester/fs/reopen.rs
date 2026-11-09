//! Pipes, sockets and anonymous-inode files live on pseudo filesystems
//! (Linux pipefs, sockfs, anon_inodefs: init_pseudo, kern_mount): fstatfs
//! names each, and opening one again through its path (a /proc/self/fd
//! link, or O_EMPTYPATH since Linux 7.2) goes by its inode's rules: a
//! pipe end joins the same pipe (fifo_open on i_pipe), a socket or an
//! anonymous inode (eventfd) is ENXIO (sock_no_open, no_open_fops)

use crate::harness::{R, check, report_r};
use crate::helpers::linux_at_least;
use hk_syscall::{
    AF_UNIX, LinuxStatFs, O_RDONLY, O_RDWR, O_WRONLY, SOCK_STREAM, sys_close, sys_eventfd2,
    sys_fstatfs, sys_open, sys_openat, sys_pipe2, sys_read, sys_socketpair, sys_write,
};

const ENXIO: i64 = -6;
const ENOENT: i64 = -2;
const O_EMPTYPATH: u32 = 1 << 26;
const PIPEFS_MAGIC: i64 = 0x5049_5045;
const SOCKFS_MAGIC: i64 = 0x534F_434B;
const ANON_INODE_FS_MAGIC: i64 = 0x0904_1934;

pub fn run_tests() {
    report_r(b"PSEUDO_FSTATFS", fstatfs());
    report_r(b"REOPEN_ANON", anon());
    report_r(b"REOPEN_SOCKET", socket());
    report_r(b"REOPEN_PIPE_PROC", pipe_proc());
    report_r(b"REOPEN_PIPE_EMPTYPATH", pipe_emptypath());
}

/// "/proc/self/fd/<fd>\0" in `b`
fn fd_path(b: &mut [u8; 32], fd: i32) -> &[u8] {
    let pre = b"/proc/self/fd/";
    b[..pre.len()].copy_from_slice(pre);
    let mut d = [0u8; 10];
    let (mut v, mut k) = (fd as u32, 0);
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..k {
        b[pre.len() + i] = d[k - 1 - i];
    }
    b[pre.len() + k] = 0;
    &b[..=pre.len() + k]
}

/// Open `fd` again through /proc/self/fd with `flags`
fn proc_reopen(fd: i32, flags: u32) -> i64 {
    let mut b = [0u8; 32];
    sys_open(fd_path(&mut b, fd).as_ptr(), flags, 0)
}

fn magic(fd: i32) -> i64 {
    let mut st = LinuxStatFs::default();
    let r = sys_fstatfs(fd, &mut st);
    if r < 0 { r } else { st.f_type }
}

/// fstatfs of each names its pseudo filesystem
fn fstatfs() -> R {
    let mut p = [0i32; 2];
    let r = sys_pipe2(p.as_mut_ptr(), 0);
    check(b"pipe", r == 0, r)?;
    let pm = magic(p[0]);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    check(b"pipefs", pm == PIPEFS_MAGIC, pm)?;
    let e = sys_eventfd2(0, 0);
    check(b"eventfd", e >= 0, e)?;
    let am = magic(e as i32);
    sys_close(e as u64);
    check(b"anon_inodefs", am == ANON_INODE_FS_MAGIC, am)?;
    let mut sv = [0i32; 2];
    let r = sys_socketpair(AF_UNIX, SOCK_STREAM, 0, &mut sv);
    check(b"socketpair", r == 0, r)?;
    let sm = magic(sv[0]);
    sys_close(sv[0] as u64);
    sys_close(sv[1] as u64);
    check(b"sockfs", sm == SOCKFS_MAGIC, sm)
}

/// An eventfd does not open again: ENXIO through /proc, and through
/// O_EMPTYPATH since 7.2 (ENOENT before: the empty path)
fn anon() -> R {
    let e = sys_eventfd2(0, 0);
    check(b"eventfd", e >= 0, e)?;
    let e = e as i32;
    let r1 = proc_reopen(e, O_RDWR);
    let r2 = sys_openat(e, b"\0".as_ptr(), O_RDWR | O_EMPTYPATH, 0);
    sys_close(e as u64);
    for r in [r1, r2] {
        if r >= 0 {
            sys_close(r as u64);
        }
    }
    check(b"/proc", r1 == ENXIO, r1)?;
    let want = if linux_at_least(7, 2) { ENXIO } else { ENOENT };
    check(b"O_EMPTYPATH", r2 == want, r2)
}

/// A socket does not open again through /proc: ENXIO
fn socket() -> R {
    let mut sv = [0i32; 2];
    let r = sys_socketpair(AF_UNIX, SOCK_STREAM, 0, &mut sv);
    check(b"socketpair", r == 0, r)?;
    let r = proc_reopen(sv[0], O_RDWR);
    if r >= 0 {
        sys_close(r as u64);
    }
    sys_close(sv[0] as u64);
    sys_close(sv[1] as u64);
    check(b"/proc", r == ENXIO, r)
}

/// `w` writes into the pipe whose read end is `rd`: one byte arrives
fn flows(w: i64, rd: i32, c: u8) -> R {
    let n = sys_write(w as u64, [c].as_ptr(), 1);
    check(b"write", n == 1, n)?;
    let mut b = [0u8; 1];
    let n = sys_read(rd as u64, b.as_mut_ptr(), 1);
    check(b"same pipe", n == 1 && b[0] == c, n)
}

/// Each end of a pipe opened again through /proc joins the same pipe
fn pipe_proc() -> R {
    let mut p = [0i32; 2];
    let r = sys_pipe2(p.as_mut_ptr(), 0);
    check(b"pipe", r == 0, r)?;
    let w = proc_reopen(p[1], O_WRONLY);
    let rd = proc_reopen(p[0], O_RDONLY);
    let r = check(b"reopen write end", w >= 0, w)
        .and_then(|()| check(b"reopen read end", rd >= 0, rd))
        .and_then(|()| flows(w, p[0], b'x'))
        .and_then(|()| flows(i64::from(p[1]), rd as i32, b'y'));
    for fd in [w, rd, i64::from(p[0]), i64::from(p[1])] {
        if fd >= 0 {
            sys_close(fd as u64);
        }
    }
    r
}

/// The write end opened again with O_EMPTYPATH (Linux 7.2) joins it
fn pipe_emptypath() -> R {
    let mut p = [0i32; 2];
    let r = sys_pipe2(p.as_mut_ptr(), 0);
    check(b"pipe", r == 0, r)?;
    let w = sys_openat(p[1], b"\0".as_ptr(), O_WRONLY | O_EMPTYPATH, 0);
    let r = if linux_at_least(7, 2) {
        check(b"reopen", w >= 0, w).and_then(|()| flows(w, p[0], b'z'))
    } else {
        check(b"before 7.2", w == ENOENT, w)
    };
    for fd in [w, i64::from(p[0]), i64::from(p[1])] {
        if fd >= 0 {
            sys_close(fd as u64);
        }
    }
    r
}
