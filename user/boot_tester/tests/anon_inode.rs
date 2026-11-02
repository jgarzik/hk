//! Anonymous inodes and pipefs (Linux fs/anon_inodes.c, fs/pipe.c),
//! and the ctime update of chmod/chown (notify_change ATTR_CTIME)
//!
//! Tests:
//! - ANON_INODE_LINK: /proc/self/fd names of eventfd, epoll, signalfd,
//!   timerfd, inotify and pidfd files
//! - ANON_INODE_SHARED: those files share one inode, mode 0600 with no
//!   file type
//! - PIPE_INO: each pipe has its own nonzero inode, `pipe:[ino]`
//! - CHMOD_CTIME: chmod and chown (even of nothing) advance ctime

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_CREAT, O_WRONLY, Stat, Timespec, sys_chmod, sys_chown, sys_close, sys_epoll_create1,
    sys_eventfd2, sys_fstat, sys_getpid, sys_inotify_init1, sys_nanosleep, sys_open,
    sys_pidfd_open, sys_pipe2, sys_readlink, sys_signalfd4, sys_stat, sys_timerfd_create,
    sys_unlink,
};

const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;
const CLOCK_MONOTONIC: i32 = 1;

pub fn run_tests() {
    anon_link();
    anon_shared();
    pipe_ino();
    chmod_ctime();
}

/// Write `n` in decimal into `buf`, returning the digits
fn fmt_num(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

/// readlink("/proc/self/fd/<fd>") into `out`; length or -errno
fn fd_link(fd: i64, out: &mut [u8; 64]) -> i64 {
    let mut path = [0u8; 40];
    let pre = b"/proc/self/fd/";
    path[..pre.len()].copy_from_slice(pre);
    let mut nb = [0u8; 20];
    let d = fmt_num(fd as u64, &mut nb);
    path[pre.len()..pre.len() + d.len()].copy_from_slice(d);
    sys_readlink(path.as_ptr(), out.as_mut_ptr(), out.len() as u64)
}

/// The anonymous files under test, with their expected link targets
fn open_anon(fds: &mut [i64; 6]) {
    let mask: u64 = 1 << (10 - 1); // SIGUSR1
    fds[0] = sys_eventfd2(0, 0);
    fds[1] = sys_epoll_create1(0);
    fds[2] = sys_signalfd4(-1, &mask, 8, 0);
    fds[3] = sys_timerfd_create(CLOCK_MONOTONIC, 0);
    fds[4] = sys_inotify_init1(0);
    fds[5] = sys_pidfd_open(sys_getpid() as i32, 0);
}

const NAMES: [&[u8]; 6] = [
    b"anon_inode:[eventfd]",
    b"anon_inode:[eventpoll]",
    b"anon_inode:[signalfd]",
    b"anon_inode:[timerfd]",
    b"anon_inode:inotify",
    b"anon_inode:[pidfd]",
];

fn close_all(fds: &[i64]) {
    for &fd in fds {
        if fd >= 0 {
            sys_close(fd as u64);
        }
    }
}

fn anon_link() {
    let mut fds = [0i64; 6];
    open_anon(&mut fds);
    let mut ok = true;
    for (i, &fd) in fds.iter().enumerate() {
        let mut buf = [0u8; 64];
        let n = fd_link(fd, &mut buf);
        if fd < 0 || n < 0 || &buf[..n as usize] != NAMES[i] {
            print(b"ANON_INODE_LINK:FAIL ");
            print(NAMES[i]);
            print(b" fd=");
            print_num(fd);
            print(b" got ");
            if n > 0 {
                print(&buf[..n as usize]);
            } else {
                print_num(n);
            }
            println(b"");
            ok = false;
        }
    }
    close_all(&fds);
    if ok {
        println(b"ANON_INODE_LINK:OK");
    }
}

fn anon_shared() {
    let mut fds = [0i64; 6];
    open_anon(&mut fds);
    let mut first = zst();
    let mut ok = sys_fstat(fds[0] as i32, &mut first) == 0;
    // pidfd moved to its own filesystem (pidfs) after Linux 6.8
    for &fd in &fds[1..5] {
        let mut st = zst();
        if sys_fstat(fd as i32, &mut st) != 0 || st.st_ino != first.st_ino {
            ok = false;
        }
    }
    if ok && first.st_mode == 0o600 {
        println(b"ANON_INODE_SHARED:OK");
    } else {
        print(b"ANON_INODE_SHARED:FAIL mode ");
        print_num(first.st_mode as i64);
        println(b"");
    }
    close_all(&fds);
}

fn pipe_ino() {
    let mut a = [0i32; 2];
    let mut b = [0i32; 2];
    if sys_pipe2(a.as_mut_ptr(), 0) != 0 || sys_pipe2(b.as_mut_ptr(), 0) != 0 {
        println(b"PIPE_INO:FAIL pipe2");
        return;
    }
    let (mut sa, mut sa1, mut sb) = (zst(), zst(), zst());
    sys_fstat(a[0], &mut sa);
    sys_fstat(a[1], &mut sa1);
    sys_fstat(b[0], &mut sb);
    let mut want = [0u8; 64];
    let pre = b"pipe:[";
    want[..pre.len()].copy_from_slice(pre);
    let mut nb = [0u8; 20];
    let d = fmt_num(sa.st_ino, &mut nb);
    want[pre.len()..pre.len() + d.len()].copy_from_slice(d);
    let wl = pre.len() + d.len() + 1;
    want[wl - 1] = b']';
    let mut got = [0u8; 64];
    let n = fd_link(a[0] as i64, &mut got);
    let ok = sa.st_ino != 0
        && sa.st_ino == sa1.st_ino
        && sa.st_ino != sb.st_ino
        && sa.st_mode & S_IFMT == S_IFIFO
        && n == wl as i64
        && got[..wl] == want[..wl];
    close_all(&[a[0] as i64, a[1] as i64, b[0] as i64, b[1] as i64]);
    if ok {
        println(b"PIPE_INO:OK");
    } else {
        print(b"PIPE_INO:FAIL ino ");
        print_num(sa.st_ino as i64);
        print(b" ");
        print_num(sb.st_ino as i64);
        println(b"");
    }
}

/// ctime as nanoseconds
fn ctime_ns(path: &[u8]) -> i64 {
    let mut st = zst();
    if sys_stat(path.as_ptr(), &mut st) != 0 {
        return -1;
    }
    st.st_ctime * 1_000_000_000 + st.st_ctime_nsec as i64
}

/// Sleep past the coarse clock tick Linux timestamps use
fn pause() {
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 30_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

fn chmod_ctime() {
    let path = b"/tmp/ctime_test\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        println(b"CHMOD_CTIME:FAIL open");
        return;
    }
    sys_close(fd as u64);
    let t0 = ctime_ns(path);
    pause();
    let r1 = sys_chmod(path.as_ptr(), 0o600);
    let t1 = ctime_ns(path);
    pause();
    let r2 = sys_chown(path.as_ptr(), u32::MAX, u32::MAX);
    let t2 = ctime_ns(path);
    sys_unlink(path.as_ptr());
    if r1 == 0 && r2 == 0 && t0 > 0 && t1 > t0 && t2 > t1 {
        println(b"CHMOD_CTIME:OK");
    } else {
        print(b"CHMOD_CTIME:FAIL ");
        print_num(t1 - t0);
        print(b" ");
        print_num(t2 - t1);
        println(b"");
    }
}

fn zst() -> Stat {
    // SAFETY: Stat is plain integers
    unsafe { core::mem::zeroed() }
}
