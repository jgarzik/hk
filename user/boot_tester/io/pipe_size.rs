//! Pipe size (Linux pipe_fcntl, pipe_set_size, fs.pipe-max-size)
//!
//! - PIPE_SZ: a new pipe holds 16 pages (F_GETPIPE_SZ 65536);
//!   F_SETPIPE_SZ rounds up to a power of two pages (0 -> one page) and
//!   returns the new size; past 2^31 is EINVAL; fewer pages than are in
//!   use is EBUSY; what is buffered survives a resize; a one-page pipe
//!   takes one page (a nonblocking write past it is EAGAIN); a file
//!   that is not a pipe is EBADF
//! - PIPE_SZ_MAX: above fs.pipe-max-size needs CAP_SYS_RESOURCE (EPERM
//!   without); the sysctl reads 1048576, rounds what is written up to a
//!   power of two pages and refuses a negative value
//! - PIPE_USER_PAGES: fs.pipe-user-pages-soft reads 16384, -hard 0;
//!   for an unprivileged user over the soft limit a new pipe has two
//!   pages and cannot grow (EPERM), past the hard limit pipe() is
//!   ENFILE (Linux alloc_pipe_info, account_pipe_buffers)

use crate::harness::{R, check, report_r};
use crate::proc::sysctl::{read_file, write_file};
use hk_syscall::{
    CapUserData, CapUserHeader, O_RDONLY, sys_capget, sys_capset, sys_close, sys_exit, sys_fcntl,
    sys_fork, sys_open, sys_pipe2, sys_read, sys_wait4, sys_write,
};

const F_SETPIPE_SZ: i32 = 1031;
const F_GETPIPE_SZ: i32 = 1032;
const O_NONBLOCK: u32 = 0o4000;
const EAGAIN: i64 = -11;
const EBADF: i64 = -9;
const EBUSY: i64 = -16;
const EINVAL: i64 = -22;
const EPERM: i64 = -1;
const CAP_SYS_RESOURCE: u32 = 24;
const PAGE: usize = 4096;
const MAX: &[u8] = b"/proc/sys/fs/pipe-max-size\0";
const SOFT: &[u8] = b"/proc/sys/fs/pipe-user-pages-soft\0";
const HARD: &[u8] = b"/proc/sys/fs/pipe-user-pages-hard\0";
const ENFILE: i64 = -23;

pub fn run_tests() {
    report_r(b"PIPE_SZ", with_pipe(sizes));
    report_r(b"PIPE_SZ_MAX", size_max());
    report_r(b"PIPE_USER_PAGES", user_pages());
}

/// Run `f` on a fresh nonblocking pipe, closed after it
fn with_pipe(f: fn(i32, i32) -> R) -> R {
    let mut fds = [0i32; 2];
    let r = sys_pipe2(fds.as_mut_ptr(), O_NONBLOCK);
    check(b"pipe2", r == 0, r)?;
    let r = f(fds[0], fds[1]);
    sys_close(fds[0] as u64);
    sys_close(fds[1] as u64);
    r
}

fn set(fd: i32, size: u64) -> i64 {
    sys_fcntl(fd, F_SETPIPE_SZ, size)
}

fn get(fd: i32) -> i64 {
    sys_fcntl(fd, F_GETPIPE_SZ, 0)
}

fn sizes(r: i32, w: i32) -> R {
    check(b"default", get(r) == 65536, get(r))?;
    let n = set(w, 4096);
    check(b"one page", n == 4096, n)?;
    check(b"get one page", get(r) == 4096, get(r))?;
    let n = set(w, 5000);
    check(b"rounded", n == 8192, n)?;
    let n = set(w, 0);
    check(b"zero", n == 4096, n)?;
    let n = set(w, 0x8000_0001);
    check(b"past 2^31", n == EINVAL, n)?;
    // Two pages in use: one slot is too few
    let n = set(w, 4 * PAGE as u64);
    check(b"four pages", n == 16384, n)?;
    let page = [0x5au8; PAGE];
    for _ in 0..2 {
        let n = sys_write(w as u64, page.as_ptr(), PAGE as u64);
        check(b"fill", n == PAGE as i64, n)?;
    }
    let n = set(w, 4096);
    check(b"busy", n == EBUSY, n)?;
    let n = set(w, 8192);
    check(b"to two pages", n == 8192, n)?;
    let n = sys_write(w as u64, page.as_ptr(), 1);
    check(b"full", n == EAGAIN, n)?;
    let mut buf = [0u8; 2 * PAGE];
    let n = sys_read(r as u64, buf.as_mut_ptr(), buf.len() as u64);
    check(
        b"kept",
        n == 2 * PAGE as i64 && buf.iter().all(|&b| b == 0x5a),
        n,
    )?;
    let n = set(w, 4096);
    check(b"emptied", n == 4096, n)?;
    let n = sys_write(w as u64, page.as_ptr(), PAGE as u64);
    check(b"one page fits", n == PAGE as i64, n)?;
    let n = sys_write(w as u64, page.as_ptr(), 1);
    check(b"one page full", n == EAGAIN, n)?;
    let fd = sys_open(b"/dev/null\0".as_ptr(), O_RDONLY, 0) as i32;
    let n = get(fd);
    sys_close(fd as u64);
    check(b"not a pipe", n == EBADF, n)
}

/// The sysctl's value, or -1
fn max_size() -> i64 {
    let mut b = [0u8; 32];
    let n = read_file(MAX, &mut b);
    if n <= 1 {
        return -1;
    }
    b[..n as usize - 1]
        .iter()
        .try_fold(0i64, |a, &d| {
            d.is_ascii_digit().then(|| a * 10 + i64::from(d - b'0'))
        })
        .unwrap_or(-1)
}

fn size_max() -> R {
    let old = max_size();
    check(b"default max", old == 1 << 20, old)?;
    let r = max_steps();
    write_file(MAX, b"1048576\n");
    r
}

fn max_steps() -> R {
    check(b"write", write_file(MAX, b"5000\n") == 5, 0)?;
    check(b"rounded", max_size() == 8192, max_size())?;
    let n = write_file(MAX, b"-1\n");
    check(b"negative", n == EINVAL, n)?;
    check(b"write back", write_file(MAX, b"1048576\n") == 8, 0)?;
    // Root (CAP_SYS_RESOURCE) may go past it
    let n = with_pipe(|_, w| {
        let n = set(w, 2 << 20);
        check(b"admin past max", n == 2 << 20, n)
    });
    n?;
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(unprivileged() as u64);
    }
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    check(b"unprivileged", ws == 0, i64::from(ws >> 8))
}

/// Without CAP_SYS_RESOURCE: past the max is EPERM, up to it works; 0
/// or the failed step
fn unprivileged() -> u8 {
    let mut h = CapUserHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut d = [CapUserData::default(); 2];
    if sys_capget(&mut h, d.as_mut_ptr()) != 0 {
        return 1;
    }
    d[0].effective &= !(1 << CAP_SYS_RESOURCE);
    if sys_capset(&h, d.as_ptr()) != 0 {
        return 2;
    }
    let mut fds = [0i32; 2];
    if sys_pipe2(fds.as_mut_ptr(), 0) != 0 {
        return 3;
    }
    if set(fds[1], 2 << 20) != EPERM {
        return 4;
    }
    if set(fds[1], 1 << 20) != 1 << 20 {
        return 5;
    }
    0
}

fn user_pages() -> R {
    let mut b = [0u8; 32];
    let n = read_file(SOFT, &mut b);
    check(b"soft", n > 0 && &b[..n as usize] == b"16384\n", n)?;
    let n = read_file(HARD, &mut b);
    check(b"hard", n > 0 && &b[..n as usize] == b"0\n", n)?;
    check(b"set soft", write_file(SOFT, b"4\n") == 2, 0)?;
    check(b"set hard", write_file(HARD, b"4\n") == 2, 0)?;
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(limited() as u64);
    }
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    write_file(SOFT, b"16384\n");
    write_file(HARD, b"0\n");
    check(b"limited user", ws == 0, i64::from(ws >> 8))
}

/// As a user of its own, without capabilities, both limits at 4
/// slots: a new pipe over the soft limit gets 2 slots and may not
/// grow (EPERM) but may shrink; one past the hard limit is ENFILE. 0
/// or the failed step
fn limited() -> u8 {
    const UID: u32 = 31337;
    if hk_syscall::sys_setresgid(UID, UID, UID) != 0
        || hk_syscall::sys_setresuid(UID, UID, UID) != 0
    {
        return 1;
    }
    let mut p = [[0i32; 2]; 3];
    if sys_pipe2(p[0].as_mut_ptr(), 0) != 0 {
        return 2;
    }
    if get(p[0][0]) != 8192 {
        return 3;
    }
    if set(p[0][1], 65536) != EPERM {
        return 4;
    }
    if set(p[0][1], 4096) != 4096 {
        return 5;
    }
    // 1 + 2 slots: within the hard limit; then 5 is past it
    if sys_pipe2(p[1].as_mut_ptr(), 0) != 0 || get(p[1][0]) != 8192 {
        return 6;
    }
    if sys_pipe2(p[2].as_mut_ptr(), 0) != ENFILE {
        return 7;
    }
    0
}
