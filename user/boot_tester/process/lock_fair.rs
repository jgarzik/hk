//! Sleeping-lock fairness (run on hk and real Linux)
//!
//! - MUTEX_HANDOFF: children share a regular file's open file with the
//!   parent and relock its position lock (Linux f_pos_lock) back to back,
//!   with a rewind and a 1 MiB read; the parent's lseeks, which sleep on
//!   that mutex, each finish within a bound. Without a handoff to the
//!   sleeping waiter, a relocker wins every race after each unlock and
//!   the parent starves.

use crate::harness::T;
use hk_syscall::{
    CLOCK_MONOTONIC, MAP_ANONYMOUS, MAP_PRIVATE, O_CREAT, O_RDWR, O_TRUNC, PROT_READ, PROT_WRITE,
    Timespec, sys_clock_gettime, sys_close, sys_fork, sys_kill, sys_lseek, sys_mmap, sys_munmap,
    sys_nanosleep, sys_open, sys_read, sys_unlink, sys_wait4, sys_write,
};

const SIGKILL: u32 = 9;
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;

pub fn run_tests() {
    test_mutex_handoff();
}

fn now_us() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec * 1_000_000 + ts.tv_nsec / 1000
}

fn sleep_ms(ms: i64) {
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: ms * 1_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// Each relocker read holds the position lock this long
const CHUNK: u64 = 1 << 20;
const RELOCKERS: usize = 3;
/// The parent's locked operations
const OPS: usize = 200;
/// Longest any one may wait (a starved one waits for seconds)
const MAX_OP_US: i64 = 200_000;

/// Rewind and read the file back to back until killed
fn relocker(fd: u64, buf: u64) -> ! {
    loop {
        sys_lseek(fd as i32, 0, SEEK_SET);
        sys_read(fd, buf as *mut u8, CHUNK);
    }
}

/// The slowest of `OPS` runs of `op` (us), giving up after a few times
/// the bound
fn slowest(mut op: impl FnMut()) -> i64 {
    let (mut worst, start) = (0, now_us());
    for _ in 0..OPS {
        let t0 = now_us();
        op();
        worst = worst.max(now_us() - t0);
        if now_us() - start > MAX_OP_US * 5 {
            break;
        }
    }
    worst
}

fn test_mutex_handoff() {
    let mut t = T::new(b"MUTEX_HANDOFF");
    let path = b"/tmp/mutex_handoff\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o600);
    let buf = sys_mmap(
        0,
        CHUNK,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if !t.ok(b"open", fd >= 0, fd) || !t.ok(b"mmap", buf > 0, buf) {
        return t.done();
    }
    let (fd, buf) = (fd as u64, buf as u64);
    let w = sys_write(fd, buf as *const u8, CHUNK);
    t.eq(b"fill", w, CHUNK as i64);
    let mut pids = [0i64; RELOCKERS];
    for pid in pids.iter_mut() {
        *pid = sys_fork();
        if *pid == 0 {
            relocker(fd, buf);
        }
    }
    sleep_ms(20);
    let worst = slowest(|| {
        sys_lseek(fd as i32, 0, SEEK_CUR);
    });
    for &pid in pids.iter() {
        if pid > 0 {
            sys_kill(pid, SIGKILL);
            let mut st = 0i32;
            sys_wait4(pid, &mut st, 0, 0);
        }
    }
    sys_close(fd);
    sys_unlink(path.as_ptr());
    sys_munmap(buf, CHUNK);
    t.ok(b"forks", pids.iter().all(|&p| p > 0), 0);
    t.ok(b"slowest lseek (us)", worst < MAX_OP_US, worst);
    t.done();
}
