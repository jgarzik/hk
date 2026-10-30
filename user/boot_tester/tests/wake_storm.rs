//! Wakeup storms (run on hk and real Linux)
//!
//! - WAKE_STORM_FUTEX: 32 processes wait on one shared futex word through
//!   1000 FUTEX_WAKE-all rounds; every one sees the last round and exits
//! - WAKE_STORM_PIPE: 5000 one-byte round trips between two processes
//!   over a pipe pair
//!
//! Bounded by a deadline so a lost wakeup shows up as FAIL, not a hang.

use super::sk::T;
use hk_syscall::{
    CLOCK_MONOTONIC, FUTEX_WAIT, FUTEX_WAKE, MAP_ANONYMOUS, MAP_SHARED, PROT_READ, PROT_WRITE,
    Timespec, sys_clock_gettime, sys_close, sys_exit, sys_fork, sys_futex, sys_kill, sys_mmap,
    sys_munmap, sys_pipe2, sys_read, sys_wait4, sys_write,
};

const WAITERS: usize = 32;
const ROUNDS: u32 = 1000;
const WNOHANG: i32 = 1;

pub fn run_tests() {
    test_futex_storm();
    test_pipe_storm();
}

fn now_ms() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

/// Reap `pids` within `ms`; how many exited 0
fn reap_all(pids: &[i64], ms: i64) -> usize {
    let end = now_ms() + ms;
    let mut done = [false; WAITERS];
    let mut ok = 0;
    while now_ms() < end && done.iter().take(pids.len()).any(|d| !d) {
        for (i, &p) in pids.iter().enumerate() {
            let mut st = 0i32;
            if !done[i] && sys_wait4(p, &mut st, WNOHANG, 0) == p {
                done[i] = true;
                ok += (st == 0) as usize;
            }
        }
        let nap = Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        hk_syscall::sys_nanosleep(&nap, core::ptr::null_mut());
    }
    for (i, &p) in pids.iter().enumerate() {
        if !done[i] {
            sys_kill(p, 9);
            let mut st = 0i32;
            sys_wait4(p, &mut st, 0, 0);
        }
    }
    ok
}

fn test_futex_storm() {
    let mut t = T::new(b"WAKE_STORM_FUTEX");
    let map = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if !t.ok(b"mmap", map > 0, map) {
        return t.done();
    }
    let word = map as *mut u32;
    let mut pids = [0i64; WAITERS];
    for p in pids.iter_mut() {
        let pid = sys_fork();
        if pid == 0 {
            // Wait out every round: the word only grows
            loop {
                // SAFETY: the shared page stays mapped in this process
                let v = unsafe { core::ptr::read_volatile(word) };
                if v >= ROUNDS {
                    sys_exit(0);
                }
                sys_futex(word, FUTEX_WAIT, v, core::ptr::null(), core::ptr::null_mut(), 0);
            }
        }
        *p = pid;
    }
    for r in 1..=ROUNDS {
        // SAFETY: as above
        unsafe { core::ptr::write_volatile(word, r) };
        sys_futex(word, FUTEX_WAKE, i32::MAX as u32, core::ptr::null(), core::ptr::null_mut(), 0);
    }
    let ok = reap_all(&pids, 20_000);
    t.eq(b"waiters done", ok as i64, WAITERS as i64);
    sys_munmap(map as u64, 4096);
    t.done();
}

fn test_pipe_storm() {
    let mut t = T::new(b"WAKE_STORM_PIPE");
    let (mut a, mut b) = ([0i32; 2], [0i32; 2]);
    sys_pipe2(a.as_mut_ptr(), 0);
    sys_pipe2(b.as_mut_ptr(), 0);
    let n = 5000;
    let pid = sys_fork();
    if pid == 0 {
        let mut c = [0u8; 1];
        for _ in 0..n {
            if sys_read(a[0] as u64, c.as_mut_ptr(), 1) != 1 {
                sys_exit(1);
            }
            sys_write(b[1] as u64, c.as_ptr(), 1);
        }
        sys_exit(0);
    }
    let mut c = [7u8; 1];
    let mut good = 0;
    for _ in 0..n {
        sys_write(a[1] as u64, c.as_ptr(), 1);
        if sys_read(b[0] as u64, c.as_mut_ptr(), 1) == 1 {
            good += 1;
        }
    }
    t.eq(b"round trips", good, n);
    t.eq(b"child", reap_all(&[pid], 20_000) as i64, 1);
    for fd in [a[0], a[1], b[0], b[1]] {
        sys_close(fd as u64);
    }
    t.done();
}
