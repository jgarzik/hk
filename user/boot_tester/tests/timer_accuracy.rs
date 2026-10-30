//! Timeout accuracy (run on hk and real Linux)
//!
//! - TIMER_ACCURACY: nanosleep, clock_nanosleep (TIMER_ABSTIME), ppoll,
//!   pselect6, epoll_pwait2 and FUTEX_WAIT never return before their
//!   timeout, overshoot it by under 50 ms on average, and a 1 ms sleep
//!   takes well under a 10 ms tick (high-resolution timers)
//! - POLL_SUBMS: a 500 us ppoll timeout blocks (it is not rounded down
//!   to a non-blocking call)
//! - SELECT_REMAINING: ppoll, pselect6 (and select on x86-64) write the
//!   time left back to the user's timeout (Linux poll_select_finish)
//! - ABSTIME_RT_SETTIME: an absolute CLOCK_REALTIME clock_nanosleep wakes
//!   when the clock is set past its deadline, and keeps sleeping when the
//!   clock is set back
//!
//! Bounds are loose (TCG).

use super::sk::T;
use hk_syscall::{
    CLOCK_MONOTONIC, CLOCK_REALTIME, EpollEvent, FUTEX_WAIT, FdSet, TIMER_ABSTIME, Timespec,
    sys_clock_gettime, sys_clock_nanosleep, sys_clock_settime, sys_close, sys_epoll_create1,
    sys_epoll_pwait2, sys_exit, sys_fork, sys_futex, sys_nanosleep, sys_pipe2, sys_ppoll,
    sys_pselect6, sys_read, sys_wait4, sys_write,
};

/// Mean overshoot allowed per kind of wait (ns)
const MAX_MEAN_LATE: i64 = 50_000_000;

pub fn run_tests() {
    test_accuracy();
    test_poll_subms();
    test_select_remaining();
    test_abstime_rt_settime();
}

fn clock_ns(clock: i32) -> i64 {
    let mut ts = ts(0);
    sys_clock_gettime(clock, &mut ts);
    ts.tv_sec * 1_000_000_000 + ts.tv_nsec
}

fn ts(ns: i64) -> Timespec {
    Timespec {
        tv_sec: ns / 1_000_000_000,
        tv_nsec: ns % 1_000_000_000,
    }
}

/// Run `wait(timeout_ns)` 8 times; check it never returns early and the
/// mean overshoot is bounded. Returns the shortest elapsed time.
fn measure(t: &mut T, why: &[u8], timeout_ns: i64, wait: &dyn Fn(i64)) -> i64 {
    let (mut late, mut min) = (0i64, i64::MAX);
    for _ in 0..8 {
        let start = clock_ns(CLOCK_MONOTONIC);
        wait(timeout_ns);
        let el = clock_ns(CLOCK_MONOTONIC) - start;
        if !t.ok(why, el >= timeout_ns, el) {
            return el;
        }
        late += el - timeout_ns;
        min = min.min(el);
    }
    t.ok(why, late / 8 < MAX_MEAN_LATE, late / 8);
    min
}

fn test_accuracy() {
    let mut t = T::new(b"TIMER_ACCURACY");
    let ns = |d: i64| {
        let r = ts(d);
        sys_nanosleep(&r, core::ptr::null_mut());
    };
    let abs = |d: i64| {
        let r = ts(clock_ns(CLOCK_MONOTONIC) + d);
        sys_clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &r, core::ptr::null_mut());
    };
    let ppoll = |d: i64| {
        let r = ts(d);
        sys_ppoll(core::ptr::null_mut(), 0, &r, 0, 0);
    };
    let pselect = |d: i64| {
        let r = ts(d);
        let null = core::ptr::null_mut();
        sys_pselect6(0, null, null, null, &r, 0);
    };
    let ep = sys_epoll_create1(0) as i32;
    let epoll = |d: i64| {
        let r = ts(d);
        let mut ev = [EpollEvent { events: 0, data: 0 }; 1];
        sys_epoll_pwait2(ep, ev.as_mut_ptr(), 1, &r, core::ptr::null(), 0);
    };
    let futex = |d: i64| {
        let mut word = 0u32;
        let r = ts(d);
        sys_futex(&mut word, FUTEX_WAIT, 0, &r, core::ptr::null_mut(), 0);
    };
    measure(&mut t, b"nanosleep", 3_000_000, &ns);
    measure(&mut t, b"clock_nanosleep abs", 3_000_000, &abs);
    measure(&mut t, b"ppoll", 3_000_000, &ppoll);
    measure(&mut t, b"pselect6", 3_000_000, &pselect);
    measure(&mut t, b"epoll_pwait2", 3_000_000, &epoll);
    measure(&mut t, b"futex", 3_000_000, &futex);
    // A 1 ms sleep: the fastest of 8 well under a 10 ms tick
    let min = measure(&mut t, b"nanosleep 1ms", 1_000_000, &ns);
    t.ok(b"1ms sleep min", min < 5_000_000, min);
    sys_close(ep as u64);
    t.done();
}

fn test_poll_subms() {
    let mut t = T::new(b"POLL_SUBMS");
    let start = clock_ns(CLOCK_MONOTONIC);
    let r = ts(500_000);
    let ret = sys_ppoll(core::ptr::null_mut(), 0, &r, 0, 0);
    let el = clock_ns(CLOCK_MONOTONIC) - start;
    t.eq(b"ret", ret, 0);
    t.ok(b"blocked", el >= 500_000, el);
    t.done();
}

/// A pipe with a byte ready to read
fn ready_pipe() -> [i32; 2] {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    p
}

fn test_select_remaining() {
    let mut t = T::new(b"SELECT_REMAINING");
    let p = ready_pipe();
    // Ready at once: nearly all of 5 s is left
    let mut r = ts(5_000_000_000);
    let mut pfd = [hk_syscall::PollFd {
        fd: p[0],
        events: 1,
        revents: 0,
    }];
    t.eq(b"ppoll ret", sys_ppoll(pfd.as_mut_ptr(), 1, &mut r, 0, 0), 1);
    let left = r.tv_sec * 1_000_000_000 + r.tv_nsec;
    t.ok(b"ppoll left", (4_000_000_000..5_000_000_000).contains(&left), left);
    let mut set = FdSet::new();
    set.bits[p[0] as usize / 64] |= 1 << (p[0] % 64);
    let mut r = ts(5_000_000_000);
    let null = core::ptr::null_mut();
    t.eq(b"pselect ret", sys_pselect6(p[0] + 1, &mut set, null, null, &mut r, 0), 1);
    let left = r.tv_sec * 1_000_000_000 + r.tv_nsec;
    t.ok(b"pselect left", (4_000_000_000..5_000_000_000).contains(&left), left);
    // Timed out: nothing left
    let mut r = ts(20_000_000);
    t.eq(b"pselect timeout", sys_pselect6(0, null, null, null, &mut r, 0), 0);
    t.eq(b"pselect zero", r.tv_sec + r.tv_nsec, 0);
    #[cfg(target_arch = "x86_64")]
    {
        let mut tv = hk_syscall::Timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        let mut set = FdSet::new();
        set.bits[p[0] as usize / 64] |= 1 << (p[0] % 64);
        t.eq(b"select ret", hk_syscall::sys_select(p[0] + 1, &mut set, null, null, &mut tv), 1);
        let left = tv.tv_sec * 1_000_000 + tv.tv_usec;
        t.ok(b"select left", (4_000_000..5_000_000).contains(&left), left);
    }
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    t.done();
}

/// Step CLOCK_REALTIME by `delta` ns
fn step_rt(delta: i64) -> i64 {
    let r = ts(clock_ns(CLOCK_REALTIME) + delta);
    sys_clock_settime(CLOCK_REALTIME, &r)
}

/// Fork a child that sleeps until CLOCK_REALTIME + `rel` ns (absolute)
/// and reports its elapsed CLOCK_MONOTONIC ms through a pipe; run
/// `step` in the parent, then return that elapsed time (-1 on error)
fn rt_sleeper(rel: i64, step: &dyn Fn() -> i64) -> i64 {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let deadline = ts(clock_ns(CLOCK_REALTIME) + rel);
    let pid = sys_fork();
    if pid == 0 {
        let start = clock_ns(CLOCK_MONOTONIC);
        let r = sys_clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &deadline, core::ptr::null_mut());
        let el = if r == 0 {
            (clock_ns(CLOCK_MONOTONIC) - start) / 1_000_000
        } else {
            -1
        };
        sys_write(p[1] as u64, &el as *const i64 as *const u8, 8);
        sys_exit(0);
    }
    // Let the child block first
    let nap = ts(100_000_000);
    sys_nanosleep(&nap, core::ptr::null_mut());
    if step() != 0 {
        return -2;
    }
    let mut el = -1i64;
    sys_read(p[0] as u64, &mut el as *mut i64 as *mut u8, 8);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    el
}

fn test_abstime_rt_settime() {
    let mut t = T::new(b"ABSTIME_RT_SETTIME");
    // Deadline 10 s ahead; the clock jumps 20 s: wake right away
    let el = rt_sleeper(10_000_000_000, &|| step_rt(20_000_000_000));
    step_rt(-20_000_000_000);
    t.ok(b"forward step wakes", (0..3000).contains(&el), el);
    // Deadline 300 ms ahead; the clock goes back 1 s: about 1.3 s
    let el = rt_sleeper(300_000_000, &|| step_rt(-1_000_000_000));
    step_rt(1_000_000_000);
    t.ok(b"backward step sleeps on", (1100..5000).contains(&el), el);
    t.done();
}
