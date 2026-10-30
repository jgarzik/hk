//! Timers on hrtimers (run on hk and real Linux)
//!
//! - TIMERFD_ABSTIME_RT: an absolute CLOCK_REALTIME timerfd fires at its
//!   wall-clock time
//! - TIMERFD_CANCEL_ON_SET: with TFD_TIMER_CANCEL_ON_SET, setting the
//!   clock makes the timerfd readable and its read fail with ECANCELED
//!   once
//! - TIMERFD_PERIODIC_COUNT: a periodic timerfd counts elapsed/period
//!   expirations (within one)
//! - POSIX_TIMER_ABSTIME_RT: an absolute CLOCK_REALTIME POSIX timer
//!   reports its remaining time and expires at its wall-clock time
//!
//! Bounds are loose (TCG).

use super::sk::T;
use hk_syscall::{
    CLOCK_MONOTONIC, CLOCK_REALTIME, ITimerSpec, PollFd, SigEvent, TFD_NONBLOCK,
    TFD_TIMER_ABSTIME, TFD_TIMER_CANCEL_ON_SET, TIMER_ABSTIME, Timespec, sigev_notify,
    sys_clock_gettime, sys_clock_settime, sys_close, sys_nanosleep, sys_ppoll, sys_read,
    sys_timer_create, sys_timer_delete, sys_timer_gettime, sys_timer_settime, sys_timerfd_create,
    sys_timerfd_settime,
};

const EAGAIN: i64 = -11;
const ECANCELED: i64 = -125;

pub fn run_tests() {
    test_timerfd_abstime_rt();
    test_timerfd_cancel_on_set();
    test_timerfd_periodic_count();
    test_posix_timer_abstime_rt();
}

fn clock_ns(clock: i32) -> i64 {
    let mut t = ts(0);
    sys_clock_gettime(clock, &mut t);
    t.tv_sec * 1_000_000_000 + t.tv_nsec
}

fn ts(ns: i64) -> Timespec {
    Timespec {
        tv_sec: ns / 1_000_000_000,
        tv_nsec: ns % 1_000_000_000,
    }
}

fn spec(value: i64, interval: i64) -> ITimerSpec {
    ITimerSpec {
        it_interval: ts(interval),
        it_value: ts(value),
    }
}

fn sleep_ns(ns: i64) {
    let r = ts(ns);
    sys_nanosleep(&r, core::ptr::null_mut());
}

/// Read a timerfd's expiration count (or a negative errno)
fn tfd_read(fd: i64) -> i64 {
    let mut n = 0u64;
    let r = sys_read(fd as u64, &mut n as *mut u64 as *mut u8, 8);
    if r < 0 { r } else { n as i64 }
}

fn test_timerfd_abstime_rt() {
    let mut t = T::new(b"TIMERFD_ABSTIME_RT");
    let fd = sys_timerfd_create(CLOCK_REALTIME, 0);
    t.ok(b"create", fd >= 0, fd);
    let start = clock_ns(CLOCK_MONOTONIC);
    let s = spec(clock_ns(CLOCK_REALTIME) + 50_000_000, 0);
    let r = sys_timerfd_settime(fd as i32, TFD_TIMER_ABSTIME, &s, core::ptr::null_mut());
    t.eq(b"settime", r, 0);
    t.eq(b"read", tfd_read(fd), 1);
    let el = clock_ns(CLOCK_MONOTONIC) - start;
    t.ok(b"elapsed", (40_000_000..2_000_000_000).contains(&el), el);
    sys_close(fd as u64);
    t.done();
}

fn test_timerfd_cancel_on_set() {
    let mut t = T::new(b"TIMERFD_CANCEL_ON_SET");
    let fd = sys_timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
    let s = spec(clock_ns(CLOCK_REALTIME) + 60_000_000_000, 0);
    let flags = TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET;
    t.eq(b"settime", sys_timerfd_settime(fd as i32, flags, &s, core::ptr::null_mut()), 0);
    t.eq(b"read before", tfd_read(fd), EAGAIN);
    // Set the clock to (about) now: the offset changes
    let now = ts(clock_ns(CLOCK_REALTIME) + 1_000_000);
    t.eq(b"clock_settime", sys_clock_settime(CLOCK_REALTIME, &now), 0);
    let mut pfd = [PollFd {
        fd: fd as i32,
        events: 1,
        revents: 0,
    }];
    let zero = ts(0);
    t.eq(b"readable", sys_ppoll(pfd.as_mut_ptr(), 1, &zero, 0, 0), 1);
    t.eq(b"read canceled", tfd_read(fd), ECANCELED);
    t.eq(b"read again", tfd_read(fd), EAGAIN);
    sys_close(fd as u64);
    t.done();
}

fn test_timerfd_periodic_count() {
    let mut t = T::new(b"TIMERFD_PERIODIC_COUNT");
    let fd = sys_timerfd_create(CLOCK_MONOTONIC, 0);
    let s = spec(10_000_000, 10_000_000);
    let start = clock_ns(CLOCK_MONOTONIC);
    t.eq(b"settime", sys_timerfd_settime(fd as i32, 0, &s, core::ptr::null_mut()), 0);
    sleep_ns(200_000_000);
    let n = tfd_read(fd);
    let want = (clock_ns(CLOCK_MONOTONIC) - start) / 10_000_000;
    t.ok(b"count", (n - want).abs() <= 1, n);
    sys_close(fd as u64);
    t.done();
}

fn test_posix_timer_abstime_rt() {
    let mut t = T::new(b"POSIX_TIMER_ABSTIME_RT");
    let sev = SigEvent {
        sigev_notify: sigev_notify::SIGEV_NONE,
        ..SigEvent::default()
    };
    let mut id = -1i32;
    t.eq(b"create", sys_timer_create(CLOCK_REALTIME, &sev, &mut id), 0);
    let s = spec(clock_ns(CLOCK_REALTIME) + 100_000_000, 0);
    t.eq(b"settime", sys_timer_settime(id, TIMER_ABSTIME, &s, core::ptr::null_mut()), 0);
    let mut cur = spec(0, 0);
    sys_timer_gettime(id, &mut cur);
    let left = cur.it_value.tv_sec * 1_000_000_000 + cur.it_value.tv_nsec;
    t.ok(b"left", left > 0 && left <= 100_000_000, left);
    sleep_ns(150_000_000);
    sys_timer_gettime(id, &mut cur);
    let left = cur.it_value.tv_sec * 1_000_000_000 + cur.it_value.tv_nsec;
    t.eq(b"expired", left, 0);
    sys_timer_delete(id);
    t.done();
}
