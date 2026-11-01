//! Every clock id (Linux posix-timers k_clock table and posix-cpu-timers)
//!
//! Tests:
//! - CLOCK_IDS_GET: clock_gettime and clock_getres work for realtime,
//!   monotonic, both CPU-time clocks, monotonic_raw, both coarse clocks,
//!   boottime and TAI; high-resolution clocks report 1ns, coarse ones a
//!   tick (1us..100ms); unknown ids (10, 12) are EINVAL
//! - CLOCK_IDS_ORDER: boottime >= monotonic, raw within 1s of
//!   monotonic, a coarse clock never ahead of its fine clock, TAI a
//!   whole number of seconds (0..40) past realtime
//! - CLOCK_IDS_CPU: process CPU time grows while spinning, the thread
//!   clock is not past the process clock; a CPU clock id built from a
//!   pid reads that process (another process too), a thread clock of
//!   another process or a missing pid is EINVAL
//! - CLOCK_IDS_SLEEP: clock_nanosleep on boottime (relative) and TAI
//!   (absolute) sleeps; raw and coarse clocks are EOPNOTSUPP
//! - CLOCK_IDS_TIMERS: timerfd and timer_create on boottime work (the
//!   timerfd fires), timerfd on monotonic_raw is EINVAL

use super::helpers::{print, print_num, println};
use hk_syscall::{
    ITimerSpec, SigEvent, Timespec, sys_clock_getres, sys_clock_gettime, sys_clock_nanosleep,
    sys_close, sys_exit, sys_fork, sys_getpid, sys_kill, sys_read, sys_timer_create,
    sys_timer_delete, sys_timerfd_create, sys_timerfd_settime, sys_wait4,
};

const REALTIME: i32 = 0;
const MONOTONIC: i32 = 1;
const PROCESS_CPU: i32 = 2;
const THREAD_CPU: i32 = 3;
const RAW: i32 = 4;
const REALTIME_COARSE: i32 = 5;
const MONOTONIC_COARSE: i32 = 6;
const BOOTTIME: i32 = 7;
const TAI: i32 = 11;
const TIMER_ABSTIME: i32 = 1;
const EINVAL: i64 = -22;
const EOPNOTSUPP: i64 = -95;
const SIGKILL: i32 = 9;
const SEC: i64 = 1_000_000_000;

pub fn run_tests() {
    get();
    order();
    cpu();
    sleep();
    timers();
}

fn report(name: &[u8], why: &[u8], detail: i64) {
    print(name);
    if why.is_empty() {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print(why);
        print(b" ");
        print_num(detail);
        println(b"");
    }
}

/// clock_gettime in ns, or the errno (negative)
fn now(id: i32) -> Result<i64, i64> {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    match sys_clock_gettime(id, &mut ts) {
        0 => Ok(ts.tv_sec * SEC + ts.tv_nsec as i64),
        e => Err(e),
    }
}

fn res(id: i32) -> Result<i64, i64> {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    match sys_clock_getres(id, &mut ts) {
        0 => Ok(ts.tv_sec * SEC + ts.tv_nsec as i64),
        e => Err(e),
    }
}

/// Linux MAKE_PROCESS_CPUCLOCK / MAKE_THREAD_CPUCLOCK (CPUCLOCK_SCHED)
fn cpuclock(pid: i64, thread: bool) -> i32 {
    ((!(pid as i32)) << 3) | if thread { 4 } else { 0 } | 2
}

fn get() {
    let n = b"CLOCK_IDS_GET";
    let hres = [REALTIME, MONOTONIC, PROCESS_CPU, THREAD_CPU, RAW, BOOTTIME, TAI];
    for id in hres {
        if now(id).is_err() {
            return report(n, b"gettime", id as i64);
        }
        if res(id) != Ok(1) {
            return report(n, b"hres getres", id as i64);
        }
    }
    for id in [REALTIME_COARSE, MONOTONIC_COARSE] {
        let r = res(id).unwrap_or(0);
        if now(id).is_err() || !(1_000..=100_000_000).contains(&r) {
            return report(n, b"coarse", id as i64);
        }
    }
    for id in [10, 12] {
        if now(id) != Err(EINVAL) || res(id) != Err(EINVAL) {
            return report(n, b"bad id not EINVAL", id as i64);
        }
    }
    report(n, b"", 0);
}

fn order() {
    let n = b"CLOCK_IDS_ORDER";
    let mono = now(MONOTONIC).unwrap_or(0);
    let boot = now(BOOTTIME).unwrap_or(0);
    if boot < mono {
        return report(n, b"boottime < monotonic", (mono - boot) as i64);
    }
    let raw = now(RAW).unwrap_or(0);
    if (raw - now(MONOTONIC).unwrap_or(0)).abs() > SEC {
        return report(n, b"raw far from monotonic", 0);
    }
    for (coarse, fine) in [(MONOTONIC_COARSE, MONOTONIC), (REALTIME_COARSE, REALTIME)] {
        let c = now(coarse).unwrap_or(i64::MAX);
        let f = now(fine).unwrap_or(0);
        if c > f {
            return report(n, b"coarse ahead", coarse as i64);
        }
    }
    let rt = now(REALTIME).unwrap_or(0);
    let tai = now(TAI).unwrap_or(0);
    let off = tai - rt;
    let secs = (off + SEC / 2) / SEC;
    if !(0..=40).contains(&secs) || (off - secs * SEC).abs() > SEC / 10 {
        return report(n, b"tai offset", off as i64);
    }
    report(n, b"", 0);
}

fn cpu() {
    let n = b"CLOCK_IDS_CPU";
    let before = now(PROCESS_CPU).unwrap_or(0);
    let start = now(MONOTONIC).unwrap_or(0);
    while now(MONOTONIC).unwrap_or(i64::MAX) - start < 30_000_000 {
        core::hint::spin_loop();
    }
    let after = now(PROCESS_CPU).unwrap_or(0);
    if after <= before {
        return report(n, b"process clock did not grow", (after - before) as i64);
    }
    if now(THREAD_CPU).unwrap_or(i64::MAX) > now(PROCESS_CPU).unwrap_or(0) {
        return report(n, b"thread past process", 0);
    }
    if now(cpuclock(sys_getpid(), false)).is_err() {
        return report(n, b"own pid clock", 0);
    }
    // Another process: its process clock reads, its thread clock is EINVAL
    let pid = sys_fork();
    if pid == 0 {
        loop {
            core::hint::spin_loop();
        }
    }
    let other = now(cpuclock(pid, false));
    let other_thread = now(cpuclock(pid, true));
    sys_kill(pid, SIGKILL as u32);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if other.is_err() {
        return report(n, b"other process clock", other.unwrap_err());
    }
    if other_thread != Err(EINVAL) {
        return report(n, b"other thread clock", 0);
    }
    // The child is gone
    if now(cpuclock(pid, false)) != Err(EINVAL) {
        return report(n, b"missing pid not EINVAL", pid);
    }
    report(n, b"", 0);
}

fn ts(ns: i64) -> Timespec {
    Timespec {
        tv_sec: (ns / SEC) as i64,
        tv_nsec: (ns % SEC) as i64,
    }
}

fn sleep() {
    let n = b"CLOCK_IDS_SLEEP";
    let start = now(MONOTONIC).unwrap_or(0);
    let req = ts(10_000_000);
    let r = sys_clock_nanosleep(BOOTTIME, 0, &req, core::ptr::null_mut());
    if r != 0 || now(MONOTONIC).unwrap_or(0) - start < 10_000_000 {
        return report(n, b"boottime", r);
    }
    let until = now(TAI).unwrap_or(0) + 10_000_000;
    let req = ts(until);
    let r = sys_clock_nanosleep(TAI, TIMER_ABSTIME, &req, core::ptr::null_mut());
    if r != 0 || now(TAI).unwrap_or(0) < until {
        return report(n, b"tai", r);
    }
    for id in [RAW, MONOTONIC_COARSE, REALTIME_COARSE] {
        let req = ts(1_000_000);
        let r = sys_clock_nanosleep(id, 0, &req, core::ptr::null_mut());
        if r != EOPNOTSUPP {
            return report(n, b"not EOPNOTSUPP", id as i64);
        }
    }
    report(n, b"", 0);
}

fn timers() {
    let n = b"CLOCK_IDS_TIMERS";
    if sys_timerfd_create(RAW, 0) != EINVAL {
        return report(n, b"timerfd raw", 0);
    }
    let fd = sys_timerfd_create(BOOTTIME, 0);
    if fd < 0 {
        return report(n, b"timerfd boottime", fd);
    }
    let spec = ITimerSpec {
        it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: ts(5_000_000),
    };
    let set = sys_timerfd_settime(fd as i32, 0, &spec, core::ptr::null_mut());
    let mut exp = [0u8; 8];
    let got = sys_read(fd as u64, exp.as_mut_ptr(), 8);
    sys_close(fd as u64);
    if set != 0 || got != 8 || u64::from_ne_bytes(exp) == 0 {
        return report(n, b"timerfd fire", got);
    }
    let pid = sys_fork();
    if pid == 0 {
        // SIGEV_NONE
        let sev = SigEvent {
            sigev_notify: 1,
            ..SigEvent::default()
        };
        let mut id = 0i32;
        let r = sys_timer_create(BOOTTIME, &sev, &mut id);
        if r == 0 {
            sys_timer_delete(id);
        }
        sys_exit((-r) as u64 & 0xff);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st != 0 {
        return report(n, b"timer_create boottime", (st >> 8) as i64);
    }
    report(n, b"", 0);
}
