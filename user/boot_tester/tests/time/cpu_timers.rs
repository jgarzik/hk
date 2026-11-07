//! Timers and sleeps on CPU-time clocks (Linux
//! kernel/time/posix-cpu-timers.c, itimer.c, RLIMIT_CPU)
//!
//! Each test burns CPU (spinning, checking its clock by syscall) until
//! a handler sees the signal, or a bound of CPU time:
//! - CPU_TIMER_PROCESS: timer_create(CLOCK_PROCESS_CPUTIME_ID) fires
//!   once 100 ms of CPU are used, not before
//! - CPU_TIMER_THREAD: likewise on CLOCK_THREAD_CPUTIME_ID
//! - CPU_TIMER_PERIODIC: a 20 ms periodic one fires again and again
//! - TIMER_CREATE_TAI: timer_create(CLOCK_TAI) works; with a TAI offset
//!   of 37 s set, an absolute timer 200 ms ahead on CLOCK_TAI fires
//!   then, not 37 s later (and CLOCK_TAI runs 37 s ahead of realtime:
//!   ADJ_TAI takes the offset from `constant`)
//! - CPU_TIMER_DEAD_THREAD: timer_settime of a timer on an exited
//!   sibling's thread CPU clock is ESRCH
//! - ITIMER_CPU: ITIMER_PROF and ITIMER_VIRTUAL send SIGPROF and
//!   SIGVTALRM after their CPU time; getitimer shows the time left
//! - RLIMIT_CPU_XCPU: past the soft limit SIGXCPU comes (and the soft
//!   limit moves up a second), at the hard limit SIGKILL
//! - CPU_NSLEEP: clock_nanosleep on the process CPU clock returns once
//!   a sibling thread has used the time; on a thread clock it is
//!   EOPNOTSUPP (Linux: thread CPU clocks have no nsleep)

use crate::tests::helpers::{print, print_num, println};
use crate::tests::mm::fork_mm::{join, spawn_thread};
use crate::tests::signal::signals::restorer_addr;
use core::sync::atomic::{AtomicU32, Ordering};
use hk_syscall::{
    ITimerSpec, ITimerVal, SA_RESTORER, SigEvent, Timespec, Timeval, sys_clock_gettime,
    sys_clock_nanosleep, sys_exit, sys_fork, sys_getitimer, sys_rt_sigaction, sys_setitimer,
    sys_timer_create, sys_timer_delete, sys_timer_settime, sys_wait4,
};

const MS: i64 = 1_000_000;
const SIGUSR2: u32 = 12;
const SIGXCPU: u32 = 24;
const SIGVTALRM: u32 = 26;
const SIGPROF: u32 = 27;
const SIGEV_SIGNAL: i32 = 0;
const CLOCK_TAI: i32 = 11;
const PROCESS_CLOCK: i32 = 2;
const THREAD_CLOCK: i32 = 3;
const EOPNOTSUPP: i64 = -95;

static HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_signal(_: i32) {
    // load+store: RMW atomics on aarch64 need libc's getauxval
    HITS.store(HITS.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
}

#[repr(C)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

fn catch(sig: u32) {
    let a = SigAction {
        handler: on_signal as *const () as u64,
        flags: SA_RESTORER,
        restorer: restorer_addr(),
        mask: 0,
    };
    sys_rt_sigaction(sig, &a as *const SigAction as u64, 0, 8);
}

fn report(name: &[u8], ok: bool, v: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(v);
        println(b"");
    }
}

fn clock_ms(clock: i32) -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(clock, &mut ts);
    ts.tv_sec * 1000 + ts.tv_nsec / MS
}

/// Burn the caller's CPU until `hits` signals came or `limit_ms` of
/// `clock` passed; the CPU ms used
fn burn_until(clock: i32, hits: u32, limit_ms: i64) -> i64 {
    let start = clock_ms(clock);
    loop {
        let used = clock_ms(clock) - start;
        if HITS.load(Ordering::Relaxed) >= hits || used >= limit_ms {
            return used;
        }
        for _ in 0..20_000 {
            core::hint::spin_loop();
        }
    }
}

fn spec(value_ms: i64, interval_ms: i64) -> ITimerSpec {
    ITimerSpec {
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: interval_ms * MS,
        },
        it_value: Timespec {
            tv_sec: 0,
            tv_nsec: value_ms * MS,
        },
    }
}

/// A SIGUSR2 timer on `clock`; its id
fn timer(clock: i32) -> i64 {
    // SAFETY: plain integers
    let mut sev: SigEvent = unsafe { core::mem::zeroed() };
    sev.sigev_signo = SIGUSR2 as i32;
    sev.sigev_notify = SIGEV_SIGNAL;
    let mut id = -1i32;
    let r = sys_timer_create(clock, &sev, &mut id);
    if r != 0 { r } else { id as i64 }
}

pub fn run_tests() {
    catch(SIGUSR2);
    one_shot(b"CPU_TIMER_PROCESS", PROCESS_CLOCK);
    one_shot(b"CPU_TIMER_THREAD", THREAD_CLOCK);
    periodic();
    tai();
    dead_thread();
    itimers();
    rlimit_cpu();
    nsleep();
}

fn one_shot(name: &[u8], clock: i32) {
    HITS.store(0, Ordering::Relaxed);
    let id = timer(clock);
    if id < 0 {
        return report(name, false, id);
    }
    let start = clock_ms(clock);
    sys_timer_settime(id as i32, 0, &spec(100, 0), core::ptr::null_mut());
    let used = burn_until(clock, 1, 2000);
    let at = clock_ms(clock) - start;
    sys_timer_delete(id as i32);
    // Fired, not before its 100 ms (and within the 2 s bound)
    report(
        name,
        HITS.load(Ordering::Relaxed) >= 1 && at >= 100 && used < 2000,
        at,
    );
}

fn periodic() {
    HITS.store(0, Ordering::Relaxed);
    let id = timer(PROCESS_CLOCK);
    if id < 0 {
        return report(b"CPU_TIMER_PERIODIC", false, id);
    }
    sys_timer_settime(id as i32, 0, &spec(20, 20), core::ptr::null_mut());
    burn_until(PROCESS_CLOCK, 4, 3000);
    sys_timer_delete(id as i32);
    let hits = HITS.load(Ordering::Relaxed) as i64;
    report(b"CPU_TIMER_PERIODIC", hits >= 4, hits);
}

fn tai() {
    use hk_syscall::{Timex, sys_adjtimex, sys_nanosleep};
    const ADJ_TAI: u32 = 0x80;
    const TIMER_ABSTIME: i32 = 1;
    let id = timer(CLOCK_TAI);
    if id < 0 {
        return report(b"TIMER_CREATE_TAI", false, id);
    }
    // SAFETY: plain integers
    let mut tx: Timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_TAI;
    tx.constant = 37;
    sys_adjtimex(&mut tx);
    HITS.store(0, Ordering::Relaxed);
    let mut now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_TAI, &mut now);
    // ADJ_TAI took the offset from `constant` (Linux)
    let mut real = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(0, &mut real);
    let ahead = now.tv_sec - real.tv_sec;
    let mut at = Timespec {
        tv_sec: now.tv_sec,
        tv_nsec: now.tv_nsec + 200 * MS,
    };
    if at.tv_nsec >= 1000 * MS {
        at.tv_sec += 1;
        at.tv_nsec -= 1000 * MS;
    }
    let s = ITimerSpec {
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: at,
    };
    sys_timer_settime(id as i32, TIMER_ABSTIME, &s, core::ptr::null_mut());
    // Up to 2 s for it
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 50 * MS,
    };
    for _ in 0..40 {
        if HITS.load(Ordering::Relaxed) > 0 {
            break;
        }
        sys_nanosleep(&ts, core::ptr::null_mut());
    }
    sys_timer_delete(id as i32);
    tx.modes = ADJ_TAI;
    tx.constant = 0;
    sys_adjtimex(&mut tx);
    let hits = HITS.load(Ordering::Relaxed) as i64;
    report(
        b"TIMER_CREATE_TAI",
        hits >= 1 && (36..=38).contains(&ahead),
        hits * 1000 + ahead,
    );
}

fn itimer_hits(which: i32, sig: u32, clock: i32) -> (u32, i64) {
    HITS.store(0, Ordering::Relaxed);
    catch(sig);
    let v = ITimerVal {
        it_interval: Timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: Timeval {
            tv_sec: 0,
            tv_usec: 80_000,
        },
    };
    sys_setitimer(which, &v, core::ptr::null_mut());
    // SAFETY: plain integers
    let mut cur: ITimerVal = unsafe { core::mem::zeroed() };
    sys_getitimer(which, &mut cur);
    let left = cur.it_value.tv_usec;
    burn_until(clock, 1, 2000);
    (HITS.load(Ordering::Relaxed), left)
}

fn itimers() {
    const ITIMER_VIRTUAL: i32 = 1;
    const ITIMER_PROF: i32 = 2;
    let (prof, pleft) = itimer_hits(ITIMER_PROF, SIGPROF, PROCESS_CLOCK);
    let (virt, vleft) = itimer_hits(ITIMER_VIRTUAL, SIGVTALRM, PROCESS_CLOCK);
    // Linux adds a tick to a CPU itimer's value (set_cpu_itimer)
    let left_ok = |l: i64| l > 0 && l <= 100_000;
    report(
        b"ITIMER_CPU",
        prof >= 1 && virt >= 1 && left_ok(pleft) && left_ok(vleft),
        (prof * 10 + virt) as i64,
    );
}

/// Child: soft 1 s, hard 2 s of CPU; it reports its SIGXCPU and new soft
/// limit on `fd`, then spins into the hard limit
fn xcpu_child(fd: i32) -> ! {
    use hk_syscall::{RLIMIT_CPU, RLimit, sys_getrlimit, sys_setrlimit, sys_write};
    HITS.store(0, Ordering::Relaxed);
    catch(SIGXCPU);
    let lim = RLimit {
        rlim_cur: 1,
        rlim_max: 2,
    };
    if sys_setrlimit(RLIMIT_CPU, &lim) != 0 {
        sys_exit(1);
    }
    burn_until(PROCESS_CLOCK, 1, 1800);
    let mut now = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    sys_getrlimit(RLIMIT_CPU, &mut now);
    let msg = [HITS.load(Ordering::Relaxed) as u8, now.rlim_cur as u8];
    sys_write(fd as u64, msg.as_ptr(), 2);
    // Into the hard limit: SIGKILL
    burn_until(PROCESS_CLOCK, u32::MAX, 5000);
    sys_exit(2)
}

fn rlimit_cpu() {
    use hk_syscall::{sys_close, sys_pipe2, sys_read};
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        xcpu_child(p[1]);
    }
    sys_close(p[1] as u64);
    let mut msg = [0u8; 2];
    let n = sys_read(p[0] as u64, msg.as_mut_ptr(), 2);
    sys_close(p[0] as u64);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    // SIGXCPU seen, soft limit now 2, then killed by SIGKILL
    let ok = n == 2 && msg[0] >= 1 && msg[1] == 2 && st & 0x7f == 9;
    report(b"RLIMIT_CPU_XCPU", ok, st as i64 + 1000 * msg[0] as i64);
}

static STOP: AtomicU32 = AtomicU32::new(0);

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;

extern "C" fn spinner(_: u64) -> ! {
    let mut n: u64 = 0;
    while STOP.load(Ordering::Relaxed) == 0 && n < (1u64 << 40) {
        n = n.wrapping_add(1);
        core::hint::spin_loop();
    }
    sys_exit(0)
}

fn nsleep() {
    let started = unsafe {
        let top = (&raw mut STACK as *mut u8).add(16384) as u64;
        let ctid = &raw mut CTID;
        core::ptr::write_volatile(ctid, 1);
        spawn_thread(top, spinner, 0, ctid) > 0
    };
    let before = clock_ms(PROCESS_CLOCK);
    let req = Timespec {
        tv_sec: 0,
        tv_nsec: 100 * MS,
    };
    let r = sys_clock_nanosleep(PROCESS_CLOCK, 0, &req, core::ptr::null_mut());
    let used = clock_ms(PROCESS_CLOCK) - before;
    STOP.store(1, Ordering::Relaxed);
    let joined = started && join(&raw mut CTID);
    let thread = sys_clock_nanosleep(THREAD_CLOCK, 0, &req, core::ptr::null_mut());
    let v = if !joined {
        -1
    } else if r != 0 {
        r
    } else if thread != EOPNOTSUPP {
        1_000_000 + thread
    } else {
        used
    };
    report(
        b"CPU_NSLEEP",
        joined && r == 0 && used >= 100 && thread == EOPNOTSUPP,
        v,
    );
}

fn dead_thread() {
    let tid = unsafe {
        let top = (&raw mut STACK as *mut u8).add(16384) as u64;
        let ctid = &raw mut CTID;
        core::ptr::write_volatile(ctid, 1);
        spawn_thread(top, spinner, 0, ctid)
    };
    if tid <= 0 {
        return report(b"CPU_TIMER_DEAD_THREAD", false, tid);
    }
    // MAKE_THREAD_CPUCLOCK(tid, CPUCLOCK_SCHED), while it runs
    let clock = ((!(tid as i32)) << 3) | 4 | 2;
    let id = timer(clock);
    STOP.store(1, Ordering::Relaxed);
    let joined = join(&raw mut CTID);
    STOP.store(0, Ordering::Relaxed);
    if id < 0 || !joined {
        return report(b"CPU_TIMER_DEAD_THREAD", false, id);
    }
    // Its tid word clears before it is released (Linux too): let it go
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 50 * MS,
    };
    hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
    let r = sys_timer_settime(id as i32, 0, &spec(10, 0), core::ptr::null_mut());
    sys_timer_delete(id as i32);
    report(b"CPU_TIMER_DEAD_THREAD", r == -3, r);
}
