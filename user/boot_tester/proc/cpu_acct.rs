//! CPU time accounting (Linux kernel/sched/cputime.c: the tick and
//! context switches charge the running task; a reader adds a running
//! task's current slice, task_sched_runtime)
//!
//! Tests:
//! - CPU_ACCT_SLEEP: 300 ms asleep in nanosleep adds well under 100 ms
//!   of system time (time off the CPU is nobody's)
//! - CPU_ACCT_USER: time spinning in user mode is user time (arm64
//!   counted it as system time: its syscall return never switched)
//! - CPU_ACCT_SPINNER: a sibling thread spinning in user mode, making no
//!   syscall, shows its CPU time in its thread CPU clock while it still
//!   spins
//! - CPU_ACCT_EXITED: a thread's CPU time stays the process's after it
//!   exits (Linux signal->utime/stime)
//! - CPU_ACCT_SCHED_FINE: the thread CPU clock (CPUCLOCK_SCHED) is the
//!   scheduler's runtime, not tick samples: spinning, it advances in
//!   steps well under a tick
//! - CPU_ACCT_CHILDREN: a reaped child's CPU time shows in wait4's
//!   rusage, getrusage(RUSAGE_CHILDREN), times()'s tms_cutime/cstime and
//!   /proc/self/stat's cutime/cstime
//! - CPU_ACCT_KTHREAD_CLOCK: a kernel thread's process CPU clock reads
//!   (Linux posix_cpu_clock_get: a kthread is a process too), it was
//!   EINVAL

use crate::harness::verdict;
use crate::mm::fork_mm::{join, spawn_thread};
use core::sync::atomic::{AtomicU32, Ordering};
use hk_syscall::{Timespec, Timeval, sys_clock_gettime, sys_getrusage, sys_nanosleep};

/// struct rusage: the two times, then 14 longs
#[repr(C)]
#[derive(Default)]
struct Rusage {
    ru_utime: Timeval,
    ru_stime: Timeval,
    rest: [i64; 14],
}

const RUSAGE_SELF: i32 = 0;
const MS: i64 = 1_000_000;

pub fn run_tests() {
    sleep();
    sched_fine();
    user();
    spinner();
    exited();
    children();
    kthread_clock();
}

/// Stat field 9 (flags) of /proc/<pid>/stat, or None
fn stat_flags(pid: i64) -> Option<u64> {
    let mut path = [0u8; 24];
    path[..6].copy_from_slice(b"/proc/");
    let mut d = [0u8; 10];
    let (mut n, mut p) = (0, pid);
    while p > 0 || n == 0 {
        d[n] = b'0' + (p % 10) as u8;
        p /= 10;
        n += 1;
    }
    for i in 0..n {
        path[6 + i] = d[n - 1 - i];
    }
    path[6 + n..6 + n + 6].copy_from_slice(b"/stat\0");
    let mut buf = [0u8; 1024];
    let r = crate::helpers::read_file(&path[..6 + n + 6], &mut buf);
    if r <= 0 {
        return None;
    }
    let b = &buf[..r as usize];
    let close = b.iter().rposition(|&c| c == b')')?;
    let tok = b[close + 1..]
        .split(|&c| c == b' ')
        .filter(|t| !t.is_empty())
        .nth(6)?;
    Some(tok.iter().fold(0u64, |v, &c| v * 10 + u64::from(c - b'0')))
}

fn kthread_clock() {
    const PF_KTHREAD: u64 = 0x0020_0000;
    let Some(pid) = (2..4096).find(|&p| stat_flags(p).is_some_and(|f| f & PF_KTHREAD != 0)) else {
        verdict(b"CPU_ACCT_KTHREAD_CLOCK", false, -1);
        return;
    };
    // MAKE_PROCESS_CPUCLOCK(pid, CPUCLOCK_SCHED)
    let clk = ((!pid) << 3) | 2;
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r = sys_clock_gettime(clk as i32, &mut ts);
    verdict(b"CPU_ACCT_KTHREAD_CLOCK", r == 0, r);
}

/// The calling thread's (`process`: process's) CPU time in ms
fn own_cpu_ms(process: bool) -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID
    sys_clock_gettime(if process { 2 } else { 3 }, &mut ts);
    ts.tv_sec * 1000 + ts.tv_nsec / MS
}

/// Use `ms` of the caller's own CPU (checking with syscalls)
fn burn(ms: i64, process: bool) {
    let start = own_cpu_ms(process);
    while own_cpu_ms(process) - start < ms {
        for _ in 0..10_000 {
            core::hint::spin_loop();
        }
    }
}

extern "C" fn burn_and_exit(_: u64) -> ! {
    burn(200, false);
    hk_syscall::sys_exit(0)
}

fn exited() {
    let before = own_cpu_ms(true);
    let ok = unsafe {
        let top = (&raw mut STACK as *mut u8).add(16384) as u64;
        let ctid = &raw mut CTID;
        core::ptr::write_volatile(ctid, 1);
        spawn_thread(top, burn_and_exit, 0, ctid) > 0 && join(ctid)
    };
    let grew = own_cpu_ms(true) - before;
    verdict(b"CPU_ACCT_EXITED", ok && grew >= 180, grew);
}

fn ms_of(t: &Timeval) -> i64 {
    t.tv_sec * 1000 + t.tv_usec / 1000
}

/// cutime + cstime from /proc/self/stat (fields 16 and 17), in ticks
fn stat_children_ticks() -> i64 {
    let mut buf = [0u8; 1024];
    let n = crate::helpers::read_file(b"/proc/self/stat\0", &mut buf);
    if n <= 0 {
        return -1;
    }
    let b = &buf[..n as usize];
    // Fields after the ")" of comm: state is field 3
    let Some(close) = b.iter().rposition(|&c| c == b')') else {
        return -1;
    };
    let mut field = 2;
    let mut sum = 0i64;
    for tok in b[close + 1..]
        .split(|&c| c == b' ')
        .filter(|t| !t.is_empty())
    {
        field += 1;
        if field == 16 || field == 17 {
            let mut v = 0i64;
            for &c in tok {
                v = v * 10 + (c - b'0') as i64;
            }
            sum += v;
        }
    }
    sum
}

fn children() {
    use hk_syscall::{sys_exit, sys_fork, sys_times, sys_wait4};
    let mut base = Rusage::default();
    sys_getrusage(-1, &mut base as *mut Rusage as *mut u8);
    let base_ms = ms_of(&base.ru_utime) + ms_of(&base.ru_stime);
    let mut tb = [0i64; 4];
    sys_times(tb.as_mut_ptr() as *mut u8);
    let base_stat = stat_children_ticks();
    let pid = sys_fork();
    if pid == 0 {
        burn(200, true);
        sys_exit(0);
    }
    let mut st = 0i32;
    let mut ru = Rusage::default();
    sys_wait4(pid, &mut st, 0, &mut ru as *mut Rusage as u64);
    let waited = ms_of(&ru.ru_utime) + ms_of(&ru.ru_stime);
    let mut ch = Rusage::default();
    sys_getrusage(-1, &mut ch as *mut Rusage as *mut u8);
    let children = ms_of(&ch.ru_utime) + ms_of(&ch.ru_stime) - base_ms;
    let mut t = [0i64; 4];
    sys_times(t.as_mut_ptr() as *mut u8);
    let ticks = t[2] + t[3] - tb[2] - tb[3];
    let stat = stat_children_ticks() - base_stat;
    let step = if waited < 180 {
        1
    } else if children < 180 {
        2
    } else if ticks < 18 {
        3
    } else if stat < 18 {
        4
    } else {
        0
    };
    verdict(b"CPU_ACCT_CHILDREN", step == 0, step * 100_000 + waited);
}

/// The calling thread's CPU clock in ns
fn own_cpu_ns() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(3, &mut ts);
    ts.tv_sec * 1_000_000_000 + ts.tv_nsec
}

fn sched_fine() {
    // The smallest of a few steps (a step may span a preemption)
    let mut best = i64::MAX;
    for _ in 0..8 {
        let a = own_cpu_ns();
        let mut b = own_cpu_ns();
        while b == a {
            b = own_cpu_ns();
        }
        best = best.min(b - a);
    }
    verdict(b"CPU_ACCT_SCHED_FINE", best < 2 * MS, best);
}

fn nap(ms: i64) {
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * MS,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// System time so far, in ms
fn stime_ms() -> i64 {
    let mut ru = Rusage::default();
    sys_getrusage(RUSAGE_SELF, &mut ru as *mut Rusage as *mut u8);
    ru.ru_stime.tv_sec * 1000 + ru.ru_stime.tv_usec / 1000
}

fn sleep() {
    let before = stime_ms();
    nap(300);
    let grew = stime_ms() - before;
    verdict(b"CPU_ACCT_SLEEP", grew < 100, grew);
}

/// User time so far, in ms
fn utime_ms() -> i64 {
    let mut ru = Rusage::default();
    sys_getrusage(RUSAGE_SELF, &mut ru as *mut Rusage as *mut u8);
    ru.ru_utime.tv_sec * 1000 + ru.ru_utime.tv_usec / 1000
}

fn user() {
    let (u0, s0) = (utime_ms(), stime_ms());
    // About 200 ms of CPU, a syscall only every few million spins
    loop {
        for _ in 0..2_000_000 {
            core::hint::spin_loop();
        }
        if utime_ms() + stime_ms() - u0 - s0 >= 200 {
            break;
        }
    }
    let du = utime_ms() - u0;
    verdict(b"CPU_ACCT_USER", du >= 100, du);
}

static STOP: AtomicU32 = AtomicU32::new(0);

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;

/// Spin without syscalls until told to stop (bounded, in case)
extern "C" fn spin(_: u64) -> ! {
    let mut n: u64 = 0;
    while STOP.load(Ordering::Relaxed) == 0 && n < (1u64 << 40) {
        n = n.wrapping_add(1);
        core::hint::spin_loop();
    }
    hk_syscall::sys_exit(0)
}

/// Thread `tid`'s CPU time in ms (MAKE_THREAD_CPUCLOCK(tid, CPUCLOCK_SCHED))
fn thread_cpu_ms(tid: i64) -> i64 {
    let clock = ((!(tid as i32)) << 3) | 4 | 2;
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if sys_clock_gettime(clock, &mut ts) != 0 {
        return -1;
    }
    ts.tv_sec * 1000 + ts.tv_nsec / MS
}

fn spinner() {
    let tid = unsafe {
        let top = (&raw mut STACK as *mut u8).add(16384) as u64;
        let ctid = &raw mut CTID;
        core::ptr::write_volatile(ctid, 1);
        spawn_thread(top, spin, 0, ctid)
    };
    if tid <= 0 {
        return verdict(b"CPU_ACCT_SPINNER", false, -1);
    }
    nap(300);
    // The spinner has had its CPU for most of the 300 ms
    let seen = thread_cpu_ms(tid);
    STOP.store(1, Ordering::Relaxed);
    let joined = join(&raw mut CTID);
    verdict(b"CPU_ACCT_SPINNER", joined && seen >= 100, seen);
}
