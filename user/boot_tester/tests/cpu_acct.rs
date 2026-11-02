//! CPU time accounting (Linux kernel/sched/cputime.c: the tick and
//! context switches charge the running task; a reader adds a running
//! task's current slice, task_sched_runtime)
//!
//! Tests:
//! - CPU_ACCT_SLEEP: 300 ms asleep in nanosleep adds well under 100 ms
//!   of system time (time off the CPU is nobody's)
//! - CPU_ACCT_SPINNER: a sibling thread spinning in user mode, making no
//!   syscall, shows its CPU time in its thread CPU clock while it still
//!   spins

use super::fork_mm::{join, spawn_thread};
use super::helpers::{print, print_num, println};
use core::sync::atomic::{AtomicU32, Ordering};
use hk_syscall::{Timespec, Timeval, sys_clock_gettime, sys_getrusage, sys_nanosleep};

/// struct rusage: the two times, then 14 longs
#[repr(C)]
struct Rusage {
    ru_utime: Timeval,
    ru_stime: Timeval,
    rest: [i64; 14],
}

const RUSAGE_SELF: i32 = 0;
const MS: i64 = 1_000_000;

pub fn run_tests() {
    sleep();
    spinner();
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

fn nap(ms: i64) {
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * MS,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// System time so far, in ms
fn stime_ms() -> i64 {
    // SAFETY: plain integers
    let mut ru: Rusage = unsafe { core::mem::zeroed() };
    sys_getrusage(RUSAGE_SELF, &mut ru as *mut Rusage as *mut u8);
    ru.ru_stime.tv_sec * 1000 + ru.ru_stime.tv_usec / 1000
}

fn sleep() {
    let before = stime_ms();
    nap(300);
    let grew = stime_ms() - before;
    report(b"CPU_ACCT_SLEEP", grew < 100, grew);
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
        return report(b"CPU_ACCT_SPINNER", false, -1);
    }
    nap(300);
    // The spinner has had its CPU for most of the 300 ms
    let seen = thread_cpu_ms(tid);
    STOP.store(1, Ordering::Relaxed);
    let joined = join(&raw mut CTID);
    report(b"CPU_ACCT_SPINNER", joined && seen >= 100, seen);
}
