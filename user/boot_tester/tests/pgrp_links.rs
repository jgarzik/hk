//! Process groups and sessions are per process, not per thread (Linux
//! pid->tasks[PIDTYPE_PGID/SID] list group leaders)
//!
//! In a forked, two-threaded child:
//! - setpgid(0, 0) from the non-leader thread moves the whole process:
//!   getpgid agrees from both threads and for the thread's tid;
//! - kill(-pgrp, sig) delivers once per process (a counting handler),
//!   not once per thread; kill(-pgrp, 0) probes the group;
//! - setsid fails with EPERM while a process group with the caller's
//!   pid as id exists, even with the caller in another group, and
//!   succeeds once it is gone, for every thread;
//! - getpriority/setpriority(PRIO_PGRP) cover every thread of the group.

use super::fork_mm::{join, spawn_thread};
use super::helpers::{print, print_num, println};
use super::signals::restorer_addr;
use core::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use hk_syscall::{
    SA_RESTORER, sys_close, sys_exit, sys_fork, sys_getpgid, sys_getpid, sys_getpriority,
    sys_getsid, sys_gettid, sys_kill, sys_pipe2, sys_read, sys_rt_sigaction, sys_rt_sigprocmask,
    sys_sched_yield, sys_setpgid, sys_setpriority, sys_setsid, sys_wait4, sys_write,
};

const SIGUSR1: u32 = 10;
const SIG_UNBLOCK: i32 = 1;
const PRIO_PROCESS: i32 = 0;
const PRIO_PGRP: i32 = 1;
const EPERM: i64 = -1;
const ESRCH: i64 = -3;
/// A pid above every pid_max: no such group
const NO_PGRP: i64 = 0x3ff_fff0;

/// The checks, one bit each in the child's exit status
const CHECKS: [&[u8]; 6] = [
    b"PGRP_LINKS_SETPGID_THREAD",
    b"PGRP_LINKS_KILL_ONCE",
    b"PGRP_LINKS_KILL_PROBE",
    b"PGRP_LINKS_SETSID_EPERM",
    b"PGRP_LINKS_SETSID_THREADS",
    b"PGRP_LINKS_PRIO_PGRP",
];

#[repr(C)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;

/// SIGUSR1 deliveries in the child
static HITS: AtomicU32 = AtomicU32::new(0);
/// The thread's tid, then its getpgid(0) after its setpgid
static T_TID: AtomicI64 = AtomicI64::new(0);
static T_PGID: AtomicI64 = AtomicI64::new(0);
/// The thread's setpgid is done
static READY: AtomicU32 = AtomicU32::new(0);
/// The read end the thread sleeps on until the leader writes a byte
static WAKE_FD: AtomicI64 = AtomicI64::new(-1);

pub fn run_tests() {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(child() as u64);
    }
    let mut st = 0i32;
    let r = sys_wait4(pid, &mut st, 0, 0);
    let fails = if r == pid && st & 0x7f == 0 {
        (st >> 8) & 0xff
    } else {
        -1
    };
    for (i, name) in CHECKS.iter().enumerate() {
        print(name);
        if fails & (1 << i) == 0 {
            println(b":OK");
        } else {
            print(b":FAIL status ");
            print_num(st as i64);
            println(b"");
        }
    }
}

extern "C" fn on_usr1(_sig: i32) {
    // No read-modify-write: arm64 outline atomics need getauxval
    HITS.store(HITS.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
}

/// The second thread: setpgid(0, 0) for the whole process, then sleep
/// (not spin: priorities change meanwhile) until the leader's byte
extern "C" fn thread(_: u64) -> ! {
    T_TID.store(sys_gettid(), Ordering::SeqCst);
    sys_setpgid(0, 0);
    T_PGID.store(sys_getpgid(0), Ordering::SeqCst);
    READY.store(1, Ordering::SeqCst);
    let fd = WAKE_FD.load(Ordering::SeqCst) as u64;
    let mut b = 0u8;
    // EINTR if the group's signal lands here: sleep again
    while sys_read(fd, &mut b, 1) != 1 {}
    sys_exit(0)
}

fn wait_ready() -> bool {
    for _ in 0..2_000_000u32 {
        if READY.load(Ordering::SeqCst) != 0 {
            return true;
        }
        sys_sched_yield();
    }
    false
}

/// SIGUSR1 counted by `on_usr1`, unblocked (an earlier test may leave
/// it blocked; the thread inherits the mask)
fn catch_usr1() -> bool {
    let act = SigAction {
        handler: on_usr1 as *const () as u64,
        flags: SA_RESTORER,
        restorer: restorer_addr(),
        mask: 0,
    };
    let usr1 = 1u64 << (SIGUSR1 - 1);
    sys_rt_sigaction(SIGUSR1, &act as *const SigAction as u64, 0, 8) == 0
        && sys_rt_sigprocmask(SIG_UNBLOCK, &usr1 as *const u64 as u64, 0, 8) == 0
}

/// The forked child: the failed checks as a bit mask
fn child() -> u32 {
    let mut wake = [0i32; 2];
    if !catch_usr1() || sys_pipe2(wake.as_mut_ptr(), 0) != 0 {
        return 0xff;
    }
    WAKE_FD.store(wake[0] as i64, Ordering::SeqCst);
    let me = sys_getpid();
    let top = unsafe { (&raw mut STACK as *mut u8).add(16384) as u64 };
    unsafe { core::ptr::write_volatile(&raw mut CTID, 1) };
    let tid = unsafe { spawn_thread(top, thread, 0, &raw mut CTID) };
    if tid <= 0 || !wait_ready() {
        return 0xff;
    }
    let mut fails = 0u32;
    let mut check = |bit: u32, ok: bool| {
        if !ok {
            fails |= 1 << bit;
        }
    };

    // setpgid from the thread moved the process
    check(
        0,
        T_TID.load(Ordering::SeqCst) == tid
            && T_PGID.load(Ordering::SeqCst) == me
            && sys_getpgid(0) == me
            && sys_getpgid(tid as u64) == me,
    );
    check(1, kill_once(me));
    // signal 0 probes the group; an empty one is ESRCH
    check(2, sys_kill(-me, 0) == 0 && sys_kill(-NO_PGRP, 0) == ESRCH);
    check(3, setsid_eperm(me));
    check(
        4,
        sys_getsid(0) == me && sys_getsid(tid as u64) == me && sys_getpgid(tid as u64) == me,
    );
    check(5, prio_pgrp(me, tid));

    let b = 1u8;
    sys_write(wake[1] as u64, &b, 1);
    if !join(&raw mut CTID) {
        fails |= 0x80;
    }
    fails
}

/// kill(-pgrp): one delivery for the two-threaded process
fn kill_once(me: i64) -> bool {
    let r = sys_kill(-me, SIGUSR1);
    for _ in 0..100_000u32 {
        if HITS.load(Ordering::SeqCst) != 0 {
            break;
        }
        sys_sched_yield();
    }
    // A second delivery (to the other thread) would come meanwhile
    for _ in 0..200 {
        sys_sched_yield();
    }
    r == 0 && HITS.load(Ordering::SeqCst) == 1
}

/// Group `me` keeps a member (Y) after the caller moves to another
/// group of its session (Z's): setsid is EPERM; once both are gone it
/// works, and only once
fn setsid_eperm(me: i64) -> bool {
    let mut hold = [0i32; 2];
    let mut ready = [0i32; 2];
    if sys_pipe2(hold.as_mut_ptr(), 0) != 0 || sys_pipe2(ready.as_mut_ptr(), 0) != 0 {
        return false;
    }
    // Y stays in group `me` until `hold` closes
    let y = sys_fork();
    if y == 0 {
        let mut b = 0u8;
        sys_close(hold[1] as u64);
        sys_read(hold[0] as u64, &mut b, 1);
        sys_exit(0);
    }
    // Z leads a group of its own, then waits likewise
    let z = sys_fork();
    if z == 0 {
        let mut b = 0u8;
        sys_close(hold[1] as u64);
        let r = sys_setpgid(0, 0) as u8;
        sys_write(ready[1] as u64, &r, 1);
        sys_read(hold[0] as u64, &mut b, 1);
        sys_exit(0);
    }
    let mut b = 0xffu8;
    sys_read(ready[0] as u64, &mut b, 1);
    let moved = b == 0 && sys_setpgid(0, z as u64) == 0 && sys_getpgid(0) == z;
    let eperm = sys_setsid();
    for fd in [hold[0], hold[1], ready[0], ready[1]] {
        sys_close(fd as u64);
    }
    let mut st = 0;
    sys_wait4(y, &mut st, 0, 0);
    sys_wait4(z, &mut st, 0, 0);
    moved && eperm == EPERM && sys_setsid() == me && sys_setsid() == EPERM
}

/// setpriority(PRIO_PGRP) sets every thread, getpriority reports the
/// group's highest (20 - nice). The thread sleeps throughout; the
/// leader only lowers itself below it and comes back, so both end at
/// nice 3.
fn prio_pgrp(me: i64, tid: i64) -> bool {
    sys_setpriority(PRIO_PGRP, 0, 3) == 0
        && sys_getpriority(PRIO_PGRP, 0) == 17
        && sys_getpriority(PRIO_PGRP, me as u64) == 17
        && sys_getpriority(PRIO_PROCESS, tid as u64) == 17
        && sys_getpriority(PRIO_PGRP, NO_PGRP as u64) == ESRCH
        && sys_setpriority(PRIO_PROCESS, 0, 5) == 0
        && sys_getpriority(PRIO_PGRP, 0) == 17
        && sys_setpriority(PRIO_PROCESS, 0, 3) == 0
}
