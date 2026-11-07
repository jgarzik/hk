//! Thread pidfds (PIDFD_THREAD, Linux 6.9+: include/uapi/linux/pidfd.h,
//! fs/pidfs.c pidfd_poll, kernel/signal.c pidfd_send_signal)
//!
//! In a forked, two-threaded child whose second thread blocks SIGUSR1
//! and whose main thread catches it:
//! - pidfd_open(tid, PIDFD_THREAD) opens the non-leader thread;
//! - the thread pidfd polls not readable while the thread runs, readable
//!   once it exited;
//! - pidfd_send_signal on it signals that thread alone (pending there,
//!   not run by the main thread), PIDFD_SIGNAL_THREAD_GROUP its process
//!   (the main thread's handler runs);
//! - more than one scope flag, or an unknown flag, is EINVAL;
//! - PIDFD_SIGNAL_PROCESS_GROUP signals the process group with the
//!   pidfd's pid as id: ESRCH for the thread, the child's own group for
//!   a pidfd of the child (its group leader);
//! - waitid(P_PIDFD) of the thread pidfd is ECHILD (no such child).
//!
//! Before Linux 6.9 PIDFD_THREAD is EINVAL: the checks are skipped.

use crate::harness::fail_num;
use crate::helpers::{linux_at_least, print, println, skip};
use crate::mm::fork_mm::{join, spawn_thread};
use crate::signal::signals::restorer_addr;
use core::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use hk_syscall::{
    O_EXCL, P_PIDFD, POLLIN, PollFd, SA_RESTORER, WEXITED, sys_close, sys_exit, sys_fork,
    sys_getpid, sys_gettid, sys_pidfd_open, sys_pidfd_send_signal, sys_pipe2, sys_poll, sys_read,
    sys_rt_sigaction, sys_rt_sigpending, sys_rt_sigprocmask, sys_sched_yield, sys_setpgid,
    sys_wait4, sys_waitid, sys_write,
};

const SIGUSR1: u32 = 10;
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
const PIDFD_THREAD: u32 = O_EXCL;
const PIDFD_SIGNAL_THREAD: u32 = 1;
const PIDFD_SIGNAL_THREAD_GROUP: u32 = 2;
const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 4;
const WNOHANG: i32 = 1;
const ESRCH: i64 = -3;
const ECHILD: i64 = -10;
const EINVAL: i64 = -22;
const USR1: u64 = 1 << (SIGUSR1 - 1);

/// The checks, one bit each in the child's exit status
const CHECKS: [&[u8]; 6] = [
    b"PIDFD_THREAD_OPEN",
    b"PIDFD_THREAD_POLL",
    b"PIDFD_THREAD_SIGNAL",
    b"PIDFD_THREAD_SIGNAL_FLAGS",
    b"PIDFD_THREAD_SIGNAL_PGRP",
    b"PIDFD_THREAD_WAITID",
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

/// The tid that ran the last SIGUSR1 handler (0: none yet)
static RAN_ON: AtomicI64 = AtomicI64::new(0);
/// The thread has blocked SIGUSR1
static READY: AtomicU32 = AtomicU32::new(0);
/// The thread's pending set when it was woken
static T_PENDING: AtomicI64 = AtomicI64::new(0);

pub fn run_tests() {
    if !linux_at_least(6, 9) {
        for name in CHECKS {
            skip(name, b"PIDFD_THREAD needs Linux 6.9");
        }
        return;
    }
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
            fail_num(b":FAIL status ", st as i64);
        }
    }
}

extern "C" fn on_usr1(_sig: i32) {
    RAN_ON.store(sys_gettid(), Ordering::SeqCst);
}

/// The second thread: SIGUSR1 blocked, sleep until the main thread's
/// byte, then record what is pending and exit
extern "C" fn thread(fd: u64) -> ! {
    sys_rt_sigprocmask(SIG_BLOCK, &USR1 as *const u64 as u64, 0, 8);
    READY.store(1, Ordering::SeqCst);
    let mut b = 0u8;
    while sys_read(fd, &mut b, 1) != 1 {}
    let mut set = 0u64;
    sys_rt_sigpending(&mut set as *mut u64 as u64, 8);
    T_PENDING.store(set as i64, Ordering::SeqCst);
    sys_exit(0)
}

/// The events of `fd` within `ms` (0 on timeout)
fn poll_in(fd: i64, ms: i32) -> i16 {
    let mut fds = [PollFd {
        fd: fd as i32,
        events: POLLIN,
        revents: 0,
    }];
    if sys_poll(fds.as_mut_ptr(), 1, ms) == 1 {
        fds[0].revents
    } else {
        0
    }
}

/// SIGUSR1 caught by `on_usr1` and unblocked in the calling thread
fn catch_usr1() -> bool {
    let act = SigAction {
        handler: on_usr1 as *const () as u64,
        flags: SA_RESTORER,
        restorer: restorer_addr(),
        mask: 0,
    };
    sys_rt_sigaction(SIGUSR1, &act as *const SigAction as u64, 0, 8) == 0
        && sys_rt_sigprocmask(SIG_UNBLOCK, &USR1 as *const u64 as u64, 0, 8) == 0
}

/// pidfd_send_signal(fd, SIGUSR1, flags)
fn send(fd: i64, flags: u32) -> i64 {
    sys_pidfd_send_signal(fd as i32, SIGUSR1 as i32, core::ptr::null(), flags)
}

/// The forked child: the failed checks as a bit mask
fn child() -> u32 {
    let mut wake = [0i32; 2];
    if !catch_usr1() || sys_pipe2(wake.as_mut_ptr(), 0) != 0 || sys_setpgid(0, 0) != 0 {
        return 0xff;
    }
    let me = sys_gettid();
    let top = unsafe { (&raw mut STACK as *mut u8).add(16384) as u64 };
    // Nonzero until the thread's exit clears it (no CLONE_CHILD_SETTID)
    unsafe { core::ptr::write_volatile(&raw mut CTID, 1) };
    let t = unsafe { spawn_thread(top, thread, wake[0] as u64, &raw mut CTID) };
    if t <= 0 {
        return 0xff;
    }
    while READY.load(Ordering::SeqCst) == 0 {
        sys_sched_yield();
    }
    let mut fails = 0u32;
    let fd = sys_pidfd_open(t as i32, PIDFD_THREAD);
    if fd < 0 {
        fails |= 1 << 0;
    }
    if poll_in(fd, 0) != 0 {
        fails |= 1 << 1;
    }
    // To the thread alone: it blocks SIGUSR1, so nothing runs here
    let thread_ok = send(fd, 0) == 0 && RAN_ON.load(Ordering::SeqCst) == 0;
    let explicit_ok = send(fd, PIDFD_SIGNAL_THREAD) == 0 && RAN_ON.load(Ordering::SeqCst) == 0;
    // To its process: the main thread alone takes it, on this return
    let group_ok = send(fd, PIDFD_SIGNAL_THREAD_GROUP) == 0 && RAN_ON.load(Ordering::SeqCst) == me;
    let bad_ok = send(fd, PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_THREAD_GROUP) == EINVAL
        && send(fd, 8) == EINVAL;
    if !bad_ok {
        fails |= 1 << 3;
    }
    // No group has the thread's id; the process's own one is ours
    RAN_ON.store(0, Ordering::SeqCst);
    let pfd = sys_pidfd_open(sys_getpid() as i32, 0);
    let pgrp_ok = send(fd, PIDFD_SIGNAL_PROCESS_GROUP) == ESRCH
        && send(pfd, PIDFD_SIGNAL_PROCESS_GROUP) == 0
        && RAN_ON.load(Ordering::SeqCst) == me;
    if !pgrp_ok {
        fails |= 1 << 4;
    }
    if sys_waitid(
        P_PIDFD,
        fd as u64,
        core::ptr::null_mut(),
        WEXITED | WNOHANG,
        0,
    ) != ECHILD
    {
        fails |= 1 << 5;
    }
    sys_write(wake[1] as u64, b"x".as_ptr(), 1);
    let exited = poll_in(fd, 2000) & POLLIN != 0;
    join(&raw mut CTID);
    if !exited || send(fd, 0) != ESRCH {
        fails |= 1 << 1;
    }
    let pending = T_PENDING.load(Ordering::SeqCst) as u64 & USR1 != 0;
    if !(thread_ok && explicit_ok && group_ok && pending) {
        fails |= 1 << 2;
    }
    sys_close(fd as u64);
    sys_close(pfd as u64);
    fails
}
