//! Temporary signal masks of rt_sigsuspend, ppoll and epoll_pwait
//!
//! Tests:
//! - EPOLL_PWAIT_SIGMASK: a pending signal blocked by the epoll_pwait
//!   mask stays pending, one it unblocks runs its handler (under the
//!   temporary mask) and the wait fails with EINTR; afterwards the old
//!   mask is back
//! - EPOLL_PWAIT_SIGMASK_RESTORE: with no signal the old mask is back
//!   after the wait; a bad sigsetsize is EINVAL
//! - PPOLL_SIGMASK_RESTORE: the same for ppoll's mask
//! - SIGSUSPEND_RESTORE: after rt_sigsuspend's handler the old mask is
//!   back, and the handler ran under the suspend mask

use super::helpers::{print, print_num, println};
use super::signals::restorer_addr;
use hk_syscall::{
    EpollEvent, PollFd, SA_RESTORER, SA_SIGINFO, SIG_BLOCK, SIG_DFL, SIG_SETMASK, SIGUSR1,
    SIGUSR2, Timespec, sys_close, sys_epoll_create1, sys_epoll_pwait, sys_getpid, sys_gettid,
    sys_pipe, sys_ppoll, sys_rt_sigaction, sys_rt_sigpending, sys_rt_sigprocmask,
    sys_rt_sigsuspend, sys_tgkill,
};

const EINTR: i64 = -4;
const EINVAL: i64 = -22;
const USR1: u64 = 1 << (SIGUSR1 - 1);
const USR2: u64 = 1 << (SIGUSR2 - 1);

#[repr(C)]
struct SigAct {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// Bit per signal whose handler ran
static mut HANDLED: u64 = 0;
/// The blocked mask the last handler ran under
static mut HANDLER_MASK: u64 = 0;

extern "C" fn handler(signo: i32, _info: *const u8, _uc: *const u8) {
    let mut mask: u64 = 0;
    sys_rt_sigprocmask(SIG_BLOCK, 0, &mut mask as *mut u64 as u64, 8);
    unsafe {
        let h = core::ptr::read_volatile(&raw const HANDLED);
        core::ptr::write_volatile(&raw mut HANDLED, h | 1 << (signo - 1));
        core::ptr::write_volatile(&raw mut HANDLER_MASK, mask);
    }
}

pub fn run_tests() {
    test_epoll_pwait_sigmask();
    test_epoll_pwait_restore();
    test_ppoll_restore();
    test_sigsuspend_restore();
}

fn handled() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const HANDLED) }
}

fn handler_mask() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const HANDLER_MASK) }
}

/// Install the handler for SIGUSR1/SIGUSR2 and clear the record
fn catch() {
    unsafe {
        core::ptr::write_volatile(&raw mut HANDLED, 0);
        core::ptr::write_volatile(&raw mut HANDLER_MASK, 0);
    }
    let act = SigAct {
        handler: handler as *const () as u64,
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: restorer_addr(),
        mask: 0,
    };
    sys_rt_sigaction(SIGUSR1, &act as *const SigAct as u64, 0, 8);
    sys_rt_sigaction(SIGUSR2, &act as *const SigAct as u64, 0, 8);
}

/// Back to SIG_DFL for SIGUSR1/SIGUSR2
fn uncatch() {
    let act = SigAct {
        handler: SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    sys_rt_sigaction(SIGUSR1, &act as *const SigAct as u64, 0, 8);
    sys_rt_sigaction(SIGUSR2, &act as *const SigAct as u64, 0, 8);
}

fn set_mask(mask: u64) -> u64 {
    let mut old: u64 = 0;
    sys_rt_sigprocmask(
        SIG_SETMASK,
        &mask as *const u64 as u64,
        &mut old as *mut u64 as u64,
        8,
    );
    old
}

fn get_mask() -> u64 {
    let mut cur: u64 = 0;
    sys_rt_sigprocmask(SIG_BLOCK, 0, &mut cur as *mut u64 as u64, 8);
    cur
}

fn pending() -> u64 {
    let mut set: u64 = 0;
    sys_rt_sigpending(&mut set as *mut u64 as u64, 8);
    set
}

/// Queue `sig` for this thread
fn raise(sig: u32) {
    sys_tgkill(sys_getpid(), sys_gettid(), sig);
}

fn fail(name: &[u8], what: &[u8], v: i64) {
    print(name);
    print(b":FAIL ");
    print(what);
    print_num(v);
    println(b"");
}

/// epoll_pwait on an empty set with `mask` as the temporary mask
fn epoll_wait_mask(timeout: i32, mask: &u64, size: usize) -> i64 {
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        return epfd;
    }
    let mut ev = [EpollEvent::new(0, 0); 1];
    let r = sys_epoll_pwait(epfd as i32, ev.as_mut_ptr(), 1, timeout, mask, size);
    sys_close(epfd as u64);
    r
}

fn test_epoll_pwait_sigmask() {
    const T: &[u8] = b"EPOLL_PWAIT_SIGMASK";
    catch();
    let orig = set_mask(USR1 | USR2);
    raise(SIGUSR1);
    raise(SIGUSR2);
    // USR2 is deliverable under the temporary mask: no wait at all
    let r = epoll_wait_mask(10_000, &USR1, 8);
    let got = handled();
    let hmask = handler_mask();
    let after = get_mask();
    let still = pending();
    // Drain USR1 before judging
    set_mask(0);
    set_mask(orig);
    uncatch();
    if r != EINTR {
        fail(T, b"ret ", r);
    } else if got != USR2 {
        fail(T, b"handled set ", got as i64);
    } else if hmask != USR1 | USR2 {
        fail(T, b"handler mask ", hmask as i64);
    } else if after != USR1 | USR2 {
        fail(T, b"mask after ", after as i64);
    } else if still & USR1 == 0 {
        fail(T, b"pending after ", still as i64);
    } else {
        println(b"EPOLL_PWAIT_SIGMASK:OK");
    }
}

fn test_epoll_pwait_restore() {
    const T: &[u8] = b"EPOLL_PWAIT_SIGMASK_RESTORE";
    let orig = set_mask(USR1);
    let r = epoll_wait_mask(0, &USR2, 8);
    let after = get_mask();
    let bad = epoll_wait_mask(0, &USR2, 16);
    let after_bad = get_mask();
    set_mask(orig);
    if r != 0 {
        fail(T, b"ret ", r);
    } else if after != USR1 {
        fail(T, b"mask after ", after as i64);
    } else if bad != EINVAL {
        fail(T, b"sigsetsize 16 ret ", bad);
    } else if after_bad != USR1 {
        fail(T, b"mask after EINVAL ", after_bad as i64);
    } else {
        println(b"EPOLL_PWAIT_SIGMASK_RESTORE:OK");
    }
}

fn test_ppoll_restore() {
    const T: &[u8] = b"PPOLL_SIGMASK_RESTORE";
    let mut fds = [0i32; 2];
    if sys_pipe(fds.as_mut_ptr()) != 0 {
        fail(T, b"pipe ", -1);
        return;
    }
    let mut pfd = [PollFd {
        fd: fds[0],
        events: 1, // POLLIN
        revents: 0,
    }];
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let orig = set_mask(USR1);
    let r = sys_ppoll(pfd.as_mut_ptr(), 1, &ts, &USR2 as *const u64 as u64, 8);
    let after = get_mask();
    set_mask(orig);
    sys_close(fds[0] as u64);
    sys_close(fds[1] as u64);
    if r != 0 {
        fail(T, b"ret ", r);
    } else if after != USR1 {
        fail(T, b"mask after ", after as i64);
    } else {
        println(b"PPOLL_SIGMASK_RESTORE:OK");
    }
}

fn test_sigsuspend_restore() {
    const T: &[u8] = b"SIGSUSPEND_RESTORE";
    catch();
    let orig = set_mask(USR1 | USR2);
    raise(SIGUSR1);
    // Suspend with only USR2 blocked: USR1 runs its handler at once
    let r = sys_rt_sigsuspend(&USR2 as *const u64 as u64, 8);
    let got = handled();
    let hmask = handler_mask();
    let after = get_mask();
    set_mask(orig);
    uncatch();
    if r != EINTR {
        fail(T, b"ret ", r);
    } else if got != USR1 {
        fail(T, b"handled set ", got as i64);
    } else if hmask != USR1 | USR2 {
        fail(T, b"handler mask ", hmask as i64);
    } else if after != USR1 | USR2 {
        fail(T, b"mask after ", after as i64);
    } else {
        println(b"SIGSUSPEND_RESTORE:OK");
    }
}
