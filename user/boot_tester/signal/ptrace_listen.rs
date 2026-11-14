//! PTRACE_INTERRUPT and PTRACE_LISTEN (run on hk and real Linux)
//!
//! - PTRACE_INTERRUPT_STOP: INTERRUPT traps a running seized tracee in
//!   PTRACE_EVENT_STOP: wait4 status (SIGTRAP | 0x80 << 8) << 8 | 0x7f,
//!   siginfo SIGTRAP with that si_code; INTERRUPT in that trap leaves
//!   it and traps again after PTRACE_CONT; then the tracee runs on
//! - PTRACE_INTERRUPT_ATTACHED: INTERRUPT is ESRCH for a process the
//!   caller does not trace; INTERRUPT and LISTEN are EIO for a
//!   PTRACE_ATTACH tracee
//! - PTRACE_LISTEN_CONT: LISTEN in a seized tracee's group-stop trap
//!   (status (SIGSTOP | 0x80 << 8) << 8 | 0x7f): wait no longer reports
//!   it, requests are ESRCH, /proc still shows 't'; INTERRUPT traps it
//!   again in the group stop; listening again, SIGCONT traps it with
//!   SIGTRAP | PTRACE_EVENT_STOP << 8, then PTRACE_CONT reaches the
//!   SIGCONT's signal-delivery stop
//! - PTRACE_LISTEN_NOT_EVENT: LISTEN is ESRCH for a running tracee and
//!   EIO in a signal-delivery stop; in an INTERRUPT's PTRACE_EVENT_STOP
//!   trap it listens until the next INTERRUPT

use crate::helpers::sleep_ms;
use crate::signal::jobctl::{in_child, kill_reap, wait_within};
use crate::signal::ptrace_exit::stat_state;
use hk_syscall::{sys_fork, sys_kill, sys_ptrace, sys_rt_sigprocmask, sys_wait4};

const SIGTRAP: i32 = 5;
const SIGUSR1: i32 = 10;
const SIGCONT: i32 = 18;
const SIGSTOP: i32 = 19;
const WNOHANG: i32 = 1;
const SIG_SETMASK: i32 = 2;
const ESRCH: i64 = -3;
const EIO: i64 = -5;
const PTRACE_CONT: i64 = 7;
const PTRACE_ATTACH: i64 = 16;
const PTRACE_GETSIGINFO: i64 = 0x4202;
const PTRACE_SEIZE: i64 = 0x4206;
const PTRACE_INTERRUPT: i64 = 0x4207;
const PTRACE_LISTEN: i64 = 0x4208;
const EVENT_STOP: i32 = 128;

/// A wait4 status: stopped with `code` (WSTOPSIG and the event)
const fn stopped(code: i32) -> i32 {
    (code << 8) | 0x7f
}

/// A PTRACE_EVENT_STOP trap's status with signal `sig`
const fn event_stop(sig: i32) -> i32 {
    stopped(sig | (EVENT_STOP << 8))
}

pub fn run_tests() {
    in_child(b"PTRACE_INTERRUPT_STOP", interrupt_stop);
    in_child(b"PTRACE_INTERRUPT_ATTACHED", interrupt_attached);
    in_child(b"PTRACE_LISTEN_CONT", listen_cont);
    in_child(b"PTRACE_LISTEN_NOT_EVENT", listen_not_event);
}

/// A child that spins in user space (`spin`) or sleeps in a loop
fn spawn(spin: bool) -> i64 {
    let c = sys_fork();
    if c == 0 {
        // Nothing blocked: a signal sent stops it for its tracer
        let none = 0u64;
        sys_rt_sigprocmask(SIG_SETMASK, &none as *const u64 as u64, 0, 8);
        loop {
            if spin {
                core::hint::spin_loop();
            } else {
                sleep_ms(5);
            }
        }
    }
    c
}

/// The next stop of tracee `c` within 5 s is `want`
fn stops(c: i64, want: i32) -> bool {
    let mut st = 0i32;
    wait_within(c, &mut st, 0) == c && st == want
}

/// Tracee `c` reports nothing to wait within 50 ms
fn quiet(c: i64) -> bool {
    sleep_ms(50);
    let mut st = 0i32;
    sys_wait4(c, &mut st, WNOHANG, 0) == 0
}

/// The stopped tracee's siginfo: (si_signo, si_code), or the error
fn siginfo(c: i64) -> Result<(i32, i32), i64> {
    let mut si = [0u64; 16];
    match sys_ptrace(PTRACE_GETSIGINFO, c, 0, si.as_mut_ptr() as u64) {
        0 => Ok((si[0] as i32, si[1] as i32)),
        e => Err(e),
    }
}

/// Run `steps` on a child (`spin` or sleeping), killed and reaped after
fn with_child(spin: bool, steps: fn(i64) -> i32) -> i32 {
    let c = spawn(spin);
    let r = steps(c);
    kill_reap(c);
    r
}

fn interrupt_stop() -> i32 {
    with_child(true, |c| {
        let trap = SIGTRAP | (EVENT_STOP << 8);
        if sys_ptrace(PTRACE_SEIZE, c, 0, 0) != 0 {
            return 1;
        }
        if sys_ptrace(PTRACE_INTERRUPT, c, 0, 0) != 0 {
            return 2;
        }
        if !stops(c, event_stop(SIGTRAP)) {
            return 3;
        }
        if siginfo(c) != Ok((SIGTRAP, trap)) {
            return 4;
        }
        // In the trap: it stays, another comes after the resume
        if sys_ptrace(PTRACE_INTERRUPT, c, 0, 0) != 0 || !quiet(c) {
            return 5;
        }
        sys_ptrace(PTRACE_CONT, c, 0, 0);
        if !stops(c, event_stop(SIGTRAP)) {
            return 6;
        }
        sys_ptrace(PTRACE_CONT, c, 0, 0);
        if !quiet(c) {
            return 7;
        }
        0
    })
}

fn interrupt_attached() -> i32 {
    with_child(false, |c| {
        if sys_ptrace(PTRACE_INTERRUPT, c, 0, 0) != ESRCH {
            return 1;
        }
        if sys_ptrace(PTRACE_ATTACH, c, 0, 0) != 0 || !stops(c, stopped(SIGSTOP)) {
            return 2;
        }
        if sys_ptrace(PTRACE_INTERRUPT, c, 0, 0) != EIO {
            return 3;
        }
        if sys_ptrace(PTRACE_LISTEN, c, 0, 0) != EIO {
            return 4;
        }
        0
    })
}

fn listen_cont() -> i32 {
    with_child(false, |c| {
        if sys_ptrace(PTRACE_SEIZE, c, 0, 0) != 0 {
            return 1;
        }
        // SIGSTOP's signal-delivery stop, then the group stop's trap
        sys_kill(c, SIGSTOP as u32);
        if !stops(c, stopped(SIGSTOP)) {
            return 2;
        }
        sys_ptrace(PTRACE_CONT, c, 0, SIGSTOP as u64);
        if !stops(c, event_stop(SIGSTOP)) {
            return 12;
        }
        if sys_ptrace(PTRACE_LISTEN, c, 0, 0) != 0 {
            return 3;
        }
        // Listening: not stopped for wait nor for requests, still in
        // its trap ('t')
        if !quiet(c) {
            return 4;
        }
        if siginfo(c) != Err(ESRCH) {
            return 5;
        }
        if stat_state(c) != b't' {
            return 6;
        }
        // INTERRUPT ends the listening: a trap in the group stop
        if sys_ptrace(PTRACE_INTERRUPT, c, 0, 0) != 0 || !stops(c, event_stop(SIGSTOP)) {
            return 7;
        }
        if sys_ptrace(PTRACE_LISTEN, c, 0, 0) != 0 {
            return 8;
        }
        // The group stop ends: the notification trap, then SIGCONT's
        // own delivery stop
        sys_kill(c, SIGCONT as u32);
        if !stops(c, event_stop(SIGTRAP)) {
            return 9;
        }
        sys_ptrace(PTRACE_CONT, c, 0, 0);
        if !stops(c, stopped(SIGCONT)) {
            return 10;
        }
        sys_ptrace(PTRACE_CONT, c, 0, 0);
        if !quiet(c) {
            return 11;
        }
        0
    })
}

fn listen_not_event() -> i32 {
    with_child(false, |c| {
        if sys_ptrace(PTRACE_SEIZE, c, 0, 0) != 0 {
            return 1;
        }
        if sys_ptrace(PTRACE_LISTEN, c, 0, 0) != ESRCH {
            return 2;
        }
        sys_kill(c, SIGUSR1 as u32);
        if !stops(c, stopped(SIGUSR1)) {
            return 3;
        }
        if sys_ptrace(PTRACE_LISTEN, c, 0, 0) != EIO {
            return 4;
        }
        // Suppressed; an INTERRUPT's trap may be listened in too
        sys_ptrace(PTRACE_CONT, c, 0, 0);
        if sys_ptrace(PTRACE_INTERRUPT, c, 0, 0) != 0 || !stops(c, event_stop(SIGTRAP)) {
            return 5;
        }
        if sys_ptrace(PTRACE_LISTEN, c, 0, 0) != 0 || !quiet(c) {
            return 6;
        }
        if sys_ptrace(PTRACE_INTERRUPT, c, 0, 0) != 0 || !stops(c, event_stop(SIGTRAP)) {
            return 7;
        }
        0
    })
}
