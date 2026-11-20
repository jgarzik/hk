//! ptrace event stops (run on hk and real Linux)
//!
//! - PTRACE_EVENT_EXIT: with PTRACE_O_TRACEEXIT a tracee that exits
//!   stops first, reported as SIGTRAP | PTRACE_EVENT_EXIT << 8, its
//!   wait status the PTRACE_GETEVENTMSG message; resumed, it exits with
//!   that status
//! - PTRACE_EVENT_FORK: with PTRACE_O_TRACEFORK a fork stops the tracee
//!   (SIGTRAP | PTRACE_EVENT_FORK << 8, the child's pid its message);
//!   the child is traced from birth and stops with SIGSTOP before it
//!   runs; the tracer's wait reports its exit, then its real parent's
//! - PTRACE_EVENT_CLONE: a clone whose exit signal is not SIGCHLD is a
//!   CLONE event, likewise traced
//! - PTRACE_EVENT_VFORK: with PTRACE_O_TRACEVFORK and
//!   PTRACE_O_TRACEVFORKDONE a vfork is a VFORK event, and once the
//!   child has exited a VFORK_DONE one, both with its pid
//! - PTRACE_EVENT_EXEC: with PTRACE_O_TRACEEXEC an exec stops the new
//!   image before it runs (SIGTRAP | PTRACE_EVENT_EXEC << 8, the
//!   thread's id its message); without it, a PTRACE_TRACEME tracee
//!   gets a plain SIGTRAP after the exec, sent as by kill (SI_USER:
//!   Linux send_sig with priv 0); under PTRACE_SYSCALL the execve entry
//!   stop, the EXEC event and the execve exit stop come in that order,
//!   the last two still naming execve as the syscall (x86 orig_rax:
//!   Linux start_thread keeps it)

use crate::harness::verdict;
use hk_syscall::{
    sys_clone, sys_exit, sys_fork, sys_getpid, sys_kill, sys_ptrace, sys_vfork, sys_wait4,
};

const PTRACE_TRACEME: i64 = 0;
const PTRACE_CONT: i64 = 7;
const PTRACE_SYSCALL: i64 = 24;
const PTRACE_O_TRACESYSGOOD: u64 = 1;
const PTRACE_O_TRACEEXEC: u64 = 1 << 4;
const PTRACE_EVENT_EXEC: i32 = 4;
const PTRACE_SETOPTIONS: i64 = 0x4200;
const PTRACE_GETEVENTMSG: i64 = 0x4201;
const PTRACE_GETSIGINFO: i64 = 0x4202;
const PTRACE_O_TRACEFORK: u64 = 1 << 1;
const PTRACE_O_TRACEVFORK: u64 = 1 << 2;
const PTRACE_O_TRACECLONE: u64 = 1 << 3;
const PTRACE_O_TRACEVFORKDONE: u64 = 1 << 5;
const PTRACE_O_TRACEEXIT: u64 = 1 << 6;
const PTRACE_EVENT_FORK: i32 = 1;
const PTRACE_EVENT_VFORK: i32 = 2;
const PTRACE_EVENT_CLONE: i32 = 3;
const PTRACE_EVENT_VFORK_DONE: i32 = 5;
const PTRACE_EVENT_EXIT: i32 = 6;
const SIGTRAP: i32 = 5;
const SIGSTOP: u32 = 19;
const SIGCHLD: i32 = 17;
const WALL: i32 = 0x4000_0000;

pub fn run_tests() {
    let r = event_exit();
    verdict(b"PTRACE_EVENT_EXIT", r == 0, r);
    let r = event_fork(PTRACE_O_TRACEFORK, PTRACE_EVENT_FORK, fork_kid);
    verdict(b"PTRACE_EVENT_FORK", r == 0, r);
    let r = event_fork(PTRACE_O_TRACECLONE, PTRACE_EVENT_CLONE, clone_kid);
    verdict(b"PTRACE_EVENT_CLONE", r == 0, r);
    let r = event_vfork();
    verdict(b"PTRACE_EVENT_VFORK", r == 0, r);
    let r = match event_exec() {
        0 => match exec_legacy() {
            0 => exec_syscall(),
            r => 100_000 + r,
        },
        r => r,
    };
    verdict(b"PTRACE_EVENT_EXEC", r == 0, r);
}

/// Exec `busybox true`
fn exec_true() -> ! {
    let argv: [*const u8; 2] = [b"true\0".as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];
    hk_syscall::sys_execve(b"/bin/busybox\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
    sys_exit(127)
}

/// Resume `c` to its exit: 0 if it exited 0
fn finish(c: i64, base: i64) -> i64 {
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    let st = wait(c);
    if st != 0 { base + i64::from(st) } else { 0 }
}

fn event_exec() -> i64 {
    let c = traced_child(PTRACE_O_TRACEEXEC, exec_true);
    if c < 0 {
        return 1;
    }
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    let st = wait(c);
    if !stopped(st, SIGTRAP, PTRACE_EVENT_EXEC) {
        return 1000 + i64::from(st);
    }
    if event_msg(c) as i64 != c {
        return 2000 + event_msg(c) as i64;
    }
    finish(c, 3000)
}

/// No TRACEEXEC: the exec's SIGTRAP, suppressed by the resume
fn exec_legacy() -> i64 {
    let c = traced_child(0, exec_true);
    if c < 0 {
        return 1;
    }
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    let st = wait(c);
    if !stopped(st, SIGTRAP, 0) {
        return 1000 + i64::from(st);
    }
    // si_code, after si_signo and si_errno: SI_USER (0)
    let mut info = [0i32; 32];
    let r = sys_ptrace(PTRACE_GETSIGINFO, c, 0, info.as_mut_ptr() as u64);
    if r != 0 || info[2] != 0 {
        return 3000 + i64::from(info[2]);
    }
    finish(c, 2000)
}

/// execve's entry stop, the EXEC event, then its exit stop
fn exec_syscall() -> i64 {
    let c = traced_child(PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD, exec_true);
    if c < 0 {
        return 1;
    }
    let want = [
        (SIGTRAP | 0x80, 0),
        (SIGTRAP, PTRACE_EVENT_EXEC),
        (SIGTRAP | 0x80, 0),
    ];
    for (i, &(sig, ev)) in want.iter().enumerate() {
        sys_ptrace(PTRACE_SYSCALL, c, 0, 0);
        let st = wait(c);
        if !stopped(st, sig, ev) {
            return (i as i64 + 1) * 1000 + i64::from(st);
        }
        // Each of the three stops still names execve
        if let Some(nr) = orig_nr(c)
            && nr != SYS_EXECVE
        {
            return (i as i64 + 1) * 10_000 + nr;
        }
    }
    finish(c, 9000)
}

/// The traced child's own child exits 5; it reaps it: 0 if that worked
fn reap_kid(g: i64) -> ! {
    let mut st = 0i32;
    let r = sys_wait4(g, &mut st, WALL, 0);
    sys_exit(if r == g && st == 5 << 8 { 0 } else { 9 })
}

fn fork_kid() -> ! {
    let g = sys_fork();
    if g == 0 {
        sys_exit(5);
    }
    reap_kid(g)
}

/// A clone with no exit signal (a CLONE event, not a FORK)
fn clone_kid() -> ! {
    let g = sys_clone(0, 0, 0, 0, 0);
    if g == 0 {
        sys_exit(5);
    }
    reap_kid(g)
}

/// The tracee's event stop for its new child, then the child traced
/// from birth (stopped by SIGSTOP), resumed to its exit, then the
/// tracee resumed to reap it
fn event_fork(opt: u64, event: i32, kid: fn() -> !) -> i64 {
    let c = traced_child(opt, kid);
    if c < 0 {
        return 1;
    }
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    let st = wait(c);
    if !stopped(st, SIGTRAP, event) {
        return 1000 + i64::from(st);
    }
    let g = event_msg(c) as i64;
    if g <= 0 {
        return 2;
    }
    let st = wait(g);
    if !stopped(st, SIGSTOP as i32, 0) {
        return 3000 + i64::from(st);
    }
    sys_ptrace(PTRACE_CONT, g, 0, 0);
    let st = wait(g);
    if st != 5 << 8 {
        return 4000 + i64::from(st);
    }
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    let st = wait_reap(c);
    if st != 0 {
        return 5000 + i64::from(st);
    }
    0
}

fn vfork_kid() -> ! {
    let g = sys_vfork();
    if g == 0 {
        sys_exit(5);
    }
    reap_kid(g)
}

/// VFORK, the child traced from birth run to its exit, then VFORK_DONE
fn event_vfork() -> i64 {
    let c = traced_child(PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE, vfork_kid);
    if c < 0 {
        return 1;
    }
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    let st = wait(c);
    if !stopped(st, SIGTRAP, PTRACE_EVENT_VFORK) {
        return 1000 + i64::from(st);
    }
    let g = event_msg(c) as i64;
    let st = wait(g);
    if g <= 0 || !stopped(st, SIGSTOP as i32, 0) {
        return 2000 + i64::from(st);
    }
    sys_ptrace(PTRACE_CONT, g, 0, 0);
    let st = wait(g);
    if st != 5 << 8 {
        return 3000 + i64::from(st);
    }
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    let st = wait(c);
    if !stopped(st, SIGTRAP, PTRACE_EVENT_VFORK_DONE) || event_msg(c) as i64 != g {
        return 4000 + i64::from(st);
    }
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    let st = wait_reap(c);
    if st != 0 {
        return 5000 + i64::from(st);
    }
    0
}

/// x86 user_regs_struct: 27 words, orig_rax word 15, rax word 10
#[cfg(target_arch = "x86_64")]
const REGS: usize = 27;
#[cfg(target_arch = "x86_64")]
const SYS_EXECVE: i64 = 59;
#[cfg(target_arch = "aarch64")]
const SYS_EXECVE: i64 = 221;

/// Stopped tracee `pid`'s syscall number (x86 orig_rax); None where it
/// cannot be read (arm64 has only PTRACE_GETREGSET for it)
#[cfg(target_arch = "x86_64")]
fn orig_nr(pid: i64) -> Option<i64> {
    const PTRACE_GETREGS: i64 = 12;
    let mut r = [0u64; REGS];
    (sys_ptrace(PTRACE_GETREGS, pid, 0, r.as_mut_ptr() as u64) == 0).then_some(r[15] as i64)
}

#[cfg(target_arch = "aarch64")]
fn orig_nr(_pid: i64) -> Option<i64> {
    None
}

/// Wait for `pid` (any kind of child): its status, or -1
fn wait(pid: i64) -> i32 {
    let mut st = 0i32;
    if sys_wait4(pid, &mut st, WALL, 0) != pid {
        return -1;
    }
    st
}

/// Wait for tracee `pid` that reaps its own child: its parent's
/// SIGCHLD for that child's exit stops it first (a signal-delivery
/// stop, as on Linux), delivered on and waited past
fn wait_reap(pid: i64) -> i32 {
    loop {
        let st = wait(pid);
        if !stopped(st, SIGCHLD, 0) {
            return st;
        }
        sys_ptrace(PTRACE_CONT, pid, 0, SIGCHLD as u64);
    }
}

/// `st` is a stop for `sig` (with the event in bits 16..)
fn stopped(st: i32, sig: i32, event: i32) -> bool {
    st & 0xff == 0x7f && (st >> 8) == (sig | event << 8)
}

/// The traced child's PTRACE_GETEVENTMSG message
fn event_msg(pid: i64) -> u64 {
    let mut m = 0u64;
    sys_ptrace(PTRACE_GETEVENTMSG, pid, 0, &mut m as *mut u64 as u64);
    m
}

/// A child traced by this process, stopped by its own SIGSTOP, then
/// running `f` once resumed: its pid, or -1
fn traced_child(opts: u64, f: fn() -> !) -> i64 {
    let c = sys_fork();
    if c == 0 {
        sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
        sys_kill(sys_getpid(), SIGSTOP);
        f();
    }
    if !stopped(wait(c), SIGSTOP as i32, 0) {
        return -1;
    }
    sys_ptrace(PTRACE_SETOPTIONS, c, 0, opts);
    c
}

fn event_exit() -> i64 {
    let c = traced_child(PTRACE_O_TRACEEXIT, || sys_exit(3));
    if c < 0 {
        return 1;
    }
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    let st = wait(c);
    if !stopped(st, SIGTRAP, PTRACE_EVENT_EXIT) {
        return 1000 + i64::from(st);
    }
    let m = event_msg(c);
    if m != 3 << 8 {
        return 2000 + m as i64;
    }
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    let st = wait(c);
    if st != 3 << 8 {
        return 3000 + i64::from(st);
    }
    0
}
