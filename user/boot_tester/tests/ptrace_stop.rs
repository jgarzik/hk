//! ptrace stops (run on hk and real Linux)
//!
//! - PTRACE_SYSCALL_STOP: a PTRACE_TRACEME child's SIGSTOP is a
//!   signal-delivery stop its parent's wait4 reports; under
//!   PTRACE_SYSCALL with PTRACE_O_TRACESYSGOOD each syscall stops at
//!   entry and exit with SIGTRAP | 0x80; on x86-64 the tracer changes
//!   the syscall number at the entry stop (getppid becomes getpid)
//! - PTRACE_STOP_KILL: SIGKILL ends a ptrace stop; wait4 reports the
//!   kill

use super::sk::T;
use hk_syscall::{sys_exit, sys_fork, sys_getpid, sys_getppid, sys_kill, sys_ptrace, sys_wait4};

const PTRACE_TRACEME: i64 = 0;
const PTRACE_CONT: i64 = 7;
const PTRACE_SYSCALL: i64 = 24;
const PTRACE_SETOPTIONS: i64 = 0x4200;
const PTRACE_O_TRACESYSGOOD: u64 = 1;
const SIGKILL: u32 = 9;
const SIGSTOP: u32 = 19;
const SYSGOOD_TRAP: i32 = 0x80 | 5;

pub fn run_tests() {
    test_syscall_stop();
    test_stop_kill();
}

/// A child that stops for its tracer, then makes one getppid: exit 7 if
/// it returned its own pid (changed to getpid), else 8
fn traced_child() -> ! {
    sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
    sys_kill(sys_getpid(), SIGSTOP);
    let r = sys_getppid();
    sys_exit(if r == sys_getpid() { 7 } else { 8 });
}

/// wait4 for `pid`: the stop signal of a stop, else -(status)
fn stop_sig(pid: i64) -> i32 {
    let mut st = 0i32;
    if sys_wait4(pid, &mut st, 0, 0) != pid {
        return -1000;
    }
    if st & 0xff == 0x7f { (st >> 8) & 0xff } else { -st }
}

fn test_syscall_stop() {
    let mut t = T::new(b"PTRACE_SYSCALL_STOP");
    let pid = sys_fork();
    if pid == 0 {
        traced_child();
    }
    t.eq(b"sigstop stop", stop_sig(pid) as i64, SIGSTOP as i64);
    let opt = sys_ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    t.eq(b"setoptions", opt, 0);
    // getppid entry: the tracer turns it into getpid (x86-64)
    t.eq(b"resume", sys_ptrace(PTRACE_SYSCALL, pid, 0, 0), 0);
    t.eq(b"entry stop", stop_sig(pid) as i64, SYSGOOD_TRAP as i64);
    let want = change_syscall(&mut t, pid);
    sys_ptrace(PTRACE_SYSCALL, pid, 0, 0);
    t.eq(b"exit stop", stop_sig(pid) as i64, SYSGOOD_TRAP as i64);
    // exit's entry stop, then it runs
    sys_ptrace(PTRACE_SYSCALL, pid, 0, 0);
    t.eq(b"exit entry stop", stop_sig(pid) as i64, SYSGOOD_TRAP as i64);
    sys_ptrace(PTRACE_CONT, pid, 0, 0);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"exit status", ((st >> 8) & 0xff) as i64, want);
    t.done();
}

/// At getppid's entry stop make it getpid (x86-64: orig_rax); the child's
/// expected exit status
#[cfg(target_arch = "x86_64")]
fn change_syscall(t: &mut T, pid: i64) -> i64 {
    const PTRACE_GETREGS: i64 = 12;
    const PTRACE_SETREGS: i64 = 13;
    const ORIG_RAX: usize = 15;
    let mut regs = [0u64; 27];
    t.eq(b"getregs", sys_ptrace(PTRACE_GETREGS, pid, 0, regs.as_mut_ptr() as u64), 0);
    t.eq(b"orig_rax", regs[ORIG_RAX] as i64, 110);
    regs[ORIG_RAX] = 39;
    t.eq(b"setregs", sys_ptrace(PTRACE_SETREGS, pid, 0, regs.as_ptr() as u64), 0);
    7
}

#[cfg(target_arch = "aarch64")]
fn change_syscall(_t: &mut T, _pid: i64) -> i64 {
    8
}

fn test_stop_kill() {
    let mut t = T::new(b"PTRACE_STOP_KILL");
    let pid = sys_fork();
    if pid == 0 {
        traced_child();
    }
    t.eq(b"stop", stop_sig(pid) as i64, SIGSTOP as i64);
    sys_kill(pid, SIGKILL);
    let mut st = 0i32;
    t.eq(b"wait", sys_wait4(pid, &mut st, 0, 0), pid);
    t.eq(b"killed", (st & 0x7f) as i64, SIGKILL as i64);
    t.done();
}
