//! ptrace stops (run on hk and real Linux)
//!
//! - PTRACE_SYSCALL_STOP: a PTRACE_TRACEME child's SIGSTOP is a
//!   signal-delivery stop its parent's wait4 reports; under
//!   PTRACE_SYSCALL with PTRACE_O_TRACESYSGOOD each syscall stops at
//!   entry and exit with SIGTRAP | 0x80; on x86-64 the tracer changes
//!   the syscall number at the entry stop (getppid becomes getpid)
//! - PTRACE_STOP_KILL: SIGKILL ends a ptrace stop; wait4 reports the
//!   kill
//! - PTRACE_PEEK_DUMPABLE: an unprivileged tracer's PEEKDATA stores the
//!   word at `data` (the raw syscall returns 0); once the tracee made
//!   itself non-dumpable it fails with EIO (Linux ptrace_access_vm)
//! - PTRACE_POKE_TEXT: a tracer's POKETEXT into the tracee's program
//!   text (read-only, private) succeeds with a copy only the tracee
//!   sees, still read-only to it (its own write faults); without force,
//!   process_vm_writev there is EFAULT, and process_vm_readv of a page
//!   never touched reads zeros (both fault pages in: Linux GUP)

use super::sk::T;
use hk_syscall::{
    sys_exit, sys_fork, sys_getpid, sys_getppid, sys_kill, sys_prctl, sys_ptrace, sys_setresgid,
    sys_setresuid, sys_wait4,
};

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
    test_peek_dumpable();
    test_poke_text();
}

/// Never called: the text word POKETEXT writes
#[inline(never)]
extern "C" fn poke_target() -> u64 {
    core::hint::black_box(0x1234)
}

const POISON: u64 = 0x5a5a_5a5a_5a5a_5a5a;

fn text_word() -> u64 {
    // SAFETY: the function's own (readable) text
    unsafe { core::ptr::read_volatile(poke_target as *const u64) }
}

fn test_poke_text() {
    const PTRACE_PEEKTEXT: i64 = 1;
    const PTRACE_POKETEXT: i64 = 4;
    const EFAULT: i64 = -14;
    const SIGSEGV: i32 = 11;
    let mut t = T::new(b"PTRACE_POKE_TEXT");
    let addr = poke_target as *const u64 as u64;
    let orig = text_word();
    // An anonymous page no one touches
    let fresh = hk_syscall::sys_mmap(0, 4096, 3, 0x22, -1, 0);
    // A written page made PROT_NONE: still reachable by a forced access
    let none = hk_syscall::sys_mmap(0, 4096, 3, 0x22, -1, 0);
    if none > 0 {
        // SAFETY: the page just mapped read-write
        unsafe { core::ptr::write_volatile(none as *mut u64, 0x1111) };
        hk_syscall::sys_mprotect(none as u64, 4096, 0);
    }
    let pid = sys_fork();
    if pid == 0 {
        sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
        sys_kill(sys_getpid(), SIGSTOP);
        if text_word() != POISON {
            sys_exit(3);
        }
        // Still read-only to the tracee: this faults
        // SAFETY: deliberately writes read-only text (expected SIGSEGV)
        unsafe { core::ptr::write_volatile(addr as *mut u64, 0) };
        sys_exit(4);
    }
    let step = (|| {
        if fresh < 0 || stop_sig(pid) != SIGSTOP as i32 {
            return 1;
        }
        if sys_ptrace(PTRACE_POKETEXT, pid, addr, POISON) != 0 {
            return 2;
        }
        let mut w = 0u64;
        if sys_ptrace(PTRACE_PEEKTEXT, pid, addr, &mut w as *mut u64 as u64) != 0 || w != POISON {
            return 3;
        }
        if text_word() != orig {
            return 4; // the tracer's own text changed: no copy was made
        }
        let local = [0u8; 8];
        let liov = hk_syscall::IoVec {
            iov_base: local.as_ptr(),
            iov_len: 8,
        };
        let riov = hk_syscall::IoVec {
            iov_base: addr as *const u8,
            iov_len: 8,
        };
        if hk_syscall::sys_process_vm_writev(pid as i32, &liov, 1, &riov, 1, 0) != EFAULT {
            return 5;
        }
        let mut got = [0xffu8; 8];
        let liov = hk_syscall::IoVec {
            iov_base: got.as_mut_ptr(),
            iov_len: 8,
        };
        let riov = hk_syscall::IoVec {
            iov_base: fresh as *const u8,
            iov_len: 8,
        };
        if hk_syscall::sys_process_vm_readv(pid as i32, &liov, 1, &riov, 1, 0) != 8 || got != [0; 8]
        {
            return 6;
        }
        // PROT_NONE: a forced read and write reach it (Linux FOLL_FORCE)
        let mut w = 0u64;
        if none < 0
            || sys_ptrace(PTRACE_PEEKTEXT, pid, none as u64, &mut w as *mut u64 as u64) != 0
            || w != 0x1111
        {
            return 9;
        }
        if sys_ptrace(PTRACE_POKETEXT, pid, none as u64, 0x2222) != 0 {
            return 10;
        }
        if sys_ptrace(PTRACE_PEEKTEXT, pid, none as u64, &mut w as *mut u64 as u64) != 0
            || w != 0x2222
        {
            return 11;
        }
        sys_ptrace(PTRACE_CONT, pid, 0, 0);
        // The tracee's write to its text: a SIGSEGV stop, then death
        if stop_sig(pid) != SIGSEGV {
            return 7;
        }
        sys_ptrace(PTRACE_CONT, pid, 0, SIGSEGV as u64);
        let mut st = 0i32;
        sys_wait4(pid, &mut st, 0, 0);
        if st & 0x7f != SIGSEGV {
            return 8;
        }
        0
    })();
    if step != 0 {
        sys_kill(pid, SIGKILL);
        let mut st = 0i32;
        sys_wait4(pid, &mut st, 0, 0);
    }
    t.eq(b"step", step, 0);
    t.done();
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
    if st & 0xff == 0x7f {
        (st >> 8) & 0xff
    } else {
        -st
    }
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
    t.eq(
        b"exit entry stop",
        stop_sig(pid) as i64,
        SYSGOOD_TRAP as i64,
    );
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
    t.eq(
        b"getregs",
        sys_ptrace(PTRACE_GETREGS, pid, 0, regs.as_mut_ptr() as u64),
        0,
    );
    t.eq(b"orig_rax", regs[ORIG_RAX] as i64, 110);
    regs[ORIG_RAX] = 39;
    t.eq(
        b"setregs",
        sys_ptrace(PTRACE_SETREGS, pid, 0, regs.as_ptr() as u64),
        0,
    );
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

/// A word for PEEKDATA to find
static MAGIC: u64 = 0x1234_5678_9abc_def0;

/// In a uid-1000 tracer: PEEKDATA of a dumpable then a non-dumpable
/// TRACEME child; exit status: bit 0 dumpable peek wrong, bit 1
/// non-dumpable peek not EIO
fn peek_tracer() -> ! {
    const PTRACE_PEEKDATA: i64 = 2;
    const PR_SET_DUMPABLE: i32 = 4;
    sys_setresgid(1000, 1000, 1000);
    sys_setresuid(1000, 1000, 1000);
    let mut bad = 0;
    for dumpable in [1u64, 0] {
        let pid = sys_fork();
        if pid == 0 {
            sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
            sys_prctl(PR_SET_DUMPABLE, dumpable, 0, 0, 0);
            sys_kill(sys_getpid(), SIGSTOP);
            sys_exit(0);
        }
        stop_sig(pid);
        let mut word = 0u64;
        let r = sys_ptrace(
            PTRACE_PEEKDATA,
            pid,
            &MAGIC as *const u64 as u64,
            &mut word as *mut u64 as u64,
        );
        if dumpable == 1 && (r != 0 || word != MAGIC) {
            bad |= 1;
        }
        if dumpable == 0 && r != -5 {
            bad |= 2;
        }
        sys_kill(pid, SIGKILL);
        let mut st = 0i32;
        sys_wait4(pid, &mut st, 0, 0);
    }
    sys_exit(bad);
}

fn test_peek_dumpable() {
    let mut t = T::new(b"PTRACE_PEEK_DUMPABLE");
    let pid = sys_fork();
    if pid == 0 {
        peek_tracer();
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"tracer status", st as i64, 0);
    t.done();
}
