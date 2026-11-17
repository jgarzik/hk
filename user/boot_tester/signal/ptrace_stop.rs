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
//! - PTRACE_UNKNOWN_EIO: an unknown request is ESRCH for a process the
//!   caller does not trace, EIO for its stopped tracee
//! - PTRACE_RESUME_SIG_EIO: a resume or detach with a signal past _NSIG
//!   is EIO (the whole word for a resume, Linux ptrace_resume; its low
//!   32 bits for a detach, ptrace_detach) and leaves the tracee stopped
//! - PTRACE_SINGLESTEP_TRACE: from its SIGSTOP stop, each
//!   PTRACE_SINGLESTEP runs one instruction of a tight loop and stops
//!   with SIGTRAP, si_code TRAP_TRACE, si_addr the next instruction
//!   (x86-64 TF, arm64 MDSCR_EL1.SS / SPSR.SS)
//! - PTRACE_TRACER_SIPID: a signal a tracer thread (not its process's
//!   leader) gives with PTRACE_CONT arrives as SI_USER from that
//!   thread's tid (Linux ptrace_signal: task_pid_vnr(current->parent))

use crate::harness::T;
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
    test_unknown_request();
    test_resume_sig_eio();
    test_singlestep();
    test_tracer_sipid();
}

/// A traced child that stops itself with SIGSTOP, its kill's syscall
/// instruction followed at once by a loop of three nops and a branch
fn step_child() -> ! {
    sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
    let pid = sys_getpid();
    // SAFETY: kill(pid, SIGSTOP), then a loop that touches no memory
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "syscall", "2:", "nop", "nop", "nop", "jmp 2b",
            in("rax") 62, in("rdi") pid, in("rsi") SIGSTOP,
            options(noreturn)
        )
    }
    // SAFETY: kill(pid, SIGSTOP), then a loop that touches no memory
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0", "2:", "nop", "nop", "nop", "b 2b",
            in("x8") 129, in("x0") pid, in("x1") SIGSTOP,
            options(noreturn)
        )
    }
}

fn test_singlestep() {
    const PTRACE_SINGLESTEP: i64 = 9;
    const PTRACE_GETSIGINFO: i64 = 0x4202;
    const SIGTRAP: i64 = 5;
    const TRAP_TRACE: i64 = 2;
    let mut t = T::new(b"PTRACE_SINGLESTEP_TRACE");
    let pid = sys_fork();
    if pid == 0 {
        step_child();
    }
    t.eq(b"sigstop stop", stop_sig(pid) as i64, SIGSTOP as i64);
    let mut addrs = [0u64; 8];
    for a in addrs.iter_mut() {
        if !t.eq(b"step", sys_ptrace(PTRACE_SINGLESTEP, pid, 0, 0), 0)
            || !t.eq(b"trap stop", stop_sig_within(pid) as i64, SIGTRAP)
        {
            break;
        }
        // siginfo: si_signo, si_errno, si_code, pad, si_addr
        let mut si = [0u64; 16];
        sys_ptrace(PTRACE_GETSIGINFO, pid, 0, si.as_mut_ptr() as u64);
        t.eq(b"si_signo", si[0] as i32 as i64, SIGTRAP);
        t.eq(b"si_code", si[1] as i32 as i64, TRAP_TRACE);
        *a = si[2];
    }
    // Each step moved within the loop (nops and the branch back)
    let lo = addrs.iter().copied().min().unwrap_or(0);
    let hi = addrs.iter().copied().max().unwrap_or(0);
    t.ok(
        b"si_addr in the loop",
        lo != 0 && hi - lo <= 16,
        (hi - lo) as i64,
    );
    let moved = addrs.windows(2).all(|w| w[0] != w[1]);
    t.ok(b"each step moves", moved, 0);
    sys_kill(pid, SIGKILL);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    t.done();
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

/// [`stop_sig`] within 2 s (-2000: still running), so a step that
/// never traps fails instead of hanging
fn stop_sig_within(pid: i64) -> i32 {
    const WNOHANG: i32 = 1;
    let mut st = 0i32;
    for _ in 0..200 {
        match sys_wait4(pid, &mut st, WNOHANG, 0) {
            0 => crate::helpers::sleep_ms(10),
            r if r == pid && st & 0xff == 0x7f => return (st >> 8) & 0xff,
            r if r == pid => return -st,
            _ => return -1000,
        }
    }
    -2000
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

/// The SIGUSR1 handler's si_pid in the tracee (0 until it runs)
static SIPID: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

#[repr(C, align(16))]
struct TracerStack([u8; 16384]);
static mut TRACER_STACK: TracerStack = TracerStack([0; 16384]);
static mut TRACER_CTID: u32 = 0;

extern "C" fn on_usr1_info(_sig: i32, info: *const i32, _ctx: u64) {
    // siginfo: si_pid after si_signo, si_errno, si_code and padding
    // SAFETY: the kernel's siginfo for this delivery
    let pid = unsafe { core::ptr::read_volatile(info.add(4)) };
    SIPID.store(
        i64::from(pid as u32) | 1 << 32,
        core::sync::atomic::Ordering::SeqCst,
    );
}

/// The tracee: a SA_SIGINFO SIGUSR1 handler, a byte on `ready`, then
/// sleep until the handler ran; its si_pid goes out on `ready` too
fn sipid_tracee(ready: i32) -> ! {
    const SA_SIGINFO: u64 = 4;
    #[repr(C)]
    struct SigAction {
        handler: u64,
        flags: u64,
        restorer: u64,
        mask: u64,
    }
    let act = SigAction {
        handler: on_usr1_info as *const () as u64,
        flags: SA_SIGINFO | hk_syscall::SA_RESTORER,
        restorer: crate::signal::signals::restorer_addr(),
        mask: 0,
    };
    hk_syscall::sys_rt_sigaction(10, &act as *const SigAction as u64, 0, 8);
    // Unblocked (an earlier test may leave it blocked)
    let usr1 = 1u64 << 9;
    hk_syscall::sys_rt_sigprocmask(1, &usr1 as *const u64 as u64, 0, 8);
    let b = 1u8;
    hk_syscall::sys_write(ready as u64, &b, 1);
    while SIPID.load(core::sync::atomic::Ordering::SeqCst) == 0 {
        hk_syscall::sys_pause();
    }
    let pid = SIPID.load(core::sync::atomic::Ordering::SeqCst) as u32 as i32;
    hk_syscall::sys_write(ready as u64, (&pid as *const i32).cast(), 4);
    sys_exit(0);
}

/// The tracer thread (arg: tracee pid << 32 | pipe read end): attach,
/// see the SIGSTOP stop, continue with SIGUSR1, then stay attached
/// until the tracee reports the si_pid it got (the tracee reads its
/// tracer as it takes the signal); its exit code is the check
extern "C" fn sipid_tracer(arg: u64) -> ! {
    const PTRACE_ATTACH: i64 = 16;
    const WALL: i32 = 0x4000_0000;
    let (pid, rd) = ((arg >> 32) as i64, (arg & 0xffff_ffff) as u64);
    let mut st = 0i32;
    let mut code = 0u64;
    if sys_ptrace(PTRACE_ATTACH, pid, 0, 0) != 0 {
        code = 1;
    } else if sys_wait4(pid, &mut st, WALL, 0) != pid || st & 0xff != 0x7f {
        code = 2;
    } else if sys_ptrace(PTRACE_CONT, pid, 0, 10) != 0 {
        code = 3;
    } else {
        let mut got = 0i32;
        let n = hk_syscall::sys_read(rd, (&mut got as *mut i32).cast(), 4);
        if n != 4 {
            code = 4;
        } else if i64::from(got) != hk_syscall::sys_gettid() {
            code = match i64::from(got) {
                0 => 7,
                p if p == sys_getpid() => 5,
                _ => 6,
            };
        }
    }
    SIPID.store(code as i64, core::sync::atomic::Ordering::SeqCst);
    sys_exit(0);
}

/// In a forked process: the tracee child, then the tracer thread; the
/// process's exit status is the tracer's check code (0: si_pid was the
/// tracer thread's tid; 5: it was the process's pid)
fn sipid_process() -> ! {
    let mut p = [0i32; 2];
    if hk_syscall::sys_pipe2(p.as_mut_ptr(), 0) != 0 {
        sys_exit(10);
    }
    let c = sys_fork();
    if c == 0 {
        sipid_tracee(p[1]);
    }
    let mut b = 0u8;
    if hk_syscall::sys_read(p[0] as u64, &mut b, 1) != 1 {
        sys_exit(11);
    }
    let top = unsafe { (&raw mut TRACER_STACK as *mut u8).add(16384) as u64 };
    unsafe { core::ptr::write_volatile(&raw mut TRACER_CTID, 1) };
    let arg = ((c as u64) << 32) | p[0] as u64;
    let tid =
        unsafe { crate::mm::fork_mm::spawn_thread(top, sipid_tracer, arg, &raw mut TRACER_CTID) };
    if tid <= 0 || !crate::mm::fork_mm::join(&raw mut TRACER_CTID) {
        sys_exit(12);
    }
    let code = SIPID.load(core::sync::atomic::Ordering::SeqCst);
    let mut st = 0i32;
    sys_wait4(c, &mut st, 0, 0);
    sys_exit(code as u64);
}

fn test_tracer_sipid() {
    let mut t = T::new(b"PTRACE_TRACER_SIPID");
    let pid = sys_fork();
    if pid == 0 {
        sipid_process();
    }
    let mut st = 0i32;
    t.eq(b"wait", sys_wait4(pid, &mut st, 0, 0), pid);
    t.eq(b"status", st as i64, 0);
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

/// PTRACE_UNKNOWN_EIO: a request ptrace does not know is ESRCH for a
/// process the caller does not trace, EIO for its stopped tracee
/// (Linux sys_ptrace: ptrace_check_attach, then ptrace_request's
/// default)
fn test_unknown_request() {
    const UNKNOWN: i64 = 0x7777;
    const ESRCH: i64 = -3;
    const EIO: i64 = -5;
    let mut t = T::new(b"PTRACE_UNKNOWN_EIO");
    let pid = sys_fork();
    if pid == 0 {
        sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
        sys_kill(sys_getpid(), SIGSTOP);
        sys_exit(0);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    t.ok(b"stopped", st & 0xff == 0x7f, i64::from(st));
    t.eq(b"untraced", sys_ptrace(UNKNOWN, 1, 0, 0), ESRCH);
    t.eq(b"stopped tracee", sys_ptrace(UNKNOWN, pid, 0, 0), EIO);
    sys_kill(pid, SIGKILL);
    sys_wait4(pid, &mut st, 0, 0);
    t.done();
}

fn test_resume_sig_eio() {
    const PTRACE_DETACH: i64 = 17;
    const EIO: i64 = -5;
    let mut t = T::new(b"PTRACE_RESUME_SIG_EIO");
    let pid = sys_fork();
    if pid == 0 {
        sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
        sys_kill(sys_getpid(), SIGSTOP);
        sys_exit(0);
    }
    t.eq(b"stop", stop_sig(pid) as i64, SIGSTOP as i64);
    t.eq(b"cont 99", sys_ptrace(PTRACE_CONT, pid, 0, 99), EIO);
    t.eq(b"cont 1<<32", sys_ptrace(PTRACE_CONT, pid, 0, 1 << 32), EIO);
    t.eq(b"syscall 65", sys_ptrace(PTRACE_SYSCALL, pid, 0, 65), EIO);
    t.eq(b"detach 99", sys_ptrace(PTRACE_DETACH, pid, 0, 99), EIO);
    // Still stopped: this resume takes it
    t.eq(b"cont 0", sys_ptrace(PTRACE_CONT, pid, 0, 0), 0);
    let mut st = 0i32;
    t.eq(b"wait", sys_wait4(pid, &mut st, 0, 0), pid);
    t.eq(b"exit 0", i64::from(st), 0);
    t.done();
}
