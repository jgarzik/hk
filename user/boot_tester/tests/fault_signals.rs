//! Synchronous fault signals (Linux force_sig_fault semantics)
//!
//! Tests (each runs in a forked child so a broken kernel cannot take down
//! the test runner with a stray SIGSEGV):
//! - FAULT_SEGV_MAPERR: load from an unmapped page -> SIGSEGV handler with
//!   si_code SEGV_MAPERR, si_addr = fault address, ucontext PC = faulting
//!   instruction; the handler moves the PC past it and edits a register, and
//!   every other register (x86: including RCX/R11) survives rt_sigreturn
//! - FAULT_SEGV_ACCERR: store to a read-only page -> SEGV_ACCERR
//! - FAULT_PROT_NONE: load from a never-touched PROT_NONE page ->
//!   SEGV_ACCERR (the fault must not map a page there)
//! - FAULT_SIGILL: ud2 / udf -> SIGILL (ILL_ILLOPN on x86, ILL_ILLOPC on arm64)
//! - FAULT_SIGFPE: x86 integer divide by zero -> SIGFPE FPE_INTDIV
//! - FAULT_SIGTRAP: int3 / brk -> SIGTRAP
//! - FAULT_BLOCKED_KILL: fault with SIGSEGV blocked (handler installed) kills
//!   the task with SIGSEGV
//! - FAULT_IGNORED_KILL: fault with SIGSEGV ignored kills the task

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_exit, sys_fork, sys_mmap, sys_munmap, sys_rt_sigaction, sys_rt_sigprocmask, sys_wait4,
    MAP_ANONYMOUS, MAP_PRIVATE, PROT_NONE, PROT_READ, SA_RESTORER, SA_SIGINFO, SIGILL, SIGSEGV, SIGTRAP,
    SIG_BLOCK, SIG_IGN,
};

const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;
#[cfg(target_arch = "x86_64")]
const ILL_ILLOPN: i32 = 2;
#[cfg(target_arch = "aarch64")]
const ILL_ILLOPC: i32 = 1;
#[cfg(target_arch = "x86_64")]
const FPE_INTDIV: i32 = 1;
#[cfg(target_arch = "x86_64")]
const SI_KERNEL: i32 = 0x80;
#[cfg(target_arch = "aarch64")]
const TRAP_BRKPT: i32 = 1;

/// Value the handler stores in the result register
const HANDLER_MARK: u64 = 0x5a5a_1234;
const MAGIC1: u64 = 0x1122_3344_5566_7788;
const MAGIC2: u64 = 0x0246_8ace_1357_9bdf;

/// What the handler saw
#[derive(Clone, Copy)]
struct Seen {
    count: u64,
    signo: i32,
    code: i32,
    addr: u64,
    pc: u64,
}

static mut SEEN: Seen = Seen { count: 0, signo: 0, code: 0, addr: 0, pc: 0 };

// ucontext offsets (Linux): x86-64 uc_mcontext at 40; arm64 at 176
#[cfg(target_arch = "x86_64")]
mod uc {
    pub const R12: usize = 40 + 4 * 8;
    pub const RAX: usize = 40 + 13 * 8;
    pub const RIP: usize = 40 + 16 * 8;
}
#[cfg(target_arch = "aarch64")]
mod uc {
    pub const fn x(n: usize) -> usize {
        176 + 8 + n * 8
    }
    pub const PC: usize = 176 + 8 + 31 * 8 + 8;
}

extern "C" fn fault_handler(signo: i32, info: *const u8, ucp: *mut u8) {
    unsafe {
        let code = *(info.add(8) as *const i32);
        let addr = *(info.add(16) as *const u64);
        #[cfg(target_arch = "x86_64")]
        {
            let pc = *(ucp.add(uc::RIP) as *const u64);
            SEEN = Seen { count: SEEN.count + 1, signo, code, addr, pc };
            // Resume at the address the test left in R12; mark RAX
            *(ucp.add(uc::RIP) as *mut u64) = *(ucp.add(uc::R12) as *const u64);
            *(ucp.add(uc::RAX) as *mut u64) = HANDLER_MARK;
        }
        #[cfg(target_arch = "aarch64")]
        {
            let pc = *(ucp.add(uc::PC) as *const u64);
            SEEN = Seen { count: SEEN.count + 1, signo, code, addr, pc };
            // Resume at the address the test left in x9; mark x12
            *(ucp.add(uc::PC) as *mut u64) = *(ucp.add(uc::x(9)) as *const u64);
            *(ucp.add(uc::x(12)) as *mut u64) = HANDLER_MARK;
        }
    }
}

/// Registers observed after the faulting instruction was skipped
struct After {
    /// Result register (x86 RAX / arm64 x12): must be HANDLER_MARK
    result: u64,
    /// Preserved registers (x86 RCX, R11 / arm64 x10, x11)
    keep1: u64,
    keep2: u64,
    /// Address of the faulting instruction
    fault_pc: u64,
    /// Address after it (where the handler resumes)
    resume_pc: u64,
}

/// Execute `$insn` (with the operand register x86 RDI / arm64 x0 = `$arg`
/// and x86 RSI = 0) after loading the preserved registers; return `After`.
#[cfg(target_arch = "x86_64")]
macro_rules! run_fault {
    ($insn:literal, $arg:expr) => {{
        let (result, keep1, keep2, fault_pc, resume_pc): (u64, u64, u64, u64, u64);
        unsafe {
            core::arch::asm!(
                "lea r12, [rip + 4f]",
                "lea r13, [rip + 3f]",
                "movabs rcx, {m1}",
                "movabs r11, {m2}",
                "xor eax, eax",
                "xor edx, edx",
                "3:",
                $insn,
                "4:",
                m1 = const MAGIC1,
                m2 = const MAGIC2,
                in("rdi") $arg,
                in("rsi") 0u64,
                out("rax") result,
                out("rcx") keep1,
                out("r11") keep2,
                out("rdx") _,
                out("r12") resume_pc,
                out("r13") fault_pc,
            );
        }
        After { result, keep1, keep2, fault_pc, resume_pc }
    }};
}

#[cfg(target_arch = "aarch64")]
macro_rules! run_fault {
    ($insn:literal, $arg:expr) => {{
        let (result, keep1, keep2, fault_pc, resume_pc): (u64, u64, u64, u64, u64);
        unsafe {
            core::arch::asm!(
                "adr x9, 4f",
                "adr x13, 3f",
                "mov x10, {m1}",
                "mov x11, {m2}",
                "mov x12, #0",
                "3:",
                $insn,
                "4:",
                m1 = in(reg) MAGIC1,
                m2 = in(reg) MAGIC2,
                in("x0") $arg,
                out("x9") resume_pc,
                out("x10") keep1,
                out("x11") keep2,
                out("x12") result,
                out("x13") fault_pc,
            );
        }
        After { result, keep1, keep2, fault_pc, resume_pc }
    }};
}

fn install(sig: u32) -> bool {
    let action: [u64; 4] = [
        fault_handler as *const () as u64,
        SA_SIGINFO | SA_RESTORER,
        super::signals::restorer_addr(),
        0,
    ];
    sys_rt_sigaction(sig, action.as_ptr() as u64, 0, 8) == 0
}

/// Check what the handler saw and the state after resuming. Prints the
/// result line; returns the child exit code.
fn verify(
    name: &[u8],
    after: &After,
    signo: u32,
    code: i32,
    addr: u64,
    pc: u64,
) -> u64 {
    let s = unsafe { core::ptr::read_volatile(&raw const SEEN) };
    let mut err: i64 = 0;
    if s.count != 1 {
        err = 1;
    } else if s.signo != signo as i32 {
        err = 2;
    } else if s.code != code {
        err = 3;
    } else if s.addr != addr {
        err = 4;
    } else if s.pc != pc {
        err = 5;
    } else if after.result != HANDLER_MARK {
        err = 6;
    } else if after.keep1 != MAGIC1 || after.keep2 != MAGIC2 {
        err = 7;
    } else if after.resume_pc <= after.fault_pc {
        err = 8;
    }
    print(name);
    if err == 0 {
        println(b":OK");
        return 0;
    }
    print(b":FAIL: check ");
    print_num(err);
    print(b" count=");
    print_num(s.count as i64);
    print(b" signo=");
    print_num(s.signo as i64);
    print(b" code=");
    print_num(s.code as i64);
    print(b" addr=");
    print_num(s.addr as i64);
    print(b" want ");
    print_num(addr as i64);
    print(b" pc=");
    print_num(s.pc as i64);
    print(b" want ");
    print_num(pc as i64);
    println(b"");
    1
}

/// Run `f` in a forked child; FAIL if the child did not exit normally
fn in_child(name: &[u8], f: fn() -> u64) {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f());
    }
    if pid < 0 {
        print(name);
        println(b":FAIL: fork");
        return;
    }
    let mut status: i32 = 0;
    sys_wait4(pid, &mut status, 0, 0);
    if status & 0x7f != 0 {
        print(name);
        print(b":FAIL: child killed by signal ");
        print_num((status & 0x7f) as i64);
        println(b"");
    } else if (status >> 8) & 0xff == 9 {
        print(name);
        println(b":FAIL: sigaction");
    }
}

fn unmapped_page() -> u64 {
    let a = sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    sys_munmap(a as u64, 4096);
    a as u64
}

fn segv_maperr() -> u64 {
    if !install(SIGSEGV) {
        return 9;
    }
    let addr = unmapped_page() + 0x28;
    #[cfg(target_arch = "x86_64")]
    let a = run_fault!("mov rax, [rdi]", addr);
    #[cfg(target_arch = "aarch64")]
    let a = run_fault!("ldr x12, [x0]", addr);
    verify(b"FAULT_SEGV_MAPERR", &a, SIGSEGV, SEGV_MAPERR, addr, a.fault_pc)
}

fn segv_accerr() -> u64 {
    if !install(SIGSEGV) {
        return 9;
    }
    let page = sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) as u64;
    let addr = page + 0x100;
    // Populate it first: the store then hits a present read-only page
    unsafe { core::ptr::read_volatile(addr as *const u64) };
    #[cfg(target_arch = "x86_64")]
    let a = run_fault!("mov qword ptr [rdi], rdx", addr);
    #[cfg(target_arch = "aarch64")]
    let a = run_fault!("str x10, [x0]", addr);
    sys_munmap(page, 4096);
    verify(b"FAULT_SEGV_ACCERR", &a, SIGSEGV, SEGV_ACCERR, addr, a.fault_pc)
}

fn segv_prot_none() -> u64 {
    if !install(SIGSEGV) {
        return 9;
    }
    let page = sys_mmap(0, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) as u64;
    let addr = page + 0x40;
    #[cfg(target_arch = "x86_64")]
    let a = run_fault!("mov rax, [rdi]", addr);
    #[cfg(target_arch = "aarch64")]
    let a = run_fault!("ldr x12, [x0]", addr);
    sys_munmap(page, 4096);
    verify(b"FAULT_PROT_NONE", &a, SIGSEGV, SEGV_ACCERR, addr, a.fault_pc)
}

fn sigill() -> u64 {
    if !install(SIGILL) {
        return 9;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let a = run_fault!("ud2", 0u64);
        verify(b"FAULT_SIGILL", &a, SIGILL, ILL_ILLOPN, a.fault_pc, a.fault_pc)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let a = run_fault!("udf #0", 0u64);
        verify(b"FAULT_SIGILL", &a, SIGILL, ILL_ILLOPC, a.fault_pc, a.fault_pc)
    }
}

#[cfg(target_arch = "x86_64")]
fn sigfpe() -> u64 {
    if !install(hk_syscall::SIGFPE) {
        return 9;
    }
    // RDX:RAX = 0, divisor RSI = 0
    let a = run_fault!("div rsi", 0u64);
    verify(b"FAULT_SIGFPE", &a, hk_syscall::SIGFPE, FPE_INTDIV, a.fault_pc, a.fault_pc)
}

fn sigtrap() -> u64 {
    if !install(SIGTRAP) {
        return 9;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // int3 is a trap: the PC already points past it; no fault address
        let a = run_fault!("int3", 0u64);
        verify(b"FAULT_SIGTRAP", &a, SIGTRAP, SI_KERNEL, 0, a.resume_pc)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let a = run_fault!("brk #0", 0u64);
        verify(b"FAULT_SIGTRAP", &a, SIGTRAP, TRAP_BRKPT, a.fault_pc, a.fault_pc)
    }
}

/// Fault in a child set up by `prep`; the child must die by SIGSEGV
fn expect_killed(name: &[u8], prep: fn() -> bool) {
    let pid = sys_fork();
    if pid == 0 {
        if !prep() {
            sys_exit(9);
        }
        let addr = unmapped_page();
        unsafe { core::ptr::read_volatile(addr as *const u64) };
        sys_exit(0);
    }
    if pid < 0 {
        print(name);
        println(b":FAIL: fork");
        return;
    }
    let mut status: i32 = 0;
    sys_wait4(pid, &mut status, 0, 0);
    print(name);
    if status & 0x7f == SIGSEGV as i32 {
        println(b":OK");
    } else {
        print(b":FAIL: wait status ");
        print_num(status as i64);
        println(b"");
    }
}

fn prep_blocked() -> bool {
    let set: u64 = 1 << (SIGSEGV - 1);
    install(SIGSEGV) && sys_rt_sigprocmask(SIG_BLOCK, &set as *const u64 as u64, 0, 8) == 0
}

fn prep_ignored() -> bool {
    let action: [u64; 4] = [SIG_IGN, 0, 0, 0];
    sys_rt_sigaction(SIGSEGV, action.as_ptr() as u64, 0, 8) == 0
}

/// Run all fault-signal tests
pub fn run_tests() {
    in_child(b"FAULT_SEGV_MAPERR", segv_maperr);
    in_child(b"FAULT_SEGV_ACCERR", segv_accerr);
    in_child(b"FAULT_PROT_NONE", segv_prot_none);
    in_child(b"FAULT_SIGILL", sigill);
    #[cfg(target_arch = "x86_64")]
    in_child(b"FAULT_SIGFPE", sigfpe);
    in_child(b"FAULT_SIGTRAP", sigtrap);
    expect_killed(b"FAULT_BLOCKED_KILL", prep_blocked);
    expect_killed(b"FAULT_IGNORED_KILL", prep_ignored);
}
