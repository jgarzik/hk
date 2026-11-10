//! Alternate signal stack (Linux kernel/signal.c do_sigaltstack,
//! signal_delivered, restore_altstack; arch get_sigframe)
//!
//! Tests (run as an isolated group: a broken kernel kills a child, not init):
//! - SIGALTSTACK_MODE_ONSTACK: ss_flags SS_ONSTACK enables the stack like
//!   0; a query off the stack reports 0
//! - SIGALTSTACK_MINSIZE: ENOMEM below the arch MINSIGSTKSZ, OK at it
//! - SIGALTSTACK_DELIVER: an SA_ONSTACK handler runs on the alt stack, one
//!   without SA_ONSTACK on the interrupted stack
//! - SIGALTSTACK_UCSTACK: the handler's uc_stack is the stack as set
//!   (Linux __save_altstack: the stored flags, no SS_ONSTACK)
//! - SIGALTSTACK_ONSTACK_EPERM: on the stack, a change is EPERM and a
//!   query reports SS_ONSTACK
//! - SIGALTSTACK_AUTODISARM: with SS_AUTODISARM the handler finds it
//!   disabled; rt_sigreturn puts it back
//! - SIGALTSTACK_FORK: fork and vfork children inherit it; a CLONE_VM
//!   thread starts without one
//! - SIGALTSTACK_OVERFLOW: the SIGSEGV of a stack overflow into a guard
//!   page is caught by an SA_ONSTACK handler

use crate::harness::{R, check, report_r};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE, SA_ONSTACK, SA_RESTORER,
    SA_SIGINFO, SIGCHLD, SIGSEGV, SIGUSR1, sys_exit, sys_exit_group, sys_fork, sys_getpid,
    sys_gettid, sys_mmap, sys_mprotect, sys_rt_sigaction, sys_sigaltstack, sys_tgkill, sys_wait4,
};

const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;
const SS_AUTODISARM: i32 = 1 << 31;
const EPERM: i64 = -1;
const ENOMEM: i64 = -12;
#[cfg(target_arch = "x86_64")]
const MINSIGSTKSZ: u64 = 2048;
#[cfg(target_arch = "aarch64")]
const MINSIGSTKSZ: u64 = 5120;

const ALT_SIZE: u64 = 65536;
const PAGE: u64 = 4096;

#[repr(C, align(16))]
struct Stack([u8; ALT_SIZE as usize]);
static mut ALT: Stack = Stack([0; ALT_SIZE as usize]);
static mut THREAD_STACK: Stack = Stack([0; ALT_SIZE as usize]);

/// Linux stack_t
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq)]
struct StackT {
    ss_sp: u64,
    ss_flags: i32,
    _pad: i32,
    ss_size: u64,
}

impl StackT {
    const fn new(ss_sp: u64, ss_flags: i32, ss_size: u64) -> Self {
        Self {
            ss_sp,
            ss_flags,
            _pad: 0,
            ss_size,
        }
    }
}

/// What the SIGUSR1 handler saw
#[derive(Clone, Copy, Default)]
struct Seen {
    count: u64,
    /// Its own stack pointer
    sp: u64,
    /// ucontext uc_stack
    uc: StackT,
    /// sigaltstack(NULL, &oss) inside it
    query: StackT,
    /// sigaltstack(&WANT, NULL) inside it
    set_ret: i64,
}

static mut SEEN: Seen = Seen {
    count: 0,
    sp: 0,
    uc: StackT::new(0, 0, 0),
    query: StackT::new(0, 0, 0),
    set_ret: 0,
};
/// The stack the test installed (the handler tries to install it again)
static mut WANT: StackT = StackT::new(0, 0, 0);

pub fn run_tests() {
    test_mode_onstack();
    test_minsize();
    test_deliver();
    test_ucstack();
    test_onstack_eperm();
    test_autodisarm();
    test_fork();
    test_overflow();
    disable();
}

fn alt() -> u64 {
    (&raw mut ALT) as u64
}

/// `sp` lies on the alt stack (Linux __on_sig_stack: it grows down)
fn in_alt(sp: u64) -> bool {
    sp > alt() && sp - alt() <= ALT_SIZE
}

#[inline(always)]
fn cur_sp() -> u64 {
    let sp: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp)
    };
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp)
    };
    sp
}

fn set(ss: StackT) -> i64 {
    sys_sigaltstack(&ss as *const StackT as u64, 0)
}

/// Install `ss` as the stack the test wants (the handler's retry too)
fn want(ss: StackT) -> i64 {
    unsafe { core::ptr::write_volatile(&raw mut WANT, ss) };
    set(ss)
}

fn get() -> StackT {
    let mut oss = StackT::new(0, -1, 0);
    let r = sys_sigaltstack(0, &mut oss as *mut StackT as u64);
    if r != 0 {
        oss.ss_flags = r as i32;
    }
    oss
}

fn disable() {
    set(StackT::new(0, SS_DISABLE, 0));
}

extern "C" fn usr1(_sig: i32, _info: *const u8, ucp: *const u8) {
    let sp = cur_sp();
    // uc_stack follows uc_flags and uc_link on both arches
    let uc = unsafe { core::ptr::read_unaligned(ucp.add(16) as *const StackT) };
    let query = get();
    let set_ret = set(unsafe { core::ptr::read_volatile(&raw const WANT) });
    unsafe {
        let count = core::ptr::read_volatile(&raw const SEEN).count + 1;
        core::ptr::write_volatile(
            &raw mut SEEN,
            Seen {
                count,
                sp,
                uc,
                query,
                set_ret,
            },
        );
    }
}

fn action(handler: u64, flags: u64) -> [u64; 4] {
    [
        handler,
        SA_SIGINFO | SA_RESTORER | flags,
        crate::signal::signals::restorer_addr(),
        0,
    ]
}

/// Raise SIGUSR1 with the handler's sa_flags `flags`; what it saw
fn raise(flags: u64) -> Seen {
    let act = action(usr1 as *const () as u64, flags);
    sys_rt_sigaction(SIGUSR1, act.as_ptr() as u64, 0, 8);
    unsafe { core::ptr::write_volatile(&raw mut SEEN, Seen::default()) };
    sys_tgkill(sys_getpid(), sys_gettid(), SIGUSR1);
    unsafe { core::ptr::read_volatile(&raw const SEEN) }
}

fn test_mode_onstack() {
    report_r(b"SIGALTSTACK_MODE_ONSTACK", mode_onstack());
    disable();
}

fn mode_onstack() -> R {
    let r = set(StackT::new(alt(), SS_ONSTACK, ALT_SIZE));
    check(b"set SS_ONSTACK", r == 0, r)?;
    let q = get();
    check(b"sp", q.ss_sp == alt(), q.ss_sp as i64)?;
    check(b"size", q.ss_size == ALT_SIZE, q.ss_size as i64)?;
    check(b"flags off the stack", q.ss_flags == 0, q.ss_flags as i64)
}

fn test_minsize() {
    report_r(b"SIGALTSTACK_MINSIZE", minsize());
    disable();
}

fn minsize() -> R {
    let r = set(StackT::new(alt(), 0, MINSIGSTKSZ - 1));
    check(b"below MINSIGSTKSZ", r == ENOMEM, r)?;
    let r = set(StackT::new(alt(), 0, MINSIGSTKSZ));
    check(b"at MINSIGSTKSZ", r == 0, r)
}

fn test_deliver() {
    report_r(b"SIGALTSTACK_DELIVER", deliver());
    disable();
}

fn deliver() -> R {
    let r = want(StackT::new(alt(), 0, ALT_SIZE));
    check(b"set", r == 0, r)?;
    let s = raise(SA_ONSTACK);
    check(b"SA_ONSTACK ran", s.count == 1, s.count as i64)?;
    check(b"SA_ONSTACK sp on alt", in_alt(s.sp), s.sp as i64)?;
    let s = raise(0);
    check(b"plain ran", s.count == 1, s.count as i64)?;
    check(b"plain sp off alt", !in_alt(s.sp), s.sp as i64)
}

fn test_ucstack() {
    report_r(b"SIGALTSTACK_UCSTACK", ucstack());
    disable();
}

fn ucstack() -> R {
    let ss = StackT::new(alt(), 0, ALT_SIZE);
    let r = want(ss);
    check(b"set", r == 0, r)?;
    let s = raise(SA_ONSTACK);
    check(b"ran", s.count == 1, s.count as i64)?;
    check(b"uc_stack.ss_sp", s.uc.ss_sp == alt(), s.uc.ss_sp as i64)?;
    check(
        b"uc_stack.ss_size",
        s.uc.ss_size == ALT_SIZE,
        s.uc.ss_size as i64,
    )?;
    check(
        b"uc_stack.ss_flags",
        s.uc.ss_flags == 0,
        s.uc.ss_flags as i64,
    )?;
    // A stack set with SS_ONSTACK keeps that mode word
    let r = want(StackT::new(alt(), SS_ONSTACK, ALT_SIZE));
    check(b"set SS_ONSTACK", r == 0, r)?;
    let s = raise(SA_ONSTACK);
    check(
        b"uc_stack mode",
        s.uc.ss_flags == SS_ONSTACK,
        s.uc.ss_flags as i64,
    )
}

fn test_onstack_eperm() {
    report_r(b"SIGALTSTACK_ONSTACK_EPERM", onstack_eperm());
    disable();
}

fn onstack_eperm() -> R {
    let r = want(StackT::new(alt(), 0, ALT_SIZE));
    check(b"set", r == 0, r)?;
    let s = raise(SA_ONSTACK);
    check(b"ran", s.count == 1, s.count as i64)?;
    check(b"change on it", s.set_ret == EPERM, s.set_ret)?;
    check(
        b"query flags",
        s.query.ss_flags == SS_ONSTACK,
        s.query.ss_flags as i64,
    )?;
    check(b"query sp", s.query.ss_sp == alt(), s.query.ss_sp as i64)?;
    let q = get();
    check(b"after: flags", q.ss_flags == 0, q.ss_flags as i64)
}

fn test_autodisarm() {
    report_r(b"SIGALTSTACK_AUTODISARM", autodisarm());
    disable();
}

fn autodisarm() -> R {
    let ss = StackT::new(alt(), SS_AUTODISARM, ALT_SIZE);
    let r = want(ss);
    check(b"set", r == 0, r)?;
    let q = get();
    check(
        b"query flags",
        q.ss_flags == SS_AUTODISARM,
        q.ss_flags as i64,
    )?;
    // The handler re-installing it would hide the restore: it tries an
    // invalid mode instead
    unsafe { core::ptr::write_volatile(&raw mut WANT, StackT::new(0, 7, 0)) };
    let s = raise(SA_ONSTACK);
    check(b"ran", s.count == 1, s.count as i64)?;
    check(b"sp on alt", in_alt(s.sp), s.sp as i64)?;
    check(
        b"inside: flags",
        s.query.ss_flags == SS_DISABLE,
        s.query.ss_flags as i64,
    )?;
    check(
        b"inside: size",
        s.query.ss_size == 0,
        s.query.ss_size as i64,
    )?;
    check(
        b"uc_stack flags",
        s.uc.ss_flags == SS_AUTODISARM,
        s.uc.ss_flags as i64,
    )?;
    let q = get();
    check(b"after: sp", q.ss_sp == alt(), q.ss_sp as i64)?;
    check(b"after: size", q.ss_size == ALT_SIZE, q.ss_size as i64)?;
    check(
        b"after: flags",
        q.ss_flags == SS_AUTODISARM,
        q.ss_flags as i64,
    )
}

fn test_fork() {
    report_r(b"SIGALTSTACK_FORK", fork());
    disable();
}

/// What a vfork child or a thread found
static mut CHILD_SAW: StackT = StackT::new(0, 0, 0);
static mut CTID: u32 = 0;

fn fork() -> R {
    let ss = StackT::new(alt(), 0, ALT_SIZE);
    let r = set(ss);
    check(b"set", r == 0, r)?;
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(u64::from(get() != ss));
    }
    check(b"fork", pid > 0, pid)?;
    let mut st = -1i32;
    sys_wait4(pid, &mut st, 0, 0);
    check(b"fork child inherits", st == 0, st as i64)?;
    vfork_child();
    let saw = unsafe { core::ptr::read_volatile(&raw const CHILD_SAW) };
    check(b"vfork child inherits", saw == ss, saw.ss_flags as i64)?;
    let saw = thread_saw();
    check(
        b"thread flags",
        saw.ss_flags == SS_DISABLE,
        saw.ss_flags as i64,
    )?;
    check(b"thread size", saw.ss_size == 0, saw.ss_size as i64)
}

/// A CLONE_VM|CLONE_VFORK child records its stack in CHILD_SAW: it runs
/// on the parent's stack, so it only makes raw syscalls
fn vfork_child() {
    const CLONE_VM: u64 = 0x100;
    const CLONE_VFORK: u64 = 0x4000;
    unsafe { core::ptr::write_volatile(&raw mut CHILD_SAW, StackT::default()) };
    let c = hk_syscall::sys_clone(CLONE_VM | CLONE_VFORK | SIGCHLD as u64, 0, 0, 0, 0);
    if c == 0 {
        sys_sigaltstack(0, (&raw mut CHILD_SAW) as u64);
        sys_exit(0);
    }
    if c > 0 {
        let mut st = 0i32;
        sys_wait4(c, &mut st, 0, 0);
    }
}

extern "C" fn thread(_arg: u64) -> ! {
    let mut oss = StackT::new(0, -1, 0);
    sys_sigaltstack(0, &mut oss as *mut StackT as u64);
    unsafe { core::ptr::write_volatile(&raw mut CHILD_SAW, oss) };
    sys_exit(0)
}

/// What a new CLONE_VM thread finds
fn thread_saw() -> StackT {
    use crate::mm::fork_mm::{join, spawn_thread};
    unsafe { core::ptr::write_volatile(&raw mut CHILD_SAW, StackT::new(0, -1, 0)) };
    let top = (&raw mut THREAD_STACK) as u64 + ALT_SIZE;
    // Cleared by the thread's exit (CLONE_CHILD_CLEARTID)
    unsafe { core::ptr::write_volatile(&raw mut CTID, 1) };
    let tid = unsafe { spawn_thread(top, thread, 0, &raw mut CTID) };
    if tid <= 0 || !join(&raw mut CTID) {
        return StackT::new(0, -100, 0);
    }
    unsafe { core::ptr::read_volatile(&raw const CHILD_SAW) }
}

/// The guard page below the overflowing stack
static mut GUARD: u64 = 0;

/// SIGSEGV on the alt stack: exit 0 if it is there and the fault is the
/// guard page's
extern "C" fn segv(_sig: i32, info: *const u8, _ucp: *const u8) {
    let sp = cur_sp();
    let addr = unsafe { *(info.add(16) as *const u64) };
    let guard = unsafe { core::ptr::read_volatile(&raw const GUARD) };
    let code = if !in_alt(sp) {
        2
    } else if !(guard..guard + PAGE).contains(&addr) {
        3
    } else {
        0
    };
    sys_exit_group(code)
}

fn test_overflow() {
    report_r(b"SIGALTSTACK_OVERFLOW", overflow());
}

fn overflow() -> R {
    let pid = sys_fork();
    if pid == 0 {
        overflow_child();
    }
    check(b"fork", pid > 0, pid)?;
    let mut st = -1i32;
    sys_wait4(pid, &mut st, 0, 0);
    check(b"not killed", st & 0x7f == 0, (st & 0x7f) as i64)?;
    check(b"exit code", st == 0, ((st >> 8) & 0xff) as i64)
}

/// Run off the bottom of a 64 KiB stack into its guard page
fn overflow_child() -> ! {
    let len = ALT_SIZE + PAGE;
    let base = sys_mmap(
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if base < 0 || sys_mprotect(base as u64, PAGE, PROT_NONE) != 0 {
        sys_exit_group(10);
    }
    unsafe { core::ptr::write_volatile(&raw mut GUARD, base as u64) };
    if set(StackT::new(alt(), 0, ALT_SIZE)) != 0 {
        sys_exit_group(11);
    }
    let act = action(segv as *const () as u64, SA_ONSTACK);
    if sys_rt_sigaction(SIGSEGV, act.as_ptr() as u64, 0, 8) != 0 {
        sys_exit_group(12);
    }
    let top = base as u64 + len;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov rsp, {top}",
            "2:",
            "sub rsp, 4096",
            "mov qword ptr [rsp], 0",
            "jmp 2b",
            top = in(reg) top,
            options(noreturn),
        )
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "mov sp, {top}",
            "2:",
            "sub sp, sp, #4096",
            "str xzr, [sp]",
            "b 2b",
            top = in(reg) top,
            options(noreturn),
        )
    }
}
