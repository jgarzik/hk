//! Seccomp actions (Linux kernel/seccomp.c __seccomp_filter,
//! __secure_computing_strict, seccomp_sync_threads)
//!
//! Each case runs in a child that sets no_new_privs and installs a
//! cBPF filter returning one action for getppid (ALLOW otherwise):
//! - SECCOMP_ERRNO: SECCOMP_RET_ERRNO|5 makes getppid return -5
//! - SECCOMP_KILL_PROCESS: the process dies by SIGSYS
//! - SECCOMP_KILL_THREAD: a lone thread dies by SIGSYS; a thread with
//!   siblings exits alone and the process goes on
//! - SECCOMP_TRAP: a SIGSYS handler runs; with SIGSYS ignored the
//!   (forced) signal kills the process
//! - SECCOMP_TRAP_INFO: the SA_SIGINFO handler's siginfo is SYS_SECCOMP
//!   with the filter's data in si_errno, si_syscall, si_arch and a user
//!   si_call_addr; on x86-64 the syscall returns its number (Linux
//!   syscall_rollback: RAX = orig_ax)
//! - SECCOMP_TRACE: with no tracer, ENOSYS
//! - SECCOMP_UNKNOWN: an action Linux does not know kills the process
//! - SECCOMP_STRICT: in strict mode getppid kills by SIGKILL
//! - SECCOMP_TSYNC: TSYNC puts the filter on the other thread too
//! - SECCOMP_TSYNC_ZOMBIE: a leader that installed its own filter and
//!   exited alone (a zombie) does not stop a sibling's TSYNC (Linux
//!   skips exiting threads)
//! - SECCOMP_IP: the filter sees the syscall's user instruction pointer
//! - SECCOMP_ARCH_PROLOGUE: the AUDIT_ARCH check every libseccomp and
//!   systemd filter starts with (a constant >= 2^31) matches, and a
//!   jump with jt = jf = 0 falls through
//! - SECCOMP_SCRATCH: scratch memory M[] stores and loads
//! - SECCOMP_REJECTS: what Linux refuses is EINVAL (16/8-bit and
//!   unaligned or out-of-range loads, MOD, division by a zero constant,
//!   RET X, a load of an unstored M[] slot, a jump past the end)
//! - SECCOMP_PATH_ENOMEM: 4096-instruction filters stack 7 deep; the
//!   8th passes MAX_INSNS_PER_PATH and is ENOMEM

use crate::tests::harness::fail_num;
use crate::tests::helpers::{print, println};
use crate::tests::mm::fork_mm::{join, spawn_thread};
use crate::tests::signal::signals::restorer_addr;
use core::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use hk_syscall::{
    SA_RESTORER, SYS_GETPPID, sys_exit, sys_fork, sys_getppid, sys_prctl, sys_rt_sigaction,
    sys_seccomp, sys_wait4,
};

const PR_SET_NO_NEW_PRIVS: i32 = 38;
const SECCOMP_SET_MODE_STRICT: u32 = 0;
const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_KILL_THREAD: u32 = 0;
const RET_TRAP: u32 = 0x0003_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_TRACE: u32 = 0x7ff0_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const SIGKILL: i32 = 9;
const SIGSYS: u32 = 31;
const SIG_IGN: u64 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const fn ins(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// BPF_LD|BPF_W|BPF_ABS, BPF_JMP|BPF_JEQ|BPF_K, BPF_RET|BPF_K
const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const RET_K: u16 = 0x06;
/// BPF_LD|BPF_IMM, BPF_ST, BPF_LD|BPF_MEM
const LD_IMM: u16 = 0x00;
const ST: u16 = 0x02;
const LD_MEM: u16 = 0x60;
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

/// Install "getppid -> `action`, else ALLOW" with `flags`
fn install(action: u32, flags: u32) -> i64 {
    let prog = [
        ins(LD_W_ABS, 0, 0, 0),
        ins(JEQ_K, 0, 1, SYS_GETPPID as u32),
        ins(RET_K, 0, 0, action),
        ins(RET_K, 0, 0, RET_ALLOW),
    ];
    load(&prog, flags)
}

fn load(prog: &[SockFilter], flags: u32) -> i64 {
    let fp = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    sys_seccomp(
        SECCOMP_SET_MODE_FILTER,
        flags,
        &fp as *const SockFprog as u64,
    )
}

/// Run `f` in a child with no_new_privs set: its wait status
fn child(f: fn() -> u64) -> i32 {
    let pid = sys_fork();
    if pid == 0 {
        if sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            sys_exit(100);
        }
        sys_exit(f());
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    st
}

fn report(name: &[u8], ok: bool, st: i32) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        fail_num(b":FAIL status ", st as i64);
    }
}

pub fn run_tests() {
    errno();
    kill_process();
    kill_thread();
    trap();
    trap_info();
    trace();
    unknown();
    strict();
    tsync();
    tsync_zombie();
    ip();
    arch_prologue();
    scratch();
    rejects();
    path_enomem();
}

fn errno() {
    let st = child(|| {
        if install(RET_ERRNO | 5, 0) != 0 {
            return 1;
        }
        if sys_getppid() == -5 { 0 } else { 2 }
    });
    report(b"SECCOMP_ERRNO", st == 0, st);
}

fn kill_process() {
    let st = child(|| {
        if install(RET_KILL_PROCESS, 0) != 0 {
            return 1;
        }
        sys_getppid();
        2
    });
    report(b"SECCOMP_KILL_PROCESS", st & 0x7f == SIGSYS as i32, st);
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;
static THREAD_RET: AtomicI64 = AtomicI64::new(0);
static GO: AtomicU32 = AtomicU32::new(0);

extern "C" fn call_getppid(_: u64) -> ! {
    while GO.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    THREAD_RET.store(sys_getppid(), Ordering::Release);
    sys_exit(0)
}

/// Start the getppid thread (it waits for GO)
fn start_thread() -> bool {
    unsafe {
        let top = (&raw mut STACK as *mut u8).add(16384) as u64;
        let ctid = &raw mut CTID;
        core::ptr::write_volatile(ctid, 1);
        spawn_thread(top, call_getppid, 0, ctid) > 0
    }
}

fn kill_thread() {
    // Alone: the process dies by SIGSYS
    let lone = child(|| {
        if install(RET_KILL_THREAD, 0) != 0 {
            return 1;
        }
        sys_getppid();
        2
    });
    // With a sibling: only that thread goes
    let sib = child(|| {
        if install(RET_KILL_THREAD, 0) != 0 || !start_thread() {
            return 1;
        }
        THREAD_RET.store(12345, Ordering::Release);
        GO.store(1, Ordering::Release);
        if !join(&raw mut CTID) {
            return 3;
        }
        // It never returned from getppid
        if THREAD_RET.load(Ordering::Acquire) == 12345 {
            0
        } else {
            4
        }
    });
    report(
        b"SECCOMP_KILL_THREAD",
        lone & 0x7f == SIGSYS as i32 && sib == 0,
        if sib != 0 { 1000 + sib } else { lone },
    );
}

static TRAPPED: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_sigsys(_: i32) {
    TRAPPED.store(1, Ordering::Release);
}

#[repr(C)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

fn sigaction(sig: u32, handler: u64) {
    let a = SigAction {
        handler,
        flags: SA_RESTORER,
        restorer: restorer_addr(),
        mask: 0,
    };
    sys_rt_sigaction(sig, &a as *const SigAction as u64, 0, 8);
}

fn trap() {
    let handled = child(|| {
        sigaction(SIGSYS, on_sigsys as *const () as u64);
        if install(RET_TRAP, 0) != 0 {
            return 1;
        }
        sys_getppid();
        if TRAPPED.load(Ordering::Acquire) == 1 {
            0
        } else {
            2
        }
    });
    let ignored = child(|| {
        sigaction(SIGSYS, SIG_IGN);
        if install(RET_TRAP, 0) != 0 {
            return 1;
        }
        sys_getppid();
        2
    });
    report(
        b"SECCOMP_TRAP",
        handled == 0 && ignored & 0x7f == SIGSYS as i32,
        if handled != 0 {
            1000 + handled
        } else {
            ignored
        },
    );
}

/// What the SA_SIGINFO SIGSYS handler saw: si_code, si_errno,
/// si_syscall, si_arch, si_call_addr != 0
static SEEN: [AtomicU32; 5] = [const { AtomicU32::new(0) }; 5];

extern "C" fn on_sigsys_info(_: i32, info: *const u8, _: *const u8) {
    // SAFETY: the kernel passes a 128-byte siginfo_t
    let b = unsafe { core::slice::from_raw_parts(info, 128) };
    let u = |at: usize| u32::from_ne_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    // si_errno 4, si_code 8, si_call_addr 16, si_syscall 24, si_arch 28
    let vals = [
        u(8),
        u(4),
        u(24),
        u(28),
        u32::from(u(16) != 0 || u(20) != 0),
    ];
    for (s, v) in SEEN.iter().zip(vals) {
        s.store(v, Ordering::Release);
    }
}

fn trap_info() {
    let st = child(|| {
        let a = SigAction {
            handler: on_sigsys_info as *const () as u64,
            flags: SA_RESTORER | 4, // SA_SIGINFO
            restorer: restorer_addr(),
            mask: 0,
        };
        sys_rt_sigaction(SIGSYS, &a as *const SigAction as u64, 0, 8);
        if install(RET_TRAP | 0x42, 0) != 0 {
            return 1;
        }
        let r = sys_getppid();
        let seen: [u32; 5] = core::array::from_fn(|i| SEEN[i].load(Ordering::Acquire));
        if seen != [1, 0x42, SYS_GETPPID as u32, AUDIT_ARCH, 1] {
            return 2;
        }
        #[cfg(target_arch = "x86_64")]
        if r != SYS_GETPPID as i64 {
            return 3;
        }
        let _ = r;
        0
    });
    report(b"SECCOMP_TRAP_INFO", st == 0, st);
}

fn trace() {
    let st = child(|| {
        if install(RET_TRACE, 0) != 0 {
            return 1;
        }
        if sys_getppid() == -38 { 0 } else { 2 }
    });
    report(b"SECCOMP_TRACE", st == 0, st);
}

fn unknown() {
    let st = child(|| {
        if install(0x7f00_0000, 0) != 0 {
            return 1;
        }
        sys_getppid();
        2
    });
    report(b"SECCOMP_UNKNOWN", st & 0x7f == SIGSYS as i32, st);
}

fn strict() {
    let st = child(|| {
        if sys_seccomp(SECCOMP_SET_MODE_STRICT, 0, 0) != 0 {
            return 1;
        }
        sys_getppid();
        2
    });
    report(b"SECCOMP_STRICT", st & 0x7f == SIGKILL, st);
}

fn tsync() {
    let st = child(|| {
        if !start_thread() {
            return 1;
        }
        if install(RET_ERRNO | 6, SECCOMP_FILTER_FLAG_TSYNC) != 0 {
            return 2;
        }
        GO.store(1, Ordering::Release);
        if !join(&raw mut CTID) {
            return 3;
        }
        if THREAD_RET.load(Ordering::Acquire) == -6 {
            0
        } else {
            4
        }
    });
    report(b"SECCOMP_TSYNC", st == 0, st);
}

fn ip() {
    let st = child(|| {
        // seccomp_data: nr at 0, arch at 4, instruction_pointer at 8
        let prog = [
            ins(LD_W_ABS, 0, 0, 0),
            ins(JEQ_K, 0, 3, SYS_GETPPID as u32),
            ins(LD_W_ABS, 0, 0, 8),
            ins(JEQ_K, 0, 1, 0),
            ins(RET_K, 0, 0, RET_ERRNO | 7),
            ins(RET_K, 0, 0, RET_ALLOW),
        ];
        if load(&prog, 0) != 0 {
            return 1;
        }
        if sys_getppid() > 0 { 0 } else { 2 }
    });
    report(b"SECCOMP_IP", st == 0, st);
}

static ZOMBIE_RESULT: AtomicI64 = AtomicI64::new(1);

/// The sibling: once the leader has gone, TSYNC an allow-all filter;
/// the whole process exits with the result
extern "C" fn tsync_after_leader(_: u64) -> ! {
    while GO.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    let ts = hk_syscall::Timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
    let prog = [ins(RET_K, 0, 0, RET_ALLOW)];
    let r = load(&prog, SECCOMP_FILTER_FLAG_TSYNC);
    ZOMBIE_RESULT.store(r, Ordering::Release);
    hk_syscall::sys_exit_group(if r == 0 { 0 } else { 1 })
}

fn tsync_zombie() {
    let st = child(|| {
        unsafe {
            let top = (&raw mut STACK as *mut u8).add(16384) as u64;
            let ctid = &raw mut CTID;
            core::ptr::write_volatile(ctid, 1);
            if spawn_thread(top, tsync_after_leader, 0, ctid) <= 0 {
                return 1;
            }
        }
        // The leader's own filter, then it exits alone
        let prog = [ins(RET_K, 0, 0, RET_ALLOW)];
        if load(&prog, 0) != 0 {
            return 2;
        }
        GO.store(1, Ordering::Release);
        sys_exit(0)
    });
    report(b"SECCOMP_TSYNC_ZOMBIE", st == 0, st);
}

fn arch_prologue() {
    let st = child(|| {
        let prog = [
            ins(LD_W_ABS, 0, 0, 4),
            ins(JEQ_K, 0, 0, 0),
            ins(JEQ_K, 1, 0, AUDIT_ARCH),
            ins(RET_K, 0, 0, RET_KILL_PROCESS),
            ins(LD_W_ABS, 0, 0, 0),
            ins(JEQ_K, 0, 1, SYS_GETPPID as u32),
            ins(RET_K, 0, 0, RET_ERRNO | 5),
            ins(RET_K, 0, 0, RET_ALLOW),
        ];
        if load(&prog, 0) != 0 {
            return 1;
        }
        if sys_getppid() == -5 { 0 } else { 2 }
    });
    report(b"SECCOMP_ARCH_PROLOGUE", st == 0, st);
}

fn scratch() {
    let st = child(|| {
        let prog = [
            ins(LD_W_ABS, 0, 0, 0),
            ins(ST, 0, 0, 15),
            ins(LD_IMM, 0, 0, 0),
            ins(ST, 0, 0, 0),
            ins(LD_MEM, 0, 0, 15),
            ins(JEQ_K, 0, 1, SYS_GETPPID as u32),
            ins(RET_K, 0, 0, RET_ERRNO | 7),
            ins(RET_K, 0, 0, RET_ALLOW),
        ];
        if load(&prog, 0) != 0 {
            return 1;
        }
        if sys_getppid() == -7 { 0 } else { 2 }
    });
    report(b"SECCOMP_SCRATCH", st == 0, st);
}

fn rejects() {
    let st = child(|| {
        let ret = ins(RET_K, 0, 0, RET_ALLOW);
        let bad: [[SockFilter; 2]; 9] = [
            [ins(0x28, 0, 0, 0), ret],                  // ld [0] halfword
            [ins(0x30, 0, 0, 0), ret],                  // ld [0] byte
            [ins(LD_W_ABS, 0, 0, 2), ret],              // unaligned
            [ins(LD_W_ABS, 0, 0, 64), ret],             // past seccomp_data
            [ins(0x94, 0, 0, 3), ret],                  // mod #3
            [ins(0x34, 0, 0, 0), ret],                  // div #0
            [ins(LD_MEM, 0, 0, 2), ret],                // M[2] never stored
            [ins(0x05, 0, 0, 1), ret],                  // ja past the end
            [ins(LD_IMM, 0, 0, 0), ins(0x0e, 0, 0, 0)], // ret x
        ];
        for (i, p) in bad.iter().enumerate() {
            if load(p, 0) != EINVAL {
                return 10 + i as u64;
            }
        }
        // Nothing installed: getppid still works
        if sys_getppid() <= 0 { 2 } else { 0 }
    });
    report(b"SECCOMP_REJECTS", st == 0, st);
}

/// 4095 loads and a RET: the longest program
static BIG: [SockFilter; 4096] = {
    let mut p = [ins(LD_IMM, 0, 0, 0); 4096];
    p[4095] = ins(RET_K, 0, 0, RET_ALLOW);
    p
};

fn path_enomem() {
    let st = child(|| {
        for n in 0..7 {
            if load(&BIG, 0) != 0 {
                return 10 + n;
            }
        }
        if load(&BIG, 0) != ENOMEM { 2 } else { 0 }
    });
    report(b"SECCOMP_PATH_ENOMEM", st == 0, st);
}
