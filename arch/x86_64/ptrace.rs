//! x86-64 ptrace support
//!
//! This module provides x86-64 specific register structures and functions
//! for ptrace operations.

use crate::task::Task;
use crate::task::ptrace::with_stopped_regs;
use crate::util::error::{KernelError, KernelResult};

// =============================================================================
// User register structure (matches Linux struct user_regs_struct)
// =============================================================================

/// x86-64 user_regs_struct (matches Linux layout)
///
/// This is the structure returned by PTRACE_GETREGS and set by PTRACE_SETREGS.
/// The order matches Linux's struct user_regs_struct from sys/user.h.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserRegsStruct {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    /// Original RAX value (syscall number before execution)
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}
crate::pod!(UserRegsStruct {
    r15,
    r14,
    r13,
    r12,
    rbp,
    rbx,
    r11,
    r10,
    r9,
    r8,
    rax,
    rcx,
    rdx,
    rsi,
    rdi,
    orig_rax,
    rip,
    cs,
    eflags,
    rsp,
    ss,
    fs_base,
    gs_base,
    ds,
    es,
    fs,
    gs
});

/// The register block PTRACE_GETREGS / PTRACE_SETREGS copy
pub type UserRegs = UserRegsStruct;

// =============================================================================
// Register access functions
// =============================================================================

/// All general-purpose registers of tracee `t`, from its pt_regs, held
/// in its ptrace stop ([`with_stopped_regs`]; ESRCH otherwise)
pub fn get_user_regs(t: &Task) -> KernelResult<UserRegsStruct> {
    with_stopped_regs(t, |tf| UserRegsStruct {
        r15: tf.r15,
        r14: tf.r14,
        r13: tf.r13,
        r12: tf.r12,
        rbp: tf.rbp,
        rbx: tf.rbx,
        r11: tf.r11,
        r10: tf.r10,
        r9: tf.r9,
        r8: tf.r8,
        rax: tf.rax,
        rcx: tf.rcx,
        rdx: tf.rdx,
        rsi: tf.rsi,
        rdi: tf.rdi,
        orig_rax: tf.orig_rax,
        rip: tf.rip,
        cs: tf.cs,
        eflags: tf.rflags,
        rsp: tf.rsp,
        ss: tf.ss,
        fs_base: t.tls.load(core::sync::atomic::Ordering::Relaxed),
        gs_base: t.gsbase.load(core::sync::atomic::Ordering::Relaxed),
        ds: 0x2b,
        es: 0x2b,
        fs: 0,
        gs: 0,
    })
}

/// Set all general-purpose registers of tracee `t`, in its pt_regs,
/// held in its ptrace stop ([`with_stopped_regs`]; ESRCH otherwise), to
/// take effect when it resumes
pub fn set_user_regs(t: &Task, regs: &UserRegsStruct) -> KernelResult<()> {
    // A non-canonical RIP would fault on the return to user mode in ring
    // 0 (SYSRET with the user stack loaded): refused (EIO). Linux takes
    // it and returns through IRET, which delivers SIGSEGV.
    if regs.rip >= 0x0000_8000_0000_0000 {
        return Err(KernelError::Io);
    }
    // Linux putreg: a base at or above TASK_SIZE_MAX is EIO
    if !super::percpu::fs_base_ok(regs.fs_base) || !super::percpu::fs_base_ok(regs.gs_base) {
        return Err(KernelError::Io);
    }

    with_stopped_regs(t, |tf| put_regs(t, tf, regs))
}

/// Write `regs` into tracee `t`'s frame `tf`
fn put_regs(t: &Task, tf: &mut crate::task::ptrace::PtRegs, regs: &UserRegsStruct) {
    tf.r15 = regs.r15;
    tf.r14 = regs.r14;
    tf.r13 = regs.r13;
    tf.r12 = regs.r12;
    tf.rbp = regs.rbp;
    tf.rbx = regs.rbx;
    tf.r11 = regs.r11;
    tf.r10 = regs.r10;
    tf.r9 = regs.r9;
    tf.r8 = regs.r8;
    tf.rax = regs.rax;
    // The syscall number: a tracer at a syscall-entry stop changes or
    // (-1) skips the syscall (Linux putreg orig_ax)
    tf.orig_rax = regs.orig_rax;
    tf.rcx = regs.rcx;
    tf.rdx = regs.rdx;
    tf.rsi = regs.rsi;
    tf.rdi = regs.rdi;
    tf.rip = regs.rip;
    tf.rflags = sanitize_rflags(regs.eflags);
    tf.rsp = regs.rsp;

    t.tls
        .store(regs.fs_base, core::sync::atomic::Ordering::Relaxed);
    t.gsbase
        .store(regs.gs_base, core::sync::atomic::Ordering::Relaxed);
}

/// Sanitize RFLAGS to prevent setting dangerous flags.
///
/// Only allow user-modifiable flags: CF, PF, AF, ZF, SF, OF, DF.
/// Preserve IF (interrupts must stay enabled).
fn sanitize_rflags(rflags: u64) -> u64 {
    const USER_FLAGS: u64 = 0x0cd5; // CF, PF, AF, ZF, SF, DF, OF
    const IF_FLAG: u64 = 0x200; // Interrupt flag (must stay set)

    // Keep only user-modifiable flags, ensure IF is set
    (rflags & USER_FLAGS) | IF_FLAG | 0x2 // Bit 1 is always set
}

// =============================================================================
// Single-step support
// =============================================================================

/// RFLAGS Trap Flag bit
const RFLAGS_TF: u64 = 0x100;

/// Single-step tracee `t` (Linux user_enable_single_step): TF in its
/// RFLAGS, so the CPU raises a debug exception after one instruction;
/// the tracee held in its ptrace stop ([`with_stopped_regs`])
pub fn enable_single_step(t: &Task) -> KernelResult<()> {
    with_stopped_regs(t, |tf| tf.rflags |= RFLAGS_TF)
}

/// Stop single-stepping tracee `t` (Linux user_disable_single_step):
/// TF cleared, the tracee held in its ptrace stop
pub fn disable_single_step(t: &Task) -> KernelResult<()> {
    with_stopped_regs(t, |tf| tf.rflags &= !RFLAGS_TF)
}
