//! x86-64 ptrace support
//!
//! This module provides x86-64 specific register structures and functions
//! for ptrace operations.

use crate::task::Tid;
use crate::task::percpu::TASKLIST;

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

// =============================================================================
// Register access functions
// =============================================================================

/// Get all general-purpose registers from a stopped tracee.
///
/// The tracee must be in Traced state. This reads its user registers
/// from its pt_regs (the entry frame at the top of its kernel stack).
pub fn get_user_regs(tid: Tid) -> Result<UserRegsStruct, i32> {
    let table = TASKLIST.read();
    let task = table.get(tid).ok_or(-3i32)?; // ESRCH

    // Check task is in traced state
    if !matches!(task.state, crate::task::TaskState::Traced(_)) {
        return Err(-3); // ESRCH - not stopped
    }

    // Its pt_regs: the frame at the top of its kernel stack
    // SAFETY: the tracee is stopped (TASKLIST held): its frame is stable
    let tf = unsafe { &*crate::task::percpu::task_pt_regs(task.task) };

    let regs = UserRegsStruct {
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
        fs_base: task.task.tls.load(core::sync::atomic::Ordering::Relaxed),
        gs_base: task.task.gsbase.load(core::sync::atomic::Ordering::Relaxed),
        ds: 0x2b,
        es: 0x2b,
        fs: 0,
        gs: 0,
    };

    Ok(regs)
}

/// Set all general-purpose registers for a stopped tracee.
///
/// The tracee must be in Traced state. This updates its pt_regs so the
/// registers take effect when it resumes.
pub fn set_user_regs(tid: Tid, regs: &UserRegsStruct) -> Result<(), i32> {
    let table = TASKLIST.read();
    let task = table.get(tid).ok_or(-3i32)?; // ESRCH

    // Check task is in traced state
    if !matches!(task.state, crate::task::TaskState::Traced(_)) {
        return Err(-3); // ESRCH - not stopped
    }

    // A non-canonical RIP would fault on the return to user mode in ring
    // 0 (SYSRET with the user stack loaded): refused (EIO). Linux takes
    // it and returns through IRET, which delivers SIGSEGV.
    if regs.rip >= 0x0000_8000_0000_0000 {
        return Err(-5);
    }
    // Linux putreg: a base at or above TASK_SIZE_MAX is EIO
    if !super::percpu::fs_base_ok(regs.fs_base) || !super::percpu::fs_base_ok(regs.gs_base) {
        return Err(-5);
    }

    // Update its pt_regs with the new register values
    // SAFETY: as in get_user_regs
    let tf = unsafe { &mut *crate::task::percpu::task_pt_regs(task.task) };
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
    tf.rcx = regs.rcx;
    tf.rdx = regs.rdx;
    tf.rsi = regs.rsi;
    tf.rdi = regs.rdi;
    tf.rip = regs.rip;
    tf.rflags = sanitize_rflags(regs.eflags);
    tf.rsp = regs.rsp;

    task.task
        .tls
        .store(regs.fs_base, core::sync::atomic::Ordering::Relaxed);
    task.task
        .gsbase
        .store(regs.gs_base, core::sync::atomic::Ordering::Relaxed);

    Ok(())
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

/// Enable single-step mode for a task.
///
/// Sets the TF (Trap Flag) in RFLAGS so the CPU generates a debug exception
/// after executing one instruction.
pub fn enable_single_step(tid: Tid) {
    let table = TASKLIST.read();
    if let Some(task) = table.get(tid) {
        // SAFETY: as in get_user_regs
        unsafe { (*crate::task::percpu::task_pt_regs(task.task)).rflags |= RFLAGS_TF };
    }
}

/// Disable single-step mode for a task.
///
/// Clears the TF (Trap Flag) in RFLAGS.
pub fn disable_single_step(tid: Tid) {
    let table = TASKLIST.read();
    if let Some(task) = table.get(tid) {
        // SAFETY: as in get_user_regs
        unsafe { (*crate::task::percpu::task_pt_regs(task.task)).rflags &= !RFLAGS_TF };
    }
}
