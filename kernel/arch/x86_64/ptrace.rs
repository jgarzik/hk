//! x86-64 ptrace support
//!
//! This module provides x86-64 specific register structures and functions
//! for ptrace operations.

use crate::task::Tid;
use crate::task::percpu::TASK_TABLE;

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
/// The tracee must be in Traced state. This reads from the task's saved
/// user context (percpu state from syscall entry or trap frame).
pub fn get_user_regs(tid: Tid) -> Result<UserRegsStruct, i32> {
    // For a stopped tracee, the registers are saved in percpu when it entered
    // the kernel (via syscall or trap). We need to find where they're stored.
    //
    // When a task is stopped for ptrace, its registers are in one of:
    // 1. The percpu syscall_user_* fields (if it stopped during a syscall)
    // 2. The trap frame on its kernel stack (if it stopped due to a trap/signal)
    //
    // For simplicity, we'll look at the percpu state for the current CPU
    // if the task is on it, otherwise we'll need to access saved state.

    // For now, we'll get registers from the task table's trap_frame
    // This is a simplified approach - full implementation would need to
    // handle the case where the task is stopped mid-syscall.

    let table = TASK_TABLE.lock();
    let task = table.tasks.iter().find(|t| t.tid == tid).ok_or(-3i32)?; // ESRCH

    // Check task is in traced state
    if !matches!(task.state, crate::task::TaskState::Traced(_)) {
        return Err(-3); // ESRCH - not stopped
    }

    // Get registers from trap frame
    // Note: The trap frame doesn't have all registers. For a full implementation,
    // we'd need to save more state on syscall entry.
    let tf = &task.trap_frame;

    // Build UserRegsStruct from what we have
    // Many values are 0 because trap_frame doesn't store them
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
        orig_rax: tf.rax, // We don't track orig_rax separately yet
        rip: tf.rip,
        cs: 0x33, // User code segment
        eflags: tf.rflags,
        rsp: tf.rsp,
        ss: 0x2b, // User stack segment
        fs_base: task.tls_base,
        gs_base: 0,
        ds: 0x2b,
        es: 0x2b,
        fs: 0,
        gs: 0,
    };

    Ok(regs)
}

/// Set all general-purpose registers for a stopped tracee.
///
/// The tracee must be in Traced state. This updates the task's saved
/// user context so the registers take effect when it resumes.
pub fn set_user_regs(tid: Tid, regs: &UserRegsStruct) -> Result<(), i32> {
    let mut table = TASK_TABLE.lock();
    let task = table.tasks.iter_mut().find(|t| t.tid == tid).ok_or(-3i32)?; // ESRCH

    // Check task is in traced state
    if !matches!(task.state, crate::task::TaskState::Traced(_)) {
        return Err(-3); // ESRCH - not stopped
    }

    // Update trap frame with new register values
    let tf = &mut task.trap_frame;
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

    // Update TLS base if changed
    if regs.fs_base != 0 {
        task.tls_base = regs.fs_base;
    }

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
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.trap_frame.rflags |= RFLAGS_TF;
    }
}

/// Disable single-step mode for a task.
///
/// Clears the TF (Trap Flag) in RFLAGS.
pub fn disable_single_step(tid: Tid) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.trap_frame.rflags &= !RFLAGS_TF;
    }
}
