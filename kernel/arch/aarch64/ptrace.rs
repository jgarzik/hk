//! aarch64 ptrace support
//!
//! This module provides aarch64-specific register structures and functions
//! for ptrace operations.

use crate::task::Tid;
use crate::task::percpu::TASK_TABLE;

// =============================================================================
// User register structure (matches Linux struct user_pt_regs)
// =============================================================================

/// aarch64 user_pt_regs (matches Linux layout)
///
/// This is the structure returned by PTRACE_GETREGS and set by PTRACE_SETREGS.
/// On aarch64, Linux uses PTRACE_GETREGSET with NT_PRSTATUS rather than
/// PTRACE_GETREGS, but we support GETREGS for compatibility.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserPtRegs {
    /// General purpose registers x0-x30
    pub regs: [u64; 31],
    /// Stack pointer (SP_EL0)
    pub sp: u64,
    /// Program counter (ELR_EL1)
    pub pc: u64,
    /// Processor state (SPSR_EL1)
    pub pstate: u64,
}

// =============================================================================
// Register access functions
// =============================================================================

/// Get all general-purpose registers from a stopped tracee.
///
/// The tracee must be in Traced state. This reads from the task's saved
/// user context (percpu state from syscall entry or trap frame).
pub fn get_user_regs(tid: Tid) -> Result<UserPtRegs, i32> {
    let table = TASK_TABLE.lock();
    let task = table.tasks.iter().find(|t| t.tid == tid).ok_or(-3i32)?; // ESRCH

    // Check task is in traced state
    if !matches!(task.state, crate::task::TaskState::Traced(_)) {
        return Err(-3); // ESRCH - not stopped
    }

    // Get registers from trap frame
    let tf = &task.trap_frame;

    let regs = UserPtRegs {
        regs: tf.x,
        sp: tf.sp,
        pc: tf.elr,
        pstate: tf.spsr,
    };

    Ok(regs)
}

/// Set all general-purpose registers for a stopped tracee.
///
/// The tracee must be in Traced state. This updates the task's saved
/// user context so the registers take effect when it resumes.
pub fn set_user_regs(tid: Tid, regs: &UserPtRegs) -> Result<(), i32> {
    let mut table = TASK_TABLE.lock();
    let task = table.tasks.iter_mut().find(|t| t.tid == tid).ok_or(-3i32)?; // ESRCH

    // Check task is in traced state
    if !matches!(task.state, crate::task::TaskState::Traced(_)) {
        return Err(-3); // ESRCH - not stopped
    }

    // Update trap frame with new register values
    let tf = &mut task.trap_frame;
    tf.x = regs.regs;
    tf.sp = regs.sp;
    tf.elr = regs.pc;
    tf.spsr = sanitize_pstate(regs.pstate);

    Ok(())
}

/// Sanitize PSTATE to prevent setting dangerous bits.
///
/// Only allow user-modifiable flags: NZCV.
/// Clear everything else to ensure EL0 execution mode.
fn sanitize_pstate(pstate: u64) -> u64 {
    const NZCV_MASK: u64 = 0xF0000000; // N, Z, C, V flags
    const EL0_MODE: u64 = 0; // EL0t mode

    // Keep only NZCV flags, force EL0 mode
    (pstate & NZCV_MASK) | EL0_MODE
}

// =============================================================================
// Single-step support
// =============================================================================

/// PSTATE Software Step bit (SS)
/// When set along with MDSCR_EL1.SS, single-step is enabled
const PSTATE_SS: u64 = 1 << 21;

/// Enable single-step mode for a task.
///
/// On aarch64, single-step requires:
/// 1. Set PSTATE.SS = 1
/// 2. Set MDSCR_EL1.SS = 1 (handled by kernel debug setup)
///
/// The CPU will generate a software step exception after one instruction.
pub fn enable_single_step(tid: Tid) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        // Set SS bit in SPSR (will be loaded into PSTATE on exception return)
        task.trap_frame.spsr |= PSTATE_SS;
    }

    // TODO: Also need to set MDSCR_EL1.SS globally or per-task
    // For now, assume debug is enabled system-wide
}

/// Disable single-step mode for a task.
///
/// Clears the SS bit in PSTATE.
pub fn disable_single_step(tid: Tid) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.trap_frame.spsr &= !PSTATE_SS;
    }
}
