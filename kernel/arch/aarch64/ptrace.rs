//! aarch64 ptrace support
//!
//! This module provides aarch64-specific register structures and functions
//! for ptrace operations.

use crate::task::Tid;
use crate::task::percpu::TASKLIST;

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
/// The tracee must be in Traced state. This reads its user registers
/// from its pt_regs (the entry frame at the top of its kernel stack).
pub fn get_user_regs(tid: Tid) -> Result<UserPtRegs, i32> {
    let table = TASKLIST.read();
    let task = table.get(tid).ok_or(-3i32)?; // ESRCH

    // Check task is in traced state
    if !matches!(task.state, crate::task::TaskState::Traced(_)) {
        return Err(-3); // ESRCH - not stopped
    }

    // Its pt_regs: the frame at the top of its kernel stack
    // SAFETY: the tracee is stopped (TASKLIST held): its frame is stable
    let tf = unsafe { &*crate::task::percpu::task_pt_regs(task.task) };

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
/// The tracee must be in Traced state. This updates its pt_regs so the
/// registers take effect when it resumes.
pub fn set_user_regs(tid: Tid, regs: &UserPtRegs) -> Result<(), i32> {
    let table = TASKLIST.read();
    let task = table.get(tid).ok_or(-3i32)?; // ESRCH

    // Check task is in traced state
    if !matches!(task.state, crate::task::TaskState::Traced(_)) {
        return Err(-3); // ESRCH - not stopped
    }

    // Update its pt_regs with the new register values
    // SAFETY: as in get_user_regs
    let tf = unsafe { &mut *crate::task::percpu::task_pt_regs(task.task) };
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
    let table = TASKLIST.read();
    if let Some(task) = table.get(tid) {
        // Set SS bit in SPSR (will be loaded into PSTATE on exception return)
        // SAFETY: as in get_user_regs
        unsafe { (*crate::task::percpu::task_pt_regs(task.task)).spsr |= PSTATE_SS };
    }

    // TODO: Also need to set MDSCR_EL1.SS globally or per-task
    // For now, assume debug is enabled system-wide
}

/// Disable single-step mode for a task.
///
/// Clears the SS bit in PSTATE.
pub fn disable_single_step(tid: Tid) {
    let table = TASKLIST.read();
    if let Some(task) = table.get(tid) {
        // SAFETY: as in get_user_regs
        unsafe { (*crate::task::percpu::task_pt_regs(task.task)).spsr &= !PSTATE_SS };
    }
}
