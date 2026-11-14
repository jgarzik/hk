//! aarch64 ptrace support
//!
//! This module provides aarch64-specific register structures and functions
//! for ptrace operations.

use crate::task::Task;
use crate::task::ptrace::with_stopped_regs;
use crate::util::error::KernelResult;

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
crate::pod!(UserPtRegs {
    regs,
    sp,
    pc,
    pstate
});

/// The register block PTRACE_GETREGS / PTRACE_SETREGS copy
pub type UserRegs = UserPtRegs;

// =============================================================================
// Register access functions
// =============================================================================

/// All general-purpose registers of tracee `t`, from its pt_regs, held
/// in its ptrace stop ([`with_stopped_regs`]; ESRCH otherwise)
pub fn get_user_regs(t: &Task) -> KernelResult<UserPtRegs> {
    with_stopped_regs(t, |tf| UserPtRegs {
        regs: tf.x,
        sp: tf.sp,
        pc: tf.elr,
        pstate: tf.spsr,
    })
}

/// Set all general-purpose registers of tracee `t`, in its pt_regs,
/// held in its ptrace stop ([`with_stopped_regs`]; ESRCH otherwise), to
/// take effect when it resumes
pub fn set_user_regs(t: &Task, regs: &UserPtRegs) -> KernelResult<()> {
    with_stopped_regs(t, |tf| {
        tf.x = regs.regs;
        tf.sp = regs.sp;
        tf.elr = regs.pc;
        tf.spsr = sanitize_pstate(regs.pstate);
    })
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
///
/// Linux user_enable_single_step; the tracee held in its ptrace stop
/// ([`with_stopped_regs`]; ESRCH otherwise).
pub fn enable_single_step(t: &Task) -> KernelResult<()> {
    // The SS bit in SPSR, loaded into PSTATE on exception return
    // TODO: Also need to set MDSCR_EL1.SS globally or per-task
    // For now, assume debug is enabled system-wide
    with_stopped_regs(t, |tf| tf.spsr |= PSTATE_SS)
}

/// Disable single-step mode for a task: the SS bit in PSTATE cleared
/// (Linux user_disable_single_step), the tracee held in its ptrace stop
pub fn disable_single_step(t: &Task) -> KernelResult<()> {
    with_stopped_regs(t, |tf| tf.spsr &= !PSTATE_SS)
}
