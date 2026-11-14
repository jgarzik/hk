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
        tf.spsr = reset_single_step(t, sanitize_pstate(regs.pstate));
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
// Single-step support (Linux arch/arm64/kernel/debug-monitors.c)
// =============================================================================

/// SPSR/PSTATE Software Step bit (Linux DBG_SPSR_SS): with MDSCR_EL1.SS
/// set, an ERET with it set runs one instruction (active-not-pending),
/// then a software step exception is taken; with it clear the exception
/// comes before any instruction (active-pending)
const SPSR_SS: u64 = 1 << 21;

/// MDSCR_EL1.SS: software step enabled (Linux MDSCR_EL1_SS)
const MDSCR_SS: u64 = 1 << 0;

/// MDSCR_EL1.TDCC: EL0 access to the debug comms channel traps (Linux
/// __cpu_setup's MDSCR_EL1 reset value)
const MDSCR_TDCC: u64 = 1 << 12;

fn mdscr_read() -> u64 {
    let v: u64;
    // SAFETY: reads a debug control register at EL1
    unsafe { core::arch::asm!("mrs {}, mdscr_el1", out(reg) v, options(nostack, nomem)) };
    v
}

fn mdscr_write(v: u64) {
    // SAFETY: writes a debug control register at EL1; with KDE clear no
    // debug exception is taken at EL1 whatever it holds
    unsafe { core::arch::asm!("msr mdscr_el1, {}", in(reg) v, options(nostack, nomem)) };
}

/// This CPU's debug state at boot (Linux __cpu_setup's MDSCR_EL1 reset,
/// debug-monitors.c clear_os_lock): no step, no EL1 debug exceptions,
/// and the OS lock (set at reset; it suppresses software step) open
pub fn debug_init_cpu() {
    mdscr_write(MDSCR_TDCC);
    // SAFETY: clears the OS double lock and the OS lock at EL1
    unsafe {
        core::arch::asm!(
            "msr osdlr_el1, xzr",
            "msr oslar_el1, xzr",
            "isb",
            options(nostack, nomem)
        )
    };
}

/// `t` is single-stepped (Linux TIF_SINGLESTEP)
fn stepping(t: &Task) -> bool {
    t.has_tif(crate::task::tif::SINGLESTEP)
}

/// Kernel entry from EL0 (Linux kernel_entry's disable_step_tsk): a
/// stepped task's MDSCR_EL1.SS goes off while the kernel runs, which
/// may unmask debug exceptions; [`exit_to_user`] sets it again
pub fn enter_from_user() {
    if stepping(&crate::task::percpu::current()) {
        mdscr_write(mdscr_read() & !MDSCR_SS);
        // SAFETY: a barrier
        unsafe { core::arch::asm!("isb", options(nostack, nomem)) };
    }
}

/// The last step back to EL0, interrupts masked (Linux ret_to_user's
/// enable_step_tsk): a stepped task's MDSCR_EL1.SS on
pub fn exit_to_user() {
    if stepping(&crate::task::percpu::current()) {
        mdscr_write(mdscr_read() | MDSCR_SS);
    }
}

/// The software step exception from EL0 (Linux do_el0_softstep): SIGTRAP
/// with TRAP_TRACE at the next instruction, then, for a stepped task,
/// the step rewound to active-not-pending (user_rewind_single_step)
pub fn el0_softstep(frame: &crate::arch::UserFrame) {
    use crate::signal::{SIGTRAP, TrapSet, si_code};
    let pc = frame.ip();
    crate::signal::force_sig_fault(SIGTRAP, si_code::TRAP_TRACE, pc, TrapSet::Keep, frame);
    if stepping(&crate::task::percpu::current()) {
        // SAFETY: a field store in the current task's own frame
        unsafe { frame.with(|f| f.spsr |= SPSR_SS) };
    }
}

/// SPSR.SS of registers a tracer sets follows the task's step state
/// (Linux user_regs_reset_single_step)
fn reset_single_step(t: &Task, spsr: u64) -> u64 {
    if stepping(t) {
        spsr | SPSR_SS
    } else {
        spsr & !SPSR_SS
    }
}

/// Single-step tracee `t` (Linux user_enable_single_step): TIF_SINGLESTEP
/// (MDSCR_EL1.SS on each return to EL0), and SPSR.SS if it was not
/// already stepping, so the next ERET runs one instruction; the tracee
/// held in its ptrace stop ([`with_stopped_regs`]; ESRCH otherwise)
pub fn enable_single_step(t: &Task) -> KernelResult<()> {
    with_stopped_regs(t, |tf| {
        if !stepping(t) {
            t.set_tif(crate::task::tif::SINGLESTEP);
            tf.spsr |= SPSR_SS;
        }
    })
}

/// Stop single-stepping tracee `t` (Linux user_disable_single_step):
/// TIF_SINGLESTEP cleared (SPSR.SS then does nothing), the tracee held
/// in its ptrace stop
pub fn disable_single_step(t: &Task) -> KernelResult<()> {
    with_stopped_regs(t, |_| t.clear_tif(crate::task::tif::SINGLESTEP))
}
