//! The way back to user mode (Linux kernel/entry/common.c)
//!
//! Every return to user mode goes through [`exit_to_user_mode`], with
//! interrupts off and the task's user registers in its pt_regs: from a
//! syscall ([`syscall_exit_to_user_mode`]), from a fault or an interrupt
//! taken in user mode, a fork child's first return and a new program
//! image. While the task has work flagged (`Task.thread_flags`) it runs
//! it with interrupts on, then looks again with them off:
//! - TIF_NEED_RESCHED: the slice is used up (the tick) or a reschedule
//!   IPI arrived; the task yields (the kernel itself is not preemptive:
//!   this is the one place a task loses the CPU involuntarily);
//! - TIF_SIGPENDING: `signal::do_signal` delivers (or acts on) it;
//! - TIF_NOTIFY_RESUME: work queued for the return (none yet).
//!
//! So a task spinning in user mode still takes SIGKILL or a handler
//! (the next tick or a kick IPI interrupts it, and the interrupt returns
//! through here) and shares its CPU with others of its priority.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::{CpuOps, CurrentArch, PtRegs};
use crate::task::tif;

/// Work for the return to user mode (Linux EXIT_TO_USER_MODE_WORK)
const EXIT_WORK: u32 = tif::NEED_RESCHED | tif::SIGPENDING | tif::NOTIFY_RESUME;

/// Run the pending work of the return to user mode (Linux
/// exit_to_user_mode_prepare / exit_to_user_mode_loop). Interrupts are
/// off on entry and on return; `regs` is the current task's pt_regs.
pub fn exit_to_user_mode(regs: &mut PtRegs) {
    loop {
        let flags = &crate::task::percpu::current().thread_flags;
        let work = flags.load(Ordering::Acquire) & EXIT_WORK;
        if work == 0 {
            break;
        }
        CurrentArch::enable_interrupts();
        if work & tif::NEED_RESCHED != 0 {
            crate::task::percpu::preempt_schedule_user();
        }
        if work & tif::SIGPENDING != 0 {
            crate::signal::do_signal(regs);
        }
        if work & tif::NOTIFY_RESUME != 0 {
            crate::task::percpu::current().clear_tif(tif::NOTIFY_RESUME);
        }
        CurrentArch::disable_interrupts();
    }
    check_user_return();
}

/// The return from a syscall (Linux syscall_exit_to_user_mode), with
/// interrupts on: the syscall's signal work first, even with nothing
/// pending (an -ERESTART* code to apply, a temporary signal mask to
/// restore, `do_signal`), then the common work with interrupts off.
/// Returns with them off.
pub fn syscall_exit_to_user_mode(regs: &mut PtRegs) {
    crate::signal::do_signal(regs);
    CurrentArch::disable_interrupts();
    exit_to_user_mode(regs);
}

/// Nothing may be held on the way to user mode: no spin lock (each
/// raises the preempt count) or preemption disable. Reported once as
/// ENTRY:FAIL (the boot tests fail on it).
fn check_user_return() {
    let pc = crate::arch::preempt_count();
    if pc != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            crate::printkln!(
                "ENTRY:FAIL return to user mode with preempt count {} (tid {})",
                pc,
                crate::task::percpu::current_tid()
            );
        }
    }
}
