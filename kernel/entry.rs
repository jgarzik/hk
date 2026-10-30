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
//! - TIF_RESTORE_SIGMASK: a syscall's temporary signal mask is still in
//!   place; `do_signal` puts the old one back;
//! - TIF_NOTIFY_RESUME: work queued for the return (none yet).
//!
//! So a task spinning in user mode still takes SIGKILL or a handler
//! (the next tick or a kick IPI interrupts it, and the interrupt returns
//! through here) and shares its CPU with others of its priority.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::{CpuOps, CurrentArch, PtRegs, UserRegs};
use crate::task::tif;

/// Work for the return to user mode (Linux EXIT_TO_USER_MODE_WORK)
const EXIT_WORK: u32 = tif::NEED_RESCHED | SIGNAL_WORK | tif::NOTIFY_RESUME;

/// Work `do_signal` handles
const SIGNAL_WORK: u32 = tif::SIGPENDING | tif::RESTORE_SIGMASK;

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
        if work & SIGNAL_WORK != 0 {
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
/// interrupts on: the syscall's signal work first (a signal, a temporary
/// mask to restore, or an -ERESTART* code to rewind even with no signal,
/// as Linux arch_do_signal_or_restart does), then the common work with
/// interrupts off. Returns with them off. The common case takes no
/// lock: only the thread flags and the result register are read.
pub fn syscall_exit_to_user_mode(regs: &mut PtRegs) {
    let me = crate::task::percpu::current();
    if me.has_tif(tif::SYSCALL_TRACE) {
        // The PTRACE_SYSCALL exit stop (Linux syscall_exit_work)
        crate::task::ptrace::ptrace_report_syscall(false);
    }
    if me.has_tif(SIGNAL_WORK) || crate::signal::syscall_restarting(regs) {
        crate::signal::do_signal(regs);
    } else {
        regs.forget_syscall();
    }
    CurrentArch::disable_interrupts();
    exit_to_user_mode(regs);
}

/// The syscall entry work (Linux syscall_enter_from_user_mode): a
/// PTRACE_SYSCALL entry stop, after which the tracer may have changed the
/// syscall number and arguments in `regs`. Returns the number to run;
/// u64::MAX (the tracer set it) skips the syscall, keeping the return
/// register as the tracer left it.
pub fn syscall_enter_from_user_mode(regs: &mut PtRegs) -> u64 {
    if crate::task::percpu::current().has_tif(tif::SYSCALL_TRACE) {
        crate::task::ptrace::ptrace_report_syscall(true);
    }
    regs.syscall_nr()
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
