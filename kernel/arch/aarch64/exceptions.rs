//! AArch64 Exception Handling
//!
//! This module contains exception handlers for synchronous exceptions and IRQs.

use crate::printkln;
use core::arch::asm;

use super::Aarch64TrapFrame;
use crate::mm::fault::{Access, VmFault};
use crate::signal::{KSigInfo, si_code};

// Exception classes (ESR_EL1[31:26])
const EC_UNKNOWN: u64 = 0x00;
const EC_SVC64: u64 = 0x15; // SVC from AArch64
const EC_IABORT_LOWER: u64 = 0x20; // Instruction abort from lower EL
const EC_IABORT_SAME: u64 = 0x21; // Instruction abort from same EL
const EC_PC_ALIGN: u64 = 0x22; // PC alignment fault
const EC_DABORT_LOWER: u64 = 0x24; // Data abort from lower EL
const EC_DABORT_SAME: u64 = 0x25; // Data abort from same EL
const EC_SP_ALIGN: u64 = 0x26; // SP alignment fault
const EC_BRK: u64 = 0x3C; // BRK instruction

// Exception vector table symbol (defined in vectors.S)
unsafe extern "C" {
    static exception_vectors: u8;
}

/// Initialize exception handling
///
/// Installs the exception vector table by writing its address to VBAR_EL1.
pub fn init() {
    unsafe {
        let vbar = &exception_vectors as *const u8 as u64;
        asm!(
            "msr vbar_el1, {0}",
            "isb",
            in(reg) vbar,
            options(nostack, preserves_flags)
        );
    }
    printkln!("Exception vectors installed at {:#x}", unsafe {
        &exception_vectors as *const u8 as u64
    });
}

/// Handle synchronous exception from EL1 (kernel mode)
#[unsafe(no_mangle)]
extern "C" fn handle_el1_sync(frame: &mut Aarch64TrapFrame, esr: u64) {
    let ec = (esr >> 26) & 0x3F; // Exception class
    let iss = esr & 0x1FFFFFF; // Instruction specific syndrome

    match ec {
        EC_DABORT_SAME => {
            // Data abort in kernel - read FAR_EL1 for fault address
            let far: u64;
            unsafe {
                asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
            }

            // Kernel access to a user address (copy_to_user etc.): resolved
            // like a user access (Linux: do_page_fault handles EL1 faults
            // on TTBR0 addresses), unless page faults are disabled (a
            // spinlock is held)
            if far >> 48 == 0 {
                // FAR is read: IRQs back on if the faulting context had
                // them (SPSR.I clear; Linux el1_abort), so a fault that
                // sleeps does not hold them off
                if frame.spsr & (1 << 7) == 0 {
                    super::cpu::enable_interrupts();
                }
                let resolve = !crate::uaccess::pagefault_disabled();
                if resolve && fault_access(iss, false).is_some_and(|a| mm_fault(far, a).is_ok()) {
                    return;
                }
                // Unresolvable fault inside a user-copy routine: resume at its
                // fixup, which reports the uncopied bytes (-> EFAULT)
                if let Some(fixup) = super::uaccess::uaccess_fixup(frame.elr) {
                    frame.elr = fixup;
                    return;
                }
            }

            panic!(
                "Kernel data abort at ELR={:#x}, FAR={:#x}, ISS={:#x}",
                frame.elr, far, iss
            );
        }
        EC_IABORT_SAME => {
            let far: u64;
            unsafe {
                asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
            }
            panic!(
                "Kernel instruction abort at ELR={:#x}, FAR={:#x}, ISS={:#x}",
                frame.elr, far, iss
            );
        }
        EC_SP_ALIGN | EC_PC_ALIGN => {
            panic!("Alignment fault at ELR={:#x}, EC={:#x}", frame.elr, ec);
        }
        EC_BRK => {
            panic!("BRK instruction at ELR={:#x}", frame.elr);
        }
        EC_UNKNOWN => {
            panic!("Unknown exception at ELR={:#x}, ESR={:#x}", frame.elr, esr);
        }
        _ => {
            panic!(
                "Unhandled EL1 sync exception: EC={:#x}, ISS={:#x}, ELR={:#x}",
                ec, iss, frame.elr
            );
        }
    }
}

/// A kernel stack overflowed (vectors.S `el1_stack_overflow`, on this
/// CPU's overflow stack): `sp` is where the exception frame would have
/// gone (Linux handle_bad_stack)
#[unsafe(no_mangle)]
extern "C" fn handle_stack_overflow(sp: u64, elr: u64, far: u64) -> ! {
    panic!(
        "kernel stack overflow: SP={:#x} ELR={:#x} FAR={:#x} (tid {})",
        sp,
        elr,
        far,
        crate::task::percpu::current_tid()
    );
}

/// Handle IRQ from EL1 (kernel mode)
#[unsafe(no_mangle)]
extern "C" fn handle_el1_irq(_frame: &mut Aarch64TrapFrame) {
    // In an interrupt handler from here to the end (in_atomic(), the
    // signal-context check)
    let depth = super::percpu::try_current_cpu().map(|p| &p.interrupt_depth);
    if let Some(d) = depth {
        d.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    irq_dispatch();
    if let Some(d) = depth {
        d.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Acknowledge, handle and end one interrupt
fn irq_dispatch() {
    // Read interrupt ID from GIC
    let intid = super::gic::acknowledge_interrupt();

    match intid {
        0..=15 => {
            // SGI (Software Generated Interrupt): IPIs
            super::ipi::handle_sgi(intid);
        }
        16..=31 => {
            // PPI (Private Peripheral Interrupt) - per-CPU interrupts
            if intid == 30 {
                // Physical timer interrupt (PPI 30)
                super::timer::handle_timer_irq();
            }
        }
        32..=1019 => {
            // SPI (Shared Peripheral Interrupt) - dispatch to registered handlers
            if !super::irq::dispatch_irq(intid) {
                printkln!("Unhandled SPI: {}", intid);
            }
        }
        1020..=1023 => {
            // Spurious interrupt - ignore
        }
        _ => {
            printkln!("Invalid interrupt ID: {}", intid);
        }
    }

    // Signal end of interrupt
    if intid < 1020 {
        super::gic::end_interrupt(intid);
    }
}

/// Handle synchronous exception from EL0 (user mode)
#[unsafe(no_mangle)]
extern "C" fn handle_el0_sync(frame: &mut Aarch64TrapFrame, esr: u64) {
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0x1FFFFFF;
    // Not a syscall frame unless it is one (Linux el0t_64_sync)
    frame.syscallno = super::NO_SYSCALL;

    match ec {
        EC_SVC64 => {
            // System call: its number and first argument, for the
            // restart (Linux el0_svc_common)
            frame.orig_x0 = frame.x[0];
            frame.syscallno = frame.x[8];
            // The user state is saved: run the syscall with IRQs
            // unmasked (Linux el0_svc). The kernel is not preemptive, so
            // an interrupt never switches tasks here (doc/LOCKING.md 7)
            super::cpu::enable_interrupts();
            // A PTRACE_SYSCALL entry stop may change the number
            // (NO_SYSCALL skips it) and the arguments
            let nr = crate::entry::syscall_enter_from_user_mode(frame);
            if nr != super::NO_SYSCALL {
                // Syscall number in x8, arguments in x0-x5, return value
                // in x0
                frame.x[0] = super::syscall::aarch64_syscall_dispatch(
                    nr, frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
                );
            }
            // Signals, -ERESTART* rules, rescheduling before returning to
            // user space (they may redirect the frame to a handler or
            // back up over the svc; rt_sigreturn restored a whole user
            // context and forgot the syscall); IRQs masked after
            crate::entry::syscall_exit_to_user_mode(frame);
            return;
        }
        EC_DABORT_LOWER => {
            let far: u64;
            unsafe {
                asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
            }

            // FAR is read: IRQs on for the fault (Linux el0_da)
            super::cpu::enable_interrupts();
            // A kernel (TTBR1) address is never resolved: its table
            // indices would alias a user address in TTBR0
            let res = match fault_access(iss, false) {
                Some(a) if far < super::paging::TASK_SIZE => mm_fault(far, a),
                _ => Err(VmFault::Segv),
            };
            if res.is_err() {
                user_abort(frame, esr, far, iss & 0x3F, res);
            }
        }
        EC_IABORT_LOWER => {
            let far: u64;
            unsafe {
                asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
            }
            super::cpu::enable_interrupts();
            let res = match fault_access(iss, true) {
                Some(a) if far < super::paging::TASK_SIZE => mm_fault(far, a),
                _ => Err(VmFault::Segv),
            };
            if res.is_err() {
                user_abort(frame, esr, far, iss & 0x3F, res);
            }
        }
        EC_BRK => {
            // brk #imm: PC still points at it
            let info = KSigInfo {
                code: si_code::TRAP_BRKPT,
                addr: frame.elr,
                ..Default::default()
            };
            user_fault(frame, crate::signal::SIGTRAP, info);
        }
        EC_PC_ALIGN | EC_SP_ALIGN => {
            let addr = if ec == EC_SP_ALIGN {
                frame.sp
            } else {
                frame.elr
            };
            let info = KSigInfo {
                code: si_code::BUS_ADRALN,
                addr,
                ..Default::default()
            };
            user_fault(frame, crate::signal::SIGBUS, info);
        }
        _ => {
            // Undefined instruction (EC 0, e.g. udf) or any other
            // unhandled exception from userland: SIGILL at the PC
            printkln!(
                "Unhandled EL0 sync exception: EC={:#x}, ISS={:#x}, ELR={:#x}",
                ec,
                iss,
                frame.elr
            );
            let info = KSigInfo {
                code: si_code::ILL_ILLOPC,
                addr: frame.elr,
                ..Default::default()
            };
            user_fault(frame, crate::signal::SIGILL, info);
        }
    }
    // Back to user mode: its pending work first (Linux
    // exit_to_user_mode); the syscall returned above
    super::cpu::disable_interrupts();
    crate::entry::exit_to_user_mode(frame);
}

/// The access of a data or instruction abort to resolve (Linux
/// do_translation_fault / do_page_fault): a translation fault, or a
/// permission fault on a write (copy-on-write); None for faults the mm
/// cannot resolve (alignment, access flag, read permission, ...)
fn fault_access(iss: u64, insn: bool) -> Option<Access> {
    let dfsc = iss & 0x3F;
    let write = !insn && iss & (1 << 6) != 0; // WnR
    let access = match (insn, write) {
        (true, _) => Access::Exec,
        (false, true) => Access::Write,
        (false, false) => Access::Read,
    };
    match dfsc {
        0x04..=0x07 => Some(access),
        0x0C..=0x0F if write => Some(access),
        _ => None,
    }
}

/// Resolve a fault on the user address `far` in the current address space
fn mm_fault(far: u64, access: Access) -> Result<(), VmFault> {
    let mm = crate::mm::get_task_mm(crate::task::percpu::current_tid()).ok_or(VmFault::Segv)?;
    crate::mm::fault::handle_mm_fault(&mm, far, access)
}

/// Unresolvable data/instruction abort from EL0 at `far` (Linux
/// do_page_fault/do_alignment_fault): SIGSEGV for translation, access-flag
/// and permission faults, SIGBUS for a mapping without a page there,
/// alignment and other aborts; out of memory kills the process
fn user_abort(
    frame: &mut Aarch64TrapFrame,
    esr: u64,
    far: u64,
    fsc: u64,
    res: Result<(), VmFault>,
) {
    use crate::signal::{SIGBUS, SIGSEGV};

    if res == Err(VmFault::Oom) {
        super::cpu::enable_interrupts();
        crate::mm::fault::pagefault_out_of_memory();
    }
    let (sig, code) = match fsc {
        _ if res == Err(VmFault::Bus) => (SIGBUS, si_code::BUS_ADRERR),
        0x04..=0x0F => (SIGSEGV, crate::signal::segv_code(far)),
        0x21 => (SIGBUS, si_code::BUS_ADRALN),
        _ => (SIGBUS, si_code::BUS_ADRERR),
    };
    printkln!(
        "User abort at ELR={:#x}, FAR={:#x}, ESR={:#x} -> signal {}",
        frame.elr,
        far,
        esr,
        sig
    );
    let info = KSigInfo {
        code,
        addr: far,
        trapno: 0,
        error: esr,
    };
    user_fault(frame, sig, info);
}

/// Deliver a synchronous fault signal (force_sig_fault) for the user
/// context in `frame`, the task's pt_regs: a handler runs when this
/// exception returns
fn user_fault(frame: &mut Aarch64TrapFrame, sig: u32, info: KSigInfo) {
    super::cpu::enable_interrupts();
    crate::signal::force_sig_fault(sig, info, frame);
}

/// Handle IRQ from EL0 (user mode)
#[unsafe(no_mangle)]
extern "C" fn handle_el0_irq(frame: &mut Aarch64TrapFrame) {
    frame.syscallno = super::NO_SYSCALL;
    handle_el1_irq(frame);
    // Back to user mode: its pending work first (Linux
    // irqentry_exit_to_user_mode)
    crate::entry::exit_to_user_mode(frame);
}
