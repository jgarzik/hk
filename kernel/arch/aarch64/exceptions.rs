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

/// Handle IRQ from EL1 (kernel mode)
#[unsafe(no_mangle)]
extern "C" fn handle_el1_irq(_frame: &mut Aarch64TrapFrame) {
    // Read interrupt ID from GIC
    let intid = super::gic::acknowledge_interrupt();

    match intid {
        0..=15 => {
            // SGI (Software Generated Interrupt) - used for IPIs
            // TODO: handle IPI for SMP
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
    set_user_frame(frame);

    match ec {
        EC_SVC64 => {
            // System call
            // Store user context for clone/fork before dispatch
            // Safety: we're in the syscall handler, single-threaded access to our per-CPU data
            // and TPIDR_EL1 has been set up during boot
            if super::percpu::try_current_cpu().is_some() {
                let percpu = unsafe { super::percpu::current_cpu_mut() };
                percpu.syscall_user_elr = frame.elr;
                percpu.syscall_user_spsr = frame.spsr;
                percpu.syscall_user_sp = frame.sp;
                // Save all GPRs for fork/clone (child needs to inherit parent's registers)
                percpu.syscall_user_regs = frame.x;
                percpu.syscall_orig_x0 = frame.x[0];
            }
            // Syscall number in x8, arguments in x0-x5, return value in x0
            let result = super::syscall::aarch64_syscall_dispatch(
                frame.x[8], // syscall number
                frame.x[0], // arg0
                frame.x[1], // arg1
                frame.x[2], // arg2
                frame.x[3], // arg3
                frame.x[4], // arg4
                frame.x[5], // arg5
            );
            frame.x[0] = result;

            // Update frame from percpu if signal delivery modified the context
            // This is needed because do_signal() modifies percpu, not the frame
            // Only update if the flag is set to avoid corrupting registers on normal syscalls
            if super::percpu::try_current_cpu().is_some() {
                let percpu = unsafe { super::percpu::current_cpu_mut() };
                if percpu.signal_context_modified {
                    percpu.signal_context_modified = false;
                    frame.elr = percpu.syscall_user_elr;
                    frame.spsr = percpu.syscall_user_spsr;
                    frame.sp = percpu.syscall_user_sp;
                    frame.x = percpu.syscall_user_regs;
                }
            }
        }
        EC_DABORT_LOWER => {
            let far: u64;
            unsafe {
                asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
            }

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
/// context in `frame`: a handler runs when this exception returns
fn user_fault(frame: &mut Aarch64TrapFrame, sig: u32, info: KSigInfo) {
    use super::percpu;

    super::cpu::enable_interrupts();
    let p = unsafe { percpu::current_cpu_mut() };
    p.syscall_user_elr = frame.elr;
    p.syscall_user_spsr = frame.spsr;
    p.syscall_user_sp = frame.sp;
    p.syscall_user_regs = frame.x;
    p.signal_context_modified = false;

    crate::signal::force_sig_fault(sig, info);

    let p = unsafe { percpu::current_cpu_mut() };
    if core::mem::take(&mut p.signal_context_modified) {
        frame.elr = p.syscall_user_elr;
        frame.spsr = p.syscall_user_spsr;
        frame.sp = p.syscall_user_sp;
        frame.x = p.syscall_user_regs;
    }
}

/// Record the trap frame of an entry from EL0 as the current task's user frame
fn set_user_frame(frame: &mut Aarch64TrapFrame) {
    if super::percpu::try_current_cpu().is_some() {
        unsafe { super::percpu::current_cpu_mut() }.user_frame = frame;
    }
}

/// Handle IRQ from EL0 (user mode)
#[unsafe(no_mangle)]
extern "C" fn handle_el0_irq(frame: &mut Aarch64TrapFrame) {
    set_user_frame(frame);
    // For now, handle same as EL1 IRQ
    handle_el1_irq(frame);
}

/// Map a user page, allocating intermediate page tables as needed
///
/// Used by mremap to move a page into place.
///
/// # Arguments
/// * `ttbr0` - Physical address of the L0 table (page table root)
/// * `vaddr` - Virtual address to map (page-aligned)
/// * `paddr` - Physical address to map to
/// * `attrs` - Page table entry attributes
pub fn map_user_page(ttbr0: u64, vaddr: u64, paddr: u64, attrs: u64) -> Result<(), ()> {
    let l0_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let l1_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let l3_idx = ((vaddr >> 12) & 0x1FF) as usize;

    // Table descriptor: bits [1:0] = 0b11
    const TABLE_DESC: u64 = 0b11;

    unsafe {
        let l0 = crate::arch::aarch64::paging::phys_to_virt(ttbr0) as *mut u64;

        // Get or create L1 table
        let l0_entry = *l0.add(l0_idx);
        let l1 = if (l0_entry & 0b11) == TABLE_DESC {
            crate::arch::aarch64::paging::phys_to_virt(l0_entry & 0x0000_FFFF_FFFF_F000) as *mut u64
        } else {
            let new_l1 = crate::FRAME_ALLOCATOR.alloc().ok_or(())?;
            core::ptr::write_bytes(crate::arch::aarch64::paging::phys_to_virt(new_l1), 0, 4096);
            *l0.add(l0_idx) = new_l1 | TABLE_DESC;
            crate::arch::aarch64::paging::phys_to_virt(new_l1) as *mut u64
        };

        // Get or create L2 table
        let l1_entry = *l1.add(l1_idx);
        let l2 = if (l1_entry & 0b11) == TABLE_DESC {
            crate::arch::aarch64::paging::phys_to_virt(l1_entry & 0x0000_FFFF_FFFF_F000) as *mut u64
        } else {
            let new_l2 = crate::FRAME_ALLOCATOR.alloc().ok_or(())?;
            core::ptr::write_bytes(crate::arch::aarch64::paging::phys_to_virt(new_l2), 0, 4096);
            *l1.add(l1_idx) = new_l2 | TABLE_DESC;
            crate::arch::aarch64::paging::phys_to_virt(new_l2) as *mut u64
        };

        // Get or create L3 table
        let l2_entry = *l2.add(l2_idx);
        let l3 = if (l2_entry & 0b11) == TABLE_DESC {
            crate::arch::aarch64::paging::phys_to_virt(l2_entry & 0x0000_FFFF_FFFF_F000) as *mut u64
        } else {
            let new_l3 = crate::FRAME_ALLOCATOR.alloc().ok_or(())?;
            core::ptr::write_bytes(crate::arch::aarch64::paging::phys_to_virt(new_l3), 0, 4096);
            *l2.add(l2_idx) = new_l3 | TABLE_DESC;
            crate::arch::aarch64::paging::phys_to_virt(new_l3) as *mut u64
        };

        // Set the L3 entry (page descriptor)
        *l3.add(l3_idx) = paddr | attrs;

        // Flush TLB for this address
        crate::arch::aarch64::paging::flush_tlb(vaddr);

        Ok(())
    }
}
