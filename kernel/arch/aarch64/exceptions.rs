//! AArch64 Exception Handling
//!
//! This module contains exception handlers for synchronous exceptions and IRQs.

use crate::printkln;
use crate::task::syscall::sys_exit;
use core::arch::asm;

use super::Aarch64TrapFrame;

// Linux signal numbers - exit status for signal death is 128 + signal
const EXIT_SIGILL: i32 = 128 + 4; // SIGILL = 4
const EXIT_SIGSEGV: i32 = 128 + 11; // SIGSEGV = 11

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
        }
        EC_DABORT_LOWER => {
            let far: u64;
            unsafe {
                asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
            }

            // Check Data Fault Status Code (ISS[5:0])
            let dfsc = iss & 0x3F;
            let is_write = (iss & (1 << 6)) != 0; // WnR bit

            // Translation fault = page not present (demand paging candidate)
            // DFSC 0x04-0x07 are translation faults at different levels
            let is_translation_fault = (0x04..=0x07).contains(&dfsc);

            if is_translation_fault {
                // Try to handle as mmap demand fault
                if let Some(true) = handle_mmap_fault(far, is_write) {
                    return; // Fault handled, resume execution
                }
            }

            // Unhandled fault - terminate process
            printkln!(
                "User data abort at ELR={:#x}, FAR={:#x}, ISS={:#x}",
                frame.elr,
                far,
                iss
            );
            sys_exit(EXIT_SIGSEGV);
        }
        EC_IABORT_LOWER => {
            let far: u64;
            unsafe {
                asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
            }
            printkln!(
                "User instruction abort at ELR={:#x}, FAR={:#x}, ISS={:#x}",
                frame.elr,
                far,
                iss
            );
            // Terminate the process (sys_exit never returns)
            sys_exit(EXIT_SIGSEGV);
        }
        _ => {
            // Unknown/unhandled exception from userland - terminate the process
            // rather than panicking the kernel. This could be an illegal instruction,
            // alignment fault, or other unrecognized exception class.
            printkln!(
                "Unhandled EL0 sync exception: EC={:#x}, ISS={:#x}, ELR={:#x} - terminating process",
                ec,
                iss,
                frame.elr
            );
            sys_exit(EXIT_SIGILL);
        }
    }
}

/// Handle IRQ from EL0 (user mode)
#[unsafe(no_mangle)]
extern "C" fn handle_el0_irq(frame: &mut Aarch64TrapFrame) {
    // For now, handle same as EL1 IRQ
    handle_el1_irq(frame);
}

/// Handle a page fault for an mmap'd region (demand paging)
///
/// Returns:
/// - Some(true) if the fault was handled successfully
/// - Some(false) if the fault was recognized but handling failed (e.g., OOM)
/// - None if the address is not in any VMA
fn handle_mmap_fault(fault_addr: u64, is_write: bool) -> Option<bool> {
    use crate::arch::aarch64::paging::{
        AF, AP_EL0_RO, AP_EL0_RW, ATTR_IDX_NORMAL, PAGE_SIZE, PXN, SH_INNER, UXN,
    };
    use crate::mm::{PROT_EXEC, PROT_WRITE, get_task_mm};
    use crate::task::percpu::current_tid;

    // Get current task's mm
    let tid = current_tid();
    let mm = get_task_mm(tid)?;

    // Lock mm and find VMA
    let mut mm_guard = mm.lock();
    let vma = match mm_guard.find_vma(fault_addr) {
        Some(vma) => vma,
        None => {
            // No VMA found - try stack expansion for VM_GROWSDOWN VMAs
            // Linux: mm/memory.c expand_stack() called from __do_page_fault()
            if let Some(vma_idx) = mm_guard.find_expandable_vma(fault_addr) {
                if mm_guard.expand_downwards(vma_idx, fault_addr).is_err() {
                    return Some(false); // Expansion failed
                }
                // Re-lookup the VMA after expansion
                mm_guard.find_vma(fault_addr)?
            } else {
                return None; // No VMA and no expandable VMA
            }
        }
    };

    // Check permissions
    if is_write && !vma.is_writable() {
        return Some(false); // Write to read-only region
    }

    // Clone VMA info we need (release lock before allocating)
    let vma_prot = vma.prot;
    let vma_is_anonymous = vma.is_anonymous();
    let vma_file = vma.file.clone();
    let vma_start = vma.start;
    let vma_offset = vma.offset;
    drop(mm_guard);

    // Allocate a physical frame
    let frame = match crate::FRAME_ALLOCATOR.alloc() {
        Some(f) => f,
        None => return Some(false), // OOM
    };

    // Initialize the page contents
    if vma_is_anonymous {
        // Anonymous mapping - zero the page
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }
    } else if let Some(file) = vma_file {
        // File-backed mapping - read file contents into the page
        // Calculate file offset for this page
        let page_addr = fault_addr & !0xFFF;
        let file_offset = vma_offset + (page_addr - vma_start);

        // First zero the frame in case the read is partial (e.g., at EOF)
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }

        // Read from file into the frame
        // Note: We read directly into the physical frame since it's identity-mapped
        // in the kernel's address space for low physical addresses
        let buf = unsafe { core::slice::from_raw_parts_mut(frame as *mut u8, PAGE_SIZE as usize) };
        let _read_result = file.pread(buf, file_offset);
        // If read fails or returns less than PAGE_SIZE, the remaining bytes are already zeroed
        // This matches Linux behavior for holes/errors
    } else {
        // File-backed but no file reference (shouldn't happen) - zero it
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }
    }

    // Build page table entry attributes
    // L3 page descriptor: [1:0] = 0b11
    let mut attrs: u64 = 0b11 | AF | SH_INNER | ATTR_IDX_NORMAL;
    if vma_prot & PROT_WRITE != 0 {
        attrs |= AP_EL0_RW;
    } else {
        attrs |= AP_EL0_RO;
    }
    if vma_prot & PROT_EXEC == 0 {
        attrs |= PXN | UXN;
    }

    // Get current page table (TTBR0_EL1 for user space)
    let ttbr0: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack, nomem));
    }
    let pt_root = ttbr0 & !0xFFF;

    // Map the page
    let page_addr = fault_addr & !0xFFF;
    if map_user_page(pt_root, page_addr, frame, attrs).is_err() {
        // Mapping failed, free the frame
        crate::FRAME_ALLOCATOR.free(frame);
        return Some(false);
    }
    // TLB is flushed by map_user_page

    Some(true)
}

/// Map a user page, allocating intermediate page tables as needed
///
/// This function is used by demand paging and shmat to map physical frames
/// into a user process's address space.
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
        let l0 = ttbr0 as *mut u64;

        // Get or create L1 table
        let l0_entry = *l0.add(l0_idx);
        let l1 = if (l0_entry & 0b11) == TABLE_DESC {
            (l0_entry & 0x0000_FFFF_FFFF_F000) as *mut u64
        } else {
            let new_l1 = crate::FRAME_ALLOCATOR.alloc().ok_or(())?;
            core::ptr::write_bytes(new_l1 as *mut u8, 0, 4096);
            *l0.add(l0_idx) = new_l1 | TABLE_DESC;
            new_l1 as *mut u64
        };

        // Get or create L2 table
        let l1_entry = *l1.add(l1_idx);
        let l2 = if (l1_entry & 0b11) == TABLE_DESC {
            (l1_entry & 0x0000_FFFF_FFFF_F000) as *mut u64
        } else {
            let new_l2 = crate::FRAME_ALLOCATOR.alloc().ok_or(())?;
            core::ptr::write_bytes(new_l2 as *mut u8, 0, 4096);
            *l1.add(l1_idx) = new_l2 | TABLE_DESC;
            new_l2 as *mut u64
        };

        // Get or create L3 table
        let l2_entry = *l2.add(l2_idx);
        let l3 = if (l2_entry & 0b11) == TABLE_DESC {
            (l2_entry & 0x0000_FFFF_FFFF_F000) as *mut u64
        } else {
            let new_l3 = crate::FRAME_ALLOCATOR.alloc().ok_or(())?;
            core::ptr::write_bytes(new_l3 as *mut u8, 0, 4096);
            *l2.add(l2_idx) = new_l3 | TABLE_DESC;
            new_l3 as *mut u64
        };

        // Set the L3 entry (page descriptor)
        *l3.add(l3_idx) = paddr | attrs;

        // Flush TLB for this address
        crate::arch::aarch64::paging::flush_tlb(vaddr);

        Ok(())
    }
}

/// Unmap a user page
///
/// Clears the page table entry for the given virtual address and flushes the TLB.
/// Returns the physical address that was mapped, or None if not mapped.
///
/// # Arguments
/// * `ttbr0` - Physical address of the L0 table (page table root)
/// * `vaddr` - Virtual address to unmap (page-aligned)
pub fn unmap_user_page(ttbr0: u64, vaddr: u64) -> Option<u64> {
    let l0_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let l1_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let l3_idx = ((vaddr >> 12) & 0x1FF) as usize;

    // Table descriptor: bits [1:0] = 0b11
    const TABLE_DESC: u64 = 0b11;
    // Page descriptor: bits [1:0] = 0b11 for valid page
    const PAGE_VALID: u64 = 0b11;

    unsafe {
        // L0
        let l0 = ttbr0 as *const u64;
        let l0_entry = *l0.add(l0_idx);
        if (l0_entry & 0b11) != TABLE_DESC {
            return None;
        }

        // L1
        let l1 = (l0_entry & 0x0000_FFFF_FFFF_F000) as *const u64;
        let l1_entry = *l1.add(l1_idx);
        if (l1_entry & 0b11) != TABLE_DESC {
            return None;
        }

        // L2
        let l2 = (l1_entry & 0x0000_FFFF_FFFF_F000) as *const u64;
        let l2_entry = *l2.add(l2_idx);
        if (l2_entry & 0b11) != TABLE_DESC {
            return None;
        }

        // L3
        let l3 = (l2_entry & 0x0000_FFFF_FFFF_F000) as *mut u64;
        let l3_ptr = l3.add(l3_idx);
        let l3_entry = *l3_ptr;

        if (l3_entry & PAGE_VALID) != PAGE_VALID {
            return None;
        }

        // Get physical address before clearing
        let phys = l3_entry & 0x0000_FFFF_FFFF_F000;

        // Clear the entry
        *l3_ptr = 0;

        // Flush TLB for this address
        crate::arch::aarch64::paging::flush_tlb(vaddr);

        Some(phys)
    }
}
