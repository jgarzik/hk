//! AArch64 Exception Handling
//!
//! This module contains exception handlers for synchronous exceptions and IRQs.

use crate::printkln;
use core::arch::asm;

use super::Aarch64TrapFrame;

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

            // Check Data Fault Status Code (ISS[5:0])
            let dfsc = iss & 0x3F;
            let is_write = (iss & (1 << 6)) != 0; // WnR bit

            // Translation fault = page not present (demand paging candidate)
            // DFSC 0x04-0x07 are translation faults at different levels
            let is_translation_fault = (0x04..=0x07).contains(&dfsc);

            // Permission fault = page present but access denied (COW candidate)
            // DFSC 0x0C-0x0F are permission faults at different levels
            let is_permission_fault = (0x0C..=0x0F).contains(&dfsc);

            if is_translation_fault {
                // Try to handle as swap fault first (swapped-out page with swap entry in PTE)
                if let Some(true) = handle_swap_fault(far) {
                    return; // Swap-in successful, resume execution
                }

                // Try to handle as mmap demand fault
                if let Some(true) = handle_mmap_fault(far, is_write) {
                    return; // Fault handled, resume execution
                }
            }

            // COW handling: permission fault on write to a COW-marked page
            if is_permission_fault
                && is_write
                && let Some(true) = handle_cow_fault(far)
            {
                return; // COW resolved, resume execution
            }
            // If handle_cow_fault returns None, it's not a COW page
            // If it returns Some(false), COW resolution failed (OOM)
            // In both cases, fall through to SIGSEGV

            // Unhandled fault - send signal to process
            printkln!(
                "User data abort at ELR={:#x}, FAR={:#x}, ISS={:#x}",
                frame.elr,
                far,
                iss
            );

            // Send SIGSEGV or SIGBUS depending on fault type
            // Access flag fault (DFSC 0x08-0x0B) suggests hardware error -> SIGBUS
            let is_bus_error = (0x08..=0x0B).contains(&dfsc);
            let sig = if is_bus_error {
                crate::signal::SIGBUS
            } else {
                crate::signal::SIGSEGV
            };

            let tid = crate::task::percpu::current_tid();
            crate::signal::send_signal(tid, sig);
            // Return to user - signal will be delivered on next syscall exit
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

            // Send SIGSEGV for instruction abort
            let tid = crate::task::percpu::current_tid();
            crate::signal::send_signal(tid, crate::signal::SIGSEGV);
            // Return to user - signal will be delivered on next syscall exit
        }
        _ => {
            // Unknown/unhandled exception from userland - send signal instead of terminating.
            // This could be an illegal instruction, alignment fault, or other exception.
            printkln!(
                "Unhandled EL0 sync exception: EC={:#x}, ISS={:#x}, ELR={:#x}",
                ec,
                iss,
                frame.elr
            );

            // Send SIGILL for unknown exceptions (likely illegal instruction)
            let tid = crate::task::percpu::current_tid();
            crate::signal::send_signal(tid, crate::signal::SIGILL);
            // Return to user - signal will be delivered on next syscall exit
        }
    }
}

/// Handle IRQ from EL0 (user mode)
#[unsafe(no_mangle)]
extern "C" fn handle_el0_irq(frame: &mut Aarch64TrapFrame) {
    // For now, handle same as EL1 IRQ
    handle_el1_irq(frame);
}

/// Try to allocate and map a 2MB huge page for a THP-eligible VMA
///
/// Returns:
/// - Some(true) if a huge page was successfully allocated and mapped
/// - Some(false) if allocation/mapping failed
/// - None if THP is not applicable (fall through to 4KB allocation)
fn try_huge_page_fault(
    pt_root: u64,
    fault_addr: u64,
    vma_start: u64,
    vma_end: u64,
    vma_prot: u32,
    anon_vma: Option<&alloc::sync::Arc<crate::mm::anon_vma::AnonVma>>,
) -> Option<bool> {
    use crate::arch::PageFlags;
    use crate::arch::aarch64::paging::Aarch64PageTable;
    use crate::mm::huge_page::{HUGE_PAGE_SIZE, huge_page_align_down};
    use crate::mm::{PROT_EXEC, PROT_WRITE};

    // Calculate the 2MB-aligned region containing this fault
    let huge_base = huge_page_align_down(fault_addr);
    let huge_end = huge_base + HUGE_PAGE_SIZE;

    // VMA must fully contain the 2MB region
    if vma_start > huge_base || vma_end < huge_end {
        return None; // Fall back to 4KB
    }

    // Try to allocate a contiguous 2MB physical region
    // Falls back to 4KB allocation if no contiguous memory available
    let huge_frame = crate::FRAME_ALLOCATOR.alloc_huge()?;

    // Zero the 2MB region
    unsafe {
        core::ptr::write_bytes(huge_frame as *mut u8, 0, HUGE_PAGE_SIZE as usize);
    }

    // Build page flags from VMA protection
    let mut flags = PageFlags::READ | PageFlags::USER;
    if vma_prot & PROT_WRITE != 0 {
        flags |= PageFlags::WRITE;
    }
    if vma_prot & PROT_EXEC != 0 {
        flags |= PageFlags::EXECUTE;
    }

    // Map the huge page
    if Aarch64PageTable::map_huge_page(
        pt_root,
        huge_base,
        huge_frame,
        flags,
        &mut &crate::FRAME_ALLOCATOR,
    )
    .is_err()
    {
        // Mapping failed - free the huge page and fall back
        crate::FRAME_ALLOCATOR.free_huge(huge_frame);
        return None;
    }

    // Register with LRU (track head frame only for huge pages)
    {
        use crate::mm::lru::lru_add_new;
        use crate::mm::rmap::page_add_anon_rmap;

        if let Some(anon_vma) = anon_vma {
            page_add_anon_rmap(huge_frame, anon_vma, huge_base);
        }
        lru_add_new(huge_frame);
    }

    // Flush TLB for the huge page region
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vale1is, {0}",
            "dsb ish",
            "isb",
            in(reg) huge_base >> 12,
            options(nostack)
        );
    }

    // Increment minor fault counter (THP is still minor - no I/O)
    crate::task::percpu::increment_min_flt();

    Some(true) // Huge page mapped successfully
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
    let vma_is_anon_private = vma.is_anon_private();
    let vma_is_thp_eligible = vma.is_thp_eligible();
    let vma_file = vma.file.clone();
    let vma_start = vma.start;
    let vma_end = vma.end;
    let vma_offset = vma.offset;
    let vma_anon_vma = vma.anon_vma.clone();
    drop(mm_guard);

    // Get current page table (TTBR0_EL1 for user space)
    let ttbr0: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack, nomem));
    }
    let pt_root = ttbr0 & !0xFFF;

    // Try THP (Transparent Huge Page) allocation for eligible VMAs
    if vma_is_thp_eligible
        && let Some(result) = try_huge_page_fault(
            pt_root,
            fault_addr,
            vma_start,
            vma_end,
            vma_prot,
            vma_anon_vma.as_ref(),
        )
    {
        return Some(result);
    }
    // Fall through to 4KB allocation if THP failed

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

    // Map the page
    let page_addr = fault_addr & !0xFFF;
    if map_user_page(pt_root, page_addr, frame, attrs).is_err() {
        // Mapping failed, free the frame
        crate::FRAME_ALLOCATOR.free(frame);
        return Some(false);
    }
    // TLB is flushed by map_user_page

    // Register anonymous page with LRU and page descriptors for swap support
    if vma_is_anon_private {
        use crate::mm::lru::lru_add_new;
        use crate::mm::rmap::page_add_anon_rmap;

        if let Some(ref anon_vma) = vma_anon_vma {
            page_add_anon_rmap(frame, anon_vma, page_addr);
        }
        lru_add_new(frame);
    }

    // Increment minor fault counter (demand paging is minor - no I/O from disk)
    crate::task::percpu::increment_min_flt();

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

/// Walk page tables and return pointer to L3 PTE, even for non-present entries
///
/// Returns (pte_pointer, pte_value) or None if page table walk fails at higher levels
unsafe fn get_pte_for_swap(ttbr0: u64, vaddr: u64) -> Option<(*mut u64, u64)> {
    let l0_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let l1_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let l3_idx = ((vaddr >> 12) & 0x1FF) as usize;

    // Table descriptor: bits [1:0] = 0b11
    const TABLE_DESC: u64 = 0b11;

    unsafe {
        let l0 = ttbr0 as *const u64;

        // L0 must be present
        let l0_entry = *l0.add(l0_idx);
        if (l0_entry & 0b11) != TABLE_DESC {
            return None;
        }

        // L1 must be present
        let l1 = (l0_entry & 0x0000_FFFF_FFFF_F000) as *const u64;
        let l1_entry = *l1.add(l1_idx);
        if (l1_entry & 0b11) != TABLE_DESC {
            return None;
        }

        // L2 must be present
        let l2 = (l1_entry & 0x0000_FFFF_FFFF_F000) as *const u64;
        let l2_entry = *l2.add(l2_idx);
        if (l2_entry & 0b11) != TABLE_DESC {
            return None;
        }

        // L3 - return PTE regardless of present bit (for swap detection)
        let l3 = (l2_entry & 0x0000_FFFF_FFFF_F000) as *mut u64;
        let pte_ptr = l3.add(l3_idx);
        let pte_value = *pte_ptr;

        Some((pte_ptr, pte_value))
    }
}

/// Handle a page fault for a swapped-out page
///
/// Detects swap entries in PTEs and performs swap-in:
/// 1. Check if PTE contains a swap entry (non-present with swap marker)
/// 2. Allocate a new physical frame
/// 3. Read page data from swap device
/// 4. Update PTE to point to the new frame
/// 5. Free the swap slot
///
/// Returns:
/// - Some(true) if the swap fault was handled successfully
/// - Some(false) if swap-in failed (e.g., OOM, I/O error)
/// - None if the PTE is not a swap entry
fn handle_swap_fault(fault_addr: u64) -> Option<bool> {
    use crate::arch::aarch64::paging::{AF, AP_EL0_RW, ATTR_IDX_NORMAL, SH_INNER};
    use crate::mm::{SwapEntry, free_swap_entry, swap_cache_lookup, swap_read_page};

    // Get current page table (TTBR0_EL1 for user space)
    let ttbr0: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack, nomem));
    }
    let pt_root = ttbr0 & !0xFFF;

    // Get the PTE (including non-present entries)
    let (pte_ptr, pte_value) = unsafe { get_pte_for_swap(pt_root, fault_addr)? };

    // Check if this is a swap entry
    if !SwapEntry::is_swap_pte(pte_value) {
        return None; // Not a swap entry, let other handlers deal with it
    }

    let entry = SwapEntry::from_pte(pte_value);

    // Step 1: Check swap cache first
    if let Some(cached) = swap_cache_lookup(entry) {
        let frame = cached.frame;

        // L3 page descriptor attributes: [1:0] = 0b11
        let attrs: u64 = 0b11 | AF | SH_INNER | ATTR_IDX_NORMAL | AP_EL0_RW;
        let new_pte = frame | attrs;

        unsafe {
            core::ptr::write_volatile(pte_ptr, new_pte);
        }

        // Flush TLB
        crate::arch::aarch64::paging::flush_tlb(fault_addr);

        // Increment major fault counter (swap cache hit still counts as major)
        crate::task::percpu::increment_maj_flt();

        return Some(true);
    }

    // Step 2: Allocate new frame
    let frame = match crate::FRAME_ALLOCATOR.alloc() {
        Some(f) => f,
        None => {
            printkln!("swap_fault: Out of memory!");
            return Some(false);
        }
    };

    // Step 3: Read from swap
    if swap_read_page(entry, frame).is_err() {
        // I/O error - free frame and fail
        crate::FRAME_ALLOCATOR.free(frame);
        printkln!("swap_fault: Swap I/O error!");
        return Some(false);
    }

    // Step 4: Update PTE - clear swap entry, set present
    // L3 page descriptor attributes: [1:0] = 0b11
    let attrs: u64 = 0b11 | AF | SH_INNER | ATTR_IDX_NORMAL | AP_EL0_RW;
    let new_pte = frame | attrs;

    unsafe {
        core::ptr::write_volatile(pte_ptr, new_pte);
    }

    // Step 5: Flush TLB for this address
    crate::arch::aarch64::paging::flush_tlb(fault_addr);

    // Step 6: Free swap slot (page is now in RAM)
    free_swap_entry(entry);

    // Increment major fault counter (swap-in requires I/O)
    crate::task::percpu::increment_maj_flt();

    Some(true) // Swap-in successful
}

/// Walk page tables and return pointer to L3 PTE for COW handling
///
/// Returns (pte_pointer, pte_value) or None if page table walk fails.
/// This is similar to get_pte_for_swap but expects a valid present page.
unsafe fn get_pte_for_cow(ttbr0: u64, vaddr: u64) -> Option<(*mut u64, u64)> {
    let l0_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let l1_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let l3_idx = ((vaddr >> 12) & 0x1FF) as usize;

    // Table descriptor: bits [1:0] = 0b11
    const TABLE_DESC: u64 = 0b11;

    unsafe {
        let l0 = ttbr0 as *const u64;

        // L0 must be present
        let l0_entry = *l0.add(l0_idx);
        if (l0_entry & 0b11) != TABLE_DESC {
            return None;
        }

        // L1 must be present
        let l1 = (l0_entry & 0x0000_FFFF_FFFF_F000) as *const u64;
        let l1_entry = *l1.add(l1_idx);
        if (l1_entry & 0b11) != TABLE_DESC {
            return None;
        }

        // L2 must be present
        let l2 = (l1_entry & 0x0000_FFFF_FFFF_F000) as *const u64;
        let l2_entry = *l2.add(l2_idx);
        if (l2_entry & 0b11) != TABLE_DESC {
            return None;
        }

        // L3 - return PTE pointer and value
        let l3 = (l2_entry & 0x0000_FFFF_FFFF_F000) as *mut u64;
        let pte_ptr = l3.add(l3_idx);
        let pte_value = *pte_ptr;

        Some((pte_ptr, pte_value))
    }
}

/// Handle a COW (Copy-on-Write) page fault
///
/// Called when a write permission fault occurs on a page marked with PAGE_COW.
/// This performs the copy-on-write resolution:
/// 1. Check if the page has the COW flag set
/// 2. If refcount > 1: allocate new frame, copy contents, update PTE
/// 3. If refcount == 1: just clear COW flag and make writable
/// 4. Use atomic CAS for race-safe PTE update
///
/// Returns:
/// - Some(true) if COW was resolved successfully
/// - Some(false) if COW resolution failed (e.g., OOM)
/// - None if not a COW page (should be handled as SIGSEGV)
fn handle_cow_fault(fault_addr: u64) -> Option<bool> {
    use crate::arch::aarch64::paging::{
        AF, AP_EL0_RO, AP_EL0_RW, ATTR_IDX_NORMAL, PAGE_COW, PAGE_SIZE, SH_INNER,
    };
    use crate::mm::anon_vma::AnonVma;
    use crate::mm::get_task_mm;
    use crate::mm::lru::lru_add_new;
    use crate::mm::rmap::{page_add_anon_rmap, page_remove_rmap};
    use crate::task::percpu::current_tid;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};

    // Physical address mask (bits [47:12])
    const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

    // Get current page table (TTBR0_EL1 for user space)
    let ttbr0: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack, nomem));
    }
    let pt_root = ttbr0 & !0xFFF;

    // Check if this address is in a huge page - if so, split it first
    // This implements the "split-first" COW strategy for THP
    {
        use crate::arch::aarch64::paging::Aarch64PageTable;
        if let Some((huge_base, _phys)) = Aarch64PageTable::is_huge_page_mapped(pt_root, fault_addr)
        {
            // Split the huge page into 512 4KB pages before handling COW
            let _ =
                Aarch64PageTable::split_huge_page(pt_root, huge_base, &mut &crate::FRAME_ALLOCATOR);
            // After splitting, the page is now a regular 4KB page - continue with COW handling
        }
    }

    // Page-align the fault address
    let page_addr = fault_addr & !0xFFF;

    // Get PTE for the faulting address
    let (pte_ptr, pte_value) = unsafe { get_pte_for_cow(pt_root, page_addr)? };

    // Check if this is a COW page
    if (pte_value & PAGE_COW) == 0 {
        return None; // Not a COW page - let SIGSEGV handler deal with it
    }

    // Save original PTE for atomic CAS
    let orig_pte = pte_value;

    // Get the physical address of the shared page
    let old_phys = pte_value & ADDR_MASK;

    // Get anon_vma from VMA for rmap updates (if available)
    let tid = current_tid();
    let anon_vma: Option<Arc<AnonVma>> = get_task_mm(tid).and_then(|mm| {
        let mm_guard = mm.lock();
        mm_guard
            .find_vma(fault_addr)
            .and_then(|vma| vma.anon_vma.clone())
    });

    // Check reference count to determine if we need to copy
    let refcount = crate::FRAME_ALLOCATOR.refcount(old_phys);

    if refcount > 1 {
        // Shared page - need to allocate new frame and copy
        let new_phys = match crate::FRAME_ALLOCATOR.alloc() {
            Some(f) => f,
            None => {
                printkln!("cow_fault: Out of memory!");
                return Some(false);
            }
        };

        // Copy page contents
        unsafe {
            let src = old_phys as *const u8;
            let dst = new_phys as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE as usize);
        }

        // Clean cache for new page
        crate::arch::aarch64::cache::cache_clean_range(new_phys as *mut u8, PAGE_SIZE as usize);

        // Build new PTE: new physical address, writable, no COW, preserve other attrs
        // Keep AF, SH, ATTR_IDX, PXN/UXN but change permissions
        let preserved_attrs = pte_value & (AF | SH_INNER | ATTR_IDX_NORMAL | (0b11 << 53));
        let new_pte = new_phys | preserved_attrs | AP_EL0_RW | 0b11; // 0b11 = valid page

        // Use atomic CAS to update PTE (prevent race with another CPU)
        let pte_atomic = unsafe { &*(pte_ptr as *const AtomicU64) };
        match pte_atomic.compare_exchange(orig_pte, new_pte, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                // CAS succeeded - we updated the PTE
                // Update rmap: register new page, remove old page
                if let Some(ref av) = anon_vma {
                    page_add_anon_rmap(new_phys, av, page_addr);
                }
                lru_add_new(new_phys);
                page_remove_rmap(old_phys);

                // Decrement reference count on old frame
                crate::FRAME_ALLOCATOR.decref(old_phys);
            }
            Err(_) => {
                // CAS failed - another CPU already resolved this fault
                // Free the frame we allocated
                crate::FRAME_ALLOCATOR.free(new_phys);
                // Still return success - the fault is resolved
                return Some(true);
            }
        }
    } else {
        // Exclusive page (refcount == 1) - just make writable
        // Clear COW flag and set writable permission
        let new_pte = (pte_value & !PAGE_COW & !AP_EL0_RO) | AP_EL0_RW;

        // Use atomic CAS for consistency
        let pte_atomic = unsafe { &*(pte_ptr as *const AtomicU64) };
        if pte_atomic
            .compare_exchange(orig_pte, new_pte, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Race - fault already resolved
            return Some(true);
        }
    }

    // Flush TLB for this address
    crate::arch::aarch64::paging::flush_tlb(page_addr);

    // Increment minor fault counter (COW is minor - no I/O)
    crate::task::percpu::increment_min_flt();

    Some(true)
}
