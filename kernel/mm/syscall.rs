//! Memory management syscalls (mmap, munmap, brk, mlock)

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::File;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;

use super::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, PAGE_SIZE, PROT_READ, PROT_WRITE, VM_LOCKED,
    VM_LOCKED_MASK, VM_LOCKONFAULT, Vma, create_default_mm, get_task_mm, init_task_mm,
};

// Error codes (negative errno)
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;
const EBADF: i64 = -9;
const EPERM: i64 = -1;

// ============================================================================
// mlock flags (user-visible)
// ============================================================================

/// mlock2 flag: Lock pages in range after they are faulted in (deferred locking)
pub const MLOCK_ONFAULT: i32 = 0x01;

/// mlockall flag: Lock all current mappings
pub const MCL_CURRENT: i32 = 1;

/// mlockall flag: Lock all future mappings
pub const MCL_FUTURE: i32 = 2;

/// mlockall flag: Lock pages on fault (deferred locking)
pub const MCL_ONFAULT: i32 = 4;

/// mmap syscall
///
/// Maps files or anonymous memory into the process's address space.
///
/// # Arguments
/// * `addr` - Requested address (hint or exact if MAP_FIXED)
/// * `length` - Length of mapping in bytes
/// * `prot` - Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
/// * `flags` - Map flags (MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS, MAP_FIXED)
/// * `fd` - File descriptor (ignored if MAP_ANONYMOUS)
/// * `offset` - Offset in file (must be page-aligned)
///
/// # Returns
/// Address of mapping on success, negative errno on failure
pub fn sys_mmap(addr: u64, length: u64, prot: u32, flags: u32, fd: i32, offset: u64) -> i64 {
    // Validate length
    if length == 0 {
        return EINVAL;
    }

    // Round up length to page boundary
    let length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // Validate offset alignment
    if offset & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }

    let is_anonymous = flags & MAP_ANONYMOUS != 0;
    let is_fixed = flags & MAP_FIXED != 0;
    let is_private = flags & MAP_PRIVATE != 0;
    let is_shared = flags & MAP_SHARED != 0;

    // Must specify exactly one of MAP_PRIVATE or MAP_SHARED
    if is_private == is_shared {
        return EINVAL;
    }

    // For MVP: only support private mappings
    if is_shared {
        return EINVAL; // MAP_SHARED not yet implemented
    }

    // Get file if not anonymous
    let file: Option<Arc<File>> = if !is_anonymous {
        if fd < 0 {
            return EBADF;
        }
        let tid = current_tid();
        let fd_table = match get_task_fd(tid) {
            Some(t) => t,
            None => return EBADF,
        };
        match fd_table.lock().get(fd) {
            Some(f) => Some(f),
            None => return EBADF,
        }
    } else {
        None
    };

    // Get or create mm for current task
    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => {
            // Create new mm for task if doesn't exist
            let mm = create_default_mm();
            init_task_mm(tid, mm.clone());
            mm
        }
    };

    let mut mm_guard = mm.lock();

    // Determine mapping address
    let map_addr = if is_fixed {
        // MAP_FIXED: use exact address
        if addr & (PAGE_SIZE - 1) != 0 {
            return EINVAL; // Must be page-aligned
        }
        // Remove any existing mappings in range
        mm_guard.remove_range(addr, addr + length);
        addr
    } else if addr != 0 {
        // Hint address - try to use it, fall back to search
        let aligned = addr & !(PAGE_SIZE - 1);
        if !mm_guard.overlaps(aligned, aligned + length) {
            aligned
        } else {
            match mm_guard.find_free_area(length) {
                Some(a) => a,
                None => return ENOMEM,
            }
        }
    } else {
        // No hint - find free area
        match mm_guard.find_free_area(length) {
            Some(a) => a,
            None => return ENOMEM,
        }
    };

    // Create VMA
    let mut vma = if let Some(f) = file {
        Vma::new_file(map_addr, map_addr + length, prot, flags, f, offset)
    } else {
        Vma::new(map_addr, map_addr + length, prot, flags | MAP_ANONYMOUS)
    };

    // Apply def_flags if MCL_FUTURE was set via mlockall
    let def_flags = mm_guard.def_flags();
    if def_flags != 0 {
        vma.flags |= def_flags;
        let pages = length / PAGE_SIZE;
        mm_guard.add_locked_vm(pages);
    }

    mm_guard.insert_vma(vma);

    // If MCL_FUTURE with immediate locking (not ONFAULT), populate now
    let should_populate = def_flags != 0 && (def_flags & VM_LOCKONFAULT == 0);

    // Release lock before potential page faults
    drop(mm_guard);

    if should_populate {
        populate_range(map_addr, length);
    }

    // Note: Pages are allocated on demand in the page fault handler
    // (unless we just populated them above for MCL_FUTURE)

    map_addr as i64
}

/// munmap syscall
///
/// Unmaps a region of memory.
///
/// # Arguments
/// * `addr` - Start address (must be page-aligned)
/// * `length` - Length of region to unmap
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_munmap(addr: u64, length: u64) -> i64 {
    // Validate alignment
    if addr & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }

    if length == 0 {
        return EINVAL;
    }

    // Round up length to page boundary
    let length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end = addr + length;

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return 0, // No mm, nothing to unmap
    };

    let mut mm_guard = mm.lock();

    // Remove VMAs in range
    let removed = mm_guard.remove_range(addr, end);

    // Release lock before doing page table operations
    drop(mm_guard);

    // Unmap pages from page table for each removed VMA
    if !removed.is_empty() {
        unmap_vma_pages(&removed, addr, end);
    }

    0
}

/// Unmap pages for removed VMAs
///
/// This handles the actual page table manipulation and frame freeing.
fn unmap_vma_pages(vmas: &[Vma], unmap_start: u64, unmap_end: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::FRAME_ALLOCATOR;
        use crate::arch::x86_64::paging::X86_64PageTable;

        // Get current page table
        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }

        for vma in vmas {
            // Calculate the actual range to unmap (intersection of VMA and requested range)
            let start = vma.start.max(unmap_start);
            let end = vma.end.min(unmap_end);

            let mut page = start;
            while page < end {
                // Try to unmap this page
                if let Some(phys) = X86_64PageTable::unmap_page(cr3, page) {
                    // Free the physical frame
                    FRAME_ALLOCATOR.decref(phys);
                }
                page += PAGE_SIZE;
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::FRAME_ALLOCATOR;
        use crate::arch::aarch64::paging::Aarch64PageTable;

        // Get current page table (TTBR0_EL1 for user space)
        let ttbr0: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack));
        }
        let pt_phys = ttbr0 & !0xFFF;

        for vma in vmas {
            let start = vma.start.max(unmap_start);
            let end = vma.end.min(unmap_end);

            let mut page = start;
            while page < end {
                if let Some(phys) = Aarch64PageTable::unmap_page(pt_phys, page) {
                    FRAME_ALLOCATOR.decref(phys);
                }
                page += PAGE_SIZE;
            }
        }
    }
}

/// Unmap pages in a range (for brk shrinking)
///
/// Unlike unmap_vma_pages, this directly unmaps pages in a range
/// without requiring VMA information.
fn unmap_pages_range(start: u64, end: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::FRAME_ALLOCATOR;
        use crate::arch::x86_64::paging::X86_64PageTable;

        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }

        let mut page = start;
        while page < end {
            if let Some(phys) = X86_64PageTable::unmap_page(cr3, page) {
                FRAME_ALLOCATOR.decref(phys);
            }
            page += PAGE_SIZE;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::FRAME_ALLOCATOR;
        use crate::arch::aarch64::paging::Aarch64PageTable;

        let ttbr0: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack));
        }
        let pt_phys = ttbr0 & !0xFFF;

        let mut page = start;
        while page < end {
            if let Some(phys) = Aarch64PageTable::unmap_page(pt_phys, page) {
                FRAME_ALLOCATOR.decref(phys);
            }
            page += PAGE_SIZE;
        }
    }
}

/// brk syscall
///
/// Change the location of the program break, which defines the end of the
/// process's data segment (the end of heap).
///
/// # Arguments
/// * `brk` - New program break address, or 0 to query current value
///
/// # Returns
/// * On success: The new program break address
/// * On failure: The current (unchanged) program break address
///
/// # Behavior
/// * `brk(0)` - Returns current program break (query mode)
/// * `brk < start_brk` - Returns current break unchanged (cannot go below start)
/// * Expanding brk - Creates/extends heap VMA, pages allocated on demand
/// * Shrinking brk - Removes pages and VMA entries for freed range
pub fn sys_brk(brk: u64) -> i64 {
    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => {
            // No mm - create default one (shouldn't happen for user tasks)
            let mm = create_default_mm();
            init_task_mm(tid, mm.clone());
            mm
        }
    };

    let mut mm_guard = mm.lock();

    let current_brk = mm_guard.get_brk();
    let start_brk = mm_guard.get_start_brk();

    // Query mode: return current brk
    if brk == 0 {
        return current_brk as i64;
    }

    // Cannot go below start_brk
    if brk < start_brk {
        return current_brk as i64;
    }

    // Page-align old and new brk values (round up)
    let old_brk_aligned = (current_brk + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let new_brk_aligned = (brk + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // If aligned values are the same, just update brk and return
    if old_brk_aligned == new_brk_aligned {
        mm_guard.update_brk(brk);
        return brk as i64;
    }

    if new_brk_aligned < old_brk_aligned {
        // Shrinking: remove pages in [new_brk_aligned, old_brk_aligned)
        // First, update the heap VMA if one exists
        let start_brk_aligned = start_brk & !(PAGE_SIZE - 1);

        // Find and shrink/remove the heap VMA
        // The heap VMA starts at start_brk (or start_brk_aligned)
        let mut vmas_to_remove = Vec::new();
        for (i, vma) in mm_guard.iter().enumerate() {
            // Check if this is the heap VMA (starts at or near start_brk)
            if vma.start >= start_brk_aligned && vma.start < old_brk_aligned {
                if vma.end <= new_brk_aligned {
                    // VMA is completely within new range - keep it
                    continue;
                }
                vmas_to_remove.push(i);
            }
        }

        // Remove affected VMAs and potentially re-add a smaller one
        // For simplicity, we remove overlapping VMAs and recreate if needed
        let removed = mm_guard.remove_range(new_brk_aligned, old_brk_aligned);

        // Update brk
        mm_guard.update_brk(brk);

        // Release lock before page table operations
        drop(mm_guard);

        // Unmap pages
        if !removed.is_empty() {
            unmap_vma_pages(&removed, new_brk_aligned, old_brk_aligned);
        }
        // Also directly unmap the range in case VMA tracking is imprecise
        unmap_pages_range(new_brk_aligned, old_brk_aligned);

        brk as i64
    } else {
        // Expanding: create/extend heap VMA for [old_brk_aligned, new_brk_aligned)
        // Check for collision with existing VMAs in the expansion range
        if mm_guard.overlaps(old_brk_aligned, new_brk_aligned) {
            // Collision - cannot expand
            return current_brk as i64;
        }

        // Check if there's an existing heap VMA to extend
        let start_brk_aligned = start_brk & !(PAGE_SIZE - 1);
        let mut found_heap_vma = false;

        // Try to find and extend existing heap VMA
        if let Some(vma) = mm_guard.find_vma_mut(start_brk_aligned)
            && vma.end == old_brk_aligned
        {
            // Extend the existing heap VMA
            vma.end = new_brk_aligned;
            found_heap_vma = true;
        }

        if !found_heap_vma {
            // Create new heap VMA
            // If old_brk_aligned > start_brk_aligned, we may need a VMA covering
            // the full heap range, or just the new portion
            let vma_start = if current_brk == start_brk {
                // First expansion - start from start_brk
                start_brk_aligned
            } else {
                // Subsequent expansion - VMA should already exist, but if not,
                // create one covering just the new region
                old_brk_aligned
            };

            let heap_vma = Vma::new(
                vma_start,
                new_brk_aligned,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
            );
            mm_guard.insert_vma(heap_vma);
        }

        // Update brk
        mm_guard.update_brk(brk);

        // Pages will be allocated on demand via page faults
        brk as i64
    }
}

// ============================================================================
// mlock syscalls
// ============================================================================

/// Check if the current task can perform mlock operations.
///
/// TODO: Check RLIMIT_MEMLOCK and CAP_IPC_LOCK when implemented.
/// For now, always returns true since hk doesn't have swap and
/// lacks rlimit infrastructure.
#[allow(dead_code)]
fn can_do_mlock() -> bool {
    // TODO: When RLIMIT_MEMLOCK is implemented, check:
    //   if rlimit(RLIMIT_MEMLOCK) != 0 { return true; }
    //   if capable(CAP_IPC_LOCK) { return true; }
    //   return false;
    true
}

/// Populate pages in a range by triggering demand paging.
///
/// This is the hk equivalent of Linux's mm_populate().
/// It walks through the address range and reads each page to trigger
/// the page fault handler, which will allocate and map the pages.
/// Populate pages by faulting them into memory
///
/// This function is a no-op for now because:
/// 1. The kernel has no swap, so pages will be faulted in on demand anyway
/// 2. Direct user memory access from kernel context requires proper uaccess
///    handling and page fault tolerance that isn't fully implemented yet
///
/// TODO: Implement proper page population using get_user_pages() or similar
/// when swap support is added.
#[allow(unused_variables)]
fn populate_range(start: u64, len: u64) {
    // Currently a no-op - pages will be demand-paged on first access
    // from userspace. When swap is implemented, this should prefault
    // the pages to lock them in memory.
}

/// mlock syscall - Lock pages in memory
///
/// Locks the pages in the specified address range into RAM, preventing
/// them from being swapped out. Since hk currently has no swap, this
/// primarily sets the VM_LOCKED flag for ABI compatibility and prefaults
/// the pages into memory.
///
/// # Arguments
/// * `addr` - Start address of the memory range
/// * `len` - Length of the memory range in bytes
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_mlock(addr: u64, len: u64) -> i64 {
    do_mlock(addr, len, VM_LOCKED)
}

/// mlock2 syscall - Lock pages in memory with flags
///
/// Extended version of mlock that supports the MLOCK_ONFAULT flag
/// for deferred locking (pages are locked when faulted in, not prefaulted).
///
/// # Arguments
/// * `addr` - Start address of the memory range
/// * `len` - Length of the memory range in bytes
/// * `flags` - Flags (MLOCK_ONFAULT)
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_mlock2(addr: u64, len: u64, flags: i32) -> i64 {
    // Validate flags - only MLOCK_ONFAULT is allowed
    if flags & !MLOCK_ONFAULT != 0 {
        return EINVAL;
    }

    let mut vm_flags = VM_LOCKED;
    if flags & MLOCK_ONFAULT != 0 {
        vm_flags |= VM_LOCKONFAULT;
    }

    do_mlock(addr, len, vm_flags)
}

/// Common implementation for mlock/mlock2
fn do_mlock(start: u64, len: u64, vm_flags: u32) -> i64 {
    // Zero length is a no-op (success)
    if len == 0 {
        return 0;
    }

    // Permission check (stub - always allows for now)
    if !can_do_mlock() {
        return EPERM;
    }

    // Page-align the range
    let start_aligned = start & !(PAGE_SIZE - 1);
    let end_unaligned = start.saturating_add(len);
    let end_aligned = (end_unaligned + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let len_aligned = end_aligned - start_aligned;

    // Get current task's mm
    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return ENOMEM,
    };

    let mut mm_guard = mm.lock();

    // Find all VMAs in range and set VM_LOCKED flag
    // Following Linux behavior: lock portions that exist, succeed even if
    // some of the range has no VMA

    // First pass: calculate total pages to add to locked_vm and update VMA flags
    let mut pages_to_add: u64 = 0;
    for vma in mm_guard.iter_mut() {
        // Check for overlap
        if vma.end <= start_aligned || vma.start >= end_aligned {
            continue; // No overlap
        }

        // Calculate pages being locked in this VMA
        let vma_start = vma.start.max(start_aligned);
        let vma_end = vma.end.min(end_aligned);
        let pages = (vma_end - vma_start) / PAGE_SIZE;

        // Only count if not already locked
        if vma.flags & VM_LOCKED == 0 {
            pages_to_add += pages;
        }

        // Set the lock flags (clear old lock flags first, then set new ones)
        vma.flags = (vma.flags & !VM_LOCKED_MASK) | vm_flags;
    }

    // Update locked_vm counter after the loop
    mm_guard.add_locked_vm(pages_to_add);

    // Release lock before populating (to avoid holding lock during page faults)
    drop(mm_guard);

    // If not MLOCK_ONFAULT, populate pages now
    if vm_flags & VM_LOCKONFAULT == 0 {
        populate_range(start_aligned, len_aligned);
    }

    0
}

/// munlock syscall - Unlock pages
///
/// Unlocks the pages in the specified address range, allowing them to be
/// swapped out again (when swap is implemented).
///
/// # Arguments
/// * `addr` - Start address of the memory range
/// * `len` - Length of the memory range in bytes
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_munlock(addr: u64, len: u64) -> i64 {
    // Zero length is a no-op
    if len == 0 {
        return 0;
    }

    // Page-align the range
    let start_aligned = addr & !(PAGE_SIZE - 1);
    let end_unaligned = addr.saturating_add(len);
    let end_aligned = (end_unaligned + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return 0, // No mm, nothing to unlock
    };

    let mut mm_guard = mm.lock();

    // Accumulate pages to subtract (can't modify locked_vm during iteration)
    let mut pages_to_subtract: u64 = 0;

    for vma in mm_guard.iter_mut() {
        // Check for overlap
        if vma.end <= start_aligned || vma.start >= end_aligned {
            continue; // No overlap
        }

        // Calculate pages being unlocked in this VMA
        let vma_start = vma.start.max(start_aligned);
        let vma_end = vma.end.min(end_aligned);
        let pages = (vma_end - vma_start) / PAGE_SIZE;

        // Only decrement if was locked
        if vma.flags & VM_LOCKED != 0 {
            pages_to_subtract += pages;
        }

        // Clear lock flags
        vma.flags &= !VM_LOCKED_MASK;
    }

    // Update locked_vm counter after iteration
    mm_guard.sub_locked_vm(pages_to_subtract);

    0
}

/// mlockall syscall - Lock all current and/or future mappings
///
/// Locks all pages in the calling process's virtual address space.
///
/// # Arguments
/// * `flags` - Combination of MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_mlockall(flags: i32) -> i64 {
    // Validate flags
    if flags == 0 {
        return EINVAL;
    }
    if flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 {
        return EINVAL;
    }
    // MCL_ONFAULT alone is invalid
    if flags == MCL_ONFAULT {
        return EINVAL;
    }

    // Permission check
    if !can_do_mlock() {
        return EPERM;
    }

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return ENOMEM,
    };

    let mut mm_guard = mm.lock();

    // Clear old def_flags
    mm_guard.set_def_flags(0);

    // Handle MCL_FUTURE
    if flags & MCL_FUTURE != 0 {
        let mut def = VM_LOCKED;
        if flags & MCL_ONFAULT != 0 {
            def |= VM_LOCKONFAULT;
        }
        mm_guard.set_def_flags(def);

        // If only MCL_FUTURE (without MCL_CURRENT), we're done
        if flags & MCL_CURRENT == 0 {
            return 0;
        }
    }

    // Handle MCL_CURRENT - lock all existing VMAs
    if flags & MCL_CURRENT != 0 {
        let vm_flags = if flags & MCL_ONFAULT != 0 {
            VM_LOCKED | VM_LOCKONFAULT
        } else {
            VM_LOCKED
        };

        // Collect ranges to populate (can't hold lock during page faults)
        let mut ranges_to_populate: Vec<(u64, u64)> = Vec::new();
        // Accumulate pages to add (can't modify locked_vm during iteration)
        let mut pages_to_add: u64 = 0;

        for vma in mm_guard.iter_mut() {
            // Calculate pages
            let pages = (vma.end - vma.start) / PAGE_SIZE;

            // Only count if not already locked
            if vma.flags & VM_LOCKED == 0 {
                pages_to_add += pages;
            }

            // Collect range for population if not ONFAULT
            if vm_flags & VM_LOCKONFAULT == 0 {
                ranges_to_populate.push((vma.start, vma.end - vma.start));
            }

            // Set the lock flags
            vma.flags = (vma.flags & !VM_LOCKED_MASK) | vm_flags;
        }

        // Update locked_vm counter after iteration
        mm_guard.add_locked_vm(pages_to_add);

        drop(mm_guard);

        // Populate pages if not ONFAULT
        for (start, len) in ranges_to_populate {
            populate_range(start, len);
        }
    }

    0
}

/// munlockall syscall - Unlock all mappings
///
/// Unlocks all pages in the calling process's virtual address space.
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_munlockall() -> i64 {
    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return 0, // No mm, nothing to unlock
    };

    let mut mm_guard = mm.lock();

    // Clear def_flags (undo MCL_FUTURE)
    mm_guard.set_def_flags(0);

    // Clear VM_LOCKED on all VMAs
    for vma in mm_guard.iter_mut() {
        vma.flags &= !VM_LOCKED_MASK;
    }

    // Reset locked_vm counter
    mm_guard.reset_locked_vm();

    0
}
