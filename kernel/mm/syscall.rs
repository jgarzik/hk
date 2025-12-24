//! Memory management syscalls (mmap, munmap, brk, mlock)

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::File;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;

use super::{
    MADV_DODUMP, MADV_DOFORK, MADV_DONTDUMP, MADV_DONTFORK, MADV_DONTNEED, MADV_FREE, MADV_NORMAL,
    MADV_RANDOM, MADV_SEQUENTIAL, MADV_WILLNEED, MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE,
    MAP_GROWSDOWN, MAP_LOCKED, MAP_NONBLOCK, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED,
    MREMAP_DONTUNMAP, MREMAP_FIXED, MREMAP_MAYMOVE, MS_ASYNC, MS_INVALIDATE, MS_SYNC, PAGE_SIZE,
    PROT_GROWSDOWN, PROT_GROWSUP, PROT_READ, PROT_WRITE, VM_DONTCOPY, VM_DONTDUMP, VM_GROWSDOWN,
    VM_LOCKED, VM_LOCKED_MASK, VM_LOCKONFAULT, VM_RAND_READ, VM_SEQ_READ, VM_SHARED, Vma,
    create_default_mm, get_task_mm, init_task_mm,
};

// Error codes (negative errno)
const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;
const EBADF: i64 = -9;
const EPERM: i64 = -1;
const EEXIST: i64 = -17;
const EBUSY: i64 = -16;
const EIO: i64 = -5;
const EFAULT: i64 = -14;

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
    let is_fixed_noreplace = flags & MAP_FIXED_NOREPLACE != 0;
    let is_private = flags & MAP_PRIVATE != 0;
    let is_shared = flags & MAP_SHARED != 0;

    // Must specify exactly one of MAP_PRIVATE or MAP_SHARED
    if is_private == is_shared {
        return EINVAL;
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
    let map_addr = if is_fixed || is_fixed_noreplace {
        // MAP_FIXED or MAP_FIXED_NOREPLACE: use exact address
        if addr & (PAGE_SIZE - 1) != 0 {
            return EINVAL; // Must be page-aligned
        }
        // MAP_FIXED_NOREPLACE: fail if address range overlaps existing mapping
        if is_fixed_noreplace && mm_guard.overlaps(addr, addr + length) {
            return EEXIST;
        }
        // MAP_FIXED: remove any existing mappings in range
        if is_fixed {
            mm_guard.remove_range(addr, addr + length);
        }
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

    // Check RLIMIT_AS (address space limit) before creating VMA
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_AS);
    if limit != crate::rlimit::RLIM_INFINITY {
        let current_bytes = mm_guard.total_vm() * PAGE_SIZE;
        if current_bytes.saturating_add(length) > limit {
            return ENOMEM;
        }
    }

    // Create VMA
    let mut vma = if let Some(f) = file {
        Vma::new_file(map_addr, map_addr + length, prot, flags, f, offset)
    } else {
        Vma::new(map_addr, map_addr + length, prot, flags | MAP_ANONYMOUS)
    };

    // Set VM_SHARED for shared mappings
    if is_shared {
        vma.flags |= VM_SHARED;
    }

    // Set VM_GROWSDOWN for stack-like mappings that grow downward
    // Linux: calc_vm_flag_bits() translates MAP_GROWSDOWN to VM_GROWSDOWN
    if flags & MAP_GROWSDOWN != 0 {
        vma.flags |= VM_GROWSDOWN;
    }

    // Handle MAP_LOCKED flag - lock pages in memory
    // Linux: do_mmap() checks can_do_mlock() and mlock_future_ok()
    let is_map_locked = flags & MAP_LOCKED != 0;
    if is_map_locked {
        // Permission check
        if !can_do_mlock() {
            return EPERM;
        }

        // Check RLIMIT_MEMLOCK (CAP_IPC_LOCK bypasses limit)
        let pages = length / PAGE_SIZE;
        if !crate::task::capable(crate::task::CAP_IPC_LOCK) {
            let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_MEMLOCK);
            if limit != crate::rlimit::RLIM_INFINITY {
                let current_bytes = mm_guard.locked_vm() * PAGE_SIZE;
                let requested_bytes = pages * PAGE_SIZE;
                if current_bytes.saturating_add(requested_bytes) > limit {
                    return EAGAIN;
                }
            }
        }

        // Set VM_LOCKED on the VMA (MAP_LOCKED and VM_LOCKED have same value 0x2000,
        // but we set explicitly for clarity like Linux's calc_vm_flag_bits)
        vma.flags |= VM_LOCKED;
        mm_guard.add_locked_vm(pages);
    }

    // Apply def_flags if MCL_FUTURE was set via mlockall
    // (This may add VM_LOCKED again if both MAP_LOCKED and MCL_FUTURE are set,
    // but that's fine - the flag is already set, we just update locked_vm count)
    let def_flags = mm_guard.def_flags();
    if def_flags != 0 && !is_map_locked {
        // Check RLIMIT_MEMLOCK for MCL_FUTURE locking (CAP_IPC_LOCK bypasses limit)
        let pages = length / PAGE_SIZE;
        if !crate::task::capable(crate::task::CAP_IPC_LOCK) {
            let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_MEMLOCK);
            if limit != crate::rlimit::RLIM_INFINITY {
                let current_bytes = mm_guard.locked_vm() * PAGE_SIZE;
                let requested_bytes = pages * PAGE_SIZE;
                if current_bytes.saturating_add(requested_bytes) > limit {
                    return EAGAIN;
                }
            }
        }
        // Only apply def_flags if not already locked via MAP_LOCKED
        vma.flags |= def_flags;
        mm_guard.add_locked_vm(pages);
    }

    let idx = mm_guard.insert_vma(vma);

    // Update total_vm for RLIMIT_AS tracking
    mm_guard.add_total_vm(length / PAGE_SIZE);

    // Try to merge with adjacent VMAs (VMA merging optimization)
    mm_guard.merge_adjacent(idx);

    // Populate pages if:
    // 1. MAP_LOCKED is set, or
    // 2. MCL_FUTURE was set via mlockall (def_flags without ONFAULT), or
    // 3. MAP_POPULATE is set without MAP_NONBLOCK
    // Linux: do_mmap() sets *populate = len if VM_LOCKED or (MAP_POPULATE && !MAP_NONBLOCK)
    let should_populate_for_map_populate = (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE;
    let should_populate = is_map_locked
        || (def_flags != 0 && (def_flags & VM_LOCKONFAULT == 0))
        || should_populate_for_map_populate;

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

    // Update total_vm for RLIMIT_AS tracking
    for vma in &removed {
        let pages = (vma.end - vma.start) / PAGE_SIZE;
        mm_guard.sub_total_vm(pages);
    }

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

        // Update total_vm for RLIMIT_AS tracking
        let shrink_pages = (old_brk_aligned - new_brk_aligned) / PAGE_SIZE;
        mm_guard.sub_total_vm(shrink_pages);

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

        // Check RLIMIT_DATA (data segment size limit)
        // Per Linux behavior, just return current brk on limit exceeded (no error)
        let data_limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_DATA);
        if data_limit != crate::rlimit::RLIM_INFINITY {
            let new_data_size = new_brk_aligned.saturating_sub(start_brk);
            if new_data_size > data_limit {
                return current_brk as i64;
            }
        }

        // Check RLIMIT_AS (address space limit)
        let as_limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_AS);
        if as_limit != crate::rlimit::RLIM_INFINITY {
            let expansion_bytes = new_brk_aligned - old_brk_aligned;
            let current_bytes = mm_guard.total_vm() * PAGE_SIZE;
            if current_bytes.saturating_add(expansion_bytes) > as_limit {
                return current_brk as i64;
            }
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
            let idx = mm_guard.insert_vma(heap_vma);
            // Try to merge with adjacent VMAs (VMA merging optimization)
            mm_guard.merge_adjacent(idx);
        } else {
            // Heap VMA was extended - try merging with next VMA
            if let Some(idx) = mm_guard.find_vma_index(start_brk_aligned) {
                mm_guard.merge_adjacent(idx);
            }
        }

        // Update total_vm for RLIMIT_AS tracking
        let expansion_pages = (new_brk_aligned - old_brk_aligned) / PAGE_SIZE;
        mm_guard.add_total_vm(expansion_pages);

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
/// Check if the current task is permitted to lock memory.
///
/// A task can lock memory if:
/// - It has CAP_IPC_LOCK capability (euid == 0)
/// - Its RLIMIT_MEMLOCK is non-zero
///
/// This follows Linux's can_do_mlock() in mm/mlock.c
fn can_do_mlock() -> bool {
    // CAP_IPC_LOCK bypasses all mlock restrictions
    if crate::task::capable(crate::task::CAP_IPC_LOCK) {
        return true;
    }
    // Non-privileged users can mlock if RLIMIT_MEMLOCK > 0
    crate::rlimit::rlimit(crate::rlimit::RLIMIT_MEMLOCK) > 0
}

/// Populate pages in a range by prefaulting them into memory
///
/// This is the hk equivalent of Linux's mm_populate(). It walks through
/// the address range page by page, allocating physical frames and mapping
/// them into the process's address space.
///
/// Used by:
/// - MAP_POPULATE to prefault pages after mmap
/// - MAP_LOCKED to lock pages in memory
/// - mlock/mlockall to lock existing mappings
fn populate_range(start: u64, len: u64) {
    if len == 0 {
        return;
    }

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return,
    };

    let end = start.saturating_add(len);
    let mut addr = start & !(PAGE_SIZE - 1); // Page align down

    while addr < end {
        // Lock mm for VMA lookup
        let mm_guard = mm.lock();

        let vma = match mm_guard.find_vma(addr) {
            Some(v) => v,
            None => {
                // No VMA at this address, skip to next page
                drop(mm_guard);
                addr += PAGE_SIZE;
                continue;
            }
        };

        // Skip if not accessible (PROT_NONE)
        if vma.prot == super::PROT_NONE {
            drop(mm_guard);
            addr += PAGE_SIZE;
            continue;
        }

        // Clone VMA info we need before dropping lock
        let vma_prot = vma.prot;
        let vma_is_anonymous = vma.is_anonymous();
        let vma_file = vma.file.clone();
        let vma_start = vma.start;
        let vma_offset = vma.offset;
        let vma_end = vma.end;
        drop(mm_guard);

        // Populate this page
        populate_page(
            addr,
            vma_prot,
            vma_is_anonymous,
            vma_file,
            vma_start,
            vma_offset,
        );

        addr += PAGE_SIZE;

        // Stop at VMA end - next iteration will find next VMA if any
        if addr >= vma_end {
            continue;
        }
    }
}

/// Populate a single page by allocating a frame and mapping it
fn populate_page(
    addr: u64,
    prot: u32,
    is_anonymous: bool,
    file: Option<Arc<File>>,
    vma_start: u64,
    vma_offset: u64,
) {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::FRAME_ALLOCATOR;
        use crate::arch::x86_64::paging::{
            PAGE_NO_EXECUTE, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE, X86_64PageTable,
        };

        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }

        // Check if already mapped
        if X86_64PageTable::translate_with_root(cr3, addr).is_some() {
            return; // Already mapped
        }

        // Allocate frame
        let frame = match FRAME_ALLOCATOR.alloc() {
            Some(f) => f,
            None => return, // OOM, silently fail (Linux behavior for populate)
        };

        // Initialize page contents
        if is_anonymous {
            unsafe {
                core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
            }
        } else if let Some(f) = file {
            // File-backed: read from file
            let file_offset = vma_offset + (addr - vma_start);
            unsafe {
                core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
            }
            let buf =
                unsafe { core::slice::from_raw_parts_mut(frame as *mut u8, PAGE_SIZE as usize) };
            let _ = f.pread(buf, file_offset);
        } else {
            // No file, zero-fill
            unsafe {
                core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
            }
        }

        // Build page flags
        let mut flags = PAGE_PRESENT | PAGE_USER;
        if prot & PROT_WRITE != 0 {
            flags |= PAGE_WRITABLE;
        }
        if prot & super::PROT_EXEC == 0 {
            flags |= PAGE_NO_EXECUTE;
        }

        // Map the page using map_user_page from interrupts module
        if crate::arch::x86_64::interrupts::map_user_page(cr3, addr, frame, flags).is_err() {
            FRAME_ALLOCATOR.free(frame);
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::FRAME_ALLOCATOR;
        use crate::arch::aarch64::paging::{
            AF, AP_EL0_RO, AP_EL0_RW, ATTR_IDX_NORMAL, Aarch64PageTable, PXN, SH_INNER, UXN,
        };

        let ttbr0: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack));
        }
        let pt_phys = ttbr0 & !0xFFF;

        // Check if already mapped
        if Aarch64PageTable::translate_with_root(pt_phys, addr).is_some() {
            return; // Already mapped
        }

        // Allocate frame
        let frame = match FRAME_ALLOCATOR.alloc() {
            Some(f) => f,
            None => return, // OOM, silently fail
        };

        // Initialize page contents
        if is_anonymous {
            unsafe {
                core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
            }
        } else if let Some(f) = file {
            let file_offset = vma_offset + (addr - vma_start);
            unsafe {
                core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
            }
            let buf =
                unsafe { core::slice::from_raw_parts_mut(frame as *mut u8, PAGE_SIZE as usize) };
            let _ = f.pread(buf, file_offset);
        } else {
            unsafe {
                core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
            }
        }

        // Build page attributes
        let mut attrs = AF | SH_INNER | ATTR_IDX_NORMAL;
        if prot & PROT_WRITE != 0 {
            attrs |= AP_EL0_RW;
        } else {
            attrs |= AP_EL0_RO;
        }
        if prot & super::PROT_EXEC == 0 {
            attrs |= PXN | UXN;
        }

        // Map the page
        if crate::arch::aarch64::exceptions::map_user_page(pt_phys, addr, frame, attrs).is_err() {
            FRAME_ALLOCATOR.free(frame);
        }
    }
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

    // Permission check
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

    // First pass: calculate total pages to add to locked_vm
    let mut pages_to_add: u64 = 0;
    for vma in mm_guard.iter() {
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
    }

    // Check RLIMIT_MEMLOCK before committing (CAP_IPC_LOCK bypasses limit)
    if !crate::task::capable(crate::task::CAP_IPC_LOCK) {
        let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_MEMLOCK);
        if limit != crate::rlimit::RLIM_INFINITY {
            let current_bytes = mm_guard.locked_vm() * PAGE_SIZE;
            let requested_bytes = pages_to_add * PAGE_SIZE;
            if current_bytes.saturating_add(requested_bytes) > limit {
                return EAGAIN;
            }
        }
    }

    // Second pass: update VMA flags now that we've passed the limit check
    // Collect indices of modified VMAs for merging
    let mut modified_indices: Vec<usize> = Vec::new();
    for (idx, vma) in mm_guard.iter_mut().enumerate() {
        // Check for overlap
        if vma.end <= start_aligned || vma.start >= end_aligned {
            continue; // No overlap
        }

        // Set the lock flags (clear old lock flags first, then set new ones)
        vma.flags = (vma.flags & !VM_LOCKED_MASK) | vm_flags;
        modified_indices.push(idx);
    }

    // Update locked_vm counter after the loop
    mm_guard.add_locked_vm(pages_to_add);

    // Try to merge modified VMAs with adjacent VMAs (VMA merging optimization)
    // Process in reverse order to maintain valid indices after removals
    for &idx in modified_indices.iter().rev() {
        mm_guard.merge_adjacent(idx);
    }

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

        // First pass: calculate total pages to add
        let mut pages_to_add: u64 = 0;
        for vma in mm_guard.iter() {
            // Calculate pages
            let pages = (vma.end - vma.start) / PAGE_SIZE;

            // Only count if not already locked
            if vma.flags & VM_LOCKED == 0 {
                pages_to_add += pages;
            }
        }

        // Check RLIMIT_MEMLOCK before committing (CAP_IPC_LOCK bypasses limit)
        if !crate::task::capable(crate::task::CAP_IPC_LOCK) {
            let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_MEMLOCK);
            if limit != crate::rlimit::RLIM_INFINITY {
                let current_bytes = mm_guard.locked_vm() * PAGE_SIZE;
                let requested_bytes = pages_to_add * PAGE_SIZE;
                if current_bytes.saturating_add(requested_bytes) > limit {
                    return EAGAIN;
                }
            }
        }

        // Second pass: update VMA flags and collect ranges to populate
        let mut ranges_to_populate: Vec<(u64, u64)> = Vec::new();
        for vma in mm_guard.iter_mut() {
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

// ============================================================================
// mprotect syscall
// ============================================================================

/// mprotect syscall - Change protection of memory region
///
/// Changes the protection of the pages in the specified address range.
///
/// # Arguments
/// * `addr` - Start address (must be page-aligned)
/// * `len` - Length of region in bytes
/// * `prot` - New protection flags (PROT_READ, PROT_WRITE, PROT_EXEC).
///   May include PROT_GROWSDOWN/PROT_GROWSUP to extend range.
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_mprotect(addr: u64, len: u64, prot: u32) -> i64 {
    // Extract and strip grow flags (Linux behavior: mm/mprotect.c)
    let grows = prot & (PROT_GROWSDOWN | PROT_GROWSUP);
    let prot = prot & !(PROT_GROWSDOWN | PROT_GROWSUP);

    // Can't specify both PROT_GROWSDOWN and PROT_GROWSUP
    if grows == (PROT_GROWSDOWN | PROT_GROWSUP) {
        return EINVAL;
    }

    // Zero length is a no-op (success per Linux behavior)
    if len == 0 {
        return 0;
    }

    // Validate alignment
    if addr & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }

    // Round up length to page boundary
    let len_aligned = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let mut end = match addr.checked_add(len_aligned) {
        Some(e) => e,
        None => return EINVAL, // Overflow
    };

    // Validate protection flags (only PROT_READ, PROT_WRITE, PROT_EXEC are valid)
    if prot & !(PROT_READ | PROT_WRITE | super::PROT_EXEC) != 0 {
        return EINVAL;
    }

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return EINVAL, // No mm
    };

    let mut mm_guard = mm.lock();

    // Handle PROT_GROWSDOWN - extend protection change to VMA start
    // Linux: mm/mprotect.c do_mprotect_pkey() lines 807-865
    let mut start = addr;

    if grows & PROT_GROWSDOWN != 0 {
        // Find VMA containing start address
        if let Some(vma) = mm_guard.find_vma(start) {
            // VMA must contain the address (not just be after it)
            if vma.start > start || start >= vma.end {
                return ENOMEM;
            }
            // VMA must have VM_GROWSDOWN flag
            if !vma.is_growsdown() {
                return EINVAL;
            }
            // Extend start to VMA start
            start = vma.start;
        } else {
            return ENOMEM;
        }
    }

    // Handle PROT_GROWSUP - always fails on x86-64/aarch64
    // Linux: mm/mprotect.c - checks for VM_GROWSUP which never exists on these architectures
    if grows & PROT_GROWSUP != 0 {
        // Find VMA containing the end of range
        let check_addr = end.saturating_sub(1);
        if let Some(vma) = mm_guard.find_vma(check_addr) {
            if vma.start > check_addr || check_addr >= vma.end {
                return ENOMEM;
            }
            // VM_GROWSUP is never set on x86-64/aarch64 (only parisc has upward-growing stacks)
            // So this always fails with EINVAL, matching Linux behavior
            return EINVAL;
        } else {
            return ENOMEM;
        }
    }

    // Recalculate end based on potentially adjusted start
    if start != addr {
        end = start.saturating_add(end.saturating_sub(addr));
    }

    // Collect VMAs that need updating and validate the range is fully mapped
    let mut vmas_to_update: Vec<(u64, u64, u32)> = Vec::new();
    let mut covered_start = start;

    for vma in mm_guard.iter() {
        // Skip VMAs that don't overlap with our range
        if vma.end <= start || vma.start >= end {
            continue;
        }

        // Check for gaps - the range must be fully mapped
        if vma.start > covered_start {
            // Gap found - return ENOMEM (Linux behavior for unmapped region)
            return ENOMEM;
        }

        // Calculate the portion of this VMA that falls within our range
        let update_start = vma.start.max(start);
        let update_end = vma.end.min(end);

        // Check if we're trying to write-protect a read-only file mapping
        // (simplified check - full implementation would check file permissions)
        if prot & PROT_WRITE != 0 && !vma.is_anonymous() && vma.is_shared() {
            // For shared file mappings, we'd need to check file write permissions
            // For now, we allow it (the page fault handler will handle actual access)
        }

        vmas_to_update.push((update_start, update_end, vma.prot));
        covered_start = vma.end;
    }

    // Check if we covered the entire range
    if covered_start < end {
        return ENOMEM; // Range not fully mapped
    }

    // Now update the VMA protection flags
    // Collect indices of modified VMAs for merging
    let mut modified_indices: Vec<usize> = Vec::new();
    for (idx, vma) in mm_guard.iter_mut().enumerate() {
        if vma.end <= start || vma.start >= end {
            continue;
        }

        // Update the protection flags for this VMA
        // Note: This is simplified - a full implementation would handle
        // VMA splitting if the mprotect range doesn't align with VMA boundaries
        vma.prot = prot;
        modified_indices.push(idx);
    }

    // Try to merge modified VMAs with adjacent VMAs (VMA merging optimization)
    // Process in reverse order to maintain valid indices after removals
    for &idx in modified_indices.iter().rev() {
        mm_guard.merge_adjacent(idx);
    }

    // Get page table root for page table updates
    #[cfg(target_arch = "x86_64")]
    let pt_root: u64 = {
        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }
        cr3
    };

    #[cfg(target_arch = "aarch64")]
    let pt_root: u64 = {
        let ttbr0: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack));
        }
        ttbr0 & !0xFFF
    };

    // Release mm lock before doing page table updates
    drop(mm_guard);

    // Update page table entries for all affected pages
    let writable = prot & PROT_WRITE != 0;
    let executable = prot & super::PROT_EXEC != 0;

    for (update_start, update_end, _old_prot) in vmas_to_update {
        let mut page = update_start;
        while page < update_end {
            #[cfg(target_arch = "x86_64")]
            {
                use crate::arch::x86_64::paging::X86_64PageTable;
                // Only update if the page is actually mapped
                X86_64PageTable::update_page_protection(pt_root, page, writable, executable);
            }

            #[cfg(target_arch = "aarch64")]
            {
                use crate::arch::aarch64::paging::Aarch64PageTable;
                // Only update if the page is actually mapped
                Aarch64PageTable::update_page_protection(pt_root, page, writable, executable);
            }

            page += PAGE_SIZE;
        }
    }

    0
}

// ============================================================================
// msync syscall
// ============================================================================

/// msync syscall - Synchronize a file with a memory map
///
/// Flushes changes made to the in-core copy of a file-backed mapping back
/// to the filesystem.
///
/// # Arguments
/// * `addr` - Start address (must be page-aligned)
/// * `length` - Length of region in bytes
/// * `flags` - Combination of MS_ASYNC, MS_SYNC, MS_INVALIDATE
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_msync(addr: u64, length: u64, flags: i32) -> i64 {
    // Validate flags - must have valid combination
    let valid_flags = MS_ASYNC | MS_INVALIDATE | MS_SYNC;
    if flags & !valid_flags != 0 {
        return EINVAL;
    }

    // MS_ASYNC and MS_SYNC are mutually exclusive
    if (flags & MS_ASYNC != 0) && (flags & MS_SYNC != 0) {
        return EINVAL;
    }

    // Validate alignment
    if addr & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }

    // Zero length: success (no-op)
    if length == 0 {
        return 0;
    }

    // Round up length to page boundary
    let length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return ENOMEM,
    };

    let mm_guard = mm.lock();
    let end = addr.saturating_add(length);

    // Walk VMAs in range
    for vma in mm_guard.iter() {
        // Skip VMAs outside our range
        if vma.end <= addr || vma.start >= end {
            continue;
        }

        // MS_INVALIDATE on locked pages returns EBUSY (Linux behavior)
        if flags & MS_INVALIDATE != 0 && vma.is_locked() {
            return EBUSY;
        }

        // MS_SYNC on shared file-backed mapping: sync to disk
        if flags & MS_SYNC != 0
            && vma.is_shared()
            && let Some(ref file) = vma.file
        {
            // Sync the file - this uses fsync for now
            // A more sophisticated implementation would only sync the affected range
            if file.f_op.fsync(file).is_err() {
                return EIO;
            }
        }
        // MS_ASYNC: schedule async write but don't wait
        // In modern Linux this is essentially a no-op as dirty pages are
        // already scheduled for writeback. We do nothing here.
    }

    0
}

// ============================================================================
// madvise syscall
// ============================================================================

/// madvise syscall - Give advice about use of memory
///
/// Advises the kernel about how to handle paging I/O in the specified
/// address range.
///
/// # Arguments
/// * `addr` - Start address (must be page-aligned)
/// * `length` - Length of region in bytes
/// * `advice` - Type of advice (MADV_*)
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_madvise(addr: u64, length: u64, advice: i32) -> i64 {
    // Validate alignment
    if addr & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }

    // Round up length to page boundary
    let length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // Zero length: no-op success
    if length == 0 {
        return 0;
    }

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return ENOMEM,
    };

    let end = addr.saturating_add(length);

    match advice {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_DONTFORK | MADV_DOFORK
        | MADV_DONTDUMP | MADV_DODUMP => {
            // These advices just update VMA flags
            madvise_update_vma_flags(&mm, addr, end, advice)
        }
        MADV_WILLNEED => {
            // Prefault pages (reuse populate_range)
            populate_range(addr, length);
            0
        }
        MADV_DONTNEED => {
            // Zap pages - unmap and free
            madvise_dontneed(&mm, addr, end)
        }
        MADV_FREE => {
            // Mark pages as lazily freeable
            // Simplified: treat as DONTNEED (kernel frees pages immediately)
            madvise_dontneed(&mm, addr, end)
        }
        _ => EINVAL,
    }
}

/// Update VMA flags based on madvise advice
fn madvise_update_vma_flags(
    mm: &alloc::sync::Arc<spin::Mutex<super::MmStruct>>,
    start: u64,
    end: u64,
    advice: i32,
) -> i64 {
    let mut mm_guard = mm.lock();

    // Walk VMAs and update flags, collect indices for merging
    let mut modified_indices: Vec<usize> = Vec::new();
    for (idx, vma) in mm_guard.iter_mut().enumerate() {
        // Skip VMAs outside our range
        if vma.end <= start || vma.start >= end {
            continue;
        }

        match advice {
            MADV_NORMAL => {
                // Clear read hints
                vma.flags &= !(VM_RAND_READ | VM_SEQ_READ);
            }
            MADV_RANDOM => {
                // Set random access hint
                vma.flags = (vma.flags & !VM_SEQ_READ) | VM_RAND_READ;
            }
            MADV_SEQUENTIAL => {
                // Set sequential access hint
                vma.flags = (vma.flags & !VM_RAND_READ) | VM_SEQ_READ;
            }
            MADV_DONTFORK => {
                // Set don't copy on fork
                vma.flags |= VM_DONTCOPY;
            }
            MADV_DOFORK => {
                // Clear don't copy on fork
                vma.flags &= !VM_DONTCOPY;
            }
            MADV_DONTDUMP => {
                // Set don't include in core dumps
                vma.flags |= VM_DONTDUMP;
            }
            MADV_DODUMP => {
                // Clear don't include in core dumps
                vma.flags &= !VM_DONTDUMP;
            }
            _ => {}
        }
        modified_indices.push(idx);
    }

    // Try to merge modified VMAs with adjacent VMAs (VMA merging optimization)
    // Process in reverse order to maintain valid indices after removals
    for &idx in modified_indices.iter().rev() {
        mm_guard.merge_adjacent(idx);
    }

    0
}

/// Handle MADV_DONTNEED - zap pages in range
fn madvise_dontneed(
    mm: &alloc::sync::Arc<spin::Mutex<super::MmStruct>>,
    start: u64,
    end: u64,
) -> i64 {
    {
        let mm_guard = mm.lock();

        // Check for locked VMAs - can't DONTNEED locked pages
        for vma in mm_guard.iter() {
            if vma.end <= start || vma.start >= end {
                continue;
            }
            if vma.is_locked() {
                return EINVAL;
            }
        }
    }

    // Unmap pages in range (reuse existing infrastructure)
    unmap_pages_range(start, end);

    0
}

// ============================================================================
// mremap syscall
// ============================================================================

/// mremap syscall - Remap a virtual memory region
///
/// Resizes and/or moves an existing memory mapping. This is used by realloc()
/// for large allocations.
///
/// # Arguments
/// * `old_addr` - Start address of existing mapping (must be page-aligned)
/// * `old_len` - Old length of mapping in bytes
/// * `new_len` - New length of mapping in bytes
/// * `flags` - MREMAP_* flags
/// * `new_addr` - New address (only used with MREMAP_FIXED)
///
/// # Returns
/// New address on success, negative errno on failure
pub fn sys_mremap(old_addr: u64, old_len: u64, new_len: u64, flags: u32, new_addr: u64) -> i64 {
    // Validate flags
    let may_move = flags & MREMAP_MAYMOVE != 0;
    let fixed = flags & MREMAP_FIXED != 0;
    let dontunmap = flags & MREMAP_DONTUNMAP != 0;

    // Check for invalid flag combinations
    let valid_flags = MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP;
    if flags & !valid_flags != 0 {
        return EINVAL;
    }

    // MREMAP_FIXED implies MREMAP_MAYMOVE (Linux behavior)
    if fixed && !may_move {
        return EINVAL;
    }

    // MREMAP_DONTUNMAP requires MREMAP_MAYMOVE
    if dontunmap && !may_move {
        return EINVAL;
    }

    // Validate address alignment
    if old_addr & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }

    // new_len must be > 0
    if new_len == 0 {
        return EINVAL;
    }

    // Round lengths to page boundaries
    let old_len = (old_len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let new_len_aligned = (new_len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // old_len == 0 is special: creates new mapping at old_addr (deprecated, return EINVAL)
    if old_len == 0 {
        return EINVAL;
    }

    // Check for overflow
    if old_addr.checked_add(old_len).is_none() {
        return EINVAL;
    }

    // MREMAP_FIXED: validate new_addr
    if fixed {
        if new_addr & (PAGE_SIZE - 1) != 0 {
            return EINVAL;
        }
        // new_addr must not overlap with old range (unless DONTUNMAP)
        if !dontunmap {
            let new_end = match new_addr.checked_add(new_len_aligned) {
                Some(e) => e,
                None => return EINVAL,
            };
            let old_end = old_addr + old_len;
            // Check for overlap
            if !(new_end <= old_addr || new_addr >= old_end) {
                return EINVAL;
            }
        }
    }

    // MREMAP_DONTUNMAP requires old_len == new_len
    if dontunmap && old_len != new_len_aligned {
        return EINVAL;
    }

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return EFAULT,
    };

    let mut mm_guard = mm.lock();

    // Find VMA containing old_addr
    let vma_idx = match mm_guard.find_vma_exact(old_addr) {
        Some(idx) => idx,
        None => {
            // Try find_vma_index in case old_addr is not exactly at VMA start
            // Linux allows mremap on any VMA that contains old_addr
            match mm_guard.find_vma_index(old_addr) {
                Some(idx) => {
                    // Check if old_addr is at VMA start
                    if let Some(vma) = mm_guard.get_vma(idx)
                        && vma.start != old_addr
                    {
                        // For simplicity, require old_addr to be at VMA start
                        return EFAULT;
                    }
                    idx
                }
                None => return EFAULT,
            }
        }
    };

    // Validate the VMA covers the requested range
    {
        let vma = match mm_guard.get_vma(vma_idx) {
            Some(v) => v,
            None => return EFAULT,
        };

        // Check that the VMA covers [old_addr, old_addr + old_len)
        if vma.end < old_addr + old_len {
            return EFAULT;
        }
    }

    // Handle shrink: new_len < old_len
    if new_len_aligned < old_len {
        // Unmap the tail portion
        let unmap_start = old_addr + new_len_aligned;
        let unmap_end = old_addr + old_len;

        // Update VMA end
        if let Some(vma) = mm_guard.get_vma_mut(vma_idx) {
            vma.end = old_addr + new_len_aligned;
        }

        // Update total_vm
        let shrink_pages = (old_len - new_len_aligned) / PAGE_SIZE;
        mm_guard.sub_total_vm(shrink_pages);

        // Release lock before page table operations
        drop(mm_guard);

        // Unmap the pages
        unmap_pages_range(unmap_start, unmap_end);

        return old_addr as i64;
    }

    // Handle expand: new_len > old_len
    if new_len_aligned > old_len {
        // Check RLIMIT_AS before expansion
        let expansion = new_len_aligned - old_len;
        let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_AS);
        if limit != crate::rlimit::RLIM_INFINITY {
            let current_bytes = mm_guard.total_vm() * PAGE_SIZE;
            if current_bytes.saturating_add(expansion) > limit {
                return ENOMEM;
            }
        }

        // Try in-place expansion first
        let new_end = old_addr + new_len_aligned;
        if mm_guard.try_expand_vma(vma_idx, new_end) {
            // Success - VMA expanded in place
            return old_addr as i64;
        }

        // In-place expansion failed (collision with next VMA)
        // Need to move if MREMAP_MAYMOVE is set
        if !may_move && !fixed {
            return ENOMEM;
        }

        // Clone VMA info before modifications
        let vma_clone = match mm_guard.get_vma(vma_idx) {
            Some(v) => v.clone(),
            None => return EFAULT,
        };

        // Determine target address
        let target_addr = if fixed {
            // MREMAP_FIXED: use specified address
            // First, unmap any existing mappings at target
            let target_end = new_addr + new_len_aligned;
            let _ = mm_guard.remove_range(new_addr, target_end);
            new_addr
        } else {
            // Find a new free area
            match mm_guard.find_free_area(new_len_aligned) {
                Some(addr) => addr,
                None => return ENOMEM,
            }
        };

        // Create new VMA at target location
        let mut new_vma = vma_clone.clone();
        new_vma.start = target_addr;
        new_vma.end = target_addr + new_len_aligned;

        // Insert new VMA
        let new_idx = mm_guard.insert_vma(new_vma);
        mm_guard.add_total_vm(new_len_aligned / PAGE_SIZE);
        // Try to merge with adjacent VMAs (VMA merging optimization)
        mm_guard.merge_adjacent(new_idx);

        // Handle old VMA based on DONTUNMAP flag
        if dontunmap {
            // Keep the old VMA but mark it as anonymous (no file backing)
            if let Some(vma) = mm_guard.get_vma_mut(vma_idx) {
                vma.file = None;
                vma.flags |= MAP_ANONYMOUS;
            }
        } else {
            // Remove old VMA
            let _ = mm_guard.remove_vma(vma_idx);
        }

        // Release lock before page table operations
        drop(mm_guard);

        // Move page table entries
        move_page_tables(old_addr, target_addr, old_len, dontunmap);

        return target_addr as i64;
    }

    // Same size - handle MREMAP_FIXED (move to new location)
    if fixed {
        // Clone VMA info
        let vma_clone = match mm_guard.get_vma(vma_idx) {
            Some(v) => v.clone(),
            None => return EFAULT,
        };

        // Unmap any existing mappings at target
        let target_end = new_addr + new_len_aligned;
        let _ = mm_guard.remove_range(new_addr, target_end);

        // Create new VMA at target
        let mut new_vma = vma_clone.clone();
        new_vma.start = new_addr;
        new_vma.end = new_addr + new_len_aligned;
        let new_idx = mm_guard.insert_vma(new_vma);
        mm_guard.add_total_vm(new_len_aligned / PAGE_SIZE);
        // Try to merge with adjacent VMAs (VMA merging optimization)
        mm_guard.merge_adjacent(new_idx);

        // Handle old VMA
        if dontunmap {
            if let Some(vma) = mm_guard.get_vma_mut(vma_idx) {
                vma.file = None;
                vma.flags |= MAP_ANONYMOUS;
            }
        } else {
            let _ = mm_guard.remove_vma(vma_idx);
        }

        drop(mm_guard);

        move_page_tables(old_addr, new_addr, old_len, dontunmap);

        return new_addr as i64;
    }

    // Same size, no flags - just return old address
    old_addr as i64
}

/// Move page table entries from old location to new location
fn move_page_tables(old_start: u64, new_start: u64, len: u64, keep_old: bool) {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::FRAME_ALLOCATOR;
        use crate::arch::x86_64::paging::X86_64PageTable;

        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }

        let mut offset: u64 = 0;
        while offset < len {
            let old_addr = old_start + offset;
            let new_addr = new_start + offset;

            // Check if old page is mapped
            if let Some((phys, flags)) = X86_64PageTable::read_pte(cr3, old_addr) {
                // Map at new location
                let _ = crate::arch::x86_64::interrupts::map_user_page(cr3, new_addr, phys, flags);
                // Increment frame refcount since we have a new mapping
                FRAME_ALLOCATOR.incref(phys);

                if !keep_old {
                    // Unmap old location
                    if let Some(old_phys) = X86_64PageTable::unmap_page(cr3, old_addr) {
                        FRAME_ALLOCATOR.decref(old_phys);
                    }
                }
            }

            offset += PAGE_SIZE;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::FRAME_ALLOCATOR;
        use crate::arch::aarch64::paging::Aarch64PageTable;

        // Page descriptor bits for L3 entries (must be 0b11 for valid page)
        const DESC_PAGE: u64 = 0b11;

        let ttbr0: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack));
        }
        let pt_phys = ttbr0 & !0xFFF;

        let mut offset: u64 = 0;
        while offset < len {
            let old_addr = old_start + offset;
            let new_addr = new_start + offset;

            // Check if old page is mapped
            if let Some((phys, attrs)) = Aarch64PageTable::read_pte(pt_phys, old_addr) {
                // Map at new location - add page descriptor bits that read_pte strips
                let _ = crate::arch::aarch64::exceptions::map_user_page(
                    pt_phys,
                    new_addr,
                    phys,
                    attrs | DESC_PAGE,
                );
                // Increment frame refcount
                FRAME_ALLOCATOR.incref(phys);

                if !keep_old {
                    // Unmap old location
                    if let Some(old_phys) = Aarch64PageTable::unmap_page(pt_phys, old_addr) {
                        FRAME_ALLOCATOR.decref(old_phys);
                    }
                }
            }

            offset += PAGE_SIZE;
        }
    }
}

// ============================================================================
// mincore syscall
// ============================================================================

/// mincore syscall - Determine whether pages are resident in memory
///
/// Reports whether pages in the specified address range are resident in
/// physical memory (i.e., will not cause a page fault when accessed).
///
/// # Arguments
/// * `addr` - Start address (must be page-aligned)
/// * `length` - Length of region in bytes
/// * `vec` - User-space pointer to result vector (1 byte per page)
///
/// # Returns
/// 0 on success, negative errno on failure
///
/// # Output Vector
/// Each byte in vec corresponds to one page. The least significant bit is set
/// if the page is currently resident in memory.
pub fn sys_mincore(addr: u64, length: u64, vec: u64) -> i64 {
    // Validate address alignment
    if addr & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }

    // Zero length: success (no pages to check)
    if length == 0 {
        return 0;
    }

    // Calculate number of pages
    let num_pages = length.div_ceil(PAGE_SIZE);

    // Check for overflow
    if addr.checked_add(num_pages * PAGE_SIZE).is_none() {
        return ENOMEM;
    }

    // Get current task's MM
    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return ENOMEM,
    };

    let mm_guard = mm.lock();

    // Build result vector
    let mut result: Vec<u8> = Vec::with_capacity(num_pages as usize);

    // Get page table root and check each page
    #[cfg(target_arch = "x86_64")]
    {
        use crate::arch::x86_64::paging::X86_64PageTable;

        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }

        for i in 0..num_pages {
            let page_addr = addr + i * PAGE_SIZE;

            // Check if address is in a valid VMA
            let in_vma = mm_guard.find_vma(page_addr).is_some();
            if !in_vma {
                return ENOMEM;
            }

            // Check if page is resident
            let resident = X86_64PageTable::translate_with_root(cr3, page_addr).is_some();
            result.push(if resident { 1 } else { 0 });
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::paging::Aarch64PageTable;

        let ttbr0: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack));
        }
        let pt_phys = ttbr0 & !0xFFF;

        for i in 0..num_pages {
            let page_addr = addr + i * PAGE_SIZE;

            // Check if address is in a valid VMA
            let in_vma = mm_guard.find_vma(page_addr).is_some();
            if !in_vma {
                return ENOMEM;
            }

            // Check if page is resident
            let resident = Aarch64PageTable::translate_with_root(pt_phys, page_addr).is_some();
            result.push(if resident { 1 } else { 0 });
        }
    }

    // Drop the mm lock before copying to user space
    drop(mm_guard);

    // Copy result to user space
    let vec_ptr = vec as *mut u8;
    for (i, &byte) in result.iter().enumerate() {
        unsafe {
            // Safety: We're writing to user-space memory
            // A more robust implementation would use proper Uaccess methods
            core::ptr::write_volatile(vec_ptr.add(i), byte);
        }
    }

    0
}
