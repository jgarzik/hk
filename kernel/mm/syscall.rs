//! Memory management syscalls (mmap, munmap, brk, mlock)

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::File;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;

use super::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_GROWSDOWN, MAP_LOCKED, MAP_NONBLOCK,
    MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE, MREMAP_DONTUNMAP, MREMAP_FIXED, MREMAP_MAYMOVE,
    MS_ASYNC, MS_INVALIDATE, MS_SYNC, PAGE_SIZE, PROT_GROWSDOWN, PROT_GROWSUP, PROT_READ,
    PROT_WRITE, VM_GROWSDOWN, VM_LOCKED, VM_LOCKED_MASK, VM_LOCKONFAULT, VM_NORESERVE, VM_SHARED,
    Vma, anon_vma::AnonVma, get_task_mm,
};
use crate::error::KernelError;

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
/// File checks of do_mmap (Linux): the file must be readable, a shared
/// writable mapping needs it open for writing and not append-only, and
/// PROT_EXEC is refused on a noexec mount (`noexec`: EPERM for mmap,
/// EACCES for mprotect, where Linux clears VM_MAYEXEC)
fn file_prot_ok(f: &File, prot: u32, shared: bool, noexec: KernelError) -> Result<(), KernelError> {
    use crate::fs::flags::O_APPEND;
    use crate::fs::mount::{MNT_NOEXEC, mnt_flags_of};
    if !f.is_readable() {
        return Err(KernelError::PermissionDenied);
    }
    if shared && prot & PROT_WRITE != 0 && (!f.is_writable() || f.get_flags() & O_APPEND != 0) {
        return Err(KernelError::PermissionDenied);
    }
    if prot & super::PROT_EXEC != 0 && mnt_flags_of(&f.dentry) & MNT_NOEXEC != 0 {
        return Err(noexec);
    }
    Ok(())
}

pub fn sys_mmap(addr: u64, length: u64, prot: u32, flags: u32, fd: i32, offset: u64) -> i64 {
    // Validate length
    if length == 0 {
        return KernelError::InvalidArgument.sysret();
    }
    if length > super::TASK_SIZE {
        return KernelError::OutOfMemory.sysret();
    }

    // Round up length to page boundary
    let length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // Validate offset alignment
    if offset & (PAGE_SIZE - 1) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    let is_anonymous = flags & MAP_ANONYMOUS != 0;
    let is_fixed = flags & MAP_FIXED != 0;
    let is_fixed_noreplace = flags & MAP_FIXED_NOREPLACE != 0;

    // Check sharing mode: MAP_SHARED (0x01), MAP_PRIVATE (0x02), or MAP_SHARED_VALIDATE (0x03)
    // MAP_SHARED_VALIDATE is special - it's MAP_SHARED | MAP_PRIVATE bits together,
    // and means "shared mapping with strict flag validation"
    let share_mode = flags & super::MAP_SHARED_VALIDATE; // Mask to just these 2 bits
    let (is_shared, is_shared_validate) = match share_mode {
        0x01 => (true, false),  // MAP_SHARED
        0x02 => (false, false), // MAP_PRIVATE
        0x03 => {
            // MAP_SHARED_VALIDATE - shared with strict validation
            // If MAP_SYNC is requested, we must reject since we don't support DAX
            if flags & super::MAP_SYNC != 0 {
                return -95_i64; // EOPNOTSUPP - no DAX filesystem support
            }
            (true, true)
        }
        _ => return KernelError::InvalidArgument.sysret(), // 0x00 = neither specified
    };
    let is_private = !is_shared;
    // Suppress unused warning - is_shared_validate is for future validation
    let _ = is_shared_validate;

    // Get file if not anonymous
    let file: Option<Arc<File>> = if !is_anonymous {
        if fd < 0 {
            return KernelError::BadFd.sysret();
        }
        let tid = current_tid();
        let fd_table = match get_task_fd(tid) {
            Some(t) => t,
            None => return KernelError::BadFd.sysret(),
        };
        match fd_table.lock().get(fd) {
            Some(f) => Some(f),
            None => return KernelError::BadFd.sysret(),
        }
    } else {
        None
    };
    if let Some(f) = &file
        && let Err(e) = file_prot_ok(f, prot, is_shared, KernelError::NotPermitted)
    {
        return e.sysret();
    }

    // Every user task has an address space; kernel threads have none
    let tid = current_tid();
    let Some(mm) = get_task_mm(tid) else {
        return KernelError::OutOfMemory.sysret();
    };

    // Mappings replaced by MAP_FIXED: declared first so that they are
    // dropped after the lock on every return
    let mut replaced = Vec::new();
    let mut mm_guard = mm.lock();

    // Determine mapping address
    let map_addr = if is_fixed || is_fixed_noreplace {
        // MAP_FIXED or MAP_FIXED_NOREPLACE: use exact address
        if addr & (PAGE_SIZE - 1) != 0 {
            return KernelError::InvalidArgument.sysret(); // Must be page-aligned
        }
        if let Err(e) = super::check_fixed(addr, length) {
            return e.sysret();
        }
        // MAP_FIXED_NOREPLACE: fail if address range overlaps existing mapping
        if is_fixed_noreplace && mm_guard.overlaps(addr, addr + length) {
            return KernelError::AlreadyExists.sysret();
        }
        // MAP_FIXED: unmap whatever was there (dropped after unlocking)
        if is_fixed {
            replaced = munmap_locked(&mut mm_guard, mm.pgd(), addr, addr + length);
        }
        addr
    } else if addr != 0 && super::hint_ok(addr & !(PAGE_SIZE - 1), length) {
        // Hint address - try to use it, fall back to search
        let aligned = addr & !(PAGE_SIZE - 1);
        if !mm_guard.overlaps(aligned, aligned + length) {
            aligned
        } else {
            match mm_guard.find_free_area(length) {
                Some(a) => a,
                None => return KernelError::OutOfMemory.sysret(),
            }
        }
    } else {
        // No hint - find free area
        match mm_guard.find_free_area(length) {
            Some(a) => a,
            None => return KernelError::OutOfMemory.sysret(),
        }
    };

    // Check RLIMIT_AS (address space limit) before creating VMA
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_AS);
    if limit != crate::rlimit::RLIM_INFINITY {
        let current_bytes = mm_guard.total_vm() * PAGE_SIZE;
        if current_bytes.saturating_add(length) > limit {
            return KernelError::OutOfMemory.sysret();
        }
    }

    // Create VMA
    let mut vma = if let Some(f) = file {
        Vma::new_file(map_addr, map_addr + length, prot, flags, f, offset)
    } else {
        // Anonymous mapping
        let mut v = Vma::new(map_addr, map_addr + length, prot, flags | MAP_ANONYMOUS);
        // Set up anon_vma for private anonymous mappings (for swap-out
        // reverse mapping); shared ones get a shared object for their
        // pages (Linux shmem_zero_setup)
        if is_private {
            let anon_vma = AnonVma::new();
            anon_vma.add_vma(mm.pgd(), map_addr, map_addr + length);
            v.set_anon_vma(anon_vma);
        } else {
            v.shmem = Some(super::shmem::Shmem::new(length / PAGE_SIZE));
        }
        v
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

    // Set VM_NORESERVE for mappings that don't require swap reservation
    // Linux: calc_vm_flag_bits() translates MAP_NORESERVE to VM_NORESERVE
    if flags & MAP_NORESERVE != 0 {
        vma.flags |= VM_NORESERVE;
    }

    // Handle MAP_LOCKED flag - lock pages in memory
    // Linux: do_mmap() checks can_do_mlock() and mlock_future_ok()
    let is_map_locked = flags & MAP_LOCKED != 0;
    if is_map_locked {
        // Permission check
        if !can_do_mlock() {
            return KernelError::NotPermitted.sysret();
        }

        // Check RLIMIT_MEMLOCK (CAP_IPC_LOCK bypasses limit)
        let pages = length / PAGE_SIZE;
        if !crate::task::capable(crate::task::CAP_IPC_LOCK) {
            let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_MEMLOCK);
            if limit != crate::rlimit::RLIM_INFINITY {
                let current_bytes = mm_guard.locked_vm() * PAGE_SIZE;
                let requested_bytes = pages * PAGE_SIZE;
                if current_bytes.saturating_add(requested_bytes) > limit {
                    return KernelError::WouldBlock.sysret();
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
                    return KernelError::WouldBlock.sysret();
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
    drop(replaced);

    if should_populate {
        let _ = populate_range(map_addr, length);
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
        return KernelError::InvalidArgument.sysret();
    }

    if length == 0 {
        return KernelError::InvalidArgument.sysret();
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
    let removed = munmap_locked(&mut mm_guard, mm.pgd(), addr, end);
    drop(mm_guard);
    // The VMAs may hold the last reference to a mapped file
    drop(removed);
    0
}

/// Unmap [start, end) of the current address space, mmap lock held
/// (Linux do_vmi_munmap): VMAs straddling the edges are split, the
/// pages inside are released (`memory::zap_range`), the VM counters and
/// rmap chains updated. Returns the removed VMAs for the caller to drop
/// once it has unlocked.
pub(crate) fn munmap_locked(mm: &mut super::MmStruct, pgd: u64, start: u64, end: u64) -> Vec<Vma> {
    let removed = mm.remove_range(start, end);
    for vma in &removed {
        let pages = vma.size() / PAGE_SIZE;
        mm.sub_total_vm(pages);
        if vma.is_locked() {
            mm.sub_locked_vm(pages);
        }
        // Drop the address space's rmap chain once no VMA uses it
        if let Some(av) = &vma.anon_vma {
            let used = mm
                .iter()
                .any(|v| v.anon_vma.as_ref().is_some_and(|a| Arc::ptr_eq(a, av)));
            if !used {
                av.remove_root(pgd);
            }
        }
    }
    for vma in &removed {
        super::memory::zap_range(pgd, vma.start.max(start), vma.end.min(end));
    }
    #[cfg(feature = "mmcheck")]
    super::check::verify(mm, pgd, "munmap");
    removed
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
    let Some(mm) = get_task_mm(tid) else {
        return 0;
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
        // Unmap the freed part of the heap (the VMA below stays)
        let removed = munmap_locked(&mut mm_guard, mm.pgd(), new_brk_aligned, old_brk_aligned);
        mm_guard.update_brk(brk);
        drop(mm_guard);
        drop(removed);

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

/// Fault in the pages of [start, start + len) (Linux mm_populate /
/// populate_vma_page_range): a write fault for a private writable
/// mapping (copy-on-write is broken now), a read fault otherwise.
/// Inaccessible VMAs and holes are skipped. False if memory ran out
/// (mlock reports it; MAP_POPULATE and mlockall ignore it, like Linux
/// mm_populate).
///
/// Used by MAP_POPULATE, MAP_LOCKED and mlock/mlockall.
fn populate_range(start: u64, len: u64) -> bool {
    use super::fault::{Access, handle_mm_fault};

    let Some(mm) = get_task_mm(current_tid()) else {
        return true;
    };
    let end = start.saturating_add(len);
    let mut addr = start & !(PAGE_SIZE - 1);
    while addr < end {
        let access = match mm.lock().find_vma(addr) {
            Some(v) if v.prot & (PROT_READ | PROT_WRITE | super::PROT_EXEC) == 0 => None,
            Some(v) if v.is_writable() && !v.is_shared() => Some(Access::Write),
            Some(_) => Some(Access::Read),
            None => None,
        };
        if let Some(a) = access
            && handle_mm_fault(&mm, addr, a) == Err(super::fault::VmFault::Oom)
        {
            return false;
        }
        addr += PAGE_SIZE;
    }
    true
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
        return KernelError::InvalidArgument.sysret();
    }

    let mut vm_flags = VM_LOCKED;
    if flags & MLOCK_ONFAULT != 0 {
        vm_flags |= VM_LOCKONFAULT;
    }

    do_mlock(addr, len, vm_flags)
}

/// Common implementation for mlock/mlock2 (Linux do_mlock): the range
/// is widened to whole pages (a length that wraps doing so locks
/// nothing), checked against RLIMIT_MEMLOCK (ENOMEM; pages already
/// locked in it do not count again), locked VMA part by VMA part, then
/// faulted in unless MLOCK_ONFAULT
fn do_mlock(start: u64, len: u64, vm_flags: u32) -> i64 {
    if !can_do_mlock() {
        return KernelError::NotPermitted.sysret();
    }
    let (start, len) = lock_range(start, len);
    let Some(mm) = get_task_mm(current_tid()) else {
        return KernelError::OutOfMemory.sysret();
    };
    let mut map = mm.lock();
    let r = if memlock_room(&map, start, len) {
        mlock_vmas(&mut map, start, len, vm_flags)
    } else {
        Err(KernelError::OutOfMemory)
    };
    drop(map);
    if let Err(e) = r {
        return e.sysret();
    }
    // Out of memory faulting the pages in is EAGAIN (Linux
    // __mlock_posix_error_return)
    if vm_flags & VM_LOCKONFAULT == 0 && !populate_range(start, len) {
        return KernelError::WouldBlock.sysret();
    }
    0
}

/// [start, start + len) widened to whole pages, as Linux computes it:
/// the length rounded up after adding the start's offset in its page,
/// both wrapping
fn lock_range(start: u64, len: u64) -> (u64, u64) {
    let len = len.wrapping_add(start & (PAGE_SIZE - 1));
    let len = len.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    (start & !(PAGE_SIZE - 1), len)
}

/// Locking `len` more bytes at `start` fits RLIMIT_MEMLOCK (Linux
/// do_mlock): the whole length counts, less the pages of the range
/// already locked; CAP_IPC_LOCK has no limit
fn memlock_room(mm: &super::MmStruct, start: u64, len: u64) -> bool {
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_MEMLOCK) / PAGE_SIZE;
    let locked = len / PAGE_SIZE + mm.locked_vm();
    if locked <= limit || crate::task::capable(crate::task::CAP_IPC_LOCK) {
        return true;
    }
    locked - locked_in(mm, start, len) <= limit
}

/// Pages of [start, start + len) in locked VMAs (Linux
/// count_mm_mlocked_page_nr)
fn locked_in(mm: &super::MmStruct, start: u64, len: u64) -> u64 {
    let end = start.saturating_add(len);
    mm.iter()
        .filter(|v| v.is_locked() && v.end > start && v.start < end)
        .map(|v| (v.end.min(end) - v.start.max(start)) / PAGE_SIZE)
        .sum()
}

/// Give the VMAs of [start, start + len) the lock flags `vm_flags`
/// (VM_LOCKED, VM_LOCKONFAULT or none; Linux apply_vma_lock_flags),
/// part by part from `start`: a range that wraps is EINVAL, a hole is
/// ENOMEM, the VMAs before it keeping their new flags
fn mlock_vmas(
    mm: &mut super::MmStruct,
    start: u64,
    len: u64,
    vm_flags: u32,
) -> Result<(), KernelError> {
    let end = start.wrapping_add(len);
    if end < start {
        return Err(KernelError::InvalidArgument);
    }
    let mut addr = start;
    while addr < end {
        let i = mm.find_vma_index(addr).ok_or(KernelError::OutOfMemory)?;
        let e = mm.get_vma(i).map_or(end, |v| v.end.min(end));
        mlock_fixup(mm, i, addr, e, vm_flags);
        addr = e;
    }
    Ok(())
}

/// [start, end) of the VMA at `idx` takes the lock flags `vm_flags`
/// (Linux mlock_fixup): split off at the range edges, locked_vm
/// counted, and merged with its neighbours. No change: no split.
fn mlock_fixup(mm: &mut super::MmStruct, idx: usize, start: u64, end: u64, vm_flags: u32) {
    let Some(old) = mm.get_vma(idx).map(|v| v.flags) else {
        return;
    };
    let new = (old & !VM_LOCKED_MASK) | vm_flags;
    if new == old {
        return;
    }
    mm.split_at(start);
    mm.split_at(end);
    let Some(i) = mm.find_vma_exact(start) else {
        return;
    };
    if let Some(v) = mm.get_vma_mut(i) {
        v.flags = new;
    }
    let pages = (end - start) / PAGE_SIZE;
    match (old & VM_LOCKED != 0, new & VM_LOCKED != 0) {
        (false, true) => mm.add_locked_vm(pages),
        (true, false) => mm.sub_locked_vm(pages),
        _ => {}
    }
    mm.merge_adjacent(i);
}

/// munlock syscall - Unlock pages (Linux munlock): the range as mlock
/// computes it, unlocked VMA part by VMA part (EINVAL if it wraps,
/// ENOMEM at a hole)
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_munlock(addr: u64, len: u64) -> i64 {
    let (start, len) = lock_range(addr, len);
    let Some(mm) = get_task_mm(current_tid()) else {
        return 0;
    };
    let r = mlock_vmas(&mut mm.lock(), start, len, 0);
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
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
        return KernelError::InvalidArgument.sysret();
    }
    if flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 {
        return KernelError::InvalidArgument.sysret();
    }
    // MCL_ONFAULT alone is invalid
    if flags == MCL_ONFAULT {
        return KernelError::InvalidArgument.sysret();
    }

    // Permission check
    if !can_do_mlock() {
        return KernelError::NotPermitted.sysret();
    }

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return KernelError::OutOfMemory.sysret(),
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
                    return KernelError::WouldBlock.sysret();
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
            let _ = populate_range(start, len);
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
        return KernelError::InvalidArgument.sysret();
    }

    // Zero length is a no-op (success per Linux behavior)
    if len == 0 {
        return 0;
    }

    // Validate alignment
    if addr & (PAGE_SIZE - 1) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Round up length to page boundary
    let len_aligned = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let mut end = match addr.checked_add(len_aligned) {
        Some(e) => e,
        None => return KernelError::InvalidArgument.sysret(), // Overflow
    };

    // Validate protection flags (PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM are valid)
    // Note: PROT_SEM is accepted but is a no-op on x86-64/aarch64 (Linux behavior)
    if prot & !(PROT_READ | PROT_WRITE | super::PROT_EXEC | super::PROT_SEM) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return KernelError::InvalidArgument.sysret(), // No mm
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
                return KernelError::OutOfMemory.sysret();
            }
            // VMA must have VM_GROWSDOWN flag
            if !vma.is_growsdown() {
                return KernelError::InvalidArgument.sysret();
            }
            // Extend start to VMA start
            start = vma.start;
        } else {
            return KernelError::OutOfMemory.sysret();
        }
    }

    // Handle PROT_GROWSUP - always fails on x86-64/aarch64
    // Linux: mm/mprotect.c - checks for VM_GROWSUP which never exists on these architectures
    if grows & PROT_GROWSUP != 0 {
        // Find VMA containing the end of range
        let check_addr = end.saturating_sub(1);
        if let Some(vma) = mm_guard.find_vma(check_addr) {
            if vma.start > check_addr || check_addr >= vma.end {
                return KernelError::OutOfMemory.sysret();
            }
            // VM_GROWSUP is never set on x86-64/aarch64 (only parisc has upward-growing stacks)
            // So this always fails with KernelError::InvalidArgument.sysret(), matching Linux behavior
            return KernelError::InvalidArgument.sysret();
        } else {
            return KernelError::OutOfMemory.sysret();
        }
    }

    // Recalculate end based on potentially adjusted start
    if start != addr {
        end = start.saturating_add(end.saturating_sub(addr));
    }

    // Validate the range is fully mapped and the change allowed
    let mut covered_start = start;

    for vma in mm_guard.iter() {
        // Skip VMAs that don't overlap with our range
        if vma.end <= start || vma.start >= end {
            continue;
        }

        // Check for gaps - the range must be fully mapped
        if vma.start > covered_start {
            // Gap found - return KernelError::OutOfMemory.sysret() (Linux behavior for unmapped region)
            return KernelError::OutOfMemory.sysret();
        }

        // Added permissions must be allowed by the mapped file (Linux
        // VM_MAYWRITE / VM_MAYEXEC)
        if let Some(f) = &vma.file
            && let Err(e) = file_prot_ok(
                f,
                prot & !vma.prot,
                vma.is_shared(),
                KernelError::PermissionDenied,
            )
        {
            return e.sysret();
        }
        // A SHM_RDONLY attachment cannot be made writable (Linux: no
        // VM_MAYWRITE)
        if prot & PROT_WRITE != 0 && vma.shm.as_ref().is_some_and(|a| a.rdonly()) {
            return KernelError::PermissionDenied.sysret();
        }

        covered_start = vma.end;
    }

    // Check if we covered the entire range
    if covered_start < end {
        return KernelError::OutOfMemory.sysret(); // Range not fully mapped
    }

    // 2MB pages that cannot keep one entry are split before anything
    // changes: ENOMEM leaves the range as it was
    let pgd = mm.pgd();
    if let Err(e) = super::mprotect::split_huge(pgd, start, end, prot) {
        return e.sysret();
    }

    // Each VMA in the range in turn (Linux mprotect_fixup): split at the
    // range edges, take the new protection, and have the PTEs it maps
    // rewritten to match, all under this one mm lock hold (a fault or
    // fork never sees a VMA and its entries disagree). The TLB of the
    // range is flushed before the lock is dropped, also on an error.
    let r = mprotect_vmas(&mut mm_guard, pgd, start, end, prot);
    crate::arch::paging::flush_tlb_range(start, end);
    #[cfg(feature = "mmcheck")]
    super::check::verify(&mm_guard, pgd, "mprotect");
    drop(mm_guard);
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

/// Give the VMAs of [start, end) (checked to cover it) protection
/// `prot`, and their mapped PTEs with them (`mprotect::change_protection`
/// on exactly each updated VMA), then merge. A split that fails stops
/// with ENOMEM: VMAs already done are complete, the rest untouched.
fn mprotect_vmas(
    mm: &mut super::MmStruct,
    pgd: u64,
    start: u64,
    end: u64,
    prot: u32,
) -> Result<(), KernelError> {
    let mut modified: Vec<usize> = Vec::new();
    let mut idx = 0;
    let mut r = Ok(());
    while let Some(vma) = mm.get_vma(idx) {
        if vma.end <= start {
            idx += 1;
            continue;
        }
        if vma.start >= end {
            break;
        }
        if start > vma.start {
            if mm.split_vma(idx, start).is_none() {
                r = Err(KernelError::OutOfMemory);
                break;
            }
            idx += 1;
        }
        if mm.get_vma(idx).is_some_and(|v| end < v.end) && mm.split_vma(idx, end).is_none() {
            r = Err(KernelError::OutOfMemory);
            break;
        }
        let Some(vma) = mm.get_vma_mut(idx) else {
            break;
        };
        vma.prot = prot;
        let (s, e, shared) = (vma.start, vma.end, vma.is_shared());
        super::mprotect::change_protection(pgd, s, e, prot, shared);
        modified.push(idx);
        idx += 1;
    }
    // Merging keeps each page's protection: VMAs and PTEs still agree
    for &i in modified.iter().rev() {
        mm.merge_adjacent(i);
    }
    r
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
        return KernelError::InvalidArgument.sysret();
    }

    // MS_ASYNC and MS_SYNC are mutually exclusive
    if (flags & MS_ASYNC != 0) && (flags & MS_SYNC != 0) {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate alignment
    if addr & (PAGE_SIZE - 1) != 0 {
        return KernelError::InvalidArgument.sysret();
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
        None => return KernelError::OutOfMemory.sysret(),
    };

    let mm_guard = mm.lock();
    let end = addr.saturating_add(length);

    // Walk VMAs in range
    for vma in mm_guard.iter() {
        // Skip VMAs outside our range
        if vma.end <= addr || vma.start >= end {
            continue;
        }

        // MS_INVALIDATE on locked pages returns KernelError::Busy.sysret() (Linux behavior)
        if flags & MS_INVALIDATE != 0 && vma.is_locked() {
            return KernelError::Busy.sysret();
        }

        // MS_SYNC on shared file-backed mapping: sync to disk
        if flags & MS_SYNC != 0
            && vma.is_shared()
            && let Some(ref file) = vma.file
        {
            // Sync the file - this uses fsync for now
            // A more sophisticated implementation would only sync the affected range
            if file.f_op.fsync(file).is_err() {
                return KernelError::Io.sysret();
            }
        }
        // MS_ASYNC: schedule async write but don't wait
        // In modern Linux this is essentially a no-op as dirty pages are
        // already scheduled for writeback. We do nothing here.
    }

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
        return KernelError::InvalidArgument.sysret();
    }

    // MREMAP_FIXED implies MREMAP_MAYMOVE (Linux behavior)
    if fixed && !may_move {
        return KernelError::InvalidArgument.sysret();
    }

    // MREMAP_DONTUNMAP requires MREMAP_MAYMOVE
    if dontunmap && !may_move {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate address alignment
    if old_addr & (PAGE_SIZE - 1) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Lengths at most TASK_SIZE once page-aligned, the new one not zero
    // (Linux check_mremap_params; rounding cannot wrap below that)
    if new_len == 0 || new_len > super::TASK_SIZE || old_len > super::TASK_SIZE {
        return KernelError::InvalidArgument.sysret();
    }
    let old_len = (old_len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let new_len_aligned = (new_len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // old_len == 0 is special: creates new mapping at old_addr (deprecated, return KernelError::InvalidArgument.sysret())
    if old_len == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Check for overflow
    if old_addr.checked_add(old_len).is_none() {
        return KernelError::InvalidArgument.sysret();
    }

    // MREMAP_FIXED: validate new_addr
    if fixed {
        if new_addr & (PAGE_SIZE - 1) != 0 {
            return KernelError::InvalidArgument.sysret();
        }
        // The new range must not overlap the old one (Linux
        // vrm_overlaps, MREMAP_DONTUNMAP included) and must end in
        // user space
        let new_end = match new_addr.checked_add(new_len_aligned) {
            Some(e) => e,
            None => return KernelError::InvalidArgument.sysret(),
        };
        if (new_end > old_addr && new_addr < old_addr + old_len) || new_end > super::TASK_SIZE {
            return KernelError::InvalidArgument.sysret();
        }
        if let Err(e) = super::check_fixed(new_addr, new_len_aligned) {
            return e.sysret();
        }
    }

    // MREMAP_DONTUNMAP requires old_len == new_len
    if dontunmap && old_len != new_len_aligned {
        return KernelError::InvalidArgument.sysret();
    }

    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return KernelError::BadAddress.sysret(),
    };

    // VMAs unmapped or moved away: dropped after the lock on every return
    let mut gone: Vec<Vma> = Vec::new();
    let mut mm_guard = mm.lock();

    // The VMA containing old_addr must cover the old range (it may
    // start before old_addr: only the moves split it, Linux
    // vma_to_resize)
    let Some(vma_idx) = mm_guard.find_vma_index(old_addr) else {
        return KernelError::BadAddress.sysret();
    };
    // A shrink's unmapped tail may cross VMAs and gaps (Linux
    // check_prep_vma): only what stays must lie in the VMA
    let kept = old_addr + old_len.min(new_len_aligned);
    let vma_end = match mm_guard.get_vma(vma_idx) {
        Some(v) if v.end >= kept => v.end,
        _ => return KernelError::BadAddress.sysret(),
    };

    let pgd = mm.pgd();
    let moves = fixed || dontunmap;
    // Shrinking: the tail is unmapped like munmap (Linux do_vmi_munmap;
    // mremap_to shrinks before it moves): the VMA is split there, so no
    // VMA loses pages it still maps
    let mut old_len = old_len;
    if new_len_aligned < old_len {
        gone = munmap_locked(
            &mut mm_guard,
            pgd,
            old_addr + new_len_aligned,
            old_addr + old_len,
        );
        old_len = new_len_aligned;
        if !moves {
            #[cfg(feature = "mmcheck")]
            super::check::verify(&mm_guard, pgd, "mremap shrink");
            drop(mm_guard);
            drop(gone);
            return old_addr as i64;
        }
    }

    // RLIMIT_AS covers what the address space grows by: the growth, or
    // with MREMAP_DONTUNMAP the whole new range (the old one stays;
    // Linux vrm_calc_charge + may_expand_vm). A locked mapping that
    // grows also needs RLIMIT_MEMLOCK room (Linux mlock_future_ok)
    let charge = if dontunmap {
        new_len_aligned
    } else {
        new_len_aligned.saturating_sub(old_len)
    };
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_AS);
    let total = (mm_guard.total_vm() * PAGE_SIZE).saturating_add(charge);
    if charge > 0 && limit != crate::rlimit::RLIM_INFINITY && total > limit {
        return KernelError::OutOfMemory.sysret();
    }
    let locked = mm_guard.get_vma(vma_idx).is_some_and(|v| v.is_locked());
    if locked && new_len_aligned > old_len && !memlock_ok(&mm_guard, new_len_aligned - old_len) {
        return KernelError::WouldBlock.sysret();
    }

    if new_len_aligned > old_len {
        // Grow in place only where the old range ends its VMA (Linux
        // vrm_can_expand_in_place) and the new end stays in user space
        let new_end = old_addr.checked_add(new_len_aligned);
        if !moves
            && vma_end == old_addr + old_len
            && let Some(new_end) = new_end.filter(|&e| e <= super::TASK_SIZE)
            && mm_guard.try_expand_vma(vma_idx, new_end)
        {
            #[cfg(feature = "mmcheck")]
            super::check::verify(&mm_guard, pgd, "mremap expand");
            return old_addr as i64;
        }
        if !may_move {
            return KernelError::OutOfMemory.sysret();
        }
    } else if !moves {
        // Same size, nothing to move
        return old_addr as i64;
    }

    // Move: MREMAP_FIXED unmaps its target first, in this same mm lock
    // hold; else a free range is found
    let target = if fixed {
        gone.extend(munmap_locked(
            &mut mm_guard,
            pgd,
            new_addr,
            new_addr + new_len_aligned,
        ));
        new_addr
    } else {
        match mm_guard.find_free_area(new_len_aligned) {
            Some(a) => a,
            None => return KernelError::OutOfMemory.sysret(),
        }
    };
    let (from, to) = ((old_addr, old_len), (target, new_len_aligned));
    if let Err(e) = move_mapping(&mut mm_guard, pgd, from, to, dontunmap, &mut gone) {
        return e.sysret();
    }
    #[cfg(feature = "mmcheck")]
    super::check::verify(&mm_guard, pgd, "mremap move");
    drop(mm_guard);
    drop(gone);
    target as i64
}

/// `bytes` more of locked memory fit RLIMIT_MEMLOCK (or the task has
/// CAP_IPC_LOCK)
fn memlock_ok(mm: &super::MmStruct, bytes: u64) -> bool {
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_MEMLOCK);
    crate::task::capable(crate::task::CAP_IPC_LOCK)
        || limit == crate::rlimit::RLIM_INFINITY
        || (mm.locked_vm() * PAGE_SIZE).saturating_add(bytes) <= limit
}

/// The VMA starting at `old_addr` after mremap moved it: kept (now
/// empty) with MREMAP_DONTUNMAP, else removed into `gone`
fn move_vma_out(mm: &mut super::MmStruct, old_addr: u64, dontunmap: bool, gone: &mut Vec<Vma>) {
    let Some(idx) = mm.find_vma_exact(old_addr) else {
        return;
    };
    if dontunmap {
        // Kept with its backing (Linux): anonymous memory refaults zero
        // pages, a file or shared object its own pages; no longer locked
        // (dontunmap_complete)
        let Some(vma) = mm.get_vma_mut(idx) else {
            return;
        };
        let locked = vma.is_locked();
        let pages = vma.size() / PAGE_SIZE;
        vma.flags &= !VM_LOCKED_MASK;
        if locked {
            mm.sub_locked_vm(pages);
        }
    } else {
        gone.extend(mm.remove_vma(idx));
    }
}

/// Move the old range `from` (address, length) to `to` (address, new
/// length; Linux move_vma), mm lock held, the old range checked to lie
/// in one VMA and the new one unmapped. What the move needs is
/// allocated first (`mremap::move_prep`): ENOMEM leaves the old mapping
/// as it was. Then, under the same mm lock hold, the old range is split
/// into a VMA of its own, retired (kept empty with MREMAP_DONTUNMAP),
/// its copy inserted at the new address, and the entries moved into it
/// (each page once, with its reference).
fn move_mapping(
    mm: &mut super::MmStruct,
    pgd: u64,
    from: (u64, u64),
    to: (u64, u64),
    dontunmap: bool,
    gone: &mut Vec<Vma>,
) -> Result<(), KernelError> {
    let ((old_addr, old_len), (new_addr, new_len)) = (from, to);
    let mut alloc = |va| crate::arch::paging::pte_alloc(pgd, va);
    super::mremap::move_prep(pgd, old_addr, new_addr, old_len, &mut alloc)?;
    mm.split_at(old_addr);
    mm.split_at(old_addr + old_len);
    let mut new_vma = mm
        .find_vma_exact(old_addr)
        .and_then(|i| mm.get_vma(i))
        .ok_or(KernelError::BadAddress)?
        .clone();
    move_vma_out(mm, old_addr, dontunmap, gone);
    new_vma.start = new_addr;
    new_vma.end = new_addr + new_len;
    // The lock moves with the mapping (Linux: locked_vm charged to the
    // new VMA)
    if new_vma.is_locked() {
        mm.add_locked_vm(new_len / PAGE_SIZE);
    }
    let idx = mm.insert_vma(new_vma);
    mm.add_total_vm(new_len / PAGE_SIZE);
    mm.merge_adjacent(idx);
    super::mremap::move_ptes(pgd, old_addr, new_addr, old_len);
    Ok(())
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
        return KernelError::InvalidArgument.sysret();
    }

    // Zero length: success (no pages to check)
    if length == 0 {
        return 0;
    }

    // Calculate number of pages
    let num_pages = length.div_ceil(PAGE_SIZE);

    // Check for overflow
    if addr.checked_add(num_pages * PAGE_SIZE).is_none() {
        return KernelError::OutOfMemory.sysret();
    }

    // Get current task's MM
    let tid = current_tid();
    let mm = match get_task_mm(tid) {
        Some(mm) => mm,
        None => return KernelError::OutOfMemory.sysret(),
    };

    let mm_guard = mm.lock();

    // Build result vector
    let mut result: Vec<u8> = Vec::with_capacity(num_pages as usize);

    // A protnone page is resident too (Linux mincore_pte_range)
    let pgd = mm.pgd();
    for i in 0..num_pages {
        let page_addr = addr + i * PAGE_SIZE;
        if mm_guard.find_vma(page_addr).is_none() {
            return KernelError::OutOfMemory.sysret();
        }
        result.push(super::memory::resident(pgd, page_addr) as u8);
    }

    // Drop the mm lock before copying to user space
    drop(mm_guard);

    // Copy result to user space
    if crate::uaccess::copy_to_user::<crate::arch::Uaccess>(vec, &result).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
}
