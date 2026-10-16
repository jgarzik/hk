//! Memory Management subsystem
//!
//! Handles virtual memory areas (VMAs), mmap/munmap syscalls, and
//! demand paging for user processes.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::spin::Mutex;

use crate::task::Tid;

pub mod anon_vma;
pub mod fault;
pub mod huge_page;
pub mod lru;
pub mod memory;
pub mod mempolicy;
pub mod page;
pub mod page_cache;
pub mod remote;
pub mod rmap;
pub mod shmem;
pub mod swap;
pub mod swap_entry;
pub mod swap_state;
pub mod syscall;
pub mod vma;
pub mod writeback;

pub use swap::{
    SWAP_FLAG_DISCARD, SWAP_FLAG_PREFER, alloc_swap_entry, free_swap_entry, get_swap_info,
    memory_pressure, should_swap_out, swap_available, swap_read_page, swap_write_page, sys_swapoff,
    sys_swapon,
};
pub use swap_entry::SwapEntry;
pub use swap_state::{
    is_swap_file_id, swap_cache_add, swap_cache_del, swap_cache_lookup, swap_file_id,
};

pub use vma::*;

// User address space layout (doc/MEMORY.md): image at its link address
// (PIE at ELF_ET_DYN_BASE), brk after it, mmap top-down from below the
// stack gap, stack at STACK_TOP

pub use crate::arch::paging::TASK_SIZE;

/// Lowest mappable user address (Linux vm.mmap_min_addr default)
pub const MMAP_MIN_ADDR: u64 = 65536;

/// Top of the initial user stack (Linux STACK_TOP, no randomization)
#[cfg(target_arch = "x86_64")]
pub const STACK_TOP: u64 = 0x7FFF_FFFF_F000;
#[cfg(target_arch = "aarch64")]
pub const STACK_TOP: u64 = TASK_SIZE;

/// Load address of PIE executables (Linux ELF_ET_DYN_BASE, 2/3 of
/// TASK_SIZE, without randomization)
#[cfg(target_arch = "x86_64")]
pub const ELF_ET_DYN_BASE: u64 = 0x5555_5555_4000;
#[cfg(target_arch = "aarch64")]
pub const ELF_ET_DYN_BASE: u64 = 0xAAAA_AAAA_0000;

/// A fixed mapping at [addr, addr + len): below MMAP_MIN_ADDR is EPERM
/// without CAP_SYS_RAWIO (Linux security_mmap_addr / cap_mmap_addr),
/// past TASK_SIZE is ENOMEM
pub fn check_fixed(addr: u64, len: u64) -> Result<(), crate::error::KernelError> {
    use crate::error::KernelError;
    if addr < MMAP_MIN_ADDR && !crate::task::capable(crate::task::CAP_SYS_RAWIO) {
        return Err(KernelError::NotPermitted);
    }
    match addr.checked_add(len) {
        Some(end) if end <= TASK_SIZE => Ok(()),
        _ => Err(KernelError::OutOfMemory),
    }
}

/// A placement hint is used only if the whole range is mappable
pub fn hint_ok(addr: u64, len: u64) -> bool {
    addr >= MMAP_MIN_ADDR && addr.checked_add(len).is_some_and(|end| end <= TASK_SIZE)
}

/// Top of the mmap region: STACK_TOP less a gap for the stack from
/// RLIMIT_STACK (Linux mmap_base: at least 128MB, at most 5/6 of the
/// space). An unlimited stack gets the minimum gap: hk always lays out
/// top-down (Linux switches to the legacy bottom-up layout).
pub fn mmap_base() -> u64 {
    const MIN_GAP: u64 = 128 << 20;
    const MAX_GAP: u64 = STACK_TOP / 6 * 5;
    let rlim = crate::rlimit::rlimit(crate::rlimit::RLIMIT_STACK);
    let rlim = if rlim == crate::rlimit::RLIM_INFINITY {
        0
    } else {
        rlim
    };
    let gap = rlim.saturating_add(STACK_GUARD_GAP).clamp(MIN_GAP, MAX_GAP);
    (STACK_TOP - gap) & !0xFFF
}

/// Stack guard gap (256KB like Linux default)
/// Prevents growsdown VMAs from expanding too close to adjacent VMAs
pub const STACK_GUARD_GAP: u64 = 256 * 1024;

/// Per-task memory descriptor
///
/// Manages the virtual memory areas (VMAs) for a task's address space.
pub struct MmStruct {
    /// List of VMAs, sorted by start address
    vmas: Vec<Vma>,
    /// Top of the mmap region: allocations grow down from here
    mmap_base: u64,
    /// Initial program break (page-aligned end of loaded segments)
    start_brk: u64,
    /// Current program break
    brk: u64,
    /// Count of locked pages (in pages, not bytes)
    /// Used for resource limit checking (RLIMIT_MEMLOCK)
    locked_vm: u64,
    /// Total virtual memory (in pages)
    /// Used for resource limit checking (RLIMIT_AS)
    total_vm: u64,
    /// Default flags for new VMAs (set by mlockall with MCL_FUTURE)
    /// Contains VM_LOCKED and/or VM_LOCKONFAULT when MCL_FUTURE is active
    def_flags: u32,
    /// Path of the executable (Linux mm->exe_file), for /proc/<pid>/exe
    exe: Option<alloc::string::String>,
}

impl MmStruct {
    /// Create a new memory descriptor
    pub fn new(mmap_base: u64) -> Self {
        Self {
            vmas: Vec::new(),
            mmap_base,
            start_brk: 0,
            brk: 0,
            locked_vm: 0,
            total_vm: 0,
            def_flags: 0,
            exe: None,
        }
    }

    /// Executable path (/proc/<pid>/exe)
    pub fn exe(&self) -> Option<alloc::string::String> {
        self.exe.clone()
    }

    /// Record the executable at exec
    pub fn set_exe(&mut self, path: alloc::string::String) {
        self.exe = Some(path);
    }

    /// Set the program break region (called during ELF loading)
    pub fn set_brk(&mut self, start_brk: u64) {
        self.start_brk = start_brk;
        self.brk = start_brk;
    }

    /// Get the current program break
    pub fn get_brk(&self) -> u64 {
        self.brk
    }

    /// Get the initial program break
    pub fn get_start_brk(&self) -> u64 {
        self.start_brk
    }

    /// Update the current program break
    pub fn update_brk(&mut self, new_brk: u64) {
        self.brk = new_brk;
    }

    /// Find VMA containing the given address
    pub fn find_vma(&self, addr: u64) -> Option<&Vma> {
        self.vmas.iter().find(|vma| vma.contains(addr))
    }

    /// Find VMA containing the given address (mutable reference)
    pub fn find_vma_mut(&mut self, addr: u64) -> Option<&mut Vma> {
        self.vmas.iter_mut().find(|vma| vma.contains(addr))
    }

    /// Insert a VMA, maintaining sorted order by start address
    ///
    /// Returns the index where the VMA was inserted, for use with `merge_adjacent()`.
    pub fn insert_vma(&mut self, vma: Vma) -> usize {
        let pos = self
            .vmas
            .iter()
            .position(|v| v.start > vma.start)
            .unwrap_or(self.vmas.len());
        self.vmas.insert(pos, vma);
        pos
    }

    /// Remove the VMA parts inside [start, end) (Linux
    /// do_vmi_align_munmap): a VMA straddling `start` or `end` is split
    /// there and keeps its outside part.
    ///
    /// Returns the removed VMAs, each within the range, for the caller
    /// to release their pages and accounting.
    pub fn remove_range(&mut self, start: u64, end: u64) -> Vec<Vma> {
        for at in [start, end] {
            if let Some(i) = self.vmas.iter().position(|v| v.start < at && at < v.end) {
                self.split_vma(i, at);
            }
        }
        // Moved out, not cloned: a clone would count as another SysV
        // shm attachment
        let (removed, kept) = core::mem::take(&mut self.vmas)
            .into_iter()
            .partition(|v| v.start >= start && v.end <= end);
        self.vmas = kept;
        removed
    }

    /// Find a free virtual address range of the given size
    ///
    /// Top-down: the highest gap below mmap_base and above MMAP_MIN_ADDR
    /// that fits (Linux arch_get_unmapped_area_topdown).
    pub fn find_free_area(&self, size: u64) -> Option<u64> {
        let mut top = self.mmap_base;
        for vma in self.vmas.iter().rev() {
            if vma.start >= top {
                continue;
            }
            if vma.end <= top && top - vma.end >= size {
                return top.checked_sub(size).filter(|&a| a >= MMAP_MIN_ADDR);
            }
            top = top.min(vma.start);
        }
        top.checked_sub(size).filter(|&a| a >= MMAP_MIN_ADDR)
    }

    /// Check if the given range overlaps any existing VMA
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.vmas
            .iter()
            .any(|vma| !(vma.end <= start || vma.start >= end))
    }

    /// Get iterator over all VMAs
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.iter()
    }

    /// Remove every VMA, resetting the VM counters (exit_mmap)
    pub fn take_vmas(&mut self) -> Vec<Vma> {
        self.total_vm = 0;
        self.locked_vm = 0;
        core::mem::take(&mut self.vmas)
    }

    // ========================================================================
    // Memory locking (mlock/mlockall) support
    // ========================================================================

    /// Get the count of locked pages
    pub fn locked_vm(&self) -> u64 {
        self.locked_vm
    }

    /// Add to the locked page count
    pub fn add_locked_vm(&mut self, pages: u64) {
        self.locked_vm = self.locked_vm.saturating_add(pages);
    }

    /// Subtract from the locked page count
    pub fn sub_locked_vm(&mut self, pages: u64) {
        self.locked_vm = self.locked_vm.saturating_sub(pages);
    }

    /// Reset the locked page count to zero
    pub fn reset_locked_vm(&mut self) {
        self.locked_vm = 0;
    }

    // ========================================================================
    // Total VM tracking (for RLIMIT_AS)
    // ========================================================================

    /// Get the total virtual memory in pages
    pub fn total_vm(&self) -> u64 {
        self.total_vm
    }

    /// Add to the total virtual memory count
    pub fn add_total_vm(&mut self, pages: u64) {
        self.total_vm = self.total_vm.saturating_add(pages);
    }

    /// Subtract from the total virtual memory count
    pub fn sub_total_vm(&mut self, pages: u64) {
        self.total_vm = self.total_vm.saturating_sub(pages);
    }

    /// Get the default VMA flags (set by mlockall MCL_FUTURE)
    pub fn def_flags(&self) -> u32 {
        self.def_flags
    }

    /// Set the default VMA flags
    pub fn set_def_flags(&mut self, flags: u32) {
        self.def_flags = flags;
    }

    /// Get mutable iterator over all VMAs
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Vma> {
        self.vmas.iter_mut()
    }

    // ========================================================================
    // Stack expansion (MAP_GROWSDOWN) support
    // ========================================================================

    /// Find index of a growsdown VMA that could expand to cover the given address
    ///
    /// Returns Some(index) if a VM_GROWSDOWN VMA exists just above `addr` and
    /// the expansion wouldn't violate the stack guard gap.
    pub fn find_expandable_vma(&self, addr: u64) -> Option<usize> {
        for (i, vma) in self.vmas.iter().enumerate() {
            // VMA must be growsdown and addr must be below it
            if vma.is_growsdown() && addr < vma.start {
                // Check stack guard gap against previous VMA
                if i > 0 {
                    let prev = &self.vmas[i - 1];
                    if addr < prev.end.saturating_add(STACK_GUARD_GAP) {
                        return None; // Would violate guard gap
                    }
                }
                return Some(i);
            }
        }
        None
    }

    /// Expand a growsdown VMA downward to include the given address
    ///
    /// Called during page fault handling when an access occurs below a
    /// VM_GROWSDOWN VMA. The VMA's start address is extended downward.
    pub fn expand_downwards(&mut self, vma_idx: usize, address: u64) -> Result<(), i32> {
        const EFAULT: i32 = 14; // Bad address

        let address = address & !0xFFF; // Page align down

        if vma_idx >= self.vmas.len() {
            return Err(EFAULT);
        }

        let vma = &mut self.vmas[vma_idx];
        if address >= vma.start {
            return Ok(()); // Already covered
        }

        if !vma.is_growsdown() {
            return Err(EFAULT);
        }

        // The stack may not grow past RLIMIT_STACK (Linux acct_stack_growth)
        let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_STACK);
        if vma.end - address > limit {
            return Err(EFAULT);
        }

        let grow_pages = (vma.start - address) >> 12;

        // Update VMA
        vma.start = address;
        self.total_vm = self.total_vm.saturating_add(grow_pages);
        if vma.is_locked() {
            self.locked_vm = self.locked_vm.saturating_add(grow_pages);
        }

        Ok(())
    }

    // ========================================================================
    // mremap support
    // ========================================================================

    /// Find the index of the VMA containing the given address
    ///
    /// Returns Some(index) if a VMA contains addr, None otherwise.
    pub fn find_vma_index(&self, addr: u64) -> Option<usize> {
        self.vmas.iter().position(|vma| vma.contains(addr))
    }

    /// Find the index of the VMA starting at exactly the given address
    ///
    /// Returns Some(index) if a VMA starts at addr, None otherwise.
    pub fn find_vma_exact(&self, addr: u64) -> Option<usize> {
        self.vmas.iter().position(|vma| vma.start == addr)
    }

    /// Try to expand a VMA's end address in-place
    ///
    /// Returns true if expansion succeeded (no collision with next VMA),
    /// false if the expansion would collide.
    pub fn try_expand_vma(&mut self, vma_idx: usize, new_end: u64) -> bool {
        if vma_idx >= self.vmas.len() {
            return false;
        }

        // Check if expansion collides with the next VMA
        if vma_idx + 1 < self.vmas.len() {
            let next_start = self.vmas[vma_idx + 1].start;
            if new_end > next_start {
                return false; // Would collide
            }
        }

        if new_end > TASK_SIZE {
            return false;
        }

        // Perform expansion
        let old_end = self.vmas[vma_idx].end;
        self.vmas[vma_idx].end = new_end;

        // Update total_vm accounting
        let grow_pages = (new_end - old_end) >> 12;
        self.total_vm = self.total_vm.saturating_add(grow_pages);
        if self.vmas[vma_idx].is_locked() {
            self.locked_vm = self.locked_vm.saturating_add(grow_pages);
        }

        true
    }

    /// Remove a VMA by index and return it
    ///
    /// Updates total_vm and locked_vm accounting.
    pub fn remove_vma(&mut self, vma_idx: usize) -> Option<Vma> {
        if vma_idx >= self.vmas.len() {
            return None;
        }

        let vma = self.vmas.remove(vma_idx);
        let pages = vma.size() >> 12;
        self.total_vm = self.total_vm.saturating_sub(pages);
        if vma.is_locked() {
            self.locked_vm = self.locked_vm.saturating_sub(pages);
        }

        Some(vma)
    }

    /// Get a reference to a VMA by index
    pub fn get_vma(&self, vma_idx: usize) -> Option<&Vma> {
        self.vmas.get(vma_idx)
    }

    /// Get a mutable reference to a VMA by index
    pub fn get_vma_mut(&mut self, vma_idx: usize) -> Option<&mut Vma> {
        self.vmas.get_mut(vma_idx)
    }

    // ========================================================================
    // VMA splitting for mprotect
    // ========================================================================

    /// Split a VMA at the given address, creating two VMAs
    ///
    /// The original VMA is truncated to [start, split_addr) and a new VMA
    /// is created for [split_addr, end). The new VMA is inserted after the
    /// original.
    ///
    /// Returns the index of the new (second) VMA on success, or None if:
    /// - vma_idx is out of bounds
    /// - split_addr is not within the VMA's range (exclusive of boundaries)
    pub fn split_vma(&mut self, vma_idx: usize, split_addr: u64) -> Option<usize> {
        // Validate index
        let vma = self.vmas.get(vma_idx)?;

        // Validate split point is strictly within the VMA
        if split_addr <= vma.start || split_addr >= vma.end {
            return None;
        }

        // Clone VMA for the second half
        let mut new_vma = vma.clone();
        new_vma.start = split_addr;

        // Adjust the offset into the backing file or shared object
        if new_vma.file.is_some() || new_vma.shmem.is_some() {
            new_vma.offset += split_addr - vma.start;
        }

        // Truncate original VMA to end at split point
        self.vmas[vma_idx].end = split_addr;

        // Insert new VMA after the original
        // (VMA list remains sorted since new_vma.start > vmas[vma_idx].start)
        self.vmas.insert(vma_idx + 1, new_vma);

        Some(vma_idx + 1)
    }

    // ========================================================================
    // VMA merging optimization
    // ========================================================================

    /// Try to merge VMA at index with the next VMA
    ///
    /// Returns true if merge occurred, false otherwise.
    /// After merge, the VMA at `idx` is extended and the next VMA is removed.
    pub fn try_merge_with_next(&mut self, idx: usize) -> bool {
        if idx + 1 >= self.vmas.len() {
            return false;
        }
        if self.vmas[idx].can_merge_with(&self.vmas[idx + 1]) {
            // Extend first VMA to cover second
            self.vmas[idx].end = self.vmas[idx + 1].end;
            // Remove second VMA (no accounting change - same total memory)
            self.vmas.remove(idx + 1);
            return true;
        }
        false
    }

    /// Try to merge VMA at index with the previous VMA
    ///
    /// Returns true if merge occurred, false otherwise.
    /// After merge, the VMA at `idx-1` is extended and the VMA at `idx` is removed.
    pub fn try_merge_with_prev(&mut self, idx: usize) -> bool {
        if idx == 0 {
            return false;
        }
        if self.vmas[idx - 1].can_merge_with(&self.vmas[idx]) {
            // Extend previous VMA to cover this one
            self.vmas[idx - 1].end = self.vmas[idx].end;
            // Remove this VMA (no accounting change - same total memory)
            self.vmas.remove(idx);
            return true;
        }
        false
    }

    /// Merge adjacent VMAs starting from the given index
    ///
    /// Cascades forward (merging with next VMAs) until no more merges,
    /// then attempts to merge with the previous VMA.
    pub fn merge_adjacent(&mut self, idx: usize) {
        if idx >= self.vmas.len() {
            return;
        }
        // Cascade merge with next VMAs
        while self.try_merge_with_next(idx) {}
        // Try merge with previous
        if idx > 0 {
            self.try_merge_with_prev(idx);
        }
    }
}

// =============================================================================
// Address-space lifetime (Linux mm_struct: mm_users / mm_count)
// =============================================================================

/// An address space: its page tables and its VMAs (Linux mm_struct)
///
/// Two counts, as in Linux: `users` (mm_users) counts what uses the
/// address space -- tasks running in it and pinned readers ([`MmRef`]);
/// when it drops to zero the mappings and user page tables are torn
/// down ([`memory::exit_mmap`]). The `Arc` strong count (mm_count) keeps
/// the struct and its top-level table: the table is freed only when the
/// last `Arc` goes ([`Drop`], Linux __mmdrop), after every CPU has left
/// it (an exiting task keeps its `Arc` until it has switched away).
pub struct Mm {
    /// mm_users
    users: AtomicUsize,
    /// Physical address of the top-level table (owned; never changes)
    pgd: u64,
    /// The VMA tree and accounting; this spin lock is hk's mmap_lock
    map: Mutex<MmStruct>,
}

impl Mm {
    /// Top-level page table (CR3 / TTBR0 value)
    pub fn pgd(&self) -> u64 {
        self.pgd
    }

    /// Lock the VMA tree (mmap_lock)
    pub fn lock(&self) -> crate::sync::spin::MutexGuard<'_, MmStruct> {
        self.map.lock()
    }

    /// Current mm_users (diagnostics)
    pub fn users(&self) -> usize {
        self.users.load(Ordering::Relaxed)
    }
}

impl Drop for Mm {
    /// __mmdrop: free the top-level table (the user tables are gone)
    fn drop(&mut self) {
        crate::FRAME_ALLOCATOR.free(self.pgd);
    }
}

/// One mm_users reference: the holder may use the address space; it is
/// torn down when the last one is dropped (mmput)
pub struct MmRef(Arc<Mm>);

impl MmRef {
    /// A new address space rooted at the fresh table `pgd`, with one user
    pub fn new(pgd: u64, map: MmStruct) -> Self {
        MmRef(Arc::new(Mm {
            users: AtomicUsize::new(1),
            pgd,
            map: Mutex::new(map),
        }))
    }

    /// The address space, as an mm_count reference (mmgrab)
    pub fn arc(&self) -> &Arc<Mm> {
        &self.0
    }
}

impl core::ops::Deref for MmRef {
    type Target = Mm;
    fn deref(&self) -> &Mm {
        &self.0
    }
}

impl Clone for MmRef {
    /// mmget: another user of a live address space
    fn clone(&self) -> Self {
        self.0.users.fetch_add(1, Ordering::Relaxed);
        MmRef(self.0.clone())
    }
}

impl Drop for MmRef {
    /// mmput: the last user tears the address space down. Never drop a
    /// user reference under a spinlock: teardown drops file references.
    fn drop(&mut self) {
        if self.0.users.fetch_sub(1, Ordering::AcqRel) == 1 {
            memory::exit_mmap(&self.0);
        }
    }
}

/// mmget_not_zero: a user reference, unless the address space is
/// already being torn down
pub fn mmget_not_zero(mm: &Arc<Mm>) -> Option<MmRef> {
    let mut n = mm.users.load(Ordering::Relaxed);
    while n != 0 {
        match mm
            .users
            .compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => return Some(MmRef(mm.clone())),
            Err(v) => n = v,
        }
    }
    None
}

use crate::task::percpu::TASK_TABLE;

/// The address space of task `tid` (an mm_count reference; the task
/// itself holds the user reference, so it stays mapped while the task
/// uses it)
pub fn get_task_mm(tid: Tid) -> Option<Arc<Mm>> {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .and_then(|t| t.mm.as_ref().map(|m| m.arc().clone()))
}

/// A user reference to task `tid`'s address space (Linux get_task_mm),
/// None for a task without one or one exiting
pub fn get_task_mm_users(tid: Tid) -> Option<MmRef> {
    let mm = get_task_mm(tid)?;
    mmget_not_zero(&mm)
}

/// Detach task `tid` from its address space (Linux exit_mm). The user
/// reference is dropped here (the last one tears the mappings down);
/// the returned mm_count reference keeps the top-level table, still
/// loaded on this CPU, until the task has switched away.
pub fn exit_task_mm(tid: Tid) -> Option<Arc<Mm>> {
    let mm = {
        let mut table = TASK_TABLE.lock();
        table
            .tasks
            .iter_mut()
            .find(|t| t.tid == tid)
            .and_then(|t| t.mm.take())
    }?;
    let keep = mm.arc().clone();
    drop(mm);
    Some(keep)
}

/// The address space of a fork child, copied from `parent` (Linux
/// dup_mm / dup_mmap) into the fresh table `pgd` (kernel half linked).
///
/// Under the parent's mmap_lock, each VMA is copied with its page tables
/// (`memory::copy_page_range`: shared mappings stay shared, private ones
/// become copy-on-write), except that a VM_DONTCOPY (MADV_DONTFORK) VMA
/// is left out and a VM_WIPEONFORK one starts empty. Memory locks are not
/// inherited (VM_LOCKED cleared, locked_vm and MCL_FUTURE reset). On
/// error the partial copy is torn down with the child mm.
pub fn dup_mm(parent: &MmRef, pgd: u64) -> Result<MmRef, i32> {
    let guard = parent.lock();
    let mut map = MmStruct::new(guard.mmap_base);
    map.start_brk = guard.start_brk;
    map.brk = guard.brk;
    map.total_vm = guard.total_vm;
    map.exe = guard.exe.clone();
    let mut res = Ok(());
    for vma in guard.iter() {
        if vma.flags & VM_DONTCOPY != 0 {
            map.total_vm -= vma.size() / PAGE_SIZE;
            continue;
        }
        let mut v = vma.clone();
        v.flags &= !VM_LOCKED_MASK;
        if v.flags & VM_WIPEONFORK != 0 {
            v.anon_vma = v.anon_vma.as_ref().map(|_| anon_vma::AnonVma::new());
        }
        if let Some(av) = &v.anon_vma {
            av.add_vma(pgd, v.start, v.end);
        }
        if v.flags & VM_WIPEONFORK == 0 {
            res = memory::copy_page_range(pgd, parent.pgd(), &v).map(|wp| {
                if wp {
                    crate::arch::paging::flush_tlb_range(v.start, v.end);
                }
            });
        }
        map.vmas.push(v);
        if res.is_err() {
            break;
        }
    }
    let child = MmRef::new(pgd, map);
    drop(guard);
    // On error `child` goes with its partial copy (outside the lock)
    res.map(|_| child)
}

/// A fresh, empty address space for exec / the first task, rooted at
/// `pgd`
pub fn mm_alloc(pgd: u64) -> MmRef {
    MmRef::new(pgd, MmStruct::new(mmap_base()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(ranges: &[(u64, u64)]) -> MmStruct {
        let mut m = MmStruct::new(0x7000_0000);
        for &(a, b) in ranges {
            m.insert_vma(Vma::new(a, b, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS));
        }
        m
    }

    fn spans(m: &MmStruct) -> Vec<(u64, u64)> {
        m.iter().map(|v| (v.start, v.end)).collect()
    }

    #[test]
    fn remove_range_splits_edges() {
        let mut m = map(&[(0x10000, 0x20000), (0x30000, 0x40000)]);
        let gone = m.remove_range(0x18000, 0x34000);
        let gone: Vec<_> = gone.iter().map(|v| (v.start, v.end)).collect();
        assert_eq!(gone, [(0x18000, 0x20000), (0x30000, 0x34000)]);
        assert_eq!(spans(&m), [(0x10000, 0x18000), (0x34000, 0x40000)]);
    }

    #[test]
    fn remove_range_inside_one_vma() {
        let mut m = map(&[(0x10000, 0x20000)]);
        let gone = m.remove_range(0x11000, 0x12000);
        assert_eq!(gone.len(), 1);
        assert_eq!(spans(&m), [(0x10000, 0x11000), (0x12000, 0x20000)]);
    }

    #[test]
    fn remove_range_of_a_hole_is_empty() {
        let mut m = map(&[(0x10000, 0x20000)]);
        assert!(m.remove_range(0x20000, 0x30000).is_empty());
        assert_eq!(spans(&m), [(0x10000, 0x20000)]);
    }
}
