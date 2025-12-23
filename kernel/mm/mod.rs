//! Memory Management subsystem
//!
//! Handles virtual memory areas (VMAs), mmap/munmap syscalls, and
//! demand paging for user processes.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Mutex;

use crate::task::Tid;

pub mod page_cache;
pub mod syscall;
pub mod vma;
pub mod writeback;

pub use vma::*;

// Address space layout for mmap region
// These are user-space virtual addresses where mmap allocations go

/// Base address for mmap region (x86-64)
#[cfg(target_arch = "x86_64")]
pub const MMAP_BASE: u64 = 0x7F00_0000_0000;

/// End address for mmap region (x86-64)
#[cfg(target_arch = "x86_64")]
pub const MMAP_END: u64 = 0x8000_0000_0000;

/// Base address for mmap region (aarch64)
#[cfg(target_arch = "aarch64")]
pub const MMAP_BASE: u64 = 0x0000_7F00_0000_0000;

/// End address for mmap region (aarch64)
#[cfg(target_arch = "aarch64")]
pub const MMAP_END: u64 = 0x0000_8000_0000_0000;

/// Stack guard gap (256KB like Linux default)
/// Prevents growsdown VMAs from expanding too close to adjacent VMAs
pub const STACK_GUARD_GAP: u64 = 256 * 1024;

/// Per-task memory descriptor
///
/// Manages the virtual memory areas (VMAs) for a task's address space.
pub struct MmStruct {
    /// List of VMAs, sorted by start address
    vmas: Vec<Vma>,
    /// Base address for mmap region
    mmap_base: u64,
    /// End address for mmap region
    mmap_end: u64,
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
}

impl MmStruct {
    /// Create a new memory descriptor
    pub fn new(mmap_base: u64, mmap_end: u64) -> Self {
        Self {
            vmas: Vec::new(),
            mmap_base,
            mmap_end,
            start_brk: 0,
            brk: 0,
            locked_vm: 0,
            total_vm: 0,
            def_flags: 0,
        }
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

    /// Remove VMAs overlapping the given range
    ///
    /// Returns the removed VMAs (for cleanup of mapped pages).
    pub fn remove_range(&mut self, start: u64, end: u64) -> Vec<Vma> {
        let mut removed = Vec::new();
        self.vmas.retain(|vma| {
            // Check for overlap: NOT (vma completely before OR vma completely after)
            let overlaps = !(vma.end <= start || vma.start >= end);
            if overlaps {
                removed.push(vma.clone());
                false // Remove
            } else {
                true // Keep
            }
        });
        removed
    }

    /// Find a free virtual address range of the given size
    ///
    /// Uses a simple first-fit algorithm starting from mmap_base.
    pub fn find_free_area(&self, size: u64) -> Option<u64> {
        let mut current = self.mmap_base;

        for vma in &self.vmas {
            // Only consider VMAs in the mmap region
            if vma.start >= self.mmap_base {
                // Check if there's enough space before this VMA
                if vma.start >= current && vma.start - current >= size {
                    return Some(current);
                }
                // Move past this VMA
                if vma.end > current {
                    current = vma.end;
                }
            }
        }

        // Check space after the last VMA
        if current < self.mmap_end && self.mmap_end - current >= size {
            Some(current)
        } else {
            None
        }
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

    /// Clone all VMAs (for fork)
    pub fn clone_vmas(&self) -> Vec<Vma> {
        self.vmas.clone()
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

        // Check against mmap_end
        if new_end > self.mmap_end {
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

/// Global mapping from task ID to memory descriptor
static TASK_MM: Mutex<BTreeMap<Tid, Arc<Mutex<MmStruct>>>> = Mutex::new(BTreeMap::new());

/// Get the memory descriptor for a task
pub fn get_task_mm(tid: Tid) -> Option<Arc<Mutex<MmStruct>>> {
    TASK_MM.lock().get(&tid).cloned()
}

/// Initialize memory descriptor for a task
pub fn init_task_mm(tid: Tid, mm: Arc<Mutex<MmStruct>>) {
    TASK_MM.lock().insert(tid, mm);
}

/// Remove memory descriptor for a task (called on exit)
///
/// Returns the removed MmStruct for cleanup.
pub fn exit_task_mm(tid: Tid) -> Option<Arc<Mutex<MmStruct>>> {
    TASK_MM.lock().remove(&tid)
}

/// Clone memory descriptor from parent to child
///
/// If `share_vm` is true (CLONE_VM), both tasks share the same MmStruct.
/// Otherwise, the child gets a copy of the parent's VMAs.
pub fn clone_task_mm(parent_tid: Tid, child_tid: Tid, share_vm: bool) {
    let parent_mm = match get_task_mm(parent_tid) {
        Some(mm) => mm,
        None => return, // Parent has no mm (kernel thread)
    };

    if share_vm {
        // Threads share the same mm
        init_task_mm(child_tid, parent_mm);
    } else {
        // Fork: create independent copy of VMAs
        let parent_guard = parent_mm.lock();
        let new_mm = MmStruct {
            vmas: parent_guard.clone_vmas(),
            mmap_base: parent_guard.mmap_base,
            mmap_end: parent_guard.mmap_end,
            start_brk: parent_guard.start_brk,
            brk: parent_guard.brk,
            // Copy mlock state for fork
            locked_vm: parent_guard.locked_vm,
            // Copy total VM for fork
            total_vm: parent_guard.total_vm,
            def_flags: parent_guard.def_flags,
        };
        drop(parent_guard);
        init_task_mm(child_tid, Arc::new(Mutex::new(new_mm)));
    }
}

/// Create a default MmStruct for a new user task
pub fn create_default_mm() -> Arc<Mutex<MmStruct>> {
    Arc::new(Mutex::new(MmStruct::new(MMAP_BASE, MMAP_END)))
}
