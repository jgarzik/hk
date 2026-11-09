//! Memory Management subsystem
//!
//! Handles virtual memory areas (VMAs), mmap/munmap syscalls, and
//! demand paging for user processes.

pub(crate) mod frame_alloc;
pub(crate) mod heap;
pub mod numa;

extern crate alloc;

use crate::util::kalloc::{arc_cyclic_nofail, box_nofail};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::sync::spin::Mutex;
use crate::sync::{RwSem, RwSemReadGuard, RwSemWriteGuard};
use crate::util::error::{KernelError, KernelResult};

pub mod anon_vma;
#[cfg(feature = "mmcheck")]
pub mod check;
pub mod fault;
pub mod fault_inject;
pub mod filemap;
pub mod gather;
pub mod huge_page;
pub mod ioremap;
pub mod lru;
pub mod madvise;
pub mod memblock;
pub mod memory;
pub mod mempolicy;
pub mod mprotect;
pub mod mremap;
pub mod page;
pub mod page_alloc;
pub mod pagewalk;
pub mod pgtable;
pub mod ptl;
pub mod remote;
pub mod rmap;
pub mod shmem;
pub mod slab;
pub mod swap;
pub mod swap_entry;
pub mod swap_state;
pub mod swapper;
pub mod syscall;
pub mod tlb;
pub mod vma;
pub mod vmalloc;
pub mod vmscan;
pub mod vmstack;
pub mod writeback;
pub mod xarray;

pub use swap::{SWAP_FLAG_DISCARD, SWAP_FLAG_PREFER, sys_swapoff, sys_swapon};
pub use swap_entry::SwapEntry;

pub use vma::*;

// User address space layout (doc/MEMORY.md): image at its link address
// (PIE at ELF_ET_DYN_BASE), brk after it, mmap top-down from below the
// stack gap, stack at STACK_TOP

pub use crate::arch::paging::TASK_SIZE;

/// Lowest mappable user address (Linux vm.mmap_min_addr default)
pub const MMAP_MIN_ADDR: u64 = 65536;

pub use crate::arch::paging::{ELF_ET_DYN_BASE, STACK_TOP};

/// Run `f` with task flag `flag` (PF_MEMALLOC, PF_MEMALLOC_NOIO) set,
/// restoring it after (Linux memalloc_noreclaim_save / memalloc_noio_save)
pub fn memalloc_scope<R>(flag: u32, f: impl FnOnce() -> R) -> R {
    let me = crate::task::percpu::current();
    let had = me.has_flag(flag);
    me.set_flag(flag);
    let r = f();
    if !had {
        me.clear_flag(flag);
    }
    r
}

/// A fixed mapping at [addr, addr + len): below MMAP_MIN_ADDR is EPERM
/// without CAP_SYS_RAWIO (Linux security_mmap_addr / cap_mmap_addr),
/// past TASK_SIZE is ENOMEM
pub fn check_fixed(addr: u64, len: u64) -> Result<(), crate::util::error::KernelError> {
    use crate::util::error::KernelError;
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
    let rlim = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_STACK);
    let rlim = if rlim == crate::task::rlimit::RLIM_INFINITY {
        0
    } else {
        rlim
    };
    let gap = rlim.saturating_add(STACK_GUARD_GAP).clamp(MIN_GAP, MAX_GAP);
    (STACK_TOP - gap) & !0xFFF
}

/// vm.max_map_count: most VMAs an address space may have (Linux
/// sysctl_max_map_count, DEFAULT_MAX_MAP_COUNT 65530)
pub static MAX_MAP_COUNT: AtomicUsize = AtomicUsize::new(65530);

fn max_map_count() -> usize {
    MAX_MAP_COUNT.load(Ordering::Relaxed)
}

/// /proc/sys/vm files of the address-space code
pub static MM_CTLS: &[crate::sysctl::Ctl] = &[crate::sysctl::Ctl {
    path: "vm/max_map_count",
    mode: 0o644,
    show: || alloc::vec![max_map_count() as i64],
    store: |v| {
        crate::sysctl::range(v[0], 0, i64::from(i32::MAX))?;
        MAX_MAP_COUNT.store(v[0] as usize, Ordering::Relaxed);
        Ok(())
    },
    text: None,
}];

/// Stack guard gap (256KB like Linux default)
/// Prevents growsdown VMAs from expanding too close to adjacent VMAs
pub const STACK_GUARD_GAP: u64 = 256 * 1024;

/// Per-task memory descriptor
///
/// Manages the virtual memory areas (VMAs) for a task's address space.
#[derive(Default)]
pub struct MmStruct {
    /// List of VMAs, sorted by start address; each its own allocation
    /// (Linux vm_area_cachep: the VMA slab cache)
    #[expect(clippy::vec_box)]
    vmas: Vec<alloc::boxed::Box<Vma>>,
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
    exe: Option<crate::fs::name::FileName>,
    /// Writes to the executable denied while this image runs (Linux
    /// mm->exe_file's deny_write_access)
    exe_deny: Option<crate::fs::inode::DenyWrite>,
    /// Where exec put the image, arguments and environment
    args: MmLayout,
    /// The address space these VMAs belong to and its top-level table,
    /// for the reverse-map chains of anonymous VMAs (set when the `Mm`
    /// is built; none in host tests)
    owner: Weak<Mm>,
    pgd: u64,
}

/// A VMA's reverse-map chain entry in the address space `owner`/`pgd`
fn avc_of(owner: &Weak<Mm>, pgd: u64, v: &Vma) -> anon_vma::Avc {
    anon_vma::Avc {
        mm: owner.clone(),
        pgd,
        start: v.start,
        end: v.end,
        pgoff: v.pgoff,
        locked: v.flags & VM_LOCKED_MASK != 0,
    }
}

/// A file VMA's i_mmap entry: its page offset is the file page of its
/// start (Linux vm_pgoff of a file VMA)
fn file_avc_of(owner: &Weak<Mm>, pgd: u64, v: &Vma) -> anon_vma::Avc {
    anon_vma::Avc {
        pgoff: v.offset / PAGE_SIZE,
        ..avc_of(owner, pgd, v)
    }
}

/// Where exec put the image and the initial stack (Linux mm->start_code
/// .. env_end, start_stack): /proc/<pid>/cmdline, environ, stat and
/// status read it
#[derive(Clone, Copy, Default, Debug)]
pub struct MmLayout {
    pub start_code: u64,
    pub end_code: u64,
    pub start_data: u64,
    pub end_data: u64,
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
    /// Initial stack pointer (argc)
    pub start_stack: u64,
}

impl MmStruct {
    /// Create a new memory descriptor
    pub fn new(mmap_base: u64) -> Self {
        Self {
            mmap_base,
            ..Default::default()
        }
    }

    /// Tie the VMAs to their address space (before any is inserted)
    fn set_owner(&mut self, owner: &Weak<Mm>, pgd: u64) {
        debug_assert!(self.vmas.is_empty());
        self.owner = owner.clone();
        self.pgd = pgd;
    }

    // ------------------------------------------------------------------
    // Reverse-map chains: every change of a VMA with an anon_vma updates
    // its entry (anon_vma lock under the mmap_lock held for writing)
    // ------------------------------------------------------------------

    /// Add the chain entries of `v`: its anon_vma's, and its file's
    /// i_mmap (Linux vma_link -> vma_link_file)
    fn link(&self, v: &Vma) {
        if let Some(av) = &v.anon_vma {
            av.link(avc_of(&self.owner, self.pgd, v));
        }
        if let Some(i) = v.inode() {
            i.i_data.i_mmap.link(file_avc_of(&self.owner, self.pgd, v));
        }
    }

    /// Drop the chain entries of `v`
    fn unlink(&self, v: &Vma) {
        if let Some(av) = &v.anon_vma {
            av.unlink(self.pgd, v.start);
        }
        if let Some(i) = v.inode() {
            i.i_data.i_mmap.unlink(self.pgd, v.start);
        }
    }

    /// Refresh the entries of the VMA at `idx`, which started at `old_start`
    fn relink(&self, idx: usize, old_start: u64) {
        let v = &self.vmas[idx];
        if let Some(av) = &v.anon_vma {
            let new = avc_of(&self.owner, self.pgd, v);
            av.update(self.pgd, old_start, |c| *c = new);
        }
        if let Some(i) = v.inode() {
            let new = file_avc_of(&self.owner, self.pgd, v);
            i.i_data.i_mmap.update(self.pgd, old_start, |c| *c = new);
        }
    }

    /// Set the flags of the VMA at `idx` (mlock state included)
    pub fn set_flags(&mut self, idx: usize, flags: u32) {
        let start = self.vmas[idx].start;
        self.vmas[idx].flags = flags;
        self.relink(idx, start);
    }

    /// Move the end of the VMA at `idx` (brk)
    pub fn set_end(&mut self, idx: usize, end: u64) {
        let start = self.vmas[idx].start;
        self.vmas[idx].end = end;
        self.relink(idx, start);
    }

    /// Layout of the image, its arguments and environment
    pub fn args(&self) -> MmLayout {
        self.args
    }

    /// Record them at exec
    pub fn set_args(&mut self, a: MmLayout) {
        self.args = a;
    }

    /// Executable path (/proc/<pid>/exe)
    pub fn exe(&self) -> Option<crate::fs::name::FileName> {
        self.exe.clone()
    }

    /// Record the executable at exec
    pub fn set_exe(
        &mut self,
        path: crate::fs::name::FileName,
        deny: Option<crate::fs::inode::DenyWrite>,
    ) {
        self.exe = Some(path);
        self.exe_deny = deny;
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

    /// VMAs in the address space (Linux mm->map_count)
    pub fn map_count(&self) -> usize {
        self.vmas.len()
    }

    /// Room for another mapping (Linux do_mmap, do_brk_flags: ENOMEM
    /// once map_count exceeds vm.max_map_count)
    pub fn may_map(&self) -> bool {
        self.map_count() <= max_map_count()
    }

    /// Unmapping [start, end) may split a VMA in two (Linux
    /// vms_gather_munmap_vmas: refused once map_count reaches
    /// vm.max_map_count, a hole inside one VMA being the only unmap
    /// that adds one)
    pub fn may_unmap(&self, start: u64, end: u64) -> bool {
        self.map_count() < max_map_count()
            || !self.vmas.iter().any(|v| v.start < start && end < v.end)
    }

    /// Split the VMA at `idx` at `at` like `split_vma`, refused with
    /// ENOMEM at vm.max_map_count (Linux split_vma: mprotect, madvise)
    pub fn split_checked(&mut self, idx: usize, at: u64) -> Result<usize, KernelError> {
        if self.map_count() >= max_map_count() {
            return Err(KernelError::OutOfMemory);
        }
        self.split_vma(idx, at).ok_or(KernelError::OutOfMemory)
    }

    /// `split_at` refused at vm.max_map_count
    pub fn split_at_checked(&mut self, addr: u64) -> Result<(), KernelError> {
        match self.find_vma_index(addr) {
            Some(i) if self.vmas[i].start < addr => self.split_checked(i, addr).map(|_| ()),
            _ => Ok(()),
        }
    }

    /// Find VMA containing the given address
    pub fn find_vma(&self, addr: u64) -> Option<&Vma> {
        self.vmas
            .iter()
            .find(|vma| vma.contains(addr))
            .map(|v| &**v)
    }

    /// Find VMA containing the given address (mutable reference)
    pub fn find_vma_mut(&mut self, addr: u64) -> Option<&mut Vma> {
        self.vmas
            .iter_mut()
            .find(|vma| vma.contains(addr))
            .map(|v| &mut **v)
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
        // VMAs never overlap: two would own the same pages and free
        // them twice (callers remove the range first, as Linux
        // vma_link's callers do)
        assert!(
            pos == 0 || self.vmas[pos - 1].end <= vma.start,
            "insert_vma: overlaps the VMA below"
        );
        assert!(
            self.vmas.get(pos).is_none_or(|v| vma.end <= v.start),
            "insert_vma: overlaps the VMA above"
        );
        self.link(&vma);
        // VMA allocation failure is not plumbed to the ~20 callers (the
        // Vec growth beside it cannot fail gracefully either)
        self.vmas.insert(pos, box_nofail(vma));
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
            .into_iter()
            .map(|v| {
                self.unlink(&v);
                *v
            })
            .collect()
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

    /// The free gap holding [start, end): the end of the VMA below it
    /// (0 if none) and the start of the one above (the page-table
    /// ceiling if none), the bounds of `memory::free_pgtables`
    pub fn gap_around(&self, start: u64, end: u64) -> (u64, u64) {
        let floor = self
            .vmas
            .iter()
            .filter(|v| v.end <= start)
            .map(|v| v.end)
            .max()
            .unwrap_or(0);
        let ceiling = self
            .vmas
            .iter()
            .find(|v| v.start >= end)
            .map_or_else(memory::pgtables_ceiling, |v| v.start);
        (floor, ceiling)
    }

    /// Check if the given range overlaps any existing VMA
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.vmas
            .iter()
            .any(|vma| !(vma.end <= start || vma.start >= end))
    }

    /// Get iterator over all VMAs
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.iter().map(|v| &**v)
    }

    /// Remove every VMA, resetting the VM counters (exit_mmap): each
    /// leaves its reverse-map chain before the page tables go
    pub fn take_vmas(&mut self) -> Vec<Vma> {
        self.total_vm = 0;
        self.locked_vm = 0;
        core::mem::take(&mut self.vmas)
            .into_iter()
            .map(|v| {
                self.unlink(&v);
                *v
            })
            .collect()
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
        self.vmas.iter_mut().map(|v| &mut **v)
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
    pub fn expand_downwards(&mut self, vma_idx: usize, address: u64) -> KernelResult<()> {
        let address = address & !0xFFF; // Page align down

        if vma_idx >= self.vmas.len() {
            return Err(KernelError::BadAddress);
        }

        let vma = &mut self.vmas[vma_idx];
        if address >= vma.start {
            return Ok(()); // Already covered
        }

        if !vma.is_growsdown() {
            return Err(KernelError::BadAddress);
        }

        // The stack may not grow past RLIMIT_STACK (Linux acct_stack_growth)
        let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_STACK);
        if vma.end - address > limit {
            return Err(KernelError::BadAddress);
        }

        let grow_pages = (vma.start - address) >> 12;

        // Its pages keep their index (Linux expand_downwards lowers
        // vm_pgoff): a VMA moved up by mremap keeps a small pgoff and
        // cannot grow below index 0 (Linux: grow <= vm_pgoff, ENOMEM)
        let Some(pgoff) = vma.pgoff.checked_sub(grow_pages) else {
            return Err(KernelError::OutOfMemory); // the access is SIGSEGV
        };
        let old_start = vma.start;
        vma.start = address;
        vma.pgoff = pgoff;
        let locked = vma.is_locked();
        self.relink(vma_idx, old_start);
        self.total_vm = self.total_vm.saturating_add(grow_pages);
        if locked {
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

    /// Index of the first VMA ending above `addr`: the one containing it,
    /// or the next one above (Linux find_vma)
    pub fn next_vma(&self, addr: u64) -> Option<usize> {
        self.vmas.iter().position(|vma| vma.end > addr)
    }

    /// Split the VMA containing `addr` there, if it starts below it
    pub fn split_at(&mut self, addr: u64) {
        if let Some(i) = self.find_vma_index(addr)
            && self.vmas[i].start < addr
        {
            self.split_vma(i, addr);
        }
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
        self.set_end(vma_idx, new_end);

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

        let vma = *self.vmas.remove(vma_idx);
        self.unlink(&vma);
        let pages = vma.size() >> 12;
        self.total_vm = self.total_vm.saturating_sub(pages);
        if vma.is_locked() {
            self.locked_vm = self.locked_vm.saturating_sub(pages);
        }

        Some(vma)
    }

    /// Get a reference to a VMA by index
    pub fn get_vma(&self, vma_idx: usize) -> Option<&Vma> {
        self.vmas.get(vma_idx).map(|v| &**v)
    }

    /// Get a mutable reference to a VMA by index
    pub fn get_vma_mut(&mut self, vma_idx: usize) -> Option<&mut Vma> {
        self.vmas.get_mut(vma_idx).map(|v| &mut **v)
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
        // Not plumbed: see `insert_vma`
        let mut new_vma = box_nofail((**vma).clone());
        new_vma.start = split_addr;
        // Bounded: pgoff + pages fits (pgoff <= TASK_SIZE / 4KB at
        // creation and only ever lowered by growth)
        new_vma.pgoff = vma
            .pgoff
            .checked_add((split_addr - vma.start) / PAGE_SIZE)?;

        // Adjust the offset into the backing file or shared object
        if new_vma.file.is_some() || new_vma.shmem.is_some() {
            new_vma.offset += split_addr - vma.start;
        }

        // Truncate original VMA to end at split point
        self.set_end(vma_idx, split_addr);

        // Insert new VMA after the original
        // (VMA list remains sorted since new_vma.start > vmas[vma_idx].start)
        self.link(&new_vma);
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
            // Remove second VMA (no accounting change - same total memory)
            let next = self.vmas.remove(idx + 1);
            self.unlink(&next);
            // Extend first VMA to cover second
            self.set_end(idx, next.end);
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
            // Remove this VMA (no accounting change - same total memory)
            let cur = self.vmas.remove(idx);
            self.unlink(&cur);
            // Extend previous VMA to cover this one
            self.set_end(idx - 1, cur.end);
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
    /// The VMA tree and accounting under the mmap_lock (Linux
    /// mm->mmap_lock, a sleeping rw_semaphore)
    map: RwSem<MmStruct>,
    /// Page-table structure changes (Linux mm->page_table_lock, `ptl`)
    page_table_lock: Mutex<()>,
    /// Dumpability (Linux mm->flags MMF_DUMPABLE: `task::dumpable`),
    /// shared by every task of the address space
    dumpable: AtomicU8,
    /// TLB state: where it is loaded, flush generation, ASID
    ctx: tlb::MmContext,
    /// membarrier registrations (Linux mm->membarrier_state,
    /// MEMBARRIER_STATE_*); a new address space starts with none
    membarrier: AtomicU32,
    /// Where its signal return trampoline page is, 0 for none (arm64:
    /// Linux mm->context.vdso): set by exec before the address space is
    /// used, moved by mremap of that page (Linux vdso_mremap) under the
    /// mmap_lock for writing, copied by fork; read with no lock by the
    /// signal delivery of a task using it, as Linux reads its word. An
    /// unmapped page is not forgotten (Linux neither).
    sigpage: AtomicU64,
}

impl Mm {
    /// Where its signal return trampoline is (arm64: Linux
    /// mm->context.vdso's sigtramp): its [sigpage] page, wherever mremap
    /// moved it; 0 if there is none (another arch)
    pub fn sigpage(&self) -> u64 {
        self.sigpage.load(Ordering::Relaxed)
    }

    /// Its signal return page is now at `addr` (exec, mremap)
    pub fn set_sigpage(&self, addr: u64) {
        self.sigpage.store(addr, Ordering::Relaxed);
    }

    /// Top-level page table (CR3 / TTBR0 value)
    pub fn pgd(&self) -> u64 {
        self.pgd
    }

    /// The mmap_lock for reading (Linux mmap_read_lock): faults,
    /// mincore, /proc maps, MADV_DONTNEED and other VMA lookups
    #[track_caller]
    pub fn mmap_read(&self) -> RwSemReadGuard<'_, MmStruct> {
        self.map.read()
    }

    /// The mmap_lock for writing (Linux mmap_write_lock): VMA changes
    #[track_caller]
    pub fn mmap_write(&self) -> RwSemWriteGuard<'_, MmStruct> {
        self.map.write()
    }

    /// `mmap_read`, or EINTR once SIGKILL is pending (Linux
    /// mmap_read_lock_killable)
    #[track_caller]
    pub fn mmap_read_killable(&self) -> Result<RwSemReadGuard<'_, MmStruct>, KernelError> {
        self.map.read_killable()
    }

    /// `mmap_write`, or EINTR once SIGKILL is pending (Linux
    /// mmap_write_lock_killable)
    #[track_caller]
    pub fn mmap_write_killable(&self) -> Result<RwSemWriteGuard<'_, MmStruct>, KernelError> {
        self.map.write_killable()
    }

    /// `map` is this address space's VMA tree (the one under its
    /// mmap_lock), so a borrow of it pins this address space's page
    /// tables (`pgtable::PgTables`)
    pub fn holds(&self, map: &MmStruct) -> bool {
        core::ptr::eq(map, self.map.data_ptr())
    }

    /// The page_table_lock (taken through `ptl::pt_lock`)
    pub(crate) fn page_table_lock(&self) -> &Mutex<()> {
        &self.page_table_lock
    }

    /// Dumpability (Linux get_dumpable): SUID_DUMP_*
    pub fn dumpable(&self) -> u8 {
        self.dumpable.load(Ordering::Relaxed)
    }

    /// Set the dumpability (Linux set_dumpable): PR_SET_DUMPABLE, exec,
    /// a credential change; seen by every task of the address space
    pub fn set_dumpable(&self, v: u8) {
        self.dumpable.store(v, Ordering::Relaxed);
    }

    /// TLB state (Linux mm->context)
    pub fn context(&self) -> &tlb::MmContext {
        &self.ctx
    }

    /// membarrier registration state (`membarrier`)
    pub fn membarrier_state(&self) -> &AtomicU32 {
        &self.membarrier
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
    pub fn new(pgd: u64, mut map: MmStruct) -> Self {
        // The failure is not plumbed (fork, exec and boot callers)
        MmRef(arc_cyclic_nofail(|me| {
            // Knowing the address space (for rmap chains)
            map.set_owner(me, pgd);
            Mm {
                users: AtomicUsize::new(1),
                pgd,
                map: RwSem::new(map),
                page_table_lock: Mutex::new(()),
                dumpable: AtomicU8::new(crate::task::dumpable::SUID_DUMP_USER),
                ctx: tlb::MmContext::new(),
                membarrier: AtomicU32::new(0),
                sigpage: AtomicU64::new(0),
            }
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

/// The address space of task `t` (an mm_count reference; the task
/// itself holds the user reference, so it stays mapped while the task
/// uses it). The current task's is `current().mm()`, lock-free.
pub fn get_task_mm(t: &crate::task::Task) -> Option<Arc<Mm>> {
    t.task_lock().mm().map(|m| m.arc().clone())
}

/// A user reference to task `t`'s address space (Linux get_task_mm),
/// None for a task without one or one exiting
pub fn get_task_mm_users(t: &crate::task::Task) -> Option<MmRef> {
    let mm = get_task_mm(t)?;
    mmget_not_zero(&mm)
}

/// Detach task `t` from its address space (Linux exit_mm). The user
/// reference is dropped here (the last one tears the mappings down);
/// the returned mm_count reference keeps the top-level table, still
/// loaded on this CPU, until the task has switched away.
pub fn exit_task_mm(t: &crate::task::Task) -> Option<Arc<Mm>> {
    let mm = t.task_lock().set_mm(None)?;
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
/// Fork copies the parent's entries of `v` (Linux vma_needs_copy): not
/// for a wipe-on-fork range, nor for a shared mapping whose pages the
/// child faults back in from a shared object or the page cache.
/// Copying those would race a truncate: one that already passed the
/// child's i_mmap entry would miss what fork copies after it. A private
/// mapping is copied (its copy-on-write pages exist only in its
/// entries), and so is a shared mapping of a file without a page cache,
/// whose faults would read a private copy (Linux copies VM_PFNMAP and
/// VM_MIXEDMAP mappings likewise).
fn vma_needs_copy(v: &Vma) -> bool {
    if v.flags & VM_WIPEONFORK != 0 {
        return false;
    }
    let refaults = v.shmem.is_some()
        || v.file
            .as_ref()
            .and_then(|f| f.mapping_inode())
            .is_some_and(|i| i.i_op.maps_cache());
    !(v.is_shared() && refaults)
}

pub fn dup_mm(parent: &MmRef, pgd: u64) -> KernelResult<MmRef> {
    let Ok(guard) = parent.mmap_write_killable() else {
        // The child mm was never built: its table is ours to free
        crate::FRAME_ALLOCATOR.free(pgd);
        return Err(KernelError::Interrupted);
    };
    let mut header = MmStruct::new(guard.mmap_base);
    header.start_brk = guard.start_brk;
    header.brk = guard.brk;
    header.total_vm = guard.total_vm;
    header.exe = guard.exe.clone();
    header.exe_deny = guard.exe_deny.clone();
    header.args = guard.args;
    let child = MmRef::new(pgd, header);
    // The child's mm lock for writing, nested in the parent's (Linux
    // dup_mmap: mmap_write_lock_nested): no one else can reach the
    // child yet, and its page tables are borrowed from this guard
    let mut map = child.mmap_write();
    let mut res = Ok(());
    for vma in guard.iter() {
        if vma.flags & VM_DONTCOPY != 0 {
            map.total_vm -= vma.size() / PAGE_SIZE;
            continue;
        }
        let mut v = vma.clone();
        v.flags &= !VM_LOCKED_MASK;
        if v.flags & VM_WIPEONFORK != 0 && v.anon_vma.is_some() {
            match anon_vma::AnonVma::new() {
                Ok(av) => v.anon_vma = Some(av),
                Err(e) => {
                    // Not linked: the child is torn down below
                    res = Err(e);
                    break;
                }
            }
        }
        // In the chain before its pages are copied (Linux
        // anon_vma_fork before copy_page_range)
        map.link(&v);
        if vma_needs_copy(&v) {
            let dst = pgtable::PgTables::new(&child, &map);
            let src = pgtable::PgTables::new(parent, &guard);
            res = memory::copy_page_range(dst, &child, src, parent, &v).map(|wp| {
                if wp {
                    tlb::flush_tlb_mm_range(parent, v.start, v.end, tlb::PAGE_SHIFT, false);
                }
            });
        }
        // Not plumbed: see `insert_vma`
        map.vmas.push(box_nofail(v));
        if res.is_err() {
            break;
        }
    }
    drop(map);
    drop(guard);
    // A fork child's address space holds the same secrets (Linux
    // dup_mmap copies mm->flags)
    child.set_dumpable(parent.dumpable());
    // Linux dup_mm copies the whole mm_struct: membarrier registrations
    // survive fork (exec's new address space starts without them)
    child
        .membarrier
        .store(parent.membarrier.load(Ordering::Relaxed), Ordering::Relaxed);
    child.set_sigpage(parent.sigpage());
    // On error `child` goes with its partial copy (outside the lock)
    res.map(|()| child)
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
    fn free_area_top_down() {
        // Empty: just below mmap_base
        let m = map(&[]);
        assert_eq!(m.find_free_area(0x1000), Some(0x6fff_f000));
        // A VMA straddling mmap_base: below its start
        let m = map(&[(0x6fff_0000, 0x7001_0000)]);
        assert_eq!(m.find_free_area(0x1000), Some(0x6ffe_f000));
        // An exact-fit gap is taken, the highest one first
        let m = map(&[(0x5000_0000, 0x6000_0000), (0x6000_1000, 0x7000_0000)]);
        assert_eq!(m.find_free_area(0x1000), Some(0x6000_0000));
        assert_eq!(m.find_free_area(0x2000), Some(0x4fff_e000));
        // Nothing fits above MMAP_MIN_ADDR
        let m = map(&[]);
        assert_eq!(m.find_free_area(0x7000_0000 - MMAP_MIN_ADDR + 0x1000), None);
    }

    #[test]
    fn gap_around_bounds() {
        let m = map(&[]);
        let (floor, ceiling) = m.gap_around(0x1000_0000, 0x1000_1000);
        assert_eq!(floor, 0);
        assert!(ceiling >= 0x1000_1000);
        let m = map(&[(0x1000, 0x2000), (0x9000, 0xa000)]);
        assert_eq!(m.gap_around(0x4000, 0x5000), (0x2000, 0x9000));
    }

    #[test]
    fn split_then_merge_back() {
        let mut m = map(&[(0x10000, 0x20000)]);
        m.split_at(0x14000);
        assert_eq!(spans(&m), [(0x10000, 0x14000), (0x14000, 0x20000)]);
        let i = m.find_vma_exact(0x14000).unwrap();
        m.merge_adjacent(i);
        assert_eq!(spans(&m), [(0x10000, 0x20000)]);
        // Different protections do not merge
        let mut m = map(&[(0x10000, 0x20000)]);
        m.split_at(0x14000);
        let i = m.find_vma_exact(0x14000).unwrap();
        m.vmas[i].prot = PROT_READ | super::PROT_WRITE;
        m.merge_adjacent(i);
        assert_eq!(m.iter().count(), 2);
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

    /// The chain entries (start, end, pgoff, locked) of an AnonVma
    fn chain(av: &anon_vma::AnonVma) -> Vec<(u64, u64, u64, bool)> {
        let mut v: Vec<_> = av
            .read()
            .iter()
            .map(|c| (c.start, c.end, c.pgoff, c.locked))
            .collect();
        v.sort();
        v
    }

    /// Every VMA change keeps the reverse-map chain in step: split,
    /// lock, merge, partial unmap, exit
    #[test]
    fn chain_follows_vma_changes() {
        let mut m = MmStruct::new(0x7000_0000);
        m.set_owner(&Weak::new(), 7);
        let av = anon_vma::AnonVma::new().unwrap();
        let rw = PROT_READ | PROT_WRITE;
        let flags = MAP_PRIVATE | MAP_ANONYMOUS;
        m.insert_vma(Vma::new_anon(0x10000, 0x20000, rw, flags, av.clone()));
        assert_eq!(chain(&av), [(0x10000, 0x20000, 0x10, false)]);
        let i = m.split_vma(0, 0x18000).unwrap();
        m.set_flags(i, flags | VM_LOCKED);
        assert_eq!(
            chain(&av),
            [
                (0x10000, 0x18000, 0x10, false),
                (0x18000, 0x20000, 0x18, true)
            ]
        );
        m.set_flags(i, flags);
        m.merge_adjacent(0);
        assert_eq!(chain(&av), [(0x10000, 0x20000, 0x10, false)]);
        let gone = m.remove_range(0x12000, 0x13000);
        assert_eq!(gone.len(), 1);
        assert_eq!(
            chain(&av),
            [
                (0x10000, 0x12000, 0x10, false),
                (0x13000, 0x20000, 0x13, false)
            ]
        );
        m.take_vmas();
        assert!(av.is_empty());
    }

    #[test]
    fn remove_range_of_a_hole_is_empty() {
        let mut m = map(&[(0x10000, 0x20000)]);
        assert!(m.remove_range(0x20000, 0x30000).is_empty());
        assert_eq!(spans(&m), [(0x10000, 0x20000)]);
    }
}
