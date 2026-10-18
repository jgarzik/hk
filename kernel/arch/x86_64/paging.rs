//! x86-64 paging (4-level page tables)
//!
//! Implements the PageTable trait for x86-64 4-level paging:
//! PML4 -> PDPT -> PD -> PT -> Physical Page

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{FrameAlloc, Leaf, MapError, PageFlags, PageTable};

/// Page size (4KB)
pub const PAGE_SIZE: u64 = 4096;

/// Page table entry flags
pub const PAGE_PRESENT: u64 = 1 << 0;
pub const PAGE_WRITABLE: u64 = 1 << 1;
pub const PAGE_USER: u64 = 1 << 2;
pub const PAGE_WRITE_THROUGH: u64 = 1 << 3;
pub const PAGE_CACHE_DISABLE: u64 = 1 << 4;
pub const PAGE_ACCESSED: u64 = 1 << 5; // Hardware-set: page was accessed
pub const PAGE_DIRTY: u64 = 1 << 6; // Hardware-set: page was written
pub const PAGE_HUGE: u64 = 1 << 7;
pub const PAGE_NO_EXECUTE: u64 = 1 << 63;

/// Mask for physical address in page table entry
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Number of entries per page table (512)
const ENTRIES_PER_TABLE: usize = 512;

// ============================================================================
// Address space layout (see kmap.rs)
// ============================================================================

/// Direct map of all RAM: physical 0 is at PAGE_OFFSET (Linux x86-64)
pub const PAGE_OFFSET: u64 = 0xFFFF_8880_0000_0000;

/// Kernel image mapping base (Linux: __START_KERNEL_map, -2GB)
pub const KERNEL_MAP: u64 = 0xFFFF_FFFF_8000_0000;

/// vmalloc/ioremap window (Linux: VMALLOC_START)
pub const VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// Virtual memory map: the struct page array, indexed by pfn (Linux
/// VMEMMAP_START)
pub const VMEMMAP_START: u64 = 0xFFFF_EA00_0000_0000;

/// End of user space (Linux: TASK_SIZE_MAX, one guard page below the
/// non-canonical hole)
pub const TASK_SIZE: u64 = 0x0000_7FFF_FFFF_F000;

/// First PML4 entry of the kernel half
pub const KERNEL_PML4_START: usize = 256;

/// Convert physical address to virtual address (direct map; Linux __va)
#[inline]
pub fn phys_to_virt(phys: u64) -> *mut u8 {
    (phys + PAGE_OFFSET) as *mut u8
}

/// Convert a direct-map or kernel-image address to physical (Linux __pa)
#[inline]
pub fn virt_to_phys(virt: u64) -> u64 {
    if virt >= KERNEL_MAP {
        virt - KERNEL_MAP
    } else {
        debug_assert!((PAGE_OFFSET..VMALLOC_START).contains(&virt));
        virt - PAGE_OFFSET
    }
}

/// Convert physical address to page table pointer
#[inline]
pub fn phys_to_virt_table(phys: u64) -> *mut RawPageTable {
    phys_to_virt(phys) as *mut RawPageTable
}

/// Convert physical address to const page table pointer
#[inline]
pub fn phys_to_virt_table_const(phys: u64) -> *const RawPageTable {
    phys_to_virt(phys) as *const RawPageTable
}

/// Physical address bits of a page table entry
pub const PTE_ADDR_MASK: u64 = ADDR_MASK;

/// `va` lies in the user half (below TASK_SIZE): the user page-table
/// walkers never reach the kernel half (x86 PML4 256-511) nor alias a
/// user entry with an address past the user range (arm64 TTBR0)
fn user_va(va: u64) -> bool {
    va < TASK_SIZE
}

/// Pointer to the 4KB leaf entry for `va` in the tables rooted at
/// `root` (present or not, e.g. a swap entry); None if an upper level
/// is missing or maps a huge page
pub fn pte_ptr(root: u64, va: u64) -> Option<*mut u64> {
    if !user_va(va) {
        return None;
    }
    let mut table = phys_to_virt_table(root);
    for shift in [39, 30, 21] {
        let e = unsafe { *(*table).entry(((va >> shift) & 511) as usize) };
        if !e.is_present() || e.is_huge() {
            return None;
        }
        table = phys_to_virt_table(e.addr());
    }
    Some(
        unsafe { (*table).entry_mut(((va >> 12) & 511) as usize) } as *mut PageTableEntry
            as *mut u64,
    )
}

/// A leaf entry maps a page: present, or protnone (Linux pte_present)
pub fn pte_present(pte: u64) -> bool {
    pte & PAGE_PRESENT != 0 || pte_protnone(pte)
}

/// Software bit of a PROT_NONE entry (Linux _PAGE_PROTNONE): not
/// present to the MMU, so every user access faults, but it keeps its
/// frame (and the frame reference) for a later mprotect to restore
pub const PAGE_PROTNONE: u64 = 1 << 10;

/// A protnone leaf entry (never a swap entry: those carry the marker)
pub fn pte_protnone(pte: u64) -> bool {
    pte & (PAGE_PRESENT | PAGE_PROTNONE | crate::mm::SwapEntry::SWAP_MARKER) == PAGE_PROTNONE
}

/// `pte` with the protection `prot` (PROT_*; Linux pte_modify): none
/// at all makes it protnone; it is writable only if `prot` asks for it
/// and it is not a copy-on-write share. Frame, accessed/dirty and cache
/// bits are kept.
pub fn pte_modify(pte: u64, prot: u32) -> u64 {
    use crate::mm::{PROT_EXEC, PROT_READ, PROT_WRITE};
    let keep = pte & !(PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE | PAGE_PROTNONE);
    if prot & (PROT_READ | PROT_WRITE | PROT_EXEC) == 0 {
        return keep | PAGE_PROTNONE | PAGE_NO_EXECUTE;
    }
    let mut e = keep | PAGE_PRESENT;
    if prot & PROT_WRITE != 0 && pte & PAGE_COW == 0 {
        e |= PAGE_WRITABLE;
    }
    if prot & PROT_EXEC == 0 {
        e |= PAGE_NO_EXECUTE;
    }
    e
}

// ============================================================================
// User PTE helpers for the generic fault and fork paths (kernel/mm)
// ============================================================================

/// Intermediate entries of user tables
const USER_TABLE: u64 = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;

/// The entry at `idx` (mod 512) of `table`, as an atomic
fn entry_atomic(table: *mut RawPageTable, idx: u64) -> &'static AtomicU64 {
    // SAFETY: a live table frame reached through the direct map
    unsafe { AtomicU64::from_ptr((*table).entry_mut((idx & 511) as usize) as *mut _ as *mut u64) }
}

/// The entry at `p` in a live table, as an atomic
fn entry_ptr(p: *mut u64) -> &'static AtomicU64 {
    // SAFETY: `p` points into a live table frame (direct map)
    unsafe { AtomicU64::from_ptr(p) }
}

/// Pointer to the 2MB-level (PD) entry for `va` in the tables rooted at
/// `root` (Linux pmd_offset); None if an upper level is missing
pub fn pmd_ptr(root: u64, va: u64) -> Option<*mut u64> {
    if !user_va(va) {
        return None;
    }
    let mut table = phys_to_virt_table(root);
    for shift in [39, 30] {
        let e = PageTableEntry(entry_atomic(table, va >> shift).load(Ordering::Acquire));
        if !e.is_present() || e.is_huge() {
            return None;
        }
        table = phys_to_virt_table(e.addr());
    }
    Some(entry_atomic(table, va >> 21).as_ptr())
}

/// The next-level table a PML4, PDPT or PD entry points to (not a
/// huge page)
pub fn table_of(e: u64) -> Option<u64> {
    let e = PageTableEntry(e);
    (e.is_present() && !e.is_huge()).then(|| e.addr())
}

/// A 2MB-level entry maps a huge page
pub fn pmd_huge(pmd: u64) -> bool {
    pmd & (PAGE_PRESENT | PAGE_HUGE) == PAGE_PRESENT | PAGE_HUGE
}

/// Pointer to the 4KB leaf entry for `va`, allocating the missing
/// tables (Linux pte_alloc). A table is installed with a compare and
/// swap, so racing faults share one. None if out of memory (down to
/// the low watermark) or a huge page maps `va`.
pub fn pte_alloc(root: u64, va: u64) -> Option<*mut u64> {
    if !user_va(va) {
        return None;
    }
    let mut table = phys_to_virt_table(root);
    for shift in [39, 30, 21] {
        let slot = entry_atomic(table, va >> shift);
        let mut e = PageTableEntry(slot.load(Ordering::Acquire));
        if !e.is_present() {
            // User page tables stop at the low watermark like the
            // user pages they map: a process touching sparse addresses
            // cannot drain the kernel's reserve with tables
            let new = crate::FRAME_ALLOCATOR.alloc_gfp(crate::mm::page_alloc::Gfp::USER)?;
            // SAFETY: a fresh frame, reached through the direct map
            unsafe { core::ptr::write_bytes(phys_to_virt(new), 0, PAGE_SIZE as usize) };
            let ent = new | USER_TABLE;
            e = match slot.compare_exchange(0, ent, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => PageTableEntry(ent),
                Err(cur) => {
                    crate::FRAME_ALLOCATOR.free(new);
                    PageTableEntry(cur)
                }
            };
        }
        if e.is_huge() {
            return None;
        }
        table = phys_to_virt_table(e.addr());
    }
    Some(entry_atomic(table, va >> 12).as_ptr())
}

/// Fill the fresh page table `pt` with the 512 4KB entries of the 2MB
/// entry `pmd`: same frames, protection and accessed/dirty bits (Linux
/// __split_huge_pmd_locked). Returns the 2MB frame's base.
pub fn split_table(pt: u64, pmd: u64) -> u64 {
    const HUGE_MASK: u64 = (2 << 20) - 1;
    let base = pmd & ADDR_MASK & !HUGE_MASK;
    let flags = (pmd & !ADDR_MASK & !PAGE_HUGE) | PAGE_PRESENT;
    let table = phys_to_virt_table(pt);
    for i in 0..ENTRIES_PER_TABLE {
        // SAFETY: a fresh table frame, not yet reachable
        unsafe {
            (*table)
                .entry_mut(i)
                .set(base + i as u64 * PAGE_SIZE, flags)
        };
    }
    base
}

/// Install the filled table `pt` in the empty 2MB-level entry at `pmdp`
/// (Linux pmd_populate)
pub fn pmd_populate(pmdp: *mut u64, pt: u64) {
    entry_ptr(pmdp).store(pt | USER_TABLE, Ordering::Release);
}

/// A user leaf entry for `phys` with the protection of a VMA (PROT_*),
/// marked accessed (Linux mk_pte + pte_mkyoung)
pub fn mk_pte(phys: u64, prot: u32) -> u64 {
    let mut pte = phys | PAGE_PRESENT | PAGE_USER | PAGE_ACCESSED;
    if prot & crate::mm::PROT_WRITE != 0 {
        pte |= PAGE_WRITABLE;
    }
    if prot & crate::mm::PROT_EXEC == 0 {
        pte |= PAGE_NO_EXECUTE;
    }
    pte
}

/// Physical address mapped by a 4KB leaf entry
pub fn pte_addr(pte: u64) -> u64 {
    pte & ADDR_MASK
}

/// The entry allows writes
pub fn pte_write(pte: u64) -> bool {
    pte & PAGE_WRITABLE != 0
}

/// The entry allows instruction fetches
pub fn pte_exec(pte: u64) -> bool {
    pte & PAGE_NO_EXECUTE == 0
}

/// The user leaf `pte` is executable by the kernel: never, SMEP
/// (enabled at boot when the CPU has it) faults any supervisor fetch
/// from a user page (Linux has the same exposure on CPUs without it)
#[cfg(feature = "mmcheck")]
pub fn pte_kexec(_pte: u64) -> bool {
    false
}

/// The user leaf `pte` is global: never (CR4.PGE is off, and user
/// entries never set G)
#[cfg(feature = "mmcheck")]
pub fn pte_global(_pte: u64) -> bool {
    false
}

/// The entry is a copy-on-write share (written only after a copy)
pub fn pte_cow(pte: u64) -> bool {
    pte & PAGE_COW != 0
}

/// Writable, dirty and young; no longer copy-on-write
pub fn pte_mkwrite(pte: u64) -> u64 {
    (pte & !PAGE_COW) | PAGE_WRITABLE | PAGE_ACCESSED | PAGE_DIRTY
}

/// Read-only and copy-on-write (fork of a private mapping)
pub fn pte_mkcow(pte: u64) -> u64 {
    (pte & !PAGE_WRITABLE) | PAGE_COW
}

/// Make a page the kernel just filled visible to instruction fetches
/// (x86 caches are coherent: nothing to do)
pub fn sync_page(_phys: u64, _exec: bool) {}

/// Make code the kernel wrote visible to instruction fetches (coherent
/// on x86: nothing to do)
pub fn sync_icache(_phys: u64, _len: usize) {}

/// The user page tables of an address space, detached from its
/// top-level table by [`detach_user`]
pub struct UserTables(alloc::vec::Vec<u64>);

/// Detach the user half from the top-level table `pml4_phys` (Linux
/// exit_mmap: unmap_vmas + free_pgtables, first half): its PML4
/// entries 0-255 are cleared, the tables below are kept intact for
/// [`UserTables::free`], which runs after the caller flushed every CPU
/// that may still walk them. The shared kernel half (PML4 256-511) is
/// left untouched.
pub fn detach_user(pml4_phys: u64) -> UserTables {
    let pml4 = phys_to_virt_table(pml4_phys);
    let mut top = alloc::vec::Vec::new();
    for i in 0..KERNEL_PML4_START {
        // SAFETY: `pml4_phys` is a live root table reached through the
        // direct map; its user entries belong to the caller
        unsafe {
            let e = *(*pml4).entry(i);
            if e.is_present() {
                top.push(e.addr());
            }
            (*pml4).entry_mut(i).clear();
        }
    }
    UserTables(top)
}

impl UserTables {
    /// Release each user leaf (to `put`) and free every table frame
    pub fn free(self, put: &mut dyn FnMut(Leaf)) {
        for t in self.0 {
            free_level(t, 3, put);
        }
    }
}

/// Release the table at `phys` and everything below it; `level` 3 is a
/// PDPT, 2 a PD, 1 a PT
fn free_level(phys: u64, level: u32, put: &mut dyn FnMut(Leaf)) {
    let table = phys_to_virt_table_const(phys);
    for i in 0..ENTRIES_PER_TABLE {
        // SAFETY: a detached table frame owned by the caller
        let e = unsafe { *(*table).entry(i) };
        match level {
            1 if pte_present(e.0) => put(Leaf::Page(e.addr())),
            1 if e.0 != 0 => put(Leaf::Swap(e.0)),
            // 1GB user pages are never created
            3 if e.is_present() && !e.is_huge() => free_level(e.addr(), 2, put),
            2 if e.is_present() && e.is_huge() => put(Leaf::Huge(e.addr())),
            2 if e.is_present() => free_level(e.addr(), 1, put),
            _ => {}
        }
    }
    crate::FRAME_ALLOCATOR.free(phys);
}

/// Page table entry
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Create an empty (not present) entry
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        self.0 & PAGE_PRESENT != 0
    }

    /// Check if entry is a huge page (2MB in PD, 1GB in PDPT)
    pub fn is_huge(&self) -> bool {
        self.0 & PAGE_HUGE != 0
    }

    /// Get physical address
    pub fn addr(&self) -> u64 {
        self.0 & ADDR_MASK
    }

    /// Get flags
    pub fn flags(&self) -> u64 {
        self.0 & !ADDR_MASK
    }

    /// Set the entry
    pub fn set(&mut self, phys_addr: u64, flags: u64) {
        self.0 = (phys_addr & ADDR_MASK) | flags;
    }

    /// Clear the entry
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

/// A page table (PML4, PDPT, PD, or PT)
#[repr(C, align(4096))]
pub struct RawPageTable {
    /// Page table entries (512 x 8 bytes = 4KB)
    pub entries: [PageTableEntry; ENTRIES_PER_TABLE],
}

impl RawPageTable {
    /// Create an empty page table
    pub const fn new() -> Self {
        Self {
            entries: [PageTableEntry::empty(); ENTRIES_PER_TABLE],
        }
    }
}

impl Default for RawPageTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RawPageTable {
    /// Get entry at index
    pub fn entry(&self, index: usize) -> &PageTableEntry {
        &self.entries[index]
    }

    /// Get mutable entry at index
    pub fn entry_mut(&mut self, index: usize) -> &mut PageTableEntry {
        &mut self.entries[index]
    }
}

/// x86-64 page table implementation
pub struct X86_64PageTable {
    /// Physical address of PML4
    pml4_phys: u64,
}

impl X86_64PageTable {
    /// Create a new page table with the given PML4 physical address
    pub fn new(pml4_phys: u64) -> Self {
        Self { pml4_phys }
    }

    /// Get the root page table physical address (architecture-neutral name)
    ///
    /// On x86-64, this returns the PML4 physical address.
    #[inline]
    pub fn root_table_phys(&self) -> u64 {
        self.pml4_phys
    }

    /// The kernel page table (swapper): kernel threads run on it
    pub fn kernel_identity() -> Self {
        Self::new(super::kmap::swapper_phys())
    }

    /// Create a new user page table (allocates PML4)
    pub fn new_user<FA: FrameAlloc<PhysAddr = u64>>(frame_alloc: &mut FA) -> Option<Self> {
        let pml4_phys = frame_alloc.alloc_frame()?;
        // Zero the PML4
        unsafe {
            core::ptr::write_bytes(phys_to_virt(pml4_phys), 0, PAGE_SIZE as usize);
        }
        Some(Self::new(pml4_phys))
    }

    /// Map a virtual address to physical with on-demand page table allocation
    ///
    /// This version allocates intermediate page tables (PDPT, PD, PT) as needed.
    /// Returns Err(MapError) if frame allocation fails.
    pub fn map_with_alloc<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        va: u64,
        pa: u64,
        flags: PageFlags,
        frame_alloc: &mut FA,
    ) -> Result<(), MapError> {
        // Convert flags to x86-64 page table flags
        let mut entry_flags = PAGE_PRESENT;
        if flags.contains(PageFlags::WRITE) {
            entry_flags |= PAGE_WRITABLE;
        }
        if flags.contains(PageFlags::USER) {
            entry_flags |= PAGE_USER;
        }
        if !flags.contains(PageFlags::EXECUTE) {
            entry_flags |= PAGE_NO_EXECUTE;
        }

        // Flags for intermediate entries (PDPT, PD, PT pointers)
        // Must have USER flag if user pages are below, and WRITABLE for future mappings
        let intermediate_flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;

        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);

        unsafe {
            let pml4 = phys_to_virt_table(self.pml4_phys);

            // Get or create PDPT
            let pml4_entry = (*pml4).entry_mut(pml4_idx);
            if !pml4_entry.is_present() {
                let pdpt_phys = frame_alloc
                    .alloc_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                core::ptr::write_bytes(phys_to_virt(pdpt_phys), 0, PAGE_SIZE as usize);
                pml4_entry.set(pdpt_phys, intermediate_flags);
            } else {
                // Entry exists - ensure USER flag is set for user-accessible mappings
                if flags.contains(PageFlags::USER) {
                    let current_flags = pml4_entry.flags();
                    if current_flags & PAGE_USER == 0 {
                        pml4_entry
                            .set(pml4_entry.addr(), current_flags | PAGE_USER | PAGE_WRITABLE);
                    }
                }
            }
            let pdpt = phys_to_virt_table(pml4_entry.addr());

            // Get or create PD
            let pdpt_entry = (*pdpt).entry_mut(pdpt_idx);
            if !pdpt_entry.is_present() {
                let pd_phys = frame_alloc
                    .alloc_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                core::ptr::write_bytes(phys_to_virt(pd_phys), 0, PAGE_SIZE as usize);
                pdpt_entry.set(pd_phys, intermediate_flags);
            } else {
                // Entry exists - ensure USER flag is set for user-accessible mappings
                if flags.contains(PageFlags::USER) {
                    let current_flags = pdpt_entry.flags();
                    if current_flags & PAGE_USER == 0 {
                        pdpt_entry
                            .set(pdpt_entry.addr(), current_flags | PAGE_USER | PAGE_WRITABLE);
                    }
                }
            }
            let pd = phys_to_virt_table(pdpt_entry.addr());

            // Get or create PT
            let pd_entry = (*pd).entry_mut(pd_idx);
            if !pd_entry.is_present() {
                let pt_phys = frame_alloc
                    .alloc_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                core::ptr::write_bytes(phys_to_virt(pt_phys), 0, PAGE_SIZE as usize);
                pd_entry.set(pt_phys, intermediate_flags);
            } else if pd_entry.flags() & PAGE_HUGE == 0 {
                // Entry exists and is not a huge page - ensure USER flag is set
                if flags.contains(PageFlags::USER) {
                    let current_flags = pd_entry.flags();
                    if current_flags & PAGE_USER == 0 {
                        pd_entry.set(pd_entry.addr(), current_flags | PAGE_USER | PAGE_WRITABLE);
                    }
                }
            } else {
                // This is a 2MB huge page - we need to split it to map 4KB pages
                // For now, return error - this case would need more complex handling
                return Err(MapError::FrameAllocationFailed);
            }
            let pt = phys_to_virt_table(pd_entry.addr());

            // Set the final page table entry (a fresh table, never
            // loaded: nothing to flush)
            let pt_entry = (*pt).entry_mut(pt_idx);
            pt_entry.set(pa, entry_flags);
        }

        Ok(())
    }

    /// Link the kernel half (PML4 entries 256-511 of the swapper) into
    /// this address space; the lower-level kernel tables are shared
    pub fn copy_kernel_mappings(&mut self) {
        unsafe {
            let kernel_pml4 = phys_to_virt_table_const(super::kmap::swapper_phys());
            let pml4 = phys_to_virt_table(self.pml4_phys);
            for i in KERNEL_PML4_START..ENTRIES_PER_TABLE {
                (*pml4).entries[i] = (*kernel_pml4).entries[i];
            }
        }
    }

    /// Get current CR3 value
    pub fn current_cr3() -> u64 {
        let cr3: u64;
        unsafe {
            ::core::arch::asm!(
                "mov {}, cr3",
                out(reg) cr3,
                options(nomem, nostack, preserves_flags)
            );
        }
        cr3
    }

    /// Translate a virtual address to physical address
    /// Returns None if the address is not mapped
    #[allow(dead_code)]
    pub fn virt_to_phys(&self, vaddr: u64) -> Option<u64> {
        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(vaddr);

        unsafe {
            let pml4 = phys_to_virt_table_const(self.pml4_phys);
            let pml4_entry = (*pml4).entry(pml4_idx);
            if !pml4_entry.is_present() {
                return None;
            }

            let pdpt = phys_to_virt_table_const(pml4_entry.addr());
            let pdpt_entry = (*pdpt).entry(pdpt_idx);
            if !pdpt_entry.is_present() {
                return None;
            }

            // Check for 1GB huge page
            if pdpt_entry.flags() & PAGE_HUGE != 0 {
                let page_offset = vaddr & 0x3FFFFFFF;
                return Some(pdpt_entry.addr() + page_offset);
            }

            let pd = phys_to_virt_table_const(pdpt_entry.addr());
            let pd_entry = (*pd).entry(pd_idx);
            if !pd_entry.is_present() {
                return None;
            }

            // Check for 2MB huge page
            if pd_entry.flags() & PAGE_HUGE != 0 {
                let page_offset = vaddr & 0x1FFFFF;
                return Some(pd_entry.addr() + page_offset);
            }

            let pt = phys_to_virt_table_const(pd_entry.addr());
            let pt_entry = (*pt).entry(pt_idx);
            if !pt_entry.is_present() {
                return None;
            }

            let page_offset = vaddr & 0xFFF;
            Some(pt_entry.addr() + page_offset)
        }
    }
}

/// Extract page table indices from virtual address
fn page_indices(vaddr: u64) -> (usize, usize, usize, usize) {
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;
    (pml4_idx, pdpt_idx, pd_idx, pt_idx)
}

impl PageTable for X86_64PageTable {
    type VirtAddr = u64;
    type PhysAddr = u64;

    fn map(&mut self, va: Self::VirtAddr, pa: Self::PhysAddr, flags: PageFlags) {
        // Convert flags
        let mut entry_flags = PAGE_PRESENT;
        if flags.contains(PageFlags::WRITE) {
            entry_flags |= PAGE_WRITABLE;
        }
        if flags.contains(PageFlags::USER) {
            entry_flags |= PAGE_USER;
        }
        if !flags.contains(PageFlags::EXECUTE) {
            entry_flags |= PAGE_NO_EXECUTE;
        }

        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);

        // Walk the page tables, creating entries as needed
        // For now, this is a simplified version that assumes tables exist
        // In a real implementation, we'd allocate missing tables

        unsafe {
            let pml4 = phys_to_virt_table(self.pml4_phys);

            // Get or create PDPT
            let pml4_entry = (*pml4).entry_mut(pml4_idx);
            if !pml4_entry.is_present() {
                // Would need to allocate a new PDPT here
                // For now, panic
                return;
            }
            let pdpt = phys_to_virt_table(pml4_entry.addr());

            // Get or create PD
            let pdpt_entry = (*pdpt).entry_mut(pdpt_idx);
            if !pdpt_entry.is_present() {
                return;
            }
            let pd = phys_to_virt_table(pdpt_entry.addr());

            // Get or create PT
            let pd_entry = (*pd).entry_mut(pd_idx);
            if !pd_entry.is_present() {
                return;
            }
            let pt = phys_to_virt_table(pd_entry.addr());

            // Set the final page table entry (callers flush: mm::tlb)
            let pt_entry = (*pt).entry_mut(pt_idx);
            pt_entry.set(pa, entry_flags);
        }
    }

    fn unmap(&mut self, va: Self::VirtAddr) {
        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);

        unsafe {
            let pml4 = phys_to_virt_table(self.pml4_phys);

            let pml4_entry = (*pml4).entry(pml4_idx);
            if !pml4_entry.is_present() {
                return;
            }
            let pdpt = phys_to_virt_table(pml4_entry.addr());

            let pdpt_entry = (*pdpt).entry(pdpt_idx);
            if !pdpt_entry.is_present() {
                return;
            }
            let pd = phys_to_virt_table(pdpt_entry.addr());

            let pd_entry = (*pd).entry(pd_idx);
            if !pd_entry.is_present() {
                return;
            }
            let pt = phys_to_virt_table(pd_entry.addr());

            // Callers flush (mm::tlb)
            let pt_entry = (*pt).entry_mut(pt_idx);
            pt_entry.clear();
        }
    }

    fn translate(&self, va: Self::VirtAddr) -> Option<Self::PhysAddr> {
        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);
        let offset = va & 0xFFF;

        unsafe {
            let pml4 = phys_to_virt_table_const(self.pml4_phys);

            let pml4_entry = (*pml4).entry(pml4_idx);
            if !pml4_entry.is_present() {
                return None;
            }
            let pdpt = phys_to_virt_table_const(pml4_entry.addr());

            let pdpt_entry = (*pdpt).entry(pdpt_idx);
            if !pdpt_entry.is_present() {
                return None;
            }
            // Check for 1GB huge page
            if pdpt_entry.flags() & PAGE_HUGE != 0 {
                let base = pdpt_entry.addr();
                return Some(base | (va & 0x3FFF_FFFF));
            }
            let pd = phys_to_virt_table_const(pdpt_entry.addr());

            let pd_entry = (*pd).entry(pd_idx);
            if !pd_entry.is_present() {
                return None;
            }
            // Check for 2MB huge page
            if pd_entry.flags() & PAGE_HUGE != 0 {
                let base = pd_entry.addr();
                return Some(base | (va & 0x1F_FFFF));
            }
            let pt = phys_to_virt_table_const(pd_entry.addr());

            let pt_entry = (*pt).entry(pt_idx);
            if !pt_entry.is_present() {
                return None;
            }

            Some(pt_entry.addr() | offset)
        }
    }

    fn map_with_alloc<FA: FrameAlloc<PhysAddr = Self::PhysAddr>>(
        &mut self,
        va: Self::VirtAddr,
        pa: Self::PhysAddr,
        flags: PageFlags,
        frame_alloc: &mut FA,
    ) -> Result<(), MapError> {
        // Delegate to the inherent method
        X86_64PageTable::map_with_alloc(self, va, pa, flags, frame_alloc)
    }

    fn new_user<FA: FrameAlloc<PhysAddr = Self::PhysAddr>>(frame_alloc: &mut FA) -> Option<Self> {
        // Delegate to the inherent method
        X86_64PageTable::new_user(frame_alloc)
    }

    fn copy_kernel_mappings(&mut self) {
        // Delegate to the inherent method
        X86_64PageTable::copy_kernel_mappings(self)
    }

    fn root_table_phys(&self) -> Self::PhysAddr {
        self.pml4_phys
    }

    fn kernel_identity() -> Self {
        // Delegate to the inherent method
        X86_64PageTable::kernel_identity()
    }
}

/// COW (Copy-on-Write) flag - we use an available bit in the PTE
/// Bit 9 is one of the "available" bits (9-11) that can be used by the OS
pub const PAGE_COW: u64 = 1 << 9;

impl X86_64PageTable {
    /// Update protection flags for a 2MB huge page
    ///
    /// # Arguments
    /// * `pml4_phys` - Physical address of the PML4 table
    /// * `va` - Virtual address (must be 2MB-aligned)
    /// * `writable` - Whether the page should be writable
    /// * `executable` - Whether the page should be executable
    ///
    /// # Returns
    /// `true` if the huge page was found and updated, `false` if not mapped
    pub fn update_huge_page_protection(
        pml4_phys: u64,
        va: u64,
        writable: bool,
        executable: bool,
    ) -> bool {
        let (pml4_idx, pdpt_idx, pd_idx, _pt_idx) = page_indices(va);

        unsafe {
            let pml4 = phys_to_virt_table(pml4_phys);

            let pml4_entry = (*pml4).entry(pml4_idx);
            if !pml4_entry.is_present() {
                return false;
            }
            let pdpt = phys_to_virt_table(pml4_entry.addr());

            let pdpt_entry = (*pdpt).entry(pdpt_idx);
            if !pdpt_entry.is_present() {
                return false;
            }
            if pdpt_entry.is_huge() {
                // 1GB huge page - not handled here
                return false;
            }
            let pd = phys_to_virt_table(pdpt_entry.addr());

            let pd_entry = (*pd).entry_mut(pd_idx);
            if !pd_entry.is_present() || !pd_entry.is_huge() {
                // Must be a 2MB huge page
                return false;
            }

            // Get current entry, preserve address and base flags
            let phys = pd_entry.addr();
            let mut flags = pd_entry.flags();

            // Update writable flag
            if writable {
                flags |= PAGE_WRITABLE;
            } else {
                flags &= !PAGE_WRITABLE;
            }

            // Update executable flag (NX bit - inverted logic)
            if executable {
                flags &= !PAGE_NO_EXECUTE;
            } else {
                flags |= PAGE_NO_EXECUTE;
            }

            // Write back the updated entry (the caller flushes the TLB)
            pd_entry.set(phys, flags);

            true
        }
    }

    /// Translate a virtual address to physical using the given page table root
    ///
    /// Static method that takes pml4_phys directly.
    pub fn translate_with_root(pml4_phys: u64, va: u64) -> Option<u64> {
        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);
        let offset = va & 0xFFF;

        unsafe {
            let pml4 = phys_to_virt_table_const(pml4_phys);

            let pml4_entry = (*pml4).entry(pml4_idx);
            if !pml4_entry.is_present() {
                return None;
            }
            let pdpt = phys_to_virt_table_const(pml4_entry.addr());

            let pdpt_entry = (*pdpt).entry(pdpt_idx);
            if !pdpt_entry.is_present() {
                return None;
            }
            if pdpt_entry.is_huge() {
                let base = pdpt_entry.addr();
                return Some(base | (va & 0x3FFF_FFFF));
            }
            let pd = phys_to_virt_table_const(pdpt_entry.addr());

            let pd_entry = (*pd).entry(pd_idx);
            if !pd_entry.is_present() {
                return None;
            }
            if pd_entry.is_huge() {
                let base = pd_entry.addr();
                return Some(base | (va & 0x1F_FFFF));
            }
            let pt = phys_to_virt_table_const(pd_entry.addr());

            let pt_entry = (*pt).entry(pt_idx);
            if !pt_entry.is_present() {
                return None;
            }

            Some(pt_entry.addr() | offset)
        }
    }

    /// Read the page table entry for a virtual address
    ///
    /// Returns the physical address and flags of the mapped page, or None if not mapped.
    /// Only supports 4KB pages (not huge pages).
    ///
    /// This is used by mremap to copy page mappings to a new location.
    pub fn read_pte(pml4_phys: u64, va: u64) -> Option<(u64, u64)> {
        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);

        unsafe {
            let pml4 = phys_to_virt_table_const(pml4_phys);

            let pml4_entry = (*pml4).entry(pml4_idx);
            if !pml4_entry.is_present() {
                return None;
            }
            let pdpt = phys_to_virt_table_const(pml4_entry.addr());

            let pdpt_entry = (*pdpt).entry(pdpt_idx);
            if !pdpt_entry.is_present() {
                return None;
            }
            // Huge pages not supported
            if pdpt_entry.is_huge() {
                return None;
            }
            let pd = phys_to_virt_table_const(pdpt_entry.addr());

            let pd_entry = (*pd).entry(pd_idx);
            if !pd_entry.is_present() {
                return None;
            }
            // Huge pages not supported
            if pd_entry.is_huge() {
                return None;
            }
            let pt = phys_to_virt_table_const(pd_entry.addr());

            let pt_entry = (*pt).entry(pt_idx);
            if !pt_entry.is_present() {
                return None;
            }

            Some((pt_entry.addr(), pt_entry.flags()))
        }
    }

    // =========================================================================
    // Transparent Huge Page (THP) Support - 2MB pages
    // =========================================================================

    /// Map a 2MB huge page at PD (Page Directory) level
    ///
    /// Creates a direct 2MB mapping in the PD entry, skipping the PT level.
    /// The virtual address must be 2MB-aligned.
    ///
    /// # Arguments
    /// * `pml4_phys` - Physical address of the PML4 table
    /// * `va` - Virtual address (must be 2MB-aligned)
    /// * `pa` - Physical address of the 2MB frame (must be 2MB-aligned)
    /// * `flags` - Page table entry flags
    /// * `frame_alloc` - Frame allocator for intermediate tables
    ///
    /// # Returns
    /// Ok(()) on success, Err(MapError) on failure
    pub fn map_huge_page<FA: FrameAlloc<PhysAddr = u64>>(
        pml4_phys: u64,
        va: u64,
        pa: u64,
        flags: PageFlags,
        frame_alloc: &mut FA,
    ) -> Result<(), MapError> {
        const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

        // Verify alignment
        if va & (HUGE_PAGE_SIZE - 1) != 0 {
            return Err(MapError::InvalidAddress);
        }
        if pa & (HUGE_PAGE_SIZE - 1) != 0 {
            return Err(MapError::InvalidAddress);
        }

        // Convert PageFlags to x86-64 PTE flags with PAGE_HUGE
        let mut entry_flags = PAGE_PRESENT | PAGE_HUGE;
        if flags.contains(PageFlags::WRITE) {
            entry_flags |= PAGE_WRITABLE;
        }
        if flags.contains(PageFlags::USER) {
            entry_flags |= PAGE_USER;
        }
        if !flags.contains(PageFlags::EXECUTE) {
            entry_flags |= PAGE_NO_EXECUTE;
        }

        let intermediate_flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;

        let (pml4_idx, pdpt_idx, pd_idx, _pt_idx) = page_indices(va);

        unsafe {
            let pml4 = phys_to_virt_table(pml4_phys);

            // Get or create PDPT
            let pml4_entry = (*pml4).entry_mut(pml4_idx);
            if !pml4_entry.is_present() {
                let pdpt_phys = frame_alloc
                    .alloc_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                core::ptr::write_bytes(phys_to_virt(pdpt_phys), 0, PAGE_SIZE as usize);
                pml4_entry.set(pdpt_phys, intermediate_flags);
            }
            let pdpt = phys_to_virt_table(pml4_entry.addr());

            // Get or create PD
            let pdpt_entry = (*pdpt).entry_mut(pdpt_idx);
            if !pdpt_entry.is_present() {
                let pd_phys = frame_alloc
                    .alloc_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                core::ptr::write_bytes(phys_to_virt(pd_phys), 0, PAGE_SIZE as usize);
                pdpt_entry.set(pd_phys, intermediate_flags);
            } else if pdpt_entry.is_huge() {
                // 1GB huge page exists here - can't map 2MB within it
                return Err(MapError::AlreadyMapped);
            }
            let pd = phys_to_virt_table(pdpt_entry.addr());

            // Check PD entry - should not already be mapped
            let pd_entry = (*pd).entry_mut(pd_idx);
            if pd_entry.is_present() {
                return Err(MapError::AlreadyMapped);
            }

            // Set the 2MB huge page entry (no PT, direct to physical frame);
            // it was empty: no TLB entry to flush
            pd_entry.set(pa, entry_flags);
        }

        Ok(())
    }
}
