//! x86-64 paging (4-level page tables)
//!
//! Implements the PageTable trait for x86-64 4-level paging:
//! PML4 -> PDPT -> PD -> PT -> Physical Page
//!
//! The user-table walkers here are `unsafe fn`s on a raw root: generic
//! code reaches them only through `mm::pgtable`, whose handles borrow
//! the lock that keeps the tables.

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

/// Kernel stacks (`mm::vmstack`): the vmalloc area's second gigabyte
pub const VMSTACK_START: u64 = VMALLOC_START + (1 << 30);

/// vmalloc allocations (`mm::vmalloc`): 16 GiB, in the vmalloc window's PML4 entry, so every address space shares its tables
pub const VMALLOC_AREA: u64 = VMALLOC_START + (4 << 30);
pub const VMALLOC_AREA_SIZE: u64 = 16 << 30;

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
    phys_to_virt(phys).cast::<RawPageTable>()
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

/// Entry `idx` (mod 512) of the table frame `table`, through the direct
/// map
#[inline]
fn slot(table: u64, idx: u64) -> *mut u64 {
    phys_to_virt(table)
        .cast::<u64>()
        .wrapping_add((idx & 511) as usize)
}

/// The value of the entry at `p`
///
/// # Safety
///
/// `p` is an entry of a live table frame.
#[inline]
unsafe fn load(p: *mut u64) -> u64 {
    // SAFETY: a live entry (the caller's guarantee); page-table entries
    // are only accessed atomically
    unsafe { AtomicU64::from_ptr(p) }.load(Ordering::Acquire)
}

/// Pointer to the 4KB leaf entry for `va` in the tables rooted at
/// `root` (present or not, e.g. a swap entry); None if an upper level
/// is missing or maps a huge page
///
/// # Safety
///
/// `root` is a live top-level table, and no table under it that maps
/// `va` is freed during the call.
pub(crate) unsafe fn pte_ptr(root: u64, va: u64) -> Option<*mut u64> {
    // SAFETY: the caller's guarantee
    let pd = unsafe { pmd_ptr(root, va) }?;
    // SAFETY: an entry of a table under `root` mapping `va`, kept
    let e = PageTableEntry(unsafe { load(pd) });
    if !e.is_present() || e.is_huge() {
        return None;
    }
    Some(slot(e.addr(), va >> 12))
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
// User PTE helpers for the generic fault and fork paths (mm)
// ============================================================================

/// Intermediate entries of user tables
const USER_TABLE: u64 = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;

/// Pointer to the 2MB-level (PD) entry for `va` in the tables rooted at
/// `root` (Linux pmd_offset); None if an upper level is missing
///
/// # Safety
///
/// As [`pte_ptr`].
pub(crate) unsafe fn pmd_ptr(root: u64, va: u64) -> Option<*mut u64> {
    if !user_va(va) {
        return None;
    }
    let mut table = root;
    for shift in [39, 30] {
        // SAFETY: an entry of `root` or of a table under it mapping
        // `va`, kept (the caller's guarantee)
        let e = PageTableEntry(unsafe { load(slot(table, va >> shift)) });
        if !e.is_present() || e.is_huge() {
            return None;
        }
        table = e.addr();
    }
    Some(slot(table, va >> 21))
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

/// A zeroed frame for a user page table, not yet in any table (Linux
/// pte_alloc_one, pmd_alloc_one): taken with no page-table lock held,
/// so it may reclaim. User page tables stop at the low watermark like
/// the user pages they map: a process touching sparse addresses cannot
/// drain the kernel's reserve with tables. None if out of memory.
pub fn table_alloc() -> Option<u64> {
    let new = crate::FRAME_ALLOCATOR.alloc_gfp(crate::mm::page_alloc::Gfp::USER)?;
    // SAFETY: a fresh frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(new), 0, PAGE_SIZE as usize) };
    Some(new)
}

/// Install the table `new` in the upper-level entry `slot` if it is
/// still empty (Linux pmd_install, pud_populate); false if an entry is
/// there, `new` then still the caller's
///
/// # Safety
///
/// `slot` is an upper-level entry of a live user table, its address
/// space's page_table_lock held (no split under way); `new` is a zeroed
/// table frame the caller owns, which the tables take over on success.
pub(crate) unsafe fn table_install(slot: &AtomicU64, new: u64) -> bool {
    slot.compare_exchange(0, new | USER_TABLE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// The table under the upper-level entry `p` of a user table, `install`
/// called to put one in while it is empty. None if `install` fails (out
/// of memory) or a huge page maps it.
///
/// # Safety
///
/// `p` is an upper-level entry of a live user table; `install` changes
/// the entry it is handed only through [`table_install`].
unsafe fn next_alloc(p: *mut u64, install: &mut dyn FnMut(&AtomicU64) -> bool) -> Option<u64> {
    // SAFETY: a live entry (the caller's guarantee), only accessed
    // atomically
    let slot = unsafe { AtomicU64::from_ptr(p) };
    loop {
        let e = crate::mm::huge_page::pmd_settled(slot);
        if e != 0 {
            return table_of(e);
        }
        if !install(slot) {
            return None;
        }
    }
}

/// Pointer to the 2MB-level (PD) entry for `va`, missing upper tables
/// put in by `install` (Linux pmd_alloc); None if out of memory
///
/// # Safety
///
/// As [`pte_ptr`]; `install` changes the entry it is handed only
/// through [`table_install`].
pub(crate) unsafe fn pmd_alloc(
    root: u64,
    va: u64,
    install: &mut dyn FnMut(&AtomicU64) -> bool,
) -> Option<*mut u64> {
    if !user_va(va) {
        return None;
    }
    let mut table = root;
    for shift in [39, 30] {
        // SAFETY: an entry of `root` or of a table under it mapping
        // `va`, kept (the caller's guarantee); `install` as required
        table = unsafe { next_alloc(slot(table, va >> shift), install) }?;
    }
    Some(slot(table, va >> 21))
}

/// Pointer to the 4KB leaf entry for `va`, missing tables put in by
/// `install` (Linux pte_alloc). None if out of memory or a huge page
/// maps `va`.
///
/// # Safety
///
/// As [`pmd_alloc`].
pub(crate) unsafe fn pte_alloc(
    root: u64,
    va: u64,
    install: &mut dyn FnMut(&AtomicU64) -> bool,
) -> Option<*mut u64> {
    // SAFETY: the caller's guarantee
    let pd = unsafe { pmd_alloc(root, va, install) }?;
    // SAFETY: the 2MB-level entry of `va` under `root`, kept; `install`
    // as required
    let pt = unsafe { next_alloc(pd, install) }?;
    Some(slot(pt, va >> 12))
}

/// The physical address `va` maps to in the tables rooted at `root`
/// (a 4KB or 2MB page); None if not mapped
///
/// # Safety
///
/// As [`pte_ptr`].
pub(crate) unsafe fn translate(root: u64, va: u64) -> Option<u64> {
    // SAFETY: the caller's guarantee
    let pd = unsafe { pmd_ptr(root, va) }?;
    // SAFETY: the 2MB-level entry of `va` under `root`, kept
    let e = PageTableEntry(unsafe { load(pd) });
    if !e.is_present() {
        return None;
    }
    if e.is_huge() {
        return Some(e.addr() | (va & 0x1F_FFFF));
    }
    // SAFETY: the 4KB entry of `va`, in a table kept like the others
    let e = PageTableEntry(unsafe { load(slot(e.addr(), va >> 12)) });
    e.is_present().then(|| e.addr() | (va & 0xFFF))
}

/// Fill the page table `pt` with the 512 4KB entries of the 2MB entry
/// `pmd`: same frames, protection and accessed/dirty bits (Linux
/// __split_huge_pmd_locked). Returns the 2MB frame's base.
///
/// # Safety
///
/// `pt` is a table frame the caller owns that no table holds yet.
pub(crate) unsafe fn split_table(pt: u64, pmd: u64) -> u64 {
    const HUGE_MASK: u64 = (2 << 20) - 1;
    let base = pmd & ADDR_MASK & !HUGE_MASK;
    let flags = (pmd & !ADDR_MASK & !PAGE_HUGE) | PAGE_PRESENT;
    for i in 0..ENTRIES_PER_TABLE as u64 {
        // SAFETY: entry `i` of the caller's unreachable table frame
        unsafe { slot(pt, i).write((base + i * PAGE_SIZE) | flags) };
    }
    base
}

/// Install the filled table `pt` in the empty 2MB-level entry `pmd`
/// (Linux pmd_populate)
///
/// # Safety
///
/// `pt` is a PTE table frame the caller owns and hands to the tables
/// `pmd` lies in.
pub(crate) unsafe fn pmd_populate(pmd: &AtomicU64, pt: u64) {
    pmd.store(pt | USER_TABLE, Ordering::Release);
}

/// A 2MB user entry for the 2MB frame `pa` with `flags` (Linux mk_pmd
/// + pmd_mkhuge)
pub fn mk_pmd(pa: u64, flags: PageFlags) -> u64 {
    let mut e = (pa & ADDR_MASK) | PAGE_PRESENT | PAGE_HUGE;
    if flags.contains(PageFlags::WRITE) {
        e |= PAGE_WRITABLE;
    }
    if flags.contains(PageFlags::USER) {
        e |= PAGE_USER;
    }
    if !flags.contains(PageFlags::EXECUTE) {
        e |= PAGE_NO_EXECUTE;
    }
    e
}

/// Install the 2MB entry `v` in the empty 2MB-level entry `pmd`: false
/// if it was not empty. No flush: an empty entry is never cached.
pub fn pmd_set_huge(pmd: &AtomicU64, v: u64) -> bool {
    pmd.compare_exchange(0, v, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// The 2MB entry `pmd` writable or not, executable or not (Linux
/// pmd_modify); frame and other bits kept
pub fn pmd_mkprot(pmd: u64, writable: bool, executable: bool) -> u64 {
    let mut e = pmd & !(PAGE_WRITABLE | PAGE_NO_EXECUTE);
    if writable {
        e |= PAGE_WRITABLE;
    }
    if !executable {
        e |= PAGE_NO_EXECUTE;
    }
    e
}

/// A user leaf entry for `phys` with the protection of a VMA (PROT_*),
/// marked accessed (Linux mk_pte + pte_mkyoung); PROT_NONE gives a
/// protnone entry (Linux vm_page_prot PAGE_NONE)
pub fn mk_pte(phys: u64, prot: u32) -> u64 {
    let mut pte = phys | PAGE_PRESENT | PAGE_USER | PAGE_ACCESSED;
    if prot & crate::mm::PROT_WRITE != 0 {
        pte |= PAGE_WRITABLE;
    }
    if prot & crate::mm::PROT_EXEC == 0 {
        pte |= PAGE_NO_EXECUTE;
    }
    if prot & (crate::mm::PROT_READ | crate::mm::PROT_WRITE | crate::mm::PROT_EXEC) == 0 {
        return pte_modify(pte, prot);
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

/// Read-only and clean (a shared file page written back: the next
/// write faults and dirties it again, Linux folio_mkclean)
pub fn pte_wrprotect(pte: u64) -> u64 {
    pte & !(PAGE_WRITABLE | PAGE_DIRTY)
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
///
/// # Invariants
///
/// Each frame is a PDPT detached from its address space, which no CPU
/// walks once the caller flushed them, owned by this value with every
/// table under it.
pub struct UserTables(alloc::vec::Vec<u64>);

/// Detach the user half from the top-level table `pml4_phys` (Linux
/// exit_mmap: unmap_vmas + free_pgtables, first half): its PML4
/// entries 0-255 are cleared, the tables below are kept intact for
/// [`UserTables::free`], which runs after the caller flushed every CPU
/// that may still walk them. The shared kernel half (PML4 256-511) is
/// left untouched.
///
/// # Safety
///
/// `pml4_phys` is a live top-level table whose user tables no one else
/// reaches (no handle to them lives or is made later), and the caller
/// frees them only after that flush.
pub(crate) unsafe fn detach_user(pml4_phys: u64) -> UserTables {
    let mut top = alloc::vec::Vec::new();
    for i in 0..KERNEL_PML4_START as u64 {
        // SAFETY: an entry of the live root (the caller's guarantee),
        // only accessed atomically
        let e = PageTableEntry(
            unsafe { AtomicU64::from_ptr(slot(pml4_phys, i)) }.swap(0, Ordering::AcqRel),
        );
        if e.is_present() {
            top.push(e.addr());
        }
    }
    // INVARIANT: the user tables, detached, ours (the caller's guarantee)
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
/// PDPT, 2 a PD, 1 a PT. A table of a `UserTables`.
fn free_level(phys: u64, level: u32, put: &mut dyn FnMut(Leaf)) {
    for i in 0..ENTRIES_PER_TABLE as u64 {
        // SAFETY: a detached table frame that no CPU walks, owned by
        // the `UserTables` being freed (its type invariant)
        let e = PageTableEntry(unsafe { slot(phys, i).read() });
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
    // A PMD table: the page tables its 2MB pages kept for a split
    if level == 2 {
        crate::mm::huge_page::free_deposits(phys);
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
///
/// # Invariants
///
/// `pml4_phys` is a live top-level table its holder owns: a fresh one
/// (`new_user`) or the swapper (`kernel_identity`), the only ways to
/// make one.
pub struct X86_64PageTable {
    /// Physical address of PML4
    pml4_phys: u64,
}

impl X86_64PageTable {
    /// The table at `pml4_phys`
    ///
    /// # Safety
    ///
    /// `pml4_phys` is a live top-level table the result's holder owns
    /// (type invariant).
    unsafe fn from_root(pml4_phys: u64) -> Self {
        // INVARIANT: the caller's guarantee
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
        // SAFETY: the swapper, live forever
        unsafe { Self::from_root(super::kmap::swapper_phys()) }
    }

    /// Create a new user page table (allocates PML4)
    pub fn new_user<FA: FrameAlloc<PhysAddr = u64>>(frame_alloc: &mut FA) -> Option<Self> {
        let pml4_phys = frame_alloc.alloc_frame()?;
        // SAFETY: a fresh frame, reached through the direct map
        unsafe { core::ptr::write_bytes(phys_to_virt(pml4_phys), 0, PAGE_SIZE as usize) };
        // SAFETY: a fresh zeroed table frame, the result's
        Some(unsafe { Self::from_root(pml4_phys) })
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

        // SAFETY: `pml4_phys` is a live root its holder owns (type
        // invariant; exec builds it before any CPU loads it), and each
        // table under it is a live frame reached through the direct
        // map; fresh frames are zeroed before they are linked
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
            } else if pdpt_entry.flags() & PAGE_HUGE != 0 {
                // A 1GB leaf covers it
                return Err(MapError::AlreadyMapped);
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
                // A 2MB leaf covers it (as aarch64 reports a block)
                return Err(MapError::AlreadyMapped);
            }
            let pt = phys_to_virt_table(pd_entry.addr());

            // Set the final page table entry (a fresh table, never
            // loaded: nothing to flush); a page already there stays
            let pt_entry = (*pt).entry_mut(pt_idx);
            if pt_entry.is_present() {
                return Err(MapError::AlreadyMapped);
            }
            pt_entry.set(pa, entry_flags);
        }

        Ok(())
    }

    /// Link the kernel half (PML4 entries 256-511 of the swapper) into
    /// this address space; the lower-level kernel tables are shared
    pub fn copy_kernel_mappings(&mut self) {
        // SAFETY: the swapper and this root are live top-level tables
        // (type invariant), reached through the direct map; the kernel
        // half is only read from the swapper
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
        // SAFETY: reads CR3 only (no memory access, no stack, flags
        // kept)
        unsafe {
            ::core::arch::asm!(
                "mov {}, cr3",
                out(reg) cr3,
                options(nomem, nostack, preserves_flags)
            );
        }
        cr3
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

    fn translate(&self, va: Self::VirtAddr) -> Option<Self::PhysAddr> {
        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);
        let offset = va & 0xFFF;

        // SAFETY: `pml4_phys` is a live root its holder owns (type
        // invariant); each table under it is a live frame reached
        // through the direct map
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
