//! AArch64 paging (4-level page tables)
//!
//! Implements the PageTable trait for AArch64 4-level translation tables:
//! L0 -> L1 -> L2 -> L3 -> Physical Page (4KB granule)
//!
//! With 48-bit virtual addresses and 4KB pages:
//! - L0: 512 entries, each covering 512GB
//! - L1: 512 entries, each covering 1GB (can be block descriptor)
//! - L2: 512 entries, each covering 2MB (can be block descriptor)
//! - L3: 512 entries, each covering 4KB (page descriptor)
//!
//! TTBR0_EL1 maps user space only (lower half of the address space);
//! TTBR1_EL1 maps the kernel (upper half): see kmap.rs and doc/MEMORY.md.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{FrameAlloc, Leaf, MapError, PageFlags, PageTable};

/// Page size (4KB)
pub const PAGE_SIZE: u64 = 4096;

/// Number of entries per page table (512)
const ENTRIES_PER_TABLE: usize = 512;

/// Mask for physical address in page table entry (bits [47:12])
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

// ============================================================================
// Address space layout (see kmap.rs)
// ============================================================================

/// Linear map of RAM: physical address p is at PAGE_OFFSET + p (start of
/// the TTBR1 half, Linux arm64 48-bit)
pub const PAGE_OFFSET: u64 = 0xFFFF_0000_0000_0000;

/// Kernel image: linked at KIMAGE_OFFSET + physical (kernel.ld)
pub const KIMAGE_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// vmalloc/ioremap window (1GB)
pub const VMALLOC_START: u64 = 0xFFFF_8001_0000_0000;

/// Device window: physical 0-1GB (QEMU virt's GIC, UART, RTC, PCI MMIO)
/// mapped as Device memory at IO_BASE + physical (an early fixmap)
pub const IO_BASE: u64 = 0xFFFF_8002_0000_0000;

/// Size of the device window
pub const IO_SIZE: u64 = 1 << 30;

/// End of user space: all of TTBR0 (48-bit)
pub const TASK_SIZE: u64 = 1 << 48;

/// Device-window address of a low physical MMIO address
pub const fn io_va(phys: u64) -> u64 {
    IO_BASE + phys
}

/// Convert physical address to virtual address (linear map; Linux __va)
#[inline]
pub fn phys_to_virt(phys: u64) -> *mut u8 {
    (phys + PAGE_OFFSET) as *mut u8
}

/// Convert a linear-map or kernel-image address to physical (Linux __pa)
#[inline]
pub fn virt_to_phys(virt: u64) -> u64 {
    if virt >= KIMAGE_OFFSET {
        debug_assert!(virt < VMALLOC_START);
        virt - KIMAGE_OFFSET
    } else {
        debug_assert!(virt >= PAGE_OFFSET);
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

// ============================================================================
// Page Table Entry Descriptor Types
// ============================================================================

/// Invalid descriptor (bits [1:0] = 0b00)
const DESC_INVALID: u64 = 0b00;

/// Block descriptor (bits [1:0] = 0b01) - for L1 (1GB) or L2 (2MB) huge pages
const DESC_BLOCK: u64 = 0b01;

/// Table descriptor (bits [1:0] = 0b11) - points to next level table
const DESC_TABLE: u64 = 0b11;

/// Page descriptor (bits [1:0] = 0b11) - for L3 4KB pages
const DESC_PAGE: u64 = 0b11;

// ============================================================================
// Page Table Entry Attribute Bits
// ============================================================================

/// Access Flag (bit 10) - must be 1 for valid entries
pub const AF: u64 = 1 << 10;

/// Shareability field (bits [9:8])
/// Inner Shareable - for SMP coherency
pub const SH_INNER: u64 = 0b11 << 8;

/// Access Permission bits [7:6] (AP[2:1])
/// Per ARM ARM: AP[2:1] for stage 1 EL1&0 regime:
/// AP[2]=0, AP[1]=0: EL1 RW, EL0 none
/// AP[2]=0, AP[1]=1: EL1 RW, EL0 RW
/// AP[2]=1, AP[1]=0: EL1 RO, EL0 none
/// AP[2]=1, AP[1]=1: EL1 RO, EL0 RO
pub const AP_EL1_RW: u64 = 0b00 << 6;
pub const AP_EL0_RW: u64 = 0b01 << 6;
pub const AP_EL1_RO: u64 = 0b10 << 6;
pub const AP_EL0_RO: u64 = 0b11 << 6;

/// Memory attribute index (bits [4:2]) - indexes into MAIR_EL1
pub const ATTR_IDX_NORMAL: u64 = 0 << 2; // Normal memory (cacheable)
pub const ATTR_IDX_DEVICE: u64 = 1 << 2; // Device memory (nGnRnE)

/// Privileged Execute Never (bit 53)
pub const PXN: u64 = 1 << 53;

/// User Execute Never (bit 54)
pub const UXN: u64 = 1 << 54;

/// Not global (bit 11): the entry is tagged with the ASID of the
/// address space; every user entry has it, kernel entries never
pub const NG: u64 = 1 << 11;

/// COW (Copy-on-Write) flag - software-defined bit
/// We use bit 55 which is available for OS use on ARM64
/// When set along with AP_EL0_RO, indicates a writable page that is
/// temporarily read-only for COW sharing between parent and child.
pub const PAGE_COW: u64 = 1 << 55;

/// Physical address bits of a page table entry
pub const PTE_ADDR_MASK: u64 = ADDR_MASK;

/// `va` lies in the user half (below TASK_SIZE): the user page-table
/// walkers never reach the kernel half (x86 PML4 256-511) nor alias a
/// user entry with an address past the user range (arm64 TTBR0)
fn user_va(va: u64) -> bool {
    va < TASK_SIZE
}

/// Pointer to the 4KB leaf (L3) entry for `va` in the tables rooted at
/// `root` (valid or not, e.g. a swap entry); None if an upper level is
/// missing or is a block
pub fn pte_ptr(root: u64, va: u64) -> Option<*mut u64> {
    if !user_va(va) {
        return None;
    }
    let mut table = phys_to_virt(root) as *mut u64;
    for shift in [39, 30, 21] {
        let e = unsafe { *table.add(((va >> shift) & 511) as usize) };
        if e & 0b11 != DESC_TABLE {
            return None;
        }
        table = phys_to_virt(e & ADDR_MASK) as *mut u64;
    }
    Some(unsafe { table.add(((va >> 12) & 511) as usize) })
}

/// A leaf entry maps a page: valid, or protnone (Linux pte_present)
pub fn pte_present(pte: u64) -> bool {
    pte & 1 != 0 || pte_protnone(pte)
}

/// Software bit of a PROT_NONE entry (Linux PTE_PROT_NONE): invalid to
/// the MMU, so every access faults, but it keeps its frame (and the
/// frame reference) for a later mprotect to restore
pub const PTE_PROTNONE: u64 = 1 << 58;

/// A protnone leaf entry (never a swap entry: those carry the marker)
pub fn pte_protnone(pte: u64) -> bool {
    pte & (1 | PTE_PROTNONE | crate::mm::SwapEntry::SWAP_MARKER) == PTE_PROTNONE
}

/// `pte` with the protection `prot` (PROT_*; Linux pte_modify): none
/// at all makes it protnone (invalid); it is writable only if `prot`
/// asks for it and it is not a copy-on-write share. Frame and memory
/// attributes are kept: only permissions change, which needs no
/// break-before-make.
pub fn pte_modify(pte: u64, prot: u32) -> u64 {
    use crate::mm::{PROT_EXEC, PROT_READ, PROT_WRITE};
    let keep = pte & !(1 | AP_RDONLY | PXN | UXN | PTE_PROTNONE);
    if prot & (PROT_READ | PROT_WRITE | PROT_EXEC) == 0 {
        return keep | PTE_PROTNONE | AP_RDONLY | PXN | UXN;
    }
    let mut e = keep | 1 | PXN;
    if prot & PROT_WRITE == 0 || pte & PAGE_COW != 0 {
        e |= AP_RDONLY;
    }
    if prot & PROT_EXEC == 0 {
        e |= UXN;
    }
    e
}

/// The user leaf `pte` is executable by the kernel (EL1): never for a
/// valid entry built here, every user leaf carries PXN (`mm::check`)
#[cfg(feature = "mmcheck")]
pub fn pte_kexec(pte: u64) -> bool {
    pte & 1 != 0 && pte & PXN == 0
}

/// The user leaf `pte` is global (would match every ASID): never, every
/// user leaf carries nG (`mm::check`)
#[cfg(feature = "mmcheck")]
pub fn pte_global(pte: u64) -> bool {
    pte & 1 != 0 && pte & NG == 0
}

/// Leaf attributes for `flags` (Linux PAGE_*): a user page is never
/// executable at EL1 (PXN, as Linux sets on every user mapping), a
/// kernel page never at EL0 (UXN)
fn leaf_attrs(flags: PageFlags) -> u64 {
    let user = flags.contains(PageFlags::USER);
    let mut attrs = AF | SH_INNER | ATTR_IDX_NORMAL;
    attrs |= match (user, flags.contains(PageFlags::WRITE)) {
        (true, true) => AP_EL0_RW,
        (true, false) => AP_EL0_RO,
        (false, true) => AP_EL1_RW,
        (false, false) => AP_EL1_RO,
    };
    attrs |= if user { PXN | NG } else { UXN };
    if !flags.contains(PageFlags::EXECUTE) {
        attrs |= PXN | UXN;
    }
    attrs
}

// ============================================================================
// User PTE helpers for the generic fault and fork paths (kernel/mm)
// ============================================================================

/// AP[2]: read-only at every level
const AP_RDONLY: u64 = 1 << 7;

/// The descriptor at `idx` (mod 512) of the table at `table`, as an atomic
fn entry_atomic(table: *mut u64, idx: u64) -> &'static AtomicU64 {
    // SAFETY: a live table frame reached through the linear map
    unsafe { AtomicU64::from_ptr(table.add((idx & 511) as usize)) }
}

/// The descriptor at `p` in a live table, as an atomic
fn entry_ptr(p: *mut u64) -> &'static AtomicU64 {
    // SAFETY: `p` points into a live table frame (linear map)
    unsafe { AtomicU64::from_ptr(p) }
}

/// Pointer to the 2MB-level (L2) entry for `va` in the tables rooted at
/// `root` (Linux pmd_offset); None if an upper level is missing
pub fn pmd_ptr(root: u64, va: u64) -> Option<*mut u64> {
    if !user_va(va) {
        return None;
    }
    let mut table = phys_to_virt(root) as *mut u64;
    for shift in [39, 30] {
        let e = entry_atomic(table, va >> shift).load(Ordering::Acquire);
        if e & 0b11 != DESC_TABLE {
            return None;
        }
        table = phys_to_virt(e & ADDR_MASK) as *mut u64;
    }
    Some(entry_atomic(table, va >> 21).as_ptr())
}

/// A 2MB-level entry maps a huge page (block)
pub fn pmd_huge(pmd: u64) -> bool {
    pmd & 0b11 == DESC_BLOCK
}

/// Pointer to the 4KB leaf (L3) entry for `va`, allocating the missing
/// tables (Linux pte_alloc). A table is installed with a compare and
/// swap, so racing faults share one. None if out of memory (down to
/// the kernel's reserve) or a block maps `va`.
pub fn pte_alloc(root: u64, va: u64) -> Option<*mut u64> {
    if !user_va(va) {
        return None;
    }
    let mut table = phys_to_virt(root) as *mut u64;
    for shift in [39, 30, 21] {
        let slot = entry_atomic(table, va >> shift);
        let mut e = slot.load(Ordering::Acquire);
        if e & 0b11 == DESC_INVALID {
            // User page tables stop at the kernel's reserve, like
            // user pages (Linux GFP_PGTABLE_USER at the min watermark)
            if crate::FRAME_ALLOCATOR.below_reserve() {
                return None;
            }
            let new = crate::FRAME_ALLOCATOR.alloc()?;
            // SAFETY: a fresh frame, reached through the linear map
            unsafe { core::ptr::write_bytes(phys_to_virt(new), 0, PAGE_SIZE as usize) };
            let ent = new | DESC_TABLE;
            e = match slot.compare_exchange(e, ent, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => ent,
                Err(cur) => {
                    crate::FRAME_ALLOCATOR.free(new);
                    cur
                }
            };
        }
        if e & 0b11 != DESC_TABLE {
            return None;
        }
        table = phys_to_virt(e & ADDR_MASK) as *mut u64;
    }
    Some(entry_atomic(table, va >> 12).as_ptr())
}

/// Fill the fresh L3 table `pt` with the 512 4KB pages of the 2MB block
/// `pmd`: same frames and attributes (Linux __split_huge_pmd_locked).
/// Returns the block's base.
pub fn split_table(pt: u64, pmd: u64) -> u64 {
    const HUGE_MASK: u64 = (2 << 20) - 1;
    let base = pmd & ADDR_MASK & !HUGE_MASK;
    let attrs = pmd & !ADDR_MASK & !0b11;
    let l3 = phys_to_virt_table(pt);
    for i in 0..ENTRIES_PER_TABLE {
        // SAFETY: a fresh table frame, not yet reachable
        unsafe {
            (*l3)
                .entry_mut(i)
                .set_page(base + i as u64 * PAGE_SIZE, attrs)
        };
    }
    base
}

/// Install the filled table `pt` in the invalid (broken and flushed)
/// L2 entry at `pmdp` (Linux pmd_populate): the table's entries are
/// visible before the table is (break-before-make, "make")
pub fn pmd_populate(pmdp: *mut u64, pt: u64) {
    // SAFETY: barriers only
    unsafe { asm!("dsb ishst", options(nostack)) };
    entry_ptr(pmdp).store(pt | DESC_TABLE, Ordering::Release);
    // SAFETY: barriers only
    unsafe { asm!("dsb ishst", "isb", options(nostack)) };
}

/// A user leaf entry for `phys` with the protection of a VMA (PROT_*),
/// access flag set (Linux mk_pte + pte_mkyoung)
pub fn mk_pte(phys: u64, prot: u32) -> u64 {
    let mut pte = phys | DESC_PAGE | AF | SH_INNER | ATTR_IDX_NORMAL | NG;
    pte |= if prot & crate::mm::PROT_WRITE != 0 {
        AP_EL0_RW
    } else {
        AP_EL0_RO
    };
    // Never executable at EL1 (Linux sets PXN on every user mapping)
    pte |= PXN;
    if prot & crate::mm::PROT_EXEC == 0 {
        pte |= UXN;
    }
    pte
}

/// Physical address mapped by a 4KB leaf entry
pub fn pte_addr(pte: u64) -> u64 {
    pte & ADDR_MASK
}

/// The entry allows writes
pub fn pte_write(pte: u64) -> bool {
    pte & AP_RDONLY == 0
}

/// The entry allows instruction fetches from EL0
pub fn pte_exec(pte: u64) -> bool {
    pte & UXN == 0
}

/// The entry is a copy-on-write share (written only after a copy)
pub fn pte_cow(pte: u64) -> bool {
    pte & PAGE_COW != 0
}

/// Writable and young; no longer copy-on-write
pub fn pte_mkwrite(pte: u64) -> u64 {
    (pte & !(PAGE_COW | AP_RDONLY)) | AP_EL0_RW | AF
}

/// Read-only and copy-on-write (fork of a private mapping)
pub fn pte_mkcow(pte: u64) -> u64 {
    pte | AP_EL0_RO | PAGE_COW
}

/// Make a page the kernel just filled visible to instruction fetches
/// (Linux __sync_icache_dcache): clean it to the point of unification
/// and, for an executable page, invalidate the instruction caches
pub fn sync_page(phys: u64, exec: bool) {
    super::cache::cache_clean_range(phys_to_virt(phys), PAGE_SIZE as usize);
    if exec {
        // SAFETY: cache maintenance only
        unsafe { asm!("ic ialluis", "dsb ish", "isb", options(nostack)) };
    }
}

/// The user page tables of an address space, detached from its
/// top-level table by [`detach_user`]
pub struct UserTables(alloc::vec::Vec<u64>);

/// Detach the user tables from the TTBR0 root `l0_phys` (Linux
/// exit_mmap: unmap_vmas + free_pgtables, first half): its L0 entries
/// are cleared, the tables below kept intact for [`UserTables::free`],
/// which runs after the caller flushed every CPU that may still walk
/// them. The root frame itself is left to the caller.
pub fn detach_user(l0_phys: u64) -> UserTables {
    let l0 = phys_to_virt_table(l0_phys);
    let mut top = alloc::vec::Vec::new();
    for i in 0..ENTRIES_PER_TABLE {
        // SAFETY: a live root table reached through the linear map; its
        // entries belong to the caller
        unsafe {
            let e = *(*l0).entry(i);
            if e.is_table() {
                top.push(e.addr());
            }
            (*l0).entry_mut(i).clear();
        }
    }
    // The cleared entries are visible to table walks before the flush
    // SAFETY: barrier only
    unsafe { asm!("dsb ishst", options(nostack)) };
    UserTables(top)
}

impl UserTables {
    /// Release each user leaf (to `put`) and free every table frame
    pub fn free(self, put: &mut dyn FnMut(Leaf)) {
        for t in self.0 {
            free_level(t, 1, put);
        }
    }
}

/// Each user leaf under the TTBR0 root `l0_phys` that maps a page, in
/// address order: `f(va, entry, huge)` for a 4KB entry (protnone
/// included) or a 2MB block (debug check, `mm::check`; mm lock held)
#[cfg(feature = "mmcheck")]
pub fn walk_user(l0_phys: u64, f: &mut dyn FnMut(u64, u64, bool)) {
    walk_level(l0_phys, 0, 0, f);
}

/// Walk the table at `phys` (`level` 0 = L0 .. 3 = L3) mapping from `base`
#[cfg(feature = "mmcheck")]
fn walk_level(phys: u64, level: u32, base: u64, f: &mut dyn FnMut(u64, u64, bool)) {
    let table = phys_to_virt_table_const(phys);
    for i in 0..ENTRIES_PER_TABLE {
        // SAFETY: a live table of the locked mm
        let e = unsafe { *(*table).entry(i) };
        let va = base + ((i as u64) << (39 - 9 * level));
        match level {
            3 if pte_present(e.0) => f(va, e.0, false),
            2 if e.is_block() => f(va, e.0, true),
            0..=2 if e.is_table() => walk_level(e.addr(), level + 1, va, f),
            _ => {}
        }
    }
}

/// Release the table at `phys` (`level` 1, 2 or 3) and everything below
fn free_level(phys: u64, level: u32, put: &mut dyn FnMut(Leaf)) {
    let table = phys_to_virt_table_const(phys);
    for i in 0..ENTRIES_PER_TABLE {
        // SAFETY: a detached table frame owned by the caller
        let e = unsafe { *(*table).entry(i) };
        match level {
            3 if pte_present(e.0) => put(Leaf::Page(e.addr())),
            3 if e.0 != 0 => put(Leaf::Swap(e.0)),
            // 1GB user blocks are never created
            1 if e.is_table() => free_level(e.addr(), 2, put),
            2 if e.is_block() => put(Leaf::Huge(e.addr())),
            2 if e.is_table() => free_level(e.addr(), 3, put),
            _ => {}
        }
    }
    crate::FRAME_ALLOCATOR.free(phys);
}

// ============================================================================
// Page Table Entry Type
// ============================================================================

/// Page table entry
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Create an empty (invalid) entry
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if entry is valid (present)
    #[inline]
    pub fn is_valid(&self) -> bool {
        (self.0 & 0b11) != DESC_INVALID
    }

    /// Check if entry is a table descriptor (points to next level)
    #[inline]
    pub fn is_table(&self) -> bool {
        (self.0 & 0b11) == DESC_TABLE
    }

    /// Check if entry is a block descriptor (1GB or 2MB huge page)
    #[inline]
    pub fn is_block(&self) -> bool {
        (self.0 & 0b11) == DESC_BLOCK
    }

    /// Get physical address from entry
    #[inline]
    pub fn addr(&self) -> u64 {
        self.0 & ADDR_MASK
    }

    /// Set entry to a table descriptor
    #[inline]
    pub fn set_table(&mut self, next_table_phys: u64) {
        self.0 = (next_table_phys & ADDR_MASK) | DESC_TABLE;
    }

    /// Set entry to a page descriptor (L3 only, 4KB)
    #[inline]
    pub fn set_page(&mut self, phys_addr: u64, attrs: u64) {
        self.0 = (phys_addr & ADDR_MASK) | attrs | DESC_PAGE;
    }

    /// Set entry to a block descriptor (L1 for 1GB, L2 for 2MB)
    #[inline]
    pub fn set_block(&mut self, phys_addr: u64, attrs: u64) {
        self.0 = (phys_addr & ADDR_MASK) | attrs | DESC_BLOCK;
    }

    /// Clear the entry
    #[inline]
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

// ============================================================================
// Raw Page Table Structure
// ============================================================================

/// A raw page table (L0, L1, L2, or L3)
#[repr(C, align(4096))]
pub struct RawPageTable {
    /// 512 entries × 8 bytes = 4KB
    pub entries: [PageTableEntry; ENTRIES_PER_TABLE],
}

impl RawPageTable {
    /// Create an empty page table
    pub const fn new() -> Self {
        Self {
            entries: [PageTableEntry::empty(); ENTRIES_PER_TABLE],
        }
    }

    /// Get entry at index
    #[inline]
    pub fn entry(&self, index: usize) -> &PageTableEntry {
        &self.entries[index]
    }

    /// Get mutable entry at index
    #[inline]
    pub fn entry_mut(&mut self, index: usize) -> &mut PageTableEntry {
        &mut self.entries[index]
    }
}

impl Default for RawPageTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TLB maintenance
// ============================================================================

// ============================================================================
// Extract Page Table Indices from Virtual Address
// ============================================================================

/// Extract page table indices from a 48-bit virtual address
///
/// Virtual address format (4KB granule):
/// [47:39] = L0 index (9 bits)
/// [38:30] = L1 index (9 bits)
/// [29:21] = L2 index (9 bits)
/// [20:12] = L3 index (9 bits)
/// [11:0]  = Page offset (12 bits)
#[inline]
fn page_indices(vaddr: u64) -> (usize, usize, usize, usize) {
    let l0_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let l1_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let l2_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let l3_idx = ((vaddr >> 12) & 0x1FF) as usize;
    (l0_idx, l1_idx, l2_idx, l3_idx)
}

// ============================================================================
// Aarch64PageTable Implementation
// ============================================================================

/// AArch64 page table
///
/// Uses 4-level page tables with 4KB pages.
pub struct Aarch64PageTable {
    /// Physical address of the root table (L0)
    root_phys: u64,
}

impl Aarch64PageTable {
    /// Create a page table from an existing root physical address
    pub fn new(root_phys: u64) -> Self {
        Self { root_phys }
    }

    /// Get the root page table physical address
    #[inline]
    pub fn root_table_phys(&self) -> u64 {
        self.root_phys
    }

    /// TTBR0 table for kernel threads: empty (the kernel is in TTBR1;
    /// Linux reserved_pg_dir)
    pub fn kernel_identity() -> Self {
        Self::new(super::kmap::reserved_phys())
    }

    /// Create a new user page table (allocates L0)
    pub fn new_user<FA: FrameAlloc<PhysAddr = u64>>(frame_alloc: &mut FA) -> Option<Self> {
        let l0_phys = frame_alloc.alloc_frame()?;
        // Zero the L0 table
        unsafe {
            core::ptr::write_bytes(phys_to_virt(l0_phys), 0, PAGE_SIZE as usize);
        }
        Some(Self::new(l0_phys))
    }

    /// Nothing to copy: the kernel lives in TTBR1, shared by all
    pub fn copy_kernel_mappings(&mut self) {}

    /// Map a virtual address to physical with on-demand page table allocation
    pub fn map_with_alloc<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        va: u64,
        pa: u64,
        flags: PageFlags,
        frame_alloc: &mut FA,
    ) -> Result<(), MapError> {
        let attrs = leaf_attrs(flags);

        let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);

        unsafe {
            let l0 = phys_to_virt_table(self.root_phys);

            // Get or create L1 table
            let l0_entry = (*l0).entry_mut(l0_idx);
            if !l0_entry.is_valid() {
                let l1_phys = frame_alloc
                    .alloc_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                core::ptr::write_bytes(phys_to_virt(l1_phys), 0, PAGE_SIZE as usize);
                l0_entry.set_table(l1_phys);
            } else if !l0_entry.is_table() {
                // L0 entries must always be table descriptors
                return Err(MapError::InvalidArgument);
            }
            let l1 = phys_to_virt_table(l0_entry.addr());

            // Get or create L2 table
            let l1_entry = (*l1).entry_mut(l1_idx);
            if !l1_entry.is_valid() {
                let l2_phys = frame_alloc
                    .alloc_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                core::ptr::write_bytes(phys_to_virt(l2_phys), 0, PAGE_SIZE as usize);
                l1_entry.set_table(l2_phys);
            } else if l1_entry.is_block() {
                // Can't map 4KB page within a 1GB block
                return Err(MapError::AlreadyMapped);
            }
            let l2 = phys_to_virt_table(l1_entry.addr());

            // Get or create L3 table
            let l2_entry = (*l2).entry_mut(l2_idx);
            if !l2_entry.is_valid() {
                let l3_phys = frame_alloc
                    .alloc_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                core::ptr::write_bytes(phys_to_virt(l3_phys), 0, PAGE_SIZE as usize);
                l2_entry.set_table(l3_phys);
            } else if l2_entry.is_block() {
                // Can't map 4KB page within a 2MB block
                return Err(MapError::AlreadyMapped);
            }
            let l3 = phys_to_virt_table(l2_entry.addr());

            // Set the L3 page entry (a fresh table, never loaded:
            // nothing to flush; table walks are cache coherent)
            let l3_entry = (*l3).entry_mut(l3_idx);
            l3_entry.set_page(pa, attrs);
        }

        Ok(())
    }

    /// Translate a virtual address to physical address
    pub fn translate(&self, va: u64) -> Option<u64> {
        let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);
        let offset = va & 0xFFF;

        unsafe {
            let l0 = phys_to_virt_table_const(self.root_phys);

            let l0_entry = (*l0).entry(l0_idx);
            if !l0_entry.is_valid() || !l0_entry.is_table() {
                return None;
            }
            let l1 = phys_to_virt_table_const(l0_entry.addr());

            let l1_entry = (*l1).entry(l1_idx);
            if !l1_entry.is_valid() {
                return None;
            }
            // Check for 1GB block
            if l1_entry.is_block() {
                let base = l1_entry.addr();
                return Some(base | (va & 0x3FFF_FFFF));
            }
            let l2 = phys_to_virt_table_const(l1_entry.addr());

            let l2_entry = (*l2).entry(l2_idx);
            if !l2_entry.is_valid() {
                return None;
            }
            // Check for 2MB block
            if l2_entry.is_block() {
                let base = l2_entry.addr();
                return Some(base | (va & 0x1F_FFFF));
            }
            let l3 = phys_to_virt_table_const(l2_entry.addr());

            let l3_entry = (*l3).entry(l3_idx);
            if !l3_entry.is_valid() {
                return None;
            }

            Some(l3_entry.addr() | offset)
        }
    }

    /// Update protection flags for a 2MB huge page (L2 block descriptor)
    ///
    /// # Arguments
    /// * `l0_phys` - Physical address of the L0 table
    /// * `va` - Virtual address (must be 2MB-aligned)
    /// * `writable` - Whether the page should be writable
    /// * `executable` - Whether the page should be executable
    ///
    /// # Returns
    /// `true` if the huge page was found and updated, `false` if not mapped
    pub fn update_huge_page_protection(
        l0_phys: u64,
        va: u64,
        writable: bool,
        executable: bool,
    ) -> bool {
        let (l0_idx, l1_idx, l2_idx, _l3_idx) = page_indices(va);

        unsafe {
            let l0 = phys_to_virt_table(l0_phys);

            let l0_entry = (*l0).entry(l0_idx);
            if !l0_entry.is_valid() || !l0_entry.is_table() {
                return false;
            }
            let l1 = phys_to_virt_table(l0_entry.addr());

            let l1_entry = (*l1).entry(l1_idx);
            if !l1_entry.is_valid() {
                return false;
            }
            if l1_entry.is_block() {
                // 1GB block page - not handled here
                return false;
            }
            let l2 = phys_to_virt_table(l1_entry.addr());

            let l2_entry = (*l2).entry_mut(l2_idx);
            if !l2_entry.is_valid() || !l2_entry.is_block() {
                // Must be a 2MB block page
                return false;
            }

            // Get current entry, preserve address
            let phys = l2_entry.addr();

            // Only the permissions change: AP[2:1] (EL0 access, bit 6,
            // is kept) and the execute-never bits
            let user = l2_entry.0 & AP_EL0_RW != 0;
            let mut flags = PageFlags::READ;
            if user {
                flags |= PageFlags::USER;
            }
            if writable {
                flags |= PageFlags::WRITE;
            }
            if executable {
                flags |= PageFlags::EXECUTE;
            }
            let keep = l2_entry.0 & !(ADDR_MASK | 0b11 | AP_EL0_RO | PXN | UXN);
            let perm = AP_EL0_RO | PXN | UXN;
            let attrs = keep | (leaf_attrs(flags) & perm);

            // Write back the updated entry as a block descriptor
            l2_entry.set_block(phys, attrs);

            // Permissions only (no break-before-make needed); the
            // caller flushes the TLB of the range
            true
        }
    }

    /// Translate a virtual address to physical using the given page table root
    ///
    /// Static method that takes l0_phys directly.
    pub fn translate_with_root(l0_phys: u64, va: u64) -> Option<u64> {
        let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);
        let offset = va & 0xFFF;

        unsafe {
            let l0 = phys_to_virt_table_const(l0_phys);

            let l0_entry = (*l0).entry(l0_idx);
            if !l0_entry.is_valid() || !l0_entry.is_table() {
                return None;
            }
            let l1 = phys_to_virt_table_const(l0_entry.addr());

            let l1_entry = (*l1).entry(l1_idx);
            if !l1_entry.is_valid() {
                return None;
            }
            if l1_entry.is_block() {
                let base = l1_entry.addr();
                return Some(base | (va & 0x3FFF_FFFF)); // 1GB mask
            }
            let l2 = phys_to_virt_table_const(l1_entry.addr());

            let l2_entry = (*l2).entry(l2_idx);
            if !l2_entry.is_valid() {
                return None;
            }
            if l2_entry.is_block() {
                let base = l2_entry.addr();
                return Some(base | (va & 0x1F_FFFF)); // 2MB mask
            }
            let l3 = phys_to_virt_table_const(l2_entry.addr());

            let l3_entry = (*l3).entry(l3_idx);
            if !l3_entry.is_valid() {
                return None;
            }

            Some(l3_entry.addr() | offset)
        }
    }

    /// Read the page table entry for a virtual address
    ///
    /// Returns the physical address and attributes of the mapped page, or None if not mapped.
    /// Only supports 4KB pages (not block descriptors).
    ///
    /// This is used by mremap to copy page mappings to a new location.
    pub fn read_pte(l0_phys: u64, va: u64) -> Option<(u64, u64)> {
        let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);

        unsafe {
            let l0 = phys_to_virt_table_const(l0_phys);

            let l0_entry = (*l0).entry(l0_idx);
            if !l0_entry.is_valid() || !l0_entry.is_table() {
                return None;
            }
            let l1 = phys_to_virt_table_const(l0_entry.addr());

            let l1_entry = (*l1).entry(l1_idx);
            if !l1_entry.is_valid() {
                return None;
            }
            // Block pages not supported
            if l1_entry.is_block() {
                return None;
            }
            let l2 = phys_to_virt_table_const(l1_entry.addr());

            let l2_entry = (*l2).entry(l2_idx);
            if !l2_entry.is_valid() {
                return None;
            }
            // Block pages not supported
            if l2_entry.is_block() {
                return None;
            }
            let l3 = phys_to_virt_table_const(l2_entry.addr());

            let l3_entry = (*l3).entry(l3_idx);
            if !l3_entry.is_valid() {
                return None;
            }

            // Get physical address and attributes (strip the descriptor type bits)
            let phys = l3_entry.addr();
            let attrs = l3_entry.0 & !ADDR_MASK & !0b11;

            Some((phys, attrs))
        }
    }
}

// ============================================================================
// PageTable Trait Implementation
// ============================================================================

impl PageTable for Aarch64PageTable {
    type VirtAddr = u64;
    type PhysAddr = u64;

    fn map(&mut self, va: Self::VirtAddr, pa: Self::PhysAddr, flags: PageFlags) {
        let attrs = leaf_attrs(flags);

        let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);

        unsafe {
            let l0 = phys_to_virt_table(self.root_phys);

            // Walk page tables (assumes they exist)
            let l0_entry = (*l0).entry(l0_idx);
            if !l0_entry.is_valid() || !l0_entry.is_table() {
                return;
            }
            let l1 = phys_to_virt_table(l0_entry.addr());

            let l1_entry = (*l1).entry(l1_idx);
            if !l1_entry.is_valid() || l1_entry.is_block() {
                return;
            }
            let l2 = phys_to_virt_table(l1_entry.addr());

            let l2_entry = (*l2).entry(l2_idx);
            if !l2_entry.is_valid() || l2_entry.is_block() {
                return;
            }
            let l3 = phys_to_virt_table(l2_entry.addr());

            // Set the page entry (callers flush: mm::tlb)
            let l3_entry = (*l3).entry_mut(l3_idx);
            l3_entry.set_page(pa, attrs);
        }
    }

    fn unmap(&mut self, va: Self::VirtAddr) {
        let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);

        unsafe {
            let l0 = phys_to_virt_table(self.root_phys);

            let l0_entry = (*l0).entry(l0_idx);
            if !l0_entry.is_valid() || !l0_entry.is_table() {
                return;
            }
            let l1 = phys_to_virt_table(l0_entry.addr());

            let l1_entry = (*l1).entry(l1_idx);
            if !l1_entry.is_valid() || l1_entry.is_block() {
                return;
            }
            let l2 = phys_to_virt_table(l1_entry.addr());

            let l2_entry = (*l2).entry(l2_idx);
            if !l2_entry.is_valid() || l2_entry.is_block() {
                return;
            }
            let l3 = phys_to_virt_table(l2_entry.addr());

            // Callers flush (mm::tlb)
            let l3_entry = (*l3).entry_mut(l3_idx);
            l3_entry.clear();
        }
    }

    fn translate(&self, va: Self::VirtAddr) -> Option<Self::PhysAddr> {
        Aarch64PageTable::translate(self, va)
    }

    fn map_with_alloc<FA: FrameAlloc<PhysAddr = Self::PhysAddr>>(
        &mut self,
        va: Self::VirtAddr,
        pa: Self::PhysAddr,
        flags: PageFlags,
        frame_alloc: &mut FA,
    ) -> Result<(), MapError> {
        Aarch64PageTable::map_with_alloc(self, va, pa, flags, frame_alloc)
    }

    fn new_user<FA: FrameAlloc<PhysAddr = Self::PhysAddr>>(frame_alloc: &mut FA) -> Option<Self> {
        Aarch64PageTable::new_user(frame_alloc)
    }

    fn copy_kernel_mappings(&mut self) {
        Aarch64PageTable::copy_kernel_mappings(self)
    }

    fn root_table_phys(&self) -> Self::PhysAddr {
        self.root_phys
    }

    fn kernel_identity() -> Self {
        Aarch64PageTable::kernel_identity()
    }
}

// ============================================================================
// Transparent Huge Page (THP) Support - 2MB blocks at L2 level
// ============================================================================

impl Aarch64PageTable {
    /// Map a 2MB huge page at L2 level (block descriptor)
    ///
    /// Creates a 2MB block descriptor in the L2 table entry.
    /// The virtual address must be 2MB-aligned.
    ///
    /// # Arguments
    /// * `l0_phys` - Physical address of the L0 (root) table
    /// * `va` - Virtual address (must be 2MB-aligned)
    /// * `pa` - Physical address of the 2MB frame (must be 2MB-aligned)
    /// * `flags` - Page flags
    /// * `frame_alloc` - Frame allocator for intermediate tables
    ///
    /// # Returns
    /// Ok(()) on success, Err(MapError) on failure
    pub fn map_huge_page<FA: FrameAlloc<PhysAddr = u64>>(
        l0_phys: u64,
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

        let attrs = leaf_attrs(flags);

        let (l0_idx, l1_idx, l2_idx, _l3_idx) = page_indices(va);

        unsafe {
            let l0 = phys_to_virt_table(l0_phys);

            // Get or create L1 table
            let l0_entry = (*l0).entry_mut(l0_idx);
            if !l0_entry.is_valid() {
                let l1_phys = frame_alloc
                    .alloc_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                core::ptr::write_bytes(phys_to_virt(l1_phys), 0, PAGE_SIZE as usize);
                l0_entry.set_table(l1_phys);
            } else if !l0_entry.is_table() {
                return Err(MapError::InvalidArgument);
            }
            let l1 = phys_to_virt_table(l0_entry.addr());

            // Get or create L2 table
            let l1_entry = (*l1).entry_mut(l1_idx);
            if !l1_entry.is_valid() {
                let l2_phys = frame_alloc
                    .alloc_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                core::ptr::write_bytes(phys_to_virt(l2_phys), 0, PAGE_SIZE as usize);
                l1_entry.set_table(l2_phys);
            } else if l1_entry.is_block() {
                // 1GB block exists here - can't map 2MB within it
                return Err(MapError::AlreadyMapped);
            }
            let l2 = phys_to_virt_table(l1_entry.addr());

            // Check L2 entry - should not already be mapped
            let l2_entry = (*l2).entry_mut(l2_idx);
            if l2_entry.is_valid() {
                return Err(MapError::AlreadyMapped);
            }

            // Set the 2MB block entry: it was invalid, no TLB entry to
            // flush; visible to table walks before the access retries
            l2_entry.set_block(pa, attrs);
            asm!("dsb ishst", "isb", options(nostack));
        }

        Ok(())
    }
}
