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

use crate::arch::{FrameAlloc, MapError, PageFlags, PageTable};

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

/// COW (Copy-on-Write) flag - software-defined bit
/// We use bit 55 which is available for OS use on ARM64
/// When set along with AP_EL0_RO, indicates a writable page that is
/// temporarily read-only for COW sharing between parent and child.
pub const PAGE_COW: u64 = 1 << 55;

/// Physical address bits of a page table entry
pub const PTE_ADDR_MASK: u64 = ADDR_MASK;

/// Pointer to the 4KB leaf (L3) entry for `va` in the tables rooted at
/// `root` (valid or not, e.g. a swap entry); None if an upper level is
/// missing or is a block
pub fn pte_ptr(root: u64, va: u64) -> Option<*mut u64> {
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

/// A leaf entry maps a page
pub fn pte_present(pte: u64) -> bool {
    pte & 1 != 0
}

/// Switch this CPU's user address space (TTBR0) to `root`
pub fn activate(root: u64) {
    unsafe {
        asm!(
            "msr ttbr0_el1, {}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            in(reg) root,
            options(nostack)
        );
    }
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

    /// Get the attributes/flags from the entry
    #[inline]
    pub fn attrs(&self) -> u64 {
        self.0 & !ADDR_MASK
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

/// Invalidate TLB entry for a specific virtual address
#[inline]
pub fn flush_tlb(vaddr: u64) {
    unsafe {
        // TLBI VAE1IS: Invalidate by VA, EL1, Inner Shareable
        // The address must be shifted right by 12 bits
        let va_shifted = vaddr >> 12;
        asm!(
            "dsb ishst",
            "tlbi vae1is, {va}",
            "dsb ish",
            "isb",
            va = in(reg) va_shifted,
            options(nostack)
        );
    }
}

/// Flush TLB for a range of virtual addresses
///
/// Uses full TLB flush for large ranges (more efficient than many individual flushes)
/// and individual TLBI instructions for small ranges.
#[inline]
pub fn flush_tlb_range(start: u64, end: u64) {
    const INVLPG_THRESHOLD: u64 = 32 * PAGE_SIZE;

    if end <= start {
        return;
    }

    let range = end - start;

    if range > INVLPG_THRESHOLD {
        // Full TLB flush is cheaper for large ranges
        flush_tlb_all();
    } else {
        // Individual flushes for small ranges
        let mut addr = start & !(PAGE_SIZE - 1);
        while addr < end {
            flush_tlb(addr);
            addr += PAGE_SIZE;
        }
    }
}

/// Flush entire TLB (all entries for EL1)
#[inline]
pub fn flush_tlb_all() {
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}

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
        // Convert generic flags to AArch64 page attributes
        let mut attrs = AF | SH_INNER | ATTR_IDX_NORMAL;

        if flags.contains(PageFlags::USER) {
            if flags.contains(PageFlags::WRITE) {
                attrs |= AP_EL0_RW;
            } else {
                attrs |= AP_EL0_RO;
            }
        } else if flags.contains(PageFlags::WRITE) {
            attrs |= AP_EL1_RW;
        } else {
            attrs |= AP_EL1_RO;
        }

        if !flags.contains(PageFlags::EXECUTE) {
            attrs |= PXN | UXN;
        }

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

            // Set the L3 page entry
            let l3_entry = (*l3).entry_mut(l3_idx);
            l3_entry.set_page(pa, attrs);

            // Clean the data cache for this page table entry
            // This ensures the write is visible to the MMU
            let entry_addr = l3_entry as *mut PageTableEntry as u64;
            asm!(
                "dc cvau, {}",
                "dsb ish",
                in(reg) entry_addr,
                options(nostack)
            );

            // Flush TLB for this address
            flush_tlb(va);
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

    /// Duplicate the user space portion of this page table for fork()
    ///
    /// Uses Copy-on-Write (COW) for writable pages:
    /// - Writable pages are marked read-only with PAGE_COW flag in both parent and child
    /// - Physical frames are shared with incremented reference count
    /// - On first write, a page fault triggers COW resolution (copy then)
    ///
    /// This is much more efficient than eager copying, especially for fork+exec patterns.
    pub fn duplicate_user_space<FA: FrameAlloc<PhysAddr = u64>>(
        &self,
        frame_alloc: &mut FA,
    ) -> Result<Self, i32> {
        // New TTBR0 table: holds only user mappings
        let new_pt = Self::new_user(frame_alloc).ok_or(-12i32)?; // ENOMEM

        // Track range for batch TLB flush
        let mut flush_start: Option<u64> = None;
        let mut flush_end: u64 = 0;

        unsafe {
            let parent_l0 = phys_to_virt_table(self.root_phys);

            // Walk all L0 entries (0-511)
            for l0_idx in 0..ENTRIES_PER_TABLE {
                let l0_entry = (*parent_l0).entry(l0_idx);
                if !l0_entry.is_valid() {
                    continue;
                }

                // L0 must be a table descriptor
                if !l0_entry.is_table() {
                    continue;
                }

                let l1 = phys_to_virt_table(l0_entry.addr());

                // Walk L1 entries
                for l1_idx in 0..ENTRIES_PER_TABLE {
                    let l1_entry = (*l1).entry(l1_idx);
                    if !l1_entry.is_valid() {
                        continue;
                    }

                    let vaddr_l1 = ((l0_idx as u64) << 39) | ((l1_idx as u64) << 30);

                    // 1GB blocks are never user mappings
                    if l1_entry.is_block() {
                        continue;
                    }

                    let l2 = phys_to_virt_table(l1_entry.addr());

                    // Walk L2 entries
                    for l2_idx in 0..ENTRIES_PER_TABLE {
                        let l2_entry = (*l2).entry(l2_idx);
                        if !l2_entry.is_valid() {
                            continue;
                        }

                        let vaddr_l2 = vaddr_l1 | ((l2_idx as u64) << 21);

                        // Check for 2MB block
                        if l2_entry.is_block() {
                            // 2MB block - skip for now
                            continue;
                        }

                        let l3_parent = phys_to_virt_table(l2_entry.addr());

                        // Walk L3 entries (4KB pages)
                        for l3_idx in 0..ENTRIES_PER_TABLE {
                            let l3_entry = (*l3_parent).entry_mut(l3_idx);
                            if !l3_entry.is_valid() {
                                continue;
                            }

                            let vaddr = vaddr_l2 | ((l3_idx as u64) << 12);

                            // Skip kernel-only pages (ioremap, etc.)
                            // User pages have AP_EL0_RW or AP_EL0_RO set
                            let pte_value = l3_entry.0;
                            let attrs = pte_value & !ADDR_MASK & !0b11;
                            if attrs & (AP_EL0_RW | AP_EL0_RO) == 0 {
                                continue;
                            }

                            let src_phys = l3_entry.addr();
                            let is_writable = (attrs & AP_EL0_RW) == AP_EL0_RW;

                            // COW handling for writable pages
                            let child_pte = if is_writable {
                                // Mark parent as read-only with COW flag
                                // Clear AP_EL0_RW, set AP_EL0_RO and PAGE_COW
                                let parent_new_pte =
                                    (pte_value & !AP_EL0_RW) | AP_EL0_RO | PAGE_COW;
                                l3_entry.0 = parent_new_pte;

                                // Track for TLB flush
                                if flush_start.is_none() {
                                    flush_start = Some(vaddr);
                                }
                                flush_end = vaddr + PAGE_SIZE;

                                // Child gets same COW mapping
                                parent_new_pte
                            } else {
                                // Read-only page - just share it as-is
                                pte_value
                            };

                            // Increment reference count on shared frame
                            crate::FRAME_ALLOCATOR.incref(src_phys);

                            // Map in child - we need to map with the raw PTE value
                            // to preserve PAGE_COW flag
                            Self::map_raw_pte(new_pt.root_phys, vaddr, child_pte, frame_alloc)
                                .map_err(|_| -12i32)?;
                        }
                    }
                }
            }

            // Batch TLB flush for parent's modified PTEs
            if let Some(start) = flush_start {
                flush_tlb_range(start, flush_end);
            }
        }

        Ok(new_pt)
    }

    /// Map a page with a raw PTE value (used by COW to preserve PAGE_COW flag)
    ///
    /// This allocates intermediate page tables as needed and sets the L3 entry
    /// to the exact PTE value provided.
    fn map_raw_pte<FA: FrameAlloc<PhysAddr = u64>>(
        l0_phys: u64,
        va: u64,
        pte_value: u64,
        frame_alloc: &mut FA,
    ) -> Result<(), MapError> {
        let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);

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
                return Err(MapError::AlreadyMapped);
            }
            let l3 = phys_to_virt_table(l2_entry.addr());

            // Set the L3 page entry with the raw PTE value
            (*l3).entry_mut(l3_idx).0 = pte_value;

            // Clean the data cache for this page table entry
            let entry_addr = (*l3).entry_mut(l3_idx) as *mut PageTableEntry as u64;
            asm!(
                "dc cvau, {}",
                "dsb ish",
                in(reg) entry_addr,
                options(nostack)
            );
        }

        Ok(())
    }

    /// Unmap a single page and return its physical address
    ///
    /// This is a static method that takes the page table root directly,
    /// useful for unmapping pages without needing a full Aarch64PageTable instance.
    ///
    /// Returns Some(phys_addr) if the page was mapped, None if not mapped.
    pub fn unmap_page(l0_phys: u64, va: u64) -> Option<u64> {
        let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);

        unsafe {
            let l0 = phys_to_virt_table(l0_phys);

            let l0_entry = (*l0).entry(l0_idx);
            if !l0_entry.is_valid() || !l0_entry.is_table() {
                return None;
            }
            let l1 = phys_to_virt_table(l0_entry.addr());

            let l1_entry = (*l1).entry(l1_idx);
            if !l1_entry.is_valid() {
                return None;
            }
            // 1GB block pages not supported for unmap
            if l1_entry.is_block() {
                return None;
            }
            let l2 = phys_to_virt_table(l1_entry.addr());

            let l2_entry = (*l2).entry(l2_idx);
            if !l2_entry.is_valid() {
                return None;
            }
            // 2MB block pages not supported for unmap
            if l2_entry.is_block() {
                return None;
            }
            let l3 = phys_to_virt_table(l2_entry.addr());

            let l3_entry = (*l3).entry_mut(l3_idx);
            if !l3_entry.is_valid() {
                return None;
            }

            // Get physical address before clearing
            let phys = l3_entry.addr();

            // Clear the entry
            l3_entry.clear();

            // Flush TLB for this address
            flush_tlb(va);

            Some(phys)
        }
    }

    /// Update the protection flags on an already-mapped page
    ///
    /// This modifies the page table entry for the given virtual address
    /// to have new protection flags, without changing the physical mapping.
    ///
    /// # Arguments
    /// * `l0_phys` - Physical address of the L0 table
    /// * `va` - Virtual address of the page to modify
    /// * `writable` - Whether the page should be writable
    /// * `executable` - Whether the page should be executable
    ///
    /// # Returns
    /// `true` if the page was found and updated, `false` if not mapped
    pub fn update_page_protection(l0_phys: u64, va: u64, writable: bool, executable: bool) -> bool {
        let (l0_idx, l1_idx, l2_idx, l3_idx) = page_indices(va);

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
            // 1GB block pages not supported for protection update
            if l1_entry.is_block() {
                return false;
            }
            let l2 = phys_to_virt_table(l1_entry.addr());

            let l2_entry = (*l2).entry(l2_idx);
            if !l2_entry.is_valid() {
                return false;
            }
            // 2MB block pages not supported for protection update
            if l2_entry.is_block() {
                return false;
            }
            let l3 = phys_to_virt_table(l2_entry.addr());

            let l3_entry = (*l3).entry_mut(l3_idx);
            if !l3_entry.is_valid() {
                return false;
            }

            // Get current entry, preserve address
            let phys = l3_entry.addr();

            // Build new attributes, preserving AF, SH, ATTR_IDX
            let mut attrs = l3_entry.0 & (AF | SH_INNER | 0b11100); // Preserve AF, SH, ATTR_IDX

            // Set access permissions
            // For user pages: AP_EL0_RW (writable) or AP_EL0_RO (read-only)
            // We detect if this is a user page by checking if AP[1] was set (EL0 access)
            let was_user = (l3_entry.0 & AP_EL0_RW) != 0 || (l3_entry.0 & AP_EL0_RO) != 0;

            if was_user {
                if writable {
                    attrs |= AP_EL0_RW;
                } else {
                    attrs |= AP_EL0_RO;
                }
            } else {
                // Kernel page
                if writable {
                    attrs |= AP_EL1_RW;
                } else {
                    attrs |= AP_EL1_RO;
                }
            }

            // Set execute permissions
            if !executable {
                attrs |= PXN | UXN;
            }

            // Write back the updated entry
            l3_entry.set_page(phys, attrs);

            // Clean data cache and flush TLB
            let entry_addr = l3_entry as *mut PageTableEntry as u64;
            asm!(
                "dc cvau, {}",
                "dsb ish",
                in(reg) entry_addr,
                options(nostack)
            );
            flush_tlb(va);

            true
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

            // Build new attributes, preserving AF, SH, ATTR_IDX
            let mut attrs = l2_entry.0 & (AF | SH_INNER | 0b11100); // Preserve AF, SH, ATTR_IDX

            // Detect if user page
            let was_user = (l2_entry.0 & AP_EL0_RW) != 0 || (l2_entry.0 & AP_EL0_RO) != 0;

            if was_user {
                if writable {
                    attrs |= AP_EL0_RW;
                } else {
                    attrs |= AP_EL0_RO;
                }
            } else if writable {
                attrs |= AP_EL1_RW;
            } else {
                attrs |= AP_EL1_RO;
            }

            // Set execute permissions
            if !executable {
                attrs |= PXN | UXN;
            }

            // Write back the updated entry as a block descriptor
            l2_entry.set_block(phys, attrs);

            // Clean data cache and flush TLB
            let entry_addr = l2_entry as *mut PageTableEntry as u64;
            asm!(
                "dc cvau, {}",
                "dsb ish",
                in(reg) entry_addr,
                options(nostack)
            );
            flush_tlb(va);

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
        // Convert flags to AArch64 attributes
        let mut attrs = AF | SH_INNER | ATTR_IDX_NORMAL;

        if flags.contains(PageFlags::USER) {
            if flags.contains(PageFlags::WRITE) {
                attrs |= AP_EL0_RW;
            } else {
                attrs |= AP_EL0_RO;
            }
        } else if flags.contains(PageFlags::WRITE) {
            attrs |= AP_EL1_RW;
        } else {
            attrs |= AP_EL1_RO;
        }

        if !flags.contains(PageFlags::EXECUTE) {
            attrs |= PXN | UXN;
        }

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

            // Set the page entry
            let l3_entry = (*l3).entry_mut(l3_idx);
            l3_entry.set_page(pa, attrs);

            flush_tlb(va);
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

            let l3_entry = (*l3).entry_mut(l3_idx);
            l3_entry.clear();

            flush_tlb(va);
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

    fn collect_table_frames(&self) -> alloc::vec::Vec<Self::PhysAddr> {
        use alloc::vec::Vec;
        let mut frames = Vec::new();

        // Add the root L0 frame
        frames.push(self.root_phys);

        unsafe {
            let l0 = phys_to_virt_table_const(self.root_phys);

            // Walk L0 entries (user space is in lower addresses)
            for l0_idx in 0..512 {
                let l0_entry = (*l0).entry(l0_idx);
                if !l0_entry.is_valid() || l0_entry.is_block() {
                    continue;
                }

                let l1_phys = l0_entry.addr();
                frames.push(l1_phys);
                let l1 = phys_to_virt_table_const(l1_phys);

                // Walk L1 entries
                for l1_idx in 0..512 {
                    let l1_entry = (*l1).entry(l1_idx);
                    if !l1_entry.is_valid() || l1_entry.is_block() {
                        continue;
                    }

                    let l2_phys = l1_entry.addr();
                    frames.push(l2_phys);
                    let l2 = phys_to_virt_table_const(l2_phys);

                    // Walk L2 entries
                    for l2_idx in 0..512 {
                        let l2_entry = (*l2).entry(l2_idx);
                        if !l2_entry.is_valid() || l2_entry.is_block() {
                            continue;
                        }

                        let l3_phys = l2_entry.addr();
                        frames.push(l3_phys);
                        // Don't recurse into L3 - those are user page frames, not table frames
                    }
                }
            }
        }

        frames
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

        // Convert generic flags to AArch64 block attributes
        let mut attrs = AF | SH_INNER | ATTR_IDX_NORMAL;

        if flags.contains(PageFlags::USER) {
            if flags.contains(PageFlags::WRITE) {
                attrs |= AP_EL0_RW;
            } else {
                attrs |= AP_EL0_RO;
            }
        } else if flags.contains(PageFlags::WRITE) {
            attrs |= AP_EL1_RW;
        } else {
            attrs |= AP_EL1_RO;
        }

        if !flags.contains(PageFlags::EXECUTE) {
            attrs |= PXN | UXN;
        }

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

            // Set the 2MB block entry
            l2_entry.set_block(pa, attrs);

            // Clean the data cache for this page table entry
            let entry_addr = l2_entry as *mut PageTableEntry as u64;
            asm!(
                "dc cvau, {}",
                "dsb ish",
                in(reg) entry_addr,
                options(nostack)
            );

            // Flush TLB for this address
            flush_tlb(va);
        }

        Ok(())
    }

    /// Unmap a 2MB huge page
    ///
    /// Clears the L2 block entry for the given 2MB-aligned virtual address.
    ///
    /// # Arguments
    /// * `l0_phys` - Physical address of the L0 (root) table
    /// * `va` - Virtual address (must be 2MB-aligned)
    ///
    /// # Returns
    /// Some(phys_addr) if a huge page was unmapped, None otherwise
    pub fn unmap_huge_page(l0_phys: u64, va: u64) -> Option<u64> {
        let (l0_idx, l1_idx, l2_idx, _l3_idx) = page_indices(va);

        unsafe {
            let l0 = phys_to_virt_table(l0_phys);

            let l0_entry = (*l0).entry(l0_idx);
            if !l0_entry.is_valid() || !l0_entry.is_table() {
                return None;
            }
            let l1 = phys_to_virt_table(l0_entry.addr());

            let l1_entry = (*l1).entry(l1_idx);
            if !l1_entry.is_valid() || l1_entry.is_block() {
                return None;
            }
            let l2 = phys_to_virt_table(l1_entry.addr());

            let l2_entry = (*l2).entry_mut(l2_idx);
            if !l2_entry.is_valid() || !l2_entry.is_block() {
                return None;
            }

            // Get physical address before clearing
            let phys = l2_entry.addr();

            // Clear the entry
            l2_entry.clear();

            // Clean the data cache for this page table entry
            let entry_addr = l2_entry as *mut PageTableEntry as u64;
            asm!(
                "dc cvau, {}",
                "dsb ish",
                in(reg) entry_addr,
                options(nostack)
            );

            // Flush TLB for this huge page region
            flush_tlb(va);

            Some(phys)
        }
    }

    /// Split a 2MB huge page into 512 4KB pages
    ///
    /// Allocates a new L3 table, creates 512 page entries pointing to the same
    /// physical memory (consecutive 4KB pages), and updates the L2 entry
    /// to point to the new L3 table.
    ///
    /// # Arguments
    /// * `l0_phys` - Physical address of the L0 (root) table
    /// * `va` - Virtual address of the huge page (must be 2MB-aligned)
    /// * `frame_alloc` - Frame allocator for the new L3 table
    ///
    /// # Returns
    /// Ok(phys_base) with the base physical address of the split huge page,
    /// Err(MapError) on failure
    pub fn split_huge_page<FA: FrameAlloc<PhysAddr = u64>>(
        l0_phys: u64,
        va: u64,
        frame_alloc: &mut FA,
    ) -> Result<u64, MapError> {
        let (l0_idx, l1_idx, l2_idx, _l3_idx) = page_indices(va);

        unsafe {
            let l0 = phys_to_virt_table(l0_phys);

            let l0_entry = (*l0).entry(l0_idx);
            if !l0_entry.is_valid() || !l0_entry.is_table() {
                return Err(MapError::NotMapped);
            }
            let l1 = phys_to_virt_table(l0_entry.addr());

            let l1_entry = (*l1).entry(l1_idx);
            if !l1_entry.is_valid() || l1_entry.is_block() {
                return Err(MapError::NotMapped);
            }
            let l2 = phys_to_virt_table(l1_entry.addr());

            let l2_entry = (*l2).entry_mut(l2_idx);
            if !l2_entry.is_valid() || !l2_entry.is_block() {
                return Err(MapError::NotMapped);
            }

            // Get the huge page physical address and attributes
            let huge_phys = l2_entry.addr();
            let old_attrs = l2_entry.attrs();

            // Convert block attributes to page attributes
            // Block and page descriptors use the same attribute bits
            let page_attrs = old_attrs & !0b11; // Clear descriptor type bits

            // Allocate a new L3 table
            let l3_phys = frame_alloc
                .alloc_frame()
                .ok_or(MapError::FrameAllocationFailed)?;
            let l3 = phys_to_virt_table(l3_phys);

            // Fill the L3 with 512 page entries pointing to consecutive 4KB pages
            for i in 0..512 {
                let page_phys = huge_phys + (i as u64 * PAGE_SIZE);
                (*l3).entry_mut(i).set_page(page_phys, page_attrs);
            }

            // Update L2 entry to point to the new L3 table
            l2_entry.set_table(l3_phys);

            // Clean the data cache for the L2 entry and all L3 entries
            let l2_entry_addr = l2_entry as *mut PageTableEntry as u64;
            asm!(
                "dc cvau, {}",
                in(reg) l2_entry_addr,
                options(nostack)
            );

            // Clean cache for all L3 entries
            for i in 0..512 {
                let l3_entry_addr = (*l3).entry(i) as *const PageTableEntry as u64;
                asm!(
                    "dc cvau, {}",
                    in(reg) l3_entry_addr,
                    options(nostack)
                );
            }

            asm!("dsb ish", options(nostack));

            // Flush entire TLB - splitting affects many addresses
            flush_tlb_all();

            Ok(huge_phys)
        }
    }

    /// Check if a virtual address is mapped as a 2MB huge page
    ///
    /// # Arguments
    /// * `l0_phys` - Physical address of the L0 (root) table
    /// * `va` - Virtual address to check
    ///
    /// # Returns
    /// Some((phys_addr, attrs)) if mapped as huge page, None otherwise
    /// The phys_addr is the 2MB-aligned base address of the huge page
    pub fn is_huge_page_mapped(l0_phys: u64, va: u64) -> Option<(u64, u64)> {
        let (l0_idx, l1_idx, l2_idx, _l3_idx) = page_indices(va);

        unsafe {
            let l0 = phys_to_virt_table_const(l0_phys);

            let l0_entry = (*l0).entry(l0_idx);
            if !l0_entry.is_valid() || !l0_entry.is_table() {
                return None;
            }
            let l1 = phys_to_virt_table_const(l0_entry.addr());

            let l1_entry = (*l1).entry(l1_idx);
            if !l1_entry.is_valid() || l1_entry.is_block() {
                return None;
            }
            let l2 = phys_to_virt_table_const(l1_entry.addr());

            let l2_entry = (*l2).entry(l2_idx);
            if !l2_entry.is_valid() || !l2_entry.is_block() {
                return None;
            }

            Some((l2_entry.addr(), l2_entry.attrs()))
        }
    }
}
