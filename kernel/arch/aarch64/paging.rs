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
//! TTBR0_EL1 is used for user space (lower half of address space)
//! TTBR1_EL1 is used for kernel space (upper half of address space)
//!
//! For simplicity during early boot, we use identity mapping with TTBR0 only.

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

use crate::arch::{FrameAlloc, MapError, PageFlags, PageTable};

/// Page size (4KB)
pub const PAGE_SIZE: u64 = 4096;

/// Number of entries per page table (512)
const ENTRIES_PER_TABLE: usize = 512;

/// Mask for physical address in page table entry (bits [47:12])
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

// ============================================================================
// Physical-to-Virtual Address Conversion
// ============================================================================
//
// Phase 1: PAGE_OFFSET = 0 (identity mapping, no-op conversion)
// Phase 2: PAGE_OFFSET = 0xFFFF_8000_0000_0000 (high-address kernel)

/// Page offset for direct map
///
/// Physical address 0 maps to virtual address PAGE_OFFSET.
/// Currently 0 for identity mapping; will be changed to
/// 0xFFFF_8000_0000_0000 for high-address kernel.
pub const PAGE_OFFSET: u64 = 0;

/// Convert physical address to virtual address (direct map)
#[inline]
pub fn phys_to_virt(phys: u64) -> *mut u8 {
    (phys + PAGE_OFFSET) as *mut u8
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

// ============================================================================
// MAIR_EL1 Memory Attribute Configuration
// ============================================================================

/// Normal memory, Write-Back Cacheable
/// Outer: Write-Back Non-transient RW-Allocate (0xFF = 0b1111_1111)
/// Inner: Write-Back Non-transient RW-Allocate
const MAIR_ATTR_NORMAL: u64 = 0xFF;

/// Device memory, nGnRnE (non-Gathering, non-Reordering, no Early write ack)
const MAIR_ATTR_DEVICE: u64 = 0x00;

/// MAIR_EL1 value: Attr0=Normal, Attr1=Device
pub const MAIR_VALUE: u64 = (MAIR_ATTR_DEVICE << 8) | MAIR_ATTR_NORMAL;

// ============================================================================
// TCR_EL1 Translation Control Register Configuration
// ============================================================================

/// T0SZ: Size offset for TTBR0 region (16 = 48-bit VA)
const TCR_T0SZ: u64 = 16;

/// T1SZ: Size offset for TTBR1 region (16 = 48-bit VA)
const TCR_T1SZ: u64 = 16 << 16;

/// TG0: TTBR0 granule size (0b00 = 4KB)
const TCR_TG0_4K: u64 = 0b00 << 14;

/// TG1: TTBR1 granule size (0b10 = 4KB)
const TCR_TG1_4K: u64 = 0b10 << 30;

/// SH0: TTBR0 shareability (0b11 = Inner Shareable)
const TCR_SH0_INNER: u64 = 0b11 << 12;

/// SH1: TTBR1 shareability (0b11 = Inner Shareable)
const TCR_SH1_INNER: u64 = 0b11 << 28;

/// ORGN0/IRGN0: TTBR0 outer/inner cacheability (0b01 = Write-Back RW-Allocate)
const TCR_ORGN0_WB: u64 = 0b01 << 10;
const TCR_IRGN0_WB: u64 = 0b01 << 8;

/// ORGN1/IRGN1: TTBR1 outer/inner cacheability
const TCR_ORGN1_WB: u64 = 0b01 << 26;
const TCR_IRGN1_WB: u64 = 0b01 << 24;

/// IPS: Intermediate Physical Address Size (from ID_AA64MMFR0_EL1.PARange)
/// We'll detect this at runtime, but default to 40-bit (1TB)
const TCR_IPS_40BIT: u64 = 0b010 << 32;

/// TCR_EL1 value for 48-bit VA, 4KB granule
pub const TCR_VALUE: u64 = TCR_T0SZ
    | TCR_T1SZ
    | TCR_TG0_4K
    | TCR_TG1_4K
    | TCR_SH0_INNER
    | TCR_SH1_INNER
    | TCR_ORGN0_WB
    | TCR_IRGN0_WB
    | TCR_ORGN1_WB
    | TCR_IRGN1_WB
    | TCR_IPS_40BIT;

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
// Static Boot Page Tables (for identity mapping)
// ============================================================================

/// L0 page table (covers 512GB per entry, we need 1 entry for identity map)
#[repr(C, align(4096))]
struct BootL0Table {
    entries: [u64; ENTRIES_PER_TABLE],
}

/// L1 page table (covers 1GB per entry, using 2MB block descriptors)
#[repr(C, align(4096))]
struct BootL1Table {
    entries: [u64; ENTRIES_PER_TABLE],
}

/// L2 page table (covers 2MB per entry, using 2MB block descriptors)
#[repr(C, align(4096))]
struct BootL2Table {
    entries: [u64; ENTRIES_PER_TABLE],
}

/// Static boot page tables for identity mapping
/// We use 2MB block descriptors to map the first 4GB
static mut BOOT_L0: BootL0Table = BootL0Table {
    entries: [0; ENTRIES_PER_TABLE],
};
static mut BOOT_L1: BootL1Table = BootL1Table {
    entries: [0; ENTRIES_PER_TABLE],
};
// We need 2 L2 tables to cover 2GB (kernel at 1GB needs at least 1GB mapped above it)
static mut BOOT_L2_0: BootL2Table = BootL2Table {
    entries: [0; ENTRIES_PER_TABLE],
};
static mut BOOT_L2_1: BootL2Table = BootL2Table {
    entries: [0; ENTRIES_PER_TABLE],
};

// ============================================================================
// MMU Setup Functions
// ============================================================================

/// Default attributes for normal memory (kernel RWX)
const KERNEL_NORMAL_ATTRS: u64 = AF | SH_INNER | ATTR_IDX_NORMAL | AP_EL1_RW;

/// Default attributes for device memory (kernel RW, no execute)
const DEVICE_ATTRS: u64 = AF | ATTR_IDX_DEVICE | AP_EL1_RW | PXN | UXN;

/// Initialize boot page tables for identity mapping
///
/// Maps the first 2GB using 2MB block descriptors:
/// - 0x0000_0000 - 0x4000_0000 (0-1GB): Device memory (for UART, GIC, etc.)
/// - 0x4000_0000 - 0x8000_0000 (1-2GB): Normal memory (kernel code/data)
///
/// # Safety
/// Must be called once during early boot before enabling MMU.
pub unsafe fn init_boot_page_tables() {
    unsafe {
        // L0[0] -> L1 table
        let l0 = core::ptr::addr_of_mut!(BOOT_L0);
        let l1_phys = core::ptr::addr_of!(BOOT_L1) as u64;
        (*l0).entries[0] = l1_phys | DESC_TABLE;

        // L1[0] -> L2_0 table (for 0-1GB)
        // L1[1] -> L2_1 table (for 1-2GB)
        let l1 = core::ptr::addr_of_mut!(BOOT_L1);
        let l2_0_phys = core::ptr::addr_of!(BOOT_L2_0) as u64;
        let l2_1_phys = core::ptr::addr_of!(BOOT_L2_1) as u64;
        (*l1).entries[0] = l2_0_phys | DESC_TABLE;
        (*l1).entries[1] = l2_1_phys | DESC_TABLE;

        // L2_0: Map 0-1GB as device memory (2MB blocks)
        // This covers UART (0x0900_0000), GIC (0x0800_0000), etc.
        let l2_0 = core::ptr::addr_of_mut!(BOOT_L2_0);
        for i in 0..512 {
            let phys_addr = (i as u64) * (2 * 1024 * 1024); // 2MB per entry
            (*l2_0).entries[i] = phys_addr | DEVICE_ATTRS | DESC_BLOCK;
        }

        // L2_1: Map 1-2GB as normal memory (2MB blocks)
        // This covers kernel code/data at 0x4000_0000
        let l2_1 = core::ptr::addr_of_mut!(BOOT_L2_1);
        for i in 0..512 {
            let phys_addr = 0x4000_0000 + (i as u64) * (2 * 1024 * 1024); // 2MB per entry
            (*l2_1).entries[i] = phys_addr | KERNEL_NORMAL_ATTRS | DESC_BLOCK;
        }
    }
}

/// Get the physical address of the boot L0 table
pub fn boot_page_table_phys() -> u64 {
    core::ptr::addr_of!(BOOT_L0) as u64
}

/// Enable the MMU
///
/// Follows the ARM Trusted Firmware sequence:
/// 1. Invalidate TLB
/// 2. Set MAIR_EL1
/// 3. Set TCR_EL1
/// 4. Set TTBR0_EL1/TTBR1_EL1
/// 5. Barrier (dsb/isb)
/// 6. Enable MMU via SCTLR_EL1
///
/// # Safety
/// - Boot page tables must be initialized first
/// - This fundamentally changes how memory is accessed
pub unsafe fn enable_mmu() {
    unsafe {
        let l0_phys = boot_page_table_phys();

        // Step 1: Invalidate all TLB entries for EL1
        asm!("tlbi vmalle1", options(nostack));

        // Ensure TLB invalidation completes
        asm!("dsb ish", options(nostack));
        asm!("isb", options(nostack));

        // Step 2: Set MAIR_EL1 (Memory Attribute Indirection Register)
        asm!(
            "msr mair_el1, {mair}",
            mair = in(reg) MAIR_VALUE,
            options(nostack)
        );

        // Step 3: Set TCR_EL1 (Translation Control Register)
        asm!(
            "msr tcr_el1, {tcr}",
            tcr = in(reg) TCR_VALUE,
            options(nostack)
        );

        // Step 4a: Set TTBR0_EL1 (Translation Table Base Register 0)
        // We use TTBR0 for both user and kernel for now (identity mapping)
        asm!(
            "msr ttbr0_el1, {ttbr}",
            ttbr = in(reg) l0_phys,
            options(nostack)
        );

        // Step 4b: Set TTBR1_EL1 to the same table for now
        // (kernel addresses will use this later)
        asm!(
            "msr ttbr1_el1, {ttbr}",
            ttbr = in(reg) l0_phys,
            options(nostack)
        );

        // Step 5: Ensure all translation table writes have drained into memory,
        // the TLB invalidation is complete, and translation register writes
        // are committed before enabling the MMU
        asm!("dsb ish", options(nostack));
        asm!("isb", options(nostack));

        // Step 6: Read SCTLR_EL1, set enable bits, and write back
        let mut sctlr: u64;
        asm!(
            "mrs {sctlr}, sctlr_el1",
            sctlr = out(reg) sctlr,
            options(nostack)
        );

        // Set:
        // - M (bit 0): MMU enable
        // - C (bit 2): Data cache enable
        // - I (bit 12): Instruction cache enable
        sctlr |= (1 << 0) | (1 << 2) | (1 << 12);

        asm!(
            "msr sctlr_el1, {sctlr}",
            sctlr = in(reg) sctlr,
            options(nostack)
        );

        // Final synchronization barrier
        asm!("isb", options(nostack));
    }
}

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

    /// Create a page table representing the kernel's identity mapping
    ///
    /// Uses the current TTBR1_EL1 value.
    pub fn kernel_identity() -> Self {
        let ttbr1: u64;
        unsafe {
            asm!("mrs {}, ttbr1_el1", out(reg) ttbr1, options(nostack));
        }
        // Mask out ASID (bits [63:48])
        Self::new(ttbr1 & 0x0000_FFFF_FFFF_FFFF)
    }

    /// Create a page table from current TTBR0_EL1
    /// Create a new user page table (allocates L0)
    pub fn new_user<FA: FrameAlloc<PhysAddr = u64>>(frame_alloc: &mut FA) -> Option<Self> {
        let l0_phys = frame_alloc.alloc_frame()?;
        // Zero the L0 table
        unsafe {
            core::ptr::write_bytes(phys_to_virt(l0_phys), 0, PAGE_SIZE as usize);
        }
        Some(Self::new(l0_phys))
    }

    /// Copy kernel mappings from current page table to this one
    ///
    /// Creates a new L1 table and copies kernel identity mapping entries.
    /// This allows user space to have its own mappings in separate L1 entries.
    pub fn copy_kernel_mappings(&mut self) {
        // For now with identity mapping, we need L0[0] to point to an L1 table
        // that has kernel's identity mapping entries (L1[0], L1[1]) but allows
        // user mappings in other L1 entries (L1[2], etc.)
        //
        // We just make L0[0] point directly to kernel's L1 table for simplicity.
        // User mappings will create new L2/L3 tables as needed.
        unsafe {
            let kernel_l0 = phys_to_virt(boot_page_table_phys()) as *const u64;
            let user_l0 = phys_to_virt(self.root_phys) as *mut u64;

            // Copy L0[0] - this makes us share kernel's L1 table
            // This is OK because user space uses different L1 entries than kernel
            write_volatile(user_l0, read_volatile(kernel_l0));
        }
    }

    /// Copy kernel mappings with a dedicated L1 table for fork()
    ///
    /// This creates a new L1 table and copies kernel entries, allowing
    /// the forked process to have independent user mappings.
    pub fn copy_kernel_mappings_with_alloc<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        frame_alloc: &mut FA,
    ) -> Result<(), i32> {
        unsafe {
            let kernel_l0 = phys_to_virt_table_const(boot_page_table_phys());
            let kernel_l0_entry = (*kernel_l0).entry(0);

            if !kernel_l0_entry.is_valid() || !kernel_l0_entry.is_table() {
                return Err(-22); // EINVAL - kernel L0[0] must be valid table
            }

            let kernel_l1 = phys_to_virt_table_const(kernel_l0_entry.addr());

            // Allocate new L1 table for this page table
            let new_l1_phys = frame_alloc.alloc_frame().ok_or(-12i32)?;
            core::ptr::write_bytes(phys_to_virt(new_l1_phys), 0, PAGE_SIZE as usize);
            let new_l1 = phys_to_virt_table(new_l1_phys);

            // Copy kernel's L1 entries (0 and 1 cover identity-mapped region)
            // L1[0] covers 0-1GB, L1[1] covers 1-2GB
            // User space starts at 0x80000000 which is L1[2]
            for i in 0..2 {
                let entry = (*kernel_l1).entry(i);
                *(*new_l1).entry_mut(i) = *entry;
            }

            // Set our L0[0] to point to the new L1 table
            let user_l0 = phys_to_virt_table(self.root_phys);
            (*user_l0).entry_mut(0).set_table(new_l1_phys);

            Ok(())
        }
    }

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
    /// Creates a new page table with copies of all user space mappings.
    pub fn duplicate_user_space<FA: FrameAlloc<PhysAddr = u64>>(
        &self,
        frame_alloc: &mut FA,
    ) -> Result<Self, i32> {
        use crate::arch::Arch;
        use crate::arch::aarch64::Aarch64Arch;

        const USER_START: u64 = <Aarch64Arch as Arch>::USER_START;
        const USER_END: u64 = <Aarch64Arch as Arch>::USER_END;

        // Create new user page table
        let mut new_pt = Self::new_user(frame_alloc).ok_or(-12i32)?; // ENOMEM

        // Copy kernel mappings FIRST, with a dedicated L1 table
        // This allows user mappings to be independent of other processes
        new_pt.copy_kernel_mappings_with_alloc(frame_alloc)?;

        unsafe {
            let parent_l0 = phys_to_virt_table_const(self.root_phys);

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

                let l1 = phys_to_virt_table_const(l0_entry.addr());

                // Walk L1 entries
                for l1_idx in 0..ENTRIES_PER_TABLE {
                    let l1_entry = (*l1).entry(l1_idx);
                    if !l1_entry.is_valid() {
                        continue;
                    }

                    let vaddr_l1 = ((l0_idx as u64) << 39) | ((l1_idx as u64) << 30);

                    // Check for 1GB block
                    if l1_entry.is_block() {
                        // 1GB block - kernel uses these, skip user-space blocks
                        if vaddr_l1 < USER_START {
                            // Kernel region - will be copied via copy_kernel_mappings
                        }
                        continue;
                    }

                    let l2 = phys_to_virt_table_const(l1_entry.addr());

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

                        let l3 = phys_to_virt_table_const(l2_entry.addr());

                        // Walk L3 entries (4KB pages)
                        for l3_idx in 0..ENTRIES_PER_TABLE {
                            let l3_entry = (*l3).entry(l3_idx);
                            if !l3_entry.is_valid() {
                                continue;
                            }

                            let vaddr = vaddr_l2 | ((l3_idx as u64) << 12);

                            // Skip non-user addresses
                            if !(USER_START..USER_END).contains(&vaddr) {
                                continue;
                            }

                            // Skip kernel-only pages (ioremap, etc.)
                            // User pages have AP_EL0_RW or AP_EL0_RO set
                            let attrs = l3_entry.0 & !ADDR_MASK & !0b11;
                            if attrs & (AP_EL0_RW | AP_EL0_RO) == 0 {
                                continue;
                            }

                            // User page - allocate new frame and copy contents
                            let src_phys = l3_entry.addr();
                            let new_frame = frame_alloc.alloc_frame().ok_or(-12i32)?; // ENOMEM

                            // Copy page contents using volatile to avoid any optimization issues
                            let src_ptr = phys_to_virt(src_phys) as *const u64;
                            let dst_ptr = phys_to_virt(new_frame) as *mut u64;
                            for i in 0..(PAGE_SIZE as usize / 8) {
                                let val = core::ptr::read_volatile(src_ptr.add(i));
                                core::ptr::write_volatile(dst_ptr.add(i), val);
                            }

                            // Clean the new frame's cache to ensure child sees correct data
                            crate::arch::aarch64::cache::cache_clean_range(
                                phys_to_virt(new_frame),
                                PAGE_SIZE as usize,
                            );

                            // Map in child with same permissions (attrs already extracted above)
                            let flags = if attrs & AP_EL0_RW == AP_EL0_RW {
                                PageFlags::USER | PageFlags::WRITE
                            } else if attrs & AP_EL0_RO == AP_EL0_RO {
                                PageFlags::USER
                            } else {
                                PageFlags::WRITE
                            };

                            let flags = if attrs & (PXN | UXN) == 0 {
                                flags | PageFlags::EXECUTE
                            } else {
                                flags
                            };

                            new_pt
                                .map_with_alloc(vaddr, new_frame, flags, frame_alloc)
                                .map_err(|_| -12i32)?; // ENOMEM
                        }
                    }
                }
            }
        }

        Ok(new_pt)
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
