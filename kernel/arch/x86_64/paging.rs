//! x86-64 paging (4-level page tables)
//!
//! Implements the PageTable trait for x86-64 4-level paging:
//! PML4 -> PDPT -> PD -> PT -> Physical Page

use crate::arch::{FrameAlloc, MapError, PageFlags, PageTable};

/// Page size (4KB)
pub const PAGE_SIZE: u64 = 4096;

/// Page table entry flags
pub const PAGE_PRESENT: u64 = 1 << 0;
pub const PAGE_WRITABLE: u64 = 1 << 1;
pub const PAGE_USER: u64 = 1 << 2;
pub const PAGE_WRITE_THROUGH: u64 = 1 << 3;
pub const PAGE_CACHE_DISABLE: u64 = 1 << 4;
pub const PAGE_HUGE: u64 = 1 << 7;
pub const PAGE_NO_EXECUTE: u64 = 1 << 63;

/// Mask for physical address in page table entry
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Number of entries per page table (512)
const ENTRIES_PER_TABLE: usize = 512;

// ============================================================================
// Physical-to-Virtual Address Conversion
// ============================================================================
//
// Phase 1: PAGE_OFFSET = 0 (identity mapping, no-op conversion)
// Phase 2: PAGE_OFFSET = 0xFFFF_8880_0000_0000 (Linux-style direct map)

/// Page offset for direct map
///
/// Physical address 0 maps to virtual address PAGE_OFFSET.
/// Currently 0 for identity mapping; will be changed to
/// 0xFFFF_8880_0000_0000 for high-address kernel.
pub const PAGE_OFFSET: u64 = 0;

/// Convert physical address to virtual address (direct map)
#[inline]
pub fn phys_to_virt(phys: u64) -> *mut u8 {
    (phys + PAGE_OFFSET) as *mut u8
}

/// Convert virtual address to physical address (direct map only)
///
/// Only valid for addresses in the direct map region.
#[inline]
pub fn virt_to_phys_direct(virt: *const u8) -> u64 {
    (virt as u64) - PAGE_OFFSET
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

    /// Create a page table representing the kernel's identity mapping
    ///
    /// This uses the current CR3 value, meaning kernel threads share
    /// the kernel's page table. No new allocation is done.
    pub fn kernel_identity() -> Self {
        Self::new(Self::current_cr3())
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

            // Set the final page table entry
            let pt_entry = (*pt).entry_mut(pt_idx);
            pt_entry.set(pa, entry_flags);

            // Flush TLB for this address
            Self::flush_tlb(va);
        }

        Ok(())
    }

    /// Copy kernel mappings (PML4[0]) from current page table to this one
    ///
    /// This ensures kernel code/data remains accessible during syscalls
    /// when the user page table is loaded.
    pub fn copy_kernel_mappings(&mut self) {
        unsafe {
            let kernel_pml4 = phys_to_virt_table_const(Self::current_cr3());
            let user_pml4 = phys_to_virt_table(self.pml4_phys);

            // Copy PML4[0] - this covers the identity-mapped kernel region (0-512GB)
            // The boot assembly maps the first 512MB using 2MB huge pages
            (*user_pml4).entries[0] = (*kernel_pml4).entries[0];
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

    /// Flush a single TLB entry
    pub fn flush_tlb(vaddr: u64) {
        unsafe {
            ::core::arch::asm!(
                "invlpg [{}]",
                in(reg) vaddr,
                options(nostack, preserves_flags)
            );
        }
    }

    /// Flush entire TLB
    #[allow(dead_code)]
    pub fn flush_tlb_all() {
        let cr3 = Self::current_cr3();
        unsafe {
            ::core::arch::asm!(
                "mov cr3, {}",
                in(reg) cr3,
                options(nostack, preserves_flags)
            );
        }
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

            // Set the final page table entry
            let pt_entry = (*pt).entry_mut(pt_idx);
            pt_entry.set(pa, entry_flags);

            // Flush TLB for this address
            Self::flush_tlb(va);
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

            let pt_entry = (*pt).entry_mut(pt_idx);
            pt_entry.clear();

            Self::flush_tlb(va);
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

    fn collect_table_frames(&self) -> alloc::vec::Vec<Self::PhysAddr> {
        use alloc::vec::Vec;
        let mut frames = Vec::new();

        // Add the root PML4 frame
        frames.push(self.pml4_phys);

        unsafe {
            let pml4 = phys_to_virt_table_const(self.pml4_phys);

            // Walk PML4 entries (only user-space portion, indices 0-255)
            for pml4_idx in 0..256 {
                let pml4_entry = (*pml4).entry(pml4_idx);
                if !pml4_entry.is_present() || pml4_entry.is_huge() {
                    continue;
                }

                let pdpt_phys = pml4_entry.addr();
                frames.push(pdpt_phys);
                let pdpt = phys_to_virt_table_const(pdpt_phys);

                // Walk PDPT entries
                for pdpt_idx in 0..512 {
                    let pdpt_entry = (*pdpt).entry(pdpt_idx);
                    if !pdpt_entry.is_present() || pdpt_entry.is_huge() {
                        continue;
                    }

                    let pd_phys = pdpt_entry.addr();
                    frames.push(pd_phys);
                    let pd = phys_to_virt_table_const(pd_phys);

                    // Walk PD entries
                    for pd_idx in 0..512 {
                        let pd_entry = (*pd).entry(pd_idx);
                        if !pd_entry.is_present() || pd_entry.is_huge() {
                            continue;
                        }

                        let pt_phys = pd_entry.addr();
                        frames.push(pt_phys);
                        // Don't recurse into PT - those are user page frames, not table frames
                    }
                }
            }
        }

        frames
    }
}

/// User address space bounds for fork/clone
/// User PIE base is 0x20000000 (512MB) - see USER_PIE_BASE in main.rs
const USER_START: u64 = 0x0000_0000_2000_0000; // 512MB - where user ELF is loaded
const USER_END: u64 = 0x0000_8000_0000_0000; // 128TB

/// COW (Copy-on-Write) flag - we use an available bit in the PTE
/// Bit 9 is one of the "available" bits (9-11) that can be used by the OS
pub const PAGE_COW: u64 = 1 << 9;

impl X86_64PageTable {
    /// Duplicate the entire user address space using Copy-on-Write (COW)
    ///
    /// For each mapped user-space page:
    /// 1. If writable: mark read-only in both parent and child, set COW flag
    /// 2. Map the same physical frame in child's page table
    /// 3. Increment the frame's reference count
    ///
    /// When either process writes to a COW page, the page fault handler will:
    /// 1. Allocate a new frame
    /// 2. Copy the page contents
    /// 3. Update the PTE to point to the new frame with write permission
    /// 4. Decrement the old frame's reference count
    pub fn duplicate_user_space<FA: FrameAlloc<PhysAddr = u64>>(
        &self,
        frame_alloc: &mut FA,
    ) -> Result<Self, i32> {
        // Create new user page table
        let mut new_pt = Self::new_user(frame_alloc).ok_or(-12i32)?; // ENOMEM

        // NOTE: We do NOT call copy_kernel_mappings() here because PML4[0] contains
        // BOTH kernel identity mappings (2MB huge pages) AND user space mappings
        // (4KB pages at 0x20000000+). If we copy PML4[0] wholesale, user pages
        // would be shared instead of copied.
        //
        // Instead, we walk the parent's page tables and:
        // - For kernel addresses (< USER_START): share by copying PTE directly
        // - For user addresses (>= USER_START): copy page contents to new frame

        unsafe {
            let parent_pml4 = phys_to_virt_table_const(self.pml4_phys);

            // Walk all PML4 entries (0-511)
            for pml4_idx in 0..ENTRIES_PER_TABLE {
                let pml4_entry = (*parent_pml4).entry(pml4_idx);
                if !pml4_entry.is_present() {
                    continue;
                }

                let pdpt = phys_to_virt_table_const(pml4_entry.addr());

                // Walk PDPT entries
                for pdpt_idx in 0..ENTRIES_PER_TABLE {
                    let pdpt_entry = (*pdpt).entry(pdpt_idx);
                    if !pdpt_entry.is_present() {
                        continue;
                    }

                    let vaddr_pdpt = ((pml4_idx as u64) << 39) | ((pdpt_idx as u64) << 30);

                    // Check for 1GB huge page
                    if pdpt_entry.flags() & PAGE_HUGE != 0 {
                        // 1GB huge page - kernel uses these, share directly
                        if vaddr_pdpt < USER_START {
                            // Kernel region - share the 1GB mapping
                            // We'd need to set up the PDPT entry in the child
                            // For now, rely on identity map being set up elsewhere
                        }
                        continue;
                    }

                    let pd = phys_to_virt_table_const(pdpt_entry.addr());

                    // Walk PD entries
                    for pd_idx in 0..ENTRIES_PER_TABLE {
                        let pd_entry = (*pd).entry(pd_idx);
                        if !pd_entry.is_present() {
                            continue;
                        }

                        let vaddr_pd = vaddr_pdpt | ((pd_idx as u64) << 21);

                        // Check for 2MB huge page
                        if pd_entry.flags() & PAGE_HUGE != 0 {
                            // 2MB huge page - kernel identity map uses these
                            if vaddr_pd < USER_START {
                                // Kernel region - share the 2MB mapping
                                // Copy the PD entry to child's page table
                                // This requires ensuring intermediate tables exist
                                new_pt.ensure_pd_entry(
                                    pml4_idx,
                                    pdpt_idx,
                                    pd_idx,
                                    *pd_entry,
                                    frame_alloc,
                                )?;
                            }
                            // Skip user 2MB pages (shouldn't exist in our setup)
                            continue;
                        }

                        let pt = phys_to_virt_table_const(pd_entry.addr());

                        // Walk PT entries (4KB pages)
                        for pt_idx in 0..ENTRIES_PER_TABLE {
                            let pt_entry = (*pt).entry(pt_idx);
                            if !pt_entry.is_present() {
                                continue;
                            }

                            // Calculate virtual address
                            let vaddr = vaddr_pd | ((pt_idx as u64) << 12);

                            // Skip addresses above user space
                            if vaddr >= USER_END {
                                continue;
                            }

                            if vaddr < USER_START {
                                // Kernel address - share the mapping (same physical page)
                                // Copy the PTE to child's page table
                                new_pt.ensure_pt_entry(
                                    pml4_idx,
                                    pdpt_idx,
                                    pd_idx,
                                    pt_idx,
                                    *pt_entry,
                                    frame_alloc,
                                )?;
                            } else {
                                // User address - use COW (Copy-on-Write)
                                let old_phys = pt_entry.addr();
                                let old_flags = pt_entry.flags();

                                // If the page was writable, mark it read-only and set COW flag
                                // in both parent and child PTEs
                                let cow_flags = if old_flags & PAGE_WRITABLE != 0 {
                                    // Remove WRITABLE, add COW marker
                                    (old_flags & !PAGE_WRITABLE) | PAGE_COW
                                } else {
                                    // Already read-only, keep as-is (no COW needed)
                                    old_flags
                                };

                                // Update parent's PTE to be read-only with COW flag
                                if old_flags & PAGE_WRITABLE != 0 {
                                    let parent_pt = phys_to_virt_table((*pd).entry(pd_idx).addr());
                                    (*parent_pt).entry_mut(pt_idx).set(old_phys, cow_flags);
                                    // Flush TLB for the parent's mapping
                                    Self::flush_tlb(vaddr);
                                }

                                // Increment reference count for the shared frame
                                crate::FRAME_ALLOCATOR.incref(old_phys);

                                // Map same physical frame in child with COW flags
                                new_pt.ensure_pt_entry(
                                    pml4_idx,
                                    pdpt_idx,
                                    pd_idx,
                                    pt_idx,
                                    PageTableEntry(old_phys | cow_flags),
                                    frame_alloc,
                                )?;
                            }
                        }
                    }
                }
            }
        }

        Ok(new_pt)
    }

    /// Helper: Ensure PD entry exists and copy a 2MB huge page entry
    unsafe fn ensure_pd_entry<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        pml4_idx: usize,
        pdpt_idx: usize,
        pd_idx: usize,
        entry: PageTableEntry,
        frame_alloc: &mut FA,
    ) -> Result<(), i32> {
        unsafe {
            let pml4 = phys_to_virt_table(self.pml4_phys);

            // Ensure PML4 entry exists
            if !(*pml4).entry(pml4_idx).is_present() {
                let pdpt_frame = frame_alloc.alloc_frame().ok_or(-12i32)?;
                core::ptr::write_bytes(phys_to_virt(pdpt_frame), 0, PAGE_SIZE as usize);
                *(*pml4).entry_mut(pml4_idx) =
                    PageTableEntry(pdpt_frame | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
            }

            let pdpt = phys_to_virt_table((*pml4).entry(pml4_idx).addr());

            // Ensure PDPT entry exists
            if !(*pdpt).entry(pdpt_idx).is_present() {
                let pd_frame = frame_alloc.alloc_frame().ok_or(-12i32)?;
                core::ptr::write_bytes(phys_to_virt(pd_frame), 0, PAGE_SIZE as usize);
                *(*pdpt).entry_mut(pdpt_idx) =
                    PageTableEntry(pd_frame | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
            }

            let pd = phys_to_virt_table((*pdpt).entry(pdpt_idx).addr());

            // Copy the 2MB huge page entry
            *(*pd).entry_mut(pd_idx) = entry;

            Ok(())
        }
    }

    /// Helper: Ensure PT entry exists and copy a 4KB page entry
    unsafe fn ensure_pt_entry<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        pml4_idx: usize,
        pdpt_idx: usize,
        pd_idx: usize,
        pt_idx: usize,
        entry: PageTableEntry,
        frame_alloc: &mut FA,
    ) -> Result<(), i32> {
        unsafe {
            let pml4 = phys_to_virt_table(self.pml4_phys);

            // Ensure PML4 entry exists
            if !(*pml4).entry(pml4_idx).is_present() {
                let pdpt_frame = frame_alloc.alloc_frame().ok_or(-12i32)?;
                core::ptr::write_bytes(phys_to_virt(pdpt_frame), 0, PAGE_SIZE as usize);
                *(*pml4).entry_mut(pml4_idx) =
                    PageTableEntry(pdpt_frame | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
            }

            let pdpt = phys_to_virt_table((*pml4).entry(pml4_idx).addr());

            // Ensure PDPT entry exists
            if !(*pdpt).entry(pdpt_idx).is_present() {
                let pd_frame = frame_alloc.alloc_frame().ok_or(-12i32)?;
                core::ptr::write_bytes(phys_to_virt(pd_frame), 0, PAGE_SIZE as usize);
                *(*pdpt).entry_mut(pdpt_idx) =
                    PageTableEntry(pd_frame | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
            }

            let pd = phys_to_virt_table((*pdpt).entry(pdpt_idx).addr());

            // Ensure PD entry exists (non-huge)
            if !(*pd).entry(pd_idx).is_present() {
                let pt_frame = frame_alloc.alloc_frame().ok_or(-12i32)?;
                core::ptr::write_bytes(phys_to_virt(pt_frame), 0, PAGE_SIZE as usize);
                *(*pd).entry_mut(pd_idx) =
                    PageTableEntry(pt_frame | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
            }

            let pt = phys_to_virt_table((*pd).entry(pd_idx).addr());

            // Copy the 4KB page entry
            *(*pt).entry_mut(pt_idx) = entry;

            Ok(())
        }
    }

    /// Unmap a single page and return its physical address
    ///
    /// This is a static method that takes the page table root directly,
    /// useful for unmapping pages without needing a full X86_64PageTable instance.
    ///
    /// Returns Some(phys_addr) if the page was mapped, None if not mapped.
    pub fn unmap_page(pml4_phys: u64, va: u64) -> Option<u64> {
        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);

        unsafe {
            let pml4 = phys_to_virt_table(pml4_phys);

            let pml4_entry = (*pml4).entry(pml4_idx);
            if !pml4_entry.is_present() {
                return None;
            }
            let pdpt = phys_to_virt_table(pml4_entry.addr());

            let pdpt_entry = (*pdpt).entry(pdpt_idx);
            if !pdpt_entry.is_present() {
                return None;
            }
            // 1GB huge pages not supported for unmap
            if pdpt_entry.is_huge() {
                return None;
            }
            let pd = phys_to_virt_table(pdpt_entry.addr());

            let pd_entry = (*pd).entry(pd_idx);
            if !pd_entry.is_present() {
                return None;
            }
            // 2MB huge pages not supported for unmap
            if pd_entry.is_huge() {
                return None;
            }
            let pt = phys_to_virt_table(pd_entry.addr());

            let pt_entry = (*pt).entry_mut(pt_idx);
            if !pt_entry.is_present() {
                return None;
            }

            // Get physical address before clearing
            let phys = pt_entry.addr();

            // Clear the entry
            pt_entry.clear();

            // Flush TLB for this address
            Self::flush_tlb(va);

            Some(phys)
        }
    }

    /// Update the protection flags on an already-mapped page
    ///
    /// This modifies the page table entry for the given virtual address
    /// to have new protection flags, without changing the physical mapping.
    ///
    /// # Arguments
    /// * `pml4_phys` - Physical address of the PML4 table
    /// * `va` - Virtual address of the page to modify
    /// * `writable` - Whether the page should be writable
    /// * `executable` - Whether the page should be executable
    ///
    /// # Returns
    /// `true` if the page was found and updated, `false` if not mapped
    pub fn update_page_protection(
        pml4_phys: u64,
        va: u64,
        writable: bool,
        executable: bool,
    ) -> bool {
        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(va);

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
            // 1GB huge pages not supported for protection update
            if pdpt_entry.is_huge() {
                return false;
            }
            let pd = phys_to_virt_table(pdpt_entry.addr());

            let pd_entry = (*pd).entry(pd_idx);
            if !pd_entry.is_present() {
                return false;
            }
            // 2MB huge pages not supported for protection update
            if pd_entry.is_huge() {
                return false;
            }
            let pt = phys_to_virt_table(pd_entry.addr());

            let pt_entry = (*pt).entry_mut(pt_idx);
            if !pt_entry.is_present() {
                return false;
            }

            // Get current entry, preserve address and base flags
            let phys = pt_entry.addr();
            let mut flags = pt_entry.flags();

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

            // Write back the updated entry
            pt_entry.set(phys, flags);

            // Flush TLB for this address
            Self::flush_tlb(va);

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
}
