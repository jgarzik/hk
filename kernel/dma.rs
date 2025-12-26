//! DMA (Direct Memory Access) subsystem
//!
//! Provides a Linux-compatible DMA API for device drivers.
//!
//! Key concepts:
//! - DMA addresses are NOT always equal to physical addresses (IOMMU can remap)
//! - Devices have addressing limits (dma_mask) that must be respected
//! - Two allocation types: coherent (always synchronized) and streaming (mapped temporarily)
//!
//! This module follows the Linux DMA API design:
//! - dma_alloc_coherent / dma_free_coherent for device-accessible buffers
//! - dma_map_single / dma_unmap_single for streaming mappings
//! - dma_map_sg / dma_unmap_sg for scatter-gather lists

use alloc::vec::Vec;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{Ordering, fence};
use spin::RwLock;

use crate::arch::phys_to_virt;
use crate::frame_alloc::{BitmapFrameAllocator, FRAME_SIZE};

/// DMA address type - what devices see
///
/// This is NOT always equal to physical address. With an IOMMU,
/// dma_addr may be an I/O virtual address (IOVA) that the IOMMU
/// translates to the actual physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct DmaAddr(pub u64);

impl DmaAddr {
    /// Invalid/error DMA address
    pub const INVALID: DmaAddr = DmaAddr(0);

    /// Check if this is a valid DMA address
    pub fn is_valid(&self) -> bool {
        self.0 != 0
    }

    /// Get raw u64 value
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<u64> for DmaAddr {
    fn from(addr: u64) -> Self {
        DmaAddr(addr)
    }
}

/// DMA transfer direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// CPU writes, device reads (e.g., sending commands/data to device)
    ToDevice,
    /// Device writes, CPU reads (e.g., receiving data from device)
    FromDevice,
    /// Both directions (e.g., command/response buffers)
    Bidirectional,
}

/// Common DMA mask values
pub mod dma_mask {
    /// 24-bit DMA mask (ISA DMA, 16MB limit)
    pub const DMA_BIT_MASK_24: u64 = (1 << 24) - 1;
    /// 32-bit DMA mask (32-bit PCI, 4GB limit)
    pub const DMA_BIT_MASK_32: u64 = (1 << 32) - 1;
    /// 64-bit DMA mask (full 64-bit addressing)
    pub const DMA_BIT_MASK_64: u64 = !0u64;
}

/// DMA configuration for a device
#[derive(Debug, Clone, Copy)]
pub struct DmaConfig {
    /// Mask for streaming DMA mappings
    pub dma_mask: u64,
    /// Mask for coherent allocations (often more restrictive)
    pub coherent_dma_mask: u64,
}

impl Default for DmaConfig {
    fn default() -> Self {
        Self {
            dma_mask: dma_mask::DMA_BIT_MASK_32,
            coherent_dma_mask: dma_mask::DMA_BIT_MASK_32,
        }
    }
}

impl DmaConfig {
    /// Create a 64-bit DMA capable config
    pub fn new_64bit() -> Self {
        Self {
            dma_mask: dma_mask::DMA_BIT_MASK_64,
            coherent_dma_mask: dma_mask::DMA_BIT_MASK_64,
        }
    }

    /// Create a 32-bit DMA config
    pub fn new_32bit() -> Self {
        Self::default()
    }
}

/// Result of dma_alloc_coherent - contains both CPU and DMA addresses
pub struct DmaCoherent {
    /// CPU-accessible pointer (kernel virtual address)
    pub cpu_addr: *mut u8,
    /// DMA address for programming into device
    pub dma_addr: DmaAddr,
    /// Size of the allocation in bytes
    pub size: usize,
}

impl DmaCoherent {
    /// Get the CPU pointer as a typed reference
    ///
    /// # Safety
    /// Caller must ensure T is compatible with the allocation size and alignment.
    pub unsafe fn as_ptr<T>(&self) -> *mut T {
        self.cpu_addr as *mut T
    }

    /// Get a slice view of the coherent memory
    ///
    /// # Safety
    /// Caller must ensure exclusive access and proper synchronization.
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.cpu_addr, self.size) }
    }

    /// Get a mutable slice view of the coherent memory
    ///
    /// # Safety
    /// Caller must ensure exclusive access and proper synchronization.
    pub unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.cpu_addr, self.size) }
    }
}

// DmaCoherent contains a raw pointer but the allocation is owned
unsafe impl Send for DmaCoherent {}
unsafe impl Sync for DmaCoherent {}

/// A single scatter-gather entry after DMA mapping
#[derive(Debug, Clone, Copy)]
pub struct DmaSgEntry {
    /// DMA address for this segment
    pub dma_addr: DmaAddr,
    /// Length in bytes
    pub length: usize,
}

/// Scatter-gather list for DMA
pub struct DmaSgList {
    /// Mapped entries
    pub entries: Vec<DmaSgEntry>,
    /// Original CPU addresses (for unmapping)
    original: Vec<(*const u8, usize)>,
    /// Direction for unmapping
    direction: DmaDirection,
}

impl DmaSgList {
    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// Safety: the pointers in DmaSgList are just addresses for unmapping
unsafe impl Send for DmaSgList {}
unsafe impl Sync for DmaSgList {}

/// Trait for devices that can perform DMA
pub trait DmaDevice {
    /// Get the DMA configuration for this device
    fn dma_config(&self) -> &DmaConfig;

    /// Get mutable DMA configuration
    fn dma_config_mut(&mut self) -> &mut DmaConfig;
}

/// Trait for pluggable DMA backends
///
/// Implementations:
/// - DirectDmaOps: dma_addr == phys_addr (MVP, for systems without IOMMU)
/// - IommuDmaOps: uses IOVA from IOMMU (future)
/// - SwiotlbDmaOps: bounce buffering for limited devices (future)
pub trait DmaOps: Send + Sync {
    /// Allocate coherent DMA memory
    ///
    /// Returns memory that is always cache-coherent between CPU and device.
    /// Both CPU and device can access without explicit sync operations.
    fn alloc_coherent(&self, config: &DmaConfig, size: usize, align: usize) -> Option<DmaCoherent>;

    /// Free coherent DMA memory
    fn free_coherent(&self, alloc: DmaCoherent);

    /// Map a single buffer for DMA
    ///
    /// Creates a streaming mapping for existing CPU memory.
    /// The CPU should not access the memory until unmapped (or synced).
    fn map_single(
        &self,
        config: &DmaConfig,
        cpu_addr: *const u8,
        size: usize,
        direction: DmaDirection,
    ) -> Option<DmaAddr>;

    /// Unmap a single buffer
    fn unmap_single(
        &self,
        config: &DmaConfig,
        dma_addr: DmaAddr,
        size: usize,
        direction: DmaDirection,
    );

    /// Map a scatter-gather list
    fn map_sg(
        &self,
        config: &DmaConfig,
        sg: &[(*const u8, usize)],
        direction: DmaDirection,
    ) -> Option<DmaSgList>;

    /// Unmap a scatter-gather list
    fn unmap_sg(&self, config: &DmaConfig, sg: DmaSgList);

    /// Sync buffer for CPU access (after device writes)
    ///
    /// Call this before CPU reads data that device wrote.
    fn sync_for_cpu(
        &self,
        config: &DmaConfig,
        dma_addr: DmaAddr,
        size: usize,
        direction: DmaDirection,
    );

    /// Sync buffer for device access (before device reads)
    ///
    /// Call this after CPU writes data that device will read.
    fn sync_for_device(
        &self,
        config: &DmaConfig,
        dma_addr: DmaAddr,
        size: usize,
        direction: DmaDirection,
    );

    /// Backend name for debugging
    fn name(&self) -> &'static str;
}

/// Direct DMA backend where dma_addr == phys_addr
///
/// Used on systems without IOMMU where physical addresses
/// are directly usable by devices. This is the common case
/// for x86 QEMU without vIOMMU.
pub struct DirectDmaOps {
    /// Reference to frame allocator
    frame_alloc: &'static BitmapFrameAllocator,
}

impl DirectDmaOps {
    /// Create a new direct DMA ops instance
    pub const fn new(frame_alloc: &'static BitmapFrameAllocator) -> Self {
        Self { frame_alloc }
    }

    /// Convert CPU address to physical address
    /// Assumes identity mapping for kernel addresses
    fn cpu_to_phys(&self, cpu_addr: *const u8) -> u64 {
        // In identity-mapped kernel, virtual == physical
        cpu_addr as u64
    }

    /// Check if physical address fits within DMA mask
    fn check_mask(&self, phys: u64, mask: u64) -> bool {
        phys <= mask
    }
}

impl DmaOps for DirectDmaOps {
    fn alloc_coherent(
        &self,
        config: &DmaConfig,
        size: usize,
        _align: usize,
    ) -> Option<DmaCoherent> {
        // Calculate number of frames needed
        let num_frames = size.div_ceil(FRAME_SIZE);

        // For simplicity, we allocate one frame at a time
        // A production implementation would support contiguous allocation
        if num_frames > 1 {
            // For multi-frame allocations, allocate frames and hope they're contiguous
            // This is a limitation - real implementation needs contiguous allocator
            let mut frames = Vec::with_capacity(num_frames);
            let mut first_frame = 0u64;

            for i in 0..num_frames {
                let frame = self.frame_alloc.alloc()?;
                if i == 0 {
                    first_frame = frame;
                    // Check if first frame fits in mask
                    if !self.check_mask(frame, config.coherent_dma_mask) {
                        self.frame_alloc.free(frame);
                        return None;
                    }
                } else {
                    // Check contiguity (required for coherent allocations)
                    let expected = first_frame + (i as u64 * FRAME_SIZE as u64);
                    if frame != expected {
                        // Not contiguous - free all and fail
                        for f in frames {
                            self.frame_alloc.free(f);
                        }
                        self.frame_alloc.free(frame);
                        return None;
                    }
                }
                frames.push(frame);
            }

            // Zero the memory (coherent memory should be zeroed)
            unsafe {
                core::ptr::write_bytes(first_frame as *mut u8, 0, size);
            }

            return Some(DmaCoherent {
                cpu_addr: first_frame as *mut u8,
                dma_addr: DmaAddr(first_frame),
                size,
            });
        }

        // Single frame allocation
        let phys = self.frame_alloc.alloc()?;

        // Check mask
        if !self.check_mask(phys, config.coherent_dma_mask) {
            self.frame_alloc.free(phys);
            return None;
        }

        // Zero the memory
        unsafe {
            core::ptr::write_bytes(phys_to_virt(phys), 0, size);
        }

        Some(DmaCoherent {
            cpu_addr: phys_to_virt(phys),
            dma_addr: DmaAddr(phys),
            size,
        })
    }

    fn free_coherent(&self, alloc: DmaCoherent) {
        let num_frames = alloc.size.div_ceil(FRAME_SIZE);
        for i in 0..num_frames {
            let frame = alloc.dma_addr.0 + (i * FRAME_SIZE) as u64;
            self.frame_alloc.free(frame);
        }
    }

    fn map_single(
        &self,
        config: &DmaConfig,
        cpu_addr: *const u8,
        size: usize,
        direction: DmaDirection,
    ) -> Option<DmaAddr> {
        let phys = self.cpu_to_phys(cpu_addr);

        // Check that entire buffer fits in mask
        let end_phys = phys + size as u64 - 1;
        if !self.check_mask(end_phys, config.dma_mask) {
            return None;
        }

        // ARM requires cache maintenance before DMA
        // - ToDevice: Clean cache to ensure device sees CPU writes
        // - FromDevice: Invalidate cache (clean first for safety) to prepare for device writes
        // - Bidirectional: Both operations
        #[cfg(target_arch = "aarch64")]
        {
            use crate::arch::aarch64::cache;
            match direction {
                DmaDirection::ToDevice => cache::cache_clean_range(cpu_addr, size),
                DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                    cache::cache_flush_range(cpu_addr, size)
                }
            }
        }

        // Suppress unused warning on x86
        #[cfg(not(target_arch = "aarch64"))]
        let _ = direction;

        // Direct mapping: DMA addr == physical addr
        Some(DmaAddr(phys))
    }

    fn unmap_single(
        &self,
        _config: &DmaConfig,
        dma_addr: DmaAddr,
        size: usize,
        direction: DmaDirection,
    ) {
        // ARM requires cache invalidation after device DMA writes to memory
        // so CPU sees fresh data instead of stale cached values
        #[cfg(target_arch = "aarch64")]
        {
            use crate::arch::aarch64::cache;
            match direction {
                DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                    // dma_addr == cpu_addr for direct mapping
                    cache::cache_invalidate_range(dma_addr.0 as *const u8, size);
                }
                DmaDirection::ToDevice => {
                    // No invalidation needed - device only read the data
                }
            }
        }

        // Suppress unused warnings on x86
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = (dma_addr, size, direction);
        }
    }

    fn map_sg(
        &self,
        config: &DmaConfig,
        sg: &[(*const u8, usize)],
        direction: DmaDirection,
    ) -> Option<DmaSgList> {
        let mut entries = Vec::with_capacity(sg.len());
        let mut original = Vec::with_capacity(sg.len());

        for &(cpu_addr, len) in sg {
            let dma_addr = self.map_single(config, cpu_addr, len, direction)?;
            entries.push(DmaSgEntry {
                dma_addr,
                length: len,
            });
            original.push((cpu_addr, len));
        }

        Some(DmaSgList {
            entries,
            original,
            direction,
        })
    }

    fn unmap_sg(&self, config: &DmaConfig, sg: DmaSgList) {
        for (entry, &(_, len)) in sg.entries.iter().zip(sg.original.iter()) {
            self.unmap_single(config, entry.dma_addr, len, sg.direction);
        }
    }

    fn sync_for_cpu(
        &self,
        _config: &DmaConfig,
        dma_addr: DmaAddr,
        size: usize,
        direction: DmaDirection,
    ) {
        // On x86-64, cache is coherent - just need memory barrier
        #[cfg(target_arch = "x86_64")]
        {
            let _ = (dma_addr, size, direction);
            fence(Ordering::SeqCst);
        }

        // On ARM, invalidate cache to see device writes
        #[cfg(target_arch = "aarch64")]
        {
            use crate::arch::aarch64::cache;
            match direction {
                DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                    cache::cache_invalidate_range(dma_addr.0 as *const u8, size);
                }
                DmaDirection::ToDevice => {}
            }
        }
    }

    fn sync_for_device(
        &self,
        _config: &DmaConfig,
        dma_addr: DmaAddr,
        size: usize,
        direction: DmaDirection,
    ) {
        // On x86-64, cache is coherent - just need memory barrier
        #[cfg(target_arch = "x86_64")]
        {
            let _ = (dma_addr, size, direction);
            fence(Ordering::SeqCst);
        }

        // On ARM, clean cache to make CPU writes visible to device
        #[cfg(target_arch = "aarch64")]
        {
            use crate::arch::aarch64::cache;
            match direction {
                DmaDirection::ToDevice | DmaDirection::Bidirectional => {
                    cache::cache_clean_range(dma_addr.0 as *const u8, size);
                }
                DmaDirection::FromDevice => {}
            }
        }
    }

    fn name(&self) -> &'static str {
        "direct"
    }
}

// ============================================================================
// Global DMA API
// ============================================================================

/// Global DMA operations backend
static DMA_OPS: RwLock<Option<&'static dyn DmaOps>> = RwLock::new(None);

/// Initialize the DMA subsystem with a backend
pub fn dma_init(ops: &'static dyn DmaOps) {
    *DMA_OPS.write() = Some(ops);
    crate::printkln!("DMA: Initialized with {} backend", ops.name());
}

/// Allocate coherent DMA memory
///
/// Returns memory that is cache-coherent between CPU and device.
pub fn dma_alloc_coherent<D: DmaDevice>(dev: &D, size: usize) -> Option<DmaCoherent> {
    dma_alloc_coherent_aligned(dev, size, FRAME_SIZE)
}

/// Allocate coherent DMA memory with specific alignment
pub fn dma_alloc_coherent_aligned<D: DmaDevice>(
    dev: &D,
    size: usize,
    align: usize,
) -> Option<DmaCoherent> {
    let ops = DMA_OPS.read();
    ops.as_ref()?.alloc_coherent(dev.dma_config(), size, align)
}

/// Free coherent DMA memory
pub fn dma_free_coherent<D: DmaDevice>(_dev: &D, alloc: DmaCoherent) {
    if let Some(ops) = DMA_OPS.read().as_ref() {
        ops.free_coherent(alloc);
    }
}

/// Map a buffer for DMA
///
/// Creates a streaming DMA mapping. The CPU should not access the buffer
/// until unmapped or synced.
pub fn dma_map_single<D: DmaDevice>(
    dev: &D,
    cpu_addr: *const u8,
    size: usize,
    direction: DmaDirection,
) -> Option<DmaAddr> {
    let ops = DMA_OPS.read();
    ops.as_ref()?
        .map_single(dev.dma_config(), cpu_addr, size, direction)
}

/// Unmap a DMA buffer
pub fn dma_unmap_single<D: DmaDevice>(
    dev: &D,
    dma_addr: DmaAddr,
    size: usize,
    direction: DmaDirection,
) {
    if let Some(ops) = DMA_OPS.read().as_ref() {
        ops.unmap_single(dev.dma_config(), dma_addr, size, direction);
    }
}

/// Map a scatter-gather list
pub fn dma_map_sg<D: DmaDevice>(
    dev: &D,
    sg: &[(*const u8, usize)],
    direction: DmaDirection,
) -> Option<DmaSgList> {
    let ops = DMA_OPS.read();
    ops.as_ref()?.map_sg(dev.dma_config(), sg, direction)
}

/// Unmap a scatter-gather list
pub fn dma_unmap_sg<D: DmaDevice>(dev: &D, sg: DmaSgList) {
    if let Some(ops) = DMA_OPS.read().as_ref() {
        ops.unmap_sg(dev.dma_config(), sg);
    }
}

/// Check if a DMA mapping failed
pub fn dma_mapping_error(dma_addr: DmaAddr) -> bool {
    !dma_addr.is_valid()
}

/// Sync buffer for CPU access after device DMA
///
/// Call this before CPU reads data that device wrote.
pub fn dma_sync_single_for_cpu<D: DmaDevice>(
    dev: &D,
    dma_addr: DmaAddr,
    size: usize,
    direction: DmaDirection,
) {
    if let Some(ops) = DMA_OPS.read().as_ref() {
        ops.sync_for_cpu(dev.dma_config(), dma_addr, size, direction);
    }
}

/// Sync buffer for device access before DMA
///
/// Call this after CPU writes data that device will read.
pub fn dma_sync_single_for_device<D: DmaDevice>(
    dev: &D,
    dma_addr: DmaAddr,
    size: usize,
    direction: DmaDirection,
) {
    if let Some(ops) = DMA_OPS.read().as_ref() {
        ops.sync_for_device(dev.dma_config(), dma_addr, size, direction);
    }
}

// ============================================================================
// Alignment helpers for specific device types
// ============================================================================

/// Standard alignment requirements
pub mod align {
    /// xHCI TRB alignment (16 bytes)
    pub const XHCI_TRB: usize = 16;
    /// xHCI Command/Transfer Ring alignment (64 bytes)
    pub const XHCI_RING: usize = 64;
    /// xHCI Device Context alignment (64 bytes)
    pub const XHCI_CONTEXT: usize = 64;
    /// General page alignment (4KB)
    pub const PAGE: usize = 4096;
    /// AHCI Command List alignment (1KB)
    pub const AHCI_CMD_LIST: usize = 1024;
    /// AHCI FIS alignment (256 bytes)
    pub const AHCI_FIS: usize = 256;
    /// AHCI Command Table alignment (128 bytes)
    pub const AHCI_CMD_TABLE: usize = 128;
}
