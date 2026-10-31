//! Memory barriers for device I/O (Linux arch/arm64/include/asm/barrier.h)

/// Order CPU writes to coherent DMA memory (outer shareable, stores)
#[inline(always)]
pub fn dma_wmb() {
    unsafe { core::arch::asm!("dmb oshst", options(nostack, preserves_flags)) };
}

/// Order CPU reads of coherent DMA memory (outer shareable, loads)
#[inline(always)]
pub fn dma_rmb() {
    unsafe { core::arch::asm!("dmb oshld", options(nostack, preserves_flags)) };
}

/// Order normal-memory writes before a following MMIO write (doorbell)
#[inline(always)]
pub fn wmb() {
    unsafe { core::arch::asm!("dsb st", options(nostack, preserves_flags)) };
}

/// Serialize this CPU's instruction stream (Linux sync_core): an ISB is
/// context synchronizing, so code modified by another CPU (made visible
/// by its cache maintenance) is fetched afresh after it
#[inline]
pub fn sync_core() {
    // SAFETY: a barrier; no memory or register effects
    unsafe { core::arch::asm!("isb", options(nostack, preserves_flags)) };
}
