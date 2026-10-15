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
