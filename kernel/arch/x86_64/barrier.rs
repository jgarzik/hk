//! Memory barriers for device I/O (Linux asm/barrier.h, x86-64)
//!
//! x86 is TSO and uncached MMIO stores are not reordered with earlier
//! stores, so the DMA barriers only need to stop the compiler.

use core::sync::atomic::{Ordering, compiler_fence};

/// Order CPU writes to coherent DMA memory (e.g. descriptor fields before
/// the field that hands it to the device)
#[inline(always)]
pub fn dma_wmb() {
    compiler_fence(Ordering::SeqCst);
}

/// Order CPU reads of coherent DMA memory (e.g. a descriptor's status
/// before the data it covers)
#[inline(always)]
pub fn dma_rmb() {
    compiler_fence(Ordering::SeqCst);
}

/// Order normal-memory writes before a following MMIO write (doorbell)
#[inline(always)]
pub fn wmb() {
    unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)) };
}

/// Serialize this CPU's instruction stream (Linux sync_core): CPUID is
/// architecturally serializing, so code modified by another CPU is
/// fetched afresh after it
#[inline]
pub fn sync_core() {
    // SAFETY: CPUID leaf 0 has no side effects; rbx is preserved by hand
    unsafe {
        core::arch::asm!(
            "mov {t}, rbx",
            "cpuid",
            "mov rbx, {t}",
            t = out(reg) _,
            inout("eax") 0u32 => _,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }
}
