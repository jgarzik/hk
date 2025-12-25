//! AArch64 cache maintenance operations
//!
//! These functions are required for DMA on ARM where the cache is not
//! hardware-coherent with device DMA like it is on x86.
//!
//! ARM requires explicit cache maintenance:
//! - Before DMA from device (FromDevice): Invalidate cache so CPU reads fresh data
//! - Before DMA to device (ToDevice): Clean cache so device sees CPU writes

use core::arch::asm;

/// Cache line size on typical ARM64 cores (64 bytes)
const CACHE_LINE_SIZE: usize = 64;

/// Clean (flush) a cache line by virtual address
///
/// This writes dirty cache lines back to memory, making CPU writes
/// visible to devices that read from RAM directly.
///
/// Uses DC CVAC (Clean by Virtual Address to Point of Coherency).
#[allow(dead_code)]
#[inline(always)]
fn dc_cvac(addr: u64) {
    unsafe {
        asm!(
            "dc cvac, {0}",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

/// Invalidate a cache line by virtual address
///
/// This discards cached data, forcing the CPU to re-read from memory
/// on the next access. Use this after device DMA writes to memory.
///
/// Uses DC IVAC (Invalidate by Virtual Address to Point of Coherency).
/// Note: IVAC requires EL1+ and may cause issues if there are dirty lines.
/// For safety, we use CIVAC (Clean and Invalidate) which handles dirty lines.
#[inline(always)]
fn dc_civac(addr: u64) {
    unsafe {
        asm!(
            "dc civac, {0}",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

/// Data synchronization barrier
///
/// Ensures all cache maintenance operations complete before continuing.
#[inline(always)]
fn dsb_sy() {
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// Clean (flush) a range of memory to the point of coherency
///
/// Call this before a device reads from memory (ToDevice DMA).
/// This ensures any CPU writes are visible in RAM.
pub fn cache_clean_range(addr: *const u8, len: usize) {
    if len == 0 {
        return;
    }

    let start = (addr as usize) & !(CACHE_LINE_SIZE - 1);
    let end = ((addr as usize) + len + CACHE_LINE_SIZE - 1) & !(CACHE_LINE_SIZE - 1);

    let mut current = start;
    while current < end {
        // Use CVAC (clean only) - writes dirty cache lines back to memory.
        // Do NOT use CIVAC (clean+invalidate) here because invalidation affects
        // ALL virtual addresses mapping the same physical page, which can corrupt
        // other processes' cached data (e.g., parent's rodata after child execve).
        dc_cvac(current as u64);
        current += CACHE_LINE_SIZE;
    }

    dsb_sy();
}

/// Invalidate a range of memory (clean + invalidate for safety)
///
/// Call this after a device writes to memory (FromDevice DMA).
/// This ensures the CPU reads fresh data from RAM, not stale cache.
///
/// Note: We use clean+invalidate (CIVAC) instead of just invalidate (IVAC)
/// because IVAC can cause data loss if there are dirty cache lines.
/// This is safer and handles the case where the buffer wasn't properly
/// flushed before DMA started.
pub fn cache_invalidate_range(addr: *const u8, len: usize) {
    if len == 0 {
        return;
    }

    let start = (addr as usize) & !(CACHE_LINE_SIZE - 1);
    let end = ((addr as usize) + len + CACHE_LINE_SIZE - 1) & !(CACHE_LINE_SIZE - 1);

    let mut current = start;
    while current < end {
        dc_civac(current as u64);
        current += CACHE_LINE_SIZE;
    }

    dsb_sy();
}

/// Clean and invalidate a range of memory
///
/// Use for bidirectional DMA buffers.
pub fn cache_flush_range(addr: *const u8, len: usize) {
    // CIVAC does both clean and invalidate
    cache_invalidate_range(addr, len);
}
