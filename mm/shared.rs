//! Kernel pages that user space maps too (Linux io_uring's
//! io_mapped_region, inserted into user mappings by vm_insert_pages)
//!
//! A [`SharedRegion`] is physically contiguous zeroed frames, reached
//! by the kernel through the direct map and by user space through the
//! mappings that fault its pages in (each mapping holds a reference per
//! page, so a frame outlives the region while a mapping still has it).
//! User space may write any of it at any time, so the kernel never
//! makes a Rust reference to its bytes: words it shares with user space
//! are atomics, and records are copied in and out with volatile
//! accesses, each field read exactly once into the copy (doc/UNSAFE.md
//! rule 8).

use core::sync::atomic::AtomicU32;

use crate::FRAME_ALLOCATOR;
use crate::util::error::KernelError;
use crate::util::pod::{FromBytes, IntoBytes};

use super::PAGE_SIZE;

/// Zeroed contiguous frames shared with user space
///
/// # Invariants
/// `phys` is the first of `pages` contiguous RAM frames from
/// `alloc_contig`, zeroed when made, each holding one reference owned
/// by the region (dropped in `Drop`).
pub struct SharedRegion {
    phys: u64,
    pages: usize,
}

impl SharedRegion {
    /// Room for `bytes` bytes, whole pages, zeroed; ENOMEM (Linux
    /// io_region_allocate_pages, physically contiguous)
    pub fn new(bytes: usize) -> Result<Self, KernelError> {
        let pages = bytes.div_ceil(PAGE_SIZE as usize).max(1);
        let phys = FRAME_ALLOCATOR
            .alloc_contig(pages)
            .ok_or(KernelError::OutOfMemory)?;
        for i in 0..pages {
            // SAFETY: a fresh frame of ours, not yet shared
            unsafe { super::page::clear_page(phys + i as u64 * PAGE_SIZE) };
        }
        // INVARIANT: contiguous fresh frames, zeroed, one reference each
        Ok(Self { phys, pages })
    }

    /// Its size in pages
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// Its size in bytes
    fn len(&self) -> usize {
        self.pages * PAGE_SIZE as usize
    }

    /// Page `i` for a user mapping, with a reference taken for its PTE;
    /// None past the end
    pub fn map_page(&self, i: u64) -> Option<u64> {
        if i >= self.pages as u64 {
            return None;
        }
        let phys = self.phys + i * PAGE_SIZE;
        // The region's own reference keeps the count above zero
        let held = FRAME_ALLOCATOR.incref(phys);
        debug_assert!(held, "shared region page without a reference");
        Some(phys)
    }

    /// The address of `size` bytes at `off`, aligned for `align`
    fn ptr(&self, off: usize, size: usize, align: usize) -> *mut u8 {
        assert!(
            off.checked_add(size).is_some_and(|e| e <= self.len()) && off.is_multiple_of(align),
            "shared region access out of bounds"
        );
        // In bounds of the contiguous frames (type invariant), checked above
        crate::arch::phys_to_virt(self.phys).wrapping_add(off)
    }

    /// The 32-bit word at byte `off` (4-aligned, in bounds: asserted),
    /// shared with user space
    pub fn word(&self, off: usize) -> &AtomicU32 {
        let p = self.ptr(off, 4, 4).cast::<AtomicU32>();
        // SAFETY: in bounds and aligned (checked); frames of the region,
        // which lives as long as the reference; an atomic tolerates the
        // other side's concurrent accesses
        unsafe { &*p }
    }

    /// A copy of the `T` at byte `off` (aligned for `T`, in bounds:
    /// asserted), read once
    pub fn read<T: FromBytes>(&self, off: usize) -> T {
        let p = self.ptr(off, size_of::<T>(), align_of::<T>()).cast::<T>();
        // SAFETY: in bounds and aligned (checked), the region's frames;
        // a volatile read takes the bytes as they are, any of them a
        // valid T (FromBytes)
        unsafe { p.read_volatile() }
    }

    /// Store `v` at byte `off` (aligned for `T`, in bounds: asserted)
    pub fn write<T: IntoBytes>(&self, off: usize, v: T) {
        let p = self.ptr(off, size_of::<T>(), align_of::<T>()).cast::<T>();
        // SAFETY: in bounds and aligned (checked), the region's frames,
        // to which no Rust reference exists (module docs)
        unsafe { p.write_volatile(v) }
    }
}

impl Drop for SharedRegion {
    fn drop(&mut self) {
        for i in 0..self.pages {
            // A page still mapped keeps its frame until it is unmapped
            FRAME_ALLOCATOR.decref(self.phys + i as u64 * PAGE_SIZE);
        }
    }
}
