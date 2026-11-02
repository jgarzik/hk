//! Shared anonymous memory (Linux mm/shmem.c, without the filesystem)
//!
//! The pages of a MAP_SHARED|MAP_ANONYMOUS mapping (Linux
//! shmem_zero_setup) and of a SysV shm segment live in a [`Shmem`]
//! object rather than only in page tables: every VMA mapping it (fork's
//! copies, the pieces of a split, mremap) faults the same page in at the
//! same index, so writes are shared even for pages first touched after
//! fork, and a zapped page (MADV_DONTNEED) keeps its data.
//!
//! The object holds one reference on each of its frames and each PTE
//! mapping one another; the pages go with the last VMA (`Arc`). Its size
//! is fixed at creation; a page past it is SIGBUS.
//!
//! The page index is an [`XArray`] (Linux uses the page cache's
//! xarray), its nodes (one per 64 pages) from the kernel heap.
//!
//! Locking: `Shmem.root` is a spin lock taken by the fault path under
//! the mm lock (mm lock -> Shmem.root) and by MADV_REMOVE with no lock
//! held; under it only `FRAME_ALLOCATOR` and the heap are taken. The drop takes no
//! lock (doc/LOCKING.md, Address Spaces).

use alloc::sync::Arc;

use super::fault::VmFault;
use super::xarray::{XArray, node_alloc};
use crate::FRAME_ALLOCATOR;
use crate::sync::spin::Mutex;

/// The pages of a shared anonymous object, by page index
pub struct Shmem {
    /// Size in pages, fixed at creation (Linux i_size of the shmem file)
    size: u64,
    /// The pages by index
    root: Mutex<XArray>,
}

/// A zeroed frame of user memory
fn zeroed() -> Option<u64> {
    let f = super::fault::alloc_user()?;
    super::page::clear_page(f);
    Some(f)
}

impl Shmem {
    /// A new, empty object of `size` pages
    pub fn new(size: u64) -> Arc<Self> {
        Arc::new(Self {
            size,
            root: Mutex::new(XArray::new()),
        })
    }

    /// The page at index `idx` (Linux shmem_get_folio), zeroed on first
    /// use, with a reference taken for the caller's PTE. Past the size
    /// (a mapping grown by mremap) is SIGBUS, like Linux; pages come
    /// from user memory, which stops at the low watermark.
    pub fn get_page(&self, idx: u64) -> Result<u64, VmFault> {
        if idx >= self.size {
            return Err(VmFault::Bus);
        }
        let mut root = self.root.lock();
        let mut page = root.load(idx);
        if page == 0 {
            page = zeroed().ok_or(VmFault::Oom)?;
            if root.store(idx, page, &mut node_alloc).is_none() {
                FRAME_ALLOCATOR.free(page);
                return Err(VmFault::Oom);
            }
        }
        // The object holds a reference until `root` is unlocked
        let held = FRAME_ALLOCATOR.incref(page);
        debug_assert!(held);
        Ok(page)
    }

    /// Clear the pages at indexes [from, to) (MADV_REMOVE, Linux
    /// shmem_fallocate hole punch): a page no mapping holds any more is
    /// freed; one still mapped elsewhere is zeroed in place, so every
    /// mapping reads zeros, as after Linux unmaps them all
    pub fn punch(&self, from: u64, to: u64) {
        let to = to.min(self.size);
        if from >= to {
            return;
        }
        let mut root = self.root.lock();
        let mut at = from;
        while let Some((i, e)) = root.find(at, to - 1, None) {
            if FRAME_ALLOCATOR.refcount(e) <= 1 {
                root.erase(i);
                FRAME_ALLOCATOR.decref(e);
            } else {
                super::page::clear_page(e);
            }
            at = i + 1;
        }
    }
}

impl Drop for Shmem {
    fn drop(&mut self) {
        self.root.get_mut().destroy(&mut |page| {
            FRAME_ALLOCATOR.decref(page);
        });
    }
}
