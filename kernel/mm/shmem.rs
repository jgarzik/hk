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
//! The page index is a radix tree like a page table (Linux uses the
//! page cache's xarray): four levels of 512-entry nodes, each node a
//! frame of user memory, allocated as pages are touched. Nothing is
//! taken from the kernel heap: what a process can make the kernel hold
//! for it stops at the low watermark like its pages.
//!
//! Locking: `Shmem.root` is a spin lock taken by the fault path under
//! the mm lock (mm lock -> Shmem.root) and by MADV_REMOVE with no lock
//! held; under it only `FRAME_ALLOCATOR` is taken. The drop takes no
//! lock (doc/LOCKING.md, Address Spaces).

use alloc::sync::Arc;

use super::fault::VmFault;
use crate::FRAME_ALLOCATOR;
use crate::arch::phys_to_virt;
use crate::sync::spin::Mutex;

/// Index bits per tree level (512 entries a node)
const BITS: u32 = 9;

/// Tree levels below the root: 4 levels index 2^36 pages, more than a
/// mapping can hold (TASK_SIZE / 4KB)
const LEVELS: u32 = 4;

/// The pages of a shared anonymous object, by page index
pub struct Shmem {
    /// Size in pages, fixed at creation (Linux i_size of the shmem file)
    size: u64,
    /// Root node of the index (a frame; 0 until the first page)
    root: Mutex<u64>,
}

/// Entry `i` (mod 512) of the node frame `node`
fn slot(node: u64, i: u64) -> &'static mut u64 {
    // SAFETY: a node frame owned by the object, through the direct map;
    // used under its lock (or by its drop)
    unsafe { &mut *(phys_to_virt(node) as *mut u64).add((i & 511) as usize) }
}

/// A zeroed frame of user memory
fn zeroed() -> Result<u64, VmFault> {
    let f = super::fault::alloc_user().ok_or(VmFault::Oom)?;
    // SAFETY: a fresh frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(f), 0, 4096) };
    Ok(f)
}

/// The leaf entry of page `idx` under `root`, creating missing nodes
fn walk(root: &mut u64, idx: u64) -> Result<&'static mut u64, VmFault> {
    if *root == 0 {
        *root = zeroed()?;
    }
    let mut node = *root;
    for level in (1..LEVELS).rev() {
        let e = slot(node, idx >> (BITS * level));
        if *e == 0 {
            *e = zeroed()?;
        }
        node = *e;
    }
    Ok(slot(node, idx))
}

/// Visit the pages of node `node` at `level` (0: a leaf) whose indexes
/// fall in [from, to); `base` is the node's first index. Empty subtrees
/// are skipped.
fn each_page(node: u64, level: u32, base: u64, from: u64, to: u64, f: &mut dyn FnMut(&mut u64)) {
    let span = 1u64 << (BITS * level);
    for i in 0..512u64 {
        let lo = base + i * span;
        if lo >= to || lo + span <= from {
            continue;
        }
        let e = slot(node, i);
        if *e == 0 {
            continue;
        }
        if level == 0 {
            f(e);
        } else {
            each_page(*e, level - 1, lo, from, to, f);
        }
    }
}

/// Free node `node` at `level` and everything below it, dropping the
/// object's reference on each page
fn free_node(node: u64, level: u32) {
    for i in 0..512 {
        let e = *slot(node, i);
        if e == 0 {
            continue;
        }
        if level == 0 {
            FRAME_ALLOCATOR.decref(e);
        } else {
            free_node(e, level - 1);
        }
    }
    FRAME_ALLOCATOR.free(node);
}

impl Shmem {
    /// A new, empty object of `size` pages
    pub fn new(size: u64) -> Arc<Self> {
        Arc::new(Self {
            size,
            root: Mutex::new(0),
        })
    }

    /// The page at index `idx` (Linux shmem_get_folio), zeroed on first
    /// use, with a reference taken for the caller's PTE. Past the size
    /// (a mapping grown by mremap) is SIGBUS, like Linux; pages and index
    /// nodes come from user memory, which stops at the low watermark.
    pub fn get_page(&self, idx: u64) -> Result<u64, VmFault> {
        if idx >= self.size {
            return Err(VmFault::Bus);
        }
        let mut root = self.root.lock();
        let e = walk(&mut root, idx)?;
        if *e == 0 {
            *e = zeroed()?;
        }
        FRAME_ALLOCATOR.incref(*e);
        Ok(*e)
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
        let root = self.root.lock();
        if *root == 0 {
            return;
        }
        each_page(*root, LEVELS - 1, 0, from, to, &mut |e| {
            if FRAME_ALLOCATOR.refcount(*e) <= 1 {
                FRAME_ALLOCATOR.decref(core::mem::take(e));
            } else {
                // SAFETY: a page of the object, through the direct map
                unsafe { core::ptr::write_bytes(phys_to_virt(*e), 0, 4096) };
            }
        });
    }
}

impl Drop for Shmem {
    fn drop(&mut self) {
        let root = *self.root.get_mut();
        if root != 0 {
            free_node(root, LEVELS - 1);
        }
    }
}
