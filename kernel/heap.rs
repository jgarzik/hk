//! Kernel heap: the global allocator
//!
//! Before the page allocator exists, allocations come from a small
//! static boot arena (a first-fit linked-list allocator in the kernel
//! image's bss); from then on from the slab allocator (`mm::slab`
//! kmalloc). Memory is freed to whichever gave it (the arena by
//! address). The arena's lock is an `IrqSpinlock` leaf, like the slab
//! locks, so the heap is IRQ-safe.

use crate::arch::IrqSpinlock;
use ::core::alloc::{GlobalAlloc, Layout};

/// Minimum allocation block size (must be at least size of usize for back-pointer)
const MIN_BLOCK_SIZE: usize = 16;

/// Heap block header (stored at the start of each free block)
#[repr(C)]
struct Block {
    /// Total size of this block (including header)
    size: usize,
    /// Next free block in the list
    next: Option<*mut Block>,
}

/// Simple linked-list heap allocator
///
/// Uses IrqSpinlock to disable interrupts while holding the lock,
/// preventing deadlock if an interrupt handler needs to allocate.
///
/// Memory layout for allocated blocks:
/// ```text
/// +----------------+--------+-----------------+
/// | Block header   | Align  | User data       |
/// | (size, unused) | gap    | (returned ptr)  |
/// +----------------+--------+-----------------+
/// ^                         ^
/// block_start               aligned_start (returned to user)
/// ```
///
/// We store block_start at (aligned_start - sizeof(usize)) so dealloc can find it.
pub struct HeapAllocator {
    inner: IrqSpinlock<HeapAllocatorInner>,
}

struct HeapAllocatorInner {
    /// Head of free list
    free_list: Option<*mut Block>,
    /// Start of heap
    heap_start: usize,
    /// End of heap
    heap_end: usize,
    /// Bytes in free blocks
    free_bytes: usize,
}

impl HeapAllocator {
    /// Create a new uninitialized heap allocator
    pub const fn new() -> Self {
        Self {
            inner: IrqSpinlock::new(HeapAllocatorInner {
                free_list: None,
                heap_start: 0,
                heap_end: 0,
                free_bytes: 0,
            }),
        }
    }

    /// Initialize the heap with the given memory region
    ///
    /// # Safety
    /// The memory region must be valid and not used elsewhere.
    pub unsafe fn init(&self, start: usize, size: usize) {
        let mut inner = self.inner.lock();
        let start = round_up(start, GRAIN);
        let size = size & !(GRAIN - 1);
        inner.heap_start = start;
        inner.heap_end = start + size;

        // Create initial free block spanning entire heap
        let block = start as *mut Block;
        unsafe {
            (*block).size = size;
            (*block).next = None;
        }
        inner.free_list = Some(block);
        inner.free_bytes = size;
    }

    /// Bytes allocated (block headers and alignment included)
    pub fn used_bytes(&self) -> usize {
        let inner = self.inner.lock();
        inner.heap_end - inner.heap_start - inner.free_bytes
    }
}

/// Block granularity: every block starts and ends 16-byte aligned so
/// headers of split remainders are aligned
const GRAIN: usize = 16;
const HDR: usize = core::mem::size_of::<Block>();

const fn round_up(n: usize, a: usize) -> usize {
    (n + a - 1) & !(a - 1)
}

unsafe impl GlobalAlloc for HeapAllocator {
    /// First fit over an address-ordered free list; a block is split
    /// only if the remainder can hold a header and a minimal block,
    /// otherwise the whole block is used (no bytes are ever lost)
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut inner = self.inner.lock();
        let size = layout.size().max(MIN_BLOCK_SIZE);
        let align = layout.align().max(core::mem::align_of::<usize>());
        let mut prev: Option<*mut Block> = None;
        let mut current = inner.free_list;
        while let Some(block) = current {
            unsafe {
                let start = block as usize;
                let bsize = (*block).size;
                let aligned = round_up(start + HDR + core::mem::size_of::<usize>(), align);
                let used = round_up(aligned - start + size, GRAIN);
                if bsize >= used {
                    let next = (*block).next;
                    let link = if bsize - used >= HDR + MIN_BLOCK_SIZE {
                        let rest = (start + used) as *mut Block;
                        (*rest).size = bsize - used;
                        (*rest).next = next;
                        (*block).size = used;
                        Some(rest)
                    } else {
                        next
                    };
                    match prev {
                        Some(p) => (*p).next = link,
                        None => inner.free_list = link,
                    }
                    *((aligned - core::mem::size_of::<usize>()) as *mut usize) = start;
                    inner.free_bytes -= (*block).size;
                    return aligned as *mut u8;
                }
                prev = current;
                current = (*block).next;
            }
        }
        core::ptr::null_mut()
    }

    /// Return a block to the address-ordered free list and merge it with
    /// adjacent free neighbours, so freed memory does not fragment
    /// forever
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let mut inner = self.inner.lock();
        unsafe {
            let start = *((ptr as usize - core::mem::size_of::<usize>()) as *const usize);
            let block = start as *mut Block;
            inner.free_bytes += (*block).size;
            let mut prev: Option<*mut Block> = None;
            let mut cur = inner.free_list;
            while let Some(c) = cur {
                if c as usize > start {
                    break;
                }
                prev = cur;
                cur = (*c).next;
            }
            (*block).next = cur;
            if let Some(c) = cur
                && start + (*block).size == c as usize
            {
                (*block).size += (*c).size;
                (*block).next = (*c).next;
            }
            match prev {
                Some(p) if p as usize + (*p).size == start => {
                    (*p).size += (*block).size;
                    (*p).next = (*block).next;
                }
                Some(p) => (*p).next = Some(block),
                None => inner.free_list = Some(block),
            }
        }
    }
}

unsafe impl Sync for HeapAllocator {}

/// Boot arena size: what boot allocates before the page allocator is up
/// (cmdline, early device tree and console state), with ample margin
const ARENA_SIZE: usize = 256 * 1024;

#[repr(C, align(4096))]
struct ArenaBuf(core::cell::UnsafeCell<[u8; ARENA_SIZE]>);

// SAFETY: handed to the arena allocator once, which serializes access
unsafe impl Sync for ArenaBuf {}

static ARENA_BUF: ArenaBuf = ArenaBuf(core::cell::UnsafeCell::new([0; ARENA_SIZE]));

/// The block came from the boot arena (its static bounds: no lock)
fn in_arena(p: *mut u8) -> bool {
    let base = ARENA_BUF.0.get() as usize;
    (base..base + ARENA_SIZE).contains(&(p as usize))
}

/// The global allocator: boot arena, then slab
pub struct KernelAlloc {
    arena: HeapAllocator,
    /// Set once the page allocator is up (Release; read Acquire)
    slab: core::sync::atomic::AtomicBool,
    once: core::sync::atomic::AtomicBool,
}

impl KernelAlloc {
    pub const fn new() -> Self {
        Self {
            arena: HeapAllocator::new(),
            slab: core::sync::atomic::AtomicBool::new(false),
            once: core::sync::atomic::AtomicBool::new(false),
        }
    }

    fn arena(&self) -> &HeapAllocator {
        use core::sync::atomic::Ordering;
        if !self.once.swap(true, Ordering::AcqRel) {
            // SAFETY: the buffer is used by this arena only
            unsafe { self.arena.init(ARENA_BUF.0.get() as usize, ARENA_SIZE) };
        }
        &self.arena
    }

    /// The page allocator is up: new allocations come from slab
    pub fn slab_ready(&self) {
        self.slab.store(true, core::sync::atomic::Ordering::Release);
    }

    /// Bytes still allocated from the boot arena
    pub fn arena_used(&self) -> usize {
        self.arena().used_bytes()
    }
}

impl Default for KernelAlloc {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl GlobalAlloc for KernelAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.slab.load(core::sync::atomic::Ordering::Acquire) {
            crate::mm::slab::kmalloc(layout.size(), layout.align())
        } else {
            unsafe { self.arena().alloc(layout) }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if in_arena(ptr) {
            unsafe { self.arena.dealloc(ptr, layout) };
        } else {
            crate::mm::slab::kfree(ptr, layout.size(), layout.align());
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        let slab = !in_arena(ptr);
        if slab && crate::mm::slab::fits(layout.size(), new, layout.align()) {
            return ptr;
        }
        // SAFETY: as GlobalAlloc::realloc requires of the caller
        unsafe {
            let new_layout = Layout::from_size_align_unchecked(new, layout.align());
            let p = self.alloc(new_layout);
            if !p.is_null() {
                core::ptr::copy_nonoverlapping(ptr, p, layout.size().min(new));
                self.dealloc(ptr, layout);
            }
            p
        }
    }
}

impl Default for HeapAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(16))]
    struct Arena([u8; 64 * 1024]);

    #[test]
    fn frees_coalesce() {
        let mut arena = Box::new(Arena([0; 64 * 1024]));
        let h = HeapAllocator::new();
        unsafe { h.init(arena.0.as_mut_ptr() as usize, arena.0.len()) };
        let big = Layout::from_size_align(60 * 1024, 8).unwrap();
        let mut ptrs = std::vec::Vec::new();
        for i in 0..200 {
            let l = Layout::from_size_align(16 + (i % 7) * 40, 8 << (i % 3)).unwrap();
            let p = unsafe { h.alloc(l) };
            assert!(!p.is_null());
            assert_eq!(p as usize % l.align(), 0);
            ptrs.push((p, l));
        }
        // Free in an interleaved order, then the whole arena is one block
        for (i, (p, l)) in ptrs.iter().enumerate().filter(|(i, _)| i % 2 == 0) {
            let _ = i;
            unsafe { h.dealloc(*p, *l) };
        }
        for (p, l) in ptrs.iter().skip(1).step_by(2) {
            unsafe { h.dealloc(*p, *l) };
        }
        let p = unsafe { h.alloc(big) };
        assert!(!p.is_null());
        unsafe { h.dealloc(p, big) };
    }
}
