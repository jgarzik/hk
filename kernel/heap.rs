//! Kernel heap allocator
//!
//! Simple linked-list allocator for the kernel heap.
//!
//! Uses IrqSpinlock instead of spin::Mutex to prevent deadlocks
//! when page fault handlers (e.g., COW) need to allocate memory
//! while interrupts are enabled.

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

    /// Bytes in free blocks (fragmentation not considered)
    pub fn free_bytes(&self) -> usize {
        self.inner.lock().free_bytes
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

impl Default for HeapAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Boot-time memory the heap must never cover (kernel image, boot
/// modules, DTB, initrd): the kernel reads it after the heap is live
#[derive(Clone, Copy)]
pub struct BootRange {
    pub name: &'static str,
    pub start: usize,
    pub end: usize,
}

impl BootRange {
    fn hits(&self, start: usize, end: usize) -> bool {
        self.start < self.end && self.start < end && start < self.end
    }
}

/// Lowest `align`-aligned (power of two) start >= `lo` whose
/// `size` bytes miss every busy range
pub fn place(lo: usize, size: usize, align: usize, busy: &[BootRange]) -> usize {
    let mut start = round_up(lo, align);
    while let Some(r) = busy.iter().find(|r| r.hits(start, start + size)) {
        start = round_up(r.end, align);
    }
    start
}

/// Boot assertion: a heap over boot data corrupts it silently, so stop
pub fn check(start: usize, end: usize, r: &BootRange) {
    if r.hits(start, end) {
        panic!(
            "heap {:#x}-{:#x} overlaps {} {:#x}-{:#x}",
            start, end, r.name, r.start, r.end
        );
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

    #[test]
    fn place_skips_busy() {
        let r = |start, end| BootRange {
            name: "x",
            start,
            end,
        };
        let busy = [r(0x100, 0x2000), r(0x5000, 0x6001), r(0x9000, 0x9000)];
        assert_eq!(place(0, 0x1000, 0x1000, &busy), 0x2000);
        assert_eq!(place(0, 0x4000, 0x1000, &busy), 0x7000);
        // empty ranges never block
        assert_eq!(place(0x8000, 0x2000, 0x1000, &busy), 0x8000);
        check(0x2000, 0x5000, &busy[1]);
    }

    #[test]
    #[should_panic(expected = "overlaps")]
    fn check_panics() {
        let r = BootRange {
            name: "initrd",
            start: 0x1000,
            end: 0x2000,
        };
        check(0x1fff, 0x3000, &r);
    }
}
