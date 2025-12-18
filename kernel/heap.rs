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
}

impl HeapAllocator {
    /// Create a new uninitialized heap allocator
    pub const fn new() -> Self {
        Self {
            inner: IrqSpinlock::new(HeapAllocatorInner {
                free_list: None,
                heap_start: 0,
                heap_end: 0,
            }),
        }
    }

    /// Initialize the heap with the given memory region
    ///
    /// # Safety
    /// The memory region must be valid and not used elsewhere.
    pub unsafe fn init(&self, start: usize, size: usize) {
        let mut inner = self.inner.lock();
        inner.heap_start = start;
        inner.heap_end = start + size;

        // Create initial free block spanning entire heap
        let block = start as *mut Block;
        unsafe {
            (*block).size = size;
            (*block).next = None;
        }
        inner.free_list = Some(block);
    }
}

unsafe impl GlobalAlloc for HeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut inner = self.inner.lock();

        let size = layout.size().max(MIN_BLOCK_SIZE);
        // Ensure alignment is at least usize for the back-pointer we store
        let align = layout.align().max(core::mem::align_of::<usize>());

        // Total size needed: Block header + space for back-pointer + alignment + user data
        // We need to store block_start just before the aligned user pointer
        let total_size =
            core::mem::size_of::<Block>() + core::mem::size_of::<usize>() + align + size;

        // Search free list for suitable block
        let mut prev: Option<*mut Block> = None;
        let mut current = inner.free_list;

        while let Some(block) = current {
            unsafe {
                if (*block).size >= total_size {
                    // Found a suitable block
                    let block_start = block as usize;
                    let block_size = (*block).size;

                    // Calculate where user data starts:
                    // - After Block header
                    // - After space for back-pointer (usize)
                    // - Properly aligned
                    let after_header =
                        block_start + core::mem::size_of::<Block>() + core::mem::size_of::<usize>();
                    let aligned_start = (after_header + align - 1) & !(align - 1);

                    // Store block_start pointer just before user data
                    let backptr_loc = (aligned_start - core::mem::size_of::<usize>()) as *mut usize;
                    *backptr_loc = block_start;

                    // Remove block from free list
                    let next = (*block).next;
                    if let Some(p) = prev {
                        (*p).next = next;
                    } else {
                        inner.free_list = next;
                    }

                    // Store the total allocated size in the block header (for dealloc)
                    let used_size = aligned_start - block_start + size;
                    (*block).size = used_size;

                    // If there's enough remaining space, create a new free block
                    if block_size - used_size >= MIN_BLOCK_SIZE + core::mem::size_of::<Block>() {
                        let new_block = (block_start + used_size) as *mut Block;
                        (*new_block).size = block_size - used_size;
                        (*new_block).next = inner.free_list;
                        inner.free_list = Some(new_block);
                    }

                    return aligned_start as *mut u8;
                }

                prev = current;
                current = (*block).next;
            }
        }

        // No suitable block found
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }

        let mut inner = self.inner.lock();

        // Retrieve the block start from the back-pointer stored just before user data
        let backptr_loc = (ptr as usize - core::mem::size_of::<usize>()) as *const usize;
        let block_start = unsafe { *backptr_loc };

        // Get the block header
        let block = block_start as *mut Block;
        let block_size = unsafe { (*block).size };

        // Add block back to free list
        unsafe {
            (*block).next = inner.free_list;
        }
        inner.free_list = Some(block);

        // Note: We don't coalesce adjacent blocks for simplicity.
        // A more sophisticated allocator would merge adjacent free blocks.
        let _ = block_size; // Silence unused warning (size is already in block header)
    }
}

unsafe impl Sync for HeapAllocator {}

impl Default for HeapAllocator {
    fn default() -> Self {
        Self::new()
    }
}
