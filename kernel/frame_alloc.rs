//! Physical frame allocator
//!
//! Bitmap-based allocator for physical memory frames.
//! Supports reference counting for copy-on-write (COW) pages.
//!
//! Uses IrqSpinlock instead of spin::Mutex to prevent deadlocks
//! when page fault handlers (COW) need to allocate frames while
//! interrupts are enabled.

use crate::arch::FrameAlloc;
use crate::arch::IrqSpinlock;

/// Page/frame size (4KB)
pub const FRAME_SIZE: usize = 4096;

/// Huge page size (2MB = 512 * 4KB)
pub const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// Number of 4KB frames per 2MB huge page
pub const FRAMES_PER_HUGE_PAGE: usize = 512;

/// Maximum number of frames we can track (256MB worth of 4KB frames)
const MAX_FRAMES: usize = 65536;

/// Bitmap frame allocator
///
/// Uses a bitmap to track which physical frames are available.
/// Each bit represents one 4KB frame.
/// Also maintains reference counts for COW support.
///
/// Uses IrqSpinlock to disable interrupts while holding the lock,
/// preventing deadlock if a page fault handler needs to allocate.
pub struct BitmapFrameAllocator {
    inner: IrqSpinlock<BitmapFrameAllocatorInner>,
}

struct BitmapFrameAllocatorInner {
    /// Bitmap of free frames (1 = free, 0 = used)
    bitmap: [u64; MAX_FRAMES / 64],
    /// Reference counts for each frame (0 = free, 1+ = in use)
    /// Using u16 to save space while allowing up to 65535 references
    refcounts: [u16; MAX_FRAMES],
    /// Base physical address
    base: u64,
    /// Total number of frames
    total_frames: usize,
    /// Next hint for free frame search
    next_free: usize,
}

impl BitmapFrameAllocator {
    /// Create a new uninitialized frame allocator
    pub const fn new() -> Self {
        Self {
            inner: IrqSpinlock::new(BitmapFrameAllocatorInner {
                bitmap: [0; MAX_FRAMES / 64],
                refcounts: [0; MAX_FRAMES],
                base: 0,
                total_frames: 0,
                next_free: 0,
            }),
        }
    }

    /// Initialize with a memory region
    ///
    /// The region from `base` to `base + size` will be available for allocation.
    pub fn init(&self, base: u64, size: u64) {
        let mut inner = self.inner.lock();
        inner.base = base;
        inner.total_frames = (size as usize / FRAME_SIZE).min(MAX_FRAMES);
        inner.next_free = 0;

        // Mark all frames as free
        let full_words = inner.total_frames / 64;
        for i in 0..full_words {
            inner.bitmap[i] = !0u64; // All 1s = all free
        }

        // Handle remaining bits
        let remaining = inner.total_frames % 64;
        if remaining > 0 {
            inner.bitmap[full_words] = (1u64 << remaining) - 1;
        }
    }

    /// Allocate a physical frame (thread-safe, takes &self)
    pub fn alloc(&self) -> Option<u64> {
        let mut inner = self.inner.lock();

        let num_words = inner.total_frames.div_ceil(64);

        // Search starting from hint
        for offset in 0..num_words {
            let word_idx = (inner.next_free / 64 + offset) % num_words;
            let word = inner.bitmap[word_idx];

            if word != 0 {
                let bit = word.trailing_zeros() as usize;
                let frame = word_idx * 64 + bit;

                if frame < inner.total_frames {
                    // Mark as used
                    inner.bitmap[word_idx] &= !(1u64 << bit);
                    inner.next_free = frame + 1;
                    // Set initial refcount to 1
                    inner.refcounts[frame] = 1;

                    let phys_addr = inner.base + (frame as u64 * FRAME_SIZE as u64);
                    return Some(phys_addr);
                }
            }
        }

        None
    }

    /// Free a physical frame (thread-safe, takes &self)
    ///
    /// This directly frees the frame, ignoring reference counts.
    /// For COW support, use `decref()` instead.
    pub fn free(&self, frame: u64) {
        let mut inner = self.inner.lock();

        if frame < inner.base {
            return;
        }

        let frame_idx = ((frame - inner.base) / FRAME_SIZE as u64) as usize;
        if frame_idx < inner.total_frames {
            let word = frame_idx / 64;
            let bit = frame_idx % 64;
            inner.bitmap[word] |= 1u64 << bit;
            inner.refcounts[frame_idx] = 0;

            // Update hint
            if frame_idx < inner.next_free {
                inner.next_free = frame_idx;
            }
        }
    }

    /// Increment reference count for a frame (for COW sharing)
    ///
    /// Call this when sharing a frame between multiple page tables.
    pub fn incref(&self, frame: u64) {
        let mut inner = self.inner.lock();

        if frame < inner.base {
            return;
        }

        let frame_idx = ((frame - inner.base) / FRAME_SIZE as u64) as usize;
        if frame_idx < inner.total_frames {
            // Saturating add to prevent overflow
            inner.refcounts[frame_idx] = inner.refcounts[frame_idx].saturating_add(1);
        }
    }

    /// Decrement reference count and free frame if it reaches zero
    ///
    /// Returns true if the frame was freed, false if still referenced.
    pub fn decref(&self, frame: u64) -> bool {
        let mut inner = self.inner.lock();

        if frame < inner.base {
            return false;
        }

        let frame_idx = ((frame - inner.base) / FRAME_SIZE as u64) as usize;
        if frame_idx < inner.total_frames {
            if inner.refcounts[frame_idx] > 0 {
                inner.refcounts[frame_idx] -= 1;
            }

            if inner.refcounts[frame_idx] == 0 {
                // Frame is no longer referenced, free it
                let word = frame_idx / 64;
                let bit = frame_idx % 64;
                inner.bitmap[word] |= 1u64 << bit;

                // Update hint
                if frame_idx < inner.next_free {
                    inner.next_free = frame_idx;
                }
                return true;
            }
        }
        false
    }

    /// Get the current reference count for a frame
    pub fn refcount(&self, frame: u64) -> u16 {
        let inner = self.inner.lock();

        if frame < inner.base {
            return 0;
        }

        let frame_idx = ((frame - inner.base) / FRAME_SIZE as u64) as usize;
        if frame_idx < inner.total_frames {
            inner.refcounts[frame_idx]
        } else {
            0
        }
    }

    /// Mark a range of frames as used (e.g., for kernel memory)
    pub fn mark_used(&self, phys_start: u64, size: u64) {
        let mut inner = self.inner.lock();

        // Calculate end of region to mark
        let phys_end = phys_start.saturating_add(size);

        // Skip if entirely below our managed region
        if phys_end <= inner.base {
            return;
        }

        // Clamp start to our base
        let clamped_start = phys_start.max(inner.base);
        let clamped_size = phys_end - clamped_start;

        let start_frame = ((clamped_start - inner.base) / FRAME_SIZE as u64) as usize;
        let num_frames = (clamped_size as usize).div_ceil(FRAME_SIZE);

        for i in 0..num_frames {
            let frame = start_frame + i;
            if frame < inner.total_frames {
                let word = frame / 64;
                let bit = frame % 64;
                inner.bitmap[word] &= !(1u64 << bit);
            }
        }
    }

    // =========================================================================
    // Huge Page Support (2MB = 512 frames)
    // =========================================================================

    /// Allocate a contiguous 2MB huge page (512 frames)
    ///
    /// Returns the physical address of the first frame, or None if
    /// no contiguous 2MB-aligned region is available.
    ///
    /// The allocation is 2MB-aligned to meet hardware requirements for
    /// huge page mappings.
    pub fn alloc_huge(&self) -> Option<u64> {
        let mut inner = self.inner.lock();

        // We need 512 consecutive free frames starting at a 512-frame boundary.
        // 512 frames = 8 consecutive bitmap words (64 bits each).
        // Each word must be all 1s (0xFFFF_FFFF_FFFF_FFFF = all free).
        const WORDS_PER_HUGE_PAGE: usize = FRAMES_PER_HUGE_PAGE / 64; // 8

        // Calculate how many complete huge pages could fit in our managed region
        let max_huge_pages = inner.total_frames / FRAMES_PER_HUGE_PAGE;
        if max_huge_pages == 0 {
            return None;
        }

        // Search for 8 consecutive all-ones words at an 8-word boundary
        for huge_idx in 0..max_huge_pages {
            let word_start = huge_idx * WORDS_PER_HUGE_PAGE;
            let frame_start = huge_idx * FRAMES_PER_HUGE_PAGE;

            // Check if this huge page region is entirely within bounds
            if frame_start + FRAMES_PER_HUGE_PAGE > inner.total_frames {
                break;
            }

            // Check if all 8 words are all 1s (all 512 frames free)
            let mut all_free = true;
            for w in 0..WORDS_PER_HUGE_PAGE {
                if inner.bitmap[word_start + w] != !0u64 {
                    all_free = false;
                    break;
                }
            }

            if all_free {
                // Mark all 512 frames as used (set all 8 words to 0)
                for w in 0..WORDS_PER_HUGE_PAGE {
                    inner.bitmap[word_start + w] = 0;
                }

                // Set refcount for the head frame (we track huge pages by head frame only)
                inner.refcounts[frame_start] = 1;

                // Update hint past this huge page
                inner.next_free = frame_start + FRAMES_PER_HUGE_PAGE;

                let phys_addr = inner.base + (frame_start as u64 * FRAME_SIZE as u64);
                return Some(phys_addr);
            }
        }

        None
    }

    /// Free a contiguous 2MB huge page
    ///
    /// Frees all 512 frames starting at the given 2MB-aligned address.
    /// The address must be 2MB-aligned.
    pub fn free_huge(&self, frame: u64) {
        let mut inner = self.inner.lock();

        if frame < inner.base {
            return;
        }

        let frame_idx = ((frame - inner.base) / FRAME_SIZE as u64) as usize;

        // Verify alignment (must be at 512-frame boundary)
        if !frame_idx.is_multiple_of(FRAMES_PER_HUGE_PAGE) {
            return;
        }

        // Check bounds
        if frame_idx + FRAMES_PER_HUGE_PAGE > inner.total_frames {
            return;
        }

        const WORDS_PER_HUGE_PAGE: usize = FRAMES_PER_HUGE_PAGE / 64;
        let word_start = frame_idx / 64;

        // Mark all 512 frames as free (set all 8 words to all 1s)
        for w in 0..WORDS_PER_HUGE_PAGE {
            inner.bitmap[word_start + w] = !0u64;
        }

        // Clear refcount for head frame
        inner.refcounts[frame_idx] = 0;

        // Update hint
        if frame_idx < inner.next_free {
            inner.next_free = frame_idx;
        }
    }

    /// Increment reference count for a huge page
    ///
    /// Used when sharing a huge page between page tables (e.g., fork with COW).
    /// Only the head frame's refcount is tracked.
    pub fn incref_huge(&self, frame: u64) {
        let mut inner = self.inner.lock();

        if frame < inner.base {
            return;
        }

        let frame_idx = ((frame - inner.base) / FRAME_SIZE as u64) as usize;

        // Verify alignment
        if !frame_idx.is_multiple_of(FRAMES_PER_HUGE_PAGE) {
            return;
        }

        if frame_idx < inner.total_frames {
            inner.refcounts[frame_idx] = inner.refcounts[frame_idx].saturating_add(1);
        }
    }

    /// Decrement reference count for a huge page and free if it reaches zero
    ///
    /// Returns true if the huge page was freed, false if still referenced.
    pub fn decref_huge(&self, frame: u64) -> bool {
        let mut inner = self.inner.lock();

        if frame < inner.base {
            return false;
        }

        let frame_idx = ((frame - inner.base) / FRAME_SIZE as u64) as usize;

        // Verify alignment
        if !frame_idx.is_multiple_of(FRAMES_PER_HUGE_PAGE) {
            return false;
        }

        if frame_idx + FRAMES_PER_HUGE_PAGE > inner.total_frames {
            return false;
        }

        if inner.refcounts[frame_idx] > 0 {
            inner.refcounts[frame_idx] -= 1;
        }

        if inner.refcounts[frame_idx] == 0 {
            // Huge page is no longer referenced, free all 512 frames
            const WORDS_PER_HUGE_PAGE: usize = FRAMES_PER_HUGE_PAGE / 64;
            let word_start = frame_idx / 64;

            for w in 0..WORDS_PER_HUGE_PAGE {
                inner.bitmap[word_start + w] = !0u64;
            }

            // Update hint
            if frame_idx < inner.next_free {
                inner.next_free = frame_idx;
            }
            return true;
        }

        false
    }

    /// Get the reference count for a huge page
    ///
    /// Returns the refcount of the head frame.
    pub fn refcount_huge(&self, frame: u64) -> u16 {
        let inner = self.inner.lock();

        if frame < inner.base {
            return 0;
        }

        let frame_idx = ((frame - inner.base) / FRAME_SIZE as u64) as usize;

        // Verify alignment
        if !frame_idx.is_multiple_of(FRAMES_PER_HUGE_PAGE) {
            return 0;
        }

        if frame_idx < inner.total_frames {
            inner.refcounts[frame_idx]
        } else {
            0
        }
    }

    /// Check if a physical address is the start of a huge page allocation
    ///
    /// Returns true if this address is 2MB-aligned and has a non-zero refcount
    /// (indicating it's the head of an allocated huge page).
    pub fn is_huge_page(&self, frame: u64) -> bool {
        let inner = self.inner.lock();

        if frame < inner.base {
            return false;
        }

        let frame_idx = ((frame - inner.base) / FRAME_SIZE as u64) as usize;

        // Must be at 512-frame boundary
        if !frame_idx.is_multiple_of(FRAMES_PER_HUGE_PAGE) {
            return false;
        }

        if frame_idx < inner.total_frames {
            // Check if head frame has non-zero refcount (allocated as huge page)
            inner.refcounts[frame_idx] > 0
        } else {
            false
        }
    }
}

impl FrameAlloc for BitmapFrameAllocator {
    type PhysAddr = u64;

    fn alloc_frame(&mut self) -> Option<Self::PhysAddr> {
        // Delegate to shared implementation
        (&*self).alloc_frame()
    }

    fn free_frame(&mut self, frame: Self::PhysAddr) {
        // Delegate to shared implementation
        (&*self).free_frame(frame);
    }
}

/// Implementation for references - allows use with static allocator
/// This works because BitmapFrameAllocator uses interior mutability (Mutex)
impl FrameAlloc for &BitmapFrameAllocator {
    type PhysAddr = u64;

    fn alloc_frame(&mut self) -> Option<Self::PhysAddr> {
        let mut inner = self.inner.lock();

        let num_words = inner.total_frames.div_ceil(64);

        // Search starting from hint
        for offset in 0..num_words {
            let word_idx = (inner.next_free / 64 + offset) % num_words;
            let word = inner.bitmap[word_idx];

            if word != 0 {
                let bit = word.trailing_zeros() as usize;
                let frame = word_idx * 64 + bit;

                if frame < inner.total_frames {
                    // Mark as used
                    inner.bitmap[word_idx] &= !(1u64 << bit);
                    inner.next_free = frame + 1;

                    let phys_addr = inner.base + (frame as u64 * FRAME_SIZE as u64);
                    return Some(phys_addr);
                }
            }
        }

        None
    }

    fn free_frame(&mut self, frame: Self::PhysAddr) {
        let mut inner = self.inner.lock();

        if frame < inner.base {
            return;
        }

        let frame_idx = ((frame - inner.base) / FRAME_SIZE as u64) as usize;
        if frame_idx < inner.total_frames {
            let word = frame_idx / 64;
            let bit = frame_idx % 64;
            inner.bitmap[word] |= 1u64 << bit;

            // Update hint
            if frame_idx < inner.next_free {
                inner.next_free = frame_idx;
            }
        }
    }
}

/// Memory statistics from frame allocator
#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    /// Total memory in bytes
    pub total_bytes: u64,
    /// Free memory in bytes
    pub free_bytes: u64,
}

impl BitmapFrameAllocator {
    /// Get memory statistics
    ///
    /// Returns total and free memory in bytes. This is used by sysinfo syscall.
    pub fn stats(&self) -> MemoryStats {
        let inner = self.inner.lock();

        let total_bytes = (inner.total_frames as u64) * (FRAME_SIZE as u64);

        // Count free frames by counting set bits in bitmap
        let mut free_frames = 0usize;
        for word in &inner.bitmap[..inner.total_frames.div_ceil(64)] {
            free_frames += word.count_ones() as usize;
        }

        // Handle the last partial word if total_frames is not a multiple of 64
        let remainder = inner.total_frames % 64;
        if remainder > 0 {
            let last_word_idx = inner.total_frames / 64;
            // Mask out bits beyond total_frames that we counted
            let valid_bits = inner.bitmap[last_word_idx] & ((1u64 << remainder) - 1);
            // Re-count just the valid bits
            free_frames = free_frames - inner.bitmap[last_word_idx].count_ones() as usize
                + valid_bits.count_ones() as usize;
        }

        let free_bytes = (free_frames as u64) * (FRAME_SIZE as u64);

        MemoryStats {
            total_bytes,
            free_bytes,
        }
    }
}

impl Default for BitmapFrameAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrapper for using the static FRAME_ALLOCATOR with traits requiring &mut self
pub struct FrameAllocRef<'a>(pub &'a BitmapFrameAllocator);

impl FrameAlloc for FrameAllocRef<'_> {
    type PhysAddr = u64;

    fn alloc_frame(&mut self) -> Option<Self::PhysAddr> {
        self.0.alloc()
    }

    fn free_frame(&mut self, frame: Self::PhysAddr) {
        self.0.free(frame)
    }
}
