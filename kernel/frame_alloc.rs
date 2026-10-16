//! Physical frame allocator
//!
//! Bitmap-based allocator for physical memory frames.
//! Supports reference counting for copy-on-write (COW) pages.
//!
//! Uses IrqSpinlock instead of crate::sync::spin::Mutex to prevent deadlocks
//! when page fault handlers (COW) need to allocate frames while
//! interrupts are enabled.

use crate::arch::FrameAlloc;
use crate::arch::IrqSpinlock;

/// Page/frame size (4KB)
pub const FRAME_SIZE: usize = 4096;

/// Number of 4KB frames per 2MB huge page
pub const FRAMES_PER_HUGE_PAGE: usize = 512;

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
    /// Bitmap of free frames (1 = free, 0 = used); lives in the first
    /// frames of the managed region, sized to it
    bitmap: &'static mut [u64],
    /// Reference counts for each frame (0 = free, 1+ = in use)
    /// Using u16 to save space while allowing up to 65535 references
    refcounts: &'static mut [u16],
    /// Base physical address
    base: u64,
    /// Total number of frames
    total_frames: usize,
    /// Next hint for free frame search
    next_free: usize,
    /// Free frames (set bits in `bitmap`), kept exact by `set_free`
    free: usize,
    /// Leading frames holding `bitmap` and `refcounts` (never free)
    meta: usize,
}

impl BitmapFrameAllocatorInner {
    /// Mark frame `idx` free or used, keeping the free count exact (a
    /// double free or double mark changes nothing)
    fn set_free(&mut self, idx: usize, free: bool) {
        let (w, b) = (idx / 64, 1u64 << (idx % 64));
        let was = self.bitmap[w] & b != 0;
        if free && !was {
            self.bitmap[w] |= b;
            self.free += 1;
        } else if !free && was {
            self.bitmap[w] &= !b;
            self.free -= 1;
        }
    }

    /// Index of the managed frame at `frame`; None for any address the
    /// allocator does not hand out (outside the region, unaligned, or a
    /// metadata frame), so a stray free or refcount op is a no-op
    /// instead of an out-of-bounds write
    fn index(&self, frame: u64) -> Option<usize> {
        let off = frame.checked_sub(self.base)?;
        if !off.is_multiple_of(FRAME_SIZE as u64) {
            return None;
        }
        let idx = usize::try_from(off / FRAME_SIZE as u64).ok()?;
        (idx >= self.meta && idx < self.total_frames).then_some(idx)
    }

    /// Index of a huge page head: 2MB-aligned (physically) and wholly
    /// inside the managed frames
    fn huge_index(&self, frame: u64) -> Option<usize> {
        let idx = self.index(frame)?;
        let fits = idx + FRAMES_PER_HUGE_PAGE <= self.total_frames;
        (frame.is_multiple_of((FRAMES_PER_HUGE_PAGE * FRAME_SIZE) as u64) && fits).then_some(idx)
    }

    /// Set a whole bitmap word (huge pages), keeping the free count exact
    fn set_word(&mut self, w: usize, v: u64) {
        self.free = self.free + v.count_ones() as usize - self.bitmap[w].count_ones() as usize;
        self.bitmap[w] = v;
    }
}

impl BitmapFrameAllocator {
    /// Create a new uninitialized frame allocator
    pub const fn new() -> Self {
        Self {
            inner: IrqSpinlock::new(BitmapFrameAllocatorInner {
                bitmap: &mut [],
                refcounts: &mut [],
                base: 0,
                total_frames: 0,
                next_free: 0,
                free: 0,
                meta: 0,
            }),
        }
    }

    /// Initialize with a memory region (all of it, however large)
    ///
    /// The region from `base` to `base + size` will be available for
    /// allocation, except its first frames, which hold the bitmap and
    /// the reference counts (used through the direct map)
    pub fn init(&self, base: u64, size: u64) {
        let p = crate::arch::phys_to_virt(base);
        unsafe { self.init_at(base, size, p) };
    }

    /// Metadata bytes for `n` frames: bitmap words, then u16 refcounts
    fn meta_bytes(n: usize) -> usize {
        n.div_ceil(64) * 8 + n * 2
    }

    /// Bytes at the start of a `size`-byte region that `init` overwrites
    /// with metadata (callers check no boot data lives there)
    pub fn meta_size(size: u64) -> u64 {
        Self::meta_bytes((size / FRAME_SIZE as u64) as usize).next_multiple_of(FRAME_SIZE) as u64
    }

    /// `init` with the metadata at kernel address `p` (the first frames
    /// of the region; host tests pass their own buffer)
    ///
    /// # Safety
    /// `p` must be writable for `meta_bytes(size / FRAME_SIZE)` rounded
    /// up to a frame, 8-byte aligned, and used for nothing else.
    unsafe fn init_at(&self, base: u64, size: u64, p: *mut u8) {
        let n = (size / FRAME_SIZE as u64) as usize;
        let words = n.div_ceil(64);
        let meta = Self::meta_bytes(n).div_ceil(FRAME_SIZE);
        assert!(meta < n, "frame region too small");
        let mut inner = self.inner.lock();
        unsafe {
            core::ptr::write_bytes(p, 0, meta * FRAME_SIZE);
            inner.bitmap = core::slice::from_raw_parts_mut(p as *mut u64, words);
            inner.refcounts = core::slice::from_raw_parts_mut(p.add(words * 8) as *mut u16, n);
        }
        // Metadata frames and the bits past `n` in the last word stay 0
        // (used): never handed out
        inner.base = base;
        inner.total_frames = n;
        inner.meta = meta;
        inner.next_free = meta;
        inner.free = 0;
        for f in meta..n {
            inner.set_free(f, true);
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
                    inner.set_free(frame, false);
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

        let Some(frame_idx) = inner.index(frame) else {
            return;
        };
        if frame_idx < inner.total_frames {
            inner.set_free(frame_idx, true);
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

        let Some(frame_idx) = inner.index(frame) else {
            return;
        };
        if frame_idx < inner.total_frames {
            // Saturates: a saturated count is sticky (see `put_count`)
            inner.refcounts[frame_idx] = inner.refcounts[frame_idx].saturating_add(1);
        }
    }

    /// Decrement reference count and free frame if it reaches zero
    ///
    /// Returns true if the frame was freed, false if still referenced.
    pub fn decref(&self, frame: u64) -> bool {
        let mut inner = self.inner.lock();

        let Some(frame_idx) = inner.index(frame) else {
            return false;
        };
        if frame_idx < inner.total_frames {
            if !put_count(&mut inner.refcounts[frame_idx]) {
                return false;
            }

            if inner.refcounts[frame_idx] == 0 {
                // Frame is no longer referenced, free it
                inner.set_free(frame_idx, true);

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

        let Some(frame_idx) = inner.index(frame) else {
            return 0;
        };
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

        // Every frame the range touches, clamped to the managed frames
        let first = ((phys_start.max(inner.base) - inner.base) / FRAME_SIZE as u64) as usize;
        let end = (phys_end - inner.base).div_ceil(FRAME_SIZE as u64);
        let end = end.min(inner.total_frames as u64) as usize;
        for frame in first..end {
            inner.set_free(frame, false);
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
            // The mapping needs a physically 2MB-aligned run
            let phys = inner.base + (frame_start * FRAME_SIZE) as u64;
            if !phys.is_multiple_of((FRAMES_PER_HUGE_PAGE * FRAME_SIZE) as u64) {
                continue;
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
                    inner.set_word(word_start + w, 0);
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

        let Some(frame_idx) = inner.huge_index(frame) else {
            return;
        };

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
            inner.set_word(word_start + w, !0u64);
        }

        // Clear refcount for head frame
        inner.refcounts[frame_idx] = 0;

        // Update hint
        if frame_idx < inner.next_free {
            inner.next_free = frame_idx;
        }
    }

    /// A huge page was split into 512 4KB mappings: every frame now
    /// carries the head's count, so each is released by its own PTE
    pub fn split_huge(&self, frame: u64) {
        let mut inner = self.inner.lock();
        let Some(idx) = inner.huge_index(frame) else {
            return;
        };
        let count = inner.refcounts[idx];
        inner.refcounts[idx + 1..idx + FRAMES_PER_HUGE_PAGE].fill(count);
    }

    /// Increment reference count for a huge page
    ///
    /// Used when sharing a huge page between page tables (e.g., fork with COW).
    /// Only the head frame's refcount is tracked.
    pub fn incref_huge(&self, frame: u64) {
        let mut inner = self.inner.lock();

        let Some(frame_idx) = inner.huge_index(frame) else {
            return;
        };

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

        let Some(frame_idx) = inner.huge_index(frame) else {
            return false;
        };

        // Verify alignment
        if !frame_idx.is_multiple_of(FRAMES_PER_HUGE_PAGE) {
            return false;
        }

        if frame_idx + FRAMES_PER_HUGE_PAGE > inner.total_frames {
            return false;
        }

        if !put_count(&mut inner.refcounts[frame_idx]) {
            return false;
        }

        if inner.refcounts[frame_idx] == 0 {
            // Huge page is no longer referenced, free all 512 frames
            const WORDS_PER_HUGE_PAGE: usize = FRAMES_PER_HUGE_PAGE / 64;
            let word_start = frame_idx / 64;

            for w in 0..WORDS_PER_HUGE_PAGE {
                inner.set_word(word_start + w, !0u64);
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

        let Some(frame_idx) = inner.huge_index(frame) else {
            return 0;
        };

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

        let Some(frame_idx) = inner.huge_index(frame) else {
            return false;
        };

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

    fn alloc_contig(&mut self, n: usize) -> Option<Self::PhysAddr> {
        BitmapFrameAllocator::alloc_contig(self, n)
    }

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

    fn alloc_contig(&mut self, n: usize) -> Option<Self::PhysAddr> {
        BitmapFrameAllocator::alloc_contig(self, n)
    }

    fn alloc_frame(&mut self) -> Option<Self::PhysAddr> {
        self.alloc()
    }

    fn free_frame(&mut self, frame: Self::PhysAddr) {
        self.free(frame)
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

impl BitmapFrameAllocator {
    /// Allocate `n` physically contiguous frames (aligned to n rounded
    /// up to a power of two, at most 2MB), each with refcount 1: kernel
    /// stacks and multi-frame DMA buffers. Linear scan; rare callers.
    pub fn alloc_contig(&self, n: usize) -> Option<u64> {
        if n == 0 {
            return None;
        }
        let align = n.next_power_of_two().min(FRAMES_PER_HUGE_PAGE);
        let mut inner = self.inner.lock();
        let total = inner.total_frames;
        let free = |inner: &BitmapFrameAllocatorInner, f: usize| {
            inner.bitmap[f / 64] & (1u64 << (f % 64)) != 0
        };
        let mut start = 0;
        while start + n <= total {
            match (start..start + n).rev().find(|&f| !free(&inner, f)) {
                Some(used) => start = (used + 1).next_multiple_of(align),
                None => {
                    for f in start..start + n {
                        inner.set_free(f, false);
                        inner.refcounts[f] = 1;
                    }
                    return Some(inner.base + (start * FRAME_SIZE) as u64);
                }
            }
        }
        None
    }

    /// Free frames now (exact, O(1))
    pub fn free_frames(&self) -> usize {
        self.inner.lock().free
    }

    /// Frames kept back from user data (page-cache pages that cannot be
    /// evicted) so page tables, stacks and DMA buffers still get memory
    /// when ramfs files fill RAM: 1/32 of memory, at least 4MB
    pub fn reserve_frames(&self) -> usize {
        (self.inner.lock().total_frames / 32).max(1024)
    }

    /// Free memory is down to the reserve (watermark-lite)
    pub fn below_reserve(&self) -> bool {
        self.free_frames() <= self.reserve_frames()
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

    fn alloc_contig(&mut self, n: usize) -> Option<Self::PhysAddr> {
        self.0.alloc_contig(n)
    }

    fn reserve_low(&self) -> bool {
        self.0.below_reserve() || crate::heap_low()
    }

    fn alloc_frame(&mut self) -> Option<Self::PhysAddr> {
        self.0.alloc()
    }

    fn free_frame(&mut self, frame: Self::PhysAddr) {
        self.0.free(frame)
    }
}

/// Drop one reference from a frame count; false if the count must not
/// change: a saturated count (u16::MAX references were taken; more
/// would have wrapped) is sticky, so the frame is never freed while some
/// of its uncounted references may remain (leaked instead, never used
/// after free)
fn put_count(count: &mut u16) -> bool {
    if *count == u16::MAX {
        return false;
    }
    *count = count.saturating_sub(1);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x4020_0000; // 2MB aligned

    /// An allocator over `n` frames at BASE, metadata in a host buffer
    fn fa(n: usize) -> (BitmapFrameAllocator, Vec<u64>) {
        let a = BitmapFrameAllocator::new();
        let bytes = BitmapFrameAllocator::meta_bytes(n).next_multiple_of(FRAME_SIZE);
        let mut buf = vec![0u64; bytes / 8];
        unsafe { a.init_at(BASE, (n * FRAME_SIZE) as u64, buf.as_mut_ptr() as *mut u8) };
        (a, buf)
    }

    fn pa(i: usize) -> u64 {
        BASE + (i * FRAME_SIZE) as u64
    }

    #[test]
    fn saturated_refcount_is_sticky() {
        let (a, _b) = fa(100);
        let f = a.alloc().unwrap();
        for _ in 0..70_000 {
            a.incref(f);
        }
        for _ in 0..70_000 {
            assert!(!a.decref(f));
        }
        assert_eq!(a.refcount(f), u16::MAX);
    }

    #[test]
    fn metadata_frames_are_never_handed_out() {
        let (a, _b) = fa(1000);
        let meta = a.inner.lock().meta;
        assert!(meta >= 1);
        assert_eq!(a.free_frames(), 1000 - meta);
        let mut got = Vec::new();
        while let Some(f) = a.alloc() {
            assert!(f >= pa(meta) && f < pa(1000), "{f:#x}");
            got.push(f);
        }
        assert_eq!(got.len(), 1000 - meta);
        // Freeing a metadata frame is a no-op
        a.free(pa(0));
        assert_eq!(a.alloc(), None);
    }

    #[test]
    fn last_partial_word_bits_stay_used() {
        // 70 frames: the second bitmap word has 6 valid bits
        let (a, _b) = fa(70);
        let mut n = 0;
        while let Some(f) = a.alloc() {
            assert!(f < pa(70));
            n += 1;
        }
        assert_eq!(n, 70 - a.inner.lock().meta);
        assert_eq!(a.stats().free_bytes, 0);
    }

    #[test]
    fn out_of_range_ops_are_noops() {
        let (a, b) = fa(128);
        let free = a.free_frames();
        let snapshot = b.clone();
        for f in [
            0,
            BASE - FRAME_SIZE as u64,
            pa(128),
            pa(1 << 30),
            u64::MAX,
            pa(5) + 8,
        ] {
            a.free(f);
            a.incref(f);
            assert!(!a.decref(f));
            assert_eq!(a.refcount(f), 0);
            a.free_huge(f);
            a.incref_huge(f);
            assert!(!a.decref_huge(f));
            assert!(!a.is_huge_page(f));
        }
        assert_eq!(a.free_frames(), free);
        assert_eq!(b, snapshot);
    }

    #[test]
    fn boundary_frames_round_trip() {
        let (a, _b) = fa(256);
        let meta = a.inner.lock().meta;
        a.mark_used(pa(meta), (256 - meta) as u64 * FRAME_SIZE as u64);
        assert_eq!(a.free_frames(), 0);
        a.free(pa(255));
        assert_eq!(a.alloc(), Some(pa(255)));
        assert_eq!(a.refcount(pa(255)), 1);
        a.incref(pa(255));
        assert!(!a.decref(pa(255)));
        assert!(a.decref(pa(255)));
        assert_eq!(a.free_frames(), 1);
    }

    #[test]
    fn mark_used_covers_partial_frames() {
        let (a, _b) = fa(64);
        let free = a.free_frames();
        // 4096 bytes starting mid-frame touch two frames
        a.mark_used(pa(10) + 100, FRAME_SIZE as u64);
        assert_eq!(a.free_frames(), free - 2);
        // A range past the end is clamped
        a.mark_used(pa(60), 1 << 40);
        assert_eq!(a.free_frames(), free - 6);
    }

    #[test]
    fn contig_alloc_at_the_end() {
        let (a, _b) = fa(64);
        let meta = a.inner.lock().meta;
        a.mark_used(pa(meta), (60 - meta) as u64 * FRAME_SIZE as u64);
        // Frames 60..63 free: a run of 4 ends exactly at the region end
        assert_eq!(a.alloc_contig(4), Some(pa(60)));
        assert_eq!(a.alloc_contig(1), None);
        assert_eq!(a.alloc_contig(4), None);
        assert_eq!(a.alloc_contig(1000), None);
        for i in 60..64 {
            assert_eq!(a.refcount(pa(i)), 1);
        }
    }

    #[test]
    fn huge_pages_stay_inside_and_aligned() {
        // 1100 frames: one full 2MB run (frames 512..1023) past metadata
        let (a, _b) = fa(1100);
        let h = a.alloc_huge().expect("huge");
        assert_eq!(h, pa(512));
        assert!(a.is_huge_page(h));
        assert_eq!(a.alloc_huge(), None);
        assert!(a.decref_huge(h));
        assert_eq!(a.alloc_huge(), Some(h));
    }

    #[test]
    fn split_huge_frames_free_one_by_one() {
        let (a, _b) = fa(1100);
        let h = a.alloc_huge().expect("huge");
        let free = a.free_frames();
        a.split_huge(h);
        assert_eq!(a.refcount(pa(1023)), 1);
        // A shared (forked) tail frame survives one put
        a.incref(pa(600));
        assert!(!a.decref(pa(600)));
        for i in 512..1024 {
            assert!(a.decref(pa(i)), "frame {i}");
        }
        assert_eq!(a.free_frames(), free + 512);
    }
}
