//! Page descriptor - per-frame metadata for memory management
//!
//! Each physical frame tracked by the frame allocator has an associated
//! PageDescriptor that tracks:
//! - Page type (anonymous, file-backed, free)
//! - Mapping information (anon_vma for anonymous, address_space for file)
//! - LRU list linkage for eviction ordering
//!
//! Follows Linux's `struct folio` / `struct page` design where each physical
//! frame has associated metadata to enable reverse mapping lookups.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use spin::RwLock;

use crate::mm::anon_vma::AnonVma;

// ============================================================================
// Page flags (stored in atomic for lock-free access)
// ============================================================================

/// Page is locked (I/O in progress)
pub const PG_LOCKED: u32 = 1 << 0;

/// Page has been modified
pub const PG_DIRTY: u32 = 1 << 1;

/// Page is on LRU list
pub const PG_LRU: u32 = 1 << 2;

/// Page is on active list (recently accessed)
pub const PG_ACTIVE: u32 = 1 << 3;

/// Page is anonymous (not file-backed)
pub const PG_ANON: u32 = 1 << 4;

/// Page is in swap cache
pub const PG_SWAPCACHE: u32 = 1 << 5;

/// Page cannot be evicted (mlocked)
pub const PG_UNEVICTABLE: u32 = 1 << 6;

/// Page is being written back
pub const PG_WRITEBACK: u32 = 1 << 7;

// ============================================================================
// Page descriptor
// ============================================================================

/// Page descriptor - metadata for each physical frame
///
/// Following Linux's design, each physical frame has associated metadata
/// that enables efficient reverse mapping lookups and LRU-based eviction.
///
/// Note: Uses atomic fields instead of Clone since atomics can't be cloned.
/// We initialize the array by allocating and zeroing memory directly.
pub struct PageDescriptor {
    /// Page flags (atomic for lock-free flag checks)
    pub flags: AtomicU32,

    /// For anonymous pages: pointer to AnonVma
    /// For file pages: pointer to AddressSpace (via page cache)
    /// Uses low bit as discriminator (0 = file, 1 = anon)
    pub mapping: AtomicU64,

    /// Index within the mapping (page offset for files, or virtual page number)
    pub index: AtomicU64,

    /// Map count - number of page table entries mapping this page
    /// Separate from frame allocator refcount (which tracks references)
    pub mapcount: AtomicU32,
}

impl PageDescriptor {
    /// Create a new uninitialized page descriptor
    pub const fn new() -> Self {
        Self {
            flags: AtomicU32::new(0),
            mapping: AtomicU64::new(0),
            index: AtomicU64::new(0),
            mapcount: AtomicU32::new(0),
        }
    }

    /// Reset page descriptor to initial state
    pub fn reset(&self) {
        self.flags.store(0, Ordering::Relaxed);
        self.mapping.store(0, Ordering::Relaxed);
        self.index.store(0, Ordering::Relaxed);
        self.mapcount.store(0, Ordering::Relaxed);
    }

    // ========================================================================
    // Flag accessors
    // ========================================================================

    /// Check if page is anonymous
    #[inline]
    pub fn is_anon(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & PG_ANON != 0
    }

    /// Check if page is locked
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & PG_LOCKED != 0
    }

    /// Check if page is unevictable (mlocked)
    #[inline]
    pub fn is_unevictable(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & PG_UNEVICTABLE != 0
    }

    /// Check if page is on LRU list
    #[inline]
    pub fn is_on_lru(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & PG_LRU != 0
    }

    /// Check if page is on active LRU list
    #[inline]
    pub fn is_active(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & PG_ACTIVE != 0
    }

    /// Check if page is dirty
    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & PG_DIRTY != 0
    }

    /// Check if page is in swap cache
    #[inline]
    pub fn is_swapcache(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & PG_SWAPCACHE != 0
    }

    // ========================================================================
    // Flag modifiers
    // ========================================================================

    /// Set a flag
    #[inline]
    pub fn set_flag(&self, flag: u32) {
        self.flags.fetch_or(flag, Ordering::Relaxed);
    }

    /// Clear a flag
    #[inline]
    pub fn clear_flag(&self, flag: u32) {
        self.flags.fetch_and(!flag, Ordering::Relaxed);
    }

    /// Try to lock the page (set PG_LOCKED if not already set)
    /// Returns true if lock was acquired
    #[inline]
    pub fn try_lock(&self) -> bool {
        let old = self.flags.fetch_or(PG_LOCKED, Ordering::Acquire);
        old & PG_LOCKED == 0
    }

    /// Unlock the page
    #[inline]
    pub fn unlock(&self) {
        self.flags.fetch_and(!PG_LOCKED, Ordering::Release);
    }

    // ========================================================================
    // Mapcount operations
    // ========================================================================

    /// Get current mapcount
    #[inline]
    pub fn mapcount(&self) -> u32 {
        self.mapcount.load(Ordering::Relaxed)
    }

    /// Increment mapcount (when a new PTE maps this page)
    #[inline]
    pub fn inc_mapcount(&self) {
        self.mapcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement mapcount and return new value
    /// Returns the new value after decrement
    #[inline]
    pub fn dec_mapcount(&self) -> u32 {
        let old = self.mapcount.fetch_sub(1, Ordering::Relaxed);
        old.saturating_sub(1)
    }

    // ========================================================================
    // Anonymous page mapping
    // ========================================================================

    /// Set this page as anonymous with the given anon_vma
    ///
    /// Stores the anon_vma pointer with the low bit set to indicate anonymous.
    /// The Arc reference is cloned, so caller retains their reference.
    pub fn set_anon_mapping(&self, anon_vma: &Arc<AnonVma>) {
        self.set_flag(PG_ANON);
        // Store pointer with low bit = 1 to indicate anon
        let ptr = Arc::as_ptr(anon_vma) as u64 | 1;
        self.mapping.store(ptr, Ordering::Release);
    }

    /// Get the anon_vma for this anonymous page
    ///
    /// Returns None if this is not an anonymous page or has no mapping.
    /// The returned Arc is a new reference (increments refcount).
    pub fn get_anon_vma(&self) -> Option<Arc<AnonVma>> {
        if !self.is_anon() {
            return None;
        }
        let ptr = self.mapping.load(Ordering::Acquire);
        if ptr == 0 || ptr & 1 == 0 {
            return None;
        }
        // Strip the discriminator bit and reconstruct Arc
        let raw_ptr = (ptr & !1) as *const AnonVma;
        if raw_ptr.is_null() {
            return None;
        }
        // SAFETY: We stored this pointer via Arc::as_ptr and maintain
        // proper reference counting. We increment refcount by cloning.
        unsafe {
            Arc::increment_strong_count(raw_ptr);
            Some(Arc::from_raw(raw_ptr))
        }
    }

    /// Clear the mapping (called when page is freed)
    pub fn clear_mapping(&self) {
        let ptr = self.mapping.swap(0, Ordering::AcqRel);
        if ptr != 0 && self.is_anon() && ptr & 1 != 0 {
            // We held a reference to the AnonVma, release it
            let raw_ptr = (ptr & !1) as *const AnonVma;
            if !raw_ptr.is_null() {
                unsafe {
                    Arc::decrement_strong_count(raw_ptr);
                }
            }
        }
        self.clear_flag(PG_ANON);
    }
}

impl Default for PageDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global page descriptor array
// ============================================================================

/// Global page descriptor array - one entry per frame
///
/// Indexed by (phys_addr - base) / PAGE_SIZE.
/// Initialized during boot after the frame allocator is set up.
pub static PAGE_DESCRIPTORS: PageDescriptorArray = PageDescriptorArray::new();

/// Wrapper for the page descriptor array with safe access
pub struct PageDescriptorArray {
    inner: RwLock<PageDescriptorArrayInner>,
}

struct PageDescriptorArrayInner {
    /// Base physical address of managed memory
    base: u64,
    /// Array of page descriptors (leaked Vec for 'static lifetime)
    descriptors: Option<&'static [PageDescriptor]>,
}

impl PageDescriptorArray {
    const fn new() -> Self {
        Self {
            inner: RwLock::new(PageDescriptorArrayInner {
                base: 0,
                descriptors: None,
            }),
        }
    }

    /// Initialize page descriptors for the managed memory region
    ///
    /// Called during boot after the heap is initialized.
    /// Creates a PageDescriptor for each physical frame.
    pub fn init(&self, base: u64, num_frames: usize) {
        // Allocate array on heap - can't use vec![] with repeat because
        // PageDescriptor contains atomics which aren't Clone.
        // Instead, allocate a Vec and initialize each element.
        let mut descriptors_vec = Vec::with_capacity(num_frames);
        for _ in 0..num_frames {
            descriptors_vec.push(PageDescriptor::new());
        }
        let descriptors: &'static [PageDescriptor] = descriptors_vec.leak();

        let mut inner = self.inner.write();
        inner.base = base;
        inner.descriptors = Some(descriptors);
    }

    /// Get the base physical address
    pub fn base(&self) -> u64 {
        self.inner.read().base
    }

    /// Get page descriptor for a physical address
    ///
    /// Returns None if:
    /// - Page descriptors not yet initialized
    /// - Physical address is below the managed base
    /// - Physical address is beyond the managed region
    pub fn get(&self, phys: u64) -> Option<&'static PageDescriptor> {
        let inner = self.inner.read();
        let descriptors = inner.descriptors?;
        let base = inner.base;

        if phys < base {
            return None;
        }

        let idx = ((phys - base) / 4096) as usize;
        descriptors.get(idx)
    }

    /// Check if page descriptors are initialized
    pub fn is_initialized(&self) -> bool {
        self.inner.read().descriptors.is_some()
    }

    /// Get the number of managed frames
    pub fn num_frames(&self) -> usize {
        self.inner.read().descriptors.map(|d| d.len()).unwrap_or(0)
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Get page descriptor for a physical address
///
/// Convenience function that accesses the global PAGE_DESCRIPTORS.
#[inline]
pub fn page_descriptor(phys: u64) -> Option<&'static PageDescriptor> {
    PAGE_DESCRIPTORS.get(phys)
}

/// Initialize page descriptors
///
/// Called during boot after heap is available.
pub fn init_page_descriptors(base: u64, num_frames: usize) {
    PAGE_DESCRIPTORS.init(base, num_frames);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_descriptor_flags() {
        let page = PageDescriptor::new();

        assert!(!page.is_anon());
        assert!(!page.is_locked());
        assert!(!page.is_unevictable());

        page.set_flag(PG_ANON);
        assert!(page.is_anon());

        page.set_flag(PG_LOCKED);
        assert!(page.is_locked());

        page.clear_flag(PG_LOCKED);
        assert!(!page.is_locked());
        assert!(page.is_anon()); // Still set
    }

    #[test]
    fn test_page_descriptor_mapcount() {
        let page = PageDescriptor::new();

        assert_eq!(page.mapcount(), 0);

        page.inc_mapcount();
        assert_eq!(page.mapcount(), 1);

        page.inc_mapcount();
        assert_eq!(page.mapcount(), 2);

        let new_count = page.dec_mapcount();
        assert_eq!(new_count, 1);
        assert_eq!(page.mapcount(), 1);
    }

    #[test]
    fn test_page_descriptor_try_lock() {
        let page = PageDescriptor::new();

        // First lock should succeed
        assert!(page.try_lock());
        assert!(page.is_locked());

        // Second lock should fail
        assert!(!page.try_lock());

        // Unlock
        page.unlock();
        assert!(!page.is_locked());

        // Can lock again
        assert!(page.try_lock());
    }

    #[test]
    fn test_page_descriptor_reset() {
        let page = PageDescriptor::new();

        page.set_flag(PG_ANON | PG_LOCKED | PG_DIRTY);
        page.inc_mapcount();
        page.mapping.store(0x1000 | 1, Ordering::Relaxed);
        page.index.store(42, Ordering::Relaxed);

        page.reset();

        assert_eq!(page.flags.load(Ordering::Relaxed), 0);
        assert_eq!(page.mapping.load(Ordering::Relaxed), 0);
        assert_eq!(page.index.load(Ordering::Relaxed), 0);
        assert_eq!(page.mapcount(), 0);
    }
}
