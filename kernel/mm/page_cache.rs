//! Page cache for file-backed memory
//!
//! Implements a page cache that stores file pages indexed by
//! (FileId, page_offset). Uses FIFO eviction when the cache is full.
//!
//! ## Dirty Pages and Writeback
//!
//! Pages can be marked as "dirty" (modified). The eviction policy respects:
//! - Clean pages: Can always be evicted (data exists on backing store)
//! - Dirty pages with writeback: Can be evicted after writeback
//! - Dirty pages without writeback: NEVER evicted (e.g., ramfs pages)
//!
//! This prevents data loss for in-memory filesystems like ramfs where
//! the page cache IS the only copy of the data.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;

use ::core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use spin::RwLock;

use crate::arch::FrameAlloc;

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Unique identifier for a file in the VFS
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileId(pub u64);

impl FileId {
    /// Create a FileId from a raw value
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Create a FileId from a file path using a simple hash
    pub fn from_path(path: &str) -> Self {
        let mut hash: u64 = 0;
        for byte in path.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        Self(hash)
    }

    /// Create a FileId from a block device DevId
    ///
    /// Uses high bit to distinguish from regular file IDs.
    /// Format: 0x8000_0000_0000_0000 | (major << 20) | minor
    pub fn from_blkdev(major: u16, minor: u16) -> Self {
        let dev_encoded = ((major as u64) << 20) | (minor as u64 & 0xFFFFF);
        Self(0x8000_0000_0000_0000 | dev_encoded)
    }

    /// Check if this FileId represents a block device
    pub fn is_blkdev(&self) -> bool {
        (self.0 & 0x8000_0000_0000_0000) != 0
    }
}

// ============================================================================
// AddressSpaceOps - Filesystem-specific page I/O operations
// ============================================================================

/// Address space operations - filesystem-specific page I/O
///
/// This is analogous to Linux's `address_space_operations`. Each filesystem
/// implements these methods to handle reading/writing pages from/to its
/// backing store.
///
/// ## Locking Context
///
/// These methods are called with the per-page lock (CachedPage.locked) held,
/// protecting the page contents during I/O. Importantly:
///
/// - **PAGE_CACHE global Mutex is NOT held** - must not be acquired by implementations
/// - **AddressSpace.inner RwLock is NOT held** - must not be acquired by implementations
/// - Implementations may acquire their own locks (e.g., block device queue locks)
///
/// This follows the rule: "Never hold high-level locks while calling a_ops" to
/// prevent blocking while holding global locks.
pub trait AddressSpaceOps: Send + Sync {
    /// Read a page from backing store into the given buffer.
    ///
    /// Called when a page cache miss occurs and the page needs to be
    /// populated from the backing store (disk, network, etc.).
    ///
    /// ## Locking Context
    /// - Per-page lock is held (CachedPage.locked)
    /// - PAGE_CACHE and AddressSpace.inner are NOT held
    ///
    /// ## Arguments
    /// * `file_id` - Identifies the file/inode
    /// * `page_offset` - Page offset within the file (in PAGE_SIZE units)
    /// * `buf` - Buffer to read into (PAGE_SIZE bytes)
    ///
    /// ## Returns
    /// Number of bytes read (may be less than PAGE_SIZE at EOF), or negative errno
    fn readpage(&self, file_id: FileId, page_offset: u64, buf: &mut [u8]) -> Result<usize, i32>;

    /// Write a dirty page back to the backing store.
    ///
    /// Called during writeback (eviction, fsync, sync). The page is locked
    /// when this is called.
    ///
    /// ## Locking Context
    /// - Per-page lock is held (CachedPage.locked)
    /// - PAGE_CACHE and AddressSpace.inner are NOT held
    ///
    /// ## Arguments
    /// * `file_id` - Identifies the file/inode
    /// * `page_offset` - Page offset within the file (in PAGE_SIZE units)
    /// * `buf` - Buffer containing page data (PAGE_SIZE bytes)
    ///
    /// ## Returns
    /// Number of bytes written on success, or negative errno
    fn writepage(&self, file_id: FileId, page_offset: u64, buf: &[u8]) -> Result<usize, i32>;

    /// Batch writeback of multiple dirty pages (optional optimization).
    ///
    /// Default implementation calls writepage() for each page sequentially.
    /// Filesystems can override for more efficient batched I/O.
    fn writepages(&self, file_id: FileId, pages: &[(u64, &[u8])]) -> Result<usize, i32> {
        let mut total = 0;
        for (offset, buf) in pages {
            total += self.writepage(file_id, *offset, buf)?;
        }
        Ok(total)
    }
}

/// Null address space operations for non-writeback filesystems.
///
/// Used for filesystems like ramfs where the page cache IS the storage
/// and there is no backing store to write to. These filesystems use
/// `can_writeback = false` so writepage should never be called.
pub struct NullAddressSpaceOps;

impl AddressSpaceOps for NullAddressSpaceOps {
    fn readpage(&self, _file_id: FileId, _page_offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        // For ramfs: pages are created zeroed, readpage fills with zeros
        buf.fill(0);
        Ok(buf.len())
    }

    fn writepage(&self, _file_id: FileId, _page_offset: u64, _buf: &[u8]) -> Result<usize, i32> {
        // Ramfs has no backing store - writepage should never be called
        // because can_writeback = false prevents eviction of dirty pages
        Err(-5) // EIO
    }
}

/// Global null address space ops instance
pub static NULL_AOPS: NullAddressSpaceOps = NullAddressSpaceOps;

/// Block device address space operations for disk-backed filesystems.
///
/// Used by filesystems like VFAT that store data on block devices.
/// This implementation looks up the block device from the global registry
/// using the major/minor encoded in the FileId.
pub struct BlkdevAddressSpaceOps;

impl AddressSpaceOps for BlkdevAddressSpaceOps {
    fn readpage(&self, file_id: FileId, page_offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        use crate::storage::{BLKDEV_REGISTRY, DevId};

        // Extract major/minor from FileId
        // Format: 0x8000_0000_0000_0000 | (major << 20) | minor
        let encoded = file_id.0 & 0x7FFF_FFFF_FFFF_FFFF;
        let major = ((encoded >> 20) & 0xFFFF) as u16;
        let minor = (encoded & 0xFFFFF) as u16;

        // Look up the block device
        let dev_id = DevId { major, minor };
        let bdev = BLKDEV_REGISTRY.read().get(dev_id).ok_or(-5i32)?; // EIO if device not found

        // Read the page from the block device
        bdev.disk
            .queue
            .driver()
            .readpage(&bdev.disk, buf.as_ptr() as u64, page_offset);

        Ok(buf.len())
    }

    fn writepage(&self, file_id: FileId, page_offset: u64, buf: &[u8]) -> Result<usize, i32> {
        use crate::storage::{BLKDEV_REGISTRY, DevId};

        // Extract major/minor from FileId
        let encoded = file_id.0 & 0x7FFF_FFFF_FFFF_FFFF;
        let major = ((encoded >> 20) & 0xFFFF) as u16;
        let minor = (encoded & 0xFFFFF) as u16;

        // Look up the block device
        let dev_id = DevId { major, minor };
        let bdev = BLKDEV_REGISTRY.read().get(dev_id).ok_or(-5i32)?; // EIO if device not found

        // Write the page to the block device
        bdev.disk
            .queue
            .driver()
            .writepage(&bdev.disk, buf.as_ptr() as u64, page_offset);

        Ok(buf.len())
    }
}

/// Global block device address space ops instance
pub static BLKDEV_AOPS: BlkdevAddressSpaceOps = BlkdevAddressSpaceOps;

/// A single cached page
///
/// Each page has its own lock (similar to Linux's PG_locked) for synchronizing
/// access to page contents during I/O operations.
pub struct CachedPage {
    /// Physical frame address holding the page data
    pub frame: u64,

    /// Reference count (number of mappings using this page)
    refcount: AtomicU32,

    /// File identifier this page belongs to
    pub file_id: FileId,

    /// Page offset within the file (in PAGE_SIZE units)
    pub page_offset: u64,

    /// Whether this page has been modified since last sync
    /// Dirty pages without writeback capability cannot be evicted.
    dirty: AtomicBool,

    /// Per-page lock for synchronizing access to page contents.
    /// Similar to Linux's PG_locked bit / folio_lock().
    /// Must be held when reading from or writing to the page frame.
    locked: AtomicBool,
}

impl CachedPage {
    /// Create a new cached page (initially clean and unlocked)
    pub fn new(frame: u64, file_id: FileId, page_offset: u64) -> Self {
        Self {
            frame,
            refcount: AtomicU32::new(1),
            file_id,
            page_offset,
            dirty: AtomicBool::new(false),
            locked: AtomicBool::new(false),
        }
    }

    /// Create a new cached page marked as dirty (initially unlocked)
    pub fn new_dirty(frame: u64, file_id: FileId, page_offset: u64) -> Self {
        Self {
            frame,
            refcount: AtomicU32::new(1),
            file_id,
            page_offset,
            dirty: AtomicBool::new(true),
            locked: AtomicBool::new(false),
        }
    }

    /// Increment reference count and return the frame address
    ///
    /// Uses AcqRel ordering to ensure visibility of page data after increment.
    pub fn get(&self) -> u64 {
        self.refcount.fetch_add(1, Ordering::AcqRel);
        self.frame
    }

    /// Decrement reference count, returns new count
    ///
    /// Uses Release ordering to ensure all modifications are visible before
    /// the reference is dropped.
    pub fn put(&self) -> u32 {
        let old = self.refcount.fetch_sub(1, Ordering::Release);
        old.saturating_sub(1)
    }

    /// Get current reference count
    ///
    /// Uses Acquire ordering to synchronize with Release in put().
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Attempt to claim this page for eviction.
    ///
    /// Uses compare-and-swap to atomically check if refcount is 0 and set it
    /// to a sentinel value (u32::MAX) to prevent concurrent get() calls from
    /// succeeding. This prevents the race where eviction sees refcount==0 but
    /// another CPU is about to increment it.
    ///
    /// Returns true if successfully claimed, false if page is in use.
    pub fn try_claim_for_eviction(&self) -> bool {
        self.refcount
            .compare_exchange(0, u32::MAX, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Release a previously claimed eviction.
    ///
    /// Called when eviction fails (e.g., writeback error) and we need to
    /// put the page back in the queue. Resets the sentinel value back to 0
    /// so the page can be used again.
    pub fn unclaim_eviction(&self) {
        // Only reset if we actually have the sentinel value
        let _ = self
            .refcount
            .compare_exchange(u32::MAX, 0, Ordering::AcqRel, Ordering::Relaxed);
    }

    /// Lock the page for exclusive access to its contents.
    ///
    /// This implements Linux's folio_lock() behavior: if the page is already
    /// locked, the task sleeps on a wait queue until it can acquire the lock.
    /// This is more efficient than spinning and allows other tasks to run.
    ///
    /// If scheduling is not yet enabled (early boot), falls back to spinning.
    #[inline]
    pub fn lock(&self) {
        use crate::task::percpu::SCHEDULING_ENABLED;
        use crate::waitqueue::page_wait_queue;

        // Fast path: try to acquire immediately
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }

        // Slow path: if scheduling enabled, sleep on wait queue
        if SCHEDULING_ENABLED.load(Ordering::Acquire) {
            // Get the wait queue for this page (hashed by frame address)
            let wq = page_wait_queue(self.frame);

            // Wait until we can acquire the lock
            loop {
                // Try to acquire lock
                if self
                    .locked
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }

                // Sleep on wait queue
                wq.wait();

                // When woken, try again (loop back to check lock)
            }
        } else {
            // Scheduling not enabled - fall back to spinning
            while self
                .locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
        }
    }

    /// Unlock the page.
    ///
    /// Must be called after lock() when done accessing page contents.
    /// Wakes one waiter if any tasks are sleeping on this page's wait queue.
    #[inline]
    pub fn unlock(&self) {
        use crate::task::percpu::SCHEDULING_ENABLED;
        use crate::waitqueue::page_wait_queue;

        // Release the lock
        self.locked.store(false, Ordering::Release);

        // Wake one waiter if scheduling is enabled
        if SCHEDULING_ENABLED.load(Ordering::Acquire) {
            let wq = page_wait_queue(self.frame);
            wq.wake_one();
        }
    }

    /// Try to lock the page without waiting.
    ///
    /// Returns true if the lock was acquired, false if the page is already locked.
    /// Useful when you need to try multiple pages or cannot block.
    #[inline]
    pub fn trylock(&self) -> bool {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Check if the page is currently locked.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Acquire)
    }

    /// Mark this page as dirty (modified)
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    /// Mark this page as clean (synced to backing store)
    pub fn mark_clean(&self) {
        self.dirty.store(false, Ordering::Release);
    }

    /// Check if this page is dirty
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }
}

/// Internal mutable state of an AddressSpace, protected by the inner RwLock.
struct AddressSpaceInner {
    /// Cached pages indexed by page offset
    pages: BTreeMap<u64, Arc<CachedPage>>,

    /// Total size of the file in bytes
    file_size: u64,

    /// Whether dirty pages can be written back to backing store.
    /// If false (e.g., ramfs), dirty pages are NEVER evicted.
    /// If true (e.g., ext4), dirty pages can be written back then evicted.
    can_writeback: bool,

    /// Whether pages in this address space are unevictable.
    /// If true, pages are NEVER evicted regardless of dirty state.
    /// Used for ramfs where the page cache IS the only storage.
    unevictable: bool,
}

/// Per-file page cache container (analogous to Linux's address_space)
///
/// Each AddressSpace has its own lock, allowing concurrent access to pages
/// from different files. This follows the Linux model where each file has
/// its own `address_space` with an XArray (`i_pages`) containing its pages.
///
/// The locking hierarchy for page cache operations:
/// 1. PageCache.address_spaces (global RwLock) - to find/create AddressSpace
/// 2. AddressSpace.inner (per-file RwLock) - to access pages within a file
/// 3. AddressSpace.invalidate_lock - for truncate/fault serialization
/// 4. CachedPage.lock() - for page contents access
/// 5. a_ops callbacks (filesystem-specific locks)
pub struct AddressSpace {
    /// File identifier (immutable after creation)
    pub file_id: FileId,

    /// Protected mutable state
    inner: RwLock<AddressSpaceInner>,

    /// Lock for serializing invalidation (truncate) with page filling (fault/read).
    /// Like Linux's `mapping->invalidate_lock`.
    ///
    /// - Read path (fault, read): hold shared
    /// - Truncate/invalidate path: hold exclusive
    ///
    /// This prevents races where truncate removes pages while fault is
    /// trying to read them.
    pub invalidate_lock: RwLock<()>,

    /// Address space operations (filesystem-specific I/O).
    /// Analogous to Linux's `a_ops` pointer in `struct address_space`.
    ///
    /// These callbacks are invoked for page I/O with only the per-page lock held.
    /// The PAGE_CACHE global mutex and AddressSpace.inner are NOT held when
    /// these are called, so implementations must not try to acquire them.
    pub a_ops: &'static dyn AddressSpaceOps,
}

impl AddressSpace {
    /// Create a new address space for a file
    ///
    /// # Arguments
    /// * `file_id` - Unique identifier for this file
    /// * `file_size` - Total size of the file in bytes
    /// * `can_writeback` - Whether dirty pages can be written to backing store.
    ///   Set to `false` for ramfs (pages are never evictable when dirty).
    ///   Set to `true` for disk-backed filesystems.
    /// * `unevictable` - Whether pages are completely unevictable regardless of state.
    ///   Set to `true` for ramfs where page cache IS the storage.
    ///   Set to `false` for disk-backed filesystems.
    /// * `a_ops` - Address space operations for filesystem-specific I/O
    pub fn new(
        file_id: FileId,
        file_size: u64,
        can_writeback: bool,
        unevictable: bool,
        a_ops: &'static dyn AddressSpaceOps,
    ) -> Self {
        Self {
            file_id,
            inner: RwLock::new(AddressSpaceInner {
                pages: BTreeMap::new(),
                file_size,
                can_writeback,
                unevictable,
            }),
            invalidate_lock: RwLock::new(()),
            a_ops,
        }
    }

    /// Check if this address space supports writeback
    pub fn can_writeback(&self) -> bool {
        self.inner.read().can_writeback
    }

    /// Check if this address space is unevictable (pages never evicted)
    pub fn is_unevictable(&self) -> bool {
        self.inner.read().unevictable
    }

    /// Find a page at the given offset
    pub fn find_page(&self, page_offset: u64) -> Option<Arc<CachedPage>> {
        self.inner.read().pages.get(&page_offset).cloned()
    }

    /// Insert a new page
    pub fn insert_page(&self, page_offset: u64, page: Arc<CachedPage>) {
        self.inner.write().pages.insert(page_offset, page);
    }

    /// Remove a page (for eviction)
    pub fn remove_page(&self, page_offset: u64) -> Option<Arc<CachedPage>> {
        self.inner.write().pages.remove(&page_offset)
    }

    /// Number of cached pages
    pub fn page_count(&self) -> usize {
        self.inner.read().pages.len()
    }

    /// Get file size
    pub fn file_size(&self) -> u64 {
        self.inner.read().file_size
    }

    /// Set file size (for truncate operations)
    pub fn set_file_size(&self, new_size: u64) {
        self.inner.write().file_size = new_size;
    }

    /// Sync all dirty pages to backing store.
    ///
    /// Writes all dirty pages in this address space to their backing store
    /// using the `a_ops.writepage()` callback. Used to implement fsync.
    ///
    /// ## Locking Context
    ///
    /// - Acquires AddressSpace.inner read lock briefly to collect dirty pages
    /// - Releases inner lock before I/O (to allow concurrent reads)
    /// - Acquires per-page lock during each writepage call
    /// - Does NOT hold PAGE_CACHE lock (caller should not hold it)
    ///
    /// ## Returns
    ///
    /// - `Ok(count)` - Number of pages written back
    /// - `Err(errno)` - First error encountered during writeback
    pub fn sync_pages(&self) -> Result<usize, i32> {
        // Step 1: Check if writeback is even possible and collect dirty pages
        // We clone the Arc to increment refcount, ensuring pages aren't
        // evicted while we're iterating
        let dirty_pages: alloc::vec::Vec<(u64, Arc<CachedPage>)> = {
            let inner = self.inner.read();

            // If writeback is disabled (e.g., ramfs), there's nothing to sync.
            // The page cache IS the storage, so dirty pages are already "persisted".
            if !inner.can_writeback {
                return Ok(0);
            }

            inner
                .pages
                .iter()
                .filter(|(_, p)| p.is_dirty())
                .map(|(off, p)| (*off, p.clone()))
                .collect()
        };
        // inner lock released here

        if dirty_pages.is_empty() {
            return Ok(0);
        }

        // Step 2: Write each page (no AddressSpace lock held)
        let mut written = 0;
        for (page_offset, page) in dirty_pages {
            // Lock the page for I/O (per-page lock)
            page.lock();

            // Copy page content to temporary buffer
            let mut buf = [0u8; PAGE_SIZE];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    page.frame as *const u8,
                    buf.as_mut_ptr(),
                    PAGE_SIZE,
                );
            }

            // Call filesystem writepage
            // a_ops.writepage is called with only per-page lock held
            let result = self.a_ops.writepage(self.file_id, page_offset, &buf);

            match result {
                Ok(_) => {
                    page.mark_clean();
                    page.unlock();
                    written += 1;
                }
                Err(errno) => {
                    page.unlock();
                    // Return first error, but page remains dirty for retry
                    return Err(errno);
                }
            }
        }

        Ok(written)
    }
}

/// Page cache error types
#[derive(Debug)]
pub enum PageCacheError {
    /// Out of physical memory
    OutOfMemory,
    /// All cached pages are in use (cannot evict)
    AllPagesInUse,
    /// Page offset out of bounds
    OutOfBounds,
}

/// Cache key for looking up pages
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PageCacheKey {
    file_id: FileId,
    page_offset: u64,
}

/// FIFO eviction queue entry
struct FifoEntry {
    key: PageCacheKey,
    page: Arc<CachedPage>,
}

/// Global page cache
///
/// The PageCache uses a hierarchical locking strategy:
/// - Global RwLock on address_spaces map for finding/creating AddressSpace objects
/// - Per-AddressSpace RwLock for page operations within a file
/// - Per-page lock for page content access
///
/// This allows concurrent access to different files without contention.
pub struct PageCache {
    /// All address spaces, indexed by FileId.
    /// Using Arc<AddressSpace> allows us to get a reference and release
    /// the outer lock quickly, enabling concurrent access to different files.
    address_spaces: BTreeMap<FileId, Arc<AddressSpace>>,

    /// FIFO eviction queue (oldest at front)
    fifo_queue: VecDeque<FifoEntry>,

    /// Maximum number of pages to cache
    max_pages: usize,

    /// Current number of cached pages
    current_pages: AtomicUsize,
}

impl PageCache {
    /// Create a new page cache with the given maximum size
    pub const fn new(max_pages: usize) -> Self {
        Self {
            address_spaces: BTreeMap::new(),
            fifo_queue: VecDeque::new(),
            max_pages,
            current_pages: AtomicUsize::new(0),
        }
    }

    /// Get or create an address space for a file
    ///
    /// Returns an Arc to the AddressSpace, which can be used after releasing
    /// the PageCache lock. This enables concurrent access to different files.
    ///
    /// # Arguments
    /// * `file_id` - Unique identifier for this file
    /// * `file_size` - Total size of the file in bytes
    /// * `can_writeback` - Whether dirty pages can be written back.
    ///   Only used when creating a new address space.
    /// * `a_ops` - Address space operations for filesystem-specific I/O.
    ///   Only used when creating a new address space.
    pub fn get_or_create_address_space(
        &mut self,
        file_id: FileId,
        file_size: u64,
        can_writeback: bool,
        unevictable: bool,
        a_ops: &'static dyn AddressSpaceOps,
    ) -> Arc<AddressSpace> {
        self.address_spaces
            .entry(file_id)
            .or_insert_with(|| {
                Arc::new(AddressSpace::new(
                    file_id,
                    file_size,
                    can_writeback,
                    unevictable,
                    a_ops,
                ))
            })
            .clone()
    }

    /// Look up a page in the cache (increments refcount if found)
    pub fn find_get_page(&self, file_id: FileId, page_offset: u64) -> Option<Arc<CachedPage>> {
        let addr_space = self.address_spaces.get(&file_id)?;
        let page = addr_space.find_page(page_offset)?;
        page.get(); // Increment refcount
        Some(page)
    }

    /// Atomically find or create a page in the cache.
    ///
    /// This method fixes the TOCTOU (time-of-check to time-of-use) race that
    /// occurs when using separate find_get_page() and add_page() calls:
    ///
    /// ```text
    /// Thread A: find_get_page() -> None
    /// Thread B: find_get_page() -> None
    /// Thread A: add_page() -> creates page
    /// Thread B: add_page() -> creates DUPLICATE page (BUG!)
    /// ```
    ///
    /// By keeping the lock held across the entire find-or-create operation,
    /// we guarantee that only one page exists for each (file_id, page_offset).
    ///
    /// # Returns
    /// - `Ok((page, true))` if a new page was created
    /// - `Ok((page, false))` if an existing page was found
    /// - `Err(...)` if allocation failed
    #[allow(clippy::too_many_arguments)]
    pub fn find_or_create_page<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        file_id: FileId,
        page_offset: u64,
        file_size: u64,
        frame_alloc: &mut FA,
        can_writeback: bool,
        unevictable: bool,
        a_ops: &'static dyn AddressSpaceOps,
    ) -> Result<(Arc<CachedPage>, bool), PageCacheError> {
        // Check if page already exists (with lock held the entire time)
        if let Some(page) = self.find_get_page(file_id, page_offset) {
            return Ok((page, false)); // false = not newly created
        }

        // Page doesn't exist - create it (still under lock)
        let page = self.add_page_zeroed(
            file_id,
            page_offset,
            file_size,
            frame_alloc,
            can_writeback,
            unevictable,
            a_ops,
        )?;

        Ok((page, true)) // true = newly created
    }

    /// Add a page to the cache
    ///
    /// Allocates a frame, copies data from file_data, and inserts into cache.
    /// May evict pages if cache is full.
    ///
    /// # Arguments
    /// * `file_id` - Unique identifier for this file
    /// * `page_offset` - Page offset within the file (in PAGE_SIZE units)
    /// * `file_data` - Source data to copy from
    /// * `file_size` - Total size of the file in bytes
    /// * `frame_alloc` - Frame allocator for allocating physical memory
    /// * `can_writeback` - Whether this file's dirty pages can be written back.
    ///   Set to `false` for ramfs (dirty pages never evicted).
    ///   Set to `true` for disk-backed filesystems.
    /// * `unevictable` - Whether pages are completely unevictable regardless of state.
    ///   Set to `true` for ramfs where page cache IS the storage.
    /// * `a_ops` - Address space operations for filesystem-specific I/O
    #[allow(clippy::too_many_arguments)]
    pub fn add_page<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        file_id: FileId,
        page_offset: u64,
        file_data: &[u8],
        file_size: u64,
        frame_alloc: &mut FA,
        can_writeback: bool,
        unevictable: bool,
        a_ops: &'static dyn AddressSpaceOps,
    ) -> Result<Arc<CachedPage>, PageCacheError> {
        // Check if we need to evict
        if self.current_pages.load(Ordering::Relaxed) >= self.max_pages {
            self.evict_one(frame_alloc)?;
        }

        // Allocate frame
        let frame = frame_alloc
            .alloc_frame()
            .ok_or(PageCacheError::OutOfMemory)?;

        // Copy data to frame
        unsafe {
            // Zero the frame first (important for partial pages and BSS)
            ::core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE);

            // Calculate how much data to copy
            let file_offset = page_offset * PAGE_SIZE as u64;
            if file_offset < file_data.len() as u64 {
                let copy_len = ::core::cmp::min(PAGE_SIZE, file_data.len() - file_offset as usize);
                ::core::ptr::copy_nonoverlapping(
                    file_data.as_ptr().add(file_offset as usize),
                    frame as *mut u8,
                    copy_len,
                );
            }
        }

        // Create cached page
        let page = Arc::new(CachedPage::new(frame, file_id, page_offset));

        // Insert into address space (AddressSpace has internal locking)
        let addr_space =
            self.get_or_create_address_space(file_id, file_size, can_writeback, unevictable, a_ops);
        addr_space.insert_page(page_offset, page.clone());

        // Add to FIFO queue
        self.fifo_queue.push_back(FifoEntry {
            key: PageCacheKey {
                file_id,
                page_offset,
            },
            page: page.clone(),
        });

        self.current_pages.fetch_add(1, Ordering::Relaxed);

        Ok(page)
    }

    /// Release a page reference (decrements refcount)
    pub fn put_page(&self, page: &Arc<CachedPage>) {
        page.put();
    }

    /// Evict one page from the cache (FIFO policy)
    ///
    /// Finds the oldest evictable page and frees it.
    ///
    /// A page is evictable if:
    /// - refcount == 0 (not currently in use), AND
    /// - page is clean, OR the address space supports writeback
    ///
    /// Dirty pages in non-writeback address spaces (e.g., ramfs) are
    /// NEVER evicted to prevent data loss.
    ///
    /// For dirty pages with writeback enabled, calls `a_ops.writepage()`
    /// to flush the page to backing store before evicting.
    ///
    /// ## Locking Context
    ///
    /// - Called with PAGE_CACHE lock held (self)
    /// - Acquires per-page lock during writeback
    /// - `a_ops.writepage()` is called with PAGE_CACHE held but this is safe
    ///   because a_ops must not acquire PAGE_CACHE (would deadlock)
    ///
    /// Uses compare-and-swap to atomically claim pages for eviction,
    /// preventing races with concurrent get() operations.
    fn evict_one<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        frame_alloc: &mut FA,
    ) -> Result<(), PageCacheError> {
        let max_attempts = self.fifo_queue.len();
        let mut attempts = 0;

        while attempts < max_attempts {
            if let Some(entry) = self.fifo_queue.pop_front() {
                // Check if address space is unevictable (ramfs pages are NEVER evicted)
                if let Some(addr_space) = self.address_spaces.get(&entry.key.file_id)
                    && addr_space.is_unevictable()
                {
                    // Unevictable pages are never evicted, move to back
                    self.fifo_queue.push_back(entry);
                    attempts += 1;
                    continue;
                }

                // Check dirty status and get address space info
                let (can_evict, needs_writeback, a_ops) = if entry.page.is_dirty() {
                    // Dirty page: only evict if writeback is possible
                    if let Some(addr_space) = self.address_spaces.get(&entry.key.file_id) {
                        if addr_space.can_writeback() {
                            (true, true, Some(addr_space.a_ops))
                        } else {
                            // Dirty page without writeback = never evict
                            (false, false, None)
                        }
                    } else {
                        (false, false, None)
                    }
                } else {
                    // Clean page: always evictable, no writeback needed
                    (true, false, None)
                };

                if !can_evict {
                    // Cannot evict dirty page without writeback, move to back
                    self.fifo_queue.push_back(entry);
                    attempts += 1;
                    continue;
                }

                // Try to atomically claim the page for eviction
                // This uses CAS to prevent race with concurrent get()
                if !entry.page.try_claim_for_eviction() {
                    // Page is in use, move to back of queue
                    self.fifo_queue.push_back(entry);
                    attempts += 1;
                    continue;
                }

                // Perform writeback if needed
                if needs_writeback && let Some(a_ops) = a_ops {
                    // Lock the page for I/O
                    entry.page.lock();

                    // Copy page content to temporary buffer
                    let mut buf = [0u8; PAGE_SIZE];
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            entry.page.frame as *const u8,
                            buf.as_mut_ptr(),
                            PAGE_SIZE,
                        );
                    }

                    // Call filesystem writepage
                    // Note: a_ops must not acquire PAGE_CACHE (would deadlock)
                    let result = a_ops.writepage(entry.key.file_id, entry.key.page_offset, &buf);

                    entry.page.unlock();

                    if result.is_err() {
                        // Writeback failed, put page back in queue
                        // Reset the claim (allow future attempts)
                        entry.page.unclaim_eviction();
                        self.fifo_queue.push_back(entry);
                        attempts += 1;
                        continue;
                    }

                    // Mark page clean after successful writeback
                    entry.page.mark_clean();
                }

                // Successfully claimed and (if needed) written back - evict
                if let Some(addr_space) = self.address_spaces.get(&entry.key.file_id) {
                    addr_space.remove_page(entry.key.page_offset);
                }
                frame_alloc.free_frame(entry.page.frame);
                self.current_pages.fetch_sub(1, Ordering::Relaxed);
                return Ok(());
            }
            attempts += 1;
        }

        Err(PageCacheError::AllPagesInUse)
    }

    /// Get cache statistics
    pub fn stats(&self) -> (usize, usize) {
        (self.current_pages.load(Ordering::Relaxed), self.max_pages)
    }

    /// Add a zeroed page to the cache (for block device reads)
    ///
    /// Allocates a frame, zeros it, and inserts into cache.
    /// Used when populating pages for block devices.
    ///
    /// # Arguments
    /// * `file_id` - Unique identifier for this file/device
    /// * `page_offset` - Page offset within the file (in PAGE_SIZE units)
    /// * `file_size` - Total size of the file/device in bytes
    /// * `frame_alloc` - Frame allocator for allocating physical memory
    /// * `can_writeback` - Whether dirty pages can be written back
    /// * `unevictable` - Whether pages are completely unevictable regardless of state.
    ///   Set to `true` for ramfs where page cache IS the storage.
    /// * `a_ops` - Address space operations for filesystem-specific I/O
    #[allow(clippy::too_many_arguments)]
    pub fn add_page_zeroed<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        file_id: FileId,
        page_offset: u64,
        file_size: u64,
        frame_alloc: &mut FA,
        can_writeback: bool,
        unevictable: bool,
        a_ops: &'static dyn AddressSpaceOps,
    ) -> Result<Arc<CachedPage>, PageCacheError> {
        // Check if we need to evict
        if self.current_pages.load(Ordering::Relaxed) >= self.max_pages {
            self.evict_one(frame_alloc)?;
        }

        // Allocate frame
        let frame = frame_alloc
            .alloc_frame()
            .ok_or(PageCacheError::OutOfMemory)?;

        // Zero the frame
        unsafe {
            ::core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE);
        }

        // Create cached page
        let page = Arc::new(CachedPage::new(frame, file_id, page_offset));

        // Insert into address space (AddressSpace has internal locking)
        let addr_space =
            self.get_or_create_address_space(file_id, file_size, can_writeback, unevictable, a_ops);
        addr_space.insert_page(page_offset, page.clone());

        // Add to FIFO queue
        self.fifo_queue.push_back(FifoEntry {
            key: PageCacheKey {
                file_id,
                page_offset,
            },
            page: page.clone(),
        });

        self.current_pages.fetch_add(1, Ordering::Relaxed);

        Ok(page)
    }

    /// Get an address space if it exists
    pub fn get_address_space(&self, file_id: FileId) -> Option<Arc<AddressSpace>> {
        self.address_spaces.get(&file_id).cloned()
    }

    /// Get all address spaces (for sync)
    ///
    /// Returns a snapshot of all address spaces. The caller can then sync each
    /// without holding the PageCache lock.
    pub fn get_all_address_spaces(&self) -> alloc::vec::Vec<Arc<AddressSpace>> {
        self.address_spaces.values().cloned().collect()
    }

    /// Invalidate all pages for a block device (hotplug removal)
    ///
    /// Removes the address space and all cached pages for the given block device.
    /// Frees the physical frames used by those pages.
    ///
    /// Note: The caller should ensure no concurrent access to this device's pages
    /// (e.g., by acquiring the AddressSpace's invalidate_lock exclusively before
    /// calling this function, if the AddressSpace still exists).
    ///
    /// # Arguments
    /// * `major` - Block device major number
    /// * `minor` - Block device minor number
    /// * `frame_alloc` - Frame allocator for freeing physical frames
    ///
    /// # Returns
    /// Number of pages that were invalidated
    pub fn invalidate_blkdev<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        major: u16,
        minor: u16,
        frame_alloc: &mut FA,
    ) -> usize {
        let file_id = FileId::from_blkdev(major, minor);

        // Remove the address space (this drops all page references in it)
        let removed_space = self.address_spaces.remove(&file_id);

        // Count pages we're about to remove
        let page_count = removed_space.as_ref().map(|a| a.page_count()).unwrap_or(0);

        if page_count == 0 {
            return 0;
        }

        // Remove matching entries from FIFO queue and free their frames
        let mut new_queue = VecDeque::with_capacity(self.fifo_queue.len());
        let mut freed_count = 0;

        while let Some(entry) = self.fifo_queue.pop_front() {
            if entry.key.file_id == file_id {
                // Free the frame for this page
                frame_alloc.free_frame(entry.page.frame);
                freed_count += 1;
            } else {
                // Keep this entry
                new_queue.push_back(entry);
            }
        }

        self.fifo_queue = new_queue;
        // Use atomic subtract, clamping to 0 if underflow would occur
        let old = self.current_pages.load(Ordering::Relaxed);
        self.current_pages
            .store(old.saturating_sub(freed_count), Ordering::Relaxed);

        freed_count
    }

    /// Truncate pages for a file beyond the given offset
    ///
    /// Removes all pages at or beyond `from_page_offset` for the given file.
    /// Used when truncating a file to a smaller size.
    ///
    /// # Arguments
    /// * `file_id` - Unique identifier for the file
    /// * `from_page_offset` - First page offset to remove (pages >= this are removed)
    /// * `frame_alloc` - Frame allocator for freeing physical frames
    ///
    /// # Returns
    /// Number of pages that were freed
    pub fn truncate_pages<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        file_id: FileId,
        from_page_offset: u64,
        frame_alloc: &mut FA,
    ) -> usize {
        let addr_space = match self.address_spaces.get(&file_id) {
            Some(a) => a.clone(),
            None => return 0,
        };

        // Collect page offsets to remove (those >= from_page_offset)
        let pages_to_remove: alloc::vec::Vec<u64> = {
            let inner = addr_space.inner.read();
            inner
                .pages
                .keys()
                .filter(|&&offset| offset >= from_page_offset)
                .cloned()
                .collect()
        };

        if pages_to_remove.is_empty() {
            return 0;
        }

        // Remove pages from address space
        for &offset in &pages_to_remove {
            addr_space.remove_page(offset);
        }

        // Remove from FIFO queue and free frames
        let mut new_queue = VecDeque::with_capacity(self.fifo_queue.len());
        let mut freed_count = 0;

        while let Some(entry) = self.fifo_queue.pop_front() {
            if entry.key.file_id == file_id && entry.key.page_offset >= from_page_offset {
                // Free the frame for this page
                frame_alloc.free_frame(entry.page.frame);
                freed_count += 1;
            } else {
                // Keep this entry
                new_queue.push_back(entry);
            }
        }

        self.fifo_queue = new_queue;
        let old = self.current_pages.load(Ordering::Relaxed);
        self.current_pages
            .store(old.saturating_sub(freed_count), Ordering::Relaxed);

        freed_count
    }

    /// Invalidate all pages for a file (used when file is unlinked/deleted)
    ///
    /// Removes the address space and all cached pages for the given file.
    /// Frees the physical frames used by those pages.
    ///
    /// # Arguments
    /// * `file_id` - Unique identifier for the file
    /// * `frame_alloc` - Frame allocator for freeing physical frames
    ///
    /// # Returns
    /// Number of pages that were freed
    pub fn invalidate_file<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        file_id: FileId,
        frame_alloc: &mut FA,
    ) -> usize {
        // Remove the address space
        let removed_space = self.address_spaces.remove(&file_id);

        let page_count = removed_space.as_ref().map(|a| a.page_count()).unwrap_or(0);

        if page_count == 0 {
            return 0;
        }

        // Remove matching entries from FIFO queue and free their frames
        let mut new_queue = VecDeque::with_capacity(self.fifo_queue.len());
        let mut freed_count = 0;

        while let Some(entry) = self.fifo_queue.pop_front() {
            if entry.key.file_id == file_id {
                // Free the frame for this page
                frame_alloc.free_frame(entry.page.frame);
                freed_count += 1;
            } else {
                // Keep this entry
                new_queue.push_back(entry);
            }
        }

        self.fifo_queue = new_queue;
        let old = self.current_pages.load(Ordering::Relaxed);
        self.current_pages
            .store(old.saturating_sub(freed_count), Ordering::Relaxed);

        freed_count
    }
}

// ============================================================================
// In-kernel self-tests (temporary - remove after verification)
// ============================================================================

/// Test reference counting correctness
#[allow(dead_code)]
pub fn test_refcount_ordering() {
    use crate::printkln;

    let file_id = FileId::new(0xDEADBEEF);
    let page = CachedPage::new(0x1000, file_id, 0);

    // Initial refcount should be 1
    assert_eq!(page.refcount(), 1, "Initial refcount should be 1");

    // get() should increment to 2
    let _ = page.get();
    assert_eq!(page.refcount(), 2, "Refcount after get() should be 2");

    // put() should decrement to 1
    page.put();
    assert_eq!(page.refcount(), 1, "Refcount after put() should be 1");

    // Cannot claim for eviction while refcount > 0
    assert!(
        !page.try_claim_for_eviction(),
        "Should not claim page with refcount > 0"
    );

    // After final put, refcount is 0
    page.put();
    assert_eq!(
        page.refcount(),
        0,
        "Refcount after second put() should be 0"
    );

    // Now can claim for eviction
    assert!(
        page.try_claim_for_eviction(),
        "Should claim page with refcount == 0"
    );

    // Refcount is now u32::MAX (sentinel)
    assert_eq!(
        page.refcount(),
        u32::MAX,
        "Refcount after claim should be sentinel"
    );

    printkln!("PASS: test_refcount_ordering");
}

/// Test page lock correctness
#[allow(dead_code)]
pub fn test_page_lock() {
    use crate::printkln;

    let file_id = FileId::new(0xCAFEBABE);
    let page = CachedPage::new(0x2000, file_id, 0);

    // Initially unlocked
    assert!(!page.is_locked(), "Page should start unlocked");

    // Lock should succeed
    page.lock();
    assert!(page.is_locked(), "Page should be locked after lock()");

    // trylock should fail while locked
    assert!(!page.trylock(), "trylock should fail on locked page");

    // Unlock
    page.unlock();
    assert!(!page.is_locked(), "Page should be unlocked after unlock()");

    // trylock should succeed now
    assert!(page.trylock(), "trylock should succeed on unlocked page");
    page.unlock();

    printkln!("PASS: test_page_lock");
}

/// Test dirty flag
#[allow(dead_code)]
pub fn test_dirty_flag() {
    use crate::printkln;

    let file_id = FileId::new(0x12345678);
    let page = CachedPage::new(0x3000, file_id, 0);

    // Initially clean
    assert!(!page.is_dirty(), "Page should start clean");

    // Mark dirty
    page.mark_dirty();
    assert!(page.is_dirty(), "Page should be dirty after mark_dirty()");

    // Mark clean
    page.mark_clean();
    assert!(!page.is_dirty(), "Page should be clean after mark_clean()");

    printkln!("PASS: test_dirty_flag");
}

/// Run all page cache self-tests
#[allow(dead_code)]
pub fn run_self_tests() {
    test_refcount_ordering();
    test_page_lock();
    test_dirty_flag();
}
