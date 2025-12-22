//! Writeback infrastructure for dirty page flushing
//!
//! This module provides:
//! - `WritebackControl` - Parameters controlling writeback operations
//! - `do_writepages` - Write dirty pages for a single file
//! - `writeback_all` - Write dirty pages for all files
//! - `BdiWriteback` - Per-device writeback state with workqueue scheduling
//!
//! ## Architecture
//!
//! Unlike the old timer-interrupt approach, writeback now uses the workqueue
//! subsystem. Each block device has a `BdiWriteback` structure that schedules
//! delayed work items to flush dirty pages periodically.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::{Mutex, RwLock};

use crate::PAGE_CACHE;
use crate::mm::page_cache::{AddressSpace, DIRTY_ADDRESS_SPACES, FileId, PAGE_SIZE};
use crate::storage::blkdev::DevId;
use crate::workqueue::{DelayedWork, Workqueue, wq_flags};

// ============================================================================
// Writeback Constants
// ============================================================================

/// Writeback interval in timer ticks (500 ticks = ~5 seconds at 100Hz)
pub const WRITEBACK_INTERVAL_TICKS: u64 = 500;

/// Pages to write per periodic writeback run
pub const WRITEBACK_BATCH_SIZE: i64 = 128;

// ============================================================================
// WritebackControl
// ============================================================================

/// Writeback synchronization modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritebackSyncMode {
    /// Asynchronous - don't wait for I/O completion (background writeback)
    None,
    /// Synchronous - wait for all I/O to complete (fsync)
    All,
}

/// Parameters controlling writeback operations
///
/// Similar to Linux's `struct writeback_control`. Controls how many pages
/// to write and whether to wait for completion.
pub struct WritebackControl {
    /// Number of pages remaining to write (decremented as pages are written)
    /// Use i64::MAX for "write everything"
    pub nr_to_write: i64,

    /// Synchronization mode
    pub sync_mode: WritebackSyncMode,

    /// Whether this is from sync(2) syscall
    pub for_sync: bool,

    /// Whether this is from periodic (kupdate-style) writeback
    pub for_kupdate: bool,

    /// Whether this is from memory pressure (background reclaim)
    pub for_background: bool,

    /// Byte range start (for ranged fsync)
    pub range_start: u64,

    /// Byte range end (for ranged fsync)
    pub range_end: u64,

    /// Number of pages written (output)
    pub pages_written: usize,

    /// Number of pages skipped (output)
    pub pages_skipped: usize,
}

impl Default for WritebackControl {
    fn default() -> Self {
        Self {
            nr_to_write: i64::MAX,
            sync_mode: WritebackSyncMode::None,
            for_sync: false,
            for_kupdate: false,
            for_background: false,
            range_start: 0,
            range_end: u64::MAX,
            pages_written: 0,
            pages_skipped: 0,
        }
    }
}

impl WritebackControl {
    /// Create a WritebackControl for fsync (synchronous, entire file)
    pub fn for_fsync() -> Self {
        Self {
            sync_mode: WritebackSyncMode::All,
            for_sync: true,
            ..Default::default()
        }
    }

    /// Create a WritebackControl for sync (synchronous, all files)
    pub fn for_sync() -> Self {
        Self {
            sync_mode: WritebackSyncMode::All,
            for_sync: true,
            ..Default::default()
        }
    }

    /// Create a WritebackControl for periodic (kupdate) writeback
    pub fn for_kupdate(nr_pages: i64) -> Self {
        Self {
            nr_to_write: nr_pages,
            sync_mode: WritebackSyncMode::None,
            for_kupdate: true,
            ..Default::default()
        }
    }

    /// Create a WritebackControl for background (memory pressure) writeback
    pub fn for_background(nr_pages: i64) -> Self {
        Self {
            nr_to_write: nr_pages,
            sync_mode: WritebackSyncMode::None,
            for_background: true,
            ..Default::default()
        }
    }
}

// ============================================================================
// Core Writeback Functions
// ============================================================================

/// Write dirty pages for a specific address space
///
/// This is the core writeback function. It collects dirty pages from the
/// address space and writes them back using the filesystem's writepage.
///
/// # Arguments
/// * `addr_space` - The address space containing dirty pages
/// * `wbc` - Writeback control parameters
///
/// # Returns
/// * `Ok(count)` - Number of pages written
/// * `Err(errno)` - First error encountered
pub fn do_writepages(addr_space: &AddressSpace, wbc: &mut WritebackControl) -> Result<usize, i32> {
    // Don't write more than requested
    if wbc.nr_to_write <= 0 {
        return Ok(0);
    }

    // Collect dirty pages (this increments their refcounts)
    let limit = wbc.nr_to_write.min(1024) as usize;
    let dirty_pages = addr_space.collect_dirty_pages(limit);

    if dirty_pages.is_empty() {
        return Ok(0);
    }

    let mut written = 0;
    let mut first_error: Option<i32> = None;

    for (page_offset, page) in dirty_pages {
        // Check range (for ranged fsync)
        let byte_offset = page_offset * PAGE_SIZE as u64;
        if byte_offset < wbc.range_start || byte_offset >= wbc.range_end {
            wbc.pages_skipped += 1;
            continue;
        }

        // Skip if page is already being written back
        if page.is_writeback() {
            wbc.pages_skipped += 1;
            continue;
        }

        // Mark page as in writeback
        page.set_writeback();

        // Lock the page for I/O
        page.lock();

        // Copy page content to temporary buffer
        let mut buf = [0u8; PAGE_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(page.frame as *const u8, buf.as_mut_ptr(), PAGE_SIZE);
        }

        // Call filesystem's writepage
        let result = addr_space
            .a_ops
            .writepage(addr_space.file_id, page_offset, &buf);

        match result {
            Ok(_) => {
                // Success - mark page clean
                page.mark_clean();
                written += 1;
                wbc.nr_to_write -= 1;
                wbc.pages_written += 1;
            }
            Err(e) => {
                // Error - leave page dirty for retry
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }

        // Unlock and end writeback
        page.unlock();
        page.end_writeback();

        // Stop if we've written enough
        if wbc.nr_to_write <= 0 {
            break;
        }
    }

    // If no more dirty pages, remove from dirty list
    if !addr_space.has_dirty_pages() {
        addr_space.mark_clean_for_writeback();
    }

    match first_error {
        Some(e) if written == 0 => Err(e),
        _ => Ok(written),
    }
}

/// Write dirty pages for a specific file by FileId
///
/// Looks up the address space and calls do_writepages.
pub fn do_writepages_for_file(file_id: FileId, wbc: &mut WritebackControl) -> Result<usize, i32> {
    let addr_space = {
        let cache = PAGE_CACHE.lock();
        cache.get_address_space(file_id)
    };

    match addr_space {
        Some(as_) => do_writepages(&as_, wbc),
        None => Ok(0), // No address space = no dirty pages
    }
}

/// Write dirty pages from all address spaces
///
/// Iterates through all dirty address spaces and writes their dirty pages.
/// Used by sync() syscall and periodic writeback.
pub fn writeback_all(wbc: &mut WritebackControl) {
    // Get snapshot of dirty file IDs
    let dirty_files: Vec<FileId> = { DIRTY_ADDRESS_SPACES.lock().iter().copied().collect() };

    for file_id in dirty_files {
        if wbc.nr_to_write <= 0 {
            break;
        }

        let _ = do_writepages_for_file(file_id, wbc);
    }
}

/// Wait for all writeback to complete for a file
///
/// Waits for any pages with the writeback flag set to complete.
/// Used by fsync to ensure all I/O is finished.
pub fn wait_on_writeback(file_id: FileId) {
    let addr_space = {
        let cache = PAGE_CACHE.lock();
        cache.get_address_space(file_id)
    };

    if let Some(as_) = addr_space {
        // Get all pages and wait on each that's in writeback
        let pages = as_.get_all_pages();

        for page in pages {
            page.wait_writeback();
        }
    }
}

// ============================================================================
// Global Writeback (Legacy/Fallback)
// ============================================================================

/// Perform periodic writeback for all dirty files
///
/// This is a fallback for files not tracked by a per-device BDI.
/// Called from do_device_writeback or sync_all.
#[allow(dead_code)]
fn do_periodic_writeback() {
    // Quick check - any dirty files?
    let has_dirty = !DIRTY_ADDRESS_SPACES.lock().is_empty();
    if !has_dirty {
        return;
    }

    // Perform background writeback
    let mut wbc = WritebackControl::for_kupdate(WRITEBACK_BATCH_SIZE);
    writeback_all(&mut wbc);
}

/// Force immediate writeback of all dirty pages (for sync syscall)
pub fn sync_all() -> Result<usize, i32> {
    let mut wbc = WritebackControl::for_sync();
    writeback_all(&mut wbc);

    // Wait for all writeback to complete
    let dirty_files: Vec<FileId> = { DIRTY_ADDRESS_SPACES.lock().iter().copied().collect() };

    for file_id in dirty_files {
        wait_on_writeback(file_id);
    }

    Ok(wbc.pages_written)
}

// ============================================================================
// Per-Device Writeback (BDI)
// ============================================================================

/// BDI workqueue for writeback operations
///
/// This is a dedicated workqueue for writeback, separate from the system
/// workqueue, allowing writeback to proceed even during memory pressure.
pub static BDI_WORKQUEUE: Workqueue =
    Workqueue::new("bdi", wq_flags::WQ_MEM_RECLAIM | wq_flags::WQ_UNBOUND);

/// Registry of per-device writeback states
static BDI_REGISTRY: RwLock<BTreeMap<DevId, Arc<BdiWriteback>>> = RwLock::new(BTreeMap::new());

/// Per-device writeback state (simplified backing_dev_info)
///
/// Each block device has a BdiWriteback that tracks:
/// - Which files on this device have dirty pages
/// - A delayed work item for periodic flushing
pub struct BdiWriteback {
    /// Device ID this writeback state belongs to
    pub dev_id: DevId,
    /// Dirty file IDs on this device
    dirty_inodes: Mutex<BTreeSet<FileId>>,
    /// Delayed work for periodic flushing
    dwork: Arc<Mutex<DelayedWork>>,
    /// Number of pages written since last sample (for bandwidth estimation)
    written_pages: AtomicU64,
}

impl BdiWriteback {
    /// Create new writeback state for a device
    fn new(dev_id: DevId) -> Self {
        // Create delayed work that performs writeback for this device
        let dev = dev_id;
        let dwork = Arc::new(Mutex::new(DelayedWork::new(move || {
            do_device_writeback(dev);
        })));

        Self {
            dev_id,
            dirty_inodes: Mutex::new(BTreeSet::new()),
            dwork,
            written_pages: AtomicU64::new(0),
        }
    }

    /// Mark a file as dirty on this device
    ///
    /// If this is the first dirty file, schedules delayed writeback.
    pub fn mark_dirty(&self, file_id: FileId) {
        let was_empty = {
            let mut set = self.dirty_inodes.lock();
            let was_empty = set.is_empty();
            set.insert(file_id);
            was_empty
        };

        // If first dirty file, schedule delayed writeback
        if was_empty {
            self.wakeup_delayed();
        }
    }

    /// Remove a file from the dirty list
    pub fn mark_clean(&self, file_id: FileId) {
        self.dirty_inodes.lock().remove(&file_id);
    }

    /// Schedule periodic writeback (delayed)
    ///
    /// Schedules writeback to occur after WRITEBACK_INTERVAL_TICKS.
    pub fn wakeup_delayed(&self) {
        BDI_WORKQUEUE.queue_delayed_work(self.dwork.clone(), WRITEBACK_INTERVAL_TICKS);
    }

    /// Wake immediately for sync/fsync
    ///
    /// Cancels any pending delayed work and queues for immediate execution.
    pub fn wakeup(&self) {
        // Cancel delayed timer and queue immediately
        {
            let dw = self.dwork.lock();
            dw.cancel_timer();
        }
        // Queue for immediate execution
        BDI_WORKQUEUE.queue_delayed_work(self.dwork.clone(), 0);
    }

    /// Get the dirty file IDs for this device
    pub fn get_dirty_files(&self) -> Vec<FileId> {
        self.dirty_inodes.lock().iter().copied().collect()
    }

    /// Check if there are dirty files
    pub fn has_dirty(&self) -> bool {
        !self.dirty_inodes.lock().is_empty()
    }

    /// Add to the written pages counter
    pub fn add_written(&self, count: u64) {
        self.written_pages.fetch_add(count, Ordering::Relaxed);
    }
}

/// Perform writeback for a specific device
///
/// This is called from the workqueue worker thread.
fn do_device_writeback(dev_id: DevId) {
    // Get the BDI for this device
    let bdi = match get_bdi(dev_id) {
        Some(b) => b,
        None => return,
    };

    // Get dirty files for this device
    let dirty_files = bdi.get_dirty_files();

    if dirty_files.is_empty() {
        return;
    }

    // Perform writeback
    let mut wbc = WritebackControl::for_kupdate(WRITEBACK_BATCH_SIZE);

    for file_id in dirty_files {
        if wbc.nr_to_write <= 0 {
            break;
        }

        if let Ok(written) = do_writepages_for_file(file_id, &mut wbc) {
            bdi.add_written(written as u64);
        }
    }

    // If there are still dirty files, re-schedule
    if bdi.has_dirty() {
        bdi.wakeup_delayed();
    }
}

/// Register a device for writeback tracking
///
/// Called when a block device is created. Returns the BdiWriteback for the device.
pub fn bdi_register(dev_id: DevId) -> Arc<BdiWriteback> {
    let bdi = Arc::new(BdiWriteback::new(dev_id));
    BDI_REGISTRY.write().insert(dev_id, bdi.clone());
    bdi
}

/// Unregister a device from writeback tracking
///
/// Called when a block device is removed.
pub fn bdi_unregister(dev_id: DevId) {
    if let Some(bdi) = BDI_REGISTRY.write().remove(&dev_id) {
        // Cancel any pending work
        bdi.dwork.lock().cancel_timer();
    }
}

/// Get the BdiWriteback for a device
pub fn get_bdi(dev_id: DevId) -> Option<Arc<BdiWriteback>> {
    BDI_REGISTRY.read().get(&dev_id).cloned()
}

/// Wake all BDIs for sync
///
/// Called by sync() to flush all devices immediately.
pub fn wakeup_all_bdis() {
    let bdis: Vec<Arc<BdiWriteback>> = BDI_REGISTRY.read().values().cloned().collect();
    for bdi in bdis {
        bdi.wakeup();
    }
}
