//! Writeback infrastructure for dirty page flushing
//!
//! This module provides:
//! - `WritebackControl` - Parameters controlling writeback operations
//! - `do_writepages` - Write dirty pages for a single file
//! - `writeback_all` - Write dirty pages for all files
//! - `writeback_timer_tick` - Periodic writeback hook called from timer interrupt

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::mm::page_cache::{AddressSpace, FileId, DIRTY_ADDRESS_SPACES, PAGE_SIZE};
use crate::PAGE_CACHE;

// ============================================================================
// Writeback Constants
// ============================================================================

/// Writeback interval in timer ticks (500 ticks = ~5 seconds at 100Hz)
const WRITEBACK_INTERVAL_TICKS: u64 = 500;

/// Pages to write per periodic writeback run
const WRITEBACK_BATCH_SIZE: i64 = 128;

/// Tick counter for periodic writeback scheduling
static WRITEBACK_TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Flag indicating writeback is pending (set from timer, processed later)
static WRITEBACK_PENDING: AtomicBool = AtomicBool::new(false);

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
        let result = addr_space.a_ops.writepage(addr_space.file_id, page_offset, &buf);

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
// Writeback Daemon (Timer-based)
// ============================================================================

/// Called from timer interrupt - checks if periodic writeback is due
///
/// This function is called from the timer interrupt handler on every tick.
/// It checks if enough time has passed since the last writeback and triggers
/// a batch writeback of dirty pages.
///
/// # Note
/// This runs in interrupt context, so we use try_lock and keep work minimal.
/// For expensive operations, we set a flag and let the scheduler do the work.
pub fn writeback_timer_tick() {
    let count = WRITEBACK_TICK_COUNT.fetch_add(1, Ordering::Relaxed);

    // Check if it's time for periodic writeback
    if count.is_multiple_of(WRITEBACK_INTERVAL_TICKS) && count > 0 {
        // For now, do writeback directly (simple approach)
        // A more sophisticated approach would set WRITEBACK_PENDING and
        // have the scheduler call check_writeback_pending()
        do_periodic_writeback();
    }
}

/// Perform periodic writeback
///
/// Called from writeback_timer_tick when it's time to flush dirty pages.
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

/// Check if writeback is pending (for deferred writeback model)
///
/// If timer set WRITEBACK_PENDING, process it now in scheduler context.
/// This is safer than doing writeback in interrupt context.
pub fn check_writeback_pending() {
    if WRITEBACK_PENDING.swap(false, Ordering::AcqRel) {
        do_periodic_writeback();
    }
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
