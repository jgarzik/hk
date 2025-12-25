//! Swap cache - caches swap pages in memory
//!
//! Provides a cache layer for swap pages to avoid redundant disk I/O when a
//! page is swapped in and might be needed again (e.g., copy-on-write scenarios).
//!
//! Uses the PageCache infrastructure with a special FileId prefix (0xC) to
//! distinguish swap entries from regular file pages.
//!
//! ## Design
//!
//! Each swap entry maps to a unique FileId:
//! - Prefix: 0xC000_0000_0000_0000 (bits 60-63 = 0xC)
//! - Lower bits: swap entry raw value (type + offset)
//!
//! This allows using the existing PageCache without modification while
//! ensuring swap pages are distinguishable from file-backed pages.

use alloc::sync::Arc;

use crate::PAGE_CACHE;
use crate::mm::page_cache::{CachedPage, FileId, NULL_AOPS, PAGE_SIZE};
use crate::mm::swap_entry::SwapEntry;

/// Swap cache FileId prefix - distinguishes swap entries from regular files
///
/// Uses nibble 0xC in the high 4 bits (bits 60-63).
/// This doesn't conflict with:
/// - Regular file IDs (path hash, typically < 0x8000_0000_0000_0000)
/// - Block device IDs (0x8000_0000_0000_0000 prefix)
const SWAP_FILEID_PREFIX: u64 = 0xC000_0000_0000_0000;

/// Mask for the prefix nibble
const SWAP_FILEID_MASK: u64 = 0xF000_0000_0000_0000;

/// Convert a swap entry to a FileId for page cache lookup
///
/// # Arguments
/// * `entry` - The swap entry to convert
///
/// # Returns
/// A FileId encoding the swap entry for page cache operations
#[inline]
pub fn swap_file_id(entry: SwapEntry) -> FileId {
    FileId(SWAP_FILEID_PREFIX | entry.raw())
}

/// Check if a FileId represents a swap entry
///
/// # Arguments
/// * `file_id` - The FileId to check
///
/// # Returns
/// true if this FileId was created from a swap entry
#[inline]
pub fn is_swap_file_id(file_id: FileId) -> bool {
    (file_id.0 & SWAP_FILEID_MASK) == SWAP_FILEID_PREFIX
}

/// Extract the SwapEntry from a swap FileId
///
/// # Safety
/// Caller must ensure `is_swap_file_id(file_id)` is true
#[inline]
pub fn file_id_to_swap_entry(file_id: FileId) -> SwapEntry {
    SwapEntry::from_raw(file_id.0 & !SWAP_FILEID_MASK)
}

/// Look up a page in the swap cache
///
/// Checks if the page for the given swap entry is already cached in memory.
/// If found, the page's reference count is incremented.
///
/// # Arguments
/// * `entry` - The swap entry to look up
///
/// # Returns
/// Some(page) if found in cache, None if the page must be read from swap
pub fn swap_cache_lookup(entry: SwapEntry) -> Option<Arc<CachedPage>> {
    let file_id = swap_file_id(entry);
    PAGE_CACHE.lock().find_get_page(file_id, 0) // offset=0 since each swap entry is unique
}

/// Add a page to the swap cache after swap-in
///
/// Called after reading a page from swap to cache it in memory.
/// This allows subsequent accesses to find the page without re-reading.
///
/// # Arguments
/// * `entry` - The swap entry this page came from
/// * `frame_phys` - Physical address of the frame containing the page
///
/// # Note
/// This creates a new CachedPage in the page cache. The page is marked
/// as clean since it matches the on-disk copy.
#[allow(dead_code)]
pub fn swap_cache_add(entry: SwapEntry, frame_phys: u64) {
    let file_id = swap_file_id(entry);

    // Create address space for this swap entry if needed
    // Swap pages are:
    // - can_writeback = true (we can write back to swap device)
    // - unevictable = false (swap cache pages CAN be evicted)
    let mut cache = PAGE_CACHE.lock();

    // Get or create address space
    let addr_space = cache.get_or_create_address_space(
        file_id,
        PAGE_SIZE as u64, // Each swap entry = 1 page
        true,             // can_writeback
        false,            // not unevictable
        &NULL_AOPS,       // Use null ops (writeback handled specially for swap)
    );

    // Create and insert the cached page
    let page = Arc::new(CachedPage::new(frame_phys, file_id, 0));
    addr_space.insert_page(0, page);
}

/// Remove a page from the swap cache when swap slot is freed
///
/// Called when a swap entry is freed to clean up any cached copy.
/// The physical frame is NOT freed here - caller is responsible.
///
/// # Arguments
/// * `entry` - The swap entry being freed
#[allow(dead_code)]
pub fn swap_cache_del(entry: SwapEntry) {
    let file_id = swap_file_id(entry);

    let cache = PAGE_CACHE.lock();
    if let Some(addr_space) = cache.get_address_space(file_id) {
        addr_space.remove_page(0);
    }
}

/// Check if a swap entry has a cached page
///
/// # Arguments
/// * `entry` - The swap entry to check
///
/// # Returns
/// true if the page is in the swap cache
#[allow(dead_code)]
pub fn swap_cache_has(entry: SwapEntry) -> bool {
    let file_id = swap_file_id(entry);
    let cache = PAGE_CACHE.lock();
    if let Some(addr_space) = cache.get_address_space(file_id) {
        addr_space.find_page(0).is_some()
    } else {
        false
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swap_file_id() {
        let entry = SwapEntry::new(3, 1000);
        let file_id = swap_file_id(entry);

        // Should have swap prefix
        assert!(is_swap_file_id(file_id));

        // Should preserve swap entry data
        let recovered = file_id_to_swap_entry(file_id);
        assert_eq!(recovered.swap_type(), 3);
        assert_eq!(recovered.offset(), 1000);
    }

    #[test]
    fn test_non_swap_file_id() {
        // Regular file ID
        let file_id = FileId::new(0x1234567890ABCDEF);
        assert!(!is_swap_file_id(file_id));

        // Block device ID
        let blkdev_id = FileId::from_blkdev(8, 0);
        assert!(!is_swap_file_id(blkdev_id));
    }
}
