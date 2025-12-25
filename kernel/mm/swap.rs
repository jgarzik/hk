//! Swap subsystem - swap device management and I/O
//!
//! This module implements:
//! - SwapInfo: Per-swap-device state and slot management
//! - Swap slot allocation/free with bitmap
//! - Swap file and partition support
//! - swapon/swapoff syscalls

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use spin::{Mutex, RwLock};

use crate::arch::Uaccess;
use crate::fs::{Inode, lookup_path};
use crate::mm::page_cache::PAGE_SIZE;
use crate::mm::swap_entry::{MAX_SWAPFILES, SwapEntry};
use crate::storage::BlockDevice;
use crate::task::{CAP_SYS_ADMIN, capable};
use crate::uaccess::strncpy_from_user;

// ============================================================================
// Error codes
// ============================================================================

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EIO: i64 = -5;
const ENOMEM: i64 = -12;
const EBUSY: i64 = -16;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;

// ============================================================================
// Swap flags (for swapon syscall)
// ============================================================================

/// Prefer this swap device (priority set to 32767)
pub const SWAP_FLAG_PREFER: i32 = 0x8000;

/// Extract priority from flags (low 15 bits when SWAP_FLAG_PREFER is set)
pub const SWAP_FLAG_PRIO_MASK: i32 = 0x7FFF;

/// Shift for priority value
pub const SWAP_FLAG_PRIO_SHIFT: i32 = 0;

/// Enable discard (TRIM) for SSD swap
pub const SWAP_FLAG_DISCARD: i32 = 0x10000;

// ============================================================================
// SwapInfo flags (internal state)
// ============================================================================

/// Swap device is in use
pub const SWP_USED: u32 = 1 << 0;

/// Swap device is writable (write OK)
pub const SWP_WRITEOK: u32 = 1 << 1;

/// Swap device is being deactivated
pub const SWP_DISCARDING: u32 = 1 << 2;

// ============================================================================
// Swap header (mkswap format)
// ============================================================================

/// Magic string for swap signature (at offset 4086)
const SWAP_MAGIC: &[u8; 10] = b"SWAPSPACE2";

/// Offset of magic string in first page
const SWAP_MAGIC_OFFSET: usize = 4086;

/// Offset of swap header info
const SWAP_HEADER_INFO_OFFSET: usize = 1024;

/// Swap header info structure (at offset 1024)
#[repr(C)]
#[derive(Clone, Copy)]
struct SwapHeaderInfo {
    version: u32,
    last_page: u32,
    nr_badpages: u32,
    uuid: [u8; 16],
    volume_name: [u8; 16],
    _padding: [u32; 117],
}

// ============================================================================
// Global swap state
// ============================================================================

/// Array of active swap devices
pub static SWAP_INFO: RwLock<[Option<Arc<SwapInfo>>; MAX_SWAPFILES]> =
    RwLock::new([const { None }; MAX_SWAPFILES]);

/// Total swap pages available across all devices
pub static TOTAL_SWAP_PAGES: AtomicU64 = AtomicU64::new(0);

/// Number of swap pages currently in use
pub static TOTAL_SWAP_USED: AtomicU64 = AtomicU64::new(0);

/// Number of active swap devices
pub static NR_SWAP_DEVICES: AtomicU8 = AtomicU8::new(0);

/// Memory pressure threshold (percentage) for triggering swap-out
/// When RAM usage exceeds this, background swap-out begins
pub static SWAP_PRESSURE_THRESHOLD: AtomicU8 = AtomicU8::new(75);

// ============================================================================
// SwapInfo - per-device state
// ============================================================================

/// Per-swap-device information
///
/// Manages swap slot allocation and tracks device state.
pub struct SwapInfo {
    /// Inode backing the swap area (for swap files)
    pub inode: Option<Arc<Inode>>,

    /// Block device (for swap partitions)
    pub bdev: Option<Arc<BlockDevice>>,

    /// Path to the swap file/device
    pub path: Vec<u8>,

    /// Internal flags (SWP_USED, SWP_WRITEOK, etc.)
    pub flags: Mutex<u32>,

    /// Priority for swap device selection (higher = preferred)
    pub priority: i16,

    /// Swap type index (0-31)
    pub swap_type: u8,

    /// Maximum number of usable slots (pages)
    pub max_slots: u64,

    /// Bitmap of free slots (1 = free, 0 = used)
    /// Each u64 covers 64 slots
    slot_bitmap: Mutex<Vec<u64>>,

    /// Reference counts per slot (for swap cache/COW sharing)
    slot_counts: Mutex<Vec<u16>>,

    /// Number of pages currently in use
    pub inuse_pages: AtomicU64,

    /// Hint for next free slot search (speeds up allocation)
    next_free_hint: AtomicU64,
}

impl SwapInfo {
    /// Create a new SwapInfo for a swap file
    fn new_file(
        inode: Arc<Inode>,
        path: Vec<u8>,
        swap_type: u8,
        max_slots: u64,
        priority: i16,
    ) -> Self {
        let bitmap_words = max_slots.div_ceil(64) as usize;
        // Initialize bitmap with all slots free (1 = free)
        let mut bitmap = vec![!0u64; bitmap_words];
        // Mark slot 0 as used (reserved for header)
        if !bitmap.is_empty() {
            bitmap[0] &= !1;
        }

        Self {
            inode: Some(inode),
            bdev: None,
            path,
            flags: Mutex::new(SWP_USED | SWP_WRITEOK),
            priority,
            swap_type,
            max_slots,
            slot_bitmap: Mutex::new(bitmap),
            slot_counts: Mutex::new(vec![0u16; max_slots as usize]),
            inuse_pages: AtomicU64::new(0),
            next_free_hint: AtomicU64::new(1), // Start after header
        }
    }

    /// Create a new SwapInfo for a swap partition
    #[allow(dead_code)]
    fn new_partition(
        bdev: Arc<BlockDevice>,
        path: Vec<u8>,
        swap_type: u8,
        max_slots: u64,
        priority: i16,
    ) -> Self {
        let bitmap_words = max_slots.div_ceil(64) as usize;
        let mut bitmap = vec![!0u64; bitmap_words];
        if !bitmap.is_empty() {
            bitmap[0] &= !1; // Reserve slot 0
        }

        Self {
            inode: None,
            bdev: Some(bdev),
            path,
            flags: Mutex::new(SWP_USED | SWP_WRITEOK),
            priority,
            swap_type,
            max_slots,
            slot_bitmap: Mutex::new(bitmap),
            slot_counts: Mutex::new(vec![0u16; max_slots as usize]),
            inuse_pages: AtomicU64::new(0),
            next_free_hint: AtomicU64::new(1),
        }
    }

    /// Allocate a swap slot
    ///
    /// Returns the slot offset, or None if swap is full
    pub fn alloc_slot(&self) -> Option<u64> {
        let mut bitmap = self.slot_bitmap.lock();
        let hint = self.next_free_hint.load(Ordering::Relaxed);

        // Search from hint
        if let Some(offset) = self.find_free_slot(&bitmap, hint) {
            self.mark_slot_used(&mut bitmap, offset);
            self.next_free_hint.store(offset + 1, Ordering::Relaxed);
            self.inuse_pages.fetch_add(1, Ordering::Relaxed);
            TOTAL_SWAP_USED.fetch_add(1, Ordering::Relaxed);
            return Some(offset);
        }

        // Wrap around and search from beginning
        if hint > 1
            && let Some(offset) = self.find_free_slot(&bitmap, 1)
        {
            self.mark_slot_used(&mut bitmap, offset);
            self.next_free_hint.store(offset + 1, Ordering::Relaxed);
            self.inuse_pages.fetch_add(1, Ordering::Relaxed);
            TOTAL_SWAP_USED.fetch_add(1, Ordering::Relaxed);
            return Some(offset);
        }

        None // Swap is full
    }

    /// Free a swap slot
    pub fn free_slot(&self, offset: u64) {
        if offset >= self.max_slots || offset == 0 {
            return; // Invalid or reserved slot
        }

        let mut bitmap = self.slot_bitmap.lock();
        let word_idx = (offset / 64) as usize;
        let bit_idx = offset % 64;

        if word_idx < bitmap.len() {
            // Check if already free
            if bitmap[word_idx] & (1 << bit_idx) == 0 {
                // Was in use, now free
                bitmap[word_idx] |= 1 << bit_idx;
                self.inuse_pages.fetch_sub(1, Ordering::Relaxed);
                TOTAL_SWAP_USED.fetch_sub(1, Ordering::Relaxed);

                // Update hint if this is earlier
                let hint = self.next_free_hint.load(Ordering::Relaxed);
                if offset < hint {
                    self.next_free_hint.store(offset, Ordering::Relaxed);
                }
            }
        }
    }

    /// Increment reference count for a slot
    pub fn incref(&self, offset: u64) {
        if offset >= self.max_slots {
            return;
        }
        let mut counts = self.slot_counts.lock();
        if let Some(count) = counts.get_mut(offset as usize) {
            *count = count.saturating_add(1);
        }
    }

    /// Decrement reference count for a slot
    ///
    /// Returns true if the slot should be freed (count reached 0)
    pub fn decref(&self, offset: u64) -> bool {
        if offset >= self.max_slots {
            return false;
        }
        let mut counts = self.slot_counts.lock();
        if let Some(count) = counts.get_mut(offset as usize)
            && *count > 0
        {
            *count -= 1;
            return *count == 0;
        }
        false
    }

    /// Get reference count for a slot
    pub fn refcount(&self, offset: u64) -> u16 {
        if offset >= self.max_slots {
            return 0;
        }
        let counts = self.slot_counts.lock();
        counts.get(offset as usize).copied().unwrap_or(0)
    }

    // Helper: find a free slot starting from `start`
    fn find_free_slot(&self, bitmap: &[u64], start: u64) -> Option<u64> {
        let start_word = (start / 64) as usize;
        let start_bit = start % 64;

        for (idx, &word) in bitmap.iter().enumerate().skip(start_word) {
            if word == 0 {
                continue; // No free bits
            }

            let skip = if idx == start_word { start_bit } else { 0 };

            for bit_idx in skip..64 {
                if word & (1 << bit_idx) != 0 {
                    let offset = (idx as u64) * 64 + bit_idx;
                    if offset < self.max_slots {
                        return Some(offset);
                    }
                }
            }
        }
        None
    }

    // Helper: mark a slot as used in the bitmap
    fn mark_slot_used(&self, bitmap: &mut [u64], offset: u64) {
        let word_idx = (offset / 64) as usize;
        let bit_idx = offset % 64;
        if word_idx < bitmap.len() {
            bitmap[word_idx] &= !(1 << bit_idx);
        }
    }

    /// Check if swap device is active and writable
    pub fn is_active(&self) -> bool {
        let flags = self.flags.lock();
        (*flags & SWP_USED) != 0 && (*flags & SWP_WRITEOK) != 0
    }
}

// ============================================================================
// Swap device lookup
// ============================================================================

/// Get swap info for a swap type
pub fn get_swap_info(swap_type: u8) -> Option<Arc<SwapInfo>> {
    if (swap_type as usize) >= MAX_SWAPFILES {
        return None;
    }
    let info = SWAP_INFO.read();
    info[swap_type as usize].clone()
}

/// Find a free swap type index
fn find_free_swap_type() -> Option<u8> {
    let info = SWAP_INFO.read();
    for (i, slot) in info.iter().enumerate() {
        if slot.is_none() {
            return Some(i as u8);
        }
    }
    None
}

/// Find swap device by path
fn find_swap_by_path(path: &[u8]) -> Option<u8> {
    let info = SWAP_INFO.read();
    for (i, slot) in info.iter().enumerate() {
        if let Some(si) = slot
            && si.path == path
        {
            return Some(i as u8);
        }
    }
    None
}

// ============================================================================
// Swap slot allocation (cross-device)
// ============================================================================

/// Allocate a swap entry from any active swap device
///
/// Tries devices in priority order.
pub fn alloc_swap_entry() -> Option<SwapEntry> {
    let info = SWAP_INFO.read();

    // Simple approach: try each device in order
    // TODO: priority-based selection
    for (swap_type, slot) in info.iter().enumerate() {
        if let Some(si) = slot
            && si.is_active()
            && let Some(offset) = si.alloc_slot()
        {
            return Some(SwapEntry::new(swap_type as u8, offset));
        }
    }
    None
}

/// Free a swap entry
pub fn free_swap_entry(entry: SwapEntry) {
    if !entry.is_valid() {
        return;
    }
    if let Some(si) = get_swap_info(entry.swap_type()) {
        si.free_slot(entry.offset());
    }
}

// ============================================================================
// Swap I/O
// ============================================================================

/// Read a page from swap into a frame
///
/// # Arguments
/// * `entry` - Swap entry identifying the slot
/// * `frame_phys` - Physical address of destination frame
///
/// # Returns
/// Ok(()) on success, Err(errno) on failure
pub fn swap_read_page(entry: SwapEntry, frame_phys: u64) -> Result<(), i64> {
    let si = get_swap_info(entry.swap_type()).ok_or(EINVAL)?;
    let offset = entry.offset();

    // Calculate page offset in swap device (page number, not byte offset)
    let page_offset = offset;

    if let Some(ref inode) = si.inode {
        // Swap file: read via inode readpage
        let mut buf = [0u8; PAGE_SIZE];
        let bytes_read = inode
            .i_op
            .readpage(inode, page_offset, &mut buf)
            .map_err(|_| EIO)?;
        if bytes_read < PAGE_SIZE {
            // Zero-fill the rest if EOF encountered
            buf[bytes_read..].fill(0);
        }
        // Copy to frame
        unsafe {
            let dest = crate::arch::phys_to_virt(frame_phys);
            core::ptr::copy_nonoverlapping(buf.as_ptr(), dest, PAGE_SIZE);
        }
        Ok(())
    } else if let Some(ref _bdev) = si.bdev {
        // Swap partition: direct block device I/O
        // TODO: implement direct block device read
        Err(EIO)
    } else {
        Err(EINVAL)
    }
}

/// Write a page to swap from a frame
///
/// # Arguments
/// * `entry` - Swap entry identifying the slot
/// * `frame_phys` - Physical address of source frame
///
/// # Returns
/// Ok(()) on success, Err(errno) on failure
pub fn swap_write_page(entry: SwapEntry, frame_phys: u64) -> Result<(), i64> {
    let si = get_swap_info(entry.swap_type()).ok_or(EINVAL)?;
    let offset = entry.offset();

    // Calculate page offset in swap device (page number, not byte offset)
    let page_offset = offset;

    if let Some(ref inode) = si.inode {
        // Swap file: write via inode writepage
        // Copy from frame
        let mut buf = [0u8; PAGE_SIZE];
        unsafe {
            let src = crate::arch::phys_to_virt(frame_phys);
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), PAGE_SIZE);
        }
        let bytes_written = inode
            .i_op
            .writepage(inode, page_offset, &buf)
            .map_err(|_| EIO)?;
        if bytes_written != PAGE_SIZE {
            return Err(EIO);
        }
        Ok(())
    } else if let Some(ref _bdev) = si.bdev {
        // Swap partition: direct block device I/O
        // TODO: implement direct block device write
        Err(EIO)
    } else {
        Err(EINVAL)
    }
}

// ============================================================================
// swapon/swapoff syscalls
// ============================================================================

/// swapon syscall - activate a swap file or partition
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `swap_flags` - Flags (SWAP_FLAG_PREFER, priority, etc.)
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_swapon(path_ptr: u64, swap_flags: i32) -> i64 {
    // Check permissions - requires CAP_SYS_ADMIN
    if !capable(CAP_SYS_ADMIN) {
        return EPERM;
    }

    // Read path from user space
    let path_str = match strncpy_from_user::<Uaccess>(path_ptr, 4096) {
        Ok(p) => p,
        Err(_) => return -14, // EFAULT
    };
    let path = path_str.into_bytes();

    // Check if already activated
    if find_swap_by_path(&path).is_some() {
        return EBUSY;
    }

    // Find a free swap type slot
    let swap_type = match find_free_swap_type() {
        Some(t) => t,
        None => return EBUSY, // Too many swap devices
    };

    // Convert path to str for lookup
    let path_str = match core::str::from_utf8(&path) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    // Lookup the file/device
    let dentry = match lookup_path(path_str) {
        Ok(d) => d,
        Err(_) => return ENOENT,
    };

    // Get inode from dentry
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Read and validate swap header (page 0)
    let mut header_page = [0u8; PAGE_SIZE];
    if inode
        .i_op
        .readpage(&inode, 0, &mut header_page)
        .unwrap_or(0)
        < PAGE_SIZE
    {
        return EINVAL;
    }

    // Check magic
    if &header_page[SWAP_MAGIC_OFFSET..SWAP_MAGIC_OFFSET + 10] != SWAP_MAGIC {
        return EINVAL;
    }

    // Parse header info
    let info_ptr = header_page[SWAP_HEADER_INFO_OFFSET..].as_ptr() as *const SwapHeaderInfo;
    let header_info = unsafe { *info_ptr };

    if header_info.version != 1 {
        return EINVAL;
    }

    let max_slots = header_info.last_page as u64;
    if max_slots == 0 {
        return EINVAL;
    }

    // Calculate priority
    let priority = if (swap_flags & SWAP_FLAG_PREFER) != 0 {
        (swap_flags & SWAP_FLAG_PRIO_MASK) as i16
    } else {
        -1 // Default low priority
    };

    // Create SwapInfo
    let si = Arc::new(SwapInfo::new_file(
        inode, path, swap_type, max_slots, priority,
    ));

    // Register in global array
    {
        let mut info = SWAP_INFO.write();
        info[swap_type as usize] = Some(si);
    }

    // Update global counters
    TOTAL_SWAP_PAGES.fetch_add(max_slots - 1, Ordering::Relaxed); // -1 for header
    NR_SWAP_DEVICES.fetch_add(1, Ordering::Relaxed);

    0
}

/// swapoff syscall - deactivate a swap file or partition
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
///
/// # Returns
/// 0 on success, negative errno on failure
pub fn sys_swapoff(path_ptr: u64) -> i64 {
    // Check permissions - requires CAP_SYS_ADMIN
    if !capable(CAP_SYS_ADMIN) {
        return EPERM;
    }

    // Read path from user space
    let path_str = match strncpy_from_user::<Uaccess>(path_ptr, 4096) {
        Ok(p) => p,
        Err(_) => return -14, // EFAULT
    };
    let path = path_str.into_bytes();

    // Find swap device by path
    let swap_type = match find_swap_by_path(&path) {
        Some(t) => t,
        None => return EINVAL,
    };

    // Get swap info
    let si = match get_swap_info(swap_type) {
        Some(s) => s,
        None => return EINVAL,
    };

    // Mark as deactivating
    {
        let mut flags = si.flags.lock();
        *flags &= !SWP_WRITEOK;
        *flags |= SWP_DISCARDING;
    }

    // TODO: Migrate all pages from swap back to RAM
    // For now, we fail if any pages are in use
    let inuse = si.inuse_pages.load(Ordering::Relaxed);
    if inuse > 0 {
        // Restore flags and fail
        let mut flags = si.flags.lock();
        *flags |= SWP_WRITEOK;
        *flags &= !SWP_DISCARDING;
        return EBUSY;
    }

    // Update global counters
    let max_slots = si.max_slots;
    TOTAL_SWAP_PAGES.fetch_sub(max_slots - 1, Ordering::Relaxed);
    NR_SWAP_DEVICES.fetch_sub(1, Ordering::Relaxed);

    // Remove from global array
    {
        let mut info = SWAP_INFO.write();
        info[swap_type as usize] = None;
    }

    0
}

// ============================================================================
// Memory pressure detection
// ============================================================================

/// Get current memory pressure as a percentage (0-100)
///
/// Returns the percentage of physical RAM currently in use.
pub fn memory_pressure() -> u8 {
    let stats = crate::FRAME_ALLOCATOR.stats();
    if stats.total_bytes == 0 {
        return 0;
    }
    let used = stats.total_bytes - stats.free_bytes;
    ((used * 100) / stats.total_bytes) as u8
}

/// Check if memory pressure exceeds the swap threshold
pub fn should_swap_out() -> bool {
    let threshold = SWAP_PRESSURE_THRESHOLD.load(Ordering::Relaxed);
    memory_pressure() > threshold
}

/// Check if any swap space is available
pub fn swap_available() -> bool {
    NR_SWAP_DEVICES.load(Ordering::Relaxed) > 0
        && TOTAL_SWAP_USED.load(Ordering::Relaxed) < TOTAL_SWAP_PAGES.load(Ordering::Relaxed)
}

// ============================================================================
// Swap-out support
// ============================================================================

/// Try to swap out one anonymous page to free memory
///
/// This is called when memory pressure is high and we need to reclaim frames.
/// Uses the LRU list to select a victim and reverse mapping to update PTEs.
///
/// # Algorithm (following Linux vmscan)
/// 1. Get victim page from LRU inactive list
/// 2. Verify page is swappable (anonymous, not locked, not unevictable)
/// 3. Allocate swap entry
/// 4. Write page content to swap
/// 5. Use try_to_unmap to replace all PTEs with swap entry
/// 6. Free the physical frame
///
/// # Returns
/// - `Some(SwapEntry)` if a page was successfully swapped out
/// - `None` if no pages could be swapped out
pub fn try_to_swap_out() -> Option<SwapEntry> {
    use crate::mm::lru::LRU;
    use crate::mm::page::page_descriptor;
    use crate::mm::rmap::try_to_unmap;

    if !swap_available() {
        return None;
    }

    let mut lru = LRU.lock();

    // Try to find a suitable victim (limit attempts to avoid infinite loop)
    for _ in 0..16 {
        let frame = lru.get_victim()?;

        // Check page descriptor
        let page = match page_descriptor(frame) {
            Some(p) => p,
            None => {
                lru.pop_victim(); // Remove invalid entry
                continue;
            }
        };

        // Skip non-anonymous pages (handled by page cache eviction)
        if !page.is_anon() {
            lru.pop_victim();
            continue;
        }

        // Skip locked or unevictable pages
        if page.is_locked() || page.is_unevictable() {
            // Move to back of list
            if let Some(f) = lru.pop_victim() {
                lru.add_new(f);
            }
            continue;
        }

        // Skip pages with very high mapcount (shared extensively, might cause issues)
        if page.mapcount() > 16 {
            if let Some(f) = lru.pop_victim() {
                lru.add_new(f);
            }
            continue;
        }

        // Found a candidate - remove from LRU
        lru.pop_victim();
        drop(lru); // Release LRU lock before I/O

        // Allocate swap entry
        let swap_entry = match alloc_swap_entry() {
            Some(e) => e,
            None => {
                // No swap space, put page back
                LRU.lock().add_new(frame);
                return None;
            }
        };

        // Write page to swap
        if swap_write_page(swap_entry, frame).is_err() {
            free_swap_entry(swap_entry);
            LRU.lock().add_new(frame);
            return None;
        }

        // Unmap from all processes
        let unmapped = try_to_unmap(frame, swap_entry);
        if unmapped == 0 {
            // Page was already unmapped (race) - still a success, we wrote to swap
            // but we should free the swap slot since no one is using it
            free_swap_entry(swap_entry);
        }

        // Clear page descriptor
        if let Some(page) = page_descriptor(frame) {
            page.clear_mapping();
        }

        // Free the physical frame
        crate::FRAME_ALLOCATOR.free(frame);

        return Some(swap_entry);
    }

    None
}

/// Reclaim memory by swapping out pages
///
/// Called by the frame allocator when allocation fails and swap is available.
/// Attempts to free at least `nr_to_free` frames by swapping out pages.
///
/// # Arguments
/// * `nr_to_free` - Minimum number of frames to try to free
///
/// # Returns
/// Number of frames actually freed
pub fn try_to_free_pages(nr_to_free: usize) -> usize {
    if !swap_available() {
        return 0;
    }

    let mut freed = 0;

    for _ in 0..nr_to_free {
        if try_to_swap_out().is_some() {
            freed += 1;
        } else {
            // No more pages can be swapped out
            break;
        }
    }

    freed
}
