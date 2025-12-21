//! RAM Disk Driver
//!
//! Page-cache-backed RAM disk with zero-copy design.
//!
//! ## Zero-Copy Architecture
//!
//! The RAM disk uses the page cache pages directly as its backing store.
//! There is no separate storage layer - the page cache IS the storage.
//!
//! ```text
//! User buffer <-> Page cache page (which IS the RAM disk data)
//! ```
//!
//! For RAM disk:
//! - `can_writeback = false` prevents eviction of dirty pages
//! - The page cache pages ARE the persistent storage
//! - Bio operations are essentially no-ops (data already in page cache)
//!
//! ## Sparse Allocation
//!
//! Pages are allocated on-demand:
//! - Read from unallocated page returns zeros
//! - Write allocates the page in page cache

use alloc::string::String;
use alloc::sync::Arc;

use super::{
    Bio, BioOp, BlockDevice, BlockDriver, BlockError, DevId, Disk, QueueLimits, RequestQueue,
    major, register_blkdev,
};
use crate::frame_alloc::FrameAllocRef;
use crate::mm::page_cache::{FileId, NULL_AOPS, PAGE_SIZE};
use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

/// RAM disk driver
///
/// Implements BlockDriver for RAM disk. Since the page cache IS the storage,
/// bio operations are essentially no-ops - the data is already where it needs to be.
pub struct RamDiskDriver {
    /// Capacity in bytes (for validation)
    #[allow(dead_code)] // Reserved for future boundary checking
    capacity_bytes: u64,
}

impl RamDiskDriver {
    /// Create a new RAM disk driver with given capacity
    pub fn new(capacity_bytes: u64) -> Arc<Self> {
        Arc::new(Self { capacity_bytes })
    }
}

impl BlockDriver for RamDiskDriver {
    fn submit(&self, _disk: &Disk, bio: Bio) {
        // RAM disk I/O is a no-op - the page cache already holds the data!
        // The bio segments point to page cache pages that ARE the storage.
        //
        // For real hardware drivers (AHCI, NVMe), this would:
        // - Build DMA descriptors
        // - Submit to hardware queues
        // - Handle completion via interrupts
        //
        // For RAM disk, we just complete immediately with success.
        let result = match bio.op {
            BioOp::Read => Ok(()),  // Data already in page cache page
            BioOp::Write => Ok(()), // Data already written to page cache page
            BioOp::Flush => Ok(()), // No volatile cache to flush
        };

        // Call completion callback
        bio.complete(result);
    }

    fn name(&self) -> &str {
        "ramdisk"
    }

    fn readpage(&self, _disk: &Disk, buf: &mut [u8], _page_offset: u64) {
        // For RAM disk, a read of an unallocated page returns zeros.
        // The page cache will call this when populating a new page.
        buf.fill(0);
    }
}

/// Create and register a RAM disk
///
/// Creates a RAM disk with the specified capacity and registers it
/// with the global block device registry.
///
/// # Arguments
/// * `minor` - Minor device number (0 for rd0, 1 for rd1, etc.)
/// * `capacity_mb` - Capacity in megabytes
///
/// # Returns
/// The created BlockDevice on success
pub fn create_ramdisk(minor: u16, capacity_mb: u64) -> Result<Arc<BlockDevice>, BlockError> {
    let capacity_bytes = capacity_mb * 1024 * 1024;
    let capacity_sectors = capacity_bytes / 512;

    // Create driver
    let driver = RamDiskDriver::new(capacity_bytes);

    // Create request queue with default limits
    let queue = Arc::new(RequestQueue::new(driver.clone(), QueueLimits::default()));

    // Create disk
    let dev_id = DevId::new(major::RAMDISK, minor);
    let name = match minor {
        0 => String::from("rd0"),
        1 => String::from("rd1"),
        2 => String::from("rd2"),
        3 => String::from("rd3"),
        n => alloc::format!("rd{}", n),
    };

    let disk = Disk::new(
        dev_id,
        name,
        capacity_sectors,
        512, // Logical block size
        queue,
    );

    // Create block device
    let bdev = Arc::new(BlockDevice::new(disk));

    // Register globally
    register_blkdev(dev_id, bdev.clone())?;

    Ok(bdev)
}

/// Create a ramdisk populated with initial data
///
/// Creates a RAM disk and copies the provided data into its page cache pages.
/// This is used to load filesystem images (like VFAT) into a block device.
///
/// # Arguments
/// * `minor` - Minor device number (0 for rd0, 1 for rd1, etc.)
/// * `data` - Source data to copy into the ramdisk
///
/// # Returns
/// The created BlockDevice on success
pub fn create_ramdisk_from_data(minor: u16, data: &[u8]) -> Result<Arc<BlockDevice>, BlockError> {
    // Round up size to MB for capacity calculation
    let size_bytes = data.len() as u64;
    let size_mb = size_bytes.div_ceil(1024 * 1024);

    // Create the empty ramdisk first
    let bdev = create_ramdisk(minor, size_mb)?;
    let file_id = FileId::from_blkdev(major::RAMDISK, minor);
    let capacity = bdev.capacity();

    // Copy data into page cache pages
    let num_pages = data.len().div_ceil(PAGE_SIZE);

    for page_idx in 0..num_pages {
        let page_offset = page_idx as u64;

        // Allocate page in cache
        let mut cache = PAGE_CACHE.lock();
        let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

        let page = cache
            .add_page_zeroed(
                file_id,
                page_offset,
                capacity,
                &mut frame_alloc,
                false, // can_writeback = false for ramdisk
                false, // not unevictable (clean pages can be evicted)
                &NULL_AOPS,
            )
            .map_err(|_| BlockError::IoError)?;

        // Copy data to the frame
        let src_offset = page_idx * PAGE_SIZE;
        let copy_len = core::cmp::min(PAGE_SIZE, data.len() - src_offset);

        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr().add(src_offset),
                page.frame as *mut u8,
                copy_len,
            );
        }

        // Mark the page as dirty since we wrote to it
        page.mark_dirty();
    }

    Ok(bdev)
}
