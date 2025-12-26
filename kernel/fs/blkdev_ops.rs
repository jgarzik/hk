//! Block Device File Operations
//!
//! Implements FileOps for block special files, routing read/write
//! through the page cache and block layer.
//!
//! ## Data Flow
//!
//! ```text
//! User buffer <-> BlockFileOps <-> Page Cache <-> BlockDevice
//! ```
//!
//! For RAM disk, the page cache IS the storage (zero-copy).

use alloc::sync::Arc;

use core::cmp::min;

use crate::frame_alloc::FrameAllocRef;
use crate::mm::page_cache::{AddressSpaceOps, FileId, PAGE_SIZE};
use crate::storage::{BlockDevice, get_blkdev};
use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

// ============================================================================
// Block Device Address Space Operations
// ============================================================================

/// Block device address space operations.
///
/// Implements page I/O for block devices. For RAM disk (can_writeback=false),
/// writepage is never called since dirty pages are permanent storage.
///
/// ## Locking Context
///
/// - Called with per-page lock held (CachedPage.locked)
/// - PAGE_CACHE mutex is NOT held - must not be acquired
/// - May acquire block device queue locks for actual I/O
pub struct BlkdevAddressSpaceOps;

impl AddressSpaceOps for BlkdevAddressSpaceOps {
    fn readpage(&self, _file_id: FileId, _page_offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        // For ramdisk: new pages start as zeros
        // For real disk: this would submit a read bio to the block device
        //
        // Currently we only have ramdisk, so just zero the buffer.
        // When we add real block devices (AHCI, NVMe), this will:
        // 1. Get the BlockDevice from file_id
        // 2. Create a bio for the read
        // 3. Submit to the device and wait for completion
        buf.fill(0);
        Ok(buf.len())
    }

    fn writepage(&self, _file_id: FileId, _page_offset: u64, buf: &[u8]) -> Result<usize, i32> {
        // For ramdisk: can_writeback=false, so this is never called
        // For real disk: this would submit a write bio to the block device
        //
        // Currently we only have ramdisk which uses can_writeback=false.
        // When we add real block devices, this will:
        // 1. Get the BlockDevice from file_id
        // 2. Create a bio for the write
        // 3. Submit to the device and wait for completion
        Ok(buf.len())
    }
}

/// Global block device address space ops instance
pub static BLKDEV_AOPS: BlkdevAddressSpaceOps = BlkdevAddressSpaceOps;

use super::file::{File, FileOps, seek};
use crate::error::KernelError;


/// Block device file operations
///
/// Implements FileOps for block special files, routing I/O through
/// the page cache for caching and the block layer for actual I/O.
pub struct BlockFileOps;

impl BlockFileOps {
    /// Get the BlockDevice from a file's inode rdev
    fn get_bdev(file: &File) -> Result<Arc<BlockDevice>, KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        get_blkdev(inode.rdev).ok_or(KernelError::NotFound)
    }

    /// Get FileId for a block device's page cache
    fn file_id_for_bdev(bdev: &BlockDevice) -> FileId {
        let dev_id = bdev.dev_id();
        FileId::from_blkdev(dev_id.major, dev_id.minor)
    }

    /// Get or allocate a page from the page cache for a block device
    ///
    /// Returns the page frame address. The page is guaranteed to be
    /// in the cache after this call.
    ///
    /// Uses `find_or_create_page()` to atomically find or create the page,
    /// preventing the TOCTOU race that could occur with separate lookup and add.
    fn get_page(bdev: &BlockDevice, page_offset: u64) -> Result<u64, KernelError> {
        let file_id = Self::file_id_for_bdev(bdev);
        let capacity = bdev.capacity();

        // Atomically find or create the page (single lock acquisition)
        let mut cache = PAGE_CACHE.lock();
        let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

        // For RAM disk with can_writeback = false, dirty pages are never evicted
        // This makes the page cache the actual storage
        let can_writeback = false; // RAM disk: page cache IS the storage
        let unevictable = false; // Block device pages can still be evicted if clean

        let (page, _is_new) = cache.find_or_create_page(
            file_id,
            page_offset,
            capacity,
            &mut frame_alloc,
            can_writeback,
            unevictable,
            &BLKDEV_AOPS,
        )?;

        Ok(page.frame)
    }

    /// Mark a page as dirty in the cache
    fn mark_page_dirty(bdev: &BlockDevice, page_offset: u64) {
        let file_id = Self::file_id_for_bdev(bdev);

        let cache = PAGE_CACHE.lock();
        if let Some(page) = cache.find_get_page(file_id, page_offset) {
            page.mark_dirty();
            // Decrement the refcount we just added with find_get_page
            cache.put_page(&page);
        }
    }
}

impl FileOps for BlockFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let bdev = Self::get_bdev(file)?;
        let pos = file.get_pos();
        let capacity = bdev.capacity();

        // EOF check
        if pos >= capacity {
            return Ok(0);
        }

        let available = (capacity - pos) as usize;
        let to_read = min(buf.len(), available);

        if to_read == 0 {
            return Ok(0);
        }

        let mut bytes_read = 0;

        while bytes_read < to_read {
            let current_pos = pos + bytes_read as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
            let chunk_size = min(PAGE_SIZE - offset_in_page, to_read - bytes_read);

            // Get the page from cache (allocates if needed)
            let frame = Self::get_page(&bdev, page_offset)?;

            // Copy data from page to user buffer
            unsafe {
                let src = (frame as *const u8).add(offset_in_page);
                core::ptr::copy_nonoverlapping(src, buf[bytes_read..].as_mut_ptr(), chunk_size);
            }

            bytes_read += chunk_size;
        }

        // Advance file position
        file.advance_pos(bytes_read as u64);

        Ok(bytes_read)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        let bdev = Self::get_bdev(file)?;
        let pos = file.get_pos();
        let capacity = bdev.capacity();

        // Cannot write past end of block device
        if pos >= capacity {
            return Err(KernelError::InvalidArgument);
        }

        let available = (capacity - pos) as usize;
        let to_write = min(buf.len(), available);

        if to_write == 0 {
            return Ok(0);
        }

        let mut bytes_written = 0;

        while bytes_written < to_write {
            let current_pos = pos + bytes_written as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
            let chunk_size = min(PAGE_SIZE - offset_in_page, to_write - bytes_written);

            // Get the page from cache (allocates if needed)
            let frame = Self::get_page(&bdev, page_offset)?;

            // Copy data from user buffer to page
            unsafe {
                let dst = (frame as *mut u8).add(offset_in_page);
                core::ptr::copy_nonoverlapping(buf[bytes_written..].as_ptr(), dst, chunk_size);
            }

            // Mark page as dirty
            Self::mark_page_dirty(&bdev, page_offset);

            bytes_written += chunk_size;
        }

        // Advance file position
        file.advance_pos(bytes_written as u64);

        Ok(bytes_written)
    }

    fn pread(&self, file: &File, buf: &mut [u8], offset: u64) -> Result<usize, KernelError> {
        let bdev = Self::get_bdev(file)?;
        let pos = offset;
        let capacity = bdev.capacity();

        // EOF check
        if pos >= capacity {
            return Ok(0);
        }

        let available = (capacity - pos) as usize;
        let to_read = min(buf.len(), available);

        if to_read == 0 {
            return Ok(0);
        }

        let mut bytes_read = 0;

        while bytes_read < to_read {
            let current_pos = pos + bytes_read as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
            let chunk_size = min(PAGE_SIZE - offset_in_page, to_read - bytes_read);

            // Get the page from cache (allocates if needed)
            let frame = Self::get_page(&bdev, page_offset)?;

            // Copy data from page to user buffer
            unsafe {
                let src = (frame as *const u8).add(offset_in_page);
                core::ptr::copy_nonoverlapping(src, buf[bytes_read..].as_mut_ptr(), chunk_size);
            }

            bytes_read += chunk_size;
        }

        // NOTE: Unlike read(), we do NOT advance file position
        Ok(bytes_read)
    }

    fn pwrite(&self, file: &File, buf: &[u8], offset: u64) -> Result<usize, KernelError> {
        let bdev = Self::get_bdev(file)?;
        let pos = offset;
        let capacity = bdev.capacity();

        // Cannot write past end of block device
        if pos >= capacity {
            return Err(KernelError::InvalidArgument);
        }

        let available = (capacity - pos) as usize;
        let to_write = min(buf.len(), available);

        if to_write == 0 {
            return Ok(0);
        }

        let mut bytes_written = 0;

        while bytes_written < to_write {
            let current_pos = pos + bytes_written as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
            let chunk_size = min(PAGE_SIZE - offset_in_page, to_write - bytes_written);

            // Get the page from cache (allocates if needed)
            let frame = Self::get_page(&bdev, page_offset)?;

            // Copy data from user buffer to page
            unsafe {
                let dst = (frame as *mut u8).add(offset_in_page);
                core::ptr::copy_nonoverlapping(buf[bytes_written..].as_ptr(), dst, chunk_size);
            }

            // Mark page as dirty
            Self::mark_page_dirty(&bdev, page_offset);

            bytes_written += chunk_size;
        }

        // NOTE: Unlike write(), we do NOT advance file position
        Ok(bytes_written)
    }

    fn llseek(&self, file: &File, offset: i64, whence: i32) -> Result<u64, KernelError> {
        let bdev = Self::get_bdev(file)?;
        let capacity = bdev.capacity();

        let new_pos = match whence {
            seek::SEEK_SET => {
                if offset < 0 {
                    return Err(KernelError::InvalidArgument);
                }
                offset as u64
            }
            seek::SEEK_CUR => {
                let cur = file.get_pos();
                if offset < 0 {
                    cur.checked_sub((-offset) as u64)
                        .ok_or(KernelError::InvalidArgument)?
                } else {
                    cur.saturating_add(offset as u64)
                }
            }
            seek::SEEK_END => {
                if offset > 0 {
                    capacity.saturating_add(offset as u64)
                } else {
                    capacity
                        .checked_sub((-offset) as u64)
                        .ok_or(KernelError::InvalidArgument)?
                }
            }
            _ => return Err(KernelError::InvalidArgument),
        };

        file.set_pos(new_pos);
        Ok(new_pos)
    }

    fn fsync(&self, file: &File) -> Result<(), KernelError> {
        use crate::mm::writeback::{WritebackControl, do_writepages_for_file, wait_on_writeback};

        let bdev = Self::get_bdev(file)?;
        let file_id = Self::file_id_for_bdev(&bdev);

        // Write all dirty pages using the writeback module
        // (proper writeback flag tracking and async I/O support)
        let mut wbc = WritebackControl::for_fsync();
        do_writepages_for_file(file_id, &mut wbc).map_err(|_| KernelError::Io)?;

        // Wait for all writeback to complete
        wait_on_writeback(file_id);

        Ok(())
    }
}

/// Static block file ops instance
pub static BLOCK_FILE_OPS: BlockFileOps = BlockFileOps;
