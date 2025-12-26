//! VFAT Filesystem Implementation
//!
//! VFAT driver for mounting FAT32 filesystems on block devices.
//!
//! ## Features
//! - FAT32 filesystem support (FAT12/16 planned for future)
//! - VFAT long filename support
//! - Read and write access
//!
//! ## On-Disk Format
//! FAT32 uses:
//! - Boot sector with BIOS Parameter Block (BPB)
//! - File Allocation Table (FAT) for cluster chains
//! - 32-byte directory entries with optional long filename entries

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::frame_alloc::FrameAllocRef;
use crate::mm::page_cache::{AddressSpaceOps, FileId, PAGE_SIZE};
use crate::storage::{BlockDevice, DevId, get_blkdev};
use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

use super::dentry::Dentry;
use super::file::{
    DirEntry as VfsDirEntry, File, FileOps, generic_file_pread, generic_file_pwrite,
    generic_file_read, generic_file_write,
};
use super::inode::{AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::superblock::{
    FileSystemType, MSDOS_SUPER_MAGIC, StatFs, SuperBlock, SuperBlockData, SuperOps, fs_flags,
};
use super::vfs::FsError;

// ============================================================================
// VFAT AddressSpaceOps - Page I/O for writeback
// ============================================================================

/// VFAT address space operations for page cache writeback
///
/// Provides readpage/writepage implementations that translate FileId
/// to block device and perform I/O via the block driver.
pub struct VfatAddressSpaceOps;

impl AddressSpaceOps for VfatAddressSpaceOps {
    fn readpage(&self, file_id: FileId, page_offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        // Decode FileId to get block device
        let (major, minor) = file_id.to_blkdev().ok_or(-5)?; // EIO if not blkdev
        let bdev = get_blkdev(DevId::new(major, minor)).ok_or(-5)?;

        // Read from block device (new slice-based API)
        bdev.disk
            .queue
            .driver()
            .readpage(&bdev.disk, buf, page_offset);

        Ok(PAGE_SIZE)
    }

    fn writepage(&self, file_id: FileId, page_offset: u64, buf: &[u8]) -> Result<usize, i32> {
        // Decode FileId to get block device
        let (major, minor) = file_id.to_blkdev().ok_or(-5)?; // EIO if not blkdev
        let bdev = get_blkdev(DevId::new(major, minor)).ok_or(-5)?;

        // Write to block device (new slice-based API)
        bdev.disk
            .queue
            .driver()
            .writepage(&bdev.disk, buf, page_offset);

        Ok(PAGE_SIZE)
    }
}

/// Global VFAT address space ops instance (for block device pages)
pub static VFAT_AOPS: VfatAddressSpaceOps = VfatAddressSpaceOps;

// ============================================================================
// VFAT File AddressSpaceOps - Page I/O for file pages
// ============================================================================

/// VFAT file address space operations for file page cache
///
/// This implements readpage/writepage for VFAT **file** pages (FileId 0x2000...).
/// Unlike VfatAddressSpaceOps (for block device pages), this translates file
/// page offsets to disk offsets via the FAT cluster chain.
///
/// ## Locking Context
///
/// These methods are called with:
/// - Per-page lock held (CachedPage.locked)
/// - PAGE_CACHE and AddressSpace.inner NOT held
///
/// This allows us to safely call read_bytes()/write_bytes() which acquire
/// PAGE_CACHE for block device pages (different FileId namespace: 0x8000...).
pub struct VfatFileAddressSpaceOps;

impl VfatFileAddressSpaceOps {
    /// Translate a file page offset to disk byte offset via cluster chain
    ///
    /// Returns (bdev, disk_byte_offset) or error.
    fn translate_offset(file_id: FileId, page_offset: u64) -> Result<(Arc<BlockDevice>, u64), i32> {
        // Decode the VFAT file FileId
        let (major, minor, start_cluster) = decode_vfat_file_id(file_id).ok_or(-5)?; // EIO

        // Get block device
        let bdev = get_blkdev(DevId::new(major as u16, minor as u16)).ok_or(-5)?;

        // Need to get superblock data to walk the cluster chain
        // We read the boot sector to get FAT parameters
        let sb_data = VfatFileAddressSpaceOps::read_sb_data(&bdev)?;

        // Convert page offset to cluster index within the file
        let bytes_per_page = PAGE_SIZE as u64;
        let file_byte_offset = page_offset * bytes_per_page;
        let cluster_index = file_byte_offset / sb_data.cluster_size as u64;

        // Walk the cluster chain to find the cluster for this offset
        let mut current_cluster = start_cluster;
        for _ in 0..cluster_index {
            if !is_valid_cluster(current_cluster) {
                return Err(-5); // EIO - tried to read past end of file
            }
            current_cluster =
                VfatFileAddressSpaceOps::get_fat_entry_cached(&bdev, &sb_data, current_cluster)?;
            if is_end_of_chain(current_cluster) {
                return Err(-5); // EIO - cluster chain shorter than expected
            }
        }

        if !is_valid_cluster(current_cluster) {
            return Err(-5); // EIO - invalid cluster
        }

        // Calculate disk byte offset
        let cluster_offset = (current_cluster as u64 - 2) * sb_data.cluster_size as u64;
        let data_region_offset = sb_data.data_start_sector * sb_data.bytes_per_sector as u64;
        let offset_within_cluster = file_byte_offset % sb_data.cluster_size as u64;
        let disk_byte_offset = data_region_offset + cluster_offset + offset_within_cluster;

        Ok((bdev, disk_byte_offset))
    }

    /// Read boot sector to get superblock data (used during a_ops callbacks)
    ///
    /// Uses read_bytes to go through the block device page cache, ensuring
    /// we see any cached updates to the boot sector.
    fn read_sb_data(bdev: &Arc<BlockDevice>) -> Result<VfatSbData, i32> {
        // Read boot sector (first 512 bytes) via page cache
        let mut boot_buf = [0u8; 512];
        read_bytes(bdev, 0, &mut boot_buf).map_err(|_| -5)?;

        // Parse boot sector
        let boot: VfatBootSector =
            unsafe { core::ptr::read_unaligned(boot_buf.as_ptr() as *const _) };

        let bytes_per_sector = boot.bytes_per_sector as u32;
        let sectors_per_cluster = boot.sectors_per_cluster as u32;
        let fat_start_sector = boot.reserved_sector_count as u64;
        let fat_sectors = if boot.fat_size_16 != 0 {
            boot.fat_size_16 as u64
        } else {
            boot.fat_size_32 as u64
        };
        let num_fats = boot.num_fats as u64;
        let data_start_sector = fat_start_sector + (fat_sectors * num_fats);

        Ok(VfatSbData {
            bdev: Arc::new(BlockDevice::new(bdev.disk.clone())), // Temporary Arc, just for data
            bytes_per_sector,
            sectors_per_cluster,
            fat_start_sector,
            fat_sectors,
            data_start_sector,
            root_cluster: boot.root_cluster,
            cluster_size: bytes_per_sector * sectors_per_cluster,
        })
    }

    /// Read a FAT entry via page cache
    ///
    /// Uses read_bytes to go through the block device page cache, ensuring
    /// we see any cached updates to the FAT table.
    ///
    /// This is safe to call from file AddressSpaceOps because file pages
    /// (FileId 0x2000_xxxx) and block device pages (FileId 0x8000_xxxx)
    /// are in different namespaces, so there's no recursion.
    fn get_fat_entry_cached(
        bdev: &Arc<BlockDevice>,
        sb_data: &VfatSbData,
        cluster: u32,
    ) -> Result<u32, i32> {
        let fat_offset = (cluster as u64) * 4;
        let fat_byte_offset =
            sb_data.fat_start_sector * sb_data.bytes_per_sector as u64 + fat_offset;

        // Read the 4-byte FAT entry via page cache
        let mut fat_entry_buf = [0u8; 4];
        read_bytes(bdev, fat_byte_offset, &mut fat_entry_buf).map_err(|_| -5)?;

        Ok(u32::from_le_bytes(fat_entry_buf) & 0x0FFF_FFFF)
    }
}

impl AddressSpaceOps for VfatFileAddressSpaceOps {
    fn readpage(&self, file_id: FileId, page_offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        // Translate file offset to disk offset
        let (bdev, disk_byte_offset) =
            VfatFileAddressSpaceOps::translate_offset(file_id, page_offset)?;

        // Read from block device via page cache to ensure we see cached writes
        // (e.g., zeros written by truncate extend)
        read_bytes(&bdev, disk_byte_offset, buf).map_err(|_| -5)?;

        Ok(PAGE_SIZE)
    }

    fn writepage(&self, file_id: FileId, page_offset: u64, buf: &[u8]) -> Result<usize, i32> {
        // Translate file offset to disk offset
        let (bdev, disk_byte_offset) =
            VfatFileAddressSpaceOps::translate_offset(file_id, page_offset)?;

        // Write to block device via page cache
        write_bytes(&bdev, disk_byte_offset, buf).map_err(|_| -5)?;

        Ok(PAGE_SIZE)
    }
}

/// Global VFAT file address space ops instance (for file pages)
pub static VFAT_FILE_AOPS: VfatFileAddressSpaceOps = VfatFileAddressSpaceOps;

// ============================================================================
// VFAT On-Disk Structures
// ============================================================================

/// VFAT Boot Sector / BIOS Parameter Block (BPB)
///
/// This is the first 512 bytes of a FAT32 volume.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct VfatBootSector {
    /// Jump instruction to boot code
    pub jump_boot: [u8; 3],
    /// OEM name
    pub oem_name: [u8; 8],
    /// Bytes per sector (usually 512)
    pub bytes_per_sector: u16,
    /// Sectors per cluster
    pub sectors_per_cluster: u8,
    /// Reserved sector count (before first FAT)
    pub reserved_sector_count: u16,
    /// Number of FATs (usually 2)
    pub num_fats: u8,
    /// Root entry count (0 for FAT32)
    pub root_entry_count: u16,
    /// Total sectors 16-bit (0 for FAT32)
    pub total_sectors_16: u16,
    /// Media type
    pub media_type: u8,
    /// FAT size 16-bit (0 for FAT32)
    pub fat_size_16: u16,
    /// Sectors per track
    pub sectors_per_track: u16,
    /// Number of heads
    pub num_heads: u16,
    /// Hidden sectors
    pub hidden_sectors: u32,
    /// Total sectors 32-bit
    pub total_sectors_32: u32,
    // FAT32 extended BPB
    /// FAT size 32-bit (sectors per FAT)
    pub fat_size_32: u32,
    /// Extended flags
    pub ext_flags: u16,
    /// Filesystem version
    pub fs_version: u16,
    /// Root directory cluster
    pub root_cluster: u32,
    /// FSInfo sector number
    pub fs_info: u16,
    /// Backup boot sector
    pub backup_boot_sector: u16,
    /// Reserved
    pub reserved: [u8; 12],
    /// Drive number
    pub drive_number: u8,
    /// Reserved
    pub reserved1: u8,
    /// Boot signature (0x29)
    pub boot_signature: u8,
    /// Volume ID
    pub volume_id: u32,
    /// Volume label
    pub volume_label: [u8; 11],
    /// Filesystem type string ("FAT32   ")
    pub fs_type: [u8; 8],
}

/// VFAT Directory Entry (32 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct VfatDirEntry {
    /// Short name (8.3 format, space padded)
    pub name: [u8; 8],
    /// Extension (3 chars, space padded)
    pub ext: [u8; 3],
    /// Attributes
    pub attr: u8,
    /// Reserved for NT
    pub nt_reserved: u8,
    /// Creation time tenths of second
    pub create_time_tenth: u8,
    /// Creation time
    pub create_time: u16,
    /// Creation date
    pub create_date: u16,
    /// Last access date
    pub access_date: u16,
    /// First cluster high 16 bits
    pub first_cluster_hi: u16,
    /// Last modification time
    pub write_time: u16,
    /// Last modification date
    pub write_date: u16,
    /// First cluster low 16 bits
    pub first_cluster_lo: u16,
    /// File size in bytes
    pub file_size: u32,
}

/// VFAT Long Filename Entry (32 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct VfatLfnEntry {
    /// Sequence number (0x01-0x14, OR'd with 0x40 for last entry)
    pub order: u8,
    /// Name characters 1-5 (UCS-2)
    pub name1: [u16; 5],
    /// Attribute (always 0x0F for LFN)
    pub attr: u8,
    /// Entry type (0 for LFN)
    pub entry_type: u8,
    /// Checksum of short name
    pub checksum: u8,
    /// Name characters 6-11 (UCS-2)
    pub name2: [u16; 6],
    /// First cluster (always 0 for LFN)
    pub first_cluster: u16,
    /// Name characters 12-13 (UCS-2)
    pub name3: [u16; 2],
}

/// Directory entry attributes
pub mod attr {
    /// Read-only file
    pub const READ_ONLY: u8 = 0x01;
    /// Hidden file
    pub const HIDDEN: u8 = 0x02;
    /// System file
    pub const SYSTEM: u8 = 0x04;
    /// Volume label
    pub const VOLUME_ID: u8 = 0x08;
    /// Directory
    pub const DIRECTORY: u8 = 0x10;
    /// Archive (file needs backup)
    pub const ARCHIVE: u8 = 0x20;
    /// Long filename entry (combination of special flags)
    pub const LONG_NAME: u8 = READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID;
    /// Mask for long filename detection
    pub const LONG_NAME_MASK: u8 = LONG_NAME | DIRECTORY | ARCHIVE;
}

/// Deleted entry marker
const DELETED_MARKER: u8 = 0xE5;
/// End of directory marker
const END_MARKER: u8 = 0x00;
/// Kanji lead byte marker (actually 0xE5)
const KANJI_MARKER: u8 = 0x05;

// ============================================================================
// VFAT Filesystem State
// ============================================================================

/// VFAT superblock data (stored in SuperBlock.private)
#[derive(Clone)]
pub struct VfatSbData {
    /// Underlying block device
    pub bdev: Arc<BlockDevice>,
    /// Bytes per sector (usually 512)
    pub bytes_per_sector: u32,
    /// Sectors per cluster
    pub sectors_per_cluster: u32,
    /// First sector of the first FAT
    pub fat_start_sector: u64,
    /// Size of each FAT in sectors
    pub fat_sectors: u64,
    /// First sector of the data region
    pub data_start_sector: u64,
    /// Root directory cluster
    pub root_cluster: u32,
    /// Cluster size in bytes
    pub cluster_size: u32,
}

impl SuperBlockData for VfatSbData {}

impl AsAny for VfatSbData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// VFAT inode data (stored in Inode.private)
pub struct VfatInodeData {
    /// Starting cluster number (0 for root with fixed location)
    pub start_cluster: u32,
    /// File size in bytes (0 for directories)
    pub file_size: u32,
    /// Is this a directory?
    pub is_dir: bool,
    /// Parent directory's cluster (for directory entry updates)
    pub parent_cluster: u32,
    /// Short name for directory entry lookup (8+3 format)
    pub short_name: [u8; 11],
    /// FileId for page cache (unique per file)
    pub file_id: FileId,
}

impl InodeData for VfatInodeData {}

impl AsAny for VfatInodeData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Create a unique FileId for a VFAT file
///
/// Format: 0x2000_0000_0000_0000 | (major << 40) | (minor << 32) | (start_cluster)
///
/// This namespace (0x2000...) is distinct from block device FileIds (0x8000...)
/// which prevents deadlocks when file readpage calls block device read_bytes.
///
/// We encode start_cluster (not inode number) because readpage needs to traverse
/// the cluster chain, and start_cluster is all we need for that.
fn vfat_file_id(dev: DevId, start_cluster: u32) -> FileId {
    FileId::new(
        0x2000_0000_0000_0000
            | ((dev.major as u64) << 40)
            | ((dev.minor as u64) << 32)
            | (start_cluster as u64),
    )
}

/// Decode a VFAT file FileId to extract device info and start cluster
///
/// Returns (major, minor, start_cluster) or None if not a VFAT file FileId
fn decode_vfat_file_id(file_id: FileId) -> Option<(u8, u8, u32)> {
    let raw = file_id.0;
    if (raw >> 60) != 0x2 {
        return None;
    }
    let major = ((raw >> 40) & 0xFF) as u8;
    let minor = ((raw >> 32) & 0xFF) as u8;
    let start_cluster = (raw & 0xFFFF_FFFF) as u32;
    Some((major, minor, start_cluster))
}

// ============================================================================
// Block Device I/O
// ============================================================================

/// Read bytes from block device via page cache
fn read_bytes(bdev: &BlockDevice, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
    let file_id = FileId::from_blkdev(bdev.dev_id().major, bdev.dev_id().minor);
    let capacity = bdev.capacity();

    let mut pos = offset;
    let mut remaining = buf.len();
    let mut buf_offset = 0;

    while remaining > 0 {
        let page_offset = pos / PAGE_SIZE as u64;
        let offset_in_page = (pos % PAGE_SIZE as u64) as usize;
        let chunk_size = core::cmp::min(remaining, PAGE_SIZE - offset_in_page);

        // Get or allocate page from cache atomically
        // Using find_or_create_page() prevents TOCTOU race
        let (frame, needs_read) = {
            let mut cache = PAGE_CACHE.lock();
            let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);
            // Use VFAT_AOPS for disk-backed page cache with writeback support
            let (page, is_new) = cache
                .find_or_create_page(
                    file_id,
                    page_offset,
                    capacity,
                    &mut frame_alloc,
                    true,  // can_writeback for vfat
                    false, // not unevictable (disk-backed)
                    &VFAT_AOPS,
                )
                .map_err(|_| FsError::IoError)?;
            (page.frame, is_new)
        };

        // Read from block device AFTER releasing the lock
        if needs_read {
            let page_buf = unsafe { core::slice::from_raw_parts_mut(frame as *mut u8, PAGE_SIZE) };
            bdev.disk
                .queue
                .driver()
                .readpage(&bdev.disk, page_buf, page_offset);
        }

        // Copy data from page to buffer
        unsafe {
            core::ptr::copy_nonoverlapping(
                (frame as *const u8).add(offset_in_page),
                buf.as_mut_ptr().add(buf_offset),
                chunk_size,
            );
        }

        pos += chunk_size as u64;
        buf_offset += chunk_size;
        remaining -= chunk_size;
    }

    Ok(())
}

/// Write bytes to block device via page cache (LAZY WRITEBACK)
///
/// Data is written to the page cache and marked dirty. The actual disk write
/// happens later via:
/// - Periodic writeback daemon (every ~5 seconds)
/// - Explicit fsync() or sync() calls
/// - Page cache eviction pressure
fn write_bytes(bdev: &BlockDevice, offset: u64, buf: &[u8]) -> Result<(), FsError> {
    use crate::mm::page_cache::DIRTY_ADDRESS_SPACES;

    let file_id = FileId::from_blkdev(bdev.dev_id().major, bdev.dev_id().minor);
    let capacity = bdev.capacity();

    let mut pos = offset;
    let mut remaining = buf.len();
    let mut buf_offset = 0;

    while remaining > 0 {
        let page_offset = pos / PAGE_SIZE as u64;
        let offset_in_page = (pos % PAGE_SIZE as u64) as usize;
        let chunk_size = core::cmp::min(remaining, PAGE_SIZE - offset_in_page);

        // Get or allocate page from cache atomically
        let (page, needs_read) = {
            let mut cache = PAGE_CACHE.lock();
            let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);
            let (page, is_new) = cache
                .find_or_create_page(
                    file_id,
                    page_offset,
                    capacity,
                    &mut frame_alloc,
                    true,       // can_writeback for vfat
                    false,      // not unevictable (disk-backed)
                    &VFAT_AOPS, // Use VFAT ops for writeback
                )
                .map_err(|_| FsError::IoError)?;
            (page, is_new)
        };

        // If this is a partial page write and the page is new, read existing data first
        if needs_read && (offset_in_page != 0 || chunk_size != PAGE_SIZE) {
            let page_buf =
                unsafe { core::slice::from_raw_parts_mut(page.frame as *mut u8, PAGE_SIZE) };
            bdev.disk
                .queue
                .driver()
                .readpage(&bdev.disk, page_buf, page_offset);
        }

        // Write data to page
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr().add(buf_offset),
                (page.frame as *mut u8).add(offset_in_page),
                chunk_size,
            );
        }

        // Mark page as dirty - writeback daemon will flush later
        page.mark_dirty();

        // Track this address space as having dirty pages
        DIRTY_ADDRESS_SPACES.lock().insert(file_id);

        // Notify the device's BDI for per-device writeback scheduling
        bdev.disk.bdi.mark_dirty(file_id);

        // NO writepage() call here - lazy writeback!

        pos += chunk_size as u64;
        buf_offset += chunk_size;
        remaining -= chunk_size;
    }

    Ok(())
}

// ============================================================================
// VFAT Helpers
// ============================================================================

/// Get VFAT superblock data from superblock (cloned to avoid lifetime issues)
fn get_sb_data(sb: &Arc<SuperBlock>) -> Result<VfatSbData, FsError> {
    let guard = sb.private.read();
    guard
        .as_ref()
        .and_then(|p| p.as_any().downcast_ref::<VfatSbData>())
        .cloned()
        .ok_or(FsError::IoError)
}

/// Get VFAT inode data from inode (cloned to avoid lifetime issues)
fn get_inode_data(inode: &Inode) -> Result<VfatInodeData, FsError> {
    let private = inode.get_private().ok_or(FsError::IoError)?;
    let data = private
        .as_any()
        .downcast_ref::<VfatInodeData>()
        .ok_or(FsError::IoError)?;
    Ok(VfatInodeData {
        start_cluster: data.start_cluster,
        file_size: data.file_size,
        is_dir: data.is_dir,
        parent_cluster: data.parent_cluster,
        short_name: data.short_name,
        file_id: data.file_id,
    })
}

/// Read a FAT entry for a cluster
fn get_fat_entry(sb_data: &VfatSbData, cluster: u32) -> Result<u32, FsError> {
    let fat_offset = (cluster as u64) * 4;
    let fat_sector = sb_data.fat_start_sector + fat_offset / sb_data.bytes_per_sector as u64;
    let offset_in_sector = (fat_offset % sb_data.bytes_per_sector as u64) as usize;

    let byte_offset = fat_sector * sb_data.bytes_per_sector as u64 + offset_in_sector as u64;
    let mut buf = [0u8; 4];
    read_bytes(&sb_data.bdev, byte_offset, &mut buf)?;

    Ok(u32::from_le_bytes(buf) & 0x0FFF_FFFF)
}

/// Check if cluster number indicates end of chain
fn is_end_of_chain(cluster: u32) -> bool {
    cluster >= 0x0FFF_FFF8
}

/// Check if cluster is valid (not reserved, free, or bad)
fn is_valid_cluster(cluster: u32) -> bool {
    (2..0x0FFF_FFF0).contains(&cluster)
}

/// Convert cluster number to byte offset in data region
fn cluster_to_offset(sb_data: &VfatSbData, cluster: u32) -> u64 {
    let data_offset = (cluster as u64 - 2) * sb_data.cluster_size as u64;
    sb_data.data_start_sector * sb_data.bytes_per_sector as u64 + data_offset
}

/// Read a cluster chain starting from a cluster
fn read_cluster_chain(sb_data: &VfatSbData, start_cluster: u32) -> Result<Vec<u32>, FsError> {
    let mut chain = Vec::new();
    let mut cluster = start_cluster;

    while is_valid_cluster(cluster) {
        chain.push(cluster);
        cluster = get_fat_entry(sb_data, cluster)?;
        if is_end_of_chain(cluster) {
            break;
        }
        // Safety check against infinite loops
        if chain.len() > 1_000_000 {
            return Err(FsError::IoError);
        }
    }

    Ok(chain)
}

// ============================================================================
// FAT Table Write Operations
// ============================================================================

/// End of chain marker for FAT32
const FAT_EOC: u32 = 0x0FFF_FFF8;

/// Free cluster marker
const FAT_FREE: u32 = 0x0000_0000;

/// Write a FAT entry for a cluster (updates all FAT copies)
fn set_fat_entry(sb_data: &VfatSbData, cluster: u32, value: u32) -> Result<(), FsError> {
    let fat_offset = (cluster as u64) * 4;
    let offset_in_fat = fat_offset % (sb_data.fat_sectors * sb_data.bytes_per_sector as u64);

    // Preserve high 4 bits of existing entry (reserved bits in FAT32)
    let existing = get_fat_entry(sb_data, cluster)?;
    let new_value = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
    let buf = new_value.to_le_bytes();

    // Write to all FAT copies (typically 2)
    let num_fats = 2u64; // FAT32 standard
    for fat_num in 0..num_fats {
        let fat_start = sb_data.fat_start_sector + fat_num * sb_data.fat_sectors;
        let byte_offset = fat_start * sb_data.bytes_per_sector as u64 + offset_in_fat;
        write_bytes(&sb_data.bdev, byte_offset, &buf)?;
    }

    Ok(())
}

/// Find and allocate a free cluster
///
/// Searches the FAT for a free cluster (value 0), marks it as end-of-chain,
/// and returns the cluster number.
fn allocate_cluster(sb_data: &VfatSbData) -> Result<u32, FsError> {
    // Calculate total data clusters
    // Total sectors = fat_start + fat_sectors * num_fats + data_sectors
    // data_clusters = data_sectors / sectors_per_cluster
    let total_sectors = sb_data.bdev.capacity() / sb_data.bytes_per_sector as u64;
    let data_sectors = total_sectors.saturating_sub(sb_data.data_start_sector);
    let total_clusters = (data_sectors / sb_data.sectors_per_cluster as u64) as u32;

    // Search for free cluster (start from cluster 2, which is first data cluster)
    for cluster in 2..total_clusters + 2 {
        let entry = get_fat_entry(sb_data, cluster)?;
        if entry == FAT_FREE {
            // Found free cluster, mark as end-of-chain
            set_fat_entry(sb_data, cluster, FAT_EOC)?;

            // Zero the cluster data
            let cluster_offset = cluster_to_offset(sb_data, cluster);
            let zeros = vec![0u8; sb_data.cluster_size as usize];
            write_bytes(&sb_data.bdev, cluster_offset, &zeros)?;

            return Ok(cluster);
        }
    }

    Err(FsError::NoSpace)
}

/// Free a cluster chain starting from start_cluster
fn free_cluster_chain(sb_data: &VfatSbData, start_cluster: u32) -> Result<(), FsError> {
    let mut cluster = start_cluster;

    while is_valid_cluster(cluster) {
        let next = get_fat_entry(sb_data, cluster)?;
        set_fat_entry(sb_data, cluster, FAT_FREE)?;

        if is_end_of_chain(next) {
            break;
        }
        cluster = next;
    }

    Ok(())
}

/// Extend a cluster chain by allocating new clusters
///
/// If last_cluster is 0, allocates a new chain. Otherwise extends the existing chain.
/// Returns the vector of newly allocated clusters.
fn extend_cluster_chain(
    sb_data: &VfatSbData,
    last_cluster: u32,
    count: usize,
) -> Result<Vec<u32>, FsError> {
    let mut new_clusters = Vec::with_capacity(count);

    for i in 0..count {
        let cluster = allocate_cluster(sb_data)?;
        new_clusters.push(cluster);

        // Link to previous cluster
        if i == 0 && last_cluster != 0 {
            // Link from existing chain
            set_fat_entry(sb_data, last_cluster, cluster)?;
        } else if i > 0 {
            // Link from previous new cluster
            set_fat_entry(sb_data, new_clusters[i - 1], cluster)?;
        }
    }

    Ok(new_clusters)
}

/// Get the last cluster in a chain
#[allow(dead_code)]
fn get_last_cluster(sb_data: &VfatSbData, start_cluster: u32) -> Result<u32, FsError> {
    let mut cluster = start_cluster;
    let mut count = 0;

    while is_valid_cluster(cluster) {
        let next = get_fat_entry(sb_data, cluster)?;
        if is_end_of_chain(next) {
            return Ok(cluster);
        }
        cluster = next;
        count += 1;
        if count > 1_000_000 {
            return Err(FsError::IoError);
        }
    }

    // If start_cluster is 0 or invalid, return 0
    Ok(start_cluster)
}

// ============================================================================
// Directory Entry Parsing
// ============================================================================

/// Parsed directory entry with long name support
#[derive(Clone)]
pub struct ParsedDirEntry {
    /// Filename (long name if available, otherwise short name)
    pub name: String,
    /// Short name (8.3 format for directory entry lookup)
    pub short_name: [u8; 11],
    /// File attributes
    pub attr: u8,
    /// First cluster
    pub start_cluster: u32,
    /// File size
    pub file_size: u32,
}

impl ParsedDirEntry {
    /// Is this a directory?
    pub fn is_dir(&self) -> bool {
        (self.attr & attr::DIRECTORY) != 0
    }
}

/// Calculate checksum of 8.3 short name for LFN verification
fn lfn_checksum(name: &[u8; 8], ext: &[u8; 3]) -> u8 {
    let mut sum: u8 = 0;
    for &b in name.iter().chain(ext.iter()) {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

/// Convert short 8.3 name to string
fn short_name_to_string(name: &[u8; 8], ext: &[u8; 3]) -> String {
    let name_part: String = name
        .iter()
        .take_while(|&&b| b != b' ')
        .map(|&b| {
            // Handle Kanji marker
            if b == KANJI_MARKER {
                0xE5 as char
            } else {
                b as char
            }
        })
        .collect();

    let ext_part: String = ext
        .iter()
        .take_while(|&&b| b != b' ')
        .map(|&b| b as char)
        .collect();

    if ext_part.is_empty() {
        name_part
    } else {
        alloc::format!("{}.{}", name_part, ext_part)
    }
}

/// Extract characters from LFN entry
fn lfn_entry_chars(entry: &VfatLfnEntry) -> Vec<char> {
    let mut chars = Vec::with_capacity(13);

    // UCS-2 to char (simplified - just handles ASCII and common chars)
    let add_char = |chars: &mut Vec<char>, c: u16| {
        if c != 0xFFFF && c != 0x0000 {
            if c < 0x80 {
                chars.push(c as u8 as char);
            } else {
                // Non-ASCII - just use replacement character for now
                chars.push('?');
            }
        }
    };

    // Read fields safely from packed struct using read_unaligned
    // name1: 5 chars, name2: 6 chars, name3: 2 chars
    unsafe {
        let name1_ptr = core::ptr::addr_of!(entry.name1);
        let name2_ptr = core::ptr::addr_of!(entry.name2);
        let name3_ptr = core::ptr::addr_of!(entry.name3);

        for i in 0..5 {
            let c = core::ptr::read_unaligned((name1_ptr as *const u16).add(i));
            add_char(&mut chars, c);
        }
        for i in 0..6 {
            let c = core::ptr::read_unaligned((name2_ptr as *const u16).add(i));
            add_char(&mut chars, c);
        }
        for i in 0..2 {
            let c = core::ptr::read_unaligned((name3_ptr as *const u16).add(i));
            add_char(&mut chars, c);
        }
    }

    chars
}

/// Read and parse directory entries from a cluster chain
fn read_directory_entries(
    sb_data: &VfatSbData,
    start_cluster: u32,
) -> Result<Vec<ParsedDirEntry>, FsError> {
    let chain = read_cluster_chain(sb_data, start_cluster)?;
    let mut entries = Vec::new();
    let mut lfn_parts: Vec<(u8, Vec<char>)> = Vec::new();
    let mut lfn_checksum_expected: Option<u8> = None;

    for &cluster in &chain {
        let cluster_offset = cluster_to_offset(sb_data, cluster);
        let entries_per_cluster = sb_data.cluster_size as usize / 32;

        for i in 0..entries_per_cluster {
            let entry_offset = cluster_offset + (i as u64 * 32);
            let mut buf = [0u8; 32];
            read_bytes(&sb_data.bdev, entry_offset, &mut buf)?;

            // Check for end of directory
            if buf[0] == END_MARKER {
                return Ok(entries);
            }

            // Skip deleted entries
            if buf[0] == DELETED_MARKER {
                lfn_parts.clear();
                lfn_checksum_expected = None;
                continue;
            }

            let attr = buf[11];

            // Check if this is a long filename entry
            if (attr & attr::LONG_NAME_MASK) == attr::LONG_NAME {
                // Parse as LFN entry
                let lfn: VfatLfnEntry =
                    unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const _) };
                let order = lfn.order & 0x3F;
                let is_last = (lfn.order & 0x40) != 0;

                if is_last {
                    lfn_parts.clear();
                    lfn_checksum_expected = Some(lfn.checksum);
                }

                let chars = lfn_entry_chars(&lfn);
                lfn_parts.push((order, chars));
            } else {
                // Parse as regular directory entry
                let dirent: VfatDirEntry =
                    unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const _) };

                // Skip volume labels
                if (attr & attr::VOLUME_ID) != 0 {
                    lfn_parts.clear();
                    lfn_checksum_expected = None;
                    continue;
                }

                // Build the filename
                let name = if !lfn_parts.is_empty() {
                    // Verify checksum
                    let expected = lfn_checksum_expected.unwrap_or(0);
                    let actual = lfn_checksum(&dirent.name, &dirent.ext);

                    if expected == actual {
                        // Sort LFN parts by order and concatenate
                        lfn_parts.sort_by_key(|(order, _)| *order);
                        let long_name: String = lfn_parts
                            .iter()
                            .flat_map(|(_, chars)| chars.iter())
                            .collect();
                        long_name
                    } else {
                        // Checksum mismatch, use short name
                        short_name_to_string(&dirent.name, &dirent.ext)
                    }
                } else {
                    short_name_to_string(&dirent.name, &dirent.ext)
                };

                // Clear LFN state
                lfn_parts.clear();
                lfn_checksum_expected = None;

                // Skip "." and ".." entries
                if name == "." || name == ".." {
                    continue;
                }

                let start_cluster =
                    ((dirent.first_cluster_hi as u32) << 16) | (dirent.first_cluster_lo as u32);

                // Build short_name array from name (8 bytes) + ext (3 bytes)
                let mut short_name = [b' '; 11];
                short_name[0..8].copy_from_slice(&dirent.name);
                short_name[8..11].copy_from_slice(&dirent.ext);

                entries.push(ParsedDirEntry {
                    name,
                    short_name,
                    attr,
                    start_cluster,
                    file_size: dirent.file_size,
                });
            }
        }
    }

    Ok(entries)
}

// ============================================================================
// Directory Entry Write Operations
// ============================================================================

/// Characters invalid in FAT short names
#[allow(dead_code)]
const INVALID_SHORT_CHARS: &[u8] = b" .\"*+,/:;<=>?[\\]|";

/// Generate an 8.3 short name from a long filename
///
/// Returns an 11-byte array with 8 chars for name + 3 chars for extension,
/// both space-padded.
fn generate_short_name(long_name: &str, existing_short_names: &[[u8; 11]]) -> [u8; 11] {
    let result = [b' '; 11];

    // Find extension (last dot that isn't at the start)
    let (base, ext) = if let Some(dot_pos) = long_name.rfind('.') {
        if dot_pos > 0 {
            (&long_name[..dot_pos], &long_name[dot_pos + 1..])
        } else {
            (long_name, "")
        }
    } else {
        (long_name, "")
    };

    // Convert base to uppercase, remove invalid chars
    let clean_base: String = base
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                Some(c.to_ascii_uppercase())
            } else if c == ' ' || c == '.' {
                None // Skip spaces and extra dots
            } else {
                Some('_') // Replace other chars with underscore
            }
        })
        .collect();

    // Convert extension similarly
    let clean_ext: String = ext
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                Some(c.to_ascii_uppercase())
            } else {
                None
            }
        })
        .take(3)
        .collect();

    // Try simple 8.3 name first
    if clean_base.len() <= 8 && clean_ext.len() <= 3 {
        // Check if this would conflict
        let mut candidate = [b' '; 11];
        for (i, c) in clean_base.bytes().enumerate().take(8) {
            candidate[i] = c;
        }
        for (i, c) in clean_ext.bytes().enumerate().take(3) {
            candidate[8 + i] = c;
        }

        if !existing_short_names.contains(&candidate) {
            return candidate;
        }
    }

    // Need to generate a numeric tail (~1, ~2, etc.)
    let base_truncated: String = clean_base.chars().take(6).collect();

    for n in 1..=999999 {
        let suffix = alloc::format!("~{}", n);
        let base_with_suffix = alloc::format!(
            "{}{}",
            &base_truncated[..core::cmp::min(base_truncated.len(), 8 - suffix.len())],
            suffix
        );

        let mut candidate = [b' '; 11];
        for (i, c) in base_with_suffix.bytes().enumerate().take(8) {
            candidate[i] = c;
        }
        for (i, c) in clean_ext.bytes().enumerate().take(3) {
            candidate[8 + i] = c;
        }

        if !existing_short_names.contains(&candidate) {
            return candidate;
        }
    }

    // Fallback (should never happen with 999999 attempts)
    result
}

/// Calculate checksum of 8.3 short name (11-byte format)
fn short_name_checksum(short_name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in short_name.iter() {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

/// Create LFN entries for a filename
///
/// Returns vector of LFN entries in reverse order (highest sequence number first).
fn create_lfn_entries(name: &str, short_name: &[u8; 11]) -> Vec<VfatLfnEntry> {
    let checksum = short_name_checksum(short_name);

    // Convert name to UCS-2 (simplified: just use ASCII, pad rest with 0xFFFF)
    let ucs2_chars: Vec<u16> = name
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c as u16
            } else {
                '?' as u16 // Replace non-ASCII with ?
            }
        })
        .chain(core::iter::once(0u16)) // Null terminator
        .collect();

    // Pad to multiple of 13 with 0xFFFF
    let padded_len = ucs2_chars.len().div_ceil(13) * 13;
    let mut padded: Vec<u16> = ucs2_chars;
    padded.resize(padded_len, 0xFFFF);

    let num_entries = padded.len() / 13;
    let mut entries = Vec::with_capacity(num_entries);

    for i in 0..num_entries {
        let seq_num = (i + 1) as u8;
        let is_last = i == num_entries - 1;
        let order = if is_last { seq_num | 0x40 } else { seq_num };

        let chunk = &padded[i * 13..(i + 1) * 13];

        let mut entry = VfatLfnEntry {
            order,
            name1: [0u16; 5],
            attr: attr::LONG_NAME,
            entry_type: 0,
            checksum,
            name2: [0u16; 6],
            first_cluster: 0,
            name3: [0u16; 2],
        };

        // Copy chars to name fields (use unsafe for packed struct unaligned writes)
        // Use addr_of_mut! to avoid creating intermediate references to packed fields
        unsafe {
            use core::ptr::addr_of_mut;
            let name1_ptr = addr_of_mut!(entry.name1) as *mut u16;
            for (k, &c) in chunk[0..5].iter().enumerate() {
                name1_ptr.add(k).write_unaligned(c);
            }
            let name2_ptr = addr_of_mut!(entry.name2) as *mut u16;
            for (k, &c) in chunk[5..11].iter().enumerate() {
                name2_ptr.add(k).write_unaligned(c);
            }
            let name3_ptr = addr_of_mut!(entry.name3) as *mut u16;
            for (k, &c) in chunk[11..13].iter().enumerate() {
                name3_ptr.add(k).write_unaligned(c);
            }
        }

        entries.push(entry);
    }

    // Reverse so highest sequence number is first (this is how they're stored on disk)
    entries.reverse();
    entries
}

/// Find consecutive free directory entry slots
///
/// Returns (cluster, index) of the first slot. Slots may span multiple clusters.
/// If not enough space exists, may extend the directory by allocating new clusters.
fn find_free_dir_slots(
    sb_data: &VfatSbData,
    dir_cluster: u32,
    num_slots: usize,
) -> Result<(u32, usize), FsError> {
    let chain = read_cluster_chain(sb_data, dir_cluster)?;
    let entries_per_cluster = sb_data.cluster_size as usize / 32;

    let mut consecutive_free = 0;
    let mut first_free_cluster = 0u32;
    let mut first_free_index = 0usize;

    for (chain_idx, &cluster) in chain.iter().enumerate() {
        let cluster_offset = cluster_to_offset(sb_data, cluster);

        for i in 0..entries_per_cluster {
            let entry_offset = cluster_offset + (i as u64 * 32);
            let mut buf = [0u8; 1];
            read_bytes(&sb_data.bdev, entry_offset, &mut buf)?;

            let is_free = buf[0] == END_MARKER || buf[0] == DELETED_MARKER;

            if is_free {
                if consecutive_free == 0 {
                    first_free_cluster = cluster;
                    first_free_index = chain_idx * entries_per_cluster + i;
                }
                consecutive_free += 1;

                if consecutive_free >= num_slots {
                    return Ok((first_free_cluster, first_free_index));
                }
            } else {
                consecutive_free = 0;
            }
        }
    }

    // Not enough space - extend directory by allocating new cluster
    let last_cluster = *chain.last().unwrap_or(&dir_cluster);
    let new_clusters = extend_cluster_chain(sb_data, last_cluster, 1)?;

    if let Some(&new_cluster) = new_clusters.first() {
        // Initialize new cluster with end markers
        let mut end_markers = vec![0u8; sb_data.cluster_size as usize];
        // First byte of first entry should be END_MARKER (rest are zeros which is fine)
        end_markers[0] = END_MARKER;
        let new_cluster_offset = cluster_to_offset(sb_data, new_cluster);
        write_bytes(&sb_data.bdev, new_cluster_offset, &end_markers)?;

        let new_index = chain.len() * entries_per_cluster;
        return Ok((new_cluster, new_index));
    }

    Err(FsError::NoSpace)
}

/// Write a directory entry (raw 32-byte entry) at a specific position
fn write_raw_dir_entry(
    sb_data: &VfatSbData,
    dir_cluster: u32,
    entry_index: usize,
    entry_bytes: &[u8; 32],
) -> Result<(), FsError> {
    let chain = read_cluster_chain(sb_data, dir_cluster)?;
    let entries_per_cluster = sb_data.cluster_size as usize / 32;

    let cluster_idx = entry_index / entries_per_cluster;
    let index_in_cluster = entry_index % entries_per_cluster;

    if cluster_idx >= chain.len() {
        return Err(FsError::InvalidArgument);
    }

    let cluster = chain[cluster_idx];
    let cluster_offset = cluster_to_offset(sb_data, cluster);
    let entry_offset = cluster_offset + (index_in_cluster as u64 * 32);

    write_bytes(&sb_data.bdev, entry_offset, entry_bytes)
}

/// Create a new directory entry with LFN support
///
/// Creates the LFN entries followed by the short entry.
/// Returns the short name (8.3 format) that was generated.
fn create_dir_entry_with_lfn(
    sb_data: &VfatSbData,
    parent_cluster: u32,
    name: &str,
    attributes: u8,
    start_cluster: u32,
    file_size: u32,
) -> Result<[u8; 11], FsError> {
    // Get existing short names to avoid collisions
    let existing_entries = read_directory_entries(sb_data, parent_cluster)?;
    let existing_short_names: Vec<[u8; 11]> =
        existing_entries.iter().map(|e| e.short_name).collect();

    // Generate short name
    let short_name = generate_short_name(name, &existing_short_names);

    // Check if we need LFN entries
    let needs_lfn = {
        // Check if name fits in 8.3 format and matches the short name we generated
        let simple_short = generate_short_name(name, &[]);
        simple_short != short_name || name.len() > 12 || name.contains(' ')
    };

    let lfn_entries = if needs_lfn {
        create_lfn_entries(name, &short_name)
    } else {
        Vec::new()
    };

    let total_slots = lfn_entries.len() + 1; // LFN entries + 1 short entry

    // Find space
    let (_first_cluster, first_index) = find_free_dir_slots(sb_data, parent_cluster, total_slots)?;

    // Write LFN entries (they come first on disk, in reverse sequence order)
    for (i, lfn) in lfn_entries.iter().enumerate() {
        let entry_index = first_index + i;
        let mut entry_bytes = [0u8; 32];

        // Convert VfatLfnEntry to bytes (use unsafe for packed struct unaligned reads)
        // Use addr_of! to avoid creating intermediate references to packed fields
        entry_bytes[0] = lfn.order;
        // name1: 5 UCS-2 chars at offset 1
        unsafe {
            use core::ptr::addr_of;
            let name1_ptr = addr_of!(lfn.name1) as *const u16;
            for j in 0..5 {
                let c = name1_ptr.add(j).read_unaligned();
                let offset = 1 + j * 2;
                entry_bytes[offset..offset + 2].copy_from_slice(&c.to_le_bytes());
            }
        }
        entry_bytes[11] = lfn.attr;
        entry_bytes[12] = lfn.entry_type;
        entry_bytes[13] = lfn.checksum;
        // name2: 6 UCS-2 chars at offset 14
        unsafe {
            use core::ptr::addr_of;
            let name2_ptr = addr_of!(lfn.name2) as *const u16;
            for j in 0..6 {
                let c = name2_ptr.add(j).read_unaligned();
                let offset = 14 + j * 2;
                entry_bytes[offset..offset + 2].copy_from_slice(&c.to_le_bytes());
            }
        }
        // first_cluster at offset 26 (always 0 for LFN)
        unsafe {
            use core::ptr::addr_of;
            let fc_ptr = addr_of!(lfn.first_cluster);
            let fc = fc_ptr.read_unaligned();
            entry_bytes[26..28].copy_from_slice(&fc.to_le_bytes());
        }
        // name3: 2 UCS-2 chars at offset 28
        unsafe {
            use core::ptr::addr_of;
            let name3_ptr = addr_of!(lfn.name3) as *const u16;
            for j in 0..2 {
                let c = name3_ptr.add(j).read_unaligned();
                let offset = 28 + j * 2;
                entry_bytes[offset..offset + 2].copy_from_slice(&c.to_le_bytes());
            }
        }

        write_raw_dir_entry(sb_data, parent_cluster, entry_index, &entry_bytes)?;
    }

    // Write short entry
    let short_entry_index = first_index + lfn_entries.len();
    let mut short_bytes = [0u8; 32];

    // Name (8 bytes) + Extension (3 bytes)
    short_bytes[0..8].copy_from_slice(&short_name[0..8]);
    short_bytes[8..11].copy_from_slice(&short_name[8..11]);

    // Attributes
    short_bytes[11] = attributes;

    // Reserved, creation time (simplified: all zeros for now)
    // NT reserved at 12, create time tenth at 13
    // Create time at 14-15, create date at 16-17
    // Access date at 18-19
    // First cluster high at 20-21
    short_bytes[20..22].copy_from_slice(&((start_cluster >> 16) as u16).to_le_bytes());

    // Write time at 22-23, write date at 24-25
    // First cluster low at 26-27
    short_bytes[26..28].copy_from_slice(&(start_cluster as u16).to_le_bytes());

    // File size at 28-31
    short_bytes[28..32].copy_from_slice(&file_size.to_le_bytes());

    write_raw_dir_entry(sb_data, parent_cluster, short_entry_index, &short_bytes)?;

    Ok(short_name)
}

/// Update the file size in a directory entry
#[allow(dead_code)]
fn update_dir_entry_size(
    sb_data: &VfatSbData,
    parent_cluster: u32,
    name: &str,
    new_size: u32,
) -> Result<(), FsError> {
    let chain = read_cluster_chain(sb_data, parent_cluster)?;
    let entries_per_cluster = sb_data.cluster_size as usize / 32;

    // Search for the entry
    for &cluster in chain.iter() {
        let cluster_offset = cluster_to_offset(sb_data, cluster);

        for i in 0..entries_per_cluster {
            let entry_offset = cluster_offset + (i as u64 * 32);
            let mut buf = [0u8; 32];
            read_bytes(&sb_data.bdev, entry_offset, &mut buf)?;

            // Skip free/deleted entries
            if buf[0] == END_MARKER || buf[0] == DELETED_MARKER {
                continue;
            }

            // Skip LFN entries
            if buf[11] == attr::LONG_NAME {
                continue;
            }

            // Check if this matches our name (case-insensitive)
            let short_name = short_name_to_string(
                buf[0..8].try_into().unwrap(),
                buf[8..11].try_into().unwrap(),
            );
            if short_name.eq_ignore_ascii_case(name) {
                // Update size field at offset 28
                buf[28..32].copy_from_slice(&new_size.to_le_bytes());
                write_bytes(&sb_data.bdev, entry_offset, &buf)?;
                return Ok(());
            }
        }
    }

    Err(FsError::NotFound)
}

/// Update directory entry metadata (start_cluster and file_size) by short name
fn update_dir_entry_by_short_name(
    sb_data: &VfatSbData,
    parent_cluster: u32,
    short_name: &[u8; 11],
    new_start_cluster: u32,
    new_size: u32,
) -> Result<(), FsError> {
    let chain = read_cluster_chain(sb_data, parent_cluster)?;
    let entries_per_cluster = sb_data.cluster_size as usize / 32;

    // Search for the entry by short name
    for &cluster in chain.iter() {
        let cluster_offset = cluster_to_offset(sb_data, cluster);

        for i in 0..entries_per_cluster {
            let entry_offset = cluster_offset + (i as u64 * 32);
            let mut buf = [0u8; 32];
            read_bytes(&sb_data.bdev, entry_offset, &mut buf)?;

            // Skip free/deleted entries
            if buf[0] == END_MARKER || buf[0] == DELETED_MARKER {
                continue;
            }

            // Skip LFN entries
            if buf[11] == attr::LONG_NAME {
                continue;
            }

            // Check if this matches our short name exactly
            if &buf[0..11] == short_name {
                // Update start cluster high (offset 20-21)
                buf[20..22].copy_from_slice(&((new_start_cluster >> 16) as u16).to_le_bytes());
                // Update start cluster low (offset 26-27)
                buf[26..28].copy_from_slice(&(new_start_cluster as u16).to_le_bytes());
                // Update size field (offset 28-31)
                buf[28..32].copy_from_slice(&new_size.to_le_bytes());
                write_bytes(&sb_data.bdev, entry_offset, &buf)?;
                return Ok(());
            }
        }
    }

    Err(FsError::NotFound)
}

/// Delete a directory entry by marking it as deleted (0xE5)
fn delete_dir_entry(sb_data: &VfatSbData, parent_cluster: u32, name: &str) -> Result<u32, FsError> {
    let chain = read_cluster_chain(sb_data, parent_cluster)?;
    let entries_per_cluster = sb_data.cluster_size as usize / 32;

    let mut lfn_start: Option<(usize, usize)> = None; // (chain_idx, entry_in_cluster)
    let mut lfn_parts: Vec<(u8, Vec<char>)> = Vec::new(); // LFN parts: (order, chars)
    let mut lfn_checksum_expected: Option<u8> = None;

    // Search for the entry
    for (chain_idx, &cluster) in chain.iter().enumerate() {
        let cluster_offset = cluster_to_offset(sb_data, cluster);

        for i in 0..entries_per_cluster {
            let entry_offset = cluster_offset + (i as u64 * 32);
            let mut buf = [0u8; 32];
            read_bytes(&sb_data.bdev, entry_offset, &mut buf)?;

            // End of directory
            if buf[0] == END_MARKER {
                return Err(FsError::NotFound);
            }

            // Skip already deleted
            if buf[0] == DELETED_MARKER {
                lfn_start = None;
                lfn_parts.clear();
                lfn_checksum_expected = None;
                continue;
            }

            // Track and collect LFN entries
            let attr_byte = buf[11];
            if (attr_byte & attr::LONG_NAME_MASK) == attr::LONG_NAME {
                let lfn: VfatLfnEntry =
                    unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const _) };
                let order = lfn.order & 0x3F;
                let is_last = (lfn.order & 0x40) != 0;

                if is_last {
                    // Start of LFN sequence
                    lfn_start = Some((chain_idx, i));
                    lfn_parts.clear();
                    lfn_checksum_expected = Some(lfn.checksum);
                }

                let chars = lfn_entry_chars(&lfn);
                lfn_parts.push((order, chars));
                continue;
            }

            // Regular entry - check name (both short and long)
            let short_name = short_name_to_string(
                buf[0..8].try_into().unwrap(),
                buf[8..11].try_into().unwrap(),
            );

            // Build long filename if LFN entries were collected
            let long_name = if !lfn_parts.is_empty() {
                let expected = lfn_checksum_expected.unwrap_or(0);
                let actual = lfn_checksum(
                    buf[0..8].try_into().unwrap(),
                    buf[8..11].try_into().unwrap(),
                );
                if expected == actual {
                    lfn_parts.sort_by_key(|(order, _)| *order);
                    let ln: String = lfn_parts
                        .iter()
                        .flat_map(|(_, chars)| chars.iter())
                        .collect();
                    Some(ln)
                } else {
                    None
                }
            } else {
                None
            };

            // Clear LFN state for next entry
            let current_lfn_start = lfn_start.take();
            lfn_parts.clear();
            lfn_checksum_expected = None;

            // Check if either short name or long name matches
            let matches = short_name.eq_ignore_ascii_case(name)
                || long_name
                    .as_ref()
                    .is_some_and(|ln| ln.eq_ignore_ascii_case(name));

            if matches {
                // Restore lfn_start for deletion
                let lfn_start = current_lfn_start;
                // Found it! Get start cluster before deleting
                let cluster_hi = u16::from_le_bytes([buf[20], buf[21]]) as u32;
                let cluster_lo = u16::from_le_bytes([buf[26], buf[27]]) as u32;
                let start_cluster_to_free = (cluster_hi << 16) | cluster_lo;

                // Delete LFN entries if any
                if let Some((lfn_chain_idx, lfn_entry_idx)) = lfn_start {
                    let lfn_global_idx = lfn_chain_idx * entries_per_cluster + lfn_entry_idx;
                    let current_global_idx = chain_idx * entries_per_cluster + i;

                    for idx in lfn_global_idx..current_global_idx {
                        let c_idx = idx / entries_per_cluster;
                        let e_idx = idx % entries_per_cluster;
                        let c = chain[c_idx];
                        let off = cluster_to_offset(sb_data, c) + (e_idx as u64 * 32);

                        let mut del_buf = [0u8; 32];
                        read_bytes(&sb_data.bdev, off, &mut del_buf)?;
                        del_buf[0] = DELETED_MARKER;
                        write_bytes(&sb_data.bdev, off, &del_buf)?;
                    }
                }

                // Delete the short entry
                buf[0] = DELETED_MARKER;
                write_bytes(&sb_data.bdev, entry_offset, &buf)?;

                return Ok(start_cluster_to_free);
            }

            lfn_start = None;
        }
    }

    Err(FsError::NotFound)
}

// ============================================================================
// VFAT Inode Operations
// ============================================================================

/// VFAT inode operations
pub struct VfatInodeOps;

impl InodeOps for VfatInodeOps {
    fn lookup(&self, dir: &Inode, name: &str) -> Result<Arc<Inode>, FsError> {
        let sb = dir.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let inode_data = get_inode_data(dir)?;

        if !inode_data.is_dir {
            return Err(FsError::NotADirectory);
        }

        // Read directory entries
        let entries = read_directory_entries(&sb_data, inode_data.start_cluster)?;

        // Find matching entry (case-insensitive for FAT)
        for entry in entries {
            if entry.name.eq_ignore_ascii_case(name) {
                return create_inode_for_entry(&sb, &entry, inode_data.start_cluster);
            }
        }

        Err(FsError::NotFound)
    }

    fn readpage(&self, inode: &Inode, page_offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let sb = inode.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let inode_data = get_inode_data(inode)?;

        let file_size = inode_data.file_size as u64;
        let byte_offset = page_offset * PAGE_SIZE as u64;

        if byte_offset >= file_size {
            buf.fill(0);
            return Ok(0);
        }

        // Read cluster chain
        let chain = read_cluster_chain(&sb_data, inode_data.start_cluster)?;
        let cluster_size = sb_data.cluster_size as u64;

        // Find which cluster contains this offset
        let cluster_index = (byte_offset / cluster_size) as usize;
        if cluster_index >= chain.len() {
            buf.fill(0);
            return Ok(0);
        }

        // Read data from clusters
        let mut bytes_read = 0;
        let mut current_offset = byte_offset;

        while bytes_read < buf.len() && current_offset < file_size {
            let cluster_idx = (current_offset / cluster_size) as usize;
            if cluster_idx >= chain.len() {
                break;
            }

            let cluster = chain[cluster_idx];
            let offset_in_cluster = (current_offset % cluster_size) as usize;
            let cluster_remaining = cluster_size as usize - offset_in_cluster;
            let file_remaining = (file_size - current_offset) as usize;
            let buf_remaining = buf.len() - bytes_read;
            let chunk_size = core::cmp::min(
                core::cmp::min(cluster_remaining, file_remaining),
                buf_remaining,
            );

            let disk_offset = cluster_to_offset(&sb_data, cluster) + offset_in_cluster as u64;
            read_bytes(
                &sb_data.bdev,
                disk_offset,
                &mut buf[bytes_read..bytes_read + chunk_size],
            )?;

            bytes_read += chunk_size;
            current_offset += chunk_size as u64;
        }

        // Zero remaining buffer if we hit EOF
        if bytes_read < buf.len() {
            buf[bytes_read..].fill(0);
        }

        Ok(bytes_read)
    }

    fn writepage(&self, inode: &Inode, page_offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let sb = inode.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let inode_data = get_inode_data(inode)?;

        let byte_offset = page_offset * PAGE_SIZE as u64;

        // Get or extend cluster chain
        let mut chain = if inode_data.start_cluster != 0 {
            read_cluster_chain(&sb_data, inode_data.start_cluster)?
        } else {
            Vec::new()
        };

        let cluster_size = sb_data.cluster_size as u64;

        // Calculate how many clusters we need
        let end_offset = byte_offset + buf.len() as u64;
        let clusters_needed = end_offset.div_ceil(cluster_size) as usize;

        // Extend chain if needed
        let mut new_start_cluster: Option<u32> = None;
        if clusters_needed > chain.len() {
            let additional = clusters_needed - chain.len();
            let last_cluster = if chain.is_empty() {
                0
            } else {
                *chain.last().unwrap()
            };
            let new_clusters = extend_cluster_chain(&sb_data, last_cluster, additional)?;

            // If this was an empty file, record the new start cluster
            if chain.is_empty() && !new_clusters.is_empty() {
                new_start_cluster = Some(new_clusters[0]);
                chain = new_clusters;
            } else {
                chain.extend(new_clusters);
            }
        }

        // Write data to clusters
        let mut bytes_written = 0;
        let mut current_offset = byte_offset;

        while bytes_written < buf.len() {
            let cluster_idx = (current_offset / cluster_size) as usize;
            if cluster_idx >= chain.len() {
                break;
            }

            let cluster = chain[cluster_idx];
            let offset_in_cluster = (current_offset % cluster_size) as usize;
            let cluster_remaining = cluster_size as usize - offset_in_cluster;
            let buf_remaining = buf.len() - bytes_written;
            let chunk_size = core::cmp::min(cluster_remaining, buf_remaining);

            let disk_offset = cluster_to_offset(&sb_data, cluster) + offset_in_cluster as u64;
            write_bytes(
                &sb_data.bdev,
                disk_offset,
                &buf[bytes_written..bytes_written + chunk_size],
            )?;

            bytes_written += chunk_size;
            current_offset += chunk_size as u64;
        }

        // If we allocated a new start cluster for a previously empty file,
        // update the directory entry immediately AND the inode's private data
        if let Some(start_cluster) = new_start_cluster {
            // Calculate the new file size (might grow)
            let new_size = core::cmp::max(
                inode_data.file_size as u64,
                byte_offset + bytes_written as u64,
            ) as u32;

            // Update directory entry with new start_cluster and size
            if inode_data.parent_cluster != 0 {
                update_dir_entry_by_short_name(
                    &sb_data,
                    inode_data.parent_cluster,
                    &inode_data.short_name,
                    start_cluster,
                    new_size,
                )?;
            }

            // Also update the inode's private data so future reads use the correct cluster
            inode.set_private(Arc::new(VfatInodeData {
                start_cluster,
                file_size: new_size,
                is_dir: inode_data.is_dir,
                parent_cluster: inode_data.parent_cluster,
                short_name: inode_data.short_name,
                file_id: inode_data.file_id,
            }));
        }

        Ok(bytes_written)
    }

    fn create(&self, dir: &Inode, name: &str, mode: InodeMode) -> Result<Arc<Inode>, FsError> {
        let _ = mode; // FAT doesn't support Unix permissions
        let sb = dir.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let dir_inode_data = get_inode_data(dir)?;

        if !dir_inode_data.is_dir {
            return Err(FsError::NotADirectory);
        }

        // Check if file already exists
        let entries = read_directory_entries(&sb_data, dir_inode_data.start_cluster)?;
        for entry in &entries {
            if entry.name.eq_ignore_ascii_case(name) {
                return Err(FsError::AlreadyExists);
            }
        }

        // Create the file (no cluster allocation for empty file)
        let start_cluster = 0u32;
        let file_size = 0u32;
        let parent_cluster = dir_inode_data.start_cluster;

        // Create directory entry (function returns the generated short name)
        let short_name = create_dir_entry_with_lfn(
            &sb_data,
            parent_cluster,
            name,
            attr::ARCHIVE,
            start_cluster,
            file_size,
        )?;

        // Create and return the new inode
        let ino = sb.alloc_ino();
        let inode = Arc::new(Inode::new(
            ino,
            InodeMode::regular(0o644),
            0,
            0,
            0, // Empty file
            Timespec::ZERO,
            Arc::downgrade(&sb),
            &VFAT_INODE_OPS,
        ));

        inode.set_private(Arc::new(VfatInodeData {
            start_cluster,
            file_size,
            is_dir: false,
            parent_cluster,
            short_name,
            file_id: vfat_file_id(sb_data.bdev.dev_id(), start_cluster),
        }));

        Ok(inode)
    }

    fn mkdir(&self, dir: &Inode, name: &str, mode: InodeMode) -> Result<Arc<Inode>, FsError> {
        let _ = mode; // FAT doesn't support Unix permissions
        let sb = dir.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let dir_inode_data = get_inode_data(dir)?;

        if !dir_inode_data.is_dir {
            return Err(FsError::NotADirectory);
        }

        // Check if directory already exists
        let entries = read_directory_entries(&sb_data, dir_inode_data.start_cluster)?;
        for entry in &entries {
            if entry.name.eq_ignore_ascii_case(name) {
                return Err(FsError::AlreadyExists);
            }
        }

        // Allocate a cluster for the new directory
        let new_cluster = allocate_cluster(&sb_data)?;

        // Initialize directory with . and .. entries
        let cluster_offset = cluster_to_offset(&sb_data, new_cluster);
        let cluster_size = sb_data.cluster_size as usize;

        // Zero out the cluster first
        let zeros = vec![0u8; cluster_size];
        write_bytes(&sb_data.bdev, cluster_offset, &zeros)?;

        // Create . entry (points to self)
        let mut dot_entry = [0u8; 32];
        dot_entry[0..8].copy_from_slice(b".       ");
        dot_entry[8..11].copy_from_slice(b"   ");
        dot_entry[11] = attr::DIRECTORY;
        dot_entry[20..22].copy_from_slice(&((new_cluster >> 16) as u16).to_le_bytes());
        dot_entry[26..28].copy_from_slice(&(new_cluster as u16).to_le_bytes());
        write_bytes(&sb_data.bdev, cluster_offset, &dot_entry)?;

        // Create .. entry (points to parent)
        let mut dotdot_entry = [0u8; 32];
        dotdot_entry[0..8].copy_from_slice(b"..      ");
        dotdot_entry[8..11].copy_from_slice(b"   ");
        dotdot_entry[11] = attr::DIRECTORY;
        let parent_cluster = dir_inode_data.start_cluster;
        dotdot_entry[20..22].copy_from_slice(&((parent_cluster >> 16) as u16).to_le_bytes());
        dotdot_entry[26..28].copy_from_slice(&(parent_cluster as u16).to_le_bytes());
        write_bytes(&sb_data.bdev, cluster_offset + 32, &dotdot_entry)?;

        // Create entry in parent (function returns the generated short name)
        let short_name = create_dir_entry_with_lfn(
            &sb_data,
            parent_cluster,
            name,
            attr::DIRECTORY,
            new_cluster,
            0, // Directories have size 0 in FAT
        )?;

        // Create and return the new inode
        let ino = sb.alloc_ino();
        let inode = Arc::new(Inode::new(
            ino,
            InodeMode::directory(0o755),
            0,
            0,
            0,
            Timespec::ZERO,
            Arc::downgrade(&sb),
            &VFAT_INODE_OPS,
        ));

        inode.set_private(Arc::new(VfatInodeData {
            start_cluster: new_cluster,
            file_size: 0,
            is_dir: true,
            parent_cluster,
            short_name,
            file_id: vfat_file_id(sb_data.bdev.dev_id(), new_cluster),
        }));

        Ok(inode)
    }

    fn unlink(&self, dir: &Inode, name: &str) -> Result<(), FsError> {
        let sb = dir.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let dir_inode_data = get_inode_data(dir)?;

        if !dir_inode_data.is_dir {
            return Err(FsError::NotADirectory);
        }

        // Find the entry to ensure it exists and is a file
        let entries = read_directory_entries(&sb_data, dir_inode_data.start_cluster)?;
        let entry = entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or(FsError::NotFound)?;

        if entry.is_dir() {
            return Err(FsError::IsADirectory);
        }

        // Delete the directory entry
        let start_cluster = delete_dir_entry(&sb_data, dir_inode_data.start_cluster, name)?;

        // Free the cluster chain if the file had data
        if start_cluster != 0 {
            free_cluster_chain(&sb_data, start_cluster)?;
        }

        Ok(())
    }

    fn rmdir(&self, dir: &Inode, name: &str) -> Result<(), FsError> {
        let sb = dir.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let dir_inode_data = get_inode_data(dir)?;

        if !dir_inode_data.is_dir {
            return Err(FsError::NotADirectory);
        }

        // Find the entry to ensure it exists and is a directory
        let entries = read_directory_entries(&sb_data, dir_inode_data.start_cluster)?;
        let entry = entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or(FsError::NotFound)?;

        if !entry.is_dir() {
            return Err(FsError::NotADirectory);
        }

        // Check if directory is empty (only . and .. allowed)
        let child_entries = read_directory_entries(&sb_data, entry.start_cluster)?;
        for child in &child_entries {
            if child.name != "." && child.name != ".." {
                return Err(FsError::DirectoryNotEmpty);
            }
        }

        // Delete the directory entry
        let start_cluster = delete_dir_entry(&sb_data, dir_inode_data.start_cluster, name)?;

        // Free the cluster chain
        if start_cluster != 0 {
            free_cluster_chain(&sb_data, start_cluster)?;
        }

        Ok(())
    }

    fn truncate(&self, inode: &Inode, length: u64) -> Result<(), FsError> {
        let sb = inode.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let inode_data = get_inode_data(inode)?;

        // Directories cannot be truncated
        if inode_data.is_dir {
            return Err(FsError::IsADirectory);
        }

        // FAT32 file size limit is 4 GiB - 1 (u32::MAX)
        if length > u32::MAX as u64 {
            return Err(FsError::FileTooLarge);
        }

        let old_size = inode_data.file_size as u64;
        let new_size = length as u32;
        let cluster_size = sb_data.cluster_size as u64;

        // Calculate cluster counts
        let old_clusters = if old_size == 0 {
            0
        } else {
            old_size.div_ceil(cluster_size) as usize
        };
        let new_clusters = if length == 0 {
            0
        } else {
            length.div_ceil(cluster_size) as usize
        };

        let mut new_start_cluster = inode_data.start_cluster;

        if new_clusters < old_clusters {
            // Shrinking: truncate cluster chain
            if new_clusters == 0 {
                // Free all clusters
                if inode_data.start_cluster != 0 {
                    free_cluster_chain(&sb_data, inode_data.start_cluster)?;
                }
                new_start_cluster = 0;
            } else {
                // Keep first new_clusters, free the rest
                let chain = read_cluster_chain(&sb_data, inode_data.start_cluster)?;
                if new_clusters < chain.len() {
                    // Mark last kept cluster as end-of-chain
                    set_fat_entry(&sb_data, chain[new_clusters - 1], FAT_EOC)?;
                    // Free remaining clusters
                    free_cluster_chain(&sb_data, chain[new_clusters])?;
                }
                // If chain.len() <= new_clusters, the on-disk chain is already
                // at or below the target size (possibly due to FS inconsistency).
                // Nothing to free; the chain's last cluster should already be EOC.
            }
        } else if new_clusters > old_clusters {
            // Extending: allocate more clusters
            let additional = new_clusters - old_clusters;
            if inode_data.start_cluster == 0 {
                // File was empty, allocate new chain
                let new_chain = extend_cluster_chain(&sb_data, 0, additional)?;
                if !new_chain.is_empty() {
                    new_start_cluster = new_chain[0];
                    // Zero the new clusters
                    for &cluster in &new_chain {
                        let offset = cluster_to_offset(&sb_data, cluster);
                        let zeros = vec![0u8; cluster_size as usize];
                        write_bytes(&sb_data.bdev, offset, &zeros)?;
                    }
                }
            } else {
                // Extend existing chain
                let chain = read_cluster_chain(&sb_data, inode_data.start_cluster)?;
                let last = *chain.last().unwrap_or(&0);
                let new_chain = extend_cluster_chain(&sb_data, last, additional)?;
                // Zero the new clusters
                for &cluster in &new_chain {
                    let offset = cluster_to_offset(&sb_data, cluster);
                    let zeros = vec![0u8; cluster_size as usize];
                    write_bytes(&sb_data.bdev, offset, &zeros)?;
                }
            }
        }

        // When extending the file, zero the bytes between old_size and new_size
        // in any cached file pages. This is necessary because:
        // 1. New clusters are zeroed on disk, but may already be cached with stale data
        // 2. Extending within the same cluster doesn't allocate new clusters, so the
        //    region between old_size and new_size may contain garbage in the page cache
        //
        // We zero directly in cached pages (if any) and mark them dirty.
        // Pages not yet cached will read correctly from disk (new clusters are zeroed).
        if length > old_size {
            let file_id = inode_data.file_id;
            let page_size = PAGE_SIZE as u64;

            // Calculate which pages contain the extended region
            let first_page = old_size / page_size;
            let last_page = length.saturating_sub(1) / page_size;

            // Lock PAGE_CACHE to find cached pages
            let cache = PAGE_CACHE.lock();

            for page_num in first_page..=last_page {
                // Try to find this page in the cache
                if let Some(page) = cache.find_get_page(file_id, page_num) {
                    // Calculate byte range to zero within this page
                    let page_start = page_num * page_size;
                    let page_end = page_start + page_size;

                    // Zero from max(old_size, page_start) to min(new_size, page_end)
                    let zero_start = core::cmp::max(old_size, page_start);
                    let zero_end = core::cmp::min(length, page_end);

                    if zero_start < zero_end {
                        let offset_in_page = (zero_start - page_start) as usize;
                        let zero_len = (zero_end - zero_start) as usize;

                        // Lock the page, zero the bytes, mark dirty, unlock
                        page.lock();
                        unsafe {
                            let ptr = (page.frame as *mut u8).add(offset_in_page);
                            core::ptr::write_bytes(ptr, 0, zero_len);
                        }
                        page.mark_dirty();
                        page.unlock();
                    }

                    // Release the page reference (find_get_page incremented refcount)
                    page.put();
                }
            }
        }

        // Update directory entry
        if inode_data.parent_cluster != 0 {
            update_dir_entry_by_short_name(
                &sb_data,
                inode_data.parent_cluster,
                &inode_data.short_name,
                new_start_cluster,
                new_size,
            )?;
        }

        // Update inode metadata
        // IMPORTANT: Update file_id when start_cluster changes, as file_id encodes the cluster
        let new_file_id = vfat_file_id(sb_data.bdev.dev_id(), new_start_cluster);
        inode.set_size(length);
        inode.set_private(Arc::new(VfatInodeData {
            start_cluster: new_start_cluster,
            file_size: new_size,
            is_dir: false,
            parent_cluster: inode_data.parent_cluster,
            short_name: inode_data.short_name,
            file_id: new_file_id,
        }));

        Ok(())
    }

    fn rename(
        &self,
        old_dir: &Inode,
        old_name: &str,
        new_dir: &Arc<Inode>,
        new_name: &str,
        flags: u32,
    ) -> Result<(), FsError> {
        // RENAME_EXCHANGE not supported for FAT
        if flags != 0 {
            return Err(FsError::InvalidArgument);
        }

        let sb = old_dir.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let old_dir_data = get_inode_data(old_dir)?;
        let new_dir_data = get_inode_data(new_dir)?;

        // Find the source entry
        let old_entries = read_directory_entries(&sb_data, old_dir_data.start_cluster)?;
        let old_entry = old_entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(old_name))
            .ok_or(FsError::NotFound)?
            .clone();

        // Check if target already exists
        let new_entries = read_directory_entries(&sb_data, new_dir_data.start_cluster)?;
        if let Some(existing) = new_entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(new_name))
        {
            // Target exists - delete it (FAT replaces existing)
            if existing.is_dir() != old_entry.is_dir() {
                // Can't replace file with dir or vice versa
                return Err(FsError::InvalidArgument);
            }
            if existing.is_dir() {
                // Check if target dir is empty
                let child_entries = read_directory_entries(&sb_data, existing.start_cluster)?;
                for child in &child_entries {
                    if child.name != "." && child.name != ".." {
                        return Err(FsError::DirectoryNotEmpty);
                    }
                }
            }
            // Delete existing entry
            let existing_cluster =
                delete_dir_entry(&sb_data, new_dir_data.start_cluster, new_name)?;
            if existing_cluster != 0 {
                free_cluster_chain(&sb_data, existing_cluster)?;
            }
        }

        // Create new entry with old entry's data
        let attr_byte = if old_entry.is_dir() {
            attr::DIRECTORY
        } else {
            attr::ARCHIVE
        };
        create_dir_entry_with_lfn(
            &sb_data,
            new_dir_data.start_cluster,
            new_name,
            attr_byte,
            old_entry.start_cluster,
            old_entry.file_size,
        )?;

        // Delete old entry (don't free clusters - they belong to new entry now)
        delete_dir_entry(&sb_data, old_dir_data.start_cluster, old_name)?;

        Ok(())
    }
}

pub static VFAT_INODE_OPS: VfatInodeOps = VfatInodeOps;

/// Create an inode for a parsed directory entry
fn create_inode_for_entry(
    sb: &Arc<SuperBlock>,
    entry: &ParsedDirEntry,
    parent_cluster: u32,
) -> Result<Arc<Inode>, FsError> {
    let sb_data = get_sb_data(sb)?;
    let mode = if entry.is_dir() {
        InodeMode::directory(0o755)
    } else {
        InodeMode::regular(0o644)
    };

    let ino = sb.alloc_ino();
    let inode = Arc::new(Inode::new(
        ino,
        mode,
        0,
        0,
        entry.file_size as u64,
        Timespec::ZERO,
        Arc::downgrade(sb),
        &VFAT_INODE_OPS,
    ));

    inode.set_private(Arc::new(VfatInodeData {
        start_cluster: entry.start_cluster,
        file_size: entry.file_size,
        is_dir: entry.is_dir(),
        parent_cluster,
        short_name: entry.short_name,
        file_id: vfat_file_id(sb_data.bdev.dev_id(), entry.start_cluster),
    }));

    Ok(inode)
}

// ============================================================================
// VFAT File Operations
// ============================================================================

/// VFAT file operations
pub struct VfatFileOps;

impl FileOps for VfatFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let inode_data = get_inode_data(&inode)?;

        // Use generic_file_read with VFAT file address space ops
        // This properly uses the page cache for file pages
        generic_file_read(
            file,
            buf,
            inode_data.file_id,
            inode.get_size(),
            true,  // can_writeback - VFAT is disk-backed
            false, // not unevictable
            &VFAT_FILE_AOPS,
        )
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, FsError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let mut inode_data = get_inode_data(&inode)?;
        let sb = inode.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let pos = file.get_pos();
        let old_size = inode.get_size();

        // For file writes, we need to allow growing the file
        let new_end = pos + buf.len() as u64;
        let effective_size = core::cmp::max(old_size, new_end);

        // Pre-allocate clusters if needed (VFAT requires clusters before data can be written)
        // This is necessary because VfatFileAddressSpaceOps::writepage cannot allocate clusters
        // (it only has FileId, not access to the inode).
        let cluster_size = sb_data.cluster_size as u64;
        let clusters_needed = effective_size.div_ceil(cluster_size) as usize;

        let current_clusters = if inode_data.start_cluster != 0 {
            read_cluster_chain(&sb_data, inode_data.start_cluster)?.len()
        } else {
            0
        };

        if clusters_needed > current_clusters {
            let additional = clusters_needed - current_clusters;
            let last_cluster = if inode_data.start_cluster != 0 {
                // Get last cluster in chain
                let chain = read_cluster_chain(&sb_data, inode_data.start_cluster)?;
                *chain.last().unwrap_or(&0)
            } else {
                0
            };

            let new_clusters = extend_cluster_chain(&sb_data, last_cluster, additional)?;

            // If this was an empty file, update inode with new start_cluster
            if inode_data.start_cluster == 0 && !new_clusters.is_empty() {
                let new_start = new_clusters[0];

                // Update directory entry
                if inode_data.parent_cluster != 0 {
                    update_dir_entry_by_short_name(
                        &sb_data,
                        inode_data.parent_cluster,
                        &inode_data.short_name,
                        new_start,
                        effective_size as u32,
                    )?;
                }

                // Update inode's private data with new start_cluster
                let new_file_id = vfat_file_id(sb_data.bdev.dev_id(), new_start);
                inode.set_private(Arc::new(VfatInodeData {
                    start_cluster: new_start,
                    file_size: effective_size as u32,
                    is_dir: inode_data.is_dir,
                    parent_cluster: inode_data.parent_cluster,
                    short_name: inode_data.short_name,
                    file_id: new_file_id,
                }));

                // Re-read inode_data with updated start_cluster
                inode_data = get_inode_data(&inode)?;
            }
        }

        // Use generic_file_write with VFAT file address space ops
        let bytes_written = generic_file_write(
            file,
            buf,
            inode_data.file_id,
            effective_size,
            true,  // can_writeback
            false, // not unevictable
            &VFAT_FILE_AOPS,
        )?;

        // Update inode size if file grew
        let new_pos = pos + bytes_written as u64;
        if new_pos > old_size {
            inode.set_size(new_pos);

            // Also update directory entry size on disk
            #[allow(clippy::collapsible_if)]
            if inode_data.parent_cluster != 0 {
                let entries = read_directory_entries(&sb_data, inode_data.parent_cluster).ok();
                let start_cluster = entries
                    .as_ref()
                    .and_then(|e| e.iter().find(|en| en.short_name == inode_data.short_name))
                    .map(|e| e.start_cluster)
                    .unwrap_or(inode_data.start_cluster);

                let _ = update_dir_entry_by_short_name(
                    &sb_data,
                    inode_data.parent_cluster,
                    &inode_data.short_name,
                    start_cluster,
                    new_pos as u32,
                );
            }
        }

        Ok(bytes_written)
    }

    fn pread(&self, file: &File, buf: &mut [u8], offset: u64) -> Result<usize, FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let inode_data = get_inode_data(&inode)?;

        // Use generic_file_pread with VFAT file address space ops
        generic_file_pread(
            file,
            buf,
            offset,
            inode_data.file_id,
            inode.get_size(),
            true,  // can_writeback
            false, // not unevictable
            &VFAT_FILE_AOPS,
        )
    }

    fn pwrite(&self, file: &File, buf: &[u8], offset: u64) -> Result<usize, FsError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let mut inode_data = get_inode_data(&inode)?;
        let sb = inode.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let old_size = inode.get_size();

        // For file writes, allow growing the file
        let new_end = offset + buf.len() as u64;
        let effective_size = core::cmp::max(old_size, new_end);

        // Pre-allocate clusters if needed (VFAT requires clusters before data can be written)
        let cluster_size = sb_data.cluster_size as u64;
        let clusters_needed = effective_size.div_ceil(cluster_size) as usize;

        let current_clusters = if inode_data.start_cluster != 0 {
            read_cluster_chain(&sb_data, inode_data.start_cluster)?.len()
        } else {
            0
        };

        if clusters_needed > current_clusters {
            let additional = clusters_needed - current_clusters;
            let last_cluster = if inode_data.start_cluster != 0 {
                let chain = read_cluster_chain(&sb_data, inode_data.start_cluster)?;
                *chain.last().unwrap_or(&0)
            } else {
                0
            };

            let new_clusters = extend_cluster_chain(&sb_data, last_cluster, additional)?;

            // If this was an empty file, update inode with new start_cluster
            if inode_data.start_cluster == 0 && !new_clusters.is_empty() {
                let new_start = new_clusters[0];

                // Update directory entry
                if inode_data.parent_cluster != 0 {
                    update_dir_entry_by_short_name(
                        &sb_data,
                        inode_data.parent_cluster,
                        &inode_data.short_name,
                        new_start,
                        effective_size as u32,
                    )?;
                }

                // Update inode's private data with new start_cluster
                let new_file_id = vfat_file_id(sb_data.bdev.dev_id(), new_start);
                inode.set_private(Arc::new(VfatInodeData {
                    start_cluster: new_start,
                    file_size: effective_size as u32,
                    is_dir: inode_data.is_dir,
                    parent_cluster: inode_data.parent_cluster,
                    short_name: inode_data.short_name,
                    file_id: new_file_id,
                }));

                // Re-read inode_data with updated start_cluster
                inode_data = get_inode_data(&inode)?;
            }
        }

        // Use generic_file_pwrite with VFAT file address space ops
        let bytes_written = generic_file_pwrite(
            file,
            buf,
            offset,
            inode_data.file_id,
            effective_size,
            true,  // can_writeback
            false, // not unevictable
            &VFAT_FILE_AOPS,
        )?;

        // Update inode size if file grew
        let new_pos = offset + bytes_written as u64;
        if new_pos > old_size {
            inode.set_size(new_pos);

            // Also update directory entry size on disk
            #[allow(clippy::collapsible_if)]
            if inode_data.parent_cluster != 0 {
                let entries = read_directory_entries(&sb_data, inode_data.parent_cluster).ok();
                let start_cluster = entries
                    .as_ref()
                    .and_then(|e| e.iter().find(|en| en.short_name == inode_data.short_name))
                    .map(|e| e.start_cluster)
                    .unwrap_or(inode_data.start_cluster);

                let _ = update_dir_entry_by_short_name(
                    &sb_data,
                    inode_data.parent_cluster,
                    &inode_data.short_name,
                    start_cluster,
                    new_pos as u32,
                );
            }
        }

        Ok(bytes_written)
    }

    // llseek: use default implementation from FileOps trait

    fn readdir(
        &self,
        file: &File,
        callback: &mut dyn FnMut(VfsDirEntry) -> bool,
    ) -> Result<(), FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let sb = inode.superblock().ok_or(FsError::IoError)?;
        let sb_data = get_sb_data(&sb)?;
        let inode_data = get_inode_data(&inode)?;

        if !inode_data.is_dir {
            return Err(FsError::NotADirectory);
        }

        // Emit . and ..
        if !callback(VfsDirEntry {
            ino: inode.ino,
            file_type: FileType::Directory,
            name: b".".to_vec(),
        }) {
            return Ok(());
        }
        if !callback(VfsDirEntry {
            ino: 1,
            file_type: FileType::Directory,
            name: b"..".to_vec(),
        }) {
            return Ok(());
        }

        // Read directory entries
        let entries = read_directory_entries(&sb_data, inode_data.start_cluster)?;

        for entry in entries {
            let file_type = if entry.is_dir() {
                FileType::Directory
            } else {
                FileType::Regular
            };

            // Use cluster as pseudo-inode number
            let ino = if entry.start_cluster > 0 {
                entry.start_cluster as u64
            } else {
                sb.alloc_ino()
            };

            if !callback(VfsDirEntry {
                ino,
                file_type,
                name: entry.name.as_bytes().to_vec(),
            }) {
                break;
            }
        }

        Ok(())
    }
}

pub static VFAT_FILE_OPS: VfatFileOps = VfatFileOps;

// ============================================================================
// VFAT Superblock Operations
// ============================================================================

/// VFAT superblock operations
pub struct VfatSuperOps;

impl SuperOps for VfatSuperOps {
    fn statfs(&self) -> StatFs {
        // TODO: Could provide actual block counts from VfatSbData if available
        // For now, return minimal valid values
        StatFs {
            f_type: MSDOS_SUPER_MAGIC,
            f_bsize: 4096, // Cluster size varies; use common value
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0, // FAT doesn't track inode count
            f_ffree: 0,
            f_namelen: 255, // LFN max length
        }
    }

    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, FsError> {
        Ok(Arc::new(Inode::new(
            sb.alloc_ino(),
            mode,
            0,
            0,
            0,
            Timespec::ZERO,
            Arc::downgrade(sb),
            i_op,
        )))
    }
}

pub static VFAT_SUPER_OPS: VfatSuperOps = VfatSuperOps;

// ============================================================================
// VFAT Mount
// ============================================================================

/// Placeholder mount function for pseudo-fs style (shouldn't be called)
fn vfat_mount_pseudo(_fs_type: &'static FileSystemType) -> Result<Arc<SuperBlock>, FsError> {
    Err(FsError::NotSupported) // FAT32 requires a device
}

/// Mount VFAT filesystem on a block device
fn vfat_mount_dev(
    fs_type: &'static FileSystemType,
    bdev: Arc<BlockDevice>,
) -> Result<Arc<SuperBlock>, FsError> {
    // Read boot sector
    let mut boot_sector_buf = [0u8; 512];
    read_bytes(&bdev, 0, &mut boot_sector_buf)?;

    let boot_sector: VfatBootSector =
        unsafe { core::ptr::read_unaligned(boot_sector_buf.as_ptr() as *const _) };

    // Validate FAT32
    // Check for valid bytes per sector (must be power of 2, 512-4096)
    let bytes_per_sector = boot_sector.bytes_per_sector;
    if !(512..=4096).contains(&bytes_per_sector) || !bytes_per_sector.is_power_of_two() {
        return Err(FsError::InvalidArgument);
    }

    // Check for FAT32 (fat_size_16 == 0 and fat_size_32 != 0)
    if boot_sector.fat_size_16 != 0 || boot_sector.fat_size_32 == 0 {
        return Err(FsError::InvalidArgument);
    }

    // Check root_entry_count is 0 (required for FAT32)
    if boot_sector.root_entry_count != 0 {
        return Err(FsError::InvalidArgument);
    }

    // Calculate filesystem layout
    let fat_start_sector = boot_sector.reserved_sector_count as u64;
    let fat_sectors = boot_sector.fat_size_32 as u64;
    let num_fats = boot_sector.num_fats as u64;
    let data_start_sector = fat_start_sector + (fat_sectors * num_fats);
    let cluster_size = (boot_sector.sectors_per_cluster as u32) * (bytes_per_sector as u32);

    // Create superblock data
    let sb_data = Arc::new(VfatSbData {
        bdev: bdev.clone(),
        bytes_per_sector: bytes_per_sector as u32,
        sectors_per_cluster: boot_sector.sectors_per_cluster as u32,
        fat_start_sector,
        fat_sectors,
        data_start_sector,
        root_cluster: boot_sector.root_cluster,
        cluster_size,
    });

    // Create superblock
    let sb = SuperBlock::new(fs_type, &VFAT_SUPER_OPS, 0);
    sb.set_private(sb_data.clone());

    // Create root inode
    let root_ino = sb.alloc_ino();
    let root_inode = Arc::new(Inode::new(
        root_ino,
        InodeMode::directory(0o755),
        0,
        0,
        0,
        Timespec::ZERO,
        Arc::downgrade(&sb),
        &VFAT_INODE_OPS,
    ));

    root_inode.set_private(Arc::new(VfatInodeData {
        start_cluster: boot_sector.root_cluster,
        file_size: 0,
        is_dir: true,
        parent_cluster: 0,      // Root has no parent
        short_name: [b' '; 11], // Root has no short name
        file_id: vfat_file_id(sb_data.bdev.dev_id(), boot_sector.root_cluster),
    }));

    // Create root dentry
    let root_dentry = Arc::new(Dentry::new_root(root_inode, Arc::downgrade(&sb)));
    sb.set_root(root_dentry);

    Ok(sb)
}

/// VFAT filesystem type
pub static VFAT_TYPE: FileSystemType = FileSystemType {
    name: "vfat",
    fs_flags: fs_flags::FS_REQUIRES_DEV,
    mount: vfat_mount_pseudo,
    mount_dev: Some(vfat_mount_dev),
    file_ops: &VFAT_FILE_OPS,
};
