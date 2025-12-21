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
use crate::mm::page_cache::{BLKDEV_AOPS, FileId, PAGE_SIZE};
use crate::storage::BlockDevice;
use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

use super::dentry::Dentry;
use super::file::{DirEntry as VfsDirEntry, File, FileOps};
use super::inode::{AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::superblock::{FileSystemType, SuperBlock, SuperBlockData, SuperOps, fs_flags};
use super::vfs::FsError;

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
}

impl InodeData for VfatInodeData {}

impl AsAny for VfatInodeData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
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
            // Use BLKDEV_AOPS for disk-backed page cache with writeback support
            let (page, is_new) = cache
                .find_or_create_page(
                    file_id,
                    page_offset,
                    capacity,
                    &mut frame_alloc,
                    true,  // can_writeback: uses BLKDEV_AOPS for disk I/O
                    false, // not unevictable (disk-backed)
                    &BLKDEV_AOPS,
                )
                .map_err(|_| FsError::IoError)?;
            (page.frame, is_new)
        };

        // Read from block device AFTER releasing the lock
        if needs_read {
            bdev.disk
                .queue
                .driver()
                .readpage(&bdev.disk, frame, page_offset);
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

/// Write bytes to block device via page cache
fn write_bytes(bdev: &BlockDevice, offset: u64, buf: &[u8]) -> Result<(), FsError> {
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
                    true,  // can_writeback: uses BLKDEV_AOPS for disk I/O
                    false, // not unevictable (disk-backed)
                    &BLKDEV_AOPS,
                )
                .map_err(|_| FsError::IoError)?;
            (page, is_new)
        };

        // If this is a partial page write and the page is new, read existing data first
        if needs_read && (offset_in_page != 0 || chunk_size != PAGE_SIZE) {
            bdev.disk
                .queue
                .driver()
                .readpage(&bdev.disk, page.frame, page_offset);
        }

        // Write data to page
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr().add(buf_offset),
                (page.frame as *mut u8).add(offset_in_page),
                chunk_size,
            );
        }

        // Mark page as dirty
        page.mark_dirty();

        // Write page to disk (write-through for now, will add proper writeback later)
        bdev.disk
            .queue
            .driver()
            .writepage(&bdev.disk, page.frame, page_offset);

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
    let existing_short_names: Vec<[u8; 11]> = existing_entries
        .iter()
        .map(|e| {
            let mut short = [b' '; 11];
            // Extract short name from entry (simplified - use uppercase)
            let upper = e.name.to_ascii_uppercase();
            for (i, c) in upper.bytes().enumerate().take(11) {
                if i < 11 {
                    short[i] = c;
                }
            }
            short
        })
        .collect();

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
        let inode = Arc::new(Inode::new(
            sb.alloc_ino(),
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
        let inode = Arc::new(Inode::new(
            sb.alloc_ino(),
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
}

pub static VFAT_INODE_OPS: VfatInodeOps = VfatInodeOps;

/// Create an inode for a parsed directory entry
fn create_inode_for_entry(
    sb: &Arc<SuperBlock>,
    entry: &ParsedDirEntry,
    parent_cluster: u32,
) -> Result<Arc<Inode>, FsError> {
    let mode = if entry.is_dir() {
        InodeMode::directory(0o755)
    } else {
        InodeMode::regular(0o644)
    };

    let inode = Arc::new(Inode::new(
        sb.alloc_ino(),
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
    }));

    Ok(inode)
}

// ============================================================================
// VFAT File Operations
// ============================================================================

/// VFAT file operations
pub struct VfatFileOps;

impl FileOps for VfatFileOps {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let pos = file.get_pos();
        let size = inode.get_size();

        if pos >= size {
            return Ok(0); // EOF
        }

        let to_read = core::cmp::min(buf.len(), (size - pos) as usize);
        let mut bytes_read = 0;

        while bytes_read < to_read {
            let current_pos = pos + bytes_read as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;

            let mut page_buf = vec![0u8; PAGE_SIZE];
            let _ = inode.i_op.readpage(&inode, page_offset, &mut page_buf)?;

            let chunk_size = core::cmp::min(PAGE_SIZE - offset_in_page, to_read - bytes_read);
            buf[bytes_read..bytes_read + chunk_size]
                .copy_from_slice(&page_buf[offset_in_page..offset_in_page + chunk_size]);

            bytes_read += chunk_size;
        }

        file.advance_pos(bytes_read as u64);
        Ok(bytes_read)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, FsError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let pos = file.get_pos();
        let mut bytes_written = 0;

        while bytes_written < buf.len() {
            let current_pos = pos + bytes_written as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;

            // Prepare page buffer
            let mut page_buf = vec![0u8; PAGE_SIZE];

            // For partial page writes, read existing data first
            if offset_in_page != 0 || (buf.len() - bytes_written) < PAGE_SIZE {
                // Try to read existing page data (may fail for new pages, which is OK)
                let _ = inode.i_op.readpage(&inode, page_offset, &mut page_buf);
            }

            // Copy new data into page buffer
            let chunk_size = core::cmp::min(PAGE_SIZE - offset_in_page, buf.len() - bytes_written);
            page_buf[offset_in_page..offset_in_page + chunk_size]
                .copy_from_slice(&buf[bytes_written..bytes_written + chunk_size]);

            // Write the page
            inode.i_op.writepage(&inode, page_offset, &page_buf)?;

            bytes_written += chunk_size;
        }

        // Update file position
        file.advance_pos(bytes_written as u64);

        // Update inode size if file grew
        let new_pos = pos + bytes_written as u64;
        let old_size = inode.get_size();
        if new_pos > old_size {
            inode.set_size(new_pos);

            // Also update directory entry size on disk
            // (writepage handles start_cluster, but we need to update size too)
            #[allow(clippy::collapsible_if)]
            if let (Ok(sb), Ok(inode_data)) = (
                inode.superblock().ok_or(FsError::IoError),
                get_inode_data(&inode),
            ) {
                if let (true, Ok(sb_data)) = (inode_data.parent_cluster != 0, get_sb_data(&sb)) {
                    // Get current start_cluster from directory entry (might have been set by writepage)
                    // We read it back since the inode's private data isn't updated
                    let entries = read_directory_entries(&sb_data, inode_data.parent_cluster).ok();
                    let start_cluster = entries
                        .as_ref()
                        .and_then(|e| e.iter().find(|en| en.short_name == inode_data.short_name))
                        .map(|e| e.start_cluster)
                        .unwrap_or(0);

                    let _ = update_dir_entry_by_short_name(
                        &sb_data,
                        inode_data.parent_cluster,
                        &inode_data.short_name,
                        start_cluster,
                        new_pos as u32,
                    );
                }
            }
        }

        Ok(bytes_written)
    }

    fn pread(&self, file: &File, buf: &mut [u8], offset: u64) -> Result<usize, FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let pos = offset;
        let size = inode.get_size();

        if pos >= size {
            return Ok(0); // EOF
        }

        let to_read = core::cmp::min(buf.len(), (size - pos) as usize);
        let mut bytes_read = 0;

        while bytes_read < to_read {
            let current_pos = pos + bytes_read as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;

            let mut page_buf = vec![0u8; PAGE_SIZE];
            let _ = inode.i_op.readpage(&inode, page_offset, &mut page_buf)?;

            let chunk_size = core::cmp::min(PAGE_SIZE - offset_in_page, to_read - bytes_read);
            buf[bytes_read..bytes_read + chunk_size]
                .copy_from_slice(&page_buf[offset_in_page..offset_in_page + chunk_size]);

            bytes_read += chunk_size;
        }

        // NOTE: Unlike read(), we do NOT advance file position
        Ok(bytes_read)
    }

    fn pwrite(&self, file: &File, buf: &[u8], offset: u64) -> Result<usize, FsError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let pos = offset;
        let mut bytes_written = 0;

        while bytes_written < buf.len() {
            let current_pos = pos + bytes_written as u64;
            let page_offset = current_pos / PAGE_SIZE as u64;
            let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;

            // Prepare page buffer
            let mut page_buf = vec![0u8; PAGE_SIZE];

            // For partial page writes, read existing data first
            if offset_in_page != 0 || (buf.len() - bytes_written) < PAGE_SIZE {
                // Try to read existing page data (may fail for new pages, which is OK)
                let _ = inode.i_op.readpage(&inode, page_offset, &mut page_buf);
            }

            // Copy new data into page buffer
            let chunk_size = core::cmp::min(PAGE_SIZE - offset_in_page, buf.len() - bytes_written);
            page_buf[offset_in_page..offset_in_page + chunk_size]
                .copy_from_slice(&buf[bytes_written..bytes_written + chunk_size]);

            // Write the page
            inode.i_op.writepage(&inode, page_offset, &page_buf)?;

            bytes_written += chunk_size;
        }

        // NOTE: Unlike write(), we do NOT advance file position

        // Update inode size if file grew
        let new_pos = pos + bytes_written as u64;
        let old_size = inode.get_size();
        if new_pos > old_size {
            inode.set_size(new_pos);

            // Also update directory entry size on disk
            #[allow(clippy::collapsible_if)]
            if let (Ok(sb), Ok(inode_data)) = (
                inode.superblock().ok_or(FsError::IoError),
                get_inode_data(&inode),
            ) {
                if let (true, Ok(sb_data)) = (inode_data.parent_cluster != 0, get_sb_data(&sb)) {
                    let entries = read_directory_entries(&sb_data, inode_data.parent_cluster).ok();
                    let start_cluster = entries
                        .as_ref()
                        .and_then(|e| e.iter().find(|en| en.short_name == inode_data.short_name))
                        .map(|e| e.start_cluster)
                        .unwrap_or(0);

                    let _ = update_dir_entry_by_short_name(
                        &sb_data,
                        inode_data.parent_cluster,
                        &inode_data.short_name,
                        start_cluster,
                        new_pos as u32,
                    );
                }
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
    let root_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
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
