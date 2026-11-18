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

use crate::util::scope::ScopeGuard;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;

use crate::block::BlockDevice;
use crate::block::blkdev::{BioOp, bdev_rw_bytes};
use crate::mm::filemap::{self, Aops, PAGE_SIZE};
use crate::mm::page::frame_bytes;
use crate::util::pod::{FromBytes, IntoBytes};

use super::dentry::Dentry;
use super::file::{DirContext, DirEntry as VfsDirEntry, File, FileOps, RwFlags};
use super::icache;
use super::inode::{
    AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, InodeRef, TimeUpdate, Timespec,
};
use super::iov_iter::{IovDest, IovSource};
use super::superblock::{
    FileSystemType, MSDOS_SUPER_MAGIC, StatFs, SuperBlock, SuperBlockData, SuperOps, fs_flags,
};
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;

mod cache;
mod direct;
mod fattime;

// ============================================================================
// VFAT file pages (Linux fat_aops: fat_read_folio, fat_writepages)
// ============================================================================

/// A file's page cache reads and writes its clusters directly (not
/// through the device's cache, which holds only FAT and directory
/// blocks; a cluster's device-cache pages are dropped when it is
/// allocated, Linux clean_bdev_aliases)
pub struct VfatAops;

/// A page's device and the disk runs holding its bytes
type PageRuns = (Arc<BlockDevice>, Vec<(u64, usize)>);

/// The runs on disk holding the page's bytes within the file (one walk
/// of its chain from the nearest cached position, `cache::extents`)
fn page_runs(inode: &Inode, index: u64) -> Result<PageRuns, KernelError> {
    page_runs_to(inode, index, false).map(|(r, _)| r)
}

/// `page_runs`, with `whole` the bytes in the page are taken to the end
/// of the filesystem block holding the last; and that count before
/// rounding (the bytes within the file)
fn page_runs_to(inode: &Inode, index: u64, whole: bool) -> Result<(PageRuns, usize), KernelError> {
    let sb = inode.superblock().ok_or(KernelError::Io)?;
    let sb_data = get_sb_data(&sb)?;
    let pos = index * PAGE_SIZE as u64;
    let valid = inode.get_size().saturating_sub(pos).min(PAGE_SIZE as u64);
    let len = if whole {
        valid
            .next_multiple_of(u64::from(sb_data.bytes_per_sector))
            .min(PAGE_SIZE as u64)
    } else {
        valid
    };
    let runs = cache::extents(&sb_data, inode, pos, len as usize)?;
    Ok(((sb_data.bdev.clone(), runs), valid as usize))
}

/// Transfer `runs` between the disk and `page` (in order from its start)
fn page_io(
    bdev: &BlockDevice,
    op: BioOp,
    page: &mut [u8],
    runs: &[(u64, usize)],
) -> Result<(), KernelError> {
    let mut at = 0;
    for &(off, n) in runs {
        bdev_rw_bytes(bdev, op, off, &mut page[at..at + n])?;
        at += n;
    }
    Ok(())
}

impl Aops for VfatAops {
    fn read_folio(&self, inode: &Inode, phys: u64, index: u64) -> Result<(), KernelError> {
        let (bdev, runs) = page_runs(inode, index)?;
        // SAFETY: the locked page being filled, ours alone
        let page = unsafe { frame_bytes(phys) };
        page.fill(0);
        page_io(&bdev, BioOp::Read, page, &runs)?;
        filemap::set_uptodate(phys);
        Ok(())
    }

    /// Swap files: the slot's clusters, read or written directly (Linux
    /// generic_swapfile_activate maps the file's blocks)
    fn swap_rw(
        &self,
        inode: &Inode,
        index: u64,
        buf: &mut [u8],
        write: bool,
    ) -> Result<(), KernelError> {
        let (bdev, runs) = page_runs(inode, index)?;
        // A slot is a whole page of the file (swapon checks the header
        // against the size); never part of one
        if runs.iter().map(|r| r.1).sum::<usize>() != PAGE_SIZE {
            return Err(KernelError::Io);
        }
        if write {
            return page_io(&bdev, BioOp::Write, buf, &runs);
        }
        buf.fill(0);
        page_io(&bdev, BioOp::Read, buf, &runs)
    }

    /// The page's blocks within the file, the last one whole with the
    /// page zeroed past the size first (Linux block_write_full_folio):
    /// no stale bytes stay on the disk in a block below mmu_private
    fn writepage(&self, inode: &Inode, phys: u64, index: u64) -> Result<(), KernelError> {
        let ((bdev, runs), valid) = page_runs_to(inode, index, true)?;
        // SAFETY: the locked page with our reference
        let page = unsafe { frame_bytes(phys) };
        page[valid..].fill(0);
        page_io(&bdev, BioOp::Write, page, &runs)
    }
}

pub static VFAT_FILE_AOPS: VfatAops = VfatAops;

/// Zero [from, to) of the file through its page cache, within the
/// clusters it already has (Linux cont_write_begin / fat_cont_expand):
/// bytes past the old end in its last cluster may be stale on disk
fn cont_expand(inode: &Inode, cs: u64, from: u64, to: u64) -> Result<(), KernelError> {
    /// The bytes written (Linux zeroes the page cache pages in place)
    static ZEROS: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
    let to = to.min(from.next_multiple_of(cs));
    let mut at = from;
    while at < to {
        let n = ((to - at) as usize).min(PAGE_SIZE - (at % PAGE_SIZE as u64) as usize);
        if filemap::perform_write(inode, &ZEROS[..n], at)? != n {
            return Err(KernelError::NoSpace);
        }
        at += n as u64;
    }
    Ok(())
}

/// Give the file the clusters `size` bytes need (FAT has no holes; new
/// clusters are zeroed on disk by `allocate_cluster`), recording a new
/// first cluster in the inode and its directory entry
fn ensure_clusters(inode: &Inode, sb_data: &VfatSbData, size: u64) -> Result<(), KernelError> {
    let d = get_inode_data(inode)?;
    let cs = u64::from(sb_data.cluster_size);
    let need = size.div_ceil(cs) as usize;
    // The chain's length and last cluster (Linux fat_chain_add)
    let (have, last) = match cache::last_cluster(sb_data, inode)? {
        Some((f, d)) => (f as usize + 1, d),
        None => (0, 0),
    };
    if need <= have {
        return Ok(());
    }
    let first = extend_cluster_chain(sb_data, last, need - have)?;
    if d.start_cluster == 0 && first != 0 {
        // The clusters are on disk now: the inode follows, and its entry
        // (Linux fat_chain_add: mark_inode_dirty)
        with_vi(inode, |v| {
            v.d.lock().start_cluster = first;
            v.cache.lock().set_start(first);
        })?;
        super::fs_writeback::mark_inode_dirty(inode);
    }
    // Linux fat_chain_add: i_blocks counts them
    with_vi(inode, |v| v.d.lock().clusters = need as u32)
}

/// Write to a vfat file (Linux fat_write_begin/end over
/// generic_perform_write): clusters first, a gap past the old end
/// zeroed, the data through the page cache (written back later), then
/// the new size in the directory entry. The VFS holds i_rwsem.
fn vfat_write(inode: &InodeRef, from: &mut IovSource<'_>, pos: u64) -> Result<usize, KernelError> {
    if from.is_empty() {
        return Ok(0);
    }
    let sb = inode.superblock().ok_or(KernelError::Io)?;
    let sb_data = get_sb_data(&sb)?;
    let len = from.len();
    let end = pos + len as u64;
    if end > u64::from(u32::MAX) {
        return Err(KernelError::FileTooLarge);
    }
    let old = inode.get_size();
    ensure_clusters(inode, &sb_data, end.max(old))?;
    mmu_extend(inode, &sb_data, end)?;
    // The gap zeroed: if that fails, mmu_private and the clusters go
    // back to the size (Linux: a failed write_begin is fat_write_failed)
    if pos > old
        && let Err(e) = cont_expand(inode, u64::from(sb_data.cluster_size), old, pos)
    {
        let _ = write_failed(inode, &sb_data);
        return Err(e);
    }
    let r = filemap::write_iter(inode, from, pos);
    // Linux fat_write_failed acts only for a write past the size: an
    // in-place one keeps the clusters (fallocate's past the end too)
    if !matches!(r, Ok(n) if n == len) && end > inode.get_size() {
        // Best effort, like its void return
        let _ = write_failed(inode, &sb_data);
    }
    let n = r?;
    crate::mm::writeback::balance_dirty_pages(inode);
    if inode.get_size() != old {
        // Linux fat_write_end: mark_inode_dirty; the entry follows at
        // write-back (__fat_write_inode)
        super::fs_writeback::mark_inode_dirty(inode);
    }
    Ok(n)
}

/// A write or expanding truncate reached byte `end`: the blocks up to
/// it are allocated and initialized (Linux cont_write_begin and
/// __fat_get_block raise mmu_private to the end of the block)
fn mmu_extend(inode: &Inode, sb_data: &VfatSbData, end: u64) -> Result<(), KernelError> {
    let bs = u64::from(sb_data.bytes_per_sector);
    with_vi(inode, |v| {
        let mut d = v.d.lock();
        if end > d.mmu_private {
            d.mmu_private = end.next_multiple_of(bs);
        }
    })
}

/// The file was cut to `size` bytes (Linux fat_truncate_blocks)
fn mmu_truncate(inode: &Inode, size: u64) -> Result<(), KernelError> {
    with_vi(inode, |v| {
        let mut d = v.d.lock();
        d.mmu_private = d.mmu_private.min(size);
    })
}

/// A write past the size that came up short (a fault in the caller's
/// buffer, no memory): the clusters past the end go again (Linux fat_write_failed
/// -> fat_truncate_blocks)
fn write_failed(inode: &Inode, sb_data: &VfatSbData) -> Result<(), KernelError> {
    // No direct I/O still reads clusters about to be freed
    inode.inode_dio_wait();
    mmu_truncate(inode, inode.get_size())?;
    let start0 = get_inode_data(inode)?.start_cluster;
    let keep = inode.get_size().div_ceil(u64::from(sb_data.cluster_size)) as usize;
    let start = free_past(sb_data, inode, start0, keep)?;
    if start != start0 {
        let d = get_inode_data(inode)?;
        set_inode_data(
            inode,
            VfatInodeData {
                start_cluster: start,
                ..d
            },
        )?;
        super::fs_writeback::mark_inode_dirty(inode);
    }
    Ok(())
}

/// Free the clusters of `inode`'s chain at `start` past its first
/// `keep`, its cached positions forgotten first (Linux fat_free from
/// fat_truncate_blocks); the chain's new first cluster (0: none left)
fn free_past(
    sb_data: &VfatSbData,
    inode: &Inode,
    start: u32,
    keep: usize,
) -> Result<u32, KernelError> {
    if start == 0 {
        return Ok(0);
    }
    cache::inval(inode)?;
    if keep == 0 {
        free_cluster_chain(sb_data, start)?;
        set_clusters(inode, 0)?;
        return Ok(0);
    }
    let want = u32::try_from(keep - 1).map_err(|_| KernelError::Io)?;
    let Some((f, last)) = cache::get_cluster(sb_data, inode, want)? else {
        return Ok(start);
    };
    if f < want {
        return Ok(start);
    }
    let next = get_fat_entry(sb_data, last)?;
    if !is_end_of_chain(next) {
        set_fat_entry(sb_data, last, FAT_EOC)?;
        // Again once the chain is cut: a walk that began in between
        // may have cached clusters past the new end
        cache::inval(inode)?;
        free_cluster_chain(sb_data, next)?;
    }
    set_clusters(inode, want + 1)?;
    Ok(start)
}

/// The file has `n` clusters left after a cut (Linux fat_free: i_blocks)
fn set_clusters(inode: &Inode, n: u32) -> Result<(), KernelError> {
    with_vi(inode, |v| {
        let mut d = v.d.lock();
        d.clusters = d.clusters.min(n);
    })
}

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
// On-disk structures are little-endian, as hk's CPUs are: their bytes
// are the in-memory layout (packed)
const _: () = assert!(cfg!(target_endian = "little"));
crate::pod!(VfatBootSector {
    jump_boot,
    oem_name,
    bytes_per_sector,
    sectors_per_cluster,
    reserved_sector_count,
    num_fats,
    root_entry_count,
    total_sectors_16,
    media_type,
    fat_size_16,
    sectors_per_track,
    num_heads,
    hidden_sectors,
    total_sectors_32,
    fat_size_32,
    ext_flags,
    fs_version,
    root_cluster,
    fs_info,
    backup_boot_sector,
    reserved,
    drive_number,
    reserved1,
    boot_signature,
    volume_id,
    volume_label,
    fs_type
});

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
crate::pod!(VfatDirEntry {
    name,
    ext,
    attr,
    nt_reserved,
    create_time_tenth,
    create_time,
    create_date,
    access_date,
    first_cluster_hi,
    write_time,
    write_date,
    first_cluster_lo,
    file_size
});

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
crate::pod!(VfatLfnEntry {
    order,
    name1,
    attr,
    entry_type,
    checksum,
    name2,
    first_cluster,
    name3
});

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
    /// Number of FAT copies, each written on a change (Linux sbi->fats)
    pub num_fats: u64,
    /// First sector of the data region
    pub data_start_sector: u64,
    /// Root directory cluster
    pub root_cluster: u32,
    /// One past the last data cluster (Linux msdos_sb_info.max_cluster):
    /// data clusters are 2..max_cluster
    pub max_cluster: u32,
    /// Cluster size in bytes
    pub cluster_size: u32,
    /// Mount options
    pub opts: VfatOpts,
    /// Serializes FAT allocation and freeing and the free count (Linux
    /// sbi->fat_lock, lock_fat): sleeping, under the inodes' i_rwsem,
    /// above the device's I/O; shared by every copy of this data
    pub fat: Arc<crate::sync::Mutex<FatState>>,
    /// Every inode's entry location (`VfatInodeData.i_pos`) is read to
    /// write the entry, and changed, under it (Linux
    /// sbi->inode_hash_lock): an attach, a detach, a write_inode's
    /// read-patch-write of the entry, and every slot written when an
    /// entry is added or removed (an unlink's detach in the same hold);
    /// block I/O here, so it is
    /// sleeping and held across the write (Linux patches the buffer
    /// under its spin lock and rechecks i_pos instead)
    pub ipos: Arc<crate::sync::Mutex<()>>,
}

impl SuperBlockData for VfatSbData {}

/// What the FAT lock guards beyond the FAT itself
pub struct FatState {
    /// Free data clusters, -1 until counted (Linux sbi->free_clusters,
    /// counted by the first statfs, fat_count_free_clusters, then kept
    /// by every allocation and free)
    free: i64,
    /// The cluster allocated last: the next search starts after it
    /// (Linux sbi->prev_free, next fit)
    prev_free: u32,
}

/// How long names map to bytes (Linux iocharset and utf8)
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// UTF-8 (the utf8 option or iocharset=utf8)
    Utf8,
    /// iso8859-1: a byte is its code point (Ubuntu's default iocharset)
    Latin1,
    /// cp437 (Ubuntu's only built-in NLS table)
    Cp437,
}

/// cp437's upper half (Linux nls_cp437)
const CP437_HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐\
    └┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";

impl Charset {
    /// A user's name as text; None if it does not decode (UTF-8)
    fn to_text(self, b: &[u8]) -> Option<String> {
        match self {
            Self::Utf8 => core::str::from_utf8(b).ok().map(String::from),
            Self::Latin1 => Some(b.iter().map(|&c| c as char).collect()),
            Self::Cp437 => Some(
                b.iter()
                    .map(|&c| match c {
                        0..0x80 => c as char,
                        _ => CP437_HIGH.chars().nth((c - 0x80) as usize).unwrap_or('?'),
                    })
                    .collect(),
            ),
        }
    }

    /// A long name as the user sees it; '?' for what the charset lacks
    fn to_bytes(self, s: &str) -> Vec<u8> {
        match self {
            Self::Utf8 => s.as_bytes().to_vec(),
            Self::Latin1 => s.chars().map(|c| u8::try_from(c).unwrap_or(b'?')).collect(),
            Self::Cp437 => s
                .chars()
                .map(|c| match c as u32 {
                    0..0x80 => c as u8,
                    _ => CP437_HIGH
                        .chars()
                        .position(|x| x == c)
                        .map_or(b'?', |i| 0x80 + i as u8),
                })
                .collect(),
        }
    }
}

/// vfat mount options (Linux struct fat_mount_options)
#[derive(Clone, Copy)]
pub struct VfatOpts {
    pub uid: u32,
    pub gid: u32,
    pub fmask: u16,
    pub dmask: u16,
    pub cs: Charset,
    /// tz=UTC or time_offset= given (Linux tz_set)
    pub tz_set: bool,
    /// Minutes the entries' local time is ahead of UTC (Linux
    /// time_offset)
    pub time_offset: i32,
}

impl VfatOpts {
    /// Files and directories are all-permissive minus their mask (Linux
    /// fat_make_mode)
    fn file_mode(&self) -> InodeMode {
        InodeMode::regular(0o777 & !self.fmask)
    }

    fn dir_mode(&self) -> InodeMode {
        InodeMode::directory(0o777 & !self.dmask)
    }

    /// The entries' offset from UTC in seconds (Linux fat_tz_offset)
    fn tz(&self) -> i64 {
        fattime::tz_offset(self.tz_set, self.time_offset)
    }

    /// Parse the mount data (Linux fat_parse_param): uid/gid default to
    /// the mounter's fs ids, the masks to its umask, the charset to
    /// iso8859-1 (Ubuntu's FAT_DEFAULT_IOCHARSET, FAT_DEFAULT_UTF8
    /// off); options that only tune what hk does not do are accepted,
    /// an unknown one is EINVAL
    fn parse(opts: &[u8]) -> Result<Self, KernelError> {
        let c = crate::fs::dac::cred();
        let umask = crate::task::percpu::current_fs().map_or(0o022, |f| f.get_umask());
        let mut o = Self {
            uid: c.fsuid,
            gid: c.fsgid,
            fmask: umask,
            dmask: umask,
            cs: Charset::Latin1,
            tz_set: false,
            time_offset: 0,
        };
        let bad = KernelError::InvalidArgument;
        let num = |v: &[u8]| {
            core::str::from_utf8(v)
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
        };
        let oct = |v: &[u8]| super::ramfs::parse_octal(v).map(|m| m & 0o777);
        let mut utf8 = false;
        for kv in opts.split(|&b| b == b',').filter(|kv| !kv.is_empty()) {
            let (k, v) = match kv.iter().position(|&b| b == b'=') {
                Some(i) => (&kv[..i], &kv[i + 1..]),
                None => (kv, &b""[..]),
            };
            match k {
                b"uid" => o.uid = num(v).ok_or(bad)?,
                b"gid" => o.gid = num(v).ok_or(bad)?,
                b"umask" => (o.fmask, o.dmask) = (oct(v).ok_or(bad)?, oct(v).ok_or(bad)?),
                b"fmask" => o.fmask = oct(v).ok_or(bad)?,
                b"dmask" => o.dmask = oct(v).ok_or(bad)?,
                b"iocharset" => {
                    o.cs = match v {
                        b"utf8" => Charset::Utf8,
                        b"iso8859-1" => Charset::Latin1,
                        b"cp437" => Charset::Cp437,
                        _ => return Err(bad),
                    }
                }
                b"utf8" => utf8 = matches!(v, b"" | b"1" | b"yes" | b"true"),
                b"codepage" if v == b"437" => {}
                b"shortname" if matches!(v, b"lower" | b"win95" | b"winnt" | b"mixed") => {}
                b"quiet" | b"showexec" | b"debug" | b"sys_immutable" | b"flush" | b"usefree"
                | b"nocase" | b"discard" | b"dos1xfloppy" | b"rodir" | b"nonumtail"
                | b"uni_xlate" | b"allow_utime" | b"errors" | b"check" | b"nfs" => {}
                // Linux fat_parse_param: tz= takes only UTC
                b"tz" if v == b"UTC" => (o.tz_set, o.time_offset) = (true, 0),
                // Minutes, within a day either way (Linux fsparam_s32:
                // kstrtoint base 0)
                b"time_offset" => {
                    let n = crate::util::kstrtox::kstrtoint(v, 0)
                        .ok()
                        .filter(|n| (-24 * 60..=24 * 60).contains(n))
                        .ok_or(bad)?;
                    (o.tz_set, o.time_offset) = (true, n);
                }
                _ => return Err(bad),
            }
        }
        if utf8 {
            o.cs = Charset::Utf8;
        }
        Ok(o)
    }
}

/// The mount's options for an inode of it
fn opts_of(i: &Inode) -> Option<VfatOpts> {
    i.superblock()
        .and_then(|sb| get_sb_data(&sb).ok())
        .map(|d| d.opts)
}

/// A name the user gave, read by the mount's charset (`err` if it does
/// not decode), trailing dots dropped (Linux vfat_striptail_len)
fn user_name(dir: &Inode, name: &[u8], err: KernelError) -> Result<String, KernelError> {
    let cs = opts_of(dir).map_or(Charset::Utf8, |o| o.cs);
    let s = cs.to_text(name).ok_or(err)?;
    Ok(String::from(s.trim_end_matches('.')))
}

/// `name` without its trailing dots (Linux vfat_striptail_len)
fn striptail(name: &[u8]) -> &[u8] {
    let n = name.iter().rposition(|&c| c != b'.').map_or(0, |i| i + 1);
    &name[..n]
}

/// Hash of a name, case folded, trailing dots dropped (Linux
/// vfat_hashi; hk folds ASCII, as its lookups match)
fn vfat_hashi(name: &[u8]) -> u64 {
    crate::fs::name::name_hash_nocase(striptail(name))
}

/// Two names match without case or trailing dots (Linux vfat_cmpi)
fn vfat_cmpi(stored: &[u8], name: &[u8]) -> bool {
    striptail(stored).eq_ignore_ascii_case(striptail(name))
}

/// vfat's dentry operations (Linux vfat_ci_dentry_ops)
static VFAT_CI_DENTRY_OPS: crate::fs::dentry::DentryOps = crate::fs::dentry::DentryOps {
    d_hash: Some(vfat_hashi),
    d_compare: Some(vfat_cmpi),
    d_revalidate: Some(vfat_revalidate_ci),
    ..crate::fs::dentry::DentryOps::NONE
};

/// Linux vfat_revalidate_ci: ECHILD in an RCU walk (every vfat name is
/// asked again in ref mode); a positive dentry stays; a negative one
/// is dropped for a lookup with no flags or one that creates (so a new
/// entry takes the spelling the caller gave: LOOKUP_CREATE,
/// LOOKUP_RENAME_TARGET), else kept while its directory's version is
/// the one its lookup saw (vfat_revalidate_shortname, `d_time`: Linux
/// d_fsdata)
fn vfat_revalidate_ci(
    dir: &Inode,
    d: &crate::fs::dentry::Dentry,
    inode: Option<&Inode>,
    flags: crate::fs::dentry::LookupBits,
) -> Result<bool, KernelError> {
    use crate::fs::dentry::LookupBits;
    if flags.contains(LookupBits::RCU) {
        return Err(KernelError::NoChild);
    }
    if inode.is_some() {
        return Ok(true);
    }
    if flags.is_empty() || flags.intersects(LookupBits::CREATE | LookupBits::RENAME_TARGET) {
        return Ok(false);
    }
    Ok(dir.iversion() == d.d_time())
}

/// A name for a new entry (Linux vfat_create_shortname /
/// vfat_valid_longname): EINVAL for nothing left or a character FAT
/// forbids, ENAMETOOLONG past 255 UTF-16 units
fn new_name(dir: &Inode, name: &[u8]) -> Result<String, KernelError> {
    let s = user_name(dir, name, KernelError::InvalidArgument)?;
    if s.is_empty()
        || s.chars()
            .any(|c| (c as u32) < 0x20 || "*?<>|\":/\\".contains(c))
    {
        return Err(KernelError::InvalidArgument);
    }
    if s.encode_utf16().count() > 255 {
        return Err(KernelError::NameTooLong);
    }
    Ok(s)
}

impl AsAny for VfatSbData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// VFAT inode data (Linux msdos_inode_info): copied in and out of
/// `VfatInode`
#[derive(Clone, Copy)]
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
    /// Bytes from the start whose blocks are allocated and initialized
    /// (Linux mmu_private): the size when read from disk, raised to the
    /// end of the block a write or expanding truncate reaches, lowered
    /// by a truncate; a direct write past it goes through the cache.
    /// Changed under i_rwsem.
    pub mmu_private: u64,
    /// Clusters the file has (Linux i_blocks in clusters): the size's
    /// when read from disk, then counted as clusters are added and freed
    pub clusters: u32,
    /// Creation time (Linux i_crtime), written back with the entry
    pub crtime: Timespec,
    /// Disk offset of its short entry, 0 for none: the root, or an
    /// entry gone (Linux i_pos, under `VfatSbData.ipos`)
    pub i_pos: u64,
}

/// A vfat inode's `Inode.private`: its data, changed in place (a
/// cluster allocated or freed, a rename) so those paths allocate
/// nothing; a leaf lock, held only to copy the data
pub struct VfatInode {
    d: crate::sync::spin::Mutex<VfatInodeData>,
    /// Cluster chain positions (Linux cache_lru_lock): a leaf, held
    /// only to look a run up or add one, never with `d`
    cache: crate::sync::spin::Mutex<cache::FatCache>,
}

impl InodeData for VfatInode {}

impl AsAny for VfatInode {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// A new inode's private data
fn new_private(d: VfatInodeData) -> Result<Arc<VfatInode>, KernelError> {
    try_arc(VfatInode {
        d: crate::sync::spin::Mutex::new(d),
        cache: cache::new_cache(d.start_cluster),
    })
}

/// Replace `inode`'s data (Linux updates msdos_inode_info in place)
fn set_inode_data(inode: &Inode, d: VfatInodeData) -> Result<(), KernelError> {
    with_vi(inode, |v| {
        *v.d.lock() = d;
        // After the data: a walk that sees the new id sees the new chain
        v.cache.lock().set_start(d.start_cluster);
    })
}

/// Run `f` on `inode`'s `VfatInode`
fn with_vi<R>(inode: &Inode, f: impl FnOnce(&VfatInode) -> R) -> Result<R, KernelError> {
    let private = inode.get_private().ok_or(KernelError::Io)?;
    let v = private
        .as_any()
        .downcast_ref::<VfatInode>()
        .ok_or(KernelError::Io)?;
    Ok(f(v))
}

// ============================================================================
// Block Device I/O
// ============================================================================

/// Read bytes of the device through its page cache (Linux sb_bread:
/// the bdev mapping, shared with device-node I/O)
fn read_bytes(bdev: &BlockDevice, offset: u64, buf: &mut [u8]) -> Result<(), KernelError> {
    match crate::mm::filemap::read(&bdev.bd_inode, buf, offset)? {
        n if n == buf.len() => Ok(()),
        _ => Err(KernelError::Io),
    }
}

/// Write bytes of the device through its cache, only the sectors
/// touched dirtied (`bdev_write_meta`): a cache page may also hold
/// file-data clusters, which the file's own cache writes
fn write_bytes(bdev: &BlockDevice, offset: u64, buf: &[u8]) -> Result<(), KernelError> {
    super::blkdev_ops::bdev_write_meta(bdev, offset, buf)
}

// ============================================================================
// VFAT Helpers
// ============================================================================

/// Get VFAT superblock data from superblock (cloned to avoid lifetime issues)
fn get_sb_data(sb: &SuperBlock) -> Result<VfatSbData, KernelError> {
    let guard = sb.private.read();
    guard
        .as_ref()
        .and_then(|p| p.as_any().downcast_ref::<VfatSbData>())
        .cloned()
        .ok_or(KernelError::Io)
}

/// The cluster size of `inode`'s filesystem, read in place
fn cluster_size(inode: &Inode) -> Option<u32> {
    let sb = inode.superblock()?;
    let p = sb.private.read();
    p.as_ref()?
        .as_any()
        .downcast_ref::<VfatSbData>()
        .map(|d| d.cluster_size)
}

/// A copy of `inode`'s VFAT data
fn get_inode_data(inode: &Inode) -> Result<VfatInodeData, KernelError> {
    with_vi(inode, |v| *v.d.lock())
}

/// Read a FAT entry for a cluster
fn get_fat_entry(sb_data: &VfatSbData, cluster: u32) -> Result<u32, KernelError> {
    // Linux fat_ent_read: "invalid access to FAT" is EIO
    if !(2..sb_data.max_cluster).contains(&cluster) {
        return Err(KernelError::Io);
    }
    let fat_offset = u64::from(cluster) * 4;
    let fat_sector = sb_data.fat_start_sector + fat_offset / u64::from(sb_data.bytes_per_sector);
    let offset_in_sector = (fat_offset % u64::from(sb_data.bytes_per_sector)) as usize;

    let byte_offset = fat_sector * u64::from(sb_data.bytes_per_sector) + offset_in_sector as u64;
    let mut buf = [0u8; 4];
    read_bytes(&sb_data.bdev, byte_offset, &mut buf)?;

    Ok(u32::from_le_bytes(buf) & 0x0FFF_FFFF)
}

/// Check if cluster number indicates end of chain
fn is_end_of_chain(cluster: u32) -> bool {
    cluster >= 0x0FFF_FFF8
}

/// The bad-cluster mark: cluster numbers stay below it (Linux
/// BAD_FAT32)
const FAT_BAD: u32 = 0x0FFF_FFF7;

/// Check if cluster is valid (not reserved, free, or bad)
fn is_valid_cluster(cluster: u32) -> bool {
    (2..0x0FFF_FFF0).contains(&cluster)
}

/// Convert cluster number to byte offset in data region
fn cluster_to_offset(sb_data: &VfatSbData, cluster: u32) -> u64 {
    let data_offset = (u64::from(cluster) - 2) * u64::from(sb_data.cluster_size);
    sb_data.data_start_sector * u64::from(sb_data.bytes_per_sector) + data_offset
}

/// The clusters of the chain at `start` (0: none), one at a time, the
/// FAT read as it goes by `fat` (Linux fat_get_cluster's walk over
/// fat_ent_read): EIO, ending the walk, for a cluster mid-chain that
/// is free, bad or past the last one (`max_cluster`), or a chain longer
/// than any file or directory may be (a loop: Linux bounds the walk by
/// s_maxbytes >> cluster_bits, 4 GiB here)
struct Chain<F> {
    fat: F,
    max_cluster: u32,
    /// The next cluster to yield, as read (None: the walk is over)
    next: Option<u32>,
    /// The one before it, whose FAT entry gives the next (None: `next`
    /// is the first)
    prev: Option<u32>,
    /// Clusters left before the chain is a loop
    left: u64,
}

impl<F: FnMut(u32) -> Result<u32, KernelError>> Chain<F> {
    fn with(fat: F, max_cluster: u32, cluster_size: u32, start: u32) -> Self {
        Self {
            fat,
            max_cluster,
            next: (start != 0).then_some(start),
            prev: None,
            left: u64::from(max_cluster).min((1u64 << 32) / u64::from(cluster_size) + 1),
        }
    }
}

/// The chain at `start` of `sb_data`'s FAT
fn fat_chain(
    sb_data: &VfatSbData,
    start: u32,
) -> Chain<impl FnMut(u32) -> Result<u32, KernelError> + '_> {
    Chain::with(
        move |c| get_fat_entry(sb_data, c),
        sb_data.max_cluster,
        sb_data.cluster_size,
        start,
    )
}

impl<F: FnMut(u32) -> Result<u32, KernelError>> Iterator for Chain<F> {
    type Item = Result<u32, KernelError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(p) = self.prev.take() {
            match (self.fat)(p) {
                Ok(n) => self.next = (!is_end_of_chain(n)).then_some(n),
                Err(e) => {
                    self.next = None;
                    return Some(Err(e));
                }
            }
        }
        let c = self.next.take()?;
        // A free (0), reserved, bad or out-of-range entry is corruption
        if !(2..self.max_cluster).contains(&c) || self.left == 0 {
            return Some(Err(KernelError::Io));
        }
        self.left -= 1;
        self.prev = Some(c);
        Some(Ok(c))
    }
}

/// The clusters of the chain at `start_cluster` (0: none), a corrupt
/// chain EIO as `Chain` finds it; the vector grows fallibly
fn read_cluster_chain(sb_data: &VfatSbData, start_cluster: u32) -> Result<Vec<u32>, KernelError> {
    let mut chain = Vec::new();
    for c in fat_chain(sb_data, start_cluster) {
        chain.try_reserve(1).map_err(|_| KernelError::OutOfMemory)?;
        chain.push(c?);
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
fn set_fat_entry(sb_data: &VfatSbData, cluster: u32, value: u32) -> Result<(), KernelError> {
    let fat_offset = u64::from(cluster) * 4;
    let offset_in_fat = fat_offset % (sb_data.fat_sectors * u64::from(sb_data.bytes_per_sector));

    // Preserve high 4 bits of existing entry (reserved bits in FAT32)
    let existing = get_fat_entry(sb_data, cluster)?;
    let new_value = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
    let buf = new_value.to_le_bytes();

    // Every FAT copy the boot sector declares (Linux fat_mirror_bhs)
    for fat_num in 0..sb_data.num_fats {
        let fat_start = sb_data.fat_start_sector + fat_num * sb_data.fat_sectors;
        let byte_offset = fat_start * u64::from(sb_data.bytes_per_sector) + offset_in_fat;
        write_bytes(&sb_data.bdev, byte_offset, &buf)?;
    }

    Ok(())
}

/// Find and allocate a free cluster
///
/// Searches the FAT for a free cluster (value 0), marks it as end-of-chain,
/// and returns the cluster number.
fn allocate_cluster(sb_data: &VfatSbData) -> Result<u32, KernelError> {
    // The search and the claim as one (Linux fat_alloc_clusters under
    // lock_fat): no two allocations take one cluster
    let mut fat = sb_data.fat.lock();
    // Next fit among the data clusters (the BPB's size, not the
    // device's): after the last one taken, then from the start
    let after = fat.prev_free.max(1) + 1;
    let found = match fat_scan(sb_data, after, sb_data.max_cluster, |_, e| e == FAT_FREE)? {
        Some(c) => Some(c),
        None => fat_scan(sb_data, 2, after.min(sb_data.max_cluster), |_, e| {
            e == FAT_FREE
        })?,
    };
    let Some(cluster) = found else {
        return Err(KernelError::NoSpace);
    };
    // Marked end-of-chain
    set_fat_entry(sb_data, cluster, FAT_EOC)?;
    fat.prev_free = cluster;
    if fat.free > 0 {
        fat.free -= 1;
    }
    drop(fat);
    if let Err(e) = zero_cluster(sb_data, cluster) {
        // Claimed and in no chain: given back, not leaked
        let _ = free_cluster_chain(sb_data, cluster);
        return Err(e);
    }
    Ok(cluster)
}

/// The first cluster in [from, to) whose FAT entry `f` picks, the FAT
/// read a page at a time (Linux fat_ent_next over its blocks, not an
/// entry at a time)
fn fat_scan(
    sb_data: &VfatSbData,
    from: u32,
    to: u32,
    mut f: impl FnMut(u32, u32) -> bool,
) -> Result<Option<u32>, KernelError> {
    const PER: u32 = 1024; // 4-byte entries in 4 KiB
    let base = sb_data.fat_start_sector * u64::from(sb_data.bytes_per_sector);
    // Off the stack: the allocation path below it goes deep (Linux reads
    // the FAT through buffer heads, no copy on the stack)
    let mut buf = crate::util::kmem::try_vec(4096, 0u8)?;
    let mut c = from;
    while c < to {
        let n = (PER - c % PER).min(to - c);
        let bytes = &mut buf[..n as usize * 4];
        read_bytes(&sb_data.bdev, base + u64::from(c) * 4, bytes)?;
        for (k, e) in bytes.as_chunks::<4>().0.iter().enumerate() {
            let v = u32::from_le_bytes(*e) & 0x0FFF_FFFF;
            if f(c + k as u32, v) {
                return Ok(Some(c + k as u32));
            }
        }
        c += n;
    }
    Ok(None)
}

/// Zero `cluster` on the disk itself, after the device cache's pages of
/// it are written back and dropped (Linux clean_bdev_aliases): a file's
/// data never goes through the device cache, so no stale or dirty copy
/// of an old directory block may outlive the reuse
fn zero_cluster(sb_data: &VfatSbData, cluster: u32) -> Result<(), KernelError> {
    let off = cluster_to_offset(sb_data, cluster);
    let len = u64::from(sb_data.cluster_size);
    filemap::invalidate_range(&sb_data.bdev.bd_inode, off, off + len)?;
    let mut zeros = crate::util::kmem::try_vec(len as usize, 0u8)?;
    bdev_rw_bytes(&sb_data.bdev, BioOp::Write, off, &mut zeros)?;
    // Again: a page a reader cached before the zeros landed holds the
    // old bytes
    filemap::invalidate_range(&sb_data.bdev.bd_inode, off, off + len)
}

/// Free a cluster chain starting from start_cluster (Linux
/// fat_free_clusters, under lock_fat)
fn free_cluster_chain(sb_data: &VfatSbData, start_cluster: u32) -> Result<(), KernelError> {
    let mut fat = sb_data.fat.lock();
    let mut cluster = start_cluster;

    while is_valid_cluster(cluster) {
        let next = get_fat_entry(sb_data, cluster)?;
        set_fat_entry(sb_data, cluster, FAT_FREE)?;
        if fat.free >= 0 {
            fat.free += 1;
        }

        if is_end_of_chain(next) {
            break;
        }
        cluster = next;
    }

    Ok(())
}

/// The free data clusters, counted from the FAT the first time (Linux
/// fat_count_free_clusters, under lock_fat)
fn free_clusters(sb_data: &VfatSbData) -> Result<u64, KernelError> {
    let mut fat = sb_data.fat.lock();
    if fat.free < 0 {
        let mut n = 0i64;
        fat_scan(sb_data, 2, sb_data.max_cluster, |_, e| {
            n += i64::from(e == FAT_FREE);
            false
        })?;
        fat.free = n;
    }
    Ok(fat.free as u64)
}

/// Extend a cluster chain by `count` clusters, linking them as it goes
/// (no buffer the size of the file). `last_cluster` 0 starts a new
/// chain. Returns the first new cluster (0 if `count` is 0). On failure
/// partway, the partial chain is freed, so no clusters leak.
fn extend_cluster_chain(
    sb_data: &VfatSbData,
    last_cluster: u32,
    count: usize,
) -> Result<u32, KernelError> {
    // Undo a partial extension: free the clusters already linked from
    // the first new one, and point the existing chain's tail back at
    // end-of-chain
    let mut first = ScopeGuard::new_with_data(0u32, |first| {
        if first != 0 {
            let _ = free_cluster_chain(sb_data, first);
        }
        if last_cluster != 0 {
            let _ = set_fat_entry(sb_data, last_cluster, FAT_EOC);
        }
    });
    let mut prev = last_cluster;
    for _ in 0..count {
        let cluster = allocate_cluster(sb_data)?;
        if prev != 0
            && let Err(e) = set_fat_entry(sb_data, prev, cluster)
        {
            // `cluster` is allocated but not yet linked: a chain of its own
            // (end of chain), freed under the FAT lock with the count
            let _ = free_cluster_chain(sb_data, cluster);
            return Err(e);
        }
        if *first == 0 {
            *first = cluster;
        }
        prev = cluster;
    }
    Ok(first.dismiss())
}

// ============================================================================
// Directory Entry Parsing
// ============================================================================

/// A short entry's times as on disk (Linux msdos_dir_entry time, date,
/// adate, ctime, cdate, ctime_cs)
#[derive(Clone, Copy, Default)]
pub struct EntryTimes {
    pub time: u16,
    pub date: u16,
    pub adate: u16,
    pub ctime: u16,
    pub cdate: u16,
    pub cs: u8,
}

impl EntryTimes {
    /// Those of entry `d`
    fn of(d: &VfatDirEntry) -> Self {
        Self {
            time: d.write_time,
            date: d.write_date,
            adate: d.access_date,
            ctime: d.create_time,
            cdate: d.create_date,
            cs: d.create_time_tenth,
        }
    }

    /// A new entry's, all `ts` (Linux vfat_build_slots,
    /// fat_alloc_new_dir)
    fn at(off: i64, ts: Timespec) -> Self {
        let (time, date, cs) = fattime::unix2fat(off, ts);
        Self {
            time,
            date,
            adate: date,
            ctime: time,
            cdate: date,
            cs,
        }
    }

    /// An inode's (Linux __fat_write_inode: mtime, atime, i_crtime)
    fn of_inode(off: i64, inode: &Inode, crtime: Timespec) -> Self {
        let (time, date, _) = fattime::unix2fat(off, inode.mtime());
        let (_, adate, _) = fattime::unix2fat(off, inode.atime());
        let (ctime, cdate, cs) = fattime::unix2fat(off, crtime);
        Self {
            time,
            date,
            adate,
            ctime,
            cdate,
            cs,
        }
    }

    /// Into the raw short entry `b`
    fn put(&self, b: &mut [u8; 32]) {
        b[13] = self.cs;
        b[14..16].copy_from_slice(&self.ctime.to_le_bytes());
        b[16..18].copy_from_slice(&self.cdate.to_le_bytes());
        b[18..20].copy_from_slice(&self.adate.to_le_bytes());
        b[22..24].copy_from_slice(&self.time.to_le_bytes());
        b[24..26].copy_from_slice(&self.date.to_le_bytes());
    }
}

/// Linux fat_fill_inode's times: mtime and ctime from the entry's time
/// and date, atime from its access date; the creation time, returned
fn fill_times(inode: &Inode, off: i64, t: &EntryTimes) -> Timespec {
    let m = fattime::fat2unix(off, t.time, t.date, 0);
    inode.set_mtime(m);
    inode.set_ctime(m);
    inode.set_atime(fattime::fat2unix(off, 0, t.adate, 0));
    fattime::fat2unix(off, t.ctime, t.cdate, t.cs)
}

/// The root (it has no entry; Linux MSDOS_ROOT_INO)
fn is_root(inode: &Inode) -> bool {
    get_inode_data(inode).is_ok_and(|d| d.parent_cluster == 0)
}

/// Linux fat_truncate_time: atime to the day, mtime to 2 s and ctime
/// with it, from `now` (else the current time); the root's stay 0
fn fat_truncate_time(inode: &Inode, now: Option<Timespec>, atime: bool, cmtime: bool) {
    if is_root(inode) {
        return;
    }
    let Some(off) = opts_of(inode).map(|o| o.tz()) else {
        return;
    };
    let now = now.unwrap_or_else(|| crate::time::TIMEKEEPER.current_time());
    if atime {
        inode.set_atime(fattime::trunc_atime(off, now));
    }
    if cmtime {
        let m = fattime::trunc_2secs(now);
        inode.set_mtime(m);
        inode.set_ctime(m);
    }
}

/// Linux fat_write_inode / __fat_write_inode (->write_inode, from
/// writeback, fsync, sync, unmount and the write-back before an
/// eviction, whatever its sync mode): size (0 for a directory), first
/// cluster and times into the inode's entry in the device's cache,
/// then marked I_METADATA_WRITEBACK for a data-integrity write to wait
/// for (`fat_sync_inode_metadata`); the root has no entry but is
/// marked all the same, an inode with no entry left (unlinked) is
/// neither
fn fat_write_inode(inode: &Inode) -> Result<(), KernelError> {
    if is_root(inode) {
        super::fs_writeback::set_inode_metadata_writeback(inode);
        return Ok(());
    }
    let sb = inode.superblock().ok_or(KernelError::Io)?;
    let sb_data = get_sb_data(&sb)?;
    {
        // i_pos and the entry it names, unchanged until the write is done
        let _l = sb_data.ipos.lock();
        let d = get_inode_data(inode)?;
        if d.i_pos == 0 {
            return Ok(());
        }
        let off = d.i_pos;
        let mut b = [0u8; 32];
        read_bytes(&sb_data.bdev, off, &mut b)?;
        let ((start, size), times) = inode_entry(inode, &d, &sb_data);
        entry_set_extent(&mut b, start, size);
        times.put(&mut b);
        write_bytes(&sb_data.bdev, off, &b)?;
    }
    super::fs_writeback::set_inode_metadata_writeback(inode);
    Ok(())
}

/// Linux fat_sync_inode_metadata (->sync_inode_metadata): the entry's
/// block on the disk (sync_dirty_buffer), then the inode's other
/// metadata blocks (mmb_sync of i_metadata_bhs). With no buffer heads
/// the device's whole cache stands in for both (BUGS.md "No buffer
/// heads").
fn fat_sync_inode_metadata(inode: &Inode) -> Result<(), KernelError> {
    let sb = inode.superblock().ok_or(KernelError::Io)?;
    sync_buffers(&get_sb_data(&sb)?)
}

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
    /// Index of the short entry's 32-byte slot in the directory (its
    /// stable readdir position, like Linux fat_readdir's cpos)
    pub slot: u64,
    /// Disk offset of the short entry (its i_pos)
    pub i_pos: u64,
    /// Its slots, the long-name ones before it included (Linux
    /// fat_slot_info.nr_slots)
    pub nr_slots: u8,
    /// Its times
    pub times: EntryTimes,
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

/// The UTF-16 units of one LFN entry, up to its terminator or padding
fn lfn_entry_chars(entry: &VfatLfnEntry) -> Vec<u16> {
    // name1: 5 chars, name2: 6 chars, name3: 2 chars (packed fields,
    // copied out by value)
    let (n1, n2, n3) = (entry.name1, entry.name2, entry.name3);
    n1.into_iter()
        .chain(n2)
        .chain(n3)
        .take_while(|&c| c != 0 && c != 0xFFFF)
        .collect()
}

/// A long name from its LFN entries' UTF-16 (a pair may span two
/// entries); unpaired surrogates become U+FFFD
fn lfn_name(parts: &mut [(u8, Vec<u16>)]) -> String {
    parts.sort_by_key(|(order, _)| *order);
    char::decode_utf16(parts.iter().flat_map(|(_, u)| u.iter().copied()))
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

/// Most LFN entries one name spans (Linux: 255 UTF-16 units in 13-unit
/// slots, fat_parse_long's "slots > 20" bogus check)
const MAX_LFN_SLOTS: usize = 20;

/// The LFN entries gathered before their short entry (Linux
/// fat_parse_long): at most MAX_LFN_SLOTS of them, the first carrying
/// the last-entry bit and the short name's checksum
#[derive(Default)]
struct Lfn {
    parts: Vec<(u8, Vec<u16>)>,
    checksum: Option<u8>,
}

impl Lfn {
    fn clear(&mut self) {
        self.parts.clear();
        self.checksum = None;
    }

    /// One LFN entry; a sequence that does not start with the last-entry
    /// bit, an order outside 1..=20 or more than 20 entries is bogus and
    /// leaves only the short name
    fn add(&mut self, lfn: &VfatLfnEntry) {
        let order = lfn.order & 0x3F;
        if lfn.order & 0x40 != 0 {
            self.clear();
            self.checksum = Some(lfn.checksum);
        }
        let bogus = order == 0 || usize::from(order) > MAX_LFN_SLOTS;
        if bogus || self.checksum.is_none() || self.parts.len() >= MAX_LFN_SLOTS {
            self.clear();
            return;
        }
        self.parts.push((order, lfn_entry_chars(lfn)));
    }

    /// The long name for the short entry `name`.`ext`, if the gathered
    /// entries belong to it (checksum); the state is cleared
    fn take_name(&mut self, name: &[u8; 8], ext: &[u8; 3]) -> Option<String> {
        let ok = !self.parts.is_empty() && self.checksum == Some(lfn_checksum(name, ext));
        let long = ok.then(|| lfn_name(&mut self.parts));
        self.clear();
        long
    }
}

/// One 32-byte slot of a directory
struct Slot<'a> {
    /// Its disk offset (a short entry's i_pos)
    off: u64,
    /// The cluster holding it
    cluster: u32,
    /// Its index in the directory
    idx: u64,
    b: &'a [u8; 32],
}

/// Walk the slots of the directory at `start` (0: none), a cluster
/// read at a time (Linux fat_get_entry through the directory's
/// buffers), the chain followed as it goes (`Chain`, EIO if corrupt):
/// `f` ends the walk with Break. None: the chain ended first.
fn dir_walk<B>(
    sb_data: &VfatSbData,
    start: u32,
    mut f: impl FnMut(&Slot<'_>) -> Result<ControlFlow<B>, KernelError>,
) -> Result<Option<B>, KernelError> {
    if start == 0 {
        return Ok(None);
    }
    let cs = sb_data.cluster_size as usize;
    let per = cs as u64 / 32;
    let mut buf = crate::util::kmem::try_vec(cs, 0u8)?;
    for (ci, c) in (0u64..).zip(fat_chain(sb_data, start)) {
        let c = c?;
        let base = cluster_to_offset(sb_data, c);
        read_bytes(&sb_data.bdev, base, &mut buf)?;
        for (i, b) in (0u64..).zip(buf.as_chunks::<32>().0) {
            let s = Slot {
                off: base + i * 32,
                cluster: c,
                idx: ci * per + i,
                b,
            };
            if let ControlFlow::Break(r) = f(&s)? {
                return Ok(Some(r));
            }
        }
    }
    Ok(None)
}

/// Directory short entries in the directory at `cluster`, "." and ".."
/// included (Linux fat_subdirs: its i_nlink)
fn fat_subdirs(sb_data: &VfatSbData, cluster: u32) -> Result<u32, KernelError> {
    let mut n = 0;
    dir_walk(sb_data, cluster, |s| {
        match s.b[0] {
            END_MARKER => return Ok(ControlFlow::Break(())),
            DELETED_MARKER => {}
            // fat_get_short_entry skips long-name slots
            _ if s.b[11] & attr::LONG_NAME_MASK == attr::LONG_NAME => {}
            _ if s.b[11] & attr::DIRECTORY != 0 => n += 1,
            _ => {}
        }
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(n)
}

/// The short entry in slot `s`, its long name (if `lfn` gathered one
/// for it) as its name and `lfn_slots` long-name slots before it
fn parse_short(s: &Slot<'_>, lfn: &mut Lfn, lfn_slots: usize) -> ParsedDirEntry {
    let dirent = VfatDirEntry::read_from(s.b).expect("32-byte entry");
    // The long name if its entries match, else the short one
    let long = lfn.take_name(&dirent.name, &dirent.ext);
    let nr_slots = if long.is_some() { lfn_slots + 1 } else { 1 };
    let name = long.unwrap_or_else(|| short_name_to_string(&dirent.name, &dirent.ext));
    let start_cluster =
        (u32::from(dirent.first_cluster_hi) << 16) | u32::from(dirent.first_cluster_lo);
    let mut short_name = [b' '; 11];
    short_name[0..8].copy_from_slice(&dirent.name);
    short_name[8..11].copy_from_slice(&dirent.ext);
    ParsedDirEntry {
        name,
        short_name,
        attr: s.b[11],
        start_cluster,
        file_size: dirent.file_size,
        slot: s.idx,
        i_pos: s.off,
        nr_slots: nr_slots as u8,
        times: EntryTimes::of(&dirent),
    }
}

/// The most slots an entry takes: its long-name ones and its short one
const MAX_SLOTS: usize = MAX_LFN_SLOTS + 1;

/// The free slots a directory walk saw, for a new entry (Linux
/// fat_add_entries' first stage, here in the walk that read the
/// entries): where the first free run of each length up to
/// `MAX_SLOTS` starts, the free run reaching the end of the walk, and
/// the walk's clusters (a slot's index to its disk offset)
#[derive(Default)]
struct FreeSlots {
    first: [Option<u64>; MAX_SLOTS],
    /// The current free run: its first slot and length
    run: Option<(u64, u64)>,
    clusters: Vec<u32>,
}

impl FreeSlots {
    /// Note slot `s`, the walk's next (`per` slots a cluster)
    fn see(&mut self, s: &Slot<'_>, per: u64) -> Result<(), KernelError> {
        if s.idx.is_multiple_of(per) {
            self.clusters
                .try_reserve(1)
                .map_err(|_| KernelError::OutOfMemory)?;
            self.clusters.push(s.cluster);
        }
        if s.b[0] != END_MARKER && s.b[0] != DELETED_MARKER {
            self.run = None;
            return Ok(());
        }
        let (start, len) = self.run.get_or_insert((s.idx, 0));
        *len += 1;
        if let Some(f) = usize::try_from(*len - 1)
            .ok()
            .and_then(|i| self.first.get_mut(i))
            && f.is_none()
        {
            *f = Some(*start);
        }
        Ok(())
    }

    /// A run of every length is known: the walk need not go on
    fn full(&self) -> bool {
        self.first[MAX_SLOTS - 1].is_some()
    }
}

/// The entries of the directory at `start_cluster`, "." and ".." and
/// volume labels left out, each with its disk offset; the list grows
/// fallibly (ENOMEM), a directory being as large as its disk says
fn read_directory_entries(
    sb_data: &VfatSbData,
    start_cluster: u32,
) -> Result<Vec<ParsedDirEntry>, KernelError> {
    read_dir(sb_data, start_cluster, None)
}

/// [`read_directory_entries`] and, in the same walk, the directory's
/// free slots for a new entry
fn scan_dir(
    sb_data: &VfatSbData,
    start_cluster: u32,
) -> Result<(Vec<ParsedDirEntry>, FreeSlots), KernelError> {
    let mut free = FreeSlots::default();
    let entries = read_dir(sb_data, start_cluster, Some(&mut free))?;
    Ok((entries, free))
}

/// Read the entries up to the end-of-directory slot; with `free`, go
/// on past it while free runs are still to be found
fn read_dir(
    sb_data: &VfatSbData,
    start_cluster: u32,
    mut free: Option<&mut FreeSlots>,
) -> Result<Vec<ParsedDirEntry>, KernelError> {
    let per = u64::from(sb_data.cluster_size) / 32;
    let mut entries = crate::util::kmem::KVec::new();
    let mut lfn = Lfn::default();
    // Long-name slots gathered since the last other one
    let mut run = 0;
    // The end-of-directory slot was seen: no entry follows
    let mut end = false;
    dir_walk(sb_data, start_cluster, |s| {
        if let Some(f) = free.as_deref_mut() {
            f.see(s, per)?;
        }
        if s.b[0] == END_MARKER {
            end = true;
        }
        if end {
            return Ok(match free.as_deref() {
                Some(f) if !f.full() => ControlFlow::Continue(()),
                _ => ControlFlow::Break(()),
            });
        }
        let attr = s.b[11];
        match s.b[0] {
            DELETED_MARKER => {
                lfn.clear();
                run = 0;
            }
            _ if attr & attr::LONG_NAME_MASK == attr::LONG_NAME => {
                let e = VfatLfnEntry::read_from(s.b).expect("32-byte entry");
                if e.order & 0x40 != 0 {
                    run = 0;
                }
                lfn.add(&e);
                run += 1;
            }
            _ if attr & attr::VOLUME_ID != 0 => {
                lfn.clear();
                run = 0;
            }
            _ => {
                let e = parse_short(s, &mut lfn, run);
                run = 0;
                if e.name != "." && e.name != ".." {
                    entries.try_push(e)?;
                }
            }
        }
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(entries.into_vec())
}

// ============================================================================
// Directory Entry Write Operations
// ============================================================================

/// Generate an 8.3 short name from a long filename
///
/// Returns an 11-byte array with 8 chars for name + 3 chars for extension,
/// both space-padded.
fn generate_short_name(long_name: &str, existing_short_names: &[[u8; 11]]) -> Option<[u8; 11]> {
    let result = [b' '; 11];

    // The extension follows the last dot, unless all before it is dots
    // and spaces ("...test", "  .txt": then all of it is the base, as
    // Linux vfat_create_shortname and Windows)
    let (base, ext) = match long_name.rfind('.') {
        Some(d) if !long_name[..d].bytes().all(|c| c == b' ' || c == b'.') => {
            (&long_name[..d], &long_name[d + 1..])
        }
        _ => (long_name, ""),
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
    // No base character left: no short name (Linux: EINVAL); one never
    // starts with a space
    if clean_base.is_empty() {
        return None;
    }

    // Convert extension similarly
    let clean_ext: String = ext
        .chars()
        .filter(|&c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        .map(|c| c.to_ascii_uppercase())
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
            return Some(candidate);
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
            return Some(candidate);
        }
    }

    // Fallback (should never happen with 999999 attempts)
    Some(result)
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

    // UTF-16; unless it fills its last entry exactly, NUL-terminated
    // and padded with 0xFFFF (Linux xlate_to_uni)
    let mut padded: Vec<u16> = name.encode_utf16().collect();
    if !padded.len().is_multiple_of(13) {
        padded.push(0);
        padded.resize(padded.len().div_ceil(13) * 13, 0xFFFF);
    }

    let num_entries = padded.len() / 13;
    let mut entries = Vec::with_capacity(num_entries);

    for i in 0..num_entries {
        let seq_num = (i + 1) as u8;
        let is_last = i == num_entries - 1;
        let order = if is_last { seq_num | 0x40 } else { seq_num };

        let chunk = &padded[i * 13..(i + 1) * 13];

        let mut entry = VfatLfnEntry {
            order,
            attr: attr::LONG_NAME,
            checksum,
            ..FromBytes::zeroed()
        };

        // The name fields (packed: assigned by value)
        entry.name1 = chunk[0..5].try_into().expect("5 chars");
        entry.name2 = chunk[5..11].try_into().expect("6 chars");
        entry.name3 = chunk[11..13].try_into().expect("2 chars");

        entries.push(entry);
    }

    // Reverse so highest sequence number is first (this is how they're stored on disk)
    entries.reverse();
    entries
}

/// The disk offsets of `n` consecutive free slots of a directory whose
/// walk saw `free` (Linux fat_add_entries: the first free run long
/// enough, else the free run at its end and new clusters,
/// fat_add_new_entries), in directory order. New clusters come zeroed
/// (`allocate_cluster`): their slots are all free and the first ends
/// the directory.
fn find_free_dir_slots(
    sb_data: &VfatSbData,
    free: &FreeSlots,
    n: usize,
) -> Result<Vec<u64>, KernelError> {
    if n == 0 || n > MAX_SLOTS {
        return Err(KernelError::InvalidArgument);
    }
    let per = u64::from(sb_data.cluster_size) / 32;
    let off = |idx: u64| {
        let c = usize::try_from(idx / per)
            .ok()
            .and_then(|i| free.clusters.get(i))
            .ok_or(KernelError::Io)?;
        Ok::<_, KernelError>(cluster_to_offset(sb_data, *c) + idx % per * 32)
    };
    let mut run = Vec::new();
    run.try_reserve(n).map_err(|_| KernelError::OutOfMemory)?;
    if let Some(start) = free.first[n - 1] {
        for i in start..start + n as u64 {
            run.push(off(i)?);
        }
        return Ok(run);
    }
    // Not enough room (the walk went to the end): the free run reaching
    // the directory's end (its end-of-directory slots among them, which
    // must not stay before the entry) continues into new clusters, only
    // the slots still needed allocated (Linux fat_add_entries:
    // fat_add_new_entries)
    if let Some((start, len)) = free.run {
        for i in start..start + len {
            run.push(off(i)?);
        }
    }
    let last = *free.clusters.last().ok_or(KernelError::Io)?;
    let more = (n - run.len()).div_ceil(per as usize);
    let mut c = extend_cluster_chain(sb_data, last, more)?;
    for k in 0..more {
        if k > 0 {
            c = get_fat_entry(sb_data, c)?;
        }
        let base = cluster_to_offset(sb_data, c);
        let take = (n - run.len()).min(per as usize);
        run.extend((0..take as u64).map(|i| base + i * 32));
    }
    Ok(run)
}

/// A new directory entry: its name, attributes, first cluster and
/// size, and the time all its times are (Linux vfat_build_slots' ts)
struct NewEntry<'a> {
    name: &'a str,
    attr: u8,
    extent: (u32, u32),
    ts: Timespec,
}

/// Add entry `e` to a directory whose walk (`scan_dir`) saw the entries
/// `existing` and the free slots `free` (Linux vfat_build_slots +
/// fat_add_entries): its long-name
/// slots (unless the name is its own 8.3 form) then its short one; on
/// a dirsync mount they are synced, and removed again if that fails
/// (fat_add_entries' error_remove). The short name and the slots' disk
/// offsets, the short entry's (its i_pos) last.
fn fat_add_entries(
    sb_data: &VfatSbData,
    dirsync: bool,
    existing: &[ParsedDirEntry],
    free: &FreeSlots,
    e: &NewEntry<'_>,
) -> Result<([u8; 11], Vec<u64>), KernelError> {
    let name = e.name;
    // Existing short names, to avoid collisions
    let existing_short_names: Vec<[u8; 11]> = existing.iter().map(|e| e.short_name).collect();

    // Generate short name
    let short_name =
        generate_short_name(name, &existing_short_names).ok_or(KernelError::InvalidArgument)?;

    // Check if we need LFN entries
    let needs_lfn = {
        // Long-name entries unless the name is exactly its 8.3 form
        let (base, ext) = short_name.split_at(8);
        let base: &[u8; 8] = base.try_into().unwrap_or(&[b' '; 8]);
        let ext: &[u8; 3] = ext.try_into().unwrap_or(&[b' '; 3]);
        short_name_to_string(base, ext) != name
    };

    let lfn_entries = if needs_lfn {
        create_lfn_entries(name, &short_name)
    } else {
        Vec::new()
    };

    // The LFN entries and the short one (any new cluster allocated
    // before `ipos`, which is never held with the FAT lock)
    let offs = find_free_dir_slots(sb_data, free, lfn_entries.len() + 1)?;
    let i_pos = *offs.last().ok_or(KernelError::Io)?;

    let mut short_bytes = [0u8; 32];
    short_bytes[0..11].copy_from_slice(&short_name);
    short_bytes[11] = e.attr;
    entry_set_extent(&mut short_bytes, e.extent.0, e.extent.1);
    EntryTimes::at(sb_data.opts.tz(), e.ts).put(&mut short_bytes);

    {
        // Every entry change under the location lock, as write_inode's
        let _l = sb_data.ipos.lock();
        // LFN entries first on disk, in reverse sequence order (the
        // entry's on-disk bytes: packed, little-endian, its layout)
        for (lfn, &off) in lfn_entries.iter().zip(&offs) {
            write_bytes(&sb_data.bdev, off, lfn.as_bytes())?;
        }
        write_bytes(&sb_data.bdev, i_pos, &short_bytes)?;
    }
    if dirsync && let Err(err) = sync_buffers(sb_data) {
        // error_remove: __fat_remove_entries, its error ignored
        let _l = sb_data.ipos.lock();
        let _ = mark_deleted(sb_data, &offs);
        return Err(err);
    }
    Ok((short_name, offs))
}

/// Set a raw short entry's first cluster (Linux fat_set_start)
fn entry_set_start(b: &mut [u8; 32], start: u32) {
    b[20..22].copy_from_slice(&((start >> 16) as u16).to_le_bytes());
    b[26..28].copy_from_slice(&(start as u16).to_le_bytes());
}

/// Set a raw short entry's first cluster and size
fn entry_set_extent(b: &mut [u8; 32], start: u32, size: u32) {
    entry_set_start(b, start);
    b[28..32].copy_from_slice(&size.to_le_bytes());
}

/// The disk offsets of entry `e`'s slots in the directory at `parent`,
/// its long-name ones first (Linux fat_remove_entries walks back from
/// the short entry): in the short entry's cluster, below it, unless
/// they begin in an earlier one
fn entry_slots(
    sb_data: &VfatSbData,
    parent: u32,
    e: &ParsedDirEntry,
) -> Result<Vec<u64>, KernelError> {
    let n = u64::from(e.nr_slots.max(1));
    let first = e.slot + 1 - n;
    let mut offs = Vec::new();
    offs.try_reserve(n as usize)
        .map_err(|_| KernelError::OutOfMemory)?;
    let per = u64::from(sb_data.cluster_size) / 32;
    if first / per == e.slot / per {
        offs.extend((0..n).rev().map(|k| e.i_pos - k * 32));
        return Ok(offs);
    }
    // Across clusters: the run's clusters from the chain
    let chain = read_cluster_chain(sb_data, parent)?;
    for idx in first..=e.slot {
        let c = usize::try_from(idx / per)
            .ok()
            .and_then(|i| chain.get(i))
            .ok_or(KernelError::Io)?;
        offs.push(cluster_to_offset(sb_data, *c) + idx % per * 32);
    }
    Ok(offs)
}

/// Mark the slots at disk offsets `offs` deleted: their first byte
/// 0xE5, as Linux sets de->name[0] in the buffer (the short entry's
/// last). The caller holds `ipos`.
fn mark_deleted(sb_data: &VfatSbData, offs: &[u64]) -> Result<(), KernelError> {
    for &off in offs {
        write_bytes(&sb_data.bdev, off, &[DELETED_MARKER])?;
    }
    Ok(())
}

/// Remove an entry of `dir` whose slots are at `offs` (Linux
/// fat_remove_entries): they are marked deleted under `ipos`, with
/// `detach`'s inode leaving the entry in the same hold (i_pos 0, Linux
/// fat_detach: no write_inode writes the entry back after its
/// deletion); on a dirsync mount they are synced, an error returned
/// before anything else changes; then the directory's version and its
/// end of change, atime too (`dir_update`)
fn fat_remove_entries(
    dir: &Inode,
    sb: &SuperBlock,
    sb_data: &VfatSbData,
    offs: &[u64],
    detach: Option<&Inode>,
) -> Result<(), KernelError> {
    {
        let _l = sb_data.ipos.lock();
        mark_deleted(sb_data, offs)?;
        if let Some(i) = detach {
            with_vi(i, |v| v.d.lock().i_pos = 0)?;
        }
    }
    if sb.dirsync() {
        sync_buffers(sb_data)?;
    }
    dir.inc_iversion();
    dir_update(dir, sb, None, true);
    Ok(())
}

// ============================================================================
// VFAT Inode Operations
// ============================================================================

/// A new directory's cluster, zeroed, with its "." and ".." entries
/// (".." the parent's i_logstart, 0 for the root) at times `et`
/// (Linux fat_alloc_new_dir); freed again if a write fails
fn fat_alloc_new_dir(
    sb_data: &VfatSbData,
    parent_cluster: u32,
    et: &EntryTimes,
) -> Result<u32, KernelError> {
    let c = allocate_cluster(sb_data)?;
    let fill = || {
        let off = cluster_to_offset(sb_data, c);
        let zeros = crate::util::kmem::try_vec(sb_data.cluster_size as usize, 0u8)?;
        write_bytes(&sb_data.bdev, off, &zeros)?;
        let up = logstart(sb_data, parent_cluster);
        for (i, (name, start)) in [(b".          ", c), (b"..         ", up)]
            .into_iter()
            .enumerate()
        {
            let mut b = [0u8; 32];
            b[0..11].copy_from_slice(name);
            b[11] = attr::DIRECTORY;
            entry_set_start(&mut b, start);
            et.put(&mut b);
            write_bytes(&sb_data.bdev, off + 32 * i as u64, &b)?;
        }
        Ok(())
    };
    if let Err(e) = fill() {
        let _ = free_cluster_chain(sb_data, c);
        return Err(e);
    }
    Ok(c)
}

/// VFAT inode operations
pub struct VfatInodeOps;

impl InodeOps for VfatInodeOps {
    /// Linux vfat_lookup: a missing name is a negative dentry stamped
    /// with the directory's version (vfat_d_version_set, under the
    /// directory's i_rwsem: no entry changes meanwhile)
    fn lookup_neg(&self, dir: &Inode, name: &[u8]) -> Result<super::inode::Found, KernelError> {
        let version = dir.iversion();
        match self.lookup(dir, name) {
            Ok(i) => Ok(super::inode::Found {
                inode: Some(i),
                d_time: 0,
            }),
            Err(KernelError::NotFound) => Ok(super::inode::Found {
                inode: None,
                d_time: version,
            }),
            Err(e) => Err(e),
        }
    }

    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<InodeRef, KernelError> {
        let name = &user_name(dir, name, KernelError::NotFound)?;
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let inode_data = get_inode_data(dir)?;

        if !inode_data.is_dir {
            return Err(KernelError::NotDirectory);
        }

        // Read directory entries
        let entries = read_directory_entries(&sb_data, inode_data.start_cluster)?;

        // Find matching entry (case-insensitive for FAT)
        for entry in entries {
            if entry.name.eq_ignore_ascii_case(name) {
                return vfat_iget(&sb, &entry, inode_data.start_cluster);
            }
        }

        Err(KernelError::NotFound)
    }

    /// Shared mappings map the page cache (Linux fat_file_mmap)
    fn maps_cache(&self) -> bool {
        true
    }

    /// Linux fat_update_time: the times truncated to FAT's
    /// (fat_truncate_time), the inode marked dirty for times only
    /// (__mark_inode_dirty(inode_time_dirty_flag): I_DIRTY_SYNC, there
    /// being no lazytime; fdatasync skips it); nothing for the root
    fn update_time(&self, inode: &Inode, what: TimeUpdate, _now: Timespec) {
        if is_root(inode) {
            return;
        }
        let atime = what == TimeUpdate::Atime;
        fat_truncate_time(inode, None, atime, !atime);
        super::fs_writeback::mark_inode_dirty_sync(inode);
    }

    /// Linux fat_setattr's end: atime to the day, mtime to 2 s with
    /// ctime the same; a ctime alone is dropped (ctime and mtime share
    /// the entry's field); then mark_inode_dirty
    fn setattr(
        &self,
        inode: &Inode,
        atime: Option<Timespec>,
        mtime: Option<Timespec>,
        _ctime: Option<Timespec>,
    ) {
        if let Some(t) = atime {
            fat_truncate_time(inode, Some(t), true, false);
        }
        if let Some(t) = mtime {
            fat_truncate_time(inode, Some(t), false, true);
        }
        super::fs_writeback::mark_inode_dirty(inode);
    }

    /// The preferred I/O size is the cluster size (Linux fat_getattr)
    fn getattr(&self, inode: &Inode) -> super::inode::InodeAttr {
        let mut a = super::inode::generic_fillattr(inode);
        let Some(cs) = cluster_size(inode) else {
            return a;
        };
        a.blksize = cs;
        // A file's blocks are its clusters (Linux i_blocks)
        if a.mode.is_file()
            && let Ok(d) = get_inode_data(inode)
        {
            a.blocks = u64::from(d.clusters) * u64::from(cs) / 512;
        }
        a
    }

    /// An unlinked file's clusters are freed with its inode, at once
    /// (Linux fat_evict_inode: fat_truncate_blocks(inode, 0); the last
    /// reference goes where sleeping is allowed, as Linux iput)
    fn evict_inode(&self, inode: &Inode) {
        if inode.get_nlink() != 0 {
            return;
        }
        let (Ok(d), Some(sb)) = (get_inode_data(inode), inode.superblock()) else {
            return;
        };
        let Ok(sb_data) = get_sb_data(&sb) else {
            return;
        };
        if d.start_cluster != 0 {
            let _ = free_cluster_chain(&sb_data, d.start_cluster);
        }
    }

    fn create(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<InodeRef, KernelError> {
        let name = &new_name(dir, name)?;
        let _ = mode; // FAT doesn't support Unix permissions
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let dir_inode_data = get_inode_data(dir)?;

        if !dir_inode_data.is_dir {
            return Err(KernelError::NotDirectory);
        }

        // Check if file already exists (the walk finds free slots too)
        let (entries, free) = scan_dir(&sb_data, dir_inode_data.start_cluster)?;
        for entry in &entries {
            if entry.name.eq_ignore_ascii_case(name) {
                return Err(KernelError::AlreadyExists);
            }
        }

        // Create the file (no cluster allocation for empty file)
        let start_cluster = 0u32;
        let file_size = 0u32;
        let parent_cluster = dir_inode_data.start_cluster;

        // Linux vfat_create: the entry's times all now (vfat_add_entry)
        let ts = crate::time::TIMEKEEPER.current_time();
        let et = EntryTimes::at(sb_data.opts.tz(), ts);
        let e = NewEntry {
            name,
            attr: attr::ARCHIVE,
            extent: (start_cluster, file_size),
            ts,
        };
        let (short_name, offs) = vfat_add_entry(dir, &sb, &sb_data, &entries, &free, &e)?;
        let i_pos = *offs.last().ok_or(KernelError::Io)?;
        // Linux vfat_create: inode_inc_iversion(dir) right after
        // vfat_add_entry, before anything that can fail: a negative
        // dentry of the name is stale from here on
        dir.inc_iversion();

        // Create and return the new inode
        let ino = sb.alloc_ino();
        let inode = Inode::alloc(Inode::new(
            ino,
            sb_data.opts.file_mode(),
            sb_data.opts.uid,
            sb_data.opts.gid,
            0, // Empty file
            Timespec::ZERO,
            Arc::downgrade(&sb),
            &VFAT_INODE_OPS,
        ))?;
        inode.i_data.set_aops(&VFAT_FILE_AOPS, Some(&inode));
        inode.inc_iversion();

        let crtime = fill_times(&inode, sb_data.opts.tz(), &et);
        inode.set_private(new_private(VfatInodeData {
            start_cluster,
            file_size,
            is_dir: false,
            parent_cluster,
            short_name,
            mmu_private: 0,
            clusters: 0,
            crtime,
            i_pos,
        })?);
        icache::insert_inode_hash(&inode, ikey(parent_cluster, &short_name));
        Ok(inode)
    }

    fn mkdir(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<InodeRef, KernelError> {
        let name = &new_name(dir, name)?;
        let _ = mode; // FAT doesn't support Unix permissions
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let dir_inode_data = get_inode_data(dir)?;

        if !dir_inode_data.is_dir {
            return Err(KernelError::NotDirectory);
        }

        // Check if directory already exists (the walk finds free slots
        // too)
        let (entries, free) = scan_dir(&sb_data, dir_inode_data.start_cluster)?;
        for entry in &entries {
            if entry.name.eq_ignore_ascii_case(name) {
                return Err(KernelError::AlreadyExists);
            }
        }

        // Linux vfat_mkdir: the new entries' times all now
        let ts = crate::time::TIMEKEEPER.current_time();
        let et = EntryTimes::at(sb_data.opts.tz(), ts);
        let parent_cluster = dir_inode_data.start_cluster;
        let new_cluster = fat_alloc_new_dir(&sb_data, parent_cluster, &et)?;
        let e = NewEntry {
            name,
            attr: attr::DIRECTORY,
            // Directories have size 0 in FAT
            extent: (new_cluster, 0),
            ts,
        };
        let (short_name, offs) = match vfat_add_entry(dir, &sb, &sb_data, &entries, &free, &e) {
            Ok(m) => m,
            Err(e) => {
                // Linux vfat_mkdir: out_free
                let _ = free_cluster_chain(&sb_data, new_cluster);
                return Err(e);
            }
        };
        let i_pos = *offs.last().ok_or(KernelError::Io)?;
        // Linux vfat_mkdir: inode_inc_iversion(dir) right after
        // vfat_add_entry, before anything that can fail
        dir.inc_iversion();
        dir.inc_nlink();

        // Create and return the new inode
        let ino = sb.alloc_ino();
        let inode = Inode::alloc(Inode::new(
            ino,
            sb_data.opts.dir_mode(),
            sb_data.opts.uid,
            sb_data.opts.gid,
            0,
            Timespec::ZERO,
            Arc::downgrade(&sb),
            &VFAT_INODE_OPS,
        ))?;
        inode.i_data.set_aops(&VFAT_FILE_AOPS, Some(&inode));
        inode.inc_iversion();
        // Linux vfat_mkdir: set_nlink(inode, 2)
        inode.nlink.store(2, core::sync::atomic::Ordering::Relaxed);

        let crtime = fill_times(&inode, sb_data.opts.tz(), &et);
        inode.set_private(new_private(VfatInodeData {
            start_cluster: new_cluster,
            file_size: 0,
            is_dir: true,
            parent_cluster,
            short_name,
            mmu_private: 0,
            clusters: 0,
            crtime,
            i_pos,
        })?);
        icache::insert_inode_hash(&inode, ikey(parent_cluster, &short_name));
        Ok(inode)
    }

    fn unlink(&self, dir: &Inode, name: &[u8], d: &Dentry) -> Result<(), KernelError> {
        let name = &user_name(dir, name, KernelError::NotFound)?;
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let dir_inode_data = get_inode_data(dir)?;

        if !dir_inode_data.is_dir {
            return Err(KernelError::NotDirectory);
        }

        // Find the entry to ensure it exists and is a file
        let entries = read_directory_entries(&sb_data, dir_inode_data.start_cluster)?;
        let entry = entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or(KernelError::NotFound)?;

        if entry.is_dir() {
            return Err(KernelError::IsDirectory);
        }

        // Delete the directory entry; its clusters go now, or with the
        // last reference to its inode (Linux vfat_unlink:
        // fat_remove_entries, then fat_detach; fat_evict_inode)
        unlink_entry(dir, &sb, &sb_data, dir_inode_data.start_cluster, entry)?;
        // vfat_unlink: the victim's atime, mtime and ctime now, in
        // memory only
        if let Some(i) = d.get_inode() {
            fat_truncate_time(&i, None, true, true);
        }
        // The dentry the VFS makes negative next is valid at this
        // version (Linux vfat_d_version_set(dentry,
        // inode_query_iversion(dir)))
        d.set_d_time(dir.iversion());
        Ok(())
    }

    fn rmdir(&self, dir: &Inode, name: &[u8], d: &Dentry) -> Result<(), KernelError> {
        let name = &user_name(dir, name, KernelError::NotFound)?;
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let dir_inode_data = get_inode_data(dir)?;

        if !dir_inode_data.is_dir {
            return Err(KernelError::NotDirectory);
        }

        // Find the entry to ensure it exists and is a directory
        let entries = read_directory_entries(&sb_data, dir_inode_data.start_cluster)?;
        let entry = entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or(KernelError::NotFound)?;

        if !entry.is_dir() {
            return Err(KernelError::NotDirectory);
        }

        // Check if directory is empty (only . and .. allowed)
        let child_entries = read_directory_entries(&sb_data, entry.start_cluster)?;
        for child in &child_entries {
            if child.name != "." && child.name != ".." {
                return Err(KernelError::DirectoryNotEmpty);
            }
        }

        // Delete the directory entry (clusters as for unlink)
        unlink_entry(dir, &sb, &sb_data, dir_inode_data.start_cluster, entry)?;
        // Linux vfat_rmdir: the parent loses the ".." link
        if dir.get_nlink() >= 3 {
            dir.dec_nlink();
        } else {
            crate::printkln!(
                "FAT-fs: parent dir link count too low ({})",
                dir.get_nlink()
            );
        }
        // vfat_rmdir: the victim's atime, mtime and ctime now, in
        // memory only
        if let Some(i) = d.get_inode() {
            fat_truncate_time(&i, None, true, true);
        }
        // The dentry the VFS makes negative next is valid at this
        // version (Linux vfat_d_version_set(dentry,
        // inode_query_iversion(dir)))
        d.set_d_time(dir.iversion());
        Ok(())
    }

    /// Linux fat_setattr(ATTR_SIZE): direct I/O in flight waited for
    /// (inode_dio_wait), then shrinking drops the pages past
    /// the end (truncate_setsize, mappings included) before the clusters
    /// go; growing zeroes the rest of the last cluster through the page
    /// cache and gives the file zeroed clusters. The VFS holds i_rwsem.
    fn truncate(&self, inode: &InodeRef, length: u64) -> Result<(), KernelError> {
        let sb = inode.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let d = get_inode_data(inode)?;
        if d.is_dir {
            return Err(KernelError::IsDirectory);
        }
        if length > u64::from(u32::MAX) {
            return Err(KernelError::FileTooLarge);
        }
        // Direct I/O in flight (a read past its lock) is done before the
        // size or the chain changes (Linux fat_setattr)
        inode.inode_dio_wait();
        let old = inode.get_size();
        let cs = u64::from(sb_data.cluster_size);
        if length < old {
            filemap::truncate_setsize(inode, length);
            // Before anything is freed (Linux fat_truncate_blocks)
            mmu_truncate(inode, length)?;
            let keep = length.div_ceil(cs) as usize;
            let start = free_past(&sb_data, inode, d.start_cluster, keep)?;
            let d = get_inode_data(inode)?;
            // The clusters are freed on disk: the inode follows
            set_inode_data(
                inode,
                VfatInodeData {
                    start_cluster: start,
                    file_size: length as u32,
                    ..d
                },
            )?;
        } else if length > old {
            ensure_clusters(inode, &sb_data, length)?;
            mmu_extend(inode, &sb_data, length)?;
            // Linux fat_cont_expand: a failure is fat_write_failed
            if let Err(e) = cont_expand(inode, cs, old, length) {
                let _ = write_failed(inode, &sb_data);
                return Err(e);
            }
            inode.set_size(length);
        }
        // Linux fat_setattr: mark_inode_dirty
        super::fs_writeback::mark_inode_dirty(inode);
        Ok(())
    }

    /// As Linux fat_fallocate: KEEP_SIZE allocates clusters past the end
    /// (fat_add_clusters), plain mode is an expanding truncate
    /// (fat_cont_expand); nothing else
    fn fallocate(
        &self,
        inode: &InodeRef,
        mode: i32,
        offset: u64,
        len: u64,
    ) -> Result<(), KernelError> {
        use super::misc::falloc_mode::FALLOC_FL_KEEP_SIZE;
        if mode & !FALLOC_FL_KEEP_SIZE != 0 || !inode.mode().is_file() {
            return Err(KernelError::OperationNotSupported);
        }
        let end = offset + len;
        if end > u64::from(u32::MAX) {
            return Err(KernelError::FileTooLarge);
        }
        if mode & FALLOC_FL_KEEP_SIZE != 0 {
            let sb = inode.superblock().ok_or(KernelError::Io)?;
            return ensure_clusters(inode, &get_sb_data(&sb)?, end);
        }
        if end <= inode.get_size() {
            return Ok(());
        }
        inode.newsize_ok(end)?;
        self.truncate(inode, end)
    }

    fn rename(
        &self,
        old_dir: &Inode,
        old_name: &[u8],
        new_dir: &InodeRef,
        new_name: &[u8],
        flags: u32,
    ) -> Result<(), KernelError> {
        let old_name = &user_name(old_dir, old_name, KernelError::NotFound)?;
        let new_name = &self::new_name(new_dir, new_name)?;
        // The VFS has checked RENAME_NOREPLACE; RENAME_EXCHANGE (Linux
        // vfat_rename_exchange) is not supported yet, whiteouts never
        if flags & !super::link::RENAME_NOREPLACE != 0 {
            return Err(KernelError::InvalidArgument);
        }

        let sb = old_dir.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let (od, nd) = (get_inode_data(old_dir)?, get_inode_data(new_dir)?);
        let (op, np) = (od.start_cluster, nd.start_cluster);

        // Linux vfat_rename: ts = current_time(old_dir)
        let ts = crate::time::TIMEKEEPER.current_time();
        // vfat_find(old_dir): the source's entry
        let old_entries = read_directory_entries(&sb_data, op)?;
        let old_entry = old_entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(old_name))
            .ok_or(KernelError::NotFound)?
            .clone();
        let old_inode = cached(&sb, op, &old_entry.short_name);
        let old_ipos = old_entry.i_pos;
        // A directory moved to another one: its ".." entry
        // (vfat_get_dotdot_de)
        let is_dir = old_entry.is_dir();
        let dotdot = if op != np && is_dir {
            Some(dotdot_offset(&sb_data, old_entry.start_cluster)?)
        } else {
            None
        };

        // The target's slot is reused (fat_detach of its inode), else a
        // new entry is added (vfat_add_entry, no cluster yet)
        let (new_entries, free) = scan_dir(&sb_data, np)?;
        let existing = new_entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(new_name));
        let mut new_inode = None;
        // The slots an added entry took
        let mut added = Vec::new();
        let (new_short, new_ipos) = match existing {
            Some(t) => {
                // A file over a directory or the reverse never gets here:
                // the VFS refused it (may_delete: EISDIR / ENOTDIR)
                if is_dir {
                    dir_empty(&sb_data, t.start_cluster)?;
                }
                new_inode = cached(&sb, np, &t.short_name);
                // Linux fat_detach(new_inode), before the slot is reused
                if let Some(i) = &new_inode {
                    fat_detach(i, &sb_data);
                }
                (t.short_name, t.i_pos)
            }
            None => {
                let a = if is_dir {
                    attr::DIRECTORY
                } else {
                    attr::ARCHIVE
                };
                let e = NewEntry {
                    name: new_name,
                    attr: a,
                    extent: (0, 0),
                    ts,
                };
                let made = vfat_add_entry(new_dir, &sb, &sb_data, &new_entries, &free, &e)?;
                added = made.1;
                (made.0, *added.last().ok_or(KernelError::Io)?)
            }
        };
        new_dir.inc_iversion();

        // fat_detach + fat_attach: the moved object's inode at the new
        // entry, then written there (vfat_sync_ipos)
        // From here every failure is undone (Linux error_inode)
        let unwind = Unwind {
            sb: &sb,
            sb_data: &sb_data,
            dir: new_dir,
            new_dir: np,
            added: &added,
            old: (&old_inode, op, old_entry.short_name, old_ipos),
            target: existing.map(|t| (&new_inode, t)),
            new_ipos,
        };
        // A cached inode's own extent and times (Linux __fat_write_inode
        // after fat_attach), else the old entry's
        let sync_ipos = || {
            let e = &old_entry;
            let (ext, times) = match &old_inode {
                Some(i) => {
                    attach(i, &sb_data, np, new_short, new_ipos)?;
                    inode_entry(i, &get_inode_data(i)?, &sb_data)
                }
                None => ((e.start_cluster, e.file_size), e.times),
            };
            write_entry(&sb_data, new_ipos, e.attr, ext, &times)?;
            // vfat_sync_ipos: on a dirsync mount at once
            if sb.dirsync() {
                sync_buffers(&sb_data)?;
            }
            Ok(())
        };
        if let Err(e) = sync_ipos() {
            unwind.inode(None);
            return Err(e);
        }
        if let Some(off) = dotdot {
            // vfat_update_dotdot_de: the parent is new_dir now, synced
            // at once on a dirsync mount
            let r = set_start(&sb_data, off, logstart(&sb_data, np)).and_then(|()| {
                if sb.dirsync() {
                    sync_buffers(&sb_data)
                } else {
                    Ok(())
                }
            });
            if let Err(e) = r {
                unwind.dotdot(dotdot, op);
                return Err(e);
            }
            old_dir.dec_nlink();
            if existing.is_none() {
                new_dir.inc_nlink();
            }
        }
        // fat_remove_entries(old_dir), then vfat_update_dir_metadata
        let removed = entry_slots(&sb_data, op, &old_entry)
            .and_then(|offs| fat_remove_entries(old_dir, &sb, &sb_data, &offs, None));
        if let Err(e) = removed {
            unwind.dotdot(dotdot, op);
            return Err(e);
        }
        vfat_update_dir_metadata(old_dir, &sb, ts);

        // The replaced object loses its name (drop_nlink): its clusters
        // go with its inode, or now if none is cached
        if let Some(t) = existing {
            match &new_inode {
                Some(i) => i.nlink.store(0, core::sync::atomic::Ordering::Release),
                None if t.start_cluster != 0 => free_cluster_chain(&sb_data, t.start_cluster)?,
                None => {}
            }
        }
        Ok(())
    }
}

/// Point `inode` at the entry `short` of the directory at `parent`
/// (Linux fat_detach + fat_attach): its data and its inode-cache key
fn attach(
    inode: &InodeRef,
    sb_data: &VfatSbData,
    parent: u32,
    short: [u8; 11],
    i_pos: u64,
) -> Result<(), KernelError> {
    let l = sb_data.ipos.lock();
    with_vi(inode, |v| {
        let mut d = v.d.lock();
        (d.parent_cluster, d.short_name, d.i_pos) = (parent, short, i_pos);
    })?;
    drop(l);
    icache::rehash(inode, ikey(parent, &short));
    Ok(())
}

/// Linux fat_detach: the inode has no entry any more (i_pos 0, so no
/// write_inode touches the slot it had, which may be reused) and is
/// out of the inode cache
fn fat_detach(inode: &InodeRef, sb_data: &VfatSbData) {
    let l = sb_data.ipos.lock();
    let _ = with_vi(inode, |v| v.d.lock().i_pos = 0);
    drop(l);
    icache::remove_inode_hash(inode);
}

/// ENOTEMPTY unless the directory at `cluster` holds only "." and ".."
/// (Linux fat_dir_empty)
fn dir_empty(sb_data: &VfatSbData, cluster: u32) -> Result<(), KernelError> {
    let entries = read_directory_entries(sb_data, cluster)?;
    if entries.iter().any(|c| c.name != "." && c.name != "..") {
        return Err(KernelError::DirectoryNotEmpty);
    }
    Ok(())
}

/// The disk offset of the ".." entry of the directory at `cluster`
/// (Linux fat_get_dotdot_entry: EIO if it is not there)
fn dotdot_offset(sb_data: &VfatSbData, cluster: u32) -> Result<u64, KernelError> {
    if !is_valid_cluster(cluster) {
        return Err(KernelError::Io);
    }
    let off = cluster_to_offset(sb_data, cluster) + 32;
    let mut b = [0u8; 32];
    read_bytes(&sb_data.bdev, off, &mut b)?;
    if &b[0..11] != b"..         " || b[11] & attr::DIRECTORY == 0 {
        return Err(KernelError::Io);
    }
    Ok(off)
}

/// A directory's first cluster as its subdirectories' ".." holds it
/// (Linux i_logstart: 0 for the root)
fn logstart(sb_data: &VfatSbData, cluster: u32) -> u32 {
    if cluster == sb_data.root_cluster {
        0
    } else {
        cluster
    }
}

/// Set the first cluster of the entry at disk offset `off` (Linux
/// fat_set_start)
fn set_start(sb_data: &VfatSbData, off: u64, start: u32) -> Result<(), KernelError> {
    let mut b = [0u8; 32];
    read_bytes(&sb_data.bdev, off, &mut b)?;
    entry_set_start(&mut b, start);
    write_bytes(&sb_data.bdev, off, &b)
}

/// Write an object's attributes, first cluster and size into the entry
/// `short` of the directory at `parent` (Linux __fat_write_inode at the
/// inode's i_pos)
fn write_entry(
    sb_data: &VfatSbData,
    off: u64,
    attr: u8,
    (start, size): (u32, u32),
    times: &EntryTimes,
) -> Result<(), KernelError> {
    // The slot's entry, as write_inode writes one (under the i_pos lock)
    let _l = sb_data.ipos.lock();
    let mut b = [0u8; 32];
    read_bytes(&sb_data.bdev, off, &mut b)?;
    b[11] = attr;
    entry_set_extent(&mut b, start, size);
    times.put(&mut b);
    write_bytes(&sb_data.bdev, off, &b)
}

/// What `inode`'s entry holds of it, `d` its data (Linux
/// __fat_write_inode): its first cluster and size (0 for a directory),
/// and its times
fn inode_entry(inode: &Inode, d: &VfatInodeData, sb_data: &VfatSbData) -> ((u32, u32), EntryTimes) {
    let size = if d.is_dir { 0 } else { inode.get_size() as u32 };
    let times = EntryTimes::of_inode(sb_data.opts.tz(), inode, d.crtime);
    ((d.start_cluster, size), times)
}

/// What a failed rename puts back (Linux vfat_rename's error_dotdot and
/// error_inode)
struct Unwind<'a> {
    sb: &'a SuperBlock,
    sb_data: &'a VfatSbData,
    /// The target directory, at `new_dir`
    dir: &'a Inode,
    new_dir: u32,
    /// The slots of the entry rename added (none if it reused one)
    added: &'a [u64],
    /// The moved object's inode, its old directory, entry and i_pos
    old: (&'a Option<InodeRef>, u32, [u8; 11], u64),
    /// The replaced object: its inode and entry
    target: Option<(&'a Option<InodeRef>, &'a ParsedDirEntry)>,
    /// The new entry's i_pos (the replaced object's slot)
    new_ipos: u64,
}

impl Unwind<'_> {
    /// error_dotdot: the data cluster may be shared now (serious
    /// corruption): ".." back to the old parent, then as `inode`
    fn dotdot(&self, dotdot: Option<u64>, old_parent: u32) {
        let mut failed = false;
        if let Some(off) = dotdot {
            let back = logstart(self.sb_data, old_parent);
            failed |= set_start(self.sb_data, off, back).is_err();
        }
        self.inode(Some(failed));
    }

    /// error_inode: the moved inode back at its old entry; the replaced
    /// one back at its own (its entry rewritten after a corruption), or
    /// the added entry removed. `corrupt`: after error_dotdot, with
    /// whether a step failed so far; a failure then is reported
    /// (fat_fs_error)
    fn inode(&self, corrupt: Option<bool>) {
        let (old_inode, op, old_short, old_ipos) = self.old;
        if let Some(i) = old_inode {
            let _ = attach(i, self.sb_data, op, old_short, old_ipos);
        }
        let mut failed = corrupt.unwrap_or(false);
        match self.target {
            Some((ni, t)) => {
                let mut ent = ((t.start_cluster, t.file_size), t.times);
                if let Some(i) = ni {
                    let _ = attach(i, self.sb_data, self.new_dir, t.short_name, self.new_ipos);
                    if let Ok(d) = get_inode_data(i) {
                        ent = inode_entry(i, &d, self.sb_data);
                    }
                }
                if corrupt.is_some() {
                    let r = write_entry(self.sb_data, self.new_ipos, t.attr, ent.0, &ent.1);
                    failed |= r.is_err();
                }
            }
            None => {
                // Linux fat_remove_entries(new_dir)
                let r = fat_remove_entries(self.dir, self.sb, self.sb_data, self.added, None);
                failed |= corrupt.is_some() && r.is_err();
            }
        }
        if corrupt.is_some() && failed {
            crate::printkln!("FAT-fs: vfat_rename: Filesystem corrupted");
        }
    }
}

pub static VFAT_INODE_OPS: VfatInodeOps = VfatInodeOps;

/// The device's cache on the disk (Linux sync_dirty_buffer of vfat's
/// metadata blocks: a directory change's on a dirsync or sync mount)
fn sync_buffers(sb_data: &VfatSbData) -> Result<(), KernelError> {
    crate::block::blkdev::sync_blockdev(&sb_data.bdev)
}

/// The end of a change to directory `dir` (Linux vfat_add_entry's,
/// fat_remove_entries', vfat_update_dir_metadata's): its mtime and
/// ctime `ts` (else now) and with `atime` its atime, the inode marked
/// dirty, and on a dirsync mount synced at once (sync_inode_metadata
/// with wait, its error ignored as Linux's (void))
fn dir_update(dir: &Inode, sb: &SuperBlock, ts: Option<Timespec>, atime: bool) {
    fat_truncate_time(dir, ts, atime, true);
    super::fs_writeback::mark_inode_dirty(dir);
    if sb.dirsync() {
        let _ = super::fs_writeback::sync_inode_metadata(dir, true);
    }
}

/// Linux vfat_add_entry: `e` added to `dir`, whose walk saw `existing`
/// and `free` (`fat_add_entries`), then the directory's end of change
/// at `e`'s time
fn vfat_add_entry(
    dir: &Inode,
    sb: &SuperBlock,
    sb_data: &VfatSbData,
    existing: &[ParsedDirEntry],
    free: &FreeSlots,
    e: &NewEntry<'_>,
) -> Result<([u8; 11], Vec<u64>), KernelError> {
    let made = fat_add_entries(sb_data, sb.dirsync(), existing, free, e)?;
    dir_update(dir, sb, Some(e.ts), false);
    Ok(made)
}

/// Linux vfat_update_dir_metadata: a rename's source directory, its
/// version, then its end of change at `ts`
fn vfat_update_dir_metadata(dir: &Inode, sb: &SuperBlock, ts: Timespec) {
    dir.inc_iversion();
    dir_update(dir, sb, Some(ts), false);
}

/// Inode cache key of the entry `short` in the directory at `parent`
/// (Linux fat i_pos: the entry's place on disk)
fn ikey(parent: u32, short: &[u8; 11]) -> u64 {
    short
        .iter()
        .fold(u64::from(parent) ^ 0xcbf2_9ce4_8422_2325, |h, &b| {
            (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
        })
}

/// `inode` is the object at (parent, short); runs under the inode
/// cache's bucket lock (takes only `Inode.private`)
fn is_obj(inode: &Inode, parent: u32, short: &[u8; 11]) -> bool {
    get_inode_data(inode).is_ok_and(|d| d.parent_cluster == parent && d.short_name == *short)
}

/// The cached inode of the entry `short` in the directory at `parent`
fn cached(sb: &Arc<SuperBlock>, parent: u32, short: &[u8; 11]) -> Option<InodeRef> {
    icache::ilookup5(sb, ikey(parent, short), &|i| is_obj(i, parent, short))
}

/// The one inode of a directory entry (Linux fat_build_inode: fat_iget,
/// else a new inode hashed by its position)
fn vfat_iget(
    sb: &Arc<SuperBlock>,
    entry: &ParsedDirEntry,
    parent: u32,
) -> Result<InodeRef, KernelError> {
    let short = entry.short_name;
    icache::iget5(
        sb,
        ikey(parent, &short),
        &|i| is_obj(i, parent, &short),
        || create_inode_for_entry(sb, entry, parent),
    )
}

/// Remove the entry `entry` of `dir` (at `parent`): its cached inode
/// leaves it in the same `ipos` hold (`fat_remove_entries`), then
/// becomes unlinked (nlink 0, unhashed) and keeps its clusters until
/// its last reference goes (`evict_inode`); with no cached inode they
/// are freed now. An unlinked inode has no directory entry any more
/// (Linux fat_detach): writes and truncates never update one (the slot
/// may belong to a new file by then).
fn unlink_entry(
    dir: &Inode,
    sb: &Arc<SuperBlock>,
    sb_data: &VfatSbData,
    parent: u32,
    entry: &ParsedDirEntry,
) -> Result<(), KernelError> {
    // Looked up before `ipos`: the lookup may wait for an inode being
    // freed, whose write-back takes it
    let inode = cached(sb, parent, &entry.short_name);
    let offs = entry_slots(sb_data, parent, entry)?;
    fat_remove_entries(dir, sb, sb_data, &offs, inode.as_deref())?;
    match inode {
        Some(i) => {
            i.nlink.store(0, core::sync::atomic::Ordering::Release);
            icache::remove_inode_hash(&i);
        }
        None if entry.start_cluster != 0 => free_cluster_chain(sb_data, entry.start_cluster)?,
        None => {}
    }
    Ok(())
}

/// Create an inode for a parsed directory entry
fn create_inode_for_entry(
    sb: &Arc<SuperBlock>,
    entry: &ParsedDirEntry,
    parent_cluster: u32,
) -> Result<InodeRef, KernelError> {
    let sb_data = get_sb_data(sb)?;
    // A directory's link count is fat_subdirs (Linux fat_fill_inode),
    // then fat_validate_dir: its "." and ".." at least, and a cluster of
    // its own; both checked before any inode exists, so a refused one
    // is never evicted with no link (its clusters are not its to free).
    // A file's first cluster is checked when its chain is walked
    // (`cache`, Linux fat_get_cluster).
    let nlink = if entry.is_dir() {
        let n = fat_subdirs(&sb_data, entry.start_cluster)?;
        if n < 2 {
            crate::printkln!("FAT-fs: corrupted directory (invalid entries)");
            return Err(KernelError::Io);
        }
        if entry.start_cluster == 0 || entry.start_cluster == sb_data.root_cluster {
            crate::printkln!("FAT-fs: corrupted directory (invalid i_start)");
            return Err(KernelError::Io);
        }
        n
    } else {
        1
    };
    let o = sb_data.opts;
    let mode = if entry.is_dir() {
        o.dir_mode()
    } else {
        o.file_mode()
    };

    let ino = sb.alloc_ino();
    let inode = Inode::alloc(Inode::new(
        ino,
        mode,
        o.uid,
        o.gid,
        u64::from(entry.file_size),
        Timespec::ZERO,
        Arc::downgrade(sb),
        &VFAT_INODE_OPS,
    ))?;
    inode.i_data.set_aops(&VFAT_FILE_AOPS, Some(&inode));
    inode.inc_iversion();
    inode
        .nlink
        .store(nlink, core::sync::atomic::Ordering::Relaxed);

    let crtime = fill_times(&inode, o.tz(), &entry.times);
    inode.set_private(new_private(VfatInodeData {
        crtime,
        i_pos: entry.i_pos,
        start_cluster: entry.start_cluster,
        file_size: entry.file_size,
        is_dir: entry.is_dir(),
        parent_cluster,
        short_name: entry.short_name,
        mmu_private: u64::from(entry.file_size),
        // Linux fat_fill_inode: i_blocks from the size
        clusters: entry.file_size.div_ceil(sb_data.cluster_size),
    })?);

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

    /// No poll (Linux fat_file_operations, fat_dir_operations)
    fn can_poll(&self, _file: &File) -> bool {
        false
    }

    /// Regular files (Linux fat_aops has ->direct_IO; directories keep
    /// empty_aops)
    fn can_odirect(&self, file: &File) -> bool {
        file.get_inode().is_some_and(|i| i.mode().is_file())
    }

    /// Regular files (Linux do_blockdev_direct_IO with an async kiocb)
    fn can_async_dio(&self, file: &File) -> bool {
        self.can_odirect(file)
    }

    /// The asynchronous O_DIRECT path (`direct::submit`)
    fn dio_submit(
        &self,
        file: &File,
        io: Arc<dyn crate::block::dio::AsyncIo>,
        pos: u64,
        write: bool,
        flags: RwFlags,
    ) -> Result<Option<usize>, KernelError> {
        direct::submit(file, io, pos, write, flags)
    }

    /// Regular files map their data (Linux generic_file_mmap);
    /// directories have no mmap
    fn mmap(&self, file: &File, _shared: bool) -> Result<(), KernelError> {
        match file.get_inode() {
            Some(i) if i.mode().is_dir() => Err(KernelError::NoDevice),
            _ => Ok(()),
        }
    }

    /// O_DIRECT from user memory or pinned pages straight from the disk
    /// (`direct::read`), else from the page cache (Linux
    /// generic_file_read_iter); no RWF_NOWAIT (EOPNOTSUPP)
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        if flags.nowait() {
            return Err(KernelError::OperationNotSupported);
        }
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let pos = at.unwrap_or_else(|| file.get_pos());
        let n = if flags.contains(RwFlags::DIRECT) && to.pinnable() && inode.mode().is_file() {
            direct::read(&inode, to, pos)?
        } else {
            filemap::read_iter(&inode, to, pos)?
        };
        if at.is_none() {
            file.advance_pos(n as u64);
        }
        Ok(n)
    }

    /// O_DIRECT from user memory or pinned pages straight to the disk
    /// where it can
    /// (`direct::write`), else `vfat_write`; no RWF_NOWAIT (EOPNOTSUPP)
    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        if flags.nowait() {
            return Err(KernelError::OperationNotSupported);
        }
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let pos = at.unwrap_or_else(|| file.get_pos());
        let n = if flags.contains(RwFlags::DIRECT) && from.pinnable() && !from.is_empty() {
            direct::write(&inode, from, pos)?
        } else {
            vfat_write(&inode, from, pos)?
        };
        if at.is_none() {
            file.advance_pos(n as u64);
        }
        Ok(n)
    }

    /// Write the file's pages, the FAT and directory blocks, then flush
    /// the disk (Linux fat_file_fsync: generic_file_fsync + blkdev flush)
    fn fsync(
        &self,
        file: &File,
        _start: u64,
        _end: u64,
        _datasync: bool,
    ) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let sb = inode.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let r = super::fs_writeback::write_inode_now(&inode, true);
        r.and(file.check_and_advance_wb_err())?;
        crate::block::blkdev::sync_blockdev(&sb_data.bdev)?;
        crate::block::blkdev::blkdev_issue_flush(&sb_data.bdev)
    }

    // llseek: use default implementation from FileOps trait

    fn readdir(&self, file: &File, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let sb = inode.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let inode_data = get_inode_data(&inode)?;

        if !inode_data.is_dir {
            return Err(KernelError::NotDirectory);
        }

        // "." and ".." at positions 0 and 1, slot n at n + 2
        let dot = |name: &[u8], ino| VfsDirEntry {
            ino,
            file_type: FileType::Directory,
            name: name.to_vec(),
        };
        if !ctx.emit_at(0, dot(b".", inode.ino)) || !ctx.emit_at(1, dot(b"..", 1)) {
            return Ok(());
        }

        let entries = read_directory_entries(&sb_data, inode_data.start_cluster)?;
        for entry in entries {
            let file_type = if entry.is_dir() {
                FileType::Directory
            } else {
                FileType::Regular
            };

            // Use cluster as pseudo-inode number
            let ino = if entry.start_cluster > 0 {
                u64::from(entry.start_cluster)
            } else {
                sb.alloc_ino()
            };

            let e = VfsDirEntry {
                ino,
                file_type,
                name: sb_data.opts.cs.to_bytes(&entry.name),
            };
            if !ctx.emit_at(entry.slot + 2, e) {
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
    /// Linux fat_write_inode
    fn write_inode(
        &self,
        inode: &Inode,
        _wbc: &super::fs_writeback::WritebackControl,
    ) -> Result<(), KernelError> {
        fat_write_inode(inode)
    }

    /// Linux fat_sync_inode_metadata
    fn sync_inode_metadata(
        &self,
        inode: &Inode,
        _wbc: &super::fs_writeback::WritebackControl,
    ) -> Result<(), KernelError> {
        fat_sync_inode_metadata(inode)
    }

    /// Linux fat_reconfigure: what is dirty is written back first
    /// (sync_filesystem, its error ignored), before a switch to
    /// read-only; the options are kept
    fn remount(&self, sb: &SuperBlock, _data: &[u8]) -> Result<(), KernelError> {
        let _ = super::sync::sync_filesystem(sb);
        Ok(())
    }

    /// Its filesystem data goes (Linux fat_put_super: the sbi freed)
    fn put_super(&self, sb: &SuperBlock) {
        let sbi = sb.private.write().take();
        drop(sbi);
    }

    /// Linux fat_statfs: clusters as blocks, the free ones counted once
    /// and kept; a long name of 255 characters of up to 6 bytes each
    /// (FAT_LFN_LEN * NLS_MAX_CHARSET_SIZE)
    fn statfs(&self, sb: &SuperBlock) -> Result<StatFs, KernelError> {
        let d = get_sb_data(sb)?;
        // A FAT that cannot be read fails the call (Linux
        // fat_count_free_clusters' error)
        let free = free_clusters(&d)?;
        Ok(StatFs {
            f_type: MSDOS_SUPER_MAGIC,
            f_bsize: u64::from(d.cluster_size),
            f_blocks: u64::from(d.max_cluster - 2),
            f_bfree: free,
            f_bavail: free,
            f_namelen: 255 * 6,
            ..StatFs::default()
        })
    }

    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        i_op: &'static dyn InodeOps,
    ) -> Result<InodeRef, KernelError> {
        Inode::alloc(Inode::new(
            sb.alloc_ino(),
            mode,
            0,
            0,
            0,
            Timespec::ZERO,
            Arc::downgrade(sb),
            i_op,
        ))
    }
}

pub static VFAT_SUPER_OPS: VfatSuperOps = VfatSuperOps;

// ============================================================================
// VFAT Mount
// ============================================================================

/// A vfat mount (Linux vfat_get_tree: get_tree_bdev)
fn vfat_get_tree(
    fc: &crate::fs::superblock::FsContext<'_>,
) -> Result<crate::fs::superblock::SbLocked, KernelError> {
    crate::fs::superblock::get_tree_bdev(fc, &VFAT_SUPER_OPS, |sb| vfat_fill_super(sb, fc.data))
}

/// Read the filesystem on `sb`'s device (Linux vfat_fill_super ->
/// fat_fill_super)
fn vfat_fill_super(sb: &Arc<SuperBlock>, opts: &[u8]) -> Result<(), KernelError> {
    let bdev = sb.bdev().ok_or(KernelError::NotBlockDevice)?.clone();
    // Options first: a bad one is EINVAL before any I/O
    let opts = VfatOpts::parse(opts)?;
    // Read boot sector
    let mut boot_sector_buf = [0u8; 512];
    read_bytes(&bdev, 0, &mut boot_sector_buf)?;

    let boot_sector =
        VfatBootSector::read_from(&boot_sector_buf).expect("boot sector fits 512 bytes");

    // Validate FAT32
    // Check for valid bytes per sector (must be power of 2, 512-4096)
    let bytes_per_sector = boot_sector.bytes_per_sector;
    if !(512..=4096).contains(&bytes_per_sector) || !bytes_per_sector.is_power_of_two() {
        return Err(KernelError::InvalidArgument);
    }
    // A FAT sector smaller than the device's logical block (Linux
    // fat_fill_super: "logical sector size too small for device"): a
    // metadata write-back of one block would cover other sectors
    if u32::from(bytes_per_sector) < bdev.logical_block_size() {
        return Err(KernelError::InvalidArgument);
    }

    // Check for FAT32 (fat_size_16 == 0 and fat_size_32 != 0)
    if boot_sector.fat_size_16 != 0 || boot_sector.fat_size_32 == 0 {
        return Err(KernelError::InvalidArgument);
    }

    // Check root_entry_count is 0 (required for FAT32)
    if boot_sector.root_entry_count != 0 {
        return Err(KernelError::InvalidArgument);
    }

    // sectors_per_cluster must be a power of two (this rejects 0, which
    // would divide by zero in the cluster math), with a non-zero FAT
    // count and reserved region and a valid media byte (Linux
    // fat_fill_super)
    let spc = boot_sector.sectors_per_cluster;
    if spc == 0 || !spc.is_power_of_two() {
        return Err(KernelError::InvalidArgument);
    }
    if boot_sector.num_fats == 0 || boot_sector.reserved_sector_count == 0 {
        return Err(KernelError::InvalidArgument);
    }
    let media = boot_sector.media_type;
    if media != 0xf0 && media < 0xf8 {
        return Err(KernelError::InvalidArgument);
    }

    // Calculate filesystem layout
    let fat_start_sector = u64::from(boot_sector.reserved_sector_count);
    let fat_sectors = u64::from(boot_sector.fat_size_32);
    let num_fats = u64::from(boot_sector.num_fats);
    let data_start_sector = fat_start_sector + (fat_sectors * num_fats);
    let cluster_size = u32::from(spc) * u32::from(bytes_per_sector);

    // The data region must fit, and the FAT must hold an entry (4 bytes)
    // for every data cluster plus the two reserved entries (Linux: the
    // cluster count is checked against the FAT size)
    let total_sectors = if boot_sector.total_sectors_16 != 0 {
        u64::from(boot_sector.total_sectors_16)
    } else {
        u64::from(boot_sector.total_sectors_32)
    };
    if total_sectors <= data_start_sector {
        return Err(KernelError::InvalidArgument);
    }
    let total_clusters = (total_sectors - data_start_sector) / u64::from(spc);
    let fat_entries = fat_sectors.saturating_mul(u64::from(bytes_per_sector)) / 4;
    if total_clusters == 0 || total_clusters + 2 > fat_entries {
        return Err(KernelError::InvalidArgument);
    }
    // FAT32 numbers clusters in 28 bits (Linux MAX_FAT32: "count of
    // clusters too big")
    if total_clusters + 2 > u64::from(FAT_BAD) {
        return Err(KernelError::InvalidArgument);
    }

    // Create superblock data
    let sb_data = try_arc(VfatSbData {
        bdev: bdev.clone(),
        bytes_per_sector: u32::from(bytes_per_sector),
        sectors_per_cluster: u32::from(boot_sector.sectors_per_cluster),
        fat_start_sector,
        fat_sectors,
        num_fats,
        data_start_sector,
        root_cluster: boot_sector.root_cluster,
        max_cluster: (total_clusters + 2) as u32,
        cluster_size,
        opts,
        ipos: try_arc(crate::sync::Mutex::new(()))?,
        fat: try_arc(crate::sync::Mutex::new(FatState {
            free: -1,
            prev_free: 2,
        }))?,
    })?;

    // The root directory's chain must be sound (Linux fat_read_root ->
    // fat_calc_dir_size walks it: EIO)
    read_cluster_chain(&sb_data, sb_data.root_cluster)?;

    // FAT sizes are 32-bit (Linux fat_fill_super: s_maxbytes 0xffffffff)
    sb.set_maxbytes(0xffff_ffff);
    sb.set_private(sb_data.clone());

    // Create root inode
    let root_ino = sb.alloc_ino();
    let root_inode = Inode::alloc(Inode::new(
        root_ino,
        sb_data.opts.dir_mode(),
        sb_data.opts.uid,
        sb_data.opts.gid,
        0,
        Timespec::ZERO,
        Arc::downgrade(sb),
        &VFAT_INODE_OPS,
    ))?;
    root_inode
        .i_data
        .set_aops(&VFAT_FILE_AOPS, Some(&root_inode));
    // Linux fat_fill_inode: inode_inc_iversion
    root_inode.inc_iversion();
    // Linux fat_read_root: fat_subdirs + 2 (the root has no "." or "..")
    let n = fat_subdirs(&sb_data, boot_sector.root_cluster)? + 2;
    root_inode
        .nlink
        .store(n, core::sync::atomic::Ordering::Relaxed);

    root_inode.set_private(new_private(VfatInodeData {
        start_cluster: boot_sector.root_cluster,
        file_size: 0,
        is_dir: true,
        parent_cluster: 0,      // Root has no parent
        short_name: [b' '; 11], // Root has no short name
        mmu_private: 0,
        clusters: 0,
        crtime: Timespec::ZERO,
        i_pos: 0,
    })?);

    // Names match without case or trailing dots (Linux setup's
    // vfat_ci_dentry_ops), before the root dentry takes them
    sb.set_d_op(&VFAT_CI_DENTRY_OPS);
    let root_dentry = crate::fs::DentryRef::new(Dentry::new_root(root_inode, Arc::downgrade(sb)))?;
    sb.set_root(root_dentry);

    Ok(())
}

/// VFAT filesystem type
pub static VFAT_TYPE: FileSystemType = FileSystemType {
    name: "vfat",
    fs_flags: fs_flags::FS_REQUIRES_DEV,
    mount: vfat_get_tree,
    kill_sb: crate::fs::superblock::kill_block_super,
    file_ops: &VFAT_FILE_OPS,
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The clusters a chain walk yields over the FAT `fat` (index =
    /// cluster), then whether it ended in EIO
    fn walk(fat: &[u32], start: u32) -> (Vec<u32>, bool) {
        let mut got = Vec::new();
        let max = fat.len() as u32;
        for c in Chain::with(|c| Ok(fat[c as usize]), max, 4096, start) {
            match c {
                Ok(c) => got.push(c),
                Err(_) => return (got, true),
            }
        }
        (got, false)
    }

    /// Linux fat_get_cluster: a chain ends at an end-of-chain mark; one
    /// that reaches a free, reserved or out-of-range cluster, or loops,
    /// is EIO (never a quiet end, which would let a later allocation
    /// cross-link the free cluster)
    #[test]
    fn chain_walk() {
        const EOC: u32 = 0x0FFF_FFFF;
        assert_eq!(walk(&[0, 0, 3, 4, EOC], 2), (vec![2, 3, 4], false));
        assert_eq!(walk(&[0, 0, EOC], 0), (vec![], false));
        // 3's entry is free (0) mid-chain: EIO after 3
        assert_eq!(walk(&[0, 0, 3, 0, 0], 2), (vec![2, 3], true));
        assert_eq!(walk(&[0, 0, 0, 0], 2), (vec![2], true));
        assert_eq!(walk(&[0, 0, 1, 0], 2), (vec![2], true));
        assert_eq!(walk(&[0, 0, 9, 0], 2), (vec![2], true));
        assert_eq!(walk(&[0, 0, FAT_BAD, 0], 2), (vec![2], true));
        // A loop: EIO once more clusters than the FAT has were walked
        assert!(walk(&[0, 0, 3, 2], 2).1);
        // A bad start
        assert_eq!(walk(&[0, 0, EOC], 1), (vec![], true));
    }

    /// Short names never start with a space; a base of only dots and
    /// spaces before the last dot makes the whole name the base (Linux
    /// vfat_create_shortname)
    #[test]
    fn short_names() {
        let g = |n: &str| generate_short_name(n, &[]);
        assert_eq!(g("a.b"), Some(*b"A       B  "));
        assert_eq!(g("  .txt"), Some(*b"TXT        "));
        assert_eq!(g("...test"), Some(*b"TEST       "));
        assert_eq!(g(".bashrc"), Some(*b"BASHRC     "));
        assert_eq!(g(" "), None);
        assert_eq!(g("..."), None);
        let taken = [*b"A       B  "];
        assert_eq!(generate_short_name("a.b", &taken), Some(*b"A~1     B  "));
    }

    /// The names of `entries` read back as the directory reader does
    fn read_back(entries: &[VfatLfnEntry]) -> String {
        let mut parts: Vec<(u8, Vec<u16>)> = entries
            .iter()
            .map(|e| (e.order & 0x3f, lfn_entry_chars(e)))
            .collect();
        lfn_name(&mut parts)
    }

    /// LFN entries: highest order first with 0x40 on it, every one
    /// carrying the short name's checksum; a name filling its last
    /// entry exactly has no terminator (Linux xlate_to_uni); a
    /// surrogate pair may span two entries
    #[test]
    fn long_name_entries() {
        let short = *b"LONGFI~1TXT";
        let sum = short_name_checksum(&short);
        let e = create_lfn_entries("a.txt", &short);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].order, 0x41);
        let n1 = e[0].name1;
        assert_eq!(n1, [0x61, 0x2e, 0x74, 0x78, 0x74]);
        let n2 = e[0].name2;
        assert_eq!(n2, [0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff]);
        let thirteen = "abcdefghijklm";
        let e = create_lfn_entries(thirteen, &short);
        assert_eq!(e.len(), 1);
        let n3 = e[0].name3;
        assert_eq!(n3, [0x6c, 0x6d]);
        assert_eq!(read_back(&e), thirteen);
        let long = "a name that needs three entries.txt";
        let e = create_lfn_entries(long, &short);
        assert_eq!(e.len(), 3);
        assert_eq!(e.iter().map(|x| x.order).collect::<Vec<_>>(), [0x43, 2, 1]);
        assert!(e.iter().all(|x| x.checksum == sum));
        assert_eq!(read_back(&e), long);
        // U+1F600 is a pair at units 12 and 13: split between entries
        let pair = "abcdefghijkl\u{1F600}x";
        assert_eq!(read_back(&create_lfn_entries(pair, &short)), pair);
    }

    /// The short-name checksum (Microsoft FAT spec, Linux fat_checksum):
    /// both forms agree
    #[test]
    fn checksums() {
        let s = *b"README  TXT";
        assert_eq!(short_name_checksum(&s), 0x73);
        let (n, e) = s.split_at(8);
        assert_eq!(
            lfn_checksum(n.try_into().unwrap(), e.try_into().unwrap()),
            0x73
        );
    }

    /// 8.3 names as text: the dot only with an extension, 0x05 is 0xE5
    #[test]
    fn short_name_text() {
        assert_eq!(short_name_to_string(b"README  ", b"TXT"), "README.TXT");
        assert_eq!(short_name_to_string(b"MAKEFILE", b"   "), "MAKEFILE");
        assert_eq!(short_name_to_string(b"\x05BC     ", b"   "), "\u{e5}BC");
    }

    /// cp437 and iso8859-1 both ways; what a charset lacks is '?'
    #[test]
    fn charsets() {
        assert_eq!(Charset::Cp437.to_bytes("\u{e9}t\u{e9}"), [0x82, b't', 0x82]);
        assert_eq!(
            Charset::Cp437.to_text(&[0x82, 0xe1]).unwrap(),
            "\u{e9}\u{df}"
        );
        assert_eq!(Charset::Latin1.to_bytes("\u{e9}\u{20ac}"), [0xe9, b'?']);
        assert_eq!(Charset::Latin1.to_text(&[0xe9]).unwrap(), "\u{e9}");
        assert!(Charset::Utf8.to_text(&[0xff]).is_none());
        for b in 0x80..=0xffu8 {
            let t = Charset::Cp437.to_text(&[b]).unwrap();
            assert_eq!(Charset::Cp437.to_bytes(&t), [b]);
        }
    }
}
