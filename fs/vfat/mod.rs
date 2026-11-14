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

use crate::block::BlockDevice;
use crate::block::blkdev::{BioOp, bdev_rw_bytes};
use crate::mm::filemap::{self, Aops, PAGE_SIZE};
use crate::mm::page::frame_bytes;
use crate::util::pod::{FromBytes, IntoBytes};

use super::dentry::Dentry;
use super::file::{DirContext, DirEntry as VfsDirEntry, File, FileOps, RwFlags};
use super::icache;
use super::inode::{AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::iov_iter::{IovDest, IovSource};
use super::superblock::{
    FileSystemType, MSDOS_SUPER_MAGIC, StatFs, SuperBlock, SuperBlockData, SuperOps, fs_flags,
};
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_arc};

mod cache;
mod direct;

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
    let to = to.min(from.next_multiple_of(cs));
    let zeros = [0u8; PAGE_SIZE];
    let mut at = from;
    while at < to {
        let n = ((to - at) as usize).min(PAGE_SIZE - (at % PAGE_SIZE as u64) as usize);
        if filemap::perform_write(inode, &zeros[..n], at)? != n {
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
        if d.parent_cluster != 0 && inode.get_nlink() != 0 {
            update_dir_entry_by_short_name(
                sb_data,
                d.parent_cluster,
                &d.short_name,
                first,
                inode.get_size() as u32,
            )?;
        }
        // The clusters are on disk now: the inode follows
        set_inode_data(
            inode,
            VfatInodeData {
                start_cluster: first,
                ..d
            },
        )?;
    }
    // Linux fat_chain_add: i_blocks counts them
    with_vi(inode, |v| v.d.lock().clusters = need as u32)
}

/// Record the file's size in its directory entry
fn update_size(inode: &Inode, sb_data: &VfatSbData) -> Result<(), KernelError> {
    let d = get_inode_data(inode)?;
    if d.parent_cluster == 0 || inode.get_nlink() == 0 {
        return Ok(());
    }
    update_dir_entry_by_short_name(
        sb_data,
        d.parent_cluster,
        &d.short_name,
        d.start_cluster,
        inode.get_size() as u32,
    )
}

/// Write to a vfat file (Linux fat_write_begin/end over
/// generic_perform_write): clusters first, a gap past the old end
/// zeroed, the data through the page cache (written back later), then
/// the new size in the directory entry. The VFS holds i_rwsem.
fn vfat_write(
    inode: &Arc<Inode>,
    from: &mut IovSource<'_>,
    pos: u64,
) -> Result<usize, KernelError> {
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
        update_size(inode, &sb_data)?;
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
        update_size(inode, sb_data)?;
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
}

impl SuperBlockData for VfatSbData {}

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
                | b"uni_xlate" | b"allow_utime" | b"errors" | b"check" | b"tz" | b"time_offset"
                | b"nfs" => {}
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

/// vfat's dentry name operations (Linux vfat_ci_dentry_ops)
static VFAT_CI_DENTRY_OPS: crate::fs::dentry::DentryOps = crate::fs::dentry::DentryOps {
    d_hash: vfat_hashi,
    d_compare: vfat_cmpi,
};

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
fn get_sb_data(sb: &Arc<SuperBlock>) -> Result<VfatSbData, KernelError> {
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

/// Read a cluster chain starting from a cluster
/// The clusters of the chain at `start_cluster` (0: none). As Linux
/// fat_get_cluster, a corrupt chain is EIO: an entry that is free, bad
/// or past the last cluster, or a chain longer than the filesystem has
/// clusters (a cycle)
fn read_cluster_chain(sb_data: &VfatSbData, start_cluster: u32) -> Result<Vec<u32>, KernelError> {
    let mut chain = Vec::new();
    if start_cluster == 0 {
        return Ok(chain);
    }
    // No file or directory is longer than 4 GiB (s_maxbytes): a longer
    // chain is a loop (Linux bounds the walk by s_maxbytes >>
    // cluster_bits), and the vector never outgrows that
    let max_len =
        (sb_data.max_cluster as usize).min((1usize << 32) / sb_data.cluster_size as usize + 1);
    let mut cluster = start_cluster;
    loop {
        if !(2..sb_data.max_cluster).contains(&cluster) || chain.len() >= max_len {
            return Err(KernelError::Io);
        }
        chain.try_reserve(1).map_err(|_| KernelError::OutOfMemory)?;
        chain.push(cluster);
        cluster = get_fat_entry(sb_data, cluster)?;
        if is_end_of_chain(cluster) {
            return Ok(chain);
        }
    }
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
    // Search for free cluster among the data clusters (the BPB's size,
    // not the device's)
    for cluster in 2..sb_data.max_cluster {
        let entry = get_fat_entry(sb_data, cluster)?;
        if entry == FAT_FREE {
            // Found free cluster, mark as end-of-chain
            set_fat_entry(sb_data, cluster, FAT_EOC)?;

            // Zeroed on the disk itself, after the device cache's pages
            // of it are written back and dropped (Linux
            // clean_bdev_aliases): a file's data never goes through the
            // device cache, so no stale or dirty copy of an old
            // directory block may outlive the reuse
            let off = cluster_to_offset(sb_data, cluster);
            let len = u64::from(sb_data.cluster_size);
            filemap::invalidate_range(&sb_data.bdev.bd_inode, off, off + len)?;
            let mut zeros = crate::util::kmem::try_vec(len as usize, 0u8)?;
            bdev_rw_bytes(&sb_data.bdev, BioOp::Write, off, &mut zeros)?;
            // Again: a page a reader cached before the zeros landed
            // holds the old bytes
            filemap::invalidate_range(&sb_data.bdev.bd_inode, off, off + len)?;

            return Ok(cluster);
        }
    }

    Err(KernelError::NoSpace)
}

/// Free a cluster chain starting from start_cluster
fn free_cluster_chain(sb_data: &VfatSbData, start_cluster: u32) -> Result<(), KernelError> {
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
            // `cluster` is allocated but not yet linked: free it directly
            let _ = set_fat_entry(sb_data, cluster, FAT_FREE);
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

/// Read and parse directory entries from a cluster chain; the list
/// grows fallibly (ENOMEM), a directory being as large as its disk says
fn read_directory_entries(
    sb_data: &VfatSbData,
    start_cluster: u32,
) -> Result<Vec<ParsedDirEntry>, KernelError> {
    let chain = read_cluster_chain(sb_data, start_cluster)?;
    let mut entries = crate::util::kmem::KVec::new();
    let mut lfn = Lfn::default();

    for (ci, &cluster) in chain.iter().enumerate() {
        let cluster_offset = cluster_to_offset(sb_data, cluster);
        let entries_per_cluster = sb_data.cluster_size as usize / 32;

        for i in 0..entries_per_cluster {
            let entry_offset = cluster_offset + (i as u64 * 32);
            let mut buf = [0u8; 32];
            read_bytes(&sb_data.bdev, entry_offset, &mut buf)?;

            // Check for end of directory
            if buf[0] == END_MARKER {
                return Ok(entries.into_vec());
            }

            // Skip deleted entries
            if buf[0] == DELETED_MARKER {
                lfn.clear();
                continue;
            }

            let attr = buf[11];

            // Check if this is a long filename entry
            if (attr & attr::LONG_NAME_MASK) == attr::LONG_NAME {
                lfn.add(&VfatLfnEntry::read_from(&buf).expect("32-byte entry"));
            } else {
                // Parse as regular directory entry
                let dirent = VfatDirEntry::read_from(&buf).expect("32-byte entry");

                // Skip volume labels
                if (attr & attr::VOLUME_ID) != 0 {
                    lfn.clear();
                    continue;
                }

                // The long name if its entries match, else the short one
                let name = lfn
                    .take_name(&dirent.name, &dirent.ext)
                    .unwrap_or_else(|| short_name_to_string(&dirent.name, &dirent.ext));

                // Skip "." and ".." entries
                if name == "." || name == ".." {
                    continue;
                }

                let start_cluster =
                    (u32::from(dirent.first_cluster_hi) << 16) | u32::from(dirent.first_cluster_lo);

                // Build short_name array from name (8 bytes) + ext (3 bytes)
                let mut short_name = [b' '; 11];
                short_name[0..8].copy_from_slice(&dirent.name);
                short_name[8..11].copy_from_slice(&dirent.ext);

                entries.try_push(ParsedDirEntry {
                    name,
                    short_name,
                    attr,
                    start_cluster,
                    file_size: dirent.file_size,
                    slot: (ci * entries_per_cluster + i) as u64,
                })?;
            }
        }
    }

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

/// Find consecutive free directory entry slots
///
/// Returns (cluster, index) of the first slot. Slots may span multiple clusters.
/// If not enough space exists, may extend the directory by allocating new clusters.
fn find_free_dir_slots(
    sb_data: &VfatSbData,
    dir_cluster: u32,
    num_slots: usize,
) -> Result<(u32, usize), KernelError> {
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
    let new_cluster = extend_cluster_chain(sb_data, last_cluster, 1)?;

    if new_cluster != 0 {
        // Initialize new cluster with end markers
        let mut end_markers = crate::util::kmem::try_vec(sb_data.cluster_size as usize, 0u8)?;
        // First byte of first entry should be END_MARKER (rest are zeros which is fine)
        end_markers[0] = END_MARKER;
        let new_cluster_offset = cluster_to_offset(sb_data, new_cluster);
        write_bytes(&sb_data.bdev, new_cluster_offset, &end_markers)?;

        let new_index = chain.len() * entries_per_cluster;
        return Ok((new_cluster, new_index));
    }

    Err(KernelError::NoSpace)
}

/// Write a directory entry (raw 32-byte entry) at a specific position
fn write_raw_dir_entry(
    sb_data: &VfatSbData,
    dir_cluster: u32,
    entry_index: usize,
    entry_bytes: &[u8; 32],
) -> Result<(), KernelError> {
    let chain = read_cluster_chain(sb_data, dir_cluster)?;
    let entries_per_cluster = sb_data.cluster_size as usize / 32;

    let cluster_idx = entry_index / entries_per_cluster;
    let index_in_cluster = entry_index % entries_per_cluster;

    if cluster_idx >= chain.len() {
        return Err(KernelError::InvalidArgument);
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
) -> Result<[u8; 11], KernelError> {
    // Get existing short names to avoid collisions
    let existing_entries = read_directory_entries(sb_data, parent_cluster)?;
    let existing_short_names: Vec<[u8; 11]> =
        existing_entries.iter().map(|e| e.short_name).collect();

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

    let total_slots = lfn_entries.len() + 1; // LFN entries + 1 short entry

    // Find space
    let (_first_cluster, first_index) = find_free_dir_slots(sb_data, parent_cluster, total_slots)?;

    // Write LFN entries (they come first on disk, in reverse sequence order)
    for (i, lfn) in lfn_entries.iter().enumerate() {
        let entry_index = first_index + i;
        let mut entry_bytes = [0u8; 32];

        // The entry's on-disk bytes (packed, little-endian: its layout)
        entry_bytes.copy_from_slice(lfn.as_bytes());

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

/// Update directory entry metadata (start_cluster and file_size) by short name
fn update_dir_entry_by_short_name(
    sb_data: &VfatSbData,
    parent_cluster: u32,
    short_name: &[u8; 11],
    new_start_cluster: u32,
    new_size: u32,
) -> Result<(), KernelError> {
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

    Err(KernelError::NotFound)
}

/// Delete a directory entry by marking it as deleted (0xE5)
fn delete_dir_entry(
    sb_data: &VfatSbData,
    parent_cluster: u32,
    name: &str,
) -> Result<u32, KernelError> {
    let chain = read_cluster_chain(sb_data, parent_cluster)?;
    let entries_per_cluster = sb_data.cluster_size as usize / 32;

    let mut lfn_start: Option<(usize, usize)> = None; // (chain_idx, entry_in_cluster)
    let mut lfn = Lfn::default();

    // Search for the entry
    for (chain_idx, &cluster) in chain.iter().enumerate() {
        let cluster_offset = cluster_to_offset(sb_data, cluster);

        for i in 0..entries_per_cluster {
            let entry_offset = cluster_offset + (i as u64 * 32);
            let mut buf = [0u8; 32];
            read_bytes(&sb_data.bdev, entry_offset, &mut buf)?;

            // End of directory
            if buf[0] == END_MARKER {
                return Err(KernelError::NotFound);
            }

            // Skip already deleted
            if buf[0] == DELETED_MARKER {
                lfn_start = None;
                lfn.clear();
                continue;
            }

            // Track and collect LFN entries
            let attr_byte = buf[11];
            if (attr_byte & attr::LONG_NAME_MASK) == attr::LONG_NAME {
                let entry = VfatLfnEntry::read_from(&buf).expect("32-byte entry");
                if entry.order & 0x40 != 0 {
                    // Start of LFN sequence
                    lfn_start = Some((chain_idx, i));
                }
                lfn.add(&entry);
                continue;
            }

            // Regular entry - check name (both short and long)
            let dirent = VfatDirEntry::read_from(&buf).expect("32-byte entry");
            let short_name = short_name_to_string(&dirent.name, &dirent.ext);
            let long_name = lfn.take_name(&dirent.name, &dirent.ext);
            let current_lfn_start = lfn_start.take();

            // Check if either short name or long name matches
            let matches = short_name.eq_ignore_ascii_case(name)
                || long_name
                    .as_ref()
                    .is_some_and(|ln| ln.eq_ignore_ascii_case(name));

            if matches {
                // Restore lfn_start for deletion
                let lfn_start = current_lfn_start;
                // Found it! Get start cluster before deleting
                let cluster_hi = u32::from(u16::from_le_bytes([buf[20], buf[21]]));
                let cluster_lo = u32::from(u16::from_le_bytes([buf[26], buf[27]]));
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

    Err(KernelError::NotFound)
}

// ============================================================================
// VFAT Inode Operations
// ============================================================================

/// VFAT inode operations
pub struct VfatInodeOps;

impl InodeOps for VfatInodeOps {
    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, KernelError> {
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

    /// An unlinked file's clusters are freed with its inode (Linux
    /// fat_evict_inode), on the system workqueue: the last reference can
    /// go where no I/O may be done
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
        if d.start_cluster == 0 {
            return;
        }
        let mut job = Some((sb_data, d.start_cluster));
        let work = crate::task::workqueue::Work::new(move || {
            if let Some((sb_data, start)) = job.take() {
                let _ = free_cluster_chain(&sb_data, start);
            }
        });
        crate::task::workqueue::SYSTEM_WQ
            .queue_work(arc_nofail(crate::sync::IrqSpinlock::new(work)));
    }

    fn create(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<Arc<Inode>, KernelError> {
        let name = &new_name(dir, name)?;
        let _ = mode; // FAT doesn't support Unix permissions
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let dir_inode_data = get_inode_data(dir)?;

        if !dir_inode_data.is_dir {
            return Err(KernelError::NotDirectory);
        }

        // Check if file already exists
        let entries = read_directory_entries(&sb_data, dir_inode_data.start_cluster)?;
        for entry in &entries {
            if entry.name.eq_ignore_ascii_case(name) {
                return Err(KernelError::AlreadyExists);
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

        inode.set_private(new_private(VfatInodeData {
            start_cluster,
            file_size,
            is_dir: false,
            parent_cluster,
            short_name,
            mmu_private: 0,
            clusters: 0,
        })?);
        icache::insert_inode_hash(&inode, ikey(parent_cluster, &short_name));
        dir_sync(&sb, &sb_data)?;
        Ok(inode)
    }

    fn mkdir(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<Arc<Inode>, KernelError> {
        let name = &new_name(dir, name)?;
        let _ = mode; // FAT doesn't support Unix permissions
        let sb = dir.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        let dir_inode_data = get_inode_data(dir)?;

        if !dir_inode_data.is_dir {
            return Err(KernelError::NotDirectory);
        }

        // Check if directory already exists
        let entries = read_directory_entries(&sb_data, dir_inode_data.start_cluster)?;
        for entry in &entries {
            if entry.name.eq_ignore_ascii_case(name) {
                return Err(KernelError::AlreadyExists);
            }
        }

        // Allocate a cluster for the new directory
        let new_cluster = allocate_cluster(&sb_data)?;

        // Initialize directory with . and .. entries
        let cluster_offset = cluster_to_offset(&sb_data, new_cluster);
        let cluster_size = sb_data.cluster_size as usize;

        // Zero out the cluster first
        let zeros = crate::util::kmem::try_vec(cluster_size, 0u8)?;
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

        inode.set_private(new_private(VfatInodeData {
            start_cluster: new_cluster,
            file_size: 0,
            is_dir: true,
            parent_cluster,
            short_name,
            mmu_private: 0,
            clusters: 0,
        })?);
        icache::insert_inode_hash(&inode, ikey(parent_cluster, &short_name));
        dir_sync(&sb, &sb_data)?;
        Ok(inode)
    }

    fn unlink(&self, dir: &Inode, name: &[u8]) -> Result<(), KernelError> {
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
        // last reference to its inode (Linux fat_unlink + fat_evict_inode)
        let start_cluster = delete_dir_entry(&sb_data, dir_inode_data.start_cluster, name)?;
        drop_link(
            &sb,
            &sb_data,
            dir_inode_data.start_cluster,
            entry,
            start_cluster,
        )?;
        dir_sync(&sb, &sb_data)
    }

    fn rmdir(&self, dir: &Inode, name: &[u8]) -> Result<(), KernelError> {
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
        let start_cluster = delete_dir_entry(&sb_data, dir_inode_data.start_cluster, name)?;
        drop_link(
            &sb,
            &sb_data,
            dir_inode_data.start_cluster,
            entry,
            start_cluster,
        )?;
        dir_sync(&sb, &sb_data)
    }

    /// Linux fat_setattr(ATTR_SIZE): direct I/O in flight waited for
    /// (inode_dio_wait), then shrinking drops the pages past
    /// the end (truncate_setsize, mappings included) before the clusters
    /// go; growing zeroes the rest of the last cluster through the page
    /// cache and gives the file zeroed clusters. The VFS holds i_rwsem.
    fn truncate(&self, inode: &Arc<Inode>, length: u64) -> Result<(), KernelError> {
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
            super::fs_writeback::mark_inode_dirty(inode);
            inode.set_size(length);
        }
        update_size(inode, &sb_data)
    }

    /// As Linux fat_fallocate: KEEP_SIZE allocates clusters past the end
    /// (fat_add_clusters), plain mode is an expanding truncate
    /// (fat_cont_expand); nothing else
    fn fallocate(
        &self,
        inode: &Arc<Inode>,
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
        new_dir: &Arc<Inode>,
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
        let old_dir_data = get_inode_data(old_dir)?;
        let new_dir_data = get_inode_data(new_dir)?;

        // Find the source entry
        let old_entries = read_directory_entries(&sb_data, old_dir_data.start_cluster)?;
        let old_entry = old_entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(old_name))
            .ok_or(KernelError::NotFound)?
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
                return Err(KernelError::InvalidArgument);
            }
            if existing.is_dir() {
                // Check if target dir is empty
                let child_entries = read_directory_entries(&sb_data, existing.start_cluster)?;
                for child in &child_entries {
                    if child.name != "." && child.name != ".." {
                        return Err(KernelError::DirectoryNotEmpty);
                    }
                }
            }
            // Delete existing entry (its clusters as for unlink)
            let existing_cluster =
                delete_dir_entry(&sb_data, new_dir_data.start_cluster, new_name)?;
            drop_link(
                &sb,
                &sb_data,
                new_dir_data.start_cluster,
                existing,
                existing_cluster,
            )?;
        }

        // Create new entry with old entry's data
        let attr_byte = if old_entry.is_dir() {
            attr::DIRECTORY
        } else {
            attr::ARCHIVE
        };
        let new_short = create_dir_entry_with_lfn(
            &sb_data,
            new_dir_data.start_cluster,
            new_name,
            attr_byte,
            old_entry.start_cluster,
            old_entry.file_size,
        )?;

        // Delete old entry (don't free clusters - they belong to new entry now)
        delete_dir_entry(&sb_data, old_dir_data.start_cluster, old_name)?;

        // The moved object keeps its inode (Linux fat_detach + fat_attach)
        if let Some(inode) = cached(&sb, old_dir_data.start_cluster, &old_entry.short_name) {
            let mut d = get_inode_data(&inode)?;
            d.parent_cluster = new_dir_data.start_cluster;
            d.short_name = new_short;
            // The entry has moved on disk: the inode follows
            set_inode_data(&inode, d)?;
            icache::rehash(&inode, ikey(new_dir_data.start_cluster, &new_short));
        }
        dir_sync(&sb, &sb_data)
    }
}

pub static VFAT_INODE_OPS: VfatInodeOps = VfatInodeOps;

/// A directory change on a dirsync or sync mount reaches the disk
/// before the call returns (Linux fat: IS_DIRSYNC, sync_dirty_buffer of
/// the entry and FAT blocks)
fn dir_sync(sb: &SuperBlock, sb_data: &VfatSbData) -> Result<(), KernelError> {
    if !sb.dirsync() {
        return Ok(());
    }
    crate::block::blkdev::sync_blockdev(&sb_data.bdev)
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
fn cached(sb: &Arc<SuperBlock>, parent: u32, short: &[u8; 11]) -> Option<Arc<Inode>> {
    icache::ilookup5(sb, ikey(parent, short), &|i| is_obj(i, parent, short))
}

/// The one inode of a directory entry (Linux fat_build_inode: fat_iget,
/// else a new inode hashed by its position)
fn vfat_iget(
    sb: &Arc<SuperBlock>,
    entry: &ParsedDirEntry,
    parent: u32,
) -> Result<Arc<Inode>, KernelError> {
    let short = entry.short_name;
    icache::iget5(
        sb,
        ikey(parent, &short),
        &|i| is_obj(i, parent, &short),
        || create_inode_for_entry(sb, entry, parent),
    )
}

/// The entry `entry` of the directory at `parent` was removed: its
/// cached inode becomes unlinked (nlink 0, unhashed) and keeps its
/// clusters until its last reference goes (`evict_inode`); with no
/// cached inode they are freed now. An unlinked inode has no directory
/// entry any more (Linux fat_detach): writes and truncates never update
/// one (the name may belong to a new file by then).
fn drop_link(
    sb: &Arc<SuperBlock>,
    sb_data: &VfatSbData,
    parent: u32,
    entry: &ParsedDirEntry,
    start_cluster: u32,
) -> Result<(), KernelError> {
    if let Some(inode) = cached(sb, parent, &entry.short_name) {
        inode.nlink.store(0, core::sync::atomic::Ordering::Release);
        icache::remove_inode_hash(&inode);
        return Ok(());
    }
    if start_cluster != 0 {
        free_cluster_chain(sb_data, start_cluster)?;
    }
    Ok(())
}

/// Create an inode for a parsed directory entry
fn create_inode_for_entry(
    sb: &Arc<SuperBlock>,
    entry: &ParsedDirEntry,
    parent_cluster: u32,
) -> Result<Arc<Inode>, KernelError> {
    let sb_data = get_sb_data(sb)?;
    // A directory points at a cluster of its own (Linux
    // fat_validate_dir); a file's first cluster is checked when its
    // chain is walked (`cache`, Linux fat_get_cluster)
    if entry.is_dir() && (entry.start_cluster == 0 || entry.start_cluster == sb_data.root_cluster) {
        return Err(KernelError::Io);
    }
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

    inode.set_private(new_private(VfatInodeData {
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
    fn fsync(&self, file: &File) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let sb = inode.superblock().ok_or(KernelError::Io)?;
        let sb_data = get_sb_data(&sb)?;
        super::fs_writeback::writeback_inode(&inode)?;
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
    fn statfs(&self, _sb: &SuperBlock) -> StatFs {
        // TODO: Could provide actual block counts from VfatSbData if available
        // For now, return minimal valid values
        StatFs {
            f_type: MSDOS_SUPER_MAGIC,
            f_bsize: 4096,  // Cluster size varies; use common value
            f_namelen: 255, // LFN max length
            ..StatFs::default()
        }
    }

    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, KernelError> {
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

/// Placeholder mount function for pseudo-fs style (shouldn't be called)
fn vfat_mount_pseudo(
    _fs_type: &'static FileSystemType,
    _opts: &[u8],
) -> Result<Arc<SuperBlock>, KernelError> {
    Err(KernelError::OperationNotSupported) // FAT32 requires a device
}

/// Mount VFAT filesystem on a block device
fn vfat_mount_dev(
    fs_type: &'static FileSystemType,
    bdev: Arc<BlockDevice>,
    opts: &[u8],
) -> Result<Arc<SuperBlock>, KernelError> {
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
    })?;

    // The root directory's chain must be sound (Linux fat_read_root ->
    // fat_calc_dir_size walks it: EIO)
    read_cluster_chain(&sb_data, sb_data.root_cluster)?;

    // Create superblock
    let sb = SuperBlock::new(fs_type, &VFAT_SUPER_OPS, 0)?;
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
        Arc::downgrade(&sb),
        &VFAT_INODE_OPS,
    ))?;
    root_inode
        .i_data
        .set_aops(&VFAT_FILE_AOPS, Some(&root_inode));

    root_inode.set_private(new_private(VfatInodeData {
        start_cluster: boot_sector.root_cluster,
        file_size: 0,
        is_dir: true,
        parent_cluster: 0,      // Root has no parent
        short_name: [b' '; 11], // Root has no short name
        mmu_private: 0,
        clusters: 0,
    })?);

    // Names match without case or trailing dots (Linux setup's
    // vfat_ci_dentry_ops), before the root dentry takes them
    sb.set_d_op(&VFAT_CI_DENTRY_OPS);
    let root_dentry = crate::fs::DentryRef::new(Dentry::new_root(root_inode, Arc::downgrade(&sb)))?;
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
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
};

#[cfg(test)]
mod tests {
    use super::*;

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
