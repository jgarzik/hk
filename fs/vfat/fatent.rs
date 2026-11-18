//! FAT entries through the device's buffer heads (Linux
//! fs/fat/fatent.c): an entry is read and written in the FAT block's
//! pinned buffer (`FatEnt`, Linux struct fat_entry), a changed block
//! goes on the FAT inode's metadata list (mmb, Linux
//! MSDOS_I(sbi->fat_inode)->i_metadata_bhs, which fsync writes) and
//! is copied into every other FAT (`fat_mirror_bhs`).
//!
//! hk mounts FAT32 only (`vfat_fill_super`), so these are Linux's
//! fat32_ops (fat_ent_blocknr, fat32_ent_set_ptr, fat_ent_bread,
//! fat32_ent_get, fat32_ent_put, fat32_ent_next): one buffer per entry.
//!
//! Allocation, freeing and the free count run under the FAT lock
//! (`VfatSbData.fat`, Linux sbi->fat_lock / lock_fat).

use alloc::vec::Vec;

use crate::fs::buffer::{self, BhRef, MappingMetadataBhs};
use crate::fs::inode::Inode;
use crate::util::error::KernelError;

use super::{VfatSbData, with_vi};

/// A free cluster's entry (Linux FAT_ENT_FREE)
pub const FAT_ENT_FREE: u32 = 0;
/// FAT32's bad-cluster mark: entries from it up read as the end (Linux
/// BAD_FAT32)
pub const BAD_FAT32: u32 = 0x0FFF_FFF7;
/// The end of a chain (Linux FAT_ENT_EOF = EOF_FAT32)
pub const FAT_ENT_EOF: u32 = 0x0FFF_FFFF;
/// The first data cluster (Linux FAT_START_ENT)
pub const FAT_START_ENT: u32 = 2;
/// Buffers of a page at the smallest block size (Linux
/// MAX_BUF_PER_PAGE)
pub const MAX_BUF_PER_PAGE: usize = crate::mm::filemap::PAGE_SIZE / 512;

/// FAT32 entries are 4 bytes (Linux sbi->fatent_shift)
const FATENT_SHIFT: u32 = 2;

/// An entry and the FAT block holding it (Linux struct fat_entry)
pub struct FatEnt {
    /// The entry (cluster) number
    pub entry: u32,
    /// Its byte offset in `bh` (Linux u.ent32_p), None past the block
    off: Option<usize>,
    /// The block's buffer, pinned (Linux bhs[0], nr_bhs 0 or 1)
    bh: Option<BhRef>,
}

impl FatEnt {
    /// No entry, no buffer (Linux fatent_init)
    pub const fn new() -> Self {
        Self {
            entry: 0,
            off: None,
            bh: None,
        }
    }

    /// Linux fatent_set_entry
    fn set_entry(&mut self, entry: u32) {
        self.entry = entry;
        self.off = None;
    }

    /// Release the buffer (Linux fatent_brelse)
    pub fn brelse(&mut self) {
        self.bh = None;
        self.off = None;
    }
}

/// `c` is a data cluster (Linux fat_valid_entry)
fn fat_valid_entry(sb: &VfatSbData, c: u32) -> bool {
    (FAT_START_ENT..sb.max_cluster).contains(&c)
}

/// Run `f` on the FAT inode's metadata list (Linux
/// MSDOS_I(sbi->fat_inode)->i_metadata_bhs)
pub fn with_fat_mmb<R>(
    sb: &VfatSbData,
    f: impl FnOnce(&MappingMetadataBhs) -> R,
) -> Result<R, KernelError> {
    with_vi(&sb.fat_inode, |v| f(&v.i_metadata_bhs))
}

/// Mark `bh` dirty on the FAT inode's list (Linux
/// mmb_mark_buffer_dirty(bh, &MSDOS_I(fat_inode)->i_metadata_bhs))
fn fat_mark_dirty(sb: &VfatSbData, bh: &BhRef) {
    let r = with_fat_mmb(sb, |m| {
        // SAFETY: the list is in the FAT inode's `VfatInode`, an `Arc`
        // that never moves and is dropped (waiting a grace period)
        // only with the inode, after its eviction emptied the list
        unsafe { buffer::mmb_mark_buffer_dirty(bh, m) }
    });
    if r.is_err() {
        buffer::mark_buffer_dirty(bh);
    }
}

/// Linux fat_ent_blocknr: the entry's byte offset in its FAT block
/// and the block's number
fn ent_blocknr(sb: &VfatSbData, entry: u32) -> (usize, u64) {
    let bytes = u64::from(entry) << FATENT_SHIFT;
    let bs = u64::from(sb.bytes_per_sector);
    ((bytes % bs) as usize, sb.fat_start_sector + bytes / bs)
}

/// Linux fat_ent_bread: the block read into `fe`, EIO if unreadable
fn ent_bread(
    sb: &VfatSbData,
    fe: &mut FatEnt,
    offset: usize,
    blocknr: u64,
) -> Result<(), KernelError> {
    let bh = buffer::bread(&sb.bdev, blocknr, sb.bytes_per_sector as usize)?;
    fe.bh = Some(bh);
    fe.off = Some(offset);
    Ok(())
}

/// The entry's raw word (Linux le32_to_cpu(*fatent->u.ent32_p))
fn ent_raw(fe: &FatEnt) -> u32 {
    let (Some(bh), Some(off)) = (&fe.bh, fe.off) else {
        return FAT_ENT_EOF;
    };
    let mut b = [0u8; 4];
    bh.read_data(off, &mut b);
    u32::from_le_bytes(b)
}

/// Linux fat32_ent_get: the next cluster, the end (FAT_ENT_EOF) for a
/// bad or end mark
pub fn ent_get(fe: &FatEnt) -> u32 {
    let next = ent_raw(fe) & 0x0FFF_FFFF;
    if next >= BAD_FAT32 { FAT_ENT_EOF } else { next }
}

/// Linux fat32_ent_put: `new` into the entry, its top four bits kept,
/// the block dirty on the FAT inode's list
fn ent_put(sb: &VfatSbData, fe: &FatEnt, new: u32) {
    let (Some(bh), Some(off)) = (&fe.bh, fe.off) else {
        return;
    };
    debug_assert!(new & 0xF000_0000 == 0);
    let v = new | (ent_raw(fe) & !0x0FFF_FFFF);
    bh.write_data(off, &v.to_le_bytes());
    fat_mark_dirty(sb, bh);
}

/// Linux fat32_ent_next: on to the next entry; false past the block
fn ent_next(sb: &VfatSbData, fe: &mut FatEnt) -> bool {
    fe.entry += 1;
    match fe.off {
        Some(o) if o + 4 < sb.bytes_per_sector as usize => {
            fe.off = Some(o + 4);
            true
        }
        _ => {
            fe.off = None;
            false
        }
    }
}

/// Linux fat_ent_update_ptr: `fe`'s buffer already holds the entry
fn fat_ent_update_ptr(fe: &mut FatEnt, offset: usize, blocknr: u64) -> bool {
    match &fe.bh {
        Some(bh) if bh.blocknr() == blocknr => {
            fe.off = Some(offset);
            true
        }
        _ => false,
    }
}

/// The entry of cluster `entry` (Linux fat_ent_read): EIO for one
/// outside the data clusters ("invalid access to FAT") or an
/// unreadable block
pub fn fat_ent_read(sb: &VfatSbData, fe: &mut FatEnt, entry: u32) -> Result<u32, KernelError> {
    if !fat_valid_entry(sb, entry) {
        fe.brelse();
        return Err(KernelError::Io);
    }
    fe.set_entry(entry);
    let (offset, blocknr) = ent_blocknr(sb, entry);
    if !fat_ent_update_ptr(fe, offset, blocknr) {
        fe.brelse();
        ent_bread(sb, fe, offset, blocknr)?;
    }
    Ok(ent_get(fe))
}

/// Write `bhs` and wait (Linux fat_sync_bhs): EIO if one failed
pub fn fat_sync_bhs(bhs: &[BhRef]) -> Result<(), KernelError> {
    for bh in bhs {
        buffer::write_dirty_buffer(bh);
    }
    let mut err = Ok(());
    for bh in bhs {
        buffer::wait_on_buffer(bh);
        if err.is_ok() && !bh.uptodate() {
            err = Err(KernelError::Io);
        }
    }
    err
}

/// Copy the FAT blocks `bhs` into every other FAT (Linux
/// fat_mirror_bhs): each copy's buffer filled under its lock (a
/// device-node read sees old or new), uptodate, dirty on the FAT
/// inode's list; on a synchronous mount written at once. `inode` is
/// the one whose change it is.
fn fat_mirror_bhs(sb: &VfatSbData, inode: &Inode, bhs: &[BhRef]) -> Result<(), KernelError> {
    let bs = sb.bytes_per_sector as usize;
    let sync = inode.is_sync();
    for copy in 1..sb.num_fats {
        let backup_fat = sb.fat_sectors * copy;
        for bh in bhs {
            let c_bh = buffer::bdev_getblk(&sb.bdev, backup_fat + bh.blocknr(), bs)?;
            // Avoid race with userspace read via bdev (Linux)
            buffer::lock_buffer(&c_bh);
            let mut chunk = [0u8; 512];
            for at in (0..bs).step_by(chunk.len()) {
                bh.read_data(at, &mut chunk);
                c_bh.write_data(at, &chunk);
            }
            c_bh.set_uptodate();
            buffer::unlock_buffer(&c_bh);
            fat_mark_dirty(sb, &c_bh);
            if sync {
                buffer::sync_dirty_buffer(&c_bh)?;
            }
        }
    }
    Ok(())
}

/// `new` into the entry `fe` holds (Linux fat_ent_write): with `wait`
/// its block written at once, then mirrored
pub fn fat_ent_write(
    sb: &VfatSbData,
    inode: &Inode,
    fe: &FatEnt,
    new: u32,
    wait: bool,
) -> Result<(), KernelError> {
    ent_put(sb, fe, new);
    let Some(bh) = &fe.bh else {
        return Err(KernelError::Io);
    };
    let bhs = core::slice::from_ref(bh);
    if wait {
        fat_sync_bhs(bhs)?;
    }
    fat_mirror_bhs(sb, inode, bhs)
}

/// Linux fat_ent_next: on to the next entry while in the block and
/// among the data clusters
fn fat_ent_next(sb: &VfatSbData, fe: &mut FatEnt) -> bool {
    ent_next(sb, fe) && fe.entry < sb.max_cluster
}

/// Linux fat_ent_read_block: the block of `fe.entry` read
fn fat_ent_read_block(sb: &VfatSbData, fe: &mut FatEnt) -> Result<(), KernelError> {
    fe.brelse();
    let (offset, blocknr) = ent_blocknr(sb, fe.entry);
    ent_bread(sb, fe, offset, blocknr)
}

/// Add `fe`'s buffer to `bhs` unless there (Linux fat_collect_bhs)
fn fat_collect_bhs(bhs: &mut Vec<BhRef>, fe: &FatEnt) {
    if let Some(bh) = &fe.bh
        && !bhs.iter().any(|b| {
            core::ptr::eq(
                core::ptr::from_ref::<buffer::BufferHead>(b),
                core::ptr::from_ref(bh),
            )
        })
    {
        bhs.push(bh.clone());
    }
}

/// The inode's changes are synchronous (Linux inode_needs_sync: IS_SYNC,
/// or a directory on a dirsync mount)
pub fn inode_needs_sync(inode: &Inode) -> bool {
    inode.is_sync() || (inode.mode().is_dir() && inode.superblock().is_some_and(|sb| sb.dirsync()))
}

/// Allocate `cluster.len()` clusters as a chain for `inode` (Linux
/// fat_alloc_clusters): the next fit after the last one taken, under
/// the FAT lock, each marked the end and linked from the one before;
/// then their blocks synced if the inode's changes are synchronous and
/// mirrored. ENOSPC when the free count says so, or the FAT has too
/// few; a failure frees what was taken.
pub fn fat_alloc_clusters(
    sb: &VfatSbData,
    inode: &Inode,
    cluster: &mut [u32],
) -> Result<(), KernelError> {
    let nr_cluster = cluster.len();
    assert!(nr_cluster <= MAX_BUF_PER_PAGE / 2, "fixed limit");
    let mut bhs: Vec<BhRef> = Vec::new();
    bhs.try_reserve(MAX_BUF_PER_PAGE)
        .map_err(|_| KernelError::OutOfMemory)?;
    let mut idx_clus = 0;
    let mut fatent = FatEnt::new();
    let mut err = {
        let mut st = sb.fat.lock();
        if st.free >= 0 && (st.free as usize) < nr_cluster {
            return Err(KernelError::NoSpace);
        }
        let mut prev_ent = FatEnt::new();
        let mut count = FAT_START_ENT;
        fatent.set_entry(st.prev_free + 1);
        let r = 'out: {
            while count < sb.max_cluster {
                if fatent.entry >= sb.max_cluster {
                    fatent.entry = FAT_START_ENT;
                }
                fatent.set_entry(fatent.entry);
                if let Err(e) = fat_ent_read_block(sb, &mut fatent) {
                    break 'out Err(e);
                }
                // Find the free entries in a block
                loop {
                    if ent_get(&fatent) == FAT_ENT_FREE {
                        let entry = fatent.entry;
                        // Make the cluster chain
                        ent_put(sb, &fatent, FAT_ENT_EOF);
                        if prev_ent.bh.is_some() {
                            ent_put(sb, &prev_ent, entry);
                        }
                        fat_collect_bhs(&mut bhs, &fatent);
                        st.prev_free = entry;
                        if st.free != -1 {
                            st.free -= 1;
                        }
                        cluster[idx_clus] = entry;
                        idx_clus += 1;
                        if idx_clus == nr_cluster {
                            break 'out Ok(());
                        }
                        // The buffer is held in `bhs` too
                        prev_ent = FatEnt {
                            entry: fatent.entry,
                            off: fatent.off,
                            bh: fatent.bh.clone(),
                        };
                    }
                    count += 1;
                    if count == sb.max_cluster {
                        break;
                    }
                    if !fat_ent_next(sb, &mut fatent) {
                        break;
                    }
                }
            }
            // Couldn't allocate the free entries
            st.free = 0;
            Err(KernelError::NoSpace)
        };
        drop(prev_ent);
        r
    };
    fatent.brelse();
    if err.is_ok() {
        if inode_needs_sync(inode) {
            err = fat_sync_bhs(&bhs);
        }
        if err.is_ok() {
            err = fat_mirror_bhs(sb, inode, &bhs);
        }
    }
    drop(bhs);
    if err.is_err() && idx_clus != 0 {
        let _ = fat_free_clusters(sb, inode, cluster[0]);
    }
    err
}

/// Free the chain at `cluster` (Linux fat_free_clusters), under the
/// FAT lock: each entry made free and counted, the blocks mirrored (and
/// synced on a synchronous mount) a page's worth at a time. EIO for a
/// chain running into a free entry ("deleting FAT entry beyond EOF").
pub fn fat_free_clusters(sb: &VfatSbData, inode: &Inode, cluster: u32) -> Result<(), KernelError> {
    let mut bhs: Vec<BhRef> = Vec::new();
    bhs.try_reserve(MAX_BUF_PER_PAGE)
        .map_err(|_| KernelError::OutOfMemory)?;
    let sync = inode.is_sync();
    let mut fatent = FatEnt::new();
    let mut st = sb.fat.lock();
    let mut cluster = cluster;
    let r = 'error: {
        loop {
            cluster = match fat_ent_read(sb, &mut fatent, cluster) {
                Ok(FAT_ENT_FREE) => break 'error Err(KernelError::Io),
                Ok(c) => c,
                Err(e) => break 'error Err(e),
            };
            ent_put(sb, &fatent, FAT_ENT_FREE);
            if st.free != -1 {
                st.free += 1;
            }
            if bhs.len() + 1 > MAX_BUF_PER_PAGE {
                if sync && let Err(e) = fat_sync_bhs(&bhs) {
                    break 'error Err(e);
                }
                if let Err(e) = fat_mirror_bhs(sb, inode, &bhs) {
                    break 'error Err(e);
                }
                bhs.clear();
            }
            fat_collect_bhs(&mut bhs, &fatent);
            if cluster == FAT_ENT_EOF {
                break;
            }
        }
        if sync {
            fat_sync_bhs(&bhs)?;
        }
        fat_mirror_bhs(sb, inode, &bhs)
    };
    fatent.brelse();
    drop(bhs);
    drop(st);
    r
}

/// The FAT blocks read ahead of a sequential walk (Linux struct
/// fatent_ra)
struct FatentRa {
    cur: u64,
    limit: u64,
    ra_blocks: u64,
    ra_advance: u64,
    ra_next: u64,
    ra_limit: u64,
}

/// The device's readahead in pages (its read_ahead_kb, 128: Linux
/// VM_READAHEAD_PAGES; one I/O as large, so no rounding to io_pages)
const RA_PAGES: u64 = 128 * 1024 / crate::mm::filemap::PAGE_SIZE as u64;

/// Linux fat_ra_init: the window over the blocks of entries
/// [fatent.entry, ent_limit)
fn fat_ra_init(sb: &VfatSbData, fatent: &FatEnt, ent_limit: u32) -> FatentRa {
    let mut ra = FatentRa {
        cur: 0,
        limit: 0,
        ra_blocks: 0,
        ra_advance: 0,
        ra_next: 0,
        ra_limit: 0,
    };
    if fatent.entry >= ent_limit {
        return ra;
    }
    // ra_pages * 2 in blocks
    let page_shift = crate::mm::filemap::PAGE_SIZE.trailing_zeros();
    let reada_blocks = RA_PAGES << (page_shift - sb.bytes_per_sector.trailing_zeros() + 1);
    let (_, blocknr) = ent_blocknr(sb, fatent.entry);
    let (_, block_end) = ent_blocknr(sb, ent_limit - 1);
    ra.limit = (block_end + 1) - blocknr;
    // Advancing the window at half size
    ra.ra_blocks = reada_blocks >> 1;
    ra.ra_limit = reada_blocks.min(ra.limit);
    ra
}

/// Linux fat_ent_reada: before reading a new block, start the window's
/// blocks once the walk reaches its advance point
fn fat_ent_reada(sb: &VfatSbData, ra: &mut FatentRa, fatent: &FatEnt) {
    if ra.ra_next >= ra.ra_limit {
        return;
    }
    if ra.cur >= ra.ra_advance {
        let (_, blocknr) = ent_blocknr(sb, fatent.entry);
        let diff = blocknr - ra.cur;
        let bs = sb.bytes_per_sector as usize;
        crate::block::plug::blk_plug(|| {
            while ra.ra_next < ra.ra_limit {
                buffer::breadahead(&sb.bdev, ra.ra_next + diff, bs);
                ra.ra_next += 1;
            }
        });
        // Advance the readahead window
        ra.ra_advance += ra.ra_blocks;
        ra.ra_limit += ra.ra_blocks.min(ra.limit - ra.ra_limit);
    }
    ra.cur += 1;
}

/// The free data clusters, counted from the FAT the first time and kept
/// after (Linux fat_count_free_clusters, under the FAT lock, the FAT
/// read ahead)
pub fn fat_count_free_clusters(sb: &VfatSbData) -> Result<u64, KernelError> {
    let mut st = sb.fat.lock();
    if st.free != -1 {
        return Ok(st.free as u64);
    }
    let mut free = 0i64;
    let mut fatent = FatEnt::new();
    fatent.set_entry(FAT_START_ENT);
    let mut ra = fat_ra_init(sb, &fatent, sb.max_cluster);
    while fatent.entry < sb.max_cluster {
        fat_ent_reada(sb, &mut ra, &fatent);
        fat_ent_read_block(sb, &mut fatent)?;
        loop {
            if ent_get(&fatent) == FAT_ENT_FREE {
                free += 1;
            }
            if !fat_ent_next(sb, &mut fatent) {
                break;
            }
        }
        crate::task::percpu::cond_resched();
    }
    st.free = free;
    Ok(free as u64)
}

/// Read the entry of `last` and link it to `new` (Linux fat_chain_add's
/// FAT step): with `wait` synced; on failure the old entry put back
pub fn fat_ent_link(
    sb: &VfatSbData,
    inode: &Inode,
    last: u32,
    new: u32,
    wait: bool,
) -> Result<(), KernelError> {
    let mut fatent = FatEnt::new();
    let old = fat_ent_read(sb, &mut fatent, last)?;
    let r = fat_ent_write(sb, inode, &fatent, new, wait);
    if r.is_err() {
        let _ = fat_ent_write(sb, inode, &fatent, old, wait);
    }
    r
}
