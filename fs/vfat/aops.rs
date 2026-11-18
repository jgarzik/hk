//! vfat file data in the page cache on buffer heads (Linux
//! fs/fat/inode.c: fat_get_block, fat_aops). A file's blocks are its
//! filesystem's (the FAT sector size, the device's soft block size set
//! at mount), mapped through its cluster chain (`cache::fat_bmap`) and
//! allocated a cluster at a time as a write reaches them; the bytes up
//! to mmu_private are allocated and initialized, so a write past them
//! first zeroes the gap through the cache (cont_write_begin).

use core::sync::atomic::Ordering;

use crate::fs::inode::Inode;
use crate::fs::pageio::buffer::{self, BufferHead};
use crate::fs::pageio::mpage;
use crate::fs::superblock::SuperBlock;
use crate::mm::filemap::{self, AddressSpace, Aops};
use crate::util::error::KernelError;

use super::fatent::{fat_alloc_clusters, fat_free_clusters};
use super::{VfatSbData, cache, fat_chain_add, fat_truncate_blocks, msdos_sb, with_vi};

/// A vfat file's page cache I/O (Linux fat_aops)
pub struct VfatAops;

pub static VFAT_FILE_AOPS: VfatAops = VfatAops;

/// Add one cluster to the end of the file's chain (Linux
/// fat_add_cluster): allocated, then linked; freed again if the link
/// fails
pub fn fat_add_cluster(sbi: &VfatSbData, inode: &Inode) -> Result<(), KernelError> {
    let mut cluster = [0u32];
    fat_alloc_clusters(sbi, inode, &mut cluster)?;
    let r = fat_chain_add(sbi, inode, cluster[0], 1);
    if r.is_err() {
        let _ = fat_free_clusters(sbi, inode, cluster[0]);
    }
    r
}

/// Map file block `iblock` and up to `max_blocks` after it into `bh`
/// (Linux __fat_get_block); `max_blocks` lowered to the blocks mapped.
/// With `create`, the block at mmu_private is allocated when unmapped:
/// a new cluster when it starts one past the file's clusters (a
/// fallocated one is used), BH_New, and mmu_private raised past the
/// blocks mapped. EIO when the chain or mmu_private disagrees with the
/// size.
fn fat_map_blocks(
    (sb, sb_data): (&SuperBlock, &VfatSbData),
    inode: &Inode,
    iblock: u64,
    max_blocks: &mut u64,
    bh: &BufferHead,
    create: bool,
) -> Result<(), KernelError> {
    let (phys, mapped) = cache::fat_bmap(sb_data, inode, iblock, create, false)?;
    if phys != 0 {
        buffer::map_bh(bh, sb, phys)?;
        *max_blocks = (*max_blocks).min(mapped);
        return Ok(());
    }
    if !create {
        return Ok(());
    }
    let bits = sb_data.bytes_per_sector.trailing_zeros();
    let (mmu_private, clusters, i_pos) = with_vi(inode, |v| {
        let d = v.d.lock();
        (v.mmu_private.load(Ordering::Relaxed), d.clusters, d.i_pos)
    })?;
    if iblock != mmu_private >> bits {
        crate::printkln!("FAT-fs: corrupted file size (i_pos {i_pos}, {mmu_private})");
        return Err(KernelError::Io);
    }
    let spc = u64::from(sb_data.sectors_per_cluster);
    let last_block = u64::from(clusters) * spc;
    let offset = iblock & (spc - 1);
    // A new cluster unless the block lies in one the file has (fallocate)
    if offset == 0 && iblock >= last_block {
        fat_add_cluster(sb_data, inode)?;
    }
    // Available blocks on this cluster
    *max_blocks = (*max_blocks).min(spc - offset);
    with_vi(inode, |v| {
        v.mmu_private
            .fetch_add(*max_blocks << bits, Ordering::Relaxed)
    })?;
    let (phys, mapped) = cache::fat_bmap(sb_data, inode, iblock, create, false)?;
    if phys == 0 {
        crate::printkln!("FAT-fs: invalid FAT chain (i_pos {i_pos}, last_block {last_block})");
        return Err(KernelError::Io);
    }
    debug_assert_eq!(*max_blocks, mapped);
    bh.set_new();
    buffer::map_bh(bh, sb, phys)
}

/// The file's get_block (Linux fat_get_block): `bh`'s size in, the bytes
/// mapped out
pub fn fat_get_block(
    inode: &Inode,
    iblock: u64,
    bh: &BufferHead,
    create: bool,
) -> Result<(), KernelError> {
    let bits = inode.blkbits();
    let mut max_blocks = (bh.size() >> bits) as u64;
    let sb = inode.superblock().ok_or(KernelError::Io)?;
    let sbi = &msdos_sb(&sb)?;
    fat_map_blocks((&sb, sbi), inode, iblock, &mut max_blocks, bh, create)?;
    bh.set_size((max_blocks << bits) as usize);
    Ok(())
}

/// The file's get_block for bmap (Linux fat_get_block_bmap): no
/// allocation, every cluster the file has mapped (fallocated ones too)
fn fat_get_block_bmap(
    inode: &Inode,
    iblock: u64,
    bh: &BufferHead,
    create: bool,
) -> Result<(), KernelError> {
    debug_assert!(!create);
    let sb = inode.superblock().ok_or(KernelError::Io)?;
    let bits = inode.blkbits();
    let mut max_blocks = (bh.size() >> bits) as u64;
    let (bmap, mapped) = cache::fat_bmap(&*msdos_sb(&sb)?, inode, iblock, false, true)?;
    if bmap != 0 {
        buffer::map_bh(bh, &sb, bmap)?;
        max_blocks = max_blocks.min(mapped);
    }
    bh.set_size((max_blocks << bits) as usize);
    Ok(())
}

/// A write to `to` that failed or came up short past the size (Linux
/// fat_write_failed): the pages and clusters past the size go again.
/// Direct I/O still in flight (a read past its lock) ends first, so no
/// cluster it reads is given to another file.
pub fn fat_write_failed(inode: &Inode, to: u64) {
    if to <= inode.get_size() {
        return;
    }
    inode.inode_dio_wait();
    filemap::truncate_pagecache(inode, inode.get_size());
    // Best effort, like its void return
    let _ = fat_truncate_blocks(inode, inode.get_size());
}

/// Zero the file from `from` to the end of its block (Linux
/// fat_block_truncate_page), before a truncate to `from`: the tail of
/// that block on the disk never shows if the file grows again
pub fn fat_block_truncate_page(inode: &Inode, from: u64) -> Result<(), KernelError> {
    buffer::block_truncate_page(inode, from, fat_get_block)
}

impl Aops for VfatAops {
    /// Linux block_dirty_folio
    fn dirty_folio(&self, m: &AddressSpace, phys: u64) {
        buffer::block_dirty_folio(m, phys);
    }

    /// Linux fat_read_folio: mpage_read_folio, which unlocks the page
    /// when the read ends
    fn read_folio(&self, inode: &Inode, phys: u64, _index: u64) -> Result<(), KernelError> {
        mpage::mpage_read_folio(inode, phys, fat_get_block);
        Ok(())
    }

    /// Linux fat_writepages: mpage_writepages, a page at a time
    /// (`mpage_write_folio`): one bio for a page of contiguous dirty
    /// blocks, else its dirty buffers only
    fn writepage(&self, inode: &Inode, phys: u64, _index: u64) -> Result<(), KernelError> {
        mpage::mpage_write_folio(inode, phys, fat_get_block)
    }

    /// Linux fat_write_begin: cont_write_begin over mmu_private, a
    /// failure undone past the size (fat_write_failed)
    fn write_begin(&self, inode: &Inode, pos: u64, len: usize) -> Result<u64, KernelError> {
        let r = with_vi(inode, |v| {
            buffer::cont_write_begin(inode, pos, len, fat_get_block, &v.mmu_private)
        })
        .and_then(|r| r);
        if r.is_err() {
            fat_write_failed(inode, pos + len as u64);
        }
        r
    }

    /// Linux fat_write_end: generic_write_end, a short write undone past
    /// the size (fat_write_failed). (Linux also sets ATTR_ARCH with the
    /// times once: hk keeps no attribute bits, BUGS vfat gaps.)
    fn write_end(&self, inode: &Inode, pos: u64, len: usize, copied: usize, phys: u64) -> usize {
        let n = buffer::generic_write_end(inode, pos, len, copied, phys);
        if n < len {
            fat_write_failed(inode, pos + len as u64);
        }
        n
    }

    /// Linux block_invalidate_folio
    fn invalidate_folio(&self, m: &AddressSpace, phys: u64, offset: usize, len: usize) {
        buffer::block_invalidate_folio(m, phys, offset, len);
    }

    /// Linux _fat_bmap: generic_block_bmap over all the file's
    /// clusters (fat_get_block_bmap); the caller's i_rwsem keeps the
    /// chain (Linux takes truncate_lock)
    fn bmap(&self, inode: &Inode, block: u64) -> Result<u64, KernelError> {
        Ok(buffer::generic_block_bmap(inode, block, fat_get_block_bmap))
    }
}
