//! vfat O_DIRECT (Linux fat_direct_IO over __blockdev_direct_IO with
//! DIO_LOCKING, called from generic_file_read_iter and
//! generic_file_direct_write / direct_write_fallback): bios between the
//! file's clusters and the caller's pinned pages (`block::dio`), the
//! chain mapped once per I/O into disk extents (`cache::extents`).
//!
//! - Alignment: the position and every segment's address and length
//!   are multiples of the filesystem's block (its logical sector), or
//!   failing that of the device's logical block; EINVAL otherwise.
//! - Reads take i_rwsem exclusive from the end-of-file check until the
//!   last bio is submitted, not across the wait (DIO_LOCKING). At or
//!   past the end: 0. Across it: the disk is read to the end of the
//!   block holding the last byte and the count cut at the size. The
//!   cache over the range is written back first, before the lock and
//!   again under it; it is not dropped.
//! - Each I/O is counted in the inode's `i_dio_count` until its last
//!   bio is done (Linux inode_dio_begin/end): a truncate or a failed
//!   write's trim waits for it (`inode_dio_wait`) before clusters go.
//! - Writes run under the i_rwsem the VFS holds. One reaching past the
//!   initialized bytes (`mmu_private`) is not done directly at all:
//!   it goes through the cache whole, so it succeeds even unaligned.
//!   Otherwise the cache over the range is written back and dropped
//!   (a page that cannot be: all of it through the cache), the bios
//!   sent, the range dropped again, and the size raised to the end if
//!   the write went past it. What the bios did not take goes through
//!   the cache, then is written back and dropped. O_DSYNC is the VFS's
//!   generic_write_sync (fsync), not FUA.

use alloc::sync::Arc;

use crate::block::dio::{self, Extent};
use crate::fs::inode::Inode;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::mm::filemap::{self, PAGE_SIZE};
use crate::util::error::KernelError;

use super::{
    VfatSbData, cache, get_inode_data, get_sb_data, update_size, vfat_write, write_failed,
};

/// Last byte of `count` (> 0) bytes at `pos`
fn last(pos: u64, count: usize) -> u64 {
    pos.saturating_add(count as u64 - 1)
}

/// The block size a direct I/O at `pos` whose memory's addresses and
/// lengths OR to `mem` is done in (Linux __blockdev_direct_IO): the
/// filesystem's block, else the device's logical block; EINVAL if
/// neither divides them all
fn blocksize(sb: &VfatSbData, pos: u64, mem: u64) -> Result<u64, KernelError> {
    let align = pos | mem;
    [sb.bytes_per_sector, sb.bdev.logical_block_size()]
        .into_iter()
        .map(u64::from)
        .find(|bs| align & (bs - 1) == 0)
        .ok_or(KernelError::InvalidArgument)
}

/// The disk extents of the file's `len` bytes at `pos`; EIO if the
/// chain ends first (Linux fat_bmap: "request beyond EOF")
fn map(
    sb: &VfatSbData,
    inode: &Inode,
    pos: u64,
    len: usize,
) -> Result<alloc::vec::Vec<Extent>, KernelError> {
    let m = cache::extents(sb, inode, pos, len)?;
    if m.iter().map(|e| e.1).sum::<usize>() != len {
        return Err(KernelError::Io);
    }
    Ok(m)
}

/// The filesystem of `inode`
fn sb_of(inode: &Inode) -> Result<VfatSbData, KernelError> {
    get_sb_data(&inode.superblock().ok_or(KernelError::Io)?)
}

/// O_DIRECT read of `to` at `pos` (Linux generic_file_read_iter with
/// IOCB_DIRECT): the cache over the range written back, the direct
/// part, then the rest through the cache if it stopped short before
/// the end of the file
pub fn read(inode: &Arc<Inode>, to: &mut IovDest<'_>, pos: u64) -> Result<usize, KernelError> {
    let count = to.len();
    if count == 0 {
        return Ok(0);
    }
    filemap::write_and_wait_range(inode, pos, last(pos, count))?;
    let n = direct_read(inode, to, pos)?;
    if n == count || pos + n as u64 >= inode.get_size() {
        return Ok(n);
    }
    match filemap::read_iter(inode, to, pos + n as u64) {
        Ok(m) => Ok(n + m),
        Err(e) if n == 0 => Err(e),
        Err(_) => Ok(n),
    }
}

/// The direct part of a read (Linux fat_direct_IO ->
/// __blockdev_direct_IO, DIO_LOCKING): under i_rwsem until the bios are
/// submitted; the bytes read, cut at the size
fn direct_read(inode: &Inode, to: &mut IovDest<'_>, pos: u64) -> Result<usize, KernelError> {
    let count = to.len();
    let lock = inode.lock();
    let size = inode.get_size();
    if pos >= size {
        return Ok(0);
    }
    let sb = sb_of(inode)?;
    let bs = blocksize(&sb, pos, to.alignment())?;
    filemap::write_and_wait_range(inode, pos, last(pos, count))?;
    // The block holding the last byte is read whole (Linux: up to
    // i_size aligned to the block)
    let len = (size.next_multiple_of(bs) - pos).min(count as u64) as usize;
    to.truncate(len);
    let m = map(&sb, inode, pos, len)?;
    // Counted until the last bio is done, after the lock is dropped: a
    // truncate waits for it before freeing clusters (Linux
    // inode_dio_begin in do_blockdev_direct_IO)
    let _dio = inode.dio_guard();
    let n = dio::direct_io_map(&sb.bdev, to, &m, lock)?;
    Ok(n.min((size - pos) as usize))
}

/// Write back and drop the cache over the range before a direct write
/// (Linux kiocb_invalidate_pages); EBUSY if a page could not be dropped
fn invalidate_pages(inode: &Inode, pos: u64, count: usize) -> Result<(), KernelError> {
    let end = last(pos, count);
    filemap::write_and_wait_range(inode, pos, end)?;
    let p = PAGE_SIZE as u64;
    filemap::invalidate_pages2(inode, pos / p, end / p)
}

/// Drop what was cached over the range during a direct write (Linux
/// kiocb_invalidate_post_direct_write): a page left is reported (Linux
/// dio_warn_stale_pagecache), not an error
fn invalidate_post(inode: &Inode, pos: u64, count: usize) {
    let p = PAGE_SIZE as u64;
    if inode.i_data.nrpages() != 0
        && filemap::invalidate_pages2(inode, pos / p, last(pos, count) / p).is_err()
    {
        crate::printkln!(
            "Page cache invalidation failure on direct I/O.  Possible data corruption due to collision with buffered I/O!"
        );
    }
}

/// O_DIRECT write of `from` at `pos` (Linux __generic_file_write_iter
/// with IOCB_DIRECT); the VFS holds i_rwsem and gave at least one byte
pub fn write(inode: &Arc<Inode>, from: &mut IovSource<'_>, pos: u64) -> Result<usize, KernelError> {
    let count = from.len();
    let n = match invalidate_pages(inode, pos, count) {
        // A page that cannot be dropped: all through the cache
        Err(KernelError::Busy) => 0,
        Err(e) => return Err(e),
        Ok(()) => direct_write(inode, from, pos)?,
    };
    if from.is_empty() {
        return Ok(n);
    }
    fallback(inode, from, pos, n)
}

/// The direct part of a write (Linux generic_file_direct_write ->
/// fat_direct_IO): 0 for one past the initialized bytes; the bios, the
/// range dropped from the cache again and the size raised
fn direct_write(
    inode: &Arc<Inode>,
    from: &mut IovSource<'_>,
    pos: u64,
) -> Result<usize, KernelError> {
    let count = from.len();
    let end = pos + count as u64;
    // Linux fat_direct_IO: blocks past mmu_private would need zeroing
    // first, so the whole write falls back to the cache
    if get_inode_data(inode)?.mmu_private < end {
        return Ok(0);
    }
    let sb = sb_of(inode)?;
    let r = blocksize(&sb, pos, from.alignment())
        .and_then(|_| map(&sb, inode, pos, count))
        .and_then(|m| {
            let _dio = inode.dio_guard();
            dio::direct_io_map(&sb.bdev, from, &m, ())
        });
    let n = match r {
        Ok(n) => n,
        Err(e) => {
            // Linux fat_write_failed
            if end > inode.get_size() {
                let _ = write_failed(inode, &sb);
            }
            return Err(e);
        }
    };
    if n > 0 {
        invalidate_post(inode, pos, n);
        let at = pos + n as u64;
        if at > inode.get_size() {
            inode.set_size(at);
            crate::fs::fs_writeback::mark_inode_dirty(inode);
            // The data is on the disk: its count is returned whatever
            // the directory entry's update does (Linux
            // generic_file_direct_write: mark_inode_dirty cannot fail)
            let _ = update_size(inode, &sb);
        }
    }
    Ok(n)
}

/// The rest of a direct write after `direct` bytes, through the cache,
/// then written back and dropped (Linux direct_write_fallback over
/// generic_perform_write): all the bytes, or the direct ones if this
/// part failed (its error if there were none)
fn fallback(
    inode: &Arc<Inode>,
    from: &mut IovSource<'_>,
    pos: u64,
    direct: usize,
) -> Result<usize, KernelError> {
    let short = |e| if direct > 0 { Ok(direct) } else { Err(e) };
    let at = pos + direct as u64;
    let n = match vfat_write(inode, from, at) {
        Ok(0) => return Ok(direct),
        Ok(n) => n,
        Err(e) => return short(e),
    };
    let end = last(at, n);
    if let Err(e) = filemap::write_and_wait_range(inode, at, end) {
        return short(e);
    }
    let p = PAGE_SIZE as u64;
    filemap::invalidate_clean(inode, at / p, end / p);
    Ok(direct + n)
}
