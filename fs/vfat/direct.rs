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
//! - Asynchronous I/O (`submit`: AIO, io_uring; Linux
//!   do_blockdev_direct_IO with an async kiocb): a read as above, its
//!   result cut at the size when the bios end; a write within the size
//!   and the initialized bytes, with no page cached over the file, no
//!   O_APPEND and no O_DSYNC, as above under i_rwsem until its bios are
//!   submitted; if the file has pages cached when they end (a buffered
//!   read meanwhile), a worker drops the written range before the
//!   result is passed on (Linux dio_bio_end_aio ->
//!   dio_aio_complete_work -> kiocb_invalidate_post_direct_write). Any
//!   other write runs to its end at once through the VFS (Linux:
//!   is_async only for a write that does not extend the file).
//!   The I/O is counted in `i_dio_count` until its last bio is done.
//!   No RWF_NOWAIT (Linux fat has no FMODE_NOWAIT: EOPNOTSUPP).

use alloc::sync::Arc;

use crate::block::dio::{self, AsyncIo, Extent};
use crate::fs::file::{File, RwFlags};
use crate::fs::inode::Inode;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::mm::filemap::{self, PAGE_SIZE};
use crate::mm::gup::PageSeg;
use crate::sync::IrqSpinlock;
use crate::task::workqueue::{SYSTEM_WQ, Work};
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;

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
/// kiocb_invalidate_post_direct_write): a page left is not the write's
/// error but the mapping's (`filemap::dio_warn_stale_pagecache`)
fn invalidate_post(inode: &Inode, pos: u64, count: usize) {
    let p = PAGE_SIZE as u64;
    if inode.i_data.nrpages() != 0
        && filemap::invalidate_pages2(inode, pos / p, last(pos, count) / p).is_err()
    {
        filemap::dio_warn_stale_pagecache(inode);
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

// ============================================================================
// Asynchronous direct I/O
// ============================================================================

/// An asynchronous direct I/O of a vfat file: counted in its inode's
/// `i_dio_count` while it lives (Linux inode_dio_begin, inode_dio_end
/// in dio_complete), a read's result cut at the size it saw; a write
/// ends in thread context when the file has pages cached at its end
/// (`PostWrite`)
struct VfatAio {
    inner: Arc<dyn AsyncIo>,
    inode: Arc<Inode>,
    /// Most bytes the result counts
    cut: usize,
    /// A write's end over a cached range
    post: Option<PostWrite>,
}

/// The end of an asynchronous write in thread context, when the file
/// has pages cached as its bios end (Linux dio_bio_end_aio defers to
/// dio_aio_complete_work then: a buffered read during the write may
/// have cached what the disk held before it, and dio_complete drops
/// the range, kiocb_invalidate_post_direct_write). Made at submission,
/// as nothing is allocated where the bios end.
struct PostWrite {
    pos: u64,
    work: Arc<IrqSpinlock<Work>>,
    /// The ended write and its result, for the work (IrqSpinlock leaf,
    /// any context)
    job: Arc<IrqSpinlock<Option<Job>>>,
}

/// An ended write handed to its work
type Job = (Arc<VfatAio>, Result<usize, KernelError>);

impl PostWrite {
    fn new(pos: u64) -> Result<Self, KernelError> {
        let job: Arc<IrqSpinlock<Option<Job>>> = try_arc(IrqSpinlock::new(None))?;
        let j = job.clone();
        let work = try_arc(IrqSpinlock::new(Work::new(move || {
            let done = j.lock().take();
            if let Some((w, res)) = done {
                w.invalidate(&res);
                w.finish(res);
            }
        })))?;
        Ok(Self { pos, work, job })
    }
}

impl VfatAio {
    /// `write`: the position of a write
    fn new(
        inner: Arc<dyn AsyncIo>,
        inode: &Arc<Inode>,
        cut: usize,
        write: Option<u64>,
    ) -> Result<Arc<Self>, KernelError> {
        let post = write.map(PostWrite::new).transpose()?;
        inode.inode_dio_begin();
        let r = try_arc(Self {
            inner,
            inode: inode.clone(),
            cut,
            post,
        });
        if r.is_err() {
            inode.inode_dio_end();
        }
        r
    }

    /// Drop what was cached over the written range meanwhile (thread
    /// context)
    fn invalidate(&self, res: &Result<usize, KernelError>) {
        if let (Some(p), Ok(n)) = (&self.post, res)
            && *n > 0
        {
            invalidate_post(&self.inode, p.pos, *n);
        }
    }

    /// End the count and pass the result on (any context)
    fn finish(self: Arc<Self>, res: Result<usize, KernelError>) {
        let inner = self.inner.clone();
        drop(self);
        inner.complete(res);
    }
}

impl Drop for VfatAio {
    fn drop(&mut self) {
        self.inode.inode_dio_end();
    }
}

// SAFETY: the pieces are the inner I/O's, pinned while it lives, and
// this holds it; `complete` cuts the result and either hands this to
// its write's work (a lock and a queueing, both any context: the work
// was made at submission) or ends the count (atomics and a wakeup) and
// drops this before passing the result on: its inode reference is not
// the last, as the inner request holds the file (`FileOps::dio_submit`)
unsafe impl AsyncIo for VfatAio {
    fn segs(&self) -> &[PageSeg] {
        self.inner.segs()
    }

    fn complete(self: Arc<Self>, res: Result<usize, KernelError>) {
        let res = res.map(|n| n.min(self.cut));
        let cached = matches!(res, Ok(n) if n > 0) && self.inode.i_data.nrpages() != 0;
        if let Some(p) = self.post.as_ref().filter(|_| cached) {
            let (job, work) = (p.job.clone(), p.work.clone());
            *job.lock() = Some((self, res));
            SYSTEM_WQ.queue_work(work);
            return;
        }
        self.finish(res);
    }
}

/// Start O_DIRECT I/O of `io`'s memory at `pos` of `file` without
/// waiting where it can (module docs): Ok(None) when queued, Ok(Some(n))
/// when done at once
pub fn submit(
    file: &File,
    io: Arc<dyn AsyncIo>,
    pos: u64,
    write: bool,
    flags: RwFlags,
) -> Result<Option<usize>, KernelError> {
    if flags.nowait() {
        return Err(KernelError::OperationNotSupported);
    }
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    if write {
        write_async(file, &inode, io, pos, flags)
    } else {
        read_async(&inode, io, pos)
    }
}

/// Bytes of `io`'s memory
fn io_len(io: &dyn AsyncIo) -> usize {
    io.segs().iter().map(|s| s.len as usize).sum()
}

/// An asynchronous direct read (`direct_read`'s steps, the wait left to
/// the bios' end)
fn read_async(
    inode: &Arc<Inode>,
    io: Arc<dyn AsyncIo>,
    pos: u64,
) -> Result<Option<usize>, KernelError> {
    let count = io_len(&*io);
    if count == 0 {
        return Ok(Some(0));
    }
    filemap::write_and_wait_range(inode, pos, last(pos, count))?;
    let lock = inode.lock();
    let size = inode.get_size();
    if pos >= size {
        return Ok(Some(0));
    }
    let sb = sb_of(inode)?;
    let bs = blocksize(&sb, pos, IovDest::async_io(&*io).alignment())?;
    filemap::write_and_wait_range(inode, pos, last(pos, count))?;
    let len = (size.next_multiple_of(bs) - pos).min(count as u64) as usize;
    let m = map(&sb, inode, pos, len)?;
    // Lossless: below `count`
    let cut = (size - pos).min(count as u64) as usize;
    let w = VfatAio::new(io, inode, cut, None)?;
    dio::submit_async_map(&sb.bdev, w, &m, len, false, RwFlags::empty())?;
    drop(lock);
    Ok(None)
}

/// An asynchronous direct write where it can be one (module docs), else
/// the whole write at once through the VFS
fn write_async(
    file: &File,
    inode: &Arc<Inode>,
    io: Arc<dyn AsyncIo>,
    pos: u64,
    flags: RwFlags,
) -> Result<Option<usize>, KernelError> {
    let count = io_len(&*io);
    // `flags` are the request's whole (its RWF_APPEND / RWF_NOAPPEND
    // over the file's O_APPEND), so they say whether it appends
    let append = Some(flags.contains(RwFlags::APPEND));
    let sync = |io: &dyn AsyncIo| {
        file.write_iter(&mut IovSource::async_io(io), Some(pos), flags, append)
            .map(Some)
    };
    let synchronous = inode.superblock().is_some_and(|sb| sb.synchronous());
    if count == 0
        || synchronous
        || flags.intersects(RwFlags::APPEND | RwFlags::DSYNC | RwFlags::SYNC)
    {
        return sync(&*io);
    }
    let lock = inode.lock();
    let sb = sb_of(inode)?;
    let end = pos
        .checked_add(count as u64)
        .ok_or(KernelError::InvalidArgument)?;
    let fits = !inode.i_swapfile.load(core::sync::atomic::Ordering::Acquire)
        && end <= inode.get_size()
        && get_inode_data(inode)?.mmu_private >= end
        && inode.i_data.nrpages() == 0
        && inode.write_limit(pos, count) == Ok(count)
        && blocksize(&sb, pos, IovSource::async_io(&*io).alignment()).is_ok();
    if !fits {
        drop(lock);
        return sync(&*io);
    }
    let m = map(&sb, inode, pos, count)?;
    // file_modified, before the data (Linux __generic_file_write_iter)
    crate::fs::dac::remove_privs(inode);
    inode.touch_mc();
    let w = VfatAio::new(io, inode, count, Some(pos))?;
    dio::submit_async_map(&sb.bdev, w, &m, count, true, flags)?;
    drop(lock);
    Ok(None)
}
