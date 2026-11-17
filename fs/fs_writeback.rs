//! Writing back dirty inodes (Linux fs/fs-writeback.c, fs/sync.c)
//!
//! An inode whose page cache gets a dirty page is marked dirty once
//! (`Inode.i_dirty`, Linux I_DIRTY_PAGES) and put at the tail of its
//! device's `b_dirty` list (`BdiWriteback`, Linux wb->b_dirty) through
//! its embedded `Inode.i_io_list`. The lists hold no reference (Linux):
//! an inode's last reference evicts it, dirty or not, and its eviction
//! takes it off (`inode_io_list_del`, Linux evict); a pass takes a
//! reference to each inode it writes, skipping one already being freed
//! (Linux I_FREEING). The device's periodic writeback is armed when its
//! lists were empty (every ~5 s).
//!
//! A pass (Linux wb_writeback) moves the inodes it takes from `b_dirty`
//! to `b_io` (Linux queue_io / move_expired_inodes: those dirtied at or
//! before a cutoff, of one superblock for a sync, oldest first), then
//! writes them one at a time: each is taken off `b_io` under the list
//! lock, marked clean, and written (`filemap::write_and_wait`) with the
//! lock released, so a page dirtied meanwhile puts it back on `b_dirty`.
//! Passes over one device's lists are serialized by its sleeping
//! `BdiWriteback.pass` (Linux runs them one at a time on the wb's work
//! list). There is no `b_more_io`: an inode is always written whole
//! (Linux parks there an inode whose wbc->nr_to_write ran out).
//!
//! `writeback_sb` (Linux sync_filesystem: sync_inodes_sb +
//! sync_blockdev) runs for sync(2), syncfs(2) and umount; the periodic
//! writeback (`wb_writeback`) for every superblock of the device and
//! its own cache (the block device's inode is on the same lists).
//!
//! Locking: `BdiWriteback.list_lock` is a spin leaf, thread context
//! only; `mark_inode_dirty` may run under a page lock (the fault path),
//! never under a spinlock. Writing sleeps (block I/O) with no spinlock
//! held, under `BdiWriteback.pass`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

/// `Inode.i_io_on`: on no list, on `b_dirty`, on `b_io`
const ON_NONE: u8 = 0;
const ON_DIRTY: u8 = 1;
const ON_IO: u8 = 2;

use super::inode::{Inode, InodeRef};
use super::superblock::{SuperBlock, iterate_supers};
use crate::mm::writeback::BdiWriteback;
use crate::util::error::KernelError;

crate::adapter!(pub IoListA, Inode, i_io_list);

/// The writeback state of `inode`'s device (Linux inode_to_wb,
/// inode_to_bdi): its filesystem's, or the block device's own for its
/// cache inode (sb_is_blkdev_sb)
fn inode_to_wb(inode: &Inode) -> Option<Arc<BdiWriteback>> {
    let sb = inode.superblock()?;
    if core::ptr::eq(sb.fs_type, crate::fs::pseudo::BDEV.fs_type()) {
        return crate::fs::blkdev_ops::inode_bdev(inode)
            .ok()
            .map(|b| b.disk.bdi.clone());
    }
    sb.bdev().map(|b| b.disk.bdi.clone())
}

/// `inode` has a new dirty page (Linux __mark_inode_dirty(I_DIRTY_PAGES)):
/// the first time, queue it on its device's `b_dirty` and arm the
/// periodic writeback if nothing was queued (its mapping notes when it
/// became dirty). An inode with no device to write to stays marked and
/// unqueued (Linux noop_backing_dev_info).
pub fn mark_inode_dirty(inode: &InodeRef) {
    if !inode.i_data.aops().can_dirty() || inode.i_dirty.swap(true, Ordering::AcqRel) {
        return;
    }
    // Its wb, found once (Linux inode->i_wb)
    let wb = match inode.i_wb.get() {
        Some(wb) => wb.clone(),
        None => {
            let Some(wb) = inode_to_wb(inode) else {
                return;
            };
            inode.i_wb.call_once(|| wb).clone()
        }
    };
    let first = {
        let mut l = wb.list_lock.lock();
        let first = l.b_dirty.is_empty() && l.b_io.is_empty();
        // Off every list: the pass that took it marked it clean under
        // this lock after taking it off b_io
        l.b_dirty.push_back(inode);
        inode.i_io_on.store(ON_DIRTY, Ordering::Relaxed);
        first
    };
    if first {
        wb.wakeup_delayed();
    }
}

/// The last reference to `inode` went: off its device's writeback list
/// if it is on one (Linux evict -> inode_io_list_del), before any of
/// its fields go (the lists' `InodeList` contract)
pub(super) fn inode_io_list_del(inode: &Inode) {
    let Some(wb) = inode.i_wb.get() else {
        return;
    };
    let mut l = wb.list_lock.lock();
    let on = inode.i_io_on.swap(ON_NONE, Ordering::Relaxed);
    // SAFETY: `i_io_on` names the list it is linked on, both changed
    // under this lock
    unsafe {
        match on {
            ON_DIRTY => l.b_dirty.remove(inode),
            ON_IO => l.b_io.remove(inode),
            _ => {}
        }
    }
}

/// Write back one inode's dirty pages (Linux writeback_single_inode,
/// for fsync and the dirty limits). The inode stays queued (`i_dirty`
/// is that membership): the next pass finds it clean.
pub fn writeback_inode(inode: &Inode) -> Result<(), KernelError> {
    crate::mm::filemap::write_and_wait(inode)
}

/// Its pages became dirty at or before `cutoff` (monotonic ns)
fn expired(inode: &Inode, cutoff: u64) -> bool {
    inode.i_data.dirtied_when.load(Ordering::Acquire) <= cutoff
}

/// One pass over `wb` (Linux wb_writeback): the inodes dirtied at or
/// before `cutoff` (of `sb` only, if given) are queued on `b_io` in
/// `b_dirty` order and written one at a time. The first error is
/// returned after the rest were tried.
fn wb_writeback(
    wb: &BdiWriteback,
    cutoff: u64,
    sb: Option<&SuperBlock>,
) -> Result<(), KernelError> {
    let _pass = wb.pass.lock();
    {
        // Linux queue_io: move_expired_inodes, filtered as
        // writeback_sb_inodes skips other superblocks for a sync
        let mut l = wb.list_lock.lock();
        let l = &mut *l;
        l.b_dirty.move_if(&mut l.b_io, |i| {
            let take = expired(i, cutoff) && sb.is_none_or(|s| core::ptr::eq(i.sb.as_ptr(), s));
            if take {
                i.i_io_on.store(ON_IO, Ordering::Relaxed);
            }
            take
        });
    }
    let mut err = Ok(());
    loop {
        let inode = {
            let mut l = wb.list_lock.lock();
            let Some(w) = l.b_io.front() else {
                break;
            };
            // A reference for the write (Linux __iget), unless its last
            // one went and its eviction waits for this lock (I_FREEING):
            // skipped. Marked clean under the lock it was queued under:
            // one dirtied from now on goes back on b_dirty
            w.i_io_on.store(ON_NONE, Ordering::Relaxed);
            let i = w.igrab();
            if let Some(i) = &i {
                i.i_dirty.store(false, Ordering::Release);
            }
            l.b_io.pop_front();
            i
        };
        let Some(inode) = inode else {
            continue;
        };
        if let Err(e) = writeback_inode(&inode)
            && err.is_ok()
        {
            err = Err(e);
        }
        // Its last reference may go here, with no lock held
        drop(inode);
    }
    err
}

/// Write back every dirty inode of `sb`, then its device's cache
/// (Linux sync_filesystem: sync_inodes_sb + sync_blockdev). The first
/// error is returned after the rest were tried.
pub fn writeback_sb(sb: &SuperBlock) -> Result<(), KernelError> {
    let Some(b) = sb.bdev() else {
        return Ok(());
    };
    let r = wb_writeback(&b.disk.bdi, u64::MAX, Some(sb));
    r.and(crate::block::blkdev::sync_blockdev(b))
}

/// Write back every device filesystem (sync(2): Linux ksys_sync, the
/// inodes; the block devices follow)
pub fn sync_all_sbs() {
    iterate_supers(|sb| {
        let _ = writeback_sb(sb);
    });
}

/// The periodic writeback of `wb` (Linux wb_workfn -> wb_do_writeback):
/// what became dirty at or before `cutoff` (kupdate: older than
/// vm.dirty_expire_centisecs; background writeback passes `u64::MAX`),
/// filesystems' inodes and the device's own cache alike. True if dirty
/// inodes are left for a later pass (Linux wb_has_dirty_io)
pub fn wb_do_writeback(wb: &BdiWriteback, cutoff: u64) -> bool {
    let _ = wb_writeback(wb, cutoff, None);
    !wb.list_lock.lock().b_dirty.is_empty()
}
