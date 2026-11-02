//! Writing back dirty inodes (Linux fs/fs-writeback.c, fs/sync.c)
//!
//! An inode whose page cache gets a dirty page is marked dirty once
//! (`Inode.i_dirty`, Linux I_DIRTY_PAGES) and put on its superblock's
//! dirty list (`SuperBlock.s_dirty`, Linux wb->b_dirty), which holds a
//! reference: a dirty inode stays in memory until written back. Its
//! device's periodic writeback is armed (`BdiWriteback`, every ~5 s).
//!
//! `writeback_sb` (Linux sync_inodes_sb + sync_blockdev) takes the list,
//! writes each inode's dirty pages (`filemap::write_and_wait`), then the
//! device's own cache (filesystem metadata). It runs from fsync's
//! superblock-wide callers: sync(2), syncfs(2), umount and the periodic
//! device writeback. Device filesystems register in `SUPER_BLOCKS`
//! (Linux super_blocks) when mounted.
//!
//! Locking: `SuperBlock.s_dirty` and `SUPER_BLOCKS` are spin leaves,
//! thread context only; `mark_inode_dirty` may run under a page lock
//! (the fault path), never under a spinlock. Writeback itself sleeps
//! (block I/O) with no spinlock held.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::inode::Inode;
use super::superblock::SuperBlock;
use crate::error::KernelError;
use crate::sync::spin::Mutex;

/// Device-backed superblocks (Linux super_blocks)
static SUPER_BLOCKS: Mutex<Vec<Weak<SuperBlock>>> = Mutex::new(Vec::new());

/// Register a device filesystem's superblock for sync(2)
pub fn register_sb(sb: &Arc<SuperBlock>) {
    let mut l = SUPER_BLOCKS.lock();
    l.retain(|w| w.strong_count() > 0);
    l.push(Arc::downgrade(sb));
}

fn live_sbs() -> Vec<Arc<SuperBlock>> {
    SUPER_BLOCKS
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .collect()
}

/// `inode` has a new dirty page (Linux __mark_inode_dirty(I_DIRTY_PAGES)):
/// the first time, put it on its superblock's dirty list and arm its
/// device's periodic writeback
pub fn mark_inode_dirty(inode: &Arc<Inode>) {
    if !inode.i_data.aops().can_dirty() || inode.i_dirty.swap(true, Ordering::AcqRel) {
        return;
    }
    let Some(sb) = inode.superblock() else {
        // The bdev pseudo filesystem: its device writes it back
        inode.i_dirty.store(false, Ordering::Release);
        return;
    };
    sb.s_dirty.lock().push(inode.clone());
    if let Some(b) = sb.bdev() {
        b.disk.bdi.kick(b.dev_id());
    }
}

/// Write back one inode's dirty pages (Linux writeback_single_inode):
/// clean first, so a page dirtied meanwhile puts it back on the list
pub fn writeback_inode(inode: &Inode) -> Result<(), KernelError> {
    inode.i_dirty.store(false, Ordering::Release);
    crate::mm::filemap::write_and_wait(inode)
}

/// Write back every dirty inode of `sb`, then its device's cache
/// (Linux sync_filesystem: sync_inodes_sb + sync_blockdev). The first
/// error is returned after the rest were tried.
pub fn writeback_sb(sb: &SuperBlock) -> Result<(), KernelError> {
    let dirty = core::mem::take(&mut *sb.s_dirty.lock());
    let mut err = Ok(());
    for inode in dirty {
        if let Err(e) = writeback_inode(&inode)
            && err.is_ok()
        {
            err = Err(e);
        }
    }
    if let Some(b) = sb.bdev()
        && let Err(e) = crate::storage::blkdev::sync_blockdev(b)
        && err.is_ok()
    {
        err = Err(e);
    }
    err
}

/// Write back every device filesystem (sync(2): Linux ksys_sync, the
/// inodes; the block devices follow)
pub fn sync_all_sbs() {
    for sb in live_sbs() {
        let _ = writeback_sb(&sb);
    }
}

/// The filesystems mounted from device `dev` (periodic writeback)
pub fn writeback_dev(dev: crate::storage::DevId) {
    for sb in live_sbs() {
        if sb.bdev().is_some_and(|b| b.dev_id() == dev) {
            let _ = writeback_sb(&sb);
        }
    }
}
