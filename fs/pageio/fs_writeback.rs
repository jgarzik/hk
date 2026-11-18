//! Writing back dirty inodes (Linux fs/fs-writeback.c, fs/sync.c)
//!
//! An inode's dirty state is in its `i_state` (Linux): I_DIRTY_PAGES
//! (a dirty page in its cache), I_DIRTY_SYNC (metadata fdatasync may
//! skip: times), I_DIRTY_DATASYNC (metadata the data needs: size,
//! clusters), set by `__mark_inode_dirty` and cleared by
//! `__writeback_single_inode` before it writes, all under `i_lock`.
//! The first dirtying of a clean inode queues it at the tail of its
//! device's `b_dirty` (`BdiWriteback`, Linux wb->b_dirty) through its
//! embedded `Inode.i_io_list`, noting when (dirtied_when). The lists
//! hold no reference (Linux): an inode's last reference evicts it,
//! dirty or not, and its eviction takes it off (`inode_io_list_del`,
//! Linux evict); a pass takes a reference to each inode it writes,
//! skipping one already being freed (Linux I_FREEING, I_WILL_FREE).
//! The device's periodic writeback is armed when its lists were empty
//! (every ~5 s).
//!
//! A pass (Linux wb_writeback) moves the inodes it takes from `b_dirty`
//! to `b_io` (Linux queue_io / move_expired_inodes: those dirtied at or
//! before a cutoff, of one superblock for a sync, oldest first, each
//! marked I_SYNC_QUEUED), after the ones a previous pass left on
//! `b_more_io`, then writes them one at a time (Linux
//! writeback_sb_inodes): each is marked I_SYNC and written
//! (`__writeback_single_inode`: its pages, then its metadata if dirty)
//! with the locks released, then requeued by its state (`requeue_inode`:
//! back on `b_dirty` if dirtied again, else off the lists). One being
//! written by someone else (I_SYNC) goes to `b_more_io` for a later
//! pass, or for a data-integrity pass is waited for. Passes over one
//! device's lists are serialized by its sleeping `BdiWriteback.pass`
//! (Linux runs them one at a time on the wb's work list). An inode is
//! always written whole (Linux stops one whose wbc->nr_to_write ran
//! out).
//!
//! `writeback_single_inode` writes one inode on demand (fsync, the
//! write-back before an eviction): under I_SYNC too, waiting for a
//! writer already at it, then off the lists if it is clean.
//!
//! `WritebackControl` (Linux writeback_control) says how: WB_SYNC_NONE
//! (the periodic and background writeback, writeback_inodes_sb) starts
//! the writes, WB_SYNC_ALL (fsync, sync_inodes_sb) waits for them, the
//! metadata's through ->sync_inode_metadata for what ->write_inode
//! marked I_METADATA_WRITEBACK (not for sync(2), whose device sync
//! follows). `sync::sync_filesystem` (writeback_inodes_sb, the
//! device's cache, sync_inodes_sb, the device's cache again) runs for
//! syncfs(2), umount and a remount; sync(2) runs sync_inodes_sb on
//! each, then the block devices; the periodic writeback
//! (`wb_writeback`) runs for every superblock of the device and its
//! own cache (the block device's inode is on the same lists), each
//! superblock pinned by s_umount for reading if free at once, else
//! skipped (Linux __writeback_inodes_wb's super_trylock_shared).
//!
//! Locking (Linux): `BdiWriteback.list_lock` -> `Inode.i_lock`, both
//! spin, thread context only; `i_state` is written under `i_lock` and
//! read lock-free. `__mark_inode_dirty` may run under a page lock (the
//! fault path), never under a spinlock. Writing sleeps (block I/O)
//! with no spinlock held, under `BdiWriteback.pass` for a pass (its
//! ->write_inode too: pass -> what that takes, vfat's `ipos`), and
//! under the inode's superblock's s_umount: the caller's for a pass
//! over one superblock (sync_filesystem, sync(2)), else taken by the
//! pass with trylock under `list_lock`.

use alloc::sync::Arc;
use core::sync::atomic::{Ordering, fence};

/// `Inode.i_io_on`: on no list, on `b_dirty`, `b_io` or `b_more_io`
const ON_NONE: u8 = 0;
const ON_DIRTY: u8 = 1;
const ON_IO: u8 = 2;
const ON_MORE_IO: u8 = 3;

use crate::fs::inode::istate::{
    I_DIRTY, I_DIRTY_ALL, I_DIRTY_PAGES, I_DIRTY_SYNC, I_FREEING, I_METADATA_WRITEBACK, I_SYNC,
    I_SYNC_QUEUED, I_WILL_FREE,
};
use crate::fs::inode::{ILocked, Inode, InodeList, InodeRef};
use crate::fs::superblock::{SuperBlock, iterate_supers, super_trylock_shared};
use crate::mm::writeback::{BdiWriteback, WbLists};
use crate::mm::xarray::{MARK_DIRTY, MARK_WRITEBACK};
use crate::sync::spin::MutexGuard;
use crate::util::error::KernelError;

crate::adapter!(pub IoListA, Inode, i_io_list);

/// Linux enum writeback_sync_modes
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Don't wait on anything (WB_SYNC_NONE)
    None,
    /// Wait on every mapping (data integrity, WB_SYNC_ALL)
    All,
}

/// How much to write and how (Linux struct writeback_control, the
/// fields hk uses)
pub struct WritebackControl {
    /// Pages to write (Linux nr_to_write); 0 writes metadata only
    pub nr_to_write: i64,
    pub sync_mode: SyncMode,
    /// A sync(2)-type data-integrity pass, whose waiting is the
    /// caller's (Linux for_sync)
    pub for_sync: bool,
    /// Tag-and-write to avoid livelock (Linux tagged_writepages)
    pub tagged_writepages: bool,
}

impl WritebackControl {
    /// `sync_mode`, `nr_to_write` pages, the flags clear (Linux's
    /// designated initializer, the rest zero)
    pub const fn new(sync_mode: SyncMode, nr_to_write: i64) -> Self {
        Self {
            nr_to_write,
            sync_mode,
            for_sync: false,
            tagged_writepages: false,
        }
    }
}

/// The writeback state of `inode`'s device (Linux inode_to_wb,
/// inode_to_bdi): its filesystem's, or the block device's own for its
/// cache inode (sb_is_blkdev_sb)
fn inode_to_wb(inode: &Inode) -> Option<Arc<BdiWriteback>> {
    let sb = inode.superblock()?;
    if core::ptr::eq(sb.fs_type, crate::fs::pseudo::BDEV.fs_type()) {
        return crate::fs::pageio::blkdev_ops::inode_bdev(inode)
            .ok()
            .map(|b| b.disk.bdi.clone());
    }
    sb.bdev().map(|b| b.disk.bdi.clone())
}

/// Its wb, found once and kept (Linux inode_attach_wb, inode->i_wb);
/// None for an inode with no device to write to (Linux
/// noop_backing_dev_info). Before `i_lock` here: the lookup may take
/// and drop a superblock reference.
fn inode_attach_wb(inode: &Inode) -> Option<&Arc<BdiWriteback>> {
    if let Some(wb) = inode.i_wb.get() {
        return Some(wb);
    }
    let wb = inode_to_wb(inode)?;
    Some(inode.i_wb.call_once(|| wb))
}

/// Its cache holds a page marked `mark` (Linux mapping_tagged)
fn mapping_tagged(inode: &Inode, mark: usize) -> bool {
    crate::mm::filemap::mapping_tagged(&inode.i_data, mark)
}

/// `inode` has a new dirty page (Linux __folio_mark_dirty ->
/// __mark_inode_dirty(I_DIRTY_PAGES)), for a mapping that writes back
/// (Linux mapping_can_writeback)
pub fn mark_inode_dirty_pages(inode: &InodeRef) {
    if !inode.i_data.aops().can_dirty() {
        return;
    }
    __mark_inode_dirty(inode, I_DIRTY_PAGES);
}

/// `inode` changed (Linux mark_inode_dirty: I_DIRTY): its filesystem's
/// ->write_inode writes it at the next writeback, fsync, fdatasync,
/// sync, unmount or the write-back before its eviction
pub fn mark_inode_dirty(inode: &Inode) {
    __mark_inode_dirty(inode, I_DIRTY);
}

/// `inode` changed in a way fdatasync may skip (Linux
/// mark_inode_dirty_sync: I_DIRTY_SYNC, as times)
pub fn mark_inode_dirty_sync(inode: &Inode) {
    __mark_inode_dirty(inode, I_DIRTY_SYNC);
}

/// Mark `inode` dirty with `flags` (Linux __mark_inode_dirty): set
/// under `i_lock`; an inode going from clean to dirty is queued at the
/// tail of its device's `b_dirty` (noting when, Linux dirtied_when),
/// unless a pass has it (I_SYNC_QUEUED: the pass requeues it by its
/// state) or it is being freed, and the periodic writeback is armed if
/// the lists were empty. An unhashed inode (but a block device's) and
/// one with no device to write to (Linux noop_backing_dev_info) stay
/// marked and unqueued. The caller holds a reference; may run under a
/// page lock, never a spinlock.
pub fn __mark_inode_dirty(inode: &Inode, flags: u32) {
    // Linux smp_mb, paired with the one in __writeback_single_inode:
    // either this test sees the bits cleared or that one sees the
    // dirtying
    fence(Ordering::SeqCst);
    if inode.state() & flags == flags {
        return;
    }
    let wb = inode_attach_wb(inode);
    let l = inode.i_lock.lock();
    let st = inode.state();
    if st & flags == flags {
        return;
    }
    inode.set_state(&l, flags);
    // On a list already (or a pass has it): not repositioned, which
    // would break b_dirty's time order
    if st & I_DIRTY != 0 {
        return;
    }
    let Some(wb) = wb else {
        return;
    };
    // Linux locked_inode_to_wb_and_lock_list: list_lock before i_lock
    drop(l);
    let first = {
        let mut lists = wb.list_lock.lock();
        let l = inode.i_lock.lock();
        if inode.state() & I_SYNC_QUEUED != 0 {
            return;
        }
        // Only a hashed inode, or a block device's, is queued (Linux:
        // an unhashed one is never written back; hashing and unhashing
        // hold `i_lock`)
        if !inode.mode().is_blkdev() && !inode.i_hash_node.is_linked() {
            return;
        }
        if inode.state() & I_FREEING != 0 {
            return;
        }
        inode
            .dirtied_when
            .store(crate::time::monotonic_ns(), Ordering::Relaxed);
        // SAFETY: not I_FREEING under `i_lock`, so its eviction has not
        // taken it off the lists, which it does under `list_lock`, held
        unsafe { io_list_move_locked(&mut lists, inode, &l, ON_DIRTY) }
    };
    if first {
        wb.wakeup_delayed();
    }
}

/// Some list holds an inode (Linux wb_has_dirty_io)
fn has_dirty_io(l: &WbLists) -> bool {
    !l.b_dirty.is_empty() || !l.b_io.is_empty() || !l.b_more_io.is_empty()
}

/// The list `on` names
fn list_of(l: &mut WbLists, on: u8) -> Option<&mut InodeList<IoListA>> {
    match on {
        ON_DIRTY => Some(&mut l.b_dirty),
        ON_IO => Some(&mut l.b_io),
        ON_MORE_IO => Some(&mut l.b_more_io),
        _ => None,
    }
}

/// Take `inode` off the list it is on, if any (Linux list_del_init of
/// i_io_list), under `list_lock` (`l`)
fn io_list_del(l: &mut WbLists, inode: &Inode) {
    let on = inode.i_io_on.swap(ON_NONE, Ordering::Relaxed);
    if let Some(list) = list_of(l, on) {
        // SAFETY: `i_io_on` names the list it is linked on, both changed
        // under `list_lock`
        unsafe { list.remove(inode) };
    }
}

/// Move `inode` to the tail of the list `to` (Linux
/// inode_io_list_move_locked); true if it is the lists' first inode
/// (Linux wb_io_lists_populated)
///
/// # Safety
/// `inode` is not yet evicted: a reference is held, or it is not
/// I_FREEING under its `i_lock` (`il`), with `list_lock` (`l`) held,
/// which its eviction takes to unlink it.
unsafe fn io_list_move_locked(l: &mut WbLists, inode: &Inode, il: &ILocked, to: u8) -> bool {
    inode.assert_locked(il);
    let first = !has_dirty_io(l);
    io_list_del(l, inode);
    let Some(list) = list_of(l, to) else {
        return false;
    };
    // SAFETY: unlinked just above; not evicted (the caller)
    unsafe { list.push_back_unref(inode) };
    inode.i_io_on.store(to, Ordering::Relaxed);
    first
}

/// Clean: off the lists (Linux inode_cgwb_move_to_attached)
fn move_to_attached(l: &mut WbLists, inode: &Inode, il: &ILocked) {
    inode.clear_state(il, I_SYNC_QUEUED);
    io_list_del(l, inode);
}

/// Dirty again: to the tail of `b_dirty`, its dirtied time now if it is
/// older than the newest there (Linux redirty_tail_locked, which also
/// drops one being freed from the lists)
///
/// # Safety
/// As [`io_list_move_locked`], but I_FREEING allowed.
unsafe fn redirty_tail_locked(l: &mut WbLists, inode: &Inode, il: &ILocked) {
    inode.clear_state(il, I_SYNC_QUEUED);
    if inode.state() & I_FREEING != 0 {
        io_list_del(l, inode);
        return;
    }
    if let Some(tail) = l.b_dirty.back()
        && inode.dirtied_when.load(Ordering::Relaxed) < tail.dirtied_when.load(Ordering::Relaxed)
    {
        inode
            .dirtied_when
            .store(crate::time::monotonic_ns(), Ordering::Relaxed);
    }
    // SAFETY: not I_FREEING under `i_lock` (just checked); the caller's
    // locks
    unsafe { io_list_move_locked(l, inode, il, ON_DIRTY) };
}

/// The last reference to `inode` went: off its device's writeback list
/// if it is on one (Linux evict -> inode_io_list_del), before any of
/// its fields go (the lists' `InodeList` contract)
pub(in crate::fs) fn inode_io_list_del(inode: &Inode) {
    let Some(wb) = inode.i_wb.get() else {
        return;
    };
    let mut l = wb.list_lock.lock();
    let il = inode.i_lock.lock();
    inode.clear_state(&il, I_SYNC_QUEUED);
    io_list_del(&mut l, inode);
}

/// The queue I_SYNC's waiters sleep on (Linux inode_bit_waitqueue(
/// __I_SYNC))
fn sync_waitqueue(inode: &Inode) -> &'static crate::sync::waitqueue::WaitQueue {
    crate::sync::waitqueue::var_waitqueue(inode.state_addr())
}

/// Writeback of `inode` is done: I_SYNC cleared and its waiters woken
/// (Linux inode_sync_complete), under its `i_lock` (`il`)
fn inode_sync_complete(inode: &Inode, il: &ILocked) {
    inode.clear_state(il, I_SYNC);
    // Under i_lock, which the waiters test I_SYNC under (Linux)
    sync_waitqueue(inode).wake_all();
}

/// Wait until `inode` is not under writeback (Linux
/// inode_wait_for_writeback): its `i_lock` (`l`) is held, dropped while
/// asleep and held again on return. The caller keeps the inode live.
pub(in crate::fs) fn inode_wait_for_writeback<'a>(
    inode: &'a Inode,
    mut l: MutexGuard<'a, ILocked>,
) -> MutexGuard<'a, ILocked> {
    use crate::sync::waitqueue::WaitEntry;
    inode.assert_locked(&l);
    if inode.state() & I_SYNC == 0 {
        return l;
    }
    let q = sync_waitqueue(inode);
    let w = core::pin::pin!(WaitEntry::new());
    loop {
        q.prepare_to_wait(w.as_ref(), crate::task::percpu::SleepState::Uninterruptible);
        if inode.state() & I_SYNC == 0 {
            break;
        }
        drop(l);
        crate::task::percpu::schedule();
        l = inode.i_lock.lock();
    }
    q.finish_wait(w.as_ref());
    l
}

/// Sleep until I_SYNC is cleared, once, for a caller holding no
/// reference (Linux inode_sleep_on_writeback): its `i_lock` (`l`) is
/// dropped here, after which the inode may go
fn inode_sleep_on_writeback(inode: &Inode, l: MutexGuard<'_, ILocked>) {
    use crate::sync::waitqueue::WaitEntry;
    inode.assert_locked(&l);
    let q = sync_waitqueue(inode);
    let w = core::pin::pin!(WaitEntry::new());
    q.prepare_to_wait(w.as_ref(), crate::task::percpu::SleepState::Uninterruptible);
    let sleep = inode.state() & I_SYNC != 0;
    drop(l);
    if sleep {
        crate::task::percpu::schedule();
    }
    q.finish_wait(w.as_ref());
}

/// Write back one inode's dirty pages (for the dirty limits: Linux
/// balance_dirty_pages writes pages only). Its dirty state stays: the
/// next pass finds the pages clean.
pub fn writeback_inode(inode: &Inode) -> Result<(), KernelError> {
    crate::mm::filemap::write_and_wait(inode)
}

/// Its pages (Linux do_writepages): none for a metadata-only write. hk's
/// page writeback is synchronous: written is waited for.
fn do_writepages(inode: &Inode, wbc: &WritebackControl) -> Result<(), KernelError> {
    if wbc.nr_to_write <= 0 {
        return Ok(());
    }
    crate::mm::filemap::write_and_wait(inode)
}

/// Its filesystem's ->write_inode (Linux write_inode)
fn write_inode(inode: &Inode, wbc: &WritebackControl) -> Result<(), KernelError> {
    match inode.superblock() {
        Some(sb) => sb.s_op.write_inode(inode, wbc),
        None => Ok(()),
    }
}

/// `inode`'s ->write_inode put metadata in flight for a later
/// data-integrity write to wait for (Linux set_inode_metadata_writeback)
pub fn set_inode_metadata_writeback(inode: &Inode) {
    let l = inode.i_lock.lock();
    inode.set_state(&l, I_METADATA_WRITEBACK);
}

/// Write one inode under I_SYNC (Linux __writeback_single_inode): its
/// pages, then its dirty bits are taken under `i_lock` (I_DIRTY_PAGES
/// set again if a page is still dirty) and its metadata written if any
/// but the pages' were set; a change meanwhile marks it again. A failed
/// write leaves it clean, as Linux. A data-integrity write other than
/// sync(2)'s (which syncs the device after) then waits for metadata in
/// flight (I_METADATA_WRITEBACK: ->sync_inode_metadata). The first
/// error is returned after all were tried. List handling is the
/// caller's.
fn __writeback_single_inode(inode: &Inode, wbc: &WritebackControl) -> Result<(), KernelError> {
    debug_assert!(inode.state() & I_SYNC != 0);
    // WB_SYNC_ALL's filemap_fdatawait: written is waited for here
    let mut r = do_writepages(inode, wbc);
    let dirty = {
        let l = inode.i_lock.lock();
        let dirty = inode.state() & I_DIRTY;
        inode.clear_state(&l, dirty);
        // Linux smp_mb, paired with __mark_inode_dirty's: either it
        // sees I_DIRTY_PAGES cleared or this sees the DIRTY mark
        fence(Ordering::SeqCst);
        if mapping_tagged(inode, MARK_DIRTY) {
            inode.set_state(&l, I_DIRTY_PAGES);
        }
        dirty
    };
    // Not for the pages alone
    if dirty & !I_DIRTY_PAGES != 0 {
        r = r.and(write_inode(inode, wbc));
    }
    if wbc.sync_mode == SyncMode::All && !wbc.for_sync && inode.state() & I_METADATA_WRITEBACK != 0
    {
        {
            let l = inode.i_lock.lock();
            inode.clear_state(&l, I_METADATA_WRITEBACK);
        }
        if let Some(sb) = inode.superblock() {
            r = r.and(sb.s_op.sync_inode_metadata(inode, wbc));
        }
    }
    r
}

/// Write one inode on demand, outside the passes (Linux
/// writeback_single_inode): a writer already at it (I_SYNC) is enough
/// for WB_SYNC_NONE and waited for with WB_SYNC_ALL; a clean inode is
/// left, unless WB_SYNC_ALL finds pages or metadata still under
/// writeback (from a WB_SYNC_NONE write) to wait for. Written
/// under I_SYNC, then off the lists if it is clean now, else back on
/// `b_dirty` unless a pass has it. The caller holds a reference, or it
/// is I_WILL_FREE (the write-back before its eviction).
fn writeback_single_inode(inode: &Inode, wbc: &WritebackControl) -> Result<(), KernelError> {
    let all = wbc.sync_mode == SyncMode::All;
    let mut l = inode.i_lock.lock();
    if inode.state() & I_SYNC != 0 {
        if !all {
            return Ok(());
        }
        l = inode_wait_for_writeback(inode, l);
    }
    if inode.state() & I_DIRTY_ALL == 0
        && (!all
            || (!mapping_tagged(inode, MARK_WRITEBACK)
                && inode.state() & I_METADATA_WRITEBACK == 0))
    {
        return Ok(());
    }
    inode.set_state(&l, I_SYNC);
    drop(l);
    let r = __writeback_single_inode(inode, wbc);
    // Linux inode_to_wb_and_lock_list
    let mut lists = inode.i_wb.get().map(|wb| wb.list_lock.lock());
    let l = inode.i_lock.lock();
    if let Some(lists) = &mut lists
        && inode.state() & I_FREEING == 0
    {
        let st = inode.state();
        if st & I_DIRTY_ALL == 0 {
            move_to_attached(lists, inode, &l);
        } else if st & I_SYNC_QUEUED == 0 {
            // SAFETY: not I_FREEING under `i_lock`, `list_lock` held
            unsafe { redirty_tail_locked(lists, inode, &l) };
        }
    }
    drop(lists);
    inode_sync_complete(inode, &l);
    r
}

/// Write back one inode whole (Linux write_inode_now): its dirty pages,
/// then its metadata; with `sync` a data-integrity write (WB_SYNC_ALL),
/// waiting for a writer already at it and for the metadata. The first
/// error is returned after both were tried. The caller holds a
/// reference, or it is I_WILL_FREE.
pub fn write_inode_now(inode: &Inode, sync: bool) -> Result<(), KernelError> {
    let can = inode.i_data.aops().can_dirty();
    let mode = if sync { SyncMode::All } else { SyncMode::None };
    let wbc = WritebackControl::new(mode, if can { i64::MAX } else { 0 });
    crate::sync::might_sleep();
    writeback_single_inode(inode, &wbc)
}

/// Write `inode`'s metadata if it is dirty, no pages (Linux
/// sync_inode_metadata); with `wait` a data-integrity write, waiting
/// for it to reach the disk (its filesystem's ->sync_inode_metadata)
pub fn sync_inode_metadata(inode: &Inode, wait: bool) -> Result<(), KernelError> {
    let mode = if wait { SyncMode::All } else { SyncMode::None };
    let wbc = WritebackControl::new(mode, 0);
    writeback_single_inode(inode, &wbc)
}

/// It went dirty at or before `cutoff` (monotonic ns)
fn expired(inode: &Inode, cutoff: u64) -> bool {
    inode.dirtied_when.load(Ordering::Relaxed) <= cutoff
}

/// Queue the inodes to write (Linux queue_io): those a previous pass
/// left on `b_more_io` first, then the ones dirtied at or before
/// `cutoff` (of `sb` only, if given: Linux writeback_sb_inodes skips
/// the others) in `b_dirty` order, each marked I_SYNC_QUEUED (Linux
/// move_expired_inodes)
fn queue_io(l: &mut WbLists, cutoff: u64, sb: Option<&SuperBlock>) {
    l.b_more_io.move_if(&mut l.b_io, |i| {
        i.i_io_on.store(ON_IO, Ordering::Relaxed);
        true
    });
    l.b_dirty.move_if(&mut l.b_io, |i| {
        let take = expired(i, cutoff) && sb.is_none_or(|s| core::ptr::eq(i.sb.as_ptr(), s));
        if take {
            let il = i.i_lock.lock();
            i.set_state(&il, I_SYNC_QUEUED);
            i.i_io_on.store(ON_IO, Ordering::Relaxed);
        }
        take
    });
}

/// Requeue `inode` by its state after a pass wrote it (Linux
/// requeue_inode): a data-integrity pass restamps one still dirty so
/// it is not taken again (livelock); dirty again: `b_dirty`'s tail;
/// clean: off the lists. Under `list_lock` (`l`) and its `i_lock`
/// (`il`); the pass holds a reference.
fn requeue_inode(l: &mut WbLists, inode: &Inode, il: &ILocked, wbc: &WritebackControl) {
    if inode.state() & I_FREEING != 0 {
        return;
    }
    if inode.state() & I_DIRTY != 0 && (wbc.sync_mode == SyncMode::All || wbc.tagged_writepages) {
        inode
            .dirtied_when
            .store(crate::time::monotonic_ns(), Ordering::Relaxed);
    }
    // A page still dirty was dirtied again (hk writes an inode whole:
    // never a used-up slice for b_more_io)
    if mapping_tagged(inode, MARK_DIRTY) || inode.state() & I_DIRTY != 0 {
        // SAFETY: the pass's reference
        unsafe { redirty_tail_locked(l, inode, il) };
    } else {
        move_to_attached(l, inode, il);
    }
}

/// What a pass does with the front of `b_io`
enum Next {
    Done,
    /// Requeued or skipped under the locks
    Again,
    /// Being written by another, for a data-integrity pass: slept on
    Waited,
    Write(InodeRef),
}

/// Take the next inode off `b_io` for `wbc`'s pass over `sb` (Linux
/// writeback_sb_inodes' checks): one of another superblock goes back
/// to `b_dirty` if the pass is for `sb` only (`only`), else ends this
/// superblock's part of the pass (Linux: back to the caller, to pin the
/// next superblock); one being freed goes back to `b_dirty` (its
/// teardown writes it); one another writer has (I_SYNC) goes to
/// `b_more_io`, or is waited for by a data-integrity pass; else it is
/// marked I_SYNC and referenced (hk pins it so; Linux by I_SYNC, which
/// evict waits for)
fn next_inode(wb: &BdiWriteback, wbc: &WritebackControl, sb: &SuperBlock, only: bool) -> Next {
    let mut lists = wb.list_lock.lock();
    let l = &mut *lists;
    let Some(w) = l.b_io.front() else {
        return Next::Done;
    };
    // SAFETY: linked, so live while `list_lock` is held, and after it
    // is dropped while its `i_lock` is: its eviction takes it off the
    // list under `list_lock` then `i_lock` before any field goes. The
    // borrow is detached from the list's so the list can be changed.
    let w: &Inode = unsafe { &*core::ptr::from_ref(w) };
    let other = !core::ptr::eq(w.sb.as_ptr(), sb);
    if other && !only {
        return Next::Done;
    }
    let il = w.i_lock.lock();
    if other || w.state() & (I_FREEING | I_WILL_FREE) != 0 {
        // SAFETY: under both locks; I_FREEING is dropped off the lists
        unsafe { redirty_tail_locked(l, w, &il) };
        return Next::Again;
    }
    if w.state() & I_SYNC != 0 {
        if wbc.sync_mode != SyncMode::All {
            // Linux requeue_io
            // SAFETY: not I_FREEING under `i_lock`, `list_lock` held
            unsafe { io_list_move_locked(l, w, &il, ON_MORE_IO) };
            return Next::Again;
        }
        drop(lists);
        inode_sleep_on_writeback(w, il);
        return Next::Waited;
    }
    w.set_state(&il, I_SYNC);
    Next::Write(w.__iget(&il))
}

/// Write the inodes of `sb` at the front of `b_io` one at a time, each
/// requeued by its state after (Linux writeback_sb_inodes), until
/// `b_io` is empty or, unless the pass is for `sb` only (`only`),
/// begins with another superblock's inode. The caller holds `sb`'s
/// s_umount (Linux: for reading, or the pass's own caller's). Write
/// errors are the mappings' (Linux: recorded by mapping_set_error for
/// fsync and syncfs to report).
fn writeback_sb_inodes(wb: &BdiWriteback, wbc: &WritebackControl, sb: &SuperBlock, only: bool) {
    loop {
        let inode = match next_inode(wb, wbc, sb, only) {
            Next::Done => break,
            Next::Again | Next::Waited => continue,
            Next::Write(i) => i,
        };
        let _ = __writeback_single_inode(&inode, wbc);
        {
            let mut lists = wb.list_lock.lock();
            let il = inode.i_lock.lock();
            requeue_inode(&mut lists, &inode, &il, wbc);
            inode_sync_complete(&inode, &il);
        }
        // Its last reference may go here, with no lock held
        drop(inode);
    }
}

/// Write `b_io` superblock by superblock (Linux __writeback_inodes_wb):
/// the front inode's superblock is pinned with s_umount for reading
/// (`super_trylock_shared`, taken under `list_lock` as Linux), its
/// inodes written, then released; one whose s_umount is not free at
/// once, or that is not set up or is being shut down, has the inode
/// sent back to `b_dirty` (Linux redirty_tail: no busy retry), so no
/// pass writes an inode of a superblock a shutdown or remount holds
fn __writeback_inodes_wb(wb: &BdiWriteback, wbc: &WritebackControl) {
    loop {
        let mut lists = wb.list_lock.lock();
        let Some(w) = lists.b_io.front() else {
            return;
        };
        // SAFETY: linked, so live while `list_lock` is held (the lists'
        // contract); detached from the list's borrow so it can change
        let w: &Inode = unsafe { &*core::ptr::from_ref(w) };
        // A passive reference, dropped with `list_lock` released
        let sb = w.superblock();
        let g = sb.as_deref().and_then(super_trylock_shared);
        let Some(g) = g else {
            let il = w.i_lock.lock();
            // SAFETY: under both locks, linked (see above)
            unsafe { redirty_tail_locked(&mut lists, w, &il) };
            drop(il);
            // `sb` goes after, at the iteration's end
            drop(lists);
            continue;
        };
        drop(lists);
        if let Some(sb) = &sb {
            writeback_sb_inodes(wb, wbc, sb, false);
        }
        drop(g);
    }
}

/// One pass over `wb` (Linux wb_writeback): the inodes dirtied at or
/// before `cutoff` (of `sb` only, if given) are queued on `b_io` and
/// written, those of `sb` under its caller's s_umount, the others
/// superblock by superblock (`__writeback_inodes_wb`)
fn wb_writeback(wb: &BdiWriteback, wbc: &WritebackControl, cutoff: u64, sb: Option<&SuperBlock>) {
    let _pass = wb.pass.lock();
    queue_io(&mut wb.list_lock.lock(), cutoff, sb);
    match sb {
        Some(sb) => writeback_sb_inodes(wb, wbc, sb, true),
        None => __writeback_inodes_wb(wb, wbc),
    }
}

/// Start writeback of every dirty inode of `sb` (Linux
/// writeback_inodes_sb: WB_SYNC_NONE, tag-and-write, those dirtied
/// before now); for sync_filesystem, under s_umount
pub fn writeback_inodes_sb(sb: &SuperBlock) {
    let Some(b) = sb.bdev() else {
        return;
    };
    let wbc = WritebackControl {
        tagged_writepages: true,
        ..WritebackControl::new(SyncMode::None, i64::MAX)
    };
    wb_writeback(&b.disk.bdi, &wbc, crate::time::monotonic_ns(), Some(sb));
}

/// Write every dirty inode of `sb` and wait (Linux sync_inodes_sb:
/// WB_SYNC_ALL for sync, those dirtied before now; the metadata's wait
/// is the caller's sync of the device); nothing for a filesystem with
/// no device (Linux noop_backing_dev_info). Write errors are the
/// mappings'.
pub fn sync_inodes_sb(sb: &SuperBlock) {
    let Some(b) = sb.bdev() else {
        return;
    };
    let wbc = WritebackControl {
        for_sync: true,
        ..WritebackControl::new(SyncMode::All, i64::MAX)
    };
    wb_writeback(&b.disk.bdi, &wbc, crate::time::monotonic_ns(), Some(sb));
}

/// sync(2)'s inode part (Linux ksys_sync: iterate_supers of
/// sync_inodes_one_sb): every writable filesystem's inodes written and
/// waited for; the block devices follow. Linux first wakes the flusher
/// threads to start every device at once; hk writes each in turn.
pub fn sync_all_sbs() {
    iterate_supers(|sb| {
        if !sb.rdonly() {
            sync_inodes_sb(sb);
        }
    });
}

/// The periodic writeback of `wb` (Linux wb_workfn -> wb_do_writeback,
/// WB_SYNC_NONE): what became dirty at or before `cutoff` (kupdate:
/// older than vm.dirty_expire_centisecs; background writeback passes
/// `u64::MAX`), filesystems' inodes and the device's own cache alike.
/// True if dirty inodes are left for a later pass (Linux
/// wb_has_dirty_io)
pub fn wb_do_writeback(wb: &BdiWriteback, cutoff: u64) -> bool {
    let wbc = WritebackControl::new(SyncMode::None, i64::MAX);
    wb_writeback(wb, &wbc, cutoff, None);
    has_dirty_io(&wb.list_lock.lock())
}
