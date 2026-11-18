//! Buffer heads (Linux fs/buffer.c, include/linux/buffer_head.h)
//!
//! A buffer head maps one block of a page-cache page: its block number
//! on a device, its size and its place in the page, and its state bits
//! (uptodate, dirty, locked, mapped, ...). A page's buffers form a ring
//! through `b_this_page`, hung on the page's private word (PG_private,
//! holding a page reference: `filemap::folio_attach_private`). The
//! block device's own cache (`BlockDevice.bd_inode`, Linux bd_mapping)
//! keeps its blocks in buffers (`bdev_getblk`, `__bread_gfp`), and a
//! mapping whose filesystem has a `GetBlock` reads, writes and dirties
//! its pages block by block (`block_read_full_folio`,
//! `block_write_full_folio`, `block_write_begin`, `block_dirty_folio`):
//! writeback writes only the dirty buffers.
//!
//! Lifetime: buffers are made with their page's ring (`folio_alloc_buffers`,
//! boxes served by their own slab cache, `mm::slab::BH_CACHE`)
//! and freed with it by `try_to_free_buffers` alone, when none is busy
//! (referenced, dirty or locked), under the page lock and the mapping's
//! `i_private_lock`. So whoever holds the page lock, `i_private_lock`,
//! or a reference on any buffer of the ring ([`BhRef`], Linux
//! get_bh/brelse) may walk the ring; a live buffer's page is held by
//! the ring's page reference, so its data stays allocated.
//!
//! Locking (doc/LOCKING.md 3.2 Per-inode page cache, Buffer heads):
//! - page lock -> `AddressSpace.i_private_lock` (spin, Linux
//!   mapping->i_private_lock) -> `i_pages`; `i_private_lock` ->
//!   `MappingMetadataBhs.lock`. `i_private_lock` keeps a page's ring
//!   from being attached or freed and its dirty bits coherent with the
//!   page's (block_dirty_folio, try_to_free_buffers).
//! - the buffer lock (BH_Lock, a sleeping bit lock over `var_waitqueue`,
//!   Linux wait_on_bit_lock_io): held across a buffer's I/O, taken under
//!   the page lock, never under a spin lock.
//! - `b_uptodate_lock` of a ring's first buffer (`IrqSpinlock` leaf,
//!   Linux b_uptodate_lock): serializes the ends of a page's async
//!   reads and writes, which run in the bio's completion (hardirq).
//! - the per-CPU LRU of looked-up buffers (`IrqSpinlock` leaf per CPU,
//!   Linux bh_lrus under local_irq_disable): emptied on every CPU by
//!   `invalidate_bh_lrus` through a cross-CPU call, as Linux.
//!
//! A bio's completion (`bh_end_*`, hardirq) touches only the buffer's
//! bits, its ring's `b_uptodate_lock`, the page's flags and wait
//! queues, and the mapping's writeback error (`mark_buffer_write_io_error`
//! under an RCU read guard: mappings live in inodes, freed a grace
//! period after their teardown).
//!
//! Not here (no user): BH_Delay, BH_Unwritten, BH_Boundary, BH_Meta,
//! BH_Prio, BH_Quiet and BH_Defer_Completion (no delayed-allocation,
//! journaling or verity filesystem), b_private, iomap_to_bh, page
//! migration (BH_Migrate) and buffer_heads_over_limit (no reclaim of
//! buffers by count).

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::ptr::{NonNull, null_mut};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering, fence};

use crate::block::blkdev::{Bio, BioOp, BlockDevice, SECTOR_SHIFT, bio_io_error, submit_bio};
use crate::fs::inode::Inode;
use crate::fs::superblock::SuperBlock;
use crate::mm::filemap::{self, AddressSpace, PAGE_SIZE};
use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::{page_wait_queue, var_waitqueue};
use crate::util::error::KernelError;

// ============================================================================
// State bits (Linux enum bh_state_bits)
// ============================================================================

/// Contains valid data
pub const BH_UPTODATE: u32 = 1 << 0;
/// Is dirty
pub const BH_DIRTY: u32 = 1 << 1;
/// Is locked
pub const BH_LOCK: u32 = 1 << 2;
/// Has been submitted for I/O
pub const BH_REQ: u32 = 1 << 3;
/// Has a disk mapping
pub const BH_MAPPED: u32 = 1 << 4;
/// Disk mapping was newly created by get_block
pub const BH_NEW: u32 = 1 << 5;
/// Is under end_buffer_async_read I/O
const BH_ASYNC_READ: u32 = 1 << 6;
/// Is under end_buffer_async_write I/O
const BH_ASYNC_WRITE: u32 = 1 << 7;
/// I/O error on write
pub const BH_WRITE_EIO: u32 = 1 << 8;

/// Buffers a page holds at most (Linux MAX_BUF_PER_PAGE)
const MAX_BUF_PER_PAGE: usize = PAGE_SIZE / 512;

/// The block mapping of a filesystem (Linux get_block_t): map block
/// `iblock` of `inode` into `bh` (b_bdev, b_blocknr, BH_Mapped), with
/// `create` allocating it (and setting BH_New) if it has none
pub type GetBlock =
    fn(inode: &Inode, iblock: u64, bh: &BufferHead, create: bool) -> Result<(), KernelError>;

// ============================================================================
// struct buffer_head
// ============================================================================

/// One block of a page-cache page (Linux struct buffer_head)
///
/// # Invariants
/// - Alive from `folio_alloc_buffers` to `free_buffer_head`, which only
///   `try_to_free_buffers` (no buffer of the ring busy, page lock and
///   `i_private_lock` held, ring detached) and the unwinding of a ring
///   never attached call.
/// - `b_this_page` links the ring of its page; set before the ring is
///   attached, fixed until it is freed.
/// - `b_folio`, `b_size` and `b_data` are fixed; while alive, its page
///   is held by the ring's page reference.
/// - `b_bdev` is null or a `Weak<BlockDevice>` from `Weak::into_raw`,
///   owned by the buffer. It changes only while BH_Mapped is clear
///   (under the page lock) or under the buffer lock (`discard_buffer`),
///   so a locked, mapped buffer's `b_bdev` is stable.
pub struct BufferHead {
    /// BH_* bits (Linux b_state)
    b_state: AtomicU32,
    /// Users (Linux b_count): `BhRef`s, the LRU's
    b_count: AtomicU32,
    /// Next buffer of the page (Linux b_this_page)
    b_this_page: AtomicPtr<BufferHead>,
    /// The page (physical address; Linux b_folio)
    b_folio: u64,
    /// Start block number, in units of `b_size` (Linux b_blocknr)
    b_blocknr: AtomicU64,
    /// Size of the mapping (Linux b_size)
    b_size: u32,
    /// Offset of the data in the page (Linux b_data - folio address)
    b_data: u32,
    /// The device (Linux b_bdev), a `Weak` (see Invariants)
    b_bdev: AtomicPtr<BlockDevice>,
    /// Link on a `MappingMetadataBhs` list (Linux b_assoc_buffers)
    b_assoc_buffers: AssocLink,
    /// The list it is on, or null (Linux b_mmb)
    b_mmb: AtomicPtr<MappingMetadataBhs>,
    /// Serializes async I/O completion of the page's buffers; the
    /// first buffer's is used (Linux b_uptodate_lock)
    b_uptodate_lock: IrqSpinlock<()>,
}

impl BufferHead {
    fn new(folio: u64, offset: usize, size: usize) -> Self {
        Self {
            b_state: AtomicU32::new(0),
            b_count: AtomicU32::new(0),
            b_this_page: AtomicPtr::new(null_mut()),
            b_folio: folio,
            b_blocknr: AtomicU64::new(u64::MAX),
            b_size: size as u32,
            b_data: offset as u32,
            b_bdev: AtomicPtr::new(null_mut()),
            b_assoc_buffers: AssocLink::new(),
            b_mmb: AtomicPtr::new(null_mut()),
            b_uptodate_lock: IrqSpinlock::new(()),
        }
    }

    #[inline]
    fn test(&self, bit: u32) -> bool {
        self.b_state.load(Ordering::Relaxed) & bit != 0
    }

    /// Set `bit` if clear (Linux set_buffer_*: no cache-line write when
    /// it is already set)
    #[inline]
    fn set(&self, bit: u32) {
        if !self.test(bit) {
            self.b_state.fetch_or(bit, Ordering::Relaxed);
        }
    }

    #[inline]
    fn clear(&self, bit: u32) {
        self.b_state.fetch_and(!bit, Ordering::Relaxed);
    }

    #[inline]
    fn test_set(&self, bit: u32) -> bool {
        self.b_state.fetch_or(bit, Ordering::AcqRel) & bit != 0
    }

    #[inline]
    fn test_clear(&self, bit: u32) -> bool {
        self.b_state.fetch_and(!bit, Ordering::AcqRel) & bit != 0
    }

    /// Its data is valid (Linux buffer_uptodate: smp_load_acquire)
    pub fn uptodate(&self) -> bool {
        self.b_state.load(Ordering::Acquire) & BH_UPTODATE != 0
    }

    /// Linux set_buffer_uptodate: the data is published before the bit
    pub fn set_uptodate(&self) {
        if !self.test(BH_UPTODATE) {
            self.b_state.fetch_or(BH_UPTODATE, Ordering::Release);
        }
    }

    pub fn clear_uptodate(&self) {
        self.clear(BH_UPTODATE);
    }

    pub fn dirty(&self) -> bool {
        self.test(BH_DIRTY)
    }

    pub fn clear_dirty(&self) {
        self.clear(BH_DIRTY);
    }

    pub fn locked(&self) -> bool {
        self.b_state.load(Ordering::Acquire) & BH_LOCK != 0
    }

    pub fn mapped(&self) -> bool {
        self.test(BH_MAPPED)
    }

    pub fn set_mapped(&self) {
        self.set(BH_MAPPED);
    }

    pub fn new_block(&self) -> bool {
        self.test(BH_NEW)
    }

    pub fn set_new(&self) {
        self.set(BH_NEW);
    }

    pub fn req(&self) -> bool {
        self.test(BH_REQ)
    }

    pub fn write_io_error(&self) -> bool {
        self.test(BH_WRITE_EIO)
    }

    /// Start block number (Linux b_blocknr)
    pub fn blocknr(&self) -> u64 {
        self.b_blocknr.load(Ordering::Relaxed)
    }

    /// Set the block number (get_block, under the page lock)
    pub fn set_blocknr(&self, block: u64) {
        self.b_blocknr.store(block, Ordering::Relaxed);
    }

    /// Size in bytes (Linux b_size)
    pub fn size(&self) -> usize {
        self.b_size as usize
    }

    /// Offset of its data in its page (Linux bh_offset)
    pub fn offset(&self) -> usize {
        self.b_data as usize
    }

    /// Its page's physical address (Linux b_folio)
    pub fn folio(&self) -> u64 {
        self.b_folio
    }

    /// The next buffer of its page (Linux b_this_page)
    fn next(&self) -> &BufferHead {
        let p = self.b_this_page.load(Ordering::Relaxed);
        // SAFETY: a live buffer's `b_this_page` is a buffer of the same
        // ring (type invariant), freed only with this one, so alive as
        // long as `self` is borrowed
        unsafe { &*p }
    }

    /// Set the device (get_block, while unmapped under the page lock;
    /// Linux bh->b_bdev = bdev)
    pub fn set_bdev(&self, bdev: &Arc<BlockDevice>) {
        let new = Weak::into_raw(Arc::downgrade(bdev)).cast_mut();
        put_bdev(self.b_bdev.swap(new, Ordering::AcqRel));
    }

    /// Its device, if set and still there
    fn bdev(&self) -> Option<Arc<BlockDevice>> {
        let p = self.b_bdev.load(Ordering::Acquire);
        if p.is_null() {
            return None;
        }
        // SAFETY: non-null `b_bdev` is a Weak owned by the buffer, stable
        // for a locked, mapped buffer (type invariant: the callers'
        // case); borrowed, not consumed
        let w = core::mem::ManuallyDrop::new(unsafe { Weak::from_raw(p) });
        w.upgrade()
    }

    /// Its device is `bdev` (an identity test: the Weak keeps the
    /// allocation, so the address is never another device's)
    fn on_bdev(&self, bdev: &BlockDevice) -> bool {
        core::ptr::eq(self.b_bdev.load(Ordering::Relaxed), bdev)
    }

    /// Copy `dst.len()` bytes of its data from byte `off` (racing
    /// writers, a mapping of the page, give torn bytes, as Linux)
    pub fn read_data(&self, off: usize, dst: &mut [u8]) {
        assert!(off.checked_add(dst.len()).is_some_and(|e| e <= self.size()));
        // SAFETY: the page is held by the ring (type invariant) while
        // the buffer lives; the range lies in the buffer, inside the page
        unsafe { crate::mm::page::copy_from_frame_racy(dst, self.b_folio, self.offset() + off) };
    }

    /// Copy `src` into its data at byte `off`
    pub fn write_data(&self, off: usize, src: &[u8]) {
        assert!(off.checked_add(src.len()).is_some_and(|e| e <= self.size()));
        // SAFETY: as `read_data`; page-cache data, not kernel memory
        unsafe { crate::mm::page::copy_to_frame_racy(self.b_folio, self.offset() + off, src) };
    }
}

/// Release a `b_bdev` Weak taken off a buffer
fn put_bdev(p: *mut BlockDevice) {
    if !p.is_null() {
        // SAFETY: `b_bdev`'s values are Weaks from `Weak::into_raw`
        // owned by the buffer (type invariant), handed over by the swap
        drop(unsafe { Weak::from_raw(p.cast_const()) });
    }
}

/// Zero `len` bytes of page `phys` at `off`, which a mapping may access
/// meanwhile (Linux folio_zero_range)
fn zero_frame(phys: u64, off: usize, len: usize) {
    const Z: [u8; 64] = [0; 64];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(Z.len());
        // SAFETY: a page-cache page the caller holds (locked or under
        // its locked buffer's I/O); the range lies in it
        unsafe { crate::mm::page::copy_to_frame_racy(phys, off + done, &Z[..n]) };
        done += n;
    }
}

/// The buffers of page `phys` (Linux folio_buffers)
///
/// # Safety
/// The caller holds the page lock, the mapping's `i_private_lock`, or a
/// reference on a buffer of the page, for `'a`.
unsafe fn folio_buffers<'a>(phys: u64) -> Option<&'a BufferHead> {
    let p = filemap::folio_private(phys)? as *const BufferHead;
    // SAFETY: a page's private word holds the head of its ring (only
    // this module attaches one), freed only under both the page lock
    // and `i_private_lock` with no buffer referenced, which the caller
    // excludes
    Some(unsafe { &*p })
}

/// The buffers of a ring, from `head` around
fn ring(head: &BufferHead) -> impl Iterator<Item = &BufferHead> {
    let mut cur = Some(head);
    core::iter::from_fn(move || {
        let bh = cur?;
        let n = bh.next();
        cur = (!core::ptr::eq(n, head)).then_some(n);
        Some(bh)
    })
}

// ============================================================================
// References (Linux get_bh, brelse)
// ============================================================================

/// A counted reference on a buffer (Linux get_bh ... brelse): the
/// buffer, its ring and its page's data stay while it is held
#[must_use]
pub struct BhRef(NonNull<BufferHead>);

// SAFETY: the buffer is all atomics and locks (Sync); the reference
// only counts it, from any thread (Linux get_bh/put_bh are atomic)
unsafe impl Send for BhRef {}
// SAFETY: as above: `&BhRef` hands out `&BufferHead` only
unsafe impl Sync for BhRef {}

impl core::ops::Deref for BhRef {
    type Target = BufferHead;
    fn deref(&self) -> &BufferHead {
        // SAFETY: the count this reference holds keeps the buffer alive
        // (type invariant of `BufferHead`: busy buffers are never freed)
        unsafe { self.0.as_ref() }
    }
}

impl Clone for BhRef {
    fn clone(&self) -> Self {
        get_bh(self)
    }
}

impl Drop for BhRef {
    /// Linux brelse / __brelse / put_bh
    fn drop(&mut self) {
        let old = self.b_count.fetch_sub(1, Ordering::Release);
        debug_assert!(old != 0, "VFS: brelse: Trying to free free buffer");
    }
}

impl BhRef {
    /// A reference over a count already taken (the LRU's)
    ///
    /// # Safety
    /// `p` is a live buffer whose count includes one this reference now
    /// owns, handed over once.
    unsafe fn from_raw(p: *const BufferHead) -> Self {
        // SAFETY: a live buffer: non-null
        Self(unsafe { NonNull::new_unchecked(p.cast_mut()) })
    }
}

/// Take a reference (Linux get_bh): `bh` is borrowed under what keeps
/// it alive (page lock, `i_private_lock`, a reference), which the count
/// then replaces
pub fn get_bh(bh: &BufferHead) -> BhRef {
    bh.b_count.fetch_add(1, Ordering::Relaxed);
    BhRef(NonNull::from(bh))
}

/// Discard its dirty data and release it (Linux bforget / __bforget)
pub fn bforget(bh: BhRef) {
    bh.clear_dirty();
    remove_assoc_queue(&bh);
    drop(bh);
}

/// Busy: referenced, dirty or locked (Linux buffer_busy)
fn buffer_busy(bh: &BufferHead) -> bool {
    bh.b_count.load(Ordering::Acquire) != 0
        || bh.b_state.load(Ordering::Acquire) & (BH_DIRTY | BH_LOCK) != 0
}

// ============================================================================
// Buffer lock (Linux lock_buffer, unlock_buffer, wait_on_buffer)
// ============================================================================

/// The wait queue of a buffer's lock bit (Linux bit_waitqueue)
fn bh_waitqueue(bh: &BufferHead) -> &'static crate::sync::waitqueue::WaitQueue {
    var_waitqueue(core::ptr::from_ref(&bh.b_state).addr())
}

/// Lock the buffer if free (Linux trylock_buffer)
pub fn trylock_buffer(bh: &BufferHead) -> bool {
    bh.b_state.fetch_or(BH_LOCK, Ordering::Acquire) & BH_LOCK == 0
}

/// Lock the buffer, sleeping while another holds it (Linux
/// lock_buffer): thread context, no spin lock held
pub fn lock_buffer(bh: &BufferHead) {
    crate::sync::might_sleep();
    while !trylock_buffer(bh) {
        bh_waitqueue(bh).wait_event(|| !bh.locked());
    }
}

/// Unlock the buffer and wake its waiters (Linux unlock_buffer:
/// clear_and_wake_up_bit). Any context; nothing of the buffer is
/// touched after the bit clears (an unlocked, unreferenced buffer may
/// be freed at once)
pub fn unlock_buffer(bh: &BufferHead) {
    let q = bh_waitqueue(bh);
    bh.b_state.fetch_and(!BH_LOCK, Ordering::Release);
    fence(Ordering::SeqCst);
    q.wake_all();
}

/// Wait until the buffer is unlocked (Linux wait_on_buffer)
pub fn wait_on_buffer(bh: &BufferHead) {
    crate::sync::might_sleep();
    if bh.locked() {
        bh_waitqueue(bh).wait_event(|| !bh.locked());
    }
}

// ============================================================================
// Page flags of a buffered folio (Linux folio_end_read, writeback)
// ============================================================================

/// The read of the locked page `phys` ended (Linux folio_end_read):
/// uptodate if it worked, then unlocked. Any context; the page is not
/// touched after
fn folio_end_read(phys: u64, uptodate: bool) {
    if uptodate {
        filemap::set_uptodate(phys);
    }
    crate::mm::page::unlock_page(phys);
}

/// The locked page `phys` goes under writeback (Linux
/// folio_start_writeback)
fn folio_start_writeback(phys: u64) {
    filemap::set_writeback(phys, true);
}

/// Its writeback ended (Linux folio_end_writeback): any context; the
/// page is not touched after the flag clears
fn folio_end_writeback(phys: u64) {
    let q = page_wait_queue(phys);
    filemap::set_writeback(phys, false);
    fence(Ordering::SeqCst);
    q.wake_all();
}

/// Wait for its writeback to end (Linux folio_wait_writeback)
fn folio_wait_writeback(phys: u64) {
    page_wait_queue(phys).wait_event(|| !filemap::writeback(phys));
}

// ============================================================================
// Bio submission and completion (Linux bh_submit, bh_end_*)
// ============================================================================

/// What a buffer's bio ends with: called in its completion (hardirq)
type BhEndIo = fn(Box<Bio>);

/// Cut a bio that runs past the end of its device to the device's end
/// (Linux guard_bio_eod, bio_truncate): a read's part past it zeroed
fn guard_bio_eod(bdev: &BlockDevice, bio: &mut Bio) {
    let max = bdev.nr_sects();
    if max == 0 || bio.sector >= max {
        return;
    }
    let left = max - bio.sector;
    if (bio.size() as u64 >> SECTOR_SHIFT) <= left {
        return;
    }
    let keep = (left << SECTOR_SHIFT) as usize;
    let seg = &mut bio.segs[0];
    if bio.op == BioOp::Read {
        zero_frame(seg.frame, seg.offset + keep, seg.len - keep);
    }
    seg.len = keep;
}

/// Start I/O on the locked, mapped buffer (Linux __bh_submit): its
/// block in one bio, `end_io` called in the completion. The device is
/// the caller's to keep until then (a mounted filesystem's, or one the
/// caller holds while it waits).
pub fn bh_submit(bh: &BufferHead, op: BioOp, end_io: BhEndIo) {
    assert!(
        bh.locked() && bh.mapped(),
        "bh_submit: unlocked or unmapped buffer"
    );
    // Only clear out a write error when rewriting
    if bh.test_set(BH_REQ) && op == BioOp::Write {
        bh.clear(BH_WRITE_EIO);
    }
    let sector = bh.blocknr().wrapping_mul(bh.size() as u64 >> SECTOR_SHIFT);
    let mut bio = Bio::new(op, sector);
    bio.add_seg(bh.folio(), bh.offset(), bh.size());
    bio.end_io = Some(end_io);
    bio.private = core::ptr::from_ref(bh).addr();
    // A removed device's buffer fails (Linux: the dead disk's bio ends
    // with an error)
    let Some(bdev) = bh.bdev() else {
        return bio_io_error(bio, KernelError::Io);
    };
    guard_bio_eod(&bdev, &mut bio);
    submit_bio(&bdev, bio);
}

/// The buffer a `bh_submit` bio carried, and whether it worked (Linux
/// bio_endio_bh); the bio is freed
fn bio_endio_bh<'a>(bio: Box<Bio>) -> (&'a BufferHead, bool) {
    let ok = bio.status.is_ok();
    let p = bio.private as *const BufferHead;
    drop(bio);
    // SAFETY: `bh_submit` put the locked buffer there; a locked buffer
    // is busy, so alive until the end handler unlocks it
    (unsafe { &*p }, ok)
}

/// "Buffer I/O error on dev ..." (Linux buffer_io_error), rate
/// limited (its printk_ratelimited's state), from a bio's completion: the device
/// named by its number, the page's mapping's (a block device's inode)
/// read under an RCU read guard, as taking a reference on the device
/// there could drop its last. (Linux skips it for a BH_Quiet buffer,
/// set from a BIO_QUIET bio: no hk driver marks a bio quiet.)
fn buffer_io_error(bh: &BufferHead, msg: &str) {
    use crate::util::ratelimit::{
        DEFAULT_RATELIMIT_BURST, DEFAULT_RATELIMIT_INTERVAL, RatelimitState,
    };
    static RS: RatelimitState =
        RatelimitState::new(DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);
    if !RS.ratelimit("buffer_io_error") {
        return;
    }
    let dev = {
        let g = crate::sync::rcu::read_lock();
        filemap::folio_mapping(bh.folio(), &g).and_then(|m| m.host_rdev())
    };
    match dev {
        Some(d) => crate::printkln!(
            "Buffer I/O error on dev {}:{}, logical block {}{}",
            d.major,
            d.minor,
            bh.blocknr(),
            msg
        ),
        None => crate::printkln!("Buffer I/O error, logical block {}{}", bh.blocknr(), msg),
    }
}

/// A buffer read through a path of its own ended (Linux
/// end_buffer_read_sync)
pub fn end_buffer_read_sync(bh: &BufferHead, uptodate: bool) {
    if uptodate {
        bh.set_uptodate();
    } else {
        bh.clear_uptodate();
    }
    unlock_buffer(bh);
}

/// End of a read (Linux bh_end_read)
fn bh_end_read(bio: Box<Bio>) {
    let (bh, ok) = bio_endio_bh(bio);
    end_buffer_read_sync(bh, ok);
}

/// End of a write (Linux bh_end_write)
fn bh_end_write(bio: Box<Bio>) {
    let (bh, ok) = bio_endio_bh(bio);
    if ok {
        bh.set_uptodate();
    } else {
        buffer_io_error(bh, ", lost sync page write");
        mark_buffer_write_io_error(bh);
        bh.clear_uptodate();
    }
    unlock_buffer(bh);
}

/// End of one of a page's async reads (Linux end_buffer_async_read):
/// the last one ends the page's read
fn end_buffer_async_read(bh: &BufferHead, uptodate: bool) {
    debug_assert!(bh.test(BH_ASYNC_READ));
    let folio = bh.folio();
    if uptodate {
        bh.set_uptodate();
    } else {
        bh.clear_uptodate();
        buffer_io_error(bh, ", async page read");
    }
    // The page is locked until the last read ends, so its ring stays
    // SAFETY: as above
    let first = unsafe { folio_buffers(folio) }.expect("async read of a page without buffers");
    let mut folio_uptodate = true;
    {
        let _g = first.b_uptodate_lock.lock();
        bh.clear(BH_ASYNC_READ);
        unlock_buffer(bh);
        let mut tmp = bh;
        loop {
            if !tmp.uptodate() {
                folio_uptodate = false;
            }
            if tmp.test(BH_ASYNC_READ) {
                debug_assert!(tmp.locked());
                return;
            }
            tmp = tmp.next();
            if core::ptr::eq(tmp, bh) {
                break;
            }
        }
    }
    folio_end_read(folio, folio_uptodate);
}

/// Completion of `block_read_full_folio`'s reads (Linux
/// bh_end_async_read)
fn bh_end_async_read(bio: Box<Bio>) {
    let (bh, ok) = bio_endio_bh(bio);
    end_buffer_async_read(bh, ok);
}

/// Completion of a page's async writes (Linux bh_end_async_write): the
/// last one ends the page's writeback
fn bh_end_async_write(bio: Box<Bio>) {
    let (bh, ok) = bio_endio_bh(bio);
    debug_assert!(bh.test(BH_ASYNC_WRITE));
    let folio = bh.folio();
    if ok {
        bh.set_uptodate();
    } else {
        buffer_io_error(bh, ", lost async page write");
        mark_buffer_write_io_error(bh);
        bh.clear_uptodate();
    }
    // The page is under writeback until the last write ends (and locked:
    // hk's ->writepage waits), so its ring stays
    // SAFETY: as above
    let first = unsafe { folio_buffers(folio) }.expect("async write of a page without buffers");
    {
        let _g = first.b_uptodate_lock.lock();
        bh.clear(BH_ASYNC_WRITE);
        unlock_buffer(bh);
        let mut tmp = bh.next();
        while !core::ptr::eq(tmp, bh) {
            if tmp.test(BH_ASYNC_WRITE) {
                debug_assert!(tmp.locked());
                return;
            }
            tmp = tmp.next();
        }
    }
    folio_end_writeback(folio);
}

/// A write of the buffer failed (Linux mark_buffer_write_io_error):
/// BH_Write_EIO, and EIO on its page's mapping and on the mapping of
/// the list it is on, each on its `wb_err` and its superblock's
/// `s_wb_err` (Linux mapping_set_error). Any context (a bio
/// completion): the mappings are reached under an RCU read guard and
/// the superblocks without a reference (`filemap::mapping_set_error_raw`)
pub fn mark_buffer_write_io_error(bh: &BufferHead) {
    bh.set(BH_WRITE_EIO);
    let g = crate::sync::rcu::read_lock();
    if let Some(m) = filemap::folio_mapping(bh.folio(), &g) {
        if bh.locked() {
            // SAFETY: a locked buffer of a page in `m`: the teardown of
            // `m`'s inode waits for its lock before it drops `i_data`,
            // then its superblock `Weak`
            unsafe { filemap::mapping_set_error_raw(m, KernelError::Io) };
        } else if let Some(i) = filemap::host_igrab(m) {
            // Not under I/O: a caller in thread context (an unlocked
            // buffer pins no inode), with a reference taken
            // SAFETY: the reference keeps the inode whole
            unsafe { filemap::mapping_set_error_raw(&i.i_data, KernelError::Io) };
            drop(g);
            drop(i);
            return mmb_set_error(bh);
        }
    }
    drop(g);
    mmb_set_error(bh);
}

/// EIO on the mapping and superblock of the list the buffer is on
/// (mark_buffer_write_io_error's mmb->mapping part)
fn mmb_set_error(bh: &BufferHead) {
    let _g = crate::sync::rcu::read_lock();
    let mmb = bh.b_mmb.load(Ordering::Acquire);
    // SAFETY: a listed buffer's list is alive: its drop empties it, then
    // waits a grace period (`Drop for MappingMetadataBhs`), and this
    // read is inside an RCU read section
    if let Some(mmb) = unsafe { mmb.as_ref() } {
        // SAFETY: the list's mapping outlives it (`MappingMetadataBhs::new`)
        unsafe { &*mmb.mapping }.wb_err.set(KernelError::Io);
        crate::fs::superblock::sb_wb_err_set(&mmb.sb, KernelError::Io);
    }
}

// ============================================================================
// Ring allocation (Linux folio_alloc_buffers, create_empty_buffers)
// ============================================================================

/// Free a buffer (Linux free_buffer_head)
///
/// # Safety
/// `p` is a buffer of `folio_alloc_buffers`, on no list, unreachable
/// by anyone else (its ring detached or never attached), freed once.
unsafe fn free_buffer_head(p: *const BufferHead) {
    // SAFETY: the caller's contract: unreachable, so this is the only
    // access
    let bh = unsafe { &*p };
    debug_assert!(!bh.b_assoc_buffers.is_listed());
    put_bdev(bh.b_bdev.swap(null_mut(), Ordering::Relaxed));
    // SAFETY: from `Box::into_raw` in `folio_alloc_buffers`, freed once
    drop(unsafe { Box::from_raw(p.cast_mut()) });
}

/// Free a chain of buffers linked through `b_this_page` up to null or
/// back to its head
///
/// # Safety
/// As [`free_buffer_head`] for every buffer of the chain.
unsafe fn free_chain(head: *const BufferHead) {
    let mut p = head;
    while !p.is_null() {
        // SAFETY: a live buffer of the chain
        let next = unsafe { &*p }.b_this_page.load(Ordering::Relaxed);
        // SAFETY: the caller's contract
        unsafe { free_buffer_head(p) };
        p = if core::ptr::eq(next, head) {
            null_mut()
        } else {
            next
        };
    }
}

/// Buffers of `size` bytes for page `phys`, linked through
/// `b_this_page` from offset 0 and ending in null (Linux
/// folio_alloc_buffers); None if out of memory, unless `nofail`
fn folio_alloc_buffers(phys: u64, size: usize, nofail: bool) -> Option<*const BufferHead> {
    debug_assert!(size.is_power_of_two() && (512..=PAGE_SIZE).contains(&size));
    let mut head: *const BufferHead = null_mut();
    let mut offset = PAGE_SIZE;
    while offset >= size {
        offset -= size;
        let bh = BufferHead::new(phys, offset, size);
        let b = if nofail {
            crate::util::kalloc::box_nofail(bh)
        } else {
            match crate::util::kalloc::try_box(bh) {
                Ok(b) => b,
                Err(_) => {
                    // SAFETY: the chain made so far, never attached
                    unsafe { free_chain(head) };
                    return None;
                }
            }
        };
        b.b_this_page.store(head.cast_mut(), Ordering::Relaxed);
        head = Box::into_raw(b);
    }
    Some(head)
}

/// Close the chain from `folio_alloc_buffers` into a ring
///
/// # Safety
/// `head` is such a chain, not yet shared.
unsafe fn close_ring(head: *const BufferHead) {
    let mut tail = head;
    loop {
        // SAFETY: buffers of the caller's unshared chain
        let next = unsafe { &*tail }.b_this_page.load(Ordering::Relaxed);
        if next.is_null() {
            break;
        }
        tail = next;
    }
    // SAFETY: as above
    unsafe { &*tail }
        .b_this_page
        .store(head.cast_mut(), Ordering::Relaxed);
}

/// Give the locked page `phys` of mapping `m` buffers of `blocksize`
/// with state bits `b_state`, dirty and uptodate as the page is (Linux
/// create_empty_buffers): never fails (Linux __GFP_NOFAIL). The head.
///
/// # Safety
/// The caller holds the page lock for `'a`, and the page has no
/// buffers.
unsafe fn create_empty_buffers<'a>(
    m: &AddressSpace,
    phys: u64,
    blocksize: usize,
    b_state: u32,
) -> &'a BufferHead {
    let head = folio_alloc_buffers(phys, blocksize, true).expect("nofail");
    // SAFETY: the new, unshared chain
    unsafe { close_ring(head) };
    // SAFETY: the new ring, not yet shared
    let h = unsafe { &*head };
    for bh in ring(h) {
        bh.b_state.fetch_or(b_state, Ordering::Relaxed);
    }
    {
        let _g = m.i_private_lock.lock();
        let (up, dirty) = (filemap::uptodate(phys), filemap::page_dirty(phys));
        if up || dirty {
            for bh in ring(h) {
                if dirty {
                    bh.set(BH_DIRTY);
                }
                if up {
                    bh.set_uptodate();
                }
            }
        }
        filemap::folio_attach_private(phys, head.addr() as u64);
    }
    // SAFETY: attached to the page, whose lock the caller holds for
    // 'a: freed only under it
    unsafe { &*head }
}

/// The locked page's buffers, made with `b_state` if it had none
/// (Linux folio_create_buffers)
///
/// # Safety
/// The caller holds the page lock for `'a`.
unsafe fn folio_create_buffers<'a>(inode: &Inode, phys: u64, b_state: u32) -> &'a BufferHead {
    assert!(crate::mm::page::phys_to_page(phys).is_some_and(|p| p.is_locked()));
    // SAFETY: the caller holds the page lock
    if let Some(h) = unsafe { folio_buffers(phys) } {
        return h;
    }
    // SAFETY: as above; no buffers
    unsafe { create_empty_buffers(&inode.i_data, phys, buffer_size(inode), b_state) }
}

/// The size of a mapping's buffers: its inode's block size. hk's
/// folios are a page: a block device's soft block size past a page
/// (BLKBSZSET to 64K) gives its cache page-sized buffers, where Linux
/// makes large folios of one block each.
fn buffer_size(inode: &Inode) -> usize {
    (inode.blocksize() as usize).min(PAGE_SIZE)
}

/// log2 of `buffer_size` (Linux i_blkbits of a block device's mapping)
fn buffer_bits(inode: &Inode) -> u32 {
    buffer_size(inode).trailing_zeros()
}

// ============================================================================
// Block device buffers (Linux grow_buffers, __getblk_slow, bdev_getblk)
// ============================================================================

/// Blocks of `size` on the device (Linux blkdev_max_block)
fn blkdev_max_block(bdev: &BlockDevice, size: usize) -> u64 {
    match bdev.capacity() {
        0 => u64::MAX,
        sz => sz >> size.trailing_zeros(),
    }
}

/// Map a block-device page's unmapped buffers to their blocks (Linux
/// folio_init_buffers); the device's block count of `size`. Under the
/// page lock.
fn folio_init_buffers(phys: u64, head: &BufferHead, bdev: &Arc<BlockDevice>, size: usize) -> u64 {
    let uptodate = filemap::uptodate(phys);
    let first = filemap::folio_pos(phys) / size as u64;
    let end_block = blkdev_max_block(bdev, size);
    for (block, bh) in (first..).zip(ring(head)) {
        if !bh.mapped() {
            bh.set_bdev(bdev);
            bh.set_blocknr(block);
            if uptodate {
                bh.set_uptodate();
            }
            if block < end_block {
                bh.set_mapped();
            }
        }
    }
    end_block
}

/// Make the device-cache page holding `block` and its buffers of
/// `size` (Linux grow_dev_folio): false if retrying cannot help;
/// ENOMEM if the page or its buffers cannot be allocated (Linux's
/// callers pass __GFP_NOFAIL, which hk's allocators lack)
fn grow_dev_folio(
    bdev: &Arc<BlockDevice>,
    block: u64,
    index: u64,
    size: usize,
) -> Result<bool, KernelError> {
    let m = &bdev.bd_inode.i_data;
    let phys = filemap::grab(m, index)?;
    let mut end_block = 0;
    let mut r = Ok(());
    // SAFETY: `grab` returned it locked
    match unsafe { folio_buffers(phys) } {
        Some(h) if h.size() == size => end_block = folio_init_buffers(phys, h, bdev, size),
        // Old buffers of another size (a changed block size): retry once
        // they could be freed
        Some(_) if !try_to_free_buffers(Some(m), phys) => end_block = u64::MAX,
        _ => match folio_alloc_buffers(phys, size, false) {
            Some(head) => {
                // Atomic with __find_get_block, which does not take the
                // page lock
                let _g = m.i_private_lock.lock();
                // SAFETY: the new, unshared chain
                unsafe { close_ring(head) };
                filemap::folio_attach_private(phys, head.addr() as u64);
                // SAFETY: attached, under the page lock
                end_block = folio_init_buffers(phys, unsafe { &*head }, bdev, size);
            }
            None => r = Err(KernelError::OutOfMemory),
        },
    }
    crate::mm::page::unlock_page(phys);
    filemap::put_page(phys);
    r.map(|()| block < end_block)
}

/// Linux grow_buffers: the block's page and buffers, unless it lies
/// past the largest page-cache offset
fn grow_buffers(bdev: &Arc<BlockDevice>, block: u64, size: usize) -> Result<bool, KernelError> {
    let pos = block.checked_mul(size as u64);
    let Some(pos) = pos.filter(|&p| p <= crate::fs::superblock::MAX_LFS_FILESIZE) else {
        crate::printkln!(
            "grow_buffers: requested out-of-range block {} for device {}",
            block,
            bdev.name
        );
        return Ok(false);
    };
    grow_dev_folio(bdev, block, pos / PAGE_SIZE as u64, size)
}

/// Linux __getblk_slow: grow the cache until the buffer is found. hk's
/// folios are a page: a block larger than a page is EINVAL. EIO for a
/// block past the device; ENOMEM where Linux's __GFP_NOFAIL retries.
fn getblk_slow(bdev: &Arc<BlockDevice>, block: u64, size: usize) -> Result<BhRef, KernelError> {
    if size > PAGE_SIZE || !size.is_power_of_two() {
        return Err(KernelError::InvalidArgument);
    }
    let lbs = bdev.logical_block_size() as usize;
    if !size.is_multiple_of(lbs) {
        crate::printkln!(
            "getblk(): block size {} not aligned to logical block size {}",
            size,
            lbs
        );
        return Err(KernelError::InvalidArgument);
    }
    loop {
        if !grow_buffers(bdev, block, size)? {
            return Err(KernelError::Io);
        }
        if let Some(bh) = find_get_block_nonatomic(bdev, block, size) {
            return Ok(bh);
        }
        // Old buffers of another size not freed yet: let their holder
        // run (hk's kernel is not preemptive)
        crate::task::percpu::cond_resched();
    }
}

/// Look `block` up in the device's cache (Linux __find_get_block_slow):
/// `atomic` under `i_private_lock` instead of the page lock. Buffers of
/// another size match by number as in Linux (a block size change drops
/// the cache, under its holder's claim); a page whose buffers are all
/// mapped yet miss the block is reported, rate limited (Linux).
fn find_get_block_slow(bdev: &BlockDevice, block: u64, atomic: bool) -> Option<BhRef> {
    let inode = &bdev.bd_inode;
    let m = &inode.i_data;
    let index = (block << buffer_bits(inode)) / PAGE_SIZE as u64;
    let phys = filemap::find_get(m, index)?;
    let found = {
        let _g = atomic.then(|| m.i_private_lock.lock());
        if !atomic {
            crate::mm::page::lock_page(phys);
        }
        // SAFETY: under the page lock or `i_private_lock`
        let r = unsafe { folio_buffers(phys) }.and_then(|h| ring_find(bdev, inode, h, block));
        if !atomic {
            crate::mm::page::unlock_page(phys);
        }
        r
    };
    filemap::put_page(phys);
    found
}

/// The mapped buffer of `block` in the ring at `head`, referenced
/// (`find_get_block_slow`'s walk, under the page lock or
/// `i_private_lock`)
fn ring_find(bdev: &BlockDevice, inode: &Inode, head: &BufferHead, block: u64) -> Option<BhRef> {
    /// Linux last_warned: once a second, no suppressed-count report
    static LAST_WARNED: crate::util::ratelimit::RatelimitState =
        crate::util::ratelimit::RatelimitState::new(1000 / crate::task::percpu::TICK_MS, 1)
            .msg_on_release();
    let mut all_mapped = true;
    for bh in ring(head) {
        if !bh.mapped() {
            all_mapped = false;
        } else if bh.blocknr() == block {
            return Some(get_bh(bh));
        }
    }
    // Some buffers unmapped: races between file I/O on the device and
    // getblk, dealt with elsewhere (Linux)
    if all_mapped && LAST_WARNED.ratelimit("__find_get_block_slow") {
        crate::printkln!(
            "__find_get_block_slow() failed. block={}, b_blocknr={}, b_state={:#010x}, b_size={}, device {} blocksize: {}",
            block,
            head.blocknr(),
            head.b_state.load(Ordering::Relaxed),
            head.size(),
            bdev.name,
            inode.blocksize()
        );
    }
    None
}

fn find_get_block_common(
    bdev: &BlockDevice,
    block: u64,
    size: usize,
    atomic: bool,
) -> Option<BhRef> {
    if let Some(bh) = lru::lookup(bdev, block, size) {
        return Some(bh);
    }
    let bh = find_get_block_slow(bdev, block, atomic)?;
    lru::install(&bh);
    Some(bh)
}

/// The cached buffer of `block` (`size` bytes), if any (Linux
/// __find_get_block); never sleeps
pub fn find_get_block(bdev: &BlockDevice, block: u64, size: usize) -> Option<BhRef> {
    find_get_block_common(bdev, block, size, true)
}

/// `find_get_block` that may sleep on the page lock (Linux
/// __find_get_block_nonatomic)
pub fn find_get_block_nonatomic(bdev: &BlockDevice, block: u64, size: usize) -> Option<BhRef> {
    find_get_block_common(bdev, block, size, false)
}

/// The buffer of `block` (`size` bytes) in the device's cache, made if
/// absent; referenced, not locked, maybe not uptodate (Linux
/// bdev_getblk). EIO past the device, ENOMEM (`getblk_slow`).
pub fn bdev_getblk(bdev: &Arc<BlockDevice>, block: u64, size: usize) -> Result<BhRef, KernelError> {
    crate::sync::might_sleep();
    match find_get_block_nonatomic(bdev, block, size) {
        Some(bh) => Ok(bh),
        None => getblk_slow(bdev, block, size),
    }
}

/// Read the locked buffer (Linux __bh_read): with `wait`, until done
/// (EIO if it failed)
pub fn bh_read_locked(bh: &BufferHead, wait: bool) -> Result<(), KernelError> {
    assert!(bh.locked());
    bh_submit(bh, BioOp::Read, bh_end_read);
    if wait {
        wait_on_buffer(bh);
        if !bh.uptodate() {
            return Err(KernelError::Io);
        }
    }
    Ok(())
}

/// Start reading the buffer (Linux bh_read_nowait)
fn bh_read_nowait(bh: &BufferHead) {
    lock_buffer(bh);
    let _ = bh_read_locked(bh, false);
}

/// Start reading the buffer unless it is uptodate or locked (Linux
/// bh_readahead)
pub fn bh_readahead(bh: &BufferHead) {
    if !bh.uptodate() && trylock_buffer(bh) {
        if bh.uptodate() {
            unlock_buffer(bh);
        } else {
            let _ = bh_read_locked(bh, false);
        }
    }
}

/// Linux __bread_slow: read it now unless it became uptodate
fn bread_slow(bh: BhRef) -> Result<BhRef, KernelError> {
    lock_buffer(&bh);
    if bh.uptodate() {
        unlock_buffer(&bh);
        return Ok(bh);
    }
    bh_submit(&bh, BioOp::Read, bh_end_read);
    wait_on_buffer(&bh);
    if bh.uptodate() {
        Ok(bh)
    } else {
        Err(KernelError::Io)
    }
}

/// Read `block` (`size` bytes) of the device through its cache (Linux
/// __bread_gfp): referenced and uptodate; EIO if unreadable, ENOMEM if
/// its buffer cannot be made (`getblk_slow`)
pub fn bread(bdev: &Arc<BlockDevice>, block: u64, size: usize) -> Result<BhRef, KernelError> {
    let bh = bdev_getblk(bdev, block, size)?;
    if bh.uptodate() {
        return Ok(bh);
    }
    bread_slow(bh)
}

/// Start reading `block` ahead (Linux __breadahead)
pub fn breadahead(bdev: &Arc<BlockDevice>, block: u64, size: usize) {
    if let Ok(bh) = bdev_getblk(bdev, block, size) {
        bh_readahead(&bh);
    }
}

/// The device a filesystem is mounted from
fn sb_bdev(sb: &SuperBlock) -> Result<&Arc<BlockDevice>, KernelError> {
    sb.bdev().ok_or(KernelError::NotBlockDevice)
}

/// Block `block` of a device filesystem, read (Linux sb_bread)
pub fn sb_bread(sb: &SuperBlock, block: u64) -> Result<BhRef, KernelError> {
    bread(sb_bdev(sb)?, block, sb.s_blocksize() as usize)
}

/// Block `block` of a device filesystem, maybe not read (Linux
/// sb_getblk)
pub fn sb_getblk(sb: &SuperBlock, block: u64) -> Result<BhRef, KernelError> {
    bdev_getblk(sb_bdev(sb)?, block, sb.s_blocksize() as usize)
}

/// Start reading block `block` of a device filesystem (Linux
/// sb_breadahead)
pub fn sb_breadahead(sb: &SuperBlock, block: u64) {
    if let Ok(b) = sb_bdev(sb) {
        breadahead(b, block, sb.s_blocksize() as usize);
    }
}

// ============================================================================
// Dirtying (Linux mark_buffer_dirty, block_dirty_folio)
// ============================================================================

/// Mark the uptodate buffer dirty, and its page and the page's inode
/// (Linux mark_buffer_dirty): never sleeps
pub fn mark_buffer_dirty(bh: &BufferHead) {
    debug_assert!(bh.uptodate(), "mark_buffer_dirty: buffer not uptodate");
    // The already-dirty case, its last check not before the caller's
    // change of the data
    if bh.dirty() {
        fence(Ordering::SeqCst);
        if bh.dirty() {
            return;
        }
    }
    if !bh.test_set(BH_DIRTY) {
        let phys = bh.folio();
        if filemap::test_set_page_dirty(phys) {
            return;
        }
        let host = {
            let g = crate::sync::rcu::read_lock();
            filemap::folio_mapping(phys, &g).and_then(|m| {
                filemap::account_dirtied(m, phys);
                filemap::host_igrab(m)
            })
        };
        // Outside the RCU read section: the reference's drop may be the
        // inode's last
        if let Some(i) = host {
            crate::fs::fs_writeback::mark_inode_dirty_pages(&i);
        }
    }
}

/// Dirty a buffered page: every buffer it has, then the page (Linux
/// block_dirty_folio), under `i_private_lock`, so buffers attached
/// meanwhile come dirty and `try_to_free_buffers` keeps them. Under the
/// page lock at most, never sleeps.
pub fn block_dirty_folio(m: &AddressSpace, phys: u64) {
    let newly = {
        let _g = m.i_private_lock.lock();
        // SAFETY: under `i_private_lock`
        if let Some(h) = unsafe { folio_buffers(phys) } {
            for bh in ring(h) {
                bh.set(BH_DIRTY);
            }
        }
        !filemap::test_set_page_dirty(phys)
    };
    if newly {
        filemap::account_dirtied(m, phys);
    }
}

// ============================================================================
// Writing single buffers (Linux write_dirty_buffer, __sync_dirty_buffer)
// ============================================================================

/// Start writing the buffer if dirty (Linux write_dirty_buffer)
pub fn write_dirty_buffer(bh: &BufferHead) {
    lock_buffer(bh);
    if !bh.test_clear(BH_DIRTY) {
        unlock_buffer(bh);
        return;
    }
    bh_submit(bh, BioOp::Write, bh_end_write);
}

/// Write the buffer if dirty and wait (Linux __sync_dirty_buffer,
/// sync_dirty_buffer): EIO if it failed or lost its mapping
pub fn sync_dirty_buffer(bh: &BhRef) -> Result<(), KernelError> {
    lock_buffer(bh);
    if !bh.test_clear(BH_DIRTY) {
        unlock_buffer(bh);
        return Ok(());
    }
    // Unmapped: the device went away (Linux: hot removal)
    if !bh.mapped() {
        unlock_buffer(bh);
        return Err(KernelError::Io);
    }
    bh_submit(bh, BioOp::Write, bh_end_write);
    wait_on_buffer(bh);
    if !bh.uptodate() {
        return Err(KernelError::Io);
    }
    Ok(())
}

// ============================================================================
// Invalidation and freeing (Linux block_invalidate_folio,
// try_to_free_buffers, clean_bdev_aliases)
// ============================================================================

/// Bits cleared when a buffer is truncated (Linux BUFFER_FLAGS_DISCARD)
const BUFFER_FLAGS_DISCARD: u32 = BH_MAPPED | BH_NEW | BH_REQ;

/// Truncate a buffer entirely (Linux discard_buffer)
fn discard_buffer(bh: &BufferHead) {
    lock_buffer(bh);
    bh.clear_dirty();
    put_bdev(bh.b_bdev.swap(null_mut(), Ordering::AcqRel));
    bh.b_state
        .fetch_and(!BUFFER_FLAGS_DISCARD, Ordering::Relaxed);
    unlock_buffer(bh);
}

/// Bytes [offset, offset + length) of the locked page `phys` of `m`
/// were truncated (Linux block_invalidate_folio): the buffers wholly
/// inside are discarded (no dirty one left, no I/O on them), and all of
/// them released if the whole page went
pub fn block_invalidate_folio(m: &AddressSpace, phys: u64, offset: usize, length: usize) {
    let stop = offset + length;
    assert!(stop <= PAGE_SIZE, "block_invalidate_folio: past the page");
    // SAFETY: the caller holds the page lock
    let Some(head) = (unsafe { folio_buffers(phys) }) else {
        return;
    };
    let mut curr_off = 0;
    for bh in ring(head) {
        let next_off = curr_off + bh.size();
        // Still fully in range?
        if next_off > stop {
            return;
        }
        // Fully invalidated?
        if offset <= curr_off {
            discard_buffer(bh);
        }
        curr_off = next_off;
    }
    // Released only if the whole page goes: no real I/O can follow
    if length == PAGE_SIZE {
        filemap::filemap_release_folio(m, phys);
    }
}

/// Unlink every buffer of the ring from its list and detach the ring;
/// false if one is busy (Linux drop_buffers)
fn drop_buffers(phys: u64, head: &BufferHead) -> bool {
    if ring(head).any(buffer_busy) {
        return false;
    }
    for bh in ring(head) {
        remove_assoc_queue(bh);
    }
    filemap::folio_detach_private(phys);
    true
}

/// Free the locked page's buffers unless one is busy (dirty, locked,
/// referenced) or the page is under writeback (Linux
/// try_to_free_buffers); a page all of whose buffers were clean comes
/// clean too. `m`: its mapping (None: removed from it). Never sleeps.
pub fn try_to_free_buffers(m: Option<&AddressSpace>, phys: u64) -> bool {
    debug_assert!(crate::mm::page::phys_to_page(phys).is_some_and(|p| p.is_locked()));
    if filemap::writeback(phys) {
        return false;
    }
    // SAFETY: under the page lock
    let Some(head) = (unsafe { folio_buffers(phys) }) else {
        return true;
    };
    let head_ptr: *const BufferHead = head;
    let freed = match m {
        None => drop_buffers(phys, head),
        Some(m) => {
            let _g = m.i_private_lock.lock();
            let r = drop_buffers(phys, head);
            // A page whose buffers are all clean is clean (truncate's
            // discard_buffer cleaned them): with i_private_lock, so no
            // block_dirty_folio's bit is lost
            if r {
                filemap::cancel_dirty(m, phys);
            }
            r
        }
    };
    if freed {
        // SAFETY: detached under the page lock and `i_private_lock`, no
        // buffer referenced, locked or listed: unreachable
        unsafe { free_chain(head_ptr) };
    }
    freed
}

/// Stop writeback of the device-cache aliases of blocks [block, block +
/// len) (`blkbits` their size's log2), a filesystem's new data blocks
/// (Linux clean_bdev_aliases): their buffers are cleaned and waited on,
/// so no old write lands on the reused blocks
pub fn clean_bdev_aliases(bdev: &BlockDevice, block: u64, len: u64) {
    let inode = &bdev.bd_inode;
    let m = &inode.i_data;
    let bits = buffer_bits(inode);
    let mut index = (block << bits) / PAGE_SIZE as u64;
    let end = ((block + len - 1) << bits) / PAGE_SIZE as u64;
    while index <= end {
        let Some((i, phys)) = filemap::find_get_range(m, index, end) else {
            return;
        };
        if filemap::folio_private(phys).is_some() {
            crate::mm::page::lock_page(phys);
            // Rechecked under the page lock, which pins the buffers
            // SAFETY: under the page lock
            if let Some(head) = unsafe { folio_buffers(phys) } {
                for bh in ring(head) {
                    if !bh.mapped() || bh.blocknr() < block {
                        continue;
                    }
                    if bh.blocknr() >= block + len {
                        break;
                    }
                    bh.clear_dirty();
                    wait_on_buffer(bh);
                    bh.clear(BH_REQ);
                }
            }
            crate::mm::page::unlock_page(phys);
        }
        filemap::put_page(phys);
        index = i + 1;
        crate::task::percpu::cond_resched();
    }
}

// ============================================================================
// Generic address-space operations (Linux block_read_full_folio,
// __block_write_full_folio, __block_write_begin_int, block_write_end)
// ============================================================================

/// Read the locked page `phys` of `inode` block by block (Linux
/// block_read_full_folio): unmapped blocks are mapped by `get_block`
/// (holes zeroed), the others read asynchronously. The page is
/// unlocked when the read ends, uptodate if every block is.
pub fn block_read_full_folio(inode: &Inode, phys: u64, get_block: GetBlock) {
    let limit = inode.get_size();
    // SAFETY: the caller holds the page lock until the read ends (the
    // last buffer's completion unlocks it: with the last submission
    // below, after which the ring is not touched)
    let head = unsafe { folio_create_buffers(inode, phys, 0) };
    let blocksize = head.size() as u64;
    let first = filemap::folio_pos(phys) / blocksize;
    let lblock = limit.div_ceil(blocksize);
    let mut prev: Option<&BufferHead> = None;
    let mut page_error = false;
    for (this, bh) in (first..).zip(ring(head)) {
        if bh.uptodate() {
            continue;
        }
        if !bh.mapped() {
            let mut err = false;
            if this < lblock && get_block(inode, this, bh, false).is_err() {
                err = true;
                page_error = true;
            }
            if !bh.mapped() {
                zero_frame(phys, bh.offset(), bh.size());
                if !err {
                    bh.set_uptodate();
                }
                continue;
            }
            // get_block may have read it in
            if bh.uptodate() {
                continue;
            }
        }
        lock_buffer(bh);
        if bh.uptodate() {
            unlock_buffer(bh);
            continue;
        }
        // The page comes unlocked when no locked async buffer is left;
        // the page lock keeps new async reads out meanwhile
        bh.set(BH_ASYNC_READ);
        if let Some(p) = prev {
            bh_submit(p, BioOp::Read, bh_end_async_read);
        }
        prev = Some(bh);
    }
    match prev {
        Some(p) => bh_submit(p, BioOp::Read, bh_end_async_read),
        // Every buffer uptodate, or get_block failed: no completion will
        // end the read
        None => folio_end_read(phys, !page_error),
    }
}

/// Write the dirty buffers of the locked page `phys` of `inode` (Linux
/// __block_write_full_folio, WB_SYNC_ALL): unmapped dirty ones are
/// mapped by `get_block` first, then each dirty buffer is locked,
/// cleaned and written under the page's writeback. hk's ->writepage is
/// synchronous and keeps the page locked: where Linux unlocks it after
/// submitting, this waits for the writeback to end. EIO if a write
/// failed (its buffer marked by `mark_buffer_write_io_error`).
pub fn block_write_full_folio_locked(
    inode: &Inode,
    phys: u64,
    get_block: GetBlock,
) -> Result<(), KernelError> {
    // SAFETY: the caller holds the page lock, kept throughout
    let head = unsafe { folio_create_buffers(inode, phys, BH_DIRTY | BH_UPTODATE) };
    let blocksize = head.size() as u64;
    let first = filemap::folio_pos(phys) / blocksize;
    let last_block = inode.get_size().saturating_sub(1) / blocksize;
    let mut err = Ok(());
    // Map the dirty buffers to disk blocks
    for (block, bh) in (first..).zip(ring(head)) {
        if block > last_block {
            // Outside i_size (a truncate in progress): zeroed by
            // block_write_full_folio
            bh.clear_dirty();
            bh.set_uptodate();
        } else if !bh.mapped() && bh.dirty() {
            debug_assert_eq!(bh.size() as u64, blocksize);
            if let Err(e) = get_block(inode, block, bh, true) {
                err = Err(e);
                break;
            }
            if bh.test_clear(BH_NEW) {
                // Block device mappings never come here
                clean_bdev_bh_alias(bh);
            }
        }
    }
    if let Err(e) = err {
        // ENOSPC or another error: the mapped dirty buffers are written
        // still, so no stale data shows (Linux recover:)
        for bh in ring(head) {
            if bh.mapped() && bh.dirty() {
                lock_buffer(bh);
                bh.set(BH_ASYNC_WRITE);
            } else {
                bh.clear_dirty();
            }
        }
        filemap::mapping_set_error(inode, e);
    } else {
        lock_dirty_buffers(head);
    }
    debug_assert!(!filemap::writeback(phys));
    folio_start_writeback(phys);
    let mut sent = [core::ptr::null::<BufferHead>(); MAX_BUF_PER_PAGE];
    let nr = collect_writes(head, &mut sent);
    for &p in &sent[..nr] {
        // SAFETY: a buffer of the locked page's ring (the page stays
        // locked here, so the ring stays)
        bh_submit(unsafe { &*p }, BioOp::Write, bh_end_async_write);
    }
    if nr == 0 {
        // The page was dirty but its buffers clean: written by hand
        folio_end_writeback(phys);
    }
    folio_wait_writeback(phys);
    err?;
    // SAFETY: as above
    if sent[..nr].iter().any(|&p| unsafe { &*p }.write_io_error()) {
        return Err(KernelError::Io);
    }
    Ok(())
}

/// Lock the mapped buffers of a page for writeback, keeping the dirty
/// ones, cleaned and marked BH_Async_Write, and unlocking the others
/// (Linux __block_write_full_folio's second loop, WB_SYNC_ALL): only
/// dirty buffers are written
fn lock_dirty_buffers(head: &BufferHead) {
    for bh in ring(head) {
        if !bh.mapped() {
            continue;
        }
        lock_buffer(bh);
        if bh.test_clear(BH_DIRTY) {
            bh.set(BH_ASYNC_WRITE);
        } else {
            unlock_buffer(bh);
        }
    }
}

/// The ring's buffers marked for an async write, into `sent`, before
/// any is submitted (the last completion may end the writeback while
/// submission goes on); how many
fn collect_writes(head: &BufferHead, sent: &mut [*const BufferHead; MAX_BUF_PER_PAGE]) -> usize {
    let mut nr = 0;
    for bh in ring(head) {
        if bh.test(BH_ASYNC_WRITE) {
            bh.clear_dirty();
            sent[nr] = bh;
            nr += 1;
        }
    }
    nr
}

/// Linux block_write_full_folio: a page straddling i_size has its tail
/// zeroed first (it may be mapped); one wholly past it is not written
pub fn block_write_full_folio(
    inode: &Inode,
    phys: u64,
    get_block: GetBlock,
) -> Result<(), KernelError> {
    let size = inode.get_size();
    let pos = filemap::folio_pos(phys);
    if pos + PAGE_SIZE as u64 <= size {
        return block_write_full_folio_locked(inode, phys, get_block);
    }
    if pos >= size {
        return Ok(());
    }
    zero_frame(
        phys,
        (size - pos) as usize,
        PAGE_SIZE - (size - pos) as usize,
    );
    block_write_full_folio_locked(inode, phys, get_block)
}

/// A newly allocated block's device-cache alias stops being written
/// (Linux clean_bdev_bh_alias)
fn clean_bdev_bh_alias(bh: &BufferHead) {
    if let Some(b) = bh.bdev() {
        clean_bdev_aliases(&b, bh.blocknr(), 1);
    }
}

/// New buffers of the locked page in [from, to) are zeroed if the page
/// is not uptodate, marked uptodate and dirty, and no longer new (Linux
/// folio_zero_new_buffers)
pub fn folio_zero_new_buffers(phys: u64, from: usize, to: usize) {
    // SAFETY: the caller holds the page lock
    let Some(head) = (unsafe { folio_buffers(phys) }) else {
        return;
    };
    let mut block_start = 0;
    for bh in ring(head) {
        let block_end = block_start + bh.size();
        if bh.new_block() && block_end > from && block_start < to {
            if !filemap::uptodate(phys) {
                let (s, e) = (from.max(block_start), to.min(block_end));
                zero_frame(phys, s, e - s);
                bh.set_uptodate();
            }
            bh.clear(BH_NEW);
            mark_buffer_dirty(bh);
        }
        block_start = block_end;
    }
}

/// Zero [s1, e1) and [s2, e2) of the page (Linux folio_zero_segments)
fn zero_segments(phys: u64, s1: usize, e1: usize, s2: usize, e2: usize) {
    if e1 > s1 {
        zero_frame(phys, s1, e1 - s1);
    }
    if e2 > s2 {
        zero_frame(phys, s2, e2 - s2);
    }
}

/// Make the blocks a write of `len` bytes at `pos` touches in the
/// locked page `phys` ready (Linux __block_write_begin_int): mapped
/// (new ones zeroed outside the write), and those it covers only in
/// part read in
pub fn block_write_begin_int(
    inode: &Inode,
    phys: u64,
    pos: u64,
    len: usize,
    get_block: GetBlock,
) -> Result<(), KernelError> {
    let from = (pos % PAGE_SIZE as u64) as usize;
    let to = from + len;
    assert!(to <= PAGE_SIZE);
    // SAFETY: the caller holds the page lock
    let head = unsafe { folio_create_buffers(inode, phys, 0) };
    let blocksize = head.size();
    let first = filemap::folio_pos(phys) / blocksize as u64;
    let folio_up = filemap::uptodate(phys);
    let mut wait: [Option<&BufferHead>; 2] = [None, None];
    let mut nwait = 0;
    let mut err = Ok(());
    let mut block_start = 0;
    for (this, bh) in (first..).zip(ring(head)) {
        let block_end = block_start + blocksize;
        let (bs, be) = (block_start, block_end);
        block_start = block_end;
        if be <= from || bs >= to {
            if folio_up {
                bh.set_uptodate();
            }
            continue;
        }
        bh.clear(BH_NEW);
        if !bh.mapped() {
            if let Err(e) = get_block(inode, this, bh, true) {
                err = Err(e);
                break;
            }
            if bh.new_block() {
                clean_bdev_bh_alias(bh);
                if folio_up {
                    bh.clear(BH_NEW);
                    bh.set_uptodate();
                    mark_buffer_dirty(bh);
                    continue;
                }
                if be > to || bs < from {
                    zero_segments(phys, to, be, bs, from);
                }
                continue;
            }
        }
        if folio_up {
            bh.set_uptodate();
            continue;
        }
        if !bh.uptodate() && (bs < from || be > to) {
            bh_read_nowait(bh);
            wait[nwait] = Some(bh);
            nwait += 1;
        }
    }
    // Let the reads complete
    for bh in wait[..nwait].iter().rev().flatten() {
        wait_on_buffer(bh);
        if !bh.uptodate() {
            err = Err(KernelError::Io);
        }
    }
    if err.is_err() {
        folio_zero_new_buffers(phys, from, to);
    }
    err
}

/// Bytes [from, to) of the locked page were written: their buffers are
/// uptodate and dirty, and the page uptodate if every buffer now is
/// (Linux block_commit_write)
pub fn block_commit_write(phys: u64, from: usize, to: usize) {
    // SAFETY: the caller holds the page lock
    let Some(head) = (unsafe { folio_buffers(phys) }) else {
        return;
    };
    let uptodate = filemap::uptodate(phys);
    let mut partial = false;
    let mut block_start = 0;
    for bh in ring(head) {
        let block_end = block_start + bh.size();
        if block_end <= from || block_start >= to {
            if !bh.uptodate() {
                partial = true;
            }
        } else {
            bh.set_uptodate();
            mark_buffer_dirty(bh);
        }
        bh.clear(BH_NEW);
        block_start = block_end;
        if uptodate && block_start >= to {
            break;
        }
    }
    // A partial write that made every buffer uptodate saves the next
    // read_folio
    if !partial {
        filemap::set_uptodate(phys);
    }
}

/// The locked page for a write of `len` bytes at `pos` (one page), its
/// blocks made ready (Linux block_write_begin)
pub fn block_write_begin(
    inode: &Inode,
    pos: u64,
    len: usize,
    get_block: GetBlock,
) -> Result<u64, KernelError> {
    let index = pos / PAGE_SIZE as u64;
    let phys = filemap::grab(&inode.i_data, index)?;
    if let Err(e) = block_write_begin_int(inode, phys, pos, len, get_block) {
        crate::mm::page::unlock_page(phys);
        filemap::put_page(phys);
        return Err(e);
    }
    Ok(phys)
}

/// `copied` of the `len` bytes at `pos` went into the locked page
/// (Linux block_write_end): a short copy into a page that is not
/// uptodate counts as none (a partly written buffer could be read over
/// by read_folio). The bytes committed.
pub fn block_write_end(phys: u64, pos: u64, len: usize, copied: usize) -> usize {
    let start = (pos % PAGE_SIZE as u64) as usize;
    let mut copied = copied;
    if copied < len {
        if !filemap::uptodate(phys) {
            copied = 0;
        }
        folio_zero_new_buffers(phys, start + copied, start + len);
    }
    block_commit_write(phys, start, start + copied);
    copied
}

/// The bytes [from, from + count) of the page are all in uptodate
/// buffers (Linux block_is_partially_uptodate)
pub fn block_is_partially_uptodate(phys: u64, from: usize, count: usize) -> bool {
    // SAFETY: the caller holds the page lock
    let Some(head) = (unsafe { folio_buffers(phys) }) else {
        return false;
    };
    let blocksize = head.size();
    let to = from + (PAGE_SIZE - from).min(count);
    if from < blocksize && to > PAGE_SIZE - blocksize {
        return false;
    }
    let mut block_start = 0;
    for bh in ring(head) {
        let block_end = block_start + blocksize;
        if block_end > from && block_start < to {
            if !bh.uptodate() {
                return false;
            }
            if block_end >= to {
                break;
            }
        }
        block_start = block_end;
    }
    true
}

// ============================================================================
// Metadata buffers of a mapping (Linux struct mapping_metadata_bhs)
// ============================================================================

/// A buffer's link on a metadata list (Linux b_assoc_buffers): a buffer
/// moves between a mapping's list and a sync's private one, and leaves
/// either from anywhere, so the link names the list it is on
///
/// # Invariants
/// Changed only under the lock of the `MappingMetadataBhs` the buffer's
/// `b_mmb` names. `head` is null (off every list; `next`, `prev` null)
/// or the live head of the list holding it, which `next`/`prev` walk
/// (null at the ends).
struct AssocLink {
    next: AtomicPtr<AssocLink>,
    prev: AtomicPtr<AssocLink>,
    head: AtomicPtr<AssocHead>,
}

/// A list of buffers' `AssocLink`s (Linux list_head as a head), null
/// ends: no pointer to itself, so an empty one may move
struct AssocHead {
    first: AtomicPtr<AssocLink>,
    last: AtomicPtr<AssocLink>,
}

impl AssocLink {
    const fn new() -> Self {
        Self {
            next: AtomicPtr::new(null_mut()),
            prev: AtomicPtr::new(null_mut()),
            head: AtomicPtr::new(null_mut()),
        }
    }

    /// On a list (Linux !list_empty(&bh->b_assoc_buffers))
    fn is_listed(&self) -> bool {
        !self.head.load(Ordering::Relaxed).is_null()
    }

    /// Unlink from the list it is on (Linux list_del_init)
    ///
    /// # Safety
    /// On a list, under its lock (type invariant).
    unsafe fn del(&self) {
        let (n, p) = (
            self.next.load(Ordering::Relaxed),
            self.prev.load(Ordering::Relaxed),
        );
        // SAFETY: on a list: `head` is its live head (type invariant)
        let h = unsafe { &*self.head.load(Ordering::Relaxed) };
        // SAFETY: the neighbours are live links of the same list
        match unsafe { n.as_ref() } {
            Some(n) => n.prev.store(p, Ordering::Relaxed),
            None => h.last.store(p, Ordering::Relaxed),
        }
        // SAFETY: as above
        match unsafe { p.as_ref() } {
            Some(p) => p.next.store(n, Ordering::Relaxed),
            None => h.first.store(n, Ordering::Relaxed),
        }
        // INVARIANT: off every list
        self.next.store(null_mut(), Ordering::Relaxed);
        self.prev.store(null_mut(), Ordering::Relaxed);
        self.head.store(null_mut(), Ordering::Relaxed);
    }
}

impl AssocHead {
    const fn new() -> Self {
        Self {
            first: AtomicPtr::new(null_mut()),
            last: AtomicPtr::new(null_mut()),
        }
    }

    fn ptr(&self) -> *mut AssocHead {
        core::ptr::from_ref(self).cast_mut()
    }

    fn is_empty(&self) -> bool {
        self.first.load(Ordering::Relaxed).is_null()
    }

    /// Add `e` at the front (Linux list_add)
    ///
    /// # Safety
    /// Under the list's lock; `e` on no list; this head stays put while
    /// `e` is on it.
    unsafe fn add(&self, e: &AssocLink) {
        let f = self.first.load(Ordering::Relaxed);
        e.prev.store(null_mut(), Ordering::Relaxed);
        e.next.store(f, Ordering::Relaxed);
        e.head.store(self.ptr(), Ordering::Relaxed);
        let me = core::ptr::from_ref(e).cast_mut();
        // SAFETY: the old first is a live link of this list
        match unsafe { f.as_ref() } {
            Some(f) => f.prev.store(me, Ordering::Relaxed),
            None => self.last.store(me, Ordering::Relaxed),
        }
        self.first.store(me, Ordering::Relaxed);
    }

    /// Add `e` at the back (Linux list_add_tail)
    ///
    /// # Safety
    /// As [`AssocHead::add`].
    unsafe fn add_tail(&self, e: &AssocLink) {
        let l = self.last.load(Ordering::Relaxed);
        e.next.store(null_mut(), Ordering::Relaxed);
        e.prev.store(l, Ordering::Relaxed);
        e.head.store(self.ptr(), Ordering::Relaxed);
        let me = core::ptr::from_ref(e).cast_mut();
        // SAFETY: the old last is a live link of this list
        match unsafe { l.as_ref() } {
            Some(l) => l.next.store(me, Ordering::Relaxed),
            None => self.first.store(me, Ordering::Relaxed),
        }
        self.last.store(me, Ordering::Relaxed);
    }
}

/// The buffer whose `b_assoc_buffers` is `l`
///
/// # Safety
/// `l` is the link of a live buffer.
unsafe fn assoc_bh<'a>(l: *mut AssocLink) -> &'a BufferHead {
    let off = core::mem::offset_of!(BufferHead, b_assoc_buffers);
    // SAFETY: the caller's contract: inside a live buffer
    unsafe { &*l.cast::<u8>().sub(off).cast::<BufferHead>() }
}

/// Buffers of the block device a mapping's fsync must write (an
/// inode's indirect blocks; Linux struct mapping_metadata_bhs)
///
/// # Invariants
/// `list` holds every buffer whose `b_mmb` is this value, except those
/// a running `mmb_sync` holds on its own list; all of them change under
/// `lock` (a spin lock, Linux mmb->lock): `i_private_lock` -> it.
pub struct MappingMetadataBhs {
    lock: crate::sync::spin::Mutex<()>,
    list: AssocHead,
    /// The mapping whose fsync writes them (Linux mmb->mapping)
    mapping: *const AddressSpace,
    /// Its inode's superblock, for a write error's `s_wb_err` from a
    /// completion (Linux mmb->mapping->host->i_sb): kept until the
    /// list's drop has waited out every reader
    sb: Weak<SuperBlock>,
    /// A buffer was ever on it: its drop waits a grace period
    used: core::sync::atomic::AtomicBool,
}

// SAFETY: the links are atomics changed only under `lock`; `mapping`
// is a shared borrow of a Sync value that outlives it (`new`)
unsafe impl Send for MappingMetadataBhs {}
// SAFETY: as above
unsafe impl Sync for MappingMetadataBhs {}

impl MappingMetadataBhs {
    /// An empty list for `mapping` (Linux mmb_init)
    ///
    /// # Safety
    /// `mapping` outlives the list (it is the inode's own, the list in
    /// the inode).
    pub unsafe fn new(mapping: &AddressSpace) -> Self {
        let sb = mapping.host_sb().unwrap_or_default();
        Self {
            lock: crate::sync::spin::Mutex::new(()),
            list: AssocHead::new(),
            mapping,
            sb,
            used: core::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl MappingMetadataBhs {
    /// Its drop need not wait a grace period: one has passed since it
    /// was emptied (in memory freed by RCU, as Linux's inode holding it)
    ///
    /// # Safety
    /// A grace period has passed since the list was last emptied
    /// (`mmb_invalidate`), and no buffer went on it since.
    pub unsafe fn rcu_passed(&self) {
        self.used.store(false, Ordering::Relaxed);
    }
}

impl Drop for MappingMetadataBhs {
    /// Emptied, then a grace period, so a completion that read a
    /// buffer's `b_mmb` before is done with it before the memory and the
    /// superblock `Weak` go (Linux: the inode holding it is freed by RCU)
    fn drop(&mut self) {
        mmb_invalidate(self);
        if self.used.load(Ordering::Relaxed) {
            crate::sync::rcu::synchronize();
        }
    }
}

/// Unlink `bh` from its list (Linux __remove_assoc_queue)
///
/// # Safety
/// `mmb.lock` is held and `bh.b_mmb` is `mmb`.
unsafe fn remove_assoc_queue_locked(mmb: &MappingMetadataBhs, bh: &BufferHead) {
    debug_assert!(core::ptr::eq(bh.b_mmb.load(Ordering::Relaxed), mmb));
    // SAFETY: on the list of `mmb` or a sync's private one, both under
    // `mmb.lock` (the caller's contract)
    unsafe { bh.b_assoc_buffers.del() };
    bh.b_mmb.store(null_mut(), Ordering::Release);
}

/// Take `bh` off its list, if on one (Linux remove_assoc_queue): the
/// list is reached under an RCU read guard and rechecked under its lock
fn remove_assoc_queue(bh: &BufferHead) {
    while !bh.b_mmb.load(Ordering::Acquire).is_null() {
        let _g = crate::sync::rcu::read_lock();
        let p = bh.b_mmb.load(Ordering::Acquire);
        // SAFETY: a listed buffer's list is freed a grace period after
        // its last buffer leaves it (`mmb_mark_buffer_dirty`'s contract)
        if let Some(mmb) = unsafe { p.as_ref() } {
            let _l = mmb.lock.lock();
            if core::ptr::eq(bh.b_mmb.load(Ordering::Relaxed), p) {
                // SAFETY: under its lock, on it
                unsafe { remove_assoc_queue_locked(mmb, bh) };
            }
        }
    }
}

/// Buffers are on the list (Linux mmb_has_buffers)
pub fn mmb_has_buffers(mmb: &MappingMetadataBhs) -> bool {
    !mmb.list.is_empty()
}

/// Mark `bh` dirty and put it on `mmb`, for its mapping's fsync (Linux
/// mmb_mark_buffer_dirty); a buffer on another list stays there
///
/// # Safety
/// `mmb` stays at its address while buffers are on it, and its memory
/// is freed only by its drop (which waits a grace period) or a grace
/// period after an `mmb_invalidate` (Linux frees the inode holding it
/// by RCU).
pub unsafe fn mmb_mark_buffer_dirty(bh: &BufferHead, mmb: &MappingMetadataBhs) {
    mark_buffer_dirty(bh);
    if !bh.b_mmb.load(Ordering::Acquire).is_null() {
        return;
    }
    let _l = mmb.lock.lock();
    // A corrupted filesystem's multiply claimed block: keep its list
    let me = core::ptr::from_ref(mmb).cast_mut();
    if bh
        .b_mmb
        .compare_exchange(null_mut(), me, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    mmb.used.store(true, Ordering::Relaxed);
    // SAFETY: under the list's lock, `bh` on no list (b_mmb was null);
    // the list stays put while it holds buffers (the caller's contract)
    unsafe { mmb.list.add_tail(&bh.b_assoc_buffers) };
}

/// Drop every buffer from the list, dirty or not (Linux
/// mmb_invalidate): an inode going away
pub fn mmb_invalidate(mmb: &MappingMetadataBhs) {
    if !mmb_has_buffers(mmb) {
        return;
    }
    let _l = mmb.lock.lock();
    while let Some(l) = core::ptr::NonNull::new(mmb.list.first.load(Ordering::Relaxed)) {
        // SAFETY: a link of the list, under its lock: a live buffer
        // (listed buffers are never freed: drop_buffers unlinks first)
        let bh = unsafe { assoc_bh(l.as_ptr()) };
        // SAFETY: under its lock, on it
        unsafe { remove_assoc_queue_locked(mmb, bh) };
    }
}

/// Write the list's dirty buffers and wait for them and for those
/// already under I/O (Linux mmb_sync): buffers dirtied meanwhile are
/// not waited for. EIO if one failed.
pub fn mmb_sync(mmb: &MappingMetadataBhs) -> Result<(), KernelError> {
    if !mmb_has_buffers(mmb) {
        return Ok(());
    }
    // The sync's own list: on this stack, under `mmb.lock` like the list
    let tmp = AssocHead::new();
    let me = core::ptr::from_ref(mmb).cast_mut();
    crate::block::plug::blk_plug(|| {
        let mut l = mmb.lock.lock();
        while let Some(p) = core::ptr::NonNull::new(mmb.list.first.load(Ordering::Relaxed)) {
            // SAFETY: a link of the list under its lock: a live buffer
            let bh = unsafe { assoc_bh(p.as_ptr()) };
            // SAFETY: under its lock, on it
            unsafe { remove_assoc_queue_locked(mmb, bh) };
            // Against mmb_mark_buffer_dirty's lockless check
            fence(Ordering::SeqCst);
            if bh.dirty() || bh.locked() {
                // SAFETY: under `mmb.lock`; `bh` on no list; `tmp` stays
                // on this stack until emptied below
                unsafe { tmp.add(&bh.b_assoc_buffers) };
                bh.b_mmb.store(me, Ordering::Release);
                if bh.dirty() {
                    let r = get_bh(bh);
                    drop(l);
                    // Any I/O in flight ends first, so this writes the
                    // current data
                    write_dirty_buffer(&r);
                    drop(r);
                    l = mmb.lock.lock();
                }
            }
        }
        drop(l);
    });
    let mut err = Ok(());
    let mut l = mmb.lock.lock();
    while let Some(p) = core::ptr::NonNull::new(tmp.last.load(Ordering::Relaxed)) {
        // SAFETY: a link of `tmp` under the list's lock: a live buffer
        // (on a list: never freed)
        let r = get_bh(unsafe { assoc_bh(p.as_ptr()) });
        // SAFETY: under the list's lock, on `tmp`, `b_mmb` this list
        unsafe { remove_assoc_queue_locked(mmb, &r) };
        fence(Ordering::SeqCst);
        if r.dirty() {
            // SAFETY: under its lock, `r` on no list
            unsafe { mmb.list.add(&r.b_assoc_buffers) };
            r.b_mmb.store(me, Ordering::Release);
        }
        drop(l);
        wait_on_buffer(&r);
        if !r.uptodate() {
            err = Err(KernelError::Io);
        }
        drop(r);
        l = mmb.lock.lock();
    }
    drop(l);
    err
}

// ============================================================================
// Per-CPU LRU of looked-up buffers (Linux bh_lrus)
// ============================================================================

mod lru {
    use super::{BhRef, BufferHead, get_bh};
    use crate::block::blkdev::BlockDevice;
    use crate::sync::IrqSpinlock;

    /// Buffers per CPU (Linux BH_LRU_SIZE)
    const BH_LRU_SIZE: usize = 16;

    /// One CPU's recently looked-up buffers, newest first, each holding
    /// a reference (Linux struct bh_lru)
    pub(super) struct BhLru {
        bhs: [*const BufferHead; BH_LRU_SIZE],
    }

    // SAFETY: the pointers are references (counts) owned by the array,
    // used only under its lock; buffers are Sync
    unsafe impl Send for BhLru {}

    crate::percpu! {
        /// Linux bh_lrus (bh_lru_lock: local_irq_disable): an
        /// IrqSpinlock per CPU, taken by its CPU and by its own
        /// `invalidate_bh_lrus` call
        static BH_LRUS: IrqSpinlock<BhLru> = IrqSpinlock::new(BhLru {
            bhs: [core::ptr::null(); BH_LRU_SIZE],
        });
    }

    /// Put `bh` at the front of this CPU's LRU, the oldest falling out
    /// (Linux bh_lru_install)
    pub(super) fn install(bh: &BhRef) {
        let want = core::ptr::from_ref::<BufferHead>(bh);
        let mut evictee = want;
        {
            let mut b = BH_LRUS.this().lock();
            for slot in b.bhs.iter_mut() {
                core::mem::swap(&mut evictee, slot);
                if core::ptr::eq(evictee, want) {
                    return;
                }
            }
            // The LRU's own reference
            core::mem::forget(get_bh(bh));
        }
        if !evictee.is_null() {
            // SAFETY: the LRU held this reference
            drop(unsafe { BhRef::from_raw(evictee) });
        }
    }

    /// The buffer of `block` of `bdev` (`size` bytes) from this CPU's
    /// LRU, moved to its front (Linux lookup_bh_lru)
    pub(super) fn lookup(bdev: &BlockDevice, block: u64, size: usize) -> Option<BhRef> {
        let mut b = BH_LRUS.this().lock();
        let i = b.bhs.iter().position(|&p| {
            // SAFETY: each non-null slot holds a reference, under the lock
            unsafe { p.as_ref() }
                .is_some_and(|bh| bh.blocknr() == block && bh.on_bdev(bdev) && bh.size() == size)
        })?;
        let p = b.bhs[i];
        b.bhs.copy_within(0..i, 1);
        b.bhs[0] = p;
        // SAFETY: held by the slot, under the lock
        Some(get_bh(unsafe { &*p }))
    }

    /// Drop this CPU's references (Linux invalidate_bh_lru), in its
    /// cross-CPU call (interrupts off)
    fn invalidate_cpu(_: usize) {
        let mut b = BH_LRUS.this().lock();
        for slot in b.bhs.iter_mut() {
            let p = core::mem::replace(slot, core::ptr::null());
            if !p.is_null() {
                // SAFETY: the slot's reference
                drop(unsafe { BhRef::from_raw(p) });
            }
        }
    }

    /// Whether `cpu`'s LRU holds a buffer (Linux has_bh_in_lru): read
    /// under that CPU's lock, stale once it is dropped, as Linux's
    /// unlocked read
    fn has_bh_in_lru(cpu: u32, _: usize) -> bool {
        BH_LRUS.get(cpu).lock().bhs.iter().any(|p| !p.is_null())
    }

    /// Empty every CPU's LRU (Linux invalidate_bh_lrus): a cross-CPU
    /// call only on those holding a buffer (on_each_cpu_cond)
    pub fn invalidate_bh_lrus() {
        crate::smp::on_each_cpu_cond(has_bh_in_lru, invalidate_cpu, 0);
    }
}

pub use lru::invalidate_bh_lrus;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A detached ring for page `phys` of `size` buffers
    fn ring_of(phys: u64, size: usize) -> *const BufferHead {
        let head = folio_alloc_buffers(phys, size, false).unwrap();
        // SAFETY: the new, unshared chain
        unsafe { close_ring(head) };
        head
    }

    fn free(head: *const BufferHead) {
        // SAFETY: a test ring, never attached
        unsafe { free_chain(head) };
    }

    #[test]
    fn ring_layout() {
        for size in [512usize, 1024, 2048, 4096] {
            let head = ring_of(0x1000, size);
            // SAFETY: the test's ring
            let h = unsafe { &*head };
            let bhs: alloc::vec::Vec<&BufferHead> = ring(h).collect();
            assert_eq!(bhs.len(), PAGE_SIZE / size);
            for (i, bh) in bhs.iter().enumerate() {
                assert_eq!(bh.offset(), i * size);
                assert_eq!(bh.size(), size);
                assert_eq!(bh.folio(), 0x1000);
            }
            // Around and back to the head
            assert!(core::ptr::eq(bhs[bhs.len() - 1].next(), h));
            free(head);
        }
    }

    #[test]
    fn blocks_of_a_page() {
        // Page 3 of a device with 1 KiB blocks holds blocks 12..16
        let size = 1024u64;
        let pos = 3 * PAGE_SIZE as u64;
        let first = pos / size;
        assert_eq!(first, 12);
        let head = ring_of(0x2000, size as usize);
        // SAFETY: the test's ring
        let h = unsafe { &*head };
        for (i, bh) in ring(h).enumerate() {
            bh.set_blocknr(first + i as u64);
        }
        for bh in ring(h) {
            // blocknr -> byte offset in the page -> back
            let off = (bh.blocknr() * size - pos) as usize;
            assert_eq!(off, bh.offset());
            assert_eq!((pos + off as u64) / size, bh.blocknr());
            // Its sector on the device
            assert_eq!(
                bh.blocknr() * (size >> SECTOR_SHIFT),
                (pos + off as u64) / 512
            );
        }
        free(head);
    }

    /// Writeback picks the dirty mapped buffers only, each locked and
    /// cleaned; the clean ones are left unlocked
    #[test]
    fn dirty_only_writeback() {
        let head = ring_of(0x6000, 1024);
        // SAFETY: the test's ring
        let h = unsafe { &*head };
        let bhs: alloc::vec::Vec<&BufferHead> = ring(h).collect();
        for bh in &bhs {
            bh.set_mapped();
            bh.set_uptodate();
        }
        bhs[1].set(BH_DIRTY);
        bhs[3].set(BH_DIRTY);
        lock_dirty_buffers(h);
        let mut sent = [core::ptr::null(); MAX_BUF_PER_PAGE];
        let nr = collect_writes(h, &mut sent);
        assert_eq!(nr, 2);
        assert!(core::ptr::eq(sent[0], bhs[1]) && core::ptr::eq(sent[1], bhs[3]));
        for (i, bh) in bhs.iter().enumerate() {
            let w = i == 1 || i == 3;
            assert_eq!(bh.locked(), w);
            assert_eq!(bh.test(BH_ASYNC_WRITE), w);
            assert!(!bh.dirty());
        }
        for bh in [bhs[1], bhs[3]] {
            bh.clear(BH_ASYNC_WRITE);
            unlock_buffer(bh);
        }
        free(head);
    }

    /// try_to_free_buffers (drop_buffers) refuses a ring with any
    /// buffer referenced, dirty or locked
    #[test]
    fn busy_buffers() {
        let head = ring_of(0x3000, 1024);
        // SAFETY: the test's ring
        let h = unsafe { &*head };
        assert!(!ring(h).any(buffer_busy));
        let r = get_bh(h.next());
        assert!(ring(h).any(buffer_busy));
        drop(r);
        h.next().next().set(BH_DIRTY);
        assert!(ring(h).any(buffer_busy));
        h.next().next().clear_dirty();
        assert!(trylock_buffer(h));
        assert!(!trylock_buffer(h));
        assert!(ring(h).any(buffer_busy));
        unlock_buffer(h);
        assert!(!ring(h).any(buffer_busy));
        free(head);
    }

    #[test]
    fn state_bits() {
        let head = ring_of(0x4000, 4096);
        // SAFETY: the test's ring
        let h = unsafe { &*head };
        assert!(!h.uptodate() && !h.dirty() && !h.mapped());
        h.set_uptodate();
        h.set_mapped();
        assert!(h.uptodate() && h.mapped());
        assert!(!h.test_set(BH_DIRTY));
        assert!(h.test_set(BH_DIRTY));
        assert!(h.test_clear(BH_DIRTY));
        assert!(!h.dirty());
        // A rewrite clears an old write error (bh_submit's REQ test)
        h.set(BH_WRITE_EIO);
        assert!(!h.test_set(BH_REQ));
        assert!(h.test_set(BH_REQ));
        free(head);
    }

    #[test]
    fn assoc_lists() {
        let head = ring_of(0x5000, 2048);
        // SAFETY: the test's ring
        let h = unsafe { &*head };
        let tmp = AssocHead::new();
        assert!(tmp.is_empty());
        // SAFETY: test lists, single-threaded
        unsafe {
            tmp.add_tail(&h.b_assoc_buffers);
            tmp.add(&h.next().b_assoc_buffers);
        }
        assert!(!tmp.is_empty() && h.b_assoc_buffers.is_listed());
        // SAFETY: the first entry's link
        let first = unsafe { assoc_bh(tmp.first.load(Ordering::Relaxed)) };
        assert!(core::ptr::eq(first, h.next()));
        // Leaves from the middle of nowhere: its link names the list
        // SAFETY: on `tmp`
        unsafe { h.b_assoc_buffers.del() };
        // SAFETY: the last entry's link
        let last = unsafe { assoc_bh(tmp.last.load(Ordering::Relaxed)) };
        assert!(core::ptr::eq(last, h.next()));
        // SAFETY: on `tmp`
        unsafe { h.next().b_assoc_buffers.del() };
        assert!(tmp.is_empty() && !h.b_assoc_buffers.is_listed());
        free(head);
    }
}
