//! Block layer core: bios, request queues, disks and block devices
//!
//! Linux reference: block/bio.c, block/blk-core.c, block/genhd.c,
//! include/linux/blk_types.h.
//!
//! ```text
//! submit_bio(bdev, bio) -> partition remap -> RequestQueue
//!     bio-based driver: BlockDriver::submit_bio (submitter's context)
//!     blk-mq driver:    per-CPU sw queue -> hw queue -> MqOps::queue_rq
//! completion: driver -> bio_endio(bio) -> bio.end_io (may be hardirq)
//! ```
//!
//! A [`Disk`] (Linux gendisk) is the device; a [`BlockDevice`] (Linux
//! block_device) is the whole disk (partno 0) or one partition of it.
//! Each block device has an inode (`bd_inode`, Linux bdev inode) whose
//! page cache serves device-file I/O and filesystem metadata
//! (`fs::blkdev_ops`); its pages are read and written a page per bio.
//! Partition scans are synchronous bios (`submit_bio_wait`).
//!
//! ## Locking (doc/LOCKING.md 3.10, Block Device Subsystem)
//!
//! - `BLKDEV_REGISTRY` (spin `RwLock`, thread context, leaf): dev_t ->
//!   block device. `MAJORS` (spin `Mutex`, leaf): block major numbers.
//! - `Disk.open_mutex` (sleeping `sync::Mutex`, Linux disk->open_mutex):
//!   serializes opens, releases and partition rescans; I/O and devtmpfs
//!   node updates happen under it.
//! - blk-mq queue locks are `IrqSpinlock` leaves (`blk_mq`).
//! - `end_io` runs in the completion context, possibly hardirq: it may
//!   only use IRQ-safe operations (atomics, `Completion::complete`, wait
//!   queue wakeups); it must not sleep or take a `Mutex`/`RwLock`.
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::sync::IrqSpinlock;
use crate::sync::completion::Completion;
use crate::sync::spin::{Mutex, RwLock};

pub use crate::fs::chardev::{DevId, DevMajor, DevMinor};
use crate::mm::writeback::{BdiWriteback, bdi_register, bdi_unregister};
use crate::util::error::KernelError;
use crate::util::kalloc::{box_nofail, try_arc};
use crate::util::smallvec::SmallVec;

use super::blk_mq::BlkMq;

/// Largest soft block size (Linux BLK_MAX_BLOCK_SIZE: 64K since 6.15
/// with CONFIG_TRANSPARENT_HUGEPAGE); the size is only reported
const BLK_MAX_BLOCK_SIZE: i32 = 64 * 1024;

/// Fixed block major numbers (Linux include/uapi/linux/major.h)
pub mod major {
    use super::DevMajor;

    /// RAM disks
    pub const RAMDISK: DevMajor = 1;
    /// SCSI disks sda..sdp (16 minors each)
    pub const SCSI_DISK: DevMajor = 8;
}

/// Sector size (Linux SECTOR_SIZE: block layer addresses are in 512-byte units)
pub const SECTOR_SIZE: u64 = 512;
pub const SECTOR_SHIFT: u32 = 9;
const PAGE: usize = 4096;
/// Default cap on a request's sectors when the device has none (Linux
/// BLK_DEF_MAX_SECTORS_CAP: 4 MiB)
pub const BLK_DEF_MAX_SECTORS_CAP: u32 = (4 << 20) >> SECTOR_SHIFT;

// ============================================================================
// Major numbers (Linux register_blkdev)
// ============================================================================

/// Highest major handed out dynamically (Linux searches 254 down to 1)
const DYN_MAJOR_MAX: DevMajor = 254;

static MAJORS: Mutex<BTreeMap<DevMajor, &'static str>> = Mutex::new(BTreeMap::new());

/// Register block major `major` for `name`; 0 picks the highest free
/// one (Linux register_blkdev). Returns the major.
pub fn register_blkdev(major: DevMajor, name: &'static str) -> Result<DevMajor, KernelError> {
    let mut m = MAJORS.lock();
    let major = if major == 0 {
        (1..=DYN_MAJOR_MAX)
            .rev()
            .find(|n| !m.contains_key(n))
            .ok_or(KernelError::Busy)?
    } else if m.get(&major).is_some_and(|n| *n != name) {
        return Err(KernelError::Busy);
    } else {
        major
    };
    m.insert(major, name);
    Ok(major)
}

// ============================================================================
// Bios
// ============================================================================

/// Block I/O operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioOp {
    Read,
    Write,
    /// Make completed writes durable (Linux REQ_OP_FLUSH / REQ_PREFLUSH)
    Flush,
}

impl BioOp {
    pub fn is_write(self) -> bool {
        self != BioOp::Read
    }
}

bitflags::bitflags! {
    /// Modifiers of a bio's operation (Linux blk_opf_t REQ_* flags)
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct BioFlags: u32 {
        /// The written data is durable when the bio completes (Linux
        /// REQ_FUA): a queue with a volatile cache but no FUA follows it
        /// with a flush
        const FUA = 1 << 0;
        /// Never wait in the block layer or driver: a bio that would
        /// (no free tag) ends with EAGAIN (Linux REQ_NOWAIT,
        /// bio_wouldblock_error); a queue without NOWAIT support ends
        /// it with EOPNOTSUPP
        const NOWAIT = 1 << 1;
    }
}

/// One segment: part of a physical frame
#[derive(Debug, Clone, Copy, Default)]
pub struct BioSeg {
    /// Physical address of the frame
    pub frame: u64,
    pub offset: usize,
    pub len: usize,
}

/// Segments a bio keeps inline (Linux BIO_INLINE_VECS): more go to
/// the heap
pub const BIO_INLINE_VECS: usize = 4;

/// A bio's segments
pub type BioSegs = SmallVec<BioSeg, BIO_INLINE_VECS>;

/// Completion callback; called once with the finished bio, possibly in
/// hardirq context (module docs)
pub type EndIo = fn(Box<Bio>);

/// A block I/O request: one contiguous sector range, scatter/gather
/// memory (Linux struct bio)
pub struct Bio {
    pub op: BioOp,
    pub flags: BioFlags,
    /// First sector; relative to the block device on submission, to the
    /// disk after the partition remap
    pub sector: u64,
    pub segs: BioSegs,
    /// Result, set by the driver before `bio_endio` (Linux bi_status)
    pub status: Result<(), KernelError>,
    pub end_io: Option<EndIo>,
    /// For the owner of `end_io` (Linux bi_private)
    pub private: usize,
    /// Bios merged behind this one into one request (Linux rq->bio
    /// chain): each ends on its own when the request does
    /// (`bio_endio`); blk-mq only
    pub merged: BioList,
    /// Sectors and segments of the `merged` bios (a request's running
    /// totals beyond its head, Linux __data_len, nr_phys_segments)
    merged_sectors: u64,
    merged_segs: usize,
    /// Address of the queue a bio is held for on a plug (`plug`), or a
    /// shared flush is out for (`FqState::kick`)
    pub(super) plug_q: usize,
    /// Software queue (CPU) of its blk-mq request, set when the request
    /// is taken (Linux rq->mq_ctx)
    pub(super) rq_ctx: u16,
    /// Link in a [`BioList`]
    next: Option<Box<Bio>>,
}

impl Bio {
    /// Linux bio_alloc: from a mempool, it cannot fail (GFP_NOIO
    /// writeback must make progress)
    pub fn new(op: BioOp, sector: u64) -> Box<Self> {
        box_nofail(Self {
            op,
            flags: BioFlags::empty(),
            sector,
            segs: BioSegs::new(),
            status: Ok(()),
            end_io: None,
            private: 0,
            merged: BioList::new(),
            merged_sectors: 0,
            merged_segs: 0,
            plug_q: 0,
            rq_ctx: 0,
            next: None,
        })
    }

    /// `new` with room for `n` segments (ENOMEM past the inline ones)
    pub fn with_segs(op: BioOp, sector: u64, n: usize) -> Result<Box<Self>, KernelError> {
        let mut b = Self::new(op, sector);
        b.segs = BioSegs::try_with_capacity(n)?;
        Ok(b)
    }

    pub fn add_seg(&mut self, frame: u64, offset: usize, len: usize) {
        self.segs.push(BioSeg { frame, offset, len });
    }

    /// Bytes of data
    pub fn size(&self) -> usize {
        self.segs.iter().map(|s| s.len).sum()
    }

    /// Sectors of data
    pub fn sectors(&self) -> u64 {
        (self.size() as u64) >> SECTOR_SHIFT
    }

    /// The bios of the request this one heads: itself, then the merged
    fn rq_bios(&self) -> impl Iterator<Item = &Bio> {
        core::iter::once(self).chain(self.merged.iter())
    }

    /// The request's segments, in order (Linux rq_for_each_segment)
    pub fn rq_segs(&self) -> impl Iterator<Item = &BioSeg> {
        self.rq_bios().flat_map(|b| b.segs.iter())
    }

    /// The request's segment count (Linux blk_rq_nr_phys_segments)
    pub fn rq_nr_segs(&self) -> usize {
        self.segs.len() + self.merged_segs
    }

    /// The request's sectors (Linux blk_rq_sectors)
    pub fn rq_sectors(&self) -> u64 {
        self.sectors() + self.merged_sectors
    }

    /// Merge `b` (a lone bio) behind the request this bio heads (Linux
    /// bio_attempt_back_merge)
    pub(super) fn rq_append(&mut self, b: Box<Bio>) {
        self.merged_sectors += b.sectors();
        self.merged_segs += b.segs.len();
        self.merged.push(b);
    }

    /// Merge `b` (a lone bio) in front of the request this bio heads
    /// (Linux bio_attempt_front_merge): `b`'s data takes the head's
    /// place, the old head and the bios behind it follow. What the head
    /// holds for the request stays: its software queue (whose hardware
    /// queue counted its tag), its queue, its flags (Linux keeps mq_ctx
    /// and cmd_flags), and the running totals grow by the old head
    pub(super) fn rq_prepend(&mut self, mut b: Box<Bio>) {
        core::mem::swap(self, &mut *b);
        // `b` is the old head now, `self` the new bio's data
        core::mem::swap(&mut self.rq_ctx, &mut b.rq_ctx);
        core::mem::swap(&mut self.plug_q, &mut b.plug_q);
        core::mem::swap(&mut self.flags, &mut b.flags);
        self.merged_sectors = b.merged_sectors + b.sectors();
        self.merged_segs = b.merged_segs + b.segs.len();
        b.merged_sectors = 0;
        b.merged_segs = 0;
        let mut rest = core::mem::take(&mut b.merged);
        self.merged.push(b);
        self.merged.append(&mut rest);
    }
}

/// Finish a bio: hand it to its `end_io` or free it (Linux bio_endio).
/// A request's head ends the bios merged behind it first, with its
/// status (Linux blk_mq_end_request: blk_update_request, bio by bio).
/// Callable in hardirq context (the heap is IRQ-safe).
pub fn bio_endio(mut bio: Box<Bio>) {
    while let Some(mut b) = bio.merged.pop() {
        b.status = bio.status;
        bio_endio(b);
    }
    match bio.end_io {
        Some(f) => f(bio),
        None => drop(bio),
    }
}

/// Fail a bio with `e`
pub fn bio_io_error(mut bio: Box<Bio>, e: KernelError) {
    bio.status = Err(e);
    bio_endio(bio);
}

/// FIFO of bios linked through the bios themselves: push and pop never
/// allocate, so lists can be kept under IRQ spinlocks (Linux bio_list)
pub struct BioList {
    head: Option<Box<Bio>>,
    tail: *mut Bio,
}

// The raw tail points into the list's own boxes
unsafe impl Send for BioList {}

impl Default for BioList {
    fn default() -> Self {
        Self::new()
    }
}

impl BioList {
    pub const fn new() -> Self {
        Self {
            head: None,
            tail: core::ptr::null_mut(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    pub fn push(&mut self, mut bio: Box<Bio>) {
        bio.next = None;
        let p: *mut Bio = &raw mut *bio;
        if self.tail.is_null() {
            self.head = Some(bio);
        } else {
            unsafe { (*self.tail).next = Some(bio) };
        }
        self.tail = p;
    }

    /// Put a bio back at the front (a driver refused it)
    pub fn push_front(&mut self, mut bio: Box<Bio>) {
        bio.next = self.head.take();
        if bio.next.is_none() {
            self.tail = &raw mut *bio;
        }
        self.head = Some(bio);
    }

    /// The software queue of the first bio's request
    pub(super) fn first_ctx(&self) -> Option<usize> {
        self.head.as_ref().map(|b| usize::from(b.rq_ctx))
    }

    /// The last bio
    pub fn last_mut(&mut self) -> Option<&mut Bio> {
        // SAFETY: `tail` is null or points into the last box of the
        // list, which `&mut self` owns
        unsafe { self.tail.as_mut() }
    }

    /// The bios in order
    pub fn iter(&self) -> impl Iterator<Item = &Bio> {
        core::iter::successors(self.head.as_deref(), |b| b.next.as_deref())
    }

    pub fn pop(&mut self) -> Option<Box<Bio>> {
        let mut bio = self.head.take()?;
        self.head = bio.next.take();
        if self.head.is_none() {
            self.tail = core::ptr::null_mut();
        }
        Some(bio)
    }

    /// Move all of `other` to the end of this list, in O(1)
    pub fn append(&mut self, other: &mut BioList) {
        let Some(head) = other.head.take() else {
            return;
        };
        if self.tail.is_null() {
            self.head = Some(head);
        } else {
            // SAFETY: `tail` points into this list's last box, which
            // `&mut self` owns
            unsafe { (*self.tail).next = Some(head) };
        }
        self.tail = other.tail;
        other.tail = core::ptr::null_mut();
    }
}

// ============================================================================
// Queues
// ============================================================================

/// Limits of a queue (Linux struct queue_limits)
#[derive(Debug, Clone, Copy)]
pub struct QueueLimits {
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    /// Largest request in sectors the block layer builds (Linux
    /// max_sectors, from max_hw_sectors in blk_validate_limits)
    pub max_sectors: u32,
    /// Largest request in sectors the device takes
    pub max_hw_sectors: u32,
    pub max_segments: u32,
    pub max_segment_size: u32,
    /// Seeks cost (Linux !QUEUE_FLAG_NONROT)
    pub rotational: bool,
    /// Mask a DMA buffer's address and length must clear (Linux
    /// dma_alignment; default SECTOR_SIZE - 1)
    pub dma_alignment: u32,
    /// Smallest efficient I/O in bytes as the device reports it, 0 if it
    /// does not (`io_min` raises it to the physical block size)
    pub io_min: u32,
    /// A bio-based driver that never waits takes NOWAIT bios (Linux
    /// BLK_FEAT_NOWAIT, which blk-mq queues always have)
    pub nowait: bool,
}

impl QueueLimits {
    /// Smallest efficient I/O (Linux io_min after blk_validate_limits:
    /// at least the physical block size)
    pub fn io_min(&self) -> u32 {
        self.io_min.max(self.physical_block_size)
    }
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            logical_block_size: 512,
            physical_block_size: 512,
            max_sectors: 128, // 64 KiB
            max_hw_sectors: 128,
            max_segments: 32,
            max_segment_size: PAGE as u32,
            rotational: true,
            dma_alignment: SECTOR_SIZE as u32 - 1,
            io_min: 0,
            nowait: false,
        }
    }
}

/// A bio-based driver (Linux block_device_operations.submit_bio, as
/// brd): bios are handled in the submitter's thread context, which may
/// sleep; the driver calls `bio_endio` when each is done
pub trait BlockDriver: Send + Sync {
    fn submit_bio(&self, bio: Box<Bio>);
}

enum QueueKind {
    Bio(Arc<dyn BlockDriver>),
    Mq(BlkMq),
}

/// Request queue of a disk (Linux struct request_queue)
pub struct RequestQueue {
    pub limits: QueueLimits,
    kind: QueueKind,
    /// The device has a volatile write cache: flushes reach the driver
    /// (Linux QUEUE_FLAG_WC); without one they complete at once
    write_cache: bool,
    /// The device takes FUA writes (Linux BLK_FEAT_FUA); no driver does
    /// yet, so a FUA write to a cache is followed by a flush
    fua: bool,
    /// Post-flush state per hardware queue
    fqs: Vec<FlushQueue>,
}

impl RequestQueue {
    /// Queue of a bio-based driver
    pub fn new_bio(driver: Arc<dyn BlockDriver>, limits: QueueLimits, write_cache: bool) -> Self {
        Self {
            limits,
            kind: QueueKind::Bio(driver),
            write_cache,
            fua: false,
            fqs: flush_queues(1),
        }
    }

    /// Queue of a blk-mq driver
    pub fn new_mq(mq: BlkMq, limits: QueueLimits, write_cache: bool) -> Self {
        let fqs = flush_queues(mq.nr_hw_queues());
        Self {
            limits,
            kind: QueueKind::Mq(mq),
            write_cache,
            fua: false,
            fqs,
        }
    }

    /// It takes NOWAIT bios (Linux bdev_nowait: BLK_FEAT_NOWAIT, which
    /// every blk-mq queue has); hk's bio-based drivers without it (sd) do
    /// their I/O in the submitter
    pub fn nowait(&self) -> bool {
        match self.kind {
            QueueKind::Mq(_) => true,
            QueueKind::Bio(_) => self.limits.nowait,
        }
    }

    /// The blk-mq queues (for the driver's interrupt handler)
    pub fn mq(&self) -> Option<&BlkMq> {
        match &self.kind {
            QueueKind::Mq(m) => Some(m),
            QueueKind::Bio(_) => None,
        }
    }

    /// The disk is going away: nothing more is started (Linux
    /// blk_queue_start_drain); bio-based drivers track nothing
    pub(super) fn start_drain(&self) {
        if let QueueKind::Mq(m) = &self.kind {
            m.start_drain();
        }
    }

    /// Wait for what was started before `start_drain` (Linux
    /// blk_mq_freeze_queue_wait)
    pub(super) fn drain(&self) {
        if let QueueKind::Mq(m) = &self.kind {
            m.drain();
        }
    }

    /// Pass `bio` to the driver; a flush without a write cache completes
    /// at once, and FUA is dropped there too or, on a cache without FUA,
    /// becomes a flush after the write (Linux submit_bio_noacct,
    /// blk_insert_flush)
    fn submit(&self, mut bio: Box<Bio>) {
        if bio.op == BioOp::Flush && !self.write_cache {
            return bio_endio(bio);
        }
        // A queue that cannot honor NOWAIT refuses it (Linux
        // submit_bio_noacct: not_supported, BLK_STS_NOTSUPP)
        if bio.flags.contains(BioFlags::NOWAIT) && !self.nowait() {
            return bio_io_error(bio, KernelError::OperationNotSupported);
        }
        if bio.flags.contains(BioFlags::FUA) && !self.fua {
            bio.flags.remove(BioFlags::FUA);
            if self.write_cache {
                return self.postflush(bio);
            }
        }
        self.submit_plugged(bio);
    }

    fn dispatch(&self, bio: Box<Bio>) {
        match &self.kind {
            QueueKind::Bio(d) => d.submit_bio(bio),
            QueueKind::Mq(m) => m.submit(bio),
        }
    }

    /// A submitted bio: on the task's plug if it has one, the queue is
    /// blk-mq and it is no flush (Linux blk_mq_submit_bio), else
    /// dispatched
    fn submit_plugged(&self, bio: Box<Bio>) {
        let bio = match self.kind {
            QueueKind::Mq(_) if bio.op != BioOp::Flush => match super::plug::hold(self, bio) {
                Ok(()) => return,
                Err(b) => b,
            },
            _ => bio,
        };
        self.dispatch(bio);
    }
}

/// How long written data may wait for others' data before its flush
/// goes out anyway (Linux FLUSH_PENDING_TIMEOUT, 5 s)
const FLUSH_PENDING_TIMEOUT_NS: u64 = 5_000_000_000;

/// One hardware queue's post-flush state (Linux struct blk_flush_queue,
/// one per hctx): FUA writes whose data is done share flushes
pub(super) struct FlushQueue(IrqSpinlock<FqState>);

struct FqState {
    /// Writes whose data is done, waiting for the next flush (Linux
    /// flush_queue[flush_pending_idx])
    pending: BioList,
    /// When the first of `pending` came (Linux flush_pending_since)
    since: u64,
    /// Writes the flush in flight serves (Linux
    /// flush_queue[flush_running_idx])
    running: BioList,
    /// FUA writes whose data is in flight (Linux flush_data_in_flight)
    data_in_flight: usize,
    /// The flush, allocated with the queue, while not in flight (Linux
    /// fq->flush_rq)
    flush: Option<Box<Bio>>,
}

impl FlushQueue {
    fn new() -> Self {
        Self(IrqSpinlock::new(FqState {
            pending: BioList::new(),
            since: 0,
            running: BioList::new(),
            data_in_flight: 0,
            flush: Some(Bio::new(BioOp::Flush, 0)),
        }))
    }
}

/// One flush queue per hardware queue (one for a bio-based queue)
fn flush_queues(n: usize) -> Vec<FlushQueue> {
    (0..n.max(1)).map(|_| FlushQueue::new()).collect()
}

impl FqState {
    /// The flush to send, if one should go now (Linux blk_kick_flush):
    /// none in flight (C1), writes waiting, and no FUA data in flight
    /// that it could also serve (C2) unless the oldest waited too long
    /// (C3). Its writes move to `running`; the flush carries its flush
    /// queue and `q`, the queue that owns it
    fn kick(&mut self, fq: &FlushQueue, q: usize) -> Option<Box<Bio>> {
        if self.flush.is_none() || self.pending.is_empty() {
            return None;
        }
        if self.data_in_flight > 0
            && crate::time::monotonic_ns().saturating_sub(self.since) < FLUSH_PENDING_TIMEOUT_NS
        {
            return None;
        }
        self.running = core::mem::take(&mut self.pending);
        let mut f = self.flush.take()?;
        f.status = Ok(());
        f.end_io = Some(fq_flush_done);
        f.private = core::ptr::from_ref(fq) as usize;
        f.plug_q = q;
        Some(f)
    }
}

/// Send a flush `kick` picked (no flush queue lock held)
fn send_flush(f: Option<Box<Bio>>) {
    if let Some(f) = f {
        // SAFETY: `kick` took `plug_q` from a write's live queue, whose
        // disk outlives the bios submitted to it, this flush's writes
        // among them
        let q = unsafe { &*(f.plug_q as *const RequestQueue) };
        // A blk-mq dispatch only takes IRQ-safe queue locks: fine in
        // hardirq
        q.dispatch(f);
    }
}

impl RequestQueue {
    /// A FUA write on a cache without FUA: the write, then a flush it
    /// shares with the writes done meanwhile, then the owner's
    /// completion with the first error (Linux blk-flush.c: REQ_FSEQ_DATA
    /// | REQ_FSEQ_POSTFLUSH through the submitting CPU's hctx flush
    /// queue). The sequence is allocated here, in the submitter's
    /// context, so completions allocate nothing.
    fn postflush(&self, mut bio: Box<Bio>) {
        let h = self
            .mq()
            .map_or(0, BlkMq::this_hctx)
            .min(self.fqs.len() - 1);
        let seq = box_nofail(FlushSeq {
            end_io: bio.end_io.take(),
            private: bio.private,
            q: core::ptr::from_ref(self) as usize,
            h,
        });
        bio.end_io = Some(flushseq_data_done);
        bio.private = Box::into_raw(seq) as usize;
        self.fqs[h].0.lock().data_in_flight += 1;
        self.dispatch(bio);
    }
}

/// A FUA write's sequence, owned by the write until it ends
struct FlushSeq {
    /// The write's own completion, restored before it runs
    end_io: Option<EndIo>,
    private: usize,
    /// Address of its queue (which outlives it) and its flush queue
    /// there
    q: usize,
    h: usize,
}

/// The data of a post-flush write is done (any context): a failed write
/// ends now, a good one waits for the next flush (Linux
/// mq_flush_data_end_io, blk_flush_complete_seq)
fn flushseq_data_done(bio: Box<Bio>) {
    // SAFETY: `postflush` made `private` a leaked FlushSeq, owned by this
    // write until it ends
    let (q, h) = unsafe {
        let seq = &*(bio.private as *const FlushSeq);
        (seq.q, seq.h)
    };
    // SAFETY: the queue outlives its bios (FlushSeq.q)
    let rq = unsafe { &*(q as *const RequestQueue) };
    let fq = &rq.fqs[h];
    let failed = bio.status.is_err();
    let (f, bio) = {
        let mut st = fq.0.lock();
        st.data_in_flight -= 1;
        let bio = if failed {
            Some(bio)
        } else {
            if st.pending.is_empty() {
                st.since = crate::time::monotonic_ns();
            }
            st.pending.push(bio);
            None
        };
        (st.kick(fq, q), bio)
    };
    send_flush(f);
    if let Some(bio) = bio {
        flushseq_end(bio);
    }
}

/// A shared flush is done (any context): the writes it served end, with
/// its error if any, and the next goes out if writes wait (Linux
/// flush_end_io)
fn fq_flush_done(f: Box<Bio>) {
    // SAFETY: `kick` made `private` the flush queue, in its queue
    let fq = unsafe { &*(f.private as *const FlushQueue) };
    let (status, q) = (f.status, f.plug_q);
    let (mut done, next) = {
        let mut st = fq.0.lock();
        st.flush = Some(f);
        let done = core::mem::take(&mut st.running);
        (done, st.kick(fq, q))
    };
    send_flush(next);
    while let Some(mut bio) = done.pop() {
        bio.status = status;
        flushseq_end(bio);
    }
}

/// Give the write its own completion back and run it
fn flushseq_end(mut bio: Box<Bio>) {
    // SAFETY: `postflush` made `private` the leaked sequence, which ends
    // with the write here
    let seq = unsafe { Box::from_raw(bio.private as *mut FlushSeq) };
    bio.end_io = seq.end_io;
    bio.private = seq.private;
    bio_endio(bio);
}

// ============================================================================
// Disks and block devices
// ============================================================================

/// What a disk's `open_mutex` guards beyond serializing opens,
/// releases and rescans
#[derive(Default)]
pub(super) struct OpenState {
    /// Partitions currently open (Linux open_partitions)
    pub(super) open_partitions: u32,
}

/// A disk (Linux struct gendisk)
/// Next disk sequence number (Linux diskseq: an atomic64 counter; only
/// uniqueness matters)
static DISKSEQ: AtomicU64 = AtomicU64::new(1);

pub struct Disk {
    pub major: DevMajor,
    pub first_minor: DevMinor,
    /// Minors reserved: 1 + the most partitions (1 = no partitions)
    pub minors: u16,
    pub name: String,
    /// Size in sectors, fixed at creation (no resize yet)
    capacity: u64,
    /// Write-protected, fixed before the disk is added
    ro: bool,
    pub queue: RequestQueue,
    pub bdi: Arc<BdiWriteback>,
    /// Opens, releases and rescans (Linux open_mutex), and the state
    /// they share
    pub(super) open_mutex: crate::sync::Mutex<OpenState>,
    /// Sequence number, unique for the boot, set at allocation (Linux
    /// diskseq)
    pub seq: u64,
    /// Driver state freed with the disk, after its last reference
    /// (Linux private_data with fops->free_disk: a driver's disk index)
    pub private: spin::Once<Box<dyn core::any::Any + Send + Sync>>,
}

impl Disk {
    pub fn new(
        major: DevMajor,
        first_minor: DevMinor,
        minors: u16,
        name: String,
        capacity: u64,
        queue: RequestQueue,
        ro: bool,
    ) -> Result<Arc<Self>, KernelError> {
        let dev = DevId::new(major, first_minor);
        let bdi = bdi_register(dev);
        try_arc(Self {
            major,
            first_minor,
            minors,
            name,
            capacity,
            ro,
            queue,
            bdi,
            open_mutex: crate::sync::Mutex::new(OpenState::default()),
            seq: DISKSEQ.fetch_add(1, Ordering::Relaxed),
            private: spin::Once::new(),
        })
        .inspect_err(|_| bdi_unregister(dev))
    }

    /// Capacity in sectors
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    pub fn ro(&self) -> bool {
        self.ro
    }

    pub fn devt(&self) -> DevId {
        DevId::new(self.major, self.first_minor)
    }
}

/// The whole disk or one partition (Linux struct block_device)
pub struct BlockDevice {
    pub disk: Arc<Disk>,
    /// 0 = the whole disk
    pub partno: u16,
    /// First sector on the disk
    pub start: u64,
    /// Size in sectors, fixed at creation
    nr_sects: u64,
    pub dev: DevId,
    pub name: String,
    /// Open files (Linux bd_openers): changed only under the disk's
    /// `open_mutex`, an atomic because it lives here, as in Linux
    openers: AtomicU32,
    /// Soft block size (Linux i_blkbits of the bdev inode, BLKBSZGET):
    /// set under the disk's `open_mutex`, read lock-free
    bsize: AtomicU32,
    /// Removed (hot unplug or partition rescan): I/O fails
    dead: AtomicBool,
    /// The device's inode in the bdev pseudo filesystem: its page cache
    /// (Linux bd_mapping) serves device-node I/O and filesystem metadata
    pub bd_inode: Arc<crate::fs::Inode>,
    /// Its device in the block class (Linux bd_device); weak: the
    /// device's data is this block device, and the class keeps it
    /// while registered
    pub kdev: spin::Once<alloc::sync::Weak<crate::base::Device>>,
}

impl BlockDevice {
    pub fn new(disk: Arc<Disk>, partno: u16, start: u64, nr_sects: u64, name: String) -> Self {
        let dev = DevId::new(disk.major, disk.first_minor + partno);
        Self {
            disk,
            partno,
            start,
            nr_sects,
            dev,
            name,
            openers: AtomicU32::new(0),
            bsize: AtomicU32::new(512),
            dead: AtomicBool::new(false),
            bd_inode: crate::fs::blkdev_ops::bdev_inode(dev, nr_sects << SECTOR_SHIFT),
            kdev: spin::Once::new(),
        }
    }

    /// Size in sectors
    pub fn nr_sects(&self) -> u64 {
        self.nr_sects
    }

    /// Size in bytes
    pub fn capacity(&self) -> u64 {
        self.nr_sects() << SECTOR_SHIFT
    }

    pub fn dev_id(&self) -> DevId {
        self.dev
    }

    pub fn logical_block_size(&self) -> u32 {
        self.disk.queue.limits.logical_block_size
    }

    pub fn physical_block_size(&self) -> u32 {
        self.disk.queue.limits.physical_block_size
    }

    /// Linux bdev_dma_alignment
    pub fn dma_alignment(&self) -> u32 {
        self.disk.queue.limits.dma_alignment
    }

    /// Linux bdev_io_min
    pub fn io_min(&self) -> u32 {
        self.disk.queue.limits.io_min()
    }

    pub fn ro(&self) -> bool {
        self.disk.ro()
    }

    pub fn block_size(&self) -> u32 {
        self.bsize.load(Ordering::Relaxed)
    }

    /// BLKBSZSET (Linux set_blocksize): a power of two from the logical
    /// block size to BLK_MAX_BLOCK_SIZE; under `open_mutex`, so it never
    /// interleaves with the first open setting the initial size
    pub fn set_block_size(&self, size: i32) -> Result<(), KernelError> {
        let lbs = self.logical_block_size() as i32;
        if !(lbs..=BLK_MAX_BLOCK_SIZE).contains(&size) || !(size as u32).is_power_of_two() {
            return Err(KernelError::InvalidArgument);
        }
        let _g = self.disk.open_mutex.lock();
        self.bsize.store(size as u32, Ordering::Relaxed);
        Ok(())
    }

    /// Initial soft block size: the largest power of two up to a page
    /// that divides the size (Linux set_init_blocksize)
    fn init_block_size(&self) {
        let size = self.capacity();
        let mut bs = u64::from(self.logical_block_size());
        while bs < PAGE as u64 && size & bs == 0 {
            bs <<= 1;
        }
        self.bsize.store(bs as u32, Ordering::Relaxed);
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    pub fn mark_dead(&self) {
        self.dead.store(true, Ordering::Release);
    }

    /// A file opened the device (Linux blkdev_get_whole/_part)
    pub fn open(&self) -> Result<(), KernelError> {
        let mut st = self.disk.open_mutex.lock();
        // Checked under open_mutex: a rescan or removal that replaced
        // this device (it holds the mutex) is seen, so an open never
        // binds to a removed partition
        if self.is_dead() {
            return Err(KernelError::NoDeviceOrAddress);
        }
        if self.openers.fetch_add(1, Ordering::Relaxed) == 0 {
            self.init_block_size();
            if self.partno != 0 {
                st.open_partitions += 1;
            }
        }
        Ok(())
    }

    /// Open the device for the kernel (a mount, active swap; Linux
    /// bdev_file_open_by_dev): counted like an open file, so a rescan
    /// sees the partition in use, until the handle is dropped
    pub fn open_handle(self: &Arc<Self>) -> Result<BdevHandle, KernelError> {
        self.open()?;
        Ok(BdevHandle(self.clone()))
    }

    /// The last reference of an open file went away; the last opener
    /// writes the cache back and drops it (Linux blkdev_put_whole ->
    /// blkdev_flush_mapping: sync_blockdev + kill_bdev), under
    /// open_mutex, so the next opener reads the disk
    pub fn release(&self) {
        let mut st = self.disk.open_mutex.lock();
        if self.openers.fetch_sub(1, Ordering::Relaxed) == 1 {
            let _ = sync_blockdev(self);
            crate::mm::filemap::invalidate(&self.bd_inode);
            if self.partno != 0 {
                st.open_partitions -= 1;
            }
        }
    }
}

/// A kernel open of a block device (`BlockDevice::open_handle`)
pub struct BdevHandle(Arc<BlockDevice>);

impl BdevHandle {
    pub fn bdev(&self) -> &Arc<BlockDevice> {
        &self.0
    }
}

impl core::ops::Deref for BdevHandle {
    type Target = BlockDevice;
    fn deref(&self) -> &BlockDevice {
        &self.0
    }
}

impl Drop for BdevHandle {
    fn drop(&mut self) {
        // Host tests make superblocks but never open devices (and
        // cannot sleep on open_mutex)
        #[cfg(not(test))]
        self.0.release();
    }
}

// ============================================================================
// Registry (dev_t -> block device)
// ============================================================================

/// Every block device by dev_t. Global like Linux's bdev lookup (one
/// map of device numbers; reads are rare: open, mount, swapon)
pub static BLKDEV_REGISTRY: RwLock<BTreeMap<DevId, Arc<BlockDevice>>> =
    RwLock::new(BTreeMap::new());

pub fn register_bdev(bdev: Arc<BlockDevice>) -> Result<(), KernelError> {
    // The device's inode does I/O on this device only (never a later
    // one with the same number)
    bdev.bd_inode
        .set_private(try_arc(crate::fs::blkdev_ops::BdevOwner(Arc::downgrade(
            &bdev,
        )))?);
    let mut r = BLKDEV_REGISTRY.write();
    if r.contains_key(&bdev.dev) {
        return Err(KernelError::AlreadyExists);
    }
    r.insert(bdev.dev, bdev);
    Ok(())
}

/// Remove one block device; I/O on it fails from now on, and its page
/// cache goes without writeback, unmapped from every mapping (Linux
/// del_gendisk / blk_drop_partitions: kill_bdev). Sleeps.
pub fn unregister_bdev(dev: DevId) -> Option<Arc<BlockDevice>> {
    let b = BLKDEV_REGISTRY.write().remove(&dev)?;
    b.mark_dead();
    crate::mm::filemap::unmap_mapping_range(&b.bd_inode.i_data, 0);
    crate::mm::filemap::invalidate(&b.bd_inode);
    Some(b)
}

pub fn get_blkdev(id: DevId) -> Option<Arc<BlockDevice>> {
    BLKDEV_REGISTRY.read().get(&id).cloned()
}

/// The block devices of `disk`, whole disk first
pub fn disk_bdevs(disk: &Arc<Disk>) -> Vec<Arc<BlockDevice>> {
    BLKDEV_REGISTRY
        .read()
        .values()
        .filter(|b| Arc::ptr_eq(&b.disk, disk))
        .cloned()
        .collect()
}

/// Forget a disk's writeback state (Linux del_gendisk, with genhd)
pub(super) fn disk_release(disk: &Disk) {
    bdi_unregister(disk.devt());
}

// ============================================================================
// Submission
// ============================================================================

/// Submit `bio` for `bdev` (Linux submit_bio): checked against the end
/// of the device, remapped to the disk; completes through `end_io`. The
/// caller keeps `bdev` (so its disk and queue) until then.
pub fn submit_bio(bdev: &BlockDevice, mut bio: Box<Bio>) {
    // A removed disk's I/O fails with EIO (Linux bio_queue_enter on a
    // dead disk: bio_io_error)
    if bdev.is_dead() {
        return bio_io_error(bio, KernelError::Io);
    }
    if bio.op != BioOp::Flush {
        let end = bio.sector.checked_add(bio.sectors());
        if end.is_none_or(|e| e > bdev.nr_sects()) {
            return bio_io_error(bio, KernelError::Io);
        }
        bio.sector += bdev.start;
    }
    bdev.disk.queue.submit(bio);
}

/// What `submit_bio_wait` waits on; lives on the waiter's stack
struct Waiter {
    done: Completion,
    bio: AtomicPtr<Bio>,
}

/// `end_io` of `submit_bio_wait`: hand the bio back, then wake (hardirq
/// safe; after `complete` the waiter may return, so nothing follows)
fn wait_endio(bio: Box<Bio>) {
    let w = unsafe { &*(bio.private as *const Waiter) };
    w.bio.store(Box::into_raw(bio), Ordering::Release);
    w.done.complete();
}

/// Submit and sleep until done (Linux submit_bio_wait); returns the bio
/// (its segments) and the result.
pub fn submit_bio_wait(
    bdev: &BlockDevice,
    mut bio: Box<Bio>,
) -> (Box<Bio>, Result<(), KernelError>) {
    let w = Waiter {
        done: Completion::new(),
        bio: AtomicPtr::new(core::ptr::null_mut()),
    };
    bio.end_io = Some(wait_endio);
    bio.private = &raw const w as usize;
    submit_bio(bdev, bio);
    w.done.wait();
    let mut bio = unsafe { Box::from_raw(w.bio.load(Ordering::Acquire)) };
    bio.end_io = None;
    let st = bio.status;
    (bio, st)
}

// ============================================================================
// Synchronous I/O helpers (bounce through frames)
// ============================================================================

/// Frames of a bounce buffer, freed on drop
struct Bounce(Vec<u64>);

impl Bounce {
    fn new(len: usize) -> Result<Self, KernelError> {
        let n = len.div_ceil(PAGE);
        let mut b = Self(Vec::with_capacity(n));
        for _ in 0..n {
            b.0.push(
                crate::FRAME_ALLOCATOR
                    .alloc()
                    .ok_or(KernelError::OutOfMemory)?,
            );
        }
        Ok(b)
    }

    fn ptr(&self, off: usize) -> *mut u8 {
        unsafe { crate::arch::phys_to_virt(self.0[off / PAGE]).add(off % PAGE) }
    }

    fn copy_in(&self, src: &[u8]) {
        for (i, c) in src.chunks(PAGE).enumerate() {
            unsafe { core::ptr::copy_nonoverlapping(c.as_ptr(), self.ptr(i * PAGE), c.len()) };
        }
    }

    fn copy_out(&self, dst: &mut [u8]) {
        for (i, c) in dst.chunks_mut(PAGE).enumerate() {
            unsafe { core::ptr::copy_nonoverlapping(self.ptr(i * PAGE), c.as_mut_ptr(), c.len()) };
        }
    }
}

impl Drop for Bounce {
    fn drop(&mut self) {
        for &f in &self.0 {
            crate::FRAME_ALLOCATOR.free(f);
        }
    }
}

/// Largest synchronous request in bytes (within the queue limits)
fn max_io(bdev: &BlockDevice) -> usize {
    let l = &bdev.disk.queue.limits;
    let by_segs = l.max_segments as usize * (l.max_segment_size as usize).min(PAGE);
    ((l.max_sectors as usize) << SECTOR_SHIFT)
        .min(by_segs)
        .min(64 * 1024)
}

/// Add `len` bytes of `frame` from `off` as segments of at most the
/// queue's segment size
fn add_frame(bio: &mut Bio, frame: u64, off: usize, len: usize, seg_max: usize) {
    let mut o = 0;
    while o < len {
        let n = (len - o).min(seg_max);
        bio.add_seg(frame, off + o, n);
        o += n;
    }
}

/// Read or write `buf` (a multiple of 512 bytes) at `sector` of `bdev`,
/// synchronously, through bounce frames
pub fn bdev_rw(
    bdev: &BlockDevice,
    op: BioOp,
    sector: u64,
    buf: &mut [u8],
) -> Result<(), KernelError> {
    if !buf.len().is_multiple_of(SECTOR_SIZE as usize) {
        return Err(KernelError::InvalidArgument);
    }
    let chunk = max_io(bdev);
    let seg_max = bdev.disk.queue.limits.max_segment_size as usize;
    for (i, part) in buf.chunks_mut(chunk).enumerate() {
        let bounce = Bounce::new(part.len())?;
        if op == BioOp::Write {
            bounce.copy_in(part);
        }
        let s = sector + ((i * chunk) as u64 >> SECTOR_SHIFT);
        let mut bio = Bio::new(op, s);
        for (k, &f) in bounce.0.iter().enumerate() {
            let len = (part.len() - k * PAGE).min(PAGE);
            add_frame(&mut bio, f, 0, len, seg_max);
        }
        submit_bio_wait(bdev, bio).1?;
        if op == BioOp::Read {
            bounce.copy_out(part);
        }
    }
    Ok(())
}

/// Read or write one page frame at `sector` (zero-copy; a page past the
/// end of the device is cut short, its tail zeroed on reads)
pub fn bdev_rw_frame(
    bdev: &BlockDevice,
    op: BioOp,
    sector: u64,
    frame: u64,
) -> Result<(), KernelError> {
    let left = bdev.nr_sects().saturating_sub(sector) << SECTOR_SHIFT;
    let len = (PAGE as u64).min(left) as usize;
    if len == 0 {
        return Err(KernelError::Io);
    }
    if len < PAGE && op == BioOp::Read {
        // SAFETY: `frame` is a whole direct-mapped page frame the caller
        // holds for this I/O (a locked page-cache or swap-cache page), the
        // same frame the bios below hand the device to fill by DMA; the
        // CPU zeroes the part past the device's end, `len..PAGE`, inside it
        unsafe { core::ptr::write_bytes(crate::arch::phys_to_virt(frame).add(len), 0, PAGE - len) };
    }
    // One bio per piece the queue limits allow (segments of at most
    // max_segment_size, at most max_segments of them)
    let seg_max = bdev.disk.queue.limits.max_segment_size as usize;
    let chunk = max_io(bdev).min(PAGE);
    let mut off = 0;
    while off < len {
        let n = chunk.min(len - off);
        let mut bio = Bio::new(op, sector + (off as u64 >> SECTOR_SHIFT));
        add_frame(&mut bio, frame, off, n, seg_max);
        submit_bio_wait(bdev, bio).1?;
        off += n;
    }
    Ok(())
}

/// Read or write page `idx` of the device from/to `buf` (a page; the
/// part past the end of the device is skipped, zeroed on reads)
pub fn bdev_rw_page(
    bdev: &BlockDevice,
    op: BioOp,
    idx: u64,
    buf: &mut [u8],
) -> Result<(), KernelError> {
    let pos = idx * PAGE as u64;
    let len = (buf.len() as u64).min(bdev.capacity().saturating_sub(pos)) as usize;
    if len == 0 {
        return Err(KernelError::Io);
    }
    if op == BioOp::Read {
        buf[len..].fill(0);
    }
    bdev_rw_bytes(bdev, op, pos, &mut buf[..len])
}

/// Read or write `buf` at byte offset `pos`, any alignment: the I/O is
/// in logical blocks (a 4Kn disk takes no 512-byte request), a partial
/// block read first, then rewritten
pub fn bdev_rw_bytes(
    bdev: &BlockDevice,
    op: BioOp,
    pos: u64,
    buf: &mut [u8],
) -> Result<(), KernelError> {
    let lbs = (bdev.logical_block_size() as usize).max(SECTOR_SIZE as usize);
    let head = pos as usize % lbs;
    let start = pos - head as u64;
    let first = start / SECTOR_SIZE;
    if head == 0 && buf.len().is_multiple_of(lbs) {
        return bdev_rw(bdev, op, first, buf);
    }
    let span = (head + buf.len()).next_multiple_of(lbs);
    let mut tmp = alloc::vec![0u8; span];
    bdev_rw(bdev, BioOp::Read, first, &mut tmp)?;
    if op == BioOp::Read {
        buf.copy_from_slice(&tmp[head..head + buf.len()]);
        return Ok(());
    }
    tmp[head..head + buf.len()].copy_from_slice(buf);
    bdev_rw(bdev, BioOp::Write, first, &mut tmp)
}

/// Write the device's dirty cache pages and wait (Linux sync_blockdev)
pub fn sync_blockdev(bdev: &BlockDevice) -> Result<(), KernelError> {
    crate::mm::filemap::write_and_wait(&bdev.bd_inode)
}

/// The page-cache inode of every block device (drop_caches, reclaim)
pub fn all_bdev_inodes() -> Vec<Arc<crate::fs::Inode>> {
    BLKDEV_REGISTRY
        .read()
        .values()
        .map(|b| b.bd_inode.clone())
        .collect()
}

/// `f` on each block device's page-cache inode until it returns false,
/// allocating nothing (reclaim): the reference is taken under the
/// registry lock, `f` runs with no lock held
pub fn for_each_bdev_inode(f: &mut dyn FnMut(&Arc<crate::fs::Inode>) -> bool) {
    let mut i = 0;
    loop {
        let inode = BLKDEV_REGISTRY
            .read()
            .values()
            .nth(i)
            .map(|b| b.bd_inode.clone());
        let Some(inode) = inode else {
            return;
        };
        if !f(&inode) {
            return;
        }
        i += 1;
    }
}

/// Write back every block device's cache (sync(2): Linux sync_bdevs)
pub fn sync_bdevs() {
    let all: Vec<Arc<BlockDevice>> = BLKDEV_REGISTRY.read().values().cloned().collect();
    for b in all {
        let _ = sync_blockdev(&b);
    }
}

/// Flush the disk's volatile write cache (Linux blkdev_issue_flush)
pub fn blkdev_issue_flush(bdev: &BlockDevice) -> Result<(), KernelError> {
    submit_bio_wait(bdev, Bio::new(BioOp::Flush, 0)).1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bio(sector: u64) -> Box<Bio> {
        Bio::new(BioOp::Read, sector)
    }

    #[test]
    fn bio_list_fifo() {
        let mut l = BioList::new();
        assert!(l.pop().is_none());
        for s in 0..4 {
            l.push(bio(s));
        }
        l.push_front(bio(9));
        let mut o = BioList::new();
        o.push(bio(5));
        l.append(&mut o);
        assert!(o.is_empty());
        let order: Vec<u64> = core::iter::from_fn(|| l.pop()).map(|b| b.sector).collect();
        assert_eq!(order, [9, 0, 1, 2, 3, 5]);
        assert!(l.is_empty());
        l.push_front(bio(7));
        l.push(bio(8));
        assert_eq!(l.pop().unwrap().sector, 7);
        assert_eq!(l.pop().unwrap().sector, 8);
        assert!(l.pop().is_none());
    }

    /// A bio-based driver that logs each bio's operation and flags, and
    /// fails the ones in `fail`
    struct LogDrv {
        log: Mutex<Vec<(BioOp, BioFlags)>>,
        fail: Vec<BioOp>,
    }

    impl BlockDriver for LogDrv {
        fn submit_bio(&self, mut bio: Box<Bio>) {
            self.log.lock().push((bio.op, bio.flags));
            if self.fail.contains(&bio.op) {
                bio.status = Err(KernelError::Io);
            }
            bio_endio(bio);
        }
    }

    /// The owner's view of a completion: (calls, last status)
    static DONE: Mutex<(u32, Option<Result<(), KernelError>>)> = Mutex::new((0, None));

    fn owner_done(bio: Box<Bio>) {
        assert_eq!(bio.private, 77);
        let mut d = DONE.lock();
        d.0 += 1;
        d.1 = Some(bio.status);
    }

    /// One FUA write through a queue: what the driver saw and what the
    /// owner got
    fn fua_write(
        write_cache: bool,
        fail: Vec<BioOp>,
    ) -> (
        Vec<(BioOp, BioFlags)>,
        (u32, Option<Result<(), KernelError>>),
    ) {
        let drv = Arc::new(LogDrv {
            log: Mutex::new(Vec::new()),
            fail,
        });
        let q = RequestQueue::new_bio(drv.clone(), QueueLimits::default(), write_cache);
        *DONE.lock() = (0, None);
        let mut b = Bio::new(BioOp::Write, 8);
        b.flags = BioFlags::FUA;
        b.end_io = Some(owner_done);
        b.private = 77;
        q.submit(b);
        let log = drv.log.lock().clone();
        (log, *DONE.lock())
    }

    #[test]
    fn fua_becomes_postflush() {
        let w = (BioOp::Write, BioFlags::empty());
        let f = (BioOp::Flush, BioFlags::empty());
        // A cache without FUA: the write, then a flush, then the owner
        let (log, done) = fua_write(true, Vec::new());
        assert_eq!(log, [w, f]);
        assert_eq!(done, (1, Some(Ok(()))));
        // No cache: FUA means nothing
        let (log, done) = fua_write(false, Vec::new());
        assert_eq!(log, [w]);
        assert_eq!(done, (1, Some(Ok(()))));
        // A failed write is not flushed; a failed flush fails the write
        let (log, done) = fua_write(true, alloc::vec![BioOp::Write]);
        assert_eq!(log, [w]);
        assert_eq!(done, (1, Some(Err(KernelError::Io))));
        let (log, done) = fua_write(true, alloc::vec![BioOp::Flush]);
        assert_eq!(log, [w, f]);
        assert_eq!(done, (1, Some(Err(KernelError::Io))));
    }

    /// A bio-based driver that logs each bio and holds it for the test
    /// to end
    struct HoldDrv {
        held: Mutex<Vec<Box<Bio>>>,
        log: Mutex<Vec<BioOp>>,
    }

    impl BlockDriver for HoldDrv {
        fn submit_bio(&self, bio: Box<Bio>) {
            self.log.lock().push(bio.op);
            self.held.lock().push(bio);
        }
    }

    static OWNED: Mutex<Vec<u64>> = Mutex::new(Vec::new());

    fn owner_seen(bio: Box<Bio>) {
        assert!(bio.status.is_ok());
        OWNED.lock().push(bio.sector);
    }

    #[test]
    fn postflushes_coalesce() {
        let drv = Arc::new(HoldDrv {
            held: Mutex::new(Vec::new()),
            log: Mutex::new(Vec::new()),
        });
        let q = RequestQueue::new_bio(drv.clone(), QueueLimits::default(), true);
        let write = |sector| {
            let mut b = Bio::new(BioOp::Write, sector);
            b.flags = BioFlags::FUA;
            b.end_io = Some(owner_seen);
            q.submit(b);
        };
        // End the held bio for `sector` (a flush is at sector 0)
        let end = |sector: u64| {
            let b = {
                let mut h = drv.held.lock();
                let i = h.iter().position(|b| b.sector == sector).unwrap();
                h.remove(i)
            };
            bio_endio(b);
        };
        let (w, f) = (BioOp::Write, BioOp::Flush);
        write(8);
        write(16);
        end(8);
        // 16's data is in flight: 8 waits to share its flush
        assert_eq!(*drv.log.lock(), [w, w]);
        end(16);
        assert_eq!(*drv.log.lock(), [w, w, f]);
        // One flush at a time: 24 waits for the next
        write(24);
        end(24);
        assert_eq!(*drv.log.lock(), [w, w, f, w]);
        end(0);
        assert_eq!(*OWNED.lock(), [8, 16]);
        assert_eq!(*drv.log.lock(), [w, w, f, w, f]);
        end(0);
        assert_eq!(*OWNED.lock(), [8, 16, 24]);
        assert!(drv.held.lock().is_empty());
    }

    #[test]
    fn segments_split_at_seg_max() {
        let mut b = bio(0);
        add_frame(&mut b, 0x1000, 0, 4096, 1536);
        let lens: Vec<usize> = b.segs.iter().map(|s| s.len).collect();
        assert_eq!(lens, [1536, 1536, 1024]);
        assert_eq!(b.sectors(), 8);
    }
}
