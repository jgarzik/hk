//! Direct I/O on a block device (Linux block/fops.c: blkdev_direct_IO,
//! __blkdev_direct_IO_simple, __blkdev_direct_IO; block/bio.c
//! bio_iov_iter_get_pages): bios between the device and the caller's
//! pinned pages, no copy.
//!
//! The pages are pinned a bio's worth at a time (at most `BIO_MAX_VECS`;
//! Linux bio_iov_iter_get_pages): each segment's address and length
//! checked against the queue's DMA alignment (EINVAL), the bio cut down
//! to whole logical blocks. An I/O of up to `BIO_MAX_VECS` pages pins
//! once, and a short pin shortens it (Linux __blkdev_direct_IO_simple);
//! a larger one pins for each further bio, and a failure there fails
//! the whole I/O (Linux __blkdev_direct_IO).
//!
//! Linux's block layer splits a bio to the queue limits
//! (bio_split_to_limits); hk's has no split, so a bio's pages go out as
//! hk bios cut at max_sectors, max_segments and max_segment_size, on
//! logical-block boundaries ([`Cursor::next_bio`]): the same requests.
//!
//! The large path's bios go out plugged (Linux __blkdev_direct_IO's
//! blk_start_plug): split or not, a batch reaches the device with one
//! notify, and the pins between them flush the plug if they sleep.
//!
//! Completion: each hk bio of the I/O counts down one [`DioWait`] on the
//! submitter's stack (Linux blkdev_dio.ref); its end_io (hardirq for
//! virtio-blk) keeps the first error, frees the bio and completes the
//! `Completion` if it is the last. The submitter sleeps once, then
//! dirties the pages of a read and unpins them in thread context (Linux
//! bio_release_pages; bio_check_pages_dirty defers to a work item for
//! the page lock).
//!
//! RWF_NOWAIT: an I/O needing a second bio, Linux's or one split off
//! it, is EAGAIN before anything is submitted (Linux: EAGAIN from the
//! loop, or from bio_split_rw_at on a REQ_NOWAIT bio). Its one bio is
//! NOWAIT: a queue with no free tag ends it with EAGAIN (Linux
//! REQ_NOWAIT); a queue without NOWAIT support never gets here (the
//! file refuses RWF_NOWAIT, EOPNOTSUPP).

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

use crate::fs::file::RwFlags;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::mm::gup::{PageSeg, PinnedPages};
use crate::sync::completion::Completion;
use crate::util::error::KernelError;
use crate::util::kalloc::try_box as box_try;
use crate::util::kmem::KVec;
use crate::util::seg::{step_back, trim_tail};
use crate::util::smallvec::SmallVec;

use super::blkdev::{
    Bio, BioFlags, BioOp, BioSeg, BioSegs, BlockDevice, EndIo, QueueLimits, SECTOR_SHIFT,
    submit_bio,
};

/// Most pages one bio carries (Linux BIO_MAX_VECS)
pub const BIO_MAX_VECS: usize = 256;

/// The caller's memory of a direct I/O
pub trait DioIter {
    /// A read from the device: the pages are written, then dirtied
    const READ: bool;
    /// Bytes left
    fn count(&self) -> usize;
    /// Pages the bytes left span, at most `max` (Linux iov_iter_npages)
    fn npages(&self, max: usize) -> usize;
    /// Pin the next bytes, at most `max` pages: segment memory aligned
    /// to `mem_mask` (EINVAL), the total cut to a multiple of
    /// `len_mask` + 1 (Linux bio_iov_iter_get_pages)
    fn get_pages(
        &mut self,
        max: usize,
        mem_mask: usize,
        len_mask: usize,
    ) -> Result<PinnedPages, KernelError>;
}

impl DioIter for IovDest<'_> {
    const READ: bool = true;

    fn count(&self) -> usize {
        self.len()
    }

    fn npages(&self, max: usize) -> usize {
        IovDest::npages(self, max)
    }

    fn get_pages(
        &mut self,
        max: usize,
        mem_mask: usize,
        len_mask: usize,
    ) -> Result<PinnedPages, KernelError> {
        IovDest::get_pages(self, max, mem_mask, len_mask)
    }
}

impl DioIter for IovSource<'_> {
    const READ: bool = false;

    fn count(&self) -> usize {
        self.len()
    }

    fn npages(&self, max: usize) -> usize {
        IovSource::npages(self, max)
    }

    fn get_pages(
        &mut self,
        max: usize,
        mem_mask: usize,
        len_mask: usize,
    ) -> Result<PinnedPages, KernelError> {
        IovSource::get_pages(self, max, mem_mask, len_mask)
    }
}

/// Position or length not in whole logical blocks (Linux
/// blkdev_dio_invalid)
pub fn invalid(pos: u64, count: usize, lbs: u32) -> bool {
    (pos | count as u64) & u64::from(lbs - 1) != 0
}

/// Direct I/O of `it` at byte `pos` of `b` (Linux blkdev_direct_IO): the
/// bytes done, 0 for none asked. `pos` lies within the device and `it`
/// ends at its end at the latest (the caller truncates).
pub fn direct_io<I: DioIter>(
    b: &BlockDevice,
    it: &mut I,
    pos: u64,
    flags: RwFlags,
) -> Result<usize, KernelError> {
    let count = it.count();
    if count == 0 {
        return Ok(0);
    }
    if invalid(pos, count, b.logical_block_size()) {
        return Err(KernelError::InvalidArgument);
    }
    let d = Dio::new::<I>(b, flags);
    // One extent: the device from `pos` on
    let map = [(pos, count)];
    let nr = it.npages(BIO_MAX_VECS + 1);
    if nr <= BIO_MAX_VECS {
        d.simple(it, &map, nr)
    } else {
        d.large(it, &map)
    }
}

/// A run of a file's bytes on the device: byte offset there, length
pub type Extent = (u64, usize);

/// Direct I/O of `it` through the device extents `map`, in order, which
/// cover exactly its bytes (Linux do_blockdev_direct_IO over a
/// filesystem's get_block mappings): pinned a bio's worth at a time and
/// sent as bios cut at each extent's end and at the queue limits, all
/// plugged and counted in one wait, without FUA (an O_DSYNC write is
/// the caller's generic_write_sync). `unlock` is dropped once every bio
/// is submitted, before the wait (Linux DIO_LOCKING releases a read's
/// i_rwsem there). The bytes done: a pin that faults after some were
/// sent ends it short (Linux dio_complete ignores EFAULT then); any
/// other error fails it, an I/O error included. The caller checked the
/// alignment (Linux __blockdev_direct_IO).
pub fn direct_io_map<I: DioIter, G>(
    b: &BlockDevice,
    it: &mut I,
    map: &[Extent],
    unlock: G,
) -> Result<usize, KernelError> {
    let d = Dio::new::<I>(b, RwFlags::empty());
    let (done, ret, r) = d.plugged(it, map, unlock)?;
    match ret {
        Err(KernelError::BadAddress) if done > 0 => {}
        r => r?,
    }
    r.map(|()| done)
}

/// A position in a list of extents: extent `i`, byte `at` of it
#[derive(Default)]
struct MapPos {
    i: usize,
    at: usize,
}

impl MapPos {
    /// The device byte offset here and the bytes left in its extent
    fn cur(&self, map: &[Extent]) -> Option<(u64, usize)> {
        let &(off, len) = map.get(self.i)?;
        Some((off + self.at as u64, len - self.at))
    }

    fn advance(&mut self, map: &[Extent], n: usize) {
        self.at += n;
        if map.get(self.i).is_some_and(|e| self.at >= e.1) {
            self.i += 1;
            self.at = 0;
        }
    }
}

/// A plugged I/O's bytes sent, its submission's first error and its
/// I/O's
type Outcome = (usize, Result<(), KernelError>, Result<(), KernelError>);

/// One direct I/O's fixed parts
struct Dio<'a> {
    b: &'a BlockDevice,
    op: BioOp,
    /// FUA for an O_DSYNC write (Linux dio_bio_write_op), NOWAIT for
    /// RWF_NOWAIT (Linux REQ_NOWAIT)
    bflags: BioFlags,
}

impl<'a> Dio<'a> {
    /// RWF_HIPRI is ignored by synchronous direct I/O (Linux mainline
    /// 9650b453a3d4: no polled sync I/O)
    fn new<I: DioIter>(b: &'a BlockDevice, flags: RwFlags) -> Self {
        Self::new_rw(b, !I::READ, flags - RwFlags::HIPRI)
    }

    fn new_rw(b: &'a BlockDevice, write: bool, flags: RwFlags) -> Self {
        let dsync = flags.intersects(RwFlags::DSYNC | RwFlags::SYNC);
        Self {
            b,
            op: if write { BioOp::Write } else { BioOp::Read },
            bflags: {
                let mut f = BioFlags::empty();
                f.set(BioFlags::FUA, write && dsync);
                f.set(BioFlags::NOWAIT, flags.nowait());
                f.set(BioFlags::POLLED, flags.contains(RwFlags::HIPRI));
                f
            },
        }
    }

    /// RWF_NOWAIT
    fn nowait(&self) -> bool {
        self.bflags.contains(BioFlags::NOWAIT)
    }

    /// Pin the next bio's worth of `it`, at most `max` pages
    fn pin<I: DioIter>(&self, it: &mut I, max: usize) -> Result<PinnedPages, KernelError> {
        let lbs = self.b.logical_block_size() as usize;
        it.get_pages(max, self.b.dma_alignment() as usize, lbs - 1)
    }

    /// Up to `BIO_MAX_VECS` pages, `nr` of them: pinned once (short if
    /// the pin is), one wait (Linux __blkdev_direct_IO_simple)
    fn simple<I: DioIter>(
        &self,
        it: &mut I,
        map: &[Extent],
        nr: usize,
    ) -> Result<usize, KernelError> {
        let pp = self.pin(it, nr)?;
        let w = DioWait::new();
        let sent = self.send(pp.segs(), map, &mut MapPos::default(), &w);
        let pp = self.sent(pp, &sent);
        let r = w.finish();
        drop(pp);
        let n = sent?;
        r.map(|()| n)
    }

    /// More than `BIO_MAX_VECS` pages: a bio's worth pinned and sent at a
    /// time, all counted in one wait; a pin that fails after the first
    /// fails the I/O (Linux __blkdev_direct_IO)
    fn large<I: DioIter>(&self, it: &mut I, map: &[Extent]) -> Result<usize, KernelError> {
        let (done, ret, r) = self.plugged(it, map, ())?;
        ret?;
        r.map(|()| done)
    }

    /// Every bio of `it` through `map`, plugged (`send_all`), then
    /// `unlock` dropped and the wait: (bytes sent, the submission's
    /// first error, the I/O's)
    fn plugged<I: DioIter, G>(
        &self,
        it: &mut I,
        map: &[Extent],
        unlock: G,
    ) -> Result<Outcome, KernelError> {
        // The pins of every bio sent are kept until the wait: room for
        // the usual count up front (a bio cut back to whole blocks
        // leaves a page for the next, so there may be more)
        let nr = it.npages(usize::MAX);
        let mut pins: KVec<PinnedPages> = KVec::try_with_capacity(nr.div_ceil(BIO_MAX_VECS) + 1)?;
        let w = DioWait::new();
        let mut at = MapPos::default();
        let (done, ret) = super::plug::blk_plug(|| self.send_all(it, map, &mut at, &mut pins, &w));
        drop(unlock);
        let r = w.finish();
        drop(pins);
        Ok((done, ret, r))
    }

    /// Pinned and sent a bio's worth at a time through `map` from `at`,
    /// the pins kept in `pins`; (bytes sent, the first error). A bio
    /// that could not be made after some went out stops it (the error
    /// is in `w`).
    fn send_all<I: DioIter>(
        &self,
        it: &mut I,
        map: &[Extent],
        at: &mut MapPos,
        pins: &mut KVec<PinnedPages>,
        w: &DioWait,
    ) -> (usize, Result<(), KernelError>) {
        let mut done = 0usize;
        while it.count() > 0 {
            // Room before the pin, so a sent bio's pins are always kept
            if let Err(e) = pins.try_reserve(1) {
                return (done, Err(e));
            }
            let pp = match self.pin(it, BIO_MAX_VECS) {
                Ok(pp) => pp,
                Err(e) => return (done, Err(e)),
            };
            // Another bio would follow (Linux: EAGAIN, nothing sent)
            if self.nowait() && it.count() > 0 {
                return (done, Err(KernelError::WouldBlock));
            }
            let len = pp.len();
            let sent = self.send(pp.segs(), map, at, w);
            if let Some(pp) = self.sent(pp, &sent) {
                // Room was reserved: no allocation, cannot fail
                let _ = pins.try_push(pp);
            }
            match sent {
                Ok(n) if n == len => done += n,
                Ok(n) => return (done + n, Ok(())),
                Err(e) => return (done, Err(e)),
            }
        }
        (done, Ok(()))
    }

    /// What of `pp` must stay pinned until the wait after `send` gave
    /// `sent`: the bytes sent, dirtied for a read when unpinned (Linux
    /// bio_release_pages, whatever the result); the rest is unpinned now,
    /// clean (None if nothing went out)
    fn sent(&self, mut pp: PinnedPages, sent: &Result<usize, KernelError>) -> Option<PinnedPages> {
        let n = *sent.as_ref().ok()?;
        pp.trim(pp.len() - n);
        if self.op == BioOp::Read {
            pp.set_dirty();
        }
        Some(pp)
    }

    /// Send `pp` through `map` from `at` as bios within the queue limits
    /// and the extents, each counted in `w`: the bytes sent. EAGAIN for
    /// RWF_NOWAIT if it takes more than one bio, before any is sent; an
    /// error after some were sent is left in `w`.
    fn send(
        &self,
        segs: &[PageSeg],
        map: &[Extent],
        at: &mut MapPos,
        w: &dyn BioCount,
    ) -> Result<usize, KernelError> {
        let lim = &self.b.disk.queue.limits;
        let mut cur = Cursor::default();
        let mut sent = 0usize;
        while !cur.done(segs) {
            let r = at.cur(map).ok_or(KernelError::Io).and_then(|(off, left)| {
                // No bio past the extent's end
                let l = QueueLimits {
                    max_sectors: (left >> SECTOR_SHIFT).min(lim.max_sectors as usize) as u32,
                    ..*lim
                };
                let mut bio = Bio::with_segs(self.op, off >> SECTOR_SHIFT, cur.room(segs, &l))?;
                let n = cur.next_bio(segs, &l, &mut bio.segs)?;
                Ok((bio, n))
            });
            let (mut bio, n) = match r {
                Ok(x) => x,
                Err(e) if sent == 0 => return Err(e),
                Err(e) => {
                    w.fail(e);
                    break;
                }
            };
            if self.nowait() && sent == 0 && !cur.done(segs) {
                return Err(KernelError::WouldBlock);
            }
            bio.flags = self.bflags;
            (bio.end_io, bio.private) = w.get();
            submit_bio(self.b, bio);
            at.advance(map, n);
            sent += n;
        }
        Ok(sent)
    }
}

/// What the bios of one I/O count down, synchronous (`DioWait`) or not
/// (`AsyncWait`)
trait BioCount {
    /// A bio is about to be submitted: the end_io and private word that
    /// count it down
    fn get(&self) -> (Option<EndIo>, usize);
    /// Keep `e` if it is the first error
    fn fail(&self, e: KernelError);
}

/// What the bios of one direct I/O count down (Linux struct blkdev_dio):
/// it lives on the submitter's stack, which `finish` keeps until the
/// last bio is done
struct DioWait {
    /// Bios in flight, plus one the submitter holds until `finish`
    left: AtomicU32,
    /// The first error's errno, 0 for none (Linux dio->bio.bi_status)
    err: AtomicI32,
    done: Completion,
}

impl BioCount for DioWait {
    fn get(&self) -> (Option<EndIo>, usize) {
        self.left.fetch_add(1, Ordering::Relaxed);
        (Some(dio_endio), core::ptr::from_ref(self) as usize)
    }

    fn fail(&self, e: KernelError) {
        let _ = self
            .err
            .compare_exchange(0, e.errno(), Ordering::Relaxed, Ordering::Relaxed);
    }
}

impl DioWait {
    fn new() -> Self {
        Self {
            left: AtomicU32::new(1),
            err: AtomicI32::new(0),
            done: Completion::new(),
        }
    }

    /// A bio is done (any context); the last one wakes the submitter and
    /// touches nothing after (the stack frame may be gone)
    fn put(&self) {
        if self.left.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.done.complete();
        }
    }

    /// Drop the submitter's count and sleep until every bio is done: the
    /// first error
    fn finish(&self) -> Result<(), KernelError> {
        if self.left.fetch_sub(1, Ordering::AcqRel) != 1 {
            self.done.wait();
        }
        match self.err.load(Ordering::Acquire) {
            0 => Ok(()),
            e => Err(KernelError::from_errno(e).unwrap_or(KernelError::Io)),
        }
    }
}

/// end_io of a direct I/O's bios (hardirq for virtio-blk: atomics, the
/// heap and `Completion::complete` only)
fn dio_endio(bio: Box<Bio>) {
    // SAFETY: `send` set `private` to the I/O's DioWait, which stays on
    // the submitter's stack until `finish` sees this bio's `put`
    let w = unsafe { &*(bio.private as *const DioWait) };
    if let Err(e) = bio.status {
        w.fail(e);
    }
    drop(bio);
    w.put();
}

// ============================================================================
// Asynchronous direct I/O (Linux __blkdev_direct_IO_async, and
// __blkdev_direct_IO with an async kiocb)
// ============================================================================

/// The memory and completion of an asynchronous direct I/O (Linux an
/// async kiocb with its bvec iterator): pages pinned at least as long as
/// the object lives, and the call that ends it
///
/// # Safety
/// The pieces `segs` returns are RAM frames that stay allocated (pinned)
/// and unchanged while the object lives: the block layer sends bios to
/// them and holds the object until the last one ends. `complete` may be
/// called in hardirq context: it neither sleeps nor allocates, and does
/// not drop a reference whose release could.
pub unsafe trait AsyncIo: Send + Sync {
    /// The I/O's memory: pinned pieces, in order
    fn segs(&self) -> &[PageSeg];
    /// The I/O ended (Linux ki_complete): the bytes done or the first
    /// error. Any context, hardirq included: no sleeping, no allocation
    fn complete(self: Arc<Self>, res: Result<usize, KernelError>);
}

/// What the bios of one asynchronous I/O count down (Linux struct
/// blkdev_dio of an async kiocb): on the heap, freed by the last end
struct AsyncWait {
    /// Bios in flight, plus one the submitter holds until it is done
    left: AtomicU32,
    err: AtomicI32,
    /// Bytes the bios carry (set before the submitter's count goes)
    bytes: AtomicUsize,
    io: Arc<dyn AsyncIo>,
}

impl BioCount for AsyncWait {
    fn get(&self) -> (Option<EndIo>, usize) {
        self.left.fetch_add(1, Ordering::Relaxed);
        (Some(async_endio), core::ptr::from_ref(self) as usize)
    }

    fn fail(&self, e: KernelError) {
        let _ = self
            .err
            .compare_exchange(0, e.errno(), Ordering::Relaxed, Ordering::Relaxed);
    }
}

/// Drop one count of the AsyncWait at `p`; the last ends the I/O
/// (`AsyncIo::complete`) and frees it
///
/// # Safety
/// `p` came from `Box::into_raw` in `submit_async` and the caller holds
/// one of its counts, given up here.
unsafe fn async_put(p: *const AsyncWait) {
    // SAFETY: live while the caller holds a count (the contract)
    let w = unsafe { &*p };
    if w.left.fetch_sub(1, Ordering::AcqRel) != 1 {
        return;
    }
    // SAFETY: the last count: nothing else uses it; from Box::into_raw
    let w = unsafe { Box::from_raw(p.cast_mut()) };
    let res = match w.err.load(Ordering::Acquire) {
        0 => Ok(w.bytes.load(Ordering::Relaxed)),
        e => Err(KernelError::from_errno(e).unwrap_or(KernelError::Io)),
    };
    let AsyncWait { io, .. } = *w;
    io.complete(res);
}

/// end_io of an asynchronous I/O's bios (hardirq for virtio-blk)
fn async_endio(bio: Box<Bio>) {
    let p = bio.private as *const AsyncWait;
    // SAFETY: `submit_async` set `private` to the I/O's AsyncWait and
    // took a count for this bio, which this end gives up
    let w = unsafe { &*p };
    if let Err(e) = bio.status {
        w.fail(e);
    }
    drop(bio);
    // SAFETY: as above: this bio's count
    unsafe { async_put(p) };
}

/// The pieces' memory is aligned to `mask` + 1 (Linux: every iovec's
/// base and length to the queue's dma_alignment; per page piece, as a
/// piece boundary inside an iovec is page-aligned)
fn segs_aligned(segs: &[PageSeg], mask: u32) -> bool {
    segs.iter().all(|s| (s.off | s.len) & mask == 0)
}

/// The first `count` bytes of `segs`
fn segs_prefix(segs: &[PageSeg], count: usize) -> Result<SmallVec<PageSeg, 4>, KernelError> {
    let mut out = SmallVec::try_with_capacity(segs.len())?;
    let mut left = count;
    for s in segs {
        if left == 0 {
            break;
        }
        // Within a page: lossless
        let n = (s.len as usize).min(left) as u32;
        out.push(PageSeg { len: n, ..*s });
        left -= n as usize;
    }
    Ok(out)
}

/// Start direct I/O of `count` bytes of `io`'s memory (count <= its
/// length; `pos` within the device and the I/O ending at its end at the
/// latest) without waiting (Linux __blkdev_direct_IO_async): `io`
/// completes once every bio is done, with the bytes they carry (a
/// memory that ends before `count` gives a short I/O) or the first
/// error. EINVAL for a position, length or memory the queue cannot take
/// (Linux blkdev_dio_invalid); with NOWAIT, EAGAIN if it takes more than
/// one bio. On an error nothing was sent and `io` is not completed.
pub fn submit_async(
    b: &BlockDevice,
    io: Arc<dyn AsyncIo>,
    pos: u64,
    count: usize,
    write: bool,
    flags: RwFlags,
) -> Result<(), KernelError> {
    if invalid(pos, count, b.logical_block_size()) || !segs_aligned(io.segs(), b.dma_alignment()) {
        return Err(KernelError::InvalidArgument);
    }
    let total: usize = io.segs().iter().map(|s| s.len as usize).sum();
    let short;
    let segs = if total > count {
        short = segs_prefix(io.segs(), count)?;
        &short[..]
    } else {
        io.segs()
    };
    let d = Dio::new_rw(b, write, flags);
    let w = Box::into_raw(box_try(AsyncWait {
        left: AtomicU32::new(1),
        err: AtomicI32::new(0),
        bytes: AtomicUsize::new(0),
        io: io.clone(),
    })?);
    // One extent: the device from `pos` on
    let map = [(pos, count.min(segs.iter().map(|s| s.len as usize).sum()))];
    // SAFETY: live until the submitter's count goes, below
    let wr = unsafe { &*w };
    let r = super::plug::blk_plug(|| d.send(segs, &map, &mut MapPos::default(), wr));
    match r {
        Err(e) => {
            // Nothing sent: ours alone
            // SAFETY: from Box::into_raw above, no bio holds it
            drop(unsafe { Box::from_raw(w) });
            Err(e)
        }
        Ok(n) => {
            // SAFETY: live: the submitter's count is still held
            unsafe { &*w }.bytes.store(n, Ordering::Relaxed);
            // SAFETY: the submitter's count, given up
            unsafe { async_put(w) };
            Ok(())
        }
    }
}

/// A position in pinned page pieces: piece `i`, byte `at` of it
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    i: usize,
    at: usize,
}

impl Cursor {
    /// Every byte was taken
    pub fn done(&self, segs: &[PageSeg]) -> bool {
        self.i >= segs.len()
    }

    /// Bio segments the next bio takes before its cut back to whole
    /// blocks (room to reserve)
    fn room(&self, segs: &[PageSeg], lim: &QueueLimits) -> usize {
        let mut n = 0;
        let mut c = *self;
        c.fill(segs, lim, &mut |_, grow| n += usize::from(!grow));
        n
    }

    /// Give `f` the next bio's segments of `segs`, as many as the limits
    /// allow (max_sectors, max_segments, segments of at most
    /// max_segment_size), stepping over them; the bytes. A piece
    /// physically contiguous with the last segment grows it, up to
    /// max_segment_size (Linux biovec_phys_mergeable): `f` gets it with
    /// `grow` set, and it takes no segment of its own
    fn fill(
        &mut self,
        segs: &[PageSeg],
        lim: &QueueLimits,
        f: &mut dyn FnMut(BioSeg, bool),
    ) -> usize {
        let max_bytes = (lim.max_sectors as usize) << SECTOR_SHIFT;
        let seg_max = (lim.max_segment_size as usize).max(1);
        let (mut bytes, mut nr) = (0, 0);
        // The last segment's end address and length
        let mut last: Option<(u64, usize)> = None;
        while let Some(s) = segs.get(self.i) {
            if bytes >= max_bytes {
                break;
            }
            let at = s.phys + u64::from(s.off) + self.at as u64;
            let left = (s.len as usize - self.at).min(max_bytes - bytes);
            let room = match last {
                Some((end, len)) if end == at => seg_max - len,
                _ => 0,
            };
            let grow = room > 0;
            if !grow && nr >= lim.max_segments as usize {
                break;
            }
            let n = left.min(if grow { room } else { seg_max });
            f(
                BioSeg {
                    frame: s.phys,
                    offset: s.off as usize + self.at,
                    len: n,
                },
                grow,
            );
            if !grow {
                nr += 1;
            }
            let len = if grow { last.map_or(0, |l| l.1) + n } else { n };
            last = Some((at + n as u64, len));
            bytes += n;
            self.at += n;
            if self.at == s.len as usize {
                self.i += 1;
                self.at = 0;
            }
        }
        bytes
    }

    /// The next bio's segments of `segs` into `out`: as many bytes as
    /// the limits allow (`fill`: physically contiguous pieces merged),
    /// cut back to whole logical blocks (Linux bio_split_rw_at); the
    /// bytes. EINVAL if not one block fits.
    pub fn next_bio(
        &mut self,
        segs: &[PageSeg],
        lim: &QueueLimits,
        out: &mut BioSegs,
    ) -> Result<usize, KernelError> {
        out.clear();
        let bytes = self.fill(segs, lim, &mut |s, grow| match out.last_mut() {
            Some(l) if grow => l.len += s.len,
            _ => out.push(s),
        });
        let excess = bytes % lim.logical_block_size as usize;
        step_back(|k| segs[k].len as usize, &mut self.i, &mut self.at, excess);
        trim_tail(out, excess, |s| s.len, |s, l| s.len = l, drop);
        match bytes - excess {
            0 => Err(KernelError::InvalidArgument),
            n => Ok(n),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn lim(max_sectors: u32, max_segments: u32, seg: u32, lbs: u32) -> QueueLimits {
        QueueLimits {
            logical_block_size: lbs,
            max_sectors,
            max_segments,
            max_segment_size: seg,
            ..QueueLimits::default()
        }
    }

    /// Pieces of `lens` bytes, page i at 0x2000 * (i + 1) (never
    /// contiguous), at offset `off` in the first page
    fn pieces(lens: &[u32], off: u32) -> Vec<PageSeg> {
        lens.iter()
            .enumerate()
            .map(|(i, &len)| PageSeg {
                phys: 0x2000 * (i as u64 + 1),
                off: if i == 0 { off } else { 0 },
                len,
            })
            .collect()
    }

    /// Every bio's (bytes, segment lengths) until the pieces run out
    fn bios(segs: &[PageSeg], l: &QueueLimits) -> Result<Vec<(usize, Vec<usize>)>, KernelError> {
        let mut c = Cursor::default();
        let mut out = Vec::new();
        while !c.done(segs) {
            let mut b = BioSegs::new();
            let n = c.next_bio(segs, l, &mut b)?;
            assert_eq!(n, b.iter().map(|s| s.len).sum::<usize>());
            out.push((n, b.iter().map(|s| s.len).collect()));
        }
        Ok(out)
    }

    #[test]
    fn whole_pages_by_max_sectors() {
        let segs = pieces(&[4096; 40], 0);
        let b = bios(&segs, &lim(128, 32, 4096, 512)).unwrap();
        assert_eq!(b.len(), 3);
        assert_eq!((b[0].0, b[0].1.len()), (65536, 16));
        assert_eq!((b[2].0, b[2].1.len()), (32768, 8));
    }

    #[test]
    fn segment_size_and_count() {
        let segs = pieces(&[4096, 4096], 0);
        let b = bios(&segs, &lim(1024, 4, 1536, 512)).unwrap();
        // 1536 1536 1024 | 1536: four segments, then the rest
        assert_eq!(b[0].1, [1536, 1536, 1024, 1536]);
        assert_eq!(b[1].1, [1536, 1024]);
        let segs = pieces(&[4096], 0);
        let b = bios(&segs, &lim(1024, 32, 4096, 512)).unwrap();
        assert_eq!(b[0].1, [4096]);
    }

    #[test]
    fn cut_to_logical_blocks() {
        // A 512-aligned buffer on a 4K-block disk: pieces 3584 + 512 + ...
        let segs = pieces(&[3584, 4096, 4096, 512], 512);
        let b = bios(&segs, &lim(1024, 2, 4096, 4096)).unwrap();
        // 3584 + 4096 = 7680 is cut to 4096; the rest of piece 1 goes next
        assert_eq!(b[0], (4096, alloc::vec![3584, 512]));
        assert_eq!(b[1], (4096, alloc::vec![3584, 512]));
        assert_eq!(b[2], (4096, alloc::vec![3584, 512]));
        assert_eq!(b.len(), 3);
        // One segment per bio: not one block fits
        let segs = pieces(&[3584, 512], 512);
        assert_eq!(
            bios(&segs, &lim(1024, 1, 4096, 4096)).err(),
            Some(KernelError::InvalidArgument)
        );
    }

    #[test]
    fn contiguous_pages_merge() {
        // Pages 1, 2, 3 contiguous, then 5, 6
        let segs: Vec<PageSeg> = [1u64, 2, 3, 5, 6]
            .iter()
            .map(|&p| PageSeg {
                phys: p * 0x1000,
                off: 0,
                len: 4096,
            })
            .collect();
        let b = bios(&segs, &lim(1024, 32, u32::MAX, 512)).unwrap();
        assert_eq!(b, [(20480, alloc::vec![12288, 8192])]);
        // Merged up to max_segment_size, then a segment of its own
        let b = bios(&segs, &lim(1024, 32, 8192, 512)).unwrap();
        assert_eq!(b[0].1, [8192, 4096, 8192]);
        // A merge needs no free segment: one segment holds it all
        let b = bios(&segs[..3], &lim(1024, 1, u32::MAX, 512)).unwrap();
        assert_eq!(b, [(12288, alloc::vec![12288])]);
        // max_sectors still cuts
        let b = bios(&segs[..3], &lim(16, 32, u32::MAX, 512)).unwrap();
        assert_eq!(b, [(8192, alloc::vec![8192]), (4096, alloc::vec![4096])]);
    }

    #[test]
    fn misaligned_requests() {
        assert!(!invalid(4096, 8192, 512));
        assert!(invalid(4097, 8192, 512));
        assert!(invalid(4096, 100, 512));
        assert!(invalid(512, 4096, 4096));
        assert!(!invalid(0, 0, 4096));
    }
}
