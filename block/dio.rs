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
//! loop, or from bio_split_rw_at on a REQ_NOWAIT bio).

use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use crate::fs::file::RwFlags;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::mm::gup::{PageSeg, PinnedPages};
use crate::sync::completion::Completion;
use crate::util::error::KernelError;
use crate::util::kmem::KVec;
use crate::util::seg::{step_back, trim_tail};

use super::blkdev::{
    Bio, BioFlags, BioOp, BioSeg, BioSegs, BlockDevice, QueueLimits, SECTOR_SHIFT, submit_bio,
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
    let d = Dio::new::<I>(b, pos, flags);
    let nr = it.npages(BIO_MAX_VECS + 1);
    if nr <= BIO_MAX_VECS {
        d.simple(it, nr)
    } else {
        d.large(it)
    }
}

/// One direct I/O's fixed parts
struct Dio<'a> {
    b: &'a BlockDevice,
    op: BioOp,
    /// FUA for an O_DSYNC write (Linux dio_bio_write_op)
    bflags: BioFlags,
    nowait: bool,
    /// First sector
    sector: u64,
}

impl<'a> Dio<'a> {
    fn new<I: DioIter>(b: &'a BlockDevice, pos: u64, flags: RwFlags) -> Self {
        let dsync = flags.intersects(RwFlags::DSYNC | RwFlags::SYNC);
        Self {
            b,
            op: if I::READ { BioOp::Read } else { BioOp::Write },
            bflags: if !I::READ && dsync {
                BioFlags::FUA
            } else {
                BioFlags::empty()
            },
            nowait: flags.nowait(),
            sector: pos >> SECTOR_SHIFT,
        }
    }

    /// Pin the next bio's worth of `it`, at most `max` pages
    fn pin<I: DioIter>(&self, it: &mut I, max: usize) -> Result<PinnedPages, KernelError> {
        let lbs = self.b.logical_block_size() as usize;
        it.get_pages(max, self.b.dma_alignment() as usize, lbs - 1)
    }

    /// Up to `BIO_MAX_VECS` pages, `nr` of them: pinned once (short if
    /// the pin is), one wait (Linux __blkdev_direct_IO_simple)
    fn simple<I: DioIter>(&self, it: &mut I, nr: usize) -> Result<usize, KernelError> {
        let pp = self.pin(it, nr)?;
        let w = DioWait::new();
        let sent = self.send(&pp, self.sector, &w);
        let pp = self.sent(pp, &sent);
        let r = w.finish();
        drop(pp);
        let n = sent?;
        r.map(|()| n)
    }

    /// More than `BIO_MAX_VECS` pages: a bio's worth pinned and sent at a
    /// time, all counted in one wait; a pin that fails after the first
    /// fails the I/O (Linux __blkdev_direct_IO)
    fn large<I: DioIter>(&self, it: &mut I) -> Result<usize, KernelError> {
        // The pins of every bio sent are kept until the wait: room for
        // the usual count up front (a bio cut back to whole blocks
        // leaves a page for the next, so there may be more)
        let nr = it.npages(usize::MAX);
        let mut pins: KVec<PinnedPages> = KVec::try_with_capacity(nr.div_ceil(BIO_MAX_VECS) + 1)?;
        let w = DioWait::new();
        let (mut done, mut ret) = (0usize, Ok(()));
        while it.count() > 0 {
            // Room before the pin, so a sent bio's pins are always kept
            if let Err(e) = pins.try_reserve(1) {
                ret = Err(e);
                break;
            }
            let pp = match self.pin(it, BIO_MAX_VECS) {
                Ok(pp) => pp,
                Err(e) => {
                    ret = Err(e);
                    break;
                }
            };
            // Another bio would follow (Linux: EAGAIN, nothing sent)
            if self.nowait && it.count() > 0 {
                ret = Err(KernelError::WouldBlock);
                break;
            }
            let sent = self.send(&pp, self.sector + (done as u64 >> SECTOR_SHIFT), &w);
            if let Some(pp) = self.sent(pp, &sent) {
                // Room was reserved: no allocation, cannot fail
                let _ = pins.try_push(pp);
            }
            match sent {
                Ok(n) => done += n,
                Err(e) => {
                    ret = Err(e);
                    break;
                }
            }
        }
        let r = w.finish();
        drop(pins);
        ret?;
        r.map(|()| done)
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

    /// Send `pp` from `sector` on as bios within the queue limits, each
    /// counted in `w`: the bytes sent. EAGAIN for RWF_NOWAIT if it takes
    /// more than one bio, before any is sent; an error after some were
    /// sent is left in `w`.
    fn send(&self, pp: &PinnedPages, sector: u64, w: &DioWait) -> Result<usize, KernelError> {
        let lim = &self.b.disk.queue.limits;
        let segs = pp.segs();
        let mut cur = Cursor::default();
        let mut sent = 0usize;
        while !cur.done(segs) {
            let r = Bio::with_segs(
                self.op,
                sector + (sent as u64 >> SECTOR_SHIFT),
                cur.room(segs, lim),
            )
            .and_then(|mut bio| cur.next_bio(segs, lim, &mut bio.segs).map(|n| (bio, n)));
            let (mut bio, n) = match r {
                Ok(x) => x,
                Err(e) if sent == 0 => return Err(e),
                Err(e) => {
                    w.fail(e);
                    break;
                }
            };
            if self.nowait && sent == 0 && !cur.done(segs) {
                return Err(KernelError::WouldBlock);
            }
            bio.flags = self.bflags;
            bio.end_io = Some(dio_endio);
            bio.private = core::ptr::from_ref(w) as usize;
            w.get();
            submit_bio(self.b, bio);
            sent += n;
        }
        Ok(sent)
    }
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

impl DioWait {
    fn new() -> Self {
        Self {
            left: AtomicU32::new(1),
            err: AtomicI32::new(0),
            done: Completion::new(),
        }
    }

    /// A bio is about to be submitted
    fn get(&self) {
        self.left.fetch_add(1, Ordering::Relaxed);
    }

    /// Keep `e` if it is the first error
    fn fail(&self, e: KernelError) {
        let _ = self
            .err
            .compare_exchange(0, e.errno(), Ordering::Relaxed, Ordering::Relaxed);
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
fn dio_endio(bio: alloc::boxed::Box<Bio>) {
    // SAFETY: `send` set `private` to the I/O's DioWait, which stays on
    // the submitter's stack until `finish` sees this bio's `put`
    let w = unsafe { &*(bio.private as *const DioWait) };
    if let Err(e) = bio.status {
        w.fail(e);
    }
    drop(bio);
    w.put();
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
        c.fill(segs, lim, &mut |_| n += 1);
        n
    }

    /// Give `f` the next bio's segments of `segs`, as many as the limits
    /// allow (max_sectors, max_segments, segments of at most
    /// max_segment_size), stepping over them; the bytes
    fn fill(&mut self, segs: &[PageSeg], lim: &QueueLimits, f: &mut dyn FnMut(BioSeg)) -> usize {
        let max_bytes = (lim.max_sectors as usize) << SECTOR_SHIFT;
        let seg_max = (lim.max_segment_size as usize).max(1);
        let (mut bytes, mut nr) = (0, 0);
        while let Some(s) = segs.get(self.i) {
            if nr >= lim.max_segments as usize || bytes >= max_bytes {
                break;
            }
            let n = (s.len as usize - self.at)
                .min(seg_max)
                .min(max_bytes - bytes);
            f(BioSeg {
                frame: s.phys,
                offset: s.off as usize + self.at,
                len: n,
            });
            nr += 1;
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
    /// the limits allow (max_sectors, max_segments, segments of at most
    /// max_segment_size), cut back to whole logical blocks (Linux
    /// bio_split_rw_at); the bytes. EINVAL if not one block fits.
    pub fn next_bio(
        &mut self,
        segs: &[PageSeg],
        lim: &QueueLimits,
        out: &mut BioSegs,
    ) -> Result<usize, KernelError> {
        out.clear();
        let bytes = self.fill(segs, lim, &mut |s| out.push(s));
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

    /// Pieces of `lens` bytes, page i at 0x1000 * (i + 1), at offset
    /// `off` in the first page
    fn pieces(lens: &[u32], off: u32) -> Vec<PageSeg> {
        lens.iter()
            .enumerate()
            .map(|(i, &len)| PageSeg {
                phys: 0x1000 * (i as u64 + 1),
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
    fn misaligned_requests() {
        assert!(!invalid(4096, 8192, 512));
        assert!(invalid(4097, 8192, 512));
        assert!(invalid(4096, 100, 512));
        assert!(invalid(512, 4096, 4096));
        assert!(!invalid(0, 0, 4096));
    }
}
