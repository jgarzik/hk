//! The rings shared with user space (Linux struct io_rings and the SQE
//! array, io_uring.c rings_size / io_allocate_scq_urings)
//!
//! One region holds the SQ and CQ heads and tails, their masks and
//! sizes, the flags and counters, the CQEs (from a cache line on) and,
//! after them, the SQ index array; the SQEs are a second region. User
//! space writes the SQ tail, the SQ array, the SQEs and the CQ head;
//! the kernel the rest. Ordering (Linux io_uring.c's comment): the
//! kernel reads the SQ tail with Acquire (the SQEs before it are
//! written), stores the SQ head with Release once it has copied the
//! SQEs (their slots may then be reused), writes CQEs before storing
//! the CQ tail with Release, and reads the CQ head with Acquire (the
//! CQEs before it were consumed).

use core::sync::atomic::{AtomicU32, Ordering};

use super::abi::{CqRingOffsets, IoUringCqe, IoUringSqe, SqRingOffsets};
use crate::mm::shared::SharedRegion;
use crate::util::error::KernelError;

/// Offsets in the rings region (Linux struct io_rings)
const SQ_HEAD: usize = 0;
const SQ_TAIL: usize = 4;
const CQ_HEAD: usize = 8;
const CQ_TAIL: usize = 12;
const SQ_RING_MASK: usize = 16;
const CQ_RING_MASK: usize = 20;
const SQ_RING_ENTRIES: usize = 24;
const CQ_RING_ENTRIES: usize = 28;
const SQ_DROPPED: usize = 32;
const SQ_FLAGS: usize = 36;
const CQ_FLAGS: usize = 40;
const CQ_OVERFLOW: usize = 44;
/// The CQEs start on a cache line (____cacheline_aligned_in_smp)
const CQES: usize = 64;
/// SMP_CACHE_BYTES
const CACHE_LINE: usize = 64;

const SQE_SIZE: usize = size_of::<IoUringSqe>();
const CQE_SIZE: usize = size_of::<IoUringCqe>();

/// The rings and SQEs of one io_uring
pub struct Rings {
    rings: SharedRegion,
    sqes: SharedRegion,
    sq_entries: u32,
    cq_entries: u32,
    /// Offset of the SQ index array in `rings`
    sq_array: usize,
}

impl Rings {
    /// Rings of `sq` and `cq` entries (powers of two, bounded by the
    /// caller); ENOMEM
    pub fn new(sq: u32, cq: u32) -> Result<Self, KernelError> {
        let sq_array = (CQES + cq as usize * CQE_SIZE).next_multiple_of(CACHE_LINE);
        let rings = SharedRegion::new(sq_array + sq as usize * 4)?;
        let sqes = SharedRegion::new(sq as usize * SQE_SIZE)?;
        let r = Self {
            rings,
            sqes,
            sq_entries: sq,
            cq_entries: cq,
            sq_array,
        };
        r.set(SQ_RING_MASK, sq - 1);
        r.set(CQ_RING_MASK, cq - 1);
        r.set(SQ_RING_ENTRIES, sq);
        r.set(CQ_RING_ENTRIES, cq);
        Ok(r)
    }

    fn word(&self, off: usize) -> &AtomicU32 {
        self.rings.word(off)
    }

    fn set(&self, off: usize, v: u32) {
        self.word(off).store(v, Ordering::Relaxed);
    }

    pub fn sq_entries(&self) -> u32 {
        self.sq_entries
    }

    pub fn cq_entries(&self) -> u32 {
        self.cq_entries
    }

    /// The offsets io_uring_setup reports (Linux io_prepare_config)
    pub fn offsets(&self) -> (SqRingOffsets, CqRingOffsets) {
        // All offsets lie within the rings region, far below 4 GiB
        let o = |v: usize| v as u32;
        let sq = SqRingOffsets {
            head: o(SQ_HEAD),
            tail: o(SQ_TAIL),
            ring_mask: o(SQ_RING_MASK),
            ring_entries: o(SQ_RING_ENTRIES),
            flags: o(SQ_FLAGS),
            dropped: o(SQ_DROPPED),
            array: o(self.sq_array),
            ..Default::default()
        };
        let cq = CqRingOffsets {
            head: o(CQ_HEAD),
            tail: o(CQ_TAIL),
            ring_mask: o(CQ_RING_MASK),
            ring_entries: o(CQ_RING_ENTRIES),
            overflow: o(CQ_OVERFLOW),
            cqes: o(CQES),
            flags: o(CQ_FLAGS),
            ..Default::default()
        };
        (sq, cq)
    }

    /// The region a mapping at `off` (its IORING_OFF_* part) shows
    pub fn region(&self, off: u64) -> Option<&SharedRegion> {
        use super::abi::{IORING_OFF_CQ_RING, IORING_OFF_SQ_RING, IORING_OFF_SQES};
        match off {
            IORING_OFF_SQ_RING | IORING_OFF_CQ_RING => Some(&self.rings),
            IORING_OFF_SQES => Some(&self.sqes),
            _ => None,
        }
    }

    /// The SQ tail user space published
    pub fn sq_tail(&self) -> u32 {
        self.word(SQ_TAIL).load(Ordering::Acquire)
    }

    /// The SQ head last published
    pub fn sq_head(&self) -> u32 {
        self.word(SQ_HEAD).load(Ordering::Acquire)
    }

    /// Hand the SQ slots before `head` back to user space
    pub fn set_sq_head(&self, head: u32) {
        self.word(SQ_HEAD).store(head, Ordering::Release);
    }

    /// The SQE index in SQ array slot `slot` (masked here)
    pub fn sq_index(&self, slot: u32) -> u32 {
        let i = (slot & (self.sq_entries - 1)) as usize;
        self.rings.read(self.sq_array + i * 4)
    }

    /// A copy of SQE `i` (< sq_entries), each field read once
    pub fn sqe(&self, i: u32) -> IoUringSqe {
        self.sqes.read(i as usize * SQE_SIZE)
    }

    /// One more SQ array slot named no SQE (Linux sq_dropped)
    pub fn inc_dropped(&self) {
        let w = self.word(SQ_DROPPED);
        w.store(w.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
    }

    /// The CQ head user space published
    pub fn cq_head(&self) -> u32 {
        self.word(CQ_HEAD).load(Ordering::Acquire)
    }

    /// The CQ tail last published
    pub fn cq_tail(&self) -> u32 {
        self.word(CQ_TAIL).load(Ordering::Acquire)
    }

    /// Write the CQE for position `tail` (not yet published)
    pub fn write_cqe(&self, tail: u32, cqe: IoUringCqe) {
        let i = (tail & (self.cq_entries - 1)) as usize;
        self.rings.write(CQES + i * CQE_SIZE, cqe);
    }

    /// Publish the CQEs before `tail`
    pub fn set_cq_tail(&self, tail: u32) {
        self.word(CQ_TAIL).store(tail, Ordering::Release);
    }

    /// One more CQE lost (Linux cq_overflow)
    pub fn inc_cq_overflow(&self) {
        let w = self.word(CQ_OVERFLOW);
        w.store(w.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
    }

    /// Set (`on`) or clear SQ ring flags `f` (Linux rings->sq_flags)
    pub fn sq_flags(&self, f: u32, on: bool) {
        if on {
            self.word(SQ_FLAGS).fetch_or(f, Ordering::Relaxed);
        } else {
            self.word(SQ_FLAGS).fetch_and(!f, Ordering::Relaxed);
        }
    }
}
