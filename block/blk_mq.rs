//! blk-mq-lite: per-CPU software queues feeding hardware queues
//!
//! Linux reference: block/blk-mq.c (no scheduler, no tags shared across
//! queues, no plugging).
//!
//! A submitter puts its bio on its CPU's software queue (Linux
//! blk_mq_ctx), then runs the hardware queue that CPU maps to (Linux
//! blk_mq_hw_ctx; `cpu % nr_hw`): the software queues of that hardware
//! queue with bios pending (its `ctx_map` bitmap, Linux
//! blk_mq_hctx_mark_pending / flush_busy_ctxs) are spliced onto its
//! dispatch list and the driver's `queue_rq` takes bios until it is
//! full. The driver's interrupt handler calls
//! [`BlkMq::complete`]: finished bios are collected, the dispatch list is
//! run again (room was freed: Linux restarts the queue from completion)
//! and the bios are ended after the lock is dropped.
//!
//! ## Locking (doc/LOCKING.md 3.10)
//!
//! - Software queue (`ctx`): `IrqSpinlock<BioList>`, one per CPU, leaf.
//!   Its pending bit in the hardware queue's `ctx_map` is set and
//!   cleared under it; a run that misses a bit being set is followed by
//!   the submitter's own run.
//! - Hardware queue: one `IrqSpinlock` over the dispatch list and the
//!   driver's queue state (for virtio-blk the virtqueue: Linux
//!   `virtio_blk_vq.lock`), taken in thread context (dispatch) and in
//!   the driver's IRQ handler (completion), leaf: a software queue is
//!   never locked under it, and `queue_rq`/`complete` must not allocate,
//!   sleep or take other locks (lock-free DMA map/unmap and MMIO only).
//! - `end_io` runs after the hardware queue lock is released.
//!
//! ## Removal (Linux del_gendisk: blk_queue_start_drain,
//! blk_mq_freeze_queue_wait; the driver's blk_mq_free_tag_set)
//!
//! `start_drain` marks every hardware queue dying under its lock: from
//! then on nothing reaches `queue_rq` (pending and new bios end with
//! EIO). `drain` sleeps on `drained` until the requests started before
//! have completed (each hardware queue counts them under its lock; the
//! completion that empties a dying queue wakes). `release` then hands
//! the driver's queue state back to its remove, which stops the device
//! and frees the rings.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::sync::waitqueue::WaitQueue;

use super::blkdev::{Bio, BioList, bio_endio};
use crate::util::error::KernelError;

/// Result of `MqOps::queue_rq` (Linux blk_status_t of queue_rq)
pub enum Queued {
    Started,
    /// Device queue full: retried when a request completes (Linux
    /// BLK_STS_RESOURCE)
    Busy(Box<Bio>),
    /// Cannot be issued: ended with the error
    Failed(Box<Bio>, KernelError),
}

/// Driver side of one hardware queue (Linux blk_mq_ops + hctx->driver_data)
///
/// Called with the hardware queue lock held, possibly in hardirq
/// context: no allocation, no sleeping, no other locks.
pub trait MqOps: Send {
    /// Start `bio`
    fn queue_rq(&mut self, bio: Box<Bio>) -> Queued;
    /// Notify the device of the bios just queued (Linux commit_rqs)
    fn commit(&mut self);
    /// Move finished bios, status set, to `done`
    fn complete(&mut self, done: &mut BioList);
    /// The driver's own type, for its remove to take apart (`release`)
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send>;
}

struct HwState {
    /// Bios taken from the software queues, not yet started
    dispatch: BioList,
    /// The driver's queue; None once released
    ops: Option<Box<dyn MqOps>>,
    /// Started, not yet completed
    inflight: usize,
    /// The disk is going away: nothing more is started (Linux
    /// QUEUE_FLAG_DYING with the queue frozen)
    dying: bool,
}

impl HwState {
    /// Start what fits; failed bios go to `done`
    fn dispatch(&mut self, done: &mut BioList) {
        let Some(ops) = self.ops.as_mut().filter(|_| !self.dying) else {
            while let Some(mut b) = self.dispatch.pop() {
                b.status = Err(KernelError::Io);
                done.push(b);
            }
            return;
        };
        let mut n = 0;
        while let Some(bio) = self.dispatch.pop() {
            match ops.queue_rq(bio) {
                Queued::Started => n += 1,
                Queued::Busy(b) => {
                    self.dispatch.push_front(b);
                    break;
                }
                Queued::Failed(mut b, e) => {
                    b.status = Err(e);
                    done.push(b);
                }
            }
        }
        if n > 0 {
            self.inflight += n;
            ops.commit();
        }
    }

    /// Dying with nothing in flight
    fn drained(&self) -> bool {
        self.dying && self.inflight == 0
    }
}

/// End every bio of `l` (no queue lock held)
fn end_all(l: &mut BioList) {
    while let Some(bio) = l.pop() {
        bio_endio(bio);
    }
}

/// The software and hardware queues of one request queue
pub struct BlkMq {
    ctxs: Vec<IrqSpinlock<BioList>>,
    /// Never empty (`new` refuses that): `map` divides by its length
    hctxs: Vec<IrqSpinlock<HwState>>,
    /// Per hardware queue, a bit per software queue mapped to it with
    /// bios pending (bit `cpu / nr_hw`; Linux hctx->ctx_map)
    ctx_maps: Vec<Box<[AtomicU64]>>,
    /// `drain` waits here (Linux mq_freeze_wq)
    drained: WaitQueue,
}

impl BlkMq {
    /// One hardware queue per element of `ops`; EINVAL for none (CPUs
    /// are mapped `cpu % nr_hw`: Linux blk_mq_alloc_tag_set refuses
    /// nr_hw_queues 0)
    pub fn new(ops: Vec<Box<dyn MqOps>>) -> Result<Self, KernelError> {
        if ops.is_empty() {
            return Err(KernelError::InvalidArgument);
        }
        let n = crate::cpu::nr_cpu_ids() as usize;
        let words = n.div_ceil(ops.len()).div_ceil(64);
        Ok(Self {
            ctxs: (0..n).map(|_| IrqSpinlock::new(BioList::new())).collect(),
            ctx_maps: (0..ops.len())
                .map(|_| (0..words).map(|_| AtomicU64::new(0)).collect())
                .collect(),
            hctxs: ops
                .into_iter()
                .map(|ops| {
                    IrqSpinlock::new(HwState {
                        dispatch: BioList::new(),
                        ops: Some(ops),
                        inflight: 0,
                        dying: false,
                    })
                })
                .collect(),
            drained: WaitQueue::new(),
        })
    }

    pub fn nr_hw_queues(&self) -> usize {
        self.hctxs.len()
    }

    /// Hardware queue of `cpu` (Linux blk_mq_map_queues)
    fn map(&self, cpu: usize) -> usize {
        cpu % self.hctxs.len()
    }

    /// `cpu`'s word and bit in its hardware queue's `ctx_map`
    fn ctx_bit(&self, cpu: usize) -> (usize, u64) {
        let i = cpu / self.hctxs.len();
        (i / 64, 1 << (i % 64))
    }

    /// Queue a bio from thread context and run its hardware queue
    pub fn submit(&self, bio: Box<Bio>) {
        let cpu = crate::cpu::this_id() as usize % self.ctxs.len();
        let h = self.map(cpu);
        let (w, bit) = self.ctx_bit(cpu);
        {
            let mut ctx = self.ctxs[cpu].lock();
            ctx.push(bio);
            self.ctx_maps[h][w].fetch_or(bit, Ordering::Relaxed);
        }
        self.run(h);
    }

    /// Splice the software queues of hardware queue `h` with bios
    /// pending, then dispatch (Linux blk_mq_run_hw_queue)
    fn run(&self, h: usize) {
        let mut batch = BioList::new();
        let nr_hw = self.hctxs.len();
        for (w, word) in self.ctx_maps[h].iter().enumerate() {
            let mut bits = word.load(Ordering::Relaxed);
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let cpu = (w * 64 + b) * nr_hw + h;
                let mut ctx = self.ctxs[cpu].lock();
                batch.append(&mut ctx);
                word.fetch_and(!(1 << b), Ordering::Relaxed);
            }
        }
        let mut failed = BioList::new();
        {
            let mut hw = self.hctxs[h].lock();
            hw.dispatch.append(&mut batch);
            hw.dispatch(&mut failed);
        }
        end_all(&mut failed);
    }

    /// Reap hardware queue `h` (the driver's IRQ handler, or polling):
    /// end finished bios and restart dispatch into the freed room
    pub fn complete(&self, h: usize) {
        let mut done = BioList::new();
        let wake = {
            let mut hw = self.hctxs[h].lock();
            let hw = &mut *hw;
            let Some(ops) = hw.ops.as_mut() else { return };
            let mut got = BioList::new();
            ops.complete(&mut got);
            let mut n = 0;
            while let Some(b) = got.pop() {
                done.push(b);
                n += 1;
            }
            hw.inflight = hw.inflight.saturating_sub(n);
            if n > 0 {
                hw.dispatch(&mut done);
            }
            n > 0 && hw.drained()
        };
        end_all(&mut done);
        if wake {
            self.drained.wake_all();
        }
    }

    /// Reap every hardware queue (polled completion before interrupts
    /// or scheduling work)
    pub fn poll(&self) {
        for h in 0..self.hctxs.len() {
            self.complete(h);
        }
    }

    /// Start nothing more: bios not yet started end with EIO (Linux
    /// blk_queue_start_drain on a dead disk)
    pub fn start_drain(&self) {
        for hctx in &self.hctxs {
            let mut failed = BioList::new();
            {
                let mut hw = hctx.lock();
                hw.dying = true;
                hw.dispatch(&mut failed);
            }
            end_all(&mut failed);
        }
    }

    /// Sleep until the requests started before `start_drain` have
    /// completed (Linux blk_mq_freeze_queue_wait). Thread context.
    pub fn drain(&self) {
        self.drained
            .wait_event(|| self.hctxs.iter().all(|h| h.lock().drained()));
    }

    /// Hand the driver's queue state back after `drain`, for its
    /// remove to stop the device and free the rings (Linux
    /// blk_mq_free_tag_set, then the driver's del_vqs); later
    /// completions and dispatches find no queue. Thread context.
    pub fn release(&self) -> Vec<Box<dyn MqOps>> {
        self.hctxs
            .iter()
            .filter_map(|h| h.lock().ops.take())
            .collect()
    }
}
