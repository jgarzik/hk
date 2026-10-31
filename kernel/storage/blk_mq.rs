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

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::IrqSpinlock;

use super::blkdev::{Bio, BioList, bio_endio};
use crate::error::KernelError;

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
}

struct HwState {
    /// Bios taken from the software queues, not yet started
    dispatch: BioList,
    ops: Box<dyn MqOps>,
}

impl HwState {
    /// Start what fits; failed bios go to `done`
    fn dispatch(&mut self, done: &mut BioList) {
        let mut n = 0;
        while let Some(bio) = self.dispatch.pop() {
            match self.ops.queue_rq(bio) {
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
            self.ops.commit();
        }
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
    hctxs: Vec<IrqSpinlock<HwState>>,
    /// Per hardware queue, a bit per software queue mapped to it with
    /// bios pending (bit `cpu / nr_hw`; Linux hctx->ctx_map)
    ctx_maps: Vec<Box<[AtomicU64]>>,
}

impl BlkMq {
    /// One hardware queue per element of `ops`
    pub fn new(ops: Vec<Box<dyn MqOps>>) -> Self {
        let n = crate::cpu::nr_cpu_ids() as usize;
        let words = n.div_ceil(ops.len().max(1)).div_ceil(64);
        Self {
            ctxs: (0..n).map(|_| IrqSpinlock::new(BioList::new())).collect(),
            ctx_maps: (0..ops.len())
                .map(|_| (0..words).map(|_| AtomicU64::new(0)).collect())
                .collect(),
            hctxs: ops
                .into_iter()
                .map(|ops| {
                    IrqSpinlock::new(HwState {
                        dispatch: BioList::new(),
                        ops,
                    })
                })
                .collect(),
        }
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
        {
            let mut hw = self.hctxs[h].lock();
            hw.ops.complete(&mut done);
            if !done.is_empty() {
                hw.dispatch(&mut done);
            }
        }
        end_all(&mut done);
    }

    /// Reap every hardware queue (polled completion before interrupts
    /// or scheduling work)
    pub fn poll(&self) {
        for h in 0..self.hctxs.len() {
            self.complete(h);
        }
    }
}
