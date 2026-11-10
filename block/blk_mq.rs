//! blk-mq-lite: per-CPU software queues feeding hardware queues
//!
//! Linux reference: block/blk-mq.c (no scheduler, no tags shared across
//! queues, no plugging).
//!
//! A submitter puts its bio on its CPU's software queue (Linux
//! blk_mq_ctx), then runs the hardware queue that CPU maps to (Linux
//! blk_mq_hw_ctx; consecutive CPUs share one, `util::group_cpus`, as
//! Linux blk_mq_map_queues and a driver's interrupt affinity map them):
//! the software queues of that hardware
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
//! - Software queue (`ctx`): `IrqSpinlock<BioList>`, one per CPU, leaf;
//!   taken by submitters, and by a completion that sends a post-flush.
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
//! `start_drain` marks every hardware queue dying under its lock and
//! runs it: from then on nothing reaches `queue_rq`, and every request
//! not yet started (on a software queue, parked for kblockd, or on the
//! dispatch list) ends with EIO, as do new ones. `drain` sleeps on
//! `drained` until every request taken (`get_rq`, counted per hardware
//! queue until its end: Linux q_usage_counter) has ended; the end that
//! empties a count wakes. `release` then hands the driver's queue state
//! back to its remove, which stops the device and frees the rings; a
//! kblockd run still queued holds the `BlkMq` and finds no driver queue.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use alloc::sync::Arc;

use crate::cpu::PerCpu;
use crate::sync::IrqSpinlock;
use crate::sync::spin::Mutex;
use crate::sync::waitqueue::WaitQueue;
use crate::task::workqueue::{Work, Workqueue, wq_flags::WQ_HIGHPRI, wq_flags::WQ_MEM_RECLAIM};
use crate::util::cpumask::NR_CPUS;
use crate::util::kalloc::try_arc;
use crate::util::kmem::KVec;

use super::blkdev::{Bio, BioFlags, BioList, bio_endio, bio_io_error};
use crate::util::error::KernelError;
use crate::util::group_cpus::{first_cpu, group_of};

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
    /// Requests it can have started at once (Linux tag set queue_depth)
    fn depth(&self) -> usize;
    /// The driver's own type, for its remove to take apart (`release`)
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send>;
}

struct HwState {
    /// Bios taken from the software queues, not yet started
    dispatch: BioList,
    /// The driver's queue; None once released
    ops: Option<Box<dyn MqOps>>,
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
            ops.commit();
        }
    }
}

/// A hardware queue over the driver queue `ops`
fn hw_state(ops: Box<dyn MqOps>) -> IrqSpinlock<HwState> {
    IrqSpinlock::new(HwState {
        dispatch: BioList::new(),
        ops: Some(ops),
        dying: false,
    })
}

/// End every request of `l` (no queue lock held): how many
fn end_all(l: &mut BioList) -> usize {
    let mut n = 0;
    while let Some(bio) = l.pop() {
        bio_endio(bio);
        n += 1;
    }
    n
}

/// The software and hardware queues of one request queue
pub struct BlkMq {
    ctxs: Vec<IrqSpinlock<BioList>>,
    /// Never empty (`new` refuses that): `map` divides by its length
    hctxs: Vec<IrqSpinlock<HwState>>,
    /// Per hardware queue, a bit per software queue mapped to it with
    /// bios pending (bit `cpu - ` its group's first CPU; Linux
    /// hctx->ctx_map)
    ctx_maps: Vec<Box<[AtomicU64]>>,
    /// `drain` waits here (Linux mq_freeze_wq)
    drained: WaitQueue,
    /// Per hardware queue, requests taken and not yet ended (Linux tags
    /// in use: a lock-free count, as Linux's sbitmap), and the driver's
    /// depth; a NOWAIT bio finding them all taken ends with EAGAIN
    rqs: Vec<AtomicUsize>,
    depth: Vec<usize>,
    /// Per hardware queue, its kblockd run (Linux hctx->run_work)
    runs: Vec<HctxRun>,
    /// `start_drain` was called: the request that brings a hardware
    /// queue's count to 0 wakes `drained` (set once)
    dying: AtomicBool,
    /// Poll queues (Linux HCTX_TYPE_POLL): no interrupt; a polled bio
    /// goes straight to one (by CPU, no software queue), and its end is
    /// found by `poll_queues`
    polls: Vec<IrqSpinlock<HwState>>,
    /// Polled requests not yet ended
    poll_rqs: AtomicUsize,
}

/// The block layer's workqueues: one worker per CPU, high priority
/// (Linux kblockd_workqueue: per-CPU, WQ_MEM_RECLAIM | WQ_HIGHPRI, the
/// highpri pool's nice -20 workers)
static KBLOCKD: PerCpu<Workqueue> =
    crate::percpu![Workqueue::new("kblockd", WQ_MEM_RECLAIM | WQ_HIGHPRI)];

/// Start each CPU's kblockd worker, bound to it (Linux blk_dev_init);
/// before any disk
pub fn kblockd_init() {
    for cpu in 0..crate::cpu::nr_cpu_ids() {
        if !crate::task::percpu::cpu_has_scheduler(cpu) {
            continue;
        }
        if let Err(e) = KBLOCKD.get(cpu).start(Some(cpu)) {
            crate::printkln!("blk-mq: no kblockd on CPU {} ({:?})", cpu, e);
        }
    }
}

/// CPU `cpu`'s kblockd, once its worker runs
fn kblockd(cpu: u32) -> Option<&'static Workqueue> {
    let wq = KBLOCKD.try_get(cpu)?;
    wq.is_initialized().then_some(wq)
}

/// A hardware queue's kblockd run: the work item, and a hold on the
/// queues while it is queued (the work drops it after the run)
struct HctxRun {
    work: Arc<crate::sync::IrqSpinlock<Work>>,
    hold: Arc<Mutex<Option<Arc<BlkMq>>>>,
}

impl HctxRun {
    fn new(h: usize) -> Result<Self, KernelError> {
        let hold: Arc<Mutex<Option<Arc<BlkMq>>>> = try_arc(Mutex::new(None))?;
        let k = hold.clone();
        let work = try_arc(crate::sync::IrqSpinlock::new(Work::new(move || {
            // Taken under the lock, run and dropped unlocked: it may be
            // the queues' last hold
            let mq = k.lock().take();
            if let Some(mq) = mq {
                mq.run(h);
            }
        })))?;
        Ok(Self { work, hold })
    }
}

/// A set of hardware queues (at most one per CPU)
#[derive(Default)]
struct HctxSet([u64; NR_CPUS.div_ceil(64)]);

impl HctxSet {
    fn add(&mut self, h: usize) {
        self.0[h / 64] |= 1 << (h % 64);
    }

    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..NR_CPUS).filter(|&h| self.0[h / 64] & (1 << (h % 64)) != 0)
    }
}

impl BlkMq {
    /// One hardware queue per element of `ops`; EINVAL for none (Linux
    /// blk_mq_alloc_tag_set refuses nr_hw_queues 0)
    pub fn new(ops: Vec<Box<dyn MqOps>>) -> Result<Self, KernelError> {
        Self::with_polls(ops, Vec::new())
    }

    /// `new`, plus a poll queue per element of `polls` (Linux the
    /// HCTX_TYPE_POLL map)
    pub fn with_polls(
        ops: Vec<Box<dyn MqOps>>,
        polls: Vec<Box<dyn MqOps>>,
    ) -> Result<Self, KernelError> {
        if ops.is_empty() {
            return Err(KernelError::InvalidArgument);
        }
        let n = crate::cpu::nr_cpu_ids() as usize;
        let words = n.div_ceil(ops.len()).div_ceil(64);
        let mut runs = KVec::try_with_capacity(ops.len())?;
        for h in 0..ops.len() {
            runs.try_push(HctxRun::new(h)?)?;
        }
        Ok(Self {
            runs: runs.into_vec(),
            dying: AtomicBool::new(false),
            rqs: ops.iter().map(|_| AtomicUsize::new(0)).collect(),
            depth: ops.iter().map(|o| o.depth().max(1)).collect(),
            ctxs: (0..n).map(|_| IrqSpinlock::new(BioList::new())).collect(),
            ctx_maps: (0..ops.len())
                .map(|_| (0..words).map(|_| AtomicU64::new(0)).collect())
                .collect(),
            hctxs: ops.into_iter().map(hw_state).collect(),
            drained: WaitQueue::new(),
            polls: polls.into_iter().map(hw_state).collect(),
            poll_rqs: AtomicUsize::new(0),
        })
    }

    pub fn nr_poll_queues(&self) -> usize {
        self.polls.len()
    }

    /// It has poll queues (Linux blk_mq_can_poll)
    pub fn can_poll(&self) -> bool {
        !self.polls.is_empty()
    }

    /// Queue the polled `bio` on this CPU's poll queue and dispatch it
    /// (Linux blk_mq_submit_bio with REQ_POLLED: the HCTX_TYPE_POLL
    /// hctx). Only for a queue that `can_poll`.
    pub fn submit_polled(&self, bio: Box<Bio>) {
        let h = crate::cpu::this_id() as usize % self.polls.len();
        self.poll_rqs.fetch_add(1, Ordering::Relaxed);
        let mut failed = BioList::new();
        {
            let mut hw = self.polls[h].lock();
            hw.dispatch.push(bio);
            hw.dispatch(&mut failed);
        }
        let n = end_all(&mut failed);
        self.put_polled(n);
    }

    /// Reap every poll queue once, restarting dispatch into the freed
    /// room (Linux blk_mq_poll); whether anything ended
    pub fn poll_queues(&self) -> bool {
        let mut n = 0;
        for q in &self.polls {
            let mut done = BioList::new();
            {
                let mut hw = q.lock();
                let hw = &mut *hw;
                if let Some(ops) = hw.ops.as_mut() {
                    ops.complete(&mut done);
                }
                hw.dispatch(&mut done);
            }
            n += end_all(&mut done);
        }
        self.put_polled(n);
        n > 0
    }

    /// `n` polled requests ended; the last of a dying queue wakes `drain`
    fn put_polled(&self, n: usize) {
        if n > 0
            && self.poll_rqs.fetch_sub(n, Ordering::AcqRel) == n
            && self.dying.load(Ordering::Acquire)
        {
            self.drained.wake_all();
        }
    }

    pub fn nr_hw_queues(&self) -> usize {
        self.hctxs.len()
    }

    /// CPUs and hardware queues, for `util::group_cpus`
    fn groups(&self) -> (u32, u32) {
        // Both are at most NR_CPUS resp. a driver's u16 queue count
        (self.ctxs.len() as u32, self.hctxs.len() as u32)
    }

    /// Hardware queue of `cpu` (Linux blk_mq_map_queues)
    fn map(&self, cpu: usize) -> usize {
        let (n, g) = self.groups();
        group_of(cpu as u32, n, g) as usize
    }

    /// `cpu`'s word and bit in its hardware queue's `ctx_map`
    fn ctx_bit(&self, cpu: usize) -> (usize, u64) {
        let (n, g) = self.groups();
        let i = cpu - first_cpu(self.map(cpu) as u32, n, g) as usize;
        (i / 64, 1 << (i % 64))
    }

    /// Take a request for `bio` on this CPU's hardware queue (Linux
    /// blk_mq_get_new_requests, BLK_MQ_REQ_NOWAIT for a NOWAIT bio):
    /// false if it is NOWAIT and every tag is taken. Others always get
    /// one and wait in the queue for the driver's room
    pub fn get_rq(&self, bio: &mut Bio) -> bool {
        let cpu = crate::cpu::this_id() as usize % self.ctxs.len();
        let h = self.map(cpu);
        let n = &self.rqs[h];
        if bio.flags.contains(BioFlags::NOWAIT) {
            let depth = self.depth[h];
            if n.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                (v < depth).then_some(v + 1)
            })
            .is_err()
            {
                return false;
            }
        } else {
            n.fetch_add(1, Ordering::Relaxed);
        }
        // cpu < NR_CPUS (256)
        bio.rq_ctx = cpu as u16;
        true
    }

    /// `n` requests of hardware queue `h` ended; the last of a dying
    /// queue wakes `drain`
    fn put_rqs(&self, h: usize, n: usize) {
        if n > 0 {
            let was = self.rqs[h].fetch_sub(n, Ordering::AcqRel);
            debug_assert!(
                was >= n,
                "hardware queue {h}: {n} requests ended, {was} taken"
            );
            if was == n && self.dying.load(Ordering::Acquire) {
                self.drained.wake_all();
            }
        }
    }

    /// Take a request and queue it (from thread context, or from a
    /// completion with no queue lock held: a FUA write's data and its
    /// flush); a NOWAIT bio with no free tag ends with EAGAIN
    pub fn submit(self: &Arc<Self>, mut bio: Box<Bio>) {
        if !self.get_rq(&mut bio) {
            return bio_io_error(bio, KernelError::WouldBlock);
        }
        let mut l = BioList::new();
        l.push(bio);
        self.submit_list(&mut l, false);
    }

    /// Queue the requests of `l` (taken by `get_rq`; a plug's, Linux
    /// blk_mq_flush_plug_list), each on its software queue, then run
    /// each hardware queue they reach once: one dispatch, one notify of
    /// the device for the lot (Linux queue_rqs / commit_rqs). From a
    /// task about to sleep (`from_schedule`) kblockd runs them, so
    /// nothing is dispatched or ended inside `schedule()`
    pub fn submit_list(self: &Arc<Self>, l: &mut BioList, from_schedule: bool) {
        for h in self.insert(l).iter() {
            if from_schedule {
                self.run_async(h);
            } else {
                self.run(h);
            }
        }
    }

    /// Put the requests of `l` on their software queues: the hardware
    /// queues they reach
    fn insert(&self, l: &mut BioList) -> HctxSet {
        let mut set = HctxSet::default();
        while let Some(first) = l.pop() {
            let cpu = usize::from(first.rq_ctx) % self.ctxs.len();
            let h = self.map(cpu);
            let (w, bit) = self.ctx_bit(cpu);
            let mut ctx = self.ctxs[cpu].lock();
            ctx.push(first);
            while l.first_ctx() == Some(cpu) {
                if let Some(b) = l.pop() {
                    ctx.push(b);
                }
            }
            self.ctx_maps[h][w].fetch_or(bit, Ordering::Relaxed);
            set.add(h);
        }
        set
    }

    /// Have kblockd run hardware queue `h` on the first CPU it serves,
    /// always the same one (Linux blk_mq_run_hw_queue async,
    /// kblockd_mod_delayed_work_on with blk_mq_hctx_next_cpu, which
    /// stays on a CPU for a batch); synchronously if that kblockd is not
    /// running
    fn run_async(self: &Arc<Self>, h: usize) {
        let (n, g) = self.groups();
        let Some(wq) = kblockd(first_cpu(h as u32, n, g)) else {
            return self.run(h);
        };
        let r = &self.runs[h];
        {
            let mut hold = r.hold.lock();
            if hold.is_none() {
                *hold = Some(self.clone());
            }
        }
        wq.queue_work(r.work.clone());
    }

    /// The hardware queue this CPU submits to
    pub fn this_hctx(&self) -> usize {
        self.map(crate::cpu::this_id() as usize % self.ctxs.len())
    }

    /// Splice the software queues of hardware queue `h` with bios
    /// pending, then dispatch (Linux blk_mq_run_hw_queue)
    fn run(&self, h: usize) {
        let mut batch = BioList::new();
        let (n, g) = self.groups();
        let first = first_cpu(h as u32, n, g) as usize;
        for (w, word) in self.ctx_maps[h].iter().enumerate() {
            let mut bits = word.load(Ordering::Relaxed);
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let cpu = first + w * 64 + b;
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
        let n = end_all(&mut failed);
        self.put_rqs(h, n);
    }

    /// Reap hardware queue `h` (the driver's IRQ handler, or polling):
    /// end finished bios and restart dispatch into the freed room
    pub fn complete(&self, h: usize) {
        let mut done = BioList::new();
        {
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
            if n > 0 {
                hw.dispatch(&mut done);
            }
        };
        let n = end_all(&mut done);
        self.put_rqs(h, n);
    }

    /// Reap every hardware queue (polled completion before interrupts
    /// or scheduling work)
    pub fn poll(&self) {
        for h in 0..self.hctxs.len() {
            self.complete(h);
        }
    }

    /// Start nothing more: requests not yet started, on a software
    /// queue (parked for kblockd too) or the dispatch list, end with
    /// EIO (Linux blk_queue_start_drain on a dead disk)
    pub fn start_drain(&self) {
        self.dying.store(true, Ordering::Release);
        for (h, hctx) in self.hctxs.iter().enumerate() {
            hctx.lock().dying = true;
            self.run(h);
        }
        for q in &self.polls {
            q.lock().dying = true;
        }
        self.poll_queues();
    }

    /// No request taken is left: every one from `get_rq` has ended
    fn idle(&self) -> bool {
        self.rqs.iter().all(|n| n.load(Ordering::Acquire) == 0)
            && self.poll_rqs.load(Ordering::Acquire) == 0
    }

    /// Sleep until every request taken has ended, started or not
    /// (Linux blk_mq_freeze_queue_wait on q_usage_counter, taken in
    /// submit_bio and dropped at the request's end), polling the poll
    /// queues each tick, as nothing else ends their requests. Thread
    /// context.
    pub fn drain(&self) {
        while !self.idle() {
            self.poll_queues();
            let wait = if self.can_poll() {
                1
            } else {
                crate::task::percpu::MAX_SCHEDULE_TIMEOUT
            };
            self.drained.wait_event_timeout(|| self.idle(), wait);
        }
    }

    /// Hand the driver's queue state back after `drain`, for its
    /// remove to stop the device and free the rings (Linux
    /// blk_mq_free_tag_set, then the driver's del_vqs); later
    /// completions and dispatches find no queue. Thread context.
    pub fn release(&self) -> Vec<Box<dyn MqOps>> {
        self.hctxs
            .iter()
            .chain(self.polls.iter())
            .filter_map(|h| h.lock().ops.take())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::blkdev::BioOp;

    /// A driver queue of depth 2 that starts nothing
    struct Full;

    impl MqOps for Full {
        fn queue_rq(&mut self, bio: Box<Bio>) -> Queued {
            Queued::Busy(bio)
        }
        fn commit(&mut self) {}
        fn complete(&mut self, _done: &mut BioList) {}
        fn depth(&self) -> usize {
            2
        }
        fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
            self
        }
    }

    fn bio(nowait: bool) -> Box<Bio> {
        let mut b = Bio::new(BioOp::Read, 0);
        if nowait {
            b.flags = BioFlags::NOWAIT;
        }
        b
    }

    /// A NOWAIT bio finds no request once the depth's worth are taken;
    /// others still get one; an ended request frees one
    #[test]
    fn nowait_requests_bounded_by_depth() {
        let mq = BlkMq::new(alloc::vec![Box::new(Full) as Box<dyn MqOps>]).unwrap();
        assert!(mq.get_rq(&mut bio(true)));
        assert!(mq.get_rq(&mut bio(true)));
        assert!(!mq.get_rq(&mut bio(true)));
        assert!(mq.get_rq(&mut bio(false)));
        mq.put_rqs(0, 1);
        assert!(!mq.get_rq(&mut bio(true)));
        mq.put_rqs(0, 1);
        assert!(mq.get_rq(&mut bio(true)));
    }

    /// A request parked on its software queue (as for kblockd) and one
    /// the driver refused (on the dispatch list) both count until they
    /// end: draining fails them with EIO and only then finds the queue
    /// idle (Linux freezes on q_usage_counter, taken in submit_bio)
    #[test]
    fn drain_waits_for_parked_requests() {
        use core::sync::atomic::AtomicU32;
        static EIO: AtomicU32 = AtomicU32::new(0);
        fn done(b: Box<Bio>) {
            if b.status == Err(KernelError::Io) {
                EIO.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mq = Arc::new(BlkMq::new(alloc::vec![Box::new(Full) as Box<dyn MqOps>]).unwrap());
        let mut l = BioList::new();
        for _ in 0..2 {
            let mut b = bio(false);
            b.end_io = Some(done);
            assert!(mq.get_rq(&mut b));
            l.push(b);
        }
        // One run reaches the driver (which refuses it), one stays parked
        let mut first = BioList::new();
        first.push(l.pop().unwrap());
        mq.submit_list(&mut first, false);
        let _ = mq.insert(&mut l);
        assert!(!mq.idle());
        mq.start_drain();
        assert!(mq.idle());
        assert_eq!(EIO.load(Ordering::Relaxed), 2);
        mq.drain();
    }

    /// A driver queue with room for one request: others are refused
    /// (Busy) until it completes
    struct One {
        busy: Option<Box<Bio>>,
    }

    impl MqOps for One {
        fn queue_rq(&mut self, bio: Box<Bio>) -> Queued {
            if self.busy.is_some() {
                return Queued::Busy(bio);
            }
            self.busy = Some(bio);
            Queued::Started
        }
        fn commit(&mut self) {}
        /// The started request is done
        fn complete(&mut self, done: &mut BioList) {
            if let Some(b) = self.busy.take() {
                done.push(b);
            }
        }
        fn depth(&self) -> usize {
            4
        }
        fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
            self
        }
    }

    /// A request the driver refuses for want of room (virtio-blk: no
    /// free full-size table) waits on the dispatch list and starts when
    /// a completion makes room (Linux BLK_STS_RESOURCE, rerun on
    /// completion)
    #[test]
    fn refused_request_restarts_on_completion() {
        use core::sync::atomic::AtomicU32;
        static ENDED: AtomicU32 = AtomicU32::new(0);
        fn done(_b: Box<Bio>) {
            ENDED.fetch_add(1, Ordering::Relaxed);
        }
        let ops = One { busy: None };
        let mq = Arc::new(BlkMq::new(alloc::vec![Box::new(ops) as Box<dyn MqOps>]).unwrap());
        for _ in 0..2 {
            let mut b = bio(false);
            b.end_io = Some(done);
            mq.submit(b);
        }
        // One started, one refused and waiting
        assert_eq!(mq.rqs[0].load(Ordering::Relaxed), 2);
        assert!(!mq.hctxs[0].lock().dispatch.is_empty());
        // The first completes: it ends and the waiting one starts
        mq.complete(0);
        assert_eq!(ENDED.load(Ordering::Relaxed), 1);
        assert!(mq.hctxs[0].lock().dispatch.is_empty());
        assert_eq!(mq.rqs[0].load(Ordering::Relaxed), 1);
        mq.complete(0);
        assert_eq!(ENDED.load(Ordering::Relaxed), 2);
        assert!(mq.idle());
    }
}
