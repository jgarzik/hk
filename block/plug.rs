//! Plugging: a task holds its bios back and sends them as a batch
//! (Linux block/blk-core.c blk_start_plug/blk_finish_plug, blk-mq.c
//! blk_add_rq_to_plug and blk_mq_flush_plug_list, blk-merge.c
//! blk_attempt_plug_merge)
//!
//! While [`blk_plug`] runs a closure (Linux blk_start_plug ...
//! blk_finish_plug, the outermost plug wins), bios a task submits to
//! a blk-mq queue wait on its plug instead of going out one by one. A
//! bio that continues the last one held for the same queue, or ends
//! where it starts, merges into its request when the queue's limits
//! allow (back and front merges; Linux blk_attempt_bio_merge). The plug
//! goes out when it holds `BLK_MAX_REQUEST_COUNT` requests, or its last
//! request reaches `BLK_PLUG_FLUSH_SIZE`, at the finish, and whenever
//! the task is about to sleep (Linux sched_submit_work: a task may wait
//! for something only its held bios would bring). Going out queues each
//! queue's run of bios on the CPU's software queue at once, so the
//! hardware queue is dispatched and the device notified once.
//!
//! Bio-based queues, flushes and the writes of a FUA sequence are never
//! plugged (Linux: blk_mq_submit_bio only, op_is_flush bypasses it).
//!
//! ## Locking
//!
//! A plug is reached only by its task: `Task.plug` points at it while
//! it is the active one (Linux current->plug), set and read by the task
//! itself, also from `schedule()` on the way to sleep (no spin lock is
//! held there, `might_sleep` checked). Going out takes the software and
//! hardware queue locks as any submission does.

use alloc::boxed::Box;
use core::sync::atomic::Ordering;

use super::blkdev::{Bio, BioList, BioOp, RequestQueue};
use crate::task::percpu::current;

/// Requests a plug holds before it goes out (Linux BLK_MAX_REQUEST_COUNT,
/// twice that for bios to several queues)
const BLK_MAX_REQUEST_COUNT: usize = 32;
/// A last request this big sends the plug out (Linux BLK_PLUG_FLUSH_SIZE)
const BLK_PLUG_FLUSH_SIZE: u64 = 128 * 1024;

/// A task's plug (Linux struct blk_plug)
pub struct BlkPlug {
    /// Requests held, oldest first (Linux mq_list)
    list: BioList,
    /// Requests in `list`
    count: usize,
    /// They are for more than one queue
    multiple_queues: bool,
}

/// Run `f` with the current task's bios plugged, then send what is
/// held (Linux blk_start_plug ... blk_finish_plug). The plug lives in
/// this frame and is unhooked before it returns, so nothing can keep
/// it past its life; within an active plug, `f` just runs
pub fn blk_plug<R>(f: impl FnOnce() -> R) -> R {
    let t = current();
    if !t.plug.load(Ordering::Relaxed).is_null() {
        return f();
    }
    let mut plug = BlkPlug {
        list: BioList::new(),
        count: 0,
        multiple_queues: false,
    };
    let p = &raw mut plug;
    t.plug.store(p, Ordering::Relaxed);
    let r = f();
    // SAFETY: `plug` is alive in this frame; the task's pointer, the
    // only other way to it, is used by this task alone and not now
    flush(unsafe { &mut *p });
    current()
        .plug
        .store(core::ptr::null_mut(), Ordering::Relaxed);
    r
}

/// Send what a plug holds (Linux blk_mq_flush_plug_list): each queue's
/// consecutive bios as one batch
fn flush(p: &mut BlkPlug) {
    let mut l = core::mem::take(&mut p.list);
    p.count = 0;
    p.multiple_queues = false;
    let mut run = BioList::new();
    let mut q = 0;
    while let Some(b) = l.pop() {
        if b.plug_q != q && !run.is_empty() {
            send(q, &mut run);
        }
        q = b.plug_q;
        run.push(b);
    }
    if !run.is_empty() {
        send(q, &mut run);
    }
}

/// Queue `run`, bios for the queue at address `q`
fn send(q: usize, run: &mut BioList) {
    // SAFETY: `hold` took `q` from a live queue; its disk outlives the
    // bios submitted to it (the submitter keeps its block device until
    // they complete), and they are still held
    let q = unsafe { &*(q as *const RequestQueue) };
    match q.mq() {
        Some(mq) => mq.submit_list(run),
        None => unreachable!("plugged bio for a bio-based queue"),
    }
}

/// The current task is about to sleep: send its plug (Linux
/// sched_submit_work -> blk_flush_plug). The plug stays active
pub fn flush_on_sleep() {
    let p = current().plug.load(Ordering::Relaxed);
    if p.is_null() {
        return;
    }
    // SAFETY: an active plug is in a `blk_plug` frame of this task,
    // unhooked before that returns; only this task reaches it, and it is
    // in the scheduler, not in a plug operation (none sleeps)
    let p = unsafe { &mut *p };
    if p.count > 0 {
        flush(p);
    }
}

/// Hold `bio` for `q` on the current task's plug, merged into a held
/// request if it can be; it comes back if there is no plug (Linux
/// blk_mq_submit_bio: blk_attempt_plug_merge, blk_add_rq_to_plug)
pub fn hold(q: &RequestQueue, mut bio: Box<Bio>) -> Result<(), Box<Bio>> {
    let p = current().plug.load(Ordering::Relaxed);
    if p.is_null() {
        return Err(bio);
    }
    // SAFETY: as in `flush_on_sleep`; the task is submitting, not
    // sleeping, so nothing else uses the plug meanwhile
    let p = unsafe { &mut *p };
    bio.plug_q = core::ptr::from_ref(q) as usize;
    let bio = match p.list.last_mut() {
        Some(last) if last.plug_q == bio.plug_q => match merge(q, last, bio) {
            Ok(()) => return Ok(()),
            Err(b) => b,
        },
        _ => bio,
    };
    let limit = if p.multiple_queues {
        2 * BLK_MAX_REQUEST_COUNT
    } else {
        BLK_MAX_REQUEST_COUNT
    };
    let big = p
        .list
        .last_mut()
        .is_some_and(|l| l.rq_sectors() << 9 >= BLK_PLUG_FLUSH_SIZE);
    if p.count >= limit || big {
        flush(p);
    }
    if p.list.last_mut().is_some_and(|l| l.plug_q != bio.plug_q) {
        p.multiple_queues = true;
    }
    p.list.push(bio);
    p.count += 1;
    Ok(())
}

/// Merge `bio` into the request `rq` heads, behind it or in front,
/// within `q`'s limits (Linux blk_rq_merge_ok, ll_back_merge_fn,
/// ll_front_merge_fn); it comes back if it does not fit
fn merge(q: &RequestQueue, rq: &mut Bio, mut bio: Box<Bio>) -> Result<(), Box<Bio>> {
    let lim = &q.limits;
    let ok = rq.op == bio.op
        && rq.op != BioOp::Flush
        && rq.flags == bio.flags
        && rq.rq_sectors() + bio.sectors() <= u64::from(lim.max_sectors)
        && rq.rq_nr_segs() + bio.segs.len() <= lim.max_segments as usize;
    if !ok {
        return Err(bio);
    }
    if rq.sector + rq.rq_sectors() == bio.sector {
        rq.merged.push(bio);
        return Ok(());
    }
    if bio.sector + bio.sectors() == rq.sector {
        // `bio` heads the request: it takes the head's place in the
        // plug, the old head and its merged bios follow it
        core::mem::swap(rq, &mut *bio);
        let mut rest = core::mem::take(&mut bio.merged);
        rq.merged.push(bio);
        rq.merged.append(&mut rest);
        return Ok(());
    }
    Err(bio)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::blkdev::{BlockDriver, QueueLimits};
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    struct Nop;

    impl BlockDriver for Nop {
        fn submit_bio(&self, _bio: Box<Bio>) {}
    }

    fn queue(max_sectors: u32, max_segments: u32) -> RequestQueue {
        let lim = QueueLimits {
            max_sectors,
            max_segments,
            ..QueueLimits::default()
        };
        RequestQueue::new_bio(Arc::new(Nop), lim, false)
    }

    /// A read of `pages` pages at `sector`
    fn bio(sector: u64, pages: usize) -> Box<Bio> {
        let mut b = Bio::new(BioOp::Read, sector);
        for i in 0..pages {
            b.add_seg(0x1000 * (sector + i as u64), 0, 4096);
        }
        b
    }

    fn sectors(rq: &Bio) -> Vec<u64> {
        core::iter::once(rq.sector)
            .chain(rq.merged.iter().map(|b| b.sector))
            .collect()
    }

    #[test]
    fn back_and_front_merges() {
        let q = queue(1024, 32);
        let mut rq = bio(16, 2);
        assert!(merge(&q, &mut rq, bio(32, 1)).is_ok());
        assert!(merge(&q, &mut rq, bio(8, 1)).is_ok());
        assert_eq!(sectors(&rq), [8, 16, 32]);
        assert_eq!((rq.rq_sectors(), rq.rq_nr_segs()), (32, 4));
        assert_eq!(rq.rq_segs().count(), 4);
        // Not adjacent, another op, another flag: refused
        assert!(merge(&q, &mut rq, bio(48, 1)).is_err());
        let mut w = bio(40, 1);
        w.op = BioOp::Write;
        assert!(merge(&q, &mut rq, w).is_err());
        let mut f = bio(40, 1);
        f.flags = crate::block::blkdev::BioFlags::FUA;
        assert!(merge(&q, &mut rq, f).is_err());
    }

    #[test]
    fn merges_within_limits() {
        // 16 sectors (two pages) at most
        let q = queue(16, 32);
        let mut rq = bio(0, 1);
        assert!(merge(&q, &mut rq, bio(8, 1)).is_ok());
        assert!(merge(&q, &mut rq, bio(16, 1)).is_err());
        // Two segments at most
        let q = queue(1024, 2);
        let mut rq = bio(0, 2);
        assert!(merge(&q, &mut rq, bio(16, 1)).is_err());
    }

    #[test]
    fn request_ends_bio_by_bio() {
        use core::sync::atomic::AtomicU32;
        static ENDED: AtomicU32 = AtomicU32::new(0);
        fn done(b: Box<Bio>) {
            assert_eq!(b.status, Err(crate::util::error::KernelError::Io));
            ENDED.fetch_add(1, Ordering::Relaxed);
        }
        let q = queue(1024, 32);
        let mut rq = bio(0, 1);
        rq.end_io = Some(done);
        for s in [8, 16] {
            let mut b = bio(s, 1);
            b.end_io = Some(done);
            assert!(merge(&q, &mut rq, b).is_ok());
        }
        rq.status = Err(crate::util::error::KernelError::Io);
        crate::block::blkdev::rq_end(rq);
        assert_eq!(ENDED.load(Ordering::Relaxed), 3);
    }
}
