//! io-wq: worker threads for requests that would block (Linux
//! io_uring/io-wq.c)
//!
//! A request whose nonblocking issue would wait (EAGAIN with
//! IOCB_NOWAIT: no free tag, cache to write back) or that asks for it
//! (IOSQE_ASYNC) is issued again, blocking, by a worker (Linux
//! io_queue_iowq). Its memory is pinned already and its file held, so a
//! worker needs nothing of the submitter's (Linux io-wq threads share
//! the submitter's mm for requests that copy; hk punts only those that
//! do not). Its end goes back to the submitter's context like any other
//! (`Tctx::push`).
//!
//! The pools are per CPU (a request runs on the CPU that punted it):
//! bounded workers each (Linux's bounded pool), started as needed and
//! kept. Locking: `Pool.q` is an IrqSpinlock leaf; workers are started
//! and woken after it is released.

use alloc::sync::Arc;

use super::rw::{Req, ReqAdapter};
use crate::cpu::PerCpu;
use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::WaitQueue;
use crate::util::cpumask::NR_CPUS;
use crate::util::list::ArcList;

/// Most workers per CPU (Linux: a bounded pool of 4 per CPU)
const MAX_WORKERS: u32 = 4;

/// One CPU's workers and queue (Linux io_wq_acct)
struct Pool {
    q: IrqSpinlock<PoolQ>,
    wait: WaitQueue,
}

struct PoolQ {
    list: ArcList<ReqAdapter>,
    /// Workers started, and those waiting for work
    workers: u32,
    idle: u32,
}

impl Pool {
    const fn new() -> Self {
        Self {
            q: IrqSpinlock::new(PoolQ {
                list: ArcList::new(),
                workers: 0,
                idle: 0,
            }),
            wait: WaitQueue::new(),
        }
    }
}

static POOLS: PerCpu<Pool> = PerCpu::new([const { Pool::new() }; NR_CPUS]);

/// Issue `req` blocking in a worker of this CPU (Linux io_wq_enqueue),
/// starting one if none is idle and the pool has room. Thread context.
pub fn queue(req: Arc<Req>) {
    let cpu = crate::cpu::this_id();
    let p = POOLS.get(cpu);
    let start = {
        let mut q = p.q.lock();
        q.list.push_back(req);
        let start = q.idle == 0 && q.workers < MAX_WORKERS;
        if start {
            q.workers += 1;
        }
        start
    };
    if start
        && crate::task::kthread::kthread_run("iou-wrk", worker, cpu as usize, Some(cpu)).is_err()
    {
        // No worker could start: with none at all, issue it here
        let orphan = {
            let mut q = p.q.lock();
            q.workers -= 1;
            if q.workers == 0 {
                q.list.pop_front()
            } else {
                None
            }
        };
        if let Some(r) = orphan {
            r.issue_blocking();
        }
    }
    p.wait.wake_one();
}

/// A worker of CPU `cpu`'s pool (Linux io_wq_worker)
fn worker(cpu: usize) {
    let p = POOLS.get(cpu as u32);
    loop {
        let req = p.q.lock().list.pop_front();
        match req {
            Some(r) => r.issue_blocking(),
            None => {
                p.q.lock().idle += 1;
                p.wait.wait_event(|| !p.q.lock().list.is_empty());
                p.q.lock().idle -= 1;
            }
        }
    }
}
