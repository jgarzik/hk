//! io-wq: the worker threads of a task's io_uring requests that would
//! block (Linux io_uring/io-wq.c)
//!
//! A request whose nonblocking attempt would wait, or that asks for it
//! (IOSQE_ASYNC), or an operation Linux always runs asynchronously
//! (fsync, statx, openat, ...), a link chain, or a request a drain held
//! back is queued on its submitter's io-wq and run to its end, blocking,
//! by a worker (Linux io_queue_iowq -> io_wq_enqueue). Workers are io
//! threads of the submitter's process (`task::percpu::create_io_thread`,
//! Linux create_io_thread): they share its mm, descriptors and fs
//! context. Each request runs with the credentials its submitter had
//! when it was queued (`task::override_creds`, Linux io_prep_async_work's
//! req->creds and io_issue_sqe's override_creds), not the worker's own,
//! which are the owner's at the worker's creation: a submitter that
//! dropped privilege since does not get it back through a worker.
//!
//! Two pools (Linux io_wq_acct): bounded work (regular files and block
//! devices), at most four workers per CPU, and unbounded work (pipes,
//! sockets, ...), up to RLIMIT_NPROC, since each may block for good.
//! Workers start on demand, when the pool has none idle, by the owner;
//! asked from another context (a worker, another task's completion), the
//! owner starts them in a task_work callback (Linux create_worker_cb).
//! They exit after five idle seconds, but a pool's last one (Linux
//! WORKER_IDLE_TIMEOUT, IO_WORKER_F_FIXED). At the owner's exit or exec
//! (`cancel`) the queued work ends with ECANCELED, running workers are
//! interrupted (TIF_NOTIFY_SIGNAL: a blocking operation ends with EINTR,
//! Linux io_wq_cancel_running) and the owner waits until every worker is
//! gone (Linux io_wq_exit_start, io_wq_put_and_exit); SIGKILL (a group
//! exit, exec's de_thread) ends them too.
//!
//! Locking: `Acct.q` and `IoWq.workers` are spin Mutex leaves, thread
//! context (no work is queued from an interrupt handler: completions go
//! through the task context first); workers are started and woken after
//! they are released. Work comes boxed (`Work::new`) and a worker's node
//! is allocated when it is started (Linux create_io_worker), so nothing
//! allocates under them.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, Ordering};

use super::opreq::{OpReq, run_chain};
use super::rw::Req;
use crate::sync::spin::Mutex;
use crate::sync::waitqueue::WaitQueue;
use crate::task::percpu::{TaskRef, current, task_ref};
use crate::task::task_work::{TaskWork, WorkHead, task_work_run};
use crate::util::error::KernelResult;
use crate::util::kalloc::{try_arc, try_box};
use crate::util::kmem::KVec;
use crate::util::list::{ArcList, BoxList, Link};

/// A worker idle this long exits, unless it is its pool's last (Linux
/// WORKER_IDLE_TIMEOUT: 5 s)
const IDLE_MS: u64 = 5000;

/// What a worker runs
pub enum WorkKind {
    /// An asynchronous O_DIRECT request whose nonblocking issue would
    /// wait: issued again, blocking (its end comes through its bios)
    Dio(Arc<Req>),
    /// An operation run to its end
    Op(OpReq),
    /// A link chain, its members in order (Linux IOSQE_IO_LINK)
    Chain(KVec<OpReq>),
}

/// A queued work item (Linux io_wq_work on its acct's work_list)
pub struct Work {
    link: Link,
    kind: WorkKind,
}

crate::adapter!(WorkAdapter, Work, link);

impl Work {
    /// Boxed for a queue: the only allocation, before any lock
    pub fn new(kind: WorkKind) -> KernelResult<Box<Self>> {
        try_box(Self {
            link: Link::new(),
            kind,
        })
    }

    /// Run it to its end
    fn run(self) {
        match self.kind {
            WorkKind::Dio(r) => r.issue_blocking(),
            WorkKind::Op(o) => o.run(),
            WorkKind::Chain(c) => run_chain(c),
        }
    }

    /// End it unrun: ECANCELED (Linux io_wq_cancel_cb)
    fn cancel(self) {
        match self.kind {
            WorkKind::Dio(r) => r.cancel(),
            WorkKind::Op(o) => o.cancel(),
            WorkKind::Chain(c) => {
                for o in c.into_vec() {
                    o.cancel();
                }
            }
        }
    }
}

/// One pool (Linux io_wq_acct)
struct Acct {
    q: Mutex<AcctQ>,
    /// Its workers wait here for work
    wait: WaitQueue,
}

struct AcctQ {
    list: BoxList<WorkAdapter>,
    workers: u32,
    idle: u32,
    /// A worker was asked for from a context that cannot start one
    want: bool,
}

impl Acct {
    const fn new() -> Self {
        Self {
            q: Mutex::new(AcctQ {
                list: BoxList::new(),
                workers: 0,
                idle: 0,
                want: false,
            }),
            wait: WaitQueue::new(),
        }
    }
}

/// A task's io-wq (Linux struct io_wq)
pub struct IoWq {
    /// Bounded (0) and unbounded (1) work
    accts: [Acct; 2],
    /// The submitter whose process the workers join
    owner: Weak<crate::task::Task>,
    /// Itself, for the workers it starts
    me: spin::Once<Weak<IoWq>>,
    /// The owner exits or execs: nothing more runs
    exiting: AtomicBool,
    /// The running workers, to interrupt them at `cancel` (Linux
    /// wq->all_list through io_worker.all_list): each links itself, its
    /// node allocated when it was started
    workers: Mutex<ArcList<WorkerLink>>,
    /// Woken when a worker exits
    gone: WaitQueue,
    /// Queued on the owner to start workers asked for elsewhere
    spawn: Arc<WorkHead>,
}

impl TaskWork for IoWq {
    /// Start the workers asked for from other contexts (Linux
    /// create_worker_cb), in the owner
    fn run(&self) {
        for i in 0..2 {
            let start = core::mem::replace(&mut self.accts[i].q.lock().want, false);
            if start {
                self.start(i);
            }
        }
    }
}

impl IoWq {
    /// The current task's io-wq
    pub fn new() -> KernelResult<Arc<Self>> {
        let spawn = try_arc(WorkHead::new())?;
        let wq = try_arc(Self {
            accts: [Acct::new(), Acct::new()],
            owner: Arc::downgrade(&task_ref(&current())),
            me: spin::Once::new(),
            exiting: AtomicBool::new(false),
            workers: Mutex::new(ArcList::new()),
            gone: WaitQueue::new(),
            spawn: spawn.clone(),
        })?;
        wq.me.call_once(|| Arc::downgrade(&wq));
        let weak: Weak<dyn TaskWork> = Arc::downgrade(&wq) as Weak<Self>;
        spawn.set_work(weak);
        Ok(wq)
    }

    /// Most workers of pool `i` (Linux: bounded 4 per CPU, unbounded
    /// RLIMIT_NPROC)
    fn max(i: usize) -> u32 {
        if i == 0 {
            4 * crate::cpu::nr_cpu_ids()
        } else {
            let n = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_NPROC);
            u32::try_from(n).unwrap_or(u32::MAX).max(1)
        }
    }

    /// Queue `w` (`unbound`: on a file that may block for good) and make
    /// sure a worker comes for it (Linux io_wq_enqueue); thread context.
    /// After `cancel` it ends unrun (ECANCELED).
    pub fn queue(&self, w: Box<Work>, unbound: bool) {
        if self.exiting.load(Ordering::Acquire) {
            return (*w).cancel();
        }
        let i = usize::from(unbound);
        let a = &self.accts[i];
        let start = {
            let mut q = a.q.lock();
            q.list.push_back(w);
            q.idle == 0 && q.workers < Self::max(i)
        };
        if start {
            self.ask_start(i);
        }
        a.wait.wake_one();
    }

    /// Start a worker of pool `i`: here in the owner, else through its
    /// callback
    fn ask_start(&self, i: usize) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        if core::ptr::eq(Arc::as_ptr(&owner), &raw const *current()) {
            self.start(i);
            return;
        }
        self.accts[i].q.lock().want = true;
        let _ = self.spawn.queue(&owner);
    }

    /// Start a worker of pool `i` in the owner's process (Linux
    /// create_io_worker); the owner runs this
    fn start(&self, i: usize) {
        let Some(wq) = self.me.get().and_then(Weak::upgrade) else {
            return;
        };
        {
            let mut q = self.accts[i].q.lock();
            if q.workers >= Self::max(i) || q.list.is_empty() {
                return;
            }
            q.workers += 1;
        }
        let started = try_arc(IoWorker {
            link: Link::new(),
            task: spin::Once::new(),
        })
        .and_then(|worker| try_arc(WorkerArg { wq, i, worker }))
        .and_then(|a| {
            let a: Arc<dyn core::any::Any + Send + Sync> = a;
            crate::task::percpu::create_io_thread(worker, a)
        });
        if started.is_err() {
            let orphans = {
                let mut q = self.accts[i].q.lock();
                q.workers -= 1;
                // None left to run them: they end unrun
                if q.workers == 0 {
                    core::mem::take(&mut q.list)
                } else {
                    BoxList::new()
                }
            };
            cancel_all(orphans);
        }
    }

    /// The owner exits or execs (Linux io_wq_exit_start, the cancel of
    /// queued and running work, io_wq_put_and_exit): queued work ends with
    /// ECANCELED, running workers are interrupted, and this waits until
    /// every worker is gone
    pub fn cancel(&self) {
        self.exiting.store(true, Ordering::Release);
        for a in &self.accts {
            let l = core::mem::take(&mut a.q.lock().list);
            cancel_all(l);
            a.wait.wake_all();
        }
        for w in self.workers.lock().iter() {
            if let Some(t) = w.task.get() {
                t.set_tif(crate::task::tif::NOTIFY_SIGNAL);
                crate::task::percpu::try_to_wake_up(
                    t,
                    crate::task::percpu::WakeMode::Interruptible,
                );
            }
        }
        while !self.none_left() {
            // The workers' ends may need this task's callbacks
            task_work_run();
            self.gone.wait_event_timeout(|| self.none_left(), 1);
        }
    }

    fn none_left(&self) -> bool {
        self.accts.iter().all(|a| a.q.lock().workers == 0)
    }
}

/// End every item of `l` unrun
fn cancel_all(mut l: BoxList<WorkAdapter>) {
    while let Some(w) = l.pop_front() {
        (*w).cancel();
    }
}

/// A worker (Linux struct io_worker), allocated before it starts
struct IoWorker {
    link: Link,
    task: spin::Once<TaskRef>,
}

crate::adapter!(WorkerLink, IoWorker, link);

/// What a worker is started with
struct WorkerArg {
    wq: Arc<IoWq>,
    i: usize,
    worker: Arc<IoWorker>,
}

/// A worker: its pool's work until it is idle too long (and not the
/// last), the owner cancels, or SIGKILL (Linux io_wq_worker)
fn worker(arg: Arc<dyn core::any::Any + Send + Sync>) {
    let Ok(arg) = arg.downcast::<WorkerArg>() else {
        return;
    };
    let (wq, i) = (&arg.wq, arg.i);
    let me = &arg.worker;
    me.task.call_once(|| task_ref(&current()));
    wq.workers.lock().push_back(me.clone());
    work_loop(wq, i);
    let gone = {
        let mut l = wq.workers.lock();
        // SAFETY: only this worker links its node, on this list, above
        unsafe { l.remove(me) }
    };
    drop(gone);
    // The last one out with work left (a kill raced a queue): it ends
    let orphans = {
        let mut q = wq.accts[i].q.lock();
        q.workers -= 1;
        if q.workers == 0 {
            core::mem::take(&mut q.list)
        } else {
            BoxList::new()
        }
    };
    cancel_all(orphans);
    wq.gone.wake_all();
}

fn work_loop(wq: &IoWq, i: usize) {
    let a = &wq.accts[i];
    loop {
        // An interrupt at cancel arrives as a callback flag: consumed here
        task_work_run();
        if crate::signal::fatal_signal_pending() || wq.exiting.load(Ordering::Acquire) {
            return;
        }
        let w = a.q.lock().list.pop_front();
        if let Some(w) = w {
            (*w).run();
            continue;
        }
        a.q.lock().idle += 1;
        let ticks = crate::task::percpu::ms_to_ticks(IDLE_MS);
        let left = a.wait.wait_event_interruptible_timeout(
            || {
                !a.q.lock().list.is_empty()
                    || wq.exiting.load(Ordering::Acquire)
                    || crate::signal::fatal_signal_pending()
            },
            ticks,
        );
        let mut q = a.q.lock();
        q.idle -= 1;
        // Idle too long: gone, unless the pool's last
        if matches!(left, Ok(0)) && q.list.is_empty() && q.workers > 1 {
            return;
        }
    }
}
