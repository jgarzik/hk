//! An AIO context (Linux fs/aio.c struct kioctx): its ring, its free
//! event slots, the completion of requests into the ring, the readers
//! of events (io_getevents), and its end (io_destroy, exit_aio).
//!
//! Locking (doc/LOCKING.md 3.11, AIO):
//! - `comp` (Linux completion_lock, IrqSpinlock): the kernel's tail and
//!   the count of events posted but not yet given back as free slots;
//!   a completion writes its event and the tail under it, in any
//!   context. A leaf.
//! - `ring_lock` (Linux ring_lock, sleeping): one reader of events at a
//!   time copies them to user space and moves the head; above the
//!   mmap_lock (the copy may fault).
//! - `active` (Linux ctx_lock, IrqSpinlock): requests that can be
//!   cancelled (IOCB_CMD_POLL), taken by io_cancel and the context's end;
//!   a poll request's state lock nests inside it.
//! - `reap` (IrqSpinlock leaf): requests whose event is posted, waiting
//!   to be released in thread context (their pins dirtied under page
//!   locks, their file dropped: Linux bio_dirty_work, delayed_fput),
//!   by io_getevents, io_submit, the context's end, or `reap_work` on
//!   the system workqueue a tick later.
//! - `users` (Linux percpu_ref users) counts the syscalls using the
//!   context, `reqs` (percpu_ref reqs) the requests alive: the end waits
//!   for both to drain.

use alloc::sync::{Arc, Weak};
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::abi::{EVENT_SIZE, IoEvent};
use super::kiocb::{ActiveAdapter, Kiocb, ReapAdapter};
use super::ring::AioRing;
use crate::io::eventfd::Eventfd;
use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::{WaitEntry, WaitQueue, signal_pending};
use crate::task::percpu::{SleepState, WakeMode, try_to_wake_up};
use crate::task::workqueue::{DelayedWork, SYSTEM_WQ};
use crate::time::hrtimer::HrClock;
use crate::uaccess::copy_to_user;
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::try_arc_cyclic;
use crate::util::list::ArcList;

/// The completion side, under `Kioctx.comp`
struct Comp {
    /// Where the next event goes (Linux ctx->tail)
    tail: u32,
    /// Events posted whose slots are not yet free again (Linux
    /// completed_events)
    completed: u32,
}

/// An AIO context
pub struct Kioctx {
    /// Its slot in its address space's table (Linux ctx->id)
    id: AtomicU32,
    /// The ring's user address, the context id (Linux user_id and
    /// mmap_base): moved by mremap under the mmap_lock
    user_id: AtomicU64,
    /// What io_setup asked for, counted in aio-nr (Linux max_reqs)
    max_reqs: u32,
    ring: Arc<AioRing>,
    /// io_destroy or the exit began (Linux ctx->dead)
    dead: AtomicBool,
    /// Event slots free for new requests (Linux reqs_available)
    avail: AtomicU32,
    comp: IrqSpinlock<Comp>,
    ring_lock: crate::sync::Mutex<()>,
    /// io_getevents sleepers (Linux ctx->wait)
    wait: WaitQueue,
    /// Requests that can be cancelled (Linux active_reqs)
    active: IrqSpinlock<ArcList<ActiveAdapter>>,
    /// Requests alive (Linux ctx->reqs)
    reqs: AtomicUsize,
    /// Syscalls using it (Linux ctx->users)
    users: AtomicUsize,
    /// Woken as `users` or `reqs` drain, or a request waits in `reap`,
    /// once the context is dead
    idle: WaitQueue,
    /// Ended requests waiting for release in thread context
    reap: IrqSpinlock<ArcList<ReapAdapter>>,
    reap_work: Arc<IrqSpinlock<DelayedWork>>,
}

/// A syscall's use of a live context (Linux percpu_ref_tryget_live of
/// ctx->users)
pub struct CtxRef(Arc<Kioctx>);

impl core::ops::Deref for CtxRef {
    type Target = Arc<Kioctx>;
    fn deref(&self) -> &Arc<Kioctx> {
        &self.0
    }
}

impl CtxRef {
    /// A use of `ctx`, unless it is dead
    pub fn get(ctx: Arc<Kioctx>) -> Option<Self> {
        // Against `kill`: either this sees `dead`, or the kill sees the
        // count (both SeqCst)
        ctx.users.fetch_add(1, Ordering::SeqCst);
        if ctx.dead.load(Ordering::SeqCst) {
            ctx.put_user();
            return None;
        }
        Some(Self(ctx))
    }
}

impl Drop for CtxRef {
    fn drop(&mut self) {
        self.0.put_user();
    }
}

/// Wake an io_getevents sleeper (`private`: the events it waits for)
/// once the ring holds that many (`key`), or at any wakeup without a
/// count (key 0: the context's end)
fn aio_wake(e: &WaitEntry, mode: WakeMode, key: usize) -> bool {
    if key != 0 && key < e.private {
        return false;
    }
    try_to_wake_up(e.task(), mode)
}

impl Kioctx {
    /// A context over `ring`, for `max_reqs` requests asked (Linux
    /// ioctx_alloc); not yet in a table
    pub fn new(ring: Arc<AioRing>, max_reqs: u32) -> KernelResult<Arc<Self>> {
        let nr = ring.nr();
        let ctx = try_arc_cyclic(|me: &Weak<Self>| {
            let w = me.clone();
            Self {
                id: AtomicU32::new(0),
                user_id: AtomicU64::new(0),
                max_reqs,
                ring: ring.clone(),
                dead: AtomicBool::new(false),
                avail: AtomicU32::new(nr - 1),
                comp: IrqSpinlock::new(Comp {
                    tail: 0,
                    completed: 0,
                }),
                ring_lock: crate::sync::Mutex::new(()),
                wait: WaitQueue::new(),
                active: IrqSpinlock::new(ArcList::new()),
                reqs: AtomicUsize::new(0),
                users: AtomicUsize::new(0),
                idle: WaitQueue::new(),
                reap: IrqSpinlock::new(ArcList::new()),
                reap_work: crate::util::kalloc::arc_nofail(IrqSpinlock::new(DelayedWork::new(
                    move || {
                        if let Some(c) = w.upgrade() {
                            c.reap_all();
                        }
                    },
                ))),
            }
        })?;
        Ok(ctx)
    }

    pub fn ring(&self) -> &AioRing {
        &self.ring
    }

    pub fn id(&self) -> u32 {
        self.id.load(Ordering::Relaxed)
    }

    /// Set its table slot (the table lock held)
    pub fn set_id(&self, id: u32) {
        self.id.store(id, Ordering::Relaxed);
        self.ring.set_id(id);
    }

    pub fn user_id(&self) -> u64 {
        self.user_id.load(Ordering::Acquire)
    }

    pub fn set_user_id(&self, addr: u64) {
        self.user_id.store(addr, Ordering::Release);
    }

    pub fn max_reqs(&self) -> u32 {
        self.max_reqs
    }

    /// Events the ring holds (Linux ctx->nr_events)
    pub fn nr_events(&self) -> u32 {
        self.ring.nr()
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// Its ring moved to `start` by mremap (Linux aio_ring_mremap): the
    /// whole ring of a live context only (EINVAL)
    pub fn ring_moved(&self, start: u64, len: u64) -> KernelResult<()> {
        if self.is_dead() || len != self.ring.bytes() {
            return Err(KernelError::InvalidArgument);
        }
        self.set_user_id(start);
        Ok(())
    }

    /// A syscall is done with it: the last one wakes the end's wait
    /// for the users, if the end has begun.
    ///
    /// Against `drain` this is store buffering: the dropper writes
    /// `users` then reads `dead`, the end wrote `dead` (`mark_dead`)
    /// then reads `users` after queueing itself on `idle`. All four
    /// accesses are SeqCst, so in their single total order at least one
    /// side sees the other's write: either this sees `dead` and wakes
    /// the end (whose queueing it then follows under `idle`'s lock), or
    /// the end's check sees the count at 0 and never sleeps. With
    /// AcqRel/Acquire both could read the old values and the end would
    /// sleep forever (Linux: percpu_ref_kill + the confirm/release
    /// callbacks under the percpu_ref's lock).
    fn put_user(&self) {
        if self.users.fetch_sub(1, Ordering::SeqCst) == 1 && self.is_dead() {
            self.idle.wake_all();
        }
    }

    // ------------------------------------------------------------------
    // Event slots (Linux get_reqs_available, put_reqs_available,
    // refill_reqs_available)
    // ------------------------------------------------------------------

    fn try_take(&self) -> bool {
        self.avail
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
    }

    /// Give back the slots of posted events user space has consumed
    /// (`comp` held): those past the events still in the ring
    fn refill(&self, c: &mut Comp, head: u32, tail: u32) {
        let nr = self.ring.nr();
        let head = head % nr;
        let in_ring = if head <= tail {
            tail - head
        } else {
            nr - (head - tail)
        };
        let freed = c.completed.saturating_sub(in_ring);
        if freed == 0 {
            return;
        }
        c.completed -= freed;
        self.put_slots(freed);
    }

    /// Take a slot for a new request; false when the ring could not hold
    /// its event (EAGAIN)
    pub fn get_slot(&self) -> bool {
        if self.try_take() {
            return true;
        }
        {
            let mut c = self.comp.lock();
            if c.completed > 0 {
                let tail = c.tail;
                self.refill(&mut c, self.ring.head(), tail);
            }
        }
        self.try_take()
    }

    /// Give back `n` slots (a request that failed before it was issued)
    pub fn put_slots(&self, n: u32) {
        self.avail.fetch_add(n, Ordering::AcqRel);
    }

    // ------------------------------------------------------------------
    // Completion (Linux aio_complete): any context
    // ------------------------------------------------------------------

    /// Post `ev` to the ring, signal `eventfd`, wake the io_getevents
    /// sleepers waiting for no more events than the ring now holds. Any
    /// context: IrqSpinlocks and wakeups only.
    pub fn complete(&self, ev: IoEvent, eventfd: Option<&Eventfd>) {
        let nr = self.ring.nr();
        let avail = {
            let mut c = self.comp.lock();
            let tail = c.tail;
            self.ring.write_event(tail, ev);
            let next = if tail + 1 >= nr { 0 } else { tail + 1 };
            c.tail = next;
            let head = self.ring.head();
            // After the event (Release): a reader of the tail sees it
            self.ring.set_tail(next);
            c.completed += 1;
            if c.completed > 1 {
                self.refill(&mut c, head, next);
            }
            let head = head % nr;
            if next > head {
                next - head
            } else {
                next + nr - head
            }
        };
        if let Some(e) = eventfd {
            e.signal();
        }
        self.wait.wake_poll(avail.max(1));
    }

    /// Hand `k`, whose event is posted, to a thread for its release
    /// (any context)
    pub fn defer(&self, k: Arc<Kiocb>) {
        let first = {
            let mut l = self.reap.lock();
            let first = l.is_empty();
            l.push_back(k);
            first
        };
        if first {
            SYSTEM_WQ.queue_delayed_work(self.reap_work.clone(), 1);
        }
        if self.is_dead() {
            self.idle.wake_all();
        }
    }

    /// Release the ended requests waiting for it (thread context)
    pub fn reap_all(&self) {
        loop {
            let k = self.reap.lock().pop_front();
            match k {
                Some(k) => drop(k),
                None => return,
            }
        }
    }

    // ------------------------------------------------------------------
    // Requests alive and cancellable
    // ------------------------------------------------------------------

    /// A request is made (by a syscall holding a use: never after the
    /// end's wait for the users, so never past its count of `reqs`)
    pub fn req_get(&self) {
        self.reqs.fetch_add(1, Ordering::SeqCst);
    }

    /// A request is released: the last one wakes the end's wait for
    /// the requests, if the end has begun (SeqCst against `drain`'s read
    /// of `reqs` after `mark_dead`, as in `put_user`)
    pub fn req_put(&self) {
        if self.reqs.fetch_sub(1, Ordering::SeqCst) == 1 && self.is_dead() {
            self.idle.wake_all();
        }
    }

    /// The cancellable list, locked (Linux ctx_lock)
    pub fn active_lock(&self) -> crate::sync::IrqSpinlockGuard<'_, ArcList<ActiveAdapter>> {
        self.active.lock()
    }

    /// Cancel the request of user iocb `obj` (Linux io_cancel's search):
    /// EINVAL if no cancellable one has it
    pub fn cancel(&self, obj: u64) -> KernelResult<()> {
        let k = {
            let mut l = self.active.lock();
            let found = l.iter().find(|k| k.obj() == obj).map(|k| &raw const *k);
            // SAFETY: found on this list just now, under its lock
            found.map(|p| unsafe { l.remove(&*p) })
        };
        match k {
            Some(k) => {
                k.cancel();
                Ok(())
            }
            None => Err(KernelError::InvalidArgument),
        }
    }

    /// Cancel every cancellable request (Linux free_ioctx_users)
    fn cancel_all(&self) {
        loop {
            let k = self.active.lock().pop_front();
            match k {
                Some(k) => k.cancel(),
                None => return,
            }
        }
    }

    // ------------------------------------------------------------------
    // The end (Linux kill_ioctx and the waits of io_destroy/exit_aio)
    // ------------------------------------------------------------------

    /// Mark it dead (EINVAL if it was) and wake its sleepers; true if
    /// this call did
    pub fn mark_dead(&self) -> bool {
        if self.dead.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.wait.wake_all();
        true
    }

    /// After `mark_dead` (thread context, no use of it held by the
    /// caller): wait out the syscalls using it, cancel what can be, and
    /// wait until every request is released, releasing those that
    /// ended meanwhile (Linux: io_destroy's wait for ctx->reqs, which
    /// keeps the kernel off user buffers once it returns)
    pub fn drain(&self) {
        // SeqCst reads after `mark_dead`'s SeqCst write of `dead`: the
        // other half of the handshake in `put_user` / `req_put`
        self.idle
            .wait_event(|| self.users.load(Ordering::SeqCst) == 0);
        self.cancel_all();
        loop {
            self.reap_all();
            if self.reqs.load(Ordering::SeqCst) == 0 {
                return;
            }
            // A request pushed onto `reap` meanwhile: `defer` pushes
            // under `reap`'s lock before it reads `dead`, so either this
            // check (under the same lock) sees it, or `defer` sees
            // `dead` and wakes this wait
            self.idle.wait_event(|| {
                self.reqs.load(Ordering::SeqCst) == 0 || !self.reap.lock().is_empty()
            });
        }
    }

    // ------------------------------------------------------------------
    // Reading events (Linux aio_read_events_ring, read_events)
    // ------------------------------------------------------------------

    /// Events in the ring now, as far as user space's head says
    fn ready(&self) -> u32 {
        let nr = self.ring.nr();
        let head = self.ring.head() % nr;
        let tail = self.ring.tail() % nr;
        (tail + nr - head) % nr
    }

    /// Copy up to `nr` events to `out` and move the head past them: how
    /// many; EFAULT leaves the head where it was
    fn read_ring(&self, out: u64, max: usize) -> KernelResult<usize> {
        /// Events copied out at once
        const CHUNK: usize = 16;
        let _g = self.ring_lock.lock();
        let nr = self.ring.nr();
        let (head, tail) = (self.ring.head(), self.ring.tail());
        if head == tail {
            return Ok(0);
        }
        let (mut head, tail) = (head % nr, tail % nr);
        let mut done = 0usize;
        let mut buf = [IoEvent::default(); CHUNK];
        while done < max && head != tail {
            let run = if head <= tail { tail } else { nr } - head;
            let k = (run as usize).min(max - done).min(CHUNK);
            for (j, e) in buf[..k].iter_mut().enumerate() {
                // Lossless: below `nr`
                *e = self.ring.read_event(head + j as u32);
            }
            let to = out
                .checked_add((done * EVENT_SIZE) as u64)
                .ok_or(KernelError::BadAddress)?;
            copy_to_user(to, crate::util::pod::slice_bytes(&buf[..k]))?;
            done += k;
            // Lossless: k <= nr
            head = (head + k as u32) % nr;
        }
        self.ring.set_head(head);
        Ok(done)
    }

    /// One read into `out` past the `*got` events already there (Linux
    /// aio_read_events): Some(result) when the wait is over (an error,
    /// the context dead, or at least `min` events), the count if any
    /// events were taken
    fn read_once(
        &self,
        min: usize,
        max: usize,
        out: u64,
        got: &mut usize,
    ) -> Option<KernelResult<usize>> {
        let at = out.wrapping_add((*got * EVENT_SIZE) as u64);
        let r = self.read_ring(at, max - *got);
        if let Ok(n) = r {
            *got += n;
        }
        let r = if self.is_dead() {
            Err(KernelError::InvalidArgument)
        } else {
            r
        };
        match r {
            Err(e) if *got == 0 => Some(Err(e)),
            Err(_) => Some(Ok(*got)),
            Ok(_) if *got >= min => Some(Ok(*got)),
            Ok(_) => None,
        }
    }

    /// Wait for at least `min` and take up to `max` events into `out`
    /// (Linux read_events): `deadline` on CLOCK_MONOTONIC (None: no
    /// limit; Some(0): no wait). The events taken, maybe fewer than
    /// `min` after the deadline or a signal; an error if none
    pub fn read_events(
        &self,
        min: usize,
        max: usize,
        out: u64,
        deadline: Option<u64>,
    ) -> KernelResult<usize> {
        let mut got = 0;
        if let Some(r) = self.read_once(min, max, out, &mut got) {
            return r;
        }
        if deadline == Some(0) {
            return Ok(got);
        }
        loop {
            let want = min - got;
            let w = pin!(WaitEntry::with_func(Some(aio_wake), want));
            self.wait
                .prepare_to_wait(w.as_ref(), SleepState::Interruptible);
            let ready = self.is_dead() || self.ready() as usize >= want;
            let stop = !ready
                && (signal_pending()
                    || crate::time::hrtimer::schedule_hrtimeout(deadline, HrClock::Monotonic));
            self.wait.finish_wait(w.as_ref());
            if let Some(r) = self.read_once(min, max, out, &mut got) {
                return r;
            }
            if stop {
                return Ok(got);
            }
        }
    }

    /// Release what waits in `reap` (a syscall's chance to do it before
    /// the work item: no extra wakeup in steady use)
    pub fn reap_now(&self) {
        if !self.reap.lock().is_empty() {
            self.reap_all();
        }
    }
}
