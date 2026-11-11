//! epoll (Linux fs/eventpoll.c)
//!
//! An `Eventpoll` (the epoll file's private data) holds its items, one
//! per watched (file, fd) pair, and a ready list. Adding an item polls
//! its file with a table that registers a callback entry on each of the
//! file's wait queues (Linux ep_ptable_queue_proc); a wakeup of one of
//! them runs `ep_poll_callback`, which puts the item on the ready list
//! and wakes the epoll's waiters, so epoll_wait looks only at items that
//! had an event, and an edge-triggered item is reported once per event
//! (Linux semantics), a level-triggered one while it stays ready.
//!
//! An item holds no reference to its file (Linux epitem): the file's
//! release removes its items (`eventpoll_release`, from `__fput`, which
//! its last `fput` queues), so a closed pipe end or socket is released
//! and its peer sees EOF. To poll an item's file, epoll takes a
//! reference unless the last one is gone (`FileRef::try_get`, Linux
//! epi_fget). Items are keyed by (file, fd): closing one descriptor of a file
//! that stays open keeps the item, as on Linux. Watching an epoll file
//! is allowed EP_MAX_NESTS deep without cycles (`ep_loop_check`, ELOOP).
//!
//! Locking (doc/LOCKING.md):
//! - `Eventpoll.mtx` (sleeping, Linux ep->mtx): the item map, held
//!   across each epoll_ctl operation, each ready-list scan (epoll_wait's
//!   and the epoll file's poll) with its files' polls and copies to
//!   user, and each item's removal at its file's release; an epoll
//!   polled under another's nests in it (acyclic, EP_MAX_NESTS deep). A
//!   last `FileRef` dropped under it only queues the release (`fput`),
//!   whose `eventpoll_release` takes it later.
//! - `Eventpoll.lock` (IrqSpinlock, Linux ep->lock; the callback runs
//!   under the woken queue's lock, possibly in an interrupt): the ready
//!   list. Nothing sleeps, allocates, polls or copies to user under it,
//!   and no last `Arc<EpItem>` is dropped under it.
//! - `EpItem.regs` (spin, thread context): the item's callback entries
//!   and the owners of their queues; registering and unregistering take
//!   the file's queue locks under it (queue lock -> `Eventpoll.lock` in
//!   the callback; never the reverse).
//! - `File.f_ep` (spin leaf): the items watching the file.
//! - `EPNESTED` (sleeping): the loop check and insert of an epoll target
//!   (Linux epnested_mutex), with no spin lock held.

use crate::fs::FileRef;
use crate::util::kalloc::{try_arc, try_arc_cyclic};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::io::fget;
use crate::io::pipe::FD_CLOEXEC;
use crate::io::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::{WaitEntry, WaitQueue};
use crate::task::Fd;
use crate::task::percpu::WakeMode;
use crate::time::Deadline;
use crate::uaccess::{UserPtr, access_ok};
use crate::util::error::KernelResult;
use crate::util::list::{ArcList, Link};

/// epoll_ctl operations
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

/// epoll event masks (input)
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLPRI: u32 = 0x002;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLRDNORM: u32 = 0x040;
pub const EPOLLRDBAND: u32 = 0x080;
pub const EPOLLWRNORM: u32 = 0x100;
pub const EPOLLWRBAND: u32 = 0x200;
pub const EPOLLMSG: u32 = 0x400;
pub const EPOLLRDHUP: u32 = 0x2000;

/// epoll event masks (output only)
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;

/// epoll behavior modifiers
pub const EPOLLET: u32 = 1 << 31; // Edge-triggered
pub const EPOLLONESHOT: u32 = 1 << 30; // One-shot
pub const EPOLLWAKEUP: u32 = 1 << 29; // Wake system
pub const EPOLLEXCLUSIVE: u32 = 1 << 28; // Exclusive wakeup

/// What survives a fired EPOLLONESHOT (Linux EP_PRIVATE_BITS)
const EP_PRIVATE_BITS: u32 = EPOLLWAKEUP | EPOLLONESHOT | EPOLLET | EPOLLEXCLUSIVE;

/// The events EPOLLEXCLUSIVE may be combined with (Linux
/// EPOLLEXCLUSIVE_OK_BITS)
const EPOLLEXCLUSIVE_OK_BITS: u32 =
    EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE;

/// epoll_create1 flags
pub const EPOLL_CLOEXEC: i32 = 0o2000000;

/// Most nested epoll levels (Linux EP_MAX_NESTS)
const EP_MAX_NESTS: u32 = 4;

/// User-space epoll_event (layout differs per arch: packed only on x86_64)
pub use crate::arch::uapi::EpollEvent;

/// Most events one epoll_wait returns (Linux EP_MAX_EVENTS)
const EP_MAX_EVENTS: usize = i32::MAX as usize / core::mem::size_of::<EpollEvent>();

// ============================================================================
// Items
// ============================================================================

/// An item's callback entries on its file's wait queues, and the owners
/// those queues live in (kept alive while registered)
pub struct EpRegs {
    entries: Vec<(*const WaitQueue, Pin<alloc::boxed::Box<WaitEntry>>)>,
    owners: Vec<Arc<dyn core::any::Any + Send + Sync>>,
    /// The item the entries call back to
    item: *const EpItem,
}

// SAFETY: the raw pointers are only followed under the owning locks
// (module docs)
unsafe impl Send for EpRegs {}

impl EpRegs {
    /// Register a callback entry on `wq` (Linux ep_ptable_queue_proc)
    pub(crate) fn add(&mut self, wq: &WaitQueue) {
        if self.entries.iter().any(|(q, _)| core::ptr::eq(*q, wq)) {
            return;
        }
        if self.entries.try_reserve(1).is_err() {
            return;
        }
        let e = alloc::boxed::Box::pin(WaitEntry::with_func(
            Some(ep_poll_callback),
            self.item as usize,
        ));
        wq.add_wait_queue(e.as_ref());
        self.entries.push((core::ptr::from_ref::<WaitQueue>(wq), e));
    }

    /// Keep `owner` alive while registered
    pub(crate) fn hold(&mut self, owner: Arc<dyn core::any::Any + Send + Sync>) {
        self.owners.push(owner);
    }

    /// Remove every entry (the queues' owners are dropped after)
    fn clear(&mut self) {
        for (wq, e) in self.entries.drain(..) {
            // SAFETY: the queue belongs to the file (alive: unregistering
            // runs before its last close completes) or to `owners`
            unsafe { (*wq).remove_wait_queue(e.as_ref()) };
        }
        self.owners.clear();
    }
}

/// One watched (file, fd) pair (Linux struct epitem)
pub struct EpItem {
    /// On the ready list (under `Eventpoll.lock`)
    rdlink: Link,
    fd: Fd,
    /// The file: no reference (its last close removes the item)
    file: Weak<File>,
    /// The epoll it belongs to; alive while the item's entries are
    /// registered (the epoll unregisters them before it is freed)
    ep_raw: *const Eventpoll,
    ep: Weak<Eventpoll>,
    /// The user's event mask and data (Linux epi->event)
    events: AtomicU32,
    data: AtomicU64,
    /// Removed: no longer reported or queued
    dead: AtomicBool,
    regs: crate::sync::spin::Mutex<EpRegs>,
}

// SAFETY: `ep_raw` is followed only while registered (see above); the
// rest is atomics and locks
unsafe impl Send for EpItem {}
// SAFETY: as Send
unsafe impl Sync for EpItem {}

crate::adapter!(RdAdapter, EpItem, rdlink);

impl EpItem {
    /// The ready events of its file, without registering
    fn poll(&self) -> u32 {
        let Some(file) = FileRef::try_get(&self.file) else {
            return 0;
        };
        let revents = u32::from(file.f_op.poll(&file, None));
        revents & (self.events.load(Ordering::Acquire) | EPOLLERR | EPOLLHUP)
    }

    /// Stop receiving callbacks
    fn unregister(&self) {
        self.dead.store(true, Ordering::Release);
        self.regs.lock().clear();
    }
}

/// A wakeup on one of an item's queues (Linux ep_poll_callback): under
/// that queue's lock, possibly in an interrupt; queues the item and
/// wakes the epoll's waiters
fn ep_poll_callback(e: &WaitEntry, _mode: WakeMode, key: usize) -> bool {
    // SAFETY: the entry lives in its item's `regs` and is unregistered
    // before the item goes; the epoll outlives its registered entries
    let item = unsafe { &*(e.private as *const EpItem) };
    // SAFETY: as above: the epoll unregisters its items before it goes
    let ep = unsafe { &*item.ep_raw };
    let events = item.events.load(Ordering::Acquire);
    // A wakeup that names its events and none this item waits for is
    // not one (Linux: pollflags && !(pollflags & epi->event.events))
    if item.dead.load(Ordering::Acquire)
        || events & !EP_PRIVATE_BITS == 0
        || (key != 0 && key as u32 & events == 0)
    {
        return false;
    }
    let queued = {
        let mut rdl = ep.lock.lock();
        if item.rdlink.is_linked() {
            false
        } else {
            // SAFETY: the item is alive while its entries are registered
            // (the map's Arc goes only after they are removed)
            let arc = unsafe {
                Arc::increment_strong_count(item);
                Arc::from_raw(item)
            };
            rdl.push_back(arc);
            true
        }
    };
    if queued {
        ep.wq.wake_all();
        ep.poll_wq.wake_poll(u32::from(POLLIN));
    }
    true
}

// ============================================================================
// The epoll instance
// ============================================================================

/// Every item by (file address, fd) (Linux ep->rbr)
type EpItems = BTreeMap<(usize, Fd), Arc<EpItem>>;

/// An epoll instance (Linux struct eventpoll)
pub struct Eventpoll {
    /// The items (Linux ep->mtx over ep->rbr)
    mtx: crate::sync::Mutex<EpItems>,
    /// Items that had an event since last reported (Linux ep->lock over
    /// ep->rdllist)
    lock: IrqSpinlock<ArcList<RdAdapter>>,
    /// epoll_wait sleepers
    wq: WaitQueue,
    /// Pollers of the epoll file itself (an epoll watching it)
    poll_wq: WaitQueue,
    /// Its own file (for the epolls watching it: the loop check's
    /// upward depth)
    file: spin::Once<Weak<File>>,
}

/// Serializes the loop check with the insert of an epoll target
static EPNESTED: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

fn key(file: &File, fd: Fd) -> (usize, Fd) {
    (core::ptr::from_ref::<File>(file) as usize, fd)
}

impl Eventpoll {
    /// Create a new epoll instance
    pub fn new() -> Result<Arc<Self>, KernelError> {
        try_arc(Self {
            mtx: crate::sync::Mutex::new(BTreeMap::new()),
            lock: IrqSpinlock::new(ArcList::new()),
            wq: WaitQueue::new(),
            poll_wq: WaitQueue::new(),
            file: spin::Once::new(),
        })
    }

    /// Queue `item` unless it is queued, and wake the epoll's waiters
    /// (Linux ep_insert / ep_modify on a ready item); `mtx` held
    fn queue(&self, item: &Arc<EpItem>) {
        let queued = {
            let mut rdl = self.lock.lock();
            let mine = !item.rdlink.is_linked();
            if mine {
                rdl.push_back(item.clone());
            }
            mine
        };
        if queued {
            self.wq.wake_all();
            self.poll_wq.wake_poll(u32::from(POLLIN));
        }
    }

    /// Put `item` back on the ready list unless an event queued it
    /// meanwhile (then the reference is dropped after the unlock); `mtx`
    /// held, so it is not removed
    fn requeue_at(&self, item: Arc<EpItem>, put: fn(&mut ArcList<RdAdapter>, Arc<EpItem>)) {
        let left = {
            let mut rdl = self.lock.lock();
            if item.rdlink.is_linked() {
                Some(item)
            } else {
                put(&mut rdl, item);
                None
            }
        };
        drop(left);
    }

    /// EPOLL_CTL_ADD (Linux ep_insert), under `mtx` (`items`)
    fn insert(
        self: &Arc<Self>,
        items: &mut EpItems,
        fd: Fd,
        file: &FileRef,
        ev: &EpollEvent,
    ) -> Result<(), KernelError> {
        let k = key(file, fd);
        if items.contains_key(&k) {
            return Err(KernelError::AlreadyExists);
        }
        let item = try_arc_cyclic(|w: &Weak<EpItem>| EpItem {
            rdlink: Link::new(),
            fd,
            file: FileRef::downgrade(file),
            ep_raw: Arc::as_ptr(self),
            ep: Arc::downgrade(self),
            events: AtomicU32::new(ev.events),
            data: AtomicU64::new(ev.data),
            dead: AtomicBool::new(false),
            regs: crate::sync::spin::Mutex::new(EpRegs {
                entries: Vec::new(),
                owners: Vec::new(),
                item: w.as_ptr(),
            }),
        })?;
        items.insert(k, item.clone());
        if let Err(e) = f_ep_add(file, &item) {
            items.remove(&k);
            return Err(e);
        }
        // Register the callbacks (Linux ep_item_poll with the queue
        // proc), under `mtx` as Linux: the file's poll may sleep, so its
        // entries are made in a local list and swapped into the item
        // after (only this add registers: nothing allocates under `regs`)
        let mut local = EpRegs {
            entries: Vec::new(),
            owners: Vec::new(),
            item: Arc::as_ptr(&item),
        };
        let revents = {
            let mut pt = PollTable::for_epoll(&mut local);
            u32::from(file.f_op.poll(file, Some(&mut pt)))
        };
        {
            let mut regs = item.regs.lock();
            core::mem::swap(&mut regs.entries, &mut local.entries);
            core::mem::swap(&mut regs.owners, &mut local.owners);
        }
        if revents & (ev.events | EPOLLERR | EPOLLHUP) != 0 {
            self.queue(&item);
        }
        Ok(())
    }

    /// EPOLL_CTL_MOD (Linux ep_modify), under `mtx` (`items`)
    fn modify(
        &self,
        items: &EpItems,
        fd: Fd,
        file: &FileRef,
        ev: &EpollEvent,
    ) -> Result<(), KernelError> {
        let item = items.get(&key(file, fd)).ok_or(KernelError::NotFound)?;
        if item.events.load(Ordering::Acquire) & EPOLLEXCLUSIVE != 0 {
            return Err(KernelError::InvalidArgument);
        }
        item.data.store(ev.data, Ordering::Release);
        item.events.store(ev.events, Ordering::Release);
        if item.poll() != 0 {
            self.queue(item);
        }
        Ok(())
    }

    /// Take `item` off the ready list, if it is on it
    fn unready(&self, item: &EpItem) -> Option<Arc<EpItem>> {
        let mut rdl = self.lock.lock();
        // SAFETY: `rdlink` is only ever on this epoll's ready list
        item.rdlink.is_linked().then(|| unsafe { rdl.remove(item) })
    }

    /// Unregister `item` and take it out of the map and the ready list
    /// (Linux ep_remove), under `mtx` (`items`), so no scan holds it;
    /// its Arcs come back to drop after the locks
    fn remove(
        &self,
        items: &mut EpItems,
        k: (usize, Fd),
        item: &Arc<EpItem>,
    ) -> (Option<Arc<EpItem>>, Option<Arc<EpItem>>) {
        // No callback first (it could queue the item again once off the
        // ready list): unregistering waits out any one running, under
        // its queue's lock (Linux ep_remove: ep_unregister_pollwait)
        item.unregister();
        let mine = items.get(&k).is_some_and(|it| Arc::ptr_eq(it, item));
        (mine.then(|| items.remove(&k)).flatten(), self.unready(item))
    }

    /// EPOLL_CTL_DEL, under `mtx` (`items`)
    fn delete(&self, items: &mut EpItems, fd: Fd, file: &FileRef) -> Result<(), KernelError> {
        let k = key(file, fd);
        let item = items.get(&k).cloned().ok_or(KernelError::NotFound)?;
        file.f_ep
            .lock()
            .retain(|w| !core::ptr::eq(w.as_ptr(), Arc::as_ptr(&item)));
        let gone = self.remove(items, k, &item);
        drop(gone);
        Ok(())
    }

    /// Report ready items into `out` (Linux ep_send_events), under `mtx`
    /// throughout, so one waiter at a time scans: the items queued when
    /// it starts are taken off the front one at a time (Linux
    /// ep_start_scan; an event meanwhile queues one again at the end,
    /// Linux's ovflist) and polled again; level-triggered ones go back
    /// at the end, edge-triggered and one-shot ones wait for their next
    /// event. A `put` failure stops it with the item back in front. The
    /// rest stay queued, and another waiter is woken if any is (Linux
    /// ep_done_scan).
    fn send_events(
        &self,
        max: usize,
        mut put: impl FnMut(usize, EpollEvent) -> bool,
    ) -> Result<usize, KernelError> {
        let _items = self.mtx.lock();
        let mut left = self.lock.lock().len();
        let mut n = 0;
        let mut fault = false;
        while left > 0 && n < max {
            left -= 1;
            let Some(item) = self.lock.lock().pop_front() else {
                break;
            };
            let revents = item.poll();
            if revents == 0 {
                continue;
            }
            let ev = EpollEvent::new(revents, item.data.load(Ordering::Acquire));
            if !put(n, ev) {
                fault = true;
                self.requeue_at(item, ArcList::push_front);
                break;
            }
            n += 1;
            let events = item.events.load(Ordering::Acquire);
            if events & EPOLLONESHOT != 0 {
                item.events.fetch_and(EP_PRIVATE_BITS, Ordering::AcqRel);
            } else if events & EPOLLET == 0 {
                self.requeue_at(item, ArcList::push_back);
            }
        }
        if self.has_ready() {
            self.wq.wake_all();
        }
        if fault && n == 0 {
            return Err(KernelError::BadAddress);
        }
        Ok(n)
    }

    /// Any queued item with an event
    fn has_ready(&self) -> bool {
        !self.lock.lock().is_empty()
    }

    /// epoll_wait's core (Linux ep_poll): report ready events, else
    /// sleep until one, the deadline or a signal (EINTR, never restarted)
    fn wait(
        &self,
        max: usize,
        deadline: Deadline,
        mut put: impl FnMut(usize, EpollEvent) -> bool,
    ) -> Result<usize, KernelError> {
        use crate::time::hrtimer::HrClock;
        loop {
            let n = self.send_events(max, &mut put)?;
            if n > 0 || deadline == Some(0) {
                return Ok(n);
            }
            match self.wq.wait_event_interruptible_deadline(
                || self.has_ready(),
                deadline,
                HrClock::Monotonic,
            ) {
                Ok(true) => {}
                Ok(false) => return self.send_events(max, &mut put),
                Err(_) => return Err(KernelError::Interrupted),
            }
        }
    }

    /// Readiness of the epoll file itself (Linux __ep_eventpoll_poll):
    /// an item on the ready list with an event; the queue it waits on is
    /// `poll_wq`. Under `mtx`, as a scan: the items queued are taken off
    /// the front and polled until one has an event, which goes back in
    /// front; those with none stay off. The epoll's waiters are woken if
    /// any item is left ready (Linux ep_done_scan). An epoll polled from
    /// another's scan or insert nests its `mtx` in that one's (Linux
    /// mutex_lock_nested by depth): the loop check keeps the nesting
    /// acyclic and at most EP_MAX_NESTS deep.
    pub fn poll(&self, pt: Option<&mut PollTable<'_>>) -> u16 {
        if let Some(pt) = pt {
            pt.poll_wait(&self.poll_wq);
        }
        let _items = self.mtx.lock();
        let n = self.lock.lock().len();
        let mut res = 0;
        for _ in 0..n {
            let Some(item) = self.lock.lock().pop_front() else {
                break;
            };
            if item.poll() != 0 {
                self.requeue_at(item, ArcList::push_front);
                res = POLLIN | POLLRDNORM;
                break;
            }
        }
        if self.has_ready() {
            self.wq.wake_all();
        }
        res
    }

    /// The epoll files among this one's targets (walked under `mtx`,
    /// Linux ep_loop_check_proc; the files are released after it)
    fn epoll_targets(&self) -> Vec<Arc<Eventpoll>> {
        let files: Vec<FileRef> = self
            .mtx
            .lock()
            .values()
            .filter_map(|it| FileRef::try_get(&it.file))
            .collect();
        files.iter().filter_map(|f| get_eventpoll(f)).collect()
    }
}

/// Put `item` on `file`'s watchers (Linux f_ep), the vector growing
/// with its lock released (nothing allocates under it): ENOMEM
fn f_ep_add(file: &File, item: &Arc<EpItem>) -> Result<(), KernelError> {
    let w = Arc::downgrade(item);
    loop {
        let cap = {
            let mut v = file.f_ep.lock();
            if v.len() < v.capacity() {
                v.push(w);
                return Ok(());
            }
            v.capacity()
        };
        let bigger = crate::util::kmem::spare(cap)?;
        let old = crate::util::kmem::adopt(&mut file.f_ep.lock(), bigger);
        drop(old);
    }
}

impl Drop for Eventpoll {
    /// The epoll file's last close (Linux ep_free): every item goes,
    /// unregistered before the ready list is emptied (no callback can
    /// queue one after); all are released with no lock held
    fn drop(&mut self) {
        let items = core::mem::take(&mut *self.mtx.lock());
        for item in items.values() {
            item.unregister();
            if let Some(f) = item.file.upgrade() {
                f.f_ep
                    .lock()
                    .retain(|w| !core::ptr::eq(w.as_ptr(), Arc::as_ptr(item)));
            }
        }
        let ready = core::mem::replace(&mut *self.lock.lock(), ArcList::new());
        drop(ready);
        drop(items);
    }
}

/// `file`'s last close (Linux eventpoll_release_file, from __fput): its
/// items leave every epoll, unregistered before the file's queues go,
/// each under its epoll's `mtx` (Linux ep_remove under ep->mtx): no scan
/// of that epoll holds the item meanwhile, so a scan's failed
/// `FileRef::try_get` never holds the file's last `Arc` (this release
/// keeps one until it is done)
pub fn eventpoll_release(file: &File) {
    let items = core::mem::take(&mut *file.f_ep.lock());
    for w in items {
        let Some(item) = w.upgrade() else {
            continue;
        };
        let Some(ep) = item.ep.upgrade() else {
            // The epoll is being freed: its drop unregisters the item
            item.unregister();
            continue;
        };
        let k = (core::ptr::from_ref::<File>(file) as usize, item.fd);
        let gone = ep.remove(&mut ep.mtx.lock(), k, &item);
        drop(gone);
    }
}

/// Epolls already measured in one loop check, by address (Linux marks
/// them with loop_check_gen): every epoll is walked once per check
type Seen = BTreeMap<usize, Option<u32>>;

/// How deep `ep`'s epoll targets go, None if one is `into` (a cycle) or
/// deeper than EP_MAX_NESTS (Linux ep_loop_check_proc)
fn down_depth(
    ep: &Arc<Eventpoll>,
    into: &Arc<Eventpoll>,
    depth: u32,
    seen: &mut Seen,
) -> Option<u32> {
    let k = Arc::as_ptr(ep) as usize;
    if let Some(&d) = seen.get(&k) {
        return d;
    }
    let mut d = Some(0);
    for t in ep.epoll_targets() {
        if Arc::ptr_eq(&t, into) || depth > EP_MAX_NESTS {
            d = None;
            break;
        }
        match down_depth(&t, into, depth + 1, seen) {
            Some(x) if x < EP_MAX_NESTS => d = d.map(|v| v.max(x + 1)),
            _ => {
                d = None;
                break;
            }
        }
    }
    seen.insert(k, d);
    d
}

/// How many epoll levels watch `ep` from above (Linux
/// ep_get_upwards_depth_proc); bounded, as every insert checked it
fn up_depth(ep: &Eventpoll, seen: &mut Seen) -> u32 {
    let k = core::ptr::from_ref::<Eventpoll>(ep) as usize;
    if let Some(&Some(d)) = seen.get(&k) {
        return d;
    }
    let Some(file) = ep.file.get().and_then(Weak::upgrade) else {
        return 0;
    };
    let watchers: Vec<Arc<Eventpoll>> = file
        .f_ep
        .lock()
        .iter()
        .filter_map(|w| w.upgrade().and_then(|it| it.ep.upgrade()))
        .collect();
    let d = watchers
        .iter()
        .map(|w| up_depth(w, seen) + 1)
        .max()
        .unwrap_or(0);
    seen.insert(k, Some(d));
    d
}

/// Whether watching `target` from `ep` would make a cycle or a chain
/// deeper than EP_MAX_NESTS (Linux ep_loop_check)
fn ep_loop_check(ep: &Arc<Eventpoll>, target: &Arc<Eventpoll>) -> bool {
    match down_depth(target, ep, 0, &mut Seen::new()) {
        None => true,
        Some(d) => d > EP_MAX_NESTS || d + 1 + up_depth(ep, &mut Seen::new()) > EP_MAX_NESTS,
    }
}

// ============================================================================
// The epoll file
// ============================================================================

/// File operations for epoll fd
pub struct EpollFileOps;

static EPOLL_FOPS: EpollFileOps = EpollFileOps;

impl FileOps for EpollFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Some(ep) = file.private_ref::<Eventpoll>() else {
            return crate::io::poll::POLLERR;
        };
        ep.poll(pt)
    }
}

/// Create an epoll file
pub fn create_epoll_file(eflags: i32) -> Result<FileRef, KernelError> {
    let ep = Eventpoll::new()?;
    let mut file_flags = flags::O_RDWR;
    if eflags & EPOLL_CLOEXEC != 0 {
        file_flags |= flags::O_CLOEXEC;
    }
    let file = crate::fs::anon_inodes::anon_inode_getfile(
        "[eventpoll]",
        &EPOLL_FOPS,
        ep.clone(),
        file_flags,
    )?;
    ep.file.call_once(|| FileRef::downgrade(&file));
    Ok(file)
}

/// The Eventpoll of an epoll file
pub fn get_eventpoll(file: &File) -> Option<Arc<Eventpoll>> {
    file.private_arc::<Eventpoll>()
}

// ============================================================================
// Syscalls
// ============================================================================

/// sys_epoll_create(size): size is ignored but must be positive
pub fn sys_epoll_create(size: i32) -> KernelResult<i32> {
    if size <= 0 {
        return Err(KernelError::InvalidArgument);
    }
    sys_epoll_create1(0)
}

/// sys_epoll_create1(flags): EPOLL_CLOEXEC or 0
pub fn sys_epoll_create1(eflags: i32) -> KernelResult<i32> {
    if eflags & !EPOLL_CLOEXEC != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let file = create_epoll_file(eflags)?;
    let fd_flags = if eflags & EPOLL_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };
    crate::fs::io::fd_install(file, fd_flags)
}

/// sys_epoll_ctl(epfd, op, fd, event) (Linux do_epoll_ctl)
pub fn sys_epoll_ctl(
    epfd: i32,
    op: i32,
    fd: i32,
    event_ptr: UserPtr<EpollEvent>,
) -> KernelResult<()> {
    // The event is read first (Linux copy_from_user before fdget)
    let mut ev = if op != EPOLL_CTL_DEL {
        event_ptr.read()?
    } else {
        EpollEvent::default()
    };
    let ep_file = fget(epfd)?;
    let tf = fget(fd)?;
    // The target must poll, before the epoll checks (Linux do_epoll_ctl)
    if !tf.f_op.can_poll(&tf) {
        return Err(KernelError::NotPermitted);
    }
    let ep = get_eventpoll(&ep_file).ok_or(KernelError::InvalidArgument)?;
    if FileRef::ptr_eq(&ep_file, &tf) {
        return Err(KernelError::InvalidArgument);
    }
    let target_ep = get_eventpoll(&tf);
    if op != EPOLL_CTL_DEL {
        // EPOLLWAKEUP needs CAP_BLOCK_SUSPEND; silently dropped
        if ev.events & EPOLLWAKEUP != 0 && !crate::task::capable(crate::task::CAP_BLOCK_SUSPEND) {
            ev.events &= !EPOLLWAKEUP;
        }
        // EPOLLEXCLUSIVE: add only, on a non-epoll file, with few events
        if ev.events & EPOLLEXCLUSIVE != 0
            && (op == EPOLL_CTL_MOD
                || target_ep.is_some()
                || ev.events & !EPOLLEXCLUSIVE_OK_BITS != 0)
        {
            return Err(KernelError::InvalidArgument);
        }
    }
    // Errors and hangups are always reported (Linux do_epoll_ctl)
    if op != EPOLL_CTL_DEL {
        ev.events |= EPOLLERR | EPOLLHUP;
    }
    // An epoll target: the loop check and the insert under EPNESTED
    // (Linux epnested_mutex, then ep->mtx)
    let _nest = match &target_ep {
        Some(t) if op == EPOLL_CTL_ADD => {
            let g = EPNESTED.lock();
            if ep_loop_check(&ep, t) {
                return Err(KernelError::TooManySymlinks);
            }
            Some(g)
        }
        _ => None,
    };
    // The operation under ep->mtx (Linux do_epoll_ctl)
    let mut items = ep.mtx.lock();
    match op {
        EPOLL_CTL_ADD => ep.insert(&mut items, fd as Fd, &tf, &ev),
        EPOLL_CTL_MOD => ep.modify(&items, fd as Fd, &tf, &ev),
        EPOLL_CTL_DEL => ep.delete(&mut items, fd as Fd, &tf),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// sys_epoll_wait(epfd, events, maxevents, timeout)
pub fn sys_epoll_wait(
    epfd: i32,
    events_ptr: UserPtr<EpollEvent>,
    maxevents: i32,
    timeout: i32,
) -> KernelResult<usize> {
    sys_epoll_pwait(epfd, events_ptr, maxevents, timeout, UserPtr::new(0), 0)
}

/// sys_epoll_pwait: `sigmask` (if not null) is the blocked mask during
/// the wait, kept for the delivery of a signal that ends it with EINTR
/// (Linux do_epoll_pwait)
pub fn sys_epoll_pwait(
    epfd: i32,
    events_ptr: UserPtr<EpollEvent>,
    maxevents: i32,
    timeout: i32,
    sigmask: UserPtr<u64>,
    sigsetsize: u64,
) -> KernelResult<usize> {
    let deadline = crate::time::deadline_ms(timeout);
    do_epoll_pwait(epfd, events_ptr, maxevents, deadline, sigmask, sigsetsize)
}

fn do_epoll_pwait(
    epfd: i32,
    events_ptr: UserPtr<EpollEvent>,
    maxevents: i32,
    deadline: Deadline,
    sigmask: UserPtr<u64>,
    sigsetsize: u64,
) -> KernelResult<usize> {
    crate::signal::set_user_sigmask(sigmask.addr(), sigsetsize)?;
    let r = do_epoll_wait(epfd, events_ptr, maxevents, deadline);
    crate::signal::restore_saved_sigmask_unless(r == Err(KernelError::Interrupted));
    r
}

/// Wait on `epfd` and copy the events out as they are found (Linux
/// do_epoll_wait / ep_send_events): no kernel buffer of maxevents
fn do_epoll_wait(
    epfd: i32,
    events_ptr: UserPtr<EpollEvent>,
    maxevents: i32,
    deadline: Deadline,
) -> KernelResult<usize> {
    let size = core::mem::size_of::<EpollEvent>();
    let max = usize::try_from(maxevents).map_err(|_| KernelError::InvalidArgument)?;
    if max == 0 || max > EP_MAX_EVENTS {
        return Err(KernelError::InvalidArgument);
    }
    if !access_ok(events_ptr.addr(), max * size) {
        return Err(KernelError::BadAddress);
    }
    let ep_file = fget(epfd)?;
    let ep = get_eventpoll(&ep_file).ok_or(KernelError::InvalidArgument)?;
    ep.wait(max, deadline, |i, ev| {
        events_ptr.offset(i).is_some_and(|p| p.write(&ev).is_ok())
    })
}

/// sys_epoll_pwait2: as epoll_pwait with a struct timespec timeout
/// (NULL waits forever; ns precision, Linux ep_timeout_to_timespec)
pub fn sys_epoll_pwait2(
    epfd: i32,
    events_ptr: UserPtr<EpollEvent>,
    maxevents: i32,
    timeout_ptr: UserPtr<crate::time::time_syscall::LinuxTimespec>,
    sigmask: UserPtr<u64>,
    sigsetsize: u64,
) -> KernelResult<usize> {
    let deadline = if timeout_ptr.is_null() {
        None
    } else {
        let ts = timeout_ptr.read()?;
        crate::time::deadline_ts(ts.tv_sec, ts.tv_nsec)?
    };
    do_epoll_pwait(epfd, events_ptr, maxevents, deadline, sigmask, sigsetsize)
}
