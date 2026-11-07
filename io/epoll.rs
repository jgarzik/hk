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
//! last close removes its items (`eventpoll_release`, from `File`'s
//! drop), so a closed pipe end or socket is released and its peer sees
//! EOF. Items are keyed by (file, fd): closing one descriptor of a file
//! that stays open keeps the item, as on Linux. Watching an epoll file
//! is allowed EP_MAX_NESTS deep without cycles (`ep_loop_check`, ELOOP).
//!
//! Locking (doc/LOCKING.md):
//! - `Eventpoll.lock` (IrqSpinlock; the callback runs under the woken
//!   queue's lock, possibly in an interrupt): the item map and the
//!   ready list. Nothing sleeps, polls or copies to user under it, and
//!   no `EpItem` is dropped under it.
//! - `EpItem.regs` (spin, thread context): the item's callback entries
//!   and the owners of their queues; registering and unregistering take
//!   the file's queue locks under it (queue lock -> `Eventpoll.lock` in
//!   the callback; never the reverse).
//! - `File.f_ep` (spin leaf): the items watching the file.
//! - `EPNESTED` (sleeping): the loop check and insert of an epoll target
//!   (Linux epnested_mutex), with no spin lock held.

use crate::util::kalloc::{try_arc, try_arc_cyclic};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::{IrqSpinlock, Uaccess};
use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, flags};
use crate::io::pipe::FD_CLOEXEC;
use crate::io::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::sync::waitqueue::{WaitEntry, WaitQueue};
use crate::task::Fd;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::{WakeMode, current_tid};
use crate::time::Deadline;
use crate::uaccess::{UaccessArch, get_user, put_user};
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
        let Some(file) = self.file.upgrade() else {
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
        let mut inner = ep.lock.lock();
        if item.rdlink.is_linked() {
            false
        } else {
            // SAFETY: the item is in `inner.items`, which holds an Arc
            let arc = unsafe {
                Arc::increment_strong_count(item);
                Arc::from_raw(item)
            };
            inner.rdl.push_back(arc);
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

struct EpInner {
    /// Every item by (file address, fd)
    items: BTreeMap<(usize, Fd), Arc<EpItem>>,
    /// Items that had an event since last reported
    rdl: ArcList<RdAdapter>,
}

/// An epoll instance (Linux struct eventpoll)
pub struct Eventpoll {
    lock: IrqSpinlock<EpInner>,
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

fn key(file: &Arc<File>, fd: Fd) -> (usize, Fd) {
    (Arc::as_ptr(file) as usize, fd)
}

impl Eventpoll {
    /// Create a new epoll instance
    pub fn new() -> Result<Arc<Self>, KernelError> {
        try_arc(Self {
            lock: IrqSpinlock::new(EpInner {
                items: BTreeMap::new(),
                rdl: ArcList::new(),
            }),
            wq: WaitQueue::new(),
            poll_wq: WaitQueue::new(),
            file: spin::Once::new(),
        })
    }

    /// Queue `item` if it is ready now and not queued; wake if so
    fn queue_if_ready(&self, item: &Arc<EpItem>) {
        if item.poll() == 0 {
            return;
        }
        let queued = {
            let mut inner = self.lock.lock();
            let mine = !item.dead.load(Ordering::Acquire) && !item.rdlink.is_linked();
            if mine {
                inner.rdl.push_back(item.clone());
            }
            mine
        };
        if queued {
            self.wq.wake_all();
            self.poll_wq.wake_poll(u32::from(POLLIN));
        }
    }

    /// EPOLL_CTL_ADD (Linux ep_insert)
    fn insert(
        self: &Arc<Self>,
        fd: Fd,
        file: &Arc<File>,
        ev: &EpollEvent,
    ) -> Result<(), KernelError> {
        let k = key(file, fd);
        let item = try_arc_cyclic(|w: &Weak<EpItem>| EpItem {
            rdlink: Link::new(),
            fd,
            file: Arc::downgrade(file),
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
        {
            let mut inner = self.lock.lock();
            if inner.items.contains_key(&k) {
                return Err(KernelError::AlreadyExists);
            }
            inner.items.insert(k, item.clone());
        }
        {
            let mut f_ep = file.f_ep.lock();
            if f_ep.try_reserve(1).is_err() {
                drop(f_ep);
                self.remove(&item);
                return Err(KernelError::OutOfMemory);
            }
            f_ep.push(Arc::downgrade(&item));
        }
        // Register the callbacks (Linux ep_item_poll with the queue
        // proc). The file is polled with no lock held (a poll method may
        // sleep); its entries go into the item after, or are removed if
        // it was deleted meanwhile
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
            if item.dead.load(Ordering::Acquire) {
                drop(regs);
                local.clear();
                return Ok(());
            }
            regs.entries.append(&mut local.entries);
            regs.owners.append(&mut local.owners);
        }
        if revents & (ev.events | EPOLLERR | EPOLLHUP) != 0 {
            self.queue_if_ready(&item);
        }
        Ok(())
    }

    /// EPOLL_CTL_MOD (Linux ep_modify)
    fn modify(&self, fd: Fd, file: &Arc<File>, ev: &EpollEvent) -> Result<(), KernelError> {
        let item = self
            .lock
            .lock()
            .items
            .get(&key(file, fd))
            .cloned()
            .ok_or(KernelError::NotFound)?;
        if item.events.load(Ordering::Acquire) & EPOLLEXCLUSIVE != 0 {
            return Err(KernelError::InvalidArgument);
        }
        item.data.store(ev.data, Ordering::Release);
        item.events.store(ev.events, Ordering::Release);
        self.queue_if_ready(&item);
        Ok(())
    }

    /// Take `item` out of the map and the ready list, and unregister it
    /// (Linux ep_remove); its Arcs are dropped after the lock
    fn remove(&self, item: &Arc<EpItem>) {
        // No callback first (it could queue the item again once off the
        // ready list): unregistering waits out any one running, under
        // its queue's lock (Linux ep_remove: ep_unregister_pollwait)
        item.unregister();
        // The file is held across the lock: no last reference to it may
        // go under `lock` (its release takes `lock`)
        let file = item.file.upgrade();
        let (mapped, ready) = {
            let mut inner = self.lock.lock();
            let mapped = file
                .as_ref()
                .and_then(|f| inner.items.remove(&key(f, item.fd)));
            // SAFETY: linked only on this epoll's ready list
            let ready = item
                .rdlink
                .is_linked()
                .then(|| unsafe { inner.rdl.remove(item) });
            (mapped, ready)
        };
        if let Some(f) = &file {
            f.f_ep
                .lock()
                .retain(|w| !core::ptr::eq(w.as_ptr(), Arc::as_ptr(item)));
        }
        drop((mapped, ready));
        drop(file);
    }

    /// EPOLL_CTL_DEL
    fn delete(&self, fd: Fd, file: &Arc<File>) -> Result<(), KernelError> {
        let item = self
            .lock
            .lock()
            .items
            .get(&key(file, fd))
            .cloned()
            .ok_or(KernelError::NotFound)?;
        self.remove(&item);
        Ok(())
    }

    /// Report ready items into `out` (Linux ep_send_events): each is
    /// polled again; level-triggered ones stay queued, edge-triggered
    /// and one-shot ones wait for their next event. A `put` failure
    /// stops the transfer with the item requeued.
    fn send_events(
        &self,
        max: usize,
        mut put: impl FnMut(usize, EpollEvent) -> bool,
    ) -> Result<usize, KernelError> {
        // Take the ready list (items queued during the transfer are new
        // events and land on it again)
        let mut tx = Vec::new();
        {
            let mut inner = self.lock.lock();
            while tx.len() < max
                && let Some(it) = inner.rdl.pop_front()
            {
                if tx.try_reserve(1).is_err() {
                    inner.rdl.push_front(it);
                    break;
                }
                tx.push(it);
            }
        }
        let mut n = 0;
        let mut requeue = Vec::new();
        let _ = requeue.try_reserve(tx.len());
        let mut fault = false;
        let mut rest = tx.into_iter();
        for item in rest.by_ref() {
            if item.dead.load(Ordering::Acquire) {
                continue;
            }
            let revents = item.poll();
            if revents == 0 {
                continue;
            }
            let ev = EpollEvent::new(revents, item.data.load(Ordering::Acquire));
            if !put(n, ev) {
                fault = true;
                requeue.push(item);
                break;
            }
            n += 1;
            let events = item.events.load(Ordering::Acquire);
            if events & EPOLLONESHOT != 0 {
                item.events.fetch_and(EP_PRIVATE_BITS, Ordering::AcqRel);
            } else if events & EPOLLET == 0 {
                requeue.push(item);
            }
        }
        requeue.extend(rest);
        {
            let mut inner = self.lock.lock();
            for item in requeue.drain(..) {
                if !item.dead.load(Ordering::Acquire) && !item.rdlink.is_linked() {
                    inner.rdl.push_back(item);
                }
            }
        }
        if fault && n == 0 {
            return Err(KernelError::BadAddress);
        }
        Ok(n)
    }

    /// Any queued item with an event
    fn has_ready(&self) -> bool {
        !self.lock.lock().rdl.is_empty()
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

    /// Readiness of the epoll file itself (Linux ep_eventpoll_poll): an
    /// item on the ready list with an event; the queue it waits on is
    /// `poll_wq`
    pub fn poll(&self, pt: Option<&mut PollTable<'_>>) -> u16 {
        if let Some(pt) = pt {
            pt.poll_wait(&self.poll_wq);
        }
        let ready: Vec<Arc<EpItem>> = {
            let inner = self.lock.lock();
            let mut v = Vec::new();
            for it in inner.rdl.iter() {
                if v.try_reserve(1).is_err() {
                    break;
                }
                // SAFETY: on the list, which holds an Arc to it
                v.push(unsafe {
                    Arc::increment_strong_count(it);
                    Arc::from_raw(core::ptr::from_ref::<EpItem>(it))
                });
            }
            v
        };
        let any = ready
            .iter()
            .any(|it| !it.dead.load(Ordering::Acquire) && it.poll() != 0);
        drop(ready);
        if any { POLLIN | POLLRDNORM } else { 0 }
    }

    /// The epoll files among this one's targets
    fn epoll_targets(&self) -> Vec<Arc<Eventpoll>> {
        let files: Vec<Arc<File>> = {
            let inner = self.lock.lock();
            inner
                .items
                .values()
                .filter_map(|it| it.file.upgrade())
                .collect()
        };
        files.iter().filter_map(|f| get_eventpoll(f)).collect()
    }
}

impl Drop for Eventpoll {
    /// The epoll file's last close (Linux ep_free): every item goes
    fn drop(&mut self) {
        let mut ready = Vec::new();
        let items: Vec<Arc<EpItem>> = {
            let mut inner = self.lock.lock();
            while let Some(it) = inner.rdl.pop_front() {
                // The map holds each too: no item is freed here
                if ready.try_reserve(1).is_ok() {
                    ready.push(it);
                }
            }
            core::mem::take(&mut inner.items).into_values().collect()
        };
        drop(ready);
        for item in &items {
            item.unregister();
            if let Some(f) = item.file.upgrade() {
                f.f_ep
                    .lock()
                    .retain(|w| !core::ptr::eq(w.as_ptr(), Arc::as_ptr(item)));
            }
        }
    }
}

/// `file`'s last close (Linux eventpoll_release, from __fput): its items
/// leave every epoll, unregistered before the file's queues go
pub fn eventpoll_release(file: &File) {
    let items = core::mem::take(&mut *file.f_ep.lock());
    for w in items {
        let Some(item) = w.upgrade() else {
            continue;
        };
        item.unregister();
        if let Some(ep) = item.ep.upgrade() {
            let gone = {
                let mut inner = ep.lock.lock();
                inner.items.retain(|_, it| !Arc::ptr_eq(it, &item));
                // SAFETY: linked only on this epoll's ready list
                item.rdlink
                    .is_linked()
                    .then(|| unsafe { inner.rdl.remove(&item) })
            };
            drop(gone);
        }
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
pub fn create_epoll_file(eflags: i32) -> Result<Arc<File>, KernelError> {
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
    ep.file.call_once(|| Arc::downgrade(&file));
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
pub fn sys_epoll_create(size: i32) -> i64 {
    if size <= 0 {
        return KernelError::InvalidArgument.sysret();
    }
    sys_epoll_create1(0)
}

fn get_nofile_limit() -> u64 {
    let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_NOFILE);
    if limit == crate::task::rlimit::RLIM_INFINITY {
        u64::MAX
    } else {
        limit
    }
}

/// sys_epoll_create1(flags): EPOLL_CLOEXEC or 0
pub fn sys_epoll_create1(eflags: i32) -> i64 {
    if eflags & !EPOLL_CLOEXEC != 0 {
        return KernelError::InvalidArgument.sysret();
    }
    let file = match create_epoll_file(eflags) {
        Ok(f) => f,
        Err(_) => return KernelError::OutOfMemory.sysret(),
    };
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::OutOfMemory.sysret(),
    };
    let mut table = fd_table.lock();
    let fd_flags = if eflags & EPOLL_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };
    match table.alloc_with_flags(file, fd_flags, get_nofile_limit()) {
        Ok(fd) => i64::from(fd),
        Err(e) => -i64::from(e),
    }
}

/// sys_epoll_ctl(epfd, op, fd, event) (Linux do_epoll_ctl)
pub fn sys_epoll_ctl(epfd: i32, op: i32, fd: i32, event_ptr: u64) -> i64 {
    match epoll_ctl(epfd, op, fd, event_ptr) {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

fn epoll_ctl(epfd: i32, op: i32, fd: i32, event_ptr: u64) -> Result<(), KernelError> {
    // The event is read first (Linux copy_from_user before fdget)
    let mut ev = if op != EPOLL_CTL_DEL {
        get_user::<Uaccess, EpollEvent>(event_ptr).map_err(|_| KernelError::BadAddress)?
    } else {
        EpollEvent::default()
    };
    let (ep_file, tf) = {
        let table = get_task_fd(current_tid()).ok_or(KernelError::BadFd)?;
        let t = table.lock();
        (
            t.get(epfd).ok_or(KernelError::BadFd)?,
            t.get(fd).ok_or(KernelError::BadFd)?,
        )
    };
    // The target must poll, before the epoll checks (Linux do_epoll_ctl)
    if !tf.f_op.can_poll(&tf) {
        return Err(KernelError::NotPermitted);
    }
    let ep = get_eventpoll(&ep_file).ok_or(KernelError::InvalidArgument)?;
    if Arc::ptr_eq(&ep_file, &tf) {
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
    match op {
        EPOLL_CTL_ADD => match target_ep {
            Some(t) => {
                let _nest = EPNESTED.lock();
                if ep_loop_check(&ep, &t) {
                    return Err(KernelError::TooManySymlinks);
                }
                ep.insert(fd as Fd, &tf, &ev)
            }
            None => ep.insert(fd as Fd, &tf, &ev),
        },
        EPOLL_CTL_MOD => ep.modify(fd as Fd, &tf, &ev),
        EPOLL_CTL_DEL => ep.delete(fd as Fd, &tf),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// sys_epoll_wait(epfd, events, maxevents, timeout)
pub fn sys_epoll_wait(epfd: i32, events_ptr: u64, maxevents: i32, timeout: i32) -> i64 {
    sys_epoll_pwait(epfd, events_ptr, maxevents, timeout, 0, 0)
}

/// sys_epoll_pwait: `sigmask` (if not null) is the blocked mask during
/// the wait, kept for the delivery of a signal that ends it with EINTR
/// (Linux do_epoll_pwait)
pub fn sys_epoll_pwait(
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    timeout: i32,
    sigmask: u64,
    sigsetsize: u64,
) -> i64 {
    let deadline = crate::time::deadline_ms(timeout);
    do_epoll_pwait(epfd, events_ptr, maxevents, deadline, sigmask, sigsetsize)
}

fn do_epoll_pwait(
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    deadline: Deadline,
    sigmask: u64,
    sigsetsize: u64,
) -> i64 {
    if let Err(e) = crate::signal::set_user_sigmask(sigmask, sigsetsize) {
        return e.sysret();
    }
    let r = match do_epoll_wait(epfd, events_ptr, maxevents, deadline) {
        Ok(n) => n as i64,
        Err(e) => e.sysret(),
    };
    crate::signal::restore_saved_sigmask_unless(r == KernelError::Interrupted.sysret());
    r
}

/// Wait on `epfd` and copy the events out as they are found (Linux
/// do_epoll_wait / ep_send_events): no kernel buffer of maxevents
fn do_epoll_wait(
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    deadline: Deadline,
) -> Result<usize, KernelError> {
    let size = core::mem::size_of::<EpollEvent>();
    let max = usize::try_from(maxevents).map_err(|_| KernelError::InvalidArgument)?;
    if max == 0 || max > EP_MAX_EVENTS {
        return Err(KernelError::InvalidArgument);
    }
    if !Uaccess::access_ok(events_ptr, max * size) {
        return Err(KernelError::BadAddress);
    }
    let ep_file = get_task_fd(current_tid())
        .ok_or(KernelError::BadFd)?
        .lock()
        .get(epfd)
        .ok_or(KernelError::BadFd)?;
    let ep = get_eventpoll(&ep_file).ok_or(KernelError::InvalidArgument)?;
    ep.wait(max, deadline, |i, ev| {
        put_user::<Uaccess, EpollEvent>(events_ptr + (i * size) as u64, ev).is_ok()
    })
}

/// sys_epoll_pwait2: as epoll_pwait with a struct timespec timeout
/// (NULL waits forever; ns precision, Linux ep_timeout_to_timespec)
pub fn sys_epoll_pwait2(
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    timeout_ptr: u64,
    sigmask: u64,
    sigsetsize: u64,
) -> i64 {
    use crate::time::time_syscall::LinuxTimespec;
    let deadline = if timeout_ptr == 0 {
        None
    } else {
        let ts: LinuxTimespec = match get_user::<Uaccess, LinuxTimespec>(timeout_ptr) {
            Ok(ts) => ts,
            Err(_) => return KernelError::BadAddress.sysret(),
        };
        match crate::time::deadline_ts(ts.tv_sec, ts.tv_nsec) {
            Ok(d) => d,
            Err(e) => return e.sysret(),
        }
    };
    do_epoll_pwait(epfd, events_ptr, maxevents, deadline, sigmask, sigsetsize)
}
