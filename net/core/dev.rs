//! Network device core: receive dispatch, NAPI and per-CPU softnet threads
//!
//! Linux equivalents: `net/core/dev.c` (`netif_receive_skb`, `netif_rx`,
//! `napi_schedule`, `net_rx_action`, `process_backlog`, `dev_add_pack`).
//!
//! ## Execution model (no softirqs)
//!
//! ```text
//! NIC IRQ ──► driver ISR: ack + mask device IRQs, napi_schedule()
//!                          │ (IRQ-safe: poll_list IrqSpinlock + WaitQueue wake)
//!                          ▼
//!              softnet/N kthread (CPU N) ──► napi poll(budget 64)
//!                          │                    └► netif_receive_skb()
//! lo xmit ──► netif_rx() ──► backlog (CPU-local) ──► netif_receive_skb()
//!                                                     └► ptype handler
//!                                                        (ip_rcv, arp_rcv)
//! ```
//!
//! All protocol processing runs in thread context: in the `softnet/N`
//! threads, or inline in a sending task at a lock-free point
//! ([`netif_rx_flush_local`], the equivalent of Linux running pending
//! softirqs at `local_bh_enable()` after `dev_queue_xmit`, and like it on
//! the CPU's IRQ stack, atomic, GFP_ATOMIC). Nothing below a driver ISR
//! ever runs in interrupt context.
//!
//! ## Locking (see doc/LOCKING.md, Network)
//!
//! - `Softnet.poll_list`: `IrqSpinlock`, leaf. Taken by `napi_schedule`
//!   (ISR) and the softnet thread. The NAPI contexts are linked through
//!   their own `poll_list` link (Linux napi_struct.poll_list), so the ISR
//!   never allocates.
//! - `Softnet.backlog`: an `SkbQueue` (its spin lock, Linux
//!   input_pkt_queue.lock), thread context only, leaf; skbs taken off
//!   under it are dropped after. The backlog is polled as its own NAPI
//!   (Linux sd->backlog), whose SCHED changes under this lock.
//! - `Napi.state`: SCHED/MISSED/DISABLE in one word, compare-and-swap
//!   transitions as Linux's.
//! - `PTYPE_BASE`: an RCU list of static `PacketType`s (Linux ptype_base),
//!   added to at boot, read under RCU; the handler is copied out and
//!   called after the guard is dropped.
//! - `PTYPE_ALL`: `crate::sync::spin::RwLock`, thread context only, leaf;
//!   taps are copied out and called after the guard is dropped. They
//!   run in the receive path (softnet or an inline backlog flush) and in
//!   `dev_queue_xmit` callers, with no lock held by this module.

use crate::util::kalloc::arc_nofail;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::sync::spin::RwLock;
use crate::util::list::{ArcList, Link};
use crate::util::rculist::RcuList;
use spin::Once;

use crate::net::device::NetDevice;
use crate::net::ethernet::{self, PktType};
use crate::net::skb::{SkBuff, SkbQueue};
use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::WaitQueue;
use crate::task::kthread::KThread;
use crate::task::percpu::cpu_has_scheduler;

/// Default NAPI weight (Linux NAPI_POLL_WEIGHT)
pub const NAPI_POLL_WEIGHT: usize = 64;
/// Packets processed per softnet round before yielding (Linux netdev_budget)
pub const NETDEV_BUDGET: usize = 300;
/// Per-CPU backlog limit (Linux netdev_max_backlog)
pub const NETDEV_MAX_BACKLOG: usize = 1000;

// ============================================================================
// Protocol handlers (Linux packet_type / dev_add_pack)
// ============================================================================

/// Protocol receive handler: takes ownership of an skb whose MAC header was
/// pulled (`skb.data()` starts at the network header)
pub type PacketHandler = fn(Box<SkBuff>);

/// A frame shown to the taps (Linux ptype_all delivery): received
/// frames after classification, transmitted ones as PACKET_OUTGOING
pub struct Tap<'a> {
    pub dev: &'a Arc<NetDevice>,
    /// The frame from its link-layer header
    pub frame: &'a [u8],
    pub pkt_type: PktType,
    /// Sending socket of an outgoing frame (`SkBuff::owner`), 0 if none
    pub owner: usize,
}

/// Tap handler (Linux ptype_all, for AF_PACKET): sees every frame
/// without consuming it
pub type PacketTap = fn(&Tap<'_>);

/// Most taps (each address family registers one)
const MAX_TAPS: usize = 4;

/// A protocol's receive handler for an EtherType (Linux struct
/// packet_type): a static, linked on `PTYPE_BASE` by `dev_add_pack`
pub struct PacketType {
    /// EtherType, host byte order
    pub ty: u16,
    pub func: PacketHandler,
    /// On `PTYPE_BASE` (Linux packet_type.list)
    list: Link,
}

crate::adapter!(pub PtypeLink, PacketType, list);

impl PacketType {
    pub const fn new(ty: u16, func: PacketHandler) -> Self {
        Self {
            ty,
            func,
            list: Link::new(),
        }
    }
}

/// The protocol handlers (IPv4, ARP; IPv6 later; Linux ptype_base):
/// read under RCU, added to at boot
static PTYPE_BASE: RcuList<PtypeLink, &'static PacketType> = RcuList::new();
/// Taps that see all frames, both directions (AF_PACKET)
static PTYPE_ALL: RwLock<[Option<PacketTap>; MAX_TAPS]> = RwLock::new([None; MAX_TAPS]);

/// Register a protocol handler (Linux dev_add_pack: first on the list)
pub fn dev_add_pack(pt: &'static PacketType) {
    PTYPE_BASE.insert_after(pt, |_| false);
}

/// Register a tap that sees every received and transmitted frame
pub fn dev_add_tap(tap: PacketTap) {
    let mut t = PTYPE_ALL.write();
    let slot = t.iter_mut().find(|s| s.is_none()).expect("too many taps");
    *slot = Some(tap);
}

/// Show a frame to the taps (copied out: called without the lock)
fn deliver_taps(t: &Tap<'_>) {
    let taps = *PTYPE_ALL.read();
    for tap in taps.iter().flatten() {
        tap(t);
    }
}

/// The handler for `ethertype`, copied out of the RCU walk: the
/// handlers take socket locks and allocate, so they run after it
fn ptype_lookup(ethertype: u16) -> Option<PacketHandler> {
    let g = crate::sync::rcu::read_lock();
    PTYPE_BASE
        .iter(&g)
        .find(|pt| pt.ty == ethertype)
        .map(|pt| pt.func)
}

// ============================================================================
// NAPI
// ============================================================================

/// Driver side of NAPI: process up to `budget` packets
pub trait NapiPoll: Send + Sync {
    /// Poll the device. Returns the number of packets processed. If it
    /// returns less than `budget`, the driver must have called
    /// [`napi_complete_done`] (and then re-enabled its interrupts); if it
    /// returns `budget`, it must not have, and it is polled again.
    fn poll(&self, napi: &Napi, budget: usize) -> usize;
}

/// NAPI state bits (Linux NAPI_STATE_*)
mod st {
    /// Scheduled: on a poll list or being polled; owned by whoever set
    /// it (Linux NAPI_STATE_SCHED)
    pub const SCHED: u32 = 1;
    /// A schedule came while scheduled: poll again rather than complete
    /// (Linux NAPI_STATE_MISSED)
    pub const MISSED: u32 = 2;
    /// `napi_disable` waits: no new schedule, the poll loop completes it
    /// (Linux NAPI_STATE_DISABLE)
    pub const DISABLE: u32 = 4;
}

/// NAPI context (Linux struct napi_struct)
pub struct Napi {
    /// `st` bits, changed by compare-and-swap (Linux napi->state)
    state: AtomicU32,
    /// Packets per poll
    weight: usize,
    /// The driver (weak: the driver owns the Napi)
    poller: Once<Weak<dyn NapiPoll>>,
    /// Polls run (stats)
    polls: AtomicU64,
    /// On a softnet poll list while scheduled (Linux poll_list)
    poll_list: Link,
}

crate::adapter!(NapiLink, Napi, poll_list);

impl Napi {
    /// Create a NAPI context; attach the driver with [`netif_napi_add`]
    pub fn new(weight: usize) -> Arc<Self> {
        // Driver probe has no failure path
        arc_nofail(Self {
            state: AtomicU32::new(0),
            weight: weight.clamp(1, NAPI_POLL_WEIGHT),
            poller: Once::new(),
            polls: AtomicU64::new(0),
            poll_list: Link::new(),
        })
    }

    /// Number of polls run so far
    pub fn polls(&self) -> u64 {
        self.polls.load(Ordering::Relaxed)
    }

    /// True while scheduled or being polled
    pub fn is_scheduled(&self) -> bool {
        self.state.load(Ordering::Acquire) & st::SCHED != 0
    }

    fn disable_pending(&self) -> bool {
        self.state.load(Ordering::Acquire) & st::DISABLE != 0
    }

    fn poll(&self, budget: usize) -> usize {
        // One poller at a time (NAPI_STATE_SCHED)
        crate::sync::Sole::sole_add(&self.polls, 1);
        match self.poller.get().and_then(|w| w.upgrade()) {
            Some(p) => p.poll(self, budget),
            None => {
                // Driver gone: complete so the Napi is not polled again
                napi_complete_done(self, 0);
                0
            }
        }
    }

    /// Apply `f` to the state until the compare-and-swap takes (Linux's
    /// try_cmpxchg loops); returns the old state, or None if `f` declines
    fn update(&self, f: impl Fn(u32) -> Option<u32>) -> Option<u32> {
        self.state
            .try_update(Ordering::AcqRel, Ordering::Acquire, f)
            .ok()
    }
}

/// Attach `poller` to `napi` and make it schedulable (Linux
/// netif_napi_add; process context)
pub fn netif_napi_add(napi: &Arc<Napi>, poller: Weak<dyn NapiPoll>) {
    napi.poller.call_once(|| poller);
}

/// Forget `napi` (Linux netif_napi_del; process context): it must be
/// disabled (`napi_disable`), so it is on no poll list and no poll runs
pub fn netif_napi_del(napi: &Arc<Napi>) {
    debug_assert!(
        !napi.poll_list.is_linked(),
        "netif_napi_del: NAPI still scheduled"
    );
}

/// Claim `napi` for a poll (Linux napi_schedule_prep): true if the
/// caller set SCHED and must queue it; while it is already scheduled
/// MISSED is set instead, so the running poll goes round again; never
/// while a disable is pending
fn napi_schedule_prep(napi: &Napi) -> bool {
    napi.update(prep_next).is_some_and(|v| v & st::SCHED == 0)
}

/// napi_schedule_prep's new state from `v`: None while disabling
fn prep_next(v: u32) -> Option<u32> {
    if v & st::DISABLE != 0 {
        return None;
    }
    let missed = if v & st::SCHED != 0 { st::MISSED } else { 0 };
    Some(v | st::SCHED | missed)
}

/// napi_complete_done's new state from `v`: SCHED kept if MISSED
fn complete_next(v: u32) -> u32 {
    let keep = if v & st::MISSED != 0 { st::SCHED } else { 0 };
    (v & !(st::SCHED | st::MISSED)) | keep
}

/// Queue `napi`, whose SCHED the caller set, on this CPU's poll list
/// (Linux ____napi_schedule)
fn napi_queue(napi: &Arc<Napi>) {
    let sd = this_softnet();
    sd.poll_list.lock().push_back(Arc::clone(napi));
    sd.wq.wake_all();
}

/// Schedule `napi` for polling on this CPU's softnet thread
///
/// IRQ-safe (Linux `napi_schedule`). The caller (an ISR) has masked the
/// device's interrupts; the poll routine re-enables them on completion.
pub fn napi_schedule(napi: &Arc<Napi>) {
    if napi_schedule_prep(napi) {
        napi_queue(napi);
    }
}

/// Mark a NAPI poll complete (Linux napi_complete_done; called by the
/// driver's poll when it did less than its budget): true if done, and
/// the driver re-enables its interrupts; false if a schedule came
/// during the poll (MISSED): it stays scheduled, queued again, and the
/// driver leaves its interrupts masked. A full barrier (the
/// compare-and-swap, as Linux's cmpxchg): causes recorded before an
/// ISR's schedule are seen by the driver's re-check after this.
pub fn napi_complete_done(napi: &Napi, _work_done: usize) -> bool {
    let old = napi
        .state
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
            debug_assert!(v & st::SCHED != 0, "napi_complete_done: not scheduled");
            Some(complete_next(v))
        })
        .unwrap_or(0);
    if old & st::MISSED != 0 {
        // Linux __napi_schedule: the poll loop holds the reference the
        // poll list gave up and puts it back when the poll returns
        this_softnet()
            .requeue
            .store(core::ptr::from_ref(napi).cast_mut(), Ordering::Relaxed);
        return false;
    }
    true
}

/// Stop polling `napi` (Linux napi_disable; process context, may
/// sleep): no new schedule from here (DISABLE), a scheduled or running
/// poll is waited out, then SCHED is held until `napi_enable`
pub fn napi_disable(napi: &Napi) {
    napi.state.fetch_or(st::DISABLE, Ordering::SeqCst);
    while napi
        .update(|v| (v & st::SCHED == 0).then_some(v | st::SCHED))
        .is_none()
    {
        napi_wait();
    }
    napi.state.fetch_and(!st::DISABLE, Ordering::SeqCst);
}

/// Allow `napi` to be scheduled again (Linux napi_enable)
pub fn napi_enable(napi: &Napi) {
    napi.state
        .fetch_and(!(st::SCHED | st::MISSED), Ordering::SeqCst);
}

/// Back off while a poll finishes
fn napi_wait() {
    let ms = crate::time::monotonic_ns() + 1_000_000;
    let _ = crate::task::percpu::sleep_until_ns(ms, false);
}

// ============================================================================
// Per-CPU softnet data
// ============================================================================

/// Per-CPU receive state (Linux struct softnet_data)
struct Softnet {
    /// NAPI contexts to poll, each holding a reference (IRQ-safe:
    /// napi_schedule runs in ISRs; Linux sd->poll_list)
    poll_list: IrqSpinlock<ArcList<NapiLink>>,
    /// Packets queued by netif_rx (Linux input_pkt_queue; thread
    /// context only)
    backlog: SkbQueue<Box<SkBuff>>,
    /// The backlog's NAPI (Linux sd->backlog): scheduled by the netif_rx
    /// that finds the queue empty, completed by the poll that empties
    /// it, both under the queue's lock; made on first use
    backlog_napi: Once<Arc<Napi>>,
    /// The NAPI this CPU's poll completed with MISSED (Linux
    /// __napi_schedule from napi_complete_done): put back on the list by
    /// the poll loop that holds it; this CPU's poller alone
    requeue: core::sync::atomic::AtomicPtr<Napi>,
    /// The softnet thread sleeps here
    wq: WaitQueue,
    /// Its `softnet/N` thread (Linux the CPU's ksoftirqd)
    thread: Once<Arc<KThread>>,
    /// Packets processed (Linux softnet_stat "processed")
    processed: AtomicU64,
    /// Packets dropped on backlog overflow (softnet_stat "dropped")
    dropped: AtomicU64,
    /// Rounds that ran out of budget (softnet_stat "time_squeeze")
    time_squeeze: AtomicU64,
}

impl Softnet {
    const fn new() -> Self {
        Self {
            poll_list: IrqSpinlock::new(ArcList::new()),
            backlog: SkbQueue::new(),
            backlog_napi: Once::new(),
            requeue: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            wq: WaitQueue::new(),
            thread: Once::new(),
            processed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            time_squeeze: AtomicU64::new(0),
        }
    }

    /// A NAPI to poll (the backlog's among them)
    fn has_work(&self) -> bool {
        !self.poll_list.lock().is_empty()
    }

    /// The backlog's NAPI, polled by [`process_backlog`] for CPU `cpu`
    fn backlog_napi(&'static self, cpu: u32) -> &'static Arc<Napi> {
        self.backlog_napi.call_once(|| {
            let n = Napi::new(NAPI_POLL_WEIGHT);
            let p: Arc<dyn NapiPoll> = arc_nofail(Backlog(cpu));
            // The poller lives as long as the per-CPU Softnet
            n.poller.call_once(|| Arc::downgrade(&p));
            core::mem::forget(p);
            n
        })
    }

    /// Poll `napi` once with `quota`; true if it stays scheduled (used
    /// its quota, or completed with MISSED): the caller puts it back
    fn poll_one(&self, napi: &Arc<Napi>, quota: usize) -> (usize, bool) {
        self.requeue.store(core::ptr::null_mut(), Ordering::Relaxed);
        let work = napi.poll(quota);
        if work < quota {
            let again = core::ptr::eq(self.requeue.load(Ordering::Relaxed), Arc::as_ptr(napi));
            return (work, again);
        }
        if napi.disable_pending() {
            // napi_disable waits: complete it (Linux __napi_poll)
            return (work, !napi_complete_done(napi, work));
        }
        (work, true)
    }
}

crate::percpu! {
    static SOFTNET: Softnet = Softnet::new();
}

static SOFTNET_STARTED: AtomicU32 = AtomicU32::new(0);

fn this_softnet() -> &'static Softnet {
    SOFTNET.this()
}

/// Start one `softnet/N` thread per CPU that runs a scheduler (after
/// scheduling is enabled). Work queued earlier (IRQs during boot) is
/// picked up on the threads' first pass.
pub fn softnet_init() {
    let mut started = 0;
    for cpu in 0..crate::cpu::nr_cpu_ids() as usize {
        if !cpu_has_scheduler(cpu as u32) {
            continue;
        }
        let name = alloc::format!("softnet/{cpu}");
        match crate::task::kthread::kthread_run(&name, softnet_thread, cpu, Some(cpu as u32)) {
            Ok(k) => {
                SOFTNET.get(cpu as u32).thread.call_once(|| k);
                started += 1;
            }
            Err(e) => crate::printkln!("net: cannot start softnet/{}: {:?}", cpu, e),
        }
    }
    SOFTNET_STARTED.store(started, Ordering::Release);
    crate::printkln!("net: {} softnet threads", started);
}

/// Body of `softnet/N` (Linux net_rx_action + ksoftirqd)
fn softnet_thread(cpu: usize) {
    let sd = SOFTNET.get(cpu as u32);
    loop {
        sd.wq.wait_event(|| sd.has_work());
        let mut budget = NETDEV_BUDGET;

        // NAPI contexts, the backlog's among them, round-robin,
        // `weight` packets each (Linux net_rx_action)
        while budget > 0 {
            let Some(napi) = sd.poll_list.lock().pop_front() else {
                break;
            };
            let (work, again) = sd.poll_one(&napi, napi.weight.min(budget));
            budget = budget.saturating_sub(work);
            if again {
                // Still scheduled (SCHED held): keep polling it
                sd.poll_list.lock().push_back(napi);
            }
        }

        if budget == 0 {
            // This CPU's softnet (Linux sd->time_squeeze++)
            crate::sync::Sole::sole_add(&sd.time_squeeze, 1);
        }
        if sd.has_work() {
            // Work left after the budget: a scheduling point (Linux
            // net_rx_action defers to ksoftirqd, which cond_rescheds)
            crate::task::percpu::cond_resched();
        }
    }
}

/// The poller of CPU `.0`'s backlog NAPI
struct Backlog(u32);

impl NapiPoll for Backlog {
    fn poll(&self, napi: &Napi, budget: usize) -> usize {
        process_backlog(SOFTNET.get(self.0), napi, budget)
    }
}

/// Deliver up to `quota` backlog packets (Linux process_backlog); the
/// poll that empties the queue completes the NAPI under the queue's
/// lock, so the next netif_rx schedules it again
fn process_backlog(sd: &Softnet, napi: &Napi, quota: usize) -> usize {
    let mut done = 0;
    while done < quota {
        let skb = {
            let mut q = sd.backlog.lock();
            match q.pop_front() {
                Some(skb) => skb,
                None => {
                    // Linux: napi->state &= NAPIF_STATE_THREADED, under
                    // the queue lock (only netif_rx sets SCHED, under it)
                    napi.state.fetch_and(!st::SCHED, Ordering::Release);
                    return done;
                }
            }
        };
        netif_receive_skb(skb);
        done += 1;
    }
    done
}

/// Queue a received packet on this CPU's backlog (Linux `netif_rx`)
///
/// Thread context only; never allocates (the skb is linked through its
/// own `list`: a transmit under socket locks queues no memory). Used by
/// devices without NAPI, notably `lo`; never processes the packet
/// synchronously, so a transmit path calling it never re-enters the
/// receive path. Returns false if the packet was dropped (backlog
/// full).
pub fn netif_rx(skb: Box<SkBuff>) -> bool {
    let cpu = crate::cpu::this_id();
    let sd = SOFTNET.get(cpu);
    crate::task::percpu::current()
        .rx_cpu
        .store(cpu, Ordering::Relaxed);
    let napi = sd.backlog_napi(cpu);
    let sched = {
        let mut q = sd.backlog.lock();
        if q.len() >= NETDEV_MAX_BACKLOG {
            drop(q);
            sd.dropped.fetch_add(1, Ordering::Relaxed);
            if let Some(dev) = skb.dev.as_ref() {
                dev.stats.inc_rx_dropped();
            }
            return false;
        }
        q.push_back(skb);
        // Linux enqueue_to_backlog: SCHED set under the queue lock
        napi.state.fetch_or(st::SCHED, Ordering::AcqRel) & st::SCHED == 0
    };
    if sched {
        // Queued on its own CPU's list (Linux napi_schedule_rps)
        sd.poll_list.lock().push_back(Arc::clone(napi));
        sd.wq.wake_all();
    }
    true
}

/// Process the backlog the calling task last queued to (Linux: softirqs
/// run at `local_bh_enable()` right after `dev_queue_xmit`, so loopback
/// traffic is delivered before `sendto()` returns).
///
/// Call only at a point where the caller holds no locks (end of a socket
/// send; never under a socket lock: delivery takes socket locks). If the
/// softnet thread is mid-round, the packets are left to it.
///
/// A send may sleep between its transmits (a user copy that faults) and
/// resume on another CPU: the backlog is the one `netif_rx` last used
/// (`Task.rx_cpu`), possibly another CPU's (deviation: Linux processes
/// only the local CPU's softirqs). Packets queued before an earlier move
/// still arrive, through that CPU's softnet thread.
pub fn netif_rx_flush_local() {
    let cpu = match crate::task::percpu::current()
        .rx_cpu
        .swap(u32::MAX, Ordering::Relaxed)
    {
        u32::MAX => crate::cpu::this_id(),
        cpu => cpu,
    };
    let sd = SOFTNET.get(cpu);
    let napi = sd.backlog_napi(cpu);
    // Taken off the poll list, it is ours to poll (Linux net_rx_action
    // splices the list); one being polled already is the thread's
    let mine = Arc::as_ptr(napi);
    let Some(napi) = sd.poll_list.lock().remove_first(|n| core::ptr::eq(n, mine)) else {
        return;
    };
    // On the IRQ stack, atomic, allocating GFP_ATOMIC (Linux runs these
    // pending softirqs at local_bh_enable through do_softirq_own_stack):
    // a receive path nested in a deep task path (an exit closing TCP
    // sockets over lo) does not add to the task's stack
    let mut again = false;
    crate::irq_stack::run_softirq(|| {
        again = crate::util::kalloc::with_gfp(crate::mm::page_alloc::Gfp::ATOMIC, || {
            let mut budget = NETDEV_BUDGET;
            loop {
                let quota = budget.min(NAPI_POLL_WEIGHT);
                let n = process_backlog(sd, &napi, quota);
                // Short: it emptied the queue and gave up SCHED, so the
                // NAPI is no longer ours (a netif_rx may have queued it
                // since: never look at its state again)
                if n < quota {
                    return false;
                }
                budget -= n;
                if budget == 0 {
                    return true;
                }
            }
        });
    });
    if again {
        // Budget spent: the rest is the thread's
        sd.poll_list.lock().push_back(napi);
        sd.wq.wake_all();
    }
}

// ============================================================================
// Receive dispatch
// ============================================================================

/// Deliver a received frame to the protocol handlers (Linux
/// `netif_receive_skb` / `__netif_receive_skb_core`). Thread context.
///
/// `skb.dev` must be set; `skb.data()` starts at the Ethernet header.
pub fn netif_receive_skb(mut skb: Box<SkBuff>) {
    let Some(dev) = skb.dev.clone() else {
        return;
    };
    // This CPU's softnet (Linux __this_cpu_inc(softnet_data.processed))
    crate::sync::Sole::sole_add(&this_softnet().processed, 1);
    if !dev.is_up() {
        // Closed device (a frame raced with dev_close)
        dev.stats.inc_rx_dropped();
        return;
    }

    let Some(ethertype) = ethernet::eth_type_trans(&mut skb, &dev) else {
        dev.stats.inc_rx_errors();
        return;
    };

    // Taps (AF_PACKET) see every frame, including other hosts' frames
    if let Some(frame) = skb.frame_from_mac() {
        deliver_taps(&Tap {
            dev: &dev,
            frame,
            pkt_type: skb.pkt_type,
            owner: 0,
        });
    }

    if skb.pkt_type == PktType::OtherHost {
        // Not addressed to us (Linux drops these in the protocol handlers)
        return;
    }

    match ptype_lookup(ethertype) {
        Some(handler) => handler(skb),
        None => dev.stats.inc_rx_nohandler(),
    }
}

/// Transmit a frame on `skb.dev` (Linux `dev_queue_xmit`; no qdisc).
/// `skb.data()` starts at the link-layer header. The taps see it as
/// PACKET_OUTGOING first (Linux dev_queue_xmit_nit), if the device is up.
pub fn dev_queue_xmit(skb: Box<SkBuff>) -> Result<(), crate::util::error::KernelError> {
    let dev: Arc<NetDevice> = skb
        .dev
        .clone()
        .ok_or(crate::util::error::KernelError::NoDevice)?;
    if dev.is_up() {
        deliver_taps(&Tap {
            dev: &dev,
            frame: skb.data(),
            pkt_type: PktType::Outgoing,
            owner: skb.owner,
        });
    }
    dev.xmit(skb)
}

/// Per-CPU softnet statistics: (processed, dropped, time_squeeze), for
/// `/proc/net/softnet_stat`-style reporting
pub fn softnet_stats(cpu: usize) -> Option<(u64, u64, u64)> {
    let sd = SOFTNET.try_get(u32::try_from(cpu).ok()?)?;
    Some((
        sd.processed.load(Ordering::Relaxed),
        sd.dropped.load(Ordering::Relaxed),
        sd.time_squeeze.load(Ordering::Relaxed),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_during_poll_is_missed() {
        // Idle -> scheduled by the first prep
        let v = prep_next(0).unwrap();
        assert_eq!(v, st::SCHED);
        // A second schedule while polled: MISSED, no new owner
        let v2 = prep_next(v).unwrap();
        assert_eq!(v2, st::SCHED | st::MISSED);
        // Completion with MISSED keeps it scheduled, clears MISSED
        assert_eq!(complete_next(v2), st::SCHED);
        // A plain completion leaves it idle
        assert_eq!(complete_next(st::SCHED), 0);
    }

    #[test]
    fn no_schedule_while_disabling() {
        assert_eq!(prep_next(st::DISABLE), None);
        assert_eq!(prep_next(st::DISABLE | st::SCHED), None);
    }
}
