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
//! softirqs at `local_bh_enable()` after `dev_queue_xmit`). Nothing below a
//! driver ISR ever runs in interrupt context.
//!
//! ## Locking (see doc/LOCKING.md, Network)
//!
//! - `Softnet.poll_list`: `IrqSpinlock`, leaf. Taken by `napi_schedule`
//!   (ISR) and the softnet thread. Capacity is reserved when a NAPI is
//!   added, so the ISR never allocates.
//! - `Softnet.backlog`: `spin::Mutex`, thread context only, leaf.
//! - `PTYPE_BASE` / `PTYPE_ALL`: `spin::RwLock`, thread context only, leaf;
//!   handlers are copied out and called after the guard is dropped.
//! - `NAPI_LIST`: `spin::Mutex`, thread context only, leaf.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use spin::{Mutex, Once, RwLock};

use crate::arch::IrqSpinlock;
use crate::net::device::NetDevice;
use crate::net::ethernet::{self, PktType};
use crate::net::skb::SkBuff;
use crate::task::kthread::KThread;
use crate::task::percpu::{MAX_SCHED_CPUS, cpu_has_scheduler, current_cpu};
use crate::waitqueue::WaitQueue;

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
pub type PacketHandler = fn(SkBuff);

/// Tap handler (Linux ptype_all, for AF_PACKET): sees every received frame
/// (MAC header still present at `skb.mac_header()`) without consuming it
pub type PacketTap = fn(&SkBuff);

/// EtherType -> handler table (IPv4, ARP; IPv6 later)
static PTYPE_BASE: RwLock<Vec<(u16, PacketHandler)>> = RwLock::new(Vec::new());
/// Taps that see all frames (reserved for AF_PACKET)
static PTYPE_ALL: RwLock<Vec<PacketTap>> = RwLock::new(Vec::new());

/// Register a protocol handler for an EtherType (host byte order)
pub fn dev_add_pack(ethertype: u16, handler: PacketHandler) {
    let mut t = PTYPE_BASE.write();
    t.retain(|&(e, _)| e != ethertype);
    t.push((ethertype, handler));
}

/// Register a tap that sees every received frame
pub fn dev_add_tap(tap: PacketTap) {
    PTYPE_ALL.write().push(tap);
}

fn ptype_lookup(ethertype: u16) -> Option<PacketHandler> {
    PTYPE_BASE
        .read()
        .iter()
        .find(|&&(e, _)| e == ethertype)
        .map(|&(_, h)| h)
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

/// NAPI context (Linux struct napi_struct)
pub struct Napi {
    /// Scheduled: on a poll list or being polled
    sched: AtomicBool,
    /// Packets per poll
    weight: usize,
    /// The driver (weak: the driver owns the Napi)
    poller: Once<Weak<dyn NapiPoll>>,
    /// Polls run (stats)
    polls: AtomicU64,
}

impl Napi {
    /// Create a NAPI context; attach the driver with [`netif_napi_add`]
    pub fn new(weight: usize) -> Arc<Self> {
        Arc::new(Self {
            sched: AtomicBool::new(false),
            weight: weight.clamp(1, NAPI_POLL_WEIGHT),
            poller: Once::new(),
            polls: AtomicU64::new(0),
        })
    }

    /// Number of polls run so far
    pub fn polls(&self) -> u64 {
        self.polls.load(Ordering::Relaxed)
    }

    /// True while scheduled or being polled
    pub fn is_scheduled(&self) -> bool {
        self.sched.load(Ordering::Acquire)
    }

    fn poll(&self, budget: usize) -> usize {
        self.polls.fetch_add(1, Ordering::Relaxed);
        match self.poller.get().and_then(|w| w.upgrade()) {
            Some(p) => p.poll(self, budget),
            None => {
                // Driver gone: complete so the Napi is not polled again
                napi_complete_done(self, 0);
                0
            }
        }
    }
}

/// All NAPI contexts (to reserve poll-list capacity)
static NAPI_LIST: Mutex<Vec<Arc<Napi>>> = Mutex::new(Vec::new());

/// Attach `poller` to `napi` and make it schedulable (process context)
pub fn netif_napi_add(napi: &Arc<Napi>, poller: Weak<dyn NapiPoll>) {
    napi.poller.call_once(|| poller);
    let n = {
        let mut list = NAPI_LIST.lock();
        list.push(Arc::clone(napi));
        list.len()
    };
    // Each Napi is on at most one poll list at a time: with this capacity
    // the ISR's push never allocates
    for sd in SOFTNET.iter() {
        let mut q = sd.poll_list.lock();
        let extra = n.saturating_sub(q.len());
        q.reserve(extra);
    }
}

/// Schedule `napi` for polling on this CPU's softnet thread
///
/// IRQ-safe (Linux `napi_schedule`). The caller (an ISR) has masked the
/// device's interrupts; the poll routine re-enables them on completion.
pub fn napi_schedule(napi: &Arc<Napi>) {
    if napi.sched.swap(true, Ordering::AcqRel) {
        return; // already scheduled
    }
    let sd = this_softnet();
    sd.poll_list.lock().push_back(Arc::clone(napi));
    sd.wq.wake_all();
}

/// Mark a NAPI poll complete (called by the driver's poll when it did less
/// than its budget, before re-enabling device interrupts)
pub fn napi_complete_done(napi: &Napi, _work_done: usize) -> bool {
    napi.sched.store(false, Ordering::Release);
    true
}

// ============================================================================
// Per-CPU softnet data
// ============================================================================

/// Per-CPU receive state (Linux struct softnet_data)
struct Softnet {
    /// NAPI contexts to poll (IRQ-safe: napi_schedule runs in ISRs)
    poll_list: IrqSpinlock<VecDeque<Arc<Napi>>>,
    /// Packets queued by netif_rx (thread context only)
    backlog: Mutex<VecDeque<Box<SkBuff>>>,
    /// The softnet thread sleeps here
    wq: WaitQueue,
    /// Set while a task processes this CPU's backlog (softnet thread or an
    /// inline flush): keeps the per-CPU processing single-threaded
    busy: AtomicBool,
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
            poll_list: IrqSpinlock::new(VecDeque::new()),
            backlog: Mutex::new(VecDeque::new()),
            wq: WaitQueue::new(),
            busy: AtomicBool::new(false),
            processed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            time_squeeze: AtomicU64::new(0),
        }
    }

    fn has_work(&self) -> bool {
        !self.poll_list.lock().is_empty() || !self.backlog.lock().is_empty()
    }
}

static SOFTNET: [Softnet; MAX_SCHED_CPUS] = [const { Softnet::new() }; MAX_SCHED_CPUS];

/// Softnet threads, by CPU
static SOFTNET_THREADS: Mutex<Vec<Arc<KThread>>> = Mutex::new(Vec::new());
static SOFTNET_STARTED: AtomicU32 = AtomicU32::new(0);

fn this_softnet() -> &'static Softnet {
    let cpu = current_cpu() as usize;
    &SOFTNET[cpu.min(MAX_SCHED_CPUS - 1)]
}

/// Thread names (kthread names are &'static str)
const SOFTNET_NAMES: [&str; 16] = [
    "softnet/0",
    "softnet/1",
    "softnet/2",
    "softnet/3",
    "softnet/4",
    "softnet/5",
    "softnet/6",
    "softnet/7",
    "softnet/8",
    "softnet/9",
    "softnet/10",
    "softnet/11",
    "softnet/12",
    "softnet/13",
    "softnet/14",
    "softnet/15",
];

/// Start one `softnet/N` thread per CPU that runs a scheduler (after
/// scheduling is enabled). Work queued earlier (IRQs during boot) is
/// picked up on the threads' first pass.
pub fn softnet_init() {
    let mut started = 0;
    for (cpu, name) in SOFTNET_NAMES.iter().enumerate().take(MAX_SCHED_CPUS) {
        if !cpu_has_scheduler(cpu as u32) {
            continue;
        }
        match crate::task::kthread::kthread_run(name, softnet_thread, cpu, Some(cpu as u32)) {
            Ok(k) => {
                SOFTNET_THREADS.lock().push(k);
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
    let sd = &SOFTNET[cpu];
    loop {
        sd.wq.wait_event(|| sd.has_work());
        let mut budget = NETDEV_BUDGET;

        // NAPI devices, round-robin, `weight` packets each
        while budget > 0 {
            let Some(napi) = sd.poll_list.lock().pop_front() else {
                break;
            };
            let quota = napi.weight.min(budget);
            let work = napi.poll(quota);
            budget = budget.saturating_sub(work);
            if work >= quota {
                // Not completed: keep polling it (sched stays set)
                sd.poll_list.lock().push_back(napi);
            }
        }

        // netif_rx backlog (Linux process_backlog)
        if budget > 0 {
            budget -= process_backlog(sd, budget.min(NAPI_POLL_WEIGHT));
        }

        if budget == 0 {
            sd.time_squeeze.fetch_add(1, Ordering::Relaxed);
        }
        if sd.has_work() {
            // Cooperative scheduler: let other tasks on this CPU run
            crate::task::percpu::yield_now();
        }
    }
}

/// Deliver up to `quota` backlog packets; returns how many
fn process_backlog(sd: &Softnet, quota: usize) -> usize {
    if sd.busy.swap(true, Ordering::Acquire) {
        return 0;
    }
    let mut done = 0;
    while done < quota {
        let Some(skb) = sd.backlog.lock().pop_front() else {
            break;
        };
        netif_receive_skb(skb);
        done += 1;
    }
    sd.busy.store(false, Ordering::Release);
    done
}

/// Queue a received packet on this CPU's backlog (Linux `netif_rx`)
///
/// Thread context only (may allocate). Used by devices without NAPI,
/// notably `lo`; never processes the packet synchronously, so a transmit
/// path calling it never re-enters the receive path. Returns false if the
/// packet was dropped (backlog full).
pub fn netif_rx(skb: Box<SkBuff>) -> bool {
    let sd = this_softnet();
    {
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
    }
    sd.wq.wake_all();
    true
}

/// Process this CPU's backlog in the calling task (Linux: softirqs run at
/// `local_bh_enable()` right after `dev_queue_xmit`, so loopback traffic
/// is delivered before `sendto()` returns).
///
/// Call only at a point where the caller holds no locks (end of a socket
/// send). If the softnet thread is mid-round, the packets are left to it.
pub fn netif_rx_flush_local() {
    let sd = this_softnet();
    let mut budget = NETDEV_BUDGET;
    while budget > 0 && !sd.backlog.lock().is_empty() {
        let n = process_backlog(sd, budget.min(NAPI_POLL_WEIGHT));
        if n == 0 {
            break;
        }
        budget -= n;
    }
    if !sd.backlog.lock().is_empty() {
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
    this_softnet().processed.fetch_add(1, Ordering::Relaxed);
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
    let taps: Vec<PacketTap> = {
        let t = PTYPE_ALL.read();
        if t.is_empty() { Vec::new() } else { t.clone() }
    };
    for tap in taps {
        tap(&skb);
    }

    if skb.pkt_type == PktType::OtherHost {
        // Not addressed to us (Linux drops these in the protocol handlers)
        return;
    }

    match ptype_lookup(ethertype) {
        Some(handler) => handler(*skb),
        None => dev.stats.inc_rx_nohandler(),
    }
}

/// Transmit a frame on `skb.dev` (Linux `dev_queue_xmit`; no qdisc)
pub fn dev_queue_xmit(skb: Box<SkBuff>) -> Result<(), crate::error::KernelError> {
    let dev: Arc<NetDevice> = skb.dev.clone().ok_or(crate::error::KernelError::NoDevice)?;
    dev.xmit(skb)
}

/// Per-CPU softnet statistics: (processed, dropped, time_squeeze), for
/// `/proc/net/softnet_stat`-style reporting
pub fn softnet_stats(cpu: usize) -> Option<(u64, u64, u64)> {
    let sd = SOFTNET.get(cpu)?;
    Some((
        sd.processed.load(Ordering::Relaxed),
        sd.dropped.load(Ordering::Relaxed),
        sd.time_squeeze.load(Ordering::Relaxed),
    ))
}
