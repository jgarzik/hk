//! Generic neighbour subsystem (Linux net/core/neighbour.c)
//!
//! A `NeighTable` maps (ifindex, protocol address) to a link-layer
//! address with the Linux NUD state machine. Protocols plug in through
//! `NeighOps` (solicit, transmit with a resolved address, report an
//! undeliverable packet): ARP is the first user; IPv6 neighbour
//! discovery adds a second table with its own ops and 16-byte keys.
//!
//! The state machine itself (`NState`) is pure (time in ms is passed in)
//! and unit-tested; the table wraps it with entries, bounded per-entry
//! packet queues (`queue_bytes`), timers and garbage collection
//! (`gc_thresh1/2/3`).
//!
//! ## Timers
//!
//! One kernel timer (`ktimerd`, thread context) serves all tables: each
//! entry keeps its own deadline; the callback runs every table's due
//! entries and GC, then re-arms for the earliest deadline.
//!
//! ## Locking (thread context only; see doc/LOCKING.md)
//!
//! `NeighTable.hash` (`spin::RwLock`) -> `Neighbour.inner`
//! (`spin::Mutex`, leaf). Lookups return `Arc<Neighbour>` and drop the
//! table lock. No packet is transmitted, solicited or reported while
//! `inner` is held: state changes return actions that run after the
//! unlock. `TABLES` and `TIMER` (`spin::Mutex`) are leaves except that
//! `TIMER` is held across `timer_add/del` (-> the timer IrqSpinlock).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::{Mutex, RwLock};

use crate::error::KernelError;
use crate::net::device::NetDevice;
use crate::net::skb::SkBuff;

/// NUD states (Linux include/uapi/linux/neighbour.h)
pub mod nud {
    pub const NONE: u8 = 0x00;
    pub const INCOMPLETE: u8 = 0x01;
    pub const REACHABLE: u8 = 0x02;
    pub const STALE: u8 = 0x04;
    pub const DELAY: u8 = 0x08;
    pub const PROBE: u8 = 0x10;
    pub const FAILED: u8 = 0x20;
    pub const NOARP: u8 = 0x40;
    pub const PERMANENT: u8 = 0x80;
    /// A usable link-layer address
    pub const VALID: u8 = PERMANENT | NOARP | REACHABLE | PROBE | STALE | DELAY;
    /// Known-good address
    pub const CONNECTED: u8 = PERMANENT | NOARP | REACHABLE;
    /// States with a running timer
    pub const IN_TIMER: u8 = INCOMPLETE | REACHABLE | DELAY | PROBE;
}

/// neigh_update flags (Linux NEIGH_UPDATE_F_*)
pub mod upd {
    /// Replace a different cached address
    pub const OVERRIDE: u32 = 1 << 0;
    /// Different address in a connected state: keep it, go STALE
    pub const WEAK_OVERRIDE: u32 = 1 << 1;
    /// Administrative change (netlink): may touch PERMANENT/NOARP
    pub const ADMIN: u32 = 1 << 31;
}

/// Link-layer address (Ethernet; IPv6 over Ethernet uses the same)
pub type Lladdr = [u8; 6];
/// Protocol address (IPv4 uses the first 4 bytes)
pub type Key = [u8; 16];

/// Table parameters (Linux neigh_parms defaults, in ms)
#[derive(Clone, Copy, Debug)]
pub struct Parms {
    pub base_reachable: u64,
    pub retrans: u64,
    pub delay_probe: u64,
    pub gc_stale: u64,
    pub locktime: u64,
    pub ucast_probes: u32,
    pub mcast_probes: u32,
    pub app_probes: u32,
    pub mcast_reprobes: u32,
    /// Bytes queued per unresolved entry (unres_qlen_bytes)
    pub queue_bytes: usize,
    pub gc_thresh1: usize,
    pub gc_thresh2: usize,
    pub gc_thresh3: usize,
    /// Periodic GC interval
    pub gc_interval: u64,
}

impl Parms {
    /// Linux arp_tbl defaults
    pub const DEFAULT: Self = Self {
        base_reachable: 30_000,
        retrans: 1000,
        delay_probe: 5000,
        gc_stale: 60_000,
        locktime: 1000,
        ucast_probes: 3,
        mcast_probes: 3,
        app_probes: 0,
        mcast_reprobes: 0,
        queue_bytes: 212_992,
        gc_thresh1: 128,
        gc_thresh2: 512,
        gc_thresh3: 1024,
        gc_interval: 30_000,
    };

    /// Retransmit interval, at least 10 ms (Linux max(RETRANS, HZ/100))
    fn retrans(&self) -> u64 {
        self.retrans.max(10)
    }
}

// ============================================================================
// State machine (pure)
// ============================================================================

/// What the caller must do after a state change
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act {
    None,
    /// Send a solicitation: unicast to the address, or multicast/broadcast
    Solicit(Option<Lladdr>),
    /// The address became known: transmit the queued packets to it
    Flush(Lladdr),
    /// Resolution failed: report and drop the queued packets
    Fail,
}

/// Verdict of `event_send` for one outgoing packet
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Send {
    /// Transmit now to this address
    Now(Lladdr),
    /// Queue until resolved
    Queue,
    /// Drop (no probes configured)
    Drop,
}

/// One entry's state (Linux struct neighbour fields), times in ms
#[derive(Clone, Copy, Debug)]
pub struct NState {
    pub state: u8,
    pub ha: Lladdr,
    pub probes: u32,
    pub updated: u64,
    pub confirmed: u64,
    pub used: u64,
    /// Randomized reachable time of this entry
    pub reachable: u64,
    /// Timer deadline (IN_TIMER states)
    pub timer: Option<u64>,
}

impl NState {
    pub fn new(now: u64, reachable: u64) -> Self {
        Self {
            state: nud::NONE,
            ha: [0; 6],
            probes: 0,
            updated: now,
            confirmed: now.saturating_sub(reachable * 2),
            used: now,
            reachable,
            timer: None,
        }
    }

    /// Linux neigh_max_probes
    fn max_probes(&self, p: &Parms) -> u32 {
        let m = if self.state & nud::PROBE != 0 {
            p.mcast_reprobes
        } else {
            p.mcast_probes
        };
        p.ucast_probes + p.app_probes + m
    }

    /// Linux neigh_probe + arp_solicit target choice: probes beyond the
    /// unicast budget are broadcast
    fn probe(&mut self, p: &Parms) -> Act {
        self.probes += 1;
        if self.probes <= p.ucast_probes {
            Act::Solicit(Some(self.ha))
        } else {
            Act::Solicit(None)
        }
    }

    /// A packet wants to go out (Linux __neigh_event_send). Returns the
    /// verdict and a probe to send right away, if any.
    pub fn event_send(&mut self, p: &Parms, now: u64) -> (Send, Act) {
        self.used = now;
        let s = self.state;
        if s & (nud::CONNECTED | nud::DELAY | nud::PROBE) != 0 {
            return (Send::Now(self.ha), Act::None);
        }
        if s & nud::STALE != 0 {
            self.state = nud::DELAY;
            self.updated = now;
            self.timer = Some(now + p.delay_probe);
            return (Send::Now(self.ha), Act::None);
        }
        if s == nud::INCOMPLETE {
            return (Send::Queue, Act::None);
        }
        // NONE or FAILED: start resolving
        if p.mcast_probes + p.app_probes == 0 {
            self.state = nud::FAILED;
            self.updated = now;
            return (Send::Drop, Act::None);
        }
        self.probes = p.ucast_probes;
        self.state = nud::INCOMPLETE;
        self.updated = now;
        self.timer = Some(now + p.retrans());
        (Send::Queue, self.probe(p))
    }

    /// The entry's timer fired (Linux neigh_timer_handler)
    pub fn timer(&mut self, p: &Parms, now: u64) -> Act {
        let s = self.state;
        if s & nud::IN_TIMER == 0 {
            self.timer = None;
            return Act::None;
        }
        let mut next = now + 1000;
        if s & nud::REACHABLE != 0 {
            if now <= self.confirmed + self.reachable {
                next = self.confirmed + self.reachable;
            } else if now <= self.used + p.delay_probe {
                self.state = nud::DELAY;
                self.updated = now;
                next = now + p.delay_probe;
            } else {
                self.state = nud::STALE;
                self.updated = now;
            }
        } else if s & nud::DELAY != 0 {
            if now <= self.confirmed + p.delay_probe {
                self.state = nud::REACHABLE;
                self.updated = now;
                next = self.confirmed + self.reachable;
            } else {
                self.state = nud::PROBE;
                self.updated = now;
                self.probes = 0;
                next = now + p.retrans();
            }
        } else {
            next = now + p.retrans();
        }
        if self.state & (nud::INCOMPLETE | nud::PROBE) != 0 && self.probes >= self.max_probes(p) {
            self.state = nud::FAILED;
            self.updated = now;
            self.timer = None;
            return Act::Fail;
        }
        self.timer = if self.state & nud::IN_TIMER != 0 {
            Some(next.max(now + 10))
        } else {
            None
        };
        if self.state & (nud::INCOMPLETE | nud::PROBE) != 0 {
            return self.probe(p);
        }
        Act::None
    }

    /// New information (Linux __neigh_update): `ll` = advertised
    /// address (None: keep the cached one), `new` = target state
    pub fn update(&mut self, ll: Option<Lladdr>, new: u8, flags: u32, now: u64) -> Act {
        let old = self.state;
        if flags & upd::ADMIN == 0 && old & (nud::NOARP | nud::PERMANENT) != 0 {
            return Act::None;
        }
        if new & nud::VALID == 0 {
            self.timer = None;
            self.state = new;
            if old & (nud::INCOMPLETE | nud::PROBE) != 0 && new & nud::FAILED != 0 {
                return Act::Fail;
            }
            return Act::None;
        }
        let mut ll = match ll {
            Some(a) => a,
            None if old & nud::VALID == 0 => return Act::None,
            None => self.ha,
        };
        if new & nud::CONNECTED != 0 {
            self.confirmed = now;
        }
        let mut new = new;
        if old & nud::VALID != 0 {
            if ll != self.ha && flags & upd::OVERRIDE == 0 {
                if flags & upd::WEAK_OVERRIDE != 0 && old & nud::CONNECTED != 0 {
                    ll = self.ha;
                    new = nud::STALE;
                } else {
                    return Act::None;
                }
            } else if ll == self.ha && new == nud::STALE && flags & upd::ADMIN == 0 {
                new = old;
            }
        }
        if new != old || ll != self.ha {
            self.updated = now;
        }
        if new != old {
            self.timer = None;
            if new & nud::PROBE != 0 {
                self.probes = 0;
            }
            if new & nud::IN_TIMER != 0 {
                let d = if new & nud::REACHABLE != 0 {
                    self.reachable
                } else {
                    0
                };
                self.timer = Some(now + d);
            }
            self.state = new;
        }
        if ll != self.ha {
            self.ha = ll;
            if new & nud::CONNECTED == 0 {
                self.confirmed = now.saturating_sub(self.reachable * 2);
            }
        }
        if new != old && old & nud::VALID == 0 {
            return Act::Flush(self.ha);
        }
        Act::None
    }

    /// Removable by GC (Linux neigh_periodic_work rule)
    pub fn stale_gc(&self, p: &Parms, now: u64) -> bool {
        if self.state & (nud::PERMANENT | nud::IN_TIMER) != 0 {
            return false;
        }
        let used = self.used.max(self.confirmed);
        self.state == nud::FAILED || now >= used + p.gc_stale
    }

    /// Removable under memory pressure (Linux neigh_forced_gc rule:
    /// not updated within the last 5 s)
    pub fn forced_gc(&self, now: u64) -> bool {
        if self.state & nud::PERMANENT != 0 {
            return false;
        }
        self.state == nud::FAILED || self.state == nud::NOARP || now >= self.updated + 5000
    }
}

/// Append to a byte-bounded queue, dropping the oldest entries first
/// (Linux unres_qlen_bytes); returns the dropped items
pub fn enqueue_bounded<T>(
    q: &mut VecDeque<(T, usize)>,
    bytes: &mut usize,
    item: T,
    size: usize,
    limit: usize,
) -> Vec<T> {
    let mut dropped = Vec::new();
    while *bytes + size > limit {
        let Some((old, sz)) = q.pop_front() else {
            break;
        };
        *bytes -= sz;
        dropped.push(old);
    }
    q.push_back((item, size));
    *bytes += size;
    dropped
}

// ============================================================================
// Table
// ============================================================================

/// Protocol hooks (Linux neigh_ops + the table's constructor bits)
pub struct NeighOps {
    /// Address family (AF_INET, AF_INET6)
    pub family: u8,
    /// Bytes of `Key` used
    pub key_len: usize,
    /// Send a solicitation for `n`: unicast to `dst` or broadcast;
    /// `hint` is the source address of the newest queued packet (source
    /// address choice, Linux arp_solicit)
    pub solicit: fn(n: &Neighbour, dst: Option<Lladdr>, hint: Option<Key>),
    /// Transmit `skb` (network header first) to link address `ha`
    pub output: fn(skb: Box<SkBuff>, ha: Lladdr) -> Result<(), KernelError>,
    /// A queued packet could not be delivered (resolution failed)
    pub error_report: fn(skb: Box<SkBuff>),
}

/// Entry state + queue (under `Neighbour.inner`)
struct Inner {
    st: NState,
    queue: VecDeque<(Box<SkBuff>, usize)>,
    qbytes: usize,
    dead: bool,
}

/// A neighbour entry (Linux struct neighbour)
pub struct Neighbour {
    pub key: Key,
    pub dev: Arc<NetDevice>,
    inner: Mutex<Inner>,
}

/// Snapshot of an entry for dumps and /proc
#[derive(Clone)]
pub struct NeighInfo {
    pub key: Key,
    pub ifindex: u32,
    pub dev: Arc<NetDevice>,
    pub state: u8,
    pub ha: Lladdr,
    pub probes: u32,
    /// Ages in ms
    pub confirmed: u64,
    pub used: u64,
    pub updated: u64,
}

/// A neighbour table (Linux struct neigh_table), one per family and
/// namespace
pub struct NeighTable {
    pub ops: &'static NeighOps,
    pub parms: Parms,
    hash: RwLock<BTreeMap<(u32, Key), Arc<Neighbour>>>,
    /// Last forced GC / next periodic GC (ms)
    last_flush: AtomicU64,
    next_gc: AtomicU64,
}

/// Milliseconds on the monotonic clock
pub fn now_ms() -> u64 {
    crate::time::monotonic_ns() / 1_000_000
}

/// Linux neigh_rand_reach_time: uniform in [base/2, 3*base/2)
fn rand_reach(base: u64) -> u64 {
    base / 2 + crate::random::get_random_u32() as u64 % base.max(1)
}

impl NeighTable {
    /// A new table, registered with the neighbour timer
    pub fn new(ops: &'static NeighOps) -> Arc<Self> {
        let t = Arc::new(Self {
            ops,
            parms: Parms::DEFAULT,
            hash: RwLock::new(BTreeMap::new()),
            last_flush: AtomicU64::new(0),
            next_gc: AtomicU64::new(0),
        });
        TABLES.lock().push(Arc::downgrade(&t));
        t
    }

    pub fn len(&self) -> usize {
        self.hash.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Entry for `key` on `ifindex`
    pub fn lookup(&self, ifindex: u32, key: &Key) -> Option<Arc<Neighbour>> {
        self.hash.read().get(&(ifindex, *key)).cloned()
    }

    /// Existing entry or a new NONE entry (Linux __neigh_create):
    /// ENOBUFS when the table is full even after forced GC
    pub fn create(&self, dev: &Arc<NetDevice>, key: &Key) -> Result<Arc<Neighbour>, KernelError> {
        if let Some(n) = self.lookup(dev.ifindex(), key) {
            return Ok(n);
        }
        let now = now_ms();
        self.maybe_forced_gc(now)?;
        let n = Arc::new(Neighbour {
            key: *key,
            dev: dev.clone(),
            inner: Mutex::new(Inner {
                st: NState::new(now, rand_reach(self.parms.base_reachable)),
                queue: VecDeque::new(),
                qbytes: 0,
                dead: false,
            }),
        });
        let n = self
            .hash
            .write()
            .entry((dev.ifindex(), *key))
            .or_insert(n)
            .clone();
        self.arm_gc(now);
        Ok(n)
    }

    /// Linux neigh_alloc's forced GC trigger
    fn maybe_forced_gc(&self, now: u64) -> Result<(), KernelError> {
        let p = &self.parms;
        let n = self.len();
        let last = self.last_flush.load(Ordering::Relaxed);
        if n >= p.gc_thresh3 || (n >= p.gc_thresh2 && now > last + 5000) {
            self.last_flush.store(now, Ordering::Relaxed);
            self.gc(now, true);
            if self.len() >= p.gc_thresh3 {
                return Err(KernelError::NoBufferSpace);
            }
        }
        Ok(())
    }

    /// Remove unreferenced entries: forced (down to gc_thresh2) or
    /// periodic (stale ones, only above gc_thresh1)
    fn gc(&self, now: u64, forced: bool) {
        let p = &self.parms;
        let mut h = self.hash.write();
        if !forced && h.len() < p.gc_thresh1 {
            return;
        }
        let mut excess = h.len().saturating_sub(p.gc_thresh2);
        h.retain(|_, n| {
            if forced && excess == 0 {
                return true;
            }
            // Referenced elsewhere (an output in progress): keep
            if Arc::strong_count(n) > 1 {
                return true;
            }
            let mut i = n.inner.lock();
            let st = &i.st;
            let rm = if forced {
                st.forced_gc(now)
            } else {
                st.stale_gc(p, now)
            };
            if rm {
                i.dead = true;
                i.queue.clear();
                excess = excess.saturating_sub(1);
            }
            !rm
        });
    }

    /// Transmit `skb` via `n` (Linux neigh_resolve_output): now if the
    /// address is usable, else queued (bounded) while resolving
    pub fn output(&self, n: &Arc<Neighbour>, skb: Box<SkBuff>) -> Result<(), KernelError> {
        let mut i = n.inner.lock();
        if i.dead {
            return Err(KernelError::HostUnreachable);
        }
        let (verdict, act) = i.st.event_send(&self.parms, now_ms());
        match verdict {
            Send::Now(ha) => {
                drop(i);
                self.after(n, act);
                (self.ops.output)(skb, ha)
            }
            Send::Drop => Err(KernelError::HostUnreachable),
            Send::Queue => {
                let sz = skb_truesize(&skb);
                let Inner { queue, qbytes, .. } = &mut *i;
                let dropped = enqueue_bounded(queue, qbytes, skb, sz, self.parms.queue_bytes);
                drop(i);
                drop(dropped);
                self.after(n, act);
                Ok(())
            }
        }
    }

    /// Run an action outside `inner` and keep the timer armed
    fn after(&self, n: &Arc<Neighbour>, act: Act) {
        match act {
            Act::None => {}
            Act::Solicit(dst) => {
                let hint = n.inner.lock().queue.back().and_then(|(s, _)| s.saddr);
                (self.ops.solicit)(n, dst, hint.map(key4));
            }
            Act::Flush(ha) => {
                for (skb, _) in n.take_queue() {
                    let _ = (self.ops.output)(skb, ha);
                }
            }
            Act::Fail => {
                for (skb, _) in n.take_queue() {
                    (self.ops.error_report)(skb);
                }
            }
        }
        if let Some(t) = n.inner.lock().st.timer {
            arm(t);
        }
    }

    /// New information about `n` (Linux neigh_update)
    pub fn update(&self, n: &Arc<Neighbour>, ll: Option<Lladdr>, new: u8, flags: u32) {
        let act = n.inner.lock().st.update(ll, new, flags, now_ms());
        self.after(n, act);
    }

    /// Whether a new address for `n` may override the cached one now
    /// (Linux arp_process: after `locktime` since the last update)
    pub fn may_override(&self, n: &Neighbour) -> bool {
        now_ms() > n.inner.lock().st.updated + self.parms.locktime
    }

    /// Run due timers and periodic GC; returns the earliest pending
    /// deadline
    fn run(&self, now: u64) -> Option<u64> {
        let due: Vec<Arc<Neighbour>> = self
            .hash
            .read()
            .values()
            .filter(|n| n.inner.lock().st.timer.is_some_and(|t| t <= now))
            .cloned()
            .collect();
        for n in due {
            let act = {
                let mut i = n.inner.lock();
                if i.dead {
                    continue;
                }
                i.st.timer(&self.parms, now)
            };
            self.after(&n, act);
        }
        if now >= self.next_gc.load(Ordering::Relaxed) {
            self.next_gc
                .store(now + self.parms.gc_interval, Ordering::Relaxed);
            self.gc(now, false);
        }
        let h = self.hash.read();
        let mut next = h.values().filter_map(|n| n.inner.lock().st.timer).min();
        if !h.is_empty() {
            let gc = self.next_gc.load(Ordering::Relaxed);
            next = Some(next.map_or(gc, |t| t.min(gc)));
        }
        next
    }

    fn arm_gc(&self, now: u64) {
        if self.next_gc.load(Ordering::Relaxed) == 0 {
            self.next_gc
                .store(now + self.parms.gc_interval, Ordering::Relaxed);
        }
        arm(self.next_gc.load(Ordering::Relaxed));
    }

    /// Forget every entry of a device going down, dropping queued
    /// packets (Linux neigh_ifdown)
    pub fn flush_dev(&self, ifindex: u32) {
        let gone: Vec<Arc<Neighbour>> = {
            let mut h = self.hash.write();
            let keys: Vec<(u32, Key)> = h.keys().filter(|k| k.0 == ifindex).copied().collect();
            keys.iter().filter_map(|k| h.remove(k)).collect()
        };
        for n in gone {
            let mut i = n.inner.lock();
            i.dead = true;
            i.queue.clear();
            i.qbytes = 0;
        }
    }

    /// Administrative add/replace (RTM_NEWNEIGH with netlink flags
    /// `nlflags`): EEXIST with NLM_F_EXCL, ENOENT without NLM_F_CREATE
    /// for a missing entry; an existing entry's address changes only
    /// with NLM_F_REPLACE
    pub fn admin_add(
        &self,
        dev: &Arc<NetDevice>,
        key: &Key,
        ll: Option<Lladdr>,
        state: u8,
        nlflags: u16,
    ) -> Result<(), KernelError> {
        use crate::net::inet::fib::{NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE};
        let create = nlflags & NLM_F_CREATE != 0;
        let excl = nlflags & NLM_F_EXCL != 0;
        let replace = nlflags & NLM_F_REPLACE != 0;
        let (n, new) = match self.lookup(dev.ifindex(), key) {
            Some(_) if excl => return Err(KernelError::AlreadyExists),
            Some(n) => (n, false),
            None if !create => return Err(KernelError::NotFound),
            None => (self.create(dev, key)?, true),
        };
        if ll.is_none() && state & nud::VALID != 0 && n.state() & nud::VALID == 0 {
            // No link-layer address to make it usable
            return Err(KernelError::InvalidArgument);
        }
        let mut flags = upd::ADMIN;
        if new || replace {
            flags |= upd::OVERRIDE;
        }
        self.update(&n, ll, state, flags);
        Ok(())
    }

    /// Administrative delete (RTM_DELNEIGH): ENOENT if absent
    pub fn admin_del(&self, ifindex: u32, key: &Key) -> Result<(), KernelError> {
        let n = self
            .hash
            .write()
            .remove(&(ifindex, *key))
            .ok_or(KernelError::NotFound)?;
        let act = {
            let mut i = n.inner.lock();
            i.dead = true;
            i.st.update(None, nud::FAILED, upd::ADMIN | upd::OVERRIDE, now_ms())
        };
        self.after(&n, act);
        Ok(())
    }

    /// Snapshot of all entries (dumps, /proc)
    pub fn dump(&self) -> Vec<NeighInfo> {
        let now = now_ms();
        self.hash
            .read()
            .values()
            .map(|n| {
                let s = n.inner.lock().st;
                NeighInfo {
                    key: n.key,
                    ifindex: n.dev.ifindex(),
                    dev: n.dev.clone(),
                    state: s.state,
                    ha: s.ha,
                    probes: s.probes,
                    confirmed: now.saturating_sub(s.confirmed),
                    used: now.saturating_sub(s.used),
                    updated: now.saturating_sub(s.updated),
                }
            })
            .collect()
    }
}

impl Neighbour {
    /// Take the queued packets
    fn take_queue(&self) -> VecDeque<(Box<SkBuff>, usize)> {
        let mut i = self.inner.lock();
        i.qbytes = 0;
        core::mem::take(&mut i.queue)
    }

    /// Current state (NUD_*)
    pub fn state(&self) -> u8 {
        self.inner.lock().st.state
    }

    /// Protocol address as IPv4 (first 4 key bytes)
    pub fn key4(&self) -> crate::net::Ipv4Addr {
        crate::net::Ipv4Addr::from_be_bytes([self.key[0], self.key[1], self.key[2], self.key[3]])
    }
}

/// Key of an IPv4 address
pub fn key4(a: crate::net::Ipv4Addr) -> Key {
    let mut k = [0u8; 16];
    k[..4].copy_from_slice(&a.to_be_bytes());
    k
}

/// Memory charged for a queued packet (data + overhead)
fn skb_truesize(skb: &SkBuff) -> usize {
    skb.len() + 256
}

// ============================================================================
// Timer (one for all tables)
// ============================================================================

/// Registered tables (pruned when their namespace goes away)
static TABLES: Mutex<Vec<Weak<NeighTable>>> = Mutex::new(Vec::new());

static ALARM: crate::timer::Alarm = crate::timer::Alarm::new(neigh_timer);

/// Make sure the neighbour timer fires no later than `at` (ms)
fn arm(at: u64) {
    ALARM.arm(at.saturating_mul(1_000_000));
}

/// Timer callback (ktimerd): run every table, re-arm for the earliest
/// deadline
fn neigh_timer(_: u64) {
    ALARM.fired();
    let tables: Vec<Arc<NeighTable>> = {
        let mut v = TABLES.lock();
        v.retain(|w| w.strong_count() > 0);
        v.iter().filter_map(|w| w.upgrade()).collect()
    };
    let now = now_ms();
    let next = tables.iter().filter_map(|t| t.run(now)).min();
    if let Some(at) = next {
        arm(at.max(now + 10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: Parms = Parms::DEFAULT;
    const MAC: Lladdr = [0x52, 0x55, 10, 0, 2, 2];

    fn fresh() -> NState {
        NState::new(100_000, 30_000)
    }

    /// Run the timer at its deadlines until it stops; returns the actions
    fn run(s: &mut NState, until: u64) -> Vec<(u64, Act)> {
        let mut out = Vec::new();
        while let Some(t) = s.timer {
            if t > until {
                break;
            }
            out.push((t, s.timer(&P, t)));
        }
        out
    }

    #[test]
    fn unanswered_fails_after_three_broadcasts() {
        let mut s = fresh();
        let (v, a) = s.event_send(&P, 100_000);
        assert_eq!(v, Send::Queue);
        assert_eq!(a, Act::Solicit(None));
        assert_eq!(s.state, nud::INCOMPLETE);
        let acts = run(&mut s, 200_000);
        assert_eq!(
            acts,
            [
                (101_000, Act::Solicit(None)),
                (102_000, Act::Solicit(None)),
                (103_000, Act::Fail)
            ]
        );
        assert_eq!(s.state, nud::FAILED);
        assert_eq!(s.timer, None);
        // A new packet restarts resolution
        assert_eq!(s.event_send(&P, 200_000).0, Send::Queue);
        assert_eq!(s.state, nud::INCOMPLETE);
    }

    #[test]
    fn reply_flushes_queue() {
        let mut s = fresh();
        s.event_send(&P, 100_000);
        assert_eq!(
            s.update(Some(MAC), nud::REACHABLE, 0, 100_200),
            Act::Flush(MAC)
        );
        assert_eq!(s.state, nud::REACHABLE);
        assert_eq!(s.event_send(&P, 100_300).0, Send::Now(MAC));
    }

    #[test]
    fn reachable_ages_to_stale_then_probes() {
        let mut s = fresh();
        s.update(Some(MAC), nud::REACHABLE, upd::OVERRIDE, 100_000);
        // Unused: REACHABLE -> STALE after the reachable time
        let acts = run(&mut s, 200_000);
        assert!(acts.iter().all(|&(t, a)| a == Act::None && t >= 130_000));
        assert_eq!(s.state, nud::STALE);
        assert_eq!(s.timer, None);
        // Use: STALE -> DELAY (sends now) -> PROBE (3 unicast) -> FAILED
        assert_eq!(s.event_send(&P, 140_000).0, Send::Now(MAC));
        assert_eq!(s.state, nud::DELAY);
        let acts = run(&mut s, 300_000);
        assert_eq!(
            acts,
            [
                (145_000, Act::Solicit(Some(MAC))),
                (146_000, Act::Solicit(Some(MAC))),
                (147_000, Act::Solicit(Some(MAC))),
                (148_000, Act::Fail)
            ]
        );
        assert_eq!(s.state, nud::FAILED);
    }

    #[test]
    fn delay_confirmed_returns_to_reachable() {
        let mut s = fresh();
        s.update(Some(MAC), nud::STALE, upd::OVERRIDE, 100_000);
        s.event_send(&P, 100_000);
        assert_eq!(s.state, nud::DELAY);
        // A reply confirms within the delay window
        s.update(Some(MAC), nud::REACHABLE, 0, 102_000);
        assert_eq!(s.state, nud::REACHABLE);
        assert!(s.timer.is_some());
    }

    #[test]
    fn address_change_needs_override() {
        let mut s = fresh();
        s.update(Some(MAC), nud::REACHABLE, upd::OVERRIDE, 100_000);
        let other = [2, 0, 0, 0, 0, 9];
        assert_eq!(s.update(Some(other), nud::REACHABLE, 0, 100_100), Act::None);
        assert_eq!(s.ha, MAC);
        s.update(Some(other), nud::REACHABLE, upd::OVERRIDE, 100_200);
        assert_eq!(s.ha, other);
    }

    #[test]
    fn permanent_is_sticky() {
        let mut s = fresh();
        s.update(Some(MAC), nud::PERMANENT, upd::ADMIN | upd::OVERRIDE, 1);
        assert_eq!(
            s.update(Some([1; 6]), nud::REACHABLE, upd::OVERRIDE, 2),
            Act::None
        );
        assert_eq!(s.state, nud::PERMANENT);
        assert!(!s.stale_gc(&P, u64::MAX / 2));
        assert!(!s.forced_gc(u64::MAX / 2));
        assert_eq!(s.event_send(&P, 3).0, Send::Now(MAC));
    }

    #[test]
    fn gc_rules() {
        let mut s = fresh();
        s.update(Some(MAC), nud::STALE, upd::OVERRIDE, 100_000);
        assert!(!s.stale_gc(&P, 120_000));
        assert!(s.stale_gc(&P, 100_000 + P.gc_stale));
        assert!(!s.forced_gc(101_000));
        assert!(s.forced_gc(106_000));
    }

    #[test]
    fn queue_is_byte_bounded() {
        let mut q = VecDeque::new();
        let mut bytes = 0;
        for i in 0..10u32 {
            let d = enqueue_bounded(&mut q, &mut bytes, i, 300, 1000);
            if i >= 3 {
                assert_eq!(d, [i - 3]);
            }
        }
        assert_eq!(q.len(), 3);
        assert_eq!(bytes, 900);
        assert_eq!(q.front().unwrap().0, 7);
    }
}
