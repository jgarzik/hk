//! Generic neighbour subsystem (Linux net/core/neighbour.c)
//!
//! A `NeighTable` (Linux struct neigh_table, one per address family for
//! every namespace: `arp::arp_tbl`) maps (device, protocol address) to a
//! link-layer address with the Linux NUD state machine. Protocols plug
//! in through `NeighOps` (bucket hash, solicit, transmit with a
//! resolved address, report an undeliverable packet): ARP is the first
//! user; IPv6 neighbour discovery adds a second table with 16-byte keys.
//!
//! The state machine itself (`NState`) is pure (time in ms is passed in)
//! and unit-tested; the table wraps it with entries, per-entry timers,
//! bounded queues of packets waiting for resolution (`arp_queue`,
//! unres_qlen_bytes) and garbage collection (`gc_thresh1/2/3`).
//!
//! ## Structure (Linux's)
//!
//! - The hash is an RCU-published `NeighHash` of `RcuHList` chains
//!   (Linux tbl->nht, hash_heads): lookups walk a chain under
//!   `rcu::read_lock` and take a reference, allocating nothing. It
//!   doubles once entries outnumber its buckets (neigh_hash_grow,
//!   GFP_ATOMIC under the table lock; on failure the old one stays);
//!   the old table is freed after a grace period.
//! - An entry is allocated before the table lock is taken (neigh_alloc,
//!   GFP_ATOMIC: it is created from the receive and output paths), then
//!   hashed, put on its device's list (`NetDevice.neighbours`, Linux
//!   dev->neighbours) and, unless exempt (PERMANENT, loopback), on the
//!   table's gc list. All three hold a reference; an entry referenced
//!   only by them is "unused" (Linux refcnt == 1).
//! - Each entry has its own timer (`ArcTimer`, Linux neigh->timer with
//!   neigh_hold per arm), armed and deleted under the entry's lock.
//! - A per-table delayed work (neigh_periodic_work, every
//!   BASE_REACHABLE/2) frees stale unused entries; neigh_alloc runs a
//!   forced GC over the gc list when the table passes gc_thresh2/3.
//! - Dumps and /proc/net/arp walk the table under RCU into
//!   preallocated buffers (`NlBuf`, `SeqBuf`).
//!
//! ## Locking (thread context only; see doc/LOCKING.md)
//!
//! `NeighTable.lock` (`TblLocked`, Linux tbl->lock) -> `Neighbour.inner`
//! (Linux neigh->lock) -> the timer base (an `ArcTimer` armed or deleted
//! under `inner`). The table lock serializes the hash chains, the gc
//! list and every device's list (their writers borrow `TblLocked`). No
//! packet is transmitted, solicited or reported under either lock:
//! state changes return actions that run after the unlock.

use crate::util::kalloc::{try_arc_gfp, with_gfp};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};

use crate::mm::page_alloc::Gfp;
use crate::sync::rcu::{self, RcuArc, RcuHead, RcuReadGuard};
use crate::sync::spin::Mutex;
use crate::sync::{IrqSpinlock, UniqueOwner};
use crate::task::workqueue::{DelayedWork, SYSTEM_WQ};
use crate::time::timer::ArcTimer;
use crate::util::list::{Link, OwnedList, Owner};
use crate::util::rculist::{RcuHList, RcuRef};

use crate::net::device::NetDevice;
use crate::net::skb::{SkBuff, SkbHead};
use crate::util::error::KernelError;

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
        self.timer = (self.state & nud::IN_TIMER != 0).then(|| next.max(now + 10));
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

// ============================================================================
// Table
// ============================================================================

/// Random words of a hash table (Linux NEIGH_NUM_HASH_RND)
pub const HASH_RND: usize = 4;

/// Protocol hooks (Linux neigh_ops + the table's constructor bits)
pub struct NeighOps {
    /// Address family (AF_INET, AF_INET6)
    pub family: u8,
    /// Bytes of `Key` used
    pub key_len: usize,
    /// Bucket hash of `key` on `dev` (Linux neigh_table.hash); the top
    /// bits pick the bucket
    pub hash: fn(key: &Key, dev: &NetDevice, rnd: &[u32; HASH_RND]) -> u32,
    /// Send a solicitation for `n`: unicast to `dst` or broadcast;
    /// `hint` is the source address of the newest queued packet (source
    /// address choice, Linux arp_solicit)
    pub solicit: fn(n: &Neighbour, dst: Option<Lladdr>, hint: Option<Key>),
    /// Transmit `skb` (network header first) to link address `ha`
    pub output: fn(skb: Box<SkBuff>, ha: Lladdr) -> Result<(), KernelError>,
    /// A queued packet could not be delivered (resolution failed)
    pub error_report: fn(skb: Box<SkBuff>),
}

/// Entry state + queue (under `Neighbour.inner`, Linux neigh->lock)
struct Inner {
    st: NState,
    /// Packets waiting for resolution (Linux arp_queue)
    arp_queue: SkbHead<Box<SkBuff>>,
    /// Their truesize (Linux arp_queue_len_bytes)
    arp_queue_len_bytes: usize,
    /// Off the table (Linux neigh->dead)
    dead: bool,
}

impl Inner {
    /// Queue `skb` behind the others, dropping the oldest while the
    /// queue would pass `limit` bytes (Linux __neigh_event_send's
    /// QUEUE_LEN_BYTES loop); the dropped packets come back, to free
    /// after the unlock
    fn enqueue(&mut self, skb: Box<SkBuff>, limit: usize) -> SkbHead<Box<SkBuff>> {
        let mut dropped = SkbHead::new();
        let size = skb.truesize();
        while self.arp_queue_len_bytes + size > limit {
            let Some(old) = self.arp_queue.pop_front() else {
                break;
            };
            self.arp_queue_len_bytes -= old.truesize();
            dropped.push_back(old);
        }
        self.arp_queue.push_back(skb);
        self.arp_queue_len_bytes += size;
        dropped
    }

    /// Take the queued packets (Linux __skb_queue_purge's list, or the
    /// flush of a resolved entry)
    fn take_queue(&mut self) -> SkbHead<Box<SkBuff>> {
        self.arp_queue_len_bytes = 0;
        core::mem::take(&mut self.arp_queue)
    }
}

/// A neighbour entry (Linux struct neighbour)
pub struct Neighbour {
    /// On its bucket's chain (Linux neigh->hash)
    hash: Link,
    /// On its device's list (Linux neigh->dev_list)
    dev_list: Link,
    dev_owner: Owner,
    /// On the table's gc list (Linux neigh->gc_list)
    gc_list: Link,
    gc_owner: Owner,
    /// Freed a grace period after it leaves the hash (Linux neigh->rcu)
    rcu: RcuHead,
    /// Its state machine's timer (Linux neigh->timer): a pending arm
    /// holds a reference
    timer: ArcTimer<Neighbour>,
    tbl: &'static NeighTable,
    pub key: Key,
    pub dev: Arc<NetDevice>,
    inner: Mutex<Inner>,
}

crate::adapter!(NeighHashLink, Neighbour, hash);
crate::owned_adapter!(pub NeighDevLink, Neighbour, dev_list, dev_owner);
crate::owned_adapter!(NeighGcLink, Neighbour, gc_list, gc_owner);
crate::rcu_head!(Neighbour, rcu);

impl Drop for Neighbour {
    /// Linux neigh_destroy: the queue goes with it
    fn drop(&mut self) {
        self.tbl.entries.fetch_sub(1, Relaxed);
    }
}

/// An entry's state for dumps and /proc (Linux __neigh_fill_info under
/// neigh->lock)
#[derive(Clone, Copy)]
pub struct NeighInfo {
    pub key: Key,
    pub ifindex: u32,
    pub state: u8,
    pub ha: Lladdr,
    pub probes: u32,
    /// Ages in ms
    pub confirmed: u64,
    pub used: u64,
    pub updated: u64,
}

/// The data of a table's lock (Linux tbl->lock): the gc list, and the
/// proof its holder writes the hash chains and the devices' lists
///
/// # Invariants
/// One value exists: `NeighTable::new` makes it, once (`MADE`).
pub struct TblLocked {
    /// Entries GC may free, oldest first (Linux tbl->gc_list)
    gc_list: OwnedList<NeighGcLink>,
}

// SAFETY: one value exists (type invariant), reachable only through
// its table's lock
unsafe impl UniqueOwner for TblLocked {}

/// A table was made (one table, ARP, exists; IPv6 neighbour discovery
/// gives its table an owner type of its own)
static MADE: AtomicBool = AtomicBool::new(false);

/// The devices' lists of entries, owned by the table lock
pub type DevNeighbours = crate::sync::LockedBy<OwnedList<NeighDevLink>, TblLocked>;

/// An empty device list (`NetDevice::new`)
pub fn dev_neighbours() -> DevNeighbours {
    crate::sync::LockedBy::new(OwnedList::new())
}

/// The hash chains (Linux struct neigh_hash_table)
struct NeighHash {
    heads: Box<[RcuHList<NeighHashLink, TblLocked>]>,
    shift: u32,
    rnd: [u32; HASH_RND],
    rcu: RcuHead,
}

crate::rcu_head!(NeighHash, rcu);

impl NeighHash {
    /// 2^`shift` empty chains with fresh random words (Linux
    /// neigh_hash_alloc: GFP_ATOMIC, it grows under the table lock)
    fn alloc(shift: u32) -> Result<Arc<Self>, KernelError> {
        with_gfp(Gfp::ATOMIC, || {
            let n = 1usize << shift;
            let mut v = Vec::new();
            v.try_reserve_exact(n)
                .map_err(|_| KernelError::OutOfMemory)?;
            v.extend((0..n).map(|_| RcuHList::new()));
            // Linux neigh_get_hash_rnd: odd
            let rnd = core::array::from_fn(|_| crate::random::get_random_u32() | 1);
            try_arc_gfp(
                Self {
                    heads: v.into_boxed_slice(),
                    shift,
                    rnd,
                    rcu: RcuHead::new(),
                },
                Gfp::ATOMIC,
            )
        })
    }

    /// The chain of `key` on `dev`
    fn bucket(
        &self,
        ops: &NeighOps,
        key: &Key,
        dev: &NetDevice,
    ) -> &RcuHList<NeighHashLink, TblLocked> {
        let h = (ops.hash)(key, dev, &self.rnd) >> (32 - self.shift);
        &self.heads[h as usize]
    }
}

/// A neighbour table (Linux struct neigh_table), one per family
pub struct NeighTable {
    pub ops: &'static NeighOps,
    pub parms: Parms,
    /// Linux tbl->lock
    lock: Mutex<TblLocked>,
    /// Linux tbl->nht: replaced under `lock`
    nht: RcuArc<NeighHash>,
    /// Allocated entries (Linux atomic tbl->entries: neigh_alloc and
    /// neigh_destroy count them without the lock)
    entries: AtomicUsize,
    /// Entries on the gc list or being created onto it (Linux atomic
    /// tbl->gc_entries, raised by neigh_alloc before the lock)
    gc_entries: AtomicUsize,
    /// Last forced GC, ms (Linux tbl->last_flush, READ_ONCE)
    last_flush: AtomicU64,
    /// neigh_periodic_work (Linux tbl->gc_work), set by `start`
    gc_work: spin::Once<Arc<IrqSpinlock<DelayedWork>>>,
}

/// Milliseconds on the monotonic clock
pub fn now_ms() -> u64 {
    crate::time::monotonic_ns() / 1_000_000
}

/// Linux neigh_rand_reach_time: uniform in [base/2, 3*base/2)
fn rand_reach(base: u64) -> u64 {
    base / 2 + u64::from(crate::random::get_random_u32()) % base.max(1)
}

/// `n`'s timer armed for its state machine's deadline, or deleted
/// (Linux neigh_add_timer / neigh_del_timer under neigh->lock)
fn sync_timer(n: &Arc<Neighbour>, st: &NState) {
    match st.timer {
        Some(t) => {
            n.timer.reset(n, t.saturating_mul(1_000_000));
        }
        None => {
            n.timer.stop();
        }
    }
}

impl NeighTable {
    /// The table, with its first hash of 8 chains (Linux
    /// neigh_table_init; boot, so it cannot fail). Panics if a table
    /// exists already (`TblLocked` is unique).
    pub fn new(ops: &'static NeighOps) -> Self {
        assert!(!MADE.swap(true, Relaxed), "neigh: one table only");
        let nht = NeighHash::alloc(3).expect("neigh: no memory at boot");
        Self {
            ops,
            parms: Parms::DEFAULT,
            // INVARIANT: the one value (MADE)
            lock: Mutex::new(TblLocked {
                gc_list: OwnedList::new(),
            }),
            nht: RcuArc::new(nht),
            entries: AtomicUsize::new(0),
            gc_entries: AtomicUsize::new(0),
            last_flush: AtomicU64::new(0),
            gc_work: spin::Once::new(),
        }
    }

    /// Start periodic GC (Linux neigh_table_init's first
    /// queue_delayed_work of gc_work)
    pub fn start(&'static self) {
        let w = self.gc_work.call_once(|| {
            crate::util::kalloc::arc_nofail(IrqSpinlock::new(DelayedWork::new(move || {
                self.periodic_work();
            })))
        });
        SYSTEM_WQ.queue_delayed_work(w.clone(), self.gc_delay());
    }

    /// Every BASE_REACHABLE/2 (Linux neigh_periodic_work's re-queue)
    fn gc_delay(&self) -> u64 {
        crate::task::percpu::ms_to_ticks(self.parms.base_reachable / 2)
    }

    /// Allocated entries (Linux tbl->entries)
    pub fn len(&self) -> usize {
        self.entries.load(Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The entry for `key` on `dev`, under `g` (Linux
    /// __neigh_lookup_noref)
    fn lookup_rcu<'a>(
        &'a self,
        g: &'a RcuReadGuard,
        dev: &NetDevice,
        key: &Key,
    ) -> Option<RcuRef<'a, Neighbour>> {
        let nht = self.nht.read(g);
        nht.bucket(self.ops, key, dev)
            .iter_ref(g)
            .find(|n| core::ptr::eq(Arc::as_ptr(&n.dev), dev) && n.key == *key)
    }

    /// The entry for `key` on `dev` (Linux neigh_lookup): an RCU walk
    /// and a reference, no lock
    pub fn lookup(&self, dev: &NetDevice, key: &Key) -> Option<Arc<Neighbour>> {
        let g = rcu::read_lock();
        self.lookup_rcu(&g, dev, key).map(RcuRef::get)
    }

    /// The entry for `key` on `dev`, created NONE if there is none
    /// (Linux __neigh_lookup with creat): ENOBUFS when the table is
    /// full even after forced GC or the entry cannot be allocated.
    /// `exempt`: never collected (Linux exempt_from_gc: PERMANENT,
    /// loopback).
    pub fn create(
        &'static self,
        dev: &Arc<NetDevice>,
        key: &Key,
        exempt: bool,
    ) -> Result<Arc<Neighbour>, KernelError> {
        if let Some(n) = self.lookup(dev, key) {
            return Ok(n);
        }
        let n = self.alloc(dev, key, exempt)?;
        let (r, lost) = self.insert(n, exempt);
        // A losing entry's last reference, after the unlock
        drop(lost);
        r
    }

    /// Linux neigh_alloc: the GC trigger, then the entry (GFP_ATOMIC),
    /// before the table lock
    fn alloc(
        &'static self,
        dev: &Arc<NetDevice>,
        key: &Key,
        exempt: bool,
    ) -> Result<Arc<Neighbour>, KernelError> {
        let p = &self.parms;
        let now = now_ms();
        if !exempt {
            let entries = self.gc_entries.fetch_add(1, Relaxed);
            let last = self.last_flush.load(Relaxed);
            if (entries >= p.gc_thresh3 || (entries >= p.gc_thresh2 && now > last + 5000))
                && self.forced_gc() == 0
                && entries >= p.gc_thresh3
            {
                // Linux net_info_ratelimited "neighbor table overflow!"
                self.gc_entries.fetch_sub(1, Relaxed);
                return Err(KernelError::NoBufferSpace);
            }
        }
        // Counted first: a failed allocation drops the entry, whose
        // drop uncounts it
        self.entries.fetch_add(1, Relaxed);
        let n = try_arc_gfp(
            Neighbour {
                hash: Link::new(),
                dev_list: Link::new(),
                dev_owner: Owner::new(),
                gc_list: Link::new(),
                gc_owner: Owner::new(),
                rcu: RcuHead::new(),
                timer: ArcTimer::new(neigh_timer_handler),
                tbl: self,
                key: *key,
                dev: dev.clone(),
                inner: Mutex::new(Inner {
                    st: NState::new(now, rand_reach(p.base_reachable)),
                    arp_queue: SkbHead::new(),
                    arp_queue_len_bytes: 0,
                    dead: true,
                }),
            },
            Gfp::ATOMIC,
        );
        n.map_err(|_| {
            if !exempt {
                self.gc_entries.fetch_sub(1, Relaxed);
            }
            KernelError::NoBufferSpace
        })
    }

    /// Hash a new entry (the rest of Linux ___neigh_create), growing
    /// the hash first if it is full; an entry another caller hashed
    /// meanwhile wins, and the new one comes back to drop after the
    /// unlock
    fn insert(
        &self,
        n: Arc<Neighbour>,
        exempt: bool,
    ) -> (Result<Arc<Neighbour>, KernelError>, Option<Arc<Neighbour>>) {
        let mut o = self.lock.lock();
        let g = rcu::read_lock();
        let nht = self.nht.read(&g);
        if self.entries.load(Relaxed) > nht.heads.len() {
            self.grow(&mut o, nht);
        }
        let nht = self.nht.read(&g);
        let unwind = |r| {
            if !exempt {
                self.gc_entries.fetch_sub(1, Relaxed);
            }
            (r, Some(n.clone()))
        };
        // An unregistered device's entries were flushed after it was
        // marked gone: none is added again (Linux parms->dead)
        if n.dev.is_gone() {
            return unwind(Err(KernelError::NoDevice));
        }
        let b = nht.bucket(self.ops, &n.key, &n.dev);
        if let Some(n1) = b
            .iter_locked(&o)
            .find(|x| Arc::ptr_eq(&x.dev, &n.dev) && x.key == n.key)
        {
            let n1 = n1.get();
            return unwind(Ok(n1));
        }
        n.inner.lock().dead = false;
        if !exempt {
            o.gc_list.push_back(n.clone());
        }
        b.push_front(n.clone(), &mut o);
        n.dev.neighbours.access_mut(&mut o).push_back(n.clone());
        (Ok(n), None)
    }

    /// Double the hash, moving every entry (Linux neigh_hash_grow);
    /// on allocation failure the old one stays
    fn grow(&self, o: &mut TblLocked, old: &NeighHash) {
        let Ok(new) = NeighHash::alloc(old.shift + 1) else {
            return;
        };
        for head in old.heads.iter() {
            head.move_all(|n| new.bucket(self.ops, &n.key, &n.dev), o);
        }
        // Freed after readers of the old chains are done (Linux
        // call_rcu(neigh_hash_free_rcu))
        self.nht.replace(new).defer();
    }

    /// Only the table references `n` besides `extra` references the
    /// caller holds (Linux refcount_read(&n->refcnt) == 1): its hash
    /// chain, its device's list and, if on it, the gc list
    fn unused(o: &TblLocked, n: &Arc<Neighbour>, extra: usize) -> bool {
        Arc::strong_count(n) == 2 + usize::from(o.gc_list.contains(n)) + extra
    }

    /// Take `n` off the gc list, mark it dead (Linux neigh_mark_dead)
    fn mark_dead(&self, o: &mut TblLocked, n: &Neighbour, i: &mut Inner) {
        i.dead = true;
        if o.gc_list.remove(n).is_some() {
            self.gc_entries.fetch_sub(1, Relaxed);
        }
    }

    /// Unhash `n` and take it off its device's list (Linux
    /// hlist_del_rcu of hash and dev_list), mark it dead; the hash's
    /// reference goes a grace period later (neigh_cleanup_and_release)
    fn unlink(&self, o: &mut TblLocked, nht: &NeighHash, n: &Neighbour, i: &mut Inner) {
        let b = nht.bucket(self.ops, &n.key, &n.dev);
        if let Some(u) = b.remove_first(|x| core::ptr::eq(x, n), o) {
            u.defer();
        }
        drop(n.dev.neighbours.access_mut(o).remove(n));
        self.mark_dead(o, n, i);
    }

    /// Free unused entries from the front of the gc list, down to
    /// gc_thresh2: failed, NOARP or not updated for 5 s (Linux
    /// neigh_forced_gc, at most a millisecond's work); how many went
    fn forced_gc(&self) -> usize {
        let max_clean = self.gc_entries.load(Relaxed) as i64 - self.parms.gc_thresh2 as i64;
        let tmax = crate::time::monotonic_ns() + 1_000_000;
        let now = now_ms();
        let (mut shrunk, mut loops) = (0usize, 0);
        let mut o = self.lock.lock();
        let g = rcu::read_lock();
        let nht = self.nht.read(&g);
        let mut cur = o.gc_list.front();
        while let Some(n) = cur {
            cur = o.gc_list.next(&n);
            // `n` is one reference of ours
            if !Self::unused(&o, &n, 1) {
                continue;
            }
            let mut i = n.inner.lock();
            if i.st.forced_gc(now) {
                self.unlink(&mut o, nht, &n, &mut i);
                shrunk += 1;
            }
            drop(i);
            if shrunk as i64 >= max_clean {
                break;
            }
            loops += 1;
            if loops == 16 {
                if crate::time::monotonic_ns() > tmax {
                    return shrunk;
                }
                loops = 0;
            }
        }
        self.last_flush.store(now, Relaxed);
        shrunk
    }

    /// Linux neigh_periodic_work: above gc_thresh1, free unused entries
    /// out of their timers that failed or went unused for gc_stale,
    /// one chain per lock hold; then run again in BASE_REACHABLE/2
    fn periodic_work(&'static self) {
        let now = now_ms();
        let mut o = self.lock.lock();
        if self.len() >= self.parms.gc_thresh1 {
            let mut b = 0;
            loop {
                {
                    let g = rcu::read_lock();
                    let nht = self.nht.read(&g);
                    let Some(head) = nht.heads.get(b) else {
                        break;
                    };
                    while let Some(n) = self.stale(&o, head, now) {
                        let mut i = n.inner.lock();
                        // Rechecked under its lock: a user may have come
                        if !Self::unused(&o, &n, 1) || !i.st.stale_gc(&self.parms, now) {
                            break;
                        }
                        self.unlink(&mut o, nht, &n, &mut i);
                    }
                }
                // The lock may go between chains even if the hash grows
                // meanwhile (Linux's cond_resched there)
                drop(o);
                o = self.lock.lock();
                b += 1;
            }
        }
        if let Some(w) = self.gc_work.get() {
            SYSTEM_WQ.queue_delayed_work(w.clone(), self.gc_delay());
        }
    }

    /// The first unused, stale entry of `head` (Linux
    /// neigh_periodic_work's test, `used` caught up with `confirmed`
    /// on the way)
    fn stale(
        &self,
        o: &TblLocked,
        head: &RcuHList<NeighHashLink, TblLocked>,
        now: u64,
    ) -> Option<Arc<Neighbour>> {
        head.iter_locked(o).map(RcuRef::get).find(|n| {
            let mut i = n.inner.lock();
            let st = &mut i.st;
            if st.used < st.confirmed && st.confirmed <= now {
                st.used = st.confirmed;
            }
            Self::unused(o, n, 1) && st.stale_gc(&self.parms, now)
        })
    }

    /// Transmit `skb` via `n` (Linux neigh_resolve_output +
    /// __neigh_event_send): now if the address is usable, else queued
    /// (bounded) while resolving
    pub fn output(&self, n: &Arc<Neighbour>, skb: Box<SkBuff>) -> Result<(), KernelError> {
        let mut i = n.inner.lock();
        if i.dead {
            return Err(KernelError::HostUnreachable);
        }
        let deadline = i.st.timer;
        let (verdict, act) = i.st.event_send(&self.parms, now_ms());
        // The fast path leaves the timer alone (Linux touches it only
        // in the slow states)
        if i.st.timer != deadline {
            sync_timer(n, &i.st);
        }
        match verdict {
            Send::Now(ha) => {
                drop(i);
                self.after(n, act);
                (self.ops.output)(skb, ha)
            }
            Send::Drop => Err(KernelError::HostUnreachable),
            Send::Queue => {
                let dropped = i.enqueue(skb, self.parms.queue_bytes);
                drop(i);
                drop(dropped);
                self.after(n, act);
                Ok(())
            }
        }
    }

    /// Run an action after `inner` was released
    fn after(&self, n: &Arc<Neighbour>, act: Act) {
        match act {
            Act::None => {}
            Act::Solicit(dst) => {
                // Linux neigh_probe: the newest queued packet's source
                let hint = n.inner.lock().arp_queue.back().and_then(|s| s.saddr);
                (self.ops.solicit)(n, dst, hint.map(key4));
            }
            Act::Flush(ha) => {
                let mut q = n.inner.lock().take_queue();
                while let Some(skb) = q.pop_front() {
                    let _ = (self.ops.output)(skb, ha);
                }
            }
            Act::Fail => {
                let mut q = n.inner.lock().take_queue();
                while let Some(skb) = q.pop_front() {
                    (self.ops.error_report)(skb);
                }
            }
        }
    }

    /// New information about `n` (Linux neigh_update); a dead entry
    /// changes no more
    pub fn update(&self, n: &Arc<Neighbour>, ll: Option<Lladdr>, new: u8, flags: u32) {
        let (act, gc) = {
            let mut i = n.inner.lock();
            if i.dead {
                return;
            }
            let old = i.st.state;
            let act = i.st.update(ll, new, flags, now_ms());
            sync_timer(n, &i.st);
            (act, (old ^ i.st.state) & nud::PERMANENT != 0)
        };
        if gc {
            self.update_gc_list(n);
        }
        self.after(n, act);
    }

    /// A PERMANENT entry leaves the gc list, another joins it at the
    /// tail (Linux neigh_update_gc_list)
    fn update_gc_list(&self, n: &Arc<Neighbour>) {
        let mut o = self.lock.lock();
        let i = n.inner.lock();
        if i.dead {
            return;
        }
        let exempt = i.st.state & nud::PERMANENT != 0;
        let on = o.gc_list.contains(n);
        if exempt && on {
            drop(o.gc_list.remove(n));
            self.gc_entries.fetch_sub(1, Relaxed);
        } else if !exempt && !on {
            o.gc_list.push_back(n.clone());
            self.gc_entries.fetch_add(1, Relaxed);
        }
    }

    /// Whether a new address for `n` may override the cached one now
    /// (Linux arp_process: after `locktime` since the last update)
    pub fn may_override(&self, n: &Neighbour) -> bool {
        now_ms() > n.inner.lock().st.updated + self.parms.locktime
    }

    /// Take `n` off the table for good (Linux neigh_flush_one): its
    /// timer stops and its queue goes; a user still holding it finds it
    /// dead, NOARP if its address was valid, else NONE
    fn flush_one(&self, o: &mut TblLocked, nht: &NeighHash, n: &Arc<Neighbour>) {
        let mut i = n.inner.lock();
        self.unlink(o, nht, n, &mut i);
        n.timer.stop();
        i.st.timer = None;
        let q = i.take_queue();
        i.st.state = if i.st.state & nud::VALID != 0 {
            nud::NOARP
        } else {
            nud::NONE
        };
        drop(i);
        drop(q);
    }

    /// Forget every entry of a device going down, dropping queued
    /// packets (Linux neigh_ifdown -> neigh_flush_dev)
    pub fn flush_dev(&self, dev: &NetDevice) {
        let mut o = self.lock.lock();
        let g = rcu::read_lock();
        let nht = self.nht.read(&g);
        while let Some(n) = dev.neighbours.access(&o).front() {
            self.flush_one(&mut o, nht, &n);
        }
    }

    /// Administrative add/replace (RTM_NEWNEIGH with netlink flags
    /// `nlflags`; Linux neigh_add): EEXIST with NLM_F_EXCL, ENOENT
    /// without NLM_F_CREATE for a missing entry; an existing entry's
    /// address changes only with NLM_F_REPLACE. A PERMANENT entry is
    /// never collected.
    pub fn admin_add(
        &'static self,
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
        let (n, new) = match self.lookup(dev, key) {
            Some(_) if excl => return Err(KernelError::AlreadyExists),
            Some(n) => (n, false),
            None if !create => return Err(KernelError::NotFound),
            None => (self.create(dev, key, state & nud::PERMANENT != 0)?, true),
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

    /// Administrative delete (RTM_DELNEIGH; Linux neigh_delete):
    /// ENOENT if absent. The entry fails, then leaves the table unless
    /// someone still uses it (then GC frees it later).
    pub fn admin_del(&self, dev: &NetDevice, key: &Key) -> Result<(), KernelError> {
        let n = self.lookup(dev, key).ok_or(KernelError::NotFound)?;
        self.update(&n, None, nud::FAILED, upd::ADMIN | upd::OVERRIDE);
        // Linux neigh_release + neigh_remove_one under tbl->lock
        let mut o = self.lock.lock();
        let g = rcu::read_lock();
        let nht = self.nht.read(&g);
        let mut i = n.inner.lock();
        if !i.dead && Self::unused(&o, &n, 1) {
            self.unlink(&mut o, nht, &n, &mut i);
        }
        Ok(())
    }

    /// Every entry, while `g` is held (Linux neigh_dump_table and
    /// neigh_seq walk the buckets under RCU); callers filter by
    /// namespace
    pub fn iter_rcu<'a>(&'a self, g: &'a RcuReadGuard) -> impl Iterator<Item = &'a Neighbour> + 'a {
        self.nht.read(g).heads.iter().flat_map(move |b| b.iter(g))
    }

    /// The entry for `key` on `dev`, as dumps report it
    pub fn info(&self, dev: &NetDevice, key: &Key) -> Option<NeighInfo> {
        let g = rcu::read_lock();
        self.lookup_rcu(&g, dev, key).map(|n| n.info(now_ms()))
    }
}

/// `n`'s timer expired (Linux neigh_timer_handler, ktimers/N): the
/// state machine's step, the timer re-armed under the entry's lock,
/// the probe or failure report after it
fn neigh_timer_handler(n: Arc<Neighbour>) {
    let tbl = n.tbl;
    let act = {
        let mut i = n.inner.lock();
        if i.dead {
            return;
        }
        let act = i.st.timer(&tbl.parms, now_ms());
        sync_timer(&n, &i.st);
        act
    };
    tbl.after(&n, act);
}

impl Neighbour {
    /// Current state (NUD_*)
    pub fn state(&self) -> u8 {
        self.inner.lock().st.state
    }

    /// Its state for a dump at `now` (ms)
    pub fn info(&self, now: u64) -> NeighInfo {
        let s = self.inner.lock().st;
        NeighInfo {
            key: self.key,
            ifindex: self.dev.ifindex(),
            state: s.state,
            ha: s.ha,
            probes: s.probes,
            confirmed: now.saturating_sub(s.confirmed),
            used: now.saturating_sub(s.used),
            updated: now.saturating_sub(s.updated),
        }
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

    fn skb(n: usize) -> Box<SkBuff> {
        let mut s = SkBuff::alloc(0, n, Gfp::KERNEL).unwrap();
        s.put(n).unwrap();
        s
    }

    /// The queue keeps the newest packets within its byte limit (Linux
    /// QUEUE_LEN_BYTES), dropping from the front
    #[test]
    fn arp_queue_is_byte_bounded() {
        let mut i = Inner {
            st: fresh(),
            arp_queue: SkbHead::new(),
            arp_queue_len_bytes: 0,
            dead: false,
        };
        let size = skb(100).truesize();
        let limit = 3 * size + size / 2;
        for n in 0..10 {
            let d = i.enqueue(skb(100), limit);
            assert_eq!(d.len(), usize::from(n >= 3));
        }
        assert_eq!(i.arp_queue.len(), 3);
        assert_eq!(i.arp_queue_len_bytes, 3 * size);
        // A packet larger than the limit still goes in, alone
        let big = skb(4000);
        let bs = big.truesize();
        assert_eq!(i.enqueue(big, bs - 1).len(), 3);
        assert_eq!(i.arp_queue_len_bytes, bs);
        assert_eq!(i.take_queue().len(), 1);
        assert_eq!(i.arp_queue_len_bytes, 0);
    }
}
