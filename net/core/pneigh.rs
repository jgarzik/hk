//! Proxy neighbour entries (Linux net/core/neighbour.c pneigh_*)
//!
//! A table's proxy entries say which protocol addresses this host
//! answers for on behalf of others (Linux `ip neigh add proxy`): a key,
//! the device it is answered on (None: any), the namespace, and the
//! flags and protocol netlink reports. ARP's proxy branch looks them up
//! (`arp_process` -> [`PneighTable::lookup`]); netlink creates, deletes
//! and dumps them through [`PneighTable::create`],
//! [`PneighTable::delete`] and [`PneighTable::for_each`].
//!
//! Locking (Linux tbl->phash_lock, a mutex; RCU readers): writers hold
//! `PneighTable.lock` (sleeping, thread context; allocation GFP_KERNEL
//! under it, as Linux), readers walk the 16 chains under
//! `rcu::read_lock`. An entry taken off is freed a grace period later
//! with its device reference (pneigh_destroy).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering::Relaxed};

use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::neigh::Key;
use crate::sync::rcu::{self, RcuHead, RcuReadGuard};
use crate::sync::{Mutex, UniqueOwner};
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;
use crate::util::rcuhlist::{HNode, RcuHList};

/// Chains of a table (Linux PNEIGH_HASHMASK + 1)
const PNEIGH_BUCKETS: usize = 16;

/// A proxy entry (Linux struct pneigh_entry)
pub struct PneighEntry {
    hash: HNode,
    rcu: RcuHead,
    /// Its namespace's id (Linux possible_net_t)
    net_id: u64,
    /// The device it answers on; None for any (Linux n->dev, held)
    pub dev: Option<Arc<NetDevice>>,
    pub key: Key,
    /// NTF_* flags and RTPROT_* protocol (Linux WRITE_ONCE under the
    /// lock, READ_ONCE by dumps)
    flags: AtomicU32,
    protocol: AtomicU8,
    /// Kept across a carrier loss (Linux n->permanent)
    permanent: AtomicBool,
}

crate::hadapter!(PneighLink, PneighEntry, hash);
crate::rcu_head!(PneighEntry, rcu);

impl PneighEntry {
    pub fn flags(&self) -> u32 {
        self.flags.load(Relaxed)
    }

    pub fn protocol(&self) -> u8 {
        self.protocol.load(Relaxed)
    }

    /// The interface index it answers on (0: any)
    pub fn ifindex(&self) -> u32 {
        self.dev.as_ref().map_or(0, |d| d.ifindex())
    }

    fn is(&self, net: &NetNamespace, key: &Key) -> bool {
        self.net_id == net.id && self.key == *key
    }
}

/// The data of a table's proxy lock (Linux tbl->phash_lock): the proof
/// its holder writes the chains
///
/// # Invariants
/// One value exists: `PneighTable::new` makes it, once (`MADE`).
pub struct PhashLocked(());

// SAFETY: one value exists (type invariant), reachable only through its
// table's lock
unsafe impl UniqueOwner for PhashLocked {}

/// A proxy table was made (ARP's; IPv6 neighbour discovery gives its
/// own an owner type of its own)
static MADE: AtomicBool = AtomicBool::new(false);

/// A table's proxy entries (Linux tbl->phash_buckets)
pub struct PneighTable {
    lock: Mutex<PhashLocked>,
    heads: [RcuHList<PneighLink, PhashLocked>; PNEIGH_BUCKETS],
    key_len: usize,
}

/// Linux pneigh_hash: the key's last word folded to 4 bits
fn pneigh_hash(key: &Key, key_len: usize) -> usize {
    let w = &key[key_len - 4..key_len];
    let mut h = u32::from_ne_bytes([w[0], w[1], w[2], w[3]]);
    h ^= h >> 16;
    h ^= h >> 8;
    h ^= h >> 4;
    (h as usize) & (PNEIGH_BUCKETS - 1)
}

impl PneighTable {
    /// Empty chains for keys of `key_len` bytes (Linux
    /// neigh_table_init's phash_buckets); panics if one exists already
    pub fn new(key_len: usize) -> Self {
        assert!(!MADE.swap(true, Relaxed), "pneigh: one table only");
        Self {
            // INVARIANT: the one value (MADE)
            lock: Mutex::new(PhashLocked(())),
            heads: [const { RcuHList::new() }; PNEIGH_BUCKETS],
            key_len,
        }
    }

    fn chain(&self, key: &Key) -> &RcuHList<PneighLink, PhashLocked> {
        &self.heads[pneigh_hash(key, self.key_len)]
    }

    /// An entry for `key` in `net` answering on `dev` or on any device
    /// (Linux pneigh_lookup, under RCU)
    pub fn lookup(&self, net: &NetNamespace, key: &Key, dev: &NetDevice) -> bool {
        let g = rcu::read_lock();
        self.chain(key)
            .iter(&g)
            .any(|n| n.is(net, key) && n.dev.as_deref().is_none_or(|d| core::ptr::eq(d, dev)))
    }

    /// Add or update the entry for `key` on `dev` (None: any) in `net`
    /// (Linux pneigh_create): its flags, its permanence and, if
    /// nonzero, its protocol; ENOBUFS without memory. Sleeps.
    pub fn create(
        &self,
        net: &NetNamespace,
        key: &Key,
        dev: Option<&Arc<NetDevice>>,
        flags: u32,
        protocol: u8,
        permanent: bool,
    ) -> Result<(), KernelError> {
        let mut o = self.lock.lock();
        let c = self.chain(key);
        let found = c.iter_locked(&o).find(|n| {
            n.is(net, key)
                && n.dev
                    .as_deref()
                    .is_none_or(|d| dev.is_some_and(|x| core::ptr::eq(d, Arc::as_ptr(x))))
        });
        let n = match found {
            Some(n) => n.get(),
            None => {
                let n = try_arc(PneighEntry {
                    hash: HNode::new(),
                    rcu: RcuHead::new(),
                    net_id: net.id,
                    dev: dev.cloned(),
                    key: *key,
                    flags: AtomicU32::new(0),
                    protocol: AtomicU8::new(0),
                    permanent: AtomicBool::new(false),
                })
                .map_err(|_| KernelError::NoBufferSpace)?;
                c.add_head(n.clone(), &mut o);
                n
            }
        };
        n.flags.store(flags, Relaxed);
        n.permanent.store(permanent, Relaxed);
        if protocol != 0 {
            n.protocol.store(protocol, Relaxed);
        }
        Ok(())
    }

    /// Remove the entry for `key` on exactly `dev` (None: the any-device
    /// one) in `net` (Linux pneigh_delete); ENOENT if there is none
    pub fn delete(
        &self,
        net: &NetNamespace,
        key: &Key,
        dev: Option<&NetDevice>,
    ) -> Result<(), KernelError> {
        let mut o = self.lock.lock();
        let same = |n: &PneighEntry| match (&n.dev, dev) {
            (None, None) => true,
            (Some(a), Some(b)) => core::ptr::eq(Arc::as_ptr(a), b),
            _ => false,
        };
        let u = self
            .chain(key)
            .remove_first(|n| n.is(net, key) && same(n), &mut o)
            .ok_or(KernelError::NotFound)?;
        drop(o);
        u.defer();
        Ok(())
    }

    /// Remove the entries of `dev` (Linux pneigh_ifdown_and_unlock;
    /// `skip_perm` keeps the permanent ones, as a carrier loss does)
    pub fn ifdown(&self, dev: &NetDevice, skip_perm: bool) {
        let mut o = self.lock.lock();
        let doomed = |n: &PneighEntry| {
            n.dev.as_deref().is_some_and(|d| core::ptr::eq(d, dev))
                && !(skip_perm && n.permanent.load(Relaxed))
        };
        for head in &self.heads {
            while let Some(u) = head.remove_first(doomed, &mut o) {
                u.defer();
            }
        }
    }

    /// The entry for `key` in `net` answering on `dev` or on any device,
    /// while `g` is held (Linux pneigh_lookup returning it: neigh_get)
    pub fn get<'a>(
        &'a self,
        g: &'a RcuReadGuard,
        net: &NetNamespace,
        key: &Key,
        dev: Option<&NetDevice>,
    ) -> Option<&'a PneighEntry> {
        self.chain(key).iter(g).find(|n| {
            n.is(net, key)
                && n.dev
                    .as_deref()
                    .is_none_or(|d| dev.is_some_and(|x| core::ptr::eq(d, x)))
        })
    }

    /// `net`'s entries, chain by chain, while `g` is held (a dump's
    /// resumable walk, Linux pneigh_dump_table)
    pub fn iter<'a>(
        &'a self,
        g: &'a RcuReadGuard,
        net: &'a NetNamespace,
    ) -> impl Iterator<Item = &'a PneighEntry> + 'a {
        self.heads
            .iter()
            .flat_map(move |h| h.iter(g))
            .filter(move |n| n.net_id == net.id)
    }

    /// Remove the entries of a namespace going away, the device-less
    /// ones included (Linux keeps those until the table is cleared: a
    /// leak)
    pub fn net_exit(&self, net_id: u64) {
        let mut o = self.lock.lock();
        for head in &self.heads {
            while let Some(u) = head.remove_first(|n| n.net_id == net_id, &mut o) {
                u.defer();
            }
        }
    }

    /// Call `f` on `net`'s entries while `g` is held (Linux
    /// pneigh_dump_table, the /proc walk)
    pub fn for_each<'a>(
        &'a self,
        g: &'a RcuReadGuard,
        net: &'a NetNamespace,
        mut f: impl FnMut(&PneighEntry),
    ) {
        for head in &self.heads {
            for n in head.iter(g).filter(|n| n.net_id == net.id) {
                f(n);
            }
        }
    }
}
