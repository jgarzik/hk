//! Long-lived IPv4 peer state (Linux net/ipv4/inetpeer.c)
//!
//! One [`InetPeer`] per remote address a namespace has heard from
//! (Linux struct inet_peer in net->ipv4.peers): today the IP
//! identifier counter of fragments received from it (`rid`, for
//! ipfrag_max_dist). Peers are created on demand and collected once
//! unreferenced and old enough (Linux inet_peer_gc: a time to live
//! falling from 10 to 2 minutes as the table nears its threshold, 0
//! past it).
//!
//! The collector looks at the entries a locked lookup passes on its
//! way down the tree (Linux lookup()'s gc_stack, at most PEER_MAX_GC),
//! as Linux.
//!
//! Locking: `InetPeerBase.tree` (spin, thread only: softnet's
//! reassembly) is a leaf; the node and the peer are allocated
//! GFP_ATOMIC before it is taken. Deviation: Linux looks up under a
//! seqlock without the lock first; hk always takes it.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

use crate::mm::page_alloc::Gfp;
use crate::net::ipv4::Ipv4Addr;
use crate::sync::spin::Mutex;
use crate::util::kalloc::try_arc_gfp;
use crate::util::rbtree::{RbTree, RbTreeNodeReservation};

/// Candidates the collector looks at per insert (Linux PEER_MAX_GC)
const PEER_MAX_GC: usize = 32;
/// Time to live under load and usually, ms (Linux inet_peer_minttl,
/// inet_peer_maxttl)
const MINTTL: u64 = 120_000;
const MAXTTL: u64 = 600_000;

/// A remote address's state (Linux struct inet_peer)
pub struct InetPeer {
    /// Fragments received from it (Linux rid)
    pub rid: AtomicU32,
    /// Last looked up, ms (Linux dtime)
    dtime: AtomicU64,
}

/// A namespace's peers (Linux struct inet_peer_base)
pub struct InetPeerBase {
    tree: Mutex<RbTree<u32, Arc<InetPeer>>>,
}

impl Default for InetPeerBase {
    fn default() -> Self {
        Self {
            tree: Mutex::new(RbTree::new()),
        }
    }
}

/// Entries at which the collector turns aggressive (Linux
/// inet_peer_threshold: 1% of memory, 4096..65664)
fn threshold() -> usize {
    let pages = crate::FRAME_ALLOCATOR.buffer_pages();
    // 64-byte cache-aligned entries in 1% of the memory
    (pages * 4096 / (100 * 64)).clamp(4096, 65536 + 128)
}

/// Linux inet_peer_gc's time to live with `total` entries, in its
/// integer order: (maxttl - minttl) / HZ * total / threshold * HZ
fn ttl(total: usize, thresh: usize) -> u64 {
    if total >= thresh {
        return 0;
    }
    MAXTTL - (MAXTTL - MINTTL) / 1000 * total as u64 / thresh as u64 * 1000
}

/// The collector's candidates: the entries a locked lookup passed
/// (Linux lookup()'s gc_stack)
struct GcStack {
    keys: [u32; PEER_MAX_GC],
    n: usize,
}

impl GcStack {
    fn push(&mut self, k: u32) {
        if self.n < PEER_MAX_GC {
            self.keys[self.n] = k;
            self.n += 1;
        }
    }
}

impl InetPeerBase {
    /// The peer of `addr`, made if there is none (Linux inet_getpeer
    /// with a reference); None without memory
    pub fn get(&self, addr: Ipv4Addr) -> Option<Arc<InetPeer>> {
        self.get_at(addr, crate::net::neigh::now_ms(), threshold())
    }

    /// [`get`](Self::get) at `now` (ms) with collector threshold
    /// `thresh`
    fn get_at(&self, addr: Ipv4Addr, now: u64, thresh: usize) -> Option<Arc<InetPeer>> {
        if let Some(p) = self.tree.lock().get(&addr.0) {
            p.dtime.store(now, Relaxed);
            return Some(p.clone());
        }
        // Linux allocates under the lock, GFP_ATOMIC; hk before it
        let node = RbTreeNodeReservation::new_gfp(Gfp::ATOMIC).ok()?;
        let p = try_arc_gfp(
            InetPeer {
                rid: AtomicU32::new(0),
                dtime: AtomicU64::new(now),
            },
            Gfp::ATOMIC,
        )
        .ok()?;
        let mut t = self.tree.lock();
        let mut gc = GcStack {
            keys: [0; PEER_MAX_GC],
            n: 0,
        };
        let found = t
            .get_mut_visiting(&addr.0, |k, _| gc.push(*k))
            .map(|o| o.clone());
        let p = match found {
            Some(o) => {
                o.dtime.store(now, Relaxed);
                o
            }
            None => {
                drop(t.insert(node.into_node(addr.0, p.clone())));
                p
            }
        };
        let gone = Self::gc(&mut t, &gc, now, thresh);
        drop(t);
        drop(gone);
        Some(p)
    }

    /// Linux inet_peer_gc: of the candidates, those unreferenced and
    /// unused for the time to live leave; their nodes come back to free
    /// after the unlock
    fn gc(
        t: &mut RbTree<u32, Arc<InetPeer>>,
        gc: &GcStack,
        now: u64,
        thresh: usize,
    ) -> [Option<PeerNode>; PEER_MAX_GC] {
        let ttl = ttl(t.len(), thresh);
        let dead = |k: &u32| {
            t.get(k).is_some_and(|p| {
                let age = now.saturating_sub(p.dtime.load(Relaxed));
                age >= ttl && Arc::strong_count(p) == 1
            })
        };
        let mut keys = [0u32; PEER_MAX_GC];
        let mut n = 0;
        for k in gc.keys[..gc.n].iter().filter(|k| dead(k)) {
            keys[n] = *k;
            n += 1;
        }
        core::array::from_fn(|i| if i < n { t.remove_node(&keys[i]) } else { None })
    }
}

/// A peer's tree node
type PeerNode = crate::util::rbtree::RbTreeNode<u32, Arc<InetPeer>>;

#[cfg(test)]
mod tests {
    use super::*;

    /// A source spraying ascending addresses, every old peer expired:
    /// the collector keeps the table near its threshold (Linux
    /// inet_getpeer gathers its candidates on the lookup path, both
    /// sides of the key)
    #[test]
    fn ascending_keys_stay_bounded() {
        let b = InetPeerBase::default();
        let thresh = 64;
        for i in 0..20_000u32 {
            let now = u64::from(i) * MAXTTL;
            drop(b.get_at(Ipv4Addr(i), now, thresh));
        }
        let n = b.tree.lock().len();
        assert!(n <= 2 * thresh, "{n} peers");
    }

    #[test]
    fn ttl_falls_with_load() {
        assert_eq!(ttl(0, 4096), 600_000);
        assert_eq!(ttl(2048, 4096), 360_000);
        assert_eq!(ttl(4096, 4096), 0);
    }
}
