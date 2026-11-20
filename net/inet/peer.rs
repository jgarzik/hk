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

/// Linux inet_peer_gc's time to live with `total` entries
fn ttl(total: usize, thresh: usize) -> u64 {
    if total >= thresh {
        return 0;
    }
    MAXTTL - (MAXTTL - MINTTL) * total as u64 / thresh as u64
}

impl InetPeerBase {
    /// The peer of `addr`, made if there is none (Linux inet_getpeer
    /// with a reference); None without memory
    pub fn get(&self, addr: Ipv4Addr) -> Option<Arc<InetPeer>> {
        let now = crate::net::neigh::now_ms();
        if let Some(p) = self.tree.lock().get(&addr.0) {
            p.dtime.store(now, Relaxed);
            return Some(p.clone());
        }
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
        if let Some(old) = t.get(&addr.0) {
            return Some(old.clone());
        }
        drop(t.insert(node.into_node(addr.0, p.clone())));
        let gone = Self::gc(&mut t, addr.0, now);
        drop(t);
        drop(gone);
        Some(p)
    }

    /// Collect the unreferenced, expired peers among the
    /// `PEER_MAX_GC` after `key` (Linux inet_peer_gc over the lookup
    /// path's candidates); the removed nodes come back to free after
    /// the unlock
    fn gc(
        t: &mut RbTree<u32, Arc<InetPeer>>,
        key: u32,
        now: u64,
    ) -> [Option<PeerNode>; PEER_MAX_GC] {
        let ttl = ttl(t.len(), threshold());
        let mut keys = [0u32; PEER_MAX_GC];
        let mut n = 0;
        for (k, p) in t.range_from(&key).take(PEER_MAX_GC) {
            let age = now.saturating_sub(p.dtime.load(Relaxed));
            if *k != key && age >= ttl && Arc::strong_count(p) == 1 {
                keys[n] = *k;
                n += 1;
            }
        }
        core::array::from_fn(|i| if i < n { t.remove_node(&keys[i]) } else { None })
    }
}

/// A peer's tree node
type PeerNode = crate::util::rbtree::RbTreeNode<u32, Arc<InetPeer>>;

#[cfg(test)]
mod tests {
    use super::ttl;

    #[test]
    fn ttl_falls_with_load() {
        assert_eq!(ttl(0, 4096), 600_000);
        assert_eq!(ttl(2048, 4096), 360_000);
        assert_eq!(ttl(4096, 4096), 0);
    }
}
