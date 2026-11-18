//! SO_REUSEPORT groups (Linux net/core/sock_reuseport.c)
//!
//! Sockets bound to one address and port with SO_REUSEPORT by one
//! owner form a group (Linux struct sock_reuseport); a lookup that
//! finds one member hands the packet to the member a flow hash picks
//! (reuseport_select_sock). Each member points at its group
//! ([`ReuseCb`], Linux sk_reuseport_cb). The members sit in an array
//! with room to spare and a count: a join fills the next slot, a leave
//! moves the last member into its slot (Linux __reuseport_add_sock,
//! __reuseport_detach_sock), and a full array is replaced by one twice
//! its size (Linux reuseport_grow).
//!
//! ## Locking
//!
//! `REUSEPORT_LOCK` (spin, Linux reuseport_lock, one for every group)
//! orders all joins, leaves and has_conns updates, inside the
//! protocol's table lock (Linux: hslot lock -> reuseport_lock). A
//! bigger array is allocated under it with GFP_ATOMIC, as Linux
//! reuseport_grow does; a leave never allocates. Readers pick a member
//! under `rcu::read_lock` (a slot read mid-leave may be empty or hold
//! the member that just moved, as Linux tolerates); member references,
//! replaced arrays and left groups are released a grace period later
//! (`put_rcu`), so the members' drops follow its rules.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::mm::page_alloc::Gfp;
use crate::sync::UniqueOwner;
use crate::sync::rcu::{HasRcuPuts, RcuLockedArc, RcuPuts, RcuReadGuard};
use crate::sync::spin::{Mutex, MutexGuard};
use crate::util::error::KernelError;
use crate::util::kalloc::{try_arc, with_gfp};

/// The data of `REUSEPORT_LOCK`: the proof its holder changes groups
///
/// # Invariants
/// One value exists, in [`REUSEPORT_LOCK`].
pub struct ReuseLocked(());

// SAFETY: one value exists (type invariant), reachable only through the
// lock
unsafe impl UniqueOwner for ReuseLocked {}

/// Linux reuseport_lock
static REUSEPORT_LOCK: Mutex<ReuseLocked> = Mutex::new(ReuseLocked(()));

/// Take `REUSEPORT_LOCK` (inside the protocol's table lock)
pub fn lock() -> MutexGuard<'static, ReuseLocked> {
    REUSEPORT_LOCK.lock()
}

/// First array size (Linux INIT_SOCKS)
const INIT_SOCKS: usize = 128;

/// One array of a group's members (Linux socks[] with max_socks and
/// num_socks)
struct Members<S> {
    socks: Box<[RcuLockedArc<S, ReuseLocked>]>,
    /// Slots `..n` hold the members
    n: AtomicUsize,
    rcu: RcuPuts,
}

// SAFETY: a field of the item, named for this use only
unsafe impl<S> HasRcuPuts for Members<S> {
    fn rcu_puts(&self) -> &RcuPuts {
        &self.rcu
    }
}

/// A group (Linux struct sock_reuseport)
pub struct Group<S> {
    members: RcuLockedArc<Members<S>, ReuseLocked>,
    /// A member connected: lookups score the pick (Linux has_conns)
    has_conns: AtomicBool,
    rcu: RcuPuts,
}

// SAFETY: a field of the item, named for this use only
unsafe impl<S> HasRcuPuts for Group<S> {
    fn rcu_puts(&self) -> &RcuPuts {
        &self.rcu
    }
}

/// An empty array of `cap` slots, allocated GFP_ATOMIC (`REUSEPORT_LOCK`
/// held, as Linux __reuseport_alloc's kzalloc(GFP_ATOMIC))
fn members<S>(cap: usize) -> Result<Arc<Members<S>>, KernelError> {
    with_gfp(Gfp::ATOMIC, || {
        let mut v = Vec::new();
        v.try_reserve_exact(cap)
            .map_err(|_| KernelError::OutOfMemory)?;
        v.resize_with(cap, RcuLockedArc::none);
        try_arc(Members {
            socks: v.into_boxed_slice(),
            n: AtomicUsize::new(0),
            rcu: RcuPuts::new(),
        })
    })
}

/// A member's group (Linux sk_reuseport_cb), none while in no group
pub struct ReuseCb<S>(RcuLockedArc<Group<S>, ReuseLocked>);

impl<S: HasRcuPuts + Send + Sync> Default for ReuseCb<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: HasRcuPuts + Send + Sync> ReuseCb<S> {
    pub const fn new() -> Self {
        Self(RcuLockedArc::none())
    }

    /// `me` starts a group of its own (Linux reuseport_alloc)
    pub fn alloc(&self, me: &Arc<S>, o: &mut ReuseLocked) -> Result<(), KernelError> {
        let m = members(INIT_SOCKS)?;
        let g = with_gfp(Gfp::ATOMIC, || {
            try_arc(Group {
                members: RcuLockedArc::new(Some(m)),
                has_conns: AtomicBool::new(false),
                rcu: RcuPuts::new(),
            })
        })?;
        Self::push(&g, me, o)?;
        self.0.replace(Some(g), o).defer_put();
        Ok(())
    }

    /// `me` joins `other`'s group (Linux reuseport_add_sock), or starts
    /// one if `other` is in none
    pub fn add(
        &self,
        me: &Arc<S>,
        other: &ReuseCb<S>,
        o: &mut ReuseLocked,
    ) -> Result<(), KernelError> {
        let Some(g) = other.0.get_protected(o) else {
            return self.alloc(me, o);
        };
        Self::push(&g, me, o)?;
        self.0.replace(Some(g), o).defer_put();
        Ok(())
    }

    /// Put `me` in the next slot of `g`, growing a full array (Linux
    /// __reuseport_add_sock, reuseport_grow)
    fn push(g: &Group<S>, me: &Arc<S>, o: &mut ReuseLocked) -> Result<(), KernelError> {
        let cur = g.members.get_protected(o).ok_or(KernelError::OutOfMemory)?;
        let n = cur.n.load(Ordering::Relaxed);
        let m = if n < cur.socks.len() {
            cur
        } else {
            let m = members(cur.socks.len() * 2)?;
            for (d, s) in m.socks.iter().zip(cur.socks.iter()) {
                // Into an empty slot: nothing comes back
                d.replace(s.get_protected(o), o).defer_put();
            }
            m.n.store(n, Ordering::Relaxed);
            g.members.replace(Some(m.clone()), o).defer_put();
            m
        };
        m.socks[n].replace(Some(me.clone()), o).defer_put();
        // Readers see the slot filled before the count covers it
        m.n.store(n + 1, Ordering::Release);
        Ok(())
    }

    /// `me` leaves its group (Linux reuseport_detach_sock): the last
    /// member moves into its slot; a no-op if in none. Never allocates.
    pub fn detach(&self, me: &S, o: &mut ReuseLocked) {
        let Some(g) = self.0.get_protected(o) else {
            return;
        };
        if let Some(m) = g.members.get_protected(o) {
            let n = m.n.load(Ordering::Relaxed);
            let i = (0..n).find(|&i| {
                m.socks[i]
                    .protected(o)
                    .is_some_and(|s| core::ptr::eq(s, me))
            });
            if let Some(i) = i {
                m.n.store(n - 1, Ordering::Release);
                if i != n - 1 {
                    let last = m.socks[n - 1].get_protected(o);
                    m.socks[i].replace(last, o).defer_put();
                }
                m.socks[n - 1].replace(None, o).defer_put();
            }
        }
        self.0.replace(None, o).defer_put();
    }

    /// A member connected (Linux reuseport_has_conns_set)
    pub fn set_conns(&self, o: &ReuseLocked) {
        if let Some(g) = self.0.protected(o) {
            g.has_conns.store(true, Ordering::Release);
        }
    }

    /// The member `hash` picks, and whether the group has connected
    /// members (Linux reuseport_select_sock with no program:
    /// reciprocal_scale over num_socks); None if in no group or the
    /// slot is empty mid-leave
    pub fn select<'a>(&'a self, hash: u32, g: &'a RcuReadGuard) -> Option<(&'a S, bool)> {
        let grp = self.0.read(g)?;
        let m = grp.members.read(g)?;
        let n = m.n.load(Ordering::Acquire).min(m.socks.len());
        let i = ((u64::from(hash) * n as u64) >> 32) as usize;
        let s = m.socks.get(i)?.read(g)?;
        Some((s, grp.has_conns.load(Ordering::Acquire)))
    }
}
