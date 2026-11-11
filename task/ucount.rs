//! Per-user counts (Linux kernel/ucount.c, the rlimit half)
//!
//! Each real uid with credentials in use has one [`Ucounts`] (Linux
//! struct ucounts; one flat table, as for the initial user namespace):
//! its rlimit counters are atomics, so a charge takes no lock and
//! allocates nothing. A [`Cred`](super::Cred) holds a counted reference
//! to its real uid's ([`set_cred_ucounts`] before the credentials are
//! committed), and so does whatever a charge outlives the credentials
//! for: a queued signal (Linux sigqueue->ucounts), a message queue
//! (info->ucounts), an io_uring ring (ctx->user), the files of an
//! AF_UNIX message (scm_fp_list->user). Root's is the static
//! [`INIT_UCOUNTS`] (Linux init_ucounts), never freed.
//!
//! The lookup table is `UCOUNTS` (Linux ucounts_hashtable under
//! ucounts_lock): an rbtree by uid of weak references. [`alloc_ucounts`]
//! looks up, and on a miss allocates the entry and its node with the
//! lock released and looks again before inserting; the last reference's
//! drop takes the lock to unlink its node (Linux put_ucounts), freed
//! after the unlock.

use super::Uid;
use crate::sync::IrqSpinlock;
use crate::util::error::KernelResult;
use crate::util::kalloc::try_arc;
use crate::util::rbtree::{RbTree, RbTreeNodeReservation};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};

/// What a user's counter counts (Linux enum rlimit_type)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ucount {
    /// Tasks, threads included (UCOUNT_RLIMIT_NPROC): charged from clone
    /// until the task is released (reaped, or at exit for a non-leader
    /// thread); a real-uid change moves the charge (commit_creds)
    Nproc,
    /// POSIX message queue bytes (UCOUNT_RLIMIT_MSGQUEUE), charged to
    /// the creator while the queue lives
    Msgqueue,
    /// Queued signals (UCOUNT_RLIMIT_SIGPENDING), charged to the
    /// receiver while queued
    Sigpending,
    /// Pages io_uring locks (rings and registered buffers) against
    /// RLIMIT_MEMLOCK: Linux user_struct.locked_vm, the uid's other
    /// per-user structure, kept here with the rest
    LockedVm,
    /// Files in flight in AF_UNIX messages: Linux
    /// user_struct.unix_inflight, charged to the sending user from
    /// queueing until received or dropped
    UnixInflight,
}

const NR_UCOUNTS: usize = 5;

/// One user's counters (Linux struct ucounts)
pub struct Ucounts {
    uid: Uid,
    rlimit: [AtomicU64; NR_UCOUNTS],
}

/// Root's counters (Linux init_ucounts): static, so the boot task's
/// credentials need no allocation
static INIT_UCOUNTS: Ucounts = Ucounts::new(0);

/// Every other user's counters by uid (Linux ucounts_hashtable and
/// ucounts_lock): an IrqSpinlock leaf, as Linux takes it with interrupts
/// off: a last reference (a cred, a queued signal) may go in any
/// context. Nothing allocates or frees under it.
static UCOUNTS: IrqSpinlock<RbTree<Uid, Weak<Ucounts>>> = IrqSpinlock::new(RbTree::new());

impl Ucounts {
    const fn new(uid: Uid) -> Self {
        Self {
            uid,
            rlimit: [const { AtomicU64::new(0) }; NR_UCOUNTS],
        }
    }

    pub fn uid(&self) -> Uid {
        self.uid
    }

    fn ctr(&self, t: Ucount) -> &AtomicU64 {
        &self.rlimit[t as usize]
    }

    /// Charge `v`; the new count, `u64::MAX` past the counter's range
    /// (Linux inc_rlimit_ucounts' LONG_MAX)
    pub fn inc(&self, t: Ucount, v: u64) -> u64 {
        let old = self.ctr(t).fetch_add(v, Ordering::Relaxed);
        old.saturating_add(v)
    }

    /// Charge `v` unless the count would pass `max`; whether it was
    /// charged (Linux __io_account_mem's cmpxchg loop)
    pub fn inc_max(&self, t: Ucount, v: u64, max: u64) -> bool {
        self.ctr(t)
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                c.checked_add(v).filter(|&n| n <= max)
            })
            .is_ok()
    }

    /// Give back `v`; true if the count is now zero (Linux
    /// dec_rlimit_ucounts)
    pub fn dec(&self, t: Ucount, v: u64) -> bool {
        let old = self.ctr(t).fetch_sub(v, Ordering::Relaxed);
        debug_assert!(old >= v, "ucounts: {t:?} below zero");
        old == v
    }

    /// The count (Linux get_rlimit_value)
    pub fn get(&self, t: Ucount) -> u64 {
        self.ctr(t).load(Ordering::Relaxed)
    }

    /// The count is over `max`, an rlimit (Linux is_rlimit_overlimit:
    /// never for RLIM_INFINITY)
    pub fn overlimit(&self, t: Ucount, max: u64) -> bool {
        max != super::rlimit::RLIM_INFINITY && self.get(t) > max
    }
}

impl Drop for Ucounts {
    /// The last reference went (Linux put_ucounts): unlink this entry's
    /// node, unless a lookup that found it dying replaced it already;
    /// the node is freed after the unlock
    fn drop(&mut self) {
        let mut t = UCOUNTS.lock();
        let mine = t
            .get(&self.uid)
            .is_some_and(|w| core::ptr::eq(w.as_ptr(), self));
        let node = if mine { t.remove_node(&self.uid) } else { None };
        drop(t);
        drop(node);
    }
}

/// A counted reference to a user's [`Ucounts`] (Linux get_ucounts /
/// put_ucounts): an `Arc`, or none for root's static one
#[derive(Clone)]
pub struct UcountsRef(Option<Arc<Ucounts>>);

impl UcountsRef {
    /// Root's (Linux init_ucounts)
    pub const INIT: Self = Self(None);
}

impl core::ops::Deref for UcountsRef {
    type Target = Ucounts;
    fn deref(&self) -> &Ucounts {
        self.0.as_deref().unwrap_or(&INIT_UCOUNTS)
    }
}

impl PartialEq for UcountsRef {
    /// The same user's (one entry per uid)
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(
            core::ptr::from_ref::<Ucounts>(self),
            core::ptr::from_ref::<Ucounts>(other),
        )
    }
}

impl Eq for UcountsRef {}

impl core::fmt::Debug for UcountsRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ucounts({})", self.uid)
    }
}

/// A live entry for `uid` (Linux find_ucounts); a dying one (its last
/// reference gone, its drop not yet past the lock) counts as none
fn find(t: &RbTree<Uid, Weak<Ucounts>>, uid: Uid) -> Option<UcountsRef> {
    t.get(&uid)
        .and_then(Weak::upgrade)
        .map(|u| UcountsRef(Some(u)))
}

/// A reference to `uid`'s counters, made if it has none (Linux
/// alloc_ucounts): looked up under the lock; on a miss the entry and its
/// node are allocated with it released, and the lookup repeated before
/// inserting (a racer's entry wins; the spare is freed after the
/// unlock). ENOMEM.
pub fn alloc_ucounts(uid: Uid) -> KernelResult<UcountsRef> {
    if uid == 0 {
        return Ok(UcountsRef::INIT);
    }
    if let Some(u) = find(&UCOUNTS.lock(), uid) {
        return Ok(u);
    }
    let new = try_arc(Ucounts::new(uid))?;
    let node = RbTreeNodeReservation::new()?;
    let mut t = UCOUNTS.lock();
    if let Some(u) = find(&t, uid) {
        drop(t);
        return Ok(u);
    }
    // A dying entry's node is replaced and comes back, to free unlocked
    let old = t.insert(node.into_node(uid, Arc::downgrade(&new)));
    drop(t);
    drop(old);
    Ok(UcountsRef(Some(new)))
}

/// Point `new`'s counters at its real uid's, if they are another's
/// (Linux set_cred_ucounts, before the credentials are committed):
/// EAGAIN if they cannot be made
pub fn set_cred_ucounts(new: &mut super::Cred) -> KernelResult<()> {
    if new.ucounts.uid() == new.uid {
        return Ok(());
    }
    new.ucounts =
        alloc_ucounts(new.uid).map_err(|_| crate::util::error::KernelError::WouldBlock)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry per uid while referenced; gone with the last reference
    #[test]
    fn lookup_and_free() {
        let a = alloc_ucounts(5001).unwrap();
        let b = alloc_ucounts(5001).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, alloc_ucounts(5002).unwrap());
        assert_eq!(alloc_ucounts(0).unwrap(), UcountsRef::INIT);
        a.inc(Ucount::Nproc, 2);
        assert_eq!(b.get(Ucount::Nproc), 2);
        assert!(!b.dec(Ucount::Nproc, 1));
        assert!(a.dec(Ucount::Nproc, 1));
        drop(a);
        assert!(UCOUNTS.lock().get(&5001).is_some());
        drop(b);
        assert!(UCOUNTS.lock().get(&5001).is_none());
    }

    /// A capped charge stops at its limit and leaves the count alone
    #[test]
    fn inc_max() {
        let u = alloc_ucounts(5003).unwrap();
        assert!(u.inc_max(Ucount::LockedVm, 3, 4));
        assert!(!u.inc_max(Ucount::LockedVm, 2, 4));
        assert_eq!(u.get(Ucount::LockedVm), 3);
        u.dec(Ucount::LockedVm, 3);
        assert!(!u.overlimit(Ucount::LockedVm, 0));
        assert!(!u.overlimit(Ucount::LockedVm, super::super::rlimit::RLIM_INFINITY));
    }

    /// set_cred_ucounts follows the real uid only
    #[test]
    fn cred_follows_uid() {
        let mut c = super::super::Cred::new(5004, 5004);
        assert_eq!(c.ucounts, UcountsRef::INIT);
        set_cred_ucounts(&mut c).unwrap();
        assert_eq!(c.ucounts.uid(), 5004);
        c.euid = 0;
        let before = c.ucounts.clone();
        set_cred_ucounts(&mut c).unwrap();
        assert_eq!(c.ucounts, before);
    }
}
