//! Per-inode file lock state and lock waits (Linux fs/locks.c:
//! file_lock_context, locks_insert_block, posix_locks_deadlock)
//!
//! Every inode has a `FileLockCtx` (Linux inode->i_flctx): its flock
//! locks and POSIX byte-range locks under one spin lock (`flc_lock`),
//! a wait queue for blocked lockers and a change counter. A blocking
//! flock or F_SETLKW that conflicts sleeps (interruptibly: EINTR) until
//! the inode's locks change, then tries again; every unlock and release
//! counts a change and wakes the waiters.
//!
//! POSIX deadlocks (Linux posix_locks_deadlock): `BLOCKED` maps each
//! waiting lock owner to the owner it waits on; before sleeping, a
//! locker follows that chain from its blocker and gets EDEADLK if it
//! comes back to itself (at most MAX_DEADLK_ITERATIONS steps, as Linux).
//!
//! `POSIX_INODES` lists the inodes holding POSIX locks, for the release
//! of a process's locks at its exit (hk's lock owner is the pid; Linux
//! uses the files_struct and needs no list).
//!
//! Locking: `flc_lock` is a spin leaf but for `BLOCKED` (flc_lock ->
//! BLOCKED, Linux flc_lock -> blocked_lock_lock); `POSIX_INODES` is a
//! leaf taken with neither held. Waits sleep with none held.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::flock::FileLock;
use super::inode::Inode;
use super::posix_lock::InodeLocks;
use crate::error::KernelError;
use crate::sync::spin::Mutex;
use crate::waitqueue::WaitQueue;

/// The locks of one inode
#[derive(Default)]
pub struct Locks {
    pub flock: FileLock,
    pub posix: InodeLocks,
}

/// An inode's lock state (Linux file_lock_context)
pub struct FileLockCtx {
    /// Linux flc_lock: flc_flock and flc_posix
    flc_lock: Mutex<Locks>,
    /// Blocked lockers (Linux the waiters' fl_wait)
    wait: WaitQueue,
    /// Changes so far: a waiter sleeps until it moves
    changes: AtomicU64,
}

impl FileLockCtx {
    pub fn new() -> Self {
        Self {
            flc_lock: Mutex::new(Locks::default()),
            wait: WaitQueue::new(),
            changes: AtomicU64::new(0),
        }
    }

    /// Run `f` on the locks under `flc_lock`; `changed` says whether it
    /// released something, waking the waiters
    pub fn with<R>(&self, f: impl FnOnce(&mut Locks) -> (R, bool)) -> R {
        let (r, changed) = f(&mut self.flc_lock.lock());
        if changed {
            self.changes.fetch_add(1, Ordering::AcqRel);
            self.wait.wake_all();
        }
        r
    }

    /// The change count, read before trying a lock
    pub fn generation(&self) -> u64 {
        self.changes.load(Ordering::Acquire)
    }

    /// Sleep until the locks change after generation `g` (Linux
    /// wait_event_interruptible on fl_wait): Err(Interrupted) on a signal
    pub fn wait_change(&self, g: u64) -> Result<(), KernelError> {
        // A pending signal ends the wait even when the locks already
        // changed: every pass of a lock retry loop can be interrupted
        if crate::task::percpu::current().sigpending() {
            return Err(KernelError::Interrupted);
        }
        self.wait
            .wait_event_interruptible(|| self.generation() != g)
    }
}

impl Default for FileLockCtx {
    fn default() -> Self {
        Self::new()
    }
}

/// Linux MAX_DEADLK_ITERATIONS
const MAX_DEADLK_ITERATIONS: usize = 10;

/// Waiting POSIX lock owners and the owner each waits on (Linux
/// blocked_hash)
static BLOCKED: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

/// Record that `owner` waits on `blocker`, unless that closes a cycle
/// (Linux posix_locks_deadlock): EDEADLK then
pub fn block_on(owner: u64, blocker: u64) -> Result<(), KernelError> {
    let mut b = BLOCKED.lock();
    let mut at = blocker;
    for _ in 0..MAX_DEADLK_ITERATIONS {
        if at == owner {
            return Err(KernelError::Deadlock);
        }
        match b.get(&at) {
            Some(&next) => at = next,
            None => break,
        }
    }
    b.insert(owner, blocker);
    Ok(())
}

/// `owner` no longer waits
pub fn unblock(owner: u64) {
    BLOCKED.lock().remove(&owner);
}

/// Inodes with POSIX locks (for `release_posix_for_pid`)
static POSIX_INODES: Mutex<Vec<Weak<Inode>>> = Mutex::new(Vec::new());

/// `inode` now has POSIX locks
pub fn note_posix_inode(inode: &Arc<Inode>) {
    let mut l = POSIX_INODES.lock();
    l.retain(|w| w.strong_count() > 0);
    if !l.iter().any(|w| Weak::as_ptr(w) == Arc::as_ptr(inode)) {
        l.push(Arc::downgrade(inode));
    }
}

/// The inodes that may hold POSIX locks
pub fn posix_inodes() -> Vec<Arc<Inode>> {
    POSIX_INODES
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .collect()
}
