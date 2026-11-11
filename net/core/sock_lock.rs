//! The socket lock (Linux socket_lock_t: include/net/sock.h,
//! net/core/sock.c lock_sock / release_sock / bh_lock_sock)
//!
//! Two levels, as Linux:
//! - the owner (`lock`, Linux lock_sock): socket calls hold it across
//!   user copies and sleeps. While it is held, input that finds the
//!   socket owned waits in the backlog, and timers and ICMP errors leave
//!   flags (Linux sk_tsq_flags TCP_*_DEFERRED) for the owner.
//! - `slock` (`bh_lock`, Linux bh_lock_sock): a spin lock over the
//!   owned bit, the backlog and the deferred flags. Input, timers and
//!   ICMP errors (softnet threads) take it, and touch the protected
//!   state only when nobody owns the socket.
//!
//! Release (Linux release_sock) feeds the backlog to
//! `SockHooks::backlog_rcv` (Linux __release_sock) with `slock`
//! dropped and the socket still owned, then runs
//! `SockHooks::release_cb` with the deferred flags the same way, until
//! neither has work; only then is the owned bit cleared, under `slock`,
//! and a waiting locker woken. Linux runs release_cb under `slock`; hk
//! runs it owned with `slock` dropped because its wakeups send SIGIO
//! (a sleeping FasyncList lock). Mutual exclusion is the same: input
//! seeing the socket owned backlogs, and whatever arrives meanwhile is
//! picked up by the next round.
//!
//! Lock order: owner (sleeping, thread context; above every spin lock)
//! -> `slock` (spin, thread context; lockdep class: the caller of
//! `SockLock::new`) -> what the protocol takes under it. `SockLock.wq`
//! (an IrqSpinlock wait queue) is a leaf under `slock` only in
//! `lock`'s wait condition.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::net::skb::{SkBuff, SkbHead};
use crate::sync::spin::{Mutex, MutexGuard};
use crate::sync::waitqueue::{Relock, WaitQueue};
use crate::util::scope::ScopeGuard;

/// What a protocol does when its socket is released
pub trait SockHooks<T> {
    /// An skb that waited in the backlog (Linux sk_backlog_rcv); the
    /// socket is owned, no spin lock held
    fn backlog_rcv(&self, t: &mut T, skb: Box<SkBuff>);
    /// Work deferred while owned, `flags` (Linux sk_prot->release_cb;
    /// called on every release, also with no flags); owned, no spin
    /// lock held
    fn release_cb(&self, t: &mut T, flags: u32);
}

/// What `slock` protects
struct Slock {
    /// Linux sk_lock.owned
    owned: bool,
    /// Linux sk_backlog: skbs linked through their own `list`
    backlog: SkbHead<Box<SkBuff>>,
    /// Truesize queued since the backlog was last empty (Linux
    /// sk_backlog.len: zeroed only once a release found it empty)
    len: usize,
    /// Linux sk_tsq_flags TCP_*_DEFERRED
    deferred: u32,
}

/// A socket lock over the protocol state `T`
///
/// # Invariants
/// `data` is touched only by the owner (the holder of the
/// `SockGuard` that set `owned`) or by a holder of `slock` that saw
/// `owned` false (a `BhGuard`'s `get`).
pub struct SockLock<T> {
    slock: Mutex<Slock>,
    /// Lockers waiting for the owner (Linux sk_lock.wq)
    wq: WaitQueue,
    data: UnsafeCell<T>,
}

// SAFETY: `data` is reached by one context at a time: the owner or an
// unowned `slock` holder (type invariant)
unsafe impl<T: Send> Send for SockLock<T> {}
// SAFETY: as above
unsafe impl<T: Send> Sync for SockLock<T> {}

impl<T> SockLock<T> {
    /// An unowned lock; `slock`'s lockdep class is the caller's
    /// location
    #[track_caller]
    pub fn new(v: T) -> Self {
        Self {
            slock: Mutex::new(Slock {
                owned: false,
                backlog: SkbHead::new(),
                len: 0,
                deferred: 0,
            }),
            wq: WaitQueue::new(),
            data: UnsafeCell::new(v),
        }
    }

    /// Become the owner (Linux lock_sock): sleep while another owns it
    #[track_caller]
    pub fn lock<'a, H: SockHooks<T>>(&'a self, hooks: &'a H) -> SockGuard<'a, T, H> {
        crate::sync::might_sleep();
        self.acquire();
        SockGuard {
            lock: self,
            hooks,
            _not_send: PhantomData,
        }
    }

    /// Set `owned`, waiting for it to be clear (Linux __lock_sock: an
    /// exclusive, uninterruptible waiter)
    fn acquire(&self) {
        let take = || {
            let mut s = self.slock.lock();
            if s.owned {
                return false;
            }
            // INVARIANT: owned from here by the caller's new guard
            s.owned = true;
            true
        };
        if !take() {
            self.wq.wait_event_exclusive(take);
        }
    }

    /// Run the backlog and the deferred work as the owner until there
    /// is none; returns `slock` held with both empty (Linux
    /// __release_sock + release_cb)
    ///
    /// # Safety
    /// - The caller owns the lock (a `SockGuard` that set `owned`) and
    ///   holds no borrow of `data`.
    unsafe fn drain<H: SockHooks<T>>(&self, hooks: &H) -> MutexGuard<'_, Slock> {
        loop {
            let mut s = self.slock.lock();
            if !s.backlog.is_empty() {
                let mut q = core::mem::take(&mut s.backlog);
                drop(s);
                while let Some(skb) = q.pop_front() {
                    // SAFETY: owned by the caller, who holds no borrow
                    // of `data` (fn contract, type invariant)
                    hooks.backlog_rcv(unsafe { &mut *self.data.get() }, skb);
                }
                continue;
            }
            let flags = core::mem::take(&mut s.deferred);
            drop(s);
            // SAFETY: as above
            hooks.release_cb(unsafe { &mut *self.data.get() }, flags);
            let mut s = self.slock.lock();
            if s.backlog.is_empty() && s.deferred == 0 {
                s.len = 0;
                return s;
            }
        }
    }

    /// Give up ownership (Linux release_sock)
    ///
    /// # Safety
    /// - As for [`Self::drain`]; the caller's ownership ends here.
    unsafe fn release<H: SockHooks<T>>(&self, hooks: &H) {
        // SAFETY: the caller's contract
        let mut s = unsafe { self.drain(hooks) };
        // INVARIANT: nothing of `data` is borrowed any more
        s.owned = false;
        drop(s);
        self.wq.wake_one();
    }

    /// Take `slock` (Linux bh_lock_sock)
    #[track_caller]
    pub fn bh_lock(&self) -> BhGuard<'_, T> {
        BhGuard {
            s: self.slock.lock(),
            data: &self.data,
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

/// The owner of a [`SockLock`]; dropping it releases (Linux
/// release_sock)
#[must_use]
pub struct SockGuard<'a, T, H: SockHooks<T>> {
    lock: &'a SockLock<T>,
    hooks: &'a H,
    /// Ownership is the caller's task's until it releases
    _not_send: PhantomData<*const ()>,
}

impl<T, H: SockHooks<T>> SockGuard<'_, T, H> {
    /// Process the backlog and the deferred work, staying the owner
    /// (Linux __sk_flush_backlog)
    pub fn flush_backlog(&mut self) {
        // SAFETY: this guard owns the lock; `&mut self` holds off every
        // borrow of the data
        drop(unsafe { self.lock.drain(self.hooks) });
    }

    /// Input waits in the backlog (Linux READ_ONCE(sk->sk_backlog.tail))
    pub fn backlog_pending(&self) -> bool {
        !self.lock.slock.lock().backlog.is_empty()
    }
}

impl<T, H: SockHooks<T>> Relock for SockGuard<'_, T, H> {
    /// Release, run `f` (a sleep), become the owner again (Linux
    /// sk_wait_event's release_sock / lock_sock)
    fn unlocked<R>(&mut self, f: impl FnOnce() -> R) -> R {
        let lock = self.lock;
        // SAFETY: this guard owns the lock (`&mut self`: no borrow of the
        // data); `relock` owns it again before the guard is used
        unsafe { lock.release(self.hooks) };
        // Owned again however `f` ends, unwinding included (host tests
        // unwind), so the guard never releases twice
        let relock = ScopeGuard::new(|()| lock.acquire());
        let r = f();
        drop(relock);
        r
    }
}

impl<T, H: SockHooks<T>> Deref for SockGuard<'_, T, H> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: this guard owns the lock (type invariant)
        unsafe { &*self.lock.data.get() }
    }
}

impl<T, H: SockHooks<T>> DerefMut for SockGuard<'_, T, H> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this guard owns the lock (type invariant)
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T, H: SockHooks<T>> Drop for SockGuard<'_, T, H> {
    fn drop(&mut self) {
        // SAFETY: this guard owns the lock and is going away with every
        // borrow of the data
        unsafe { self.lock.release(self.hooks) };
    }
}

/// `slock` held (Linux bh_lock_sock)
#[must_use]
pub struct BhGuard<'a, T> {
    s: MutexGuard<'a, Slock>,
    data: &'a UnsafeCell<T>,
}

impl<T> BhGuard<'_, T> {
    /// Linux sock_owned_by_user
    pub fn owned(&self) -> bool {
        self.s.owned
    }

    /// The protected state, unless an owner has it
    pub fn get(&mut self) -> Option<&mut T> {
        if self.s.owned {
            return None;
        }
        // SAFETY: `slock` is held and nobody owns the socket, so no one
        // else reaches `data` until this borrow of the guard ends (type
        // invariant)
        Some(unsafe { &mut *self.data.get() })
    }

    /// Queue `skb` for the owner (Linux sk_add_backlog): refused, and
    /// handed back, when the backlog plus `rmem` (the receive queue's
    /// size) is over `limit` (Linux sk_rcvqueues_full)
    pub fn add_backlog(
        &mut self,
        skb: Box<SkBuff>,
        rmem: usize,
        limit: usize,
    ) -> Result<(), Box<SkBuff>> {
        if self.s.len.saturating_add(rmem) > limit {
            return Err(skb);
        }
        self.s.len = self.s.len.saturating_add(skb.truesize());
        self.s.backlog.push_back(skb);
        Ok(())
    }

    /// Leave `flag` for the owner's release (Linux test_and_set_bit on
    /// sk_tsq_flags)
    pub fn defer(&mut self, flag: u32) {
        self.s.deferred |= flag;
    }
}
