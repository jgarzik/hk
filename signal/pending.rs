//! Pending signals and their queued info (Linux struct sigpending and
//! struct sigqueue, kernel/signal.c)
//!
//! Neither allocation nor free happens under `Task.sig` or the shared
//! pending lock: a sender builds its entry first ([`SigQueue::alloc`]),
//! hands it to [`SigPending::queue`] under the lock and drops an unused
//! one after unlocking; a dequeue returns its entry inside a
//! [`Dequeued`], which the caller drops (`Dequeued::info`) after
//! unlocking, and a flushed set is dropped the same way.

use super::{SIGRTMIN, SYNCHRONOUS_MASK, SigInfo, SigSet, si_code};
use crate::task::{Ucount, Uid, ucount_dec, ucount_inc};
use crate::util::kalloc::try_box;
use alloc::boxed::Box;

/// One queued signal (Linux struct sigqueue): its info, charged to the
/// receiving user's RLIMIT_SIGPENDING count until freed
pub struct SigQueue {
    info: SigInfo,
    /// The user charged (Linux sigqueue.ucounts)
    uid: Uid,
    next: Option<Box<SigQueue>>,
}

impl SigQueue {
    /// An entry for `info` charged to `uid`, the receiver's real uid
    /// (Linux sigqueue_alloc): none if that takes the user past `limit`
    /// (its RLIMIT_SIGPENDING) unless `override_rlimit`, or without
    /// memory. Thread context, no spin lock held.
    pub fn alloc(info: SigInfo, uid: Uid, limit: u64, override_rlimit: bool) -> Option<Box<Self>> {
        let n = ucount_inc(uid, Ucount::Sigpending);
        // Holds the charge from here: dropped, it gives it back
        let q = Self {
            info,
            uid,
            next: None,
        };
        if !override_rlimit && n > limit {
            return None;
        }
        try_box(q).ok()
    }
}

impl Drop for SigQueue {
    fn drop(&mut self) {
        ucount_dec(self.uid, Ucount::Sigpending);
    }
}

/// A dequeued signal: its info, and its entry until dropped (with no
/// spin lock held)
#[must_use]
pub struct Dequeued {
    info: SigInfo,
    _q: Option<Box<SigQueue>>,
}

impl Dequeued {
    /// The signal number
    pub fn sig(&self) -> u32 {
        self.info.sig()
    }

    /// The info, freeing the entry (call with no spin lock held)
    pub fn info(self) -> SigInfo {
        self.info
    }
}

/// Pending signals for a task or thread group (Linux struct sigpending):
/// the set, and the info queued for them in arrival order
#[derive(Default)]
pub struct SigPending {
    /// Bitmask of pending signals
    pub signal: SigSet,
    list: Option<Box<SigQueue>>,
}

impl SigPending {
    /// Create empty pending set
    pub const fn new() -> Self {
        Self {
            signal: SigSet::EMPTY,
            list: None,
        }
    }

    /// Check if any signals are pending
    pub fn any(&self) -> bool {
        self.signal.any()
    }

    /// Mark `sig` pending with no info queued (SIGKILL needs none)
    pub fn add(&mut self, sig: u32) {
        self.signal.add(sig);
    }

    /// Check if a specific signal is pending
    pub fn is_pending(&self, sig: u32) -> bool {
        self.signal.contains(sig)
    }

    /// A non-RT signal already pending is not queued again (Linux
    /// legacy_queue): one instance, the first sender's info
    pub fn legacy(&self, sig: u32) -> bool {
        sig < SIGRTMIN && self.signal.contains(sig)
    }

    /// Queue `q` behind the others and mark its signal pending
    pub fn queue(&mut self, mut q: Box<SigQueue>) {
        q.next = None;
        self.signal.add(q.info.sig());
        let mut cur = &mut self.list;
        while let Some(next) = cur {
            cur = &mut next.next;
        }
        *cur = Some(q);
    }

    fn iter(&self) -> impl Iterator<Item = &SigQueue> {
        core::iter::successors(self.list.as_deref(), |q| q.next.as_deref())
    }

    /// Unlink the first entry `f` picks
    fn unlink(&mut self, f: impl Fn(&SigQueue) -> bool) -> Option<Box<SigQueue>> {
        let mut cur = &mut self.list;
        while cur.as_deref().is_some_and(|q| !f(q)) {
            cur = &mut cur.as_mut()?.next;
        }
        let mut q = cur.take()?;
        *cur = q.next.take();
        Some(q)
    }

    /// Take `sig`'s first queued info (Linux collect_signal): it stays
    /// pending while another instance is queued; with none queued (it
    /// came without info) the info is SI_USER from pid 0
    fn collect(&mut self, sig: u32) -> Dequeued {
        let q = self.unlink(|q| q.info.sig() == sig);
        if q.is_none() || !self.iter().any(|e| e.info.sig() == sig) {
            self.signal.remove(sig);
        }
        let info = match &q {
            Some(q) => q.info,
            None => SigInfo::kill(sig, si_code::SI_USER, 0, 0),
        };
        Dequeued { info, _q: q }
    }

    /// The next signal not in `skip` (Linux next_signal): a
    /// synchronous one (SEGV, BUS, ILL, TRAP, FPE, SYS: a fault of the
    /// task's own) first, else the lowest-numbered
    fn next(&self, skip: &SigSet) -> Option<u32> {
        let take = self.signal.subtract(skip);
        let sync = SigSet(take.0 & SYNCHRONOUS_MASK);
        if sync.any() { sync } else { take }.first()
    }

    /// Dequeue the next signal not in `skip`, with its info (Linux
    /// __dequeue_signal)
    pub fn dequeue(&mut self, skip: &SigSet) -> Option<Dequeued> {
        let sig = self.next(skip)?;
        Some(self.collect(sig))
    }

    /// Dequeue the first queued kernel-generated synchronous signal not
    /// in `blocked`, in arrival order (Linux dequeue_synchronous_signal:
    /// a fault is delivered before anything else; a blocked one waits)
    pub fn dequeue_sync(&mut self, blocked: &SigSet) -> Option<Dequeued> {
        if self.signal.subtract(blocked).0 & SYNCHRONOUS_MASK == 0 {
            return None;
        }
        let sync = |q: &SigQueue| {
            let s = q.info.sig();
            q.info.code > si_code::SI_USER
                && SigSet(SYNCHRONOUS_MASK).contains(s)
                && !blocked.contains(s)
        };
        let sig = self.iter().find(|q| sync(q))?.info.sig();
        Some(self.collect(sig))
    }
}

impl SigPending {
    /// Take the signals of `mask` out, their queued info with them
    /// (Linux flush_sigqueue_mask): returned to be dropped after the
    /// lock is released
    pub fn flush_mask(&mut self, mask: &SigSet) -> SigPending {
        let mut gone = SigPending::new();
        gone.signal = self.signal.intersect(mask);
        self.signal = self.signal.subtract(mask);
        while let Some(q) = self.unlink(|q| mask.contains(q.info.sig())) {
            gone.queue(q);
        }
        gone
    }
}

impl Drop for SigPending {
    /// One entry at a time: a long queue must not recurse
    fn drop(&mut self) {
        let mut cur = self.list.take();
        while let Some(mut q) = cur {
            cur = q.next.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{SIGBUS, SIGFPE, SIGHUP, SIGSEGV, SIGUSR1, SigFields};

    const NONE: SigSet = SigSet::EMPTY;

    fn rt(sig: u32, value: u64) -> Box<SigQueue> {
        let f = SigFields::Rt {
            pid: 1,
            uid: 0,
            value,
        };
        let info = SigInfo::new(sig, si_code::SI_QUEUE, f);
        SigQueue::alloc(info, 4242, u64::MAX, false).unwrap()
    }

    fn value(d: Dequeued) -> u64 {
        match d.info().fields() {
            SigFields::Rt { value, .. } => value,
            _ => 0,
        }
    }

    /// A task's own fault comes before a lower-numbered signal (Linux
    /// next_signal); otherwise the lowest first; blocked ones wait
    #[test]
    fn synchronous_first() {
        let mut p = SigPending::new();
        for s in [SIGHUP, SIGUSR1, SIGSEGV, SIGBUS] {
            p.add(s);
        }
        let mut take = |p: &mut SigPending, b: &SigSet| p.dequeue(b).map(|d| d.sig());
        assert_eq!(take(&mut p, &NONE), Some(SIGBUS));
        assert_eq!(take(&mut p, &NONE), Some(SIGSEGV));
        assert_eq!(take(&mut p, &NONE), Some(SIGHUP));
        p.add(SIGFPE);
        let mut blocked = SigSet::EMPTY;
        blocked.add(SIGFPE);
        assert_eq!(take(&mut p, &blocked), Some(SIGUSR1));
        assert_eq!(take(&mut p, &blocked), None);
        assert_eq!(take(&mut p, &NONE), Some(SIGFPE));
    }

    /// RT instances come out in order, each with its info; the signal
    /// stays pending until the last; each entry holds a charge
    #[test]
    fn rt_queue_order() {
        let sig = SIGRTMIN + 3;
        let mut p = SigPending::new();
        for v in 1..=3 {
            p.queue(rt(sig, v));
        }
        assert_eq!(crate::task::ucount(4242, Ucount::Sigpending), 3);
        for v in 1..=3 {
            assert!(p.is_pending(sig));
            assert_eq!(p.dequeue(&NONE).map(value), Some(v));
        }
        assert!(!p.is_pending(sig));
        assert!(p.dequeue(&NONE).is_none());
        assert_eq!(crate::task::ucount(4242, Ucount::Sigpending), 0);
    }

    /// flush_mask takes the signal and every queued instance, nothing else
    #[test]
    fn flush() {
        let sig = SIGRTMIN + 5;
        let mut p = SigPending::new();
        p.queue(rt(sig, 1));
        p.queue(rt(SIGRTMIN + 6, 2));
        p.queue(rt(sig, 3));
        let mut m = SigSet::EMPTY;
        m.add(sig);
        let gone = p.flush_mask(&m);
        assert!(gone.is_pending(sig) && !p.is_pending(sig));
        assert_eq!(p.dequeue(&NONE).map(value), Some(2));
        assert!(p.dequeue(&NONE).is_none());
    }

    /// A kernel fault is taken before an earlier-numbered pending one and
    /// in queue order; past the limit no entry is made
    #[test]
    fn sync_and_limit() {
        let mut p = SigPending::new();
        p.add(SIGHUP);
        let segv = SigInfo::fault(SIGSEGV, si_code::SEGV_MAPERR, 0x1000);
        p.queue(SigQueue::alloc(segv, 4243, 1, false).unwrap());
        assert!(SigQueue::alloc(segv, 4243, 1, false).is_none());
        let d = p.dequeue_sync(&NONE).unwrap();
        assert_eq!(d.info(), segv);
        assert!(p.dequeue_sync(&NONE).is_none());
        assert_eq!(crate::task::ucount(4243, Ucount::Sigpending), 0);
    }
}
