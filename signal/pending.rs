//! Pending signals and their queued info (Linux struct sigpending and
//! struct sigqueue, kernel/signal.c)
//!
//! A sender makes its entry under the receiver's `Task.sig` with
//! GFP_ATOMIC once the signal is known to be queued (Linux
//! __send_signal_locked: __sigqueue_alloc(.., GFP_ATOMIC, ..)) and
//! hands it to [`SigPending::queue`]; a dequeue returns its entry inside
//! a [`Dequeued`], which the caller drops (`Dequeued::info`) after
//! unlocking, and a flushed set is dropped the same way.
//!
//! A POSIX timer's entry is made with the timer (Linux
//! SIGQUEUE_PREALLOC) and is never freed while it lives: dequeued,
//! flushed or refused, it goes back to its timer
//! (`posix_timer::reclaim`), which also decides at dequeue whether the
//! signal still counts and rearms an interval timer.

use super::{SYNCHRONOUS_MASK, SigInfo, SigSet, Signal, si_code};
use crate::task::{Ucount, UcountsRef};
use crate::time::posix_timer::PosixTimer;
use crate::util::kalloc::try_box;
use crate::util::list::{BoxList, Link};
use alloc::boxed::Box;
use alloc::sync::Weak;

/// One queued signal (Linux struct sigqueue): its signal and info,
/// charged to the receiving user's RLIMIT_SIGPENDING count until freed
pub struct SigQueue {
    sig: Signal,
    /// Its si_signo is `sig`
    info: SigInfo,
    /// The user charged, a counted reference (Linux sigqueue.ucounts)
    ucounts: UcountsRef,
    /// The POSIX timer whose entry this is (Linux SIGQUEUE_PREALLOC)
    timer: Option<Weak<PosixTimer>>,
    /// On its SigPending's list (Linux sigqueue.list)
    link: Link,
}

crate::adapter!(SigQueueLink, SigQueue, link);

impl SigQueue {
    /// An entry for `sig` with `info` charged to `ucounts`, the
    /// receiver's real uid's (Linux sigqueue_alloc, sig_get_ucounts):
    /// none if that takes the user past `limit` (its RLIMIT_SIGPENDING)
    /// unless `override_rlimit`, or without memory. Allocates with the
    /// caller's GFP: a send calls it under the receiver's Task.sig with
    /// GFP_ATOMIC (Linux __send_signal_locked).
    pub fn alloc(
        sig: Signal,
        info: SigInfo,
        ucounts: &UcountsRef,
        limit: u64,
        override_rlimit: bool,
    ) -> Option<Box<Self>> {
        let n = ucounts.inc(Ucount::Sigpending, 1);
        // Holds the charge from here: dropped, it gives it back
        let q = Self {
            sig,
            info: info.with_sig(sig),
            ucounts: ucounts.clone(),
            timer: None,
            link: Link::new(),
        };
        if !override_rlimit && n > limit {
            return None;
        }
        try_box(q).ok()
    }

    /// POSIX timer `timer`'s entry for `sig`, charged to the current
    /// task's user within its RLIMIT_SIGPENDING (Linux
    /// posixtimer_init_sigqueue)
    pub fn alloc_timer(sig: Signal, info: SigInfo, timer: Weak<PosixTimer>) -> Option<Box<Self>> {
        let ucounts = crate::task::current_cred().ucounts;
        let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_SIGPENDING);
        let mut q = Self::alloc(sig, info, &ucounts, limit, false)?;
        q.timer = Some(timer);
        Some(q)
    }

    /// Its signal
    pub fn sig(&self) -> Signal {
        self.sig
    }

    /// Its info
    pub fn info(&self) -> &SigInfo {
        &self.info
    }

    /// The timer it belongs to, if any
    pub fn timer(&self) -> Option<&Weak<PosixTimer>> {
        self.timer.as_ref()
    }
}

/// Free an unlinked entry, or give a timer's back to it (no spin lock
/// held)
fn release(q: Box<SigQueue>) {
    if q.timer.is_some() {
        crate::time::posix_timer::reclaim(q);
    }
}

impl Drop for SigQueue {
    /// Its charge goes back, then its reference (Linux __sigqueue_free:
    /// dec_rlimit_put_ucounts)
    fn drop(&mut self) {
        self.ucounts.dec(Ucount::Sigpending, 1);
    }
}

/// A dequeued signal: its info, and its entry until dropped (with no
/// spin lock held)
#[must_use]
pub struct Dequeued {
    sig: Signal,
    info: SigInfo,
    q: Option<Box<SigQueue>>,
}

impl Dequeued {
    /// The signal
    pub fn sig(&self) -> Signal {
        self.sig
    }

    /// The info, freeing the entry (call with no spin lock held); None
    /// for a timer's signal its timer no longer wants delivered (Linux
    /// posixtimer_deliver_signal: dequeue again)
    pub fn info(mut self) -> Option<SigInfo> {
        match self.q.take() {
            Some(q) if q.timer.is_some() => crate::time::posix_timer::deliver(q),
            _ => Some(self.info),
        }
    }
}

impl Drop for Dequeued {
    fn drop(&mut self) {
        if let Some(q) = self.q.take() {
            release(q);
        }
    }
}

/// Pending signals for a task or thread group (Linux struct sigpending):
/// the set, and the info queued for them in arrival order
#[derive(Default)]
pub struct SigPending {
    /// Bitmask of pending signals
    pub signal: SigSet,
    list: BoxList<SigQueueLink>,
}

impl SigPending {
    /// Create empty pending set
    pub const fn new() -> Self {
        Self {
            signal: SigSet::EMPTY,
            list: BoxList::new(),
        }
    }

    /// Check if any signals are pending
    pub fn any(&self) -> bool {
        self.signal.any()
    }

    /// Mark `sig` pending with no info queued (SIGKILL needs none)
    pub fn add(&mut self, sig: Signal) {
        self.signal.add(sig);
    }

    /// `sig` is pending
    pub fn is_pending(&self, sig: Signal) -> bool {
        self.signal.contains(sig)
    }

    /// A non-RT signal already pending is not queued again (Linux
    /// legacy_queue): one instance, the first sender's info
    pub fn legacy(&self, sig: Signal) -> bool {
        !sig.is_rt() && self.signal.contains(sig)
    }

    /// Queue `q` behind the others and mark its signal pending
    pub fn queue(&mut self, q: Box<SigQueue>) {
        self.signal.add(q.sig);
        self.list.push_back(q);
    }

    fn iter(&self) -> impl Iterator<Item = &SigQueue> {
        self.list.iter()
    }

    /// Take `sig`'s first queued info (Linux collect_signal): it stays
    /// pending while another instance is queued; with none queued (it
    /// came without info) the info is SI_USER from pid 0
    fn collect(&mut self, sig: Signal) -> Dequeued {
        let q = self.list.remove_first(|q| q.sig == sig);
        if q.is_none() || !self.iter().any(|e| e.sig == sig) {
            self.signal.remove(sig);
        }
        let info = match &q {
            Some(q) => q.info,
            None => SigInfo::kill(sig, si_code::SI_USER, 0, 0),
        };
        Dequeued { sig, info, q }
    }

    /// The next signal not in `skip` (Linux next_signal): a
    /// synchronous one (SEGV, BUS, ILL, TRAP, FPE, SYS: a fault of the
    /// task's own) first, else the lowest-numbered
    fn next(&self, skip: &SigSet) -> Option<Signal> {
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
            q.info.code > si_code::SI_USER
                && SigSet(SYNCHRONOUS_MASK).contains(q.sig)
                && !blocked.contains(q.sig)
        };
        let sig = self.iter().find(|q| sync(q))?.sig;
        Some(self.collect(sig))
    }
}

impl SigPending {
    /// Take the POSIX timers' queued signals out (Linux
    /// __flush_itimer_signals): their signals stay pending only while
    /// another entry for them is queued; returned to be dropped after
    /// the lock is released
    pub fn flush_timers(&mut self) -> SigPending {
        let mut gone = SigPending::new();
        self.list
            .drain_if(|q| q.info.code == si_code::SI_TIMER, |q| gone.queue(q));
        self.signal = self.signal.subtract(&gone.signal);
        for q in self.list.iter() {
            self.signal.add(q.sig);
        }
        gone
    }

    /// The info of its `n`th queued entry (PTRACE_PEEKSIGINFO)
    pub fn nth(&self, n: u64) -> Option<SigInfo> {
        self.iter().nth(usize::try_from(n).ok()?).map(|q| q.info)
    }

    /// Take the signals of `mask` out, their queued info with them
    /// (Linux flush_sigqueue_mask): returned to be dropped after the
    /// lock is released
    pub fn flush_mask(&mut self, mask: &SigSet) -> SigPending {
        let mut gone = SigPending::new();
        gone.signal = self.signal.intersect(mask);
        self.signal = self.signal.subtract(mask);
        self.list
            .drain_if(|q| mask.contains(q.sig), |q| gone.queue(q));
        gone
    }
}

impl Drop for SigPending {
    /// One entry at a time: a long queue must not recurse; a timer's
    /// goes back to it
    fn drop(&mut self) {
        while let Some(q) = self.list.pop_front() {
            release(q);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{SIGBUS, SIGFPE, SIGHUP, SIGRTMIN, SIGSEGV, SIGUSR1, SigFields};
    use crate::task::{Uid, alloc_ucounts};

    const NONE: SigSet = SigSet::EMPTY;

    /// SIGRTMIN + `n`
    fn rtsig(n: u32) -> Signal {
        Signal::new(SIGRTMIN.nr() + n).unwrap()
    }

    fn rt(sig: Signal, value: u64) -> Box<SigQueue> {
        rt_as(4242, sig, value)
    }

    /// An RT entry charged to `uid` (each test its own uid: they run in
    /// parallel on one count table)
    fn rt_as(uid: Uid, sig: Signal, value: u64) -> Box<SigQueue> {
        let f = SigFields::Rt {
            pid: 1,
            uid: 0,
            value,
        };
        let info = SigInfo::new(sig, si_code::SI_QUEUE, f);
        SigQueue::alloc(sig, info, &alloc_ucounts(uid).unwrap(), u64::MAX, false).unwrap()
    }

    fn value(d: Dequeued) -> u64 {
        match d.info().unwrap().fields() {
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
        let sig = rtsig(3);
        let u = alloc_ucounts(4242).unwrap();
        let mut p = SigPending::new();
        for v in 1..=3 {
            p.queue(rt(sig, v));
        }
        assert_eq!(u.get(Ucount::Sigpending), 3);
        for v in 1..=3 {
            assert!(p.is_pending(sig));
            assert_eq!(p.dequeue(&NONE).map(value), Some(v));
        }
        assert!(!p.is_pending(sig));
        assert!(p.dequeue(&NONE).is_none());
        assert_eq!(u.get(Ucount::Sigpending), 0);
    }

    /// flush_mask takes the signal and every queued instance, nothing else
    #[test]
    fn flush() {
        let sig = rtsig(5);
        let mut p = SigPending::new();
        p.queue(rt_as(4244, sig, 1));
        p.queue(rt_as(4244, rtsig(6), 2));
        p.queue(rt_as(4244, sig, 3));
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
        let u = alloc_ucounts(4243).unwrap();
        let segv = SigInfo::fault(SIGSEGV, si_code::SEGV_MAPERR, 0x1000);
        p.queue(SigQueue::alloc(SIGSEGV, segv, &u, 1, false).unwrap());
        assert!(SigQueue::alloc(SIGSEGV, segv, &u, 1, false).is_none());
        let d = p.dequeue_sync(&NONE).unwrap();
        assert_eq!(d.info(), Some(segv));
        assert!(p.dequeue_sync(&NONE).is_none());
        assert_eq!(u.get(Ucount::Sigpending), 0);
    }
}
