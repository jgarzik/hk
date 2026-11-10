//! Error sequence counters (Linux lib/errseq.c, errseq_t)
//!
//! One 32-bit word: the latest error's errno (12 bits), a SEEN flag, and
//! above them a counter bumped when a new error comes after the last one
//! was seen. A reader keeps the value it last saw (its "since", e.g. a
//! file's sample of its mapping's at open) and reports an error once per
//! change: every reader that sampled before an error sees it, once. An
//! error nobody has seen yet is reported to a reader that samples after
//! it too (`sample` gives 0 then), so it is not lost between the failed
//! writeback and the first open.

use core::sync::atomic::{AtomicU32, Ordering};

use super::error::KernelError;

/// Bits of the errno (Linux ERRSEQ_SHIFT: MAX_ERRNO 4095 fits)
const SHIFT: u32 = 12;
/// The error was reported to some reader (Linux ERRSEQ_SEEN)
const SEEN: u32 = 1 << SHIFT;
const ERRNO_MASK: u32 = SEEN - 1;
/// The counter's unit (Linux ERRSEQ_CTR_INC)
const CTR_INC: u32 = 1 << (SHIFT + 1);

/// An error sequence (Linux errseq_t)
#[derive(Debug, Default)]
pub struct ErrSeq(AtomicU32);

/// The error a value holds
fn error_of(v: u32) -> Option<KernelError> {
    match v & ERRNO_MASK {
        0 => None,
        e => Some(KernelError::from_errno(e as i32).unwrap_or(KernelError::Io)),
    }
}

impl ErrSeq {
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    /// Record `err` (Linux errseq_set): the latest error, and a new one
    /// for readers if the last was seen
    pub fn set(&self, err: KernelError) {
        let errno = err.errno().unsigned_abs();
        if errno == 0 || errno > ERRNO_MASK {
            return;
        }
        let mut old = self.0.load(Ordering::Relaxed);
        loop {
            let mut new = (old & !(ERRNO_MASK | SEEN)) | errno;
            if old & SEEN != 0 {
                new = new.wrapping_add(CTR_INC);
            }
            if new == old {
                return;
            }
            match self
                .0
                .compare_exchange(old, new, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return,
                // Someone else stored the same: done as well
                Err(cur) if cur == new => return,
                Err(cur) => old = cur,
            }
        }
    }

    /// A sample to check against later (Linux errseq_sample): an error
    /// nobody has seen yet is left for this reader to see
    pub fn sample(&self) -> u32 {
        let v = self.0.load(Ordering::Acquire);
        if v & SEEN == 0 { 0 } else { v }
    }

    /// The latest error, if any came since `since` (Linux errseq_check)
    pub fn check(&self, since: u32) -> Option<KernelError> {
        let v = self.0.load(Ordering::Acquire);
        if v == since { None } else { error_of(v) }
    }

    /// As `check`, marking the error seen and moving `since` to it (Linux
    /// errseq_check_and_advance); the caller serializes updates of
    /// `since`
    pub fn check_and_advance(&self, since: &mut u32) -> Option<KernelError> {
        let old = self.0.load(Ordering::Acquire);
        if old == *since {
            return None;
        }
        let new = old | SEEN;
        if new != old {
            // Lost to a writer or another reader: either is fine
            let _ = self
                .0
                .compare_exchange(old, new, Ordering::AcqRel, Ordering::Relaxed);
        }
        *since = new;
        error_of(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_once_per_reader() {
        let e = ErrSeq::new();
        let (mut a, mut b) = (e.sample(), e.sample());
        assert_eq!(e.check_and_advance(&mut a), None);
        e.set(KernelError::Io);
        assert_eq!(e.check(a), Some(KernelError::Io));
        assert_eq!(e.check_and_advance(&mut a), Some(KernelError::Io));
        assert_eq!(e.check_and_advance(&mut a), None);
        // The other reader sampled before it: it sees it too, once
        assert_eq!(e.check_and_advance(&mut b), Some(KernelError::Io));
        assert_eq!(e.check_and_advance(&mut b), None);
        // Seen now: a later sample does not see it
        let mut c = e.sample();
        assert_eq!(e.check_and_advance(&mut c), None);
    }

    #[test]
    fn unseen_error_reaches_a_later_sample() {
        let e = ErrSeq::new();
        e.set(KernelError::Io);
        let mut late = e.sample();
        assert_eq!(late, 0);
        assert_eq!(e.check_and_advance(&mut late), Some(KernelError::Io));
        assert_eq!(e.check_and_advance(&mut late), None);
    }

    #[test]
    fn new_error_after_seen_counts() {
        let e = ErrSeq::new();
        let mut a = e.sample();
        e.set(KernelError::Io);
        assert!(e.check_and_advance(&mut a).is_some());
        let seen = a;
        // The same error again, after it was seen: a new one
        e.set(KernelError::Io);
        assert_ne!(e.sample(), seen);
        assert_eq!(e.check_and_advance(&mut a), Some(KernelError::Io));
        // Repeated before anyone looks: one report, the latest errno
        e.set(KernelError::NoSpace);
        e.set(KernelError::Io);
        e.set(KernelError::NoSpace);
        assert_eq!(e.check_and_advance(&mut a), Some(KernelError::NoSpace));
        assert_eq!(e.check_and_advance(&mut a), None);
    }
}
