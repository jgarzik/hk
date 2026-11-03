//! Open-descriptor bitmap (Linux fs/file.c: fdtable open_fds +
//! full_fds_bits, files_struct.next_fd) and the fs.nr_open cap
//!
//! Bit `fd` of `open` is set while `fd` is open; bit `w` of `full` is
//! set while word `w` of `open` is all ones. Finding the lowest free
//! descriptor skips full words through `full`, so it reads about one
//! `full` word per 4096 open descriptors instead of probing each fd.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

const BITS: usize = u64::BITS as usize;

/// fs.nr_open (Linux sysctl_nr_open): no descriptor at or above it, and
/// no RLIMIT_NOFILE hard limit above it
static NR_OPEN: AtomicU32 = AtomicU32::new(1024 * 1024);
/// Its range (Linux sysctl_nr_open_min, sysctl_nr_open_max)
const NR_OPEN_MIN: i64 = BITS as i64;
const NR_OPEN_MAX: i64 = i32::MAX as i64 & -(BITS as i64);

pub fn nr_open() -> u64 {
    NR_OPEN.load(Ordering::Relaxed) as u64
}

/// /proc/sys/fs files of the descriptor table
pub static FS_CTLS: &[crate::sysctl::Ctl] = &[crate::sysctl::Ctl {
    path: "fs/nr_open",
    mode: 0o644,
    show: || alloc::vec![nr_open() as i64],
    store: |v| {
        crate::sysctl::range(v[0], NR_OPEN_MIN, NR_OPEN_MAX)?;
        NR_OPEN.store(v[0] as u32, Ordering::Relaxed);
        Ok(())
    },
    text: None,
}];

/// Two-level bitmap of open descriptors; both levels grow on demand
#[derive(Clone)]
pub struct OpenFds {
    open: Vec<u64>,
    full: Vec<u64>,
    /// No descriptor below this is free (Linux files_struct.next_fd)
    next: usize,
}

/// First zero bit at or above `from`; bits past the end are zero
fn next_zero(bits: &[u64], from: usize) -> usize {
    let mut w = from / BITS;
    let Some(&first) = bits.get(w) else {
        return from;
    };
    let mut v = first | low_mask(from % BITS);
    while v == !0 {
        w += 1;
        v = bits.get(w).copied().unwrap_or(0);
    }
    w * BITS + (!v).trailing_zeros() as usize
}

/// The bits below `b` (b < 64)
fn low_mask(b: usize) -> u64 {
    (1u64 << b) - 1
}

/// Grow `v` to hold word `w`; false if memory is short
fn grow(v: &mut Vec<u64>, w: usize) -> bool {
    if w < v.len() {
        return true;
    }
    if v.try_reserve(w + 1 - v.len()).is_err() {
        return false;
    }
    v.resize(w + 1, 0);
    true
}

impl OpenFds {
    pub const fn new() -> Self {
        Self {
            open: Vec::new(),
            full: Vec::new(),
            next: 0,
        }
    }

    /// Lowest free descriptor at or above `start` (Linux find_next_fd)
    pub fn find(&self, start: usize) -> usize {
        let mut fd = start.max(self.next);
        loop {
            let w = next_zero(&self.full, fd / BITS);
            if w > fd / BITS {
                fd = w * BITS;
            }
            let v = self.open.get(w).copied().unwrap_or(0) | low_mask(fd % BITS);
            if v != !0 {
                return w * BITS + (!v).trailing_zeros() as usize;
            }
            // Word `w` has room only below `fd`: go on from the next word
            fd = (w + 1) * BITS;
        }
    }

    /// Claim the lowest free descriptor at or above `start` and below
    /// `limit` (Linux alloc_fd): Err(EMFILE) past the limit or
    /// fs.nr_open, Err(ENOMEM) if the bitmap cannot grow
    pub fn alloc(&mut self, start: usize, limit: u64) -> Result<usize, i32> {
        let fd = self.find(start);
        if fd as u64 >= limit.min(nr_open()) {
            return Err(24); // EMFILE
        }
        let lowest = start <= self.next;
        if !self.set(fd) {
            return Err(12); // ENOMEM
        }
        // Searched from `next`: nothing below `fd` is free now
        if lowest {
            self.next = fd + 1;
        }
        Ok(fd)
    }

    /// Make room for `fd` (Linux expand_files): Err(EMFILE) at or past
    /// fs.nr_open, Err(ENOMEM) if the bitmap cannot grow. Unlike Linux,
    /// whose table may already cover a descriptor past a lowered
    /// fs.nr_open, the cap always applies.
    pub fn reserve(&mut self, fd: usize) -> Result<(), i32> {
        if fd as u64 >= nr_open() {
            return Err(24); // EMFILE
        }
        let w = fd / BITS;
        if !grow(&mut self.open, w) || !grow(&mut self.full, w / BITS) {
            return Err(12); // ENOMEM
        }
        Ok(())
    }

    /// Mark `fd` open (Linux __set_open_fd); false if memory is short
    pub fn set(&mut self, fd: usize) -> bool {
        let w = fd / BITS;
        if !grow(&mut self.open, w) || !grow(&mut self.full, w / BITS) {
            return false;
        }
        self.open[w] |= 1 << (fd % BITS);
        if self.open[w] == !0 {
            self.full[w / BITS] |= 1 << (w % BITS);
        }
        if fd == self.next {
            self.next = fd + 1;
        }
        true
    }

    /// Mark `fd` free (Linux __clear_open_fd + __put_unused_fd)
    pub fn clear(&mut self, fd: usize) {
        let w = fd / BITS;
        if let Some(v) = self.open.get_mut(w) {
            *v &= !(1 << (fd % BITS));
        }
        if let Some(v) = self.full.get_mut(w / BITS) {
            *v &= !(1 << (w % BITS));
        }
        self.next = self.next.min(fd);
    }

    /// Whether `fd` is marked open
    pub fn test(&self, fd: usize) -> bool {
        self.open
            .get(fd / BITS)
            .is_some_and(|v| v & (1 << (fd % BITS)) != 0)
    }
}

impl Default for OpenFds {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference: linear probe for the lowest clear fd >= start
    fn slow(b: &OpenFds, start: usize) -> usize {
        (start..).find(|&fd| !b.test(fd)).unwrap()
    }

    #[test]
    fn empty() {
        let b = OpenFds::new();
        assert_eq!(b.find(0), 0);
        assert_eq!(b.find(12345), 12345);
    }

    #[test]
    fn dense_fill() {
        let mut b = OpenFds::new();
        for fd in 0..10_000 {
            assert_eq!(b.find(0), fd);
            assert!(b.set(fd));
        }
        assert_eq!(b.find(0), 10_000);
        b.clear(4096);
        assert_eq!(b.find(0), 4096);
        assert_eq!(b.find(4097), 10_000);
        b.clear(63);
        assert_eq!(b.find(0), 63);
        assert_eq!(b.find(64), 4096);
    }

    #[test]
    fn nr_open_cap() {
        let mut b = OpenFds::new();
        let cap = nr_open() as usize;
        assert_eq!(b.reserve(cap), Err(24));
        assert_eq!(b.reserve(cap - 1), Ok(()));
        assert!(!b.test(cap - 1));
        assert_eq!(b.alloc(cap, u64::MAX), Err(24));
    }

    #[test]
    fn alloc_limit_and_hint() {
        let mut b = OpenFds::new();
        assert_eq!(b.alloc(0, 3), Ok(0));
        assert_eq!(b.alloc(0, 3), Ok(1));
        assert_eq!(b.alloc(10, 3), Err(24));
        assert_eq!(b.alloc(10, 100), Ok(10));
        assert_eq!(b.alloc(0, 100), Ok(2));
        assert_eq!(b.alloc(0, 3), Err(24));
        b.clear(1);
        assert_eq!(b.alloc(0, 3), Ok(1));
        assert!(!b.test(3) && b.test(10));
        assert_eq!(b.alloc(0, 100), Ok(3));
    }

    #[test]
    fn room_below_start() {
        let mut b = OpenFds::new();
        // Word 0 has fd 3 free; words 1..=70 are full
        for fd in 0..(71 * 64) {
            if fd != 3 {
                assert!(b.set(fd));
            }
        }
        assert_eq!(b.find(5), 71 * 64);
        assert_eq!(b.find(0), 3);
    }

    /// FdTable keeps its bitmap in step through every add/remove path
    #[test]
    fn fdtable_paths() {
        use crate::task::{FD_CLOEXEC, FdTable};
        use alloc::sync::Arc;
        let mut t: FdTable<u32> = FdTable::new();
        let f = Arc::new(7u32);
        for want in 0..200 {
            assert_eq!(t.alloc(f.clone(), u64::MAX), Ok(want));
        }
        t.close_range(10, 19);
        assert_eq!(t.alloc(f.clone(), u64::MAX), Ok(10));
        assert!(t.close(5));
        assert_eq!(t.alloc_at_or_above(f.clone(), 3, 0, u64::MAX), Ok(5));
        assert_eq!(
            t.alloc_at_with_flags(11, f.clone(), FD_CLOEXEC, u64::MAX),
            Ok(())
        );
        assert_eq!(t.alloc_at_with_flags(11, f.clone(), 0, u64::MAX), Err(9));
        assert!(t.alloc_at(300, f.clone()));
        let c = t.deep_clone();
        assert_eq!(c.count(), t.count());
        t.cloexec_range(150, 199);
        let mut e = t.exec_copy();
        assert_eq!(e.alloc(f.clone(), u64::MAX), Ok(11));
        assert_eq!(e.alloc(f.clone(), u64::MAX), Ok(12));
        assert_eq!(e.alloc_at_or_above(f.clone(), 100, 0, u64::MAX), Ok(150));
        assert_eq!(t.alloc_at_or_above(f.clone(), 100, 0, u64::MAX), Ok(200));
        assert_eq!(t.alloc_at_or_above(f.clone(), 100, 0, 201), Err(24));
        t.close_range(0, i32::MAX);
        assert_eq!(t.count(), 0);
        assert_eq!(t.alloc(f.clone(), u64::MAX), Ok(0));
    }

    #[test]
    fn matches_linear() {
        // xorshift: deterministic pseudo-random set/clear churn
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut b = OpenFds::new();
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let fd = (x % 9000) as usize;
            if x & (1 << 40) != 0 {
                assert!(b.set(fd));
            } else {
                b.clear(fd);
            }
            let start = ((x >> 20) % 9100) as usize;
            assert_eq!(b.find(start), slow(&b, start));
            if x & (1 << 41) != 0 {
                let want = slow(&b, start);
                assert_eq!(b.alloc(start, u64::MAX), Ok(want));
            }
            assert_eq!(b.find(0), slow(&b, 0));
        }
    }
}
