//! The descriptor table itself (Linux fs/file.c: struct fdtable, the
//! part of files_struct under file_lock) and the fs.nr_open cap
//!
//! A table (`Fdt`) has `max_fds` slots, fixed when it is allocated, and
//! three bitmaps: `open` (bit `fd` set while `fd` is reserved or holds
//! a file), `cloexec`, and `full` (bit `w` set while word `w` of `open`
//! is all ones). Finding the lowest free descriptor skips full words
//! through `full`. Nothing here allocates but [`Fdt::alloc`], which the
//! caller runs with the table lock dropped (`fdtable::Files`, Linux
//! expand_fdtable / dup_fd): a table that must grow is replaced by a
//! bigger one the caller made, its contents moved over.

use super::{FD_CLOEXEC, Fd};
use crate::util::error::{KernelError, KernelResult};
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, Ordering};

const BITS: usize = u64::BITS as usize;

/// Slots of a new table (Linux NR_OPEN_DEFAULT)
pub const NR_OPEN_DEFAULT: usize = BITS;

/// fs.nr_open (Linux sysctl_nr_open): no descriptor at or above it, and
/// no RLIMIT_NOFILE hard limit above it
static NR_OPEN: AtomicU32 = AtomicU32::new(1024 * 1024);
/// Its range (Linux sysctl_nr_open_min, sysctl_nr_open_max)
const NR_OPEN_MIN: i64 = BITS as i64;
const NR_OPEN_MAX: i64 = i32::MAX as i64 & -(BITS as i64);

pub fn nr_open() -> u64 {
    u64::from(NR_OPEN.load(Ordering::Relaxed))
}

/// /proc/sys/fs files of the descriptor table
pub static FS_CTLS: &[crate::sysctl::Ctl] = &[
    crate::sysctl::Ctl {
        path: "fs/dentry-state",
        mode: 0o444,
        show: crate::fs::dentry::dentry_state,
        store: |_| Err(crate::fs::KernelError::PermissionDenied),
        text: None,
    },
    crate::sysctl::Ctl {
        path: "fs/nr_open",
        mode: 0o644,
        show: || alloc::vec![nr_open() as i64],
        store: |v| {
            crate::sysctl::range(v[0], NR_OPEN_MIN, NR_OPEN_MAX)?;
            NR_OPEN.store(v[0] as u32, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
];

/// The bits below `b` (b < 64)
fn low_mask(b: usize) -> u64 {
    (1u64 << b) - 1
}

/// First zero bit of `bits` at or above `from`, else `bits.len() * 64`
fn next_zero(bits: &[u64], from: usize) -> usize {
    let n = bits.len() * BITS;
    if from >= n {
        return n;
    }
    let mut w = from / BITS;
    let mut v = bits[w] | low_mask(from % BITS);
    while v == !0 {
        w += 1;
        if w == bits.len() {
            return n;
        }
        v = bits[w];
    }
    w * BITS + (!v).trailing_zeros() as usize
}

/// First set bit of `bits` at or above `from`, else `bits.len() * 64`
fn next_set(bits: &[u64], from: usize) -> usize {
    let n = bits.len() * BITS;
    if from >= n {
        return n;
    }
    let mut w = from / BITS;
    let mut v = bits[w] & !low_mask(from % BITS);
    while v == 0 {
        w += 1;
        if w == bits.len() {
            return n;
        }
        v = bits[w];
    }
    w * BITS + v.trailing_zeros() as usize
}

/// Last set bit of `bits` (Linux find_last_bit)
fn last_set(bits: &[u64]) -> Option<usize> {
    let w = bits.iter().rposition(|&v| v != 0)?;
    Some(w * BITS + (BITS - 1 - bits[w].leading_zeros() as usize))
}

fn test_bit(bits: &[u64], b: usize) -> bool {
    bits[b / BITS] & (1 << (b % BITS)) != 0
}

fn set(bits: &mut [u64], b: usize) {
    bits[b / BITS] |= 1 << (b % BITS);
}

fn clear(bits: &mut [u64], b: usize) {
    bits[b / BITS] &= !(1 << (b % BITS));
}

/// Set bits `lo..=hi` (Linux bitmap_set)
fn set_range(bits: &mut [u64], lo: usize, hi: usize) {
    let mut b = lo;
    while b <= hi {
        let off = b % BITS;
        let n = (BITS - off).min(hi - b + 1);
        let m = if n == BITS { !0 } else { low_mask(n) << off };
        bits[b / BITS] |= m;
        b += n;
    }
}

/// Copy the first `n` bits of `src` into `dst`, whose other bits are
/// zero (Linux bitmap_copy_and_extend)
fn copy_bits(dst: &mut [u64], src: &[u64], n: usize) {
    let w = n / BITS;
    dst[..w].copy_from_slice(&src[..w]);
    if !n.is_multiple_of(BITS) {
        dst[w] = src[w] & low_mask(n % BITS);
    }
}

/// One descriptor table (Linux struct fdtable)
pub struct Fdt<F> {
    /// The slots: None while free or reserved but not installed yet
    fd: Box<[Option<F>]>,
    /// `open`, then `cloexec` (max_fds / 64 words each), then `full`,
    /// in one block as Linux's
    bits: Box<[u64]>,
}

impl<F: Clone> Fdt<F> {
    /// A table for at least `slots_wanted` descriptors (Linux
    /// alloc_fdtable): the next power of two, at least 64; EMFILE when
    /// fs.nr_open leaves fewer than wanted or the slots would pass
    /// INT_MAX bytes, ENOMEM
    pub fn alloc(slots_wanted: usize) -> KernelResult<Self> {
        let mut nr = slots_wanted.max(NR_OPEN_DEFAULT).next_power_of_two();
        let cap = nr_open() as usize;
        if nr > cap {
            nr = cap & !(BITS - 1);
            if nr < slots_wanted {
                return Err(KernelError::ProcessFileLimit);
            }
        }
        if nr > i32::MAX as usize / core::mem::size_of::<usize>() {
            return Err(KernelError::ProcessFileLimit);
        }
        let words = nr / BITS;
        let fd = crate::util::kmem::try_vec(nr, None)?.into_boxed_slice();
        let bits = crate::util::kmem::try_vec(2 * words + words.div_ceil(BITS), 0u64)?;
        Ok(Self {
            fd,
            bits: bits.into_boxed_slice(),
        })
    }
}

impl<F> Fdt<F> {
    /// Its size (Linux fdtable->max_fds), a multiple of 64
    pub fn max_fds(&self) -> usize {
        self.fd.len()
    }

    fn words(&self) -> usize {
        self.fd.len() / BITS
    }

    fn open(&self) -> &[u64] {
        &self.bits[..self.words()]
    }

    fn cloexec(&self) -> &[u64] {
        let w = self.words();
        &self.bits[w..2 * w]
    }

    fn full(&self) -> &[u64] {
        &self.bits[2 * self.words()..]
    }

    /// `open`, `cloexec`, `full`, mutable
    fn bits_mut(&mut self) -> (&mut [u64], &mut [u64], &mut [u64]) {
        let w = self.words();
        let (open, rest) = self.bits.split_at_mut(w);
        let (cloexec, full) = rest.split_at_mut(w);
        (open, cloexec, full)
    }

    fn is_open(&self, fd: usize) -> bool {
        test_bit(self.open(), fd)
    }

    /// Mark `fd` open, close-on-exec or not (Linux __set_open_fd)
    fn set_open(&mut self, fd: usize, cloexec: bool) {
        let (open, ce, full) = self.bits_mut();
        set(open, fd);
        if cloexec {
            set(ce, fd);
        } else {
            clear(ce, fd);
        }
        if open[fd / BITS] == !0 {
            set(full, fd / BITS);
        }
    }

    /// Mark `fd` free (Linux __clear_open_fd)
    fn clear_open(&mut self, fd: usize) {
        let (open, _, full) = self.bits_mut();
        clear(open, fd);
        clear(full, fd / BITS);
    }

    /// Lowest free descriptor at or above `start` (< max_fds), else
    /// max_fds (Linux find_next_fd: the start word first, then the
    /// words `full` says have room)
    fn find_next_fd(&self, start: usize) -> usize {
        let max = self.max_fds();
        let w = start / BITS;
        let v = self.open()[w] | low_mask(start % BITS);
        if v != !0 {
            return w * BITS + (!v).trailing_zeros() as usize;
        }
        let bitbit = next_zero(self.full(), w) * BITS;
        if bitbit >= max {
            return max;
        }
        next_zero(self.open(), start.max(bitbit))
    }

    /// Move `old`'s descriptors and bits into this bigger, empty table
    /// (Linux copy_fdtable)
    fn copy_from(&mut self, old: &mut Fdt<F>) {
        for (new, f) in self.fd.iter_mut().zip(old.fd.iter_mut()) {
            *new = f.take();
        }
        let n = old.max_fds();
        let (open, ce, full) = self.bits_mut();
        copy_bits(open, old.open(), n);
        copy_bits(ce, old.cloexec(), n);
        copy_bits(full, old.full(), n / BITS);
    }
}

/// What [`FdTable::alloc_fd`] found
#[derive(Debug, PartialEq, Eq)]
pub enum Slot {
    /// This descriptor is now reserved
    Fd(Fd),
    /// The table must first grow to hold this one (Linux expand_files)
    Expand(usize),
}

/// A task's descriptors (Linux files_struct: the current fdtable and
/// next_fd, under file_lock). A descriptor is free, reserved (open bit
/// set, no file: between get_unused_fd_flags and fd_install, invisible
/// to lookups) or installed.
pub struct FdTable<F> {
    fdt: Fdt<F>,
    /// No descriptor below this is free (Linux files_struct.next_fd)
    next_fd: usize,
    /// A task is allocating a bigger table with the lock dropped; others
    /// that need one wait for it (Linux files_struct.resize_in_progress,
    /// `fdtable::Files::expand_files`)
    pub(super) resize_in_progress: bool,
}

impl<F: Clone> FdTable<F> {
    /// An empty table in `fdt`
    pub fn new(fdt: Fdt<F>) -> Self {
        Self {
            fdt,
            next_fd: 0,
            resize_in_progress: false,
        }
    }

    /// Descriptors the table has room for (Linux fdtable->max_fds)
    pub fn max_fds(&self) -> usize {
        self.fdt.max_fds()
    }

    /// The file installed at `fd`
    fn slot(&self, fd: Fd) -> Option<&F> {
        let i = usize::try_from(fd).ok()?;
        self.fdt.fd.get(i)?.as_ref()
    }

    /// A reference to the file at `fd` (Linux files_lookup_fd_locked)
    pub fn get(&self, fd: Fd) -> Option<F> {
        self.slot(fd).cloned()
    }

    /// A file is installed at `fd`
    pub fn is_valid(&self, fd: Fd) -> bool {
        self.slot(fd).is_some()
    }

    /// The descriptor flags of `fd`: FD_CLOEXEC or 0 (Linux
    /// get_close_on_exec)
    pub fn get_fd_flags(&self, fd: Fd) -> u32 {
        match usize::try_from(fd) {
            Ok(i) if i < self.max_fds() && test_bit(self.fdt.cloexec(), i) => FD_CLOEXEC,
            _ => 0,
        }
    }

    /// Set the descriptor flags of `fd` (only FD_CLOEXEC is one, Linux
    /// set_close_on_exec); false if no file is installed there
    pub fn set_fd_flags(&mut self, fd: Fd, flags: u32) -> bool {
        if !self.is_valid(fd) {
            return false;
        }
        let (_, ce, _) = self.fdt.bits_mut();
        if flags & FD_CLOEXEC != 0 {
            set(ce, fd as usize);
        } else {
            clear(ce, fd as usize);
        }
        true
    }

    /// Reserve the lowest free descriptor at or above `start` and below
    /// `end` (RLIMIT_NOFILE), with FD_CLOEXEC from `flags` (Linux
    /// alloc_fd): EMFILE at or past `end`; `Slot::Expand` when the table
    /// is too small, to grow and retry
    pub fn alloc_fd(&mut self, start: usize, flags: u32, end: u64) -> KernelResult<Slot> {
        let max = self.max_fds();
        let mut fd = start.max(self.next_fd);
        if fd < max {
            fd = self.fdt.find_next_fd(fd);
        }
        if fd as u64 >= end {
            return Err(KernelError::ProcessFileLimit);
        }
        if fd >= max {
            return Ok(Slot::Expand(fd));
        }
        if start <= self.next_fd {
            self.next_fd = fd + 1;
        }
        self.fdt.set_open(fd, flags & FD_CLOEXEC != 0);
        // fd < max_fds <= fs.nr_open <= i32::MAX
        Ok(Slot::Fd(fd as Fd))
    }

    /// Whether descriptor `nr` needs a bigger table (Linux expand_files'
    /// checks): EMFILE at or past fs.nr_open
    pub fn need_expand(&self, nr: usize) -> KernelResult<bool> {
        if nr < self.max_fds() {
            return Ok(false);
        }
        if nr as u64 >= nr_open() {
            return Err(KernelError::ProcessFileLimit);
        }
        Ok(true)
    }

    /// Move into `new`, bigger (Linux expand_fdtable: copy_fdtable, then
    /// the new table replaces the old; under resize_in_progress nothing
    /// else grew it); the table left over, empty, is returned to free
    /// after the unlock
    #[must_use]
    pub fn expand(&mut self, mut new: Fdt<F>) -> Fdt<F> {
        if new.max_fds() <= self.max_fds() {
            return new;
        }
        new.copy_from(&mut self.fdt);
        core::mem::replace(&mut self.fdt, new)
    }

    /// Put `file` in the reserved descriptor `fd` (Linux fd_install)
    pub fn install(&mut self, fd: Fd, file: F) {
        let i = fd as usize;
        // A kernel bug otherwise: fd is not reserved, or already holds a
        // file (Linux VFS_BUG_ON)
        assert!(self.fdt.is_open(i) && self.fdt.fd[i].is_none());
        self.fdt.fd[i] = Some(file);
    }

    /// Release the reserved or closed descriptor `fd` (Linux
    /// __put_unused_fd)
    pub fn put_unused(&mut self, fd: Fd) {
        let i = fd as usize;
        self.fdt.clear_open(i);
        self.next_fd = self.next_fd.min(i);
    }

    /// Detach the file at `fd` and free the descriptor, the caller
    /// releasing the file after the unlock (Linux file_close_fd_locked);
    /// None (EBADF) if no file is installed there, a reservation too
    pub fn close_fd(&mut self, fd: Fd) -> Option<F> {
        let i = usize::try_from(fd).ok()?;
        let f = self.fdt.fd.get_mut(i)?.take()?;
        self.put_unused(fd);
        Some(f)
    }

    /// Install `file` at `fd`, below max_fds, taking out the file there
    /// before, if any, for the caller to close after the unlock (Linux
    /// do_dup2): EBUSY for a descriptor reserved but not installed yet
    pub fn dup2(&mut self, fd: usize, file: F, flags: u32) -> KernelResult<Option<F>> {
        if self.fdt.fd[fd].is_none() && self.fdt.is_open(fd) {
            return Err(KernelError::Busy);
        }
        let tofree = self.fdt.fd[fd].replace(file);
        self.fdt.set_open(fd, flags & FD_CLOEXEC != 0);
        Ok(tofree)
    }

    /// Detach the lowest installed descriptor in `from..=hi` (Linux
    /// __range_close, one descriptor per lock hold; reserved ones are
    /// passed over)
    pub fn close_next(&mut self, from: usize, hi: usize) -> Option<(usize, F)> {
        let end = hi.min(self.max_fds() - 1);
        let mut fd = from;
        loop {
            fd = next_set(self.fdt.open(), fd);
            if fd > end {
                return None;
            }
            if let Some(f) = self.close_fd(fd as Fd) {
                return Some((fd, f));
            }
            fd += 1;
        }
    }

    /// The lowest close-on-exec descriptor at or above `from`, its flag
    /// cleared and its file, if one is installed, detached (Linux
    /// do_close_on_exec, one descriptor per lock hold)
    pub fn take_cloexec(&mut self, from: usize) -> Option<(usize, Option<F>)> {
        let fd = next_set(self.fdt.cloexec(), from);
        if fd >= self.max_fds() {
            return None;
        }
        let (_, ce, _) = self.fdt.bits_mut();
        clear(ce, fd);
        Some((fd, self.close_fd(fd as Fd)))
    }

    /// Set close-on-exec on `lo..=hi`, open or not (Linux __range_cloexec)
    pub fn range_cloexec(&mut self, lo: usize, hi: usize) {
        let hi = hi.min(self.max_fds() - 1);
        if lo <= hi {
            let (_, ce, _) = self.fdt.bits_mut();
            set_range(ce, lo, hi);
        }
    }

    /// The lowest descriptor at or above `from` with a file installed
    pub fn next_installed(&self, from: usize) -> Option<Fd> {
        let mut fd = from;
        loop {
            fd = next_set(self.fdt.open(), fd);
            if fd >= self.max_fds() {
                return None;
            }
            if self.fdt.fd[fd].is_some() {
                return Some(fd as Fd);
            }
            fd += 1;
        }
    }

    /// Slots a copy needs: through the last open descriptor, in whole
    /// words (Linux sane_fdtable_size)
    pub fn sane_size(&self) -> usize {
        last_set(self.fdt.open()).map_or(NR_OPEN_DEFAULT, |l| (l + 1).next_multiple_of(BITS))
    }

    /// A copy in `new`, which holds at least [`sane_size`](Self::sane_size)
    /// slots (Linux dup_fd): each file gains a reference; a reserved
    /// descriptor is free in the copy
    pub fn dup_into(&self, mut new: Fdt<F>) -> Self {
        let n = self.sane_size();
        let (open, ce, full) = new.bits_mut();
        copy_bits(open, self.fdt.open(), n);
        copy_bits(ce, self.fdt.cloexec(), n);
        copy_bits(full, self.fdt.full(), n / BITS);
        for i in 0..n {
            match &self.fdt.fd[i] {
                Some(f) => new.fd[i] = Some(f.clone()),
                None => new.clear_open(i),
            }
        }
        Self::new(new)
    }

    /// Installed descriptors
    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.fdt.fd.iter().filter(|f| f.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    type T = FdTable<Arc<u32>>;

    fn table() -> T {
        FdTable::new(Fdt::alloc(NR_OPEN_DEFAULT).unwrap())
    }

    /// Grow `t` until it holds descriptor `nr` (as `Files::expand_files`)
    fn grow(t: &mut T, nr: usize) {
        while t.need_expand(nr).unwrap() {
            let spare = t.expand(Fdt::alloc(nr + 1).unwrap());
            assert_eq!(spare.fd.iter().filter(|f| f.is_some()).count(), 0);
        }
    }

    /// Reserve and install at the lowest free descriptor >= `start`
    fn add(t: &mut T, start: usize, flags: u32, end: u64, f: &Arc<u32>) -> KernelResult<Fd> {
        loop {
            match t.alloc_fd(start, flags, end)? {
                Slot::Fd(fd) => {
                    t.install(fd, f.clone());
                    return Ok(fd);
                }
                Slot::Expand(nr) => {
                    t.need_expand(nr)?;
                    grow(t, nr);
                }
            }
        }
    }

    /// Reference: linear probe for the lowest free fd >= start
    fn slow(t: &T, start: usize) -> usize {
        (start..)
            .find(|&fd| fd >= t.max_fds() || !t.fdt.is_open(fd))
            .unwrap()
    }

    #[test]
    fn sizes() {
        let t = table();
        assert_eq!(t.max_fds(), 64);
        assert_eq!(Fdt::<Arc<u32>>::alloc(65).unwrap().max_fds(), 128);
        assert_eq!(Fdt::<Arc<u32>>::alloc(1000).unwrap().max_fds(), 1024);
        let cap = nr_open() as usize;
        assert_eq!(Fdt::<Arc<u32>>::alloc(300_000).unwrap().max_fds(), cap / 2);
        assert_eq!(
            Fdt::<Arc<u32>>::alloc(cap + 1).err(),
            Some(KernelError::ProcessFileLimit)
        );
    }

    #[test]
    fn dense_fill_and_growth() {
        let mut t = table();
        let f = Arc::new(7u32);
        for want in 0..10_000 {
            assert_eq!(add(&mut t, 0, 0, u64::MAX, &f), Ok(want));
        }
        assert_eq!(t.max_fds(), 16384);
        assert_eq!(t.count(), 10_000);
        assert!(t.close_fd(4096).is_some());
        assert_eq!(add(&mut t, 0, 0, u64::MAX, &f), Ok(4096));
        assert!(t.close_fd(63).is_some());
        assert!(t.close_fd(4096).is_some());
        assert_eq!(add(&mut t, 64, 0, u64::MAX, &f), Ok(4096));
        assert_eq!(add(&mut t, 0, 0, u64::MAX, &f), Ok(63));
        // Growth kept every file
        assert_eq!(Arc::strong_count(&f), 10_001);
    }

    #[test]
    fn nr_open_cap() {
        let mut t = table();
        let cap = nr_open() as usize;
        assert_eq!(t.need_expand(cap), Err(KernelError::ProcessFileLimit));
        assert_eq!(t.need_expand(cap - 1), Ok(true));
        assert_eq!(
            t.alloc_fd(cap, 0, u64::MAX),
            Ok(Slot::Expand(cap)),
            "the cap applies when growing"
        );
    }

    #[test]
    fn limit_and_hint() {
        let mut t = table();
        let f = Arc::new(1u32);
        assert_eq!(add(&mut t, 0, 0, 3, &f), Ok(0));
        assert_eq!(add(&mut t, 0, 0, 3, &f), Ok(1));
        assert_eq!(
            add(&mut t, 10, 0, 3, &f),
            Err(KernelError::ProcessFileLimit)
        );
        assert_eq!(add(&mut t, 10, 0, 100, &f), Ok(10));
        assert_eq!(add(&mut t, 0, 0, 100, &f), Ok(2));
        assert_eq!(add(&mut t, 0, 0, 3, &f), Err(KernelError::ProcessFileLimit));
        t.close_fd(1);
        assert_eq!(add(&mut t, 0, 0, 3, &f), Ok(1));
        assert!(!t.is_valid(3) && t.is_valid(10));
        assert_eq!(add(&mut t, 0, 0, 100, &f), Ok(3));
        // Past the table: grows to the start descriptor
        assert_eq!(add(&mut t, 5000, 0, u64::MAX, &f), Ok(5000));
        assert_eq!(t.max_fds(), 8192);
    }

    #[test]
    fn room_below_start() {
        let mut t = table();
        let f = Arc::new(0u32);
        // Word 0 has fd 3 free; words 1..=70 are full
        for _ in 0..(71 * 64) {
            add(&mut t, 0, 0, u64::MAX, &f).unwrap();
        }
        t.close_fd(3);
        assert_eq!(t.fdt.find_next_fd(5), 71 * 64);
        assert_eq!(t.fdt.find_next_fd(0), 3);
    }

    /// A reservation is invisible to lookups, close and copies, and
    /// refuses dup2 (EBUSY) until installed or released
    #[test]
    fn reserved() {
        let mut t = table();
        let f = Arc::new(0u32);
        assert_eq!(t.alloc_fd(0, 0, u64::MAX), Ok(Slot::Fd(0)));
        assert!(t.get(0).is_none() && !t.is_valid(0));
        assert!(t.close_fd(0).is_none());
        assert_eq!(t.dup2(0, f.clone(), 0), Err(KernelError::Busy));
        assert_eq!(add(&mut t, 0, 0, u64::MAX, &f), Ok(1));
        let c = t.dup_into(Fdt::alloc(t.sane_size()).unwrap());
        assert!(c.is_valid(1) && !c.fdt.is_open(0));
        assert!(t.close_next(0, 100).is_some_and(|(fd, _)| fd == 1));
        assert!(t.close_next(0, 100).is_none());
        t.install(0, f.clone());
        assert!(t.is_valid(0));
        assert!(t.close_fd(0).is_some());
        assert_eq!(t.alloc_fd(0, 0, u64::MAX), Ok(Slot::Fd(0)));
        t.put_unused(0);
        assert_eq!(t.alloc_fd(0, 0, u64::MAX), Ok(Slot::Fd(0)));
    }

    /// The table keeps its bitmaps in step through every path
    #[test]
    fn paths() {
        let mut t = table();
        let f = Arc::new(7u32);
        for want in 0..200 {
            assert_eq!(add(&mut t, 0, 0, u64::MAX, &f), Ok(want));
        }
        for fd in 10..=19 {
            assert!(t.close_next(fd, 19).is_some());
        }
        assert_eq!(add(&mut t, 0, 0, u64::MAX, &f), Ok(10));
        assert!(t.close_fd(5).is_some());
        assert_eq!(add(&mut t, 3, 0, u64::MAX, &f), Ok(5));
        // dup2 over an open descriptor hands the old file back
        assert!(t.dup2(11, f.clone(), FD_CLOEXEC).unwrap().is_none());
        assert_eq!(t.get_fd_flags(11), FD_CLOEXEC);
        assert!(t.dup2(11, f.clone(), 0).unwrap().is_some());
        assert_eq!(t.get_fd_flags(11), 0);
        grow(&mut t, 300);
        assert!(t.dup2(300, f.clone(), 0).unwrap().is_none());
        assert_eq!(t.max_fds(), 512);
        let c = t.dup_into(Fdt::alloc(t.sane_size()).unwrap());
        assert_eq!(c.count(), t.count());
        assert_eq!(c.max_fds(), 512);
        t.range_cloexec(150, 199);
        assert_eq!(t.get_fd_flags(150), FD_CLOEXEC);
        assert_eq!(t.get_fd_flags(149), 0);
        let mut closed = 0;
        let mut fd = 0;
        while let Some((n, file)) = t.take_cloexec(fd) {
            closed += usize::from(file.is_some());
            fd = n + 1;
        }
        // 150..=199 had files; the rest of the range was not open
        assert_eq!(closed, 50);
        assert_eq!(add(&mut t, 100, 0, u64::MAX, &f), Ok(150));
        assert_eq!(t.next_installed(151), Some(300));
        let mut fd = 0;
        while let Some((n, _)) = t.close_next(fd, usize::MAX) {
            fd = n + 1;
        }
        assert_eq!(t.count(), 0);
        assert_eq!(t.next_installed(0), None);
        assert_eq!(t.sane_size(), NR_OPEN_DEFAULT);
        assert_eq!(add(&mut t, 0, 0, u64::MAX, &f), Ok(0));
        drop((t, c));
        assert_eq!(Arc::strong_count(&f), 1);
    }

    #[test]
    fn matches_linear() {
        // xorshift: deterministic pseudo-random alloc/close churn
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut t = table();
        let f = Arc::new(0u32);
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let fd = (x % 9000) as usize;
            if x & (1 << 40) != 0 {
                grow(&mut t, fd);
                if !t.is_valid(fd as Fd) {
                    assert!(t.dup2(fd, f.clone(), 0).unwrap().is_none());
                }
            } else {
                t.close_fd(fd as Fd);
            }
            let start = ((x >> 20) % 9100) as usize;
            let want = slow(&t, start);
            if x & (1 << 41) != 0 {
                assert_eq!(add(&mut t, start, 0, u64::MAX, &f), Ok(want as Fd));
            } else if start < t.max_fds() {
                assert_eq!(t.fdt.find_next_fd(start), slow(&t, start));
            }
        }
    }
}
