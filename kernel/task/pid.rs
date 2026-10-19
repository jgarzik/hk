//! Process identifiers (Linux kernel/pid.c, the 4.14 pidmap design)
//!
//! A [`Pid`] is one number per pid namespace level, from the root
//! namespace down to the one the task was created in (`numbers[0]` is
//! the global number, the task's tid). Numbers come from a bitmap per
//! namespace, handed out cyclically like Linux alloc_pidmap (up to
//! PID_MAX_LIMIT before wrapping); a 4 KB page
//! of the bitmap (32768 ids) is allocated on first use, outside every
//! lock, and installed with compare-and-swap, and bits are set and
//! cleared atomically, so allocation takes no lock.
//!
//! Every number of every live `Pid` is in one global hash keyed by
//! (namespace, number) for lookups (`find_pid`). Its chains are
//! intrusive (each `UPid` links to the next), protected by
//! `PIDMAP_LOCK` (spin leaf, thread context only; nothing allocates under
//! it). The hash holds a weak reference per number: a lookup takes a
//! strong one only while the `Pid` is alive, and the last drop unhashes
//! it and frees its numbers.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicI64, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::ns::PidNamespace;
use crate::sync::spin::Mutex;

/// Ids per bitmap page (Linux BITS_PER_PAGE)
const PER_PAGE: u32 = 4096 * 8;
/// Linux PID_MAX_LIMIT (64-bit): numbers are handed out up to it before
/// they wrap, so a freed number is not reused soon (raw tids still name
/// tasks in places: ptrace and parent links until the tasklist
/// conversion)
const PID_MAX_LIMIT: u32 = 4 * 1024 * 1024;
/// After a wrap, numbers restart above these (Linux RESERVED_PIDS)
const RESERVED_PIDS: u32 = 300;

/// One namespace's number of a [`Pid`] (Linux struct upid)
pub struct UPid {
    pub nr: u32,
    pub ns: Arc<PidNamespace>,
    /// Next number in this hash chain (under PIDMAP_LOCK)
    next: AtomicPtr<UPid>,
    /// The `Pid` this number belongs to, as a `Weak::into_raw` pointer
    /// (set once the `Pid` is in its `Arc`)
    pid: AtomicPtr<Pid>,
}

/// A process identifier (Linux struct pid)
pub struct Pid {
    /// Level of the namespace it was created in (0 = root)
    pub level: u32,
    /// Its number at each level, root first
    numbers: Box<[UPid]>,
    /// The task it names (Linux pid->tasks[PIDTYPE_PID]): a
    /// `*const KernelTask` set and cleared under TASKLIST's write lock
    /// while the task is in the task list
    task: AtomicPtr<()>,
    /// pidfd pollers of the process this pid leads (Linux wait_pidfd)
    pub wait_pidfd: crate::waitqueue::WaitQueue,
    /// The process's wait status once all its threads have exited;
    /// ALIVE before
    exit: AtomicI64,
}

/// `Pid.exit` of a process that still runs
const ALIVE: i64 = i64::MIN;

impl Pid {
    /// The global number (root namespace): the tid
    pub fn nr(&self) -> u32 {
        self.numbers[0].nr
    }

    /// Its number in `ns`, if it is visible there (Linux pid_nr_ns)
    pub fn nr_in(&self, ns: &PidNamespace) -> Option<u32> {
        let u = self.numbers.get(ns.level as usize)?;
        core::ptr::eq(Arc::as_ptr(&u.ns), ns).then_some(u.nr)
    }

    /// The process it leads has exited: its wait status
    pub fn exited(&self) -> Option<i32> {
        let v = self.exit.load(Ordering::Acquire);
        (v != ALIVE).then_some(v as i32)
    }

    /// Its process has exited with `status` (the last thread's exit):
    /// pidfd pollers wake (Linux do_notify_pidfd)
    pub fn set_exited(&self, status: i32) {
        self.exit.store(status as i64, Ordering::Release);
        self.wait_pidfd.wake_all();
    }

    /// The task it names (null if none: not yet attached, or released)
    pub fn task(&self) -> *const () {
        self.task.load(Ordering::Acquire)
    }

    /// Attach (non-null) or detach (null) its task; TASKLIST held for
    /// writing
    pub fn set_task(&self, t: *const ()) {
        self.task.store(t as *mut (), Ordering::Release);
    }

    /// The namespace it was created in
    pub fn ns(&self) -> &Arc<PidNamespace> {
        &self.numbers[self.level as usize].ns
    }
}

/// The bitmap of a namespace's numbers (Linux struct pidmap array)
pub struct PidMap {
    /// Numbers are below this (Linux pid_max)
    max: u32,
    /// Bitmap pages, allocated on first use
    pages: Box<[AtomicPtr<[AtomicU64; 512]>]>,
    /// Last number handed out (cyclic allocation)
    last: AtomicU32,
}

impl PidMap {
    pub fn new() -> Self {
        let max = PID_MAX_LIMIT;
        let pages = (0..max.div_ceil(PER_PAGE))
            .map(|_| AtomicPtr::new(core::ptr::null_mut()))
            .collect();
        Self {
            max,
            pages,
            last: AtomicU32::new(0),
        }
    }

    /// The bitmap page of `nr`, allocated if missing (no lock held)
    fn page(&self, nr: u32) -> Option<&[AtomicU64; 512]> {
        let slot = self.pages.get((nr / PER_PAGE) as usize)?;
        let mut p = slot.load(Ordering::Acquire);
        if p.is_null() {
            let new = Box::into_raw(Box::new([const { AtomicU64::new(0) }; 512]));
            match slot.compare_exchange(
                core::ptr::null_mut(),
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => p = new,
                Err(cur) => {
                    // SAFETY: ours, never published
                    drop(unsafe { Box::from_raw(new) });
                    p = cur;
                }
            }
        }
        // SAFETY: installed pages live as long as the map
        Some(unsafe { &*p })
    }

    /// Take `nr` if it is free
    fn take(&self, nr: u32) -> bool {
        let Some(page) = self.page(nr) else {
            return false;
        };
        let off = nr % PER_PAGE;
        let bit = 1u64 << (off % 64);
        page[(off / 64) as usize].fetch_or(bit, Ordering::AcqRel) & bit == 0
    }

    /// Give `nr` back
    fn free(&self, nr: u32) {
        if let Some(page) = self.page(nr) {
            let off = nr % PER_PAGE;
            page[(off / 64) as usize].fetch_and(!(1u64 << (off % 64)), Ordering::AcqRel);
        }
    }

    /// The next free number after the last one handed out, wrapping to
    /// RESERVED_PIDS (Linux alloc_pidmap); None if every one is taken
    fn alloc(&self) -> Option<u32> {
        let start = self.last.load(Ordering::Relaxed);
        let mut nr = start;
        for _ in 0..self.max {
            nr += 1;
            if nr >= self.max {
                nr = RESERVED_PIDS.min(self.max - 1);
            }
            if self.take(nr) {
                self.last.store(nr, Ordering::Relaxed);
                return Some(nr);
            }
        }
        None
    }
}

impl Default for PidMap {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PidMap {
    fn drop(&mut self) {
        for p in self.pages.iter() {
            let p = p.load(Ordering::Relaxed);
            if !p.is_null() {
                // SAFETY: allocated by `page`, freed once here
                drop(unsafe { Box::from_raw(p) });
            }
        }
    }
}

/// Hash buckets (power of two)
const BUCKETS: usize = 4096;

/// The pid hash: chains of `UPid`s (Linux pid_hash)
static HASH: [AtomicPtr<UPid>; BUCKETS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; BUCKETS];

/// Protects the hash chains (Linux pidmap_lock; spin leaf, thread
/// context, nothing allocates under it)
static PIDMAP_LOCK: Mutex<()> = Mutex::new(());

fn bucket(ns: &PidNamespace, nr: u32) -> &'static AtomicPtr<UPid> {
    let h = (ns as *const PidNamespace as usize >> 4) ^ (nr as usize).wrapping_mul(0x9e37_79b9);
    &HASH[h & (BUCKETS - 1)]
}

/// A new `Pid` in `ns` and each ancestor namespace (Linux alloc_pid);
/// None if a namespace has no number left (EAGAIN)
pub fn alloc_pid(ns: &Arc<PidNamespace>) -> Option<Arc<Pid>> {
    alloc_pid_nr(ns, None)
}

/// `alloc_pid` with the root number chosen (init: 1)
pub fn alloc_pid_nr(ns: &Arc<PidNamespace>, root_nr: Option<u32>) -> Option<Arc<Pid>> {
    let mut chain = alloc::vec::Vec::new();
    let mut n = Some(ns.clone());
    while let Some(cur) = n {
        n = cur.parent.clone();
        chain.push(cur);
    }
    chain.reverse(); // root first
    let mut numbers = alloc::vec::Vec::with_capacity(chain.len());
    for (level, ns) in chain.into_iter().enumerate() {
        let nr = match root_nr {
            Some(nr) if level == 0 => ns.map.take(nr).then_some(nr),
            _ => ns.map.alloc(),
        };
        let Some(nr) = nr else {
            for u in &numbers {
                let u: &UPid = u;
                u.ns.map.free(u.nr);
            }
            return None;
        };
        numbers.push(UPid {
            nr,
            ns,
            next: AtomicPtr::new(core::ptr::null_mut()),
            pid: AtomicPtr::new(core::ptr::null_mut()),
        });
    }
    let pid = Arc::new(Pid {
        level: numbers.len() as u32 - 1,
        numbers: numbers.into_boxed_slice(),
        task: AtomicPtr::new(core::ptr::null_mut()),
        wait_pidfd: crate::waitqueue::WaitQueue::new(),
        exit: AtomicI64::new(ALIVE),
    });
    let _g = PIDMAP_LOCK.lock();
    for u in pid.numbers.iter() {
        let weak = Weak::into_raw(Arc::downgrade(&pid)) as *mut Pid;
        u.pid.store(weak, Ordering::Relaxed);
        let b = bucket(&u.ns, u.nr);
        u.next.store(b.load(Ordering::Relaxed), Ordering::Relaxed);
        b.store(u as *const UPid as *mut UPid, Ordering::Release);
    }
    Some(pid)
}

/// The live `Pid` numbered `nr` in `ns` (Linux find_pid_ns)
pub fn find_pid(ns: &PidNamespace, nr: u32) -> Option<Arc<Pid>> {
    let _g = PIDMAP_LOCK.lock();
    let mut u = bucket(ns, nr).load(Ordering::Acquire);
    // SAFETY: hashed UPids live until unhashed under PIDMAP_LOCK
    while let Some(up) = unsafe { u.as_ref() } {
        if up.nr == nr && core::ptr::eq(Arc::as_ptr(&up.ns), ns) {
            let p = up.pid.load(Ordering::Relaxed);
            // SAFETY: the hash's weak reference keeps the allocation;
            // upgrade fails once the last strong one is gone
            let weak = core::mem::ManuallyDrop::new(unsafe { Weak::from_raw(p) });
            return weak.upgrade();
        }
        u = up.next.load(Ordering::Relaxed);
    }
    None
}

impl Drop for Pid {
    /// Unhash every number and free it (Linux free_pid)
    fn drop(&mut self) {
        let mut weaks = [core::ptr::null_mut::<Pid>(); 33];
        {
            let _g = PIDMAP_LOCK.lock();
            for (i, u) in self.numbers.iter().enumerate() {
                let b = bucket(&u.ns, u.nr);
                let me = u as *const UPid as *mut UPid;
                let mut link = b;
                loop {
                    let cur = link.load(Ordering::Relaxed);
                    if cur.is_null() {
                        break;
                    }
                    if cur == me {
                        link.store(u.next.load(Ordering::Relaxed), Ordering::Release);
                        break;
                    }
                    // SAFETY: hashed, under PIDMAP_LOCK
                    link = unsafe { &(*cur).next };
                }
                if let Some(w) = weaks.get_mut(i) {
                    *w = u.pid.load(Ordering::Relaxed);
                }
            }
        }
        for u in self.numbers.iter() {
            u.ns.map.free(u.nr);
        }
        for w in weaks.into_iter().filter(|w| !w.is_null()) {
            // SAFETY: the hash's weak references, released once here
            drop(unsafe { Weak::from_raw(w) });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_cyclic_and_reserved() {
        let m = PidMap::new();
        assert!(m.take(1));
        assert!(!m.take(1));
        // Cyclic: after the last one handed out (0), 1 is taken, so 2
        assert_eq!(m.alloc(), Some(2));
        assert_eq!(m.alloc(), Some(3));
        m.free(1);
        assert!(m.take(1));
        // Wraps past the end to RESERVED_PIDS
        m.last.store(m.max - 1, Ordering::Relaxed);
        assert_eq!(m.alloc(), Some(RESERVED_PIDS));
    }
}
