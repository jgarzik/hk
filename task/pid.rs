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

use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, box_nofail, try_arc, try_box};
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::ns::PidNamespace;
use crate::sync::spin::Mutex;
use crate::task::TableCell;
use crate::task::percpu::{PgrpLink, SessionLink};
use crate::util::list::List;

/// Ids per bitmap page (Linux BITS_PER_PAGE)
const PER_PAGE: u32 = 4096 * 8;
/// Linux PID_MAX_LIMIT (64-bit): numbers are handed out up to it before
/// they wrap, so a freed number is not reused soon (raw tids still name
/// tasks in places: ptrace and parent links until the tasklist
/// conversion)
pub const PID_MAX_LIMIT: u32 = 4 * 1024 * 1024;
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
    /// `*const Task` set and cleared under TASKLIST's write lock
    /// while the task is in the task list
    task: AtomicPtr<()>,
    /// The process group whose id this is: its member processes'
    /// group leaders (Linux pid->tasks[PIDTYPE_PGID]; links
    /// `Task.pgrp_link`), changed under TASKLIST's write lock and
    /// walked under its read lock. Every thread of a member holds a
    /// reference to this `Pid` (`TaskInner.pgrp`), so it outlives its
    /// group.
    pub(crate) pgrp: TableCell<List<PgrpLink>>,
    /// The session whose id this is, likewise (Linux
    /// pid->tasks[PIDTYPE_SID]; links `Task.session_link`)
    pub(crate) session: TableCell<List<SessionLink>>,
    /// pidfd pollers of the task it names (Linux wait_pidfd): woken
    /// under TASKLIST when it exits and when it is released
    pub wait_pidfd: crate::sync::waitqueue::WaitQueue,
    /// Execs the process it leads has done (Linux self_exec_id, which
    /// the leader carries): what it registered before an exec is not
    /// delivered after it
    exec_gen: AtomicU64,
    /// Its numbers are hashed and taken: from alloc until the last task
    /// leaves it (`release_numbers`, Linux free_pid) or it is dropped;
    /// changed under PIDMAP_LOCK, which orders it
    hashed: AtomicBool,
}

impl Pid {
    /// The global number (root namespace): the tid
    pub fn nr(&self) -> u32 {
        self.numbers[0].nr
    }

    /// Its number in `ns`, if it is visible there
    pub fn nr_in(&self, ns: &PidNamespace) -> Option<u32> {
        let u = self.numbers.get(ns.level as usize)?;
        core::ptr::eq(Arc::as_ptr(&u.ns), ns).then_some(u.nr)
    }

    /// Its number in `ns`, 0 if it is not visible there (Linux
    /// pid_nr_ns)
    pub fn nr_ns(&self, ns: &PidNamespace) -> u32 {
        self.nr_in(ns).unwrap_or(0)
    }

    /// Its number in the caller's namespace, 0 if not visible (Linux
    /// pid_vnr)
    pub fn vnr(&self) -> u32 {
        self.nr_ns(current_pid_ns())
    }

    /// Execs of the process it leads
    pub fn exec_gen(&self) -> u64 {
        self.exec_gen.load(Ordering::Acquire)
    }

    /// The process it leads exec'd (its point of no return)
    pub fn exec_done(&self) {
        self.exec_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// The task it names (null if none: not yet attached, or released)
    pub fn task(&self) -> *const () {
        self.task.load(Ordering::Acquire)
    }

    /// Attach (non-null) or detach (null) its task; TASKLIST held for
    /// writing
    pub fn set_task(&self, t: *const ()) {
        self.task.store(t.cast_mut(), Ordering::Release);
    }

    /// Its numbers, one per level from the root (Linux pid->numbers)
    pub fn numbers(&self) -> &[UPid] {
        &self.numbers
    }

    /// The namespace it was created in
    pub fn ns(&self) -> &Arc<PidNamespace> {
        &self.numbers[self.level as usize].ns
    }

    /// It is 1 in the namespace it was made in: its process is that
    /// namespace's init (Linux is_child_reaper)
    pub fn is_child_reaper(&self) -> bool {
        self.numbers[self.level as usize].nr == 1
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
    /// The number handed out last (Linux idr_get_cursor - 1)
    pub fn last(&self) -> u32 {
        self.last.load(Ordering::Relaxed)
    }

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

    /// The bitmap page of `nr`, allocated if missing (no lock held):
    /// None past the end, ENOMEM
    fn page(&self, nr: u32) -> Result<Option<&[AtomicU64; 512]>, KernelError> {
        let Some(slot) = self.pages.get((nr / PER_PAGE) as usize) else {
            return Ok(None);
        };
        let mut p = slot.load(Ordering::Acquire);
        if p.is_null() {
            let new = Box::into_raw(try_box([const { AtomicU64::new(0) }; 512])?);
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
        Ok(Some(unsafe { &*p }))
    }

    /// The bitmap page of `nr` if it is installed
    fn page_if(&self, nr: u32) -> Option<&[AtomicU64; 512]> {
        let p = self
            .pages
            .get((nr / PER_PAGE) as usize)?
            .load(Ordering::Acquire);
        // SAFETY: installed pages live as long as the map
        (!p.is_null()).then(|| unsafe { &*p })
    }

    /// Take `nr` if it is free; ENOMEM
    fn take(&self, nr: u32) -> Result<bool, KernelError> {
        let Some(page) = self.page(nr)? else {
            return Ok(false);
        };
        let off = nr % PER_PAGE;
        let bit = 1u64 << (off % 64);
        Ok(page[(off / 64) as usize].fetch_or(bit, Ordering::AcqRel) & bit == 0)
    }

    /// Give `nr` back (a taken number's page is installed)
    fn free(&self, nr: u32) {
        if let Some(page) = self.page_if(nr) {
            let off = nr % PER_PAGE;
            page[(off / 64) as usize].fetch_and(!(1u64 << (off % 64)), Ordering::AcqRel);
        }
    }

    /// The next free number after the last one handed out, wrapping to
    /// RESERVED_PIDS (Linux alloc_pidmap); None if every one is taken,
    /// ENOMEM
    fn alloc(&self) -> Result<Option<u32>, KernelError> {
        let start = self.last.load(Ordering::Relaxed);
        let mut nr = start;
        for _ in 0..self.max {
            nr += 1;
            if nr >= self.max {
                nr = RESERVED_PIDS.min(self.max - 1);
            }
            if self.take(nr)? {
                self.last.store(nr, Ordering::Relaxed);
                return Ok(Some(nr));
            }
        }
        Ok(None)
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
    let h = (core::ptr::from_ref::<PidNamespace>(ns) as usize >> 4)
        ^ (nr as usize).wrapping_mul(0x9e37_79b9);
    &HASH[h & (BUCKETS - 1)]
}

/// A new `Pid` in `ns` and each ancestor namespace (Linux alloc_pid);
/// EAGAIN if a namespace has no number left, ENOMEM
pub fn alloc_pid(ns: &Arc<PidNamespace>) -> Result<Arc<Pid>, KernelError> {
    alloc_pid_nr(ns, &[])
}

/// The numbers taken so far, given back on an error
fn free_numbers(numbers: &[UPid]) {
    for u in numbers {
        u.ns.map.free(u.nr);
    }
}

/// `alloc_pid` with the numbers of the innermost `set_tid.len()`
/// levels chosen, `ns`'s first (Linux alloc_pid's set_tid: clone3,
/// init's 1): EEXIST if one is taken. The caller checked them (at most
/// one per level, each in 1..PID_MAX_LIMIT).
pub fn alloc_pid_nr(ns: &Arc<PidNamespace>, set_tid: &[u32]) -> Result<Arc<Pid>, KernelError> {
    let mut chain = alloc::vec::Vec::new();
    let mut n = Some(ns.clone());
    while let Some(cur) = n {
        n = cur.parent.clone();
        chain.push(cur);
    }
    chain.reverse(); // root first
    let mut numbers = alloc::vec::Vec::with_capacity(chain.len());
    let top = chain.len() - 1;
    for (level, ns) in chain.into_iter().enumerate() {
        let chosen = set_tid.get(top - level).copied();
        let nr = match chosen {
            Some(nr) => ns.map.take(nr).map(|t| t.then_some(nr)),
            None => ns.map.alloc(),
        };
        let nr = match nr {
            Ok(Some(nr)) => nr,
            Ok(None) => {
                free_numbers(&numbers);
                return Err(if chosen.is_some() {
                    KernelError::AlreadyExists
                } else {
                    KernelError::WouldBlock
                });
            }
            Err(e) => {
                free_numbers(&numbers);
                return Err(e);
            }
        };
        numbers.push(UPid {
            nr,
            ns,
            next: AtomicPtr::new(core::ptr::null_mut()),
            pid: AtomicPtr::new(core::ptr::null_mut()),
        });
    }
    if let Err(e) = admit(&numbers) {
        free_numbers(&numbers);
        return Err(e);
    }
    // Counted now: on failure the unbuilt Pid's Drop uncounts it and
    // gives its numbers back (it was never hashed)
    let pid = try_arc(Pid {
        level: numbers.len() as u32 - 1,
        numbers: numbers.into_boxed_slice(),
        task: AtomicPtr::new(core::ptr::null_mut()),
        pgrp: TableCell::new(List::new()),
        session: TableCell::new(List::new()),
        wait_pidfd: crate::sync::waitqueue::WaitQueue::new(),
        exec_gen: AtomicU64::new(0),
        hashed: AtomicBool::new(true),
    })?;
    let _g = PIDMAP_LOCK.lock();
    for u in pid.numbers.iter() {
        let weak = Weak::into_raw(Arc::downgrade(&pid)).cast_mut();
        u.pid.store(weak, Ordering::Relaxed);
        let b = bucket(&u.ns, u.nr);
        u.next.store(b.load(Ordering::Relaxed), Ordering::Relaxed);
        b.store(core::ptr::from_ref::<UPid>(u).cast_mut(), Ordering::Release);
    }
    Ok(pid)
}

/// Count `numbers` in their namespaces (Linux alloc_pid under
/// pidmap_lock): EINVAL if a namespace with no init yet would get a
/// number other than 1 (pid 1 is made first), ENOMEM if one takes no
/// new pids (its init died: PIDNS_ADDING cleared)
fn admit(numbers: &[UPid]) -> Result<(), KernelError> {
    use crate::ns::pid::{NS_ADDING, NS_INIT};
    let _g = PIDMAP_LOCK.lock();
    let state = |u: &UPid| u.ns.alloc.load(Ordering::Relaxed);
    if numbers.iter().any(|u| u.nr != 1 && state(u) & NS_INIT == 0) {
        return Err(KernelError::InvalidArgument);
    }
    if numbers.iter().any(|u| state(u) & NS_ADDING == 0) {
        return Err(KernelError::OutOfMemory);
    }
    for u in numbers {
        u.ns.alloc.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// No more pids in `ns` (Linux disable_pid_allocation): its init died
pub fn disable_pid_allocation(ns: &PidNamespace) {
    let _g = PIDMAP_LOCK.lock();
    ns.alloc
        .fetch_and(!crate::ns::pid::NS_ADDING, Ordering::Relaxed);
}

/// `ns` and every namespace above it still take new pids (Linux
/// copy_process: PIDNS_ADDING, checked again under tasklist_lock as a
/// task joins, so a zap that disabled allocation sees the task or the
/// fork fails)
pub fn ns_adding(ns: &PidNamespace) -> bool {
    let _g = PIDMAP_LOCK.lock();
    let mut n = Some(ns);
    while let Some(cur) = n {
        if cur.alloc.load(Ordering::Relaxed) & crate::ns::pid::NS_ADDING == 0 {
            return false;
        }
        n = cur.parent.as_deref();
    }
    true
}

/// The count of pids numbered in `ns` (Linux pid_allocated)
pub fn ns_pids(ns: &PidNamespace) -> u32 {
    let _g = PIDMAP_LOCK.lock();
    ns.alloc.load(Ordering::Relaxed) & crate::ns::pid::NS_PIDS
}

/// `ns` has had its init (Linux child_reaper set): a number other than
/// 1 may be made there
pub fn ns_has_init(ns: &PidNamespace) -> bool {
    let _g = PIDMAP_LOCK.lock();
    ns.alloc.load(Ordering::Relaxed) & crate::ns::pid::NS_INIT != 0
}

/// `ns`'s init joined the task list (Linux copy_process sets
/// child_reaper)
pub fn set_ns_init(ns: &PidNamespace) {
    let _g = PIDMAP_LOCK.lock();
    ns.alloc
        .fetch_or(crate::ns::pid::NS_INIT, Ordering::Relaxed);
}

/// One pid fewer in `ns` (PIDMAP_LOCK held): true if it is dying and
/// down to its init's pids (Linux free_pid: pid_allocated 2 or 1)
fn uncount(ns: &PidNamespace) -> bool {
    use crate::ns::pid::{NS_ADDING, NS_PIDS};
    let old = ns.alloc.fetch_sub(1, Ordering::Relaxed);
    old & NS_ADDING == 0 && (old & NS_PIDS) <= 3
}

/// The process group and session of the boot task, number 0 (Linux
/// init_struct_pid): never hashed, never freed; init starts in it
pub static INIT_STRUCT_PID: spin::Lazy<Arc<Pid>> = spin::Lazy::new(|| {
    // Boot-time static: failure cannot be reported
    arc_nofail(Pid {
        level: 0,
        numbers: box_nofail([UPid {
            nr: 0,
            ns: crate::ns::INIT_PID_NS.clone(),
            next: AtomicPtr::new(core::ptr::null_mut()),
            pid: AtomicPtr::new(core::ptr::null_mut()),
        }]),
        task: AtomicPtr::new(core::ptr::null_mut()),
        pgrp: TableCell::new(List::new()),
        session: TableCell::new(List::new()),
        wait_pidfd: crate::sync::waitqueue::WaitQueue::new(),
        exec_gen: AtomicU64::new(0),
        hashed: AtomicBool::new(false),
    })
});

/// The process group (or session) numbered `nr` in `ns`: 0 in the root
/// namespace is the boot one (`INIT_STRUCT_PID`)
pub fn find_pgrp(ns: &PidNamespace, nr: u64) -> Option<Arc<Pid>> {
    if nr == 0 {
        return (ns.level == 0).then(|| INIT_STRUCT_PID.clone());
    }
    find_pid(ns, u32::try_from(nr).ok()?)
}

/// The caller's pid namespace (Linux task_active_pid_ns(current)):
/// lock-free, it cannot change while the task runs
pub fn current_pid_ns() -> &'static PidNamespace {
    crate::task::percpu::current_pid_ns()
}

/// The caller's pid namespace, a counted reference to keep (Linux
/// get_pid_ns(task_active_pid_ns(current)))
pub fn get_current_pid_ns() -> Arc<PidNamespace> {
    crate::task::percpu::current().get_pid_ns()
}

/// The caller has a number in `ns`: it is in `ns` or a namespace
/// below it (Linux task_pid_nr_ns(current, ns) != 0); lock-free
pub fn current_in(ns: &PidNamespace) -> bool {
    let mut n = Some(current_pid_ns());
    while let Some(cur) = n {
        if core::ptr::eq(cur, ns) {
            return true;
        }
        if cur.level <= ns.level {
            return false;
        }
        n = cur.parent.as_deref();
    }
    false
}

/// The live `Pid` numbered `nr` in the caller's namespace (Linux
/// find_vpid)
pub fn find_vpid(nr: u32) -> Option<Arc<Pid>> {
    find_pid(current_pid_ns(), nr)
}

/// Root number `nr` (a tid, tgid, process group or session id) as `ns`
/// numbers it, 0 if not visible there (Linux pid_nr_ns of its struct
/// pid). The caller keeps its owner alive (it is the caller's own, or
/// TASKLIST is held), so the number is not reused meanwhile.
pub fn nr_ns(nr: u64, ns: &PidNamespace) -> u32 {
    let Ok(n) = u32::try_from(nr) else {
        return 0;
    };
    if ns.level == 0 {
        return n;
    }
    find_pid(&crate::ns::INIT_PID_NS, n).map_or(0, |p| p.nr_ns(ns))
}

/// Root number `nr` in the caller's namespace (Linux pid_vnr)
pub fn vnr(nr: u64) -> u32 {
    nr_ns(nr, current_pid_ns())
}

/// The root number of the caller's number `nr` (a syscall argument:
/// a tid, tgid, process group or session id), so lookups by root
/// number find what the caller names: None if no live pid has it in
/// the caller's namespace (ESRCH); in the root namespace `nr` itself
/// (Linux find_vpid, by number)
pub fn from_vnr(nr: u64) -> Option<u64> {
    let ns = current_pid_ns();
    if ns.level == 0 {
        return Some(nr);
    }
    find_pid(ns, u32::try_from(nr).ok()?).map(|p| u64::from(p.nr()))
}

/// [`from_vnr`] with 0 naming the caller (`me`), as most pid
/// arguments do
pub fn from_vnr_or(nr: u64, me: u64) -> Option<u64> {
    if nr == 0 { Some(me) } else { from_vnr(nr) }
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

impl Pid {
    /// No task uses it any more (Linux free_pid, from the last
    /// detach_pid): its numbers leave the hash and are given back, so
    /// find_pid no longer finds it and they can name a new task, while
    /// the struct lives on for its holders (a pidfd, a timer, an F_SETOWN
    /// owner, a tty's session), naming no task. Once.
    pub fn release_numbers(&self) {
        let mut weaks = [core::ptr::null_mut::<Pid>(); 33];
        let mut zapping = false;
        {
            let _g = PIDMAP_LOCK.lock();
            if !self.hashed.swap(false, Ordering::Relaxed) {
                return;
            }
            for (i, u) in self.numbers.iter().enumerate() {
                zapping |= uncount(&u.ns);
                let b = bucket(&u.ns, u.nr);
                let me = core::ptr::from_ref::<UPid>(u).cast_mut();
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
                    *w = u.pid.swap(core::ptr::null_mut(), Ordering::Relaxed);
                }
            }
        }
        for u in self.numbers.iter() {
            u.ns.map.free(u.nr);
        }
        // A dying namespace's init waits for its last pids
        // (zap_pid_ns_processes; Linux free_pid wakes child_reaper)
        if zapping {
            crate::task::proc::CHILD_EXIT_WQ.wake_all();
        }
        for w in weaks.into_iter().filter(|w| !w.is_null()) {
            // SAFETY: the hash's weak references, released once here
            // (the Pid itself is alive: the caller holds it)
            drop(unsafe { Weak::from_raw(w) });
        }
    }
}

impl Drop for Pid {
    /// Unhash every number and free it (Linux free_pid), unless the last
    /// task's detach did
    fn drop(&mut self) {
        self.release_numbers();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_cyclic_and_reserved() {
        let m = PidMap::new();
        assert_eq!(m.take(1), Ok(true));
        assert_eq!(m.take(1), Ok(false));
        // Cyclic: after the last one handed out (0), 1 is taken, so 2
        assert_eq!(m.alloc(), Ok(Some(2)));
        assert_eq!(m.alloc(), Ok(Some(3)));
        m.free(1);
        assert_eq!(m.take(1), Ok(true));
        // Wraps past the end to RESERVED_PIDS
        m.last.store(m.max - 1, Ordering::Relaxed);
        assert_eq!(m.alloc(), Ok(Some(RESERVED_PIDS)));
    }

    /// A struct pid no task uses gives its number back while it is held:
    /// not found, free to take again, not given back twice
    #[test]
    fn release_while_held() {
        let ns = &crate::ns::INIT_PID_NS;
        let p = alloc_pid(ns).unwrap();
        let nr = p.nr();
        assert!(find_pid(ns, nr).is_some());
        p.release_numbers();
        assert!(find_pid(ns, nr).is_none());
        assert_eq!(ns.map.take(nr), Ok(true));
        drop(p);
        // The number is the new owner's still
        assert_eq!(ns.map.take(nr), Ok(false));
        ns.map.free(nr);
    }
}
