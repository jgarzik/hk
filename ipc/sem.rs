//! System V Semaphore Implementation
//!
//! Provides semaphore arrays for process synchronization with support for:
//! - Multiple semaphores per array
//! - Atomic multi-semaphore operations
//! - Blocking with optional timeout
//! - Automatic undo on process exit (SEM_UNDO)

use crate::util::kalloc::try_arc;
use crate::util::list::{ArcList, Link, List};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::marker::PhantomPinned;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

use crate::ipc::util::{
    IPC_PERM_READ, IPC_PERM_WRITE, IpcObject, IpcOps, KernIpcPerm, ipc_checkperm, ipcget,
};
use crate::ipc::{
    IPC_64, IPC_NOWAIT, IPC_RMID, IPC_SET, IPC_STAT, IpcNamespace, Sembuf, Semid64Ds,
    current_ipc_ns,
};
use crate::sync::spin::Mutex;
use crate::task::Task;
use crate::task::percpu::{WakeQ, current_pid};
use crate::time::TIMEKEEPER;
use crate::uaccess::{UserPtr, UserSlice};
use crate::util::error::{KernelError, KernelResult};

/// Get current time in seconds
fn current_time_secs() -> i64 {
    TIMEKEEPER.current_time().sec
}

// ============================================================================
// Semaphore Constants
// ============================================================================

/// Undo operation on exit
pub const SEM_UNDO: i16 = 0x1000;

/// semctl commands
pub const GETPID: i32 = 11;
pub const GETVAL: i32 = 12;
pub const GETALL: i32 = 13;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const SETVAL: i32 = 16;
pub const SETALL: i32 = 17;
pub const SEM_STAT: i32 = 18;
pub const SEM_INFO: i32 = 19;

/// Maximum semaphore value
pub const SEMVMX: i32 = 32767;

// ============================================================================
// Semaphore Structures and locking (Linux ipc/sem.c sem_lock)
// ============================================================================
//
// Two lock levels, as Linux:
// - each semaphore's `SemSlot.lock` (Linux sem->lock) covers its value,
//   sempid, otime, its single-operation waiters and every undo
//   structure's adjustment of it: a semop of one operation takes only
//   that lock, so different semaphores of one array do not contend;
// - `SemArray.global` (Linux sem_perm.lock) covers the multi-operation
//   waiters, `complex_count`, ctime and the array's undo structures
//   (`list_id`), and in complex mode every semaphore's data.
// Complex mode (`use_global_lock` != 0, Linux complex_mode with its
// hysteresis): a multi-operation semop, semctl, exit and removal take
// the global lock, set the flag and take and drop every semaphore lock,
// which waits out the single-operation holders; a single operation that
// then finds the flag set takes the global lock instead. The flag stays
// set while multi-operation waiters exist and for
// USE_GLOBAL_LOCK_HYSTERESIS further global holds, then is cleared with
// release; the fast path rechecks it with acquire after its semaphore
// lock (Linux SEM_BARRIER_1).
//
// Waiters are on-stack `SemQueue`s on intrusive lists (Linux
// pending_alter / pending_const, per semaphore and per array): queueing,
// completing and moving them allocates nothing.

/// Global holds before complex mode is left (Linux
/// USE_GLOBAL_LOCK_HYSTERESIS)
const USE_GLOBAL_LOCK_HYSTERESIS: u32 = 10;

/// `SemQueue.status` until a waker completes it (Linux -EINTR)
const WAITING: i32 = -1;

/// A sleeping semop (Linux struct sem_queue), pinned on its sleeper's
/// stack and linked on one pending list of its array
///
/// A waker completes it under the array's locks: it unlinks it, queues
/// the sleeper on its `WakeQ`, then stores `status` (Release) as its
/// last touch, since the sleeper may return as soon as it sees the
/// status (Acquire) and its stack frame goes. A sleeper that gives up
/// (timeout, signal, removal) unlinks it itself under the locks before
/// it returns.
struct SemQueue {
    link: Link,
    /// The sleeping task (alive while the entry is queued)
    sleeper: *const Task,
    /// Thread-group id recorded as sempid when it completes
    pid: i32,
    /// Operations to perform
    sops: Vec<Sembuf>,
    /// Does this alter semaphore values?
    alter: bool,
    /// The caller's undo structure for this array (SEM_UNDO)
    undo: Option<Arc<SemUndo>>,
    /// Index in `sops` of the operation it waits on (Linux q->blocking,
    /// for GETNCNT/GETZCNT): written and read under the array's locks
    /// (an atomic only so the entry is `Sync`)
    blocking: AtomicUsize,
    /// `WAITING`, then the result: 0 or a `KernelError` code
    status: AtomicI32,
    _pin: PhantomPinned,
}

// SAFETY: wakers use the entry under the array's locks (the link,
// `blocking`) or through `status`; `sleeper` is only dereferenced while
// the entry is queued, when the task is alive in semop
unsafe impl Sync for SemQueue {}
// SAFETY: as above
unsafe impl Send for SemQueue {}

crate::adapter!(QueueA, SemQueue, link);

impl Drop for SemQueue {
    /// Every exit path unlinks it first (or a waker did): a linked entry
    /// leaving would leave a dangling pointer on its list
    fn drop(&mut self) {
        assert!(!self.link.is_linked(), "semop queue entry still linked");
    }
}

/// The status word for `r`
fn status_code(r: KernelResult<()>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

/// The result a status word holds; a completed semop fails only with
/// these (perform_atomic_semop, freeary)
fn status_result(code: i32) -> KernelResult<()> {
    const ERRS: [KernelError; 3] = [
        KernelError::WouldBlock,
        KernelError::Range,
        KernelError::IdentifierRemoved,
    ];
    if code == 0 {
        return Ok(());
    }
    let e = ERRS.into_iter().find(|&e| e as i32 == code);
    Err(e.expect("semop status"))
}

/// Complete `q` with `r` (Linux wake_up_sem_queue_prepare): its sleeper
/// goes on `wq`, then the status store is the last touch of `q`
///
/// # Safety
/// - `q` was just unlinked from a pending list under the array's locks,
///   which the caller still holds, and its status is unset.
unsafe fn complete(q: *const SemQueue, r: KernelResult<()>, wq: &mut WakeQ) {
    // SAFETY: unlinked under the locks with its status unset: its sleeper
    // has not returned (the caller)
    let q = unsafe { &*q };
    // SAFETY: the sleeper is in semop until it sees the status
    wq.add(unsafe { &*q.sleeper });
    q.status.store(status_code(r), Ordering::Release);
}

/// One semaphore's state (Linux struct sem)
struct PerSem {
    val: i32,
    /// Last modifier (sempid)
    pid: i32,
    /// Last semop on it (Linux sem_otime; IPC_STAT reports the latest)
    otime: i64,
    /// Single-operation waiters that alter it, oldest first; they move
    /// to the array's list while multi-operation waiters exist (Linux
    /// pending_alter, merge_queues)
    pending_alter: List<QueueA>,
    /// Single-operation waits for zero (Linux pending_const)
    pending_const: List<QueueA>,
}

impl PerSem {
    const fn new() -> Self {
        Self {
            val: 0,
            pid: 0,
            otime: 0,
            pending_alter: List::new(),
            pending_const: List::new(),
        }
    }
}

/// A semaphore and its lock; `data` is reached only through `SemLock`
struct SemSlot {
    lock: Mutex<()>,
    data: UnsafeCell<PerSem>,
}

// SAFETY: `data` is only accessed through a `SemLock`, which holds this
// slot's `lock` or the array's global lock in complex mode (see above):
// one context at a time.
unsafe impl Sync for SemSlot {}

/// The array-wide state (under `SemArray.global`)
struct GlobalState {
    /// Multi-operation alter waiters, and single-operation ones while
    /// any multi-operation waiter exists (Linux sma->pending_alter)
    pending_alter: List<QueueA>,
    /// Multi-operation waits for zero (Linux sma->pending_const)
    pending_const: List<QueueA>,
    /// Multi-operation waiters queued (Linux complex_count)
    complex_count: usize,
    /// Last change time
    ctime: i64,
    /// The undo structures of this array (Linux sma->list_id)
    list_id: ArcList<UndoIdA>,
}

/// Semaphore array
pub struct SemArray {
    /// IPC permissions and ID
    pub perm: KernIpcPerm,
    /// Number of semaphores
    pub nsems: u32,
    /// The semaphores
    sems: Vec<SemSlot>,
    /// Linux sem_perm.lock
    global: Mutex<GlobalState>,
    /// Complex mode (Linux use_global_lock): written under `global`,
    /// read by the single-operation fast path without it
    use_global_lock: AtomicU32,
    /// Namespace reference
    ns: Arc<IpcNamespace>,
}

/// A pending list: one semaphore's or the array's
#[derive(Clone, Copy)]
enum Pending {
    Sem(usize),
    Array,
}

/// The array locked for an operation: one semaphore (fast path) or the
/// whole array (complex mode)
enum SemLock<'a> {
    One {
        arr: &'a SemArray,
        n: usize,
        _g: crate::sync::spin::MutexGuard<'a, ()>,
    },
    All {
        arr: &'a SemArray,
        g: crate::sync::spin::MutexGuard<'a, GlobalState>,
    },
}

impl<'a> SemLock<'a> {
    /// The array, checking that semaphore `n` is covered
    fn covering(&self, n: usize) -> &'a SemArray {
        match self {
            SemLock::One { arr, n: held, .. } => {
                assert_eq!(n, *held, "semaphore {} not locked", n);
                arr
            }
            SemLock::All { arr, .. } => arr,
        }
    }

    fn arr(&self) -> &'a SemArray {
        match self {
            SemLock::One { arr, .. } | SemLock::All { arr, .. } => arr,
        }
    }

    /// Semaphore `n`'s state: the one locked, or any in complex mode
    fn sem(&mut self, n: usize) -> &mut PerSem {
        let arr = self.covering(n);
        // SAFETY: `One` holds semaphore n's lock and saw complex mode off
        // after taking it, so no global holder touches it; `All` holds
        // the global lock in complex mode, which waited out every
        // single-semaphore holder and keeps new ones out. `&mut self`
        // makes the reference unique.
        unsafe { &mut *arr.sems[n].data.get() }
    }

    /// `un`'s adjustment of semaphore `n` (Linux un->semadj[n]), under
    /// that semaphore's lock as its value is
    fn adj<'s>(&'s mut self, un: &'s SemUndo, n: usize) -> &'s mut i16 {
        self.covering(n);
        // SAFETY: as in `sem`: semaphore n is locked for this context
        // alone, and `&mut self` makes the reference unique
        unsafe { &mut *un.semadj[n].get() }
    }

    /// Zero every undo structure's adjustment of semaphore `n`, or of
    /// all semaphores (Linux SETVAL, SETALL over sma->list_id); complex
    /// mode only
    fn clear_adj(&mut self, n: Option<usize>) {
        let SemLock::All { g, .. } = self else {
            panic!("clear_adj outside complex mode");
        };
        for un in g.list_id.iter() {
            let cells = match n {
                Some(n) => &un.semadj[n..=n],
                None => &un.semadj[..],
            };
            for c in cells {
                // SAFETY: complex mode under the global lock covers every
                // semaphore, so every adjustment
                unsafe { *c.get() = 0 };
            }
        }
    }

    /// The array-wide state (complex mode only)
    fn global(&mut self) -> Option<&mut GlobalState> {
        match self {
            SemLock::All { g, .. } => Some(g),
            SemLock::One { .. } => None,
        }
    }

    /// Multi-operation waiters (none can exist outside complex mode)
    fn complex_count(&mut self) -> usize {
        self.global().map_or(0, |g| g.complex_count)
    }

    /// A pending list; the array's are empty outside complex mode and
    /// not reachable there
    fn list(&mut self, at: Pending, alter: bool) -> Option<&mut List<QueueA>> {
        let (a, c) = match at {
            Pending::Sem(n) => {
                let s = self.sem(n);
                (&mut s.pending_alter, &mut s.pending_const)
            }
            Pending::Array => {
                let g = self.global()?;
                (&mut g.pending_alter, &mut g.pending_const)
            }
        };
        Some(if alter { a } else { c })
    }

    /// Take a pending list out, to walk it while changing the array
    fn take(&mut self, at: Pending, alter: bool) -> List<QueueA> {
        self.list(at, alter)
            .map_or_else(List::new, |l| core::mem::replace(l, List::new()))
    }

    /// Put back a list `take` gave (nothing was queued there meanwhile)
    fn put(&mut self, at: Pending, alter: bool, list: List<QueueA>) {
        match self.list(at, alter) {
            Some(l) => {
                assert!(l.is_empty(), "semop list changed while taken");
                *l = list;
            }
            None => assert!(list.is_empty(), "array list outside complex mode"),
        }
    }
}

impl Drop for SemLock<'_> {
    /// Linux sem_unlock: the global holder moves single-operation alter
    /// waiters back once no multi-operation one is left (unmerge_queues)
    /// and counts down complex mode (complexmode_tryleave)
    fn drop(&mut self) {
        let SemLock::All { arr, g } = self else {
            return;
        };
        if g.complex_count != 0 {
            return;
        }
        while let Some(q) = g.pending_alter.pop_front() {
            // SAFETY: a queued entry is live (see `SemQueue`)
            let n = unsafe { &*q }.sops[0].sem_num as usize;
            // SAFETY: complex mode, under the global lock (as `sem`)
            let s = unsafe { &mut *arr.sems[n].data.get() };
            // SAFETY: live, and just taken off its only list
            unsafe { s.pending_alter.push_back(q) };
        }
        let u = arr.use_global_lock.load(Ordering::Relaxed);
        if u == 1 {
            arr.use_global_lock.store(0, Ordering::Release);
        } else if u > 1 {
            arr.use_global_lock.store(u - 1, Ordering::Relaxed);
        }
    }
}

/// What became of a semop's operations that did not fail
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Semop {
    /// Applied, all of them
    Done,
    /// One would block; none applied
    Blocks,
}

/// Apply `sops` in order, all or nothing (Linux
/// perform_atomic_semop_slow, which also sums repeated operations on one
/// semaphore): Done when applied (sempid and otime updated), Blocks when
/// an operation would block (`blocking` is its index), or an error
/// (WouldBlock for a blocking operation with IPC_NOWAIT, Range above
/// SEMVMX or past the adjustment range). A SEM_UNDO operation also
/// changes `un`'s adjustment by its negative. Undone on anything but
/// Done.
fn perform_atomic_semop(
    l: &mut SemLock<'_>,
    sops: &[Sembuf],
    pid: i32,
    un: Option<&SemUndo>,
    blocking: &mut usize,
) -> KernelResult<Semop> {
    let undo_of = |sop: &Sembuf| un.filter(|_| sop.sem_flg & SEM_UNDO != 0);
    for (n, sop) in sops.iter().enumerate() {
        let i = sop.sem_num as usize;
        let cur = l.sem(i).val;
        let result = cur + i32::from(sop.sem_op);
        let r = if (sop.sem_op == 0 && cur != 0) || result < 0 {
            *blocking = n;
            if sop.sem_flg & IPC_NOWAIT as i16 != 0 {
                Err(KernelError::WouldBlock)
            } else {
                Ok(Semop::Blocks)
            }
        } else if result > SEMVMX {
            Err(KernelError::Range)
        } else if let Some(un) = undo_of(sop) {
            // The adjustment must stay in -SEMAEM-1..=SEMAEM
            let adj = l.adj(un, i);
            match i16::try_from(i32::from(*adj) - i32::from(sop.sem_op)) {
                Ok(v) => {
                    *adj = v;
                    l.sem(i).val = result;
                    continue;
                }
                Err(_) => Err(KernelError::Range),
            }
        } else {
            l.sem(i).val = result;
            continue;
        };
        for done in sops[..n].iter().rev() {
            let i = done.sem_num as usize;
            l.sem(i).val -= i32::from(done.sem_op);
            if let Some(un) = undo_of(done) {
                *l.adj(un, i) += done.sem_op;
            }
        }
        return r;
    }
    let now = current_time_secs();
    for sop in sops {
        let s = l.sem(sop.sem_num as usize);
        s.pid = pid;
        s.otime = now;
    }
    Ok(Semop::Done)
}

/// Retry `q` (a linked entry); its blocking index is updated if it
/// still blocks
fn retry(l: &mut SemLock<'_>, q: &SemQueue) -> KernelResult<Semop> {
    let mut blocking = 0;
    let r = perform_atomic_semop(l, &q.sops, q.pid, q.undo.as_deref(), &mut blocking);
    if r == Ok(Semop::Blocks) {
        q.blocking.store(blocking, Ordering::Relaxed);
    }
    r
}

/// A waker took `q` off a list it walks (Linux unlink_queue's count)
fn unlinked(l: &mut SemLock<'_>, q: &SemQueue) {
    if q.sops.len() > 1 {
        l.global().expect("complex mode").complex_count -= 1;
    }
}

/// Complete the waits for zero on list `at` that can proceed (Linux
/// wake_const_ops): true if one completed
fn wake_const_ops(l: &mut SemLock<'_>, at: Pending, wq: &mut WakeQ) -> bool {
    let mut list = l.take(at, false);
    let mut done = false;
    let mut cur = list.front();
    while let Some(p) = cur {
        // SAFETY: `p` is on `list`; its successor is read before it may
        // leave
        cur = unsafe { list.next(p) };
        // SAFETY: a linked entry is live (see `SemQueue`)
        let q = unsafe { &*p };
        let r = retry(l, q);
        if r == Ok(Semop::Blocks) {
            continue;
        }
        // SAFETY: on `list`
        unsafe { list.remove(p) };
        unlinked(l, q);
        done |= r.is_ok();
        // SAFETY: just unlinked, under the locks
        unsafe { complete(p, r.map(|_| ()), wq) };
    }
    l.put(at, false, list);
    done
}

/// After values changed: the waits for zero on the semaphores that
/// reached zero, then the array's if any did (Linux
/// do_smart_wakeup_zero); `sops` None means any semaphore may have
fn do_smart_wakeup_zero(l: &mut SemLock<'_>, sops: Option<&[Sembuf]>, wq: &mut WakeQ) {
    let mut zero = false;
    let mut each = |l: &mut SemLock<'_>, n: usize| {
        if l.sem(n).val == 0 {
            zero = true;
            wake_const_ops(l, Pending::Sem(n), wq);
        }
    };
    match sops {
        Some(sops) => sops.iter().for_each(|s| each(l, s.sem_num as usize)),
        None => (0..l.arr().nsems as usize).for_each(|n| each(l, n)),
    }
    if zero {
        wake_const_ops(l, Pending::Array, wq);
    }
}

/// Complete the alter waiters on list `at` that can proceed, oldest
/// first (Linux update_queue): one that completed may let older ones
/// run, so the walk restarts after a multi-operation one or while the
/// array's list has entries (check_restart)
fn update_queue(l: &mut SemLock<'_>, at: Pending, wq: &mut WakeQ) {
    let mut list = l.take(at, true);
    'again: loop {
        let mut cur = list.front();
        while let Some(p) = cur {
            // A semaphore at zero lets no decrement through (and single
            // increments never wait)
            if let Pending::Sem(n) = at
                && l.sem(n).val == 0
            {
                break 'again;
            }
            // SAFETY: `p` is on `list`; its successor is read before it
            // may leave
            cur = unsafe { list.next(p) };
            // SAFETY: a linked entry is live (see `SemQueue`)
            let q = unsafe { &*p };
            let r = retry(l, q);
            if r == Ok(Semop::Blocks) {
                continue;
            }
            // SAFETY: on `list`
            unsafe { list.remove(p) };
            unlinked(l, q);
            let mut restart = false;
            if r.is_ok() {
                do_smart_wakeup_zero(l, Some(&q.sops), wq);
                restart = q.sops.len() > 1 || matches!(at, Pending::Array) && !list.is_empty();
            }
            // SAFETY: just unlinked, under the locks; `q` is not used
            // after this
            unsafe { complete(p, r.map(|_| ()), wq) };
            if restart {
                continue 'again;
            }
        }
        break;
    }
    l.put(at, true, list);
}

/// After a change: complete what can proceed now (Linux
/// do_smart_update): the waits for zero, then the array's alter list if
/// it has entries, else the lists of the semaphores `sops` increased
/// (all of them for None). Single-operation waiters only exist for the
/// semaphore a fast-path holder locked.
fn do_smart_update(l: &mut SemLock<'_>, sops: Option<&[Sembuf]>, wq: &mut WakeQ) {
    do_smart_wakeup_zero(l, sops, wq);
    if l.list(Pending::Array, true).is_some_and(|q| !q.is_empty()) {
        update_queue(l, Pending::Array, wq);
        return;
    }
    match sops {
        Some(sops) => {
            for s in sops.iter().filter(|s| s.sem_op > 0) {
                update_queue(l, Pending::Sem(s.sem_num as usize), wq);
            }
        }
        None => {
            for n in 0..l.arr().nsems as usize {
                update_queue(l, Pending::Sem(n), wq);
            }
        }
    }
}

/// Single-operation alter waiters join the array's list ahead of a
/// first multi-operation waiter (Linux merge_queues, which splices each
/// semaphore's list onto the head in index order)
fn merge_queues(l: &mut SemLock<'_>) {
    for n in (0..l.arr().nsems as usize).rev() {
        let mut q = l.take(Pending::Sem(n), true);
        let g = l.global().expect("complex mode");
        g.pending_alter.append(&mut q);
    }
}

/// Queue `q` for its sleep (Linux do_semtimedop): a single operation on
/// its semaphore's list, unless it alters while multi-operation waiters
/// exist; multi-operation ones on the array's
fn queue(l: &mut SemLock<'_>, q: &SemQueue) {
    let at = if q.sops.len() > 1 {
        if l.complex_count() == 0 {
            merge_queues(l);
        }
        l.global().expect("complex mode").complex_count += 1;
        Pending::Array
    } else if q.alter && l.complex_count() != 0 {
        Pending::Array
    } else {
        Pending::Sem(q.sops[0].sem_num as usize)
    };
    let list = l.list(at, q.alter).expect("queue list");
    // SAFETY: pinned on the sleeper's stack until unlinked (by a waker,
    // or by the sleeper before it returns)
    unsafe { list.push_back(q) };
}

/// Take a waiter that gave up off its list (Linux unlink_queue): a
/// single alter operation is on the array's list exactly while
/// multi-operation waiters exist (merge_queues on the first; the last
/// holder of complex mode moves it back, unmerge_queues)
fn unlink_queue(l: &mut SemLock<'_>, q: &SemQueue) {
    let multi = q.sops.len() > 1;
    let at = if multi || q.alter && l.complex_count() != 0 {
        Pending::Array
    } else {
        Pending::Sem(q.sops[0].sem_num as usize)
    };
    let list = l.list(at, q.alter).expect("queue list");
    debug_assert!(list.iter().any(|e| core::ptr::eq(e, q)));
    // SAFETY: on `list` (above)
    unsafe { list.remove(q) };
    if multi {
        l.global().expect("complex mode").complex_count -= 1;
    }
}

impl SemArray {
    /// Create a new semaphore array
    pub fn new(key: i32, nsems: u32, mode: u16, ns: Arc<IpcNamespace>) -> KernelResult<Arc<Self>> {
        let sems = (0..nsems)
            .map(|_| SemSlot {
                lock: Mutex::new(()),
                data: UnsafeCell::new(PerSem::new()),
            })
            .collect();
        try_arc(Self {
            perm: KernIpcPerm::new(key, mode),
            nsems,
            sems,
            global: Mutex::new(GlobalState {
                pending_alter: List::new(),
                pending_const: List::new(),
                complex_count: 0,
                ctime: current_time_secs(),
                list_id: ArcList::new(),
            }),
            use_global_lock: AtomicU32::new(0),
            ns,
        })
    }

    /// The whole array, in complex mode (Linux sem_lock for nsops != 1
    /// and semctl: complexmode_enter)
    fn lock_all(&self) -> SemLock<'_> {
        let g = self.global.lock();
        if self.use_global_lock.load(Ordering::Relaxed) == 0 {
            self.use_global_lock
                .store(USE_GLOBAL_LOCK_HYSTERESIS, Ordering::SeqCst);
            // Wait out every single-semaphore holder
            for s in &self.sems {
                drop(s.lock.lock());
            }
        } else {
            self.use_global_lock
                .store(USE_GLOBAL_LOCK_HYSTERESIS, Ordering::Relaxed);
        }
        SemLock::All { arr: self, g }
    }

    /// The locks `sops` need (Linux sem_lock): a single operation takes
    /// only its semaphore's lock unless complex mode is on
    fn lock_for(&self, sops: &[Sembuf]) -> SemLock<'_> {
        if sops.len() != 1 {
            return self.lock_all();
        }
        let n = sops[0].sem_num as usize;
        if self.use_global_lock.load(Ordering::Acquire) == 0 {
            let g = self.sems[n].lock.lock();
            // Pairs with the release that leaves complex mode
            if self.use_global_lock.load(Ordering::Acquire) == 0 {
                return SemLock::One {
                    arr: self,
                    n,
                    _g: g,
                };
            }
        }
        let gl = self.global.lock();
        if self.use_global_lock.load(Ordering::Relaxed) == 0 {
            // Left complex mode meanwhile: down to the semaphore's lock
            let g = self.sems[n].lock.lock();
            drop(gl);
            return SemLock::One {
                arr: self,
                n,
                _g: g,
            };
        }
        SemLock::All { arr: self, g: gl }
    }

    /// `lock_all`, or EIDRM once removed (Linux ipc_valid_object)
    fn lock_valid(&self) -> KernelResult<SemLock<'_>> {
        let l = self.lock_all();
        if self.perm.is_deleted() {
            return Err(KernelError::IdentifierRemoved);
        }
        Ok(l)
    }

    /// After a change under `l`: complete what can proceed, then (after
    /// the unlock) wake the sleepers
    fn unlock_and_wake(&self, mut l: SemLock<'_>, sops: Option<&[Sembuf]>) {
        let mut wq = WakeQ::new();
        do_smart_update(&mut l, sops, &mut wq);
        drop(l);
        wq.wake_up();
    }

    /// Fill semid64_ds structure for IPC_STAT (complex mode)
    fn fill_semid64_ds(&self, l: &mut SemLock<'_>, ds: &mut Semid64Ds) {
        self.perm.fill_ipc64_perm(&mut ds.sem_perm);
        ds.sem_otime = (0..self.nsems as usize)
            .map(|i| l.sem(i).otime)
            .max()
            .unwrap_or(0);
        ds.sem_ctime = l.global().map_or(0, |g| g.ctime);
        ds.sem_nsems = u64::from(self.nsems);
        ds.__unused3 = 0;
        ds.__unused4 = 0;
    }
}

impl IpcObject for SemArray {
    fn perm(&self) -> &KernIpcPerm {
        &self.perm
    }

    /// Linux freeary: the undo structures leave both their lists (and
    /// are freed after the lock), every waiter fails with EIDRM
    fn destroy(&self) {
        let mut wq = WakeQ::new();
        let mut dead = ArcList::<UndoIdA>::new();
        {
            let mut l = self.lock_all();
            let g = l.global().expect("complex mode");
            while let Some(un) = g.list_id.pop_front() {
                un.unlink_proc();
                dead.push_back(un);
            }
            g.complex_count = 0;
            let eidrm = Err(KernelError::IdentifierRemoved);
            let lists = (0..self.nsems as usize)
                .map(Pending::Sem)
                .chain([Pending::Array]);
            for at in lists {
                for alter in [true, false] {
                    let list = l.list(at, alter).expect("complex mode");
                    while let Some(q) = list.pop_front() {
                        // SAFETY: just unlinked, under the locks
                        unsafe { complete(q, eidrm, &mut wq) };
                    }
                }
            }
        }
        drop(dead);
        wq.wake_up();
        self.ns.used_sems.fetch_sub(self.nsems, Ordering::Relaxed);
    }
}

// ============================================================================
// Syscalls
// ============================================================================

/// semget - get semaphore set
///
/// # Arguments
/// * `key` - Key to identify semaphore set
/// * `nsems` - Number of semaphores in set (for creation)
/// * `semflg` - Flags (IPC_CREAT, IPC_EXCL, permission bits)
pub fn sys_semget(key: i32, nsems: i32, semflg: i32) -> KernelResult<i32> {
    let ns = current_ipc_ns();

    // Validate nsems
    if nsems < 0 || nsems > ns.sem_ctls[0] {
        return Err(KernelError::InvalidArgument);
    }

    let nsems_u32 = nsems as u32;
    let ns_clone = ns.clone();

    let ns_added = ns.clone();
    let ops = IpcOps {
        // Linux newary: EINVAL for no semaphores, ENOSPC past SEMMNS
        new: move |k, mode| {
            if nsems_u32 == 0 {
                return Err(KernelError::InvalidArgument);
            }
            let used = u64::from(ns_clone.used_sems.load(Ordering::Relaxed));
            if used + u64::from(nsems_u32) > ns_clone.sem_ctls[1] as u64 {
                return Err(KernelError::NoSpace);
            }
            SemArray::new(k, nsems_u32, mode, ns_clone.clone())
        },
        // Linux sem_more_checks
        more_checks: |sem: &SemArray| {
            if nsems_u32 > sem.nsems {
                return Err(KernelError::InvalidArgument);
            }
            Ok(())
        },
        added: move |sem: &SemArray| {
            ns_added.used_sems.fetch_add(sem.nsems, Ordering::Relaxed);
        },
    };
    ipcget(ns.sem_ids(), key, semflg, ns.sem_ctls[3] as u32, ops)
}

/// semop - semaphore operations
pub fn sys_semop(semid: i32, sops_ptr: UserPtr<Sembuf>, nsops: usize) -> KernelResult<i32> {
    sys_semtimedop(semid, sops_ptr, nsops, UserPtr::new(0))
}

/// Timespec structure for semtimedop timeout (matches Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SemTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}
crate::pod!(SemTimespec { tv_sec, tv_nsec });

/// semtimedop - semaphore operations with timeout
///
/// # Arguments
/// * `semid` - Semaphore set ID
/// * `sops_ptr` - Pointer to array of sembuf operations
/// * `nsops` - Number of operations
/// * `timeout_ptr` - Timeout (NULL = infinite)
pub fn sys_semtimedop(
    semid: i32,
    sops_ptr: UserPtr<Sembuf>,
    nsops: usize,
    timeout_ptr: UserPtr<SemTimespec>,
) -> KernelResult<i32> {
    let ns = current_ipc_ns();
    let einval = KernelError::InvalidArgument;

    // Linux order: the timeout is copied in, then nsops (E2BIG, EINVAL),
    // the operations, semid and the timeout's validity
    let ts = if timeout_ptr.is_null() {
        None
    } else {
        Some(timeout_ptr.read()?)
    };
    if nsops > ns.sem_ctls[2] as usize {
        return Err(KernelError::ArgListTooLong);
    }
    if nsops == 0 {
        return Err(einval);
    }
    let mut sops = vec![Sembuf::default(); nsops];
    // At most SEMOPM operations: the size cannot overflow
    let mut r = UserSlice::new(sops_ptr.addr(), nsops * core::mem::size_of::<Sembuf>()).reader();
    for sop in sops.iter_mut() {
        *sop = r.read()?;
    }
    if semid < 0 {
        return Err(einval);
    }
    // A relative timeout on CLOCK_MONOTONIC (Linux ktime_get() + timeout)
    let deadline_ns = match ts {
        Some(ts) if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) => {
            return Err(einval);
        }
        Some(ts) => Some(crate::time::deadline_after(
            crate::time::monotonic_ns(),
            crate::time::timespec_to_ns(ts.tv_sec, ts.tv_nsec),
        )),
        None => None,
    };

    let max = sops.iter().map(|s| u32::from(s.sem_num)).max().unwrap_or(0);
    let has_undo = sops.iter().any(|s| s.sem_flg & SEM_UNDO != 0);
    let alter = sops.iter().any(|s| s.sem_op != 0);

    let sem_array_ref = ns.sem_ids().find_by_id(semid).ok_or(einval)?;
    let sem_array: &SemArray = &sem_array_ref;
    if max >= sem_array.nsems {
        return Err(KernelError::FileTooLarge);
    }
    let access = if alter { IPC_PERM_WRITE } else { IPC_PERM_READ };
    ipc_checkperm(&sem_array.perm, access)?;

    // The caller's undo structure for this array, made before the lock
    // (Linux find_alloc_undo)
    let un = if has_undo {
        let ulp = get_or_create_undo_list(&crate::task::percpu::current())?;
        Some(find_alloc_undo(&ulp, &sem_array_ref, semid)?)
    } else {
        None
    };
    let pid = crate::task::pid::vnr(current_pid()) as i32;
    let mut wq = WakeQ::new();
    let mut l = sem_array.lock_for(&sops);
    if sem_array.perm.is_deleted() {
        return Err(KernelError::IdentifierRemoved);
    }
    // Removed and its id given again since find_alloc_undo (Linux
    // un->semid == -1)
    if un.as_ref().is_some_and(|u| u.semid() == -1) {
        return Err(KernelError::IdentifierRemoved);
    }
    let mut blocking = 0;
    let r = perform_atomic_semop(&mut l, &sops, pid, un.as_deref(), &mut blocking);
    if r != Ok(Semop::Blocks) {
        if r == Ok(Semop::Done) && alter {
            do_smart_update(&mut l, Some(&sops), &mut wq);
        }
        return r.map(|_| 0);
    }

    // Would block: queue it and sleep (Linux: the status is -EINTR until
    // a waker completes the operation)
    let q = core::pin::pin!(SemQueue {
        link: Link::new(),
        sleeper: &raw const *crate::task::percpu::current(),
        pid,
        sops,
        alter,
        undo: un,
        blocking: AtomicUsize::new(blocking),
        status: AtomicI32::new(WAITING),
        _pin: PhantomPinned,
    });
    let q: &SemQueue = &q;
    queue(&mut l, q);
    drop(l);
    loop {
        let why = sem_sleep(q, deadline_ns);
        let st = q.status.load(Ordering::Acquire);
        if st != WAITING {
            return status_result(st).map(|()| 0);
        }
        // Not completed: recheck under the locks, where a waker may have
        // completed it meanwhile; else it unlinks itself
        let mut l = sem_array.lock_for(&q.sops);
        let st = q.status.load(Ordering::Acquire);
        if st != WAITING {
            return status_result(st).map(|()| 0);
        }
        let err = if sem_array.perm.is_deleted() {
            KernelError::IdentifierRemoved
        } else {
            match why {
                SemSleep::Woken => continue,
                SemSleep::Timeout => KernelError::WouldBlock,
                SemSleep::Signal => KernelError::Interrupted,
            }
        };
        unlink_queue(&mut l, q);
        return Err(err);
    }
}

/// Why a semop sleep ended
enum SemSleep {
    /// Its status is set
    Woken,
    Signal,
    Timeout,
}

/// Sleep until `q` is completed, a signal arrives or the deadline (on
/// CLOCK_MONOTONIC) passes (Linux do_semtimedop's schedule loop; semop
/// is never restarted: EINTR)
fn sem_sleep(q: &SemQueue, deadline: Option<u64>) -> SemSleep {
    use crate::task::percpu::{SleepState, set_current_state};
    use crate::time::hrtimer::{HrClock, schedule_hrtimeout};
    let clock = HrClock::Monotonic;
    let why = loop {
        set_current_state(SleepState::Interruptible);
        if q.status.load(Ordering::Acquire) != WAITING {
            break SemSleep::Woken;
        }
        if crate::sync::waitqueue::signal_pending() {
            break SemSleep::Signal;
        }
        if deadline.is_some_and(|d| clock.now() >= d) {
            break SemSleep::Timeout;
        }
        schedule_hrtimeout(deadline, clock);
    };
    set_current_state(SleepState::Running);
    why
}

/// The waiters blocked on semaphore `n`: decrements, or waits for zero
/// (Linux count_semcnt): all of its own lists' (each waits on it
/// alone), and those of the array's whose blocking operation is on it
/// (check_qop)
fn count_semcnt(l: &mut SemLock<'_>, n: usize, zero: bool) -> usize {
    let mut cnt = l.list(Pending::Sem(n), !zero).map_or(0, |q| q.len());
    let check_qop = |q: &SemQueue| {
        let op = &q.sops[q.blocking.load(Ordering::Relaxed)];
        usize::from(op.sem_num) == n && if zero { op.sem_op == 0 } else { op.sem_op < 0 }
    };
    let lists: &[bool] = if zero { &[true, false] } else { &[true] };
    for &alter in lists {
        if let Some(q) = l.list(Pending::Array, alter) {
            cnt += q.iter().filter(|q| check_qop(q)).count();
        }
    }
    cnt
}

/// semctl - semaphore control
pub fn sys_semctl(semid: i32, semnum: i32, cmd: i32, arg: u64) -> KernelResult<i32> {
    let ns = current_ipc_ns();
    let cmd_only = cmd & !IPC_64;

    match cmd_only {
        IPC_STAT | SEM_STAT => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument)?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray = &sem;

            let mut ds = Semid64Ds::default();
            let mut l = sem_array.lock_all();
            sem_array.fill_semid64_ds(&mut l, &mut ds);
            drop(l);

            let buf = UserPtr::<Semid64Ds>::new(arg);
            if !buf.is_null() {
                buf.write(&ds)?;
            }

            Ok(0)
        }

        IPC_SET => {
            // Copied in first, before the IPC locks (Linux: the copy
            // may fault)
            let ds: Semid64Ds = UserPtr::<Semid64Ds>::new(arg).read()?;
            let _w = ns.sem_ids().rwsem.write();
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument)?;

            let uid = crate::task::percpu::current_cred().euid;
            let perm = sem.perm();
            {
                let mut p = perm.lock.lock();
                if !KernIpcPerm::is_owner(&p, perm.cuid, uid) {
                    return Err(KernelError::NotPermitted);
                }
                p.uid = ds.sem_perm.uid;
                p.gid = ds.sem_perm.gid;
                p.mode = ds.sem_perm.mode & 0o777;
            }
            if let Some(g) = sem.lock_all().global() {
                g.ctime = current_time_secs();
            }

            Ok(0)
        }

        IPC_RMID => {
            let _w = ns.sem_ids().rwsem.write();
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument)?;

            let uid = crate::task::percpu::current_cred().euid;
            let perm = sem.perm();
            if !KernIpcPerm::is_owner(&perm.lock.lock(), perm.cuid, uid) {
                return Err(KernelError::NotPermitted);
            }

            if let Some(removed) = ns.sem_ids().remove(semid) {
                removed.destroy();
            }

            Ok(0)
        }

        GETVAL => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument)?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray = &sem;

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                return Err(KernelError::InvalidArgument);
            }

            Ok(sem_array.lock_valid()?.sem(semnum as usize).val)
        }

        SETVAL => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument)?;

            ipc_checkperm(sem.perm(), IPC_PERM_WRITE)?;

            let sem_array: &SemArray = &sem;

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                return Err(KernelError::InvalidArgument);
            }

            let val = arg as i32;
            if !(0..=SEMVMX).contains(&val) {
                return Err(KernelError::Range);
            }

            // Linux semctl_setval
            let mut l = sem_array.lock_valid()?;
            l.clear_adj(Some(semnum as usize));
            let s = l.sem(semnum as usize);
            s.val = val;
            s.pid = crate::task::pid::vnr(current_pid()) as i32;
            if let Some(g) = l.global() {
                g.ctime = current_time_secs();
            }
            sem_array.unlock_and_wake(l, None);

            Ok(0)
        }

        GETALL => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument)?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray = &sem;

            // A snapshot under the lock into a buffer sized before it
            // (nsems is fixed), copied out after it
            let mut vals = crate::util::kmem::try_vec(sem_array.nsems as usize, 0i32)?;
            {
                let mut l = sem_array.lock_valid()?;
                for (i, v) in vals.iter_mut().enumerate() {
                    *v = l.sem(i).val;
                }
            }
            // Values are at most SEMVMX: each fits a u16
            let mut w = UserSlice::new(arg, vals.len() * 2).writer();
            for &v in &vals {
                w.write(&(v as u16))?;
            }

            Ok(0)
        }

        SETALL => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument)?;

            ipc_checkperm(sem.perm(), IPC_PERM_WRITE)?;

            let sem_array: &SemArray = &sem;

            // Copied in and checked first, then set under the lock
            // (Linux semctl_main SETALL)
            let mut vals = vec![0i32; sem_array.nsems as usize];
            let mut r = UserSlice::new(arg, vals.len() * 2).reader();
            for v in vals.iter_mut() {
                *v = i32::from(r.read::<u16>()?);
            }
            if vals.iter().any(|&v| v > SEMVMX) {
                return Err(KernelError::Range);
            }
            let pid = crate::task::pid::vnr(current_pid()) as i32;
            let mut l = sem_array.lock_valid()?;
            l.clear_adj(None);
            for (i, &v) in vals.iter().enumerate() {
                let s = l.sem(i);
                s.val = v;
                s.pid = pid;
            }
            if let Some(g) = l.global() {
                g.ctime = current_time_secs();
            }
            sem_array.unlock_and_wake(l, None);

            Ok(0)
        }

        GETPID => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument)?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray = &sem;

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                return Err(KernelError::InvalidArgument);
            }

            Ok(sem_array.lock_valid()?.sem(semnum as usize).pid)
        }

        GETNCNT | GETZCNT => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument)?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;
            let sem_array: &SemArray = &sem;
            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                return Err(KernelError::InvalidArgument);
            }
            let mut l = sem_array.lock_valid()?;
            Ok(count_semcnt(&mut l, semnum as usize, cmd_only == GETZCNT) as i32)
        }

        _ => Err(KernelError::InvalidArgument),
    }
}

// ============================================================================
// SEM_UNDO Support - Automatic semaphore adjustment on process exit
// ============================================================================

/// One process's adjustments of one array (Linux struct sem_undo), on
/// its undo list (`list_proc`, under `SemUndoList.list_proc`'s lock) and
/// on the array's (`list_id`, under `SemArray.global`): both links are
/// set and cleared together, under both locks (find_alloc_undo, freeary,
/// exit_sem), each list holding one reference.
pub struct SemUndo {
    list_proc: Link,
    list_id: Link,
    /// The undo list it is on (Linux un->ulp); a list freed without
    /// exit_sem (its task never ran) dropped its entries
    ulp: Weak<SemUndoList>,
    /// The array it adjusts: told apart from a later array with the
    /// same id (a list may outlive its namespace's arrays)
    sma: Weak<SemArray>,
    /// The array's id; -1 once freeary took it off both lists. Written
    /// under both locks, read under either (an atomic only for that)
    semid: AtomicI32,
    /// The adjustment of each semaphore (Linux semadj[]): element `n`
    /// under semaphore `n`'s lock, as its value (`SemLock::adj`)
    semadj: Vec<UnsafeCell<i16>>,
}

// SAFETY: `semadj` is only reached through `SemLock::adj`/`clear_adj`,
// which hold the lock covering each element; the other fields are Sync
unsafe impl Sync for SemUndo {}

crate::adapter!(UndoProcA, SemUndo, list_proc);
crate::adapter!(UndoIdA, SemUndo, list_id);

impl SemUndo {
    /// Off its undo list (freeary): the list's lock nests inside the
    /// array's global lock, which the caller holds with the entry just
    /// taken off `list_id`
    fn unlink_proc(&self) {
        let Some(ulp) = self.ulp.upgrade() else {
            // The list is being freed: its drop takes the entry off
            self.semid.store(-1, Ordering::Relaxed);
            return;
        };
        let mut lp = ulp.list_proc.lock();
        self.semid.store(-1, Ordering::Relaxed);
        // SAFETY: on its undo list while it was on `list_id` (both
        // change together) and the list is alive
        drop(unsafe { lp.remove(self) });
    }

    fn semid(&self) -> i32 {
        self.semid.load(Ordering::Relaxed)
    }

    /// For `semid`, `sma`
    fn is(&self, semid: i32, sma: &Arc<SemArray>) -> bool {
        self.semid() == semid && core::ptr::eq(self.sma.as_ptr(), Arc::as_ptr(sma))
    }
}

/// Per-task semaphore undo list (Linux struct sem_undo_list), shared by
/// CLONE_SYSVSEM; the adjustments are applied when the last sharing
/// task exits
pub struct SemUndoList {
    /// Tasks sharing it (Linux refcnt)
    refcnt: AtomicU32,
    /// Its undo structures, most recently used first (Linux ulp->lock
    /// and list_proc); taken under an array's global lock, or alone
    list_proc: Mutex<ArcList<UndoProcA>>,
}

impl SemUndoList {
    /// Create a new empty undo list
    pub fn new() -> Self {
        Self {
            refcnt: AtomicU32::new(1),
            list_proc: Mutex::new(ArcList::new()),
        }
    }
}

/// `semid`'s undo structure for `sma` on `list`, moved to the front
/// (Linux lookup_undo)
fn lookup_undo(
    list: &mut ArcList<UndoProcA>,
    semid: i32,
    sma: &Arc<SemArray>,
) -> Option<Arc<SemUndo>> {
    let un: *const SemUndo = list.iter().find(|u| u.is(semid, sma))?;
    // SAFETY: found on `list`, which holds a reference to it
    let un = unsafe { list.remove(&*un) };
    list.push_front(un.clone());
    Some(un)
}

/// The caller's undo structure for `sma` (id `semid`), made if it has
/// none (Linux find_alloc_undo): allocated before the array's lock and
/// looked up again under it; EIDRM if the array was removed meanwhile
fn find_alloc_undo(
    ulp: &Arc<SemUndoList>,
    sma: &Arc<SemArray>,
    semid: i32,
) -> KernelResult<Arc<SemUndo>> {
    if let Some(un) = lookup_undo(&mut ulp.list_proc.lock(), semid, sma) {
        return Ok(un);
    }
    let n = sma.nsems as usize;
    let mut semadj = Vec::new();
    semadj
        .try_reserve_exact(n)
        .map_err(|_| KernelError::OutOfMemory)?;
    semadj.extend((0..n).map(|_| UnsafeCell::new(0)));
    let new = try_arc(SemUndo {
        list_proc: Link::new(),
        list_id: Link::new(),
        ulp: Arc::downgrade(ulp),
        sma: Arc::downgrade(sma),
        semid: AtomicI32::new(semid),
        semadj,
    })?;
    let mut l = sma.lock_valid()?;
    let mut lp = ulp.list_proc.lock();
    if let Some(un) = lookup_undo(&mut lp, semid, sma) {
        return Ok(un);
    }
    lp.push_front(new.clone());
    l.global()
        .expect("complex mode")
        .list_id
        .push_front(new.clone());
    Ok(new)
}

// =============================================================================
// Task SemUndo accessors - uses Task.sysvsem field directly via TASKLIST
// =============================================================================

use crate::task::percpu::TASKLIST;

/// Task `t`'s undo list, created if it has none (Linux get_undo_list):
/// allocated before TASKLIST, which is checked again
pub fn get_or_create_undo_list(t: &Task) -> Result<Arc<SemUndoList>, KernelError> {
    if let Some(ul) = get_undo_list(t) {
        return Ok(ul);
    }
    let new = try_arc(SemUndoList::new())?;
    let mut table = TASKLIST.write();
    let Some(mut task) = table.view_mut(t) else {
        // Task not found - shouldn't happen but return a new list
        return Ok(new);
    };
    if let Some(ul) = task.sysvsem() {
        return Ok(ul.clone());
    }
    task.set_sysvsem(new.clone());
    Ok(new)
}

/// Task `t`'s undo list, if it has one
pub fn get_undo_list(t: &Task) -> Option<Arc<SemUndoList>> {
    TASKLIST.read().view(t)?.sysvsem().cloned()
}

/// Clone semaphore undo list for a new task
///
/// If `share` is true (CLONE_SYSVSEM set), the child shares the parent's
/// list (Linux copy_semundo: refcount_inc). Otherwise, child starts with
/// None (lazy allocation on first SEM_UNDO operation).
pub fn clone_task_semundo(parent: &Task, child: &Task, share: bool) {
    if share {
        // CLONE_SYSVSEM: share the same undo list
        let parent_undo = get_undo_list(parent);
        if let Some(undo) = parent_undo {
            let mut table = TASKLIST.write();
            if let Some(mut child) = table.view_mut(child) {
                undo.refcnt.fetch_add(1, Ordering::Relaxed);
                child.set_sysvsem(undo);
            }
        }
        // If parent has no undo list, child also starts with none (will be created on demand)
    }
    // Without CLONE_SYSVSEM: child starts with no undo list
    // It will be created lazily if the child uses SEM_UNDO
}

/// Apply all of task `t`'s semaphore undo operations on its exit
/// (Linux exit_sem), once the last task sharing its list (CLONE_SYSVSEM)
/// lets go: one undo structure at a time, each looked up again under
/// its array's lock and taken off both lists there
pub fn exit_sem(t: &Task) {
    let ulp = {
        let mut table = TASKLIST.write();
        table.view_mut(t).and_then(|mut t| t.take_sysvsem())
    };
    let Some(ulp) = ulp else {
        return;
    };
    if ulp.refcnt.fetch_sub(1, Ordering::AcqRel) != 1 {
        return;
    }
    let pid = crate::task::pid::vnr(current_pid()) as i32;
    loop {
        let (first, semid, sma) = match ulp.list_proc.lock().front() {
            Some(un) => (core::ptr::from_ref(un), un.semid(), un.sma.upgrade()),
            None => break,
        };
        let Some(sma) = sma else {
            // The array is gone without IPC_RMID (its namespace died),
            // and its list with it: nothing to undo. Off the undo list
            // unless freeary took it meanwhile.
            let mut lp = ulp.list_proc.lock();
            let un = lp
                .front()
                .is_some_and(|u| core::ptr::eq(u, first))
                .then(|| lp.pop_front());
            drop(lp);
            drop(un);
            continue;
        };
        // Removed (IPC_RMID): freeary takes the entry off (Linux:
        // continue)
        let Ok(mut l) = sma.lock_valid() else {
            continue;
        };
        let mut lp = ulp.list_proc.lock();
        let un: *const SemUndo = match lp.iter().find(|u| u.is(semid, &sma)) {
            Some(un) => un,
            None => continue,
        };
        // SAFETY: found on the undo list, which holds a reference
        let un = unsafe { lp.remove(&*un) };
        drop(lp);
        let g = l.global().expect("complex mode");
        // SAFETY: on `list_id` while it was on the undo list (both
        // change together, under both locks)
        let id_ref = unsafe { g.list_id.remove(&un) };
        for i in 0..sma.nsems as usize {
            let a = *l.adj(&un, i);
            if a != 0 {
                let s = l.sem(i);
                s.val = (s.val + i32::from(a)).clamp(0, SEMVMX);
                s.pid = pid;
            }
        }
        sma.unlock_and_wake(l, None);
        drop(id_ref);
        drop(un);
    }
}
