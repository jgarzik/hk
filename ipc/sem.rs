//! System V Semaphore Implementation
//!
//! Provides semaphore arrays for process synchronization with support for:
//! - Multiple semaphores per array
//! - Atomic multi-semaphore operations
//! - Blocking with optional timeout
//! - Automatic undo on process exit (SEM_UNDO)

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use crate::arch::Uaccess;
use crate::ipc::util::{
    IPC_PERM_READ, IPC_PERM_WRITE, IpcObject, IpcOps, KernIpcPerm, ipc_checkperm, ipcget,
};
use crate::ipc::{
    IPC_64, IPC_NOWAIT, IPC_RMID, IPC_SET, IPC_STAT, IpcNamespace, Sembuf, Semid64Ds,
    current_ipc_ns,
};
use crate::sync::spin::Mutex;
use crate::sync::waitqueue::WaitQueue;
use crate::task::percpu::{current_pid, current_tid};
use crate::time::TIMEKEEPER;
use crate::uaccess::{get_user, put_user};
use crate::util::error::KernelError;

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
//   sempid, otime, its single-operation waiters and its SEM_UNDO
//   adjustments: a semop of one operation takes only that lock, so
//   different semaphores of one array do not contend;
// - `SemArray.global` (Linux sem_perm.lock) covers the multi-operation
//   waiters, `complex_count` and ctime, and in complex mode every
//   semaphore's data.
// Complex mode (`use_global_lock` != 0, Linux complex_mode with its
// hysteresis): a multi-operation semop, semctl, exit and removal take
// the global lock, set the flag and take and drop every semaphore lock,
// which waits out the single-operation holders; a single operation that
// then finds the flag set takes the global lock instead. The flag stays
// set while multi-operation waiters exist and for
// USE_GLOBAL_LOCK_HYSTERESIS further global holds, then is cleared with
// release; the fast path rechecks it with acquire after its semaphore
// lock (Linux SEM_BARRIER_1).

/// A queued operation's status while it waits (Linux: the sleeper sets
/// -EINTR, the waker stores the result with release)
const SEM_WAITING: i32 = -(KernelError::Interrupted as i32);

/// Global holds before complex mode is left (Linux
/// USE_GLOBAL_LOCK_HYSTERESIS)
const USE_GLOBAL_LOCK_HYSTERESIS: u32 = 10;

/// Pending semaphore operation (Linux struct sem_queue)
pub struct SemQueue {
    /// Thread-group id recorded as sempid when it completes
    pid: i32,
    /// Operations to perform
    sops: Vec<Sembuf>,
    /// Does this alter semaphore values?
    alter: bool,
    /// The caller's undo list (SEM_UNDO), whose adjustments it changes
    undo: Option<u64>,
    /// `SEM_WAITING` until a waker completes it under the array's locks,
    /// then 0 or a negative errno (Release; the sleeper reads it Acquire
    /// without a lock, Linux q->status)
    status: AtomicI32,
}

/// A waiting operation and the index of the one it is blocked on
/// (Linux q->blocking, for GETNCNT/GETZCNT)
type Waiter = (Arc<SemQueue>, usize);

/// One semaphore's state (Linux struct sem)
struct PerSem {
    val: i32,
    /// Last modifier (sempid)
    pid: i32,
    /// Last semop on it (Linux sem_otime; IPC_STAT reports the latest)
    otime: i64,
    /// Single-operation waiters on it, oldest first (Linux pending_alter
    /// and pending_const; alter waiters move to the array's list while
    /// multi-operation waiters exist, Linux merge_queues)
    pending: VecDeque<Waiter>,
    /// Each undo list's adjustment of it, by `SemUndoList.id` (Linux
    /// un->semadj[i]); a zero adjustment is not kept
    undo: BTreeMap<u64, i16>,
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
    /// Multi-operation waiters, and single-operation alter waiters while
    /// any exist (Linux sma->pending_alter/pending_const), oldest first
    pending: VecDeque<Waiter>,
    /// Multi-operation waiters queued (Linux complex_count)
    complex_count: usize,
    /// Last change time
    ctime: i64,
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
    /// Sleepers in semop; each waits for its own queue entry's status
    waitq: WaitQueue,
    /// Namespace reference
    ns: Arc<IpcNamespace>,
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

impl SemLock<'_> {
    /// Semaphore `n`'s state: the one locked, or any in complex mode
    fn sem(&mut self, n: usize) -> &mut PerSem {
        let arr = match self {
            SemLock::One { arr, n: held, .. } => {
                assert_eq!(n, *held, "semaphore {} not locked", n);
                *arr
            }
            SemLock::All { arr, .. } => *arr,
        };
        // SAFETY: `One` holds semaphore n's lock and saw complex mode off
        // after taking it, so no global holder touches it; `All` holds
        // the global lock in complex mode, which waited out every
        // single-semaphore holder and keeps new ones out. `&mut self`
        // makes the reference unique.
        unsafe { &mut *arr.sems[n].data.get() }
    }

    /// The array-wide state (complex mode only)
    fn global(&mut self) -> Option<&mut GlobalState> {
        match self {
            SemLock::All { g, .. } => Some(g),
            SemLock::One { .. } => None,
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
        let back: Vec<Waiter> = g.pending.drain(..).collect();
        for w in back {
            let n = w.0.sops[0].sem_num as usize;
            // SAFETY: complex mode, under the global lock (as `sem`)
            unsafe { &mut *arr.sems[n].data.get() }.pending.push_back(w);
        }
        let u = arr.use_global_lock.load(Ordering::Relaxed);
        if u == 1 {
            arr.use_global_lock.store(0, Ordering::Release);
        } else if u > 1 {
            arr.use_global_lock.store(u - 1, Ordering::Relaxed);
        }
    }
}

/// Apply `sops` in order, all or nothing (Linux
/// perform_atomic_semop_slow, which also sums repeated operations on one
/// semaphore): 0 when applied (sempid and otime updated), 1 when an
/// operation would block (`blocking` is its index), or a negative errno
/// (EAGAIN for a blocking operation with IPC_NOWAIT, ERANGE above SEMVMX
/// or past the adjustment range). A SEM_UNDO operation also changes the
/// `undo` list's adjustment by its negative. Undone on anything but 0.
fn perform_atomic_semop(
    l: &mut SemLock,
    sops: &[Sembuf],
    pid: i32,
    undo: Option<u64>,
    blocking: &mut usize,
) -> i32 {
    let adj_of = |s: &PerSem| undo.and_then(|u| s.undo.get(&u).copied()).unwrap_or(0);
    for (n, sop) in sops.iter().enumerate() {
        let s = l.sem(sop.sem_num as usize);
        let cur = s.val;
        let result = cur + sop.sem_op as i32;
        let r = if (sop.sem_op == 0 && cur != 0) || result < 0 {
            *blocking = n;
            if sop.sem_flg & IPC_NOWAIT as i16 != 0 {
                KernelError::WouldBlock.to_errno_neg()
            } else {
                1
            }
        } else if result > SEMVMX {
            KernelError::Range.to_errno_neg()
        } else if let (true, Some(u)) = (sop.sem_flg & SEM_UNDO != 0, undo) {
            // The adjustment must stay in -SEMAEM-1..=SEMAEM
            match i16::try_from(adj_of(s) as i32 - sop.sem_op as i32) {
                Ok(v) => {
                    set_adj(s, u, v);
                    s.val = result;
                    continue;
                }
                Err(_) => KernelError::Range.to_errno_neg(),
            }
        } else {
            s.val = result;
            continue;
        };
        for done in sops[..n].iter().rev() {
            let s = l.sem(done.sem_num as usize);
            s.val -= done.sem_op as i32;
            if let (true, Some(u)) = (done.sem_flg & SEM_UNDO != 0, undo) {
                let v = adj_of(s) + done.sem_op;
                set_adj(s, u, v);
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
    0
}

fn set_adj(s: &mut PerSem, undo: u64, v: i16) {
    if v == 0 {
        s.undo.remove(&undo);
    } else {
        s.undo.insert(undo, v);
    }
}

/// Retry the waiters in `q`, oldest first (Linux update_queue): each
/// completed one is unlinked and its status set; one that changed values
/// restarts the scan. Returns whether any was completed and whether one
/// changed values; `done` collects the semaphores the completed alter
/// operations changed.
fn retry(l: &mut SemLock, q: &mut VecDeque<Waiter>, done: &mut Vec<usize>) -> (bool, bool) {
    let (mut woke, mut altered) = (false, false);
    let mut i = 0;
    while i < q.len() {
        let w = q[i].0.clone();
        let mut blocking = 0;
        let r = perform_atomic_semop(l, &w.sops, w.pid, w.undo, &mut blocking);
        if r == 1 {
            q[i].1 = blocking;
            i += 1;
            continue;
        }
        q.remove(i);
        if w.sops.len() > 1
            && let Some(g) = l.global()
        {
            g.complex_count -= 1;
        }
        w.status.store(r, Ordering::Release);
        woke = true;
        if r == 0 && w.alter {
            altered = true;
            done.extend(w.sops.iter().map(|s| s.sem_num as usize));
            i = 0;
        }
    }
    (woke, altered)
}

/// After a change: complete what can proceed now (Linux
/// do_smart_update). Under one semaphore's lock only its waiters exist
/// to try; in complex mode the array's waiters and those of every
/// semaphore that changed, until nothing more completes. True if a
/// sleeper must be woken after the unlock.
fn update_queue(l: &mut SemLock, changed: impl IntoIterator<Item = usize>) -> bool {
    let mut woke = false;
    let mut dirty: Vec<usize> = changed.into_iter().collect();
    loop {
        let mut again = false;
        // The array's waiters first; what they change joins `dirty`
        if let Some(g) = l.global() {
            let mut q = core::mem::take(&mut g.pending);
            let (w, _) = retry(l, &mut q, &mut dirty);
            let g = l.global().expect("complex mode");
            q.append(&mut g.pending);
            g.pending = q;
            woke |= w;
        }
        while let Some(n) = dirty.pop() {
            let mut q = core::mem::take(&mut l.sem(n).pending);
            let mut more = Vec::new();
            let (w, a) = retry(l, &mut q, &mut more);
            let s = l.sem(n);
            q.append(&mut s.pending);
            s.pending = q;
            woke |= w;
            // A value changed: the array's waiters may proceed now
            again |= a && l.global().is_some();
            dirty.extend(more.into_iter().filter(|&m| m != n));
        }
        if !again {
            break;
        }
    }
    woke
}

impl SemArray {
    /// Create a new semaphore array
    pub fn new(key: i32, nsems: u32, mode: u16, ns: Arc<IpcNamespace>) -> Result<Arc<Self>, i32> {
        let sems = (0..nsems)
            .map(|_| SemSlot {
                lock: Mutex::new(()),
                data: UnsafeCell::new(PerSem {
                    val: 0,
                    pid: 0,
                    otime: 0,
                    pending: VecDeque::new(),
                    undo: BTreeMap::new(),
                }),
            })
            .collect();
        Ok(Arc::new(Self {
            perm: KernIpcPerm::new(key, mode),
            nsems,
            sems,
            global: Mutex::new(GlobalState {
                pending: VecDeque::new(),
                complex_count: 0,
                ctime: current_time_secs(),
            }),
            use_global_lock: AtomicU32::new(0),
            waitq: WaitQueue::new(),
            ns,
        }))
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
    fn lock_valid(&self) -> Result<SemLock<'_>, i32> {
        let l = self.lock_all();
        if self.perm.is_deleted() {
            return Err(KernelError::IdentifierRemoved.errno());
        }
        Ok(l)
    }

    /// After a change under `l`: complete what can proceed, then (after
    /// the unlock) wake the sleepers
    fn unlock_and_wake(&self, mut l: SemLock<'_>, changed: impl IntoIterator<Item = usize>) {
        let woke = update_queue(&mut l, changed);
        drop(l);
        if woke {
            self.waitq.wake_all();
        }
    }

    /// Fill semid64_ds structure for IPC_STAT (complex mode)
    fn fill_semid64_ds(&self, l: &mut SemLock, ds: &mut Semid64Ds) {
        self.perm.fill_ipc64_perm(&mut ds.sem_perm);
        ds.sem_otime = (0..self.nsems as usize)
            .map(|i| l.sem(i).otime)
            .max()
            .unwrap_or(0);
        ds.sem_ctime = l.global().map_or(0, |g| g.ctime);
        ds.sem_nsems = self.nsems as u64;
        ds.__unused3 = 0;
        ds.__unused4 = 0;
    }
}

impl IpcObject for SemArray {
    fn perm(&self) -> &KernIpcPerm {
        &self.perm
    }

    /// Linux freeary: every waiter fails with EIDRM
    fn destroy(&self) {
        {
            let mut l = self.lock_all();
            let eidrm = KernelError::IdentifierRemoved.to_errno_neg();
            let g = l.global().expect("complex mode");
            g.complex_count = 0;
            for (q, _) in g.pending.drain(..) {
                q.status.store(eidrm, Ordering::Release);
            }
            for i in 0..self.nsems as usize {
                for (q, _) in l.sem(i).pending.drain(..) {
                    q.status.store(eidrm, Ordering::Release);
                }
            }
        }
        self.waitq.wake_all();
        self.ns.used_sems.fetch_sub(self.nsems, Ordering::Relaxed);
    }
}

// ============================================================================
// Syscalls
// ============================================================================

/// semget - get semaphore set
/// Convert Result to syscall return value
fn result_to_i64(res: Result<i32, i32>) -> i64 {
    match res {
        Ok(v) => v as i64,
        Err(e) => -(e as i64),
    }
}

///
/// # Arguments
/// * `key` - Key to identify semaphore set
/// * `nsems` - Number of semaphores in set (for creation)
/// * `semflg` - Flags (IPC_CREAT, IPC_EXCL, permission bits)
pub fn sys_semget(key: i32, nsems: i32, semflg: i32) -> i64 {
    result_to_i64(do_semget(key, nsems, semflg))
}

fn do_semget(key: i32, nsems: i32, semflg: i32) -> Result<i32, i32> {
    let ns = current_ipc_ns();

    // Validate nsems
    if nsems < 0 || nsems > ns.sem_ctls[0] {
        return Err(KernelError::InvalidArgument.errno());
    }

    let nsems_u32 = nsems as u32;
    let ns_clone = ns.clone();

    let ns_added = ns.clone();
    let ops = IpcOps {
        // Linux newary: EINVAL for no semaphores, ENOSPC past SEMMNS
        new: move |k, mode| {
            if nsems_u32 == 0 {
                return Err(KernelError::InvalidArgument.errno());
            }
            let used = ns_clone.used_sems.load(Ordering::Relaxed) as u64;
            if used + nsems_u32 as u64 > ns_clone.sem_ctls[1] as u64 {
                return Err(KernelError::NoSpace.errno());
            }
            SemArray::new(k, nsems_u32, mode, ns_clone.clone())
        },
        // Linux sem_more_checks
        more_checks: |sem: &SemArray| {
            if nsems_u32 > sem.nsems {
                return Err(KernelError::InvalidArgument.errno());
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
pub fn sys_semop(semid: i32, sops_ptr: u64, nsops: usize) -> i64 {
    sys_semtimedop(semid, sops_ptr, nsops, 0)
}

/// semtimedop - semaphore operations with timeout
///
/// # Arguments
/// * `semid` - Semaphore set ID
/// * `sops_ptr` - Pointer to array of sembuf operations
/// * `nsops` - Number of operations
/// * `timeout_ptr` - Timeout (0 = infinite)
pub fn sys_semtimedop(semid: i32, sops_ptr: u64, nsops: usize, timeout_ptr: u64) -> i64 {
    result_to_i64(do_semtimedop(semid, sops_ptr, nsops, timeout_ptr))
}

/// Timespec structure for semtimedop timeout (matches Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct SemTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}
crate::pod!(SemTimespec { tv_sec, tv_nsec });

fn do_semtimedop(semid: i32, sops_ptr: u64, nsops: usize, timeout_ptr: u64) -> Result<i32, i32> {
    let ns = current_ipc_ns();
    let einval = KernelError::InvalidArgument.errno();

    // Linux order: the timeout is copied in, then nsops (E2BIG, EINVAL),
    // the operations, semid and the timeout's validity
    let ts = if timeout_ptr != 0 {
        Some(
            get_user::<Uaccess, SemTimespec>(timeout_ptr)
                .map_err(|_| KernelError::BadAddress.errno())?,
        )
    } else {
        None
    };
    if nsops > ns.sem_ctls[2] as usize {
        return Err(KernelError::ArgListTooLong.errno());
    }
    if nsops == 0 {
        return Err(einval);
    }
    let mut sops = vec![Sembuf::default(); nsops];
    for (i, sop) in sops.iter_mut().enumerate() {
        let offset = sops_ptr + (i * core::mem::size_of::<Sembuf>()) as u64;
        *sop = get_user::<Uaccess, Sembuf>(offset).map_err(|_| KernelError::BadAddress.errno())?;
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

    let max = sops.iter().map(|s| s.sem_num as u32).max().unwrap_or(0);
    let has_undo = sops.iter().any(|s| s.sem_flg & SEM_UNDO != 0);
    let alter = sops.iter().any(|s| s.sem_op != 0);

    let sem_array_ref = ns.sem_ids().find_by_id(semid).ok_or(einval)?;
    let sem_array: &SemArray = &sem_array_ref;
    if max >= sem_array.nsems {
        return Err(KernelError::FileTooLarge.errno());
    }
    let access = if alter { IPC_PERM_WRITE } else { IPC_PERM_READ };
    ipc_checkperm(&sem_array.perm, access)?;

    // The undo list knows the array before the array knows the list
    // (Linux find_alloc_undo), so exit finds every adjustment
    let undo = has_undo.then(|| {
        let ul = get_or_create_undo_list(current_tid());
        ul.register(semid, &sem_array_ref);
        ul.id
    });
    let pid = current_pid() as i32;
    let mut l = sem_array.lock_for(&sops);
    if sem_array.perm.is_deleted() {
        return Err(KernelError::IdentifierRemoved.errno());
    }
    let mut blocking = 0;
    let r = perform_atomic_semop(&mut l, &sops, pid, undo, &mut blocking);
    if r <= 0 {
        if r == 0 && alter {
            sem_array.unlock_and_wake(l, sops.iter().map(|s| s.sem_num as usize));
        } else {
            drop(l);
        }
        if r < 0 {
            return Err(-r);
        }
        return Ok(0);
    }

    // Would block: queue it and sleep (Linux: the status is -EINTR until
    // a waker completes the operation). A single operation waits on its
    // semaphore, unless it alters while multi-operation waiters exist;
    // those, and multi-operation ones, wait on the array.
    let queue = Arc::new(SemQueue {
        pid,
        sops,
        alter,
        undo,
        status: AtomicI32::new(SEM_WAITING),
    });
    let w = (queue.clone(), blocking);
    if queue.sops.len() == 1 {
        let n = queue.sops[0].sem_num as usize;
        match l.global() {
            Some(g) if alter && g.complex_count != 0 => g.pending.push_back(w),
            _ => l.sem(n).pending.push_back(w),
        }
    } else {
        let g = l.global().expect("complex mode");
        if g.complex_count == 0 {
            // Linux merge_queues: single-operation alter waiters join the
            // array's queue, keeping their order with the new one
            for i in 0..sem_array.nsems as usize {
                let s = l.sem(i);
                let (alt, rest): (VecDeque<Waiter>, VecDeque<Waiter>) =
                    s.pending.drain(..).partition(|(q, _)| q.alter);
                s.pending = rest;
                l.global().expect("complex mode").pending.extend(alt);
            }
        }
        let g = l.global().expect("complex mode");
        g.pending.push_back(w);
        g.complex_count += 1;
    }
    drop(l);
    let status = loop {
        // Sleep until completed, the deadline or a signal (semop is
        // never restarted: EINTR)
        let r = sem_array.waitq.wait_event_interruptible_deadline(
            || queue.status.load(Ordering::Acquire) != SEM_WAITING,
            deadline_ns,
            crate::time::hrtimer::HrClock::Monotonic,
        );
        let status = queue.status.load(Ordering::Acquire);
        if status != SEM_WAITING {
            break status;
        }
        // Not completed: recheck under the locks, then unlink
        let mut l = sem_array.lock_for(&queue.sops);
        if sem_array.perm.is_deleted() {
            return Err(KernelError::IdentifierRemoved.errno());
        }
        let status = queue.status.load(Ordering::Acquire);
        if status != SEM_WAITING {
            break status;
        }
        let timed_out = match r {
            Ok(true) => continue,
            Ok(false) => true,
            Err(_) => false,
        };
        unlink(&mut l, &queue);
        return Err(if timed_out {
            KernelError::WouldBlock.errno()
        } else {
            KernelError::Interrupted.errno()
        });
    };
    if status < 0 {
        return Err(-status);
    }
    Ok(0)
}

/// Take a waiter that gave up off its queue (Linux unlink_queue)
fn unlink(l: &mut SemLock, q: &Arc<SemQueue>) {
    let mine = |(w, _): &Waiter| Arc::ptr_eq(w, q);
    if let Some(g) = l.global()
        && let Some(i) = g.pending.iter().position(mine)
    {
        g.pending.remove(i);
        if q.sops.len() > 1 {
            g.complex_count -= 1;
        }
        return;
    }
    let n = q.sops[0].sem_num as usize;
    l.sem(n).pending.retain(|w| !mine(w));
}

/// semctl - semaphore control
pub fn sys_semctl(semid: i32, semnum: i32, cmd: i32, arg: u64) -> i64 {
    result_to_i64(do_semctl(semid, semnum, cmd, arg))
}

fn do_semctl(semid: i32, semnum: i32, cmd: i32, arg: u64) -> Result<i32, i32> {
    let ns = current_ipc_ns();
    let cmd_only = cmd & !IPC_64;

    match cmd_only {
        IPC_STAT | SEM_STAT => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray = &sem;

            let mut ds = Semid64Ds::default();
            let mut l = sem_array.lock_all();
            sem_array.fill_semid64_ds(&mut l, &mut ds);
            drop(l);

            if arg != 0 {
                put_user::<Uaccess, Semid64Ds>(arg, ds)
                    .map_err(|_| KernelError::BadAddress.errno())?;
            }

            Ok(0)
        }

        IPC_SET => {
            // Copied in first, before the IPC locks (Linux: the copy
            // may fault)
            let ds: Semid64Ds =
                get_user::<Uaccess, Semid64Ds>(arg).map_err(|_| KernelError::BadAddress.errno())?;
            let _w = ns.sem_ids().rwsem.write();
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            let uid = crate::task::percpu::current_cred().euid;
            let perm = sem.perm();
            {
                let mut p = perm.lock.lock();
                if !KernIpcPerm::is_owner(&p, perm.cuid, uid) {
                    return Err(KernelError::NotPermitted.errno());
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
                .ok_or(KernelError::InvalidArgument.errno())?;

            let uid = crate::task::percpu::current_cred().euid;
            let perm = sem.perm();
            if !KernIpcPerm::is_owner(&perm.lock.lock(), perm.cuid, uid) {
                return Err(KernelError::NotPermitted.errno());
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
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray = &sem;

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                return Err(KernelError::InvalidArgument.errno());
            }

            Ok(sem_array.lock_valid()?.sem(semnum as usize).val)
        }

        SETVAL => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_WRITE)?;

            let sem_array: &SemArray = &sem;

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                return Err(KernelError::InvalidArgument.errno());
            }

            let val = arg as i32;
            if !(0..=SEMVMX).contains(&val) {
                return Err(KernelError::Range.errno());
            }

            // Linux semctl_setval
            let mut l = sem_array.lock_valid()?;
            let s = l.sem(semnum as usize);
            s.val = val;
            s.pid = current_pid() as i32;
            s.undo.clear();
            if let Some(g) = l.global() {
                g.ctime = current_time_secs();
            }
            sem_array.unlock_and_wake(l, [semnum as usize]);

            Ok(0)
        }

        GETALL => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray = &sem;

            // A snapshot under the lock, copied out after it
            let vals: Vec<i32> = {
                let mut l = sem_array.lock_valid()?;
                (0..sem_array.nsems as usize)
                    .map(|i| l.sem(i).val)
                    .collect()
            };
            for (i, &v) in vals.iter().enumerate() {
                let offset = arg + (i * 2) as u64;
                put_user::<Uaccess, u16>(offset, v as u16)
                    .map_err(|_| KernelError::BadAddress.errno())?;
            }

            Ok(0)
        }

        SETALL => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_WRITE)?;

            let sem_array: &SemArray = &sem;

            // Copied in and checked first, then set under the lock
            // (Linux semctl_main SETALL)
            let mut vals = vec![0i32; sem_array.nsems as usize];
            for (i, v) in vals.iter_mut().enumerate() {
                let offset = arg + (i * 2) as u64;
                let val: u16 = get_user::<Uaccess, u16>(offset)
                    .map_err(|_| KernelError::BadAddress.errno())?;
                *v = val as i32;
            }
            if vals.iter().any(|&v| v > SEMVMX) {
                return Err(KernelError::Range.errno());
            }
            let pid = current_pid() as i32;
            let mut l = sem_array.lock_valid()?;
            for (i, &v) in vals.iter().enumerate() {
                let s = l.sem(i);
                s.val = v;
                s.pid = pid;
                s.undo.clear();
            }
            if let Some(g) = l.global() {
                g.ctime = current_time_secs();
            }
            sem_array.unlock_and_wake(l, 0..sem_array.nsems as usize);

            Ok(0)
        }

        GETPID => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray = &sem;

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                return Err(KernelError::InvalidArgument.errno());
            }

            Ok(sem_array.lock_valid()?.sem(semnum as usize).pid)
        }

        GETNCNT | GETZCNT => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;
            let sem_array: &SemArray = &sem;
            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                return Err(KernelError::InvalidArgument.errno());
            }
            // Linux count_semcnt: the waiters whose blocking operation is
            // on `semnum`, decrements for GETNCNT, waits-for-zero for
            // GETZCNT
            let zero = cmd_only == GETZCNT;
            let counts = |(q, b): &Waiter| {
                let op = &q.sops[*b];
                op.sem_num as i32 == semnum && if zero { op.sem_op == 0 } else { op.sem_op < 0 }
            };
            let mut l = sem_array.lock_valid()?;
            let mut n = l
                .sem(semnum as usize)
                .pending
                .iter()
                .filter(|w| counts(w))
                .count();
            n += l
                .global()
                .map_or(0, |g| g.pending.iter().filter(|w| counts(w)).count());
            Ok(n as i32)
        }

        _ => Err(KernelError::InvalidArgument.errno()),
    }
}

// ============================================================================
// SEM_UNDO Support - Automatic semaphore adjustment on process exit
// ============================================================================

use crate::task::Tid;
use alloc::sync::Weak;

/// Undo list ids (never reused, so a stale entry cannot alias a new list)
static UNDO_IDS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Per-task semaphore undo list (Linux struct sem_undo_list)
///
/// The adjustments themselves live in each array (`SemState.undo`,
/// under its lock); the list names the arrays it has adjustments in.
/// When CLONE_SYSVSEM is used, tasks share it via Arc, and the
/// adjustments are applied when the last sharing task exits.
pub struct SemUndoList {
    /// Key of this list's adjustments in each array
    id: u64,
    /// The arrays it has adjusted, by semid (a removed array or a reused
    /// id is told apart by the Weak)
    arrays: Mutex<BTreeMap<i32, Weak<SemArray>>>,
}

impl SemUndoList {
    /// Create a new empty undo list
    pub fn new() -> Self {
        Self {
            id: UNDO_IDS.fetch_add(1, Ordering::Relaxed),
            arrays: Mutex::new(BTreeMap::new()),
        }
    }

    /// Note that this list adjusts `sem` (Linux find_alloc_undo)
    fn register(&self, semid: i32, sem: &Arc<SemArray>) {
        let mut arrays = self.arrays.lock();
        let same = arrays
            .get(&semid)
            .is_some_and(|w| core::ptr::eq(w.as_ptr(), Arc::as_ptr(sem)));
        if !same {
            arrays.insert(semid, Arc::downgrade(sem));
        }
    }
}

impl Default for SemUndoList {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Task SemUndo accessors - uses Task.sysvsem field directly via TASKLIST
// =============================================================================

use crate::task::percpu::TASKLIST;

/// Get the undo list for a task, creating if necessary
pub fn get_or_create_undo_list(tid: Tid) -> Arc<SemUndoList> {
    let mut table = TASKLIST.write();
    if let Some(mut task) = table.get_mut(tid) {
        if task.sysvsem.is_none() {
            task.sysvsem = Some(Arc::new(SemUndoList::new()));
        }
        task.sysvsem.clone().unwrap()
    } else {
        // Task not found - shouldn't happen but return a new list
        Arc::new(SemUndoList::new())
    }
}

/// Get the undo list for a task (if it exists)
pub fn get_undo_list(tid: Tid) -> Option<Arc<SemUndoList>> {
    let table = TASKLIST.read();
    table.get(tid).and_then(|t| t.sysvsem.clone())
}

/// Clone semaphore undo list for a new task
///
/// If `share` is true (CLONE_SYSVSEM set), child shares parent's Arc<SemUndoList>.
/// Otherwise, child starts with None (lazy allocation on first SEM_UNDO operation).
pub fn clone_task_semundo(parent_tid: Tid, child_tid: Tid, share: bool) {
    if share {
        // CLONE_SYSVSEM: share the same undo list
        let parent_undo = get_undo_list(parent_tid);
        if let Some(undo) = parent_undo {
            let mut table = TASKLIST.write();
            if let Some(mut child) = table.get_mut(child_tid) {
                child.sysvsem = Some(undo);
            }
        }
        // If parent has no undo list, child also starts with none (will be created on demand)
    }
    // Without CLONE_SYSVSEM: child starts with no undo list
    // It will be created lazily if the child uses SEM_UNDO
}

/// Apply all semaphore undo operations for a task on exit (Linux
/// exit_sem)
///
/// If the task's undo list is shared (via CLONE_SYSVSEM), the
/// adjustments are only applied when the last sharing task exits (its
/// drop is the one `Arc::into_inner` gives the list to).
pub fn exit_sem(tid: Tid) {
    let undo_list = {
        let mut table = TASKLIST.write();
        table.get_mut(tid).and_then(|mut t| t.sysvsem.take())
    };
    // The last sharer's drop gives the list back, exactly once even when
    // CLONE_SYSVSEM sharers exit together (Linux refcount_dec_and_test)
    let Some(undo_list) = undo_list.and_then(Arc::into_inner) else {
        return;
    };
    let arrays = core::mem::take(&mut *undo_list.arrays.lock());
    let pid = current_pid() as i32;
    for (_, weak) in arrays {
        // Gone, or removed (IPC_RMID): nothing to undo
        let Some(sem_array) = weak.upgrade() else {
            continue;
        };
        let Ok(mut l) = sem_array.lock_valid() else {
            continue;
        };
        let mut changed = Vec::new();
        for i in 0..sem_array.nsems as usize {
            let s = l.sem(i);
            if let Some(a) = s.undo.remove(&undo_list.id) {
                s.val = (s.val + a as i32).clamp(0, SEMVMX);
                s.pid = pid;
                changed.push(i);
            }
        }
        sem_array.unlock_and_wake(l, changed);
    }
}
