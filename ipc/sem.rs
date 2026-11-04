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
use core::sync::atomic::{AtomicI32, Ordering};

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
// Semaphore Structures
// ============================================================================

/// A queued operation's status while it waits (Linux: the sleeper sets
/// -EINTR, the waker stores the result with release)
const SEM_WAITING: i32 = -(KernelError::Interrupted as i32);

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
    /// `SEM_WAITING` until a waker completes it under the array lock,
    /// then 0 or a negative errno (Release; the sleeper reads it Acquire
    /// without the lock, Linux q->status)
    status: AtomicI32,
}

/// Everything semop and semctl read or change, under one lock (Linux:
/// sem_perm.lock, the global mode of sem_lock)
pub struct SemState {
    /// Each semaphore's value
    val: Vec<i32>,
    /// Each semaphore's last modifier (sempid)
    pid: Vec<i32>,
    /// Waiting operations, oldest first, each with the index of the
    /// operation it is blocked on (Linux q->blocking, for GETNCNT/GETZCNT)
    pending: VecDeque<(Arc<SemQueue>, usize)>,
    /// Last semop time
    otime: i64,
    /// Last change time
    ctime: i64,
    /// Each undo list's adjustments to this array (Linux sem_undo on
    /// sma->list_id), by `SemUndoList.id`; applied when its owner exits
    undo: BTreeMap<u64, Vec<i16>>,
}

/// Semaphore array
pub struct SemArray {
    /// IPC permissions and ID
    pub perm: KernIpcPerm,
    /// Number of semaphores
    pub nsems: u32,
    /// Values, pending operations and times
    sem: Mutex<SemState>,
    /// Sleepers in semop; each waits for its own queue entry's status
    waitq: WaitQueue,
    /// Namespace reference
    ns: Arc<IpcNamespace>,
}

/// Apply `sops` to `st` in order, all or nothing (Linux
/// perform_atomic_semop_slow, which also sums repeated operations on one
/// semaphore): 0 when applied (sempid updated), 1 when an operation
/// would block, or a negative errno (EAGAIN for a blocking operation
/// with IPC_NOWAIT, ERANGE above SEMVMX or past the adjustment range).
/// A SEM_UNDO operation also changes the `undo` list's adjustment by
/// its negative. Undone on anything but 0; on 1, `blocking` is the
/// index of the operation that would block.
fn perform_atomic_semop(
    st: &mut SemState,
    sops: &[Sembuf],
    pid: i32,
    undo: Option<u64>,
    blocking: &mut usize,
) -> i32 {
    let SemState {
        val,
        pid: pids,
        undo: undos,
        ..
    } = st;
    let mut adj = undo.and_then(|u| undos.get_mut(&u));
    for (n, sop) in sops.iter().enumerate() {
        let i = sop.sem_num as usize;
        let cur = val[i];
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
        } else if let (true, Some(a)) = (sop.sem_flg & SEM_UNDO != 0, adj.as_deref_mut()) {
            // The adjustment must stay in -SEMAEM-1..=SEMAEM
            match i16::try_from(a[i] as i32 - sop.sem_op as i32) {
                Ok(v) => {
                    a[i] = v;
                    val[i] = result;
                    continue;
                }
                Err(_) => KernelError::Range.to_errno_neg(),
            }
        } else {
            val[i] = result;
            continue;
        };
        for done in sops[..n].iter().rev() {
            let d = done.sem_num as usize;
            val[d] -= done.sem_op as i32;
            if let (true, Some(a)) = (done.sem_flg & SEM_UNDO != 0, adj.as_deref_mut()) {
                a[d] += done.sem_op;
            }
        }
        return r;
    }
    for sop in sops {
        pids[sop.sem_num as usize] = pid;
    }
    0
}

/// Complete the waiting operations that can proceed now, oldest first
/// (Linux update_queue): each completed one is unlinked and its status
/// set; one that changed values restarts the scan. True if any was
/// completed (its sleeper must be woken after the unlock).
fn update_queue(st: &mut SemState) -> bool {
    let mut woke = false;
    let mut i = 0;
    while i < st.pending.len() {
        let q = st.pending[i].0.clone();
        let mut blocking = 0;
        let r = perform_atomic_semop(st, &q.sops, q.pid, q.undo, &mut blocking);
        if r == 1 {
            st.pending[i].1 = blocking;
            i += 1;
            continue;
        }
        st.pending.remove(i);
        if r == 0 {
            st.otime = current_time_secs();
        }
        q.status.store(r, Ordering::Release);
        woke = true;
        if r == 0 && q.alter {
            i = 0;
        }
    }
    woke
}

impl SemArray {
    /// Create a new semaphore array
    pub fn new(key: i32, nsems: u32, mode: u16, ns: Arc<IpcNamespace>) -> Result<Arc<Self>, i32> {
        Ok(Arc::new(Self {
            perm: KernIpcPerm::new(key, mode),
            nsems,
            sem: Mutex::new(SemState {
                val: vec![0; nsems as usize],
                pid: vec![0; nsems as usize],
                pending: VecDeque::new(),
                otime: 0,
                ctime: current_time_secs(),
                undo: BTreeMap::new(),
            }),
            waitq: WaitQueue::new(),
            ns,
        }))
    }

    /// The array's state, or EIDRM once removed (Linux sem_lock then
    /// ipc_valid_object)
    fn lock_valid(&self) -> Result<crate::sync::spin::MutexGuard<'_, SemState>, i32> {
        let st = self.sem.lock();
        if self.perm.is_deleted() {
            return Err(KernelError::IdentifierRemoved.errno());
        }
        Ok(st)
    }

    /// After a change under the lock: complete what can proceed, then
    /// (after the caller drops the lock) wake the sleepers
    fn unlock_and_wake(&self, mut st: crate::sync::spin::MutexGuard<'_, SemState>) {
        let woke = update_queue(&mut st);
        drop(st);
        if woke {
            self.waitq.wake_all();
        }
    }

    /// Fill semid64_ds structure for IPC_STAT
    fn fill_semid64_ds(&self, st: &SemState, ds: &mut Semid64Ds) {
        self.perm.fill_ipc64_perm(&mut ds.sem_perm);
        ds.sem_otime = st.otime;
        ds.sem_ctime = st.ctime;
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
            let mut st = self.sem.lock();
            for (q, _) in st.pending.drain(..) {
                q.status.store(
                    KernelError::IdentifierRemoved.to_errno_neg(),
                    Ordering::Release,
                );
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
    let mut st = sem_array.lock_valid()?;
    if let Some(u) = undo {
        st.undo
            .entry(u)
            .or_insert_with(|| vec![0; sem_array.nsems as usize]);
    }
    let mut blocking = 0;
    let r = perform_atomic_semop(&mut st, &sops, pid, undo, &mut blocking);
    if r <= 0 {
        if r == 0 {
            st.otime = current_time_secs();
        }
        if r == 0 && alter {
            sem_array.unlock_and_wake(st);
        } else {
            drop(st);
        }
        if r < 0 {
            return Err(-r);
        }
        return Ok(0);
    }

    // Would block: queue it and sleep (Linux: the status is -EINTR until
    // a waker completes the operation)
    let queue = Arc::new(SemQueue {
        pid,
        sops,
        alter,
        undo,
        status: AtomicI32::new(SEM_WAITING),
    });
    st.pending.push_back((queue.clone(), blocking));
    drop(st);
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
        // Not completed: recheck under the lock, then unlink
        let mut st = sem_array.lock_valid()?;
        let status = queue.status.load(Ordering::Acquire);
        if status != SEM_WAITING {
            break status;
        }
        let timed_out = match r {
            Ok(true) => continue,
            Ok(false) => true,
            Err(_) => false,
        };
        st.pending.retain(|(q, _)| !Arc::ptr_eq(q, &queue));
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
            sem_array.fill_semid64_ds(&sem_array.sem.lock(), &mut ds);

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
            sem.sem.lock().ctime = current_time_secs();

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

            Ok(sem_array.lock_valid()?.val[semnum as usize])
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
            let mut st = sem_array.lock_valid()?;
            st.val[semnum as usize] = val;
            st.pid[semnum as usize] = current_pid() as i32;
            for adj in st.undo.values_mut() {
                adj[semnum as usize] = 0;
            }
            st.ctime = current_time_secs();
            sem_array.unlock_and_wake(st);

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
            let vals = sem_array.lock_valid()?.val.clone();
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
            let mut st = sem_array.lock_valid()?;
            st.val = vals;
            st.pid.fill(pid);
            for adj in st.undo.values_mut() {
                adj.fill(0);
            }
            st.ctime = current_time_secs();
            sem_array.unlock_and_wake(st);

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

            Ok(sem_array.lock_valid()?.pid[semnum as usize])
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
            let st = sem_array.lock_valid()?;
            let n = st
                .pending
                .iter()
                .filter(|(q, b)| {
                    let op = &q.sops[*b];
                    op.sem_num as i32 == semnum && if zero { op.sem_op == 0 } else { op.sem_op < 0 }
                })
                .count();
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
/// adjustments are only applied when the last sharing task exits (Arc
/// refcount drops to 1).
pub fn exit_sem(tid: Tid) {
    let undo_list = {
        let mut table = TASKLIST.write();
        table.get_mut(tid).and_then(|mut t| t.sysvsem.take())
    };
    let Some(undo_list) = undo_list else {
        return;
    };
    if Arc::strong_count(&undo_list) > 1 {
        return;
    }
    let arrays = core::mem::take(&mut *undo_list.arrays.lock());
    let pid = current_pid() as i32;
    for (_, weak) in arrays {
        // Gone, or removed (IPC_RMID): nothing to undo
        let Some(sem_array) = weak.upgrade() else {
            continue;
        };
        let Ok(mut st) = sem_array.lock_valid() else {
            continue;
        };
        let Some(adj) = st.undo.remove(&undo_list.id) else {
            continue;
        };
        for (i, &a) in adj.iter().enumerate() {
            if a != 0 {
                st.val[i] = (st.val[i] + a as i32).clamp(0, SEMVMX);
                st.pid[i] = pid;
            }
        }
        sem_array.unlock_and_wake(st);
    }
}
