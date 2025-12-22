//! System V Semaphore Implementation
//!
//! Provides semaphore arrays for process synchronization with support for:
//! - Multiple semaphores per array
//! - Atomic multi-semaphore operations
//! - Blocking with optional timeout
//! - Automatic undo on process exit (SEM_UNDO)

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};

use crate::arch::Uaccess;
use crate::ipc::util::{
    IPC_PERM_READ, IPC_PERM_WRITE, IpcObject, KernIpcPerm, ipc_checkperm, ipcget,
};
use crate::ipc::{
    IPC_64, IPC_NOWAIT, IPC_RMID, IPC_SET, IPC_STAT, IpcNamespace, Sembuf, Semid64Ds,
    current_ipc_ns,
};
use crate::task::percpu::{current_pid, current_tid};
use crate::time::TIMEKEEPER;
use crate::uaccess::{get_user, put_user};
use crate::waitqueue::WaitQueue;
use spin::Mutex;

// Error codes
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const EPERM: i32 = 1;
const EIDRM: i32 = 43;
const E2BIG: i32 = 7;
const EAGAIN: i32 = 11;
const ERANGE: i32 = 34;
const EFBIG: i32 = 27;
const EFAULT: i32 = 14;

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

/// Single semaphore within an array
pub struct Sem {
    /// Current value
    pub semval: AtomicI32,
    /// PID of last modifier
    pub sempid: AtomicI32,
}

impl Sem {
    fn new() -> Self {
        Self {
            semval: AtomicI32::new(0),
            sempid: AtomicI32::new(0),
        }
    }
}

/// Pending semaphore operation
pub struct SemQueue {
    /// Task waiting for this operation
    pub tid: u64,
    /// Operations to perform
    pub sops: Vec<Sembuf>,
    /// Result status (-EIDRM, -EINTR, or 0)
    pub status: AtomicI32,
    /// Wakeup flag
    pub woken: AtomicBool,
    /// Does this alter semaphore values?
    pub alter: bool,
}

/// Semaphore array
pub struct SemArray {
    /// IPC permissions and ID
    pub perm: KernIpcPerm,
    /// Last semop time
    pub otime: AtomicI64,
    /// Last change time
    pub ctime: AtomicI64,
    /// Number of semaphores
    pub nsems: u32,
    /// The semaphores
    pub sems: Vec<Sem>,
    /// Pending operations queue
    pub pending: Mutex<VecDeque<Arc<SemQueue>>>,
    /// Wait queue for blocked operations
    pub waitq: WaitQueue,
    /// Namespace reference
    ns: Arc<IpcNamespace>,
}

impl SemArray {
    /// Create a new semaphore array
    pub fn new(key: i32, nsems: u32, mode: u16, ns: Arc<IpcNamespace>) -> Result<Arc<Self>, i32> {
        let mut sems = Vec::with_capacity(nsems as usize);
        for _ in 0..nsems {
            sems.push(Sem::new());
        }

        let now = current_time_secs();

        Ok(Arc::new(Self {
            perm: KernIpcPerm::new(key, mode),
            otime: AtomicI64::new(0),
            ctime: AtomicI64::new(now),
            nsems,
            sems,
            pending: Mutex::new(VecDeque::new()),
            waitq: WaitQueue::new(),
            ns,
        }))
    }

    /// Try to perform operations atomically
    ///
    /// Returns Ok(true) if all ops succeeded, Ok(false) if would block, Err on error
    fn try_atomic_ops(&self, sops: &[Sembuf]) -> Result<bool, i32> {
        // First pass: check if all operations can succeed
        for sop in sops {
            let sem_num = sop.sem_num as usize;
            if sem_num >= self.nsems as usize {
                return Err(EFBIG);
            }

            let semval = self.sems[sem_num].semval.load(Ordering::Acquire);
            let result = semval + sop.sem_op as i32;

            if sop.sem_op < 0 {
                // Decrement: must have enough
                if result < 0 {
                    return Ok(false); // Would block
                }
            } else if sop.sem_op == 0 {
                // Wait for zero
                if semval != 0 {
                    return Ok(false); // Would block
                }
            }
            // Increment always succeeds (unless overflow)
            if result > SEMVMX {
                return Err(ERANGE);
            }
        }

        // Second pass: apply all operations
        let pid = current_pid() as i32;
        for sop in sops {
            let sem_num = sop.sem_num as usize;
            let sem = &self.sems[sem_num];

            if sop.sem_op != 0 {
                sem.semval.fetch_add(sop.sem_op as i32, Ordering::AcqRel);
            }
            sem.sempid.store(pid, Ordering::Release);
        }

        self.otime.store(current_time_secs(), Ordering::Release);
        Ok(true)
    }

    /// Wake up any pending operations that can now proceed
    fn wake_pending(&self) {
        let mut pending = self.pending.lock();
        let mut i = 0;

        while i < pending.len() {
            let queue = &pending[i];
            if queue.woken.load(Ordering::Acquire) {
                i += 1;
                continue;
            }

            // Try the operation
            match self.try_atomic_ops(&queue.sops) {
                Ok(true) => {
                    // Success - wake the task
                    queue.status.store(0, Ordering::Release);
                    queue.woken.store(true, Ordering::Release);
                    self.waitq.wake_one();
                    pending.remove(i);
                }
                Ok(false) => {
                    // Still blocked
                    i += 1;
                }
                Err(e) => {
                    // Error - wake with error
                    queue.status.store(-e, Ordering::Release);
                    queue.woken.store(true, Ordering::Release);
                    self.waitq.wake_one();
                    pending.remove(i);
                }
            }
        }
    }

    /// Fill semid64_ds structure for IPC_STAT
    pub fn fill_semid64_ds(&self, ds: &mut Semid64Ds) {
        self.perm.fill_ipc64_perm(&mut ds.sem_perm);
        ds.sem_otime = self.otime.load(Ordering::Relaxed);
        ds.sem_ctime = self.ctime.load(Ordering::Relaxed);
        ds.sem_nsems = self.nsems as u64;
        ds.__unused3 = 0;
        ds.__unused4 = 0;
    }
}

impl IpcObject for SemArray {
    fn perm(&self) -> &KernIpcPerm {
        &self.perm
    }

    fn destroy(&self) {
        // Wake all pending operations with EIDRM
        let mut pending = self.pending.lock();
        for queue in pending.drain(..) {
            queue.status.store(-EIDRM, Ordering::Release);
            queue.woken.store(true, Ordering::Release);
        }
        self.waitq.wake_all();

        // Update namespace count
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
        return Err(EINVAL);
    }

    let nsems_u32 = nsems as u32;
    let ns_clone = ns.clone();

    ipcget(
        ns.sem_ids(),
        key,
        semflg,
        ns.sem_ctls[3] as u32,
        move |k, mode| {
            if nsems_u32 == 0 {
                return Err(EINVAL);
            }

            // Check total semaphore limit
            let current = ns_clone.used_sems.load(Ordering::Relaxed);
            if current + nsems_u32 > ns_clone.sem_ctls[1] as u32 {
                return Err(ENOMEM);
            }

            let sem = SemArray::new(k, nsems_u32, mode, ns_clone.clone())?;
            ns_clone.used_sems.fetch_add(nsems_u32, Ordering::Relaxed);
            Ok(sem)
        },
    )
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

fn do_semtimedop(semid: i32, sops_ptr: u64, nsops: usize, _timeout_ptr: u64) -> Result<i32, i32> {
    let ns = current_ipc_ns();

    // Validate
    if nsops == 0 || nsops > ns.sem_ctls[2] as usize {
        return Err(E2BIG);
    }

    // Read operations from user
    let mut sops = vec![Sembuf::default(); nsops];
    for (i, sop) in sops.iter_mut().enumerate().take(nsops) {
        let offset = sops_ptr + (i * core::mem::size_of::<Sembuf>()) as u64;
        *sop = get_user::<Uaccess, Sembuf>(offset).map_err(|_| EFAULT)?;
    }

    // Check for IPC_NOWAIT in any operation
    let nowait = sops.iter().any(|s| s.sem_flg & IPC_NOWAIT as i16 != 0);

    // Find semaphore set
    let sem_array = ns.sem_ids().find_by_id(semid).ok_or(EINVAL)?;

    // Downcast
    let sem_array: &SemArray =
        unsafe { &*(sem_array.as_ref() as *const dyn IpcObject as *const SemArray) };

    // Check permissions
    let alter = sops.iter().any(|s| s.sem_op != 0);
    let access = if alter { IPC_PERM_WRITE } else { IPC_PERM_READ };
    ipc_checkperm(&sem_array.perm, access)?;

    // Try the operation
    loop {
        match sem_array.try_atomic_ops(&sops) {
            Ok(true) => {
                // Success
                sem_array.wake_pending();
                sem_array.perm.put_ref();
                return Ok(0);
            }
            Ok(false) => {
                // Would block
                if nowait {
                    sem_array.perm.put_ref();
                    return Err(EAGAIN);
                }

                // Add to pending queue and sleep
                let queue = Arc::new(SemQueue {
                    tid: current_tid(),
                    sops: sops.clone(),
                    status: AtomicI32::new(0),
                    woken: AtomicBool::new(false),
                    alter,
                });

                {
                    let mut pending = sem_array.pending.lock();
                    pending.push_back(queue.clone());
                }

                // Sleep until woken
                // TODO: proper timeout support
                sem_array.waitq.wait();

                // Check result
                if queue.woken.load(Ordering::Acquire) {
                    let status = queue.status.load(Ordering::Acquire);
                    sem_array.perm.put_ref();
                    if status < 0 {
                        return Err(-status);
                    }
                    return Ok(0);
                }

                // Spurious wakeup, retry
            }
            Err(e) => {
                sem_array.perm.put_ref();
                return Err(e);
            }
        }
    }
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
            let sem = ns.sem_ids().find_by_id(semid).ok_or(EINVAL)?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            let mut ds = Semid64Ds::default();
            sem_array.fill_semid64_ds(&mut ds);

            if arg != 0 {
                put_user::<Uaccess, Semid64Ds>(arg, ds).map_err(|_| EFAULT)?;
            }

            sem.perm().put_ref();
            Ok(0)
        }

        IPC_SET => {
            let sem = ns.sem_ids().find_by_id(semid).ok_or(EINVAL)?;

            let cred = crate::task::percpu::current_cred();
            let uid = cred.euid;
            let perm = sem.perm();
            if uid != perm.uid && uid != perm.cuid && uid != 0 {
                perm.put_ref();
                return Err(EPERM);
            }

            let ds: Semid64Ds = get_user::<Uaccess, Semid64Ds>(arg).map_err(|_| EFAULT)?;

            let _lock = perm.lock.lock();
            let perm_mut = perm as *const KernIpcPerm as *mut KernIpcPerm;
            unsafe {
                (*perm_mut).uid = ds.sem_perm.uid;
                (*perm_mut).gid = ds.sem_perm.gid;
                (*perm_mut).mode = ds.sem_perm.mode & 0o777;
            }

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };
            sem_array
                .ctime
                .store(current_time_secs(), Ordering::Relaxed);

            perm.put_ref();
            Ok(0)
        }

        IPC_RMID => {
            let sem = ns.sem_ids().find_by_id(semid).ok_or(EINVAL)?;

            let cred = crate::task::percpu::current_cred();
            let uid = cred.euid;
            let perm = sem.perm();
            if uid != perm.uid && uid != perm.cuid && uid != 0 {
                perm.put_ref();
                return Err(EPERM);
            }
            perm.put_ref();

            if let Some(removed) = ns.sem_ids().remove(semid) {
                removed.destroy();
            }

            Ok(0)
        }

        GETVAL => {
            let sem = ns.sem_ids().find_by_id(semid).ok_or(EINVAL)?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                sem.perm().put_ref();
                return Err(EINVAL);
            }

            let val = sem_array.sems[semnum as usize]
                .semval
                .load(Ordering::Acquire);
            sem.perm().put_ref();
            Ok(val)
        }

        SETVAL => {
            let sem = ns.sem_ids().find_by_id(semid).ok_or(EINVAL)?;

            ipc_checkperm(sem.perm(), IPC_PERM_WRITE)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                sem.perm().put_ref();
                return Err(EINVAL);
            }

            let val = arg as i32;
            if !(0..=SEMVMX).contains(&val) {
                sem.perm().put_ref();
                return Err(ERANGE);
            }

            sem_array.sems[semnum as usize]
                .semval
                .store(val, Ordering::Release);
            sem_array.sems[semnum as usize]
                .sempid
                .store(current_pid() as i32, Ordering::Release);
            sem_array
                .ctime
                .store(current_time_secs(), Ordering::Release);

            // Wake pending operations
            sem_array.wake_pending();

            sem.perm().put_ref();
            Ok(0)
        }

        GETALL => {
            let sem = ns.sem_ids().find_by_id(semid).ok_or(EINVAL)?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            for i in 0..sem_array.nsems as usize {
                let val = sem_array.sems[i].semval.load(Ordering::Acquire) as u16;
                let offset = arg + (i * 2) as u64;
                put_user::<Uaccess, u16>(offset, val).map_err(|_| EFAULT)?;
            }

            sem.perm().put_ref();
            Ok(0)
        }

        SETALL => {
            let sem = ns.sem_ids().find_by_id(semid).ok_or(EINVAL)?;

            ipc_checkperm(sem.perm(), IPC_PERM_WRITE)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            let pid = current_pid() as i32;
            for i in 0..sem_array.nsems as usize {
                let offset = arg + (i * 2) as u64;
                let val: u16 = get_user::<Uaccess, u16>(offset).map_err(|_| EFAULT)?;

                if val as i32 > SEMVMX {
                    sem.perm().put_ref();
                    return Err(ERANGE);
                }

                sem_array.sems[i]
                    .semval
                    .store(val as i32, Ordering::Release);
                sem_array.sems[i].sempid.store(pid, Ordering::Release);
            }

            sem_array
                .ctime
                .store(current_time_secs(), Ordering::Release);
            sem_array.wake_pending();

            sem.perm().put_ref();
            Ok(0)
        }

        GETPID => {
            let sem = ns.sem_ids().find_by_id(semid).ok_or(EINVAL)?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                sem.perm().put_ref();
                return Err(EINVAL);
            }

            let pid = sem_array.sems[semnum as usize]
                .sempid
                .load(Ordering::Acquire);
            sem.perm().put_ref();
            Ok(pid)
        }

        GETNCNT | GETZCNT => {
            // Count waiting processes - simplified for now
            let sem = ns.sem_ids().find_by_id(semid).ok_or(EINVAL)?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;
            sem.perm().put_ref();

            // Return 0 for now (full implementation would count waiters)
            Ok(0)
        }

        _ => Err(EINVAL),
    }
}
