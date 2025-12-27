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
use crate::error::KernelError;
use crate::ipc::util::{
    IPC_PERM_READ, IPC_PERM_WRITE, IpcObject, IpcType, KernIpcPerm, ipc_checkperm, ipcget,
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
                return Err(KernelError::FileTooLarge.errno());
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
                return Err(KernelError::Range.errno());
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

    fn ipc_type(&self) -> IpcType {
        IpcType::Sem
    }

    fn destroy(&self) {
        // Wake all pending operations with EIDRM
        let mut pending = self.pending.lock();
        for queue in pending.drain(..) {
            queue.status.store(
                KernelError::IdentifierRemoved.to_errno_neg(),
                Ordering::Release,
            );
            queue.woken.store(true, Ordering::Release);
        }
        self.waitq.wake_all();

        // Update namespace count
        self.ns.used_sems.fetch_sub(self.nsems, Ordering::Relaxed);
    }
}

// ============================================================================
// Safe Downcasting
// ============================================================================

/// Safely downcast an IpcObject to SemArray
///
/// Returns None if the object is not a semaphore array.
/// This is safe because we verify the type tag before casting.
fn downcast_sem(obj: &dyn IpcObject) -> Option<&SemArray> {
    if obj.ipc_type() == IpcType::Sem {
        // SAFETY: We verified the type tag matches, so this cast is valid.
        // The IpcType::Sem tag is only returned by SemArray::ipc_type().
        Some(unsafe { &*(obj as *const dyn IpcObject as *const SemArray) })
    } else {
        None
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

    ipcget(
        ns.sem_ids(),
        key,
        semflg,
        ns.sem_ctls[3] as u32,
        move |k, mode| {
            if nsems_u32 == 0 {
                return Err(KernelError::InvalidArgument.errno());
            }

            // Check total semaphore limit
            let current = ns_clone.used_sems.load(Ordering::Relaxed);
            if current + nsems_u32 > ns_clone.sem_ctls[1] as u32 {
                return Err(KernelError::OutOfMemory.errno());
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
        return Err(KernelError::ArgListTooLong.errno());
    }

    // Read operations from user
    let mut sops = vec![Sembuf::default(); nsops];
    for (i, sop) in sops.iter_mut().enumerate().take(nsops) {
        let offset = sops_ptr + (i * core::mem::size_of::<Sembuf>()) as u64;
        *sop = get_user::<Uaccess, Sembuf>(offset).map_err(|_| KernelError::BadAddress.errno())?;
    }

    // Check for IPC_NOWAIT in any operation
    let nowait = sops.iter().any(|s| s.sem_flg & IPC_NOWAIT as i16 != 0);
    // Check if any operation has SEM_UNDO flag
    let has_undo = sops.iter().any(|s| s.sem_flg & SEM_UNDO != 0);

    // Find semaphore set
    let sem_array = ns
        .sem_ids()
        .find_by_id(semid)
        .ok_or(KernelError::InvalidArgument.errno())?;

    // Downcast
    let sem_array: &SemArray =
        unsafe { &*(sem_array.as_ref() as *const dyn IpcObject as *const SemArray) };

    // Check permissions
    let alter = sops.iter().any(|s| s.sem_op != 0);
    let access = if alter { IPC_PERM_WRITE } else { IPC_PERM_READ };
    ipc_checkperm(&sem_array.perm, access)?;

    let nsems = sem_array.nsems as usize;

    // Try the operation
    loop {
        match sem_array.try_atomic_ops(&sops) {
            Ok(true) => {
                // Success - record SEM_UNDO adjustments if needed
                if has_undo {
                    record_undo_for_ops(semid, nsems, &sops);
                }
                sem_array.wake_pending();
                sem_array.perm.put_ref();
                return Ok(0);
            }
            Ok(false) => {
                // Would block
                if nowait {
                    sem_array.perm.put_ref();
                    return Err(KernelError::WouldBlock.errno());
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
                    if status < 0 {
                        sem_array.perm.put_ref();
                        return Err(-status);
                    }
                    // Success - record SEM_UNDO adjustments if needed
                    if has_undo {
                        record_undo_for_ops(semid, nsems, &sops);
                    }
                    sem_array.perm.put_ref();
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
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            let mut ds = Semid64Ds::default();
            sem_array.fill_semid64_ds(&mut ds);

            if arg != 0 {
                put_user::<Uaccess, Semid64Ds>(arg, ds)
                    .map_err(|_| KernelError::BadAddress.errno())?;
            }

            sem.perm().put_ref();
            Ok(0)
        }

        IPC_SET => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            let cred = crate::task::percpu::current_cred();
            let uid = cred.euid;
            let perm = sem.perm();
            let _lock = perm.lock.lock();
            // SAFETY: We hold the lock
            let perm_mutable = unsafe { perm.mutable() };
            if uid != perm_mutable.uid && uid != perm.cuid && uid != 0 {
                drop(_lock);
                perm.put_ref();
                return Err(KernelError::NotPermitted.errno());
            }

            let ds: Semid64Ds =
                get_user::<Uaccess, Semid64Ds>(arg).map_err(|_| KernelError::BadAddress.errno())?;

            // Update fields
            perm_mutable.uid = ds.sem_perm.uid;
            perm_mutable.gid = ds.sem_perm.gid;
            perm_mutable.mode = ds.sem_perm.mode & 0o777;

            // Safe downcast with type verification
            let sem_array: &SemArray = match downcast_sem(sem.as_ref()) {
                Some(s) => s,
                None => {
                    perm.put_ref();
                    return Err(KernelError::InvalidArgument.errno());
                }
            };
            sem_array
                .ctime
                .store(current_time_secs(), Ordering::Relaxed);

            perm.put_ref();
            Ok(0)
        }

        IPC_RMID => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            let cred = crate::task::percpu::current_cred();
            let uid = cred.euid;
            let perm = sem.perm();
            {
                let _lock = perm.lock.lock();
                // SAFETY: We hold the lock
                let perm_mutable = unsafe { perm.mutable_ref() };
                if uid != perm_mutable.uid && uid != perm.cuid && uid != 0 {
                    drop(_lock);
                    perm.put_ref();
                    return Err(KernelError::NotPermitted.errno());
                }
            }
            perm.put_ref();

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

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                sem.perm().put_ref();
                return Err(KernelError::InvalidArgument.errno());
            }

            let val = sem_array.sems[semnum as usize]
                .semval
                .load(Ordering::Acquire);
            sem.perm().put_ref();
            Ok(val)
        }

        SETVAL => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_WRITE)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                sem.perm().put_ref();
                return Err(KernelError::InvalidArgument.errno());
            }

            let val = arg as i32;
            if !(0..=SEMVMX).contains(&val) {
                sem.perm().put_ref();
                return Err(KernelError::Range.errno());
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
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            for i in 0..sem_array.nsems as usize {
                let val = sem_array.sems[i].semval.load(Ordering::Acquire) as u16;
                let offset = arg + (i * 2) as u64;
                put_user::<Uaccess, u16>(offset, val)
                    .map_err(|_| KernelError::BadAddress.errno())?;
            }

            sem.perm().put_ref();
            Ok(0)
        }

        SETALL => {
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_WRITE)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            let pid = current_pid() as i32;
            for i in 0..sem_array.nsems as usize {
                let offset = arg + (i * 2) as u64;
                let val: u16 = get_user::<Uaccess, u16>(offset)
                    .map_err(|_| KernelError::BadAddress.errno())?;

                if val as i32 > SEMVMX {
                    sem.perm().put_ref();
                    return Err(KernelError::Range.errno());
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
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;

            let sem_array: &SemArray =
                unsafe { &*(sem.as_ref() as *const dyn IpcObject as *const SemArray) };

            if semnum < 0 || semnum as u32 >= sem_array.nsems {
                sem.perm().put_ref();
                return Err(KernelError::InvalidArgument.errno());
            }

            let pid = sem_array.sems[semnum as usize]
                .sempid
                .load(Ordering::Acquire);
            sem.perm().put_ref();
            Ok(pid)
        }

        GETNCNT | GETZCNT => {
            // Count waiting processes - simplified for now
            let sem = ns
                .sem_ids()
                .find_by_id(semid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(sem.perm(), IPC_PERM_READ)?;
            sem.perm().put_ref();

            // Return 0 for now (full implementation would count waiters)
            Ok(0)
        }

        _ => Err(KernelError::InvalidArgument.errno()),
    }
}

// ============================================================================
// SEM_UNDO Support - Automatic semaphore adjustment on process exit
// ============================================================================

use crate::task::Tid;
use alloc::collections::BTreeMap;
use spin::RwLock;

/// Individual semaphore undo entry for a specific semaphore array
///
/// Tracks adjustments to semaphores that should be reversed on process exit.
/// When a process performs semop() with SEM_UNDO flag, the operation's
/// negative is recorded here.
#[derive(Clone)]
pub struct SemUndo {
    /// Semaphore set ID
    pub semid: i32,
    /// Per-semaphore adjustments (negative of operations performed)
    /// Index corresponds to semaphore number, value is cumulative adjustment
    pub semadj: Vec<i16>,
}

impl SemUndo {
    /// Create a new undo entry for a semaphore array
    pub fn new(semid: i32, nsems: usize) -> Self {
        Self {
            semid,
            semadj: vec![0; nsems],
        }
    }

    /// Record an undo adjustment for a semaphore operation
    ///
    /// The adjustment is the negative of the operation value.
    /// When the process exits, these adjustments will be applied.
    pub fn record_adj(&mut self, sem_num: usize, sem_op: i16) {
        if sem_num < self.semadj.len() {
            // Record the negative - on exit, we reverse the operation
            self.semadj[sem_num] = self.semadj[sem_num].saturating_sub(sem_op);
        }
    }

    /// Check if all adjustments are zero (can be removed)
    pub fn is_empty(&self) -> bool {
        self.semadj.iter().all(|&adj| adj == 0)
    }
}

/// Per-task semaphore undo list
///
/// Contains all SEM_UNDO adjustments for a task. When the task exits,
/// all adjustments are applied to the corresponding semaphores.
///
/// When CLONE_SYSVSEM is used, multiple tasks share the same undo list
/// via Arc. The adjustments are only applied when the last sharing task exits.
pub struct SemUndoList {
    /// Map of semid -> SemUndo entries
    pub undos: RwLock<BTreeMap<i32, SemUndo>>,
}

impl SemUndoList {
    /// Create a new empty undo list
    pub fn new() -> Self {
        Self {
            undos: RwLock::new(BTreeMap::new()),
        }
    }

    /// Get or create an undo entry for a semaphore array
    pub fn get_or_create(&self, semid: i32, nsems: usize) -> SemUndo {
        let undos = self.undos.read();
        if let Some(undo) = undos.get(&semid) {
            return undo.clone();
        }
        drop(undos);

        // Create new entry
        let mut undos = self.undos.write();
        undos
            .entry(semid)
            .or_insert_with(|| SemUndo::new(semid, nsems))
            .clone()
    }

    /// Update an undo entry after recording an adjustment
    pub fn update(&self, undo: SemUndo) {
        let mut undos = self.undos.write();
        if undo.is_empty() {
            undos.remove(&undo.semid);
        } else {
            undos.insert(undo.semid, undo);
        }
    }

    /// Take all undo entries (for exit processing)
    pub fn take_all(&self) -> BTreeMap<i32, SemUndo> {
        let mut undos = self.undos.write();
        core::mem::take(&mut *undos)
    }
}

impl Default for SemUndoList {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Task SemUndo accessors - uses Task.sysvsem field directly via TASK_TABLE
// =============================================================================

use crate::task::percpu::TASK_TABLE;

/// Get the undo list for a task, creating if necessary
pub fn get_or_create_undo_list(tid: Tid) -> Arc<SemUndoList> {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
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
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .and_then(|t| t.sysvsem.clone())
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
            let mut table = TASK_TABLE.lock();
            if let Some(child) = table.tasks.iter_mut().find(|t| t.tid == child_tid) {
                child.sysvsem = Some(undo);
            }
        }
        // If parent has no undo list, child also starts with none (will be created on demand)
    }
    // Without CLONE_SYSVSEM: child starts with no undo list
    // It will be created lazily if the child uses SEM_UNDO
}

/// Apply all semaphore undo operations for a task on exit
///
/// This is called when a task exits. If the task's undo list is shared
/// (via CLONE_SYSVSEM), the adjustments are only applied when the last
/// sharing task exits (Arc refcount drops to 1).
pub fn exit_sem(tid: Tid) {
    // Remove this task's undo list reference
    let undo_list = {
        let mut table = TASK_TABLE.lock();
        if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
            task.sysvsem.take()
        } else {
            None
        }
    };

    let Some(undo_list) = undo_list else {
        return; // No undo list for this task
    };

    // Check if this is the last reference
    // Arc::strong_count returns the number of references
    // If it's 1, we are the last holder and should apply undos
    if Arc::strong_count(&undo_list) > 1 {
        // Other tasks still sharing this list, don't apply undos yet
        return;
    }

    // We're the last holder - apply all undo operations
    let undos = undo_list.take_all();
    let ns = current_ipc_ns();

    for (semid, undo) in undos {
        // Find the semaphore array
        let Some(sem_obj) = ns.sem_ids().find_by_id(semid) else {
            continue; // Semaphore array was deleted
        };

        // Downcast to SemArray
        let Some(sem_array) = downcast_sem(sem_obj.as_ref()) else {
            sem_obj.perm().put_ref();
            continue;
        };

        // Apply adjustments
        let pid = current_pid() as i32;
        for (i, &adj) in undo.semadj.iter().enumerate() {
            if adj == 0 || i >= sem_array.nsems as usize {
                continue;
            }

            let sem = &sem_array.sems[i];
            let old_val = sem.semval.load(Ordering::Acquire);
            let new_val = (old_val + adj as i32).clamp(0, SEMVMX);
            sem.semval.store(new_val, Ordering::Release);
            sem.sempid.store(pid, Ordering::Release);
        }

        // Wake any pending operations that may now succeed
        sem_array.wake_pending();
        sem_obj.perm().put_ref();
    }
}

/// Record SEM_UNDO adjustments for a successful semop
///
/// Called after a successful semop when any operation has SEM_UNDO flag set.
fn record_undo_for_ops(semid: i32, nsems: usize, sops: &[Sembuf]) {
    let tid = current_tid();
    let undo_list = get_or_create_undo_list(tid);

    let mut undo = undo_list.get_or_create(semid, nsems);

    for sop in sops {
        if sop.sem_flg & SEM_UNDO != 0 && sop.sem_op != 0 {
            undo.record_adj(sop.sem_num as usize, sop.sem_op);
        }
    }

    undo_list.update(undo);
}
