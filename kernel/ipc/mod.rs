//! System V IPC Implementation
//!
//! This module implements Linux-compatible SysV IPC mechanisms:
//! - Shared memory segments (shm)
//! - Semaphore arrays (sem)
//! - Message queues (msg)
//!
//! ## Design
//!
//! Following Linux kernel patterns:
//! - Per-namespace IPC isolation via `IpcNamespace`
//! - Three-tier locking: namespace RwLock, per-object spinlock, refcounting
//! - Composite IDs with sequence numbers to prevent ABA problems
//!
//! ## Locking
//!
//! Lock ordering (outermost to innermost):
//! ```text
//! IpcIds.inner (RwLock) - protects ID table
//!   └─ KernIpcPerm.lock (Mutex) - protects object state
//!       └─ Per-object data locks (e.g., message queues)
//! ```
//!
//! ## References
//!
//! - Linux kernel ipc/util.c, ipc/shm.c, ipc/sem.c, ipc/msg.c

pub mod mqueue;
pub mod msg;
pub mod sem;
pub mod shm;
mod util;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64};
use spin::Lazy;

pub use mqueue::{
    sys_mq_getsetattr, sys_mq_notify, sys_mq_open, sys_mq_timedreceive, sys_mq_timedsend,
    sys_mq_unlink,
};
pub use msg::{sys_msgctl, sys_msgget, sys_msgrcv, sys_msgsnd};
pub use sem::{sys_semctl, sys_semget, sys_semop, sys_semtimedop};
pub use shm::{sys_shmat, sys_shmctl, sys_shmdt, sys_shmget};
pub use util::{IpcIds, IpcIdsInner, KernIpcPerm, ipc_checkperm};

// ============================================================================
// IPC Constants (Linux ABI compatible)
// ============================================================================

/// Create if key is nonexistent
pub const IPC_CREAT: i32 = 0o1000;
/// Fail if key exists
pub const IPC_EXCL: i32 = 0o2000;
/// Return error on wait
pub const IPC_NOWAIT: i32 = 0o4000;

/// Remove resource
pub const IPC_RMID: i32 = 0;
/// Set ipc_perm options
pub const IPC_SET: i32 = 1;
/// Get ipc_perm options
pub const IPC_STAT: i32 = 2;
/// See ipcs
pub const IPC_INFO: i32 = 3;

/// Private key - always creates new
pub const IPC_PRIVATE: i32 = 0;

/// New version flag for *ctl commands
pub const IPC_64: i32 = 0x0100;

// Subsystem indices in IpcNamespace.ids array
const IPC_SEM_IDS: usize = 0;
const IPC_MSG_IDS: usize = 1;
const IPC_SHM_IDS: usize = 2;

// ============================================================================
// IPC Namespace
// ============================================================================

/// IPC Namespace - isolates SysV IPC objects
///
/// Each namespace has independent:
/// - Shared memory segments
/// - Semaphore arrays
/// - Message queues
/// - Resource limits
pub struct IpcNamespace {
    /// ID tables: [0]=sem, [1]=msg, [2]=shm
    pub ids: [IpcIds; 3],

    // Semaphore limits (SEMMSL, SEMMNS, SEMOPM, SEMMNI)
    pub sem_ctls: [i32; 4],
    pub used_sems: AtomicU32,

    // Message queue limits
    pub msg_ctlmax: u32, // Max message size (MSGMAX)
    pub msg_ctlmnb: u32, // Max bytes in queue (MSGMNB)
    pub msg_ctlmni: u32, // Max queues (MSGMNI)
    pub msg_bytes: AtomicU64,
    pub msg_hdrs: AtomicU64,

    // Shared memory limits
    pub shm_ctlmax: usize, // Max segment size (SHMMAX)
    pub shm_ctlall: usize, // Total max memory (SHMALL)
    pub shm_tot: AtomicU64,
    pub shm_ctlmni: u32, // Max segments (SHMMNI)
}

impl IpcNamespace {
    /// Create a new IPC namespace with default limits
    pub fn new() -> Self {
        Self {
            ids: [IpcIds::new(), IpcIds::new(), IpcIds::new()],

            // Semaphore defaults (from Linux)
            sem_ctls: [
                32000, // SEMMSL - max semaphores per array
                32000, // SEMMNS - max semaphores system-wide (unused, tracked per-ns)
                500,   // SEMOPM - max ops per semop
                32000, // SEMMNI - max semaphore arrays
            ],
            used_sems: AtomicU32::new(0),

            // Message queue defaults
            msg_ctlmax: 8192,  // MSGMAX
            msg_ctlmnb: 16384, // MSGMNB
            msg_ctlmni: 32000, // MSGMNI
            msg_bytes: AtomicU64::new(0),
            msg_hdrs: AtomicU64::new(0),

            // Shared memory defaults
            shm_ctlmax: usize::MAX - (1 << 24), // SHMMAX
            shm_ctlall: usize::MAX - (1 << 24), // SHMALL (pages)
            shm_tot: AtomicU64::new(0),
            shm_ctlmni: 4096, // SHMMNI
        }
    }

    /// Clone this namespace (for CLONE_NEWIPC)
    ///
    /// Creates a new empty namespace with same limits.
    /// IPC objects are NOT copied - new namespace starts empty.
    pub fn clone_ns(&self) -> Result<Arc<Self>, i32> {
        Ok(Arc::new(Self {
            ids: [IpcIds::new(), IpcIds::new(), IpcIds::new()],
            sem_ctls: self.sem_ctls,
            used_sems: AtomicU32::new(0),
            msg_ctlmax: self.msg_ctlmax,
            msg_ctlmnb: self.msg_ctlmnb,
            msg_ctlmni: self.msg_ctlmni,
            msg_bytes: AtomicU64::new(0),
            msg_hdrs: AtomicU64::new(0),
            shm_ctlmax: self.shm_ctlmax,
            shm_ctlall: self.shm_ctlall,
            shm_tot: AtomicU64::new(0),
            shm_ctlmni: self.shm_ctlmni,
        }))
    }

    /// Get semaphore IDs table
    #[inline]
    pub fn sem_ids(&self) -> &IpcIds {
        &self.ids[IPC_SEM_IDS]
    }

    /// Get message queue IDs table
    #[inline]
    pub fn msg_ids(&self) -> &IpcIds {
        &self.ids[IPC_MSG_IDS]
    }

    /// Get shared memory IDs table
    #[inline]
    pub fn shm_ids(&self) -> &IpcIds {
        &self.ids[IPC_SHM_IDS]
    }
}

impl Default for IpcNamespace {
    fn default() -> Self {
        Self::new()
    }
}

/// Initial (root) IPC namespace
pub static INIT_IPC_NS: Lazy<Arc<IpcNamespace>> = Lazy::new(|| Arc::new(IpcNamespace::new()));

// ============================================================================
// User-space ABI structures (must match Linux exactly)
// ============================================================================

/// IPC permission structure (64-bit version)
///
/// This is the ipc64_perm structure used by modern Linux.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Ipc64Perm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u16,
    pub __pad1: [u8; 2], // Padding for mode_t if 16-bit
    pub seq: u16,
    pub __pad2: u16,
    pub __unused1: u64,
    pub __unused2: u64,
}

/// Shared memory segment descriptor (64-bit version)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Shmid64Ds {
    pub shm_perm: Ipc64Perm,
    pub shm_segsz: usize,
    pub shm_atime: i64,
    pub shm_dtime: i64,
    pub shm_ctime: i64,
    pub shm_cpid: i32,
    pub shm_lpid: i32,
    pub shm_nattch: u64,
    pub __unused4: u64,
    pub __unused5: u64,
}

/// Semaphore array descriptor (64-bit version)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Semid64Ds {
    pub sem_perm: Ipc64Perm,
    pub sem_otime: i64,
    pub sem_ctime: i64,
    pub sem_nsems: u64,
    pub __unused3: u64,
    pub __unused4: u64,
}

/// Message queue descriptor (64-bit version)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Msqid64Ds {
    pub msg_perm: Ipc64Perm,
    pub msg_stime: i64,
    pub msg_rtime: i64,
    pub msg_ctime: i64,
    pub msg_cbytes: u64,
    pub msg_qnum: u64,
    pub msg_qbytes: u64,
    pub msg_lspid: i32,
    pub msg_lrpid: i32,
    pub __unused4: u64,
    pub __unused5: u64,
}

/// Semaphore operation buffer
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Sembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

// ============================================================================
// Helper to get current IPC namespace
// ============================================================================

/// Get the current task's IPC namespace
pub fn current_ipc_ns() -> Arc<IpcNamespace> {
    // Get from task's namespace proxy
    if let Some(ns_proxy) = crate::ns::get_task_ns(crate::task::percpu::current_tid()) {
        ns_proxy.ipc_ns.clone()
    } else {
        INIT_IPC_NS.clone()
    }
}
