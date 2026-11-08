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

use crate::util::error::KernelResult;
use crate::util::kalloc::{arc_nofail, try_arc};
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
    /// ID tables, one per object type
    sem_ids: IpcIds<sem::SemArray>,
    msg_ids: IpcIds<msg::MsgQueue>,
    shm_ids: IpcIds<shm::ShmidKernel>,

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

    /// Its inode number (Linux ns.inum)
    pub inum: crate::ns::inum::Inum,
}

impl IpcNamespace {
    /// The initial IPC namespace, with default limits
    fn new_init() -> Self {
        Self {
            sem_ids: IpcIds::new(),
            msg_ids: IpcIds::new(),
            shm_ids: IpcIds::new(),

            // Semaphore defaults (from Linux)
            sem_ctls: [
                32000,         // SEMMSL - max semaphores per array
                1_024_000_000, // SEMMNS - semaphores in all arrays (Linux SEMMNI*SEMMSL)
                500,           // SEMOPM - max ops per semop
                32000,         // SEMMNI - max semaphore arrays
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
            inum: crate::ns::inum::Inum::fixed(crate::ns::inum::IPC_INIT),
        }
    }

    /// Clone this namespace (for CLONE_NEWIPC)
    ///
    /// Creates a new empty namespace with same limits.
    /// IPC objects are NOT copied - new namespace starts empty.
    pub fn clone_ns(&self) -> KernelResult<Arc<Self>> {
        let inum = crate::ns::inum::Inum::alloc()?;
        try_arc(Self {
            sem_ids: IpcIds::new(),
            msg_ids: IpcIds::new(),
            shm_ids: IpcIds::new(),
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
            inum,
        })
    }

    /// Get semaphore IDs table
    #[inline]
    pub fn sem_ids(&self) -> &IpcIds<sem::SemArray> {
        &self.sem_ids
    }

    /// Get message queue IDs table
    #[inline]
    pub fn msg_ids(&self) -> &IpcIds<msg::MsgQueue> {
        &self.msg_ids
    }

    /// Get shared memory IDs table
    #[inline]
    pub fn shm_ids(&self) -> &IpcIds<shm::ShmidKernel> {
        &self.shm_ids
    }
}

/// Initial (root) IPC namespace
pub static INIT_IPC_NS: Lazy<Arc<IpcNamespace>> =
    Lazy::new(|| arc_nofail(IpcNamespace::new_init()));

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
    /// Explicit padding before __unused1 (always zero; implicit in Linux)
    pub __pad3: u32,
    pub __unused1: u64,
    pub __unused2: u64,
}
crate::pod!(Ipc64Perm {
    key,
    uid,
    gid,
    cuid,
    cgid,
    mode,
    __pad1,
    seq,
    __pad2,
    __pad3,
    __unused1,
    __unused2
});

const _: () = assert!(core::mem::size_of::<Ipc64Perm>() == 48);

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
crate::pod!(Shmid64Ds {
    shm_perm,
    shm_segsz,
    shm_atime,
    shm_dtime,
    shm_ctime,
    shm_cpid,
    shm_lpid,
    shm_nattch,
    __unused4,
    __unused5
});

/// Semaphore array descriptor (64-bit version; layout differs per arch)
pub use crate::arch::uapi::Semid64Ds;

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
crate::pod!(Msqid64Ds {
    msg_perm,
    msg_stime,
    msg_rtime,
    msg_ctime,
    msg_cbytes,
    msg_qnum,
    msg_qbytes,
    msg_lspid,
    msg_lrpid,
    __unused4,
    __unused5
});

/// Semaphore operation buffer
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Sembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}
crate::pod!(Sembuf {
    sem_num,
    sem_op,
    sem_flg
});

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
