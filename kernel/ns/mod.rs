//! Linux-compatible namespace infrastructure
//!
//! This module implements the namespace proxy (nsproxy) pattern from Linux,
//! providing per-task namespace isolation. Each task has an NsProxy that
//! holds references to its namespaces (UTS, mount, PID, user, etc.).
//!
//! ## Design Overview
//!
//! Following Linux's `struct nsproxy` pattern:
//! - Each task has an `Arc<NsProxy>` (via `TASK_NS` global table)
//! - Multiple tasks can share the same NsProxy (threads)
//! - Clone with CLONE_NEW* flags creates new namespace(s)
//! - Reference counting via Arc handles cleanup
//!
//! ## Locking
//!
//! - `TASK_NS`: `spin::Mutex` (thread context only)
//! - Per-namespace data: `spin::RwLock` (read-heavy)
//!
//! ## Lock Ordering
//!
//! VFS locks → Namespace locks → Filesystem context → Per-CPU scheduler → TASK_TABLE

pub mod pid;
pub mod user;
pub mod uts;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::{Lazy, Mutex};

use crate::task::Tid;
pub use pid::{
    INIT_PID_NS, PidNamespace, find_task_by_pid_ns, register_task_pids, task_pid_nr,
    task_pid_nr_ns, unregister_task_pids,
};
pub use user::{INIT_USER_NS, UidGidExtent, UidGidMap, UserNamespace};
pub use uts::{__NEW_UTS_LEN, INIT_UTS_NS, NewUtsname, UTS_FIELD_SIZE, UtsNamespace};

use crate::ipc::{INIT_IPC_NS, IpcNamespace};

// ============================================================================
// Namespace Clone Flags (Linux compatible)
// ============================================================================

/// Create new mount namespace (CLONE_NEWNS)
pub const CLONE_NEWNS: u64 = 0x0002_0000;

/// Create new cgroup namespace
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;

/// Create new UTS namespace (hostname, domainname)
pub const CLONE_NEWUTS: u64 = 0x0400_0000;

/// Create new IPC namespace
pub const CLONE_NEWIPC: u64 = 0x0800_0000;

/// Create new user namespace
pub const CLONE_NEWUSER: u64 = 0x1000_0000;

/// Create new PID namespace
pub const CLONE_NEWPID: u64 = 0x2000_0000;

/// Create new network namespace
pub const CLONE_NEWNET: u64 = 0x4000_0000;

/// Mask of all namespace clone flags
pub const CLONE_NS_FLAGS: u64 = CLONE_NEWNS
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWUSER
    | CLONE_NEWCGROUP;

// ============================================================================
// Mount Namespace Wrapper
// ============================================================================

/// Mount namespace wrapper
///
/// Currently wraps the global MOUNT_NS for namespace compatibility.
/// Future: per-namespace mount trees with proper isolation.
pub struct MntNamespace {
    // For now, just a marker - actual mount tree is in fs::MOUNT_NS
    // Future: own mount tree root
}

impl MntNamespace {
    /// Create initial mount namespace
    fn new_init() -> Arc<Self> {
        Arc::new(Self {})
    }

    /// Clone this namespace (for CLONE_NEWNS)
    ///
    /// Currently returns a new wrapper (mounts still shared globally).
    /// Future: copy mount tree for proper isolation.
    pub fn clone_ns(&self) -> Result<Arc<Self>, i32> {
        Ok(Arc::new(Self {}))
    }
}

/// Initial mount namespace
static INIT_MNT_NS: Lazy<Arc<MntNamespace>> = Lazy::new(MntNamespace::new_init);

// ============================================================================
// NsProxy - Namespace Proxy
// ============================================================================

/// Namespace proxy - holds pointers to all namespaces for a task
///
/// Like Linux's `struct nsproxy`, this is shared between threads
/// that share namespaces. When a CLONE_NEW* flag is used, a new
/// NsProxy is created with the new namespace.
///
/// ## Reference Counting
///
/// NsProxy is reference-counted via Arc. Multiple tasks can share
/// the same NsProxy (e.g., threads created without CLONE_NEW* flags).
pub struct NsProxy {
    /// UTS namespace (hostname, domainname)
    pub uts_ns: Arc<UtsNamespace>,

    /// Mount namespace (filesystem view)
    pub mnt_ns: Arc<MntNamespace>,

    /// PID namespace (process ID isolation)
    pub pid_ns: Arc<PidNamespace>,

    /// User namespace (UID/GID mapping)
    pub user_ns: Arc<UserNamespace>,

    /// IPC namespace (SysV IPC isolation)
    pub ipc_ns: Arc<IpcNamespace>,
    // Future namespaces:
    // pub net_ns: Arc<NetNamespace>,
    // pub cgroup_ns: Arc<CgroupNamespace>,
    // pub time_ns: Arc<TimeNamespace>,
}

impl NsProxy {
    /// Create the initial (root) nsproxy
    fn new_init() -> Self {
        Self {
            uts_ns: INIT_UTS_NS.clone(),
            mnt_ns: INIT_MNT_NS.clone(),
            pid_ns: INIT_PID_NS.clone(),
            user_ns: INIT_USER_NS.clone(),
            ipc_ns: INIT_IPC_NS.clone(),
        }
    }

    /// Copy this nsproxy, optionally creating new namespaces
    ///
    /// For each CLONE_NEW* flag set, create a new namespace.
    /// For flags not set, share the existing namespace.
    ///
    /// # Arguments
    /// * `flags` - Clone flags (CLONE_NEWUTS, CLONE_NEWNS, etc.)
    ///
    /// # Returns
    /// * `Ok(Arc<NsProxy>)` - New nsproxy (may share namespaces with self)
    /// * `Err(errno)` - On allocation failure
    pub fn copy(&self, flags: u64) -> Result<Arc<Self>, i32> {
        let uts_ns = if flags & CLONE_NEWUTS != 0 {
            self.uts_ns.clone_ns()?
        } else {
            self.uts_ns.clone()
        };

        let mnt_ns = if flags & CLONE_NEWNS != 0 {
            self.mnt_ns.clone_ns()?
        } else {
            self.mnt_ns.clone()
        };

        let pid_ns = if flags & CLONE_NEWPID != 0 {
            PidNamespace::clone_ns(&self.pid_ns)?
        } else {
            self.pid_ns.clone()
        };

        let user_ns = if flags & CLONE_NEWUSER != 0 {
            UserNamespace::clone_ns(&self.user_ns)?
        } else {
            self.user_ns.clone()
        };

        let ipc_ns = if flags & CLONE_NEWIPC != 0 {
            self.ipc_ns.clone_ns()?
        } else {
            self.ipc_ns.clone()
        };

        Ok(Arc::new(Self {
            uts_ns,
            mnt_ns,
            pid_ns,
            user_ns,
            ipc_ns,
        }))
    }
}

/// Initial (root) namespace proxy
///
/// All tasks inherit from this unless they create new namespaces.
pub static INIT_NSPROXY: Lazy<Arc<NsProxy>> = Lazy::new(|| Arc::new(NsProxy::new_init()));

// ============================================================================
// Task-NsProxy Mapping (following FsStruct pattern)
// ============================================================================

/// Global table mapping TID -> NsProxy
///
/// Multiple tasks can share the same Arc<NsProxy> when created
/// without CLONE_NEW* flags (threads sharing namespaces).
static TASK_NS: Mutex<BTreeMap<Tid, Arc<NsProxy>>> = Mutex::new(BTreeMap::new());

/// Initialize nsproxy for a new task
///
/// Called when creating a new task to set up its namespace context.
pub fn init_task_ns(tid: Tid, nsproxy: Arc<NsProxy>) {
    TASK_NS.lock().insert(tid, nsproxy);
}

/// Get the NsProxy for a task
///
/// Returns a cloned Arc (increments refcount).
pub fn get_task_ns(tid: Tid) -> Option<Arc<NsProxy>> {
    TASK_NS.lock().get(&tid).cloned()
}

/// Remove nsproxy when task exits
///
/// This decrements the Arc refcount. If this was the last reference
/// (no other tasks sharing this NsProxy), the NsProxy is dropped,
/// which in turn drops the namespace references.
pub fn exit_task_ns(tid: Tid) {
    TASK_NS.lock().remove(&tid);
}

/// Clone nsproxy for fork/clone
///
/// If any CLONE_NEW* flags are set, creates a new NsProxy with
/// new namespace(s). Otherwise, shares the parent's NsProxy.
///
/// # Arguments
/// * `parent_tid` - Parent task's TID
/// * `child_tid` - Child task's TID
/// * `flags` - Clone flags
///
/// # Returns
/// * `Ok(())` - Success
/// * `Err(errno)` - On allocation failure
pub fn copy_namespaces(parent_tid: Tid, child_tid: Tid, flags: u64) -> Result<(), i32> {
    let ns_flags = flags & CLONE_NS_FLAGS;

    let child_ns = if ns_flags != 0 {
        // Some namespace flags set - copy with potential new namespaces
        let parent_ns = get_task_ns(parent_tid).unwrap_or_else(|| INIT_NSPROXY.clone());
        parent_ns.copy(ns_flags)?
    } else {
        // No namespace flags - share parent's nsproxy
        get_task_ns(parent_tid).unwrap_or_else(|| INIT_NSPROXY.clone())
    };

    init_task_ns(child_tid, child_ns);
    Ok(())
}

// ============================================================================
// Accessor Functions (for syscall handlers)
// ============================================================================

/// Get current task's UTS namespace
///
/// Returns the UTS namespace for the calling task, or the init
/// namespace if no namespace context is set.
pub fn current_uts_ns() -> Arc<UtsNamespace> {
    let tid = crate::task::percpu::current_tid();
    get_task_ns(tid)
        .map(|ns| ns.uts_ns.clone())
        .unwrap_or_else(|| INIT_UTS_NS.clone())
}

/// Get current task's mount namespace
///
/// Returns the mount namespace for the calling task, or the init
/// namespace if no namespace context is set.
pub fn current_mnt_ns() -> Arc<MntNamespace> {
    let tid = crate::task::percpu::current_tid();
    get_task_ns(tid)
        .map(|ns| ns.mnt_ns.clone())
        .unwrap_or_else(|| INIT_MNT_NS.clone())
}

/// Get current task's PID namespace
///
/// Returns the PID namespace for the calling task, or the init
/// namespace if no namespace context is set.
pub fn current_pid_ns() -> Arc<PidNamespace> {
    let tid = crate::task::percpu::current_tid();
    get_task_ns(tid)
        .map(|ns| ns.pid_ns.clone())
        .unwrap_or_else(|| INIT_PID_NS.clone())
}

/// Get current task's user namespace
///
/// Returns the user namespace for the calling task, or the init
/// namespace if no namespace context is set.
pub fn current_user_ns() -> Arc<UserNamespace> {
    let tid = crate::task::percpu::current_tid();
    get_task_ns(tid)
        .map(|ns| ns.user_ns.clone())
        .unwrap_or_else(|| INIT_USER_NS.clone())
}

// ============================================================================
// Unshare Syscall
// ============================================================================

/// Error codes for namespace operations
const EPERM: i64 = 1;
const EINVAL: i64 = 22;

/// Currently supported namespace flags for unshare
///
/// We support UTS, mount, PID, user, and IPC namespaces.
const SUPPORTED_NS_FLAGS: u64 =
    CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWIPC;

/// sys_unshare - disassociate parts of the process execution context
///
/// Creates new namespaces for the calling process, disassociating from
/// the parent's namespace(s).
///
/// # Arguments
/// * `unshare_flags` - Bitwise OR of CLONE_NEW* flags
///
/// # Returns
/// * 0 on success
/// * -EPERM if unprivileged and namespace requires privilege
/// * -EINVAL if unsupported flags are specified
///
/// # Notes
/// Unlike clone(), unshare() always affects the calling thread.
/// The new namespace takes effect immediately.
/// CLONE_SYSVSEM flag - used by unshare to detach from shared semundo
const CLONE_SYSVSEM: u64 = 0x00040000;

pub fn sys_unshare(unshare_flags: u64) -> i64 {
    let tid = crate::task::percpu::current_tid();
    let ns_flags = unshare_flags & CLONE_NS_FLAGS;
    let sysvsem_flag = unshare_flags & CLONE_SYSVSEM;

    // Handle CLONE_SYSVSEM - detach from shared semaphore undo list
    // Similar to what Linux does: exit_sem(current) effectively
    if sysvsem_flag != 0 {
        // Detach from any shared undo list by exiting and re-creating
        // This applies any pending undos if we're the last holder
        crate::ipc::sem::exit_sem(tid);
    }

    // No namespace flags - nothing more to do
    if ns_flags == 0 {
        return 0;
    }

    // Check for unsupported namespace flags
    // Currently we support: UTS, mount
    // PID and user will be added in Phase 2-3
    let unsupported = ns_flags & !SUPPORTED_NS_FLAGS;
    if unsupported != 0 {
        return -EINVAL;
    }

    // Permission check: CAP_SYS_ADMIN required for namespace creation
    // In our current model, only euid==0 has this capability
    let cred = crate::task::percpu::current_cred();
    if cred.euid != 0 {
        return -EPERM;
    }

    // Get current namespace proxy
    let current_ns = get_task_ns(tid).unwrap_or_else(|| INIT_NSPROXY.clone());

    // Create new nsproxy with new namespace(s)
    let new_ns = match current_ns.copy(ns_flags) {
        Ok(ns) => ns,
        Err(_) => return -EINVAL,
    };

    // Switch to new namespace (atomic via mutex)
    switch_task_namespaces(tid, new_ns);

    0
}

/// Switch a task's namespace to a new nsproxy
///
/// This atomically replaces the task's nsproxy. Used by both
/// unshare() and setns().
pub fn switch_task_namespaces(tid: Tid, new_ns: Arc<NsProxy>) {
    TASK_NS.lock().insert(tid, new_ns);
}

// ============================================================================
// Setns Syscall
// ============================================================================

/// Error codes for setns
const EBADF: i64 = 9;
const ESRCH: i64 = 3;

/// sys_setns - reassociate thread with a namespace
///
/// Join an existing namespace by file descriptor. The fd should refer
/// to a namespace file (typically `/proc/<pid>/ns/<type>`).
///
/// # Arguments
/// * `fd` - File descriptor referring to a namespace
/// * `nstype` - Type of namespace (0 = any, or specific CLONE_NEW* flag)
///
/// # Returns
/// * 0 on success
/// * -EBADF if fd is invalid or not a namespace file
/// * -EINVAL if nstype doesn't match the namespace type
/// * -EPERM if permission denied
pub fn sys_setns(fd: i32, nstype: i32) -> i64 {
    use crate::fs::procfs::{NamespaceType, ProcfsInodeData, ProcfsInodeWrapper};
    use crate::task::fdtable::get_task_fd;
    use crate::task::percpu::current_tid;

    let tid = current_tid();

    // Get file from fd
    let fd_table = match get_task_fd(tid) {
        Some(t) => t,
        None => return -EBADF,
    };
    let file = match fd_table.lock().get(fd) {
        Some(f) => f,
        None => return -EBADF,
    };

    // Get inode from file
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return -EBADF,
    };

    // Get private data and check if it's a namespace file
    let private = match inode.get_private() {
        Some(p) => p,
        None => return -EINVAL,
    };

    let wrapper = match private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()
    {
        Some(w) => w,
        None => return -EINVAL, // Not a procfs file
    };

    let data = wrapper.0.read();
    let (target_pid, ns_type) = match &*data {
        ProcfsInodeData::NamespaceFile { pid, ns_type } => (*pid, *ns_type),
        _ => return -EINVAL, // Not a namespace file
    };

    // Validate nstype if specified
    if nstype != 0 {
        let expected_flag = ns_type.clone_flag() as i32;
        if nstype != expected_flag {
            return -EINVAL;
        }
    }

    // Get the TID for the target PID
    let target_tid = match crate::fs::procfs::get_tid_for_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Permission check: require root for now
    let cred = crate::task::percpu::current_cred();
    if cred.euid != 0 {
        return -EPERM;
    }

    // Get target task's namespace using TID
    let target_ns = match get_task_ns(target_tid) {
        Some(ns) => ns,
        None => return -ESRCH,
    };

    let current_ns = get_task_ns(tid).unwrap_or_else(|| INIT_NSPROXY.clone());

    // Create new nsproxy with the target namespace for the specified type
    let new_ns = match ns_type {
        NamespaceType::Uts => Arc::new(NsProxy {
            uts_ns: target_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
        }),
        NamespaceType::Mnt => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: target_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
        }),
        NamespaceType::Pid => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: target_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
        }),
        NamespaceType::User => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: target_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
        }),
        NamespaceType::Ipc => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: target_ns.ipc_ns.clone(),
        }),
    };

    switch_task_namespaces(tid, new_ns);
    0
}
