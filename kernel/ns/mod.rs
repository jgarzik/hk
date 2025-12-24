//! Linux-compatible namespace infrastructure
//!
//! This module implements the namespace proxy (nsproxy) pattern from Linux,
//! providing per-task namespace isolation. Each task has an NsProxy that
//! holds references to its namespaces (UTS, mount, PID, user, etc.).
//!
//! ## Design Overview
//!
//! Following Linux's `struct nsproxy` pattern:
//! - Each task has an `Arc<NsProxy>` (via `Task.nsproxy` field)
//! - Multiple tasks can share the same NsProxy (threads)
//! - Clone with CLONE_NEW* flags creates new namespace(s)
//! - Reference counting via Arc handles cleanup
//!
//! ## Locking
//!
//! - `TASK_TABLE`: Protects task struct access (including nsproxy field)
//! - Per-namespace data: `spin::RwLock` (read-heavy)
//!
//! ## Lock Ordering
//!
//! VFS locks → Namespace locks → Filesystem context → Per-CPU scheduler → TASK_TABLE

pub mod net;
pub mod pid;
pub mod user;
pub mod uts;

use alloc::sync::Arc;
use spin::{Lazy, RwLock};

use crate::task::Tid;
pub use pid::{
    INIT_PID_NS, PidNamespace, find_task_by_pid_ns, register_task_pids, task_pid_nr,
    task_pid_nr_ns, unregister_task_pids,
};
pub use user::{INIT_USER_NS, UidGidExtent, UidGidMap, UserNamespace};
pub use uts::{__NEW_UTS_LEN, INIT_UTS_NS, NewUtsname, UTS_FIELD_SIZE, UtsNamespace};

use crate::ipc::{INIT_IPC_NS, IpcNamespace};
pub use net::{INIT_NET_NS, NetNamespace, init_net_ns};

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
// Mount Namespace
// ============================================================================

use crate::fs::mount::Mount;

/// Mount namespace - per-namespace mount tree
///
/// Each mount namespace has its own view of the filesystem hierarchy.
/// When CLONE_NEWNS is used, the entire mount tree is cloned.
pub struct MntNamespace {
    /// Root mount of this namespace
    pub root: RwLock<Option<Arc<Mount>>>,
}

impl MntNamespace {
    /// Create a new empty mount namespace
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            root: RwLock::new(None),
        })
    }

    /// Create initial mount namespace
    fn new_init() -> Arc<Self> {
        Self::new()
    }

    /// Clone this namespace (for CLONE_NEWNS)
    ///
    /// Deep-copies the entire mount tree so the new namespace has
    /// an independent view of the filesystem hierarchy.
    pub fn clone_ns(&self) -> Result<Arc<Self>, i32> {
        let new_ns = Self::new();

        // Clone the mount tree if we have a root
        if let Some(old_root) = self.root.read().as_ref() {
            let new_root = Mount::clone_tree(old_root)?;
            *new_ns.root.write() = Some(new_root);
        }

        Ok(new_ns)
    }

    /// Set the root mount
    pub fn set_root(&self, mount: Arc<Mount>) {
        *self.root.write() = Some(mount);
    }

    /// Get the root mount
    pub fn get_root(&self) -> Option<Arc<Mount>> {
        self.root.read().clone()
    }

    /// Get the root dentry
    pub fn get_root_dentry(&self) -> Option<Arc<crate::fs::dentry::Dentry>> {
        self.get_root().map(|m| m.root.clone())
    }

    /// Find which mount a dentry belongs to by device ID
    pub fn find_mount_for_dev(&self, dev_id: u64) -> Option<Arc<Mount>> {
        let root = self.get_root()?;

        // Check if dentry belongs to root mount's filesystem
        if root.sb.dev_id == dev_id {
            return Some(root.clone());
        }

        // Check children recursively
        self.find_mount_for_dev_recursive(&root, dev_id)
    }

    fn find_mount_for_dev_recursive(&self, mount: &Arc<Mount>, dev_id: u64) -> Option<Arc<Mount>> {
        for child in mount.children.read().iter() {
            if child.sb.dev_id == dev_id {
                return Some(child.clone());
            }
            if let Some(found) = self.find_mount_for_dev_recursive(child, dev_id) {
                return Some(found);
            }
        }
        None
    }

    /// Find mount whose root dentry matches the given dentry
    pub fn find_mount_at(&self, dentry: &Arc<crate::fs::dentry::Dentry>) -> Option<Arc<Mount>> {
        let root = self.get_root()?;

        // Check if this is the root mount
        if Arc::ptr_eq(&root.root, dentry) {
            return Some(root);
        }

        // Check if dentry matches root mount's root by inode
        if let (Some(root_ino), Some(d_ino)) = (root.root.get_inode(), dentry.get_inode())
            && root_ino.ino == d_ino.ino
            && root.root.superblock().map(|s| s.dev_id) == dentry.superblock().map(|s| s.dev_id)
        {
            return Some(root);
        }

        // Search children recursively
        self.find_mount_recursive(&root, dentry)
    }

    fn find_mount_recursive(
        &self,
        mount: &Arc<Mount>,
        dentry: &Arc<crate::fs::dentry::Dentry>,
    ) -> Option<Arc<Mount>> {
        for child in mount.children.read().iter() {
            // Check if child's root dentry matches the target
            if Arc::ptr_eq(&child.root, dentry) {
                return Some(child.clone());
            }

            // Also check by inode number + device ID
            if let (Some(child_ino), Some(d_ino)) = (child.root.get_inode(), dentry.get_inode())
                && child_ino.ino == d_ino.ino
                && child.root.superblock().map(|s| s.dev_id)
                    == dentry.superblock().map(|s| s.dev_id)
            {
                return Some(child.clone());
            }

            // Recurse into child's children
            if let Some(found) = self.find_mount_recursive(child, dentry) {
                return Some(found);
            }
        }
        None
    }

    /// Find which mount a dentry belongs to
    ///
    /// Given a dentry, returns the mount whose filesystem contains it.
    /// This walks up the mount tree to find the appropriate mount.
    pub fn find_mount_for_dentry(
        &self,
        dentry: &Arc<crate::fs::dentry::Dentry>,
    ) -> Option<Arc<Mount>> {
        let root = self.get_root()?;

        // Check if dentry belongs to root mount's filesystem
        if let Some(dentry_sb) = dentry.superblock() {
            // First check root mount
            if dentry_sb.dev_id == root.sb.dev_id {
                return Some(root.clone());
            }

            // Check children recursively by device ID
            self.find_mount_for_dev_recursive(&root, dentry_sb.dev_id)
        } else {
            // Fall back to root mount
            Some(root)
        }
    }
}

impl Default for MntNamespace {
    fn default() -> Self {
        Self {
            root: RwLock::new(None),
        }
    }
}

/// Initial mount namespace
pub static INIT_MNT_NS: Lazy<Arc<MntNamespace>> = Lazy::new(MntNamespace::new_init);

/// Get the init mount namespace
pub fn init_mnt_ns() -> Arc<MntNamespace> {
    INIT_MNT_NS.clone()
}

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

    /// Network namespace (network stack isolation)
    pub net_ns: Arc<NetNamespace>,
    // Future namespaces:
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
            net_ns: INIT_NET_NS.clone(),
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

        let net_ns = if flags & CLONE_NEWNET != 0 {
            self.net_ns.clone_ns()?
        } else {
            self.net_ns.clone()
        };

        Ok(Arc::new(Self {
            uts_ns,
            mnt_ns,
            pid_ns,
            user_ns,
            ipc_ns,
            net_ns,
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

// =============================================================================
// Task NS accessors - uses Task.nsproxy field directly via TASK_TABLE
// =============================================================================

use crate::task::percpu::TASK_TABLE;

/// Initialize nsproxy for a new task
///
/// Called when creating a new task to set up its namespace context.
pub fn init_task_ns(tid: Tid, nsproxy: Arc<NsProxy>) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.nsproxy = Some(nsproxy);
    }
}

/// Get the NsProxy for a task
///
/// Returns a cloned Arc (increments refcount).
pub fn get_task_ns(tid: Tid) -> Option<Arc<NsProxy>> {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .and_then(|t| t.nsproxy.clone())
}

/// Remove nsproxy when task exits
///
/// This decrements the Arc refcount. If this was the last reference
/// (no other tasks sharing this NsProxy), the NsProxy is dropped,
/// which in turn drops the namespace references.
pub fn exit_task_ns(tid: Tid) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.nsproxy = None;
    }
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

/// Get current task's network namespace
///
/// Returns the network namespace for the calling task, or the init
/// namespace if no namespace context is set.
pub fn current_net_ns() -> Arc<NetNamespace> {
    let tid = crate::task::percpu::current_tid();
    get_task_ns(tid)
        .map(|ns| ns.net_ns.clone())
        .unwrap_or_else(|| INIT_NET_NS.clone())
}

// ============================================================================
// Unshare Syscall
// ============================================================================

/// Error codes for namespace operations
const EPERM: i64 = 1;
const EINVAL: i64 = 22;

/// Currently supported namespace flags for unshare
///
/// We support UTS, mount, PID, user, IPC, and network namespaces.
const SUPPORTED_NS_FLAGS: u64 =
    CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWNET;

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
    init_task_ns(tid, new_ns);
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
            net_ns: current_ns.net_ns.clone(),
        }),
        NamespaceType::Mnt => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: target_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
            net_ns: current_ns.net_ns.clone(),
        }),
        NamespaceType::Pid => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: target_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
            net_ns: current_ns.net_ns.clone(),
        }),
        NamespaceType::User => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: target_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
            net_ns: current_ns.net_ns.clone(),
        }),
        NamespaceType::Ipc => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: target_ns.ipc_ns.clone(),
            net_ns: current_ns.net_ns.clone(),
        }),
        NamespaceType::Net => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
            net_ns: target_ns.net_ns.clone(),
        }),
    };

    switch_task_namespaces(tid, new_ns);
    0
}
