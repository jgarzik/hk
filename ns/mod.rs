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
//! - `Task.alloc_lock` (Linux task_lock): the nsproxy field (lock-free
//!   for the task itself, which alone replaces it)
//! - Per-namespace data: `crate::sync::spin::RwLock` (read-heavy)
//!
//! ## Lock Ordering
//!
//! VFS locks → Namespace locks → Filesystem context → Per-CPU scheduler → TASKLIST
#![expect(clippy::disallowed_methods)] // TODO(alloc): util::kalloc

pub mod cgroup;
pub mod net;
pub mod pid;
pub mod user;
pub mod uts;

use crate::sync::spin::RwLock;
use alloc::sync::Arc;
use spin::Lazy;

use crate::task::Tid;
pub use cgroup::{CgroupNamespace, INIT_CGROUP_NS};
pub use pid::{INIT_PID_NS, PidNamespace};
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
    /// `fs` (the new task's, or the unsharer's own) moves its root and
    /// pwd to the copies of their mounts (Linux copy_mnt_ns)
    pub fn clone_ns(&self, fs: Option<&crate::fs::FsStruct>) -> Result<Arc<Self>, i32> {
        let new_ns = Self::new();
        let old_root = self.root.read().clone();
        if let Some(old_root) = old_root {
            let (new_root, map) = Mount::clone_tree(&old_root)?;
            *new_ns.root.write() = Some(new_root);
            if let Some(fs) = fs {
                fs.repoint(&map);
            }
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

    /// Where "/" lands in this namespace (Linux LOOKUP_DOWN from the
    /// namespace root): the topmost mount on the nullfs root, the
    /// rootfs until something is pivoted or mounted over it
    pub fn root_path(&self) -> Option<crate::fs::Path> {
        let m = self.get_root()?;
        Some(crate::fs::mount::follow_mount(crate::fs::Path::new(
            m.clone(),
            m.root.clone(),
        )))
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

    /// Cgroup namespace (cgroup hierarchy virtualization)
    pub cgroup_ns: Arc<CgroupNamespace>,
    // Future namespaces:
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
            cgroup_ns: INIT_CGROUP_NS.clone(),
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
    pub fn copy(&self, flags: u64, fs: Option<&crate::fs::FsStruct>) -> Result<Arc<Self>, i32> {
        let uts_ns = if flags & CLONE_NEWUTS != 0 {
            self.uts_ns.clone_ns()?
        } else {
            self.uts_ns.clone()
        };

        let mnt_ns = if flags & CLONE_NEWNS != 0 {
            self.mnt_ns.clone_ns(fs)?
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

        let cgroup_ns = if flags & CLONE_NEWCGROUP != 0 {
            // New cgroup namespace rooted at current task's cgroup
            // For now, use the same root (proper implementation would get task's cgroup)
            self.cgroup_ns.clone_ns(self.cgroup_ns.root())?
        } else {
            self.cgroup_ns.clone()
        };

        Ok(Arc::new(Self {
            uts_ns,
            mnt_ns,
            pid_ns,
            user_ns,
            ipc_ns,
            net_ns,
            cgroup_ns,
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
// Task NS accessors - Task.nsproxy under its alloc_lock (Linux task_lock)
// =============================================================================

use crate::task::percpu::{current, with_task_lock};

/// Initialize nsproxy for a new task
///
/// Called when creating a new task to set up its namespace context, or
/// by the task itself (unshare, setns; Linux switch_task_namespaces).
pub fn init_task_ns(tid: Tid, nsproxy: Arc<NsProxy>) {
    let old = with_task_lock(tid, |a| a.set_nsproxy(Some(nsproxy)));
    drop(old);
}

/// Get the NsProxy for a task
///
/// Returns a cloned Arc (increments refcount); lock-free for the
/// current task (Linux current->nsproxy).
pub fn get_task_ns(tid: Tid) -> Option<Arc<NsProxy>> {
    let me = current();
    if me.tid() == tid {
        return me.nsproxy();
    }
    with_task_lock(tid, |a| a.nsproxy().cloned()).flatten()
}

/// Remove nsproxy when task exits
///
/// This decrements the Arc refcount. If this was the last reference
/// (no other tasks sharing this NsProxy), the NsProxy is dropped,
/// which in turn drops the namespace references (after the task's
/// alloc_lock is released: a network namespace's teardown takes RTNL).
pub fn exit_task_ns(tid: Tid) {
    let ns = with_task_lock(tid, |a| a.set_nsproxy(None)).flatten();
    drop(ns);
}

/// New namespaces other than a user namespace need CAP_SYS_ADMIN (Linux
/// copy_namespaces, unshare_nsproxy_namespaces); a user namespace alone
/// needs none. Linux checks in the new user namespace when CLONE_NEWUSER
/// comes with them, where the caller holds every capability; hk's user
/// namespaces grant none (BUGS.md), so it checks the caller's own.
fn may_create_namespaces(ns_flags: u64) -> bool {
    ns_flags & !CLONE_NEWUSER == 0 || crate::task::capable(crate::task::CAP_SYS_ADMIN)
}

/// The namespaces a child of `parent_tid` gets (Linux copy_namespaces):
/// new ones for the CLONE_NEW* flags, else the parent's. `child_fs` is
/// the child's fs context, moved to the copies of its root's and cwd's
/// mounts in a new mount namespace. Built before the child is visible,
/// so a failure leaves nothing behind.
pub fn fork_nsproxy(
    parent_tid: Tid,
    flags: u64,
    child_fs: Option<&crate::fs::FsStruct>,
) -> Result<Arc<NsProxy>, i32> {
    let ns_flags = flags & CLONE_NS_FLAGS;
    // CLONE_NEWNS with a shared fs struct is EINVAL, before any
    // permission check (Linux copy_process); the child's own copy
    // follows its new mounts
    if ns_flags & CLONE_NEWNS != 0 && flags & crate::task::clone_flags::CLONE_FS != 0 {
        return Err(22);
    }
    if !may_create_namespaces(ns_flags) {
        return Err(EPERM as i32);
    }
    let parent_ns = get_task_ns(parent_tid).unwrap_or_else(|| INIT_NSPROXY.clone());
    if ns_flags == 0 {
        return Ok(parent_ns);
    }
    parent_ns.copy(ns_flags, child_fs)
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

    if !may_create_namespaces(ns_flags) {
        return -EPERM;
    }

    // Get current namespace proxy
    let current_ns = get_task_ns(tid).unwrap_or_else(|| INIT_NSPROXY.clone());

    // Create new nsproxy with new namespace(s)
    // CLONE_NEWNS implies CLONE_FS (Linux unshare): a private fs
    // struct, moved to the copies of its mounts
    let fs = if ns_flags & CLONE_NEWNS != 0 {
        let fs = crate::task::percpu::current_fs().map(|f| f.copy());
        if let Some(f) = &fs {
            crate::fs::init_task_fs(tid, f.clone());
        }
        fs
    } else {
        None
    };
    let new_ns = match current_ns.copy(ns_flags, fs.as_deref()) {
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
    use crate::fs::proc::{NamespaceType, ProcfsInodeData, ProcfsInodeWrapper};
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
    let target_tid = match crate::fs::proc::get_tid_for_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Linux ->install: CAP_SYS_ADMIN, and CAP_SYS_CHROOT for a mount
    // namespace (mntns_install)
    let chroot_ok =
        !matches!(ns_type, NamespaceType::Mnt) || crate::task::capable(crate::task::CAP_SYS_CHROOT);
    if !crate::task::capable(crate::task::CAP_SYS_ADMIN) || !chroot_ok {
        return -EPERM;
    }

    // Get target task's namespace using TID
    let target_ns = match get_task_ns(target_tid) {
        Some(ns) => ns,
        None => return -ESRCH,
    };

    let current_ns = get_task_ns(tid).unwrap_or_else(|| INIT_NSPROXY.clone());

    // A mount namespace moves root and cwd: not with an fs struct
    // shared with other tasks (Linux mntns_install: fs->users != 1)
    if matches!(ns_type, NamespaceType::Mnt)
        && crate::task::percpu::current_fs()
            .is_some_and(|fs| fs.users.load(core::sync::atomic::Ordering::SeqCst) != 1)
    {
        return -EINVAL;
    }

    // Create new nsproxy with the target namespace for the specified type
    let new_ns = match ns_type {
        NamespaceType::Uts => Arc::new(NsProxy {
            uts_ns: target_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
            net_ns: current_ns.net_ns.clone(),
            cgroup_ns: current_ns.cgroup_ns.clone(),
        }),
        NamespaceType::Mnt => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: target_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
            net_ns: current_ns.net_ns.clone(),
            cgroup_ns: current_ns.cgroup_ns.clone(),
        }),
        NamespaceType::Pid => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: target_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
            net_ns: current_ns.net_ns.clone(),
            cgroup_ns: current_ns.cgroup_ns.clone(),
        }),
        NamespaceType::User => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: target_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
            net_ns: current_ns.net_ns.clone(),
            cgroup_ns: current_ns.cgroup_ns.clone(),
        }),
        NamespaceType::Ipc => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: target_ns.ipc_ns.clone(),
            net_ns: current_ns.net_ns.clone(),
            cgroup_ns: current_ns.cgroup_ns.clone(),
        }),
        NamespaceType::Net => Arc::new(NsProxy {
            uts_ns: current_ns.uts_ns.clone(),
            mnt_ns: current_ns.mnt_ns.clone(),
            pid_ns: current_ns.pid_ns.clone(),
            user_ns: current_ns.user_ns.clone(),
            ipc_ns: current_ns.ipc_ns.clone(),
            net_ns: target_ns.net_ns.clone(),
            cgroup_ns: current_ns.cgroup_ns.clone(),
        }),
    };

    let mnt_root = matches!(ns_type, NamespaceType::Mnt)
        .then(|| new_ns.mnt_ns.root_path())
        .flatten();
    switch_task_namespaces(tid, new_ns);
    // Joining a mount namespace puts root and cwd at its root, past
    // what is mounted there (Linux mntns_install: LOOKUP_DOWN)
    if let (Some(root), Some(fs)) = (mnt_root, crate::task::percpu::current_fs()) {
        fs.set_root(root.clone());
        fs.set_pwd(root);
    }
    0
}
