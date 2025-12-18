//! Linux-compatible namespace infrastructure
//!
//! This module implements the namespace proxy (nsproxy) pattern from Linux,
//! providing per-task namespace isolation. Each task has an NsProxy that
//! holds references to its namespaces (UTS, mount, etc.).
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

pub mod uts;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::{Lazy, Mutex};

use crate::task::Tid;
pub use uts::{__NEW_UTS_LEN, INIT_UTS_NS, NewUtsname, UTS_FIELD_SIZE, UtsNamespace};

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
// User Namespace Placeholder
// ============================================================================

/// User namespace (placeholder for capability checks)
///
/// Currently not implemented - all tasks have root capabilities.
/// Future: proper user namespace with uid/gid mapping.
pub struct UserNamespace {
    // Placeholder
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
    // Future namespaces:
    // pub ipc_ns: Arc<IpcNamespace>,
    // pub pid_ns: Arc<PidNamespace>,
    // pub net_ns: Arc<NetNamespace>,
    // pub user_ns: Arc<UserNamespace>,
    // pub cgroup_ns: Arc<CgroupNamespace>,
    // pub time_ns: Arc<TimeNamespace>,
}

impl NsProxy {
    /// Create the initial (root) nsproxy
    fn new_init() -> Self {
        Self {
            uts_ns: INIT_UTS_NS.clone(),
            mnt_ns: INIT_MNT_NS.clone(),
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

        Ok(Arc::new(Self { uts_ns, mnt_ns }))
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
