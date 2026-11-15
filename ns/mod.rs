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

pub mod cgroup;
pub mod common;
pub mod inum;
pub mod net;
pub mod pid;
pub mod setns;
pub mod user;
pub mod uts;

use crate::sync::spin::RwLock;
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::{arc_nofail, try_arc};
use crate::util::rbtree::{RbTree, RbTreeNodeReservation};
use alloc::sync::{Arc, Weak};
use spin::Lazy;

pub use cgroup::{CgroupNamespace, INIT_CGROUP_NS};
pub use common::{NsCommon, NsRef};
pub use pid::{INIT_PID_NS, PidNamespace};
pub use setns::sys_setns;
pub use user::{INIT_USER_NS, UidGidExtent, UidGidMap, UserNamespace};
pub use uts::{__NEW_UTS_LEN, INIT_UTS_NS, NewUtsname, UTS_FIELD_SIZE, UtsNamespace};

use crate::ipc::{INIT_IPC_NS, IpcNamespace};
pub use net::{INIT_NET_NS, NetNamespace, NetRef, init_net_ns};

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

use crate::fs::mount::{Mount, MountRef};

impl Drop for MntNamespace {
    /// Linux put_mnt_ns: the tree is unmounted whole (sleeps: the last
    /// reference goes in thread context with nothing held, an exit or
    /// unshare/setns, or a namespace file's deferred release); first
    /// it leaves the namespace tree (Linux mnt_ns_tree_remove)
    fn drop(&mut self) {
        let node = MNT_NS_TREE.lock().remove_node(&self.id());
        drop(node);
        if let Some(root) = self.root.get_mut().take() {
            crate::fs::mount::put_mnt_ns(root);
        }
    }
}

/// A mount namespace's entry in the namespace tree: its owning user
/// namespace and itself, neither kept alive by it
type MntNsEntry = (Weak<UserNamespace>, Weak<MntNamespace>);

/// Live mount namespaces by id, each with its owning user namespace
/// (Linux mnt_ns_tree, which finds a namespace from a mount's mnt_ns id
/// here, and ns_tree's list NS_MNT_GET_NEXT/PREV walk): a namespace is
/// added once made, removed at its end. A spin leaf (Linux
/// mnt_ns_tree_lock), taken under NAMESPACE_SEM by graft; nothing is
/// upgraded or dropped but a `Weak` under it.
static MNT_NS_TREE: crate::sync::spin::Mutex<RbTree<u64, MntNsEntry>> =
    crate::sync::spin::Mutex::new(RbTree::new());

/// Add `ns` to the namespace tree (Linux mnt_ns_tree_add)
fn mnt_ns_tree_add(ns: &Arc<MntNamespace>, node: RbTreeNodeReservation<u64, MntNsEntry>) {
    let e = (Arc::downgrade(&ns.user_ns), Arc::downgrade(ns));
    let node = node.into_node(ns.id(), e);
    let old = MNT_NS_TREE.lock().insert(node);
    debug_assert!(old.is_none(), "ns: a mount namespace id reused");
}

/// The mount namespaces numbered `a` and `b` are owned by the same user
/// namespace (Linux a->user_ns == b->user_ns, each found from a mount's
/// mnt_ns); false if either is gone
pub fn mnt_ns_same_owner(a: u64, b: u64) -> bool {
    let t = MNT_NS_TREE.lock();
    match (t.get(&a), t.get(&b)) {
        (Some(x), Some(y)) => Weak::ptr_eq(&x.0, &y.0),
        _ => false,
    }
}

/// The live mount namespace after (or with `previous` before) the one
/// numbered `id` in id order whose owner the caller has CAP_SYS_ADMIN
/// over (Linux get_sequential_mnt_ns, ns_tree_adjoined_rcu): ENOENT
/// past the end. Each candidate is taken out of the tree's lock as a
/// `Weak` and upgraded after it, so a dying one is skipped and no last
/// reference goes under the lock.
pub fn mnt_ns_adjoined(id: u64, previous: bool) -> Result<Arc<MntNamespace>, KernelError> {
    let mut at = id;
    loop {
        let next = {
            let t = MNT_NS_TREE.lock();
            let e = if previous {
                t.before(&at)
            } else {
                t.range_from(&at.saturating_add(1)).next()
            };
            e.map(|(k, v)| (*k, v.1.clone()))
        };
        let (k, w) = next.ok_or(KernelError::NotFound)?;
        at = k;
        // Linux also requires ns_capable_noaudit(mntns->user_ns,
        // CAP_SYS_ADMIN) per candidate; hk's capabilities ignore user
        // namespaces (BUGS.md), so that is the caller's
        // may_see_all_namespaces check, already made
        if let Some(m) = w.upgrade() {
            return Ok(m);
        }
    }
}

/// Mount namespace - per-namespace mount tree
///
/// Each mount namespace has its own view of the filesystem hierarchy.
/// When CLONE_NEWNS is used, the entire mount tree is cloned.
pub struct MntNamespace {
    /// Root mount of this namespace
    pub root: RwLock<Option<MountRef>>,
    /// Its inode number and nsfs dentry (Linux ns)
    pub ns: NsCommon,
    /// The user namespace that owns it (Linux mnt_namespace.user_ns),
    /// set at creation
    pub user_ns: Arc<UserNamespace>,
}

impl MntNamespace {
    /// A new empty mount namespace owned by `user_ns`, not yet in the
    /// namespace tree, or ENOMEM (Linux alloc_mnt_ns)
    fn alloc(user_ns: Arc<UserNamespace>) -> Result<Arc<Self>, KernelError> {
        try_arc(Self::with(inum::Inum::alloc()?, user_ns))
    }

    /// Create initial mount namespace (boot: failure cannot be reported)
    fn new_init() -> Arc<Self> {
        let ns = arc_nofail(Self::with(
            inum::Inum::fixed(inum::MNT_INIT),
            INIT_USER_NS.clone(),
        ));
        mnt_ns_tree_add(&ns, RbTreeNodeReservation::new_nofail());
        ns
    }

    /// Its id, never reused, what `Mount::mnt_ns` names (Linux
    /// mnt_ns->ns.ns_id)
    pub fn id(&self) -> u64 {
        self.ns.ns_id
    }

    /// The mounts in it (Linux mnt_ns->nr_mounts), by a walk of its
    /// tree under NAMESPACE_SEM read
    pub fn nr_mounts(&self) -> usize {
        let Some(root) = self.get_root() else {
            return 0;
        };
        let g = crate::fs::mount::namespace_read();
        crate::fs::mount::walk(&root, &*g).count()
    }

    /// An empty namespace numbered `inum`, owned by `user_ns`
    fn with(inum: inum::Inum, user_ns: Arc<UserNamespace>) -> Self {
        Self {
            root: RwLock::new(None),
            ns: NsCommon::new(inum),
            user_ns,
        }
    }

    /// Clone this namespace for CLONE_NEWNS, owned by `user_ns` (Linux
    /// copy_mnt_ns)
    ///
    /// Deep-copies the entire mount tree so the new namespace has
    /// an independent view of the filesystem hierarchy: peers of the
    /// originals, or their slaves for another user namespace (CL_SLAVE).
    /// `fs` (the new task's, or the unsharer's own) moves its root and
    /// pwd to the copies of their mounts
    pub fn clone_ns(
        &self,
        fs: Option<&crate::fs::FsStruct>,
        user_ns: &Arc<UserNamespace>,
    ) -> KernelResult<Arc<Self>> {
        // Its tree node first: once the copy is built, listing it
        // cannot fail
        let node = RbTreeNodeReservation::new()?;
        let new_ns = Self::alloc(user_ns.clone())?;
        let slave = !Arc::ptr_eq(user_ns, &self.user_ns);
        let old_root = self.get_root();
        if let Some(old_root) = old_root {
            let (new_root, map) = Mount::clone_tree(&old_root, new_ns.id(), slave)?;
            *new_ns.root.write() = Some(new_root);
            if let Some(fs) = fs {
                fs.repoint(&map);
            }
        }
        // Listed only now, whole (Linux copy_mnt_ns: ns_tree_add_raw at
        // the end), so NS_MNT_GET_NEXT/PREV never find a namespace
        // half built or whose copy failed
        mnt_ns_tree_add(&new_ns, node);
        Ok(new_ns)
    }

    /// Set the root mount, once (Linux: a namespace's root never
    /// changes): the tree's reference to it; EBUSY if one is set
    pub fn set_root(&self, mount: MountRef) -> KernelResult<()> {
        let mut root = self.root.write();
        if root.is_some() {
            // A live root is never replaced (Linux: set once): its
            // tree's references would leave by the fast path, uncounted
            return Err(crate::util::error::KernelError::Busy);
        }
        *root = Some(mount);
        Ok(())
    }

    /// Get the root mount
    pub fn get_root(&self) -> Option<MountRef> {
        self.root.read().clone()
    }

    /// Get the root dentry
    pub fn get_root_dentry(&self) -> Option<crate::fs::dentry::DentryRef> {
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

    /// PID namespace its children go to (Linux pid_ns_for_children;
    /// the task's own is `Task::pid_ns`)
    pub pid_ns: Arc<PidNamespace>,

    /// User namespace (UID/GID mapping)
    pub user_ns: Arc<UserNamespace>,

    /// IPC namespace (SysV IPC isolation)
    pub ipc_ns: Arc<IpcNamespace>,

    /// Network namespace (network stack isolation)
    pub net_ns: NetRef,

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

    /// A copy sharing every namespace (Linux create_new_namespaces with
    /// no flags)
    pub fn dup(&self) -> Self {
        Self {
            uts_ns: self.uts_ns.clone(),
            mnt_ns: self.mnt_ns.clone(),
            pid_ns: self.pid_ns.clone(),
            user_ns: self.user_ns.clone(),
            ipc_ns: self.ipc_ns.clone(),
            net_ns: self.net_ns.clone(),
            cgroup_ns: self.cgroup_ns.clone(),
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
    pub fn copy(&self, flags: u64, fs: Option<&crate::fs::FsStruct>) -> KernelResult<Arc<Self>> {
        // First: every new namespace is owned by it (Linux
        // create_new_namespaces' user_ns, the new creds')
        let user_ns = if flags & CLONE_NEWUSER != 0 {
            UserNamespace::clone_ns(&self.user_ns)?
        } else {
            self.user_ns.clone()
        };

        let uts_ns = if flags & CLONE_NEWUTS != 0 {
            self.uts_ns.clone_ns(&user_ns)?
        } else {
            self.uts_ns.clone()
        };

        let mnt_ns = if flags & CLONE_NEWNS != 0 {
            self.mnt_ns.clone_ns(fs, &user_ns)?
        } else {
            self.mnt_ns.clone()
        };

        let pid_ns = if flags & CLONE_NEWPID != 0 {
            PidNamespace::clone_ns(&self.pid_ns, &user_ns)?
        } else {
            self.pid_ns.clone()
        };

        let ipc_ns = if flags & CLONE_NEWIPC != 0 {
            self.ipc_ns.clone_ns(&user_ns)?
        } else {
            self.ipc_ns.clone()
        };

        let net_ns = if flags & CLONE_NEWNET != 0 {
            self.net_ns.clone_ns(&user_ns)?
        } else {
            self.net_ns.clone()
        };

        let cgroup_ns = if flags & CLONE_NEWCGROUP != 0 {
            // Rooted at the caller's cgroup (Linux copy_cgroup_ns:
            // current's css_set, the parent's for a clone)
            let cg = crate::task::percpu::current().cgroup.lock().clone();
            self.cgroup_ns
                .clone_ns(cg.unwrap_or_else(|| self.cgroup_ns.root()), &user_ns)?
        } else {
            self.cgroup_ns.clone()
        };

        try_arc(Self {
            uts_ns,
            mnt_ns,
            pid_ns,
            user_ns,
            ipc_ns,
            net_ns,
            cgroup_ns,
        })
    }
}

/// Initial (root) namespace proxy
///
/// All tasks inherit from this unless they create new namespaces.
pub static INIT_NSPROXY: Lazy<Arc<NsProxy>> = Lazy::new(|| arc_nofail(NsProxy::new_init()));

// ============================================================================
// Task-NsProxy Mapping (following FsStruct pattern)
// ============================================================================

// =============================================================================
// Task NS accessors - Task.nsproxy under its alloc_lock (Linux task_lock)
// =============================================================================

use crate::task::Task;
use crate::task::percpu::current;

/// Initialize the nsproxy of task `t`
///
/// Called when creating a new task to set up its namespace context, or
/// by the task itself (unshare, setns; Linux switch_task_namespaces).
pub fn init_task_ns(t: &Task, nsproxy: Arc<NsProxy>) {
    let old = t.task_lock().set_nsproxy(Some(nsproxy));
    drop(old);
}

/// The NsProxy of task `t`
///
/// Returns a cloned Arc (increments refcount), under its alloc_lock;
/// the current task's is `current().nsproxy()`, lock-free (Linux
/// current->nsproxy).
pub fn get_task_ns(t: &Task) -> Option<Arc<NsProxy>> {
    t.task_lock().nsproxy().cloned()
}

/// Remove nsproxy when task exits
///
/// This decrements the Arc refcount. If this was the last reference
/// (no other tasks sharing this NsProxy), the NsProxy is dropped,
/// which in turn drops the namespace references (after the task's
/// alloc_lock is released: a network namespace's teardown takes RTNL).
pub fn exit_task_ns(t: &Task) {
    let ns = t.task_lock().set_nsproxy(None);
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

/// The namespaces a child of the caller gets (Linux copy_namespaces,
/// reading current->nsproxy lock-free): new ones for the CLONE_NEW*
/// flags, else the caller's. `child_fs` is
/// the child's fs context, moved to the copies of its root's and cwd's
/// mounts in a new mount namespace. Built before the child is visible,
/// so a failure leaves nothing behind.
pub fn fork_nsproxy(
    flags: u64,
    child_fs: Option<&crate::fs::FsStruct>,
) -> KernelResult<Arc<NsProxy>> {
    let ns_flags = flags & CLONE_NS_FLAGS;
    // CLONE_NEWNS with a shared fs struct is EINVAL, before any
    // permission check (Linux copy_process); the child's own copy
    // follows its new mounts
    if ns_flags & CLONE_NEWNS != 0 && flags & crate::task::clone_flags::CLONE_FS != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if !may_create_namespaces(ns_flags) {
        return Err(KernelError::NotPermitted);
    }
    let parent_ns = current().nsproxy().unwrap_or_else(|| INIT_NSPROXY.clone());
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
    current()
        .nsproxy()
        .map(|ns| ns.uts_ns.clone())
        .unwrap_or_else(|| INIT_UTS_NS.clone())
}

/// Get current task's mount namespace
///
/// Returns the mount namespace for the calling task, or the init
/// namespace if no namespace context is set.
pub fn current_mnt_ns() -> Arc<MntNamespace> {
    current()
        .nsproxy()
        .map(|ns| ns.mnt_ns.clone())
        .unwrap_or_else(|| INIT_MNT_NS.clone())
}

/// Get current task's user namespace
///
/// Returns the user namespace for the calling task, or the init
/// namespace if no namespace context is set.
pub fn current_user_ns() -> Arc<UserNamespace> {
    current()
        .nsproxy()
        .map(|ns| ns.user_ns.clone())
        .unwrap_or_else(|| INIT_USER_NS.clone())
}

/// Get current task's network namespace
///
/// Returns the network namespace for the calling task, or the init
/// namespace if no namespace context is set.
pub fn current_net_ns() -> NetRef {
    current()
        .nsproxy()
        .map(|ns| ns.net_ns.clone())
        .unwrap_or_else(|| INIT_NET_NS.clone())
}

// ============================================================================
// Unshare Syscall
// ============================================================================

/// Currently supported namespace flags for unshare
///
/// We support UTS, mount, PID, user, IPC, and network namespaces.
const SUPPORTED_NS_FLAGS: u64 = CLONE_NEWUTS
    | CLONE_NEWNS
    | CLONE_NEWPID
    | CLONE_NEWUSER
    | CLONE_NEWIPC
    | CLONE_NEWNET
    | CLONE_NEWCGROUP;

/// CLONE_SYSVSEM flag - used by unshare to detach from shared semundo
const CLONE_SYSVSEM: u64 = 0x00040000;

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
pub fn sys_unshare(unshare_flags: u64) -> KernelResult<()> {
    let ns_flags = unshare_flags & CLONE_NS_FLAGS;
    let sysvsem_flag = unshare_flags & CLONE_SYSVSEM;

    // Handle CLONE_SYSVSEM - detach from shared semaphore undo list
    // Similar to what Linux does: exit_sem(current) effectively
    if sysvsem_flag != 0 {
        // Detach from any shared undo list by exiting and re-creating
        // This applies any pending undos if we're the last holder
        crate::ipc::sem::exit_sem(&crate::task::percpu::current());
    }

    // No namespace flags - nothing more to do
    if ns_flags == 0 {
        return Ok(());
    }

    // Check for unsupported namespace flags
    if ns_flags & !SUPPORTED_NS_FLAGS != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if !may_create_namespaces(ns_flags) {
        return Err(KernelError::NotPermitted);
    }

    // Get current namespace proxy
    let current_ns = current().nsproxy().unwrap_or_else(|| INIT_NSPROXY.clone());

    // Create new nsproxy with new namespace(s)
    // CLONE_NEWNS implies CLONE_FS (Linux unshare): a private fs
    // struct, moved to the copies of its mounts
    let fs = if ns_flags & CLONE_NEWNS != 0 {
        let fs = crate::task::percpu::current_fs()
            .map(|f| f.copy())
            .transpose()?;
        if let Some(f) = &fs {
            crate::fs::init_task_fs(&current(), f.clone());
        }
        fs
    } else {
        None
    };
    let new_ns = current_ns.copy(ns_flags, fs.as_deref())?;

    // Switch to new namespace (atomic via mutex)
    switch_task_namespaces(&current(), new_ns);
    Ok(())
}

/// Switch task `t`'s namespaces to a new nsproxy
///
/// This atomically replaces the task's nsproxy. Used by both
/// unshare() and setns().
pub fn switch_task_namespaces(t: &Task, new_ns: Arc<NsProxy>) {
    init_task_ns(t, new_ns);
}
