//! What every namespace has (Linux include/linux/ns_common.h,
//! proc_ns_operations): its inode number, the nsfs dentry made for it,
//! and [`NsRef`], a counted reference to a namespace of any type with
//! its type's operations
//!
//! Active references (Linux __ns_ref_active, kernel/nscommon.c): a
//! namespace is in active use while something holds one, as opposed to
//! merely being kept in memory by a counted reference. An nsproxy holds
//! one on each of its namespaces once installed on a task, a task in
//! the task list one on its user namespace, a `Pid` one on the
//! namespace it was made in, and an nsfs inode one on its namespace
//! ([`Namespace::active_get`] callers). The namespace tree hands out
//! only active namespaces (listns(2), Linux ns_get_unless_inactive).
//! A namespace's first active reference takes one on its owning user
//! namespace and its last puts that one, up the chain of owners; the
//! initial namespaces are always active and never counted.
//!
//! Locking: `stashed` is an atomic pointer, set by a compare-exchange
//! and cleared the same way by the dentry's kill (`fs::nsfs`); a reader
//! takes a reference under an RCU read guard (Linux ns->stashed with
//! lockref_get_not_dead). `linked` is changed under the namespace
//! tree's lock (`ns::tree`). `active` is an atomic count, as Linux's
//! atomic_t, changed lock-free in any context (no lock to take: its
//! holders come and go under unrelated locks, TASKLIST included).

use alloc::sync::Arc;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use super::inum::Inum;
use super::{
    CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER,
    CLONE_NEWUTS, CgroupNamespace, MntNamespace, NetRef, PidNamespace, UserNamespace, UtsNamespace,
};
use crate::fs::dentry::Dentry;
use crate::ipc::IpcNamespace;

/// The last namespace id handed out (Linux namespace_cookie), one
/// sequence for every type, past the initial namespaces' fixed ids
static NS_ID: AtomicU64 = AtomicU64::new(super::inum::NS_LAST_INIT_ID + 1);

/// A namespace's common part (Linux struct ns_common)
pub struct NsCommon {
    /// Its id, never reused, in creation order across all types (Linux
    /// ns_id, __ns_tree_gen_id): an initial namespace's is fixed (Linux
    /// init_ns_id); NS_GET_ID and NS_GET_MNTNS_ID give it, and a mount
    /// names its mount namespace by it
    pub ns_id: u64,
    /// Its inode number (Linux ns.inum): /proc/<pid>/ns/<type> reads
    /// "<type>:[<inum>]", the st_ino of its nsfs file
    pub inum: Inum,
    /// Its nsfs dentry while one lives, no reference (Linux
    /// ns->stashed): every open of a /proc/<pid>/ns link while it does
    /// gets that dentry, cleared by its kill (`fs::nsfs`)
    pub(crate) stashed: AtomicPtr<Dentry>,
    /// It is in the namespace tree (Linux !RB_EMPTY_NODE of
    /// ns_tree_node, ns_tree_active): set by `tree::add`, cleared by
    /// `tree::remove`, both under its lock; an atomic only because it
    /// lives here, outside the lock's data, as Linux's node does
    pub(super) linked: AtomicBool,
    /// Its active references (Linux __ns_ref_active): 1 for an initial
    /// namespace, never changed; a new one starts at 0 (Linux
    /// __ns_common_init) until it is installed in an nsproxy, a task's
    /// credentials, a pid or a namespace file
    active: AtomicU32,
}

impl NsCommon {
    /// A new namespace's, numbered `inum`, with a fresh id (Linux
    /// ns_tree_gen_id)
    pub fn new(inum: Inum) -> Self {
        Self::with_id(inum, NS_ID.fetch_add(1, Ordering::Relaxed) + 1)
    }

    /// An initial namespace's (only its constructor calls this): its
    /// fixed inode number `inum` and the type's fixed id (Linux decides
    /// by identity, __ns == ns_init_ns(__ns))
    pub fn init(inum: Inum) -> Self {
        let id = super::inum::init_id(inum.get()).expect("ns: not an initial inode number");
        Self::with_id(inum, id)
    }

    fn with_id(inum: Inum, ns_id: u64) -> Self {
        let init = ns_id <= super::inum::NS_LAST_INIT_ID;
        Self {
            ns_id,
            inum,
            stashed: AtomicPtr::new(null_mut()),
            linked: AtomicBool::new(false),
            active: AtomicU32::new(u32::from(init)),
        }
    }

    /// Its inode number
    pub fn inum(&self) -> u32 {
        self.inum.get()
    }

    /// An initial namespace (Linux is_ns_init_id): always active
    fn is_init(&self) -> bool {
        self.ns_id <= super::inum::NS_LAST_INIT_ID
    }

    /// Something holds an active reference to it (Linux
    /// __ns_ref_active_read != 0); racy, as Linux's: a namespace may
    /// become inactive, or active again, right after
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire) != 0
    }

    /// One more active reference; true if it was the first (Linux
    /// atomic_fetch_add == 0)
    fn active_inc(&self) -> bool {
        let prev = self.active.fetch_add(1, Ordering::AcqRel);
        debug_assert!(prev != u32::MAX, "ns: active count overflow");
        prev == 0
    }

    /// One active reference fewer; true if it was the last (Linux
    /// atomic_dec_and_test)
    fn active_dec(&self) -> bool {
        let prev = self.active.fetch_sub(1, Ordering::AcqRel);
        // Linux VFS_WARN_ON_ONCE(__ns_ref_active_read(ns) < 0)
        debug_assert!(prev != 0, "ns: active count underflow, id {}", self.ns_id);
        prev == 1
    }
}

/// A namespace of any type, for its active references (Linux struct
/// ns_common with ops->owner)
pub trait Namespace {
    /// Its common part
    fn ns_common(&self) -> &NsCommon;

    /// The user namespace that owns it (Linux ns_owner's ops->owner): a
    /// user namespace's parent, None for the initial user namespace
    fn ns_owner(&self) -> Option<&UserNamespace>;

    /// Take an active reference (Linux __ns_ref_active_get): a first one
    /// takes one on its owner, and so on up the owners until one was
    /// already active. Any context: atomics only.
    fn active_get(&self) {
        let c = self.ns_common();
        if c.is_init() || !c.active_inc() {
            return;
        }
        let mut owner = self.ns_owner();
        // Linux ns_owner skips the initial user namespace: always active
        while let Some(u) = owner.filter(|u| !u.ns.is_init()) {
            if !u.ns.active_inc() {
                return;
            }
            owner = u.parent.as_deref();
        }
    }

    /// Put an active reference (Linux __ns_ref_active_put): the last one
    /// puts its owner's, and so on up while each was the last. The
    /// holder keeps a counted reference, which keeps the owners in
    /// memory. Any context.
    fn active_put(&self) {
        let c = self.ns_common();
        if c.is_init() || !c.active_dec() {
            return;
        }
        let mut owner = self.ns_owner();
        while let Some(u) = owner.filter(|u| !u.ns.is_init()) {
            if !u.ns.active_dec() {
                return;
            }
            owner = u.parent.as_deref();
        }
    }
}

/// Namespace types with an owning user namespace in `user_ns`
macro_rules! owned_namespace {
    ($($t:ty),*) => {$(
        impl Namespace for $t {
            fn ns_common(&self) -> &NsCommon {
                &self.ns
            }
            fn ns_owner(&self) -> Option<&UserNamespace> {
                Some(&self.user_ns)
            }
        }
    )*};
}

owned_namespace!(
    MntNamespace,
    UtsNamespace,
    IpcNamespace,
    super::NetNamespace,
    PidNamespace,
    CgroupNamespace
);

impl Namespace for UserNamespace {
    fn ns_common(&self) -> &NsCommon {
        &self.ns
    }
    fn ns_owner(&self) -> Option<&UserNamespace> {
        self.parent.as_deref()
    }
}

impl Namespace for NsRef {
    fn ns_common(&self) -> &NsCommon {
        self.common()
    }
    fn ns_owner(&self) -> Option<&UserNamespace> {
        match self {
            Self::Mnt(n) => n.ns_owner(),
            Self::Uts(n) => n.ns_owner(),
            Self::Ipc(n) => n.ns_owner(),
            Self::Net(n) => (**n).ns_owner(),
            Self::Pid(n) => n.ns_owner(),
            Self::User(n) => n.ns_owner(),
            Self::Cgroup(n) => n.ns_owner(),
        }
    }
}

impl Drop for NsCommon {
    /// Linux ns_tree_remove in each type's free path: the namespace
    /// leaves the tree as its memory goes, if it has not already (a
    /// network namespace leaves at its teardown, a mount namespace
    /// before its unmount); any context
    fn drop(&mut self) {
        // Nothing holds it actively once it is unreferenced (Linux
        // __ns_ref_put: VFS_WARN_ON_ONCE(__ns_ref_active_read(ns)))
        debug_assert!(
            self.is_init() || *self.active.get_mut() == 0,
            "ns: id {} freed while active",
            self.ns_id
        );
        if *self.linked.get_mut() {
            super::tree::remove(self);
        }
    }
}

/// A counted reference to one namespace (Linux struct ns_common * with
/// its proc_ns_operations): what an nsfs inode holds (Linux i_private,
/// put at evict), so an open namespace file or a bind mount of one
/// keeps the namespace alive
#[derive(Clone)]
pub enum NsRef {
    Mnt(Arc<MntNamespace>),
    Uts(Arc<UtsNamespace>),
    Ipc(Arc<IpcNamespace>),
    Net(NetRef),
    Pid(Arc<PidNamespace>),
    User(Arc<UserNamespace>),
    Cgroup(Arc<CgroupNamespace>),
}

impl NsRef {
    /// Its common part
    pub fn common(&self) -> &NsCommon {
        match self {
            Self::Mnt(n) => &n.ns,
            Self::Uts(n) => &n.ns,
            Self::Ipc(n) => &n.ns,
            Self::Net(n) => &n.ns,
            Self::Pid(n) => &n.ns,
            Self::User(n) => &n.ns,
            Self::Cgroup(n) => &n.ns,
        }
    }

    /// Its inode number
    pub fn inum(&self) -> u32 {
        self.common().inum()
    }

    /// Its type, as a CLONE_NEW* flag (Linux ops->type)
    pub fn ns_type(&self) -> u64 {
        match self {
            Self::Mnt(_) => CLONE_NEWNS,
            Self::Uts(_) => CLONE_NEWUTS,
            Self::Ipc(_) => CLONE_NEWIPC,
            Self::Net(_) => CLONE_NEWNET,
            Self::Pid(_) => CLONE_NEWPID,
            Self::User(_) => CLONE_NEWUSER,
            Self::Cgroup(_) => CLONE_NEWCGROUP,
        }
    }

    /// Its type's name (Linux ops->name): the nsfs dentry's
    /// "<name>:[<inum>]"
    pub fn name(&self) -> &'static str {
        match self {
            Self::Mnt(_) => "mnt",
            Self::Uts(_) => "uts",
            Self::Ipc(_) => "ipc",
            Self::Net(_) => "net",
            Self::Pid(_) => "pid",
            Self::User(_) => "user",
            Self::Cgroup(_) => "cgroup",
        }
    }

    /// The user namespace that owns it (Linux ops->owner): a user
    /// namespace's parent, None for the initial one
    pub fn owner(&self) -> Option<Arc<UserNamespace>> {
        Some(match self {
            Self::Mnt(n) => n.user_ns.clone(),
            Self::Uts(n) => n.user_ns.clone(),
            Self::Ipc(n) => n.user_ns.clone(),
            Self::Net(n) => n.user_ns.clone(),
            Self::Pid(n) => n.user_ns.clone(),
            Self::User(n) => return n.parent.clone(),
            Self::Cgroup(n) => n.user_ns.clone(),
        })
    }

    /// A reference that does not keep it alive, for the namespace tree
    /// (a network namespace's passive one)
    pub(super) fn downgrade(&self) -> super::tree::NsWeak {
        use super::tree::NsWeak;
        match self {
            Self::Mnt(n) => NsWeak::Mnt(Arc::downgrade(n)),
            Self::Uts(n) => NsWeak::Uts(Arc::downgrade(n)),
            Self::Ipc(n) => NsWeak::Ipc(Arc::downgrade(n)),
            Self::Net(n) => NsWeak::Net(Arc::downgrade(n.passive())),
            Self::Pid(n) => NsWeak::Pid(Arc::downgrade(n)),
            Self::User(n) => NsWeak::User(Arc::downgrade(n)),
            Self::Cgroup(n) => NsWeak::Cgroup(Arc::downgrade(n)),
        }
    }

    /// The same namespace
    pub fn ptr_eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.common(), other.common())
    }
}
