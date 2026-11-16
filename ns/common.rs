//! What every namespace has (Linux include/linux/ns_common.h,
//! proc_ns_operations): its inode number, the nsfs dentry made for it,
//! and [`NsRef`], a counted reference to a namespace of any type with
//! its type's operations
//!
//! Locking: `stashed` is an atomic pointer, set by a compare-exchange
//! and cleared the same way by the dentry's kill (`fs::nsfs`); a reader
//! takes a reference under an RCU read guard (Linux ns->stashed with
//! lockref_get_not_dead). `linked` is changed under the namespace
//! tree's lock (`ns::tree`).

use alloc::sync::Arc;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

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
        Self {
            ns_id,
            inum,
            stashed: AtomicPtr::new(null_mut()),
            linked: AtomicBool::new(false),
        }
    }

    /// Its inode number
    pub fn inum(&self) -> u32 {
        self.inum.get()
    }
}

impl Drop for NsCommon {
    /// Linux ns_tree_remove in each type's free path: the namespace
    /// leaves the tree as its memory goes, if it has not already (a
    /// network namespace leaves at its teardown, a mount namespace
    /// before its unmount); any context
    fn drop(&mut self) {
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
