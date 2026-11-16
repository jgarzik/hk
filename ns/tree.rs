//! The namespace tree (Linux kernel/nstree.c): every namespace of every
//! type, the initial ones included, by `ns_id`, in three orders: all
//! types together (Linux ns_unified_root), one type (Linux
//! mnt_ns_tree, net_ns_tree, ...) and those one user namespace owns
//! (Linux ns_owner_root). A namespace is added once made, whole
//! ([`add`], Linux ns_tree_add at the end of each type's creation), and
//! removed at its end ([`remove`], Linux ns_tree_remove in its free
//! path; [`NsCommon`]'s drop does it for every type).
//!
//! Lookups and walks hand back counted references ([`NsRef`]): an entry
//! holds a `Weak`, upgraded under the lock only if the namespace still
//! has a reference, so a namespace being freed is never returned.
//! [`Strong::get`] is where the walk asks whether a namespace may be
//! handed out: only one in active use (Linux ns_get_unless_inactive,
//! `ns::common`'s active references). A caller may hold the
//! last reference to what it gets, so it drops it only where that
//! namespace's last put may run (a mount namespace's sleeps).
//!
//! Locking: `NS_TREE` (Linux ns_tree_lock, a seqlock) is an IrqSpinlock
//! leaf: removal runs wherever a namespace's last reference goes, any
//! context. Its nodes are allocated before it is taken ([`Nodes`],
//! Linux's rb nodes embedded in ns_common), so insertion cannot fail;
//! removed nodes are freed after it is released. Under it nothing is
//! allocated or freed and no strong reference is dropped: a candidate
//! is upgraded under it and checked or dropped after it. Linux readers
//! walk the trees under RCU and retry on the seqcount; hk's readers
//! take the lock, each step one descent of the tree.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering::Relaxed;

use super::{
    CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER,
    CLONE_NEWUTS, CgroupNamespace, MntNamespace, NetNamespace, NsCommon, NsRef, PidNamespace,
    UserNamespace, UtsNamespace,
};
use crate::ipc::IpcNamespace;
use crate::sync::IrqSpinlock;
use crate::util::error::KernelError;
use crate::util::rbtree::{RbTree, RbTreeNodeReservation};

/// A reference to a namespace that does not keep it alive (a network
/// namespace's is passive: Linux net->passive)
#[derive(Clone)]
pub enum NsWeak {
    Mnt(Weak<MntNamespace>),
    Uts(Weak<UtsNamespace>),
    Ipc(Weak<IpcNamespace>),
    Net(Weak<NetNamespace>),
    Pid(Weak<PidNamespace>),
    User(Weak<UserNamespace>),
    Cgroup(Weak<CgroupNamespace>),
}

impl NsWeak {
    /// A strong reference, if the namespace still has one (Linux
    /// __ns_ref_get: refcount_inc_not_zero); only an atomic, so it may
    /// run under `NS_TREE`
    fn upgrade(&self) -> Option<Strong> {
        Some(match self {
            Self::Mnt(w) => Strong::Ref(NsRef::Mnt(w.upgrade()?)),
            Self::Uts(w) => Strong::Ref(NsRef::Uts(w.upgrade()?)),
            Self::Ipc(w) => Strong::Ref(NsRef::Ipc(w.upgrade()?)),
            Self::Net(w) => Strong::Net(w.upgrade()?),
            Self::Pid(w) => Strong::Ref(NsRef::Pid(w.upgrade()?)),
            Self::User(w) => Strong::Ref(NsRef::User(w.upgrade()?)),
            Self::Cgroup(w) => Strong::Ref(NsRef::Cgroup(w.upgrade()?)),
        })
    }

    /// Its type, as a CLONE_NEW* flag (Linux ns_type)
    fn ns_type(&self) -> u64 {
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
}

/// A namespace upgraded under `NS_TREE`, not yet checked: dropped, if
/// refused, only after the lock is released (a last reference's drop
/// removes its namespace, taking the lock)
enum Strong {
    Ref(NsRef),
    /// A passive reference to a network namespace, which also needs an
    /// active one
    Net(Arc<NetNamespace>),
}

impl Strong {
    /// The namespace, if it may be handed out (Linux
    /// ns_get_unless_inactive): one something holds actively
    /// (`NsCommon::is_active`, Linux __ns_ref_active), and for a network
    /// namespace a counted reference left too (Linux __ns_ref_get, here
    /// maybe_get_net)
    fn get(self) -> Option<NsRef> {
        match self {
            Self::Ref(r) => r.common().is_active().then_some(r),
            Self::Net(n) if n.ns.is_active() => n.maybe_get().map(NsRef::Net),
            Self::Net(_) => None,
        }
    }

    /// The namespace, active or not, if it still has a counted
    /// reference (Linux ns_ref_get: a network namespace's maybe_get_net)
    fn get_any(self) -> Option<NsRef> {
        match self {
            Self::Ref(r) => Some(r),
            Self::Net(n) => n.maybe_get().map(NsRef::Net),
        }
    }
}

/// A namespace's entry: itself and its owner's id (None for the
/// initial user namespace), which finds its owner-tree node at removal
#[derive(Clone)]
struct Entry {
    ns: NsWeak,
    owner: Option<u64>,
}

/// The types with a tree, in `Trees::types` order
const TYPES: [u64; 7] = [
    CLONE_NEWNS,
    CLONE_NEWUTS,
    CLONE_NEWIPC,
    CLONE_NEWNET,
    CLONE_NEWPID,
    CLONE_NEWUSER,
    CLONE_NEWCGROUP,
];

/// The index of type `ty`'s tree (Linux ns_tree_from_type), None for no
/// single known type
fn type_idx(ty: u64) -> Option<usize> {
    TYPES.iter().position(|&t| t == ty)
}

/// The trees (Linux ns_unified_root, the per-type roots and every user
/// namespace's ns_owner_root: one tree keyed by (owner id, id), so all
/// live under the one lock as Linux's do)
struct Trees {
    unified: RbTree<u64, Entry>,
    types: [RbTree<u64, Entry>; TYPES.len()],
    owned: RbTree<(u64, u64), Entry>,
}

/// Every namespace (Linux ns_tree_lock and the trees it guards): a
/// global, as Linux's, since a lookup by id must see every CPU's
static NS_TREE: IrqSpinlock<Trees> = IrqSpinlock::new(Trees {
    unified: RbTree::new(),
    types: [const { RbTree::new() }; TYPES.len()],
    owned: RbTree::new(),
});

/// Which namespaces a lookup or walk covers
#[derive(Clone, Copy, Debug)]
pub enum Tree {
    /// Every type (Linux ns_unified_root)
    All,
    /// One type, a CLONE_NEW* flag (Linux ns_tree_from_type); an
    /// unknown one has none
    Type(u64),
    /// Those owned by the user namespace with this id (Linux
    /// ns_owner_root)
    Owner(u64),
}

impl Tree {
    /// Those `user_ns` owns
    pub fn owned_by(user_ns: &UserNamespace) -> Self {
        Self::Owner(user_ns.ns.ns_id)
    }

    /// One type, or every type for 0 (Linux ns_tree_lookup_rcu's
    /// ns_type)
    pub fn of_type(ty: u64) -> Self {
        if ty == 0 { Self::All } else { Self::Type(ty) }
    }
}

impl Trees {
    /// The tree of `ty`
    fn of(&self, ty: u64) -> Option<&RbTree<u64, Entry>> {
        type_idx(ty).map(|i| &self.types[i])
    }

    /// The entry numbered `id` in `tree`
    fn get(&self, tree: Tree, id: u64) -> Option<&Entry> {
        match tree {
            Tree::All => self.unified.get(&id),
            Tree::Type(ty) => self.of(ty)?.get(&id),
            Tree::Owner(o) => self.owned.get(&(o, id)),
        }
    }

    /// The entry with the smallest id >= `id` in `tree`
    fn at(&self, tree: Tree, id: u64) -> Option<(u64, &Entry)> {
        match tree {
            Tree::All => self.unified.range_from(&id).next().map(|(k, e)| (*k, e)),
            Tree::Type(ty) => self.of(ty)?.range_from(&id).next().map(|(k, e)| (*k, e)),
            Tree::Owner(o) => match self.owned.range_from(&(o, id)).next() {
                Some((&(ko, k), e)) if ko == o => Some((k, e)),
                _ => None,
            },
        }
    }

    /// The entry with the greatest id < `id` in `tree`
    fn before(&self, tree: Tree, id: u64) -> Option<(u64, &Entry)> {
        match tree {
            Tree::All => self.unified.before(&id).map(|(k, e)| (*k, e)),
            Tree::Type(ty) => self.of(ty)?.before(&id).map(|(k, e)| (*k, e)),
            Tree::Owner(o) => match self.owned.before(&(o, id)) {
                Some((&(ko, k), e)) if ko == o => Some((k, e)),
                _ => None,
            },
        }
    }
}

/// A namespace's three tree nodes, allocated before it is made so that
/// listing it cannot fail (Linux embeds them in ns_common)
pub struct Nodes {
    unified: RbTreeNodeReservation<u64, Entry>,
    ty: RbTreeNodeReservation<u64, Entry>,
    owned: RbTreeNodeReservation<(u64, u64), Entry>,
}

impl Nodes {
    /// ENOMEM if they cannot be had: the namespace's creation fails
    pub fn new() -> Result<Self, KernelError> {
        Ok(Self {
            unified: RbTreeNodeReservation::new()?,
            ty: RbTreeNodeReservation::new()?,
            owned: RbTreeNodeReservation::new()?,
        })
    }

    /// An initial namespace's (boot: failure cannot be reported)
    #[track_caller]
    pub fn nofail() -> Self {
        Self {
            unified: RbTreeNodeReservation::new_nofail(),
            ty: RbTreeNodeReservation::new_nofail(),
            owned: RbTreeNodeReservation::new_nofail(),
        }
    }
}

/// List `ns`, made whole, in its trees with `nodes` (Linux
/// __ns_tree_add_raw); allocates nothing
pub fn add(ns: &NsRef, nodes: Nodes) {
    let id = ns.common().ns_id;
    let idx = type_idx(ns.ns_type()).expect("ns: a type without a tree");
    // Only the initial user namespace has no owner (Linux warns)
    let owner = ns.owner().map(|u| u.ns.ns_id);
    let e = Entry {
        ns: ns.downgrade(),
        owner,
    };
    let unified = nodes.unified.into_node(id, e.clone());
    let ty = nodes.ty.into_node(id, e.clone());
    let owned = owner.map(|o| nodes.owned.into_node((o, id), e));
    let mut t = NS_TREE.lock();
    // Ids are never reused (Linux VFS_WARN_ON_ONCE(node)): a second
    // namespace with one stays out, its nodes freed after the unlock
    if t.unified.get(&id).is_some() {
        drop(t);
        debug_assert!(false, "ns: id {} listed twice", id);
        return;
    }
    let old = t.unified.insert(unified);
    debug_assert!(old.is_none());
    let old = t.types[idx].insert(ty);
    debug_assert!(old.is_none());
    if let Some(n) = owned {
        let old = t.owned.insert(n);
        debug_assert!(old.is_none());
    }
    ns.common().linked.store(true, Relaxed);
}

/// Take `ns` out of its trees if it is in them (Linux __ns_tree_remove);
/// any context, the nodes freed after the unlock
pub fn remove(ns: &NsCommon) {
    let id = ns.ns_id;
    let nodes = {
        let mut t = NS_TREE.lock();
        if !ns.linked.load(Relaxed) {
            return;
        }
        ns.linked.store(false, Relaxed);
        let Some(e) = t.unified.get(&id) else {
            unreachable!("ns: id {} linked but not listed", id);
        };
        let (ty, owner) = (e.ns.ns_type(), e.owner);
        let idx = type_idx(ty).expect("ns: a type without a tree");
        let u = t.unified.remove_node(&id);
        let ty = t.types[idx].remove_node(&id);
        let o = owner.and_then(|o| t.owned.remove_node(&(o, id)));
        (u, ty, o)
    };
    drop(nodes);
}

/// The namespace numbered `id` in `tree`, counted, if it may be handed
/// out (Linux lookup_ns_id: ns_tree_lookup_rcu, ns_get_unless_inactive)
pub fn lookup(tree: Tree, id: u64) -> Option<NsRef> {
    let s = NS_TREE.lock().get(tree, id)?.ns.upgrade()?;
    s.get()
}

/// The id of the owner of the namespace numbered `id` in `tree`, None
/// if it is not listed or has no owner; takes no reference, for a
/// caller under a lock the namespace's last put would take
pub fn owner_id(tree: Tree, id: u64) -> Option<u64> {
    NS_TREE.lock().get(tree, id)?.owner
}

/// The namespace with the smallest id >= `id` in `tree`, counted, None
/// if there is none or it may not be handed out (Linux lookup_ns_id_at,
/// lookup_ns_owner_at: a listns resume point)
pub fn lookup_at(tree: Tree, id: u64) -> Option<NsRef> {
    let s = NS_TREE.lock().at(tree, id)?.1.ns.upgrade()?;
    s.get()
}

/// The first namespace after the one numbered `id` in `tree` that may
/// be handed out, counted (a list walk skipping what Linux
/// ns_get_unless_inactive refuses); with `previous`, the last one
/// before it
pub fn adjoined(tree: Tree, id: u64, previous: bool) -> Option<NsRef> {
    adjoined_by(tree, id, previous, Strong::get)
}

/// [`adjoined`] for any namespace still referenced, active or not
/// (Linux ns_tree_adjoined_rcu then ns_ref_get: NS_MNT_GET_NEXT/PREV)
pub fn adjoined_any(tree: Tree, id: u64, previous: bool) -> Option<NsRef> {
    adjoined_by(tree, id, previous, Strong::get_any)
}

/// [`adjoined`], each candidate checked by `get`
fn adjoined_by(
    tree: Tree,
    id: u64,
    previous: bool,
    get: fn(Strong) -> Option<NsRef>,
) -> Option<NsRef> {
    let mut at = id;
    loop {
        let (k, s) = {
            let t = NS_TREE.lock();
            let (k, e) = if previous {
                t.before(tree, at)?
            } else {
                t.at(tree, at.checked_add(1)?)?
            };
            (k, e.ns.upgrade())
        };
        // A refused candidate is dropped here, the lock released
        if let Some(r) = s.and_then(get) {
            return Some(r);
        }
        at = k;
    }
}

/// The namespaces of `tree` in id order, each counted as it is reached
/// (Linux list_for_each_entry_from_rcu over a tree's list): one added
/// meanwhile is seen if its id is past the walk's position
pub fn walk(tree: Tree) -> Walk {
    Walk { tree, at: Some(0) }
}

/// A walk of one tree ([`walk`]): the last id reached, None at the end
pub struct Walk {
    tree: Tree,
    at: Option<u64>,
}

impl Iterator for Walk {
    type Item = NsRef;

    fn next(&mut self) -> Option<NsRef> {
        let r = adjoined(self.tree, self.at?, false);
        self.at = r.as_ref().map(|r| r.common().ns_id);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ns::inum::Inum;
    use crate::ns::{INIT_USER_NS, INIT_UTS_NS, Namespace, UidGidMap};
    use alloc::vec::Vec;

    /// A user namespace below the initial one, listed
    fn user_ns() -> Arc<UserNamespace> {
        let nodes = Nodes::new().unwrap();
        let u = crate::util::kalloc::try_arc(UserNamespace {
            uid_map: UidGidMap::default(),
            gid_map: UidGidMap::default(),
            level: 1,
            parent: Some(INIT_USER_NS.clone()),
            owner: 0,
            group: 0,
            ns: NsCommon::new(Inum::alloc().unwrap()),
        })
        .unwrap();
        add(&NsRef::User(u.clone()), nodes);
        u
    }

    /// An active reference to a namespace (as an installed nsproxy's),
    /// put as it drops, before the namespace's own
    struct Held<T: Namespace>(Arc<T>);

    impl<T: Namespace> core::ops::Deref for Held<T> {
        type Target = Arc<T>;
        fn deref(&self) -> &Arc<T> {
            &self.0
        }
    }

    impl<T: Namespace> Drop for Held<T> {
        fn drop(&mut self) {
            self.0.active_put();
        }
    }

    /// A UTS namespace owned by `owner`, listed and not yet active
    fn new_uts_ns(owner: &Arc<UserNamespace>) -> Arc<UtsNamespace> {
        INIT_UTS_NS.clone_ns(owner).unwrap()
    }

    /// A UTS namespace owned by `owner`, listed, held active
    fn uts_ns(owner: &Arc<UserNamespace>) -> Held<UtsNamespace> {
        let n = new_uts_ns(owner);
        n.active_get();
        Held(n)
    }

    fn ids(it: impl Iterator<Item = NsRef>) -> Vec<u64> {
        it.map(|r| r.common().ns_id).collect()
    }

    #[test]
    fn initial_namespaces_listed() {
        let u = lookup(Tree::All, INIT_USER_NS.ns.ns_id).unwrap();
        assert!(matches!(u, NsRef::User(ref n) if Arc::ptr_eq(n, &INIT_USER_NS)));
        let t = lookup(Tree::Type(CLONE_NEWUTS), INIT_UTS_NS.ns.ns_id).unwrap();
        assert!(t.ptr_eq(&NsRef::Uts(INIT_UTS_NS.clone())));
        // The wrong type's tree does not have it
        assert!(lookup(Tree::Type(CLONE_NEWPID), INIT_UTS_NS.ns.ns_id).is_none());
        // Owned by the initial user namespace, which itself has no owner
        let owned = Tree::owned_by(&INIT_USER_NS);
        assert!(lookup(owned, INIT_UTS_NS.ns.ns_id).is_some());
        assert!(lookup(owned, INIT_USER_NS.ns.ns_id).is_none());
    }

    #[test]
    fn lookup_and_removal() {
        let u = user_ns();
        let a = uts_ns(&u);
        let id = a.ns.ns_id;
        assert!(
            lookup(Tree::All, id)
                .unwrap()
                .ptr_eq(&NsRef::Uts(a.clone()))
        );
        assert!(lookup(Tree::Type(CLONE_NEWUTS), id).is_some());
        assert!(lookup(Tree::owned_by(&u), id).is_some());
        assert!(lookup(Tree::Type(0x1234), id).is_none());
        drop(a);
        assert!(lookup(Tree::All, id).is_none());
        assert!(lookup(Tree::Type(CLONE_NEWUTS), id).is_none());
        assert!(lookup(Tree::owned_by(&u), id).is_none());
    }

    #[test]
    fn lookup_at_smallest_at_or_above() {
        let u = user_ns();
        let a = uts_ns(&u);
        let b = uts_ns(&u);
        let o = Tree::owned_by(&u);
        let (ia, ib) = (a.ns.ns_id, b.ns.ns_id);
        assert!(ia < ib);
        assert_eq!(lookup_at(o, 0).unwrap().common().ns_id, ia);
        assert_eq!(lookup_at(o, ia).unwrap().common().ns_id, ia);
        assert_eq!(lookup_at(o, ia + 1).unwrap().common().ns_id, ib);
        assert!(lookup_at(o, ib + 1).is_none());
        // The type tree holds `b` at its id (other tests' namespaces,
        // some inactive, come and go between `a` and `b`)
        let n = lookup_at(Tree::Type(CLONE_NEWUTS), ib).unwrap();
        assert_eq!(n.common().ns_id, ib);
    }

    #[test]
    fn walks_in_id_order() {
        let u = user_ns();
        let a = uts_ns(&u);
        let b = uts_ns(&u);
        let c = uts_ns(&u);
        let o = Tree::owned_by(&u);
        let want = [a.ns.ns_id, b.ns.ns_id, c.ns.ns_id];
        assert_eq!(ids(walk(o)), want);
        // Every tree is sorted and holds each of them (other tests'
        // namespaces come and go meanwhile)
        for tree in [Tree::All, Tree::Type(CLONE_NEWUTS)] {
            let got = ids(walk(tree));
            assert!(got.windows(2).all(|w| w[0] < w[1]));
            assert!(want.iter().all(|i| got.contains(i)));
        }
        assert!(ids(walk(Tree::Type(CLONE_NEWUSER))).contains(&u.ns.ns_id));
        assert!(!ids(walk(Tree::Type(CLONE_NEWUSER))).contains(&a.ns.ns_id));
        // A removed one is skipped; neighbours step over it
        drop(b);
        assert_eq!(ids(walk(o)), [want[0], want[2]]);
        let n = adjoined(o, want[0], false).unwrap();
        assert_eq!(n.common().ns_id, want[2]);
        let p = adjoined(o, want[2], true).unwrap();
        assert_eq!(p.common().ns_id, want[0]);
        assert!(adjoined(o, want[0], true).is_none());
        assert!(adjoined(o, want[2], false).is_none());
        drop((a, c, n, p));
        assert!(walk(o).next().is_none());
    }

    /// Only a namespace in active use is handed out; its first active
    /// reference activates its owner, its last deactivates it
    #[test]
    fn only_active_handed_out() {
        let u = user_ns();
        let a = new_uts_ns(&u);
        let (id, uid) = (a.ns.ns_id, u.ns.ns_id);
        assert!(lookup(Tree::All, id).is_none());
        assert!(lookup(Tree::All, uid).is_none());
        assert!(walk(Tree::owned_by(&u)).next().is_none());
        a.active_get();
        assert!(lookup(Tree::All, id).is_some());
        assert!(lookup(Tree::Type(CLONE_NEWUSER), uid).is_some());
        // A second holder: the owner is not counted again
        a.active_get();
        a.active_put();
        assert!(u.ns.is_active());
        a.active_put();
        assert!(!a.ns.is_active() && !u.ns.is_active());
        assert!(lookup(Tree::All, id).is_none());
        assert!(lookup_at(Tree::owned_by(&u), 0).is_none());
        // The initial ones are always active, never counted
        INIT_UTS_NS.active_put();
        assert!(lookup(Tree::All, INIT_UTS_NS.ns.ns_id).is_some());
    }
}
