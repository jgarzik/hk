//! Mount propagation (Linux fs/pnode.c): peer groups and slaves
//!
//! As Linux, the members of a peer group are a ring through
//! `mnt_share` sharing `group_id`; a slave hangs on one master mount's
//! `slave_list` through `slave` and points at it with `master`, and
//! receives from the master's whole peer group. A mount attached under
//! a shared mount is copied to every peer and down the slave groups;
//! an umount takes along the copies Linux propagate_umount allows,
//! and a mount left on the root of one that goes slides down.
//!
//! Every link lives in [`PropLinks`] (`Mount.prop`), owned by
//! NAMESPACE_SEM ([`NsTree`]: read under either side, written under
//! write), Linux's namespace_sem; there is no lock of its own. A mount
//! a link names is linked itself, and stays alive while linked: it is
//! in a namespace (the tree holds it) or held by the caller, and is
//! made private before it leaves (umount, a namespace's end); its
//! teardown unlinks one left behind (`teardown_prop`). Group ids come
//! from [`GROUP_IDA`] (Linux mnt_group_ida).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::null;

use super::dentry::{Dentry, DentryRef};
use super::mount::{
    MNT_LOCKED, MNT_UMOUNT, MOUNT_LOCK, Mount, MountRef, MpPtr, NsTree, UmountList, copy_plan,
    copy_tree, for_each_mut, is_path_reachable,
};
use super::path_ref::Path;
use crate::util::ida::Ida;

/// Not a peer of the original: a slave of it (Linux CL_SLAVE)
pub const CL_SLAVE: u32 = 0x02;
/// A peer group of its own if it has none (Linux CL_MAKE_SHARED)
pub const CL_MAKE_SHARED: u32 = 0x08;
/// No propagation at all (Linux CL_PRIVATE)
pub const CL_PRIVATE: u32 = 0x10;

/// Peer group ids, from 1 (Linux mnt_group_ida): allocated under
/// NAMESPACE_SEM write, freed when a group's last member leaves
static GROUP_IDA: Ida = Ida::new();

/// The propagation type of a mount (Linux MS_SHARED and friends)
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Prop {
    Shared,
    Slave,
    Private,
    Unbindable,
}

/// Where a slave's `slave` link hangs (Linux mnt_slave.pprev): first
/// on its master's list, or after another slave
#[derive(Clone, Copy)]
enum Pprev {
    Unlinked,
    Head(*const Mount),
    After(*const Mount),
}

/// A mount's propagation state (Linux mnt_group_id, mnt_share,
/// mnt_slave_list, mnt_slave, mnt_master, T_MARKED), under
/// NAMESPACE_SEM
pub struct PropLinks {
    /// Peer group, 0 if not shared (Linux mnt_group_id; shared exactly
    /// when nonzero: Linux's T_SHARED without the window
    /// invent_group_ids leaves before it is set)
    group_id: u32,
    /// The peer ring (Linux mnt_share); null alone (list_empty)
    share_next: *const Mount,
    share_prev: *const Mount,
    /// First of this mount's slaves (Linux mnt_slave_list.first)
    slave_first: *const Mount,
    /// The next slave of this mount's master (Linux mnt_slave.next)
    slave_next: *const Mount,
    slave_pprev: Pprev,
    /// The mount this one is a slave of (Linux mnt_master)
    master: *const Mount,
    /// propagate_mnt's, propagate_umount's and bulk_make_private's
    /// mark (Linux T_MARKED)
    marked: bool,
    /// An umount candidate (Linux T_UMOUNT_CANDIDATE)
    candidate: bool,
}

// SAFETY: the pointers name mounts (Sync), followed only under
// NAMESPACE_SEM (the `LockedBy` owner), while the mounts are linked
unsafe impl Send for PropLinks {}
// SAFETY: as above
unsafe impl Sync for PropLinks {}

impl PropLinks {
    pub const fn new() -> Self {
        Self {
            group_id: 0,
            share_next: null(),
            share_prev: null(),
            slave_first: null(),
            slave_next: null(),
            slave_pprev: Pprev::Unlinked,
            master: null(),
            marked: false,
            candidate: false,
        }
    }

    /// On some ring or list, or the head of one
    fn linked(&self) -> bool {
        self.group_id != 0
            || !self.share_next.is_null()
            || !self.slave_first.is_null()
            || !matches!(self.slave_pprev, Pprev::Unlinked)
            || !self.master.is_null()
    }
}

/// The mount `p` names, borrowed for the guard's borrow `ns`
fn mnt(ns: &NsTree, p: *const Mount) -> &Mount {
    let _ = ns;
    // SAFETY: `p` is a held mount or one a link names, linked; a linked
    // mount stays alive (module doc) and is unlinked only under
    // `&mut NsTree`, which cannot be borrowed while `ns` is
    unsafe { &*p }
}

fn links(ns: &NsTree, p: *const Mount) -> &PropLinks {
    mnt(ns, p).prop.access(ns)
}

fn links_mut(ns: &mut NsTree, p: *const Mount) -> &mut PropLinks {
    // SAFETY: as `mnt`: alive for this borrow of the guard, the only
    // one that can unlink it
    let m = unsafe { &*p };
    m.prop.access_mut(ns)
}

/// A reference to the linked mount `p` (in a namespace or held)
fn get(ns: &NsTree, p: *const Mount) -> MountRef {
    MountRef::entry_ref(mnt(ns, p))
}

/// The peer group of `m`, 0 if not shared; stable under NAMESPACE_SEM
pub fn group_id(ns: &NsTree, m: &Mount) -> u32 {
    m.prop.access(ns).group_id
}

/// `m` is shared (Linux IS_MNT_SHARED)
pub fn is_shared(ns: &NsTree, m: &Mount) -> bool {
    group_id(ns, m) != 0
}

fn master(ns: &NsTree, m: *const Mount) -> *const Mount {
    links(ns, m).master
}

/// Linux next_peer: alone, itself
fn next_peer(ns: &NsTree, m: *const Mount) -> *const Mount {
    let n = links(ns, m).share_next;
    if n.is_null() { m } else { n }
}

/// Linux peers()
fn peers(ns: &NsTree, a: *const Mount, b: *const Mount) -> bool {
    let g = links(ns, a).group_id;
    g != 0 && g == links(ns, b).group_id
}

/// Added by the propagation under way: in no namespace yet (Linux
/// IS_MNT_NEW)
fn is_new(ns: &NsTree, m: *const Mount) -> bool {
    mnt(ns, m).ns() == 0
}

/// Linux mnt_alloc_group_id, failing with ENOMEM
fn alloc_group_id(ns: &mut NsTree, m: *const Mount) -> Result<(), super::KernelError> {
    links_mut(ns, m).group_id = GROUP_IDA.try_alloc_min(1)?;
    Ok(())
}

/// Linux mnt_release_group_id
fn release_group_id(ns: &mut NsTree, m: *const Mount) {
    let l = links_mut(ns, m);
    GROUP_IDA.free(l.group_id);
    l.group_id = 0;
}

/// Linux set_mnt_shared: shared ends unbindable (T_SHARED_MASK)
fn set_mnt_shared(ns: &NsTree, m: *const Mount) {
    mnt(ns, m).set_unbindable(false);
}

/// Linux list_add(&new->mnt_share, &old->mnt_share)
fn share_add(ns: &mut NsTree, new: *const Mount, old: *const Mount) {
    let on = next_peer(ns, old);
    {
        let l = links_mut(ns, new);
        l.share_next = on;
        l.share_prev = old;
    }
    links_mut(ns, on).share_prev = new;
    links_mut(ns, old).share_next = new;
}

/// Linux list_del_init(&m->mnt_share)
fn share_del_init(ns: &mut NsTree, m: *const Mount) {
    let (p, n) = {
        let l = links(ns, m);
        (l.share_prev, l.share_next)
    };
    if n.is_null() {
        return;
    }
    if p == n {
        // Two in the ring: the other is left alone
        let l = links_mut(ns, p);
        l.share_next = null();
        l.share_prev = null();
    } else {
        links_mut(ns, p).share_next = n;
        links_mut(ns, n).share_prev = p;
    }
    let l = links_mut(ns, m);
    l.share_next = null();
    l.share_prev = null();
}

/// Point `pp` (a list head or a slave) at `next`
fn set_pprev_target(ns: &mut NsTree, pp: Pprev, next: *const Mount) {
    match pp {
        Pprev::Unlinked => {}
        Pprev::Head(o) => links_mut(ns, o).slave_first = next,
        Pprev::After(p) => links_mut(ns, p).slave_next = next,
    }
}

/// Linux hlist_add_head(&m->mnt_slave, &to->mnt_slave_list)
fn slave_add_head(ns: &mut NsTree, m: *const Mount, to: *const Mount) {
    let first = links(ns, to).slave_first;
    if !first.is_null() {
        links_mut(ns, first).slave_pprev = Pprev::After(m);
    }
    {
        let l = links_mut(ns, m);
        l.slave_next = first;
        l.slave_pprev = Pprev::Head(to);
    }
    links_mut(ns, to).slave_first = m;
}

/// Linux hlist_add_behind(&m->mnt_slave, &prev->mnt_slave)
fn slave_add_behind(ns: &mut NsTree, m: *const Mount, prev: *const Mount) {
    let next = links(ns, prev).slave_next;
    if !next.is_null() {
        links_mut(ns, next).slave_pprev = Pprev::After(m);
    }
    {
        let l = links_mut(ns, m);
        l.slave_next = next;
        l.slave_pprev = Pprev::After(prev);
    }
    links_mut(ns, prev).slave_next = m;
}

/// Linux hlist_del_init(&m->mnt_slave)
fn slave_del_init(ns: &mut NsTree, m: *const Mount) {
    let (pp, next) = {
        let l = links(ns, m);
        (l.slave_pprev, l.slave_next)
    };
    if matches!(pp, Pprev::Unlinked) {
        return;
    }
    set_pprev_target(ns, pp, next);
    if !next.is_null() {
        links_mut(ns, next).slave_pprev = pp;
    }
    let l = links_mut(ns, m);
    l.slave_next = null();
    l.slave_pprev = Pprev::Unlinked;
}

/// Linux hlist_splice_init(&from->mnt_slave_list, last,
/// &to->mnt_slave_list): `from`'s slaves, `last` the final one, go to
/// the front of `to`'s
fn slave_splice_init(ns: &mut NsTree, from: *const Mount, last: *const Mount, to: *const Mount) {
    let tf = links(ns, to).slave_first;
    if !tf.is_null() {
        links_mut(ns, tf).slave_pprev = Pprev::After(last);
    }
    links_mut(ns, last).slave_next = tf;
    let ff = links(ns, from).slave_first;
    links_mut(ns, to).slave_first = ff;
    links_mut(ns, ff).slave_pprev = Pprev::Head(to);
    links_mut(ns, from).slave_first = null();
}

/// Set up `new`, a clone of `old`, for propagation as `flag` says
/// (Linux clone_mnt's part after alloc_vfsmnt): a peer of `old`
/// unless CL_SLAVE or CL_PRIVATE, a group of its own with
/// CL_MAKE_SHARED, a slave of `old` (CL_SLAVE, `old` shared) or of
/// `old`'s master, nothing with CL_PRIVATE. `new` is fresh: no
/// reference to it was shared.
pub fn clone_links(ns: &mut NsTree, old: &Mount, new: &Mount, flag: u32) {
    let (old, new) = (core::ptr::from_ref(old), core::ptr::from_ref(new));
    let og = links(ns, old).group_id;
    links_mut(ns, new).group_id = if flag & (CL_SLAVE | CL_PRIVATE) != 0 {
        0
    } else {
        og
    };
    if flag & CL_MAKE_SHARED != 0 && links(ns, new).group_id == 0 {
        // A copy cannot be unwound here (Linux: -ENOMEM unwinds it)
        links_mut(ns, new).group_id = GROUP_IDA.alloc_min(1);
    }
    if links(ns, new).group_id != 0 {
        set_mnt_shared(ns, new);
    }
    if flag & CL_PRIVATE != 0 {
        return;
    }
    if peers(ns, new, old) {
        share_add(ns, new, old);
    }
    let om = master(ns, old);
    if flag & CL_SLAVE != 0 && og != 0 {
        slave_add_head(ns, new, old);
        links_mut(ns, new).master = old;
    } else if !om.is_null() {
        slave_add_behind(ns, new, old);
        links_mut(ns, new).master = om;
    }
}

/// `m`, and with `recurse` every mount below it, gets a peer group if
/// it has none (Linux invent_group_ids), or ENOMEM with the ids it gave
/// released (cleanup_group_ids)
pub fn invent_group_ids(
    ns: &mut NsTree,
    m: &MountRef,
    recurse: bool,
) -> Result<(), super::KernelError> {
    let mut fresh: Vec<*const Mount> = Vec::new();
    let mut err = Ok(());
    let top = MountRef::as_ptr(m);
    for_each_mut(ns, m, |ns, t| {
        let t = MountRef::as_ptr(t);
        if err.is_err() || (!recurse && t != top) || links(ns, t).group_id != 0 {
            return;
        }
        if fresh.try_reserve(1).is_err() {
            err = Err(super::KernelError::OutOfMemory);
            return;
        }
        err = alloc_group_id(ns, t);
        if err.is_ok() {
            fresh.push(t);
        }
    });
    if err.is_err() {
        for t in fresh {
            release_group_id(ns, t);
        }
    }
    err
}

/// Linux transfer_propagation: `mnt`'s slaves go to `to` (or are freed)
fn transfer_propagation(ns: &mut NsTree, mnt: *const Mount, to: *const Mount) {
    let mut last = null();
    let mut s = links(ns, mnt).slave_first;
    while !s.is_null() {
        let n = links(ns, s).slave_next;
        links_mut(ns, s).master = to;
        if to.is_null() {
            slave_del_init(ns, s);
        } else {
            last = s;
        }
        s = n;
    }
    if !last.is_null() {
        slave_splice_init(ns, mnt, last, to);
    }
}

/// Linux change_mnt_propagation; MS_SHARED needs a group id already
/// (do_change_type's invent_group_ids)
pub fn change_mnt_propagation(ns: &mut NsTree, mnt: &Mount, ty: Prop) {
    let mnt = core::ptr::from_ref(mnt);
    let mut m = master(ns, mnt);
    if ty == Prop::Shared {
        set_mnt_shared(ns, mnt);
        return;
    }
    if is_shared(ns, crate::fs::pnode::mnt(ns, mnt)) {
        if links(ns, mnt).share_next.is_null() {
            release_group_id(ns, mnt);
        } else {
            m = next_peer(ns, mnt);
            share_del_init(ns, mnt);
            links_mut(ns, mnt).group_id = 0;
        }
        transfer_propagation(ns, mnt, m);
    }
    slave_del_init(ns, mnt);
    if ty == Prop::Slave {
        links_mut(ns, mnt).master = m;
        if !m.is_null() {
            slave_add_head(ns, mnt, m);
        }
    } else {
        links_mut(ns, mnt).master = null();
        self::mnt(ns, mnt).set_unbindable(ty == Prop::Unbindable);
    }
}

/// Linux __propagation_next
fn __propagation_next(ns: &NsTree, m: *const Mount, origin: *const Mount) -> Option<*const Mount> {
    let mut m = m;
    loop {
        let master = master(ns, m);
        if master == self::master(ns, origin) {
            let next = next_peer(ns, m);
            return (next != origin).then_some(next);
        }
        let n = links(ns, m).slave_next;
        if !n.is_null() {
            return Some(n);
        }
        // Back at the master
        m = master;
    }
}

/// The next mount in the propagation tree from `origin`, `m` seen
/// last (Linux propagation_next)
fn propagation_next(ns: &NsTree, m: *const Mount, origin: *const Mount) -> Option<*const Mount> {
    let first = links(ns, m).slave_first;
    if !is_new(ns, m) && !first.is_null() {
        return Some(first);
    }
    __propagation_next(ns, m, origin)
}

/// The first mount of the next peer group in the propagation tree
/// from `origin`, depth first (Linux next_group)
fn next_group(ns: &NsTree, m: *const Mount, origin: *const Mount) -> Option<*const Mount> {
    let og = links(ns, origin).group_id;
    let mut m = m;
    loop {
        loop {
            let first = links(ns, m).slave_first;
            if !is_new(ns, m) && !first.is_null() {
                return Some(first);
            }
            let next = next_peer(ns, m);
            if links(ns, m).group_id == og {
                if next == origin {
                    return None;
                }
            } else if links(ns, m).slave_next != next {
                break;
            }
            m = next;
        }
        // m is the last peer
        loop {
            let master = master(ns, m);
            let sn = links(ns, m).slave_next;
            if !sn.is_null() {
                return Some(sn);
            }
            m = next_peer(ns, master);
            if links(ns, master).group_id == og {
                break;
            }
            if links(ns, master).slave_next == m {
                break;
            }
            m = master;
        }
        if m == origin {
            return None;
        }
    }
}

/// Linux need_secondary: not one of this propagation's copies, and the
/// mountpoint is inside what `m` shows
fn need_secondary(ns: &NsTree, m: *const Mount, d: &DentryRef) -> bool {
    !is_new(ns, m) && super::is_subdir(d, &mnt(ns, m).root)
}

/// Linux find_master: the copy the copies for `m`'s group are slaves
/// of, from `last_copy` up the chain of copies toward `original`
fn find_master(
    ns: &NsTree,
    m: *const Mount,
    last_copy: *const Mount,
    original: *const Mount,
) -> *const Mount {
    let mut m = m;
    // Ascend until there's a copy for something with the same master
    let p = loop {
        let p = master(ns, m);
        if p.is_null() || links(ns, p).marked {
            break p;
        }
        m = p;
    };
    let mut last_copy = last_copy;
    while !peers(ns, last_copy, original) {
        let parent = mnt(ns, last_copy)
            .parent_in(ns)
            .map_or(null(), core::ptr::from_ref);
        if master(ns, parent) == p {
            if !peers(ns, parent, m) {
                last_copy = master(ns, last_copy);
            }
            break;
        }
        last_copy = master(ns, last_copy);
    }
    last_copy
}

fn set_mark(ns: &mut NsTree, m: *const Mount, on: bool) {
    if !m.is_null() {
        links_mut(ns, m).marked = on;
    }
}

/// Copies of the tree at `src`, to go at `dest_mp` on the shared mount
/// `dest`, for every mount `dest`'s events reach (Linux
/// propagate_mnt): peers of `dest` get peers of `src`, the slave
/// groups slaves, a group of shared slaves a peer group of its own.
/// Each copy is hung on its mountpoint, not visible (no list or hash
/// entry), its tree left out of every namespace (IS_MNT_NEW) for
/// graft to commit. The copies' roots are returned (Linux tree_list).
pub(super) fn propagate_mnt(
    ns: &mut NsTree,
    dest: &MountRef,
    dest_mp: MpPtr,
    src: &MountRef,
) -> Vec<MountRef> {
    let mut list: Vec<MountRef> = Vec::new();
    // SAFETY: the caller pins it, under NAMESPACE_SEM write
    let d = unsafe { dest_mp.dentry() };
    let d = &d;
    let dest_p = MountRef::as_ptr(dest);
    let src_p = MountRef::as_ptr(src);
    let dm = master(ns, dest_p);
    set_mark(ns, dm, true);
    let mut copy = src.clone();
    let mut m = Some(dest_p);
    while let Some(mp) = m {
        let (mut ty, mut n);
        if mp == dest_p {
            // Have one for dest itself
            copy = src.clone();
            ty = CL_MAKE_SHARED;
            n = next_peer(ns, mp);
            if n == mp {
                m = next_group(ns, mp, dest_p);
                continue;
            }
        } else {
            ty = CL_SLAVE;
            // Beginning of a peer group among the slaves?
            if links(ns, mp).group_id != 0 {
                ty |= CL_MAKE_SHARED;
            }
            n = mp;
        }
        loop {
            if need_secondary(ns, n, d) {
                if ty & CL_SLAVE != 0 {
                    // First in this peer group
                    let c = find_master(ns, n, MountRef::as_ptr(&copy), src_p);
                    copy = get(ns, c);
                }
                let this = copy_prop(ns, &copy, ty);
                // On its mountpoint, not yet visible: graft makes it so
                // (Linux mnt_set_mountpoint under mount_locked_reader)
                let to = get(ns, n);
                this.set_mountpoint(&mut MOUNT_LOCK.read_excl(), &to, dest_mp);
                let nm = master(ns, n);
                set_mark(ns, nm, true);
                copy = this.clone();
                list.push(this);
                ty = CL_MAKE_SHARED;
            }
            n = next_peer(ns, n);
            if n == mp {
                break;
            }
        }
        m = next_group(ns, mp, dest_p);
    }
    for c in &list {
        let pm = c
            .parent_in(&*ns)
            .map_or(null(), |p| master(ns, core::ptr::from_ref(p)));
        set_mark(ns, pm, false);
    }
    set_mark(ns, dm, false);
    list
}

/// Linux copy_tree(copy, copy->mnt.mnt_root, ty) for propagate_mnt
fn copy_prop(ns: &mut NsTree, copy: &MountRef, ty: u32) -> MountRef {
    // A tree being attached holds no unbindable mount (a recursive
    // bind leaves them out, MS_MOVE refuses them under a shared
    // mount), nor do its copies: no EPERM here
    let plan = copy_plan(ns, copy, &copy.root)
        .unwrap_or_else(|_| unreachable!("pnode: a locked unbindable mount in a propagated tree"));
    copy_tree(ns, &plan, ty)
}

/// The parent of the linked mount `m`, null for none
fn parent_of(ns: &NsTree, m: *const Mount) -> *const Mount {
    mnt(ns, m).parent_in(ns).map_or(null(), core::ptr::from_ref)
}

/// The mount on `d` in `m` (Linux __lookup_mnt), null for none: a mount
/// in the tree, which NAMESPACE_SEM keeps
fn lookup_at(ns: &NsTree, m: *const Mount, d: *const Dentry) -> *const Mount {
    let g = crate::sync::rcu::read_lock();
    // SAFETY: `d` is a mountpoint of a mount in the tree, pinned by its
    // Mountpoint while NAMESPACE_SEM holds that mount there
    let d = unsafe { &*d };
    super::mount::__lookup_mnt(mnt(ns, m), d, &g).map_or(null(), core::ptr::from_ref)
}

/// Linux will_be_unmounted: MNT_UMOUNT set
fn will_be_unmounted(ns: &NsTree, m: *const Mount) -> bool {
    mnt(ns, m).flags() & MNT_UMOUNT != 0
}

fn is_candidate(ns: &NsTree, m: *const Mount) -> bool {
    links(ns, m).candidate
}

fn set_candidate(ns: &mut NsTree, m: *const Mount, on: bool) {
    links_mut(ns, m).candidate = on;
}

fn is_marked(ns: &NsTree, m: *const Mount) -> bool {
    links(ns, m).marked
}

fn locked(ns: &NsTree, m: *const Mount) -> bool {
    mnt(ns, m).flags() & MNT_LOCKED != 0
}

/// A reference to the linked mount `m`, as an umount list entry
fn entry(ns: &NsTree, m: *const Mount) -> Arc<Mount> {
    get(ns, m).into_entry()
}

/// Put the reference an umount list entry held
fn put_entry(e: Arc<Mount>) {
    // SAFETY: umount list entries are references (`entry`, `into_entry`)
    drop(unsafe { MountRef::from_entry(e) });
}

/// Linux skip_propagation_subtree: past everything that gets
/// propagation from `m`
fn skip_propagation_subtree(
    ns: &NsTree,
    m: *const Mount,
    origin: *const Mount,
) -> Option<*const Mount> {
    let mut p = __propagation_next(ns, m, origin);
    while let Some(pp) = p {
        if !peers(ns, m, pp) {
            break;
        }
        p = __propagation_next(ns, pp, origin);
    }
    p
}

/// `m` receives propagation from `parent` (Linux receives_from)
fn receives_from(ns: &NsTree, m: *const Mount, parent: *const Mount) -> bool {
    if m == parent {
        return false;
    }
    let mut m = m;
    while !m.is_null() {
        if m == parent || peers(ns, m, parent) {
            return true;
        }
        m = master(ns, m);
    }
    false
}

/// The next umount candidate below `m` in the chain of `victim` (Linux
/// next_candidate): the mount at the victim's mountpoint in `m`, if `m`
/// receives propagation from the victim's parent
fn next_candidate(ns: &NsTree, m: *const Mount, victim: *const Mount) -> *const Mount {
    if !receives_from(ns, m, parent_of(ns, victim)) {
        return null();
    }
    lookup_at(ns, m, mnt(ns, victim).mountpoint_in(ns))
}

/// `m` has a submount `f` accepts
fn any_kid(ns: &NsTree, m: *const Mount, mut f: impl FnMut(*const Mount) -> bool) -> bool {
    mnt(ns, m).kids_in(ns).any(|n| f(core::ptr::from_ref(n)))
}

/// Would propagate_umount take a mount of the chain of candidates
/// from `c`, and has that mount references beyond its tree's (Linux
/// chain_busy, for a synchronous umount of one `victim` with no
/// submounts)
fn chain_busy(ns: &NsTree, c: *const Mount, victim: *const Mount) -> bool {
    // The deepest candidate with a submount outside the chain
    let mut deepest = null();
    let mut m = c;
    while !m.is_null() {
        let next = next_candidate(ns, m, victim);
        if any_kid(ns, m, |n| n != next && n != victim) {
            deepest = m;
        }
        m = next;
    }
    let mut above = !deepest.is_null();
    m = c;
    while !m.is_null() {
        let next = next_candidate(ns, m, victim);
        let over = mnt(ns, m).overmount_in(ns);
        let mut goes = !any_kid(ns, m, |n| n != next && n != over && n != victim);
        if goes && !next.is_null() && next != over && above && m != deepest {
            goes = false;
        }
        if m == deepest {
            above = false;
        }
        if goes && mnt(ns, m).mnt_get_count() > 1 {
            return true;
        }
        m = next;
    }
    false
}

/// An umount of `m` would fail EBUSY (Linux propagate_mount_busy): it
/// has submounts or more than `refs` references, or a mount the
/// propagation takes along has more than its tree's; under
/// NAMESPACE_SEM and MOUNT_LOCK, approximate as Linux's while fast
/// paths run
pub(super) fn propagate_mount_busy(ns: &NsTree, m: &Mount, refs: isize) -> bool {
    if m.has_children(ns) || m.mnt_get_count() > refs {
        return true;
    }
    let victim = core::ptr::from_ref(m);
    let parent = parent_of(ns, victim);
    if parent.is_null() {
        return false;
    }
    let d = m.mountpoint_in(ns);
    let mut q = propagation_next(ns, parent, parent);
    while let Some(qm) = q {
        let c = lookup_at(ns, qm, d);
        // Each chain once, from its top: skip receivers that are
        // candidates
        let qp = parent_of(ns, qm);
        let skip = c.is_null()
            || (!qp.is_null()
                && core::ptr::eq(mnt(ns, qm).mountpoint_in(ns), d)
                && receives_from(ns, qp, parent));
        if !skip && chain_busy(ns, c, victim) {
            return true;
        }
        q = propagation_next(ns, qm, parent);
    }
    false
}

/// Clear MNT_LOCKED on the copies an umount of `m` takes along (Linux
/// propagate_mount_unlock)
pub(super) fn propagate_mount_unlock(ns: &NsTree, m: &Mount) {
    let parent = parent_of(ns, core::ptr::from_ref(m));
    if parent.is_null() {
        return;
    }
    let d = m.mountpoint_in(ns);
    let mut q = propagation_next(ns, parent, parent);
    while let Some(qm) = q {
        let c = lookup_at(ns, qm, d);
        if !c.is_null() {
            mnt(ns, c).mark(MNT_LOCKED, false);
        }
        q = propagation_next(ns, qm, parent);
    }
}

/// Take `e`'s mount out of its parent's list, committed to going
/// (Linux umount_one), onto `to_umount` with the reference `e` holds
fn umount_one(ns: &mut NsTree, e: Arc<Mount>, to_umount: &mut UmountList) {
    let tree = super::mount::hide_mnt(ns, &e);
    to_umount.push_back(e);
    drop(tree);
}

/// Linux remove_from_candidate_list: unmarked, off `candidates`, its
/// reference handed back
fn remove_from_candidate_list(
    ns: &mut NsTree,
    m: *const Mount,
    candidates: &mut UmountList,
) -> Option<Arc<Mount>> {
    let l = links_mut(ns, m);
    l.marked = false;
    l.candidate = false;
    candidates.remove(mnt(ns, m))
}

/// The candidates an umount of the mounts in `set` makes (Linux
/// gather_candidates): at each set member's mountpoint, in every mount
/// receiving propagation from its parent
fn gather_candidates(ns: &mut NsTree, set: &UmountList, candidates: &mut UmountList) {
    for m in set.iter() {
        let m = core::ptr::from_ref(m);
        if is_candidate(ns, m) {
            continue;
        }
        set_candidate(ns, m, true);
        let p = parent_of(ns, m);
        if p.is_null() {
            continue;
        }
        let d = mnt(ns, m).mountpoint_in(ns);
        let mut q = propagation_next(ns, p, p);
        while let Some(qm) = q {
            let child = lookup_at(ns, qm, d);
            if !child.is_null() {
                // Met already on an earlier member: nothing new on what
                // gets propagation from `qm`
                if is_candidate(ns, child) {
                    q = skip_propagation_subtree(ns, qm, p);
                    continue;
                }
                set_candidate(ns, child, true);
                if !will_be_unmounted(ns, child) {
                    candidates.push_front(entry(ns, child));
                }
            }
            q = propagation_next(ns, qm, p);
        }
    }
    for m in set.iter() {
        set_candidate(ns, core::ptr::from_ref(m), false);
    }
}

/// A submount of `m` stays: wherever `m`'s chain of descent has a mount
/// not on its parent's root, the parent stays too (Linux
/// trim_ancestors)
fn trim_ancestors(ns: &mut NsTree, m: *const Mount) {
    let mut m = m;
    let mut p = parent_of(ns, m);
    while !p.is_null() && is_candidate(ns, p) {
        // Every candidate below is an overmount
        if is_marked(ns, m) {
            return;
        }
        set_mark(ns, m, true);
        if m != mnt(ns, p).overmount_in(ns) {
            set_candidate(ns, p, false);
        }
        m = p;
        p = parent_of(ns, m);
    }
}

/// Exclude the candidates `m` forbids, or commit to unmounting `m` if it
/// is unlocked and holds nothing (Linux trim_one); only `m` may leave
/// `candidates`
fn trim_one(
    ns: &mut NsTree,
    m: *const Mount,
    candidates: &mut UmountList,
    to_umount: &mut UmountList,
) {
    if !is_candidate(ns, m) {
        // trim_ancestors left it on the list
        if let Some(e) = remove_from_candidate_list(ns, m, candidates) {
            put_entry(e);
        }
        return;
    }
    let over = mnt(ns, m).overmount_in(ns);
    let (mut found, mut remove_this) = (false, false);
    for n in mnt(ns, m).kids_in(ns) {
        let n = core::ptr::from_ref(n);
        if !is_candidate(ns, n) {
            found = true;
            if n != over {
                remove_this = true;
                break;
            }
        }
    }
    let mut umount_this = false;
    if found {
        trim_ancestors(ns, m);
    } else if !locked(ns, m) && !mnt(ns, m).has_children(ns) {
        remove_this = true;
        umount_this = true;
    }
    if remove_this && let Some(e) = remove_from_candidate_list(ns, m, candidates) {
        if umount_this {
            umount_one(ns, e, to_umount);
        } else {
            put_entry(e);
        }
    }
}

/// Unmount `m` and the candidates above it up to the first locked one
/// that would reveal what it hides (Linux handle_locked)
fn handle_locked(
    ns: &mut NsTree,
    m: *const Mount,
    candidates: &mut UmountList,
    to_umount: &mut UmountList,
) {
    if !is_candidate(ns, m) {
        // trim_ancestors left it on the list
        if let Some(e) = remove_from_candidate_list(ns, m, candidates) {
            put_entry(e);
        }
        return;
    }
    let mut chain = UmountList::new();
    let mut cutoff = m;
    let mut p = m;
    while !p.is_null() && is_candidate(ns, p) {
        if let Some(e) = remove_from_candidate_list(ns, p, candidates) {
            chain.push_back(e);
        }
        if !locked(ns, p) {
            cutoff = parent_of(ns, p);
        }
        p = parent_of(ns, p);
    }
    if !p.is_null() && will_be_unmounted(ns, p) {
        cutoff = p;
    }
    let mut m = m;
    while m != cutoff {
        let e = chain
            .remove(mnt(ns, m))
            .expect("pnode: a candidate below the cutoff off its chain");
        umount_one(ns, e, to_umount);
        m = parent_of(ns, m);
    }
    while let Some(e) = chain.pop_front() {
        put_entry(e);
    }
}

/// `m` stays, over the top of a stack of mounts that go, each fully
/// covered by the one above: it slides to where the bottom of the stack
/// hangs (Linux reparent); for the moment two mounts share that place,
/// until umount_tree takes the stack off
fn reparent(ns: &mut NsTree, m: *const Mount) {
    let mut p = m;
    let mp = loop {
        let mp = mnt(ns, p)
            .mp_in(ns)
            .expect("pnode: an unmounted mount off its mountpoint");
        p = parent_of(ns, p);
        if !will_be_unmounted(ns, p) {
            break mp;
        }
    };
    let (to, m) = (get(ns, p), get(ns, m));
    super::mount::change_mountpoint(ns, &to, mp, &m);
}

/// Add to `set` (mounts an umount takes, each off its parent's list
/// and marked MNT_UMOUNT) every mount receiving propagation from one
/// of them that can go with no obstacle (Linux propagate_umount; see
/// Linux Documentation/filesystems/propagate_umount.txt): the
/// candidates are gathered, reduced until nothing shifts and nothing
/// locked is revealed, and a mount that stays on the root of one that
/// goes slides down. Under NAMESPACE_SEM write.
pub(super) fn propagate_umount(ns: &mut NsTree, set: &mut UmountList) {
    let mut to_umount = UmountList::new();
    let mut candidates = UmountList::new();
    gather_candidates(ns, set, &mut candidates);
    // Reduce the set until it's non-shifting
    let mut cur = candidates.first().map(core::ptr::from_ref);
    while let Some(c) = cur {
        let next = candidates.next_ref(mnt(ns, c)).map(core::ptr::from_ref);
        trim_one(ns, c, &mut candidates, &mut to_umount);
        cur = next;
    }
    // ... and non-revealing
    while let Some(m) = candidates.first().map(core::ptr::from_ref) {
        handle_locked(ns, m, &mut candidates, &mut to_umount);
    }
    // A surviving overmount of one that goes slides down
    let mut cur = to_umount.first().map(core::ptr::from_ref);
    while let Some(m) = cur {
        let over = mnt(ns, m).overmount_in(ns);
        if !over.is_null() && !will_be_unmounted(ns, over) {
            reparent(ns, over);
        }
        cur = to_umount.next_ref(mnt(ns, m)).map(core::ptr::from_ref);
    }
    while let Some(e) = to_umount.pop_front() {
        set.push_back(e);
    }
}

/// Linux trace_transfers: `m` and the peers or masters it would hand
/// its slaves to that also go leave propagation, marked; the mount the
/// slaves end up with
fn trace_transfers(ns: &mut NsTree, m: *const Mount) -> *const Mount {
    let mut m = m;
    loop {
        let mut next = next_peer(ns, m);
        if next != m {
            share_del_init(ns, m);
            let l = links_mut(ns, m);
            l.group_id = 0;
            l.master = next;
        } else {
            if links(ns, m).group_id != 0 {
                release_group_id(ns, m);
            }
            next = master(ns, m);
        }
        slave_del_init(ns, m);
        set_mark(ns, m, true);
        if next.is_null() || !will_be_unmounted(ns, next) {
            return next;
        }
        if is_marked(ns, next) {
            return master(ns, next);
        }
        m = next;
    }
}

/// Linux set_destinations: every mount on `m`'s master chain up to
/// `master` hands its slaves to `master`
fn set_destinations(ns: &mut NsTree, m: *const Mount, to: *const Mount) {
    let mut m = m;
    loop {
        let next = master(ns, m);
        if next == to {
            return;
        }
        links_mut(ns, m).master = to;
        m = next;
    }
}

/// Every mount in `set` leaves propagation, its slaves going to the
/// nearest peer or master that stays (Linux bulk_make_private)
pub(super) fn bulk_make_private(ns: &mut NsTree, set: &UmountList) {
    for m in set.iter() {
        let m = core::ptr::from_ref(m);
        if !is_marked(ns, m) {
            let to = trace_transfers(ns, m);
            set_destinations(ns, m, to);
        }
    }
    for m in set.iter() {
        let m = core::ptr::from_ref(m);
        let to = master(ns, m);
        transfer_propagation(ns, m, to);
        let l = links_mut(ns, m);
        l.master = null();
        l.marked = false;
    }
}

/// A peer of `mnt` in namespace `ns_id` that the reader's `root`
/// reaches (Linux get_peer_under_root)
fn get_peer_under_root(
    ns: &NsTree,
    mnt: *const Mount,
    ns_id: u64,
    root: &Path,
) -> Option<*const Mount> {
    let mut m = mnt;
    loop {
        // The namespace first, it is cheap
        if self::mnt(ns, m).ns() == ns_id
            && is_path_reachable(&Path::new(get(ns, m), self::mnt(ns, m).root.clone()), root)
        {
            return Some(m);
        }
        m = next_peer(ns, m);
        if m == mnt {
            return None;
        }
    }
}

/// The id of the closest dominating peer group with a member under
/// `root` (Linux get_dominating_id), 0 if none
fn get_dominating_id(ns: &NsTree, mnt: &Mount, root: &Path) -> u32 {
    let mut m = master(ns, mnt);
    while !m.is_null() {
        if let Some(d) = get_peer_under_root(ns, m, mnt.ns(), root) {
            return links(ns, d).group_id;
        }
        m = master(ns, m);
    }
    0
}

/// The mountinfo optional fields of `m` for a reader rooted at `root`
/// (Linux show_mountinfo): shared:N, master:N, propagate_from:N,
/// unbindable
pub fn optional_fields(ns: &NsTree, m: &Mount, root: &Path) -> Vec<u8> {
    use alloc::fmt::Write;
    let mut s = alloc::string::String::new();
    let l = m.prop.access(ns);
    if l.group_id != 0 {
        let _ = write!(s, " shared:{}", l.group_id);
    }
    if !l.master.is_null() {
        let master = links(ns, l.master).group_id;
        let dom = get_dominating_id(ns, m, root);
        let _ = write!(s, " master:{}", master);
        if dom != 0 && dom != master {
            let _ = write!(s, " propagate_from:{}", dom);
        }
    }
    if m.is_unbindable() {
        s.push_str(" unbindable");
    }
    s.into_bytes()
}

/// A mount being torn down leaves propagation if it is still in it:
/// it never is (umount and a namespace's end make every mount private
/// first), but a link left to freed memory would be unsound
pub fn teardown_prop(m: &Mount) {
    let linked = m.prop.access(&super::mount::namespace_read()).linked();
    if linked {
        let mut ns = super::mount::namespace_lock();
        change_mnt_propagation(&mut ns, m, Prop::Private);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::mount::{namespace_lock, test_mnt};

    /// Peer rings and slave lists as Linux keeps them: a peer leaving
    /// keeps the group, the last one frees it and hands its slaves to
    /// its own master
    #[test]
    fn peers_and_slaves() {
        let mut ns = namespace_lock();
        let (a, b, s) = (test_mnt(), test_mnt(), test_mnt());
        let (pa, pb, ps) = (
            MountRef::as_ptr(&a),
            MountRef::as_ptr(&b),
            MountRef::as_ptr(&s),
        );
        alloc_group_id(&mut ns, pa).unwrap();
        links_mut(&mut ns, pb).group_id = links(&ns, pa).group_id;
        share_add(&mut ns, pb, pa);
        assert!(peers(&ns, pa, pb));
        assert_eq!(next_peer(&ns, pa), pb);
        assert_eq!(next_peer(&ns, pb), pa);
        // s: a slave of the group, through a
        links_mut(&mut ns, ps).master = pa;
        slave_add_head(&mut ns, ps, pa);
        change_mnt_propagation(&mut ns, &a, Prop::Private);
        assert_eq!(group_id(&ns, &a), 0);
        assert!(is_shared(&ns, &b) && next_peer(&ns, pb) == pb);
        // a's slaves went to its peer
        assert_eq!(master(&ns, ps), pb);
        assert_eq!(links(&ns, pb).slave_first, ps);
        change_mnt_propagation(&mut ns, &b, Prop::Private);
        assert_eq!(master(&ns, ps), null());
        assert!(links(&ns, pb).slave_first.is_null());
        assert!(!links(&ns, pa).linked() && !links(&ns, pb).linked());
        assert!(!links(&ns, ps).linked());
    }

    /// A slave made shared then slave again keeps its master; one with
    /// peers becomes their slave
    #[test]
    fn make_slave() {
        let mut ns = namespace_lock();
        let (a, b) = (test_mnt(), test_mnt());
        let (pa, pb) = (MountRef::as_ptr(&a), MountRef::as_ptr(&b));
        alloc_group_id(&mut ns, pa).unwrap();
        clone_links(&mut ns, &a, &b, 0);
        assert!(peers(&ns, pa, pb));
        change_mnt_propagation(&mut ns, &b, Prop::Slave);
        assert_eq!(master(&ns, pb), pa);
        assert_eq!(group_id(&ns, &b), 0);
        change_mnt_propagation(&mut ns, &a, Prop::Private);
        change_mnt_propagation(&mut ns, &b, Prop::Private);
        assert!(!links(&ns, pa).linked() && !links(&ns, pb).linked());
    }
}
