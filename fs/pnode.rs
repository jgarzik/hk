//! Mount propagation (Linux fs/pnode.c): peer groups and slaves
//!
//! A shared mount belongs to a peer group (`Mount::group`, an id from
//! 1); a slave mount receives from a master group (`Mount::master`).
//! Linux points a slave at one master mount, but propagation always
//! covers the master's whole peer group, so the group is the master
//! here. A mount attached under a shared mount is copied to every peer
//! and, as slaves, down the slave groups; an umount takes the copies
//! that hold nothing with it. Changes run under `mount::NAMESPACE_SEM`
//! (write); `GROUPS` (a sleeping `Mutex`, inside NAMESPACE_SEM; Linux
//! keeps the mnt_share rings under namespace_sem itself) is never held
//! across a call into the mount tree.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::dentry::Dentry;
use super::mount::{Mount, MountRef, NsTree, attach_mnt, clone_mnt, commit_tree, copy_below, walk};
use super::path_ref::Path;

/// A peer group: its members, and the mounts it is master of
#[derive(Default)]
struct Group {
    members: Vec<Weak<Mount>>,
    slaves: Vec<Weak<Mount>>,
    /// Has had a member or slave: only such a group, now without any,
    /// is free again (a fresh one waits for the copies it was made for)
    used: bool,
}

/// Peer groups by id (Linux mnt_group_ida plus the mnt_share rings)
static GROUPS: crate::sync::Mutex<BTreeMap<u32, Group>> = crate::sync::Mutex::new(BTreeMap::new());

/// The propagation type of a mount (Linux MS_SHARED and friends)
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Prop {
    Shared,
    Slave,
    Private,
    Unbindable,
}

fn live(v: &mut Vec<Weak<Mount>>) -> Vec<MountRef> {
    v.retain(MountRef::is_live);
    v.iter().filter_map(MountRef::try_get).collect()
}

/// The lowest free group id: a used one with no live member and no
/// live slave is free again
fn alloc_group() -> u32 {
    let mut g = GROUPS.lock();
    g.retain(|_, grp| {
        live(&mut grp.members);
        live(&mut grp.slaves);
        !grp.used || !grp.members.is_empty() || !grp.slaves.is_empty()
    });
    let id = (1..).find(|i| !g.contains_key(i)).unwrap_or(u32::MAX);
    g.insert(id, Group::default());
    id
}

/// Live members of group `gid`
pub fn peers(gid: u32) -> Vec<MountRef> {
    GROUPS
        .lock()
        .get_mut(&gid)
        .map_or_else(Vec::new, |g| live(&mut g.members))
}

/// Live slaves of group `gid`
fn slaves(gid: u32) -> Vec<MountRef> {
    GROUPS
        .lock()
        .get_mut(&gid)
        .map_or_else(Vec::new, |g| live(&mut g.slaves))
}

/// Put `m` in group `gid` (0: none)
fn join(m: &MountRef, gid: u32) {
    let old = m.group.swap(gid, Ordering::SeqCst);
    let mut g = GROUPS.lock();
    if let Some(grp) = g.get_mut(&old) {
        grp.members
            .retain(|w| !core::ptr::eq(w.as_ptr(), MountRef::as_ptr(m)));
    }
    if gid != 0 {
        let grp = g.entry(gid).or_default();
        grp.members.push(MountRef::downgrade(m));
        grp.used = true;
    }
}

/// Make `m` a slave of group `gid` (0: of none)
fn set_master(m: &MountRef, gid: u32) {
    let old = m.master.swap(gid, Ordering::SeqCst);
    let mut g = GROUPS.lock();
    if let Some(grp) = g.get_mut(&old) {
        grp.slaves
            .retain(|w| !core::ptr::eq(w.as_ptr(), MountRef::as_ptr(m)));
    }
    if gid != 0 {
        let grp = g.entry(gid).or_default();
        grp.slaves.push(MountRef::downgrade(m));
        grp.used = true;
    }
}

/// `copy` takes `orig`'s place in propagation: a peer of its group and
/// a slave of its master (Linux clone_mnt without CL_PRIVATE)
pub fn clone_prop(orig: &Mount, copy: &MountRef) {
    let (g, m) = (
        orig.group.load(Ordering::SeqCst),
        orig.master.load(Ordering::SeqCst),
    );
    if g != 0 {
        join(copy, g);
    }
    if m != 0 {
        set_master(copy, m);
    }
}

/// Every mount of the tree at `m` gets a peer group if it has none
/// (Linux invent_group_ids before attaching under a shared mount)
pub fn invent_groups(ns: &NsTree, m: &MountRef) {
    for t in walk(m, ns) {
        if t.group.load(Ordering::SeqCst) == 0 {
            join(&t, alloc_group());
        }
    }
}

/// Linux do_make_slave: a mount with peers leaves them and becomes
/// their slave; the last peer of a group hands the group's slaves to
/// its own master (or frees them) and the group ends
fn make_slave(m: &MountRef) {
    let g = m.group.load(Ordering::SeqCst);
    if g == 0 {
        return;
    }
    let others = peers(g).into_iter().any(|p| !MountRef::ptr_eq(&p, m));
    join(m, 0);
    if others {
        set_master(m, g);
        return;
    }
    let master = m.master.load(Ordering::SeqCst);
    for s in slaves(g) {
        set_master(&s, master);
    }
    GROUPS.lock().remove(&g);
}

/// Linux change_mnt_propagation
pub fn change_propagation(m: &MountRef, p: Prop) {
    if p == Prop::Shared {
        // Shared ends unbindable (Linux set_mnt_shared: T_SHARED_MASK)
        m.set_unbindable(false);
        if m.group.load(Ordering::SeqCst) == 0 {
            join(m, alloc_group());
        }
        return;
    }
    make_slave(m);
    if p != Prop::Slave {
        set_master(m, 0);
        m.set_unbindable(p == Prop::Unbindable);
    }
}

/// Copies of the tree at `src`, set up for propagation by `prop(orig,
/// copy)`, with the same shape (Linux copy_tree for propagate_one)
fn copy_prop(ns: &mut NsTree, src: &MountRef, prop: &dyn Fn(&Mount, &MountRef)) -> MountRef {
    let top = clone_mnt(src, src.root.clone());
    prop(src, &top);
    copy_below(ns, src, &top, |k| {
        let n = clone_mnt(k, k.root.clone());
        prop(k, &n);
        // A submount keeps hiding what is under it (Linux copy_tree)
        if k.flags() & super::mount::MNT_LOCKED != 0 {
            n.mark(super::mount::MNT_LOCKED, true);
        }
        n
    });
    top
}

/// `d` is inside what `m` shows
fn visible(m: &Mount, d: &Arc<Dentry>) -> bool {
    super::is_subdir(d, &m.root)
}

/// The tree at `src` was attached at `d` under the shared mount
/// `dest`: copy it to every peer of `dest` (as peers) and down the
/// slave groups (as slaves; among shared slaves, as a new peer group)
/// (Linux propagate_mnt)
pub fn propagate_mnt(ns: &mut NsTree, dest: &MountRef, d: &Arc<Dentry>, src: &MountRef) {
    let g = dest.group.load(Ordering::SeqCst);
    if g == 0 {
        return;
    }
    for p in peers(g) {
        if !MountRef::ptr_eq(&p, dest) && visible(&p, d) {
            let c = copy_prop(ns, src, &|o, c| clone_prop(o, c));
            attach_mnt(ns, c.clone(), &Path::new(p, d.clone()));
            commit_tree(ns, &c);
        }
    }
    let up: BTreeMap<usize, u32> = walk(src, &*ns)
        .map(|m| {
            (
                MountRef::as_ptr(&m) as usize,
                m.group.load(Ordering::SeqCst),
            )
        })
        .collect();
    to_slaves(ns, g, d, src, &up);
}

/// Copies for the slaves of group `g`; `up` maps each mount of the
/// source tree to the group its copies here are slaves of
fn to_slaves(ns: &mut NsTree, g: u32, d: &Arc<Dentry>, src: &MountRef, up: &BTreeMap<usize, u32>) {
    let mut seen = BTreeSet::new();
    for s in slaves(g) {
        let sg = s.group.load(Ordering::SeqCst);
        if sg != 0 && !seen.insert(sg) {
            continue;
        }
        let set = if sg != 0 { peers(sg) } else { alloc::vec![s] };
        // Copies among shared slaves are peers of one another: a group
        // per source mount, made with its first copy
        let new = core::cell::RefCell::new(BTreeMap::<usize, u32>::new());
        for m in set.iter().filter(|m| visible(m, d)) {
            let c = copy_prop(ns, src, &|o, c| {
                let k = core::ptr::from_ref::<Mount>(o) as usize;
                set_master(c, up.get(&k).copied().unwrap_or(0));
                if sg != 0 {
                    let ng = *new.borrow_mut().entry(k).or_insert_with(alloc_group);
                    join(c, ng);
                }
            });
            attach_mnt(ns, c.clone(), &Path::new(m.clone(), d.clone()));
            commit_tree(ns, &c);
        }
        let new = new.into_inner();
        if !new.is_empty() {
            to_slaves(ns, sg, d, src, &new);
        }
    }
}

/// Every mount events in group `g` reach: its members and, down the
/// slave groups, theirs
fn reach(g: u32) -> Vec<MountRef> {
    let mut out = peers(g);
    let mut seen = BTreeSet::from([g]);
    let mut todo = alloc::vec![g];
    while let Some(x) = todo.pop() {
        for s in slaves(x) {
            let sg = s.group.load(Ordering::SeqCst);
            if sg == 0 {
                out.push(s);
            } else if seen.insert(sg) {
                out.extend(peers(sg));
                todo.push(sg);
            }
        }
    }
    out
}

/// The propagated copies an umount of `m` takes along: under every
/// mount its parent's events reach, the mount of `m`'s filesystem at
/// the same place, unless something is mounted on it (Linux
/// propagate_umount: such a copy stays)
pub fn propagate_umount(ns: &NsTree, m: &MountRef) -> Vec<MountRef> {
    let (Some(parent), Some(mp)) = (m.get_parent(), m.get_mountpoint()) else {
        return Vec::new();
    };
    let g = parent.group.load(Ordering::SeqCst);
    if g == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for t in reach(g) {
        if MountRef::ptr_eq(&t, &parent) {
            continue;
        }
        out.extend(t.kids(ns).filter(|c| {
            !MountRef::ptr_eq(c, m)
                && Arc::ptr_eq(&*c.sb, &*m.sb)
                && c.get_mountpoint().is_some_and(|x| Arc::ptr_eq(&x, &mp))
                && !c.has_children(ns)
        }));
    }
    out
}

/// The mountinfo optional fields of `m` (Linux show_mountinfo):
/// shared:N, master:N, propagate_from:N (the nearest group up the
/// master chain with a member the reader sees, if not the master),
/// unbindable
pub fn optional_fields(m: &Mount, visible_peer: &dyn Fn(u32) -> bool) -> Vec<u8> {
    use alloc::fmt::Write;
    let mut s = alloc::string::String::new();
    let g = m.group.load(Ordering::SeqCst);
    let master = m.master.load(Ordering::SeqCst);
    if g != 0 {
        let _ = write!(s, " shared:{}", g);
    }
    if master != 0 {
        let _ = write!(s, " master:{}", master);
        if let Some(dom) = dominating(master, visible_peer)
            && dom != master
        {
            let _ = write!(s, " propagate_from:{}", dom);
        }
    }
    if m.is_unbindable() {
        s.push_str(" unbindable");
    }
    s.into_bytes()
}

/// The first group up the master chain from `gid` with a member the
/// reader sees (Linux get_dominating_id)
fn dominating(gid: u32, visible_peer: &dyn Fn(u32) -> bool) -> Option<u32> {
    let mut g = gid;
    let mut hops = 0;
    while g != 0 && hops < 64 {
        if visible_peer(g) {
            return Some(g);
        }
        g = peers(g)
            .first()
            .map_or(0, |p| p.master.load(Ordering::SeqCst));
        hops += 1;
    }
    None
}
