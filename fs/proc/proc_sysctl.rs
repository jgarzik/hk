//! /proc/sys/net (Linux fs/proc/proc_sysctl.c with net/sysctl_net.c's
//! net_sysctl_root)
//!
//! The global sysctls are procfs's static tree (`build_sys`). The
//! network ones are per namespace: the root /proc/sys/net holds links
//! (Linux insert_links: an S_IFLNK entry for each directory a namespace
//! registered, its data net_sysctl_root), and a lookup of one follows
//! it into the looking-up task's namespace (sysctl_follow_link ->
//! net_ctl_header_lookup: current->nsproxy->net_ns->sysctls). What is
//! found there is bound to that namespace (the inode's header): its
//! files act on it whoever reads them, and a lookup below it stays in
//! it. A cached dentry of a namespace's tree matches only lookups by a
//! task of that namespace (proc_sys_compare -> sysctl_is_seen), so each
//! namespace walking /proc/sys/net finds its own, and an fd keeps the
//! one it was opened on.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use super::{ProcfsInodeData, create_dir_inode, create_file_inode};
use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{DirContext, DirEntry, File};
use crate::fs::inode::{FileType, Inode, InodeMode, InodeRef};
use crate::net::sysctl::{NetCtl, all, registered};
use crate::net::{NetNamespace, NetRef};
use crate::sysctl::Entry;

/// The network namespace a /proc/sys/net directory is of (Linux its
/// ctl_dir's set, net->sysctls): weak, as `sysctl::Entry`, and its id
#[derive(Clone)]
pub struct NetDir {
    net: Weak<NetNamespace>,
    pub id: u64,
    set: Arc<crate::net::sysctl::SysctlSet>,
}

impl NetDir {
    fn of(net: &Arc<NetNamespace>) -> Self {
        Self {
            net: Arc::downgrade(net),
            id: net.id,
            set: net.sysctls.clone(),
        }
    }

    /// In use, or ENOENT once the namespace is going (Linux
    /// sysctl_head_grab on an unregistering header)
    fn grab(&self) -> Result<NetRef, KernelError> {
        if self.unregistering() {
            return Err(KernelError::NotFound);
        }
        self.net
            .upgrade()
            .and_then(|n| n.maybe_get())
            .ok_or(KernelError::NotFound)
    }

    /// The namespace's teardown started (Linux head->unregistering):
    /// a flag read, no reference taken
    pub fn unregistering(&self) -> bool {
        self.set.unregistering()
    }
}

/// An entry of a sysctl directory
#[derive(Clone, Copy)]
enum Child {
    File(&'static NetCtl),
    /// A subdirectory, by its path below /proc/sys
    Dir(&'static str),
}

/// The entries of directory `dir` ("net", "net/ipv4") among `ctls`,
/// by name in name order (Linux a ctl_dir's rb-tree, namecmp)
fn children(
    ctls: impl Iterator<Item = &'static NetCtl>,
    dir: &str,
) -> BTreeMap<&'static str, Child> {
    let mut m = BTreeMap::new();
    for c in ctls {
        let Some(rest) = c.path.strip_prefix(dir).and_then(|r| r.strip_prefix('/')) else {
            continue;
        };
        let child = match rest.split_once('/') {
            Some((name, _)) => (name, Child::Dir(&c.path[..dir.len() + 1 + name.len()])),
            None => (rest, Child::File(c)),
        };
        m.entry(child.0).or_insert(child.1);
    }
    m
}

/// The current task's network namespace, its id (Linux
/// current->nsproxy->net_ns), with no reference taken
fn current_net_id() -> u64 {
    crate::task::percpu::current()
        .nsproxy()
        .map_or_else(|| crate::net::INIT_NET_NS.id, |p| p.net_ns.id)
}

/// The child `name` of the sysctl directory `parent` (path `dir`, of
/// namespace `net`, None for the root set's /proc/sys/net) (Linux
/// proc_sys_lookup: lookup_entry, sysctl_follow_link for a link)
pub(super) fn lookup(
    parent: &Inode,
    dir: &'static str,
    net: Option<&NetDir>,
    name: &str,
) -> Result<InodeRef, KernelError> {
    let (net, nd) = match net {
        // A link: the directory of that name in the current task's
        // namespace (sysctl_follow_link: ENOENT if it has none)
        None => {
            if !matches!(children(all(), dir).get(name), Some(Child::Dir(_))) {
                return Err(KernelError::NotFound);
            }
            let n = crate::net::current_net_ns();
            let nd = NetDir::of(n.passive());
            (n, nd)
        }
        Some(nd) => (nd.grab()?, nd.clone()),
    };
    let child = *children(registered(&net), dir)
        .get(name)
        .ok_or(KernelError::NotFound)?;
    make_inode(parent, &net, nd, child)
}

/// A new inode of `child` in namespace `net` (Linux
/// proc_sys_make_inode: a fresh number, owned by root of the
/// namespace's user namespace, net_ctl_set_ownership)
fn make_inode(
    parent: &Inode,
    net: &NetRef,
    nd: NetDir,
    child: Child,
) -> Result<InodeRef, KernelError> {
    let sb = parent.superblock().ok_or(KernelError::Io)?;
    let ino = sb.alloc_ino();
    let inode = match child {
        Child::File(ctl) => create_file_inode(
            parent,
            ino,
            InodeMode::regular(ctl.mode_in(net)),
            ProcfsInodeData::Sysctl {
                ctl: Entry::net(ctl, net.passive()),
            },
        )?,
        Child::Dir(path) => create_dir_inode(
            parent,
            ino,
            ProcfsInodeData::SysctlDir {
                dir: path,
                net: Some(nd),
            },
        )?,
    };
    if let Some(uid) = net.user_ns.to_kuid(0) {
        inode.set_uid(uid);
    }
    if let Some(gid) = net.user_ns.to_kgid(0) {
        inode.set_gid(gid);
    }
    Ok(inode)
}

/// The entries of the sysctl directory `inode` (path `dir`, namespace
/// `net` as for [`lookup`]) after "." and ".." (Linux
/// proc_sys_readdir: each through the dcache, proc_sys_fill_cache; a
/// link followed into the reader's namespace, skipped if it has none
/// there, proc_sys_link_fill_cache)
pub(super) fn readdir(
    file: &File,
    inode: &Inode,
    dir: &'static str,
    net: Option<&NetDir>,
    ctx: &mut DirContext<'_>,
) -> Result<(), KernelError> {
    let names: Vec<&'static str> = match net {
        None => children(all(), dir).into_keys().collect(),
        Some(nd) => children(registered(&*nd.grab()?), dir)
            .into_keys()
            .collect(),
    };
    for name in names {
        let Some((ino, file_type)) = fill_cache(file, inode, dir, net, name)? else {
            continue;
        };
        let e = DirEntry {
            ino,
            file_type,
            name: Vec::from(name.as_bytes()),
        };
        if !ctx.emit(e) {
            break;
        }
    }
    Ok(())
}

/// The dentry of `name` in the directory `file` reads, made if not
/// cached (Linux proc_sys_fill_cache: d_lookup, else d_alloc_parallel
/// and proc_sys_make_inode): its inode number and type; None if it
/// cannot be found (a link the reader's namespace lacks)
fn fill_cache(
    file: &File,
    inode: &Inode,
    dir: &'static str,
    net: Option<&NetDir>,
    name: &'static str,
) -> Result<Option<(u64, FileType)>, KernelError> {
    let parent = &file.dentry;
    let child = match parent.lookup_child(name.as_bytes()) {
        Some(c) if !c.is_negative() => c,
        _ => {
            let Ok(i) = lookup(inode, dir, net, name) else {
                return Ok(None);
            };
            let d = Dentry::prealloc(parent, name.as_bytes())?;
            Dentry::add(parent, d, Some(i))
        }
    };
    Ok(child.get_inode().map(|i| {
        let t = i.mode().file_type().unwrap_or(FileType::Regular);
        (i.ino, t)
    }))
}

/// procfs's d_compare: a cached child of a namespace's sysctl tree is
/// the one a lookup wants only when the looking-up task is in that
/// namespace (Linux proc_sys_compare: sysctl_is_seen, net's is_seen);
/// a negative one never (proc_sys_compare: no inode, 1; procfs keeps
/// none, `delete`); the rest by their bytes
pub(super) fn compare(c: &Dentry, stored: &[u8], name: &[u8]) -> bool {
    if stored != name {
        return false;
    }
    let g = crate::sync::rcu::read_lock();
    let Some(inode) = c.d_inode_rcu(&g) else {
        return false;
    };
    let net = super::proc_rcu(inode).and_then(|r| r.net);
    net.is_none_or(|id| id == current_net_id())
}
