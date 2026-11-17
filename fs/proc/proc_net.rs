//! /proc/<pid>/net and /proc/<pid>/task/<tid>/net (Linux
//! fs/proc/proc_net.c)
//!
//! Each shows the network namespace of the task whose directory it is
//! (Linux get_proc_task_net: the task's nsproxy, under task_lock);
//! /proc/net is the link "self/net". A file found there is bound to
//! that namespace (Linux: a proc_dir_entry of net->proc_net) and never
//! stays cached (proc_net_d_revalidate: 0), so a walk after a setns
//! finds the new one; an open pins the namespace while it is alive
//! (get_proc_net: maybe_get_net, else ENXIO) and every read generates
//! from it.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{ProcPid, ProcfsInodeData, create_file_inode, pid_ino, task_nsproxy};
use crate::fs::KernelError;
use crate::fs::file::{DirContext, DirEntry};
use crate::fs::inode::{FileType, Inode, InodeMode, InodeRef};
use crate::net::NetNamespace;
use crate::task::percpu::TaskRef;

/// A /proc/<pid>/net file's content for a namespace
pub type NetGen = fn(&NetNamespace) -> Vec<u8>;

/// The files of a /proc/<pid>/net directory (Linux: what the protocols
/// register in net->proc_net), read-only
const NET_FILES: [(&str, NetGen); 10] = [
    ("arp", crate::net::arp::proc_net_arp),
    ("dev", crate::net::proc::proc_net_dev),
    ("netstat", crate::net::proc::proc_net_netstat),
    ("packet", crate::net::packet::proc_net_packet),
    ("route", crate::net::proc::proc_net_route),
    ("snmp", crate::net::proc::proc_net_snmp),
    ("sockstat", crate::net::proc::proc_net_sockstat),
    ("tcp", crate::net::tcp::info::proc_net_tcp),
    ("udp", crate::net::udp::proc_net_udp),
    ("unix", crate::net::unix::proc_net_unix),
];

/// Inode offset of /proc/<pid>/net, and its files' base
pub(super) const NET_DIR_INO: u64 = 130;
const NET_FILE_INO: u64 = 131;

/// Task `t`'s network namespace (Linux get_proc_task_net: none once it
/// has dropped its nsproxy on exit)
fn task_net(t: &TaskRef) -> Option<Arc<NetNamespace>> {
    task_nsproxy(t).map(|ns| Arc::clone(ns.net_ns.passive()))
}

/// Look `name` up in the /proc/<pid>/net directory `dir` of `p`
/// (Linux proc_tgid_net_lookup)
pub(super) fn lookup(dir: &Inode, p: &ProcPid, name: &str) -> Result<InodeRef, KernelError> {
    let t = p.task().ok_or(KernelError::NotFound)?;
    let net = task_net(&t).ok_or(KernelError::NotFound)?;
    let (i, &(_, generator)) = NET_FILES
        .iter()
        .enumerate()
        .find(|(_, (n, _))| *n == name)
        .ok_or(KernelError::NotFound)?;
    create_file_inode(
        dir,
        pid_ino(t.tid(), NET_FILE_INO + i as u64),
        InodeMode::regular(0o444),
        ProcfsInodeData::NetFile { net, generator },
    )
}

/// The entries of `t`'s /proc/<pid>/net (Linux proc_tgid_net_readdir:
/// EINVAL without a namespace)
pub(super) fn readdir(t: &TaskRef, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
    if task_net(t).is_none() {
        return Err(KernelError::InvalidArgument);
    }
    for (i, (name, _)) in NET_FILES.iter().enumerate() {
        let e = DirEntry {
            ino: pid_ino(t.tid(), NET_FILE_INO + i as u64),
            file_type: FileType::Regular,
            name: Vec::from(name.as_bytes()),
        };
        if !ctx.emit(e) {
            break;
        }
    }
    Ok(())
}
