//! /proc/<pid>/mounts and /proc/<pid>/mountinfo (Linux
//! fs/proc_namespace.c): the mounts of the process's namespace that its
//! root reaches, by mount order (mnt_id_unique), with every name field
//! escaped so a name cannot split or forge a line

use alloc::vec::Vec;

use super::super::Path;
use super::super::dentry::{d_path, dentry_path};
use super::super::mount::{
    MNT_NOATIME, MNT_NODEV, MNT_NODIRATIME, MNT_NOEXEC, MNT_NOSUID, MNT_NOSYMFOLLOW, MNT_READONLY,
    MNT_RELATIME, Mount, MountRef, NsTree, namespace_read, walk,
};
use super::super::name::mangle;
use crate::task::percpu::TaskRef;

/// mangle's set: space, tab, newline, backslash (Linux seq_escape)
const ESC: &[u8] = b" \t\n\\";
/// For source and type, '#' too (Linux mangle in proc_namespace.c)
const ESC_HASH: &[u8] = b" \t\n\\#";

/// Typical line lengths, to size a whole file in one allocation (a
/// longer line only grows the buffer)
const MOUNTS_LINE: usize = 96;
const MOUNTINFO_LINE: usize = 128;

/// The mounts task `t` sees: (mount, mountpoint as seen from its root),
/// by mount order; a mount its root does not reach is left out. `show`
/// formats them under NAMESPACE_SEM read (Linux m_start .. m_stop), so
/// no umount runs meanwhile and the references held here make no mount
/// busy for one.
fn with_visible(t: &TaskRef, show: impl FnOnce(&Vis<'_>) -> Vec<u8>) -> Vec<u8> {
    let (Some(ns), Some(fs)) = (super::task_nsproxy(t), crate::fs::get_task_fs(t)) else {
        return Vec::new();
    };
    let root = fs.get_root();
    let g = namespace_read();
    let Some(top) = ns.mnt_ns.get_root() else {
        return Vec::new();
    };
    let mut all: Vec<MountRef> = walk(&top, &*g).collect();
    all.sort_by_key(|m| m.mnt_id_unique);
    let vis: Vec<(MountRef, Vec<u8>)> = all
        .into_iter()
        .filter_map(|m| {
            let (mp, reached) = d_path(&Path::new(m.clone(), m.root.clone()), &root);
            reached.then_some((m, mp))
        })
        .collect();
    let out = show(&Vis {
        mnts: &vis,
        ns: &g,
        root: &root,
    });
    drop(vis);
    drop(top);
    drop(g);
    out
}

/// What a mount list shows: the mounts with their mountpoints, under
/// NAMESPACE_SEM read, for a reader rooted at `root`
struct Vis<'a> {
    mnts: &'a [(MountRef, Vec<u8>)],
    ns: &'a NsTree,
    root: &'a Path,
}

/// The superblock's options after rw/ro (Linux show_sb_opts)
fn sb_opts(out: &mut Vec<u8>, m: &Mount) {
    use super::super::superblock::{SB_DIRSYNC, SB_SYNCHRONOUS};
    let f = m.sb.flags();
    for (bit, name) in [(SB_SYNCHRONOUS, &b",sync"[..]), (SB_DIRSYNC, b",dirsync")] {
        if f & bit != 0 {
            out.extend_from_slice(name);
        }
    }
}

/// The per-mount options after rw/ro (Linux show_mnt_opts)
fn mnt_opts(out: &mut Vec<u8>, m: &Mount) {
    let f = m.flags();
    for (bit, name) in [
        (MNT_NOSUID, &b",nosuid"[..]),
        (MNT_NODEV, b",nodev"),
        (MNT_NOEXEC, b",noexec"),
        (MNT_NOATIME, b",noatime"),
        (MNT_NODIRATIME, b",nodiratime"),
        (MNT_RELATIME, b",relatime"),
        (MNT_NOSYMFOLLOW, b",nosymfollow"),
    ] {
        if f & bit != 0 {
            out.extend_from_slice(name);
        }
    }
}

/// /proc/<pid>/mounts (Linux show_vfsmnt): source mountpoint type
/// options 0 0
pub fn show_mounts(t: &TaskRef) -> Vec<u8> {
    with_visible(t, show_mounts_of)
}

fn show_mounts_of(vis: &Vis<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(vis.mnts.len() * MOUNTS_LINE);
    for (m, mp) in vis.mnts {
        mangle(&mut out, &m.devname, ESC_HASH);
        out.push(b' ');
        mangle(&mut out, mp, ESC);
        out.push(b' ');
        mangle(&mut out, m.sb.fs_type.name.as_bytes(), ESC_HASH);
        out.push(b' ');
        // Read-only through the mount or its superblock (Linux
        // __mnt_is_readonly)
        out.extend_from_slice(if m.is_readonly() { b"ro" } else { b"rw" });
        sb_opts(&mut out, m);
        mnt_opts(&mut out, m);
        m.sb.s_op.show_options(&m.sb, &mut out);
        out.extend_from_slice(b" 0 0\n");
    }
    out
}

/// /proc/<pid>/mountinfo (Linux show_mountinfo): id parent major:minor
/// root mountpoint options [optional fields] - type source super-options
pub fn show_mountinfo(t: &TaskRef) -> Vec<u8> {
    with_visible(t, show_mountinfo_of)
}

fn show_mountinfo_of(vis: &Vis<'_>) -> Vec<u8> {
    use alloc::fmt::Write;
    let mut out = Vec::with_capacity(vis.mnts.len() * MOUNTINFO_LINE);
    for (m, mp) in vis.mnts.iter().cloned() {
        // The namespace root's parent is itself (Linux: its mnt_parent)
        let parent = m.get_parent().map_or(m.mnt_id, |p| p.mnt_id);
        let dev = m.sb.dev_id;
        let mut head = alloc::string::String::new();
        let _ = write!(
            head,
            "{} {} {}:{} ",
            m.mnt_id,
            parent,
            (dev >> 8) & 0xfff,
            dev & 0xff
        );
        out.extend_from_slice(head.as_bytes());
        mangle(&mut out, &dentry_path(&m.root).unwrap_or_default(), ESC);
        out.push(b' ');
        mangle(&mut out, &mp, ESC);
        out.push(b' ');
        // The mount's own read-only flag (Linux show_mountinfo)
        out.extend_from_slice(if m.flags() & MNT_READONLY != 0 {
            b"ro"
        } else {
            b"rw"
        });
        mnt_opts(&mut out, &m);
        out.extend_from_slice(&super::super::pnode::optional_fields(vis.ns, &m, vis.root));
        out.extend_from_slice(b" - ");
        mangle(&mut out, m.sb.fs_type.name.as_bytes(), ESC_HASH);
        out.push(b' ');
        mangle(&mut out, &m.devname, ESC_HASH);
        out.push(b' ');
        out.extend_from_slice(if m.sb.rdonly() { b"ro" } else { b"rw" });
        sb_opts(&mut out, &m);
        m.sb.s_op.show_options(&m.sb, &mut out);
        out.push(b'\n');
    }
    out
}
