//! nsfs, the namespace files (Linux fs/nsfs.c)
//!
//! A namespace's file is an inode on the nsfs mount numbered as the
//! namespace (its `NsCommon.inum`), holding a reference to it (Linux
//! i_private, put at evict), under a dentry outside any tree named
//! "<type>:[<inum>]". While that dentry lives it is stashed in the
//! namespace (`NsCommon.stashed`), so every open of a
//! /proc/<pid>/ns/<type> link gets the same dentry and inode (Linux
//! ns_get_path / path_from_stashed); its kill clears the stash
//! (`ns_prune_dentry`, Linux ns_prune_dentry / stashed_dentry_prune).
//! An open namespace file, or a bind mount of one, keeps the namespace
//! alive; setns(2) joins the namespace the file holds.
//!
//! Locking: the stash is a compare-exchange on an atomic pointer; a
//! reader takes its reference under an RCU read guard (Linux
//! lockref_get_not_dead), and the dentry's memory outlives its kill by
//! a grace period. The last reference to a namespace may go with the
//! inode, so a namespace file's dentry is put only where sleeping is
//! allowed (a file's release, a mount's teardown, a path put in a
//! syscall), as Linux dput.

use alloc::sync::Arc;
use core::ptr::null_mut;
use core::sync::atomic::Ordering;

use super::NSFS;
use crate::fs::dentry::{Dentry, DentryOps, DentryRef};
use crate::fs::file::{File, FileOps};
use crate::fs::inode::{AsAny, Inode, InodeData, InodeMode, NULL_INODE_OPS};
use crate::fs::path_ref::Path;
use crate::ns::{MntNamespace, Namespace, NsRef};
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;

/// The nsfs ioctls (Linux uapi nsfs.h: _IO(NSIO, n), _IOR(NSIO, n,
/// type))
const NS_GET_USERNS: u32 = 0xb701;
const NS_GET_PARENT: u32 = 0xb702;
const NS_GET_NSTYPE: u32 = 0xb703;
const NS_GET_OWNER_UID: u32 = 0xb704;
const NS_GET_MNTNS_ID: u32 = 0x8008_b705;
const NS_GET_PID_FROM_PIDNS: u32 = 0x8004_b706;
const NS_GET_TGID_FROM_PIDNS: u32 = 0x8004_b707;
const NS_GET_PID_IN_PIDNS: u32 = 0x8004_b708;
const NS_GET_TGID_IN_PIDNS: u32 = 0x8004_b709;
const NS_GET_ID: u32 = 0x8008_b70d;
/// The extensible ones, by number: _IOR with any size from
/// MNT_NS_INFO_SIZE_VER0 up (Linux extensible_ioctl_valid)
const NS_MNT_GET_INFO_NR: u32 = 10;
const NS_MNT_GET_NEXT_NR: u32 = 11;
const NS_MNT_GET_PREV_NR: u32 = 12;
/// struct mnt_ns_info's first published size
const MNT_NS_INFO_SIZE_VER0: usize = 16;

/// An extensible NSIO read ioctl numbered `nr` of at least
/// MNT_NS_INFO_SIZE_VER0 bytes: its size, None for another command
fn extensible(cmd: u32, nr: u32) -> Option<usize> {
    let size = ((cmd >> 16) & 0x3fff) as usize;
    let ok = cmd >> 30 == 2 && (cmd >> 8) & 0xff == 0xb7 && cmd & 0xff == nr;
    (ok && size >= MNT_NS_INFO_SIZE_VER0).then_some(size)
}

/// Copy struct mnt_ns_info for `m` to `to`, the first `usize` bytes the
/// caller knows of (Linux copy_ns_info_to_user): size, mounts but the
/// root, id
fn copy_ns_info(m: &crate::ns::MntNamespace, to: u64, usize: usize) -> Result<(), KernelError> {
    let size = usize.min(MNT_NS_INFO_SIZE_VER0);
    let nr = u32::try_from(m.nr_mounts().saturating_sub(1)).unwrap_or(u32::MAX);
    let mut b = [0u8; MNT_NS_INFO_SIZE_VER0];
    b[..4].copy_from_slice(&(size as u32).to_ne_bytes());
    b[4..8].copy_from_slice(&nr.to_ne_bytes());
    b[8..].copy_from_slice(&m.id().to_ne_bytes());
    crate::uaccess::copy_to_user(to, &b[..size]).map_err(|_| KernelError::BadAddress)?;
    Ok(())
}

/// A pid namespace ioctl (Linux ns_ioctl's NS_GET_{PID,TGID}_{FROM,IN}_
/// PIDNS): the task `arg` names in `ns` (FROM) or in the caller's pid
/// namespace (IN), and its thread or thread-group id in the caller's
/// namespace (FROM) or in `ns` (IN); ESRCH if there is none or it has
/// no number there
fn pidns_ioctl(ns: &NsRef, cmd: u32, arg: u64) -> Result<i64, KernelError> {
    use crate::task::percpu::{find_task_by_pid_ns, find_task_by_vpid};
    use crate::task::pid::{nr_ns, vnr};
    let NsRef::Pid(p) = ns else {
        return Err(KernelError::InvalidArgument);
    };
    // A pid_t argument
    let nr = u64::from(arg as u32);
    let from = matches!(cmd, NS_GET_PID_FROM_PIDNS | NS_GET_TGID_FROM_PIDNS);
    let t = if from {
        find_task_by_pid_ns(nr, p)
    } else {
        find_task_by_vpid(nr)
    }
    .ok_or(KernelError::NoProcess)?;
    let n = match cmd {
        NS_GET_PID_FROM_PIDNS => vnr(t.tid()),
        NS_GET_TGID_FROM_PIDNS => vnr(t.pid),
        NS_GET_PID_IN_PIDNS => nr_ns(t.tid(), p),
        _ => nr_ns(t.pid, p),
    };
    match n {
        0 => Err(KernelError::NoProcess),
        n => Ok(i64::from(n)),
    }
}

/// NS_MNT_GET_NEXT / NS_MNT_GET_PREV (Linux ns_ioctl): the mount
/// namespace after or before `m` in id order the caller may see, as a
/// new O_CLOEXEC descriptor, with its struct mnt_ns_info copied to
/// `to` first (EFAULT leaves no descriptor)
fn mnt_ns_adjoined_fd(
    m: &crate::ns::MntNamespace,
    previous: bool,
    to: u64,
    usize: usize,
) -> Result<i64, KernelError> {
    let next = crate::ns::mnt_ns_adjoined(m.id(), previous)?;
    let fd = crate::fs::io::get_unused_fd_flags(crate::task::FD_CLOEXEC)?;
    let file = ns_file(NsRef::Mnt(next.clone()))?;
    copy_ns_info(&next, to, usize)?;
    Ok(i64::from(fd.install(file)))
}

/// A namespace file's operations (Linux ns_file_operations): it opens,
/// has no read or write (EINVAL), and answers the NS_GET_* ioctls
pub struct NsFileOps;

impl FileOps for NsFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// Linux ns_ioctl: NS_GET_USERNS and NS_GET_PARENT give a new
    /// O_CLOEXEC descriptor of the owning user namespace or the parent
    /// (pid and user namespaces only, else EINVAL); NS_GET_NSTYPE its
    /// CLONE_NEW* type; NS_GET_OWNER_UID a user namespace's creator's
    /// uid as the caller's user namespace sees it; NS_GET_ID its id
    /// (NS_GET_MNTNS_ID: a mount namespace's only); the pid namespace
    /// translations; NS_MNT_GET_INFO a mount namespace's struct
    /// mnt_ns_info, NS_MNT_GET_NEXT/PREV the next or previous one
    /// (EPERM unless the caller may see all namespaces). ENOTTY
    /// otherwise.
    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let ns = file
            .get_inode()
            .and_then(|i| get_proc_ns(&i))
            .ok_or(KernelError::NotTty)?;
        let next = extensible(cmd, NS_MNT_GET_NEXT_NR);
        let prev = extensible(cmd, NS_MNT_GET_PREV_NR);
        if (next.is_some() || prev.is_some()) && !crate::ns::may_see_all_namespaces() {
            return Err(KernelError::NotPermitted);
        }
        if let Some(usize) = extensible(cmd, NS_MNT_GET_INFO_NR) {
            let NsRef::Mnt(m) = &ns else {
                return Err(KernelError::InvalidArgument);
            };
            if arg == 0 {
                return Err(KernelError::InvalidArgument);
            }
            copy_ns_info(m, arg, usize)?;
            return Ok(0);
        }
        if let Some(usize) = next.or(prev) {
            let NsRef::Mnt(m) = &ns else {
                return Err(KernelError::InvalidArgument);
            };
            return mnt_ns_adjoined_fd(m, prev.is_some(), arg, usize);
        }
        match cmd {
            NS_GET_USERNS => open_related_ns(ns_get_owner(&ns)?),
            NS_GET_PARENT => open_related_ns(match &ns {
                NsRef::User(_) => ns_get_owner(&ns)?,
                NsRef::Pid(p) => pidns_get_parent(p)?,
                _ => return Err(KernelError::InvalidArgument),
            }),
            NS_GET_NSTYPE => Ok(ns.ns_type() as i64),
            NS_GET_OWNER_UID => {
                let NsRef::User(u) = &ns else {
                    return Err(KernelError::InvalidArgument);
                };
                let uid = crate::ns::current_user_ns().from_kuid_munged(u.owner);
                crate::uaccess::put_user(arg, uid).map_err(|_| KernelError::BadAddress)?;
                Ok(0)
            }
            NS_GET_PID_FROM_PIDNS
            | NS_GET_TGID_FROM_PIDNS
            | NS_GET_PID_IN_PIDNS
            | NS_GET_TGID_IN_PIDNS => pidns_ioctl(&ns, cmd, arg),
            NS_GET_MNTNS_ID | NS_GET_ID => {
                if cmd == NS_GET_MNTNS_ID && !matches!(ns, NsRef::Mnt(_)) {
                    return Err(KernelError::InvalidArgument);
                }
                let id = ns.common().ns_id;
                crate::uaccess::put_user(arg, id).map_err(|_| KernelError::BadAddress)?;
                Ok(0)
            }
            _ => Err(KernelError::NotTty),
        }
    }
}

/// `ns`'s owning user namespace, if the caller's user namespace is it
/// or one of its ancestors (Linux ns_get_owner): EPERM if not, and for
/// the initial user namespace, which has none
fn ns_get_owner(ns: &NsRef) -> Result<NsRef, KernelError> {
    let mine = crate::ns::current_user_ns();
    let owner = ns.owner().ok_or(KernelError::NotPermitted)?;
    let mut p = Some(&owner);
    while let Some(u) = p {
        if Arc::ptr_eq(u, &mine) {
            return Ok(NsRef::User(owner.clone()));
        }
        p = u.parent.as_ref();
    }
    Err(KernelError::NotPermitted)
}

/// `ns`'s parent pid namespace, if the caller's pid namespace is it or
/// one of its ancestors (Linux pidns_get_parent): EPERM if not
fn pidns_get_parent(ns: &crate::ns::PidNamespace) -> Result<NsRef, KernelError> {
    let active = crate::task::pid::current_pid_ns();
    let parent = ns.parent.as_ref().ok_or(KernelError::NotPermitted)?;
    let mut p = Some(parent);
    while let Some(n) = p {
        if core::ptr::eq(Arc::as_ptr(n), active) {
            return Ok(NsRef::Pid(parent.clone()));
        }
        p = n.parent.as_ref();
    }
    Err(KernelError::NotPermitted)
}

/// A new O_CLOEXEC descriptor of `ns`'s file, opened read-only (Linux
/// open_related_ns)
fn open_related_ns(ns: NsRef) -> Result<i64, KernelError> {
    let fd = crate::fs::io::fd_install(ns_file(ns)?, crate::task::FD_CLOEXEC)?;
    Ok(i64::from(fd))
}

/// `ns`'s file opened read-only (Linux open_namespace_file)
fn ns_file(ns: NsRef) -> Result<crate::fs::FileRef, KernelError> {
    let path = ns_get_path(ns)?;
    let flags = crate::fs::flags::O_RDONLY;
    File::new(
        path.dentry.clone(),
        Some(path.mnt.clone()),
        flags,
        &NS_FILE_OPS,
    )
    .alloc()
}

pub static NS_FILE_OPS: NsFileOps = NsFileOps;

/// nsfs's dentry operations (Linux ns_dentry_operations): its names
/// are plain bytes; a dentry's kill clears its namespace's stash
pub static NS_DENTRY_OPS: DentryOps = DentryOps {
    d_hash: crate::fs::name::name_hash,
    d_compare: |a, b| a == b,
    d_prune: Some(ns_prune_dentry),
};

/// A namespace file inode's private data (Linux i_private): the
/// namespace, held until the inode goes, and an active reference to
/// it, taken as the inode is made (Linux nsfs_init_inode: one made for
/// an inactive namespace, as SIOCGSKNS's, brings it and its owners back
/// to life) and put as it goes (Linux nsfs_evict)
struct NsInode(NsRef);

impl NsInode {
    fn new(ns: NsRef) -> Self {
        ns.active_get();
        Self(ns)
    }
}

impl Drop for NsInode {
    fn drop(&mut self) {
        self.0.active_put();
    }
}

impl AsAny for NsInode {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for NsInode {}

/// The namespace an nsfs inode holds (Linux get_proc_ns), None for
/// any other inode
pub fn get_proc_ns(inode: &Inode) -> Option<NsRef> {
    let p = inode.get_private()?;
    p.as_any().downcast_ref::<NsInode>().map(|n| n.0.clone())
}

/// `file` is a namespace file (Linux proc_ns_file: its f_op)
pub fn proc_ns_file(file: &File) -> bool {
    file.f_op.as_any().is::<NsFileOps>()
}

/// `d` is an nsfs dentry (Linux d_op == &ns_dentry_operations)
fn is_ns_dentry(d: &Dentry) -> bool {
    d.superblock()
        .is_some_and(|sb| core::ptr::eq(sb.fs_type, NSFS.fs_type()))
}

/// The namespace an nsfs dentry's file holds, None for any other
/// dentry
pub fn ns_of_dentry(d: &Dentry) -> Option<NsRef> {
    if !is_ns_dentry(d) {
        return None;
    }
    let inode = d.get_inode()?;
    get_proc_ns(&inode)
}

/// An nsfs mount's root, as mountinfo shows it: "<type>:[<inum>]"
/// (Linux nsfs_show_path)
pub(super) fn nsfs_show_path(root: &Dentry) -> Option<alloc::vec::Vec<u8>> {
    let ns = ns_of_dentry(root)?;
    Some(alloc::format!("{}:[{}]", ns.name(), ns.inum()).into_bytes())
}

/// The mount namespace `d`'s file holds, if it is a mount namespace
/// file (Linux mnt_ns_from_dentry)
pub fn mnt_ns_from_dentry(d: &Dentry) -> Option<Arc<MntNamespace>> {
    match ns_of_dentry(d)? {
        NsRef::Mnt(m) => Some(m),
        _ => None,
    }
}

/// `d` is a mount namespace file (Linux is_mnt_ns_file)
pub fn is_mnt_ns_file(d: &Dentry) -> bool {
    mnt_ns_from_dentry(d).is_some()
}

/// A dentry is killed: its namespace forgets it, if it is the one
/// stashed (Linux ns_prune_dentry: a dentry that lost the stash race
/// was never stashed)
fn ns_prune_dentry(d: &Dentry) {
    let Some(inode) = d.get_inode() else { return };
    let Some(ns) = get_proc_ns(&inode) else {
        return;
    };
    let me = core::ptr::from_ref(d).cast_mut();
    let _ =
        ns.common()
            .stashed
            .compare_exchange(me, null_mut(), Ordering::AcqRel, Ordering::Relaxed);
}

/// The stashed dentry of `ns`, a new reference, if one lives (Linux
/// path_from_stashed's fast path)
fn stashed(ns: &NsRef) -> Option<DentryRef> {
    let _g = crate::sync::rcu::read_lock();
    let d = ns.common().stashed.load(Ordering::Acquire);
    if d.is_null() {
        return None;
    }
    // SAFETY: a stashed dentry is cleared from the stash by its kill
    // (`ns_prune_dentry`) before its memory's grace period starts, and
    // this read guard was taken before the load, so the memory is live;
    // `try_get` refuses one whose last reference went
    DentryRef::try_get(unsafe { &*d })
}

/// The file of `ns` (Linux ns_get_path): its stashed dentry, or a new
/// inode numbered as the namespace (S_IFREG | 0444, holding `ns`) under
/// a new dentry "<type>:[<inum>]" that becomes the stash; on the nsfs
/// mount. ENOMEM.
pub fn ns_get_path(ns: NsRef) -> Result<Path, KernelError> {
    let mnt = NSFS.mnt()?;
    loop {
        if let Some(d) = stashed(&ns) {
            return Ok(Path::new(mnt, d));
        }
        let inum = ns.inum();
        let inode = Inode::alloc(Inode::new(
            u64::from(inum),
            InodeMode::regular(0o444),
            0,
            0,
            0,
            crate::time::TIMEKEEPER.current_time(),
            Arc::downgrade(&mnt.sb),
            &NULL_INODE_OPS,
        ))?;
        let name = alloc::format!("{}:[{inum}]", ns.name());
        inode.set_private(try_arc(NsInode::new(ns.clone()))?);
        let d = DentryRef::new(Dentry::new_pseudo(name.as_bytes(), inode, &mnt.sb)?)?;
        let me = DentryRef::as_ptr(&d).cast_mut();
        match ns.common().stashed.compare_exchange(
            null_mut(),
            me,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(Path::new(mnt, d)),
            // Another made one first, or a dead one is still stashed
            // until its kill clears it (Linux -EAGAIN, retried): ours
            // was never stashed, so its kill leaves the stash alone
            Err(_) => {
                drop(d);
                core::hint::spin_loop();
            }
        }
    }
}
