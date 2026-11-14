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
use crate::ns::{MntNamespace, NsRef};
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;

/// The nsfs ioctls (Linux uapi nsfs.h, _IO(NSIO, n))
const NS_GET_USERNS: u32 = 0xb701;
const NS_GET_PARENT: u32 = 0xb702;
const NS_GET_NSTYPE: u32 = 0xb703;
const NS_GET_OWNER_UID: u32 = 0xb704;

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
    /// uid as the caller's user namespace sees it. ENOTTY otherwise.
    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let ns = file
            .get_inode()
            .and_then(|i| get_proc_ns(&i))
            .ok_or(KernelError::NotTty)?;
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
    let path = ns_get_path(ns)?;
    let flags = crate::fs::flags::O_RDONLY;
    let file = File::new(
        path.dentry.clone(),
        Some(path.mnt.clone()),
        flags,
        &NS_FILE_OPS,
    );
    let fd = crate::fs::io::fd_install(file.alloc()?, crate::task::FD_CLOEXEC)?;
    Ok(i64::from(fd))
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
/// namespace, held until the inode goes (Linux nsfs_evict)
struct NsInode(NsRef);

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
        inode.set_private(try_arc(NsInode(ns.clone()))?);
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
