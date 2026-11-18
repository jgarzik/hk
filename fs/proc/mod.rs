//! Procfs - process information pseudo-filesystem
//!
//! Procfs provides a filesystem interface for accessing kernel and
//! process information. Content is generated dynamically on read.
//!
//! ## Per-PID Directories
//!
//! Each process has a directory `/proc/<pid>/` containing:
//! - `/proc/<pid>/ns/` - Namespace file descriptors
//! - `/proc/<pid>/ns/uts` - UTS namespace
//! - `/proc/<pid>/ns/mnt` - Mount namespace
//! - `/proc/<pid>/ns/pid` - PID namespace
//! - `/proc/<pid>/ns/user` - User namespace
//!
//! These files can be opened and passed to `setns(2)` to join namespaces.
//!
//! ## Pid namespaces
//!
//! A procfs shows the pid namespace of whoever mounted it (Linux
//! proc_fs_info.pid_ns, `ProcOpts.pid_ns`, fixed at mount): its
//! process directories are the tasks visible there, named by their
//! numbers there, and the pids inside its files are numbered there.
//! Inode data holds the task's struct pid (`ProcPid`, Linux
//! proc_inode->pid), found from the mount's number at lookup; each
//! access pins the task through it once (Linux get_pid_task) and works
//! on that task, never on its number, so a reused number never reaches
//! another task, and a reaped one's files read ESRCH.

mod array;
mod mounts;
mod opts;
mod proc_net;
pub mod seq;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::spin::RwLock;

use super::KernelError;
use super::dentry::Dentry;
use super::file::{DirContext, DirEntry, File, FileOps, RwFlags, WRITE_CHUNK};
use super::inode::{AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, InodeRef, Timespec};
use super::iov_iter::{IovDest, IovSource};
use super::superblock::{FileSystemType, PROC_SUPER_MAGIC, StatFs, SuperBlock, SuperOps};
use crate::io::poll::{DEFAULT_POLLMASK, POLLIN, POLLRDNORM, PollTable};
use crate::ns::PidNamespace;
use crate::task::Cred;
use crate::task::Pid;
use crate::task::percpu::TaskRef;
use crate::util::kalloc::try_arc;

/// Get current timestamp for new inodes
/// Returns current wall-clock time from TIMEKEEPER if available, otherwise zero
fn current_time() -> Timespec {
    use crate::time::TIMEKEEPER;
    TIMEKEEPER.current_time()
}

/// `t` is still in the task list, not reaped (Linux pid_alive, no
/// lock)
fn alive(t: &crate::task::Task) -> bool {
    t.pid_alive()
}

/// Task `t`'s descriptor table, fs struct, namespaces and address space
/// (Linux get_files_struct, get_task_fs..., under task_lock)
fn task_files(t: &crate::task::Task) -> Option<Arc<crate::task::fdtable::Files>> {
    t.task_lock().files().cloned()
}

pub(crate) fn task_nsproxy(t: &crate::task::Task) -> Option<Arc<crate::ns::NsProxy>> {
    t.task_lock().nsproxy().cloned()
}

pub(super) fn task_mm(t: &crate::task::Task) -> Option<Arc<crate::mm::Mm>> {
    t.task_lock().mm().map(|m| m.arc().clone())
}

/// The task a /proc inode belongs to, by its struct pid (Linux
/// proc_inode->pid): a reused number never redirects an inode or an
/// open file to another task
#[derive(Clone)]
pub struct ProcPid(Arc<crate::task::pid::Pid>);

impl ProcPid {
    /// The task, pinned, while the pid names one (Linux get_pid_task,
    /// under RCU), None once it is reaped. Every per-process path works
    /// on this task, never on its number.
    pub fn task(&self) -> Option<TaskRef> {
        crate::task::percpu::get_pid_task(&self.0)
    }

    /// Its root number, for inode numbers (fixed)
    fn ino(&self) -> u64 {
        u64::from(self.0.nr())
    }
}

/// Inode number for per-PID directories
///
/// We use a simple scheme: PID * 1000 + offset
/// - offset 0: /proc/<pid>
/// - offset 1: /proc/<pid>/ns
/// - offset 2+: /proc/<pid>/ns/<type>
fn pid_ino(pid: Pid, offset: u64) -> u64 {
    // Above every allocated inode: a marker bit, the pid, then a 32-bit
    // offset (fixed entries below 2^24, fd links and fdinfo files at
    // FD_INO / FDINFO_INO plus the fd)
    (1 << 62) | (pid << 32) | offset
}

/// Offset base of /proc/<pid>/fd/<fd>
const FD_INO: u64 = 1 << 24;
/// Offset base of /proc/<pid>/fdinfo/<fd>
const FDINFO_INO: u64 = 2 << 24;

/// A generated file's content (Linux its show()): from the system
/// state alone, or also from the open file (the opener's credentials:
/// Linux file_ns_capable(m->file, ..))
#[derive(Clone, Copy)]
pub enum ContentGenerator {
    Plain(fn() -> Vec<u8>),
    Opener(fn(&File) -> Vec<u8>),
}

/// The links of /proc/<pid>/ns (Linux proc_ns_operations, ns_entries
/// in this order): each names one of the task's namespaces
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    /// Network namespace (network stack isolation)
    Net,
    /// UTS namespace (hostname, domainname)
    Uts,
    /// IPC namespace (SysV IPC)
    Ipc,
    /// PID namespace the task is in (Linux task_active_pid_ns)
    Pid,
    /// PID namespace its children go to (Linux pid_ns_for_children)
    PidForChildren,
    /// User namespace (UID/GID mapping)
    User,
    /// Mount namespace (filesystem view)
    Mnt,
    /// Cgroup namespace (cgroup root)
    Cgroup,
}

impl NamespaceType {
    /// Its name in /proc/<pid>/ns (Linux ops->name)
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Net => "net",
            Self::Uts => "uts",
            Self::Ipc => "ipc",
            Self::Pid => "pid",
            Self::PidForChildren => "pid_for_children",
            Self::User => "user",
            Self::Mnt => "mnt",
            Self::Cgroup => "cgroup",
        }
    }

    /// Convert from filename to namespace type
    pub fn parse(s: &str) -> Option<Self> {
        Self::all().iter().copied().find(|t| t.as_str() == s)
    }

    /// Its inode number offset under the process (`pid_ino`)
    fn offset(&self) -> u64 {
        2 + Self::all().iter().position(|t| t == self).unwrap_or(0) as u64
    }

    /// Task `t`'s namespace of this type, a new reference (Linux
    /// ops->get): None once it has exited, and for pid_for_children
    /// until that namespace has its init (Linux pidns_for_children_get)
    pub fn get(&self, t: &crate::task::Task) -> Option<crate::ns::NsRef> {
        use crate::ns::NsRef;
        let ns = task_nsproxy(t)?;
        Some(match self {
            Self::Net => NsRef::Net(ns.net_ns.clone()),
            Self::Uts => NsRef::Uts(ns.uts_ns.clone()),
            Self::Ipc => NsRef::Ipc(ns.ipc_ns.clone()),
            Self::Pid => NsRef::Pid(t.get_pid_ns()),
            Self::PidForChildren => {
                if !crate::task::pidns::has_reaper(&ns.pid_ns) {
                    return None;
                }
                NsRef::Pid(ns.pid_ns.clone())
            }
            Self::User => NsRef::User(ns.user_ns.clone()),
            Self::Mnt => NsRef::Mnt(ns.mnt_ns.clone()),
            Self::Cgroup => NsRef::Cgroup(ns.cgroup_ns.clone()),
        })
    }

    /// List of all supported namespace types
    pub fn all() -> &'static [NamespaceType] {
        &[
            Self::Net,
            Self::Uts,
            Self::Ipc,
            Self::Pid,
            Self::PidForChildren,
            Self::User,
            Self::Mnt,
            Self::Cgroup,
        ]
    }
}

/// Procfs inode private data
pub enum ProcfsInodeData {
    /// Directory with static children (built at mount; shared, so a
    /// readdir walks them with no lock held)
    Directory {
        children: Arc<BTreeMap<String, InodeRef>>,
    },
    /// File with content generator
    File { generator: ContentGenerator },
    /// Per-PID root directory (/proc/<pid>)
    ///
    /// Children are generated dynamically based on PID.
    PidDirectory { pid: ProcPid },
    /// Per-PID namespace directory (/proc/<pid>/ns)
    ///
    /// Contains namespace files for setns(2).
    PidNsDirectory { pid: ProcPid },
    /// Namespace file (/proc/<pid>/ns/<type>)
    ///
    /// Can be opened and passed to setns(2) to join a namespace.
    NamespaceFile {
        pid: ProcPid,
        ns_type: NamespaceType,
    },
    /// Thread directory (/proc/<pid>/task): one entry per thread, each
    /// a view of the process directory (per-thread files are a subset)
    PidTaskDirectory { pid: ProcPid },
    /// Per-PID fd directory (/proc/<pid>/fd)
    ///
    /// Contains symlinks to open file descriptors.
    PidFdDirectory { pid: ProcPid },
    /// Per-PID fdinfo directory (/proc/<pid>/fdinfo)
    ///
    /// Contains files with information about open file descriptors.
    PidFdinfoDirectory { pid: ProcPid },
    /// Fd symlink (/proc/<pid>/fd/<n>)
    ///
    /// Symlink to the open file descriptor.
    FdSymlink { pid: ProcPid, fd: i32 },
    /// /proc/self: symlink to the reader's process directory
    SelfLink,
    /// A symlink with a fixed target (/proc/mounts -> self/mounts)
    FixedLink(&'static [u8]),
    /// Fdinfo file (/proc/<pid>/fdinfo/<n>)
    ///
    /// File containing information about an open file descriptor.
    FdinfoFile { pid: ProcPid, fd: i32 },
    /// Generated per-process file (/proc/<pid>/cgroup, maps, ...)
    PidFile { pid: ProcPid, generator: PidGen },
    /// Per-process symlink (/proc/<pid>/exe, cwd, root)
    PidLink { pid: ProcPid, target: PidLinkKind },
    /// /proc/sys file (readable, maybe writable)
    Sysctl { ctl: &'static crate::sysctl::Ctl },
    /// /proc/<pid>/fail-nth: the task's fault-injection countdown
    /// (Linux proc_fail_nth_operations, `mm::fault_inject`)
    FailNth { pid: ProcPid },
    /// /proc/<pid>/net: the task's network namespace (`proc_net`)
    PidNetDirectory { pid: ProcPid },
    /// A file of /proc/<pid>/net, bound to the namespace it was found
    /// in (a passive reference: Linux PDE's net)
    NetFile {
        net: Arc<crate::net::NetNamespace>,
        generator: proc_net::NetGen,
    },
}

impl ProcfsInodeData {
    /// Create directory data
    pub fn new_dir() -> Result<Self, KernelError> {
        Ok(Self::Directory {
            children: try_arc(BTreeMap::new())?,
        })
    }

    /// Create file data with generator
    pub fn new_file(generator: fn() -> Vec<u8>) -> Self {
        Self::File {
            generator: ContentGenerator::Plain(generator),
        }
    }

    /// File data whose generator reads the open file
    pub fn new_opener_file(generator: fn(&File) -> Vec<u8>) -> Self {
        Self::File {
            generator: ContentGenerator::Opener(generator),
        }
    }

    /// Create per-PID directory data
    pub fn new_pid_dir(pid: ProcPid) -> Self {
        Self::PidDirectory { pid }
    }

    /// Create per-PID namespace directory data
    pub fn new_pid_ns_dir(pid: ProcPid) -> Self {
        Self::PidNsDirectory { pid }
    }

    /// Create namespace file data
    pub fn new_ns_file(pid: ProcPid, ns_type: NamespaceType) -> Self {
        Self::NamespaceFile { pid, ns_type }
    }

    /// Create per-PID fd directory data
    pub fn new_pid_fd_dir(pid: ProcPid) -> Self {
        Self::PidFdDirectory { pid }
    }

    /// Create per-PID fdinfo directory data
    pub fn new_pid_fdinfo_dir(pid: ProcPid) -> Self {
        Self::PidFdinfoDirectory { pid }
    }

    /// Create fd symlink data
    pub fn new_fd_symlink(pid: ProcPid, fd: i32) -> Self {
        Self::FdSymlink { pid, fd }
    }

    /// Create fdinfo file data
    pub fn new_fdinfo_file(pid: ProcPid, fd: i32) -> Self {
        Self::FdinfoFile { pid, fd }
    }

    /// Create per-process generated file data
    pub fn new_pid_file(pid: ProcPid, generator: PidGen) -> Self {
        Self::PidFile { pid, generator }
    }

    /// Get children map (for static directories)
    pub fn children(&self) -> Option<&BTreeMap<String, InodeRef>> {
        match self {
            Self::Directory { children } => Some(children),
            _ => None,
        }
    }

    /// Get PID for per-PID entries
    pub fn pid(&self) -> Option<ProcPid> {
        match self {
            Self::PidDirectory { pid }
            | Self::PidNsDirectory { pid }
            | Self::NamespaceFile { pid, .. }
            | Self::PidFdDirectory { pid }
            | Self::PidTaskDirectory { pid }
            | Self::PidNetDirectory { pid }
            | Self::PidFdinfoDirectory { pid }
            | Self::FdSymlink { pid, .. }
            | Self::FdinfoFile { pid, .. }
            | Self::PidFile { pid, .. }
            | Self::PidLink { pid, .. } => Some(pid.clone()),
            _ => None,
        }
    }

    /// Get namespace type for namespace files
    pub fn ns_type(&self) -> Option<NamespaceType> {
        match self {
            Self::NamespaceFile { ns_type, .. } => Some(*ns_type),
            _ => None,
        }
    }

    /// Check if this is a directory type
    pub fn is_directory(&self) -> bool {
        matches!(
            self,
            Self::Directory { .. }
                | Self::PidDirectory { .. }
                | Self::PidNsDirectory { .. }
                | Self::PidFdDirectory { .. }
                | Self::PidTaskDirectory { .. }
                | Self::PidNetDirectory { .. }
                | Self::PidFdinfoDirectory { .. }
        )
    }
}

impl AsAny for ProcfsInodeData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for ProcfsInodeData {}

/// Wrapper to allow interior mutability for procfs data
pub struct ProcfsInodeWrapper(pub RwLock<ProcfsInodeData>);

impl AsAny for ProcfsInodeWrapper {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for ProcfsInodeWrapper {}

/// Procfs inode operations
pub struct ProcfsInodeOps;

impl InodeOps for ProcfsInodeOps {
    /// Targets of /proc/self and /proc/<pid>/fd/<n> (Linux
    /// proc_self_get_link, proc_fd_link + d_path/d_dname)
    fn readlink(&self, inode: &Inode) -> Result<Vec<u8>, KernelError> {
        // What the link is, copied out: a target may sleep (exe takes
        // exec_update_lock) or allocate, so none is made under the inode
        // data's spinning read lock
        enum Link {
            Pid(ProcPid, PidLinkKind),
            Me,
            Fixed(&'static [u8]),
            Fd(ProcPid, i32),
            Ns(ProcPid, NamespaceType),
        }
        let l = with_data(inode, |d| match d {
            ProcfsInodeData::PidLink { pid, target } => Ok(Link::Pid(pid.clone(), *target)),
            ProcfsInodeData::SelfLink => Ok(Link::Me),
            ProcfsInodeData::FixedLink(t) => Ok(Link::Fixed(t)),
            ProcfsInodeData::FdSymlink { pid, fd } => Ok(Link::Fd(pid.clone(), *fd)),
            ProcfsInodeData::NamespaceFile { pid, ns_type } => Ok(Link::Ns(pid.clone(), *ns_type)),
            _ => Err(KernelError::InvalidArgument),
        })
        .ok_or(KernelError::Io)??;
        match l {
            // EACCES once the task is gone (Linux proc_fd_access_allowed)
            Link::Pid(pid, target) => {
                let p = pid_link_path(&pid.task().ok_or(KernelError::PermissionDenied)?, target)?;
                super::dentry::d_path_link(&p)
            }
            Link::Me => self_link(inode),
            Link::Fixed(t) => Ok(t.to_vec()),
            Link::Fd(pid, fd) => fd_link(&pid, fd),
            Link::Ns(pid, ns_type) => {
                let ns = task_ns(&pid, ns_type)?;
                Ok(alloc::format!("{}:[{}]", ns.name(), ns.inum()).into_bytes())
            }
        }
    }

    /// The magic links jump (Linux proc_pid_get_link, after
    /// proc_fd_access_allowed: proc_fd_link, proc_cwd_link,
    /// proc_root_link, proc_exe_link; proc_ns_get_link: ns_get_path);
    /// /proc/self and the fixed links are text
    fn get_link(&self, inode: &Inode, rcu: bool) -> Result<crate::fs::inode::Link, KernelError> {
        use crate::fs::inode::Link;
        // /proc/self in RCU mode (Linux proc_self_get_link, GFP_ATOMIC);
        // the magic links are ECHILD there (proc_pid_get_link,
        // proc_ns_get_link)
        if rcu {
            return match proc_rcu(inode) {
                Some(r) if r.kind == RcuKind::SelfLink => self_link_rcu(r).map(Link::Text),
                _ => Err(KernelError::NoChild),
            };
        }
        enum J {
            Fd(ProcPid, i32),
            Pid(ProcPid, PidLinkKind),
            Ns(ProcPid, NamespaceType),
            Text,
        }
        let symlink = inode.mode().is_symlink();
        let j = with_data(inode, |d| match d {
            ProcfsInodeData::FdSymlink { pid, fd } => J::Fd(pid.clone(), *fd),
            ProcfsInodeData::PidLink { pid, target } => J::Pid(pid.clone(), *target),
            ProcfsInodeData::NamespaceFile { pid, ns_type } if symlink => {
                J::Ns(pid.clone(), *ns_type)
            }
            _ => J::Text,
        })
        .ok_or(KernelError::Io)?;
        Ok(Link::Jump(match j {
            J::Fd(pid, fd) => fd_jump(&pid, fd)?,
            J::Pid(pid, k) => pid_link_path(&link_task(&pid)?, k)?,
            J::Ns(pid, ns_type) => ns_file(pid, ns_type)?,
            J::Text => return Ok(Link::Text(self.readlink(inode)?)),
        }))
    }

    /// Linux proc_pid_getattr: a process hidepid=invisible hides is
    /// ENOENT to stat too (a dentry looked up by someone else stays
    /// cached), consistent with readdir
    fn getattr_ok(&self, inode: &Inode) -> Result<(), KernelError> {
        match pid_dir_pid(inode) {
            Some(t) if !opts::with(inode, |o| o.visible(&t)).unwrap_or(true) => {
                Err(KernelError::NotFound)
            }
            _ => Ok(()),
        }
    }

    /// /proc/<pid> (Linux proc_pid_permission: ESRCH for a task that is
    /// gone, hidepid=), fd/ (proc_fd_permission: the generic check or
    /// the same thread group), fdinfo/ and its files
    /// (proc_fdinfo_permission: ESRCH, ptrace-read access), /proc/sys
    /// files (proc_sys_permission: never executable, then sysctl_perm:
    /// no capability override of the mode)
    fn permission(&self, inode: &Inode, cred: &Cred, mask: u32) -> Result<(), KernelError> {
        // An RCU walk reads what the inode keeps for it (`private`
        // goes with the teardown)
        if mask & crate::fs::dac::MAY_NOT_BLOCK != 0 {
            return permission_rcu(inode, cred, mask);
        }
        match pid_perm(inode) {
            // Linux proc_pid_permission: ESRCH for a task that is gone,
            // then what hidepid= hides
            Some((Perm::PidDir, p)) => {
                let t = p.task().ok_or(KernelError::NoProcess)?;
                opts::with(inode, |o| o.pid_permission(&t)).unwrap_or(Ok(()))?;
            }
            Some((Perm::FdDir, p)) => {
                let same = p
                    .task()
                    .is_some_and(|t| crate::task::ptrace::same_thread_group(&t));
                return proc_fd_permission(inode, cred, mask, same);
            }
            // Linux proc_fdinfo_permission: ESRCH for a task that is
            // gone, EACCES without ptrace-read access
            Some((Perm::Fdinfo, p)) => {
                let t = p.task().ok_or(KernelError::NoProcess)?;
                if !crate::task::ptrace::may_access_task(&t, true) {
                    return Err(KernelError::PermissionDenied);
                }
            }
            None => {}
        }
        // The owner follows the task's identity and dumpability (Linux
        // pid_revalidate -> pid_update_inode)
        if let Some(t) = pid_file_pid(inode) {
            let (uid, gid) = task_dump_owner(&t, inode.mode());
            inode.set_uid(uid);
            inode.set_gid(gid);
        }
        let Some(ctl) = sysctl_of(inode) else {
            return crate::fs::dac::generic_permission(cred, inode, mask);
        };
        if mask & crate::fs::MAY_EXEC != 0 {
            return Err(KernelError::PermissionDenied);
        }
        crate::sysctl::permission(ctl, cred, mask)
    }

    /// A new per-process inode takes the task's owner (Linux
    /// proc_pid_make_inode -> pid_update_inode), so its first permission
    /// check sees it
    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<InodeRef, KernelError> {
        let inode = proc_lookup(dir, name)?;
        pid_update_inode(&inode);
        Ok(inode)
    }
}

/// What an RCU walk reads of a procfs inode (Linux proc_inode's pid
/// and sysctl entry, the dentry operations picked at instantiate, and
/// i_sb's proc_fs_info): fixed at creation, released a grace period
/// after the inode's teardown (`Inode::private_rcu`; Linux
/// proc_free_inode's put_pid), so its drop (a `Pid`'s, the options')
/// is fit for an RCU callback
pub struct ProcRcu {
    pid: Option<ProcPid>,
    kind: RcuKind,
    ctl: Option<&'static crate::sysctl::Ctl>,
    /// The superblock's options (`ProcOpts`)
    opts: Option<Arc<dyn crate::fs::superblock::SuperBlockData>>,
}

impl AsAny for ProcRcu {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for ProcRcu {}

/// How a procfs inode answers an RCU walk (Linux its d_op and i_op)
#[derive(Clone, Copy, PartialEq, Eq)]
enum RcuKind {
    /// A static entry (a PDE: proc_misc_d_revalidate, ECHILD), or a
    /// directory with no special permission
    Static,
    /// /proc/self (no d_op; proc_self_get_link works in RCU mode)
    SelfLink,
    /// An entry of a process (pid_dentry_operations: pid_revalidate)
    Pid,
    /// /proc/<pid> and task/<tid> (proc_pid_permission)
    PidDir,
    /// fd/ (proc_fd_permission)
    FdDir,
    /// fdinfo/ (proc_fdinfo_permission)
    FdinfoDir,
    /// A per-process file, whose owner follows the task
    PidFile,
    /// fd/<n> (tid_fd_revalidate: ECHILD)
    Fd,
    /// fdinfo/<n> (tid_fd_revalidate: ECHILD; proc_fdinfo_permission)
    FdinfoFile,
    /// /proc/sys (proc_sys_revalidate: ECHILD; proc_sys_permission)
    Sysctl,
    /// /proc/<pid>/net/* (proc_net_d_revalidate: always stale)
    Net,
}

impl ProcRcu {
    fn of(
        d: &ProcfsInodeData,
        opts: Option<Arc<dyn crate::fs::superblock::SuperBlockData>>,
    ) -> Self {
        use ProcfsInodeData as D;
        let kind = match d {
            D::Directory { .. } | D::File { .. } | D::FixedLink(_) => RcuKind::Static,
            D::SelfLink => RcuKind::SelfLink,
            D::PidDirectory { .. } => RcuKind::PidDir,
            D::PidFdDirectory { .. } => RcuKind::FdDir,
            D::PidFdinfoDirectory { .. } => RcuKind::FdinfoDir,
            D::PidFile { .. } => RcuKind::PidFile,
            D::FdSymlink { .. } => RcuKind::Fd,
            D::FdinfoFile { .. } => RcuKind::FdinfoFile,
            D::Sysctl { .. } => RcuKind::Sysctl,
            D::NetFile { .. } => RcuKind::Net,
            D::PidNsDirectory { .. }
            | D::NamespaceFile { .. }
            | D::PidTaskDirectory { .. }
            | D::PidLink { .. }
            | D::FailNth { .. }
            | D::PidNetDirectory { .. } => RcuKind::Pid,
        };
        let ctl = match d {
            D::Sysctl { ctl } => Some(*ctl),
            _ => None,
        };
        Self {
            pid: d.pid(),
            kind,
            ctl,
            opts,
        }
    }

    /// The superblock's options
    fn opts(&self) -> Option<&opts::ProcOpts> {
        self.opts
            .as_ref()?
            .as_any()
            .downcast_ref::<opts::ProcOpts>()
    }

    /// The task, borrowed for `g` (Linux pid_task under rcu_read_lock)
    fn task<'g>(&'g self, g: &'g crate::sync::rcu::RcuReadGuard) -> Option<&'g crate::task::Task> {
        self.pid.as_ref()?.0.task(g)
    }
}

/// A new procfs inode's data, and what an RCU walk reads of it, before
/// the inode is visible
fn set_data(inode: &InodeRef, data: ProcfsInodeData) -> Result<(), KernelError> {
    let opts = inode.superblock().and_then(|sb| sb.fs_info_arc());
    inode.set_private_rcu(try_arc(ProcRcu::of(&data, opts))?);
    inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(data)))?);
    Ok(())
}

/// The RCU-readable data of a procfs inode
fn proc_rcu(inode: &Inode) -> Option<&ProcRcu> {
    inode.private_rcu()?.as_any().downcast_ref::<ProcRcu>()
}

/// [`proc_revalidate`] under LOOKUP_RCU (Linux pid_revalidate:
/// the task under rcu_read_lock, its owner taken over; tid_fd_revalidate,
/// proc_sys_revalidate and proc_misc_d_revalidate are ECHILD;
/// proc_net_d_revalidate is always stale)
fn revalidate_rcu(inode: &Inode) -> Result<bool, KernelError> {
    let r = proc_rcu(inode).ok_or(KernelError::NoChild)?;
    match r.kind {
        RcuKind::Static | RcuKind::Fd | RcuKind::FdinfoFile | RcuKind::Sysctl => {
            Err(KernelError::NoChild)
        }
        RcuKind::SelfLink => Ok(true),
        RcuKind::Net => Ok(false),
        RcuKind::Pid | RcuKind::PidDir | RcuKind::FdDir | RcuKind::FdinfoDir | RcuKind::PidFile => {
            let g = crate::sync::rcu::read_lock();
            let Some(t) = r.task(&g) else {
                return Ok(false);
            };
            let (uid, gid) = task_dump_owner(t, inode.mode());
            inode.set_uid(uid);
            inode.set_gid(gid);
            Ok(true)
        }
    }
}

/// [`InodeOps::permission`] with MAY_NOT_BLOCK: what ref mode checks,
/// from the RCU-readable data (Linux proc_pid_permission,
/// proc_fd_permission and proc_sys_permission run there too)
fn permission_rcu(inode: &Inode, cred: &Cred, mask: u32) -> Result<(), KernelError> {
    let r = proc_rcu(inode).ok_or(KernelError::NoChild)?;
    let g = crate::sync::rcu::read_lock();
    let t = r.task(&g);
    match (r.kind, t) {
        (RcuKind::PidDir | RcuKind::FdinfoDir | RcuKind::FdinfoFile, None) => {
            return Err(KernelError::NoProcess);
        }
        (RcuKind::PidDir, Some(t)) => {
            let o = r.opts().ok_or(KernelError::NoChild)?;
            o.pid_permission(t)?;
        }
        (RcuKind::FdDir, t) => {
            let same = t.is_some_and(crate::task::ptrace::same_thread_group);
            drop(g);
            return proc_fd_permission(inode, cred, mask, same);
        }
        (RcuKind::FdinfoDir | RcuKind::FdinfoFile, Some(t))
            if !crate::task::ptrace::may_access_task(t, true) =>
        {
            return Err(KernelError::PermissionDenied);
        }
        (RcuKind::PidFile, Some(t)) => {
            let (uid, gid) = task_dump_owner(t, inode.mode());
            inode.set_uid(uid);
            inode.set_gid(gid);
        }
        (RcuKind::Sysctl, _) => {
            let ctl = r.ctl.ok_or(KernelError::NoChild)?;
            if mask & crate::fs::MAY_EXEC != 0 {
                return Err(KernelError::PermissionDenied);
            }
            return crate::sysctl::permission(ctl, cred, mask);
        }
        _ => {}
    }
    drop(g);
    crate::fs::dac::generic_permission(cred, inode, mask)
}

/// The permission checks of a process's directories and fdinfo files
/// (Linux proc_pid_permission, proc_fd_permission,
/// proc_fdinfo_permission)
#[derive(Clone, Copy)]
enum Perm {
    PidDir,
    FdDir,
    Fdinfo,
}

/// Which of [`Perm`] `inode` has, and its process
fn pid_perm(inode: &Inode) -> Option<(Perm, ProcPid)> {
    with_data(inode, |d| match d {
        ProcfsInodeData::PidDirectory { pid } => Some((Perm::PidDir, pid.clone())),
        ProcfsInodeData::PidFdDirectory { pid } => Some((Perm::FdDir, pid.clone())),
        ProcfsInodeData::PidFdinfoDirectory { pid } | ProcfsInodeData::FdinfoFile { pid, .. } => {
            Some((Perm::Fdinfo, pid.clone()))
        }
        _ => None,
    })?
}

/// fd/ (Linux proc_fd_permission): the generic check, else a thread of
/// the process itself (`same`) may still search it, its owner being
/// root when the process is not dumpable
fn proc_fd_permission(
    inode: &Inode,
    cred: &Cred,
    mask: u32,
    same: bool,
) -> Result<(), KernelError> {
    match crate::fs::dac::generic_permission(cred, inode, mask) {
        Err(_) if same => Ok(()),
        r => r,
    }
}

/// [`proc_revalidate`] of a procfs inode in ref mode
fn revalidate_ref(inode: &Inode) -> bool {
    // A /proc/<pid>/net file is looked up afresh by every walk, so
    // it follows the task's namespace (Linux proc_net_d_revalidate)
    if with_data(inode, |d| matches!(d, ProcfsInodeData::NetFile { .. })).unwrap_or(false) {
        return false;
    }
    let fd_of = |d: &ProcfsInodeData| match d {
        ProcfsInodeData::FdSymlink { fd, .. } | ProcfsInodeData::FdinfoFile { fd, .. } => Some(*fd),
        _ => None,
    };
    let Some((Some(p), fd)) = with_data(inode, |d| (d.pid(), fd_of(d))) else {
        return true;
    };
    let Some(t) = p.task() else {
        return false;
    };
    if let Some(fd) = fd {
        let Some(file) = task_files(&t).and_then(|f| f.lock().get(fd)) else {
            return false;
        };
        fd_update_inode(inode, &file);
    }
    let (uid, gid) = task_dump_owner(&t, inode.mode());
    inode.set_uid(uid);
    inode.set_gid(gid);
    true
}

/// `f` on the inode's procfs data under its read lock (copy out what
/// the caller acts on: nothing that sleeps or allocates runs under it);
/// None for an inode without procfs data
pub(crate) fn with_data<T>(inode: &Inode, f: impl FnOnce(&ProcfsInodeData) -> T) -> Option<T> {
    let p = inode.get_private()?;
    let w = p.as_ref().as_any().downcast_ref::<ProcfsInodeWrapper>()?;
    let d = w.0.read();
    Some(f(&d))
}

/// The owner of a per-process inode follows the task's identity and
/// dumpability (Linux pid_update_inode, task_dump_owner)
fn pid_update_inode(inode: &Inode) {
    // Copied out: dump_owner takes TASKLIST, never under the data's lock
    let p = with_data(inode, ProcfsInodeData::pid).flatten();
    if let Some(t) = p.and_then(|p| p.task()) {
        let (uid, gid) = task_dump_owner(&t, inode.mode());
        inode.set_uid(uid);
        inode.set_gid(gid);
    }
}

/// Look up `name` in the /proc directory `dir`
fn proc_lookup(dir: &Inode, name: &[u8]) -> Result<InodeRef, KernelError> {
    // Every /proc name is text: anything else names nothing
    let name = core::str::from_utf8(name).map_err(|_| KernelError::NotFound)?;

    // What the directory is, copied out: lookups allocate inodes and
    // take TASKLIST, so none runs under the inode data's spin lock
    enum Dir {
        Static(Option<InodeRef>, bool),
        Pid(ProcPid),
        Ns(ProcPid),
        Fd(ProcPid),
        Task(ProcPid),
        Fdinfo(ProcPid),
        Net(ProcPid),
    }
    let kind = with_data(dir, |d| -> Result<_, KernelError> {
        Ok(match d {
            // A static child, and whether this is the root (it has
            // "version")
            ProcfsInodeData::Directory { children } => Dir::Static(
                children.get(name).cloned(),
                children.contains_key("version"),
            ),
            ProcfsInodeData::PidDirectory { pid } => Dir::Pid(pid.clone()),
            ProcfsInodeData::PidNsDirectory { pid } => Dir::Ns(pid.clone()),
            ProcfsInodeData::PidFdDirectory { pid } => Dir::Fd(pid.clone()),
            ProcfsInodeData::PidTaskDirectory { pid } => Dir::Task(pid.clone()),
            ProcfsInodeData::PidFdinfoDirectory { pid } => Dir::Fdinfo(pid.clone()),
            ProcfsInodeData::PidNetDirectory { pid } => Dir::Net(pid.clone()),
            ProcfsInodeData::File { .. }
            | ProcfsInodeData::NamespaceFile { .. }
            | ProcfsInodeData::FdSymlink { .. }
            | ProcfsInodeData::PidLink { .. }
            | ProcfsInodeData::SelfLink
            | ProcfsInodeData::FixedLink(_)
            | ProcfsInodeData::FdinfoFile { .. }
            | ProcfsInodeData::PidFile { .. }
            | ProcfsInodeData::FailNth { .. }
            | ProcfsInodeData::NetFile { .. }
            | ProcfsInodeData::Sysctl { .. } => return Err(KernelError::NotDirectory),
        })
    })
    .ok_or(KernelError::Io)??;
    match kind {
        Dir::Static(child, root) => {
            // subset=pid: the root has only "self" and the processes
            let pidonly = root && opts::with(dir, |o| o.pidonly()).unwrap_or(false);
            // First check static children
            if let Some(child) = child.filter(|_| !pidonly) {
                return Ok(child);
            }
            // The root also has self and the processes
            if root {
                if name == "self" {
                    return create_self_link(dir);
                }
                // A task by its number in the mount's pid namespace
                // (Linux proc_pid_lookup); hidepid=invisible: another
                // user's process is not there
                if let Some(p) = name
                    .parse::<u32>()
                    .ok()
                    .and_then(|nr| crate::task::pid::find_pid(&opts::pid_ns(dir), nr))
                    .map(ProcPid)
                    && let Some(t) = p.task()
                    && opts::with(dir, |o| o.visible(&t)).unwrap_or(true)
                {
                    return create_pid_dir_inode(dir, p);
                }
            }

            Err(KernelError::NotFound)
        }
        Dir::Pid(p) => lookup_pid_entry(dir, &p, name),
        Dir::Ns(p) => lookup_pid_ns_entry(dir, &p, name),
        Dir::Fd(p) => lookup_pid_fd_entry(dir, &p, name),
        Dir::Task(p) => {
            // A thread of the process by its number in the mount's
            // namespace (Linux proc_task_lookup)
            let t = p.task().ok_or(KernelError::NotFound)?;
            let nr: u32 = name.parse().map_err(|_| KernelError::NotFound)?;
            let ns = opts::pid_ns(dir);
            // The thread's own struct pid: its directory describes
            // that thread, not the leader
            let tp = ProcPid(crate::task::pid::find_pid(&ns, nr).ok_or(KernelError::NotFound)?);
            let thread = tp.task().ok_or(KernelError::NotFound)?;
            let mine = group_threads(&t, &ns)
                .iter()
                .any(|&(x, _, _)| core::ptr::eq(x, Arc::as_ptr(&thread)));
            if !mine {
                return Err(KernelError::NotFound);
            }
            create_dir_inode(
                dir,
                pid_ino(thread.tid(), 0),
                ProcfsInodeData::new_pid_dir(tp),
            )
        }
        Dir::Fdinfo(p) => lookup_pid_fdinfo_entry(dir, &p, name),
        Dir::Net(p) => proc_net::lookup(dir, &p, name),
    }
}

// ============================================================================
// Per-PID Inode Creation Helpers
// ============================================================================

/// The live threads of task `t`'s process visible in `ns`: each one
/// (its address, only to compare), its tid and its number in `ns`
fn group_threads(
    t: &crate::task::Task,
    ns: &PidNamespace,
) -> Vec<(*const crate::task::Task, crate::task::Tid, u32)> {
    crate::task::percpu::GlobalTaskTable::collect_group(t, |_, x| {
        if matches!(x.state(), crate::task::TaskState::Zombie(_)) {
            return None;
        }
        let nr = x.thread_pid()?.nr_in(ns)?;
        Some((core::ptr::from_ref(x.task), x.task.tid(), nr))
    })
}

/// A procfs directory inode (r-xr-xr-x, root) with `data`
fn create_dir_inode(
    parent: &Inode,
    ino: u64,
    data: ProcfsInodeData,
) -> Result<InodeRef, KernelError> {
    let sb = parent.superblock().expect("superblock dropped");
    let inode = Inode::alloc(Inode::new(
        ino,
        InodeMode::directory(0o555),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    set_data(&inode, data)?;
    Ok(inode)
}

/// A procfs file inode (root's) with `mode` and `data`
fn create_file_inode(
    parent: &Inode,
    ino: u64,
    mode: InodeMode,
    data: ProcfsInodeData,
) -> Result<InodeRef, KernelError> {
    let sb = parent.superblock().ok_or(KernelError::Io)?;
    let inode = Inode::alloc(Inode::new(
        ino,
        mode,
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    set_data(&inode, data)?;
    Ok(inode)
}

fn create_pid_dir_inode(parent: &Inode, pid: ProcPid) -> Result<InodeRef, KernelError> {
    let sb = parent.superblock().expect("superblock dropped");
    let inode = Inode::alloc(Inode::new(
        pid_ino(pid.ino(), 0),
        InodeMode::directory(0o555), // r-xr-xr-x
        0,                           // uid: root
        0,                           // gid: root
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    set_data(&inode, ProcfsInodeData::new_pid_dir(pid))?;
    Ok(inode)
}

/// Look up entries in /proc/<pid>/
fn lookup_pid_entry(dir: &Inode, p: &ProcPid, name: &str) -> Result<InodeRef, KernelError> {
    // The task, while its pid names one; its tid only numbers inodes
    let t = p.task().ok_or(KernelError::NotFound)?;
    let pid = t.tid();

    match name {
        "ns" => {
            // Create /proc/<pid>/ns directory
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = Inode::alloc(Inode::new(
                pid_ino(pid, 1),
                InodeMode::directory(0o555), // r-xr-xr-x
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            set_data(&inode, ProcfsInodeData::new_pid_ns_dir(p.clone()))?;
            Ok(inode)
        }
        "fd" => {
            // Create /proc/<pid>/fd directory
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = Inode::alloc(Inode::new(
                pid_ino(pid, 100),           // offset 100 for fd dir
                InodeMode::directory(0o500), // dr-x------ (only owner can read)
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            set_data(&inode, ProcfsInodeData::new_pid_fd_dir(p.clone()))?;
            Ok(inode)
        }
        "task" => create_dir_inode(
            dir,
            pid_ino(pid, 120),
            ProcfsInodeData::PidTaskDirectory { pid: p.clone() },
        ),
        // Linux tgid_base_stuff / tid_base_stuff DIR("net")
        "net" => create_dir_inode(
            dir,
            pid_ino(pid, proc_net::NET_DIR_INO),
            ProcfsInodeData::PidNetDirectory { pid: p.clone() },
        ),
        "fdinfo" => {
            // Create /proc/<pid>/fdinfo directory
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = Inode::alloc(Inode::new(
                pid_ino(pid, 101),           // offset 101 for fdinfo dir
                InodeMode::directory(0o500), // dr-x------ (only owner can read)
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            set_data(&inode, ProcfsInodeData::new_pid_fdinfo_dir(p.clone()))?;
            Ok(inode)
        }
        name if PID_LINKS.iter().any(|(n, _, _)| *n == name) => {
            let &(_, off, target) = PID_LINKS
                .iter()
                .find(|(n, _, _)| *n == name)
                .ok_or(KernelError::NotFound)?;
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = Inode::alloc(Inode::new(
                pid_ino(pid, off),
                InodeMode::symlink(),
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            set_data(
                &inode,
                ProcfsInodeData::PidLink {
                    pid: p.clone(),
                    target,
                },
            )?;
            Ok(inode)
        }
        "fail-nth" => {
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let (uid, gid) = task_dump_owner(&t, InodeMode::regular(0o644));
            let inode = Inode::alloc(Inode::new(
                pid_ino(pid, FAIL_NTH_INO),
                InodeMode::regular(0o644),
                uid,
                gid,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            set_data(&inode, ProcfsInodeData::FailNth { pid: p.clone() })?;
            Ok(inode)
        }
        name if pid_file(name).is_some() => {
            let (off, mode, generator) = pid_file(name).ok_or(KernelError::NotFound)?;
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let (uid, gid) = task_dump_owner(&t, InodeMode::regular(mode));
            let inode = Inode::alloc(Inode::new(
                pid_ino(pid, off),
                InodeMode::regular(mode),
                uid,
                gid,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            set_data(&inode, ProcfsInodeData::new_pid_file(p.clone(), generator))?;
            Ok(inode)
        }
        _ => Err(KernelError::NotFound),
    }
}

/// Look up entries in /proc/<pid>/ns/
fn lookup_pid_ns_entry(dir: &Inode, p: &ProcPid, name: &str) -> Result<InodeRef, KernelError> {
    // The task, while its pid names one; its tid only numbers inodes
    let t = p.task().ok_or(KernelError::NotFound)?;
    let pid = t.tid();

    // Parse namespace type from name
    let ns_type = NamespaceType::parse(name).ok_or(KernelError::NotFound)?;

    // Create namespace file inode
    let sb = dir.superblock().ok_or(KernelError::Io)?;
    let offset = ns_type.offset();

    // A magic link to the namespace (Linux proc_ns_dir_operations:
    // S_IFLNK | 0777)
    let inode = Inode::alloc(Inode::new(
        pid_ino(pid, offset),
        InodeMode::symlink(),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    set_data(&inode, ProcfsInodeData::new_ns_file(p.clone(), ns_type))?;
    Ok(inode)
}

/// The target of /proc/self: the reader's process as the mount's pid
/// namespace numbers it, ENOENT if it is not visible there (Linux
/// proc_self_get_link)
fn self_link(inode: &Inode) -> Result<Vec<u8>, KernelError> {
    let ns = opts::pid_ns(inode);
    match crate::task::pid::nr_ns(crate::task::percpu::current_pid(), &ns) {
        0 => Err(KernelError::NotFound),
        n => Ok(alloc::format!("{n}").into_bytes()),
    }
}

/// [`self_link`] for an RCU walk (Linux proc_self_get_link with a NULL
/// dentry): the mount's pid namespace from the RCU-readable data, the
/// text allocated GFP_ATOMIC, ECHILD if that fails
fn self_link_rcu(r: &ProcRcu) -> Result<Vec<u8>, KernelError> {
    let ns = r.opts().ok_or(KernelError::NoChild)?.pid_ns_ref();
    let n = crate::task::pid::nr_ns(crate::task::percpu::current_pid(), ns);
    if n == 0 {
        return Err(KernelError::NotFound);
    }
    let mut d = [0u8; 10];
    let (mut v, mut k) = (n, d.len());
    while v > 0 {
        k -= 1;
        d[k] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let mut out = Vec::new();
    let ok = crate::util::kalloc::with_gfp(crate::mm::page_alloc::Gfp::ATOMIC, || {
        out.try_reserve_exact(d.len() - k).is_ok()
    });
    if !ok {
        return Err(KernelError::NoChild);
    }
    out.extend_from_slice(&d[k..]);
    Ok(out)
}

/// /proc/self (resolved at readlink time to the reader's pid)
fn create_self_link(parent: &Inode) -> Result<InodeRef, KernelError> {
    let sb = parent.superblock().expect("superblock dropped");
    let inode = Inode::alloc(Inode::new(
        pid_ino(0, 999),
        InodeMode::symlink(),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    set_data(&inode, ProcfsInodeData::SelfLink)?;
    Ok(inode)
}

/// Target of /proc/<pid>/fd/<fd>: `socket:[ino]`, `pipe:[ino]`,
/// `anon_inode:<name>` for the pseudo filesystems' files, else the path; EACCES without ptrace-read access, checked
/// at each read, not only at lookup in fd/ (Linux proc_pid_readlink,
/// proc_fd_access_allowed)
fn fd_link(pid: &ProcPid, fd: i32) -> Result<Vec<u8>, KernelError> {
    let t = link_task(pid)?;
    let table = task_files(&t).ok_or(KernelError::NotFound)?;
    let file = table.lock().get(fd).ok_or(KernelError::NotFound)?;
    let inode = file.get_inode().ok_or(KernelError::NotFound)?;
    // A pipe, socket, anonymous or namespace file: its pseudo fs's name
    // for it (Linux d_dname); a file of no filesystem (an mqueue) by
    // its dentry's name
    if let Some(n) = super::pseudo::dname(&file.dentry) {
        return Ok(n);
    }
    if inode.superblock().is_none() {
        return Ok([b"anon_inode:".as_slice(), &file.dentry.name()].concat());
    }
    match file.f_path() {
        Some(p) => super::dentry::d_path_link(&p),
        None => Ok(Vec::new()),
    }
}

/// /proc/<pid>/fd/<fd> leads to the open file itself, its pseudo fs
/// path for a pipe, socket or anonymous file (Linux proc_fd_link +
/// nd_jump_link), so a deleted or unnamed one (O_TMPFILE, memfd) can be
/// opened again, a pipe joined, and the walk goes on from a directory;
/// EACCES without ptrace-read access, checked at each follow (Linux
/// proc_pid_get_link, proc_fd_access_allowed); ENOENT once the fd is
/// closed
fn fd_jump(pid: &ProcPid, fd: i32) -> Result<crate::fs::Path, KernelError> {
    let t = link_task(pid)?;
    let table = task_files(&t).ok_or(KernelError::NotFound)?;
    let file = table.lock().get(fd).ok_or(KernelError::NotFound)?;
    file.f_path().ok_or(KernelError::NotFound)
}

/// Look up entries in /proc/<pid>/fd/
fn lookup_pid_fd_entry(dir: &Inode, p: &ProcPid, name: &str) -> Result<InodeRef, KernelError> {
    // The task, while its pid names one; its tid only numbers inodes
    let t = p.task().ok_or(KernelError::NotFound)?;
    let pid = t.tid();

    // Parse fd number from name
    let fd: i32 = name.parse().map_err(|_| KernelError::NotFound)?;
    if fd < 0 {
        return Err(KernelError::NotFound);
    }

    // The file at the fd, if any
    let file = task_files(&t)
        .and_then(|f| f.lock().get(fd))
        .ok_or(KernelError::NotFound)?;

    // Create symlink inode for /proc/<pid>/fd/<n>
    let sb = dir.superblock().ok_or(KernelError::Io)?;
    let inode = Inode::alloc(Inode::new(
        pid_ino(pid, FD_INO + fd as u64), // fd symlinks
        InodeMode::symlink(),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    fd_update_inode(&inode, &file);
    set_data(&inode, ProcfsInodeData::new_fd_symlink(p.clone(), fd))?;
    Ok(inode)
}

/// An fd/ link's mode follows the file's access (Linux
/// tid_fd_update_inode): r-x for reading, -wx for writing, none for a
/// path-only file; an fdinfo/ file keeps its own
fn fd_update_inode(inode: &Inode, file: &File) {
    if !inode.mode().is_symlink() {
        return;
    }
    let mut perm = 0;
    if file.is_readable() {
        perm |= 0o500;
    }
    if file.is_writable() {
        perm |= 0o300;
    }
    inode.set_mode_perm(perm);
}

/// Look up entries in /proc/<pid>/fdinfo/
fn lookup_pid_fdinfo_entry(dir: &Inode, p: &ProcPid, name: &str) -> Result<InodeRef, KernelError> {
    // The task, while its pid names one; its tid only numbers inodes
    let t = p.task().ok_or(KernelError::NotFound)?;
    let pid = t.tid();

    // Parse fd number from name
    let fd: i32 = name.parse().map_err(|_| KernelError::NotFound)?;
    if fd < 0 {
        return Err(KernelError::NotFound);
    }

    // Verify the FD exists for this task
    let fd_exists = task_files(&t).is_some_and(|f| f.lock().get(fd).is_some());
    if !fd_exists {
        return Err(KernelError::NotFound);
    }

    // Create regular file inode for /proc/<pid>/fdinfo/<n>
    let sb = dir.superblock().ok_or(KernelError::Io)?;
    let inode = Inode::alloc(Inode::new(
        pid_ino(pid, FDINFO_INO + fd as u64), // fdinfo files
        InodeMode::regular(0o444),            // r--r--r--
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    set_data(&inode, ProcfsInodeData::new_fdinfo_file(p.clone(), fd))?;
    Ok(inode)
}

/// /proc/<pid>/fdinfo/<n> (Linux seq_show): position, open flags
/// (O_CLOEXEC added for a close-on-exec descriptor) in octal with a
/// leading 0, the mount id, the inode number; then the file's own lines,
/// a pidfd's pids numbered in the mount's pid namespace `ns`
fn gen_fdinfo_content(t: &TaskRef, fd: i32, ns: &PidNamespace) -> Vec<u8> {
    use alloc::fmt::Write;
    let Some(table) = task_files(t) else {
        return Vec::new();
    };
    let (file, cloexec) = {
        let t = table.lock();
        match t.get(fd) {
            Some(f) => (f, t.get_fd_flags(fd) & crate::task::FD_CLOEXEC != 0),
            None => return Vec::new(),
        }
    };
    let mut flags = file.get_flags();
    if cloexec {
        flags |= super::file::flags::O_CLOEXEC;
    }
    let mnt_id = file.f_path().map_or(0, |p| p.mnt.mnt_id);
    let ino = file.get_inode().map_or(0, |i| i.ino);
    let mut out = String::new();
    let _ = write!(
        out,
        "pos:\t{}\nflags:\t0{:o}\nmnt_id:\t{}\nino:\t{}\n",
        file.get_pos(),
        flags,
        mnt_id,
        ino
    );
    crate::task::pidfd::show_fdinfo(&file, ns, &mut out);
    out.into_bytes()
}

/// The task `pid` names, if the caller may follow or read its fd/ and
/// ns/ links (Linux proc_fd_access_allowed, proc_ns_get_link /
/// proc_ns_readlink): EACCES once it is gone or without
/// PTRACE_MODE_READ_FSCREDS access
fn link_task(pid: &ProcPid) -> Result<TaskRef, KernelError> {
    let t = pid.task().ok_or(KernelError::PermissionDenied)?;
    if !crate::task::ptrace::may_access_task(&t, true) {
        return Err(KernelError::PermissionDenied);
    }
    Ok(t)
}

/// The `ns_type` namespace of the task `pid` names (Linux
/// proc_ns_get_link / proc_ns_readlink: EACCES without ptrace-read
/// access, ENOENT if it has none)
fn task_ns(pid: &ProcPid, ns_type: NamespaceType) -> Result<crate::ns::NsRef, KernelError> {
    let t = link_task(pid)?;
    ns_type.get(&t).ok_or(KernelError::NotFound)
}

/// Where the /proc link of the `ns_type` namespace of the task `pid`
/// leads: the namespace's nsfs file (Linux ns_get_path)
fn ns_file(pid: ProcPid, ns_type: NamespaceType) -> Result<crate::fs::Path, KernelError> {
    crate::fs::pseudo::nsfs::ns_get_path(task_ns(&pid, ns_type)?)
}

/// Generate content for /proc/<pid>/cgroup
///
/// Returns the cgroup membership for the process.
/// For cgroup v2, this is a single line: "0::<path>\n"
/// The path is relative to the task's cgroup namespace root.
fn gen_cgroup_content(t: &TaskRef) -> Vec<u8> {
    // cgroup v2 format: "0::<path>", the path's bytes as they are
    // The "0" indicates the unified hierarchy (cgroup v2)
    // The empty string between colons indicates no named controllers
    let mut output = Vec::from(b"0::".as_slice());
    output.extend_from_slice(&get_task_cgroup_path(t));
    output.push(b'\n');
    output
}

/// Generated files in /proc/<pid>/: name, inode offset, generator
/// Access checks a procfs file needs at open
enum OpenCheck {
    /// Address-space file of the task: pin its mm
    Mm(TaskRef),
}

/// The open-time check of `inode`, if any
fn open_check(inode: &Inode) -> Option<OpenCheck> {
    // Copied out, the task looked up after the inode data's lock
    let p = with_data(inode, |d| match d {
        ProcfsInodeData::PidFile {
            pid,
            generator: PidGen::Mm(_),
        } => Some(pid.clone()),
        _ => None,
    })??;
    Some(OpenCheck::Mm(p.task()?))
}

/// Content generator of a per-process file
#[derive(Clone, Copy)]
pub enum PidGen {
    /// World-readable content of the process
    Pub(fn(&TaskRef) -> Vec<u8>),
    /// World-readable content with pids in it, numbered in the mount's
    /// pid namespace (Linux proc_pid_ns(inode->i_sb))
    Ns(fn(&TaskRef, &PidNamespace) -> Vec<u8>),
    /// A mount table of the process (mounts, mountinfo): as `Pub`, and
    /// pollable (Linux mounts_poll)
    Mnt(fn(&mounts::MntView) -> Vec<u8>),
    /// Private content of the address space: open needs ptrace-read
    /// access and pins the mm it reads from (Linux proc_mem_open: an
    /// mm_count reference)
    Mm(fn(&crate::mm::Mm) -> Result<Vec<u8>, KernelError>),
}

/// The address space a /proc/<pid>/ file reads, if the caller may
/// (Linux mm_access): EACCES without ptrace-read access
///
/// Decided and taken under the process's exec_update_lock (read), which
/// exec holds for writing while it installs the new mm and
/// dumpability, so the result is never an mm the check did not cover
/// (Linux mm_access)
fn mm_access(t: &TaskRef) -> Result<Option<Arc<crate::mm::Mm>>, KernelError> {
    // The check and the mm it covers under the process's
    // exec_update_lock: no exec of it switches mm or dumpability between;
    // check and mm both of that one pinned task
    let _g = crate::signal::ExecUpdateRead::lock(t);
    if !crate::task::ptrace::may_access_task(t, true) {
        return Err(KernelError::PermissionDenied);
    }
    Ok(task_mm(t))
}

/// An open /proc file (Linux seq_file and the proc private data): the
/// address space it was opened on (maps), and what the last read
/// generated
struct ProcOpen {
    mm: Option<Arc<crate::mm::Mm>>,
    /// The mount namespace a mounts file was opened on and the number
    /// of its change last reported (Linux proc_mounts.ns,
    /// seq_file.poll_event)
    mnt: Option<MntOpen>,
    /// The network namespace a /proc/<pid>/net file was opened on
    /// (Linux seq_net_private.net: an active reference)
    net: Option<crate::net::NetRef>,
    /// Held across generation and the copy out, which may fault (Linux
    /// seq_file m->lock); under f_pos_lock for read()
    seq: crate::sync::Mutex<Option<SeqBuf>>,
}

/// One generation of a file and where the last read of it ended
struct SeqBuf {
    data: Vec<u8>,
    end: u64,
}

fn proc_open(file: &File) -> Option<Arc<ProcOpen>> {
    file.private.get()?.clone().downcast::<ProcOpen>().ok()
}

/// The namespace a /proc/<pid>/net inode is bound to
fn net_of(inode: &Inode) -> Option<Arc<crate::net::NetNamespace>> {
    with_data(inode, |d| match d {
        ProcfsInodeData::NetFile { net, .. } => Some(net.clone()),
        _ => None,
    })?
}

/// What a /proc/<pid>/mounts file shows, taken at its open (Linux
/// mounts_open_common: EINVAL without the task)
fn mnt_view_of(inode: &Inode) -> Result<mounts::MntView, KernelError> {
    let pid = with_data(inode, |d| match d {
        ProcfsInodeData::PidFile { pid, .. } => Some(pid.clone()),
        _ => None,
    })
    .flatten()
    .ok_or(KernelError::InvalidArgument)?;
    let t = pid.task().ok_or(KernelError::InvalidArgument)?;
    mounts::task_view(&t)
}

/// An open mounts file's view and the change number of its namespace
/// last reported (Linux proc_mounts, seq_file.poll_event)
struct MntOpen {
    view: mounts::MntView,
    seen: core::sync::atomic::AtomicU64,
}

/// The namespace an open /proc/<pid>/net file pinned
fn open_net(file: &File) -> Option<crate::net::NetRef> {
    proc_open(file)?.net.clone()
}

/// Content of a per-process file for this open file (or, with none,
/// checked afresh)
fn pid_content(file: Option<&File>, t: &TaskRef, g: PidGen) -> Result<Vec<u8>, KernelError> {
    match g {
        PidGen::Pub(f) => Ok(f(t)),
        // The namespace and root taken at open (afresh without a file)
        PidGen::Mnt(f) => {
            if let Some(p) = file.and_then(proc_open)
                && let Some(m) = &p.mnt
            {
                return Ok(f(&m.view));
            }
            Ok(f(&mounts::task_view(t)?))
        }
        PidGen::Ns(f) => {
            let ns = file
                .and_then(File::get_inode)
                .map_or_else(|| crate::ns::INIT_PID_NS.clone(), |i| opts::pid_ns(&i));
            Ok(f(t, &ns))
        }
        PidGen::Mm(f) => {
            let mm = match file.and_then(proc_open) {
                Some(p) => p.mm.clone(),
                None => mm_access(t)?,
            };
            // The open file pins only the struct (mm_count); a read uses
            // the address space only while it still has users, else it
            // reads as empty; once the task is reaped it is ESRCH (Linux
            // m_start: get_proc_task, mmget_not_zero)
            if !alive(t) {
                return Err(KernelError::NoProcess);
            }
            let users = mm.as_ref().and_then(crate::mm::mmget_not_zero);
            let Some(m) = users else {
                return Ok(Vec::new());
            };
            // The generator takes the mmap_lock itself, for as long as it
            // needs (a remote read faults with it released)
            f(&m)
        }
    }
}

/// Generated files in /proc/<pid>/: name, inode offset, mode (Linux
/// fs/proc/base.c tgid_base_stuff), generator
const PID_FILES: &[(&str, u64, u16, PidGen)] = &[
    ("cgroup", 102, 0o444, PidGen::Pub(gen_cgroup_content)),
    ("maps", 103, 0o444, PidGen::Mm(gen_maps)),
    ("status", 105, 0o444, PidGen::Ns(array::gen_status)),
    ("stat", 106, 0o444, PidGen::Ns(array::gen_stat)),
    ("cmdline", 107, 0o444, PidGen::Pub(array::gen_cmdline)),
    ("environ", 108, 0o400, PidGen::Mm(array::gen_environ)),
    ("mounts", 109, 0o444, PidGen::Mnt(mounts::show_mounts)),
    ("mountinfo", 110, 0o444, PidGen::Mnt(mounts::show_mountinfo)),
];

/// How a /proc file polls (Linux: which fops it has)
#[derive(PartialEq)]
enum ProcPoll {
    /// No poll: proc dirs, per-process files, fdinfo, ns, fail-nth
    None,
    /// DEFAULT_POLLMASK: proc_dir_entry files (proc_reg_poll), sysctls
    /// (proc_sys_poll)
    Default,
    /// mounts, mountinfo (mounts_poll)
    Mounts,
}

fn proc_poll(file: &File) -> ProcPoll {
    let Some(inode) = file.get_inode() else {
        return ProcPoll::None;
    };
    with_data(&inode, |d| match d {
        ProcfsInodeData::File { .. }
        | ProcfsInodeData::NetFile { .. }
        | ProcfsInodeData::Sysctl { .. } => ProcPoll::Default,
        ProcfsInodeData::PidFile {
            generator: PidGen::Mnt(_),
            ..
        } => ProcPoll::Mounts,
        _ => ProcPoll::None,
    })
    .unwrap_or(ProcPoll::None)
}

/// The process of a /proc/<pid>/fail-nth inode
fn fail_nth_of(inode: &Inode) -> Option<ProcPid> {
    with_data(inode, |d| match d {
        ProcfsInodeData::FailNth { pid } => Some(pid.clone()),
        _ => None,
    })?
}

/// Set task `pid`'s countdown from a decimal (or 0x/0 prefixed) number
/// (Linux proc_fail_nth_write: kstrtouint, any task the file names)
fn write_fail_nth(t: &TaskRef, from: &mut IovSource<'_>) -> Result<usize, KernelError> {
    let mut buf = [0u8; 24];
    let len = from.len();
    if len > buf.len() {
        return Err(KernelError::InvalidArgument);
    }
    from.copy_from_full(&mut buf[..len])?;
    let text = core::str::from_utf8(&buf[..len]).map_err(|_| KernelError::InvalidArgument)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let n = match text.strip_prefix("0x") {
        Some(h) => u32::from_str_radix(h, 16),
        None => text.parse::<u32>(),
    }
    .map_err(|_| KernelError::InvalidArgument)?;
    t.fail_nth.store(n, core::sync::atomic::Ordering::Relaxed);
    Ok(len)
}

/// Inode offset of /proc/<pid>/fail-nth
const FAIL_NTH_INO: u64 = 113;

/// What a per-process symlink names (Linux proc_exe_link,
/// proc_cwd_link, proc_root_link)
#[derive(Clone, Copy, Debug)]
pub enum PidLinkKind {
    Exe,
    Cwd,
    Root,
}

/// Per-process symlinks: name, inode offset, what they name
const PID_LINKS: &[(&str, u64, PidLinkKind)] = &[
    ("exe", 104, PidLinkKind::Exe),
    ("cwd", 111, PidLinkKind::Cwd),
    ("root", 112, PidLinkKind::Root),
];

fn pid_file(name: &str) -> Option<(u64, u16, PidGen)> {
    PID_FILES
        .iter()
        .find(|(n, _, _, _)| *n == name)
        .map(|&(_, off, mode, g)| (off, mode, g))
}

/// Owner of a /proc/<pid> inode of `mode` (Linux task_dump_owner): a
/// kernel thread's are root's; else the task's euid/egid (its
/// credentials read under RCU), but for anything other than a
/// world-readable and -searchable directory root's while it is not
/// dumpable or has no address space (task_lock). No sleeping lock: an
/// RCU walk asks too.
fn task_dump_owner(t: &crate::task::Task, mode: InodeMode) -> (u32, u32) {
    if t.has_flag(crate::task::pf::KTHREAD) {
        return (0, 0);
    }
    let (uid, gid) = {
        let g = crate::sync::rcu::read_lock();
        let c = t.cred_rcu(&g);
        (c.euid, c.egid)
    };
    if mode.raw() == InodeMode::directory(0o555).raw() {
        return (uid, gid);
    }
    let dumpable = t
        .task_lock()
        .mm()
        .map(|m| m.dumpable() == crate::task::dumpable::SUID_DUMP_USER);
    match dumpable {
        Some(true) => (uid, gid),
        _ => (0, 0),
    }
}

/// The process a per-process file belongs to
fn pid_file_pid(inode: &Inode) -> Option<TaskRef> {
    let p = with_data(inode, |d| match d {
        ProcfsInodeData::PidFile { pid, .. } => Some(pid.clone()),
        _ => None,
    })??;
    p.task()
}

/// What /proc/<pid>/cwd, root or exe names: the task's fs pwd or root
/// (ENOENT for a task without one), its executable (through
/// mm_access, so the check and the image it reveals are one:
/// exec_update_lock read; ENOENT for a kernel thread); EACCES without
/// ptrace-read access (Linux proc_fd_access_allowed). readlink shows it
/// as the reader names it, a follow jumps to it. An exec resolving
/// /proc/self/exe (busybox re-execs itself) holds only cred_guard while
/// it walks paths: it takes exec_update for writing later, in
/// exec_replace_image.
fn pid_link_path(t: &TaskRef, k: PidLinkKind) -> Result<crate::fs::Path, KernelError> {
    if !crate::task::ptrace::may_access_task(t, true) {
        return Err(KernelError::PermissionDenied);
    }
    match k {
        PidLinkKind::Cwd | PidLinkKind::Root => {
            let fs = crate::fs::get_task_fs(t).ok_or(KernelError::NotFound)?;
            Ok(if matches!(k, PidLinkKind::Root) {
                fs.get_root()
            } else {
                fs.get_pwd()
            })
        }
        PidLinkKind::Exe => {
            let mm = mm_access(t)?.ok_or(KernelError::NotFound)?;
            let exe = mm.mmap_read_killable()?.exe();
            exe.ok_or(KernelError::NotFound)
        }
    }
}

/// /proc/<pid>/maps: one line per VMA (Linux show_map_vma)
fn gen_maps(m: &crate::mm::Mm) -> Result<Vec<u8>, KernelError> {
    let g = m.mmap_read_killable()?;
    maps_of(&g)
}

/// /proc/<pid>/maps of `mm`, its mmap_lock held: each line is bounded
/// (a name is at most PATH_MAX), the whole grows with the VMA count
/// through a fallible buffer (ENOMEM)
fn maps_of(mm: &crate::mm::MmStruct) -> Result<Vec<u8>, KernelError> {
    use crate::mm::{PROT_EXEC, PROT_READ, PROT_WRITE, VM_GROWSDOWN, VM_SHARED};
    use alloc::fmt::Write;
    let mut out = crate::util::kmem::KVec::new();
    let (start_brk, brk) = (mm.get_start_brk(), mm.get_brk());
    for v in mm.iter() {
        let bit = |b: bool, c: char| if b { c } else { '-' };
        let (ino, dev, name) = match &v.file {
            Some(f) => {
                let ino = f.get_inode().map(|i| i.ino).unwrap_or(0);
                // seq_file_path(m, file, "\n"): a newline in a name
                // cannot start a forged line
                let mut p = Vec::new();
                let name = f
                    .f_path()
                    .and_then(|fp| super::dentry::d_path_link(&fp).ok());
                super::name::mangle(&mut p, &name.unwrap_or_default(), b"\n");
                (ino, "00:00", p)
            }
            None if v.flags & VM_GROWSDOWN != 0 => (0, "00:00", b"[stack]".to_vec()),
            None if v.flags & crate::mm::VM_SIGPAGE != 0 => (0, "00:00", b"[sigpage]".to_vec()),
            None if v.start >= start_brk
                && v.end <= brk.next_multiple_of(4096)
                && brk > start_brk =>
            {
                (0, "00:00", b"[heap]".to_vec())
            }
            None => (0, "00:00", Vec::new()),
        };
        let mut line = String::new();
        let _ = write!(
            line,
            "{:08x}-{:08x} {}{}{}{} {:08x} {} {} ",
            v.start,
            v.end,
            bit(v.prot & PROT_READ != 0, 'r'),
            bit(v.prot & PROT_WRITE != 0, 'w'),
            bit(v.prot & PROT_EXEC != 0, 'x'),
            if v.flags & VM_SHARED != 0 { 's' } else { 'p' },
            if v.file.is_some() { v.offset } else { 0 },
            dev,
            ino
        );
        let mut line = line.into_bytes();
        if !name.is_empty() {
            line.resize(line.len().max(73), b' ');
            line.extend_from_slice(&name);
        }
        while line.last() == Some(&b' ') {
            line.pop();
        }
        line.push(b'\n');
        out.try_extend_from_slice(&line)?;
    }
    Ok(out.into_vec())
}

/// The cgroup path of task `t`, seen from the reader's cgroup namespace
fn get_task_cgroup_path(t: &TaskRef) -> Vec<u8> {
    use crate::ns::INIT_CGROUP_NS;

    // Get the task's cgroup
    let task_cgroup = t.cgroup.lock().clone();

    let Some(cgroup) = task_cgroup else {
        // Task not in any cgroup - return root
        return Vec::from(b"/".as_slice());
    };

    // Seen from the reader's cgroup namespace (Linux proc_cgroup_show:
    // current->nsproxy->cgroup_ns)
    let cgroup_ns = crate::task::percpu::current()
        .nsproxy()
        .map_or_else(|| INIT_CGROUP_NS.clone(), |ns| ns.cgroup_ns.clone());
    cgroup_ns.translate_path(&cgroup)
}

/// The content of the procfs file `file` (Linux: its show() / sysctl
/// handler output). Per-process generators may sleep (exec_update_lock,
/// mmap_lock): they run after the inode data's spinning read lock is
/// dropped.
fn proc_content(file: &File) -> Result<Vec<u8>, KernelError> {
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    // What to generate, copied out: no generator runs under the
    // inode's spin lock (they allocate and take TASKLIST, network and
    // mount locks; Linux seq_file show() runs under no inode lock)
    enum Gen {
        Pid(ProcPid, PidGen),
        File(ContentGenerator),
        Fdinfo(ProcPid, i32),
        Sysctl(&'static crate::sysctl::Ctl),
        FailNth(ProcPid),
        Net(proc_net::NetGen),
    }
    let g = with_data(&inode, |d| -> Result<_, KernelError> {
        Ok(match d {
            ProcfsInodeData::PidFile { pid, generator } => Gen::Pid(pid.clone(), *generator),
            ProcfsInodeData::File { generator } => Gen::File(*generator),
            // A namespace file has no read (Linux ns_file_operations)
            ProcfsInodeData::NamespaceFile { .. } => return Err(KernelError::InvalidArgument),
            ProcfsInodeData::FdinfoFile { pid, fd } => Gen::Fdinfo(pid.clone(), *fd),
            ProcfsInodeData::Sysctl { ctl } => Gen::Sysctl(ctl),
            ProcfsInodeData::FailNth { pid } => Gen::FailNth(pid.clone()),
            ProcfsInodeData::NetFile { generator, .. } => Gen::Net(*generator),
            ProcfsInodeData::FdSymlink { .. }
            | ProcfsInodeData::PidLink { .. }
            | ProcfsInodeData::SelfLink
            | ProcfsInodeData::FixedLink(_) => return Err(KernelError::Io),
            ProcfsInodeData::Directory { .. }
            | ProcfsInodeData::PidDirectory { .. }
            | ProcfsInodeData::PidTaskDirectory { .. }
            | ProcfsInodeData::PidNsDirectory { .. }
            | ProcfsInodeData::PidFdDirectory { .. }
            | ProcfsInodeData::PidNetDirectory { .. }
            | ProcfsInodeData::PidFdinfoDirectory { .. } => return Err(KernelError::IsDirectory),
        })
    })
    .ok_or(KernelError::Io)??;
    // A per-process file of a reaped task reads ESRCH (Linux
    // proc_single_show: get_pid_task fails)
    let task = |p: &ProcPid| p.task().ok_or(KernelError::NoProcess);
    Ok(match g {
        // A mounts file shows what its open took, the task gone or not
        // (Linux mounts_open_common pins the namespace and root)
        Gen::Pid(_, PidGen::Mnt(f)) if proc_open(file).is_some_and(|p| p.mnt.is_some()) => {
            let p = proc_open(file).ok_or(KernelError::Io)?;
            p.mnt.as_ref().map_or_else(Vec::new, |m| f(&m.view))
        }
        Gen::Pid(p, g) => return pid_content(Some(file), &task(&p)?, g),
        Gen::File(ContentGenerator::Plain(g)) => g(),
        Gen::File(ContentGenerator::Opener(g)) => g(file),
        Gen::Fdinfo(p, fd) => gen_fdinfo_content(&task(&p)?, fd, &opts::pid_ns(&inode)),
        Gen::Sysctl(ctl) => crate::sysctl::read(ctl),
        Gen::FailNth(p) => {
            let n = task(&p)?
                .fail_nth
                .load(core::sync::atomic::Ordering::Relaxed);
            alloc::format!("{n}\n").into_bytes()
        }
        // The namespace the open pinned (Linux seq_file_net): every
        // open of a net file pins one or fails with ENXIO
        Gen::Net(generator) => {
            let n = open_net(file).ok_or(KernelError::NoDeviceOrAddress)?;
            generator(&n)
        }
    })
}

/// Static procfs inode ops
pub static PROCFS_INODE_OPS: ProcfsInodeOps = ProcfsInodeOps;

/// Procfs file operations
pub struct ProcfsFileOps;

impl FileOps for ProcfsFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// No procfs file maps (its readers may take the mmap_lock a fault
    /// holds): proc_dir_entry files fail in pde_mmap (EIO), per-process
    /// and sysctl files have no mmap (ENODEV)
    fn mmap(&self, file: &File, _shared: bool) -> Result<(), KernelError> {
        let pde = file.get_inode().is_some_and(|i| {
            with_data(&i, |d| {
                matches!(
                    d,
                    ProcfsInodeData::File { .. } | ProcfsInodeData::NetFile { .. }
                )
            })
            .unwrap_or(false)
        });
        Err(if pde {
            KernelError::Io
        } else {
            KernelError::NoDevice
        })
    }

    /// A mount table is readable, and POLLERR|POLLPRI once after each
    /// change of its namespace's mounts (Linux mounts_poll); the rest
    /// DEFAULT_POLLMASK (vfs_poll)
    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        use core::sync::atomic::Ordering;
        if proc_poll(file) != ProcPoll::Mounts {
            return DEFAULT_POLLMASK;
        }
        let Some(po) = proc_open(file) else {
            return POLLIN | POLLRDNORM;
        };
        let Some(MntOpen { view, seen }) = po.mnt.as_ref() else {
            return POLLIN | POLLRDNORM;
        };
        let ev = &view.ns.events;
        if let Some(pt) = pt {
            pt.poll_wait(&ev.poll);
        }
        let event = ev.event();
        let mut res = POLLIN | POLLRDNORM;
        if seen.swap(event, Ordering::AcqRel) != event {
            res |= crate::io::poll::POLLERR | crate::io::poll::POLLPRI;
        }
        res
    }

    fn can_poll(&self, file: &File) -> bool {
        proc_poll(file) != ProcPoll::None
    }

    /// Address-space files check ptrace-read access at open (Linux
    /// proc_mem_open); maps keeps the address
    /// space it was opened on, so a later setuid exec cannot leak
    fn open(&self, file: &File) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let mm = match open_check(&inode) {
            Some(OpenCheck::Mm(t)) => mm_access(&t)?,
            None => None,
        };
        // A /proc/<pid>/net file pins its namespace while it lives
        // (Linux seq_open_net: get_proc_net, else ENXIO)
        let net = match net_of(&inode) {
            Some(n) => Some(n.maybe_get().ok_or(KernelError::NoDeviceOrAddress)?),
            None => None,
        };
        let mnt = match proc_poll(file) {
            ProcPoll::Mounts => {
                let view = mnt_view_of(&inode)?;
                let seen = core::sync::atomic::AtomicU64::new(view.ns.events.event());
                Some(MntOpen { view, seen })
            }
            _ => None,
        };
        // A generated file keeps its last generation (seq_file)
        if inode.mode().is_file() && sysctl_of(&inode).is_none() && fail_nth_of(&inode).is_none() {
            let po = try_arc(ProcOpen {
                mm,
                mnt,
                net,
                seq: crate::sync::Mutex::new(None),
            })?;
            file.private.call_once(|| po);
        }
        Ok(())
    }

    /// Generate the content and copy it from the offset on (Linux
    /// seq_read_iter / proc_sys_read); no FMODE_NOWAIT: RWF_NOWAIT is
    /// EOPNOTSUPP
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        rw: RwFlags,
    ) -> Result<usize, KernelError> {
        if rw.nowait() {
            return Err(KernelError::OperationNotSupported);
        }
        let pos = at.unwrap_or_else(|| file.get_pos());
        // A numeric sysctl reads only from offset 0 (Linux
        // do_proc_dointvec: *ppos on a read is EOF); a text one from
        // any (proc_dostring)
        if pos != 0
            && let Some(inode) = file.get_inode()
            && sysctl_of(&inode).is_some_and(|c| c.text.is_none())
        {
            return Ok(0);
        }
        let n = match proc_open(file) {
            Some(po) => seq_read(file, &po, to, pos)?,
            None => {
                let content = proc_content(file)?;
                copy_from(&content, to, pos)?
            }
        };
        if at.is_none() {
            file.advance_pos(n as u64);
        }
        Ok(n)
    }

    /// Writes reach /proc/sys files only, at `at` or the file position
    /// (Linux proc_sys_write: iocb->ki_pos): one store of at most
    /// `WRITE_CHUNK` bytes
    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        rw: RwFlags,
    ) -> Result<usize, KernelError> {
        if rw.nowait() {
            return Err(KernelError::OperationNotSupported);
        }
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        if let Some(p) = fail_nth_of(&inode) {
            return write_fail_nth(&p.task().ok_or(KernelError::NoProcess)?, from);
        }
        let ctl = sysctl_of(&inode).ok_or(KernelError::Io)?;
        crate::sysctl::permission(ctl, &crate::task::current_cred(), crate::fs::MAY_WRITE)?;
        let mut buf = crate::util::kmem::try_vec(from.len().min(WRITE_CHUNK), 0u8)?;
        // Whole or EFAULT (Linux proc_sys_call_handler)
        from.copy_from_full(&mut buf)?;
        let n = crate::sysctl::write(ctl, &buf, at.unwrap_or_else(|| file.get_pos()))?;
        if at.is_none() {
            file.advance_pos(n as u64);
        }
        Ok(n)
    }

    fn readdir(&self, file: &File, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;

        if !inode.mode().is_dir() {
            return Err(KernelError::NotDirectory);
        }

        // What the directory is, copied out (the static children by a
        // shared reference): entries are emitted, and TASKLIST taken,
        // with the inode data's spin lock released
        enum Dir {
            Static(Arc<BTreeMap<String, InodeRef>>),
            Pid(ProcPid),
            Ns(ProcPid),
            Fd(ProcPid),
            Task(ProcPid),
            Fdinfo(ProcPid),
            Net(ProcPid),
        }
        let kind = with_data(&inode, |d| -> Result<_, KernelError> {
            Ok(match d {
                ProcfsInodeData::Directory { children } => Dir::Static(children.clone()),
                ProcfsInodeData::PidDirectory { pid } => Dir::Pid(pid.clone()),
                ProcfsInodeData::PidNsDirectory { pid } => Dir::Ns(pid.clone()),
                ProcfsInodeData::PidFdDirectory { pid } => Dir::Fd(pid.clone()),
                ProcfsInodeData::PidTaskDirectory { pid } => Dir::Task(pid.clone()),
                ProcfsInodeData::PidFdinfoDirectory { pid } => Dir::Fdinfo(pid.clone()),
                ProcfsInodeData::PidNetDirectory { pid } => Dir::Net(pid.clone()),
                ProcfsInodeData::File { .. }
                | ProcfsInodeData::NamespaceFile { .. }
                | ProcfsInodeData::FdSymlink { .. }
                | ProcfsInodeData::PidLink { .. }
                | ProcfsInodeData::SelfLink
                | ProcfsInodeData::FixedLink(_)
                | ProcfsInodeData::FdinfoFile { .. }
                | ProcfsInodeData::PidFile { .. }
                | ProcfsInodeData::FailNth { .. }
                | ProcfsInodeData::NetFile { .. }
                | ProcfsInodeData::Sysctl { .. } => return Err(KernelError::NotDirectory),
            })
        })
        .ok_or(KernelError::Io)??;

        // A reaped task's directory lists nothing, not even "." (Linux
        // proc_pident_readdir: ENOENT)
        let task = match &kind {
            Dir::Static(_) => None,
            Dir::Pid(p) | Dir::Ns(p) | Dir::Fd(p) | Dir::Task(p) | Dir::Fdinfo(p) | Dir::Net(p) => {
                Some(p.task().ok_or(KernelError::NotFound)?)
            }
        };
        let task = task.as_ref();

        // Emit "." and ".."
        let should_continue = ctx.emit(DirEntry {
            ino: inode.ino,
            file_type: FileType::Directory,
            name: Vec::from(b"."),
        });

        if !should_continue {
            return Ok(());
        }

        let parent_ino = file
            .dentry
            .get_parent()
            .and_then(|p| p.get_inode())
            .map(|i| i.ino)
            .unwrap_or(inode.ino);

        let should_continue = ctx.emit(DirEntry {
            ino: parent_ino,
            file_type: FileType::Directory,
            name: Vec::from(b".."),
        });

        if !should_continue {
            return Ok(());
        }

        match kind {
            Dir::Static(children) => {
                let pidonly = children.contains_key("version")
                    && opts::with(&inode, |o| o.pidonly()).unwrap_or(false);
                // Emit static children
                for (name, child_inode) in children.iter().filter(|_| !pidonly) {
                    let file_type = child_inode.mode().file_type().unwrap_or(FileType::Regular);

                    let should_continue = ctx.emit(DirEntry {
                        ino: child_inode.ino,
                        file_type,
                        name: Vec::from(name.as_bytes()),
                    });

                    if !should_continue {
                        return Ok(());
                    }
                }

                // /proc root (has "version"): "self", then the PIDs
                if children.contains_key("version") {
                    let me = DirEntry {
                        ino: pid_ino(0, 999),
                        file_type: FileType::Symlink,
                        name: Vec::from(b"self"),
                    };
                    if !ctx.emit(me) {
                        return Ok(());
                    }
                    readdir_emit_pids(&inode, ctx)?;
                }
            }
            Dir::Pid(_) => readdir_emit_pid_entries(task.map_or(0, |t| t.tid()), ctx)?,
            Dir::Ns(_) => readdir_emit_ns_entries(task.map_or(0, |t| t.tid()), ctx)?,
            Dir::Fd(_) => readdir_emit_fd_entries(task, ctx)?,
            Dir::Task(_) => {
                let Some(t) = task else {
                    return Ok(());
                };
                for (_, tid, nr) in group_threads(t, &opts::pid_ns(&inode)) {
                    let e = DirEntry {
                        ino: pid_ino(tid, 0),
                        file_type: FileType::Directory,
                        name: Vec::from(alloc::format!("{nr}").as_bytes()),
                    };
                    if !ctx.emit(e) {
                        break;
                    }
                }
            }
            Dir::Fdinfo(_) => readdir_emit_fdinfo_entries(task, ctx)?,
            Dir::Net(_) => {
                if let Some(t) = task {
                    proc_net::readdir(t, ctx)?;
                }
            }
        }

        Ok(())
    }
}

/// First readdir position of the PID entries in /proc (Linux
/// FIRST_PROCESS_ENTRY): the static entries sit below it
const PID_POS: u64 = 256;

/// Emit PID directory entries for /proc readdir: the processes visible
/// in the mount's pid namespace, by their numbers there; a process's
/// position is PID_POS + that number (Linux proc_pid_readdir, next_tgid),
/// stable while others exit
fn readdir_emit_pids(root: &Inode, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
    let ns = opts::pid_ns(root);
    // Each group leader, by its number in ns, gathered with no
    // allocation under TASKLIST (references dropped after it)
    let mut pids = crate::task::percpu::GlobalTaskTable::collect_tasks(|_, t| {
        if t.task.tid() != t.task.pid || t.task.pid == 0 {
            return None;
        }
        let nr = t.thread_pid()?.nr_in(&ns)?;
        Some((nr, crate::task::percpu::task_ref(t.task)))
    });
    pids.sort_unstable_by_key(|&(nr, _)| nr);

    // hidepid=invisible: other users' processes are left out
    for (nr, t) in pids
        .into_iter()
        .filter(|(_, t)| opts::with(root, |o| o.visible(t)).unwrap_or(true))
    {
        let e = DirEntry {
            ino: pid_ino(t.tid(), 0),
            file_type: FileType::Directory,
            name: Vec::from(alloc::format!("{nr}").as_bytes()),
        };
        if !ctx.emit_at(PID_POS + u64::from(nr), e) {
            break;
        }
    }

    Ok(())
}

/// Emit entries for /proc/<pid>/ directory
fn readdir_emit_pid_entries(pid: Pid, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
    // Emit "ns" subdirectory
    let should_continue = ctx.emit(DirEntry {
        ino: pid_ino(pid, 1),
        file_type: FileType::Directory,
        name: Vec::from(b"ns"),
    });

    if !should_continue {
        return Ok(());
    }

    // Emit "fd" subdirectory
    let should_continue = ctx.emit(DirEntry {
        ino: pid_ino(pid, 100),
        file_type: FileType::Directory,
        name: Vec::from(b"fd"),
    });

    if !should_continue {
        return Ok(());
    }

    if !ctx.emit(DirEntry {
        ino: pid_ino(pid, 120),
        file_type: FileType::Directory,
        name: Vec::from(&b"task"[..]),
    }) {
        return Ok(());
    }

    if !ctx.emit(DirEntry {
        ino: pid_ino(pid, proc_net::NET_DIR_INO),
        file_type: FileType::Directory,
        name: Vec::from(&b"net"[..]),
    }) {
        return Ok(());
    }

    // Emit "fdinfo" subdirectory
    let should_continue = ctx.emit(DirEntry {
        ino: pid_ino(pid, 101),
        file_type: FileType::Directory,
        name: Vec::from(b"fdinfo"),
    });

    if !should_continue {
        return Ok(());
    }

    if !ctx.emit(DirEntry {
        ino: pid_ino(pid, FAIL_NTH_INO),
        file_type: FileType::Regular,
        name: Vec::from(&b"fail-nth"[..]),
    }) {
        return Ok(());
    }

    for (name, off, _) in PID_LINKS {
        let more = ctx.emit(DirEntry {
            ino: pid_ino(pid, *off),
            file_type: FileType::Symlink,
            name: Vec::from(name.as_bytes()),
        });
        if !more {
            return Ok(());
        }
    }
    for (name, off, _, _) in PID_FILES {
        let more = ctx.emit(DirEntry {
            ino: pid_ino(pid, *off),
            file_type: FileType::Regular,
            name: Vec::from(name.as_bytes()),
        });
        if !more {
            return Ok(());
        }
    }

    Ok(())
}

/// Emit entries for /proc/<pid>/ns/ directory
fn readdir_emit_ns_entries(pid: Pid, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
    // Emit all namespace files
    for ns_type in NamespaceType::all() {
        let should_continue = ctx.emit(DirEntry {
            ino: pid_ino(pid, ns_type.offset()),
            file_type: FileType::Symlink,
            name: Vec::from(ns_type.as_str().as_bytes()),
        });

        if !should_continue {
            break;
        }
    }

    Ok(())
}

/// Emit entries for /proc/<pid>/fd/ directory
fn readdir_emit_fd_entries(
    t: Option<&TaskRef>,
    ctx: &mut DirContext<'_>,
) -> Result<(), KernelError> {
    let Some(t) = t else {
        return Ok(());
    };
    // Its tid only numbers the inodes
    let pid = t.tid();

    let Some(files) = task_files(t) else {
        return Ok(());
    };
    // One descriptor per table lock hold, emitted after it (Linux
    // proc_readfd_common: fget_task_next)
    let fds = core::iter::successors(files.lock().next_installed(0), |&fd| {
        files.lock().next_installed(fd as usize + 1)
    });

    // Emit all FD symlinks
    for fd in fds {
        let name = alloc::format!("{}", fd);
        // Position fd + 2, after "." and ".." (Linux proc_readfd_common)
        let should_continue = ctx.emit_at(
            fd as u64 + 2,
            DirEntry {
                ino: pid_ino(pid, FD_INO + fd as u64),
                file_type: FileType::Symlink,
                name: Vec::from(name.as_bytes()),
            },
        );

        if !should_continue {
            break;
        }
    }

    Ok(())
}

/// Emit entries for /proc/<pid>/fdinfo/ directory
fn readdir_emit_fdinfo_entries(
    t: Option<&TaskRef>,
    ctx: &mut DirContext<'_>,
) -> Result<(), KernelError> {
    let Some(t) = t else {
        return Ok(());
    };
    // Its tid only numbers the inodes
    let pid = t.tid();

    let Some(files) = task_files(t) else {
        return Ok(());
    };
    // One descriptor per table lock hold, emitted after it (Linux
    // proc_readfd_common: fget_task_next)
    let fds = core::iter::successors(files.lock().next_installed(0), |&fd| {
        files.lock().next_installed(fd as usize + 1)
    });

    // Emit all fdinfo files
    for fd in fds {
        let name = alloc::format!("{}", fd);
        // Position fd + 2, after "." and ".." (Linux proc_readfd_common)
        let should_continue = ctx.emit_at(
            fd as u64 + 2,
            DirEntry {
                ino: pid_ino(pid, FDINFO_INO + fd as u64),
                file_type: FileType::Regular,
                name: Vec::from(name.as_bytes()),
            },
        );

        if !should_continue {
            break;
        }
    }

    Ok(())
}

/// Static procfs file ops
pub static PROCFS_FILE_OPS: ProcfsFileOps = ProcfsFileOps;

/// Procfs superblock operations
pub struct ProcfsSuperOps;

impl SuperOps for ProcfsSuperOps {
    /// Linux proc_reconfigure: hidepid=, gid=, subset=
    fn remount(&self, sb: &SuperBlock, data: &[u8]) -> Result<(), KernelError> {
        opts::with_sb(sb, |o| o.apply(data)).unwrap_or(Ok(()))
    }

    fn show_options(&self, sb: &SuperBlock, out: &mut Vec<u8>) {
        opts::with_sb(sb, |o| o.show(out));
    }

    fn statfs(&self, _sb: &SuperBlock) -> Result<StatFs, KernelError> {
        Ok({
            StatFs {
                f_type: PROC_SUPER_MAGIC,
                f_bsize: 4096,
                f_namelen: 255,
                ..StatFs::default()
            }
        })
    }

    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        i_op: &'static dyn InodeOps,
    ) -> Result<InodeRef, KernelError> {
        let inode = Inode::alloc(Inode::new(
            sb.alloc_ino(),
            mode,
            0, // uid: root owns all procfs entries
            0, // gid: root group
            0,
            current_time(),
            Arc::downgrade(sb),
            i_op,
        ))?;

        // Default to empty directory
        set_data(&inode, ProcfsInodeData::new_dir()?)?;

        Ok(inode)
    }
}

/// The process of a /proc/<pid> or /proc/<pid>/task/<tid> directory
fn pid_dir_pid(inode: &Inode) -> Option<TaskRef> {
    let pid = with_data(inode, |d| match d {
        ProcfsInodeData::PidDirectory { pid } => Some(pid.clone()),
        _ => None,
    })??;
    pid.task()
}

/// `data` from offset `pos` on into `to`
fn copy_from(data: &[u8], to: &mut IovDest<'_>, pos: u64) -> Result<usize, KernelError> {
    match usize::try_from(pos).ok().and_then(|p| data.get(p..)) {
        Some(rest) if !rest.is_empty() => to.copy_to(rest),
        _ => Ok(0),
    }
}

/// Linux seq_read_iter of a single_open file: a read that continues
/// where the last one ended reads the same generation, so chunked reads
/// never mix two (a record torn between them); any other offset, 0
/// included, generates afresh
fn seq_read(
    file: &File,
    po: &ProcOpen,
    to: &mut IovDest<'_>,
    pos: u64,
) -> Result<usize, KernelError> {
    let mut seq = po.seq.lock();
    let stale = !matches!(&*seq, Some(b) if pos != 0 && b.end == pos);
    if stale {
        *seq = Some(SeqBuf {
            data: proc_content(file)?,
            end: pos,
        });
    }
    let b = seq.as_mut().ok_or(KernelError::Io)?;
    let n = copy_from(&b.data, to, pos)?;
    b.end = pos + n as u64;
    Ok(n)
}

/// Static procfs super ops
pub static PROCFS_SUPER_OPS: ProcfsSuperOps = ProcfsSuperOps;

// --- Content generators for procfs files ---

/// Generate /proc/version content
fn gen_version() -> Vec<u8> {
    use alloc::fmt::Write;
    let mut output = alloc::string::String::new();
    let _ = writeln!(output, "hk {}", env!("CARGO_PKG_VERSION"));
    Vec::from(output.as_bytes())
}

/// /proc/cmdline: the kernel command line (Linux cmdline_proc_show)
fn gen_cmdline() -> Vec<u8> {
    let mut v = Vec::from(crate::cmdline::saved().as_bytes());
    v.push(b'\n');
    v
}

/// Generate /proc/meminfo content (Linux meminfo_proc_show subset:
/// 16-column labels, values in kB). Free memory is the frame
/// allocator's exact count; Buffers is the block devices' caches,
/// Cached the rest of the page cache (ramfs included, as Linux counts
/// tmpfs), Unevictable ramfs's, MemAvailable free plus the clean
/// evictable cache. Writeback is 0 (writes are synchronous). Shmem is
/// tmpfs's pages (SysV shm and shared anonymous memory included). Slab
/// is the slab caches' pages.
fn gen_meminfo() -> Vec<u8> {
    use alloc::fmt::Write;
    let fa = &crate::FRAME_ALLOCATOR;
    let total = fa.stats().total_bytes >> 10;
    let free = (fa.free_frames() as u64 * 4096) >> 10;
    let slab = (crate::mm::slab::slab_bytes() as u64) >> 10;
    let (swap_total, swap_free) = crate::mm::swap::swapfile::swap_totals();
    let swap_cached = crate::mm::swap::swap_state::total_cached();
    let mut out = String::new();
    use crate::mm::filemap;
    let file = filemap::nr_file_pages() * 4;
    let buffers = crate::block::blkdev::nr_blockdev_pages() * 4;
    let dirty = filemap::nr_dirty() * 4;
    let unevict = filemap::nr_unevictable() * 4;
    // What reclaim could free without I/O (Linux si_mem_available,
    // without the low-watermark and half-of-cache reserve)
    let avail = free + file.saturating_sub(unevict + dirty);
    for (label, kb) in [
        ("MemTotal:", total),
        ("MemFree:", free),
        ("MemAvailable:", avail),
        ("Buffers:", buffers),
        ("Cached:", file.saturating_sub(buffers)),
        ("SwapCached:", swap_cached * 4),
        ("Unevictable:", unevict),
        ("SwapTotal:", swap_total * 4),
        ("SwapFree:", swap_free * 4),
        ("Dirty:", dirty),
        ("Writeback:", 0),
        ("Shmem:", filemap::nr_shmem() * 4),
        ("Slab:", slab),
    ] {
        let _ = writeln!(out, "{label:<16}{kb:>8} kB");
    }
    out.into_bytes()
}

/// The sysctl behind a /proc/sys inode
fn sysctl_of(inode: &Inode) -> Option<&'static crate::sysctl::Ctl> {
    with_data(inode, |d| match d {
        ProcfsInodeData::Sysctl { ctl } => Some(*ctl),
        _ => None,
    })?
}

/// A new procfs inode with `data`
fn mk_inode(
    sb: &Arc<SuperBlock>,
    mode: InodeMode,
    data: ProcfsInodeData,
) -> Result<InodeRef, KernelError> {
    let inode = Inode::alloc(Inode::new(
        sb.alloc_ino(),
        mode,
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(sb),
        &PROCFS_INODE_OPS,
    ))?;
    // A fixed symlink's target in the inode (Linux proc_symlink's
    // de->data as i_link, simple_get_link)
    if let ProcfsInodeData::FixedLink(t) = &data {
        inode.set_link(t.to_vec().into_boxed_slice());
    }
    set_data(&inode, data)?;
    Ok(inode)
}

/// A static directory while procfs is built: its inode, linked
/// nowhere yet, and its entries, which become the inode's data in
/// `finish`, before anything can reach it (Linux allocates each
/// proc_dir_entry before proc_register links it under
/// proc_subdir_lock), so nothing is added under the data's lock
struct DirBuild {
    inode: InodeRef,
    files: BTreeMap<String, InodeRef>,
    dirs: BTreeMap<String, DirBuild>,
}

impl DirBuild {
    /// A new empty directory, its inode numbered now
    fn new(sb: &Arc<SuperBlock>) -> Result<Self, KernelError> {
        let inode = Inode::alloc(Inode::new(
            sb.alloc_ino(),
            InodeMode::directory(0o555),
            0,
            0,
            0,
            current_time(),
            Arc::downgrade(sb),
            &PROCFS_INODE_OPS,
        ))?;
        Ok(Self {
            inode,
            files: BTreeMap::new(),
            dirs: BTreeMap::new(),
        })
    }

    /// A new file `name` with `data`
    fn file(
        &mut self,
        sb: &Arc<SuperBlock>,
        name: &str,
        mode: InodeMode,
        data: ProcfsInodeData,
    ) -> Result<(), KernelError> {
        let i = mk_inode(sb, mode, data)?;
        self.files.insert(String::from(name), i);
        Ok(())
    }

    /// Subdirectory `name`, made if missing
    fn dir(&mut self, sb: &Arc<SuperBlock>, name: &str) -> Result<&mut DirBuild, KernelError> {
        use alloc::collections::btree_map::Entry;
        Ok(match self.dirs.entry(String::from(name)) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(DirBuild::new(sb)?),
        })
    }

    /// The directory's inode, its entries (subdirectories finished
    /// first) now its data
    fn finish(self) -> Result<InodeRef, KernelError> {
        let mut map = self.files;
        for (name, d) in self.dirs {
            map.insert(name, d.finish()?);
        }
        let data = ProcfsInodeData::Directory {
            children: try_arc(map)?,
        };
        set_data(&self.inode, data)?;
        Ok(self.inode)
    }
}

/// /proc/sysvipc (Linux ipc/util.c ipc_init_proc_interface): shm
fn build_sysvipc(sb: &Arc<SuperBlock>, root: &mut DirBuild) -> Result<(), KernelError> {
    root.dir(sb, "sysvipc")?.file(
        sb,
        "shm",
        InodeMode::regular(0o444),
        ProcfsInodeData::new_file(crate::ipc::shm::proc_sysvipc_shm),
    )
}

/// /proc/sys from the sysctl tables
fn build_sys(sb: &Arc<SuperBlock>, root: &mut DirBuild) -> Result<(), KernelError> {
    let sys = root.dir(sb, "sys")?;
    for ctl in crate::sysctl::tables().iter().flat_map(|t| t.iter()) {
        let (dirs, name) = ctl.path.rsplit_once('/').unwrap_or(("", ctl.path));
        let mut d = &mut *sys;
        for part in dirs.split('/').filter(|p| !p.is_empty()) {
            d = d.dir(sb, part)?;
        }
        d.file(
            sb,
            name,
            InodeMode::regular(ctl.mode),
            ProcfsInodeData::Sysctl { ctl },
        )?;
    }
    Ok(())
}

/// A released task's /proc entries leave every procfs dcache (Linux
/// proc_flush_pid, d_invalidate): /proc/<tid>, and the process
/// directory with it when the task was its leader,
/// /proc/<pid>/task/<tid> otherwise, each named as that procfs's pid
/// namespace numbers it, with what is mounted on or below them.
/// TASKLIST not held; sleeps (d_invalidate's NAMESPACE_SEM).
pub fn proc_flush_pid(
    t: &crate::task::Task,
    thread: Option<alloc::sync::Arc<crate::task::pid::Pid>>,
) {
    use crate::task::percpu::TASKLIST;
    // Its struct pid (pinned by the release that cleared it) and its
    // leader's, whose numbers stay readable after they are given back;
    // taken under TASKLIST, dropped after it
    let leader = {
        let table = TASKLIST.read();
        if t.tid() == t.pid {
            None
        } else {
            table.get(t.pid).and_then(|l| l.thread_pid())
        }
    };
    let Some(thread) = thread else {
        return;
    };
    let name = |n: u32| alloc::format!("{n}").into_bytes();
    // No s_umount (Linux proc_flush_pid takes none): every reap passes
    // here, and must not wait for a procfs mount's fill or shutdown
    crate::fs::superblock::iterate_supers_type_active(&PROCFS_TYPE, |sb| {
        let ns = opts::sb_pid_ns(sb);
        let (Some(root), Some(tid)) = (sb.get_root(), thread.nr_in(&ns)) else {
            return;
        };
        // Linux d_invalidate: what is mounted there goes too
        let flush = |dir: &super::dentry::DentryRef, n: u32| {
            if let Some(d) = dir.lookup_child(&name(n)) {
                super::dentry::d_invalidate(&d);
            }
        };
        flush(&root, tid);
        if let Some(pid) = leader.as_ref().and_then(|l| l.nr_in(&ns))
            && let Some(task) = root
                .lookup_child(&name(pid))
                .and_then(|d| d.lookup_child(b"task"))
        {
            flush(&task, tid);
        }
    });
}

/// procfs's kill_sb (Linux proc_kill_sb): kill_anon_super; its options
/// (the pid namespace reference) go with the superblock's memory
fn proc_kill_sb(sb: &SuperBlock, g: crate::fs::superblock::SbUmount<'_>) {
    crate::fs::superblock::kill_anon_super(sb, g);
}

/// Mount function for procfs
fn procfs_mount(
    fc: &crate::fs::superblock::FsContext<'_>,
) -> Result<crate::fs::superblock::SbLocked, KernelError> {
    let opts = try_arc(opts::ProcOpts::new(fc.data)?)?;
    crate::fs::superblock::get_tree_nodev(fc, &PROCFS_SUPER_OPS, |sb| {
        sb.set_fs_info(opts);
        procfs_fill(sb)
    })
}

/// procfs's dentry operations (Linux pid_dentry_operations,
/// tid_fd_dentry_operations, proc_sys_dentry_operations,
/// proc_misc_dentry_ops, proc_net_dentry_ops: one set here, told apart
/// by the inode)
static PROC_DENTRY_OPS: crate::fs::dentry::DentryOps = crate::fs::dentry::DentryOps {
    d_revalidate: Some(proc_revalidate),
    ..crate::fs::dentry::DentryOps::NONE
};

/// Linux pid_revalidate / tid_fd_revalidate: an entry of a task that
/// is gone, or of an fd no longer open, is invalid, and so is a
/// negative one (pid_revalidate: no inode, 0); a live one takes the
/// task's current owner (pid_update_inode). An RCU walk is answered
/// from what the inode keeps for it, ECHILD where Linux's is
/// (`revalidate_rcu`).
fn proc_revalidate(
    _: &Inode,
    _: &Dentry,
    inode: Option<&Inode>,
    flags: crate::fs::dentry::LookupBits,
) -> Result<bool, KernelError> {
    let Some(inode) = inode else {
        return Ok(false);
    };
    if flags.contains(crate::fs::dentry::LookupBits::RCU) {
        return revalidate_rcu(inode);
    }
    Ok(revalidate_ref(inode))
}

/// The static tree (Linux proc_fill_super)
fn procfs_fill(sb: &Arc<SuperBlock>) -> Result<(), KernelError> {
    sb.set_d_op(&PROC_DENTRY_OPS);
    // The static tree, built before it is reachable, in the order its
    // inodes are numbered (the root is 1)
    let mut root = DirBuild::new(sb)?;
    let file = ProcfsInodeData::new_file;
    let ro = InodeMode::regular(0o444);
    root.file(sb, "version", ro, file(gen_version))?;
    // /proc/mounts -> self/mounts (Linux proc_symlink)
    root.file(
        sb,
        "mounts",
        InodeMode::symlink(),
        ProcfsInodeData::FixedLink(b"self/mounts"),
    )?;
    root.file(sb, "meminfo", ro, file(gen_meminfo))?;
    root.file(sb, "loadavg", ro, file(crate::task::loadavg::proc_loadavg))?;
    // Linux ioresources_init: /proc/ioports
    root.file(
        sb,
        "ioports",
        ro,
        ProcfsInodeData::new_opener_file(crate::base::resource::proc_ioports),
    )?;

    // /proc/net -> self/net (Linux proc_net_init: proc_symlink)
    root.file(
        sb,
        "net",
        InodeMode::symlink(),
        ProcfsInodeData::FixedLink(b"self/net"),
    )?;

    root.file(
        sb,
        "slabinfo",
        InodeMode::regular(0o400),
        file(crate::mm::slab::slabinfo),
    )?;
    root.file(
        sb,
        "partitions",
        ro,
        file(crate::block::genhd::proc_partitions),
    )?;
    root.file(sb, "cmdline", ro, file(gen_cmdline))?;

    build_sys(sb, &mut root)?;
    build_sysvipc(sb, &mut root)?;
    let root_inode = root.finish()?;

    // Create root dentry
    let root_dentry = crate::fs::DentryRef::new(Dentry::new_root(root_inode, Arc::downgrade(sb)))?;

    // Set root in superblock
    sb.set_root(root_dentry);

    Ok(())
}

/// Procfs filesystem type
pub static PROCFS_TYPE: FileSystemType = FileSystemType {
    name: "proc",
    fs_flags: super::superblock::fs_flags::FS_PSEUDO
        | super::superblock::fs_flags::FS_USERNS_MOUNT_RESTRICTED,
    mount: procfs_mount,
    kill_sb: proc_kill_sb,
    file_ops: &PROCFS_FILE_OPS,
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
};
