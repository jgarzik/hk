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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::spin::RwLock;

use super::KernelError;
use super::dentry::Dentry;
use super::file::{DirContext, DirEntry, File, FileOps, RwFlags, WRITE_CHUNK};
use super::inode::{AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
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

/// `t` is still in the task list (not reaped)
fn alive(t: &crate::task::Task) -> bool {
    crate::task::percpu::TASKLIST.read().view(t).is_some()
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
    /// The task, pinned, while the pid names one (Linux get_pid_task),
    /// None once it is reaped; TASKLIST read only to take the reference.
    /// Every per-process path works on this task, never on its number.
    pub fn task(&self) -> Option<TaskRef> {
        crate::task::percpu::TASKLIST.read().pid_task_ref(&self.0)
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

/// Content generator function type
pub type ContentGenerator = fn() -> Vec<u8>;

/// Namespace types for /proc/<pid>/ns/* files
///
/// Used by setns(2) to identify which namespace to join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    /// UTS namespace (hostname, domainname)
    Uts,
    /// Mount namespace (filesystem view)
    Mnt,
    /// PID namespace (process IDs)
    Pid,
    /// User namespace (UID/GID mapping)
    User,
    /// IPC namespace (SysV IPC)
    Ipc,
    /// Network namespace (network stack isolation)
    Net,
    // Future: Cgroup, Time
}

impl NamespaceType {
    /// Get the filename for this namespace type
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Uts => "uts",
            Self::Mnt => "mnt",
            Self::Pid => "pid",
            Self::User => "user",
            Self::Ipc => "ipc",
            Self::Net => "net",
        }
    }

    /// Convert from filename to namespace type
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "uts" => Some(Self::Uts),
            "mnt" => Some(Self::Mnt),
            "pid" => Some(Self::Pid),
            "user" => Some(Self::User),
            "ipc" => Some(Self::Ipc),
            "net" => Some(Self::Net),
            _ => None,
        }
    }

    /// Get the CLONE_NEW* flag for this namespace type
    pub fn clone_flag(&self) -> u64 {
        match self {
            Self::Uts => crate::ns::CLONE_NEWUTS,
            Self::Mnt => crate::ns::CLONE_NEWNS,
            Self::Pid => crate::ns::CLONE_NEWPID,
            Self::User => crate::ns::CLONE_NEWUSER,
            Self::Ipc => crate::ns::CLONE_NEWIPC,
            Self::Net => crate::ns::CLONE_NEWNET,
        }
    }

    /// The inode number of `ns`'s namespace of this type (Linux
    /// ns.inum)
    pub fn inum(&self, ns: &crate::ns::NsProxy) -> u32 {
        match self {
            Self::Uts => ns.uts_ns.inum.get(),
            Self::Mnt => ns.mnt_ns.inum.get(),
            Self::Pid => ns.pid_ns.inum.get(),
            Self::User => ns.user_ns.inum.get(),
            Self::Ipc => ns.ipc_ns.inum.get(),
            Self::Net => ns.net_ns.inum.get(),
        }
    }

    /// List of all supported namespace types
    pub fn all() -> &'static [NamespaceType] {
        &[
            Self::Uts,
            Self::Mnt,
            Self::Pid,
            Self::User,
            Self::Ipc,
            Self::Net,
        ]
    }
}

/// Procfs inode private data
pub enum ProcfsInodeData {
    /// Directory with static children (built at mount; shared, so a
    /// readdir walks them with no lock held)
    Directory {
        children: Arc<BTreeMap<String, Arc<Inode>>>,
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
    /// Per-process symlink (/proc/<pid>/exe)
    PidLink { pid: ProcPid, target: LinkFn },
    /// /proc/sys file (readable, maybe writable)
    Sysctl { ctl: &'static crate::sysctl::Ctl },
    /// /proc/<pid>/fail-nth: the task's fault-injection countdown
    /// (Linux proc_fail_nth_operations, `mm::fault_inject`)
    FailNth { pid: ProcPid },
}

impl ProcfsInodeData {
    /// Create directory data
    pub fn new_dir() -> Result<Self, KernelError> {
        Ok(Self::Directory {
            children: try_arc(BTreeMap::new())?,
        })
    }

    /// Create file data with generator
    pub fn new_file(generator: ContentGenerator) -> Self {
        Self::File { generator }
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
    pub fn children(&self) -> Option<&BTreeMap<String, Arc<Inode>>> {
        match self {
            Self::Directory { children } => Some(children),
            _ => None,
        }
    }

    /// Get mutable children map
    /// The children to add to, at mount (copied first if a readdir
    /// holds them)
    pub fn children_mut(&mut self) -> Option<&mut BTreeMap<String, Arc<Inode>>> {
        match self {
            Self::Directory { children } => Some(Arc::make_mut(children)),
            _ => None,
        }
    }

    /// Generate content (for generator files)
    pub fn generate(&self) -> Option<Vec<u8>> {
        match self {
            Self::File { generator } => Some(generator()),
            Self::Sysctl { ctl } => Some(crate::sysctl::read(ctl)),
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
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(KernelError::Io)?;
        // What the link is, copied out: a target may sleep (exe takes
        // exec_update_lock) or allocate, so none is made under the inode
        // data's spinning read lock
        enum Link {
            Pid(ProcPid, LinkFn),
            Me,
            Fixed(&'static [u8]),
            Fd(ProcPid, i32),
            Ns(ProcPid, NamespaceType),
        }
        let l = match &*wrapper.0.read() {
            ProcfsInodeData::PidLink { pid, target } => Link::Pid(pid.clone(), *target),
            ProcfsInodeData::SelfLink => Link::Me,
            ProcfsInodeData::FixedLink(t) => Link::Fixed(t),
            ProcfsInodeData::FdSymlink { pid, fd } => Link::Fd(pid.clone(), *fd),
            ProcfsInodeData::NamespaceFile { pid, ns_type } => Link::Ns(pid.clone(), *ns_type),
            _ => return Err(KernelError::InvalidArgument),
        };
        match l {
            Link::Pid(pid, target) => target(&pid.task().ok_or(KernelError::NotFound)?),
            Link::Me => self_link(inode),
            Link::Fixed(t) => Ok(t.to_vec()),
            Link::Fd(pid, fd) => fd_link(&pid.task().ok_or(KernelError::NotFound)?, fd),
            Link::Ns(pid, ns_type) => {
                let inum = ns_inum(&pid, ns_type)?;
                Ok(alloc::format!("{}:[{inum}]", ns_type.as_str()).into_bytes())
            }
        }
    }

    /// /proc/<pid>/ns/<type> leads to the namespace's file (Linux
    /// proc_ns_get_link: ns_get_path, nd_jump_link)
    fn jump_link(
        &self,
        inode: &Inode,
        mnt: &Arc<crate::fs::mount::Mount>,
    ) -> Option<Result<crate::fs::Path, KernelError>> {
        let wrapper = inode.get_private()?;
        let wrapper = wrapper
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()?;
        let (pid, ns_type) = match &*wrapper.0.read() {
            ProcfsInodeData::NamespaceFile { pid, ns_type } if inode.mode().is_symlink() => {
                (pid.clone(), *ns_type)
            }
            _ => return None,
        };
        Some(ns_file(inode, mnt, pid, ns_type))
    }

    /// /proc/sys files: Linux proc_sys_permission (never executable,
    /// then sysctl_perm: no capability override of the mode); fd/ and
    /// fdinfo/ need ptrace-read access
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

    fn permission(&self, inode: &Inode, cred: &Cred, mask: u32) -> Result<(), KernelError> {
        // A process directory hidepid= hides (Linux proc_pid_permission)
        if let Some(t) = pid_dir_pid(inode) {
            opts::with(inode, |o| o.pid_permission(&t)).unwrap_or(Ok(()))?;
        }
        // fd/ and fdinfo/: ptrace-read access (Linux proc_fd_permission)
        if let Some(OpenCheck::Fds(t)) = open_check(inode)
            && !crate::task::ptrace::may_access_task(&t, true)
        {
            return Err(KernelError::PermissionDenied);
        }
        // The owner follows the task's identity and dumpability (Linux
        // pid_revalidate -> pid_update_inode)
        if let Some(t) = pid_file_pid(inode) {
            let (uid, gid) = dump_owner(&t);
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

    /// Linux pid_revalidate / tid_fd_revalidate: an entry of a task that
    /// is gone, or of an fd no longer open, is invalid; a live one takes
    /// the task's current owner (pid_update_inode)
    fn revalidate(&self, inode: &Inode) -> bool {
        let Some(private) = inode.get_private() else {
            return true;
        };
        let Some(w) = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
        else {
            return true;
        };
        let data = w.0.read();
        let Some(p) = data.pid() else {
            return true;
        };
        let fd = match &*data {
            ProcfsInodeData::FdSymlink { fd, .. } | ProcfsInodeData::FdinfoFile { fd, .. } => {
                Some(*fd)
            }
            _ => None,
        };
        drop(data);
        let Some(t) = p.task() else {
            return false;
        };
        if let Some(fd) = fd {
            let open = task_files(&t).is_some_and(|f| f.lock().get(fd).is_some());
            if !open {
                return false;
            }
        }
        let (uid, gid) = dump_owner(&t);
        inode.set_uid(uid);
        inode.set_gid(gid);
        true
    }

    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, KernelError> {
        // Every /proc name is text: anything else names nothing
        let name = core::str::from_utf8(name).map_err(|_| KernelError::NotFound)?;
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        // What the directory is, copied out: lookups allocate inodes and
        // take TASKLIST, so none runs under the inode data's spin lock
        enum Dir {
            Static(Option<Arc<Inode>>, bool),
            Pid(ProcPid),
            Ns(ProcPid),
            Fd(ProcPid),
            Task(ProcPid),
            Fdinfo(ProcPid),
        }
        let kind = match &*wrapper.0.read() {
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
            ProcfsInodeData::File { .. }
            | ProcfsInodeData::NamespaceFile { .. }
            | ProcfsInodeData::FdSymlink { .. }
            | ProcfsInodeData::PidLink { .. }
            | ProcfsInodeData::SelfLink
            | ProcfsInodeData::FixedLink(_)
            | ProcfsInodeData::FdinfoFile { .. }
            | ProcfsInodeData::PidFile { .. }
            | ProcfsInodeData::FailNth { .. }
            | ProcfsInodeData::Sysctl { .. } => return Err(KernelError::NotDirectory),
        };
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
        }
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
        if matches!(x.state, crate::task::TaskState::Zombie(_)) {
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
) -> Result<Arc<Inode>, KernelError> {
    let sb = parent.superblock().expect("superblock dropped");
    let inode = try_arc(Inode::new(
        ino,
        InodeMode::directory(0o555),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(data)))?);
    Ok(inode)
}

fn create_pid_dir_inode(parent: &Inode, pid: ProcPid) -> Result<Arc<Inode>, KernelError> {
    let sb = parent.superblock().expect("superblock dropped");
    let inode = try_arc(Inode::new(
        pid_ino(pid.ino(), 0),
        InodeMode::directory(0o555), // r-xr-xr-x
        0,                           // uid: root
        0,                           // gid: root
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_pid_dir(pid),
    )))?);
    Ok(inode)
}

/// Look up entries in /proc/<pid>/
fn lookup_pid_entry(dir: &Inode, p: &ProcPid, name: &str) -> Result<Arc<Inode>, KernelError> {
    // The task, while its pid names one; its tid only numbers inodes
    let t = p.task().ok_or(KernelError::NotFound)?;
    let pid = t.tid();

    match name {
        "ns" => {
            // Create /proc/<pid>/ns directory
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = try_arc(Inode::new(
                pid_ino(pid, 1),
                InodeMode::directory(0o555), // r-xr-xr-x
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::new_pid_ns_dir(p.clone()),
            )))?);
            Ok(inode)
        }
        "fd" => {
            // Create /proc/<pid>/fd directory
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = try_arc(Inode::new(
                pid_ino(pid, 100),           // offset 100 for fd dir
                InodeMode::directory(0o500), // dr-x------ (only owner can read)
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::new_pid_fd_dir(p.clone()),
            )))?);
            Ok(inode)
        }
        "task" => create_dir_inode(
            dir,
            pid_ino(pid, 120),
            ProcfsInodeData::PidTaskDirectory { pid: p.clone() },
        ),
        "fdinfo" => {
            // Create /proc/<pid>/fdinfo directory
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = try_arc(Inode::new(
                pid_ino(pid, 101),           // offset 101 for fdinfo dir
                InodeMode::directory(0o500), // dr-x------ (only owner can read)
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::new_pid_fdinfo_dir(p.clone()),
            )))?);
            Ok(inode)
        }
        name if PID_LINKS.iter().any(|(n, _, _)| *n == name) => {
            let &(_, off, target) = PID_LINKS
                .iter()
                .find(|(n, _, _)| *n == name)
                .ok_or(KernelError::NotFound)?;
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = try_arc(Inode::new(
                pid_ino(pid, off),
                InodeMode::symlink(),
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::PidLink {
                    pid: p.clone(),
                    target,
                },
            )))?);
            Ok(inode)
        }
        "fail-nth" => {
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let (uid, gid) = dump_owner(&t);
            let inode = try_arc(Inode::new(
                pid_ino(pid, FAIL_NTH_INO),
                InodeMode::regular(0o644),
                uid,
                gid,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::FailNth { pid: p.clone() },
            )))?);
            Ok(inode)
        }
        name if pid_file(name).is_some() => {
            let (off, mode, generator) = pid_file(name).ok_or(KernelError::NotFound)?;
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let (uid, gid) = dump_owner(&t);
            let inode = try_arc(Inode::new(
                pid_ino(pid, off),
                InodeMode::regular(mode),
                uid,
                gid,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ))?;
            inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::new_pid_file(p.clone(), generator),
            )))?);
            Ok(inode)
        }
        _ => Err(KernelError::NotFound),
    }
}

/// Look up entries in /proc/<pid>/ns/
fn lookup_pid_ns_entry(dir: &Inode, p: &ProcPid, name: &str) -> Result<Arc<Inode>, KernelError> {
    // The task, while its pid names one; its tid only numbers inodes
    let t = p.task().ok_or(KernelError::NotFound)?;
    let pid = t.tid();

    // Parse namespace type from name
    let ns_type = NamespaceType::parse(name).ok_or(KernelError::NotFound)?;

    // Create namespace file inode
    let sb = dir.superblock().ok_or(KernelError::Io)?;
    let offset = match ns_type {
        NamespaceType::Uts => 2,
        NamespaceType::Mnt => 3,
        NamespaceType::Pid => 4,
        NamespaceType::User => 5,
        NamespaceType::Ipc => 6,
        NamespaceType::Net => 7,
    };

    // A magic link to the namespace (Linux proc_ns_dir_operations:
    // S_IFLNK | 0777)
    let inode = try_arc(Inode::new(
        pid_ino(pid, offset),
        InodeMode::symlink(),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_ns_file(p.clone(), ns_type),
    )))?);
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

/// /proc/self (resolved at readlink time to the reader's pid)
fn create_self_link(parent: &Inode) -> Result<Arc<Inode>, KernelError> {
    let sb = parent.superblock().expect("superblock dropped");
    let inode = try_arc(Inode::new(
        pid_ino(0, 999),
        InodeMode::symlink(),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::SelfLink,
    )))?);
    Ok(inode)
}

/// Target of /proc/<pid>/fd/<fd>: `socket:[ino]` / `pipe:[ino]` for
/// sockets and pipes, `anon_inode:<name>` for other files without a
/// filesystem, else the path
fn fd_link(t: &TaskRef, fd: i32) -> Result<Vec<u8>, KernelError> {
    let table = task_files(t).ok_or(KernelError::NotFound)?;
    let file = table.lock().get(fd).ok_or(KernelError::NotFound)?;
    let inode = file.get_inode().ok_or(KernelError::NotFound)?;
    let mode = inode.mode();
    if mode.is_socket() {
        return Ok(alloc::format!("socket:[{}]", inode.ino).into_bytes());
    }
    if inode.superblock().is_none() {
        if mode.file_type() == Some(crate::fs::inode::FileType::Fifo) {
            return Ok(alloc::format!("pipe:[{}]", inode.ino).into_bytes());
        }
        return Ok([b"anon_inode:".as_slice(), &file.dentry.name()].concat());
    }
    match file.f_path() {
        Some(p) => super::dentry::d_path_link(&p),
        None => Ok(Vec::new()),
    }
}

/// Look up entries in /proc/<pid>/fd/
fn lookup_pid_fd_entry(dir: &Inode, p: &ProcPid, name: &str) -> Result<Arc<Inode>, KernelError> {
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

    // Create symlink inode for /proc/<pid>/fd/<n>
    let sb = dir.superblock().ok_or(KernelError::Io)?;
    let inode = try_arc(Inode::new(
        pid_ino(pid, FD_INO + fd as u64), // fd symlinks
        InodeMode::symlink(),             // lrwxrwxrwx
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_fd_symlink(p.clone(), fd),
    )))?);
    Ok(inode)
}

/// Look up entries in /proc/<pid>/fdinfo/
fn lookup_pid_fdinfo_entry(
    dir: &Inode,
    p: &ProcPid,
    name: &str,
) -> Result<Arc<Inode>, KernelError> {
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
    let inode = try_arc(Inode::new(
        pid_ino(pid, FDINFO_INO + fd as u64), // fdinfo files
        InodeMode::regular(0o444),            // r--r--r--
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_fdinfo_file(p.clone(), fd),
    )))?);
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

/// The task `pid` names, if the caller may see its namespaces (Linux
/// proc_ns_get_link / proc_ns_readlink: EACCES once it is gone or
/// without PTRACE_MODE_READ_FSCREDS access)
fn ns_task(pid: &ProcPid) -> Result<TaskRef, KernelError> {
    let t = pid.task().ok_or(KernelError::PermissionDenied)?;
    if !crate::task::ptrace::may_access_task(&t, true) {
        return Err(KernelError::PermissionDenied);
    }
    Ok(t)
}

/// The inode number of the `ns_type` namespace of the task `pid` names
/// (Linux ns_get_name)
fn ns_inum(pid: &ProcPid, ns_type: NamespaceType) -> Result<u32, KernelError> {
    let t = ns_task(pid)?;
    let ns = task_nsproxy(&t).ok_or(KernelError::PermissionDenied)?;
    Ok(ns_type.inum(&ns))
}

/// The file of the `ns_type` namespace of the task `pid` names, where
/// its /proc link `link` (on `mnt`) leads: a read-only inode numbered
/// as the namespace (Linux ns_get_path: the nsfs inode, ino ns.inum),
/// which setns takes
fn ns_file(
    link: &Inode,
    mnt: &Arc<crate::fs::mount::Mount>,
    pid: ProcPid,
    ns_type: NamespaceType,
) -> Result<crate::fs::Path, KernelError> {
    let inum = ns_inum(&pid, ns_type)?;
    let sb = link.superblock().ok_or(KernelError::Io)?;
    let inode = try_arc(Inode::new(
        u64::from(inum),
        InodeMode::regular(0o444),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_ns_file(pid, ns_type),
    )))?);
    let name = alloc::format!("{}:[{inum}]", ns_type.as_str()).into_bytes();
    let dentry = try_arc(Dentry::new_anonymous(name.into(), Some(inode)))?;
    Ok(crate::fs::Path::new(mnt.clone(), dentry))
}

/// Generate content for /proc/<pid>/cgroup
///
/// Returns the cgroup membership for the process.
/// For cgroup v2, this is a single line: "0::<path>\n"
/// The path is relative to the task's cgroup namespace root.
fn gen_cgroup_content(t: &TaskRef) -> Vec<u8> {
    use alloc::fmt::Write;
    let mut output = String::new();

    // Get the task's cgroup path (namespace-virtualized)
    let cgroup_path = get_task_cgroup_path(t);

    // cgroup v2 format: "0::<path>"
    // The "0" indicates the unified hierarchy (cgroup v2)
    // The empty string between colons indicates no named controllers
    let _ = writeln!(output, "0::{}", cgroup_path);

    Vec::from(output.as_bytes())
}

/// Generated files in /proc/<pid>/: name, inode offset, generator
/// Access checks a procfs file needs at open
enum OpenCheck {
    /// Address-space file of the task: pin its mm
    Mm(TaskRef),
    /// fd/ or fdinfo/ of the task
    Fds(TaskRef),
}

/// The open-time check of `inode`, if any
fn open_check(inode: &Inode) -> Option<OpenCheck> {
    let private = inode.get_private()?;
    let wrapper = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()?;
    // Copied out, the task looked up after the inode data's lock
    let (p, mm) = match &*wrapper.0.read() {
        ProcfsInodeData::PidFile {
            pid,
            generator: PidGen::Mm(_),
        } => (pid.clone(), true),
        ProcfsInodeData::PidFdDirectory { pid } | ProcfsInodeData::PidFdinfoDirectory { pid } => {
            (pid.clone(), false)
        }
        _ => return None,
    };
    let t = p.task()?;
    Some(if mm {
        OpenCheck::Mm(t)
    } else {
        OpenCheck::Fds(t)
    })
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
    Mnt(fn(&TaskRef) -> Vec<u8>),
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

/// Content of a per-process file for this open file (or, with none,
/// checked afresh)
fn pid_content(file: Option<&File>, t: &TaskRef, g: PidGen) -> Result<Vec<u8>, KernelError> {
    match g {
        PidGen::Pub(f) | PidGen::Mnt(f) => Ok(f(t)),
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
    let Some(private) = file.get_inode().and_then(|i| i.get_private()) else {
        return ProcPoll::None;
    };
    let Some(w) = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()
    else {
        return ProcPoll::None;
    };
    match &*w.0.read() {
        ProcfsInodeData::File { .. } | ProcfsInodeData::Sysctl { .. } => ProcPoll::Default,
        ProcfsInodeData::PidFile {
            generator: PidGen::Mnt(_),
            ..
        } => ProcPoll::Mounts,
        _ => ProcPoll::None,
    }
}

/// The process of a /proc/<pid>/fail-nth inode
fn fail_nth_of(inode: &Inode) -> Option<ProcPid> {
    let private = inode.get_private()?;
    let w = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()?;
    match &*w.0.read() {
        ProcfsInodeData::FailNth { pid } => Some(pid.clone()),
        _ => None,
    }
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

/// Per-process symlinks: name, inode offset, target (Linux
/// proc_exe_link, proc_cwd_link, proc_root_link)
/// The target of a per-process symlink
type LinkFn = fn(&TaskRef) -> Result<Vec<u8>, KernelError>;

const PID_LINKS: &[(&str, u64, LinkFn)] = &[
    ("exe", 104, exe_link),
    ("cwd", 111, cwd_link),
    ("root", 112, root_link),
];

fn pid_file(name: &str) -> Option<(u64, u16, PidGen)> {
    PID_FILES
        .iter()
        .find(|(n, _, _, _)| *n == name)
        .map(|&(_, off, mode, g)| (off, mode, g))
}

/// Owner of a /proc/<pid>/ file (Linux task_dump_owner): the task's
/// euid/egid while it is dumpable, else root, so a non-dumpable task's
/// mode-0400 files are root's
fn dump_owner(task: &TaskRef) -> (u32, u32) {
    use crate::task::percpu::TASKLIST;
    let table = TASKLIST.read();
    table
        .view(task)
        .filter(|t| {
            t.task
                .task_lock()
                .mm()
                .is_none_or(|m| m.dumpable() == crate::task::dumpable::SUID_DUMP_USER)
        })
        .map_or((0, 0), |t| (t.cred().euid, t.cred().egid))
}

/// The process a per-process file belongs to
fn pid_file_pid(inode: &Inode) -> Option<TaskRef> {
    let private = inode.get_private()?;
    let wrapper = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()?;
    let p = match &*wrapper.0.read() {
        ProcfsInodeData::PidFile { pid, .. } => pid.clone(),
        _ => return None,
    };
    p.task()
}

/// /proc/<pid>/cwd and root: the task's fs pwd or root as the reader
/// names it, EACCES without ptrace-read access (Linux
/// proc_fd_access_allowed), ENOENT for a task without one
fn fs_link(t: &TaskRef, root: bool) -> Result<Vec<u8>, KernelError> {
    if !crate::task::ptrace::may_access_task(t, true) {
        return Err(KernelError::PermissionDenied);
    }
    let fs = crate::fs::get_task_fs(t).ok_or(KernelError::NotFound)?;
    let p = if root { fs.get_root() } else { fs.get_pwd() };
    super::dentry::d_path_link(&p)
}

fn cwd_link(t: &TaskRef) -> Result<Vec<u8>, KernelError> {
    fs_link(t, false)
}

fn root_link(t: &TaskRef) -> Result<Vec<u8>, KernelError> {
    fs_link(t, true)
}

/// /proc/<pid>/exe: the executable's path (ENOENT for kernel threads,
/// EACCES without ptrace-read access, Linux proc_fd_access_allowed)
fn exe_link(t: &TaskRef) -> Result<Vec<u8>, KernelError> {
    // Through mm_access, so the check and the image it reveals are one
    // (exec_update_lock read). An exec resolving /proc/self/exe (busybox
    // re-execs itself) holds only cred_guard while it walks paths: it
    // takes exec_update for writing later, in exec_replace_image
    let mm = mm_access(t)?.ok_or(KernelError::NotFound)?;
    let exe = mm
        .mmap_read_killable()?
        .exe()
        .ok_or(KernelError::NotFound)?;
    Ok(exe.into_vec())
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

/// Get the cgroup path for a task (virtualized to its namespace)
fn get_task_cgroup_path(t: &TaskRef) -> String {
    use crate::ns::INIT_CGROUP_NS;

    // Get the task's cgroup
    let task_cgroup = t.cgroup.lock().clone();

    let Some(cgroup) = task_cgroup else {
        // Task not in any cgroup - return root
        return String::from("/");
    };

    // Get the task's cgroup namespace
    let cgroup_ns =
        task_nsproxy(t).map_or_else(|| INIT_CGROUP_NS.clone(), |ns| ns.cgroup_ns.clone());

    // Translate the cgroup path relative to the namespace root
    cgroup_ns.translate_path(&cgroup)
}

/// The content of the procfs file `file` (Linux: its show() / sysctl
/// handler output). Per-process generators may sleep (exec_update_lock,
/// mmap_lock): they run after the inode data's spinning read lock is
/// dropped.
fn proc_content(file: &File) -> Result<Vec<u8>, KernelError> {
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    let private = inode.get_private().ok_or(KernelError::Io)?;
    let wrapper = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()
        .ok_or(KernelError::Io)?;
    // What to generate, copied out: no generator runs under the
    // inode's spin lock (they allocate and take TASKLIST, network and
    // mount locks; Linux seq_file show() runs under no inode lock)
    enum Gen {
        Pid(ProcPid, PidGen),
        File(ContentGenerator),
        Fdinfo(ProcPid, i32),
        Sysctl(&'static crate::sysctl::Ctl),
        FailNth(ProcPid),
    }
    let g = match &*wrapper.0.read() {
        ProcfsInodeData::PidFile { pid, generator } => Gen::Pid(pid.clone(), *generator),
        ProcfsInodeData::File { generator } => Gen::File(*generator),
        // A namespace file has no read (Linux ns_file_operations)
        ProcfsInodeData::NamespaceFile { .. } => return Err(KernelError::InvalidArgument),
        ProcfsInodeData::FdinfoFile { pid, fd } => Gen::Fdinfo(pid.clone(), *fd),
        ProcfsInodeData::Sysctl { ctl } => Gen::Sysctl(ctl),
        ProcfsInodeData::FailNth { pid } => Gen::FailNth(pid.clone()),
        ProcfsInodeData::FdSymlink { .. }
        | ProcfsInodeData::PidLink { .. }
        | ProcfsInodeData::SelfLink
        | ProcfsInodeData::FixedLink(_) => return Err(KernelError::Io),
        ProcfsInodeData::Directory { .. }
        | ProcfsInodeData::PidDirectory { .. }
        | ProcfsInodeData::PidTaskDirectory { .. }
        | ProcfsInodeData::PidNsDirectory { .. }
        | ProcfsInodeData::PidFdDirectory { .. }
        | ProcfsInodeData::PidFdinfoDirectory { .. } => return Err(KernelError::IsDirectory),
    };
    // A per-process file of a reaped task reads ESRCH (Linux
    // proc_single_show: get_pid_task fails)
    let task = |p: &ProcPid| p.task().ok_or(KernelError::NoProcess);
    Ok(match g {
        Gen::Pid(p, g) => return pid_content(Some(file), &task(&p)?, g),
        Gen::File(generator) => generator(),
        Gen::Fdinfo(p, fd) => gen_fdinfo_content(&task(&p)?, fd, &opts::pid_ns(&inode)),
        Gen::Sysctl(ctl) => crate::sysctl::read(ctl),
        Gen::FailNth(p) => {
            let n = task(&p)?
                .fail_nth
                .load(core::sync::atomic::Ordering::Relaxed);
            alloc::format!("{n}\n").into_bytes()
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
        let pde = file
            .get_inode()
            .and_then(|i| i.get_private())
            .is_some_and(|p| {
                p.as_ref()
                    .as_any()
                    .downcast_ref::<ProcfsInodeWrapper>()
                    .is_some_and(|w| matches!(&*w.0.read(), ProcfsInodeData::File { .. }))
            });
        Err(if pde {
            KernelError::Io
        } else {
            KernelError::NoDevice
        })
    }

    /// A mount table is readable (Linux mounts_poll; no POLLERR|POLLPRI
    /// on a change of it yet); the rest DEFAULT_POLLMASK (vfs_poll)
    fn poll(&self, file: &File, _pt: Option<&mut PollTable<'_>>) -> u16 {
        match proc_poll(file) {
            ProcPoll::Mounts => POLLIN | POLLRDNORM,
            _ => DEFAULT_POLLMASK,
        }
    }

    fn can_poll(&self, file: &File) -> bool {
        proc_poll(file) != ProcPoll::None
    }

    /// Private per-process files check ptrace-read access at open
    /// (Linux proc_mem_open, proc_fd_permission); maps keeps the address
    /// space it was opened on, so a later setuid exec cannot leak
    fn open(&self, file: &File) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let mm = match open_check(&inode) {
            Some(OpenCheck::Mm(t)) => mm_access(&t)?,
            Some(OpenCheck::Fds(t)) if !crate::task::ptrace::may_access_task(&t, true) => {
                return Err(KernelError::PermissionDenied);
            }
            _ => None,
        };
        // A generated file keeps its last generation (seq_file)
        if inode.mode().is_file() && sysctl_of(&inode).is_none() && fail_nth_of(&inode).is_none() {
            let po = try_arc(ProcOpen {
                mm,
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
        if rw.nowait {
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
        if rw.nowait {
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

        let private = inode.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        // What the directory is, copied out (the static children by a
        // shared reference): entries are emitted, and TASKLIST taken,
        // with the inode data's spin lock released
        enum Dir {
            Static(Arc<BTreeMap<String, Arc<Inode>>>),
            Pid(ProcPid),
            Ns(ProcPid),
            Fd(ProcPid),
            Task(ProcPid),
            Fdinfo(ProcPid),
        }
        let kind = match &*wrapper.0.read() {
            ProcfsInodeData::Directory { children } => Dir::Static(children.clone()),
            ProcfsInodeData::PidDirectory { pid } => Dir::Pid(pid.clone()),
            ProcfsInodeData::PidNsDirectory { pid } => Dir::Ns(pid.clone()),
            ProcfsInodeData::PidFdDirectory { pid } => Dir::Fd(pid.clone()),
            ProcfsInodeData::PidTaskDirectory { pid } => Dir::Task(pid.clone()),
            ProcfsInodeData::PidFdinfoDirectory { pid } => Dir::Fdinfo(pid.clone()),
            ProcfsInodeData::File { .. }
            | ProcfsInodeData::NamespaceFile { .. }
            | ProcfsInodeData::FdSymlink { .. }
            | ProcfsInodeData::PidLink { .. }
            | ProcfsInodeData::SelfLink
            | ProcfsInodeData::FixedLink(_)
            | ProcfsInodeData::FdinfoFile { .. }
            | ProcfsInodeData::PidFile { .. }
            | ProcfsInodeData::FailNth { .. }
            | ProcfsInodeData::Sysctl { .. } => return Err(KernelError::NotDirectory),
        };

        // A reaped task's directory lists nothing, not even "." (Linux
        // proc_pident_readdir: ENOENT)
        let task = match &kind {
            Dir::Static(_) => None,
            Dir::Pid(p) | Dir::Ns(p) | Dir::Fd(p) | Dir::Task(p) | Dir::Fdinfo(p) => {
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
    for (idx, ns_type) in NamespaceType::all().iter().enumerate() {
        let should_continue = ctx.emit(DirEntry {
            ino: pid_ino(pid, 2 + idx as u64),
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

    // Get FDs from the task's FD table
    let fds: Vec<i32> = {
        if let Some(table_arc) = task_files(t) {
            let table = table_arc.lock();
            table.fds().copied().collect()
        } else {
            return Ok(());
        }
    };

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

    // Get FDs from the task's FD table
    let fds: Vec<i32> = {
        if let Some(table_arc) = task_files(t) {
            let table = table_arc.lock();
            table.fds().copied().collect()
        } else {
            return Ok(());
        }
    };

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

    fn statfs(&self) -> StatFs {
        StatFs {
            f_type: PROC_SUPER_MAGIC,
            f_bsize: 4096,
            f_namelen: 255,
            ..StatFs::default()
        }
    }

    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, KernelError> {
        let inode = try_arc(Inode::new(
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
        inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
            ProcfsInodeData::new_dir()?,
        )))?);

        Ok(inode)
    }
}

/// The process of a /proc/<pid> or /proc/<pid>/task/<tid> directory
fn pid_dir_pid(inode: &Inode) -> Option<TaskRef> {
    let p = inode.get_private()?;
    let w = p.as_ref().as_any().downcast_ref::<ProcfsInodeWrapper>()?;
    let pid = match &*w.0.read() {
        ProcfsInodeData::PidDirectory { pid } => pid.clone(),
        _ => return None,
    };
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

/// Generate /proc/meminfo content (Linux meminfo_proc_show subset:
/// 16-column labels, values in kB). Free memory is the frame
/// allocator's exact count; Buffers is the block devices' caches,
/// Cached the rest of the page cache (ramfs included, as Linux counts
/// tmpfs), Unevictable ramfs's, MemAvailable free plus the clean
/// evictable cache. Writeback is 0 (writes are synchronous). Slab is
/// the slab caches' pages.
fn gen_meminfo() -> Vec<u8> {
    use alloc::fmt::Write;
    let fa = &crate::FRAME_ALLOCATOR;
    let total = fa.stats().total_bytes >> 10;
    let free = (fa.free_frames() as u64 * 4096) >> 10;
    let slab = (crate::mm::slab::slab_bytes() as u64) >> 10;
    let (swap_total, swap_free) = crate::mm::swap::swap_totals();
    let swap_cached = crate::mm::swap_state::total_cached();
    let mut out = String::new();
    use crate::mm::filemap;
    let file = filemap::nr_file_pages() * 4;
    let buffers: u64 = crate::block::blkdev::all_bdev_inodes()
        .iter()
        .map(|i| i.i_data.nrpages() * 4)
        .sum();
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
        ("Slab:", slab),
    ] {
        let _ = writeln!(out, "{label:<16}{kb:>8} kB");
    }
    out.into_bytes()
}

/// The sysctl behind a /proc/sys inode
fn sysctl_of(inode: &Inode) -> Option<&'static crate::sysctl::Ctl> {
    let private = inode.get_private()?;
    let w = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()?;
    match &*w.0.read() {
        ProcfsInodeData::Sysctl { ctl } => Some(*ctl),
        _ => None,
    }
}

/// A new procfs inode with `data`
fn mk_inode(
    sb: &Arc<SuperBlock>,
    mode: InodeMode,
    data: ProcfsInodeData,
) -> Result<Arc<Inode>, KernelError> {
    let inode = try_arc(Inode::new(
        sb.alloc_ino(),
        mode,
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(sb),
        &PROCFS_INODE_OPS,
    ))?;
    inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(data)))?);
    Ok(inode)
}

/// Child directory `name` of `dir`, created if missing
fn subdir(sb: &Arc<SuperBlock>, dir: &Arc<Inode>, name: &str) -> Result<Arc<Inode>, KernelError> {
    let private = dir.get_private().expect("procfs dir");
    let w = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()
        .expect("procfs dir");
    let mut data = w.0.write();
    let children = data.children_mut().expect("procfs dir");
    if let Some(c) = children.get(name) {
        return Ok(c.clone());
    }
    let d = mk_inode(sb, InodeMode::directory(0o555), ProcfsInodeData::new_dir()?)?;
    children.insert(String::from(name), d.clone());
    Ok(d)
}

/// /proc/sys from the sysctl tables
fn build_sys(sb: &Arc<SuperBlock>, root: &Arc<Inode>) -> Result<(), KernelError> {
    let sys = subdir(sb, root, "sys")?;
    for ctl in crate::sysctl::tables().iter().flat_map(|t| t.iter()) {
        let (dirs, name) = ctl.path.rsplit_once('/').unwrap_or(("", ctl.path));
        let mut d = sys.clone();
        for part in dirs.split('/').filter(|p| !p.is_empty()) {
            d = subdir(sb, &d, part)?;
        }
        let f = mk_inode(
            sb,
            InodeMode::regular(ctl.mode),
            ProcfsInodeData::Sysctl { ctl },
        )?;
        let private = d.get_private().expect("procfs dir");
        let w = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .expect("procfs dir");
        if let Some(c) = w.0.write().children_mut() {
            c.insert(String::from(name), f);
        }
    }
    Ok(())
}

/// Mount function for procfs
/// Every procfs superblock, for proc_flush_pid
static PROC_SBS: crate::sync::spin::Mutex<Vec<alloc::sync::Weak<SuperBlock>>> =
    crate::sync::spin::Mutex::new(Vec::new());

/// A released task's /proc entries leave every procfs dcache (Linux
/// proc_flush_pid): /proc/<tid>, and the process directory with it
/// when the task was its leader, /proc/<pid>/task/<tid> otherwise, each
/// named as that procfs's pid namespace numbers it. TASKLIST not held.
pub fn proc_flush_pid(t: &crate::task::Task) {
    use crate::task::percpu::TASKLIST;
    // Its struct pid and its leader's, whose numbers stay readable after
    // they are given back; taken under TASKLIST, dropped after it
    let (thread, leader) = {
        let table = TASKLIST.read();
        let thread = t
            .inner()
            .access(&table)
            .as_ref()
            .and_then(|i| i.thread_pid().cloned());
        let leader = if t.tid() == t.pid {
            None
        } else {
            table.get(t.pid).and_then(|l| l.thread_pid().cloned())
        };
        (thread, leader)
    };
    let Some(thread) = thread else {
        return;
    };
    let sbs: Vec<Arc<SuperBlock>> = {
        let mut v = PROC_SBS.lock();
        v.retain(|w| w.strong_count() != 0);
        v.iter().filter_map(alloc::sync::Weak::upgrade).collect()
    };
    let name = |n: u32| alloc::format!("{n}").into_bytes();
    for sb in sbs {
        let ns = opts::sb_pid_ns(&sb);
        let (Some(root), Some(tid)) = (sb.get_root(), thread.nr_in(&ns)) else {
            continue;
        };
        root.remove_child(&name(tid));
        if let Some(pid) = leader.as_ref().and_then(|l| l.nr_in(&ns))
            && let Some(task) = root
                .lookup_child(&name(pid))
                .and_then(|d| d.lookup_child(b"task"))
        {
            task.remove_child(&name(tid));
        }
    }
}

fn procfs_mount(
    fs_type: &'static FileSystemType,
    data: &[u8],
) -> Result<Arc<SuperBlock>, KernelError> {
    let opts = try_arc(opts::ProcOpts::new(data)?)?;
    // Create superblock
    let sb = SuperBlock::new(fs_type, &PROCFS_SUPER_OPS, 0)?;
    sb.set_private(opts);
    PROC_SBS.lock().push(Arc::downgrade(&sb));

    // Create root inode (directory)
    let root_inode = try_arc(Inode::new(
        sb.alloc_ino(),
        InodeMode::directory(0o555),
        0, // uid: root
        0, // gid: root
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    root_inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_dir()?,
    )))?);

    // Create /proc/version
    let version_inode = try_arc(Inode::new(
        sb.alloc_ino(),
        InodeMode::regular(0o444),
        0, // uid: root
        0, // gid: root
        0, // Size will be determined on read
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    version_inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_file(gen_version),
    )))?);

    // /proc/mounts -> self/mounts (Linux proc_symlink)
    let mounts_inode = mk_inode(
        &sb,
        InodeMode::symlink(),
        ProcfsInodeData::FixedLink(b"self/mounts"),
    )?;

    let meminfo_inode = mk_inode(
        &sb,
        InodeMode::regular(0o444),
        ProcfsInodeData::new_file(gen_meminfo),
    )?;
    let loadavg_inode = mk_inode(
        &sb,
        InodeMode::regular(0o444),
        ProcfsInodeData::new_file(crate::task::loadavg::proc_loadavg),
    )?;

    // Create /proc/net (directory) with /proc/net/{dev,route}; contents follow
    // the reader's network namespace
    let net_dir_inode = try_arc(Inode::new(
        sb.alloc_ino(),
        InodeMode::directory(0o555),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    let mut net_dir = ProcfsInodeData::new_dir()?;
    let net_dev_inode = try_arc(Inode::new(
        sb.alloc_ino(),
        InodeMode::regular(0o444),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    net_dev_inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_file(crate::net::proc::proc_net_dev),
    )))?);
    let net_route_inode = try_arc(Inode::new(
        sb.alloc_ino(),
        InodeMode::regular(0o444),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ))?;
    net_route_inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_file(crate::net::proc::proc_net_route),
    )))?);
    let net_arp_inode = mk_inode(
        &sb,
        InodeMode::regular(0o444),
        ProcfsInodeData::new_file(crate::net::arp::proc_net_arp),
    )?;
    if let Some(children) = net_dir.children_mut() {
        children.insert(String::from("dev"), net_dev_inode);
        children.insert(String::from("route"), net_route_inode);
        children.insert(String::from("arp"), net_arp_inode);
        let udp = mk_inode(
            &sb,
            InodeMode::regular(0o444),
            ProcfsInodeData::new_file(crate::net::udp::proc_net_udp),
        )?;
        children.insert(String::from("udp"), udp);
        let tcp = mk_inode(
            &sb,
            InodeMode::regular(0o444),
            ProcfsInodeData::new_file(crate::net::tcp::info::proc_net_tcp),
        )?;
        children.insert(String::from("tcp"), tcp);
        let unix = mk_inode(
            &sb,
            InodeMode::regular(0o444),
            ProcfsInodeData::new_file(crate::net::unix::proc_net_unix),
        )?;
        children.insert(String::from("unix"), unix);
        let packet = mk_inode(
            &sb,
            InodeMode::regular(0o444),
            ProcfsInodeData::new_file(crate::net::packet::proc_net_packet),
        )?;
        children.insert(String::from("packet"), packet);
    }
    net_dir_inode.set_private(try_arc(ProcfsInodeWrapper(RwLock::new(net_dir)))?);

    // Add files to root directory
    {
        let private = root_inode.get_private().unwrap();
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .unwrap();
        let mut data = wrapper.0.write();
        if let Some(children) = data.children_mut() {
            children.insert(String::from("version"), version_inode);
            children.insert(String::from("mounts"), mounts_inode);
            children.insert(String::from("meminfo"), meminfo_inode);
            children.insert(String::from("loadavg"), loadavg_inode);
            let slabinfo = mk_inode(
                &sb,
                InodeMode::regular(0o400),
                ProcfsInodeData::new_file(crate::mm::slab::slabinfo),
            )?;
            children.insert(String::from("slabinfo"), slabinfo);
            children.insert(String::from("net"), net_dir_inode);
            let parts = mk_inode(
                &sb,
                InodeMode::regular(0o444),
                ProcfsInodeData::new_file(crate::block::genhd::proc_partitions),
            )?;
            children.insert(String::from("partitions"), parts);
        }
    }

    build_sys(&sb, &root_inode)?;

    // Create root dentry
    let root_dentry = try_arc(Dentry::new_root(root_inode, Arc::downgrade(&sb)))?;

    // Set root in superblock
    sb.set_root(root_dentry);

    Ok(sb)
}

/// Procfs filesystem type
pub static PROCFS_TYPE: FileSystemType = FileSystemType {
    name: "proc",
    fs_flags: super::superblock::fs_flags::FS_PSEUDO,
    mount: procfs_mount,
    mount_dev: None, // Procfs doesn't use a backing device
    file_ops: &PROCFS_FILE_OPS,
};
