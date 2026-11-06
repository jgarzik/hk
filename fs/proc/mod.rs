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
use crate::task::Cred;
use crate::task::Pid;
use crate::util::kalloc::try_arc;

/// Get current timestamp for new inodes
/// Returns current wall-clock time from TIMEKEEPER if available, otherwise zero
fn current_time() -> Timespec {
    use crate::time::TIMEKEEPER;
    TIMEKEEPER.current_time()
}

/// Check if a task with the given PID exists
///
/// Looks up the PID in the global task table.
fn task_exists(pid: Pid) -> bool {
    use crate::task::percpu::TASKLIST;
    let table = TASKLIST.read();
    table.get(pid).is_some()
}

/// Public version of task_exists for use by setns
pub fn task_exists_pub(pid: Pid) -> bool {
    task_exists(pid)
}

/// Get the TID for a task with the given PID
///
/// Looks up the PID in the global task table and returns the TID.
/// Returns None if no task with the given PID exists.
pub fn get_tid_for_pid(pid: Pid) -> Option<crate::task::Tid> {
    use crate::task::percpu::TASKLIST;
    let table = TASKLIST.read();
    table.get(pid).map(|t| t.task.tid())
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
    PidDirectory { pid: Pid },
    /// Per-PID namespace directory (/proc/<pid>/ns)
    ///
    /// Contains namespace files for setns(2).
    PidNsDirectory { pid: Pid },
    /// Namespace file (/proc/<pid>/ns/<type>)
    ///
    /// Can be opened and passed to setns(2) to join a namespace.
    NamespaceFile { pid: Pid, ns_type: NamespaceType },
    /// Thread directory (/proc/<pid>/task): one entry per thread, each
    /// a view of the process directory (per-thread files are a subset)
    PidTaskDirectory { pid: Pid },
    /// Per-PID fd directory (/proc/<pid>/fd)
    ///
    /// Contains symlinks to open file descriptors.
    PidFdDirectory { pid: Pid },
    /// Per-PID fdinfo directory (/proc/<pid>/fdinfo)
    ///
    /// Contains files with information about open file descriptors.
    PidFdinfoDirectory { pid: Pid },
    /// Fd symlink (/proc/<pid>/fd/<n>)
    ///
    /// Symlink to the open file descriptor.
    FdSymlink { pid: Pid, fd: i32 },
    /// /proc/self: symlink to the reader's process directory
    SelfLink,
    /// A symlink with a fixed target (/proc/mounts -> self/mounts)
    FixedLink(&'static [u8]),
    /// Fdinfo file (/proc/<pid>/fdinfo/<n>)
    ///
    /// File containing information about an open file descriptor.
    FdinfoFile { pid: Pid, fd: i32 },
    /// Generated per-process file (/proc/<pid>/cgroup, maps, ...)
    PidFile { pid: Pid, generator: PidGen },
    /// Per-process symlink (/proc/<pid>/exe)
    PidLink { pid: Pid, target: LinkFn },
    /// /proc/sys file (readable, maybe writable)
    Sysctl { ctl: &'static crate::sysctl::Ctl },
    /// /proc/<pid>/fail-nth: the task's fault-injection countdown
    /// (Linux proc_fail_nth_operations, `mm::fault_inject`)
    FailNth { pid: Pid },
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
    pub fn new_pid_dir(pid: Pid) -> Self {
        Self::PidDirectory { pid }
    }

    /// Create per-PID namespace directory data
    pub fn new_pid_ns_dir(pid: Pid) -> Self {
        Self::PidNsDirectory { pid }
    }

    /// Create namespace file data
    pub fn new_ns_file(pid: Pid, ns_type: NamespaceType) -> Self {
        Self::NamespaceFile { pid, ns_type }
    }

    /// Create per-PID fd directory data
    pub fn new_pid_fd_dir(pid: Pid) -> Self {
        Self::PidFdDirectory { pid }
    }

    /// Create per-PID fdinfo directory data
    pub fn new_pid_fdinfo_dir(pid: Pid) -> Self {
        Self::PidFdinfoDirectory { pid }
    }

    /// Create fd symlink data
    pub fn new_fd_symlink(pid: Pid, fd: i32) -> Self {
        Self::FdSymlink { pid, fd }
    }

    /// Create fdinfo file data
    pub fn new_fdinfo_file(pid: Pid, fd: i32) -> Self {
        Self::FdinfoFile { pid, fd }
    }

    /// Create per-process generated file data
    pub fn new_pid_file(pid: Pid, generator: PidGen) -> Self {
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
    pub fn pid(&self) -> Option<Pid> {
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
            | Self::PidLink { pid, .. } => Some(*pid),
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
            Pid(Pid, LinkFn),
            Me,
            Fixed(&'static [u8]),
            Fd(Pid, i32),
        }
        let l = match &*wrapper.0.read() {
            ProcfsInodeData::PidLink { pid, target } => Link::Pid(*pid, *target),
            ProcfsInodeData::SelfLink => Link::Me,
            ProcfsInodeData::FixedLink(t) => Link::Fixed(t),
            ProcfsInodeData::FdSymlink { pid, fd } => Link::Fd(*pid, *fd),
            _ => return Err(KernelError::InvalidArgument),
        };
        match l {
            Link::Pid(pid, target) => target(pid),
            Link::Me => Ok(alloc::format!("{}", crate::task::percpu::current_pid()).into_bytes()),
            Link::Fixed(t) => Ok(t.to_vec()),
            Link::Fd(pid, fd) => fd_link(pid, fd),
        }
    }

    /// /proc/sys files: Linux proc_sys_permission (never executable,
    /// then sysctl_perm: no capability override of the mode); fd/ and
    /// fdinfo/ need ptrace-read access
    /// Linux proc_pid_getattr: a process hidepid=invisible hides is
    /// ENOENT to stat too (a dentry looked up by someone else stays
    /// cached), consistent with readdir
    fn getattr_ok(&self, inode: &Inode) -> Result<(), KernelError> {
        match pid_dir_pid(inode) {
            Some(pid) if !opts::with(inode, |o| o.visible(pid)).unwrap_or(true) => {
                Err(KernelError::NotFound)
            }
            _ => Ok(()),
        }
    }

    fn permission(&self, inode: &Inode, cred: &Cred, mask: u32) -> Result<(), KernelError> {
        // A process directory hidepid= hides (Linux proc_pid_permission)
        if let Some(pid) = pid_dir_pid(inode) {
            opts::with(inode, |o| o.pid_permission(pid)).unwrap_or(Ok(()))?;
        }
        // fd/ and fdinfo/: ptrace-read access (Linux proc_fd_permission)
        if let Some(OpenCheck::Fds(pid)) = open_check(inode)
            && !crate::task::ptrace::may_read_proc(pid)
        {
            return Err(KernelError::PermissionDenied);
        }
        // The owner follows the task's identity and dumpability (Linux
        // pid_revalidate -> pid_update_inode)
        if let Some(pid) = pid_file_pid(inode) {
            let (uid, gid) = dump_owner(pid);
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
        let Some(pid) = data.pid() else {
            return true;
        };
        let fd = match &*data {
            ProcfsInodeData::FdSymlink { fd, .. } | ProcfsInodeData::FdinfoFile { fd, .. } => {
                Some(*fd)
            }
            _ => None,
        };
        drop(data);
        if !task_exists(pid) {
            return false;
        }
        if let Some(fd) = fd {
            let open = get_tid_for_pid(pid)
                .and_then(crate::task::fdtable::get_task_fd)
                .is_some_and(|t| t.lock().get(fd).is_some());
            if !open {
                return false;
            }
        }
        let (uid, gid) = dump_owner(pid);
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
            Pid(Pid),
            Ns(Pid),
            Fd(Pid),
            Task(Pid),
            Fdinfo(Pid),
        }
        let kind = match &*wrapper.0.read() {
            // A static child, and whether this is the root (it has
            // "version")
            ProcfsInodeData::Directory { children } => Dir::Static(
                children.get(name).cloned(),
                children.contains_key("version"),
            ),
            ProcfsInodeData::PidDirectory { pid } => Dir::Pid(*pid),
            ProcfsInodeData::PidNsDirectory { pid } => Dir::Ns(*pid),
            ProcfsInodeData::PidFdDirectory { pid } => Dir::Fd(*pid),
            ProcfsInodeData::PidTaskDirectory { pid } => Dir::Task(*pid),
            ProcfsInodeData::PidFdinfoDirectory { pid } => Dir::Fdinfo(*pid),
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
                    // This is /proc root - check for numeric PID lookup
                    // hidepid=invisible: another user's process is not there
                    if let Ok(pid) = name.parse::<u64>()
                        && task_exists(pid)
                        && opts::with(dir, |o| o.visible(pid)).unwrap_or(true)
                    {
                        return create_pid_dir_inode(dir, pid);
                    }
                }

                Err(KernelError::NotFound)
            }
            Dir::Pid(pid) => lookup_pid_entry(dir, pid, name),
            Dir::Ns(pid) => lookup_pid_ns_entry(dir, pid, name),
            Dir::Fd(pid) => lookup_pid_fd_entry(dir, pid, name),
            Dir::Task(pid) => {
                let tid: crate::task::Tid = name.parse().map_err(|_| KernelError::NotFound)?;
                if group_threads(pid).contains(&tid) {
                    create_dir_inode(dir, pid_ino(tid, 0), ProcfsInodeData::new_pid_dir(pid))
                } else {
                    Err(KernelError::NotFound)
                }
            }
            Dir::Fdinfo(pid) => lookup_pid_fdinfo_entry(dir, pid, name),
        }
    }
}

// ============================================================================
// Per-PID Inode Creation Helpers
// ============================================================================

/// Create a /proc/<pid> directory inode
/// The live threads (tids) of process `pid`
fn group_threads(pid: Pid) -> alloc::vec::Vec<crate::task::Tid> {
    use crate::task::percpu::TASKLIST;
    let table = TASKLIST.read();
    table
        .threads(pid)
        .filter(|t| !matches!(t.state, crate::task::TaskState::Zombie(_)))
        .map(|t| t.task.tid())
        .collect()
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

fn create_pid_dir_inode(parent: &Inode, pid: Pid) -> Result<Arc<Inode>, KernelError> {
    let sb = parent.superblock().expect("superblock dropped");
    let inode = try_arc(Inode::new(
        pid_ino(pid, 0),
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
fn lookup_pid_entry(dir: &Inode, pid: Pid, name: &str) -> Result<Arc<Inode>, KernelError> {
    // Verify the task still exists
    if !task_exists(pid) {
        return Err(KernelError::NotFound);
    }

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
                ProcfsInodeData::new_pid_ns_dir(pid),
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
                ProcfsInodeData::new_pid_fd_dir(pid),
            )))?);
            Ok(inode)
        }
        "task" => create_dir_inode(
            dir,
            pid_ino(pid, 120),
            ProcfsInodeData::PidTaskDirectory { pid },
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
                ProcfsInodeData::new_pid_fdinfo_dir(pid),
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
                ProcfsInodeData::PidLink { pid, target },
            )))?);
            Ok(inode)
        }
        "fail-nth" => {
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let (uid, gid) = dump_owner(pid);
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
                ProcfsInodeData::FailNth { pid },
            )))?);
            Ok(inode)
        }
        name if pid_file(name).is_some() => {
            let (off, mode, generator) = pid_file(name).ok_or(KernelError::NotFound)?;
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let (uid, gid) = dump_owner(pid);
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
                ProcfsInodeData::new_pid_file(pid, generator),
            )))?);
            Ok(inode)
        }
        _ => Err(KernelError::NotFound),
    }
}

/// Look up entries in /proc/<pid>/ns/
fn lookup_pid_ns_entry(dir: &Inode, pid: Pid, name: &str) -> Result<Arc<Inode>, KernelError> {
    // Verify the task still exists
    if !task_exists(pid) {
        return Err(KernelError::NotFound);
    }

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

    let inode = try_arc(Inode::new(
        pid_ino(pid, offset),
        InodeMode::regular(0o444), // r--r--r--
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
    Ok(inode)
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
fn fd_link(pid: Pid, fd: i32) -> Result<Vec<u8>, KernelError> {
    let tid = get_tid_for_pid(pid).ok_or(KernelError::NotFound)?;
    let table = crate::task::fdtable::get_task_fd(tid).ok_or(KernelError::NotFound)?;
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
    Ok(file
        .f_path()
        .map(|p| super::dentry::d_path_link(&p))
        .unwrap_or_default())
}

/// Look up entries in /proc/<pid>/fd/
fn lookup_pid_fd_entry(dir: &Inode, pid: Pid, name: &str) -> Result<Arc<Inode>, KernelError> {
    // Verify the task still exists
    if !task_exists(pid) {
        return Err(KernelError::NotFound);
    }

    // Parse fd number from name
    let fd: i32 = name.parse().map_err(|_| KernelError::NotFound)?;
    if fd < 0 {
        return Err(KernelError::NotFound);
    }

    // Verify the FD exists for this task
    let tid = get_tid_for_pid(pid).ok_or(KernelError::NotFound)?;
    let fd_exists = {
        if let Some(table_arc) = crate::task::fdtable::get_task_fd(tid) {
            let table = table_arc.lock();
            table.get(fd).is_some()
        } else {
            false
        }
    };
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
        ProcfsInodeData::new_fd_symlink(pid, fd),
    )))?);
    Ok(inode)
}

/// Look up entries in /proc/<pid>/fdinfo/
fn lookup_pid_fdinfo_entry(dir: &Inode, pid: Pid, name: &str) -> Result<Arc<Inode>, KernelError> {
    // Verify the task still exists
    if !task_exists(pid) {
        return Err(KernelError::NotFound);
    }

    // Parse fd number from name
    let fd: i32 = name.parse().map_err(|_| KernelError::NotFound)?;
    if fd < 0 {
        return Err(KernelError::NotFound);
    }

    // Verify the FD exists for this task
    let tid = get_tid_for_pid(pid).ok_or(KernelError::NotFound)?;
    let fd_exists = {
        if let Some(table_arc) = crate::task::fdtable::get_task_fd(tid) {
            let table = table_arc.lock();
            table.get(fd).is_some()
        } else {
            false
        }
    };
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
        ProcfsInodeData::new_fdinfo_file(pid, fd),
    )))?);
    Ok(inode)
}

/// /proc/<pid>/fdinfo/<n> (Linux seq_show): position, open flags
/// (O_CLOEXEC added for a close-on-exec descriptor) in octal with a
/// leading 0, the mount id, the inode number; then the file's own lines
fn gen_fdinfo_content(pid: Pid, fd: i32) -> Vec<u8> {
    use alloc::fmt::Write;
    let Some(tid) = get_tid_for_pid(pid) else {
        return Vec::new();
    };
    let Some(table) = crate::task::fdtable::get_task_fd(tid) else {
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
    if let Some(target) = crate::task::pidfd::get_pidfd_pid(&file) {
        let _ = writeln!(out, "Pid:\t{}", target);
    }
    out.into_bytes()
}

/// Generate content for namespace files
///
/// Returns a string identifying the namespace, similar to Linux's
/// "ns:[inode]" format but simplified.
fn gen_namespace_content(pid: Pid, ns_type: NamespaceType) -> Vec<u8> {
    use alloc::fmt::Write;
    let mut output = String::new();

    // Format: <type>:[<pid>]
    // This identifies which namespace instance the task is in
    let _ = writeln!(output, "{}:[{}]", ns_type.as_str(), pid);
    Vec::from(output.as_bytes())
}

/// Generate content for /proc/<pid>/cgroup
///
/// Returns the cgroup membership for the process.
/// For cgroup v2, this is a single line: "0::<path>\n"
/// The path is relative to the task's cgroup namespace root.
fn gen_cgroup_content(pid: Pid) -> Vec<u8> {
    use alloc::fmt::Write;
    let mut output = String::new();

    // Get the task's cgroup path (namespace-virtualized)
    let cgroup_path = get_task_cgroup_path(pid);

    // cgroup v2 format: "0::<path>"
    // The "0" indicates the unified hierarchy (cgroup v2)
    // The empty string between colons indicates no named controllers
    let _ = writeln!(output, "0::{}", cgroup_path);

    Vec::from(output.as_bytes())
}

/// Generated files in /proc/<pid>/: name, inode offset, generator
/// Access checks a procfs file needs at open
enum OpenCheck {
    /// Address-space file of `pid`: pin its mm
    Mm(Pid),
    /// fd/ or fdinfo/ of `pid`
    Fds(Pid),
}

/// The open-time check of `inode`, if any
fn open_check(inode: &Inode) -> Option<OpenCheck> {
    let private = inode.get_private()?;
    let wrapper = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()?;
    match &*wrapper.0.read() {
        ProcfsInodeData::PidFile {
            pid,
            generator: PidGen::Mm(_),
        } => Some(OpenCheck::Mm(*pid)),
        ProcfsInodeData::PidFdDirectory { pid } | ProcfsInodeData::PidFdinfoDirectory { pid } => {
            Some(OpenCheck::Fds(*pid))
        }
        _ => None,
    }
}

/// Content generator of a per-process file
#[derive(Clone, Copy)]
pub enum PidGen {
    /// World-readable content of the process
    Pub(fn(Pid) -> Vec<u8>),
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
fn mm_access(pid: Pid) -> Result<Option<Arc<crate::mm::Mm>>, KernelError> {
    let Some(tid) = get_tid_for_pid(pid) else {
        return Ok(None);
    };
    // The check and the mm it covers under the process's
    // exec_update_lock: no exec of it switches mm or dumpability between
    // exec_update_lock; check and mm both of that one task, so a pid
    // reused meanwhile cannot split them
    let _g = crate::signal::ExecUpdateRead::lock(tid);
    if !crate::task::ptrace::may_read_task(tid) {
        return Err(KernelError::PermissionDenied);
    }
    Ok(crate::mm::get_task_mm(tid))
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
fn pid_content(file: Option<&File>, pid: Pid, g: PidGen) -> Result<Vec<u8>, KernelError> {
    match g {
        PidGen::Pub(f) => Ok(f(pid)),
        PidGen::Mm(f) => {
            let mm = match file.and_then(proc_open) {
                Some(p) => p.mm.clone(),
                None => mm_access(pid)?,
            };
            // The open file pins only the struct (mm_count); a read uses
            // the address space only while it still has users, else it
            // reads as empty; once the task is reaped it is ESRCH (Linux
            // m_start: get_proc_task, mmget_not_zero)
            if get_tid_for_pid(pid).is_none() {
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
    ("status", 105, 0o444, PidGen::Pub(array::gen_status)),
    ("stat", 106, 0o444, PidGen::Pub(array::gen_stat)),
    ("cmdline", 107, 0o444, PidGen::Pub(array::gen_cmdline)),
    ("environ", 108, 0o400, PidGen::Mm(array::gen_environ)),
    ("mounts", 109, 0o444, PidGen::Pub(mounts::show_mounts)),
    ("mountinfo", 110, 0o444, PidGen::Pub(mounts::show_mountinfo)),
];

/// The process of a /proc/<pid>/fail-nth inode
fn fail_nth_of(inode: &Inode) -> Option<Pid> {
    let private = inode.get_private()?;
    let w = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()?;
    match &*w.0.read() {
        ProcfsInodeData::FailNth { pid } => Some(*pid),
        _ => None,
    }
}

/// Set task `pid`'s countdown from a decimal (or 0x/0 prefixed) number
/// (Linux proc_fail_nth_write: kstrtouint, any task the file names)
fn write_fail_nth(pid: Pid, from: &mut IovSource<'_>) -> Result<usize, KernelError> {
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
    fail_nth_task(pid)?
        .fail_nth
        .store(n, core::sync::atomic::Ordering::Relaxed);
    Ok(len)
}

/// Inode offset of /proc/<pid>/fail-nth
const FAIL_NTH_INO: u64 = 113;

/// Task `pid`, for its fault-injection countdown
fn fail_nth_task(pid: Pid) -> Result<crate::task::percpu::TaskRef, KernelError> {
    crate::task::percpu::TASKLIST
        .read()
        .task(pid)
        .ok_or(KernelError::NoProcess)
}

/// Per-process symlinks: name, inode offset, target (Linux
/// proc_exe_link, proc_cwd_link, proc_root_link)
/// The target of a per-process symlink
type LinkFn = fn(Pid) -> Result<Vec<u8>, KernelError>;

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
fn dump_owner(pid: Pid) -> (u32, u32) {
    use crate::task::percpu::TASKLIST;
    let table = TASKLIST.read();
    table
        .get(pid)
        .filter(|t| {
            t.task
                .task_lock()
                .mm()
                .is_none_or(|m| m.dumpable() == crate::task::dumpable::SUID_DUMP_USER)
        })
        .map_or((0, 0), |t| (t.cred().euid, t.cred().egid))
}

/// The process a per-process file belongs to
fn pid_file_pid(inode: &Inode) -> Option<Pid> {
    let private = inode.get_private()?;
    let wrapper = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()?;
    match &*wrapper.0.read() {
        ProcfsInodeData::PidFile { pid, .. } => Some(*pid),
        _ => None,
    }
}

/// /proc/<pid>/cwd and root: the task's fs pwd or root as the reader
/// names it, EACCES without ptrace-read access (Linux
/// proc_fd_access_allowed), ENOENT for a task without one
fn fs_link(pid: Pid, root: bool) -> Result<Vec<u8>, KernelError> {
    let tid = get_tid_for_pid(pid).ok_or(KernelError::NotFound)?;
    if !crate::task::ptrace::may_read_task(tid) {
        return Err(KernelError::PermissionDenied);
    }
    let fs = crate::fs::get_task_fs(tid).ok_or(KernelError::NotFound)?;
    let p = if root { fs.get_root() } else { fs.get_pwd() };
    Ok(super::dentry::d_path_link(&p))
}

fn cwd_link(pid: Pid) -> Result<Vec<u8>, KernelError> {
    fs_link(pid, false)
}

fn root_link(pid: Pid) -> Result<Vec<u8>, KernelError> {
    fs_link(pid, true)
}

/// /proc/<pid>/exe: the executable's path (ENOENT for kernel threads,
/// EACCES without ptrace-read access, Linux proc_fd_access_allowed)
fn exe_link(pid: Pid) -> Result<Vec<u8>, KernelError> {
    // Through mm_access, so the check and the image it reveals are one
    // (exec_update_lock read). An exec resolving /proc/self/exe (busybox
    // re-execs itself) holds only cred_guard while it walks paths: it
    // takes exec_update for writing later, in exec_replace_image
    let mm = mm_access(pid)?.ok_or(KernelError::NotFound)?;
    let exe = mm
        .mmap_read_killable()?
        .exe()
        .ok_or(KernelError::NotFound)?;
    Ok(exe.into_vec())
}

/// /proc/<pid>/maps: one line per VMA (Linux show_map_vma)
fn gen_maps(m: &crate::mm::Mm) -> Result<Vec<u8>, KernelError> {
    let g = m.mmap_read_killable()?;
    Ok(maps_of(&g))
}

/// /proc/<pid>/maps of `mm`, its mmap_lock held
fn maps_of(mm: &crate::mm::MmStruct) -> Vec<u8> {
    use crate::mm::{PROT_EXEC, PROT_READ, PROT_WRITE, VM_GROWSDOWN, VM_SHARED};
    use alloc::fmt::Write;
    let mut out = Vec::new();
    let (start_brk, brk) = (mm.get_start_brk(), mm.get_brk());
    for v in mm.iter() {
        let bit = |b: bool, c: char| if b { c } else { '-' };
        let (ino, dev, name) = match &v.file {
            Some(f) => {
                let ino = f.get_inode().map(|i| i.ino).unwrap_or(0);
                // seq_file_path(m, file, "\n"): a newline in a name
                // cannot start a forged line
                let mut p = Vec::new();
                let name = f.f_path().map(|fp| super::dentry::d_path_link(&fp));
                super::name::mangle(&mut p, &name.unwrap_or_default(), b"\n");
                (ino, "00:00", p)
            }
            None if v.flags & VM_GROWSDOWN != 0 => (0, "00:00", b"[stack]".to_vec()),
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
        out.extend_from_slice(&line);
        out.push(b'\n');
    }
    out
}

/// Get the cgroup path for a task (virtualized to its namespace)
fn get_task_cgroup_path(pid: Pid) -> String {
    use crate::ns::INIT_CGROUP_NS;
    use crate::task::percpu::TASKLIST;

    // Get the task's TID to look up its cgroup namespace
    let tid = match get_tid_for_pid(pid) {
        Some(t) => t,
        None => return String::from("/"),
    };

    // Get the task's cgroup
    let task_cgroup = {
        let table = TASKLIST.read();
        if let Some(task) = table.get(tid) {
            // Try to get from TASK_CGROUP mapping
            task.task.cgroup.lock().clone()
        } else {
            None
        }
    };

    let cgroup = match task_cgroup {
        Some(cg) => cg,
        None => {
            // Task not in any cgroup - return root
            return String::from("/");
        }
    };

    // Get the task's cgroup namespace
    let cgroup_ns = crate::ns::get_task_ns(tid)
        .map_or_else(|| INIT_CGROUP_NS.clone(), |ns| ns.cgroup_ns.clone());

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
        Pid(Pid, PidGen),
        File(ContentGenerator),
        Ns(Pid, NamespaceType),
        Fdinfo(Pid, i32),
        Sysctl(&'static crate::sysctl::Ctl),
        FailNth(Pid),
    }
    let g = match &*wrapper.0.read() {
        ProcfsInodeData::PidFile { pid, generator } => Gen::Pid(*pid, *generator),
        ProcfsInodeData::File { generator } => Gen::File(*generator),
        ProcfsInodeData::NamespaceFile { pid, ns_type } => Gen::Ns(*pid, *ns_type),
        ProcfsInodeData::FdinfoFile { pid, fd } => Gen::Fdinfo(*pid, *fd),
        ProcfsInodeData::Sysctl { ctl } => Gen::Sysctl(ctl),
        ProcfsInodeData::FailNth { pid } => Gen::FailNth(*pid),
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
    Ok(match g {
        Gen::Pid(pid, g) => return pid_content(Some(file), pid, g),
        Gen::File(generator) => generator(),
        Gen::Ns(pid, ns_type) => gen_namespace_content(pid, ns_type),
        Gen::Fdinfo(pid, fd) => gen_fdinfo_content(pid, fd),
        Gen::Sysctl(ctl) => crate::sysctl::read(ctl),
        Gen::FailNth(pid) => {
            let n = fail_nth_task(pid)?
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

    /// Private per-process files check ptrace-read access at open
    /// (Linux proc_mem_open, proc_fd_permission); maps keeps the address
    /// space it was opened on, so a later setuid exec cannot leak
    fn open(&self, file: &File) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let mm = match open_check(&inode) {
            Some(OpenCheck::Mm(pid)) => mm_access(pid)?,
            Some(OpenCheck::Fds(pid)) if !crate::task::ptrace::may_read_proc(pid) => {
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
        if let Some(pid) = fail_nth_of(&inode) {
            return write_fail_nth(pid, from);
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
            Pid(Pid),
            Ns(Pid),
            Fd(Pid),
            Task(Pid),
            Fdinfo(Pid),
        }
        let kind = match &*wrapper.0.read() {
            ProcfsInodeData::Directory { children } => Dir::Static(children.clone()),
            ProcfsInodeData::PidDirectory { pid } => Dir::Pid(*pid),
            ProcfsInodeData::PidNsDirectory { pid } => Dir::Ns(*pid),
            ProcfsInodeData::PidFdDirectory { pid } => Dir::Fd(*pid),
            ProcfsInodeData::PidTaskDirectory { pid } => Dir::Task(*pid),
            ProcfsInodeData::PidFdinfoDirectory { pid } => Dir::Fdinfo(*pid),
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
            Dir::Pid(pid) => readdir_emit_pid_entries(pid, ctx)?,
            Dir::Ns(pid) => readdir_emit_ns_entries(pid, ctx)?,
            Dir::Fd(pid) => readdir_emit_fd_entries(pid, ctx)?,
            Dir::Task(pid) => {
                for tid in group_threads(pid) {
                    let e = DirEntry {
                        ino: pid_ino(tid, 0),
                        file_type: FileType::Directory,
                        name: Vec::from(alloc::format!("{tid}").as_bytes()),
                    };
                    if !ctx.emit(e) {
                        break;
                    }
                }
            }
            Dir::Fdinfo(pid) => readdir_emit_fdinfo_entries(pid, ctx)?,
        }

        Ok(())
    }
}

/// First readdir position of the PID entries in /proc (Linux
/// FIRST_PROCESS_ENTRY): the static entries sit below it
const PID_POS: u64 = 256;

/// Emit PID directory entries for /proc readdir; a PID's position is
/// PID_POS + pid (Linux proc_pid_readdir), stable while others exit
fn readdir_emit_pids(root: &Inode, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
    use crate::task::percpu::TASKLIST;

    // Collect PIDs first to release lock quickly (sorted, unique)
    let pids: alloc::collections::BTreeSet<Pid> = {
        let table = TASKLIST.read();
        table
            .iter()
            .map(|t| t.task.pid)
            .filter(|&p| p != 0)
            .collect()
    };

    // hidepid=invisible: other users' processes are left out
    for pid in pids
        .into_iter()
        .filter(|&p| opts::with(root, |o| o.visible(p)).unwrap_or(true))
    {
        let name = alloc::format!("{}", pid);
        let e = DirEntry {
            ino: pid_ino(pid, 0),
            file_type: FileType::Directory,
            name: Vec::from(name.as_bytes()),
        };
        if !ctx.emit_at(PID_POS + pid, e) {
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
            file_type: FileType::Regular, // Namespace files appear as regular files
            name: Vec::from(ns_type.as_str().as_bytes()),
        });

        if !should_continue {
            break;
        }
    }

    Ok(())
}

/// Emit entries for /proc/<pid>/fd/ directory
fn readdir_emit_fd_entries(pid: Pid, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
    // Get the task's TID
    let tid = match get_tid_for_pid(pid) {
        Some(t) => t,
        None => return Ok(()),
    };

    // Get FDs from the task's FD table
    let fds: Vec<i32> = {
        if let Some(table_arc) = crate::task::fdtable::get_task_fd(tid) {
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
fn readdir_emit_fdinfo_entries(pid: Pid, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
    // Get the task's TID
    let tid = match get_tid_for_pid(pid) {
        Some(t) => t,
        None => return Ok(()),
    };

    // Get FDs from the task's FD table
    let fds: Vec<i32> = {
        if let Some(table_arc) = crate::task::fdtable::get_task_fd(tid) {
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
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0,
            f_ffree: 0,
            f_namelen: 255,
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
fn pid_dir_pid(inode: &Inode) -> Option<Pid> {
    let p = inode.get_private()?;
    let w = p.as_ref().as_any().downcast_ref::<ProcfsInodeWrapper>()?;
    match &*w.0.read() {
        ProcfsInodeData::PidDirectory { pid } => Some(*pid),
        _ => None,
    }
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
/// when the task was its leader, /proc/<pid>/task/<tid> otherwise
pub fn proc_flush_pid(pid: Pid, tid: Pid) {
    let sbs: Vec<Arc<SuperBlock>> = {
        let mut v = PROC_SBS.lock();
        v.retain(|w| w.strong_count() != 0);
        v.iter().filter_map(alloc::sync::Weak::upgrade).collect()
    };
    let name = |n: Pid| alloc::format!("{}", n).into_bytes();
    for sb in sbs {
        let Some(root) = sb.get_root() else {
            continue;
        };
        root.remove_child(&name(tid));
        if pid != tid
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
