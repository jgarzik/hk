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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::spin::RwLock;
use ::core::cmp::min;

use super::KernelError;
use super::dentry::Dentry;
use super::file::{DirContext, DirEntry, File, FileOps};
use super::inode::{AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::superblock::{FileSystemType, PROC_SUPER_MAGIC, StatFs, SuperBlock, SuperOps};
use crate::task::Cred;
use crate::task::Pid;

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
    use crate::task::percpu::TASK_TABLE;
    let table = TASK_TABLE.lock();
    table.iter().any(|t| t.pid == pid)
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
    use crate::task::percpu::TASK_TABLE;
    let table = TASK_TABLE.lock();
    table.find(|t| t.pid == pid).map(|t| t.task.tid)
}

/// Inode number for per-PID directories
///
/// We use a simple scheme: PID * 1000 + offset
/// - offset 0: /proc/<pid>
/// - offset 1: /proc/<pid>/ns
/// - offset 2+: /proc/<pid>/ns/<type>
fn pid_ino(pid: Pid, offset: u64) -> u64 {
    // Use high range to avoid conflicts with static inodes
    0x1000_0000 + pid * 1000 + offset
}

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
    /// Directory with static children
    Directory {
        children: BTreeMap<String, Arc<Inode>>,
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
    /// Fdinfo file (/proc/<pid>/fdinfo/<n>)
    ///
    /// File containing information about an open file descriptor.
    FdinfoFile { pid: Pid, fd: i32 },
    /// Generated per-process file (/proc/<pid>/cgroup, maps, ...)
    PidFile { pid: Pid, generator: PidGen },
    /// Per-process symlink (/proc/<pid>/exe)
    PidLink {
        pid: Pid,
        target: fn(Pid) -> Result<String, KernelError>,
    },
    /// /proc/sys file (readable, maybe writable)
    Sysctl { ctl: &'static crate::sysctl::Ctl },
}

impl ProcfsInodeData {
    /// Create directory data
    pub fn new_dir() -> Self {
        Self::Directory {
            children: BTreeMap::new(),
        }
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
    pub fn children_mut(&mut self) -> Option<&mut BTreeMap<String, Arc<Inode>>> {
        match self {
            Self::Directory { children } => Some(children),
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
    fn readlink(&self, inode: &Inode) -> Result<String, KernelError> {
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(KernelError::Io)?;
        let data = wrapper.0.read();
        // A link target may sleep (exe takes exec_update_lock): call it
        // after dropping the inode data's spinning read lock
        if let ProcfsInodeData::PidLink { pid, target } = &*data {
            let (pid, target) = (*pid, *target);
            drop(data);
            return target(pid);
        }
        match &*data {
            ProcfsInodeData::SelfLink => {
                Ok(alloc::format!("{}", crate::task::percpu::current_pid()))
            }
            ProcfsInodeData::FdSymlink { pid, fd } => fd_link(*pid, *fd),
            _ => Err(KernelError::InvalidArgument),
        }
    }

    /// /proc/sys files: Linux proc_sys_permission (never executable,
    /// then sysctl_perm: no capability override of the mode); fd/ and
    /// fdinfo/ need ptrace-read access
    fn permission(&self, inode: &Inode, cred: &Cred, mask: u32) -> Result<(), KernelError> {
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

    fn lookup(&self, dir: &Inode, name: &str) -> Result<Arc<Inode>, KernelError> {
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        let data = wrapper.0.read();
        match &*data {
            ProcfsInodeData::Directory { children } => {
                // First check static children
                if let Some(child) = children.get(name) {
                    return Ok(child.clone());
                }

                // Check if this is the root /proc directory looking up a PID
                // Root /proc has ino == 1 typically (first allocated inode)
                // We detect root by checking if it's the procfs root (has static entries like "version")
                if children.contains_key("version") {
                    if name == "self" {
                        return Ok(create_self_link(dir));
                    }
                    // This is /proc root - check for numeric PID lookup
                    if let Ok(pid) = name.parse::<u64>()
                        && task_exists(pid)
                    {
                        return Ok(create_pid_dir_inode(dir, pid));
                    }
                }

                Err(KernelError::NotFound)
            }
            ProcfsInodeData::PidDirectory { pid } => {
                // Handle /proc/<pid>/* lookups
                lookup_pid_entry(dir, *pid, name)
            }
            ProcfsInodeData::PidNsDirectory { pid } => {
                // Handle /proc/<pid>/ns/* lookups
                lookup_pid_ns_entry(dir, *pid, name)
            }
            ProcfsInodeData::PidFdDirectory { pid } => {
                // Handle /proc/<pid>/fd/* lookups
                lookup_pid_fd_entry(dir, *pid, name)
            }
            ProcfsInodeData::PidFdinfoDirectory { pid } => {
                // Handle /proc/<pid>/fdinfo/* lookups
                lookup_pid_fdinfo_entry(dir, *pid, name)
            }
            ProcfsInodeData::File { .. }
            | ProcfsInodeData::NamespaceFile { .. }
            | ProcfsInodeData::FdSymlink { .. }
            | ProcfsInodeData::PidLink { .. }
            | ProcfsInodeData::SelfLink
            | ProcfsInodeData::FdinfoFile { .. }
            | ProcfsInodeData::PidFile { .. }
            | ProcfsInodeData::Sysctl { .. } => Err(KernelError::NotDirectory),
        }
    }

    fn readpage(
        &self,
        inode: &Inode,
        page_offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, KernelError> {
        // For procfs, we generate content on demand
        // This is called for page cache integration but procfs typically
        // doesn't use the page cache (content is ephemeral)
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        let data = wrapper.0.read();
        let content = match &*data {
            ProcfsInodeData::File { generator } => generator(),
            ProcfsInodeData::NamespaceFile { pid, ns_type } => {
                // Generate namespace identifier content
                // Format matches Linux: "ns:[<inode>]" but we use a simpler format
                gen_namespace_content(*pid, *ns_type)
            }
            ProcfsInodeData::FdinfoFile { pid, fd } => gen_fdinfo_content(*pid, *fd),
            ProcfsInodeData::PidFile { pid, generator } => pid_content(None, *pid, *generator)?,
            ProcfsInodeData::Sysctl { ctl } => crate::sysctl::read(ctl),
            ProcfsInodeData::FdSymlink { .. }
            | ProcfsInodeData::PidLink { .. }
            | ProcfsInodeData::SelfLink => {
                // Symlinks don't have content, readlink() handles them
                return Err(KernelError::Io);
            }
            ProcfsInodeData::Directory { .. }
            | ProcfsInodeData::PidDirectory { .. }
            | ProcfsInodeData::PidNsDirectory { .. }
            | ProcfsInodeData::PidFdDirectory { .. }
            | ProcfsInodeData::PidFdinfoDirectory { .. } => return Err(KernelError::IsDirectory),
        };

        let page_size = buf.len();
        let offset = page_offset as usize * page_size;

        if offset >= content.len() {
            buf.fill(0);
            return Ok(0);
        }

        let available = content.len() - offset;
        let to_copy = min(page_size, available);

        buf[..to_copy].copy_from_slice(&content[offset..offset + to_copy]);
        if to_copy < page_size {
            buf[to_copy..].fill(0);
        }

        Ok(to_copy)
    }
}

// ============================================================================
// Per-PID Inode Creation Helpers
// ============================================================================

/// Create a /proc/<pid> directory inode
fn create_pid_dir_inode(parent: &Inode, pid: Pid) -> Arc<Inode> {
    let sb = parent.superblock().expect("superblock dropped");
    let inode = Arc::new(Inode::new(
        pid_ino(pid, 0),
        InodeMode::directory(0o555), // r-xr-xr-x
        0,                           // uid: root
        0,                           // gid: root
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_pid_dir(pid),
    ))));
    inode
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
            let inode = Arc::new(Inode::new(
                pid_ino(pid, 1),
                InodeMode::directory(0o555), // r-xr-xr-x
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ));
            inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::new_pid_ns_dir(pid),
            ))));
            Ok(inode)
        }
        "fd" => {
            // Create /proc/<pid>/fd directory
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = Arc::new(Inode::new(
                pid_ino(pid, 100),           // offset 100 for fd dir
                InodeMode::directory(0o500), // dr-x------ (only owner can read)
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ));
            inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::new_pid_fd_dir(pid),
            ))));
            Ok(inode)
        }
        "fdinfo" => {
            // Create /proc/<pid>/fdinfo directory
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = Arc::new(Inode::new(
                pid_ino(pid, 101),           // offset 101 for fdinfo dir
                InodeMode::directory(0o500), // dr-x------ (only owner can read)
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ));
            inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::new_pid_fdinfo_dir(pid),
            ))));
            Ok(inode)
        }
        "exe" => {
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = Arc::new(Inode::new(
                pid_ino(pid, 104),
                InodeMode::symlink(),
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ));
            inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::PidLink {
                    pid,
                    target: exe_link,
                },
            ))));
            Ok(inode)
        }
        name if pid_file(name).is_some() => {
            let (off, mode, generator) = pid_file(name).ok_or(KernelError::NotFound)?;
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let (uid, gid) = dump_owner(pid);
            let inode = Arc::new(Inode::new(
                pid_ino(pid, off),
                InodeMode::regular(mode),
                uid,
                gid,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ));
            inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::new_pid_file(pid, generator),
            ))));
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

    let inode = Arc::new(Inode::new(
        pid_ino(pid, offset),
        InodeMode::regular(0o444), // r--r--r--
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_ns_file(pid, ns_type),
    ))));
    Ok(inode)
}

/// /proc/self (resolved at readlink time to the reader's pid)
fn create_self_link(parent: &Inode) -> Arc<Inode> {
    let sb = parent.superblock().expect("superblock dropped");
    let inode = Arc::new(Inode::new(
        pid_ino(0, 999),
        InodeMode::symlink(),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::SelfLink,
    ))));
    inode
}

/// Target of /proc/<pid>/fd/<fd>: `socket:[ino]` / `pipe:[ino]` for
/// sockets and pipes, `anon_inode:<name>` for other files without a
/// filesystem, else the path
fn fd_link(pid: Pid, fd: i32) -> Result<String, KernelError> {
    let tid = get_tid_for_pid(pid).ok_or(KernelError::NotFound)?;
    let table = crate::task::fdtable::get_task_fd(tid).ok_or(KernelError::NotFound)?;
    let file = table.lock().get(fd).ok_or(KernelError::NotFound)?;
    let inode = file.get_inode().ok_or(KernelError::NotFound)?;
    let mode = inode.mode();
    if mode.is_socket() {
        return Ok(alloc::format!("socket:[{}]", inode.ino));
    }
    if inode.superblock().is_none() {
        if mode.file_type() == Some(crate::fs::inode::FileType::Fifo) {
            return Ok(alloc::format!("pipe:[{}]", inode.ino));
        }
        return Ok(alloc::format!("anon_inode:{}", file.dentry.name));
    }
    Ok(file.dentry.full_path())
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
    let inode = Arc::new(Inode::new(
        pid_ino(pid, 200 + fd as u64), // offset 200+ for fd symlinks
        InodeMode::symlink(),          // lrwxrwxrwx
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_fd_symlink(pid, fd),
    ))));
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
    let inode = Arc::new(Inode::new(
        pid_ino(pid, 500 + fd as u64), // offset 500+ for fdinfo files
        InodeMode::regular(0o444),     // r--r--r--
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_fdinfo_file(pid, fd),
    ))));
    Ok(inode)
}

/// Generate content for /proc/<pid>/fdinfo/<n> files
fn gen_fdinfo_content(pid: Pid, fd: i32) -> Vec<u8> {
    use alloc::fmt::Write;
    let mut output = String::new();

    // Get the task's TID
    let tid = match get_tid_for_pid(pid) {
        Some(t) => t,
        None => {
            return Vec::new();
        }
    };

    // Get file info from the FD table
    let (flags, is_pidfd, pidfd_target_pid) = {
        if let Some(table_arc) = crate::task::fdtable::get_task_fd(tid) {
            let table = table_arc.lock();
            if let Some(file) = table.get(fd) {
                let flags = file.get_flags();
                // Check if this is a pidfd
                let target_pid = crate::pidfd::get_pidfd_pid(&file);
                (flags, target_pid.is_some(), target_pid)
            } else {
                return Vec::new();
            }
        } else {
            return Vec::new();
        }
    };

    // Output in Linux fdinfo format
    let _ = writeln!(output, "pos:\t0");
    let _ = writeln!(output, "flags:\t{:o}", flags);
    let _ = writeln!(output, "mnt_id:\t0");

    // If this is a pidfd, add the Pid line (Linux-compatible)
    if is_pidfd && let Some(target) = pidfd_target_pid {
        let _ = writeln!(output, "Pid:\t{}", target);
    }

    Vec::from(output.as_bytes())
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
    Mm(fn(&crate::mm::Mm, &crate::mm::MmStruct) -> Vec<u8>),
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

/// Content of a per-process file for this open file (or, with none,
/// checked afresh)
fn pid_content(file: Option<&File>, pid: Pid, g: PidGen) -> Result<Vec<u8>, KernelError> {
    match g {
        PidGen::Pub(f) => Ok(f(pid)),
        PidGen::Mm(f) => {
            let mm = match file.and_then(|fl| fl.private.get()) {
                Some(p) => p.clone().downcast::<crate::mm::Mm>().ok(),
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
            let g = m.mmap_read_killable()?;
            let out = f(&m, &g);
            Ok(out)
        }
    }
}

/// Generated files in /proc/<pid>/: name, inode offset, mode (Linux
/// fs/proc/base.c tgid_base_stuff), generator
const PID_FILES: &[(&str, u64, u16, PidGen)] = &[
    ("cgroup", 102, 0o444, PidGen::Pub(gen_cgroup_content)),
    ("maps", 103, 0o444, PidGen::Mm(gen_maps)),
    (
        "status",
        105,
        0o444,
        PidGen::Pub(super::proc_array::gen_status),
    ),
    ("stat", 106, 0o444, PidGen::Pub(super::proc_array::gen_stat)),
    (
        "cmdline",
        107,
        0o444,
        PidGen::Pub(super::proc_array::gen_cmdline),
    ),
    (
        "environ",
        108,
        0o400,
        PidGen::Mm(super::proc_array::gen_environ),
    ),
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
    use crate::task::percpu::TASK_TABLE;
    let table = TASK_TABLE.lock();
    table
        .find(|t| t.tgid == pid)
        .filter(|t| {
            t.mm.as_ref()
                .is_none_or(|m| m.dumpable() == crate::task::dumpable::SUID_DUMP_USER)
        })
        .map_or((0, 0), |t| (t.cred.euid, t.cred.egid))
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

/// /proc/<pid>/exe: the executable's path (ENOENT for kernel threads,
/// EACCES without ptrace-read access, Linux proc_fd_access_allowed)
fn exe_link(pid: Pid) -> Result<String, KernelError> {
    // Through mm_access, so the check and the image it reveals are one
    // (exec_update_lock read). An exec resolving /proc/self/exe (busybox
    // re-execs itself) holds only cred_guard while it walks paths: it
    // takes exec_update for writing later, in exec_replace_image
    let mm = mm_access(pid)?.ok_or(KernelError::NotFound)?;
    let exe = mm
        .mmap_read_killable()?
        .exe()
        .ok_or(KernelError::NotFound)?;
    Ok(exe)
}

/// /proc/<pid>/maps: one line per VMA (Linux show_map_vma)
fn gen_maps(_: &crate::mm::Mm, mm: &crate::mm::MmStruct) -> Vec<u8> {
    use crate::mm::{PROT_EXEC, PROT_READ, PROT_WRITE, VM_GROWSDOWN, VM_SHARED};
    use alloc::fmt::Write;
    let mut out = String::new();
    let (start_brk, brk) = (mm.get_start_brk(), mm.get_brk());
    for v in mm.iter() {
        let bit = |b: bool, c: char| if b { c } else { '-' };
        let (ino, dev, name) = match &v.file {
            Some(f) => {
                let ino = f.get_inode().map(|i| i.ino).unwrap_or(0);
                (ino, "00:00", f.dentry.full_path())
            }
            None if v.flags & VM_GROWSDOWN != 0 => (0, "00:00", String::from("[stack]")),
            None if v.start >= start_brk
                && v.end <= brk.next_multiple_of(4096)
                && brk > start_brk =>
            {
                (0, "00:00", String::from("[heap]"))
            }
            None => (0, "00:00", String::new()),
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
        if !name.is_empty() {
            while line.len() < 73 {
                line.push(' ');
            }
            line.push_str(&name);
        }
        let _ = writeln!(out, "{}", line.trim_end());
    }
    Vec::from(out.as_bytes())
}

/// Get the cgroup path for a task (virtualized to its namespace)
fn get_task_cgroup_path(pid: Pid) -> String {
    use crate::cgroup::TASK_CGROUP;
    use crate::ns::INIT_CGROUP_NS;
    use crate::task::percpu::TASK_TABLE;

    // Get the task's TID to look up its cgroup namespace
    let tid = match get_tid_for_pid(pid) {
        Some(t) => t,
        None => return String::from("/"),
    };

    // Get the task's cgroup
    let task_cgroup = {
        let table = TASK_TABLE.lock();
        if let Some(task) = table.get(tid) {
            // Try to get from TASK_CGROUP mapping
            TASK_CGROUP.read().get(&task.task.tid).cloned()
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
    let cgroup_ns = {
        let table = TASK_TABLE.lock();
        if let Some(task) = table.get(tid) {
            if let Some(ref nsproxy) = task.nsproxy {
                nsproxy.cgroup_ns.clone()
            } else {
                INIT_CGROUP_NS.clone()
            }
        } else {
            INIT_CGROUP_NS.clone()
        }
    };

    // Translate the cgroup path relative to the namespace root
    cgroup_ns.translate_path(&cgroup)
}

/// Copy `content` from the file position on into `buf` and advance it
fn copy_out(file: &File, buf: &mut [u8], content: &[u8]) -> usize {
    let pos = file.get_pos() as usize;
    if pos >= content.len() {
        return 0; // EOF
    }
    let n = min(buf.len(), content.len() - pos);
    buf[..n].copy_from_slice(&content[pos..pos + n]);
    file.advance_pos(n as u64);
    n
}

/// Copy `content` from `offset` on into `buf` (pread: no position)
fn copy_at(buf: &mut [u8], content: &[u8], offset: u64) -> usize {
    let pos = offset as usize;
    if pos >= content.len() {
        return 0;
    }
    let n = min(buf.len(), content.len() - pos);
    buf[..n].copy_from_slice(&content[pos..pos + n]);
    n
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
    fn mmap(&self, file: &File) -> Result<(), KernelError> {
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
        let Some(check) = file.get_inode().and_then(|i| open_check(&i)) else {
            return Ok(());
        };
        match check {
            OpenCheck::Mm(pid) => {
                if let Some(mm) = mm_access(pid)? {
                    file.private.call_once(|| mm);
                }
                Ok(())
            }
            OpenCheck::Fds(pid) if crate::task::ptrace::may_read_proc(pid) => Ok(()),
            OpenCheck::Fds(_) => Err(KernelError::PermissionDenied),
        }
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        let data = wrapper.0.read();
        // Per-process generators may sleep (exec_update_lock, mmap_lock):
        // they run after the inode data's spinning read lock is dropped
        if let ProcfsInodeData::PidFile { pid, generator } = &*data {
            let (pid, g) = (*pid, *generator);
            drop(data);
            let content = pid_content(Some(file), pid, g)?;
            return Ok(copy_out(file, buf, &content));
        }
        let content = match &*data {
            ProcfsInodeData::File { generator } => generator(),
            ProcfsInodeData::NamespaceFile { pid, ns_type } => {
                gen_namespace_content(*pid, *ns_type)
            }
            ProcfsInodeData::FdinfoFile { pid, fd } => gen_fdinfo_content(*pid, *fd),
            ProcfsInodeData::PidFile { .. } => return Err(KernelError::Io),
            ProcfsInodeData::Sysctl { ctl } => crate::sysctl::read(ctl),
            ProcfsInodeData::FdSymlink { .. }
            | ProcfsInodeData::PidLink { .. }
            | ProcfsInodeData::SelfLink => {
                return Err(KernelError::Io);
            }
            ProcfsInodeData::Directory { .. }
            | ProcfsInodeData::PidDirectory { .. }
            | ProcfsInodeData::PidNsDirectory { .. }
            | ProcfsInodeData::PidFdDirectory { .. }
            | ProcfsInodeData::PidFdinfoDirectory { .. } => return Err(KernelError::IsDirectory),
        };

        drop(data);
        Ok(copy_out(file, buf, &content))
    }

    fn pread(&self, file: &File, buf: &mut [u8], offset: u64) -> Result<usize, KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        let data = wrapper.0.read();
        // Per-process generators may sleep (exec_update_lock, mmap_lock):
        // they run after the inode data's spinning read lock is dropped
        if let ProcfsInodeData::PidFile { pid, generator } = &*data {
            let (pid, g) = (*pid, *generator);
            drop(data);
            let content = pid_content(Some(file), pid, g)?;
            return Ok(copy_at(buf, &content, offset));
        }
        let content = match &*data {
            ProcfsInodeData::File { generator } => generator(),
            ProcfsInodeData::NamespaceFile { pid, ns_type } => {
                gen_namespace_content(*pid, *ns_type)
            }
            ProcfsInodeData::FdinfoFile { pid, fd } => gen_fdinfo_content(*pid, *fd),
            ProcfsInodeData::PidFile { .. } => return Err(KernelError::Io),
            ProcfsInodeData::Sysctl { ctl } => crate::sysctl::read(ctl),
            ProcfsInodeData::FdSymlink { .. }
            | ProcfsInodeData::PidLink { .. }
            | ProcfsInodeData::SelfLink => {
                return Err(KernelError::Io);
            }
            ProcfsInodeData::Directory { .. }
            | ProcfsInodeData::PidDirectory { .. }
            | ProcfsInodeData::PidNsDirectory { .. }
            | ProcfsInodeData::PidFdDirectory { .. }
            | ProcfsInodeData::PidFdinfoDirectory { .. } => return Err(KernelError::IsDirectory),
        };

        let pos = offset as usize;

        if pos >= content.len() {
            return Ok(0); // EOF
        }

        let available = content.len() - pos;
        let to_read = min(buf.len(), available);

        buf[..to_read].copy_from_slice(&content[pos..pos + to_read]);
        // NOTE: Unlike read(), we do NOT advance file position

        Ok(to_read)
    }

    /// Writes reach /proc/sys files only
    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let ctl = sysctl_of(&inode).ok_or(KernelError::Io)?;
        crate::sysctl::permission(ctl, &crate::task::current_cred(), crate::fs::MAY_WRITE)?;
        let n = crate::sysctl::write(ctl, buf, file.get_pos())?;
        file.advance_pos(n as u64);
        Ok(n)
    }

    fn readdir(&self, file: &File, ctx: &mut DirContext) -> Result<(), KernelError> {
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

        let data = wrapper.0.read();

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

        match &*data {
            ProcfsInodeData::Directory { children } => {
                // Emit static children
                for (name, child_inode) in children.iter() {
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
                    readdir_emit_pids(inode.ino, ctx)?;
                }
            }
            ProcfsInodeData::PidDirectory { pid } => {
                // Emit /proc/<pid>/* entries
                readdir_emit_pid_entries(*pid, ctx)?;
            }
            ProcfsInodeData::PidNsDirectory { pid } => {
                // Emit /proc/<pid>/ns/* entries
                readdir_emit_ns_entries(*pid, ctx)?;
            }
            ProcfsInodeData::PidFdDirectory { pid } => {
                // Emit /proc/<pid>/fd/* entries
                readdir_emit_fd_entries(*pid, ctx)?;
            }
            ProcfsInodeData::PidFdinfoDirectory { pid } => {
                // Emit /proc/<pid>/fdinfo/* entries
                readdir_emit_fdinfo_entries(*pid, ctx)?;
            }
            ProcfsInodeData::File { .. }
            | ProcfsInodeData::NamespaceFile { .. }
            | ProcfsInodeData::FdSymlink { .. }
            | ProcfsInodeData::PidLink { .. }
            | ProcfsInodeData::SelfLink
            | ProcfsInodeData::FdinfoFile { .. }
            | ProcfsInodeData::PidFile { .. }
            | ProcfsInodeData::Sysctl { .. } => {
                return Err(KernelError::NotDirectory);
            }
        }

        Ok(())
    }
}

/// First readdir position of the PID entries in /proc (Linux
/// FIRST_PROCESS_ENTRY): the static entries sit below it
const PID_POS: u64 = 256;

/// Emit PID directory entries for /proc readdir; a PID's position is
/// PID_POS + pid (Linux proc_pid_readdir), stable while others exit
fn readdir_emit_pids(proc_ino: u64, ctx: &mut DirContext) -> Result<(), KernelError> {
    use crate::task::percpu::TASK_TABLE;

    // Collect PIDs first to release lock quickly (sorted, unique)
    let pids: alloc::collections::BTreeSet<Pid> = {
        let table = TASK_TABLE.lock();
        table.iter().map(|t| t.pid).filter(|&p| p != 0).collect()
    };

    for pid in pids {
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

    let _ = proc_ino; // Silence unused warning
    Ok(())
}

/// Emit entries for /proc/<pid>/ directory
fn readdir_emit_pid_entries(pid: Pid, ctx: &mut DirContext) -> Result<(), KernelError> {
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
        ino: pid_ino(pid, 104),
        file_type: FileType::Symlink,
        name: Vec::from(&b"exe"[..]),
    }) {
        return Ok(());
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
fn readdir_emit_ns_entries(pid: Pid, ctx: &mut DirContext) -> Result<(), KernelError> {
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
fn readdir_emit_fd_entries(pid: Pid, ctx: &mut DirContext) -> Result<(), KernelError> {
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
                ino: pid_ino(pid, 200 + fd as u64),
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
fn readdir_emit_fdinfo_entries(pid: Pid, ctx: &mut DirContext) -> Result<(), KernelError> {
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
                ino: pid_ino(pid, 500 + fd as u64),
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
        let inode = Arc::new(Inode::new(
            sb.alloc_ino(),
            mode,
            0, // uid: root owns all procfs entries
            0, // gid: root group
            0,
            current_time(),
            Arc::downgrade(sb),
            i_op,
        ));

        // Default to empty directory
        inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
            ProcfsInodeData::new_dir(),
        ))));

        Ok(inode)
    }
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
/// allocator's exact count; hk has no reclaimable caches counted yet,
/// so MemAvailable equals MemFree. Slab is the slab caches' pages.
fn gen_meminfo() -> Vec<u8> {
    use alloc::fmt::Write;
    let fa = &crate::FRAME_ALLOCATOR;
    let total = fa.stats().total_bytes >> 10;
    let free = (fa.free_frames() as u64 * 4096) >> 10;
    let slab = (crate::mm::slab::slab_bytes() as u64) >> 10;
    let (swap_total, swap_free) = crate::mm::swap::swap_totals();
    let swap_cached = crate::mm::swap_state::total_cached();
    let mut out = String::new();
    for (label, kb) in [
        ("MemTotal:", total),
        ("MemFree:", free),
        ("MemAvailable:", free),
        ("Buffers:", 0),
        ("Cached:", 0),
        ("SwapCached:", swap_cached * 4),
        ("SwapTotal:", swap_total * 4),
        ("SwapFree:", swap_free * 4),
        ("Slab:", slab),
    ] {
        let _ = writeln!(out, "{label:<16}{kb:>8} kB");
    }
    out.into_bytes()
}

/// Generate /proc/mounts content
///
/// Format: device mountpoint fstype options dump pass
/// Example: none / ramfs rw 0 0
fn gen_mounts() -> Vec<u8> {
    use crate::ns::current_mnt_ns;
    use alloc::fmt::Write;

    let mut output = String::new();

    // Get root mount from current task's mount namespace
    if let Some(root_mount) = current_mnt_ns().get_root() {
        // Output root mount
        let fs_name = root_mount.sb.fs_type.name;
        let _ = writeln!(output, "none / {} {} 0 0", fs_name, root_mount.opts());

        // Walk children recursively
        gen_mounts_recursive(&root_mount, &mut output);
    }

    Vec::from(output.as_bytes())
}

/// Recursively generate mount entries for child mounts
fn gen_mounts_recursive(mount: &super::mount::Mount, output: &mut String) {
    use alloc::fmt::Write;

    for child in mount.children.read().iter() {
        let fs_name = child.sb.fs_type.name;

        // Get mount point path
        let mountpoint = if let Some(mp) = child.get_mountpoint() {
            mp.full_path()
        } else {
            String::from("unknown")
        };

        let _ = writeln!(
            output,
            "none {} {} {} 0 0",
            mountpoint,
            fs_name,
            child.opts()
        );

        // Recurse into children
        gen_mounts_recursive(child, output);
    }
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
fn mk_inode(sb: &Arc<SuperBlock>, mode: InodeMode, data: ProcfsInodeData) -> Arc<Inode> {
    let inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        mode,
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(sb),
        &PROCFS_INODE_OPS,
    ));
    inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(data))));
    inode
}

/// Child directory `name` of `dir`, created if missing
fn subdir(sb: &Arc<SuperBlock>, dir: &Arc<Inode>, name: &str) -> Arc<Inode> {
    let private = dir.get_private().expect("procfs dir");
    let w = private
        .as_ref()
        .as_any()
        .downcast_ref::<ProcfsInodeWrapper>()
        .expect("procfs dir");
    let mut data = w.0.write();
    let children = data.children_mut().expect("procfs dir");
    if let Some(c) = children.get(name) {
        return c.clone();
    }
    let d = mk_inode(sb, InodeMode::directory(0o555), ProcfsInodeData::new_dir());
    children.insert(String::from(name), d.clone());
    d
}

/// /proc/sys from the sysctl tables
fn build_sys(sb: &Arc<SuperBlock>, root: &Arc<Inode>) {
    let sys = subdir(sb, root, "sys");
    for ctl in crate::sysctl::tables().iter().flat_map(|t| t.iter()) {
        let (dirs, name) = ctl.path.rsplit_once('/').unwrap_or(("", ctl.path));
        let mut d = sys.clone();
        for part in dirs.split('/').filter(|p| !p.is_empty()) {
            d = subdir(sb, &d, part);
        }
        let f = mk_inode(
            sb,
            InodeMode::regular(ctl.mode),
            ProcfsInodeData::Sysctl { ctl },
        );
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
}

/// Mount function for procfs
fn procfs_mount(fs_type: &'static FileSystemType) -> Result<Arc<SuperBlock>, KernelError> {
    // Create superblock
    let sb = SuperBlock::new(fs_type, &PROCFS_SUPER_OPS, 0);

    // Create root inode (directory)
    let root_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        InodeMode::directory(0o555),
        0, // uid: root
        0, // gid: root
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    root_inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_dir(),
    ))));

    // Create /proc/version
    let version_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        InodeMode::regular(0o444),
        0, // uid: root
        0, // gid: root
        0, // Size will be determined on read
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    version_inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_file(gen_version),
    ))));

    // Create /proc/mounts
    let mounts_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        InodeMode::regular(0o444),
        0, // uid: root
        0, // gid: root
        0, // Size will be determined on read
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    mounts_inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_file(gen_mounts),
    ))));

    let meminfo_inode = mk_inode(
        &sb,
        InodeMode::regular(0o444),
        ProcfsInodeData::new_file(gen_meminfo),
    );

    // Create /proc/net (directory) with /proc/net/{dev,route}; contents follow
    // the reader's network namespace
    let net_dir_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        InodeMode::directory(0o555),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    let mut net_dir = ProcfsInodeData::new_dir();
    let net_dev_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        InodeMode::regular(0o444),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    net_dev_inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_file(crate::net::proc::proc_net_dev),
    ))));
    let net_route_inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        InodeMode::regular(0o444),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &PROCFS_INODE_OPS,
    ));
    net_route_inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
        ProcfsInodeData::new_file(crate::net::proc::proc_net_route),
    ))));
    let net_arp_inode = mk_inode(
        &sb,
        InodeMode::regular(0o444),
        ProcfsInodeData::new_file(crate::net::arp::proc_net_arp),
    );
    if let ProcfsInodeData::Directory { children } = &mut net_dir {
        children.insert(String::from("dev"), net_dev_inode);
        children.insert(String::from("route"), net_route_inode);
        children.insert(String::from("arp"), net_arp_inode);
        let udp = mk_inode(
            &sb,
            InodeMode::regular(0o444),
            ProcfsInodeData::new_file(crate::net::udp::proc_net_udp),
        );
        children.insert(String::from("udp"), udp);
        let tcp = mk_inode(
            &sb,
            InodeMode::regular(0o444),
            ProcfsInodeData::new_file(crate::net::tcp::info::proc_net_tcp),
        );
        children.insert(String::from("tcp"), tcp);
        let unix = mk_inode(
            &sb,
            InodeMode::regular(0o444),
            ProcfsInodeData::new_file(crate::net::unix::proc_net_unix),
        );
        children.insert(String::from("unix"), unix);
        let packet = mk_inode(
            &sb,
            InodeMode::regular(0o444),
            ProcfsInodeData::new_file(crate::net::packet::proc_net_packet),
        );
        children.insert(String::from("packet"), packet);
    }
    net_dir_inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(net_dir))));

    // Add files to root directory
    {
        let private = root_inode.get_private().unwrap();
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .unwrap();
        let mut data = wrapper.0.write();
        if let ProcfsInodeData::Directory { children } = &mut *data {
            children.insert(String::from("version"), version_inode);
            children.insert(String::from("mounts"), mounts_inode);
            children.insert(String::from("meminfo"), meminfo_inode);
            let slabinfo = mk_inode(
                &sb,
                InodeMode::regular(0o400),
                ProcfsInodeData::new_file(crate::mm::slab::slabinfo),
            );
            children.insert(String::from("slabinfo"), slabinfo);
            children.insert(String::from("net"), net_dir_inode);
            let parts = mk_inode(
                &sb,
                InodeMode::regular(0o444),
                ProcfsInodeData::new_file(crate::storage::genhd::proc_partitions),
            );
            children.insert(String::from("partitions"), parts);
        }
    }

    build_sys(&sb, &root_inode);

    // Create root dentry
    let root_dentry = Arc::new(Dentry::new_root(root_inode, Arc::downgrade(&sb)));

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
