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

use ::core::cmp::min;
use spin::RwLock;

use super::KernelError;
use super::dentry::Dentry;
use super::file::{DirEntry, File, FileOps};
use super::inode::{AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::superblock::{FileSystemType, PROC_SUPER_MAGIC, StatFs, SuperBlock, SuperOps};
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
    table.tasks.iter().any(|t| t.pid == pid)
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
    table.tasks.iter().find(|t| t.pid == pid).map(|t| t.tid)
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
    /// Fdinfo file (/proc/<pid>/fdinfo/<n>)
    ///
    /// File containing information about an open file descriptor.
    FdinfoFile { pid: Pid, fd: i32 },
    /// Cgroup file (/proc/<pid>/cgroup)
    ///
    /// Shows the cgroup(s) the process belongs to.
    /// For cgroup v2: "0::<path>\n"
    PidCgroupFile { pid: Pid },
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

    /// Create cgroup file data
    pub fn new_pid_cgroup_file(pid: Pid) -> Self {
        Self::PidCgroupFile { pid }
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
            | Self::PidCgroupFile { pid } => Some(*pid),
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
            | ProcfsInodeData::FdinfoFile { .. }
            | ProcfsInodeData::PidCgroupFile { .. } => Err(KernelError::NotDirectory),
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
            ProcfsInodeData::PidCgroupFile { pid } => gen_cgroup_content(*pid),
            ProcfsInodeData::FdSymlink { .. } => {
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
        "cgroup" => {
            // Create /proc/<pid>/cgroup file
            let sb = dir.superblock().ok_or(KernelError::Io)?;
            let inode = Arc::new(Inode::new(
                pid_ino(pid, 102),         // offset 102 for cgroup file
                InodeMode::regular(0o444), // r--r--r--
                0,
                0,
                0,
                current_time(),
                Arc::downgrade(&sb),
                &PROCFS_INODE_OPS,
            ));
            inode.set_private(Arc::new(ProcfsInodeWrapper(RwLock::new(
                ProcfsInodeData::new_pid_cgroup_file(pid),
            ))));
            Ok(inode)
        }
        // Future: add "status", "cmdline", "maps", etc.
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
        if let Some(task) = table.tasks.iter().find(|t| t.tid == tid) {
            // Try to get from TASK_CGROUP mapping
            TASK_CGROUP.read().get(&task.tid).cloned()
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
        if let Some(task) = table.tasks.iter().find(|t| t.tid == tid) {
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

/// Static procfs inode ops
pub static PROCFS_INODE_OPS: ProcfsInodeOps = ProcfsInodeOps;

/// Procfs file operations
pub struct ProcfsFileOps;

impl FileOps for ProcfsFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
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
        let content = match &*data {
            ProcfsInodeData::File { generator } => generator(),
            ProcfsInodeData::NamespaceFile { pid, ns_type } => {
                gen_namespace_content(*pid, *ns_type)
            }
            ProcfsInodeData::FdinfoFile { pid, fd } => gen_fdinfo_content(*pid, *fd),
            ProcfsInodeData::PidCgroupFile { pid } => gen_cgroup_content(*pid),
            ProcfsInodeData::FdSymlink { .. } => return Err(KernelError::Io),
            ProcfsInodeData::Directory { .. }
            | ProcfsInodeData::PidDirectory { .. }
            | ProcfsInodeData::PidNsDirectory { .. }
            | ProcfsInodeData::PidFdDirectory { .. }
            | ProcfsInodeData::PidFdinfoDirectory { .. } => return Err(KernelError::IsDirectory),
        };

        let pos = file.get_pos() as usize;

        if pos >= content.len() {
            return Ok(0); // EOF
        }

        let available = content.len() - pos;
        let to_read = min(buf.len(), available);

        buf[..to_read].copy_from_slice(&content[pos..pos + to_read]);
        file.advance_pos(to_read as u64);

        Ok(to_read)
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
        let content = match &*data {
            ProcfsInodeData::File { generator } => generator(),
            ProcfsInodeData::NamespaceFile { pid, ns_type } => {
                gen_namespace_content(*pid, *ns_type)
            }
            ProcfsInodeData::FdinfoFile { pid, fd } => gen_fdinfo_content(*pid, *fd),
            ProcfsInodeData::PidCgroupFile { pid } => gen_cgroup_content(*pid),
            ProcfsInodeData::FdSymlink { .. } => return Err(KernelError::Io),
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

    fn readdir(
        &self,
        file: &File,
        callback: &mut dyn FnMut(DirEntry) -> bool,
    ) -> Result<(), KernelError> {
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
        let should_continue = callback(DirEntry {
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

        let should_continue = callback(DirEntry {
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

                    let should_continue = callback(DirEntry {
                        ino: child_inode.ino,
                        file_type,
                        name: Vec::from(name.as_bytes()),
                    });

                    if !should_continue {
                        return Ok(());
                    }
                }

                // If this is /proc root (has "version"), also emit PIDs
                if children.contains_key("version") {
                    readdir_emit_pids(inode.ino, callback)?;
                }
            }
            ProcfsInodeData::PidDirectory { pid } => {
                // Emit /proc/<pid>/* entries
                readdir_emit_pid_entries(*pid, callback)?;
            }
            ProcfsInodeData::PidNsDirectory { pid } => {
                // Emit /proc/<pid>/ns/* entries
                readdir_emit_ns_entries(*pid, callback)?;
            }
            ProcfsInodeData::PidFdDirectory { pid } => {
                // Emit /proc/<pid>/fd/* entries
                readdir_emit_fd_entries(*pid, callback)?;
            }
            ProcfsInodeData::PidFdinfoDirectory { pid } => {
                // Emit /proc/<pid>/fdinfo/* entries
                readdir_emit_fdinfo_entries(*pid, callback)?;
            }
            ProcfsInodeData::File { .. }
            | ProcfsInodeData::NamespaceFile { .. }
            | ProcfsInodeData::FdSymlink { .. }
            | ProcfsInodeData::FdinfoFile { .. }
            | ProcfsInodeData::PidCgroupFile { .. } => {
                return Err(KernelError::NotDirectory);
            }
        }

        Ok(())
    }
}

/// Emit PID directory entries for /proc readdir
fn readdir_emit_pids(
    proc_ino: u64,
    callback: &mut dyn FnMut(DirEntry) -> bool,
) -> Result<(), KernelError> {
    use crate::task::percpu::TASK_TABLE;

    // Collect PIDs first to release lock quickly
    let pids: Vec<Pid> = {
        let table = TASK_TABLE.lock();
        table.tasks.iter().map(|t| t.pid).collect()
    };

    // Emit entries for each unique PID
    let mut seen_pids = alloc::collections::BTreeSet::new();
    for pid in pids {
        if seen_pids.insert(pid) {
            // Convert PID to string
            let name = alloc::format!("{}", pid);
            let should_continue = callback(DirEntry {
                ino: pid_ino(pid, 0),
                file_type: FileType::Directory,
                name: Vec::from(name.as_bytes()),
            });

            if !should_continue {
                break;
            }
        }
    }

    let _ = proc_ino; // Silence unused warning
    Ok(())
}

/// Emit entries for /proc/<pid>/ directory
fn readdir_emit_pid_entries(
    pid: Pid,
    callback: &mut dyn FnMut(DirEntry) -> bool,
) -> Result<(), KernelError> {
    // Emit "ns" subdirectory
    let should_continue = callback(DirEntry {
        ino: pid_ino(pid, 1),
        file_type: FileType::Directory,
        name: Vec::from(b"ns"),
    });

    if !should_continue {
        return Ok(());
    }

    // Emit "fd" subdirectory
    let should_continue = callback(DirEntry {
        ino: pid_ino(pid, 100),
        file_type: FileType::Directory,
        name: Vec::from(b"fd"),
    });

    if !should_continue {
        return Ok(());
    }

    // Emit "fdinfo" subdirectory
    let should_continue = callback(DirEntry {
        ino: pid_ino(pid, 101),
        file_type: FileType::Directory,
        name: Vec::from(b"fdinfo"),
    });

    if !should_continue {
        return Ok(());
    }

    // Emit "cgroup" file
    let should_continue = callback(DirEntry {
        ino: pid_ino(pid, 102),
        file_type: FileType::Regular,
        name: Vec::from(b"cgroup"),
    });

    if !should_continue {
        return Ok(());
    }

    // Future: add "status", "cmdline", "maps", etc.

    Ok(())
}

/// Emit entries for /proc/<pid>/ns/ directory
fn readdir_emit_ns_entries(
    pid: Pid,
    callback: &mut dyn FnMut(DirEntry) -> bool,
) -> Result<(), KernelError> {
    // Emit all namespace files
    for (idx, ns_type) in NamespaceType::all().iter().enumerate() {
        let should_continue = callback(DirEntry {
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
fn readdir_emit_fd_entries(
    pid: Pid,
    callback: &mut dyn FnMut(DirEntry) -> bool,
) -> Result<(), KernelError> {
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
        let should_continue = callback(DirEntry {
            ino: pid_ino(pid, 200 + fd as u64),
            file_type: FileType::Symlink,
            name: Vec::from(name.as_bytes()),
        });

        if !should_continue {
            break;
        }
    }

    Ok(())
}

/// Emit entries for /proc/<pid>/fdinfo/ directory
fn readdir_emit_fdinfo_entries(
    pid: Pid,
    callback: &mut dyn FnMut(DirEntry) -> bool,
) -> Result<(), KernelError> {
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
        let should_continue = callback(DirEntry {
            ino: pid_ino(pid, 500 + fd as u64),
            file_type: FileType::Regular,
            name: Vec::from(name.as_bytes()),
        });

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

/// Generate /proc/mounts content
///
/// Format: device mountpoint fstype options dump pass
/// Example: none / ramfs rw 0 0
fn gen_mounts() -> Vec<u8> {
    use super::mount::current_mnt_ns;
    use alloc::fmt::Write;

    let mut output = String::new();

    // Get root mount from current task's mount namespace
    if let Some(root_mount) = current_mnt_ns().get_root() {
        // Output root mount
        let fs_name = root_mount.sb.fs_type.name;
        let _ = writeln!(output, "none / {} rw 0 0", fs_name);

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

        let _ = writeln!(output, "none {} {} rw 0 0", mountpoint, fs_name);

        // Recurse into children
        gen_mounts_recursive(child, output);
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
        }
    }

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
