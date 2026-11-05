//! Cgroupfs - cgroup v2 virtual filesystem
//!
//! Cgroupfs provides a filesystem interface for managing cgroups.
//! It is typically mounted at /sys/fs/cgroup.
//!
//! ## Directory Structure
//!
//! - `/sys/fs/cgroup/` - Root cgroup
//! - `/sys/fs/cgroup/<name>/` - Child cgroups (created via mkdir)
//! - `cgroup.procs` - List/migrate tasks (read/write PIDs)
//! - `cgroup.controllers` - Available controllers
//! - `cgroup.subtree_control` - Enabled controllers for children
//! - `cgroup.events` - Event counters
//! - `cgroup.freeze` - Freeze/thaw control (freezer controller)
//! - `pids.max`, `pids.current` - Pids controller files
//! - `cpu.max`, `cpu.weight`, `cpu.stat` - CPU controller files
//! - `memory.max`, `memory.current`, `memory.stat` - Memory controller files
//! - `io.max`, `io.stat` - IO controller files

use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::sync::spin::RwLock;
use core::cmp::min;

use super::KernelError;
use super::dentry::Dentry;
use super::file::{DirContext, DirEntry, File, FileOps};
use super::inode::{AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::superblock::{FileSystemType, StatFs, SuperBlock, SuperOps};

use crate::cgroup::{CGROUP_ROOT, Cgroup, ControllerType, cgroup_init, cgroup_mkdir, cgroup_rmdir};
use crate::task::Pid;

/// Cgroup2 superblock magic
pub const CGROUP2_SUPER_MAGIC: u64 = 0x63677270;

/// Get current timestamp for new inodes
fn current_time() -> Timespec {
    use crate::time::TIMEKEEPER;
    TIMEKEEPER.current_time()
}

/// Control file types (built-in cgroup control files)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupControlFileType {
    /// cgroup.procs - list/migrate tasks
    Procs,
    /// cgroup.controllers - available controllers
    Controllers,
    /// cgroup.subtree_control - enabled controllers for children
    SubtreeControl,
    /// cgroup.events - event notifications
    Events,
    /// cgroup.type - domain vs threaded mode
    Type,
    /// cgroup.stat - statistics
    Stat,
}

impl CgroupControlFileType {
    /// Get filename for this control file type
    pub fn filename(&self) -> &'static str {
        match self {
            Self::Procs => "cgroup.procs",
            Self::Controllers => "cgroup.controllers",
            Self::SubtreeControl => "cgroup.subtree_control",
            Self::Events => "cgroup.events",
            Self::Type => "cgroup.type",
            Self::Stat => "cgroup.stat",
        }
    }

    /// Check if this file is writable
    pub fn is_writable(&self) -> bool {
        matches!(self, Self::Procs | Self::SubtreeControl)
    }

    /// Get file mode
    pub fn mode(&self) -> u16 {
        if self.is_writable() { 0o644 } else { 0o444 }
    }

    /// Parse filename to control file type
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "cgroup.procs" => Some(Self::Procs),
            "cgroup.controllers" => Some(Self::Controllers),
            "cgroup.subtree_control" => Some(Self::SubtreeControl),
            "cgroup.events" => Some(Self::Events),
            "cgroup.type" => Some(Self::Type),
            "cgroup.stat" => Some(Self::Stat),
            _ => None,
        }
    }

    /// List all control file types
    pub fn all() -> &'static [Self] {
        &[
            Self::Procs,
            Self::Controllers,
            Self::SubtreeControl,
            Self::Events,
            Self::Type,
            Self::Stat,
        ]
    }
}

/// Cgroupfs inode private data
#[derive(Clone)]
pub enum CgroupfsInodeData {
    /// Cgroup directory
    Directory { cgroup: Weak<Cgroup> },
    /// Built-in control file
    ControlFile {
        cgroup: Weak<Cgroup>,
        file_type: CgroupControlFileType,
    },
    /// Controller-specific file
    SubsysFile {
        cgroup: Weak<Cgroup>,
        controller: ControllerType,
        file_name: &'static str,
    },
}

impl CgroupfsInodeData {
    /// Get the cgroup for this inode
    pub fn cgroup(&self) -> Option<Arc<Cgroup>> {
        match self {
            Self::Directory { cgroup }
            | Self::ControlFile { cgroup, .. }
            | Self::SubsysFile { cgroup, .. } => cgroup.upgrade(),
        }
    }

    /// Check if this is a directory
    pub fn is_directory(&self) -> bool {
        matches!(self, Self::Directory { .. })
    }
}

impl AsAny for CgroupfsInodeData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for CgroupfsInodeData {}

/// Wrapper for interior mutability
pub struct CgroupfsInodeWrapper(pub RwLock<CgroupfsInodeData>);

impl AsAny for CgroupfsInodeWrapper {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl InodeData for CgroupfsInodeWrapper {}

/// Cgroupfs inode operations
pub struct CgroupfsInodeOps;

impl InodeOps for CgroupfsInodeOps {
    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, KernelError> {
        // cgroup names are text (Linux: any bytes); others name nothing
        let name = core::str::from_utf8(name).map_err(|_| KernelError::NotFound)?;
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<CgroupfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        let data = wrapper.0.read();
        match &*data {
            CgroupfsInodeData::Directory { cgroup } => {
                let cg = cgroup.upgrade().ok_or(KernelError::NotFound)?;

                // First check for child cgroups
                if let Some(child) = cg.lookup_child(name) {
                    return Ok(create_cgroup_dir_inode(dir, &child));
                }

                // Check for built-in control files
                if let Some(file_type) = CgroupControlFileType::from_name(name) {
                    return Ok(create_control_file_inode(dir, &cg, file_type));
                }

                // Check for controller-specific files
                for controller in cg.enabled_controllers() {
                    if let Some(ops) = CGROUP_ROOT.get_controller(controller) {
                        for cf in ops.control_files() {
                            if cf.name == name {
                                return Ok(create_subsys_file_inode(dir, &cg, controller, cf.name));
                            }
                        }
                    }
                }

                Err(KernelError::NotFound)
            }
            _ => Err(KernelError::NotDirectory),
        }
    }

    fn mkdir(&self, dir: &Inode, name: &[u8], _mode: InodeMode) -> Result<Arc<Inode>, KernelError> {
        // hk keeps cgroup names as text (deviation: Linux takes any bytes)
        let name = core::str::from_utf8(name).map_err(|_| KernelError::InvalidArgument)?;
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<CgroupfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        // Out of the inode's spin lock before cgroup_mkdir takes
        // CGROUP_MUTEX
        let parent = match &*wrapper.0.read() {
            CgroupfsInodeData::Directory { cgroup } => cgroup.clone(),
            _ => return Err(KernelError::NotDirectory),
        };
        let parent_cg = parent.upgrade().ok_or(KernelError::NoDevice)?;
        let new_cg = cgroup_mkdir(&parent_cg, name)?;
        Ok(create_cgroup_dir_inode(dir, &new_cg))
    }

    fn rmdir(&self, dir: &Inode, name: &[u8]) -> Result<(), KernelError> {
        let name = core::str::from_utf8(name).map_err(|_| KernelError::NotFound)?;
        let private = dir.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<CgroupfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        // Out of the inode's spin lock before cgroup_rmdir takes
        // CGROUP_MUTEX
        let parent = match &*wrapper.0.read() {
            CgroupfsInodeData::Directory { cgroup } => cgroup.clone(),
            _ => return Err(KernelError::NotDirectory),
        };
        let parent_cg = parent.upgrade().ok_or(KernelError::NotFound)?;
        cgroup_rmdir(&parent_cg, name)
    }
}

/// Static cgroupfs inode ops
pub static CGROUPFS_INODE_OPS: CgroupfsInodeOps = CgroupfsInodeOps;

// ============================================================================
// Inode Creation Helpers
// ============================================================================

/// Create a cgroup directory inode
fn create_cgroup_dir_inode(parent: &Inode, cgroup: &Arc<Cgroup>) -> Arc<Inode> {
    let sb = parent.superblock().expect("superblock dropped");
    let inode = Arc::new(Inode::new(
        cgroup.ino,
        InodeMode::directory(0o755),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &CGROUPFS_INODE_OPS,
    ));
    inode.set_private(Arc::new(CgroupfsInodeWrapper(RwLock::new(
        CgroupfsInodeData::Directory {
            cgroup: Arc::downgrade(cgroup),
        },
    ))));
    inode
}

/// Create a control file inode
fn create_control_file_inode(
    parent: &Inode,
    cgroup: &Arc<Cgroup>,
    file_type: CgroupControlFileType,
) -> Arc<Inode> {
    let sb = parent.superblock().expect("superblock dropped");
    let mode = if file_type.is_writable() {
        0o644
    } else {
        0o444
    };
    let inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        InodeMode::regular(mode),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &CGROUPFS_INODE_OPS,
    ));
    inode.set_private(Arc::new(CgroupfsInodeWrapper(RwLock::new(
        CgroupfsInodeData::ControlFile {
            cgroup: Arc::downgrade(cgroup),
            file_type,
        },
    ))));
    inode
}

/// Create a controller-specific file inode
fn create_subsys_file_inode(
    parent: &Inode,
    cgroup: &Arc<Cgroup>,
    controller: ControllerType,
    file_name: &'static str,
) -> Arc<Inode> {
    let sb = parent.superblock().expect("superblock dropped");

    // Determine mode from controller's control file definition
    let mode = if let Some(ops) = CGROUP_ROOT.get_controller(controller) {
        ops.control_files()
            .iter()
            .find(|cf| cf.name == file_name)
            .map(|cf| cf.mode)
            .unwrap_or(0o444)
    } else {
        0o444
    };

    let inode = Arc::new(Inode::new(
        sb.alloc_ino(),
        InodeMode::regular(mode),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &CGROUPFS_INODE_OPS,
    ));
    inode.set_private(Arc::new(CgroupfsInodeWrapper(RwLock::new(
        CgroupfsInodeData::SubsysFile {
            cgroup: Arc::downgrade(cgroup),
            controller,
            file_name,
        },
    ))));
    inode
}

// ============================================================================
// Content Generation
// ============================================================================

/// Generate content for a built-in control file
fn generate_control_file_content(
    cgroup: &Arc<Cgroup>,
    file_type: CgroupControlFileType,
) -> Result<Vec<u8>, KernelError> {
    match file_type {
        CgroupControlFileType::Procs => {
            // Each member process once, by its tgid (Linux cgroup.procs;
            // cgroup.threads would list the threads)
            let mut tgids: Vec<Pid> = {
                let table = crate::task::percpu::TASKLIST.read();
                cgroup
                    .tasks()
                    .into_iter()
                    .filter_map(|tid| table.get(tid as crate::task::Tid).map(|t| t.task.pid))
                    .collect()
            };
            tgids.sort_unstable();
            tgids.dedup();
            let mut content = String::new();
            for pid in tgids {
                content.push_str(&format!("{}\n", pid));
            }
            Ok(content.into_bytes())
        }
        CgroupControlFileType::Controllers => {
            // List available controllers
            let mut content = String::new();
            let controllers = CGROUP_ROOT.registered_controllers();
            for (i, ctrl) in controllers.iter().enumerate() {
                if i > 0 {
                    content.push(' ');
                }
                content.push_str(ctrl.name());
            }
            content.push('\n');
            Ok(content.into_bytes())
        }
        CgroupControlFileType::SubtreeControl => {
            // List enabled controllers for children
            let mut content = String::new();
            let mut first = true;
            for ctrl in ControllerType::all() {
                if cgroup.subtree_control_enabled(*ctrl) {
                    if !first {
                        content.push(' ');
                    }
                    content.push_str(ctrl.name());
                    first = false;
                }
            }
            content.push('\n');
            Ok(content.into_bytes())
        }
        CgroupControlFileType::Events => {
            // Show events (populated, frozen)
            let populated = if cgroup.nr_tasks() > 0 { 1 } else { 0 };
            let frozen = if cgroup.is_frozen() { 1 } else { 0 };
            let content = format!("populated {}\nfrozen {}\n", populated, frozen);
            Ok(content.into_bytes())
        }
        CgroupControlFileType::Type => {
            // cgroup type (domain or threaded)
            let content = String::from("domain\n");
            Ok(content.into_bytes())
        }
        CgroupControlFileType::Stat => {
            // Basic statistics
            let nr_descendants = cgroup.children().len();
            let nr_dying_descendants = 0u64; // We don't track dying cgroups
            let content = format!(
                "nr_descendants {}\nnr_dying_descendants {}\n",
                nr_descendants, nr_dying_descendants
            );
            Ok(content.into_bytes())
        }
    }
}

/// Handle write to a built-in control file
fn handle_control_file_write(
    cgroup: &Arc<Cgroup>,
    file_type: CgroupControlFileType,
    data: &[u8],
) -> Result<(), KernelError> {
    match file_type {
        CgroupControlFileType::Procs => {
            // Migrate a task to this cgroup
            let s = core::str::from_utf8(data).map_err(|_| KernelError::InvalidArgument)?;
            let pid: Pid = s.trim().parse().map_err(|_| KernelError::InvalidArgument)?;
            // The whole thread group moves, against forks (Linux
            // cgroup_procs_write: cgroup_attach_lock, threadgroup)
            let _tg = crate::cgroup::CGROUP_THREADGROUP_RWSEM.write();
            crate::cgroup::migrate_thread_group(cgroup, pid)
        }
        CgroupControlFileType::SubtreeControl => {
            // Enable/disable controllers for children
            // Format: "+controller -controller"
            let s = core::str::from_utf8(data).map_err(|_| KernelError::InvalidArgument)?;
            for token in s.split_whitespace() {
                if let Some(name) = token.strip_prefix('+')
                    && let Some(ctrl) = ControllerType::from_name(name)
                {
                    cgroup.enable_subtree_control(ctrl);
                } else if let Some(name) = token.strip_prefix('-')
                    && let Some(ctrl) = ControllerType::from_name(name)
                {
                    cgroup.disable_subtree_control(ctrl);
                }
            }
            Ok(())
        }
        _ => Err(KernelError::OperationNotSupported),
    }
}

/// Generate content for a controller-specific file
fn generate_subsys_file_content(
    cgroup: &Arc<Cgroup>,
    controller: ControllerType,
    file_name: &str,
) -> Result<Vec<u8>, KernelError> {
    let css = cgroup.css(controller).ok_or(KernelError::NotFound)?;

    if let Some(ops) = CGROUP_ROOT.get_controller(controller) {
        for cf in ops.control_files() {
            if cf.name == file_name
                && let Some(read_fn) = cf.read
            {
                return read_fn(&css);
            }
        }
    }

    Err(KernelError::OperationNotSupported)
}

/// Handle write to a controller-specific file
fn handle_subsys_file_write(
    cgroup: &Arc<Cgroup>,
    controller: ControllerType,
    file_name: &str,
    data: &[u8],
) -> Result<(), KernelError> {
    let css = cgroup.css(controller).ok_or(KernelError::NotFound)?;

    if let Some(ops) = CGROUP_ROOT.get_controller(controller) {
        for cf in ops.control_files() {
            if cf.name == file_name
                && let Some(write_fn) = cf.write
            {
                return write_fn(&css, data);
            }
        }
    }

    Err(KernelError::OperationNotSupported)
}

// ============================================================================
// File Operations
// ============================================================================

/// Cgroupfs file operations
pub struct CgroupfsFileOps;

impl FileOps for CgroupfsFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<CgroupfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        let data = wrapper.0.read();
        let content = match &*data {
            CgroupfsInodeData::ControlFile { cgroup, file_type } => {
                let cg = cgroup.upgrade().ok_or(KernelError::NotFound)?;
                generate_control_file_content(&cg, *file_type)?
            }
            CgroupfsInodeData::SubsysFile {
                cgroup,
                controller,
                file_name,
            } => {
                let cg = cgroup.upgrade().ok_or(KernelError::NotFound)?;
                generate_subsys_file_content(&cg, *controller, file_name)?
            }
            CgroupfsInodeData::Directory { .. } => return Err(KernelError::IsDirectory),
        };

        let pos = file.get_pos() as usize;
        if pos >= content.len() {
            return Ok(0);
        }

        let to_read = min(buf.len(), content.len() - pos);
        buf[..to_read].copy_from_slice(&content[pos..pos + to_read]);
        file.advance_pos(to_read as u64);

        Ok(to_read)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<CgroupfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        // Writes run under CGROUP_MUTEX (Linux cgroup_kn_lock_live for
        // cgroup.procs, subtree_control and freeze), taken before the
        // inode's spin lock; a removed cgroup's files are ENODEV (Linux
        // kernfs_fop_write: no active reference to a removed node)
        let _g = crate::cgroup::CGROUP_MUTEX.lock();
        // A copy, so no spin lock is held while the write sleeps
        // (cgroup.procs takes the threadgroup rwsem)
        let data = wrapper.0.read().clone();
        let live = |c: &alloc::sync::Weak<Cgroup>| {
            c.upgrade()
                .filter(|c| !c.is_dead())
                .ok_or(KernelError::NoDevice)
        };
        match &data {
            CgroupfsInodeData::ControlFile { cgroup, file_type } => {
                let cg = live(cgroup)?;
                handle_control_file_write(&cg, *file_type, buf)?;
                Ok(buf.len())
            }
            CgroupfsInodeData::SubsysFile {
                cgroup,
                controller,
                file_name,
            } => {
                let cg = live(cgroup)?;
                handle_subsys_file_write(&cg, *controller, file_name, buf)?;
                Ok(buf.len())
            }
            CgroupfsInodeData::Directory { .. } => Err(KernelError::IsDirectory),
        }
    }

    fn readdir(&self, file: &File, ctx: &mut DirContext) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let private = inode.get_private().ok_or(KernelError::Io)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<CgroupfsInodeWrapper>()
            .ok_or(KernelError::Io)?;

        let data = wrapper.0.read();
        match &*data {
            CgroupfsInodeData::Directory { cgroup } => {
                let cg = cgroup.upgrade().ok_or(KernelError::NotFound)?;

                // Emit "."
                if !ctx.emit(DirEntry {
                    ino: cg.ino,
                    file_type: FileType::Directory,
                    name: Vec::from(b".".as_slice()),
                }) {
                    return Ok(());
                }

                // Emit ".."
                let parent_ino = cg.parent().map(|p| p.ino).unwrap_or(cg.ino);
                if !ctx.emit(DirEntry {
                    ino: parent_ino,
                    file_type: FileType::Directory,
                    name: Vec::from(b"..".as_slice()),
                }) {
                    return Ok(());
                }

                // Emit child cgroups
                for child in cg.children() {
                    if !ctx.emit(DirEntry {
                        ino: child.ino,
                        file_type: FileType::Directory,
                        name: Vec::from(child.name.as_bytes()),
                    }) {
                        return Ok(());
                    }
                }

                // Emit control files
                for file_type in CgroupControlFileType::all() {
                    if !ctx.emit(DirEntry {
                        ino: cg.ino + 1000 + *file_type as u64,
                        file_type: FileType::Regular,
                        name: Vec::from(file_type.filename().as_bytes()),
                    }) {
                        return Ok(());
                    }
                }

                // Emit controller-specific files
                for controller in cg.enabled_controllers() {
                    if let Some(ops) = CGROUP_ROOT.get_controller(controller) {
                        for cf in ops.control_files() {
                            if !ctx.emit(DirEntry {
                                ino: cg.ino + 2000 + controller as u64 * 100,
                                file_type: FileType::Regular,
                                name: Vec::from(cf.name.as_bytes()),
                            }) {
                                return Ok(());
                            }
                        }
                    }
                }

                Ok(())
            }
            _ => Err(KernelError::NotDirectory),
        }
    }
}

/// Static cgroupfs file ops
pub static CGROUPFS_FILE_OPS: CgroupfsFileOps = CgroupfsFileOps;

// ============================================================================
// Superblock Operations
// ============================================================================

/// Cgroupfs super ops
pub struct CgroupfsSuperOps;

impl SuperOps for CgroupfsSuperOps {
    fn statfs(&self) -> StatFs {
        StatFs {
            f_type: CGROUP2_SUPER_MAGIC,
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
            0,
            0,
            0,
            current_time(),
            Arc::downgrade(sb),
            i_op,
        ));
        inode.set_private(Arc::new(CgroupfsInodeWrapper(RwLock::new(
            CgroupfsInodeData::Directory {
                cgroup: Weak::new(),
            },
        ))));
        Ok(inode)
    }
}

/// Static cgroupfs super ops
pub static CGROUPFS_SUPER_OPS: CgroupfsSuperOps = CgroupfsSuperOps;

// ============================================================================
// Mount Function
// ============================================================================

/// Mount cgroupfs
fn cgroupfs_mount(
    fs_type: &'static FileSystemType,
    _opts: &[u8],
) -> Result<Arc<SuperBlock>, KernelError> {
    // Initialize cgroup subsystem if not done
    cgroup_init();

    // Create superblock
    let sb = SuperBlock::new(fs_type, &CGROUPFS_SUPER_OPS, 0);

    // Get root cgroup
    let root_cg = CGROUP_ROOT
        .root_cgroup()
        .ok_or(KernelError::InvalidArgument)?;

    // Create root inode
    let root_inode = Arc::new(Inode::new(
        root_cg.ino,
        InodeMode::directory(0o755),
        0,
        0,
        0,
        current_time(),
        Arc::downgrade(&sb),
        &CGROUPFS_INODE_OPS,
    ));
    root_inode.set_private(Arc::new(CgroupfsInodeWrapper(RwLock::new(
        CgroupfsInodeData::Directory {
            cgroup: Arc::downgrade(&root_cg),
        },
    ))));

    // Create root dentry
    let root_dentry = Arc::new(Dentry::new_root(root_inode, Arc::downgrade(&sb)));

    // Set root in superblock
    sb.set_root(root_dentry);

    // Mark as mounted
    CGROUP_ROOT.mount();

    Ok(sb)
}

/// Cgroupfs filesystem type
pub static CGROUPFS_TYPE: FileSystemType = FileSystemType {
    name: "cgroup2",
    fs_flags: super::superblock::fs_flags::FS_PSEUDO,
    mount: cgroupfs_mount,
    mount_dev: None,
    file_ops: &CGROUPFS_FILE_OPS,
};
