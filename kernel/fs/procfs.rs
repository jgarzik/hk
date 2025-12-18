//! Procfs - process information pseudo-filesystem
//!
//! Procfs provides a filesystem interface for accessing kernel and
//! process information. Content is generated dynamically on read.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ::core::cmp::min;
use spin::RwLock;

use super::FsError;
use super::dentry::Dentry;
use super::file::{DirEntry, File, FileOps};
use super::inode::{AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::superblock::{FileSystemType, SuperBlock, SuperOps};

/// Get current timestamp for new inodes
/// Returns current wall-clock time from TIMEKEEPER if available, otherwise zero
fn current_time() -> Timespec {
    use crate::time::TIMEKEEPER;
    TIMEKEEPER.current_time()
}

/// Content generator function type
pub type ContentGenerator = fn() -> Vec<u8>;

/// Procfs inode private data
pub enum ProcfsInodeData {
    /// Directory with static children
    Directory {
        children: BTreeMap<String, Arc<Inode>>,
    },
    /// File with content generator
    File { generator: ContentGenerator },
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

    /// Get children map (for directories)
    pub fn children(&self) -> Option<&BTreeMap<String, Arc<Inode>>> {
        match self {
            Self::Directory { children } => Some(children),
            Self::File { .. } => None,
        }
    }

    /// Get mutable children map
    pub fn children_mut(&mut self) -> Option<&mut BTreeMap<String, Arc<Inode>>> {
        match self {
            Self::Directory { children } => Some(children),
            Self::File { .. } => None,
        }
    }

    /// Generate content (for files)
    pub fn generate(&self) -> Option<Vec<u8>> {
        match self {
            Self::File { generator } => Some(generator()),
            Self::Directory { .. } => None,
        }
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
    fn lookup(&self, dir: &Inode, name: &str) -> Result<Arc<Inode>, FsError> {
        let private = dir.get_private().ok_or(FsError::IoError)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(FsError::IoError)?;

        let data = wrapper.0.read();
        match &*data {
            ProcfsInodeData::Directory { children } => {
                children.get(name).cloned().ok_or(FsError::NotFound)
            }
            ProcfsInodeData::File { .. } => Err(FsError::NotADirectory),
        }
    }

    fn readpage(&self, inode: &Inode, page_offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // For procfs, we generate content on demand
        // This is called for page cache integration but procfs typically
        // doesn't use the page cache (content is ephemeral)
        let private = inode.get_private().ok_or(FsError::IoError)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(FsError::IoError)?;

        let data = wrapper.0.read();
        let content = match &*data {
            ProcfsInodeData::File { generator } => generator(),
            ProcfsInodeData::Directory { .. } => return Err(FsError::IsADirectory),
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

/// Static procfs inode ops
pub static PROCFS_INODE_OPS: ProcfsInodeOps = ProcfsInodeOps;

/// Procfs file operations
pub struct ProcfsFileOps;

impl FileOps for ProcfsFileOps {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let private = inode.get_private().ok_or(FsError::IoError)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(FsError::IoError)?;

        let data = wrapper.0.read();
        let content = match &*data {
            ProcfsInodeData::File { generator } => generator(),
            ProcfsInodeData::Directory { .. } => return Err(FsError::IsADirectory),
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

    fn pread(&self, file: &File, buf: &mut [u8], offset: u64) -> Result<usize, FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let private = inode.get_private().ok_or(FsError::IoError)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(FsError::IoError)?;

        let data = wrapper.0.read();
        let content = match &*data {
            ProcfsInodeData::File { generator } => generator(),
            ProcfsInodeData::Directory { .. } => return Err(FsError::IsADirectory),
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
    ) -> Result<(), FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;

        if !inode.mode().is_dir() {
            return Err(FsError::NotADirectory);
        }

        let private = inode.get_private().ok_or(FsError::IoError)?;
        let wrapper = private
            .as_ref()
            .as_any()
            .downcast_ref::<ProcfsInodeWrapper>()
            .ok_or(FsError::IoError)?;

        let data = wrapper.0.read();
        let children = match &*data {
            ProcfsInodeData::Directory { children } => children,
            ProcfsInodeData::File { .. } => return Err(FsError::NotADirectory),
        };

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

        // Emit children
        for (name, child_inode) in children.iter() {
            let file_type = child_inode.mode().file_type().unwrap_or(FileType::Regular);

            let should_continue = callback(DirEntry {
                ino: child_inode.ino,
                file_type,
                name: Vec::from(name.as_bytes()),
            });

            if !should_continue {
                break;
            }
        }

        Ok(())
    }
}

/// Static procfs file ops
pub static PROCFS_FILE_OPS: ProcfsFileOps = ProcfsFileOps;

/// Procfs superblock operations
pub struct ProcfsSuperOps;

impl SuperOps for ProcfsSuperOps {
    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, FsError> {
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
    use super::mount::MOUNT_NS;
    use alloc::fmt::Write;

    let mut output = String::new();

    // Get root mount
    if let Some(root_mount) = MOUNT_NS.get_root() {
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
fn procfs_mount(fs_type: &'static FileSystemType) -> Result<Arc<SuperBlock>, FsError> {
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
