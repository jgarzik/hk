//! BPF file descriptor integration
//!
//! This module provides file descriptor support for BPF objects (maps and programs).
//! BPF objects are exposed as file descriptors to userspace, allowing them to be
//! managed with standard fd operations (close, dup, etc.).

use alloc::string::String;
use alloc::sync::{Arc, Weak};

use super::map::BpfMap;
use super::prog::BpfProg;
use crate::error::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::fs::syscall::{current_fd_table, get_nofile_limit};
use crate::poll::PollTable;

// =============================================================================
// BPF Map File Operations
// =============================================================================

/// File operations for BPF maps
pub struct BpfMapFileOps;

static BPF_MAP_FOPS: BpfMapFileOps = BpfMapFileOps;

impl FileOps for BpfMapFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, KernelError> {
        // BPF map fds don't support read()
        Err(KernelError::InvalidArgument)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        // BPF map fds don't support write()
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, _file: &File, _pt: Option<&mut PollTable>) -> u16 {
        // BPF map fds are always "ready" (operations never block)
        0
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        // Map is dropped when Arc refcount reaches 0
        Ok(())
    }
}

// =============================================================================
// BPF Program File Operations
// =============================================================================

/// A BPF program fd's private data
struct BpfProgFile {
    /// The underlying BPF program
    prog: Arc<BpfProg>,
    /// Program type
    prog_type: u32,
}

/// File operations for BPF programs
pub struct BpfProgFileOps;

static BPF_PROG_FOPS: BpfProgFileOps = BpfProgFileOps;

impl FileOps for BpfProgFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, KernelError> {
        // BPF program fds don't support read()
        Err(KernelError::InvalidArgument)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        // BPF program fds don't support write()
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, _file: &File, _pt: Option<&mut PollTable>) -> u16 {
        0
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        // Program is dropped when Arc refcount reaches 0
        Ok(())
    }
}

// =============================================================================
// File Descriptor Creation
// =============================================================================

/// Create a file descriptor for a BPF map
pub fn create_bpf_map_fd(map: Arc<BpfMap>) -> Result<i32, KernelError> {
    // Create dummy dentry for the BPF map
    let dentry = create_bpf_dentry("bpf-map");

    // Create file with read/write flags
    let file = Arc::new(File::new_anon(dentry, flags::O_RDWR, &BPF_MAP_FOPS, map));

    // Allocate file descriptor using the fd table
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();

    match table.alloc_with_flags(file, 0, get_nofile_limit()) {
        Ok(fd) => Ok(fd),
        Err(e) => Err(KernelError::from_errno(e).unwrap_or(KernelError::Io)),
    }
}

/// Create a file descriptor for a BPF program
pub fn create_bpf_prog_fd(prog: Arc<BpfProg>, prog_type: u32) -> Result<i32, KernelError> {
    let private = Arc::new(BpfProgFile { prog, prog_type });

    // Create dummy dentry for the BPF program
    let dentry = create_bpf_dentry("bpf-prog");

    // Create file with read/write flags
    let file = Arc::new(File::new_anon(
        dentry,
        flags::O_RDWR,
        &BPF_PROG_FOPS,
        private,
    ));

    // Allocate file descriptor using the fd table
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();

    match table.alloc_with_flags(file, 0, get_nofile_limit()) {
        Ok(fd) => Ok(fd),
        Err(e) => Err(KernelError::from_errno(e).unwrap_or(KernelError::Io)),
    }
}

/// Create a dummy dentry for BPF objects
fn create_bpf_dentry(name: &str) -> Arc<Dentry> {
    let mode = InodeMode::regular(0o600);
    let inode = Arc::new(Inode::new(
        0, // ino=0 for anonymous
        mode,
        0,                           // uid (root)
        0,                           // gid (root)
        0,                           // size
        InodeTimespec::from_secs(0), // mtime
        Weak::new(),                 // no superblock
        &NULL_INODE_OPS,
    ));

    Arc::new(Dentry::new_anonymous(String::from(name), Some(inode)))
}

// =============================================================================
// File Descriptor Extraction
// =============================================================================

/// Get a BPF map from a file descriptor
pub fn get_bpf_map_from_fd(fd: i32) -> Result<Arc<BpfMap>, KernelError> {
    let fd_table = current_fd_table();
    let table = fd_table.lock();

    let file = table.get(fd).ok_or(KernelError::BadFd)?;

    file.private_arc::<BpfMap>().ok_or(KernelError::BadFd)
}

/// Get a BPF program from a file descriptor
pub fn get_bpf_prog_from_fd(fd: i32) -> Result<Arc<BpfProg>, KernelError> {
    let fd_table = current_fd_table();
    let table = fd_table.lock();

    let file = table.get(fd).ok_or(KernelError::BadFd)?;

    file.private_ref::<BpfProgFile>()
        .map(|p| Arc::clone(&p.prog))
        .ok_or(KernelError::BadFd)
}

/// Get BPF program info from a file descriptor
pub fn get_bpf_prog_info_from_fd(fd: i32) -> Result<(Arc<BpfProg>, u32), KernelError> {
    let fd_table = current_fd_table();
    let table = fd_table.lock();

    let file = table.get(fd).ok_or(KernelError::BadFd)?;

    file.private_ref::<BpfProgFile>()
        .map(|p| (Arc::clone(&p.prog), p.prog_type))
        .ok_or(KernelError::BadFd)
}
