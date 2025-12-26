//! File - open file description
//!
//! A File represents an open file handle. Multiple file descriptors
//! can point to the same file (e.g., after dup()).
//!
//! ## Generic Page-Cache File Operations
//!
//! This module provides `generic_file_read` and `generic_file_write` which
//! implement page-cache-backed I/O. Filesystems can use these directly or
//! as building blocks for their FileOps implementations.

use alloc::sync::Arc;
use alloc::vec::Vec;

use ::core::cmp::min;
use ::core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::FsError;
use super::dentry::Dentry;
use super::inode::{FileType, Inode, InodeId};
use super::mount::{Mount, current_mnt_ns};
use crate::poll::{
    DEFAULT_POLLMASK, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable,
};

use crate::frame_alloc::FrameAllocRef;
use crate::mm::page_cache::{AddressSpaceOps, FileId, PAGE_SIZE};
use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

/// Open file flags (Linux O_* flags)
pub mod flags {
    /// Open for reading only
    pub const O_RDONLY: u32 = 0;
    /// Open for writing only
    pub const O_WRONLY: u32 = 1;
    /// Open for reading and writing
    pub const O_RDWR: u32 = 2;
    /// Access mode mask
    pub const O_ACCMODE: u32 = 3;

    /// Create file if it doesn't exist
    pub const O_CREAT: u32 = 0o100;
    /// Fail if file exists (with O_CREAT)
    pub const O_EXCL: u32 = 0o200;
    /// Truncate file to zero length
    pub const O_TRUNC: u32 = 0o1000;
    /// Append mode
    pub const O_APPEND: u32 = 0o2000;
    /// Non-blocking mode
    pub const O_NONBLOCK: u32 = 0o4000;
    /// Must be a directory
    pub const O_DIRECTORY: u32 = 0o200000;
    /// Don't follow symlinks
    pub const O_NOFOLLOW: u32 = 0o400000;
    /// Close on exec
    pub const O_CLOEXEC: u32 = 0o2000000;
}

/// Seek whence values (for lseek)
pub mod seek {
    /// Seek from beginning of file
    pub const SEEK_SET: i32 = 0;
    /// Seek from current position
    pub const SEEK_CUR: i32 = 1;
    /// Seek from end of file
    pub const SEEK_END: i32 = 2;
}

/// Flags for read/write operations (preadv2/pwritev2 RWF_* flags)
#[derive(Debug, Clone, Copy, Default)]
pub struct RwFlags {
    /// RWF_NOWAIT - return EAGAIN if operation would block
    pub nowait: bool,
}

impl RwFlags {
    /// Create empty flags (no special behavior)
    pub const fn empty() -> Self {
        Self { nowait: false }
    }

    /// Create flags with NOWAIT set
    pub const fn with_nowait() -> Self {
        Self { nowait: true }
    }
}

/// Directory entry for getdents
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Inode number
    pub ino: InodeId,
    /// File type
    pub file_type: FileType,
    /// Entry name
    pub name: Vec<u8>,
}

/// File operations trait - filesystem-specific behavior for open files
pub trait FileOps: Send + Sync {
    /// Returns self as Any for downcasting to concrete types
    fn as_any(&self) -> &dyn core::any::Any;

    /// Read from file at current position
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, FsError>;

    /// Write to file at current position
    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, FsError> {
        let _ = (file, buf);
        Err(FsError::NotSupported)
    }

    /// Positioned read - read from file at given offset without modifying file position
    ///
    /// Unlike read(), this does NOT advance the file position.
    /// Returns NotSupported for files that don't support positioned I/O (pipes, sockets).
    fn pread(&self, file: &File, buf: &mut [u8], offset: u64) -> Result<usize, FsError> {
        let _ = (file, buf, offset);
        Err(FsError::NotSupported)
    }

    /// Positioned write - write to file at given offset without modifying file position
    ///
    /// Unlike write(), this does NOT advance the file position.
    /// Returns NotSupported for files that don't support positioned I/O (pipes, sockets).
    fn pwrite(&self, file: &File, buf: &[u8], offset: u64) -> Result<usize, FsError> {
        let _ = (file, buf, offset);
        Err(FsError::NotSupported)
    }

    /// Seek to a position
    fn llseek(&self, file: &File, offset: i64, whence: i32) -> Result<u64, FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let size = inode.get_size();

        let new_pos = match whence {
            seek::SEEK_SET => {
                if offset < 0 {
                    return Err(FsError::InvalidArgument);
                }
                offset as u64
            }
            seek::SEEK_CUR => {
                let cur = file.get_pos();
                if offset < 0 {
                    cur.checked_sub((-offset) as u64)
                        .ok_or(FsError::InvalidArgument)?
                } else {
                    cur.saturating_add(offset as u64)
                }
            }
            seek::SEEK_END => {
                if offset < 0 {
                    size.checked_sub((-offset) as u64)
                        .ok_or(FsError::InvalidArgument)?
                } else {
                    size.saturating_add(offset as u64)
                }
            }
            _ => return Err(FsError::InvalidArgument),
        };

        file.set_pos(new_pos);
        Ok(new_pos)
    }

    /// Read directory entries
    fn readdir(
        &self,
        file: &File,
        callback: &mut dyn FnMut(DirEntry) -> bool,
    ) -> Result<(), FsError> {
        let _ = (file, callback);
        Err(FsError::NotADirectory)
    }

    /// Sync file data to backing store
    fn fsync(&self, _file: &File) -> Result<(), FsError> {
        Ok(())
    }

    /// Release file (called when last reference is dropped)
    fn release(&self, _file: &File) -> Result<(), FsError> {
        Ok(())
    }

    /// Poll for events (like f_op->poll in Linux)
    ///
    /// Returns mask of ready events (POLLIN, POLLOUT, etc.).
    /// Implementation should:
    /// 1. Call pt.poll_wait() to register on wait queues
    /// 2. Return current ready events mask
    ///
    /// Default: regular files are always readable and writable.
    fn poll(&self, _file: &File, _pt: Option<&mut PollTable>) -> u16 {
        // Default for regular files - always ready
        DEFAULT_POLLMASK
    }

    /// Read with RWF flags (for preadv2/pwritev2)
    ///
    /// Supports RWF_NOWAIT: if set and operation would block, return WouldBlock.
    /// Default implementation rejects NOWAIT (returns NotSupported).
    fn read_with_flags(
        &self,
        file: &File,
        buf: &mut [u8],
        flags: RwFlags,
    ) -> Result<usize, FsError> {
        if flags.nowait {
            return Err(FsError::NotSupported);
        }
        self.read(file, buf)
    }

    /// Positioned read with RWF flags
    ///
    /// Supports RWF_NOWAIT: if set and operation would block, return WouldBlock.
    /// Default implementation rejects NOWAIT (returns NotSupported).
    fn pread_with_flags(
        &self,
        file: &File,
        buf: &mut [u8],
        offset: u64,
        flags: RwFlags,
    ) -> Result<usize, FsError> {
        if flags.nowait {
            return Err(FsError::NotSupported);
        }
        self.pread(file, buf, offset)
    }

    /// Write with RWF flags (for preadv2/pwritev2)
    ///
    /// Supports RWF_NOWAIT: if set and operation would block, return WouldBlock.
    /// Default implementation rejects NOWAIT (returns NotSupported).
    fn write_with_flags(&self, file: &File, buf: &[u8], flags: RwFlags) -> Result<usize, FsError> {
        if flags.nowait {
            return Err(FsError::NotSupported);
        }
        self.write(file, buf)
    }

    /// Positioned write with RWF flags
    ///
    /// Supports RWF_NOWAIT: if set and operation would block, return WouldBlock.
    /// Default implementation rejects NOWAIT (returns NotSupported).
    fn pwrite_with_flags(
        &self,
        file: &File,
        buf: &[u8],
        offset: u64,
        flags: RwFlags,
    ) -> Result<usize, FsError> {
        if flags.nowait {
            return Err(FsError::NotSupported);
        }
        self.pwrite(file, buf, offset)
    }
}

/// Open file description
///
/// This struct mirrors Linux's `struct file`. It holds references to:
/// - The dentry (f_path.dentry in Linux)
/// - The mount (f_path.mnt in Linux) - increments mnt_count
/// - File position and operations
pub struct File {
    /// Dentry this file was opened from
    pub dentry: Arc<Dentry>,

    /// Mount this file belongs to (like Linux f_path.mnt)
    /// Holds a reference via mntget() - decremented on drop via mntput()
    mnt: Option<Arc<Mount>>,

    /// Current file position
    pos: AtomicU64,

    /// Open flags (protected by f_lock, like Linux)
    f_lock: Mutex<u32>,

    /// File operations
    pub f_op: &'static dyn FileOps,
}

impl File {
    /// Create a new file
    ///
    /// Finds the mount for the dentry and increments its reference count
    /// via mntget(). This ensures the mount cannot be unmounted while
    /// this file is open.
    pub fn new(dentry: Arc<Dentry>, flags: u32, f_op: &'static dyn FileOps) -> Self {
        // Find the mount for this dentry and call mntget
        let mnt = current_mnt_ns().find_mount_for_dentry(&dentry);
        if let Some(ref m) = mnt {
            m.mntget();
        }

        Self {
            dentry,
            mnt,
            pos: AtomicU64::new(0),
            f_lock: Mutex::new(flags),
            f_op,
        }
    }

    /// Get the inode for this file
    pub fn get_inode(&self) -> Option<Arc<Inode>> {
        self.dentry.get_inode()
    }

    /// Get current file position
    pub fn get_pos(&self) -> u64 {
        self.pos.load(Ordering::Relaxed)
    }

    /// Set file position
    pub fn set_pos(&self, pos: u64) {
        self.pos.store(pos, Ordering::Relaxed);
    }

    /// Advance file position by n bytes
    pub fn advance_pos(&self, n: u64) -> u64 {
        self.pos.fetch_add(n, Ordering::Relaxed)
    }

    /// Get current flags
    pub fn get_flags(&self) -> u32 {
        *self.f_lock.lock()
    }

    /// Set status flags (for F_SETFL)
    ///
    /// Only O_APPEND, O_NONBLOCK can be modified. Access mode is preserved.
    pub fn set_status_flags(&self, new_status: u32) {
        const SETTABLE_FLAGS: u32 = flags::O_APPEND | flags::O_NONBLOCK;
        let mut guard = self.f_lock.lock();
        *guard = (*guard & !SETTABLE_FLAGS) | (new_status & SETTABLE_FLAGS);
    }

    /// Check if file is readable
    pub fn is_readable(&self) -> bool {
        let mode = self.get_flags() & flags::O_ACCMODE;
        mode == flags::O_RDONLY || mode == flags::O_RDWR
    }

    /// Check if file is writable
    pub fn is_writable(&self) -> bool {
        let mode = self.get_flags() & flags::O_ACCMODE;
        mode == flags::O_WRONLY || mode == flags::O_RDWR
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        self.get_inode().map(|i| i.mode().is_dir()).unwrap_or(false)
    }

    /// Get the file operations
    pub fn ops(&self) -> &'static dyn FileOps {
        self.f_op
    }

    /// Read from file
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, FsError> {
        if !self.is_readable() {
            return Err(FsError::PermissionDenied);
        }
        self.f_op.read(self, buf)
    }

    /// Write to file
    pub fn write(&self, buf: &[u8]) -> Result<usize, FsError> {
        if !self.is_writable() {
            return Err(FsError::PermissionDenied);
        }
        self.f_op.write(self, buf)
    }

    /// Positioned read - read at given offset without modifying file position
    pub fn pread(&self, buf: &mut [u8], offset: u64) -> Result<usize, FsError> {
        if !self.is_readable() {
            return Err(FsError::PermissionDenied);
        }
        self.f_op.pread(self, buf, offset)
    }

    /// Positioned write - write at given offset without modifying file position
    pub fn pwrite(&self, buf: &[u8], offset: u64) -> Result<usize, FsError> {
        if !self.is_writable() {
            return Err(FsError::PermissionDenied);
        }
        self.f_op.pwrite(self, buf, offset)
    }

    /// Read with RWF flags (for preadv2/pwritev2 with RWF_NOWAIT support)
    pub fn read_with_flags(&self, buf: &mut [u8], flags: RwFlags) -> Result<usize, FsError> {
        if !self.is_readable() {
            return Err(FsError::PermissionDenied);
        }
        self.f_op.read_with_flags(self, buf, flags)
    }

    /// Write with RWF flags
    pub fn write_with_flags(&self, buf: &[u8], flags: RwFlags) -> Result<usize, FsError> {
        if !self.is_writable() {
            return Err(FsError::PermissionDenied);
        }
        self.f_op.write_with_flags(self, buf, flags)
    }

    /// Positioned read with RWF flags
    pub fn pread_with_flags(
        &self,
        buf: &mut [u8],
        offset: u64,
        flags: RwFlags,
    ) -> Result<usize, FsError> {
        if !self.is_readable() {
            return Err(FsError::PermissionDenied);
        }
        self.f_op.pread_with_flags(self, buf, offset, flags)
    }

    /// Positioned write with RWF flags
    pub fn pwrite_with_flags(
        &self,
        buf: &[u8],
        offset: u64,
        flags: RwFlags,
    ) -> Result<usize, FsError> {
        if !self.is_writable() {
            return Err(FsError::PermissionDenied);
        }
        self.f_op.pwrite_with_flags(self, buf, offset, flags)
    }

    /// Seek
    pub fn lseek(&self, offset: i64, whence: i32) -> Result<u64, FsError> {
        self.f_op.llseek(self, offset, whence)
    }

    /// Read directory entries
    pub fn readdir(&self, callback: &mut dyn FnMut(DirEntry) -> bool) -> Result<(), FsError> {
        if !self.is_dir() {
            return Err(FsError::NotADirectory);
        }
        self.f_op.readdir(self, callback)
    }

    /// Poll for events
    ///
    /// Returns mask of ready events (POLLIN, POLLOUT, etc.)
    pub fn poll(&self, pt: Option<&mut PollTable>) -> u16 {
        self.f_op.poll(self, pt)
    }
}

// File is Send + Sync because all interior mutability is through atomic
unsafe impl Send for File {}
unsafe impl Sync for File {}

impl Drop for File {
    fn drop(&mut self) {
        // Decrement mount reference count via mntput
        // This mirrors Linux's fput() -> mntput()
        if let Some(ref mnt) = self.mnt {
            mnt.mntput();
        }
    }
}

/// Null file ops - returns errors for all operations
pub struct NullFileOps;

impl FileOps for NullFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, FsError> {
        Err(FsError::NotSupported)
    }

    fn poll(&self, _file: &File, _pt: Option<&mut PollTable>) -> u16 {
        POLLERR
    }
}

/// Static null file ops
pub static NULL_FILE_OPS: NullFileOps = NullFileOps;

// ============================================================================
// Character Device File Operations
// ============================================================================

use crate::chardev::{DeviceError, get_chardev};

/// Character device file operations.
///
/// Routes VFS file operations to the CharDevice trait via the chardev registry.
/// Device is looked up by major/minor stored in the inode's rdev field.
pub struct CharDevFileOps;

impl CharDevFileOps {
    /// Convert DeviceError to FsError
    fn to_fs_error(e: DeviceError) -> FsError {
        match e {
            DeviceError::NotReady => FsError::IoError,
            DeviceError::WouldBlock => FsError::WouldBlock,
            DeviceError::NotSupported => FsError::NotSupported,
            DeviceError::IoError => FsError::IoError,
            DeviceError::InvalidArg => FsError::InvalidArgument,
            DeviceError::NotFound => FsError::NotFound,
            DeviceError::NotTty => FsError::NotTty,
        }
    }
}

impl FileOps for CharDevFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let rdev = inode.rdev;

        let device = get_chardev(rdev).ok_or(FsError::NotFound)?;
        device.read(buf).map_err(Self::to_fs_error)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let rdev = inode.rdev;

        let device = get_chardev(rdev).ok_or(FsError::NotFound)?;
        device.write(buf).map_err(Self::to_fs_error)
    }

    fn llseek(&self, _file: &File, _offset: i64, _whence: i32) -> Result<u64, FsError> {
        // Most character devices don't support seeking
        Err(FsError::InvalidArgument)
    }

    fn poll(&self, file: &File, _pt: Option<&mut PollTable>) -> u16 {
        let inode = match file.get_inode() {
            Some(i) => i,
            None => return POLLERR,
        };

        let device = match get_chardev(inode.rdev) {
            Some(d) => d,
            None => return POLLHUP | POLLERR,
        };

        let mut mask = 0u16;

        // Check if readable
        if device.poll_read() {
            mask |= POLLIN | POLLRDNORM;
        }

        // Check if writable
        if device.poll_write() {
            mask |= POLLOUT | POLLWRNORM;
        }

        mask
    }
}

/// Static character device file ops
pub static CHAR_FILE_OPS: CharDevFileOps = CharDevFileOps;

// ============================================================================
// Generic Page-Cache File Operations
// ============================================================================

/// Generic page-cache-backed file read.
///
/// Reads data from a file using the page cache. Pages are populated via
/// `a_ops.readpage()` when first accessed (cache miss).
///
/// ## Locking Context
///
/// - Acquires PAGE_CACHE lock briefly per page (for find_or_create)
/// - Releases PAGE_CACHE lock before calling a_ops.readpage
/// - Acquires per-page lock during readpage if populating
///
/// ## Arguments
///
/// * `file` - The file being read
/// * `buf` - Buffer to read into
/// * `file_id` - Page cache identifier for this file
/// * `file_size` - Total file size in bytes
/// * `can_writeback` - Whether dirty pages can be written back
/// * `unevictable` - Whether pages are completely unevictable (ramfs)
/// * `a_ops` - Address space operations for page I/O
///
/// ## Returns
///
/// Number of bytes read, or error
#[allow(clippy::too_many_arguments)]
pub fn generic_file_read(
    file: &File,
    buf: &mut [u8],
    file_id: FileId,
    file_size: u64,
    can_writeback: bool,
    unevictable: bool,
    a_ops: &'static dyn AddressSpaceOps,
) -> Result<usize, FsError> {
    let pos = file.get_pos();

    // EOF check
    if pos >= file_size {
        return Ok(0);
    }

    let available = (file_size - pos) as usize;
    let to_read = min(buf.len(), available);

    if to_read == 0 {
        return Ok(0);
    }

    let mut bytes_read = 0;

    while bytes_read < to_read {
        let current_pos = pos + bytes_read as u64;
        let page_offset = current_pos / PAGE_SIZE as u64;
        let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
        let chunk_size = min(PAGE_SIZE - offset_in_page, to_read - bytes_read);

        // Get or create the page (PAGE_CACHE lock acquired/released)
        let (page, is_new) = {
            let mut cache = PAGE_CACHE.lock();
            let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

            cache
                .find_or_create_page(
                    file_id,
                    page_offset,
                    file_size,
                    &mut frame_alloc,
                    can_writeback,
                    unevictable,
                    a_ops,
                )
                .map_err(|_| FsError::IoError)?
        };
        // PAGE_CACHE lock released here

        // If this is a new page, populate it via readpage
        if is_new {
            // Lock the page for I/O
            page.lock();

            // Read page content from backing store
            let mut page_buf = [0u8; PAGE_SIZE];
            let read_result = a_ops.readpage(file_id, page_offset, &mut page_buf);

            match read_result {
                Ok(_) => {
                    // Copy data to the frame
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            page_buf.as_ptr(),
                            page.frame as *mut u8,
                            PAGE_SIZE,
                        );
                    }
                }
                Err(_) => {
                    page.unlock();
                    return Err(FsError::IoError);
                }
            }

            page.unlock();
        }

        // Copy data from page to user buffer (page is refcounted, safe to access)
        unsafe {
            let src = (page.frame as *const u8).add(offset_in_page);
            core::ptr::copy_nonoverlapping(src, buf[bytes_read..].as_mut_ptr(), chunk_size);
        }

        // Release our reference to the page
        let cache = PAGE_CACHE.lock();
        cache.put_page(&page);

        bytes_read += chunk_size;
    }

    // Advance file position
    file.advance_pos(bytes_read as u64);

    Ok(bytes_read)
}

/// Generic page-cache-backed file write.
///
/// Writes data to a file using the page cache. Pages are allocated on
/// first write and marked dirty.
///
/// ## Locking Context
///
/// - Acquires PAGE_CACHE lock briefly per page (for find_or_create)
/// - Releases PAGE_CACHE lock before I/O
/// - Does not call a_ops during write (writeback happens later)
///
/// ## Arguments
///
/// * `file` - The file being written
/// * `buf` - Data to write
/// * `file_id` - Page cache identifier for this file
/// * `file_size` - Current file size in bytes (may grow)
/// * `can_writeback` - Whether dirty pages can be written back
/// * `unevictable` - Whether pages are completely unevictable (ramfs)
/// * `a_ops` - Address space operations for page I/O
///
/// ## Returns
///
/// Number of bytes written, or error
#[allow(clippy::too_many_arguments)]
pub fn generic_file_write(
    file: &File,
    buf: &[u8],
    file_id: FileId,
    file_size: u64,
    can_writeback: bool,
    unevictable: bool,
    a_ops: &'static dyn AddressSpaceOps,
) -> Result<usize, FsError> {
    let pos = file.get_pos();

    if buf.is_empty() {
        return Ok(0);
    }

    // For block devices, cannot write past end
    // For regular files, this would extend the file
    let available = if file_size > pos {
        (file_size - pos) as usize
    } else {
        0
    };

    let to_write = min(buf.len(), available);
    if to_write == 0 {
        return Err(FsError::InvalidArgument);
    }

    let mut bytes_written = 0;

    while bytes_written < to_write {
        let current_pos = pos + bytes_written as u64;
        let page_offset = current_pos / PAGE_SIZE as u64;
        let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
        let chunk_size = min(PAGE_SIZE - offset_in_page, to_write - bytes_written);

        // Get or create the page
        let (page, is_new) = {
            let mut cache = PAGE_CACHE.lock();
            let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

            cache
                .find_or_create_page(
                    file_id,
                    page_offset,
                    file_size,
                    &mut frame_alloc,
                    can_writeback,
                    unevictable,
                    a_ops,
                )
                .map_err(|_| FsError::IoError)?
        };

        // If this is a partial page write and it's new, we need to read existing data first
        // (for block devices, this ensures we don't corrupt surrounding data)
        if is_new && (offset_in_page != 0 || chunk_size != PAGE_SIZE) {
            page.lock();

            let mut page_buf = [0u8; PAGE_SIZE];
            if a_ops.readpage(file_id, page_offset, &mut page_buf).is_ok() {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        page_buf.as_ptr(),
                        page.frame as *mut u8,
                        PAGE_SIZE,
                    );
                }
            }
            // If readpage fails, the page was already zeroed which is acceptable

            page.unlock();
        }

        // Write data to the page
        unsafe {
            let dst = (page.frame as *mut u8).add(offset_in_page);
            core::ptr::copy_nonoverlapping(buf[bytes_written..].as_ptr(), dst, chunk_size);
        }

        // Mark page as dirty
        page.mark_dirty();

        // Release our reference
        let cache = PAGE_CACHE.lock();
        cache.put_page(&page);

        bytes_written += chunk_size;
    }

    // Advance file position
    file.advance_pos(bytes_written as u64);

    Ok(bytes_written)
}

/// Generic positioned read using page cache.
///
/// Like `generic_file_read`, but reads at an explicit offset without
/// modifying the file position. Used for pread64 syscall.
///
/// ## Locking Context
///
/// Same as `generic_file_read` - acquires PAGE_CACHE lock briefly per page.
///
/// ## Arguments
///
/// * `_file` - The file being read (unused, but kept for consistency)
/// * `buf` - Buffer to read into
/// * `offset` - Position to read from (does NOT modify file position)
/// * `file_id` - Page cache identifier for this file
/// * `file_size` - Total file size in bytes
/// * `can_writeback` - Whether dirty pages can be written back
/// * `unevictable` - Whether pages are completely unevictable (ramfs)
/// * `a_ops` - Address space operations for page I/O
///
/// ## Returns
///
/// Number of bytes read, or error
#[allow(clippy::too_many_arguments)]
pub fn generic_file_pread(
    _file: &File,
    buf: &mut [u8],
    offset: u64,
    file_id: FileId,
    file_size: u64,
    can_writeback: bool,
    unevictable: bool,
    a_ops: &'static dyn AddressSpaceOps,
) -> Result<usize, FsError> {
    let pos = offset;

    // EOF check
    if pos >= file_size {
        return Ok(0);
    }

    let available = (file_size - pos) as usize;
    let to_read = min(buf.len(), available);

    if to_read == 0 {
        return Ok(0);
    }

    let mut bytes_read = 0;

    while bytes_read < to_read {
        let current_pos = pos + bytes_read as u64;
        let page_offset = current_pos / PAGE_SIZE as u64;
        let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
        let chunk_size = min(PAGE_SIZE - offset_in_page, to_read - bytes_read);

        // Get or create the page (PAGE_CACHE lock acquired/released)
        let (page, is_new) = {
            let mut cache = PAGE_CACHE.lock();
            let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

            cache
                .find_or_create_page(
                    file_id,
                    page_offset,
                    file_size,
                    &mut frame_alloc,
                    can_writeback,
                    unevictable,
                    a_ops,
                )
                .map_err(|_| FsError::IoError)?
        };
        // PAGE_CACHE lock released here

        // If this is a new page, populate it via readpage
        if is_new {
            // Lock the page for I/O
            page.lock();

            // Read page content from backing store
            let mut page_buf = [0u8; PAGE_SIZE];
            let read_result = a_ops.readpage(file_id, page_offset, &mut page_buf);

            match read_result {
                Ok(_) => {
                    // Copy data to the frame
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            page_buf.as_ptr(),
                            page.frame as *mut u8,
                            PAGE_SIZE,
                        );
                    }
                }
                Err(_) => {
                    page.unlock();
                    return Err(FsError::IoError);
                }
            }

            page.unlock();
        }

        // Copy data from page to user buffer (page is refcounted, safe to access)
        unsafe {
            let src = (page.frame as *const u8).add(offset_in_page);
            core::ptr::copy_nonoverlapping(src, buf[bytes_read..].as_mut_ptr(), chunk_size);
        }

        // Release our reference to the page
        let cache = PAGE_CACHE.lock();
        cache.put_page(&page);

        bytes_read += chunk_size;
    }

    // NOTE: Unlike generic_file_read, we do NOT advance file position
    Ok(bytes_read)
}

/// Generic positioned write using page cache.
///
/// Like `generic_file_write`, but writes at an explicit offset without
/// modifying the file position. Used for pwrite64 syscall.
///
/// ## Locking Context
///
/// Same as `generic_file_write` - acquires PAGE_CACHE lock briefly per page.
///
/// ## Arguments
///
/// * `_file` - The file being written (unused, but kept for consistency)
/// * `buf` - Data to write
/// * `offset` - Position to write to (does NOT modify file position)
/// * `file_id` - Page cache identifier for this file
/// * `file_size` - Current file size in bytes (may grow)
/// * `can_writeback` - Whether dirty pages can be written back
/// * `unevictable` - Whether pages are completely unevictable (ramfs)
/// * `a_ops` - Address space operations for page I/O
///
/// ## Returns
///
/// Number of bytes written, or error
#[allow(clippy::too_many_arguments)]
pub fn generic_file_pwrite(
    _file: &File,
    buf: &[u8],
    offset: u64,
    file_id: FileId,
    file_size: u64,
    can_writeback: bool,
    unevictable: bool,
    a_ops: &'static dyn AddressSpaceOps,
) -> Result<usize, FsError> {
    let pos = offset;

    if buf.is_empty() {
        return Ok(0);
    }

    // For block devices, cannot write past end
    // For regular files, this would extend the file
    let available = if file_size > pos {
        (file_size - pos) as usize
    } else {
        0
    };

    let to_write = min(buf.len(), available);
    if to_write == 0 {
        return Err(FsError::InvalidArgument);
    }

    let mut bytes_written = 0;

    while bytes_written < to_write {
        let current_pos = pos + bytes_written as u64;
        let page_offset = current_pos / PAGE_SIZE as u64;
        let offset_in_page = (current_pos % PAGE_SIZE as u64) as usize;
        let chunk_size = min(PAGE_SIZE - offset_in_page, to_write - bytes_written);

        // Get or create the page
        let (page, is_new) = {
            let mut cache = PAGE_CACHE.lock();
            let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

            cache
                .find_or_create_page(
                    file_id,
                    page_offset,
                    file_size,
                    &mut frame_alloc,
                    can_writeback,
                    unevictable,
                    a_ops,
                )
                .map_err(|_| FsError::IoError)?
        };

        // If this is a partial page write and it's new, we need to read existing data first
        // (for block devices, this ensures we don't corrupt surrounding data)
        if is_new && (offset_in_page != 0 || chunk_size != PAGE_SIZE) {
            page.lock();

            let mut page_buf = [0u8; PAGE_SIZE];
            if a_ops.readpage(file_id, page_offset, &mut page_buf).is_ok() {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        page_buf.as_ptr(),
                        page.frame as *mut u8,
                        PAGE_SIZE,
                    );
                }
            }
            // If readpage fails, the page was already zeroed which is acceptable

            page.unlock();
        }

        // Write data to the page
        unsafe {
            let dst = (page.frame as *mut u8).add(offset_in_page);
            core::ptr::copy_nonoverlapping(buf[bytes_written..].as_ptr(), dst, chunk_size);
        }

        // Mark page as dirty
        page.mark_dirty();

        // Release our reference
        let cache = PAGE_CACHE.lock();
        cache.put_page(&page);

        bytes_written += chunk_size;
    }

    // NOTE: Unlike generic_file_write, we do NOT advance file position
    Ok(bytes_written)
}

/// Generic fsync implementation using page cache.
///
/// Syncs all dirty pages for a file to backing store using the writeback module.
/// This is the proper async writeback path - it writes pages via do_writepages
/// and waits for all I/O to complete.
///
/// ## Locking Context
///
/// - Acquires PAGE_CACHE lock briefly to get AddressSpace
/// - Uses writeback module for actual I/O (proper writeback flag tracking)
/// - Waits for all in-flight writeback to complete
///
/// ## Arguments
///
/// * `file_id` - Page cache identifier for this file
///
/// ## Returns
///
/// Ok(()) on success, or error
pub fn generic_file_fsync(file_id: FileId) -> Result<(), FsError> {
    use crate::mm::writeback::{WritebackControl, do_writepages_for_file, wait_on_writeback};

    // Write all dirty pages for this file
    let mut wbc = WritebackControl::for_fsync();
    do_writepages_for_file(file_id, &mut wbc).map_err(|_| FsError::IoError)?;

    // Wait for all writeback to complete
    wait_on_writeback(file_id);

    Ok(())
}
