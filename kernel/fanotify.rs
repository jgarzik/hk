//! Fanotify (filesystem-wide notification) implementation
//!
//! Provides filesystem event notification via file descriptor, compatible with Linux fanotify API.
//! fanotify is more powerful than inotify - it can monitor entire mount points or filesystems.
//!
//! ## Architecture
//!
//! ```text
//! User Process
//!     |
//!     v
//! fanotify_init(flags, event_f_flags) -> fd
//!     |
//!     v
//! fanotify_mark(fd, flags, mask, dirfd, pathname) -> 0
//!     |
//!     v
//! read(fd, buf, count) -> fanotify_event_metadata structures
//! poll(fd) -> POLLIN when events pending
//! ```
//!
//! ## Key Features
//!
//! - Monitor entire mount points or filesystems (not just individual files)
//! - Events include PID of process causing the event
//! - Events can include fd to the affected file
//! - Support for permission events (blocking operations pending user decision)
//! - Multiple marks per fanotify instance

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::waitqueue::WaitQueue;

// =============================================================================
// Fanotify Init Flags (Linux ABI)
// =============================================================================

/// Close-on-exec for fanotify fd
pub const FAN_CLOEXEC: u32 = 0x00000001;
/// Non-blocking mode
pub const FAN_NONBLOCK: u32 = 0x00000002;
/// Notification class (default)
pub const FAN_CLASS_NOTIF: u32 = 0x00000000;
/// Content class - for permission events (requires CAP_SYS_ADMIN)
pub const FAN_CLASS_CONTENT: u32 = 0x00000004;
/// Pre-content class - for permission events before content (requires CAP_SYS_ADMIN)
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x00000008;
/// Unlimited queue (CAP_SYS_ADMIN)
pub const FAN_UNLIMITED_QUEUE: u32 = 0x00000010;
/// Unlimited marks (CAP_SYS_ADMIN)
pub const FAN_UNLIMITED_MARKS: u32 = 0x00000020;
/// Report thread ID instead of process ID
pub const FAN_REPORT_TID: u32 = 0x00000100;
/// Report file ID (handle-based, not fd-based)
pub const FAN_REPORT_FID: u32 = 0x00000200;
/// Report directory file ID
pub const FAN_REPORT_DIR_FID: u32 = 0x00000400;
/// Report name with directory file ID
pub const FAN_REPORT_NAME: u32 = 0x00000800;
/// Report target file ID (for FAN_RENAME)
pub const FAN_REPORT_TARGET_FID: u32 = 0x00001000;
/// Report pidfd
pub const FAN_REPORT_PIDFD: u32 = 0x00000080;

/// Class mask (bits 2-3)
const FAN_CLASS_MASK: u32 = FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT;

/// Valid init flags for unprivileged users
const FAN_INIT_VALID_UNPRIVILEGED: u32 = FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_NOTIF;

/// All valid init flags
const FAN_INIT_VALID: u32 = FAN_CLOEXEC
    | FAN_NONBLOCK
    | FAN_CLASS_NOTIF
    | FAN_CLASS_CONTENT
    | FAN_CLASS_PRE_CONTENT
    | FAN_UNLIMITED_QUEUE
    | FAN_UNLIMITED_MARKS
    | FAN_REPORT_TID
    | FAN_REPORT_FID
    | FAN_REPORT_DIR_FID
    | FAN_REPORT_NAME
    | FAN_REPORT_TARGET_FID
    | FAN_REPORT_PIDFD;

// =============================================================================
// Fanotify Mark Flags (Linux ABI)
// =============================================================================

/// Add mask to mark
pub const FAN_MARK_ADD: u32 = 0x00000001;
/// Remove mask from mark
pub const FAN_MARK_REMOVE: u32 = 0x00000002;
/// Don't follow symlinks
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x00000004;
/// Only create if path is directory
pub const FAN_MARK_ONLYDIR: u32 = 0x00000008;
/// Mark mount point
pub const FAN_MARK_MOUNT: u32 = 0x00000010;
/// Create ignore mask (suppress events)
pub const FAN_MARK_IGNORED_MASK: u32 = 0x00000020;
/// Ignore mask survives modify
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x00000040;
/// Flush all marks
pub const FAN_MARK_FLUSH: u32 = 0x00000080;
/// Mark filesystem (all files on this filesystem)
pub const FAN_MARK_FILESYSTEM: u32 = 0x00000100;
/// Mark can be evicted under memory pressure
pub const FAN_MARK_EVICTABLE: u32 = 0x00000200;
/// Ignore mark (newer form)
pub const FAN_MARK_IGNORE: u32 = 0x00000400;

/// Mark type mask
#[allow(dead_code)]
const FAN_MARK_TYPE_MASK: u32 = FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM;

/// Mark inode (default, no flag set)
pub const FAN_MARK_INODE: u32 = 0x00000000;

// =============================================================================
// Fanotify Event Masks (Linux ABI)
// =============================================================================

/// File was accessed
pub const FAN_ACCESS: u64 = 0x00000001;
/// File was modified
pub const FAN_MODIFY: u64 = 0x00000002;
/// Metadata changed
pub const FAN_ATTRIB: u64 = 0x00000004;
/// Writable file closed
pub const FAN_CLOSE_WRITE: u64 = 0x00000008;
/// Unwritable file closed
pub const FAN_CLOSE_NOWRITE: u64 = 0x00000010;
/// File was opened
pub const FAN_OPEN: u64 = 0x00000020;
/// File was moved from X
pub const FAN_MOVED_FROM: u64 = 0x00000040;
/// File was moved to Y
pub const FAN_MOVED_TO: u64 = 0x00000080;
/// File was created in watched directory
pub const FAN_CREATE: u64 = 0x00000100;
/// File was deleted from watched directory
pub const FAN_DELETE: u64 = 0x00000200;
/// Watched file/directory was deleted
pub const FAN_DELETE_SELF: u64 = 0x00000400;
/// Watched file/directory was moved
pub const FAN_MOVE_SELF: u64 = 0x00000800;
/// File was opened for execution
pub const FAN_OPEN_EXEC: u64 = 0x00001000;

/// Event queue overflowed
pub const FAN_Q_OVERFLOW: u64 = 0x00004000;
/// Filesystem error
pub const FAN_FS_ERROR: u64 = 0x00008000;

/// File open permission event
pub const FAN_OPEN_PERM: u64 = 0x00010000;
/// File access permission event
pub const FAN_ACCESS_PERM: u64 = 0x00020000;
/// File open execute permission event
pub const FAN_OPEN_EXEC_PERM: u64 = 0x00040000;

/// Helper: close (write + nowrite)
pub const FAN_CLOSE: u64 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;
/// Helper: move (from + to)
pub const FAN_MOVE: u64 = FAN_MOVED_FROM | FAN_MOVED_TO;

/// Event occurred on directory
pub const FAN_ONDIR: u64 = 0x40000000;
/// Interested in events on children (only for directories)
pub const FAN_EVENT_ON_CHILD: u64 = 0x08000000;

/// Rename event (requires FAN_REPORT_NAME)
pub const FAN_RENAME: u64 = 0x10000000;

/// All notification events (no permission events)
pub const FAN_ALL_EVENTS: u64 = FAN_ACCESS
    | FAN_MODIFY
    | FAN_ATTRIB
    | FAN_CLOSE_WRITE
    | FAN_CLOSE_NOWRITE
    | FAN_OPEN
    | FAN_MOVED_FROM
    | FAN_MOVED_TO
    | FAN_CREATE
    | FAN_DELETE
    | FAN_DELETE_SELF
    | FAN_MOVE_SELF
    | FAN_OPEN_EXEC;

/// Permission events
pub const FAN_ALL_PERM_EVENTS: u64 = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM;

// =============================================================================
// Fanotify Event Metadata (Linux ABI)
// =============================================================================

/// fanotify_event_metadata - Linux ABI
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FanotifyEventMetadata {
    /// Total size of this event (including info records if any)
    pub event_len: u32,
    /// Metadata version (FANOTIFY_METADATA_VERSION)
    pub vers: u8,
    /// Reserved
    pub reserved: u8,
    /// Size of this metadata structure
    pub metadata_len: u16,
    /// Event mask
    pub mask: u64,
    /// File descriptor to affected file (-1 if FAN_NOFD or FID mode)
    pub fd: i32,
    /// PID of process causing the event
    pub pid: i32,
}

/// Metadata version
pub const FANOTIFY_METADATA_VERSION: u8 = 3;

/// Size of metadata structure
pub const FANOTIFY_METADATA_SIZE: usize = core::mem::size_of::<FanotifyEventMetadata>();

// =============================================================================
// Maximum queued events
// =============================================================================

/// Maximum queued events per instance (default)
const FANOTIFY_MAX_QUEUED_EVENTS: usize = 16384;

// =============================================================================
// Fanotify Mark
// =============================================================================

/// A fanotify mark on an inode, mount, or filesystem
struct FanotifyMark {
    /// Events to watch for
    mask: u64,
    /// Flags from mark operation
    #[allow(dead_code)]
    flags: u32,
    /// Ignored event mask
    ignored_mask: u64,
}

impl FanotifyMark {
    fn new(mask: u64, flags: u32) -> Self {
        Self {
            mask,
            flags,
            ignored_mask: 0,
        }
    }
}

// =============================================================================
// Fanotify Event
// =============================================================================

/// A queued fanotify event
struct FanotifyEvent {
    /// Event mask
    mask: u64,
    /// PID of process causing event
    pid: i32,
    /// Path to file (for opening fd when event is read)
    #[allow(dead_code)]
    path: Option<String>,
    /// Inode number (for matching)
    #[allow(dead_code)]
    ino: u64,
}

impl FanotifyEvent {
    /// Serialized size
    fn serialized_size(&self) -> usize {
        FANOTIFY_METADATA_SIZE
    }
}

// =============================================================================
// Fanotify Instance
// =============================================================================

/// Internal fanotify state
struct FanotifyInner {
    /// Inode marks: inode_number -> mark
    inode_marks: BTreeMap<u64, FanotifyMark>,
    /// Mount marks: mount_id -> mark
    mount_marks: BTreeMap<u64, FanotifyMark>,
    /// Filesystem marks: superblock_id -> mark
    fs_marks: BTreeMap<u64, FanotifyMark>,
    /// Queued events
    events: Vec<FanotifyEvent>,
}

/// Fanotify instance
pub struct Fanotify {
    /// Inner state protected by spinlock
    inner: IrqSpinlock<FanotifyInner>,
    /// Wait queue for blocking readers
    wait_queue: WaitQueue,
    /// Unique ID for this instance
    id: u64,
    /// Init flags
    init_flags: u32,
    /// Event file flags (O_RDONLY, O_RDWR, etc.)
    #[allow(dead_code)]
    event_f_flags: u32,
}

/// Global counter for fanotify IDs
static NEXT_FANOTIFY_ID: AtomicU64 = AtomicU64::new(1);

/// Global fanotify registry for event dispatch
static FANOTIFY_REGISTRY: IrqSpinlock<Vec<(u64, Weak<Fanotify>)>> = IrqSpinlock::new(Vec::new());

impl Fanotify {
    /// Create a new fanotify instance
    pub fn new(init_flags: u32, event_f_flags: u32) -> Arc<Self> {
        let id = NEXT_FANOTIFY_ID.fetch_add(1, Ordering::Relaxed);

        let fanotify = Arc::new(Self {
            inner: IrqSpinlock::new(FanotifyInner {
                inode_marks: BTreeMap::new(),
                mount_marks: BTreeMap::new(),
                fs_marks: BTreeMap::new(),
                events: Vec::new(),
            }),
            wait_queue: WaitQueue::new(),
            id,
            init_flags,
            event_f_flags,
        });

        // Register in global registry
        let weak = Arc::downgrade(&fanotify);
        FANOTIFY_REGISTRY.lock().push((id, weak));

        fanotify
    }

    /// Add or update a mark
    pub fn add_mark(&self, mark_flags: u32, mask: u64, target_id: u64) -> Result<(), i32> {
        let mut inner = self.inner.lock();

        let marks = if (mark_flags & FAN_MARK_FILESYSTEM) != 0 {
            &mut inner.fs_marks
        } else if (mark_flags & FAN_MARK_MOUNT) != 0 {
            &mut inner.mount_marks
        } else {
            &mut inner.inode_marks
        };

        if let Some(existing) = marks.get_mut(&target_id) {
            // Add to existing mark
            existing.mask |= mask;
        } else {
            // Create new mark
            marks.insert(target_id, FanotifyMark::new(mask, mark_flags));
        }

        Ok(())
    }

    /// Remove mask bits from a mark
    pub fn remove_mark(&self, mark_flags: u32, mask: u64, target_id: u64) -> Result<(), i32> {
        let mut inner = self.inner.lock();

        let marks = if (mark_flags & FAN_MARK_FILESYSTEM) != 0 {
            &mut inner.fs_marks
        } else if (mark_flags & FAN_MARK_MOUNT) != 0 {
            &mut inner.mount_marks
        } else {
            &mut inner.inode_marks
        };

        if let Some(existing) = marks.get_mut(&target_id) {
            existing.mask &= !mask;
            if existing.mask == 0 && existing.ignored_mask == 0 {
                marks.remove(&target_id);
            }
        }

        Ok(())
    }

    /// Flush all marks of a given type
    pub fn flush_marks(&self, mark_flags: u32) -> Result<(), i32> {
        let mut inner = self.inner.lock();

        if (mark_flags & FAN_MARK_FILESYSTEM) != 0 {
            inner.fs_marks.clear();
        } else if (mark_flags & FAN_MARK_MOUNT) != 0 {
            inner.mount_marks.clear();
        } else {
            inner.inode_marks.clear();
        }

        Ok(())
    }

    /// Queue an event
    #[allow(dead_code)]
    pub fn queue_event(&self, mask: u64, pid: i32, path: Option<String>, ino: u64) {
        let mut inner = self.inner.lock();

        if inner.events.len() < FANOTIFY_MAX_QUEUED_EVENTS {
            inner.events.push(FanotifyEvent {
                mask,
                pid,
                path,
                ino,
            });
        } else if inner.events.is_empty()
            || inner.events.last().map(|e| e.mask) != Some(FAN_Q_OVERFLOW)
        {
            // Queue overflow event
            inner.events.push(FanotifyEvent {
                mask: FAN_Q_OVERFLOW,
                pid: 0,
                path: None,
                ino: 0,
            });
        }

        drop(inner);
        self.wait_queue.wake_all();
    }

    /// Check if any events are pending
    fn has_events(&self) -> bool {
        !self.inner.lock().events.is_empty()
    }

    /// Read events from the fanotify instance
    pub fn read(&self, buf: &mut [u8], nonblock: bool) -> Result<usize, KernelError> {
        // Buffer must be at least big enough for one event
        if buf.len() < FANOTIFY_METADATA_SIZE {
            return Err(KernelError::InvalidArgument);
        }

        loop {
            let mut inner = self.inner.lock();

            if !inner.events.is_empty() {
                let mut bytes_written = 0;

                // Copy as many events as will fit
                while !inner.events.is_empty() {
                    let event = &inner.events[0];
                    let event_size = event.serialized_size();

                    if bytes_written + event_size > buf.len() {
                        if bytes_written == 0 {
                            // First event doesn't fit
                            return Err(KernelError::InvalidArgument);
                        }
                        break;
                    }

                    // Remove event from queue
                    let event = inner.events.remove(0);

                    // Create metadata structure
                    // Note: In a full implementation, we would open the file here
                    // and pass the fd. For now, we pass -1 (FAN_NOFD equivalent).
                    let metadata = FanotifyEventMetadata {
                        event_len: FANOTIFY_METADATA_SIZE as u32,
                        vers: FANOTIFY_METADATA_VERSION,
                        reserved: 0,
                        metadata_len: FANOTIFY_METADATA_SIZE as u16,
                        mask: event.mask,
                        fd: -1, // FAN_NOFD - file descriptor not provided
                        pid: event.pid,
                    };

                    // Copy metadata to buffer
                    let metadata_bytes = unsafe {
                        core::slice::from_raw_parts(
                            &metadata as *const FanotifyEventMetadata as *const u8,
                            FANOTIFY_METADATA_SIZE,
                        )
                    };
                    buf[bytes_written..bytes_written + FANOTIFY_METADATA_SIZE]
                        .copy_from_slice(metadata_bytes);
                    bytes_written += FANOTIFY_METADATA_SIZE;
                }

                return Ok(bytes_written);
            }

            drop(inner);

            if nonblock {
                return Err(KernelError::WouldBlock);
            }

            // Wait for events
            self.wait_queue.wait();
        }
    }

    /// Poll for readiness
    pub fn poll(&self, pt: Option<&mut PollTable>) -> u16 {
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.wait_queue);
        }

        if self.has_events() {
            POLLIN | POLLRDNORM
        } else {
            0
        }
    }

    /// Get the total size of queued events
    #[allow(dead_code)]
    pub fn queued_size(&self) -> usize {
        let inner = self.inner.lock();
        inner.events.iter().map(|e| e.serialized_size()).sum()
    }

    /// Release the fanotify instance
    fn release(&self) {
        let mut registry = FANOTIFY_REGISTRY.lock();
        registry.retain(|(id, _)| *id != self.id);
    }

    /// Get init flags
    pub fn get_init_flags(&self) -> u32 {
        self.init_flags
    }
}

// =============================================================================
// File Operations
// =============================================================================

/// File operations for fanotify
pub struct FanotifyFileOps {
    fanotify: Arc<Fanotify>,
}

impl FanotifyFileOps {
    /// Create file ops for a fanotify instance
    pub fn new(fanotify: Arc<Fanotify>) -> Self {
        Self { fanotify }
    }
}

impl FileOps for FanotifyFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        self.fanotify.read(buf, nonblock)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        // TODO: Write is used for responding to permission events
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        self.fanotify.poll(pt)
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        self.fanotify.release();
        Ok(())
    }
}

// =============================================================================
// Syscall Interface
// =============================================================================

/// Create a new fanotify instance
pub fn create_fanotify(init_flags: u32, event_f_flags: u32) -> Result<Arc<File>, KernelError> {
    let fanotify = Fanotify::new(init_flags, event_f_flags);

    // Create file operations
    let ops: &'static dyn FileOps = Box::leak(Box::new(FanotifyFileOps::new(fanotify)));

    // Create dummy dentry for fanotify
    let dentry = create_fanotify_dentry()?;

    // Determine file flags
    let mut file_flags = flags::O_RDONLY;
    if init_flags & FAN_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = Arc::new(File::new(dentry, file_flags, ops));
    Ok(file)
}

/// Create a dummy dentry for fanotify
fn create_fanotify_dentry() -> Result<Arc<Dentry>, KernelError> {
    let mode = InodeMode::regular(0o600);
    let inode = Arc::new(Inode::new(
        0,
        mode,
        0,
        0,
        0,
        InodeTimespec::from_secs(0),
        Weak::new(),
        &NULL_INODE_OPS,
    ));

    let dentry = Arc::new(Dentry::new_anonymous(String::from("fanotify"), Some(inode)));
    Ok(dentry)
}

/// Get the Fanotify from a File
pub fn get_fanotify(file: &File) -> Option<Arc<Fanotify>> {
    file.f_op
        .as_any()
        .downcast_ref::<FanotifyFileOps>()
        .map(|ops| Arc::clone(&ops.fanotify))
}

// =============================================================================
// Syscall Handlers
// =============================================================================

/// sys_fanotify_init(flags, event_f_flags) - create fanotify instance
pub fn sys_fanotify_init(init_flags: u32, event_f_flags: u32) -> i64 {
    use crate::pipe::FD_CLOEXEC;
    use crate::task::fdtable::get_task_fd;
    use crate::task::percpu::current_tid;

    // Validate init_flags
    if init_flags & !FAN_INIT_VALID != 0 {
        return -22; // EINVAL
    }

    // Check for mutually exclusive flags
    if (init_flags & FAN_REPORT_PIDFD) != 0 && (init_flags & FAN_REPORT_TID) != 0 {
        return -22; // EINVAL
    }

    // FAN_REPORT_NAME requires FAN_REPORT_DIR_FID
    if (init_flags & FAN_REPORT_NAME) != 0 && (init_flags & FAN_REPORT_DIR_FID) == 0 {
        return -22; // EINVAL
    }

    // FAN_REPORT_TARGET_FID requires FAN_REPORT_NAME and FAN_REPORT_FID
    if (init_flags & FAN_REPORT_TARGET_FID) != 0
        && ((init_flags & FAN_REPORT_NAME) == 0 || (init_flags & FAN_REPORT_FID) == 0)
    {
        return -22; // EINVAL
    }

    // Privileged flags check
    let has_privileged_flags =
        (init_flags & !FAN_INIT_VALID_UNPRIVILEGED) != 0 || (init_flags & FAN_CLASS_MASK) != 0;

    if has_privileged_flags {
        // Check CAP_SYS_ADMIN
        if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            return -1; // EPERM
        }
    }

    // Validate event_f_flags (O_RDONLY, O_WRONLY, O_RDWR, O_LARGEFILE, O_CLOEXEC, O_APPEND)
    let access_mode = event_f_flags & 0o3; // O_ACCMODE
    if access_mode != 0o0 && access_mode != 0o1 && access_mode != 0o2 {
        // O_RDONLY, O_WRONLY, O_RDWR
        return -22; // EINVAL
    }

    // Create fanotify file
    let file = match create_fanotify(init_flags, event_f_flags) {
        Ok(f) => f,
        Err(_) => return -12, // ENOMEM
    };

    // Allocate fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return -24, // EMFILE
    };

    let mut table = fd_table.lock();
    let fd_flags = if init_flags & FAN_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };

    // Get RLIMIT_NOFILE
    let nofile_limit = {
        let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
        if limit == crate::rlimit::RLIM_INFINITY {
            u64::MAX
        } else {
            limit
        }
    };

    match table.alloc_with_flags(file, fd_flags, nofile_limit) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// Maximum path length
const PATH_MAX: usize = 4096;

/// sys_fanotify_mark(fd, flags, mask, dirfd, pathname) - add/remove/flush marks
pub fn sys_fanotify_mark(fd: i32, mark_flags: u32, mask: u64, dirfd: i32, pathname: u64) -> i64 {
    use crate::fs::path_ref::Path;
    use crate::fs::{LookupFlags, lookup_path_at};
    use crate::task::fdtable::get_task_fd;
    use crate::task::percpu::current_tid;
    use crate::uaccess::strncpy_from_user;

    // Get fd table
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return -9, // EBADF
    };

    // Get fanotify file
    let file = match fd_table.lock().get(fd) {
        Some(f) => f,
        None => return -9, // EBADF
    };

    // Verify it's a fanotify fd
    let fanotify = match get_fanotify(&file) {
        Some(f) => f,
        None => return -9, // EBADF
    };

    // Determine operation
    let is_add = (mark_flags & FAN_MARK_ADD) != 0;
    let is_remove = (mark_flags & FAN_MARK_REMOVE) != 0;
    let is_flush = (mark_flags & FAN_MARK_FLUSH) != 0;

    // Exactly one of ADD, REMOVE, FLUSH must be set (or none for flush compatibility)
    let op_count = is_add as u32 + is_remove as u32 + is_flush as u32;
    if op_count > 1 {
        return -22; // EINVAL
    }

    // Handle FLUSH - doesn't need path
    if is_flush {
        return match fanotify.flush_marks(mark_flags) {
            Ok(()) => 0,
            Err(e) => e as i64,
        };
    }

    // For ADD and REMOVE, we need a path (unless FAN_MARK_FLUSH only)
    if op_count == 0 && pathname == 0 {
        // Treat as flush
        return match fanotify.flush_marks(mark_flags) {
            Ok(()) => 0,
            Err(e) => e as i64,
        };
    }

    // Validate mask for ADD/REMOVE
    if mask == 0 && is_add {
        return -22; // EINVAL
    }

    // Check for privileged mark types
    if (mark_flags & (FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM)) != 0
        && !crate::task::capable(crate::task::CAP_SYS_ADMIN)
    {
        return -1; // EPERM
    }

    // Resolve path to get target ID
    let target_id = if pathname != 0 {
        // Copy pathname from user
        let pathname_str = match strncpy_from_user::<crate::arch::Uaccess>(pathname, PATH_MAX) {
            Ok(p) => p,
            Err(_) => return -14, // EFAULT
        };

        // Get starting directory
        let start: Option<Path> = if pathname_str.starts_with('/') {
            None // Absolute path
        } else if dirfd == -100 {
            // AT_FDCWD
            crate::task::percpu::current_cwd()
        } else {
            // Get dentry from dirfd
            match fd_table.lock().get(dirfd) {
                Some(f) => Path::from_dentry(f.dentry.clone()),
                None => return -9, // EBADF
            }
        };

        // Set up lookup flags
        let mut lookup_flags = LookupFlags::open();
        if (mark_flags & FAN_MARK_DONT_FOLLOW) != 0 {
            lookup_flags.follow = false;
        }

        // Lookup path
        let dentry = match lookup_path_at(start, &pathname_str, lookup_flags) {
            Ok(d) => d,
            Err(e) => {
                return match e {
                    KernelError::NotFound => -2,          // ENOENT
                    KernelError::NotDirectory => -20,     // ENOTDIR
                    KernelError::PermissionDenied => -13, // EACCES
                    KernelError::TooManySymlinks => -40,  // ELOOP
                    _ => -22,                             // EINVAL
                };
            }
        };

        // Check ONLYDIR
        if (mark_flags & FAN_MARK_ONLYDIR) != 0
            && let Some(inode) = dentry.get_inode()
            && !inode.mode().is_dir()
        {
            return -20; // ENOTDIR
        }

        // Get target ID based on mark type
        if (mark_flags & FAN_MARK_FILESYSTEM) != 0 {
            // Use superblock ID (use dev_id from superblock)
            if let Some(inode) = dentry.get_inode() {
                if let Some(sb) = inode.sb.upgrade() {
                    sb.dev_id
                } else {
                    0
                }
            } else {
                0
            }
        } else if (mark_flags & FAN_MARK_MOUNT) != 0 {
            // Use mount ID (simplified: use dev_id from superblock)
            if let Some(inode) = dentry.get_inode() {
                if let Some(sb) = inode.sb.upgrade() {
                    sb.dev_id
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            // Use inode number
            if let Some(inode) = dentry.get_inode() {
                inode.ino
            } else {
                return -2; // ENOENT
            }
        }
    } else {
        return -22; // EINVAL - pathname required for ADD/REMOVE
    };

    // Perform operation
    if is_remove {
        match fanotify.remove_mark(mark_flags, mask, target_id) {
            Ok(()) => 0,
            Err(e) => e as i64,
        }
    } else {
        // ADD (default if no op specified and pathname given)
        match fanotify.add_mark(mark_flags, mask, target_id) {
            Ok(()) => 0,
            Err(e) => e as i64,
        }
    }
}
