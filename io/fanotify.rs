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

use crate::util::kalloc::try_arc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch::IrqSpinlock;
use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, RwFlags, flags, stream_rw};
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::io::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::sync::waitqueue::WaitQueue;
use crate::util::pod::IntoBytes;

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
#[expect(dead_code)]
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

crate::pod!(FanotifyEventMetadata {
    event_len,
    vers,
    reserved,
    metadata_len,
    mask,
    fd,
    pid
});

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
    #[expect(dead_code)]
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
    #[expect(dead_code)]
    path: Option<String>,
    /// Inode number (for matching)
    #[expect(dead_code)]
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
    /// Init flags
    init_flags: u32,
    /// Event file flags (O_RDONLY, O_RDWR, etc.)
    #[expect(dead_code)]
    event_f_flags: u32,
}

impl Fanotify {
    /// Create a new fanotify instance
    pub fn new(init_flags: u32, event_f_flags: u32) -> Result<Arc<Self>, KernelError> {
        try_arc(Self {
            inner: IrqSpinlock::new(FanotifyInner {
                inode_marks: BTreeMap::new(),
                mount_marks: BTreeMap::new(),
                fs_marks: BTreeMap::new(),
                events: Vec::new(),
            }),
            wait_queue: WaitQueue::new(),
            init_flags,
            event_f_flags,
        })
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

    /// The oldest event if it fits in `room` bytes (EINVAL if not),
    /// waiting for one unless `nonblock` (Linux get_one_event)
    fn get_event(&self, room: usize, nonblock: bool) -> Result<FanotifyEvent, KernelError> {
        let mut inner = self.inner.lock();
        if inner.events.is_empty() {
            if nonblock {
                return Err(KernelError::WouldBlock);
            }
            // Wait for events (a signal ends the wait)
            self.wait_queue
                .wait_event_interruptible_locked(&mut inner, |i| !i.events.is_empty())?;
        }
        if inner.events[0].serialized_size() > room {
            return Err(KernelError::InvalidArgument);
        }
        Ok(inner.events.remove(0))
    }

    /// Read events into `to` (Linux fanotify_read): each is taken off
    /// the queue under the lock and copied out after it. Blocks only
    /// while nothing was read; a first event too big for the buffer is
    /// EINVAL. A fault loses the event and is EFAULT even after earlier
    /// events were copied (Linux).
    pub fn read(&self, to: &mut IovDest<'_>, nonblock: bool) -> Result<usize, KernelError> {
        // Buffer must be at least big enough for one event
        if to.len() < FANOTIFY_METADATA_SIZE {
            return Err(KernelError::InvalidArgument);
        }
        let mut done = 0;
        loop {
            let event = match self.get_event(to.len(), nonblock || done > 0) {
                Ok(e) => e,
                Err(_) if done > 0 => return Ok(done),
                Err(e) => return Err(e),
            };
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
            to.copy_to_full(metadata.as_bytes())?;
            done += FANOTIFY_METADATA_SIZE;
        }
    }

    /// Poll for readiness
    pub fn poll(&self, pt: Option<&mut PollTable<'_>>) -> u16 {
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
    pub fn queued_size(&self) -> usize {
        let inner = self.inner.lock();
        inner.events.iter().map(|e| e.serialized_size()).sum()
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
pub struct FanotifyFileOps;

static FANOTIFY_FOPS: FanotifyFileOps = FanotifyFileOps;

impl FileOps for FanotifyFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        stream_rw(at, flags)?;
        let fanotify = file.private_ref::<Fanotify>().ok_or(KernelError::BadFd)?;
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        fanotify.read(to, nonblock)
    }

    /// A fanotify fd is not writable (TODO: write answers permission
    /// events)
    fn write_iter(
        &self,
        _file: &File,
        _from: &mut IovSource<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        stream_rw(at, flags)?;
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Some(fanotify) = file.private_ref::<Fanotify>() else {
            return crate::io::poll::POLLERR;
        };
        fanotify.poll(pt)
    }
}

// =============================================================================
// Syscall Interface
// =============================================================================

/// Create a new fanotify instance
pub fn create_fanotify(init_flags: u32, event_f_flags: u32) -> Result<Arc<File>, KernelError> {
    let fanotify = Fanotify::new(init_flags, event_f_flags)?;

    // Create dummy dentry for fanotify

    // Determine file flags
    let mut file_flags = flags::O_RDONLY;
    if init_flags & FAN_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = crate::fs::anon_inodes::anon_inode_getfile(
        "[fanotify]",
        &FANOTIFY_FOPS,
        fanotify,
        file_flags,
    )?;
    Ok(file)
}

/// Get the Fanotify from a File
pub fn get_fanotify(file: &File) -> Option<Arc<Fanotify>> {
    file.private_arc::<Fanotify>()
}

// =============================================================================
// Syscall Handlers
// =============================================================================

/// sys_fanotify_init(flags, event_f_flags) - create fanotify instance
pub fn sys_fanotify_init(init_flags: u32, event_f_flags: u32) -> i64 {
    use crate::io::pipe::FD_CLOEXEC;
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
        let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_NOFILE);
        if limit == crate::task::rlimit::RLIM_INFINITY {
            u64::MAX
        } else {
            limit
        }
    };

    match table.alloc_with_flags(file, fd_flags, nofile_limit) {
        Ok(fd) => i64::from(fd),
        Err(e) => -i64::from(e),
    }
}

/// sys_fanotify_mark(fd, flags, mask, dirfd, pathname) - add/remove/flush marks
pub fn sys_fanotify_mark(fd: i32, mark_flags: u32, mask: u64, dirfd: i32, pathname: u64) -> i64 {
    use crate::fs::path_ref::Path;
    use crate::fs::{LookupFlags, lookup_path_at};
    use crate::task::fdtable::get_task_fd;
    use crate::task::percpu::current_tid;

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
    let op_count = u32::from(is_add) + u32::from(is_remove) + u32::from(is_flush);
    if op_count > 1 {
        return -22; // EINVAL
    }

    // Handle FLUSH - doesn't need path
    if is_flush {
        return match fanotify.flush_marks(mark_flags) {
            Ok(()) => 0,
            Err(e) => i64::from(e),
        };
    }

    // For ADD and REMOVE, we need a path (unless FAN_MARK_FLUSH only)
    if op_count == 0 && pathname == 0 {
        // Treat as flush
        return match fanotify.flush_marks(mark_flags) {
            Ok(()) => 0,
            Err(e) => i64::from(e),
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
        let pathname_str = match crate::fs::namei::getname(pathname, false) {
            Ok(p) => p,
            Err(e) => return e.sysret(),
        };

        // Get starting directory
        let start: Option<Path> = if pathname_str.starts_with(b"/") {
            None // Absolute path
        } else if dirfd == -100 {
            // AT_FDCWD
            crate::task::percpu::current_cwd()
        } else {
            // Get dentry from dirfd
            match fd_table.lock().get(dirfd) {
                Some(f) => f.f_path(),
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
            // Any lookup error as is (Linux fanotify_find_path)
            Err(e) => return e.sysret(),
        };

        // Check ONLYDIR
        if (mark_flags & FAN_MARK_ONLYDIR) != 0
            && let Some(inode) = dentry.get_inode()
            && !inode.mode().is_dir()
        {
            return -20; // ENOTDIR
        }

        // fanotify_find_path: the marked object must be readable
        if let Some(inode) = dentry.get_inode()
            && let Err(e) = crate::fs::dac::permission(&inode, crate::fs::MAY_READ)
        {
            return e.sysret();
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
            Err(e) => i64::from(e),
        }
    } else {
        // ADD (default if no op specified and pathname given)
        match fanotify.add_mark(mark_flags, mask, target_id) {
            Ok(()) => 0,
            Err(e) => i64::from(e),
        }
    }
}
