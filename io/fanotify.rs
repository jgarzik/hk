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

use crate::fs::FileRef;
use crate::util::kalloc::{try_arc, try_box};
use crate::util::list::{BoxList, Link};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, RwFlags, flags, stream_rw};
use crate::fs::iov_iter::IovDest;
use crate::io::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::WaitQueue;
use crate::uaccess::UserPtr;
use crate::util::error::KernelResult;
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
    /// Ignored event mask
    ignored_mask: u64,
}

impl FanotifyMark {
    fn new(mask: u64) -> Self {
        Self {
            mask,
            ignored_mask: 0,
        }
    }
}

// =============================================================================
// Fanotify Event
// =============================================================================

/// A queued fanotify event
#[derive(Clone, Copy)]
struct FanotifyEvent {
    /// Event mask
    mask: u64,
    /// PID of process causing event
    pid: i32,
}

impl FanotifyEvent {
    /// Serialized size
    fn serialized_size(&self) -> usize {
        FANOTIFY_METADATA_SIZE
    }
}

/// FAN_Q_OVERFLOW as read (Linux's preallocated group->overflow_event)
const OVERFLOW_EVENT: FanotifyEvent = FanotifyEvent {
    mask: FAN_Q_OVERFLOW,
    pid: 0,
};

/// A queued event, allocated before the queue lock is taken (Linux
/// fanotify_alloc_event, then fsnotify_insert_event)
struct EvNode {
    link: Link,
    ev: FanotifyEvent,
}

crate::adapter!(EvAdapter, EvNode, link);

// =============================================================================
// Fanotify Instance
// =============================================================================

/// A group's marks (Linux: the marks a group holds, under
/// group->mark_mutex)
#[derive(Default)]
struct FanMarks {
    /// Inode marks: inode_number -> mark
    inode_marks: BTreeMap<u64, FanotifyMark>,
    /// Mount marks: mount_id -> mark
    mount_marks: BTreeMap<u64, FanotifyMark>,
    /// Filesystem marks: superblock_id -> mark
    fs_marks: BTreeMap<u64, FanotifyMark>,
}

impl FanMarks {
    /// The marks of the type `mark_flags` names
    fn of(&mut self, mark_flags: u32) -> &mut BTreeMap<u64, FanotifyMark> {
        if (mark_flags & FAN_MARK_FILESYSTEM) != 0 {
            &mut self.fs_marks
        } else if (mark_flags & FAN_MARK_MOUNT) != 0 {
            &mut self.mount_marks
        } else {
            &mut self.inode_marks
        }
    }
}

/// A group's event queue (Linux group->notification_list under
/// notification_lock)
struct FanotifyInner {
    /// Queued events, oldest first
    events: BoxList<EvAdapter>,
    /// The one FAN_Q_OVERFLOW, while queued: how many of `events` are
    /// ahead of it (a position, so queueing it allocates nothing)
    overflow: Option<usize>,
}

impl FanotifyInner {
    const fn new() -> Self {
        Self {
            events: BoxList::new(),
            overflow: None,
        }
    }

    /// Queued events, the overflow counted (Linux q_len)
    fn len(&self) -> usize {
        self.events.len() + usize::from(self.overflow.is_some())
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queue `ev` (Linux fsnotify_insert_event): past
    /// FANOTIFY_MAX_QUEUED_EVENTS, or without memory for it (None),
    /// FAN_Q_OVERFLOW is queued in its place, once. Whether anything
    /// was queued, and the event if it was not, to free after the
    /// unlock.
    fn push(&mut self, ev: Option<Box<EvNode>>) -> (bool, Option<Box<EvNode>>) {
        match ev {
            Some(e) if self.len() < FANOTIFY_MAX_QUEUED_EVENTS => {
                self.events.push_back(e);
                (true, None)
            }
            e if self.overflow.is_none() => {
                self.overflow = Some(self.events.len());
                (true, e)
            }
            e => (false, e),
        }
    }

    /// The oldest event (Linux fsnotify_peek_first_event)
    fn front(&self) -> Option<FanotifyEvent> {
        match self.overflow {
            Some(0) => Some(OVERFLOW_EVENT),
            _ => self.events.iter().next().map(|n| n.ev),
        }
    }

    /// Take the oldest event (Linux fsnotify_remove_first_event): its
    /// node, if any, is freed by the caller after the unlock
    fn pop(&mut self) -> Option<(FanotifyEvent, Option<Box<EvNode>>)> {
        match self.overflow {
            Some(0) => {
                self.overflow = None;
                Some((OVERFLOW_EVENT, None))
            }
            Some(n) => {
                self.overflow = Some(n - 1);
                self.events.pop_front().map(|b| (b.ev, Some(b)))
            }
            None => self.events.pop_front().map(|b| (b.ev, Some(b))),
        }
    }
}

/// Fanotify instance
pub struct Fanotify {
    /// The marks (sleeping, Linux group->mark_mutex)
    mark_mutex: crate::sync::Mutex<FanMarks>,
    /// The event queue (Linux group->notification_lock)
    inner: IrqSpinlock<FanotifyInner>,
    /// Wait queue for blocking readers
    wait_queue: WaitQueue,
    /// Init flags
    init_flags: u32,
}

impl Fanotify {
    /// Create a new fanotify instance
    pub fn new(init_flags: u32) -> Result<Arc<Self>, KernelError> {
        try_arc(Self {
            mark_mutex: crate::sync::Mutex::new(FanMarks::default()),
            inner: IrqSpinlock::new(FanotifyInner::new()),
            wait_queue: WaitQueue::new(),
            init_flags,
        })
    }

    /// Add or update a mark (Linux fanotify_add_mark, under mark_mutex)
    pub fn add_mark(&self, mark_flags: u32, mask: u64, target_id: u64) {
        let mut all = self.mark_mutex.lock();
        let marks = all.of(mark_flags);

        if let Some(existing) = marks.get_mut(&target_id) {
            // Add to existing mark
            existing.mask |= mask;
        } else {
            // Create new mark
            marks.insert(target_id, FanotifyMark::new(mask));
        }
    }

    /// Remove mask bits from a mark
    pub fn remove_mark(&self, mark_flags: u32, mask: u64, target_id: u64) {
        let mut all = self.mark_mutex.lock();
        let marks = all.of(mark_flags);

        if let Some(existing) = marks.get_mut(&target_id) {
            existing.mask &= !mask;
            if existing.mask == 0 && existing.ignored_mask == 0 {
                marks.remove(&target_id);
            }
        }
    }

    /// Flush all marks of a given type
    pub fn flush_marks(&self, mark_flags: u32) {
        // The marks are freed after the lock
        let gone = core::mem::take(self.mark_mutex.lock().of(mark_flags));
        drop(gone);
    }

    /// Queue an event: allocated before the queue lock (Linux
    /// fanotify_handle_event: fanotify_alloc_event, then
    /// fsnotify_insert_event; no memory queues FAN_Q_OVERFLOW)
    pub fn queue_event(&self, mask: u64, pid: i32) {
        let ev = try_box(EvNode {
            link: Link::new(),
            ev: FanotifyEvent { mask, pid },
        })
        .ok();
        let (queued, left) = self.inner.lock().push(ev);
        drop(left);
        if queued {
            self.wait_queue.wake_all();
        }
    }

    /// Check if any events are pending
    fn has_events(&self) -> bool {
        !self.inner.lock().is_empty()
    }

    /// The oldest event if it fits in `room` bytes (EINVAL if not),
    /// waiting for one unless `nonblock` (Linux get_one_event)
    fn get_event(&self, room: usize, nonblock: bool) -> Result<FanotifyEvent, KernelError> {
        let mut inner = self.inner.lock();
        if inner.is_empty() {
            if nonblock {
                return Err(KernelError::WouldBlock);
            }
            // Wait for events (a signal ends the wait)
            self.wait_queue
                .wait_event_interruptible_locked(&mut inner, |i| !i.is_empty())?;
        }
        if inner.front().map_or(0, |e| e.serialized_size()) > room {
            return Err(KernelError::InvalidArgument);
        }
        let (ev, node) = inner.pop().ok_or(KernelError::WouldBlock)?;
        drop(inner);
        drop(node);
        Ok(ev)
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
        self.inner.lock().len() * FANOTIFY_METADATA_SIZE
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

    /// FIONREAD: the bytes a read would return now (Linux fanotify_ioctl)
    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let g = file.private_ref::<Fanotify>().ok_or(KernelError::BadFd)?;
        match cmd {
            crate::fs::file::FIONREAD => crate::fs::file::put_fionread(arg, g.queued_size() as i64),
            _ => Err(KernelError::NotTty),
        }
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
pub fn create_fanotify(init_flags: u32) -> Result<FileRef, KernelError> {
    let fanotify = Fanotify::new(init_flags)?;

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
pub fn sys_fanotify_init(init_flags: u32, event_f_flags: u32) -> KernelResult<i32> {
    use crate::io::pipe::FD_CLOEXEC;

    // Validate init_flags
    if init_flags & !FAN_INIT_VALID != 0 {
        return Err(KernelError::InvalidArgument);
    }

    // Check for mutually exclusive flags
    if (init_flags & FAN_REPORT_PIDFD) != 0 && (init_flags & FAN_REPORT_TID) != 0 {
        return Err(KernelError::InvalidArgument);
    }

    // FAN_REPORT_NAME requires FAN_REPORT_DIR_FID
    if (init_flags & FAN_REPORT_NAME) != 0 && (init_flags & FAN_REPORT_DIR_FID) == 0 {
        return Err(KernelError::InvalidArgument);
    }

    // FAN_REPORT_TARGET_FID requires FAN_REPORT_NAME and FAN_REPORT_FID
    if (init_flags & FAN_REPORT_TARGET_FID) != 0
        && ((init_flags & FAN_REPORT_NAME) == 0 || (init_flags & FAN_REPORT_FID) == 0)
    {
        return Err(KernelError::InvalidArgument);
    }

    // Privileged flags check
    let has_privileged_flags =
        (init_flags & !FAN_INIT_VALID_UNPRIVILEGED) != 0 || (init_flags & FAN_CLASS_MASK) != 0;

    if has_privileged_flags && !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }

    // Validate event_f_flags (O_RDONLY, O_WRONLY, O_RDWR, O_LARGEFILE, O_CLOEXEC, O_APPEND)
    let access_mode = event_f_flags & 0o3; // O_ACCMODE
    if access_mode != 0o0 && access_mode != 0o1 && access_mode != 0o2 {
        // O_RDONLY, O_WRONLY, O_RDWR
        return Err(KernelError::InvalidArgument);
    }

    let file = create_fanotify(init_flags)?;
    let fd_flags = if init_flags & FAN_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };
    crate::fs::io::fd_install(file, fd_flags)
}

/// sys_fanotify_mark(fd, flags, mask, dirfd, pathname) - add/remove/flush marks
pub fn sys_fanotify_mark(
    fd: i32,
    mark_flags: u32,
    mask: u64,
    dirfd: i32,
    pathname: UserPtr<u8>,
) -> KernelResult<()> {
    use crate::fs::io::fget;
    use crate::fs::path_ref::Path;
    use crate::fs::{LookupFlags, lookup_path_at};

    let file = fget(fd)?;
    let fanotify = get_fanotify(&file).ok_or(KernelError::BadFd)?;

    // Determine operation
    let is_add = (mark_flags & FAN_MARK_ADD) != 0;
    let is_remove = (mark_flags & FAN_MARK_REMOVE) != 0;
    let is_flush = (mark_flags & FAN_MARK_FLUSH) != 0;

    // Exactly one of ADD, REMOVE, FLUSH must be set (or none for flush compatibility)
    let op_count = u32::from(is_add) + u32::from(is_remove) + u32::from(is_flush);
    if op_count > 1 {
        return Err(KernelError::InvalidArgument);
    }

    // FLUSH needs no path; neither does no operation without a path
    if is_flush || (op_count == 0 && pathname.is_null()) {
        fanotify.flush_marks(mark_flags);
        return Ok(());
    }

    // Validate mask for ADD/REMOVE
    if mask == 0 && is_add {
        return Err(KernelError::InvalidArgument);
    }

    // Check for privileged mark types
    if (mark_flags & (FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM)) != 0
        && !crate::task::capable(crate::task::CAP_SYS_ADMIN)
    {
        return Err(KernelError::NotPermitted);
    }

    // pathname required for ADD/REMOVE
    if pathname.is_null() {
        return Err(KernelError::InvalidArgument);
    }
    let pathname_str = crate::fs::namei::getname(pathname, false)?;

    // Get starting directory
    let start: Option<Path> = if pathname_str.starts_with(b"/") {
        None // Absolute path
    } else if dirfd == -100 {
        // AT_FDCWD
        crate::task::percpu::current_cwd()
    } else {
        crate::fs::io::fget_raw(dirfd)?.f_path()
    };

    // Set up lookup flags
    let mut lookup_flags = LookupFlags::open();
    if (mark_flags & FAN_MARK_DONT_FOLLOW) != 0 {
        lookup_flags.follow = false;
    }

    // Any lookup error as is (Linux fanotify_find_path)
    let dentry = lookup_path_at(start, &pathname_str, lookup_flags)?;

    // Check ONLYDIR
    if (mark_flags & FAN_MARK_ONLYDIR) != 0
        && let Some(inode) = dentry.get_inode()
        && !inode.mode().is_dir()
    {
        return Err(KernelError::NotDirectory);
    }

    // fanotify_find_path: the marked object must be readable
    if let Some(inode) = dentry.get_inode() {
        crate::fs::dac::permission(&inode, crate::fs::MAY_READ)?;
    }

    // Target ID by mark type: the superblock's dev_id for a filesystem
    // or (simplified) a mount mark, else the inode number
    let inode = dentry.get_inode();
    let target_id = if (mark_flags & (FAN_MARK_FILESYSTEM | FAN_MARK_MOUNT)) != 0 {
        inode.and_then(|i| i.sb.upgrade()).map_or(0, |sb| sb.dev_id)
    } else {
        inode.ok_or(KernelError::NotFound)?.ino
    };

    if is_remove {
        fanotify.remove_mark(mark_flags, mask, target_id);
    } else {
        // ADD (default if no op specified and pathname given)
        fanotify.add_mark(mark_flags, mask, target_id);
    }
    Ok(())
}
