//! Inotify (inode notification) implementation
//!
//! Provides filesystem event notification via file descriptor, compatible with Linux inotify API.
//!
//! ## Architecture
//!
//! ```text
//! User Process
//!     |
//!     v
//! inotify_init1(flags) -> fd
//!     |
//!     v
//! inotify_add_watch(fd, path, mask) -> wd
//!     |
//!     v
//! read(fd, buf, count) -> inotify_event structures
//! poll(fd) -> POLLIN when events pending
//!     |
//!     v
//! inotify_rm_watch(fd, wd)
//! ```
//!
//! ## Key Features
//!
//! - Watch files and directories for events (access, modify, create, delete, etc.)
//! - Events are queued and consumed via read()
//! - poll/epoll support for integration with event loops
//! - Multiple watches per inotify instance
//! - Watch descriptors (wd) are unique per instance

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::waitqueue::WaitQueue;

// =============================================================================
// Inotify Constants (Linux ABI)
// =============================================================================

/// Inotify event flags - file was accessed
pub const IN_ACCESS: u32 = 0x00000001;
/// File was modified
pub const IN_MODIFY: u32 = 0x00000002;
/// Metadata changed
pub const IN_ATTRIB: u32 = 0x00000004;
/// Writable file was closed
pub const IN_CLOSE_WRITE: u32 = 0x00000008;
/// Unwritable file closed
pub const IN_CLOSE_NOWRITE: u32 = 0x00000010;
/// File was opened
pub const IN_OPEN: u32 = 0x00000020;
/// File was moved from X
pub const IN_MOVED_FROM: u32 = 0x00000040;
/// File was moved to Y
pub const IN_MOVED_TO: u32 = 0x00000080;
/// Subfile was created
pub const IN_CREATE: u32 = 0x00000100;
/// Subfile was deleted
pub const IN_DELETE: u32 = 0x00000200;
/// Self was deleted
pub const IN_DELETE_SELF: u32 = 0x00000400;
/// Self was moved
pub const IN_MOVE_SELF: u32 = 0x00000800;

/// Backing fs was unmounted
pub const IN_UNMOUNT: u32 = 0x00002000;
/// Event queue overflowed
pub const IN_Q_OVERFLOW: u32 = 0x00004000;
/// File was ignored (watch removed)
pub const IN_IGNORED: u32 = 0x00008000;

/// Helper: close events
pub const IN_CLOSE: u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
/// Helper: move events
pub const IN_MOVE: u32 = IN_MOVED_FROM | IN_MOVED_TO;

/// Only watch if path is directory
pub const IN_ONLYDIR: u32 = 0x01000000;
/// Don't follow symlink
pub const IN_DONT_FOLLOW: u32 = 0x02000000;
/// Exclude events on unlinked objects
pub const IN_EXCL_UNLINK: u32 = 0x04000000;
/// Only create watches (error if exists)
pub const IN_MASK_CREATE: u32 = 0x10000000;
/// Add to mask of existing watch
pub const IN_MASK_ADD: u32 = 0x20000000;
/// Event occurred against directory
pub const IN_ISDIR: u32 = 0x40000000;
/// Only send event once
pub const IN_ONESHOT: u32 = 0x80000000;

/// All events user can watch for
pub const IN_ALL_EVENTS: u32 = IN_ACCESS
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_OPEN
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_DELETE
    | IN_CREATE
    | IN_DELETE_SELF
    | IN_MOVE_SELF;

/// inotify_init1 flags
pub mod in_flags {
    /// Set close-on-exec on inotify fd
    pub const IN_CLOEXEC: i32 = 0o2000000;
    /// Set non-blocking on inotify fd
    pub const IN_NONBLOCK: i32 = 0o4000;
}

/// Maximum queued events per instance
const INOTIFY_MAX_QUEUED_EVENTS: usize = 16384;

// =============================================================================
// Inotify Event Structure (Linux ABI)
// =============================================================================

/// inotify_event header - Linux ABI
///
/// Followed by `len` bytes of null-terminated name (if len > 0)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InotifyEventHeader {
    /// Watch descriptor
    pub wd: i32,
    /// Watch mask / event type
    pub mask: u32,
    /// Cookie for rename synchronization
    pub cookie: u32,
    /// Length of name (including padding/nulls)
    pub len: u32,
}

const INOTIFY_EVENT_HEADER_SIZE: usize = core::mem::size_of::<InotifyEventHeader>();

// =============================================================================
// Inotify Watch
// =============================================================================

/// An inotify watch on a specific path
struct InotifyWatch {
    /// Watch descriptor (unique within instance)
    #[allow(dead_code)]
    wd: i32,
    /// Events to watch for
    mask: u32,
    /// Path being watched (for reference)
    #[allow(dead_code)]
    path: String,
    /// Inode number of watched file/dir
    ino: u64,
}

// =============================================================================
// Queued Event
// =============================================================================

/// A queued inotify event
struct QueuedEvent {
    /// Watch descriptor
    wd: i32,
    /// Event mask
    mask: u32,
    /// Cookie for pairing move events
    cookie: u32,
    /// Optional filename (for directory events)
    name: Option<String>,
}

impl QueuedEvent {
    /// Calculate total size of this event when serialized
    fn serialized_size(&self) -> usize {
        let name_len = self.name.as_ref().map(|n| n.len() + 1).unwrap_or(0);
        // Pad to multiple of inotify_event size (16 bytes)
        let padded_len = if name_len > 0 {
            (name_len + 15) & !15
        } else {
            0
        };
        INOTIFY_EVENT_HEADER_SIZE + padded_len
    }
}

// =============================================================================
// Inotify Instance
// =============================================================================

/// Internal inotify state
struct InotifyInner {
    /// Next watch descriptor to allocate
    next_wd: i32,
    /// Active watches: wd -> watch
    watches: BTreeMap<i32, InotifyWatch>,
    /// Queued events
    events: Vec<QueuedEvent>,
    /// Cookie counter for rename events (reserved for future use)
    #[allow(dead_code)]
    next_cookie: u32,
}

/// Inotify instance
pub struct Inotify {
    /// Inner state protected by spinlock
    inner: IrqSpinlock<InotifyInner>,
    /// Wait queue for blocking readers
    wait_queue: WaitQueue,
    /// Unique ID for this instance
    id: u64,
}

/// Global counter for inotify IDs
static NEXT_INOTIFY_ID: AtomicU64 = AtomicU64::new(1);

/// Global cookie counter for rename event pairing
static NEXT_RENAME_COOKIE: AtomicI32 = AtomicI32::new(1);

/// Global inotify registry for event dispatch
static INOTIFY_REGISTRY: IrqSpinlock<Vec<(u64, Weak<Inotify>)>> = IrqSpinlock::new(Vec::new());

impl Inotify {
    /// Create a new inotify instance
    pub fn new() -> Arc<Self> {
        let id = NEXT_INOTIFY_ID.fetch_add(1, Ordering::Relaxed);

        let inotify = Arc::new(Self {
            inner: IrqSpinlock::new(InotifyInner {
                next_wd: 1,
                watches: BTreeMap::new(),
                events: Vec::new(),
                next_cookie: 0,
            }),
            wait_queue: WaitQueue::new(),
            id,
        });

        // Register in global registry
        let weak = Arc::downgrade(&inotify);
        INOTIFY_REGISTRY.lock().push((id, weak));

        inotify
    }

    /// Add a watch on a path
    ///
    /// Returns the watch descriptor on success, or negative errno on error.
    pub fn add_watch(&self, path: &str, mask: u32, ino: u64) -> Result<i32, i32> {
        let mut inner = self.inner.lock();

        // Check if IN_MASK_ADD or IN_MASK_CREATE
        let mask_add = (mask & IN_MASK_ADD) != 0;
        let mask_create = (mask & IN_MASK_CREATE) != 0;

        // Check for existing watch on same inode
        for (wd, watch) in inner.watches.iter_mut() {
            if watch.ino == ino {
                if mask_create {
                    return Err(-17); // EEXIST
                }
                // Update existing watch
                if mask_add {
                    watch.mask |= mask & IN_ALL_EVENTS;
                } else {
                    watch.mask = mask & IN_ALL_EVENTS;
                }
                return Ok(*wd);
            }
        }

        // Create new watch
        let wd = inner.next_wd;
        inner.next_wd += 1;

        let watch = InotifyWatch {
            wd,
            mask: mask & IN_ALL_EVENTS,
            path: String::from(path),
            ino,
        };
        inner.watches.insert(wd, watch);

        Ok(wd)
    }

    /// Remove a watch by descriptor
    ///
    /// Returns 0 on success, negative errno on error.
    pub fn rm_watch(&self, wd: i32) -> Result<(), i32> {
        let mut inner = self.inner.lock();

        if inner.watches.remove(&wd).is_some() {
            // Queue IN_IGNORED event
            if inner.events.len() < INOTIFY_MAX_QUEUED_EVENTS {
                inner.events.push(QueuedEvent {
                    wd,
                    mask: IN_IGNORED,
                    cookie: 0,
                    name: None,
                });
            }
            drop(inner);
            self.wait_queue.wake_all();
            Ok(())
        } else {
            Err(-22) // EINVAL
        }
    }

    /// Queue an event for a specific watch
    pub fn queue_event(&self, wd: i32, mask: u32, cookie: u32, name: Option<String>) {
        let mut inner = self.inner.lock();

        // Check if watch still exists
        if let Some(watch) = inner.watches.get(&wd) {
            // Check if this event type is being watched
            if (watch.mask & mask) != 0 || (mask & (IN_IGNORED | IN_UNMOUNT | IN_Q_OVERFLOW)) != 0 {
                if inner.events.len() < INOTIFY_MAX_QUEUED_EVENTS {
                    inner.events.push(QueuedEvent {
                        wd,
                        mask,
                        cookie,
                        name,
                    });
                } else if inner.events.is_empty()
                    || inner.events.last().map(|e| e.mask) != Some(IN_Q_OVERFLOW)
                {
                    // Queue overflow event
                    inner.events.push(QueuedEvent {
                        wd: -1,
                        mask: IN_Q_OVERFLOW,
                        cookie: 0,
                        name: None,
                    });
                }
            }
        }

        drop(inner);
        self.wait_queue.wake_all();
    }

    /// Check if any events are pending
    fn has_events(&self) -> bool {
        !self.inner.lock().events.is_empty()
    }

    /// Read events from the inotify instance
    pub fn read(&self, buf: &mut [u8], nonblock: bool) -> Result<usize, KernelError> {
        // Buffer must be at least big enough for one event header
        if buf.len() < INOTIFY_EVENT_HEADER_SIZE {
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

                    // Serialize header
                    let name_len = event.name.as_ref().map(|n| n.len() + 1).unwrap_or(0);
                    let padded_len = if name_len > 0 {
                        (name_len + 15) & !15
                    } else {
                        0
                    };

                    let header = InotifyEventHeader {
                        wd: event.wd,
                        mask: event.mask,
                        cookie: event.cookie,
                        len: padded_len as u32,
                    };

                    // Copy header
                    let header_bytes = unsafe {
                        core::slice::from_raw_parts(
                            &header as *const InotifyEventHeader as *const u8,
                            INOTIFY_EVENT_HEADER_SIZE,
                        )
                    };
                    buf[bytes_written..bytes_written + INOTIFY_EVENT_HEADER_SIZE]
                        .copy_from_slice(header_bytes);
                    bytes_written += INOTIFY_EVENT_HEADER_SIZE;

                    // Copy name if present
                    if let Some(name) = event.name {
                        let name_bytes = name.as_bytes();
                        buf[bytes_written..bytes_written + name_bytes.len()]
                            .copy_from_slice(name_bytes);
                        bytes_written += name_bytes.len();
                        // Null terminator
                        buf[bytes_written] = 0;
                        bytes_written += 1;
                        // Padding
                        let padding = padded_len - name_bytes.len() - 1;
                        for i in 0..padding {
                            buf[bytes_written + i] = 0;
                        }
                        bytes_written += padding;
                    }
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

    /// Get the total size of queued events (for FIONREAD ioctl)
    pub fn queued_size(&self) -> usize {
        let inner = self.inner.lock();
        inner.events.iter().map(|e| e.serialized_size()).sum()
    }

    /// Release the inotify instance
    fn release(&self) {
        let mut registry = INOTIFY_REGISTRY.lock();
        registry.retain(|(id, _)| *id != self.id);
    }
}

impl Default for Inotify {
    fn default() -> Self {
        // Note: This creates an unregistered instance - use Inotify::new() instead
        Self {
            inner: IrqSpinlock::new(InotifyInner {
                next_wd: 1,
                watches: BTreeMap::new(),
                events: Vec::new(),
                next_cookie: 0,
            }),
            wait_queue: WaitQueue::new(),
            id: 0,
        }
    }
}

// =============================================================================
// File Operations
// =============================================================================

/// File operations for inotify
pub struct InotifyFileOps {
    inotify: Arc<Inotify>,
}

impl InotifyFileOps {
    /// Create file ops for an inotify instance
    pub fn new(inotify: Arc<Inotify>) -> Self {
        Self { inotify }
    }
}

impl FileOps for InotifyFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        self.inotify.read(buf, nonblock)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        self.inotify.poll(pt)
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        self.inotify.release();
        Ok(())
    }
}

// =============================================================================
// Syscall Interface
// =============================================================================

/// Create a new inotify instance
///
/// # Arguments
/// * `in_flags` - IN_CLOEXEC | IN_NONBLOCK
///
/// # Returns
/// Arc<File> for the new inotify fd
pub fn create_inotify(in_flags: i32) -> Result<Arc<File>, KernelError> {
    let inotify = Inotify::new();

    // Create file operations
    let ops: &'static dyn FileOps = Box::leak(Box::new(InotifyFileOps::new(inotify)));

    // Create dummy dentry for inotify
    let dentry = create_inotify_dentry()?;

    // Determine file flags
    let mut file_flags = flags::O_RDONLY;
    if in_flags & in_flags::IN_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = Arc::new(File::new(dentry, file_flags, ops));
    Ok(file)
}

/// Create a dummy dentry for inotify
fn create_inotify_dentry() -> Result<Arc<Dentry>, KernelError> {
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

    let dentry = Arc::new(Dentry::new_anonymous(String::from("inotify"), Some(inode)));
    Ok(dentry)
}

/// Get the Inotify from a File
pub fn get_inotify(file: &File) -> Option<Arc<Inotify>> {
    file.f_op
        .as_any()
        .downcast_ref::<InotifyFileOps>()
        .map(|ops| Arc::clone(&ops.inotify))
}

/// Generate a unique cookie for rename event pairing
#[allow(dead_code)]
pub fn generate_cookie() -> u32 {
    NEXT_RENAME_COOKIE.fetch_add(1, Ordering::Relaxed) as u32
}

// =============================================================================
// Syscall Handlers
// =============================================================================

/// sys_inotify_init() - create inotify instance (legacy, no flags)
pub fn sys_inotify_init() -> i64 {
    sys_inotify_init1(0)
}

/// sys_inotify_init1(flags) - create inotify instance
pub fn sys_inotify_init1(in_flags: i32) -> i64 {
    use crate::pipe::FD_CLOEXEC;
    use crate::task::fdtable::get_task_fd;
    use crate::task::percpu::current_tid;

    // Validate flags
    let valid_flags = in_flags::IN_CLOEXEC | in_flags::IN_NONBLOCK;
    if in_flags & !valid_flags != 0 {
        return -22; // EINVAL
    }

    // Create inotify file
    let file = match create_inotify(in_flags) {
        Ok(f) => f,
        Err(_) => return -12, // ENOMEM
    };

    // Allocate fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return -24, // EMFILE
    };

    let mut table = fd_table.lock();
    let fd_flags = if in_flags & in_flags::IN_CLOEXEC != 0 {
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

/// sys_inotify_add_watch(fd, pathname, mask) - add watch to inotify instance
pub fn sys_inotify_add_watch(fd: i32, pathname_ptr: u64, mask: u32) -> i64 {
    use crate::arch::Uaccess;
    use crate::task::fdtable::get_task_fd;
    use crate::task::percpu::current_tid;
    use crate::uaccess::strncpy_from_user;

    // Validate mask
    if mask == 0 {
        return -22; // EINVAL
    }

    // IN_MASK_ADD and IN_MASK_CREATE are mutually exclusive
    if (mask & IN_MASK_ADD) != 0 && (mask & IN_MASK_CREATE) != 0 {
        return -22; // EINVAL
    }

    // Get fd table
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return -9, // EBADF
    };

    // Get file
    let file = match fd_table.lock().get(fd) {
        Some(f) => f,
        None => return -9, // EBADF
    };

    // Verify it's an inotify fd
    let inotify = match get_inotify(&file) {
        Some(i) => i,
        None => return -22, // EINVAL
    };

    // Copy pathname from user
    let pathname = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return -14, // EFAULT
    };

    // Resolve path to get inode
    let (ino, is_dir) = match resolve_path_to_ino(&pathname, mask) {
        Ok(info) => info,
        Err(e) => return e,
    };

    // Check IN_ONLYDIR
    if (mask & IN_ONLYDIR) != 0 && !is_dir {
        return -20; // ENOTDIR
    }

    // Add watch
    match inotify.add_watch(&pathname, mask, ino) {
        Ok(wd) => wd as i64,
        Err(e) => e as i64,
    }
}

/// sys_inotify_rm_watch(fd, wd) - remove watch from inotify instance
pub fn sys_inotify_rm_watch(fd: i32, wd: i32) -> i64 {
    use crate::task::fdtable::get_task_fd;
    use crate::task::percpu::current_tid;

    // Get fd table
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return -9, // EBADF
    };

    // Get file
    let file = match fd_table.lock().get(fd) {
        Some(f) => f,
        None => return -9, // EBADF
    };

    // Verify it's an inotify fd
    let inotify = match get_inotify(&file) {
        Some(i) => i,
        None => return -22, // EINVAL
    };

    // Remove watch
    match inotify.rm_watch(wd) {
        Ok(()) => 0,
        Err(e) => e as i64,
    }
}

/// Resolve a path to its inode number
///
/// Returns (ino, is_dir) on success, negative errno on error.
fn resolve_path_to_ino(pathname: &str, mask: u32) -> Result<(u64, bool), i64> {
    use crate::fs::path_ref::Path;
    use crate::fs::{LookupFlags, lookup_path_at};

    // Get current working directory
    let start: Option<Path> = if pathname.starts_with('/') {
        // Absolute path
        None
    } else {
        // Use current working directory
        crate::task::percpu::current_cwd()
    };

    // Set up lookup flags
    let mut lookup_flags = LookupFlags::open();
    if (mask & IN_DONT_FOLLOW) != 0 {
        lookup_flags.follow = false;
    }

    // Lookup path
    let dentry = match lookup_path_at(start, pathname, lookup_flags) {
        Ok(d) => d,
        Err(e) => {
            return Err(match e {
                KernelError::NotFound => -2,          // ENOENT
                KernelError::NotDirectory => -20,    // ENOTDIR
                KernelError::PermissionDenied => -13, // EACCES
                KernelError::TooManySymlinks => -40,  // ELOOP
                _ => -22,                         // EINVAL
            });
        }
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return Err(-2), // ENOENT
    };

    let ino = inode.ino;
    let is_dir = inode.mode().is_dir();

    Ok((ino, is_dir))
}
