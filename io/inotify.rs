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

use crate::util::kalloc::try_arc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicI64, Ordering};

use crate::arch::IrqSpinlock;
use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, RwFlags, flags, stream_rw};
use crate::fs::iov_iter::IovDest;
use crate::io::fasync::{FasyncList, POLL_IN, fasync_helper, kill_fasync};
use crate::io::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::sync::spin::Mutex;
use crate::sync::waitqueue::WaitQueue;
use crate::util::pod::IntoBytes;

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

crate::pod!(InotifyEventHeader {
    wd,
    mask,
    cookie,
    len
});

const INOTIFY_EVENT_HEADER_SIZE: usize = core::mem::size_of::<InotifyEventHeader>();

// =============================================================================
// Inotify Watch
// =============================================================================

/// An inotify watch on a specific path
struct InotifyWatch {
    /// Watch descriptor (unique within instance)
    #[expect(dead_code)]
    wd: i32,
    /// Events to watch for
    mask: u32,
    /// Path being watched (for reference)
    #[expect(dead_code)]
    path: crate::fs::name::FileName,
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
    /// Bytes of the name field: the name, its NUL and padding to a
    /// multiple of the header size (16 bytes); 0 without a name
    fn name_field_len(&self) -> usize {
        self.name.as_ref().map_or(0, |n| (n.len() + 1 + 15) & !15)
    }

    /// Calculate total size of this event when serialized
    fn serialized_size(&self) -> usize {
        INOTIFY_EVENT_HEADER_SIZE + self.name_field_len()
    }

    /// Copy the event out whole (Linux copy_event_to_user): EFAULT if
    /// a fault cuts it short
    fn copy_out(&self, to: &mut IovDest<'_>) -> Result<usize, KernelError> {
        let len = self.name_field_len();
        let header = InotifyEventHeader {
            wd: self.wd,
            mask: self.mask,
            cookie: self.cookie,
            len: len as u32,
        };
        to.copy_to_full(header.as_bytes())?;
        if let Some(name) = &self.name {
            to.copy_to_full(name.as_bytes())?;
            let pad = len - name.len();
            if to.zero(pad)? != pad {
                return Err(KernelError::BadAddress);
            }
        }
        Ok(INOTIFY_EVENT_HEADER_SIZE + len)
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
    #[expect(dead_code)]
    next_cookie: u32,
}

impl InotifyInner {
    /// Change the existing watch on `ino`, if any: its result (EEXIST
    /// for IN_MASK_CREATE; IN_MASK_ADD adds to the mask, else replaces)
    fn update_watch(&mut self, mask: u32, ino: u64) -> Option<Result<i32, i32>> {
        let (wd, watch) = self.watches.iter_mut().find(|(_, w)| w.ino == ino)?;
        if mask & IN_MASK_CREATE != 0 {
            return Some(Err(KernelError::AlreadyExists.to_errno_neg()));
        }
        if mask & IN_MASK_ADD != 0 {
            watch.mask |= mask & IN_ALL_EVENTS;
        } else {
            watch.mask = mask & IN_ALL_EVENTS;
        }
        Some(Ok(*wd))
    }

    /// A free watch descriptor, cyclically in 1..=INT_MAX from the last
    /// one handed out (Linux idr_alloc_cyclic(idr, mark, 1, 0))
    fn alloc_wd(&mut self) -> Option<i32> {
        let next = |wd: i32| if wd == i32::MAX { 1 } else { wd + 1 };
        let mut wd = self.next_wd;
        for _ in 0..=self.watches.len() {
            if !self.watches.contains_key(&wd) {
                self.next_wd = next(wd);
                return Some(wd);
            }
            wd = next(wd);
        }
        None
    }
}

impl Drop for Inotify {
    /// The group's watches go with it (Linux inotify_free_mark)
    fn drop(&mut self) {
        let n = self.inner.lock().watches.len();
        watch_uncharge(self.uid, n);
    }
}

/// Approximate cost of one watch in Linux (INOTIFY_WATCH_COST: an
/// inotify_inode_mark and two inodes, about 1.3 KB on x86-64), for the
/// default max_user_watches
const INOTIFY_WATCH_COST: u64 = 1320;

/// fs.inotify.max_user_watches (Linux ucount_max[UCOUNT_INOTIFY_WATCHES]);
/// negative until first used, then the default or the value written
static MAX_USER_WATCHES: AtomicI64 = AtomicI64::new(-1);

/// The watch limit per user: by default 1% of RAM in watches, within
/// 8192..=1048576 (Linux inotify_user_setup)
fn max_user_watches() -> i64 {
    let v = MAX_USER_WATCHES.load(Ordering::Relaxed);
    if v >= 0 {
        return v;
    }
    let ram = crate::FRAME_ALLOCATOR.stats().total_bytes;
    let dflt = (ram / 100 / INOTIFY_WATCH_COST).clamp(8192, 1_048_576) as i64;
    match MAX_USER_WATCHES.compare_exchange(-1, dflt, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => dflt,
        Err(cur) => cur,
    }
}

/// Each user's watches (Linux UCOUNT_INOTIFY_WATCHES ucounts); a leaf,
/// never taken under a group's `inner` lock
static USER_WATCHES: Mutex<BTreeMap<u32, i64>> = Mutex::new(BTreeMap::new());

/// Charge one watch to `uid`: ENOSPC at max_user_watches (Linux
/// inc_inotify_watches -> inc_ucount)
fn watch_charge(uid: u32) -> Result<(), KernelError> {
    let max = max_user_watches();
    let mut users = USER_WATCHES.lock();
    let n = users.entry(uid).or_insert(0);
    if *n >= max {
        if *n == 0 {
            users.remove(&uid);
        }
        return Err(KernelError::NoSpace);
    }
    *n += 1;
    Ok(())
}

/// Return `n` watches' charge to `uid`
fn watch_uncharge(uid: u32, n: usize) {
    if n == 0 {
        return;
    }
    let mut users = USER_WATCHES.lock();
    if let Some(c) = users.get_mut(&uid) {
        *c = c.saturating_sub(n as i64);
        if *c == 0 {
            users.remove(&uid);
        }
    }
}

/// /proc/sys/fs/inotify/max_user_watches (0644; Linux
/// proc_doulongvec_minmax, 0..LONG_MAX)
pub static INOTIFY_CTLS: &[crate::sysctl::Ctl] = &[crate::sysctl::Ctl {
    path: "fs/inotify/max_user_watches",
    mode: 0o644,
    show: || alloc::vec![max_user_watches()],
    store: |v| {
        crate::sysctl::range(v[0], 0, i64::MAX)?;
        MAX_USER_WATCHES.store(v[0], Ordering::Relaxed);
        Ok(())
    },
    text: None,
}];

/// Inotify instance
pub struct Inotify {
    /// Inner state protected by spinlock
    inner: IrqSpinlock<InotifyInner>,
    /// The creator's euid, charged for each watch (Linux
    /// group->inotify_data.ucounts)
    uid: u32,
    /// Wait queue for blocking readers
    wait_queue: WaitQueue,
    /// O_ASYNC files (Linux group->fsn_fa)
    fasync: FasyncList,
}

/// Global cookie counter for rename event pairing
static NEXT_RENAME_COOKIE: AtomicI32 = AtomicI32::new(1);

impl Inotify {
    /// Create a new inotify instance
    pub fn new() -> Result<Arc<Self>, KernelError> {
        try_arc(Self {
            inner: IrqSpinlock::new(InotifyInner {
                next_wd: 1,
                watches: BTreeMap::new(),
                events: Vec::new(),
                next_cookie: 0,
            }),
            uid: crate::task::percpu::current_cred().euid,
            wait_queue: WaitQueue::new(),
            fasync: FasyncList::new(),
        })
    }

    /// Add a watch on a path
    ///
    /// Returns the watch descriptor on success, or negative errno on error.
    pub fn add_watch(&self, path: &[u8], mask: u32, ino: u64) -> Result<i32, i32> {
        if let Some(r) = self.inner.lock().update_watch(mask, ino) {
            return r;
        }
        // A new watch: charged to the creator first (ENOSPC past
        // max_user_watches), outside the group's lock
        watch_charge(self.uid).map_err(|e| e.to_errno_neg())?;
        let mut inner = self.inner.lock();
        if let Some(r) = inner.update_watch(mask, ino) {
            // Another thread added this inode meanwhile
            drop(inner);
            watch_uncharge(self.uid, 1);
            return r;
        }
        let Some(wd) = inner.alloc_wd() else {
            drop(inner);
            watch_uncharge(self.uid, 1);
            return Err(KernelError::NoSpace.to_errno_neg());
        };
        let watch = InotifyWatch {
            wd,
            mask: mask & IN_ALL_EVENTS,
            path: path.into(),
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
            let uid = self.uid;
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
            watch_uncharge(uid, 1);
            self.wait_queue.wake_all();
            Ok(())
        } else {
            Err(-22) // EINVAL
        }
    }

    /// Queue an event for a specific watch
    pub fn queue_event(&self, wd: i32, mask: u32, cookie: u32, name: Option<String>) {
        let mut queued = false;
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
                queued = true;
            }
        }

        drop(inner);
        self.wait_queue.wake_all();
        // Linux fsnotify_insert_event, with the queue lock dropped
        if queued {
            kill_fasync(&self.fasync, crate::signal::SIGIO, POLL_IN);
        }
    }

    /// Check if any events are pending
    fn has_events(&self) -> bool {
        !self.inner.lock().events.is_empty()
    }

    /// The oldest event if it fits in `room` bytes (EINVAL if not),
    /// waiting for one unless `nonblock` (Linux get_one_event)
    fn get_event(&self, room: usize, nonblock: bool) -> Result<QueuedEvent, KernelError> {
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

    /// Read events into `to` (Linux inotify_read): each is taken off
    /// the queue under the lock and copied out after it. Blocks only
    /// while nothing was read; a first event too big for the buffer is
    /// EINVAL. A fault loses the event and is EFAULT even after earlier
    /// events were copied (Linux).
    pub fn read(&self, to: &mut IovDest<'_>, nonblock: bool) -> Result<usize, KernelError> {
        // Buffer must be at least big enough for one event header
        if to.len() < INOTIFY_EVENT_HEADER_SIZE {
            return Err(KernelError::InvalidArgument);
        }
        let mut done = 0;
        loop {
            let event = match self.get_event(to.len(), nonblock || done > 0) {
                Ok(e) => e,
                Err(_) if done > 0 => return Ok(done),
                Err(e) => return Err(e),
            };
            done += event.copy_out(to)?;
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

    /// Get the total size of queued events (for FIONREAD ioctl)
    pub fn queued_size(&self) -> usize {
        let inner = self.inner.lock();
        inner.events.iter().map(|e| e.serialized_size()).sum()
    }
}

// =============================================================================
// File Operations
// =============================================================================

/// File operations for inotify
pub struct InotifyFileOps;

static INOTIFY_FOPS: InotifyFileOps = InotifyFileOps;

impl FileOps for InotifyFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// Linux fsnotify_fasync: the group's list; a failure is EIO
    fn fasync(&self, file: &File, fd: i32, on: bool) -> Option<Result<(), KernelError>> {
        let g = match file.private_ref::<Inotify>() {
            Some(g) => g,
            None => return Some(Err(KernelError::BadFd)),
        };
        Some(
            fasync_helper(&g.fasync, file, fd, on)
                .map(|_| ())
                .map_err(|_| KernelError::Io),
        )
    }

    /// FIONREAD: the bytes a read would return now (Linux inotify_ioctl)
    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let g = file.private_ref::<Inotify>().ok_or(KernelError::BadFd)?;
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
        let inotify = file.private_ref::<Inotify>().ok_or(KernelError::BadFd)?;
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        inotify.read(to, nonblock)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Some(inotify) = file.private_ref::<Inotify>() else {
            return crate::io::poll::POLLERR;
        };
        inotify.poll(pt)
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
    let inotify = Inotify::new()?;

    // Create dummy dentry for inotify

    // Determine file flags
    let mut file_flags = flags::O_RDONLY;
    if in_flags & in_flags::IN_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file =
        crate::fs::anon_inodes::anon_inode_getfile("inotify", &INOTIFY_FOPS, inotify, file_flags)?;
    Ok(file)
}

/// Get the Inotify from a File
pub fn get_inotify(file: &File) -> Option<Arc<Inotify>> {
    file.private_arc::<Inotify>()
}

/// Generate a unique cookie for rename event pairing
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
    use crate::io::pipe::FD_CLOEXEC;
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

/// sys_inotify_add_watch(fd, pathname, mask) - add watch to inotify instance
pub fn sys_inotify_add_watch(fd: i32, pathname_ptr: u64, mask: u32) -> i64 {
    use crate::task::fdtable::get_task_fd;
    use crate::task::percpu::current_tid;

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
    let pathname = match crate::fs::namei::getname(pathname_ptr, false) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
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
        Ok(wd) => i64::from(wd),
        Err(e) => i64::from(e),
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
        Err(e) => i64::from(e),
    }
}

/// Resolve a path to its inode number
///
/// Returns (ino, is_dir) on success, negative errno on error.
fn resolve_path_to_ino(pathname: &[u8], mask: u32) -> Result<(u64, bool), i64> {
    use crate::fs::path_ref::Path;
    use crate::fs::{LookupFlags, lookup_path_at};

    // Get current working directory
    let start: Option<Path> = if pathname.starts_with(b"/") {
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
        // Any lookup error as is (Linux user_path_at)
        Err(e) => return Err(e.sysret()),
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return Err(-2), // ENOENT
    };

    // inotify_find_inode: the watched inode must be readable
    if let Err(e) = crate::fs::dac::permission(&inode, crate::fs::MAY_READ) {
        return Err(e.sysret());
    }

    let ino = inode.ino;
    let is_dir = inode.mode().is_dir();

    Ok((ino, is_dir))
}
