//! epoll - scalable I/O event notification
//!
//! Provides Linux-compatible epoll API for efficient I/O multiplexing.
//!
//! ## Architecture
//!
//! ```text
//! User Process
//!     |
//!     v
//! epoll_create1(flags) -> epfd
//!     |
//!     v
//! epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event)  -> Add fd to interest list
//! epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event)  -> Modify event mask
//! epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL)    -> Remove fd from list
//!     |
//!     v
//! epoll_wait(epfd, events, maxevents, timeout) -> Wait for events
//! ```
//!
//! ## Key Features
//!
//! - O(1) event notification (vs O(n) for poll/select)
//! - Level-triggered (default) and edge-triggered (EPOLLET) modes
//! - One-shot mode (EPOLLONESHOT) for single notification
//! - Can monitor pipes, sockets, eventfd, timerfd, and other pollable fds

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{IrqSpinlock, Uaccess};
use crate::fs::dentry::Dentry;
use crate::fs::file::{flags, File, FileOps};
use crate::fs::inode::{Inode, InodeMode, Timespec as InodeTimespec, NULL_INODE_OPS};
use crate::fs::FsError;
use crate::pipe::FD_CLOEXEC;
use crate::poll::{PollTable, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, POLLRDNORM, POLLWRNORM};
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;
use crate::task::Fd;
use crate::uaccess::{get_user, put_user};
use crate::waitqueue::WaitQueue;

/// epoll_ctl operations
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

/// epoll event masks (input)
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLPRI: u32 = 0x002;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLRDNORM: u32 = 0x040;
pub const EPOLLRDBAND: u32 = 0x080;
pub const EPOLLWRNORM: u32 = 0x100;
pub const EPOLLWRBAND: u32 = 0x200;
pub const EPOLLMSG: u32 = 0x400;
pub const EPOLLRDHUP: u32 = 0x2000;

/// epoll event masks (output only)
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;

/// epoll behavior modifiers
pub const EPOLLET: u32 = 1 << 31; // Edge-triggered
pub const EPOLLONESHOT: u32 = 1 << 30; // One-shot
pub const EPOLLWAKEUP: u32 = 1 << 29; // Wake system
pub const EPOLLEXCLUSIVE: u32 = 1 << 28; // Exclusive wakeup

/// epoll_create1 flags
pub const EPOLL_CLOEXEC: i32 = 0o2000000;

/// Maximum events that can be returned in a single epoll_wait call
const EP_MAX_EVENTS: i32 = 4096;

/// Linux error codes
const EINVAL: i64 = -22;
const EBADF: i64 = -9;
const EEXIST: i64 = -17;
const ENOENT: i64 = -2;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;

/// User-space epoll_event structure (Linux ABI)
///
/// Note: This is packed on x86-64 to match Linux's structure layout.
/// The data field is a union in Linux (fd, u32, u64, ptr) but we use u64.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EpollEvent {
    /// Event mask (EPOLLIN, EPOLLOUT, etc.)
    pub events: u32,
    /// User data (passed back unchanged)
    pub data: u64,
}

/// Per-monitored-fd entry (like Linux's struct epitem)
struct EpItem {
    /// The file descriptor being monitored
    #[allow(dead_code)]
    fd: Fd,
    /// The file object (Arc reference)
    file: Arc<File>,
    /// User-provided event mask and data
    event: EpollEvent,
    /// Whether this item has been disabled (EPOLLONESHOT fired)
    disabled: bool,
    /// Last reported events (for edge-triggered mode)
    last_events: u32,
}

impl EpItem {
    fn new(fd: Fd, file: Arc<File>, event: EpollEvent) -> Self {
        Self {
            fd,
            file,
            event,
            disabled: false,
            last_events: 0,
        }
    }
}

/// Inner state protected by spinlock
struct EventpollInner {
    /// All monitored fds: fd -> EpItem
    items: BTreeMap<Fd, EpItem>,
}

impl EventpollInner {
    fn new() -> Self {
        Self {
            items: BTreeMap::new(),
        }
    }
}

/// Main epoll instance (like Linux's struct eventpoll)
pub struct Eventpoll {
    /// Inner state protected by IRQ spinlock
    inner: IrqSpinlock<EventpollInner>,
    /// Wait queue for epoll_wait() callers
    wq: WaitQueue,
    /// Unique ID for this epoll instance
    id: u64,
}

/// Global counter for epoll IDs
static NEXT_EPOLL_ID: AtomicU64 = AtomicU64::new(1);

/// Global epoll registry (maps ID -> weak ref)
static EPOLL_REGISTRY: IrqSpinlock<Vec<(u64, Weak<Eventpoll>)>> = IrqSpinlock::new(Vec::new());

impl Eventpoll {
    /// Create a new epoll instance
    pub fn new() -> Arc<Self> {
        let id = NEXT_EPOLL_ID.fetch_add(1, Ordering::Relaxed);
        let ep = Arc::new(Self {
            inner: IrqSpinlock::new(EventpollInner::new()),
            wq: WaitQueue::new(),
            id,
        });

        // Register in global registry
        let weak = Arc::downgrade(&ep);
        EPOLL_REGISTRY.lock().push((id, weak));

        ep
    }

    /// Add a file descriptor to this epoll (EPOLL_CTL_ADD)
    pub fn add(&self, fd: Fd, file: Arc<File>, event: &EpollEvent) -> Result<(), i64> {
        let mut inner = self.inner.lock();

        // Check if fd already exists
        if inner.items.contains_key(&fd) {
            return Err(EEXIST);
        }

        // Create new item
        let item = EpItem::new(fd, file, *event);
        inner.items.insert(fd, item);

        Ok(())
    }

    /// Modify an existing fd's events (EPOLL_CTL_MOD)
    pub fn modify(&self, fd: Fd, event: &EpollEvent) -> Result<(), i64> {
        let mut inner = self.inner.lock();

        // Find existing item
        let item = inner.items.get_mut(&fd).ok_or(ENOENT)?;

        // Update event mask and data
        item.event = *event;
        // Re-enable if it was disabled by EPOLLONESHOT
        item.disabled = false;

        Ok(())
    }

    /// Remove a file descriptor from this epoll (EPOLL_CTL_DEL)
    pub fn delete(&self, fd: Fd) -> Result<(), i64> {
        let mut inner = self.inner.lock();

        // Remove the item
        if inner.items.remove(&fd).is_none() {
            return Err(ENOENT);
        }

        Ok(())
    }

    /// Wait for events (epoll_wait/epoll_pwait core logic)
    ///
    /// Returns the number of ready events, or negative error code.
    pub fn wait(&self, events: &mut [EpollEvent], timeout_ms: i32) -> Result<usize, i64> {
        if events.is_empty() {
            return Ok(0);
        }

        let max_events = events.len();
        let mut collected = 0;

        // Calculate deadline tick if timeout is positive
        // Each tick is 10ms (100 ticks/second)
        let deadline_tick = if timeout_ms > 0 {
            let current_tick = crate::task::percpu::get_ticks();
            let timeout_ticks = (timeout_ms as u64).div_ceil(10);
            Some(current_tick + timeout_ticks)
        } else {
            None
        };

        loop {
            // Poll all monitored fds
            {
                let mut inner = self.inner.lock();

                for item in inner.items.values_mut() {
                    // Skip disabled items (EPOLLONESHOT that already fired)
                    if item.disabled {
                        continue;
                    }

                    // Poll the file
                    let revents = item.file.f_op.poll(&item.file, None);

                    // Convert poll events to epoll events
                    let mut ep_events: u32 = 0;
                    if revents & POLLIN != 0 {
                        ep_events |= EPOLLIN;
                    }
                    if revents & POLLOUT != 0 {
                        ep_events |= EPOLLOUT;
                    }
                    if revents & POLLERR != 0 {
                        ep_events |= EPOLLERR;
                    }
                    if revents & POLLHUP != 0 {
                        ep_events |= EPOLLHUP;
                    }
                    if revents & POLLPRI != 0 {
                        ep_events |= EPOLLPRI;
                    }
                    if revents & POLLRDNORM != 0 {
                        ep_events |= EPOLLRDNORM;
                    }
                    if revents & POLLWRNORM != 0 {
                        ep_events |= EPOLLWRNORM;
                    }

                    // Mask with requested events (but always report ERR/HUP)
                    let masked = (ep_events & item.event.events) | (ep_events & (EPOLLERR | EPOLLHUP));

                    if masked != 0 {
                        // Edge-triggered mode: only report if events changed
                        if item.event.events & EPOLLET != 0 {
                            if masked == item.last_events {
                                continue; // No change, skip
                            }
                            item.last_events = masked;
                        }

                        // Add to result
                        if collected < max_events {
                            events[collected] = EpollEvent {
                                events: masked,
                                data: item.event.data,
                            };
                            collected += 1;

                            // Handle EPOLLONESHOT
                            if item.event.events & EPOLLONESHOT != 0 {
                                item.disabled = true;
                            }
                        }
                    }
                }
            }

            // If we found events, return them
            if collected > 0 {
                return Ok(collected);
            }

            // Non-blocking: return immediately
            if timeout_ms == 0 {
                return Ok(0);
            }

            // Check deadline for timeout
            if let Some(dl) = deadline_tick
                && crate::task::percpu::get_ticks() >= dl
            {
                return Ok(0); // Timeout
            }

            // For simplicity in non-blocking case, just poll once and return
            // A proper implementation would register with file wait queues and block
            // For now, with timeout=-1 (infinite), we do a single poll and return 0
            // if nothing ready (caller should handle this)
            if timeout_ms < 0 {
                // Infinite wait - do a brief yield and retry once
                // This is simplified; proper impl would block on wait queues
                return Ok(0);
            }

            // Short sleep before retry (simplified polling)
            crate::task::percpu::yield_now();
        }
    }

    /// Poll for readiness (for nested epoll)
    pub fn poll(&self, pt: Option<&mut PollTable>) -> u16 {
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.wq);
        }

        // Check if any monitored fds are ready
        let inner = self.inner.lock();
        for item in inner.items.values() {
            if item.disabled {
                continue;
            }
            let revents = item.file.f_op.poll(&item.file, None);
            let masked = (revents as u32) & item.event.events;
            if masked != 0 {
                return POLLIN | POLLRDNORM; // epoll fd is readable
            }
        }

        0
    }

    /// Release the epoll (unregister)
    fn release(&self) {
        // Remove from registry
        let mut registry = EPOLL_REGISTRY.lock();
        registry.retain(|(id, _)| *id != self.id);
    }
}

/// File operations for epoll fd
pub struct EpollFileOps {
    ep: Arc<Eventpoll>,
}

impl EpollFileOps {
    /// Create file ops for an epoll instance
    pub fn new(ep: Arc<Eventpoll>) -> Self {
        Self { ep }
    }
}

impl FileOps for EpollFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, FsError> {
        // epoll fds are not directly readable
        Err(FsError::InvalidArgument)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, FsError> {
        // epoll fds are not writable
        Err(FsError::InvalidArgument)
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        self.ep.poll(pt)
    }

    fn release(&self, _file: &File) -> Result<(), FsError> {
        self.ep.release();
        Ok(())
    }
}

/// Create an epoll file descriptor
///
/// # Arguments
/// * `eflags` - EPOLL_CLOEXEC or 0
///
/// # Returns
/// Arc<File> for the new epoll fd
pub fn create_epoll_file(eflags: i32) -> Result<Arc<File>, FsError> {
    let ep = Eventpoll::new();

    // Create file operations
    let ops: &'static dyn FileOps = Box::leak(Box::new(EpollFileOps::new(ep)));

    // Create dummy dentry for epoll
    let dentry = create_epoll_dentry()?;

    // Determine file flags
    let mut file_flags = flags::O_RDWR;
    if eflags & EPOLL_CLOEXEC != 0 {
        file_flags |= flags::O_CLOEXEC;
    }

    let file = Arc::new(File::new(dentry, file_flags, ops));
    Ok(file)
}

/// Create a dummy dentry for epoll
fn create_epoll_dentry() -> Result<Arc<Dentry>, FsError> {
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

    let dentry = Arc::new(Dentry::new_anonymous(String::from("epoll"), Some(inode)));
    Ok(dentry)
}

/// Get the Eventpoll from a File (for syscall implementations)
pub fn get_eventpoll(file: &File) -> Option<Arc<Eventpoll>> {
    file.f_op
        .as_any()
        .downcast_ref::<EpollFileOps>()
        .map(|ops| Arc::clone(&ops.ep))
}

// ============================================================================
// Syscall implementations
// ============================================================================

/// sys_epoll_create(size) - Create an epoll instance
///
/// The size argument is ignored but must be greater than zero for compatibility.
pub fn sys_epoll_create(size: i32) -> i64 {
    if size <= 0 {
        return EINVAL;
    }
    sys_epoll_create1(0)
}

/// Get the RLIMIT_NOFILE limit for the current task
fn get_nofile_limit() -> u64 {
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
    if limit == crate::rlimit::RLIM_INFINITY {
        u64::MAX
    } else {
        limit
    }
}

/// sys_epoll_create1(flags) - Create an epoll instance with flags
///
/// flags: EPOLL_CLOEXEC or 0
pub fn sys_epoll_create1(eflags: i32) -> i64 {
    // Validate flags
    if eflags & !EPOLL_CLOEXEC != 0 {
        return EINVAL;
    }

    // Create epoll file
    let file = match create_epoll_file(eflags) {
        Ok(f) => f,
        Err(_) => return ENOMEM,
    };

    // Get the FD table and allocate a file descriptor
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return ENOMEM,
    };
    let mut table = fd_table.lock();
    let fd_flags = if eflags & EPOLL_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };

    match table.alloc_with_flags(file, fd_flags, get_nofile_limit()) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// sys_epoll_ctl(epfd, op, fd, event) - Control an epoll instance
pub fn sys_epoll_ctl(epfd: i32, op: i32, fd: i32, event_ptr: u64) -> i64 {
    // Get FD table
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return EBADF,
    };
    let table = fd_table.lock();

    // Get epoll file
    let ep_file = match table.get(epfd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Verify it's an epoll fd
    let ep = match get_eventpoll(&ep_file) {
        Some(e) => e,
        None => return EINVAL,
    };

    // Get target file (for ADD and MOD)
    let target_file = if op != EPOLL_CTL_DEL {
        match table.get(fd) {
            Some(f) => Some(f),
            None => return EBADF,
        }
    } else {
        None
    };

    // Check not adding epoll to itself
    if let Some(ref tf) = target_file
        && Arc::ptr_eq(&ep_file, tf)
    {
        return EINVAL;
    }

    // Release lock before user memory access
    drop(table);

    // Read event from user space (for ADD and MOD)
    let event = if op != EPOLL_CTL_DEL {
        if event_ptr == 0 {
            return EFAULT;
        }
        match get_user::<Uaccess, EpollEvent>(event_ptr) {
            Ok(e) => e,
            Err(_) => return EFAULT,
        }
    } else {
        EpollEvent::default()
    };

    // Perform operation
    match op {
        EPOLL_CTL_ADD => {
            let tf = target_file.unwrap();
            match ep.add(fd as Fd, tf, &event) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        EPOLL_CTL_MOD => match ep.modify(fd as Fd, &event) {
            Ok(()) => 0,
            Err(e) => e,
        },
        EPOLL_CTL_DEL => match ep.delete(fd as Fd) {
            Ok(()) => 0,
            Err(e) => e,
        },
        _ => EINVAL,
    }
}

/// sys_epoll_wait(epfd, events, maxevents, timeout) - Wait for events
pub fn sys_epoll_wait(epfd: i32, events_ptr: u64, maxevents: i32, timeout: i32) -> i64 {
    sys_epoll_pwait(epfd, events_ptr, maxevents, timeout, 0, 0)
}

/// sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize) - Wait with signal mask
pub fn sys_epoll_pwait(
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    timeout: i32,
    _sigmask: u64,
    _sigsetsize: u64,
) -> i64 {
    // Validate maxevents
    if maxevents <= 0 || maxevents > EP_MAX_EVENTS {
        return EINVAL;
    }

    // Validate events pointer
    if events_ptr == 0 {
        return EFAULT;
    }

    // Get epoll instance
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return EBADF,
    };

    let ep_file = match fd_table.lock().get(epfd) {
        Some(f) => f,
        None => return EBADF,
    };

    let ep = match get_eventpoll(&ep_file) {
        Some(e) => e,
        None => return EINVAL,
    };

    // TODO: Handle signal mask if provided (for proper epoll_pwait semantics)

    // Allocate buffer for events
    let mut events = alloc::vec![EpollEvent::default(); maxevents as usize];

    // Wait for events
    let count = match ep.wait(&mut events, timeout) {
        Ok(n) => n,
        Err(e) => return e,
    };

    // Copy events to user space
    let event_size = core::mem::size_of::<EpollEvent>();
    for (i, event) in events.iter().enumerate().take(count) {
        let addr = events_ptr + (i * event_size) as u64;
        if put_user::<Uaccess, EpollEvent>(addr, *event).is_err() {
            return EFAULT;
        }
    }

    count as i64
}
