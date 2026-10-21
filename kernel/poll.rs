//! Poll/Select Infrastructure
//!
//! This module implements the core I/O multiplexing mechanism for poll(2),
//! ppoll(2), select(2), and pselect6(2) syscalls.
//!
//! ## Architecture (following Linux fs/select.c)
//!
//! ```text
//! User space: poll(fds, nfds, timeout)
//!        ↓
//! Kernel: Create PollContext for this syscall
//!        ↓
//! Loop: For each fd, call file.poll(&mut PollTable)
//!        ↓
//! Driver: Calls poll_wait() to register on wait queues
//!        ↓
//! If events ready → return immediately
//! Else → sleep until triggered or timeout
//! ```
//!
//! ## Key Components
//!
//! - `PollContext` - Per-syscall state (like Linux poll_wqueues)
//! - `PollTable` - Passed to file->poll() for registration
//! - `poll_wait()` - Called by drivers to register on wait queues
//!
//! ## Reference
//!
//! - `./select-poll.md` - Implementation guide
//! - `./external-linux/fs/select.c` - Linux implementation

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::fs::File;
use crate::task::Tid;
use crate::task::percpu::{WakeMode, try_to_wake_up};
use crate::waitqueue::{WaitEntry, WaitQueue};

// =============================================================================
// Poll Event Masks (from include/uapi/asm-generic/poll.h)
// =============================================================================

/// Data available for reading
pub const POLLIN: u16 = 0x0001;
/// Urgent data for reading (OOB data on sockets)
pub const POLLPRI: u16 = 0x0002;
/// Ready for writing
pub const POLLOUT: u16 = 0x0004;
/// Error condition (output only)
pub const POLLERR: u16 = 0x0008;
/// Hang up (output only)
pub const POLLHUP: u16 = 0x0010;
/// Invalid fd (output only)
pub const POLLNVAL: u16 = 0x0020;
/// Normal data readable (same as POLLIN for most)
pub const POLLRDNORM: u16 = 0x0040;
/// Priority data readable
pub const POLLRDBAND: u16 = 0x0080;
/// Normal data writable (same as POLLOUT for most)
pub const POLLWRNORM: u16 = 0x0100;
/// Priority data writable
pub const POLLWRBAND: u16 = 0x0200;
/// Linux extension: message available
pub const POLLMSG: u16 = 0x0400;
/// Linux extension: peer closed connection
pub const POLLRDHUP: u16 = 0x2000;

/// Default readable events mask
pub const POLL_IN_EVENTS: u16 = POLLIN | POLLRDNORM;
/// Default writable events mask
pub const POLL_OUT_EVENTS: u16 = POLLOUT | POLLWRNORM;
/// Error events (always checked)
pub const POLL_ERR_EVENTS: u16 = POLLERR | POLLHUP;

// =============================================================================
// User-Space Structures (Linux ABI)
// =============================================================================

/// User-space pollfd structure (exact Linux layout)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PollFd {
    /// File descriptor
    pub fd: i32,
    /// Requested events
    pub events: i16,
    /// Returned events
    pub revents: i16,
}

/// fd_set for select(2) - 1024 bits = 128 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdSet {
    pub bits: [u64; 16], // 16 * 64 = 1024 bits
}

impl FdSet {
    /// Create an empty fd_set
    pub const fn new() -> Self {
        Self { bits: [0; 16] }
    }

    /// Check if fd is set
    pub fn is_set(&self, fd: i32) -> bool {
        if !(0..1024).contains(&fd) {
            return false;
        }
        let idx = fd as usize / 64;
        let bit = fd as usize % 64;
        (self.bits[idx] >> bit) & 1 != 0
    }

    /// Set fd
    pub fn set(&mut self, fd: i32) {
        if !(0..1024).contains(&fd) {
            return;
        }
        let idx = fd as usize / 64;
        let bit = fd as usize % 64;
        self.bits[idx] |= 1 << bit;
    }

    /// Clear fd
    pub fn clear(&mut self, fd: i32) {
        if !(0..1024).contains(&fd) {
            return;
        }
        let idx = fd as usize / 64;
        let bit = fd as usize % 64;
        self.bits[idx] &= !(1 << bit);
    }

    /// Clear all
    pub fn zero(&mut self) {
        self.bits = [0; 16];
    }

    /// Count set bits up to nfds
    pub fn count(&self, nfds: i32) -> i32 {
        let mut count = 0;
        for fd in 0..nfds.min(1024) {
            if self.is_set(fd) {
                count += 1;
            }
        }
        count
    }

    /// Get number of bytes needed for nfds
    pub fn bytes_for_nfds(nfds: i32) -> usize {
        if nfds <= 0 {
            return 0;
        }
        // Round up to nearest 8 bytes (64 bits)
        let bits = nfds as usize;
        bits.div_ceil(64) * 8
    }
}

impl Default for FdSet {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Poll Context (Per-Syscall State)
// =============================================================================

/// Per-syscall poll context (like Linux poll_wqueues)
///
/// Holds the polling task's registrations on the wait queues of the polled
/// files (entries pinned on the heap, Linux poll_table_entry, whose wake
/// function `pollwake` flags the context and wakes the poller, until the
/// poll ends) and references to those files, which keep the wait queues
/// alive. Dropping the context removes all registrations.
pub struct PollContext {
    /// Task ID of the polling task
    pub task: Tid,
    /// Set by any registration's wakeup (Linux poll_wqueues.triggered);
    /// boxed: the entries point at it
    triggered: Box<AtomicBool>,
    /// Registered (wait queue, entry) pairs
    entries: Vec<(*const WaitQueue, Pin<Box<WaitEntry>>)>,
    /// Files whose wait queues we registered on (keeps them alive)
    files: Vec<Arc<File>>,
}

/// A poll registration's wakeup (Linux pollwake): flag the context,
/// wake the poller (under the queue's lock; the flag outlives the
/// entry, which the context unlinks before it goes)
fn pollwake(e: &WaitEntry, mode: WakeMode, _key: usize) -> bool {
    // SAFETY: `private` is the context's `triggered` (see above)
    unsafe { &*(e.private as *const AtomicBool) }.store(true, Ordering::Release);
    try_to_wake_up(e.task(), mode)
}

impl PollContext {
    /// Create a new poll context for the current task
    pub fn new(tid: Tid) -> Self {
        Self {
            task: tid,
            triggered: Box::new(AtomicBool::new(false)),
            entries: Vec::new(),
            files: Vec::new(),
        }
    }

    /// A registration was woken since the last `clear_triggered`
    pub fn triggered(&self) -> bool {
        self.triggered.load(Ordering::Acquire)
    }

    /// Forget past wakeups (before a new scan)
    pub fn clear_triggered(&self) {
        self.triggered.store(false, Ordering::Release);
    }

    /// Keep `file` alive for the lifetime of this context (call before
    /// polling it with a registering table)
    pub fn hold_file(&mut self, file: Arc<File>) {
        self.files.push(file);
    }

    /// Register the polling task on `wq`
    fn add_entry(&mut self, wq: &WaitQueue) {
        if self.entries.iter().any(|(q, _)| core::ptr::eq(*q, wq)) {
            return;
        }
        let flag = &*self.triggered as *const AtomicBool as usize;
        let entry = Box::pin(WaitEntry::with_func(Some(pollwake), flag));
        wq.add_wait_queue(entry.as_ref());
        self.entries.push((wq as *const WaitQueue, entry));
    }

    /// Number of registrations
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl Drop for PollContext {
    fn drop(&mut self) {
        for (wq, entry) in self.entries.drain(..) {
            // Safety: the wait queues belong to files in `self.files`,
            // which are still alive (dropped after this loop)
            unsafe { (*wq).remove_wait_queue(entry.as_ref()) };
        }
        self.files.clear();
    }
}

// =============================================================================
// Poll Table (Passed to file->poll())
// =============================================================================

/// Poll table passed to file->poll() method
///
/// Files call `poll_wait()` on this to register interest in wait queues.
/// After poll_wait(), they return a mask of currently ready events.
pub struct PollTable<'a> {
    /// Poll context (holds registrations)
    ctx: &'a mut PollContext,
    /// Event mask of interest (filters wakeups)
    pub key: u32,
    /// Whether to actually register (false after first ready event)
    qproc_enabled: bool,
}

impl<'a> PollTable<'a> {
    /// Create a new poll table
    pub fn new(ctx: &'a mut PollContext) -> Self {
        Self {
            ctx,
            key: 0,
            qproc_enabled: true,
        }
    }

    /// Register interest in a wait queue
    ///
    /// Called by file->poll() implementations. The wait queue will wake
    /// the polling task when events matching `self.key` occur.
    ///
    /// # Arguments
    /// * `wq` - The wait queue to register on
    pub fn poll_wait(&mut self, wq: &WaitQueue) {
        if !self.qproc_enabled {
            return;
        }
        // Wakeups are not filtered by key: the poller re-scans all fds
        self.ctx.add_entry(wq);
    }

    /// Keep `file` alive while registered on its wait queues (no-op once
    /// registration is disabled)
    pub fn hold_file(&mut self, file: &Arc<File>) {
        if self.qproc_enabled {
            self.ctx.hold_file(file.clone());
        }
    }

    /// Disable further registrations
    ///
    /// Called after finding a ready fd to avoid unnecessary registrations.
    pub fn disable(&mut self) {
        self.qproc_enabled = false;
    }

    /// Check if registrations are enabled
    pub fn is_enabled(&self) -> bool {
        self.qproc_enabled
    }

    /// Set the event key for the next poll_wait call
    pub fn set_key(&mut self, events: u16) {
        // Include error/hangup events that are always monitored
        self.key = (events | POLLERR | POLLHUP) as u32;
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert poll events to select category
///
/// Maps POLL* events to read/write/except categories for select().
pub fn poll_to_select(events: u16) -> (bool, bool, bool) {
    let readable = events & (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI | POLLHUP | POLLERR) != 0;
    let writable = events & (POLLOUT | POLLWRNORM | POLLWRBAND | POLLERR) != 0;
    let exceptional = events & (POLLPRI | POLLERR) != 0;
    (readable, writable, exceptional)
}

/// Convert select category to poll events
pub fn select_to_poll(readable: bool, writable: bool, exceptional: bool) -> u16 {
    let mut events = 0u16;
    if readable {
        events |= POLLIN | POLLRDNORM;
    }
    if writable {
        events |= POLLOUT | POLLWRNORM;
    }
    if exceptional {
        events |= POLLPRI;
    }
    events
}

// =============================================================================
// Default Poll Mask
// =============================================================================

/// Default poll mask for regular files
///
/// Regular files are always readable and writable.
pub const DEFAULT_POLLMASK: u16 = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;

/// Default poll mask for directories
///
/// Directories cannot be read/written via read()/write().
pub const DIR_POLLMASK: u16 = POLLERR;
