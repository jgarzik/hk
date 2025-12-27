//! Timer file descriptor (timerfd) implementation
//!
//! Provides file descriptor-based timers compatible with Linux timerfd API.
//!
//! ## Architecture
//!
//! ```text
//! User Process
//!     |
//!     v
//! timerfd_create() -> fd
//!     |
//!     v
//! timerfd_settime(fd, ...)  -> Arms timer
//!     |
//!     v
//! read(fd) -> Blocks until timer fires, returns expiration count
//! ```
//!
//! ## Key Features
//!
//! - One-shot and periodic timers
//! - Blocking and non-blocking reads
//! - poll() support for integration with select/poll/epoll
//! - CLOCK_REALTIME and CLOCK_MONOTONIC support

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::time::{ClockId, TIMEKEEPER};
use crate::time_syscall::LinuxTimespec;
use crate::timer::{TimerHandle, timer_add, timer_del};
use crate::waitqueue::WaitQueue;

/// Timerfd create flags
pub mod tfd_flags {
    /// Set close-on-exec flag
    pub const TFD_CLOEXEC: i32 = 0o2000000;
    /// Set non-blocking flag
    pub const TFD_NONBLOCK: i32 = 0o4000;
}

/// Timerfd settime flags
pub mod tfd_timer_flags {
    /// Time value is absolute
    pub const TFD_TIMER_ABSTIME: i32 = 1;
    /// Cancel timer if clock changes (not implemented)
    pub const TFD_TIMER_CANCEL_ON_SET: i32 = 2;
}

/// Linux itimerspec structure
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ITimerSpec {
    /// Interval for periodic timer (0 = one-shot)
    pub it_interval: LinuxTimespec,
    /// Initial expiration time
    pub it_value: LinuxTimespec,
}

impl ITimerSpec {
    /// Check if this timer spec represents a disarmed timer
    pub fn is_disarmed(&self) -> bool {
        self.it_value.tv_sec == 0 && self.it_value.tv_nsec == 0
    }

    /// Convert it_value to nanoseconds
    pub fn value_to_ns(&self) -> u64 {
        if self.it_value.tv_sec < 0 {
            return 0;
        }
        self.it_value.tv_sec as u64 * 1_000_000_000 + self.it_value.tv_nsec as u64
    }

    /// Convert it_interval to nanoseconds
    pub fn interval_to_ns(&self) -> u64 {
        if self.it_interval.tv_sec < 0 {
            return 0;
        }
        self.it_interval.tv_sec as u64 * 1_000_000_000 + self.it_interval.tv_nsec as u64
    }

    /// Create from nanosecond values
    pub fn from_ns(value_ns: u64, interval_ns: u64) -> Self {
        Self {
            it_value: LinuxTimespec {
                tv_sec: (value_ns / 1_000_000_000) as i64,
                tv_nsec: (value_ns % 1_000_000_000) as i64,
            },
            it_interval: LinuxTimespec {
                tv_sec: (interval_ns / 1_000_000_000) as i64,
                tv_nsec: (interval_ns % 1_000_000_000) as i64,
            },
        }
    }
}

/// Internal timerfd state
struct TimerfdInner {
    /// Clock ID (CLOCK_REALTIME or CLOCK_MONOTONIC)
    clockid: i32,
    /// Next expiration time (absolute monotonic ns, 0 if disarmed)
    expires_ns: u64,
    /// Interval for periodic timers (0 = one-shot)
    interval_ns: u64,
    /// Number of expirations since last read
    ticks: u64,
    /// Handle to the timer in the timer subsystem
    timer_handle: TimerHandle,
    /// settime flags (TFD_TIMER_ABSTIME, etc.)
    settime_flags: i32,
}

impl TimerfdInner {
    fn new(clockid: i32) -> Self {
        Self {
            clockid,
            expires_ns: 0,
            interval_ns: 0,
            ticks: 0,
            timer_handle: TimerHandle::NULL,
            settime_flags: 0,
        }
    }
}

/// Timerfd structure
pub struct Timerfd {
    /// Inner state protected by IRQ spinlock
    inner: IrqSpinlock<TimerfdInner>,
    /// Wait queue for blocking reads
    wait_queue: WaitQueue,
    /// Unique ID for this timerfd (used as timer callback data)
    id: u64,
}

/// Global counter for timerfd IDs
static NEXT_TIMERFD_ID: AtomicU64 = AtomicU64::new(1);

/// Global timerfd registry (maps ID -> weak ref)
/// This allows the timer callback to find the timerfd
static TIMERFD_REGISTRY: IrqSpinlock<alloc::vec::Vec<(u64, Weak<Timerfd>)>> =
    IrqSpinlock::new(alloc::vec::Vec::new());

impl Timerfd {
    /// Create a new timerfd
    pub fn new(clockid: i32) -> Arc<Self> {
        let id = NEXT_TIMERFD_ID.fetch_add(1, Ordering::Relaxed);
        let timerfd = Arc::new(Self {
            inner: IrqSpinlock::new(TimerfdInner::new(clockid)),
            wait_queue: WaitQueue::new(),
            id,
        });

        // Register in global registry
        let weak = Arc::downgrade(&timerfd);
        TIMERFD_REGISTRY.lock().push((id, weak));

        timerfd
    }

    /// Get current monotonic time in nanoseconds
    fn now_ns() -> u64 {
        let ts = TIMEKEEPER.read(ClockId::Monotonic, TIMEKEEPER.get_read_cycles());
        ts.sec as u64 * 1_000_000_000 + ts.nsec as u64
    }

    /// Arm the timer
    ///
    /// # Arguments
    /// * `new_value` - New timer specification
    /// * `flags` - TFD_TIMER_ABSTIME for absolute time
    ///
    /// # Returns
    /// Previous timer value
    pub fn settime(self: &Arc<Self>, new_value: &ITimerSpec, flags: i32) -> ITimerSpec {
        let mut inner = self.inner.lock();

        // Save old value
        let old_value = self.get_current_value_locked(&inner);

        // Cancel existing timer if any
        if inner.timer_handle.is_valid() {
            timer_del(inner.timer_handle);
            inner.timer_handle = TimerHandle::NULL;
        }

        // Reset ticks
        inner.ticks = 0;
        inner.settime_flags = flags;

        // Check if disarming
        if new_value.is_disarmed() {
            inner.expires_ns = 0;
            inner.interval_ns = 0;
            return old_value;
        }

        // Calculate expiration time
        let value_ns = new_value.value_to_ns();
        inner.interval_ns = new_value.interval_to_ns();

        let expires_ns = if flags & tfd_timer_flags::TFD_TIMER_ABSTIME != 0 {
            // Absolute time - convert to monotonic if needed
            if inner.clockid == 0 {
                // CLOCK_REALTIME - need to convert to monotonic
                // For simplicity, we assume realtime ~= monotonic + offset
                // A proper implementation would handle clock jumps
                value_ns
            } else {
                // CLOCK_MONOTONIC - use directly
                value_ns
            }
        } else {
            // Relative time
            Self::now_ns() + value_ns
        };

        inner.expires_ns = expires_ns;

        // Register timer callback
        inner.timer_handle = timer_add(expires_ns, inner.interval_ns, timerfd_callback, self.id);

        old_value
    }

    /// Get current timer value
    pub fn gettime(&self) -> ITimerSpec {
        let inner = self.inner.lock();
        self.get_current_value_locked(&inner)
    }

    /// Get current value while holding the lock
    fn get_current_value_locked(&self, inner: &TimerfdInner) -> ITimerSpec {
        if inner.expires_ns == 0 {
            return ITimerSpec::default();
        }

        let now = Self::now_ns();
        let remaining = inner.expires_ns.saturating_sub(now);

        ITimerSpec::from_ns(remaining, inner.interval_ns)
    }

    /// Read the timerfd (returns expiration count)
    ///
    /// Blocks until timer expires (unless O_NONBLOCK is set).
    /// Returns the number of expirations as an 8-byte u64.
    pub fn read(&self, nonblock: bool) -> Result<u64, KernelError> {
        loop {
            {
                let mut inner = self.inner.lock();
                if inner.ticks > 0 {
                    let count = inner.ticks;
                    inner.ticks = 0;
                    return Ok(count);
                }

                // Timer not armed?
                if inner.expires_ns == 0 {
                    if nonblock {
                        return Err(KernelError::WouldBlock);
                    }
                    // Could wait forever, but that's undefined behavior
                    // For now, return EAGAIN
                    return Err(KernelError::WouldBlock);
                }
            }

            if nonblock {
                return Err(KernelError::WouldBlock);
            }

            // Wait for timer to fire
            self.wait_queue.wait();
        }
    }

    /// Poll for readiness
    pub fn poll(&self, pt: Option<&mut PollTable>) -> u16 {
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.wait_queue);
        }

        let inner = self.inner.lock();
        if inner.ticks > 0 {
            POLLIN | POLLRDNORM
        } else {
            0
        }
    }

    /// Called when timer expires (from timer callback)
    fn on_expire(&self) {
        {
            let mut inner = self.inner.lock();
            inner.ticks = inner.ticks.saturating_add(1);

            // For periodic timers, the timer infrastructure handles rescheduling
            // For one-shot, clear expires_ns
            if inner.interval_ns == 0 {
                inner.expires_ns = 0;
            }
        }

        // Wake any waiting readers
        self.wait_queue.wake_all();
    }

    /// Release the timerfd (cancel timer, unregister)
    fn release(&self) {
        // Cancel timer
        {
            let mut inner = self.inner.lock();
            if inner.timer_handle.is_valid() {
                timer_del(inner.timer_handle);
                inner.timer_handle = TimerHandle::NULL;
            }
        }

        // Remove from registry
        let mut registry = TIMERFD_REGISTRY.lock();
        registry.retain(|(id, _)| *id != self.id);
    }
}

impl Drop for Timerfd {
    fn drop(&mut self) {
        // Cancel timer on drop
        let inner = self.inner.lock();
        if inner.timer_handle.is_valid() {
            timer_del(inner.timer_handle);
        }
    }
}

/// Timer callback - finds the timerfd and calls on_expire
fn timerfd_callback(data: u64) {
    // Find timerfd by ID in registry
    let timerfd_opt = {
        let registry = TIMERFD_REGISTRY.lock();
        registry
            .iter()
            .find(|(id, _)| *id == data)
            .and_then(|(_, weak)| weak.upgrade())
    };

    if let Some(timerfd) = timerfd_opt {
        timerfd.on_expire();
    }
}

/// File operations for timerfd
pub struct TimerfdFileOps {
    timerfd: Arc<Timerfd>,
}

impl TimerfdFileOps {
    /// Create file ops for a timerfd
    pub fn new(timerfd: Arc<Timerfd>) -> Self {
        Self { timerfd }
    }
}

impl FileOps for TimerfdFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        // timerfd read always returns 8 bytes (u64)
        if buf.len() < 8 {
            return Err(KernelError::InvalidArgument);
        }

        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        let count = self.timerfd.read(nonblock)?;

        // Write u64 to buffer (little-endian)
        buf[0..8].copy_from_slice(&count.to_le_bytes());
        Ok(8)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        // timerfd doesn't support write
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        self.timerfd.poll(pt)
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        self.timerfd.release();
        Ok(())
    }
}

/// Create a timerfd file
///
/// # Arguments
/// * `clockid` - CLOCK_REALTIME (0) or CLOCK_MONOTONIC (1)
/// * `flags` - TFD_CLOEXEC | TFD_NONBLOCK
///
/// # Returns
/// Arc<File> for the new timerfd
pub fn create_timerfd(clockid: i32, tfd_flags: i32) -> Result<Arc<File>, KernelError> {
    let timerfd = Timerfd::new(clockid);

    // Create file operations
    let ops: &'static dyn FileOps = Box::leak(Box::new(TimerfdFileOps::new(timerfd)));

    // Create dummy dentry for timerfd
    let dentry = create_timerfd_dentry()?;

    // Determine file flags
    let mut file_flags = flags::O_RDONLY;
    if tfd_flags & tfd_flags::TFD_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = Arc::new(File::new(dentry, file_flags, ops));
    Ok(file)
}

/// Create a dummy dentry for timerfd
fn create_timerfd_dentry() -> Result<Arc<Dentry>, KernelError> {
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

    let dentry = Arc::new(Dentry::new_anonymous(String::from("timerfd"), Some(inode)));
    Ok(dentry)
}

/// Get the Timerfd from a File (for syscall implementations)
pub fn get_timerfd(file: &File) -> Option<Arc<Timerfd>> {
    file.f_op
        .as_any()
        .downcast_ref::<TimerfdFileOps>()
        .map(|ops| Arc::clone(&ops.timerfd))
}
