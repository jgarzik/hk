//! Event file descriptor (eventfd) implementation
//!
//! Provides file descriptor-based event notification compatible with Linux eventfd API.
//!
//! ## Architecture
//!
//! ```text
//! User Process
//!     |
//!     v
//! eventfd2(initval, flags) -> fd
//!     |
//!     v
//! write(fd, &value, 8)  -> Adds value to counter
//! read(fd, buf, 8)      -> Returns counter (blocks if 0)
//! poll(fd)              -> POLLIN if count>0, POLLOUT if not at max
//! ```
//!
//! ## Key Features
//!
//! - Simple u64 counter for inter-process signaling
//! - Blocking and non-blocking reads/writes
//! - poll() support for integration with select/poll/epoll
//! - Semaphore mode (EFD_SEMAPHORE) for decrement-by-1 semantics

use alloc::string::String;
use alloc::sync::{Arc, Weak};

use crate::arch::IrqSpinlock;
use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::poll::{POLLERR, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::waitqueue::WaitQueue;

/// Eventfd flags
pub mod efd_flags {
    /// Semaphore mode - read returns 1 and decrements by 1
    pub const EFD_SEMAPHORE: i32 = 1;
    /// Set close-on-exec flag
    pub const EFD_CLOEXEC: i32 = 0o2000000;
    /// Set non-blocking flag
    pub const EFD_NONBLOCK: i32 = 0o4000;
}

/// Maximum value before overflow
const ULLONG_MAX: u64 = u64::MAX;

/// Internal eventfd state
struct EventfdInner {
    /// The counter value
    count: u64,
    /// Flags (EFD_SEMAPHORE, etc.)
    flags: i32,
}

impl EventfdInner {
    fn new(initval: u64, flags: i32) -> Self {
        Self {
            count: initval,
            flags,
        }
    }

    /// Check if semaphore mode is enabled
    fn is_semaphore(&self) -> bool {
        self.flags & efd_flags::EFD_SEMAPHORE != 0
    }
}

/// Eventfd structure
pub struct Eventfd {
    /// Inner state protected by IRQ spinlock
    inner: IrqSpinlock<EventfdInner>,
    /// Wait queue for blocking readers/writers
    wait_queue: WaitQueue,
}

impl Eventfd {
    /// Create a new eventfd
    pub fn new(initval: u64, flags: i32) -> Arc<Self> {
        Arc::new(Self {
            inner: IrqSpinlock::new(EventfdInner::new(initval, flags)),
            wait_queue: WaitQueue::new(),
        })
    }

    /// Read the eventfd (returns counter value)
    ///
    /// Blocks until counter is non-zero (unless O_NONBLOCK is set).
    /// Returns the counter value as an 8-byte u64.
    /// In normal mode, resets counter to 0.
    /// In semaphore mode, decrements counter by 1.
    pub fn read(&self, nonblock: bool) -> Result<u64, KernelError> {
        loop {
            {
                let mut inner = self.inner.lock();
                if inner.count > 0 {
                    let value = if inner.is_semaphore() {
                        // Semaphore mode: return 1, decrement by 1
                        inner.count -= 1;
                        1
                    } else {
                        // Normal mode: return count, reset to 0
                        let count = inner.count;
                        inner.count = 0;
                        count
                    };

                    // Wake any blocked writers since we freed up space
                    drop(inner);
                    self.wait_queue.wake_all();
                    return Ok(value);
                }
            }

            if nonblock {
                return Err(KernelError::WouldBlock);
            }

            // Wait for someone to write (a signal ends the wait)
            self.wait_queue
                .wait_event_interruptible(|| self.inner.lock().count > 0)?;
        }
    }

    /// Write to the eventfd (adds to counter)
    ///
    /// Adds the value to the counter.
    /// Blocks if counter would overflow (unless O_NONBLOCK is set).
    /// The value must not be ULLONG_MAX.
    pub fn write(&self, value: u64, nonblock: bool) -> Result<usize, KernelError> {
        // Value of ULLONG_MAX is not allowed
        if value == ULLONG_MAX {
            return Err(KernelError::InvalidArgument);
        }

        loop {
            {
                let mut inner = self.inner.lock();
                // Check if we can add without overflow
                // Must have room for at least value more (count + value < ULLONG_MAX)
                if ULLONG_MAX - inner.count > value {
                    inner.count += value;
                    // Wake any blocked readers
                    drop(inner);
                    self.wait_queue.wake_all();
                    return Ok(8);
                }
            }

            if nonblock {
                return Err(KernelError::WouldBlock);
            }

            // Wait for someone to read (a signal ends the wait)
            self.wait_queue
                .wait_event_interruptible(|| ULLONG_MAX - self.inner.lock().count > value)?;
        }
    }

    /// Poll for readiness
    pub fn poll(&self, pt: Option<&mut PollTable>) -> u16 {
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.wait_queue);
        }

        let inner = self.inner.lock();
        let mut events: u16 = 0;

        // POLLIN if count > 0
        if inner.count > 0 {
            events |= POLLIN | POLLRDNORM;
        }

        // POLLERR if count == ULLONG_MAX (overflow indicator)
        if inner.count == ULLONG_MAX {
            events |= POLLERR;
        }

        // POLLOUT if count < ULLONG_MAX - 1 (room to write at least 1)
        if ULLONG_MAX - 1 > inner.count {
            events |= POLLOUT | POLLWRNORM;
        }

        events
    }
}

/// File operations for eventfd
pub struct EventfdFileOps;

static EVENTFD_FOPS: EventfdFileOps = EventfdFileOps;

impl FileOps for EventfdFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let eventfd = file.private_ref::<Eventfd>().ok_or(KernelError::BadFd)?;
        // eventfd read always returns 8 bytes (u64)
        if buf.len() < 8 {
            return Err(KernelError::InvalidArgument);
        }

        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        let count = eventfd.read(nonblock)?;

        // Write u64 to buffer (little-endian)
        buf[0..8].copy_from_slice(&count.to_le_bytes());
        Ok(8)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        let eventfd = file.private_ref::<Eventfd>().ok_or(KernelError::BadFd)?;
        // eventfd write requires exactly 8 bytes (u64)
        if buf.len() < 8 {
            return Err(KernelError::InvalidArgument);
        }

        // Read u64 from buffer (little-endian)
        let value = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);

        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        eventfd.write(value, nonblock)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable>) -> u16 {
        let Some(eventfd) = file.private_ref::<Eventfd>() else {
            return POLLERR;
        };
        eventfd.poll(pt)
    }
}

/// Create an eventfd file
///
/// # Arguments
/// * `initval` - Initial counter value
/// * `flags` - EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE
///
/// # Returns
/// Arc<File> for the new eventfd
pub fn create_eventfd(initval: u64, efd_flags: i32) -> Result<Arc<File>, KernelError> {
    let eventfd = Eventfd::new(initval, efd_flags);

    // Create dummy dentry for eventfd
    let dentry = create_eventfd_dentry()?;

    // Determine file flags - eventfd is read/write
    let mut file_flags = flags::O_RDWR;
    if efd_flags & efd_flags::EFD_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = Arc::new(File::new_anon(dentry, file_flags, &EVENTFD_FOPS, eventfd));
    Ok(file)
}

/// Create a dummy dentry for eventfd
fn create_eventfd_dentry() -> Result<Arc<Dentry>, KernelError> {
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

    let dentry = Arc::new(Dentry::new_anonymous(String::from("eventfd"), Some(inode)));
    Ok(dentry)
}

/// Get the Eventfd from a File (for syscall implementations)
pub fn get_eventfd(file: &File) -> Option<Arc<Eventfd>> {
    file.private_arc::<Eventfd>()
}
