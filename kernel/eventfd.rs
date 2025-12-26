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

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};

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
    /// Unique ID for this eventfd
    id: u64,
}

/// Global counter for eventfd IDs
static NEXT_EVENTFD_ID: AtomicU64 = AtomicU64::new(1);

/// Global eventfd registry (maps ID -> weak ref)
static EVENTFD_REGISTRY: IrqSpinlock<alloc::vec::Vec<(u64, Weak<Eventfd>)>> =
    IrqSpinlock::new(alloc::vec::Vec::new());

impl Eventfd {
    /// Create a new eventfd
    pub fn new(initval: u64, flags: i32) -> Arc<Self> {
        let id = NEXT_EVENTFD_ID.fetch_add(1, Ordering::Relaxed);
        let eventfd = Arc::new(Self {
            inner: IrqSpinlock::new(EventfdInner::new(initval, flags)),
            wait_queue: WaitQueue::new(),
            id,
        });

        // Register in global registry
        let weak = Arc::downgrade(&eventfd);
        EVENTFD_REGISTRY.lock().push((id, weak));

        eventfd
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

            // Wait for someone to write
            self.wait_queue.wait();
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

            // Wait for someone to read
            self.wait_queue.wait();
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

    /// Release the eventfd (unregister)
    fn release(&self) {
        // Remove from registry
        let mut registry = EVENTFD_REGISTRY.lock();
        registry.retain(|(id, _)| *id != self.id);
    }
}

/// File operations for eventfd
pub struct EventfdFileOps {
    eventfd: Arc<Eventfd>,
}

impl EventfdFileOps {
    /// Create file ops for an eventfd
    pub fn new(eventfd: Arc<Eventfd>) -> Self {
        Self { eventfd }
    }
}

impl FileOps for EventfdFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        // eventfd read always returns 8 bytes (u64)
        if buf.len() < 8 {
            return Err(KernelError::InvalidArgument);
        }

        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        let count = self.eventfd.read(nonblock)?;

        // Write u64 to buffer (little-endian)
        buf[0..8].copy_from_slice(&count.to_le_bytes());
        Ok(8)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        // eventfd write requires exactly 8 bytes (u64)
        if buf.len() < 8 {
            return Err(KernelError::InvalidArgument);
        }

        // Read u64 from buffer (little-endian)
        let value = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);

        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        self.eventfd.write(value, nonblock)
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        self.eventfd.poll(pt)
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        self.eventfd.release();
        Ok(())
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

    // Create file operations
    let ops: &'static dyn FileOps = Box::leak(Box::new(EventfdFileOps::new(eventfd)));

    // Create dummy dentry for eventfd
    let dentry = create_eventfd_dentry()?;

    // Determine file flags - eventfd is read/write
    let mut file_flags = flags::O_RDWR;
    if efd_flags & efd_flags::EFD_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = Arc::new(File::new(dentry, file_flags, ops));
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
    file.f_op
        .as_any()
        .downcast_ref::<EventfdFileOps>()
        .map(|ops| Arc::clone(&ops.eventfd))
}
