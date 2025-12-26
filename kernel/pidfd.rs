//! Process file descriptor (pidfd) implementation
//!
//! Provides file descriptor-based process references compatible with Linux pidfd API.
//! Pidfds solve the PID reuse race condition by providing a stable reference to a process.
//!
//! ## Architecture
//!
//! ```text
//! User Process
//!     |
//!     v
//! pidfd_open(pid, flags) -> fd
//!     |
//!     v
//! poll(fd)              -> POLLIN when process exits
//! pidfd_send_signal()   -> Send signal via pidfd
//! waitid(P_PIDFD, fd)   -> Wait for process exit
//! ```
//!
//! ## Key Features
//!
//! - Race-free process references (no PID reuse issues)
//! - Poll support for process exit notification
//! - Signal sending via pidfd
//! - Integration with waitid(P_PIDFD)
//! - CLONE_PIDFD support for automatic pidfd creation

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::fs::FsError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::poll::{POLLHUP, POLLIN, POLLRDNORM, PollTable};
use crate::task::Pid;
use crate::waitqueue::WaitQueue;

/// Pidfd flags (from Linux uapi)
pub mod pidfd_flags {
    /// Non-blocking mode
    pub const PIDFD_NONBLOCK: u32 = 0o4000; // O_NONBLOCK
}

/// Internal pidfd state
struct PidfdInner {
    /// The process ID this pidfd refers to
    pid: Pid,
    /// Whether the process has exited
    exited: bool,
    /// Exit status (valid only if exited is true)
    exit_status: i32,
}

impl PidfdInner {
    fn new(pid: Pid) -> Self {
        Self {
            pid,
            exited: false,
            exit_status: 0,
        }
    }
}

/// Pidfd structure
pub struct Pidfd {
    /// Inner state protected by IRQ spinlock
    inner: IrqSpinlock<PidfdInner>,
    /// Wait queue for poll/blocking operations
    wait_queue: WaitQueue,
    /// Unique ID for this pidfd (for registry)
    id: u64,
}

/// Global counter for pidfd IDs
static NEXT_PIDFD_ID: AtomicU64 = AtomicU64::new(1);

/// Global pidfd registry (maps ID -> weak ref)
/// Used to notify pidfds when processes exit
static PIDFD_REGISTRY: IrqSpinlock<Vec<(u64, Weak<Pidfd>)>> = IrqSpinlock::new(Vec::new());

impl Pidfd {
    /// Create a new pidfd for the given process
    pub fn new(pid: Pid) -> Arc<Self> {
        let id = NEXT_PIDFD_ID.fetch_add(1, Ordering::Relaxed);
        let pidfd = Arc::new(Self {
            inner: IrqSpinlock::new(PidfdInner::new(pid)),
            wait_queue: WaitQueue::new(),
            id,
        });

        // Register in global registry
        let weak = Arc::downgrade(&pidfd);
        PIDFD_REGISTRY.lock().push((id, weak));

        pidfd
    }

    /// Get the PID this pidfd refers to
    pub fn pid(&self) -> Pid {
        self.inner.lock().pid
    }

    /// Check if the process has exited
    pub fn is_exited(&self) -> bool {
        self.inner.lock().exited
    }

    /// Mark the process as exited with the given status
    /// Called from mark_zombie() when process exits
    pub fn notify_exit(&self, status: i32) {
        {
            let mut inner = self.inner.lock();
            inner.exited = true;
            inner.exit_status = status;
        }
        // Wake all waiters
        self.wait_queue.wake_all();
    }

    /// Poll for process exit
    pub fn poll(&self, pt: Option<&mut PollTable>) -> u16 {
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.wait_queue);
        }

        let inner = self.inner.lock();
        if inner.exited {
            // Process has exited - return readable + hangup
            POLLIN | POLLRDNORM | POLLHUP
        } else {
            0
        }
    }

    /// Release the pidfd (unregister from global registry)
    fn release(&self) {
        let mut registry = PIDFD_REGISTRY.lock();
        registry.retain(|(id, _)| *id != self.id);
    }
}

/// File operations for pidfd
pub struct PidfdFileOps {
    pidfd: Arc<Pidfd>,
}

impl PidfdFileOps {
    /// Create file ops for a pidfd
    pub fn new(pidfd: Arc<Pidfd>) -> Self {
        Self { pidfd }
    }
}

impl FileOps for PidfdFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, FsError> {
        // pidfds don't support read
        Err(FsError::InvalidArgument)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, FsError> {
        // pidfds don't support write
        Err(FsError::InvalidArgument)
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        self.pidfd.poll(pt)
    }

    fn release(&self, _file: &File) -> Result<(), FsError> {
        self.pidfd.release();
        Ok(())
    }
}

/// Create a pidfd file for the given process
///
/// # Arguments
/// * `pid` - Process ID to create pidfd for
/// * `file_flags` - File flags (O_NONBLOCK, O_CLOEXEC via FD_CLOEXEC)
///
/// # Returns
/// Arc<File> for the new pidfd
pub fn create_pidfd(pid: Pid, file_flags: u32) -> Result<Arc<File>, FsError> {
    let pidfd = Pidfd::new(pid);

    // Create file operations
    let ops: &'static dyn FileOps = Box::leak(Box::new(PidfdFileOps::new(pidfd)));

    // Create dummy dentry for pidfd
    let dentry = create_pidfd_dentry()?;

    // Determine file flags
    let mut f_flags = flags::O_RDONLY;
    if file_flags & pidfd_flags::PIDFD_NONBLOCK != 0 {
        f_flags |= flags::O_NONBLOCK;
    }

    let file = Arc::new(File::new(dentry, f_flags, ops));
    Ok(file)
}

/// Create a dummy dentry for pidfd
fn create_pidfd_dentry() -> Result<Arc<Dentry>, FsError> {
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

    let dentry = Arc::new(Dentry::new_anonymous(String::from("pidfd"), Some(inode)));
    Ok(dentry)
}

/// Notify all pidfds for the given PID that the process has exited
///
/// Called from mark_zombie() when a process transitions to zombie state.
pub fn notify_process_exit(pid: Pid, status: i32) {
    let registry = PIDFD_REGISTRY.lock();
    for (_, weak) in registry.iter() {
        if let Some(pidfd) = weak.upgrade()
            && pidfd.pid() == pid
        {
            pidfd.notify_exit(status);
        }
    }
}

/// Get the Pidfd from a File (for syscall implementations)
///
/// Returns the Arc<Pidfd> if the file is a pidfd, None otherwise.
pub fn get_pidfd(file: &File) -> Option<Arc<Pidfd>> {
    file.f_op
        .as_any()
        .downcast_ref::<PidfdFileOps>()
        .map(|ops| Arc::clone(&ops.pidfd))
}

/// Get the PID from a pidfd File
///
/// Returns the PID if the file is a pidfd, None otherwise.
pub fn get_pidfd_pid(file: &File) -> Option<Pid> {
    get_pidfd(file).map(|pidfd| pidfd.pid())
}

/// Check if a file is a pidfd
pub fn is_pidfd(file: &File) -> bool {
    file.f_op.as_any().downcast_ref::<PidfdFileOps>().is_some()
}
