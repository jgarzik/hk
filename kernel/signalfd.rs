//! Signal file descriptor (signalfd) implementation
//!
//! Provides file descriptor-based signal reception compatible with Linux signalfd API.
//!
//! ## Architecture
//!
//! ```text
//! User Process
//!     |
//!     v
//! signalfd4(fd, mask, sizemask, flags) -> fd
//!     |
//!     v
//! read(fd, buf, 128)  -> Returns signalfd_siginfo structures
//! poll(fd)            -> POLLIN if matching signals pending
//! ```
//!
//! ## Key Features
//!
//! - Receive signals via file descriptor read()
//! - Signals are consumed from pending queue (not copied)
//! - poll() support for integration with select/poll/epoll
//! - Mask can be updated by calling signalfd4 with existing fd

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::signal::{SigSet, UNMASKABLE_SIGNALS, with_task_signal_state};
use crate::task::Tid;
use crate::waitqueue::WaitQueue;

/// Signalfd flags
pub mod sfd_flags {
    /// Set close-on-exec flag
    pub const SFD_CLOEXEC: i32 = 0o2000000;
    /// Set non-blocking flag
    pub const SFD_NONBLOCK: i32 = 0o4000;
}

/// signalfd_siginfo structure - Linux ABI (128 bytes)
///
/// Must match the Linux layout exactly for compatibility.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SignalfdSiginfo {
    /// Signal number
    pub ssi_signo: u32,
    /// Error number (unused for most signals)
    pub ssi_errno: i32,
    /// Signal code
    pub ssi_code: i32,
    /// Sender's PID
    pub ssi_pid: u32,
    /// Sender's UID
    pub ssi_uid: u32,
    /// File descriptor (SIGIO)
    pub ssi_fd: i32,
    /// Sender's TID
    pub ssi_tid: u32,
    /// Band event (SIGIO)
    pub ssi_band: u32,
    /// POSIX timer overrun count
    pub ssi_overrun: u32,
    /// Trap number
    pub ssi_trapno: u32,
    /// Exit status/signal (SIGCHLD)
    pub ssi_status: i32,
    /// sigqueue() integer
    pub ssi_int: i32,
    /// sigqueue() pointer
    pub ssi_ptr: u64,
    /// User CPU time (SIGCHLD)
    pub ssi_utime: u64,
    /// System CPU time (SIGCHLD)
    pub ssi_stime: u64,
    /// Fault address (SIGBUS, SIGFPE, SIGSEGV, SIGTRAP)
    pub ssi_addr: u64,
    /// LSB of address
    pub ssi_addr_lsb: u16,
    __pad2: u16,
    /// System call number
    pub ssi_syscall: i32,
    /// Address of system call instruction
    pub ssi_call_addr: u64,
    /// Architecture
    pub ssi_arch: u32,
    __pad: [u8; 28],
}

// Compile-time assertion that SignalfdSiginfo is exactly 128 bytes
const _: () = assert!(core::mem::size_of::<SignalfdSiginfo>() == 128);

/// Internal signalfd state
struct SignalfdInner {
    /// Signal mask - signals we're interested in
    mask: SigSet,
}

/// Signalfd structure
pub struct Signalfd {
    /// Inner state protected by IRQ spinlock
    inner: IrqSpinlock<SignalfdInner>,
    /// Wait queue for blocking readers
    wait_queue: WaitQueue,
    /// Unique ID for this signalfd
    id: u64,
    /// Task ID that created this signalfd (for signal access)
    owner_tid: Tid,
}

/// Global counter for signalfd IDs
static NEXT_SIGNALFD_ID: AtomicU64 = AtomicU64::new(1);

/// Global signalfd registry (maps ID -> weak ref)
static SIGNALFD_REGISTRY: IrqSpinlock<Vec<(u64, Weak<Signalfd>)>> = IrqSpinlock::new(Vec::new());

impl Signalfd {
    /// Create a new signalfd
    pub fn new(mask: SigSet, tid: Tid) -> Arc<Self> {
        let id = NEXT_SIGNALFD_ID.fetch_add(1, Ordering::Relaxed);
        // Cannot monitor SIGKILL or SIGSTOP
        let filtered_mask = mask.subtract(&UNMASKABLE_SIGNALS);

        let signalfd = Arc::new(Self {
            inner: IrqSpinlock::new(SignalfdInner {
                mask: filtered_mask,
            }),
            wait_queue: WaitQueue::new(),
            id,
            owner_tid: tid,
        });

        // Register in global registry for signal wake integration
        let weak = Arc::downgrade(&signalfd);
        SIGNALFD_REGISTRY.lock().push((id, weak));

        signalfd
    }

    /// Update the signal mask (for signalfd reuse)
    pub fn update_mask(&self, new_mask: SigSet) {
        let mut inner = self.inner.lock();
        inner.mask = new_mask.subtract(&UNMASKABLE_SIGNALS);
    }

    /// Get current mask
    pub fn get_mask(&self) -> SigSet {
        self.inner.lock().mask
    }

    /// Check if any monitored signals are pending
    fn has_pending_signals(&self) -> bool {
        let mask = self.inner.lock().mask;
        with_task_signal_state(self.owner_tid, |state| {
            let shared = state.shared_pending.lock();
            let pending = state.pending.signal.union(&shared.signal);
            pending.intersect(&mask).any()
        })
        .unwrap_or(false)
    }

    /// Dequeue a pending signal that matches our mask
    fn dequeue_signal(&self) -> Option<u32> {
        let mask = self.inner.lock().mask;
        with_task_signal_state(self.owner_tid, |state| {
            // First check private pending
            let deliverable = state.pending.signal.intersect(&mask);
            if let Some(sig) = deliverable.first() {
                state.pending.signal.remove(sig);
                state.recalc_sigpending();
                return Some(sig);
            }

            // Then check shared pending
            let mut shared = state.shared_pending.lock();
            let deliverable = shared.signal.intersect(&mask);
            if let Some(sig) = deliverable.first() {
                shared.signal.remove(sig);
                drop(shared);
                state.recalc_sigpending();
                return Some(sig);
            }
            None
        })?
    }

    /// Read signals from the signalfd
    ///
    /// Blocks until at least one matching signal is pending (unless nonblock).
    /// Returns signalfd_siginfo structures (128 bytes each).
    pub fn read(&self, buf: &mut [u8], nonblock: bool) -> Result<usize, KernelError> {
        const SIGINFO_SIZE: usize = 128;

        if buf.len() < SIGINFO_SIZE {
            return Err(KernelError::InvalidArgument);
        }

        let max_signals = buf.len() / SIGINFO_SIZE;
        let mut bytes_written = 0;

        loop {
            // Try to dequeue signals up to max_signals
            while bytes_written / SIGINFO_SIZE < max_signals {
                if let Some(sig) = self.dequeue_signal() {
                    let siginfo = self.build_siginfo(sig);
                    let offset = bytes_written;
                    // Copy siginfo to buffer
                    let siginfo_bytes = unsafe {
                        core::slice::from_raw_parts(
                            &siginfo as *const SignalfdSiginfo as *const u8,
                            SIGINFO_SIZE,
                        )
                    };
                    buf[offset..offset + SIGINFO_SIZE].copy_from_slice(siginfo_bytes);
                    bytes_written += SIGINFO_SIZE;
                } else {
                    break;
                }
            }

            if bytes_written > 0 {
                return Ok(bytes_written);
            }

            if nonblock {
                return Err(KernelError::WouldBlock);
            }

            // Wait for signals
            self.wait_queue.wait();
        }
    }

    /// Build signalfd_siginfo from signal number
    fn build_siginfo(&self, sig: u32) -> SignalfdSiginfo {
        // TODO: Fill in sender info from SigInfo when we have queued signals
        // For now, just return the signal number
        SignalfdSiginfo {
            ssi_signo: sig,
            ..Default::default()
        }
    }

    /// Poll for readiness
    pub fn poll(&self, pt: Option<&mut PollTable>) -> u16 {
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.wait_queue);
        }

        if self.has_pending_signals() {
            POLLIN | POLLRDNORM
        } else {
            0
        }
    }

    /// Called when a matching signal is delivered to wake waiters
    pub fn notify_signal(&self) {
        self.wait_queue.wake_all();
    }

    /// Release the signalfd (unregister)
    fn release(&self) {
        let mut registry = SIGNALFD_REGISTRY.lock();
        registry.retain(|(id, _)| *id != self.id);
    }
}

/// File operations for signalfd
pub struct SignalfdFileOps {
    signalfd: Arc<Signalfd>,
}

impl SignalfdFileOps {
    /// Create file ops for a signalfd
    pub fn new(signalfd: Arc<Signalfd>) -> Self {
        Self { signalfd }
    }
}

impl FileOps for SignalfdFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        self.signalfd.read(buf, nonblock)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        // signalfd doesn't support write
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        self.signalfd.poll(pt)
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        self.signalfd.release();
        Ok(())
    }
}

/// Create a signalfd file
///
/// # Arguments
/// * `mask` - Signal mask to monitor
/// * `sfd_flags` - SFD_CLOEXEC | SFD_NONBLOCK
///
/// # Returns
/// Arc<File> for the new signalfd
pub fn create_signalfd(mask: SigSet, sfd_flags: i32) -> Result<Arc<File>, KernelError> {
    let tid = crate::task::percpu::current_tid();
    let signalfd = Signalfd::new(mask, tid);

    // Create file operations
    let ops: &'static dyn FileOps = Box::leak(Box::new(SignalfdFileOps::new(signalfd)));

    // Create dummy dentry for signalfd
    let dentry = create_signalfd_dentry()?;

    // Determine file flags - signalfd is read-only
    let mut file_flags = flags::O_RDONLY;
    if sfd_flags & sfd_flags::SFD_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = Arc::new(File::new(dentry, file_flags, ops));
    Ok(file)
}

/// Create a dummy dentry for signalfd
fn create_signalfd_dentry() -> Result<Arc<Dentry>, KernelError> {
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

    let dentry = Arc::new(Dentry::new_anonymous(String::from("signalfd"), Some(inode)));
    Ok(dentry)
}

/// Get the Signalfd from a File (for syscall implementations)
pub fn get_signalfd(file: &File) -> Option<Arc<Signalfd>> {
    file.f_op
        .as_any()
        .downcast_ref::<SignalfdFileOps>()
        .map(|ops| Arc::clone(&ops.signalfd))
}

/// Wake all signalfds that are interested in signal `sig` for task `tid`
///
/// Called from send_signal() when a signal is added to pending.
pub fn wake_signalfds_for_signal(tid: Tid, sig: u32) {
    let registry = SIGNALFD_REGISTRY.lock();
    for (_, weak) in registry.iter() {
        if let Some(signalfd) = weak.upgrade() {
            // Only wake signalfds owned by this task that are monitoring this signal
            if signalfd.owner_tid == tid {
                let mask = signalfd.inner.lock().mask;
                if mask.contains(sig) {
                    signalfd.notify_signal();
                }
            }
        }
    }
}
