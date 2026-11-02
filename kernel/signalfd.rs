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

use alloc::string::String;
use alloc::sync::{Arc, Weak};

use crate::arch::IrqSpinlock;
use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::signal::{SigSet, UNMASKABLE_SIGNALS, with_task_signal_state};
use crate::task::percpu::current_tid;

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

/// Signalfd structure: only a mask. Reads and polls see the signals of
/// the task doing them (Linux signalfd_read / signalfd_poll on
/// current), so after fork a child reads its own
pub struct Signalfd {
    /// Inner state protected by IRQ spinlock
    inner: IrqSpinlock<SignalfdInner>,
}

impl Signalfd {
    /// Create a new signalfd
    pub fn new(mask: SigSet) -> Arc<Self> {
        // Cannot monitor SIGKILL or SIGSTOP
        let filtered_mask = mask.subtract(&UNMASKABLE_SIGNALS);
        Arc::new(Self {
            inner: IrqSpinlock::new(SignalfdInner {
                mask: filtered_mask,
            }),
        })
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
        with_task_signal_state(current_tid(), |state| {
            let shared = state.shared_pending.lock();
            let pending = state.pending.signal.union(&shared.signal);
            pending.intersect(&mask).any()
        })
        .unwrap_or(false)
    }

    /// Dequeue a pending signal that matches our mask
    fn dequeue_signal(&self) -> Option<u32> {
        let mask = self.inner.lock().mask;
        with_task_signal_state(current_tid(), |state| {
            // First check private pending
            let deliverable = state.pending.signal.intersect(&mask);
            if let Some(sig) = deliverable.first() {
                state.pending.signal.remove(sig);
                return Some(sig);
            }

            // Then check shared pending
            let mut shared = state.shared_pending.lock();
            let deliverable = shared.signal.intersect(&mask);
            if let Some(sig) = deliverable.first() {
                shared.signal.remove(sig);
                drop(shared);
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

            // Wait on the caller's handler table for a matching signal
            // (a signal ends the wait)
            let Some(sighand) = crate::signal::get_task_sighand(current_tid()) else {
                return Err(KernelError::WouldBlock);
            };
            sighand
                .signalfd_wq
                .wait_event_interruptible(|| self.has_pending_signals())?;
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
        // The caller's handler table, held by the poll for as long as it
        // stays registered on its queue (Linux instead detaches pollers
        // when it is freed, signalfd_cleanup)
        if let Some(poll_table) = pt
            && let Some(sighand) = crate::signal::get_task_sighand(current_tid())
        {
            poll_table.hold(sighand.clone());
            poll_table.poll_wait(&sighand.signalfd_wq);
        }

        if self.has_pending_signals() {
            POLLIN | POLLRDNORM
        } else {
            0
        }
    }
}

/// File operations for signalfd
pub struct SignalfdFileOps;

static SIGNALFD_FOPS: SignalfdFileOps = SignalfdFileOps;

impl FileOps for SignalfdFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let signalfd = file.private_ref::<Signalfd>().ok_or(KernelError::BadFd)?;
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        signalfd.read(buf, nonblock)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        // signalfd doesn't support write
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable>) -> u16 {
        let Some(signalfd) = file.private_ref::<Signalfd>() else {
            return crate::poll::POLLERR;
        };
        signalfd.poll(pt)
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
    let signalfd = Signalfd::new(mask);

    // Create dummy dentry for signalfd
    let dentry = create_signalfd_dentry()?;

    // Determine file flags - signalfd is read-only
    let mut file_flags = flags::O_RDONLY;
    if sfd_flags & sfd_flags::SFD_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = Arc::new(File::new_anon(dentry, file_flags, &SIGNALFD_FOPS, signalfd));
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
    file.private_arc::<Signalfd>()
}
