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

use crate::util::kalloc::try_arc;
use alloc::sync::Arc;

use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, RwFlags, flags, nowait_rw};
use crate::fs::iov_iter::IovDest;
use crate::io::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::signal::siginfo::Layout;
use crate::signal::{
    SigFields, SigInfo, SigSet, Signal, UNMASKABLE_SIGNALS, with_task_signal_state,
};
use crate::sync::IrqSpinlock;
use crate::task::percpu::current;
use crate::util::pod::IntoBytes;

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

crate::pod!(SignalfdSiginfo {
    ssi_signo,
    ssi_errno,
    ssi_code,
    ssi_pid,
    ssi_uid,
    ssi_fd,
    ssi_tid,
    ssi_band,
    ssi_overrun,
    ssi_trapno,
    ssi_status,
    ssi_int,
    ssi_ptr,
    ssi_utime,
    ssi_stime,
    ssi_addr,
    ssi_addr_lsb,
    __pad2,
    ssi_syscall,
    ssi_call_addr,
    ssi_arch,
    __pad,
});

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
    pub fn new(mask: SigSet) -> Result<Arc<Self>, KernelError> {
        // Cannot monitor SIGKILL or SIGSTOP
        let filtered_mask = mask.subtract(&UNMASKABLE_SIGNALS);
        try_arc(Self {
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
        with_task_signal_state(&current(), |state| {
            let shared = state.shared_pending.lock();
            let pending = state.pending.signal.union(&shared.signal);
            pending.intersect(&mask).any()
        })
        .unwrap_or(false)
    }

    /// Dequeue a pending signal that matches our mask, with its info
    fn dequeue_signal(&self) -> Option<(Signal, SigInfo)> {
        let mask = self.inner.lock().mask;
        crate::signal::dequeue_signal(&mask)
    }

    /// Read signals from the signalfd into `to` (Linux signalfd_read)
    ///
    /// Blocks until at least one matching signal is pending (unless
    /// nonblock), then takes as many more as fit without blocking.
    /// Each is one 128-byte signalfd_siginfo, dequeued and then copied
    /// out with no lock held; a smaller buffer is EINVAL, and a fault
    /// loses that signal (EFAULT unless earlier ones were copied).
    pub fn read(&self, to: &mut IovDest<'_>, nonblock: bool) -> Result<usize, KernelError> {
        const SIGINFO_SIZE: usize = core::mem::size_of::<SignalfdSiginfo>();

        if to.len() < SIGINFO_SIZE {
            return Err(KernelError::InvalidArgument);
        }
        let mut done = 0;
        loop {
            while to.len() >= SIGINFO_SIZE {
                let Some((sig, info)) = self.dequeue_signal() else {
                    break;
                };
                match to.copy_to_full(self.build_siginfo(sig, &info).as_bytes()) {
                    Ok(()) => done += SIGINFO_SIZE,
                    Err(_) if done > 0 => return Ok(done),
                    Err(e) => return Err(e),
                }
            }
            if done > 0 {
                return Ok(done);
            }
            if nonblock {
                return Err(KernelError::WouldBlock);
            }
            // Wait on the caller's handler table for a matching signal
            // (a signal ends the wait)
            let Some(sighand) = crate::signal::get_task_sighand(&current()) else {
                return Err(KernelError::WouldBlock);
            };
            sighand
                .signalfd_wq
                .wait_event_interruptible(|| self.has_pending_signals())?;
        }
    }

    /// The signalfd_siginfo of `sig` with `info` (Linux
    /// signalfd_copyinfo): the fields its layout carries, the rest zero
    fn build_siginfo(&self, sig: Signal, info: &SigInfo) -> SignalfdSiginfo {
        let mut s = SignalfdSiginfo {
            ssi_signo: sig.nr(),
            ssi_errno: info.errno,
            ssi_code: info.code,
            ..Default::default()
        };
        // Each truncation below is Linux's (ssi_band, ssi_utime, ...)
        match info.fields() {
            SigFields::Kill { pid, uid } => {
                s.ssi_pid = pid as u32;
                s.ssi_uid = uid;
            }
            SigFields::Rt { pid, uid, value } => {
                s.ssi_pid = pid as u32;
                s.ssi_uid = uid;
                s.ssi_ptr = value;
                s.ssi_int = value as i32;
            }
            SigFields::Timer {
                tid,
                overrun,
                value,
            } => {
                s.ssi_tid = tid as u32;
                s.ssi_overrun = overrun as u32;
                s.ssi_ptr = value;
                s.ssi_int = value as i32;
            }
            SigFields::Chld {
                pid,
                uid,
                status,
                utime,
                stime,
            } => {
                s.ssi_pid = pid as u32;
                s.ssi_uid = uid;
                s.ssi_status = status;
                s.ssi_utime = utime as u64;
                s.ssi_stime = stime as u64;
            }
            SigFields::Fault { addr, addr_lsb } => {
                s.ssi_addr = addr;
                if info.layout() == Layout::FaultMceerr {
                    s.ssi_addr_lsb = addr_lsb as u16;
                }
            }
            SigFields::Sys {
                call_addr,
                syscall,
                arch,
            } => {
                s.ssi_call_addr = call_addr;
                s.ssi_syscall = syscall;
                s.ssi_arch = arch;
            }
            SigFields::Poll { band, fd } => {
                s.ssi_band = band as u32;
                s.ssi_fd = fd;
            }
        }
        s
    }

    /// Poll for readiness
    pub fn poll(&self, pt: Option<&mut PollTable<'_>>) -> u16 {
        // The caller's handler table, held by the poll for as long as it
        // stays registered on its queue (Linux instead detaches pollers
        // when it is freed, signalfd_cleanup)
        if let Some(poll_table) = pt
            && let Some(sighand) = crate::signal::get_task_sighand(&current())
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

    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        let nb = nowait_rw(file, at, flags)?;
        let signalfd = file.private_ref::<Signalfd>().ok_or(KernelError::BadFd)?;
        signalfd.read(to, nb)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Some(signalfd) = file.private_ref::<Signalfd>() else {
            return crate::io::poll::POLLERR;
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
    let signalfd = Signalfd::new(mask)?;

    // Create dummy dentry for signalfd

    // Determine file flags - signalfd is read-only
    let mut file_flags = flags::O_RDONLY;
    if sfd_flags & sfd_flags::SFD_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = crate::fs::anon_inodes::anon_inode_getfile(
        "[signalfd]",
        &SIGNALFD_FOPS,
        signalfd,
        file_flags,
    )?;
    Ok(file)
}

/// Get the Signalfd from a File (for syscall implementations)
pub fn get_signalfd(file: &File) -> Option<Arc<Signalfd>> {
    file.private_arc::<Signalfd>()
}
