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

use alloc::string::String;
use alloc::sync::{Arc, Weak};

use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::poll::{POLLHUP, POLLIN, POLLRDNORM, PollTable};
use crate::task::Pid;

/// Pidfd flags (from Linux uapi)
pub mod pidfd_flags {
    /// Non-blocking mode
    pub const PIDFD_NONBLOCK: u32 = 0o4000; // O_NONBLOCK
}

/// A pidfd (Linux: the file's private data is the struct pid): a
/// reference to the process's leader `Pid`, so a recycled number never
/// names another process
pub struct Pidfd {
    pid: Arc<crate::task::pid::Pid>,
}

impl Pidfd {
    /// The process's pid
    pub fn pid(&self) -> Pid {
        self.pid.nr() as Pid
    }

    /// Its `Pid`
    pub fn pid_ref(&self) -> &Arc<crate::task::pid::Pid> {
        &self.pid
    }

    pub fn is_exited(&self) -> bool {
        self.pid.exited().is_some()
    }

    pub fn poll(&self, pt: Option<&mut PollTable>) -> u16 {
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.pid.wait_pidfd);
        }
        if self.is_exited() {
            // Process has exited - return readable + hangup
            POLLIN | POLLRDNORM | POLLHUP
        } else {
            0
        }
    }
}

pub struct PidfdFileOps;

static PIDFD_FOPS: PidfdFileOps = PidfdFileOps;

impl FileOps for PidfdFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, KernelError> {
        // pidfds don't support read
        Err(KernelError::InvalidArgument)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        // pidfds don't support write
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable>) -> u16 {
        let Some(pidfd) = file.private_ref::<Pidfd>() else {
            return crate::poll::POLLERR;
        };
        pidfd.poll(pt)
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
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
pub fn create_pidfd(pid: Pid, file_flags: u32) -> Result<Arc<File>, KernelError> {
    let nr = u32::try_from(pid).map_err(|_| KernelError::NoProcess)?;
    let pid =
        crate::task::pid::find_pid(&crate::ns::INIT_PID_NS, nr).ok_or(KernelError::NoProcess)?;
    let pidfd = Arc::new(Pidfd { pid });

    // Create dummy dentry for pidfd
    let dentry = create_pidfd_dentry()?;

    // Determine file flags
    let mut f_flags = flags::O_RDONLY;
    if file_flags & pidfd_flags::PIDFD_NONBLOCK != 0 {
        f_flags |= flags::O_NONBLOCK;
    }

    let file = Arc::new(File::new_anon(dentry, f_flags, &PIDFD_FOPS, pidfd));
    Ok(file)
}

/// Create a dummy dentry for pidfd
fn create_pidfd_dentry() -> Result<Arc<Dentry>, KernelError> {
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
/// Process `pid` has exited with wait `status` (its last thread): its
/// pidfds become readable
pub fn notify_process_exit(pid: Pid, status: i32) {
    let Ok(nr) = u32::try_from(pid) else { return };
    if let Some(p) = crate::task::pid::find_pid(&crate::ns::INIT_PID_NS, nr) {
        p.set_exited(status);
    }
}

/// Get the Pidfd from a File (for syscall implementations)
///
/// Returns the Arc<Pidfd> if the file is a pidfd, None otherwise.
pub fn get_pidfd(file: &File) -> Option<Arc<Pidfd>> {
    file.private_arc::<Pidfd>()
}

/// Get the PID from a pidfd File
///
/// Returns the PID if the file is a pidfd, None otherwise.
pub fn get_pidfd_pid(file: &File) -> Option<Pid> {
    get_pidfd(file).map(|pidfd| pidfd.pid())
}

/// The pid of a pidfd's process while it is still in the task list
/// (not yet reaped): EBADF for another file, ESRCH once it is gone, so
/// a number reused later never reaches another process
pub fn pidfd_live_pid(file: &File) -> Result<Pid, KernelError> {
    let pidfd = get_pidfd(file).ok_or(KernelError::BadFd)?;
    let _list = crate::task::percpu::TASKLIST.read();
    if pidfd.pid.task().is_null() {
        return Err(KernelError::NoProcess);
    }
    Ok(pidfd.pid())
}

/// Check if a file is a pidfd
pub fn is_pidfd(file: &File) -> bool {
    file.f_op.as_any().is::<PidfdFileOps>()
}
