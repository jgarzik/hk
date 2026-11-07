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

use crate::util::kalloc::try_arc;
use alloc::sync::Arc;

use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, flags};
use crate::io::poll::{POLLHUP, POLLIN, POLLRDNORM, PollTable};
use crate::task::Pid;

/// Pidfd flags (from Linux uapi)
pub mod pidfd_flags {
    /// Non-blocking mode
    pub const PIDFD_NONBLOCK: u32 = 0o4000; // O_NONBLOCK
    /// A thread's pidfd, any thread's (O_EXCL; Linux 6.9)
    pub const PIDFD_THREAD: u32 = 0o200;
}

/// A pidfd (Linux: the file's private data is the struct pid): a
/// reference to its task's `Pid` (a process's leader, or with
/// PIDFD_THREAD any thread), so a recycled number never names another
/// task
pub struct Pidfd {
    pid: Arc<crate::task::pid::Pid>,
    /// Opened with PIDFD_THREAD (Linux f_flags & PIDFD_THREAD): signals
    /// go to the thread by default
    thread: bool,
}

impl Pidfd {
    /// The process's pid
    pub fn pid(&self) -> Pid {
        Pid::from(self.pid.nr())
    }

    /// Its `Pid`
    pub fn pid_ref(&self) -> &Arc<crate::task::pid::Pid> {
        &self.pid
    }

    /// A thread pidfd (PIDFD_THREAD)
    pub fn thread(&self) -> bool {
        self.thread
    }

    /// Readable once its task exited, its whole group if it leads one;
    /// hung up too once it is released (Linux pidfd_poll)
    pub fn poll(&self, pt: Option<&mut PollTable<'_>>) -> u16 {
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.pid.wait_pidfd);
        }
        match crate::task::percpu::pidfd_exited(&self.pid) {
            None => POLLIN | POLLRDNORM | POLLHUP,
            Some(true) => POLLIN | POLLRDNORM,
            Some(false) => 0,
        }
    }
}

pub struct PidfdFileOps;

static PIDFD_FOPS: PidfdFileOps = PidfdFileOps;

impl FileOps for PidfdFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Some(pidfd) = file.private_ref::<Pidfd>() else {
            return crate::io::poll::POLLERR;
        };
        pidfd.poll(pt)
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        Ok(())
    }
}

/// pidfd_open's pidfd for task `pid` (Linux pidfd_prepare): ESRCH
/// once its task is released, ENOENT for a thread that does not lead
/// its group unless PIDFD_THREAD asks for a thread's
pub fn open_pidfd(pid: Pid, file_flags: u32) -> Result<Arc<File>, KernelError> {
    // The caller's number (Linux pidfd_open: find_get_pid)
    let nr = u32::try_from(pid).map_err(|_| KernelError::NoProcess)?;
    let p = crate::task::pid::find_vpid(nr).ok_or(KernelError::NoProcess)?;
    let thread = file_flags & pidfd_flags::PIDFD_THREAD != 0;
    {
        let table = crate::task::percpu::TASKLIST.read();
        let tid = table.pid_tid(&p).ok_or(KernelError::NoProcess)?;
        if !thread && !table.get(tid).is_some_and(|t| t.leader) {
            return Err(KernelError::NotFound);
        }
    }
    pidfd_file(p, file_flags)
}

/// A pidfd file for `pid` (no check that it names a task: clone's
/// child is not listed yet, Linux PIDFD_STALE)
pub fn pidfd_file(
    pid: Arc<crate::task::pid::Pid>,
    file_flags: u32,
) -> Result<Arc<File>, KernelError> {
    let thread = file_flags & pidfd_flags::PIDFD_THREAD != 0;
    let pidfd = try_arc(Pidfd { pid, thread })?;
    let mut f_flags = flags::O_RDONLY;
    if file_flags & pidfd_flags::PIDFD_NONBLOCK != 0 {
        f_flags |= flags::O_NONBLOCK;
    }

    let file = crate::fs::anon_inodes::anon_inode_getfile("[pidfd]", &PIDFD_FOPS, pidfd, f_flags)?;
    Ok(file)
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

/// The tid of a pidfd's process (Linux pidfd_get_task): from its struct
/// pid under TASKLIST, never by number, so a reused number never
/// reaches another process; EBADF for another file, ESRCH once gone
pub fn pidfd_tid(file: &File) -> Result<crate::task::Tid, KernelError> {
    let pidfd = get_pidfd(file).ok_or(KernelError::BadFd)?;
    crate::task::percpu::TASKLIST
        .read()
        .pid_tid(&pidfd.pid)
        .ok_or(KernelError::NoProcess)
}

/// Check if a file is a pidfd
pub fn is_pidfd(file: &File) -> bool {
    file.f_op.as_any().is::<PidfdFileOps>()
}
