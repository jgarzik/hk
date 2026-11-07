//! POSIX Message Queue Implementation
//!
//! Implements Linux-compatible POSIX message queue syscalls:
//! - mq_open, mq_unlink, mq_timedsend, mq_timedreceive, mq_notify, mq_getsetattr
//!
//! ## Design
//!
//! Unlike SysV message queues, POSIX mqueues use file descriptors and are identified
//! by names (raw syscall names have no '/'; libc strips the leading one).
//! Messages are prioritized (higher priority first) and delivered FIFO within
//! the same priority.
//!
//! ## Key Features
//!
//! - File descriptor-based access (integrates with close, read, poll)
//! - Name-based registry (single path component; '/' in a name is EACCES)
//! - Priority-ordered message delivery (0 to MQ_PRIO_MAX-1)
//! - Blocking/non-blocking send and receive with timeouts
//! - SIGEV_SIGNAL and SIGEV_THREAD_ID notifications
//!
//! ## References
//!
//! - Linux kernel ipc/mqueue.c
//! - POSIX.1-2017 mq_overview(7)

use crate::fs::name::FileName;
use crate::time::hrtimer::HrClock;
use crate::util::kalloc::try_arc;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::cmp::Ordering;
use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::sync::spin::{Mutex, RwLock};
use spin::Lazy;

use crate::arch::Uaccess;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, RwFlags, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::fs::iov_iter::IovDest;
use crate::io::pipe::FD_CLOEXEC;
use crate::io::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::sync::waitqueue::WaitQueue;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;
use crate::task::rlimit;
use crate::uaccess::{
    UaccessArch, copy_from_user, copy_to_user, get_user, put_user, strncpy_from_user,
};
use crate::util::error::KernelError;

// ============================================================================
// Constants (Linux ABI compatible)
// ============================================================================

/// Maximum message priority (priorities are 0 to MQ_PRIO_MAX-1)
pub const MQ_PRIO_MAX: u32 = 32768;

/// Default maximum number of messages in queue
pub const DFLT_MSGMAX: i64 = 10;

/// Default maximum message size
pub const DFLT_MSGSIZEMAX: i64 = 8192;

/// Hard limit on max messages
pub const HARD_MSGMAX: i64 = 65536;

/// Hard limit on message size (16MB)
pub const HARD_MSGSIZEMAX: i64 = 16 * 1024 * 1024;

/// Maximum queue name length
pub const NAME_MAX: usize = 255;

// Open flags
const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
const O_ACCMODE: i32 = 3;
const O_CREAT: i32 = 0o100;
const O_EXCL: i32 = 0o200;
const O_NONBLOCK: i32 = 0o4000;
const O_CLOEXEC: i32 = 0o2000000;

// Notification types
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const SIGEV_THREAD_ID: i32 = 4;

// ============================================================================
// Data Structures
// ============================================================================

/// Message queue attributes (Linux ABI compatible)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MqAttr {
    pub mq_flags: i64,
    pub mq_maxmsg: i64,
    pub mq_msgsize: i64,
    pub mq_curmsgs: i64,
    pub __reserved: [i64; 4],
}
crate::pod!(MqAttr {
    mq_flags,
    mq_maxmsg,
    mq_msgsize,
    mq_curmsgs,
    __reserved
});

/// sigevent structure (Linux ABI compatible)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SigEvent {
    pub sigev_value: u64,
    pub sigev_signo: i32,
    pub sigev_notify: i32,
    pub sigev_notify_tid: i32,
    pub _pad: [i32; 11],
}
crate::pod!(SigEvent {
    sigev_value,
    sigev_signo,
    sigev_notify,
    sigev_notify_tid,
    _pad
});

/// Internal message structure
struct MqMessage {
    priority: u32,
    data: Vec<u8>,
}

impl PartialEq for MqMessage {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for MqMessage {}

impl PartialOrd for MqMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MqMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority = greater (for max-heap behavior)
        self.priority.cmp(&other.priority)
    }
}

/// Notification registration (Linux info->notify_owner, a referenced
/// struct pid, and notify_self_exec_id): holding the owner's `Pid`
/// keeps its number from naming another process
struct MqNotify {
    owner: Arc<crate::task::pid::Pid>,
    /// The owner's exec generation when it registered
    exec_gen: u64,
    sigev_notify: i32,
    sigev_signo: i32,
    sigev_value: u64,
}

/// Message queue
pub struct MqQueue {
    #[expect(dead_code)] // Used for debugging and future /dev/mqueue filesystem
    name: FileName,
    maxmsg: i64,
    msgsize: i64,
    messages: Mutex<Vec<MqMessage>>,
    flags: Mutex<i64>,
    mode: u32,
    uid: u32,
    gid: u32,
    notify: Mutex<Option<MqNotify>>,
    waitq_send: WaitQueue,
    waitq_recv: WaitQueue,
}

impl MqQueue {
    /// "QSIZE:... NOTIFY:... SIGNO:... NOTIFY_PID:...\n" (Linux
    /// mqueue_read_file's format)
    fn status(&self) -> alloc::string::String {
        let qsize: usize = self.messages.lock().iter().map(|m| m.data.len()).sum();
        let (notify, signo, pid) = match self.notify.lock().as_ref() {
            Some(n) => (
                n.sigev_notify,
                if n.sigev_notify == SIGEV_SIGNAL {
                    n.sigev_signo
                } else {
                    0
                },
                // In the reader's namespace (Linux mqueue_read_file:
                // pid_vnr)
                n.owner.vnr(),
            ),
            None => (0, 0, 0),
        };
        alloc::format!(
            "QSIZE:{qsize:<10} NOTIFY:{notify:<5} SIGNO:{signo:<5} NOTIFY_PID:{pid:<6}\n"
        )
    }

    fn new(name: FileName, mode: u32, maxmsg: i64, msgsize: i64) -> Self {
        // Get current task's effective uid/gid as owner
        let cred = crate::task::percpu::current_cred();
        Self {
            name,
            maxmsg,
            msgsize,
            messages: Mutex::new(Vec::new()),
            flags: Mutex::new(0),
            mode,
            // Linux mqueue_get_inode: the creator's fsuid and fsgid
            uid: cred.fsuid,
            gid: cred.fsgid,
            notify: Mutex::new(None),
            waitq_send: WaitQueue::new(),
            waitq_recv: WaitQueue::new(),
        }
    }

    /// Check if the given access mode is permitted (Linux mq_open:
    /// inode_permission of the queue's inode, generic_permission)
    fn check_access(&self, access_mode: i32) -> bool {
        use crate::fs::dac::{MAY_READ, MAY_WRITE};
        let mask = match access_mode {
            O_RDONLY => MAY_READ,
            O_WRONLY => MAY_WRITE,
            _ => MAY_READ | MAY_WRITE,
        };
        let cred = crate::task::percpu::current_cred();
        crate::fs::dac::permission_ids(
            &cred,
            self.uid,
            self.gid,
            self.mode as u16 & 0o7777,
            false,
            mask,
        )
        .is_ok()
    }

    /// May the caller remove it (Linux mq_unlink: vfs_unlink in the
    /// mqueue root, a 01777 directory owned by root): write and search
    /// there are everyone's, so the sticky bit decides (check_sticky):
    /// the queue's owner, the directory's (root) or CAP_FOWNER
    fn may_unlink(&self) -> bool {
        let cred = crate::task::percpu::current_cred();
        cred.fsuid == self.uid || cred.fsuid == 0 || crate::task::capable(crate::task::CAP_FOWNER)
    }

    /// Get the queue name (for debugging and future /dev/mqueue filesystem)
    #[expect(dead_code)]
    fn name(&self) -> &[u8] {
        &self.name
    }

    fn get_attr(&self) -> MqAttr {
        let msgs = self.messages.lock();
        MqAttr {
            mq_flags: *self.flags.lock(),
            mq_maxmsg: self.maxmsg,
            mq_msgsize: self.msgsize,
            mq_curmsgs: msgs.len() as i64,
            __reserved: [0; 4],
        }
    }

    fn set_flags(&self, new_flags: i64) {
        // Only O_NONBLOCK can be changed
        let mut flags = self.flags.lock();
        *flags = new_flags & i64::from(O_NONBLOCK);
    }

    fn is_nonblocking(&self) -> bool {
        (*self.flags.lock() & i64::from(O_NONBLOCK)) != 0
    }

    fn send(
        &self,
        data: Vec<u8>,
        priority: u32,
        nonblock: bool,
        deadline: Option<u64>,
    ) -> Result<(), i64> {
        loop {
            {
                let mut msgs = self.messages.lock();
                if (msgs.len() as i64) < self.maxmsg {
                    // Insert maintaining priority order (higher priority first)
                    let msg = MqMessage { priority, data };

                    // Find insertion point (sorted by priority, descending)
                    let pos = msgs
                        .iter()
                        .position(|m| m.priority < priority)
                        .unwrap_or(msgs.len());
                    msgs.insert(pos, msg);

                    // Check for notification
                    let should_notify = msgs.len() == 1; // Queue was empty
                    drop(msgs);

                    if should_notify {
                        self.fire_notification();
                    }

                    // Wake up receivers
                    self.waitq_recv.wake_all();
                    return Ok(());
                }
            }

            if nonblock || self.is_nonblocking() {
                return Err(KernelError::WouldBlock.sysret());
            }

            // Wait for space (Linux wq_sleep: ERESTARTSYS, ETIMEDOUT)
            let room = || (self.messages.lock().len() as i64) < self.maxmsg;
            match self.waitq_send.wait_event_interruptible_deadline(
                room,
                deadline,
                HrClock::Realtime,
            ) {
                Ok(true) => {}
                Ok(false) => return Err(KernelError::TimedOut.sysret()),
                Err(e) => return Err(e.sysret()),
            }
        }
    }

    fn receive(&self, nonblock: bool, deadline: Option<u64>) -> Result<(Vec<u8>, u32), i64> {
        loop {
            {
                let mut msgs = self.messages.lock();
                if !msgs.is_empty() {
                    // Remove highest priority message (at front); the
                    // caller copies it out, so no kernel buffer is sized
                    // by the user's request
                    let msg = msgs.remove(0);
                    drop(msgs);

                    // Wake up senders
                    self.waitq_send.wake_all();
                    return Ok((msg.data, msg.priority));
                }
            }

            if nonblock || self.is_nonblocking() {
                return Err(KernelError::WouldBlock.sysret());
            }

            // Wait for messages
            let ready = || !self.messages.lock().is_empty();
            match self.waitq_recv.wait_event_interruptible_deadline(
                ready,
                deadline,
                HrClock::Realtime,
            ) {
                Ok(true) => {}
                Ok(false) => return Err(KernelError::TimedOut.sysret()),
                Err(e) => return Err(e.sysret()),
            }
        }
    }

    fn fire_notification(&self) {
        // Taken out of the lock: the send allocates its queue entry
        let n = self.notify.lock().take();
        if let Some(n) = n {
            // The registrant's authority, not the sender's (Linux
            // __do_notify sends without the kill permission check), and
            // only to the process that registered: not after it exited
            // or exec'd (Linux __do_notify: pid_task and self_exec_id;
            // a released process has no task to send to); signal 0
            // sends nothing
            let live = n.owner.exec_gen() == n.exec_gen;
            let sig = n.sigev_signo as u32;
            if n.sigev_notify == SIGEV_SIGNAL && live && sig != 0 {
                let info = mesgq_info(sig, n.sigev_value, &n.owner);
                // To the registrant's struct pid, never its number
                crate::signal::kill_pid_info(&n.owner, sig, info, |_| 0);
            }
        }
    }
}

/// SI_MESGQ info from the current task, the process that made the queue
/// non-empty, as the registrant `owner`'s namespace numbers it, with its
/// sigev_value (Linux __do_notify: task_tgid_nr_ns(current,
/// ns_of_pid(notify_owner)))
fn mesgq_info(sig: u32, value: u64, owner: &crate::task::pid::Pid) -> crate::signal::SendInfo {
    use crate::signal::{SendInfo, SigFields, SigInfo, si_code};
    let me = crate::task::percpu::current_pid();
    let fields = SigFields::Rt {
        pid: crate::task::pid::nr_ns(me, owner.ns()) as i32,
        uid: crate::task::current_cred().uid,
        value,
    };
    SendInfo::Info(SigInfo::new(sig, si_code::SI_MESGQ, fields))
}

/// A message queue descriptor's private data
pub struct MqFile {
    queue: Arc<MqQueue>,
    access_mode: i32,
}

/// File operations for message queue
pub struct MqFileOps;

static MQ_FOPS: MqFileOps = MqFileOps;

/// The queue behind a message queue file
fn mq_of(file: &File) -> Option<&MqFile> {
    file.private_ref::<MqFile>()
}

impl FileOps for MqFileOps {
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// The queue's status line (Linux mqueue_read_file): bytes queued
    /// and the notification registered; no message is consumed. The
    /// file position moves through the line.
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        _flags: RwFlags,
    ) -> Result<usize, KernelError> {
        let mq = mq_of(file).ok_or(KernelError::BadFd)?;
        let line = mq.queue.status();
        let pos = at.unwrap_or_else(|| file.get_pos()) as usize;
        let n = to.copy_to(line.as_bytes().get(pos..).unwrap_or(&[]))?;
        if at.is_none() {
            file.advance_pos(n as u64);
        }
        Ok(n)
    }

    fn poll(&self, file: &File, table: Option<&mut PollTable<'_>>) -> u16 {
        let Some(mq) = mq_of(file) else {
            return crate::io::poll::POLLERR;
        };
        if let Some(pt) = table {
            pt.poll_wait(&mq.queue.waitq_recv);
            pt.poll_wait(&mq.queue.waitq_send);
        }
        let msgs = mq.queue.messages.lock();
        let mut events = 0u16;

        if !msgs.is_empty() {
            events |= POLLIN | POLLRDNORM;
        }
        if (msgs.len() as i64) < mq.queue.maxmsg {
            events |= POLLOUT | POLLWRNORM;
        }

        events
    }

    /// The owner closing any descriptor of the queue drops its
    /// registration (Linux mqueue_flush_file)
    fn flush(&self, file: &File) {
        if let Some(mq) = mq_of(file) {
            let me = crate::task::percpu::current_pid();
            let mut notify = mq.queue.notify.lock();
            if notify
                .as_ref()
                .is_some_and(|n| u64::from(n.owner.nr()) == me)
            {
                *notify = None;
            }
        }
    }
}

// ============================================================================
// Global Registry
// ============================================================================

static MQ_REGISTRY: Lazy<RwLock<BTreeMap<FileName, Arc<MqQueue>>>> =
    Lazy::new(|| RwLock::new(BTreeMap::new()));

static MQ_NEXT_ID: AtomicU64 = AtomicU64::new(1);

// ============================================================================
// Helper Functions
// ============================================================================

fn get_nofile_limit() -> u64 {
    let limit = rlimit::rlimit(rlimit::RLIMIT_NOFILE);
    if limit == rlimit::RLIM_INFINITY {
        u64::MAX
    } else {
        limit
    }
}

fn create_mq_file(queue: Arc<MqQueue>, access_mode: i32, oflag: i32) -> Result<Arc<File>, i64> {
    // Create anonymous inode
    let mode = InodeMode::regular(0o644);
    let inode = try_arc(Inode::new(
        MQ_NEXT_ID.fetch_add(1, AtomicOrdering::SeqCst),
        mode,
        0,                           // uid
        0,                           // gid
        0,                           // size
        InodeTimespec::from_secs(0), // mtime
        Weak::new(),                 // no superblock
        &NULL_INODE_OPS,
    ))
    .map_err(KernelError::sysret)?;

    let dentry = try_arc(Dentry::new_anonymous("mqueue".into(), Some(inode)))
        .map_err(KernelError::sysret)?;

    let mut file_flags = match access_mode {
        O_RDONLY => flags::O_RDONLY,
        O_WRONLY => flags::O_WRONLY,
        O_RDWR => flags::O_RDWR,
        _ => flags::O_RDWR,
    };

    if oflag & O_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let private = try_arc(MqFile { queue, access_mode }).map_err(KernelError::sysret)?;
    try_arc(File::new_anon(dentry, file_flags, &MQ_FOPS, private)).map_err(KernelError::sysret)
}

// ============================================================================
// Syscall Implementations
// ============================================================================

/// Validate a raw mq_open/mq_unlink name.
///
/// The raw syscall name has no leading '/' (libc strips it). Linux looks the
/// name up as a single component in the mqueue fs root
/// (ipc/mqueue.c -> lookup_noperm_common() in fs/namei.c): an empty name is
/// ENOENT (getname), "." / ".." or any '/' is EACCES.
fn validate_mq_name(name: &[u8]) -> Result<(), KernelError> {
    if name.is_empty() {
        return Err(KernelError::NotFound);
    }
    if name.len() > NAME_MAX {
        return Err(KernelError::NameTooLong);
    }
    if crate::fs::name::is_dot_or_dotdot(name) || name.contains(&b'/') {
        return Err(KernelError::PermissionDenied);
    }
    Ok(())
}

/// mq_open - open a message queue
/// Linux mq_attr_ok: both values positive; without CAP_SYS_RESOURCE a
/// queue is capped at the soft defaults, with it at the hard maxima; the
/// total storage must not overflow (EOVERFLOW).
fn mq_attr_ok(maxmsg: i64, msgsize: i64) -> Result<(i64, i64), KernelError> {
    if maxmsg <= 0 || msgsize <= 0 {
        return Err(KernelError::InvalidArgument);
    }
    let (max_m, max_s) = if crate::task::capable(crate::task::CAP_SYS_RESOURCE) {
        (HARD_MSGMAX, HARD_MSGSIZEMAX)
    } else {
        (DFLT_MSGMAX, DFLT_MSGSIZEMAX)
    };
    if maxmsg > max_m || msgsize > max_s {
        return Err(KernelError::InvalidArgument);
    }
    // Total bytes must not overflow (Linux checks maxmsg*msgsize)
    (maxmsg as u64)
        .checked_mul(msgsize as u64)
        .ok_or(KernelError::Overflow)?;
    Ok((maxmsg, msgsize))
}

pub fn sys_mq_open(name_ptr: u64, oflag: i32, mode: u32, attr_ptr: u64) -> i64 {
    // Read name from user space
    // Longer than NAME_MAX: ENAMETOOLONG (Linux: the lookup of the
    // name in the mqueue root)
    let name = match strncpy_from_user::<Uaccess>(name_ptr, NAME_MAX + 1) {
        Ok(s) => s,
        Err(crate::uaccess::UaccessError::TooLong) => return KernelError::NameTooLong.sysret(),
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    if let Err(e) = validate_mq_name(&name) {
        return e.sysret();
    }
    let queue_name = name;
    let access_mode = oflag & O_ACCMODE;

    // Check flags
    let creating = (oflag & O_CREAT) != 0;
    let exclusive = (oflag & O_EXCL) != 0;

    // Attributes are read before the registry is locked (Linux do_mq_open
    // copies them first; no user access under a spinlock)
    let attr_in = if creating && attr_ptr != 0 {
        match get_user::<Uaccess, MqAttr>(attr_ptr) {
            Ok(a) => Some(a),
            Err(_) => return KernelError::BadAddress.sysret(),
        }
    } else {
        None
    };

    // Try to find or create queue
    let queue = {
        let mut registry = MQ_REGISTRY.write();

        if let Some(q) = registry.get(queue_name.as_slice()) {
            if creating && exclusive {
                return KernelError::AlreadyExists.sysret();
            }
            // Check access permissions
            if !q.check_access(access_mode) {
                return KernelError::PermissionDenied.sysret();
            }
            q.clone()
        } else {
            if !creating {
                return KernelError::NotFound.sysret();
            }

            // Read attributes if provided (Linux mq_attr_ok)
            let (maxmsg, msgsize) = match attr_in {
                Some(attr) => match mq_attr_ok(attr.mq_maxmsg, attr.mq_msgsize) {
                    Ok(v) => v,
                    Err(e) => return e.sysret(),
                },
                None => (DFLT_MSGMAX, DFLT_MSGSIZEMAX),
            };

            let queue = match try_arc(MqQueue::new(
                queue_name.clone().into(),
                mode,
                maxmsg,
                msgsize,
            )) {
                Ok(q) => q,
                Err(e) => return e.sysret(),
            };

            // Set initial flags
            if oflag & O_NONBLOCK != 0 {
                queue.set_flags(i64::from(O_NONBLOCK));
            }

            registry.insert(queue_name.into(), queue.clone());
            queue
        }
    };

    // Create file and allocate fd
    let file = match create_mq_file(queue, access_mode, oflag) {
        Ok(f) => f,
        Err(e) => return e,
    };

    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::ProcessFileLimit.sysret(),
    };

    let fd_flags = if oflag & O_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };

    match fd_table
        .lock()
        .alloc_with_flags(file, fd_flags, get_nofile_limit())
    {
        Ok(fd) => i64::from(fd),
        Err(e) => -i64::from(e),
    }
}

/// mq_unlink - remove a message queue
pub fn sys_mq_unlink(name_ptr: u64) -> i64 {
    // Read name from user space
    // Longer than NAME_MAX: ENAMETOOLONG (Linux: the lookup of the
    // name in the mqueue root)
    let name = match strncpy_from_user::<Uaccess>(name_ptr, NAME_MAX + 1) {
        Ok(s) => s,
        Err(crate::uaccess::UaccessError::TooLong) => return KernelError::NameTooLong.sysret(),
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    if let Err(e) = validate_mq_name(&name) {
        return e.sysret();
    }
    let queue_name = name;

    let mut registry = MQ_REGISTRY.write();
    if let Some(q) = registry.get(queue_name.as_slice()) {
        // The mqueue root's sticky bit (Linux may_delete): EPERM
        if !q.may_unlink() {
            return KernelError::NotPermitted.sysret();
        }
        registry.remove(queue_name.as_slice());
        0
    } else {
        KernelError::NotFound.sysret()
    }
}

/// The absolute CLOCK_REALTIME deadline of a timeout (`struct timespec
/// *`, 0 = none; EINVAL for a bad tv_nsec, EFAULT), kept on that clock so
/// it follows clock_settime (Linux do_mq_timedsend: HRTIMER_MODE_ABS)
fn mq_deadline(abs: u64) -> Result<Option<u64>, KernelError> {
    if abs == 0 {
        return Ok(None);
    }
    let sec = get_user::<Uaccess, i64>(abs).map_err(|_| KernelError::BadAddress)?;
    let nsec = get_user::<Uaccess, i64>(abs + 8).map_err(|_| KernelError::BadAddress)?;
    if !(0..1_000_000_000).contains(&nsec) || sec < 0 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(Some(crate::time::timespec_to_ns(sec, nsec)))
}

/// mq_timedsend - send a message to a queue
pub fn sys_mq_timedsend(
    mqdes: i32,
    msg_ptr: u64,
    msg_len: usize,
    msg_prio: u32,
    abs_timeout: u64,
) -> i64 {
    // Validate priority
    if msg_prio >= MQ_PRIO_MAX {
        return KernelError::InvalidArgument.sysret();
    }

    // Get file from fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::BadFd.sysret(),
    };

    let file = match fd_table.lock().get(mqdes) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Get MqFileOps from file
    let mq_ops = match mq_of(&file) {
        Some(ops) => ops,
        None => return KernelError::BadFd.sysret(),
    };

    // Check write permission
    if mq_ops.access_mode == O_RDONLY {
        return KernelError::BadFd.sysret();
    }

    // Check message size
    if msg_len as i64 > mq_ops.queue.msgsize {
        return KernelError::MessageTooLong.sysret();
    }

    // Read message from user space (bounded by msgsize, fallible)
    let mut msg_buf = match crate::util::kmem::try_vec(msg_len, 0u8) {
        Ok(b) => b,
        Err(e) => return e.sysret(),
    };
    if msg_len > 0 {
        if !Uaccess::access_ok(msg_ptr, msg_len) {
            return KernelError::BadAddress.sysret();
        }
        if copy_from_user::<Uaccess>(&mut msg_buf, msg_ptr, msg_len).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    let deadline = match mq_deadline(abs_timeout) {
        Ok(d) => d,
        Err(e) => return e.sysret(),
    };
    let nonblock = mq_ops.queue.is_nonblocking();
    match mq_ops.queue.send(msg_buf, msg_prio, nonblock, deadline) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// mq_timedreceive - receive a message from a queue
pub fn sys_mq_timedreceive(
    mqdes: i32,
    msg_ptr: u64,
    msg_len: usize,
    prio_ptr: u64,
    abs_timeout: u64,
) -> i64 {
    // Get file from fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::BadFd.sysret(),
    };

    let file = match fd_table.lock().get(mqdes) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Get MqFileOps from file
    let mq_ops = match mq_of(&file) {
        Some(ops) => ops,
        None => return KernelError::BadFd.sysret(),
    };

    // Check read permission
    if mq_ops.access_mode == O_WRONLY {
        return KernelError::BadFd.sysret();
    }

    // Check buffer size
    if (msg_len as i64) < mq_ops.queue.msgsize {
        return KernelError::MessageTooLong.sysret();
    }

    let deadline = match mq_deadline(abs_timeout) {
        Ok(d) => d,
        Err(e) => return e.sysret(),
    };
    let nonblock = mq_ops.queue.is_nonblocking();
    let (data, prio) = match mq_ops.queue.receive(nonblock, deadline) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let len = data.len().min(msg_len);

    // Write message to user space
    if len > 0 {
        if !Uaccess::access_ok(msg_ptr, len) {
            return KernelError::BadAddress.sysret();
        }
        if copy_to_user::<Uaccess>(msg_ptr, &data[..len]).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    // Write priority if requested
    if prio_ptr != 0 && put_user::<Uaccess, u32>(prio_ptr, prio).is_err() {
        return KernelError::BadAddress.sysret();
    }

    len as i64
}

/// mq_notify - register for notification
pub fn sys_mq_notify(mqdes: i32, sevp_ptr: u64) -> i64 {
    // Get file from fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::BadFd.sysret(),
    };

    let file = match fd_table.lock().get(mqdes) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Get MqFileOps from file
    let mq_ops = match mq_of(&file) {
        Some(ops) => ops,
        None => return KernelError::BadFd.sysret(),
    };

    let current_pid = crate::task::percpu::current_pid();

    if sevp_ptr == 0 {
        // Remove notification (only if we own it)
        let mut notify = mq_ops.queue.notify.lock();
        if notify
            .as_ref()
            .is_some_and(|n| u64::from(n.owner.nr()) == current_pid)
        {
            *notify = None;
        }
        return 0; // Not an error to remove non-existent
    }

    // Read sigevent from user
    let sev: SigEvent = match get_user::<Uaccess, SigEvent>(sevp_ptr) {
        Ok(s) => s,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate notification type
    match sev.sigev_notify {
        SIGEV_NONE | SIGEV_SIGNAL => {}
        // Linux mqueue notify does not take SIGEV_THREAD_ID (only
        // timers do); SIGEV_THREAD is a user-space pthread mechanism
        SIGEV_THREAD_ID | SIGEV_THREAD => return KernelError::InvalidArgument.sysret(),
        _ => return KernelError::InvalidArgument.sysret(),
    }

    // Check if already registered by another process
    let Some(owner) = u32::try_from(current_pid)
        .ok()
        .and_then(|nr| crate::task::pid::find_pid(&crate::ns::INIT_PID_NS, nr))
    else {
        return KernelError::NoProcess.sysret();
    };
    let mut notify = mq_ops.queue.notify.lock();
    if notify
        .as_ref()
        .is_some_and(|n| u64::from(n.owner.nr()) != current_pid)
    {
        return KernelError::Busy.sysret();
    }

    // Register notification
    *notify = Some(MqNotify {
        exec_gen: owner.exec_gen(),
        owner,
        sigev_notify: sev.sigev_notify,
        sigev_signo: sev.sigev_signo,
        sigev_value: sev.sigev_value,
    });

    0
}

/// mq_getsetattr - get/set message queue attributes
pub fn sys_mq_getsetattr(mqdes: i32, newattr_ptr: u64, oldattr_ptr: u64) -> i64 {
    // Get file from fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::BadFd.sysret(),
    };

    let file = match fd_table.lock().get(mqdes) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Get MqFileOps from file
    let mq_ops = match mq_of(&file) {
        Some(ops) => ops,
        None => return KernelError::BadFd.sysret(),
    };

    // Get old attributes if requested
    if oldattr_ptr != 0 {
        let old_attr = mq_ops.queue.get_attr();
        if put_user::<Uaccess, MqAttr>(oldattr_ptr, old_attr).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    // Set new attributes if provided
    if newattr_ptr != 0 {
        let new_attr: MqAttr = match get_user::<Uaccess, MqAttr>(newattr_ptr) {
            Ok(a) => a,
            Err(_) => return KernelError::BadAddress.sysret(),
        };
        // Only mq_flags (O_NONBLOCK) can be changed
        mq_ops.queue.set_flags(new_attr.mq_flags);
    }

    0
}
