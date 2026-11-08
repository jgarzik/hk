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
use crate::signal::Signal;
use crate::time::hrtimer::HrClock;
use crate::util::kalloc::try_arc;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::cmp::Ordering;
use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::sync::RwSem;
use crate::sync::spin::Mutex;

use crate::arch::Uaccess;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, RwFlags, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::fs::io::{fd_install, fget};
use crate::fs::iov_iter::IovDest;
use crate::io::pipe::FD_CLOEXEC;
use crate::io::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::sync::waitqueue::WaitQueue;
use crate::task::rlimit;
use crate::uaccess::{UserPtr, copy_from_user, copy_to_user, strncpy_from_user};
use crate::util::error::{KernelError, KernelResult};

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
    /// SIGEV_SIGNAL's signal (None for SIGEV_NONE)
    sig: Option<Signal>,
    sigev_value: u64,
}

/// Message queue
pub struct MqQueue {
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
    /// The creator's real uid and the bytes charged to it (Linux
    /// info->ucounts, mq_bytes), returned when the queue is freed
    charge: (u32, u64),
}

impl Drop for MqQueue {
    /// The queue is gone (unlinked, last file closed): its charges go
    /// (Linux mqueue_evict_inode)
    fn drop(&mut self) {
        mq_uncharge(self.charge.0, self.charge.1);
    }
}

impl MqQueue {
    /// "QSIZE:... NOTIFY:... SIGNO:... NOTIFY_PID:...\n" (Linux
    /// mqueue_read_file's format)
    fn status(&self) -> alloc::string::String {
        let qsize: usize = self.messages.lock().iter().map(|m| m.data.len()).sum();
        let (notify, signo, pid) = match self.notify.lock().as_ref() {
            Some(n) => (
                n.sigev_notify,
                n.sig.map_or(0, Signal::nr),
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

    /// A queue charged as `charge` (see [`mq_charge`])
    fn new(mode: u32, maxmsg: i64, msgsize: i64, charge: (u32, u64)) -> Self {
        // Get current task's effective uid/gid as owner
        let cred = crate::task::percpu::current_cred();
        Self {
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
            charge,
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
    ) -> KernelResult<()> {
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
                return Err(KernelError::WouldBlock);
            }

            // Wait for space (Linux wq_sleep: ERESTARTSYS, ETIMEDOUT)
            let room = || (self.messages.lock().len() as i64) < self.maxmsg;
            match self.waitq_send.wait_event_interruptible_deadline(
                room,
                deadline,
                HrClock::Realtime,
            ) {
                Ok(true) => {}
                Ok(false) => return Err(KernelError::TimedOut),
                Err(e) => return Err(e),
            }
        }
    }

    fn receive(&self, nonblock: bool, deadline: Option<u64>) -> KernelResult<(Vec<u8>, u32)> {
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
                return Err(KernelError::WouldBlock);
            }

            // Wait for messages
            let ready = || !self.messages.lock().is_empty();
            match self.waitq_recv.wait_event_interruptible_deadline(
                ready,
                deadline,
                HrClock::Realtime,
            ) {
                Ok(true) => {}
                Ok(false) => return Err(KernelError::TimedOut),
                Err(e) => return Err(e),
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
            if let Some(sig) = n.sig.filter(|_| live) {
                let info = mesgq_info(sig, n.sigev_value, &n.owner);
                // To the registrant's struct pid, never its number
                let _ = crate::signal::kill_pid_info(&n.owner, sig, info, |_| Ok(()));
            }
        }
    }
}

/// SI_MESGQ info from the current task, the process that made the queue
/// non-empty, as the registrant `owner`'s namespace numbers it, with its
/// sigev_value (Linux __do_notify: task_tgid_nr_ns(current,
/// ns_of_pid(notify_owner)))
fn mesgq_info(sig: Signal, value: u64, owner: &crate::task::pid::Pid) -> crate::signal::SendInfo {
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

/// The queues by name (Linux: the mqueue root directory, under its
/// i_rwsem): sleeping, as a create allocates the queue under it
static MQ_REGISTRY: RwSem<BTreeMap<FileName, Arc<MqQueue>>> = RwSem::new(BTreeMap::new());

static MQ_NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Queues in the system without CAP_SYS_RESOURCE (Linux
/// DFLT_QUEUESMAX, fs.mqueue.queues_max)
const QUEUES_MAX: u32 = 256;

/// sizeof(struct msg_msg) and sizeof(struct posix_msg_tree_node) on
/// 64-bit Linux: the per-message overhead in a queue's charge
const MSG_MSG_SIZE: u64 = 48;
const MSG_TREE_NODE_SIZE: u64 = 48;

/// The queue count and each user's queue bytes (Linux mq_lock over
/// ipc_ns->mq_queues_count and the UCOUNT_RLIMIT_MSGQUEUE ucounts); a
/// leaf, taken under `MQ_REGISTRY` by a create and by a queue's Drop
struct MqAcct {
    queues: u32,
    /// (uid, bytes) of each user with a charge; grown with the lock
    /// released (`kmem::spare`): nothing allocates under it
    bytes: Vec<(u32, u64)>,
}

static MQ_ACCT: Mutex<MqAcct> = Mutex::new(MqAcct {
    queues: 0,
    bytes: Vec::new(),
});

/// What a queue of `maxmsg` messages of `msgsize` bytes charges its
/// creator against RLIMIT_MSGQUEUE (Linux mqueue_get_inode's mq_bytes);
/// both positive and capped by mq_attr_ok, so the sum fits
fn mq_bytes(maxmsg: i64, msgsize: i64) -> u64 {
    let (m, s) = (maxmsg as u64, msgsize as u64);
    m * MSG_MSG_SIZE + m.min(u64::from(MQ_PRIO_MAX)) * MSG_TREE_NODE_SIZE + m * s
}

/// Charge a new queue of `bytes` to the caller's real uid (Linux
/// mqueue_create_attr, mqueue_get_inode): ENOSPC past QUEUES_MAX
/// without CAP_SYS_RESOURCE, EMFILE past `limit` (the caller's
/// RLIMIT_MSGQUEUE), ENOMEM; the charge. A user's first charge needs
/// room in the list: it is made with `MQ_ACCT` released and the check
/// repeated (Linux charges the cred's ucounts, made before)
fn mq_charge(bytes: u64, limit: u64) -> Result<(u32, u64), KernelError> {
    let uid = crate::task::percpu::current_cred().uid;
    let cap = crate::task::capable(crate::task::CAP_SYS_RESOURCE);
    loop {
        let full = 'locked: {
            let mut a = MQ_ACCT.lock();
            if a.queues >= QUEUES_MAX && !cap {
                return Err(KernelError::NoSpace);
            }
            let i = a.bytes.iter().position(|e| e.0 == uid);
            let cur = i.map_or(0, |i| a.bytes[i].1);
            let new = cur
                .checked_add(bytes)
                .filter(|&n| limit == rlimit::RLIM_INFINITY || n <= limit)
                .ok_or(KernelError::ProcessFileLimit)?;
            match i {
                Some(i) => a.bytes[i].1 = new,
                None if a.bytes.len() < a.bytes.capacity() => a.bytes.push((uid, new)),
                None => break 'locked a.bytes.capacity(),
            }
            a.queues += 1;
            return Ok((uid, bytes));
        };
        mq_grow(full)?;
    }
}

/// Room for one more user in `MQ_ACCT` if its list is still full at
/// `cap`: allocated, and the old list freed, with the lock released
fn mq_grow(cap: usize) -> Result<(), KernelError> {
    let bigger = crate::util::kmem::spare(cap)?;
    let old = crate::util::kmem::adopt(&mut MQ_ACCT.lock().bytes, bigger);
    drop(old);
    Ok(())
}

/// Return a queue's charge
fn mq_uncharge(uid: u32, bytes: u64) {
    let mut a = MQ_ACCT.lock();
    a.queues = a.queues.saturating_sub(1);
    if let Some(i) = a.bytes.iter().position(|e| e.0 == uid) {
        let b = &mut a.bytes[i].1;
        *b = b.saturating_sub(bytes);
        if *b == 0 {
            a.bytes.swap_remove(i);
        }
    }
}

fn create_mq_file(queue: Arc<MqQueue>, access_mode: i32, oflag: i32) -> KernelResult<Arc<File>> {
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
    ))?;

    let dentry = try_arc(Dentry::new_anonymous("mqueue".into(), Some(inode)))?;

    let mut file_flags = match access_mode {
        O_RDONLY => flags::O_RDONLY,
        O_WRONLY => flags::O_WRONLY,
        O_RDWR => flags::O_RDWR,
        _ => flags::O_RDWR,
    };

    if oflag & O_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let private = try_arc(MqFile { queue, access_mode })?;
    try_arc(File::new_anon(dentry, file_flags, &MQ_FOPS, private))
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

pub fn sys_mq_open(
    name_ptr: UserPtr<u8>,
    oflag: i32,
    mode: u32,
    attr_ptr: UserPtr<MqAttr>,
) -> KernelResult<i32> {
    // Longer than NAME_MAX: ENAMETOOLONG (Linux: the lookup of the
    // name in the mqueue root)
    let name = strncpy_from_user::<Uaccess>(name_ptr.addr(), NAME_MAX + 1)?;
    validate_mq_name(&name)?;
    let queue_name = name;
    let access_mode = oflag & O_ACCMODE;

    // Check flags
    let creating = (oflag & O_CREAT) != 0;
    let exclusive = (oflag & O_EXCL) != 0;

    // Attributes are read before the registry is locked (Linux do_mq_open
    // copies them first; no user access under a spinlock)
    let attr_in = if creating && !attr_ptr.is_null() {
        Some(attr_ptr.read()?)
    } else {
        None
    };

    // Read before the registry's spin lock
    let msgq_limit = rlimit::rlimit(rlimit::RLIMIT_MSGQUEUE);

    // Try to find or create queue
    let queue = {
        let mut registry = MQ_REGISTRY.write();

        if let Some(q) = registry.get(queue_name.as_slice()) {
            if creating && exclusive {
                return Err(KernelError::AlreadyExists);
            }
            // Check access permissions
            if !q.check_access(access_mode) {
                return Err(KernelError::PermissionDenied);
            }
            q.clone()
        } else {
            if !creating {
                return Err(KernelError::NotFound);
            }

            // Read attributes if provided (Linux mq_attr_ok)
            let (maxmsg, msgsize) = match attr_in {
                Some(attr) => mq_attr_ok(attr.mq_maxmsg, attr.mq_msgsize)?,
                None => (DFLT_MSGMAX, DFLT_MSGSIZEMAX),
            };

            let charge = mq_charge(mq_bytes(maxmsg, msgsize), msgq_limit)?;
            // A queue that cannot be made returns its charge as it drops
            let queue = try_arc(MqQueue::new(mode, maxmsg, msgsize, charge))?;

            // Set initial flags
            if oflag & O_NONBLOCK != 0 {
                queue.set_flags(i64::from(O_NONBLOCK));
            }

            registry.insert(queue_name.into(), queue.clone());
            queue
        }
    };

    let file = create_mq_file(queue, access_mode, oflag)?;
    let fd_flags = if oflag & O_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };
    fd_install(file, fd_flags)
}

/// mq_unlink - remove a message queue
pub fn sys_mq_unlink(name_ptr: UserPtr<u8>) -> KernelResult<()> {
    // Longer than NAME_MAX: ENAMETOOLONG (Linux: the lookup of the
    // name in the mqueue root)
    let name = strncpy_from_user::<Uaccess>(name_ptr.addr(), NAME_MAX + 1)?;
    validate_mq_name(&name)?;
    let queue_name = name;

    let mut registry = MQ_REGISTRY.write();
    let q = registry
        .get(queue_name.as_slice())
        .ok_or(KernelError::NotFound)?;
    // The mqueue root's sticky bit (Linux may_delete): EPERM
    if !q.may_unlink() {
        return Err(KernelError::NotPermitted);
    }
    registry.remove(queue_name.as_slice());
    Ok(())
}

/// The absolute CLOCK_REALTIME deadline of a timeout (`struct timespec
/// *`, NULL = none; EINVAL for a bad tv_nsec, EFAULT), kept on that clock
/// so it follows clock_settime (Linux do_mq_timedsend: HRTIMER_MODE_ABS)
fn mq_deadline(abs: UserPtr<[i64; 2]>) -> KernelResult<Option<u64>> {
    if abs.is_null() {
        return Ok(None);
    }
    let [sec, nsec] = abs.read()?;
    if !(0..1_000_000_000).contains(&nsec) || sec < 0 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(Some(crate::time::timespec_to_ns(sec, nsec)))
}

/// mq_timedsend - send a message to a queue
pub fn sys_mq_timedsend(
    mqdes: i32,
    msg_ptr: UserPtr<u8>,
    msg_len: usize,
    msg_prio: u32,
    abs_timeout: UserPtr<[i64; 2]>,
) -> KernelResult<()> {
    // Validate priority
    if msg_prio >= MQ_PRIO_MAX {
        return Err(KernelError::InvalidArgument);
    }
    let file = fget(mqdes)?;
    let mq_ops = mq_of(&file).ok_or(KernelError::BadFd)?;

    // Check write permission
    if mq_ops.access_mode == O_RDONLY {
        return Err(KernelError::BadFd);
    }

    // Check message size (msgsize is positive: mq_attr_ok)
    if msg_len > mq_ops.queue.msgsize as usize {
        return Err(KernelError::MessageTooLong);
    }

    // Read message from user space (bounded by msgsize, fallible)
    let mut msg_buf = crate::util::kmem::try_vec(msg_len, 0u8)?;
    if msg_len > 0 {
        copy_from_user::<Uaccess>(&mut msg_buf, msg_ptr.addr(), msg_len)?;
    }

    let deadline = mq_deadline(abs_timeout)?;
    let nonblock = mq_ops.queue.is_nonblocking();
    mq_ops.queue.send(msg_buf, msg_prio, nonblock, deadline)
}

/// mq_timedreceive - receive a message from a queue
pub fn sys_mq_timedreceive(
    mqdes: i32,
    msg_ptr: UserPtr<u8>,
    msg_len: usize,
    prio_ptr: UserPtr<u32>,
    abs_timeout: UserPtr<[i64; 2]>,
) -> KernelResult<usize> {
    let file = fget(mqdes)?;
    let mq_ops = mq_of(&file).ok_or(KernelError::BadFd)?;

    // Check read permission
    if mq_ops.access_mode == O_WRONLY {
        return Err(KernelError::BadFd);
    }

    // Check buffer size (msgsize is positive: mq_attr_ok)
    if msg_len < mq_ops.queue.msgsize as usize {
        return Err(KernelError::MessageTooLong);
    }

    let deadline = mq_deadline(abs_timeout)?;
    let nonblock = mq_ops.queue.is_nonblocking();
    let (data, prio) = mq_ops.queue.receive(nonblock, deadline)?;
    let len = data.len().min(msg_len);

    // Write message to user space
    if len > 0 {
        copy_to_user::<Uaccess>(msg_ptr.addr(), &data[..len])?;
    }

    // Write priority if requested
    if !prio_ptr.is_null() {
        prio_ptr.write(&prio)?;
    }

    Ok(len)
}

/// mq_notify - register for notification
pub fn sys_mq_notify(mqdes: i32, sevp_ptr: UserPtr<SigEvent>) -> KernelResult<()> {
    // The sigevent is read and checked before the descriptor is looked
    // up (Linux sys_mq_notify, do_mq_notify)
    let sev = if sevp_ptr.is_null() {
        None
    } else {
        Some(notify_event(sevp_ptr.read()?)?)
    };
    let file = fget(mqdes)?;
    let mq_ops = mq_of(&file).ok_or(KernelError::BadFd)?;

    let current_pid = crate::task::percpu::current_pid();

    let Some((sev, sig)) = sev else {
        // Remove notification (only if we own it)
        let mut notify = mq_ops.queue.notify.lock();
        if notify
            .as_ref()
            .is_some_and(|n| u64::from(n.owner.nr()) == current_pid)
        {
            *notify = None;
        }
        return Ok(()); // Not an error to remove non-existent
    };

    // Check if already registered by another process
    let owner = u32::try_from(current_pid)
        .ok()
        .and_then(|nr| crate::task::pid::find_pid(&crate::ns::INIT_PID_NS, nr))
        .ok_or(KernelError::NoProcess)?;
    let mut notify = mq_ops.queue.notify.lock();
    if notify
        .as_ref()
        .is_some_and(|n| u64::from(n.owner.nr()) != current_pid)
    {
        return Err(KernelError::Busy);
    }

    // Register notification
    *notify = Some(MqNotify {
        exec_gen: owner.exec_gen(),
        owner,
        sigev_notify: sev.sigev_notify,
        sig,
        sigev_value: sev.sigev_value,
    });

    Ok(())
}

/// mq_notify's sigevent and its signal, or EINVAL (Linux do_mq_notify):
/// SIGEV_NONE, or SIGEV_SIGNAL with a signal (not 0, not past NSIG)
fn notify_event(sev: SigEvent) -> KernelResult<(SigEvent, Option<Signal>)> {
    match sev.sigev_notify {
        SIGEV_NONE => Ok((sev, None)),
        SIGEV_SIGNAL => {
            let sig = u32::try_from(sev.sigev_signo).ok().and_then(Signal::new);
            Ok((sev, Some(sig.ok_or(KernelError::InvalidArgument)?)))
        }
        // Linux mqueue notify does not take SIGEV_THREAD_ID (only
        // timers do); SIGEV_THREAD (a netlink notice) is not supported
        SIGEV_THREAD_ID | SIGEV_THREAD => Err(KernelError::InvalidArgument),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// mq_getsetattr - get/set message queue attributes
pub fn sys_mq_getsetattr(
    mqdes: i32,
    newattr_ptr: UserPtr<MqAttr>,
    oldattr_ptr: UserPtr<MqAttr>,
) -> KernelResult<()> {
    let file = fget(mqdes)?;
    let mq_ops = mq_of(&file).ok_or(KernelError::BadFd)?;

    // Get old attributes if requested
    if !oldattr_ptr.is_null() {
        oldattr_ptr.write(&mq_ops.queue.get_attr())?;
    }

    // Set new attributes if provided
    if !newattr_ptr.is_null() {
        let new_attr = newattr_ptr.read()?;
        // Only mq_flags (O_NONBLOCK) can be changed
        mq_ops.queue.set_flags(new_attr.mq_flags);
    }

    Ok(())
}
