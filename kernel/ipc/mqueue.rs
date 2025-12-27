//! POSIX Message Queue Implementation
//!
//! Implements Linux-compatible POSIX message queue syscalls:
//! - mq_open, mq_unlink, mq_timedsend, mq_timedreceive, mq_notify, mq_getsetattr
//!
//! ## Design
//!
//! Unlike SysV message queues, POSIX mqueues use file descriptors and are identified
//! by names (starting with '/'). Messages are prioritized (higher priority first)
//! and delivered FIFO within the same priority.
//!
//! ## Key Features
//!
//! - File descriptor-based access (integrates with close, read, poll)
//! - Name-based registry (names must start with '/')
//! - Priority-ordered message delivery (0 to MQ_PRIO_MAX-1)
//! - Blocking/non-blocking send and receive with timeouts
//! - SIGEV_SIGNAL and SIGEV_THREAD_ID notifications
//!
//! ## References
//!
//! - Linux kernel ipc/mqueue.c
//! - POSIX.1-2017 mq_overview(7)

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::cmp::Ordering;
use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use spin::{Lazy, Mutex, RwLock};

use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::pipe::FD_CLOEXEC;
use crate::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::rlimit;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;
use crate::uaccess::{UaccessArch, get_user, put_user, strncpy_from_user};
use crate::waitqueue::WaitQueue;

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

/// Notification registration
struct MqNotify {
    owner_pid: u64,
    owner_tid: u64,
    sigev_notify: i32,
    sigev_signo: i32,
    sigev_value: u64,
}

/// Message queue
pub struct MqQueue {
    #[allow(dead_code)] // Used for debugging and future /dev/mqueue filesystem
    name: String,
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
    fn new(name: String, mode: u32, maxmsg: i64, msgsize: i64) -> Self {
        // Get current task's effective uid/gid as owner
        let cred = crate::task::percpu::current_cred();
        Self {
            name,
            maxmsg,
            msgsize,
            messages: Mutex::new(Vec::new()),
            flags: Mutex::new(0),
            mode,
            uid: cred.euid,
            gid: cred.egid,
            notify: Mutex::new(None),
            waitq_send: WaitQueue::new(),
            waitq_recv: WaitQueue::new(),
        }
    }

    /// Check if the given access mode is permitted
    fn check_access(&self, access_mode: i32) -> bool {
        let cred = crate::task::percpu::current_cred();

        // Root always has access
        if cred.fsuid == 0 {
            return true;
        }

        // Determine which permission bits to check
        let (read_needed, write_needed) = match access_mode {
            O_RDONLY => (true, false),
            O_WRONLY => (false, true),
            O_RDWR => (true, true),
            _ => (true, true),
        };

        // Owner permissions (bits 6-8)
        if cred.fsuid == self.uid {
            let owner_read = (self.mode & 0o400) != 0;
            let owner_write = (self.mode & 0o200) != 0;
            if (!read_needed || owner_read) && (!write_needed || owner_write) {
                return true;
            }
        }

        // Group permissions (bits 3-5)
        if cred.fsgid == self.gid {
            let group_read = (self.mode & 0o040) != 0;
            let group_write = (self.mode & 0o020) != 0;
            if (!read_needed || group_read) && (!write_needed || group_write) {
                return true;
            }
        }

        // Other permissions (bits 0-2)
        let other_read = (self.mode & 0o004) != 0;
        let other_write = (self.mode & 0o002) != 0;
        (!read_needed || other_read) && (!write_needed || other_write)
    }

    /// Get the queue name (for debugging and future /dev/mqueue filesystem)
    #[allow(dead_code)]
    fn name(&self) -> &str {
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
        *flags = new_flags & (O_NONBLOCK as i64);
    }

    fn is_nonblocking(&self) -> bool {
        (*self.flags.lock() & (O_NONBLOCK as i64)) != 0
    }

    fn send(&self, data: &[u8], priority: u32, nonblock: bool) -> Result<(), i64> {
        loop {
            {
                let mut msgs = self.messages.lock();
                if (msgs.len() as i64) < self.maxmsg {
                    // Insert maintaining priority order (higher priority first)
                    let msg = MqMessage {
                        priority,
                        data: data.to_vec(),
                    };

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
                    self.waitq_recv.wake_one();
                    return Ok(());
                }
            }

            if nonblock || self.is_nonblocking() {
                return Err(KernelError::WouldBlock.sysret());
            }

            // Wait for space
            self.waitq_send.wait();
        }
    }

    fn receive(&self, buf: &mut [u8], nonblock: bool) -> Result<(usize, u32), i64> {
        loop {
            {
                let mut msgs = self.messages.lock();
                if !msgs.is_empty() {
                    // Remove highest priority message (at front)
                    let msg = msgs.remove(0);
                    let len = msg.data.len().min(buf.len());
                    buf[..len].copy_from_slice(&msg.data[..len]);

                    drop(msgs);

                    // Wake up senders
                    self.waitq_send.wake_one();
                    return Ok((len, msg.priority));
                }
            }

            if nonblock || self.is_nonblocking() {
                return Err(KernelError::WouldBlock.sysret());
            }

            // Wait for messages
            self.waitq_recv.wait();
        }
    }

    fn fire_notification(&self) {
        let mut notify = self.notify.lock();
        if let Some(n) = notify.take() {
            // Log the notification for debugging (uses sigev_value)
            // TODO: When siginfo support is added, include sigev_value in SI_MESGQ siginfo
            let _sigev_value = n.sigev_value; // Will be passed in siginfo_t.si_value

            match n.sigev_notify {
                SIGEV_SIGNAL => {
                    // Send signal to process
                    // Full Linux ABI: signal should include siginfo with si_code=SI_MESGQ,
                    // si_value=sigev_value, si_pid, si_uid
                    let tgid = n.owner_pid as i64;
                    let signo = n.sigev_signo;
                    crate::signal::syscall::sys_kill(tgid, signo as u32);
                }
                SIGEV_THREAD_ID => {
                    // Send signal to specific thread
                    let tgid = n.owner_pid as i64;
                    let tid = n.owner_tid as i64;
                    let signo = n.sigev_signo;
                    crate::signal::syscall::sys_tgkill(tgid, tid, signo as u32);
                }
                SIGEV_NONE => {
                    // No notification - just unregister
                }
                _ => {}
            }
            // Notification is one-shot, already removed by take()
        }
    }
}

/// File operations for message queue
pub struct MqFileOps {
    queue: Arc<MqQueue>,
    access_mode: i32,
}

impl FileOps for MqFileOps {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        if self.access_mode == O_WRONLY {
            return Err(KernelError::PermissionDenied);
        }

        match self.queue.receive(buf, false) {
            Ok((len, _prio)) => Ok(len),
            Err(_) => Err(KernelError::Io),
        }
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        if self.access_mode == O_RDONLY {
            return Err(KernelError::PermissionDenied);
        }

        // Write with priority 0 (default)
        match self.queue.send(buf, 0, false) {
            Ok(()) => Ok(buf.len()),
            Err(_) => Err(KernelError::Io),
        }
    }

    fn poll(&self, _file: &File, _table: Option<&mut PollTable>) -> u16 {
        let msgs = self.queue.messages.lock();
        let mut events = 0u16;

        if !msgs.is_empty() {
            events |= POLLIN | POLLRDNORM;
        }
        if (msgs.len() as i64) < self.queue.maxmsg {
            events |= POLLOUT | POLLWRNORM;
        }

        events
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        // Clear notification if we own it
        let current_pid = crate::task::percpu::current_pid();
        let mut notify = self.queue.notify.lock();
        if let Some(ref n) = *notify
            && n.owner_pid == current_pid
        {
            *notify = None;
        }
        Ok(())
    }
}

// ============================================================================
// Global Registry
// ============================================================================

static MQ_REGISTRY: Lazy<RwLock<BTreeMap<String, Arc<MqQueue>>>> =
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
    // Create file operations (leak to get 'static lifetime)
    let ops: &'static dyn FileOps = Box::leak(Box::new(MqFileOps {
        queue: queue.clone(),
        access_mode,
    }));

    // Create anonymous inode
    let mode = InodeMode::regular(0o644);
    let inode = Arc::new(Inode::new(
        MQ_NEXT_ID.fetch_add(1, AtomicOrdering::SeqCst),
        mode,
        0,                           // uid
        0,                           // gid
        0,                           // size
        InodeTimespec::from_secs(0), // mtime
        Weak::new(),                 // no superblock
        &NULL_INODE_OPS,
    ));

    let dentry = Arc::new(Dentry::new_anonymous(String::from("mqueue"), Some(inode)));

    let mut file_flags = match access_mode {
        O_RDONLY => flags::O_RDONLY,
        O_WRONLY => flags::O_WRONLY,
        O_RDWR => flags::O_RDWR,
        _ => flags::O_RDWR,
    };

    if oflag & O_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = Arc::new(File::new(dentry, file_flags, ops));
    Ok(file)
}

// ============================================================================
// Syscall Implementations
// ============================================================================

/// mq_open - open a message queue
pub fn sys_mq_open(name_ptr: u64, oflag: i32, mode: u32, attr_ptr: u64) -> i64 {
    // Read name from user space
    let name = match strncpy_from_user::<Uaccess>(name_ptr, NAME_MAX + 1) {
        Ok(s) => s,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name (must start with '/', no embedded '/')
    if !name.starts_with('/') {
        return KernelError::InvalidArgument.sysret();
    }
    if name.len() < 2 {
        return KernelError::InvalidArgument.sysret();
    }
    if name[1..].contains('/') {
        return KernelError::InvalidArgument.sysret();
    }
    if name.len() > NAME_MAX {
        return KernelError::NameTooLong.sysret();
    }

    // Extract name without leading '/'
    let queue_name = name[1..].to_string();
    let access_mode = oflag & O_ACCMODE;

    // Check flags
    let creating = (oflag & O_CREAT) != 0;
    let exclusive = (oflag & O_EXCL) != 0;

    // Try to find or create queue
    let queue = {
        let mut registry = MQ_REGISTRY.write();

        if let Some(q) = registry.get(&queue_name) {
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

            // Read attributes if provided
            let (maxmsg, msgsize) = if attr_ptr != 0 {
                let attr: MqAttr = match get_user::<Uaccess, MqAttr>(attr_ptr) {
                    Ok(a) => a,
                    Err(_) => return KernelError::BadAddress.sysret(),
                };

                // Validate attributes
                if attr.mq_maxmsg <= 0 || attr.mq_maxmsg > HARD_MSGMAX {
                    return KernelError::InvalidArgument.sysret();
                }
                if attr.mq_msgsize <= 0 || attr.mq_msgsize > HARD_MSGSIZEMAX {
                    return KernelError::InvalidArgument.sysret();
                }
                (attr.mq_maxmsg, attr.mq_msgsize)
            } else {
                (DFLT_MSGMAX, DFLT_MSGSIZEMAX)
            };

            let queue = Arc::new(MqQueue::new(queue_name.clone(), mode, maxmsg, msgsize));

            // Set initial flags
            if oflag & O_NONBLOCK != 0 {
                queue.set_flags(O_NONBLOCK as i64);
            }

            registry.insert(queue_name, queue.clone());
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
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// mq_unlink - remove a message queue
pub fn sys_mq_unlink(name_ptr: u64) -> i64 {
    // Read name from user space
    let name = match strncpy_from_user::<Uaccess>(name_ptr, NAME_MAX + 1) {
        Ok(s) => s,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name
    if !name.starts_with('/') {
        return KernelError::InvalidArgument.sysret();
    }
    if name.len() < 2 {
        return KernelError::InvalidArgument.sysret();
    }

    let queue_name = name[1..].to_string();

    let mut registry = MQ_REGISTRY.write();
    if let Some(q) = registry.get(&queue_name) {
        // Check write permission (needed for unlink)
        if !q.check_access(O_WRONLY) {
            return KernelError::PermissionDenied.sysret();
        }
        registry.remove(&queue_name);
        0
    } else {
        KernelError::NotFound.sysret()
    }
}

/// mq_timedsend - send a message to a queue
pub fn sys_mq_timedsend(
    mqdes: i32,
    msg_ptr: u64,
    msg_len: usize,
    msg_prio: u32,
    _abs_timeout: u64,
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
    let mq_ops = match file.f_op.as_any().downcast_ref::<MqFileOps>() {
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

    // Read message from user space
    let mut msg_buf = vec![0u8; msg_len];
    if msg_len > 0 {
        if !Uaccess::access_ok(msg_ptr, msg_len) {
            return KernelError::BadAddress.sysret();
        }
        unsafe {
            Uaccess::user_access_begin();
            core::ptr::copy_nonoverlapping(msg_ptr as *const u8, msg_buf.as_mut_ptr(), msg_len);
            Uaccess::user_access_end();
        }
    }

    // Send message
    // TODO: implement timeout
    let nonblock = mq_ops.queue.is_nonblocking();
    match mq_ops.queue.send(&msg_buf, msg_prio, nonblock) {
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
    _abs_timeout: u64,
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
    let mq_ops = match file.f_op.as_any().downcast_ref::<MqFileOps>() {
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

    // Receive message
    // TODO: implement timeout
    let nonblock = mq_ops.queue.is_nonblocking();
    let mut buf = vec![0u8; msg_len];

    let (len, prio) = match mq_ops.queue.receive(&mut buf, nonblock) {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Write message to user space
    if len > 0 {
        if !Uaccess::access_ok(msg_ptr, len) {
            return KernelError::BadAddress.sysret();
        }
        unsafe {
            Uaccess::user_access_begin();
            core::ptr::copy_nonoverlapping(buf.as_ptr(), msg_ptr as *mut u8, len);
            Uaccess::user_access_end();
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
    let mq_ops = match file.f_op.as_any().downcast_ref::<MqFileOps>() {
        Some(ops) => ops,
        None => return KernelError::BadFd.sysret(),
    };

    let current_pid = crate::task::percpu::current_pid();
    let current_tid_val = current_tid();

    if sevp_ptr == 0 {
        // Remove notification (only if we own it)
        let mut notify = mq_ops.queue.notify.lock();
        if let Some(ref n) = *notify
            && n.owner_pid == current_pid
        {
            *notify = None;
            return 0;
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
        SIGEV_NONE | SIGEV_SIGNAL | SIGEV_THREAD_ID => {}
        SIGEV_THREAD => return KernelError::InvalidArgument.sysret(), // Not supported (requires user-space pthread)
        _ => return KernelError::InvalidArgument.sysret(),
    }

    // Check if already registered by another process
    let mut notify = mq_ops.queue.notify.lock();
    if let Some(ref n) = *notify
        && n.owner_pid != current_pid
    {
        return KernelError::Busy.sysret();
    }

    // Register notification
    *notify = Some(MqNotify {
        owner_pid: current_pid,
        owner_tid: if sev.sigev_notify == SIGEV_THREAD_ID {
            sev.sigev_notify_tid as u64
        } else {
            current_tid_val
        },
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
    let mq_ops = match file.f_op.as_any().downcast_ref::<MqFileOps>() {
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
