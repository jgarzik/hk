//! System V Message Queue Implementation
//!
//! Provides message queues for inter-process communication with support for:
//! - Multiple message types for selective receiving
//! - Blocking send/receive with optional timeout
//! - Per-queue byte limits

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};

use crate::arch::Uaccess;
use crate::ipc::util::{
    IPC_PERM_READ, IPC_PERM_WRITE, IpcObject, IpcType, KernIpcPerm, ipc_checkperm, ipcget,
};
use crate::ipc::{
    IPC_64, IPC_NOWAIT, IPC_RMID, IPC_SET, IPC_STAT, IpcNamespace, Msqid64Ds, current_ipc_ns,
};
use crate::task::percpu::current_pid;
use crate::time::TIMEKEEPER;
use crate::uaccess::{copy_from_user, copy_to_user, get_user, put_user};
use crate::waitqueue::WaitQueue;
use spin::Mutex;

// Error codes
const EINVAL: i32 = 22;
#[allow(dead_code)]
const ENOMEM: i32 = 12;
const EPERM: i32 = 1;
const EIDRM: i32 = 43;
const E2BIG: i32 = 7;
const EAGAIN: i32 = 11;
const ENOMSG: i32 = 42;
const EMSGSIZE: i32 = 90;
const EFAULT: i32 = 14;

/// Get current time in seconds
fn current_time_secs() -> i64 {
    TIMEKEEPER.current_time().sec
}

// ============================================================================
// Message Queue Constants
// ============================================================================

/// Don't truncate message if too big
pub const MSG_NOERROR: i32 = 0o10000;
/// Receive any message except specified type
pub const MSG_EXCEPT: i32 = 0o20000;
/// Copy message without removing
pub const MSG_COPY: i32 = 0o40000;

/// msgctl commands
pub const MSG_STAT: i32 = 11;
pub const MSG_INFO: i32 = 12;

// ============================================================================
// Message Structures
// ============================================================================

/// A single message
pub struct MsgMsg {
    /// Message type (must be > 0)
    pub mtype: i64,
    /// Message data
    pub mtext: Vec<u8>,
}

/// Waiting receiver
#[allow(dead_code)]
struct MsgReceiver {
    tid: u64,
    msgtype: i64,
    maxsize: usize,
    mode: i32,
    result: Mutex<Option<Result<MsgMsg, i32>>>,
    woken: AtomicBool,
}

/// Waiting sender
#[allow(dead_code)]
struct MsgSender {
    tid: u64,
    msg: MsgMsg,
    woken: AtomicBool,
    result: AtomicI32,
}

/// Message queue
pub struct MsgQueue {
    /// IPC permissions and ID
    pub perm: KernIpcPerm,
    /// Last msgsnd time
    pub stime: AtomicI64,
    /// Last msgrcv time
    pub rtime: AtomicI64,
    /// Last change time
    pub ctime: AtomicI64,
    /// Current bytes in queue
    pub cbytes: AtomicU64,
    /// Current number of messages
    pub qnum: AtomicU32,
    /// Maximum bytes allowed
    pub qbytes: u64,
    /// Last sender PID
    pub lspid: AtomicI32,
    /// Last receiver PID
    pub lrpid: AtomicI32,
    /// Message list
    pub messages: Mutex<VecDeque<MsgMsg>>,
    /// Waiting receivers
    receivers: Mutex<VecDeque<Arc<MsgReceiver>>>,
    /// Waiting senders
    senders: Mutex<VecDeque<Arc<MsgSender>>>,
    /// Wait queue for blocked operations
    pub waitq: WaitQueue,
    /// Namespace reference
    ns: Arc<IpcNamespace>,
}

impl MsgQueue {
    /// Create a new message queue
    pub fn new(key: i32, mode: u16, ns: Arc<IpcNamespace>) -> Result<Arc<Self>, i32> {
        let now = current_time_secs();

        Ok(Arc::new(Self {
            perm: KernIpcPerm::new(key, mode),
            stime: AtomicI64::new(0),
            rtime: AtomicI64::new(0),
            ctime: AtomicI64::new(now),
            cbytes: AtomicU64::new(0),
            qnum: AtomicU32::new(0),
            qbytes: ns.msg_ctlmnb as u64,
            lspid: AtomicI32::new(0),
            lrpid: AtomicI32::new(0),
            messages: Mutex::new(VecDeque::new()),
            receivers: Mutex::new(VecDeque::new()),
            senders: Mutex::new(VecDeque::new()),
            waitq: WaitQueue::new(),
            ns,
        }))
    }

    /// Find a message matching the type criteria
    fn find_msg(&self, msgtyp: i64, msgflg: i32) -> Option<MsgMsg> {
        let mut messages = self.messages.lock();

        if msgtyp == 0 {
            // Return first message
            return messages.pop_front();
        }

        let except = msgflg & MSG_EXCEPT != 0;

        if msgtyp > 0 {
            // Find message of exact type (or not that type if MSG_EXCEPT)
            for i in 0..messages.len() {
                let matches = if except {
                    messages[i].mtype != msgtyp
                } else {
                    messages[i].mtype == msgtyp
                };

                if matches {
                    return messages.remove(i);
                }
            }
        } else {
            // msgtyp < 0: find lowest type <= |msgtyp|
            let max_type = -msgtyp;
            let mut best_idx = None;
            let mut best_type = i64::MAX;

            for i in 0..messages.len() {
                if messages[i].mtype <= max_type && messages[i].mtype < best_type {
                    best_type = messages[i].mtype;
                    best_idx = Some(i);
                }
            }

            if let Some(idx) = best_idx {
                return messages.remove(idx);
            }
        }

        None
    }

    /// Try to deliver message to a waiting receiver
    fn try_deliver_to_receiver(&self, msg: &MsgMsg) -> bool {
        let mut receivers = self.receivers.lock();

        for i in 0..receivers.len() {
            let receiver = &receivers[i];

            // Check type match
            let matches = if receiver.msgtype == 0 {
                true
            } else if receiver.msgtype > 0 {
                if receiver.mode & MSG_EXCEPT != 0 {
                    msg.mtype != receiver.msgtype
                } else {
                    msg.mtype == receiver.msgtype
                }
            } else {
                msg.mtype <= -receiver.msgtype
            };

            if matches {
                // Check size
                if msg.mtext.len() > receiver.maxsize && receiver.mode & MSG_NOERROR == 0 {
                    // Message too big and no truncation allowed
                    continue;
                }

                // Deliver message
                let truncated_msg = MsgMsg {
                    mtype: msg.mtype,
                    mtext: if msg.mtext.len() > receiver.maxsize {
                        msg.mtext[..receiver.maxsize].to_vec()
                    } else {
                        msg.mtext.clone()
                    },
                };

                {
                    let mut result = receiver.result.lock();
                    *result = Some(Ok(truncated_msg));
                }
                receiver.woken.store(true, Ordering::Release);
                receivers.remove(i);
                self.waitq.wake_one();
                return true;
            }
        }

        false
    }

    /// Fill msqid64_ds structure for IPC_STAT
    pub fn fill_msqid64_ds(&self, ds: &mut Msqid64Ds) {
        self.perm.fill_ipc64_perm(&mut ds.msg_perm);
        ds.msg_stime = self.stime.load(Ordering::Relaxed);
        ds.msg_rtime = self.rtime.load(Ordering::Relaxed);
        ds.msg_ctime = self.ctime.load(Ordering::Relaxed);
        ds.msg_cbytes = self.cbytes.load(Ordering::Relaxed);
        ds.msg_qnum = self.qnum.load(Ordering::Relaxed) as u64;
        ds.msg_qbytes = self.qbytes;
        ds.msg_lspid = self.lspid.load(Ordering::Relaxed);
        ds.msg_lrpid = self.lrpid.load(Ordering::Relaxed);
        ds.__unused4 = 0;
        ds.__unused5 = 0;
    }
}

impl IpcObject for MsgQueue {
    fn perm(&self) -> &KernIpcPerm {
        &self.perm
    }

    fn ipc_type(&self) -> IpcType {
        IpcType::Msg
    }

    fn destroy(&self) {
        // Wake all waiting receivers with EIDRM
        {
            let mut receivers = self.receivers.lock();
            for receiver in receivers.drain(..) {
                {
                    let mut result = receiver.result.lock();
                    *result = Some(Err(EIDRM));
                }
                receiver.woken.store(true, Ordering::Release);
            }
        }

        // Wake all waiting senders with EIDRM
        {
            let mut senders = self.senders.lock();
            for sender in senders.drain(..) {
                sender.result.store(-EIDRM, Ordering::Release);
                sender.woken.store(true, Ordering::Release);
            }
        }

        self.waitq.wake_all();

        // Update namespace counters
        let bytes = self.cbytes.load(Ordering::Relaxed);
        let hdrs = self.qnum.load(Ordering::Relaxed) as u64;
        self.ns.msg_bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.ns.msg_hdrs.fetch_sub(hdrs, Ordering::Relaxed);
    }
}

// ============================================================================
// Safe Downcasting
// ============================================================================

/// Safely downcast an IpcObject to MsgQueue
///
/// Returns None if the object is not a message queue.
/// This is safe because we verify the type tag before casting.
fn downcast_msg(obj: &dyn IpcObject) -> Option<&MsgQueue> {
    if obj.ipc_type() == IpcType::Msg {
        // SAFETY: We verified the type tag matches, so this cast is valid.
        // The IpcType::Msg tag is only returned by MsgQueue::ipc_type().
        Some(unsafe { &*(obj as *const dyn IpcObject as *const MsgQueue) })
    } else {
        None
    }
}

// ============================================================================
// Syscalls
// ============================================================================

/// Convert Result to syscall return value
fn result_to_i64(res: Result<i32, i32>) -> i64 {
    match res {
        Ok(v) => v as i64,
        Err(e) => -(e as i64),
    }
}

/// msgget - get message queue
///
/// # Arguments
/// * `key` - Key to identify queue
/// * `msgflg` - Flags (IPC_CREAT, IPC_EXCL, permission bits)
pub fn sys_msgget(key: i32, msgflg: i32) -> i64 {
    result_to_i64(do_msgget(key, msgflg))
}

fn do_msgget(key: i32, msgflg: i32) -> Result<i32, i32> {
    let ns = current_ipc_ns();
    let ns_clone = ns.clone();

    ipcget(ns.msg_ids(), key, msgflg, ns.msg_ctlmni, move |k, mode| {
        MsgQueue::new(k, mode, ns_clone.clone())
    })
}

/// msgsnd - send message
///
/// # Arguments
/// * `msqid` - Queue ID
/// * `msgp` - Pointer to msgbuf (mtype + mtext)
/// * `msgsz` - Size of mtext
/// * `msgflg` - Flags (IPC_NOWAIT)
pub fn sys_msgsnd(msqid: i32, msgp: u64, msgsz: usize, msgflg: i32) -> i64 {
    result_to_i64(do_msgsnd(msqid, msgp, msgsz, msgflg))
}

fn do_msgsnd(msqid: i32, msgp: u64, msgsz: usize, msgflg: i32) -> Result<i32, i32> {
    let ns = current_ipc_ns();

    // Validate size
    if msgsz > ns.msg_ctlmax as usize {
        return Err(EMSGSIZE);
    }

    // Read message type
    let mtype: i64 = get_user::<Uaccess, i64>(msgp).map_err(|_| EFAULT)?;

    if mtype <= 0 {
        return Err(EINVAL);
    }

    // Read message data
    let mut mtext = vec![0u8; msgsz];
    if msgsz > 0 {
        let data_ptr = msgp + 8; // Skip mtype (i64 = 8 bytes)
        copy_from_user::<Uaccess>(&mut mtext, data_ptr, msgsz).map_err(|_| EFAULT)?;
    }

    let msg = MsgMsg { mtype, mtext };

    // Find queue
    let queue = ns.msg_ids().find_by_id(msqid).ok_or(EINVAL)?;

    let queue: &MsgQueue = unsafe { &*(queue.as_ref() as *const dyn IpcObject as *const MsgQueue) };

    // Check write permission
    ipc_checkperm(&queue.perm, IPC_PERM_WRITE)?;

    let nowait = msgflg & IPC_NOWAIT != 0;
    let pid = current_pid() as i32;

    loop {
        // Try to deliver directly to a waiting receiver
        if queue.try_deliver_to_receiver(&msg) {
            queue.stime.store(current_time_secs(), Ordering::Release);
            queue.lspid.store(pid, Ordering::Release);
            queue.perm.put_ref();
            return Ok(0);
        }

        // Check queue limits
        let current_bytes = queue.cbytes.load(Ordering::Acquire);
        if current_bytes + msgsz as u64 > queue.qbytes {
            if nowait {
                queue.perm.put_ref();
                return Err(EAGAIN);
            }

            // Block until space available
            // For simplicity, just sleep and retry
            // A full implementation would add to senders queue
            queue.waitq.wait();
            continue;
        }

        // Add message to queue
        {
            let mut messages = queue.messages.lock();
            messages.push_back(MsgMsg {
                mtype: msg.mtype,
                mtext: msg.mtext.clone(),
            });
        }

        queue.cbytes.fetch_add(msgsz as u64, Ordering::AcqRel);
        queue.qnum.fetch_add(1, Ordering::AcqRel);
        queue.stime.store(current_time_secs(), Ordering::Release);
        queue.lspid.store(pid, Ordering::Release);

        // Update namespace counters
        ns.msg_bytes.fetch_add(msgsz as u64, Ordering::Relaxed);
        ns.msg_hdrs.fetch_add(1, Ordering::Relaxed);

        // Wake any waiting receivers
        queue.waitq.wake_all();

        queue.perm.put_ref();
        return Ok(0);
    }
}

/// msgrcv - receive message
///
/// # Arguments
/// * `msqid` - Queue ID
/// * `msgp` - Pointer to msgbuf (mtype + mtext)
/// * `msgsz` - Maximum size of mtext
/// * `msgtyp` - Message type to receive
/// * `msgflg` - Flags (IPC_NOWAIT, MSG_NOERROR, MSG_EXCEPT)
pub fn sys_msgrcv(msqid: i32, msgp: u64, msgsz: usize, msgtyp: i64, msgflg: i32) -> i64 {
    result_to_i64(do_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg))
}

fn do_msgrcv(msqid: i32, msgp: u64, msgsz: usize, msgtyp: i64, msgflg: i32) -> Result<i32, i32> {
    let ns = current_ipc_ns();

    // Find queue
    let queue = ns.msg_ids().find_by_id(msqid).ok_or(EINVAL)?;

    let queue: &MsgQueue = unsafe { &*(queue.as_ref() as *const dyn IpcObject as *const MsgQueue) };

    // Check read permission
    ipc_checkperm(&queue.perm, IPC_PERM_READ)?;

    let nowait = msgflg & IPC_NOWAIT != 0;
    let noerror = msgflg & MSG_NOERROR != 0;
    let pid = current_pid() as i32;

    loop {
        // Try to find a matching message
        if let Some(msg) = queue.find_msg(msgtyp, msgflg) {
            // Check size
            if msg.mtext.len() > msgsz && !noerror {
                // Put message back
                let mut messages = queue.messages.lock();
                messages.push_front(msg);
                queue.perm.put_ref();
                return Err(E2BIG);
            }

            // Update queue stats
            queue
                .cbytes
                .fetch_sub(msg.mtext.len() as u64, Ordering::AcqRel);
            queue.qnum.fetch_sub(1, Ordering::AcqRel);
            queue.rtime.store(current_time_secs(), Ordering::Release);
            queue.lrpid.store(pid, Ordering::Release);

            // Update namespace counters
            ns.msg_bytes
                .fetch_sub(msg.mtext.len() as u64, Ordering::Relaxed);
            ns.msg_hdrs.fetch_sub(1, Ordering::Relaxed);

            // Copy to user
            put_user::<Uaccess, i64>(msgp, msg.mtype).map_err(|_| EFAULT)?;

            let copy_len = core::cmp::min(msg.mtext.len(), msgsz);
            if copy_len > 0 {
                let data_ptr = msgp + 8;
                copy_to_user::<Uaccess>(data_ptr, &msg.mtext[..copy_len]).map_err(|_| EFAULT)?;
            }

            // Wake any waiting senders
            queue.waitq.wake_all();

            queue.perm.put_ref();
            return Ok(copy_len as i32);
        }

        // No matching message
        if nowait {
            queue.perm.put_ref();
            return Err(ENOMSG);
        }

        // Block until message available
        queue.waitq.wait();

        // Check if queue was removed
        if queue.perm.is_deleted() {
            queue.perm.put_ref();
            return Err(EIDRM);
        }
    }
}

/// msgctl - message queue control
pub fn sys_msgctl(msqid: i32, cmd: i32, buf: u64) -> i64 {
    result_to_i64(do_msgctl(msqid, cmd, buf))
}

fn do_msgctl(msqid: i32, cmd: i32, buf: u64) -> Result<i32, i32> {
    let ns = current_ipc_ns();
    let cmd_only = cmd & !IPC_64;

    match cmd_only {
        IPC_STAT | MSG_STAT => {
            let queue = ns.msg_ids().find_by_id(msqid).ok_or(EINVAL)?;

            ipc_checkperm(queue.perm(), IPC_PERM_READ)?;

            let queue_inner: &MsgQueue =
                unsafe { &*(queue.as_ref() as *const dyn IpcObject as *const MsgQueue) };

            let mut ds = Msqid64Ds::default();
            queue_inner.fill_msqid64_ds(&mut ds);

            if buf != 0 {
                put_user::<Uaccess, Msqid64Ds>(buf, ds).map_err(|_| EFAULT)?;
            }

            queue.perm().put_ref();
            Ok(0)
        }

        IPC_SET => {
            let queue = ns.msg_ids().find_by_id(msqid).ok_or(EINVAL)?;

            let cred = crate::task::percpu::current_cred();
            let uid = cred.euid;
            let perm = queue.perm();
            let _lock = perm.lock.lock();
            // SAFETY: We hold the lock
            let perm_mutable = unsafe { perm.mutable() };
            if uid != perm_mutable.uid && uid != perm.cuid && uid != 0 {
                drop(_lock);
                perm.put_ref();
                return Err(EPERM);
            }

            let ds: Msqid64Ds = get_user::<Uaccess, Msqid64Ds>(buf).map_err(|_| EFAULT)?;

            // Update fields
            perm_mutable.uid = ds.msg_perm.uid;
            perm_mutable.gid = ds.msg_perm.gid;
            perm_mutable.mode = ds.msg_perm.mode & 0o777;

            // Safe downcast with type verification
            let queue_inner: &MsgQueue = match downcast_msg(queue.as_ref()) {
                Some(q) => q,
                None => {
                    perm.put_ref();
                    return Err(EINVAL);
                }
            };

            // Update qbytes if root
            if uid == 0 {
                // Safety: single writer with lock held
                let queue_mut = queue_inner as *const MsgQueue as *mut MsgQueue;
                unsafe {
                    (*queue_mut).qbytes = ds.msg_qbytes;
                }
            }

            queue_inner
                .ctime
                .store(current_time_secs(), Ordering::Release);

            perm.put_ref();
            Ok(0)
        }

        IPC_RMID => {
            let queue = ns.msg_ids().find_by_id(msqid).ok_or(EINVAL)?;

            let cred = crate::task::percpu::current_cred();
            let uid = cred.euid;
            let perm = queue.perm();
            {
                let _lock = perm.lock.lock();
                // SAFETY: We hold the lock
                let perm_mutable = unsafe { perm.mutable_ref() };
                if uid != perm_mutable.uid && uid != perm.cuid && uid != 0 {
                    drop(_lock);
                    perm.put_ref();
                    return Err(EPERM);
                }
            }
            perm.put_ref();

            if let Some(removed) = ns.msg_ids().remove(msqid) {
                removed.destroy();
            }

            Ok(0)
        }

        _ => Err(EINVAL),
    }
}
