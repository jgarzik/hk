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
use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};

use crate::arch::Uaccess;
use crate::ipc::util::{
    IPC_PERM_READ, IPC_PERM_WRITE, IpcObject, KernIpcPerm, ipc_checkperm, ipcget,
};
use crate::ipc::{
    IPC_64, IPC_NOWAIT, IPC_RMID, IPC_SET, IPC_STAT, IpcNamespace, Msqid64Ds, current_ipc_ns,
};
use crate::sync::spin::Mutex;
use crate::sync::waitqueue::WaitQueue;
use crate::task::percpu::current_pid;
use crate::time::TIMEKEEPER;
use crate::uaccess::{copy_from_user, copy_to_user, get_user, put_user};
use crate::util::error::KernelError;

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

/// Which messages msgrcv takes (Linux convert_mode / testmsg)
#[derive(Clone, Copy)]
enum Search {
    Any,
    Equal(i64),
    NotEqual(i64),
    LessEqual(i64),
}

impl Search {
    fn new(msgtyp: i64, msgflg: i32) -> Self {
        match msgtyp {
            0 => Search::Any,
            // LONG_MIN has no negation: Linux takes LONG_MAX
            t if t < 0 => Search::LessEqual(t.checked_neg().unwrap_or(i64::MAX)),
            t if msgflg & MSG_EXCEPT != 0 => Search::NotEqual(t),
            t => Search::Equal(t),
        }
    }

    fn test(self, mtype: i64) -> bool {
        match self {
            Search::Any => true,
            Search::Equal(t) => mtype == t,
            Search::NotEqual(t) => mtype != t,
            Search::LessEqual(t) => mtype <= t,
        }
    }
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
    /// Maximum bytes allowed (IPC_SET changes it, msgsnd reads it
    /// unlocked)
    pub qbytes: AtomicU64,
    /// Last sender PID
    pub lspid: AtomicI32,
    /// Last receiver PID
    pub lrpid: AtomicI32,
    /// Message list
    pub messages: Mutex<VecDeque<MsgMsg>>,
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
            qbytes: AtomicU64::new(ns.msg_ctlmnb as u64),
            lspid: AtomicI32::new(0),
            lrpid: AtomicI32::new(0),
            messages: Mutex::new(VecDeque::new()),
            waitq: WaitQueue::new(),
            ns,
        }))
    }

    /// A message matching `search` is queued
    fn has_msg(&self, search: Search) -> bool {
        self.messages.lock().iter().any(|m| search.test(m.mtype))
    }

    /// Dequeue the message matching `search` (the first, or for
    /// LessEqual the first of the lowest type) if it fits in `msgsz`
    /// bytes or may be truncated (Linux find_msg); E2BIG leaves it queued
    fn take_msg(&self, search: Search, msgsz: usize, noerror: bool) -> Result<Option<MsgMsg>, i32> {
        let mut messages = self.messages.lock();
        let mut found = messages
            .iter()
            .enumerate()
            .filter(|(_, m)| search.test(m.mtype));
        let idx = match search {
            Search::LessEqual(_) => found.min_by_key(|(i, m)| (m.mtype, *i)),
            _ => found.next(),
        }
        .map(|(i, _)| i);
        let Some(i) = idx else {
            return Ok(None);
        };
        if messages[i].mtext.len() > msgsz && !noerror {
            return Err(KernelError::ArgListTooLong.errno());
        }
        let msg = messages.remove(i);
        if let Some(m) = &msg {
            self.account(-(m.mtext.len() as i64));
        }
        Ok(msg)
    }

    /// Queue `msg` if it fits (Linux do_msgsnd under the queue lock): the
    /// limit and removal are checked, and the counters kept, with the
    /// queue locked, so concurrent senders never pass qbytes and a removed
    /// queue takes nothing. A message that does not fit comes back
    fn try_send(&self, msg: MsgMsg) -> Result<Option<MsgMsg>, i32> {
        let mut messages = self.messages.lock();
        if self.perm.is_deleted() {
            return Err(KernelError::IdentifierRemoved.errno());
        }
        let len = msg.mtext.len() as u64;
        if self.cbytes.load(Ordering::Relaxed) + len > self.qbytes.load(Ordering::Relaxed) {
            return Ok(Some(msg));
        }
        messages.push_back(msg);
        self.account(len as i64);
        Ok(None)
    }

    /// One message of `bytes` added (> 0) or removed (< 0), under the
    /// `messages` lock: queue and namespace counters
    fn account(&self, bytes: i64) {
        let n = bytes.unsigned_abs();
        if bytes >= 0 {
            self.cbytes.fetch_add(n, Ordering::Relaxed);
            self.qnum.fetch_add(1, Ordering::Relaxed);
            self.ns.msg_bytes.fetch_add(n, Ordering::Relaxed);
            self.ns.msg_hdrs.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cbytes.fetch_sub(n, Ordering::Relaxed);
            self.qnum.fetch_sub(1, Ordering::Relaxed);
            self.ns.msg_bytes.fetch_sub(n, Ordering::Relaxed);
            self.ns.msg_hdrs.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Fill msqid64_ds structure for IPC_STAT
    pub fn fill_msqid64_ds(&self, ds: &mut Msqid64Ds) {
        self.perm.fill_ipc64_perm(&mut ds.msg_perm);
        ds.msg_stime = self.stime.load(Ordering::Relaxed);
        ds.msg_rtime = self.rtime.load(Ordering::Relaxed);
        ds.msg_ctime = self.ctime.load(Ordering::Relaxed);
        ds.msg_cbytes = self.cbytes.load(Ordering::Relaxed);
        ds.msg_qnum = self.qnum.load(Ordering::Relaxed) as u64;
        ds.msg_qbytes = self.qbytes.load(Ordering::Relaxed);
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

    fn destroy(&self) {
        // Marked deleted before this: after the lock no sender adds more
        {
            let mut messages = self.messages.lock();
            while let Some(m) = messages.pop_front() {
                self.account(-(m.mtext.len() as i64));
            }
        }
        self.waitq.wake_all();
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
        return Err(KernelError::MessageTooLong.errno());
    }

    // Read message type
    let mtype: i64 = get_user::<Uaccess, i64>(msgp).map_err(|_| KernelError::BadAddress.errno())?;

    if mtype <= 0 {
        return Err(KernelError::InvalidArgument.errno());
    }

    // Read message data
    let mut mtext = vec![0u8; msgsz];
    if msgsz > 0 {
        let data_ptr = msgp + 8; // Skip mtype (i64 = 8 bytes)
        copy_from_user::<Uaccess>(&mut mtext, data_ptr, msgsz)
            .map_err(|_| KernelError::BadAddress.errno())?;
    }

    let msg = MsgMsg { mtype, mtext };

    // Find queue
    let queue = ns
        .msg_ids()
        .find_by_id(msqid)
        .ok_or(KernelError::InvalidArgument.errno())?;

    // Check write permission
    ipc_checkperm(&queue.perm, IPC_PERM_WRITE)?;

    let nowait = msgflg & IPC_NOWAIT != 0;
    let pid = current_pid() as i32;

    let mut msg = msg;
    while let Some(back) = queue.try_send(msg)? {
        msg = back;
        if nowait {
            return Err(KernelError::WouldBlock.errno());
        }
        // Sleep until space or removal; a signal ends the call
        // (System V IPC is never restarted after a handler)
        let room = || {
            queue.cbytes.load(Ordering::Acquire) + msgsz as u64
                <= queue.qbytes.load(Ordering::Relaxed)
                || queue.perm.is_deleted()
        };
        queue
            .waitq
            .wait_event_interruptible(room)
            .map_err(|_| KernelError::RestartNoHand.errno())?;
    }
    queue.stime.store(current_time_secs(), Ordering::Release);
    queue.lspid.store(pid, Ordering::Release);
    // Wake any waiting receivers
    queue.waitq.wake_all();
    Ok(0)
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
    let queue = ns
        .msg_ids()
        .find_by_id(msqid)
        .ok_or(KernelError::InvalidArgument.errno())?;

    // Check read permission
    ipc_checkperm(&queue.perm, IPC_PERM_READ)?;

    let nowait = msgflg & IPC_NOWAIT != 0;
    let noerror = msgflg & MSG_NOERROR != 0;
    let pid = current_pid() as i32;

    let search = Search::new(msgtyp, msgflg);
    loop {
        if let Some(msg) = queue.take_msg(search, msgsz, noerror)? {
            queue.rtime.store(current_time_secs(), Ordering::Release);
            queue.lrpid.store(pid, Ordering::Release);

            // Copy to user
            put_user::<Uaccess, i64>(msgp, msg.mtype)
                .map_err(|_| KernelError::BadAddress.errno())?;

            let copy_len = core::cmp::min(msg.mtext.len(), msgsz);
            if copy_len > 0 {
                let data_ptr = msgp + 8;
                copy_to_user::<Uaccess>(data_ptr, &msg.mtext[..copy_len])
                    .map_err(|_| KernelError::BadAddress.errno())?;
            }

            // Wake any waiting senders
            queue.waitq.wake_all();

            return Ok(copy_len as i32);
        }

        // No matching message
        if nowait {
            return Err(KernelError::NoMessage.errno());
        }

        // Sleep until a matching message arrives or the queue is removed
        queue
            .waitq
            .wait_event_interruptible(|| queue.has_msg(search) || queue.perm.is_deleted())
            .map_err(|_| KernelError::RestartNoHand.errno())?;

        // Check if queue was removed
        if queue.perm.is_deleted() {
            return Err(KernelError::IdentifierRemoved.errno());
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
            let queue = ns
                .msg_ids()
                .find_by_id(msqid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            ipc_checkperm(queue.perm(), IPC_PERM_READ)?;

            let mut ds = Msqid64Ds::default();
            queue.fill_msqid64_ds(&mut ds);

            if buf != 0 {
                put_user::<Uaccess, Msqid64Ds>(buf, ds)
                    .map_err(|_| KernelError::BadAddress.errno())?;
            }

            Ok(0)
        }

        IPC_SET => {
            let queue = ns
                .msg_ids()
                .find_by_id(msqid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            let uid = crate::task::percpu::current_cred().euid;
            // Copied in before the spin lock (the copy may fault)
            let ds: Msqid64Ds =
                get_user::<Uaccess, Msqid64Ds>(buf).map_err(|_| KernelError::BadAddress.errno())?;
            let perm = queue.perm();
            {
                let mut p = perm.lock.lock();
                if !KernIpcPerm::is_owner(&p, perm.cuid, uid) {
                    return Err(KernelError::NotPermitted.errno());
                }
                p.uid = ds.msg_perm.uid;
                p.gid = ds.msg_perm.gid;
                p.mode = ds.msg_perm.mode & 0o777;
                // Only root raises the limit
                if uid == 0 {
                    queue.qbytes.store(ds.msg_qbytes, Ordering::Relaxed);
                }
            }

            queue.ctime.store(current_time_secs(), Ordering::Release);

            Ok(0)
        }

        IPC_RMID => {
            let queue = ns
                .msg_ids()
                .find_by_id(msqid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            let uid = crate::task::percpu::current_cred().euid;
            let perm = queue.perm();
            if !KernIpcPerm::is_owner(&perm.lock.lock(), perm.cuid, uid) {
                return Err(KernelError::NotPermitted.errno());
            }

            if let Some(removed) = ns.msg_ids().remove(msqid) {
                removed.destroy();
            }

            Ok(0)
        }

        _ => Err(KernelError::InvalidArgument.errno()),
    }
}
