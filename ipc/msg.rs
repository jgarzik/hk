//! System V Message Queue Implementation
//!
//! Provides message queues for inter-process communication with support for:
//! - Multiple message types for selective receiving
//! - Blocking send/receive with optional timeout
//! - Per-queue byte limits

use crate::util::kalloc::try_arc;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::arch::Uaccess;
use crate::ipc::util::{
    IPC_PERM_READ, IPC_PERM_WRITE, IpcObject, IpcOps, KernIpcPerm, ipc_checkperm, ipcget,
};
use crate::ipc::{
    IPC_64, IPC_NOWAIT, IPC_RMID, IPC_SET, IPC_STAT, IpcNamespace, Msqid64Ds, current_ipc_ns,
};
use crate::sync::spin::Mutex;
use crate::sync::waitqueue::WaitQueue;
use crate::task::percpu::current_pid;
use crate::time::TIMEKEEPER;
use crate::uaccess::{UserPtr, copy_from_user, copy_to_user};
use crate::util::error::{KernelError, KernelResult};

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

/// Everything msgsnd, msgrcv and msgctl read or change, under one lock
/// (Linux: the msq lock, ipc_lock_object(&msq->q_perm))
#[derive(Default)]
pub struct MsgState {
    /// Message list
    list: VecDeque<MsgMsg>,
    /// Current bytes in queue
    cbytes: u64,
    /// Current number of messages
    qnum: u64,
    /// Maximum bytes allowed
    qbytes: u64,
    /// Last msgsnd time
    stime: i64,
    /// Last msgrcv time
    rtime: i64,
    /// Last change time
    ctime: i64,
    /// Last sender PID
    lspid: i32,
    /// Last receiver PID
    lrpid: i32,
}

/// Message queue
pub struct MsgQueue {
    /// IPC permissions and ID
    pub perm: KernIpcPerm,
    /// The messages, counters, limit, times and pids
    q: Mutex<MsgState>,
    /// Wait queue for blocked operations
    pub waitq: WaitQueue,
    /// Namespace reference
    ns: Arc<IpcNamespace>,
}

impl MsgQueue {
    /// Create a new message queue
    pub fn new(key: i32, mode: u16, ns: Arc<IpcNamespace>) -> KernelResult<Arc<Self>> {
        try_arc(Self {
            perm: KernIpcPerm::new(key, mode),
            q: Mutex::new(MsgState {
                qbytes: u64::from(ns.msg_ctlmnb),
                ctime: current_time_secs(),
                ..Default::default()
            }),
            waitq: WaitQueue::new(),
            ns,
        })
    }

    /// A message matching `search` is queued
    fn has_msg(&self, search: Search) -> bool {
        self.q.lock().list.iter().any(|m| search.test(m.mtype))
    }

    /// Dequeue the message matching `search` (the first, or for
    /// LessEqual the first of the lowest type) if it fits in `msgsz`
    /// bytes or may be truncated (Linux find_msg); E2BIG leaves it queued.
    /// The receiver's pid and the time are recorded with it.
    fn take_msg(
        &self,
        search: Search,
        msgsz: usize,
        noerror: bool,
        pid: i32,
    ) -> KernelResult<Option<MsgMsg>> {
        let mut q = self.q.lock();
        let mut found = q
            .list
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
        if q.list[i].mtext.len() > msgsz && !noerror {
            return Err(KernelError::ArgListTooLong);
        }
        let msg = q.list.remove(i);
        if let Some(m) = &msg {
            self.account(&mut q, -(m.mtext.len() as i64));
            q.rtime = current_time_secs();
            q.lrpid = pid;
        }
        Ok(msg)
    }

    /// Queue `msg` if it fits (Linux do_msgsnd under the queue lock): the
    /// limit and removal are checked, the counters kept and the sender's
    /// pid and time recorded with the queue locked, so concurrent senders
    /// never pass qbytes and a removed queue takes nothing. A message that
    /// does not fit comes back
    fn try_send(&self, msg: MsgMsg, pid: i32) -> KernelResult<Option<MsgMsg>> {
        let mut q = self.q.lock();
        if self.perm.is_deleted() {
            return Err(KernelError::IdentifierRemoved);
        }
        if !Self::fits(&q, msg.mtext.len()) {
            return Ok(Some(msg));
        }
        let len = msg.mtext.len() as i64;
        q.list.push_back(msg);
        self.account(&mut q, len);
        q.stime = current_time_secs();
        q.lspid = pid;
        Ok(None)
    }

    /// A message of `len` bytes fits (Linux msg_fits_inqueue): qbytes
    /// bounds the bytes and also the number of messages
    fn fits(q: &MsgState, len: usize) -> bool {
        q.cbytes + len as u64 <= q.qbytes && q.qnum < q.qbytes
    }

    /// One message of `bytes` added (> 0) or removed (< 0): the queue's
    /// counters (under its lock) and the namespace's statistics
    fn account(&self, q: &mut MsgState, bytes: i64) {
        let n = bytes.unsigned_abs();
        if bytes >= 0 {
            q.cbytes += n;
            q.qnum += 1;
            self.ns.msg_bytes.fetch_add(n, Ordering::Relaxed);
            self.ns.msg_hdrs.fetch_add(1, Ordering::Relaxed);
        } else {
            q.cbytes -= n;
            q.qnum -= 1;
            self.ns.msg_bytes.fetch_sub(n, Ordering::Relaxed);
            self.ns.msg_hdrs.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Fill msqid64_ds structure for IPC_STAT: one snapshot under the
    /// queue lock (Linux msgctl_stat)
    pub fn fill_msqid64_ds(&self, ds: &mut Msqid64Ds) {
        self.perm.fill_ipc64_perm(&mut ds.msg_perm);
        let q = self.q.lock();
        ds.msg_stime = q.stime;
        ds.msg_rtime = q.rtime;
        ds.msg_ctime = q.ctime;
        ds.msg_cbytes = q.cbytes;
        ds.msg_qnum = q.qnum;
        ds.msg_qbytes = q.qbytes;
        // In the caller's namespace (Linux msg: pid_vnr)
        ds.msg_lspid = crate::task::pid::vnr(q.lspid as u64) as i32;
        ds.msg_lrpid = crate::task::pid::vnr(q.lrpid as u64) as i32;
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
            let mut q = self.q.lock();
            while let Some(m) = q.list.pop_front() {
                self.account(&mut q, -(m.mtext.len() as i64));
            }
        }
        self.waitq.wake_all();
    }
}

// ============================================================================
// Syscalls
// ============================================================================

/// msgget - get message queue
///
/// # Arguments
/// * `key` - Key to identify queue
/// * `msgflg` - Flags (IPC_CREAT, IPC_EXCL, permission bits)
pub fn sys_msgget(key: i32, msgflg: i32) -> KernelResult<i32> {
    let ns = current_ipc_ns();
    let ns_clone = ns.clone();

    let ops = IpcOps {
        new: move |k, mode| MsgQueue::new(k, mode, ns_clone.clone()),
        more_checks: |_: &MsgQueue| Ok(()),
        added: |_: &MsgQueue| {},
    };
    ipcget(ns.msg_ids(), key, msgflg, ns.msg_ctlmni, ops)
}

/// msgsnd - send message
///
/// # Arguments
/// * `msqid` - Queue ID
/// * `msgp` - Pointer to msgbuf (mtype + mtext)
/// * `msgsz` - Size of mtext
/// * `msgflg` - Flags (IPC_NOWAIT)
pub fn sys_msgsnd(msqid: i32, msgp: UserPtr<i64>, msgsz: usize, msgflg: i32) -> KernelResult<()> {
    let ns = current_ipc_ns();

    // Linux do_msgsnd: a size past msgmax or negative as a long, or a
    // negative id, is EINVAL
    if msgsz > ns.msg_ctlmax as usize || (msgsz as i64) < 0 || msqid < 0 {
        return Err(KernelError::InvalidArgument);
    }

    // Read message type
    let mtype = msgp.read()?;

    if mtype <= 0 {
        return Err(KernelError::InvalidArgument);
    }

    // Read message data
    let mut mtext = vec![0u8; msgsz];
    if msgsz > 0 {
        let data_ptr = msgp.addr() + 8; // Skip mtype (i64 = 8 bytes)
        copy_from_user::<Uaccess>(&mut mtext, data_ptr, msgsz)?;
    }

    let msg = MsgMsg { mtype, mtext };

    // Find queue
    let queue = ns
        .msg_ids()
        .find_by_id(msqid)
        .ok_or(KernelError::InvalidArgument)?;

    // Check write permission
    ipc_checkperm(&queue.perm, IPC_PERM_WRITE)?;

    let nowait = msgflg & IPC_NOWAIT != 0;
    let pid = current_pid() as i32;

    let mut msg = msg;
    while let Some(back) = queue.try_send(msg, pid)? {
        msg = back;
        if nowait {
            return Err(KernelError::WouldBlock);
        }
        // Sleep until space or removal; a signal ends the call
        // (System V IPC is never restarted after a handler)
        let room = || MsgQueue::fits(&queue.q.lock(), msgsz) || queue.perm.is_deleted();
        queue
            .waitq
            .wait_event_interruptible(room)
            .map_err(|_| KernelError::RestartNoHand)?;
        // Permissions may have changed while it slept (Linux rechecks)
        ipc_checkperm(&queue.perm, IPC_PERM_WRITE)?;
    }
    // Wake any waiting receivers
    queue.waitq.wake_all();
    Ok(())
}

/// msgrcv - receive message
///
/// # Arguments
/// * `msqid` - Queue ID
/// * `msgp` - Pointer to msgbuf (mtype + mtext)
/// * `msgsz` - Maximum size of mtext
/// * `msgtyp` - Message type to receive
/// * `msgflg` - Flags (IPC_NOWAIT, MSG_NOERROR, MSG_EXCEPT)
pub fn sys_msgrcv(
    msqid: i32,
    msgp: UserPtr<i64>,
    msgsz: usize,
    msgtyp: i64,
    msgflg: i32,
) -> KernelResult<usize> {
    // Linux do_msgrcv: a negative id or size (as a long) is EINVAL
    if msqid < 0 || (msgsz as i64) < 0 {
        return Err(KernelError::InvalidArgument);
    }
    let ns = current_ipc_ns();

    // Find queue
    let queue = ns
        .msg_ids()
        .find_by_id(msqid)
        .ok_or(KernelError::InvalidArgument)?;

    // Check read permission
    ipc_checkperm(&queue.perm, IPC_PERM_READ)?;

    let nowait = msgflg & IPC_NOWAIT != 0;
    let noerror = msgflg & MSG_NOERROR != 0;
    let pid = current_pid() as i32;

    let search = Search::new(msgtyp, msgflg);
    loop {
        if let Some(msg) = queue.take_msg(search, msgsz, noerror, pid)? {
            // Copy to user
            msgp.write(&msg.mtype)?;

            let copy_len = core::cmp::min(msg.mtext.len(), msgsz);
            if copy_len > 0 {
                let data_ptr = msgp.addr() + 8;
                copy_to_user::<Uaccess>(data_ptr, &msg.mtext[..copy_len])?;
            }

            // Wake any waiting senders
            queue.waitq.wake_all();

            return Ok(copy_len);
        }

        // No matching message
        if nowait {
            return Err(KernelError::NoMessage);
        }

        // Sleep until a matching message arrives or the queue is removed
        queue
            .waitq
            .wait_event_interruptible(|| queue.has_msg(search) || queue.perm.is_deleted())
            .map_err(|_| KernelError::RestartNoHand)?;

        // Check if queue was removed
        if queue.perm.is_deleted() {
            return Err(KernelError::IdentifierRemoved);
        }
        // Permissions may have changed while it slept (Linux rechecks)
        ipc_checkperm(&queue.perm, IPC_PERM_READ)?;
    }
}

/// msgctl - message queue control
pub fn sys_msgctl(msqid: i32, cmd: i32, buf: UserPtr<Msqid64Ds>) -> KernelResult<i32> {
    let ns = current_ipc_ns();
    let cmd_only = cmd & !IPC_64;

    match cmd_only {
        IPC_STAT | MSG_STAT => {
            let queue = ns
                .msg_ids()
                .find_by_id(msqid)
                .ok_or(KernelError::InvalidArgument)?;

            ipc_checkperm(queue.perm(), IPC_PERM_READ)?;

            let mut ds = Msqid64Ds::default();
            queue.fill_msqid64_ds(&mut ds);

            if !buf.is_null() {
                buf.write(&ds)?;
            }

            Ok(0)
        }

        IPC_SET => {
            // Copied in first, before the IPC locks (Linux: the copy
            // may fault)
            let ds = buf.read()?;
            let _w = ns.msg_ids().rwsem.write();
            let queue = ns
                .msg_ids()
                .find_by_id(msqid)
                .ok_or(KernelError::InvalidArgument)?;

            let uid = crate::task::percpu::current_cred().euid;
            let perm = queue.perm();
            if !KernIpcPerm::is_owner(&perm.lock.lock(), perm.cuid, uid) {
                return Err(KernelError::NotPermitted);
            }
            // Linux msgctl_down: past MSGMNB needs CAP_SYS_RESOURCE; below
            // it anyone allowed to IPC_SET may lower or raise the limit
            if ds.msg_qbytes > u64::from(ns.msg_ctlmnb)
                && !crate::task::capable(crate::task::CAP_SYS_RESOURCE)
            {
                return Err(KernelError::NotPermitted);
            }
            {
                let mut q = queue.q.lock();
                let mut p = perm.lock.lock();
                p.uid = ds.msg_perm.uid;
                p.gid = ds.msg_perm.gid;
                p.mode = ds.msg_perm.mode & 0o777;
                drop(p);
                q.qbytes = ds.msg_qbytes;
                q.ctime = current_time_secs();
            }
            // Senders may fit now; receivers recheck their permission
            queue.waitq.wake_all();

            Ok(0)
        }

        IPC_RMID => {
            let _w = ns.msg_ids().rwsem.write();
            let queue = ns
                .msg_ids()
                .find_by_id(msqid)
                .ok_or(KernelError::InvalidArgument)?;

            let uid = crate::task::percpu::current_cred().euid;
            let perm = queue.perm();
            if !KernIpcPerm::is_owner(&perm.lock.lock(), perm.cuid, uid) {
                return Err(KernelError::NotPermitted);
            }

            if let Some(removed) = ns.msg_ids().remove(msqid) {
                removed.destroy();
            }

            Ok(0)
        }

        _ => Err(KernelError::InvalidArgument),
    }
}
