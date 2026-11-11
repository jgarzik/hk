//! AF_UNIX ancillary data (Linux net/core/scm.c, net/unix/af_unix.c
//! unix_attach_fds/unix_detach_fds, garbage.c inflight accounting)
//!
//! Send side: `Scm::parse` turns SOL_SOCKET control messages into a
//! cookie: SCM_RIGHTS files (at most `SCM_MAX_FD` per message, held as
//! `FileRef`) and SCM_CREDENTIALS (only values the sender could set
//! with setuid/setgid, its own pid unless CAP_SYS_ADMIN).
//!
//! Files in flight are charged to the sending user (`INFLIGHT`, Linux
//! user->unix_inflight) from the moment they are queued until they are
//! received or their message is dropped. Attaching more while the
//! user's count exceeds RLIMIT_NOFILE is ETOOMANYREFS (Linux
//! too_many_unix_fds). There is no garbage collector for unreachable
//! cycles of in-flight sockets (BUGS.md); this cap bounds what such
//! cycles can pin per user.
//!
//! Receive side: `put` emits SCM_CREDENTIALS and installs SCM_RIGHTS
//! files in the receiver's table (MSG_CMSG_CLOEXEC honored); files that
//! do not fit the control buffer are closed and MSG_CTRUNC is set.
//!
//! Dropping files can release sockets whose queues hold more files
//! (recursively, without bound): `fput` defers each release (task_work
//! or the delayed list), so chains are released one file at a time,
//! never from inside a socket lock.
//!
//! ## Locking
//!
//! `INFLIGHT` is a `crate::sync::spin::Mutex` leaf (thread context only);
//! no file is ever dropped while it is held.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::FileRef;
use crate::net::msg::{MSG_CMSG_CLOEXEC, RecvMsg, cmsgs};
use crate::net::socket::SOL_SOCKET;
use crate::sync::spin::Mutex;
use crate::task::Uid;
use crate::util::error::KernelError;

pub const SCM_RIGHTS: i32 = 1;
pub const SCM_CREDENTIALS: i32 = 2;
/// Most files in one message (Linux SCM_MAX_FD)
pub const SCM_MAX_FD: usize = 253;
/// struct cmsghdr
const CMSG_HDR: usize = 16;
/// overflowuid / overflowgid
const OVERFLOW_ID: u32 = 65534;

/// Credentials carried by a message (Linux UNIXCB pid/uid/gid): the
/// sender's struct pid, numbered only for a receiver (none: pid 0)
#[derive(Clone, Default)]
pub struct Creds {
    pub pid: Option<Arc<crate::task::pid::Pid>>,
    pub uid: u32,
    pub gid: u32,
}

impl PartialEq for Creds {
    /// The same pid (not number), uid and gid (Linux unix_skb_scm_eq)
    fn eq(&self, o: &Self) -> bool {
        let same = match (&self.pid, &o.pid) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        same && self.uid == o.uid && self.gid == o.gid
    }
}

impl Creds {
    /// The current task's (process, real uid, real gid)
    pub fn current() -> Self {
        let c = crate::task::current_cred();
        Self {
            pid: crate::task::pid::find_pid(
                &crate::ns::INIT_PID_NS,
                crate::task::percpu::current_pid() as u32,
            ),
            uid: c.uid,
            gid: c.gid,
        }
    }

    /// struct ucred, its pid in the reader's namespace (Linux
    /// scm_set_cred: pid_vnr; 0 if not visible)
    fn bytes(c: Option<&Self>) -> [u8; 12] {
        let (pid, uid, gid) = c.map_or((0, OVERFLOW_ID, OVERFLOW_ID), |c| {
            (c.pid.as_ref().map_or(0, |p| p.vnr()), c.uid, c.gid)
        });
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&pid.to_ne_bytes());
        b[4..8].copy_from_slice(&uid.to_ne_bytes());
        b[8..].copy_from_slice(&gid.to_ne_bytes());
        b
    }
}

/// Files of one message (Linux struct scm_fp_list)
pub struct FpList {
    files: Vec<FileRef>,
    /// Sending user, charged while queued
    uid: Uid,
    inflight: bool,
}

/// In-flight files per user (Linux user_struct.unix_inflight)
static INFLIGHT: Mutex<BTreeMap<Uid, usize>> = Mutex::new(BTreeMap::new());

fn inflight_add(uid: Uid, n: usize) {
    *INFLIGHT.lock().entry(uid).or_insert(0) += n;
}

fn inflight_sub(uid: Uid, n: usize) {
    let mut t = INFLIGHT.lock();
    if let Some(v) = t.get_mut(&uid) {
        *v = v.saturating_sub(n);
        if *v == 0 {
            t.remove(&uid);
        }
    }
}

/// Ceiling on a user's in-flight files whatever its RLIMIT_NOFILE
/// (Linux UNIX_INFLIGHT_SANE_USER). Linux only uses it to trigger the
/// garbage collector; without one, files pinned by unreachable cycles
/// stay charged, so a fixed ceiling (not the user-raisable soft limit)
/// is what bounds them.
const INFLIGHT_MAX: u64 = (SCM_MAX_FD * 8) as u64;

/// Linux too_many_unix_fds: the sender's in-flight count is over its
/// RLIMIT_NOFILE (and over `INFLIGHT_MAX` here) and it lacks
/// CAP_SYS_RESOURCE and CAP_SYS_ADMIN
pub fn too_many_fds() -> bool {
    let uid = crate::task::current_cred().uid;
    let n = INFLIGHT.lock().get(&uid).copied().unwrap_or(0) as u64;
    let lim = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_NOFILE).min(INFLIGHT_MAX);
    n > lim
        && !crate::task::capable(crate::task::CAP_SYS_RESOURCE)
        && !crate::task::capable(crate::task::CAP_SYS_ADMIN)
}

impl FpList {
    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Charge to the sender: the message was queued (Linux
    /// unix_add_edges)
    pub fn queued(&mut self) {
        if !self.inflight {
            inflight_add(self.uid, self.files.len());
            self.inflight = true;
        }
    }

    /// Received or dropped (Linux unix_del_edges)
    fn uncharge(&mut self) {
        if self.inflight {
            inflight_sub(self.uid, self.files.len());
            self.inflight = false;
        }
    }

    /// Copy for MSG_PEEK (Linux scm_fp_dup: not in flight itself)
    pub fn dup(&self) -> Self {
        Self {
            files: self.files.clone(),
            uid: self.uid,
            inflight: false,
        }
    }

    /// Take the files out (received): no longer in flight
    fn take(mut self) -> Vec<FileRef> {
        self.uncharge();
        core::mem::take(&mut self.files)
    }
}

/// Dropped unreceived: uncharged; its files' references go with it
/// (`fput`: a socket among them is released later, not under the lock
/// of the queue that held the message)
impl Drop for FpList {
    fn drop(&mut self) {
        self.uncharge();
    }
}

/// Send-side cookie (Linux struct scm_cookie)
#[derive(Default)]
pub struct Scm {
    pub creds: Option<Creds>,
    pub fds: Option<FpList>,
}

impl Scm {
    /// Parse the control messages of a send (Linux __scm_send):
    /// non-SOL_SOCKET levels are skipped, unknown SOL_SOCKET types and
    /// malformed headers are EINVAL
    pub fn parse(control: &[u8]) -> Result<Self, KernelError> {
        let mut scm = Self::default();
        for c in cmsgs(control) {
            let (level, ty, data) = c?;
            if level != SOL_SOCKET {
                continue;
            }
            match ty {
                SCM_RIGHTS => scm.add_fds(data)?,
                SCM_CREDENTIALS => scm.creds = Some(check_creds(data)?),
                _ => return Err(KernelError::InvalidArgument),
            }
        }
        if scm.fds.as_ref().is_some_and(|f| f.is_empty()) {
            scm.fds = None;
        }
        Ok(scm)
    }

    /// Linux scm_fp_copy: EINVAL past SCM_MAX_FD or for an io_uring
    /// file, EBADF for a bad descriptor (O_PATH files are fine)
    fn add_fds(&mut self, data: &[u8]) -> Result<(), KernelError> {
        let n = data.len() / 4;
        if n == 0 {
            return Ok(());
        }
        let fpl = self.fds.get_or_insert_with(|| FpList {
            files: Vec::new(),
            uid: crate::task::current_cred().uid,
            inflight: false,
        });
        if n > SCM_MAX_FD || fpl.files.len() + n > SCM_MAX_FD {
            return Err(KernelError::InvalidArgument);
        }
        let table = crate::task::percpu::current()
            .files()
            .ok_or(KernelError::BadFd)?;
        for c in data[..n * 4].as_chunks::<4>().0 {
            let fd = i32::from_ne_bytes(*c);
            let f = table.lock().get(fd).ok_or(KernelError::BadFd)?;
            if crate::io::io_uring::is_uring(&f) {
                return Err(KernelError::InvalidArgument);
            }
            fpl.files.push(f);
        }
        Ok(())
    }
}

/// SCM_CREDENTIALS from a sender (Linux scm_check_creds + __scm_send):
/// exactly a struct ucred; the pid must be the sender's tgid (or any
/// existing process with CAP_SYS_ADMIN: ESRCH if none), the uid one of
/// its real/effective/saved uids (or CAP_SETUID), the gid likewise
fn check_creds(data: &[u8]) -> Result<Creds, KernelError> {
    if data.len() != 12 {
        return Err(KernelError::InvalidArgument);
    }
    let w = |o: usize| u32::from_ne_bytes(data[o..o + 4].try_into().unwrap());
    let (pid, uid, gid) = (w(0) as i32, w(4), w(8));
    if uid == u32::MAX || gid == u32::MAX {
        return Err(KernelError::InvalidArgument);
    }
    let c = crate::task::current_cred();
    // The caller's numbers (Linux scm_check_creds: task_tgid_vnr)
    let me = crate::task::pid::vnr(crate::task::percpu::current_pid()) as i32;
    let cap = crate::task::capable;
    let pid_ok = pid == me || cap(crate::task::CAP_SYS_ADMIN);
    let uid_ok = [c.uid, c.euid, c.suid].contains(&uid) || cap(crate::task::CAP_SETUID);
    let gid_ok = [c.gid, c.egid, c.sgid].contains(&gid) || cap(crate::task::CAP_SETGID);
    if !(pid_ok && uid_ok && gid_ok) {
        return Err(KernelError::NotPermitted);
    }
    // Held by struct pid, numbered again for each reader (Linux
    // __scm_send: find_get_pid)
    let p = u32::try_from(pid)
        .ok()
        .and_then(crate::task::pid::find_vpid)
        .ok_or(KernelError::NoProcess)?;
    Ok(Creds {
        pid: Some(p),
        uid,
        gid,
    })
}

/// Deliver received ancillary data (Linux scm_recv_unix): credentials
/// when the receiver set SO_PASSCRED, then the files. Without control
/// space everything is truncated (MSG_CTRUNC) and the files closed.
pub fn put(m: &mut RecvMsg<'_>, passcred: bool, creds: Option<Creds>, fds: Option<FpList>) {
    if m.cmsg.capacity() == 0 {
        if passcred || fds.is_some() {
            m.cmsg.trunc = true;
        }
        drop(fds);
        return;
    }
    if passcred {
        m.cmsg
            .put(SOL_SOCKET, SCM_CREDENTIALS, &Creds::bytes(creds.as_ref()));
    }
    if let Some(f) = fds {
        put_fds(m, f);
    }
}

/// Install as many files as fit (Linux scm_detach_fds); the rest are
/// closed with MSG_CTRUNC
fn put_fds(m: &mut RecvMsg<'_>, fpl: FpList) {
    let cloexec = m.flags & MSG_CMSG_CLOEXEC != 0;
    let room = m.cmsg.room();
    let max = if room <= CMSG_HDR {
        0
    } else {
        (room - CMSG_HDR) / 4
    };
    let files = fpl.take();
    let count = files.len();
    let mut fds = Vec::new();
    // Clones go to the table, so a failed install never drops the last
    // reference under the table lock
    for f in files.iter().take(max) {
        match crate::net::syscall::fd_install(f.clone(), cloexec) {
            Ok(fd) => fds.extend_from_slice(&fd.to_ne_bytes()),
            Err(_) => break,
        }
    }
    let n = fds.len() / 4;
    if n > 0 {
        m.cmsg.put(SOL_SOCKET, SCM_RIGHTS, &fds);
    }
    if n < count {
        m.cmsg.trunc = true;
    }
    drop(files);
}
