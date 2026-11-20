//! AF_UNIX ancillary data (Linux net/core/scm.c, net/unix/af_unix.c
//! unix_attach_fds/unix_detach_fds, garbage.c inflight accounting)
//!
//! Send side: `Scm::parse` turns SOL_SOCKET control messages into a
//! cookie: SCM_RIGHTS files (at most `SCM_MAX_FD` per message, held as
//! `FileRef`) and SCM_CREDENTIALS (only values the sender could set
//! with setuid/setgid, its own pid unless CAP_SYS_ADMIN).
//!
//! Files in flight are charged to the sending user (its ucounts'
//! `UnixInflight`, Linux user->unix_inflight) from the moment they are
//! queued until they are received or their message is dropped, and the
//! unix sockets among them are edges of the collector's graph
//! (`gc.rs`) for as long. Attaching more while the user's count
//! exceeds RLIMIT_NOFILE is ETOOMANYREFS (Linux too_many_unix_fds).
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
//! The in-flight count is an atomic of the sender's ucounts, changed
//! under `gc::UNIX_GC` with the edges (under the receiver's `st` when
//! queued); nothing is allocated there: a message's vertices and edges
//! are made when it is attached (`prepare`).

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::FileRef;
use crate::util::kalloc::try_arc;
use crate::util::list::OwnedList;

use super::gc::{self, Edge, VEntry, Vertex};
use crate::net::msg::{MSG_CMSG_CLOEXEC, RecvMsg, cmsgs};
use crate::net::socket::SOL_SOCKET;
use crate::task::ucount::{Ucount, UcountsRef};
use crate::util::error::KernelError;

pub const SCM_RIGHTS: i32 = 1;
pub const SCM_CREDENTIALS: i32 = 2;
/// A pidfd of the sender (Linux SCM_PIDFD)
pub const SCM_PIDFD: i32 = 4;
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

    /// struct ucred in the reader's namespaces: the pid 0 if not
    /// visible, an unmapped id the overflow id (Linux scm_recv:
    /// pid_vnr, from_kuid_munged, from_kgid_munged)
    fn bytes(c: Option<&Self>) -> [u8; 12] {
        let ns = crate::ns::current_user_ns();
        let (pid, uid, gid) = c.map_or((0, OVERFLOW_ID, OVERFLOW_ID), |c| {
            (
                c.pid.as_ref().map_or(0, |p| p.vnr()),
                ns.from_kuid_munged(c.uid),
                ns.from_kgid_munged(c.gid),
            )
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
    /// The files in order; a unix socket's is held by its edge while
    /// the message is prepared (None here)
    pub(super) files: Vec<Option<FileRef>>,
    /// Sending user, charged while queued (Linux fpl->user)
    pub(super) user: UcountsRef,
    pub(super) inflight: bool,
    /// Unix sockets among the files (Linux count_unix)
    pub(super) count_unix: usize,
    /// Freed by the collector (Linux fpl->dead)
    pub(super) dead: bool,
    /// One per unix socket, in order (Linux fpl->edges)
    pub(super) edges: Vec<Arc<Edge>>,
    /// Spare vertices, one per edge (Linux fpl->vertices)
    pub(super) vertices: OwnedList<VEntry>,
}

/// Linux too_many_unix_fds: the sender's in-flight count is over its
/// RLIMIT_NOFILE and it lacks CAP_SYS_RESOURCE and CAP_SYS_ADMIN
pub fn too_many_fds() -> bool {
    let n = crate::task::current_cred()
        .ucounts
        .get(Ucount::UnixInflight);
    let lim = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_NOFILE);
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

    fn new(user: UcountsRef) -> Self {
        Self {
            files: Vec::new(),
            user,
            inflight: false,
            count_unix: 0,
            dead: false,
            edges: Vec::new(),
            vertices: OwnedList::new(),
        }
    }

    /// Attached to a message (Linux unix_prepare_fpl): a spare vertex
    /// and an edge (holding the file) per unix socket, then a
    /// collection if the sender has too many files in flight
    pub fn prepare(&mut self) -> Result<(), KernelError> {
        if self.count_unix == 0 {
            return Ok(());
        }
        for _ in 0..self.count_unix {
            self.vertices.push_back(try_arc(Vertex::default())?);
        }
        self.edges
            .try_reserve_exact(self.count_unix)
            .map_err(|_| KernelError::OutOfMemory)?;
        for slot in self.files.iter_mut() {
            let Some(u) = slot.as_ref().and_then(gc::unix_get_socket) else {
                continue;
            };
            let f = slot.take().expect("checked");
            self.edges.push(try_arc(Edge::new(u, f))?);
        }
        gc::schedule(Some(&self.user));
        Ok(())
    }

    /// The message was queued on `receiver` (Linux unix_add_edges):
    /// charged to the sender, its sockets' edges in the graph
    pub fn queued(&mut self, receiver: &Arc<super::UnixSock>) {
        if !self.inflight {
            gc::add_edges(self, receiver);
        }
    }

    /// Received or dropped (Linux unix_del_edges, from
    /// unix_destroy_fpl or scm_stat_del)
    pub fn detach(&mut self) {
        if self.inflight {
            gc::del_edges(self);
        }
    }

    /// The files in order, those held by edges included (each a new
    /// reference)
    fn all_files(&self) -> Vec<FileRef> {
        let mut edges = self.edges.iter();
        self.files
            .iter()
            .filter_map(|f| match f {
                Some(f) => Some(f.clone()),
                None => edges.next().map(|e| e.file.clone()),
            })
            .collect()
    }

    /// Copy for MSG_PEEK (Linux scm_fp_dup: not in flight itself),
    /// telling a running collection (unix_peek_fpl)
    pub fn dup(&self) -> Self {
        let mut d = Self::new(self.user.clone());
        d.files = self.all_files().into_iter().map(Some).collect();
        d.count_unix = self.count_unix;
        gc::peek_fpl(&d);
        d
    }

    /// Take the files out (received): no longer in flight; the edges'
    /// references come back to their places
    fn take(mut self) -> Vec<FileRef> {
        self.detach();
        let mut edges = core::mem::take(&mut self.edges).into_iter();
        core::mem::take(&mut self.files)
            .into_iter()
            .filter_map(|f| match f {
                Some(f) => Some(f),
                None => edges.next().map(|e| match Arc::try_unwrap(e) {
                    Ok(e) => e.file,
                    Err(e) => e.file.clone(),
                }),
            })
            .collect()
    }
}

/// Dropped unreceived (Linux unix_destroy_fpl): out of the graph and
/// uncharged; its files' references go with it (`fput`: a socket among
/// them is released later, not under the lock of the queue that held
/// the message)
impl Drop for FpList {
    fn drop(&mut self) {
        self.detach();
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
        let fpl = self
            .fds
            .get_or_insert_with(|| FpList::new(crate::task::current_cred().ucounts));
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
            if gc::unix_get_socket(&f).is_some() {
                fpl.count_unix += 1;
            }
            fpl.files.push(Some(f));
        }
        Ok(())
    }
}

/// SCM_CREDENTIALS from a sender (Linux scm_check_creds + __scm_send):
/// exactly a struct ucred whose ids map in the sender's user namespace
/// (EINVAL); the pid must be the sender's tgid (or any existing process
/// with CAP_SYS_ADMIN: ESRCH if none), the uid one of its
/// real/effective/saved uids (or CAP_SETUID), the gid likewise
fn check_creds(data: &[u8]) -> Result<Creds, KernelError> {
    if data.len() != 12 {
        return Err(KernelError::InvalidArgument);
    }
    let w = |o: usize| u32::from_ne_bytes(data[o..o + 4].try_into().unwrap());
    let (pid, uid, gid) = (w(0) as i32, w(4), w(8));
    // Linux make_kuid / make_kgid in cred->user_ns; -1 never maps
    let ns = crate::ns::current_user_ns();
    let kid = |id: u32, k: Option<u32>| k.filter(|_| id != u32::MAX);
    let (Some(uid), Some(gid)) = (kid(uid, ns.to_kuid(uid)), kid(gid, ns.to_kgid(gid))) else {
        return Err(KernelError::InvalidArgument);
    };
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
/// when the receiver set SO_PASSCRED, then the files, then with
/// SO_PASSPIDFD a pidfd of the sender. Without control space
/// everything is truncated (MSG_CTRUNC) and the files closed.
pub fn put(
    m: &mut RecvMsg<'_>,
    passcred: bool,
    passpidfd: bool,
    creds: Option<Creds>,
    fds: Option<FpList>,
) {
    if m.cmsg.capacity() == 0 {
        if passcred || passpidfd || fds.is_some() {
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
    if passpidfd {
        put_pidfd(m, creds.as_ref());
    }
}

/// Linux scm_pidfd_recv: SCM_PIDFD, a pidfd (O_CLOEXEC) for the
/// sender's process, or the error making it gave; MSG_CTRUNC without
/// room for it; nothing for a message without a sender pid
fn put_pidfd(m: &mut RecvMsg<'_>, creds: Option<&Creds>) {
    if m.cmsg.room() < CMSG_HDR + 4 {
        m.cmsg.trunc = true;
        return;
    }
    let Some(pid) = creds.and_then(|c| c.pid.clone()) else {
        return;
    };
    let fd = m
        .cmsg
        .reserve_fds(1)
        .and_then(|()| crate::task::pidfd::pidfd_prepare(pid))
        .map_or_else(|e| e.to_errno_neg(), |(fd, f)| m.cmsg.defer_install(fd, f));
    m.cmsg.put(SOL_SOCKET, SCM_PIDFD, &fd.to_ne_bytes());
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
    let fl = if cloexec { crate::task::FD_CLOEXEC } else { 0 };
    let want = count.min(max);
    if fds.try_reserve(want * 4).is_ok() && m.cmsg.reserve_fds(want).is_ok() {
        // Linux receive_fd: reserved, its number copied out, then
        // installed (here once the control data is copied out)
        for f in files.iter().take(want) {
            match crate::fs::io::get_unused_fd_flags(fl) {
                Ok(fd) => {
                    let n = m.cmsg.defer_install(fd, f.clone());
                    fds.extend_from_slice(&n.to_ne_bytes());
                }
                Err(_) => break,
            }
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
