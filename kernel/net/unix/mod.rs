//! AF_UNIX sockets (Linux net/unix/af_unix.c)
//!
//! SOCK_STREAM (`stream.rs`), SOCK_DGRAM and SOCK_SEQPACKET
//! (`dgram.rs`; SOCK_RAW is an alias of SOCK_DGRAM like Linux), with
//! ancillary data in `scm.rs`.
//!
//! Addresses: a filesystem name creates an S_IFSOCK inode (VFS mknod:
//! DAC on the parent, umask; an existing name is EADDRINUSE) and is
//! found again through the inode (`BSD` table, global like Linux's
//! bsd_socket_buckets); connecting needs write permission on it. An
//! abstract name (sun_path[0] == 0) lives in the socket's network
//! namespace, separately per socket type (`UnixTable.names`). Autobind
//! picks "\0" + 5 hex digits. Unlinking the file does not unbind.
//!
//! Data moves between sockets directly: a sender queues `Skb`s on the
//! receiver's queue (`rq`). Each is charged to the sender's `wmem` until
//! it is consumed or dropped, so a sender is bounded by its SO_SNDBUF
//! (Linux sock_alloc_send_pskb / sock_wfree). Datagram receivers are
//! also bounded by queue length (`backlog`: net.unix.max_dgram_qlen,
//! or the listen backlog for listeners, whose queue holds embryo
//! connections) for senders they are not connected back to.
//!
//! ## Locking (Linux af_unix order; see doc/LOCKING.md)
//!
//! - `bindlock` (`sync::Mutex`, sleeping): bind/autobind; taken before
//!   the address tables. bind of a path runs the VFS mknod (parent
//!   i_rwsem) first and takes `bindlock` after it is released; a bind
//!   that then finds the socket bound unlinks the node after dropping
//!   `bindlock` (no i_rwsem under it).
//! - `iolock` (`sync::Mutex`, sleeping): one reader at a time across
//!   dequeue -> user copy -> consume (Linux u->iolock); never held
//!   while waiting for data.
//! - `st` (`crate::sync::spin::Mutex`, the Linux unix_state_lock): peer pointer;
//!   `state`, shutdown bits and `dead` change under it. Two at once:
//!   a listener's before the connecting socket's (stream connect),
//!   otherwise in ascending address order (`lock2`, Linux
//!   unix_state_double_lock).
//! - `rq` (`crate::sync::spin::Mutex`): receive queue, under `st` (senders queue
//!   while holding the receiver's `st`, so they never queue to a dead
//!   socket); leaf except for `relay` wakeups done after unlock.
//! - `UnixTable.st` (per netns) and `BSD` (`crate::sync::spin::RwLock`): after
//!   `bindlock`; `addr` (`crate::sync::spin::RwLock` leaf) is set under them, so a
//!   name found in a table always has its address. Lookups return
//!   `Arc`s; no socket lock is taken under a table lock.
//! - `relay` (`crate::sync::spin::Mutex` leaf; Linux peer_wait.lock for peer_wake),
//!   `peercred` (leaf, Linux sk_peer_lock).
//! - Wakeups (`Sock.wq`, `peer_wait`) happen after unlocking; queued
//!   messages and their files are always dropped with no lock held.

pub mod dgram;
pub mod scm;
pub mod stream;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};

use crate::sync::spin::{Mutex, MutexGuard, RwLock};

use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::fs::Dentry;
use crate::net::NetNamespace;
use crate::net::msg::{RecvMsg, SendMsg};
use crate::net::sock::{RCV_SHUTDOWN, SEND_SHUTDOWN, SHUTDOWN_MASK, Sock, sf};
use crate::net::socket::{
    AF_UNIX, OptIn, OptOut, ProtoOps, SIOCINQ, SIOCOUTQ, SO_PEERCRED, SOCK_DGRAM, SOCK_RAW,
    SOCK_SEQPACKET, SOCK_STREAM, SOL_SOCKET,
};
use crate::sync::Mutex as SMutex;
use crate::waitqueue::WaitQueue;

use scm::{Creds, FpList};

pub const PF_UNIX: i32 = 1;
/// offsetof(struct sockaddr_un, sun_path)
pub const SUN_PATH: usize = 2;
/// sizeof(struct sockaddr_un)
pub const SOCKADDR_UN_LEN: usize = 110;

/// Socket states (Linux reuses the TCP numbers)
pub const ESTABLISHED: u8 = 1;
pub const CLOSE: u8 = 7;
pub const LISTEN: u8 = 10;

/// Buffer charge per message beyond its bytes (Linux skb truesize
/// overhead: struct sk_buff + skb_shared_info), so tiny messages cannot
/// pin unbounded memory
const SKB_OVERHEAD: usize = 576;

/// A bound name (Linux struct unix_address + unix_sock.path)
pub struct UnixAddr {
    /// The sockaddr_un getsockname returns (family + sun_path; Linux
    /// addr->len bytes)
    pub name: Vec<u8>,
    /// The socket inode of a filesystem name
    pub path: Option<Arc<Dentry>>,
}

impl UnixAddr {
    fn is_abstract(&self) -> bool {
        self.path.is_none()
    }
}

/// SO_PEERCRED values (Linux sk_peer_pid + sk_peer_cred as ucred)
#[derive(Clone, Copy)]
pub struct PeerCred {
    pid: i32,
    uid: u32,
    gid: u32,
}

impl PeerCred {
    fn current() -> Self {
        let c = crate::task::current_cred();
        Self {
            pid: crate::task::percpu::current_pid() as i32,
            uid: c.euid,
            gid: c.egid,
        }
    }
}

/// A queued message (Linux sk_buff + UNIXCB)
pub struct Skb {
    pub data: Vec<u8>,
    /// Bytes already read (stream)
    pub consumed: usize,
    /// Sender: holds the buffer charge, source address (Linux skb->sk)
    from: Arc<UnixSock>,
    truesize: usize,
    pub creds: Option<Creds>,
    pub fds: Option<FpList>,
    /// A listener's pending connection (Linux: the embryo is skb->sk)
    pub embryo: Option<Arc<UnixSock>>,
}

impl Skb {
    /// A message from `from` charged to it (call `wmem_wait` first)
    fn new(from: &Arc<UnixSock>, data: Vec<u8>) -> Self {
        let truesize = data.len() + SKB_OVERHEAD;
        from.wmem.fetch_add(truesize, Ordering::AcqRel);
        Self {
            data,
            consumed: 0,
            from: from.clone(),
            truesize,
            creds: None,
            fds: None,
            embryo: None,
        }
    }

    /// Unread bytes
    pub fn len(&self) -> usize {
        self.data.len() - self.consumed
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Linux unix_maybe_add_creds: attach the sender's credentials when
    /// either end passes them or the receiver is an embryo (no socket
    /// file yet), unless the sender gave SCM_CREDENTIALS
    fn add_creds(&mut self, me: &UnixSock, other: &UnixSock) {
        if self.creds.is_none() && (me.passcred() || other.passcred() || !other.has_file()) {
            self.creds = Some(Creds::current());
        }
    }
}

impl Drop for Skb {
    /// Linux sock_wfree: return the charge, wake a blocked writer
    fn drop(&mut self) {
        self.from.wfree(self.truesize);
    }
}

/// A receive queue (Linux sk_receive_queue)
#[derive(Default)]
pub struct RxQueue {
    pub q: VecDeque<Skb>,
    /// Unread bytes (Linux unix_sock.inq_len)
    pub bytes: usize,
}

impl RxQueue {
    fn push(&mut self, skb: Skb) {
        self.bytes += skb.len();
        self.q.push_back(skb);
    }

    fn take_all(&mut self) -> VecDeque<Skb> {
        self.bytes = 0;
        core::mem::take(&mut self.q)
    }
}

/// An AF_UNIX socket (Linux struct unix_sock)
pub struct UnixSock {
    pub sk: Sock,
    me: Weak<UnixSock>,
    /// unix_state_lock: the peer (Linux unix_peer)
    st: Mutex<Option<Arc<UnixSock>>>,
    /// ESTABLISHED / CLOSE / LISTEN, written under `st`
    state: AtomicU8,
    rq: Mutex<RxQueue>,
    addr: RwLock<Option<Arc<UnixAddr>>>,
    iolock: SMutex<()>,
    bindlock: SMutex<()>,
    /// Writers waiting for room in our queue, connectors waiting for
    /// the backlog (Linux peer_wait)
    peer_wait: WaitQueue,
    /// Sockets whose pollers wait for room in our queue (Linux
    /// peer_wake entries on peer_wait): woken once, then dropped
    relay: Mutex<Vec<Weak<UnixSock>>>,
    /// Address of the socket whose `relay` holds us (0 = none),
    /// changed under that socket's `relay`
    peer_wake: AtomicUsize,
    /// Bytes charged for our messages not yet consumed (sk_wmem_alloc)
    wmem: AtomicUsize,
    /// Released (Linux SOCK_DEAD), set under `st`
    dead: AtomicBool,
    /// Queue length limit (Linux sk_max_ack_backlog)
    backlog: AtomicU32,
    peercred: Mutex<Option<PeerCred>>,
}

/// A held unix_state_lock
type StGuard<'a> = MutexGuard<'a, Option<Arc<UnixSock>>>;

/// All sockets and abstract names of a network namespace (Linux
/// net->unx.table)
#[derive(Default)]
pub struct UnixTable {
    st: RwLock<Tables>,
}

#[derive(Default)]
struct Tables {
    socks: BTreeMap<usize, Weak<UnixSock>>,
    /// (type, sockaddr bytes) -> socket
    names: BTreeMap<(i32, Vec<u8>), Weak<UnixSock>>,
}

impl UnixTable {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, s: &Arc<UnixSock>) {
        self.st.write().socks.insert(s.id(), Arc::downgrade(s));
    }

    /// Unhash at release: the socket, and its abstract name if it owns
    /// it (an accepted socket shares its listener's name)
    fn remove(&self, s: &UnixSock) {
        let mut t = self.st.write();
        t.socks.remove(&s.id());
        if let Some(a) = s.addr().filter(|a| a.is_abstract()) {
            let key = (s.sk.stype, a.name.clone());
            if t.names
                .get(&key)
                .is_some_and(|w| core::ptr::eq(w.as_ptr(), s))
            {
                t.names.remove(&key);
            }
        }
    }

    /// Bind an abstract name (EADDRINUSE if taken); the address is
    /// published under the table lock
    fn bind(&self, s: &Arc<UnixSock>, name: Vec<u8>) -> Result<(), KernelError> {
        let mut t = self.st.write();
        let key = (s.sk.stype, name);
        if t.names.get(&key).is_some_and(|w| w.strong_count() > 0) {
            return Err(KernelError::AddressInUse);
        }
        *s.addr.write() = Some(Arc::new(UnixAddr {
            name: key.1.clone(),
            path: None,
        }));
        t.names.insert(key, Arc::downgrade(s));
        Ok(())
    }

    fn find(&self, stype: i32, name: &[u8]) -> Option<Arc<UnixSock>> {
        let t = self.st.read();
        t.names.get(&(stype, name.to_vec()))?.upgrade()
    }

    fn all(&self) -> Vec<Arc<UnixSock>> {
        let t = self.st.read();
        t.socks.values().filter_map(|w| w.upgrade()).collect()
    }
}

/// Sockets bound to filesystem names, by socket inode (Linux
/// bsd_socket_buckets; global: a path reaches across namespaces)
static BSD: RwLock<BTreeMap<usize, Weak<UnixSock>>> = RwLock::new(BTreeMap::new());

fn inode_key(d: &Dentry) -> Option<usize> {
    d.get_inode().map(|i| Arc::as_ptr(&i) as usize)
}

impl UnixSock {
    /// A new socket in `net` (Linux unix_create1)
    fn new(net: Arc<NetNamespace>, stype: i32) -> Arc<Self> {
        let qlen = net.sysctl.unix_max_dgram_qlen.load(Ordering::Relaxed) as u32;
        let s = Arc::new_cyclic(|me| Self {
            sk: Sock::new(net, AF_UNIX, stype, 0),
            me: me.clone(),
            st: Mutex::new(None),
            state: AtomicU8::new(CLOSE),
            rq: Mutex::new(RxQueue::default()),
            addr: RwLock::new(None),
            iolock: SMutex::new(()),
            bindlock: SMutex::new(()),
            peer_wait: WaitQueue::new(),
            relay: Mutex::new(Vec::new()),
            peer_wake: AtomicUsize::new(0),
            wmem: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
            backlog: AtomicU32::new(qlen),
            peercred: Mutex::new(None),
        });
        s.sk.net.unix.insert(&s);
        s
    }

    fn arc(&self) -> Arc<Self> {
        self.me.upgrade().expect("unix socket in use")
    }

    /// Identity (lock order, tables)
    fn id(&self) -> usize {
        self as *const Self as usize
    }

    pub fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    /// Change state (caller holds `st`)
    fn set_state(&self, s: u8) {
        self.state.store(s, Ordering::Release);
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// Linux unix_peer_get
    pub fn peer(&self) -> Option<Arc<UnixSock>> {
        self.st.lock().clone()
    }

    pub fn addr(&self) -> Option<Arc<UnixAddr>> {
        self.addr.read().clone()
    }

    fn passcred(&self) -> bool {
        self.sk.flag(sf::PASSCRED)
    }

    /// Has a socket file (an embryo gets one when accepted)
    fn has_file(&self) -> bool {
        self.sk.ino.load(Ordering::Acquire) != 0
    }

    fn connected_type(&self) -> bool {
        self.sk.stype == SOCK_STREAM || self.sk.stype == SOCK_SEQPACKET
    }

    /// Linux unix_recvq_full_lockless: more queued than the limit
    fn recvq_full(&self) -> bool {
        self.rq.lock().q.len() as u64 > self.backlog.load(Ordering::Acquire) as u64
    }

    /// Linux unix_writable: under a quarter of sndbuf in flight
    fn writable(&self) -> bool {
        self.state() != LISTEN && self.wmem.load(Ordering::Acquire) * 4 <= self.sk.sndbuf() as usize
    }

    /// Linux sock_wfree + unix_write_space
    fn wfree(&self, truesize: usize) {
        self.wmem.fetch_sub(truesize, Ordering::AcqRel);
        if self.writable() {
            self.sk.write_space();
        }
    }

    /// Wait until a message may be charged (Linux sock_alloc_send_pskb):
    /// a pending error first, EPIPE after SHUT_WR, then room below
    /// sndbuf (one message may overshoot it)
    fn wmem_wait(&self, timeo: &mut u64) -> Result<(), KernelError> {
        loop {
            if let Some(e) = self.sk.take_err() {
                return Err(e);
            }
            if self.sk.shutdown() & SEND_SHUTDOWN != 0 {
                return Err(KernelError::BrokenPipe);
            }
            if self.wmem.load(Ordering::Acquire) < self.sk.sndbuf() as usize {
                return Ok(());
            }
            *timeo = self.sk.wait(*timeo, || {
                self.wmem.load(Ordering::Acquire) < self.sk.sndbuf() as usize
                    || self.sk.has_err()
                    || self.sk.shutdown() & SEND_SHUTDOWN != 0
            })?;
        }
    }

    /// Lock two sockets' `st` in address order (Linux
    /// unix_state_double_lock); `b` may be `a`
    fn lock2<'a>(a: &'a UnixSock, b: &'a UnixSock) -> (StGuard<'a>, Option<StGuard<'a>>) {
        if a.id() == b.id() {
            return (a.st.lock(), None);
        }
        if a.id() < b.id() {
            let ga = a.st.lock();
            let gb = b.st.lock();
            (ga, Some(gb))
        } else {
            let gb = b.st.lock();
            let ga = a.st.lock();
            (ga, Some(gb))
        }
    }

    // --- binding -----------------------------------------------------------

    /// Linux unix_bind
    fn do_bind(&self, a: &[u8]) -> Result<(), KernelError> {
        if a.len() == SUN_PATH && family(a) == AF_UNIX {
            return self.autobind();
        }
        validate(a)?;
        if a[SUN_PATH] != 0 {
            self.bind_bsd(a)
        } else {
            self.bind_abstract(a.to_vec())
        }
    }

    /// Linux unix_bind_bsd: create the inode first (EEXIST is
    /// EADDRINUSE), then fail with EINVAL, removing it, if this socket
    /// got bound meanwhile
    fn bind_bsd(&self, a: &[u8]) -> Result<(), KernelError> {
        let (path, name) = bsd_name(a)?;
        let d = crate::fs::dir::mknod_sock(&path, 0o777).map_err(|e| match e {
            KernelError::AlreadyExists => KernelError::AddressInUse,
            e => e,
        })?;
        let b = self.bindlock.lock();
        if self.addr().is_some() {
            // Unlinked after bindlock is dropped (Linux out_unlink: the
            // parent's i_rwsem is never taken under bindlock)
            drop(b);
            crate::fs::dir::unlink_sock(&path);
            return Err(KernelError::InvalidArgument);
        }
        let key = inode_key(&d).ok_or(KernelError::NotFound)?;
        let mut t = BSD.write();
        *self.addr.write() = Some(Arc::new(UnixAddr {
            name,
            path: Some(d),
        }));
        t.insert(key, self.me.clone());
        Ok(())
    }

    fn bind_abstract(&self, name: Vec<u8>) -> Result<(), KernelError> {
        let _b = self.bindlock.lock();
        if self.addr().is_some() {
            return Err(KernelError::InvalidArgument);
        }
        self.sk.net.unix.bind(&self.arc(), name)
    }

    /// Linux unix_autobind: "\0" + 5 hex digits from a random start;
    /// ENOSPC when all 2^20 are taken
    pub fn autobind(&self) -> Result<(), KernelError> {
        let _b = self.bindlock.lock();
        if self.addr().is_some() {
            return Ok(());
        }
        let me = self.arc();
        let mut n = crate::random::get_random_u32() & 0xFFFFF;
        let last = n;
        loop {
            n = (n + 1) & 0xFFFFF;
            let mut name = Vec::with_capacity(SUN_PATH + 6);
            name.extend_from_slice(&AF_UNIX.to_ne_bytes());
            name.push(0);
            let mut hex = String::new();
            let _ = write!(hex, "{:05x}", n);
            name.extend_from_slice(hex.as_bytes());
            match self.sk.net.unix.bind(&me, name) {
                Err(KernelError::AddressInUse) if n != last => continue,
                Err(KernelError::AddressInUse) => return Err(KernelError::NoSpace),
                r => return r,
            }
        }
    }

    /// Autobind first when credentials are passed (Linux
    /// unix_may_passcred && !u->addr)
    fn passcred_autobind(&self) -> Result<(), KernelError> {
        if self.passcred() && self.addr().is_none() {
            self.autobind()?;
        }
        Ok(())
    }

    // --- release -----------------------------------------------------------

    /// Linux unix_release_sock: unhash, mark dead, hang up a connected
    /// peer (ECONNRESET if we leave unread data or are an unaccepted
    /// embryo), drop our queue (a listener's pending connections are
    /// released as embryos)
    fn release_sock(&self, embryo: bool) {
        self.sk.net.unix.remove(self);
        self.unhash_bsd();
        let (state, peer) = {
            let mut st = self.st.lock();
            self.dead.store(true, Ordering::Release);
            self.sk.or_shutdown(SHUTDOWN_MASK);
            let state = self.state();
            self.set_state(CLOSE);
            (state, st.take())
        };
        self.sk.state_change();
        self.peer_wait.wake_all();
        if let Some(p) = peer {
            if self.connected_type() {
                let unread = !self.rq.lock().q.is_empty();
                {
                    let _g = p.st.lock();
                    p.sk.or_shutdown(SHUTDOWN_MASK);
                    if unread || embryo {
                        p.sk.store_err(KernelError::ConnectionReset as u32);
                    }
                }
                p.sk.state_change();
            }
            dgram::peer_wake_disconnect(self, &p);
        }
        let q = self.rq.lock().take_all();
        for mut skb in q {
            if state == LISTEN
                && let Some(e) = skb.embryo.take()
            {
                e.release_sock(true);
            }
        }
        self.relay_wake();
    }

    fn unhash_bsd(&self) {
        let Some(key) = self
            .addr()
            .and_then(|a| a.path.as_ref().and_then(|d| inode_key(d)))
        else {
            return;
        };
        let mut t = BSD.write();
        if t.get(&key).is_some_and(|w| core::ptr::eq(w.as_ptr(), self)) {
            t.remove(&key);
        }
    }

    // --- wakeups -----------------------------------------------------------

    /// Room was made in our queue: wake blocked writers and relay to
    /// pollers (Linux wake_up on peer_wait + unix_dgram_peer_wake_relay)
    fn relay_wake(&self) {
        self.peer_wait.wake_all();
        let waiters = {
            let mut r = self.relay.lock();
            for w in r.iter().filter_map(|w| w.upgrade()) {
                w.peer_wake.store(0, Ordering::Release);
            }
            core::mem::take(&mut *r)
        };
        for w in waiters.iter().filter_map(|w| w.upgrade()) {
            w.sk.write_space();
        }
    }

    // --- options -----------------------------------------------------------

    /// SO_PEERCRED: struct ucred of the peer captured at connect,
    /// listen or socketpair
    fn peercred_opt(&self) -> OptOut {
        let c = *self.peercred.lock();
        OptOut::Bytes(crate::net::socket::peercred_bytes(
            c.map(|c| (c.pid, c.uid, c.gid)),
        ))
    }

    /// Linux unix_inq_len: EINVAL on a listener; a stream's unread
    /// bytes, a seqpacket's queued bytes, a datagram socket's first
    /// message
    fn inq_len(&self) -> Result<usize, KernelError> {
        if self.state() == LISTEN {
            return Err(KernelError::InvalidArgument);
        }
        let q = self.rq.lock();
        Ok(match self.sk.stype {
            SOCK_STREAM | SOCK_SEQPACKET => q.bytes,
            _ => q.q.front().map_or(0, |s| s.len()),
        })
    }
}

/// sun_family of a sockaddr
fn family(a: &[u8]) -> u16 {
    u16::from_ne_bytes([a[0], a[1]])
}

/// Linux unix_validate_addr: a name and at most sizeof(sockaddr_un)
fn validate(a: &[u8]) -> Result<(), KernelError> {
    if a.len() <= SUN_PATH || a.len() > SOCKADDR_UN_LEN || family(a) != AF_UNIX {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

/// Linux unix_mkname_bsd: the path ends at the first NUL (or the
/// address end); the stored name is family + path + NUL
fn bsd_name(a: &[u8]) -> Result<(String, Vec<u8>), KernelError> {
    let p = &a[SUN_PATH..];
    let n = p.iter().position(|&c| c == 0).unwrap_or(p.len());
    let path = core::str::from_utf8(&p[..n]).map_err(|_| KernelError::InvalidArgument)?;
    let mut name = a[..SUN_PATH + n].to_vec();
    name.push(0);
    Ok((String::from(path), name))
}

/// Find the socket an address names (Linux unix_find_other): a path
/// needs write permission on its inode and a bound socket of the same
/// type (ECONNREFUSED, EPROTOTYPE); an abstract name is per type
fn find_other(net: &NetNamespace, a: &[u8], stype: i32) -> Result<Arc<UnixSock>, KernelError> {
    if a[SUN_PATH] == 0 {
        return net
            .unix
            .find(stype, a)
            .ok_or(KernelError::ConnectionRefused);
    }
    let (path, _) = bsd_name(a)?;
    let d = crate::fs::path::lookup_path(&path)?;
    let inode = d.get_inode().ok_or(KernelError::NotFound)?;
    crate::fs::dac::permission_as(&crate::task::current_cred(), &inode, crate::fs::MAY_WRITE)?;
    if !inode.mode().is_socket() {
        return Err(KernelError::ConnectionRefused);
    }
    let key = Arc::as_ptr(&inode) as usize;
    let s = BSD
        .read()
        .get(&key)
        .and_then(|w| w.upgrade())
        .ok_or(KernelError::ConnectionRefused)?;
    if s.sk.stype != stype {
        return Err(KernelError::ProtocolType);
    }
    Ok(s)
}

/// socket(AF_UNIX, type, protocol) (Linux unix_create)
pub fn create(stype: i32, protocol: i32) -> Result<Arc<dyn ProtoOps>, KernelError> {
    if protocol != 0 && protocol != PF_UNIX {
        return Err(KernelError::ProtocolNotSupported);
    }
    let stype = match stype {
        SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET => stype,
        SOCK_RAW => SOCK_DGRAM,
        _ => return Err(KernelError::SocketTypeNotSupported),
    };
    Ok(UnixSock::new(crate::net::current_net_ns(), stype))
}

impl ProtoOps for UnixSock {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sk(&self) -> &Sock {
        &self.sk
    }

    fn release(&self) {
        self.release_sock(false);
    }

    fn bind(&self, a: &[u8]) -> Result<(), KernelError> {
        if a.len() < SUN_PATH {
            return Err(KernelError::InvalidArgument);
        }
        self.do_bind(a)
    }

    fn connect(&self, a: &[u8], nonblock: bool) -> Result<(), KernelError> {
        if self.sk.stype == SOCK_DGRAM {
            dgram::connect(self, a)
        } else {
            stream::connect(self, a, nonblock)
        }
    }

    fn listen(&self, backlog: i32) -> Result<(), KernelError> {
        stream::listen(self, backlog)
    }

    fn accept(&self, nonblock: bool) -> Result<Arc<dyn ProtoOps>, KernelError> {
        stream::accept(self, nonblock).map(|s| s as Arc<dyn ProtoOps>)
    }

    /// Linux unix_getname: an unnamed socket is just the family
    fn getname(&self, peer: bool) -> Result<Vec<u8>, KernelError> {
        let s = if peer {
            self.peer().ok_or(KernelError::NotConnected)?
        } else {
            self.arc()
        };
        Ok(match s.addr() {
            Some(a) => a.name.clone(),
            None => AF_UNIX.to_ne_bytes().to_vec(),
        })
    }

    fn poll(&self) -> u16 {
        if self.sk.stype == SOCK_STREAM {
            stream::poll(self)
        } else {
            dgram::poll(self)
        }
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let v = match cmd {
            SIOCOUTQ => self.wmem.load(Ordering::Acquire),
            SIOCINQ => self.inq_len()?,
            _ => return Err(KernelError::NotTty),
        };
        crate::uaccess::put_user::<Uaccess, i32>(arg, v as i32)
            .map_err(|_| KernelError::BadAddress)?;
        Ok(0)
    }

    fn inq(&self) -> usize {
        self.inq_len().unwrap_or(0)
    }

    /// Linux unix_shutdown: set our bits; a connected stream/seqpacket
    /// peer gets the mirror image (our SHUT_WR is its RCV_SHUTDOWN)
    fn shutdown(&self, how: i32) -> Result<(), KernelError> {
        let mode = crate::net::socket::shut_bits(how)?;
        let peer = {
            let st = self.st.lock();
            self.sk.or_shutdown(mode);
            st.clone()
        };
        self.sk.state_change();
        if let Some(p) = peer.filter(|_| self.connected_type()) {
            let mut pm = 0;
            if mode & RCV_SHUTDOWN != 0 {
                pm |= SEND_SHUTDOWN;
            }
            if mode & SEND_SHUTDOWN != 0 {
                pm |= RCV_SHUTDOWN;
            }
            {
                let _g = p.st.lock();
                p.sk.or_shutdown(pm);
            }
            p.sk.state_change();
        }
        Ok(())
    }

    /// Linux unix_setsockopt: only SOL_SOCKET (EOPNOTSUPP otherwise)
    fn setsockopt(&self, level: i32, _opt: i32, _v: OptIn) -> Option<Result<(), KernelError>> {
        (level != SOL_SOCKET).then_some(Err(KernelError::OperationNotSupported))
    }

    /// Linux: no proto getsockopt (EOPNOTSUPP), SO_PEERCRED from the
    /// connection
    fn getsockopt(&self, level: i32, opt: i32) -> Option<Result<OptOut, KernelError>> {
        if level != SOL_SOCKET {
            return Some(Err(KernelError::OperationNotSupported));
        }
        (opt == SO_PEERCRED).then(|| Ok(self.peercred_opt()))
    }

    fn sendmsg(&self, m: &mut SendMsg, flags: i32) -> Result<usize, KernelError> {
        match self.sk.stype {
            SOCK_STREAM => stream::sendmsg(self, m, flags),
            SOCK_SEQPACKET => dgram::seqpacket_sendmsg(self, m, flags),
            _ => dgram::sendmsg(self, m, flags),
        }
    }

    fn recvmsg(&self, m: &mut RecvMsg, flags: i32) -> Result<usize, KernelError> {
        match self.sk.stype {
            SOCK_STREAM => stream::recvmsg(self, m, flags),
            SOCK_SEQPACKET => dgram::seqpacket_recvmsg(self, m, flags),
            _ => dgram::recvmsg(self, m, flags),
        }
    }

    /// Linux unix_socketpair: back to back, both established, each with
    /// the creator's credentials as peer credentials
    fn socketpair(&self, other: &dyn ProtoOps) -> Result<(), KernelError> {
        let b = other
            .as_any()
            .downcast_ref::<UnixSock>()
            .ok_or(KernelError::InvalidArgument)?
            .arc();
        let a = self.arc();
        let cred = PeerCred::current();
        *a.peercred.lock() = Some(cred);
        *b.peercred.lock() = Some(cred);
        let (mut ga, gb) = UnixSock::lock2(&a, &b);
        *ga = Some(b.clone());
        if let Some(mut gb) = gb {
            *gb = Some(a.clone());
        }
        a.set_state(ESTABLISHED);
        b.set_state(ESTABLISHED);
        Ok(())
    }

    /// Only stream sockets raise SIGPIPE (Linux unix_stream_sendmsg;
    /// datagram EPIPE comes from sock_alloc_send_pskb without one)
    fn sigpipe(&self) -> bool {
        self.sk.stype == SOCK_STREAM
    }
}

// ============================================================================
// /proc/net/unix (Linux unix_seq_show)
// ============================================================================

/// __SO_ACCEPTCON
const SO_ACCEPTCON: u32 = 1 << 16;
/// socket_state
const SS_UNCONNECTED: u8 = 1;
const SS_CONNECTING: u8 = 2;
const SS_CONNECTED: u8 = 3;
const SS_DISCONNECTING: u8 = 4;

/// One line: kernel addresses print as 0 (Linux %pK for readers without
/// CAP_SYSLOG under kptr_restrict)
fn proc_line(out: &mut String, s: &Arc<UnixSock>) {
    let est = s.state() == ESTABLISHED;
    let st = match (s.has_file(), est) {
        (true, true) => SS_CONNECTED,
        (true, false) => SS_UNCONNECTED,
        (false, true) => SS_CONNECTING,
        (false, false) => SS_DISCONNECTING,
    };
    let flags = if s.state() == LISTEN { SO_ACCEPTCON } else { 0 };
    let _ = write!(
        out,
        "{:016x}: {:08X} {:08X} {:08X} {:04X} {:02X} {:5}",
        0,
        Arc::strong_count(s),
        0,
        flags,
        s.sk.stype,
        st,
        s.sk.ino.load(Ordering::Acquire)
    );
    if let Some(a) = s.addr() {
        out.push(' ');
        let p = &a.name[SUN_PATH..];
        let p = if a.is_abstract() {
            out.push('@');
            &p[1..]
        } else {
            &p[..p.len() - 1]
        };
        for &c in p {
            out.push(if c == 0 { '@' } else { c as char });
        }
    }
    out.push('\n');
}

/// `/proc/net/unix` of the reader's namespace
pub fn proc_net_unix() -> Vec<u8> {
    let mut out = String::from("Num       RefCount Protocol Flags    Type St Inode Path\n");
    for s in crate::net::current_net_ns().unix.all() {
        proc_line(&mut out, &s);
    }
    out.into_bytes()
}

/// Queue `skb` on `to` (caller holds `to.st`, so `to` is alive) and
/// charge its files as in flight
fn queue(to: &UnixSock, mut skb: Skb) {
    if let Some(f) = skb.fds.as_mut() {
        f.queued();
    }
    to.rq.lock().push(skb);
}

/// Shutdown bits test helper
fn rcv_shut(s: &UnixSock) -> bool {
    s.sk.shutdown() & RCV_SHUTDOWN != 0
}

/// Common receive tail: credentials and files into control messages
fn scm_recv(s: &UnixSock, m: &mut RecvMsg, creds: Option<Creds>, fds: Option<FpList>) {
    scm::put(m, s.passcred(), creds, fds);
}
