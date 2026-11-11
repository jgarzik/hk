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
//! namespace, hashed with the socket type (`UnixTable`). Autobind
//! picks "\0" + 5 hex digits. Unlinking the file does not unbind.
//!
//! Data moves between sockets directly: a sender queues skbs (`UnixCb`
//! in their cb) on the receiver's queue (`rq`). Each is charged to the sender's `wmem` until
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
//! - `rq` (an `SkbOwnedQueue`, spin): receive queue, under `st`
//!   (senders queue while holding the receiver's `st`, so they never
//!   queue to a dead socket); a leaf (`UnixCb.fp` aside): a message's
//!   `Arc` is made before it, a reader takes a reference under it and
//!   copies after, and taken messages are freed after it.
//! - `UnixTable` buckets (per netns) and `BSD` buckets (global):
//!   `crate::sync::spin::Mutex` per bucket (Linux unx.table.locks,
//!   bsd_socket_locks), sockets linked intrusively and held weakly;
//!   after `bindlock`. A bind makes its address first, then moves the
//!   socket between two buckets locked in index order and publishes
//!   `addr` (`crate::sync::spin::RwLock` leaf) under them, so a name
//!   found in a bucket always has its address. Lookups return `Arc`s,
//!   dropped after the bucket lock; no socket lock is taken under one;
//!   /proc/net/unix formats each bucket under its lock into a `SeqBuf`.
//! - `relay` (`crate::sync::spin::Mutex`; Linux peer_wait.lock for
//!   peer_wake registrations) -> `peer_wait`'s head: a datagram poller
//!   (or sender) that finds its peer's queue full links its own
//!   `peer_wake` entry there, under its own `st` (the peer stays its
//!   peer); the peer's reader wakes `peer_wait`, whose relay callback
//!   unlinks the entry and wakes the poller's `Sock.wq` (head -> head,
//!   never the reverse). Nothing is allocated.
//!   `peercred` (leaf, Linux sk_peer_lock).
//! - Wakeups (`Sock.wq`, `peer_wait`) happen after unlocking; queued
//!   messages and their files are always dropped with no lock held.

pub mod dgram;
pub mod scm;
pub mod stream;

use crate::util::kalloc::{try_arc, try_arc_cyclic, try_box};
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};

use crate::sync::spin::{Mutex, MutexGuard, RwLock};

use crate::fs::Dentry;
use crate::fs::proc::seq::SeqBuf;
use crate::io::fasync::{POLL_HUP, POLL_IN};
use crate::io::poll::{POLLOUT, POLLWRBAND, POLLWRNORM};
use crate::net::NetNamespace;
use crate::net::msg::{RecvMsg, SendMsg};
use crate::net::skb::{SkBuff, SkbCb, SkbOwned, SkbOwnedQueue};
use crate::net::sock::{RCV_SHUTDOWN, SEND_SHUTDOWN, SHUTDOWN_MASK, Sock, WakeHow, sf};
use crate::net::socket::{
    AF_UNIX, OptIn, OptOut, ProtoOps, SIOCINQ, SIOCOUTQ, SO_PEERCRED, SOCK_DGRAM, SOCK_RAW,
    SOCK_SEQPACKET, SOCK_STREAM, SOL_SOCKET,
};
use crate::sync::Mutex as SMutex;
use crate::sync::waitqueue::{WaitEntry, WaitQueue};
use crate::util::error::KernelError;
use crate::util::list::{Link, OwnedList, WeakList};
use core::pin::Pin;

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

/// SO_PEERCRED values (Linux sk_peer_pid + sk_peer_cred): the peer's
/// struct pid, numbered for each reader
#[derive(Clone)]
pub struct PeerCred {
    pid: Option<Arc<crate::task::pid::Pid>>,
    uid: u32,
    gid: u32,
}

impl PeerCred {
    fn current() -> Self {
        let c = crate::task::current_cred();
        Self {
            pid: crate::task::pid::find_pid(
                &crate::ns::INIT_PID_NS,
                crate::task::percpu::current_pid() as u32,
            ),
            uid: c.euid,
            gid: c.egid,
        }
    }
}

/// A sender's buffer charge for one message, returned when the skb is
/// freed (Linux skb->sk + sock_wfree, the skb destructor)
pub struct Wmem {
    /// The sender (its address is the message's source)
    pub from: Arc<UnixSock>,
    truesize: usize,
}

impl Drop for Wmem {
    /// Linux sock_wfree: return the charge, wake a blocked writer
    fn drop(&mut self) {
        self.from.wfree(self.truesize);
    }
}

/// What a queued AF_UNIX message keeps beside its bytes (Linux UNIXCB
/// and the skb's owner). Queued messages and the files they carry are
/// freed only with no spin lock held: their drop returns the charge
/// (waking writers) and may release sockets.
pub struct UnixCb {
    pub wmem: Wmem,
    pub creds: Option<Creds>,
    /// The files (Linux UNIXCB.fp): changed only by the `iolock`
    /// holder (the reader that takes them, a peek that copies them);
    /// a leaf lock, nothing allocated under it
    pub fp: Mutex<Option<FpList>>,
    /// Bytes already read (stream; Linux UNIXCB.consumed): written
    /// under `iolock`
    consumed: AtomicUsize,
    /// A listener's pending connection (Linux: the embryo is skb->sk)
    pub embryo: Option<Arc<UnixSock>>,
}

/// A message from `from` of `data`, charged to it (call `wmem_wait`
/// first); its `Arc` is made by the caller before any lock
fn unix_skb(from: &Arc<UnixSock>, data: Vec<u8>) -> Result<SkBuff, KernelError> {
    let truesize = data.len() + SKB_OVERHEAD;
    from.wmem.fetch_add(truesize, Ordering::AcqRel);
    let wmem = Wmem {
        from: from.clone(),
        truesize,
    };
    let cb = try_box(UnixCb {
        wmem,
        creds: None,
        fp: Mutex::new(None),
        consumed: AtomicUsize::new(0),
        embryo: None,
    })?;
    let mut skb = SkBuff::from_vec(data);
    skb.cb = SkbCb::Unix(cb);
    Ok(skb)
}

/// The `UnixCb` of a message (every skb on a unix queue has one)
pub fn ucb(skb: &SkBuff) -> &UnixCb {
    match &skb.cb {
        SkbCb::Unix(c) => c,
        _ => unreachable!("AF_UNIX skb without its cb"),
    }
}

fn ucb_mut(skb: &mut SkBuff) -> &mut UnixCb {
    match &mut skb.cb {
        SkbCb::Unix(c) => c,
        _ => unreachable!("AF_UNIX skb without its cb"),
    }
}

/// Unread bytes (Linux unix_skb_len)
pub fn unix_len(skb: &SkBuff) -> usize {
    skb.len() - ucb(skb).consumed.load(Ordering::Acquire)
}

/// Linux unix_maybe_add_creds: attach the sender's credentials when
/// either end passes them or the receiver is an embryo (no socket file
/// yet), unless the sender gave SCM_CREDENTIALS
fn add_creds(skb: &mut SkBuff, me: &UnixSock, other: &UnixSock) {
    let cb = ucb_mut(skb);
    if cb.creds.is_none() && (me.passcred() || other.passcred() || !other.has_file()) {
        cb.creds = Some(Creds::current());
    }
}

/// The message's files, copied for MSG_PEEK (Linux unix_peek_fds:
/// scm_fp_dup, not in flight itself). The `iolock` holder takes them
/// out, copies them with no lock held and puts them back.
fn peek_fds(skb: &SkBuff) -> Option<FpList> {
    let cb = ucb(skb);
    let fp = cb.fp.lock().take()?;
    let dup = fp.dup();
    *cb.fp.lock() = Some(fp);
    Some(dup)
}

/// An AF_UNIX socket (Linux struct unix_sock)
///
/// # Invariants
/// Lives only in the `Arc` `new` makes (never moved), so `peer_wake`
/// is pinned. `peer_wake` is linked only on the `peer_wait` of the
/// socket `peer_wake_to` names, which is our peer while it is linked
/// (we hold it through `st`), and it is the first field: its drop
/// unlinks it before anything else of ours (or our peer) goes.
pub struct UnixSock {
    /// Our entry on the peer's `peer_wait` while a poller waits for
    /// room in its queue (Linux unix_sock.peer_wake)
    peer_wake: WaitEntry,
    pub sk: Sock,
    me: Weak<UnixSock>,
    /// unix_state_lock: the peer (Linux unix_peer)
    st: Mutex<Option<Arc<UnixSock>>>,
    /// ESTABLISHED / CLOSE / LISTEN, written under `st`
    state: AtomicU8,
    /// Receive queue (Linux sk_receive_queue): messages in their
    /// `Arc`s, made before the lock
    rq: SkbOwnedQueue,
    /// Unread bytes queued (Linux unix_sock.inq_len), changed under
    /// `rq`'s lock
    inq_len: AtomicUsize,
    addr: RwLock<Option<Arc<UnixAddr>>>,
    iolock: SMutex<()>,
    bindlock: SMutex<()>,
    /// Writers waiting for room in our queue, connectors waiting for
    /// the backlog (Linux peer_wait)
    peer_wait: WaitQueue,
    /// Serializes peer_wake registrations on our `peer_wait` (Linux
    /// takes peer_wait.lock for them)
    relay: Mutex<()>,
    /// Address of the socket whose `peer_wait` has our `peer_wake`
    /// (0 = none; Linux peer_wake.private): set under that socket's
    /// `relay`, cleared under it or by the relay wakeup
    peer_wake_to: AtomicUsize,
    /// Bytes charged for our messages not yet consumed (sk_wmem_alloc)
    wmem: AtomicUsize,
    /// Released (Linux SOCK_DEAD), set under `st`
    dead: AtomicBool,
    /// Queue length limit (Linux sk_max_ack_backlog)
    backlog: AtomicU32,
    peercred: Mutex<Option<PeerCred>>,
    /// Link on our namespace table's bucket (Linux sk_node)
    node: Link,
    /// Link on a `BSD` bucket while bound to a path (Linux sk_bind_node)
    bind_node: Link,
    /// Our table bucket (Linux sk_hash): changes under the old and new
    /// buckets' locks; a filesystem binding's `BSD` bucket is its inode
    /// number's
    hash: AtomicU32,
}

impl Drop for UnixSock {
    /// A socket never released (its creation failed before it had a
    /// file) leaves the tables first: they hold it weakly and walkers
    /// read linked sockets (WeakList's contract)
    fn drop(&mut self) {
        self.sk.net.unix.remove(self);
        self.unhash_bsd();
    }
}

/// A held unix_state_lock
type StGuard<'a> = MutexGuard<'a, Option<Arc<UnixSock>>>;

/// Buckets per half of a namespace's table (Linux UNIX_HASH_SIZE)
const UNIX_HASH_SIZE: usize = 256;
const UNIX_HASH_MOD: u32 = UNIX_HASH_SIZE as u32 - 1;

crate::adapter!(UnixNode, UnixSock, node);
crate::adapter!(UnixBindNode, UnixSock, bind_node);

/// A hash bucket: sockets linked through `node` (or `bind_node`), held
/// weakly (Linux __sk_add_node takes no reference); a socket leaves it
/// at release or, if never released, first thing in its drop
type Bucket<A> = Mutex<WeakList<A>>;

/// All sockets of a network namespace (Linux net->unx.table): unbound
/// and filesystem-bound ones in the lower half, by address or inode
/// number; abstract names in the upper half, by name and type. Each
/// bucket has its own spin lock (Linux unx.table.locks), taken two at a
/// time in index order when a bind moves a socket.
pub struct UnixTable {
    buckets: Box<[Bucket<UnixNode>]>,
}

impl Default for UnixTable {
    fn default() -> Self {
        Self {
            buckets: (0..2 * UNIX_HASH_SIZE)
                .map(|_| Mutex::new(WeakList::new()))
                .collect(),
        }
    }
}

/// Sockets bound to filesystem names, by socket inode number (Linux
/// bsd_socket_buckets and bsd_socket_locks; global: a path reaches
/// across namespaces), linked through `bind_node`
static BSD: [Bucket<UnixBindNode>; UNIX_HASH_SIZE] =
    [const { Mutex::new(WeakList::new()) }; UNIX_HASH_SIZE];

/// Linux unix_unbound_hash
fn unbound_hash(s: &UnixSock) -> u32 {
    let mut h = s.id();
    h ^= h >> 16;
    h ^= h >> 8;
    // Truncation intended: a bucket index
    (h as u32 ^ s.sk.stype as u32) & UNIX_HASH_MOD
}

/// Linux unix_bsd_hash
fn bsd_hash(ino: u64) -> u32 {
    // Truncation intended: a bucket index
    ino as u32 & UNIX_HASH_MOD
}

/// Linux unix_abstract_hash: a ones'-complement sum of the sockaddr
/// (csum_partial + csum_fold), with the type, in the upper half
fn abstract_hash(name: &[u8], stype: i32) -> u32 {
    let mut sum: u32 = 0;
    for c in name.chunks(2) {
        sum += u32::from(u16::from_ne_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let mut h = !sum & 0xffff;
    h ^= h >> 8;
    h ^= stype as u32;
    UNIX_HASH_MOD + 1 + (h & UNIX_HASH_MOD)
}

impl UnixTable {
    fn bucket(&self, hash: u32) -> &Bucket<UnixNode> {
        &self.buckets[hash as usize]
    }

    /// Linux unix_insert_unbound_socket (from unix_create1)
    fn insert_unbound(&self, s: &Arc<UnixSock>) {
        let h = unbound_hash(s);
        s.hash.store(h, Ordering::Relaxed);
        self.bucket(h).lock().push_front(s);
    }

    /// Linux unix_remove_socket (release, or the drop of a socket never
    /// released): off its bucket if still on it
    fn remove(&self, s: &UnixSock) {
        let mut b = self.bucket(s.hash.load(Ordering::Relaxed)).lock();
        if s.node.is_linked() {
            // SAFETY: a linked `node` is on the bucket `hash` names,
            // which changes only under that bucket's lock (and the new
            // one's), held here
            drop(unsafe { b.remove(s) });
        }
    }

    /// Linux unix_table_double_lock: both buckets in index order
    fn lock2(
        &self,
        h1: u32,
        h2: u32,
    ) -> (
        MutexGuard<'_, WeakList<UnixNode>>,
        Option<MutexGuard<'_, WeakList<UnixNode>>>,
    ) {
        if h1 == h2 {
            return (self.bucket(h1).lock(), None);
        }
        let (lo, hi) = (h1.min(h2), h1.max(h2));
        let a = self.bucket(lo).lock();
        let b = self.bucket(hi).lock();
        (a, Some(b))
    }

    /// Linux __unix_find_socket_byname: a live socket in bucket `b`
    /// whose address is `name`
    fn find_in(b: &WeakList<UnixNode>, name: &[u8]) -> Option<Arc<UnixSock>> {
        b.iter()
            .find(|e| e.get().addr.read().as_ref().is_some_and(|a| a.name == name) && e.is_live())
            .and_then(|e| e.upgrade())
    }

    /// Linux __unix_set_addr_hash under unix_table_double_lock: publish
    /// `addr` and move `s` to bucket `new`, unless `check` and a live
    /// socket there has the name (EADDRINUSE). The address was made
    /// before (Linux unix_create_addr); the caller holds `bindlock`.
    fn set_addr(
        &self,
        s: &Arc<UnixSock>,
        addr: Arc<UnixAddr>,
        new: u32,
        check: bool,
    ) -> Result<(), (KernelError, Arc<UnixAddr>)> {
        let old = s.hash.load(Ordering::Relaxed);
        let (mut a, mut b) = self.lock2(old, new);
        let (go, gn) = match &mut b {
            None => (None, &mut a),
            Some(b) if old < new => (Some(&mut a), b),
            Some(b) => (Some(b), &mut a),
        };
        if check && let Some(found) = Self::find_in(gn, &addr.name) {
            drop((a, b));
            drop(found);
            return Err((KernelError::AddressInUse, addr));
        }
        let gold = go.unwrap_or(&mut *gn);
        if s.node.is_linked() {
            // SAFETY: linked on bucket `old` (see `remove`), locked here
            drop(unsafe { gold.remove(s) });
        }
        *s.addr.write() = Some(addr);
        s.hash.store(new, Ordering::Relaxed);
        gn.push_front(s);
        Ok(())
    }

    /// Linux unix_find_socket_byname for an abstract name
    fn find(&self, stype: i32, name: &[u8]) -> Option<Arc<UnixSock>> {
        let b = self.bucket(abstract_hash(name, stype)).lock();
        let s = Self::find_in(&b, name);
        drop(b);
        s
    }

    /// /proc/net/unix lines of every socket, bucket by bucket under
    /// each bucket's lock (Linux unix_seq_start/next/show), into `m`
    /// (allocating nothing)
    fn show(&self, m: &mut SeqBuf) {
        for b in self.buckets.iter() {
            let b = b.lock();
            for e in b.iter().filter(|e| e.is_live()) {
                proc_line(m, e.get(), e.strong_count());
            }
        }
    }
}

/// Linux unix_insert_bsd_socket
fn insert_bsd(s: &Arc<UnixSock>, ino: u64) {
    BSD[bsd_hash(ino) as usize].lock().push_front(s);
}

/// Linux unix_find_socket_byinode: the live socket bound to `inode`
fn find_bsd(inode: &crate::fs::Inode) -> Option<Arc<UnixSock>> {
    let b = BSD[bsd_hash(inode.ino) as usize].lock();
    let s = b
        .iter()
        .find(|e| {
            e.is_live()
                && e.get().addr.read().as_ref().is_some_and(|a| {
                    a.path
                        .as_ref()
                        .and_then(|d| d.get_inode())
                        .is_some_and(|i| core::ptr::eq(Arc::as_ptr(&i), inode))
                })
        })
        .and_then(|e| e.upgrade());
    drop(b);
    s
}

impl UnixSock {
    /// A new socket in `net` (Linux unix_create1)
    fn new(net: Arc<NetNamespace>, stype: i32) -> Result<Arc<Self>, KernelError> {
        let qlen = net.sysctl.unix_max_dgram_qlen.load(Ordering::Relaxed) as u32;
        let s = try_arc_cyclic(|me| Self {
            peer_wake: WaitEntry::with_func(Some(dgram::peer_wake_relay), me.as_ptr() as usize),
            sk: Sock::new(net, AF_UNIX, stype, 0),
            me: me.clone(),
            st: Mutex::new(None),
            state: AtomicU8::new(CLOSE),
            rq: SkbOwnedQueue::new(),
            inq_len: AtomicUsize::new(0),
            addr: RwLock::new(None),
            iolock: SMutex::new(()),
            bindlock: SMutex::new(()),
            peer_wait: WaitQueue::new(),
            relay: Mutex::new(()),
            peer_wake_to: AtomicUsize::new(0),
            wmem: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
            backlog: AtomicU32::new(qlen),
            peercred: Mutex::new(None),
            node: Link::new(),
            bind_node: Link::new(),
            hash: AtomicU32::new(0),
        })?;
        s.sk.net.unix.insert_unbound(&s);
        Ok(s)
    }

    fn arc(&self) -> Arc<Self> {
        self.me.upgrade().expect("unix socket in use")
    }

    /// Identity (lock order, tables)
    fn id(&self) -> usize {
        core::ptr::from_ref::<Self>(self) as usize
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
        self.rq.len() as u64 > u64::from(self.backlog.load(Ordering::Acquire))
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
            self.sk.send_nospace(*timeo);
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
        let ino = d.get_inode().map(|i| i.ino);
        let addr = match try_arc(UnixAddr {
            name,
            path: Some(d),
        }) {
            Ok(a) => a,
            Err(e) => {
                crate::fs::dir::unlink_sock(&path);
                return Err(e);
            }
        };
        let b = self.bindlock.lock();
        let Some(ino) = ino.filter(|_| self.addr().is_none()) else {
            // Unlinked after bindlock is dropped (Linux out_unlink: the
            // parent's i_rwsem is never taken under bindlock)
            drop(b);
            crate::fs::dir::unlink_sock(&path);
            return Err(KernelError::InvalidArgument);
        };
        let me = self.arc();
        let _ = self.sk.net.unix.set_addr(&me, addr, bsd_hash(ino), false);
        insert_bsd(&me, ino);
        Ok(())
    }

    /// Linux unix_bind_abstract: the address made first, EINVAL if
    /// bound, EADDRINUSE if the name is taken
    fn bind_abstract(&self, name: Vec<u8>) -> Result<(), KernelError> {
        let hash = abstract_hash(&name, self.sk.stype);
        let addr = try_arc(UnixAddr { name, path: None })?;
        let _b = self.bindlock.lock();
        if self.addr().is_some() {
            return Err(KernelError::InvalidArgument);
        }
        self.sk
            .net
            .unix
            .set_addr(&self.arc(), addr, hash, true)
            .map_err(|(e, _)| e)
    }

    /// Linux unix_autobind: "\0" + 5 hex digits from a random start;
    /// ENOSPC when all 2^20 are taken. The address is made once, before
    /// any lock, and its name rewritten for each try.
    pub fn autobind(&self) -> Result<(), KernelError> {
        let _b = self.bindlock.lock();
        if self.addr().is_some() {
            return Ok(());
        }
        let me = self.arc();
        let mut name = crate::util::kmem::try_vec(SUN_PATH + 6, 0u8)?;
        name[..SUN_PATH].copy_from_slice(&AF_UNIX.to_ne_bytes());
        let mut addr = try_arc(UnixAddr { name, path: None })?;
        let mut n = crate::random::get_random_u32() & 0xFFFFF;
        let last = n;
        loop {
            n = (n + 1) & 0xFFFFF;
            // Ours alone until published
            let a = Arc::get_mut(&mut addr).ok_or(KernelError::Busy)?;
            hex5(&mut a.name[SUN_PATH + 1..], n);
            let hash = abstract_hash(&a.name, self.sk.stype);
            match self.sk.net.unix.set_addr(&me, addr, hash, true) {
                Ok(()) => return Ok(()),
                Err((_, a)) if n != last => addr = a,
                Err(_) => return Err(KernelError::NoSpace),
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
                let unread = !self.rq.is_empty();
                {
                    let _g = p.st.lock();
                    p.sk.or_shutdown(SHUTDOWN_MASK);
                    if unread || embryo {
                        p.sk.store_err(KernelError::ConnectionReset as u32);
                    }
                }
                p.sk.state_change();
                p.sk.wake_async(WakeHow::WaitData, POLL_HUP);
            }
            dgram::peer_wake_disconnect(self, &p);
        }
        let q = self.purge();
        if state == LISTEN {
            for skb in q.iter() {
                if let Some(e) = &ucb(skb).embryo {
                    e.release_sock(true);
                }
            }
        }
        drop(q);
        self.relay_wake();
    }

    /// Take the whole receive queue off; the caller frees it unlocked
    pub(super) fn purge(&self) -> OwnedList<SkbOwned> {
        let mut g = self.rq.lock();
        self.inq_len.store(0, Ordering::Release);
        core::mem::take(&mut *g)
    }

    /// Linux unix_remove_bsd_socket
    fn unhash_bsd(&self) {
        if !self.bind_node.is_linked() {
            return;
        }
        let mut b = BSD[self.hash.load(Ordering::Relaxed) as usize].lock();
        if self.bind_node.is_linked() {
            // SAFETY: a linked `bind_node` is on the `BSD` bucket of its
            // inode number, which is our `hash` (set before the insert,
            // never changed after: a bound socket does not rebind)
            drop(unsafe { b.remove(self) });
        }
    }

    // --- wakeups -----------------------------------------------------------

    /// Room was made in our queue: wake blocked writers and, through
    /// their `peer_wake` entries, pollers of senders waiting for room
    /// (Linux wake_up_interruptible_sync_poll on peer_wait, relayed by
    /// unix_dgram_peer_wake_relay)
    fn relay_wake(&self) {
        self.peer_wait
            .wake_poll(u32::from(POLLOUT | POLLWRNORM | POLLWRBAND));
    }

    /// Our `peer_wake`, pinned
    fn peer_wake(&self) -> Pin<&WaitEntry> {
        // SAFETY: never moved out of its Arc (type invariant)
        unsafe { Pin::new_unchecked(&self.peer_wake) }
    }

    // --- options -----------------------------------------------------------

    /// SO_PEERCRED: struct ucred of the peer captured at connect,
    /// listen or socketpair
    fn peercred_opt(&self) -> OptOut {
        let c = self.peercred.lock().clone();
        // The pid in the reader's namespace, 0 if not visible (Linux
        // cred_to_ucred: pid_vnr)
        OptOut::Bytes(crate::net::socket::peercred_bytes(c.map(|c| {
            let pid = c.pid.as_ref().map_or(0, |p| p.vnr()) as i32;
            (pid, c.uid, c.gid)
        })))
    }

    /// Linux unix_inq_len: EINVAL on a listener; a stream's unread
    /// bytes, a seqpacket's queued bytes, a datagram socket's first
    /// message
    fn inq_len(&self) -> Result<usize, KernelError> {
        if self.state() == LISTEN {
            return Err(KernelError::InvalidArgument);
        }
        Ok(match self.sk.stype {
            SOCK_STREAM | SOCK_SEQPACKET => self.inq_len.load(Ordering::Acquire),
            _ => self.rq.lock().first().map_or(0, SkBuff::len),
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
fn bsd_name(a: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KernelError> {
    let p = &a[SUN_PATH..];
    let n = p.iter().position(|&c| c == 0).unwrap_or(p.len());
    let path = p[..n].to_vec();
    let mut name = a[..SUN_PATH + n].to_vec();
    name.push(0);
    Ok((path, name))
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
    let d = crate::fs::namei::lookup_path(&path)?;
    let inode = d.get_inode().ok_or(KernelError::NotFound)?;
    crate::fs::dac::permission_as(&crate::task::current_cred(), &inode, crate::fs::MAY_WRITE)?;
    if !inode.mode().is_socket() {
        return Err(KernelError::ConnectionRefused);
    }
    let s = find_bsd(&inode).ok_or(KernelError::ConnectionRefused)?;
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
    Ok(UnixSock::new(crate::net::current_net_ns(), stype)?)
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
        crate::uaccess::put_user::<i32>(arg, v as i32).map_err(|_| KernelError::BadAddress)?;
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
            if pm == SHUTDOWN_MASK {
                p.sk.wake_async(WakeHow::WaitData, POLL_HUP);
            } else if pm & RCV_SHUTDOWN != 0 {
                p.sk.wake_async(WakeHow::WaitData, POLL_IN);
            }
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

    fn sendmsg(&self, m: &mut SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
        match self.sk.stype {
            SOCK_STREAM => stream::sendmsg(self, m, flags),
            SOCK_SEQPACKET => dgram::seqpacket_sendmsg(self, m, flags),
            _ => dgram::sendmsg(self, m, flags),
        }
    }

    fn recvmsg(&self, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
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
        *a.peercred.lock() = Some(cred.clone());
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
/// CAP_SYSLOG under kptr_restrict); `refs` is its reference count.
/// Written under its bucket's lock: a whole line or, on overflow,
/// nothing (the file is generated again into a larger buffer).
fn proc_line(m: &mut SeqBuf, s: &UnixSock, refs: usize) {
    let est = s.state() == ESTABLISHED;
    let st = match (s.has_file(), est) {
        (true, true) => SS_CONNECTED,
        (true, false) => SS_UNCONNECTED,
        (false, true) => SS_CONNECTING,
        (false, false) => SS_DISCONNECTING,
    };
    let flags = if s.state() == LISTEN { SO_ACCEPTCON } else { 0 };
    let _ = write!(
        m,
        "{:016x}: {:08X} {:08X} {:08X} {:04X} {:02X} {:5}",
        0,
        refs,
        0,
        flags,
        s.sk.stype,
        st,
        s.sk.ino.load(Ordering::Acquire)
    );
    if let Some(a) = s.addr.read().as_ref() {
        let _ = m.write_char(' ');
        let p = &a.name[SUN_PATH..];
        let p = if a.is_abstract() {
            let _ = m.write_char('@');
            &p[1..]
        } else {
            &p[..p.len() - 1]
        };
        for &c in p {
            let _ = m.write_char(if c == 0 { '@' } else { c as char });
        }
    }
    let _ = m.write_char('\n');
}

/// `/proc/net/unix` of the reader's namespace
pub fn proc_net_unix() -> Vec<u8> {
    let net = crate::net::current_net_ns();
    crate::fs::proc::seq::generate(|m| {
        let _ = m.write_str("Num       RefCount Protocol Flags    Type St Inode Path\n");
        net.unix.show(m);
    })
}

/// `n` as five lower-case hex digits (Linux "%05x"), into `out`
fn hex5(out: &mut [u8], n: u32) {
    for (i, b) in out.iter_mut().take(5).enumerate() {
        let d = (n >> (4 * (4 - i))) & 0xf;
        *b = b"0123456789abcdef"[d as usize];
    }
}

/// Queue `skb` on `to` (caller holds `to.st`, so `to` is alive) and
/// charge its files as in flight
fn queue(to: &UnixSock, skb: Arc<SkBuff>) {
    if let Some(f) = ucb(&skb).fp.lock().as_mut() {
        f.queued();
    }
    let len = unix_len(&skb);
    let mut q = to.rq.lock();
    q.push_back(skb);
    to.inq_len.fetch_add(len, Ordering::AcqRel);
}

/// Shutdown bits test helper
fn rcv_shut(s: &UnixSock) -> bool {
    s.sk.shutdown() & RCV_SHUTDOWN != 0
}

/// Common receive tail: credentials and files into control messages
fn scm_recv(s: &UnixSock, m: &mut RecvMsg<'_>, creds: Option<Creds>, fds: Option<FpList>) {
    scm::put(m, s.passcred(), creds, fds);
}
