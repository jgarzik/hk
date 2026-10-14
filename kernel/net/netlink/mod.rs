//! AF_NETLINK sockets (Linux net/netlink/af_netlink.c)
//!
//! Only NETLINK_ROUTE is implemented (`rtnetlink.rs`); other protocols are
//! EPROTONOSUPPORT. A socket is identified by its port id (`nl_pid`):
//! bound explicitly, or autobound on first use to the process's tgid, then
//! to unique negative values. Multicast groups are a bitmap; kernel
//! notifications go to every subscribed socket of the namespace.
//!
//! Requests sent to the kernel (nl_pid 0) are processed synchronously in
//! the sender's `sendmsg` (Linux netlink_unicast_kernel); replies and
//! ACKs are queued on the sender's receive queue.
//!
//! Every queued message is charged to the receiver's rcvbuf (`truesize`
//! = payload + overhead), so per-socket memory is bounded by rcvbuf plus
//! one message. Kernel messages (replies, ACKs, notifications) that do
//! not fit are dropped and reported once as ENOBUFS (Linux
//! netlink_overrun; not with NETLINK_NO_ENOBUFS); user-to-user unicast
//! waits for room or fails with EAGAIN. Dumps are resumable (Linux
//! netlink_dump): a `DumpCb` cursor produces <= 8 KB NLM_F_MULTI parts,
//! the first at request time, later ones as recvmsg drains the queue to
//! half of rcvbuf; NLMSG_DONE ends it. A second dump while one runs is
//! EBUSY.
//!
//! ## Locking
//!
//! - `NlTable.socks` (per netns): `spin::RwLock`, thread context only,
//!   leaf; lookups return `Arc` clones (no guard escapes).
//! - `NlSock.dump`: `spin::Mutex`, thread context only; held while the
//!   cursor reads table snapshots and while its part is queued.
//! - `NlSock.rxq`: `spin::Mutex`, thread context only, leaf. Senders
//!   (notifications under RTNL, requests, peers, dump steps) push and
//!   wake `wq` after dropping it.
//! - Order: RTNL -> FIB/addresses -> `NlTable.socks` -> `NlSock.rxq`;
//!   `NlSock.dump` -> devices/FIB/ARP snapshots -> `NlSock.rxq`. RTNL is
//!   never taken under `NlSock.dump`.

pub mod attr;
pub mod rtnetlink;
pub mod sys;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use spin::{Mutex, RwLock};

use crate::error::KernelError;
use crate::net::NetNamespace;
use crate::waitqueue::WaitQueue;

pub const AF_NETLINK: i32 = 16;
pub const NETLINK_ROUTE: i32 = 0;
pub const SOL_NETLINK: i32 = 270;

/// Socket options (level SOL_NETLINK)
pub const NETLINK_ADD_MEMBERSHIP: i32 = 1;
pub const NETLINK_DROP_MEMBERSHIP: i32 = 2;
pub const NETLINK_PKTINFO: i32 = 3;
pub const NETLINK_BROADCAST_ERROR: i32 = 4;
pub const NETLINK_NO_ENOBUFS: i32 = 5;
pub const NETLINK_LISTEN_ALL_NSID: i32 = 8;
pub const NETLINK_LIST_MEMBERSHIPS: i32 = 9;
pub const NETLINK_CAP_ACK: i32 = 10;
pub const NETLINK_EXT_ACK: i32 = 11;
pub const NETLINK_GET_STRICT_CHK: i32 = 12;

/// Control message types
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_MIN_TYPE: u16 = 0x10;

/// Header flags
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ECHO: u16 = 0x08;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
/// NLMSG_ERROR flags
pub const NLM_F_CAPPED: u16 = 0x100;
pub const NLM_F_ACK_TLVS: u16 = 0x200;
/// Extended ACK attribute: error message string
pub const NLMSGERR_ATTR_MSG: u16 = 1;

/// sizeof(struct sockaddr_nl)
pub const SOCKADDR_NL_LEN: usize = 12;
/// Linux rmem_default / wmem_default
const SK_BUF_DEFAULT: u32 = 212_992;
/// Linux SOCK_MIN_RCVBUF-ish floor for SO_RCVBUF
const SK_BUF_MIN: u32 = 2304;
/// Multicast groups of NETLINK_ROUTE (RTNLGRP_MAX)
pub const RTNL_NGROUPS: u32 = 39;

/// Notification origin: the request's portid and sequence (0 = kernel)
#[derive(Clone, Copy, Default, Debug)]
pub struct NlInfo {
    pub portid: u32,
    pub seq: u32,
}

/// Destination of a send: (portid, group), and whether the sender named
/// it (msg_name) rather than using the connected default
#[derive(Clone, Copy, Debug, Default)]
pub struct NlDst {
    pub portid: u32,
    pub group: u32,
    pub explicit: bool,
}

/// A queued datagram
#[derive(Clone)]
pub struct NlSkb {
    pub data: Vec<u8>,
    /// Sender port id (0 = kernel)
    pub portid: u32,
    /// Destination group (0 = unicast)
    pub group: u32,
}

/// Option bits in `NlSock.flags`
pub mod sflags {
    pub const PKTINFO: u32 = 1 << 0;
    pub const NO_ENOBUFS: u32 = 1 << 1;
    pub const CAP_ACK: u32 = 1 << 2;
    pub const EXT_ACK: u32 = 1 << 3;
    pub const STRICT_CHK: u32 = 1 << 4;
    pub const BCAST_ERR: u32 = 1 << 5;
    pub const LISTEN_ALL: u32 = 1 << 6;
}

/// A netlink socket (Linux struct netlink_sock)
pub struct NlSock {
    pub protocol: i32,
    /// SOCK_RAW or SOCK_DGRAM (same behavior)
    pub stype: i32,
    pub net: Arc<NetNamespace>,
    portid: AtomicU32,
    bound: AtomicBool,
    /// Subscribed groups: bit g-1 for group g
    groups: AtomicU64,
    /// Connected destination (portid, group)
    dst: Mutex<(u32, u32)>,
    rxq: Mutex<VecDeque<NlSkb>>,
    rmem: AtomicUsize,
    /// SO_RCVBUF / SO_SNDBUF (already doubled, as reported)
    pub rcvbuf: AtomicU32,
    pub sndbuf: AtomicU32,
    pub flags: AtomicU32,
    /// Capabilities of the opener (the socket file's f_cred)
    opener: crate::task::KernelCap,
    /// Pending socket error (positive errno; ENOBUFS on overrun)
    err: AtomicI32,
    /// Receive queue overran; cleared when the reader empties it
    congested: AtomicBool,
    /// Messages dropped on overrun
    drops: AtomicU32,
    /// Running dump (Linux cb_running + netlink_callback)
    dump: Mutex<Option<Dump>>,
    pub wq: WaitQueue,
}

/// Bytes charged to rcvbuf per queued message (Linux skb truesize:
/// payload plus buffer overhead), so tiny messages cannot pin unbounded
/// memory
fn truesize(len: usize) -> usize {
    len + 256
}

/// A dump producer (Linux netlink_callback.dump): appends the next
/// messages to `buf` (at least one if any are left, at most about
/// `rtnetlink::DUMP_SIZE` bytes); `Ok(true)` when finished
pub trait DumpCb: Send {
    fn fill(&mut self, sk: &NlSock, buf: &mut Vec<u8>) -> Result<bool, KernelError>;
}

struct Dump {
    cb: Box<dyn DumpCb>,
    seq: u32,
}

/// Next negative autobind port id (Linux netlink_autobind rover)
static ROVER: AtomicI32 = AtomicI32::new(-4097);

impl NlSock {
    /// New socket in the current task's namespace
    pub fn new(protocol: i32, stype: i32) -> Arc<Self> {
        Arc::new(Self {
            protocol,
            stype,
            net: crate::net::current_net_ns(),
            portid: AtomicU32::new(0),
            bound: AtomicBool::new(false),
            groups: AtomicU64::new(0),
            dst: Mutex::new((0, 0)),
            rxq: Mutex::new(VecDeque::new()),
            rmem: AtomicUsize::new(0),
            rcvbuf: AtomicU32::new(SK_BUF_DEFAULT),
            sndbuf: AtomicU32::new(SK_BUF_DEFAULT),
            flags: AtomicU32::new(0),
            opener: crate::task::current_cred().cap_effective,
            err: AtomicI32::new(0),
            congested: AtomicBool::new(false),
            drops: AtomicU32::new(0),
            dump: Mutex::new(None),
            wq: WaitQueue::new(),
        })
    }

    /// Linux __netlink_ns_capable: the sender holds `cap`, and so does
    /// the opener of the socket unless the message named its destination
    /// explicitly (NETLINK_SKB_DST). A privileged program that merely
    /// write()s to a descriptor it was handed cannot be abused as a
    /// confused deputy.
    pub fn net_capable(&self, cap: u32, explicit_dst: bool) -> bool {
        (explicit_dst || self.opener.has(cap)) && crate::task::capable(cap)
    }

    pub fn portid(&self) -> u32 {
        self.portid.load(Ordering::Acquire)
    }

    /// First 32 groups (sockaddr_nl.nl_groups)
    pub fn groups32(&self) -> u32 {
        self.groups.load(Ordering::Acquire) as u32
    }

    pub fn has_flag(&self, f: u32) -> bool {
        self.flags.load(Ordering::Acquire) & f != 0
    }

    pub fn set_flag(&self, f: u32, on: bool) {
        if on {
            self.flags.fetch_or(f, Ordering::AcqRel);
        } else {
            self.flags.fetch_and(!f, Ordering::AcqRel);
        }
    }

    /// Largest message accepted by sendmsg (Linux: sndbuf - 32)
    pub fn max_msg(&self) -> usize {
        (self.sndbuf.load(Ordering::Acquire) as usize).saturating_sub(32)
    }

    /// Connected destination (portid, group)
    pub fn dst(&self) -> (u32, u32) {
        *self.dst.lock()
    }

    /// Bind to `portid` or autobind (0); EINVAL if already bound to
    /// another port id, EADDRINUSE if taken
    pub fn bind(self: &Arc<Self>, portid: u32, groups: u32) -> Result<(), KernelError> {
        if self.bound.load(Ordering::Acquire) {
            if portid != self.portid() {
                return Err(KernelError::InvalidArgument);
            }
        } else if portid != 0 {
            self.insert(portid)?;
        } else {
            self.autobind()?;
        }
        let mask = (1u64 << RTNL_NGROUPS) - 1;
        let g = groups as u64 & mask;
        let cur = self.groups.load(Ordering::Acquire);
        self.groups
            .store((cur & !0xFFFF_FFFF) | g, Ordering::Release);
        Ok(())
    }

    fn insert(self: &Arc<Self>, portid: u32) -> Result<(), KernelError> {
        self.net.nl.insert(self.protocol, portid, self)?;
        self.portid.store(portid, Ordering::Release);
        self.bound.store(true, Ordering::Release);
        Ok(())
    }

    /// Linux netlink_autobind: tgid first, then unique negative ids
    pub fn autobind(self: &Arc<Self>) -> Result<(), KernelError> {
        if self.bound.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut id = crate::task::percpu::current_pid() as u32;
        loop {
            match self.insert(id) {
                Err(KernelError::AddressInUse) => {
                    id = ROVER.fetch_sub(1, Ordering::Relaxed) as u32;
                }
                r => return r,
            }
        }
    }

    /// Connect (default destination); AF_UNSPEC disconnects
    pub fn connect(self: &Arc<Self>, portid: u32, groups: u32) -> Result<(), KernelError> {
        self.autobind()?;
        *self.dst.lock() = (portid, ffs(groups));
        Ok(())
    }

    pub fn disconnect(&self) {
        *self.dst.lock() = (0, 0);
    }

    /// Join (`on`) or leave a group (NETLINK_ADD/DROP_MEMBERSHIP)
    pub fn membership(self: &Arc<Self>, group: u32, on: bool) -> Result<(), KernelError> {
        if group == 0 || group > RTNL_NGROUPS {
            return Err(KernelError::InvalidArgument);
        }
        self.autobind()?;
        let bit = 1u64 << (group - 1);
        if on {
            self.groups.fetch_or(bit, Ordering::AcqRel);
        } else {
            self.groups.fetch_and(!bit, Ordering::AcqRel);
        }
        Ok(())
    }

    /// All subscribed groups as a u32 array (NETLINK_LIST_MEMBERSHIPS)
    pub fn groups_all(&self) -> u64 {
        self.groups.load(Ordering::Acquire)
    }

    /// Charge `skb` to the receive buffer if it fits (Linux
    /// netlink_attachskb: the first skb always fits, later ones while
    /// rmem stays within rcvbuf and the socket is not congested)
    fn charge(&self, skb: &NlSkb) -> bool {
        let ts = truesize(skb.data.len());
        let before = self.rmem.fetch_add(ts, Ordering::AcqRel);
        let limit = self.rcvbuf.load(Ordering::Acquire) as usize;
        if (before == 0 || before + ts <= limit) && !self.congested.load(Ordering::Acquire) {
            return true;
        }
        self.rmem.fetch_sub(ts, Ordering::AcqRel);
        false
    }

    fn push(&self, skb: NlSkb) {
        self.rxq.lock().push_back(skb);
        self.wq.wake_all();
    }

    /// Queue a kernel message (reply, ACK, notification): dropped with
    /// an ENOBUFS overrun when the receive buffer is full (Linux
    /// netlink_unicast/broadcast from the kernel, MSG_DONTWAIT)
    pub fn queue(&self, skb: NlSkb) -> bool {
        if !self.charge(&skb) {
            self.overrun();
            return false;
        }
        self.push(skb);
        true
    }

    /// Linux netlink_overrun: report ENOBUFS once per congestion episode
    /// (unless NETLINK_NO_ENOBUFS) and count the drop
    fn overrun(&self) {
        if !self.has_flag(sflags::NO_ENOBUFS) && !self.congested.swap(true, Ordering::AcqRel) {
            self.err
                .store(KernelError::NoBufferSpace.errno(), Ordering::Release);
            self.wq.wake_all();
        }
        self.drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Queue a message from a user socket: wait for room unless
    /// `nonblock` (EAGAIN), like netlink_attachskb with a send timeout
    fn deliver(&self, skb: NlSkb, nonblock: bool) -> Result<(), KernelError> {
        loop {
            if self.charge(&skb) {
                self.push(skb);
                return Ok(());
            }
            if nonblock {
                return Err(KernelError::WouldBlock);
            }
            self.wq.wait_event_interruptible(|| self.has_room())?;
        }
    }

    fn has_room(&self) -> bool {
        let r = self.rmem.load(Ordering::Acquire);
        (r == 0 || r < self.rcvbuf.load(Ordering::Acquire) as usize)
            && !self.congested.load(Ordering::Acquire)
    }

    /// Something to read (or an error to report)
    /// (a pending dump part counts: recv produces it)
    pub fn readable(&self) -> bool {
        // Separate statements: never hold rxq while taking dump (order
        // is dump -> rxq)
        let queued = !self.rxq.lock().is_empty();
        let dumping = self.dump.lock().is_some();
        queued || dumping || self.err.load(Ordering::Acquire) != 0
    }

    pub fn has_error(&self) -> bool {
        self.err.load(Ordering::Acquire) != 0
    }

    /// Take the pending error (SO_ERROR / recvmsg)
    pub fn take_error(&self) -> i32 {
        self.err.swap(0, Ordering::AcqRel)
    }

    /// Next datagram: removed unless `peek`; EAGAIN if `nonblock` and
    /// empty; a pending overrun is reported first as ENOBUFS. Reading
    /// makes room, so a running dump continues (Linux netlink_recvmsg).
    pub fn recv(&self, peek: bool, nonblock: bool) -> Result<NlSkb, KernelError> {
        loop {
            let e = self.take_error();
            if e != 0 {
                return Err(KernelError::NoBufferSpace);
            }
            if let Some(skb) = self.dequeue(peek) {
                self.dump_more();
                return Ok(skb);
            }
            // Never wait on an empty queue while a dump is pending: its
            // next part always fits an empty buffer
            if self.dump_step() {
                continue;
            }
            if nonblock {
                return Err(KernelError::WouldBlock);
            }
            self.wq.wait_event_interruptible(|| self.readable())?;
        }
    }

    fn dequeue(&self, peek: bool) -> Option<NlSkb> {
        let mut q = self.rxq.lock();
        if peek {
            return q.front().cloned();
        }
        let skb = q.pop_front()?;
        self.rmem
            .fetch_sub(truesize(skb.data.len()), Ordering::AcqRel);
        let empty = q.is_empty();
        drop(q);
        // Linux netlink_rcv_wake
        if empty {
            self.congested.store(false, Ordering::Release);
        }
        self.wq.wake_all();
        Some(skb)
    }

    /// Start a dump (Linux netlink_dump_start): EBUSY while one runs;
    /// the first part is queued now, the rest as the reader drains
    pub fn dump_start(&self, cb: Box<dyn DumpCb>, seq: u32) -> Result<(), KernelError> {
        {
            let mut d = self.dump.lock();
            if d.is_some() {
                return Err(KernelError::Busy);
            }
            *d = Some(Dump { cb, seq });
        }
        self.dump_step();
        Ok(())
    }

    /// Continue a running dump once at most half the buffer is used
    fn dump_more(&self) {
        let half = self.rcvbuf.load(Ordering::Acquire) as usize / 2;
        if self.rmem.load(Ordering::Acquire) <= half {
            self.dump_step();
        }
    }

    /// Queue the next part of the running dump if it fits; ends with
    /// NLMSG_DONE carrying 0 or the dump's error (Linux netlink_dump)
    ///
    /// Always makes progress when it runs: a part holds at least one
    /// object (even one larger than rcvbuf, admitted into an empty
    /// buffer like Linux's first skb) or ends the dump, and the cursor
    /// only moves forward, so objects removed mid-dump cannot stall it.
    /// Returns whether a part was queued.
    fn dump_step(&self) -> bool {
        let mut d = self.dump.lock();
        let Some(st) = d.as_mut() else {
            return false;
        };
        let r = self.rmem.load(Ordering::Acquire);
        if r != 0 && r >= self.rcvbuf.load(Ordering::Acquire) as usize {
            return false;
        }
        let mut buf = Vec::new();
        let done = match st.cb.fill(self, &mut buf) {
            Ok(false) => None,
            Ok(true) => Some(0),
            Err(e) => Some(-e.errno()),
        };
        if let Some(err) = done {
            let mut m = attr::Msg::new(NLMSG_DONE, NLM_F_MULTI, st.seq, self.portid());
            m.put(&err.to_ne_bytes());
            buf.extend_from_slice(&m.finish());
            *d = None;
        }
        // Admission was checked above (a racing notification may push
        // rmem past rcvbuf, which Linux also allows for one skb). Pushed
        // under the dump lock so parts stay in order.
        self.rmem.fetch_add(truesize(buf.len()), Ordering::AcqRel);
        self.push(NlSkb {
            data: buf,
            portid: 0,
            group: 0,
        });
        true
    }

    /// Send `data` to `dst` from this socket (Linux netlink_sendmsg
    /// after address checks): portid 0 = the kernel
    pub fn send(
        self: &Arc<Self>,
        data: &[u8],
        dst: NlDst,
        nonblock: bool,
    ) -> Result<usize, KernelError> {
        let NlDst {
            portid,
            group,
            explicit,
        } = dst;
        self.autobind()?;
        if data.len() > self.max_msg() {
            return Err(KernelError::MessageTooLong);
        }
        let me = self.portid();
        if group != 0 {
            let skb = NlSkb {
                data: data.to_vec(),
                portid: me,
                group,
            };
            broadcast(&self.net, self.protocol, skb, me);
        }
        if portid == 0 {
            if group == 0 {
                rtnetlink::rcv(self, data, explicit);
            }
            return Ok(data.len());
        }
        let peer = self
            .net
            .nl
            .get(self.protocol, portid)
            .ok_or(KernelError::ConnectionRefused)?;
        let skb = NlSkb {
            data: data.to_vec(),
            portid: me,
            group: 0,
        };
        peer.deliver(skb, nonblock)?;
        Ok(data.len())
    }

    /// Close: leave the namespace table, drop a running dump
    pub fn release(&self) {
        *self.dump.lock() = None;
        if self.bound.load(Ordering::Acquire) {
            self.net.nl.remove(self.protocol, self.portid());
        }
    }
}

/// Lowest set bit as a 1-based group number (0 if none)
fn ffs(groups: u32) -> u32 {
    if groups == 0 {
        0
    } else {
        groups.trailing_zeros() + 1
    }
}

/// Deliver `skb` to every socket of `protocol` in `net` subscribed to
/// `skb.group`, except port `exclude` (Linux netlink_broadcast)
pub fn broadcast(net: &NetNamespace, protocol: i32, skb: NlSkb, exclude: u32) {
    if skb.group == 0 || skb.group > 64 {
        return;
    }
    let bit = 1u64 << (skb.group - 1);
    for s in net.nl.socks(protocol) {
        if s.portid() != exclude && s.groups_all() & bit != 0 {
            s.queue(skb.clone());
        }
    }
}

/// Bound netlink sockets of a namespace by (protocol, portid)
pub struct NlTable {
    socks: RwLock<BTreeMap<(i32, u32), Weak<NlSock>>>,
}

impl Default for NlTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NlTable {
    pub fn new() -> Self {
        Self {
            socks: RwLock::new(BTreeMap::new()),
        }
    }

    fn insert(&self, protocol: i32, portid: u32, s: &Arc<NlSock>) -> Result<(), KernelError> {
        let mut t = self.socks.write();
        if let Some(w) = t.get(&(protocol, portid))
            && w.strong_count() > 0
        {
            return Err(KernelError::AddressInUse);
        }
        t.insert((protocol, portid), Arc::downgrade(s));
        Ok(())
    }

    fn remove(&self, protocol: i32, portid: u32) {
        self.socks.write().remove(&(protocol, portid));
    }

    /// Socket bound to `portid`
    pub fn get(&self, protocol: i32, portid: u32) -> Option<Arc<NlSock>> {
        self.socks.read().get(&(protocol, portid))?.upgrade()
    }

    /// All live sockets of `protocol`
    pub fn socks(&self, protocol: i32) -> Vec<Arc<NlSock>> {
        self.socks
            .read()
            .iter()
            .filter(|((p, _), _)| *p == protocol)
            .filter_map(|(_, w)| w.upgrade())
            .collect()
    }
}
