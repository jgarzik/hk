//! AF_NETLINK sockets (Linux net/netlink/af_netlink.c)
//!
//! Only NETLINK_ROUTE is implemented (`rtnetlink.rs`); other protocols are
//! EPROTONOSUPPORT. A socket is identified by its port id (`nl_pid`):
//! bound explicitly, or autobound on first use to the process's tgid, then
//! to unique negative values. Multicast groups are a bitmap; kernel
//! notifications go to every subscribed socket of the namespace.
//!
//! Requests sent to the kernel (nl_pid 0) are processed synchronously in
//! the sender's `sendmsg` (Linux netlink_unicast_kernel); replies, ACKs and
//! whole dumps (precomputed into <= 8 KB NLM_F_MULTI datagrams + DONE) are
//! queued on the sender's receive queue. Multicast delivery respects the
//! receive buffer: a full queue drops the message and reports ENOBUFS on
//! the next recvmsg (unless NETLINK_NO_ENOBUFS).
//!
//! ## Locking
//!
//! - `NlTable.socks` (per netns): `spin::RwLock`, thread context only,
//!   leaf; lookups return `Arc` clones (no guard escapes).
//! - `NlSock.rxq`: `spin::Mutex`, thread context only, leaf. Senders
//!   (notifications under RTNL, requests, peers) push and wake `wq` after
//!   dropping it.
//! - Order: RTNL -> FIB/addresses -> `NlTable.socks` -> `NlSock.rxq`.

pub mod attr;
pub mod rtnetlink;
pub mod sys;

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
    /// Pending socket error (positive errno; ENOBUFS on overrun)
    err: AtomicI32,
    pub wq: WaitQueue,
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
            err: AtomicI32::new(0),
            wq: WaitQueue::new(),
        })
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

    /// Queue `skb` unconditionally (replies to this socket's requests)
    pub fn queue(&self, skb: NlSkb) {
        self.rmem.fetch_add(skb.data.len(), Ordering::AcqRel);
        self.rxq.lock().push_back(skb);
        self.wq.wake_all();
    }

    /// Queue if the receive buffer has room, else record ENOBUFS
    /// (Linux netlink_overrun); returns false when dropped
    pub fn queue_bounded(&self, skb: NlSkb) -> bool {
        if self.rmem.load(Ordering::Acquire) > self.rcvbuf.load(Ordering::Acquire) as usize {
            if !self.has_flag(sflags::NO_ENOBUFS) {
                self.err
                    .store(KernelError::NoBufferSpace.errno(), Ordering::Release);
                self.wq.wake_all();
            }
            return false;
        }
        self.queue(skb);
        true
    }

    /// Something to read (or an error to report)
    pub fn readable(&self) -> bool {
        !self.rxq.lock().is_empty() || self.err.load(Ordering::Acquire) != 0
    }

    pub fn has_error(&self) -> bool {
        self.err.load(Ordering::Acquire) != 0
    }

    /// Take the pending error (SO_ERROR / recvmsg)
    pub fn take_error(&self) -> i32 {
        self.err.swap(0, Ordering::AcqRel)
    }

    /// Next datagram: removed unless `peek`; EAGAIN if `nonblock` and
    /// empty; a pending overrun is reported first as ENOBUFS
    pub fn recv(&self, peek: bool, nonblock: bool) -> Result<NlSkb, KernelError> {
        loop {
            let e = self.take_error();
            if e != 0 {
                return Err(KernelError::NoBufferSpace);
            }
            {
                let mut q = self.rxq.lock();
                if let Some(front) = q.front() {
                    if peek {
                        return Ok(front.clone());
                    }
                    let skb = q.pop_front().unwrap();
                    self.rmem.fetch_sub(skb.data.len(), Ordering::AcqRel);
                    return Ok(skb);
                }
            }
            if nonblock {
                return Err(KernelError::WouldBlock);
            }
            self.wq.wait_event_interruptible(|| self.readable())?;
        }
    }

    /// Send `data` to (`portid`, `group`) from this socket (Linux
    /// netlink_sendmsg after address checks): portid 0 = the kernel
    pub fn send(
        self: &Arc<Self>,
        data: &[u8],
        portid: u32,
        group: u32,
    ) -> Result<usize, KernelError> {
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
                rtnetlink::rcv(self, data);
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
        if !peer.queue_bounded(skb) {
            return Err(KernelError::WouldBlock);
        }
        Ok(data.len())
    }

    /// Close: leave the namespace table
    pub fn release(&self) {
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
            s.queue_bounded(skb.clone());
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
