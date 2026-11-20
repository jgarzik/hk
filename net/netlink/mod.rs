//! AF_NETLINK sockets (Linux net/netlink/af_netlink.c)
//!
//! Protocols are described by `NlProto` (Linux netlink_kernel_cfg):
//! NETLINK_ROUTE (`rtnetlink.rs`) and NETLINK_KOBJECT_UEVENT
//! (`base/uevent.rs`: events to user space, and a privileged sender's
//! rebroadcast in its namespace); others are EPROTONOSUPPORT. A socket is identified by its port id (`nl_pid`):
//! bound explicitly, or autobound on first use to the process's tgid, then
//! to unique negative values. Multicast groups are a bitmap; kernel
//! notifications go to every subscribed socket of the namespace.
//!
//! Requests sent to the kernel (nl_pid 0) are processed synchronously in
//! the sender's `sendmsg` (Linux netlink_unicast_kernel); replies and
//! ACKs are queued on the sender's receive queue.
//!
//! Every queued message is charged to the receiver's rcvbuf (`truesize`
//! = buffer allocated + overhead), so per-socket memory is bounded by rcvbuf plus
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
//! - `NL_TABLE.lock` (spin, one for every namespace; Linux nl_table's
//!   rhashtable locks and netlink_table_grab): binds (the bound check,
//!   the port id search and the insert in one hold), releases, and
//!   additions to a namespace's multicast lists (`NlNet.mc`, Linux
//!   nl_table[].mc_list, whose writers' spin leaf nests inside it).
//!   Unicast lookups walk a port id chain under RCU (Linux
//!   netlink_lookup) and take a reference under the guard; broadcasts
//!   walk a multicast list under RCU, or a snapshot taken before when
//!   the clones may sleep (Linux netlink_lock_table pins the list, and
//!   do_one_broadcast clones with the caller's GFP). A released
//!   socket's references go a grace period later, possibly in
//!   `rcuc/N`.
//! - `NlSock.dump`: sleeping `crate::sync::Mutex` (Linux nlk->cb_mutex),
//!   thread context only (sendmsg, recvmsg, release); held while the
//!   cursor reads table snapshots and while its part is queued.
//!   `NlSock.running` (Linux cb_running) mirrors whether a dump is set,
//!   written under it, read lock-free by poll.
//! - `NlSock.rxq`: an `SkbQueue` (spin), thread context only, leaf.
//!   Senders (notifications under RTNL, requests, peers, dump steps)
//!   build the skb and its `Arc` before it, push, and wake `wq` after
//!   dropping it; MSG_PEEK takes a reference under it.
//! - Order: RTNL -> FIB/addresses -> `NL_TABLE.lock` -> `NlSock.rxq`;
//!   `NlSock.dump` -> devices/FIB/ARP snapshots -> `NlSock.rxq`. RTNL is
//!   never taken under `NlSock.dump`.

pub mod attr;
pub mod ops;
pub mod rtnetlink;

use crate::util::kalloc::try_arc_cyclic;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::mm::page_alloc::Gfp;
use crate::net::skb::{SkBuff, SkbCb, SkbQueue};
use crate::sync::UniqueOwner;
use crate::sync::rcu::RcuPuts;
use crate::sync::spin::Mutex;
use crate::util::kalloc::try_arc_gfp;
use crate::util::rcuhlist::{HNode, RcuHList};

use crate::net::sock::{Sock, wait_on};
use crate::net::socket::{ProtoOps, SOCK_DGRAM, SOCK_RAW};
use crate::net::unix::scm::Creds;
use crate::net::{NetNamespace, NetRef};
use crate::sync::waitqueue::WaitQueue;
use crate::util::error::KernelError;

pub const AF_NETLINK: i32 = 16;
pub const NETLINK_ROUTE: i32 = 0;
pub const NETLINK_KOBJECT_UEVENT: i32 = 15;
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
/// Extended ACK attributes (Linux NLMSGERR_ATTR_*): the error message
/// string, the offset of the invalid attribute in the request
pub const NLMSGERR_ATTR_MSG: u16 = 1;
pub const NLMSGERR_ATTR_OFFS: u16 = 2;

/// sizeof(struct sockaddr_nl)
pub const SOCKADDR_NL_LEN: usize = 12;
/// Multicast groups of NETLINK_ROUTE (RTNLGRP_MAX)
pub const RTNL_NGROUPS: u32 = 39;

/// Notification origin (Linux struct nl_info): the request's portid
/// and sequence (0 = kernel), and whether it asked for the
/// notification back (NLM_F_ECHO, Linux nlmsg_report(info->nlh))
#[derive(Clone, Copy, Default, Debug)]
pub struct NlInfo {
    pub portid: u32,
    pub seq: u32,
    pub report: bool,
}

/// What a request's handler reports beside its errno (Linux struct
/// netlink_ext_ack: _msg, bad_attr), sent back as NLMSGERR_ATTR_MSG
/// and NLMSGERR_ATTR_OFFS when the socket set NETLINK_EXT_ACK. Lives
/// on the stack of the request's processing; handlers set it through a
/// shared reference (Linux NL_SET_ERR_MSG overwrites).
#[derive(Default)]
pub struct ExtAck {
    msg: core::cell::Cell<Option<&'static str>>,
    /// Address of the offending attribute's header (0: none), turned
    /// into an offset against the request when the ACK is built
    bad_attr: core::cell::Cell<usize>,
}

impl ExtAck {
    /// Linux NL_SET_ERR_MSG
    pub fn msg(&self, m: &'static str) {
        self.msg.set(Some(m));
    }

    /// Linux NL_SET_BAD_ATTR: `payload` is the attribute's payload in
    /// the request
    pub fn bad_attr(&self, payload: &[u8]) {
        let hdr = (payload.as_ptr() as usize).wrapping_sub(attr::NLA_HDRLEN);
        self.bad_attr.set(hdr);
    }

    /// Linux NL_SET_ERR_MSG_ATTR
    pub fn attr_msg(&self, payload: &[u8], m: &'static str) {
        self.bad_attr(payload);
        self.msg(m);
    }

    /// The message set, if any
    pub fn get_msg(&self) -> Option<&'static str> {
        self.msg.get()
    }

    /// The offending attribute's offset in request `req`, if one was
    /// set and lies in its payload (Linux nlmsg_check_in_payload)
    pub fn offs(&self, req: &[u8]) -> Option<u32> {
        let a = self.bad_attr.get();
        let off = a.checked_sub(req.as_ptr() as usize)?;
        if a == 0 || off < attr::NLMSG_HDRLEN || off >= req.len() {
            return None;
        }
        u32::try_from(off).ok()
    }
}

/// Destination of a send: (portid, group), and whether the sender named
/// it (msg_name) rather than using the connected default
#[derive(Clone, Copy, Debug, Default)]
pub struct NlDst {
    pub portid: u32,
    pub group: u32,
    pub explicit: bool,
}

/// What a queued netlink message keeps beside its data (Linux
/// NETLINK_CB)
#[derive(Clone, Default)]
pub struct NlCb {
    /// Sender port id (0 = kernel)
    pub portid: u32,
    /// Destination group (0 = unicast)
    pub group: u32,
    /// Sender credentials (Linux NETLINK_CB.creds), for SCM_CREDENTIALS
    pub creds: Creds,
}

/// A message as an skb: `data` taken over, the sender in its cb
pub fn nl_skb(data: Vec<u8>, cb: NlCb) -> SkBuff {
    let mut skb = SkBuff::from_vec(data);
    skb.cb = SkbCb::Nl(cb);
    skb
}

/// A message from the kernel: port 0, credentials pid/uid/gid 0
pub fn kernel_skb(data: Vec<u8>, group: u32) -> SkBuff {
    nl_skb(
        data,
        NlCb {
            group,
            ..Default::default()
        },
    )
}

/// The `NlCb` of a queued message
pub fn nl_cb(skb: &SkBuff) -> NlCb {
    match &skb.cb {
        SkbCb::Nl(cb) => cb.clone(),
        _ => NlCb::default(),
    }
}

/// Kernel receiver of messages sent to port 0 (`explicit`: the sender
/// named the destination)
pub type NlInput = fn(&Arc<NlSock>, &[u8], bool);

/// A netlink protocol (Linux netlink_kernel_cfg)
pub struct NlProto {
    /// Multicast groups 1..=ngroups
    pub ngroups: u32,
    pub input: Option<NlInput>,
}

static ROUTE: NlProto = NlProto {
    ngroups: RTNL_NGROUPS,
    input: Some(rtnetlink::rcv),
};

static UEVENT: NlProto = NlProto {
    ngroups: 1,
    input: Some(crate::base::uevent::uevent_net_rcv),
};

/// The protocol of socket(AF_NETLINK, _, `protocol`)
fn proto(protocol: i32) -> Option<&'static NlProto> {
    match protocol {
        NETLINK_ROUTE => Some(&ROUTE),
        NETLINK_KOBJECT_UEVENT => Some(&UEVENT),
        _ => None,
    }
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
    /// Common state (type SOCK_RAW or SOCK_DGRAM: same behavior)
    pub sk: Sock,
    proto: &'static NlProto,
    portid: AtomicU32,
    bound: AtomicBool,
    /// Subscribed groups: bit g-1 for group g
    groups: AtomicU64,
    /// Connected destination (portid, group)
    dst: Mutex<(u32, u32)>,
    /// Receive queue (Linux sk_receive_queue): each message an skb in
    /// its `Arc`, made before the lock
    rxq: SkbQueue,
    rmem: AtomicUsize,
    pub flags: AtomicU32,
    /// Receive queue overran; cleared when the reader empties it
    congested: AtomicBool,
    /// Messages dropped on overrun
    drops: AtomicU32,
    /// Running dump (Linux netlink_callback, under nlk->cb_mutex)
    dump: crate::sync::Mutex<Option<Dump>>,
    /// A dump is set (Linux cb_running): written under `dump`, read
    /// lock-free by poll, which may run in atomic context
    running: AtomicBool,
    /// Released (Linux SOCK_DEAD): senders waiting for room give up
    /// with ECONNREFUSED
    dead: AtomicBool,
    /// User senders waiting for room in the receive queue (Linux
    /// nlk->wait): not `sk.wq`, so a reader's dequeue wakes no poller
    wait: WaitQueue,
    /// Link on its port id chain (Linux nlk->node)
    node: HNode,
    /// The chain reference's deferred release (Linux SOCK_RCU_FREE)
    rcu: RcuPuts,
    /// On its namespace's multicast list of its protocol (Linux
    /// sk_bind_node) while it subscribes to any group; written under
    /// `NL_TABLE.lock`. It rejoins only a grace period after it left
    /// (`mc_left` leaves so far, `mc_settled` of them a grace period
    /// old; both under `NL_TABLE.lock`): a broadcast walking under RCU
    /// may stand on it, and back at the chain's head it would lead that
    /// walk over sockets it already served
    mc_node: HNode,
    mc_left: AtomicU32,
    mc_settled: AtomicU32,
    me: Weak<NlSock>,
}

/// A dump producer (Linux netlink_callback.dump): appends the next
/// messages to `buf` (at least one if any are left, at most about
/// `rtnetlink::DUMP_SIZE` bytes); `Ok(true)` when finished
pub trait DumpCb: Send {
    fn fill(&mut self, sk: &NlSock, buf: &mut Vec<u8>) -> Result<bool, KernelError>;

    /// The message of the error a dump ended with (Linux cb->extack's
    /// _msg, sent in NLMSG_DONE with NETLINK_EXT_ACK)
    fn ext_msg(&self) -> Option<&'static str> {
        None
    }
}

struct Dump {
    cb: Box<dyn DumpCb>,
    seq: u32,
}

/// Next negative autobind port id (Linux netlink_autobind rover)
static ROVER: AtomicI32 = AtomicI32::new(-4097);

impl NlSock {
    /// New socket in the current task's namespace
    fn new(proto: &'static NlProto, protocol: i32, stype: i32) -> Result<Arc<Self>, KernelError> {
        let net = crate::net::current_net_ns();
        try_arc_cyclic(|me| Self {
            sk: Sock::new(net, AF_NETLINK as u16, stype, protocol),
            proto,
            portid: AtomicU32::new(0),
            bound: AtomicBool::new(false),
            groups: AtomicU64::new(0),
            dst: Mutex::new((0, 0)),
            rxq: SkbQueue::new(),
            rmem: AtomicUsize::new(0),
            flags: AtomicU32::new(0),
            congested: AtomicBool::new(false),
            drops: AtomicU32::new(0),
            dump: crate::sync::Mutex::new(None),
            running: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            wait: WaitQueue::new(),
            node: HNode::new(),
            rcu: RcuPuts::new(),
            mc_node: HNode::new(),
            mc_left: AtomicU32::new(0),
            mc_settled: AtomicU32::new(0),
            me: me.clone(),
        })
    }

    /// Linux __netlink_ns_capable: the sender holds `cap`, and so does
    /// the opener of the socket unless the message named its destination
    /// explicitly (NETLINK_SKB_DST). A privileged program that merely
    /// write()s to a descriptor it was handed cannot be abused as a
    /// confused deputy.
    pub fn net_capable(&self, cap: u32, explicit_dst: bool) -> bool {
        (explicit_dst || self.sk.cred.cap_effective.has(cap)) && crate::task::capable(cap)
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
        (self.sk.sndbuf() as usize).saturating_sub(32)
    }

    pub fn net(&self) -> &NetRef {
        &self.sk.net
    }

    pub fn protocol(&self) -> i32 {
        self.sk.protocol
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
            match self.insert(portid) {
                // A concurrent bind won: same rule as above
                Err(KernelError::Busy) if portid != self.portid() => {
                    return Err(KernelError::InvalidArgument);
                }
                Err(KernelError::Busy) => {}
                r => r?,
            }
        } else {
            self.autobind()?;
        }
        let mask = (1u64 << self.proto.ngroups) - 1;
        let g = u64::from(groups) & mask;
        // One update of the first 32 groups: a concurrent
        // ADD/DROP_MEMBERSHIP of a higher group is not lost (Linux does
        // both under netlink_table_grab)
        let _ = self
            .groups
            .try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                Some((cur & !0xFFFF_FFFF) | g)
            });
        self.mc_update();
        Ok(())
    }

    /// Hash under `portid` (Linux netlink_insert: the bound check and
    /// the publication happen under the table lock, so two binds of one
    /// socket cannot both insert). EBUSY if it got bound meanwhile.
    fn insert(self: &Arc<Self>, portid: u32) -> Result<(), KernelError> {
        let mut o = NL_TABLE.lock.lock();
        if self.bound.load(Ordering::Acquire) {
            return Err(KernelError::Busy);
        }
        let (net, proto) = (&*self.sk.net, self.sk.protocol);
        let chain = slot(net, proto, portid);
        if chain.iter_locked(&o).any(|x| x.is(net, proto, portid)) {
            return Err(KernelError::AddressInUse);
        }
        self.portid.store(portid, Ordering::Release);
        chain.add_head(self.clone(), &mut o);
        self.bound.store(true, Ordering::Release);
        Ok(())
    }

    /// Bound to `portid` of `proto` in `net`
    fn is(&self, net: &NetNamespace, proto: i32, portid: u32) -> bool {
        self.sk.net.id == net.id && self.sk.protocol == proto && self.portid() == portid
    }

    /// Its subscriptions changed: on its multicast list while it has
    /// any, off it with none (Linux netlink_update_subscriptions:
    /// sk_add_bind_node, __sk_del_bind_node); the list's reference goes
    /// a grace period after it leaves. Rejoining after a leave first
    /// waits out a grace period, with no lock held (thread context:
    /// bind, NETLINK_ADD_MEMBERSHIP), where Linux's broadcast walk
    /// excludes list changes (netlink_lock_table)
    fn mc_update(self: &Arc<Self>) {
        loop {
            let mut o = NL_TABLE.lock.lock();
            let list = self.sk.net.nl.mc(self.sk.protocol);
            let want = self.groups_all() != 0 && !self.dead.load(Ordering::Acquire);
            if want && !self.mc_node.is_hashed() {
                let left = self.mc_left.load(Ordering::Relaxed);
                if self.mc_settled.load(Ordering::Relaxed) != left {
                    drop(o);
                    crate::sync::rcu::synchronize();
                    // The leaves up to `left` are a grace period old; a
                    // later one is not, and is looked at again
                    let _o = NL_TABLE.lock.lock();
                    self.mc_settled.store(left, Ordering::Relaxed);
                    continue;
                }
                list.add_head(self.clone(), &mut o);
            } else if !want && let Some(u) = list.del_init(self, &mut o) {
                let n = self.mc_left.load(Ordering::Relaxed).wrapping_add(1);
                self.mc_left.store(n, Ordering::Relaxed);
                u.defer_put();
            }
            return;
        }
    }

    /// Linux netlink_autobind: the caller's tgid as its pid namespace
    /// numbers it (task_tgid_vnr) first, then unique negative ids
    pub fn autobind(self: &Arc<Self>) -> Result<(), KernelError> {
        if self.bound.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut id = crate::task::pid::vnr(crate::task::percpu::current_pid());
        loop {
            match self.insert(id) {
                Err(KernelError::AddressInUse) => {
                    id = ROVER.fetch_sub(1, Ordering::Relaxed) as u32;
                }
                // Bound by a concurrent bind/autobind
                Err(KernelError::Busy) => return Ok(()),
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
        if group == 0 || group > self.proto.ngroups {
            return Err(KernelError::InvalidArgument);
        }
        self.autobind()?;
        let bit = 1u64 << (group - 1);
        if on {
            self.groups.fetch_or(bit, Ordering::AcqRel);
        } else {
            self.groups.fetch_and(!bit, Ordering::AcqRel);
        }
        self.mc_update();
        Ok(())
    }

    /// All subscribed groups as a u32 array (NETLINK_LIST_MEMBERSHIPS)
    pub fn groups_all(&self) -> u64 {
        self.groups.load(Ordering::Acquire)
    }

    /// Charge `ts` bytes (an skb's truesize, Linux skb truesize: the
    /// buffer as allocated, so tiny messages in large buffers cannot pin
    /// unbounded memory) to the receive buffer if they fit (Linux
    /// netlink_attachskb: the first skb always fits, later ones while
    /// rmem stays within rcvbuf and the socket is not congested)
    fn charge(&self, ts: usize) -> bool {
        let before = self.rmem.fetch_add(ts, Ordering::AcqRel);
        let limit = self.sk.rcvbuf() as usize;
        if (before == 0 || before + ts <= limit) && !self.congested.load(Ordering::Acquire) {
            return true;
        }
        self.rmem.fetch_sub(ts, Ordering::AcqRel);
        false
    }

    fn push(&self, skb: Arc<SkBuff>) {
        self.enqueue(skb);
        self.sk.data_ready();
    }

    /// Queue without waking (the caller wakes after its locks)
    fn enqueue(&self, skb: Arc<SkBuff>) {
        self.rxq.lock().push_back(skb);
    }

    /// Queue a kernel message (reply, ACK, notification): dropped with
    /// an ENOBUFS overrun when the receive buffer is full (Linux
    /// netlink_unicast/broadcast from the kernel, MSG_DONTWAIT). Its
    /// `Arc` is allocated GFP_ATOMIC before the queue lock (Linux has
    /// the skb already); failing that it is dropped like an overrun.
    pub fn queue(&self, skb: SkBuff) -> bool {
        if !self.charge(skb.truesize()) {
            self.overrun();
            return false;
        }
        let ts = skb.truesize();
        let Ok(skb) = try_arc_gfp(skb, Gfp::ATOMIC) else {
            self.rmem.fetch_sub(ts, Ordering::AcqRel);
            self.overrun();
            return false;
        };
        self.push(skb);
        true
    }

    /// Linux netlink_overrun: report ENOBUFS once per congestion episode
    /// (unless NETLINK_NO_ENOBUFS) and count the drop
    fn overrun(&self) {
        if !self.has_flag(sflags::NO_ENOBUFS) && !self.congested.swap(true, Ordering::AcqRel) {
            self.sk.set_err(KernelError::NoBufferSpace);
        }
        self.drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Queue a message from a user socket: wait for room unless
    /// `nonblock` (EAGAIN), like netlink_attachskb with a send timeout;
    /// ECONNREFUSED once the receiver is released (Linux SOCK_DEAD,
    /// which netlink_release wakes us for)
    fn deliver(&self, skb: Arc<SkBuff>, timeo: u64) -> Result<(), KernelError> {
        let mut timeo = timeo;
        let ts = skb.truesize();
        loop {
            if self.dead.load(Ordering::Acquire) {
                return Err(KernelError::ConnectionRefused);
            }
            if self.charge(ts) {
                self.push(skb);
                return Ok(());
            }
            timeo = wait_on(&self.wait, timeo, || {
                self.has_room(ts) || self.dead.load(Ordering::Acquire)
            })?;
        }
    }

    /// `charge` would admit `ts` bytes now (the wait condition must be
    /// the admission rule, or a sender spins between them)
    fn has_room(&self, ts: usize) -> bool {
        let r = self.rmem.load(Ordering::Acquire);
        (r == 0 || r + ts <= self.sk.rcvbuf() as usize) && !self.congested.load(Ordering::Acquire)
    }

    /// Something to read (or an error to report)
    /// (a pending dump part counts: recv produces it)
    pub fn readable(&self) -> bool {
        // Separate statements: never hold rxq while taking dump (order
        // is dump -> rxq)
        let queued = !self.rxq.is_empty();
        let dumping = self.running.load(Ordering::Acquire);
        queued || dumping || self.sk.has_err()
    }

    pub fn has_error(&self) -> bool {
        self.sk.has_err()
    }

    /// Next datagram: removed unless `peek` (then a reference to it,
    /// left queued); EAGAIN if `nonblock` and empty; a pending overrun
    /// is reported first as ENOBUFS. Reading makes room, so a running
    /// dump continues (Linux netlink_recvmsg).
    pub fn recv(&self, peek: bool, nonblock: bool) -> Result<Arc<SkBuff>, KernelError> {
        let mut timeo = self.sk.rcv_timeo(nonblock);
        loop {
            if let Some(e) = self.sk.take_err() {
                return Err(e);
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
            timeo = self.sk.wait(timeo, || self.readable())?;
        }
    }

    fn dequeue(&self, peek: bool) -> Option<Arc<SkBuff>> {
        if peek {
            return self.rxq.peek();
        }
        let (skb, empty) = {
            let mut q = self.rxq.lock();
            let skb = q.pop_front()?;
            (skb, q.is_empty())
        };
        self.rmem.fetch_sub(skb.truesize(), Ordering::AcqRel);
        // Linux netlink_rcv_wake
        if empty {
            self.congested.store(false, Ordering::Release);
        }
        self.wait.wake_all();
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
            self.running.store(true, Ordering::Release);
        }
        self.dump_step();
        Ok(())
    }

    /// Continue a running dump once at most half the buffer is used
    fn dump_more(&self) {
        let half = self.sk.rcvbuf() as usize / 2;
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
        if self.dump.lock().is_none() {
            return false;
        }
        // One part, NLMSG_DONE included (fill leaves room for it), one
        // slab object
        let mut buf = Vec::with_capacity(rtnetlink::DUMP_SIZE);
        let mut d = self.dump.lock();
        let Some(st) = d.as_mut() else {
            return false;
        };
        let r = self.rmem.load(Ordering::Acquire);
        if r != 0 && r >= self.sk.rcvbuf() as usize {
            return false;
        }
        let done = match st.cb.fill(self, &mut buf) {
            Ok(false) => None,
            Ok(true) => Some(0),
            Err(e) => Some(-e.errno()),
        };
        if let Some(err) = done {
            buf.extend_from_slice(&self.dump_done(st, err));
            *d = None;
            self.running.store(false, Ordering::Release);
        }
        // Admission was checked above (a racing notification may push
        // rmem past rcvbuf, which Linux also allows for one skb). Queued
        // under the dump lock (sleeping: the skb's Arc is allocated
        // there, before the queue lock) so parts stay in order; readers
        // are woken after it is dropped.
        let skb = kernel_skb(buf, 0);
        let ts = skb.truesize();
        if let Ok(skb) = try_arc_gfp(skb, Gfp::KERNEL) {
            self.rmem.fetch_add(ts, Ordering::AcqRel);
            self.enqueue(skb);
        }
        drop(d);
        self.sk.data_ready();
        true
    }

    /// The NLMSG_DONE ending dump `st` with `err` (Linux
    /// netlink_dump_done): with NETLINK_EXT_ACK and an error message,
    /// NLM_F_ACK_TLVS and NLMSGERR_ATTR_MSG after the error
    fn dump_done(&self, st: &Dump, err: i32) -> Vec<u8> {
        let msg = st.cb.ext_msg().filter(|_| self.has_flag(sflags::EXT_ACK));
        let flags = NLM_F_MULTI | if msg.is_some() { NLM_F_ACK_TLVS } else { 0 };
        let mut m = attr::Msg::new(NLMSG_DONE, flags, st.seq, self.portid());
        m.put(&err.to_ne_bytes());
        if let Some(s) = msg {
            m.str(NLMSGERR_ATTR_MSG, s);
        }
        m.finish()
    }

    /// Send `data` to `dst` from this socket with the sender's `creds`
    /// (Linux netlink_sendmsg after address checks): portid 0 = the
    /// kernel
    pub fn send(
        self: &Arc<Self>,
        data: &[u8],
        dst: NlDst,
        creds: Creds,
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
        let cb = |group| NlCb {
            portid: me,
            group,
            creds: creds.clone(),
        };
        if group != 0 {
            let skb = nl_skb(data.to_vec(), cb(group));
            broadcast(&self.sk.net, self.sk.protocol, skb, me, Gfp::KERNEL);
        }
        if portid == 0 {
            if group == 0
                && let Some(input) = self.proto.input
            {
                input(self, data, explicit);
            }
            return Ok(data.len());
        }
        let peer = NlNet::get(&self.sk.net, self.sk.protocol, portid)
            .ok_or(KernelError::ConnectionRefused)?;
        let skb = try_arc_gfp(nl_skb(data.to_vec(), cb(0)), Gfp::KERNEL)?;
        peer.deliver(skb, self.sk.snd_timeo(nonblock))?;
        Ok(data.len())
    }

    /// Close (Linux netlink_release): leave the namespace table, drop a
    /// running dump, mark the socket dead, purge the receive queue and
    /// wake senders waiting for room in it (they fail ECONNREFUSED)
    pub fn release(&self) {
        let dump = {
            let mut d = self.dump.lock();
            self.running.store(false, Ordering::Release);
            d.take()
        };
        drop(dump);
        // Dead first: a subscription racing the release cannot put it
        // back on a multicast list
        self.dead.store(true, Ordering::Release);
        self.unhash();
        let q = self.rxq.purge();
        let n: usize = q.iter().map(SkBuff::truesize).sum();
        self.rmem.fetch_sub(n, Ordering::AcqRel);
        drop(q);
        self.wait.wake_all();
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
/// its group, except port `exclude` (Linux netlink_broadcast): each
/// but the first receiver gets a clone allocated under `gfp` (Linux
/// do_one_broadcast's skb_clone(allocation)). A `gfp` that may sleep
/// walks a snapshot of the list, taken before; another walks the list
/// under RCU.
pub fn broadcast(net: &NetNamespace, protocol: i32, skb: SkBuff, exclude: u32, gfp: Gfp) {
    let group = nl_cb(&skb).group;
    if group == 0 || group > 64 || !(0..MAX_LINKS as i32).contains(&protocol) {
        return;
    }
    let bit = 1u64 << (group - 1);
    let list = net.nl.mc(protocol);
    if gfp.has(Gfp::RECLAIM) {
        let socks = mc_snapshot(list);
        deliver(socks.iter().map(|s| &**s), skb, exclude, bit, gfp);
    } else {
        let g = crate::sync::rcu::read_lock();
        deliver(list.iter_ref(&g).map(|s| s.item()), skb, exclude, bit, gfp);
    }
}

/// Send a notification to `group` and, when `report`, back to port
/// `portid` (Linux nlmsg_notify): the requester is left out of the
/// multicast and gets its own copy, queued after it
pub fn notify(net: &NetNamespace, protocol: i32, skb: SkBuff, portid: u32, report: bool, gfp: Gfp) {
    if !report {
        broadcast(net, protocol, skb, 0, gfp);
        return;
    }
    let copy = skb.clone_gfp(gfp);
    broadcast(net, protocol, skb, portid, gfp);
    let Some(peer) = NlNet::get(net, protocol, portid) else {
        return;
    };
    match copy {
        Some(c) => {
            peer.queue(c);
        }
        None => peer.overrun(),
    }
}

/// References to the sockets on `list`, for a broadcast whose clones
/// may sleep: sized under the table lock, allocated with no lock, then
/// filled under RCU without allocating; again if the list grew
fn mc_snapshot(list: &RcuHList<NlMcNode, NlLocked>) -> Vec<Arc<NlSock>> {
    loop {
        let n = list.iter_locked(&NL_TABLE.lock.lock()).count();
        let mut v = Vec::with_capacity(n + 1);
        let g = crate::sync::rcu::read_lock();
        for s in list.iter_ref(&g) {
            if v.len() == v.capacity() {
                break;
            }
            v.push(s.get());
        }
        drop(g);
        if v.len() < v.capacity() {
            return v;
        }
    }
}

/// `broadcast` to the sockets of `socks`
fn deliver<'a>(
    socks: impl Iterator<Item = &'a NlSock>,
    skb: SkBuff,
    exclude: u32,
    bit: u64,
    gfp: Gfp,
) {
    let mut first = None;
    for s in socks {
        if s.portid() == exclude || s.groups_all() & bit == 0 {
            continue;
        }
        if first.is_none() {
            first = Some(s);
            continue;
        }
        match skb.clone_gfp(gfp) {
            Some(c) => {
                s.queue(c);
            }
            None => s.overrun(),
        }
    }
    if let Some(s) = first {
        s.queue(skb);
    }
}

/// Protocols (Linux MAX_LINKS)
const MAX_LINKS: usize = 32;

crate::hadapter!(NlNode, NlSock, node);
crate::rcu_puts!(NlSock, rcu);
crate::hadapter!(NlMcNode, NlSock, mc_node);

/// The data of the netlink table's lock: the proof its holder writes
/// the port id chains and the multicast lists' membership
///
/// # Invariants
/// One value exists, in [`NL_TABLE`].
pub struct NlLocked(());

// SAFETY: one value exists (type invariant), reachable only through the
// table's lock
unsafe impl UniqueOwner for NlLocked {}

/// Bound sockets of every namespace and protocol, by port id (Linux
/// nl_table[].hash: read under RCU)
struct NlTable {
    hash: spin::Once<Box<[RcuHList<NlNode, NlLocked>]>>,
    lock: Mutex<NlLocked>,
}

static NL_TABLE: NlTable = NlTable {
    hash: spin::Once::new(),
    lock: Mutex::new(NlLocked(())),
};

/// Size the port id table from memory (Linux grows its rhashtable;
/// here one chain per 2 MiB, 256 to 64 Ki chains, as UDP)
pub fn init() {
    let n = (crate::FRAME_ALLOCATOR.buffer_pages() >> 9)
        .next_power_of_two()
        .clamp(256, 1 << 16);
    NL_TABLE.hash.call_once(|| {
        let mut v = Vec::new();
        v.resize_with(n, RcuHList::new);
        v.into_boxed_slice()
    });
}

/// Linux netlink_compare_arg's hash: the namespace's random mix, the
/// protocol and the port id
fn slot(net: &NetNamespace, protocol: i32, portid: u32) -> &'static RcuHList<NlNode, NlLocked> {
    let t = NL_TABLE.hash.get().expect("netlink table not initialized");
    let h = crate::net::inet::port::secure_hash(
        0x6e6c_6861_7368,
        &[
            u64::from(net.hash_mix),
            (u64::from(protocol as u32) << 32) | u64::from(portid),
        ],
    );
    &t[h as usize & (t.len() - 1)]
}

impl NlSock {
    /// Leave the port id chain and the multicast list (Linux
    /// netlink_remove); references go a grace period later
    fn unhash(&self) {
        let mut o = NL_TABLE.lock.lock();
        if self.bound.load(Ordering::Acquire) {
            let chain = slot(&self.sk.net, self.sk.protocol, self.portid());
            if let Some(u) = chain.del_init(self, &mut o) {
                u.defer_put();
            }
        }
        if let Some(u) = self.sk.net.nl.mc(self.sk.protocol).del_init(self, &mut o) {
            u.defer_put();
        }
    }
}

/// A namespace's netlink state: per protocol, its sockets subscribed to
/// any group (Linux nl_table[].mc_list, net_eq filtered there)
pub struct NlNet {
    mc: [RcuHList<NlMcNode, NlLocked>; MAX_LINKS],
}

impl Default for NlNet {
    fn default() -> Self {
        Self {
            mc: [const { RcuHList::new() }; MAX_LINKS],
        }
    }
}

impl NlNet {
    fn mc(&self, protocol: i32) -> &RcuHList<NlMcNode, NlLocked> {
        &self.mc[protocol as usize % MAX_LINKS]
    }

    /// Socket of `net` bound to `portid` (Linux netlink_lookup: under
    /// RCU, with a reference taken under the guard)
    pub fn get(net: &NetNamespace, protocol: i32, portid: u32) -> Option<Arc<NlSock>> {
        let g = crate::sync::rcu::read_lock();
        let s = slot(net, protocol, portid)
            .iter_ref(&g)
            .find(|s| s.is(net, protocol, portid))?;
        Some(s.get())
    }
}

/// socket(AF_NETLINK, type, protocol)
pub fn create(stype: i32, protocol: i32) -> Result<Arc<dyn ProtoOps>, KernelError> {
    if stype != SOCK_RAW && stype != SOCK_DGRAM {
        return Err(KernelError::SocketTypeNotSupported);
    }
    let p = proto(protocol).ok_or(KernelError::ProtocolNotSupported)?;
    Ok(NlSock::new(p, protocol, stype)?)
}

/// Run `cb` on each request message of `data` (Linux netlink_rcv_skb):
/// messages without NLM_F_REQUEST and control types are skipped, a
/// short or truncated one ends the walk; each that fails is answered
/// with its error, each that asks with an ACK (`ack`)
pub fn rcv_skb(
    sk: &NlSock,
    mut data: &[u8],
    mut cb: impl FnMut(&attr::Hdr, &[u8]) -> Result<(), KernelError>,
) {
    while data.len() >= attr::NLMSG_HDRLEN {
        let Some(h) = attr::Hdr::parse(data) else {
            return;
        };
        let len = h.len as usize;
        if len < attr::NLMSG_HDRLEN || data.len() < len {
            return;
        }
        let msg = &data[..len];
        if h.flags & NLM_F_REQUEST != 0 && h.ty >= NLMSG_MIN_TYPE {
            match cb(&h, msg) {
                Err(e) => ack(sk, &h, msg, -e.errno()),
                Ok(()) if h.flags & NLM_F_ACK != 0 => ack(sk, &h, msg, 0),
                Ok(()) => {}
            }
        }
        data = &data[attr::align(len).min(data.len())..];
    }
}

/// Queue an NLMSG_ERROR (0: an ACK) for request `msg` with header `h`
/// (Linux netlink_ack without extended ACK attributes): an error
/// echoes the request unless NETLINK_CAP_ACK; with no memory for even
/// the capped form the socket gets ENOBUFS
pub fn ack(sk: &NlSock, h: &attr::Hdr, msg: &[u8], err: i32) {
    let echo = err != 0 && !sk.has_flag(sflags::CAP_ACK);
    let len = attr::NLMSG_HDRLEN
        + 4
        + if echo {
            attr::align(msg.len())
        } else {
            attr::NLMSG_HDRLEN
        };
    let flags = if echo { 0 } else { NLM_F_CAPPED };
    let mut m = Vec::new();
    if m.try_reserve_exact(len).is_err() {
        sk.sk.set_err(KernelError::NoBufferSpace);
        return;
    }
    m.extend_from_slice(&(len as u32).to_ne_bytes());
    m.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&h.seq.to_ne_bytes());
    m.extend_from_slice(&sk.portid().to_ne_bytes());
    m.extend_from_slice(&err.to_ne_bytes());
    let body = if echo {
        msg
    } else {
        &msg[..attr::NLMSG_HDRLEN]
    };
    m.extend_from_slice(body);
    m.resize(len, 0);
    sk.queue(kernel_skb(m, 0));
}
