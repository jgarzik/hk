//! Network Buffer (SkBuff)
//!
//! This module implements the network buffer structure, equivalent to
//! Linux's sk_buff. It provides efficient packet manipulation with
//! the head/data/tail/end pointer model.
//!
//! ## Memory Layout
//!
//! ```text
//! +-------+------+------+-------+
//! | head  | data |      | tail  | end
//! +-------+------+------+-------+
//!    ^       ^              ^       ^
//!    |       |              |       |
//!    |       +- start of    |       +- end of buffer
//!    |          packet data |
//!    |                      +- end of packet data
//!    +- start of buffer
//!
//! Headroom: head..data (for pushing headers)
//! Data:     data..tail (actual packet data)
//! Tailroom: tail..end  (for appending data)
//! ```
//!
//! ## Queues
//!
//! An skb is linked into a queue through its own `list` link (Linux
//! skb->next/prev): an [`SkbHead`] (Linux sk_buff_head used with the
//! unlocked `__skb_*` calls under its owner's lock) or an [`SkbQueue`]
//! (an `SkbHead` with its own lock: skb_queue_tail, skb_dequeue). A
//! queue owns each skb through `P`: a `Box` where the skb has one owner
//! (the per-CPU backlog), an `Arc` where it is shared (Linux
//! skb->users). Queueing never allocates. An skb taken off under the
//! lock is dropped after it (its device reference may be the last).

use crate::util::kalloc::{try_box, with_gfp};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::mm::page_alloc::Gfp;
use crate::sync::spin::{Mutex, MutexGuard};
use crate::util::list::{Link, ListPtr, OwnedList, Owner, PtrList};
use crate::util::rbtree::{RbNode, RbRoot};

use crate::net::af_inet::RxInfo;
use crate::net::device::NetDevice;
use crate::net::ethernet::{EtherType, PktType};
use crate::net::ipv4::Ipv4Addr;

/// Standard headroom to reserve for headers
pub const NET_SKB_PAD: usize = 64;

/// Maximum packet size we'll allocate
/// Largest buffer: a 64 KB IP datagram plus headroom (loopback MTU)
pub const MAX_SKB_SIZE: usize = 65536 + 512;

/// Headroom of a transmitted skb: Ethernet (14) + IP (20-60) + TCP
/// (20-60) headers
pub const TX_HEADROOM: usize = 14 + 60 + 60;

/// Network buffer - equivalent to Linux sk_buff
///
/// # Invariants
/// `data <= tail <= buf.len()`; `mac` and `nh`, when set, are at most
/// `tail` (moving `tail` below one clears it).
#[derive(Default)]
pub struct SkBuff {
    /// Its link on a queue (Linux skb->next/prev)
    list: Link,
    /// Which [`SkbOwnedQueue`] holds it through `list` (none: 0)
    qowner: Owner,
    /// Its node in a TCP socket's out-of-order or retransmit tree
    /// (Linux skb->rbnode); an skb is on one list or tree at a time
    rb: RbNode,
    /// The buffer: headroom, packet data, tailroom (a Vec so a message
    /// built in one is adopted whole, `from_vec`)
    buf: Vec<u8>,
    /// Start of the packet data (moves with push/pull)
    data: usize,
    /// End of the packet data (moves with put/trim)
    tail: usize,
    /// Bytes charged to a socket buffer for it (Linux skb->truesize):
    /// the buffer and the skb itself as allocated; TCP's send skbs
    /// count their header room, then the payload copied in
    truesize: usize,

    // Protocol information
    /// EtherType (set by eth_type_trans)
    pub protocol: EtherType,
    /// IP protocol number (set by IP layer)
    pub ip_protocol: u8,

    // Device reference
    /// Source/destination device
    pub dev: Option<Arc<NetDevice>>,

    // IP addresses (set by IP layer for routing)
    pub saddr: Option<Ipv4Addr>,
    pub daddr: Option<Ipv4Addr>,

    /// Receive classification (set by eth_type_trans)
    pub pkt_type: PktType,
    /// Received IP packet was addressed to a broadcast address (Linux
    /// RTCF_BROADCAST; set by ip_rcv)
    pub ip_bcast: bool,
    /// Received IP header TTL and TOS (for IP_RECVTTL / IP_RECVTOS)
    pub ip_ttl: u8,
    pub ip_tos: u8,
    /// Sending socket of a frame from an AF_PACKET socket (its address
    /// as an id, 0 if none): its own outgoing tap skips it (Linux
    /// skb_loop_sk)
    pub owner: usize,
    /// The transport checksum is left to the device (Linux ip_summed
    /// CHECKSUM_PARTIAL: a UDP datagram out through lo, whose
    /// NETIF_F_HW_CSUM Linux uses; hk computes it anyway); seen by the
    /// packet taps (TP_STATUS_CSUMNOTREADY), kept as lo loops it back
    pub csum_partial: bool,
    /// The sender saw forward progress: the next hop's neighbour entry
    /// is confirmed as the packet goes out (Linux dst_pending_confirm,
    /// skb_set_dst_pending_confirm; sock_confirm_neigh)
    pub dst_pending_confirm: bool,
    /// The received IP header's compiled options (Linux IPCB(skb)->opt)
    pub ip_opt: crate::net::inet::options::OptMeta,
    /// Run when the skb is freed or orphaned (Linux skb->destructor
    /// with skb->sk: a TX ring frame's completion); not cloned
    pub destructor: Option<Box<dyn SkbDestructor>>,
    /// Start of the MAC header in the buffer (None until received)
    mac: Option<usize>,
    /// Start of the IP header of a received packet (None until marked)
    nh: Option<usize>,
    /// Arrival time, CLOCK_REALTIME ns (Linux skb->tstamp, a ktime_t;
    /// 0: not stamped yet, the receiving socket stamps it as it queues);
    /// of an skb TCP sent, when it last went out, monotonic ns (Linux
    /// skb_mstamp_ns, the same union)
    pub tstamp: i64,
    /// The receiving socket's drop count when it was queued (Linux
    /// SOCK_SKB_CB(skb)->dropcount, for SO_RXQ_OVFL)
    pub dropcount: u32,
    /// A zero-length datagram was peeked at an offset (Linux
    /// skb->peeked, skb_set_peeked): later offset peeks skip it
    pub peeked: core::sync::atomic::AtomicBool,
    /// Per-layer data of a queued skb (Linux skb->cb)
    pub cb: SkbCb,
}

/// What a protocol keeps with a queued skb (Linux skb->cb, typed: each
/// layer reads only its own variant)
#[derive(Default)]
pub enum SkbCb {
    #[default]
    None,
    /// A datagram queued to a UDP, ping or raw socket: its control
    /// message data (Linux IPCB + PKTINFO_SKB_CB) and source port
    Inet(InetCb),
    /// An extended error on a socket's error queue (Linux
    /// SKB_EXT_ERR / sock_exterr_skb)
    Exterr(crate::net::sock::ExtErr),
    /// A frame queued to a packet socket (Linux PACKET_SKB_CB)
    Pkt(crate::net::packet::PktCb),
    /// A netlink message (Linux NETLINK_CB)
    Nl(crate::net::netlink::NlCb),
    /// An IPv4 fragment in a reassembly queue (Linux FRAG_CB)
    Frag(crate::net::inet::frag::FragCb),
    /// A TCP segment: the sequence space it covers and its header
    /// fields (Linux TCP_SKB_CB)
    Tcp(TcpSkbCb),
    /// A request waiting on a neighbour table's proxy queue (Linux
    /// NEIGH_CB)
    Neigh(crate::net::neigh::NeighCb),
    /// An AF_UNIX message (Linux UNIXCB and the skb's sock_wfree
    /// destructor); boxed, so every skb stays small (skbs are passed by
    /// value down the receive path)
    Unix(Box<crate::net::unix::UnixCb>),
}

impl SkbCb {
    /// The cb of a clone (Linux skb_clone copies cb). AF_UNIX messages,
    /// which own their files and their sender's charge, are never
    /// cloned: theirs comes back empty.
    fn dup(&self) -> Self {
        match self {
            Self::None | Self::Unix(_) => Self::None,
            Self::Inet(c) => Self::Inet(*c),
            Self::Exterr(e) => Self::Exterr(*e),
            Self::Pkt(p) => Self::Pkt(*p),
            Self::Nl(n) => Self::Nl(n.clone()),
            Self::Frag(f) => Self::Frag(*f),
            Self::Tcp(t) => Self::Tcp(*t),
            Self::Neigh(n) => Self::Neigh(*n),
        }
    }
}

/// What an skb's destructor does is its `Drop` (Linux skb->destructor,
/// called by kfree_skb and skb_orphan): any context, possibly under the
/// freeing path's spin locks, so it takes only leaf locks and wakes
pub trait SkbDestructor: Send + Sync {}

impl SkBuff {
    /// Run the destructor now and forget the owner's charge (Linux
    /// skb_orphan, as loopback_xmit before looping a frame back)
    pub fn orphan(&mut self) {
        self.destructor = None;
    }
}

/// [`SkbCb::Inet`]
#[derive(Clone, Copy, Default)]
pub struct InetCb {
    pub info: RxInfo,
    /// Source port (0 for ping and raw)
    pub sport: u16,
}

impl SkBuff {
    /// Allocate an skb with `headroom` bytes reserved before the data
    /// and room for `data_len` bytes of it (Linux alloc_skb +
    /// skb_reserve), both allocations under `gfp`: GFP_ATOMIC where
    /// Linux allocates in atomic context (receive and protocol paths,
    /// drivers), GFP_KERNEL for a socket's sendmsg. None on failure.
    pub fn alloc(headroom: usize, data_len: usize, gfp: Gfp) -> Option<Box<Self>> {
        let total_size = headroom.checked_add(data_len)?;
        if total_size > MAX_SKB_SIZE {
            return None;
        }
        with_gfp(gfp, || {
            let buf = crate::util::kmem::try_vec(total_size, 0u8).ok()?;
            try_box(Self {
                truesize: buf.capacity() + core::mem::size_of::<Self>(),
                buf,
                data: headroom,
                tail: headroom,
                ..Default::default()
            })
            .ok()
        })
    }

    /// Allocate an skb for transmitting `data_len` bytes, with headroom
    /// for every header below them (Ethernet + IP + TCP)
    pub fn alloc_tx(data_len: usize, gfp: Gfp) -> Option<Box<Self>> {
        Self::alloc(TX_HEADROOM, data_len, gfp)
    }

    /// Room for `n` bytes after the data: short of it, the buffer
    /// grows under `gfp` so the data could reach a whole number of
    /// `step` bytes, no more than `max` (as TCP's send path takes page
    /// frags of Linux's sk_page_frag_refill). None without memory or
    /// past [`MAX_SKB_SIZE`] (unchanged).
    pub fn grow(&mut self, n: usize, step: usize, max: usize, gfp: Gfp) -> Option<()> {
        if self.tailroom() >= n {
            return Some(());
        }
        let need = self.len().checked_add(n)?;
        let room = MAX_SKB_SIZE.checked_sub(self.data)?;
        if need > room {
            return None;
        }
        let want = need
            .div_ceil(step)
            .saturating_mul(step)
            .min(max)
            .min(room)
            .max(need);
        let extra = self.data + want - self.buf.len();
        with_gfp(gfp, || crate::util::kmem::try_reserve(&mut self.buf, extra)).ok()?;
        self.buf.resize(self.data + want, 0);
        Some(())
    }

    /// Give back the buffer around the data beyond `headroom` before it
    /// once more than `slack` bytes would go: the data move to a buffer
    /// that fits, allocated under `gfp` (Linux frees the frags
    /// tcp_trim_head and tcp_fragment leave unused); header marks are
    /// dropped. False without memory (unchanged).
    pub fn compact(&mut self, headroom: usize, slack: usize, gfp: Gfp) -> bool {
        let waste = self.data.saturating_sub(headroom) + self.tailroom();
        if waste <= slack {
            return true;
        }
        let h = headroom.min(self.data);
        let Ok(mut v) = with_gfp(gfp, || crate::util::kmem::try_vec(h + self.len(), 0u8)) else {
            return false;
        };
        v[h..].copy_from_slice(self.data());
        self.tail = h + self.len();
        self.data = h;
        self.buf = v;
        self.mac = None;
        self.nh = None;
        true
    }

    /// Get current data length
    #[inline]
    pub fn len(&self) -> usize {
        self.tail - self.data
    }

    /// Check if buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get headroom (space before data)
    #[inline]
    pub fn headroom(&self) -> usize {
        self.data
    }

    /// Get tailroom (space after tail)
    #[inline]
    pub fn tailroom(&self) -> usize {
        self.buf.len() - self.tail
    }

    /// Get the data as a byte slice
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buf[self.data..self.tail]
    }

    /// Get the data as a mutable byte slice
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.data..self.tail]
    }

    /// Get raw data pointer
    #[inline]
    pub fn data_ptr(&self) -> *const u8 {
        self.data().as_ptr()
    }

    /// Get raw data pointer (mutable)
    #[inline]
    pub fn data_ptr_mut(&mut self) -> *mut u8 {
        self.data_mut().as_mut_ptr()
    }

    /// Reserve headroom (call before adding data): moves the (empty) data
    /// forward; clamped to the buffer
    pub fn reserve(&mut self, len: usize) {
        debug_assert!(self.is_empty(), "reserve called on non-empty skb");
        let at = self.tail.saturating_add(len).min(self.buf.len());
        // INVARIANT: data == tail <= buf.len()
        self.data = at;
        self.tail = at;
    }

    /// Push header - prepend bytes to the front
    ///
    /// Moves the data pointer backward, returns slice to fill.
    /// Used for adding headers (Ethernet, IP, TCP).
    pub fn push(&mut self, len: usize) -> Option<&mut [u8]> {
        if self.headroom() < len {
            return None;
        }
        self.data -= len;
        Some(&mut self.buf[self.data..self.data + len])
    }

    /// Pull header - consume bytes from the front
    ///
    /// Moves the data pointer forward, returns consumed data.
    /// Used for parsing headers.
    pub fn pull(&mut self, len: usize) -> Option<&[u8]> {
        if self.len() < len {
            return None;
        }
        let start = self.data;
        self.data += len;
        Some(&self.buf[start..start + len])
    }

    /// Put data - append bytes to the tail
    ///
    /// Moves the tail pointer forward, returns slice to fill.
    /// Used for adding payload data.
    pub fn put(&mut self, len: usize) -> Option<&mut [u8]> {
        if self.tailroom() < len {
            return None;
        }
        let start = self.tail;
        self.tail += len;
        Some(&mut self.buf[start..start + len])
    }

    /// Put data from a slice
    pub fn put_slice(&mut self, data: &[u8]) -> Option<()> {
        let buf = self.put(data.len())?;
        buf.copy_from_slice(data);
        Some(())
    }

    /// Trim data from the tail
    ///
    /// Moves the tail pointer backward.
    pub fn trim(&mut self, len: usize) -> Option<()> {
        if self.len() < len {
            return None;
        }
        self.tail -= len;
        // INVARIANT: a header mark past the new tail is gone
        let tail = self.tail;
        self.mac = self.mac.filter(|&m| m <= tail);
        self.nh = self.nh.filter(|&n| n <= tail);
        Some(())
    }

    /// Set the data length (adjusts tail)
    pub fn set_len(&mut self, len: usize) -> Option<()> {
        let current_len = self.len();
        if len > current_len {
            self.put(len - current_len)?;
        } else if len < current_len {
            self.trim(current_len - len)?;
        }
        Some(())
    }

    /// Reset the buffer to initial state (keeps allocation); the headroom
    /// is clamped to the buffer
    pub fn reset(&mut self, headroom: usize) {
        self.data = headroom.min(self.buf.len());
        self.tail = self.data;
        self.protocol = EtherType::Unknown(0);
        self.ip_protocol = 0;
        self.saddr = None;
        self.daddr = None;
        self.pkt_type = PktType::Host;
        self.ip_bcast = false;
        self.owner = 0;
        self.csum_partial = false;
        self.dst_pending_confirm = false;
        self.ip_opt = Default::default();
        self.destructor = None;
        self.mac = None;
        self.nh = None;
        self.tstamp = 0;
        self.dropcount = 0;
        self.cb = SkbCb::None;
    }

    /// Record the current data pointer as the start of the MAC header
    pub fn mark_mac_header(&mut self) {
        self.mac = Some(self.data);
    }

    /// The received frame from its MAC header to the end (after the
    /// header was pulled), if one was recorded
    pub fn frame_from_mac(&self) -> Option<&[u8]> {
        self.buf.get(self.mac?..self.tail)
    }

    /// Record the current data pointer as the start of the IP header
    pub fn mark_network_header(&mut self) {
        self.nh = Some(self.data);
    }

    /// The received packet from its IP header to the end (after the
    /// header was pulled), if one was recorded
    pub fn network_packet(&self) -> Option<&[u8]> {
        self.buf.get(self.nh?..self.tail)
    }

    /// Bytes it holds: the buffer and the skb itself (host tests)
    #[cfg(test)]
    pub fn mem_size(&self) -> usize {
        self.buf.capacity() + core::mem::size_of::<Self>()
    }

    /// Bytes charged to a socket buffer for it (Linux skb->truesize)
    pub fn truesize(&self) -> usize {
        self.truesize
    }

    /// Change what it is charged as (Linux skb->truesize written by
    /// TCP: tcp_stream_alloc_skb, the payload copied in or moved by
    /// tcp_fragment, skb_shift, tcp_trim_head); only while uncharged,
    /// or with the charge adjusted alike
    pub fn set_truesize(&mut self, n: usize) {
        self.truesize = n;
    }

    /// An skb whose data is `v`, taken over without a copy (a netlink
    /// or AF_UNIX message built before any lock); its truesize counts
    /// the Vec's capacity
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self {
            tail: v.len(),
            truesize: v.capacity() + core::mem::size_of::<Self>(),
            buf: v,
            ..Default::default()
        }
    }

    /// The received packet's data offset past its IP header (None if
    /// none was marked): `push` that much to get back to it
    pub fn network_offset(&self) -> Option<usize> {
        Some(self.data - self.nh?)
    }

    /// A copy under `gfp` with its own buffer and no queue link (Linux
    /// skb_clone: hk skbs do not share data, so a clone copies it; the
    /// receive paths clone GFP_ATOMIC). None on failure.
    pub fn clone_gfp(&self, gfp: Gfp) -> Option<Self> {
        let buf = with_gfp(gfp, || crate::util::kmem::try_to_vec(&self.buf)).ok()?;
        Some(Self {
            list: Link::new(),
            qowner: Owner::new(),
            rb: RbNode::new(),
            buf,
            data: self.data,
            tail: self.tail,
            truesize: self.truesize,
            protocol: self.protocol,
            ip_protocol: self.ip_protocol,
            dev: self.dev.clone(),
            saddr: self.saddr,
            daddr: self.daddr,
            pkt_type: self.pkt_type,
            ip_bcast: self.ip_bcast,
            ip_ttl: self.ip_ttl,
            ip_tos: self.ip_tos,
            owner: self.owner,
            csum_partial: self.csum_partial,
            dst_pending_confirm: self.dst_pending_confirm,
            ip_opt: self.ip_opt,
            destructor: None,
            mac: self.mac,
            nh: self.nh,
            tstamp: self.tstamp,
            dropcount: self.dropcount,
            peeked: core::sync::atomic::AtomicBool::new(false),
            cb: self.cb.dup(),
        })
    }

    /// Network namespace of the skb's device (receive path: the namespace
    /// the packet arrived in; never the current task's)
    pub fn net(&self) -> Option<Arc<crate::net::NetNamespace>> {
        self.dev.as_ref()?.net()
    }
}

crate::adapter!(pub SkbLink, SkBuff, list);
crate::owned_adapter!(pub SkbOwned, SkBuff, list, qowner);
crate::rb_adapter!(pub SkbRb, SkBuff, rb);

/// A tree of skbs ordered by the caller (Linux rb_root of skb->rbnode:
/// TCP's out-of-order queue and retransmit queue)
pub type SkbTree = RbRoot<SkbRb, Box<SkBuff>>;

/// TCP's per-skb state (Linux struct tcp_skb_cb, its fields only): the
/// sequence space the skb covers, its flags, scoreboard tags, segment
/// count and the rate sample's delivery state at its transmission. A
/// segment's header (window, options, SACK blocks) is not kept here:
/// it is in the skb's data until TCP processes it, or written there
/// when it is sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpSkbCb {
    /// The connection's delivered count when it went out, and a
    /// nonzero us stamp until a SACK counted its delivery (Linux
    /// tx.delivered, tx.delivered_mstamp; its send time is the skb's
    /// `tstamp`, Linux skb_mstamp_ns)
    pub tx_delivered_mstamp: u64,
    pub tx_delivered: u32,
    pub seq: u32,
    /// `seq` + data length + SYN + FIN
    pub end_seq: u32,
    /// The ACK field of a received segment (Linux ack_seq)
    pub ack_seq: u32,
    /// A SYN taking over a TIME_WAIT tuple: the new connection's ISN,
    /// else 0 (Linux tcp_tw_isn)
    pub tw_isn: u32,
    /// A received segment's header length in words (Linux
    /// tcp_hdr(skb)->doff, which header prediction compares)
    pub doff: u8,
    /// Segments a sent skb counts as, and their size when more than
    /// one (Linux tcp_gso_segs, tcp_gso_size)
    gso_segs: u16,
    gso_size: u16,
    /// TCP header flags (Linux tcp_flags)
    pub flags: u8,
    /// A sent skb's scoreboard tags (Linux sacked: TCPCB_SACKED_ACKED,
    /// _SACKED_RETRANS, _LOST, _EVER_RETRANS)
    pub sacked: u8,
}

impl TcpSkbCb {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    /// Linux tcp_skb_pcount
    pub fn pcount(&self) -> u32 {
        u32::from(self.gso_segs)
    }

    /// Linux tcp_skb_pcount_set
    pub fn set_pcount(&mut self, n: u32) {
        self.gso_segs = n.min(u32::from(u16::MAX)) as u16;
    }

    /// Linux tcp_skb_mss's tcp_gso_size
    pub fn gso_size(&self) -> u32 {
        u32::from(self.gso_size)
    }

    pub fn set_gso_size(&mut self, n: u32) {
        self.gso_size = n.min(u32::from(u16::MAX)) as u16;
    }
}

/// Most SACK blocks an option carries (Linux TCP_NUM_SACKS)
pub const NUM_SACKS: usize = 4;

/// The blocks of a SACK option, [start, end) each, in option order
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sacks {
    pub n: u8,
    pub b: [(u32, u32); NUM_SACKS],
}

impl Sacks {
    /// The blocks present
    pub fn blocks(&self) -> &[(u32, u32)] {
        &self.b[..usize::from(self.n).min(NUM_SACKS)]
    }

    /// Append a block; false if full
    pub fn push(&mut self, blk: (u32, u32)) -> bool {
        let i = usize::from(self.n);
        if i >= NUM_SACKS {
            return false;
        }
        self.b[i] = blk;
        self.n += 1;
        true
    }
}

impl SkBuff {
    /// TCP's control block (Linux TCP_SKB_CB): empty unless TCP set it
    #[inline]
    pub fn tcp(&self) -> TcpSkbCb {
        match self.cb {
            SkbCb::Tcp(t) => t,
            _ => TcpSkbCb::default(),
        }
    }

    /// TCP's control block to change, made empty first if the cb holds
    /// another protocol's
    #[inline]
    pub fn tcp_mut(&mut self) -> &mut TcpSkbCb {
        if !matches!(self.cb, SkbCb::Tcp(_)) {
            self.cb = SkbCb::Tcp(TcpSkbCb::default());
        }
        match &mut self.cb {
            SkbCb::Tcp(t) => t,
            _ => unreachable!("skb: cb just set"),
        }
    }

    /// Set TCP's control block
    #[inline]
    pub fn set_tcp(&mut self, t: TcpSkbCb) {
        self.cb = SkbCb::Tcp(t);
    }
}

/// A queue of skbs, each owned through `P` (Linux sk_buff_head with the
/// unlocked `__skb_queue_tail`/`__skb_dequeue`/`skb_queue_walk_safe`
/// calls): used under its owner's lock, or as an [`SkbQueue`]'s
/// contents under the queue's own. Dropping it frees what is left
/// (Linux __skb_queue_purge).
pub type SkbHead<P = Arc<SkBuff>> = PtrList<SkbLink, P>;

/// An skb queue with its own lock (Linux sk_buff_head and its lock):
/// thread context only (no protocol code runs in an interrupt
/// handler), a leaf: nothing is taken under it and nothing is dropped
/// under it that could take a lock or sleep
pub struct SkbQueue<P: ListPtr<Target = SkBuff> = Arc<SkBuff>> {
    q: Mutex<SkbHead<P>>,
}

impl<P: ListPtr<Target = SkBuff>> SkbQueue<P> {
    /// An empty queue; its lockdep class is the caller's location (Linux
    /// skb_queue_head_init's static key)
    #[track_caller]
    pub const fn new() -> Self {
        Self {
            q: Mutex::new(SkbHead::new()),
        }
    }

    /// Take the queue's lock for several steps at once (Linux
    /// spin_lock(&list->lock) around `__skb_*` calls)
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, SkbHead<P>> {
        self.q.lock()
    }

    /// The first skb, taken off (Linux skb_dequeue)
    pub fn dequeue(&self) -> Option<P> {
        self.q.lock().pop_front()
    }

    /// Whether the queue is empty (Linux skb_queue_empty_lockless: a
    /// hint unless the caller orders it with the queueing)
    pub fn is_empty(&self) -> bool {
        self.q.lock().is_empty()
    }

    /// Take every skb off at once (Linux skb_queue_splice_init under the
    /// lock, then __skb_queue_purge): the caller drops what comes back
    /// after the lock is released
    #[must_use]
    pub fn purge(&self) -> SkbHead<P> {
        core::mem::take(&mut *self.q.lock())
    }
}

impl SkbQueue<Arc<SkBuff>> {
    /// A reference to the first skb, left queued (Linux skb_peek +
    /// skb_get under the queue lock): the caller reads it unlocked
    pub fn peek(&self) -> Option<Arc<SkBuff>> {
        self.q.lock().front_arc()
    }
}

/// An skb queue with its own lock whose skbs carry its owner mark
/// (Linux sk_buff_head with skb_peek_next and skb_unlink of a given
/// skb): for a reader that copies an skb with the lock dropped and
/// then steps past it or unlinks it, which is safe even if the queue
/// was purged meanwhile (the skb is then on no queue: nothing happens).
/// Thread context only, a leaf; nothing is dropped under it.
pub struct SkbOwnedQueue {
    q: Mutex<OwnedList<SkbOwned>>,
}

impl SkbOwnedQueue {
    #[track_caller]
    pub fn new() -> Self {
        Self {
            q: Mutex::new(OwnedList::new()),
        }
    }

    /// Take the lock for several steps (`push_back`, `len`, a walk)
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, OwnedList<SkbOwned>> {
        self.q.lock()
    }

    /// Linux skb_queue_tail
    pub fn push(&self, skb: Arc<SkBuff>) {
        self.q.lock().push_back(skb);
    }

    /// The first skb, taken off (Linux skb_dequeue)
    pub fn dequeue(&self) -> Option<Arc<SkBuff>> {
        self.q.lock().pop_front()
    }

    /// A reference to the first skb, left queued (Linux skb_peek)
    pub fn peek(&self) -> Option<Arc<SkBuff>> {
        self.q.lock().front()
    }

    /// A reference to the skb after `skb` (Linux skb_peek_next); None
    /// at the end, or if `skb` is no longer queued here
    pub fn peek_next(&self, skb: &SkBuff) -> Option<Arc<SkBuff>> {
        self.q.lock().next(skb)
    }

    /// Take `skb` off (Linux skb_unlink): the queue's reference, which
    /// the caller drops after the lock; None if it is not queued here
    #[must_use]
    pub fn unlink(&self, skb: &SkBuff) -> Option<Arc<SkBuff>> {
        self.q.lock().remove(skb)
    }

    pub fn is_empty(&self) -> bool {
        self.q.lock().is_empty()
    }

    pub fn len(&self) -> usize {
        self.q.lock().len()
    }

    /// Take every skb off at once; the caller drops them after the lock
    /// (Linux skb_queue_splice_init + __skb_queue_purge)
    #[must_use]
    pub fn purge(&self) -> OwnedList<SkbOwned> {
        core::mem::take(&mut *self.q.lock())
    }
}

impl Default for SkbOwnedQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_and_put() {
        let mut skb = SkBuff::alloc(64, 1500, Gfp::KERNEL).unwrap();
        assert_eq!(skb.len(), 0);
        assert!(skb.headroom() >= 64);

        // Add some data
        let buf = skb.put(100).unwrap();
        buf.fill(0xAB);
        assert_eq!(skb.len(), 100);
        assert_eq!(skb.data()[0], 0xAB);
    }

    #[test]
    fn test_push_and_pull() {
        let mut skb = SkBuff::alloc(64, 1500, Gfp::KERNEL).unwrap();

        // Add payload
        skb.put(100);

        // Push header
        let hdr = skb.push(14).unwrap();
        hdr.fill(0xCD);
        assert_eq!(skb.len(), 114);

        // Pull header
        let pulled = skb.pull(14).unwrap();
        assert_eq!(pulled[0], 0xCD);
        assert_eq!(skb.len(), 100);
    }

    #[test]
    fn test_bounds_from_safe_calls() {
        let mut skb = SkBuff::alloc(16, 32, Gfp::KERNEL).unwrap();
        // A headroom past the buffer is clamped: no tailroom overflow
        skb.reset(1000);
        assert_eq!(skb.tailroom(), 0);
        assert!(skb.put(1).is_none());
        // A MAC mark above a trimmed tail is dropped, not underflowed
        skb.reset(16);
        skb.put(20);
        skb.pull(14);
        skb.mark_mac_header();
        skb.push(14);
        skb.trim(skb.len());
        assert!(skb.frame_from_mac().is_none());
    }

    fn skb(n: usize) -> Box<SkBuff> {
        let mut s = SkBuff::alloc(0, 8, Gfp::ATOMIC).unwrap();
        s.put(n).unwrap();
        s
    }

    fn lens<P: ListPtr<Target = SkBuff>>(h: &SkbHead<P>) -> alloc::vec::Vec<usize> {
        h.iter().map(SkBuff::len).collect()
    }

    /// FIFO order; a walk unlinks the ones it picks into another head
    /// in order (Linux skb_queue_walk_safe + __skb_unlink)
    #[test]
    fn queue_fifo_and_walk_unlink() {
        let q: SkbQueue<Box<SkBuff>> = SkbQueue::new();
        for n in 1..=5 {
            q.lock().push_back(skb(n));
        }
        assert_eq!(q.lock().len(), 5);
        assert_eq!(q.dequeue().map(|s| s.len()), Some(1));
        let mut gone: SkbHead<Box<SkBuff>> = SkbHead::new();
        q.lock()
            .drain_if(|s| s.len() % 2 == 0, |s| gone.push_back(s));
        assert_eq!(lens(&gone), [2, 4]);
        assert_eq!(lens(&q.lock()), [3, 5]);
        // The link is free again once off every queue
        let s = gone.pop_front().unwrap();
        q.lock().push_back(s);
        assert_eq!(lens(&q.lock()), [3, 5, 2]);
    }

    /// peek takes a reference and leaves the skb queued; purge takes
    /// them all off at once
    #[test]
    fn peek_and_purge() {
        let q: SkbQueue = SkbQueue::new();
        assert!(q.peek().is_none());
        q.lock().push_back(Arc::from(skb(1)));
        q.lock().push_back(Arc::from(skb(2)));
        let p = q.peek().unwrap();
        assert_eq!((p.len(), Arc::strong_count(&p)), (1, 2));
        assert_eq!(q.lock().len(), 2);
        let all = q.purge();
        assert!(q.is_empty());
        assert_eq!(lens(&all), [1, 2]);
        drop(all);
        assert_eq!(Arc::strong_count(&p), 1);
    }

    /// An owned queue steps from and unlinks a given skb, and ignores
    /// one it no longer holds
    #[test]
    fn owned_queue_next_unlink() {
        let q = SkbOwnedQueue::new();
        let a: Arc<SkBuff> = Arc::from(skb(1));
        let b: Arc<SkBuff> = Arc::from(skb(2));
        q.push(a.clone());
        q.push(b.clone());
        assert_eq!(q.peek_next(&a).map(|s| s.len()), Some(2));
        assert!(q.peek_next(&b).is_none());
        let gone = q.purge();
        assert!(q.peek_next(&a).is_none());
        assert!(q.unlink(&a).is_none());
        drop(gone);
        q.push(a.clone());
        assert!(q.unlink(&b).is_none());
        assert!(q.unlink(&a).is_some());
        assert!(q.is_empty());
    }

    /// A clone has its own buffer and keeps the marks and cb
    #[test]
    fn clone_copies() {
        let mut a = skb(4);
        a.data_mut().copy_from_slice(b"abcd");
        a.mark_network_header();
        a.pull(2);
        a.cb = SkbCb::Inet(InetCb::default());
        let mut c = a.clone_gfp(Gfp::ATOMIC).unwrap();
        c.data_mut()[0] = b'X';
        assert_eq!(a.data(), b"cd");
        assert_eq!(c.data(), b"Xd");
        assert_eq!(c.network_offset(), Some(2));
        assert!(matches!(c.cb, SkbCb::Inet(_)));
        assert_eq!(c.truesize(), a.truesize());
    }

    /// A shared skb stays alive in the queue while its other reference
    /// goes, and the queue's drop frees the rest
    #[test]
    fn shared_queue_holds_references() {
        let a: Arc<SkBuff> = Arc::from(skb(3));
        let q: SkbQueue = SkbQueue::new();
        q.lock().push_back(a.clone());
        q.lock().push_back(Arc::from(skb(4)));
        assert_eq!(Arc::strong_count(&a), 2);
        drop(q);
        assert_eq!(Arc::strong_count(&a), 1);
    }
}

#[cfg(test)]
mod tcp_cb_tests {
    /// TCP's per-skb state fits Linux's 48-byte skb->cb, which every
    /// skb of every protocol carries
    #[test]
    fn tcp_cb_fits_linux_cb() {
        assert!(core::mem::size_of::<super::TcpSkbCb>() <= 48);
    }
}
