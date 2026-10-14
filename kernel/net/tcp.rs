//! TCP (interim; the structured rewrite is P6)
//!
//! `TcpSock` is the protocol socket: common `Sock`, IPv4 `Inet`, the
//! control block `TcpCb` (sequence state; segments processed in
//! tcp_input/tcp_output), the receive byte queue and, for listeners,
//! the accept queue. Sockets that own a local port are in the
//! namespace's `TcpBind` table (bind conflicts per Linux
//! SO_REUSEADDR/SO_REUSEPORT rules); connections are in the four-tuple
//! table, listeners in the listener table. A socket leaves all tables
//! when its connection is done (CLOSED, or TIME_WAIT: no 2MSL timer yet)
//! or, if never connected, at close.
//!
//! ## Locking (thread context only)
//!
//! `TcpCb.sk_lock` (Linux lock_sock) serializes segment processing with
//! connect/send/close/shutdown/listen; never held across a sleep.
//! Order: `sk_lock` (listener before child) -> `TcpBind.socks` /
//! netns tables (RwLocks) -> `Inet.addr` / `rx` / `accept_queue` /
//! retransmit/ooo queues (Mutex leaves) -> FIB/ARP/device TX. Wakeups
//! (`Sock.wq`) are issued after the leaves are dropped.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use spin::{Mutex, RwLock};

use crate::net::KernelError;
use crate::net::af_inet::{self, IPPROTO_TCP as PROTO_TCP, Inet, SOL_IP};
use crate::net::inet::fib::RouteType;
use crate::net::inet::port::{self, BindInfo, Flow};
use crate::net::ipv4::{self, IPPROTO_TCP, Ipv4Addr};
use crate::net::msg::{
    MSG_DONTWAIT, MSG_ERRQUEUE, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL, RecvMsg, SendMsg,
};
use crate::net::request_sock::RequestSockQueue;
use crate::net::sock::{RCV_SHUTDOWN, SEND_SHUTDOWN, SHUTDOWN_MASK, Sock, sf};
use crate::net::socket::{
    AF_INET, AF_UNSPEC, OptIn, OptOut, ProtoOps, SIOCINQ, SIOCOUTQ, SOCK_STREAM, SOL_SOCKET,
    shut_bits,
};
use crate::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};

// Re-export submodules
pub use crate::net::tcp_input::tcp_rcv;

/// TCP header length (without options)
pub const TCP_HLEN_MIN: usize = 20;

/// TCP header maximum length (with options)
pub const TCP_HLEN_MAX: usize = 60;

/// TCP flags
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// TCP states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpState {
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
}

impl TcpState {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => TcpState::Closed,
            1 => TcpState::Listen,
            2 => TcpState::SynSent,
            3 => TcpState::SynReceived,
            4 => TcpState::Established,
            5 => TcpState::FinWait1,
            6 => TcpState::FinWait2,
            7 => TcpState::CloseWait,
            8 => TcpState::Closing,
            9 => TcpState::LastAck,
            10 => TcpState::TimeWait,
            _ => TcpState::Closed,
        }
    }

    /// Check if connection is established or later
    pub fn is_connected(self) -> bool {
        matches!(
            self,
            TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck
        )
    }
}

/// TCP header structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcpHdr {
    /// Source port (big-endian)
    pub source: [u8; 2],
    /// Destination port (big-endian)
    pub dest: [u8; 2],
    /// Sequence number (big-endian)
    pub seq: [u8; 4],
    /// Acknowledgment number (big-endian)
    pub ack_seq: [u8; 4],
    /// Data offset (4 bits) + reserved (4 bits)
    pub doff_reserved: u8,
    /// Flags
    pub flags: u8,
    /// Window size (big-endian)
    pub window: [u8; 2],
    /// Checksum (big-endian)
    pub check: [u8; 2],
    /// Urgent pointer (big-endian)
    pub urg_ptr: [u8; 2],
}

impl TcpHdr {
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes(self.source)
    }

    pub fn dest_port(&self) -> u16 {
        u16::from_be_bytes(self.dest)
    }

    pub fn seq(&self) -> u32 {
        u32::from_be_bytes(self.seq)
    }

    pub fn ack_seq(&self) -> u32 {
        u32::from_be_bytes(self.ack_seq)
    }

    pub fn data_offset(&self) -> usize {
        ((self.doff_reserved >> 4) as usize) * 4
    }

    pub fn window(&self) -> u16 {
        u16::from_be_bytes(self.window)
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// TCP connection four-tuple
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcpFourTuple {
    pub local_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_addr: Ipv4Addr,
    pub remote_port: u16,
}

/// TCP control block (sequence state)
pub struct TcpCb {
    /// TCP state
    state: AtomicU8,

    /// Initial send sequence number
    pub iss: u32,
    /// Send unacknowledged
    pub snd_una: AtomicU32,
    /// Send next
    pub snd_nxt: AtomicU32,
    /// Send window
    pub snd_wnd: AtomicU32,

    /// Initial receive sequence number
    pub irs: AtomicU32,
    /// Receive next (expected)
    pub rcv_nxt: AtomicU32,
    /// Receive window
    pub rcv_wnd: AtomicU32,

    /// Maximum segment size
    pub mss: u16,

    /// Retransmit timeout (in ms)
    pub rto: u32,

    /// Retransmit queue
    pub retransmit_queue: Mutex<Vec<TcpSegment>>,

    /// Out-of-order receive queue
    pub ooo_queue: Mutex<BTreeMap<u32, Vec<u8>>>,

    /// Socket lock (Linux lock_sock, without the backlog: input runs in
    /// thread context). Thread context only; never held across a sleep.
    sk_lock: Mutex<()>,
}

/// Segment in retransmit queue
pub struct TcpSegment {
    /// Sequence number
    pub seq: u32,
    /// Segment data (includes TCP header)
    pub data: Vec<u8>,
    /// Timestamp when sent
    pub sent_at: u64,
    /// Retransmit count
    pub retries: u8,
}

impl TcpCb {
    /// Create a new TCP control block
    pub fn new() -> Self {
        let iss = crate::random::get_random_u32();
        Self {
            state: AtomicU8::new(TcpState::Closed as u8),
            iss,
            snd_una: AtomicU32::new(iss),
            snd_nxt: AtomicU32::new(iss),
            snd_wnd: AtomicU32::new(0),
            irs: AtomicU32::new(0),
            rcv_nxt: AtomicU32::new(0),
            rcv_wnd: AtomicU32::new(65535),
            mss: 1460,
            rto: 1000,
            retransmit_queue: Mutex::new(Vec::new()),
            ooo_queue: Mutex::new(BTreeMap::new()),
            sk_lock: Mutex::new(()),
        }
    }

    /// Take the socket lock
    pub fn lock(&self) -> spin::MutexGuard<'_, ()> {
        self.sk_lock.lock()
    }

    pub fn state(&self) -> TcpState {
        TcpState::from_u8(self.state.load(Ordering::Acquire))
    }

    pub fn set_state(&self, state: TcpState) {
        self.state.store(state as u8, Ordering::Release);
    }

    pub fn snd_nxt(&self) -> u32 {
        self.snd_nxt.load(Ordering::Acquire)
    }

    pub fn inc_snd_nxt(&self, n: u32) {
        self.snd_nxt.fetch_add(n, Ordering::AcqRel);
    }

    pub fn rcv_nxt(&self) -> u32 {
        self.rcv_nxt.load(Ordering::Acquire)
    }

    pub fn set_rcv_nxt(&self, v: u32) {
        self.rcv_nxt.store(v, Ordering::Release);
    }
}

impl Default for TcpCb {
    fn default() -> Self {
        Self::new()
    }
}

/// Receive queue limit (bytes beyond are dropped; window management is P6)
const RX_LIMIT: usize = 65536;
/// Linux net.core.somaxconn default
const SOMAXCONN: u32 = 4096;

/// TCP options stored for P6/P7 (level IPPROTO_TCP)
pub const TCP_NODELAY: i32 = 1;
pub const TCP_MAXSEG: i32 = 2;
pub const TCP_CORK: i32 = 3;
pub const TCP_KEEPIDLE: i32 = 4;
pub const TCP_KEEPINTVL: i32 = 5;
pub const TCP_KEEPCNT: i32 = 6;
pub const TCP_SYNCNT: i32 = 7;
pub const TCP_QUICKACK: i32 = 12;
pub const TCP_USER_TIMEOUT: i32 = 18;

/// A TCP socket
pub struct TcpSock {
    pub sk: Sock,
    pub inet: Inet,
    pub tcp: TcpCb,
    /// In-order received bytes not yet read
    pub rx: Mutex<VecDeque<u8>>,
    /// Listener: pending and accepted connections
    pub accept_queue: Mutex<Option<RequestSockQueue>>,
    /// Was connected; a closed socket then reads EOF, not ENOTCONN
    /// (Linux SOCK_DONE)
    done: AtomicBool,
    /// Owns its local port in `TcpBind`
    bound: AtomicBool,
    /// A non-blocking connect is in progress (Linux SS_CONNECTING): the
    /// next connect() reports its outcome
    connecting: AtomicBool,
    /// Registered connection tuple
    tuple: Mutex<Option<TcpFourTuple>>,
    /// Stored IPPROTO_TCP options, by option number
    opts: Mutex<BTreeMap<i32, i32>>,
    me: Weak<TcpSock>,
}

/// socket(AF_INET, SOCK_STREAM, 0)
pub fn create() -> Arc<dyn ProtoOps> {
    TcpSock::new(Sock::new(
        crate::net::current_net_ns(),
        AF_INET,
        SOCK_STREAM,
        PROTO_TCP,
    ))
}

impl TcpSock {
    pub fn new(sk: Sock) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            sk,
            inet: Inet::default(),
            tcp: TcpCb::new(),
            rx: Mutex::new(VecDeque::new()),
            accept_queue: Mutex::new(None),
            done: AtomicBool::new(false),
            bound: AtomicBool::new(false),
            connecting: AtomicBool::new(false),
            tuple: Mutex::new(None),
            opts: Mutex::new(BTreeMap::new()),
            me: me.clone(),
        })
    }

    /// A child of `listener` for an accepted connection (Linux
    /// inet_csk_clone_lock)
    pub fn child(listener: &TcpSock) -> Arc<Self> {
        let c = Self::new(Sock::clone_from(&listener.sk));
        c.inet.clone_opts(&listener.inet);
        *c.opts.lock() = listener.opts.lock().clone();
        c
    }

    fn arc(&self) -> Arc<TcpSock> {
        self.me.upgrade().expect("tcp socket alive")
    }

    pub fn net(&self) -> &crate::net::NetNamespace {
        &self.sk.net
    }

    /// Local (address, port) once a port is owned
    pub fn local_addr(&self) -> Option<(Ipv4Addr, u16)> {
        let a = self.inet.get();
        (a.sport != 0).then_some((a.saddr, a.sport))
    }

    /// Remote (address, port) once connected/connecting
    pub fn remote_addr(&self) -> Option<(Ipv4Addr, u16)> {
        let a = self.inet.get();
        (a.dport != 0).then_some((a.daddr, a.dport))
    }

    pub fn set_local(&self, addr: Ipv4Addr, port: u16) {
        let mut a = self.inet.addr.lock();
        a.saddr = addr;
        a.rcv_saddr = addr;
        a.sport = port;
    }

    pub fn set_remote(&self, addr: Ipv4Addr, port: u16) {
        let mut a = self.inet.addr.lock();
        a.daddr = addr;
        a.dport = port;
    }

    /// Queue in-order data (bounded; window management is P6)
    pub fn deliver_data(&self, data: &[u8]) {
        let mut rx = self.rx.lock();
        let room = RX_LIMIT.saturating_sub(rx.len());
        rx.extend(&data[..data.len().min(room)]);
    }

    /// The peer closed its side (FIN): readers see EOF
    pub fn set_eof(&self) {
        self.sk.set_shutdown(RCV_SHUTDOWN);
    }

    /// Asynchronous error (RST, refused): reported once, wakes everyone
    pub fn set_error(&self, e: KernelError) {
        self.sk.set_err(e);
    }

    pub fn wake_rx(&self) {
        self.sk.data_ready();
    }

    pub fn wake_tx(&self) {
        self.sk.write_space();
    }

    pub fn wake_connect(&self) {
        self.sk.state_change();
    }

    pub fn wake_all(&self) {
        self.sk.state_change();
    }

    /// A listener got a connection ready to accept
    pub fn accept_wake(&self) {
        self.sk.data_ready();
    }

    fn bind_info(&self, addr: Ipv4Addr) -> BindInfo {
        BindInfo {
            addr,
            dev: self.sk.bound_dev_if(),
            reuse: self.sk.flag(sf::REUSEADDR),
            reuseport: self.sk.flag(sf::REUSEPORT),
            uid: self.sk.cred.euid,
            listen: self.tcp.state() == TcpState::Listen,
        }
    }

    /// Claim `port` (0 = ephemeral for `flow`) on address `addr`
    fn get_port(&self, addr: Ipv4Addr, port: u16, flow: Flow) -> Result<u16, KernelError> {
        let p = self
            .sk
            .net
            .tcp_bind
            .insert(&self.arc(), &self.bind_info(addr), port, flow)?;
        self.bound.store(true, Ordering::Release);
        Ok(p)
    }

    /// Register the connection four-tuple: EADDRNOTAVAIL if another
    /// connection already uses it (Linux __inet_hash_connect)
    fn hash(&self, t: TcpFourTuple) -> Result<(), KernelError> {
        if !self.sk.net.tcp_register(t, self.arc()) {
            return Err(KernelError::AddressNotAvailable);
        }
        *self.tuple.lock() = Some(t);
        Ok(())
    }

    /// Leave every table (Linux tcp_done / inet_put_port)
    pub fn unhash(&self) {
        if let Some(t) = self.tuple.lock().take() {
            self.sk.net.tcp_unregister(&t, self);
        }
        let port = self.inet.get().sport;
        if self.sk.flag(sf::ACCEPTCONN) {
            self.sk.set_flag(sf::ACCEPTCONN, false);
            self.sk.net.tcp_listen_unregister(port, self);
        }
        if self.bound.swap(false, Ordering::AcqRel) {
            self.sk.net.tcp_bind.remove(self, port);
        }
    }

    /// The connection is over (CLOSED, or TIME_WAIT without a timer yet):
    /// leave the tables, wake everyone (Linux tcp_done)
    pub fn done(&self) {
        self.done.store(true, Ordering::Release);
        self.unhash();
        self.sk.set_shutdown(SHUTDOWN_MASK);
    }

    /// Abort: RST to the peer (if synchronized), CLOSED, done
    pub fn abort(&self) {
        if let (Some((la, lp)), Some((ra, rp))) = (self.local_addr(), self.remote_addr())
            && self.tcp.state().is_connected()
        {
            let _ = crate::net::tcp_output::tcp_send_rst(
                self.net(),
                la,
                lp,
                ra,
                rp,
                self.tcp.snd_nxt(),
                None,
            );
        }
        self.tcp.set_state(TcpState::Closed);
        self.done();
    }

    // --- connect -----------------------------------------------------------

    /// Linux tcp_v4_connect
    fn start_connect(&self, daddr: Ipv4Addr, dport: u16) -> Result<(), KernelError> {
        let _g = self.tcp.lock();
        if self.tcp.state() != TcpState::Closed {
            return Err(KernelError::AlreadyConnected);
        }
        let a = self.inet.get();
        let rt =
            crate::net::inet::route::output(&self.sk.net, daddr, a.saddr, self.sk.bound_dev_if())?;
        if matches!(rt.rtype, RouteType::Broadcast | RouteType::Multicast) {
            return Err(KernelError::NetworkUnreachable);
        }
        let saddr = if a.saddr.is_unspecified() {
            rt.saddr
        } else {
            a.saddr
        };
        let sport = if a.sport != 0 {
            a.sport
        } else {
            let flow = Flow {
                proto: IPPROTO_TCP,
                saddr,
                daddr,
                dport,
            };
            self.get_port(saddr, 0, flow)?
        };
        let t = TcpFourTuple {
            local_addr: saddr,
            local_port: sport,
            remote_addr: daddr,
            remote_port: dport,
        };
        if let Err(e) = self.hash(t) {
            if a.sport == 0 {
                self.unhash();
            }
            return Err(e);
        }
        self.set_local(saddr, sport);
        self.set_remote(daddr, dport);
        self.tcp.set_state(TcpState::SynSent);
        let me = self.arc();
        if let Err(e) = crate::net::tcp_output::tcp_send_syn(&me) {
            self.tcp.set_state(TcpState::Closed);
            self.unhash();
            return Err(e);
        }
        Ok(())
    }

    /// Wait for the handshake (Linux inet_wait_for_connect): send timeout
    /// -> EINPROGRESS; failure -> the socket error or ECONNABORTED
    fn wait_connect(&self, nonblock: bool) -> Result<(), KernelError> {
        let timeo = self.sk.snd_timeo(nonblock);
        let r = self.sk.wait(timeo, || {
            !matches!(self.tcp.state(), TcpState::SynSent | TcpState::SynReceived)
        });
        match r {
            Err(KernelError::WouldBlock) => return Err(KernelError::InProgress),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        if self.tcp.state() == TcpState::Closed {
            return Err(self.sk.take_err().unwrap_or(KernelError::ConnectionAborted));
        }
        Ok(())
    }

    // --- data ----------------------------------------------------------------

    /// Bytes readable now
    fn rx_len(&self) -> usize {
        self.rx.lock().len()
    }

    /// Copy (or with MSG_TRUNC discard) up to `want` queued bytes into
    /// `m` at `off`; consumes unless `peek`
    fn take_rx(
        &self,
        m: &mut RecvMsg,
        off: usize,
        want: usize,
        flags: i32,
    ) -> Result<usize, KernelError> {
        let peek = flags & MSG_PEEK != 0;
        let mut rx = self.rx.lock();
        // MSG_PEEK reads past what earlier loop rounds already peeked
        let skip = if peek { off } else { 0 };
        let n = want.min(rx.len().saturating_sub(skip));
        if n == 0 {
            return Ok(0);
        }
        let chunk: Vec<u8> = rx.range(skip..skip + n).copied().collect();
        if !peek {
            rx.drain(..n);
        }
        drop(rx);
        if flags & MSG_TRUNC != 0 {
            return Ok(n);
        }
        let put = m.data.put(off, &chunk)?;
        if !peek {
            self.sk.write_space();
        }
        Ok(put)
    }

    /// Readers can stop waiting
    fn rx_ready(&self) -> bool {
        self.rx_len() > 0
            || self.sk.has_err()
            || self.sk.shutdown() & RCV_SHUTDOWN != 0
            || self.tcp.state() == TcpState::Closed
    }
}

/// Linux tcp_recvmsg main loop (no urgent data, no prequeue)
fn tcp_recvmsg(s: &TcpSock, m: &mut RecvMsg, flags: i32) -> Result<usize, KernelError> {
    if s.tcp.state() == TcpState::Listen {
        return Err(KernelError::NotConnected);
    }
    if flags & MSG_ERRQUEUE != 0 {
        return Err(KernelError::WouldBlock);
    }
    if flags & MSG_OOB != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let len = m.data.len();
    let mut timeo = s.sk.rcv_timeo(flags & MSG_DONTWAIT != 0);
    let target = if flags & MSG_WAITALL != 0 {
        len
    } else {
        (s.sk.rcvlowat().max(1) as usize).min(len)
    };
    let mut copied = 0;
    loop {
        if copied < len {
            copied += s.take_rx(m, copied, len - copied, flags)?;
        }
        if copied >= target.max(1) || (len == 0) {
            break;
        }
        if copied > 0 {
            if s.sk.has_err()
                || s.tcp.state() == TcpState::Closed
                || s.sk.shutdown() & RCV_SHUTDOWN != 0
            {
                break;
            }
        } else {
            if let Some(e) = s.sk.take_err() {
                return Err(e);
            }
            if s.sk.shutdown() & RCV_SHUTDOWN != 0 {
                break;
            }
            if s.tcp.state() == TcpState::Closed {
                if !s.done.load(Ordering::Acquire) {
                    return Err(KernelError::NotConnected);
                }
                break;
            }
        }
        if flags & MSG_PEEK != 0 && copied > 0 {
            break;
        }
        match s.sk.wait(timeo, || {
            s.rx_ready() && (flags & MSG_PEEK == 0 || s.rx_len() > copied)
        }) {
            Ok(t) => timeo = t,
            Err(e)
                if copied > 0
                    && matches!(
                        e,
                        KernelError::WouldBlock
                            | KernelError::Interrupted
                            | KernelError::RestartSys
                    ) =>
            {
                break;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(copied)
}

/// Linux tcp_sendmsg: wait for the connection, then send everything
/// (blocking) or what the window takes (non-blocking)
fn tcp_sendmsg(s: &Arc<TcpSock>, m: &mut SendMsg, flags: i32) -> Result<usize, KernelError> {
    if flags & MSG_OOB != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    let mut timeo = s.sk.snd_timeo(flags & MSG_DONTWAIT != 0);
    // sk_stream_wait_connect
    loop {
        if let Some(e) = s.sk.take_err() {
            return Err(e);
        }
        if s.sk.shutdown() & SEND_SHUTDOWN != 0 {
            return Err(KernelError::BrokenPipe);
        }
        match s.tcp.state() {
            TcpState::Established | TcpState::CloseWait => break,
            TcpState::SynSent | TcpState::SynReceived => {
                timeo = s.sk.wait(timeo, || {
                    !matches!(s.tcp.state(), TcpState::SynSent | TcpState::SynReceived)
                })?;
            }
            _ => return Err(KernelError::BrokenPipe),
        }
    }
    let total = m.data.len();
    let mut sent = 0;
    while sent < total {
        let n = (total - sent).min(65536);
        let chunk = m.data.take_at(sent, n)?;
        match crate::net::tcp_output::tcp_sendmsg(s, &chunk) {
            Ok(k) => sent += k,
            Err(KernelError::WouldBlock) => {}
            Err(e) if sent > 0 => {
                let _ = e;
                break;
            }
            Err(e) => return Err(e),
        }
        crate::net::dev::netif_rx_flush_local();
        if sent == total {
            break;
        }
        let wnd = || {
            s.tcp.snd_wnd.load(Ordering::Acquire) > 0
                || s.sk.has_err()
                || !matches!(s.tcp.state(), TcpState::Established | TcpState::CloseWait)
        };
        match s.sk.wait(timeo, wnd) {
            Ok(t) => timeo = t,
            Err(_) if sent > 0 => break,
            Err(e) => return Err(e),
        }
        if s.sk.has_err() || !matches!(s.tcp.state(), TcpState::Established | TcpState::CloseWait) {
            if sent > 0 {
                break;
            }
            return Err(s.sk.take_err().unwrap_or(KernelError::BrokenPipe));
        }
    }
    Ok(sent)
}

impl ProtoOps for TcpSock {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sk(&self) -> &Sock {
        &self.sk
    }

    /// Last close (Linux tcp_close without linger/RST-on-unread: P6)
    fn release(&self) {
        self.sk.set_shutdown(SHUTDOWN_MASK);
        let state = self.tcp.state();
        match state {
            TcpState::Listen => {
                let q = self.accept_queue.lock().take();
                self.tcp.set_state(TcpState::Closed);
                self.unhash();
                if let Some(q) = q {
                    while let Some(c) = q.accept_queue_remove() {
                        c.abort();
                    }
                }
            }
            TcpState::Closed | TcpState::SynSent => {
                self.tcp.set_state(TcpState::Closed);
                self.unhash();
            }
            _ => {
                let _ = tcp_close(&self.arc());
                crate::net::dev::netif_rx_flush_local();
            }
        }
    }

    /// Linux inet_bind for TCP
    fn bind(&self, a: &[u8]) -> Result<(), KernelError> {
        let (addr, port, ty) = af_inet::bind_check(&self.sk, &self.inet, a)?;
        if matches!(ty, RouteType::Multicast | RouteType::Broadcast) {
            return Err(KernelError::AddressNotAvailable);
        }
        let _g = self.tcp.lock();
        if self.tcp.state() != TcpState::Closed || self.inet.get().sport != 0 {
            return Err(KernelError::InvalidArgument);
        }
        let no_port = port == 0 && self.inet.flag(af_inet::ipf::BIND_NO_PORT);
        let p = if no_port {
            0
        } else {
            let flow = Flow {
                proto: IPPROTO_TCP,
                saddr: addr,
                ..Default::default()
            };
            self.get_port(addr, port, flow)?
        };
        let mut s = self.inet.addr.lock();
        s.rcv_saddr = addr;
        s.saddr = addr;
        s.sport = p;
        s.addr_lock = !addr.is_unspecified();
        s.port_lock = port != 0;
        Ok(())
    }

    /// Linux __inet_stream_connect
    fn connect(&self, a: &[u8], nonblock: bool) -> Result<(), KernelError> {
        if af_inet::sa_family(a)? == AF_UNSPEC {
            // Linux tcp_disconnect: abort, back to an unconnected socket
            self.abort();
            self.done.store(false, Ordering::Release);
            self.sk.clear_shutdown();
            *self.inet.addr.lock() = Default::default();
            return Ok(());
        }
        let state = self.tcp.state();
        if matches!(state, TcpState::SynSent | TcpState::SynReceived) {
            if nonblock {
                return Err(KernelError::AlreadyInProgress);
            }
            let r = self.wait_connect(false);
            self.connecting.store(false, Ordering::Release);
            return r;
        }
        // The outcome of an earlier non-blocking connect (SS_CONNECTING)
        if self.connecting.swap(false, Ordering::AcqRel) {
            return match state {
                TcpState::Closed => {
                    Err(self.sk.take_err().unwrap_or(KernelError::ConnectionAborted))
                }
                _ => Ok(()),
            };
        }
        if state != TcpState::Closed {
            return Err(KernelError::AlreadyConnected);
        }
        let (daddr, dport) = af_inet::sin_parse(a, false)?;
        let r = self.start_connect(daddr, dport);
        crate::net::dev::netif_rx_flush_local();
        r?;
        if nonblock {
            self.connecting.store(true, Ordering::Release);
            return Err(KernelError::InProgress);
        }
        self.wait_connect(false)
    }

    /// Linux inet_listen (autobinds an unbound socket)
    fn listen(&self, backlog: i32) -> Result<(), KernelError> {
        let _g = self.tcp.lock();
        let backlog = (backlog as u32).clamp(1, SOMAXCONN);
        match self.tcp.state() {
            TcpState::Listen => return Ok(()),
            TcpState::Closed => {}
            _ => return Err(KernelError::InvalidArgument),
        }
        let a = self.inet.get();
        if a.sport == 0 {
            let flow = Flow {
                proto: IPPROTO_TCP,
                saddr: a.rcv_saddr,
                ..Default::default()
            };
            let p = self.get_port(a.rcv_saddr, 0, flow)?;
            self.inet.addr.lock().sport = p;
        } else if !self
            .sk
            .net
            .tcp_bind
            .can_listen(self, &self.bind_info(a.rcv_saddr), a.sport)
        {
            return Err(KernelError::AddressInUse);
        }
        *self.accept_queue.lock() = Some(RequestSockQueue::new(backlog));
        self.tcp.set_state(TcpState::Listen);
        self.sk.set_flag(sf::ACCEPTCONN, true);
        let port = self.inet.get().sport;
        self.sk.net.tcp_listen_register(port, self.arc());
        Ok(())
    }

    /// Linux inet_csk_accept: waits up to SO_RCVTIMEO
    fn accept(&self, nonblock: bool) -> Result<Arc<dyn ProtoOps>, KernelError> {
        if self.tcp.state() != TcpState::Listen {
            return Err(KernelError::InvalidArgument);
        }
        let mut timeo = self.sk.rcv_timeo(nonblock);
        loop {
            let c = self
                .accept_queue
                .lock()
                .as_ref()
                .and_then(|q| q.accept_queue_remove());
            if let Some(c) = c {
                return Ok(c);
            }
            if self.tcp.state() != TcpState::Listen {
                return Err(KernelError::InvalidArgument);
            }
            let ready = || {
                self.accept_queue
                    .lock()
                    .as_ref()
                    .is_none_or(|q| !q.accept_queue_is_empty())
                    || self.tcp.state() != TcpState::Listen
            };
            timeo = self.sk.wait(timeo, ready)?;
        }
    }

    fn getname(&self, peer: bool) -> Result<Vec<u8>, KernelError> {
        let a = self.inet.get();
        if peer {
            if a.dport == 0 || matches!(self.tcp.state(), TcpState::Closed | TcpState::SynSent) {
                return Err(KernelError::NotConnected);
            }
            return Ok(af_inet::sin_bytes(a.daddr, a.dport));
        }
        let addr = if a.rcv_saddr.is_unspecified() {
            a.saddr
        } else {
            a.rcv_saddr
        };
        Ok(af_inet::sin_bytes(addr, a.sport))
    }

    /// Linux tcp_poll
    fn poll(&self) -> u16 {
        let state = self.tcp.state();
        if state == TcpState::Listen {
            let ready = self
                .accept_queue
                .lock()
                .as_ref()
                .is_some_and(|q| !q.accept_queue_is_empty());
            return if ready { POLLIN | POLLRDNORM } else { 0 };
        }
        let mut mask = 0;
        let sh = self.sk.shutdown();
        if sh == SHUTDOWN_MASK || state == TcpState::Closed {
            mask |= POLLHUP;
        }
        if sh & RCV_SHUTDOWN != 0 {
            mask |= POLLIN | POLLRDNORM | POLLRDHUP;
        }
        if !matches!(state, TcpState::SynSent | TcpState::SynReceived) {
            if self.rx_len() >= self.sk.rcvlowat().max(1) as usize {
                mask |= POLLIN | POLLRDNORM;
            }
            if sh & SEND_SHUTDOWN != 0
                || self.tcp.snd_wnd.load(Ordering::Acquire) > 0
                || state == TcpState::Closed
            {
                mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
            }
        }
        if self.sk.has_err() {
            mask |= POLLERR;
        }
        mask
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let v = match cmd {
            SIOCINQ => {
                if self.tcp.state() == TcpState::Listen {
                    return Err(KernelError::InvalidArgument);
                }
                self.rx_len()
            }
            SIOCOUTQ => {
                if self.tcp.state() == TcpState::Listen {
                    return Err(KernelError::InvalidArgument);
                }
                0
            }
            _ => return Err(KernelError::NotTty),
        };
        crate::uaccess::put_user::<crate::arch::Uaccess, i32>(arg, v as i32)
            .map_err(|_| KernelError::BadAddress)?;
        Ok(0)
    }

    fn inq(&self) -> usize {
        self.rx_len()
    }

    /// Linux inet_shutdown + tcp_shutdown
    fn shutdown(&self, how: i32) -> Result<(), KernelError> {
        let bits = shut_bits(how)?;
        let state = self.tcp.state();
        let r = match state {
            TcpState::Closed => {
                self.sk.set_shutdown(bits);
                Err(KernelError::NotConnected)
            }
            TcpState::Listen => {
                if bits & RCV_SHUTDOWN != 0 {
                    self.release();
                    self.sk.set_shutdown(0);
                }
                Ok(())
            }
            TcpState::SynSent => {
                self.abort();
                Ok(())
            }
            _ => {
                self.sk.set_shutdown(bits);
                if bits & SEND_SHUTDOWN != 0
                    && matches!(
                        state,
                        TcpState::Established | TcpState::SynReceived | TcpState::CloseWait
                    )
                {
                    let _ = tcp_close(&self.arc());
                    crate::net::dev::netif_rx_flush_local();
                }
                Ok(())
            }
        };
        self.sk.state_change();
        r
    }

    fn setsockopt(&self, level: i32, opt: i32, v: OptIn) -> Option<Result<(), KernelError>> {
        match level {
            SOL_SOCKET => None,
            SOL_IP => Some(self.inet.setsockopt(&self.sk, opt, v)),
            PROTO_TCP => Some(self.set_tcp_opt(opt, v)),
            _ => Some(Err(KernelError::NoProtocolOption)),
        }
    }

    fn getsockopt(&self, level: i32, opt: i32) -> Option<Result<OptOut, KernelError>> {
        match level {
            SOL_SOCKET => None,
            SOL_IP => Some(self.inet.getsockopt(opt)),
            PROTO_TCP => Some(self.get_tcp_opt(opt)),
            // Linux do_ip_getsockopt: other levels are EOPNOTSUPP
            _ => Some(Err(KernelError::OperationNotSupported)),
        }
    }

    fn sendmsg(&self, m: &mut SendMsg, flags: i32) -> Result<usize, KernelError> {
        tcp_sendmsg(&self.arc(), m, flags)
    }

    fn recvmsg(&self, m: &mut RecvMsg, flags: i32) -> Result<usize, KernelError> {
        tcp_recvmsg(self, m, flags)
    }
}

impl TcpSock {
    /// IPPROTO_TCP options (validated like Linux, stored for P6/P7)
    fn set_tcp_opt(&self, opt: i32, v: OptIn) -> Result<(), KernelError> {
        let val = v.int()?;
        let ok = match opt {
            TCP_NODELAY | TCP_CORK | TCP_QUICKACK => true,
            TCP_MAXSEG => val == 0 || (88..=65535).contains(&val),
            TCP_KEEPIDLE | TCP_KEEPINTVL => (1..=32767).contains(&val),
            TCP_KEEPCNT => (1..=127).contains(&val),
            TCP_SYNCNT => (1..=127).contains(&val),
            TCP_USER_TIMEOUT => val >= 0,
            _ => return Err(KernelError::NoProtocolOption),
        };
        if !ok {
            return Err(KernelError::InvalidArgument);
        }
        let val = if matches!(opt, TCP_NODELAY | TCP_CORK | TCP_QUICKACK) {
            (val != 0) as i32
        } else {
            val
        };
        self.opts.lock().insert(opt, val);
        Ok(())
    }

    fn get_tcp_opt(&self, opt: i32) -> Result<OptOut, KernelError> {
        let default = match opt {
            TCP_NODELAY | TCP_CORK | TCP_USER_TIMEOUT => 0,
            TCP_QUICKACK => 1,
            TCP_MAXSEG => self.tcp.mss as i32,
            TCP_KEEPIDLE => 7200,
            TCP_KEEPINTVL => 75,
            TCP_KEEPCNT => 9,
            TCP_SYNCNT => 6,
            _ => return Err(KernelError::NoProtocolOption),
        };
        Ok(OptOut::Int(*self.opts.lock().get(&opt).unwrap_or(&default)))
    }
}

/// Register an accepted child's connection; false if the four-tuple is
/// already in use (the child is then dropped)
pub fn tcp_register_connection(tuple: TcpFourTuple, socket: Arc<TcpSock>) -> bool {
    socket.bound.store(false, Ordering::Release);
    socket.hash(tuple).is_ok()
}

/// Initiate a FIN close of a synchronized connection
pub fn tcp_close(socket: &Arc<TcpSock>) -> Result<(), KernelError> {
    let tcp = &socket.tcp;
    let _guard = tcp.lock();
    match tcp.state() {
        TcpState::Closed | TcpState::Listen | TcpState::SynSent => {
            tcp.set_state(TcpState::Closed);
            drop(_guard);
            socket.done();
        }
        TcpState::SynReceived | TcpState::Established => {
            tcp.set_state(TcpState::FinWait1);
            crate::net::tcp_output::tcp_send_fin(socket)?;
        }
        TcpState::CloseWait => {
            tcp.set_state(TcpState::LastAck);
            crate::net::tcp_output::tcp_send_fin(socket)?;
        }
        _ => {}
    }
    Ok(())
}

// ============================================================================
// Port ownership table (per namespace)
// ============================================================================

/// TCP sockets owning a local port (bound, listening or connected)
#[derive(Default)]
pub struct TcpBind {
    socks: RwLock<BTreeMap<u16, Vec<Arc<TcpSock>>>>,
}

impl TcpBind {
    fn free(
        map: &BTreeMap<u16, Vec<Arc<TcpSock>>>,
        port: u16,
        me: &TcpSock,
        info: &BindInfo,
    ) -> bool {
        map.get(&port).is_none_or(|v| {
            v.iter()
                .filter(|o| !core::ptr::eq(Arc::as_ptr(o), me))
                .all(|o| !port::conflict(info, &o.bind_info(o.inet.get().rcv_saddr), true))
        })
    }

    fn insert(
        &self,
        s: &Arc<TcpSock>,
        info: &BindInfo,
        port: u16,
        flow: Flow,
    ) -> Result<u16, KernelError> {
        let mut map = self.socks.write();
        let port = if port != 0 {
            if !Self::free(&map, port, s, info) {
                return Err(KernelError::AddressInUse);
            }
            port
        } else {
            let range = s.sk.net.port_range.get();
            // Ephemeral: an entirely unused port
            port::ephemeral(range, flow, |p| !map.contains_key(&p))
                .ok_or(KernelError::AddressInUse)?
        };
        map.entry(port).or_default().push(s.clone());
        Ok(port)
    }

    /// May `s`, already owning `port`, start listening (SO_REUSEADDR
    /// does not share with a listener)?
    fn can_listen(&self, s: &TcpSock, info: &BindInfo, port: u16) -> bool {
        let mut i = *info;
        i.listen = true;
        let map = self.socks.read();
        map.get(&port).is_none_or(|v| {
            v.iter()
                .filter(|o| !core::ptr::eq(Arc::as_ptr(o), s))
                .all(|o| !port::conflict(&i, &o.bind_info(o.inet.get().rcv_saddr), true))
        })
    }

    fn remove(&self, s: &TcpSock, port: u16) {
        let mut map = self.socks.write();
        if let Some(v) = map.get_mut(&port) {
            v.retain(|o| !core::ptr::eq(Arc::as_ptr(o), s));
            if v.is_empty() {
                map.remove(&port);
            }
        }
    }
}

/// Compute TCP checksum
pub fn tcp_checksum(saddr: Ipv4Addr, daddr: Ipv4Addr, tcp_data: &[u8]) -> u16 {
    let len = tcp_data.len() as u16;

    // Start with pseudo-header
    let mut sum = ipv4::pseudo_header_checksum(saddr, daddr, IPPROTO_TCP, len);

    // Add TCP header and data
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }

    // Fold and complement
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
