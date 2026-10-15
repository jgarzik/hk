//! The TCP control block (RFC 9293 TCB): an I/O-free state machine
//!
//! `TcpCb` holds the whole protocol state of one connection: the 11
//! RFC 9293 states, the send and receive sequence spaces, the send queue
//! (unacknowledged + unsent bytes), the receive queue and the
//! out-of-order intervals, RTT/RTO estimation, congestion state and the
//! timer deadlines. It never transmits, sleeps or locks: user calls
//! (`connect`, `send`, `recv`, `close`, ...), segments (`input`) and
//! timer expiry (`on_timer`) only change state and append what must
//! happen to an [`Out`]: segments to send, wakeups, errors, shutdown
//! bits, "done" (leave the tables) and timer changes (`next_timer`).
//! The socket glue (`tcp/mod.rs`) runs those actions after dropping the
//! socket lock; host unit tests (`tcp/tests.rs`) drive two control
//! blocks over a simulated lossy network with a virtual clock.
//!
//! Time is in milliseconds on any monotonic clock chosen by the caller.
//! Sequence numbers compare modulo 2^32 (`before`/`after`).
//!
//! Window scaling and timestamps (RFC 7323) come in P7: the receive
//! window is at most 65535 and `snd_wscale`/`rcv_wscale` stay 0.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::cong::Cong;
use crate::error::KernelError;

/// TCP header flags
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

/// Connection states (RFC 9293 3.3.2; values are Linux's TCP_* order is
/// not kept: use `linux()` for /proc and TCP_INFO)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    /// Synchronized states (a SYN was received and acknowledged)
    pub fn synced(self) -> bool {
        !matches!(
            self,
            TcpState::Closed | TcpState::Listen | TcpState::SynSent | TcpState::SynReceived
        )
    }

    /// Linux TCP_* number (include/net/tcp_states.h)
    pub fn linux(self) -> u8 {
        match self {
            TcpState::Established => 1,
            TcpState::SynSent => 2,
            TcpState::SynReceived => 3,
            TcpState::FinWait1 => 4,
            TcpState::FinWait2 => 5,
            TcpState::TimeWait => 6,
            TcpState::Closed => 7,
            TcpState::CloseWait => 8,
            TcpState::LastAck => 9,
            TcpState::Listen => 10,
            TcpState::Closing => 11,
        }
    }
}

/// Default send MSS when the peer sends no MSS option (RFC 9293 3.7.1)
pub const MSS_DEFAULT: u32 = 536;
/// IPv4 + TCP header bytes (no options) per segment
pub const HDRS: u32 = 40;
/// Largest receive window without window scaling
pub const MAX_WINDOW: u32 = 65535;
/// RFC 6298 initial RTO, Linux TCP_RTO_MIN / TCP_RTO_MAX (ms)
pub const RTO_INIT: u64 = 1000;
pub const RTO_MIN: u64 = 200;
pub const RTO_MAX: u64 = 120_000;
/// RTO after a retransmitted SYN when no RTT was measured (RFC 6298 5.7)
pub const RTO_FALLBACK: u64 = 3000;
/// 2*MSL (Linux TCP_TIMEWAIT_LEN, ms)
pub const TIMEWAIT_LEN: u64 = 60_000;
/// Retransmissions of an orphaned connection (Linux tcp_orphan_retries 0)
pub const ORPHAN_RETRIES: u32 = 8;

/// Global TCP buffer memory (send + receive queues of all connections;
/// Linux tcp_mem): past `MEM_LIMIT`, senders wait and receive windows
/// only shrink, so many connections cannot exhaust the kernel heap
static MEM: AtomicUsize = AtomicUsize::new(0);
pub const MEM_LIMIT: usize = 4 * 1024 * 1024;

/// Bytes of the global TCP memory still free
pub fn mem_free() -> usize {
    MEM_LIMIT.saturating_sub(MEM.load(Ordering::Relaxed))
}

/// Per-namespace knobs a connection uses (sysctls, read at creation)
#[derive(Clone, Copy, Debug)]
pub struct Cfg {
    pub syn_retries: u32,
    pub synack_retries: u32,
    pub retries2: u32,
    /// FIN_WAIT2 lifetime of an orphan (tcp_fin_timeout, ms)
    pub fin_timeout: u64,
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            syn_retries: 6,
            synack_retries: 5,
            retries2: 15,
            fin_timeout: 60_000,
        }
    }
}

/// A segment to transmit (header fields + payload; addresses and ports
/// are the connection's)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seg {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub wnd: u16,
    /// MSS option (SYN and SYN-ACK)
    pub mss: Option<u16>,
    pub data: Vec<u8>,
}

impl Seg {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

/// A received segment, already checksummed and parsed
#[derive(Clone, Copy, Debug)]
pub struct SegIn<'a> {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub wnd: u16,
    pub mss: Option<u16>,
    pub data: &'a [u8],
}

impl SegIn<'_> {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    /// Sequence space occupied: data plus SYN and FIN
    pub fn seq_len(&self) -> u32 {
        self.data.len() as u32 + self.has(flags::SYN) as u32 + self.has(flags::FIN) as u32
    }
}

/// What a call into the control block asks the caller to do
#[derive(Debug, Default)]
pub struct Out {
    pub segs: Vec<Seg>,
    /// Report this error (sk_err) and wake everyone
    pub err: Option<KernelError>,
    /// Socket shutdown bits to set (Linux sk_shutdown)
    pub shut: u8,
    /// Wake readers, writers and pollers
    pub wake: bool,
    /// The connection is over (CLOSED): leave the tables
    pub done: bool,
    /// Entered TIME_WAIT: hand over to a timewait entry
    pub timewait: bool,
    /// The handshake completed (SYN_RECEIVED/SYN_SENT -> ESTABLISHED)
    pub established: bool,
}

/// Socket shutdown bits (same values as `net::sock`)
pub const RCV_SHUTDOWN: u8 = 1;
pub const SEND_SHUTDOWN: u8 = 2;
pub const SHUTDOWN_MASK: u8 = 3;

/// a before b (mod 2^32)
pub fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// a after b (mod 2^32)
pub fn after(a: u32, b: u32) -> bool {
    before(b, a)
}

/// lo <= x <= hi (mod 2^32)
pub fn between(x: u32, lo: u32, hi: u32) -> bool {
    hi.wrapping_sub(lo) >= x.wrapping_sub(lo)
}

/// Copy `buf.len()` bytes of `q` starting at `skip` into `buf`
pub(super) fn copy_out(q: &VecDeque<u8>, skip: usize, buf: &mut [u8]) {
    let (a, b) = q.as_slices();
    let mut done = 0;
    if skip < a.len() {
        done = (a.len() - skip).min(buf.len());
        buf[..done].copy_from_slice(&a[skip..skip + done]);
    }
    if done < buf.len() {
        let s = skip + done - a.len();
        let n = buf.len() - done;
        buf[done..].copy_from_slice(&b[s..s + n]);
    }
}

/// What the retransmission timer is running for
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tmr {
    /// Unacknowledged data/SYN/FIN (RFC 6298)
    Rtx,
    /// Zero-window probe (persist)
    Probe,
}

/// Most out-of-order pieces kept: a peer sending many tiny scattered
/// segments cannot make insertion slow or the bookkeeping unbounded
/// (Linux prunes its ofo queue by truesize); later pieces are dropped
/// and come again with retransmissions
pub const OOO_MAX: usize = 256;
/// Bookkeeping charged per piece on top of its bytes (truesize-like)
pub const OOO_OVERHEAD: usize = 64;

/// Out-of-order receive data: disjoint pieces keyed by their offset from
/// `base` (a sequence number at or before RCV.NXT). Inserting copies only
/// the bytes not held yet (no re-concatenation), O(log n) per piece.
#[derive(Debug, Default)]
pub struct Ooo {
    base: u32,
    map: BTreeMap<u32, Vec<u8>>,
    bytes: usize,
}

impl Ooo {
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Bytes plus per-piece overhead, charged to the receive buffer
    pub fn truesize(&self) -> usize {
        self.bytes + self.map.len() * OOO_OVERHEAD
    }

    pub fn pieces(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn add(&mut self, off: u32, d: &[u8]) -> bool {
        if d.is_empty() {
            return true;
        }
        if self.map.len() >= OOO_MAX {
            return false;
        }
        self.bytes += d.len();
        self.map.insert(off, d.to_vec());
        true
    }

    /// Add `data` at `seq` (after `nxt`): only the parts not held yet
    pub fn insert(&mut self, nxt: u32, seq: u32, data: &[u8]) {
        if self.map.is_empty() {
            self.base = nxt;
        } else if nxt.wrapping_sub(self.base) > 1 << 30 {
            self.rebase(nxt);
        }
        let lo = seq.wrapping_sub(self.base);
        let hi = lo + data.len() as u32;
        let mut cur = lo;
        // The piece starting before `lo` may cover its beginning
        let first = self
            .map
            .range(..=lo)
            .next_back()
            .map(|(&s, d)| s + d.len() as u32);
        if let Some(end) = first {
            cur = cur.max(end);
        }
        let held: Vec<(u32, u32)> = self
            .map
            .range(lo..hi)
            .map(|(&s, d)| (s, s + d.len() as u32))
            .collect();
        for (s, e) in held {
            if s > cur && !self.add(cur, &data[(cur - lo) as usize..(s - lo) as usize]) {
                return;
            }
            cur = cur.max(e);
        }
        if cur < hi {
            self.add(cur, &data[(cur - lo) as usize..]);
        }
    }

    /// Re-key on `nxt` so offsets stay far from wrapping (pieces it
    /// passed are dropped)
    fn rebase(&mut self, nxt: u32) {
        let shift = nxt.wrapping_sub(self.base);
        let old = core::mem::take(&mut self.map);
        self.bytes = 0;
        self.base = nxt;
        for (s, d) in old {
            let skip = shift.saturating_sub(s) as usize;
            if skip < d.len() {
                self.bytes += d.len() - skip;
                self.map.insert(s + skip as u32 - shift, d[skip..].to_vec());
            }
        }
    }

    /// The first piece that reaches `nxt`, trimmed to start there;
    /// pieces `nxt` already passed are dropped on the way
    pub fn take(&mut self, nxt: u32) -> Option<Vec<u8>> {
        let at = nxt.wrapping_sub(self.base);
        loop {
            let (&s, _) = self.map.iter().next()?;
            if s > at {
                return None;
            }
            let d = self.map.remove(&s)?;
            self.bytes -= d.len();
            let skip = (at - s) as usize;
            if skip < d.len() {
                return Some(d[skip..].to_vec());
            }
        }
    }
}

/// The control block
pub struct TcpCb {
    pub state: TcpState,
    pub cfg: Cfg,

    // --- send sequence space (RFC 9293 3.3.1) -----------------------------
    pub iss: u32,
    pub snd_una: u32,
    /// Next sequence number to send (rewinds on retransmission timeout)
    pub snd_nxt: u32,
    /// Highest sequence number sent + 1
    pub snd_max: u32,
    pub snd_wnd: u32,
    pub(super) snd_wl1: u32,
    pub(super) snd_wl2: u32,
    /// Largest window the peer offered (RFC 5961 ACK range)
    pub(super) max_wnd: u32,
    /// Send queue: bytes from `sndq_seq` on (unacknowledged, then unsent)
    pub(super) sndq: VecDeque<u8>,
    pub(super) sndq_seq: u32,
    /// Send queue limit (from SO_SNDBUF)
    pub snd_cap: usize,
    /// The user closed the sending side: a FIN follows the queued data
    pub(super) fin_queued: bool,

    // --- receive sequence space -------------------------------------------
    pub irs: u32,
    pub rcv_nxt: u32,
    /// Right edge of the window last advertised (never moves left)
    pub(super) rcv_adv: u32,
    /// In-order bytes not yet read
    pub(super) rcvq: VecDeque<u8>,
    pub(super) ooo: Ooo,
    /// A FIN seen beyond a hole: its sequence number
    pub(super) ooo_fin: Option<u32>,
    /// Receive buffer limit (from SO_RCVBUF)
    pub rcv_cap: usize,
    /// No more data will be read (close or SHUT_RD): new data in
    /// FIN_WAIT_1/2 resets the connection (Linux tcp_rcv_state_process)
    pub rcv_shut: bool,

    // --- segment sizes ----------------------------------------------------
    /// Send MSS: min(peer's MSS option, path MTU - 40, TCP_MAXSEG)
    pub mss: u32,
    pub(super) peer_mss: u32,
    /// Path MTU - 40 (route, then ICMP frag needed)
    pub(super) path_mss: u32,
    /// MSS we advertise (our device MTU - 40)
    pub adv_mss: u32,
    /// TCP_MAXSEG (0 = none)
    pub user_mss: u32,

    // --- timers and RTT (RFC 6298) ----------------------------------------
    pub(super) srtt8: u64,
    pub(super) rttvar4: u64,
    pub(super) rto: u64,
    /// Consecutive timeouts / probes (exponential backoff)
    pub(super) backoff: u32,
    /// Zero-window probes without an answer
    pub(super) probes: u32,
    /// Karn: (sequence that must be acknowledged, send time)
    pub(super) rtt_seq: Option<(u32, u64)>,
    pub(super) syn_rtx: bool,
    pub(super) tmr: Option<(Tmr, u64)>,
    /// TIME_WAIT 2MSL or orphan FIN_WAIT_2 deadline
    pub(super) wait_at: Option<u64>,

    pub(super) cong: Cong,

    // --- misc -------------------------------------------------------------
    /// Closed by the user (no file refers to it any more)
    pub orphan: bool,
    /// Last ICMP error, reported if the connection times out
    pub soft_err: Option<KernelError>,
    /// An ACK must go out (pure ACK if no data segment carries it)
    pub(super) ack_now: bool,
    /// Bytes charged to the global TCP memory
    charged: usize,
}

impl TcpCb {
    /// A closed control block
    pub fn new(cfg: Cfg) -> Self {
        Self {
            state: TcpState::Closed,
            cfg,
            iss: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_max: 0,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            max_wnd: 0,
            sndq: VecDeque::new(),
            sndq_seq: 0,
            snd_cap: 64 * 1024,
            fin_queued: false,
            irs: 0,
            rcv_nxt: 0,
            rcv_adv: 0,
            rcvq: VecDeque::new(),
            ooo: Ooo::default(),
            ooo_fin: None,
            rcv_cap: 64 * 1024,
            rcv_shut: false,
            mss: MSS_DEFAULT,
            peer_mss: MSS_DEFAULT,
            path_mss: 65495,
            adv_mss: MSS_DEFAULT,
            user_mss: 0,
            srtt8: 0,
            rttvar4: 0,
            rto: RTO_INIT,
            backoff: 0,
            probes: 0,
            rtt_seq: None,
            syn_rtx: false,
            tmr: None,
            wait_at: None,
            cong: Cong::default(),
            orphan: false,
            soft_err: None,
            ack_now: false,
            charged: 0,
        }
    }

    /// Active open (Linux tcp_connect): send SYN with initial sequence
    /// `iss`; `mss` is what we advertise (route MTU - 40)
    pub fn connect(&mut self, iss: u32, mss: u32, now: u64, out: &mut Out) {
        self.iss = iss;
        self.snd_una = iss;
        self.snd_nxt = iss.wrapping_add(1);
        self.snd_max = self.snd_nxt;
        self.sndq_seq = self.snd_nxt;
        self.set_adv_mss(mss);
        self.state = TcpState::SynSent;
        self.rtt_seq = Some((self.snd_nxt, now));
        out.segs.push(self.syn_seg());
        self.arm_rtx(now);
    }

    /// Passive open: a child for a listener's SYN `syn`, in SYN_RECEIVED
    /// with its SYN-ACK queued (Linux tcp_conn_request +
    /// tcp_create_openreq_child); `bufs` = (receive, send) limits
    pub fn passive(
        cfg: Cfg,
        syn: &SegIn,
        iss: u32,
        mss: u32,
        bufs: (usize, usize),
        now: u64,
        out: &mut Out,
    ) -> Self {
        let mut cb = Self::new(cfg);
        (cb.rcv_cap, cb.snd_cap) = bufs;
        cb.iss = iss;
        cb.snd_una = iss;
        cb.snd_nxt = iss.wrapping_add(1);
        cb.snd_max = cb.snd_nxt;
        cb.sndq_seq = cb.snd_nxt;
        cb.set_adv_mss(mss);
        cb.syn_rcvd(syn);
        cb.state = TcpState::SynReceived;
        cb.rtt_seq = Some((cb.snd_nxt, now));
        out.segs.push(cb.syn_seg());
        cb.arm_rtx(now);
        cb
    }

    /// Record the peer's SYN: IRS, window, MSS option
    pub(super) fn syn_rcvd(&mut self, s: &SegIn) {
        self.irs = s.seq;
        self.rcv_nxt = s.seq.wrapping_add(1);
        self.rcv_adv = self.rcv_nxt;
        self.snd_wnd = s.wnd as u32;
        self.max_wnd = self.snd_wnd;
        self.snd_wl1 = s.seq;
        self.snd_wl2 = s.ack;
        self.peer_mss = s.mss.map_or(MSS_DEFAULT, |m| (m as u32).max(64));
        self.update_mss();
    }

    /// Our MSS from the route (device MTU - 40); also the path limit
    fn set_adv_mss(&mut self, mss: u32) {
        self.path_mss = mss.clamp(64, 65495);
        self.adv_mss = self.path_mss;
        if self.user_mss != 0 {
            self.adv_mss = self.adv_mss.min(self.user_mss);
        }
        self.update_mss();
    }

    /// Recompute the send MSS
    pub(super) fn update_mss(&mut self) {
        let mut m = self.peer_mss.min(self.path_mss);
        if self.user_mss != 0 {
            m = m.min(self.user_mss);
        }
        self.mss = m.max(64);
        self.cong.set_mss(self.mss);
    }

    /// The path MTU to the peer changed (ICMP frag needed): shrink the
    /// MSS and resend what is in flight in the new size (Linux
    /// tcp_v4_mtu_reduced -> tcp_simple_retransmit)
    pub fn pmtu(&mut self, mtu: u32, now: u64, out: &mut Out) {
        let m = mtu.saturating_sub(HDRS).max(68);
        if m >= self.mss {
            return;
        }
        self.path_mss = m;
        self.update_mss();
        if self.state.synced() && self.snd_nxt != self.snd_una {
            self.snd_nxt = self.snd_una;
            self.rtt_seq = None;
            self.output(now, out);
        }
    }

    // --- user calls --------------------------------------------------------

    /// Queue up to `data.len()` bytes for sending; returns how many fit
    /// (the caller calls `output`)
    pub fn send(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.snd_space());
        self.sndq.extend(&data[..n]);
        self.charge();
        n
    }

    /// Room in the send queue
    pub fn snd_space(&self) -> usize {
        self.snd_cap.saturating_sub(self.sndq.len()).min(mem_free())
    }

    /// Bytes queued for sending, sent or not (SIOCOUTQ)
    pub fn sndq_len(&self) -> usize {
        self.sndq.len()
    }

    /// Bytes sent but not acknowledged (SIOCOUTQNSD complement)
    pub fn unsent(&self) -> usize {
        self.sndq.len()
            - self
                .snd_max
                .wrapping_sub(self.sndq_seq)
                .min(self.sndq.len() as u32) as usize
    }

    /// Linux sk_stream_is_writeable: free space is at least half of what
    /// is queued
    pub fn writable(&self) -> bool {
        let free = self.snd_cap.saturating_sub(self.sndq.len());
        free > 0 && free * 2 >= self.sndq.len() && mem_free() > 0
    }

    /// Bytes readable
    pub fn rcvq_len(&self) -> usize {
        self.rcvq.len()
    }

    /// Copy (`take`: and consume) readable bytes at `skip` into `buf`;
    /// consuming may open the window: a window update goes out when it
    /// grew enough (Linux tcp_cleanup_rbuf)
    pub fn recv(&mut self, buf: &mut [u8], skip: usize, take: bool, out: &mut Out) -> usize {
        let n = buf.len().min(self.rcvq.len().saturating_sub(skip));
        copy_out(&self.rcvq, skip, &mut buf[..n]);
        if take && n > 0 {
            self.rcvq.drain(..skip + n);
            self.charge();
            self.cleanup_rbuf(out);
        }
        n
    }

    /// Drop `n` readable bytes (MSG_TRUNC reads)
    pub fn discard(&mut self, n: usize, out: &mut Out) -> usize {
        let n = n.min(self.rcvq.len());
        self.rcvq.drain(..n);
        self.charge();
        if n > 0 {
            self.cleanup_rbuf(out);
        }
        n
    }

    /// After reading: advertise a window that doubled (or opened from
    /// zero) right away
    fn cleanup_rbuf(&mut self, out: &mut Out) {
        if !matches!(
            self.state,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
        ) {
            return;
        }
        let cur = self.rcv_wnd();
        if 2 * cur > self.full_space() {
            return;
        }
        let new = self.window_now();
        if new != 0 && new >= 2 * cur {
            self.ack_now = true;
            self.send_ack(out);
        }
    }

    /// Close the sending side (shutdown(SHUT_WR) / close): FIN after the
    /// queued data (Linux tcp_close_state + tcp_send_fin). Returns false
    /// if there is nothing to close (Linux: no FIN in SYN_SENT/CLOSED).
    pub fn shutdown_wr(&mut self, now: u64, out: &mut Out) -> bool {
        let next = match self.state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::SynReceived => {
                // The FIN follows once the SYN is acknowledged
                self.fin_queued = true;
                return true;
            }
            TcpState::CloseWait => TcpState::LastAck,
            _ => return false,
        };
        self.state = next;
        self.fin_queued = true;
        self.output(now, out);
        true
    }

    /// The user closed the socket (Linux tcp_close): unread data or
    /// `linger0` (SO_LINGER {1, 0}) abort with RST, else close the
    /// sending side. The connection lives on as an orphan. A connection
    /// still in SYN_RECEIVED (simultaneous open) is reset instead of
    /// sending a FIN before its SYN is acknowledged.
    pub fn close(&mut self, linger0: bool, now: u64, out: &mut Out) {
        self.orphan = true;
        self.rcv_shut = true;
        let unread = !self.rcvq.is_empty();
        match self.state {
            TcpState::Listen | TcpState::SynSent | TcpState::Closed => self.set_closed(out),
            TcpState::TimeWait => {}
            _ if unread || linger0 || self.state == TcpState::SynReceived => self.abort(out),
            _ => {
                self.shutdown_wr(now, out);
                if self.state == TcpState::FinWait2 {
                    self.arm_fw2(now);
                }
            }
        }
    }

    /// Abort: RST to a synchronized peer, then CLOSED (Linux
    /// tcp_disconnect / tcp_send_active_reset)
    pub fn abort(&mut self, out: &mut Out) {
        if matches!(
            self.state,
            TcpState::SynReceived
                | TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
        ) {
            out.segs.push(Seg {
                seq: self.snd_max,
                ack: self.rcv_nxt,
                flags: flags::RST | flags::ACK,
                ..Default::default()
            });
        }
        self.set_closed(out);
    }

    /// Fail the connection with `err` (timeout, ICMP hard error)
    pub fn fail(&mut self, err: KernelError, out: &mut Out) {
        out.err = Some(err);
        self.set_closed(out);
    }

    /// Enter CLOSED (Linux tcp_done): queues and timers go, everyone wakes
    pub fn set_closed(&mut self, out: &mut Out) {
        self.state = TcpState::Closed;
        self.sndq.clear();
        self.ooo = Ooo::default();
        self.tmr = None;
        self.wait_at = None;
        self.charge();
        out.shut |= SHUTDOWN_MASK;
        out.wake = true;
        out.done = true;
    }

    /// Entering TIME_WAIT (2MSL); the glue hands it to a timewait entry
    pub(super) fn time_wait(&mut self, now: u64, out: &mut Out) {
        self.state = TcpState::TimeWait;
        self.tmr = None;
        self.sndq.clear();
        self.charge();
        self.wait_at = Some(now + TIMEWAIT_LEN);
        out.timewait = true;
        out.wake = true;
    }

    /// The TIME_WAIT part of this control block, without queues: what a
    /// timewait entry keeps (Linux tcp_timewait_sock)
    pub fn tw_clone(&self) -> TcpCb {
        let mut t = TcpCb::new(self.cfg);
        t.state = TcpState::TimeWait;
        t.iss = self.iss;
        t.snd_una = self.snd_una;
        t.snd_nxt = self.snd_nxt;
        t.snd_max = self.snd_max;
        t.snd_wnd = self.snd_wnd;
        t.max_wnd = self.max_wnd;
        t.snd_wl1 = self.snd_wl1;
        t.snd_wl2 = self.snd_wl2;
        t.sndq_seq = self.data_end();
        t.fin_queued = self.fin_queued;
        t.irs = self.irs;
        t.rcv_nxt = self.rcv_nxt;
        t.rcv_adv = self.rcv_adv;
        t.rcv_cap = self.rcv_cap;
        t.mss = self.mss;
        t.adv_mss = self.adv_mss;
        t.wait_at = self.wait_at;
        t
    }

    /// The socket's side after handing TIME_WAIT over: CLOSED, readable
    /// data kept
    pub fn tw_done(&mut self, out: &mut Out) {
        self.state = TcpState::Closed;
        self.tmr = None;
        self.wait_at = None;
        out.shut |= SHUTDOWN_MASK;
        out.wake = true;
    }

    /// Orphan in FIN_WAIT_2: give up after tcp_fin_timeout
    pub(super) fn arm_fw2(&mut self, now: u64) {
        if self.orphan {
            self.wait_at = Some(now + self.cfg.fin_timeout);
        }
    }

    // --- receive window ----------------------------------------------------

    /// Window space for the receive buffer (Linux tcp_full_space)
    pub(super) fn full_space(&self) -> u32 {
        (self.rcv_cap as u32).clamp(1, MAX_WINDOW)
    }

    /// Unused receive space (Linux tcp_space), also bounded by the
    /// global TCP memory
    fn free_space(&self) -> u32 {
        let used = self.rcvq.len() + self.ooo.truesize();
        let free = (self.full_space() as usize).saturating_sub(used);
        free.min(mem_free()) as u32
    }

    /// Window currently offered (Linux tcp_receive_window)
    pub fn rcv_wnd(&self) -> u32 {
        if before(self.rcv_adv, self.rcv_nxt) {
            0
        } else {
            self.rcv_adv.wrapping_sub(self.rcv_nxt)
        }
    }

    /// Window we would offer now (Linux __tcp_select_window without
    /// scaling): receiver SWS avoidance, multiples of the MSS
    fn window_now(&self) -> u32 {
        let full = self.full_space();
        let mss = self.adv_mss.min(full);
        let free = self.free_space();
        if free < full / 2 && (free < full / 16 || free < mss) {
            return 0;
        }
        let cur = self.rcv_wnd();
        if cur + mss <= free || cur > free {
            free / mss * mss
        } else if mss == full && free > cur + full / 2 {
            free
        } else {
            cur
        }
    }

    /// Window field for a segment; the offered right edge never moves
    /// left (Linux tcp_select_window)
    pub(super) fn select_window(&mut self) -> u16 {
        let w = self.window_now().max(self.rcv_wnd()).min(MAX_WINDOW);
        self.rcv_adv = self.rcv_nxt.wrapping_add(w);
        w as u16
    }

    // --- memory ------------------------------------------------------------

    /// Re-charge the global TCP memory for the current queue sizes
    pub(super) fn charge(&mut self) {
        let now = self.sndq.len() + self.rcvq.len() + self.ooo.truesize();
        if now >= self.charged {
            MEM.fetch_add(now - self.charged, Ordering::Relaxed);
        } else {
            MEM.fetch_sub(self.charged - now, Ordering::Relaxed);
        }
        self.charged = now;
    }

    // --- timers --------------------------------------------------------------

    /// Earliest deadline the caller must call `on_timer` at
    pub fn next_timer(&self) -> Option<u64> {
        match (self.tmr.map(|t| t.1), self.wait_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

impl Drop for TcpCb {
    fn drop(&mut self) {
        MEM.fetch_sub(self.charged, Ordering::Relaxed);
    }
}
