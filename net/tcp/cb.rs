//! The TCP control block (RFC 9293 TCB): an I/O-free state machine
//!
//! `TcpCb` holds the whole protocol state of one connection: the 11
//! RFC 9293 states, the send and receive sequence spaces, the queues as
//! Linux keeps them (skbs, each with its TCP control block `skb.tcp`:
//! the write queue of unsent data, the retransmit queue of sent and
//! unacknowledged segments, the receive queue and the out-of-order
//! queue), RTT/RTO estimation, congestion state and the timer
//! deadlines. It never transmits, sleeps or locks: user calls
//! (`connect`, `send`, `recv`, `close`, ...), segments (`input`, which
//! takes the received skb) and timer expiry (`on_timer`) only change
//! state and append what must happen to an [`Out`]: segments to send
//! (skbs, their header fields in `skb.tcp`), wakeups, errors, shutdown
//! bits, "done" (leave the tables) and timer changes (`next_timer`).
//! The socket glue (`tcp/mod.rs`) transmits them under the socket
//! lock and wakes after it; host unit tests (`tcp/tests.rs`) drive two control
//! blocks over a simulated lossy network with a virtual clock.
//!
//! Time is in milliseconds on any monotonic clock chosen by the caller.
//! Sequence numbers compare modulo 2^32 (`before`/`after`).
//!
//! Options (RFC 7323): window scaling and timestamps are negotiated on
//! the SYN/SYN-ACK; timestamps give RTT samples on every ACK of new data
//! and PAWS (`input.rs`). The TS clock is the caller's ms clock plus a
//! per-connection keyed offset (`Open.ts_off`, Linux
//! secure_tcp_seq_and_ts_off over the four-tuple). SACK (RFC 2018,
//! RFC 2883 D-SACK) is negotiated likewise (`sack.rs`).
//! Delayed ACKs live in `ack.rs`, Nagle/cork in `output.rs`, keepalive
//! and the user timeout in `time/timer.rs`.

use alloc::boxed::Box;
use alloc::sync::Arc;

use super::ack::Dack;
use super::cong::Cong;
use super::mem;
use super::recovery::{CaState, Rack};
use super::sack::Dsack;
use crate::mm::page_alloc::Gfp;
use crate::net::mib::*;
use crate::net::skb::{NUM_SACKS, Sacks, SkBuff, SkbHead, SkbTree};
use crate::sync::{SoleCell, Word};
use crate::util::error::KernelError;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpState {
    #[default]
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

    /// The state of Linux TCP_* number `v` (`linux()`'s inverse;
    /// anything else is CLOSED)
    pub fn from_linux(v: u8) -> Self {
        match v {
            1 => TcpState::Established,
            2 => TcpState::SynSent,
            3 => TcpState::SynReceived,
            4 => TcpState::FinWait1,
            5 => TcpState::FinWait2,
            6 => TcpState::TimeWait,
            8 => TcpState::CloseWait,
            9 => TcpState::LastAck,
            10 => TcpState::Listen,
            11 => TcpState::Closing,
            _ => TcpState::Closed,
        }
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

/// `TcpCb.sack_ok` bits (Linux TCP_SACK_SEEN, TCP_DSACK_SEEN)
pub const SACK_SEEN: u8 = 1;
pub const DSACK_SEEN: u8 = 4;

/// Default send MSS when the peer sends no MSS option (RFC 9293 3.7.1)
pub const MSS_DEFAULT: u32 = 536;
/// Smallest send MSS (Linux tcp_min_snd_mss)
pub const MSS_MIN: u32 = 48;
/// IPv4 + TCP header bytes (no options) per segment
pub const HDRS: u32 = 40;
/// Option bytes of a timestamp on a non-SYN segment (NOP NOP TS)
pub const TS_LEN: u32 = 12;
/// Largest window field
pub const MAX_WINDOW: u32 = 65535;
/// Largest window scale shift (RFC 7323 2.3)
pub const MAX_WSCALE: u8 = 14;
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
/// Linux tcp_invalid_ratelimit: at most one out-of-window / challenge
/// ACK per this many ms per connection
pub const OOW_RATELIMIT: u64 = 500;
/// Linux TCP_PAWS_WRAP (INT_MAX / USEC_PER_SEC s): TS.Recent older
/// than this (ms) is not trusted
pub const PAWS_WRAP: u64 = (i32::MAX as u64 / 1_000_000) * 1000;

/// Linux tcp_wmem[0] (4096) in hk's byte counts, which leave out
/// truesize overhead (half, as SO_SNDBUF): the send bytes a connection
/// may queue whatever the memory (tcp_wmem_schedule) and below the hard
/// limit (__sk_mem_raise_allocated); tcp_rmem[0] / 2 likewise
const WMEM_MIN: usize = 2048;

/// Which queue a charge is for (Linux SK_MEM_SEND / SK_MEM_RECV)
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum MemKind {
    Send,
    Recv,
}

/// Per-namespace knobs a connection uses (sysctls, read at creation)
#[derive(Clone, Copy, Debug)]
pub struct Cfg {
    pub syn_retries: u32,
    pub synack_retries: u32,
    pub retries2: u32,
    /// FIN_WAIT2 lifetime of an orphan (tcp_fin_timeout, ms)
    pub fin_timeout: u64,
    /// tcp_window_scaling
    pub wscale: bool,
    /// tcp_timestamps (0 off, 1 on with offset, 2 on without offset)
    pub ts: u8,
    /// tcp_sack: offer and accept SACK
    pub sack: bool,
    /// tcp_dsack: report duplicate segments in D-SACK blocks
    pub dsack: bool,
    /// tcp_reordering: initial reordering degree (packets);
    /// tcp_max_reordering: its bound
    pub reordering: u32,
    pub max_reordering: u32,
    /// tcp_recovery: RACK option bits (`recovery::RACK_*`)
    pub recovery: u8,
    /// tcp_rmem[0]: receive bytes a connection may always hold below
    /// the hard memory limit
    pub rmem_min: u32,
    /// tcp_rmem[2]: the receive space the window scale allows for
    pub rmem_max: u32,
    /// tcp_keepalive_time / _intvl (ms), tcp_keepalive_probes
    pub keepidle: u64,
    pub keepintvl: u64,
    pub keepcnt: u32,
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            syn_retries: 6,
            synack_retries: 5,
            retries2: 15,
            fin_timeout: 60_000,
            wscale: true,
            ts: 1,
            sack: true,
            dsack: true,
            reordering: 3,
            max_reordering: 300,
            recovery: 1,
            rmem_min: 4096,
            rmem_max: 6 * 1024 * 1024,
            keepidle: 7_200_000,
            keepintvl: 75_000,
            keepcnt: 9,
        }
    }
}

/// Per-socket TCP options (IPPROTO_TCP setsockopt, SO_KEEPALIVE),
/// inherited by a listener's children
#[derive(Clone, Copy, Debug, Default)]
pub struct Opts {
    /// TCP_NODELAY: no Nagle
    pub nodelay: bool,
    /// TCP_CORK: only full segments (partial ones after 200 ms)
    pub cork: bool,
    /// SO_KEEPALIVE
    pub keepalive: bool,
    /// TCP_KEEPIDLE / TCP_KEEPINTVL (s) and TCP_KEEPCNT; 0 = sysctl
    pub keepidle: u32,
    pub keepintvl: u32,
    pub keepcnt: u32,
    /// TCP_USER_TIMEOUT (ms; 0 = the retry counts decide)
    pub user_timeout: u32,
    /// TCP_MAXSEG (0 = none)
    pub user_mss: u32,
    /// TCP_SYNCNT (0 = sysctl)
    pub syncnt: u32,
    /// TCP_NOTSENT_LOWAT (0 = unlimited)
    pub notsent_lowat: u32,
    /// TCP_DEFER_ACCEPT (retransmissions; stored only)
    pub defer_accept: u8,
    /// TCP_CONGESTION (index into `cong::ALGOS`)
    pub ca: usize,
}

/// Per-connection values for opening (ISN, timestamp offset, our MSS)
#[derive(Clone, Copy, Debug, Default)]
pub struct Open {
    pub iss: u32,
    pub ts_off: u32,
    /// MSS we advertise: route MTU - 40
    pub mss: u32,
}

/// A segment's header fields and the sequence space it covers (Linux
/// struct tcp_skb_cb): the control block of every skb TCP queues,
/// receives or sends; addresses and ports of a segment to send are the
/// connection's
pub use crate::net::skb::TcpSkbCb as Seg;
/// A received segment's header, checksummed and parsed (its payload is
/// the skb's data)
pub type SegIn = Seg;

impl Seg {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    /// Sequence space occupied: data plus SYN and FIN
    pub fn seq_len(&self) -> u32 {
        self.end_seq.wrapping_sub(self.seq)
    }

    /// Payload bytes
    pub fn data_len(&self) -> u32 {
        self.seq_len() - u32::from(self.has(flags::SYN)) - u32::from(self.has(flags::FIN))
    }

    /// Set `end_seq` for `len` payload bytes and the flags
    pub fn set_len(&mut self, len: u32) {
        self.end_seq = self
            .seq
            .wrapping_add(len + u32::from(self.has(flags::SYN)) + u32::from(self.has(flags::FIN)));
    }
}

/// What a call into the control block asks the caller to do
pub struct Out {
    /// Segments to transmit, in order: skbs holding the payload with
    /// headroom for every header, the TCP header fields in `skb.tcp`
    /// (Linux: tcp_transmit_skb builds the header on the clone)
    pub segs: SkbHead<Box<SkBuff>>,
    /// The GFP segment buffers are allocated with (Linux passes it down
    /// to tcp_transmit_skb: GFP_ATOMIC from tcp_write_xmit, ACKs and
    /// retransmits; sk_allocation for connect's SYN)
    pub gfp: Gfp,
    /// Report this error (sk_err) and wake everyone
    pub err: Option<KernelError>,
    /// Socket shutdown bits to set (Linux sk_shutdown)
    pub shut: u8,
    /// Wakeups to make at the end of the locked step (`wake::*`)
    pub wake: u8,
    /// The connection is over (CLOSED): leave the tables
    pub done: bool,
    /// Entered TIME_WAIT: hand over to a timewait entry
    pub timewait: bool,
    /// The handshake completed (SYN_RECEIVED/SYN_SENT -> ESTABLISHED)
    pub established: bool,
    /// A request's completing ACK passed tcp_check_req, unprocessed: the
    /// socket layer makes it a full socket (its port, the accept queue)
    /// and feeds it again (Linux tcp_v4_syn_recv_sock,
    /// inet_csk_complete_hashdance, tcp_child_process)
    pub req_ack: Option<Box<SkBuff>>,
}

impl Default for Out {
    fn default() -> Self {
        Self {
            segs: SkbHead::new(),
            gfp: Gfp::ATOMIC,
            err: None,
            shut: 0,
            wake: 0,
            done: false,
            timewait: false,
            established: false,
            req_ack: None,
        }
    }
}

impl Out {
    /// Queue a header-only segment `h` (SYN, ACK, RST), its buffer
    /// allocated with `gfp`; false if that failed (the segment is lost,
    /// as after Linux's failed alloc_skb in tcp_send_ack)
    pub fn ctl(&mut self, mut h: Seg) -> bool {
        let Some(mut skb) = SkBuff::alloc_tx(0, self.gfp) else {
            return false;
        };
        h.set_len(0);
        skb.set_tcp(h);
        self.segs.push_back(skb);
        true
    }
}

/// What an `Out` wakes the socket for
pub mod wake {
    /// State change: everyone (Linux sk_state_change)
    pub const STATE: u8 = 1;
    /// Data to read (Linux tcp_data_ready)
    pub const DATA: u8 = 2;
    /// Room to write (Linux tcp_new_space)
    pub const SPACE: u8 = 4;
    /// With STATE: the connection is established (Linux
    /// tcp_finish_connect / tcp_rcv_state_process: SIGIO POLL_OUT)
    pub const EST: u8 = 8;
    /// With STATE: the peer's FIN arrived (Linux tcp_fin: SIGIO POLL_IN,
    /// POLL_HUP once both directions are shut)
    pub const FIN: u8 = 16;
    /// An error was set under the lock (Linux sk_error_report)
    pub const ERR: u8 = 32;
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

/// What the retransmission timer is running for
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tmr {
    /// Unacknowledged data/SYN/FIN (RFC 6298)
    Rtx,
    /// Zero-window probe (persist)
    Probe,
    /// RACK reordering window (Linux ICSK_TIME_REO_TIMEOUT)
    Reo,
    /// Tail loss probe (Linux ICSK_TIME_LOSS_PROBE)
    LossProbe,
}

/// The kind in the top three bits (0: none), the deadline (ms) below
impl Word for Option<(Tmr, u64)> {
    fn pack(self) -> u64 {
        match self {
            None => 0,
            Some((k, t)) => {
                let k = match k {
                    Tmr::Rtx => 1,
                    Tmr::Probe => 2,
                    Tmr::Reo => 3,
                    Tmr::LossProbe => 4,
                };
                k << 61 | t.min(TMR_AT)
            }
        }
    }

    fn unpack(w: u64) -> Self {
        let t = w & TMR_AT;
        match w >> 61 {
            1 => Some((Tmr::Rtx, t)),
            2 => Some((Tmr::Probe, t)),
            3 => Some((Tmr::Reo, t)),
            4 => Some((Tmr::LossProbe, t)),
            _ => None,
        }
    }
}

/// The deadline bits of a packed `Tmr`
const TMR_AT: u64 = (1 << 61) - 1;

/// The control block's fields /proc/net/tcp reads with no lock (Linux
/// get_tcp4_sock's racy reads: icsk_pending and icsk_timeout, the
/// keepalive timer, icsk_backoff, icsk_probes_out, icsk_rto, icsk_ack
/// ato / quick / pingpong, snd_cwnd, snd_ssthresh, mss_cache,
/// fastopenq.max_qlen). They are the block's own fields, not copies,
/// kept apart from it so a reader may load them while the socket
/// lock's holder stores them: the socket shares this with its block
/// (`TcpSock.live`), and the block with its `Cong`. One writer: the block's holder.
#[derive(Debug, Default)]
pub struct Live {
    /// The retransmit or zero-window probe timer and its deadline
    pub(super) tmr: SoleCell<Option<(Tmr, u64)>>,
    /// TIME_WAIT 2MSL or orphan FIN_WAIT_2 deadline
    pub(super) wait_at: SoleCell<Option<u64>>,
    /// Keepalive deadline
    pub(super) keep_at: SoleCell<Option<u64>>,
    /// RTO before backoff (ms)
    pub(super) rto: SoleCell<u64>,
    /// Consecutive timeouts / probes (exponential backoff)
    pub(super) backoff: SoleCell<u32>,
    /// Retransmission timeouts since SND.UNA last moved (Linux
    /// icsk_retransmits): what tcp_write_timeout counts; a shrunk-window
    /// probe is not one
    pub(super) retransmits: SoleCell<u32>,
    /// Zero-window or keepalive probes without an answer
    pub(super) probes: SoleCell<u32>,
    /// Send MSS: payload per segment (min(peer's MSS option, path MTU -
    /// 40, TCP_MAXSEG) less option bytes)
    pub(super) mss: SoleCell<u32>,
    /// Delayed ACK (Linux icsk_ack): ACKs left to send at once
    /// (quickack mode), interactive (replies follow data, ACKs ride on
    /// them), the adaptive delay (ms; 0 until data arrives)
    pub(super) quick: SoleCell<u32>,
    pub(super) pingpong: SoleCell<bool>,
    pub(super) ato: SoleCell<u64>,
    /// `Cong`'s window and slow start threshold (bytes)
    pub(super) cwnd: SoleCell<u32>,
    pub(super) ssthresh: SoleCell<u32>,
    /// TCP_FASTOPEN queue length (stored only: no TFO). The socket's,
    /// not the connection's (Linux fastopenq, in the accept queue): a
    /// new block keeps it, a listener's child starts at 0
    pub(super) fastopen: SoleCell<u32>,
}

impl Live {
    /// A new connection's values; `fastopen` stays (`TcpCb::new`, then
    /// `Cong::new`)
    fn reset(&self) {
        self.tmr.set(None);
        self.wait_at.set(None);
        self.keep_at.set(None);
        self.rto.set(RTO_INIT);
        self.backoff.set(0);
        self.retransmits.set(0);
        self.probes.set(0);
        self.mss.set(MSS_DEFAULT);
        self.quick.set(0);
        self.pingpong.set(false);
        self.ato.set(0);
    }
}

/// Most out-of-order pieces kept: a peer sending many tiny scattered
/// segments cannot make insertion slow or the bookkeeping unbounded
/// (Linux prunes its ofo queue by truesize); later pieces are dropped
/// and come again with retransmissions
pub const OOO_MAX: usize = 256;
/// Bookkeeping charged per piece on top of its bytes (truesize-like)
pub const OOO_OVERHEAD: usize = 64;

/// The out-of-order queue (Linux tp->out_of_order_queue): received
/// skbs beyond RCV.NXT in an rbtree by sequence number, linked through
/// their own `rb` node, so queueing allocates nothing (Linux
/// tcp_data_queue_ofo). An skb wholly inside one held already is
/// dropped; one starting where another starts and reaching past it
/// replaces it, and the ones it covers after it go; partial overlaps
/// stay and are trimmed as they reach RCV.NXT (tcp_ofo_queue).
#[derive(Default)]
pub struct Ooo {
    tree: SkbTree,
    /// Payload bytes held
    bytes: usize,
    /// Skbs dropped as covered since the owner last looked (Linux
    /// TCPOFOMerge)
    pub(super) merged: u64,
}

/// `skb`'s payload end (its `end_seq` less a FIN)
fn data_end(skb: &SkBuff) -> u32 {
    skb.tcp().seq.wrapping_add(skb.len() as u32)
}

impl Ooo {
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Bytes plus per-piece overhead, charged to the receive buffer
    pub fn truesize(&self) -> usize {
        self.bytes + self.tree.len() * OOO_OVERHEAD
    }

    pub fn pieces(&self) -> usize {
        self.tree.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Queue `skb` (payload at `skb.tcp.seq`, beyond RCV.NXT; Linux
    /// tcp_data_queue_ofo). Duplicate bytes go into `d` (Linux
    /// tcp_dsack_set / tcp_dsack_extend: wholly covered, a partial
    /// overlap with the one before, the ones it covers); returns what
    /// became of it and how many D-SACK blocks were started (each a
    /// TCPDSACKOfoSent)
    pub fn insert(&mut self, skb: Box<SkBuff>, mut d: Option<&mut Dsack>) -> (Ins, u64) {
        let (seq, end) = (skb.tcp().seq, data_end(&skb));
        let mut sets = 0;
        let mut c = self.tree.cursor_floor_mut(|x| !after(x.tcp().seq, seq));
        if let Some(prev) = c.current() {
            let pend = data_end(prev);
            if !after(end, pend) {
                // Wholly inside one held: drop
                self.merged += 1;
                if let Some(d) = d.as_deref_mut() {
                    d.on = false;
                    sets += u64::from(d.extend(seq, end));
                }
                return (Ins::Covered, sets);
            }
            if prev.tcp().seq == seq {
                // It covers `prev` (Linux rb_replace_node)
                let pseq = prev.tcp().seq;
                let len = skb.len();
                let old = c.replace_current(skb);
                self.bytes = self.bytes + len - old.len();
                self.merged += 1;
                if let Some(d) = d.as_deref_mut() {
                    sets += u64::from(d.extend(pseq, pend));
                }
                sets += self.drop_covered(seq, end, d);
                return (Ins::Queued, sets);
            }
            if before(seq, pend) {
                // Partial overlap with the one before
                if let Some(d) = d.as_deref_mut() {
                    d.on = false;
                    sets += u64::from(d.extend(seq, pend));
                }
            }
        }
        if self.tree.len() >= OOO_MAX {
            return (Ins::Full, sets);
        }
        self.bytes += skb.len();
        self.tree
            .insert_by(skb, |a, b| before(a.tcp().seq, b.tcp().seq));
        sets += self.drop_covered(seq, end, d);
        (Ins::Queued, sets)
    }

    /// Remove the skbs after the one at `seq` that [`seq`, `end`)
    /// covers, their bytes D-SACKed, and D-SACK the overlap with the
    /// first it does not cover (Linux tcp_data_queue_ofo merge_right)
    fn drop_covered(&mut self, seq: u32, end: u32, mut d: Option<&mut Dsack>) -> u64 {
        let mut sets = 0;
        let mut c = self.tree.cursor_floor_mut(|x| !after(x.tcp().seq, seq));
        c.move_next();
        while let Some(n) = c.current() {
            let (nseq, nend) = (n.tcp().seq, data_end(n));
            if !after(end, nseq) {
                break;
            }
            if after(nend, end) {
                if let Some(d) = d.as_deref_mut() {
                    sets += u64::from(d.extend(nseq, end));
                }
                break;
            }
            if let Some(gone) = c.remove_current() {
                self.bytes -= gone.len();
                self.merged += 1;
            }
            if let Some(d) = d.as_deref_mut() {
                sets += u64::from(d.extend(nseq, nend));
            }
        }
        sets
    }

    /// Drop the last skb if it lies after `seq`: true if one went
    /// (Linux tcp_prune_ofo_queue, from the highest sequence down)
    pub fn prune_after(&mut self, seq: u32) -> bool {
        let mut c = self.tree.cursor_back_mut();
        match c.current() {
            Some(l) if after(l.tcp().seq, seq) => {}
            _ => return false,
        }
        if let Some(gone) = c.remove_current() {
            self.bytes -= gone.len();
        }
        true
    }

    /// The first skb that reaches `nxt`, its payload trimmed to start
    /// there; skbs `nxt` already passed are dropped on the way (Linux
    /// tcp_ofo_queue). Bytes of each below `high` (RCV.NXT before the
    /// walk) are D-SACKed into `d`; returns how many blocks that started
    pub fn take(
        &mut self,
        nxt: u32,
        high: u32,
        mut d: Option<&mut Dsack>,
    ) -> (Option<Box<SkBuff>>, u64) {
        let mut sets = 0;
        loop {
            let Some(first) = self.tree.first() else {
                return (None, sets);
            };
            if after(first.tcp().seq, nxt) {
                return (None, sets);
            }
            let Some(mut skb) = self.tree.pop_first() else {
                return (None, sets);
            };
            self.bytes -= skb.len();
            let (seq, end) = (skb.tcp().seq, data_end(&skb));
            if before(seq, high)
                && let Some(d) = d.as_deref_mut()
            {
                let e = if before(end, high) { end } else { high };
                sets += u64::from(d.extend(seq, e));
            }
            if after(end, nxt) {
                let skip = nxt.wrapping_sub(seq) as usize;
                let _ = skb.pull(skip);
                skb.tcp_mut().seq = nxt;
                return (Some(skb), sets);
            }
        }
    }
}

/// What became of an skb offered to the out-of-order queue
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ins {
    Queued,
    /// Its bytes were all held already
    Covered,
    /// Dropped: `OOO_MAX` pieces held
    Full,
}

/// The control block
pub struct TcpCb {
    pub state: TcpState,
    pub cfg: Cfg,
    pub opts: Opts,

    // --- send sequence space (RFC 9293 3.3.1) -----------------------------
    pub iss: u32,
    pub snd_una: u32,
    /// Next sequence number to send (Linux snd_nxt: never moves back)
    pub snd_nxt: u32,
    /// Highest sequence number sent + 1
    pub snd_max: u32,
    /// Peer's window in bytes (scaled)
    pub snd_wnd: u32,
    pub(super) snd_wl1: u32,
    pub(super) snd_wl2: u32,
    /// Largest window the peer offered (RFC 5961 ACK range)
    pub(super) max_wnd: u32,
    /// Unsent data (Linux sk_write_queue): skbs of up to an MSS each,
    /// filled by the sender
    pub(super) wq: SkbHead<Box<SkBuff>>,
    /// Sent, unacknowledged segments by sequence (Linux tcp_rtx_queue)
    pub(super) rtx: SkbTree,
    /// End of the data queued (Linux write_seq; the FIN is after it)
    pub(super) write_seq: u32,
    /// Send queue limit (from SO_SNDBUF)
    pub snd_cap: usize,
    /// The user closed the sending side: a FIN follows the queued data
    pub(super) fin_queued: bool,
    /// End of the last segment shorter than the MSS (Nagle, Minshall)
    pub(super) snd_sml: u32,

    // --- receive sequence space -------------------------------------------
    pub irs: u32,
    pub rcv_nxt: u32,
    /// Right edge of the window last advertised (never moves left)
    pub(super) rcv_adv: u32,
    /// RCV.NXT when that window was sent (RFC 7323 Last.ACK.sent)
    pub(super) rcv_wup: u32,
    /// In-order data not yet read (Linux sk_receive_queue): skbs from
    /// `copied_seq` on (the first may start before it)
    pub(super) rcvq: SkbHead<Box<SkBuff>>,
    /// The next byte the reader takes (Linux copied_seq)
    pub(super) copied_seq: u32,
    /// Bytes readable: RCV.NXT - copied_seq, less a received FIN
    pub(super) rcv_bytes: usize,
    pub(super) ooo: Ooo,
    /// A FIN seen beyond a hole: its sequence number
    pub(super) ooo_fin: Option<u32>,
    /// Receive buffer limit (from SO_RCVBUF)
    pub rcv_cap: usize,
    /// SO_RCVBUF was set: the window scale follows it (Linux
    /// SOCK_RCVBUF_LOCK)
    pub rcv_locked: bool,
    /// No more data will be read (close or SHUT_RD): new data in
    /// FIN_WAIT_1/2 resets the connection (Linux tcp_rcv_state_process)
    pub rcv_shut: bool,

    // --- options (RFC 7323) ------------------------------------------------
    /// Window scale shifts: the peer's (applied to its window field)
    /// and ours; 0 unless both SYNs carried the option
    pub snd_wscale: u8,
    pub rcv_wscale: u8,
    pub wscale_ok: bool,
    /// Timestamps negotiated
    pub ts_ok: bool,
    /// SACK negotiated (Linux rx_opt.sack_ok: `SACK_SEEN`, plus
    /// `DSACK_SEEN` once the peer sent a D-SACK); before the handshake
    /// completes, whether we offer or accept it
    pub sack_ok: u8,
    /// Out-of-order data reported to the peer, the newest block first
    /// (Linux selective_acks, rx_opt.num_sacks)
    pub(super) selective_acks: Sacks,
    /// A duplicate to report once (Linux rx_opt.dsack, duplicate_sack)
    pub(super) dsack: Dsack,
    /// TSval = clock + ts_off
    pub(super) ts_off: u32,
    /// TS.Recent and the clock when it was stored
    pub(super) ts_recent: u32,
    pub(super) ts_stamp: u64,
    /// Latest clock value seen (ms; stamps segments built without `now`)
    pub(super) clock: u64,

    // --- segment sizes (the send MSS is `live.mss`) ------------------------
    pub(super) peer_mss: u32,
    /// Path MTU - 40 (route, then ICMP frag needed)
    pub(super) path_mss: u32,
    /// MSS we advertise (our device MTU - 40)
    pub adv_mss: u32,

    // --- timers and RTT (RFC 6298) ----------------------------------------
    pub(super) srtt8: u64,
    pub(super) rttvar4: u64,
    /// Karn: (sequence that must be acknowledged, send time)
    pub(super) rtt_seq: Option<(u32, u64)>,
    pub(super) syn_rtx: bool,
    /// Our SYN is not yet acknowledged (Linux: the SYN skb heads the
    /// retransmit queue): a retransmission resends the SYN or SYN-ACK,
    /// in FIN_WAIT_1 too after a close in SYN_RECEIVED
    pub(super) syn_unacked: bool,
    /// A listener's child: in SYN_RECEIVED it is Linux's request sock
    /// (tcp_check_req rules), not a simultaneous open
    pub(super) passive: bool,
    /// The listener made this request a full socket (Linux: the child
    /// sock exists, tcp_v4_syn_recv_sock): its completing ACK is
    /// processed as tcp_child_process does
    pub(super) req_full: bool,
    /// When the oldest unacknowledged data was (about) first sent, once
    /// retransmitting or probing (Linux retrans_stamp; TCP_USER_TIMEOUT)
    pub(super) rtx_stamp: Option<u64>,
    /// Last ACK received / last data sent (keepalive, cwnd restart)
    pub(super) rcv_tstamp: u64,
    pub(super) lsndtime: u64,

    pub(super) cong: Cong,

    // --- loss recovery (Linux tcp_sock, tcp_input.c; `recovery.rs`) -------
    /// Packets sent and not cumulatively acknowledged, of them SACKed
    /// (without SACK: duplicate ACKs), marked lost and retransmitted
    /// (Linux packets_out, sacked_out, lost_out, retrans_out)
    pub(super) packets_out: u32,
    pub(super) sacked_out: u32,
    pub(super) lost_out: u32,
    pub(super) retrans_out: u32,
    /// Packets delivered and marked lost, ever (Linux delivered, lost)
    pub(super) delivered: u32,
    pub(super) lost: u32,
    /// Reordering degree (packets) and times seen (Linux reordering,
    /// reord_seen)
    pub(super) reordering: u32,
    pub(super) reord_seen: u32,
    /// Congestion state (Linux icsk_ca_state)
    pub(super) ca_state: CaState,
    /// SND.NXT when the recovery or loss episode began (Linux high_seq)
    pub(super) high_seq: u32,
    /// Undo (Linux undo_marker, None for 0; undo_retrans; prior_ssthresh,
    /// 0 for none; prior_cwnd), windows in packets
    pub(super) undo_marker: Option<u32>,
    pub(super) undo_retrans: i32,
    pub(super) prior_ssthresh: u32,
    pub(super) prior_cwnd: u32,
    /// Proportional rate reduction (Linux prr_delivered, prr_out)
    pub(super) prr_delivered: u32,
    pub(super) prr_out: u32,
    /// Where retransmission resumes: the seq of that skb (Linux
    /// retransmit_skb_hint)
    pub(super) rtx_hint: Option<u32>,
    /// The skb after the highest SACKed one, by seq; None: past the
    /// queue (Linux highest_sack)
    pub(super) highest_sack: Option<u32>,
    /// RACK loss detection state (Linux rack)
    pub(super) rack: Rack,
    /// SND.NXT after a loss probe went out, until its episode ends
    /// (Linux tlp_high_seq, None for 0)
    pub(super) tlp_high_seq: Option<u32>,
    /// Data transmissions so far: the send order of each (`tx_order`)
    pub(super) tx_count: u64,
    /// Duplicates the peer D-SACKed (Linux dsack_dups)
    pub(super) dsack_dups: u32,
    /// The last ACK's SACK blocks, sorted, at the end (Linux
    /// recv_sack_cache)
    pub(super) recv_sack_cache: [(u32, u32); NUM_SACKS],
    /// The receiver reneged on SACKs; until the loss is recovered from
    /// (Linux is_sack_reneg)
    pub(super) is_sack_reneg: bool,
    /// The ACK being processed echoed this TSval (Linux
    /// rx_opt.saw_tstamp and rcv_tsecr)
    pub(super) rcv_tsecr: Option<u32>,
    /// Delayed ACK state
    pub(super) dack: Dack,
    /// The fields /proc/net/tcp reads with no lock: timers, RTO and
    /// backoff, probes, MSS, the delayed ACK mode, cwnd / ssthresh
    pub live: Arc<Live>,

    // --- misc -------------------------------------------------------------
    /// Closed by the user (no file refers to it any more)
    pub orphan: bool,
    /// Last ICMP error, reported if the connection times out
    pub soft_err: Option<KernelError>,
    /// An ACK must go out now (pure ACK if no data segment carries it)
    pub(super) ack_now: bool,
    /// In-order data was dropped for memory: the next ACK offers a zero
    /// window (Linux ICSK_ACK_NOMEM)
    pub(super) ack_nomem: bool,
    /// When the last out-of-window / challenge ACK went out
    pub(super) last_oow: Option<u64>,
    /// Counters (TCP_INFO)
    pub(super) stats: Stats,
    /// Quanta held in the global TCP memory; counts the socket too
    held: mem::Held,
    /// The namespace's MIBs, counted in as Linux counts in
    /// sock_net(sk)->mib (None: not counted, unit tests)
    pub mib: Option<Arc<NetMib>>,
}

/// Counters for TCP_INFO; the u32 ones wrap, as Linux tcp_info's
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub total_retrans: u32,
    pub segs_out: u32,
    pub segs_in: u32,
    pub data_segs_out: u32,
    pub data_segs_in: u32,
    pub bytes_acked: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub bytes_retrans: u64,
    pub last_data_recv: u64,
    pub rto_count: u32,
    /// Smallest RTT sample (ms)
    pub min_rtt: Option<u64>,
}

impl TcpCb {
    /// A closed control block, its lockless fields in `live` (reset,
    /// but for the socket's own: see `Live`)
    pub fn new(cfg: Cfg, live: Arc<Live>) -> Self {
        live.reset();
        Self {
            state: Default::default(),
            cfg,
            opts: Default::default(),
            iss: Default::default(),
            snd_una: Default::default(),
            snd_nxt: Default::default(),
            snd_max: Default::default(),
            snd_wnd: Default::default(),
            snd_wl1: Default::default(),
            snd_wl2: Default::default(),
            max_wnd: Default::default(),
            wq: Default::default(),
            rtx: Default::default(),
            write_seq: Default::default(),
            snd_cap: 64 * 1024,
            fin_queued: Default::default(),
            snd_sml: Default::default(),
            irs: Default::default(),
            rcv_nxt: Default::default(),
            rcv_adv: Default::default(),
            rcv_wup: Default::default(),
            rcvq: Default::default(),
            copied_seq: Default::default(),
            rcv_bytes: Default::default(),
            ooo: Default::default(),
            ooo_fin: Default::default(),
            rcv_cap: 64 * 1024,
            rcv_locked: Default::default(),
            rcv_shut: Default::default(),
            snd_wscale: Default::default(),
            rcv_wscale: Default::default(),
            wscale_ok: Default::default(),
            ts_ok: Default::default(),
            sack_ok: Default::default(),
            selective_acks: Default::default(),
            dsack: Default::default(),
            ts_off: Default::default(),
            ts_recent: Default::default(),
            ts_stamp: Default::default(),
            clock: Default::default(),
            peer_mss: MSS_DEFAULT,
            path_mss: 65495,
            adv_mss: MSS_DEFAULT,
            srtt8: Default::default(),
            rttvar4: Default::default(),
            rtt_seq: Default::default(),
            syn_rtx: Default::default(),
            syn_unacked: Default::default(),
            passive: Default::default(),
            req_full: Default::default(),
            rtx_stamp: Default::default(),
            rcv_tstamp: Default::default(),
            lsndtime: Default::default(),
            cong: Cong::new(live.clone()),
            packets_out: 0,
            sacked_out: 0,
            lost_out: 0,
            retrans_out: 0,
            delivered: 0,
            lost: 0,
            reordering: cfg.reordering,
            reord_seen: 0,
            ca_state: CaState::Open,
            high_seq: 0,
            undo_marker: None,
            undo_retrans: -1,
            prior_ssthresh: 0,
            prior_cwnd: 0,
            prr_delivered: 0,
            prr_out: 0,
            rtx_hint: None,
            highest_sack: None,
            rack: Rack::default(),
            tlp_high_seq: None,
            tx_count: 0,
            dsack_dups: 0,
            recv_sack_cache: [(0, 0); NUM_SACKS],
            is_sack_reneg: false,
            rcv_tsecr: None,
            dack: Default::default(),
            orphan: Default::default(),
            soft_err: Default::default(),
            ack_now: Default::default(),
            ack_nomem: Default::default(),
            last_oow: Default::default(),
            stats: Default::default(),
            held: Default::default(),
            mib: Default::default(),
            live,
        }
    }

    /// Advance the clock (every entry point with a time calls this)
    pub(super) fn tick(&mut self, now: u64) {
        self.clock = self.clock.max(now);
    }

    /// Our current TSval
    pub(super) fn tsval(&self) -> u32 {
        (self.clock as u32).wrapping_add(self.ts_off)
    }

    /// Common setup of both opens
    fn open(&mut self, o: &Open, now: u64) {
        self.tick(now);
        self.iss = o.iss;
        self.snd_una = o.iss;
        self.snd_nxt = o.iss.wrapping_add(1);
        self.snd_max = self.snd_nxt;
        self.write_seq = self.snd_nxt;
        self.syn_unacked = true;
        self.ts_off = if self.cfg.ts == 1 { o.ts_off } else { 0 };
        self.cong.set_algo(self.opts.ca);
        self.set_adv_mss(o.mss);
        self.rtt_seq = Some((self.snd_nxt, now));
        self.rcv_tstamp = now;
        self.lsndtime = now;
    }

    /// Active open (Linux tcp_connect): send SYN with our MSS, window
    /// scale and timestamp options as the sysctls allow
    pub fn connect(&mut self, o: Open, now: u64, out: &mut Out) {
        self.open(&o, now);
        self.wscale_ok = self.cfg.wscale;
        self.rcv_wscale = if self.wscale_ok {
            self.pick_wscale()
        } else {
            0
        };
        self.ts_ok = self.cfg.ts != 0;
        self.sack_ok = if self.cfg.sack { SACK_SEEN } else { 0 };
        self.set_state(TcpState::SynSent);
        if self.syn_seg(out) {
            self.tcp_stat(TCP_MIB_OUTSEGS);
        }
        self.tcp_stat(TCP_MIB_ACTIVEOPENS);
        self.arm_rtx(now);
    }

    /// Passive open: become a listener's child for its SYN `syn`, in
    /// SYN_RECEIVED with the SYN-ACK queued (Linux tcp_conn_request +
    /// tcp_create_openreq_child); options are those of the SYN that the
    /// sysctls allow
    pub fn passive(&mut self, syn: &SegIn, o: Open, now: u64, out: &mut Out) {
        self.open(&o, now);
        self.wscale_ok = self.cfg.wscale && syn.ws.is_some();
        self.ts_ok = self.cfg.ts != 0 && syn.ts.is_some();
        self.sack_ok = if self.cfg.sack && syn.sack_perm {
            SACK_SEEN
        } else {
            0
        };
        self.syn_rcvd(syn, now);
        self.set_state(TcpState::SynReceived);
        self.passive = true;
        if self.syn_seg(out) {
            self.tcp_stat(TCP_MIB_OUTSEGS);
        }
        self.arm_rtx(now);
    }

    /// Record the peer's SYN: IRS, window, options (`wscale_ok`,
    /// `ts_ok` and `sack_ok` hold what we offered or accept)
    pub(super) fn syn_rcvd(&mut self, s: &SegIn, now: u64) {
        self.irs = s.seq;
        self.rcv_nxt = s.seq.wrapping_add(1);
        self.copied_seq = self.rcv_nxt;
        self.rcv_adv = self.rcv_nxt;
        self.rcv_wup = self.rcv_nxt;
        self.snd_wnd = u32::from(s.wnd);
        self.max_wnd = self.snd_wnd;
        self.snd_wl1 = s.seq;
        self.snd_wl2 = s.ack;
        self.peer_mss = s.mss.map_or(MSS_DEFAULT, |m| u32::from(m).max(64));
        match s.ws {
            Some(w) if self.wscale_ok => {
                self.snd_wscale = w.min(MAX_WSCALE);
                if self.state != TcpState::SynSent {
                    self.rcv_wscale = self.pick_wscale();
                }
            }
            _ => {
                self.wscale_ok = false;
                self.snd_wscale = 0;
                self.rcv_wscale = 0;
            }
        }
        match s.ts {
            Some((v, _)) if self.ts_ok => {
                self.ts_recent = v;
                self.ts_stamp = now;
            }
            _ => self.ts_ok = false,
        }
        if !s.sack_perm {
            self.sack_ok = 0;
        }
        self.update_mss();
        self.dack
            .init(self.adv_mss.min(self.live.mss.get()), self.rcv_cap as u32);
    }

    /// Our window scale (Linux tcp_select_initial_window): enough for
    /// tcp_rmem[2] (or the SO_RCVBUF-fixed buffer) in a 16-bit field
    fn pick_wscale(&self) -> u8 {
        let space = if self.rcv_locked {
            self.rcv_cap as u32
        } else {
            (self.rcv_cap as u32).max(self.cfg.rmem_max)
        };
        let log = 31 - space.max(1).leading_zeros();
        log.saturating_sub(15).min(u32::from(MAX_WSCALE)) as u8
    }

    /// Our MSS from the route (device MTU - 40); also the path limit
    fn set_adv_mss(&mut self, mss: u32) {
        self.path_mss = mss.clamp(64, 65495);
        self.adv_mss = self.path_mss;
        if self.opts.user_mss != 0 {
            self.adv_mss = self.adv_mss.min(self.opts.user_mss);
        }
        self.update_mss();
    }

    /// Option bytes on every non-SYN segment
    pub(super) fn opt_len(&self) -> u32 {
        if self.ts_ok { TS_LEN } else { 0 }
    }

    /// Recompute the send MSS (Linux tcp_sync_mss: the peer's and the
    /// user's clamp, then the option bytes come off)
    pub(super) fn update_mss(&mut self) {
        let mut m = self.peer_mss.min(self.path_mss);
        if self.opts.user_mss != 0 {
            m = m.min(self.opts.user_mss);
        }
        self.live
            .mss
            .set(m.saturating_sub(self.opt_len()).max(MSS_MIN));
        self.cong.set_mss(self.live.mss.get());
    }

    /// The path MTU to the peer changed (ICMP frag needed): shrink the
    /// MSS and resend what is in flight in the new size (Linux
    /// tcp_v4_mtu_reduced -> tcp_simple_retransmit)
    pub fn pmtu(&mut self, mtu: u32, now: u64, out: &mut Out) {
        let m = mtu.saturating_sub(HDRS).max(68);
        if m >= self.path_mss {
            return;
        }
        let old = self.live.mss.get();
        self.path_mss = m;
        self.update_mss();
        if self.live.mss.get() < old && self.state.synced() && self.packets_out != 0 {
            self.tick(now);
            self.simple_retransmit(out);
        }
    }

    // --- user calls --------------------------------------------------------

    /// Queue up to `max` bytes for sending, filled in place by `fill`
    /// (Linux tcp_sendmsg_locked; the caller calls `output`): into the
    /// tail skb of the write queue while it has room, then into new ones
    /// of one MSS (tcp_stream_alloc_skb with sk_allocation: socket calls
    /// own the socket, nothing atomic). `fill` gets each skb's new tail
    /// and returns the bytes it stored there, short or Err after a
    /// fault. Returns the bytes queued (0: no room or no memory), Err if
    /// a fault left none; what `fill` did not store is taken back.
    pub fn send_with(
        &mut self,
        max: usize,
        mut fill: impl FnMut(&mut [u8]) -> Result<usize, KernelError>,
    ) -> Result<usize, KernelError> {
        let n = self.wmem_schedule(max.min(self.snd_space()));
        let (mut done, mut err, mut short) = (0, None, false);
        while done < n {
            let Some(mut skb) = self.wq_tail() else {
                break;
            };
            let k = (n - done).min(skb.tailroom());
            let got = match skb.put(k).map(&mut fill) {
                Some(Ok(g)) => g.min(k),
                Some(Err(e)) => {
                    err = Some(e);
                    0
                }
                None => 0,
            };
            if got < k {
                let _ = skb.trim(k - got);
            }
            skb.tcp_mut().end_seq = skb.tcp().end_seq.wrapping_add(got as u32);
            self.write_seq = self.write_seq.wrapping_add(got as u32);
            done += got;
            if !skb.is_empty() {
                self.wq.push_back(skb);
            }
            if got < k {
                short = true;
                break;
            }
        }
        if done < n {
            self.mem_settle();
        }
        match err {
            _ if done > 0 => Ok(done),
            Some(e) => Err(e),
            None if short => Err(KernelError::BadAddress),
            None => Ok(0),
        }
    }

    /// The skb new data goes into: the write queue's tail while it has
    /// room, else a new one of one MSS (Linux tcp_write_queue_tail /
    /// tcp_stream_alloc_skb); None without memory
    fn wq_tail(&mut self) -> Option<Box<SkBuff>> {
        if let Some(t) = self.wq.pop_back() {
            if t.tailroom() > 0 {
                return Some(t);
            }
            self.wq.push_back(t);
        }
        let mut skb = SkBuff::alloc_tx(self.live.mss.get() as usize, Gfp::KERNEL)?;
        skb.set_tcp(Seg {
            seq: self.write_seq,
            end_seq: self.write_seq,
            flags: flags::ACK,
            ..Default::default()
        });
        Some(skb)
    }

    /// Queue up to `data.len()` bytes for sending; returns how many fit
    /// (host tests)
    #[cfg(test)]
    pub fn send(&mut self, data: &[u8]) -> usize {
        let mut at = 0;
        self.send_with(data.len(), |b| {
            b.copy_from_slice(&data[at..at + b.len()]);
            at += b.len();
            Ok(b.len())
        })
        .unwrap_or(0)
    }

    /// How much of `n` bytes may be queued (Linux tcp_wmem_schedule):
    /// all if memory allows; else, so a sender with little queued still
    /// progresses, its tcp_wmem[0] floor is charged regardless and what
    /// the held quanta cover is taken; 0: wait for memory
    fn wmem_schedule(&mut self, n: usize) -> usize {
        if n == 0 || self.mem_schedule(n, MemKind::Send) {
            return n;
        }
        let left = WMEM_MIN.saturating_sub(self.sndq_len());
        if left > 0 {
            self.mem_force(left.min(n));
        }
        n.min((self.held.get() * mem::QUANTUM).saturating_sub(self.mem_used()))
    }

    /// Room in the send queue (none while TCP_NOTSENT_LOWAT unsent
    /// bytes wait, Linux sk_stream_memory_free)
    pub fn snd_space(&self) -> usize {
        let lowat = self.opts.notsent_lowat as usize;
        if lowat != 0 && self.unsent() >= lowat {
            return 0;
        }
        self.snd_cap.saturating_sub(self.sndq_len())
    }

    /// Data bytes queued for sending, sent or not (SIOCOUTQ: Linux
    /// write_seq - snd_una, the SYN and FIN left out)
    pub fn sndq_len(&self) -> usize {
        let start = if after(self.snd_una, self.iss) {
            self.snd_una
        } else {
            self.iss.wrapping_add(1)
        };
        if after(self.write_seq, start) {
            self.write_seq.wrapping_sub(start) as usize
        } else {
            0
        }
    }

    /// Bytes not sent yet (Linux write_seq - snd_nxt, SIOCOUTQNSD)
    pub fn unsent(&self) -> usize {
        if after(self.write_seq, self.snd_max) {
            self.write_seq.wrapping_sub(self.snd_max) as usize
        } else {
            0
        }
    }

    /// Linux sk_stream_is_writeable: free space is at least half of what
    /// is queued, and fewer unsent bytes than TCP_NOTSENT_LOWAT
    pub fn writable(&self) -> bool {
        let q = self.sndq_len();
        let free = self.snd_cap.saturating_sub(q);
        let lowat = self.opts.notsent_lowat;
        free > 0 && free * 2 >= q && (lowat == 0 || self.unsent() < lowat as usize)
    }

    /// Bytes readable
    pub fn rcvq_len(&self) -> usize {
        self.rcv_bytes
    }

    /// Hand up to `max` readable bytes past `skip` to `sink` in pieces,
    /// skb by skb from `copied_seq` (Linux tcp_recvmsg_locked's copies
    /// to user memory); `sink` returns the bytes it stored, short or Err
    /// after a fault. With `take` only those are consumed (a faulting
    /// copy leaves the rest queued), the skbs read through are freed
    /// (sk_eat_skb), and the window may open: a window update goes out
    /// when it grew enough (Linux tcp_cleanup_rbuf). Returns the bytes
    /// stored, Err if a fault stored none.
    pub fn recv_with(
        &mut self,
        skip: usize,
        max: usize,
        take: bool,
        mut sink: impl FnMut(&[u8]) -> Result<usize, KernelError>,
        out: &mut Out,
    ) -> Result<usize, KernelError> {
        let want = max.min(self.rcv_bytes.saturating_sub(skip));
        let (mut done, mut err) = (0, None);
        let mut seq = self.copied_seq.wrapping_add(skip as u32);
        for skb in self.rcvq.iter() {
            if done == want {
                break;
            }
            if !after(data_end(skb), seq) {
                continue;
            }
            let off = seq.wrapping_sub(skb.tcp().seq) as usize;
            let piece = &skb.data()[off..];
            let piece = &piece[..piece.len().min(want - done)];
            match sink(piece) {
                Ok(k) => {
                    let k = k.min(piece.len());
                    done += k;
                    seq = seq.wrapping_add(k as u32);
                    if k < piece.len() {
                        break;
                    }
                }
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        if take && done > 0 {
            self.consume(done);
            self.cleanup_rbuf(out);
        }
        match err {
            Some(e) if done == 0 => Err(e),
            _ => Ok(done),
        }
    }

    /// The reader took `n` bytes: free the skbs it read through (Linux
    /// tcp_recvmsg's copied_seq update + sk_eat_skb)
    fn consume(&mut self, n: usize) {
        self.copied_seq = self.copied_seq.wrapping_add(n as u32);
        self.rcv_bytes -= n;
        while self
            .rcvq
            .front()
            .is_some_and(|s| !after(data_end(s), self.copied_seq))
        {
            drop(self.rcvq.pop_front());
        }
        self.mem_settle();
    }

    /// Copy (`take`: and consume) readable bytes at `skip` into `buf`
    /// (host tests)
    #[cfg(test)]
    pub fn recv(&mut self, buf: &mut [u8], skip: usize, take: bool, out: &mut Out) -> usize {
        let mut at = 0;
        let max = buf.len();
        self.recv_with(
            skip,
            max,
            take,
            |d| {
                buf[at..at + d.len()].copy_from_slice(d);
                at += d.len();
                Ok(d.len())
            },
            out,
        )
        .unwrap_or(0)
    }

    /// After reading (Linux tcp_cleanup_rbuf): send an owed ACK when
    /// more than a segment is unacknowledged or the reader emptied the
    /// queue after a small segment; advertise a window that doubled (or
    /// opened from zero) right away
    fn cleanup_rbuf(&mut self, out: &mut Out) {
        if !matches!(
            self.state,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
        ) {
            return;
        }
        if self.dack.pending
            && (self.rcv_nxt.wrapping_sub(self.rcv_wup) > self.dack.rcv_mss
                || (self.dack.pushed && !self.live.pingpong.get() && self.rcv_bytes == 0))
        {
            self.send_ack(out);
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
    /// SYN_RECEIVED goes to FIN_WAIT_1 at once, its FIN sent behind the
    /// unacknowledged SYN-ACK (Linux's new_state table)
    pub fn shutdown_wr(&mut self, now: u64, out: &mut Out) -> bool {
        let next = match self.state {
            TcpState::Established | TcpState::SynReceived => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            _ => return false,
        };
        self.set_state(next);
        self.fin_queued = true;
        self.output(now, out);
        true
    }

    /// The user closed the socket (Linux tcp_close): unread data resets
    /// in any state, then `linger0` (SO_LINGER {1, 0}) aborts as
    /// tcp_disconnect, else the sending side closes (SYN_RECEIVED of a
    /// simultaneous open included: FIN_WAIT_1 and a FIN). The
    /// connection lives on as an orphan.
    pub fn close(&mut self, linger0: bool, now: u64, out: &mut Out) {
        self.orphan = true;
        self.rcv_shut = true;
        let unread = self.rcv_bytes != 0;
        match self.state {
            TcpState::Listen | TcpState::SynSent | TcpState::Closed => self.set_closed(out),
            TcpState::TimeWait => {}
            _ if unread => {
                self.net_stat(LINUX_MIB_TCPABORTONCLOSE);
                self.send_reset(out);
                self.set_closed(out);
            }
            _ if linger0 => {
                self.disconnect(out);
                self.net_stat(LINUX_MIB_TCPABORTONDATA);
            }
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
        if self.need_reset() {
            self.send_reset(out);
        }
        self.set_closed(out);
    }

    /// RST to the peer (Linux tcp_send_active_reset: counted before
    /// the buffer is allocated)
    fn send_reset(&self, out: &mut Out) {
        self.tcp_stat(TCP_MIB_OUTRSTS);
        let sent = out.ctl(Seg {
            seq: self.snd_max,
            ack: self.rcv_nxt,
            flags: flags::RST | flags::ACK,
            ..Default::default()
        });
        self.tcp_stat_if(sent, TCP_MIB_OUTSEGS);
        if !sent {
            self.net_stat(LINUX_MIB_TCPABORTFAILED);
        }
    }

    /// The RST `r` answering a received segment (Linux tcp_v4_send_reset from
    /// tcp_v4_do_rcv or a request's send_reset)
    pub(super) fn reset_seg(&self, r: Seg, out: &mut Out) {
        out.ctl(r);
        self.tcp_stat(TCP_MIB_OUTSEGS);
        self.tcp_stat(TCP_MIB_OUTRSTS);
    }

    /// Linux tcp_disconnect's abort: CLOSED, RST to a synchronized peer
    /// or (CLOSING, LAST_ACK) one still owed data or the FIN, then
    /// ECONNRESET for a connection made or being made. The error is
    /// reported whether or not one was set; no state change wakeup.
    pub fn disconnect(&mut self, out: &mut Out) {
        let unsent = matches!(self.state, TcpState::Closing | TcpState::LastAck)
            && self.snd_max != self.write_seq.wrapping_add(1);
        let reset = unsent || self.state == TcpState::SynSent || self.need_reset();
        if unsent {
            self.send_reset(out);
        }
        self.abort(out);
        if reset {
            out.err = Some(KernelError::ConnectionReset);
        }
        out.wake = (out.wake & !wake::STATE) | wake::ERR;
    }

    /// Linux tcp_need_reset: an abort sends RST
    fn need_reset(&self) -> bool {
        matches!(
            self.state,
            TcpState::SynReceived
                | TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
        )
    }

    /// Drop the send queues (Linux tcp_write_queue_purge): nothing is
    /// queued for sending any more
    fn purge_wq(&mut self) {
        self.wq = SkbHead::new();
        self.rtx = SkbTree::new();
        // Linux tcp_write_queue_purge + tcp_clear_all_retrans_hints
        self.packets_out = 0;
        self.rtx_hint = None;
        if after(self.write_seq, self.snd_una) {
            self.write_seq = self.snd_una;
        }
    }

    /// Fail the connection with `err` (timeout, ICMP hard error, RST;
    /// Linux tcp_done_with_error)
    pub fn fail(&mut self, err: KernelError, out: &mut Out) {
        out.err = Some(err);
        self.done(out);
    }

    /// Linux tcp_done: a connection still opening is a failed attempt
    /// (a listener's child is Linux's request sock, counted where its
    /// RST or SYN arrives, tcp_check_req), then CLOSED
    fn done(&mut self, out: &mut Out) {
        let opening = match self.state {
            TcpState::SynSent => true,
            TcpState::SynReceived => !self.passive,
            _ => false,
        };
        self.tcp_stat_if(opening, TCP_MIB_ATTEMPTFAILS);
        self.set_closed(out);
    }

    /// Enter CLOSED (Linux tcp_set_state(TCP_CLOSE) and the cleanup of
    /// tcp_done): queues and timers go, everyone wakes
    pub fn set_closed(&mut self, out: &mut Out) {
        self.set_state(TcpState::Closed);
        self.purge_wq();
        self.ooo = Ooo::default();
        self.stop_timers();
        self.mem_settle();
        out.shut |= SHUTDOWN_MASK;
        out.wake |= wake::STATE;
        out.done = true;
    }

    /// Entering TIME_WAIT: the glue hands it to a timewait entry at once,
    /// which owns the 2MSL timer and every later segment (Linux
    /// tcp_time_wait: a full socket never processes one in TIME_WAIT)
    pub(super) fn time_wait(&mut self, out: &mut Out) {
        self.set_state(TcpState::TimeWait);
        self.stop_timers();
        self.purge_wq();
        self.mem_settle();
        out.timewait = true;
        out.wake |= wake::STATE;
    }

    /// The socket's side after handing TIME_WAIT over: CLOSED, readable
    /// data kept
    pub fn tw_done(&mut self, out: &mut Out) {
        self.set_state(TcpState::Closed);
        self.stop_timers();
        out.shut |= SHUTDOWN_MASK;
        out.wake |= wake::STATE;
    }

    /// Change state (Linux tcp_set_state): CurrEstab counts
    /// connections in ESTABLISHED or CLOSE_WAIT; a reset of one of them
    /// is an EstabReset
    pub(super) fn set_state(&mut self, state: TcpState) {
        use TcpState::{CloseWait, Closed, Established, SynReceived};
        let old = self.state;
        let was = matches!(old, Established | CloseWait);
        match state {
            Established => self.tcp_stat_if(old != Established, TCP_MIB_CURRESTAB),
            CloseWait => self.tcp_stat_if(old == SynReceived, TCP_MIB_CURRESTAB),
            _ => {
                self.tcp_stat_if(state == Closed && was, TCP_MIB_ESTABRESETS);
                if was && let Some(m) = &self.mib {
                    m.tcp.dec(TCP_MIB_CURRESTAB);
                }
            }
        }
        self.state = state;
    }

    /// Linux TCP_INC_STATS
    pub(super) fn tcp_stat(&self, f: usize) {
        if let Some(m) = &self.mib {
            m.tcp.inc(f);
        }
    }

    /// Linux TCP_ADD_STATS
    pub(super) fn tcp_add(&self, f: usize, n: u64) {
        if let Some(m) = &self.mib {
            m.tcp.add(f, n);
        }
    }

    /// TCP_INC_STATS when `cond`
    pub(super) fn tcp_stat_if(&self, cond: bool, f: usize) {
        if cond {
            self.tcp_stat(f);
        }
    }

    /// Linux NET_INC_STATS (TcpExt)
    pub(super) fn net_stat(&self, f: usize) {
        if let Some(m) = &self.mib {
            m.net.inc(f);
        }
    }

    /// Linux NET_ADD_STATS
    pub(super) fn net_add(&self, f: usize, n: u64) {
        if let Some(m) = &self.mib {
            m.net.add(f, n);
        }
    }

    /// NET_INC_STATS when `cond`
    pub(super) fn net_stat_if(&self, cond: bool, f: usize) {
        if cond {
            self.net_stat(f);
        }
    }

    /// Orphan in FIN_WAIT_2: give up after tcp_fin_timeout
    pub(super) fn arm_fw2(&mut self, now: u64) {
        if self.orphan {
            self.live.wait_at.set(Some(now + self.cfg.fin_timeout));
        }
    }

    // --- receive window ----------------------------------------------------

    /// Window space for the receive buffer (Linux tcp_full_space), up
    /// to what the window field can express
    pub(super) fn full_space(&self) -> u32 {
        (self.rcv_cap as u32).clamp(1, MAX_WINDOW << self.rcv_wscale)
    }

    /// Unused receive space (Linux tcp_space)
    fn free_space(&self) -> u32 {
        let used = self.rcv_bytes + self.ooo.truesize();
        (self.full_space() as usize).saturating_sub(used) as u32
    }

    /// Window currently offered (Linux tcp_receive_window)
    pub fn rcv_wnd(&self) -> u32 {
        if before(self.rcv_adv, self.rcv_nxt) {
            0
        } else {
            self.rcv_adv.wrapping_sub(self.rcv_nxt)
        }
    }

    /// Window we would offer now (Linux __tcp_select_window): receiver
    /// SWS avoidance; without scaling in multiples of the MSS, with
    /// scaling rounded up to the scale unit
    pub(super) fn window_now(&mut self) -> u32 {
        let full = self.full_space();
        let mss = self.adv_mss.min(full);
        let unit = 1u32 << self.rcv_wscale;
        let mut free = self.free_space();
        if free < full / 2 {
            self.live.quick.set(0);
            free = free / unit * unit;
            if free < full / 16 || free < mss {
                return 0;
            }
        }
        if self.rcv_wscale != 0 {
            return free.div_ceil(unit) * unit;
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

    /// Window field for a segment (Linux tcp_select_window): the offered
    /// right edge never moves left (a scaled window rounds up to its
    /// unit); records Last.ACK.sent
    pub(super) fn select_window(&mut self) -> u16 {
        // Data dropped for memory: close the window to stop the sender
        // (the one case the right edge moves left)
        if self.ack_nomem {
            self.rcv_adv = self.rcv_nxt;
            self.rcv_wup = self.rcv_nxt;
            return 0;
        }
        let unit = 1u32 << self.rcv_wscale;
        let old = self.rcv_adv.wrapping_sub(self.rcv_wup);
        let cur = self.rcv_wnd();
        let mut w = self.window_now();
        if w < cur {
            // Never shrink: a zero window wanted is not offered yet
            self.net_stat_if(w == 0, LINUX_MIB_TCPWANTZEROWINDOWADV);
            w = cur.div_ceil(unit) * unit;
        }
        let w = w.min(MAX_WINDOW << self.rcv_wscale);
        self.rcv_adv = self.rcv_nxt.wrapping_add(w);
        self.rcv_wup = self.rcv_nxt;
        let field = (w >> self.rcv_wscale) as u16;
        if field == 0 {
            self.net_stat_if(old != 0, LINUX_MIB_TCPTOZEROWINDOWADV);
        } else if old == 0 {
            self.net_stat(LINUX_MIB_TCPFROMZEROWINDOWADV);
        }
        field
    }

    /// Window field of a SYN or SYN-ACK: never scaled (RFC 7323 2.2)
    pub(super) fn syn_window(&mut self) -> u16 {
        let w = self.full_space().min(MAX_WINDOW);
        if self.state == TcpState::SynReceived {
            self.rcv_adv = self.rcv_nxt.wrapping_add(w);
            self.rcv_wup = self.rcv_nxt;
        }
        w as u16
    }

    /// The peer's window field of `s` in bytes
    pub(super) fn seg_wnd(&self, s: &SegIn) -> u32 {
        if s.has(flags::SYN) {
            u32::from(s.wnd)
        } else {
            u32::from(s.wnd) << self.snd_wscale
        }
    }

    // --- memory ------------------------------------------------------------

    /// Bytes in the queues (Linux sk_wmem_queued + sk_rmem_alloc)
    fn mem_used(&self) -> usize {
        self.sndq_len() + self.rcv_bytes + self.ooo.truesize()
    }

    /// Cover `size` more bytes before queueing them (Linux
    /// sk_wmem_schedule / sk_rmem_schedule): what the held quanta lack
    /// is added to the global count first, then checked, and taken back
    /// on failure (__sk_mem_raise_allocated), so racing connections
    /// never all pass one check
    pub(super) fn mem_schedule(&mut self, size: usize, kind: MemKind) -> bool {
        let need = mem::quanta(self.mem_used() + size);
        if need <= self.held.get() {
            return true;
        }
        let amt = need - self.held.get();
        mem::add(amt);
        if self.mem_raise(mem::allocated(), size, kind) {
            self.held.set(need);
            return true;
        }
        mem::sub(amt);
        false
    }

    /// May the total, `allocated` with this charge in it, stand (Linux
    /// __sk_mem_raise_allocated)? Under tcp_mem[0] always, leaving
    /// pressure; past [1] pressure starts; past [2] never, except a
    /// sender filling its own buffer (suppress_allocation for
    /// SOCK_STREAM: it cannot wait for memory it is not using). Between,
    /// when not under pressure, or for a connection under its
    /// tcp_rmem[0] / tcp_wmem[0] floor or using less than an even share
    /// of [2].
    fn mem_raise(&self, allocated: usize, size: usize, kind: MemKind) -> bool {
        if allocated <= mem::limit(0) {
            if let Some(ms) = mem::leave_pressure() {
                self.net_add(LINUX_MIB_TCPMEMORYPRESSURESCHRONO, ms);
            }
            return true;
        }
        if allocated > mem::limit(1) && mem::enter_pressure() {
            self.net_stat(LINUX_MIB_TCPMEMORYPRESSURES);
        }
        if allocated <= mem::limit(2) {
            let floor = match kind {
                MemKind::Recv => {
                    self.rcv_bytes + self.ooo.truesize() < self.cfg.rmem_min as usize / 2
                }
                MemKind::Send => self.sndq_len() < WMEM_MIN,
            };
            if floor {
                return true;
            }
            if !mem::under_pressure() || mem::limit(2) > mem::sockets() * self.held.get() {
                return true;
            }
        }
        kind == MemKind::Send && self.sndq_len() + size >= self.snd_cap
    }

    /// Charge `size` more bytes without a limit (Linux
    /// sk_forced_mem_schedule)
    fn mem_force(&mut self, size: usize) {
        let need = mem::quanta(self.mem_used() + size);
        if need > self.held.get() {
            mem::add(need - self.held.get());
            self.held.set(need);
        }
    }

    /// Settle the held quanta on the queues (Linux sk_mem_uncharge +
    /// sk_mem_reclaim; up only for a charge already granted or forced,
    /// sk_forced_mem_schedule)
    pub(super) fn mem_settle(&mut self) {
        let now = mem::quanta(self.mem_used());
        if now >= self.held.get() {
            mem::add(now - self.held.get());
        } else {
            mem::sub(self.held.get() - now);
        }
        self.held.set(now);
    }

    // --- timers --------------------------------------------------------------

    /// Earliest deadline the caller must call `on_timer` at
    pub fn next_timer(&self) -> Option<u64> {
        [
            self.live.tmr.get().map(|t| t.1),
            self.live.wait_at.get(),
            self.dack.at,
            self.live.keep_at.get(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Cancel every timer
    pub(super) fn stop_timers(&mut self) {
        self.live.tmr.set(None);
        self.live.wait_at.set(None);
        self.dack.at = None;
        self.live.keep_at.set(None);
    }
}
