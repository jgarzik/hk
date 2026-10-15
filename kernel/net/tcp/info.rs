//! TCP_INFO (Linux tcp_get_info, uapi struct tcp_info) and
//! /proc/net/tcp (Linux tcp4_seq_show)
//!
//! `struct tcp_info` is laid out field by field in its uapi order (280
//! bytes, the current Linux size; getsockopt truncates to the caller's
//! length like Linux). Fields hk has no counterpart for (SACK, pacing,
//! delivery rate, ECN) are 0, or ~0 for the pacing rates as Linux
//! reports without pacing. Counts Linux keeps in packets (cwnd,
//! ssthresh, unacked) are bytes / MSS.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::Ordering;

use super::cb::{RTO_INIT, RTO_MAX, TcpCb, TcpState, Tmr};
use super::table::Ent;
use super::timer::now_ms;

/// tcpi_options bits
const OPT_TIMESTAMPS: u8 = 1;
const OPT_WSCALE: u8 = 4;
/// Linux TCP_CA_Open / TCP_CA_Recovery / TCP_CA_Loss
const CA_OPEN: u8 = 0;
const CA_RECOVERY: u8 = 3;
const CA_LOSS: u8 = 4;
/// Linux TCP_INFINITE_SSTHRESH
const INFINITE_SSTHRESH: u32 = 0x7fff_ffff;
/// sizeof(struct tcp_info)
pub const INFO_LEN: usize = 280;

/// Linux secs_to_retrans with TCP_TIMEOUT_INIT and TCP_RTO_MAX (s)
pub fn secs_to_retrans(secs: i32) -> u8 {
    let (init, max) = ((RTO_INIT / 1000) as i32, (RTO_MAX / 1000) as i32);
    if secs <= 0 {
        return 0;
    }
    let (mut res, mut timeout, mut period) = (1u8, init, init);
    while secs > period && res < 255 {
        res += 1;
        timeout = (timeout * 2).min(max);
        period += timeout;
    }
    res
}

/// Linux retrans_to_secs
pub fn retrans_to_secs(retrans: u8) -> u32 {
    let (init, max) = ((RTO_INIT / 1000) as u32, (RTO_MAX / 1000) as u32);
    if retrans == 0 {
        return 0;
    }
    let (mut timeout, mut period) = (init, init);
    for _ in 1..retrans {
        timeout = (timeout * 2).min(max);
        period += timeout;
    }
    period
}

/// Packets for `bytes` of segments of `mss`
fn pkts(bytes: u32, mss: u32) -> u32 {
    bytes.div_ceil(mss.max(1))
}

/// Little helper writing native-endian fields in order
struct Buf(Vec<u8>);

impl Buf {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_ne_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_ne_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_ne_bytes());
    }
    fn ms_ago(&mut self, now: u64, t: u64) {
        self.u32(now.saturating_sub(t).min(u32::MAX as u64) as u32);
    }
}

impl TcpCb {
    /// Linux TCP_CA_* state
    fn ca_state(&self) -> u8 {
        if self.cong.in_recovery() {
            CA_RECOVERY
        } else if self.backoff > 0 && self.snd_una != self.snd_max {
            CA_LOSS
        } else {
            CA_OPEN
        }
    }
}

/// `struct tcp_info` of `cb` at `now`
pub fn tcp_info(cb: &TcpCb, now: u64) -> Vec<u8> {
    let mut b = Buf(Vec::with_capacity(INFO_LEN));
    let mss = cb.mss;
    let st = &cb.stats;
    let synced = cb.state.synced();
    b.u8(cb.state.linux());
    b.u8(cb.ca_state());
    b.u8(cb.backoff.min(255) as u8);
    b.u8(cb.probes.min(255) as u8);
    b.u8(cb.backoff.min(255) as u8);
    let mut opt = 0;
    if cb.ts_ok {
        opt |= OPT_TIMESTAMPS;
    }
    if cb.wscale_ok {
        opt |= OPT_WSCALE;
    }
    b.u8(opt);
    b.u8((cb.snd_wscale & 15) | (cb.rcv_wscale << 4));
    b.u8(0);
    b.u32((cb.rto_cur() * 1000) as u32);
    b.u32((cb.dack.ato * 1000) as u32);
    b.u32(mss);
    b.u32(cb.dack.rcv_mss);
    b.u32(pkts(cb.snd_max.wrapping_sub(cb.snd_una), mss)); // unacked
    for _ in 0..4 {
        b.u32(0); // sacked, lost, retrans, fackets
    }
    b.ms_ago(now, cb.lsndtime); // last_data_sent
    b.u32(0); // last_ack_sent
    b.ms_ago(now, st.last_data_recv);
    b.ms_ago(now, cb.rcv_tstamp);
    b.u32(cb.path_mss + super::cb::HDRS); // pmtu
    b.u32(cb.full_space()); // rcv_ssthresh
    let (srtt, var) = cb.rtt();
    b.u32((srtt * 1000) as u32);
    b.u32((var * 1000) as u32);
    let ss = cb.cong.ssthresh;
    b.u32(if ss >= INFINITE_SSTHRESH {
        INFINITE_SSTHRESH
    } else {
        pkts(ss, mss)
    });
    b.u32(pkts(cb.cong.cwnd, mss));
    b.u32(cb.adv_mss);
    b.u32(3); // reordering (tcp_reordering)
    b.u32(0); // rcv_rtt
    b.u32(cb.full_space()); // rcv_space
    b.u32(st.total_retrans);
    b.u64(u64::MAX); // pacing_rate
    b.u64(u64::MAX); // max_pacing_rate
    b.u64(st.bytes_acked);
    b.u64(st.bytes_received);
    b.u32(st.segs_out);
    b.u32(st.segs_in);
    b.u32(cb.unsent() as u32);
    b.u32(st.min_rtt.map_or(u32::MAX, |r| (r * 1000) as u32));
    b.u32(st.data_segs_in);
    b.u32(st.data_segs_out);
    b.u64(0); // delivery_rate
    for _ in 0..3 {
        b.u64(0); // busy_time, rwnd_limited, sndbuf_limited
    }
    b.u32(pkts(st.bytes_acked.min(u32::MAX as u64) as u32, mss)); // delivered
    b.u32(0); // delivered_ce
    b.u64(st.bytes_sent);
    b.u64(st.bytes_retrans);
    b.u32(0); // dsack_dups
    b.u32(0); // reord_seen
    b.u32(0); // rcv_ooopack
    b.u32(if synced { cb.snd_wnd } else { 0 });
    b.u32(if synced { cb.rcv_wnd() } else { 0 });
    b.u32(0); // rehash
    b.u16(st.rto_count.min(u16::MAX as u32) as u16);
    b.u16(0); // total_rto_recoveries
    b.u32(0); // total_rto_time
    for _ in 0..8 {
        b.u32(0); // received_ce, AccECN counters, ecn bits
    }
    debug_assert_eq!(b.0.len(), INFO_LEN);
    b.0
}

// ============================================================================
// /proc/net/tcp
// ============================================================================

/// Address as the raw network-order word (Linux prints __be32 with %08X)
fn raw(a: crate::net::ipv4::Ipv4Addr) -> u32 {
    u32::from_ne_bytes(a.to_be_bytes())
}

/// ms -> clock_t (USER_HZ 100)
fn ticks(ms: u64) -> u64 {
    ms / 10
}

/// One line padded like Linux seq_pad (TMPSZ - 1 = 149 columns)
fn line(out: &mut String, l: &str) {
    let _ = writeln!(out, "{:<149}", l);
}

/// (timer kind, ms left) of a connection (Linux tcp4_seq_show
/// timer_active: 1 retransmit, 4 zero-window probe, 2 keepalive /
/// FIN_WAIT2 timer)
fn timer(cb: &TcpCb, now: u64) -> (u8, u64) {
    let left = |t: u64| t.saturating_sub(now);
    match (cb.tmr, cb.keep_at.or(cb.wait_at)) {
        (Some((Tmr::Rtx, t)), _) => (1, left(t)),
        (Some((Tmr::Probe, t)), _) => (4, left(t)),
        (None, Some(t)) => (2, left(t)),
        _ => (0, 0),
    }
}

/// A listener or connection line
fn sock_line(out: &mut String, i: usize, s: &super::TcpSock, now: u64) {
    let a = s.inet.get();
    let ino = s.sk.ino.load(Ordering::Relaxed);
    let uid = s.sk.cred.euid;
    let g = s.cb.lock();
    let cb = &g.cb;
    let listen = cb.state == TcpState::Listen;
    let rxq = if listen {
        s.queue.lock().as_ref().map_or(0, |q| q.ready.len())
    } else {
        cb.rcvq_len()
    };
    let (tr, when) = timer(cb, now);
    let ss = cb.cong.ssthresh;
    let last: i64 = if listen {
        cb.opts.fastopen as i64
    } else if ss >= INFINITE_SSTHRESH {
        -1
    } else {
        pkts(ss, cb.mss) as i64
    };
    let l = alloc::format!(
        "{:4}: {:08X}:{:04X} {:08X}:{:04X} {:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} {} {:016x} {} {} {} {} {}",
        i,
        raw(a.rcv_saddr),
        a.sport,
        raw(a.daddr),
        a.dport,
        cb.state.linux(),
        cb.sndq_len(),
        rxq,
        tr,
        ticks(when),
        cb.backoff,
        uid,
        cb.probes,
        ino,
        1,
        0,
        ticks(cb.rto_cur()),
        ticks(cb.dack.ato),
        (cb.dack.quick << 1) | cb.dack.pingpong as u32,
        pkts(cb.cong.cwnd, cb.mss),
        last
    );
    drop(g);
    line(out, &l);
}

/// A TIME_WAIT line (Linux get_timewait4_sock)
fn tw_line(out: &mut String, i: usize, tw: &super::timewait::TimeWait, now: u64) {
    let t = &tw.tuple;
    let l = alloc::format!(
        "{:4}: {:08X}:{:04X} {:08X}:{:04X} {:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} {} {:016x}",
        i,
        raw(t.laddr),
        t.lport,
        raw(t.raddr),
        t.rport,
        TcpState::TimeWait.linux(),
        0,
        0,
        3,
        ticks(tw.left(now)),
        0,
        0,
        0,
        0,
        3,
        0
    );
    line(out, &l);
}

/// `/proc/net/tcp` of the reader's namespace: listeners, then
/// connections and TIME_WAIT entries (socket locks are taken one at a
/// time after the table locks are dropped)
pub fn proc_net_tcp() -> Vec<u8> {
    let mut out = String::new();
    line(
        &mut out,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
    );
    let (ls, es) = crate::net::current_net_ns().tcp.snapshot();
    let now = now_ms();
    let mut i = 0;
    for s in &ls {
        sock_line(&mut out, i, s, now);
        i += 1;
    }
    for e in &es {
        match e {
            Ent::Sk(s) => sock_line(&mut out, i, s, now),
            Ent::Tw(t) => tw_line(&mut out, i, t, now),
        }
        i += 1;
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defer_accept_rounding() {
        assert_eq!(secs_to_retrans(0), 0);
        assert_eq!(secs_to_retrans(1), 1);
        assert_eq!(secs_to_retrans(5), 3);
        assert_eq!(retrans_to_secs(3), 7);
        assert_eq!(retrans_to_secs(secs_to_retrans(30)), 31);
        assert_eq!(secs_to_retrans(i32::MAX), 255);
    }

    #[test]
    fn info_layout() {
        let cb = TcpCb::new(super::super::cb::Cfg::default());
        let b = tcp_info(&cb, 0);
        assert_eq!(b.len(), INFO_LEN);
        assert_eq!(b[0], TcpState::Closed.linux());
    }
}
