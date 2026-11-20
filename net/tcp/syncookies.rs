//! SYN cookies (Linux v6.8 net/ipv4/syncookies.c, the tcp.h helpers)
//!
//! A listener whose SYN queue is full answers a SYN with a SYN-ACK
//! whose ISN encodes the peer's MSS (an index into `MSSTAB`) and a
//! minute counter under two keyed hashes, keeping no state; the
//! completing ACK (ack - 1 the cookie) rebuilds the request. With
//! timestamps the SYN-ACK's TSval also carries the SYN's window scale,
//! SACK and ECN bits in its low `TSBITS`, read back from the ACK's echo.
//!
//! The secrets (Linux syncookie_secret, net_get_random_once) are global,
//! drawn once; a listener's last SYN queue overflow time (Linux
//! rx_opt.ts_recent_stamp of the listener) is an atomic of its socket.

use core::sync::atomic::{AtomicU32, Ordering};

use super::cb::{Cfg, MAX_WINDOW, SegIn};
use super::output::Tuple;

/// Upper bits store the count (Linux COOKIEBITS)
const COOKIEBITS: u32 = 24;
const COOKIEMASK: u32 = (1 << COOKIEBITS) - 1;

/// The low TSval bits of a cookie SYN-ACK: the SYN's window scale
/// (0xf: none), SACK, ECN (Linux TS_OPT_*)
const TS_OPT_WSCALE_MASK: u32 = 0xf;
const TS_OPT_SACK: u32 = 1 << 4;
const TS_OPT_ECN: u32 = 1 << 5;
const TSBITS: u32 = 6;

/// A cookie is valid for at most this many counter periods (Linux
/// MAX_SYNCOOKIE_AGE, TCP_SYNCOOKIE_PERIOD, TCP_SYNCOOKIE_VALID; ms)
const MAX_SYNCOOKIE_AGE: u32 = 2;
const SYNCOOKIE_PERIOD: u64 = 60 * HZ;
const SYNCOOKIE_VALID: u32 = MAX_SYNCOOKIE_AGE * SYNCOOKIE_PERIOD as u32;

/// hk's jiffies are its ms clock
const HZ: u64 = 1000;

/// Linux INITIAL_JIFFIES (-300 s): a listener's overflow stamp starts
/// at 0, far from the clock, as Linux's
const INITIAL_JIFFIES: u32 = (-300 * HZ as i32) as u32;

/// The MSS values a cookie encodes, sorted (Linux msstab)
pub const MSSTAB: [u16; 4] = [536, 1300, 1440, 1460];

/// The two keys (Linux syncookie_secret[2])
#[cfg(not(test))]
fn secret(c: usize) -> [u64; 2] {
    static SECRET: spin::Once<[[u64; 2]; 2]> = spin::Once::new();
    let r = || {
        (u64::from(crate::random::get_random_u32()) << 32)
            | u64::from(crate::random::get_random_u32())
    };
    SECRET.call_once(|| [[r(), r()], [r(), r()]])[c]
}

#[cfg(test)]
fn secret(c: usize) -> [u64; 2] {
    [[1, 2], [3, 4]][c]
}

/// Linux jiffies (32 bits)
fn jiffies32(now: u64) -> u32 {
    (now as u32).wrapping_add(INITIAL_JIFFIES)
}

/// Linux time_between32
fn time_between32(t: u32, l: u32, h: u32) -> bool {
    h.wrapping_sub(l) >= t.wrapping_sub(l)
}

/// Linux cookie_hash: siphash_4u32 of the SYN's addresses, its ports,
/// `count`, under key `c` (the wire's byte order, as Linux hashes __be
/// values)
fn cookie_hash(t: &Tuple, count: u32, c: usize) -> u32 {
    let saddr = t.raddr.0.to_be();
    let daddr = t.laddr.0.to_be();
    let ports = (u32::from(t.rport.to_be()) << 16) | u32::from(t.lport.to_be());
    let w = [
        (u64::from(daddr) << 32) | u64::from(saddr),
        (u64::from(count) << 32) | u64::from(ports),
    ];
    crate::util::siphash::siphash(secret(c), &w) as u32
}

/// Linux tcp_cookie_time: the counter, one per period
pub fn cookie_time(now: u64) -> u32 {
    ((now + u64::from(INITIAL_JIFFIES)) / SYNCOOKIE_PERIOD) as u32
}

/// Linux secure_tcp_syn_cookie
fn secure_syn_cookie(t: &Tuple, sseq: u32, data: u32, count: u32) -> u32 {
    cookie_hash(t, 0, 0)
        .wrapping_add(sseq)
        .wrapping_add(count << COOKIEBITS)
        .wrapping_add(cookie_hash(t, count, 1).wrapping_add(data) & COOKIEMASK)
}

/// Linux check_tcp_syn_cookie: the data, or out of range (u32::MAX)
/// for a cookie older than MAX_SYNCOOKIE_AGE periods
fn check_syn_cookie(cookie: u32, t: &Tuple, sseq: u32, count: u32) -> u32 {
    let cookie = cookie.wrapping_sub(cookie_hash(t, 0, 0).wrapping_add(sseq));
    let diff = count.wrapping_sub(cookie >> COOKIEBITS) & (u32::MAX >> COOKIEBITS);
    if diff >= MAX_SYNCOOKIE_AGE {
        return u32::MAX;
    }
    cookie.wrapping_sub(cookie_hash(t, count.wrapping_sub(diff), 1)) & COOKIEMASK
}

/// Linux __cookie_v4_init_sequence: the ISN for the SYN `seq` on `t`
/// (local, remote) and the MSS, rounded down to the table's
pub fn init_sequence(t: &Tuple, seq: u32, mss: u16, now: u64) -> (u32, u16) {
    let i = (1..MSSTAB.len())
        .rev()
        .find(|&i| mss >= MSSTAB[i])
        .unwrap_or(0);
    let isn = secure_syn_cookie(t, seq, i as u32, cookie_time(now));
    (isn, MSSTAB[i])
}

/// Linux __cookie_v4_check: the MSS of a valid cookie in the ACK
/// (`seq`, `ack`) on `t`, else 0
pub fn check(t: &Tuple, seq: u32, ack: u32, now: u64) -> u16 {
    let cookie = ack.wrapping_sub(1);
    let i = check_syn_cookie(cookie, t, seq.wrapping_sub(1), cookie_time(now));
    MSSTAB.get(i as usize).copied().unwrap_or(0)
}

/// The options of a request a cookie's timestamp carries (Linux
/// inet_request_sock's wscale_ok, snd_wscale, sack_ok, ecn_ok)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReqOpts {
    pub ts: bool,
    pub wscale: Option<u8>,
    pub sack: bool,
    pub ecn: bool,
}

/// A request a valid cookie ACK rebuilds (Linux cookie_tcp_reqsk_alloc):
/// its options, the cookie's MSS, our timestamp offset
pub struct Req {
    pub r: ReqOpts,
    pub mss: u16,
    pub tsoff: u32,
}

impl Req {
    /// The SYN the cookie ACK `s` stands for: a sequence number before
    /// it (rcv_isn), the cookie's MSS, the options the timestamp
    /// carried, the ACK's TSval to become TS.Recent (req->ts_recent)
    pub fn syn(&self, s: &SegIn) -> SegIn {
        let mut syn = SegIn {
            seq: s.seq.wrapping_sub(1),
            flags: super::cb::flags::SYN,
            mss: Some(self.mss),
            ws: self.r.wscale,
            ts: s.ts.filter(|_| self.r.ts).map(|(v, _)| (v, 0)),
            sack_perm: self.r.sack,
            sport: s.sport,
            dport: s.dport,
            ..SegIn::default()
        };
        syn.set_len(0);
        syn
    }
}

/// Linux cookie_init_timestamp in ms: the clock with its low `TSBITS`
/// replaced by the request's options, never past `now`
pub fn init_timestamp(r: &ReqOpts, now: u64) -> u32 {
    let mut o = r.wscale.map_or(TS_OPT_WSCALE_MASK, u32::from);
    if r.sack {
        o |= TS_OPT_SACK;
    }
    if r.ecn {
        o |= TS_OPT_ECN;
    }
    let mut ts = ((now >> TSBITS) << TSBITS) | u64::from(o);
    if ts > now {
        ts -= 1 << TSBITS;
    }
    ts as u32
}

/// Linux cookie_timestamp_decode: the request's options from the ACK's
/// timestamp `ts` (TSval, TSecr less our offset); None when they name
/// an option the sysctls `c` disable
pub fn timestamp_decode(ts: Option<(u32, u32)>, c: &Cfg) -> Option<ReqOpts> {
    let Some((_, o)) = ts else {
        return Some(ReqOpts::default());
    };
    if c.ts == 0 {
        return None;
    }
    let mut r = ReqOpts {
        ts: true,
        sack: o & TS_OPT_SACK != 0,
        ecn: o & TS_OPT_ECN != 0,
        wscale: None,
    };
    if r.sack && !c.sack {
        return None;
    }
    if o & TS_OPT_WSCALE_MASK == TS_OPT_WSCALE_MASK {
        return Some(r);
    }
    r.wscale = Some((o & TS_OPT_WSCALE_MASK) as u8);
    c.wscale.then_some(r)
}

/// Linux tcp_synq_overflow: note a SYN queue overflow on the listener
/// whose stamp is `last` (at most once a second; racy, as Linux's)
pub fn synq_overflow(last: &AtomicU32, now: u64) {
    let now = jiffies32(now);
    let l = last.load(Ordering::Relaxed);
    if !time_between32(now, l, l.wrapping_add(HZ as u32)) {
        last.store(now, Ordering::Relaxed);
    }
}

/// Linux tcp_synq_no_recent_overflow: no overflow within a cookie's
/// lifetime (a second of slack below, for a racing stamp)
pub fn synq_no_recent_overflow(last: &AtomicU32, now: u64) -> bool {
    let l = last.load(Ordering::Relaxed);
    !time_between32(
        jiffies32(now),
        l.wrapping_sub(HZ as u32),
        l.wrapping_add(SYNCOOKIE_VALID),
    )
}

/// What a cookie SYN-ACK is built from: the listener's SO_RCVBUF
/// (and whether set), its window clamp and TCP_MAXSEG, the MSS the
/// route allows us, the timestamp offset
pub struct Synack {
    pub rcvbuf: u32,
    pub rcvbuf_locked: bool,
    pub window_clamp: u32,
    pub user_mss: u32,
    pub adv_mss: u32,
    pub ts_off: u32,
}

/// The request a cookie SYN-ACK answers (Linux tcp_conn_request with
/// want_cookie: tcp_parse_options under the sysctls, all options
/// cleared without a timestamp, mss_clamp as TCP_MAXSEG allows, else
/// TCP_MSS_DEFAULT; hk has no ECN)
pub fn request(syn: &SegIn, c: &Cfg, user_mss: u32) -> (ReqOpts, u16) {
    let mut mss = super::cb::MSS_DEFAULT as u16;
    if let Some(m) = syn.mss {
        mss = if user_mss != 0 && user_mss < u32::from(m) {
            user_mss as u16
        } else {
            m
        };
    }
    if c.ts == 0 || syn.ts.is_none() {
        return (ReqOpts::default(), mss);
    }
    let r = ReqOpts {
        ts: true,
        wscale: syn.ws.filter(|_| c.wscale),
        sack: syn.sack_perm && c.sack,
        ecn: false,
    };
    (r, mss)
}

/// The SYN-ACK of a cookie request `r` for `syn` with ISN `isn` (Linux
/// tcp_make_synack, TCP_SYNACK_COOKIE: our MSS clamped by TCP_MAXSEG;
/// the window and scale tcp_openreq_init_rwin picks from the listener's
/// full space, rounded to that MSS less the timestamp option; the cookie
/// timestamp echoing the SYN's TSval; the window unscaled)
pub fn synack(syn: &SegIn, r: &ReqOpts, isn: u32, c: &Cfg, s: &Synack, now: u64) -> SegIn {
    use super::buf::{DEFAULT_SCALING_RATIO, initial_window, win_from_space};
    use super::cb::flags;
    // As a child's (`TcpCb::set_adv_mss`)
    let mut mss = s.adv_mss.clamp(64, 65495);
    if s.user_mss != 0 {
        mss = mss.min(s.user_mss);
    }
    let full = win_from_space(DEFAULT_SCALING_RATIO, i64::from(s.rcvbuf)).max(0) as u32;
    let mut clamp = s.window_clamp;
    if s.rcvbuf_locked && (clamp > full || clamp == 0) {
        clamp = full;
    }
    let wmss = mss - if r.ts { super::cb::TS_LEN } else { 0 };
    let w = initial_window(i64::from(full), wmss, r.wscale.is_some(), clamp, c.rmem_max);
    let (ws, wnd) = (w.wscale, w.rcv_wnd.min(MAX_WINDOW));
    let ts = syn
        .ts
        .filter(|_| r.ts)
        .map(|(v, _)| (init_timestamp(r, now).wrapping_add(s.ts_off), v));
    let mut h = SegIn {
        seq: isn,
        ack: syn.seq.wrapping_add(1),
        flags: flags::SYN | flags::ACK,
        wnd: wnd as u16,
        mss: Some(mss.min(u32::from(u16::MAX)) as u16),
        ws: r.wscale.map(|_| ws),
        ts,
        sack_perm: r.sack,
        ..Default::default()
    };
    h.set_len(0);
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::ipv4::Ipv4Addr;

    fn tuple() -> Tuple {
        Tuple {
            laddr: Ipv4Addr(0x7f00_0001),
            lport: 80,
            raddr: Ipv4Addr(0xc000_024e),
            rport: 7781,
        }
    }

    /// A cookie names its MSS rounded down to the table, and only for
    /// its own tuple; it ages out after two counter periods
    #[test]
    fn cookie_round_trip() {
        let t = tuple();
        let now = 1_000_000;
        for (mss, want) in [
            (1460, 1460),
            (1452, 1440),
            (1300, 1300),
            (1000, 536),
            (100, 536),
        ] {
            let (isn, m) = init_sequence(&t, 5000, mss, now);
            assert_eq!(m, want);
            assert_eq!(check(&t, 5001, isn.wrapping_add(1), now), want);
            // Another tuple's ACK: no
            let mut o = t;
            o.rport += 1;
            assert_eq!(check(&o, 5001, isn.wrapping_add(1), now), 0);
        }
        let (isn, _) = init_sequence(&t, 5000, 1460, now);
        // The next period still accepts it; two periods later not
        let p = SYNCOOKIE_PERIOD;
        assert_eq!(check(&t, 5001, isn.wrapping_add(1), now + p), 1460);
        assert_eq!(check(&t, 5001, isn.wrapping_add(1), now + 2 * p + p), 0);
    }

    /// The SYN-ACK's TSval carries the options in its low six bits and
    /// is never ahead of the clock
    #[test]
    fn cookie_timestamp_options() {
        let c = Cfg::default();
        let r = ReqOpts {
            ts: true,
            wscale: Some(7),
            sack: true,
            ecn: false,
        };
        for now in [64 * 1000, 64 * 1000 + 3, 64 * 1000 + 63] {
            let ts = init_timestamp(&r, now);
            assert!(u64::from(ts) <= now && now - u64::from(ts) < 64);
            assert_eq!(timestamp_decode(Some((9, ts)), &c), Some(r));
        }
        let none = ReqOpts {
            ts: true,
            ..ReqOpts::default()
        };
        let ts = init_timestamp(&none, 6400);
        assert_eq!(timestamp_decode(Some((9, ts)), &c), Some(none));
        // No timestamp: no options
        assert_eq!(timestamp_decode(None, &c), Some(ReqOpts::default()));
        // An option the sysctls disable: not a cookie of ours
        let nosack = Cfg {
            sack: false,
            ..Cfg::default()
        };
        let ts = init_timestamp(&r, 6400);
        assert_eq!(timestamp_decode(Some((9, ts)), &nosack), None);
        let nows = Cfg {
            wscale: false,
            ..Cfg::default()
        };
        assert_eq!(timestamp_decode(Some((9, ts)), &nows), None);
    }

    /// A listener counts as flooded for a cookie's lifetime after its
    /// last overflow, and not before any
    #[test]
    fn synq_overflow_window() {
        let last = AtomicU32::new(0);
        let now = 10_000;
        assert!(synq_no_recent_overflow(&last, now));
        synq_overflow(&last, now);
        assert!(!synq_no_recent_overflow(&last, now));
        assert!(!synq_no_recent_overflow(
            &last,
            now + u64::from(SYNCOOKIE_VALID)
        ));
        assert!(synq_no_recent_overflow(
            &last,
            now + u64::from(SYNCOOKIE_VALID) + 1
        ));
        // Stamped at most once a second
        let s = last.load(Ordering::Relaxed);
        synq_overflow(&last, now + 500);
        assert_eq!(last.load(Ordering::Relaxed), s);
        synq_overflow(&last, now + 1001);
        assert_ne!(last.load(Ordering::Relaxed), s);
    }
}
