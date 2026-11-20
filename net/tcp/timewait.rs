//! TIME_WAIT entries (Linux inet_timewait_sock / tcp_timewait_sock,
//! tcp_minisocks.c, inet_timewait_sock.c)
//!
//! When a connection enters TIME_WAIT its socket goes to CLOSED (the
//! user may still read queued data) and a `TimeWait` takes its place in
//! the ehash and as owner of its port: the tuple, the bind rules and a
//! `TwCb`, the few fields of the connection TIME_WAIT still needs
//! (Linux tcp_timewait_sock). Segments are handled on those fields
//! directly (`TwCb::rcv`, Linux tcp_timewait_state_process): a bare
//! in-window ACK restarts 2MSL, an in-window RST ends the entry (unless
//! tcp_rfc1337), a SYN beyond RCV.NXT or with a newer timestamp may take
//! the tuple over (TCP_TW_SYN: a listener gets it), anything else is
//! answered with an ACK (rate limited) and restarts 2MSL. Only that
//! ACK's skb is allocated (Linux tcp_v4_timewait_ack).
//!
//! Its 2MSL timer is embedded (Linux tw_timer, armed with a reference
//! to the entry: `time::timer::ArcTimer`) and runs in `ktimers/N`; it
//! only unhashes the entry (Linux tw_timer_handler).
//!
//! Locking: `inner` is a `crate::sync::spin::Mutex` in the place of a
//! socket's `TcpSock.lock` slock (thread context only; table and timer
//! locks may be taken under it). Linux reads and writes the tw fields
//! with READ_ONCE/WRITE_ONCE and no lock; hk keeps them under `inner`
//! (one event at a time), and transmits after unlocking.

use crate::util::error::KernelError;
use crate::util::kalloc::try_arc_cyclic;
use alloc::sync::{Arc, Weak};

use crate::sync::spin::Mutex;

use super::cb::{OOW_RATELIMIT, PAWS_WRAP, Seg, SegIn, TIMEWAIT_LEN, TcpCb, after, flags};
use super::output::Tuple;
use super::timer::now_ms;
use crate::net::NetNamespace;
use crate::net::inet::port::BindInfo;
use crate::net::ipv4::IpParams;
use crate::net::mib::{
    LINUX_MIB_PAWS_TW_REJECTED, LINUX_MIB_TCPACKSKIPPEDTIMEWAIT, NetMib, TCP_MIB_OUTSEGS,
};
use crate::net::skb::SkBuff;
use crate::sync::rcu::RcuPuts;
use crate::time::timer::ArcTimer;
use crate::util::list::Link;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};

/// Linux TCP_PAWS_MSL (60 s, ms): an RST passes PAWS once TS.Recent is
/// this old
const PAWS_MSL: u64 = 60_000;

/// What a TIME_WAIT entry keeps of its connection (Linux
/// tcp_timewait_sock: no queues, no congestion or RTT state)
#[derive(Clone, Debug)]
pub struct TwCb {
    /// Linux tw_rcv_nxt
    pub rcv_nxt: u32,
    /// Linux tw_snd_nxt (hk's SND.MAX)
    snd_nxt: u32,
    /// Window offered at entry (Linux tw_rcv_wnd), its scale
    /// (tw_rcv_wscale)
    rcv_wnd: u32,
    rcv_wscale: u8,
    /// Timestamps negotiated (Linux: a nonzero tw_ts_recent_stamp)
    ts_ok: bool,
    /// Linux tw_ts_offset, tw_ts_recent, tw_ts_recent_stamp (ms)
    ts_off: u32,
    pub ts_recent: u32,
    ts_stamp: u64,
    /// Last out-of-window ACK (Linux tw_last_oow_ack_time)
    last_oow: Option<u64>,
    /// When 2MSL ends (ms; Linux tw_timer's expiry)
    at: u64,
}

/// What a segment asks of its TIME_WAIT entry (Linux enum tcp_tw_status)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwStatus {
    /// Nothing to send (TCP_TW_SUCCESS)
    Success,
    /// ACK it (TCP_TW_ACK_OOW)
    Ack,
    /// A new connection's SYN: a listener may take the tuple over, else
    /// ACK it (TCP_TW_SYN)
    Syn,
    /// The entry ends (an in-window RST: inet_twsk_deschedule_put)
    Kill,
}

impl TwCb {
    /// The TIME_WAIT part of `c` (Linux tcp_time_wait's copy into the
    /// tcp_timewait_sock), its 2MSL running from `c`'s TIME_WAIT entry
    pub fn from_cb(c: &TcpCb) -> Self {
        Self {
            rcv_nxt: c.rcv_nxt,
            snd_nxt: c.snd_max,
            rcv_wnd: c.rcv_wnd(),
            rcv_wscale: c.rcv_wscale,
            ts_ok: c.ts_ok,
            ts_off: c.ts_off,
            ts_recent: c.ts_recent,
            ts_stamp: c.ts_stamp,
            last_oow: None,
            at: c.live.wait_at.get().unwrap_or(c.clock + TIMEWAIT_LEN),
        }
    }

    /// When 2MSL ends
    pub fn expires(&self) -> u64 {
        self.at
    }

    /// Restart 2MSL (Linux inet_twsk_reschedule)
    fn reschedule(&mut self, now: u64) {
        self.at = now + TIMEWAIT_LEN;
    }

    /// Linux tcp_paws_reject on the entry's TS.Recent: `tsval` older,
    /// and TS.Recent neither 0 nor too old to trust; an RST passes once
    /// TS.Recent is PAWS_MSL old
    fn paws_reject(&self, tsval: u32, rst: bool, now: u64) -> bool {
        let age = now.saturating_sub(self.ts_stamp);
        let ok = (self.ts_recent.wrapping_sub(tsval) as i32) <= 0
            || age >= PAWS_WRAP
            || self.ts_recent == 0;
        !ok && !(rst && age >= PAWS_MSL)
    }

    /// Linux tcp_timewait_state_process for the TIME_WAIT substate (hk
    /// hands only TIME_WAIT over, never an orphan's FIN_WAIT_2): `s` at
    /// `now`, `rfc1337` the namespace's tcp_rfc1337
    pub fn rcv(&mut self, s: &SegIn, now: u64, rfc1337: bool, mib: Option<&NetMib>) -> TwStatus {
        // Linux parses the timestamp only when the connection had them
        let ts = s.ts.filter(|_| self.ts_ok).map(|(v, _)| v);
        let rst = s.has(flags::RST);
        let paws = ts.is_some_and(|v| self.paws_reject(v, rst, now));
        // In window: only a reset or a bare ACK
        if !paws && s.seq == self.rcv_nxt && (s.seq_len() == 0 || rst) {
            if rst {
                // TIME_WAIT assassination (RFC 1337)
                if !rfc1337 {
                    return TwStatus::Kill;
                }
            } else {
                self.reschedule(now);
            }
            if let Some(v) = ts {
                self.ts_recent = v;
                self.ts_stamp = now;
            }
            return TwStatus::Success;
        }
        // A new SYN that is no old duplicate (RFC 1122 4.2.2.13)
        if s.has(flags::SYN)
            && !s.has(flags::RST | flags::ACK)
            && !paws
            && (after(s.seq, self.rcv_nxt)
                || ts.is_some_and(|v| (self.ts_recent.wrapping_sub(v) as i32) < 0))
        {
            return TwStatus::Syn;
        }
        if paws && let Some(m) = mib {
            m.net.inc(LINUX_MIB_PAWS_TW_REJECTED);
        }
        if rst {
            return TwStatus::Success;
        }
        // An ACK-less SYN may be a new connection's below RCV.NXT: it
        // does not restart 2MSL
        if paws || s.has(flags::ACK) {
            self.reschedule(now);
        }
        if self.oow_limited(s, now, mib) {
            TwStatus::Success
        } else {
            TwStatus::Ack
        }
    }

    /// Linux tcp_oow_rate_limited with tw_last_oow_ack_time: segments
    /// with sequence space and no SYN are never limited
    fn oow_limited(&mut self, s: &SegIn, now: u64, mib: Option<&NetMib>) -> bool {
        if s.seq_len() != 0 && !s.has(flags::SYN) {
            return false;
        }
        if let Some(t) = self.last_oow
            && now >= t
            && now - t < OOW_RATELIMIT
        {
            if let Some(m) = mib {
                m.net.inc(LINUX_MIB_TCPACKSKIPPEDTIMEWAIT);
            }
            return true;
        }
        self.last_oow = Some(now);
        false
    }

    /// The ACK the entry sends at `now` (Linux tcp_v4_timewait_ack ->
    /// tcp_v4_send_ack): SND.NXT, RCV.NXT, the entry's window, a
    /// timestamp echoing TS.Recent when it has one
    pub fn ack(&self, now: u64) -> Seg {
        let ts = (self.ts_ok && self.ts_recent != 0)
            .then(|| ((now as u32).wrapping_add(self.ts_off), self.ts_recent));
        let mut h = Seg {
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            flags: flags::ACK,
            wnd: (self.rcv_wnd >> self.rcv_wscale).min(u32::from(u16::MAX)) as u16,
            ts,
            ..Default::default()
        };
        h.set_len(0);
        h
    }
}

pub struct TimeWait {
    pub tuple: Tuple,
    /// Port owner record for the bind rules (`tw` set)
    pub bind: BindInfo,
    net: Arc<NetNamespace>,
    params: IpParams,
    oif: u32,
    /// The connection's fields and the deadline (ms) `timer` is armed
    /// for
    inner: Mutex<(TwCb, Option<u64>)>,
    /// 2MSL (Linux tw_timer)
    timer: ArcTimer<TimeWait>,
    /// Its ehash entry while hashed (a leaf: set before the hand-over,
    /// taken by whoever unhashes it), its bhash owner link (Linux
    /// tw_bind_node), and whether its socket took the port with bind()
    eh: Mutex<Option<Arc<super::table::Eh>>>,
    pub(super) bind_link: Link,
    pub(super) by_bind: bool,
    /// Ended early (`kill`): the timer
    /// is never armed again (Linux timer_shutdown in
    /// inet_twsk_deschedule_put); set under `inner`
    killed: AtomicBool,
    /// The tables' references, dropped a grace period after unhashing
    rcu_puts: RcuPuts,
    me: Weak<TimeWait>,
}

crate::rcu_puts!(TimeWait, rcu_puts);

impl TimeWait {
    /// Entry for `cb` (already in TIME_WAIT); register with [`start`]
    pub fn new(
        net: Arc<NetNamespace>,
        tuple: Tuple,
        bind: BindInfo,
        by_bind: bool,
        params: IpParams,
        oif: u32,
        cb: TwCb,
    ) -> Result<Arc<Self>, KernelError> {
        try_arc_cyclic(|me| Self {
            tuple,
            bind,
            net,
            params,
            oif,
            inner: Mutex::new((cb, None)),
            timer: ArcTimer::new(TimeWait::tw_timer),
            eh: Mutex::new(None),
            bind_link: Link::new(),
            by_bind,
            killed: AtomicBool::new(false),
            rcu_puts: RcuPuts::new(),
            me: me.clone(),
        })
    }

    /// Its ehash entry, before it replaces its socket there
    pub(super) fn set_eh(&self, eh: Arc<super::table::Eh>) {
        *self.eh.lock() = Some(eh);
    }

    /// Leave the tables (once: the entry is taken)
    fn unhash(self: &Arc<Self>) {
        let eh = self.eh.lock().take();
        self.net.tcp.tw_unhash(self, eh);
    }

    /// Its namespace
    pub fn net(&self) -> &Arc<NetNamespace> {
        &self.net
    }

    /// Milliseconds of 2MSL left at `now` (/proc/net/tcp)
    pub fn left(&self, now: u64) -> u64 {
        self.inner.lock().0.expires().saturating_sub(now)
    }

    /// Arm the 2MSL timer
    pub fn start(&self) {
        let mut g = self.inner.lock();
        self.sync(&mut g, false);
    }

    /// Arm the timer for the entry's deadline, or stop it once the
    /// entry is `done` (the timer's reference goes)
    fn sync(&self, g: &mut (TwCb, Option<u64>), done: bool) {
        let want = if done || self.killed.load(Ordering::Relaxed) {
            None
        } else {
            Some(g.0.expires())
        };
        if want == g.1 && (want.is_none() || self.timer.pending()) {
            return;
        }
        match want {
            Some(at) => {
                let me = self.me.upgrade().expect("timewait entry alive");
                self.timer.reset(&me, at.saturating_mul(1_000_000));
            }
            None => {
                self.timer.stop();
            }
        }
        g.1 = want;
    }

    /// A segment for this tuple (header in `skb.tcp`; Linux tcp_v4_rcv's
    /// do_time_wait). Handed back: a new connection's SYN (TCP_TW_SYN),
    /// which the caller gives to a listener, then [`kill`]s the entry,
    /// or, with no listener, answers with [`syn_ack`].
    pub fn rcv(self: &Arc<Self>, skb: Box<SkBuff>, now: u64) -> Option<Box<SkBuff>> {
        let (s, _) = super::output::parse(skb.data())?;
        let rfc1337 = self.net.sysctl.tcp_rfc1337.load(Ordering::Relaxed) != 0;
        let mut g = self.inner.lock();
        let st = g.0.rcv(&s, now, rfc1337, Some(&self.net.mib));
        match st {
            TwStatus::Syn => return Some(skb),
            TwStatus::Kill => {
                drop(g);
                self.kill();
            }
            TwStatus::Ack => {
                let h = g.0.ack(now);
                self.sync(&mut g, false);
                drop(g);
                self.send_ack(&h);
            }
            TwStatus::Success => self.sync(&mut g, false),
        }
        None
    }

    /// ACK a takeover SYN no listener wanted (Linux do_time_wait's
    /// TCP_TW_SYN falling through to tcp_v4_timewait_ack)
    pub fn syn_ack(&self, now: u64) {
        let h = self.inner.lock().0.ack(now);
        self.send_ack(&h);
    }

    /// Transmit `h` (Linux tcp_v4_send_ack: an skb of its own, GFP_ATOMIC)
    fn send_ack(&self, h: &Seg) {
        super::xmit(&self.net, &self.tuple, h, self.params, self.oif);
        self.net.mib.tcp.inc(TCP_MIB_OUTSEGS);
    }
}

impl TimeWait {
    /// End the entry now (Linux inet_twsk_deschedule_put: an in-window
    /// RST, a takeover SYN went to a listener, or tcp_twsk_purge as its
    /// namespace goes):
    /// the timer stops, and the entry leaves the tables
    pub fn kill(self: &Arc<Self>) {
        let mut g = self.inner.lock();
        self.killed.store(true, Ordering::Relaxed);
        self.sync(&mut g, true);
        drop(g);
        self.unhash();
    }

    /// 2MSL passed (`ktimers/N`; Linux tw_timer_handler ->
    /// inet_twsk_kill): the entry leaves the tables; the timer's
    /// reference goes with `tw`. Nothing is allocated.
    fn tw_timer(tw: Arc<TimeWait>) {
        let mut g = tw.inner.lock();
        // Rescheduled as this run started (Linux's mod_timer moves a
        // pending timer instead): wait for the new deadline
        if g.0.expires() > now_ms() {
            tw.sync(&mut g, false);
            return;
        }
        tw.sync(&mut g, true);
        drop(g);
        tw.unhash();
    }
}
