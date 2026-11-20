//! TIME_WAIT entries (Linux inet_timewait_sock / tcp_timewait_sock)
//!
//! When a connection enters TIME_WAIT its socket goes to CLOSED (the
//! user may still read queued data) and a `TimeWait` takes its place in
//! the ehash and as owner of its port: just the tuple, the bind rules
//! and a queue-less control block in TIME_WAIT, which re-ACKs a
//! retransmitted FIN (restarting 2MSL), answers other segments with an
//! ACK, dies on an acceptable RST, and after 2MSL leaves the tables. A
//! new SYN beyond its RCV.NXT or with a newer timestamp ends it early so
//! the tuple can be reused (Linux tcp_timewait_state_process TCP_TW_SYN).
//! The entry keeps a compact `TwCb` (no queues, no congestion or RTT
//! state), from which each segment or timer event rebuilds a control
//! block for the call.
//!
//! Its 2MSL timer is embedded (Linux tw_timer, armed with a reference
//! to the entry: `time::timer::ArcTimer`) and runs in `ktimers/N`.
//!
//! Locking: `inner` is a `crate::sync::spin::Mutex` in the place of a
//! socket's `TcpSock.lock` slock (thread context only; table and timer
//! locks may be taken under it).

use crate::mm::page_alloc::Gfp;
use crate::util::error::KernelError;
use crate::util::kalloc::{try_arc_cyclic, try_arc_gfp};
use alloc::sync::{Arc, Weak};

use crate::sync::spin::Mutex;

use super::cb::{Live, Out, TwCb};
use super::output::Tuple;
use super::timer::now_ms;
use crate::net::NetNamespace;
use crate::net::inet::port::BindInfo;
use crate::net::ipv4::IpParams;
use crate::net::skb::SkBuff;
use crate::sync::rcu::RcuPuts;
use crate::time::timer::ArcTimer;
use crate::util::list::Link;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};

pub struct TimeWait {
    pub tuple: Tuple,
    /// Port owner record for the bind rules (`tw` set)
    pub bind: BindInfo,
    net: Arc<NetNamespace>,
    params: IpParams,
    oif: u32,
    /// The control block and the deadline (ms) `timer` is armed for
    inner: Mutex<(TwCb, Option<u64>)>,
    /// 2MSL (Linux tw_timer)
    timer: ArcTimer<TimeWait>,
    /// Its ehash entry while hashed (a leaf: set before the hand-over,
    /// taken by whoever unhashes it), its bhash owner link (Linux
    /// tw_bind_node), and whether its socket took the port with bind()
    eh: Mutex<Option<Arc<super::table::Eh>>>,
    pub(super) bind_link: Link,
    pub(super) by_bind: bool,
    /// Ended by its namespace's teardown: the timer is never armed
    /// again (Linux timer_shutdown in inet_twsk_deschedule_put); set
    /// under `inner`
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
        let g = self.inner.lock();
        g.0.next_timer().map_or(0, |t| t.saturating_sub(now))
    }

    /// Arm the 2MSL timer
    pub fn start(&self) {
        let mut g = self.inner.lock();
        self.sync(&mut g, false);
    }

    /// Arm the timer for the control block's deadline, or stop it once
    /// the entry is `done` (the timer's reference goes)
    fn sync(&self, g: &mut (TwCb, Option<u64>), done: bool) {
        let want = if done || self.killed.load(Ordering::Relaxed) {
            None
        } else {
            g.0.next_timer()
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

    /// A segment for this tuple (header in `skb.tcp`). Handed back: it
    /// is a new connection's SYN, this entry is gone and the caller
    /// gives it to a listener.
    pub fn rcv(self: &Arc<Self>, skb: Box<SkBuff>, now: u64) -> Option<Box<SkBuff>> {
        let mut out = Out::default();
        let s = skb.tcp();
        // A new connection's SYN takes the tuple over with nothing
        // allocated (Linux TCP_TW_SYN)
        if self.syn_takeover(&s) {
            return Some(skb);
        }
        // Any other event rebuilds a control block, which needs
        // lockless fields of its own, scratch for the event: made
        // GFP_ATOMIC before the lock (an entry keeps none, so it stays
        // small); none, no event (the segment is dropped, the peer
        // sends again)
        let Ok(live) = try_arc_gfp(Live::default(), Gfp::ATOMIC) else {
            return None;
        };
        let mut g = self.inner.lock();
        // A SYN that became acceptable between the two holds
        if g.0.tw_syn_ok(&s) {
            drop(g);
            return self.syn_takeover(&s).then_some(skb);
        }
        let mut cb = g.0.cb(super::cfg(&self.net), live);
        cb.mib = Some(Arc::clone(&self.net.mib));
        cb.input(&s, skb, now, &mut out);
        g.0 = TwCb::from_cb(&cb);
        self.post(&mut g, &out);
        // Transmitted under the entry lock, in order
        self.send(&mut out);
        drop(g);
        // The control block's queues go after the lock
        drop(cb);
        None
    }

    /// `s` is a SYN that may reuse the tuple: the entry ends, and the
    /// caller hands the segment to a listener
    fn syn_takeover(self: &Arc<Self>, s: &crate::net::skb::TcpSkbCb) -> bool {
        let mut g = self.inner.lock();
        if !g.0.tw_syn_ok(s) {
            return false;
        }
        self.sync(&mut g, true);
        drop(g);
        self.unhash();
        true
    }

    fn post(self: &Arc<Self>, g: &mut (TwCb, Option<u64>), out: &Out) {
        self.sync(g, out.done);
        if out.done {
            self.unhash();
        }
    }

    fn send(&self, out: &mut Out) {
        super::send_segs(&self.net, &self.tuple, out, self.params, self.oif);
    }
}

impl TimeWait {
    /// End the entry now: its namespace goes (Linux
    /// inet_twsk_deschedule_put from tcp_twsk_purge): the timer stops,
    /// and the entry leaves the tables
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
        if g.0.next_timer().is_some_and(|at| at > now_ms()) {
            tw.sync(&mut g, false);
            return;
        }
        tw.sync(&mut g, true);
        drop(g);
        tw.unhash();
    }
}
