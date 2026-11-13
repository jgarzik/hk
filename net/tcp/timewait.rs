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

use crate::util::error::KernelError;
use crate::util::kalloc::try_arc_cyclic;
use alloc::sync::{Arc, Weak};

use crate::sync::spin::Mutex;

use super::cb::{Out, TwCb};
use super::output::Tuple;
use super::timer::now_ms;
use crate::net::NetNamespace;
use crate::net::inet::port::BindInfo;
use crate::net::ipv4::IpParams;
use crate::net::skb::SkBuff;
use crate::sync::rcu::RcuPuts;
use crate::time::timer::ArcTimer;
use crate::util::hlist_nulls::NullsLink;
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
    /// Its ehash chain link and bhash owner link (Linux tw_node,
    /// tw_bind_node), and whether its socket took the port with bind()
    pub(super) eh_link: NullsLink,
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
            eh_link: NullsLink::new(),
            bind_link: Link::new(),
            by_bind,
            killed: AtomicBool::new(false),
            rcu_puts: RcuPuts::new(),
            me: me.clone(),
        })
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
        let s = skb.tcp;
        let mut g = self.inner.lock();
        if g.0.tw_syn_ok(&s) {
            self.sync(&mut g, true);
            drop(g);
            self.net.tcp.tw_unhash(self);
            return Some(skb);
        }
        let mut cb = g.0.cb(super::cfg(&self.net));
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

    fn post(self: &Arc<Self>, g: &mut (TwCb, Option<u64>), out: &Out) {
        self.sync(g, out.done);
        if out.done {
            self.net.tcp.tw_unhash(self);
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
        self.net.tcp.tw_unhash(self);
    }

    /// 2MSL passed (`ktimers/N`; Linux tw_timer_handler): the entry
    /// leaves the tables; the timer's reference goes with `tw`
    fn tw_timer(tw: Arc<TimeWait>) {
        let mut out = Out::default();
        let mut g = tw.inner.lock();
        let mut cb = g.0.cb(super::cfg(&tw.net));
        cb.on_timer(now_ms(), &mut out);
        g.0 = TwCb::from_cb(&cb);
        tw.post(&mut g, &out);
        tw.send(&mut out);
        drop(g);
        drop(cb);
    }
}
