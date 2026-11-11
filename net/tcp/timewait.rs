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
//! Locking: `inner` is a `crate::sync::spin::Mutex` in the place of a
//! socket's `TcpSock.lock` slock (thread context only; table and timer
//! locks may be taken under it).

use crate::util::error::KernelError;
use crate::util::kalloc::try_arc_cyclic;
use alloc::sync::{Arc, Weak};

use crate::sync::spin::Mutex;

use super::cb::{Out, TwCb};
use super::output::Tuple;
use super::timer::{self, Expire, Slot};
use crate::net::NetNamespace;
use crate::net::inet::port::BindInfo;
use crate::net::ipv4::IpParams;
use crate::net::skb::SkBuff;
use alloc::boxed::Box;

pub struct TimeWait {
    pub tuple: Tuple,
    /// Port owner record for the bind rules (`tw` set)
    pub bind: BindInfo,
    net: Arc<NetNamespace>,
    params: IpParams,
    oif: u32,
    inner: Mutex<(TwCb, Slot)>,
    me: Weak<TimeWait>,
}

impl TimeWait {
    /// Entry for `cb` (already in TIME_WAIT); register with [`start`]
    pub fn new(
        net: Arc<NetNamespace>,
        tuple: Tuple,
        bind: BindInfo,
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
            inner: Mutex::new((cb, Slot::default())),
            me: me.clone(),
        })
    }

    /// Milliseconds of 2MSL left at `now` (/proc/net/tcp)
    pub fn left(&self, now: u64) -> u64 {
        let g = self.inner.lock();
        g.0.next_timer().map_or(0, |t| t.saturating_sub(now))
    }

    /// Arm the 2MSL timer
    pub fn start(&self) {
        let mut g = self.inner.lock();
        let want = g.0.next_timer();
        timer::rearm(&mut g.1, want, self.me.clone() as Weak<dyn Expire>);
    }

    /// A segment for this tuple (header in `skb.tcp`). Handed back: it
    /// is a new connection's SYN, this entry is gone and the caller
    /// gives it to a listener.
    pub fn rcv(self: &Arc<Self>, skb: Box<SkBuff>, now: u64) -> Option<Box<SkBuff>> {
        let mut out = Out::default();
        let s = skb.tcp;
        let mut g = self.inner.lock();
        if g.0.tw_syn_ok(&s) {
            timer::rearm(&mut g.1, None, self.me.clone() as Weak<dyn Expire>);
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

    fn post(self: &Arc<Self>, g: &mut (TwCb, Slot), out: &Out) {
        let want = if out.done { None } else { g.0.next_timer() };
        timer::rearm(&mut g.1, want, self.me.clone() as Weak<dyn Expire>);
        if out.done {
            self.net.tcp.tw_unhash(self);
        }
    }

    fn send(&self, out: &mut Out) {
        super::send_segs(&self.net, &self.tuple, out, self.params, self.oif);
    }
}

impl Expire for TimeWait {
    fn expire(self: Arc<Self>, id: u64, now: u64) {
        let mut out = Out::default();
        {
            let mut g = self.inner.lock();
            if !timer::fired(&mut g.1, id) {
                return;
            }
            let mut cb = g.0.cb(super::cfg(&self.net));
            cb.on_timer(now, &mut out);
            g.0 = TwCb::from_cb(&cb);
            self.post(&mut g, &out);
            self.send(&mut out);
        }
    }
}
