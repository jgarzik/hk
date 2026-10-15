//! TCP (RFC 9293; Linux net/ipv4/tcp*.c)
//!
//! - `cb`, `input`, `output`, `ack`, `timer`, `cong`: the I/O-free
//!   control block (state machine, queues, options, delayed ACK, RTO,
//!   keepalive, congestion) and the wire format.
//! - this file: the socket (`TcpSock`, ProtoOps, IPPROTO_TCP options),
//!   segment demux (`tcp_rcv`), listeners and their queues, ICMP errors
//!   (`tcp_err`).
//! - `info`: TCP_INFO and /proc/net/tcp.
//! - `table`: ehash / lhash / bhash; `timewait`: TIME_WAIT entries.
//!
//! ## Locking (thread context only; see doc/LOCKING.md, Network)
//!
//! `TcpSock.cb` (`spin::Mutex<Inner>`) is the socket lock: Linux
//! bh_lock_sock and the tcp_sock fields it protects. Segment input
//! (softnet), timers (softnet/0) and the socket calls take it for a
//! bounded step and never sleep or touch user memory under it. Unlike
//! Linux there is no separate owner lock (lock_sock) with a backlog:
//! user calls copy data through a bounded kernel buffer outside the
//! lock and re-check state each step, so input never waits for a
//! sleeping user. Work decided under the lock is returned as an `Out`
//! and done after unlocking: transmit, wakeups, errors (`finish`).
//!
//! Order: `TcpSock.cb` (a listener's before its child's; a child never
//! takes its listener's `cb`) -> tables (`bhash` -> `ehash`, `lhash`) ->
//! `Inet.addr` -> `TcpSock.queue` (listener SYN/accept queues, leaf) ->
//! timer `TIMERS` -> FIB / neighbour / device TX (route lookups).

pub mod ack;
pub mod cb;
pub mod cong;
pub mod info;
pub mod input;
pub mod output;
pub mod table;
#[cfg(test)]
mod tests;
pub mod timer;
pub mod timewait;

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use spin::{Mutex, MutexGuard};

use self::cb::{Cfg, Open, Out, Seg, SegIn, TcpCb, flags};
use self::output::Tuple;
use self::table::Ent;
use self::timer::{Expire, Slot, now_ms};
use self::timewait::TimeWait;
use crate::net::KernelError;
use crate::net::af_inet::{self, IPPROTO_TCP as PROTO_TCP, Inet, SOL_IP, ipf};
use crate::net::icmp::IcmpErr;
use crate::net::inet::fib::RouteType;
use crate::net::inet::port::BindInfo;
use crate::net::inet::route;
use crate::net::ipv4::{self, IPPROTO_TCP, IpParams, Ipv4Addr};
use crate::net::msg::{
    MSG_DONTWAIT, MSG_ERRQUEUE, MSG_MORE, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL, RecvMsg,
    SendMsg,
};
use crate::net::skb::SkBuff;
use crate::net::sock::{RCV_SHUTDOWN, SEND_SHUTDOWN, SHUTDOWN_MASK, Sock, sf};
use crate::net::socket::{
    AF_INET, AF_UNSPEC, OptIn, OptOut, ProtoOps, SIOCINQ, SIOCOUTQ, SO_KEEPALIVE, SOCK_STREAM,
    SOL_SOCKET, shut_bits,
};
use crate::net::{NetNamespace, dev};
use crate::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};

pub use self::cb::TcpState;

/// IPPROTO_TCP options
pub const TCP_NODELAY: i32 = 1;
pub const TCP_MAXSEG: i32 = 2;
pub const TCP_CORK: i32 = 3;
pub const TCP_KEEPIDLE: i32 = 4;
pub const TCP_KEEPINTVL: i32 = 5;
pub const TCP_KEEPCNT: i32 = 6;
pub const TCP_SYNCNT: i32 = 7;
pub const TCP_DEFER_ACCEPT: i32 = 9;
pub const TCP_INFO: i32 = 11;
pub const TCP_QUICKACK: i32 = 12;
pub const TCP_CONGESTION: i32 = 13;
pub const TCP_USER_TIMEOUT: i32 = 18;
pub const TCP_FASTOPEN: i32 = 23;
pub const TCP_NOTSENT_LOWAT: i32 = 25;
/// Linux MAX_TCP_KEEPIDLE / KEEPINTVL / KEEPCNT, MAX_TCP_SYNCNT
const MAX_KEEPIDLE: i32 = 32767;
const MAX_KEEPCNT: i32 = 127;
const MAX_SYNCNT: i32 = 127;

/// Bytes copied between user memory and the queues per locked step
const CHUNK: usize = 64 * 1024;

/// What `TcpSock.cb` protects
struct Inner {
    cb: TcpCb,
    /// Hashed in ehash under this tuple
    tuple: Option<Tuple>,
    /// Owns its local port in bhash
    bound: bool,
    /// The listener of a child still in SYN_RECEIVED
    parent: Option<Weak<TcpSock>>,
    slot: Slot,
}

/// A listener's queues (Linux request_sock_queue + accept queue)
struct Accept {
    backlog: u32,
    /// Children in SYN_RECEIVED (hk keeps full child sockets where Linux
    /// has request socks; the count is bounded by the backlog)
    syn: Vec<Arc<TcpSock>>,
    /// Established, not yet accepted
    ready: VecDeque<Arc<TcpSock>>,
}

impl Accept {
    /// Linux sk_acceptq_is_full
    fn full(&self) -> bool {
        self.ready.len() as u32 > self.backlog
    }
}

/// A TCP socket
pub struct TcpSock {
    pub sk: Sock,
    pub inet: Inet,
    cb: Mutex<Inner>,
    queue: Mutex<Option<Accept>>,
    /// A non-blocking connect is in progress (Linux SS_CONNECTING)
    connecting: AtomicBool,
    /// Serializes readers across peek, user copy and consume (the
    /// reader part of Linux lock_sock; sleeping, above `cb`)
    rd: crate::sync::Mutex<()>,
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

/// Connection knobs from the namespace's sysctls
fn cfg(net: &NetNamespace) -> Cfg {
    let s = &net.sysctl;
    let secs = |v: &core::sync::atomic::AtomicI32| v.load(Ordering::Relaxed).max(1) as u64 * 1000;
    Cfg {
        syn_retries: s.tcp_syn_retries.load(Ordering::Relaxed) as u32,
        synack_retries: s.tcp_synack_retries.load(Ordering::Relaxed) as u32,
        retries2: s.tcp_retries2.load(Ordering::Relaxed) as u32,
        fin_timeout: secs(&s.tcp_fin_timeout),
        wscale: s.tcp_window_scaling.load(Ordering::Relaxed) != 0,
        ts: s.tcp_timestamps.load(Ordering::Relaxed),
        rmem_max: s.tcp_rmem[2].load(Ordering::Relaxed).max(1) as u32,
        keepidle: secs(&s.tcp_keepalive_time),
        keepintvl: secs(&s.tcp_keepalive_intvl),
        keepcnt: s.tcp_keepalive_probes.load(Ordering::Relaxed) as u32,
    }
}

/// RFC 6528 initial sequence number: keyed hash of the tuple plus a
/// 64 ns clock (Linux secure_tcp_seq)
fn isn(t: &Tuple) -> u32 {
    let w = [
        ((t.laddr.0 as u64) << 32) | t.raddr.0 as u64,
        ((t.lport as u64) << 16) | t.rport as u64,
    ];
    let h = crate::net::inet::port::secure_hash(0x7463_7073_6571, &w) as u32;
    h.wrapping_add((crate::time::monotonic_ns() >> 6) as u32)
}

/// Timestamp offset of a connection (Linux secure_tcp_seq_and_ts_off:
/// keyed hash of the four-tuple, RFC 7323 7.1, so the clock leaks
/// neither uptime nor other connections' offsets)
fn ts_off(t: &Tuple) -> u32 {
    let w = [
        ((t.laddr.0 as u64) << 32) | t.raddr.0 as u64,
        ((t.lport as u64) << 16) | t.rport as u64,
    ];
    crate::net::inet::port::secure_hash(0x7463_7074_736f, &w) as u32
}

/// Opening values for `t`
fn open(net: &NetNamespace, t: &Tuple, oif: u32) -> Open {
    Open {
        iss: isn(t),
        ts_off: ts_off(t),
        mss: route_mss(net, t.raddr, t.laddr, oif),
    }
}

/// Transmit `seg` on `t` (route each time; no cached dst)
pub(super) fn xmit(net: &NetNamespace, t: &Tuple, seg: &Seg, p: IpParams, oif: u32) {
    let Some(skb) = output::build(seg, t) else {
        return;
    };
    if let Ok(rt) = route::output(net, t.raddr, t.laddr, oif) {
        let _ = ipv4::ip_send_rt(net, &rt, skb, IPPROTO_TCP, p);
    }
}

/// MSS we advertise toward `daddr` (route MTU - 40)
fn route_mss(net: &NetNamespace, daddr: Ipv4Addr, saddr: Ipv4Addr, oif: u32) -> u32 {
    route::output(net, daddr, saddr, oif)
        .map_or(cb::MSS_DEFAULT, |rt| rt.mtu.saturating_sub(cb::HDRS))
}

impl TcpSock {
    pub fn new(sk: Sock) -> Arc<Self> {
        let mut cb = TcpCb::new(cfg(&sk.net));
        cb.opts.ca = sk.net.sysctl.tcp_ca.load(Ordering::Relaxed) as usize;
        Arc::new_cyclic(|me| Self {
            sk,
            inet: Inet::default(),
            cb: Mutex::new(Inner {
                cb,
                tuple: None,
                bound: false,
                parent: None,
                slot: Slot::default(),
            }),
            queue: Mutex::new(None),
            connecting: AtomicBool::new(false),
            rd: crate::sync::Mutex::new(()),
            me: me.clone(),
        })
    }

    fn arc(&self) -> Arc<TcpSock> {
        self.me.upgrade().expect("tcp socket alive")
    }

    /// The socket lock, with the buffer limits synced from SO_RCVBUF /
    /// SO_SNDBUF (Linux charges about half of them to overhead)
    fn lock(&self) -> MutexGuard<'_, Inner> {
        let mut g = self.cb.lock();
        g.cb.rcv_cap = (self.sk.rcvbuf() / 2) as usize;
        g.cb.snd_cap = (self.sk.sndbuf() / 2) as usize;
        g.cb.rcv_locked = self.sk.flag(sf::RCVBUF_LOCK);
        g
    }

    pub fn state(&self) -> TcpState {
        self.cb.lock().cb.state
    }

    pub(crate) fn bind_info(&self, addr: Ipv4Addr) -> BindInfo {
        BindInfo {
            addr,
            dev: self.sk.bound_dev_if(),
            reuse: self.sk.flag(sf::REUSEADDR),
            reuseport: self.sk.flag(sf::REUSEPORT),
            uid: self.sk.cred.euid,
            listen: self.sk.flag(sf::ACCEPTCONN),
            tw: false,
        }
    }

    fn oif(&self) -> u32 {
        self.sk.bound_dev_if()
    }

    // --- after a control block step -----------------------------------------

    /// Bookkeeping under the lock after `cb` produced `out`: TIME_WAIT
    /// hand-over, leaving the tables, listener queues, timer
    fn post(&self, g: &mut Inner, out: &mut Out) {
        if out.timewait {
            self.to_timewait(g, out);
        }
        if out.established
            && let Some(p) = g.parent.take().and_then(|w| w.upgrade())
        {
            p.child_ready(&self.arc());
        }
        if out.done {
            if let Some(p) = g.parent.take().and_then(|w| w.upgrade()) {
                p.child_gone(self);
            }
            // Like Linux tcp_set_state(TCP_CLOSE): a port fixed by bind()
            // stays until close()
            let keep = !g.cb.orphan && self.inet.get().port_lock;
            self.unhash_conn(g);
            if !keep {
                self.unbind(g);
            }
        }
        let want = g.cb.next_timer();
        timer::rearm(&mut g.slot, want, self.me.clone() as Weak<dyn Expire>);
    }

    /// Hand TIME_WAIT to a timewait entry (Linux tcp_time_wait)
    fn to_timewait(&self, g: &mut Inner, out: &mut Out) {
        let Some(t) = g.tuple.take() else {
            return;
        };
        let mut bind = self.bind_info(t.laddr);
        bind.addr = self.inet.get().rcv_saddr;
        bind.tw = true;
        bind.listen = false;
        let tw = TimeWait::new(
            self.sk.net.clone(),
            t,
            bind,
            self.inet.params(),
            self.oif(),
            g.cb.tw_clone(),
        );
        self.sk.net.tcp.tw_hashdance(&self.arc(), &tw);
        g.bound = false;
        tw.start();
        g.cb.tw_done(out);
    }

    /// Leave ehash (Linux inet_unhash)
    fn unhash_conn(&self, g: &mut Inner) {
        if let Some(t) = g.tuple.take() {
            self.sk.net.tcp.unhash(&t, &self.arc());
        }
    }

    /// Give up the local port (Linux inet_put_port: the number goes too)
    fn unbind(&self, g: &mut Inner) {
        if core::mem::take(&mut g.bound) {
            let mut a = self.inet.addr.lock();
            let port = core::mem::take(&mut a.sport);
            a.port_lock = false;
            drop(a);
            self.sk.net.tcp.unbind(&self.arc(), port);
        }
    }

    /// Run `out` after the lock is dropped: transmit, report, wake
    fn finish(&self, out: Out, t: Option<Tuple>) {
        if let Some(t) = t {
            let p = self.inet.params();
            for seg in &out.segs {
                xmit(&self.sk.net, &t, seg, p, self.oif());
            }
        }
        if out.shut != 0 {
            self.sk.set_shutdown(out.shut);
        }
        if let Some(e) = out.err {
            self.sk.set_err(e);
        }
        if out.wake || out.err.is_some() {
            self.sk.state_change();
        }
    }

    /// Lock, run `f` on the control block, post-process, unlock, finish;
    /// the tuple segments go to is the connection's
    fn step<R>(&self, f: impl FnOnce(&mut Inner, &mut Out) -> R) -> R {
        let mut out = Out::default();
        let (r, t) = {
            let mut g = self.lock();
            let r = f(&mut g, &mut out);
            let t = g.tuple.or_else(|| self.cur_tuple());
            self.post(&mut g, &mut out);
            (r, t)
        };
        self.finish(out, t);
        r
    }

    /// The address part of the socket as a tuple (after the connection
    /// left ehash, e.g. for a final RST)
    fn cur_tuple(&self) -> Option<Tuple> {
        let a = self.inet.get();
        (a.dport != 0).then_some(Tuple {
            laddr: a.saddr,
            lport: a.sport,
            raddr: a.daddr,
            rport: a.dport,
        })
    }

    // --- segment input --------------------------------------------------------

    /// A segment for this connection (Linux tcp_v4_do_rcv)
    fn rcv(&self, s: &SegIn, now: u64) {
        self.step(|g, out| {
            if g.cb.state == TcpState::SynReceived
                && s.has(flags::ACK)
                && g.parent
                    .as_ref()
                    .and_then(|w| w.upgrade())
                    .is_some_and(|p| p.acceptq_full())
            {
                // Linux listen overflow: drop the completing ACK, the
                // SYN-ACK is retransmitted later
                return;
            }
            g.cb.input(s, now, out);
        });
    }

    // --- listener ---------------------------------------------------------------

    fn acceptq_full(&self) -> bool {
        self.queue.lock().as_ref().is_none_or(|q| q.full())
    }

    /// A SYN for this listener (Linux tcp_conn_request): a child in
    /// SYN_RECEIVED answers with SYN-ACK. Dropped when the accept queue
    /// or the SYN queue is full (no syncookies).
    fn listen_rcv(&self, s: &SegIn, t: Tuple, now: u64) {
        if s.has(flags::RST) {
            return;
        }
        if s.has(flags::ACK) {
            // A stray ACK (no request): RST (Linux tcp_rcv_state_process)
            if let Some(r) = output::reset_for(s) {
                xmit(&self.sk.net, &t, &r, IpParams::default(), 0);
            }
            return;
        }
        // Only a plain SYN opens (Linux drops SYN+FIN in LISTEN)
        if !s.has(flags::SYN) || s.has(flags::FIN) {
            return;
        }
        let g = self.cb.lock();
        if g.cb.state != TcpState::Listen {
            return;
        }
        {
            let q = self.queue.lock();
            match q.as_ref() {
                Some(q) if !q.full() && (q.syn.len() as u32) < q.backlog.max(1) => {}
                _ => return,
            }
        }
        let child = self.child(s, t, g.cb.opts, now);
        drop(g);
        if let Some((c, out)) = child {
            c.finish(out, Some(t));
        }
    }

    /// Create, hash and queue a SYN_RECEIVED child (listener locked;
    /// `opts` are the listener's)
    fn child(&self, s: &SegIn, t: Tuple, opts: cb::Opts, now: u64) -> Option<(Arc<TcpSock>, Out)> {
        let c = TcpSock::new(Sock::clone_from(&self.sk));
        c.inet.clone_opts(&self.inet);
        {
            let mut a = c.inet.addr.lock();
            a.rcv_saddr = t.laddr;
            a.saddr = t.laddr;
            a.sport = t.lport;
            a.daddr = t.raddr;
            a.dport = t.rport;
        }
        let mut out = Out::default();
        let o = open(&self.sk.net, &t, self.oif());
        {
            let mut g = c.lock();
            // TCP_SYNCNT of a listener bounds its SYN-ACK retries (Linux
            // reqsk_timer_handler)
            let mut kc = cfg(&self.sk.net);
            if opts.syncnt != 0 {
                kc.synack_retries = opts.syncnt;
            }
            let mut cb = TcpCb::new(kc);
            cb.opts = opts;
            (cb.rcv_cap, cb.snd_cap, cb.rcv_locked) = (g.cb.rcv_cap, g.cb.snd_cap, g.cb.rcv_locked);
            cb.passive(s, o, now, &mut out);
            g.cb = cb;
            if !self.sk.net.tcp.hash(t, &c) {
                return None;
            }
            g.tuple = Some(t);
            self.sk.net.tcp.inherit(&c, t.lport);
            g.bound = true;
            g.parent = Some(self.me.clone());
            if let Some(q) = self.queue.lock().as_mut() {
                q.syn.push(c.clone());
            }
            c.post(&mut g, &mut Out::default());
        }
        Some((c, out))
    }

    /// A child completed its handshake (Linux inet_csk_complete_hashdance)
    fn child_ready(&self, c: &Arc<TcpSock>) {
        {
            let mut q = self.queue.lock();
            let Some(q) = q.as_mut() else {
                return;
            };
            q.syn.retain(|x| !Arc::ptr_eq(x, c));
            q.ready.push_back(c.clone());
        }
        self.sk.data_ready();
    }

    /// A child died before being accepted
    fn child_gone(&self, c: &TcpSock) {
        if let Some(q) = self.queue.lock().as_mut() {
            q.syn.retain(|x| !core::ptr::eq(Arc::as_ptr(x), c));
        }
    }

    /// TCP_SYNCNT or the sysctl
    fn syncnt(&self, o: &cb::Opts) -> u32 {
        match o.syncnt {
            0 => self.sk.net.sysctl.tcp_syn_retries.load(Ordering::Relaxed) as u32,
            v => v,
        }
    }

    // --- user calls -----------------------------------------------------------

    /// Linux tcp_v4_connect: route, local address and port, ISN, SYN
    fn start_connect(&self, daddr: Ipv4Addr, dport: u16) -> Result<(), KernelError> {
        let me = self.arc();
        self.step(|g, out| {
            if g.cb.state != TcpState::Closed {
                return Err(KernelError::AlreadyConnected);
            }
            let a = self.inet.get();
            let rt = route::output(&self.sk.net, daddr, a.saddr, self.oif())?;
            if matches!(rt.rtype, RouteType::Broadcast | RouteType::Multicast) {
                return Err(KernelError::NetworkUnreachable);
            }
            let saddr = if a.saddr.is_unspecified() {
                rt.saddr
            } else {
                a.saddr
            };
            let want = Tuple {
                laddr: saddr,
                lport: a.sport,
                raddr: daddr,
                rport: dport,
            };
            let range = self.sk.net.port_range.get();
            let t = self.sk.net.tcp.connect(&me, want, range)?;
            g.tuple = Some(t);
            if a.sport == 0 {
                g.bound = true;
            }
            {
                let mut ad = self.inet.addr.lock();
                ad.saddr = saddr;
                if ad.rcv_saddr.is_unspecified() {
                    ad.rcv_saddr = saddr;
                }
                ad.sport = t.lport;
                ad.daddr = daddr;
                ad.dport = dport;
            }
            self.sk.clear_shutdown();
            let mut c = cfg(&self.sk.net);
            c.syn_retries = self.syncnt(&g.cb.opts);
            let mut cb = TcpCb::new(c);
            cb.opts = g.cb.opts;
            (cb.rcv_cap, cb.snd_cap, cb.rcv_locked) = (g.cb.rcv_cap, g.cb.snd_cap, g.cb.rcv_locked);
            g.cb = cb;
            let o = Open {
                iss: isn(&t),
                ts_off: ts_off(&t),
                mss: rt.mtu.saturating_sub(cb::HDRS),
            };
            g.cb.connect(o, now_ms(), out);
            Ok(())
        })
    }

    /// Wait for the handshake (Linux inet_wait_for_connect): send timeout
    /// -> EINPROGRESS; failure -> the socket error or ECONNABORTED
    fn wait_connect(&self) -> Result<(), KernelError> {
        let timeo = self.sk.snd_timeo(false);
        let r = self.sk.wait(timeo, || {
            !matches!(self.state(), TcpState::SynSent | TcpState::SynReceived)
        });
        match r {
            Err(KernelError::WouldBlock) => return Err(KernelError::InProgress),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        if self.state() == TcpState::Closed {
            return Err(self.sk.take_err().unwrap_or(KernelError::ConnectionAborted));
        }
        Ok(())
    }

    /// Readers can stop waiting
    fn rx_ready(&self, more_than: usize) -> bool {
        let g = self.cb.lock();
        g.cb.rcvq_len() > more_than
            || self.sk.has_err()
            || self.sk.shutdown() & RCV_SHUTDOWN != 0
            || g.cb.state == TcpState::Closed
    }

    /// Copy (or with MSG_TRUNC drop) up to `want` readable bytes into
    /// `m` at `off`; MSG_PEEK reads past the `off` bytes already peeked
    fn take_rx(
        &self,
        m: &mut RecvMsg,
        off: usize,
        want: usize,
        flags: i32,
    ) -> Result<usize, KernelError> {
        let peek = flags & MSG_PEEK != 0;
        let skip = if peek { off } else { 0 };
        let want = want.min(CHUNK);
        if flags & MSG_TRUNC != 0 && !peek {
            return Ok(self.step(|g, out| g.cb.discard(want, out)));
        }
        let mut buf = alloc::vec![0u8; want];
        let _rd = self.rd.lock();
        let n = self.step(|g, out| g.cb.recv(&mut buf, skip, false, out));
        if n == 0 || flags & MSG_TRUNC != 0 {
            return Ok(n);
        }
        // Consume only what reached user memory (Linux leaves data
        // queued when the copy faults)
        let put = m.data.put(off, &buf[..n])?;
        if !peek {
            self.step(|g, out| g.cb.discard(put, out));
        }
        Ok(put)
    }

    /// Writers can stop waiting
    fn tx_ready(&self) -> bool {
        let g = self.cb.lock();
        g.cb.writable()
            || self.sk.has_err()
            || !matches!(g.cb.state, TcpState::Established | TcpState::CloseWait)
            || self.sk.shutdown() & SEND_SHUTDOWN != 0
    }

    /// Queue `data` (Linux tcp_sendmsg_locked step; `more`: MSG_MORE
    /// holds a partial last segment); Err if the connection cannot send
    fn push(&self, data: &[u8], more: bool) -> Result<usize, KernelError> {
        self.step(|g, out| {
            if self.sk.has_err() {
                return Err(self.sk.take_err().unwrap_or(KernelError::BrokenPipe));
            }
            if self.sk.shutdown() & SEND_SHUTDOWN != 0
                || !matches!(g.cb.state, TcpState::Established | TcpState::CloseWait)
            {
                return Err(KernelError::BrokenPipe);
            }
            let n = g.cb.send(data);
            if n > 0 && more {
                g.cb.output_more(now_ms(), out);
            } else if n > 0 {
                g.cb.output(now_ms(), out);
            }
            Ok(n)
        })
    }

    /// Abort children of a closed listener (Linux inet_csk_listen_stop)
    fn listen_stop(&self, q: Accept) {
        for c in q.syn.into_iter().chain(q.ready) {
            c.step(|g, out| {
                g.parent = None;
                g.cb.close(true, now_ms(), out);
            });
        }
    }

    /// Linux tcp_disconnect (connect(AF_UNSPEC)): abort, stop listening,
    /// back to an unconnected socket keeping a bind()-fixed address/port
    fn disconnect(&self) {
        let q = self.step(|g, out| {
            let q = if g.cb.state == TcpState::Listen {
                self.sk.set_flag(sf::ACCEPTCONN, false);
                self.sk
                    .net
                    .tcp
                    .listen_del(self.inet.get().sport, &self.arc());
                self.queue.lock().take()
            } else {
                None
            };
            g.cb.abort(out);
            out.shut = 0;
            q
        });
        if let Some(q) = q {
            self.listen_stop(q);
        }
        self.sk.clear_shutdown();
        dev::netif_rx_flush_local();
        let mut ad = self.inet.addr.lock();
        ad.daddr = Ipv4Addr::default();
        ad.dport = 0;
        if !ad.addr_lock {
            ad.saddr = Ipv4Addr::default();
            ad.rcv_saddr = Ipv4Addr::default();
        }
    }

    /// Wait for the close handshake up to SO_LINGER seconds (Linux
    /// sk_stream_wait_close)
    fn linger_wait(&self) {
        if !self.sk.flag(sf::LINGER) || self.sk.linger_secs() == 0 {
            return;
        }
        let ns = self.sk.linger_secs() as u64 * 1_000_000_000;
        let _ = self.sk.wait(ns, || {
            !matches!(
                self.state(),
                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
            )
        });
    }
}

impl Expire for TcpSock {
    fn expire(self: Arc<Self>, id: u64, now: u64) {
        self.step(|g, out| {
            timer::fired(&mut g.slot, id);
            g.cb.on_timer(now, out);
        });
    }
}

// ============================================================================
// Segment demux (Linux tcp_v4_rcv)
// ============================================================================

/// Receive a TCP segment (softnet or an inline loopback flush; thread
/// context). Lookups use the receiving device's namespace.
pub fn tcp_rcv(skb: SkBuff) {
    let (Some(net), Some(saddr), Some(daddr)) = (skb.net(), skb.saddr, skb.daddr) else {
        return;
    };
    // Unicast to us only (Linux: pkt_type != PACKET_HOST is dropped)
    if skb.ip_bcast {
        return;
    }
    if output::checksum(saddr, daddr, skb.data()) != 0 {
        return;
    }
    let Some((sport, dport, s)) = output::parse(skb.data()) else {
        return;
    };
    let t = Tuple {
        laddr: daddr,
        lport: dport,
        raddr: saddr,
        rport: sport,
    };
    let now = now_ms();
    match net.tcp.lookup(&t) {
        Some(Ent::Sk(sk)) => return sk.rcv(&s, now),
        // A TIME_WAIT entry consumes it unless it is a new SYN
        Some(Ent::Tw(tw)) if tw.rcv(&s, now) => return,
        _ => {}
    }
    let dif = skb.dev.as_ref().map_or(0, |d| d.ifindex());
    if let Some(l) = net.tcp.listener(daddr, dport, dif) {
        return l.listen_rcv(&s, t, now);
    }
    // No socket: reset (never answer a RST)
    if let Some(r) = output::reset_for(&s) {
        xmit(&net, &t, &r, IpParams::default(), 0);
    }
}

/// An ICMP error quoting one of our segments (Linux tcp_v4_err)
pub fn tcp_err(net: &NetNamespace, e: &IcmpErr) {
    let l4 = e.l4();
    if l4.len() < 8 {
        return;
    }
    let t = Tuple {
        laddr: e.inner_saddr(),
        lport: u16::from_be_bytes([l4[0], l4[1]]),
        raddr: e.inner_daddr(),
        rport: u16::from_be_bytes([l4[2], l4[3]]),
    };
    let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
    let Some(Ent::Sk(s)) = net.tcp.lookup(&t) else {
        return;
    };
    let pmtudisc = s.inet.pmtudisc();
    let Some((err, _)) = e.errno(pmtudisc) else {
        return;
    };
    let frag = err == KernelError::MessageTooLong;
    let recverr = s.inet.flag(ipf::RECVERR);
    let mut syn_err = false;
    s.step(|g, out| {
        if !cb::between(seq, g.cb.snd_una, g.cb.snd_max) {
            return;
        }
        if frag {
            g.cb.pmtu(e.info, now_ms(), out);
            return;
        }
        match g.cb.state {
            TcpState::SynSent | TcpState::SynReceived => {
                if g.parent.is_some() {
                    // A listener's child: drop it quietly (Linux tcp_req_err)
                    g.cb.set_closed(out);
                } else {
                    syn_err = true;
                    g.cb.fail(err, out);
                }
            }
            _ if recverr => out.err = Some(err),
            _ => g.cb.soft_err = Some(err),
        }
    });
    if syn_err && recverr {
        af_inet::ip_icmp_error(&s.sk, e, err, t.rport, &l4[..8]);
    }
}

// ============================================================================
// recvmsg / sendmsg
// ============================================================================

/// Linux tcp_recvmsg main loop (no urgent data)
fn tcp_recvmsg(s: &TcpSock, m: &mut RecvMsg, flags: i32) -> Result<usize, KernelError> {
    if s.state() == TcpState::Listen {
        return Err(KernelError::NotConnected);
    }
    if flags & MSG_ERRQUEUE != 0 {
        return af_inet::ip_recv_error(&s.sk, &s.inet, m);
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
        while copied < len {
            let n = match s.take_rx(m, copied, len - copied, flags) {
                Ok(n) => n,
                Err(_) if copied > 0 => return Ok(copied),
                Err(e) => return Err(e),
            };
            if n == 0 {
                break;
            }
            copied += n;
        }
        if copied >= target.max(1) || len == 0 {
            break;
        }
        if copied > 0 {
            if s.sk.has_err()
                || s.sk.shutdown() & RCV_SHUTDOWN != 0
                || s.state() == TcpState::Closed
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
            if s.state() == TcpState::Closed {
                return Err(KernelError::NotConnected);
            }
        }
        if flags & MSG_PEEK != 0 && copied > 0 {
            break;
        }
        let more = if flags & MSG_PEEK != 0 { copied } else { 0 };
        match s.sk.wait(timeo, || s.rx_ready(more)) {
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
    dev::netif_rx_flush_local();
    Ok(copied)
}

/// sk_stream_wait_connect: wait while the handshake runs
fn wait_connected(s: &TcpSock, timeo: &mut u64) -> Result<(), KernelError> {
    loop {
        if let Some(e) = s.sk.take_err() {
            return Err(e);
        }
        if s.sk.shutdown() & SEND_SHUTDOWN != 0 {
            return Err(KernelError::BrokenPipe);
        }
        match s.state() {
            TcpState::Established | TcpState::CloseWait => return Ok(()),
            TcpState::SynSent | TcpState::SynReceived => {
                *timeo = s.sk.wait(*timeo, || {
                    !matches!(s.state(), TcpState::SynSent | TcpState::SynReceived)
                })?;
            }
            _ => return Err(KernelError::BrokenPipe),
        }
    }
}

/// Linux tcp_sendmsg: queue everything (blocking) or what fits
/// (non-blocking), copying through a bounded kernel buffer
fn tcp_sendmsg(s: &TcpSock, m: &mut SendMsg, flags: i32) -> Result<usize, KernelError> {
    if flags & MSG_OOB != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    let mut timeo = s.sk.snd_timeo(flags & MSG_DONTWAIT != 0);
    wait_connected(s, &mut timeo)?;
    let total = m.data.len();
    let mut sent = 0;
    let mut buf: Vec<u8> = Vec::new();
    let mut at = 0;
    let r = loop {
        if sent == total {
            break Ok(());
        }
        if at == buf.len() {
            buf = match m.data.take_at(sent, (total - sent).min(CHUNK)) {
                Ok(b) => b,
                Err(e) => break Err(e),
            };
            at = 0;
        }
        // MSG_MORE holds only the last piece (Linux tcp_push)
        let more = flags & MSG_MORE != 0 || (total - sent > buf.len() - at);
        let n = match s.push(&buf[at..], more) {
            Ok(n) => n,
            Err(e) => break Err(e),
        };
        at += n;
        sent += n;
        dev::netif_rx_flush_local();
        if n == 0 && cb::mem_free() == 0 {
            // Global TCP memory pressure: nobody wakes us when other
            // connections free memory, so poll (Linux sk_stream_wait_memory
            // under pressure also sleeps a short random time)
            if timeo == 0 {
                break Err(KernelError::WouldBlock);
            }
            let step = timeo.min(20_000_000);
            let _ = s.sk.wait(step, || false);
            if timeo != crate::net::sock::TIMEO_FOREVER {
                timeo -= step;
            }
        } else if n == 0
            && let Err(e) = s.sk.wait(timeo, || s.tx_ready()).map(|t| timeo = t)
        {
            break Err(e);
        }
    };
    match r {
        Err(_) if sent > 0 => Ok(sent),
        Err(e) => Err(e),
        Ok(()) => Ok(sent),
    }
}

// ============================================================================
// ProtoOps
// ============================================================================

impl ProtoOps for TcpSock {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sk(&self) -> &Sock {
        &self.sk
    }

    /// Last close (Linux tcp_close)
    fn release(&self) {
        self.sk.set_shutdown(SHUTDOWN_MASK);
        let linger0 = self.sk.flag(sf::LINGER) && self.sk.linger_secs() == 0;
        let q = self.step(|g, out| {
            g.cb.orphan = true;
            if g.cb.state == TcpState::Listen {
                self.sk.set_flag(sf::ACCEPTCONN, false);
                self.sk
                    .net
                    .tcp
                    .listen_del(self.inet.get().sport, &self.arc());
                g.cb.set_closed(out);
                return self.queue.lock().take();
            }
            g.cb.close(linger0, now_ms(), out);
            if g.cb.state == TcpState::Closed {
                out.done = true;
            }
            None
        });
        if let Some(q) = q {
            self.listen_stop(q);
        }
        dev::netif_rx_flush_local();
        self.linger_wait();
    }

    /// Linux inet_bind for TCP
    fn bind(&self, a: &[u8]) -> Result<(), KernelError> {
        let (addr, port, ty) = af_inet::bind_check(&self.sk, &self.inet, a)?;
        if matches!(ty, RouteType::Multicast | RouteType::Broadcast) {
            return Err(KernelError::AddressNotAvailable);
        }
        let me = self.arc();
        let mut g = self.lock();
        if g.cb.state != TcpState::Closed || self.inet.get().sport != 0 {
            return Err(KernelError::InvalidArgument);
        }
        let no_port = port == 0 && self.inet.flag(ipf::BIND_NO_PORT);
        let p = if no_port {
            0
        } else {
            let range = self.sk.net.port_range.get();
            let p = self
                .sk
                .net
                .tcp
                .bind(&me, &self.bind_info(addr), port, range)?;
            g.bound = true;
            p
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
            self.disconnect();
            return Ok(());
        }
        let state = self.state();
        if matches!(state, TcpState::SynSent | TcpState::SynReceived) {
            if nonblock {
                return Err(KernelError::AlreadyInProgress);
            }
            let r = self.wait_connect();
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
        dev::netif_rx_flush_local();
        r?;
        if nonblock {
            self.connecting.store(true, Ordering::Release);
            return Err(KernelError::InProgress);
        }
        self.wait_connect()
    }

    /// Linux inet_listen (autobinds an unbound socket); a listening
    /// socket only gets its backlog updated
    fn listen(&self, backlog: i32) -> Result<(), KernelError> {
        // Linux __sys_listen: capped at net.core.somaxconn
        let backlog = (backlog as u32).min(self.sk.net.sysctl.somaxconn());
        let me = self.arc();
        let mut g = self.lock();
        match g.cb.state {
            TcpState::Listen => {
                if let Some(q) = self.queue.lock().as_mut() {
                    q.backlog = backlog;
                }
                return Ok(());
            }
            TcpState::Closed if g.tuple.is_none() => {}
            _ => return Err(KernelError::InvalidArgument),
        }
        let a = self.inet.get();
        if a.sport == 0 {
            let range = self.sk.net.port_range.get();
            let p = self
                .sk
                .net
                .tcp
                .bind(&me, &self.bind_info(a.rcv_saddr), 0, range)?;
            g.bound = true;
            self.inet.addr.lock().sport = p;
        } else if !self
            .sk
            .net
            .tcp
            .can_listen(&me, &self.bind_info(a.rcv_saddr), a.sport)
        {
            return Err(KernelError::AddressInUse);
        }
        *self.queue.lock() = Some(Accept {
            backlog,
            syn: Vec::new(),
            ready: VecDeque::new(),
        });
        g.cb.state = TcpState::Listen;
        self.sk.set_flag(sf::ACCEPTCONN, true);
        self.sk.net.tcp.listen_add(self.inet.get().sport, me);
        Ok(())
    }

    /// Linux inet_csk_accept: waits up to SO_RCVTIMEO
    fn accept(&self, nonblock: bool) -> Result<Arc<dyn ProtoOps>, KernelError> {
        if self.state() != TcpState::Listen {
            return Err(KernelError::InvalidArgument);
        }
        let mut timeo = self.sk.rcv_timeo(nonblock);
        loop {
            let c = self.queue.lock().as_mut().and_then(|q| q.ready.pop_front());
            if let Some(c) = c {
                return Ok(c);
            }
            if self.state() != TcpState::Listen {
                return Err(KernelError::InvalidArgument);
            }
            let ready = || {
                self.queue
                    .lock()
                    .as_ref()
                    .is_none_or(|q| !q.ready.is_empty())
                    || self.state() != TcpState::Listen
            };
            timeo = self.sk.wait(timeo, ready)?;
        }
    }

    fn getname(&self, peer: bool) -> Result<Vec<u8>, KernelError> {
        let a = self.inet.get();
        if peer {
            if a.dport == 0 || matches!(self.state(), TcpState::Closed | TcpState::SynSent) {
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
        let g = self.cb.lock();
        let state = g.cb.state;
        if state == TcpState::Listen {
            drop(g);
            let ready = self
                .queue
                .lock()
                .as_ref()
                .is_some_and(|q| !q.ready.is_empty());
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
            if g.cb.rcvq_len() >= self.sk.rcvlowat().max(1) as usize {
                mask |= POLLIN | POLLRDNORM;
            }
            if sh & SEND_SHUTDOWN != 0 || g.cb.writable() {
                mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
            }
        }
        if self.sk.err_pending() {
            mask |= POLLERR;
        }
        mask
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        let g = self.cb.lock();
        if matches!(cmd, SIOCINQ | SIOCOUTQ) && g.cb.state == TcpState::Listen {
            return Err(KernelError::InvalidArgument);
        }
        let v = match cmd {
            SIOCINQ => g.cb.rcvq_len(),
            SIOCOUTQ => g.cb.sndq_len(),
            _ => return Err(KernelError::NotTty),
        };
        drop(g);
        crate::uaccess::put_user::<crate::arch::Uaccess, i32>(arg, v as i32)
            .map_err(|_| KernelError::BadAddress)?;
        Ok(0)
    }

    fn inq(&self) -> usize {
        self.cb.lock().cb.rcvq_len()
    }

    /// Linux inet_shutdown + tcp_shutdown
    fn shutdown(&self, how: i32) -> Result<(), KernelError> {
        let bits = shut_bits(how)?;
        let state = self.state();
        let r = match state {
            TcpState::Closed => {
                self.sk.set_shutdown(bits);
                Err(KernelError::NotConnected)
            }
            TcpState::Listen => {
                // Linux inet_shutdown: stop listening (disconnect)
                if bits & RCV_SHUTDOWN != 0 {
                    self.disconnect();
                }
                Ok(())
            }
            TcpState::SynSent => {
                // Linux: disconnect, back to unconnected
                self.disconnect();
                Ok(())
            }
            _ => {
                self.sk.set_shutdown(bits);
                self.step(|g, out| {
                    if bits & RCV_SHUTDOWN != 0 {
                        g.cb.rcv_shut = true;
                    }
                    if bits & SEND_SHUTDOWN != 0 {
                        g.cb.shutdown_wr(now_ms(), out);
                    }
                });
                dev::netif_rx_flush_local();
                Ok(())
            }
        };
        self.sk.state_change();
        r
    }

    fn setsockopt(&self, level: i32, opt: i32, v: OptIn) -> Option<Result<(), KernelError>> {
        match level {
            SOL_SOCKET if opt == SO_KEEPALIVE => Some(self.set_keepalive(v)),
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
        tcp_sendmsg(self, m, flags)
    }

    fn recvmsg(&self, m: &mut RecvMsg, flags: i32) -> Result<usize, KernelError> {
        tcp_recvmsg(self, m, flags)
    }
}

impl TcpSock {
    /// IPPROTO_TCP setsockopt (Linux do_tcp_setsockopt)
    fn set_tcp_opt(&self, opt: i32, v: OptIn) -> Result<(), KernelError> {
        if opt == TCP_CONGESTION {
            return self.set_congestion(v);
        }
        let val = v.int()?;
        let bad = || Err(KernelError::InvalidArgument);
        let now = now_ms();
        self.step(|g, out| {
            match opt {
                TCP_NODELAY => {
                    g.cb.opts.nodelay = val != 0;
                    if val != 0 {
                        g.cb.output(now, out);
                    }
                }
                TCP_CORK => {
                    g.cb.opts.cork = val != 0;
                    if val == 0 {
                        g.cb.output(now, out);
                    }
                }
                TCP_QUICKACK => g.cb.set_quickack(val, out),
                TCP_MAXSEG if val != 0 && !(88..=65535).contains(&val) => return bad(),
                TCP_MAXSEG => g.cb.opts.user_mss = val as u32,
                TCP_KEEPIDLE if !(1..=MAX_KEEPIDLE).contains(&val) => return bad(),
                TCP_KEEPIDLE => {
                    g.cb.opts.keepidle = val as u32;
                    g.cb.arm_keepalive(now);
                }
                TCP_KEEPINTVL if !(1..=MAX_KEEPIDLE).contains(&val) => return bad(),
                TCP_KEEPINTVL => g.cb.opts.keepintvl = val as u32,
                TCP_KEEPCNT if !(1..=MAX_KEEPCNT).contains(&val) => return bad(),
                TCP_KEEPCNT => g.cb.opts.keepcnt = val as u32,
                TCP_SYNCNT if !(1..=MAX_SYNCNT).contains(&val) => return bad(),
                TCP_SYNCNT => g.cb.opts.syncnt = val as u32,
                TCP_USER_TIMEOUT if val < 0 => return bad(),
                TCP_USER_TIMEOUT => g.cb.opts.user_timeout = val as u32,
                TCP_DEFER_ACCEPT => g.cb.opts.defer_accept = info::secs_to_retrans(val),
                TCP_FASTOPEN => {
                    if val < 0 || !matches!(g.cb.state, TcpState::Closed | TcpState::Listen) {
                        return bad();
                    }
                    g.cb.opts.fastopen = (val as u32).min(self.sk.net.sysctl.somaxconn());
                }
                TCP_NOTSENT_LOWAT => {
                    g.cb.opts.notsent_lowat = val as u32;
                    out.wake = true;
                }
                _ => return Err(KernelError::NoProtocolOption),
            }
            Ok(())
        })
    }

    /// TCP_CONGESTION: a NUL-terminated name of a built-in algorithm
    /// (Linux tcp_set_congestion_control: ENOENT when none matches)
    fn set_congestion(&self, v: OptIn) -> Result<(), KernelError> {
        if v.len < 1 {
            return Err(KernelError::InvalidArgument);
        }
        let b = v.bytes(cong::NAME_MAX - 1)?;
        let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        let name = core::str::from_utf8(&b[..n]).map_err(|_| KernelError::NotFound)?;
        let i = cong::find(name).ok_or(KernelError::NotFound)?;
        let mut g = self.lock();
        g.cb.opts.ca = i;
        g.cb.cong.set_algo(i);
        Ok(())
    }

    /// IPPROTO_TCP getsockopt (Linux do_tcp_getsockopt)
    fn get_tcp_opt(&self, opt: i32) -> Result<OptOut, KernelError> {
        let g = self.lock();
        let o = &g.cb.opts;
        let v = match opt {
            TCP_INFO => return Ok(OptOut::Bytes(info::tcp_info(&g.cb, now_ms()))),
            TCP_CONGESTION => {
                let mut b = alloc::vec![0u8; cong::NAME_MAX];
                let name = g.cb.cong.name().as_bytes();
                b[..name.len()].copy_from_slice(name);
                return Ok(OptOut::Bytes(b));
            }
            TCP_MAXSEG => {
                // Linux: mss_cache, or the user's value when not connected
                let closed = matches!(g.cb.state, TcpState::Closed | TcpState::Listen);
                if closed && o.user_mss != 0 {
                    o.user_mss
                } else if closed {
                    cb::MSS_DEFAULT
                } else {
                    g.cb.mss
                }
            }
            TCP_NODELAY => o.nodelay as u32,
            TCP_CORK => o.cork as u32,
            TCP_QUICKACK => g.cb.quickack() as u32,
            TCP_KEEPIDLE => g.cb.keep_idle() as u32 / 1000,
            TCP_KEEPINTVL => g.cb.keep_intvl() as u32 / 1000,
            TCP_KEEPCNT => g.cb.keep_cnt(),
            TCP_SYNCNT => self.syncnt(o),
            TCP_USER_TIMEOUT => o.user_timeout,
            TCP_DEFER_ACCEPT => info::retrans_to_secs(o.defer_accept),
            TCP_FASTOPEN => o.fastopen,
            TCP_NOTSENT_LOWAT => o.notsent_lowat,
            _ => return Err(KernelError::NoProtocolOption),
        };
        Ok(OptOut::Int(v as i32))
    }

    /// SO_KEEPALIVE: the generic flag plus the keepalive timer (Linux
    /// sk_setsockopt -> tcp_set_keepalive)
    fn set_keepalive(&self, v: OptIn) -> Result<(), KernelError> {
        crate::net::socket::sock_setsockopt(self, SO_KEEPALIVE, v)?;
        let on = self.sk.flag(sf::KEEPALIVE);
        self.step(|g, _| g.cb.set_keepalive(on, now_ms()));
        Ok(())
    }
}
