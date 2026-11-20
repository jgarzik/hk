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
//! `TcpSock.lock` (`net::sock_lock::SockLock<Inner>`, Linux
//! socket_lock_t) guards the tcp_sock state (`Inner`: the I/O-free
//! `TcpCb`, tuple, port ownership, listener link, timer slot). Socket
//! calls own it (Linux lock_sock) across user copies and sleeps:
//! recvmsg copies straight from the receive queue to user memory and
//! sendmsg straight into the send queue, releasing it only while
//! asleep (Linux sk_wait_event). Segment input (softnet), timers
//! (`ktimers/N`, embedded: `timer.rs`) and ICMP errors take its `slock` (Linux bh_lock_sock):
//! if nobody owns the socket they run at once under it (Linux
//! tcp_v4_do_rcv), else input waits in the backlog (Linux
//! tcp_add_backlog) and timers and errors leave deferred flags; the
//! owner's release runs both (`SockHooks`: `backlog_rcv`, `release_cb`,
//! Linux tcp_release_cb) before it lets go.
//!
//! A locked step's `Out` is applied before the step ends, like Linux
//! transmitting under the socket lock: segments are transmitted (so
//! two CPUs never reorder one connection's segments), the error and
//! shutdown bits and the lockless view (`Snap`: state, queue sizes,
//! writability, send window edges, Linux's READ_ONCE fields that
//! tcp_poll, the waits and tcp_v4_err read) are published. The fields
//! /proc/net/tcp reads beyond `Snap` (timers, RTO, cwnd, ...) are the
//! block's own `cb::Live` cells, stored where they change and read with
//! no lock (`TcpSock.live`; Linux get_tcp4_sock's racy reads). Wakeups,
//! SIGIO included, run in the step: from the owner, or under `slock`
//! (unowned input, timers and errors; `release_cb`), as Linux. Transmitting never re-enters a socket lock: `lo`
//! queues to the receive backlog and `netif_rx_flush_local` runs only
//! with no lock held.
//!
//! Order: `TcpSock.lock` owner (sleeping) -> its `slock` (one
//! socket's at a time: a listener's SYN path takes none, its new child
//! is set up under the child's own) -> tables (`bhash` -> `ehash`,
//! `lhash`) -> `Inet.addr` ->
//! `TcpSock.queue` (listener SYN/accept queues, leaf) -> the
//! timer bases (the socket's timers); and either -> FIB / neighbour / device TX (transmit).

pub mod ack;
pub mod cb;
pub mod cong;
pub mod cubic;
pub mod info;
pub mod input;
pub mod mem;
pub mod output;
pub mod recovery;
pub mod sack;
pub mod table;
#[cfg(test)]
mod tests;
pub mod timer;
pub mod timewait;

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicUsize, Ordering};

use crate::net::sock_lock::{BhGuard, SockGuard, SockHooks, SockLock};
use crate::sync::spin::Mutex;
use crate::sync::waitqueue::Relock;
use crate::util::kalloc::{try_arc, try_arc_cyclic};

use self::cb::{Cfg, Open, Out, Seg, SegIn, TcpCb, flags};
use self::output::Tuple;
use self::table::Ent;
use self::timer::now_ms;
use self::timewait::{TimeWait, TwCb};
use crate::io::fasync::{POLL_HUP, POLL_IN, POLL_OUT};
use crate::io::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};
use crate::mm::page_alloc::Gfp;
use crate::net::KernelError;
use crate::net::af_inet::{self, IPPROTO_TCP as PROTO_TCP, Inet, SOL_IP, ipf};
use crate::net::icmp::IcmpErr;
use crate::net::inet::fib::RouteType;
use crate::net::inet::port::BindInfo;
use crate::net::inet::route;
use crate::net::ipv4::{self, IPPROTO_TCP, IpParams, Ipv4Addr};
use crate::net::mib::*;
use crate::net::msg::{
    MSG_DONTWAIT, MSG_ERRQUEUE, MSG_MORE, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL, RecvMsg,
    SendMsg,
};
use crate::net::skb::SkBuff;
use crate::net::sock::{RCV_SHUTDOWN, SEND_SHUTDOWN, SHUTDOWN_MASK, Sock, WakeHow, sf};
use crate::net::socket::{
    AF_INET, AF_UNSPEC, OptIn, OptOut, ProtoOps, SIOCINQ, SIOCOUTQ, SO_KEEPALIVE, SO_RCVLOWAT,
    SOCK_STREAM, SOL_SOCKET, shut_bits,
};
use crate::net::{NetNamespace, dev};
use crate::sync::rcu::RcuPuts;
use crate::time::timer::ArcTimer;
use crate::util::hlist_nulls::NullsLink;
use crate::util::kalloc::with_gfp;
use crate::util::list::{Link, OwnedList, Owner};

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

/// Work left for the owner's release (Linux sk_tsq_flags
/// TCP_*_DEFERRED)
mod deferred {
    /// A timer fired (Linux TCP_WRITE_TIMER_DEFERRED,
    /// TCP_DELACK_TIMER_DEFERRED)
    pub const TIMER: u32 = 1;
    /// ICMP frag needed: `TcpSock.mtu_info` (Linux
    /// TCP_MTU_REDUCED_DEFERRED)
    pub const MTU: u32 = 2;
    /// Another ICMP error: `TcpSock.err_soft` becomes the soft error
    /// (Linux sk_err_soft, written while owned)
    pub const ERR: u32 = 4;
}

/// Mark the connection orphaned (Linux sock_orphan with the
/// tcp_orphan_count increment): counted once until destroyed
fn orphan(g: &mut Inner) {
    g.cb.orphan = true;
    g.orphan.get_or_insert_with(mem::Orphan::new);
}

/// What `TcpSock.lock` protects
struct Inner {
    cb: TcpCb,
    /// Hashed in ehash under this tuple
    tuple: Option<Tuple>,
    /// Its ehash entry while hashed (set and taken with `tuple`)
    eh: Option<Arc<table::Eh>>,
    /// Owns its local port in bhash
    bound: bool,
    /// The listener of a child still in SYN_RECEIVED
    parent: Option<Weak<TcpSock>>,
    /// The deadline (ms) each of `TcpSock.timers` was last armed for
    armed: [Option<u64>; 3],
    /// A non-blocking connect is in progress (Linux sock->state
    /// SS_CONNECTING, under lock_sock)
    connecting: bool,
    /// Counted as an orphan (`cb.orphan`) until destroyed
    orphan: Option<mem::Orphan>,
}

/// A listener's queues (Linux request_sock_queue + accept queue):
/// children linked through their own `accept_link` (Linux
/// rskq_accept_head through req->dl_next), on one list at a time, which
/// their `accept_owner` names, so a child leaves either in O(1)
struct Accept {
    backlog: u32,
    /// Children in SYN_RECEIVED (hk keeps full child sockets where Linux
    /// has request socks; the count is bounded by the backlog)
    syn: OwnedList<AcceptLink>,
    /// Established, not yet accepted
    ready: OwnedList<AcceptLink>,
}

crate::owned_adapter!(AcceptLink, TcpSock, accept_link, accept_owner);

impl Accept {
    /// Linux sk_acceptq_is_full
    fn full(&self) -> bool {
        self.ready.len() as u32 > self.backlog
    }
}

/// A connection as lockless readers see it (Linux's fields tcp_poll,
/// the sk_wait_event conditions and tcp_v4_err read with READ_ONCE):
/// stored at the end of every locked step (the owner's, or under
/// `slock` when unowned: one writer at a time), read with no lock
#[derive(Default)]
struct Snap {
    /// `TcpState::linux()` (Linux sk_state)
    state: AtomicU8,
    /// Readable bytes (Linux tcp_inq)
    rcvq: AtomicUsize,
    /// Bytes queued for sending (Linux write_seq - snd_una)
    sndq: AtomicUsize,
    /// Linux sk_stream_is_writeable
    writable: AtomicBool,
    /// Linux snd_una / snd_nxt (the ICMP error sequence check)
    snd_una: AtomicU32,
    snd_max: AtomicU32,
}

impl Snap {
    /// Publish `c` (Release: a reader that sees a new value sees the
    /// queue it describes)
    fn store(&self, c: &TcpCb) {
        self.rcvq.store(c.rcvq_len(), Ordering::Release);
        self.sndq.store(c.sndq_len(), Ordering::Release);
        self.writable.store(c.writable(), Ordering::Release);
        self.snd_una.store(c.snd_una, Ordering::Release);
        self.snd_max.store(c.snd_max, Ordering::Release);
        self.state.store(c.state.linux(), Ordering::Release);
    }
}

/// A TCP socket
pub struct TcpSock {
    pub sk: Sock,
    pub inet: Inet,
    lock: SockLock<Inner>,
    queue: Mutex<Option<Accept>>,
    /// Children ready to accept (Linux sk_ack_backlog): changed under
    /// `queue` with its `ready` list (sk_acceptq_added / removed),
    /// read lock-free by poll, accept's wait and /proc (READ_ONCE)
    ack_backlog: AtomicU32,
    snap: Snap,
    /// Its control block's fields /proc/net/tcp reads with no lock
    /// (`cb::Live`, shared with the block)
    live: Arc<cb::Live>,
    /// MTU of an ICMP frag needed met while owned (Linux tp->mtu_info)
    mtu_info: AtomicU32,
    /// errno of another ICMP error met while owned (Linux sk_err_soft)
    err_soft: AtomicI32,
    /// The retransmit, delayed ACK and keepalive timers (`timer::RTX`,
    /// `DELACK`, `KEEPALIVE`; Linux icsk_retransmit_timer,
    /// icsk_delack_timer, sk_timer), armed by `sync_timers` under the
    /// socket lock
    timers: [ArcTimer<TcpSock>; 3],
    /// Its lhash chain link (its ehash entry is `Inner.eh`), its bhash
    /// owner link (sk_bind_node) and whether it took the port with
    /// bind()/listen() (written under the bhash chain lock)
    lh_link: NullsLink,
    bind_link: Link,
    by_bind: AtomicBool,
    /// The tables' references, dropped a grace period after unhashing
    /// Counted in its namespace's INUSE_TCP (`table::tcp_inuse`)
    pub(super) inuse: AtomicBool,
    rcu_puts: RcuPuts,
    /// A child's place on its listener's SYN or accept queue
    accept_link: Link,
    /// The accept queue `accept_link` is on
    accept_owner: Owner,
    /// A listener's options as its children inherit them, for the
    /// lockless SYN path (Linux reads the listener's fields with no
    /// lock): copied at the end of every locked step in LISTEN; leaf
    listen_opts: Mutex<cb::Opts>,
    me: Weak<TcpSock>,
}

crate::rcu_puts!(TcpSock, rcu_puts);

/// The owner of a TCP socket
type Guard<'a> = SockGuard<'a, Inner, TcpSock>;

/// The wakeups of a locked step, made before it ends
#[must_use]
struct Wake {
    /// `cb::wake` bits
    w: u8,
    /// A listener a child became acceptable for
    ready: Option<Arc<TcpSock>>,
}

/// socket(AF_INET, SOCK_STREAM, 0)
pub fn create() -> Result<Arc<dyn ProtoOps>, KernelError> {
    Ok(TcpSock::new(Sock::new(
        crate::net::current_net_ns(),
        AF_INET,
        SOCK_STREAM,
        PROTO_TCP,
    ))?)
}

/// Connection knobs from the namespace's sysctls
pub(super) fn cfg(net: &NetNamespace) -> Cfg {
    let s = &net.sysctl;
    let secs = |v: &core::sync::atomic::AtomicI32| v.load(Ordering::Relaxed).max(1) as u64 * 1000;
    Cfg {
        syn_retries: u32::from(s.tcp_syn_retries.load(Ordering::Relaxed)),
        synack_retries: u32::from(s.tcp_synack_retries.load(Ordering::Relaxed)),
        retries2: u32::from(s.tcp_retries2.load(Ordering::Relaxed)),
        fin_timeout: secs(&s.tcp_fin_timeout),
        wscale: s.tcp_window_scaling.load(Ordering::Relaxed) != 0,
        ts: s.tcp_timestamps.load(Ordering::Relaxed),
        sack: s.tcp_sack.load(Ordering::Relaxed) != 0,
        dsack: s.tcp_dsack.load(Ordering::Relaxed) != 0,
        reordering: s.tcp_reordering.load(Ordering::Relaxed).max(1) as u32,
        max_reordering: s.tcp_max_reordering.load(Ordering::Relaxed).max(1) as u32,
        recovery: s.tcp_recovery.load(Ordering::Relaxed),
        early_retrans: s.tcp_early_retrans.load(Ordering::Relaxed),
        rmem_min: s.tcp_rmem[0].load(Ordering::Relaxed).max(1) as u32,
        rmem_max: s.tcp_rmem[2].load(Ordering::Relaxed).max(1) as u32,
        keepidle: secs(&s.tcp_keepalive_time),
        keepintvl: secs(&s.tcp_keepalive_intvl),
        keepcnt: u32::from(s.tcp_keepalive_probes.load(Ordering::Relaxed)),
        frto: s.tcp_frto.load(Ordering::Relaxed),
        min_rtt_wlen: s.tcp_min_rtt_wlen.load(Ordering::Relaxed).max(0) as u32,
        slow_start_after_idle: s.tcp_slow_start_after_idle.load(Ordering::Relaxed) != 0,
        orphan_retries: u32::from(s.tcp_orphan_retries.load(Ordering::Relaxed)),
    }
}

/// RFC 6528 initial sequence number: keyed hash of the tuple plus a
/// 64 ns clock (Linux secure_tcp_seq)
fn isn(t: &Tuple) -> u32 {
    let w = [
        (u64::from(t.laddr.0) << 32) | u64::from(t.raddr.0),
        (u64::from(t.lport) << 16) | u64::from(t.rport),
    ];
    let h = crate::net::inet::port::secure_hash(0x7463_7073_6571, &w) as u32;
    h.wrapping_add((crate::time::monotonic_ns() >> 6) as u32)
}

/// Timestamp offset of a connection (Linux secure_tcp_seq_and_ts_off:
/// keyed hash of the four-tuple, RFC 7323 7.1, so the clock leaks
/// neither uptime nor other connections' offsets)
fn ts_off(t: &Tuple) -> u32 {
    let w = [
        (u64::from(t.laddr.0) << 32) | u64::from(t.raddr.0),
        (u64::from(t.lport) << 16) | u64::from(t.rport),
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

/// Transmit the header-only segment `seg` on `t`, allocated GFP_ATOMIC
/// (Linux tcp_v4_send_reset's ip_send_unicast_reply)
pub(super) fn xmit(net: &NetNamespace, t: &Tuple, seg: &Seg, p: IpParams, oif: u32) {
    if let Some(skb) = output::build(seg, t, Gfp::ATOMIC) {
        let _ = send(net, t, skb, p, oif);
    }
}

/// Route and send `skb` (its TCP header on) to `t` (route each time;
/// no cached dst); false without a route
fn send(net: &NetNamespace, t: &Tuple, skb: Box<SkBuff>, p: IpParams, oif: u32) -> bool {
    let Ok(rt) = route::output(net, t.raddr, t.laddr, oif) else {
        return false;
    };
    let _ = ipv4::ip_send_rt(net, &rt, skb, IPPROTO_TCP, p);
    true
}

/// Transmit `out`'s segments to `t` in order (Linux tcp_transmit_skb
/// with ip_queue_xmit), each header put on its payload skb
pub(super) fn send_segs(net: &NetNamespace, t: &Tuple, out: &mut Out, p: IpParams, oif: u32) {
    while let Some(mut skb) = out.segs.pop_front() {
        if output::finish_hdr(&mut skb, t).is_some() && !send(net, t, skb, p, oif) {
            // Linux __ip_queue_xmit's no_route
            net.mib.ip.inc(crate::net::mib::IPSTATS_MIB_OUTNOROUTES);
        }
    }
}

/// MSS we advertise toward `daddr` (route MTU - 40)
fn route_mss(net: &NetNamespace, daddr: Ipv4Addr, saddr: Ipv4Addr, oif: u32) -> u32 {
    route::output(net, daddr, saddr, oif)
        .map_or(cb::MSS_DEFAULT, |rt| rt.mtu.saturating_sub(cb::HDRS))
}

impl TcpSock {
    pub fn new(sk: Sock) -> Result<Arc<Self>, KernelError> {
        let live = try_arc(cb::Live::default())?;
        let mut cb = TcpCb::new(cfg(&sk.net), live.clone());
        cb.mib = Some(Arc::clone(&sk.net.mib));
        // Linux tcp_init_sock: tcp_assign_congestion_control
        cb.opts.ca = sk.net.sysctl.tcp_ca.load(Ordering::Relaxed) as usize;
        cb.assign_cc(cb.opts.ca);
        let snap = Snap::default();
        snap.store(&cb);
        try_arc_cyclic(|me| Self {
            sk,
            inet: Inet::default(),
            lock: SockLock::new(Inner {
                cb,
                tuple: None,
                eh: None,
                bound: false,
                orphan: None,
                parent: None,
                armed: [None; 3],
                connecting: false,
            }),
            queue: Mutex::new(None),
            ack_backlog: AtomicU32::new(0),
            snap,
            live,
            mtu_info: AtomicU32::new(0),
            err_soft: AtomicI32::new(0),
            timers: [
                ArcTimer::new(TcpSock::rtx_timer),
                ArcTimer::new(TcpSock::delack_timer),
                ArcTimer::new(TcpSock::keepalive_timer),
            ],
            lh_link: NullsLink::new(),
            bind_link: Link::new(),
            by_bind: AtomicBool::new(false),
            inuse: AtomicBool::new(false),
            rcu_puts: RcuPuts::new(),
            accept_link: Link::new(),
            accept_owner: Owner::new(),
            listen_opts: Mutex::new(cb::Opts::default()),
            me: me.clone(),
        })
    }

    fn arc(&self) -> Arc<TcpSock> {
        self.me.upgrade().expect("tcp socket alive")
    }

    /// Own the socket (Linux lock_sock)
    #[track_caller]
    fn lock_sock(&self) -> Guard<'_> {
        let mut g = self.lock.lock(self);
        self.sync_caps(&mut g);
        g
    }

    /// The state under `slock` if nobody owns the socket (Linux
    /// bh_lock_sock + !sock_owned_by_user)
    fn bh_get<'a>(&self, b: &'a mut BhGuard<'_, Inner>) -> Option<&'a mut Inner> {
        let g = b.get()?;
        self.sync_caps(g);
        Some(g)
    }

    /// The buffer limits from SO_RCVBUF / SO_SNDBUF (Linux charges
    /// about half of them to overhead)
    fn sync_caps(&self, g: &mut Inner) {
        g.cb.rcv_cap = (self.sk.rcvbuf() / 2) as usize;
        g.cb.snd_cap = (self.sk.sndbuf() / 2) as usize;
        g.cb.rcv_locked = self.sk.flag(sf::RCVBUF_LOCK);
    }

    /// Linux READ_ONCE(sk->sk_state)
    pub fn state(&self) -> TcpState {
        TcpState::from_linux(self.snap.state.load(Ordering::Acquire))
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
    /// hand-over, leaving the tables, listener queues, timer. Returns a
    /// listener to wake (a child became acceptable).
    fn post(&self, g: &mut Inner, out: &mut Out) -> Option<Arc<TcpSock>> {
        if out.timewait {
            self.to_timewait(g, out);
        }
        let mut ready = None;
        if out.established && g.tuple.is_some() {
            // A child whose handshake completed is a socket now (Linux
            // makes it here: sk_clone_lock, inet_ehash_nolisten)
            self.sk.inuse_start();
            table::tcp_inuse(self, true);
        }
        if out.established
            && let Some(w) = g.parent.take()
        {
            // A child completing its handshake was queued on its
            // listener (`syn_recv_sock`): wake it (Linux
            // tcp_child_process -> sk_data_ready)
            ready = w.upgrade();
        }
        if out.done {
            if let Some(p) = g.parent.take().and_then(|w| w.upgrade()) {
                p.child_gone(self);
                put_listener(p);
            }
            // Like Linux tcp_set_state(TCP_CLOSE): a port fixed by bind()
            // stays until close()
            let keep = !g.cb.orphan && self.inet.get().port_lock;
            // Linux inet_csk_destroy_sock: no longer an orphan
            // (tcp_v4_destroy_sock: tcp_cleanup_congestion_control)
            g.orphan = None;
            g.cb.cleanup_cc();
            self.unhash_conn(g);
            if !keep {
                self.unbind(g);
            }
        }
        self.sync_timers(g);
        // Linux inet_csk_destroy_sock of an orphan (tcp_done, tcp_close
        // in TCP_CLOSE, tcp_time_wait): with its timers stopped, its
        // last reference goes (sk_free)
        if g.cb.orphan && g.cb.state == TcpState::Closed {
            self.sk.inuse_end();
        }
        ready
    }

    /// Arm or stop the three timers for the control block's deadlines
    /// (Linux inet_csk_reset_xmit_timer / sk_reset_timer /
    /// inet_csk_clear_xmit_timer): a pending timer holds a reference to
    /// the socket, so a closed connection's timers are stopped here and
    /// release it
    fn sync_timers(&self, g: &mut Inner) {
        let want = g.cb.deadlines();
        for (k, t) in self.timers.iter().enumerate() {
            if want[k] == g.armed[k] && (want[k].is_none() || t.pending()) {
                continue;
            }
            match want[k] {
                Some(at) => {
                    t.reset(&self.arc(), at.saturating_mul(1_000_000));
                }
                None => {
                    t.stop();
                }
            }
            g.armed[k] = want[k];
        }
    }

    /// Hand TIME_WAIT to a timewait entry (Linux tcp_time_wait)
    fn to_timewait(&self, g: &mut Inner, out: &mut Out) {
        let Some(t) = g.tuple.take() else {
            // Not hashed: nothing to hand over, so close (Linux
            // tcp_time_wait without a tw falls back to tcp_done)
            g.cb.tw_done(out);
            out.done = true;
            return;
        };
        let mut bind = self.bind_info(t.laddr);
        bind.addr = self.inet.get().rcv_saddr;
        bind.tw = true;
        bind.listen = false;
        // GFP_ATOMIC under the socket lock (Linux inet_twsk_alloc)
        let tw = with_gfp(Gfp::ATOMIC, || {
            TimeWait::new(
                Arc::clone(self.sk.net.passive()),
                t,
                bind,
                self.by_bind.load(Ordering::Relaxed),
                self.inet.params(),
                self.oif(),
                TwCb::from_cb(&g.cb),
            )
        });
        // Its ehash entry, GFP_ATOMIC with it
        let tw = tw.and_then(|tw| {
            let eh = table::Eh::new(&self.sk.net, Ent::Tw(tw.clone()), Gfp::ATOMIC)?;
            Ok((tw, eh))
        });
        let Ok((tw, tw_eh)) = tw else {
            // Out of memory: close without TIME_WAIT (Linux tcp_time_wait
            // falls back to tcp_done); `post` leaves the tables
            self.sk.net.mib.net.inc(LINUX_MIB_TCPTIMEWAITOVERFLOW);
            g.tuple = Some(t);
            g.cb.tw_done(out);
            out.done = true;
            return;
        };
        tw.set_eh(tw_eh.clone());
        self.sk
            .net
            .tcp
            .tw_hashdance(&self.arc(), g.eh.take(), &tw, &tw_eh);
        g.bound = false;
        // Linux tcp_time_wait -> tcp_done -> inet_csk_destroy_sock
        g.orphan = None;
        // Linux inet_twsk_schedule: 2MSL is past the "killed" bound
        self.sk.net.mib.net.inc(LINUX_MIB_TIMEWAITED);
        tw.start();
        g.cb.tw_done(out);
    }

    /// Leave ehash (Linux inet_unhash)
    fn unhash_conn(&self, g: &mut Inner) {
        g.tuple = None;
        if let Some(eh) = g.eh.take() {
            self.sk.net.tcp.unhash(&eh, self);
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

    /// Apply `out` under the lock (Linux transmits and sets sk_err /
    /// sk_shutdown under the socket lock): publish the shutdown bits and
    /// the error (reported with the wakeups), then transmit to `t`.
    /// Returns the wakeups still to make.
    fn emit(&self, out: &mut Out, t: Option<Tuple>) -> u8 {
        if out.shut != 0 {
            self.sk.set_shutdown(out.shut);
        }
        if let Some(e) = out.err {
            self.sk.store_err(e as u32);
        }
        if let Some(t) = t {
            send_segs(&self.sk.net, &t, out, self.inet.params(), self.oif());
        }
        if out.err.is_some() {
            out.wake | cb::wake::ERR
        } else {
            out.wake
        }
    }

    /// End of a locked step (owner, or `slock` unowned): post-process
    /// and apply `out` (segments go to the connection's tuple) and
    /// publish the lockless view; the wakeups follow (`wake_up`)
    fn apply(&self, g: &mut Inner, out: &mut Out) -> Wake {
        let t = g.tuple.or_else(|| self.cur_tuple());
        let ready = self.post(g, out);
        let w = self.emit(out, t);
        if g.cb.state == TcpState::Listen {
            *self.listen_opts.lock() = g.cb.opts;
        }
        self.snap.store(&g.cb);
        Wake { w, ready }
    }

    /// `apply`, then the wakeups, still locked (Linux wakes under the
    /// socket lock, either level)
    fn finish(&self, g: &mut Inner, out: &mut Out) {
        let w = self.apply(g, out);
        self.wake_up(w);
    }

    /// Own the socket, run `f` on it, apply the result and wake,
    /// release (which runs the backlog)
    fn step<R>(&self, f: impl FnOnce(&mut Inner, &mut Out) -> R) -> R {
        let mut out = Out::default();
        let mut g = self.lock_sock();
        let r = f(&mut g, &mut out);
        self.finish(&mut g, &mut out);
        r
    }

    /// The wakeups of a step
    fn wake_up(&self, w: Wake) {
        self.wake(w.w);
        if let Some(l) = w.ready {
            l.sk.data_ready();
            put_listener(l);
        }
    }

    /// The wakeups `w` (`cb::wake`) asked for, each of them, in Linux's
    /// order within one segment: an establishing state change before the
    /// data it carried (tcp_finish_connect, then tcp_data_queue), the
    /// data before the FIN behind it (tcp_data_queue, then tcp_fin); an
    /// error is reported after the close's state change (Linux
    /// tcp_done_with_error: tcp_done, then sk_error_report)
    fn wake(&self, w: u8) {
        let fin = w & cb::wake::FIN != 0;
        if w & cb::wake::STATE != 0 && !fin {
            self.sk.state_change();
            self.state_async(w);
        }
        if w & cb::wake::ERR != 0 {
            self.sk.error_report();
        }
        if w & cb::wake::DATA != 0 {
            self.sk.data_ready();
        }
        if w & cb::wake::SPACE != 0 {
            self.sk.stream_write_space();
        }
        if fin {
            self.sk.state_change();
            self.state_async(w);
        }
    }

    /// The SIGIO of a state change (Linux tcp_finish_connect, tcp_fin)
    fn state_async(&self, w: u8) {
        if w & cb::wake::EST != 0 {
            self.sk.wake_async(WakeHow::Io, POLL_OUT);
        }
        if w & cb::wake::FIN != 0 {
            let band = if self.sk.shutdown() == SHUTDOWN_MASK {
                POLL_HUP
            } else {
                POLL_IN
            };
            self.sk.wake_async(WakeHow::WaitData, band);
        }
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

    /// A segment found for this socket under `t` in ehash or lhash
    /// (Linux tcp_v4_rcv's socket part): processed at once unless the
    /// socket is owned, else queued to the backlog for the owner.
    ///
    /// A request whose listener stopped listening is dropped and the
    /// segment handed back to be looked up again (Linux tcp_v4_rcv:
    /// inet_csk_reqsk_queue_drop_and_put, goto lookup).
    fn rcv(&self, skb: Box<SkBuff>, t: Tuple) -> Option<Box<SkBuff>> {
        let mut b = self.lock.bh_lock();
        match self.bh_get(&mut b) {
            Some(g) => {
                let mut out = Out::default();
                if g.tuple == Some(t) && self.req_dead(g) {
                    // Dropped silently: it leaves the tables, its timer
                    // stops (Linux inet_csk_reqsk_queue_drop_and_put)
                    g.cb.set_closed(&mut out);
                    self.finish(g, &mut out);
                    return Some(skb);
                }
                self.do_rcv(g, skb, t, now_ms(), &mut out);
                self.finish(g, &mut out);
            }
            None => self.add_backlog(b, skb),
        }
        None
    }

    /// A listener's child still in SYN_RECEIVED (Linux's request sock)
    /// whose listener is no longer listening (closed, or gone)
    fn req_dead(&self, g: &Inner) -> bool {
        if !(g.cb.passive && g.cb.state == TcpState::SynReceived) {
            return false;
        }
        match g.parent.as_ref().and_then(Weak::upgrade) {
            None => true,
            Some(p) => {
                let dead = !p.listening();
                put_listener(p);
                dead
            }
        }
    }

    /// Linux tcp_add_backlog: over rcvbuf * 2 + sndbuf / 2 + 64 KiB of
    /// backlog and receive queue the segment is dropped (after `slock`)
    fn add_backlog(&self, mut b: BhGuard<'_, Inner>, skb: Box<SkBuff>) {
        let limit = (self.sk.rcvbuf() as usize)
            .saturating_mul(2)
            .saturating_add(self.sk.sndbuf() as usize / 2)
            .saturating_add(64 * 1024);
        let rmem = self.snap.rcvq.load(Ordering::Relaxed);
        let r = b.add_backlog(skb, rmem, limit);
        drop(b);
        if r.is_err() {
            self.sk.net.mib.net.inc(LINUX_MIB_TCPBACKLOGDROP);
        }
        drop(r);
    }

    /// A segment for this socket, `slock` held unowned or as the owner
    /// (Linux tcp_v4_do_rcv): a listener's goes to `listen_rcv`; a
    /// connection's is dropped if the socket left the tuple `t` it was
    /// found by between the lookup and taking its lock
    fn do_rcv(&self, g: &mut Inner, mut skb: Box<SkBuff>, t: Tuple, now: u64, out: &mut Out) {
        // The header, then the payload alone (Linux __skb_pull)
        let Some((s, doff)) = output::parse(skb.data()) else {
            return;
        };
        let _ = skb.pull(doff);
        let s = &s;
        if g.cb.state == TcpState::Listen {
            return self.conn_request(s, t, now);
        }
        if g.tuple != Some(t) {
            return;
        }
        g.cb.input(s, skb, now, out);
        if let Some(skb) = out.req_ack.take() {
            self.syn_recv_sock(g, s, skb, t, now, out);
        }
    }

    /// A request's completing ACK passed tcp_check_req (Linux
    /// tcp_v4_syn_recv_sock, inet_csk_complete_hashdance, then
    /// tcp_child_process): a full accept queue drops it (the request
    /// stays, its SYN-ACK is resent); it takes the listener's port
    /// (without a bind bucket it is dropped); it is queued as a full
    /// socket, or forgotten with a reset if the listener stopped
    /// listening (Linux inet_child_forget: tcp_disconnect from
    /// SYN_RECV), before it processes the segment
    fn syn_recv_sock(
        &self,
        g: &mut Inner,
        s: &SegIn,
        skb: Box<SkBuff>,
        t: Tuple,
        now: u64,
        out: &mut Out,
    ) {
        let Some(p) = g.parent.as_ref().and_then(Weak::upgrade) else {
            return;
        };
        let full = p.acceptq_full();
        if full {
            self.listen_overflow();
        } else if !self.sk.net.tcp.inherit(&self.arc(), t.lport) {
            self.listen_drop();
        } else {
            g.bound = true;
            if p.child_ready(&self.arc()) {
                g.cb.req_full = true;
                g.cb.input(s, skb, now, out);
            } else {
                g.parent = None;
                orphan(g);
                g.cb.disconnect(out);
            }
        }
        put_listener(p);
    }

    // --- listener ---------------------------------------------------------------

    fn acceptq_full(&self) -> bool {
        self.queue.lock().as_ref().is_some_and(|q| q.full())
    }

    /// Listening: an accept queue exists (taken under the owner by
    /// close and disconnect before their children are stopped, Linux
    /// TCP_CLOSE set before inet_csk_listen_stop)
    fn listening(&self) -> bool {
        self.queue.lock().is_some()
    }

    /// Linux tcp_listendrop: a connection request was dropped
    fn listen_drop(&self) {
        self.sk.net.mib.net.inc(LINUX_MIB_LISTENDROPS);
    }

    /// The accept queue was full (Linux LISTENOVERFLOWS, then
    /// tcp_listendrop)
    fn listen_overflow(&self) {
        self.sk.net.mib.net.inc(LINUX_MIB_LISTENOVERFLOWS);
        self.listen_drop();
    }

    /// A segment for this listener (Linux tcp_v4_rcv's TCP_LISTEN
    /// case): handled with no socket lock, as Linux; a socket that left
    /// LISTEN meanwhile takes the locked path
    fn listen_rcv(&self, skb: Box<SkBuff>, t: Tuple) {
        if self.state() != TcpState::Listen {
            // Not a request: nothing comes back
            drop(self.rcv(skb, t));
            return;
        }
        let Some(s) = seg_of(&skb) else {
            return;
        };
        drop(skb);
        self.conn_request(&s, t, now_ms());
    }

    /// A segment in LISTEN (Linux tcp_rcv_state_process,
    /// tcp_conn_request): a SYN makes a child in SYN_RECEIVED that
    /// answers with SYN-ACK. Dropped when the accept queue or the SYN
    /// queue is full (no syncookies). Takes no lock of the listener but
    /// its queue's (the options and buffer sizes are read as published)
    fn conn_request(&self, s: &SegIn, t: Tuple, now: u64) {
        if s.has(flags::RST) {
            return;
        }
        if s.has(flags::ACK) {
            // A stray ACK (no request): RST (Linux tcp_rcv_state_process)
            if let Some(r) = output::reset_for(s) {
                send_reset(&self.sk.net, &t, &r);
            }
            return;
        }
        // Only a plain SYN opens (Linux drops SYN+FIN in LISTEN)
        if !s.has(flags::SYN) || s.has(flags::FIN) {
            return;
        }
        {
            let q = self.queue.lock();
            let Some(q) = q.as_ref() else {
                return;
            };
            if q.syn.len() as u32 >= q.backlog.max(1) {
                // Linux tcp_syn_flood_action without syncookies
                self.sk.net.mib.net.inc(LINUX_MIB_TCPREQQFULLDROP);
                self.listen_drop();
                return;
            }
            if q.full() {
                self.listen_overflow();
                return;
            }
        }
        let opts = *self.listen_opts.lock();
        let caps = (
            (self.sk.rcvbuf() / 2) as usize,
            (self.sk.sndbuf() / 2) as usize,
            self.sk.flag(sf::RCVBUF_LOCK),
        );
        self.child(s, t, opts, caps, now);
    }

    /// Create, hash and queue a SYN_RECEIVED child and send its SYN-ACK
    /// (under the new child's `slock`: nobody owns it yet; `opts` and
    /// the buffer `caps` are the listener's). The child is allocated
    /// GFP_ATOMIC before any lock is taken (Linux inet_reqsk_alloc,
    /// sk_clone_lock)
    fn child(&self, s: &SegIn, t: Tuple, opts: cb::Opts, caps: (usize, usize, bool), now: u64) {
        // Out of memory: drop the SYN (Linux inet_reqsk_alloc failing in
        // tcp_conn_request: tcp_listendrop)
        let Ok(c) = with_gfp(Gfp::ATOMIC, || TcpSock::new(Sock::clone_from(&self.sk))) else {
            self.listen_drop();
            return;
        };
        c.inet.clone_opts(&self.inet);
        {
            let mut a = c.inet.addr.lock();
            a.rcv_saddr = t.laddr;
            a.saddr = t.laddr;
            a.sport = t.lport;
            a.daddr = t.raddr;
            a.dport = t.rport;
        }
        // Its ehash entry, GFP_ATOMIC with the child, before any lock
        let Ok(eh) = table::Eh::new(&self.sk.net, Ent::Sk(c.clone()), Gfp::ATOMIC) else {
            self.listen_drop();
            return;
        };
        let mut out = Out::default();
        let o = open(&self.sk.net, &t, self.oif());
        let mut b = c.lock.bh_lock();
        let Some(g) = b.get() else {
            return;
        };
        // TCP_SYNCNT of a listener bounds its SYN-ACK retries (Linux
        // reqsk_timer_handler)
        let mut kc = cfg(&self.sk.net);
        if opts.syncnt != 0 {
            kc.synack_retries = opts.syncnt;
        }
        let mut cb = TcpCb::new(kc, Arc::clone(&c.live));
        cb.mib = Some(Arc::clone(&self.sk.net.mib));
        cb.opts = opts;
        // Linux tcp_ca_openreq_child: the namespace's default unless the
        // listener chose one (icsk_ca_setsockopt)
        if !cb.opts.ca_set {
            cb.opts.ca = self.sk.net.sysctl.tcp_ca.load(Ordering::Relaxed) as usize;
        }
        (cb.rcv_cap, cb.snd_cap, cb.rcv_locked) = caps;
        cb.passive(s, o, now, &mut out);
        g.cb = cb;
        if !self.sk.net.tcp.hash(t, &eh, &c) {
            self.listen_drop();
            return;
        }
        g.tuple = Some(t);
        g.eh = Some(eh);
        g.parent = Some(self.me.clone());
        let queued = match self.queue.lock().as_mut() {
            Some(q) => {
                q.syn.push_back(c.clone());
                true
            }
            None => false,
        };
        if !queued {
            // The listener closed meanwhile (Linux: the request finds
            // no listener): the child leaves the tables unanswered
            g.parent = None;
            g.cb.set_closed(&mut Out::default());
            let mut gone = Out {
                done: true,
                ..Out::default()
            };
            let _ = c.post(g, &mut gone);
            return;
        }
        // SYN-ACK: nobody waits on a new child, no wakeup
        let _ = c.apply(g, &mut out);
    }

    /// A child completed its handshake (Linux inet_csk_complete_hashdance;
    /// under the child's lock). True: it was queued, the step wakes the
    /// listener under the child's lock (Linux tcp_child_process). False:
    /// not listening (Linux inet_csk_reqsk_queue_add); a request made
    /// before the listener closed and listened again is queued too, as
    /// in Linux (the request still names its listener).
    fn child_ready(&self, c: &Arc<TcpSock>) -> bool {
        let mut q = self.queue.lock();
        let Some(q) = q.as_mut() else {
            return false;
        };
        let r = q.syn.remove(c).unwrap_or_else(|| c.clone());
        q.ready.push_back(r);
        // Under `queue` (Linux sk_acceptq_added)
        self.ack_backlog
            .store(q.ready.len() as u32, Ordering::Relaxed);
        true
    }

    /// A child died before being accepted
    fn child_gone(&self, c: &TcpSock) {
        let gone = self.queue.lock().as_mut().and_then(|q| q.syn.remove(c));
        // The queue's reference goes after its lock (the caller holds
        // another)
        drop(gone);
    }

    /// TCP_SYNCNT or the sysctl
    fn syncnt(&self, o: &cb::Opts) -> u32 {
        match o.syncnt {
            0 => u32::from(self.sk.net.sysctl.tcp_syn_retries.load(Ordering::Relaxed)),
            v => v,
        }
    }

    // --- user calls -----------------------------------------------------------

    /// Linux tcp_v4_connect: route, local address and port, ISN, SYN
    /// Begin a connection to `daddr:dport` (Linux tcp_v4_connect), the
    /// socket locked
    fn start_connect(
        &self,
        g: &mut Inner,
        out: &mut Out,
        daddr: Ipv4Addr,
        dport: u16,
    ) -> Result<(), KernelError> {
        let me = self.arc();
        {
            if g.cb.state != TcpState::Closed {
                return Err(KernelError::AlreadyConnected);
            }
            let a = self.inet.get();
            let rt = route::output(&self.sk.net, daddr, a.saddr, self.oif())
                .inspect_err(|e| self.sk.net.mib.route_err(e))?;
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
            // Made as the owner, before the tables' spin locks
            let eh = table::Eh::new(&self.sk.net, Ent::Sk(me.clone()), Gfp::KERNEL)?;
            let t = self.sk.net.tcp.connect(&me, &eh, want, range)?;
            g.tuple = Some(t);
            g.eh = Some(eh);
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
            // A new connection starts with no pending error (Linux
            // tcp_connect_init)
            self.sk.store_err(0);
            let mut c = cfg(&self.sk.net);
            c.syn_retries = self.syncnt(&g.cb.opts);
            let mut cb = TcpCb::new(c, Arc::clone(&self.live));
            cb.mib = Some(Arc::clone(&self.sk.net.mib));
            cb.opts = g.cb.opts;
            (cb.rcv_cap, cb.snd_cap, cb.rcv_locked) = (g.cb.rcv_cap, g.cb.snd_cap, g.cb.rcv_locked);
            g.cb = cb;
            let o = Open {
                iss: isn(&t),
                ts_off: ts_off(&t),
                mss: rt.mtu.saturating_sub(cb::HDRS),
            };
            // The SYN is allocated with sk_allocation (Linux tcp_connect)
            out.gfp = Gfp::KERNEL;
            g.cb.connect(o, now_ms(), out);
            out.gfp = Gfp::ATOMIC;
            Ok(())
        }
    }

    /// __inet_stream_connect's part as the owner: the result now, or
    /// None to wait for the handshake
    fn connect_locked(
        &self,
        g: &mut Inner,
        out: &mut Out,
        a: &[u8],
        nonblock: bool,
    ) -> Option<Result<(), KernelError>> {
        let state = g.cb.state;
        if matches!(state, TcpState::SynSent | TcpState::SynReceived) {
            return nonblock.then_some(Err(KernelError::AlreadyInProgress));
        }
        // The outcome of an earlier non-blocking connect
        if g.connecting {
            g.connecting = false;
            return Some(match state {
                TcpState::Closed => {
                    Err(self.sk.take_err().unwrap_or(KernelError::ConnectionAborted))
                }
                _ => Ok(()),
            });
        }
        if state != TcpState::Closed {
            return Some(Err(KernelError::AlreadyConnected));
        }
        let r = af_inet::sin_parse(a, false)
            .and_then(|(daddr, dport)| self.start_connect(g, out, daddr, dport));
        match r {
            Err(e) => Some(Err(e)),
            Ok(()) if nonblock => {
                g.connecting = true;
                Some(Err(KernelError::InProgress))
            }
            Ok(()) => None,
        }
    }

    /// Wait for the handshake, the socket released while asleep (Linux
    /// inet_wait_for_connect): send timeout -> EINPROGRESS; failure ->
    /// the socket error or ECONNABORTED
    fn wait_connect(&self, g: &mut Guard<'_>) -> Result<(), KernelError> {
        let timeo = self.sk.snd_timeo(false);
        let r = g.unlocked(|| {
            dev::netif_rx_flush_local();
            self.sk.wait(timeo, || {
                !matches!(self.state(), TcpState::SynSent | TcpState::SynReceived)
            })
        });
        match r {
            Err(KernelError::WouldBlock) => return Err(KernelError::InProgress),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        if g.cb.state == TcpState::Closed {
            return Err(self.sk.take_err().unwrap_or(KernelError::ConnectionAborted));
        }
        Ok(())
    }

    /// Readers can stop waiting: more than `more_than` bytes queued, or
    /// an end (read with no lock, Linux sk_wait_data)
    fn rx_ready(&self, more_than: usize) -> bool {
        self.snap.rcvq.load(Ordering::Acquire) > more_than
            || self.sk.has_err()
            || self.sk.shutdown() & RCV_SHUTDOWN != 0
            || self.state() == TcpState::Closed
    }

    /// Writers can stop waiting (read with no lock, Linux
    /// sk_stream_wait_memory)
    fn tx_ready(&self) -> bool {
        self.snap.writable.load(Ordering::Acquire)
            || self.sk.has_err()
            || !matches!(self.state(), TcpState::Established | TcpState::CloseWait)
            || self.sk.shutdown() & SEND_SHUTDOWN != 0
    }

    /// The queues of a listener that stopped listening (Linux
    /// inet_csk_listen_stop): children not yet accepted are aborted, a
    /// RST to each peer (inet_child_forget -> tcp_disconnect); requests
    /// (children in SYN_RECEIVED) are left alone: each is dropped
    /// silently when its timer fires, or when a segment comes, which is
    /// then looked up again (`req_dead`; Linux reqsk_timer_handler,
    /// tcp_v4_rcv)
    /// Take the listener's queues away (it stops listening): its ready
    /// count goes to 0 with them, under `queue`
    fn take_queue(&self) -> Option<Accept> {
        let mut g = self.queue.lock();
        self.ack_backlog.store(0, Ordering::Relaxed);
        g.take()
    }

    fn listen_stop(&self, mut q: Accept) {
        while q.syn.pop_front().is_some() {}
        while let Some(c) = q.ready.pop_front() {
            // Unaccepted, so never owned (Linux WARN_ON
            // sock_owned_by_user): its slock (bh_lock_sock(child))
            let mut b = c.lock.bh_lock();
            if let Some(g) = c.bh_get(&mut b) {
                let mut out = Out::default();
                g.parent = None;
                orphan(g);
                g.cb.disconnect(&mut out);
                c.finish(g, &mut out);
            }
        }
    }

    /// Linux tcp_disconnect (connect(AF_UNSPEC)): abort, stop listening,
    /// back to an unconnected socket keeping a bind()-fixed address/port
    fn disconnect(&self) {
        self.step(|g, out| self.disconnect_locked(g, out));
        self.disconnect_done();
    }

    /// tcp_disconnect's part under the socket lock: stop listening (its
    /// unaccepted children aborted as the owner, Linux
    /// inet_csk_listen_stop under lock_sock), abort, clear the shutdown
    /// bits and the connecting state, report the error (ECONNRESET for a
    /// connection; the report comes anyway)
    fn disconnect_locked(&self, g: &mut Inner, out: &mut Out) {
        if g.cb.state == TcpState::Listen {
            self.sk.set_flag(sf::ACCEPTCONN, false);
            self.sk
                .net
                .tcp
                .listen_del(self.inet.get().sport, &self.arc());
            let q = self.take_queue();
            if let Some(q) = q {
                self.listen_stop(q);
            }
        }
        g.cb.disconnect(out);
        out.shut = 0;
        self.sk.clear_shutdown();
        g.connecting = false;
    }

    /// tcp_disconnect's rest, after the unlock: the listener's queue
    /// and the connection's addresses
    fn disconnect_done(&self) {
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
    /// sk_stream_wait_close); an exiting task does not wait (Linux
    /// inet_release: no linger time under PF_EXITING)
    fn linger_wait(&self) {
        let secs = match self.sk.linger() {
            Some(s) if s != 0 && !crate::task::exit::current_exiting() => s,
            _ => return,
        };
        let ns = u64::from(secs) * 1_000_000_000;
        let _ = self.sk.wait(ns, || {
            !matches!(
                self.state(),
                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
            )
        });
    }
}

impl TcpSock {
    /// Linux tcp_write_timer: the retransmit timer
    fn rtx_timer(s: Arc<TcpSock>) {
        let _ = s.timer_fired();
    }

    /// Linux tcp_delack_timer: one that finds the socket owned is
    /// DelayedACKLocked
    fn delack_timer(s: Arc<TcpSock>) {
        if !s.timer_fired() {
            s.sk.net.mib.net.inc(LINUX_MIB_DELAYEDACKLOCKED);
        }
    }

    /// Linux tcp_keepalive_timer (keepalive, orphan FIN_WAIT_2)
    fn keepalive_timer(s: Arc<TcpSock>) {
        let _ = s.timer_fired();
    }

    /// A timer fired (`ktimers/N`): the control block's due work runs
    /// now unless the socket is owned, else at the owner's release
    /// (Linux TCP_*_TIMER_DEFERRED); the timer's reference to the socket
    /// goes with the caller's `Arc`. False if it was deferred.
    fn timer_fired(&self) -> bool {
        let mut b = self.lock.bh_lock();
        match self.bh_get(&mut b) {
            Some(g) => {
                let mut out = Out::default();
                self.on_timer(g, now_ms(), &mut out);
                self.finish(g, &mut out);
                true
            }
            None => {
                b.defer(deferred::TIMER);
                false
            }
        }
    }

    /// The control block's due timer work; a dead request is dropped
    /// instead of resending its SYN-ACK (Linux reqsk_timer_handler)
    fn on_timer(&self, g: &mut Inner, now: u64, out: &mut Out) {
        if self.req_dead(g) {
            g.cb.set_closed(out);
        } else {
            g.cb.on_timer(now, out);
        }
    }
}

/// Put a listener reference taken under one of its children's slocks:
/// a grace period later, so its last drop never runs nested under
/// another socket's lock (a TCP socket's last drop runs in `rcuc/N`,
/// as the tables' references do; Linux sock_put of rsk_listener)
fn put_listener(p: Arc<TcpSock>) {
    crate::sync::rcu::put_rcu(p);
}

impl SockHooks<Inner> for TcpSock {
    /// A segment that waited for the owner (Linux sk_backlog_rcv ->
    /// tcp_v4_do_rcv; its checksum was checked on arrival)
    fn backlog_rcv(&self, g: &mut Inner, skb: Box<SkBuff>) {
        let Some(t) = seg_of(&skb).and_then(|s| tuple_of(&skb, &s)) else {
            return;
        };
        let mut out = Out::default();
        self.do_rcv(g, skb, t, now_ms(), &mut out);
        self.finish(g, &mut out);
    }

    /// Linux tcp_release_cb, under `slock`: the timers that fired, an
    /// MTU reduction (tcp_v4_mtu_reduced) and the soft error left while
    /// owned; then the lockless view of the owner's work is published
    /// and the wakeups made. With no deferred work it still publishes
    /// that view (Linux returns early: it writes sk_state and the other
    /// lockless fields in place, where steps that skip `apply`, such as
    /// listen() and TCP_CONGESTION, rely on this one). Wakeups made
    /// while still owned are Linux's too (release_sock runs the backlog
    /// and release_cb before sock_release_ownership).
    fn release_cb(&self, g: &mut Inner, flags: u32) {
        let mut out = Out::default();
        let now = now_ms();
        if flags & deferred::TIMER != 0 {
            self.on_timer(g, now, &mut out);
        }
        if flags & deferred::MTU != 0 && !matches!(g.cb.state, TcpState::Listen | TcpState::Closed)
        {
            g.cb.pmtu(self.mtu_info.load(Ordering::Relaxed), now, &mut out);
        }
        if flags & deferred::ERR != 0 {
            g.cb.soft_err = KernelError::from_errno(self.err_soft.load(Ordering::Relaxed));
        }
        self.finish(g, &mut out);
    }
}

// ============================================================================
// Segment demux (Linux tcp_v4_rcv)
// ============================================================================

/// The tuple (local first) of a received segment with header `s`
fn tuple_of(skb: &SkBuff, s: &Seg) -> Option<Tuple> {
    Some(Tuple {
        laddr: skb.daddr?,
        lport: s.dport,
        raddr: skb.saddr?,
        rport: s.sport,
    })
}

/// The header of a received segment, still at its data (Linux
/// tcp_hdr and tcp_parse_options; it was checked by `tcp_rcv`)
fn seg_of(skb: &SkBuff) -> Option<Seg> {
    output::parse(skb.data()).map(|(s, _)| s)
}

/// Receive a TCP segment (softnet or an inline loopback flush; thread
/// context). Lookups use the receiving device's namespace.
pub fn tcp_rcv(mut skb: Box<SkBuff>) {
    let (Some(net), Some(saddr), Some(daddr)) = (skb.net(), skb.saddr, skb.daddr) else {
        return;
    };
    // Unicast to us only (Linux: pkt_type != PACKET_HOST is dropped)
    if skb.ip_bcast {
        return;
    }
    let tcp = &net.mib.tcp;
    tcp.inc(TCP_MIB_INSEGS);
    let b = skb.data();
    if b.len() < output::HLEN {
        return;
    }
    if b[12] >> 4 < 5 {
        // Linux bad_packet: doff below the header
        tcp.inc(TCP_MIB_INERRS);
        return;
    }
    if output::checksum(saddr, daddr, b) != 0 {
        tcp.inc(TCP_MIB_CSUMERRORS);
        tcp.inc(TCP_MIB_INERRS);
        return;
    }
    // The control block from the header, which stays until TCP
    // processes the segment (Linux tcp_v4_fill_cb)
    let Some((s, _)) = output::parse(skb.data()) else {
        return;
    };
    let cb = skb.tcp_mut();
    cb.seq = s.seq;
    cb.end_seq = s.end_seq;
    cb.ack_seq = s.ack;
    cb.flags = s.flags;
    let Some(t) = tuple_of(&skb, &s) else {
        return;
    };
    // The device reference is not needed past here: it goes after the
    // socket locks (an skb may be queued or dropped under them)
    let dev = skb.dev.take();
    let dif = dev.as_ref().map_or(0, |d| d.ifindex());
    let now = now_ms();
    let skb = loop {
        match net.tcp.lookup(&t) {
            // A dead request hands the segment back, dropped from ehash
            Some(Ent::Sk(sk)) => match sk.rcv(skb, t) {
                Some(again) => skb = again,
                None => return,
            },
            // A TIME_WAIT entry consumes it unless it is a new SYN: a
            // listener takes the tuple over, else the entry ACKs it
            // (Linux do_time_wait TCP_TW_SYN)
            Some(Ent::Tw(tw)) => match tw.rcv(skb, now) {
                Some(skb) => match net.tcp.listener(daddr, t.lport, dif) {
                    Some(l) => {
                        tw.kill();
                        return l.listen_rcv(skb, t);
                    }
                    None => {
                        tw.syn_ack(now);
                        return;
                    }
                },
                None => return,
            },
            None => break skb,
        }
    };
    if let Some(l) = net.tcp.listener(daddr, t.lport, dif) {
        return l.listen_rcv(skb, t);
    }
    // No socket: reset (never answer a RST)
    if let Some(r) = output::reset_for(&s) {
        send_reset(&net, &t, &r);
    }
}

/// RST `r` answering a segment on `t` with no socket to send it
/// (Linux tcp_v4_send_reset)
fn send_reset(net: &NetNamespace, t: &Tuple, r: &Seg) {
    xmit(net, t, r, IpParams::default(), 0);
    net.mib.tcp.inc(TCP_MIB_OUTSEGS);
    net.mib.tcp.inc(TCP_MIB_OUTRSTS);
}

/// An ICMP error quoting one of our segments (Linux tcp_v4_err)
pub fn tcp_err(net: &NetNamespace, e: &IcmpErr<'_>) {
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
    let s = match net.tcp.lookup(&t) {
        Some(Ent::Sk(s)) => s,
        Some(Ent::Tw(_)) => return,
        None => {
            // Linux tcp_v4_err: no socket for it
            net.mib.icmp.inc(ICMP_MIB_INERRORS);
            return;
        }
    };
    let pmtudisc = s.inet.pmtudisc();
    let Some((err, _)) = e.errno(pmtudisc) else {
        return;
    };
    let recverr = s.inet.flag(ipf::RECVERR);
    // A handshake's error goes to the IP_RECVERR queue before the
    // socket fails with it (Linux tcp_v4_err: ip_icmp_error, then
    // tcp_done_with_error, under bh_lock_sock)
    let queue = |syn_err: bool| {
        if syn_err && recverr {
            af_inet::ip_icmp_error(&s.sk, e, err, t.rport, &l4[..8]);
        }
    };
    let mut b = s.lock.bh_lock();
    match s.bh_get(&mut b) {
        Some(g) => {
            let mut out = Out::default();
            queue(s.err_rcv(g, seq, e.info, err, recverr, &mut out));
            s.finish(g, &mut out);
        }
        None => queue(s.err_owned(&mut b, seq, e.info, err)),
    }
}

impl TcpSock {
    /// tcp_v4_err on an unowned socket (`slock` held): true if the
    /// handshake failed with `err`
    fn err_rcv(
        &self,
        g: &mut Inner,
        seq: u32,
        info: u32,
        err: KernelError,
        recverr: bool,
        out: &mut Out,
    ) -> bool {
        if g.cb.state == TcpState::Closed {
            return false;
        }
        if g.cb.state != TcpState::Listen && !cb::between(seq, g.cb.snd_una, g.cb.snd_max) {
            self.sk.net.mib.net.inc(LINUX_MIB_OUTOFWINDOWICMPS);
            return false;
        }
        if err == KernelError::MessageTooLong {
            g.cb.pmtu(info, now_ms(), out);
            return false;
        }
        match g.cb.state {
            TcpState::SynSent | TcpState::SynReceived => {
                if g.parent.is_some() {
                    // A listener's child: drop it quietly (Linux tcp_req_err)
                    g.cb.set_closed(out);
                    return false;
                }
                g.cb.fail(err, out);
                return true;
            }
            _ if recverr => out.err = Some(err),
            _ => g.cb.soft_err = Some(err),
        }
        false
    }

    /// tcp_v4_err on an owned socket: the sequence check on the
    /// published window edges, then frag needed reduces the MTU and
    /// other errors become the soft error at the owner's release
    /// (Linux TCP_MTU_REDUCED_DEFERRED, sk_err_soft); true in the
    /// handshake (the IP_RECVERR queue still gets it)
    fn err_owned(&self, b: &mut BhGuard<'_, Inner>, seq: u32, info: u32, err: KernelError) -> bool {
        let mib = &self.sk.net.mib.net;
        if err != KernelError::MessageTooLong {
            mib.inc(LINUX_MIB_LOCKDROPPEDICMPS);
        }
        let state = self.state();
        if state == TcpState::Closed {
            return false;
        }
        let una = self.snap.snd_una.load(Ordering::Acquire);
        let nxt = self.snap.snd_max.load(Ordering::Acquire);
        if state != TcpState::Listen && !cb::between(seq, una, nxt) {
            mib.inc(LINUX_MIB_OUTOFWINDOWICMPS);
            return false;
        }
        if err == KernelError::MessageTooLong {
            if state != TcpState::Listen {
                self.mtu_info.store(info, Ordering::Relaxed);
                b.defer(deferred::MTU);
            }
            return false;
        }
        self.err_soft.store(err as i32, Ordering::Relaxed);
        b.defer(deferred::ERR);
        matches!(state, TcpState::SynSent | TcpState::SynReceived)
    }
}

// ============================================================================
// recvmsg / sendmsg
// ============================================================================

/// Linux tcp_recvmsg
fn tcp_recvmsg(s: &TcpSock, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
    if flags & MSG_ERRQUEUE != 0 {
        return af_inet::ip_recv_error(&s.sk, &s.inet, m);
    }
    let mut g = s.lock_sock();
    let r = recvmsg_locked(s, &mut g, m, flags);
    drop(g);
    dev::netif_rx_flush_local();
    r
}

/// Hand up to `want` readable bytes past the `copied` already peeked
/// (MSG_PEEK) or taken to user memory at `copied` (MSG_TRUNC: count or
/// drop them), applying what consuming them sends (window updates)
fn recv_some(
    s: &TcpSock,
    g: &mut Guard<'_>,
    m: &mut RecvMsg<'_>,
    copied: usize,
    flags: i32,
) -> Result<usize, KernelError> {
    let peek = flags & MSG_PEEK != 0;
    let skip = if peek { copied } else { 0 };
    let want = m.data.len() - copied;
    let mut out = Out::default();
    let r = if flags & MSG_TRUNC != 0 {
        g.cb.recv_with(skip, want, !peek, |d| Ok(d.len()), &mut out)
    } else {
        let mut at = copied;
        g.cb.recv_with(
            skip,
            want,
            !peek,
            |d| {
                let n = m.data.put(at, d)?;
                at += n;
                Ok(n)
            },
            &mut out,
        )
    };
    s.finish(g, &mut out);
    r
}

/// Linux tcp_recvmsg_locked (no urgent data): copy straight from the
/// receive queue to user memory as the owner; wait for data with the
/// socket released (sk_wait_data); the end conditions are tested owned,
/// with everything that arrived before them processed
fn recvmsg_locked(
    s: &TcpSock,
    g: &mut Guard<'_>,
    m: &mut RecvMsg<'_>,
    flags: i32,
) -> Result<usize, KernelError> {
    if g.cb.state == TcpState::Listen {
        return Err(KernelError::NotConnected);
    }
    if flags & MSG_OOB != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let len = m.data.len();
    let peek = flags & MSG_PEEK != 0;
    let mut timeo = s.sk.rcv_timeo(flags & MSG_DONTWAIT != 0);
    // Linux sock_rcvlowat
    let target = if flags & MSG_WAITALL != 0 {
        len
    } else {
        (s.sk.rcvlowat().max(0) as usize).min(len)
    }
    .max(1);
    let mut copied = 0;
    loop {
        match recv_some(s, g, m, copied, flags) {
            Ok(n) if n > 0 => copied += n,
            // Data, but no room for it (a zero-length read)
            Ok(_) if g.cb.rcvq_len() > if peek { copied } else { 0 } => break,
            Ok(_) => {
                if !recv_wait(s, g, &mut timeo, copied, target, peek)? {
                    break;
                }
            }
            Err(_) if copied > 0 => break,
            Err(e) => return Err(e),
        }
        if copied >= len {
            break;
        }
    }
    Ok(copied)
}

/// The receive queue has nothing more for a reader with `copied`
/// bytes (Linux tcp_recvmsg_locked's tail): false to return them, an
/// error to return instead, true to look again after processing the
/// backlog or after waiting for data with the socket released
fn recv_wait(
    s: &TcpSock,
    g: &mut Guard<'_>,
    timeo: &mut u64,
    copied: usize,
    target: usize,
    peek: bool,
) -> Result<bool, KernelError> {
    if copied >= target && !g.backlog_pending() {
        return Ok(false);
    }
    let err = s.sk.has_err();
    let shut = s.sk.shutdown() & RCV_SHUTDOWN != 0;
    let closed = g.cb.state == TcpState::Closed;
    if copied > 0 {
        if *timeo == 0 || err || shut || closed {
            return Ok(false);
        }
    } else {
        if err && let Some(e) = s.sk.take_err() {
            return Err(e);
        }
        if shut {
            return Ok(false);
        }
        if closed {
            // Never connected, or the step that closed it published its
            // error first
            return Err(KernelError::NotConnected);
        }
        if *timeo == 0 {
            return Err(KernelError::WouldBlock);
        }
    }
    if copied >= target {
        // Do not sleep, just process the backlog
        g.flush_backlog();
        return Ok(true);
    }
    let more = if peek { copied } else { 0 };
    let r = g.unlocked(|| {
        dev::netif_rx_flush_local();
        s.sk.wait_data(*timeo, || s.rx_ready(more))
    });
    match r {
        Ok(t) => *timeo = t,
        Err(_) if copied > 0 => return Ok(false),
        Err(e) => return Err(e),
    }
    Ok(true)
}

/// sk_stream_wait_connect: wait while the handshake runs, the socket
/// released while asleep
fn wait_connected(s: &TcpSock, g: &mut Guard<'_>, timeo: &mut u64) -> Result<(), KernelError> {
    loop {
        if let Some(e) = s.sk.take_err() {
            return Err(e);
        }
        if s.sk.shutdown() & SEND_SHUTDOWN != 0 {
            return Err(KernelError::BrokenPipe);
        }
        match g.cb.state {
            TcpState::Established | TcpState::CloseWait => return Ok(()),
            TcpState::SynSent | TcpState::SynReceived => {
                let t = *timeo;
                *timeo = g.unlocked(|| {
                    dev::netif_rx_flush_local();
                    s.sk.wait(t, || {
                        !matches!(s.state(), TcpState::SynSent | TcpState::SynReceived)
                    })
                })?;
            }
            _ => return Err(s.sk.take_err().unwrap_or(KernelError::BrokenPipe)),
        }
    }
}

/// One memory wait of a sender (Linux sk_stream_wait_memory with
/// vm_wait set), the socket released while asleep: EAGAIN without time
/// left, the signal errno of the whole send timeout if interrupted
fn wait_memory(s: &TcpSock, g: &mut Guard<'_>, timeo: &mut u64) -> Result<(), KernelError> {
    use crate::net::sock::TIMEO_FOREVER;
    s.sk.send_nospace(*timeo);
    // SOCK_NOSPACE, whether it waits or not
    s.live.nospace.store(true, Ordering::Release);
    if *timeo == 0 {
        return Err(KernelError::WouldBlock);
    }
    let vm_wait = u64::from(2 + crate::random::get_random_u32() % 200) * 1_000_000;
    let step = (*timeo).min(vm_wait);
    let r = g.unlocked(|| {
        dev::netif_rx_flush_local();
        s.sk.wait(step, || {
            s.sk.has_err() || s.sk.shutdown() & SEND_SHUTDOWN != 0
        })
    });
    let left = match r {
        Ok(left) => left,
        Err(KernelError::WouldBlock) => 0,
        Err(KernelError::Interrupted) if *timeo == TIMEO_FOREVER => {
            return Err(KernelError::RestartSys);
        }
        Err(e) => return Err(e),
    };
    if *timeo != TIMEO_FOREVER {
        *timeo -= step - left;
    }
    Ok(())
}

/// Linux sk_stream_wait_memory: wait for room in the send buffer, the
/// socket released while asleep
fn wait_space(s: &TcpSock, g: &mut Guard<'_>, timeo: &mut u64) -> Result<(), KernelError> {
    s.sk.send_nospace(*timeo);
    s.live.nospace.store(true, Ordering::Release);
    let t = *timeo;
    *timeo = g.unlocked(|| {
        dev::netif_rx_flush_local();
        s.sk.wait(t, || s.tx_ready())
    })?;
    Ok(())
}

/// Linux tcp_sendmsg
fn tcp_sendmsg(s: &TcpSock, m: &mut SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
    if flags & MSG_OOB != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    let mut g = s.lock_sock();
    let r = sendmsg_locked(s, &mut g, m, flags);
    drop(g);
    dev::netif_rx_flush_local();
    r
}

/// Queue up to the rest of `m` from `sent` on, copied straight from
/// user memory into the send queue, and transmit what may go (MSG_MORE
/// holds a partial last segment, Linux tcp_push): the bytes queued and
/// whether none were for want of TCP memory while the send buffer had
/// room (Linux sk_stream_memory_free at the failed charge); Err if the
/// connection cannot send or the copy faulted first
fn send_some(
    s: &TcpSock,
    g: &mut Guard<'_>,
    m: &mut SendMsg<'_>,
    sent: usize,
    flags: i32,
) -> Result<(usize, bool), KernelError> {
    if s.sk.has_err() {
        return Err(s.sk.take_err().unwrap_or(KernelError::BrokenPipe));
    }
    if s.sk.shutdown() & SEND_SHUTDOWN != 0
        || !matches!(g.cb.state, TcpState::Established | TcpState::CloseWait)
    {
        return Err(KernelError::BrokenPipe);
    }
    let total = m.data.len();
    let mut at = sent;
    let n = g.cb.send_with(total - sent, |b| {
        let k = m.data.copy_at(at, b)?;
        at += k;
        Ok(k)
    })?;
    let mut out = Out::default();
    if n > 0 && sent + n == total && flags & MSG_MORE != 0 {
        g.cb.output_more(now_ms(), &mut out);
    } else if n > 0 {
        g.cb.output(now_ms(), &mut out);
    }
    let no_mem = n == 0 && g.cb.snd_space() > 0;
    s.finish(g, &mut out);
    Ok((n, no_mem))
}

/// Linux tcp_sendmsg_locked: queue everything (blocking) or what fits
/// (non-blocking) as the owner, waiting for the handshake and for room
/// with the socket released
fn sendmsg_locked(
    s: &TcpSock,
    g: &mut Guard<'_>,
    m: &mut SendMsg<'_>,
    flags: i32,
) -> Result<usize, KernelError> {
    let mut timeo = s.sk.snd_timeo(flags & MSG_DONTWAIT != 0);
    wait_connected(s, g, &mut timeo)?;
    let total = m.data.len();
    let mut sent = 0;
    let r = loop {
        if sent == total {
            break Ok(());
        }
        let (n, no_mem) = match send_some(s, g, m, sent, flags) {
            Ok(r) => r,
            Err(e) => break Err(e),
        };
        sent += n;
        let w = if no_mem {
            // Room in the buffer but no TCP memory: nobody wakes us when
            // other connections free some, so sleep a random 2..201 ms
            // (Linux sk_stream_wait_memory vm_wait), cut short only by an
            // error or shutdown
            wait_memory(s, g, &mut timeo)
        } else if n == 0 {
            wait_space(s, g, &mut timeo)
        } else {
            Ok(())
        };
        if let Err(e) = w {
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
        let linger0 = self.sk.linger() == Some(0);
        self.step(|g, out| {
            // As the owner, as every write of the shutdown bits (Linux
            // __tcp_close under lock_sock)
            self.sk.set_shutdown(SHUTDOWN_MASK);
            g.cb.orphan = true;
            g.orphan.get_or_insert_with(mem::Orphan::new);
            if g.cb.state == TcpState::Listen {
                self.sk.set_flag(sf::ACCEPTCONN, false);
                self.sk
                    .net
                    .tcp
                    .listen_del(self.inet.get().sport, &self.arc());
                g.cb.set_closed(out);
                // Its children stop as the owner (Linux tcp_close ->
                // inet_csk_listen_stop under lock_sock, after TCP_CLOSE)
                let q = self.take_queue();
                if let Some(q) = q {
                    self.listen_stop(q);
                }
                return;
            }
            g.cb.close(linger0, now_ms(), out);
            if g.cb.state == TcpState::Closed {
                out.done = true;
            }
        });
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
        let mut g = self.lock_sock();
        if g.cb.state != TcpState::Closed || self.inet.get().sport != 0 {
            return Err(KernelError::InvalidArgument);
        }
        let no_port = port == 0 && self.inet.flag(ipf::BIND_NO_PORT);
        // Like Linux inet_bind: the address is set before the bhash entry
        // is published (conflict checks read it under bhash), reset if
        // that fails
        self.inet.set_saddrs(addr, addr);
        let p = if no_port {
            0
        } else {
            let range = self.sk.net.port_range.get();
            match self
                .sk
                .net
                .tcp
                .bind(&me, &self.bind_info(addr), port, range)
            {
                Ok(p) => p,
                Err(e) => {
                    self.inet
                        .set_saddrs(Ipv4Addr::default(), Ipv4Addr::default());
                    return Err(e);
                }
            }
        };
        g.bound = !no_port;
        let mut s = self.inet.addr.lock();
        s.sport = p;
        s.addr_lock = !addr.is_unspecified();
        s.port_lock = port != 0;
        Ok(())
    }

    /// Linux __inet_stream_connect, as the owner: the state checks, the
    /// start and SS_CONNECTING; the wait releases the socket while
    /// asleep
    fn connect(&self, a: &[u8], nonblock: bool) -> Result<(), KernelError> {
        if af_inet::sa_family(a)? == AF_UNSPEC {
            self.disconnect();
            return Ok(());
        }
        let mut g = self.lock_sock();
        let mut out = Out::default();
        let next = self.connect_locked(&mut g, &mut out, a, nonblock);
        self.finish(&mut g, &mut out);
        let r = match next {
            Some(r) => r,
            None => {
                let r = self.wait_connect(&mut g);
                g.connecting = false;
                r
            }
        };
        drop(g);
        dev::netif_rx_flush_local();
        r
    }

    /// Linux inet_listen (autobinds an unbound socket); a listening
    /// socket only gets its backlog updated
    fn listen(&self, backlog: i32) -> Result<(), KernelError> {
        // Linux __sys_listen: capped at net.core.somaxconn
        let backlog = (backlog as u32).min(self.sk.net.sysctl.somaxconn());
        let me = self.arc();
        let mut g = self.lock_sock();
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
            syn: OwnedList::new(),
            ready: OwnedList::new(),
        });
        g.cb.state = TcpState::Listen;
        self.sk.set_flag(sf::ACCEPTCONN, true);
        // The options children copy, set before the listener can be
        // found: a SYN backlogged while this call owns the socket is
        // answered at its release, before `apply` would copy them
        // (Linux tcp_conn_request reads the listener itself)
        *self.listen_opts.lock() = g.cb.opts;
        let port = self.inet.get().sport;
        self.sk.net.tcp.listen_add(port, me);
        // Debug and LOCKDEP builds: a listener owns its port in bhash.
        // Checked here, as the owner (a close cannot race it), not on
        // the lockless SYN path, where one can
        if cfg!(any(debug_assertions, feature = "lockdep")) {
            assert!(
                self.sk.net.tcp.owns(port, &self.arc()),
                "tcp: listener on port {port} is no bhash owner"
            );
        }
        Ok(())
    }

    /// Linux inet_csk_accept: waits up to SO_RCVTIMEO
    fn accept(&self, nonblock: bool) -> Result<Arc<dyn ProtoOps>, KernelError> {
        if self.state() != TcpState::Listen {
            return Err(KernelError::InvalidArgument);
        }
        let mut timeo = self.sk.rcv_timeo(nonblock);
        loop {
            let c = self.queue.lock().as_mut().and_then(|q| {
                let c = q.ready.pop_front();
                // Under `queue` (Linux sk_acceptq_removed)
                self.ack_backlog
                    .store(q.ready.len() as u32, Ordering::Relaxed);
                c
            });
            if let Some(c) = c {
                return Ok(c);
            }
            if self.state() != TcpState::Listen {
                return Err(KernelError::InvalidArgument);
            }
            // Linux inet_csk_wait_for_connect: the queue's emptiness
            // read lock-free (reqsk_queue_empty)
            let ready = || {
                self.ack_backlog.load(Ordering::Relaxed) != 0 || self.state() != TcpState::Listen
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

    /// Linux tcp_poll: the lockless view (READ_ONCE fields)
    fn poll(&self) -> u16 {
        let state = self.state();
        if state == TcpState::Listen {
            // Linux inet_csk_listen_poll: reqsk_queue_empty, lock-free
            let ready = self.ack_backlog.load(Ordering::Relaxed) != 0;
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
            let inq = self.snap.rcvq.load(Ordering::Acquire);
            if inq >= self.sk.rcvlowat().max(1) as usize {
                mask |= POLLIN | POLLRDNORM;
            }
            let writable = || self.snap.writable.load(Ordering::Acquire);
            if sh & SEND_SHUTDOWN != 0 || writable() {
                mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
            } else {
                // SIGIO once there is room; room made before the bits
                // were set is seen by the second look (Linux tcp_poll:
                // SOCKWQ_ASYNC_NOSPACE and SOCK_NOSPACE)
                self.sk.set_nospace();
                self.live.nospace.store(true, Ordering::Release);
                if writable() {
                    mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
                }
            }
        }
        if self.sk.err_pending() {
            mask |= POLLERR;
        }
        mask
    }

    /// Linux tcp_ioctl: SIOCINQ as the owner, SIOCOUTQ from the
    /// lockless view
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        if matches!(cmd, SIOCINQ | SIOCOUTQ) && self.state() == TcpState::Listen {
            return Err(KernelError::InvalidArgument);
        }
        let v = match cmd {
            SIOCINQ => self.lock_sock().cb.rcvq_len(),
            SIOCOUTQ => self.snap.sndq.load(Ordering::Acquire),
            _ => return Err(KernelError::NotTty),
        };
        crate::uaccess::put_user::<i32>(arg, v as i32).map_err(|_| KernelError::BadAddress)?;
        Ok(0)
    }

    fn inq(&self) -> usize {
        self.snap.rcvq.load(Ordering::Acquire)
    }

    /// Linux inet_shutdown + tcp_shutdown: the state test and the
    /// shutdown change as the owner
    fn shutdown(&self, how: i32) -> Result<(), KernelError> {
        let bits = shut_bits(how)?;
        let (r, q) = self.step(|g, out| match g.cb.state {
            TcpState::Closed => {
                self.sk.or_shutdown(bits);
                (Err(KernelError::NotConnected), false)
            }
            // Linux: a listener stops listening on SHUT_RD, a SYN_SENT
            // socket goes back to unconnected (disconnect)
            TcpState::Listen if bits & RCV_SHUTDOWN == 0 => (Ok(()), false),
            TcpState::Listen | TcpState::SynSent => {
                self.disconnect_locked(g, out);
                (Ok(()), true)
            }
            _ => {
                self.sk.or_shutdown(bits);
                if bits & RCV_SHUTDOWN != 0 {
                    g.cb.rcv_shut = true;
                }
                if bits & SEND_SHUTDOWN != 0 {
                    g.cb.shutdown_wr(now_ms(), out);
                }
                (Ok(()), false)
            }
        });
        if q {
            self.disconnect_done();
        } else {
            dev::netif_rx_flush_local();
        }
        self.sk.state_change();
        r
    }

    fn setsockopt(&self, level: i32, opt: i32, v: OptIn) -> Option<Result<(), KernelError>> {
        match level {
            SOL_SOCKET if opt == SO_KEEPALIVE => Some(self.set_keepalive(v)),
            SOL_SOCKET if opt == SO_RCVLOWAT => Some(self.set_rcvlowat(v)),
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

    fn sendmsg(&self, m: &mut SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
        tcp_sendmsg(self, m, flags)
    }

    fn recvmsg(&self, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
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
                    g.cb.live
                        .fastopen
                        .set((val as u32).min(self.sk.net.sysctl.somaxconn()));
                }
                TCP_NOTSENT_LOWAT => {
                    g.cb.opts.notsent_lowat = val as u32;
                    out.wake |= cb::wake::SPACE;
                }
                _ => return Err(KernelError::NoProtocolOption),
            }
            Ok(())
        })
    }

    /// TCP_CONGESTION: a NUL-terminated name of a built-in algorithm
    /// (Linux tcp_set_congestion_control: the current one is no change;
    /// ENOENT when none matches, EPERM for a restricted one without
    /// CAP_NET_ADMIN)
    fn set_congestion(&self, v: OptIn) -> Result<(), KernelError> {
        if v.len < 1 {
            return Err(KernelError::InvalidArgument);
        }
        let b = v.bytes(cong::NAME_MAX - 1)?;
        let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        let name = core::str::from_utf8(&b[..n]).map_err(|_| KernelError::NotFound)?;
        let i = cong::find(name);
        let mut g = self.lock_sock();
        if i != Some(g.cb.cong.algo()) {
            let i = i.ok_or(KernelError::NotFound)?;
            if !cong::allowed(i) && !crate::task::capable(crate::task::CAP_NET_ADMIN) {
                return Err(KernelError::PermissionDenied);
            }
            g.cb.opts.ca = i;
            g.cb.set_cc(i);
        }
        g.cb.opts.ca_set = true;
        Ok(())
    }

    /// IPPROTO_TCP getsockopt (Linux do_tcp_getsockopt)
    fn get_tcp_opt(&self, opt: i32) -> Result<OptOut, KernelError> {
        let g = self.lock_sock();
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
                    g.cb.live.mss.get()
                }
            }
            TCP_NODELAY => u32::from(o.nodelay),
            TCP_CORK => u32::from(o.cork),
            TCP_QUICKACK => u32::from(g.cb.quickack()),
            TCP_KEEPIDLE => g.cb.keep_idle() as u32 / 1000,
            TCP_KEEPINTVL => g.cb.keep_intvl() as u32 / 1000,
            TCP_KEEPCNT => g.cb.keep_cnt(),
            TCP_SYNCNT => self.syncnt(o),
            TCP_USER_TIMEOUT => o.user_timeout,
            TCP_DEFER_ACCEPT => info::retrans_to_secs(o.defer_accept),
            TCP_FASTOPEN => g.cb.live.fastopen.get(),
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

    /// Readers may have enough now (Linux tcp_set_rcvlowat:
    /// tcp_data_ready)
    fn set_rcvlowat(&self, v: OptIn) -> Result<(), KernelError> {
        crate::net::socket::sock_setsockopt(self, SO_RCVLOWAT, v)?;
        self.sk.data_ready();
        Ok(())
    }
}
