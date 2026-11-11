//! Datagram receive queue shared by UDP, ping and raw sockets (Linux
//! net/core/datagram.c + the sk_receive_queue/sk_rmem_alloc parts of
//! sock.c)
//!
//! ## Locking
//!
//! `RxQueue.q` is an `SkbQueue` (its spin lock a leaf, thread only:
//! softnet enqueue, recvmsg). A datagram is the received skb itself,
//! wrapped in an `Arc` (Linux skb->users) before the lock is taken, so
//! queueing allocates nothing; MSG_PEEK takes a reference under the
//! lock and copies after it. The socket is woken after it is dropped,
//! and skbs taken off are dropped after it too.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::io::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};
use crate::mm::page_alloc::Gfp;
use crate::net::af_inet::{self, Inet, RxInfo};
use crate::net::msg::{MSG_DONTWAIT, MSG_PEEK, MSG_TRUNC, RecvMsg};
use crate::net::skb::{InetCb, SkBuff, SkbCb, SkbQueue};
use crate::net::sock::{RCV_SHUTDOWN, SHUTDOWN_MASK, Sock, sf};
use crate::net::socket::SOL_SOCKET;
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc_gfp;

/// SCM_TIMESTAMP / SCM_TIMESTAMPNS (= SO_TIMESTAMP*_OLD), SO_RXQ_OVFL
const SCM_TIMESTAMP: i32 = 29;
const SCM_TIMESTAMPNS: i32 = 35;
const SO_RXQ_OVFL: i32 = 40;

/// Make a received skb (data at the payload to deliver) a datagram for
/// a socket: its control message data and source port go in the cb
pub fn prepare(skb: &mut SkBuff, info: RxInfo, sport: u16) {
    skb.cb = SkbCb::Inet(InetCb { info, sport });
}

/// The CLOCK_REALTIME time now (ns), for a skb not stamped on arrival
pub fn now() -> i128 {
    crate::time::TIMEKEEPER.current_time().to_nanos()
}

/// A socket's receive queue, bounded by SO_RCVBUF
pub struct RxQueue {
    q: SkbQueue,
    rmem: AtomicUsize,
}

impl Default for RxQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl RxQueue {
    #[track_caller]
    pub const fn new() -> Self {
        Self {
            q: SkbQueue::new(),
            rmem: AtomicUsize::new(0),
        }
    }

    /// Queue unless the receive buffer is full (Linux
    /// __udp_enqueue_schedule_skb / sock_queue_rcv_skb: admit while
    /// rmem <= rcvbuf); drops are counted. The `Arc` around the skb is
    /// allocated GFP_ATOMIC before the lock (receive path); failing
    /// that, the datagram is dropped like a full queue's.
    pub fn enqueue(&self, sk: &Sock, mut skb: SkBuff) {
        if self.rmem.load(Ordering::Acquire) > sk.rcvbuf() as usize {
            sk.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        skb.dropcount = sk.drops.load(Ordering::Relaxed);
        // No device reference in a socket queue (Linux: the cb keeps
        // the ifindex)
        skb.dev = None;
        if skb.tstamp == 0 {
            skb.tstamp = now();
        }
        let size = skb.truesize();
        let Ok(skb) = try_arc_gfp(skb, Gfp::ATOMIC) else {
            sk.drops.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.rmem.fetch_add(size, Ordering::AcqRel);
        self.q.lock().push_back(skb);
        sk.data_ready();
    }

    pub fn readable(&self) -> bool {
        !self.q.is_empty()
    }

    /// Next datagram: taken off, or a reference left queued if `peek`
    fn dequeue(&self, peek: bool) -> Option<Arc<SkBuff>> {
        if peek {
            return self.q.peek();
        }
        let skb = self.q.dequeue()?;
        self.rmem.fetch_sub(skb.truesize(), Ordering::AcqRel);
        Some(skb)
    }

    /// Payload length of the first datagram (Linux first_packet_length)
    pub fn inq(&self) -> usize {
        self.q.lock().front().map_or(0, SkBuff::len)
    }

    /// Bytes charged (Linux sk_rmem_alloc)
    pub fn rmem(&self) -> usize {
        self.rmem.load(Ordering::Relaxed)
    }

    /// Purge the queue, uncharging exactly what it held (a concurrent
    /// enqueue charges before it pushes, a dequeue uncharges after it
    /// pops: zeroing the counter would let them skew it); the skbs are
    /// dropped after the lock
    pub fn clear(&self) {
        let q = self.q.purge();
        let n: usize = q.iter().map(SkBuff::truesize).sum();
        self.rmem.fetch_sub(n, Ordering::AcqRel);
    }

    /// Wait for a datagram (Linux __skb_recv_datagram): a pending error
    /// first; non-blocking: EAGAIN; blocking after SHUT_RD: None (recv
    /// returns 0); timeout EAGAIN; signals per `Sock::wait`
    pub fn recv(&self, sk: &Sock, flags: i32) -> Result<Option<Arc<SkBuff>>, KernelError> {
        let mut timeo = sk.rcv_timeo(flags & MSG_DONTWAIT != 0);
        loop {
            if let Some(e) = sk.take_err() {
                return Err(e);
            }
            if let Some(d) = self.dequeue(flags & MSG_PEEK != 0) {
                return Ok(Some(d));
            }
            if timeo == 0 {
                return Err(KernelError::WouldBlock);
            }
            if sk.shutdown() & RCV_SHUTDOWN != 0 {
                return Ok(None);
            }
            timeo = sk.wait(timeo, || {
                self.readable() || sk.has_err() || sk.shutdown() & RCV_SHUTDOWN != 0
            })?;
        }
    }
}

/// Copy a datagram into a receive request: data (MSG_TRUNC when cut),
/// source address, SOL_SOCKET and IP control messages. Returns the
/// length recvmsg reports (the full length with MSG_TRUNC in `flags`).
pub fn deliver(
    sk: &Sock,
    inet: &Inet,
    m: &mut RecvMsg<'_>,
    skb: &SkBuff,
    flags: i32,
) -> Result<usize, KernelError> {
    let SkbCb::Inet(cb) = skb.cb else {
        return Err(KernelError::InvalidArgument);
    };
    let data = skb.data();
    let n = m.data.put(0, data)?;
    if n < data.len() {
        m.flags |= MSG_TRUNC;
    }
    if m.want_name {
        m.name = Some(af_inet::sin_bytes(skb.saddr.unwrap_or_default(), cb.sport));
    }
    sock_cmsgs(sk, m, skb.tstamp, skb.dropcount);
    inet.recv_cmsgs(&mut m.cmsg, &cb.info);
    Ok(if flags & MSG_TRUNC != 0 {
        data.len()
    } else {
        n
    })
}

/// SOL_SOCKET control messages (Linux __sock_recv_cmsgs) of a packet
/// that arrived at `stamp` (CLOCK_REALTIME ns) with the socket's drop
/// count at `drops`
pub fn sock_cmsgs(sk: &Sock, m: &mut RecvMsg<'_>, stamp: i128, drops: u32) {
    if sk.flag(sf::TIMESTAMPNS) {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&((stamp / 1_000_000_000) as i64).to_ne_bytes());
        b[8..].copy_from_slice(&((stamp % 1_000_000_000) as i64).to_ne_bytes());
        m.cmsg.put(SOL_SOCKET, SCM_TIMESTAMPNS, &b);
    } else if sk.flag(sf::TIMESTAMP) {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&((stamp / 1_000_000_000) as i64).to_ne_bytes());
        b[8..].copy_from_slice(&((stamp % 1_000_000_000 / 1000) as i64).to_ne_bytes());
        m.cmsg.put(SOL_SOCKET, SCM_TIMESTAMP, &b);
    }
    if sk.flag(sf::RXQ_OVFL) && drops != 0 {
        m.cmsg.put(SOL_SOCKET, SO_RXQ_OVFL, &drops.to_ne_bytes());
    }
}

/// Linux datagram_poll: sends are synchronous, so always writable
pub fn poll(sk: &Sock, rxq: &RxQueue) -> u16 {
    let mut mask = 0;
    if sk.err_pending() {
        mask |= POLLERR;
    }
    let sh = sk.shutdown();
    if sh & RCV_SHUTDOWN != 0 {
        mask |= POLLRDHUP | POLLIN | POLLRDNORM;
    }
    if sh == SHUTDOWN_MASK {
        mask |= POLLHUP;
    }
    if rxq.readable() {
        mask |= POLLIN | POLLRDNORM;
    }
    mask | POLLOUT | POLLWRNORM | POLLWRBAND
}
