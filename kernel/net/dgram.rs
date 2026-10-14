//! Datagram receive queue shared by UDP, ping and raw sockets (Linux
//! net/core/datagram.c + the sk_receive_queue/sk_rmem_alloc parts of
//! sock.c)
//!
//! ## Locking
//!
//! `RxQueue.q` is a `spin::Mutex` leaf (thread only: softnet enqueue,
//! recvmsg); the socket is woken after it is dropped.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::Mutex;

use crate::error::KernelError;
use crate::net::af_inet::{self, Inet, RxInfo};
use crate::net::ipv4::Ipv4Addr;
use crate::net::msg::{MSG_DONTWAIT, MSG_PEEK, MSG_TRUNC, RecvMsg};
use crate::net::sock::{RCV_SHUTDOWN, SHUTDOWN_MASK, Sock, sf};
use crate::net::socket::SOL_SOCKET;
use crate::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};

/// SCM_TIMESTAMP / SCM_TIMESTAMPNS (= SO_TIMESTAMP*_OLD), SO_RXQ_OVFL
const SCM_TIMESTAMP: i32 = 29;
const SCM_TIMESTAMPNS: i32 = 35;
const SO_RXQ_OVFL: i32 = 40;

/// A queued datagram
#[derive(Clone)]
pub struct Dgram {
    pub src: Ipv4Addr,
    /// Source port (0 for ping and raw)
    pub sport: u16,
    pub data: Vec<u8>,
    pub info: RxInfo,
    /// CLOCK_REALTIME arrival (ns)
    pub stamp: i128,
    /// Socket drop count when queued (SO_RXQ_OVFL)
    pub drops: u32,
}

impl Dgram {
    /// A datagram arriving now
    pub fn new(src: Ipv4Addr, sport: u16, data: Vec<u8>, info: RxInfo) -> Self {
        Self {
            src,
            sport,
            data,
            info,
            stamp: crate::time::TIMEKEEPER.current_time().to_nanos(),
            drops: 0,
        }
    }
}

/// Bytes charged to rcvbuf per datagram (payload + skb overhead)
fn truesize(len: usize) -> usize {
    len + 512
}

/// A socket's receive queue, bounded by SO_RCVBUF
#[derive(Default)]
pub struct RxQueue {
    q: Mutex<VecDeque<Dgram>>,
    rmem: AtomicUsize,
}

impl RxQueue {
    /// Queue unless the receive buffer is full (Linux
    /// __udp_enqueue_schedule_skb / sock_queue_rcv_skb: admit while
    /// rmem <= rcvbuf); drops are counted
    pub fn enqueue(&self, sk: &Sock, mut d: Dgram) {
        if self.rmem.load(Ordering::Acquire) > sk.rcvbuf() as usize {
            sk.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.rmem
            .fetch_add(truesize(d.data.len()), Ordering::AcqRel);
        d.drops = sk.drops.load(Ordering::Relaxed);
        self.q.lock().push_back(d);
        sk.data_ready();
    }

    pub fn readable(&self) -> bool {
        !self.q.lock().is_empty()
    }

    /// Next datagram (a copy if `peek`)
    fn dequeue(&self, peek: bool) -> Option<Dgram> {
        let mut q = self.q.lock();
        if peek {
            return q.front().cloned();
        }
        let d = q.pop_front()?;
        drop(q);
        self.rmem
            .fetch_sub(truesize(d.data.len()), Ordering::AcqRel);
        Some(d)
    }

    /// Payload length of the first datagram (Linux first_packet_length)
    pub fn inq(&self) -> usize {
        self.q.lock().front().map_or(0, |d| d.data.len())
    }

    pub fn clear(&self) {
        self.q.lock().clear();
        self.rmem.store(0, Ordering::Release);
    }

    /// Wait for a datagram (Linux __skb_recv_datagram): a pending error
    /// first; non-blocking: EAGAIN; blocking after SHUT_RD: None (recv
    /// returns 0); timeout EAGAIN; signals per `Sock::wait`
    pub fn recv(&self, sk: &Sock, flags: i32) -> Result<Option<Dgram>, KernelError> {
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
    m: &mut RecvMsg,
    d: &Dgram,
    flags: i32,
) -> Result<usize, KernelError> {
    let n = m.data.put(0, &d.data)?;
    if n < d.data.len() {
        m.flags |= MSG_TRUNC;
    }
    if m.want_name {
        m.name = Some(af_inet::sin_bytes(d.src, d.sport));
    }
    sock_cmsgs(sk, m, d);
    inet.recv_cmsgs(&mut m.cmsg, &d.info);
    Ok(if flags & MSG_TRUNC != 0 {
        d.data.len()
    } else {
        n
    })
}

/// SOL_SOCKET control messages (Linux __sock_recv_cmsgs)
fn sock_cmsgs(sk: &Sock, m: &mut RecvMsg, d: &Dgram) {
    if sk.flag(sf::TIMESTAMPNS) {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&((d.stamp / 1_000_000_000) as i64).to_ne_bytes());
        b[8..].copy_from_slice(&((d.stamp % 1_000_000_000) as i64).to_ne_bytes());
        m.cmsg.put(SOL_SOCKET, SCM_TIMESTAMPNS, &b);
    } else if sk.flag(sf::TIMESTAMP) {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&((d.stamp / 1_000_000_000) as i64).to_ne_bytes());
        b[8..].copy_from_slice(&((d.stamp % 1_000_000_000 / 1000) as i64).to_ne_bytes());
        m.cmsg.put(SOL_SOCKET, SCM_TIMESTAMP, &b);
    }
    if sk.flag(sf::RXQ_OVFL) && d.drops != 0 {
        m.cmsg.put(SOL_SOCKET, SO_RXQ_OVFL, &d.drops.to_ne_bytes());
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
