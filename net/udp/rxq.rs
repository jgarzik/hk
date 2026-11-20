//! A UDP socket's receive queue and its memory (Linux sk_receive_queue
//! with __udp_enqueue_schedule_skb, udp_rmem_release, __skb_recv_udp,
//! __skb_try_recv_from_queue)
//!
//! A queued datagram is charged its truesize to the socket (`rmem`,
//! Linux sk_rmem_alloc) and to UDP's global count in whole pages ahead
//! of need (`fwd`, Linux sk_forward_alloc; `mem`). Reading gives bytes
//! back in batches (`deficit`, Linux forward_deficit: released once a
//! quarter of SO_RCVBUF is owed or the queue empties) and returns
//! whole pages, keeping under one page forward-allocated until close.
//!
//! ## Locking
//!
//! `UdpRxq.st` (spin, Linux sk_receive_queue.lock: a leaf, thread
//! only) guards the queue, `fwd` and `deficit`; `rmem` changes only
//! under it and is read without it (admission, /proc). The global count
//! (`mem`) takes no lock. The socket is woken after the lock is
//! dropped, and skbs taken off are dropped after it too.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::mem;
use crate::mm::page_alloc::Gfp;
use crate::net::dgram::{QueueErr, now};
use crate::net::msg::{MSG_DONTWAIT, MSG_PEEK};
use crate::net::skb::{SkBuff, SkbHead};
use crate::net::sock::{RCV_SHUTDOWN, Sock, sf};
use crate::sync::spin::Mutex;
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc_gfp;

/// What `UdpRxq.st` guards
#[derive(Default)]
struct RxState {
    q: SkbHead,
    /// Bytes charged to the global count, not yet to a datagram (Linux
    /// sk_forward_alloc)
    fwd: usize,
    /// Bytes read and not yet released (Linux forward_deficit)
    deficit: usize,
    /// Datagrams queued so far: a reader waits for it to change when
    /// every queued one is behind its peek offset (Linux
    /// __skb_wait_for_more_packets' `last`)
    seq: u64,
}

#[derive(Default)]
pub struct UdpRxq {
    st: Mutex<RxState>,
    /// Bytes queued (Linux sk_rmem_alloc)
    rmem: AtomicUsize,
}

impl UdpRxq {
    /// Bytes charged (Linux sk_rmem_alloc)
    pub fn rmem(&self) -> usize {
        self.rmem.load(Ordering::Relaxed)
    }

    pub fn readable(&self) -> bool {
        !self.st.lock().q.is_empty()
    }

    /// Payload length of the first datagram (Linux first_packet_length;
    /// checksums are verified on arrival)
    pub fn inq(&self) -> usize {
        self.st.lock().q.front().map_or(0, SkBuff::len)
    }

    /// Queue a datagram (Linux __udp_enqueue_schedule_skb): dropped
    /// when it would pass SO_RCVBUF unless the queue is empty (RcvBuf),
    /// or when its pages cannot be charged (NoMem); drops are counted
    pub fn enqueue(&self, sk: &Sock, rmem_min: usize, mut skb: SkBuff) -> Result<(), QueueErr> {
        let rmem = self.rmem();
        let rcvbuf = sk.rcvbuf() as usize;
        let size = skb.truesize();
        if rmem + size > rcvbuf && (rcvbuf > (i32::MAX >> 1) as usize || rmem != 0) {
            sk.drops.fetch_add(1, Ordering::Relaxed);
            return Err(QueueErr::RcvBuf);
        }
        skb.dropcount = if sk.flag(sf::RXQ_OVFL) {
            sk.drops.load(Ordering::Relaxed)
        } else {
            0
        };
        // No device reference in a socket queue (Linux: the cb keeps
        // the ifindex)
        skb.dev = None;
        if skb.tstamp == 0 {
            skb.tstamp = now();
        }
        let Ok(skb) = try_arc_gfp(skb, Gfp::ATOMIC) else {
            sk.drops.fetch_add(1, Ordering::Relaxed);
            return Err(QueueErr::NoMem);
        };
        let mut st = self.st.lock();
        // Linux udp_rmem_schedule
        if size > st.fwd {
            let amt = mem::pages(size - st.fwd);
            if !mem::raise(amt, self.rmem(), rmem_min) {
                drop(st);
                sk.drops.fetch_add(1, Ordering::Relaxed);
                return Err(QueueErr::NoMem);
            }
            st.fwd += amt * mem::QUANTUM;
        }
        st.fwd -= size;
        st.q.push_back(skb);
        st.seq += 1;
        self.rmem.fetch_add(size, Ordering::Relaxed);
        drop(st);
        sk.data_ready();
        Ok(())
    }

    /// Give back `size` bytes read (Linux udp_rmem_release): `partial`
    /// batches them until a quarter of SO_RCVBUF is owed or the queue
    /// is empty, and keeps under a page forward-allocated
    fn release(&self, st: &mut RxState, rcvbuf: usize, size: usize, partial: bool) {
        let mut size = size;
        if partial {
            st.deficit += size;
            size = st.deficit;
            if size < rcvbuf >> 2 && !st.q.is_empty() {
                return;
            }
        } else {
            size += st.deficit;
        }
        st.deficit = 0;
        let amt = (size + st.fwd - usize::from(partial)) & !(mem::QUANTUM - 1);
        st.fwd = st.fwd + size - amt;
        if amt != 0 {
            mem::reduce(amt / mem::QUANTUM);
        }
        self.rmem.fetch_sub(size, Ordering::Relaxed);
    }

    /// The datagram a read with `flags` gets (Linux
    /// __skb_try_recv_from_queue): taken off and released, or with
    /// MSG_PEEK a reference left queued, skipping whole datagrams
    /// before the peek offset `off` (a zero-length one once peeked);
    /// `off` becomes the offset into the one returned
    fn try_recv(&self, sk: &Sock, flags: i32, off: &mut i32) -> Option<Arc<SkBuff>> {
        let mut st = self.st.lock();
        if flags & MSG_PEEK == 0 {
            let skb = st.q.pop_front()?;
            // Linux udp_skb_destructor
            self.release(&mut st, sk.rcvbuf() as usize, skb.truesize(), true);
            *off = 0;
            return Some(skb);
        }
        let at = *off >= 0;
        let mut o = if at { *off as usize } else { 0 };
        let skb = st.q.find_arc(|s| {
            if at && o >= s.len() && (o != 0 || s.peeked.load(Ordering::Relaxed)) {
                o -= s.len();
                return false;
            }
            true
        })?;
        if skb.is_empty() {
            skb.peeked.store(true, Ordering::Relaxed);
        }
        *off = o as i32;
        Some(skb)
    }

    /// Wait for a datagram (Linux __skb_recv_udp): a pending error
    /// first; non-blocking: EAGAIN; blocking after SHUT_RD: None (recv
    /// returns 0); timeout EAGAIN; signals per `Sock::wait`. With
    /// MSG_PEEK at an offset past every queued byte it waits for more.
    pub fn recv(
        &self,
        sk: &Sock,
        flags: i32,
        off: &mut i32,
    ) -> Result<Option<Arc<SkBuff>>, KernelError> {
        let mut timeo = sk.rcv_timeo(flags & MSG_DONTWAIT != 0);
        loop {
            if let Some(e) = sk.take_err() {
                return Err(e);
            }
            let want = *off;
            let last = self.st.lock().seq;
            if let Some(d) = self.try_recv(sk, flags, off) {
                return Ok(Some(d));
            }
            *off = want;
            if timeo == 0 {
                return Err(KernelError::WouldBlock);
            }
            if sk.shutdown() & RCV_SHUTDOWN != 0 {
                return Ok(None);
            }
            timeo = sk.wait(timeo, || {
                self.st.lock().seq != last || sk.has_err() || sk.shutdown() & RCV_SHUTDOWN != 0
            })?;
        }
    }

    /// Purge the queue and give back every byte (Linux
    /// udp_destruct_common: udp_rmem_release with no partial); the skbs
    /// are dropped after the lock. At close, and again when the socket
    /// goes, for what a receive queued meanwhile.
    pub fn clear(&self) {
        let mut st = self.st.lock();
        let q = core::mem::take(&mut st.q);
        let n: usize = q.iter().map(SkBuff::truesize).sum();
        self.release(&mut st, 0, n, false);
        drop(st);
        drop(q);
    }
}

impl Drop for UdpRxq {
    fn drop(&mut self) {
        self.clear();
    }
}
