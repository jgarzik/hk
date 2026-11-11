//! AF_UNIX SOCK_DGRAM and SOCK_SEQPACKET data (Linux af_unix.c
//! unix_dgram_connect, unix_dgram_sendmsg, __unix_dgram_recvmsg,
//! unix_seqpacket_*, unix_dgram_poll, unix_dgram_peer_wake_*)
//!
//! A datagram socket accepts messages from anyone unless it is itself
//! connected (then only from its peer: EPERM). A receiver that is not
//! connected back to the sender takes at most `backlog` queued messages
//! from it (net.unix.max_dgram_qlen); the sender then blocks or gets
//! EAGAIN. A poller of such a sender registers on the receiver's
//! `relay` list and is woken once when the receiver makes room (Linux
//! peer_wake). Sending to a connected peer that was closed is
//! ECONNREFUSED once (the connection is dropped), then ENOTCONN.
//!
//! SOCK_SEQPACKET is connection-oriented (connect/accept in
//! `stream.rs`) and keeps message boundaries through these paths;
//! after the peer closes, reads return 0 and writes EPIPE.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::io::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};
use crate::net::msg::{MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_TRUNC, RecvMsg, SendMsg};
use crate::net::sock::SHUTDOWN_MASK;
use crate::net::socket::{AF_UNSPEC, SOCK_SEQPACKET};
use crate::sync::waitqueue::WaitEntry;
use crate::task::percpu::WakeMode;
use crate::util::error::KernelError;

use super::scm::{Creds, FpList, Scm, too_many_fds};
use super::{
    CLOSE, ESTABLISHED, LISTEN, SUN_PATH, UnixSock, add_creds, family, find_other, peek_fds, queue,
    rcv_shut, ucb, ucb_mut, unix_len, unix_skb, validate,
};
use crate::mm::page_alloc::Gfp;
use crate::net::skb::SkBuff;
use crate::util::kalloc::try_arc_gfp;

/// Linux unix_may_send: `other` (whose peer is `other_peer`) takes
/// messages from `s` unless connected to someone else
fn may_send(s: &UnixSock, other_peer: &Option<Arc<UnixSock>>) -> bool {
    other_peer.as_ref().is_none_or(|p| p.id() == s.id())
}

fn is(p: &Option<Arc<UnixSock>>, s: &UnixSock) -> bool {
    p.as_ref().is_some_and(|p| p.id() == s.id())
}

/// Linux unix_dgram_connect: set (or with AF_UNSPEC clear) the default
/// destination; both ends count as established
pub fn connect(s: &UnixSock, a: &[u8]) -> Result<(), KernelError> {
    if a.len() < SUN_PATH {
        return Err(KernelError::InvalidArgument);
    }
    if family(a) == AF_UNSPEC {
        let old = {
            let mut g = s.st.lock();
            let old = g.take();
            if old.is_some() {
                s.set_state(CLOSE);
            }
            old
        };
        reconnected(s, old, None);
        return Ok(());
    }
    validate(a)?;
    s.passcred_autobind()?;
    loop {
        let other = find_other(&s.sk.net, a, s.sk.stype)?;
        let old = {
            let (mut gs, go) = UnixSock::lock2(s, &other);
            // Released after the lookup: look up again
            if other.is_dead() {
                continue;
            }
            let other_peer = match &go {
                Some(g) => (**g).clone(),
                None => (*gs).clone(),
            };
            if !may_send(s, &other_peer) {
                return Err(KernelError::NotPermitted);
            }
            s.set_state(ESTABLISHED);
            other.set_state(ESTABLISHED);
            gs.replace(other.clone())
        };
        reconnected(s, old, Some(&other));
        return Ok(());
    }
}

/// After the peer changed from `old` (Linux unix_dgram_connect tail):
/// writers polling for room in `old` are released, and messages that
/// came from `old` are dropped
fn reconnected(s: &UnixSock, old: Option<Arc<UnixSock>>, new: Option<&Arc<UnixSock>>) {
    let Some(old) = old else {
        return;
    };
    peer_wake_disconnect(s, &old);
    s.sk.write_space();
    if new.is_some_and(|n| n.id() == old.id()) {
        return;
    }
    disconnected(s, &old);
    let g = old.st.lock();
    if g.is_none() {
        old.set_state(CLOSE);
    }
}

/// Linux unix_dgram_disconnected: purge our queue; if `other` was
/// connected back to us, it loses messages: ECONNRESET for it
fn disconnected(s: &UnixSock, other: &UnixSock) {
    let q = s.purge();
    if q.is_empty() {
        return;
    }
    s.relay_wake();
    if !other.is_dead() && is(&other.peer(), s) {
        other.sk.set_err(KernelError::ConnectionReset);
    }
    drop(q);
}

/// Outcome of one queueing attempt
enum Tx {
    Sent,
    /// The receiver's queue is full
    Full,
    /// The receiver was released
    Dead,
}

/// Linux unix_dgram_sendmsg
pub fn sendmsg(s: &UnixSock, m: &mut SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
    let mut scm = Scm::parse(&m.control)?;
    if flags & MSG_OOB != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    if let Some(a) = &m.addr {
        validate(a)?;
    }
    s.passcred_autobind()?;
    let len = m.data.len();
    if len > (s.sk.sndbuf() as usize).saturating_sub(32) {
        return Err(KernelError::MessageTooLong);
    }
    let nonblock = flags & MSG_DONTWAIT != 0;
    let mut timeo = s.sk.snd_timeo(nonblock);
    s.wmem_wait(&mut timeo)?;
    let mut skb = unix_skb(&s.arc(), m.data.take(len)?);
    ucb_mut(&mut skb).creds = scm.creds;
    if let Some(f) = scm.fds.take() {
        if too_many_fds() {
            return Err(KernelError::TooManyRefs);
        }
        *ucb_mut(&mut skb).fp.get_mut() = Some(f);
    }
    let mut other = match &m.addr {
        Some(a) => find_other(&s.sk.net, a, s.sk.stype)?,
        None => s.peer().ok_or(KernelError::NotConnected)?,
    };
    add_creds(&mut skb, s, &other);
    // Its Arc before any lock (Linux: the skb is allocated first)
    let mut skb = Some(try_arc_gfp(skb, Gfp::KERNEL)?);
    loop {
        match try_send(s, &other, &mut skb)? {
            Tx::Sent => return Ok(len),
            Tx::Dead => other = peer_died(s, &other, m.addr.as_deref())?,
            Tx::Full if timeo > 0 => {
                match crate::net::sock::wait_on(&other.peer_wait, timeo, || {
                    other.is_dead() || rcv_shut(&other) || !other.recvq_full()
                }) {
                    Ok(t) => timeo = t,
                    Err(KernelError::WouldBlock) => timeo = 0,
                    Err(e) => return Err(e),
                }
            }
            Tx::Full => {
                // Under our state lock, so the peer stays our peer
                // (Linux: under unix_state_double_lock)
                let st = s.st.lock();
                if !is(&st, &other) || peer_wake_me(s, &other) {
                    return Err(KernelError::WouldBlock);
                }
            }
        }
    }
}

/// Queue under the receiver's lock (Linux unix_dgram_sendmsg
/// restart_locked)
fn try_send(
    s: &UnixSock,
    other: &Arc<UnixSock>,
    skb: &mut Option<Arc<SkBuff>>,
) -> Result<Tx, KernelError> {
    {
        let g = other.st.lock();
        if !may_send(s, &g) {
            return Err(KernelError::NotPermitted);
        }
        if other.is_dead() {
            return Ok(Tx::Dead);
        }
        if rcv_shut(other) {
            return Err(KernelError::BrokenPipe);
        }
        if other.id() != s.id() && !is(&g, s) && other.recvq_full() {
            return Ok(Tx::Full);
        }
        queue(other, skb.take().expect("message"));
    }
    other.sk.data_ready();
    Ok(Tx::Sent)
}

/// The receiver was released: a seqpacket write is EPIPE; our
/// connection to it is dropped (ECONNREFUSED); a connected send without
/// an address is ECONNRESET; a named destination is looked up again
fn peer_died(
    s: &UnixSock,
    other: &Arc<UnixSock>,
    addr: Option<&[u8]>,
) -> Result<Arc<UnixSock>, KernelError> {
    if s.sk.stype == SOCK_SEQPACKET {
        return Err(KernelError::BrokenPipe);
    }
    let was = {
        let mut g = s.st.lock();
        if is(&g, other) {
            s.set_state(CLOSE);
            g.take()
        } else {
            None
        }
    };
    if let Some(o) = was {
        peer_wake_disconnect(s, &o);
        s.sk.write_space();
        disconnected(s, &o);
        return Err(KernelError::ConnectionRefused);
    }
    match addr {
        Some(a) => find_other(&s.sk.net, a, s.sk.stype),
        None => Err(KernelError::ConnectionReset),
    }
}

/// Linux unix_seqpacket_sendmsg: established only; an address is
/// ignored
pub fn seqpacket_sendmsg(
    s: &UnixSock,
    m: &mut SendMsg<'_>,
    flags: i32,
) -> Result<usize, KernelError> {
    if let Some(e) = s.sk.take_err() {
        return Err(e);
    }
    if s.state() != ESTABLISHED {
        return Err(KernelError::NotConnected);
    }
    m.addr = None;
    sendmsg(s, m, flags)
}

/// Linux unix_seqpacket_recvmsg
pub fn seqpacket_recvmsg(
    s: &UnixSock,
    m: &mut RecvMsg<'_>,
    flags: i32,
) -> Result<usize, KernelError> {
    if s.state() != ESTABLISHED {
        return Err(KernelError::NotConnected);
    }
    recvmsg(s, m, flags)
}

/// A received message: taken off, or a reference left queued for
/// MSG_PEEK; its files taken (or copied for MSG_PEEK)
struct Rx {
    skb: Arc<SkBuff>,
    creds: Option<Creds>,
    fds: Option<FpList>,
}

/// Take (or reference, with MSG_PEEK) the head message; a dequeue
/// makes room for blocked or polling senders. The caller holds
/// `iolock`, so only it takes the files.
fn take(s: &UnixSock, peek: bool) -> Option<Rx> {
    let skb = if peek {
        s.rq.peek()?
    } else {
        let mut q = s.rq.lock();
        let skb = q.pop_front()?;
        s.inq_len.fetch_sub(unix_len(&skb), Ordering::AcqRel);
        drop(q);
        s.relay_wake();
        skb
    };
    let fds = if peek {
        peek_fds(&skb)
    } else {
        ucb(&skb).fp.lock().take()
    };
    Some(Rx {
        creds: ucb(&skb).creds.clone(),
        fds,
        skb,
    })
}

/// Linux __unix_dgram_recvmsg: whole messages; MSG_TRUNC flags a short
/// buffer (and as a flag returns the full length). With nothing queued:
/// EAGAIN when non-blocking (0 for a shut-down seqpacket socket), 0
/// after receive shutdown, ENOTCONN for a disconnected seqpacket socket.
pub fn recvmsg(s: &UnixSock, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
    if flags & MSG_OOB != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    let seqpacket = s.sk.stype == SOCK_SEQPACKET;
    let mut timeo = s.sk.rcv_timeo(flags & MSG_DONTWAIT != 0);
    loop {
        if let Some(e) = s.sk.take_err() {
            return Err(e);
        }
        {
            let _io = s.iolock.lock();
            if let Some(rx) = take(s, flags & MSG_PEEK != 0) {
                return deliver(s, m, flags, rx);
            }
        }
        if timeo == 0 {
            return if seqpacket && rcv_shut(s) {
                Ok(0)
            } else {
                Err(KernelError::WouldBlock)
            };
        }
        if rcv_shut(s) {
            return Ok(0);
        }
        if seqpacket && s.state() != ESTABLISHED && s.state() != LISTEN {
            return Err(KernelError::NotConnected);
        }
        match s.sk.wait(timeo, || {
            !s.rq.is_empty()
                || s.sk.has_err()
                || rcv_shut(s)
                || (seqpacket && s.state() != ESTABLISHED)
        }) {
            Ok(t) => timeo = t,
            Err(KernelError::WouldBlock) => timeo = 0,
            Err(e) => return Err(e),
        }
    }
}

/// Copy one message out with its address and ancillary data
fn deliver(
    s: &UnixSock,
    m: &mut RecvMsg<'_>,
    flags: i32,
    mut rx: Rx,
) -> Result<usize, KernelError> {
    if m.want_name {
        m.name = ucb(&rx.skb).wmem.from.addr().map(|a| a.name.clone());
    }
    let n = rx.skb.len();
    let size = n.min(m.data.len());
    if size < n {
        m.flags |= MSG_TRUNC;
    }
    m.data.put(0, &rx.skb.data()[..size])?;
    super::scm_recv(s, m, rx.creds.take(), rx.fds.take());
    drop(rx);
    Ok(if flags & MSG_TRUNC != 0 { n } else { size })
}

/// A wakeup on the peer's `peer_wait` reached our `peer_wake` entry
/// (Linux unix_dgram_peer_wake_relay): under that queue's lock, which
/// unlinks the entry (it returns true); wake our pollers
pub fn peer_wake_relay(e: &WaitEntry, _mode: WakeMode, key: usize) -> bool {
    // SAFETY: `private` is the socket embedding `e` (UnixSock::new),
    // alive while its entry is linked: its drop unlinks it first under
    // this queue's lock, which the waker holds
    let u = unsafe { &*(e.private as *const UnixSock) };
    u.peer_wake_to.store(0, Ordering::Release);
    u.sk.wq.wake_poll(key as u32);
    true
}

/// Linux unix_dgram_peer_wake_connect: link our `peer_wake` once on
/// `other`'s `peer_wait`; true if this call linked it. The caller holds
/// our `st` with `other` as our peer.
fn peer_wake_connect(s: &UnixSock, other: &UnixSock) -> bool {
    let _r = other.relay.lock();
    if s.peer_wake_to.load(Ordering::Acquire) != 0 {
        return false;
    }
    s.peer_wake_to.store(other.id(), Ordering::Release);
    // INVARIANT: linked on our peer's queue
    other.peer_wait.add_wait_queue_once(s.peer_wake());
    true
}

/// Linux unix_dgram_peer_wake_disconnect: off `other`'s `peer_wait`
/// (called before our reference to the old peer goes)
pub fn peer_wake_disconnect(s: &UnixSock, other: &UnixSock) {
    let _r = other.relay.lock();
    if s.peer_wake_to.load(Ordering::Acquire) == other.id() {
        other.peer_wait.remove_wait_queue(s.peer_wake());
        s.peer_wake_to.store(0, Ordering::Release);
    }
}

/// Linux unix_dgram_peer_wake_me: true (stay unwritable, registered)
/// while `other`'s queue is full and it is alive; a dead receiver must
/// look writable so the next write reports ECONNREFUSED. The caller
/// holds our `st` with `other` as our peer.
fn peer_wake_me(s: &UnixSock, other: &UnixSock) -> bool {
    let connected = peer_wake_connect(s, other);
    if other.recvq_full() && !other.is_dead() {
        return true;
    }
    if connected {
        peer_wake_disconnect(s, other);
    }
    false
}

/// Linux unix_dgram_poll: also unwritable while the peer we are not
/// mutually connected with has a full queue
pub fn poll(s: &UnixSock) -> u16 {
    let shut = s.sk.shutdown();
    let mut mask = 0;
    if s.sk.has_err() {
        mask |= POLLERR;
    }
    if rcv_shut(s) {
        mask |= POLLRDHUP | POLLIN | POLLRDNORM;
    }
    if shut == SHUTDOWN_MASK {
        mask |= POLLHUP;
    }
    if !s.rq.is_empty() {
        mask |= POLLIN | POLLRDNORM;
    }
    if s.sk.stype == SOCK_SEQPACKET && s.state() == CLOSE {
        mask |= POLLHUP;
    }
    let mut writable = s.writable();
    if writable
        && let Some(other) = s.peer()
        && !is(&other.peer(), s)
        && other.recvq_full()
    {
        // Under our state lock, so `other` stays our peer while our
        // entry is linked on it (Linux unix_dgram_poll)
        let st = s.st.lock();
        if is(&st, &other) && peer_wake_me(s, &other) {
            writable = false;
        }
    }
    if writable {
        mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
    } else {
        // SIGIO once there is room (Linux unix_dgram_poll)
        s.sk.set_nospace();
    }
    mask
}
