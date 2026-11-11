//! AF_UNIX connection setup and SOCK_STREAM data (Linux af_unix.c
//! unix_listen, unix_stream_connect, unix_accept, unix_stream_sendmsg,
//! unix_stream_read_generic, unix_poll)
//!
//! connect() creates the server-side socket at once (an "embryo") and
//! queues it on the listener; the client is established immediately and
//! may write before accept(). A full backlog (more queued than the
//! listen backlog) blocks the connector or is EAGAIN.
//!
//! A stream is a queue of messages read as bytes. A read joins messages
//! but stops after one that carried files (so files arrive with the
//! bytes sent with them, and never with a later message's), and with
//! SO_PASSCRED never joins messages of different senders.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::io::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};
use crate::net::msg::{MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_WAITALL, RecvMsg, SendMsg};
use crate::net::sock::{RCV_SHUTDOWN, SEND_SHUTDOWN, SHUTDOWN_MASK, sf};
use crate::net::socket::{SOCK_SEQPACKET, SOCK_STREAM};
use crate::util::error::KernelError;

use super::scm::{Creds, FpList, Scm, too_many_fds};
use super::{
    CLOSE, ESTABLISHED, LISTEN, PeerCred, UnixSock, add_creds, find_other, peek_fds, queue, ucb,
    ucb_mut, unix_len, unix_skb, validate,
};
use crate::mm::page_alloc::Gfp;
use crate::net::skb::SkBuff;
use crate::util::kalloc::try_arc_gfp;

/// Largest message one stream write queues (Linux: half of sndbuf less
/// 64, at most SKB_MAX_HEAD(0) + 32 KiB of pages)
fn chunk_max(s: &UnixSock) -> usize {
    ((s.sk.sndbuf() as usize >> 1).saturating_sub(64)).clamp(1, 32768 + 3776)
}

/// Linux unix_listen (the backlog was clamped to somaxconn by
/// sys_listen in Linux; done here)
pub fn listen(s: &UnixSock, backlog: i32) -> Result<(), KernelError> {
    if s.sk.stype != SOCK_STREAM && s.sk.stype != SOCK_SEQPACKET {
        return Err(KernelError::OperationNotSupported);
    }
    if s.addr().is_none() {
        return Err(KernelError::InvalidArgument);
    }
    let max = s.sk.net.sysctl.somaxconn();
    let backlog = (backlog as u32).min(max);
    let cred = PeerCred::current();
    {
        let _st = s.st.lock();
        let state = s.state();
        if state != CLOSE && state != LISTEN {
            return Err(KernelError::InvalidArgument);
        }
        s.backlog
            .store(backlog, core::sync::atomic::Ordering::Release);
        s.set_state(LISTEN);
        // Credentials a connecting socket copies (SO_PEERCRED)
        *s.peercred.lock() = Some(cred);
    }
    s.sk.set_flag(sf::ACCEPTCONN, true);
    // A larger backlog may unblock connectors
    s.peer_wait.wake_all();
    Ok(())
}

/// Linux unix_stream_connect (also SOCK_SEQPACKET)
pub fn connect(s: &UnixSock, a: &[u8], nonblock: bool) -> Result<(), KernelError> {
    validate(a)?;
    s.passcred_autobind()?;
    let mut timeo = s.sk.snd_timeo(nonblock);
    let cred = PeerCred::current();
    let newsk = UnixSock::new(s.sk.net.clone(), s.sk.stype)?;
    let r = connect_to(s, a, &newsk, cred, &mut timeo);
    if r.is_err() {
        newsk.release_sock(false);
    }
    r
}

fn connect_to(
    s: &UnixSock,
    a: &[u8],
    newsk: &Arc<UnixSock>,
    cred: PeerCred,
    timeo: &mut u64,
) -> Result<(), KernelError> {
    loop {
        let other = find_other(&s.sk.net, a, s.sk.stype)?;
        match try_connect(s, &other, newsk, cred.clone()) {
            Err(KernelError::WouldBlock) => {
                if *timeo == 0 {
                    return Err(KernelError::WouldBlock);
                }
                // Linux unix_wait_for_peer
                match crate::net::sock::wait_on(&other.peer_wait, *timeo, || {
                    other.is_dead() || super::rcv_shut(&other) || !other.recvq_full()
                }) {
                    Ok(t) => *timeo = t,
                    Err(KernelError::WouldBlock) => *timeo = 0,
                    Err(e) => return Err(e),
                }
            }
            // The listener died after the lookup: look up again
            Err(KernelError::NoDevice) => {}
            r => return r,
        }
    }
}

/// One connect attempt under the listener's lock then ours (Linux
/// lock order): `WouldBlock` = backlog full, `NoDevice` = listener died
fn try_connect(
    s: &UnixSock,
    other: &Arc<UnixSock>,
    newsk: &Arc<UnixSock>,
    cred: PeerCred,
) -> Result<(), KernelError> {
    // The embryo's skb, made before any lock (Linux
    // unix_stream_connect allocates it first)
    let mut skb = unix_skb(newsk, alloc::vec::Vec::new())?;
    ucb_mut(&mut skb).embryo = Some(newsk.clone());
    let skb = try_arc_gfp(skb, Gfp::KERNEL)?;
    let ost = other.st.lock();
    if other.is_dead() {
        return Err(KernelError::NoDevice);
    }
    if other.state() != LISTEN || super::rcv_shut(other) {
        return Err(KernelError::ConnectionRefused);
    }
    if other.recvq_full() {
        return Err(KernelError::WouldBlock);
    }
    // Checked before taking our lock: a listener (connecting to itself,
    // or to a listener connecting back to it) never takes a second
    // state lock, so listener -> connector order cannot cycle
    own_state_ok(s)?;
    let mut st = s.st.lock();
    own_state_ok(s)?;
    let me = s.arc();
    {
        let mut nst = newsk.st.lock();
        *nst = Some(me.clone());
        newsk.set_state(ESTABLISHED);
    }
    *newsk.peercred.lock() = Some(cred);
    // The server side passes credentials if the listener does
    let pass = other.sk.flag(sf::PASSCRED);
    newsk.sk.set_flag(sf::PASSCRED, pass);
    newsk.sk.set_flag(sf::PASSSEC, other.sk.flag(sf::PASSSEC));
    *newsk.addr.write() = other.addr();
    let pc = other.peercred.lock().clone();
    *s.peercred.lock() = pc;
    s.set_state(ESTABLISHED);
    *st = Some(newsk.clone());
    drop(st);
    queue(other, skb);
    drop(ost);
    other.sk.data_ready();
    Ok(())
}

/// A connecting socket must be unconnected: EISCONN when established,
/// EINVAL otherwise (listening)
fn own_state_ok(s: &UnixSock) -> Result<(), KernelError> {
    match s.state() {
        CLOSE => Ok(()),
        ESTABLISHED => Err(KernelError::AlreadyConnected),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// Linux unix_accept: the next embryo becomes a connected socket
pub fn accept(s: &UnixSock, nonblock: bool) -> Result<Arc<UnixSock>, KernelError> {
    if s.sk.stype != SOCK_STREAM && s.sk.stype != SOCK_SEQPACKET {
        return Err(KernelError::OperationNotSupported);
    }
    if s.state() != LISTEN {
        return Err(KernelError::InvalidArgument);
    }
    let mut timeo = s.sk.rcv_timeo(nonblock);
    loop {
        if let Some(e) = s.sk.take_err() {
            return Err(e);
        }
        if let Some(skb) = s.rq.dequeue() {
            let e = ucb(&skb).embryo.clone();
            drop(skb);
            let e = e.ok_or(KernelError::InvalidArgument)?;
            // A connector may wait for backlog room
            s.peer_wait.wake_all();
            return Ok(e);
        }
        // Receive shutdown: EINVAL (skb_recv_datagram returns no error)
        if super::rcv_shut(s) {
            return Err(KernelError::InvalidArgument);
        }
        timeo = s.sk.wait(timeo, || {
            !s.rq.is_empty() || s.sk.has_err() || super::rcv_shut(s)
        })?;
    }
}

/// Linux unix_stream_sendmsg: chunks of at most `chunk_max` bytes, each
/// waiting for sndbuf room; files ride on the first chunk only. A
/// partial write returns its count; EPIPE (SIGPIPE from the socket
/// layer) only when nothing was sent.
pub fn sendmsg(s: &UnixSock, m: &mut SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
    let mut scm = Scm::parse(&m.control)?;
    if flags & MSG_OOB != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    if m.addr.is_some() {
        return Err(if s.state() == ESTABLISHED {
            KernelError::AlreadyConnected
        } else {
            KernelError::OperationNotSupported
        });
    }
    let other = s.peer().ok_or(KernelError::NotConnected)?;
    if s.sk.shutdown() & SEND_SHUTDOWN != 0 {
        return Err(KernelError::BrokenPipe);
    }
    let len = m.data.len();
    let mut timeo = s.sk.snd_timeo(flags & MSG_DONTWAIT != 0);
    let mut sent = 0;
    while sent < len {
        match send_chunk(s, &other, m, sent, &mut scm, &mut timeo) {
            Ok(n) => sent += n,
            Err(e) if sent == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(sent)
}

/// Queue the next chunk at `off`; returns its size
fn send_chunk(
    s: &UnixSock,
    other: &Arc<UnixSock>,
    m: &mut SendMsg<'_>,
    off: usize,
    scm: &mut Scm,
    timeo: &mut u64,
) -> Result<usize, KernelError> {
    let size = (m.data.len() - off).min(chunk_max(s));
    s.wmem_wait(timeo)?;
    let data = m.data.take_at(off, size)?;
    let mut skb = unix_skb(&s.arc(), data)?;
    ucb_mut(&mut skb).creds = scm.creds.take();
    if let Some(f) = scm.fds.take() {
        if too_many_fds() {
            return Err(KernelError::TooManyRefs);
        }
        *ucb_mut(&mut skb).fp.get_mut() = Some(f);
    }
    add_creds(&mut skb, s, other);
    let skb = try_arc_gfp(skb, Gfp::KERNEL)?;
    {
        let _ost = other.st.lock();
        if other.is_dead() || super::rcv_shut(other) {
            drop(_ost);
            drop(skb);
            return Err(KernelError::BrokenPipe);
        }
        queue(other, skb);
    }
    other.sk.data_ready();
    Ok(size)
}

/// What a read accumulated (Linux scm_cookie of the receive)
#[derive(Default)]
struct Got {
    copied: usize,
    creds: Option<Creds>,
    check_creds: bool,
    fds: Option<FpList>,
    named: bool,
}

/// Linux unix_stream_read_generic
pub fn recvmsg(s: &UnixSock, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
    if s.state() != ESTABLISHED {
        return Err(KernelError::InvalidArgument);
    }
    if flags & MSG_OOB != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    let size = m.data.len();
    let target = if flags & MSG_WAITALL != 0 {
        size
    } else {
        (s.sk.rcvlowat().max(0) as usize).min(size)
    };
    let mut timeo = s.sk.rcv_timeo(flags & MSG_DONTWAIT != 0);
    let mut g = Got::default();
    let mut last: Option<Arc<SkBuff>> = None;
    let err = loop {
        match read_some(s, m, flags, size, target, timeo, &mut g, &mut last) {
            Ok(Some(())) => {}
            Ok(None) => break None,
            Err(e) => break Some(e),
        }
        // Linux unix_stream_data_wait, with no lock held: a peek waits
        // for a message after the last one it copied
        match s.sk.wait_data(timeo, || {
            next_skb(s, last.as_deref()).is_some()
                || s.sk.has_err()
                || super::rcv_shut(s)
                || s.is_dead()
        }) {
            Ok(t) => timeo = t,
            Err(KernelError::WouldBlock) => timeo = 0,
            Err(e) => break Some(e),
        }
    };
    let copied = g.copied;
    super::scm_recv(s, m, g.creds, g.fds);
    match err {
        Some(e) if copied == 0 => Err(e),
        _ => Ok(copied),
    }
}

/// The message a read continues with: the head, or for a peek the one
/// after `last` (the last it copied; Linux skb_peek_next). A `last`
/// that left the queue (a purge) ends the peek.
fn next_skb(s: &UnixSock, last: Option<&SkBuff>) -> Option<Arc<SkBuff>> {
    match last {
        None => s.rq.peek(),
        Some(l) => s.rq.peek_next(l),
    }
}

/// One pass under `iolock`: `Ok(Some(()))` = wait for more data,
/// `Ok(None)` = done, `Err` = error (returned unless data was copied)
#[expect(clippy::too_many_arguments)]
fn read_some(
    s: &UnixSock,
    m: &mut RecvMsg<'_>,
    flags: i32,
    size: usize,
    target: usize,
    timeo: u64,
    g: &mut Got,
    last: &mut Option<Arc<SkBuff>>,
) -> Result<Option<()>, KernelError> {
    let _io = s.iolock.lock();
    let peek = flags & MSG_PEEK != 0;
    while g.copied < size || size == 0 {
        if s.is_dead() {
            return Err(KernelError::ConnectionReset);
        }
        let step = if peek {
            peek_one(s, m, size, g, last)?
        } else {
            read_one(s, m, size, g)?
        };
        match step {
            Step::Empty => {
                if g.copied >= target {
                    return Ok(None);
                }
                // Linux tests the end conditions with the queue empty
                // under unix_state_lock; here the peer may queue and
                // then shut down after the queue looked empty, so an
                // end counts only if nothing was queued ahead of it. The
                // ends are sampled once: one that lands after the queue
                // check is left for the next pass.
                let err = s.sk.has_err();
                let shut = super::rcv_shut(s);
                let cur = if peek { last.as_deref() } else { None };
                if (err || shut) && next_skb(s, cur).is_some() {
                    continue;
                }
                if err && let Some(e) = s.sk.take_err() {
                    return Err(e);
                }
                if shut {
                    return Ok(None);
                }
                if timeo == 0 {
                    return Err(KernelError::WouldBlock);
                }
                return Ok(Some(()));
            }
            Step::More => {}
            Step::Stop => return Ok(None),
        }
        if size == 0 {
            break;
        }
    }
    Ok(None)
}

enum Step {
    /// Nothing (more) queued
    Empty,
    /// Copied; continue with the next message
    More,
    /// Copied; this read ends here
    Stop,
}

/// Credentials rule: a passcred reader never joins senders (Linux
/// unix_skb_scm_eq); also copies the source address once
fn may_join(
    s: &UnixSock,
    creds: Option<&Creds>,
    from: &UnixSock,
    m: &mut RecvMsg<'_>,
    g: &mut Got,
) -> bool {
    if g.check_creds {
        if creds != g.creds.as_ref() {
            return false;
        }
    } else if s.passcred() {
        g.creds = creds.cloned();
        g.check_creds = true;
    }
    if m.want_name && !g.named {
        m.name = from.addr().map(|a| a.name.clone());
        g.named = true;
    }
    true
}

/// Consume from the head message (Linux unix_stream_read_generic
/// without MSG_PEEK): the head is referenced under the queue lock and
/// copied after it; `iolock` is held, so only we consume or unlink, and
/// a fully read message is unlinked and freed after the lock
fn read_one(
    s: &UnixSock,
    m: &mut RecvMsg<'_>,
    size: usize,
    g: &mut Got,
) -> Result<Step, KernelError> {
    let Some(skb) = s.rq.peek() else {
        return Ok(Step::Empty);
    };
    let cb = ucb(&skb);
    if !may_join(s, cb.creds.as_ref(), &cb.wmem.from, m, g) {
        return Ok(Step::Stop);
    }
    let from = cb.consumed.load(Ordering::Acquire);
    let chunk = unix_len(&skb).min(size - g.copied);
    if let Err(e) = m.data.put(g.copied, &skb.data()[from..from + chunk]) {
        return if g.copied == 0 {
            Err(e)
        } else {
            Ok(Step::Stop)
        };
    }
    g.copied += chunk;
    cb.consumed.fetch_add(chunk, Ordering::AcqRel);
    let fds = cb.fp.lock().take();
    let had_fds = fds.is_some();
    if fds.is_some() {
        g.fds = fds;
    }
    let done = unix_len(&skb) == 0;
    let gone = {
        let mut q = s.rq.lock();
        s.inq_len.fetch_sub(chunk, Ordering::AcqRel);
        if done { q.remove(&skb) } else { None }
    };
    drop(gone);
    if !done {
        return Ok(Step::Stop);
    }
    Ok(if had_fds { Step::Stop } else { Step::More })
}

/// MSG_PEEK: copy from the message after `last` without consuming;
/// files are duplicated (Linux unix_peek_fds) and end the read
fn peek_one(
    s: &UnixSock,
    m: &mut RecvMsg<'_>,
    size: usize,
    g: &mut Got,
    last: &mut Option<Arc<SkBuff>>,
) -> Result<Step, KernelError> {
    let Some(skb) = next_skb(s, last.as_deref()) else {
        return Ok(Step::Empty);
    };
    let cb = ucb(&skb);
    if !may_join(s, cb.creds.as_ref(), &cb.wmem.from, m, g) {
        return Ok(Step::Stop);
    }
    let from = cb.consumed.load(Ordering::Acquire);
    let chunk = unix_len(&skb).min(size - g.copied);
    if let Err(e) = m.data.put(g.copied, &skb.data()[from..from + chunk]) {
        return if g.copied == 0 {
            Err(e)
        } else {
            Ok(Step::Stop)
        };
    }
    g.copied += chunk;
    let fds = peek_fds(&skb);
    *last = Some(skb);
    if fds.is_some() {
        g.fds = fds;
        return Ok(Step::Stop);
    }
    Ok(Step::More)
}

/// Linux unix_poll (stream sockets): writable "when the other side has
/// shut down the connection" too, so writers see the error
pub fn poll(s: &UnixSock) -> u16 {
    let shut = s.sk.shutdown();
    let mut mask = 0;
    if s.sk.has_err() {
        mask |= POLLERR;
    }
    if shut == SHUTDOWN_MASK {
        mask |= POLLHUP;
    }
    if shut & RCV_SHUTDOWN != 0 {
        mask |= POLLRDHUP | POLLIN | POLLRDNORM;
    }
    if !s.rq.is_empty() {
        mask |= POLLIN | POLLRDNORM;
    }
    if s.state() == CLOSE {
        mask |= POLLHUP;
    }
    if s.writable() {
        mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
    }
    mask
}
