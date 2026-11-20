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
//!
//! MSG_OOB (Linux CONFIG_AF_UNIX_OOB) sends the last byte as its own
//! skb, the receiver's out-of-band byte: reads stop before it; MSG_OOB
//! takes it, unless SO_OOBINLINE leaves it in the stream; a read past
//! it without SO_OOBINLINE drops it. The owner gets SIGURG, poll
//! POLLPRI.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::io::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};
use crate::net::msg::{MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_WAITALL, RecvMsg, SendMsg};
use crate::net::sock::{RCV_SHUTDOWN, SEND_SHUTDOWN, SHUTDOWN_MASK, sf};
use crate::net::socket::{SOCK_SEQPACKET, SOCK_STREAM};
use crate::util::error::KernelError;

use super::scm::{Creds, FpList, Scm, too_many_fds};
use super::{
    CLOSE, ESTABLISHED, LISTEN, PeerCred, UnixSock, add_creds, find_other, peek_fds, queue,
    queue_oob, ucb, ucb_mut, unix_len, unix_skb, validate,
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
    // Its in-flight edges count as the listener's until accepted
    super::gc::set_listener(newsk, other);
    *newsk.peercred.lock() = Some(cred);
    // The server side passes credentials if the listener does
    let pass = other.sk.flag(sf::PASSCRED);
    newsk.sk.set_flag(sf::PASSCRED, pass);
    newsk
        .sk
        .set_flag(sf::PASSPIDFD, other.sk.flag(sf::PASSPIDFD));
    newsk.sk.set_flag(sf::PASSSEC, other.sk.flag(sf::PASSSEC));
    *newsk.addr.write() = other.addr();
    // Linux unix_stream_connect: path_get(&otheru->path), the copy
    // made before the embryo's lock (both are `UnixSock.path`, a leaf)
    let path = other.path.lock().clone();
    *newsk.path.lock() = path;
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
            super::gc::update_edges(&e);
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
/// waiting for sndbuf room; files ride on the first skb only. With
/// MSG_OOB the last byte goes alone as the out-of-band byte (queue_oob;
/// EOPNOTSUPP for an empty send). A partial write returns its count;
/// EPIPE (SIGPIPE from the socket layer) only when nothing was sent.
pub fn sendmsg(s: &UnixSock, m: &mut SendMsg<'_>, flags: i32) -> Result<usize, KernelError> {
    let mut scm = Scm::parse(&m.control)?;
    let oob = flags & MSG_OOB != 0;
    let mut len = m.data.len();
    if oob {
        if len == 0 {
            return Err(KernelError::OperationNotSupported);
        }
        len -= 1;
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
    let mut timeo = s.sk.snd_timeo(flags & MSG_DONTWAIT != 0);
    let mut sent = 0;
    while sent < len {
        let size = (len - sent).min(chunk_max(s));
        match send_skb(s, &other, m, sent, size, &mut scm, &mut timeo, false) {
            Ok(()) => sent += size,
            Err(e) if sent == 0 => return Err(e),
            Err(_) => return Ok(sent),
        }
    }
    if oob {
        match send_skb(s, &other, m, sent, 1, &mut scm, &mut timeo, true) {
            Ok(()) => sent += 1,
            Err(e) if sent == 0 => return Err(e),
            Err(_) => {}
        }
    }
    Ok(sent)
}

/// Queue `size` bytes at `off` as one skb, or as the out-of-band byte
/// (`urg`, Linux queue_oob: the receiver's owner gets SIGURG)
#[expect(clippy::too_many_arguments)]
fn send_skb(
    s: &UnixSock,
    other: &Arc<UnixSock>,
    m: &mut SendMsg<'_>,
    off: usize,
    size: usize,
    scm: &mut Scm,
    timeo: &mut u64,
    urg: bool,
) -> Result<(), KernelError> {
    s.wmem_wait(timeo)?;
    let data = m.data.take_at(off, size)?;
    let mut skb = unix_skb(&s.arc(), data)?;
    ucb_mut(&mut skb).creds = scm.creds.take();
    if let Some(f) = scm.fds.take() {
        if too_many_fds() {
            return Err(KernelError::TooManyRefs);
        }
        // Linux unix_attach_fds: unix_prepare_fpl
        let mut f = f;
        f.prepare()?;
        *ucb_mut(&mut skb).fp.get_mut() = Some(f);
    }
    add_creds(&mut skb, s, other);
    let skb = try_arc_gfp(skb, Gfp::KERNEL)?;
    let old = {
        let _ost = other.st.lock();
        if other.is_dead() || super::rcv_shut(other) {
            drop(_ost);
            drop(skb);
            return Err(KernelError::BrokenPipe);
        }
        if urg {
            let old = queue_oob(other, skb);
            // Under unix_state_lock, as Linux queue_oob
            other.sk.send_sigurg();
            old
        } else {
            queue(other, skb);
            None
        }
    };
    drop(old);
    other.sk.data_ready();
    Ok(())
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

/// Where the read loop goes next (Linux unix_stream_read_generic's
/// labels)
enum Next {
    /// Copy from this skb at `skip` (`unix_state_lock` released)
    Copy(Arc<SkBuff>),
    /// Done: return what was copied, else the error
    Out(Option<KernelError>),
    /// Nothing to read yet: wait for an skb after `last` (redo)
    Wait(Option<Arc<SkBuff>>),
}

/// Linux unix_stream_read_generic
pub fn recvmsg(s: &UnixSock, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
    if s.state() != ESTABLISHED {
        return Err(KernelError::InvalidArgument);
    }
    if flags & MSG_OOB != 0 {
        return recv_urg(s, m, flags);
    }
    let size = m.data.len();
    // Linux sock_rcvlowat: at least 1
    let lowat = s.sk.rcvlowat().max(0) as usize;
    let target = if flags & MSG_WAITALL != 0 {
        size
    } else {
        lowat.min(size)
    }
    .max(1);
    let mut timeo = s.sk.rcv_timeo(flags & MSG_DONTWAIT != 0);
    let mut g = Got::default();
    let err = loop {
        let last = match read_locked(s, m, flags, size, target, timeo, &mut g) {
            Ok(Some(last)) => last,
            Ok(None) => break None,
            Err(e) => break Some(e),
        };
        // Linux unix_stream_data_wait: until an skb is queued after
        // `last`, an error, receive shutdown or release
        match s.sk.wait_data(timeo, || {
            !super::tail_is(s, last.as_deref().map(core::ptr::from_ref))
                || s.sk.has_err()
                || super::rcv_shut(s)
                || s.is_dead()
        }) {
            Ok(t) => timeo = t,
            Err(KernelError::WouldBlock) => timeo = 0,
            Err(e) => {
                // A signal: the cookie is destroyed (Linux scm_destroy)
                drop(g.fds.take());
                return if g.copied > 0 { Ok(g.copied) } else { Err(e) };
            }
        }
    };
    let copied = g.copied;
    super::scm_recv(s, m, g.creds, g.fds);
    match err {
        Some(e) if copied == 0 => Err(e),
        _ => Ok(copied),
    }
}

/// One pass under `iolock` (Linux from `redo` to the end or the next
/// wait): `Ok(Some(last))` = wait for an skb after `last`, `Ok(None)` =
/// done, `Err` = error (returned unless data was copied)
fn read_locked(
    s: &UnixSock,
    m: &mut RecvMsg<'_>,
    flags: i32,
    size: usize,
    target: usize,
    timeo: u64,
    g: &mut Got,
) -> Result<Option<Option<Arc<SkBuff>>>, KernelError> {
    let _io = s.iolock.lock();
    let peek = flags & MSG_PEEK != 0;
    let mut skip = s.sk.peek_offset(flags).max(0) as usize;
    // An skb a peek continues with (Linux `goto again` from the tail)
    let mut resume: Option<Arc<SkBuff>> = None;
    loop {
        // Skbs `find` unlinked, freed after `st`
        let mut drops: Drops = [None, None];
        let st = s.st.lock();
        let first = match resume.take() {
            Some(r) => Some(r),
            None => {
                if s.is_dead() {
                    return Err(KernelError::ConnectionReset);
                }
                s.rq.peek()
            }
        };
        let skb = match find(
            s, first, &mut skip, flags, size, g.copied, target, &mut drops,
        ) {
            Next::Copy(skb) => skb,
            Next::Out(e) => return e.map_or(Ok(None), Err),
            Next::Wait(last) => {
                drop(st);
                if timeo == 0 {
                    return Err(KernelError::WouldBlock);
                }
                return Ok(Some(last));
            }
        };
        drop(st);
        let cb = ucb(&skb);
        if !may_join(s, cb.creds.as_ref(), &cb.wmem.from, m, g) {
            return Ok(None);
        }
        let off = cb.consumed.load(Ordering::Acquire) + skip;
        let chunk = (unix_len(&skb) - skip).min(size - g.copied);
        if let Err(e) = m.data.put(g.copied, &skb.data()[off..off + chunk]) {
            return if g.copied == 0 { Err(e) } else { Ok(None) };
        }
        g.copied += chunk;
        if !peek {
            if !consume(s, &skb, chunk, g) {
                return Ok(None);
            }
        } else {
            let fds = peek_fds(&skb);
            s.sk.peek_offset_fwd(chunk as i32);
            if fds.is_some() {
                g.fds = fds;
                return Ok(None);
            }
            skip = 0;
            let st = s.st.lock();
            resume = s.rq.peek_next(&skb);
            drop(st);
            if resume.is_none() {
                return Ok(None);
            }
        }
        if g.copied == size {
            return Ok(None);
        }
    }
}

/// Skbs unlinked under `unix_state_lock`, freed after it
type Drops = [Option<Arc<SkBuff>>; 2];

/// From `skb` (the head, or the skb a peek continues with) under
/// `unix_state_lock`: past the out-of-band byte (`manage_oob`), the skb
/// to copy from, past `skip` bytes, or what to do with none (Linux the
/// `again` label's tests)
#[expect(clippy::too_many_arguments)]
fn find(
    s: &UnixSock,
    mut skb: Option<Arc<SkBuff>>,
    skip: &mut usize,
    flags: i32,
    size: usize,
    copied: usize,
    target: usize,
    drops: &mut Drops,
) -> Next {
    let mut last = skb.clone();
    if let Some(cur) = skb {
        skb = manage_oob(s, cur, &mut last, flags, copied, drops);
        if skb.is_none() && (copied > 0 || size == 0) {
            return Next::Out(None);
        }
    }
    loop {
        let Some(cur) = skb else {
            if copied >= target {
                return Next::Out(None);
            }
            // POSIX 1003.1g order: error, then shutdown
            if let Some(e) = s.sk.take_err() {
                return Next::Out(Some(e));
            }
            if super::rcv_shut(s) {
                return Next::Out(None);
            }
            return Next::Wait(last);
        };
        if *skip < unix_len(&cur) {
            return Next::Copy(cur);
        }
        *skip -= unix_len(&cur);
        skb = s.rq.peek_next(&cur);
        last = Some(cur);
    }
}

/// Linux manage_oob, under `unix_state_lock`: a read stops before the
/// out-of-band skb once it copied anything; without SO_OOBINLINE that
/// skb is skipped by a peek and dropped by a read (the mark passed),
/// and a fully read skb at the head (a read out-of-band byte) is
/// stepped over or unlinked. Unlinked skbs go to `drops`.
fn manage_oob(
    s: &UnixSock,
    skb: Arc<SkBuff>,
    last: &mut Option<Arc<SkBuff>>,
    flags: i32,
    copied: usize,
    drops: &mut Drops,
) -> Option<Arc<SkBuff>> {
    if unix_len(&skb) != 0 && !s.is_oob(&skb) {
        return Some(skb);
    }
    let peek = flags & MSG_PEEK != 0;
    let inline = s.sk.flag(sf::OOBINLINE);
    let mut q = s.rq.lock();
    let mut oob = s.oob.lock();
    let is_oob =
        |x: &SkBuff, o: &Option<Arc<SkBuff>>| o.as_deref().is_some_and(|o| core::ptr::eq(o, x));
    let mut skb = skb;
    if unix_len(&skb) == 0 {
        let next = if copied > 0 && (oob.is_none() || is_oob(&skb, &oob)) {
            None
        } else if peek {
            let n = q.next(&skb);
            *last = Some(skb);
            n
        } else {
            let n = q.next(&skb);
            drops[0] = q.remove(&skb);
            *last = n.clone();
            n
        };
        skb = next?;
    }
    if !is_oob(&skb, &oob) {
        return Some(skb);
    }
    if copied > 0 {
        None
    } else if !peek {
        let o = oob.take();
        if inline {
            drops[1] = o;
            return Some(skb);
        }
        drops[1] = q.remove(&skb);
        drop(o);
        // The unread byte leaves the count (Linux v6.8 summed the queue)
        s.inq_len.fetch_sub(unix_len(&skb), Ordering::AcqRel);
        let head = q.front();
        *last = head.clone();
        head
    } else if !inline {
        let n = q.next(&skb);
        *last = Some(skb);
        n
    } else {
        Some(skb)
    }
}

/// Linux unix_stream_recv_urg: MSG_OOB reads (or peeks at) the
/// out-of-band byte; EINVAL with SO_OOBINLINE or none pending. A read
/// marks it consumed and unlinks the read skb before it, if any.
fn recv_urg(s: &UnixSock, m: &mut RecvMsg<'_>, flags: i32) -> Result<usize, KernelError> {
    let peek = flags & MSG_PEEK != 0;
    let io = s.iolock.lock();
    let (skb, read) = {
        let _st = s.st.lock();
        let q = s.rq.lock();
        let mut oob = s.oob.lock();
        if s.sk.flag(sf::OOBINLINE) {
            return Err(KernelError::InvalidArgument);
        }
        let Some(o) = oob.clone() else {
            return Err(KernelError::InvalidArgument);
        };
        let mut read = None;
        if !peek {
            let held = oob.take();
            s.inq_len.fetch_sub(1, Ordering::AcqRel);
            drop(oob);
            let mut q = q;
            if let Some(p) = q.prev(&o).filter(|p| unix_len(p) == 0) {
                read = q.remove(&p);
            }
            // The queue's reference remains: not the last
            drop(held);
        }
        (o, read)
    };
    let cb = ucb(&skb);
    let off = cb.consumed.load(Ordering::Acquire);
    let r = m.data.put(0, &skb.data()[off..off + 1]);
    if !peek {
        cb.consumed.fetch_add(1, Ordering::AcqRel);
    }
    drop(io);
    drop(read);
    drop(skb);
    r.map_err(|_| KernelError::BadAddress)?;
    m.flags |= MSG_OOB;
    Ok(1)
}

/// Mark `chunk` bytes of `skb` read (Linux, without MSG_PEEK): the
/// files go to the cookie; a fully read skb is unlinked and freed after
/// the queue lock. False: the read ends here.
fn consume(s: &UnixSock, skb: &Arc<SkBuff>, chunk: usize, g: &mut Got) -> bool {
    let cb = ucb(skb);
    cb.consumed.fetch_add(chunk, Ordering::AcqRel);
    s.sk.peek_offset_bwd(chunk as i32);
    // Linux scm_stat_del + unix_detach_fds
    let mut fds = cb.fp.lock().take();
    if let Some(f) = fds.as_mut() {
        f.detach();
    }
    if fds.is_some() {
        g.fds = fds;
    }
    let gone = {
        let mut q = s.rq.lock();
        s.inq_len.fetch_sub(chunk, Ordering::AcqRel);
        if unix_len(skb) != 0 {
            return false;
        }
        q.remove(skb)
    };
    drop(gone);
    g.fds.is_none()
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
    } else if s.may_passcred() {
        g.creds = creds.cloned();
        g.check_creds = true;
    }
    if m.want_name && !g.named {
        m.name = from.addr().map(|a| a.name.clone());
        g.named = true;
    }
    true
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
    if s.has_oob() {
        mask |= POLLPRI;
    }
    if s.state() == CLOSE {
        mask |= POLLHUP;
    }
    if s.writable() {
        mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
    }
    mask
}
