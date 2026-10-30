//! Protocol-independent socket state (Linux struct sock subset,
//! net/core/sock.c)
//!
//! Every protocol socket embeds a `Sock`: identity, namespace, opener
//! credentials, the wait queue, pending error, shutdown state, buffer
//! sizes, timeouts and the SOL_SOCKET flags. `sk_wait` implements the
//! Linux blocking rules once for all protocols.
//!
//! ## Locking
//!
//! `Sock` holds atomics, its `WaitQueue` (IrqSpinlock leaf) and the
//! error queue `errq` (`crate::sync::spin::Mutex` leaf, thread only). Wakeups
//! (`data_ready`, `write_space`, `state_change`, `error_report`) are
//! issued after the caller dropped its protocol locks.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::sync::spin::Mutex;

use crate::error::KernelError;
use crate::net::NetNamespace;
use crate::task::Cred;
use crate::waitqueue::WaitQueue;

/// Linux rmem_default / wmem_default and rmem_max / wmem_max
pub const BUF_DEFAULT: u32 = 212_992;
pub const BUF_MAX: u32 = 212_992;
/// Linux SOCK_MIN_RCVBUF / SOCK_MIN_SNDBUF (2048 + sizeof(sk_buff), x2)
pub const MIN_RCVBUF: u32 = 2304;
pub const MIN_SNDBUF: u32 = 4608;

/// shutdown bits (Linux RCV_SHUTDOWN / SEND_SHUTDOWN)
pub const RCV_SHUTDOWN: u8 = 1;
pub const SEND_SHUTDOWN: u8 = 2;
pub const SHUTDOWN_MASK: u8 = 3;

/// SOL_SOCKET boolean options (bits of `Sock.flags`)
pub mod sf {
    pub const REUSEADDR: u32 = 1 << 0;
    pub const REUSEPORT: u32 = 1 << 1;
    pub const KEEPALIVE: u32 = 1 << 2;
    pub const BROADCAST: u32 = 1 << 3;
    pub const DONTROUTE: u32 = 1 << 4;
    pub const OOBINLINE: u32 = 1 << 5;
    pub const TIMESTAMP: u32 = 1 << 6;
    pub const TIMESTAMPNS: u32 = 1 << 7;
    pub const PASSCRED: u32 = 1 << 8;
    pub const RXQ_OVFL: u32 = 1 << 9;
    pub const DEBUG: u32 = 1 << 10;
    pub const NO_CHECK: u32 = 1 << 11;
    pub const PASSSEC: u32 = 1 << 12;
    pub const LINGER: u32 = 1 << 13;
    /// Listening (SO_ACCEPTCONN)
    pub const ACCEPTCONN: u32 = 1 << 14;
    /// SO_RCVBUF was set (Linux SOCK_RCVBUF_LOCK in sk_userlocks)
    pub const RCVBUF_LOCK: u32 = 1 << 15;
}

/// sock_extended_err origins (SO_EE_ORIGIN_*)
pub const EE_ORIGIN_LOCAL: u8 = 1;
pub const EE_ORIGIN_ICMP: u8 = 2;

/// An error-queue entry (Linux sock_exterr_skb): `struct
/// sock_extended_err` plus what recvmsg(MSG_ERRQUEUE) returns with it.
/// Addresses are kept as socket addresses, so IPv6 can reuse it.
#[derive(Clone, Debug, Default)]
pub struct ErrSkb {
    pub errno: u32,
    pub origin: u8,
    pub ty: u8,
    pub code: u8,
    pub info: u32,
    /// msg_name: the offending packet's destination (sockaddr)
    pub name: Vec<u8>,
    /// SO_EE_OFFENDER: who reported it (sockaddr; empty = none)
    pub offender: Vec<u8>,
    /// Data returned: the offending packet's payload as quoted
    pub payload: Vec<u8>,
    /// Receive metadata of the ICMP message (for IP_PKTINFO etc.)
    pub rx: Option<crate::net::af_inet::RxInfo>,
}

impl ErrSkb {
    /// Bytes charged to the receive buffer
    fn truesize(&self) -> usize {
        self.payload.len() + 256
    }
}

/// Timeout "never" (MAX_SCHEDULE_TIMEOUT in ns)
pub const TIMEO_FOREVER: u64 = u64::MAX;

/// Common socket state
/// SO_LINGER switch bit of `Sock.linger` (the time is the low 32 bits)
const LINGER_ON: u64 = 1 << 32;

pub struct Sock {
    pub family: u16,
    pub stype: i32,
    pub protocol: i32,
    /// Namespace (Linux sock_net)
    pub net: Arc<NetNamespace>,
    /// Credentials of the creator (the socket file's f_cred)
    pub cred: Cred,
    /// Readers, writers, connect/accept waiters and pollers
    pub wq: WaitQueue,
    /// Pending error (positive errno; SO_ERROR reads and clears)
    err: AtomicI32,
    shutdown: AtomicU8,
    rcvbuf: AtomicU32,
    sndbuf: AtomicU32,
    rcvlowat: AtomicI32,
    /// SO_RCVTIMEO / SO_SNDTIMEO in ns (`TIMEO_FOREVER` = none)
    rcvtimeo: AtomicU64,
    sndtimeo: AtomicU64,
    flags: AtomicU32,
    /// SO_LINGER as one word, `LINGER_ON | seconds`, so readers never
    /// see the switch and the time of different setsockopt calls
    /// (`sf::LINGER` mirrors the switch)
    linger: AtomicU64,
    bound_dev_if: AtomicU32,
    pub priority: AtomicU32,
    pub mark: AtomicU32,
    /// Datagrams dropped on a full receive queue
    pub drops: AtomicU32,
    /// sockfs inode number (0 until the file exists)
    pub ino: AtomicU64,
    /// Error queue (IP_RECVERR, MSG_ERRQUEUE) and its memory charge
    errq: Mutex<VecDeque<ErrSkb>>,
    errmem: AtomicUsize,
}

impl Sock {
    /// New socket state in `net`, created by the current task
    pub fn new(net: Arc<NetNamespace>, family: u16, stype: i32, protocol: i32) -> Self {
        Self {
            family,
            stype,
            protocol,
            net,
            cred: crate::task::current_cred(),
            wq: WaitQueue::new(),
            err: AtomicI32::new(0),
            shutdown: AtomicU8::new(0),
            rcvbuf: AtomicU32::new(BUF_DEFAULT),
            sndbuf: AtomicU32::new(BUF_DEFAULT),
            rcvlowat: AtomicI32::new(1),
            rcvtimeo: AtomicU64::new(TIMEO_FOREVER),
            sndtimeo: AtomicU64::new(TIMEO_FOREVER),
            flags: AtomicU32::new(0),
            linger: AtomicU64::new(0),
            bound_dev_if: AtomicU32::new(0),
            priority: AtomicU32::new(0),
            mark: AtomicU32::new(0),
            drops: AtomicU32::new(0),
            ino: AtomicU64::new(0),
            errq: Mutex::new(VecDeque::new()),
            errmem: AtomicUsize::new(0),
        }
    }

    /// A child (accept) inheriting the listener's options and owner
    /// (Linux sk_clone_lock: sk_uid comes from the listener, never from
    /// whatever task runs the receive path)
    pub fn clone_from(p: &Sock) -> Self {
        let mut s = Self::new(p.net.clone(), p.family, p.stype, p.protocol);
        s.cred = p.cred;
        s.rcvbuf.store(p.rcvbuf(), Ordering::Relaxed);
        s.sndbuf.store(p.sndbuf(), Ordering::Relaxed);
        s.rcvtimeo
            .store(p.rcvtimeo.load(Ordering::Relaxed), Ordering::Relaxed);
        s.sndtimeo
            .store(p.sndtimeo.load(Ordering::Relaxed), Ordering::Relaxed);
        let inherit = p.flags.load(Ordering::Relaxed) & !sf::ACCEPTCONN;
        s.flags.store(inherit, Ordering::Relaxed);
        s.linger
            .store(p.linger.load(Ordering::Relaxed), Ordering::Relaxed);
        s.bound_dev_if.store(p.bound_dev_if(), Ordering::Relaxed);
        s
    }

    // --- flags -----------------------------------------------------------

    pub fn flag(&self, f: u32) -> bool {
        self.flags.load(Ordering::Acquire) & f != 0
    }

    pub fn set_flag(&self, f: u32, on: bool) {
        if on {
            self.flags.fetch_or(f, Ordering::AcqRel);
        } else {
            self.flags.fetch_and(!f, Ordering::AcqRel);
        }
    }

    // --- errors ----------------------------------------------------------

    /// Record an asynchronous error and wake everyone (Linux
    /// sk_error_report)
    pub fn set_err(&self, e: KernelError) {
        self.err.store(e as i32, Ordering::Release);
        self.wq.wake_all();
    }

    pub fn has_err(&self) -> bool {
        self.err.load(Ordering::Acquire) != 0
    }

    /// Set the pending error without a wakeup (callers report later)
    pub fn store_err(&self, errno: u32) {
        self.err.store(errno as i32, Ordering::Release);
    }

    /// POLLERR condition (Linux datagram_poll): a pending error or a
    /// queued extended error
    pub fn err_pending(&self) -> bool {
        self.has_err() || !self.errq.lock().is_empty()
    }

    /// Queue an extended error (Linux sock_queue_err_skb): dropped when
    /// it would exceed the receive buffer
    pub fn queue_err(&self, e: ErrSkb) -> bool {
        let ts = e.truesize();
        if self.errmem.load(Ordering::Acquire) + ts >= self.rcvbuf() as usize {
            return false;
        }
        self.errmem.fetch_add(ts, Ordering::AcqRel);
        self.errq.lock().push_back(e);
        self.wq.wake_all();
        true
    }

    /// Take the oldest extended error (Linux sock_dequeue_err_skb): the
    /// pending error follows the next queued ICMP error, or is cleared
    /// when the taken one was an ICMP error and no other follows
    pub fn dequeue_err(&self) -> Option<ErrSkb> {
        let (e, next) = {
            let mut q = self.errq.lock();
            let e = q.pop_front()?;
            let next = q.front().map(|n| (n.origin, n.errno));
            (e, next)
        };
        self.errmem.fetch_sub(e.truesize(), Ordering::AcqRel);
        match next {
            Some((EE_ORIGIN_ICMP, errno)) => self.store_err(errno),
            _ if e.origin == EE_ORIGIN_ICMP => self.store_err(0),
            _ => {}
        }
        if next.is_some() {
            self.wq.wake_all();
        }
        Some(e)
    }

    /// Drop all queued extended errors (close)
    pub fn purge_err(&self) {
        self.errq.lock().clear();
        self.errmem.store(0, Ordering::Release);
    }

    /// Take the pending error (Linux sock_error)
    pub fn take_err(&self) -> Option<KernelError> {
        let e = self.err.swap(0, Ordering::AcqRel);
        if e == 0 {
            None
        } else {
            Some(KernelError::from_errno(e).unwrap_or(KernelError::Io))
        }
    }

    /// Pending error as a positive errno, cleared (SO_ERROR)
    pub fn take_errno(&self) -> i32 {
        self.err.swap(0, Ordering::AcqRel)
    }

    // --- shutdown --------------------------------------------------------

    pub fn shutdown(&self) -> u8 {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Reset after a disconnect (Linux tcp_disconnect)
    pub fn clear_shutdown(&self) {
        self.shutdown.store(0, Ordering::Release);
    }

    /// Set shutdown bits without a wakeup (callers holding a protocol
    /// lock wake after dropping it)
    pub fn or_shutdown(&self, how: u8) {
        self.shutdown.fetch_or(how, Ordering::AcqRel);
    }

    pub fn set_shutdown(&self, how: u8) {
        self.shutdown.fetch_or(how, Ordering::AcqRel);
        self.wq.wake_all();
    }

    // --- buffers -----------------------------------------------------------

    pub fn rcvbuf(&self) -> u32 {
        self.rcvbuf.load(Ordering::Acquire)
    }

    pub fn sndbuf(&self) -> u32 {
        self.sndbuf.load(Ordering::Acquire)
    }

    /// SO_RCVBUF: Linux doubles the request (for bookkeeping overhead),
    /// caps it at rmem_max unless `force`, floors it at SOCK_MIN_RCVBUF
    pub fn set_rcvbuf(&self, v: i32, force: bool) {
        self.rcvbuf
            .store(buf_size(v, force, MIN_RCVBUF), Ordering::Release);
        self.set_flag(sf::RCVBUF_LOCK, true);
        self.wq.wake_all();
    }

    pub fn set_sndbuf(&self, v: i32, force: bool) {
        self.sndbuf
            .store(buf_size(v, force, MIN_SNDBUF), Ordering::Release);
        self.wq.wake_all();
    }

    pub fn rcvlowat(&self) -> i32 {
        self.rcvlowat.load(Ordering::Acquire)
    }

    /// SO_RCVLOWAT: negative = INT_MAX, 0 = 1 (Linux sk_setsockopt)
    pub fn set_rcvlowat(&self, v: i32) {
        let v = if v < 0 { i32::MAX } else { v.max(1) };
        self.rcvlowat.store(v, Ordering::Release);
        self.wq.wake_all();
    }

    /// SO_LINGER: the time in seconds when switched on (one atomic
    /// snapshot of both)
    pub fn linger(&self) -> Option<u32> {
        let v = self.linger.load(Ordering::Acquire);
        (v & LINGER_ON != 0).then_some(v as u32)
    }

    /// SO_LINGER (l_onoff, l_linger) as (on, time)
    pub fn linger_opt(&self) -> (bool, u32) {
        let v = self.linger.load(Ordering::Acquire);
        (v & LINGER_ON != 0, v as u32)
    }

    pub fn set_linger(&self, on: bool, secs: u32) {
        let on_bit = if on { LINGER_ON } else { 0 };
        self.linger.store(on_bit | secs as u64, Ordering::Release);
        self.set_flag(sf::LINGER, on);
    }

    pub fn bound_dev_if(&self) -> u32 {
        self.bound_dev_if.load(Ordering::Acquire)
    }

    pub fn set_bound_dev_if(&self, i: u32) {
        self.bound_dev_if.store(i, Ordering::Release);
    }

    // --- timeouts --------------------------------------------------------

    pub fn rcvtimeo(&self) -> u64 {
        self.rcvtimeo.load(Ordering::Acquire)
    }

    pub fn sndtimeo(&self) -> u64 {
        self.sndtimeo.load(Ordering::Acquire)
    }

    pub fn set_timeo(&self, rcv: bool, ns: u64) {
        let t = if rcv { &self.rcvtimeo } else { &self.sndtimeo };
        t.store(ns, Ordering::Release);
    }

    /// Effective receive timeout of one call (Linux sock_rcvtimeo):
    /// 0 when non-blocking
    pub fn rcv_timeo(&self, nonblock: bool) -> u64 {
        if nonblock { 0 } else { self.rcvtimeo() }
    }

    pub fn snd_timeo(&self, nonblock: bool) -> u64 {
        if nonblock { 0 } else { self.sndtimeo() }
    }

    // --- wakeups (Linux sk_data_ready / sk_write_space / sk_state_change)

    pub fn data_ready(&self) {
        self.wq.wake_all();
    }

    pub fn write_space(&self) {
        self.wq.wake_all();
    }

    pub fn state_change(&self) {
        self.wq.wake_all();
    }

    /// Wait on this socket's queue until `cond()` (`wait_on`)
    #[track_caller]
    pub fn wait<F: FnMut() -> bool>(&self, timeo: u64, cond: F) -> Result<u64, KernelError> {
        crate::sync::might_sleep();
        wait_on(&self.wq, timeo, cond)
    }
}

/// Wait on `wq` until `cond()` (Linux sk_wait_event + sock_intr_errno):
/// `timeo` ns (0 = do not wait: EAGAIN; `TIMEO_FOREVER`). Returns the
/// time left. A timeout is EAGAIN; a signal is ERESTARTSYS when waiting
/// forever, EINTR with a socket timeout (never restarted, like Linux).
/// `wq` may belong to another socket (AF_UNIX waits for room in its
/// peer's queue); the caller keeps that socket alive.
pub fn wait_on<F: FnMut() -> bool>(
    wq: &WaitQueue,
    timeo: u64,
    mut cond: F,
) -> Result<u64, KernelError> {
    if cond() {
        return Ok(timeo);
    }
    if timeo == 0 {
        return Err(KernelError::WouldBlock);
    }
    if timeo == TIMEO_FOREVER {
        return match wq.wait_event_interruptible(&mut cond) {
            Ok(()) => Ok(timeo),
            Err(_) => Err(KernelError::RestartSys),
        };
    }
    let deadline = crate::time::monotonic_ns().saturating_add(timeo);
    let mono = crate::hrtimer::HrClock::Monotonic;
    match wq.wait_event_interruptible_deadline(&mut cond, Some(deadline), mono) {
        Ok(true) => Ok(deadline.saturating_sub(crate::time::monotonic_ns()).max(1)),
        Ok(false) => Err(KernelError::WouldBlock),
        Err(_) => Err(KernelError::Interrupted),
    }
}

/// Linux __sock_set_rcvbuf/sndbuf size rule
fn buf_size(v: i32, force: bool, min: u32) -> u32 {
    // Linux: min_t(u32, val, sysctl_*mem_max) treats negatives as huge
    let v = if force {
        v.max(0) as u32
    } else {
        (v as u32).min(BUF_MAX)
    };
    let v = v.min(i32::MAX as u32 / 2);
    (v * 2).max(min)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buf_sizes() {
        assert_eq!(buf_size(0, false, MIN_RCVBUF), MIN_RCVBUF);
        assert_eq!(buf_size(4096, false, MIN_RCVBUF), 8192);
        assert_eq!(buf_size(-1, false, MIN_RCVBUF), BUF_MAX * 2);
        assert_eq!(buf_size(i32::MAX, false, MIN_SNDBUF), BUF_MAX * 2);
        assert_eq!(buf_size(-5, true, MIN_RCVBUF), MIN_RCVBUF);
        assert_eq!(
            buf_size(i32::MAX, true, MIN_RCVBUF),
            (i32::MAX as u32 / 2) * 2
        );
    }
}
