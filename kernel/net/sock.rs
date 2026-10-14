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
//! `Sock` holds only atomics and its `WaitQueue` (IrqSpinlock leaf).
//! Wakeups (`data_ready`, `write_space`, `state_change`) are issued after
//! the caller dropped its protocol locks.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::error::KernelError;
use crate::net::NetNamespace;
use crate::task::Cred;
use crate::task::percpu::{MAX_SCHEDULE_TIMEOUT, ns_to_ticks};
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
}

/// Timeout "never" (MAX_SCHEDULE_TIMEOUT in ns)
pub const TIMEO_FOREVER: u64 = u64::MAX;

/// Common socket state
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
    /// SO_LINGER seconds (on/off is `sf::LINGER`)
    linger: AtomicU32,
    bound_dev_if: AtomicU32,
    pub priority: AtomicU32,
    pub mark: AtomicU32,
    /// Datagrams dropped on a full receive queue
    pub drops: AtomicU32,
    /// sockfs inode number (0 until the file exists)
    pub ino: AtomicU64,
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
            linger: AtomicU32::new(0),
            bound_dev_if: AtomicU32::new(0),
            priority: AtomicU32::new(0),
            mark: AtomicU32::new(0),
            drops: AtomicU32::new(0),
            ino: AtomicU64::new(0),
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
        s.linger.store(p.linger_secs(), Ordering::Relaxed);
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

    pub fn linger_secs(&self) -> u32 {
        self.linger.load(Ordering::Acquire)
    }

    pub fn set_linger(&self, on: bool, secs: u32) {
        self.linger.store(secs, Ordering::Release);
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

    /// Wait until `cond()` (Linux sk_wait_event + sock_intr_errno):
    /// `timeo` ns (0 = do not wait: EAGAIN; `TIMEO_FOREVER`). Returns
    /// the time left. A timeout is EAGAIN; a signal is ERESTARTSYS when
    /// waiting forever, EINTR with a socket timeout (never restarted,
    /// like Linux).
    pub fn wait<F: FnMut() -> bool>(&self, timeo: u64, mut cond: F) -> Result<u64, KernelError> {
        if cond() {
            return Ok(timeo);
        }
        if timeo == 0 {
            return Err(KernelError::WouldBlock);
        }
        let start = crate::time::monotonic_ns();
        let ticks = if timeo == TIMEO_FOREVER {
            MAX_SCHEDULE_TIMEOUT
        } else {
            ns_to_ticks(timeo).max(1)
        };
        match self.wq.wait_event_interruptible_timeout(&mut cond, ticks) {
            Ok(0) => Err(KernelError::WouldBlock),
            Ok(_) if timeo == TIMEO_FOREVER => Ok(timeo),
            Ok(_) => {
                let used = crate::time::monotonic_ns().saturating_sub(start);
                Ok(timeo.saturating_sub(used).max(1))
            }
            Err(_) if timeo == TIMEO_FOREVER => Err(KernelError::RestartSys),
            Err(_) => Err(KernelError::Interrupted),
        }
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
