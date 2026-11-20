//! A network namespace's TCP state the control blocks share (Linux
//! net->ipv4's TCP fields): the RFC 5961 challenge-ACK budget
//! (tcp_challenge_ack_limit, tcp_challenge_timestamp,
//! tcp_challenge_count) and the TIME_WAIT entry count and limit
//! (tcp_death_row: tw_refcount, sysctl_max_tw_buckets). An `Arc` in
//! the namespace and in each of its control blocks, which reach it
//! without the namespace at hand.
//!
//! Lock-free, as Linux (READ_ONCE/WRITE_ONCE, no lock): independent
//! words, Relaxed. Racing connections may each take the same unit of
//! the budget, as in Linux.

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

use crate::util::error::KernelError;

pub struct TcpNet {
    /// net.ipv4.tcp_challenge_ack_limit (INT_MAX: no budget)
    challenge_limit: AtomicI32,
    /// The second the budget is for, and what is left of it
    challenge_stamp: AtomicU32,
    challenge_count: AtomicU32,
    /// TIME_WAIT entries scheduled and not yet killed (Linux
    /// tw_refcount - 1) and net.ipv4.tcp_max_tw_buckets
    tw_count: AtomicUsize,
    max_tw_buckets: AtomicI32,
}

/// tcp_max_tw_buckets of a new namespace: half the ehash entries
/// (Linux tcp_sk_init), set with the tables
static MAX_TW_DEFAULT: AtomicI32 = AtomicI32::new(512);

/// Linux tcp_sk_init's tcp_max_tw_buckets: half the ehash entries
/// (the initial namespace, made before the tables, takes it too)
pub fn set_max_tw_default(ehash: usize) {
    let v = (ehash / 2).min(i32::MAX as usize) as i32;
    MAX_TW_DEFAULT.store(v, Ordering::Relaxed);
    crate::net::INIT_NET_NS
        .tcp_net
        .max_tw_buckets
        .store(v, Ordering::Relaxed);
}

impl Default for TcpNet {
    fn default() -> Self {
        Self {
            // Linux tcp_sk_init (6.0 on: no global budget by default)
            challenge_limit: AtomicI32::new(i32::MAX),
            challenge_stamp: AtomicU32::new(0),
            challenge_count: AtomicU32::new(0),
            tw_count: AtomicUsize::new(0),
            max_tw_buckets: AtomicI32::new(MAX_TW_DEFAULT.load(Ordering::Relaxed)),
        }
    }
}

impl TcpNet {
    /// The host-wide half of Linux tcp_send_challenge_ack at `now`
    /// (ms): unlimited at INT_MAX; else each second draws a budget
    /// uniformly from [limit/2, limit*3/2) and each challenge ACK
    /// takes one. Unsigned and wrapping as Linux's u32 arithmetic.
    pub fn challenge_ok(&self, now: u64) -> bool {
        let limit = self.challenge_limit.load(Ordering::Relaxed);
        if limit == i32::MAX {
            return true;
        }
        let limit = limit as u32;
        let sec = (now / 1000) as u32;
        if sec != self.challenge_stamp.load(Ordering::Relaxed) {
            let half = limit.wrapping_add(1) >> 1;
            self.challenge_stamp.store(sec, Ordering::Relaxed);
            let count = random_inclusive(half, limit.wrapping_add(half).wrapping_sub(1));
            self.challenge_count.store(count, Ordering::Relaxed);
        }
        let count = self.challenge_count.load(Ordering::Relaxed);
        if count == 0 {
            return false;
        }
        self.challenge_count.store(count - 1, Ordering::Relaxed);
        true
    }

    pub fn challenge_limit(&self) -> i32 {
        self.challenge_limit.load(Ordering::Relaxed)
    }

    /// tcp_challenge_ack_limit write (Linux proc_dointvec: any int)
    pub fn set_challenge_limit(&self, v: i64) -> Result<(), KernelError> {
        crate::sysctl::range(v, i64::from(i32::MIN), i64::from(i32::MAX))?;
        self.challenge_limit.store(v as i32, Ordering::Relaxed);
        Ok(())
    }

    /// Linux inet_twsk_alloc's refusal: as many TIME_WAIT entries as
    /// tcp_max_tw_buckets (compared unsigned, as Linux: a negative
    /// limit is none)
    pub fn tw_full(&self) -> bool {
        let n = self.tw_count.load(Ordering::Relaxed) as u32;
        n >= self.max_tw_buckets.load(Ordering::Relaxed) as u32
    }

    /// A TIME_WAIT entry was scheduled (Linux __inet_twsk_schedule's
    /// refcount_inc) or killed (inet_twsk_kill's refcount_dec)
    pub fn tw_add(&self) {
        self.tw_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn tw_sub(&self) {
        self.tw_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn max_tw_buckets(&self) -> i32 {
        self.max_tw_buckets.load(Ordering::Relaxed)
    }

    /// tcp_max_tw_buckets write (Linux proc_dointvec: any int)
    pub fn set_max_tw_buckets(&self, v: i64) -> Result<(), KernelError> {
        crate::sysctl::range(v, i64::from(i32::MIN), i64::from(i32::MAX))?;
        self.max_tw_buckets.store(v as i32, Ordering::Relaxed);
        Ok(())
    }
}

/// Linux get_random_u32_inclusive (its u32 span, wrapping)
fn random_inclusive(floor: u32, ceil: u32) -> u32 {
    let span = ceil.wrapping_sub(floor).wrapping_add(1);
    let r = crate::random::get_random_u32();
    floor.wrapping_add(if span == 0 { r } else { r % span })
}
