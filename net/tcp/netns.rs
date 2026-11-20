//! A network namespace's TCP state the control blocks share (Linux
//! net->ipv4's TCP fields): the RFC 5961 challenge-ACK budget
//! (tcp_challenge_ack_limit, tcp_challenge_timestamp,
//! tcp_challenge_count). An `Arc` in the namespace and in each of its
//! control blocks, which reach it without the namespace at hand.
//!
//! Lock-free, as Linux (READ_ONCE/WRITE_ONCE, no lock): independent
//! words, Relaxed. Racing connections may each take the same unit of
//! the budget, as in Linux.

use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use crate::util::error::KernelError;

pub struct TcpNet {
    /// net.ipv4.tcp_challenge_ack_limit (INT_MAX: no budget)
    challenge_limit: AtomicI32,
    /// The second the budget is for, and what is left of it
    challenge_stamp: AtomicU32,
    challenge_count: AtomicU32,
}

impl Default for TcpNet {
    fn default() -> Self {
        Self {
            // Linux tcp_sk_init (6.0 on: no global budget by default)
            challenge_limit: AtomicI32::new(i32::MAX),
            challenge_stamp: AtomicU32::new(0),
            challenge_count: AtomicU32::new(0),
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
}

/// Linux get_random_u32_inclusive (its u32 span, wrapping)
fn random_inclusive(floor: u32, ceil: u32) -> u32 {
    let span = ceil.wrapping_sub(floor).wrapping_add(1);
    let r = crate::random::get_random_u32();
    floor.wrapping_add(if span == 0 { r } else { r % span })
}
