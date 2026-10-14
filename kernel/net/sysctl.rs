//! Network sysctls (Linux net/ipv4/sysctl_net_ipv4.c,
//! net/core/sysctl_net_core.c subset)
//!
//! Values are per network namespace (`NetNamespace.sysctl`, plus
//! `port_range`), atomics only; /proc/sys/net files act on the
//! current task's namespace like Linux.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use crate::error::KernelError;
use crate::net::current_net_ns;
use crate::sysctl::{Ctl, range};

/// GID_T_MAX: largest gid in ping_group_range
const GID_MAX: i64 = 0x7fff_ffff;
/// ip_unprivileged_port_start
const PROT_SOCK: i64 = 1024;
/// MAX_TCP_SYNCNT
const MAX_SYNCNT: i64 = 127;

/// Per-namespace values
pub struct NetSysctl {
    /// ping_group_range as (high << 32) | low
    ping_group: AtomicU64,
    pub icmp_echo_ignore_all: AtomicU8,
    pub icmp_echo_ignore_bcast: AtomicU8,
    /// icmp_ratelimit in ms
    pub icmp_ratelimit: AtomicI32,
    pub icmp_ratemask: AtomicI32,
    pub icmp_msgs_per_sec: AtomicI32,
    pub icmp_msgs_burst: AtomicI32,
    pub tcp_syn_retries: AtomicU8,
    pub somaxconn: AtomicI32,
    pub frag_high: AtomicUsize,
    pub frag_low: AtomicUsize,
    /// ipfrag_time in seconds
    pub frag_time: AtomicI32,
}

impl Default for NetSysctl {
    fn default() -> Self {
        Self {
            // "1 0": nobody may create ping sockets
            ping_group: AtomicU64::new(1),
            icmp_echo_ignore_all: AtomicU8::new(0),
            icmp_echo_ignore_bcast: AtomicU8::new(1),
            icmp_ratelimit: AtomicI32::new(1000),
            icmp_ratemask: AtomicI32::new(0x1818),
            icmp_msgs_per_sec: AtomicI32::new(1000),
            icmp_msgs_burst: AtomicI32::new(50),
            tcp_syn_retries: AtomicU8::new(6),
            somaxconn: AtomicI32::new(4096),
            frag_high: AtomicUsize::new(4 * 1024 * 1024),
            frag_low: AtomicUsize::new(3 * 1024 * 1024),
            frag_time: AtomicI32::new(30),
        }
    }
}

impl NetSysctl {
    /// (low, high) of ping_group_range
    pub fn ping_group(&self) -> (u32, u32) {
        let v = self.ping_group.load(Ordering::Acquire);
        (v as u32, (v >> 32) as u32)
    }

    fn set_ping_group(&self, lo: u32, hi: u32) {
        self.ping_group
            .store(((hi as u64) << 32) | lo as u64, Ordering::Release);
    }

    pub fn icmp_echo_ignore_all(&self) -> bool {
        self.icmp_echo_ignore_all.load(Ordering::Relaxed) != 0
    }

    pub fn icmp_echo_ignore_bcast(&self) -> bool {
        self.icmp_echo_ignore_bcast.load(Ordering::Relaxed) != 0
    }

    pub fn somaxconn(&self) -> u32 {
        self.somaxconn.load(Ordering::Relaxed).max(0) as u32
    }
}

fn get_i32(f: fn(&NetSysctl) -> &AtomicI32) -> Vec<i64> {
    vec![f(&current_net_ns().sysctl).load(Ordering::Relaxed) as i64]
}

fn get_u8(f: fn(&NetSysctl) -> &AtomicU8) -> Vec<i64> {
    vec![f(&current_net_ns().sysctl).load(Ordering::Relaxed) as i64]
}

fn set_bool(f: fn(&NetSysctl) -> &AtomicU8, v: &[i64]) -> Result<(), KernelError> {
    range(v[0], 0, 1)?;
    f(&current_net_ns().sysctl).store(v[0] as u8, Ordering::Relaxed);
    Ok(())
}

fn set_int(
    f: fn(&NetSysctl) -> &AtomicI32,
    v: &[i64],
    lo: i64,
    hi: i64,
) -> Result<(), KernelError> {
    range(v[0], lo, hi)?;
    f(&current_net_ns().sysctl).store(v[0] as i32, Ordering::Relaxed);
    Ok(())
}

const INT_MAX: i64 = i32::MAX as i64;
const INT_MIN: i64 = i32::MIN as i64;

/// Linux ipv4_ping_group_range: an inverted range means "nobody" (1 0)
fn ping_group_store(v: &[i64]) -> Result<(), KernelError> {
    range(v[0], 0, GID_MAX)?;
    range(v[1], 0, GID_MAX)?;
    let (lo, hi) = if v[1] < v[0] {
        (1, 0)
    } else {
        (v[0] as u32, v[1] as u32)
    };
    current_net_ns().sysctl.set_ping_group(lo, hi);
    Ok(())
}

fn ping_group_show() -> Vec<i64> {
    let (lo, hi) = current_net_ns().sysctl.ping_group();
    vec![lo as i64, hi as i64]
}

/// Linux ipv4_local_port_range: 1..65535, low <= high, low above the
/// privileged ports
fn port_range_store(v: &[i64]) -> Result<(), KernelError> {
    range(v[0], 1, 65535)?;
    range(v[1], 1, 65535)?;
    if v[1] < v[0] || v[0] < PROT_SOCK {
        return Err(KernelError::InvalidArgument);
    }
    current_net_ns().port_range.set(v[0] as u16, v[1] as u16);
    Ok(())
}

fn port_range_show() -> Vec<i64> {
    let (lo, hi) = current_net_ns().port_range.get();
    vec![lo as i64, hi as i64]
}

fn frag_show(high: bool) -> Vec<i64> {
    let s = &current_net_ns().sysctl;
    let v = if high { &s.frag_high } else { &s.frag_low };
    vec![v.load(Ordering::Relaxed) as i64]
}

/// ipfrag_high_thresh >= ipfrag_low_thresh (Linux extra1/extra2 bounds)
fn frag_store(high: bool, v: &[i64]) -> Result<(), KernelError> {
    let s = &current_net_ns().sysctl;
    if high {
        range(v[0], s.frag_low.load(Ordering::Relaxed) as i64, i64::MAX)?;
        s.frag_high.store(v[0] as usize, Ordering::Relaxed);
    } else {
        range(v[0], 0, s.frag_high.load(Ordering::Relaxed) as i64)?;
        s.frag_low.store(v[0] as usize, Ordering::Relaxed);
    }
    Ok(())
}

fn ro(_: &[i64]) -> Result<(), KernelError> {
    Err(KernelError::PermissionDenied)
}

/// The /proc/sys/net files
pub static CTLS: &[Ctl] = &[
    Ctl {
        path: "net/ipv4/ping_group_range",
        mode: 0o644,
        show: ping_group_show,
        store: ping_group_store,
    },
    Ctl {
        path: "net/ipv4/ip_local_port_range",
        mode: 0o644,
        show: port_range_show,
        store: port_range_store,
    },
    Ctl {
        path: "net/ipv4/icmp_echo_ignore_all",
        mode: 0o644,
        show: || get_u8(|s| &s.icmp_echo_ignore_all),
        store: |v| set_bool(|s| &s.icmp_echo_ignore_all, v),
    },
    Ctl {
        path: "net/ipv4/icmp_echo_ignore_broadcasts",
        mode: 0o644,
        show: || get_u8(|s| &s.icmp_echo_ignore_bcast),
        store: |v| set_bool(|s| &s.icmp_echo_ignore_bcast, v),
    },
    Ctl {
        path: "net/ipv4/icmp_ratelimit",
        mode: 0o644,
        show: || get_i32(|s| &s.icmp_ratelimit),
        store: |v| set_int(|s| &s.icmp_ratelimit, v, 0, INT_MAX),
    },
    Ctl {
        path: "net/ipv4/icmp_ratemask",
        mode: 0o644,
        show: || get_i32(|s| &s.icmp_ratemask),
        store: |v| set_int(|s| &s.icmp_ratemask, v, INT_MIN, INT_MAX),
    },
    Ctl {
        path: "net/ipv4/icmp_msgs_per_sec",
        mode: 0o644,
        show: || get_i32(|s| &s.icmp_msgs_per_sec),
        store: |v| set_int(|s| &s.icmp_msgs_per_sec, v, 0, INT_MAX),
    },
    Ctl {
        path: "net/ipv4/icmp_msgs_burst",
        mode: 0o644,
        show: || get_i32(|s| &s.icmp_msgs_burst),
        store: |v| set_int(|s| &s.icmp_msgs_burst, v, 0, INT_MAX),
    },
    Ctl {
        path: "net/ipv4/tcp_syn_retries",
        mode: 0o644,
        show: || get_u8(|s| &s.tcp_syn_retries),
        store: |v| {
            range(v[0], 1, MAX_SYNCNT)?;
            current_net_ns()
                .sysctl
                .tcp_syn_retries
                .store(v[0] as u8, Ordering::Relaxed);
            Ok(())
        },
    },
    Ctl {
        path: "net/ipv4/ip_forward",
        mode: 0o444,
        show: || vec![0],
        store: ro,
    },
    Ctl {
        path: "net/ipv4/ipfrag_high_thresh",
        mode: 0o644,
        show: || frag_show(true),
        store: |v| frag_store(true, v),
    },
    Ctl {
        path: "net/ipv4/ipfrag_low_thresh",
        mode: 0o644,
        show: || frag_show(false),
        store: |v| frag_store(false, v),
    },
    Ctl {
        path: "net/ipv4/ipfrag_time",
        mode: 0o644,
        show: || get_i32(|s| &s.frag_time),
        store: |v| set_int(|s| &s.frag_time, v, 1, INT_MAX),
    },
    Ctl {
        path: "net/core/somaxconn",
        mode: 0o644,
        show: || get_i32(|s| &s.somaxconn),
        store: |v| set_int(|s| &s.somaxconn, v, 0, INT_MAX),
    },
];
