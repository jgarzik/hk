//! Network sysctls (Linux net/ipv4/sysctl_net_ipv4.c,
//! net/core/sysctl_net_core.c subset)
//!
//! Values are per network namespace (`NetNamespace.sysctl`, plus
//! `port_range`), atomics only. A namespace's files are `CTLS`, plus
//! `INIT_CTLS` in the initial one (Linux register_net_sysctl of
//! ipv4_net_table / netns_core_table per namespace, ipv4_table /
//! net_core_table for init_net only); a /proc/sys/net file acts on the
//! namespace it was looked up in (`sysctl::Entry`), whoever reads it.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use crate::net::NetNamespace;
use crate::sysctl::range;
use crate::util::error::KernelError;

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
    pub tcp_synack_retries: AtomicU8,
    /// SYN cookies: 0 never, 1 when the SYN queue is full, 2 always
    pub tcp_syncookies: AtomicU8,
    /// Without SYN cookies, the last quarter of this many requests is
    /// kept for proven peers (Linux sysctl_max_syn_backlog)
    pub tcp_max_syn_backlog: AtomicI32,
    /// Fast Open bits (Linux TFO_CLIENT_ENABLE 1, TFO_SERVER_ENABLE 2,
    /// TFO_SERVER_COOKIE_NOT_REQD 0x200, TFO_SERVER_WO_SOCKOPT1 0x400)
    pub tcp_fastopen: AtomicI32,
    /// Active Fast Open's first pause after a suspected blackhole, s
    /// (0: never paused; Linux sysctl_tcp_fastopen_blackhole_timeout)
    pub tcp_fastopen_blackhole_timeout: AtomicI32,
    pub tcp_retries2: AtomicU8,
    /// tcp_fin_timeout in seconds
    pub tcp_fin_timeout: AtomicI32,
    pub tcp_window_scaling: AtomicU8,
    /// 0 off, 1 on with a random offset per address pair, 2 no offset
    pub tcp_timestamps: AtomicU8,
    /// Nonzero: offer and accept SACK (RFC 2018)
    pub tcp_sack: AtomicU8,
    /// Nonzero: report duplicate segments in D-SACK blocks (RFC 2883)
    pub tcp_dsack: AtomicU8,
    /// Initial reordering degree of a connection (packets) and its bound
    pub tcp_reordering: AtomicI32,
    pub tcp_max_reordering: AtomicI32,
    /// RACK option bits (1 loss detection, 2 static reordering window,
    /// 4 no dupthresh)
    pub tcp_recovery: AtomicU8,
    /// Tail loss probes when 3 or 4
    pub tcp_early_retrans: AtomicU8,
    /// Nonzero: a TIME_WAIT entry ignores an in-window RST (RFC 1337)
    pub tcp_rfc1337: AtomicU8,
    /// tcp_rmem min / default / max (a connection's floor, initial
    /// SO_RCVBUF, autotuning's bound)
    pub tcp_rmem: [AtomicI32; 3],
    /// tcp_wmem min / default / max (a connection's floor, initial
    /// SO_SNDBUF, tcp_sndbuf_expand's bound)
    pub tcp_wmem: [AtomicI32; 3],
    /// tcp_app_win: 1/2^n of the window kept for the application
    pub tcp_app_win: AtomicU8,
    /// tcp_moderate_rcvbuf: receive buffer autotuning
    pub tcp_moderate_rcvbuf: AtomicU8,
    /// tcp_keepalive_time / _intvl in seconds
    pub tcp_keepalive_time: AtomicI32,
    pub tcp_keepalive_intvl: AtomicI32,
    pub tcp_keepalive_probes: AtomicU8,
    /// tcp_frto: F-RTO (RFC 5682) after a timeout when nonzero
    pub tcp_frto: AtomicU8,
    /// tcp_min_rtt_wlen: the windowed minimum RTT's window, s
    pub tcp_min_rtt_wlen: AtomicI32,
    /// tcp_slow_start_after_idle (RFC 2861 window validation)
    pub tcp_slow_start_after_idle: AtomicU8,
    /// tcp_orphan_retries: an orphan's retransmissions (0: 8 while its
    /// RTO is below the maximum)
    pub tcp_orphan_retries: AtomicU8,
    /// Default congestion control (index into tcp::cong::ALGOS)
    pub tcp_ca: AtomicU8,
    pub somaxconn: AtomicI32,
    pub frag_high: AtomicUsize,
    pub frag_low: AtomicUsize,
    /// ipfrag_time in seconds
    pub frag_time: AtomicI32,
    /// net.unix.max_dgram_qlen (queue limit of new AF_UNIX sockets)
    pub unix_max_dgram_qlen: AtomicI32,
    /// udp_rmem_min: bytes a UDP socket may queue past udp_mem[0]
    pub udp_rmem_min: AtomicI32,
    /// udp_wmem_min (Linux uses it for SK_MEM_SEND charges, which UDP
    /// never makes)
    pub udp_wmem_min: AtomicI32,
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
            tcp_synack_retries: AtomicU8::new(5),
            // Linux tcp_sk_init
            tcp_syncookies: AtomicU8::new(1),
            tcp_max_syn_backlog: AtomicI32::new(crate::net::tcp::table::max_syn_backlog()),
            // Linux tcp_sk_init: TFO_CLIENT_ENABLE
            tcp_fastopen: AtomicI32::new(1),
            // Linux tcp_sk_init (since 5.14)
            tcp_fastopen_blackhole_timeout: AtomicI32::new(0),
            tcp_retries2: AtomicU8::new(15),
            tcp_fin_timeout: AtomicI32::new(60),
            tcp_window_scaling: AtomicU8::new(1),
            tcp_timestamps: AtomicU8::new(1),
            tcp_sack: AtomicU8::new(1),
            tcp_dsack: AtomicU8::new(1),
            tcp_reordering: AtomicI32::new(3),
            tcp_max_reordering: AtomicI32::new(300),
            tcp_recovery: AtomicU8::new(1),
            tcp_early_retrans: AtomicU8::new(3),
            tcp_rfc1337: AtomicU8::new(0),
            tcp_rmem: [
                AtomicI32::new(4096),
                AtomicI32::new(131_072),
                AtomicI32::new(6_291_456),
            ],
            tcp_wmem: [
                AtomicI32::new(4096),
                AtomicI32::new(16_384),
                AtomicI32::new(4_194_304),
            ],
            tcp_app_win: AtomicU8::new(31),
            tcp_moderate_rcvbuf: AtomicU8::new(1),
            tcp_keepalive_time: AtomicI32::new(7200),
            tcp_keepalive_intvl: AtomicI32::new(75),
            tcp_keepalive_probes: AtomicU8::new(9),
            tcp_frto: AtomicU8::new(2),
            tcp_min_rtt_wlen: AtomicI32::new(300),
            tcp_slow_start_after_idle: AtomicU8::new(1),
            tcp_orphan_retries: AtomicU8::new(0),
            tcp_ca: AtomicU8::new(crate::net::tcp::cong::DEFAULT as u8),
            somaxconn: AtomicI32::new(4096),
            frag_high: AtomicUsize::new(4 * 1024 * 1024),
            frag_low: AtomicUsize::new(3 * 1024 * 1024),
            frag_time: AtomicI32::new(30),
            unix_max_dgram_qlen: AtomicI32::new(10),
            // Linux udp_sysctl_init: PAGE_SIZE
            udp_rmem_min: AtomicI32::new(4096),
            udp_wmem_min: AtomicI32::new(4096),
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
            .store((u64::from(hi) << 32) | u64::from(lo), Ordering::Release);
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

/// A namespace's sysctl registration (Linux the ctl_table_headers of
/// net->sysctls): shared by its /proc/sys/net inodes, which hold it,
/// not the namespace, and marked unregistering once the namespace's
/// teardown starts (Linux start_unregistering from the pernet exits in
/// cleanup_net)
#[derive(Default)]
pub struct SysctlSet {
    /// Linux header->unregistering: set once, by `cleanup_net`; read
    /// with no lock and no reference by revalidate and d_delete
    /// (proc_sys_revalidate, proc_sys_delete)
    unregistering: AtomicBool,
}

impl SysctlSet {
    /// The namespace is going: its sysctls are no longer found
    pub fn unregistering(&self) -> bool {
        self.unregistering.load(Ordering::Acquire)
    }

    /// Mark it going (Linux start_unregistering)
    pub fn start_unregistering(&self) {
        self.unregistering.store(true, Ordering::Release);
    }
}

/// One network sysctl, in every namespace or the initial one only
/// (Linux a ctl_table of net_sysctl_root, its data pointer moved into
/// each namespace's copy: here the namespace is an argument)
pub struct NetCtl {
    /// Path below /proc/sys ("net/ipv4/ip_local_port_range")
    pub path: &'static str,
    /// File mode bits (0644, 0444)
    pub mode: u16,
    /// Its data is global, not the namespace's (Linux an
    /// ipv4_net_table entry without a data pointer): read-only outside
    /// the initial namespace ([`NetCtl::mode_in`])
    pub global: bool,
    /// Current value in a namespace
    pub show: fn(&NetNamespace) -> Vec<i64>,
    /// Validate and store a value (as `sysctl::Ctl::store`)
    pub store: fn(&NetNamespace, &[i64]) -> Result<(), KernelError>,
    /// A string value instead (as `sysctl::Ctl::text`)
    pub text: Option<NetText>,
}

/// Show / store of a string network sysctl
pub struct NetText {
    pub show: fn(&NetNamespace) -> String,
    pub store: fn(&NetNamespace, &str) -> Result<(), KernelError>,
}

impl NetCtl {
    /// Its mode in `net` (Linux ipv4_net_table_dup: an entry without
    /// per-net data loses its write bits outside init_net)
    pub fn mode_in(&self, net: &NetNamespace) -> u16 {
        if self.global && !is_init(net) {
            self.mode & !0o222
        } else {
            self.mode
        }
    }
}

/// `net` is the initial namespace (Linux net_eq(net, &init_net))
fn is_init(net: &NetNamespace) -> bool {
    let init: &NetNamespace = &crate::net::INIT_NET_NS;
    core::ptr::eq(net, init)
}

/// The sysctls registered in `net` (Linux net->sysctls: the per-net
/// tables, and the init_net-only ones there)
pub fn registered(net: &NetNamespace) -> impl Iterator<Item = &'static NetCtl> + use<> {
    let init: &'static [NetCtl] = if is_init(net) { INIT_CTLS } else { &[] };
    CTLS.iter().chain(init)
}

/// Every network sysctl, whichever namespaces register it (what the
/// links of the root set's /proc/sys/net name: Linux insert_links)
pub fn all() -> impl Iterator<Item = &'static NetCtl> {
    CTLS.iter().chain(INIT_CTLS)
}

fn get_i32(n: &NetNamespace, f: fn(&NetSysctl) -> &AtomicI32) -> Vec<i64> {
    vec![i64::from(f(&n.sysctl).load(Ordering::Relaxed))]
}

fn get_u8(n: &NetNamespace, f: fn(&NetSysctl) -> &AtomicU8) -> Vec<i64> {
    vec![i64::from(f(&n.sysctl).load(Ordering::Relaxed))]
}

/// A u8 sysctl (Linux proc_dou8vec_minmax: 0..=255)
fn set_u8(n: &NetNamespace, f: fn(&NetSysctl) -> &AtomicU8, v: &[i64]) -> Result<(), KernelError> {
    range(v[0], 0, 255)?;
    f(&n.sysctl).store(v[0] as u8, Ordering::Relaxed);
    Ok(())
}

fn set_bool(
    n: &NetNamespace,
    f: fn(&NetSysctl) -> &AtomicU8,
    v: &[i64],
) -> Result<(), KernelError> {
    range(v[0], 0, 1)?;
    f(&n.sysctl).store(v[0] as u8, Ordering::Relaxed);
    Ok(())
}

fn set_int(
    n: &NetNamespace,
    f: fn(&NetSysctl) -> &AtomicI32,
    v: &[i64],
    lo: i64,
    hi: i64,
) -> Result<(), KernelError> {
    range(v[0], lo, hi)?;
    f(&n.sysctl).store(v[0] as i32, Ordering::Relaxed);
    Ok(())
}

const INT_MAX: i64 = i32::MAX as i64;
const INT_MIN: i64 = i32::MIN as i64;

/// Linux ipv4_ping_group_range: an inverted range means "nobody" (1 0)
fn ping_group_store(n: &NetNamespace, v: &[i64]) -> Result<(), KernelError> {
    range(v[0], 0, GID_MAX)?;
    range(v[1], 0, GID_MAX)?;
    let (lo, hi) = if v[1] < v[0] {
        (1, 0)
    } else {
        (v[0] as u32, v[1] as u32)
    };
    n.sysctl.set_ping_group(lo, hi);
    Ok(())
}

fn ping_group_show(n: &NetNamespace) -> Vec<i64> {
    let (lo, hi) = n.sysctl.ping_group();
    vec![i64::from(lo), i64::from(hi)]
}

/// Linux ipv4_local_port_range: 1..65535, low <= high, low above the
/// privileged ports
fn port_range_store(n: &NetNamespace, v: &[i64]) -> Result<(), KernelError> {
    range(v[0], 1, 65535)?;
    range(v[1], 1, 65535)?;
    if v[1] < v[0] || v[0] < PROT_SOCK {
        return Err(KernelError::InvalidArgument);
    }
    n.port_range.set(v[0] as u16, v[1] as u16);
    Ok(())
}

fn port_range_show(n: &NetNamespace) -> Vec<i64> {
    let (lo, hi) = n.port_range.get();
    vec![i64::from(lo), i64::from(hi)]
}

fn frag_show(n: &NetNamespace, high: bool) -> Vec<i64> {
    let s = &n.sysctl;
    let v = if high { &s.frag_high } else { &s.frag_low };
    vec![v.load(Ordering::Relaxed) as i64]
}

/// ipfrag_high_thresh >= ipfrag_low_thresh (Linux extra1/extra2 bounds)
fn frag_store(n: &NetNamespace, high: bool, v: &[i64]) -> Result<(), KernelError> {
    let s = &n.sysctl;
    if high {
        range(v[0], s.frag_low.load(Ordering::Relaxed) as i64, i64::MAX)?;
        s.frag_high.store(v[0] as usize, Ordering::Relaxed);
    } else {
        range(v[0], 0, s.frag_high.load(Ordering::Relaxed) as i64)?;
        s.frag_low.store(v[0] as usize, Ordering::Relaxed);
    }
    Ok(())
}

fn mem3_show(m: &[AtomicI32; 3]) -> Vec<i64> {
    m.iter()
        .map(|v| i64::from(v.load(Ordering::Relaxed)))
        .collect()
}

/// tcp_rmem / tcp_wmem: three integers, each at least 1 (Linux
/// proc_dointvec_minmax, extra1 SYSCTL_ONE)
fn mem3_store(m: &[AtomicI32; 3], v: &[i64]) -> Result<(), KernelError> {
    for &x in v {
        range(x, 1, INT_MAX)?;
    }
    for (a, &x) in m.iter().zip(v) {
        a.store(x as i32, Ordering::Relaxed);
    }
    Ok(())
}

fn ca_show(n: &NetNamespace) -> String {
    let i = n.sysctl.tcp_ca.load(Ordering::Relaxed) as usize;
    String::from(crate::net::tcp::cong::ALGOS[i].name())
}

/// tcp_congestion_control: a built-in algorithm (Linux
/// tcp_set_default_congestion_control: ENOENT when no module provides
/// it, EPERM for a restricted one outside the initial namespace)
fn ca_store(n: &NetNamespace, name: &str) -> Result<(), KernelError> {
    use crate::net::tcp::cong;
    let i = cong::find(name).ok_or(KernelError::NotFound)?;
    cong::set_default(is_init(n), i)?;
    n.sysctl.tcp_ca.store(i as u8, Ordering::Relaxed);
    Ok(())
}

fn ro_text(_: &NetNamespace, _: &str) -> Result<(), KernelError> {
    Err(KernelError::PermissionDenied)
}

fn no_ints(_: &NetNamespace) -> Vec<i64> {
    Vec::new()
}

fn ro(_: &NetNamespace, _: &[i64]) -> Result<(), KernelError> {
    Err(KernelError::PermissionDenied)
}

/// The /proc/sys/net files of every namespace (Linux ipv4_net_table,
/// netns_core_table, ip4_frags_ns_ctl_table, devinet's ip_forward,
/// unix_table)
pub static CTLS: &[NetCtl] = &[
    NetCtl {
        path: "net/ipv4/ping_group_range",
        mode: 0o644,
        global: false,
        show: ping_group_show,
        store: ping_group_store,
        text: None,
    },
    NetCtl {
        path: "net/ipv4/ip_local_port_range",
        mode: 0o644,
        global: false,
        show: port_range_show,
        store: port_range_store,
        text: None,
    },
    NetCtl {
        path: "net/ipv4/icmp_echo_ignore_all",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.icmp_echo_ignore_all),
        store: |n, v| set_bool(n, |s| &s.icmp_echo_ignore_all, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/icmp_echo_ignore_broadcasts",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.icmp_echo_ignore_bcast),
        store: |n, v| set_bool(n, |s| &s.icmp_echo_ignore_bcast, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/icmp_ratelimit",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.icmp_ratelimit),
        store: |n, v| set_int(n, |s| &s.icmp_ratelimit, v, 0, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/icmp_ratemask",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.icmp_ratemask),
        store: |n, v| set_int(n, |s| &s.icmp_ratemask, v, INT_MIN, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/icmp_msgs_per_sec",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.icmp_msgs_per_sec),
        store: |n, v| set_int(n, |s| &s.icmp_msgs_per_sec, v, 0, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/icmp_msgs_burst",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.icmp_msgs_burst),
        store: |n, v| set_int(n, |s| &s.icmp_msgs_burst, v, 0, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_syn_retries",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_syn_retries),
        store: |n, v| {
            range(v[0], 1, MAX_SYNCNT)?;
            n.sysctl
                .tcp_syn_retries
                .store(v[0] as u8, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_synack_retries",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_synack_retries),
        store: |n, v| set_u8(n, |s| &s.tcp_synack_retries, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_syncookies",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_syncookies),
        store: |n, v| set_u8(n, |s| &s.tcp_syncookies, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_max_syn_backlog",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.tcp_max_syn_backlog),
        store: |n, v| set_int(n, |s| &s.tcp_max_syn_backlog, v, INT_MIN, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_fastopen",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.tcp_fastopen),
        store: |n, v| set_int(n, |s| &s.tcp_fastopen, v, INT_MIN, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_fastopen_blackhole_timeout_sec",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.tcp_fastopen_blackhole_timeout),
        // Linux proc_tfo_blackhole_detect_timeout: a write restarts the
        // pauses
        store: |n, v| {
            set_int(n, |s| &s.tcp_fastopen_blackhole_timeout, v, 0, INT_MAX)?;
            n.tcp.tfo_disable_times.store(0, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_fastopen_key",
        mode: 0o600,
        global: false,
        show: no_ints,
        store: ro,
        text: Some(NetText {
            show: |n| crate::net::tcp::fastopen::key_show(n.tcp.fastopen_ctx().as_ref()),
            store: |n, s| {
                n.tcp
                    .fastopen_reset(crate::net::tcp::fastopen::key_store(s)?);
                Ok(())
            },
        }),
    },
    NetCtl {
        path: "net/ipv4/tcp_retries2",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_retries2),
        store: |n, v| set_u8(n, |s| &s.tcp_retries2, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_fin_timeout",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.tcp_fin_timeout),
        store: |n, v| set_int(n, |s| &s.tcp_fin_timeout, v, 1, INT_MAX / 1000),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_window_scaling",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_window_scaling),
        store: |n, v| set_u8(n, |s| &s.tcp_window_scaling, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_timestamps",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_timestamps),
        store: |n, v| set_u8(n, |s| &s.tcp_timestamps, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_sack",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_sack),
        store: |n, v| set_u8(n, |s| &s.tcp_sack, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_dsack",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_dsack),
        store: |n, v| set_u8(n, |s| &s.tcp_dsack, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_reordering",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.tcp_reordering),
        store: |n, v| {
            let max = n.sysctl.tcp_max_reordering.load(Ordering::Relaxed);
            set_int(n, |s| &s.tcp_reordering, v, 1, i64::from(max))
        },
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_max_reordering",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.tcp_max_reordering),
        store: |n, v| set_int(n, |s| &s.tcp_max_reordering, v, 1, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_recovery",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_recovery),
        store: |n, v| set_u8(n, |s| &s.tcp_recovery, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_early_retrans",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_early_retrans),
        store: |n, v| {
            range(v[0], 0, 4)?;
            n.sysctl
                .tcp_early_retrans
                .store(v[0] as u8, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_rfc1337",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_rfc1337),
        store: |n, v| set_u8(n, |s| &s.tcp_rfc1337, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_rmem",
        mode: 0o644,
        global: false,
        show: |n| mem3_show(&n.sysctl.tcp_rmem),
        store: |n, v| mem3_store(&n.sysctl.tcp_rmem, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_wmem",
        mode: 0o644,
        global: false,
        show: |n| mem3_show(&n.sysctl.tcp_wmem),
        store: |n, v| mem3_store(&n.sysctl.tcp_wmem, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_app_win",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_app_win),
        store: |n, v| {
            range(v[0], 0, 31)?;
            n.sysctl.tcp_app_win.store(v[0] as u8, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_max_tw_buckets",
        mode: 0o644,
        global: false,
        show: |n| vec![i64::from(n.tcp_net.max_tw_buckets())],
        store: |n, v| n.tcp_net.set_max_tw_buckets(v[0]),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_challenge_ack_limit",
        mode: 0o644,
        global: false,
        show: |n| vec![i64::from(n.tcp_net.challenge_limit())],
        store: |n, v| n.tcp_net.set_challenge_limit(v[0]),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_moderate_rcvbuf",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_moderate_rcvbuf),
        store: |n, v| set_u8(n, |s| &s.tcp_moderate_rcvbuf, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_keepalive_time",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.tcp_keepalive_time),
        store: |n, v| set_int(n, |s| &s.tcp_keepalive_time, v, 1, INT_MAX / 1000),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_keepalive_intvl",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.tcp_keepalive_intvl),
        store: |n, v| set_int(n, |s| &s.tcp_keepalive_intvl, v, 1, INT_MAX / 1000),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_keepalive_probes",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_keepalive_probes),
        store: |n, v| set_u8(n, |s| &s.tcp_keepalive_probes, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_frto",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_frto),
        store: |n, v| set_u8(n, |s| &s.tcp_frto, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_min_rtt_wlen",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.tcp_min_rtt_wlen),
        store: |n, v| set_int(n, |s| &s.tcp_min_rtt_wlen, v, 0, 86400),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_slow_start_after_idle",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_slow_start_after_idle),
        store: |n, v| set_u8(n, |s| &s.tcp_slow_start_after_idle, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_orphan_retries",
        mode: 0o644,
        global: false,
        show: |n| get_u8(n, |s| &s.tcp_orphan_retries),
        store: |n, v| set_u8(n, |s| &s.tcp_orphan_retries, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_congestion_control",
        mode: 0o644,
        global: false,
        show: no_ints,
        store: ro,
        text: Some(NetText {
            show: ca_show,
            store: ca_store,
        }),
    },
    NetCtl {
        path: "net/ipv4/tcp_available_congestion_control",
        mode: 0o444,
        global: true,
        show: no_ints,
        store: ro,
        text: Some(NetText {
            show: |_| crate::net::tcp::cong::names(),
            store: ro_text,
        }),
    },
    // Linux ipv4_net_table, its data global (tcp_cong_list's flags):
    // read-only outside init_net
    NetCtl {
        path: "net/ipv4/tcp_allowed_congestion_control",
        mode: 0o644,
        global: true,
        show: no_ints,
        store: ro,
        text: Some(NetText {
            show: |_| crate::net::tcp::cong::allowed_names(),
            store: |_, s| crate::net::tcp::cong::set_allowed(s),
        }),
    },
    // Linux ipv4_route_netns_table: a write bumps the namespace's route
    // cache generation (ipv4_sysctl_rtcache_flush)
    NetCtl {
        path: "net/ipv4/route/flush",
        mode: 0o200,
        global: false,
        show: no_ints,
        store: ro,
        text: Some(NetText {
            show: |_| String::new(),
            store: crate::net::inet::route::rtcache_flush,
        }),
    },
    NetCtl {
        path: "net/ipv4/udp_rmem_min",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.udp_rmem_min),
        store: |n, v| set_int(n, |s| &s.udp_rmem_min, v, 1, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/udp_wmem_min",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.udp_wmem_min),
        store: |n, v| set_int(n, |s| &s.udp_wmem_min, v, 1, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/ip_forward",
        mode: 0o444,
        global: false,
        show: |_| vec![0],
        store: ro,
        text: None,
    },
    NetCtl {
        path: "net/ipv4/ipfrag_high_thresh",
        mode: 0o644,
        global: false,
        show: |n| frag_show(n, true),
        store: |n, v| frag_store(n, true, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/ipfrag_low_thresh",
        mode: 0o644,
        global: false,
        show: |n| frag_show(n, false),
        store: |n, v| frag_store(n, false, v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/ipfrag_time",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.frag_time),
        store: |n, v| set_int(n, |s| &s.frag_time, v, 1, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/core/somaxconn",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.somaxconn),
        store: |n, v| set_int(n, |s| &s.somaxconn, v, 0, INT_MAX),
        text: None,
    },
    NetCtl {
        path: "net/unix/max_dgram_qlen",
        mode: 0o644,
        global: false,
        show: |n| get_i32(n, |s| &s.unix_max_dgram_qlen),
        store: |n, v| set_int(n, |s| &s.unix_max_dgram_qlen, v, INT_MIN, INT_MAX),
        text: None,
    },
];

/// The machine-wide network sysctls, registered for the initial
/// namespace only (Linux ipv4_table, net_core_table): absent elsewhere
pub static INIT_CTLS: &[NetCtl] = &[
    NetCtl {
        path: "net/ipv4/tcp_mem",
        mode: 0o644,
        global: false,
        show: |_| crate::net::tcp::mem::sysctl_show(),
        store: |_, v| crate::net::tcp::mem::sysctl_store(v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/tcp_max_orphans",
        mode: 0o644,
        global: false,
        show: |_| crate::net::tcp::mem::max_orphans_show(),
        store: |_, v| crate::net::tcp::mem::max_orphans_store(v),
        text: None,
    },
    NetCtl {
        path: "net/ipv4/udp_mem",
        mode: 0o644,
        global: false,
        show: |_| crate::net::udp::mem::sysctl_show(),
        store: |_, v| crate::net::udp::mem::sysctl_store(v),
        text: None,
    },
    NetCtl {
        path: "net/core/netdev_unregister_timeout_secs",
        mode: 0o644,
        global: false,
        show: |_| {
            let s = crate::net::rtnl::UNREGISTER_TIMEOUT_SECS.load(Ordering::Relaxed);
            vec![i64::from(s)]
        },
        store: |_, v| {
            range(v[0], 1, 3600)?;
            crate::net::rtnl::UNREGISTER_TIMEOUT_SECS.store(v[0] as u32, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
    NetCtl {
        path: "net/core/mem_pcpu_rsv",
        mode: 0o644,
        global: false,
        show: |_| crate::net::tcp::mem::rsv_show(),
        store: |_, v| crate::net::tcp::mem::rsv_store(v),
        text: None,
    },
];
