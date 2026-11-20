//! IPv4 per-device configuration (Linux net/ipv4/devinet.c:
//! ipv4_devconf, the devinet_sysctl table)
//!
//! Each namespace has an "all" and a "default" set (Linux
//! net->ipv4.devconf_all / devconf_dflt), and each device its own
//! (Linux in_dev->cnf), copied from the namespace's default as the
//! device registers (inetdev_init). A value written for a device is
//! marked in its state bits; a write to "default" reaches every device
//! whose value was never written (devinet_copy_dflt_conf). Readers
//! combine a device's value with "all" as Linux's IN_DEV_*CONF macros.
//! /proc/sys/net/ipv4/conf/{all,default,<dev>}/ are `CONF_DIR`.
//!
//! Values are read without a lock (Linux plain ints: READ_ONCE); a
//! write of "forwarding" holds RTNL while it walks the devices (Linux
//! devinet_sysctl_forward under rtnl_net_trylock), the others walk them
//! under RCU (devinet_copy_dflt_conf).

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering::Relaxed};

use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::sysctl::{DevCtl, DevDir, Target};
use crate::util::error::KernelError;

/// Attributes (Linux IPV4_DEVCONF_*, 1-based)
pub mod ci {
    pub const FORWARDING: usize = 1;
    pub const MC_FORWARDING: usize = 2;
    pub const PROXY_ARP: usize = 3;
    pub const ACCEPT_REDIRECTS: usize = 4;
    pub const SECURE_REDIRECTS: usize = 5;
    pub const SEND_REDIRECTS: usize = 6;
    pub const SHARED_MEDIA: usize = 7;
    pub const RP_FILTER: usize = 8;
    pub const ACCEPT_SOURCE_ROUTE: usize = 9;
    pub const BOOTP_RELAY: usize = 10;
    pub const LOG_MARTIANS: usize = 11;
    pub const TAG: usize = 12;
    pub const ARPFILTER: usize = 13;
    pub const MEDIUM_ID: usize = 14;
    pub const NOXFRM: usize = 15;
    pub const NOPOLICY: usize = 16;
    pub const FORCE_IGMP_VERSION: usize = 17;
    pub const ARP_ANNOUNCE: usize = 18;
    pub const ARP_IGNORE: usize = 19;
    pub const PROMOTE_SECONDARIES: usize = 20;
    pub const ARP_ACCEPT: usize = 21;
    pub const ARP_NOTIFY: usize = 22;
    pub const ACCEPT_LOCAL: usize = 23;
    pub const SRC_VMARK: usize = 24;
    pub const PROXY_ARP_PVLAN: usize = 25;
    pub const ROUTE_LOCALNET: usize = 26;
    pub const IGMPV2_UNSOLICITED_REPORT_INTERVAL: usize = 27;
    pub const IGMPV3_UNSOLICITED_REPORT_INTERVAL: usize = 28;
    pub const IGNORE_ROUTES_WITH_LINKDOWN: usize = 29;
    pub const DROP_UNICAST_IN_L2_MULTICAST: usize = 30;
    pub const DROP_GRATUITOUS_ARP: usize = 31;
    pub const BC_FORWARDING: usize = 32;
    pub const ARP_EVICT_NOCARRIER: usize = 33;
    /// Linux IPV4_DEVCONF_MAX
    pub const MAX: usize = 33;
}

/// A set of values (Linux struct ipv4_devconf: data[] and state)
pub struct DevConf {
    data: [AtomicI32; ci::MAX],
    /// Bit i-1: attribute i was written for this set (Linux state)
    state: AtomicU64,
}

/// (attribute, value) pairs of a compiled-in set; the rest are 0
type Init = &'static [(usize, i32)];

/// Linux ipv4_devconf ("all")
const ALL_INIT: Init = &[
    (ci::ACCEPT_REDIRECTS, 1),
    (ci::SEND_REDIRECTS, 1),
    (ci::SECURE_REDIRECTS, 1),
    (ci::SHARED_MEDIA, 1),
    (ci::IGMPV2_UNSOLICITED_REPORT_INTERVAL, 10_000),
    (ci::IGMPV3_UNSOLICITED_REPORT_INTERVAL, 1000),
    (ci::ARP_EVICT_NOCARRIER, 1),
];

/// Linux ipv4_devconf_dflt ("default"): source routes accepted too
const DFLT_INIT: Init = &[
    (ci::ACCEPT_REDIRECTS, 1),
    (ci::SEND_REDIRECTS, 1),
    (ci::SECURE_REDIRECTS, 1),
    (ci::SHARED_MEDIA, 1),
    (ci::ACCEPT_SOURCE_ROUTE, 1),
    (ci::IGMPV2_UNSOLICITED_REPORT_INTERVAL, 10_000),
    (ci::IGMPV3_UNSOLICITED_REPORT_INTERVAL, 1000),
    (ci::ARP_EVICT_NOCARRIER, 1),
];

impl DevConf {
    fn of(init: Init) -> Self {
        let c = Self {
            data: [const { AtomicI32::new(0) }; ci::MAX],
            state: AtomicU64::new(0),
        };
        for &(i, v) in init {
            c.data[i - 1].store(v, Relaxed);
        }
        c
    }

    /// Linux ipv4_devconf
    pub fn all() -> Self {
        Self::of(ALL_INIT)
    }

    /// Linux ipv4_devconf_dflt
    pub fn dflt() -> Self {
        Self::of(DFLT_INIT)
    }

    /// Attribute `i` (Linux IPV4_DEVCONF)
    pub fn get(&self, i: usize) -> i32 {
        self.data[i - 1].load(Relaxed)
    }

    fn put(&self, i: usize, v: i32) {
        self.data[i - 1].store(v, Relaxed);
    }

    fn is_set(&self, i: usize) -> bool {
        self.state.load(Relaxed) & (1 << (i - 1)) != 0
    }

    fn mark(&self, i: usize) {
        self.state.fetch_or(1 << (i - 1), Relaxed);
    }

    /// Set attribute `i` as written for this set (Linux
    /// ipv4_devconf_set, IN_DEV_CONF_SET)
    pub fn set(&self, i: usize, v: i32) {
        self.mark(i);
        self.put(i, v);
    }

    /// Every attribute as written: "default" reaches it no more (Linux
    /// ipv4_devconf_setall)
    pub fn setall(&self) {
        self.state.store((1 << ci::MAX) - 1, Relaxed);
    }

    /// Become a copy of `src`, state included (Linux inetdev_init's
    /// memcpy of devconf_dflt; devinet_init_net's copy of init_net's)
    pub fn copy_from(&self, src: &Self) {
        for (d, s) in self.data.iter().zip(&src.data) {
            d.store(s.load(Relaxed), Relaxed);
        }
        self.state.store(src.state.load(Relaxed), Relaxed);
    }
}

/// Linux IN_DEV_ORCONF: `cnf`'s value or "all"'s
pub fn orconf(net: &NetNamespace, cnf: &DevConf, i: usize) -> bool {
    net.devconf_all.get(i) != 0 || cnf.get(i) != 0
}

/// Linux IN_DEV_MAXCONF: the larger of `cnf`'s and "all"'s
pub fn maxconf(net: &NetNamespace, cnf: &DevConf, i: usize) -> i32 {
    net.devconf_all.get(i).max(cnf.get(i))
}

/// Linux IN_DEV_FORWARD: the device's own value
pub fn forward(dev: &NetDevice) -> bool {
    dev.in_dev().cnf.get(ci::FORWARDING) != 0
}

/// Linux IN_DEV_PROXY_ARP
pub fn proxy_arp(net: &NetNamespace, dev: &NetDevice) -> bool {
    orconf(net, &dev.in_dev().cnf, ci::PROXY_ARP)
}

/// The set a directory stands for
fn conf<'a>(net: &'a NetNamespace, t: &'a Target) -> &'a DevConf {
    match t {
        Target::All => &net.devconf_all,
        Target::Default => &net.devconf_dflt,
        Target::Dev(d) => &d.in_dev().cnf,
    }
}

/// A value written as Linux proc_dointvec reads it: any int
fn int(v: &[i64]) -> Result<i32, KernelError> {
    i32::try_from(v[0]).map_err(|_| KernelError::InvalidArgument)
}

/// A write of "default"'s attribute `i` reaches every device that never
/// had its own written (Linux devinet_copy_dflt_conf, under RCU)
fn copy_dflt(net: &NetNamespace, i: usize) {
    let g = crate::sync::rcu::read_lock();
    for dev in net.devices_rcu(&g) {
        let cnf = &dev.in_dev().cnf;
        if !cnf.is_set(i) {
            cnf.put(i, net.devconf_dflt.get(i));
        }
    }
}

/// Linux devinet_conf_proc for attribute `i`: the value, its state bit
/// and the copy to the devices for "default", except for the
/// attributes that bypass state tracking. Linux then flushes the route
/// cache for some (devinet_conf_post_set); hk keeps none.
fn conf_store(net: &NetNamespace, t: &Target, i: usize, v: &[i64]) -> Result<(), KernelError> {
    let val = int(v)?;
    let c = conf(net, t);
    c.put(i, val);
    match i {
        ci::NOXFRM | ci::NOPOLICY | ci::PROMOTE_SECONDARIES | ci::DROP_UNICAST_IN_L2_MULTICAST => {}
        _ => {
            c.mark(i);
            if matches!(t, Target::Default) {
                copy_dflt(net, i);
            }
        }
    }
    Ok(())
}

/// "all"'s forwarding changed (Linux inet_forward_change, RTNL held):
/// redirects are accepted only when not forwarding, and "default" and
/// every device follow
fn forward_change(net: &NetNamespace) {
    let on = net.devconf_all.get(ci::FORWARDING);
    net.devconf_all
        .put(ci::ACCEPT_REDIRECTS, i32::from(on == 0));
    net.devconf_dflt.put(ci::FORWARDING, on);
    for dev in net.devices() {
        dev.in_dev().cnf.set(ci::FORWARDING, on);
    }
}

/// Linux devinet_sysctl_forward: CAP_NET_ADMIN, then the value; a
/// change of "all"'s or a device's is made under RTNL, and "all"'s
/// carries to "default" and the devices
pub fn forward_store(net: &NetNamespace, t: &Target, v: &[i64]) -> Result<(), KernelError> {
    if !crate::task::capable(crate::task::CAP_NET_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    let val = int(v)?;
    let c = conf(net, t);
    if matches!(t, Target::Default) {
        c.put(ci::FORWARDING, val);
        return Ok(());
    }
    let rtnl = crate::net::rtnl::lock();
    let old = c.get(ci::FORWARDING);
    c.put(ci::FORWARDING, val);
    if old != val && matches!(t, Target::All) {
        forward_change(net);
    }
    drop(rtnl);
    Ok(())
}

fn show(net: &NetNamespace, t: &Target, i: usize) -> Vec<i64> {
    vec![i64::from(conf(net, t).get(i))]
}

/// "all" and "default" in every namespace
fn fixed(_: &NetNamespace) -> &'static [(&'static str, bool)] {
    &[("all", true), ("default", false)]
}

/// A read-write entry of attribute `$i` (Linux DEVINET_SYSCTL_RW_ENTRY)
macro_rules! rw {
    ($name:literal, $i:expr) => {
        DevCtl {
            name: $name,
            mode: 0o644,
            default_only: false,
            show: |n, t| show(n, t, $i),
            store: |n, t, v| conf_store(n, t, $i, v),
        }
    };
}

/// net/ipv4/conf/{all,default,<dev>} (Linux devinet_sysctl.devinet_vars)
pub static CONF_DIR: DevDir = DevDir {
    path: "net/ipv4/conf",
    fixed,
    ctls: &[
        DevCtl {
            name: "forwarding",
            mode: 0o644,
            default_only: false,
            show: |n, t| show(n, t, ci::FORWARDING),
            store: forward_store,
        },
        DevCtl {
            name: "mc_forwarding",
            mode: 0o444,
            default_only: false,
            show: |n, t| show(n, t, ci::MC_FORWARDING),
            store: |n, t, v| conf_store(n, t, ci::MC_FORWARDING, v),
        },
        rw!("bc_forwarding", ci::BC_FORWARDING),
        rw!("accept_redirects", ci::ACCEPT_REDIRECTS),
        rw!("secure_redirects", ci::SECURE_REDIRECTS),
        rw!("shared_media", ci::SHARED_MEDIA),
        rw!("rp_filter", ci::RP_FILTER),
        rw!("send_redirects", ci::SEND_REDIRECTS),
        rw!("accept_source_route", ci::ACCEPT_SOURCE_ROUTE),
        rw!("accept_local", ci::ACCEPT_LOCAL),
        rw!("src_valid_mark", ci::SRC_VMARK),
        rw!("proxy_arp", ci::PROXY_ARP),
        rw!("medium_id", ci::MEDIUM_ID),
        rw!("bootp_relay", ci::BOOTP_RELAY),
        rw!("log_martians", ci::LOG_MARTIANS),
        rw!("tag", ci::TAG),
        rw!("arp_filter", ci::ARPFILTER),
        rw!("arp_announce", ci::ARP_ANNOUNCE),
        rw!("arp_ignore", ci::ARP_IGNORE),
        rw!("arp_accept", ci::ARP_ACCEPT),
        rw!("arp_notify", ci::ARP_NOTIFY),
        rw!("arp_evict_nocarrier", ci::ARP_EVICT_NOCARRIER),
        rw!("proxy_arp_pvlan", ci::PROXY_ARP_PVLAN),
        rw!("force_igmp_version", ci::FORCE_IGMP_VERSION),
        rw!(
            "igmpv2_unsolicited_report_interval",
            ci::IGMPV2_UNSOLICITED_REPORT_INTERVAL
        ),
        rw!(
            "igmpv3_unsolicited_report_interval",
            ci::IGMPV3_UNSOLICITED_REPORT_INTERVAL
        ),
        rw!(
            "ignore_routes_with_linkdown",
            ci::IGNORE_ROUTES_WITH_LINKDOWN
        ),
        rw!("drop_gratuitous_arp", ci::DROP_GRATUITOUS_ARP),
        rw!("disable_xfrm", ci::NOXFRM),
        rw!("disable_policy", ci::NOPOLICY),
        rw!("promote_secondaries", ci::PROMOTE_SECONDARIES),
        rw!("route_localnet", ci::ROUTE_LOCALNET),
        rw!(
            "drop_unicast_in_l2_multicast",
            ci::DROP_UNICAST_IN_L2_MULTICAST
        ),
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_state() {
        let (a, d) = (DevConf::all(), DevConf::dflt());
        assert_eq!(a.get(ci::ACCEPT_SOURCE_ROUTE), 0);
        assert_eq!(d.get(ci::ACCEPT_SOURCE_ROUTE), 1);
        assert_eq!(a.get(ci::IGMPV2_UNSOLICITED_REPORT_INTERVAL), 10_000);
        let c = DevConf::all();
        c.copy_from(&d);
        assert!(!c.is_set(ci::RP_FILTER));
        c.set(ci::RP_FILTER, 2);
        assert!(c.is_set(ci::RP_FILTER));
        assert!(!c.is_set(ci::ARP_EVICT_NOCARRIER));
        c.set(ci::MAX, 0);
        assert!(c.is_set(ci::MAX));
        // A copy takes the state too (Linux inetdev_init's memcpy)
        let e = DevConf::all();
        e.copy_from(&c);
        assert!(e.is_set(ci::RP_FILTER) && e.get(ci::RP_FILTER) == 2);
    }
}
