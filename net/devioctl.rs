//! Socket interface ioctls (Linux net/core/dev_ioctl.c,
//! net/ipv4/devinet.c devinet_ioctl, fib_frontend.c ip_rt_ioctl)
//!
//! Link commands (SIOCGIFCONF/INDEX/NAME/FLAGS/MTU/HWADDR and their SET
//! forms) work on any socket; address and route commands
//! (SIOC[GS]IFADDR/NETMASK/BRDADDR, SIOCADDRT/DELRT) need an AF_INET
//! socket. The namespace is the socket's. User memory only via uaccess.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::error::KernelError;
use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::inet::fib::{self, FibConfig, NLM_F_CREATE, RT_TABLE_MAIN, RTPROT_BOOT, RouteType};
use crate::net::inet::ifaddr::{
    self, IFNAMSIZ, InIfaddr, RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE,
    inet_make_mask, inet_mask_len,
};
use crate::net::ipv4::Ipv4Addr;
use crate::net::netlink::NlInfo;
use crate::net::rtnl;
use crate::uaccess::{copy_from_user, copy_to_user};

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::uaccess::Aarch64Uaccess as Uaccess;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::uaccess::X86_64Uaccess as Uaccess;

pub const SIOCADDRT: u32 = 0x890B;
pub const SIOCDELRT: u32 = 0x890C;
pub const SIOCGIFNAME: u32 = 0x8910;
pub const SIOCGIFCONF: u32 = 0x8912;
pub const SIOCGIFFLAGS: u32 = 0x8913;
pub const SIOCSIFFLAGS: u32 = 0x8914;
pub const SIOCGIFADDR: u32 = 0x8915;
pub const SIOCSIFADDR: u32 = 0x8916;
pub const SIOCGIFBRDADDR: u32 = 0x8919;
pub const SIOCSIFBRDADDR: u32 = 0x891A;
pub const SIOCGIFNETMASK: u32 = 0x891B;
pub const SIOCSIFNETMASK: u32 = 0x891C;
pub const SIOCGIFMTU: u32 = 0x8921;
pub const SIOCSIFMTU: u32 = 0x8922;
pub const SIOCGIFHWADDR: u32 = 0x8927;
pub const SIOCGIFINDEX: u32 = 0x8933;

/// sizeof(struct ifreq)
const IFREQ_LEN: usize = 40;
/// sizeof(struct rtentry) (64-bit)
const RTENTRY_LEN: usize = 120;
const AF_INET: u16 = 2;

// rtentry.rt_flags
const RTF_GATEWAY: u16 = 0x0002;
const RTF_HOST: u16 = 0x0004;
const RTF_REJECT: u16 = 0x0200;

/// struct ifreq: name + 24-byte union
struct Ifreq {
    raw: [u8; IFREQ_LEN],
}

impl Ifreq {
    fn read(arg: u64) -> Result<Self, KernelError> {
        let mut raw = [0u8; IFREQ_LEN];
        copy_from_user::<Uaccess>(&mut raw, arg, IFREQ_LEN).map_err(|_| KernelError::BadAddress)?;
        raw[IFNAMSIZ - 1] = 0;
        Ok(Self { raw })
    }

    fn write(&self, arg: u64) -> Result<i64, KernelError> {
        copy_to_user::<Uaccess>(arg, &self.raw).map_err(|_| KernelError::BadAddress)?;
        Ok(0)
    }

    /// ifr_name up to the NUL
    fn name(&self) -> &str {
        let n = self.raw[..IFNAMSIZ]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(IFNAMSIZ);
        core::str::from_utf8(&self.raw[..n]).unwrap_or("")
    }

    fn set_name(&mut self, s: &str) {
        self.raw[..IFNAMSIZ].fill(0);
        let n = s.len().min(IFNAMSIZ - 1);
        self.raw[..n].copy_from_slice(&s.as_bytes()[..n]);
    }

    fn i32(&self) -> i32 {
        i32::from_ne_bytes(self.raw[16..20].try_into().unwrap())
    }

    fn set_i32(&mut self, v: i32) {
        self.raw[16..20].copy_from_slice(&v.to_ne_bytes());
    }

    fn short(&self) -> u16 {
        u16::from_ne_bytes([self.raw[16], self.raw[17]])
    }

    fn set_short(&mut self, v: u16) {
        self.raw[16..18].copy_from_slice(&v.to_ne_bytes());
    }

    /// ifr_addr as (family, IPv4 address)
    fn sin(&self) -> (u16, Ipv4Addr) {
        let f = u16::from_ne_bytes([self.raw[16], self.raw[17]]);
        let a = Ipv4Addr::from_be_bytes(self.raw[20..24].try_into().unwrap());
        (f, a)
    }

    /// Store a sockaddr_in in the union
    fn set_sin(&mut self, a: Ipv4Addr) {
        self.raw[16..IFREQ_LEN].fill(0);
        self.raw[16..18].copy_from_slice(&AF_INET.to_ne_bytes());
        self.raw[20..24].copy_from_slice(&a.to_be_bytes());
    }
}

fn need_admin() -> Result<(), KernelError> {
    if crate::task::capable(crate::task::CAP_NET_ADMIN) {
        Ok(())
    } else {
        Err(KernelError::NotPermitted)
    }
}

fn dev_by_name(net: &NetNamespace, name: &str) -> Result<Arc<NetDevice>, KernelError> {
    net.get_device(name).ok_or(KernelError::NoDevice)
}

/// Socket ioctl entry: `inet` = AF_INET socket
pub fn ioctl(net: &NetNamespace, inet: bool, cmd: u32, arg: u64) -> Result<i64, KernelError> {
    match cmd {
        SIOCGIFCONF => ifconf(net, arg),
        SIOCGIFNAME | SIOCGIFINDEX | SIOCGIFFLAGS | SIOCSIFFLAGS | SIOCGIFMTU | SIOCSIFMTU
        | SIOCGIFHWADDR => {
            let mut ifr = Ifreq::read(arg)?;
            dev_ifreq(net, cmd, &mut ifr)?;
            ifr.write(arg)
        }
        SIOCGIFADDR | SIOCSIFADDR | SIOCGIFBRDADDR | SIOCSIFBRDADDR | SIOCGIFNETMASK
        | SIOCSIFNETMASK
            if inet =>
        {
            let mut ifr = Ifreq::read(arg)?;
            devinet(net, cmd, &mut ifr)?;
            ifr.write(arg)
        }
        SIOCADDRT | SIOCDELRT if inet => rt_ioctl(net, cmd, arg),
        _ => Err(KernelError::NotTty),
    }
}

/// Link ioctls (Linux dev_ifsioc_locked / dev_ifsioc)
fn dev_ifreq(net: &NetNamespace, cmd: u32, ifr: &mut Ifreq) -> Result<(), KernelError> {
    if cmd == SIOCGIFNAME {
        let dev = net
            .dev_get_by_index(ifr.i32() as u32)
            .ok_or(KernelError::NoDevice)?;
        ifr.set_name(dev.name());
        return Ok(());
    }
    if cmd == SIOCSIFFLAGS || cmd == SIOCSIFMTU {
        need_admin()?;
    }
    let dev = dev_by_name(net, ifr.name())?;
    match cmd {
        SIOCGIFINDEX => ifr.set_i32(dev.ifindex() as i32),
        SIOCGIFFLAGS => ifr.set_short(dev.get_flags() as u16),
        SIOCGIFMTU => ifr.set_i32(dev.mtu() as i32),
        SIOCGIFHWADDR => {
            ifr.raw[16..IFREQ_LEN].fill(0);
            ifr.raw[16..18].copy_from_slice(&dev.link().dev_type.to_ne_bytes());
            ifr.raw[18..24].copy_from_slice(&dev.mac());
        }
        SIOCSIFFLAGS => {
            let r = rtnl::lock();
            rtnl::dev_change_flags(&r, net, &dev, ifr.short() as u32, NlInfo::default())?;
        }
        SIOCSIFMTU => {
            let mtu = ifr.i32();
            if mtu < 0 {
                return Err(KernelError::InvalidArgument);
            }
            let r = rtnl::lock();
            rtnl::dev_set_mtu(&r, net, &dev, mtu as u32, NlInfo::default())?;
        }
        _ => return Err(KernelError::NotTty),
    }
    Ok(())
}

/// SIOCGIFCONF: one ifreq (label, sockaddr_in) per IPv4 address
fn ifconf(net: &NetNamespace, arg: u64) -> Result<i64, KernelError> {
    let mut hdr = [0u8; 16];
    copy_from_user::<Uaccess>(&mut hdr, arg, 16).map_err(|_| KernelError::BadAddress)?;
    let len = i32::from_ne_bytes(hdr[..4].try_into().unwrap());
    let buf = u64::from_ne_bytes(hdr[8..16].try_into().unwrap());
    let mut out: Vec<u8> = Vec::new();
    for dev in net.devices() {
        for ifa in dev.inet_addrs() {
            let mut r = Ifreq {
                raw: [0; IFREQ_LEN],
            };
            r.set_name(&ifa.label);
            r.set_sin(ifa.local);
            out.extend_from_slice(&r.raw);
        }
    }
    let total = if buf == 0 {
        out.len()
    } else {
        let room = (len.max(0) as usize / IFREQ_LEN) * IFREQ_LEN;
        let n = room.min(out.len());
        copy_to_user::<Uaccess>(buf, &out[..n]).map_err(|_| KernelError::BadAddress)?;
        n
    };
    copy_to_user::<Uaccess>(arg, &(total as i32).to_ne_bytes())
        .map_err(|_| KernelError::BadAddress)?;
    Ok(0)
}

/// Classful prefix length (Linux inet_abc_len); None for class D
fn abc_len(a: Ipv4Addr) -> Option<u8> {
    let top = a.0 >> 24;
    if top == 0 || a.is_broadcast() {
        Some(0)
    } else if top < 128 {
        Some(8)
    } else if top < 192 {
        Some(16)
    } else if top < 224 {
        Some(24)
    } else if top >= 240 {
        Some(32)
    } else {
        None
    }
}

/// Address ioctls (Linux devinet_ioctl): the address is found by label
/// (and, for AF_INET requests, address first, 4.4BSD style)
fn devinet(net: &NetNamespace, cmd: u32, ifr: &mut Ifreq) -> Result<(), KernelError> {
    let (family, sin) = ifr.sin();
    if matches!(cmd, SIOCSIFADDR | SIOCSIFBRDADDR | SIOCSIFNETMASK) {
        need_admin()?;
        if family != AF_INET {
            return Err(KernelError::InvalidArgument);
        }
    }
    let label = alloc::string::String::from(ifr.name());
    let r = rtnl::lock();
    let dev = dev_by_name(net, label.split(':').next().unwrap_or(""))?;
    let addrs = dev.inet_addrs();
    let found = addrs
        .iter()
        .find(|a| family == AF_INET && a.label == label && a.local == sin)
        .or_else(|| addrs.iter().find(|a| a.label == label))
        .cloned();
    let ctx = Ctx {
        r: &r,
        net,
        dev: &dev,
    };
    if cmd == SIOCSIFADDR {
        return ctx.set_addr(found, sin, &label);
    }
    let ifa = found.ok_or(KernelError::AddressNotAvailable)?;
    match cmd {
        SIOCGIFADDR => ifr.set_sin(ifa.local),
        SIOCGIFBRDADDR => ifr.set_sin(ifa.broadcast),
        SIOCGIFNETMASK => ifr.set_sin(ifa.mask()),
        SIOCSIFBRDADDR => ctx.set_brd(ifa, sin)?,
        SIOCSIFNETMASK => ctx.set_mask(ifa, sin)?,
        _ => return Err(KernelError::InvalidArgument),
    }
    Ok(())
}

/// A device being reconfigured under RTNL
struct Ctx<'a> {
    r: &'a rtnl::RtnlGuard,
    net: &'a NetNamespace,
    dev: &'a Arc<NetDevice>,
}

impl Ctx<'_> {
    fn del(&self, ifa: &InIfaddr) {
        ifaddr::inet_del_ifa(self.r, self.net, self.dev, ifa, NlInfo::default());
    }

    fn add(&self, ifa: InIfaddr) -> Result<(), KernelError> {
        ifaddr::inet_insert_ifa(self.r, self.net, self.dev, ifa, NlInfo::default())
    }

    fn bcast_ok(&self, plen: u8) -> bool {
        self.dev.admin_flags() & crate::net::device::flags::IFF_BROADCAST != 0 && plen < 31
    }

    /// SIOCSIFADDR: classful prefix and broadcast; 0.0.0.0 removes
    fn set_addr(
        &self,
        old: Option<InIfaddr>,
        sin: Ipv4Addr,
        label: &str,
    ) -> Result<(), KernelError> {
        let plen = abc_len(sin).ok_or(KernelError::InvalidArgument)?;
        let mut ifa = match old {
            Some(o) if o.local == sin => return Ok(()),
            Some(o) => {
                self.del(&o);
                InIfaddr {
                    broadcast: Ipv4Addr(0),
                    scope: RT_SCOPE_UNIVERSE,
                    ..o
                }
            }
            None => InIfaddr::new(sin, plen, label),
        };
        if sin.is_unspecified() {
            return Ok(());
        }
        ifa.local = sin;
        ifa.address = sin;
        ifa.prefixlen = plen;
        if self.bcast_ok(plen) {
            ifa.broadcast = Ipv4Addr(sin.0 | !inet_make_mask(plen).0);
        }
        if sin.is_loopback() {
            ifa.scope = RT_SCOPE_HOST;
        }
        self.add(ifa)
    }

    /// SIOCSIFBRDADDR
    fn set_brd(&self, ifa: InIfaddr, sin: Ipv4Addr) -> Result<(), KernelError> {
        if ifa.broadcast == sin {
            return Ok(());
        }
        self.del(&ifa);
        self.add(InIfaddr {
            broadcast: sin,
            ..ifa
        })
    }

    /// SIOCSIFNETMASK: a broadcast derived from the old mask follows
    fn set_mask(&self, ifa: InIfaddr, sin: Ipv4Addr) -> Result<(), KernelError> {
        let plen = bad_mask(sin, Ipv4Addr(0)).ok_or(KernelError::InvalidArgument)?;
        if ifa.mask() == sin {
            return Ok(());
        }
        let old_mask = ifa.mask();
        self.del(&ifa);
        let mut n = InIfaddr {
            prefixlen: plen,
            ..ifa
        };
        if self.bcast_ok(plen) && n.broadcast.0 == n.local.0 | !old_mask.0 {
            n.broadcast = Ipv4Addr(n.local.0 | !sin.0);
        }
        self.add(n)
    }
}

/// Prefix length of `mask` if contiguous and `addr` has no host bits
/// (Linux !bad_mask)
fn bad_mask(mask: Ipv4Addr, addr: Ipv4Addr) -> Option<u8> {
    if addr.0 & !mask.0 != 0 {
        return None;
    }
    inet_mask_len(mask)
}

/// SIOCADDRT / SIOCDELRT with struct rtentry (Linux ip_rt_ioctl)
fn rt_ioctl(net: &NetNamespace, cmd: u32, arg: u64) -> Result<i64, KernelError> {
    need_admin()?;
    let mut rt = [0u8; RTENTRY_LEN];
    copy_from_user::<Uaccess>(&mut rt, arg, RTENTRY_LEN).map_err(|_| KernelError::BadAddress)?;
    let r = rtnl::lock();
    let cfg = rtentry_cfg(net, cmd, &rt)?;
    if cmd == SIOCDELRT {
        fib::fib_table_delete(&r, net, &cfg)?;
    } else {
        fib::fib_table_insert(&r, net, &cfg)?;
    }
    Ok(0)
}

/// sockaddr at `off` in an rtentry: (family, IPv4 address)
fn rt_sa(rt: &[u8], off: usize) -> (u16, Ipv4Addr) {
    (
        u16::from_ne_bytes([rt[off], rt[off + 1]]),
        Ipv4Addr::from_be_bytes(rt[off + 4..off + 8].try_into().unwrap()),
    )
}

/// Linux rtentry_to_fib_config
fn rtentry_cfg(net: &NetNamespace, cmd: u32, rt: &[u8]) -> Result<FibConfig, KernelError> {
    let (dfam, dst) = rt_sa(rt, 8);
    let (gfam, gw) = rt_sa(rt, 24);
    let (mfam, mask) = rt_sa(rt, 40);
    let flags = u16::from_ne_bytes([rt[56], rt[57]]);
    let metric = i16::from_ne_bytes([rt[80], rt[81]]);
    let devp = u64::from_ne_bytes(rt[88..96].try_into().unwrap());
    if dfam != AF_INET {
        return Err(KernelError::AddressFamilyNotSupported);
    }
    let mut cfg = FibConfig {
        dst,
        dst_len: 32,
        ..Default::default()
    };
    if flags & RTF_HOST == 0 {
        if mfam != AF_INET && (!mask.is_unspecified() || mfam != 0) {
            return Err(KernelError::AddressFamilyNotSupported);
        }
        cfg.dst_len = bad_mask(mask, dst).ok_or(KernelError::InvalidArgument)?;
    }
    if cmd != SIOCDELRT {
        cfg.nlflags = NLM_F_CREATE;
        cfg.protocol = RTPROT_BOOT;
    }
    if metric > 0 {
        cfg.priority = metric as u32 - 1;
    }
    if flags & RTF_REJECT != 0 {
        cfg.scope = RT_SCOPE_HOST;
        cfg.rtype = RouteType::Unreachable as u8;
        return Ok(cfg);
    }
    cfg.scope = RT_SCOPE_NOWHERE;
    cfg.rtype = RouteType::Unicast as u8;
    if devp != 0 {
        let mut name = [0u8; IFNAMSIZ];
        copy_from_user::<Uaccess>(&mut name[..IFNAMSIZ - 1], devp, IFNAMSIZ - 1)
            .map_err(|_| KernelError::BadAddress)?;
        let n = name.iter().position(|&c| c == 0).unwrap_or(IFNAMSIZ);
        let label = core::str::from_utf8(&name[..n]).map_err(|_| KernelError::NoDevice)?;
        let devname = label.split(':').next().unwrap_or("");
        let dev = dev_by_name(net, devname)?;
        cfg.oif = dev.ifindex();
        if label.contains(':') {
            let ifa = dev
                .inet_addrs()
                .into_iter()
                .find(|a| a.label == label)
                .ok_or(KernelError::NoDevice)?;
            cfg.prefsrc = Some(ifa.local);
        }
    }
    if gfam == AF_INET && !gw.is_unspecified() {
        cfg.gateway = Some(gw);
        if flags & RTF_GATEWAY != 0 && net.fib.addr_type(gw) == RouteType::Unicast {
            cfg.scope = RT_SCOPE_UNIVERSE;
        }
    }
    cfg.table = RT_TABLE_MAIN;
    if cmd == SIOCDELRT {
        return Ok(cfg);
    }
    if flags & RTF_GATEWAY != 0 && cfg.gateway.is_none() {
        return Err(KernelError::InvalidArgument);
    }
    if cfg.scope == RT_SCOPE_NOWHERE {
        cfg.scope = RT_SCOPE_LINK;
    }
    Ok(cfg)
}
