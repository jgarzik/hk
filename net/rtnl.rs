//! RTNL: the network configuration lock and link changes (Linux
//! rtnl_mutex, dev_change_flags, dev_set_mtu)
//!
//! Every configuration change (link up/down and MTU, interface addresses,
//! routes) runs under RTNL, from netlink requests, SIOCS* ioctls or
//! kernel-internal configuration. Functions that require it take an
//! `&RtnlGuard`, so the requirement is checked at compile time.
//!
//! ## Locking
//!
//! `RTNL`: a sleeping `sync::Mutex<()>` (Linux rtnl_mutex), thread
//! context only, never taken from the receive path (softnet) or IRQ
//! context, and never while any spinlock is held. It is the OUTERMOST
//! network lock: RTNL -> device address lists -> FIB tables -> ARP ->
//! netlink socket queues. Holders may sleep (user copies such as the
//! SIOCADDRT device name, driver open/stop waiting for NAPI) but never
//! take a socket lock (`sk_lock`) and never wait for packets. Read-only
//! users (dumps, route lookups, /proc) do not take it.

use alloc::sync::Arc;

use crate::sync::{Mutex, MutexGuard};

use crate::net::NetNamespace;
use crate::net::device::{NetDevice, flags};
use crate::net::inet::ifaddr;
use crate::net::netlink::{NlInfo, rtnetlink};
use crate::util::error::KernelError;

static RTNL: Mutex<()> = Mutex::new(());

/// Proof that RTNL is held
pub struct RtnlGuard(
    #[expect(dead_code, reason = "held only for its Drop, which releases RTNL")]
    MutexGuard<'static, ()>,
);

/// Take RTNL (Linux rtnl_lock)
pub fn lock() -> RtnlGuard {
    RtnlGuard(RTNL.lock())
}

/// Change a device's flags (Linux dev_change_flags): IFF_UP opens or
/// closes it, the changeable flags are stored, everything else is
/// ignored. Announces RTM_NEWLINK when something changed.
pub fn dev_change_flags(
    rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &Arc<NetDevice>,
    new: u32,
    nl: NlInfo,
) -> Result<(), KernelError> {
    let old = dev.admin_flags();
    dev.set_flags(new);
    let want_up = new & flags::IFF_UP != 0;
    if want_up && !dev.is_up() {
        dev.open()?;
        ifaddr::inetdev_up(rtnl, net, dev);
    } else if !want_up && dev.is_up() {
        close(rtnl, net, dev);
    }
    if dev.admin_flags() != old {
        rtnetlink::notify_link(net, dev, nl);
    }
    Ok(())
}

/// Linux __dev_close + NETDEV_DOWN: the driver stops, the device's
/// routes and ARP entries go, packet sockets on it get ENETDOWN
fn close(rtnl: &RtnlGuard, net: &NetNamespace, dev: &Arc<NetDevice>) {
    dev.close();
    ifaddr::inetdev_down(rtnl, net, dev);
    crate::net::packet::netdev_down(net, dev);
}

/// Close an open device and announce it (Linux dev_close)
pub fn dev_close(rtnl: &RtnlGuard, net: &NetNamespace, dev: &Arc<NetDevice>) {
    if dev.is_up() {
        close(rtnl, net, dev);
        rtnetlink::notify_link(net, dev, NlInfo::default());
    }
}

/// Unregister `dev` (Linux unregister_netdevice_many_notify for one
/// device, RTNL held): it closes; leaves the namespace's list (its
/// ifindex is never reused); the driver is detached once no transmit
/// runs in it (Linux synchronize_net), so no driver callback runs
/// again; then NETDEV_UNREGISTER: its addresses (RTM_DELADDR), every
/// route through it and its ARP entries go, packet sockets lose it;
/// RTM_DELLINK; its sysfs device goes ("remove" uevent). The
/// `NetDevice` may outlive this in queued packets: it stays down and
/// driverless.
pub fn unregister_netdevice(rtnl: &RtnlGuard, dev: &Arc<NetDevice>) {
    let Some(net) = dev.net() else { return };
    if dev.is_gone() {
        return;
    }
    dev_close(rtnl, &net, dev);
    net.unlist_device(dev);
    dev.detach_ops(rtnl);
    ifaddr::inetdev_destroy(rtnl, &net, dev);
    net.arp.flush_dev(dev.ifindex());
    crate::net::packet::netdev_unregister(rtnl, &net, dev);
    rtnetlink::notify_dellink(&net, dev);
    crate::net::sysfs::netdev_unregister_kobject(dev);
}

/// Change a device's MTU (Linux dev_set_mtu): EINVAL if negative or
/// outside the device's range. The MTU is an int as in Linux
/// (dev_validate_mtu): both ioctl's ifr_mtu and IFLA_MTU's u32 arrive
/// here as one, so a value above INT_MAX is negative.
pub fn dev_set_mtu(
    _rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &NetDevice,
    mtu: i32,
    nl: NlInfo,
) -> Result<(), KernelError> {
    let mtu = u32::try_from(mtu).map_err(|_| KernelError::InvalidArgument)?;
    let (min, max) = dev.mtu_range();
    if mtu < min || (max != 0 && mtu > max) {
        return Err(KernelError::InvalidArgument);
    }
    if mtu != dev.mtu() {
        dev.store_mtu(mtu);
        rtnetlink::notify_link(net, dev, nl);
    }
    Ok(())
}
