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

use crate::error::KernelError;
use crate::net::NetNamespace;
use crate::net::device::{NetDevice, flags};
use crate::net::inet::ifaddr;
use crate::net::netlink::{NlInfo, rtnetlink};

static RTNL: Mutex<()> = Mutex::new(());

/// Proof that RTNL is held
pub struct RtnlGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

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
        dev.close();
        ifaddr::inetdev_down(rtnl, net, dev);
    }
    if dev.admin_flags() != old {
        rtnetlink::notify_link(net, dev, nl);
    }
    Ok(())
}

/// Change a device's MTU (Linux dev_set_mtu): EINVAL outside the
/// device's range
pub fn dev_set_mtu(
    _rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &NetDevice,
    mtu: u32,
    nl: NlInfo,
) -> Result<(), KernelError> {
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
