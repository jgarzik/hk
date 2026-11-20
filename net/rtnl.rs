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
//!
//! Releasing RTNL runs the unregistration todo list (Linux rtnl_unlock
//! -> netdev_run_todo): the devices unregistered under that hold are
//! waited for, with RTNL dropped, until only their owner references
//! them (`netdev_run_todo`). `NET_TODO` is a leaf spin lock taken under
//! RTNL.

use alloc::sync::Arc;

use crate::sync::{Mutex, MutexGuard};

use crate::net::NetNamespace;
use crate::net::device::{NetDevice, TodoList, flags};
use crate::net::inet::ifaddr;
use crate::net::netlink::{NlInfo, rtnetlink};
use crate::util::error::KernelError;
use crate::util::list::ArcList;

static RTNL: Mutex<()> = Mutex::new(());

/// Devices unregistered under the current RTNL hold, waited for when it
/// is released (Linux net_todo_list); added to and taken under RTNL
static NET_TODO: crate::sync::spin::Mutex<ArcList<TodoList>> =
    crate::sync::spin::Mutex::new(ArcList::new());

/// Proof that RTNL is held; dropping it releases RTNL and runs the
/// todo list (Linux rtnl_unlock)
pub struct RtnlGuard(Option<MutexGuard<'static, ()>>);

/// Take RTNL (Linux rtnl_lock)
pub fn lock() -> RtnlGuard {
    RtnlGuard(Some(RTNL.lock()))
}

impl RtnlGuard {
    /// Release RTNL without running the todo list (Linux __rtnl_unlock)
    fn unlock(mut self) {
        self.0 = None;
    }
}

impl Drop for RtnlGuard {
    /// Linux rtnl_unlock -> netdev_run_todo: the list is taken under
    /// RTNL, then RTNL is released and its devices are waited for
    fn drop(&mut self) {
        let Some(g) = self.0.take() else { return };
        let todo = core::mem::take(&mut *NET_TODO.lock());
        drop(g);
        if !todo.is_empty() {
            netdev_run_todo(todo);
        }
    }
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
        crate::net::packet::netdev_up(net, dev);
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
/// again; then NETDEV_UNREGISTER; RTM_DELLINK; its sysfs device goes
/// ("remove" uevent). It is queued on the todo list (Linux
/// net_set_todo): releasing RTNL waits until only its owner (the
/// driver, or the namespace for its loopback) references it.
pub fn unregister_netdevice(rtnl: &RtnlGuard, dev: &Arc<NetDevice>) {
    let Some(net) = dev.net() else { return };
    if dev.is_gone() {
        return;
    }
    dev_close(rtnl, &net, dev);
    net.unlist_device(dev);
    dev.detach_ops(rtnl);
    netdev_unregister_notify(rtnl, &net, dev);
    rtnetlink::notify_dellink(&net, dev);
    crate::net::sysfs::netdev_unregister_kobject(dev);
    NET_TODO.lock().push_back(Arc::clone(dev));
}

/// NETDEV_UNREGISTER (Linux call_netdevice_notifiers): every holder of
/// a reference to `dev` lets it go. Its addresses (RTM_DELADDR) and
/// every route through it go (inetdev_destroy, fib_disable_ip; routes
/// are freed after a grace period), its ARP entries and their queued
/// packets (neigh_ifdown), packet sockets keep only its index
/// (packet_notifier). Repeatable: the todo wait sends it again to
/// holders that took a reference meanwhile.
fn netdev_unregister_notify(rtnl: &RtnlGuard, net: &NetNamespace, dev: &Arc<NetDevice>) {
    // inetdev_destroy's fib_disable_ip flushes its ARP entries too
    // (Linux fib_netdev_event -> fib_disable_ip -> arp_ifdown)
    ifaddr::inetdev_destroy(rtnl, net, dev);
    crate::net::packet::netdev_unregister(rtnl, net, dev);
    // Rules naming it detach (Linux fib_rules_event's detach_rules)
    net.fib.rules.detach(dev);
}

/// References an unregistered device keeps once every holder let it
/// go: its owner's (Linux alloc_netdev's, the 1 netdev_refcnt_read
/// waits for: the driver binding, or a namespace's loopback slot) and
/// the todo list's
const OWNER_REFS: usize = 2;
/// First and longest sleep between checks (Linux WAIT_REFS_MIN_MSECS,
/// WAIT_REFS_MAX_MSECS)
const WAIT_REFS_MIN_MS: u64 = 1;
const WAIT_REFS_MAX_MS: u64 = 250;
/// NETDEV_UNREGISTER is sent again this often (Linux 1 * HZ)
const REBROADCAST_MS: u64 = 1000;
/// A device still referenced is reported this often, in seconds
/// (Linux netdev_unregister_timeout_secs: 10 at boot, 1..3600 through
/// net.core.netdev_unregister_timeout_secs, read racily)
pub static UNREGISTER_TIMEOUT_SECS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(10);

/// Linux netdev_run_todo, with RTNL released: once the RCU callbacks
/// queued meanwhile ran (routes and neighbours freed), each device is
/// waited for until only its owner holds it; the todo list's reference
/// then goes
fn netdev_run_todo(mut list: ArcList<TodoList>) {
    crate::sync::rcu::rcu_barrier();
    while !list.is_empty() {
        drop(netdev_wait_allrefs_any(&mut list));
    }
}

/// The first device on `list` whose holders let it go, taken off it
/// (Linux netdev_wait_allrefs_any): checked after an RCU barrier and a
/// sleep of 1 ms doubling to 250; every second NETDEV_UNREGISTER is sent
/// again under RTNL, and every 10 s each device still held is reported
fn netdev_wait_allrefs_any(list: &mut ArcList<TodoList>) -> Arc<NetDevice> {
    if let Some(dev) = take_free(list) {
        return dev;
    }
    let mut rebroadcast = now_ms();
    let mut warning = rebroadcast;
    let mut wait = 0;
    loop {
        if now_ms().saturating_sub(rebroadcast) > REBROADCAST_MS {
            rebroadcast_unregister(list);
            rebroadcast = now_ms();
        }
        crate::sync::rcu::rcu_barrier();
        if wait == 0 {
            wait = WAIT_REFS_MIN_MS;
        } else {
            crate::task::percpu::sleep_current_ms(wait);
            wait = (wait << 1).min(WAIT_REFS_MAX_MS);
        }
        if let Some(dev) = take_free(list) {
            return dev;
        }
        let timeout =
            u64::from(UNREGISTER_TIMEOUT_SECS.load(core::sync::atomic::Ordering::Relaxed)) * 1000;
        if now_ms().saturating_sub(warning) > timeout {
            for_each_todo(list, |dev| {
                crate::printkln!(
                    "unregister_netdevice: waiting for {} to become free. Usage count = {}",
                    dev.name(),
                    Arc::strong_count(dev) - 1
                );
            });
            warning = now_ms();
        }
    }
}

/// NETDEV_UNREGISTER again for every device on `list`, under RTNL
/// released without running the todo list, then an RCU barrier (Linux
/// netdev_wait_allrefs_any's rebroadcast)
fn rebroadcast_unregister(list: &mut ArcList<TodoList>) {
    let r = lock();
    for_each_todo(list, |dev| {
        if let Some(net) = dev.net() {
            netdev_unregister_notify(&r, &net, dev);
        }
    });
    r.unlock();
    crate::sync::rcu::rcu_barrier();
}

/// Take the first device on `list` that only its owner and the list
/// still reference
fn take_free(list: &mut ArcList<TodoList>) -> Option<Arc<NetDevice>> {
    for _ in 0..list.len() {
        let dev = list.pop_front()?;
        if Arc::strong_count(&dev) <= OWNER_REFS {
            return Some(dev);
        }
        list.push_back(dev);
    }
    None
}

/// Run `f` on each device on `list`, keeping their order
fn for_each_todo(list: &mut ArcList<TodoList>, mut f: impl FnMut(&Arc<NetDevice>)) {
    for _ in 0..list.len() {
        let Some(dev) = list.pop_front() else { return };
        f(&dev);
        list.push_back(dev);
    }
}

fn now_ms() -> u64 {
    crate::time::monotonic_ns() / 1_000_000
}

/// Unregister the devices of a namespace whose last active reference
/// went (Linux cleanup_net -> default_device_exit_batch, loopback last;
/// from the netns workqueue): each through `unregister_netdevice`, as
/// the namespace is still allocated (its teardown holds it). No socket
/// of the namespace is left to hear the announcements. The references
/// taken here go before RTNL is released, whose todo wait leaves the
/// loopback its namespace's.
pub fn netns_exit(net: &Arc<crate::net::NetNamespace>) {
    let mut devs = net.devices();
    // Registration order puts lo first; it goes last
    devs.sort_by_key(|d| d.is_loopback());
    let r = lock();
    for dev in devs {
        unregister_netdevice(&r, &dev);
    }
    // Device-less proxy entries go with their namespace (Linux keeps
    // them until the table is cleared: a leak)
    crate::net::arp::arp_tbl().phash.net_exit(net.id);
    drop(r);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::device::{LinkInfo, NetDeviceOps};
    use crate::net::skb::SkBuff;
    use crate::util::kalloc::arc_nofail;
    use alloc::boxed::Box;
    use alloc::string::String;

    struct NoOps;

    impl NetDeviceOps for NoOps {
        fn xmit(&self, _skb: Box<SkBuff>) -> Result<(), KernelError> {
            Ok(())
        }

        fn mac_address(&self) -> [u8; 6] {
            [0; 6]
        }
    }

    fn dev(name: &str) -> Arc<NetDevice> {
        arc_nofail(NetDevice::new(
            String::from(name),
            [0; 6],
            LinkInfo::ETHER,
            arc_nofail(NoOps),
        ))
    }

    /// A device is taken off the todo list only once no holder but its
    /// owner is left (Linux netdev_refcnt_read(dev) == 1); the others
    /// stay, in order
    #[test]
    fn take_free_waits_for_holders() {
        let (a, b) = (dev("a"), dev("b"));
        let mut list = ArcList::<TodoList>::new();
        list.push_back(Arc::clone(&a));
        list.push_back(Arc::clone(&b));
        let (ha, hb) = (Arc::clone(&a), Arc::clone(&b));
        assert!(take_free(&mut list).is_none());
        assert_eq!(list.len(), 2);
        drop(hb);
        let got = take_free(&mut list).unwrap();
        assert!(Arc::ptr_eq(&got, &b));
        assert_eq!(list.len(), 1);
        assert!(take_free(&mut list).is_none());
        drop(ha);
        let got = take_free(&mut list).unwrap();
        assert!(Arc::ptr_eq(&got, &a));
        assert!(list.is_empty());
    }

    /// A device whose owner already let it go is free too
    #[test]
    fn take_free_without_owner() {
        let mut list = ArcList::<TodoList>::new();
        list.push_back(dev("c"));
        assert!(take_free(&mut list).is_some());
    }
}
