//! Network devices in sysfs (Linux net/core/net-sysfs.c)
//!
//! Each registered device is a "net" class device below its hardware
//! device (or /sys/devices/virtual/net), tagged with its namespace so
//! each namespace's sysfs mounts show only its own devices, with the
//! attributes ip, ifupdown and udev read and INTERFACE/IFINDEX uevents.
//! Devices registered before the class exist (the initial namespace's
//! loopback) are added when it does (Linux netdev_kobject_init running
//! the pernet registrations for existing namespaces).
//!
//! ## Locking
//!
//! `NetDevice.kdev` is set once, when its sysfs device is created (under
//! RTNL for driver registrations); `NET_SYSFS` is set once at init.
//! Attributes read the device without RTNL, as its receive path does.

use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use spin::Once;

use super::device::NetDevice;
use crate::base::{Class, Device, DeviceInfo, device_create};
use crate::fs::kernfs::{self, KNode};
use crate::util::error::KernelError;

/// The net class (Linux net_class)
pub static NET_CLASS: Class = Class::with_uevent("net", net_uevent);

/// The class exists: devices register their sysfs entries
static NET_SYSFS: Once<()> = Once::new();

/// A net class device's data: its interface
struct NetDevRef(Weak<NetDevice>);

fn netdev_of(dev: &Device) -> Option<Arc<NetDevice>> {
    dev.data::<NetDevRef>()?.0.upgrade()
}

/// Linux netdev_uevent
fn net_uevent(dev: &Device, env: &mut Vec<Vec<u8>>) {
    if let Some(n) = netdev_of(dev) {
        env.push(format!("INTERFACE={}", n.name()).into_bytes());
        env.push(format!("IFINDEX={}", n.ifindex()).into_bytes());
    }
}

fn mac_str(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// Linux operstates[]
fn operstate_name(s: u8) -> &'static str {
    match s {
        1 => "notpresent",
        2 => "down",
        3 => "lowerlayerdown",
        4 => "testing",
        5 => "dormant",
        6 => "up",
        _ => "unknown",
    }
}

/// An attribute: its name and its value, from the interface
type NAttr = (&'static [u8], fn(&NetDevice) -> Result<String, KernelError>);

const ATTRS: [NAttr; 14] = [
    (b"address", |n| Ok(format!("{}\n", mac_str(&n.mac())))),
    (b"broadcast", |n| {
        Ok(format!("{}\n", mac_str(&n.link().broadcast)))
    }),
    (b"addr_len", |_| Ok(String::from("6\n"))),
    // NET_ADDR_PERM: the device's own address
    (b"addr_assign_type", |_| Ok(String::from("0\n"))),
    (b"type", |n| Ok(format!("{}\n", n.link().dev_type))),
    (b"ifindex", |n| Ok(format!("{}\n", n.ifindex()))),
    (b"iflink", |n| Ok(format!("{}\n", n.ifindex()))),
    (b"flags", |n| Ok(format!("{:#x}\n", n.get_flags()))),
    (b"mtu", |n| Ok(format!("{}\n", n.mtu()))),
    (b"tx_queue_len", |n| Ok(format!("{}\n", n.link().txqlen))),
    (b"operstate", |n| {
        Ok(format!("{}\n", operstate_name(n.operstate())))
    }),
    // Linux carrier_show: EINVAL while the interface is down
    (b"carrier", |n| {
        if !n.is_up() {
            return Err(KernelError::InvalidArgument);
        }
        Ok(format!("{}\n", u8::from(n.carrier_ok())))
    }),
    (b"carrier_changes", |n| {
        Ok(format!("{}\n", n.carrier_changes()))
    }),
    (b"dev_id", |_| Ok(String::from("0x0\n"))),
];

/// An interface's attribute file
struct NetAttr(
    Weak<NetDevice>,
    fn(&NetDevice) -> Result<String, KernelError>,
);

impl kernfs::Attr for NetAttr {
    fn show(&self, out: &mut kernfs::SysBuf) -> Result<(), KernelError> {
        let n = self.0.upgrade().ok_or(KernelError::NoDevice)?;
        out.bytes((self.1)(&n)?.as_bytes());
        Ok(())
    }
}

fn add_attrs(dir: &Arc<KNode>, n: &Arc<NetDevice>) -> Result<(), KernelError> {
    for (name, f) in ATTRS {
        dir.create_file(name, 0o444, try_arc(NetAttr(Arc::downgrade(n), f))?)?;
    }
    let st = dir.create_dir(b"statistics", 0o755)?;
    let stats: [NAttr; 8] = [
        (b"rx_packets", |n| {
            Ok(format!(
                "{}\n",
                n.stats
                    .rx_packets
                    .load(core::sync::atomic::Ordering::Relaxed)
            ))
        }),
        (b"tx_packets", |n| {
            Ok(format!(
                "{}\n",
                n.stats
                    .tx_packets
                    .load(core::sync::atomic::Ordering::Relaxed)
            ))
        }),
        (b"rx_bytes", |n| {
            Ok(format!(
                "{}\n",
                n.stats.rx_bytes.load(core::sync::atomic::Ordering::Relaxed)
            ))
        }),
        (b"tx_bytes", |n| {
            Ok(format!(
                "{}\n",
                n.stats.tx_bytes.load(core::sync::atomic::Ordering::Relaxed)
            ))
        }),
        (b"rx_errors", |n| {
            Ok(format!(
                "{}\n",
                n.stats
                    .rx_errors
                    .load(core::sync::atomic::Ordering::Relaxed)
            ))
        }),
        (b"tx_errors", |n| {
            Ok(format!(
                "{}\n",
                n.stats
                    .tx_errors
                    .load(core::sync::atomic::Ordering::Relaxed)
            ))
        }),
        (b"rx_dropped", |n| {
            Ok(format!(
                "{}\n",
                n.stats
                    .rx_dropped
                    .load(core::sync::atomic::Ordering::Relaxed)
            ))
        }),
        (b"tx_dropped", |n| {
            Ok(format!(
                "{}\n",
                n.stats
                    .tx_dropped
                    .load(core::sync::atomic::Ordering::Relaxed)
            ))
        }),
    ];
    for (name, f) in stats {
        st.create_file(name, 0o444, try_arc(NetAttr(Arc::downgrade(n), f))?)?;
    }
    Ok(())
}

fn net_attrs(dev: &Arc<Device>) -> Result<(), KernelError> {
    let n = netdev_of(dev).ok_or(KernelError::NoDevice)?;
    add_attrs(dev.kobj(), &n)
}

/// Register `n`'s sysfs device in its namespace (Linux
/// netdev_register_kobject); nothing before the class exists
pub fn netdev_register_kobject(n: &Arc<NetDevice>) {
    if NET_SYSFS.get().is_none() || n.kdev.get().is_some() {
        return;
    }
    let Some(net) = n.net() else { return };
    let parent = n.parent.get();
    let r = try_arc(NetDevRef(Arc::downgrade(n))).and_then(|data| {
        device_create(DeviceInfo {
            parent,
            class: Some(&NET_CLASS),
            data: Some(data),
            attrs: Some(net_attrs),
            ns: net.id,
            ..DeviceInfo::named(n.name())
        })
    });
    match r {
        Ok(d) => {
            n.kdev.call_once(|| d);
        }
        Err(e) => crate::printkln!("net: {}: sysfs: {:?}", n.name(), e),
    }
}

/// Remove `n`'s sysfs device (Linux netdev_unregister_kobject)
pub fn netdev_unregister_kobject(n: &NetDevice) {
    if let Some(d) = n.kdev.get() {
        d.del();
    }
}

/// Remove a dropped namespace's devices from sysfs, from the system
/// workqueue (Linux cleanup_net -> default_device_exit_batch)
pub fn netns_exit(kdevs: Vec<Arc<Device>>) {
    if kdevs.is_empty() {
        return;
    }
    let mut pending = Some(kdevs);
    let work = crate::task::workqueue::Work::new(move || {
        for d in pending.take().unwrap_or_default() {
            d.del();
        }
    });
    // Namespace teardown cannot fail
    let work = arc_nofail(crate::sync::IrqSpinlock::new(work));
    crate::task::workqueue::SYSTEM_WQ.queue_work(work);
}

/// Linux netdev_kobject_init: the class, then the devices already
/// registered in every namespace
pub fn net_sysfs_init() {
    NET_CLASS.register();
    NET_SYSFS.call_once(|| ());
    for net in crate::ns::net::all_net_ns() {
        for n in net.devices() {
            netdev_register_kobject(&n);
        }
    }
}
