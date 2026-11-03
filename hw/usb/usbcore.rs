//! USB on the device core (Linux drivers/usb/core/usb.c, hub.c,
//! generic.c, message.c, sysfs.c): the bus, root hub `usbN` and the
//! devices `N-<port>` below it (DEVTYPE=usb_device), the generic
//! usb_device driver "usb", whose probe adds the active
//! configuration's interfaces `N-<port>:C.I` (DEVTYPE=usb_interface;
//! Linux usb_set_configuration), and their attributes.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::driver::{UsbDeviceId, UsbIds, modalias, product_env, usb_match_id};
use super::{EndpointType, UsbConfig, UsbDevice, UsbEndpoint, UsbInterface, UsbSpeed, class};
use crate::base::bus::BusType;
use crate::base::{Bound, Device, DeviceInfo, Driver, device_create};
use crate::fs::kernfs;
use crate::printkln;
use crate::util::error::KernelError;

pub static USB_BUS: BusType =
    BusType::with_drv_attrs("usb", usb_match, Some(usb_uevent), Some(usb_drv_attrs));

/// Ids added through interface drivers' new_id files, by driver name
/// (Linux usb_driver.dynids; spin leaf)
static DYNIDS: crate::sync::spin::Mutex<Vec<(&'static str, UsbDeviceId)>> =
    crate::sync::spin::Mutex::new(Vec::new());

/// new_id (Linux usb_store_new_id): "idVendor idProduct
/// [bInterfaceClass [refVendor refProduct]]"; the id is added and
/// unbound interfaces probed
struct NewId(&'static Driver);

impl crate::fs::kernfs::Attr for NewId {
    fn show(&self, _out: &mut crate::fs::kernfs::SysBuf) -> Result<(), KernelError> {
        Err(KernelError::Io)
    }

    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let f = crate::base::bus::hex_fields(data, 5);
        if f.len() < 2 {
            return Err(KernelError::InvalidArgument);
        }
        let mut id = UsbDeviceId::device(f[0] as u16, f[1] as u16);
        if f.len() > 2 && f[2] != 0 {
            if f[2] > 255 {
                return Err(KernelError::InvalidArgument);
            }
            id.b_interface_class = f[2] as u8;
            id.match_flags |= super::driver::id_match::INT_CLASS;
        }
        DYNIDS.lock().push((self.0.name, id));
        crate::base::dd::driver_attach(self.0);
        Ok(data.len())
    }
}

/// remove_id (Linux usb_remove_id): every dynamic id of "idVendor
/// idProduct" goes
struct RemoveId(&'static Driver);

impl crate::fs::kernfs::Attr for RemoveId {
    fn show(&self, _out: &mut crate::fs::kernfs::SysBuf) -> Result<(), KernelError> {
        Err(KernelError::Io)
    }

    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let f = crate::base::bus::hex_fields(data, 2);
        if f.len() < 2 {
            return Err(KernelError::InvalidArgument);
        }
        let (v, p) = (f[0] as u16, f[1] as u16);
        DYNIDS
            .lock()
            .retain(|(n, id)| !(*n == self.0.name && id.id_vendor == v && id.id_product == p));
        Ok(data.len())
    }
}

/// An interface driver's new_id and remove_id (Linux
/// usb_create_newid_files)
fn usb_drv_attrs(drv: &'static Driver, dir: &Arc<crate::fs::kernfs::KNode>) {
    if matches!(drv.ids.downcast_ref::<UsbIds>(), Some(UsbIds::Interface(_))) {
        let _ = dir.create_file(b"new_id", 0o200, Arc::new(NewId(drv)));
        let _ = dir.create_file(b"remove_id", 0o200, Arc::new(RemoveId(drv)));
    }
}

/// The generic usb_device driver (Linux usb_generic_driver)
pub static USB_GENERIC_DRIVER: Driver =
    Driver::new("usb", &USB_BUS, None, &UsbIds::Device, generic_probe);

/// Linux usb_init: the bus and the generic driver
pub fn usb_init() {
    USB_BUS.register();
    USB_GENERIC_DRIVER.register();
}

/// A usb_device's data (Linux struct usb_device)
pub struct UsbDevNode {
    pub dev: UsbDevice,
    pub busnum: u8,
    pub devnum: u8,
    /// Port path below the root hub ("0" for the root hub itself)
    pub devpath: String,
}

/// An interface's data (Linux struct usb_interface): its current
/// setting; the device is its parent's
pub struct UsbIntfNode {
    pub intf: UsbInterface,
}

/// The USB device behind a usb_device `dev`
pub fn usb_dev(dev: &Device) -> Option<&UsbDevice> {
    dev.data::<UsbDevNode>().map(|n| &n.dev)
}

/// The device and interface setting behind an interface `dev`
pub fn usb_intf(dev: &Device) -> Option<(&UsbDevice, &UsbInterface)> {
    let f = dev.data::<UsbIntfNode>()?;
    Some((usb_dev(dev.parent()?)?, &f.intf))
}

/// Linux usb_device_match: usb_device drivers take devices, interface
/// drivers interfaces their table matches
fn usb_match(dev: &Device, drv: &'static Driver) -> bool {
    match drv.ids.downcast_ref::<UsbIds>() {
        Some(UsbIds::Device) => usb_dev(dev).is_some(),
        Some(UsbIds::Interface(ids)) => usb_intf(dev).is_some_and(|(d, f)| {
            let dynamic = DYNIDS
                .lock()
                .iter()
                .any(|(n, id)| *n == drv.name && id.matches(d, f));
            dynamic || usb_match_id(ids, d, f).is_some()
        }),
        None => false,
    }
}

/// Linux usb_uevent, then usb_dev_uevent or usb_if_uevent
fn usb_uevent(dev: &Device, env: &mut Vec<Vec<u8>>) {
    if let Some(n) = dev.data::<UsbDevNode>() {
        product_env(&n.dev, env);
        env.push(format!("BUSNUM={:03}", n.busnum).into_bytes());
        env.push(format!("DEVNUM={:03}", n.devnum).into_bytes());
    } else if let Some((d, f)) = usb_intf(dev) {
        product_env(d, env);
        env.push(format!("INTERFACE={}/{}/{}", f.class, f.subclass, f.protocol).into_bytes());
        env.push(format!("MODALIAS={}", modalias(d, f)).into_bytes());
    }
}

/// Linux speed_show: Mbit/s
fn speed_mbps(s: UsbSpeed) -> &'static str {
    match s {
        UsbSpeed::Low => "1.5",
        UsbSpeed::Full => "12",
        UsbSpeed::High => "480",
        UsbSpeed::Super => "5000",
        UsbSpeed::SuperPlus => "10000",
    }
}

/// Linux usb_get_max_power: mA
fn max_power_ma(d: &UsbDevice) -> u32 {
    d.config.max_power as u32 * if d.speed.is_super() { 8 } else { 2 }
}

/// Read-only attributes `files` of `dev`
fn add_files(dev: &Arc<Device>, files: Vec<(&'static [u8], String)>) -> Result<(), KernelError> {
    for (name, v) in files {
        dev.create_file(name, 0o444, kernfs::show(move |o| o.bytes(v.as_bytes())))?;
    }
    Ok(())
}

/// A usb_device's attributes (Linux usb_dev_attrs subset; the
/// configuration ones empty while unconfigured, as Linux's)
fn usb_dev_attrs(dev: &Arc<Device>) -> Result<(), KernelError> {
    let Some(n) = dev.data::<UsbDevNode>() else {
        return Ok(());
    };
    let d = &n.dev;
    let cfg = |s: String| {
        if d.config.value != 0 {
            s
        } else {
            String::new()
        }
    };
    add_files(
        dev,
        alloc::vec![
            (b"idVendor", format!("{:04x}\n", d.vendor_id)),
            (b"idProduct", format!("{:04x}\n", d.product_id)),
            (b"bcdDevice", format!("{:04x}\n", d.bcd_device)),
            (b"bDeviceClass", format!("{:02x}\n", d.device_class)),
            (b"bDeviceSubClass", format!("{:02x}\n", d.device_subclass)),
            (b"bDeviceProtocol", format!("{:02x}\n", d.device_protocol)),
            (b"bNumConfigurations", format!("{}\n", d.num_configurations)),
            (b"bMaxPacketSize0", format!("{}\n", d.max_packet_size0)),
            (b"bConfigurationValue", cfg(format!("{}\n", d.config.value))),
            (
                b"bNumInterfaces",
                cfg(format!("{:2}\n", d.config.num_interfaces))
            ),
            (
                b"bmAttributes",
                cfg(format!("{:2x}\n", d.config.attributes))
            ),
            (b"bMaxPower", cfg(format!("{}mA\n", max_power_ma(d)))),
            (b"speed", format!("{}\n", speed_mbps(d.speed))),
            (b"busnum", format!("{}\n", n.busnum)),
            (b"devnum", format!("{}\n", n.devnum)),
            (b"devpath", format!("{}\n", n.devpath)),
            (
                b"version",
                format!("{:2x}.{:02x}\n", d.bcd_usb >> 8, d.bcd_usb & 0xff)
            ),
            // Set by the hub driver (Linux hub_configure); none yet
            (b"maxchild", String::from("0\n")),
        ],
    )
}

/// An interface's attributes (Linux intf_attrs subset)
fn usb_intf_attrs(dev: &Arc<Device>) -> Result<(), KernelError> {
    let Some((d, f)) = usb_intf(dev) else {
        return Ok(());
    };
    add_files(
        dev,
        alloc::vec![
            (b"bInterfaceNumber", format!("{:02x}\n", f.number)),
            (b"bAlternateSetting", format!("{:2}\n", f.alternate_setting)),
            (b"bNumEndpoints", format!("{:02x}\n", f.num_endpoints)),
            (b"bInterfaceClass", format!("{:02x}\n", f.class)),
            (b"bInterfaceSubClass", format!("{:02x}\n", f.subclass)),
            (b"bInterfaceProtocol", format!("{:02x}\n", f.protocol)),
            (b"modalias", format!("{}\n", modalias(d, f))),
        ],
    )
}

/// Linux bin2bcd
fn bcd(x: u8) -> u16 {
    (((x / 10) << 4) | (x % 10)) as u16
}

/// The USB 2.0 root hub (Linux usb2_rh_dev_descriptor,
/// hs_rh_config_descriptor): Linux Foundation 1d6b:0002, bcdDevice
/// the kernel's major.minor, one hub interface with its status-change
/// endpoint
fn root_hub() -> UsbDevice {
    let ver = |s: &str| s.parse::<u8>().unwrap_or(0);
    let mut d = UsbDevice::new(0, 0, UsbSpeed::High);
    d.bcd_usb = 0x0200;
    d.vendor_id = 0x1d6b;
    d.product_id = 0x0002;
    d.bcd_device =
        bcd(ver(env!("CARGO_PKG_VERSION_MAJOR"))) << 8 | bcd(ver(env!("CARGO_PKG_VERSION_MINOR")));
    d.device_class = class::HUB;
    d.max_packet_size0 = 64;
    d.num_configurations = 1;
    d.config = UsbConfig {
        value: 1,
        num_interfaces: 1,
        attributes: 0xc0,
        max_power: 0,
    };
    d.interfaces.push(UsbInterface {
        number: 0,
        alternate_setting: 0,
        num_endpoints: 1,
        class: class::HUB,
        subclass: 0,
        protocol: 0,
        endpoints: alloc::vec![UsbEndpoint {
            address: 0x81,
            ep_type: EndpointType::Interrupt,
            // 1 + USB_MAXCHILDREN (31) bits, rounded up to bytes
            max_packet_size: 4,
            interval: 0x0c,
            max_burst: 0,
            bytes_per_interval: 0,
        }],
    });
    d
}

/// Register a usb_device below `parent` (Linux usb_new_device)
fn usb_new_device(
    parent: &Arc<Device>,
    name: &str,
    node: UsbDevNode,
) -> Result<Arc<Device>, KernelError> {
    device_create(DeviceInfo {
        parent: Some(parent),
        bus: Some(&USB_BUS),
        devtype: Some("usb_device"),
        data: Some(Arc::new(node)),
        attrs: Some(usb_dev_attrs),
        ..DeviceInfo::named(name)
    })
}

/// Register the root hub `usbN` below the host controller and each
/// device on its ports as `N-<port>` (Linux usb_add_hcd, then
/// hub_event's usb_new_device); devnums go in order from 1, the root
/// hub's (Linux choose_devnum)
pub fn usb_register_devices(hcd: &Arc<Device>, devs: Vec<UsbDevice>) -> Vec<Arc<Device>> {
    let busnum = 1;
    let mut out = Vec::new();
    let rh = UsbDevNode {
        dev: root_hub(),
        busnum,
        devnum: 1,
        devpath: String::from("0"),
    };
    let root = match usb_new_device(hcd, &format!("usb{}", busnum), rh) {
        Ok(r) => r,
        Err(e) => {
            printkln!("usb: root hub registration failed: {:?}", e);
            return out;
        }
    };
    for (i, d) in devs.into_iter().enumerate() {
        let devpath = format!("{}", d.port);
        let name = format!("{}-{}", busnum, devpath);
        let node = UsbDevNode {
            dev: d,
            busnum,
            devnum: 2 + i as u8,
            devpath,
        };
        match usb_new_device(&root, &name, node) {
            Ok(dev) => out.push(dev),
            Err(e) => printkln!("usb {}: registration failed: {:?}", name, e),
        }
    }
    out.push(root);
    out
}

/// Unregister what `usb_register_devices` registered, the root hub's
/// devices before it (Linux usb_disconnect, depth first: each device's
/// interfaces go when its generic driver unbinds, Linux
/// usb_disable_device, then the device)
pub fn usb_unregister_devices(devs: &[Arc<Device>]) {
    for d in devs {
        d.del();
    }
}

/// Each interface's current setting: alternate setting 0, else its
/// first (Linux usb_set_configuration)
pub(super) fn cur_altsettings(intfs: &[UsbInterface]) -> Vec<&UsbInterface> {
    let mut cur: Vec<&UsbInterface> = Vec::new();
    for f in intfs {
        match cur.iter_mut().find(|c| c.number == f.number) {
            Some(c) if f.alternate_setting == 0 => *c = f,
            Some(_) => {}
            None => cur.push(f),
        }
    }
    cur
}

/// The interfaces the generic driver added (removed with it)
struct UsbGeneric {
    intfs: Vec<Arc<Device>>,
}

impl Bound for UsbGeneric {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn remove(&self) {
        for f in self.intfs.iter().rev() {
            f.del();
        }
    }
}

/// Linux generic_probe: the active configuration's interfaces become
/// devices (Linux usb_set_configuration's device_add of each; the
/// configuration itself was set at enumeration), each probed in turn
fn generic_probe(dev: &Arc<Device>) -> Result<Box<dyn Bound>, KernelError> {
    let n = dev.data::<UsbDevNode>().ok_or(KernelError::NoDevice)?;
    let mut intfs = Vec::new();
    if n.dev.config.value != 0 {
        for f in cur_altsettings(&n.dev.interfaces) {
            let name = format!(
                "{}-{}:{}.{}",
                n.busnum, n.devpath, n.dev.config.value, f.number
            );
            let r = device_create(DeviceInfo {
                parent: Some(dev),
                bus: Some(&USB_BUS),
                devtype: Some("usb_interface"),
                data: Some(Arc::new(UsbIntfNode { intf: f.clone() })),
                attrs: Some(usb_intf_attrs),
                ..DeviceInfo::named(&name)
            });
            match r {
                Ok(i) => intfs.push(i),
                Err(e) => printkln!("usb {}: interface add failed: {:?}", name, e),
            }
        }
    }
    Ok(Box::new(UsbGeneric { intfs }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alt(number: u8, alternate_setting: u8) -> UsbInterface {
        UsbInterface {
            number,
            alternate_setting,
            num_endpoints: 0,
            class: 0,
            subclass: 0,
            protocol: 0,
            endpoints: Vec::new(),
        }
    }

    #[test]
    fn altsettings() {
        let v = [alt(0, 1), alt(0, 0), alt(1, 2), alt(1, 3)];
        let cur = cur_altsettings(&v);
        assert_eq!(cur.len(), 2);
        assert_eq!((cur[0].number, cur[0].alternate_setting), (0, 0));
        assert_eq!((cur[1].number, cur[1].alternate_setting), (1, 2));
    }

    #[test]
    fn root_hub_desc() {
        let d = root_hub();
        assert_eq!((d.vendor_id, d.product_id, d.bcd_usb), (0x1d6b, 2, 0x0200));
        assert_eq!(bcd(12), 0x12);
        assert_eq!(max_power_ma(&d), 0);
    }
}
