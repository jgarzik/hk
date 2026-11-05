//! PCI on the device core (Linux drivers/pci/pci-driver.c, pci-sysfs.c,
//! probe.c pci_device_add)
//!
//! Each function is a `Device` named "0000:BB:DD.F" below the host
//! bridge's /sys/devices/pci0000:00, with Linux's attributes (vendor,
//! device, class, config, driver_override, ...) and uevent variables.
//! Drivers match by id table, or only by name once driver_override is
//! set.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;

use spin::Once;

use super::PciDevice;
use crate::base::bus::BusType;
use crate::base::{Device, DeviceInfo, Driver, device_create};
use crate::fs::kernfs::{self, Attr, BinAttr, SysBuf};
use crate::sync::spin::Mutex;
use crate::util::error::KernelError;

pub static PCI_BUS: BusType =
    BusType::with_drv_attrs("pci", pci_match, Some(pci_uevent), Some(pci_drv_attrs));

/// Ids added through drivers' new_id files, by driver name (Linux
/// pci_driver.dynids; spin leaf)
static DYNIDS: Mutex<Vec<(&'static str, PciDeviceId)>> = Mutex::new(Vec::new());

/// Matches any vendor/device/subsystem id (Linux PCI_ANY_ID)
pub const PCI_ANY_ID: u32 = !0;

/// One id table entry (Linux struct pci_device_id)
#[derive(Clone, Copy)]
pub struct PciDeviceId {
    pub vendor: u32,
    pub device: u32,
    pub subvendor: u32,
    pub subdevice: u32,
    pub class: u32,
    pub class_mask: u32,
}

impl PciDeviceId {
    /// Linux PCI_DEVICE
    pub const fn device(vendor: u16, device: u16) -> Self {
        Self {
            vendor: vendor as u32,
            device: device as u32,
            subvendor: PCI_ANY_ID,
            subdevice: PCI_ANY_ID,
            class: 0,
            class_mask: 0,
        }
    }

    /// Any device of `vendor`
    pub const fn vendor(vendor: u16) -> Self {
        Self {
            device: PCI_ANY_ID,
            ..Self::device(vendor, 0)
        }
    }

    /// Linux PCI_DEVICE_CLASS
    pub const fn class(class: u32, class_mask: u32) -> Self {
        Self {
            vendor: PCI_ANY_ID,
            device: PCI_ANY_ID,
            subvendor: PCI_ANY_ID,
            subdevice: PCI_ANY_ID,
            class,
            class_mask,
        }
    }

    /// Linux pci_match_one_device
    fn matches(&self, p: &PciDevice) -> bool {
        let h = &p.header;
        self.matches_ids(
            [
                u32::from(h.vendor_id),
                u32::from(h.device_id),
                u32::from(h.subsystem_vendor_id),
                u32::from(h.subsystem_id),
            ],
            p.class24(),
        )
    }

    /// pci_match_one_device against raw (vendor, device, subvendor,
    /// subdevice) and class
    fn matches_ids(&self, v: [u32; 4], class: u32) -> bool {
        let any = |want: u32, have: u32| want == PCI_ANY_ID || want == have;
        any(self.vendor, v[0])
            && any(self.device, v[1])
            && any(self.subvendor, v[2])
            && any(self.subdevice, v[3])
            && (self.class ^ class) & self.class_mask == 0
    }
}

/// A PCI driver's id table
pub struct PciIds(pub &'static [PciDeviceId]);

/// A function's device data: the function and its driver_override
pub struct PciDev {
    pub pci: PciDevice,
    driver_override: Mutex<Option<String>>,
}

/// The PCI function behind `dev`
pub fn pci_dev(dev: &Device) -> Option<&PciDevice> {
    dev.data::<PciDev>().map(|d| &d.pci)
}

/// Linux pci_bus_match -> pci_match_device: driver_override names the
/// only driver that may bind, else the id table decides
fn pci_match(dev: &Device, drv: &'static Driver) -> bool {
    let Some(d) = dev.data::<PciDev>() else {
        return false;
    };
    if let Some(o) = d.driver_override.lock().as_deref() {
        return o == drv.name;
    }
    let dynamic = DYNIDS
        .lock()
        .iter()
        .any(|(n, id)| *n == drv.name && id.matches(&d.pci));
    dynamic || static_ids(drv).iter().any(|id| id.matches(&d.pci))
}

fn static_ids(drv: &'static Driver) -> &'static [PciDeviceId] {
    drv.ids.downcast_ref::<PciIds>().map_or(&[], |i| i.0)
}

/// An id from new_id/remove_id fields: vendor device [subvendor
/// subdevice class class_mask] (missing ones match anything)
fn field_id(f: &[u32]) -> PciDeviceId {
    let get = |i: usize, d: u32| f.get(i).copied().unwrap_or(d);
    PciDeviceId {
        vendor: f[0],
        device: f[1],
        subvendor: get(2, PCI_ANY_ID),
        subdevice: get(3, PCI_ANY_ID),
        class: get(4, 0),
        class_mask: get(5, 0),
    }
}

/// new_id (Linux new_id_store): EEXIST if the driver matches such a
/// device already, EINVAL for a driver_data no table entry has (hk ids
/// carry none: only 0), then the id is added and unbound devices probed
struct NewId(&'static Driver);

impl Attr for NewId {
    fn show(&self, _out: &mut SysBuf) -> Result<(), KernelError> {
        Err(KernelError::Io)
    }

    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let drv = self.0;
        let f = crate::base::bus::hex_fields(data, 7);
        if f.len() < 2 {
            return Err(KernelError::InvalidArgument);
        }
        let id = field_id(&f);
        if f.len() != 7 {
            let dev = [id.vendor, id.device, id.subvendor, id.subdevice];
            let dynamic = DYNIDS
                .lock()
                .iter()
                .any(|(n, d)| *n == drv.name && d.matches_ids(dev, id.class));
            if dynamic || static_ids(drv).iter().any(|s| s.matches_ids(dev, id.class)) {
                return Err(KernelError::AlreadyExists);
            }
        } else if f[6] != 0 {
            return Err(KernelError::InvalidArgument);
        }
        DYNIDS.lock().push((drv.name, id));
        crate::base::dd::driver_attach(drv);
        Ok(data.len())
    }
}

/// remove_id (Linux remove_id_store): ENODEV if no such dynamic id
struct RemoveId(&'static Driver);

impl Attr for RemoveId {
    fn show(&self, _out: &mut SysBuf) -> Result<(), KernelError> {
        Err(KernelError::Io)
    }

    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let f = crate::base::bus::hex_fields(data, 6);
        if f.len() < 2 {
            return Err(KernelError::InvalidArgument);
        }
        let id = field_id(&f);
        let mut ids = DYNIDS.lock();
        let i = ids
            .iter()
            .position(|(n, d)| {
                *n == self.0.name
                    && (
                        d.vendor,
                        d.device,
                        d.subvendor,
                        d.subdevice,
                        d.class,
                        d.class_mask,
                    ) == (
                        id.vendor,
                        id.device,
                        id.subvendor,
                        id.subdevice,
                        id.class,
                        id.class_mask,
                    )
            })
            .ok_or(KernelError::NoDevice)?;
        ids.remove(i);
        Ok(data.len())
    }
}

/// new_id and remove_id of a PCI driver (Linux pci_drv_groups)
fn pci_drv_attrs(drv: &'static Driver, dir: &Arc<crate::fs::kernfs::KNode>) {
    let _ = dir.create_file(b"new_id", 0o200, Arc::new(NewId(drv)));
    let _ = dir.create_file(b"remove_id", 0o200, Arc::new(RemoveId(drv)));
}

fn modalias(p: &PciDevice) -> String {
    let h = &p.header;
    format!(
        "pci:v{:08X}d{:08X}sv{:08X}sd{:08X}bc{:02X}sc{:02X}i{:02X}",
        h.vendor_id,
        h.device_id,
        h.subsystem_vendor_id,
        h.subsystem_id,
        h.class_code,
        h.subclass,
        h.prog_if
    )
}

/// Linux pci_uevent
fn pci_uevent(dev: &Device, env: &mut Vec<Vec<u8>>) {
    let Some(p) = pci_dev(dev) else { return };
    let h = &p.header;
    let mut kv = |s: String| env.push(s.into_bytes());
    kv(format!("PCI_CLASS={:X}", p.class24()));
    kv(format!("PCI_ID={:04X}:{:04X}", h.vendor_id, h.device_id));
    kv(format!(
        "PCI_SUBSYS_ID={:04X}:{:04X}",
        h.subsystem_vendor_id, h.subsystem_id
    ));
    kv(format!("PCI_SLOT_NAME={}", dev.name()));
    kv(format!("MODALIAS={}", modalias(p)));
}

/// config: configuration space (Linux pci_read_config/pci_write_config;
/// beyond the first 64 bytes only for CAP_SYS_ADMIN)
struct ConfigAttr(Arc<PciDev>);

/// Size of conventional configuration space
const CFG_SIZE: u64 = 256;

/// The next access at `off` with `left` bytes: dword, word or byte as
/// alignment allows (Linux pci_read_config's split)
fn chunk(off: u64, left: usize) -> usize {
    if off & 3 == 0 && left >= 4 {
        4
    } else if off & 1 == 0 && left >= 2 {
        2
    } else {
        1
    }
}

impl BinAttr for ConfigAttr {
    fn size(&self) -> u64 {
        CFG_SIZE
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, KernelError> {
        let lim = if crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            CFG_SIZE
        } else {
            64
        };
        let p = &self.0.pci;
        let end = (off + buf.len() as u64).min(lim.max(off));
        let mut o = off;
        while o < end {
            let n = chunk(o, (end - o) as usize);
            let i = (o - off) as usize;
            let r = o as u8;
            match n {
                4 => buf[i..i + 4].copy_from_slice(&p.cfg_read32(r).to_le_bytes()),
                2 => buf[i..i + 2].copy_from_slice(&p.cfg_read16(r).to_le_bytes()),
                _ => buf[i] = p.cfg_read8(r),
            }
            o += n as u64;
        }
        Ok((end - off) as usize)
    }

    fn write(&self, off: u64, data: &[u8]) -> Result<usize, KernelError> {
        if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            return Err(KernelError::NotPermitted);
        }
        let p = &self.0.pci;
        let mut o = off;
        let end = off + data.len() as u64;
        while o < end {
            let n = chunk(o, (end - o) as usize);
            let d = &data[(o - off) as usize..];
            let r = o as u8;
            match n {
                4 => p.cfg_write32(r, u32::from_le_bytes([d[0], d[1], d[2], d[3]])),
                2 => p.cfg_write16(r, u16::from_le_bytes([d[0], d[1]])),
                _ => p.cfg_write8(r, d[0]),
            }
            o += n as u64;
        }
        Ok(data.len())
    }
}

/// driver_override (Linux driver_override_show/store)
struct DriverOverride(Arc<PciDev>);

impl Attr for DriverOverride {
    fn show(&self, out: &mut SysBuf) -> Result<(), KernelError> {
        let o = self.0.driver_override.lock();
        let _ = writeln!(out, "{}", o.as_deref().unwrap_or("(null)"));
        Ok(())
    }

    /// Linux driver_set_override: an empty write (or newline) clears it
    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let v = crate::base::bus::trim(data);
        let v = core::str::from_utf8(v).map_err(|_| KernelError::InvalidArgument)?;
        *self.0.driver_override.lock() = (!v.is_empty()).then(|| v.into());
        Ok(data.len())
    }
}

/// The function's attributes (Linux pci_dev_groups)
fn pci_attrs(dev: &Arc<Device>) -> Result<(), KernelError> {
    let d = dev.data_arc::<PciDev>().ok_or(KernelError::NoDevice)?;
    let h = d.pci.header.clone();
    let text: [(&[u8], String); 6] = [
        (b"vendor", format!("0x{:04x}\n", h.vendor_id)),
        (b"device", format!("0x{:04x}\n", h.device_id)),
        (
            b"subsystem_vendor",
            format!("0x{:04x}\n", h.subsystem_vendor_id),
        ),
        (b"subsystem_device", format!("0x{:04x}\n", h.subsystem_id)),
        (b"class", format!("0x{:06x}\n", d.pci.class24())),
        (b"revision", format!("0x{:02x}\n", h.revision_id)),
    ];
    for (name, v) in text {
        dev.create_file(name, 0o444, kernfs::show(move |o| o.bytes(v.as_bytes())))?;
    }
    let irq = d.pci.intx_irq().unwrap_or(0);
    dev.create_file(
        b"irq",
        0o444,
        kernfs::show(move |o| {
            let _ = writeln!(o, "{}", irq);
        }),
    )?;
    let alias = modalias(&d.pci);
    dev.create_file(
        b"modalias",
        0o444,
        kernfs::show(move |o| {
            let _ = writeln!(o, "{}", alias);
        }),
    )?;
    dev.create_file(
        b"driver_override",
        0o644,
        Arc::new(DriverOverride(d.clone())),
    )?;
    dev.kobj()
        .create_bin(b"config", 0o644, Arc::new(ConfigAttr(d)))?;
    Ok(())
}

/// /sys/devices/pci0000:00 (the host bridge's device)
static ROOT: Once<Arc<Device>> = Once::new();

/// Linux pci_driver_init: the bus, then the root bus device
pub fn pci_bus_init() {
    PCI_BUS.register();
    ROOT.call_once(|| device_create(DeviceInfo::named("pci0000:00")).expect("pci0000:00"));
}

/// Register a scanned function (Linux pci_device_add + pci_bus_add_device)
pub fn pci_device_add(pci: PciDevice) -> Result<Arc<Device>, KernelError> {
    let name = format!("0000:{:02x}:{:02x}.{:x}", pci.bus, pci.device, pci.function);
    let root = ROOT.get().ok_or(KernelError::NoDevice)?;
    let data = Arc::new(PciDev {
        pci,
        driver_override: Mutex::new(None),
    });
    device_create(DeviceInfo {
        parent: Some(root),
        bus: Some(&PCI_BUS),
        data: Some(data),
        attrs: Some(pci_attrs),
        ..DeviceInfo::named(&name)
    })
}
