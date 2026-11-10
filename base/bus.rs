//! Buses (Linux drivers/base/bus.c): /sys/bus/<bus>/{devices,drivers,
//! drivers_autoprobe,drivers_probe,uevent}; a device added to a bus is
//! matched against the bus's drivers, a registered driver against its
//! unbound devices (Linux bus_probe_device, driver_attach).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

use spin::Once;

use super::core::Device;
use super::driver::Driver;
use crate::fs::KernelError;
use crate::fs::kernfs::sysfs;
use crate::fs::kernfs::{Attr, KNode, SysBuf};
use crate::sync::spin::Mutex;
use crate::util::kalloc::arc_nofail;

static BUS_DIR: Once<Arc<KNode>> = Once::new();
static SYSTEM_DIR: Once<Arc<KNode>> = Once::new();

/// Linux buses_init: /sys/bus, /sys/devices/system
pub fn buses_init() {
    BUS_DIR.call_once(|| sysfs::top_dir(b"bus"));
    SYSTEM_DIR.call_once(|| {
        sysfs::top_dir(b"devices")
            .create_dir(b"system", 0o755)
            .expect("/sys/devices/system")
    });
}

/// /sys/devices/system (Linux system_kset)
pub fn system_dir() -> &'static Arc<KNode> {
    SYSTEM_DIR.get().expect("buses_init")
}

/// Adds a bus's variables to a device's uevent environment
pub type UeventFn = fn(&Device, &mut Vec<Vec<u8>>);

/// Adds a bus's files to a driver's directory (Linux bus->drv_groups)
pub type DrvAttrsFn = fn(&'static Driver, &Arc<KNode>);

/// Hex numbers of a sysfs write, as sscanf("%x %x ...") reads them:
/// at most `max`, stopping at the first that does not parse
pub fn hex_fields(data: &[u8], max: usize) -> Vec<u32> {
    let mut out = Vec::new();
    for w in data
        .split(|c| c.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
    {
        if out.len() == max {
            break;
        }
        let w = w
            .strip_prefix(b"0x")
            .or_else(|| w.strip_prefix(b"0X"))
            .unwrap_or(w);
        let Ok(t) = core::str::from_utf8(w) else {
            break;
        };
        let Ok(v) = u32::from_str_radix(t, 16) else {
            break;
        };
        out.push(v);
    }
    out
}

/// A bus's registered state (Linux struct subsys_private)
struct BusPriv {
    dir: Arc<KNode>,
    devices_dir: Arc<KNode>,
    drivers_dir: Arc<KNode>,
}

/// A bus type (Linux struct bus_type)
pub struct BusType {
    pub name: &'static str,
    /// Does `drv` handle `dev` (Linux bus->match)
    pub matches: fn(&Device, &'static Driver) -> bool,
    /// Bus variables of a device's uevents (Linux bus->uevent)
    pub uevent: Option<UeventFn>,
    /// Bus files of each driver directory (Linux bus->drv_groups)
    pub drv_attrs: Option<DrvAttrsFn>,
    p: Once<BusPriv>,
    /// Probe new devices and drivers (drivers_autoprobe)
    autoprobe: AtomicBool,
    /// Devices in registration order (Linux klist_devices)
    devices: Mutex<Vec<Arc<Device>>>,
    /// Registered drivers (Linux klist_drivers)
    drivers: Mutex<Vec<&'static Driver>>,
}

/// drivers_autoprobe (Linux bus_attr_drivers_autoprobe)
struct Autoprobe(&'static BusType);

impl Attr for Autoprobe {
    fn show(&self, out: &mut SysBuf) -> Result<(), KernelError> {
        let _ = writeln!(
            out,
            "{}",
            u8::from(self.0.autoprobe.load(Ordering::Acquire))
        );
        Ok(())
    }

    /// Linux drivers_autoprobe_store: "0" disables, anything else enables
    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let on = data.first() != Some(&b'0');
        self.0.autoprobe.store(on, Ordering::Release);
        Ok(data.len())
    }
}

/// drivers_probe: attach the named device (Linux bind_store's sibling)
struct DriversProbe(&'static BusType);

impl Attr for DriversProbe {
    fn show(&self, _out: &mut SysBuf) -> Result<(), KernelError> {
        Err(KernelError::Io)
    }

    /// Linux drivers_probe_store: ENODEV if no such device or no driver
    /// takes it
    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let name = trim(data);
        let dev = self.0.find_device(name).ok_or(KernelError::NoDevice)?;
        if !super::dd::device_attach(&dev) {
            return Err(KernelError::NoDevice);
        }
        Ok(data.len())
    }
}

/// The bus's own uevent file (Linux bus_uevent_store; write-only)
struct BusUevent(&'static BusType);

impl Attr for BusUevent {
    fn show(&self, _out: &mut SysBuf) -> Result<(), KernelError> {
        Err(KernelError::Io)
    }

    /// Linux bus_uevent_store: a synthetic event of the bus object
    /// (SUBSYSTEM=bus)
    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        super::uevent::synth_kobj(&self.0.dir().path(), b"bus", data)?;
        Ok(data.len())
    }
}

/// A sysfs-written name: one trailing newline dropped
pub fn trim(data: &[u8]) -> &[u8] {
    data.strip_suffix(b"\n").unwrap_or(data)
}

impl BusType {
    pub const fn new(
        name: &'static str,
        matches: fn(&Device, &'static Driver) -> bool,
        uevent: Option<UeventFn>,
    ) -> Self {
        Self::with_drv_attrs(name, matches, uevent, None)
    }

    /// A bus whose driver directories get `drv_attrs`' files
    pub const fn with_drv_attrs(
        name: &'static str,
        matches: fn(&Device, &'static Driver) -> bool,
        uevent: Option<UeventFn>,
        drv_attrs: Option<DrvAttrsFn>,
    ) -> Self {
        Self {
            name,
            matches,
            uevent,
            drv_attrs,
            p: Once::new(),
            autoprobe: AtomicBool::new(true),
            devices: Mutex::new(Vec::new()),
            drivers: Mutex::new(Vec::new()),
        }
    }

    fn p(&self) -> &BusPriv {
        self.p.get().expect("bus registered")
    }

    /// /sys/bus/<name> (the target of `subsystem` links)
    pub fn dir(&self) -> &Arc<KNode> {
        &self.p().dir
    }

    pub(super) fn drivers_dir(&self) -> &Arc<KNode> {
        &self.p().drivers_dir
    }

    /// Linux bus_register
    pub fn register(&'static self) {
        self.p.call_once(|| {
            let root = BUS_DIR.get().expect("buses_init");
            let dir = root
                .create_dir(self.name.as_bytes(), 0o755)
                .expect("bus directory");
            let _ = dir.create_file(b"uevent", 0o200, arc_nofail(BusUevent(self)));
            let devices_dir = dir.create_dir(b"devices", 0o755).expect("bus devices");
            let drivers_dir = dir.create_dir(b"drivers", 0o755).expect("bus drivers");
            let _ = dir.create_file(b"drivers_probe", 0o200, arc_nofail(DriversProbe(self)));
            let _ = dir.create_file(b"drivers_autoprobe", 0o644, arc_nofail(Autoprobe(self)));
            BusPriv {
                dir,
                devices_dir,
                drivers_dir,
            }
        });
    }

    pub fn autoprobe(&self) -> bool {
        self.autoprobe.load(Ordering::Acquire)
    }

    /// Linux bus_add_device: links, then the bus list
    pub(super) fn add_device(&self, dev: &Arc<Device>) -> Result<(), KernelError> {
        let p = self.p();
        dev.kobj().create_link(b"subsystem", &p.dir)?;
        p.devices_dir
            .create_link(dev.name().as_bytes(), dev.kobj())?;
        self.devices.lock().push(dev.clone());
        Ok(())
    }

    /// Linux bus_remove_device
    pub(super) fn remove_device(&self, dev: &Device) {
        self.p().devices_dir.remove_child(dev.name().as_bytes());
        self.devices
            .lock()
            .retain(|d| !core::ptr::eq(Arc::as_ptr(d), dev));
    }

    pub(super) fn add_driver(&self, drv: &'static Driver) {
        self.drivers.lock().push(drv);
    }

    pub fn devices(&self) -> Vec<Arc<Device>> {
        self.devices.lock().clone()
    }

    pub fn drivers(&self) -> Vec<&'static Driver> {
        self.drivers.lock().clone()
    }

    pub fn find_device(&self, name: &[u8]) -> Option<Arc<Device>> {
        self.devices
            .lock()
            .iter()
            .find(|d| d.name().as_bytes() == name)
            .cloned()
    }
}
