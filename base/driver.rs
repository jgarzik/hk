//! Drivers (Linux drivers/base/driver.c, bus.c driver half, module.c):
//! /sys/bus/<bus>/drivers/<drv>/{bind,unbind,uevent,module}, and the
//! built-in module's /sys/module/<mod>/drivers/<bus>:<drv> link (when
//! the bus names the module).

use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use core::any::Any;

use spin::Once;

use super::bus::{BusType, trim};
use super::core::Device;
use crate::fs::KernelError;
use crate::fs::kernfs::{Attr, KNode, SysBuf};
use crate::fs::sysfs;
use crate::util::kalloc::arc_nofail;

/// A driver's id table, of its bus's type (`platform::Names`,
/// `pci::PciIds`, ...); the bus's match downcasts it
pub type Ids = &'static (dyn Any + Send + Sync);

/// A driver's per-device state, kept while bound (Linux drvdata plus
/// the driver's remove/shutdown callbacks)
pub trait Bound: Send + Sync {
    fn as_any(&self) -> &dyn Any;

    /// Quiesce the device before power-off (Linux ->shutdown)
    fn shutdown(&self) {}

    /// Release the device: the driver is unbound (Linux ->remove)
    fn remove(&self) {}
}

pub type ProbeFn = fn(&Arc<Device>) -> Result<Box<dyn Bound>, KernelError>;

/// A driver (Linux struct device_driver)
pub struct Driver {
    pub name: &'static str,
    pub bus: &'static BusType,
    /// Built-in module name, for buses that pass KBUILD_MODNAME (PCI,
    /// USB; platform and virtio drivers have none)
    pub mod_name: Option<&'static str>,
    pub ids: Ids,
    pub probe: ProbeFn,
    dir: Once<Arc<KNode>>,
}

static MODULE_DIR: Once<Arc<KNode>> = Once::new();

/// Linux param_sysfs_init: /sys/module
pub fn module_init() {
    MODULE_DIR.call_once(|| sysfs::top_dir(b"module"));
}

/// bind: attach the named device (Linux bind_store)
struct BindAttr(&'static Driver);

impl Attr for BindAttr {
    fn show(&self, _out: &mut SysBuf) -> Result<(), KernelError> {
        Err(KernelError::Io)
    }

    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let drv = self.0;
        let dev = drv
            .bus
            .find_device(trim(data))
            .ok_or(KernelError::NoDevice)?;
        if !(drv.bus.matches)(&dev, drv) {
            return Err(KernelError::NoDevice);
        }
        super::dd::driver_probe_device(drv, &dev)?;
        Ok(data.len())
    }
}

/// unbind: detach the named device (Linux unbind_store)
struct UnbindAttr(&'static Driver);

impl Attr for UnbindAttr {
    fn show(&self, _out: &mut SysBuf) -> Result<(), KernelError> {
        Err(KernelError::Io)
    }

    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let drv = self.0;
        let dev = drv
            .bus
            .find_device(trim(data))
            .ok_or(KernelError::NoDevice)?;
        if !dev.driver().is_some_and(|d| core::ptr::eq(d, drv)) {
            return Err(KernelError::NoDevice);
        }
        super::dd::device_release_driver(&dev);
        Ok(data.len())
    }
}

/// A driver's uevent file: synthetic events of the driver object
/// (Linux driver_uevent_store; SUBSYSTEM=drivers)
struct DriverUevent(&'static Driver);

impl Attr for DriverUevent {
    fn show(&self, _out: &mut SysBuf) -> Result<(), KernelError> {
        Err(KernelError::Io)
    }

    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let path = self.0.dir().path();
        super::uevent::synth_kobj(&path, b"drivers", data)?;
        Ok(data.len())
    }
}

impl Driver {
    pub const fn new(
        name: &'static str,
        bus: &'static BusType,
        mod_name: Option<&'static str>,
        ids: Ids,
        probe: ProbeFn,
    ) -> Self {
        Self {
            name,
            bus,
            mod_name,
            ids,
            probe,
            dir: Once::new(),
        }
    }

    /// /sys/bus/<bus>/drivers/<name>
    pub fn dir(&self) -> &Arc<KNode> {
        self.dir.get().expect("driver registered")
    }

    /// Linux driver_register: the driver's directory and module link,
    /// then every matching unbound device of the bus is probed
    pub fn register(&'static self) {
        let made = self.dir.call_once(|| {
            let d = self
                .bus
                .drivers_dir()
                .create_dir(self.name.as_bytes(), 0o755)
                .expect("driver directory");
            let _ = d.create_file(b"uevent", 0o200, arc_nofail(DriverUevent(self)));
            let _ = d.create_file(b"bind", 0o200, arc_nofail(BindAttr(self)));
            let _ = d.create_file(b"unbind", 0o200, arc_nofail(UnbindAttr(self)));
            if let Some(f) = self.bus.drv_attrs {
                f(self, &d);
            }
            d
        });
        self.add_module_links(made);
        self.bus.add_driver(self);
        if self.bus.autoprobe() {
            super::dd::driver_attach(self);
        }
    }

    /// Linux module_add_driver for a built-in driver
    fn add_module_links(&self, dir: &Arc<KNode>) {
        let (Some(mods), Some(name)) = (MODULE_DIR.get(), self.mod_name) else {
            return;
        };
        let m = match mods.find(name.as_bytes()) {
            Some(m) => m,
            None => match mods.create_dir(name.as_bytes(), 0o755) {
                Ok(m) => m,
                Err(_) => return,
            },
        };
        let _ = dir.create_link(b"module", &m);
        let drivers = match m.find(b"drivers") {
            Some(d) => d,
            None => match m.create_dir(b"drivers", 0o755) {
                Ok(d) => d,
                Err(_) => return,
            },
        };
        let link = format!("{}:{}", self.bus.name, self.name);
        let _ = drivers.create_link(link.as_bytes(), dir);
    }
}
