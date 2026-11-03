//! Driver binding (Linux drivers/base/dd.c)
//!
//! Probing runs under the device lock: the `driver` link and the
//! driver's link to the device exist during probe (Linux
//! driver_sysfs_add) and go if it fails; a successful bind sends the
//! "bind" uevent, a release "unbind".

use alloc::sync::Arc;

use super::core::Device;
use super::driver::Driver;
use super::uevent::{Action, uevent};
use crate::fs::KernelError;

/// Bind `dev` to `drv` (Linux driver_probe_device + really_probe):
/// EBUSY if bound already; the probe's error otherwise
pub fn driver_probe_device(drv: &'static Driver, dev: &Arc<Device>) -> Result<(), KernelError> {
    let _g = dev.lock.lock();
    if *_g {
        return Err(KernelError::NoDevice);
    }
    if dev.driver().is_some() {
        return Err(KernelError::Busy);
    }
    let name = dev.name().as_bytes();
    drv.dir().create_link(name, dev.kobj())?;
    if let Err(e) = dev.kobj().create_link(b"driver", drv.dir()) {
        drv.dir().remove_child(name);
        return Err(e);
    }
    dev.set_driver(Some(drv));
    match (drv.probe)(dev) {
        Ok(b) => {
            dev.set_bound(Some(b.into()));
            drop(_g);
            uevent(dev, Action::Bind);
            Ok(())
        }
        Err(e) => {
            dev.set_driver(None);
            dev.kobj().remove_child(b"driver");
            drv.dir().remove_child(name);
            crate::printkln!("{} {}: probe failed: {:?}", drv.name, dev.name(), e);
            Err(e)
        }
    }
}

/// Try every driver of the device's bus (Linux device_attach): true if
/// one bound it
pub fn device_attach(dev: &Arc<Device>) -> bool {
    let Some(bus) = dev.bus else { return false };
    if dev.driver().is_some() {
        return true;
    }
    for drv in bus.drivers() {
        if (bus.matches)(dev, drv) && driver_probe_device(drv, dev).is_ok() {
            return true;
        }
    }
    false
}

/// Probe every unbound device of the driver's bus it matches (Linux
/// driver_attach)
pub fn driver_attach(drv: &'static Driver) {
    for dev in drv.bus.devices() {
        if dev.driver().is_none() && (drv.bus.matches)(&dev, drv) {
            let _ = driver_probe_device(drv, &dev);
        }
    }
}

/// Unbind `dev` from its driver (Linux device_release_driver): the
/// driver's state is dropped, links go, "unbind" is sent
pub fn device_release_driver(dev: &Arc<Device>) {
    let g = dev.lock.lock();
    let Some(drv) = dev.driver() else { return };
    if let Some(b) = dev.set_bound(None) {
        b.remove();
    }
    dev.set_driver(None);
    dev.kobj().remove_child(b"driver");
    drv.dir().remove_child(dev.name().as_bytes());
    drop(g);
    uevent(dev, Action::Unbind);
}
