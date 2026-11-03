//! Device model (Linux drivers/base): devices, classes, and their
//! sysfs presence under /sys/{devices,class,dev}

pub mod class;
pub mod core;

pub use class::Class;
pub use core::{DevNode, Device, DeviceInfo, device_create};

/// Linux driver_init: the core directories, before any device
/// registers (devtmpfs is initialized just before, by the caller)
pub fn driver_init() {
    core::devices_init();
    class::classes_init();
    crate::fs::sysfs::top_dir(b"firmware");
    crate::fs::sysfs::top_dir(b"hypervisor");
}
