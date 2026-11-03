//! Device model (Linux drivers/base): devices, classes, and their
//! sysfs presence under /sys/{devices,class,dev}

pub mod bus;
pub mod class;
pub mod core;
pub mod cpu;
pub mod dd;
pub mod driver;
pub mod node;
pub mod platform;
pub mod uevent;

pub use bus::BusType;
pub use class::Class;
pub use core::{DevNode, Device, DeviceInfo, device_create, device_shutdown};
pub use driver::{Bound, Driver, Ids};

/// Linux driver_init: the core directories, before any device
/// registers (devtmpfs is initialized just before, by the caller)
pub fn driver_init() {
    core::devices_init();
    bus::buses_init();
    class::classes_init();
    crate::fs::sysfs::top_dir(b"firmware");
    crate::fs::sysfs::top_dir(b"hypervisor");
    platform::platform_bus_init();
    cpu::cpu_dev_init();
    driver::module_init();
}

/// Linux topology_init (a subsys initcall): the CPU devices, then the
/// NUMA nodes linked to them
pub fn topology_init() {
    cpu::register_cpus();
    node::node_dev_init();
}
