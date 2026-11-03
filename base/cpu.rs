//! CPUs (Linux drivers/base/cpu.c): the cpu subsystem below
//! /sys/devices/system/cpu, its online/possible/present/offline/
//! kernel_max masks and a cpuN device per possible CPU.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Once;

use super::bus::{BusType, system_dir};
use super::{Device, DeviceInfo, Driver, device_create};
use crate::fs::kernfs;
use crate::util::cpumask::{CpuSet, NR_CPUS};

/// The cpu subsystem (Linux cpu_subsys; no drivers bind)
pub static CPU_BUS: BusType = BusType::new("cpu", no_match, None);

fn no_match(_: &Device, _: &'static Driver) -> bool {
    false
}

/// /sys/devices/system/cpu
static ROOT: Once<Arc<Device>> = Once::new();

/// cpuN devices, by CPU number
static CPUS: Once<Vec<Arc<Device>>> = Once::new();

/// The possible CPUs (nr_cpu_ids; no hotplug, so present and possible
/// are the same)
fn possible() -> CpuSet {
    CpuSet::first(crate::cpu::nr_cpu_ids())
}

/// A subsystem root's attribute: name and value
pub type MaskAttr = (&'static [u8], fn() -> String);

fn list(s: CpuSet) -> String {
    format!("{}\n", s.fmt_list())
}

/// Linux cpu_dev_init: the subsystem and its root's masks
pub fn cpu_dev_init() {
    CPU_BUS.register();
    let root = device_create(DeviceInfo {
        dir: Some(system_dir().clone()),
        ..DeviceInfo::named("cpu")
    })
    .expect("/sys/devices/system/cpu");
    let attrs: [MaskAttr; 5] = [
        (b"online", || list(crate::smp::active_cpus())),
        (b"possible", || list(possible())),
        (b"present", || list(possible())),
        (b"offline", || {
            let p = possible();
            let mut off = CpuSet::default();
            let on = crate::smp::active_cpus();
            for c in p.iter().filter(|&c| !on.test(c)) {
                off.set(c);
            }
            list(off)
        }),
        (b"kernel_max", || format!("{}\n", NR_CPUS - 1)),
    ];
    for (name, f) in attrs {
        let _ = root.create_file(name, 0o444, kernfs::show(move |o| o.bytes(f().as_bytes())));
    }
    ROOT.call_once(|| root);
}

/// Linux topology_init -> register_cpu: cpuN for every possible CPU
pub fn register_cpus() {
    let Some(root) = ROOT.get() else { return };
    let devs = possible()
        .iter()
        .filter_map(|c| {
            device_create(DeviceInfo {
                parent: Some(root),
                bus: Some(&CPU_BUS),
                ..DeviceInfo::named(&format!("cpu{}", c))
            })
            .ok()
        })
        .collect();
    CPUS.call_once(|| devs);
}

/// The device of CPU `cpu`
pub fn get_cpu_device(cpu: u32) -> Option<&'static Arc<Device>> {
    CPUS.get()?.get(cpu as usize)
}
