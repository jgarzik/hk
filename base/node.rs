//! NUMA nodes (Linux drivers/base/node.c): the node subsystem below
//! /sys/devices/system/node, its possible/online/has_cpu/
//! has_normal_memory masks and a nodeN device per online node with its
//! cpumap, cpulist and distance, linked with its CPUs both ways.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::Write;

use super::bus::{BusType, system_dir};
use super::{Device, DeviceInfo, Driver, device_create};
use crate::fs::kernfs;
use crate::mm::numa::{MAX_NUMA_NODES, NUMA_TOPOLOGY};
use crate::util::cpumask::CpuSet;

/// The node subsystem (Linux node_subsys; no drivers bind)
pub static NODE_BUS: BusType = BusType::new("node", no_match, None);

fn no_match(_: &Device, _: &'static Driver) -> bool {
    false
}

/// Nodes as a list ("0-1"), from a mask of node ids
fn node_list(mask: u64) -> String {
    let mut s = CpuSet::default();
    for n in 0..MAX_NUMA_NODES as u32 {
        if mask & (1 << n) != 0 {
            s.set(n);
        }
    }
    format!("{}\n", s.fmt_list())
}

fn online() -> u64 {
    NUMA_TOPOLOGY.lock().online_mask()
}

/// Nodes with CPUs (Linux N_CPU)
fn with_cpus() -> u64 {
    let t = NUMA_TOPOLOGY.lock();
    (0..MAX_NUMA_NODES as u32)
        .filter(|&n| t.get_node(n).is_some_and(|nd| !nd.cpus.is_empty()))
        .fold(0, |m, n| m | (1 << n))
}

/// Linux node_dev_init: the subsystem, its masks, then each online node
/// and its CPUs' links
pub fn node_dev_init() {
    NODE_BUS.register();
    let Ok(root) = device_create(DeviceInfo {
        dir: Some(system_dir().clone()),
        ..DeviceInfo::named("node")
    }) else {
        return;
    };
    let attrs: [super::cpu::MaskAttr; 5] = [
        (b"possible", || node_list(online())),
        (b"online", || node_list(online())),
        (b"has_cpu", || node_list(with_cpus())),
        (b"has_memory", || node_list(online())),
        (b"has_normal_memory", || node_list(online())),
    ];
    for (name, f) in attrs {
        let _ = root.create_file(name, 0o444, kernfs::show(move |o| o.bytes(f().as_bytes())));
    }
    let mask = online();
    for n in (0..MAX_NUMA_NODES as u32).filter(|&n| mask & (1 << n) != 0) {
        register_node(&root, n);
    }
}

/// The CPUs of node `n`
fn node_cpus(n: u32) -> CpuSet {
    NUMA_TOPOLOGY
        .lock()
        .get_node(n)
        .map_or(CpuSet::default(), |nd| nd.cpus)
}

/// Linux register_node + register_cpu_under_node
fn register_node(root: &Arc<Device>, n: u32) {
    let Ok(dev) = device_create(DeviceInfo {
        parent: Some(root),
        bus: Some(&NODE_BUS),
        ..DeviceInfo::named(&format!("node{}", n))
    }) else {
        return;
    };
    let _ = dev.create_file(
        b"cpumap",
        0o444,
        kernfs::show(move |o| {
            let nbits = crate::cpu::nr_cpu_ids();
            let _ = writeln!(o, "{}", node_cpus(n).fmt_hex(nbits));
        }),
    );
    let _ = dev.create_file(
        b"cpulist",
        0o444,
        kernfs::show(move |o| {
            let _ = writeln!(o, "{}", node_cpus(n).fmt_list());
        }),
    );
    let _ = dev.create_file(
        b"distance",
        0o444,
        kernfs::show(move |o| {
            // Copied out first: nothing allocates under the IrqSpinlock
            let mut d = [0u8; MAX_NUMA_NODES];
            let mut k = 0;
            {
                let t = NUMA_TOPOLOGY.lock();
                let mask = t.online_mask();
                for to in (0..MAX_NUMA_NODES as u32).filter(|&m| mask & (1 << m) != 0) {
                    d[k] = t.node_distance(n, to);
                    k += 1;
                }
            }
            for (i, v) in d[..k].iter().enumerate() {
                let _ = write!(o, "{}{}", if i == 0 { "" } else { " " }, v);
            }
            o.bytes(b"\n");
        }),
    );
    for c in node_cpus(n).iter() {
        if let Some(cd) = super::cpu::get_cpu_device(c) {
            let _ = dev.kobj().create_link(cd.name().as_bytes(), cd.kobj());
            let _ = cd.kobj().create_link(dev.name().as_bytes(), dev.kobj());
        }
    }
}
