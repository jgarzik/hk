//! Device Tree parsing for aarch64 hardware discovery
//!
//! This module extracts hardware configuration from the Device Tree Blob (DTB)
//! passed by the bootloader. It produces an AcpiInfo structure compatible with
//! the architecture-independent kernel code.
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{AcpiInfo, CpuInfo, phys_to_virt};
use crate::dt::DeviceTree;

/// Physical address of the boot DTB (0: none); set once by `set_boot`
static DTB_PHYS: AtomicU64 = AtomicU64::new(0);

/// Record the boot DTB
///
/// # Safety
/// `pa` is 0 or the physical address of readable RAM (through the
/// direct map), at least 8 bytes, holding the bootloader's FDT if its
/// magic matches; it stays reserved for the kernel's life.
pub unsafe fn set_boot(pa: u64) {
    DTB_PHYS.store(pa, Ordering::Relaxed);
}

/// Physical address of the boot DTB (0: none)
pub fn boot_phys() -> u64 {
    DTB_PHYS.load(Ordering::Relaxed)
}

/// Parse DTB and extract hardware configuration
pub fn parse_dtb() -> Option<AcpiInfo> {
    let dtb_data = blob()?;

    let dt = DeviceTree::from_fdt(dtb_data).ok()?;

    // Extract GIC distributor base address
    let gic_base = extract_gic_base(&dt)?;

    // PCI INTx routing (host bridge interrupt-map)
    super::pci_irq::init_from_dt(&dt);

    // Extract CPU list
    let cpus = extract_cpus(&dt);

    // If no CPUs found, return None (invalid DTB)
    if cpus.is_empty() {
        return None;
    }

    Some(AcpiInfo {
        interrupt_controller_base: gic_base,
        cpus,
        bsp_cpu_id: 0,    // Will be set later from MPIDR
        power_info: None, // ARM uses PSCI, not ACPI power ports
    })
}

/// Extract GIC distributor base address from DTB
fn extract_gic_base(dt: &DeviceTree<'_>) -> Option<u64> {
    // Look for GICv3: compatible = "arm,gic-v3"
    let gic_nodes = dt.find_compatible("arm,gic-v3");
    if let Some(gic) = gic_nodes.first()
        && let Some((Some(addr), _)) = gic.reg()
    {
        return Some(addr);
    }

    // Fallback: Look for GICv2 variants
    for compat in &["arm,gic-400", "arm,cortex-a15-gic", "arm,cortex-a9-gic"] {
        let nodes = dt.find_compatible(compat);
        if let Some(gic) = nodes.first()
            && let Some((Some(addr), _)) = gic.reg()
        {
            return Some(addr);
        }
    }

    None
}

/// Extract CPU list from DTB /cpus node
fn extract_cpus(dt: &DeviceTree<'_>) -> Vec<CpuInfo> {
    let mut cpus = Vec::new();

    let Some(cpus_node) = dt.find_node("/cpus") else {
        return cpus;
    };

    for cpu_child in cpus_node.children() {
        // Check device_type property (should be "cpu")
        let is_cpu = cpu_child
            .property("device_type")
            .and_then(|p| p.as_str())
            .map(|s| s == "cpu")
            .unwrap_or(false);

        if !is_cpu {
            // Also check if node name starts with "cpu@"
            let name = cpu_child.name();
            if !name.starts_with("cpu@") && name != "cpu" {
                continue;
            }
        }

        // Get CPU ID from reg property
        let cpu_id: u32 = if let Some(reg_prop) = cpu_child.property("reg") {
            reg_prop.as_u32().unwrap_or(0)
        } else {
            continue; // Skip CPUs without reg property
        };

        // Check if CPU is enabled (status != "disabled")
        let enabled = cpu_child
            .property("status")
            .and_then(|s| s.as_str())
            .map(|s| s != "disabled")
            .unwrap_or(true);

        cpus.push(CpuInfo {
            hw_cpu_id: cpu_id,
            enabled,
            is_bsp: cpu_id == 0, // CPU 0 is BSP
        });
    }

    // Sort by CPU ID for consistency
    cpus.sort_by_key(|c| c.hw_cpu_id);

    cpus
}

/// Total size of the boot FDT blob (header `totalsize`), if
/// the magic matches; reads only the header, so it is usable before the
/// heap exists
pub fn total_size() -> Option<usize> {
    blob().map(|b| b.len())
}

/// The boot FDT blob (read through the direct map), if the header magic
/// matches and the size is sane (1KB-16MB)
fn blob() -> Option<&'static [u8]> {
    let dtb = boot_phys();
    if dtb == 0 {
        return None;
    }
    let p = phys_to_virt(dtb).cast_const();
    // SAFETY: 8 readable bytes at the recorded address (`set_boot`)
    let h = unsafe { core::slice::from_raw_parts(p, 8) };
    if h[..4] != [0xd0, 0x0d, 0xfe, 0xed] {
        return None;
    }
    let size = u32::from_be_bytes([h[4], h[5], h[6], h[7]]) as usize;
    if !(1024..=16 * 1024 * 1024).contains(&size) {
        return None;
    }
    // SAFETY: an FDT (magic checked) of `size` bytes, reserved RAM
    // (`set_boot`)
    Some(unsafe { core::slice::from_raw_parts(p, size) })
}

/// Call `f(base, size)` for every RAM range of every /memory node
/// (each `reg` pair); false if the DTB has none
pub fn for_each_memory(mut f: impl FnMut(u64, u64)) -> bool {
    let Some(dt) = blob().and_then(|b| DeviceTree::from_fdt(b).ok()) else {
        return false;
    };
    let Some(root) = dt.find_node("/") else {
        return false;
    };
    let cells = root.cells();
    let mut any = false;
    let disabled =
        |c: &crate::dt::Node<'_>| c.property("status").and_then(|p| p.as_str()) == Some("disabled");
    for c in root.children() {
        if (c.name() == "memory" || c.name().starts_with("memory@")) && !disabled(&c) {
            for (base, size) in c.regs(cells).filter(|&(_, size)| size != 0) {
                f(base, size);
                any = true;
            }
        }
    }
    any
}

/// Call `f(base, size)` for every range the firmware keeps for itself:
/// the FDT memory reservation block and each /reserved-memory child
/// (Linux early_init_fdt_scan_reserved_mem; `no-map` ranges are only
/// reserved, they stay in the linear map)
pub fn for_each_firmware_reserved(mut f: impl FnMut(u64, u64)) {
    let Some(b) = blob() else {
        return;
    };
    let be64 = |o: usize| u64::from_be_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
    let mut off = u32::from_be_bytes([b[16], b[17], b[18], b[19]]) as usize;
    while off + 16 <= b.len() {
        let (base, size) = (be64(off), be64(off + 8));
        if base == 0 && size == 0 {
            break;
        }
        f(base, size);
        off += 16;
    }
    let Ok(dt) = DeviceTree::from_fdt(b) else {
        return;
    };
    if let Some(rm) = dt.find_node("/reserved-memory") {
        let cells = rm.cells();
        for c in rm.children() {
            c.regs(cells).for_each(|(base, size)| f(base, size));
        }
    }
}

/// Initramfs location from DTB
#[derive(Debug, Clone, Copy)]
pub struct InitramfsInfo {
    /// Physical start address of initramfs
    pub start: u64,
    /// Physical end address of initramfs (exclusive)
    pub end: u64,
}

impl InitramfsInfo {
    /// Size of the initramfs in bytes
    pub fn size(&self) -> usize {
        (self.end - self.start) as usize
    }

    /// Get a slice pointing to the initramfs data
    ///
    /// # Safety
    /// The start/end addresses must be valid and mapped.
    pub unsafe fn as_slice(&self) -> &'static [u8] {
        unsafe { core::slice::from_raw_parts(phys_to_virt(self.start), self.size()) }
    }
}

/// Extract initramfs location from DTB /chosen node
///
/// Looks for `linux,initrd-start` and `linux,initrd-end` properties.
pub fn extract_initramfs() -> Option<InitramfsInfo> {
    let dtb_data = blob()?;

    let dt = DeviceTree::from_fdt(dtb_data).ok()?;

    // Find /chosen node
    let chosen = dt.find_node("/chosen")?;

    // Get initrd-start and initrd-end properties
    // These can be either 32-bit or 64-bit depending on the DTB
    let start = chosen.property("linux,initrd-start")?;
    let end = chosen.property("linux,initrd-end")?;

    // Try 64-bit first, fall back to 32-bit
    let start_addr = start.as_u64().or_else(|| start.as_u32().map(u64::from))?;
    let end_addr = end.as_u64().or_else(|| end.as_u32().map(u64::from))?;

    // Sanity check
    if end_addr <= start_addr || (end_addr - start_addr) > 1024 * 1024 * 1024 {
        // Empty or > 1GB - suspicious
        return None;
    }

    Some(InitramfsInfo {
        start: start_addr,
        end: end_addr,
    })
}

/// Extract kernel command line from DTB /chosen node bootargs property
///
/// Returns the command line string if found, or None if not present.
pub fn extract_bootargs() -> Option<&'static str> {
    let dtb_data = blob()?;

    let dt = DeviceTree::from_fdt(dtb_data).ok()?;

    // Find /chosen node
    let chosen = dt.find_node("/chosen")?;

    // Get bootargs property (kernel command line)
    let bootargs = chosen.property("bootargs")?;

    // Convert to string
    bootargs.as_str()
}

/// Extract simple-framebuffer info from DTB
///
/// Looks for nodes with compatible = "simple-framebuffer" and extracts
/// the framebuffer parameters (address, size, width, height, stride, format).
pub fn extract_simple_framebuffer() -> Option<crate::gfx::FramebufferInfo> {
    use crate::gfx::{FramebufferInfo, PixelFormat};

    let dtb_data = blob()?;

    let dt = DeviceTree::from_fdt(dtb_data).ok()?;

    // Find simple-framebuffer node
    let fb_nodes = dt.find_compatible("simple-framebuffer");
    let fb_node = fb_nodes.first()?;

    // Get reg property (address and size)
    let (Some(phys_addr), Some(size)) = fb_node.reg()? else {
        return None;
    };

    // Get width property
    let width = fb_node.property("width")?.as_u32()?;

    // Get height property
    let height = fb_node.property("height")?.as_u32()?;

    // Get stride property
    let stride = fb_node.property("stride")?.as_u32()?;

    // Get format property
    let format_str = fb_node.property("format")?.as_str()?;

    // Parse format string to PixelFormat
    let format = match format_str {
        "a8r8g8b8" | "x8r8g8b8" => PixelFormat::Xrgb8888,
        "a8b8g8r8" | "x8b8g8r8" => PixelFormat::Xbgr8888,
        "r8g8b8a8" => PixelFormat::Xrgb8888, // Close enough
        "b8g8r8a8" => PixelFormat::Xbgr8888, // Close enough
        "r5g6b5" => PixelFormat::Rgb565,
        _ => {
            // Unknown format - try to guess from stride
            if stride == width * 4 {
                PixelFormat::Xrgb8888
            } else if stride == width * 2 {
                PixelFormat::Rgb565
            } else {
                return None;
            }
        }
    };

    Some(FramebufferInfo::new(
        phys_addr, size, width, height, stride, format,
    ))
}

/// Initialize NUMA topology from device tree numa-node-id properties
///
/// Looks for `numa-node-id` properties on `/memory` and `/cpus/cpu@N` nodes.
/// True if NUMA topology was found, false if no NUMA info (caller should
/// use single-node fallback).
pub fn init_numa_topology() -> bool {
    use crate::mm::numa::{
        LOCAL_DISTANCE, MAX_NUMA_NODES, NUMA_TOPOLOGY, NumaNode, REMOTE_DISTANCE,
    };

    let Some(dtb_data) = blob() else {
        return false;
    };

    let Ok(dt) = DeviceTree::from_fdt(dtb_data) else {
        return false;
    };

    let mut found_numa = false;
    let mut topology = NUMA_TOPOLOGY.lock();

    // Extract memory nodes with numa-node-id
    // Memory nodes can be /memory or /memory@ADDR
    let Some(root) = dt.find_node("/") else {
        return false;
    };

    for child in root.children() {
        let name = child.name();
        if (name == "memory" || name.starts_with("memory@"))
            && let Some(numa_prop) = child.property("numa-node-id")
            && let Some(node_id) = numa_prop.as_u32()
        {
            let node_id = node_id as usize;
            if node_id < MAX_NUMA_NODES {
                found_numa = true;

                // Get memory region from reg property
                if let Some((Some(base), Some(size))) = child.reg() {
                    let start_pfn = base / 4096;
                    let end_pfn = (base + size) / 4096;
                    let pages = size / 4096;

                    // Get or create node
                    if topology.nodes[node_id].is_none() {
                        topology.nodes[node_id] = Some(NumaNode::new(node_id as u32));
                        topology.node_online_mask |= 1u64 << node_id;
                    }

                    if let Some(ref mut node) = topology.nodes[node_id] {
                        // Extend node's memory range
                        if node.start_pfn == 0 || start_pfn < node.start_pfn {
                            node.start_pfn = start_pfn;
                        }
                        if end_pfn > node.end_pfn {
                            node.end_pfn = end_pfn;
                        }
                        node.present_pages += pages;
                    }
                }
            }
        }
    }

    // Extract CPU NUMA affinity from /cpus/cpu@N nodes
    if let Some(cpus_node) = dt.find_node("/cpus") {
        for cpu_child in cpus_node.children() {
            let name = cpu_child.name();
            if !name.starts_with("cpu@") && name != "cpu" {
                continue;
            }

            // Check if this is actually a CPU node
            let is_cpu = cpu_child
                .property("device_type")
                .and_then(|p| p.as_str())
                .map(|s| s == "cpu")
                .unwrap_or(name.starts_with("cpu@") || name == "cpu");

            if !is_cpu {
                continue;
            }

            // Its MPIDR affinity, from reg (one or two cells)
            let hwid = match cpu_child.property("reg") {
                Some(reg) if reg.data().len() >= 8 => reg.as_u64().unwrap_or(0),
                Some(reg) => u64::from(reg.as_u32().unwrap_or(0)),
                None => continue,
            };
            let hwid = hwid & super::cpu::MPIDR_HWID_BITMASK;

            // Get numa-node-id if present
            if let Some(numa_prop) = cpu_child.property("numa-node-id")
                && let Some(node_id) = numa_prop.as_u32()
            {
                let node_id = node_id as usize;
                if node_id < MAX_NUMA_NODES {
                    found_numa = true;
                    // By MPIDR affinity: the logical CPU joins at bring-up
                    topology.set_hwid_node(hwid, node_id as u32);

                    // Ensure node exists
                    if topology.nodes[node_id].is_none() {
                        topology.nodes[node_id] = Some(NumaNode::new(node_id as u32));
                        topology.node_online_mask |= 1u64 << node_id;
                    }
                }
            }
        }
    }

    if !found_numa {
        return false;
    }

    // Update node count
    topology.nr_nodes = topology.node_online_mask.count_ones() as usize;

    // Check for numa-distance-map-v1 (optional)
    // Look for /distance-map compatible = "numa-distance-map-v1"
    let distance_nodes = dt.find_compatible("numa-distance-map-v1");
    if let Some(dist_node) = distance_nodes.first() {
        // distance-matrix property format: <from1 to1 dist1 from2 to2 dist2 ...>
        if let Some(dist_prop) = dist_node.property("distance-matrix") {
            let data = dist_prop.data();
            // Each entry is 3 u32s (12 bytes): from, to, distance
            let entries = data.len() / 12;
            for i in 0..entries {
                let offset = i * 12;
                if offset + 12 <= data.len() {
                    let from = u32::from_be_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]) as usize;
                    let to = u32::from_be_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]) as usize;
                    let dist = u32::from_be_bytes([
                        data[offset + 8],
                        data[offset + 9],
                        data[offset + 10],
                        data[offset + 11],
                    ]) as u8;

                    if from < MAX_NUMA_NODES && to < MAX_NUMA_NODES {
                        topology.set_distance(from, to, dist);
                    }
                }
            }
        }
    } else {
        // No distance map, use defaults
        for from in 0..MAX_NUMA_NODES {
            for to in 0..MAX_NUMA_NODES {
                if from == to {
                    topology.set_distance(from, to, LOCAL_DISTANCE);
                } else {
                    topology.set_distance(from, to, REMOTE_DISTANCE);
                }
            }
        }
    }

    // Mark as initialized
    topology.set_initialized();

    true
}

#[cfg(test)]
mod tests {
    // Tests would go here, but require std for the test framework
}
