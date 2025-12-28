//! Device Tree parsing for aarch64 hardware discovery
//!
//! This module extracts hardware configuration from the Device Tree Blob (DTB)
//! passed by the bootloader. It produces an AcpiInfo structure compatible with
//! the architecture-independent kernel code.

extern crate alloc;

use alloc::vec::Vec;

use crate::arch::{AcpiInfo, CpuInfo};
use crate::dt::DeviceTree;

/// Parse DTB and extract hardware configuration
///
/// # Safety
/// The dtb_ptr must point to a valid FDT blob in memory.
pub fn parse_dtb(dtb_ptr: u64) -> Option<AcpiInfo> {
    if dtb_ptr == 0 {
        return None;
    }

    // Safety: DTB pointer comes from bootloader (x0 register)
    // First read header to get totalsize
    let dtb_data = unsafe {
        let header = core::slice::from_raw_parts(dtb_ptr as *const u8, 8);

        // Check magic number first (big-endian 0xd00dfeed)
        if header[0] != 0xd0 || header[1] != 0x0d || header[2] != 0xfe || header[3] != 0xed {
            return None;
        }

        let totalsize = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        // Sanity check size (between 1KB and 16MB)
        if !(1024..=16 * 1024 * 1024).contains(&totalsize) {
            return None;
        }

        core::slice::from_raw_parts(dtb_ptr as *const u8, totalsize)
    };

    let dt = DeviceTree::from_fdt(dtb_data).ok()?;

    // Extract GIC distributor base address
    let gic_base = extract_gic_base(&dt)?;

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
fn extract_gic_base(dt: &DeviceTree) -> Option<u64> {
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
fn extract_cpus(dt: &DeviceTree) -> Vec<CpuInfo> {
    let mut cpus = Vec::new();

    let cpus_node = match dt.find_node("/cpus") {
        Some(node) => node,
        None => return cpus,
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
        unsafe { core::slice::from_raw_parts(self.start as *const u8, self.size()) }
    }
}

/// Extract initramfs location from DTB /chosen node
///
/// Looks for `linux,initrd-start` and `linux,initrd-end` properties.
///
/// # Safety
/// The dtb_ptr must point to a valid FDT blob in memory.
pub fn extract_initramfs(dtb_ptr: u64) -> Option<InitramfsInfo> {
    if dtb_ptr == 0 {
        return None;
    }

    // Safety: DTB pointer comes from bootloader (x0 register)
    let dtb_data = unsafe {
        let header = core::slice::from_raw_parts(dtb_ptr as *const u8, 8);

        // Check magic number first (big-endian 0xd00dfeed)
        if header[0] != 0xd0 || header[1] != 0x0d || header[2] != 0xfe || header[3] != 0xed {
            return None;
        }

        let totalsize = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        // Sanity check size (between 1KB and 16MB)
        if !(1024..=16 * 1024 * 1024).contains(&totalsize) {
            return None;
        }

        core::slice::from_raw_parts(dtb_ptr as *const u8, totalsize)
    };

    let dt = DeviceTree::from_fdt(dtb_data).ok()?;

    // Find /chosen node
    let chosen = dt.find_node("/chosen")?;

    // Get initrd-start and initrd-end properties
    // These can be either 32-bit or 64-bit depending on the DTB
    let start = chosen.property("linux,initrd-start")?;
    let end = chosen.property("linux,initrd-end")?;

    // Try 64-bit first, fall back to 32-bit
    let start_addr = start
        .as_u64()
        .or_else(|| start.as_u32().map(|v| v as u64))?;
    let end_addr = end.as_u64().or_else(|| end.as_u32().map(|v| v as u64))?;

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
pub fn extract_bootargs(dtb_ptr: *const u8) -> Option<&'static str> {
    if dtb_ptr.is_null() {
        return None;
    }

    // Parse just enough to get the total size
    let magic = unsafe { (dtb_ptr as *const u32).read() }.to_be();
    if magic != 0xd00dfeed {
        return None;
    }

    let totalsize = unsafe { (dtb_ptr as *const u32).add(1).read() }.to_be() as usize;

    // Create a slice for the device tree
    let dtb_data = unsafe { core::slice::from_raw_parts(dtb_ptr, totalsize) };

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
///
/// # Safety
/// The dtb_ptr must point to a valid FDT blob in memory.
pub unsafe fn extract_simple_framebuffer(dtb_ptr: u64) -> Option<crate::gfx::FramebufferInfo> {
    use crate::gfx::{FramebufferInfo, PixelFormat};

    if dtb_ptr == 0 {
        return None;
    }

    // Parse just enough to get the total size
    // SAFETY: dtb_ptr was validated to be non-zero, and we're reading the DTB header
    let magic = unsafe { (dtb_ptr as *const u32).read() }.to_be();
    if magic != 0xd00dfeed {
        return None;
    }

    // SAFETY: dtb_ptr is valid, and we're reading the totalsize field from the DTB header
    let totalsize = unsafe { (dtb_ptr as *const u32).add(1).read() }.to_be() as usize;

    // Sanity check size (between 1KB and 16MB)
    if !(1024..=16 * 1024 * 1024).contains(&totalsize) {
        return None;
    }

    // Create a slice for the device tree
    // SAFETY: dtb_ptr is valid and totalsize has been validated to be reasonable
    let dtb_data = unsafe { core::slice::from_raw_parts(dtb_ptr as *const u8, totalsize) };

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
/// Returns Ok(true) if NUMA topology was found, Ok(false) if no NUMA info
/// (caller should use single-node fallback).
///
/// # Safety
/// The dtb_ptr must point to a valid FDT blob in memory.
pub fn init_numa_topology(dtb_ptr: u64) -> Result<bool, &'static str> {
    use crate::numa::{LOCAL_DISTANCE, MAX_NUMA_NODES, NUMA_TOPOLOGY, NumaNode, REMOTE_DISTANCE};

    if dtb_ptr == 0 {
        return Ok(false);
    }

    // Parse DTB header for size
    let dtb_data = unsafe {
        let header = core::slice::from_raw_parts(dtb_ptr as *const u8, 8);

        // Check magic number first (big-endian 0xd00dfeed)
        if header[0] != 0xd0 || header[1] != 0x0d || header[2] != 0xfe || header[3] != 0xed {
            return Ok(false);
        }

        let totalsize = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        // Sanity check size (between 1KB and 16MB)
        if !(1024..=16 * 1024 * 1024).contains(&totalsize) {
            return Ok(false);
        }

        core::slice::from_raw_parts(dtb_ptr as *const u8, totalsize)
    };

    let dt = match DeviceTree::from_fdt(dtb_data) {
        Ok(dt) => dt,
        Err(_) => return Ok(false),
    };

    let mut found_numa = false;
    let mut topology = NUMA_TOPOLOGY.lock();

    // Extract memory nodes with numa-node-id
    // Memory nodes can be /memory or /memory@ADDR
    let root = match dt.find_node("/") {
        Some(root) => root,
        None => return Ok(false),
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

            // Get CPU ID from reg property
            let cpu_id = match cpu_child.property("reg") {
                Some(reg) => reg.as_u32().unwrap_or(0),
                None => continue,
            };

            // Get numa-node-id if present
            if let Some(numa_prop) = cpu_child.property("numa-node-id")
                && let Some(node_id) = numa_prop.as_u32()
            {
                let node_id = node_id as usize;
                if node_id < MAX_NUMA_NODES && (cpu_id as usize) < crate::numa::MAX_CPUS {
                    found_numa = true;
                    topology.cpu_to_node[cpu_id as usize] = node_id as u8;

                    // Ensure node exists
                    if topology.nodes[node_id].is_none() {
                        topology.nodes[node_id] = Some(NumaNode::new(node_id as u32));
                        topology.node_online_mask |= 1u64 << node_id;
                    }

                    // Add CPU to node's cpu_mask
                    if cpu_id < 64
                        && let Some(ref mut node) = topology.nodes[node_id]
                    {
                        node.add_cpu(cpu_id);
                    }
                }
            }
        }
    }

    if !found_numa {
        return Ok(false);
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

    Ok(true)
}

#[cfg(test)]
mod tests {
    // Tests would go here, but require std for the test framework
}
