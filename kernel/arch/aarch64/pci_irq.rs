//! PCI INTx -> GIC interrupt routing from the device tree
//!
//! The PCI host bridge node (`pci-host-ecam-generic`) describes legacy INTx
//! routing with `interrupt-map` / `interrupt-map-mask` (IEEE 1275 PCI
//! binding, Linux of_irq_parse_raw). Each map entry is:
//!
//! ```text
//! <child unit address (3 cells: phys.hi phys.mid phys.lo)>
//! <child interrupt (1 cell: pin, 1 = INTA)>
//! <interrupt-parent phandle>
//! <parent unit address (#address-cells of the parent)>
//! <parent interrupt specifier (#interrupt-cells of the parent)>
//! ```
//!
//! For a GICv3 parent the specifier is `<type number flags>` (type 0 = SPI,
//! INTID = 32 + number). The table is parsed once at boot; lookups fall back
//! to QEMU virt's fixed swizzle (SPIs 3..6) if there is no usable map.

use alloc::vec::Vec;

use spin::Mutex;

use crate::bus::pci_intx::{IntxMapEntry as MapEntry, match_interrupt_map, qemu_virt_swizzle};
use crate::dt::DeviceTree;

/// Parsed routing: (mask phys.hi, mask pin, entries)
struct IntxMap {
    mask_hi: u32,
    mask_pin: u32,
    entries: Vec<MapEntry>,
}

/// Filled at boot from the DTB (process context only)
static INTX_MAP: Mutex<Option<IntxMap>> = Mutex::new(None);

fn be32(data: &[u8], cell: usize) -> Option<u32> {
    let b = data.get(cell * 4..cell * 4 + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn prop_u32(node: &crate::dt::Node<'_>, name: &str) -> Option<u32> {
    node.property(name).and_then(|p| be32(p.data(), 0))
}

/// Parse the PCI host bridge interrupt-map (called while parsing the DTB)
pub fn init_from_dt(dt: &DeviceTree<'_>) {
    let Some(host) = dt
        .find_compatible("pci-host-ecam-generic")
        .into_iter()
        .next()
    else {
        return;
    };
    let (Some(map), Some(mask)) = (
        host.property("interrupt-map"),
        host.property("interrupt-map-mask"),
    ) else {
        return;
    };
    let child_addr_cells = prop_u32(&host, "#address-cells").unwrap_or(3) as usize;
    let child_irq_cells = prop_u32(&host, "#interrupt-cells").unwrap_or(1) as usize;
    if child_addr_cells != 3 || child_irq_cells != 1 {
        return;
    }
    let mask = mask.data();
    let (Some(mask_hi), Some(mask_pin)) = (be32(mask, 0), be32(mask, 3)) else {
        return;
    };

    // The interrupt parent must be the GIC (we know its specifier format)
    let gic = ["arm,gic-v3", "arm,gic-400", "arm,cortex-a15-gic"]
        .iter()
        .find_map(|c| dt.find_compatible(c).into_iter().next());
    let Some(gic) = gic else { return };
    let gic_phandle = prop_u32(&gic, "phandle");
    let parent_addr_cells = prop_u32(&gic, "#address-cells").unwrap_or(0) as usize;
    let parent_irq_cells = prop_u32(&gic, "#interrupt-cells").unwrap_or(3) as usize;
    if parent_irq_cells < 2 {
        return;
    }

    let data = map.data();
    let entry_cells = 3 + 1 + 1 + parent_addr_cells + parent_irq_cells;
    let mut entries = Vec::new();
    let mut cell = 0;
    while (cell + entry_cells) * 4 <= data.len() {
        let phys_hi = be32(data, cell).unwrap_or(0);
        let pin = be32(data, cell + 3).unwrap_or(0);
        let phandle = be32(data, cell + 4).unwrap_or(0);
        let spec = cell + 5 + parent_addr_cells;
        let kind = be32(data, spec).unwrap_or(u32::MAX);
        let number = be32(data, spec + 1).unwrap_or(0);
        cell += entry_cells;
        if Some(phandle) != gic_phandle {
            continue; // routed to some other controller: not supported
        }
        let intid = match kind {
            0 => 32 + number, // SPI
            1 => 16 + number, // PPI
            _ => continue,
        };
        entries.push(MapEntry {
            phys_hi: phys_hi & mask_hi,
            pin: pin & mask_pin,
            intid,
        });
    }
    crate::printkln!("PCI: {} INTx routes from DT interrupt-map", entries.len());
    *INTX_MAP.lock() = Some(IntxMap {
        mask_hi,
        mask_pin,
        entries,
    });
}

/// GIC INTID for (bus, device, function, pin); pin 1 = INTA, 0 = none
pub fn intx_to_intid(bus: u8, device: u8, function: u8, pin: u8) -> Option<u32> {
    if !(1..=4).contains(&pin) {
        return None;
    }
    if let Some(map) = INTX_MAP.lock().as_ref()
        && let Some(intid) = match_interrupt_map(
            &map.entries,
            map.mask_hi,
            map.mask_pin,
            bus,
            device,
            function,
            pin,
        )
    {
        return Some(intid);
    }
    // No (matching) interrupt-map: QEMU virt's fixed routing
    Some(qemu_virt_swizzle(device, pin))
}
