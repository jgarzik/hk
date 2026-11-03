//! Arch-independent PCI INTx routing helpers (host-testable)
//!
//! Matching of a device-tree `interrupt-map` (IEEE 1275 PCI binding) and
//! the QEMU `virt` fixed swizzle. The arch layer parses the DTB and owns the
//! table; see `arch::aarch64::pci_irq`.

/// One `interrupt-map` entry, child address/pin already masked
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntxMapEntry {
    /// Masked child phys.hi (bus << 16 | dev << 11 | fn << 8)
    pub phys_hi: u32,
    /// Masked child interrupt (pin, 1 = INTA)
    pub pin: u32,
    /// Parent interrupt (GIC INTID)
    pub intid: u32,
}

/// Child unit-address phys.hi cell for a PCI function
pub fn phys_hi(bus: u8, device: u8, function: u8) -> u32 {
    ((bus as u32) << 16) | ((device as u32) << 11) | ((function as u32) << 8)
}

/// Look up (bus, device, function, pin) in a parsed interrupt-map
pub fn match_interrupt_map(
    entries: &[IntxMapEntry],
    mask_hi: u32,
    mask_pin: u32,
    bus: u8,
    device: u8,
    function: u8,
    pin: u8,
) -> Option<u32> {
    let key_hi = phys_hi(bus, device, function) & mask_hi;
    let key_pin = pin as u32 & mask_pin;
    entries
        .iter()
        .find(|e| e.phys_hi == key_hi && e.pin == key_pin)
        .map(|e| e.intid)
}

/// QEMU virt fixed INTx routing (hw/arm/virt.c create_pcie_irq_map): slot
/// s, pin p (1 = INTA) -> SPI 3 + (s + p - 1) % 4, i.e. INTID 35..38
pub fn qemu_virt_swizzle(device: u8, pin: u8) -> u32 {
    32 + 3 + ((device as u32 + pin as u32 - 1) % 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swizzle_matches_qemu_virt() {
        assert_eq!(qemu_virt_swizzle(0, 1), 35);
        assert_eq!(qemu_virt_swizzle(1, 1), 36);
        assert_eq!(qemu_virt_swizzle(3, 2), 35);
        assert_eq!(qemu_virt_swizzle(2, 4), 36);
    }

    #[test]
    fn interrupt_map_matches_masked_slot_and_pin() {
        // QEMU virt style: mask <0x1800 0 0 7>, 4 slots x 4 pins
        let mut entries = alloc::vec::Vec::new();
        for slot in 0..4u8 {
            for pin in 1..=4u8 {
                entries.push(IntxMapEntry {
                    phys_hi: phys_hi(0, slot, 0) & 0x1800,
                    pin: pin as u32,
                    intid: qemu_virt_swizzle(slot, pin),
                });
            }
        }
        // Slot 5 aliases slot 1 under the mask; function bits are masked
        assert_eq!(
            match_interrupt_map(&entries, 0x1800, 7, 0, 5, 3, 1),
            Some(36)
        );
        assert_eq!(
            match_interrupt_map(&entries, 0x1800, 7, 0, 2, 0, 2),
            Some(32 + 3 + 3)
        );
        assert_eq!(match_interrupt_map(&entries, 0x1800, 7, 0, 2, 0, 5), None);
    }
}
