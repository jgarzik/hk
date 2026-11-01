//! xHCI extended capabilities (Linux drivers/usb/host/xhci-ext-caps.h)
//!
//! HCCPARAMS1 bits 31:16 give the first capability's offset in dwords
//! from the start of the MMIO space; each capability's first dword holds
//! its ID (bits 7:0) and the dword offset of the next (bits 15:8, 0 =
//! last).
//!
//! Locking: none (reads the caller's MMIO mapping).

/// 32-bit MMIO register access at byte offsets into one mapping (a real
/// BAR, or a host-test double)
#[allow(clippy::len_without_is_empty)]
pub trait Mmio {
    fn read32(&self, off: u32) -> u32;
    fn write32(&self, off: u32, val: u32);
    /// Size of the mapping in bytes
    fn len(&self) -> u32;
}

/// HCCPARAMS1 (capability register offset)
pub const HCC_PARAMS1: u32 = 0x10;

/// USB Legacy Support capability (BIOS/OS ownership, SMI control)
pub const CAP_LEGACY: u8 = 1;

/// Supported Protocol capability
pub const CAP_PROTOCOL: u8 = 2;

/// Capabilities walked at most (Linux XHCI_MAX_EXT_CAPS): bounds a list
/// that loops
const MAX_EXT_CAPS: u32 = 50;

/// Offset of the first capability with ID `id` after `start` (0: from
/// the list head), or 0 if there is none (Linux xhci_find_next_ext_cap).
/// All-ones reads (a controller that stopped responding) and offsets
/// past the mapping end the walk.
pub fn find_ext_cap(regs: &impl Mmio, start: u32, id: u8) -> u32 {
    let mut off = start;
    if start == 0 || start == HCC_PARAMS1 {
        let params = regs.read32(HCC_PARAMS1);
        if params == !0 {
            return 0;
        }
        off = (params >> 16) << 2;
        if off == 0 {
            return 0;
        }
    }
    for _ in 0..MAX_EXT_CAPS {
        if off.saturating_add(4) > regs.len() {
            return 0;
        }
        let val = regs.read32(off);
        if val == !0 {
            return 0;
        }
        if off != start && (id == 0 || val as u8 == id) {
            return off;
        }
        let next = (val >> 8) & 0xff;
        if next == 0 {
            return 0;
        }
        off += next << 2;
    }
    0
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use core::cell::RefCell;

    /// A register file: dword array, optional hook on writes
    pub struct FakeRegs {
        pub mem: RefCell<alloc::vec::Vec<u32>>,
    }

    impl FakeRegs {
        pub fn new(bytes: u32) -> Self {
            Self {
                mem: RefCell::new(alloc::vec![0; bytes as usize / 4]),
            }
        }
        pub fn set(&self, off: u32, val: u32) {
            self.mem.borrow_mut()[off as usize / 4] = val;
        }
        pub fn get(&self, off: u32) -> u32 {
            self.mem.borrow()[off as usize / 4]
        }
    }

    impl Mmio for FakeRegs {
        fn read32(&self, off: u32) -> u32 {
            self.get(off)
        }
        fn write32(&self, off: u32, val: u32) {
            self.set(off, val)
        }
        fn len(&self) -> u32 {
            self.mem.borrow().len() as u32 * 4
        }
    }

    /// Protocol at 0x500 -> legacy at 0x540 -> protocol at 0x560
    fn chain() -> FakeRegs {
        let r = FakeRegs::new(0x1000);
        r.set(HCC_PARAMS1, (0x500 / 4) << 16);
        r.set(0x500, (0x10 << 8) | CAP_PROTOCOL as u32);
        r.set(0x540, (0x08 << 8) | CAP_LEGACY as u32);
        r.set(0x560, CAP_PROTOCOL as u32);
        r
    }

    #[test]
    fn finds_by_id() {
        let r = chain();
        assert_eq!(find_ext_cap(&r, 0, CAP_LEGACY), 0x540);
        assert_eq!(find_ext_cap(&r, 0, CAP_PROTOCOL), 0x500);
        assert_eq!(find_ext_cap(&r, 0x500, CAP_PROTOCOL), 0x560);
        assert_eq!(find_ext_cap(&r, 0, 0), 0x500);
        assert_eq!(find_ext_cap(&r, 0, 9), 0);
    }

    #[test]
    fn no_caps() {
        let r = FakeRegs::new(0x1000);
        assert_eq!(find_ext_cap(&r, 0, CAP_LEGACY), 0);
    }

    #[test]
    fn dead_controller() {
        let r = FakeRegs::new(0x1000);
        r.set(HCC_PARAMS1, !0);
        assert_eq!(find_ext_cap(&r, 0, CAP_LEGACY), 0);
        let r = chain();
        r.set(0x500, !0);
        assert_eq!(find_ext_cap(&r, 0, CAP_LEGACY), 0);
    }

    /// A next pointer past the mapping or a loop ends the walk
    #[test]
    fn garbage_list() {
        let r = chain();
        r.set(0x500, (0xff << 8) | CAP_PROTOCOL as u32); // 0x500 + 0x3fc
        r.set(0x8fc, (0xff << 8) | 7); // -> 0xcf8, then past 0x1000
        r.set(0xcf8, (0xff << 8) | 7);
        assert_eq!(find_ext_cap(&r, 0, CAP_LEGACY), 0);
        let r = chain();
        r.set(0x540, 7); // ends the list before 0x560
        assert_eq!(find_ext_cap(&r, 0x500, CAP_PROTOCOL), 0);
    }
}
