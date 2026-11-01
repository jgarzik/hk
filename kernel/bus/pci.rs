//! PCI Host Controller Driver
//!
//! Provides PCI configuration space access via I/O ports CF8/CFC
//! and bus enumeration for device discovery.
//!
//! Implements the Bus/Driver model for layered device enumeration.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::Any;

use spin::Once;

use crate::dma::{DmaConfig, DmaDevice};
use crate::printkln;

use super::bus::{Bus, BusContext, BusDevice, BusDriver};
use super::driver::{Device, DriverError};

// ============================================================================
// PCI BAR Allocator (for platforms without firmware BAR assignment)
// ============================================================================

/// Cross-platform BAR address allocator
///
/// On platforms without firmware BAR assignment (ARM with direct kernel boot),
/// the OS must allocate and assign PCI BAR addresses. On platforms with firmware
/// (x86 with BIOS/UEFI), BARs are pre-assigned and this allocator is not used.
///
/// The allocator is called only for BARs with address portion == 0.
mod bar_alloc {
    use core::sync::atomic::{AtomicU64, Ordering};

    // Platform-specific MMIO regions for PCI BAR allocation
    //
    // These ranges must not conflict with other memory mappings.
    // On x86, BIOS typically assigns BARs, so this is a fallback.
    // On ARM QEMU virt, this is the primary PCI MMIO window.

    #[cfg(target_arch = "x86_64")]
    const MMIO_START: u64 = 0xE000_0000; // Below LAPIC/IOAPIC region
    #[cfg(target_arch = "x86_64")]
    const MMIO_END: u64 = 0xFEB0_0000; // Before typical BIOS allocations

    #[cfg(target_arch = "aarch64")]
    const MMIO_START: u64 = 0x1000_0000; // QEMU virt PCI MMIO window
    #[cfg(target_arch = "aarch64")]
    const MMIO_END: u64 = 0x3F00_0000;

    /// Current allocation pointer (atomic for thread-safety)
    static NEXT_ADDR: AtomicU64 = AtomicU64::new(MMIO_START);

    /// Allocate a BAR address with the given size and alignment
    ///
    /// Returns None if the MMIO space is exhausted.
    pub fn allocate(size: u64) -> Option<u64> {
        if size == 0 {
            return None;
        }

        // BARs must be naturally aligned (address aligned to size)
        let align = size;

        loop {
            let current = NEXT_ADDR.load(Ordering::Relaxed);

            // Align up to the required alignment
            let aligned = (current + align - 1) & !(align - 1);
            let next = aligned + size;

            if next > MMIO_END {
                return None; // Out of space
            }

            // Try to update atomically
            match NEXT_ADDR.compare_exchange(current, next, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_) => return Some(aligned),
                Err(_) => continue, // Retry on contention
            }
        }
    }
}

/// PCI class codes
pub mod class {
    pub const MASS_STORAGE: u8 = 0x01;
    pub const NETWORK: u8 = 0x02;
    pub const DISPLAY: u8 = 0x03;
    pub const MULTIMEDIA: u8 = 0x04;
    pub const MEMORY: u8 = 0x05;
    pub const BRIDGE: u8 = 0x06;
    pub const SERIAL_BUS: u8 = 0x0C;
}

/// PCI serial bus subclass codes
pub mod subclass {
    pub const USB: u8 = 0x03;
}

/// USB programming interface codes
pub mod prog_if {
    pub const UHCI: u8 = 0x00;
    pub const OHCI: u8 = 0x10;
    pub const EHCI: u8 = 0x20;
    pub const XHCI: u8 = 0x30;
}

/// PCI configuration space offsets
mod offset {
    pub const VENDOR_ID: u8 = 0x00;
    pub const DEVICE_ID: u8 = 0x02;
    pub const COMMAND: u8 = 0x04;
    pub const STATUS: u8 = 0x06;
    pub const REVISION_ID: u8 = 0x08;
    pub const PROG_IF: u8 = 0x09;
    pub const SUBCLASS: u8 = 0x0A;
    pub const CLASS_CODE: u8 = 0x0B;
    pub const CACHE_LINE_SIZE: u8 = 0x0C;
    pub const LATENCY_TIMER: u8 = 0x0D;
    pub const HEADER_TYPE: u8 = 0x0E;
    pub const BIST: u8 = 0x0F;
    pub const BAR0: u8 = 0x10;
    pub const BAR1: u8 = 0x14;
    pub const BAR2: u8 = 0x18;
    pub const BAR3: u8 = 0x1C;
    pub const BAR4: u8 = 0x20;
    pub const BAR5: u8 = 0x24;
    pub const SUBSYSTEM_VENDOR_ID: u8 = 0x2C;
    pub const SUBSYSTEM_ID: u8 = 0x2E;
    pub const CAPABILITY_LIST: u8 = 0x34;
    pub const INTERRUPT_LINE: u8 = 0x3C;
    pub const INTERRUPT_PIN: u8 = 0x3D;
}

/// PCI status register bits
mod status {
    /// Capability list present
    pub const CAP_LIST: u16 = 1 << 4;
}

/// PCI capability IDs (Linux PCI_CAP_ID_*)
pub mod cap_id {
    pub const PM: u8 = 0x01;
    pub const VNDR: u8 = 0x09;
    pub const MSIX: u8 = 0x11;
}

/// Maximum capabilities walked (Linux PCI_FIND_CAP_TTL): bounds a list
/// that loops
const CAP_TTL: u32 = 48;

/// Walk a capability list (Linux __pci_find_next_cap_ttl), reading config
/// bytes through `read8`
pub struct PciCapIter<F: Fn(u8) -> u8> {
    read8: F,
    pos: u8,
    ttl: u32,
}

impl<F: Fn(u8) -> u8> PciCapIter<F> {
    /// Start at the list head `first` (0 = no list)
    pub fn new(read8: F, first: u8) -> Self {
        Self {
            read8,
            pos: first,
            ttl: CAP_TTL,
        }
    }
}

impl<F: Fn(u8) -> u8> Iterator for PciCapIter<F> {
    /// (offset, capability ID)
    type Item = (u8, u8);

    fn next(&mut self) -> Option<(u8, u8)> {
        let pos = self.pos & !3;
        // Capabilities live after the 64-byte standard header
        if self.ttl == 0 || pos < 0x40 {
            return None;
        }
        self.ttl -= 1;
        let id = (self.read8)(pos);
        if id == 0xFF {
            return None;
        }
        self.pos = (self.read8)(pos + 1);
        Some((pos, id))
    }
}

/// PCI command register bits
pub mod command {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const INTERRUPT_DISABLE: u16 = 1 << 10;
}

// ============================================================================
// PCI Configuration Space Access Abstraction
// ============================================================================

/// Trait for PCI configuration space access
///
/// Abstracts the mechanism for accessing PCI config registers:
/// - Port I/O (x86 legacy: CF8/CFC)
/// - ECAM (memory-mapped, PCIe standard)
pub trait PciConfigAccess: Send + Sync {
    /// Read 32-bit value from config space
    fn read32(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u32;

    /// Write 32-bit value to config space
    fn write32(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u32);

    /// Read 16-bit value (default: extract from 32-bit read)
    fn read16(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
        let val = self.read32(bus, dev, func, offset & 0xFC);
        ((val >> ((offset & 2) * 8)) & 0xFFFF) as u16
    }

    /// Read 8-bit value (default: extract from 32-bit read)
    fn read8(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
        let val = self.read32(bus, dev, func, offset & 0xFC);
        ((val >> ((offset & 3) * 8)) & 0xFF) as u8
    }

    /// Write 16-bit value (default: read-modify-write of the dword, for
    /// test doubles; real accessors write just the word, since a dword
    /// write would also write back the neighbour's write-1-to-clear bits,
    /// e.g. STATUS when writing COMMAND)
    fn write16(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
        let shift = (offset & 2) * 8;
        let mask = !(0xFFFF << shift);
        let old = self.read32(bus, dev, func, offset & 0xFC);
        let new = (old & mask) | ((val as u32) << shift);
        self.write32(bus, dev, func, offset & 0xFC, new);
    }

    /// Write 8-bit value (default: read-modify-write, as `write16`)
    fn write8(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u8) {
        let shift = (offset & 3) * 8;
        let mask = !(0xFF << shift);
        let old = self.read32(bus, dev, func, offset & 0xFC);
        let new = (old & mask) | ((val as u32) << shift);
        self.write32(bus, dev, func, offset & 0xFC, new);
    }
}

/// ECAM (Enhanced Configuration Access Mechanism) for PCIe
///
/// Memory-mapped PCI config space access. Works on all architectures.
/// Address formula: Base + (Bus << 20) | (Dev << 15) | (Func << 12) | Offset
pub struct EcamConfigAccess {
    /// Base virtual address of ECAM region
    base: *mut u8,
}

// Safety: ECAM region is device memory, access is synchronized by hardware
unsafe impl Send for EcamConfigAccess {}
unsafe impl Sync for EcamConfigAccess {}

impl EcamConfigAccess {
    /// Create ECAM accessor
    ///
    /// # Safety
    /// base_addr must be a valid mapped ECAM region that remains valid
    /// for the lifetime of this struct.
    pub const unsafe fn new(base_addr: *mut u8) -> Self {
        Self { base: base_addr }
    }

    /// Calculate offset into ECAM space
    #[inline]
    fn offset(bus: u8, dev: u8, func: u8, reg: u8) -> usize {
        ((bus as usize) << 20) | ((dev as usize) << 15) | ((func as usize) << 12) | (reg as usize)
    }
}

impl PciConfigAccess for EcamConfigAccess {
    fn read32(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
        let addr = unsafe { self.base.add(Self::offset(bus, dev, func, offset)) };
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    fn write32(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
        let addr = unsafe { self.base.add(Self::offset(bus, dev, func, offset)) };
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
    }

    fn read16(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
        let addr = unsafe { self.base.add(Self::offset(bus, dev, func, offset & 0xFE)) };
        unsafe { core::ptr::read_volatile(addr as *const u16) }
    }

    fn read8(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
        let addr = unsafe { self.base.add(Self::offset(bus, dev, func, offset)) };
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write16(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
        let addr = unsafe { self.base.add(Self::offset(bus, dev, func, offset & 0xFE)) };
        unsafe { core::ptr::write_volatile(addr as *mut u16, val) }
    }

    fn write8(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u8) {
        let addr = unsafe { self.base.add(Self::offset(bus, dev, func, offset)) };
        unsafe { core::ptr::write_volatile(addr, val) }
    }
}

// ============================================================================
// Global PCI Config Accessor
// ============================================================================

/// Global PCI config access mechanism
static PCI_CONFIG: Once<&'static dyn PciConfigAccess> = Once::new();

/// Initialize PCI config access with port I/O (x86 legacy)
#[cfg(target_arch = "x86_64")]
pub fn init_port_io() {
    PCI_CONFIG.call_once(|| &crate::arch::x86_64::pci_conf::PORT_IO);
}

/// Initialize PCI config access with ECAM (memory-mapped)
///
/// # Safety
/// base_addr must be a valid mapped ECAM region.
pub unsafe fn init_ecam(base_addr: *mut u8) {
    // Leak a box to get 'static lifetime
    // Safety: caller guarantees base_addr is valid
    let accessor = Box::leak(Box::new(unsafe { EcamConfigAccess::new(base_addr) }));
    PCI_CONFIG.call_once(|| accessor as &dyn PciConfigAccess);
}

/// Check if PCI config access has been initialized
pub fn is_initialized() -> bool {
    PCI_CONFIG.get().is_some()
}

/// Get config accessor (panics if not initialized)
fn config() -> &'static dyn PciConfigAccess {
    *PCI_CONFIG
        .get()
        .expect("PCI config access not initialized - call init_port_io() or init_ecam() first")
}

// ============================================================================
// Legacy PCI Config Functions (now use trait)
// ============================================================================

/// Read 32-bit value from PCI configuration space
pub fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    config().read32(bus, dev, func, offset)
}

/// Write 32-bit value to PCI configuration space
pub fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    config().write32(bus, dev, func, offset, val)
}

/// Read 16-bit value from PCI configuration space
pub fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    config().read16(bus, dev, func, offset)
}

/// Write 16-bit value to PCI configuration space
pub fn pci_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    config().write16(bus, dev, func, offset, val)
}

/// Read 8-bit value from PCI configuration space
pub fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    config().read8(bus, dev, func, offset)
}

/// Write 8-bit value to PCI configuration space
pub fn pci_write8(bus: u8, dev: u8, func: u8, offset: u8, val: u8) {
    config().write8(bus, dev, func, offset, val)
}

/// PCI device header (Type 0 - standard)
#[derive(Debug, Clone)]
pub struct PciDeviceHeader {
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub revision_id: u8,
    pub prog_if: u8,
    pub subclass: u8,
    pub class_code: u8,
    pub cache_line_size: u8,
    pub latency_timer: u8,
    pub header_type: u8,
    pub bist: u8,
    pub bar: [u32; 6],
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    /// Subsystem vendor and device (type 0 headers; 0 otherwise): the
    /// board, for quirks keyed on it
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
}

impl PciDeviceHeader {
    /// Read header from PCI configuration space
    pub fn read(bus: u8, dev: u8, func: u8) -> Self {
        let type0 = pci_read8(bus, dev, func, offset::HEADER_TYPE) & 0x7F == 0;
        let subsys = |off| {
            if type0 {
                pci_read16(bus, dev, func, off)
            } else {
                0
            }
        };
        Self {
            vendor_id: pci_read16(bus, dev, func, offset::VENDOR_ID),
            device_id: pci_read16(bus, dev, func, offset::DEVICE_ID),
            command: pci_read16(bus, dev, func, offset::COMMAND),
            status: pci_read16(bus, dev, func, offset::STATUS),
            revision_id: pci_read8(bus, dev, func, offset::REVISION_ID),
            prog_if: pci_read8(bus, dev, func, offset::PROG_IF),
            subclass: pci_read8(bus, dev, func, offset::SUBCLASS),
            class_code: pci_read8(bus, dev, func, offset::CLASS_CODE),
            cache_line_size: pci_read8(bus, dev, func, offset::CACHE_LINE_SIZE),
            latency_timer: pci_read8(bus, dev, func, offset::LATENCY_TIMER),
            header_type: pci_read8(bus, dev, func, offset::HEADER_TYPE),
            bist: pci_read8(bus, dev, func, offset::BIST),
            bar: [
                pci_read32(bus, dev, func, offset::BAR0),
                pci_read32(bus, dev, func, offset::BAR1),
                pci_read32(bus, dev, func, offset::BAR2),
                pci_read32(bus, dev, func, offset::BAR3),
                pci_read32(bus, dev, func, offset::BAR4),
                pci_read32(bus, dev, func, offset::BAR5),
            ],
            interrupt_line: pci_read8(bus, dev, func, offset::INTERRUPT_LINE),
            interrupt_pin: pci_read8(bus, dev, func, offset::INTERRUPT_PIN),
            subsystem_vendor_id: subsys(offset::SUBSYSTEM_VENDOR_ID),
            subsystem_id: subsys(offset::SUBSYSTEM_ID),
        }
    }

    /// Check if this is a multi-function device
    pub fn is_multifunction(&self) -> bool {
        (self.header_type & 0x80) != 0
    }

    /// Get header type (0, 1, or 2)
    pub fn header_type_number(&self) -> u8 {
        self.header_type & 0x7F
    }
}

/// A BAR's size from the mask read back after writing all ones (`lo`,
/// and `hi` for the upper half of a 64-bit BAR, else 0): the lowest
/// address bit that sticks (Linux pci_size). Upper address bits may be
/// hardwired to zero, so the size is not the mask's complement.
fn bar_size_from_mask(io: bool, lo: u32, hi: u32) -> u64 {
    let lo = if io { lo & !0x3 } else { lo & !0xF };
    let mask = (hi as u64) << 32 | lo as u64;
    mask.isolate_lowest_one()
}

/// Represents a discovered PCI device
#[derive(Debug, Clone)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub header: PciDeviceHeader,
    /// DMA configuration (addressing masks)
    pub dma_config: DmaConfig,
    /// BAR sizes in bytes, probed once at scan (0: unused, or the upper
    /// half of a 64-bit BAR)
    bar_sizes: [u64; 6],
}

impl PciDevice {
    /// Read a PCI device from configuration space
    pub fn read(bus: u8, device: u8, function: u8) -> Option<Self> {
        let vendor_id = pci_read16(bus, device, function, offset::VENDOR_ID);
        if vendor_id == 0xFFFF {
            return None;
        }

        let mut dev = Self {
            bus,
            device,
            function,
            header: PciDeviceHeader::read(bus, device, function),
            dma_config: DmaConfig::default(), // 32-bit DMA by default
            bar_sizes: [0; 6],
        };
        dev.size_bars();
        Some(dev)
    }

    /// Probe every BAR's size, once, with decoding off (Linux
    /// __pci_read_base): writing all ones to a live BAR moves the device
    /// for the moment, under its driver - or under firmware still using
    /// it (USB legacy emulation in SMM). Host bridges keep decoding
    /// (Linux mmio_always_on).
    fn size_bars(&mut self) {
        let nbars = match self.header.header_type_number() {
            0 => 6,
            1 => 2,
            _ => return,
        };
        let host_bridge = self.class24() >> 8 == 0x0600;
        let cmd = self.cfg_read16(offset::COMMAND);
        let decode = command::IO_SPACE | command::MEMORY_SPACE;
        if !host_bridge && cmd & decode != 0 {
            self.cfg_write16(offset::COMMAND, cmd & !decode);
        }
        let mut i = 0;
        while i < nbars {
            let wide = self.bar_is_64bit(i) && i + 1 < nbars;
            self.bar_sizes[i] = self.probe_bar(i, wide);
            i += if wide { 2 } else { 1 };
        }
        if !host_bridge && cmd & decode != 0 {
            self.cfg_write16(offset::COMMAND, cmd);
        }
    }

    /// Size BAR `i` (and `i + 1` as its upper half if `wide`): write all
    /// ones, read the mask back, restore
    fn probe_bar(&self, i: usize, wide: bool) -> u64 {
        let size_of = |off: u8| {
            let orig = self.cfg_read32(off);
            self.cfg_write32(off, 0xFFFF_FFFF);
            let mask = self.cfg_read32(off);
            self.cfg_write32(off, orig);
            (orig, mask)
        };
        let off = offset::BAR0 + i as u8 * 4;
        let (orig, lo) = size_of(off);
        if lo == 0 || lo == 0xFFFF_FFFF {
            return 0;
        }
        let hi = if wide { size_of(off + 4).1 } else { 0 };
        bar_size_from_mask(orig & 1 != 0, lo, hi)
    }

    /// Set the DMA mask for streaming DMA mappings
    ///
    /// Returns true if the mask is acceptable, false if the device
    /// cannot support the requested addressing width.
    pub fn set_dma_mask(&mut self, mask: u64) -> bool {
        // For MVP, always accept (real impl would check device capability)
        self.dma_config.dma_mask = mask;
        true
    }

    /// Set the coherent DMA mask
    ///
    /// This mask is often more restrictive than the streaming DMA mask.
    pub fn set_coherent_dma_mask(&mut self, mask: u64) -> bool {
        self.dma_config.coherent_dma_mask = mask;
        true
    }

    /// Set both DMA masks at once (common pattern)
    pub fn set_dma_mask_and_coherent(&mut self, mask: u64) -> bool {
        self.set_dma_mask(mask) && self.set_coherent_dma_mask(mask)
    }

    /// Get BAR address (handles 32-bit and 64-bit BARs)
    pub fn bar_address(&self, bar_index: usize) -> Option<u64> {
        if bar_index >= 6 {
            return None;
        }

        let bar = self.header.bar[bar_index];
        if bar == 0 {
            return None;
        }

        // Check if I/O or memory BAR
        if (bar & 1) != 0 {
            // I/O BAR - return I/O port address
            Some((bar & !0x3) as u64)
        } else {
            // Memory BAR
            let bar_type = (bar >> 1) & 0x3;
            match bar_type {
                0 => {
                    // 32-bit BAR
                    Some((bar & !0xF) as u64)
                }
                2 => {
                    // 64-bit BAR - need to read next BAR too
                    if bar_index >= 5 {
                        return None;
                    }
                    let high = self.header.bar[bar_index + 1] as u64;
                    Some((high << 32) | (bar & !0xF) as u64)
                }
                _ => None,
            }
        }
    }

    /// Check if BAR is memory-mapped (vs I/O port)
    pub fn bar_is_mmio(&self, bar_index: usize) -> bool {
        if bar_index >= 6 {
            return false;
        }
        (self.header.bar[bar_index] & 1) == 0
    }

    /// Size of BAR `bar_index` in bytes, as probed at scan (0: none)
    pub fn bar_size(&self, bar_index: usize) -> u64 {
        self.bar_sizes.get(bar_index).copied().unwrap_or(0)
    }

    /// Check if a BAR is a 64-bit BAR
    fn bar_is_64bit(&self, bar_index: usize) -> bool {
        if bar_index >= 6 {
            return false;
        }
        let bar = self.header.bar[bar_index];
        // Memory BAR (bit 0 = 0) with type 2 (bits 2:1 = 10) is 64-bit
        (bar & 1) == 0 && ((bar >> 1) & 0x3) == 2
    }

    /// Assign a BAR address (for platforms without firmware BAR assignment)
    ///
    /// On platforms without firmware (e.g., ARM with direct kernel boot),
    /// there's no BIOS to assign BAR addresses. This method allocates an
    /// address from the MMIO region and writes it to the BAR register.
    ///
    /// On platforms with firmware (x86 with BIOS), BARs are pre-assigned
    /// and this is typically not called (checked by assign_all_bars).
    ///
    /// Returns the assigned address, or None if allocation failed.
    pub fn assign_bar(&mut self, bar_index: usize) -> Option<u64> {
        if bar_index >= 6 {
            return None;
        }

        let bar_val = self.header.bar[bar_index];
        let is_io = (bar_val & 1) != 0;
        if is_io {
            // I/O BARs not supported on ARM
            return None;
        }

        let is_64bit = self.bar_is_64bit(bar_index);
        if is_64bit && bar_index >= 5 {
            // 64-bit BAR needs two slots
            return None;
        }

        // Get the BAR size
        let size = self.bar_size(bar_index);
        if size == 0 {
            return None;
        }

        // Allocate address (always use 32-bit range for simplicity)
        let addr = bar_alloc::allocate(size)?;

        // Write address to BAR (preserve type bits)
        let bar_offset = offset::BAR0 + (bar_index as u8 * 4);
        let new_bar = (addr as u32) | (bar_val & 0xF);
        pci_write32(self.bus, self.device, self.function, bar_offset, new_bar);
        self.header.bar[bar_index] = new_bar;

        // For 64-bit BARs, write high 32 bits to next BAR
        if is_64bit {
            let bar_offset_high = offset::BAR0 + ((bar_index + 1) as u8 * 4);
            let high = (addr >> 32) as u32;
            pci_write32(self.bus, self.device, self.function, bar_offset_high, high);
            self.header.bar[bar_index + 1] = high;
        }

        Some(addr)
    }

    /// Assign all unassigned BARs (cross-platform)
    ///
    /// Iterates through all BARs and assigns addresses to any that are
    /// unassigned (address portion == 0). On platforms with firmware (x86 BIOS),
    /// BARs are typically pre-assigned, so this does nothing. On platforms
    /// without firmware (ARM direct boot), this allocates addresses.
    pub fn assign_all_bars(&mut self) {
        let mut i = 0;
        while i < 6 {
            // Check if BAR is unassigned (address portion is 0)
            let bar = self.header.bar[i];
            let is_io = (bar & 1) != 0;
            let addr = if is_io { bar & !0x3 } else { bar & !0xF };
            let is_64bit = self.bar_is_64bit(i);

            if addr == 0 {
                // Try to assign
                if let Some(assigned) = self.assign_bar(i) {
                    printkln!(
                        "PCI: Assigned BAR{} = {:#x} for {}",
                        i,
                        assigned,
                        BusDevice::bus_id(self)
                    );
                }
            }

            // Skip the next BAR slot if this was a 64-bit BAR
            if is_64bit {
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    /// Enable memory space access
    pub fn enable_memory_space(&self) {
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd | command::MEMORY_SPACE,
        );
    }

    /// Enable bus mastering (for DMA)
    pub fn enable_bus_master(&self) {
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd | command::BUS_MASTER,
        );
    }

    /// Read a config space byte of this function
    pub fn cfg_read8(&self, off: u8) -> u8 {
        pci_read8(self.bus, self.device, self.function, off)
    }

    /// Read a config space word of this function
    pub fn cfg_read16(&self, off: u8) -> u16 {
        pci_read16(self.bus, self.device, self.function, off)
    }

    /// Read a config space dword of this function
    pub fn cfg_read32(&self, off: u8) -> u32 {
        pci_read32(self.bus, self.device, self.function, off)
    }

    /// Write a config space byte of this function
    pub fn cfg_write8(&self, off: u8, val: u8) {
        pci_write8(self.bus, self.device, self.function, off, val)
    }

    /// Write a config space word of this function
    pub fn cfg_write16(&self, off: u8, val: u16) {
        pci_write16(self.bus, self.device, self.function, off, val)
    }

    /// Write a config space dword of this function
    pub fn cfg_write32(&self, off: u8, val: u32) {
        pci_write32(self.bus, self.device, self.function, off, val)
    }

    /// Class code, subclass and programming interface as one 24-bit value
    /// (Linux pci_dev.class)
    pub fn class24(&self) -> u32 {
        (self.header.class_code as u32) << 16
            | (self.header.subclass as u32) << 8
            | self.header.prog_if as u32
    }

    /// Put the function in D3hot, if it has power management (Linux
    /// pci_set_power_state(PCI_D3hot) for a shutdown): PMCSR power state
    /// 3, then the 10 ms the spec allows before the next access
    pub fn set_power_d3hot(&self) {
        // PMCSR: power state in bits 1:0; PME_Status (bit 15) is
        // write-1-to-clear, keep it out of the write
        const PMCSR: u8 = 4;
        const PME_STATUS: u16 = 1 << 15;
        let Some((pm, _)) = self.caps().find(|&(_, id)| id == cap_id::PM) else {
            return;
        };
        let csr = self.cfg_read16(pm + PMCSR);
        self.cfg_write16(pm + PMCSR, (csr & !(PME_STATUS | 3)) | 3);
        crate::delay::mdelay(10);
    }

    /// The capability list: (offset, ID) pairs (Linux pci_find_capability)
    pub fn caps(&self) -> PciCapIter<impl Fn(u8) -> u8 + '_> {
        let first = if self.cfg_read16(offset::STATUS) & status::CAP_LIST != 0 {
            self.cfg_read8(offset::CAPABILITY_LIST)
        } else {
            0
        };
        PciCapIter::new(move |off| self.cfg_read8(off), first)
    }

    /// IRQ number of this device's INTx pin (arch routing: x86-64 legacy
    /// PIC line from config space; aarch64 DT interrupt-map / virt swizzle)
    pub fn intx_irq(&self) -> Option<u32> {
        crate::arch::irq::pci_intx_irq(
            self.bus,
            self.device,
            self.function,
            self.header.interrupt_pin,
            self.header.interrupt_line,
        )
    }

    /// Unique handler id for this device (bus/device/function)
    fn irq_id(&self) -> usize {
        ((self.bus as usize) << 16) | ((self.device as usize) << 8) | (self.function as usize)
    }

    /// Register a (shareable, level-triggered) INTx handler for this device
    /// and enable INTx at the device
    ///
    /// # Returns
    /// The IRQ number on success, or an error description
    pub fn register_irq_handler(
        &self,
        handler: crate::arch::irq::IrqHandler,
        data: *mut (),
    ) -> Result<u32, &'static str> {
        let irq = self.intx_irq().ok_or("No valid IRQ assigned to device")?;
        crate::arch::irq::register_irq_handler(irq, handler, data, self.irq_id())?;

        // Clear INTERRUPT_DISABLE bit in command register to enable interrupts
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd & !command::INTERRUPT_DISABLE,
        );
        Ok(irq)
    }

    /// Unregister this device's INTx handler (device removal / hotplug):
    /// disables INTx at the device first
    ///
    /// # Returns
    /// The IRQ number that was unregistered, or an error
    pub fn unregister_irq_handler(&self) -> Result<u32, &'static str> {
        let irq = self.intx_irq().ok_or("No valid IRQ assigned to device")?;

        // Disable interrupts at device level first (set INTERRUPT_DISABLE bit)
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd | command::INTERRUPT_DISABLE,
        );

        crate::arch::irq::unregister_irq_handler(irq, self.irq_id())?;
        Ok(irq)
    }

    /// Check if this is an xHCI USB controller
    pub fn is_xhci(&self) -> bool {
        self.header.class_code == class::SERIAL_BUS
            && self.header.subclass == subclass::USB
            && self.header.prog_if == prog_if::XHCI
    }

    /// Get a descriptive class name
    pub fn class_name(&self) -> &'static str {
        match (
            self.header.class_code,
            self.header.subclass,
            self.header.prog_if,
        ) {
            (0x0C, 0x03, 0x00) => "USB UHCI",
            (0x0C, 0x03, 0x10) => "USB OHCI",
            (0x0C, 0x03, 0x20) => "USB EHCI",
            (0x0C, 0x03, 0x30) => "USB xHCI",
            (0x0C, 0x03, _) => "USB Controller",
            (0x06, 0x00, _) => "Host Bridge",
            (0x06, 0x01, _) => "ISA Bridge",
            (0x06, 0x04, _) => "PCI Bridge",
            (0x06, _, _) => "Bridge",
            (0x01, _, _) => "Mass Storage",
            (0x02, _, _) => "Network",
            (0x03, _, _) => "Display",
            (0x04, _, _) => "Multimedia",
            _ => "Unknown",
        }
    }
}

/// Implement BusDevice for PciDevice to participate in bus/driver model
impl BusDevice for PciDevice {
    fn name(&self) -> &str {
        self.class_name()
    }

    fn bus_id(&self) -> String {
        use alloc::format;
        format!(
            "{:04x}:{:02x}:{:02x}.{:x}",
            0, // segment
            self.bus,
            self.device,
            self.function
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Enumerate all devices on a PCI bus
pub fn enumerate_bus() -> Vec<PciDevice> {
    let mut devices = Vec::new();

    // Scan bus 0 (we could scan more buses via PCI bridges)
    for dev in 0..32 {
        // Check function 0 first
        if let Some(pci_dev) = PciDevice::read(0, dev, 0) {
            let is_multifunction = pci_dev.header.is_multifunction();
            devices.push(pci_dev);

            // If multi-function, scan other functions
            if is_multifunction {
                for func in 1..8 {
                    if let Some(pci_dev) = PciDevice::read(0, dev, func) {
                        devices.push(pci_dev);
                    }
                }
            }
        }
    }

    devices
}

// ============================================================================
// PCI Bus Implementation (Bus/Driver Model)
// ============================================================================

/// PCI bus implementing the Bus trait for the bus/driver model
pub struct PciBus {
    /// Discovered PCI devices
    devices: Vec<PciDevice>,
    /// Registered drivers for PCI devices
    drivers: Vec<Box<dyn BusDriver>>,
    /// Probed devices (devices that have been matched to drivers)
    probed_devices: Vec<Box<dyn Device>>,
}

impl PciBus {
    /// Create a new PCI bus (does not enumerate yet)
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            drivers: Vec::new(),
            probed_devices: Vec::new(),
        }
    }
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus for PciBus {
    fn name(&self) -> &str {
        "pci"
    }

    fn probed_devices(&self) -> &[Box<dyn Device>] {
        &self.probed_devices
    }

    fn register_driver(&mut self, driver: Box<dyn BusDriver>) {
        printkln!("PCI: Registered driver '{}'", driver.name());
        self.drivers.push(driver);
    }

    fn enumerate(&mut self, ctx: &mut BusContext) {
        // Initialize PCI config access if not already done
        if !is_initialized() {
            #[cfg(target_arch = "x86_64")]
            {
                init_port_io();
                printkln!("PCI: Using port I/O config access");
            }

            #[cfg(target_arch = "aarch64")]
            {
                use crate::arch::{CurrentArch, IoremapOps};
                // ARM: Use ECAM with QEMU virt address (from DTB: reg = <0x40 0x10000000 ...>)
                // ECAM needs 1MB for bus 0 (32 devices × 8 functions × 4KB)
                let ecam_phys = 0x40_1000_0000u64; // QEMU virt high ECAM
                let ecam_size = 0x10_0000u64; // 1MB for bus 0
                let ecam_virt = CurrentArch::ioremap(ecam_phys, ecam_size)
                    .expect("PCI: Failed to ioremap ECAM region");
                unsafe {
                    init_ecam(ecam_virt);
                }
                printkln!(
                    "PCI: Using ECAM config access at phys {:#x} -> virt {:p}",
                    ecam_phys,
                    ecam_virt
                );
            }
        }

        let _ = ctx; // Suppress unused warning
        printkln!("PCI: Enumerating bus 0...");

        // Scan bus 0 for devices
        for dev in 0..32 {
            if let Some(pci_dev) = PciDevice::read(0, dev, 0) {
                let is_multifunction = pci_dev.header.is_multifunction();

                printkln!(
                    "PCI: Found {} at {}",
                    pci_dev.class_name(),
                    BusDevice::bus_id(&pci_dev)
                );
                self.devices.push(pci_dev);

                // Check other functions if multi-function device
                if is_multifunction {
                    for func in 1..8 {
                        if let Some(pci_dev) = PciDevice::read(0, dev, func) {
                            printkln!(
                                "PCI: Found {} at {}",
                                pci_dev.class_name(),
                                BusDevice::bus_id(&pci_dev)
                            );
                            self.devices.push(pci_dev);
                        }
                    }
                }
            }
        }

        printkln!("PCI: Found {} device(s)", self.devices.len());

        // Assign BAR addresses for any unassigned BARs (cross-platform)
        //
        // On x86 with BIOS: BARs are pre-assigned, this loop does nothing
        // On ARM with direct boot: BARs are 0, this allocates addresses
        //
        // Following Linux kernel pattern: pci_assign_unassigned_resources()
        for device in &mut self.devices {
            device.assign_all_bars();
            // Enable memory space access (needed for newly assigned BARs)
            device.enable_memory_space();
        }

        // Firmware hand-offs and chipset fixups, before any driver
        // touches a device (Linux FIXUP_FINAL, pci_bus_add_device)
        super::quirks::fixup_final(&self.devices);

        // Match devices to drivers and probe
        for device in &self.devices {
            for driver in &self.drivers {
                if driver.matches(device) {
                    printkln!(
                        "PCI: Driver '{}' matched device at {}",
                        driver.name(),
                        BusDevice::bus_id(device)
                    );

                    match driver.probe(device, ctx) {
                        Ok(dev_instance) => {
                            printkln!("PCI: Successfully probed '{}'", dev_instance.name());
                            self.probed_devices.push(dev_instance);
                        }
                        Err(e) => {
                            printkln!("PCI: Failed to probe: {:?}", e);
                        }
                    }

                    // Only match first driver per device
                    break;
                }
            }
        }
    }

    fn is_root(&self) -> bool {
        true // PCI is a root bus
    }

    /// Remove a device from this PCI bus (hotplug support)
    ///
    /// Following Linux kernel PCI hotplug patterns:
    /// 1. Find the device by bus_id
    /// 2. Find the driver that probed this device
    /// 3. Call driver.remove() for cleanup
    /// 4. Remove from probed_devices
    /// 5. Remove from devices list
    fn remove_device(&mut self, bus_id: &str) -> Result<(), DriverError> {
        printkln!("PCI: Removing device at {}", bus_id);

        // Find the device index
        let device_idx = self
            .devices
            .iter()
            .position(|d| BusDevice::bus_id(d) == bus_id);

        let device_idx = match device_idx {
            Some(idx) => idx,
            None => {
                printkln!("PCI: Device {} not found", bus_id);
                return Err(DriverError::MissingResource);
            }
        };

        // Get reference to device for driver matching
        let device = &self.devices[device_idx];

        // Find matching driver and call remove()
        for driver in &self.drivers {
            if driver.matches(device) {
                printkln!(
                    "PCI: Calling driver '{}' remove for {}",
                    driver.name(),
                    bus_id
                );

                // Call driver's remove callback
                if let Err(e) = driver.remove(device) {
                    printkln!("PCI: Driver remove failed: {:?}", e);
                    return Err(e);
                }

                break;
            }
        }

        // Remove from probed_devices list
        // The Device trait has bus_id() that returns Option<&str>
        self.probed_devices.retain(|dev| {
            if let Some(dev_bus_id) = dev.bus_id() {
                dev_bus_id != bus_id
            } else {
                true // Keep devices without bus_id tracking
            }
        });

        // Remove from devices list
        self.devices.remove(device_idx);

        printkln!("PCI: Device {} removed successfully", bus_id);
        Ok(())
    }
}

// ============================================================================
// DMA Support
// ============================================================================

impl DmaDevice for PciDevice {
    fn dma_config(&self) -> &DmaConfig {
        &self.dma_config
    }

    fn dma_config_mut(&mut self) -> &mut DmaConfig {
        &mut self.dma_config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk(cfg: &[u8; 256], first: u8) -> Vec<(u8, u8)> {
        PciCapIter::new(|off| cfg[off as usize], first).collect()
    }

    #[test]
    fn cap_list_walk() {
        let mut cfg = [0u8; 256];
        // 0x40: MSI-X -> 0x50: vendor -> 0x62 (low bits ignored): vendor -> end
        cfg[0x40] = cap_id::MSIX;
        cfg[0x41] = 0x50;
        cfg[0x50] = cap_id::VNDR;
        cfg[0x51] = 0x63;
        cfg[0x60] = cap_id::VNDR;
        cfg[0x61] = 0;
        assert_eq!(
            walk(&cfg, 0x40),
            [
                (0x40, cap_id::MSIX),
                (0x50, cap_id::VNDR),
                (0x60, cap_id::VNDR)
            ]
        );
        assert!(walk(&cfg, 0).is_empty());
        // A pointer into the standard header ends the list
        cfg[0x61] = 0x10;
        assert_eq!(walk(&cfg, 0x40).len(), 3);
    }

    #[test]
    fn cap_list_loop_is_bounded() {
        let mut cfg = [0u8; 256];
        cfg[0x40] = cap_id::VNDR;
        cfg[0x41] = 0x40; // points at itself
        assert_eq!(walk(&cfg, 0x40).len(), CAP_TTL as usize);
        // An all-ones read (device gone) ends the walk
        let gone = [0xFFu8; 256];
        assert!(walk(&gone, 0x40).is_empty());
    }
}

#[cfg(test)]
mod bar_size_tests {
    use super::bar_size_from_mask;

    #[test]
    fn bar_size_masks() {
        // 16 KiB 32-bit memory BAR, prefetchable bit set
        assert_eq!(bar_size_from_mask(false, 0xFFFF_C008, 0), 0x4000);
        // 64-bit BAR decoding only 40 address bits (upper bits hardwired 0)
        assert_eq!(bar_size_from_mask(false, 0xFFFF_C00C, 0x0000_00FF), 0x4000);
        // 8 GiB 64-bit BAR
        assert_eq!(
            bar_size_from_mask(false, 0x0000_000C, 0xFFFF_FFFE),
            0x2_0000_0000
        );
        // 32-byte I/O BAR whose upper 16 bits read 0
        assert_eq!(bar_size_from_mask(true, 0x0000_FFE1, 0), 0x20);
        assert_eq!(bar_size_from_mask(false, 0, 0), 0);
    }
}
