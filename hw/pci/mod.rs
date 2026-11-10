//! PCI Host Controller Driver
//!
//! Provides PCI configuration space access via I/O ports CF8/CFC
//! and bus enumeration for device discovery.
//!
//! Functions are registered on the device core (`driver.rs`).

pub mod driver;
pub mod intx;
pub mod msix;
pub mod quirks;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Once;

use crate::hw::dma::{DmaConfig, DmaDevice};
use crate::irq::{IrqHandler, IrqRegistration};
use crate::printkln;
use crate::util::error::KernelError;
use crate::util::kalloc::box_nofail;

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

    use crate::arch::{ArchBusOps, CurrentArch};

    // The platform's MMIO window for BARs (must not overlap other
    // mappings)
    const MMIO_START: u64 = CurrentArch::PCI_MMIO.0;
    const MMIO_END: u64 = CurrentArch::PCI_MMIO.1;

    /// Current allocation pointer (atomic for thread-safety)
    static NEXT_ADDR: AtomicU64 = AtomicU64::new(MMIO_START);

    /// Allocate a BAR address with the given size and alignment
    ///
    /// Returns None if the MMIO space is exhausted.
    pub fn allocate(size: u64) -> Option<u64> {
        loop {
            let current = NEXT_ADDR.load(Ordering::Relaxed);
            let (aligned, next) = place(current, size)?;

            // Try to update atomically
            match NEXT_ADDR.compare_exchange(current, next, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_) => return Some(aligned),
                Err(_) => continue, // Retry on contention
            }
        }
    }

    /// Where a BAR of `size` goes with the window's free space starting
    /// at `current`: (its address, the new start). BARs are naturally
    /// aligned powers of two; a size the device reports that is not one,
    /// or that would run past the window (or past 2^64, which a 64-bit
    /// BAR can claim), gets None (Linux pci_assign_resource fails).
    pub(super) fn place(current: u64, size: u64) -> Option<(u64, u64)> {
        if !size.is_power_of_two() {
            return None;
        }
        let aligned = current.checked_next_multiple_of(size)?;
        let next = aligned.checked_add(size)?;
        (next <= MMIO_END).then_some((aligned, next))
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
        let new = (old & mask) | (u32::from(val) << shift);
        self.write32(bus, dev, func, offset & 0xFC, new);
    }

    /// Write 8-bit value (default: read-modify-write, as `write16`)
    fn write8(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u8) {
        let shift = (offset & 3) * 8;
        let mask = !(0xFF << shift);
        let old = self.read32(bus, dev, func, offset & 0xFC);
        let new = (old & mask) | (u32::from(val) << shift);
        self.write32(bus, dev, func, offset & 0xFC, new);
    }
}

/// ECAM (Enhanced Configuration Access Mechanism) for PCIe
///
/// Memory-mapped PCI config space access. Works on all architectures.
/// Address formula: Base + (Bus << 20) | (Dev << 15) | (Func << 12) | Offset
pub struct EcamConfigAccess {
    /// The mapped ECAM window (bus 0 only: 1 MB)
    regs: crate::hw::mmio::IoMem,
}

impl EcamConfigAccess {
    /// ECAM accessor over a mapped window
    pub const fn new(regs: crate::hw::mmio::IoMem) -> Self {
        Self { regs }
    }

    /// The window offset of `reg` of bus/dev/func (None: no such device)
    fn off(dev: u8, func: u8, bus: u8, reg: u8) -> Option<usize> {
        (dev <= 31 && func <= 7).then_some(
            ((bus as usize) << 20)
                | ((dev as usize) << 15)
                | ((func as usize) << 12)
                | reg as usize,
        )
    }
}

/// Out-of-window or misaligned accesses read as all ones (no device, as
/// a master abort reads) and writes are dropped
impl PciConfigAccess for EcamConfigAccess {
    fn read32(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
        Self::off(dev, func, bus, offset)
            .and_then(|o| self.regs.try_read32(o))
            .unwrap_or(u32::MAX)
    }

    fn write32(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
        if let Some(o) = Self::off(dev, func, bus, offset) {
            self.regs.try_write32(o, val);
        }
    }

    fn read16(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
        Self::off(dev, func, bus, offset & 0xFE)
            .and_then(|o| self.regs.try_read16(o))
            .unwrap_or(u16::MAX)
    }

    fn read8(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
        Self::off(dev, func, bus, offset)
            .and_then(|o| self.regs.try_read8(o))
            .unwrap_or(u8::MAX)
    }

    fn write16(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
        if let Some(o) = Self::off(dev, func, bus, offset & 0xFE) {
            self.regs.try_write16(o, val);
        }
    }

    fn write8(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u8) {
        if let Some(o) = Self::off(dev, func, bus, offset) {
            self.regs.try_write8(o, val);
        }
    }
}

// ============================================================================
// Global PCI Config Accessor
// ============================================================================

/// Global PCI config access mechanism
static PCI_CONFIG: Once<&'static dyn PciConfigAccess> = Once::new();

/// Initialize PCI config access with a static accessor (x86 port I/O)
pub fn init_config(access: &'static dyn PciConfigAccess) {
    PCI_CONFIG.call_once(|| access);
}

/// Initialize PCI config access with ECAM (memory-mapped)
///
/// # Safety
/// `len` bytes at `base_addr` are a mapped ECAM window, never unmapped.
pub unsafe fn init_ecam(base_addr: *mut u8, len: usize) {
    let base = core::ptr::NonNull::new(base_addr).expect("ECAM base");
    // SAFETY: the caller's mapping, per this fn's contract
    let regs = unsafe { crate::hw::mmio::IoMem::new(base, len) };
    // Leak a box to get 'static lifetime (boot-time setup)
    let accessor = Box::leak(box_nofail(EcamConfigAccess::new(regs)));
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
        .expect("PCI config access not initialized - call init_config() or init_ecam() first")
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
    let mask = u64::from(hi) << 32 | u64::from(lo);
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
            Some(u64::from(bar & !0x3))
        } else {
            // Memory BAR
            let bar_type = (bar >> 1) & 0x3;
            match bar_type {
                0 => {
                    // 32-bit BAR
                    Some(u64::from(bar & !0xF))
                }
                2 => {
                    // 64-bit BAR - need to read next BAR too
                    if bar_index >= 5 {
                        return None;
                    }
                    let high = u64::from(self.header.bar[bar_index + 1]);
                    Some((high << 32) | u64::from(bar & !0xF))
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
                        self.bus_id()
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
        u32::from(self.header.class_code) << 16
            | u32::from(self.header.subclass) << 8
            | u32::from(self.header.prog_if)
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
        crate::time::delay::mdelay(10);
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
        crate::irq::pci_intx_irq(
            self.bus,
            self.device,
            self.function,
            self.header.interrupt_pin,
            self.header.interrupt_line,
        )
    }

    /// Request this device's (shareable, level-triggered) INTx line for
    /// `handler` and enable INTx at the device (Linux request_irq on
    /// pdev->irq; INTx is enabled as pci_enable_device does). Dropping
    /// the registration frees the line (Linux free_irq; INTx stays
    /// enabled at the device, so the driver first stops the device
    /// interrupting: a shared level-triggered line left asserted with
    /// no handler to ack it is disabled as nobody cared)
    ///
    /// # Returns
    /// The registration; NoDevice without an INTx line, the IRQ table's
    /// error otherwise
    pub fn request_irq<T: IrqHandler + 'static>(
        &self,
        handler: Arc<T>,
    ) -> Result<IrqRegistration<T>, KernelError> {
        let irq = self.intx_irq().ok_or(KernelError::NoDevice)?;
        let reg = crate::irq::request_irq(irq, handler)?;
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd & !command::INTERRUPT_DISABLE,
        );
        Ok(reg)
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

impl PciDevice {
    /// Slot name "0000:BB:DD.F" (Linux pci_name)
    pub fn bus_id(&self) -> String {
        alloc::format!(
            "{:04x}:{:02x}:{:02x}.{:x}",
            0,
            self.bus,
            self.device,
            self.function
        )
    }
}

/// Set up configuration access once (the arch's mechanism: port I/O on
/// x86, ECAM on arm64)
fn config_init() {
    if !is_initialized() {
        use crate::arch::ArchBusOps;
        crate::arch::CurrentArch::pci_config_init();
    }
}

/// Scan bus 0, assign unassigned BARs, run the final fixups, then
/// register every function (Linux pci_scan_root_bus,
/// pci_assign_unassigned_resources, pci_bus_add_devices)
pub fn pci_scan() {
    config_init();
    driver::pci_bus_init();
    let mut devices = Vec::new();
    for dev in 0..32 {
        let Some(f0) = PciDevice::read(0, dev, 0) else {
            continue;
        };
        let multi = f0.header.is_multifunction();
        devices.push(f0);
        if multi {
            devices.extend((1..8).filter_map(|f| PciDevice::read(0, dev, f)));
        }
    }
    for d in &devices {
        printkln!("PCI: Found {} at {}", d.class_name(), d.bus_id());
    }
    // On x86 firmware assigned the BARs; on arm64 direct boot they are 0
    for d in &mut devices {
        d.assign_all_bars();
        d.enable_memory_space();
    }
    // Firmware hand-offs and chipset fixups, before any driver
    // touches a device (Linux FIXUP_FINAL, pci_bus_add_device)
    quirks::fixup_final(&devices);
    for d in devices {
        let _ = driver::pci_device_add(d);
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

    #[test]
    fn bar_place() {
        use super::bar_alloc::place;
        let base = 0x1000_0000;
        assert_eq!(
            place(base + 0x10, 0x1000),
            Some((base + 0x1000, base + 0x2000))
        );
        assert_eq!(place(base, 0), None);
        assert_eq!(place(base, 0x3000), None);
        // a 64-bit BAR claiming 2^63 bytes: no wrap, just no room
        assert_eq!(place(base, 1 << 63), None);
        assert_eq!(place(u64::MAX - 0xfff, 0x1000), None);
    }
}
