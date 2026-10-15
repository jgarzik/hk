//! Modern virtio-PCI transport (virtio 1.2 section 4.1; no legacy)
//!
//! Linux reference: drivers/virtio/virtio_pci_modern{,_dev}.c.
//!
//! The device's vendor capabilities locate four structures inside its
//! memory BARs: common configuration, notification area, ISR status and
//! device-specific configuration; each is ioremapped. Interrupts are INTx
//! (shareable, level-triggered): reading the ISR status byte returns the
//! causes and deasserts the line. MSI-X is not used.
//!
//! ## Locking
//!
//! Common configuration is written only during probe (single-threaded
//! bus enumeration). Afterwards the transport touches lock-free state
//! only: config reads (generation-checked), notify writes (under the
//! caller's queue lock) and the ISR byte (IRQ context).

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::{Deref, DerefMut};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Once;

use super::ring::{self, Layout, Vring};
use super::{VirtioIrq, find_driver, status};
use crate::CurrentArch;
use crate::arch::IoremapOps;
use crate::arch::barrier::wmb;
use crate::bus::bus::{BusContext, BusDevice, BusDriver};
use crate::bus::driver::{Device, DriverError};
use crate::bus::pci::{PciDevice, cap_id};
use crate::dma::{DmaCoherent, DmaConfig, DmaDevice};
use crate::printkln;

/// Red Hat / virtio vendor ID
const VENDOR_VIRTIO: u16 = 0x1AF4;
/// Modern device IDs: 0x1040 + virtio device ID
const MODERN_BASE: u16 = 0x1040;
const MODERN_LAST: u16 = 0x107F;

/// virtio_pci_cap.cfg_type
mod cfg_type {
    pub const COMMON: u8 = 1;
    pub const NOTIFY: u8 = 2;
    pub const ISR: u8 = 3;
    pub const DEVICE: u8 = 4;
}

/// struct virtio_pci_common_cfg offsets
mod common {
    pub const DFSELECT: usize = 0x00;
    pub const DF: usize = 0x04;
    pub const GFSELECT: usize = 0x08;
    pub const GF: usize = 0x0C;
    pub const NUM_QUEUES: usize = 0x12;
    pub const STATUS: usize = 0x14;
    pub const CFG_GENERATION: usize = 0x15;
    pub const Q_SELECT: usize = 0x16;
    pub const Q_SIZE: usize = 0x18;
    pub const Q_ENABLE: usize = 0x1C;
    pub const Q_NOFF: usize = 0x1E;
    pub const Q_DESC: usize = 0x20;
    pub const Q_AVAIL: usize = 0x28;
    pub const Q_USED: usize = 0x30;
    /// Size of the structure up to queue_device (all we use)
    pub const LEN: u32 = 0x38;
}

/// ISR status bits
mod isr {
    pub const QUEUE: u8 = 1;
    pub const CONFIG: u8 = 2;
}

/// A virtio_pci_cap: where a structure lives
#[derive(Clone, Copy)]
struct Cap {
    bar: u8,
    off: u32,
    len: u32,
}

/// The structures located by the capability list
#[derive(Default)]
struct Caps {
    common: Option<Cap>,
    notify: Option<Cap>,
    isr: Option<Cap>,
    device: Option<Cap>,
    notify_mul: u32,
}

/// Walk the vendor capabilities; the first of each type wins (spec
/// 4.1.4: drivers use the first one they can)
fn find_caps(pci: &PciDevice) -> Caps {
    let mut c = Caps::default();
    for (pos, id) in pci.caps() {
        if id != cap_id::VNDR || pci.cfg_read8(pos + 2) < 16 {
            continue;
        }
        let bar = pci.cfg_read8(pos + 4);
        if bar > 5 {
            continue; // reserved BAR number: skip (spec)
        }
        let cap = Cap {
            bar,
            off: pci.cfg_read32(pos + 8),
            len: pci.cfg_read32(pos + 12),
        };
        let slot = match pci.cfg_read8(pos + 3) {
            cfg_type::COMMON => &mut c.common,
            cfg_type::NOTIFY if pci.cfg_read8(pos + 2) >= 20 => {
                if c.notify.is_none() {
                    c.notify_mul = pci.cfg_read32(pos + 16);
                }
                &mut c.notify
            }
            cfg_type::ISR => &mut c.isr,
            cfg_type::DEVICE => &mut c.device,
            _ => continue,
        };
        if slot.is_none() {
            *slot = Some(cap);
        }
    }
    c
}

/// ioremap the part of a BAR a capability describes (at most `max` bytes)
fn map_cap(pci: &PciDevice, cap: Cap, max: u32) -> Result<(*mut u8, u32), DriverError> {
    let len = cap.len.min(max);
    let bar = cap.bar as usize;
    let base = match pci.bar_address(bar) {
        Some(b) if pci.bar_is_mmio(bar) && len > 0 => b,
        _ => return Err(DriverError::MissingResource),
    };
    let virt = CurrentArch::ioremap(base + cap.off as u64, len as u64)
        .map_err(|_| DriverError::MissingResource)?;
    Ok((virt, len))
}

/// A virtio device on the modern PCI transport (Linux virtio_pci_device)
pub struct VirtioDevice {
    /// Virtio device ID
    id: u32,
    pci: PciDevice,
    common: *mut u8,
    isr: *const u8,
    device: *mut u8,
    device_len: u32,
    notify: *mut u8,
    notify_len: u32,
    notify_mul: u32,
    /// Negotiated features
    features: u64,
    irq: Once<Arc<dyn VirtioIrq>>,
    /// Interrupts that were ours (stats)
    irqs: AtomicU64,
}

// MMIO pointers into ioremapped BARs, valid for the device's life
unsafe impl Send for VirtioDevice {}
unsafe impl Sync for VirtioDevice {}

impl VirtioDevice {
    /// Locate and map the transport structures
    fn map(pci: PciDevice, id: u32) -> Result<Self, DriverError> {
        let caps = find_caps(&pci);
        let (Some(c), Some(n), Some(i)) = (caps.common, caps.notify, caps.isr) else {
            printkln!("virtio-pci: {} lacks a required capability", pci.bus_id());
            return Err(DriverError::MissingResource);
        };
        let (common, clen) = map_cap(&pci, c, common::LEN)?;
        if clen < common::LEN {
            return Err(DriverError::MissingResource);
        }
        let (notify, notify_len) = map_cap(&pci, n, u32::MAX)?;
        let (isr, _) = map_cap(&pci, i, 1)?;
        let (device, device_len) = match caps.device {
            Some(d) => map_cap(&pci, d, 0x1000)?,
            None => (core::ptr::null_mut(), 0),
        };
        Ok(Self {
            id,
            pci,
            common,
            isr,
            device,
            device_len,
            notify,
            notify_len,
            notify_mul: caps.notify_mul,
            features: 0,
            irq: Once::new(),
            irqs: AtomicU64::new(0),
        })
    }

    fn r8(&self, off: usize) -> u8 {
        unsafe { read_volatile(self.common.add(off)) }
    }

    fn w8(&self, off: usize, v: u8) {
        unsafe { write_volatile(self.common.add(off), v) }
    }

    fn r16(&self, off: usize) -> u16 {
        u16::from_le(unsafe { read_volatile(self.common.add(off) as *const u16) })
    }

    fn w16(&self, off: usize, v: u16) {
        unsafe { write_volatile(self.common.add(off) as *mut u16, v.to_le()) }
    }

    fn r32(&self, off: usize) -> u32 {
        u32::from_le(unsafe { read_volatile(self.common.add(off) as *const u32) })
    }

    fn w32(&self, off: usize, v: u32) {
        unsafe { write_volatile(self.common.add(off) as *mut u32, v.to_le()) }
    }

    /// 64-bit fields as two 32-bit writes, low first (Linux
    /// vp_iowrite64_twopart)
    fn w64(&self, off: usize, v: u64) {
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }

    /// Virtio device ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// PCI address, for messages
    pub fn bus_id(&self) -> alloc::string::String {
        self.pci.bus_id()
    }

    pub fn status(&self) -> u8 {
        self.r8(common::STATUS)
    }

    /// OR bits into the device status
    pub fn add_status(&self, bits: u8) {
        self.w8(common::STATUS, self.status() | bits);
    }

    /// Reset the device and wait until it reports the reset done
    fn reset(&self) -> Result<(), DriverError> {
        self.w8(common::STATUS, 0);
        for _ in 0..1_000_000 {
            if self.status() == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(DriverError::InitFailed)
    }

    fn device_features(&self) -> u64 {
        self.w32(common::DFSELECT, 0);
        let lo = self.r32(common::DF) as u64;
        self.w32(common::DFSELECT, 1);
        let hi = self.r32(common::DF) as u64;
        (hi << 32) | lo
    }

    /// Negotiate features and set FEATURES_OK (spec 3.1.1 steps 4-6)
    fn negotiate(&mut self, driver: u64) -> Result<(), DriverError> {
        let f = super::negotiate(self.device_features(), driver)?;
        self.w32(common::GFSELECT, 0);
        self.w32(common::GF, f as u32);
        self.w32(common::GFSELECT, 1);
        self.w32(common::GF, (f >> 32) as u32);
        self.add_status(status::FEATURES_OK);
        if self.status() & status::FEATURES_OK == 0 {
            return Err(DriverError::Unsupported);
        }
        self.features = f;
        Ok(())
    }

    /// Feature bit `bit` was negotiated
    pub fn has_feature(&self, bit: u32) -> bool {
        self.features & (1 << bit) != 0
    }

    /// Number of queues the device offers
    pub fn num_queues(&self) -> u16 {
        self.r16(common::NUM_QUEUES)
    }

    /// Run `f` (device config reads) until it sees one config generation
    /// (spec 4.1.4.3.1: multi-field reads must be consistent)
    pub fn read_config<T>(&self, f: impl Fn(&Self) -> T) -> T {
        loop {
            let g = self.r8(common::CFG_GENERATION);
            let v = f(self);
            if self.r8(common::CFG_GENERATION) == g {
                return v;
            }
        }
    }

    /// Device config byte (0 if absent)
    pub fn cfg8(&self, off: u32) -> u8 {
        if off >= self.device_len {
            return 0;
        }
        unsafe { read_volatile(self.device.add(off as usize)) }
    }

    /// Device config le16 (0 if absent)
    pub fn cfg16(&self, off: u32) -> u16 {
        if off + 2 > self.device_len || off & 1 != 0 {
            return 0;
        }
        u16::from_le(unsafe { read_volatile(self.device.add(off as usize) as *const u16) })
    }

    /// Set up queue `index` (spec 4.1.5.1.3); before `ready()`
    pub fn setup_vq(&self, index: u16) -> Result<Virtqueue, DriverError> {
        if index >= self.num_queues() {
            return Err(DriverError::MissingResource);
        }
        self.w16(common::Q_SELECT, index);
        if self.r16(common::Q_ENABLE) != 0 {
            return Err(DriverError::InitFailed);
        }
        let num = ring::pick_size(self.r16(common::Q_SIZE)).ok_or(DriverError::MissingResource)?;
        let off = self.r16(common::Q_NOFF) as u64 * self.notify_mul as u64;
        if off + 2 > self.notify_len as u64 {
            return Err(DriverError::MissingResource);
        }
        let lay = Layout::new(num);
        // Zeroed, page-aligned: satisfies every ring part's alignment
        let mem =
            crate::dma::dma_alloc_coherent(self, lay.size).ok_or(DriverError::MissingResource)?;
        let d = mem.dma_addr.0;
        self.w16(common::Q_SIZE, num);
        self.w64(common::Q_DESC, d);
        self.w64(common::Q_AVAIL, d + lay.avail as u64);
        self.w64(common::Q_USED, d + lay.used as u64);
        self.w16(common::Q_ENABLE, 1);
        Ok(Virtqueue {
            ring: unsafe { Vring::new(mem.cpu_addr, num) },
            _mem: mem,
            index,
            notify: unsafe { self.notify.add(off as usize) as *mut u16 },
        })
    }

    /// Register the driver's interrupt callbacks and enable INTx
    pub fn request_irq(self: &Arc<Self>, cb: Arc<dyn VirtioIrq>) -> Result<u32, &'static str> {
        self.irq.call_once(|| cb);
        // The Arc is kept by the driver for the device's life
        self.pci
            .register_irq_handler(vp_interrupt, Arc::as_ptr(self) as *mut ())
    }

    /// Interrupts handled (stats)
    pub fn irqs(&self) -> u64 {
        self.irqs.load(Ordering::Relaxed)
    }

    /// Driver set up: the device may now operate (DRIVER_OK)
    pub fn ready(&self) {
        self.add_status(status::DRIVER_OK);
    }
}

impl DmaDevice for VirtioDevice {
    fn dma_config(&self) -> &DmaConfig {
        &self.pci.dma_config
    }

    fn dma_config_mut(&mut self) -> &mut DmaConfig {
        &mut self.pci.dma_config
    }
}

/// Transport interrupt handler (Linux vp_interrupt; IRQ context)
fn vp_interrupt(_irq: u32, data: *mut ()) -> bool {
    let vdev = unsafe { &*(data as *const VirtioDevice) };
    // Read-to-clear; deasserts the level-triggered line
    let isr = unsafe { read_volatile(vdev.isr) };
    if isr == 0 {
        return false; // shared line: not ours
    }
    vdev.irqs.fetch_add(1, Ordering::Relaxed);
    if let Some(cb) = vdev.irq.get() {
        if isr & isr::CONFIG != 0 {
            cb.config_changed();
        }
        if isr & isr::QUEUE != 0 {
            cb.vq_interrupt();
        }
    }
    true
}

/// A split virtqueue in coherent DMA memory with its doorbell
pub struct Virtqueue {
    ring: Vring,
    /// Ring memory (lives as long as the queue: the device keeps using it)
    _mem: DmaCoherent,
    index: u16,
    notify: *mut u16,
}

unsafe impl Send for Virtqueue {}
unsafe impl Sync for Virtqueue {}

impl Virtqueue {
    /// Notify the device of new buffers if it wants to be (Linux
    /// virtqueue_kick)
    pub fn kick(&self) {
        if self.ring.needs_notify() {
            // Ring writes before the doorbell MMIO write
            wmb();
            unsafe { write_volatile(self.notify, self.index.to_le()) };
        }
    }
}

impl Deref for Virtqueue {
    type Target = Vring;
    fn deref(&self) -> &Vring {
        &self.ring
    }
}

impl DerefMut for Virtqueue {
    fn deref_mut(&mut self) -> &mut Vring {
        &mut self.ring
    }
}

/// PCI driver for modern virtio devices; binds the virtio driver
/// registered for the device ID (Linux virtio_pci_probe + virtio_dev_probe)
pub struct VirtioPciDriver;

fn virtio_id(pci: &PciDevice) -> Option<u32> {
    let h = &pci.header;
    if h.vendor_id == VENDOR_VIRTIO && (MODERN_BASE..=MODERN_LAST).contains(&h.device_id) {
        Some((h.device_id - MODERN_BASE) as u32)
    } else {
        None
    }
}

/// Reset, acknowledge and negotiate (spec 3.1.1 steps 1-6)
fn vp_init(pci: &PciDevice, id: u32, driver: u64) -> Result<VirtioDevice, DriverError> {
    let mut pci = pci.clone();
    // Virtio devices address all 64 bits (Linux virtio_pci_modern_probe)
    pci.set_dma_mask_and_coherent(u64::MAX);
    pci.enable_memory_space();
    pci.enable_bus_master();
    let mut vdev = VirtioDevice::map(pci, id)?;
    vdev.reset()?;
    vdev.add_status(status::ACKNOWLEDGE);
    vdev.add_status(status::DRIVER);
    if let Err(e) = vdev.negotiate(driver) {
        vdev.add_status(status::FAILED);
        return Err(e);
    }
    Ok(vdev)
}

impl BusDriver for VirtioPciDriver {
    fn name(&self) -> &str {
        "virtio-pci"
    }

    fn matches(&self, device: &dyn BusDevice) -> bool {
        device
            .as_any()
            .downcast_ref::<PciDevice>()
            .and_then(virtio_id)
            .is_some_and(|id| find_driver(id).is_some())
    }

    fn probe(
        &self,
        device: &dyn BusDevice,
        _ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError> {
        let pci = device
            .as_any()
            .downcast_ref::<PciDevice>()
            .ok_or(DriverError::Unsupported)?;
        let id = virtio_id(pci).ok_or(DriverError::Unsupported)?;
        let drv = find_driver(id).ok_or(DriverError::Unsupported)?;
        let vdev = Arc::new(vp_init(pci, id, drv.features())?);
        printkln!(
            "virtio-pci: {} device {} features {:#x}",
            vdev.bus_id(),
            id,
            vdev.features
        );
        drv.probe(Arc::clone(&vdev)).inspect_err(|_| {
            vdev.add_status(status::FAILED);
        })
    }
}
