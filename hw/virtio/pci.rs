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
//! Common configuration is written under the virtio device's lock
//! (bus probe and driver remove: status, features, queue setup, reset)
//! or the PCI function's (transport probe and remove). Otherwise the
//! transport touches lock-free state only: config reads
//! (generation-checked), notify writes (under the caller's queue lock)
//! and the ISR byte (IRQ context). The INTx registration
//! (`VirtioDevice.irq`, which owns the driver's interrupt callbacks) is
//! a spin leaf, thread context only: set by `request_irq` (driver probe)
//! and taken by `free_irq` (driver remove, transport remove), which
//! drops it (`IRQ_TABLE`) after unlocking.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

use super::ring::{self, Layout, Vring};
use super::{VirtioIrq, status};
use crate::arch::barrier::wmb;
use crate::hw::dma::{DmaCoherent, DmaConfig, DmaDevice};
use crate::hw::mmio::IoMem;
use crate::hw::pci::{PciDevice, cap_id};
use crate::irq::{IrqHandler, IrqRegistration, IrqReturn};
use crate::printkln;
use crate::sync::spin::Mutex;
use crate::util::error::KernelError;
use crate::util::kalloc::{try_arc, try_box};

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
fn map_cap(pci: &PciDevice, cap: Cap, max: u32) -> Result<IoMem, KernelError> {
    let len = cap.len.min(max);
    let bar = cap.bar as usize;
    let base = match pci.bar_address(bar) {
        Some(b) if pci.bar_is_mmio(bar) && len > 0 => b,
        _ => return Err(KernelError::NoDevice),
    };
    // SAFETY: part of a memory BAR of this device, which the capability
    // places there: registers, not RAM
    unsafe { IoMem::ioremap(base + u64::from(cap.off), len as usize) }.ok_or(KernelError::NoDevice)
}

/// A virtio device on the modern PCI transport (Linux virtio_pci_device)
pub struct VirtioDevice {
    /// Virtio device ID
    id: u32,
    pci: PciDevice,
    /// Common configuration (spec 4.1.4.3), little-endian registers
    common: IoMem,
    isr: IoMem,
    /// Device-specific configuration (None if the device has none)
    device: Option<IoMem>,
    notify: IoMem,
    notify_mul: u32,
    /// Negotiated features: written by `negotiate` in the virtio bus
    /// probe under the device lock, before the driver's probe runs;
    /// read by the bound driver and the sysfs `features` file (Linux
    /// vdev->features, a plain field under the same rule)
    features: AtomicU64,
    /// The INTx handler with the bound driver's interrupt callbacks
    /// (Linux vq->callback and config_changed): between `request_irq`
    /// and `free_irq`
    irq: Mutex<Option<IrqRegistration<VpIntx>>>,
    /// Interrupts that were ours (stats)
    irqs: AtomicU64,
}

impl VirtioDevice {
    /// Locate and map the transport structures
    fn map(pci: PciDevice, id: u32) -> Result<Self, KernelError> {
        let caps = find_caps(&pci);
        let (Some(c), Some(n), Some(i)) = (caps.common, caps.notify, caps.isr) else {
            printkln!("virtio-pci: {} lacks a required capability", pci.bus_id());
            return Err(KernelError::NoDevice);
        };
        let common = map_cap(&pci, c, common::LEN)?;
        if common.len() < common::LEN as usize {
            return Err(KernelError::NoDevice);
        }
        let notify = map_cap(&pci, n, u32::MAX)?;
        let isr = map_cap(&pci, i, 1)?;
        let device = match caps.device {
            Some(d) => Some(map_cap(&pci, d, 0x1000)?),
            None => None,
        };
        Ok(Self {
            id,
            pci,
            common,
            isr,
            device,
            notify,
            notify_mul: caps.notify_mul,
            features: AtomicU64::new(0),
            irq: Mutex::new(None),
            irqs: AtomicU64::new(0),
        })
    }

    fn r8(&self, off: usize) -> u8 {
        self.common.read8(off)
    }

    fn w8(&self, off: usize, v: u8) {
        self.common.write8(off, v)
    }

    fn r16(&self, off: usize) -> u16 {
        u16::from_le(self.common.read16(off))
    }

    fn w16(&self, off: usize, v: u16) {
        self.common.write16(off, v.to_le())
    }

    fn r32(&self, off: usize) -> u32 {
        u32::from_le(self.common.read32(off))
    }

    fn w32(&self, off: usize, v: u32) {
        self.common.write32(off, v.to_le())
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
    /// (Linux virtio_reset_device): it stops using its queues and
    /// raising interrupts
    pub fn reset(&self) -> Result<(), KernelError> {
        self.w8(common::STATUS, 0);
        for _ in 0..1_000_000 {
            if self.status() == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(KernelError::Io)
    }

    pub fn device_features(&self) -> u64 {
        self.w32(common::DFSELECT, 0);
        let lo = u64::from(self.r32(common::DF));
        self.w32(common::DFSELECT, 1);
        let hi = u64::from(self.r32(common::DF));
        (hi << 32) | lo
    }

    /// Negotiate features and set FEATURES_OK (spec 3.1.1 steps 4-6)
    pub fn negotiate(&self, driver: u64) -> Result<(), KernelError> {
        let f = super::negotiate(self.device_features(), driver)?;
        self.w32(common::GFSELECT, 0);
        self.w32(common::GF, f as u32);
        self.w32(common::GFSELECT, 1);
        self.w32(common::GF, (f >> 32) as u32);
        self.add_status(status::FEATURES_OK);
        if self.status() & status::FEATURES_OK == 0 {
            return Err(KernelError::NoDevice);
        }
        self.features.store(f, Ordering::Release);
        Ok(())
    }

    /// Negotiated features
    pub fn features(&self) -> u64 {
        self.features.load(Ordering::Acquire)
    }

    /// Feature bit `bit` was negotiated
    pub fn has_feature(&self, bit: u32) -> bool {
        self.features() & (1 << bit) != 0
    }

    /// Vendor id (Linux virtio_pci_modern_probe: the PCI subsystem vendor)
    pub fn vendor(&self) -> u32 {
        u32::from(self.pci.header.subsystem_vendor_id)
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
        self.device
            .and_then(|d| d.try_read8(off as usize))
            .unwrap_or(0)
    }

    /// Device config le16 (0 if absent)
    pub fn cfg16(&self, off: u32) -> u16 {
        u16::from_le(
            self.device
                .and_then(|d| d.try_read16(off as usize))
                .unwrap_or(0),
        )
    }

    /// Device config le32 (0 if absent)
    pub fn cfg32(&self, off: u32) -> u32 {
        u32::from_le(
            self.device
                .and_then(|d| d.try_read32(off as usize))
                .unwrap_or(0),
        )
    }

    /// Device config le64 as two 32-bit reads, low first (spec 4.1.3.1;
    /// wrap in `read_config` for a consistent value)
    pub fn cfg64(&self, off: u32) -> u64 {
        u64::from(self.cfg32(off)) | (u64::from(self.cfg32(off.saturating_add(4))) << 32)
    }

    /// Set up queue `index` (spec 4.1.5.1.3); before `ready()`
    pub fn setup_vq(&self, index: u16) -> Result<Virtqueue, KernelError> {
        if index >= self.num_queues() {
            return Err(KernelError::NoDevice);
        }
        self.w16(common::Q_SELECT, index);
        if self.r16(common::Q_ENABLE) != 0 {
            return Err(KernelError::Io);
        }
        let num = ring::pick_size(self.r16(common::Q_SIZE)).ok_or(KernelError::NoDevice)?;
        let off = self.r16(common::Q_NOFF) as usize * self.notify_mul as usize;
        let notify = self.notify.sub(off, 2).ok_or(KernelError::NoDevice)?;
        let lay = Layout::new(num);
        // Zeroed, page-aligned: satisfies every ring part's alignment
        let mem =
            crate::hw::dma::dma_alloc_coherent(self, lay.size).ok_or(KernelError::NoDevice)?;
        let d = mem.dma_addr().0;
        self.w16(common::Q_SIZE, num);
        self.w64(common::Q_DESC, d);
        self.w64(common::Q_AVAIL, d + lay.avail as u64);
        self.w64(common::Q_USED, d + lay.used as u64);
        self.w16(common::Q_ENABLE, 1);
        Ok(Virtqueue {
            // SAFETY: `mem` is zeroed DMA memory of `lay.size` bytes for
            // `num` entries, owned by the queue (`mem`) for the ring's life
            ring: unsafe { Vring::new(mem.cpu_addr(), num) },
            mem,
            owner: core::ptr::from_ref::<Self>(self) as usize,
            index,
            notify,
        })
    }

    /// Register the driver's interrupt callbacks and enable INTx (Linux
    /// find_vqs: vp_request_intx); Busy if already requested. Probe and
    /// remove, which request and free, are serialized by the virtio
    /// device's lock
    pub fn request_irq(self: &Arc<Self>, cb: Arc<dyn VirtioIrq>) -> Result<u32, KernelError> {
        if self.irq.lock().is_some() {
            return Err(KernelError::Busy);
        }
        let h = try_arc(VpIntx {
            vdev: self.clone(),
            cb,
        })?;
        // Holds the device until `free_irq` (the driver's remove)
        let reg = self.pci.request_irq(h)?;
        let irq = reg.irq();
        *self.irq.lock() = Some(reg);
        Ok(irq)
    }

    /// Reset the device, then free the rings of `vqs` (Linux del_vqs:
    /// vp_del_vqs after virtio_reset_device). If the reset does not
    /// complete the rings are leaked, never freed under a live device;
    /// the error says so (callers then keep their other DMA memory).
    /// Queues of another device are leaked too.
    pub fn del_vqs(&self, vqs: impl IntoIterator<Item = Virtqueue>) -> Result<(), KernelError> {
        let r = self.reset();
        for vq in vqs {
            // A DmaCoherent not freed is leaked (it has no Drop)
            if r.is_ok() && vq.owner == core::ptr::from_ref::<Self>(self) as usize {
                // SAFETY: the device is reset: it no longer reads or
                // writes the ring, and the ring (`vq.ring`, the only CPU
                // pointer into it) goes with `vq` here
                unsafe { crate::hw::dma::dma_free_coherent(self, vq.mem) };
            }
        }
        r
    }

    /// Unregister the interrupt handler and drop the driver's callbacks
    /// (Linux del_vqs: vp_del_vqs -> free_irq); a later bind may
    /// `request_irq` again. No handler is running once it returns. The
    /// caller resets the device first, so it is not left asserting a
    /// shared level-triggered line nobody acks.
    pub fn free_irq(&self) {
        // Dropped outside the lock: the callbacks may own the driver
        let irq = self.irq.lock().take();
        drop(irq);
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

/// The transport's INTx handler: the device and its driver's callbacks
struct VpIntx {
    vdev: Arc<VirtioDevice>,
    cb: Arc<dyn VirtioIrq>,
}

impl IrqHandler for VpIntx {
    fn handle(&self, _irq: u32) -> IrqReturn {
        vp_interrupt(&self.vdev, &*self.cb)
    }
}

/// Transport interrupt handler (Linux vp_interrupt; IRQ context)
fn vp_interrupt(vdev: &VirtioDevice, cb: &dyn VirtioIrq) -> IrqReturn {
    // Read-to-clear; deasserts the level-triggered line
    let isr = vdev.isr.read8(0);
    if isr == 0 {
        return IrqReturn::None; // shared line: not ours
    }
    vdev.irqs.fetch_add(1, Ordering::Relaxed);
    if isr & isr::CONFIG != 0 {
        cb.config_changed();
    }
    if isr & isr::QUEUE != 0 {
        cb.vq_interrupt();
    }
    IrqReturn::Handled
}

/// A split virtqueue in coherent DMA memory with its doorbell
///
/// Its ring is freed only by `VirtioDevice::del_vqs`, after the device
/// is reset: a queue dropped otherwise leaks its ring (the device may
/// still use it).
pub struct Virtqueue {
    ring: Vring,
    /// Ring memory (lives as long as the queue: the device keeps using it)
    mem: DmaCoherent,
    /// Address of the `VirtioDevice` that set it up: only its reset
    /// frees the ring
    owner: usize,
    index: u16,
    /// This queue's 2-byte doorbell
    notify: IoMem,
}

// SAFETY: the ring is DMA memory reached under the driver's queue lock
// (Vring's own rule); the doorbell is an IoMem
unsafe impl Send for Virtqueue {}
// SAFETY: as above
unsafe impl Sync for Virtqueue {}

impl Virtqueue {
    /// Notify the device of new buffers if it wants to be (Linux
    /// virtqueue_kick)
    pub fn kick(&self) {
        if self.ring.needs_notify() {
            // Ring writes before the doorbell MMIO write
            wmb();
            self.notify.write16(0, self.index.to_le());
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

/// The virtio PCI driver (Linux virtio-pci: every Red Hat/Qumranet
/// function); binds the virtio driver registered for the device ID
/// (virtio_pci_probe + virtio_dev_probe)
pub static VIRTIO_PCI_DRIVER: crate::base::Driver = crate::base::Driver::new(
    "virtio-pci",
    &crate::hw::pci::driver::PCI_BUS,
    Some("virtio_pci"),
    &crate::hw::pci::driver::PciIds(&[crate::hw::pci::driver::PciDeviceId::vendor(VENDOR_VIRTIO)]),
    virtio_pci_probe,
);

fn virtio_id(pci: &PciDevice) -> Option<u32> {
    let h = &pci.header;
    (h.vendor_id == VENDOR_VIRTIO && (MODERN_BASE..=MODERN_LAST).contains(&h.device_id))
        .then(|| u32::from(h.device_id - MODERN_BASE))
}

/// Map, reset and acknowledge (spec 3.1.1 steps 1-2; Linux
/// register_virtio_device); the virtio bus probe negotiates
fn vp_init(pci: &PciDevice, id: u32) -> Result<VirtioDevice, KernelError> {
    let mut pci = pci.clone();
    // Virtio devices address all 64 bits (Linux virtio_pci_modern_probe)
    pci.set_dma_mask_and_coherent(u64::MAX);
    pci.enable_memory_space();
    pci.enable_bus_master();
    let vdev = VirtioDevice::map(pci, id)?;
    vdev.reset()?;
    vdev.add_status(status::ACKNOWLEDGE);
    Ok(vdev)
}

/// A bound virtio-pci function: its virtio device
struct VirtioPciDev {
    pci: PciDevice,
    dev: Arc<crate::base::Device>,
    vdev: Arc<VirtioDevice>,
    index: u32,
}

impl crate::base::Bound for VirtioPciDev {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// Linux virtio_pci_remove: unregister_virtio_device (the virtio
    /// driver is unbound, virtio<N> deleted, its index freed), then
    /// the device is left reset with its IRQ freed and bus mastering
    /// off (pci_disable_device). The BAR mappings stay (BUGS.md).
    fn remove(&self) {
        self.dev.del();
        super::free_index(self.index);
        let _ = self.vdev.reset();
        self.vdev.free_irq();
        let cmd = self.pci.cfg_read16(PCI_COMMAND);
        self.pci
            .cfg_write16(PCI_COMMAND, cmd & !crate::hw::pci::command::BUS_MASTER);
    }
}

/// PCI command register offset
const PCI_COMMAND: u8 = 0x04;

/// Modern devices only (ENODEV for legacy ones, as without
/// virtio_pci.force_legacy support)
fn virtio_pci_probe(
    dev: &Arc<crate::base::Device>,
) -> Result<Box<dyn crate::base::Bound>, KernelError> {
    let pci = crate::hw::pci::driver::pci_dev(dev).ok_or(KernelError::NoDevice)?;
    let id = virtio_id(pci).ok_or(KernelError::NoDevice)?;
    // The binding's memory first: nothing to undo should it fail
    let slot = try_box(MaybeUninit::<VirtioPciDev>::uninit())?;
    let vdev = try_arc(vp_init(pci, id)?)?;
    let (v, index) = super::register_virtio_device(dev, vdev.clone())?;
    Ok(Box::write(
        slot,
        VirtioPciDev {
            pci: pci.clone(),
            dev: v,
            vdev,
            index,
        },
    ))
}
