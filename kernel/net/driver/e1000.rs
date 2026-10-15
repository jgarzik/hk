//! Intel 82540EM / 82545EM (e1000) Network Driver
//!
//! Linux reference: drivers/net/ethernet/intel/e1000/e1000_main.c.
//!
//! ## Design
//!
//! - PCI memory BAR0 mapped with ioremap; bus mastering enabled.
//! - RX and TX descriptor rings and one 2 KiB bounce buffer per descriptor
//!   live in coherent DMA memory; descriptors only ever hold DMA addresses
//!   from the DMA API. Packets are copied into an skb on receive and out
//!   of the skb on transmit, so no skb memory is ever exposed to the device.
//! - Interrupts (shareable, level-triggered INTx): the ISR reads ICR
//!   (read-to-clear), masks all causes (IMC), records the causes and calls
//!   `napi_schedule`. The NAPI poll, in the `softnet/N` thread, reclaims TX
//!   descriptors, receives up to `budget` frames, handles link changes, and
//!   on completion re-enables interrupts (IMS). A cause raised while masked
//!   stays latched in ICR and fires when IMS is rewritten.
//! - TX ring full: the frame is dropped (`tx_dropped`, ENOBUFS to the
//!   sender), like a qdisc drop.
//!
//! ## Locking (doc/LOCKING.md, Network)
//!
//! - ISR: touches only MMIO, atomics and `napi_schedule` (IrqSpinlock).
//! - `rx`: `crate::sync::spin::Mutex`, thread context only (NAPI poll). Leaf.
//! - `tx`: `crate::sync::spin::Mutex`, thread context only (xmit, NAPI poll reclaim).
//!   Taken under socket/ARP locks (end of the network lock order). Leaf.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::sync::spin::Mutex;
use spin::Once;

use crate::CurrentArch;
use crate::arch::IoremapOps;
use crate::arch::barrier::{dma_rmb, dma_wmb, wmb};
use crate::bus::bus::{BusContext, BusDevice, BusDriver};
use crate::bus::driver::{Device, DriverError};
use crate::bus::pci::PciDevice;
use crate::dma::DmaCoherent;
use crate::net::dev::{
    NAPI_POLL_WEIGHT, Napi, NapiPoll, napi_complete_done, napi_disable, napi_enable, napi_schedule,
};
use crate::net::device::{LinkInfo, NetDevice, NetDeviceOps};
use crate::net::skb::{NET_SKB_PAD, SkBuff};
use crate::net::{self, KernelError};
use crate::printkln;

// ============================================================================
// Hardware Constants
// ============================================================================

/// Intel vendor ID
const VENDOR_INTEL: u16 = 0x8086;
/// 82540EM device ID
const DEVICE_82540EM: u16 = 0x100E;
/// 82545EM device ID (also common in QEMU)
const DEVICE_82545EM_COPPER: u16 = 0x100F;

// Register offsets
mod reg {
    pub const CTRL: u32 = 0x0000;
    pub const STATUS: u32 = 0x0008;
    pub const ICR: u32 = 0x00C0;
    pub const ITR: u32 = 0x00C4;
    pub const IMS: u32 = 0x00D0;
    pub const IMC: u32 = 0x00D8;
    pub const RCTL: u32 = 0x0100;
    pub const TCTL: u32 = 0x0400;
    pub const TIPG: u32 = 0x0410;
    pub const RDBAL: u32 = 0x2800;
    pub const RDBAH: u32 = 0x2804;
    pub const RDLEN: u32 = 0x2808;
    pub const RDH: u32 = 0x2810;
    pub const RDT: u32 = 0x2818;
    pub const RDTR: u32 = 0x2820;
    pub const TDBAL: u32 = 0x3800;
    pub const TDBAH: u32 = 0x3804;
    pub const TDLEN: u32 = 0x3808;
    pub const TDH: u32 = 0x3810;
    pub const TDT: u32 = 0x3818;
    pub const MTA: u32 = 0x5200;
    pub const RAL0: u32 = 0x5400;
    pub const RAH0: u32 = 0x5404;
}

// Control register bits
mod ctrl {
    pub const ASDE: u32 = 1 << 5;
    pub const SLU: u32 = 1 << 6;
    pub const RST: u32 = 1 << 26;
}

// Status register bits
mod status {
    pub const LU: u32 = 1 << 1;
}

// RCTL bits
mod rctl {
    pub const EN: u32 = 1 << 1;
    pub const BAM: u32 = 1 << 15;
    /// Buffer size 2048 (BSIZE = 00, BSEX = 0)
    pub const BSIZE_2048: u32 = 0;
    pub const SECRC: u32 = 1 << 26;
}

// TCTL bits
mod tctl {
    pub const EN: u32 = 1 << 1;
    pub const PSP: u32 = 1 << 3;
    pub const CT_SHIFT: u32 = 4;
    pub const COLD_SHIFT: u32 = 12;
}

// Interrupt cause bits (ICR/IMS/IMC)
mod int {
    pub const TXDW: u32 = 1 << 0;
    pub const LSC: u32 = 1 << 2;
    pub const RXSEQ: u32 = 1 << 3;
    pub const RXDMT0: u32 = 1 << 4;
    pub const RXO: u32 = 1 << 6;
    pub const RXT0: u32 = 1 << 7;
    /// Causes we enable (Linux IMS_ENABLE_MASK + RXO)
    pub const ENABLE: u32 = RXT0 | TXDW | RXDMT0 | RXSEQ | LSC | RXO;
}

/// Receive Address High: address valid
const RAH_AV: u32 = 1 << 31;

/// RX descriptors (multiple of 8; >= NAPI weight)
const RX_RING_SIZE: usize = 128;
/// TX descriptors (multiple of 8)
const TX_RING_SIZE: usize = 64;
/// Bounce buffer per descriptor (RCTL.BSIZE)
const BUF_SIZE: usize = 2048;
/// Largest frame accepted (no jumbo, no VLAN; CRC stripped)
const MAX_FRAME: usize = 1518;

/// Legacy RX Descriptor (16 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RxDesc {
    buffer_addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

/// Legacy TX Descriptor (16 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TxDesc {
    buffer_addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

const _: () = assert!(core::mem::size_of::<RxDesc>() == 16);
const _: () = assert!(core::mem::size_of::<TxDesc>() == 16);

mod rxd_stat {
    pub const DD: u8 = 1 << 0;
    pub const EOP: u8 = 1 << 1;
}

mod txd_cmd {
    pub const EOP: u8 = 1 << 0;
    pub const IFCS: u8 = 1 << 1;
    pub const RS: u8 = 1 << 3;
}

mod txd_stat {
    pub const DD: u8 = 1 << 0;
}

// ============================================================================
// Rings
// ============================================================================

/// RX ring: descriptors + bounce buffers (NAPI poll only)
struct RxRing {
    desc: DmaCoherent,
    bufs: Vec<DmaCoherent>,
    /// Next descriptor to examine
    next: usize,
}

/// TX ring: descriptors + bounce buffers
struct TxRing {
    desc: DmaCoherent,
    bufs: Vec<DmaCoherent>,
    /// Next descriptor to fill (software copy of TDT)
    tail: usize,
    /// Oldest descriptor not yet reclaimed
    clean: usize,
}

impl RxRing {
    fn desc(&self, i: usize) -> *mut RxDesc {
        unsafe { (self.desc.cpu_addr as *mut RxDesc).add(i) }
    }
}

impl TxRing {
    fn desc(&self, i: usize) -> *mut TxDesc {
        unsafe { (self.desc.cpu_addr as *mut TxDesc).add(i) }
    }

    /// Reclaim descriptors the device is done with; returns how many
    fn reclaim(&mut self) -> usize {
        let mut n = 0;
        while self.clean != self.tail {
            let st = unsafe { read_volatile(&(*self.desc(self.clean)).status) };
            if st & txd_stat::DD == 0 {
                break;
            }
            self.clean = (self.clean + 1) % TX_RING_SIZE;
            n += 1;
        }
        n
    }
}

/// e1000 device state
struct E1000 {
    /// MMIO base (kernel virtual)
    mmio_base: u64,
    /// MAC address
    mac: [u8; 6],
    rx: Mutex<RxRing>,
    tx: Mutex<TxRing>,
    napi: Arc<Napi>,
    /// Our net device (weak: the netdev's ops own us)
    netdev: Once<Weak<NetDevice>>,
    /// Causes seen by the ISR, not yet handled by the poll
    pending_icr: AtomicU32,
    /// Interrupts we handled
    irqs: AtomicU64,
    /// Interrupts on our line that were not ours (ICR == 0)
    irqs_not_ours: AtomicU64,
}

impl E1000 {
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    fn write_reg(&self, offset: u32, value: u32) {
        unsafe { write_volatile((self.mmio_base + offset as u64) as *mut u32, value) }
    }

    fn read_mac(&self) -> [u8; 6] {
        let ral = self.read_reg(reg::RAL0);
        let rah = self.read_reg(reg::RAH0);
        [
            ral as u8,
            (ral >> 8) as u8,
            (ral >> 16) as u8,
            (ral >> 24) as u8,
            rah as u8,
            (rah >> 8) as u8,
        ]
    }

    fn reset(&self) {
        self.write_reg(reg::IMC, 0xFFFF_FFFF);
        self.write_reg(reg::CTRL, ctrl::RST);
        for _ in 0..100_000 {
            if self.read_reg(reg::CTRL) & ctrl::RST == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        self.write_reg(reg::IMC, 0xFFFF_FFFF);
        let _ = self.read_reg(reg::ICR);
    }

    /// Program the receive address filter with our MAC
    fn set_mac_filter(&self) {
        let m = self.mac;
        let ral = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
        let rah = u32::from(m[4]) | (u32::from(m[5]) << 8) | RAH_AV;
        self.write_reg(reg::RAL0, ral);
        self.write_reg(reg::RAH0, rah);
        for i in 0..128 {
            self.write_reg(reg::MTA + i * 4, 0);
        }
    }

    fn init_rx(&self) {
        let rx = self.rx.lock();
        for i in 0..RX_RING_SIZE {
            unsafe {
                write_volatile(
                    rx.desc(i),
                    RxDesc {
                        buffer_addr: rx.bufs[i].dma_addr.0,
                        ..RxDesc::default()
                    },
                );
            }
        }
        let phys = rx.desc.dma_addr.0;
        wmb();
        self.write_reg(reg::RDBAL, phys as u32);
        self.write_reg(reg::RDBAH, (phys >> 32) as u32);
        self.write_reg(reg::RDLEN, (RX_RING_SIZE * 16) as u32);
        self.write_reg(reg::RDH, 0);
        // All descriptors but one belong to the device
        self.write_reg(reg::RDT, (RX_RING_SIZE - 1) as u32);
        self.write_reg(reg::RDTR, 0);
        self.write_reg(
            reg::RCTL,
            rctl::EN | rctl::BAM | rctl::BSIZE_2048 | rctl::SECRC,
        );
    }

    fn init_tx(&self) {
        let tx = self.tx.lock();
        for i in 0..TX_RING_SIZE {
            unsafe {
                write_volatile(
                    tx.desc(i),
                    TxDesc {
                        buffer_addr: tx.bufs[i].dma_addr.0,
                        ..TxDesc::default()
                    },
                );
            }
        }
        let phys = tx.desc.dma_addr.0;
        wmb();
        self.write_reg(reg::TDBAL, phys as u32);
        self.write_reg(reg::TDBAH, (phys >> 32) as u32);
        self.write_reg(reg::TDLEN, (TX_RING_SIZE * 16) as u32);
        self.write_reg(reg::TDH, 0);
        self.write_reg(reg::TDT, 0);
        self.write_reg(reg::TIPG, 0x0060_200A);
        self.write_reg(
            reg::TCTL,
            tctl::EN | tctl::PSP | (0x10 << tctl::CT_SHIFT) | (0x40 << tctl::COLD_SHIFT),
        );
    }

    fn link_up(&self) -> bool {
        self.read_reg(reg::STATUS) & status::LU != 0
    }

    fn netdev(&self) -> Option<Arc<NetDevice>> {
        self.netdev.get()?.upgrade()
    }

    /// Transmit: copy the frame into the next descriptor's bounce buffer
    fn transmit(&self, skb: &SkBuff) -> Result<(), KernelError> {
        let len = skb.len();
        if len == 0 || len > BUF_SIZE {
            return Err(KernelError::MessageTooLong);
        }
        let mut tx = self.tx.lock();
        tx.reclaim();
        let next = (tx.tail + 1) % TX_RING_SIZE;
        if next == tx.clean {
            return Err(KernelError::NoBufferSpace);
        }
        let i = tx.tail;
        unsafe {
            core::ptr::copy_nonoverlapping(skb.data_ptr(), tx.bufs[i].cpu_addr, len);
            let d = tx.desc(i);
            write_volatile(&mut (*d).length, len as u16);
            write_volatile(&mut (*d).cso, 0);
            write_volatile(&mut (*d).css, 0);
            write_volatile(&mut (*d).special, 0);
            write_volatile(&mut (*d).status, 0);
            dma_wmb();
            write_volatile(&mut (*d).cmd, txd_cmd::EOP | txd_cmd::IFCS | txd_cmd::RS);
        }
        tx.tail = next;
        // Descriptor and buffer writes before the doorbell
        wmb();
        self.write_reg(reg::TDT, next as u32);
        Ok(())
    }

    /// Receive up to `budget` frames; returns them (delivered by the caller
    /// after the ring lock is dropped)
    #[allow(clippy::vec_box)] // skbs travel as Box<SkBuff> through the stack
    fn receive(&self, dev: &Arc<NetDevice>, budget: usize, out: &mut Vec<Box<SkBuff>>) {
        let mut rx = self.rx.lock();
        let mut last = None;
        while out.len() < budget {
            let i = rx.next;
            let d = rx.desc(i);
            let st = unsafe { read_volatile(&(*d).status) };
            if st & rxd_stat::DD == 0 {
                break;
            }
            // Status before the length and data it covers
            dma_rmb();
            let len = unsafe { read_volatile(&(*d).length) } as usize;
            let errors = unsafe { read_volatile(&(*d).errors) };
            if st & rxd_stat::EOP == 0 || errors != 0 || !(14..=MAX_FRAME).contains(&len) {
                // Multi-descriptor (oversize) or errored frame
                dev.stats.inc_rx_errors();
            } else {
                // 2 extra bytes of headroom align the IP header (NET_IP_ALIGN)
                match SkBuff::alloc(NET_SKB_PAD + 2, len) {
                    Some(mut skb) => {
                        let src = unsafe { core::slice::from_raw_parts(rx.bufs[i].cpu_addr, len) };
                        let _ = skb.put_slice(src);
                        skb.dev = Some(Arc::clone(dev));
                        dev.stats.rx_packet(len);
                        if src[0] & 1 != 0 {
                            dev.stats.multicast.fetch_add(1, Ordering::Relaxed);
                        }
                        out.push(skb);
                    }
                    None => dev.stats.inc_rx_dropped(),
                }
            }
            // Give the descriptor back
            unsafe {
                write_volatile(&mut (*d).status, 0);
                write_volatile(&mut (*d).errors, 0);
                write_volatile(&mut (*d).length, 0);
            }
            last = Some(i);
            rx.next = (i + 1) % RX_RING_SIZE;
        }
        if let Some(i) = last {
            // The processed descriptors are the device's again: the last
            // one becomes the one software holds
            wmb();
            self.write_reg(reg::RDT, i as u32);
        }
    }

    fn handle_link_change(&self) {
        let Some(dev) = self.netdev() else { return };
        let up = self.link_up();
        if up != dev.carrier_ok() {
            if up {
                dev.netif_carrier_on();
            } else {
                dev.netif_carrier_off();
            }
            printkln!(
                "e1000: {} link {}",
                dev.name(),
                if up { "up" } else { "down" }
            );
        }
    }
}

/// Interrupt handler (IRQ context): ack, mask, schedule NAPI
fn e1000_isr(_irq: u32, data: *mut ()) -> bool {
    let dev = unsafe { &*(data as *const E1000) };
    let icr = dev.read_reg(reg::ICR); // read-to-clear
    if icr == 0 {
        // Shared line: another device's interrupt
        dev.irqs_not_ours.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    dev.irqs.fetch_add(1, Ordering::Relaxed);
    dev.write_reg(reg::IMC, 0xFFFF_FFFF);
    dev.pending_icr.fetch_or(icr, Ordering::AcqRel);
    napi_schedule(&dev.napi);
    true
}

impl NapiPoll for E1000 {
    fn poll(&self, napi: &Napi, budget: usize) -> usize {
        let icr = self.pending_icr.swap(0, Ordering::AcqRel);
        if icr & int::LSC != 0 {
            self.handle_link_change();
        }

        // TX completions
        self.tx.lock().reclaim();

        // RX
        let mut frames = Vec::new();
        if let Some(dev) = self.netdev() {
            self.receive(&dev, budget, &mut frames);
        }
        let work = frames.len();
        for skb in frames {
            net::dev::netif_receive_skb(skb);
        }

        if work < budget {
            napi_complete_done(napi, work);
            if self.rearm() {
                napi_schedule(&self.napi);
            }
        }
        work
    }
}

impl E1000 {
    /// Re-enable interrupts after a completed poll while the device is
    /// running (checked under `rx`, which `stop` takes to mask, so a
    /// closing device stays masked). True: causes arrived meanwhile,
    /// interrupts are masked again and the poll must run again.
    fn rearm(&self) -> bool {
        let _rx = self.rx.lock();
        if !self.netdev().is_some_and(|d| d.netif_running()) {
            return false;
        }
        self.write_reg(reg::IMS, int::ENABLE);
        // On a shared line our ISR may have run during the poll (for
        // another device's interrupt) and consumed ICR causes: those
        // will not interrupt again, so poll once more (Linux
        // NAPIF_STATE_MISSED). napi_complete_done was a full barrier.
        if self.pending_icr.load(Ordering::SeqCst) != 0 {
            self.write_reg(reg::IMC, 0xFFFF_FFFF);
            return true;
        }
        false
    }

    /// Mask every cause (under `rx`, serialized with `rearm`)
    fn mask(&self) {
        let _rx = self.rx.lock();
        self.write_reg(reg::IMC, 0xFFFF_FFFF);
    }
}

// ============================================================================
// Net device glue
// ============================================================================

/// e1000 NetDeviceOps implementation
struct E1000Ops {
    device: Arc<E1000>,
}

impl NetDeviceOps for E1000Ops {
    fn xmit(&self, skb: Box<SkBuff>) -> Result<(), KernelError> {
        self.device.transmit(&skb)
    }

    fn mac_address(&self) -> [u8; 6] {
        self.device.mac
    }

    fn mtu(&self) -> u32 {
        1500
    }

    fn max_mtu(&self) -> u32 {
        1500 // no jumbo frames (RX buffers are 2 KB)
    }

    fn open(&self, dev: &NetDevice) -> Result<(), KernelError> {
        if self.device.link_up() {
            dev.netif_carrier_on();
        } else {
            dev.netif_carrier_off();
        }
        let c = self.device.read_reg(reg::CTRL);
        self.device.write_reg(reg::CTRL, c | ctrl::SLU | ctrl::ASDE);
        self.device.write_reg(reg::ITR, 0);
        napi_enable(&self.device.napi);
        self.device.write_reg(reg::IMS, int::ENABLE);
        Ok(())
    }

    /// Linux e1000_down: NAPI off (waits for a running poll), then mask
    fn stop(&self) -> Result<(), KernelError> {
        napi_disable(&self.device.napi);
        self.device.mask();
        Ok(())
    }
}

/// e1000 device wrapper (implements Device trait)
struct E1000DeviceWrapper {
    netdev: Arc<NetDevice>,
    device: Arc<E1000>,
}

impl Device for E1000DeviceWrapper {
    fn name(&self) -> &str {
        "e1000"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn shutdown(&self) {
        printkln!(
            "e1000: {} irqs={} not_ours={} napi_polls={}",
            self.netdev.name(),
            self.device.irqs.load(Ordering::Relaxed),
            self.device.irqs_not_ours.load(Ordering::Relaxed),
            self.device.napi.polls(),
        );
        self.device.write_reg(reg::IMC, 0xFFFF_FFFF);
    }
}

/// e1000 PCI driver
pub struct E1000PciDriver;

fn alloc_bufs(pci: &PciDevice, n: usize) -> Result<Vec<DmaCoherent>, DriverError> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let b =
            crate::dma::dma_alloc_coherent(pci, BUF_SIZE).ok_or(DriverError::MissingResource)?;
        v.push(b);
    }
    Ok(v)
}

impl BusDriver for E1000PciDriver {
    fn name(&self) -> &str {
        "e1000"
    }

    fn matches(&self, device: &dyn BusDevice) -> bool {
        if let Some(pci) = device.as_any().downcast_ref::<PciDevice>() {
            pci.header.vendor_id == VENDOR_INTEL
                && (pci.header.device_id == DEVICE_82540EM
                    || pci.header.device_id == DEVICE_82545EM_COPPER)
        } else {
            false
        }
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

        printkln!(
            "e1000: probing {:04x}:{:04x} at {}",
            pci.header.vendor_id,
            pci.header.device_id,
            pci.bus_id()
        );

        let bar0 = pci.header.bar[0];
        if bar0 == 0 {
            printkln!("e1000: BAR0 not configured");
            return Err(DriverError::MissingResource);
        }
        let mmio_phys = (bar0 & !0xF) as u64;
        let mmio_base = match CurrentArch::ioremap(mmio_phys, 128 * 1024) {
            Ok(virt) => virt as u64,
            Err(e) => {
                printkln!("e1000: Failed to ioremap MMIO region: {:?}", e);
                return Err(DriverError::MissingResource);
            }
        };

        // The device DMAs descriptors and packets: it must master the bus
        pci.enable_memory_space();
        pci.enable_bus_master();

        let rx_desc = crate::dma::dma_alloc_coherent(pci, RX_RING_SIZE * 16)
            .ok_or(DriverError::MissingResource)?;
        let tx_desc = crate::dma::dma_alloc_coherent(pci, TX_RING_SIZE * 16)
            .ok_or(DriverError::MissingResource)?;
        let rx_bufs = alloc_bufs(pci, RX_RING_SIZE)?;
        let tx_bufs = alloc_bufs(pci, TX_RING_SIZE)?;

        let mut dev = E1000 {
            mmio_base,
            mac: [0; 6],
            rx: Mutex::new(RxRing {
                desc: rx_desc,
                bufs: rx_bufs,
                next: 0,
            }),
            tx: Mutex::new(TxRing {
                desc: tx_desc,
                bufs: tx_bufs,
                tail: 0,
                clean: 0,
            }),
            napi: Napi::new(NAPI_POLL_WEIGHT),
            netdev: Once::new(),
            pending_icr: AtomicU32::new(0),
            irqs: AtomicU64::new(0),
            irqs_not_ours: AtomicU64::new(0),
        };

        dev.reset();
        dev.mac = dev.read_mac();
        let mac = dev.mac;
        printkln!(
            "e1000: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );
        dev.set_mac_filter();
        dev.init_rx();
        dev.init_tx();

        let device = Arc::new(dev);
        let poller: Weak<dyn NapiPoll> = Arc::downgrade(&device) as Weak<dyn NapiPoll>;
        net::dev::netif_napi_add(&device.napi, poller);

        let ops: &'static dyn NetDeviceOps = Box::leak(Box::new(E1000Ops {
            device: Arc::clone(&device),
        }));
        let netdev = Arc::new(NetDevice::new(
            net::dev_alloc_name("eth%d"),
            mac,
            LinkInfo::ETHER,
            ops,
        ));
        device.netdev.call_once(|| Arc::downgrade(&netdev));

        // Carrier from the PHY now; later changes arrive as LSC interrupts
        if device.link_up() {
            netdev.netif_carrier_on();
        } else {
            netdev.netif_carrier_off();
        }
        printkln!(
            "e1000: link {}",
            if device.link_up() { "up" } else { "down" }
        );

        // Shareable level-triggered INTx; the device's interrupts stay
        // masked until userspace brings the interface up (open())
        match pci.register_irq_handler(e1000_isr, Arc::as_ptr(&device) as *mut ()) {
            Ok(irq) => printkln!("e1000: IRQ {}", irq),
            Err(e) => {
                printkln!("e1000: no IRQ ({}), RX disabled", e);
                return Err(DriverError::MissingResource);
            }
        }

        net::register_netdev(Arc::clone(&netdev));

        Ok(Box::new(E1000DeviceWrapper { netdev, device }))
    }
}
