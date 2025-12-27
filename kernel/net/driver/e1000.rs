//! Intel 82540EM (e1000) Network Driver
//!
//! This module implements a driver for the Intel 82540EM Gigabit Ethernet
//! controller, commonly emulated by QEMU.
//!
//! ## Hardware Overview
//!
//! - Vendor ID: 0x8086 (Intel)
//! - Device ID: 0x100E (82540EM)
//! - MMIO BAR: BAR0 contains all registers
//! - TX/RX: Ring buffer descriptors in system memory
//! - Interrupts: Legacy PCI interrupt

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

use spin::Mutex;

use crate::CurrentArch;
use crate::arch::IoremapOps;
use crate::bus::bus::{BusContext, BusDevice, BusDriver};
use crate::bus::driver::{Device, DriverError};
use crate::bus::pci::PciDevice;
use crate::dma::{DmaCoherent, DmaConfig, DmaDevice};
use crate::net::device::{NetDevice, NetDeviceOps};
use crate::net::skb::SkBuff;
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
    /// Device Control
    pub const CTRL: u32 = 0x0000;
    /// Device Status
    pub const STATUS: u32 = 0x0008;
    /// Interrupt Mask Set
    pub const IMS: u32 = 0x00D0;
    /// Interrupt Mask Clear
    pub const IMC: u32 = 0x00D8;
    /// Receive Control
    pub const RCTL: u32 = 0x0100;
    /// Transmit Control
    pub const TCTL: u32 = 0x0400;
    /// RX Descriptor Base Low
    pub const RDBAL: u32 = 0x2800;
    /// RX Descriptor Base High
    pub const RDBAH: u32 = 0x2804;
    /// RX Descriptor Length
    pub const RDLEN: u32 = 0x2808;
    /// RX Descriptor Head
    pub const RDH: u32 = 0x2810;
    /// RX Descriptor Tail
    pub const RDT: u32 = 0x2818;
    /// TX Descriptor Base Low
    pub const TDBAL: u32 = 0x3800;
    /// TX Descriptor Base High
    pub const TDBAH: u32 = 0x3804;
    /// TX Descriptor Length
    pub const TDLEN: u32 = 0x3808;
    /// TX Descriptor Head
    pub const TDH: u32 = 0x3810;
    /// TX Descriptor Tail
    pub const TDT: u32 = 0x3818;
    /// Receive Address Low (MAC)
    pub const RAL0: u32 = 0x5400;
    /// Receive Address High (MAC)
    pub const RAH0: u32 = 0x5404;
    /// Multicast Table Array
    pub const MTA: u32 = 0x5200;
}

// Control register bits
mod ctrl {
    /// Auto-Speed Detection Enable
    pub const ASDE: u32 = 1 << 5;
    /// Set Link Up
    pub const SLU: u32 = 1 << 6;
    /// Device Reset
    pub const RST: u32 = 1 << 26;
}

// Status register bits
mod status {
    /// Link Up
    pub const LU: u32 = 1 << 1;
}

// RCTL bits
mod rctl {
    /// Receiver Enable
    pub const EN: u32 = 1 << 1;
    /// Broadcast Accept
    pub const BAM: u32 = 1 << 15;
    /// Buffer Size (00 = 2048, 01 = 1024, 10 = 512, 11 = 256)
    pub const BSIZE_2048: u32 = 0 << 16;
    /// Strip CRC
    pub const SECRC: u32 = 1 << 26;
}

// TCTL bits
mod tctl {
    /// Transmitter Enable
    pub const EN: u32 = 1 << 1;
    /// Pad Short Packets
    pub const PSP: u32 = 1 << 3;
    /// Collision Threshold (shift by 4)
    pub const CT_SHIFT: u32 = 4;
    /// Collision Distance (shift by 12)
    pub const COLD_SHIFT: u32 = 12;
}

// Interrupt bits
mod int {
    /// TX Descriptor Written Back
    pub const TXDW: u32 = 1 << 0;
    /// Link Status Change
    pub const LSC: u32 = 1 << 2;
    /// RX Timer Interrupt
    pub const RXT0: u32 = 1 << 7;
}

/// Number of RX descriptors
const RX_RING_SIZE: usize = 32;
/// Number of TX descriptors
const TX_RING_SIZE: usize = 32;
/// RX buffer size
const RX_BUFFER_SIZE: usize = 2048;

/// Legacy RX Descriptor (16 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct E1000RxDesc {
    /// Buffer address (physical)
    buffer_addr: u64,
    /// Length of received packet
    length: u16,
    /// Checksum
    checksum: u16,
    /// Status
    status: u8,
    /// Errors
    errors: u8,
    /// Special (VLAN tag)
    special: u16,
}

/// Legacy TX Descriptor (16 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct E1000TxDesc {
    /// Buffer address (physical)
    buffer_addr: u64,
    /// Length
    length: u16,
    /// Checksum offset
    cso: u8,
    /// Command
    cmd: u8,
    /// Status
    status: u8,
    /// Checksum start
    css: u8,
    /// Special (VLAN)
    special: u16,
}

// TX descriptor command bits
mod txd_cmd {
    /// End of Packet
    pub const EOP: u8 = 1 << 0;
    /// Insert FCS
    pub const IFCS: u8 = 1 << 1;
    /// Report Status
    pub const RS: u8 = 1 << 3;
}

// TX descriptor status bits
mod txd_stat {
    /// Descriptor Done
    pub const DD: u8 = 1 << 0;
}

/// e1000 device state
struct E1000Device {
    /// MMIO base address
    mmio_base: u64,
    /// MAC address
    mac: [u8; 6],
    /// DMA configuration
    dma_config: DmaConfig,
    /// RX descriptor ring
    rx_ring: DmaCoherent,
    /// TX descriptor ring
    tx_ring: DmaCoherent,
    /// RX buffers (owned to keep DMA allocations alive for hardware)
    _rx_buffers: Vec<DmaCoherent>,
    /// TX buffers (in-flight packets)
    tx_buffers: Mutex<[Option<Box<SkBuff>>; TX_RING_SIZE]>,
    /// Current TX index
    tx_index: Mutex<usize>,
    /// TX clean index (next to reclaim)
    tx_clean: Mutex<usize>,
    /// Link state
    link_up: AtomicBool,
}

impl E1000Device {
    /// Read MMIO register
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write MMIO register
    fn write_reg(&self, offset: u32, value: u32) {
        unsafe { write_volatile((self.mmio_base + offset as u64) as *mut u32, value) }
    }

    /// Read MAC address from hardware
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

    /// Reset the device
    fn reset(&self) {
        // Disable interrupts
        self.write_reg(reg::IMC, 0xFFFFFFFF);

        // Reset device
        self.write_reg(reg::CTRL, ctrl::RST);

        // Wait for reset to complete (spec says 1µs, we wait longer)
        for _ in 0..1000 {
            if self.read_reg(reg::CTRL) & ctrl::RST == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Disable interrupts again after reset
        self.write_reg(reg::IMC, 0xFFFFFFFF);
    }

    /// Initialize RX ring
    fn init_rx(&self) {
        // Set RX descriptor ring base address
        let rx_phys = self.rx_ring.dma_addr.0;
        self.write_reg(reg::RDBAL, rx_phys as u32);
        self.write_reg(reg::RDBAH, (rx_phys >> 32) as u32);

        // Set ring length (in bytes)
        self.write_reg(reg::RDLEN, (RX_RING_SIZE * 16) as u32);

        // Set head and tail
        self.write_reg(reg::RDH, 0);
        self.write_reg(reg::RDT, (RX_RING_SIZE - 1) as u32);

        // Configure RCTL
        let rctl = rctl::EN | rctl::BAM | rctl::BSIZE_2048 | rctl::SECRC;
        self.write_reg(reg::RCTL, rctl);
    }

    /// Initialize TX ring
    fn init_tx(&self) {
        // Set TX descriptor ring base address
        let tx_phys = self.tx_ring.dma_addr.0;
        self.write_reg(reg::TDBAL, tx_phys as u32);
        self.write_reg(reg::TDBAH, (tx_phys >> 32) as u32);

        // Set ring length (in bytes)
        self.write_reg(reg::TDLEN, (TX_RING_SIZE * 16) as u32);

        // Set head and tail
        self.write_reg(reg::TDH, 0);
        self.write_reg(reg::TDT, 0);

        // Configure TCTL
        let tctl = tctl::EN
            | tctl::PSP
            | (15 << tctl::CT_SHIFT)      // Collision threshold
            | (64 << tctl::COLD_SHIFT); // Collision distance
        self.write_reg(reg::TCTL, tctl);
    }

    /// Check link status
    fn check_link(&self) -> bool {
        let status = self.read_reg(reg::STATUS);
        status & status::LU != 0
    }

    /// Transmit a packet
    fn transmit(&self, skb: Box<SkBuff>) -> Result<(), KernelError> {
        let mut tx_idx = self.tx_index.lock();
        let mut tx_clean = self.tx_clean.lock();

        // Clean up completed transmits
        while *tx_clean != *tx_idx {
            let desc = unsafe { &*((self.tx_ring.cpu_addr as *const E1000TxDesc).add(*tx_clean)) };
            if desc.status & txd_stat::DD == 0 {
                break;
            }

            // Free the buffer
            let mut buffers = self.tx_buffers.lock();
            buffers[*tx_clean] = None;
            drop(buffers);

            *tx_clean = (*tx_clean + 1) % TX_RING_SIZE;
        }

        // Check if ring is full
        let next_idx = (*tx_idx + 1) % TX_RING_SIZE;
        if next_idx == *tx_clean {
            return Err(KernelError::NoBufferSpace);
        }

        // Get pointer to descriptor
        let desc = unsafe { &mut *((self.tx_ring.cpu_addr as *mut E1000TxDesc).add(*tx_idx)) };

        // Set up descriptor
        desc.buffer_addr = skb.data_ptr() as u64;
        desc.length = skb.len() as u16;
        desc.cso = 0;
        desc.css = 0;
        desc.special = 0;
        desc.status = 0;
        desc.cmd = txd_cmd::EOP | txd_cmd::IFCS | txd_cmd::RS;

        // Store skb
        {
            let mut buffers = self.tx_buffers.lock();
            buffers[*tx_idx] = Some(skb);
        }

        // Update tail
        *tx_idx = next_idx;
        self.write_reg(reg::TDT, *tx_idx as u32);

        Ok(())
    }
}

impl DmaDevice for E1000Device {
    fn dma_config(&self) -> &DmaConfig {
        &self.dma_config
    }

    fn dma_config_mut(&mut self) -> &mut DmaConfig {
        &mut self.dma_config
    }
}

/// e1000 NetDeviceOps implementation
struct E1000Ops {
    device: Arc<E1000Device>,
}

impl NetDeviceOps for E1000Ops {
    fn xmit(&self, skb: Box<SkBuff>) -> Result<(), KernelError> {
        self.device.transmit(skb)
    }

    fn mac_address(&self) -> [u8; 6] {
        self.device.mac
    }

    fn mtu(&self) -> u32 {
        1500
    }

    fn open(&self) -> Result<(), KernelError> {
        // Enable interrupts
        let ims = int::LSC | int::RXT0 | int::TXDW;
        self.device.write_reg(reg::IMS, ims);

        // Set link up
        let ctrl = self.device.read_reg(reg::CTRL);
        self.device.write_reg(reg::CTRL, ctrl | ctrl::SLU);

        Ok(())
    }

    fn stop(&self) -> Result<(), KernelError> {
        // Disable interrupts
        self.device.write_reg(reg::IMC, 0xFFFFFFFF);
        Ok(())
    }
}

/// e1000 device wrapper (implements Device trait)
struct E1000DeviceWrapper {
    netdev: Arc<NetDevice>,
    _device: Arc<E1000Device>,
}

impl Device for E1000DeviceWrapper {
    fn name(&self) -> &str {
        "e1000"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn shutdown(&self) {
        let _ = self.netdev.down();
    }
}

/// e1000 PCI driver
pub struct E1000PciDriver;

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

        // Get BAR0 (MMIO)
        let bar0 = pci.header.bar[0];
        if bar0 == 0 {
            printkln!("e1000: BAR0 not configured");
            return Err(DriverError::MissingResource);
        }

        // MMIO physical address (mask off type bits)
        let mmio_phys = (bar0 & !0xF) as u64;

        printkln!("e1000: MMIO at {:#x}", mmio_phys);

        // Map MMIO region using ioremap
        // e1000 register space is 128KB
        let mmio_size = 128 * 1024;
        let mmio_base = match CurrentArch::ioremap(mmio_phys, mmio_size) {
            Ok(virt) => virt as u64,
            Err(e) => {
                printkln!("e1000: Failed to ioremap MMIO region: {:?}", e);
                return Err(DriverError::MissingResource);
            }
        };

        // Use PCI device's DMA config for allocations
        // Copy it so we can store in E1000Device
        let dma_config = pci.dma_config;

        // Allocate descriptor rings (using pci which implements DmaDevice)
        let rx_ring = crate::dma::dma_alloc_coherent(pci, RX_RING_SIZE * 16)
            .ok_or(DriverError::MissingResource)?;
        let tx_ring = crate::dma::dma_alloc_coherent(pci, TX_RING_SIZE * 16)
            .ok_or(DriverError::MissingResource)?;

        // Allocate RX buffers
        let mut rx_buffers = Vec::with_capacity(RX_RING_SIZE);
        for i in 0..RX_RING_SIZE {
            let buf = crate::dma::dma_alloc_coherent(pci, RX_BUFFER_SIZE)
                .ok_or(DriverError::MissingResource)?;

            // Initialize RX descriptor
            let desc = unsafe { &mut *((rx_ring.cpu_addr as *mut E1000RxDesc).add(i)) };
            desc.buffer_addr = buf.dma_addr.0;
            desc.status = 0;

            rx_buffers.push(buf);
        }

        // Create device
        let device = Arc::new(E1000Device {
            mmio_base,
            mac: [0; 6],
            dma_config,
            rx_ring,
            tx_ring,
            _rx_buffers: rx_buffers,
            tx_buffers: Mutex::new([const { None }; TX_RING_SIZE]),
            tx_index: Mutex::new(0),
            tx_clean: Mutex::new(0),
            link_up: AtomicBool::new(false),
        });

        // Reset and initialize hardware
        device.reset();

        // Read MAC address
        let mac = device.read_mac();
        // Update MAC in device (need Arc::get_mut which won't work, so we cheat)
        unsafe {
            let dev_ptr = Arc::as_ptr(&device) as *mut E1000Device;
            (*dev_ptr).mac = mac;
        }

        printkln!(
            "e1000: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );

        // Clear multicast table
        for i in 0..128 {
            device.write_reg(reg::MTA + i * 4, 0);
        }

        // Initialize RX and TX rings
        device.init_rx();
        device.init_tx();

        // Set up link
        let ctrl = device.read_reg(reg::CTRL);
        device.write_reg(reg::CTRL, ctrl | ctrl::SLU | ctrl::ASDE);

        // Check link status
        let link = device.check_link();
        device.link_up.store(link, Ordering::Release);
        printkln!("e1000: link {}", if link { "up" } else { "down" });

        // Create NetDeviceOps
        let ops: &'static dyn NetDeviceOps = Box::leak(Box::new(E1000Ops {
            device: Arc::clone(&device),
        }));

        // Create NetDevice
        let netdev = Arc::new(NetDevice::new(String::from("eth0"), mac, ops));

        // Bring interface up
        netdev.up().map_err(|_| DriverError::InitFailed)?;

        // Register with network subsystem
        net::register_netdev(Arc::clone(&netdev));

        Ok(Box::new(E1000DeviceWrapper {
            netdev,
            _device: device,
        }))
    }
}
