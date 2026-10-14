//! Network Device Abstraction
//!
//! This module defines the `NetDevice` trait and related types for
//! network interface management.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use spin::{Mutex, RwLock};

use crate::net::KernelError;
use crate::net::ipv4::Ipv4Addr;
use crate::net::skb::SkBuff;
use crate::waitqueue::WaitQueue;

/// Interface flags (matches Linux IFF_* flags)
pub mod flags {
    /// Interface is up
    pub const IFF_UP: u32 = 1 << 0;
    /// Broadcast address valid
    pub const IFF_BROADCAST: u32 = 1 << 1;
    /// Loopback interface
    pub const IFF_LOOPBACK: u32 = 1 << 3;
    /// Point-to-point link
    pub const IFF_POINTOPOINT: u32 = 1 << 4;
    /// Resources allocated
    pub const IFF_RUNNING: u32 = 1 << 6;
    /// No ARP protocol
    pub const IFF_NOARP: u32 = 1 << 7;
    /// Receive all packets
    pub const IFF_PROMISC: u32 = 1 << 8;
    /// Receive all multicast
    pub const IFF_ALLMULTI: u32 = 1 << 9;
    /// Supports multicast
    pub const IFF_MULTICAST: u32 = 1 << 12;
}

/// Network device operations trait
///
/// Device drivers implement this trait to provide hardware-specific
/// functionality.
pub trait NetDeviceOps: Send + Sync {
    /// Transmit a packet
    ///
    /// Takes ownership of the skb. Returns Ok(()) on success or
    /// error if transmission failed.
    fn xmit(&self, skb: Box<SkBuff>) -> Result<(), KernelError>;

    /// Get the hardware MAC address
    fn mac_address(&self) -> [u8; 6];

    /// Get the Maximum Transmission Unit (default: 1500)
    fn mtu(&self) -> u32 {
        1500
    }

    /// Open/start the interface
    fn open(&self) -> Result<(), KernelError> {
        Ok(())
    }

    /// Stop the interface
    fn stop(&self) -> Result<(), KernelError> {
        Ok(())
    }

    /// Set promiscuous mode
    fn set_promisc(&self, _enable: bool) {}

    /// Set multicast list
    fn set_multicast_list(&self, _addrs: &[[u8; 6]]) {}
}

/// Network device statistics
#[derive(Default)]
pub struct NetDeviceStats {
    /// Total packets received
    pub rx_packets: AtomicU64,
    /// Total packets transmitted
    pub tx_packets: AtomicU64,
    /// Total bytes received
    pub rx_bytes: AtomicU64,
    /// Total bytes transmitted
    pub tx_bytes: AtomicU64,
    /// Receive errors
    pub rx_errors: AtomicU64,
    /// Transmit errors
    pub tx_errors: AtomicU64,
    /// Packets dropped (rx)
    pub rx_dropped: AtomicU64,
    /// Packets dropped (tx)
    pub tx_dropped: AtomicU64,
    /// Multicast packets received
    pub multicast: AtomicU64,
    /// Collisions
    pub collisions: AtomicU64,
    /// Received frames with no protocol handler (Linux rx_nohandler)
    pub rx_nohandler: AtomicU64,
}

impl NetDeviceStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_rx_packets(&self) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_packets(&self) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_rx_bytes(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_tx_bytes(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn inc_rx_errors(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_errors(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_dropped(&self) {
        self.rx_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_dropped(&self) {
        self.tx_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_nohandler(&self) {
        self.rx_nohandler.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one received packet of `len` bytes
    pub fn rx_packet(&self, len: usize) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }
}

/// Network device structure
///
/// Represents a network interface in the kernel.
pub struct NetDevice {
    /// Interface name (e.g., "eth0")
    name: String,

    /// Hardware MAC address
    mac: [u8; 6],

    /// Maximum Transmission Unit
    mtu: u32,

    /// Interface flags
    pub flags: AtomicU32,

    /// Device operations (provided by driver)
    ops: &'static dyn NetDeviceOps,

    /// Device statistics
    pub stats: NetDeviceStats,

    /// IPv4 address
    ipv4_addr: Mutex<Option<Ipv4Addr>>,

    /// IPv4 netmask
    ipv4_netmask: Mutex<Option<Ipv4Addr>>,

    /// Wait queue for RX events
    rx_wait: WaitQueue,

    /// Wait queue for TX space available
    tx_wait: WaitQueue,

    /// Network namespace the device lives in (weak: the namespace owns
    /// its devices). Thread context only; read on every received packet.
    net: RwLock<Weak<crate::net::NetNamespace>>,

    /// Physical link state (Linux carrier; IFF_RUNNING = up && carrier)
    carrier: AtomicBool,
}

impl NetDevice {
    /// Create a new network device
    pub fn new(name: String, mac: [u8; 6], ops: &'static dyn NetDeviceOps) -> Self {
        let mtu = ops.mtu();
        Self {
            name,
            mac,
            mtu,
            flags: AtomicU32::new(flags::IFF_BROADCAST | flags::IFF_MULTICAST),
            ops,
            stats: NetDeviceStats::new(),
            ipv4_addr: Mutex::new(None),
            ipv4_netmask: Mutex::new(None),
            rx_wait: WaitQueue::new(),
            tx_wait: WaitQueue::new(),
            net: RwLock::new(Weak::new()),
            carrier: AtomicBool::new(true),
        }
    }

    /// Network namespace of this device
    pub fn net(&self) -> Option<Arc<crate::net::NetNamespace>> {
        self.net.read().upgrade()
    }

    /// Move the device into `net` (registration)
    pub fn set_net(&self, net: &Arc<crate::net::NetNamespace>) {
        *self.net.write() = Arc::downgrade(net);
    }

    /// Link came up (Linux netif_carrier_on); callable from any thread
    pub fn netif_carrier_on(&self) {
        self.carrier.store(true, Ordering::Release);
        if self.is_up() {
            self.flags.fetch_or(flags::IFF_RUNNING, Ordering::Release);
        }
    }

    /// Link went down (Linux netif_carrier_off)
    pub fn netif_carrier_off(&self) {
        self.carrier.store(false, Ordering::Release);
        self.flags.fetch_and(!flags::IFF_RUNNING, Ordering::Release);
    }

    /// Physical link state
    pub fn carrier_ok(&self) -> bool {
        self.carrier.load(Ordering::Acquire)
    }

    /// Get interface name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get MAC address
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Get MTU
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Set MTU
    pub fn set_mtu(&mut self, mtu: u32) {
        self.mtu = mtu;
    }

    /// Get interface flags
    pub fn get_flags(&self) -> u32 {
        self.flags.load(Ordering::Acquire)
    }

    /// Check if interface is up
    pub fn is_up(&self) -> bool {
        self.get_flags() & flags::IFF_UP != 0
    }

    /// Check if interface is running
    pub fn is_running(&self) -> bool {
        self.get_flags() & flags::IFF_RUNNING != 0
    }

    /// Bring interface up
    pub fn up(&self) -> Result<(), KernelError> {
        self.ops.open()?;
        let running = if self.carrier_ok() {
            flags::IFF_RUNNING
        } else {
            0
        };
        self.flags
            .fetch_or(flags::IFF_UP | running, Ordering::Release);
        Ok(())
    }

    /// Bring interface down
    pub fn down(&self) -> Result<(), KernelError> {
        self.flags
            .fetch_and(!(flags::IFF_UP | flags::IFF_RUNNING), Ordering::Release);
        self.ops.stop()?;
        Ok(())
    }

    /// Set promiscuous mode
    pub fn set_promisc(&self, enable: bool) {
        if enable {
            self.flags.fetch_or(flags::IFF_PROMISC, Ordering::Release);
        } else {
            self.flags.fetch_and(!flags::IFF_PROMISC, Ordering::Release);
        }
        self.ops.set_promisc(enable);
    }

    /// Get IPv4 address
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        *self.ipv4_addr.lock()
    }

    /// Get IPv4 netmask
    pub fn ipv4_netmask(&self) -> Option<Ipv4Addr> {
        *self.ipv4_netmask.lock()
    }

    /// Set IPv4 address and netmask
    pub fn set_ipv4(&self, addr: Ipv4Addr, netmask: Ipv4Addr) {
        *self.ipv4_addr.lock() = Some(addr);
        *self.ipv4_netmask.lock() = Some(netmask);
    }

    /// Transmit a packet
    pub fn xmit(&self, skb: Box<SkBuff>) -> Result<(), KernelError> {
        if !self.is_up() {
            return Err(KernelError::NetworkDown);
        }

        let len = skb.len() as u64;
        match self.ops.xmit(skb) {
            Ok(()) => {
                self.stats.inc_tx_packets();
                self.stats.add_tx_bytes(len);
                Ok(())
            }
            Err(KernelError::NoBufferSpace) => {
                // Queue (TX ring) full: dropped, like a qdisc drop
                self.stats.inc_tx_dropped();
                Err(KernelError::NoBufferSpace)
            }
            Err(e) => {
                self.stats.inc_tx_errors();
                Err(e)
            }
        }
    }

    /// Get RX wait queue (for blocking reads)
    pub fn rx_wait(&self) -> &WaitQueue {
        &self.rx_wait
    }

    /// Get TX wait queue (for blocking writes when buffer full)
    pub fn tx_wait(&self) -> &WaitQueue {
        &self.tx_wait
    }

    /// Wake up tasks waiting for RX data
    pub fn wake_rx(&self) {
        self.rx_wait.wake_all();
    }

    /// Wake up tasks waiting for TX space
    pub fn wake_tx(&self) {
        self.tx_wait.wake_all();
    }
}
