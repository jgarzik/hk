//! Network Device Abstraction
//!
//! This module defines the `NetDevice` trait and related types for
//! network interface management.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use spin::RwLock;

use crate::net::KernelError;
use crate::net::inet::ifaddr::IfAddrs;
use crate::net::skb::SkBuff;

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
    /// Driver signals L1 up (reported, never stored)
    pub const IFF_LOWER_UP: u32 = 1 << 16;
    /// Driver signals dormant (reported, never stored)
    pub const IFF_DORMANT: u32 = 1 << 17;

    /// Flags userspace may change (Linux dev_change_flags); IFF_UP is
    /// handled separately (open/close)
    pub const CHANGEABLE: u32 = IFF_NOARP | IFF_MULTICAST | IFF_PROMISC | IFF_ALLMULTI;
}

/// RFC 2863 operational states (Linux IF_OPER_*)
pub mod operstate {
    pub const IF_OPER_UNKNOWN: u8 = 0;
    pub const IF_OPER_DOWN: u8 = 2;
    pub const IF_OPER_UP: u8 = 6;
}

/// Link-layer types (Linux ARPHRD_*)
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_LOOPBACK: u16 = 772;

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

    /// Initial Maximum Transmission Unit (default: 1500)
    fn mtu(&self) -> u32 {
        1500
    }

    /// Largest MTU the device supports (Linux max_mtu; 0 = no limit)
    fn max_mtu(&self) -> u32 {
        1500
    }

    /// Open/start the interface (Linux ndo_open; called under RTNL with
    /// the device going up). Drivers report the current link state with
    /// `netif_carrier_on/off` from here.
    fn open(&self, _dev: &NetDevice) -> Result<(), KernelError> {
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

/// Static link-layer description of a device (Linux net_device fields set
/// by ether_setup/loopback_setup)
pub struct LinkInfo {
    /// ARPHRD_* type
    pub dev_type: u16,
    /// Initial flags (IFF_BROADCAST|IFF_MULTICAST, IFF_LOOPBACK|IFF_NOARP)
    pub flags: u32,
    /// Hardware broadcast address
    pub broadcast: [u8; 6],
    /// Transmit queue length (reported only; there is no qdisc)
    pub txqlen: u32,
    /// Smallest MTU accepted
    pub min_mtu: u32,
}

impl LinkInfo {
    /// Ethernet (Linux ether_setup)
    pub const ETHER: LinkInfo = LinkInfo {
        dev_type: ARPHRD_ETHER,
        flags: flags::IFF_BROADCAST | flags::IFF_MULTICAST,
        broadcast: [0xff; 6],
        txqlen: 1000,
        min_mtu: 68,
    };
    /// Loopback (Linux loopback_setup)
    pub const LOOPBACK: LinkInfo = LinkInfo {
        dev_type: ARPHRD_LOOPBACK,
        flags: flags::IFF_LOOPBACK,
        broadcast: [0; 6],
        txqlen: 1000,
        min_mtu: 68,
    };
}

/// Network device (Linux struct net_device)
///
/// Administrative state (`IFF_UP` and the changeable flags) lives in
/// `flags`; operational state (`IFF_RUNNING`, `IFF_LOWER_UP`, operstate)
/// is derived from it and the carrier on every read, like Linux
/// `dev_get_flags()`. Configuration changes (up/down, MTU, addresses) are
/// serialized by RTNL (`net::rtnl`); the fields are atomics or leaf
/// `RwLock`s so the receive path reads them without RTNL.
pub struct NetDevice {
    /// Interface name (e.g., "eth0")
    name: String,

    /// Interface index, unique per network namespace (lo = 1); 0 until
    /// registered
    ifindex: AtomicU32,

    /// Link-layer description
    link: LinkInfo,

    /// Hardware MAC address
    mac: [u8; 6],

    /// Maximum Transmission Unit
    mtu: AtomicU32,

    /// Administrative flags (IFF_UP, IFF_BROADCAST, ...); never contains
    /// IFF_RUNNING / IFF_LOWER_UP (derived)
    flags: AtomicU32,

    /// Device operations (provided by driver)
    ops: &'static dyn NetDeviceOps,

    /// Device statistics
    pub stats: NetDeviceStats,

    /// Protocol addresses by family (Linux in_device / inet6_dev). Leaf
    /// `RwLock`, thread context only; written only under RTNL, read via
    /// snapshots (`inet_addrs()`).
    addrs: RwLock<IfAddrs>,

    /// Network namespace the device lives in (weak: the namespace owns
    /// its devices). Thread context only; read on every received packet.
    net: RwLock<Weak<crate::net::NetNamespace>>,

    /// Physical link state (Linux carrier)
    carrier: AtomicBool,

    /// Number of carrier transitions (IFLA_CARRIER_CHANGES)
    carrier_changes: AtomicU32,

    /// Promiscuity and allmulti users (AF_PACKET memberships; Linux
    /// dev->promiscuity / allmulti); changed under RTNL
    promiscuity: AtomicU32,
    allmulti: AtomicU32,
}

impl NetDevice {
    /// Create a device named `name` (see `net::dev_alloc_name`)
    pub fn new(name: String, mac: [u8; 6], link: LinkInfo, ops: &'static dyn NetDeviceOps) -> Self {
        let mtu = ops.mtu();
        let flags = link.flags;
        Self {
            name,
            ifindex: AtomicU32::new(0),
            link,
            mac,
            mtu: AtomicU32::new(mtu),
            flags: AtomicU32::new(flags),
            ops,
            stats: NetDeviceStats::new(),
            addrs: RwLock::new(IfAddrs::default()),
            net: RwLock::new(Weak::new()),
            carrier: AtomicBool::new(true),
            carrier_changes: AtomicU32::new(0),
            promiscuity: AtomicU32::new(0),
            allmulti: AtomicU32::new(0),
        }
    }

    /// Network namespace of this device
    pub fn net(&self) -> Option<Arc<crate::net::NetNamespace>> {
        self.net.read().upgrade()
    }

    /// Move the device into `net` with index `ifindex` (registration)
    pub fn set_net(&self, net: &Arc<crate::net::NetNamespace>, ifindex: u32) {
        *self.net.write() = Arc::downgrade(net);
        self.ifindex.store(ifindex, Ordering::Release);
    }

    /// Interface index (0 = not registered)
    pub fn ifindex(&self) -> u32 {
        self.ifindex.load(Ordering::Acquire)
    }

    /// Link came up (Linux netif_carrier_on); callable from any thread
    pub fn netif_carrier_on(&self) {
        if !self.carrier.swap(true, Ordering::AcqRel) {
            self.carrier_changes.fetch_add(1, Ordering::Relaxed);
            self.link_changed();
        }
    }

    /// Link went down (Linux netif_carrier_off)
    pub fn netif_carrier_off(&self) {
        if self.carrier.swap(false, Ordering::AcqRel) {
            self.carrier_changes.fetch_add(1, Ordering::Relaxed);
            self.link_changed();
        }
    }

    /// Announce an operational change (Linux linkwatch -> RTM_NEWLINK)
    fn link_changed(&self) {
        if self.ifindex() != 0
            && let Some(net) = self.net()
        {
            crate::net::netlink::rtnetlink::notify_link(&net, self, Default::default());
        }
    }

    /// Physical link state
    pub fn carrier_ok(&self) -> bool {
        self.carrier.load(Ordering::Acquire)
    }

    /// Number of carrier transitions
    pub fn carrier_changes(&self) -> u32 {
        self.carrier_changes.load(Ordering::Relaxed)
    }

    /// Get interface name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get MAC address
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Link-layer description (type, broadcast, txqlen)
    pub fn link(&self) -> &LinkInfo {
        &self.link
    }

    /// Get MTU
    pub fn mtu(&self) -> u32 {
        self.mtu.load(Ordering::Acquire)
    }

    /// MTU bounds (min, max; max 0 = unlimited)
    pub fn mtu_range(&self) -> (u32, u32) {
        (self.link.min_mtu, self.ops.max_mtu())
    }

    /// Store a validated MTU (RTNL held; see `rtnl::dev_set_mtu`)
    pub(crate) fn store_mtu(&self, mtu: u32) {
        self.mtu.store(mtu, Ordering::Release);
    }

    /// Administrative flags as stored (no derived bits)
    pub fn admin_flags(&self) -> u32 {
        self.flags.load(Ordering::Acquire)
    }

    /// Store changeable flags (RTNL held)
    pub(crate) fn set_flags(&self, new: u32) {
        let keep = !flags::CHANGEABLE;
        let cur = self.admin_flags();
        self.flags
            .store((cur & keep) | (new & flags::CHANGEABLE), Ordering::Release);
    }

    /// Flags as reported to userspace (Linux dev_get_flags): admin flags
    /// plus IFF_RUNNING (operationally up) and IFF_LOWER_UP (carrier)
    /// while the device is up
    pub fn get_flags(&self) -> u32 {
        let mut f =
            self.admin_flags() & !(flags::IFF_RUNNING | flags::IFF_LOWER_UP | flags::IFF_DORMANT);
        if f & flags::IFF_UP != 0 {
            let op = self.operstate();
            if op == operstate::IF_OPER_UP || op == operstate::IF_OPER_UNKNOWN {
                f |= flags::IFF_RUNNING;
            }
            if self.carrier_ok() {
                f |= flags::IFF_LOWER_UP;
            }
        }
        f
    }

    /// RFC 2863 operational state: DOWN when administratively down or
    /// without carrier; loopback (no link management) reports UNKNOWN
    /// like Linux `lo`
    pub fn operstate(&self) -> u8 {
        if !self.is_up() {
            operstate::IF_OPER_DOWN
        } else if self.is_loopback() {
            operstate::IF_OPER_UNKNOWN
        } else if self.carrier_ok() {
            operstate::IF_OPER_UP
        } else {
            operstate::IF_OPER_DOWN
        }
    }

    /// Check if interface is administratively up
    pub fn is_up(&self) -> bool {
        self.admin_flags() & flags::IFF_UP != 0
    }

    /// Loopback device
    pub fn is_loopback(&self) -> bool {
        self.admin_flags() & flags::IFF_LOOPBACK != 0
    }

    /// Open the device (RTNL held; see `rtnl::dev_change_flags`)
    pub(crate) fn open(&self) -> Result<(), KernelError> {
        self.ops.open(self)?;
        self.flags.fetch_or(flags::IFF_UP, Ordering::AcqRel);
        Ok(())
    }

    /// Close the device (RTNL held)
    pub(crate) fn close(&self) {
        self.flags.fetch_and(!flags::IFF_UP, Ordering::AcqRel);
        let _ = self.ops.stop();
    }

    /// Add or remove a promiscuity user (Linux dev_set_promiscuity, RTNL
    /// held): the driver is told on the first and last one. Like Linux,
    /// the IFF_PROMISC reported to userspace is only the admin flag.
    pub fn set_promiscuity(&self, _rtnl: &crate::net::rtnl::RtnlGuard, inc: i32) {
        let old = self.promiscuity.load(Ordering::Acquire);
        let new = old.saturating_add_signed(inc);
        self.promiscuity.store(new, Ordering::Release);
        if (old == 0) != (new == 0) {
            self.ops.set_promisc(new != 0);
        }
    }

    /// Add or remove an allmulti user (Linux dev_set_allmulti, RTNL held)
    pub fn set_allmulti(&self, _rtnl: &crate::net::rtnl::RtnlGuard, inc: i32) {
        let old = self.allmulti.load(Ordering::Acquire);
        self.allmulti
            .store(old.saturating_add_signed(inc), Ordering::Release);
    }

    /// Promiscuity users (AF_PACKET memberships)
    pub fn promiscuity(&self) -> u32 {
        self.promiscuity.load(Ordering::Acquire)
    }

    /// Snapshot of the IPv4 addresses (primaries before secondaries)
    pub fn inet_addrs(&self) -> alloc::vec::Vec<crate::net::inet::ifaddr::InIfaddr> {
        self.addrs.read().inet.clone()
    }

    /// Replace the IPv4 address list (RTNL held; inet::ifaddr only)
    pub(crate) fn addrs_mut<R>(&self, f: impl FnOnce(&mut IfAddrs) -> R) -> R {
        f(&mut self.addrs.write())
    }

    /// Transmit a packet
    pub fn xmit(&self, skb: Box<SkBuff>) -> Result<(), KernelError> {
        if !self.is_up() {
            self.stats.inc_tx_dropped();
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
}
