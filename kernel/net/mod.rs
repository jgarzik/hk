//! Network Subsystem
//!
//! This module implements a TCP/IP network stack for the hk kernel.
//!
//! ## Architecture
//!
//! ```text
//! Application Layer (userspace)
//!         |
//!         v
//! Socket Syscalls (socket, connect, read, write, etc.)
//!         |
//!         v
//! Socket Layer (socket.rs, socket_file.rs)
//!         |
//!         v
//! Transport Layer (tcp.rs, udp.rs)
//!         |
//!         v
//! Network Layer (ipv4.rs, route.rs, icmp.rs)
//!         |
//!         v
//! Link Layer (ethernet.rs, arp.rs)
//!         |
//!         v
//! Device Driver (driver/e1000.rs)
//!         |
//!         v
//! Hardware (Intel 82540EM via PCI)
//! ```
//!
//! ## Static Network Configuration
//!
//! For MVP, we use static IP configuration:
//! - Guest IP: 10.0.2.15/24
//! - Gateway: 10.0.2.2 (QEMU slirp default)
//! - DNS: 10.0.2.3 (optional)

use alloc::boxed::Box;
use alloc::sync::Arc;

// Re-export namespace access
pub use crate::ns::{INIT_NET_NS, NetNamespace, current_net_ns, init_net_ns};

// Submodules
pub mod arp;
pub mod device;
pub mod driver;
pub mod ethernet;
pub mod ipv4;
pub mod route;
pub mod skb;
pub mod socket;
pub mod socket_file;
pub mod syscall;
pub mod tcp;
pub mod tcp_input;
pub mod tcp_output;

// Re-export commonly used types
pub use device::{NetDevice, NetDeviceOps, NetDeviceStats};
pub use ethernet::EtherType;
pub use ipv4::Ipv4Addr;
pub use skb::SkBuff;
pub use socket::Socket;

/// Network error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// No route to destination
    NoRoute,
    /// Network is unreachable
    NetworkUnreachable,
    /// Host is unreachable
    HostUnreachable,
    /// Connection refused
    ConnectionRefused,
    /// Connection reset
    ConnectionReset,
    /// Connection timed out
    TimedOut,
    /// Address already in use
    AddressInUse,
    /// Address not available
    AddressNotAvailable,
    /// No buffer space available
    NoBufferSpace,
    /// Operation would block
    WouldBlock,
    /// Invalid argument
    InvalidArgument,
    /// Device not found
    DeviceNotFound,
    /// Protocol not supported
    ProtocolNotSupported,
    /// Socket type not supported
    SocketTypeNotSupported,
    /// Operation not supported
    NotSupported,
    /// Device is down
    DeviceDown,
    /// Packet too large
    PacketTooLarge,
    /// Checksum error
    ChecksumError,
    /// Out of memory
    OutOfMemory,
}

impl NetError {
    /// Convert to errno value for syscalls
    pub fn to_errno(self) -> i32 {
        match self {
            NetError::NoRoute => -libc::ENETUNREACH,
            NetError::NetworkUnreachable => -libc::ENETUNREACH,
            NetError::HostUnreachable => -libc::EHOSTUNREACH,
            NetError::ConnectionRefused => -libc::ECONNREFUSED,
            NetError::ConnectionReset => -libc::ECONNRESET,
            NetError::TimedOut => -libc::ETIMEDOUT,
            NetError::AddressInUse => -libc::EADDRINUSE,
            NetError::AddressNotAvailable => -libc::EADDRNOTAVAIL,
            NetError::NoBufferSpace => -libc::ENOBUFS,
            NetError::WouldBlock => -libc::EAGAIN,
            NetError::InvalidArgument => -libc::EINVAL,
            NetError::DeviceNotFound => -libc::ENODEV,
            NetError::ProtocolNotSupported => -libc::EPROTONOSUPPORT,
            NetError::SocketTypeNotSupported => -libc::ESOCKTNOSUPPORT,
            NetError::NotSupported => -libc::EOPNOTSUPP,
            NetError::DeviceDown => -libc::ENETDOWN,
            NetError::PacketTooLarge => -libc::EMSGSIZE,
            NetError::ChecksumError => -libc::EBADMSG,
            NetError::OutOfMemory => -libc::ENOMEM,
        }
    }
}

/// Initialize the network subsystem
pub fn init() {
    crate::printkln!("net: initializing network subsystem");

    // Static IP configuration for QEMU slirp networking
    let config = NetConfig {
        ipv4_addr: Ipv4Addr::new(10, 0, 2, 15),
        ipv4_netmask: Ipv4Addr::new(255, 255, 255, 0),
        ipv4_gateway: Ipv4Addr::new(10, 0, 2, 2),
    };

    // Store config in init network namespace
    INIT_NET_NS.set_config(config);

    crate::printkln!("net: configured 10.0.2.15/24, gw 10.0.2.2");
}

/// Network configuration
#[derive(Debug, Clone, Copy)]
pub struct NetConfig {
    pub ipv4_addr: Ipv4Addr,
    pub ipv4_netmask: Ipv4Addr,
    pub ipv4_gateway: Ipv4Addr,
}

/// Get the current network configuration from current namespace
pub fn get_config() -> Option<NetConfig> {
    current_net_ns().get_config()
}

/// Register a network device
///
/// Physical devices are registered in the init network namespace.
pub fn register_netdev(dev: Arc<NetDevice>) {
    crate::printkln!(
        "net: registered {} (MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        dev.name(),
        dev.mac()[0],
        dev.mac()[1],
        dev.mac()[2],
        dev.mac()[3],
        dev.mac()[4],
        dev.mac()[5]
    );

    // Register device in init network namespace
    let init_ns = init_net_ns();

    // Configure device with static IP if this is the first physical device
    // (init namespace starts with only loopback)
    if init_ns.devices.read().len() == 1
        && let Some(config) = init_ns.get_config()
    {
        dev.set_ipv4(config.ipv4_addr, config.ipv4_netmask);

        // Add routes for this device in init namespace
        init_ns.add_interface_route(
            config.ipv4_addr & config.ipv4_netmask,
            config.ipv4_netmask,
            Arc::clone(&dev),
        );
        init_ns.add_default_route(config.ipv4_gateway, Arc::clone(&dev));
    }

    // Add to init namespace
    init_ns.register_device(dev);
}

/// Get a network device by name in current namespace
pub fn get_netdev(name: &str) -> Option<Arc<NetDevice>> {
    current_net_ns().get_device(name)
}

/// Get the first network device in current namespace (for simple single-NIC setups)
pub fn get_default_netdev() -> Option<Arc<NetDevice>> {
    current_net_ns().get_default_device()
}

/// Receive path entry point - called by device drivers
///
/// This is the main entry point for received packets. The driver
/// calls this after filling the SkBuff with received data.
pub fn net_rx(skb: SkBuff) {
    // Parse Ethernet header and dispatch
    match ethernet::eth_type_trans(&skb) {
        EtherType::Ipv4 => ipv4::ip_rcv(skb),
        EtherType::Arp => arp::arp_rcv(skb),
        EtherType::Ipv6 => {
            // IPv6 not supported yet - drop silently
        }
        EtherType::Vlan => {
            // VLAN tagging not supported yet - drop silently
        }
        EtherType::Unknown(_) => {
            // Unknown protocol - drop
        }
    }
}

/// Transmit a packet through the appropriate interface
///
/// Called by the IP layer after routing decision is made.
pub fn dev_queue_xmit(skb: Box<SkBuff>) -> Result<(), NetError> {
    // Clone the device reference before moving skb
    let dev = skb.dev.clone().ok_or(NetError::DeviceNotFound)?;

    if !dev.is_up() {
        return Err(NetError::DeviceDown);
    }

    // Let the device transmit the packet
    dev.xmit(skb)
}

/// libc constants for errno conversion
mod libc {
    pub const ENETUNREACH: i32 = 101;
    pub const EHOSTUNREACH: i32 = 113;
    pub const ECONNREFUSED: i32 = 111;
    pub const ECONNRESET: i32 = 104;
    pub const ETIMEDOUT: i32 = 110;
    pub const EADDRINUSE: i32 = 98;
    pub const EADDRNOTAVAIL: i32 = 99;
    pub const ENOBUFS: i32 = 105;
    pub const EAGAIN: i32 = 11;
    pub const EINVAL: i32 = 22;
    pub const ENODEV: i32 = 19;
    pub const EPROTONOSUPPORT: i32 = 93;
    pub const ESOCKTNOSUPPORT: i32 = 94;
    pub const EOPNOTSUPP: i32 = 95;
    pub const ENETDOWN: i32 = 100;
    pub const EMSGSIZE: i32 = 90;
    pub const EBADMSG: i32 = 74;
    pub const ENOMEM: i32 = 12;
}
