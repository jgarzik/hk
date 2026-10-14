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
//! Device core (core/dev.rs: netif_receive_skb, NAPI, softnet/N threads)
//!         |
//!         v
//! Device Driver (driver/e1000.rs; loopback in ns/net.rs)
//!         |
//!         v
//! Hardware (Intel 82540EM via PCI)
//! ```
//!
//! Receive processing never runs in interrupt context: driver ISRs only
//! schedule NAPI, and `softnet/N` kernel threads (or a sending task, for
//! loopback) run the protocol code. The namespace of a received packet is
//! that of its device (`skb.net()`), never the current task's.
//!
//! ## Static Network Configuration
//!
//! For MVP, we use static IP configuration:
//! - Guest IP: 10.0.2.15/24
//! - Gateway: 10.0.2.2 (QEMU slirp default)
//! - DNS: 10.0.2.3 (optional)

use alloc::sync::Arc;

// Re-export namespace access
pub use crate::ns::{INIT_NET_NS, NetNamespace, current_net_ns, init_net_ns};

// Submodules
pub mod arp;
#[path = "core/dev.rs"]
pub mod dev;
pub mod device;
pub mod driver;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod request_sock;
pub mod route;
pub mod skb;
pub mod socket;
pub mod socket_file;
pub mod syscall;
pub mod tcp;
pub mod tcp_input;
pub mod tcp_output;
pub mod udp;

// Re-export commonly used types
pub use device::{NetDevice, NetDeviceOps, NetDeviceStats};
pub use ethernet::EtherType;
pub use ipv4::Ipv4Addr;
pub use skb::SkBuff;
pub use socket::{Socket, SocketOptions};

// Import unified error type
use crate::error::KernelError;

/// Start the per-CPU softnet threads (after scheduling is enabled)
pub fn start_threads() {
    dev::softnet_init();
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

    // Protocol handlers by EtherType (IPv6 will add 0x86DD here)
    dev::dev_add_pack(EtherType::Ipv4.to_be(), ipv4::ip_rcv);
    dev::dev_add_pack(EtherType::Arp.to_be(), arp::arp_rcv);

    crate::printkln!("net: configured 10.0.2.15/24, gw 10.0.2.2");
}

/// Network configuration
#[derive(Debug, Clone, Copy)]
pub struct NetConfig {
    pub ipv4_addr: Ipv4Addr,
    pub ipv4_netmask: Ipv4Addr,
    pub ipv4_gateway: Ipv4Addr,
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
    if init_ns.device_count() == 1
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
