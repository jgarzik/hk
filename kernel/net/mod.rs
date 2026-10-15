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
//! Socket layer (socket.rs: sockfs + per-family ops; sock.rs: common state)
//!         |
//!         v
//! Transport Layer (tcp.rs, udp.rs)
//!         |
//!         v
//! Network Layer (ipv4.rs, inet/{ifaddr,fib,route}.rs, icmp.rs)
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
//! ## Configuration
//!
//! Like Linux, interfaces start down and unconfigured (`lo` included; it
//! gets 127.0.0.1/8 when brought up). Userspace configures links,
//! addresses and routes with NETLINK_ROUTE (`netlink/`) or SIOC* ioctls
//! (`devioctl.rs`); all changes serialize on RTNL (`rtnl.rs`).

use alloc::sync::Arc;

// Re-export namespace access
pub use crate::ns::{INIT_NET_NS, NetNamespace, current_net_ns, init_net_ns};

// Submodules
pub mod af_inet;
pub mod arp;
#[path = "core/dev.rs"]
pub mod dev;
pub mod device;
pub mod devioctl;
pub mod dgram;
pub mod driver;
pub mod ethernet;
#[path = "core/filter.rs"]
pub mod filter;
pub mod icmp;
pub mod inet;
pub mod ipv4;
pub mod msg;
#[path = "core/neigh.rs"]
pub mod neigh;
pub mod netlink;
pub mod packet;
pub mod ping;
pub mod proc;
pub mod raw;
pub mod rtnl;
pub mod skb;
pub mod sock;
pub mod socket;
pub mod syscall;
pub mod sysctl;
pub mod tcp;
pub mod udp;
pub mod unix;

// Re-export commonly used types
pub use device::{NetDevice, NetDeviceOps, NetDeviceStats};
pub use ethernet::EtherType;
pub use ipv4::Ipv4Addr;
pub use skb::SkBuff;

// Import unified error type
use crate::error::KernelError;

/// Start the per-CPU softnet threads (after scheduling is enabled)
pub fn start_threads() {
    dev::softnet_init();
}

/// Initialize the network subsystem
pub fn init() {
    // Protocol handlers by EtherType (IPv6 will add 0x86DD here)
    dev::dev_add_pack(EtherType::Ipv4.to_be(), ipv4::ip_rcv);
    dev::dev_add_pack(EtherType::Arp.to_be(), arp::arp_rcv);
    // AF_PACKET sees frames in both directions
    dev::dev_add_tap(packet::tap);
}

/// Name for a new physical device from a template like "eth%d" (unique
/// in the init namespace, where physical devices register)
pub fn dev_alloc_name(template: &str) -> alloc::string::String {
    init_net_ns().dev_alloc_name(template)
}

/// Register a physical network device in the init namespace; it starts
/// down and unconfigured
pub fn register_netdev(dev: Arc<NetDevice>) {
    let m = dev.mac();
    crate::printkln!(
        "net: registered {} (MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        dev.name(),
        m[0],
        m[1],
        m[2],
        m[3],
        m[4],
        m[5]
    );
    init_net_ns().register_device(dev);
}
