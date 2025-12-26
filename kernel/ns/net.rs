//! Network Namespace Implementation
//!
//! This module implements network namespace isolation, providing per-namespace:
//! - Network devices (each namespace has its own loopback)
//! - TCP connection table
//! - Routing table
//! - ARP cache
//! - Network configuration
//!
//! ## Linux Compatibility
//!
//! Follows the Linux kernel's network namespace design where:
//! - New namespaces start with only a loopback device
//! - Physical devices belong to the init namespace by default
//! - Sockets, routes, and ARP entries are namespace-local

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::{Lazy, Mutex, RwLock};

use crate::net::NetConfig;
use crate::net::NetError;
use crate::net::device::{NetDevice, NetDeviceOps, flags as dev_flags};
use crate::net::ipv4::Ipv4Addr;
use crate::net::route::Route;
use crate::net::socket::Socket;
use crate::net::tcp::TcpFourTuple;
use crate::net::udp::UdpTwoTuple;

// ARP types from arp.rs that we need
use crate::net::arp::ArpEntry;

/// Network namespace - isolates network stack per-namespace
///
/// Each network namespace has its own:
/// - Network devices (loopback always present)
/// - Routing table
/// - TCP connection table
/// - ARP cache
/// - Network configuration
pub struct NetNamespace {
    /// Network devices in this namespace
    pub devices: RwLock<Vec<Arc<NetDevice>>>,

    /// Network configuration (IP, netmask, gateway)
    pub config: RwLock<Option<NetConfig>>,

    /// Routing table
    pub routes: RwLock<Vec<Route>>,

    /// TCP connection table (four-tuple -> socket)
    pub tcp_connections: RwLock<BTreeMap<TcpFourTuple, Arc<Socket>>>,

    /// TCP listening sockets (local_port -> socket)
    /// Following Linux's inet_hashtables listening hash
    pub tcp_listeners: RwLock<BTreeMap<u16, Arc<Socket>>>,

    /// UDP socket table (two-tuple -> socket)
    pub udp_sockets: RwLock<BTreeMap<UdpTwoTuple, Arc<Socket>>>,

    /// ARP cache entries indexed by IP address
    pub arp_entries: Mutex<BTreeMap<u32, ArpEntry>>,

    /// Packets waiting for ARP resolution
    pub arp_pending: Mutex<BTreeMap<u32, VecDeque<crate::net::arp::PendingPacket>>>,

    /// Next ephemeral port
    pub next_port: AtomicU32,

    /// Loopback device for this namespace
    pub loopback: RwLock<Option<Arc<NetDevice>>>,
}

impl NetNamespace {
    /// Create a new network namespace with loopback device
    pub fn new() -> Arc<Self> {
        let ns = Arc::new(Self {
            devices: RwLock::new(Vec::new()),
            config: RwLock::new(None),
            routes: RwLock::new(Vec::new()),
            tcp_connections: RwLock::new(BTreeMap::new()),
            tcp_listeners: RwLock::new(BTreeMap::new()),
            udp_sockets: RwLock::new(BTreeMap::new()),
            arp_entries: Mutex::new(BTreeMap::new()),
            arp_pending: Mutex::new(BTreeMap::new()),
            next_port: AtomicU32::new(32768),
            loopback: RwLock::new(None),
        });

        // Create loopback device for this namespace
        let lo = create_loopback_device();
        ns.devices.write().push(lo.clone());
        *ns.loopback.write() = Some(lo.clone());

        // Add loopback route (127.0.0.0/8 -> lo)
        ns.routes.write().push(Route {
            dest: Ipv4Addr::new(127, 0, 0, 0),
            netmask: Ipv4Addr::new(255, 0, 0, 0),
            gateway: Ipv4Addr::new(0, 0, 0, 0),
            dev: lo,
            flags: crate::net::route::flags::RTF_UP,
            metric: 0,
        });

        ns
    }

    /// Clone this namespace (creates new empty namespace with loopback)
    ///
    /// Network namespaces don't copy state - new namespace starts fresh
    /// with only loopback device (unlike mount namespace which clones tree).
    pub fn clone_ns(&self) -> Result<Arc<Self>, i32> {
        Ok(Self::new())
    }

    // ========================================================================
    // TCP connection management
    // ========================================================================

    /// Register a TCP connection in this namespace
    pub fn tcp_register(&self, tuple: TcpFourTuple, socket: Arc<Socket>) {
        self.tcp_connections.write().insert(tuple, socket);
    }

    /// Unregister a TCP connection from this namespace
    pub fn tcp_unregister(&self, tuple: &TcpFourTuple) {
        self.tcp_connections.write().remove(tuple);
    }

    /// Look up a TCP connection in this namespace
    pub fn tcp_lookup(&self, tuple: &TcpFourTuple) -> Option<Arc<Socket>> {
        self.tcp_connections.read().get(tuple).cloned()
    }

    /// Register a listening socket in this namespace
    ///
    /// Following Linux's inet_csk_listen_start() which adds to listening hash.
    pub fn tcp_listen_register(&self, port: u16, socket: Arc<Socket>) {
        self.tcp_listeners.write().insert(port, socket);
    }

    /// Unregister a listening socket from this namespace
    pub fn tcp_listen_unregister(&self, port: u16) {
        self.tcp_listeners.write().remove(&port);
    }

    /// Look up a listening socket by port
    ///
    /// Following Linux's __inet_lookup_listener().
    /// For now we just match by port; Linux also considers local address.
    pub fn tcp_lookup_listener(&self, local_port: u16) -> Option<Arc<Socket>> {
        self.tcp_listeners.read().get(&local_port).cloned()
    }

    /// Allocate an ephemeral port in this namespace
    pub fn alloc_port(&self) -> u16 {
        let port = self.next_port.fetch_add(1, Ordering::Relaxed);
        if port > 60999 {
            self.next_port.store(32768, Ordering::Relaxed);
        }
        port as u16
    }

    // ========================================================================
    // UDP socket management
    // ========================================================================

    /// Register a UDP socket in this namespace
    pub fn udp_register(&self, tuple: UdpTwoTuple, socket: Arc<Socket>) {
        self.udp_sockets.write().insert(tuple, socket);
    }

    /// Unregister a UDP socket from this namespace
    pub fn udp_unregister(&self, tuple: &UdpTwoTuple) {
        self.udp_sockets.write().remove(tuple);
    }

    /// Look up a UDP socket by port in this namespace
    ///
    /// For UDP, we only need to match by local port (and optionally local address).
    /// This is simpler than TCP's four-tuple matching.
    pub fn udp_lookup_by_port(&self, local_port: u16) -> Option<Arc<Socket>> {
        let sockets = self.udp_sockets.read();

        // First try to find exact match with any local address
        for (tuple, socket) in sockets.iter() {
            if tuple.local_port == local_port {
                return Some(Arc::clone(socket));
            }
        }

        None
    }

    // ========================================================================
    // Routing management
    // ========================================================================

    /// Look up a route in this namespace
    pub fn route_lookup(&self, dest: Ipv4Addr) -> Result<(Arc<NetDevice>, Ipv4Addr), NetError> {
        let table = self.routes.read();

        // Find best matching route (longest prefix)
        let mut best_route: Option<&Route> = None;
        let mut best_prefix_len = 0u32;

        for route in table.iter() {
            if route.matches(dest) {
                let prefix_len = route.netmask.to_u32().count_ones();
                if best_route.is_none() || prefix_len > best_prefix_len {
                    best_route = Some(route);
                    best_prefix_len = prefix_len;
                }
            }
        }

        match best_route {
            Some(route) => {
                let next_hop = if route.is_gateway() {
                    route.gateway
                } else {
                    dest
                };
                Ok((Arc::clone(&route.dev), next_hop))
            }
            None => Err(NetError::NoRoute),
        }
    }

    /// Add a route to this namespace
    pub fn add_route(&self, route: Route) {
        self.routes.write().push(route);
    }

    /// Add an interface route in this namespace
    pub fn add_interface_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, dev: Arc<NetDevice>) {
        self.routes.write().push(Route {
            dest,
            netmask,
            gateway: Ipv4Addr::new(0, 0, 0, 0),
            dev,
            flags: crate::net::route::flags::RTF_UP,
            metric: 0,
        });
    }

    /// Add a default route in this namespace
    pub fn add_default_route(&self, gateway: Ipv4Addr, dev: Arc<NetDevice>) {
        use crate::net::route::flags;
        self.routes.write().push(Route {
            dest: Ipv4Addr::new(0, 0, 0, 0),
            netmask: Ipv4Addr::new(0, 0, 0, 0),
            gateway,
            dev,
            flags: flags::RTF_UP | flags::RTF_GATEWAY | flags::RTF_DEFAULT,
            metric: 100,
        });
    }

    // ========================================================================
    // ARP cache management
    // ========================================================================

    /// Look up an ARP entry in this namespace
    pub fn arp_lookup(&self, ip: Ipv4Addr) -> Option<ArpEntry> {
        self.arp_entries.lock().get(&ip.to_u32()).cloned()
    }

    /// Insert an ARP entry in this namespace
    pub fn arp_insert(&self, entry: ArpEntry) {
        self.arp_entries.lock().insert(entry.ip.to_u32(), entry);
    }

    /// Queue a packet waiting for ARP resolution
    pub fn arp_queue_packet(&self, ip: Ipv4Addr, packet: crate::net::arp::PendingPacket) {
        self.arp_pending
            .lock()
            .entry(ip.to_u32())
            .or_default()
            .push_back(packet);
    }

    /// Take all pending packets for an IP (after ARP resolution)
    pub fn arp_take_pending(&self, ip: Ipv4Addr) -> VecDeque<crate::net::arp::PendingPacket> {
        self.arp_pending
            .lock()
            .remove(&ip.to_u32())
            .unwrap_or_default()
    }

    // ========================================================================
    // Device management
    // ========================================================================

    /// Get a network device by name in this namespace
    pub fn get_device(&self, name: &str) -> Option<Arc<NetDevice>> {
        self.devices
            .read()
            .iter()
            .find(|d| d.name() == name)
            .cloned()
    }

    /// Get the first (default) network device in this namespace
    pub fn get_default_device(&self) -> Option<Arc<NetDevice>> {
        self.devices.read().first().cloned()
    }

    /// Register a network device in this namespace
    pub fn register_device(&self, dev: Arc<NetDevice>) {
        self.devices.write().push(dev);
    }

    /// Get network configuration for this namespace
    pub fn get_config(&self) -> Option<NetConfig> {
        *self.config.read()
    }

    /// Set network configuration for this namespace
    pub fn set_config(&self, config: NetConfig) {
        *self.config.write() = Some(config);
    }
}

impl Default for NetNamespace {
    fn default() -> Self {
        // Can't use Self::new() here since it returns Arc
        // This is only used internally
        Self {
            devices: RwLock::new(Vec::new()),
            config: RwLock::new(None),
            routes: RwLock::new(Vec::new()),
            tcp_connections: RwLock::new(BTreeMap::new()),
            tcp_listeners: RwLock::new(BTreeMap::new()),
            udp_sockets: RwLock::new(BTreeMap::new()),
            arp_entries: Mutex::new(BTreeMap::new()),
            arp_pending: Mutex::new(BTreeMap::new()),
            next_port: AtomicU32::new(32768),
            loopback: RwLock::new(None),
        }
    }
}

// ============================================================================
// Loopback Device Implementation
// ============================================================================

/// Loopback device operations
struct LoopbackOps;

impl NetDeviceOps for LoopbackOps {
    fn xmit(&self, skb: alloc::boxed::Box<crate::net::skb::SkBuff>) -> Result<(), NetError> {
        // Loopback: packet comes right back as received
        // For a proper implementation, we'd queue it for rx processing
        // For now, just drop it (loopback in userspace isn't critical for namespace tests)
        drop(skb);
        Ok(())
    }

    fn mac_address(&self) -> [u8; 6] {
        [0, 0, 0, 0, 0, 0] // Loopback has no MAC
    }

    fn mtu(&self) -> u32 {
        65536 // Loopback has large MTU
    }
}

/// Static loopback operations
static LOOPBACK_OPS: LoopbackOps = LoopbackOps;

/// Create a loopback device
fn create_loopback_device() -> Arc<NetDevice> {
    use alloc::string::String;

    let dev = NetDevice::new(String::from("lo"), [0, 0, 0, 0, 0, 0], &LOOPBACK_OPS);

    // Set loopback IP address
    dev.set_ipv4(Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(255, 0, 0, 0));

    // Bring interface up with loopback flag
    dev.flags.fetch_or(
        dev_flags::IFF_UP | dev_flags::IFF_LOOPBACK | dev_flags::IFF_RUNNING,
        Ordering::Release,
    );

    Arc::new(dev)
}

// ============================================================================
// Global Init Network Namespace
// ============================================================================

/// Initial (root) network namespace
///
/// Physical network devices are registered here. Created lazily on first access.
pub static INIT_NET_NS: Lazy<Arc<NetNamespace>> = Lazy::new(NetNamespace::new);

/// Get the init network namespace
pub fn init_net_ns() -> Arc<NetNamespace> {
    INIT_NET_NS.clone()
}
