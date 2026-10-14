//! Network Namespace Implementation
//!
//! This module implements network namespace isolation, providing per-namespace:
//! - Network devices (each namespace has its own loopback)
//! - TCP connection table
//! - IPv4 FIB (`net::inet::fib`)
//! - ARP cache
//! - netlink sockets
//!
//! ## Linux Compatibility
//!
//! Follows the Linux kernel's network namespace design where:
//! - New namespaces start with only a loopback device
//! - Physical devices belong to the init namespace by default
//! - Sockets, routes, and ARP entries are namespace-local

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::{Lazy, RwLock};

use crate::error::KernelError;
use crate::net::device::{LinkInfo, NetDevice, NetDeviceOps};
use crate::net::inet::fib::Fib;
use crate::net::inet::port::PortRange;
use crate::net::ipv4::Ipv4Addr;
use crate::net::netlink::NlTable;
use crate::net::tcp::{TcpFourTuple, TcpSock};
use crate::net::udp::UdpTable;

/// Network namespace - isolates network stack per-namespace
///
/// Tables are reached only through the lookup/insert methods below, which
/// return owned values or `Arc` handles and never let a lock guard escape,
/// so the backing synchronization (today `RwLock`/`Mutex`, thread context
/// only, leaf locks) can later become RCU without touching callers. Lock
/// order: a socket lock may be held while calling these; none of them is
/// held while taking a socket lock.
///
/// Each network namespace has its own:
/// - Network devices (loopback always present, ifindex 1)
/// - IPv4 FIB
/// - TCP/UDP tables
/// - ARP cache
/// - netlink sockets
pub struct NetNamespace {
    /// Network devices in this namespace (registration = ifindex order)
    devices: RwLock<Vec<Arc<NetDevice>>>,

    /// Next interface index (Linux dev_new_index; lo gets 1)
    next_ifindex: AtomicU32,

    /// IPv4 routing tables
    pub fib: Fib,

    /// netlink sockets bound in this namespace
    pub nl: NlTable,

    /// TCP connection table (four-tuple -> socket)
    tcp_connections: RwLock<BTreeMap<TcpFourTuple, Arc<TcpSock>>>,

    /// TCP listening sockets (local_port -> socket)
    /// Following Linux's inet_hashtables listening hash
    tcp_listeners: RwLock<BTreeMap<u16, Vec<Arc<TcpSock>>>>,

    /// UDP sockets by local port
    pub udp: UdpTable,

    /// TCP sockets owning a local port
    pub tcp_bind: crate::net::tcp::TcpBind,

    /// net.ipv4.ip_local_port_range
    pub port_range: PortRange,

    /// /proc/sys/net values (`net::sysctl`)
    pub sysctl: crate::net::sysctl::NetSysctl,

    /// IPv4 reassembly queues
    pub frags: crate::net::inet::frag::FragTable,

    /// Learned path MTUs
    pub pmtu: crate::net::inet::route::PmtuCache,

    /// ICMP rate-limit state
    pub icmp: crate::net::icmp::IcmpRate,

    /// Ping sockets by echo identifier
    pub ping: crate::net::ping::PingTable,

    /// Raw sockets by protocol
    pub raw: crate::net::raw::RawTable,

    /// Key of the IP identification hash (Linux ip_id_key)
    pub ip_id_key: [u64; 2],

    /// ARP neighbour table (IPv6 neighbour discovery gets its own)
    pub arp: Arc<crate::net::neigh::NeighTable>,

    /// Loopback device for this namespace
    loopback: RwLock<Option<Arc<NetDevice>>>,
}

impl NetNamespace {
    /// Create a new network namespace with loopback device
    pub fn new() -> Arc<Self> {
        let ns = Arc::new(Self {
            devices: RwLock::new(Vec::new()),
            next_ifindex: AtomicU32::new(1),
            fib: Fib::new(),
            nl: NlTable::new(),
            tcp_connections: RwLock::new(BTreeMap::new()),
            tcp_listeners: RwLock::new(BTreeMap::new()),
            udp: UdpTable::default(),
            tcp_bind: Default::default(),
            port_range: PortRange::default(),
            sysctl: Default::default(),
            frags: Default::default(),
            pmtu: Default::default(),
            icmp: Default::default(),
            ping: Default::default(),
            raw: Default::default(),
            ip_id_key: [
                ((crate::random::get_random_u32() as u64) << 32)
                    | crate::random::get_random_u32() as u64,
                ((crate::random::get_random_u32() as u64) << 32)
                    | crate::random::get_random_u32() as u64,
            ],
            arp: crate::net::neigh::NeighTable::new(&crate::net::arp::ARP_OPS),
            loopback: RwLock::new(None),
        });

        // Loopback device: ifindex 1, down and without addresses until
        // brought up (then 127.0.0.1/8, like Linux)
        let lo = create_loopback_device();
        ns.register_device(Arc::clone(&lo));
        *ns.loopback.write() = Some(lo);

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

    /// Register a TCP connection; false if the four-tuple is taken (an
    /// existing connection is never replaced or shadowed: Linux
    /// inet_ehash_insert / __inet_hash_connect uniqueness)
    pub fn tcp_register(&self, tuple: TcpFourTuple, socket: Arc<TcpSock>) -> bool {
        let mut t = self.tcp_connections.write();
        if t.contains_key(&tuple) {
            return false;
        }
        t.insert(tuple, socket);
        true
    }

    /// Unregister `socket`'s connection entry (only if it is the owner)
    pub fn tcp_unregister(&self, tuple: &TcpFourTuple, socket: &TcpSock) {
        let mut t = self.tcp_connections.write();
        if t.get(tuple)
            .is_some_and(|s| core::ptr::eq(Arc::as_ptr(s), socket))
        {
            t.remove(tuple);
        }
    }

    /// Look up a TCP connection by its full four-tuple
    pub fn tcp_lookup(&self, tuple: &TcpFourTuple) -> Option<Arc<TcpSock>> {
        self.tcp_connections.read().get(tuple).cloned()
    }

    /// Register a listening socket (several per port: different
    /// addresses, or a SO_REUSEPORT group)
    pub fn tcp_listen_register(&self, port: u16, socket: Arc<TcpSock>) {
        self.tcp_listeners
            .write()
            .entry(port)
            .or_default()
            .push(socket);
    }

    /// Unregister listening socket `socket` from `port`
    pub fn tcp_listen_unregister(&self, port: u16, socket: &TcpSock) {
        let mut t = self.tcp_listeners.write();
        if let Some(v) = t.get_mut(&port) {
            v.retain(|s| !core::ptr::eq(Arc::as_ptr(s), socket));
            if v.is_empty() {
                t.remove(&port);
            }
        }
    }

    /// Listener for a segment to `daddr:port` received on `dif` (Linux
    /// __inet_lookup_listener: the bound address must match or be the
    /// wildcard, exact matches win; a bound device must match)
    pub fn tcp_lookup_listener(
        &self,
        daddr: Ipv4Addr,
        port: u16,
        dif: u32,
    ) -> Option<Arc<TcpSock>> {
        let t = self.tcp_listeners.read();
        let v = t.get(&port)?;
        let score = |s: &TcpSock| -> i32 {
            let a = s.inet.get().rcv_saddr;
            let dev = s.sk.bound_dev_if();
            if (!a.is_unspecified() && a != daddr) || (dev != 0 && dev != dif) {
                return -1;
            }
            (!a.is_unspecified()) as i32 * 2 + (dev != 0) as i32
        };
        let best = v.iter().map(|s| score(s)).max().filter(|&b| b >= 0)?;
        v.iter().find(|s| score(s) == best).cloned()
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

    /// Device with interface index `ifindex`
    pub fn dev_get_by_index(&self, ifindex: u32) -> Option<Arc<NetDevice>> {
        if ifindex == 0 {
            return None;
        }
        self.devices
            .read()
            .iter()
            .find(|d| d.ifindex() == ifindex)
            .cloned()
    }

    /// First free name for a template like "eth%d" (Linux dev_alloc_name)
    pub fn dev_alloc_name(&self, template: &str) -> alloc::string::String {
        let Some((pre, post)) = template.split_once("%d") else {
            return alloc::string::String::from(template);
        };
        let devs = self.devices.read();
        (0..)
            .map(|i| alloc::format!("{}{}{}", pre, i, post))
            .find(|n| devs.iter().all(|d| d.name() != n))
            .unwrap()
    }

    /// Snapshot of this namespace's devices (registration order)
    pub fn devices(&self) -> Vec<Arc<NetDevice>> {
        self.devices.read().clone()
    }

    /// Number of devices in this namespace
    pub fn device_count(&self) -> usize {
        self.devices.read().len()
    }

    /// The namespace's loopback device
    pub fn loopback(&self) -> Option<Arc<NetDevice>> {
        self.loopback.read().clone()
    }

    /// Register a network device in this namespace: assign the next
    /// ifindex and set the device's netns (Linux register_netdevice)
    pub fn register_device(self: &Arc<Self>, dev: Arc<NetDevice>) {
        let mut devs = self.devices.write();
        let idx = self.next_ifindex.fetch_add(1, Ordering::Relaxed);
        dev.set_net(self, idx);
        devs.push(dev);
    }
}

// ============================================================================
// Loopback Device Implementation
// ============================================================================

/// Loopback device operations
struct LoopbackOps;

impl NetDeviceOps for LoopbackOps {
    /// Linux loopback_xmit: the frame comes straight back as received,
    /// through this CPU's backlog (never processed synchronously, so the
    /// transmit path never re-enters the receive path)
    fn xmit(&self, skb: alloc::boxed::Box<crate::net::skb::SkBuff>) -> Result<(), KernelError> {
        let len = skb.len();
        let dev = skb.dev.clone().ok_or(KernelError::NoDevice)?;
        if crate::net::dev::netif_rx(skb) {
            dev.stats.rx_packet(len);
        }
        Ok(())
    }

    fn mac_address(&self) -> [u8; 6] {
        [0, 0, 0, 0, 0, 0] // Loopback has no MAC
    }

    fn mtu(&self) -> u32 {
        65536 // Loopback has large MTU
    }

    fn max_mtu(&self) -> u32 {
        0 // no limit (Linux loopback leaves max_mtu 0)
    }
}

/// Static loopback operations
static LOOPBACK_OPS: LoopbackOps = LoopbackOps;

/// Create a loopback device (down, no addresses)
fn create_loopback_device() -> Arc<NetDevice> {
    use alloc::string::String;
    Arc::new(NetDevice::new(
        String::from("lo"),
        [0; 6],
        LinkInfo::LOOPBACK,
        &LOOPBACK_OPS,
    ))
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
