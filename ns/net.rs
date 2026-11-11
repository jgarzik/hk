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

use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::sync::spin::RwLock;
use spin::Lazy;

use crate::net::device::{DevList, LinkInfo, NetDevice, NetDeviceOps};
use crate::net::inet::fib::Fib;
use crate::net::inet::port::PortRange;
use crate::net::netlink::NlTable;
use crate::net::udp::UdpTable;
use crate::util::error::KernelError;
use crate::util::rculist::RcuList;

/// Next network namespace id (never reused)
static NEXT_NET_ID: AtomicU64 = AtomicU64::new(1);

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
    /// Unique id: the sysfs namespace tag of its devices
    pub id: u64,

    /// Its inode number (Linux ns.inum)
    pub inum: super::inum::Inum,

    /// Network devices in this namespace (registration = ifindex order;
    /// Linux dev_base_head): read under RCU, changed under RTNL
    devices: RcuList<DevList>,

    /// Next interface index (Linux dev_new_index; lo gets 1)
    next_ifindex: AtomicU32,

    /// IPv4 routing tables
    pub fib: Fib,

    /// netlink sockets bound in this namespace
    pub nl: NlTable,

    /// TCP connection, listener and port tables
    pub tcp: crate::net::tcp::table::TcpTables,

    /// UDP sockets by local port
    pub udp: UdpTable,

    /// net.ipv4.ip_local_port_range
    pub port_range: PortRange,

    /// /proc/sys/net values (`net::sysctl`)
    pub sysctl: crate::net::sysctl::NetSysctl,

    /// IPv4 reassembly queues
    pub frags: crate::net::inet::frag::FragTable,

    /// ICMP rate-limit state
    pub icmp: crate::net::icmp::IcmpRate,

    /// Ping sockets by echo identifier
    pub ping: crate::net::ping::PingTable,

    /// Raw sockets by protocol
    pub raw: crate::net::raw::RawTable,

    /// AF_UNIX sockets and abstract names
    pub unix: crate::net::unix::UnixTable,

    /// AF_PACKET sockets
    pub packet: crate::net::packet::PacketTable,

    /// Key of the IP identification hash (Linux ip_id_key)
    pub ip_id_key: [u64; 2],

    /// ARP neighbour table (IPv6 neighbour discovery gets its own)
    pub arp: Arc<crate::net::neigh::NeighTable>,

    /// Loopback device for this namespace
    loopback: RwLock<Option<Arc<NetDevice>>>,
}

impl NetNamespace {
    /// Create a new network namespace with loopback device, or ENOMEM
    pub fn new() -> Result<Arc<Self>, KernelError> {
        // The device first: nothing to undo but itself
        let lo = try_arc(loopback_device(try_arc(LoopbackOps)?))?;
        let ns = try_arc(Self::fresh(super::inum::Inum::alloc()?)?)?;
        Ok(Self::attach(ns, lo))
    }

    /// The initial namespace (boot: failure cannot be reported)
    fn new_init() -> Arc<Self> {
        let ns = Self::fresh(super::inum::Inum::fixed(super::inum::NET_INIT));
        let ns = arc_nofail(ns.expect("init_net: no memory at boot"));
        let lo = arc_nofail(loopback_device(arc_nofail(LoopbackOps)));
        Self::attach(ns, lo)
    }

    /// A namespace's state, before it is listed and has its loopback
    fn fresh(inum: super::inum::Inum) -> Result<Self, KernelError> {
        Ok(Self {
            id: NEXT_NET_ID.fetch_add(1, Ordering::Relaxed),
            inum,
            devices: RcuList::new(),
            next_ifindex: AtomicU32::new(1),
            fib: Fib::new()?,
            nl: Default::default(),
            tcp: Default::default(),
            udp: UdpTable::default(),
            port_range: PortRange::default(),
            sysctl: Default::default(),
            frags: Default::default(),
            icmp: Default::default(),
            ping: Default::default(),
            raw: Default::default(),
            unix: Default::default(),
            packet: Default::default(),
            ip_id_key: [
                (u64::from(crate::random::get_random_u32()) << 32)
                    | u64::from(crate::random::get_random_u32()),
                (u64::from(crate::random::get_random_u32()) << 32)
                    | u64::from(crate::random::get_random_u32()),
            ],
            arp: crate::net::neigh::NeighTable::new(&crate::net::arp::ARP_OPS),
            loopback: RwLock::new(None),
        })
    }

    /// List `ns` and give it its loopback device `lo`
    fn attach(ns: Arc<Self>, lo: Arc<NetDevice>) -> Arc<Self> {
        {
            // Linux setup_net: list_add_tail_rcu under net_rwsem (write);
            // namespaces gone since are pruned here
            let mut l = NET_NAMESPACE_LIST.write();
            l.retain(|w| w.strong_count() > 0);
            l.push(Arc::downgrade(&ns));
        }

        // Loopback device: ifindex 1, down and without addresses until
        // brought up (then 127.0.0.1/8, like Linux)
        ns.register_device(Arc::clone(&lo));
        *ns.loopback.write() = Some(lo);

        ns
    }

    /// Clone this namespace (creates new empty namespace with loopback)
    ///
    /// Network namespaces don't copy state - new namespace starts fresh
    /// with only loopback device (unlike mount namespace which clones tree).
    pub fn clone_ns(&self) -> Result<Arc<Self>, KernelError> {
        Self::new()
    }

    // ========================================================================
    // Device management
    // ========================================================================

    /// Get a network device by name in this namespace
    pub fn get_device(&self, name: &str) -> Option<Arc<NetDevice>> {
        self.devices.find(|d| d.name() == name)
    }

    /// Device with interface index `ifindex`
    pub fn dev_get_by_index(&self, ifindex: u32) -> Option<Arc<NetDevice>> {
        if ifindex == 0 {
            return None;
        }
        self.devices.find(|d| d.ifindex() == ifindex)
    }

    /// First free name for a template like "eth%d" (Linux dev_alloc_name)
    pub fn dev_alloc_name(&self, template: &str) -> alloc::string::String {
        let Some((pre, post)) = template.split_once("%d") else {
            return alloc::string::String::from(template);
        };
        let devs = self.devices();
        (0..)
            .map(|i| alloc::format!("{}{}{}", pre, i, post))
            .find(|n| devs.iter().all(|d| d.name() != n))
            .unwrap()
    }

    /// This namespace's devices in registration order, while `g` is
    /// held (Linux for_each_netdev_rcu)
    pub fn devices_rcu<'a>(
        &'a self,
        g: &'a crate::sync::rcu::RcuReadGuard,
    ) -> impl Iterator<Item = &'a NetDevice> + 'a {
        self.devices.iter(g)
    }

    /// References to this namespace's devices (registration order), for
    /// work done per device outside RCU
    pub fn devices(&self) -> Vec<Arc<NetDevice>> {
        self.devices.snapshot()
    }

    /// Number of devices in this namespace
    pub fn device_count(&self) -> usize {
        self.devices.count()
    }

    /// The namespace's loopback device
    pub fn loopback(&self) -> Option<Arc<NetDevice>> {
        self.loopback.read().clone()
    }

    /// Register a network device in this namespace: assign the next
    /// ifindex and set the device's netns (Linux register_netdevice:
    /// RTNL held, or the namespace not yet listed); readers see it at
    /// once (list_add_tail_rcu)
    pub fn register_device(self: &Arc<Self>, dev: Arc<NetDevice>) {
        let idx = self.next_ifindex.fetch_add(1, Ordering::Relaxed);
        dev.set_net(self, idx);
        self.devices.push_back(dev.clone());
        // Sleeping sysfs work
        crate::net::sysfs::netdev_register_kobject(&dev);
    }

    /// Take a device off this namespace's list (Linux
    /// unlist_netdevice, then synchronize_net; RTNL held by
    /// `net::unregister_netdevice`): no lookup finds it again, and no
    /// reader still walks over it on return; its ifindex is never reused
    pub fn unlist_device(&self, dev: &NetDevice) {
        drop(self.devices.remove_first(|d| core::ptr::eq(d, dev)));
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

/// A loopback device (down, no addresses)
fn loopback_device(ops: Arc<LoopbackOps>) -> NetDevice {
    use alloc::string::String;
    NetDevice::new(String::from("lo"), [0; 6], LinkInfo::LOOPBACK, ops)
}

// ============================================================================
// Global Init Network Namespace
// ============================================================================

/// Initial (root) network namespace
///
/// Physical network devices are registered here. Created lazily on first access.
pub static INIT_NET_NS: Lazy<Arc<NetNamespace>> = Lazy::new(NetNamespace::new_init);

/// Every network namespace (Linux net_namespace_list under net_rwsem,
/// a sleeping lock): written at creation, read by the walkers; thread
/// context only
static NET_NAMESPACE_LIST: crate::sync::RwSem<Vec<Weak<NetNamespace>>> =
    crate::sync::RwSem::new(Vec::new());

/// A namespace's devices are unregistered with it (Linux cleanup_net ->
/// default_device_exit_batch, loopback last)
impl Drop for NetNamespace {
    fn drop(&mut self) {
        // Walked through `&mut`: no reader or writer is left
        let devs = self.devices.drain().collect();
        // Sleeping RTNL and sysfs work: deferred (Linux cleanup_net runs
        // from a workqueue); the last reference may drop in any context
        crate::net::rtnl::netns_exit(devs);
    }
}

/// References to the live network namespaces, for work that takes
/// `NET_NAMESPACE_LIST` again (registering sysfs devices sends uevents)
pub fn all_net_ns() -> Vec<Arc<NetNamespace>> {
    let l = NET_NAMESPACE_LIST.read();
    l.iter().filter_map(Weak::upgrade).collect()
}

/// Run `f` on each live network namespace, under `net_rwsem` read (Linux
/// for_each_net with down_read(&net_rwsem)); `f` must not take it again
pub fn for_each_net(mut f: impl FnMut(&Arc<NetNamespace>)) {
    let l = NET_NAMESPACE_LIST.read();
    for net in l.iter().filter_map(Weak::upgrade) {
        f(&net);
    }
}

/// Get the init network namespace
pub fn init_net_ns() -> Arc<NetNamespace> {
    INIT_NET_NS.clone()
}
