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
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::sync::IrqSpinlock;
use crate::sync::spin::RwLock;
use crate::task::workqueue::{Work, Workqueue};
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
    pub ping: crate::net::ping::PingNet,

    /// Raw sockets by protocol
    pub raw: crate::net::raw::RawTable,

    /// AF_UNIX sockets and abstract names
    pub unix: crate::net::unix::UnixTable,

    /// AF_PACKET sockets
    pub packet: crate::net::packet::PacketTable,

    /// Key of the IP identification hash (Linux ip_id_key)
    pub ip_id_key: [u64; 2],

    /// Loopback device for this namespace
    loopback: RwLock<Option<Arc<NetDevice>>>,

    /// Active references (Linux net->ns.count: [`NetRef`]s, held by
    /// tasks' nsproxies and user sockets); the `Arc` count is the
    /// passive one (Linux net->passive: the memory)
    active: AtomicUsize,

    /// Next on `CLEANUP_LIST` once inactive (Linux net->cleanup_list)
    cleanup_next: AtomicPtr<NetNamespace>,
}

/// An active reference to a network namespace (Linux get_net/put_net):
/// while one exists the namespace is listed and keeps its devices. It
/// derefs to the namespace's `Arc` (a passive reference, Linux
/// net->passive: the memory only), so the namespace's methods and
/// fields are reached through it. Dropping the last one queues the
/// namespace's teardown (Linux __put_net -> cleanup_net) and allocates
/// nothing: any context.
pub struct NetRef(Option<Arc<NetNamespace>>);

impl NetRef {
    /// The first active reference of a new namespace
    fn first(ns: Arc<NetNamespace>) -> Self {
        ns.active.store(1, Ordering::Release);
        Self(Some(ns))
    }

    fn arc(&self) -> &Arc<NetNamespace> {
        self.0.as_ref().expect("NetRef: taken")
    }
}

impl core::ops::Deref for NetRef {
    type Target = Arc<NetNamespace>;
    fn deref(&self) -> &Arc<NetNamespace> {
        self.arc()
    }
}

impl Clone for NetRef {
    /// Linux get_net: the holder keeps one already
    fn clone(&self) -> Self {
        self.active.fetch_add(1, Ordering::Relaxed);
        Self(Some(self.arc().clone()))
    }
}

impl Drop for NetRef {
    /// Linux put_net: the last one queues the teardown
    fn drop(&mut self) {
        let Some(a) = self.0.take() else { return };
        if a.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            put_net_last(a);
        }
    }
}


impl NetNamespace {
    /// Create a new network namespace with loopback device, or ENOMEM
    /// (Linux copy_net_ns -> setup_net)
    pub fn create() -> Result<NetRef, KernelError> {
        // The device first: nothing to undo but itself
        let lo = try_arc(loopback_device(try_arc(LoopbackOps)?))?;
        let ns = try_arc(Self::fresh(super::inum::Inum::alloc()?)?)?;
        Ok(Self::attach(ns, lo))
    }

    /// The initial namespace (boot: failure cannot be reported)
    fn new_init() -> NetRef {
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
            loopback: RwLock::new(None),
            active: AtomicUsize::new(0),
            cleanup_next: AtomicPtr::new(null_mut()),
        })
    }

    /// List `ns` and give it its loopback device `lo`
    fn attach(ns: Arc<Self>, lo: Arc<NetDevice>) -> NetRef {
        let ns = NetRef::first(ns);
        // Linux setup_net: list_add_tail_rcu under net_rwsem (write);
        // `cleanup_net` unlists it
        NET_NAMESPACE_LIST.write().push(Arc::downgrade(&ns));

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
    pub fn clone_ns(&self) -> Result<NetRef, KernelError> {
        Self::create()
    }

    /// An active reference if the namespace still has one (Linux
    /// maybe_get_net: refcount_inc_not_zero), for a walker that reached
    /// it through a passive one
    pub fn maybe_get(self: &Arc<Self>) -> Option<NetRef> {
        let mut n = self.active.load(Ordering::Relaxed);
        loop {
            if n == 0 {
                return None;
            }
            match self
                .active
                .compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return Some(NetRef(Some(self.clone()))),
                Err(cur) => n = cur,
            }
        }
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
pub static INIT_NET_NS: Lazy<NetRef> = Lazy::new(NetNamespace::new_init);

/// Every network namespace (Linux net_namespace_list under net_rwsem,
/// a sleeping lock): written at creation, read by the walkers; thread
/// context only
static NET_NAMESPACE_LIST: crate::sync::RwSem<Vec<Weak<NetNamespace>>> =
    crate::sync::RwSem::new(Vec::new());

/// The namespace teardown's queue (Linux netns_wq: cleanup_net waits
/// for grace periods and takes RTNL, so it runs apart from other work)
static NETNS_WQ: Workqueue = Workqueue::new("netns", 0);

/// Namespaces whose last active reference went, each holding one
/// passive reference (`Arc::into_raw`), linked through `cleanup_next`
/// (Linux cleanup_list, an llist: pushed in any context)
static CLEANUP_LIST: AtomicPtr<NetNamespace> = AtomicPtr::new(null_mut());

/// The teardown work (Linux net_cleanup_work: static, so queueing it
/// allocates nothing)
static CLEANUP_WORK: spin::Once<Arc<IrqSpinlock<Work>>> = spin::Once::new();

/// Make the teardown work (boot, before any namespace can go)
pub fn net_ns_init() {
    CLEANUP_WORK.call_once(|| arc_nofail(IrqSpinlock::new(Work::new(cleanup_net))));
}

/// Start the teardown queue's worker (once the scheduler runs)
pub fn net_ns_start() {
    if let Err(e) = NETNS_WQ.start(None) {
        crate::printkln!("netns: no cleanup worker: {:?}", e);
    }
}

/// The last active reference to `ns` went (Linux __put_net): queue its
/// teardown with the passive reference `ns`; no allocation, any context
fn put_net_last(ns: Arc<NetNamespace>) {
    let p = Arc::into_raw(ns).cast_mut();
    let mut head = CLEANUP_LIST.load(Ordering::Relaxed);
    loop {
        // SAFETY: `p` is the passive reference just leaked, live until
        // `cleanup_net` takes it back
        unsafe { (*p).cleanup_next.store(head, Ordering::Relaxed) };
        match CLEANUP_LIST.compare_exchange_weak(head, p, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => break,
            Err(h) => head = h,
        }
    }
    let w = CLEANUP_WORK.get().expect("netns: cleanup before init");
    NETNS_WQ.queue_work(w.clone());
}

/// Tear down the namespaces queued (Linux cleanup_net): unlist them so
/// no walker finds them, unregister their devices (Linux
/// default_device_exit_batch, loopback last) and end their TIME_WAIT
/// entries (tcp_twsk_purge), wait for the callbacks queued meanwhile
/// (rcu_barrier), then drop the passive references the list held
fn cleanup_net() {
    let mut nets = Vec::new();
    let mut cur = CLEANUP_LIST.swap(null_mut(), Ordering::Acquire);
    while !cur.is_null() {
        // SAFETY: the passive reference `put_net_last` leaked, taken
        // back once (the swap took the whole list)
        let a = unsafe { Arc::from_raw(cur) };
        cur = a.cleanup_next.load(Ordering::Relaxed);
        nets.push(a);
    }
    if nets.is_empty() {
        return;
    }
    NET_NAMESPACE_LIST.write().retain(|w| {
        !nets
            .iter()
            .any(|n| core::ptr::eq(w.as_ptr(), Arc::as_ptr(n)))
    });
    for net in &nets {
        crate::net::rtnl::netns_exit(net);
        net.tcp.twsk_purge();
    }
    crate::sync::rcu::rcu_barrier();
}

/// Active references to the live network namespaces, for work that
/// takes `NET_NAMESPACE_LIST` again (registering sysfs devices sends
/// uevents)
pub fn all_net_ns() -> Vec<NetRef> {
    let l = NET_NAMESPACE_LIST.read();
    l.iter()
        .filter_map(Weak::upgrade)
        .filter_map(|n| n.maybe_get())
        .collect()
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
pub fn init_net_ns() -> NetRef {
    INIT_NET_NS.clone()
}
