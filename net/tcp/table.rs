//! The TCP socket tables (Linux struct inet_hashinfo tcp_hashinfo:
//! inet_hashtables.c, inet_connection_sock.c, inet_timewait_sock.c)
//!
//! One set of tables for every network namespace, as Linux: an entry
//! matches a lookup only in its own namespace (net_eq). A namespace's
//! [`TcpTables`] is its handle on them (`NetNamespace.tcp`).
//!
//! - `ehash`: four-tuple -> connection (SYN_SENT, SYN_RECEIVED children,
//!   synchronized states) or TIME_WAIT entry; tuples are unique. One
//!   hlist_nulls RCU chain per bucket holds both (Linux: sock_common
//!   heads both kinds), each through an [`Eh`] node naming its
//!   namespace, tuple and owner; a socket entering TIME_WAIT is
//!   replaced by its entry under the bucket's one lock.
//! - `lhash`: listeners by (namespace, local port), an hlist_nulls RCU
//!   chain per bucket (Linux lhash2; address and device scored).
//! - `bhash`: bind buckets (Linux inet_bind_bucket) by (namespace,
//!   local port) holding the port's owners (bound, listening, connected
//!   and TIME_WAIT sockets; a listener's child from its handshake's
//!   completion, never as a request) for the bind conflict rules; an
//!   owner that came from bind()/listen() (`by_bind`, Linux
//!   tb->fastreuse >= 0) keeps connect()'s ephemeral port selection off
//!   its port, while ports chosen by connect() are shared by different four-tuples
//!   (Linux __inet_hash_connect). A bucket is allocated GFP_ATOMIC under
//!   its chain's lock (Linux inet_bind_bucket_create) and freed with
//!   its last owner.
//!
//! ## Locking
//!
//! Lookups (`lookup`, `listener`, /proc/net/tcp) walk the ehash and
//! lhash chains under `rcu::read_lock` with no lock and take a
//! reference to what they find, re-checking its key after (Linux
//! __inet_lookup_established: refcount_inc_not_zero and the key
//! recheck); a chain's reference to an entry taken off is dropped a
//! grace period later (`NullsUnlinked::defer`, `rcu::put_rcu`), so a
//! reader never sees a freed entry (Linux: the hash's sock_hold plus
//! SLAB_TYPESAFE_BY_RCU). Writers take the chain's bucket lock (spin,
//! thread context; Linux inet_ehash_lockp, ilb2->lock). Order: bhash
//! chain -> bind bucket owners -> ehash bucket; `Inet.addr`
//! of candidates is read under the bhash locks and under RCU. Socket
//! locks (`TcpSock.lock`, owner or slock) are never taken under a table
//! lock (callers may hold their own).

use crate::net::mib::{INUSE_TCP, INUSE_TW};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::sync::spin::Mutex;

use super::TcpSock;
use super::output::Tuple;
use super::timewait::TimeWait;
use crate::mm::page_alloc::Gfp;
use crate::net::NetNamespace;
use crate::net::inet::port::{self, BindInfo, Flow, Parity};
use crate::net::ipv4::{IPPROTO_TCP, Ipv4Addr};
use crate::sync::rcu::RcuPuts;
use crate::util::error::KernelError;
use crate::util::hlist_nulls::{NullsGuard, NullsHead, NullsLink};
use crate::util::kalloc::try_arc_gfp;
use crate::util::list::{ArcList, Link};

crate::nulls_adapter!(pub(super) EhLink, Eh, link);
crate::rcu_puts!(Eh, rcu);
crate::nulls_adapter!(pub(super) SkLhash, TcpSock, lh_link);
crate::adapter!(pub(super) SkBind, TcpSock, bind_link);
crate::adapter!(pub(super) TwBind, TimeWait, bind_link);
crate::adapter!(BucketLink, BindBucket, link);

/// An ehash entry found by a lookup
#[derive(Clone)]
pub enum Ent {
    Sk(Arc<TcpSock>),
    Tw(Arc<TimeWait>),
}

/// An ehash entry (Linux the hash part of struct sock_common: skc_net,
/// the four-tuple, skc_nulls_node), with a reference to what it hashes.
/// Made before any table lock by whoever hashes it; its key is set
/// before each insert. The entry keeps its owner alive while hashed;
/// the owner holds it to unhash it, and the chain's reference goes a
/// grace period after (`NullsUnlinked::defer`).
pub struct Eh {
    link: NullsLink,
    net: usize,
    key: EhKey,
    ent: Ent,
    rcu: RcuPuts,
}

impl Eh {
    /// An unhashed entry of `net` for `ent`, allocated with `gfp`
    pub fn new(net: &NetNamespace, ent: Ent, gfp: Gfp) -> Result<Arc<Self>, KernelError> {
        try_arc_gfp(
            Self {
                link: NullsLink::new(),
                net: net_id(net),
                key: EhKey::new(),
                ent,
                rcu: RcuPuts::new(),
            },
            gfp,
        )
    }

    /// The tuple it was last hashed under
    fn tuple(&self) -> Tuple {
        self.key.get()
    }
}

/// A port's owners (Linux inet_bind_bucket)
struct BindBucket {
    link: Link,
    /// The namespace (its address: Linux ib_net) and the port
    net: usize,
    port: u16,
    /// Linux tb->owners (sockets) and the TIME_WAIT entries that took
    /// their place; a leaf under the chain lock
    owners: Mutex<Owners>,
}

#[derive(Default)]
struct Owners {
    sk: ArcList<SkBind>,
    tw: ArcList<TwBind>,
}

impl Owners {
    fn is_empty(&self) -> bool {
        self.sk.is_empty() && self.tw.is_empty()
    }

    /// No owner but `me` conflicts with `info` (Linux
    /// inet_csk_bind_conflict)
    fn free_for(&self, me: &TcpSock, info: &BindInfo) -> bool {
        let sk = self
            .sk
            .iter()
            .filter(|o| !core::ptr::eq(*o, me))
            .all(|o| !port::conflict(info, &o.bind_info(o.inet.get().rcv_saddr), true));
        sk && self.tw.iter().all(|o| !port::conflict(info, &o.bind, true))
    }

    /// Only connect() uses the port (Linux tb->fastreuse == -1)
    fn connect_only(&self) -> bool {
        self.sk.iter().all(|o| !o.by_bind.load(Ordering::Relaxed))
            && self.tw.iter().all(|o| !o.by_bind)
    }
}

/// The tables (Linux struct inet_hashinfo)
struct Hashinfo {
    /// Connections and TIME_WAIT entries, one chain per bucket
    ehash: Box<[NullsHead<EhLink>]>,
    lhash: Box<[NullsHead<SkLhash>]>,
    bhash: Box<[Mutex<ArcList<BucketLink>>]>,
}

static HASHINFO: spin::Once<Hashinfo> = spin::Once::new();

/// Listener buckets (Linux INET_LHTABLE_SIZE)
const LHASH: usize = 256;

/// Size the tables from memory (Linux tcp_init: alloc_large_system_hash
/// for ehash and bhash, one bucket per 16 pages of buffer memory, a
/// power of two between 1 Ki and 1 Mi buckets)
pub fn init() {
    let n = (crate::FRAME_ALLOCATOR.buffer_pages() / 16)
        .next_power_of_two()
        .clamp(1 << 10, 1 << 20);
    let mut bhash = alloc::vec::Vec::new();
    bhash.resize_with(n, || Mutex::new(ArcList::new()));
    super::mem::set_max_orphans(n);
    super::netns::set_max_tw_default(n);
    HASHINFO.call_once(|| Hashinfo {
        ehash: NullsHead::table(n).expect("tcp: ehash"),
        lhash: NullsHead::table(LHASH).expect("tcp: lhash"),
        bhash: bhash.into_boxed_slice(),
    });
    // Linux tcp_metrics_init
    super::metrics::init();
    // Linux tcp_sk_init(init_net) -> tcp_set_hashinfo, after tcp_init
    // sized the table: the initial namespace was made before it
    crate::ns::net::init_net_ns()
        .sysctl
        .tcp_max_syn_backlog
        .store(max_syn_backlog(), Ordering::Relaxed);
}

/// A namespace's initial tcp_max_syn_backlog (Linux tcp_set_hashinfo:
/// max(128, ehash entries / 128), of the one table every namespace
/// shares; 128 before it is sized)
pub fn max_syn_backlog() -> i32 {
    HASHINFO
        .get()
        .map_or(128, |h| (h.ehash.len() / 128).max(128) as i32)
}

fn hi() -> &'static Hashinfo {
    HASHINFO.get().expect("tcp tables not initialized")
}

/// Linux inet_ehashfn: a keyed hash of the namespace and four-tuple
fn ehashfn(net: usize, t: &Tuple) -> u64 {
    let w = [
        net as u64,
        (u64::from(t.laddr.0) << 32) | u64::from(t.raddr.0),
        (u64::from(t.lport) << 16) | u64::from(t.rport),
    ];
    port::secure_hash(0x7463_7065_6861, &w)
}

/// Linux inet_bhashfn / ipv4_portaddr_hash: namespace and port
fn porthash(net: usize, port: u16) -> u64 {
    port::secure_hash(0x7463_7062_6861, &[net as u64, u64::from(port)])
}

/// An entry's ehash key (Linux sk_portpair / sk_addrpair): written
/// before it is hashed, read by lockless lookups
pub(super) struct EhKey {
    addrs: core::sync::atomic::AtomicU64,
    ports: core::sync::atomic::AtomicU32,
}

impl EhKey {
    pub(super) const fn new() -> Self {
        Self {
            addrs: core::sync::atomic::AtomicU64::new(0),
            ports: core::sync::atomic::AtomicU32::new(0),
        }
    }

    fn set(&self, t: &Tuple) {
        let (a, p) = Self::words(t);
        self.addrs.store(a, Ordering::Relaxed);
        self.ports.store(p, Ordering::Relaxed);
    }

    fn is(&self, t: &Tuple) -> bool {
        let (a, p) = Self::words(t);
        self.addrs.load(Ordering::Relaxed) == a && self.ports.load(Ordering::Relaxed) == p
    }

    fn get(&self) -> Tuple {
        let a = self.addrs.load(Ordering::Relaxed);
        let p = self.ports.load(Ordering::Relaxed);
        Tuple {
            laddr: Ipv4Addr((a >> 32) as u32),
            raddr: Ipv4Addr(a as u32),
            lport: (p >> 16) as u16,
            rport: p as u16,
        }
    }

    fn words(t: &Tuple) -> (u64, u32) {
        (
            (u64::from(t.laddr.0) << 32) | u64::from(t.raddr.0),
            (u32::from(t.lport) << 16) | u32::from(t.rport),
        )
    }
}

/// A namespace's handle on the TCP tables: its address is the
/// namespace's identity in them (Linux net_eq)
#[derive(Default)]
pub struct TcpTables {
    _id: u8,
    /// The namespace's Fast Open keys (Linux net->ipv4.tcp_fastopen_ctx,
    /// replaced whole: tcp_fastopen_reset_cipher); leaf
    fastopen_ctx: Mutex<Option<super::fastopen::Ctx>>,
    /// Active Fast Open paused (Linux tfo_active_disable_stamp, ms, and
    /// tfo_active_disable_times)
    pub tfo_disable_stamp: core::sync::atomic::AtomicU64,
    pub tfo_disable_times: core::sync::atomic::AtomicU32,
}

impl TcpTables {
    /// Linux tcp_fastopen_init_key_once: a random primary key unless
    /// the namespace has keys
    pub fn fastopen_init_key_once(&self) {
        let mut g = self.fastopen_ctx.lock();
        if g.is_none() {
            *g = Some(super::fastopen::Ctx::random());
        }
    }

    /// The namespace's keys
    pub fn fastopen_ctx(&self) -> Option<super::fastopen::Ctx> {
        *self.fastopen_ctx.lock()
    }

    /// Replace the namespace's keys (Linux tcp_fastopen_reset_cipher
    /// with no socket)
    pub fn fastopen_reset(&self, c: super::fastopen::Ctx) {
        *self.fastopen_ctx.lock() = Some(c);
    }
}

/// End every TIME_WAIT entry of the namespaces `nets` going (Linux
/// tcp_twsk_purge from cleanup_net, one walk for the batch): they hold
/// no active reference, so a namespace goes without waiting out their
/// 2MSL. A lookup that followed a moved entry walks its bucket again
/// (`find_rcu`).
pub fn twsk_purge(nets: &[Arc<NetNamespace>]) {
    let theirs = |e: &Eh| matches!(e.ent, Ent::Tw(_)) && nets.iter().any(|n| e.net == net_id(n));
    for b in hi().ehash.iter() {
        loop {
            let tw = {
                let g = crate::sync::rcu::read_lock();
                b.find_rcu(&g, |e| theirs(e))
                    .and_then(|e| match &e.get().ent {
                        Ent::Tw(tw) => Some(tw.clone()),
                        Ent::Sk(_) => None,
                    })
            };
            let Some(tw) = tw else { break };
            tw.kill();
        }
    }
}

/// Count `s` in or out of its namespace's TCP inuse, once each way
/// (Linux sock_prot_inuse_add at hash and unhash)
pub fn tcp_inuse(s: &TcpSock, up: bool) {
    if s.inuse.swap(up, Ordering::Relaxed) != up {
        s.sk.net.mib.inuse_add(INUSE_TCP, up);
    }
}

/// The namespace an entry is in, as the tables name it
fn net_id(net: &NetNamespace) -> usize {
    core::ptr::from_ref(&net.tcp).addr()
}

impl TcpTables {
    fn id(&self) -> usize {
        core::ptr::from_ref(self).addr()
    }

    fn ehead(&self, t: &Tuple) -> &'static NullsHead<EhLink> {
        let h = hi();
        &h.ehash[(ehashfn(self.id(), t) as usize) & (h.ehash.len() - 1)]
    }

    fn lhead(&self, port: u16) -> &'static NullsHead<SkLhash> {
        let h = hi();
        &h.lhash[(porthash(self.id(), port) as usize) & (LHASH - 1)]
    }

    fn bchain(&self, port: u16) -> &'static Mutex<ArcList<BucketLink>> {
        let h = hi();
        &h.bhash[(porthash(self.id(), port) as usize) & (h.bhash.len() - 1)]
    }

    fn mine_sk(&self, s: &TcpSock) -> bool {
        net_id(&s.sk.net) == self.id()
    }

    /// `e` is this namespace's entry for `t`
    fn is(&self, e: &Eh, t: &Tuple) -> bool {
        e.net == self.id() && e.key.is(t)
    }

    // --- bind ----------------------------------------------------------------

    /// Run `f` on `port`'s bucket of this namespace, made (GFP_ATOMIC,
    /// Linux inet_bind_bucket_create) if `make` and there is none;
    /// None without a bucket or memory
    fn with_bucket<R>(
        &self,
        chain: &mut ArcList<BucketLink>,
        port: u16,
        make: bool,
        f: impl FnOnce(&BindBucket) -> R,
    ) -> Option<R> {
        let id = self.id();
        if let Some(b) = chain.iter().find(|b| b.net == id && b.port == port) {
            return Some(f(b));
        }
        if !make {
            return None;
        }
        let b = try_arc_gfp(
            BindBucket {
                link: Link::new(),
                net: id,
                port,
                owners: Mutex::new(Owners::default()),
            },
            Gfp::ATOMIC,
        )
        .ok()?;
        let r = f(&b);
        chain.push_back(b);
        Some(r)
    }

    /// Drop `port`'s bucket once it has no owner (Linux
    /// inet_bind_bucket_destroy)
    fn prune(&self, chain: &mut ArcList<BucketLink>, port: u16) {
        let id = self.id();
        let gone =
            chain.remove_first(|b| b.net == id && b.port == port && b.owners.lock().is_empty());
        drop(gone);
    }

    /// Add `s` to `port`'s owners in a held chain; false without memory
    fn own(
        &self,
        chain: &mut ArcList<BucketLink>,
        s: &Arc<TcpSock>,
        port: u16,
        by_bind: bool,
    ) -> bool {
        s.by_bind.store(by_bind, Ordering::Relaxed);
        self.with_bucket(chain, port, true, |b| {
            b.owners.lock().sk.push_back(s.clone())
        })
        .is_some()
    }

    /// Claim `port` for `s` (0: an unused port of the local range) after
    /// the conflict rules (Linux inet_csk_get_port)
    pub fn bind(
        &self,
        s: &Arc<TcpSock>,
        info: &BindInfo,
        port: u16,
        range: (u16, u16),
    ) -> Result<u16, KernelError> {
        if port != 0 {
            let mut c = self.bchain(port).lock();
            let free = self
                .with_bucket(&mut c, port, false, |b| b.owners.lock().free_for(s, info))
                .unwrap_or(true);
            if !free {
                return Err(KernelError::AddressInUse);
            }
            if !self.own(&mut c, s, port, true) {
                return Err(KernelError::NoBufferSpace);
            }
            return Ok(port);
        }
        let flow = Flow {
            proto: IPPROTO_TCP,
            saddr: info.addr,
            ..Default::default()
        };
        // Each candidate checked and claimed under its own chain lock
        // (Linux inet_csk_find_open_port)
        let claim = |p: u16| {
            let mut c = self.bchain(p).lock();
            self.with_bucket(&mut c, p, false, |_| ()).is_none() && self.own(&mut c, s, p, true)
        };
        port::bind_halves(range, info.reuse)
            .into_iter()
            .find_map(|r| port::ephemeral(r, flow, Parity::Bind, claim))
            .ok_or(KernelError::AddressInUse)
    }

    /// May `s`, owning `port`, listen (SO_REUSEADDR does not share with
    /// a listener)?
    pub fn can_listen(&self, s: &Arc<TcpSock>, info: &BindInfo, port: u16) -> bool {
        let mut i = *info;
        i.listen = true;
        let mut c = self.bchain(port).lock();
        self.with_bucket(&mut c, port, false, |b| b.owners.lock().free_for(s, &i))
            .unwrap_or(true)
    }

    /// A child completing its handshake shares its listener's port
    /// (Linux __inet_inherit_port); false without memory
    pub fn inherit(&self, child: &Arc<TcpSock>, port: u16) -> bool {
        let mut c = self.bchain(port).lock();
        self.own(&mut c, child, port, true)
    }

    /// `s` is an owner of `port`
    pub fn owns(&self, port: u16, s: &Arc<TcpSock>) -> bool {
        let mut c = self.bchain(port).lock();
        self.with_bucket(&mut c, port, false, |b| {
            b.owners
                .lock()
                .sk
                .iter()
                .any(|o| core::ptr::eq(o, Arc::as_ptr(s)))
        })
        .unwrap_or(false)
    }

    /// `s` releases `port` (Linux inet_put_port)
    pub fn unbind(&self, s: &Arc<TcpSock>, port: u16) {
        let mut c = self.bchain(port).lock();
        let gone = self.with_bucket(&mut c, port, false, |b| {
            b.owners
                .lock()
                .sk
                .remove_first(|o| core::ptr::eq(o, Arc::as_ptr(s)))
        });
        self.prune(&mut c, port);
        drop(c);
        drop(gone);
    }

    // --- connections ---------------------------------------------------------

    /// Hash `eh` (`s`'s entry) under `t` if no connection or TIME_WAIT
    /// entry of this namespace has the tuple (Linux
    /// __inet_check_established's uniqueness test and insert, under the
    /// ehash bucket lock)
    fn hash_unique(&self, t: &Tuple, eh: &Arc<Eh>, s: &TcpSock, count: bool) -> bool {
        let mut g = self.ehead(t).lock();
        if g.find(|x| self.is(x, t)).is_some() {
            return false;
        }
        eh.key.set(t);
        g.add_head_rcu(eh.clone());
        // Linux inet_ehash_nolisten (a child counts once established)
        if count {
            tcp_inuse(s, true);
        }
        true
    }

    /// Hash `s` under `t` for connect(): with `t.lport` 0 pick an
    /// ephemeral port first (RFC 6056 offset; a port is usable if only
    /// connect() uses it and the four-tuple is free; Linux
    /// __inet_hash_connect, the bhash bucket lock held across the
    /// ehash insert). EADDRNOTAVAIL if the tuple of a bound port is
    /// taken or no port is left.
    pub fn connect(
        &self,
        s: &Arc<TcpSock>,
        eh: &Arc<Eh>,
        mut t: Tuple,
        range: (u16, u16),
    ) -> Result<Tuple, KernelError> {
        if t.lport != 0 {
            return if self.hash_unique(&t, eh, s, true) {
                Ok(t)
            } else {
                Err(KernelError::AddressNotAvailable)
            };
        }
        let flow = Flow {
            proto: IPPROTO_TCP,
            saddr: t.laddr,
            daddr: t.raddr,
            dport: t.rport,
        };
        let claim = |p: u16| {
            let tp = Tuple { lport: p, ..t };
            let mut c = self.bchain(p).lock();
            let usable = self
                .with_bucket(&mut c, p, false, |b| b.owners.lock().connect_only())
                .unwrap_or(true);
            if !usable || !self.hash_unique(&tp, eh, s, true) {
                return false;
            }
            if !self.own(&mut c, s, p, false) {
                drop(c);
                self.unhash(eh, s);
                return false;
            }
            true
        };
        t.lport = port::ephemeral(range, flow, Parity::Connect, claim)
            .ok_or(KernelError::AddressNotAvailable)?;
        Ok(t)
    }

    /// Insert a connection (a listener's child) through its entry `eh`;
    /// false if `t` is taken
    pub fn hash(&self, t: Tuple, eh: &Arc<Eh>, s: &TcpSock) -> bool {
        self.hash_unique(&t, eh, s, false)
    }

    /// Remove `s`'s entry `eh` (Linux inet_unhash): the chain's
    /// reference goes a grace period later
    pub fn unhash(&self, eh: &Eh, s: &TcpSock) {
        let mut g = self.ehead(&eh.tuple()).lock();
        if let Some(u) = g.del_rcu(eh) {
            u.defer();
            tcp_inuse(s, false);
        }
    }

    /// The connection or TIME_WAIT entry for a segment's tuple, found
    /// under RCU (Linux __inet_lookup_established), its key checked
    /// again once referenced (an entry may be rehashed under another
    /// tuple meanwhile: a connect() trying ports)
    pub fn lookup(&self, t: &Tuple) -> Option<Ent> {
        let g = crate::sync::rcu::read_lock();
        let head = self.ehead(t);
        loop {
            let e = head.find_rcu(&g, |x| self.is(x, t))?;
            let ent = e.get().ent.clone();
            if e.get().key.is(t) {
                return Some(ent);
            }
        }
    }

    // --- TIME_WAIT -------------------------------------------------------------

    /// `s` entered TIME_WAIT: `tw` replaces it in ehash (its entry
    /// `tw_eh` for `s`'s `eh`, hashed first under the bucket's one lock,
    /// so a lookup finds one of them) and as port owner (Linux
    /// inet_twsk_hashdance)
    pub fn tw_hashdance(
        &self,
        s: &Arc<TcpSock>,
        eh: Option<Arc<Eh>>,
        tw: &Arc<TimeWait>,
        tw_eh: &Arc<Eh>,
    ) {
        let port = tw.tuple.lport;
        let mut c = self.bchain(port).lock();
        let _ = self.with_bucket(&mut c, port, false, |b| {
            let mut o = b.owners.lock();
            if o.sk
                .remove_first(|x| core::ptr::eq(x, Arc::as_ptr(s)))
                .is_some()
            {
                o.tw.push_back(tw.clone());
            }
        });
        drop(c);
        let mib = &s.sk.net.mib;
        tw_eh.key.set(&tw.tuple);
        let mut g = self.ehead(&tw.tuple).lock();
        g.add_head_rcu(tw_eh.clone());
        mib.inuse_add(INUSE_TW, true);
        if let Some(u) = eh.and_then(|e| g.del_rcu(&e)) {
            u.defer();
            // Linux inet_twsk_hashdance: the socket leaves
            tcp_inuse(s, false);
        }
    }

    /// A TIME_WAIT entry ends (2MSL, RST, or a new SYN took its tuple);
    /// `eh` is its ehash entry, if it still had it
    pub fn tw_unhash(&self, tw: &Arc<TimeWait>, eh: Option<Arc<Eh>>) {
        let port = tw.tuple.lport;
        let mut c = self.bchain(port).lock();
        let gone = self.with_bucket(&mut c, port, false, |b| {
            b.owners
                .lock()
                .tw
                .remove_first(|x| core::ptr::eq(x, Arc::as_ptr(tw)))
        });
        self.prune(&mut c, port);
        drop(c);
        drop(gone);
        let Some(eh) = eh else { return };
        let mut g = self.ehead(&tw.tuple).lock();
        if let Some(u) = g.del_rcu(&eh) {
            u.defer();
            tw.net().mib.inuse_add(INUSE_TW, false);
        }
    }

    // --- listeners -------------------------------------------------------------

    /// Hash a listener on `port` (Linux __inet_hash into lhash2)
    pub fn listen_add(&self, port: u16, s: Arc<TcpSock>) {
        tcp_inuse(&s, true);
        self.lhead(port).lock().add_head_rcu(s);
    }

    /// Unhash a listener (Linux inet_unhash)
    pub fn listen_del(&self, port: u16, s: &Arc<TcpSock>) {
        let mut g: NullsGuard<'_, SkLhash> = self.lhead(port).lock();
        if let Some(u) = g.del_rcu(s) {
            u.defer();
            tcp_inuse(s, false);
        }
    }

    /// Listener for a segment to `daddr:port` received on `dif` (Linux
    /// __inet_lookup_listener under RCU: the bound address must match or
    /// be the wildcard, exact matches win; a bound device must match)
    pub fn listener(&self, daddr: Ipv4Addr, port: u16, dif: u32) -> Option<Arc<TcpSock>> {
        let score = |s: &TcpSock| -> i32 {
            let a = s.inet.get();
            let dev = s.sk.bound_dev_if();
            if !self.mine_sk(s)
                || a.sport != port
                || (!a.rcv_saddr.is_unspecified() && a.rcv_saddr != daddr)
                || (dev != 0 && dev != dif)
            {
                return -1;
            }
            i32::from(!a.rcv_saddr.is_unspecified()) * 2 + i32::from(dev != 0)
        };
        let head = self.lhead(port);
        let g = crate::sync::rcu::read_lock();
        loop {
            // One pass, each listener scored once: a bind or
            // SO_BINDTODEVICE racing this lookup cannot make a second
            // look miss the winner (Linux inet_lhash2_lookup)
            let mut best: Option<(i32, Arc<TcpSock>)> = None;
            let mut it = head.iter_rcu(&g);
            for e in it.by_ref() {
                let sc = score(e.get());
                if sc >= 0 && best.as_ref().is_none_or(|b| sc > b.0) {
                    best = Some((sc, e.arc()));
                }
            }
            if it.ended_at() == Some(head.nulls()) {
                return best.map(|b| b.1);
            }
        }
    }

    /// Walk this namespace's listeners, then its connections and
    /// TIME_WAIT entries, under `g` (Linux /proc/net/tcp order:
    /// listening hash, then established hash); entries moving meanwhile
    /// may be missed or seen twice, as Linux's seq walk
    pub fn walk_rcu(
        &self,
        g: &crate::sync::rcu::RcuReadGuard,
        mut ls: impl FnMut(&TcpSock),
        mut es: impl FnMut(&TcpSock),
        mut tws: impl FnMut(&TimeWait),
    ) {
        let h = hi();
        for b in h.lhash.iter() {
            b.iter_rcu(g)
                .filter(|e| self.mine_sk(e.get()))
                .for_each(|e| ls(e.get()));
        }
        for b in h.ehash.iter() {
            for e in b
                .iter_rcu(g)
                .map(|e| e.get())
                .filter(|e| e.net == self.id())
            {
                match &e.ent {
                    Ent::Sk(s) => es(s),
                    Ent::Tw(t) => tws(t),
                }
            }
        }
    }
}
