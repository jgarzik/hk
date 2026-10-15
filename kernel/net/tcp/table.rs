//! TCP socket tables of a namespace (Linux inet_hashtables.c,
//! inet_connection_sock.c, inet_timewait_sock.c)
//!
//! - `ehash`: four-tuple -> connection (SYN_SENT, SYN_RECEIVED children,
//!   synchronized states) or TIME_WAIT entry; tuples are unique.
//! - `lhash`: local port -> listeners (address / device / SO_REUSEPORT
//!   groups; the best match wins).
//! - `bhash`: local port -> owners (bound, listening, connected and
//!   TIME_WAIT sockets) for the bind conflict rules; an owner that came
//!   from bind()/listen() (`by_bind`, Linux tb->fastreuse >= 0) keeps
//!   connect()'s ephemeral port selection off its port, while ports
//!   chosen by connect() are shared by different four-tuples (Linux
//!   __inet_hash_connect).
//!
//! ## Locking
//!
//! `crate::sync::spin::RwLock`s, thread context only, reached only through the
//! methods below (no guard escapes; RCU-ready). Order: `bhash` ->
//! `ehash` (connect picks a port and inserts its tuple atomically);
//! `lhash` is a leaf. Candidate owners' `Inet.addr` and `Sock` flags are
//! read under `bhash`; socket locks (`TcpSock.cb`) are never taken
//! under a table lock (callers may hold their own socket lock).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::spin::RwLock;

use super::TcpSock;
use super::output::Tuple;
use super::timewait::TimeWait;
use crate::error::KernelError;
use crate::net::inet::port::{self, BindInfo, Flow};
use crate::net::ipv4::{IPPROTO_TCP, Ipv4Addr};

/// An ehash entry
#[derive(Clone)]
pub enum Ent {
    Sk(Arc<TcpSock>),
    Tw(Arc<TimeWait>),
}

impl Ent {
    fn is(&self, other: &Ent) -> bool {
        match (self, other) {
            (Ent::Sk(a), Ent::Sk(b)) => Arc::ptr_eq(a, b),
            (Ent::Tw(a), Ent::Tw(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    fn bind_info(&self) -> BindInfo {
        match self {
            Ent::Sk(s) => s.bind_info(s.inet.get().rcv_saddr),
            Ent::Tw(t) => t.bind,
        }
    }
}

/// A port owner
#[derive(Clone)]
struct Owner {
    ent: Ent,
    /// Took the port with bind()/listen() (or inherited it from a
    /// listener), not through connect()'s port selection
    by_bind: bool,
}

#[derive(Default)]
pub struct TcpTables {
    ehash: RwLock<BTreeMap<Tuple, Ent>>,
    lhash: RwLock<BTreeMap<u16, Vec<Arc<TcpSock>>>>,
    bhash: RwLock<BTreeMap<u16, Vec<Owner>>>,
}

/// No owner of `port` (other than `me`) conflicts with `info`
fn port_free(owners: Option<&Vec<Owner>>, me: &Ent, info: &BindInfo) -> bool {
    owners.is_none_or(|v| {
        v.iter()
            .filter(|o| !o.ent.is(me))
            .all(|o| !port::conflict(info, &o.ent.bind_info(), true))
    })
}

impl TcpTables {
    // --- bind ----------------------------------------------------------------

    /// Claim `port` for `s` (0: an unused port of the local range) after
    /// the conflict rules (Linux inet_csk_get_port)
    pub fn bind(
        &self,
        s: &Arc<TcpSock>,
        info: &BindInfo,
        port: u16,
        range: (u16, u16),
    ) -> Result<u16, KernelError> {
        let me = Ent::Sk(s.clone());
        let mut b = self.bhash.write();
        let port = if port != 0 {
            if !port_free(b.get(&port), &me, info) {
                return Err(KernelError::AddressInUse);
            }
            port
        } else {
            let flow = Flow {
                proto: IPPROTO_TCP,
                saddr: info.addr,
                ..Default::default()
            };
            port::ephemeral(range, flow, |p| !b.contains_key(&p))
                .ok_or(KernelError::AddressInUse)?
        };
        b.entry(port).or_default().push(Owner {
            ent: me,
            by_bind: true,
        });
        Ok(port)
    }

    /// May `s`, owning `port`, listen (SO_REUSEADDR does not share with
    /// a listener)?
    pub fn can_listen(&self, s: &Arc<TcpSock>, info: &BindInfo, port: u16) -> bool {
        let mut i = *info;
        i.listen = true;
        port_free(self.bhash.read().get(&port), &Ent::Sk(s.clone()), &i)
    }

    /// A child shares its listener's port (Linux inet_inherit_port)
    pub fn inherit(&self, child: &Arc<TcpSock>, port: u16) {
        self.bhash.write().entry(port).or_default().push(Owner {
            ent: Ent::Sk(child.clone()),
            by_bind: true,
        });
    }

    fn unbind_ent(&self, e: &Ent, port: u16) {
        let mut b = self.bhash.write();
        if let Some(v) = b.get_mut(&port) {
            v.retain(|o| !o.ent.is(e));
            if v.is_empty() {
                b.remove(&port);
            }
        }
    }

    /// `s` releases `port`
    pub fn unbind(&self, s: &Arc<TcpSock>, port: u16) {
        self.unbind_ent(&Ent::Sk(s.clone()), port);
    }

    // --- connections ---------------------------------------------------------

    /// Hash `s` under `t` for connect(): with `t.lport` 0 pick an
    /// ephemeral port first (RFC 6056 offset; a port is usable if only
    /// connect() uses it and the four-tuple is free). EADDRNOTAVAIL if
    /// the tuple of a bound port is taken or no port is left.
    pub fn connect(
        &self,
        s: &Arc<TcpSock>,
        mut t: Tuple,
        range: (u16, u16),
    ) -> Result<Tuple, KernelError> {
        let me = Ent::Sk(s.clone());
        let mut b = self.bhash.write();
        let pick = t.lport == 0;
        if pick {
            let flow = Flow {
                proto: IPPROTO_TCP,
                saddr: t.laddr,
                daddr: t.raddr,
                dport: t.rport,
            };
            let e = self.ehash.read();
            let usable = |p: u16| {
                let tp = Tuple { lport: p, ..t };
                b.get(&p).is_none_or(|v| v.iter().all(|o| !o.by_bind)) && !e.contains_key(&tp)
            };
            t.lport =
                port::ephemeral(range, flow, usable).ok_or(KernelError::AddressNotAvailable)?;
            drop(e);
            b.entry(t.lport).or_default().push(Owner {
                ent: me.clone(),
                by_bind: false,
            });
        }
        let mut e = self.ehash.write();
        if e.contains_key(&t) {
            drop(e);
            if pick {
                if let Some(v) = b.get_mut(&t.lport) {
                    v.retain(|o| !o.ent.is(&me));
                }
                if b.get(&t.lport).is_some_and(|v| v.is_empty()) {
                    b.remove(&t.lport);
                }
            }
            return Err(KernelError::AddressNotAvailable);
        }
        e.insert(t, me);
        Ok(t)
    }

    /// Insert a connection (a listener's child); false if `t` is taken
    pub fn hash(&self, t: Tuple, s: &Arc<TcpSock>) -> bool {
        let mut e = self.ehash.write();
        if e.contains_key(&t) {
            return false;
        }
        e.insert(t, Ent::Sk(s.clone()));
        true
    }

    /// Remove `s`'s entry for `t`
    pub fn unhash(&self, t: &Tuple, s: &Arc<TcpSock>) {
        self.unhash_ent(t, &Ent::Sk(s.clone()));
    }

    fn unhash_ent(&self, t: &Tuple, me: &Ent) {
        let mut e = self.ehash.write();
        if e.get(t).is_some_and(|x| x.is(me)) {
            e.remove(t);
        }
    }

    /// The connection or TIME_WAIT entry for a segment's tuple
    pub fn lookup(&self, t: &Tuple) -> Option<Ent> {
        self.ehash.read().get(t).cloned()
    }

    // --- TIME_WAIT -------------------------------------------------------------

    /// `s` entered TIME_WAIT: `tw` replaces it in ehash and as port owner
    /// (Linux inet_twsk_hashdance)
    pub fn tw_hashdance(&self, s: &Arc<TcpSock>, tw: &Arc<TimeWait>) {
        let (old, new) = (Ent::Sk(s.clone()), Ent::Tw(tw.clone()));
        let mut b = self.bhash.write();
        if let Some(v) = b.get_mut(&tw.tuple.lport) {
            for o in v.iter_mut().filter(|o| o.ent.is(&old)) {
                o.ent = new.clone();
            }
        }
        let mut e = self.ehash.write();
        if e.get(&tw.tuple).is_some_and(|x| x.is(&old)) {
            e.insert(tw.tuple, new);
        }
    }

    /// A TIME_WAIT entry ends (2MSL, RST, or a new SYN took its tuple)
    pub fn tw_unhash(&self, tw: &Arc<TimeWait>) {
        let me = Ent::Tw(tw.clone());
        self.unbind_ent(&me, tw.tuple.lport);
        self.unhash_ent(&tw.tuple, &me);
    }

    // --- listeners -------------------------------------------------------------

    pub fn listen_add(&self, port: u16, s: Arc<TcpSock>) {
        self.lhash.write().entry(port).or_default().push(s);
    }

    pub fn listen_del(&self, port: u16, s: &Arc<TcpSock>) {
        let mut l = self.lhash.write();
        if let Some(v) = l.get_mut(&port) {
            v.retain(|x| !Arc::ptr_eq(x, s));
            if v.is_empty() {
                l.remove(&port);
            }
        }
    }

    /// Listener for a segment to `daddr:port` received on `dif` (Linux
    /// __inet_lookup_listener: the bound address must match or be the
    /// wildcard, exact matches win; a bound device must match)
    pub fn listener(&self, daddr: Ipv4Addr, port: u16, dif: u32) -> Option<Arc<TcpSock>> {
        let l = self.lhash.read();
        let v = l.get(&port)?;
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

    /// Listeners, then connections and TIME_WAIT entries (Linux
    /// /proc/net/tcp order: listening hash, then established hash)
    pub fn snapshot(&self) -> (Vec<Arc<TcpSock>>, Vec<Ent>) {
        let l = self.lhash.read().values().flatten().cloned().collect();
        let e = self.ehash.read().values().cloned().collect();
        (l, e)
    }

    /// Connections and TIME_WAIT entries (tests)
    pub fn count(&self) -> (usize, usize) {
        let e = self.ehash.read();
        let tw = e.values().filter(|x| matches!(x, Ent::Tw(_))).count();
        (e.len() - tw, tw)
    }
}
