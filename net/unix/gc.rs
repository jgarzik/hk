//! AF_UNIX garbage collector (Linux net/unix/garbage.c)
//!
//! A unix socket whose file is in flight (sent with SCM_RIGHTS, not yet
//! received) is a vertex of the in-flight graph; each in-flight
//! reference to it is an edge from it to the receiving socket (a
//! queued embryo's edges count as its listener's). An edge is added
//! when its message is queued (`add_edges`) and removed when the
//! message is received or dropped (`del_edges`).
//!
//! `unix_gc` (a work item, scheduled at release and by senders) finds
//! the strongly connected components of the graph (Tarjan:
//! `walk_scc`). A component is dead when every edge of its vertices
//! stays inside it and each vertex's file has no reference but its
//! in-flight ones (file_count == out_degree): nothing outside can ever
//! receive those files again. The receive queues of a dead component's
//! sockets (a listener's: its embryos') are taken whole and freed after
//! the lock, which drops the files and so the sockets. A graph with no
//! cyclic component is skipped; one whose components are unchanged
//! since the last walk is checked component by component
//! (`walk_scc_fast`, each component's vertices kept on a ring through
//! `scc_next`/`scc_prev`, as Linux keeps them on their scc_entry ring).
//! A MSG_PEEK copying in-flight sockets while the collector runs
//! defers a component's verdict to the next run (`unix_peek_fpl`).
//!
//! Senders are throttled: a user with more than `INFLIGHT_SANE_USER`
//! files in flight runs (and while cyclic components exist, waits for)
//! a collection before each send of sockets (Linux unix_schedule_gc).
//!
//! ## Locking
//!
//! `UNIX_GC` (spin, Linux unix_gc_lock) owns the whole graph: every
//! vertex and edge field and each socket's `vertex`, `listener` and
//! `nr_unix_fds` (`LockedBy` cells). Taken under the receiver's
//! `UnixSock.st` (`add_edges`, from `queue`, under `UnixCb.fp`), with no
//! lock (`del_edges`, `update_edges`), under the connecting sockets'
//! `st` (`set_listener`); the collector takes `UnixSock.rq` and
//! `UnixSock.oob` under it to take a dead socket's queue. Nothing is
//! allocated under it (vertices and edges are allocated by the sender,
//! `prepare`), and no reference dropped under it is the last one.
//! `STATE`, `CYCLIC_SCCS`, `IN_PROGRESS` are written under it (or by
//! the collector) and read without it (Linux READ_ONCE).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use crate::fs::FileRef;
use crate::net::skb::SkbOwned;
use crate::sync::IrqSpinlock;
use crate::sync::spin::{Mutex, MutexGuard};
use crate::sync::{LockedBy, SeqCount, UniqueOwner};
use crate::task::ucount::{Ucount, UcountsRef};
use crate::task::workqueue::{SYSTEM_WQ, Work};
use crate::util::kalloc::try_arc;
use crate::util::list::{Link, OwnedList, Owner};

use super::scm::{FpList, SCM_MAX_FD};
use super::{LISTEN, UnixSock, ucb};

/// The data of `UNIX_GC`: the graph's lists and indexes, and the proof
/// its holder owns every vertex, edge and socket graph field
///
/// # Invariants
/// One value exists, made once inside `UNIX_GC`.
pub struct Graph {
    /// Vertices not yet visited by this walk (all of them between
    /// walks; Linux unix_unvisited_vertices)
    unvisited: OwnedList<VEntry>,
    /// Vertices this walk visited (Linux unix_visited_vertices)
    visited: OwnedList<VEntry>,
    /// `Vertex.index` of an unvisited vertex, and of one grouped into a
    /// component by this walk; swapped after each full walk (Linux
    /// unix_vertex_unvisited_index, unix_vertex_grouped_index)
    unvisited_index: usize,
    grouped_index: usize,
    /// Largest component number (Linux unix_vertex_max_scc_index)
    max_scc_index: usize,
}

// SAFETY: one value exists (type invariant), reachable only through
// `UNIX_GC`
unsafe impl UniqueOwner for Graph {}

/// A graph field
pub type GcCell<T> = LockedBy<T, Graph>;

/// Linux unix_vertex_index
const INDEX_MARK1: usize = 0;
const INDEX_MARK2: usize = 1;
const INDEX_START: usize = 2;

/// Linux unix_gc_lock
static UNIX_GC: spin::Once<Mutex<Graph>> = spin::Once::new();

fn lock() -> MutexGuard<'static, Graph> {
    UNIX_GC
        .call_once(|| {
            Mutex::new(Graph {
                unvisited: OwnedList::new(),
                visited: OwnedList::new(),
                unvisited_index: INDEX_MARK1,
                grouped_index: INDEX_MARK2,
                max_scc_index: INDEX_START,
            })
        })
        .lock()
}

/// Linux unix_graph_state
const NOT_CYCLIC: u8 = 0;
const MAYBE_CYCLIC: u8 = 1;
const CYCLIC: u8 = 2;

static STATE: AtomicU8 = AtomicU8::new(NOT_CYCLIC);
/// Cyclic components found by the last walk (Linux
/// unix_graph_cyclic_sccs)
static CYCLIC_SCCS: AtomicUsize = AtomicUsize::new(0);
/// The collector runs (Linux gc_in_progress)
static IN_PROGRESS: AtomicBool = AtomicBool::new(false);
/// MSG_PEEK of in-flight sockets during a run (Linux unix_peek_seq,
/// its writers serialized by `PEEK_LOCK`, unix_peek_lock)
static PEEK_SEQ: SeqCount = SeqCount::new();
static PEEK_LOCK: Mutex<()> = Mutex::new(());

/// Linux UNIX_INFLIGHT_SANE_USER
const INFLIGHT_SANE_USER: u64 = (SCM_MAX_FD * 8) as u64;

/// A unix socket in flight (Linux struct unix_vertex)
pub struct Vertex {
    /// On `Graph.unvisited`/`visited`, or a message's spare list
    entry: Link,
    entry_owner: Owner,
    /// Its in-flight references (edges whose predecessor it is)
    edges: GcCell<OwnedList<EdgeLink>>,
    out_degree: GcCell<usize>,
    index: GcCell<usize>,
    scc_index: GcCell<usize>,
    /// Its component's ring (None: alone; Linux scc_entry)
    scc_next: GcCell<Option<Arc<Vertex>>>,
    scc_prev: GcCell<Option<Arc<Vertex>>>,
    /// Tarjan's vertex stack (Linux scc_entry on vertex_stack)
    stack_next: GcCell<Option<Arc<Vertex>>>,
}

crate::owned_adapter!(pub VEntry, Vertex, entry, entry_owner);

impl Default for Vertex {
    fn default() -> Self {
        Self {
            entry: Link::new(),
            entry_owner: Owner::new(),
            edges: GcCell::new(OwnedList::new()),
            out_degree: GcCell::new(0),
            index: GcCell::new(0),
            scc_index: GcCell::new(0),
            scc_next: GcCell::new(None),
            scc_prev: GcCell::new(None),
            stack_next: GcCell::new(None),
        }
    }
}

/// One in-flight reference to a unix socket (Linux struct unix_edge):
/// it holds that reference (the message's file, moved here while the
/// message is prepared, `FpList::take` puts it back)
pub struct Edge {
    /// On the predecessor's `Vertex.edges`
    link: Link,
    owner: Owner,
    /// The socket in flight and its file
    pub(super) pred: Arc<UnixSock>,
    pub(super) file: FileRef,
    /// The receiver, set when queued
    succ: GcCell<Option<Arc<UnixSock>>>,
    /// Tarjan's edge stack (Linux stack_entry)
    stack_next: GcCell<Option<Arc<Edge>>>,
}

crate::owned_adapter!(pub EdgeLink, Edge, link, owner);

impl Edge {
    pub fn new(pred: Arc<UnixSock>, file: FileRef) -> Self {
        Self {
            link: Link::new(),
            owner: Owner::new(),
            pred,
            file,
            succ: GcCell::new(None),
            stack_next: GcCell::new(None),
        }
    }
}

/// The unix socket a file is, unless opened O_PATH (Linux
/// unix_get_socket)
pub fn unix_get_socket(f: &FileRef) -> Option<Arc<UnixSock>> {
    if f.is_path() {
        return None;
    }
    let s = crate::net::socket::sock_of(f)?;
    let u = s.as_any().downcast_ref::<UnixSock>()?;
    Some(u.arc())
}

/// The vertex an edge leads to: the receiver's, or for an embryo its
/// listener's, which holds the embryo (Linux unix_edge_successor)
fn successor(g: &Graph, e: &Edge) -> Option<Arc<Vertex>> {
    let s = e.succ.access(g).as_ref()?;
    match s.listener.access(g) {
        Some(l) => l.vertex.access(g).clone(),
        None => s.vertex.access(g).clone(),
    }
}

/// Linux unix_update_graph: an edge into an in-flight socket may close
/// a cycle
fn update_graph(v: Option<Arc<Vertex>>) {
    if v.is_some() {
        STATE.store(MAYBE_CYCLIC, Ordering::Release);
    }
}

/// Linux unix_add_edge: the predecessor becomes a vertex (one of the
/// message's spares) on its first edge
fn add_edge(g: &mut Graph, spare: &mut OwnedList<VEntry>, e: &Arc<Edge>) {
    let v = match e.pred.vertex.access(g).clone() {
        Some(v) => v,
        None => {
            let v = spare
                .pop_front()
                .expect("unix gc: vertex prepared per edge");
            *v.index.access_mut(g) = g.unvisited_index;
            g.max_scc_index += 1;
            *v.scc_index.access_mut(g) = g.max_scc_index;
            *v.out_degree.access_mut(g) = 0;
            *v.scc_next.access_mut(g) = None;
            *v.scc_prev.access_mut(g) = None;
            g.unvisited.push_back(v.clone());
            *e.pred.vertex.access_mut(g) = Some(v.clone());
            v
        }
    };
    *v.out_degree.access_mut(g) += 1;
    v.edges.access_mut(g).push_back(e.clone());
    update_graph(successor(g, e));
}

/// Linux unix_del_edge: a vertex left with no edge goes to the
/// message's spares (freed with it) and leaves its ring
fn del_edge(g: &mut Graph, spare: &mut OwnedList<VEntry>, e: &Edge, dead: bool) {
    let v = e
        .pred
        .vertex
        .access(g)
        .clone()
        .expect("unix gc: an edge's predecessor is a vertex");
    if !dead {
        update_graph(successor(g, e));
    }
    // The message still holds the edge: not its last reference
    drop(v.edges.access_mut(g).remove(e));
    let d = v.out_degree.access_mut(g);
    *d -= 1;
    if *d != 0 {
        return;
    }
    *e.pred.vertex.access_mut(g) = None;
    let v = match g.unvisited.remove(&v) {
        Some(v) => v,
        None => g.visited.remove(&v).expect("unix gc: vertex listed"),
    };
    ring_del(g, &v);
    spare.push_back(v);
}

/// Take `v` off its component's ring (Linux list_del(&scc_entry))
fn ring_del(g: &mut Graph, v: &Vertex) {
    let n = v.scc_next.access_mut(g).take();
    let p = v.scc_prev.access_mut(g).take();
    if let (Some(n), Some(p)) = (n, p) {
        if Arc::ptr_eq(&n, &p) {
            *n.scc_next.access_mut(g) = None;
            *n.scc_prev.access_mut(g) = None;
        } else {
            *p.scc_next.access_mut(g) = Some(n.clone());
            *n.scc_prev.access_mut(g) = Some(p);
        }
    }
}

/// The next member of `v`'s ring in Linux's reverse order (its
/// predecessor on the ring), None after `start` came round
fn ring_step(g: &Graph, v: &Arc<Vertex>, start: &Arc<Vertex>) -> Option<Arc<Vertex>> {
    v.scc_prev
        .access(g)
        .clone()
        .filter(|p| !Arc::ptr_eq(p, start))
}

/// Linux unix_add_edges: the message's sockets' edges lead to
/// `receiver`; the sender's in-flight count grows by all its files.
/// Called under the receiver's `st`; the unused spare vertices are
/// freed after the lock (Linux unix_free_vertices).
pub fn add_edges(fpl: &mut FpList, receiver: &Arc<UnixSock>) {
    let spare = {
        let mut g = lock();
        if fpl.count_unix != 0 {
            for e in &fpl.edges {
                *e.succ.access_mut(&mut g) = Some(receiver.clone());
                add_edge(&mut g, &mut fpl.vertices, e);
            }
            *receiver.nr_unix_fds.access_mut(&mut g) += fpl.count_unix;
        }
        fpl.user.inc(Ucount::UnixInflight, fpl.files.len() as u64);
        core::mem::take(&mut fpl.vertices)
    };
    fpl.inflight = true;
    drop(spare);
}

/// Linux unix_del_edges: received or dropped; a message the collector
/// freed (`dead`) leaves its receiver alone
pub fn del_edges(fpl: &mut FpList) {
    {
        let mut g = lock();
        if fpl.count_unix != 0 {
            for e in &fpl.edges {
                del_edge(&mut g, &mut fpl.vertices, e, fpl.dead);
            }
            if !fpl.dead
                && let Some(r) = fpl.edges[0].succ.access(&g).clone()
            {
                *r.nr_unix_fds.access_mut(&mut g) -= fpl.count_unix;
            }
        }
        fpl.user.dec(Ucount::UnixInflight, fpl.files.len() as u64);
    }
    fpl.inflight = false;
}

/// An embryo's listener holds it until accepted (Linux unix_stream_connect
/// newu->listener = other), set under the sockets' `st`. Linux writes
/// it without unix_gc_lock (the embryo is not in the graph yet); the
/// cell is the graph's, so this takes `UNIX_GC` (doc/LOCKING.md)
pub fn set_listener(embryo: &UnixSock, listener: &Arc<UnixSock>) {
    let mut g = lock();
    *embryo.listener.access_mut(&mut g) = Some(listener.clone());
}

/// Accepted: the embryo's edges are its own from now on (Linux
/// unix_update_edges)
pub fn update_edges(receiver: &UnixSock) {
    let old = {
        let mut g = lock();
        if *receiver.nr_unix_fds.access(&g) != 0
            && let Some(l) = receiver.listener.access(&g)
        {
            update_graph(l.vertex.access(&g).clone());
        }
        receiver.listener.access_mut(&mut g).take()
    };
    drop(old);
}

/// A MSG_PEEK copied in-flight sockets: a run in progress must not
/// trust its reference counts (Linux unix_peek_fpl)
pub fn peek_fpl(fpl: &FpList) {
    if fpl.count_unix == 0 || !IN_PROGRESS.load(Ordering::Acquire) {
        return;
    }
    let _l = PEEK_LOCK.lock();
    PEEK_SEQ.invalidate();
}

/// Linux unix_vertex_dead: every edge leads into the same component,
/// and the file has no reference but its in-flight ones
fn vertex_dead(g: &Graph, v: &Vertex) -> bool {
    let me = *v.scc_index.access(g);
    for e in v.edges.access(g).iter() {
        match successor(g, e) {
            Some(n) if *n.scc_index.access(g) == me => {}
            _ => return false,
        }
    }
    let Some(e) = v.edges.access(g).first() else {
        return false;
    };
    crate::fs::file_count(&e.file) == *v.out_degree.access(g)
}

/// Linux unix_scc_dead: the component starting at `start` (each
/// vertex moved to `visited`), unless a MSG_PEEK intervened
fn scc_dead(g: &mut Graph, start: &Arc<Vertex>) -> bool {
    let seq = PEEK_SEQ.read_begin();
    let mut dead = true;
    let mut v = Some(start.clone());
    while let Some(cur) = v {
        let moved = g
            .unvisited
            .remove(&cur)
            .or_else(|| g.visited.remove(&cur))
            .expect("unix gc: vertex listed");
        g.visited.push_back(moved);
        if dead {
            dead = vertex_dead(g, &cur);
        }
        v = ring_step(g, &cur, start);
    }
    !PEEK_SEQ.read_retry(seq) && dead
}

/// Move every skb of `q` to `hit`
fn splice(q: &mut OwnedList<SkbOwned>, hit: &mut OwnedList<SkbOwned>) {
    while let Some(skb) = q.pop_front() {
        hit.push_back(skb);
    }
}

/// Take `u`'s whole queue (and its out-of-band mark, so the skb's last
/// reference is the queue's) into `hit`
fn take_queue(u: &UnixSock, hit: &mut OwnedList<SkbOwned>) {
    let mut q = u.purge();
    let oob = u.oob.lock().take();
    splice(&mut q, hit);
    drop(q);
    // The skb is on `hit`: not the last reference
    drop(oob);
}

/// Linux unix_collect_skb: the receive queues of a dead component's
/// sockets (a listener's: each embryo's) go to `hit`
fn collect(g: &Graph, start: &Arc<Vertex>, hit: &mut OwnedList<SkbOwned>) {
    let mut v = Some(start.clone());
    while let Some(cur) = v {
        if let Some(e) = cur.edges.access(g).first() {
            let u = &e.pred;
            if u.state() == LISTEN {
                let mut skb = u.rq.peek();
                while let Some(s) = skb {
                    if let Some(em) = &ucb(&s).embryo {
                        take_queue(em, hit);
                    }
                    skb = u.rq.peek_next(&s);
                }
            } else {
                take_queue(u, hit);
            }
        }
        v = ring_step(g, &cur, start);
    }
}

/// Linux unix_scc_cyclic: several vertices, or one with an edge to
/// itself (or an embryo of its own listener)
fn scc_cyclic(g: &Graph, v: &Arc<Vertex>) -> bool {
    if v.scc_prev.access(g).is_some() {
        return true;
    }
    v.edges
        .access(g)
        .iter()
        .any(|e| successor(g, e).is_some_and(|n| Arc::ptr_eq(&n, v)))
}

/// Push `v` on Tarjan's vertex stack
fn vpush(g: &mut Graph, top: &mut Option<Arc<Vertex>>, v: &Arc<Vertex>) {
    *v.stack_next.access_mut(g) = top.take();
    *top = Some(v.clone());
}

/// Pop the component rooted at `root` off the vertex stack, grouped
/// and linked on a fresh ring that starts at `root` (Linux
/// __list_cut_position and the grouping loop)
fn vcut(g: &mut Graph, top: &mut Option<Arc<Vertex>>, root: &Arc<Vertex>) {
    let scc = *root.scc_index.access(g);
    let mut first: Option<Arc<Vertex>> = None;
    let mut prev: Option<Arc<Vertex>> = None;
    loop {
        let v = top.take().expect("unix gc: root on the stack");
        *top = v.stack_next.access_mut(g).take();
        *v.index.access_mut(g) = g.grouped_index;
        *v.scc_index.access_mut(g) = scc;
        *v.scc_next.access_mut(g) = None;
        *v.scc_prev.access_mut(g) = prev.clone();
        if let Some(p) = &prev {
            *p.scc_next.access_mut(g) = Some(v.clone());
        }
        if first.is_none() {
            first = Some(v.clone());
        }
        let done = Arc::ptr_eq(&v, root);
        prev = Some(v);
        if done {
            break;
        }
    }
    // Close the ring: root -> first; alone when one vertex
    let f = first.expect("unix gc: one vertex at least");
    if !Arc::ptr_eq(&f, root) {
        *f.scc_prev.access_mut(g) = Some(root.clone());
        *root.scc_next.access_mut(g) = Some(f);
    }
}

/// Linux __unix_walk_scc: Tarjan's algorithm from `start`, iterative,
/// each finished component judged at once; returns the cyclic live
/// components found
fn walk_scc(
    g: &mut Graph,
    start: Arc<Vertex>,
    last_index: &mut usize,
    hit: &mut OwnedList<SkbOwned>,
) -> usize {
    let mut cyclic = 0;
    let mut vstack: Option<Arc<Vertex>> = None;
    let mut estack: Option<Arc<Edge>> = None;
    let mut vertex = start;
    'next_vertex: loop {
        vpush(g, &mut vstack, &vertex);
        *vertex.index.access_mut(g) = *last_index;
        *vertex.scc_index.access_mut(g) = *last_index;
        *last_index += 1;
        let mut edge = vertex.edges.access(g).front();
        loop {
            // Explore the receivers of this vertex's file
            while let Some(e) = edge {
                if let Some(next) = successor(g, &e) {
                    let ni = *next.index.access(g);
                    if ni == g.unvisited_index {
                        // Deeper: push the forward edge
                        *e.stack_next.access_mut(g) = estack.take();
                        estack = Some(e);
                        vertex = next;
                        continue 'next_vertex;
                    } else if ni != g.grouped_index {
                        // On the stack: the same component
                        let m = (*vertex.scc_index.access(g)).min(*next.scc_index.access(g));
                        *vertex.scc_index.access_mut(g) = m;
                    }
                }
                edge = vertex.edges.access(g).next(&e);
            }
            if *vertex.index.access(g) == *vertex.scc_index.access(g) {
                // Component finished
                vcut(g, &mut vstack, &vertex);
                if scc_dead(g, &vertex) {
                    collect(g, &vertex, hit);
                } else {
                    let si = *vertex.scc_index.access(g);
                    if g.max_scc_index < si {
                        g.max_scc_index = si;
                    }
                    if scc_cyclic(g, &vertex) {
                        cyclic += 1;
                    }
                }
            }
            // Backtrack along the edge that led here
            let Some(e) = estack.take() else {
                return cyclic;
            };
            estack = e.stack_next.access_mut(g).take();
            let next = vertex;
            vertex = e
                .pred
                .vertex
                .access(g)
                .clone()
                .expect("unix gc: an edge's predecessor is a vertex");
            let m = (*vertex.scc_index.access(g)).min(*next.scc_index.access(g));
            *vertex.scc_index.access_mut(g) = m;
            edge = vertex.edges.access(g).next(&e);
        }
    }
}

/// Linux unix_walk_scc: every vertex once; the components and the
/// cyclic count are new
fn walk(g: &mut Graph, hit: &mut OwnedList<SkbOwned>) {
    let mut last_index = INDEX_START;
    let mut cyclic = 0;
    g.max_scc_index = INDEX_START;
    while let Some(v) = g.unvisited.front() {
        cyclic += walk_scc(g, v, &mut last_index, hit);
    }
    core::mem::swap(&mut g.unvisited, &mut g.visited);
    core::mem::swap(&mut g.unvisited_index, &mut g.grouped_index);
    set_cyclic(cyclic);
}

/// Linux unix_walk_scc_fast: the components are those of the last
/// walk; each is judged again
fn walk_fast(g: &mut Graph, hit: &mut OwnedList<SkbOwned>) {
    let mut cyclic = CYCLIC_SCCS.load(Ordering::Relaxed);
    while let Some(v) = g.unvisited.front() {
        if scc_dead(g, &v) {
            cyclic = cyclic.saturating_sub(1);
            collect(g, &v, hit);
        }
    }
    core::mem::swap(&mut g.unvisited, &mut g.visited);
    set_cyclic(cyclic);
}

fn set_cyclic(n: usize) {
    CYCLIC_SCCS.store(n, Ordering::Release);
    STATE.store(if n != 0 { CYCLIC } else { NOT_CYCLIC }, Ordering::Release);
}

/// Linux unix_gc (unix_gc_work): free the dead components' queues
fn unix_gc() {
    IN_PROGRESS.store(true, Ordering::SeqCst);
    let mut hit: OwnedList<SkbOwned> = OwnedList::new();
    {
        let mut g = lock();
        match STATE.load(Ordering::Acquire) {
            NOT_CYCLIC => {}
            CYCLIC => walk_fast(&mut g, &mut hit),
            _ => walk(&mut g, &mut hit),
        }
    }
    // Their edges go without touching the receivers, which are in the
    // same dead components
    for skb in hit.iter() {
        if let Some(f) = ucb(skb).fp.lock().as_mut() {
            f.dead = true;
        }
    }
    drop(hit);
    IN_PROGRESS.store(false, Ordering::SeqCst);
}

static GC_WORK: spin::Once<Arc<IrqSpinlock<Work>>> = spin::Once::new();

/// The work item (Linux DECLARE_WORK(unix_gc_work)), made on first use
fn gc_work() -> Option<Arc<IrqSpinlock<Work>>> {
    GC_WORK
        .try_call_once(|| try_arc(IrqSpinlock::new(Work::new(unix_gc))))
        .ok()
        .cloned()
}

/// Linux unix_schedule_gc: after a release (`user` None), or before a
/// send of sockets by `user` with more than `INFLIGHT_SANE_USER` files
/// in flight, which then waits for the run while cyclic components
/// exist. Sleeps; no lock held.
///
/// Deviation: a release queues another run even while one is in
/// progress (Linux skips it while gc_in_progress). That run's walk may
/// have checked a component before this release, or the last user
/// descriptor of one of its sockets, made it dead, and nothing else
/// would run the collector for it; the work item queues at most one
/// run behind the current one. A send still skips it, as Linux: it
/// adds edges, so it makes nothing collectable.
pub fn schedule(user: Option<&UcountsRef>) {
    if STATE.load(Ordering::Acquire) == NOT_CYCLIC {
        return;
    }
    if let Some(u) = user
        && u.get(Ucount::UnixInflight) < INFLIGHT_SANE_USER
    {
        return;
    }
    let Some(w) = gc_work() else {
        return;
    };
    if user.is_none() || !IN_PROGRESS.load(Ordering::SeqCst) {
        SYSTEM_WQ.queue_work(w.clone());
    }
    if user.is_some() && CYCLIC_SCCS.load(Ordering::Acquire) != 0 {
        crate::task::workqueue::flush_work(&w);
    }
}
