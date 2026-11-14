//! kernfs: the in-memory tree behind sysfs (Linux fs/kernfs)
//!
//! A `KNode` is a directory, a text or binary attribute, or a symlink. Nodes live
//! independently of any mount: subsystems build the tree from early
//! boot on, and each sysfs mount shows it through `vfs.rs`, which makes
//! inodes on lookup.
//!
//! Children are kept in (hash, namespace, name) order (Linux
//! kernfs_name_hash): the hash is the readdir position, so a directory
//! listing resumes correctly while entries come and go. A node tagged
//! with a network namespace (nonzero `ns`: net devices and their class
//! links) is seen only through mounts of that namespace; one name may
//! exist once per namespace (Linux KERNFS_NS).
//!
//! Attribute show/store run under an active reference (Linux
//! kernfs_get_active), never under a tree lock. Removal deactivates the
//! whole subtree first, waits for in-flight operations to drain (Linux
//! kernfs_drain), then drops the attributes' operations (a node kept by
//! a stale dentry or open file no longer pins the object behind them,
//! as Linux kernfs nodes do not pin their kobject) and unlinks it;
//! operations on files opened before fail with ENODEV.
//!
//! ## Locking
//!
//! - `KERNFS_RWSEM` (sleeping `RwSem`, Linux kernfs_rwsem): held for
//!   write while adding, removing or renaming nodes, for read while
//!   building a symlink target path. Never held across show/store.
//! - `KNode.children` (sleeping `RwSem`; Linux keeps the children's
//!   rbtree under kernfs_rwsem): taken alone for lookups and listings,
//!   or under `KERNFS_RWSEM` for changes; thread context only.
//! - `KNode.parent` (spin `RwLock`, leaf): set when linked, cleared when
//!   unlinked. `KNode.name` never changes (no rename), so it has no
//!   lock.
//! - `AttrNode.ops` (spin `RwLock`, leaf): read to clone the operations
//!   under an active reference; cleared once, after the drain.
//! - `KNode.active`: incremented lock-free by `get_active` (CAS, refused
//!   once negative); the deactivation bias is added only under the
//!   rwsem (write), once per node. Drain waits on `KNode.drain` with no
//!   lock held, woken when the count reaches the bias.

pub mod sysfs;
pub mod vfs;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

use crate::sync::RwSem;
use crate::sync::spin::RwLock;
use crate::sync::waitqueue::WaitQueue;
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_arc};

/// Serializes changes to the tree's shape
static KERNFS_RWSEM: RwSem<()> = RwSem::new(());

/// Largest show() output and store() input (Linux PAGE_SIZE)
pub const ATTR_MAX: usize = 4096;

/// Active count bias of a deactivated node (Linux KN_DEACTIVATED_BIAS)
const DEACTIVATED: i32 = i32::MIN / 2;

/// Next inode number (Linux kernfs IDR; 1 is the root)
static NEXT_INO: AtomicU64 = AtomicU64::new(1);

/// Output of a show() (Linux sysfs_emit buffer)
#[derive(Default)]
pub struct SysBuf(pub Vec<u8>);

impl SysBuf {
    pub fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
}

impl fmt::Write for SysBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// A text attribute (Linux sysfs_ops show/store)
pub trait Attr: Send + Sync {
    /// Produce the whole value (at most `ATTR_MAX - 1` bytes are kept)
    fn show(&self, out: &mut SysBuf) -> Result<(), KernelError>;

    /// Consume one write: bytes accepted
    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let _ = data;
        Err(KernelError::Io)
    }
}

/// A binary attribute (Linux bin_attribute): raw reads and writes at an
/// offset below `size` (any offset if 0), no show() buffering
pub trait BinAttr: Send + Sync {
    /// st_size; 0: no limit (Linux sysfs_kf_bin_read)
    fn size(&self) -> u64;

    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, KernelError>;

    fn write(&self, off: u64, data: &[u8]) -> Result<usize, KernelError> {
        let _ = (off, data);
        Err(KernelError::Io)
    }
}

/// Read-only attribute from a closure
pub struct ShowFn<F>(pub F);

impl<F: Fn(&mut SysBuf) + Send + Sync> Attr for ShowFn<F> {
    fn show(&self, out: &mut SysBuf) -> Result<(), KernelError> {
        (self.0)(out);
        Ok(())
    }
}

/// Read-only attribute showing `f()`
pub fn show(f: impl Fn(&mut SysBuf) + Send + Sync + 'static) -> Arc<dyn Attr> {
    arc_nofail(ShowFn(f))
}

/// An attribute node's state
pub struct AttrNode {
    /// None once the node is removed
    ops: RwLock<Option<Arc<dyn Attr>>>,
    /// Bumped by `notify` (Linux kernfs_open_node.event)
    event: AtomicU32,
    /// Pollers of `event`
    poll: WaitQueue,
}

impl AttrNode {
    /// The operations, while the node is not removed (call under an
    /// active reference)
    pub fn ops(&self) -> Option<Arc<dyn Attr>> {
        self.ops.read().clone()
    }
}

/// A binary attribute node's operations (Linux kernfs_ops of a bin
/// attribute): revoked at removal, so a node a dentry or open file
/// keeps holds no device object
pub struct BinNode {
    /// None once the node is removed
    ops: RwLock<Option<Arc<dyn BinAttr>>>,
}

impl BinNode {
    /// The operations, while the node is not removed
    pub fn ops(&self) -> Option<Arc<dyn BinAttr>> {
        self.ops.read().clone()
    }
}

/// A child's key: (name hash, namespace tag, name)
type Key = (u32, u64, Vec<u8>);

/// A directory's entries by key
pub type Children = RwSem<BTreeMap<Key, Arc<KNode>>>;

pub enum Kind {
    Dir(Children),
    Attr(AttrNode),
    Bin(BinNode),
    /// Symlink to a node (Linux holds a reference; a link outliving its
    /// target reads as ENOENT)
    Link(Weak<KNode>),
}

/// Attributes set on a node by chmod, chown or utimes (Linux struct
/// kernfs_iattrs): every inode made for it starts from them
#[derive(Clone, Copy)]
pub struct Iattr {
    pub perm: u16,
    pub uid: crate::task::Uid,
    pub gid: crate::task::Gid,
    pub atime: crate::time::Timespec,
    pub mtime: crate::time::Timespec,
    pub ctime: crate::time::Timespec,
}

/// A kernfs node (Linux struct kernfs_node)
pub struct KNode {
    /// Fixed at creation (Linux changes kn->name only on rename)
    name: Vec<u8>,
    parent: RwLock<Weak<KNode>>,
    /// Permission bits
    pub mode: u16,
    pub ino: u64,
    /// Namespace tag (0: untagged, visible in every mount)
    pub ns: u64,
    pub kind: Kind,
    /// In-flight operations, plus `DEACTIVATED` once removal starts
    active: AtomicI32,
    /// Removal waits here for `active` to drain
    drain: WaitQueue,
    /// What chmod/chown/utimes set (None: the defaults)
    pub iattr: crate::sync::spin::Mutex<Option<Iattr>>,
}

/// Linux kernfs_name_hash: positions 0, 1 and i32::MAX are reserved
fn name_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in name {
        h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    let h = h & 0x7fff_ffff;
    if h < 2 {
        h + 2
    } else if h >= i32::MAX as u32 {
        i32::MAX as u32 - 1
    } else {
        h
    }
}

fn key(name: &[u8], ns: u64) -> Key {
    (name_hash(name), ns, name.to_vec())
}

/// An active reference: the node is not removed while it is held
pub struct Active<'a>(&'a KNode);

impl Drop for Active<'_> {
    fn drop(&mut self) {
        let v = self.0.active.fetch_sub(1, Ordering::AcqRel) - 1;
        if v == DEACTIVATED {
            self.0.drain.wake_all();
        }
    }
}

impl KNode {
    fn new(name: &[u8], mode: u16, kind: Kind) -> Self {
        Self::new_ns(name, mode, kind, 0)
    }

    fn new_ns(name: &[u8], mode: u16, kind: Kind, ns: u64) -> Self {
        Self {
            name: name.to_vec(),
            parent: RwLock::new(Weak::new()),
            mode,
            ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
            ns,
            kind,
            active: AtomicI32::new(0),
            drain: WaitQueue::new(),
            iattr: crate::sync::spin::Mutex::new(None),
        }
    }

    /// A new root directory
    pub fn new_root() -> Arc<Self> {
        arc_nofail(Self::new(
            b"",
            0o755,
            Kind::Dir(RwSem::new(BTreeMap::new())),
        ))
    }

    pub fn name(&self) -> Vec<u8> {
        self.name.clone()
    }

    /// The name, borrowed (fixed at creation)
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    pub fn parent(&self) -> Option<Arc<KNode>> {
        self.parent.read().upgrade()
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.kind, Kind::Dir(_))
    }

    /// Removal started (Linux !kernfs_active)
    pub fn removed(&self) -> bool {
        self.active.load(Ordering::Acquire) < 0
    }

    /// Take an active reference; None once removal started
    pub fn get_active(&self) -> Option<Active<'_>> {
        let mut v = self.active.load(Ordering::Acquire);
        loop {
            if v < 0 {
                return None;
            }
            match self
                .active
                .compare_exchange_weak(v, v + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(Active(self)),
                Err(cur) => v = cur,
            }
        }
    }

    fn children(&self) -> Option<&Children> {
        match &self.kind {
            Kind::Dir(c) => Some(c),
            _ => None,
        }
    }

    /// Child `name`
    pub fn find(&self, name: &[u8]) -> Option<Arc<KNode>> {
        self.find_ns(name, 0)
    }

    /// Child `name` as a mount of namespace `ns` sees it: tagged with
    /// `ns`, else untagged
    pub fn find_ns(&self, name: &[u8], ns: u64) -> Option<Arc<KNode>> {
        let c = self.children()?.read();
        if ns != 0
            && let Some(n) = c.get(&key(name, ns))
        {
            return Some(n.clone());
        }
        c.get(&key(name, 0)).cloned()
    }

    /// Children a mount of namespace `ns` sees, from readdir position
    /// `pos` on, as (position, node)
    pub fn list_from(&self, pos: u32, ns: u64) -> Vec<(u32, Arc<KNode>)> {
        let Some(c) = self.children() else {
            return Vec::new();
        };
        c.read()
            .range((pos, 0, Vec::new())..)
            .filter(|(_, n)| n.ns == 0 || n.ns == ns)
            .map(|((h, _, _), n)| (*h, n.clone()))
            .collect()
    }

    /// No children at all, of any namespace
    pub fn is_empty(&self) -> bool {
        self.children().is_none_or(|c| c.read().is_empty())
    }

    /// Child directories a mount of `ns` sees (st_nlink = this + 2)
    pub fn subdirs(&self, ns: u64) -> u32 {
        self.children().map_or(0, |c| {
            c.read()
                .values()
                .filter(|n| n.is_dir() && (n.ns == 0 || n.ns == ns))
                .count() as u32
        })
    }

    fn add(self: &Arc<Self>, child: Arc<KNode>) -> Result<Arc<KNode>, KernelError> {
        let _w = KERNFS_RWSEM.write();
        if self.removed() {
            return Err(KernelError::NotFound);
        }
        let c = self.children().ok_or(KernelError::NotDirectory)?;
        let k = key(&child.name, child.ns);
        let mut map = c.write();
        if map.contains_key(&k) {
            return Err(KernelError::AlreadyExists);
        }
        *child.parent.write() = Arc::downgrade(self);
        map.insert(k, child.clone());
        Ok(child)
    }

    /// New directory `name` (EEXIST if taken)
    pub fn create_dir(self: &Arc<Self>, name: &[u8], mode: u16) -> Result<Arc<KNode>, KernelError> {
        self.create_dir_ns(name, mode, 0)
    }

    /// New directory `name` tagged with namespace `ns`
    pub fn create_dir_ns(
        self: &Arc<Self>,
        name: &[u8],
        mode: u16,
        ns: u64,
    ) -> Result<Arc<KNode>, KernelError> {
        let kind = Kind::Dir(RwSem::new(BTreeMap::new()));
        self.add(try_arc(Self::new_ns(name, mode, kind, ns))?)
    }

    /// New attribute `name` with permission bits `mode`
    pub fn create_file(
        self: &Arc<Self>,
        name: &[u8],
        mode: u16,
        ops: Arc<dyn Attr>,
    ) -> Result<Arc<KNode>, KernelError> {
        let a = AttrNode {
            ops: RwLock::new(Some(ops)),
            event: AtomicU32::new(0),
            poll: WaitQueue::new(),
        };
        self.add(try_arc(Self::new(name, mode, Kind::Attr(a)))?)
    }

    /// New binary attribute `name`
    pub fn create_bin(
        self: &Arc<Self>,
        name: &[u8],
        mode: u16,
        ops: Arc<dyn BinAttr>,
    ) -> Result<Arc<KNode>, KernelError> {
        let b = BinNode {
            ops: RwLock::new(Some(ops)),
        };
        self.add(try_arc(Self::new(name, mode, Kind::Bin(b)))?)
    }

    /// New symlink `name` -> `target`
    pub fn create_link(
        self: &Arc<Self>,
        name: &[u8],
        target: &Arc<KNode>,
    ) -> Result<Arc<KNode>, KernelError> {
        self.create_link_ns(name, target, 0)
    }

    /// New symlink `name` -> `target` tagged with namespace `ns`
    pub fn create_link_ns(
        self: &Arc<Self>,
        name: &[u8],
        target: &Arc<KNode>,
        ns: u64,
    ) -> Result<Arc<KNode>, KernelError> {
        let kind = Kind::Link(Arc::downgrade(target));
        self.add(try_arc(Self::new_ns(name, 0o777, kind, ns))?)
    }

    /// The subtree rooted here, parents first
    fn subtree(self: &Arc<Self>) -> Vec<Arc<KNode>> {
        let mut out = alloc::vec![self.clone()];
        let mut i = 0;
        while i < out.len() {
            if let Some(c) = out[i].children() {
                let kids: Vec<_> = c.read().values().cloned().collect();
                out.extend(kids);
            }
            i += 1;
        }
        out
    }

    /// Remove the node and everything below it (Linux __kernfs_remove):
    /// under the rwsem the subtree is deactivated (no node can be added
    /// below a deactivated one, and a node another remover already
    /// deactivated keeps its single bias); the rwsem is dropped to wait
    /// until every node's active references drain, which every remover
    /// waits for; then the node is unlinked
    pub fn remove(self: &Arc<Self>) {
        let nodes = {
            let _w = KERNFS_RWSEM.write();
            let nodes = self.subtree();
            for n in &nodes {
                if n.active.load(Ordering::Acquire) >= 0 {
                    n.active.fetch_add(DEACTIVATED, Ordering::AcqRel);
                }
            }
            nodes
        };
        for n in &nodes {
            n.drain
                .wait_event(|| n.active.load(Ordering::Acquire) == DEACTIVATED);
            // Dropped outside the lock: they may own the object
            match &n.kind {
                Kind::Attr(a) => drop(a.ops.write().take()),
                Kind::Bin(b) => drop(b.ops.write().take()),
                _ => {}
            }
        }
        let _w = KERNFS_RWSEM.write();
        let Some(p) = self.parent() else { return };
        if let Some(c) = p.children() {
            let k = key(&self.name, self.ns);
            let mut map = c.write();
            if map.get(&k).is_some_and(|n| Arc::ptr_eq(n, self)) {
                map.remove(&k);
            }
        }
        *self.parent.write() = Weak::new();
    }

    /// Remove child `name` if present (Linux kernfs_remove_by_name)
    pub fn remove_child(&self, name: &[u8]) {
        self.remove_child_ns(name, 0);
    }

    /// Remove child `name` tagged with `ns`
    pub fn remove_child_ns(&self, name: &[u8], ns: u64) {
        let n = self
            .children()
            .and_then(|c| c.read().get(&key(name, ns)).cloned());
        if let Some(n) = n {
            n.remove();
        }
    }

    /// Ancestors from the root's child down to `self`
    fn chain(self: &Arc<Self>) -> Vec<Arc<KNode>> {
        let mut v = Vec::new();
        let mut cur = Some(self.clone());
        while let Some(n) = cur {
            cur = n.parent();
            if cur.is_some() {
                v.push(n);
            }
        }
        v.reverse();
        v
    }

    /// Path below the root, "/"-separated with a leading "/"
    pub fn path(self: &Arc<Self>) -> Vec<u8> {
        let mut p = Vec::new();
        for n in self.chain() {
            p.push(b'/');
            p.extend_from_slice(&n.name);
        }
        p
    }

    /// Relative target of a symlink in directory `self` pointing at
    /// `target` (Linux kernfs_get_target_path: "../" up to the common
    /// ancestor, then down)
    pub fn rel_path(self: &Arc<Self>, target: &Arc<KNode>) -> Vec<u8> {
        let _r = KERNFS_RWSEM.read();
        let from = self.chain();
        let to = target.chain();
        let common = from
            .iter()
            .zip(&to)
            .take_while(|(a, b)| Arc::ptr_eq(a, b))
            .count()
            // A strict ancestor of the target: a link to a directory
            // above it names that directory ("../../../virtio0")
            .min(to.len().saturating_sub(1));
        let mut p = Vec::new();
        for _ in common..from.len() {
            p.extend_from_slice(b"../");
        }
        for (i, n) in to[common..].iter().enumerate() {
            if i > 0 {
                p.push(b'/');
            }
            p.extend_from_slice(&n.name);
        }
        p
    }

    /// Wake pollers of an attribute (Linux sysfs_notify / kernfs_notify)
    pub fn notify(&self) {
        if let Kind::Attr(a) = &self.kind {
            a.event.fetch_add(1, Ordering::AcqRel);
            a.poll.wake_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Probe;

    impl BinAttr for Probe {
        fn size(&self) -> u64 {
            4
        }

        fn read(&self, _off: u64, _buf: &mut [u8]) -> Result<usize, KernelError> {
            Ok(0)
        }
    }

    /// Linux kernfs_drain, then the ops are gone: a removed binary
    /// attribute no longer holds its object, though the node lives on
    #[test]
    // The kernfs locks reach aarch64 per-CPU and IRQ-state registers,
    // which a host (EL0) test cannot read
    #[cfg_attr(target_arch = "aarch64", ignore)]
    fn removed_bin_drops_ops() {
        let root = KNode::new_root();
        let ops: Arc<dyn BinAttr> = Arc::new(Probe);
        let kn = root.create_bin(b"config", 0o644, ops.clone()).unwrap();
        assert_eq!(Arc::strong_count(&ops), 2);
        kn.remove();
        assert_eq!(Arc::strong_count(&ops), 1);
        match &kn.kind {
            Kind::Bin(b) => assert!(b.ops().is_none()),
            _ => panic!("not a bin attribute"),
        }
    }
}
