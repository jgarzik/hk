//! kernfs: the in-memory tree behind sysfs (Linux fs/kernfs)
//!
//! A `KNode` is a directory, an attribute or a symlink. Nodes live
//! independently of any mount: subsystems build the tree from early
//! boot on, and each sysfs mount shows it through `vfs.rs`, which makes
//! inodes on lookup.
//!
//! Children are kept in (hash, name) order (Linux kernfs_name_hash): the
//! hash is the readdir position, so a directory listing resumes
//! correctly while entries come and go.
//!
//! Attribute show/store run under an active reference (Linux
//! kernfs_get_active), never under a tree lock. Removal deactivates the
//! whole subtree first, waits for in-flight operations to drain (Linux
//! kernfs_drain), then unlinks it; operations on files opened before
//! fail with ENODEV.
//!
//! ## Locking
//!
//! - `KERNFS_RWSEM` (sleeping `RwSem`, Linux kernfs_rwsem): held for
//!   write while adding, removing or renaming nodes, for read while
//!   building a symlink target path. Never held across show/store.
//! - `KNode.children`, `KNode.name`, `KNode.parent` (spin `RwLock`,
//!   leaves): taken alone, for lookups and listings, or under the rwsem
//!   for changes.
//! - Drain waits on `KNode.drain` with no lock held.

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
    Arc::new(ShowFn(f))
}

/// An attribute node's state
pub struct AttrNode {
    pub ops: Arc<dyn Attr>,
    /// Bumped by `notify` (Linux kernfs_open_node.event)
    event: AtomicU32,
    /// Pollers of `event`
    poll: WaitQueue,
}

/// A directory's entries by (name hash, name)
pub type Children = RwLock<BTreeMap<(u32, Vec<u8>), Arc<KNode>>>;

pub enum Kind {
    Dir(Children),
    Attr(AttrNode),
    /// Symlink to a node (Linux holds a reference; a link outliving its
    /// target reads as ENOENT)
    Link(Weak<KNode>),
}

/// A kernfs node (Linux struct kernfs_node)
pub struct KNode {
    name: RwLock<Vec<u8>>,
    parent: RwLock<Weak<KNode>>,
    /// Permission bits
    pub mode: u16,
    pub ino: u64,
    pub kind: Kind,
    /// In-flight operations, plus `DEACTIVATED` once removal starts
    active: AtomicI32,
    /// Removal waits here for `active` to drain
    drain: WaitQueue,
}

/// Linux kernfs_name_hash: positions 0, 1 and i32::MAX are reserved
fn name_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in name {
        h = (h ^ b as u32).wrapping_mul(0x0100_0193);
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

fn key(name: &[u8]) -> (u32, Vec<u8>) {
    (name_hash(name), name.to_vec())
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
    fn new(name: &[u8], mode: u16, kind: Kind) -> Arc<Self> {
        Arc::new(Self {
            name: RwLock::new(name.to_vec()),
            parent: RwLock::new(Weak::new()),
            mode,
            ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
            kind,
            active: AtomicI32::new(0),
            drain: WaitQueue::new(),
        })
    }

    /// A new root directory
    pub fn new_root() -> Arc<Self> {
        Self::new(b"", 0o755, Kind::Dir(RwLock::new(BTreeMap::new())))
    }

    pub fn name(&self) -> Vec<u8> {
        self.name.read().clone()
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
        self.children()?.read().get(&key(name)).cloned()
    }

    /// Children from readdir position `pos` on, as (position, node)
    pub fn list_from(&self, pos: u32) -> Vec<(u32, Arc<KNode>)> {
        let Some(c) = self.children() else {
            return Vec::new();
        };
        c.read()
            .range((pos, Vec::new())..)
            .map(|((h, _), n)| (*h, n.clone()))
            .collect()
    }

    /// Number of child directories (st_nlink = this + 2)
    pub fn subdirs(&self) -> u32 {
        self.children().map_or(0, |c| {
            c.read().values().filter(|n| n.is_dir()).count() as u32
        })
    }

    fn add(self: &Arc<Self>, child: Arc<KNode>) -> Result<Arc<KNode>, KernelError> {
        let _w = KERNFS_RWSEM.write();
        if self.removed() {
            return Err(KernelError::NotFound);
        }
        let c = self.children().ok_or(KernelError::NotDirectory)?;
        let k = key(&child.name.read());
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
        self.add(Self::new(
            name,
            mode,
            Kind::Dir(RwLock::new(BTreeMap::new())),
        ))
    }

    /// New attribute `name` with permission bits `mode`
    pub fn create_file(
        self: &Arc<Self>,
        name: &[u8],
        mode: u16,
        ops: Arc<dyn Attr>,
    ) -> Result<Arc<KNode>, KernelError> {
        let a = AttrNode {
            ops,
            event: AtomicU32::new(0),
            poll: WaitQueue::new(),
        };
        self.add(Self::new(name, mode, Kind::Attr(a)))
    }

    /// New symlink `name` -> `target`
    pub fn create_link(
        self: &Arc<Self>,
        name: &[u8],
        target: &Arc<KNode>,
    ) -> Result<Arc<KNode>, KernelError> {
        self.add(Self::new(name, 0o777, Kind::Link(Arc::downgrade(target))))
    }

    /// Deactivate the subtree and wait for its operations to finish
    fn deactivate(&self) {
        if let Some(c) = self.children() {
            let kids: Vec<_> = c.read().values().cloned().collect();
            for k in kids {
                k.deactivate();
            }
        }
        let prev = self.active.fetch_add(DEACTIVATED, Ordering::AcqRel);
        if prev < 0 {
            // Already deactivated: undo
            self.active.fetch_sub(DEACTIVATED, Ordering::AcqRel);
            return;
        }
        self.drain
            .wait_event(|| self.active.load(Ordering::Acquire) == DEACTIVATED);
    }

    /// Remove the node and everything below it (Linux kernfs_remove)
    pub fn remove(self: &Arc<Self>) {
        self.deactivate();
        let _w = KERNFS_RWSEM.write();
        let Some(p) = self.parent() else { return };
        if let Some(c) = p.children() {
            let k = key(&self.name.read());
            let mut map = c.write();
            if map.get(&k).is_some_and(|n| Arc::ptr_eq(n, self)) {
                map.remove(&k);
            }
        }
        *self.parent.write() = Weak::new();
    }

    /// Remove child `name` if present (Linux kernfs_remove_by_name)
    pub fn remove_child(&self, name: &[u8]) {
        if let Some(n) = self.find(name) {
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
            p.extend_from_slice(&n.name.read());
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
            .count();
        let mut p = Vec::new();
        for _ in common..from.len() {
            p.extend_from_slice(b"../");
        }
        for (i, n) in to[common..].iter().enumerate() {
            if i > 0 {
                p.push(b'/');
            }
            p.extend_from_slice(&n.name.read());
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
