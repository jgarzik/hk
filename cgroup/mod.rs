//! Control Groups (cgroups) v2 implementation
//!
//! Cgroups provide a mechanism for organizing processes into hierarchical groups
//! and applying resource limits and accounting to those groups.
//!
//! This implementation follows the Linux cgroup v2 (unified hierarchy) model:
//! - Single unified hierarchy
//! - All controllers follow the same tree structure
//! - Tasks can only be in leaf cgroups (no internal process constraint)
//!
//! # Architecture
//!
//! - `Cgroup`: A node in the hierarchy, contains tasks and child cgroups
//! - `CgroupSubsysState` (CSS): Per-controller per-cgroup state
//! - `CssSet`: Optimized task-to-cgroup mapping (shared among tasks in same cgroups)
//! - `CgroupRoot`: The root of the unified hierarchy
//!
//! # Controllers
//!
//! - `pids`: Limits number of tasks in a cgroup
//! - `freezer`: Freeze/thaw task execution
//! - `cpu`: CPU bandwidth limits and weights
//! - `memory`: Memory usage limits and accounting
//! - `io`: Block I/O bandwidth limits

use crate::sync::RwSem;
use crate::sync::spin::{Mutex, RwLock};
use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Lazy;

use crate::task::{Pid, Task};
use crate::util::error::KernelError;

pub mod subsys;

pub mod cgroupfs;

// Re-export controller modules
pub mod cpu;
pub mod freezer;
pub mod io;
pub mod memory;
pub mod pids;

pub use subsys::{CgroupSubsys, CgroupSubsysOps, ControllerType, CssPrivate};

/// Unique cgroup identifier
pub type CgroupId = u64;

/// Cgroup - a node in the cgroup hierarchy
///
/// Represents a single cgroup in the unified hierarchy.
/// Each cgroup can contain tasks and child cgroups.
///
/// ## Thread Safety
///
/// - `children`, `subsys`: sleeping RwSems, written under CGROUP_MUTEX
///   (Linux cgroup_mutex; lookups read `children` as kernfs_rwsem's
///   readers do); thread context, never under a spin lock
/// - `tasks`: spin RwLock (Linux css_set_lock), a leaf
pub struct Cgroup {
    /// Unique identifier for this cgroup
    pub id: CgroupId,

    /// Name of this cgroup (directory name, empty for root): bytes, any
    /// but '/', NUL and newline (Linux kernfs, cgroup_mkdir)
    pub name: Vec<u8>,

    /// Parent cgroup (None for root)
    parent: RwLock<Option<Weak<Cgroup>>>,

    /// Child cgroups (name -> Cgroup)
    children: RwSem<BTreeMap<Vec<u8>, Arc<Cgroup>>>,

    /// Reference to the root of this hierarchy
    root: Weak<CgroupRoot>,

    /// Hierarchy depth (0 for root)
    pub level: u32,

    /// Ancestor chain (indexed by level, for O(1) ancestor lookup)
    /// ancestors[0] = root, ancestors[level-1] = parent
    ancestors: RwLock<Vec<Weak<Cgroup>>>,

    /// Per-controller subsystem state (controller_type -> css)
    /// Only populated for controllers enabled on this cgroup
    subsys: RwSem<BTreeMap<ControllerType, Arc<CgroupSubsysState>>>,

    /// Tasks currently in this cgroup (pid list for iteration)
    tasks: RwLock<Vec<Pid>>,

    /// Removed (Linux CGRP_DEAD): set under CGROUP_MUTEX by rmdir, read
    /// under it (and lock-free by the file paths, which then fail
    /// ENODEV as kernfs does for a removed node)
    dead: AtomicBool,

    /// Subtree control - which controllers are enabled for children
    /// Bitmask of ControllerType values
    subtree_control: AtomicU64,

    /// Frozen state (for cgroup.freeze)
    pub frozen: AtomicBool,

    /// Inode number for cgroupfs
    pub ino: u64,
}

impl Cgroup {
    /// Create a new cgroup as a child of parent, or ENOMEM
    pub fn new(
        id: CgroupId,
        name: Vec<u8>,
        parent: Option<&Arc<Cgroup>>,
        root: &Arc<CgroupRoot>,
    ) -> Result<Arc<Self>, KernelError> {
        let cg = try_arc(Self::fresh(id, name, parent, root))?;

        // Build ancestor chain
        if let Some(p) = parent {
            let mut ancestors = p.ancestors.read().clone();
            ancestors.push(Arc::downgrade(p));
            *cg.ancestors.write() = ancestors;
        }

        Ok(cg)
    }

    /// A root cgroup made at boot (failure cannot be reported)
    pub fn new_root(id: CgroupId, name: Vec<u8>, root: &Arc<CgroupRoot>) -> Arc<Self> {
        arc_nofail(Self::fresh(id, name, None, root))
    }

    /// A cgroup's state, before its ancestor chain is built
    fn fresh(
        id: CgroupId,
        name: Vec<u8>,
        parent: Option<&Arc<Cgroup>>,
        root: &Arc<CgroupRoot>,
    ) -> Self {
        let level = parent.map(|p| p.level + 1).unwrap_or(0);
        let ino = root.alloc_ino();

        Self {
            id,
            name,
            parent: RwLock::new(parent.map(Arc::downgrade)),
            children: RwSem::new(BTreeMap::new()),
            root: Arc::downgrade(root),
            level,
            ancestors: RwLock::new(Vec::new()),
            subsys: RwSem::new(BTreeMap::new()),
            tasks: RwLock::new(Vec::new()),
            dead: AtomicBool::new(false),
            subtree_control: AtomicU64::new(0),
            frozen: AtomicBool::new(false),
            ino,
        }
    }

    /// Get parent cgroup
    pub fn parent(&self) -> Option<Arc<Cgroup>> {
        self.parent.read().as_ref().and_then(Weak::upgrade)
    }

    /// Get the root of this hierarchy
    pub fn root(&self) -> Option<Arc<CgroupRoot>> {
        self.root.upgrade()
    }

    /// Check if `other` is an ancestor of this cgroup
    pub fn is_descendant_of(&self, other: &Arc<Cgroup>) -> bool {
        if self.level <= other.level {
            return false;
        }
        let ancestors = self.ancestors.read();
        if let Some(ancestor) = ancestors.get(other.level as usize)
            && let Some(a) = ancestor.upgrade()
        {
            return Arc::ptr_eq(&a, other);
        }
        false
    }

    /// Get ancestor at a specific level
    pub fn ancestor(&self, level: u32) -> Option<Arc<Cgroup>> {
        if level >= self.level {
            return None;
        }
        let ancestors = self.ancestors.read();
        ancestors.get(level as usize).and_then(Weak::upgrade)
    }

    /// Lookup child by name
    pub fn lookup_child(&self, name: &[u8]) -> Option<Arc<Cgroup>> {
        self.children.read().get(name).cloned()
    }

    /// Get all child cgroups
    pub fn children(&self) -> Vec<Arc<Cgroup>> {
        self.children.read().values().cloned().collect()
    }

    /// Add a child cgroup
    pub fn add_child(&self, child: Arc<Cgroup>) -> Result<(), KernelError> {
        let name = child.name.clone();
        let mut children = self.children.write();
        if children.contains_key(&name) {
            return Err(KernelError::AlreadyExists);
        }
        children.insert(name, child);
        Ok(())
    }

    /// Remove a child cgroup
    pub fn remove_child(&self, name: &[u8]) -> Option<Arc<Cgroup>> {
        self.children.write().remove(name)
    }

    /// Get CSS for a controller (if enabled)
    pub fn css(&self, controller: ControllerType) -> Option<Arc<CgroupSubsysState>> {
        self.subsys.read().get(&controller).cloned()
    }

    /// Set CSS for a controller
    pub fn set_css(&self, controller: ControllerType, css: Arc<CgroupSubsysState>) {
        self.subsys.write().insert(controller, css);
    }

    /// Remove CSS for a controller
    pub fn remove_css(&self, controller: ControllerType) -> Option<Arc<CgroupSubsysState>> {
        self.subsys.write().remove(&controller)
    }

    /// Get all enabled controllers for this cgroup
    pub fn enabled_controllers(&self) -> Vec<ControllerType> {
        self.subsys.read().keys().cloned().collect()
    }

    /// Each enabled controller's state with its ops, read before any
    /// spin lock is taken (Linux: the css_set a migration moves to is
    /// found under cgroup_mutex, before css_set_lock)
    fn css_ops(&self) -> Vec<(Arc<CgroupSubsysState>, &'static dyn CgroupSubsysOps)> {
        self.subsys
            .read()
            .iter()
            .filter_map(|(&c, css)| Some((css.clone(), CGROUP_ROOT.get_controller(c)?)))
            .collect()
    }

    /// Add a task to this cgroup
    pub fn add_task(&self, pid: Pid) {
        let mut tasks = self.tasks.write();
        if !tasks.contains(&pid) {
            tasks.push(pid);
        }
    }

    /// Remove a task from this cgroup
    pub fn remove_task(&self, pid: Pid) {
        let mut tasks = self.tasks.write();
        if let Some(pos) = tasks.iter().position(|&p| p == pid) {
            tasks.remove(pos);
        }
    }

    /// Get task count
    pub fn nr_tasks(&self) -> u32 {
        self.tasks.read().len() as u32
    }

    /// Removed by rmdir (Linux cgroup_is_dead)
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// Get all tasks in this cgroup
    pub fn tasks(&self) -> Vec<Pid> {
        self.tasks.read().clone()
    }

    /// Check if cgroup is empty (no tasks, no children)
    pub fn is_empty(&self) -> bool {
        // The sleeping lock first, never under the spin one
        let no_children = self.children.read().is_empty();
        no_children && self.tasks.read().is_empty()
    }

    /// Check if this cgroup or any ancestor is frozen
    pub fn is_frozen(&self) -> bool {
        if self.frozen.load(Ordering::Acquire) {
            return true;
        }
        if let Some(parent) = self.parent() {
            return parent.is_frozen();
        }
        false
    }

    /// This cgroup's own cgroup.freeze, ancestors aside
    pub fn self_frozen(&self) -> bool {
        self.frozen.load(Ordering::Acquire)
    }

    /// Set frozen state (under CGROUP_MUTEX: cgroup.freeze writes)
    pub fn set_frozen(&self, freeze: bool) {
        self.frozen.store(freeze, Ordering::Release);
    }

    /// The full path of this cgroup, its names' bytes as they are
    pub fn path(&self) -> Vec<u8> {
        if self.level == 0 {
            return Vec::from(b"/".as_slice());
        }
        let mut path = Vec::new();
        for cg in self.ancestors.read().iter().filter_map(|a| a.upgrade()) {
            if cg.level > 0 {
                path.push(b'/');
                path.extend_from_slice(&cg.name);
            }
        }
        path.push(b'/');
        path.extend_from_slice(&self.name);
        path
    }

    /// This cgroup or its ancestor at `level` (at most its own)
    fn at_level(&self, anc: &[Weak<Cgroup>], level: u32) -> *const Cgroup {
        if level == self.level {
            core::ptr::from_ref(self)
        } else {
            anc.get(level as usize)
                .map_or(core::ptr::null(), Weak::as_ptr)
        }
    }

    /// The path to this cgroup from `from` (Linux kernfs_path_from_node,
    /// as cgroup_path_ns uses it): "/" for `from` itself, else "/.." for
    /// each level from `from` up to their common ancestor, then "/name"
    /// for each level down to this one
    pub fn path_from(&self, from: &Cgroup) -> Vec<u8> {
        if core::ptr::eq(self, from) {
            return Vec::from(b"/".as_slice());
        }
        let common = {
            let mine = self.ancestors.read();
            let theirs = from.ancestors.read();
            (0..=self.level.min(from.level))
                .take_while(|&l| self.at_level(&mine, l) == from.at_level(&theirs, l))
                .last()
        };
        // Different hierarchies: the full path
        let Some(common) = common else {
            return self.path();
        };
        // The ancestors below the common one, nearest first
        let mut up = Vec::new();
        let mut cur = self.parent();
        while let Some(c) = cur.filter(|c| c.level > common) {
            cur = c.parent();
            up.push(c);
        }
        let mut p = Vec::new();
        for _ in common..from.level {
            p.extend_from_slice(b"/..");
        }
        for c in up.iter().rev() {
            p.push(b'/');
            p.extend_from_slice(&c.name);
        }
        if common < self.level {
            p.push(b'/');
            p.extend_from_slice(&self.name);
        }
        p
    }

    /// Check subtree_control for a controller
    pub fn subtree_control_enabled(&self, controller: ControllerType) -> bool {
        let mask = self.subtree_control.load(Ordering::Relaxed);
        (mask & (1 << controller as u64)) != 0
    }

    /// Enable a controller in subtree_control
    pub fn enable_subtree_control(&self, controller: ControllerType) {
        self.subtree_control
            .fetch_or(1 << controller as u64, Ordering::Relaxed);
    }

    /// Disable a controller in subtree_control
    pub fn disable_subtree_control(&self, controller: ControllerType) {
        self.subtree_control
            .fetch_and(!(1 << controller as u64), Ordering::Relaxed);
    }
}

/// Cgroup Subsystem State (CSS)
///
/// Per-controller per-cgroup state. Each controller has one CSS per cgroup
/// where it's enabled. The CSS holds controller-specific data and provides
/// a link back to the cgroup.
pub struct CgroupSubsysState {
    /// Back-pointer to the cgroup
    pub cgroup: Weak<Cgroup>,

    /// Controller type
    pub controller: ControllerType,

    /// CSS ID (unique within the controller)
    pub id: u64,

    /// Parent CSS (for resource inheritance)
    parent: Option<Weak<CgroupSubsysState>>,

    /// Controller-specific private data
    private: RwLock<Option<Arc<dyn CssPrivate>>>,
}

impl CgroupSubsysState {
    /// Create a new CSS for a cgroup
    pub fn new(
        cgroup: &Arc<Cgroup>,
        controller: ControllerType,
        id: u64,
        parent_css: Option<&Arc<CgroupSubsysState>>,
    ) -> Result<Arc<Self>, KernelError> {
        try_arc(Self {
            cgroup: Arc::downgrade(cgroup),
            controller,
            id,
            parent: parent_css.map(Arc::downgrade),
            private: RwLock::new(None),
        })
    }

    /// Get the cgroup this CSS belongs to
    pub fn cgroup(&self) -> Option<Arc<Cgroup>> {
        self.cgroup.upgrade()
    }

    /// Get parent CSS
    pub fn parent(&self) -> Option<Arc<CgroupSubsysState>> {
        self.parent.as_ref().and_then(Weak::upgrade)
    }

    /// Set controller-specific private data
    pub fn set_private(&self, data: Arc<dyn CssPrivate>) {
        *self.private.write() = Some(data);
    }

    /// Get controller-specific private data
    pub fn private(&self) -> Option<Arc<dyn CssPrivate>> {
        self.private.read().clone()
    }

    /// Get private data cast to a specific type
    pub fn private_as<T: CssPrivate + 'static>(&self) -> Option<Arc<T>> {
        self.private()
            .and_then(|p| p.as_any_arc().downcast::<T>().ok())
    }
}

/// CSS Set - Optimized task-to-cgroup mapping
///
/// Multiple tasks in the same set of cgroups share a CssSet.
/// This reduces memory overhead when many tasks are in identical cgroup
/// configurations (common case: all tasks in root cgroups).
pub struct CssSet {
    /// Hash of CSS pointers (for fast CssSet lookup)
    hash: u64,

    /// CSS pointers indexed by controller type
    subsys: RwLock<BTreeMap<ControllerType, Arc<CgroupSubsysState>>>,

    /// Link to default cgroup (for controllers not enabled)
    default_cgroup: Weak<Cgroup>,
}

impl CssSet {
    /// Create a new CssSet
    pub fn new(
        css_map: BTreeMap<ControllerType, Arc<CgroupSubsysState>>,
        default: &Arc<Cgroup>,
    ) -> Result<Arc<Self>, KernelError> {
        let hash = Self::compute_hash(&css_map);
        try_arc(Self {
            hash,
            subsys: RwLock::new(css_map),
            default_cgroup: Arc::downgrade(default),
        })
    }

    /// Compute hash of CSS set for deduplication
    fn compute_hash(css_map: &BTreeMap<ControllerType, Arc<CgroupSubsysState>>) -> u64 {
        let mut hash = 0u64;
        for (ctrl, css) in css_map.iter() {
            hash ^= css.id.wrapping_mul(31u64.wrapping_pow(*ctrl as u32));
        }
        hash
    }

    /// Get CSS for a controller
    pub fn css(&self, controller: ControllerType) -> Option<Arc<CgroupSubsysState>> {
        self.subsys.read().get(&controller).cloned()
    }

    /// Get the cgroup for a controller (or default if not enabled)
    pub fn cgroup_for_controller(&self, controller: ControllerType) -> Option<Arc<Cgroup>> {
        if let Some(css) = self.css(controller) {
            css.cgroup()
        } else {
            self.default_cgroup.upgrade()
        }
    }

    /// Get hash
    pub fn hash(&self) -> u64 {
        self.hash
    }
}

/// Global CssSet cache for deduplication
pub static CSS_SET_CACHE: Mutex<BTreeMap<u64, Weak<CssSet>>> = Mutex::new(BTreeMap::new());

/// Find or create a CssSet for the given CSS configuration
pub fn find_css_set(
    css_map: BTreeMap<ControllerType, Arc<CgroupSubsysState>>,
    default: &Arc<Cgroup>,
) -> Result<Arc<CssSet>, KernelError> {
    let hash = CssSet::compute_hash(&css_map);

    let mut cache = CSS_SET_CACHE.lock();

    // Try to find existing CssSet with same hash
    if let Some(weak) = cache.get(&hash)
        && let Some(css_set) = weak.upgrade()
    {
        return Ok(css_set);
    }

    // Create new CssSet
    let css_set = CssSet::new(css_map, default)?;
    cache.insert(hash, Arc::downgrade(&css_set));
    Ok(css_set)
}

/// Cgroup Root - The unified hierarchy root
///
/// In cgroup v2, there is a single unified hierarchy with one root.
/// This structure holds global state for the entire hierarchy.
pub struct CgroupRoot {
    /// Root cgroup of the hierarchy
    pub root_cgrp: RwLock<Option<Arc<Cgroup>>>,

    /// Registered controllers
    pub controllers: RwLock<BTreeMap<ControllerType, &'static dyn CgroupSubsysOps>>,

    /// Next cgroup ID to allocate
    next_cg_id: AtomicU64,

    /// Next inode number for cgroupfs
    next_ino: AtomicU64,
}

impl CgroupRoot {
    /// Create a new cgroup hierarchy root
    pub const fn new() -> Self {
        Self {
            root_cgrp: RwLock::new(None),
            controllers: RwLock::new(BTreeMap::new()),
            next_cg_id: AtomicU64::new(1),
            next_ino: AtomicU64::new(1),
        }
    }

    /// Allocate a new cgroup ID
    pub fn alloc_cg_id(&self) -> CgroupId {
        self.next_cg_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocate a new inode number
    pub fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
    }

    /// Get the root cgroup
    pub fn root_cgroup(&self) -> Option<Arc<Cgroup>> {
        self.root_cgrp.read().clone()
    }

    /// Set the root cgroup
    pub fn set_root_cgroup(&self, cg: Arc<Cgroup>) {
        *self.root_cgrp.write() = Some(cg);
    }

    /// Register a controller
    pub fn register_controller(
        &self,
        controller: ControllerType,
        ops: &'static dyn CgroupSubsysOps,
    ) {
        self.controllers.write().insert(controller, ops);
    }

    /// Get a controller's operations
    pub fn get_controller(
        &self,
        controller: ControllerType,
    ) -> Option<&'static dyn CgroupSubsysOps> {
        self.controllers.read().get(&controller).copied()
    }

    /// Get all registered controllers
    pub fn registered_controllers(&self) -> Vec<ControllerType> {
        self.controllers.read().keys().cloned().collect()
    }
}

/// Global unified cgroup hierarchy root
pub static CGROUP_ROOT: Lazy<Arc<CgroupRoot>> = Lazy::new(|| arc_nofail(CgroupRoot::new()));

/// The cgroup of task `t` (`Task.cgroup`, Linux task->cgroups)
pub fn get_task_cgroup(t: &Task) -> Option<Arc<Cgroup>> {
    t.cgroup.lock().clone()
}

/// Set the cgroup of task `t` (the old one is dropped after its lock)
pub fn set_task_cgroup(t: &Task, cgroup: Arc<Cgroup>) {
    let old = t.cgroup.lock().replace(cgroup);
    drop(old);
}

/// Take task `t` out of its cgroup pointer
pub fn remove_task_cgroup(t: &Task) -> Option<Arc<Cgroup>> {
    t.cgroup.lock().take()
}

/// Initialize the cgroup subsystem
///
/// Called during kernel init to set up the root cgroup and register controllers.
pub fn cgroup_init() {
    let root = CGROUP_ROOT.clone();

    // Create root cgroup
    let root_cg = Cgroup::new_root(root.alloc_cg_id(), Vec::new(), &root);

    root.set_root_cgroup(root_cg.clone());

    // Register controllers
    root.register_controller(ControllerType::Pids, &pids::PIDS_CONTROLLER);
    root.register_controller(ControllerType::Freezer, &freezer::FREEZER_CONTROLLER);
    root.register_controller(ControllerType::Cpu, &cpu::CPU_CONTROLLER);
    root.register_controller(ControllerType::Memory, &memory::MEMORY_CONTROLLER);
    root.register_controller(ControllerType::Io, &io::IO_CONTROLLER);

    // Initialize CSS for root cgroup for each controller
    for controller in root.registered_controllers() {
        if let Some(ops) = root.get_controller(controller)
            && let Ok(private) = ops.css_alloc(None)
            && let Ok(css) = CgroupSubsysState::new(&root_cg, controller, 1, None)
        {
            css.set_private(private);
            root_cg.set_css(controller, css);
        }
    }
}

/// Move the process `pid` names into `target` (Linux cgroup_migrate,
/// under CGROUP_MUTEX and CGROUP_THREADGROUP_RWSEM write): every
/// controller's can_attach for every live thread first, so a refusal
/// moves none; then each thread under its own cgroup pointer's lock,
/// which exit also takes to detach it, so a thread that exits meanwhile
/// is skipped, never re-attached
pub fn migrate_thread_group(target: &Arc<Cgroup>, pid: Pid) -> Result<(), KernelError> {
    let threads = thread_group(pid)?;
    let to = target.css_ops();
    for t in &threads {
        for (css, ops) in &to {
            ops.can_attach(css, t.tid() as Pid)?;
        }
    }
    for t in &threads {
        migrate_one(target, &to, t);
    }
    Ok(())
}

/// Thread `t`'s move (Linux cgroup_migrate_execute for one task) to
/// `target`, whose controllers are `to`. Its current cgroup's
/// controllers are read first, outside the task's cgroup lock (Linux
/// cgroup_migrate_add_src / prepare_dst under cgroup_mutex, before
/// css_set_lock). That cgroup stays current until the lock is taken:
/// other migrations (CGROUP_MUTEX) and post_fork
/// (CGROUP_THREADGROUP_RWSEM) are held off, and exit marks the thread
/// exiting before it clears the pointer
fn migrate_one(
    target: &Arc<Cgroup>,
    to: &[(Arc<CgroupSubsysState>, &dyn CgroupSubsysOps)],
    t: &Task,
) {
    let old = get_task_cgroup(t);
    if old.as_ref().is_some_and(|o| Arc::ptr_eq(o, target)) {
        return;
    }
    let from = old.as_ref().map(|o| o.css_ops()).unwrap_or_default();
    let mut slot = t.cgroup.lock();
    // Exiting: exit owns it (Linux skips PF_EXITING). Exit sets the flag
    // before it detaches under this lock, so a thread seen live here is
    // detached from wherever this leaves it
    if t.has_flag(crate::task::pf::EXITING) {
        return;
    }
    let pid = t.tid() as Pid;
    if let Some(old) = slot.clone() {
        for (css, ops) in &from {
            ops.detach(css, pid);
        }
        old.remove_task(pid);
    }
    for (css, ops) in to {
        ops.attach(css, pid);
    }
    target.add_task(pid);
    *slot = Some(target.clone());
}

/// Detach the exiting task `t` from its cgroup (Linux cgroup_exit):
/// from exit_current while it still runs, before it is a zombie, so no
/// reap can remove it from the task list first
pub fn detach_task(t: &Task) {
    let root = CGROUP_ROOT.clone();
    let pid = t.tid();
    if let Some(cg) = remove_task_cgroup(t) {
        for controller in cg.enabled_controllers() {
            if let Some(css) = cg.css(controller)
                && let Some(ops) = root.get_controller(controller)
            {
                ops.exit(&css, pid);
            }
        }
        cg.remove_task(pid);
    }
}

/// The cgroup hierarchy's sleeping lock (Linux cgroup_mutex): mkdir,
/// rmdir, cgroup.procs, subtree_control and freeze writes, and a
/// CLONE_INTO_CGROUP fork from admission to post_fork; whoever holds it
/// sees a cgroup's death and membership settle together. Under a
/// cgroupfs directory's i_rwsem; above `Cgroup.{children, subsys}`,
/// every cgroup spin lock and TASKLIST.
pub static CGROUP_MUTEX: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

/// Fork against migration (Linux cgroup_threadgroup_rwsem, its default
/// global form): a fork holds it shared from admission to post_fork, a
/// cgroup.procs write exclusively while it moves a thread group, so no
/// thread is created in the old cgroup behind a migration. Under
/// CGROUP_MUTEX; above `Cgroup.subsys`, TASKLIST and the cgroup spin
/// locks.
pub static CGROUP_THREADGROUP_RWSEM: crate::sync::RwSem<()> = crate::sync::RwSem::new(());

/// The threads of the process `pid` names in the caller's pid
/// namespace (any of its threads; 0: the caller's): ESRCH if none
/// (Linux cgroup_procs_write_start finds the task by find_task_by_vpid,
/// then its group leader's whole group; exiting threads are skipped)
pub fn thread_group(pid: Pid) -> Result<Vec<crate::task::percpu::TaskRef>, KernelError> {
    use crate::task::percpu::{GlobalTaskTable, current, find_task_by_vpid, task_ref};
    let t = if pid == 0 {
        task_ref(&current())
    } else {
        find_task_by_vpid(pid).ok_or(KernelError::NoProcess)?
    };
    Ok(GlobalTaskTable::collect_group(&t, |_, x| {
        (!x.task.has_flag(crate::task::pf::EXITING)).then(|| task_ref(x.task))
    }))
}

/// Create a child cgroup (Linux cgroup_mkdir: EINVAL for a name with a
/// newline, which would break /proc/<pid>/cgroup; ENODEV in a removed
/// parent)
pub fn cgroup_mkdir(parent: &Arc<Cgroup>, name: &[u8]) -> Result<Arc<Cgroup>, KernelError> {
    if name.contains(&b'\n') {
        return Err(KernelError::InvalidArgument);
    }
    let _g = CGROUP_MUTEX.lock();
    if parent.is_dead() {
        return Err(KernelError::NoDevice);
    }
    let root = CGROUP_ROOT.clone();

    // Check if name already exists
    if parent.lookup_child(name).is_some() {
        return Err(KernelError::AlreadyExists);
    }

    // Create new cgroup
    let new_cg = Cgroup::new(root.alloc_cg_id(), Vec::from(name), Some(parent), &root)?;

    // Initialize CSS for controllers enabled in parent's subtree_control
    for controller in root.registered_controllers() {
        if parent.subtree_control_enabled(controller)
            && let Some(ops) = root.get_controller(controller)
        {
            let parent_css = parent.css(controller);
            // ENOMEM fails the mkdir (Linux css_create); the new cgroup
            // is not linked yet, and css_free has nothing to undo
            let private = ops.css_alloc(parent_css.as_ref())?;
            let css_id = root.alloc_cg_id(); // Reuse cg_id allocator for css_id
            let css = CgroupSubsysState::new(&new_cg, controller, css_id, parent_css.as_ref())?;
            css.set_private(private);
            new_cg.set_css(controller, css);
        }
    }

    // Add to parent
    parent.add_child(new_cg.clone())?;

    Ok(new_cg)
}

/// Remove a cgroup (Linux cgroup_destroy_locked, under cgroup_mutex):
/// EBUSY while it has tasks or children, else it is dead from here on,
/// so no attach or CLONE_INTO_CGROUP can join it after the check
pub fn cgroup_rmdir(parent: &Arc<Cgroup>, name: &[u8]) -> Result<(), KernelError> {
    let _g = CGROUP_MUTEX.lock();
    let child = parent.lookup_child(name).ok_or(KernelError::NotFound)?;

    // Check if empty
    if !child.is_empty() {
        return Err(KernelError::Busy);
    }
    child.dead.store(true, Ordering::Release);

    // Cleanup CSS for all controllers
    let root = CGROUP_ROOT.clone();
    for controller in child.enabled_controllers() {
        if let Some(css) = child.remove_css(controller)
            && let Some(ops) = root.get_controller(controller)
        {
            ops.css_free(&css);
        }
    }

    // Remove from parent
    parent.remove_child(name);

    Ok(())
}

// ============================================================================
// Helper functions for task integration (clone/exit)
// ============================================================================

/// A child admitted into its cgroup before it exists (Linux
/// cgroup_can_fork .. cgroup_post_fork / cgroup_cancel_fork): the
/// controllers' charges are held; dropping it (the fork failed) gives
/// them back, `post_fork` makes the child a member
pub struct ForkCg {
    cg: Arc<Cgroup>,
    /// The controllers whose `can_fork` admitted it
    charged: Vec<ControllerType>,
    /// CGROUP_THREADGROUP_RWSEM, shared, until post_fork (Linux
    /// cgroup_threadgroup_change_begin in cgroup_css_set_fork); dropped
    /// after the charges are given back
    _tg: crate::sync::RwSemReadGuard<'static, ()>,
    /// CLONE_INTO_CGROUP: CGROUP_MUTEX until post_fork (Linux
    /// cgroup_css_set_fork .. cgroup_css_set_put_fork), released last
    _lock: Option<crate::sync::MutexGuard<'static, ()>>,
}

/// Admit a new task into its cgroup (Linux cgroup_css_set_fork +
/// cgroup_can_fork): `into`, the CLONE_INTO_CGROUP one, which is locked
/// and must not be dead (ENODEV), else the parent's, read under
/// CGROUP_THREADGROUP_RWSEM so no migration moves the parent in between;
/// every enabled controller's `can_fork`, undone if a later one
/// refuses. None when the parent is in no cgroup.
pub fn can_fork(into: Option<Arc<Cgroup>>) -> Result<Option<ForkCg>, KernelError> {
    let lock = into.is_some().then(|| CGROUP_MUTEX.lock());
    let tg = CGROUP_THREADGROUP_RWSEM.read();
    let cg = match into {
        Some(cg) if cg.is_dead() => return Err(KernelError::NoDevice),
        Some(cg) => cg,
        None => match get_task_cgroup(&crate::task::percpu::current()) {
            Some(cg) => cg,
            None => return Ok(None),
        },
    };
    let mut fc = ForkCg {
        cg: cg.clone(),
        charged: Vec::new(),
        _tg: tg,
        _lock: lock,
    };
    for controller in cg.enabled_controllers() {
        if let Some(css) = cg.css(controller)
            && let Some(ops) = CGROUP_ROOT.get_controller(controller)
        {
            ops.can_fork(&css)?;
            fc.charged.push(controller);
        }
    }
    Ok(Some(fc))
}

impl ForkCg {
    /// The child exists: it joins the cgroup, keeping the charges
    /// (Linux cgroup_post_fork)
    pub fn post_fork(mut self, child: &Task) {
        self.charged.clear();
        self.cg.add_task(child.tid());
        set_task_cgroup(child, self.cg.clone());
    }
}

impl Drop for ForkCg {
    /// Linux cgroup_cancel_fork
    fn drop(&mut self) {
        for &controller in &self.charged {
            if let Some(css) = self.cg.css(controller)
                && let Some(ops) = CGROUP_ROOT.get_controller(controller)
            {
                ops.cancel_fork(&css);
            }
        }
    }
}
