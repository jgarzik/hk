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

use crate::sync::spin::{Mutex, RwLock};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Lazy;

use crate::task::Pid;
use crate::util::error::KernelError;

pub mod subsys;

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
/// The Cgroup struct uses fine-grained locking:
/// - `children`: RwLock for directory operations (mkdir/rmdir)
/// - `tasks`: RwLock for task list iteration and modification
/// - `subsys`: RwLock for per-controller state access
///
/// Lock ordering: children -> tasks -> subsys
pub struct Cgroup {
    /// Unique identifier for this cgroup
    pub id: CgroupId,

    /// Name of this cgroup (directory name, empty for root)
    pub name: String,

    /// Parent cgroup (None for root)
    parent: RwLock<Option<Weak<Cgroup>>>,

    /// Child cgroups (name -> Cgroup)
    children: RwLock<BTreeMap<String, Arc<Cgroup>>>,

    /// Reference to the root of this hierarchy
    root: Weak<CgroupRoot>,

    /// Hierarchy depth (0 for root)
    pub level: u32,

    /// Ancestor chain (indexed by level, for O(1) ancestor lookup)
    /// ancestors[0] = root, ancestors[level-1] = parent
    ancestors: RwLock<Vec<Weak<Cgroup>>>,

    /// Per-controller subsystem state (controller_type -> css)
    /// Only populated for controllers enabled on this cgroup
    subsys: RwLock<BTreeMap<ControllerType, Arc<CgroupSubsysState>>>,

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
    /// Create a new cgroup as a child of parent
    pub fn new(
        id: CgroupId,
        name: String,
        parent: Option<&Arc<Cgroup>>,
        root: &Arc<CgroupRoot>,
    ) -> Arc<Self> {
        let level = parent.map(|p| p.level + 1).unwrap_or(0);
        let ino = root.alloc_ino();

        let cg = Arc::new(Self {
            id,
            name,
            parent: RwLock::new(parent.map(Arc::downgrade)),
            children: RwLock::new(BTreeMap::new()),
            root: Arc::downgrade(root),
            level,
            ancestors: RwLock::new(Vec::new()),
            subsys: RwLock::new(BTreeMap::new()),
            tasks: RwLock::new(Vec::new()),
            dead: AtomicBool::new(false),
            subtree_control: AtomicU64::new(0),
            frozen: AtomicBool::new(false),
            ino,
        });

        // Build ancestor chain
        if let Some(p) = parent {
            let mut ancestors = p.ancestors.read().clone();
            ancestors.push(Arc::downgrade(p));
            *cg.ancestors.write() = ancestors;
        }

        cg
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
    pub fn lookup_child(&self, name: &str) -> Option<Arc<Cgroup>> {
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
    pub fn remove_child(&self, name: &str) -> Option<Arc<Cgroup>> {
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
        self.tasks.read().is_empty() && self.children.read().is_empty()
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

    /// Get the full path of this cgroup
    pub fn path(&self) -> String {
        if self.level == 0 {
            return String::from("/");
        }

        let mut parts = Vec::new();
        parts.push(self.name.clone());

        let ancestors = self.ancestors.read();
        for ancestor in ancestors.iter().rev() {
            if let Some(cg) = ancestor.upgrade()
                && cg.level > 0
            {
                parts.push(cg.name.clone());
            }
        }

        parts.reverse();
        let mut path = String::from("/");
        path.push_str(&parts.join("/"));
        path
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

    /// Reference count (tasks using this CSS)
    refcount: AtomicU32,

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
    ) -> Arc<Self> {
        Arc::new(Self {
            cgroup: Arc::downgrade(cgroup),
            controller,
            id,
            parent: parent_css.map(Arc::downgrade),
            refcount: AtomicU32::new(1),
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

    /// Increment reference count
    pub fn get(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement reference count
    pub fn put(&self) {
        self.refcount.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get reference count
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::Relaxed)
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
    /// Reference count (tasks using this set)
    refcount: AtomicU32,

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
    ) -> Arc<Self> {
        let hash = Self::compute_hash(&css_map);
        Arc::new(Self {
            refcount: AtomicU32::new(1),
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

    /// Get reference count
    pub fn get(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement reference count
    pub fn put(&self) {
        self.refcount.fetch_sub(1, Ordering::Relaxed);
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
) -> Arc<CssSet> {
    let hash = CssSet::compute_hash(&css_map);

    let mut cache = CSS_SET_CACHE.lock();

    // Try to find existing CssSet with same hash
    if let Some(weak) = cache.get(&hash)
        && let Some(css_set) = weak.upgrade()
    {
        css_set.get();
        return css_set;
    }

    // Create new CssSet
    let css_set = CssSet::new(css_map, default);
    cache.insert(hash, Arc::downgrade(&css_set));
    css_set
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

    /// Mount count (for reference tracking)
    mount_count: AtomicU32,
}

impl Default for CgroupRoot {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupRoot {
    /// Create a new cgroup hierarchy root
    pub const fn new() -> Self {
        Self {
            root_cgrp: RwLock::new(None),
            controllers: RwLock::new(BTreeMap::new()),
            next_cg_id: AtomicU64::new(1),
            next_ino: AtomicU64::new(1),
            mount_count: AtomicU32::new(0),
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

    /// Increment mount count
    pub fn mount(&self) {
        self.mount_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement mount count
    pub fn umount(&self) {
        self.mount_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Check if mounted
    pub fn is_mounted(&self) -> bool {
        self.mount_count.load(Ordering::Relaxed) > 0
    }
}

/// Global unified cgroup hierarchy root
pub static CGROUP_ROOT: Lazy<Arc<CgroupRoot>> = Lazy::new(|| Arc::new(CgroupRoot::new()));

/// Task `tid` (its cgroup is `Task.cgroup`, Linux task->cgroups)
fn task(tid: Pid) -> Option<crate::task::percpu::TaskRef> {
    crate::task::percpu::TASKLIST.read().task(tid)
}

/// Get the cgroup for a task
pub fn get_task_cgroup(tid: Pid) -> Option<Arc<Cgroup>> {
    task(tid).and_then(|t| t.cgroup.lock().clone())
}

/// Set the cgroup for a task (the old one is dropped after its lock)
pub fn set_task_cgroup(tid: Pid, cgroup: Arc<Cgroup>) {
    if let Some(t) = task(tid) {
        let old = t.cgroup.lock().replace(cgroup);
        drop(old);
    }
}

/// Remove cgroup mapping for a task
pub fn remove_task_cgroup(tid: Pid) -> Option<Arc<Cgroup>> {
    task(tid).and_then(|t| t.cgroup.lock().take())
}

/// Initialize the cgroup subsystem
///
/// Called during kernel init to set up the root cgroup and register controllers.
pub fn cgroup_init() {
    let root = CGROUP_ROOT.clone();

    // Create root cgroup
    let root_cg = Cgroup::new(root.alloc_cg_id(), String::new(), None, &root);

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
        {
            let css = CgroupSubsysState::new(&root_cg, controller, 1, None);
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
    let root = CGROUP_ROOT.clone();
    let tids = thread_group(pid)?;
    let ctrls: Vec<_> = target
        .enabled_controllers()
        .into_iter()
        .filter_map(|c| Some((target.css(c)?, root.get_controller(c)?)))
        .collect();
    for &tid in &tids {
        for (css, ops) in &ctrls {
            ops.can_attach(css, tid as Pid)?;
        }
    }
    for tid in tids {
        migrate_one(&root, target, tid);
    }
    Ok(())
}

/// One thread's move (Linux cgroup_migrate_execute for one task)
fn migrate_one(root: &CgroupRoot, target: &Arc<Cgroup>, tid: Tid) {
    let Some(t) = task(tid as Pid) else {
        return;
    };
    let mut slot = t.cgroup.lock();
    // Exiting: exit owns it (Linux skips PF_EXITING). Exit sets the flag
    // before it detaches under this lock, so a thread seen live here is
    // detached from wherever this leaves it
    if t.has_flag(crate::task::pf::EXITING) {
        return;
    }
    let pid = tid as Pid;
    if let Some(old) = slot.clone() {
        if Arc::ptr_eq(&old, target) {
            return;
        }
        for c in old.enabled_controllers() {
            if let (Some(css), Some(ops)) = (old.css(c), root.get_controller(c)) {
                ops.detach(&css, pid);
            }
        }
        old.remove_task(pid);
    }
    for c in target.enabled_controllers() {
        if let (Some(css), Some(ops)) = (target.css(c), root.get_controller(c)) {
            ops.attach(&css, pid);
        }
    }
    target.add_task(pid);
    *slot = Some(target.clone());
}

/// Detach a task from its cgroup (on exit)
pub fn cgroup_exit_task(pid: Pid) {
    let root = CGROUP_ROOT.clone();

    if let Some(cg) = remove_task_cgroup(pid) {
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
/// cgroupfs directory's i_rwsem; above every cgroup spin lock and
/// TASKLIST.
pub static CGROUP_MUTEX: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

/// Fork against migration (Linux cgroup_threadgroup_rwsem, its default
/// global form): a fork holds it shared from admission to post_fork, a
/// cgroup.procs write exclusively while it moves a thread group, so no
/// thread is created in the old cgroup behind a migration. Under
/// CGROUP_MUTEX; above TASKLIST and the cgroup spin locks.
pub static CGROUP_THREADGROUP_RWSEM: crate::sync::RwSem<()> = crate::sync::RwSem::new(());

/// The threads of the process `pid` names (any of its threads; 0: the
/// caller's): ESRCH if none (Linux cgroup_procs_write_start finds the
/// task, then its group leader's whole group)
pub fn thread_group(pid: Pid) -> Result<Vec<Tid>, KernelError> {
    let table = crate::task::percpu::TASKLIST.read();
    let tid = if pid == 0 {
        crate::task::percpu::current_tid()
    } else {
        pid as Tid
    };
    let tgid = table.get(tid).ok_or(KernelError::NoProcess)?.task.pid;
    Ok(table
        .iter()
        .filter(|t| t.task.pid == tgid && !t.task.has_flag(crate::task::pf::EXITING))
        .map(|t| t.task.tid())
        .collect())
}

/// Create a child cgroup (Linux cgroup_mkdir: ENODEV in a removed
/// parent)
pub fn cgroup_mkdir(parent: &Arc<Cgroup>, name: &str) -> Result<Arc<Cgroup>, KernelError> {
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
    let new_cg = Cgroup::new(root.alloc_cg_id(), String::from(name), Some(parent), &root);

    // Initialize CSS for controllers enabled in parent's subtree_control
    for controller in root.registered_controllers() {
        if parent.subtree_control_enabled(controller)
            && let Some(ops) = root.get_controller(controller)
        {
            let parent_css = parent.css(controller);
            if let Ok(private) = ops.css_alloc(parent_css.as_ref()) {
                let css_id = root.alloc_cg_id(); // Reuse cg_id allocator for css_id
                let css = CgroupSubsysState::new(&new_cg, controller, css_id, parent_css.as_ref());
                css.set_private(private);
                new_cg.set_css(controller, css);
            }
        }
    }

    // Add to parent
    parent.add_child(new_cg.clone())?;

    Ok(new_cg)
}

/// Remove a cgroup (Linux cgroup_destroy_locked, under cgroup_mutex):
/// EBUSY while it has tasks or children, else it is dead from here on,
/// so no attach or CLONE_INTO_CGROUP can join it after the check
pub fn cgroup_rmdir(parent: &Arc<Cgroup>, name: &str) -> Result<(), KernelError> {
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

use crate::task::Tid;

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
        None => match get_task_cgroup(crate::task::percpu::current_tid() as Pid) {
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
    pub fn post_fork(mut self, tid: Tid) {
        self.charged.clear();
        self.cg.add_task(tid);
        set_task_cgroup(tid, self.cg.clone());
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

/// Detach a task from its cgroup on exit
///
/// Called from mark_zombie to cleanup cgroup membership.
pub fn detach_task(tid: Tid) {
    // Use the existing cgroup_exit_task implementation
    cgroup_exit_task(tid);
}
