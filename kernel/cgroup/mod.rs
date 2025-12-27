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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Lazy, Mutex, RwLock};

use crate::error::KernelError;
use crate::task::Pid;

pub mod subsys;

// Re-export controller modules
pub mod cpu;
pub mod freezer;
pub mod io;
pub mod memory;
pub mod pids;

pub use subsys::{CgroupSubsys, CgroupSubsysOps, CssPrivate, ControllerType};

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

    /// Reference count for tasks using this cgroup
    nr_tasks: AtomicU32,

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
            nr_tasks: AtomicU32::new(0),
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
        if let Some(ancestor) = ancestors.get(other.level as usize) {
            if let Some(a) = ancestor.upgrade() {
                return Arc::ptr_eq(&a, other);
            }
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
            self.nr_tasks.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Remove a task from this cgroup
    pub fn remove_task(&self, pid: Pid) {
        let mut tasks = self.tasks.write();
        if let Some(pos) = tasks.iter().position(|&p| p == pid) {
            tasks.remove(pos);
            self.nr_tasks.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get task count
    pub fn nr_tasks(&self) -> u32 {
        self.nr_tasks.load(Ordering::Relaxed)
    }

    /// Get all tasks in this cgroup
    pub fn tasks(&self) -> Vec<Pid> {
        self.tasks.read().clone()
    }

    /// Check if cgroup is empty (no tasks, no children)
    pub fn is_empty(&self) -> bool {
        self.nr_tasks() == 0 && self.children.read().is_empty()
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

    /// Set frozen state
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
            if let Some(cg) = ancestor.upgrade() {
                if cg.level > 0 {
                    parts.push(cg.name.clone());
                }
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
    if let Some(weak) = cache.get(&hash) {
        if let Some(css_set) = weak.upgrade() {
            css_set.get();
            return css_set;
        }
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
    pub fn register_controller(&self, controller: ControllerType, ops: &'static dyn CgroupSubsysOps) {
        self.controllers.write().insert(controller, ops);
    }

    /// Get a controller's operations
    pub fn get_controller(&self, controller: ControllerType) -> Option<&'static dyn CgroupSubsysOps> {
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

/// Task-to-cgroup mapping
/// Maps TID -> Arc<Cgroup>
pub static TASK_CGROUP: RwLock<BTreeMap<Pid, Arc<Cgroup>>> = RwLock::new(BTreeMap::new());

/// Get the cgroup for a task
pub fn get_task_cgroup(pid: Pid) -> Option<Arc<Cgroup>> {
    TASK_CGROUP.read().get(&pid).cloned()
}

/// Set the cgroup for a task
pub fn set_task_cgroup(pid: Pid, cgroup: Arc<Cgroup>) {
    TASK_CGROUP.write().insert(pid, cgroup);
}

/// Remove cgroup mapping for a task
pub fn remove_task_cgroup(pid: Pid) -> Option<Arc<Cgroup>> {
    TASK_CGROUP.write().remove(&pid)
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
        if let Some(ops) = root.get_controller(controller) {
            if let Ok(private) = ops.css_alloc(None) {
                let css = CgroupSubsysState::new(&root_cg, controller, 1, None);
                css.set_private(private);
                root_cg.set_css(controller, css);
            }
        }
    }
}

/// Attach a task to a cgroup
///
/// Migrates the task from its current cgroup to the target cgroup.
pub fn cgroup_attach_task(target_cg: &Arc<Cgroup>, pid: Pid) -> Result<(), KernelError> {
    let root = CGROUP_ROOT.clone();

    // Get old cgroup if any
    let old_cg = get_task_cgroup(pid);

    // Call can_attach on all controllers
    for controller in target_cg.enabled_controllers() {
        if let Some(css) = target_cg.css(controller) {
            if let Some(ops) = root.get_controller(controller) {
                ops.can_attach(&css, pid)?;
            }
        }
    }

    // Detach from old cgroup
    if let Some(ref old) = old_cg {
        for controller in old.enabled_controllers() {
            if let Some(css) = old.css(controller) {
                if let Some(ops) = root.get_controller(controller) {
                    ops.detach(&css, pid);
                }
            }
        }
        old.remove_task(pid);
    }

    // Attach to new cgroup
    for controller in target_cg.enabled_controllers() {
        if let Some(css) = target_cg.css(controller) {
            if let Some(ops) = root.get_controller(controller) {
                ops.attach(&css, pid)?;
            }
        }
    }

    target_cg.add_task(pid);
    set_task_cgroup(pid, target_cg.clone());

    Ok(())
}

/// Detach a task from its cgroup (on exit)
pub fn cgroup_exit_task(pid: Pid) {
    let root = CGROUP_ROOT.clone();

    if let Some(cg) = remove_task_cgroup(pid) {
        for controller in cg.enabled_controllers() {
            if let Some(css) = cg.css(controller) {
                if let Some(ops) = root.get_controller(controller) {
                    ops.exit(&css, pid);
                }
            }
        }
        cg.remove_task(pid);
    }
}

/// Check if a task can fork (pids controller check)
pub fn cgroup_can_fork(pid: Pid) -> Result<(), KernelError> {
    if let Some(cg) = get_task_cgroup(pid) {
        if let Some(css) = cg.css(ControllerType::Pids) {
            if let Some(ops) = CGROUP_ROOT.get_controller(ControllerType::Pids) {
                return ops.can_fork(&css);
            }
        }
    }
    Ok(())
}

/// Called after successful fork to charge pids controller
pub fn cgroup_fork(parent_pid: Pid, child_pid: Pid) -> Result<(), KernelError> {
    // Child inherits parent's cgroup
    if let Some(cg) = get_task_cgroup(parent_pid) {
        // Call fork on all controllers
        for controller in cg.enabled_controllers() {
            if let Some(css) = cg.css(controller) {
                if let Some(ops) = CGROUP_ROOT.get_controller(controller) {
                    ops.fork(&css, child_pid)?;
                }
            }
        }

        // Add child to same cgroup
        cg.add_task(child_pid);
        set_task_cgroup(child_pid, cg);
    }
    Ok(())
}

/// Create a child cgroup
pub fn cgroup_mkdir(parent: &Arc<Cgroup>, name: &str) -> Result<Arc<Cgroup>, KernelError> {
    let root = CGROUP_ROOT.clone();

    // Check if name already exists
    if parent.lookup_child(name).is_some() {
        return Err(KernelError::AlreadyExists);
    }

    // Create new cgroup
    let new_cg = Cgroup::new(root.alloc_cg_id(), String::from(name), Some(parent), &root);

    // Initialize CSS for controllers enabled in parent's subtree_control
    for controller in root.registered_controllers() {
        if parent.subtree_control_enabled(controller) {
            if let Some(ops) = root.get_controller(controller) {
                let parent_css = parent.css(controller);
                if let Ok(private) = ops.css_alloc(parent_css.as_ref()) {
                    let css_id = root.alloc_cg_id(); // Reuse cg_id allocator for css_id
                    let css = CgroupSubsysState::new(&new_cg, controller, css_id, parent_css.as_ref());
                    css.set_private(private);
                    new_cg.set_css(controller, css);
                }
            }
        }
    }

    // Add to parent
    parent.add_child(new_cg.clone())?;

    Ok(new_cg)
}

/// Remove a cgroup
pub fn cgroup_rmdir(parent: &Arc<Cgroup>, name: &str) -> Result<(), KernelError> {
    let child = parent.lookup_child(name).ok_or(KernelError::NotFound)?;

    // Check if empty
    if !child.is_empty() {
        return Err(KernelError::Busy);
    }

    // Cleanup CSS for all controllers
    let root = CGROUP_ROOT.clone();
    for controller in child.enabled_controllers() {
        if let Some(css) = child.remove_css(controller) {
            if let Some(ops) = root.get_controller(controller) {
                ops.css_free(&css);
            }
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

/// Check if forking is allowed for a cgroup (pids controller check)
///
/// Returns true if fork is allowed, false if pids.max limit would be exceeded.
pub fn pids_can_fork(cgroup: &Arc<Cgroup>) -> bool {
    // Check pids controller if enabled
    if let Some(css) = cgroup.css(ControllerType::Pids) {
        if let Some(ops) = CGROUP_ROOT.get_controller(ControllerType::Pids) {
            return ops.can_fork(&css).is_ok();
        }
    }
    // No pids controller enabled - allow fork
    true
}

/// Attach a task to a cgroup during clone
///
/// Called from do_clone to inherit parent's cgroup membership.
/// This is a simpler version of cgroup_attach_task for the clone path.
pub fn attach_task(tid: Tid, cgroup: &Arc<Cgroup>) {
    let root = CGROUP_ROOT.clone();

    // Call fork on all controllers to update accounting
    for controller in cgroup.enabled_controllers() {
        if let Some(css) = cgroup.css(controller)
            && let Some(ops) = root.get_controller(controller)
        {
            let _ = ops.fork(&css, tid);
        }
    }

    // Add task to cgroup
    cgroup.add_task(tid);
    set_task_cgroup(tid, cgroup.clone());
}

/// Detach a task from its cgroup on exit
///
/// Called from mark_zombie to cleanup cgroup membership.
pub fn detach_task(tid: Tid) {
    // Use the existing cgroup_exit_task implementation
    cgroup_exit_task(tid);
}
