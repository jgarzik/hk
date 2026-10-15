//! PID namespace implementation
//!
//! PID namespaces isolate process IDs. Each PID namespace has its own
//! numbering starting from 1. A process has a PID in each namespace
//! from its own up to the root (init) PID namespace.
//!
//! ## Key Concepts
//!
//! - **Level**: Nesting depth (init_pid_ns is level 0)
//! - **Child reaper**: The process that becomes the new "init" (PID 1) in this namespace
//! - **PID translation**: Each process has potentially different PIDs in different namespaces
//!
//! ## Linux Compatibility
//!
//! We follow Linux's PID namespace semantics:
//! - Processes can see PIDs in their namespace and all ancestor namespaces
//! - A process in a child namespace cannot see processes in parent namespaces
//! - When PID 1 (child reaper) exits, all processes in the namespace are killed
//!
//! ## Locking
//!
//! - `PidNamespace.pid_map`: RwLock for PID→TID mapping
//! - `PidNamespace.next_pid`: Mutex for PID allocation

use crate::sync::spin::{Mutex, RwLock};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::Lazy;

use crate::task::Tid;

/// Maximum PID namespace nesting level (same as Linux)
pub const MAX_PID_NS_LEVEL: u32 = 32;

/// PID namespace
///
/// Provides isolated PID numbering for a set of processes.
pub struct PidNamespace {
    /// PID allocator for this namespace
    next_pid: Mutex<u32>,

    /// Maximum PID value (default 32768, matches Linux default)
    pid_max: u32,

    /// Nesting level (0 = init_pid_ns, increases with each child)
    pub level: u32,

    /// Parent namespace (None for init_pid_ns)
    pub parent: Option<Arc<PidNamespace>>,

    /// Init process for this namespace (the child reaper, PID 1)
    /// When this exits, all processes in the namespace are killed
    child_reaper: RwLock<Option<Tid>>,

    /// PID → TID mapping within this namespace
    /// Maps namespace-local PIDs to global TIDs
    pid_map: RwLock<BTreeMap<u32, Tid>>,

    /// Reverse mapping: TID → PID in this namespace
    /// For efficient lookup when a process needs its PID in this namespace
    tid_map: RwLock<BTreeMap<Tid, u32>>,
}

impl PidNamespace {
    /// Create the initial (root) PID namespace
    fn new_init() -> Arc<Self> {
        Arc::new(Self {
            next_pid: Mutex::new(1),
            pid_max: 32768,
            level: 0,
            parent: None,
            child_reaper: RwLock::new(None),
            pid_map: RwLock::new(BTreeMap::new()),
            tid_map: RwLock::new(BTreeMap::new()),
        })
    }

    /// Clone this namespace (create a child namespace)
    ///
    /// Called when a process unshares or clones with CLONE_NEWPID.
    /// The child namespace starts with PID numbering at 1.
    ///
    /// # Arguments
    /// * `parent` - The parent namespace (self as Arc)
    ///
    /// # Returns
    /// * `Ok(Arc<PidNamespace>)` - New child namespace
    /// * `Err(errno)` - If max nesting level exceeded
    pub fn clone_ns(parent: &Arc<PidNamespace>) -> Result<Arc<Self>, i32> {
        // Check nesting level
        if parent.level >= MAX_PID_NS_LEVEL {
            return Err(11); // EAGAIN - max nesting exceeded
        }

        Ok(Arc::new(Self {
            next_pid: Mutex::new(1),
            pid_max: parent.pid_max,
            level: parent.level + 1,
            parent: Some(parent.clone()),
            child_reaper: RwLock::new(None),
            pid_map: RwLock::new(BTreeMap::new()),
            tid_map: RwLock::new(BTreeMap::new()),
        }))
    }

    /// Allocate a PID in this namespace
    ///
    /// Returns the next available PID, or error if exhausted.
    pub fn alloc_pid(&self) -> Result<u32, i32> {
        let mut next = self.next_pid.lock();
        if *next >= self.pid_max {
            return Err(11); // EAGAIN - no PIDs available
        }
        let pid = *next;
        *next += 1;
        Ok(pid)
    }

    /// Register a task in this namespace
    ///
    /// Associates a namespace-local PID with a global TID.
    /// If this is PID 1 and no child reaper is set, becomes the child reaper.
    pub fn register(&self, pid: u32, tid: Tid) {
        self.pid_map.write().insert(pid, tid);
        self.tid_map.write().insert(tid, pid);

        // First process (PID 1) becomes the child reaper
        if pid == 1 {
            let mut reaper = self.child_reaper.write();
            if reaper.is_none() {
                *reaper = Some(tid);
            }
        }
    }

    /// Unregister a task from this namespace
    ///
    /// Called when a task exits to remove it from the namespace's maps.
    pub fn unregister(&self, tid: Tid) {
        let pid = self.tid_map.write().remove(&tid);
        if let Some(p) = pid {
            self.pid_map.write().remove(&p);
        }
    }

    /// Get the TID for a PID in this namespace
    pub fn get_tid(&self, pid: u32) -> Option<Tid> {
        self.pid_map.read().get(&pid).copied()
    }

    /// Get the PID for a TID in this namespace
    ///
    /// Returns None if the task is not visible in this namespace
    /// (i.e., belongs to a parent or unrelated namespace).
    pub fn get_pid(&self, tid: Tid) -> Option<u32> {
        self.tid_map.read().get(&tid).copied()
    }

    /// Get the child reaper (init process) for this namespace
    pub fn get_child_reaper(&self) -> Option<Tid> {
        *self.child_reaper.read()
    }

    /// Check if this namespace is an ancestor of another
    ///
    /// Returns true if `self` is in the ancestry chain of `other`.
    pub fn is_ancestor_of(&self, other: &PidNamespace) -> bool {
        let self_ptr = self as *const PidNamespace;
        let mut current = other.parent.as_ref();

        while let Some(ns) = current {
            if Arc::as_ptr(ns) == self_ptr {
                return true;
            }
            current = ns.parent.as_ref();
        }

        false
    }
}

/// Initial (root) PID namespace
///
/// All processes belong to this namespace unless they create child namespaces.
pub static INIT_PID_NS: Lazy<Arc<PidNamespace>> = Lazy::new(PidNamespace::new_init);

/// Get a task's PID in a specific namespace
///
/// Returns the task's PID as seen from the given namespace.
/// Returns 0 if the task is not visible in that namespace.
///
/// # Arguments
/// * `tid` - Global task ID
/// * `ns` - Namespace to get PID in
pub fn task_pid_nr_ns(tid: Tid, ns: &PidNamespace) -> u32 {
    ns.get_pid(tid).unwrap_or(0)
}

/// Get a task's PID in the init namespace
///
/// This is the "global" PID visible to the init namespace.
pub fn task_pid_nr(tid: Tid) -> u32 {
    task_pid_nr_ns(tid, &INIT_PID_NS)
}

/// Find a task by PID in a specific namespace
///
/// # Arguments
/// * `pid` - PID to look up
/// * `ns` - Namespace to search in
///
/// # Returns
/// * `Some(tid)` - Global TID of the task
/// * `None` - If no task with that PID exists in the namespace
pub fn find_task_by_pid_ns(pid: u32, ns: &PidNamespace) -> Option<Tid> {
    ns.get_tid(pid)
}

/// Register a task in all applicable namespaces
///
/// When a task is created, it gets a PID in its owning namespace
/// and all ancestor namespaces. This function handles that registration.
///
/// # Arguments
/// * `tid` - Global task ID
/// * `pid_ns` - The task's owning PID namespace
///
/// # Returns
/// * `Ok(pid)` - The PID in the owning namespace
/// * `Err(errno)` - If PID allocation fails
pub fn register_task_pids(tid: Tid, pid_ns: &Arc<PidNamespace>) -> Result<u32, i32> {
    // Allocate and register in the owning namespace
    let pid = pid_ns.alloc_pid()?;
    pid_ns.register(pid, tid);

    // Walk up the hierarchy and register in each ancestor
    let mut current = pid_ns.parent.as_ref();
    while let Some(ns) = current {
        // Allocate PID in ancestor namespace
        // Note: In Linux, this is more complex with upid arrays
        // For simplicity, we allocate fresh PIDs in each namespace
        if let Ok(ancestor_pid) = ns.alloc_pid() {
            ns.register(ancestor_pid, tid);
        }
        current = ns.parent.as_ref();
    }

    Ok(pid)
}

/// Unregister a task from all namespaces
///
/// Called when a task exits to clean up PID mappings.
///
/// # Arguments
/// * `tid` - Global task ID
/// * `pid_ns` - The task's owning PID namespace
pub fn unregister_task_pids(tid: Tid, pid_ns: &Arc<PidNamespace>) {
    // Unregister from owning namespace
    pid_ns.unregister(tid);

    // Walk up the hierarchy
    let mut current = pid_ns.parent.as_ref();
    while let Some(ns) = current {
        ns.unregister(tid);
        current = ns.parent.as_ref();
    }
}
