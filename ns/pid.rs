//! PID namespace implementation
//!
//! PID namespaces isolate process IDs (Linux: each namespace numbers its
//! tasks from 1, and a task has a PID in its own namespace and every
//! ancestor). Each namespace has its number bitmap (`task::pid`), and a
//! task gets a number in each level of its namespace chain; syscalls
//! translate between the caller's numbers and the root ones
//! (`task::pid::vnr`).

use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::sync::Arc;
use spin::Lazy;

/// Maximum PID namespace nesting level (same as Linux)
pub const MAX_PID_NS_LEVEL: u32 = 32;

/// PID namespace (immutable after creation)
pub struct PidNamespace {
    /// Nesting level (0 = init_pid_ns, increases with each child)
    pub level: u32,

    /// Parent namespace (None for init_pid_ns)
    pub parent: Option<Arc<PidNamespace>>,

    /// Its numbers (Linux pid_namespace->pidmap)
    pub map: crate::task::pid::PidMap,
}

impl PidNamespace {
    /// Create the initial (root) PID namespace
    fn new_init() -> Arc<Self> {
        // Boot: failure cannot be reported
        arc_nofail(Self {
            level: 0,
            parent: None,
            map: crate::task::pid::PidMap::new(),
        })
    }

    /// Create a child namespace (CLONE_NEWPID, unshare)
    ///
    /// EAGAIN past MAX_PID_NS_LEVEL levels, like Linux create_pid_namespace.
    pub fn clone_ns(parent: &Arc<PidNamespace>) -> Result<Arc<Self>, i32> {
        if parent.level >= MAX_PID_NS_LEVEL {
            return Err(11); // EAGAIN - max nesting exceeded
        }
        try_arc(Self {
            level: parent.level + 1,
            parent: Some(parent.clone()),
            map: crate::task::pid::PidMap::new(),
        })
        .map_err(|e| e.errno())
    }
}

/// Initial (root) PID namespace
///
/// All processes belong to this namespace unless they create child namespaces.
pub static INIT_PID_NS: Lazy<Arc<PidNamespace>> = Lazy::new(PidNamespace::new_init);
