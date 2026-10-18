//! PID namespace implementation
//!
//! PID namespaces isolate process IDs (Linux: each namespace numbers its
//! tasks from 1, and a task has a PID in its own namespace and every
//! ancestor). Only the namespace hierarchy exists so far: tasks are
//! numbered by the global pid/tid counters (BUGS.md), so a child
//! namespace does not renumber its tasks yet.

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
}

impl PidNamespace {
    /// Create the initial (root) PID namespace
    fn new_init() -> Arc<Self> {
        Arc::new(Self {
            level: 0,
            parent: None,
        })
    }

    /// Create a child namespace (CLONE_NEWPID, unshare)
    ///
    /// EAGAIN past MAX_PID_NS_LEVEL levels, like Linux create_pid_namespace.
    pub fn clone_ns(parent: &Arc<PidNamespace>) -> Result<Arc<Self>, i32> {
        if parent.level >= MAX_PID_NS_LEVEL {
            return Err(11); // EAGAIN - max nesting exceeded
        }
        Ok(Arc::new(Self {
            level: parent.level + 1,
            parent: Some(parent.clone()),
        }))
    }
}

/// Initial (root) PID namespace
///
/// All processes belong to this namespace unless they create child namespaces.
pub static INIT_PID_NS: Lazy<Arc<PidNamespace>> = Lazy::new(PidNamespace::new_init);
