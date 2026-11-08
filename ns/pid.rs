//! PID namespace implementation
//!
//! PID namespaces isolate process IDs (Linux: each namespace numbers its
//! tasks from 1, and a task has a PID in its own namespace and every
//! ancestor). Each namespace has its number bitmap (`task::pid`), and a
//! task gets a number in each level of its namespace chain; syscalls
//! translate between the caller's numbers and the root ones
//! (`task::pid::vnr`).

use crate::task::TableCell;
use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::AtomicU32;
use spin::Lazy;

/// Maximum PID namespace nesting level (same as Linux)
pub const MAX_PID_NS_LEVEL: u32 = 32;

/// `PidNamespace.alloc`: new pids may be made (Linux PIDNS_ADDING),
/// until its init dies
pub const NS_ADDING: u32 = 1 << 31;
/// `PidNamespace.alloc`: its init (pid 1) has been in the task list
/// (Linux child_reaper != NULL); until then only 1 may be made
pub const NS_INIT: u32 = 1 << 30;
/// `PidNamespace.alloc`: the count of its pids (Linux pid_allocated)
pub const NS_PIDS: u32 = NS_INIT - 1;

/// PID namespace: its level, parent and number bitmap are fixed at
/// creation; the init state below is locked
pub struct PidNamespace {
    /// Nesting level (0 = init_pid_ns, increases with each child)
    pub level: u32,

    /// Parent namespace (None for init_pid_ns)
    pub parent: Option<Arc<PidNamespace>>,

    /// Its numbers (Linux pid_namespace->pidmap)
    pub map: crate::task::pid::PidMap,

    /// Its pids, with `NS_ADDING` and `NS_INIT` (Linux pid_allocated):
    /// changed under PIDMAP_LOCK (`task::pid`)
    pub alloc: AtomicU32,

    /// The task its orphans go to (Linux child_reaper): its init, or
    /// another live thread of init's group once init's thread exits.
    /// Under TASKLIST (`task::pidns`); set when init joins the task
    /// list, kept after it dies (nothing is made in the namespace then)
    pub reaper: TableCell<Option<Weak<crate::task::Task>>>,

    /// Signal its init's group reports, set by reboot(2) inside (Linux
    /// pid_ns->reboot: SIGHUP to restart, SIGINT to halt), 0 otherwise;
    /// under TASKLIST
    pub reboot: TableCell<i32>,

    /// Its process accounting file (Linux pid_namespace->bacct): set by
    /// acct(2) inside, ended with the namespace (`task::acct`)
    pub bacct: crate::task::acct::Acct,
}

impl PidNamespace {
    /// Create the initial (root) PID namespace
    fn new_init() -> Arc<Self> {
        // Boot: failure cannot be reported. Linux init_pid_ns: its
        // child_reaper is set from the start
        arc_nofail(Self {
            level: 0,
            parent: None,
            map: crate::task::pid::PidMap::new(),
            alloc: AtomicU32::new(NS_ADDING | NS_INIT),
            reaper: TableCell::new(None),
            reboot: TableCell::new(0),
            bacct: crate::task::acct::Acct::default(),
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
            alloc: AtomicU32::new(NS_ADDING),
            reaper: TableCell::new(None),
            reboot: TableCell::new(0),
            bacct: crate::task::acct::Acct::default(),
        })
        .map_err(|e| e.errno())
    }
}

/// Initial (root) PID namespace
///
/// All processes belong to this namespace unless they create child namespaces.
pub static INIT_PID_NS: Lazy<Arc<PidNamespace>> = Lazy::new(PidNamespace::new_init);
