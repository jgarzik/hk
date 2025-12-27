//! Task-related syscalls (getpid, gettid, sched_yield, exit, clone, etc.)
//!
//! This module re-exports syscall handlers from specialized modules:
//! - id: Identity/credential syscalls (getpid, setuid, etc.)
//! - pgrp: Process group/session syscalls (getpgid, setsid, etc.)
//! - proc: Process lifecycle syscalls (fork, clone, wait, exit)
//! - schedsys: Scheduler syscalls (nice, sched_*, ioprio_*)
//! - misc: Miscellaneous syscalls (sysinfo, prctl, pidfd_*, etc.)

// Re-export all syscalls from submodules
pub use super::id::*;
pub use super::misc::*;
pub use super::pgrp::*;
pub use super::proc::*;
pub use super::schedsys::*;
