//! Process, credential and namespace tests

pub mod capabilities;
pub mod caps_checks;
pub mod clone3_syslog;
pub mod group_exit;
pub mod groups;
pub mod init_args;
pub mod init_signals;
pub mod kcmp;
pub mod namespace;
pub mod nproc;
pub mod pgrp_links;
pub mod pid_tid;
pub mod pidfd;
pub mod pidfd_thread;
pub mod pidns;
pub mod pidns_init;
pub mod prctl;
pub mod prctl_extra;
pub mod preempt;
pub mod process;
pub mod rlimit;
pub mod sched_ids;
pub mod setpgid;
pub mod startup;
pub mod wake_storm;
