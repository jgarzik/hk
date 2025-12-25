//! Test modules for boot_tester
//!
//! Each module contains related tests organized by category.

pub mod helpers;
pub mod vfs;
pub mod process;
pub mod file_io;
pub mod fs_common;
pub mod fs_ops;
pub mod permissions;
pub mod sync;
pub mod sysinfo;
pub mod signals;
pub mod ipc;
pub mod mmap;
pub mod rlimit;
pub mod namespace;
pub mod sockets;
pub mod futex;
pub mod timerfd;
pub mod posix_timer;
pub mod xattr;
pub mod mqueue;
pub mod capabilities;
pub mod eventfd;
pub mod epoll;
pub mod signalfd;
pub mod prctl;
pub mod inotify;
pub mod clone3_syslog;

/// Run all test categories in order
pub fn run_all_tests() {
    vfs::run_tests();
    process::run_tests();
    file_io::run_tests();
    fs_ops::run_tests();
    permissions::run_tests();
    sync::run_tests();
    sysinfo::run_tests();
    signals::run_tests();
    ipc::run_tests();
    mmap::run_tests();
    rlimit::run_tests();
    namespace::run_tests();
    sockets::run_tests();
    futex::run_tests();
    timerfd::run_tests();
    posix_timer::run_tests();
    xattr::run_tests();
    mqueue::run_tests();
    capabilities::run_tests();
    eventfd::run_tests();
    epoll::run_tests();
    signalfd::run_tests();
    prctl::run_tests();
    inotify::run_tests();
    clone3_syslog::run_tests();
}
