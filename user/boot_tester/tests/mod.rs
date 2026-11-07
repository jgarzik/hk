//! Test modules for boot_tester
//!
//! Each module contains related tests organized by category.

pub mod arch;
pub mod exec;
pub mod fs;
pub mod helpers;
pub mod io;
pub mod ipc;
pub mod mm;
pub mod net;
pub mod proc;
pub mod process;
pub mod signal;
pub mod time;

/// Run a test group in a child process: boot_tester is init, and a
/// group that crashes must show up as a FAIL, never kill init
fn isolated(name: &[u8], f: fn()) {
    use hk_syscall::{sys_exit, sys_fork, sys_wait4};
    let before = helpers::fail_count();
    let pid = sys_fork();
    if pid == 0 {
        f();
        sys_exit((helpers::fail_count() - before).min(255) as u64);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    helpers::add_fails(((st >> 8) & 0xff) as u32);
    if st & 0x7f != 0 {
        helpers::print(name);
        helpers::print(b"_GROUP:FAIL killed by signal ");
        helpers::print_num((st & 0x7f) as i64);
        helpers::println(b"");
    }
}

/// Run all test categories in order
pub fn run_all_tests() {
    fs::vfs::run_tests();
    io::stdio::run_tests();
    fs::dirents::run_tests();
    fs::namei::run_tests();
    io::cloexec::run_tests();
    io::close_range::run_tests();
    fs::append::run_tests();
    fs::mountflags::run_tests();
    fs::fs_times::run_tests();
    fs::mounts::run_tests();
    fs::mntns_check::run_tests();
    fs::mountinfo::run_tests();
    proc::sysfs::run_tests();
    fs::pnode::run_tests();
    proc::proc_dcache::run_tests();
    process::process::run_tests();
    fs::file_io::run_tests();
    fs::bigio::run_tests();
    fs::fs_ops::run_tests();
    fs::rename2::run_tests();
    fs::linkat::run_tests();
    fs::permissions::run_tests();
    fs::dac::run_tests();
    fs::sync::run_tests();
    proc::sysinfo::run_tests();
    io::gencalls::run_tests();
    process::init_args::run_tests();
    process::init_signals::run_tests();
    exec::exec_at::run_tests();
    exec::script_exec::run_tests();
    time::clock_ids::run_tests();
    mm::dev_mem::run_tests();
    proc::kmsg::run_tests();
    process::groups::run_tests();
    fs::fifo::run_tests();
    fs::anon_inode::run_tests();
    fs::etxtbsy::run_tests();
    fs::cpio_nodes::run_tests();
    signal::signals::run_tests();
    signal::sigqueue::run_tests();
    signal::sigmask::run_tests();
    arch::fpu::run_tests();
    process::preempt::run_tests();
    signal::fault_signals::run_tests();
    ipc::ipc::run_tests();
    mm::mmap::run_tests();
    isolated(b"MM_LIFE", mm::mm_life::run_tests);
    isolated(b"MM_OOM", mm::mm_oom::run_tests);
    isolated(b"FAULT_INJECT", io::fault_inject::run_tests);
    isolated(b"FORK_MM", mm::fork_mm::run_tests);
    isolated(b"MPROTECT", mm::mprotect::run_tests);
    isolated(b"TLB", mm::tlb::run_tests);
    isolated(b"MRANGE", mm::mrange::run_tests);
    isolated(b"LAYOUT", mm::layout::run_tests);
    isolated(b"STARTUP", process::startup::run_tests);
    isolated(b"ELF_EXEC", exec::elf_exec::run_tests);
    isolated(b"EXEC_IDENTITY", exec::exec_identity::run_tests);
    isolated(b"EXEC_RACE", exec::exec_race::run_tests);
    isolated(b"PROCFS_ACCESS", proc::procfs_access::run_tests);
    proc::proc_hidepid::run_tests();
    proc::proc_seq::run_tests();
    fs::pread_special::run_tests();
    isolated(b"PTRACE_ACCESS", signal::ptrace_access::run_tests);
    isolated(b"PROC_PID", proc::proc_pid::run_tests);
    isolated(b"NPROC", process::nproc::run_tests);
    isolated(b"FD_LEAK", io::fd_leak::run_tests);
    isolated(b"FD_SCALE", io::fd_scale::run_tests);
    process::rlimit::run_tests();
    isolated(b"NR_OPEN", io::nr_open::run_tests);
    process::namespace::run_tests();
    net::sockets::run_tests();
    net::sockcore::run_tests();
    net::unix::run_tests();
    net::udp::run_tests();
    mm::frag::run_tests();
    proc::sysctl::run_tests();
    net::sockopts::run_tests();
    io::nonblock::run_tests();
    ipc::futex::run_tests();
    ipc::futex_requeue::run_tests();
    ipc::futex_shared::run_tests();
    ipc::sysv_race::run_tests();
    fs::attr_race::run_tests();
    process::caps_checks::run_tests();
    fs::mount_race::run_tests();
    time::timerfd::run_tests();
    time::posix_timer::run_tests();
    fs::xattr::run_tests();
    ipc::mqueue::run_tests();
    process::capabilities::run_tests();
    io::eventfd::run_tests();
    io::epoll::run_tests();
    io::pollperm::run_tests();
    signal::signalfd::run_tests();
    process::prctl::run_tests();
    fs::inotify::run_tests();
    fs::fanotify::run_tests();
    proc::acct::run_tests();
    process::clone3_syslog::run_tests();
    process::pidfd::run_tests();
    mm::swap::run_tests();
    isolated(b"BLK", fs::blk::run_tests);
    isolated(b"SWAPOUT", mm::swapout::run_tests);
    time::adjtimex::run_tests();
    isolated(b"SETTIME", time::settime::run_tests);
    isolated(b"SECCOMP", signal::seccomp::run_tests);
    isolated(b"SCHED_IDS", process::sched_ids::run_tests);
    io::errno_pass::run_tests();
    isolated(b"CPU_ACCT", proc::cpu_acct::run_tests);
    isolated(b"CPU_TIMERS", time::cpu_timers::run_tests);
    io::io_uring::run_tests();
    net::tcp::run_tests();
    isolated(b"MEMCORE", mm::memcore::run_tests);
    isolated(b"MMLOCK", mm::mmlock::run_tests);
    isolated(b"MM_POPULATE", mm::mm_populate::run_tests);
    isolated(b"MAPCOUNT", mm::mapcount::run_tests);
    process::group_exit::run_tests();
    process::pid_tid::run_tests();
    process::pgrp_links::run_tests();
    isolated(b"SETPGID", process::setpgid::run_tests);
    net::netlink::run_tests();
    net::netdev_ioctl::run_tests();
    net::netdev::run_tests();
    net::neigh::run_tests();
    net::icmp::run_tests();
    net::icmp::run_ping_tests();
    net::raw::run_tests();
    net::packet::run_tests();
    net::tcp_xfer::run_tests();
    net::tcp_conn::run_tests();
    net::tcp_mem::run_tests();
    net::tcp_opt::run_tests();
    net::tcp_close::run_tests();
    net::net_stress::run_tests();
    ipc::keys::run_tests();
    process::kcmp::run_tests();
    mm::process_vm::run_tests();
    io::tty::run_tests();
    proc::cgroup::run_tests();
    proc::cgroup_race::run_tests();
    mm::mempolicy::run_tests();
    net::bpf::run_tests();
    fs::flock::run_tests();
    fs::posix_lock::run_tests();
    io::fcntl_owner::run_tests();
    io::sigio::run_tests();
    process::prctl_extra::run_tests();
    arch::tls::run_tests();
    io::poll::run_tests();
    time::timing::run_tests();
    time::timer_accuracy::run_tests();
    time::timer_rt::run_tests();
    signal::ptrace_stop::run_tests();
    process::wake_storm::run_tests();
    io::enomem::run_tests();
    io::uaccess::run_tests();
    isolated(b"BUSYBOX", exec::busybox::run_tests);
    isolated(b"DYN_EXEC", exec::dyn_exec::run_tests);
    #[cfg(target_arch = "x86_64")]
    arch::ioport::run_tests();
    #[cfg(target_arch = "x86_64")]
    arch::gs_sel::run_tests();
    #[cfg(target_arch = "x86_64")]
    arch::arch_gs::run_tests();
}
