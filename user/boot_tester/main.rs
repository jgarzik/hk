//! Boot tester - Thin orchestrator for kernel test suite
//!
//! Runs every suite of the subsystem directories (fs/, net/, ...) in order

#![no_std]
#![no_main]

pub mod arch;
pub mod exec;
pub mod fs;
pub mod harness;
pub mod helpers;
pub mod io;
pub mod ipc;
pub mod mm;
pub mod net;
pub mod proc;
pub mod process;
pub mod signal;
pub mod time;

use core::ffi::c_void;
use core::panic::PanicInfo;

use hk_syscall::{
    LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, sys_exit, sys_exit_group,
    sys_getpid, sys_ioctl, sys_reboot,
};

/// tcdrain is TCSBRK with a nonzero argument
const TCSBRK: u64 = 0x5409;
use helpers::{
    dev_setup, fail_count, fs_setup, host_mode, init_host_mode, loopback_up, print, print_num,
    println,
};

/// Process entry: the kernel enters with a 16-byte aligned sp and no return
/// address, so realign per the C ABI before calling into Rust.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "xor ebp, ebp",
        "and rsp, -16",
        "call {main}",
        "ud2",
        main = sym rust_start,
    )
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov x29, xzr",
        "mov x30, xzr",
        "bl {main}",
        "brk 0",
        main = sym rust_start,
    )
}

extern "C" fn rust_start() -> ! {
    init_host_mode();

    println(b"=== hk Boot Tester ===");
    if host_mode() {
        println(b"(host mode: running on a non-hk kernel)");
    }
    fs_setup();
    dev_setup();
    loopback_up();
    println(b"");

    // Run all test categories
    run_all_tests();

    // Print final marker
    println(b"");
    println(b"BOOT_COMPLETE");

    if host_mode() {
        print(b"Host mode: ");
        print_num(fail_count() as i64);
        println(b" failed checks"); // must not itself contain "FAIL"
        // Not init (run directly on a host): report via exit status
        if sys_getpid() != 1 {
            sys_exit_group((fail_count() != 0) as u64);
        }
    }

    // Shutdown the system via ACPI S5, the console drained first
    // (tcdrain): the kernel's power-off message must not land inside
    // the output still queued for the serial port
    println(b"Powering off...");
    sys_ioctl(1, TCSBRK, 1);
    sys_reboot(
        LINUX_REBOOT_MAGIC1,
        LINUX_REBOOT_MAGIC2,
        LINUX_REBOOT_CMD_POWER_OFF,
    )
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    print(b"PANIC!");
    sys_exit(1);
}

// Compiler intrinsics required for no_std
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    unsafe {
        let mut i = 0;
        while i < n {
            *d.add(i) = c as u8;
            i += 1;
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    let s = src as *const u8;
    unsafe {
        let mut i = 0;
        while i < n {
            *d.add(i) = *s.add(i);
            i += 1;
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    let s = src as *const u8;
    unsafe {
        if s < d as *const u8 {
            let mut i = n;
            while i > 0 {
                i -= 1;
                *d.add(i) = *s.add(i);
            }
        } else {
            let mut i = 0;
            while i < n {
                *d.add(i) = *s.add(i);
                i += 1;
            }
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    let p1 = s1 as *const u8;
    let p2 = s2 as *const u8;
    unsafe {
        let mut i = 0;
        while i < n {
            let a = *p1.add(i);
            let b = *p2.add(i);
            if a != b {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        0
    }
}

// Newer LLVM lowers equality-only memcmp to bcmp
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    unsafe { memcmp(s1, s2, n) }
}

/// Run a test group in a child process: boot_tester is init, and a
/// group that crashes must show up as a FAIL, never kill init
fn isolated(name: &[u8], f: fn()) {
    use hk_syscall::{sys_exit, sys_fork, sys_wait4};
    let before = helpers::fail_count();
    let pid = sys_fork();
    if pid < 0 {
        group_fail(name, b"fork", pid);
        return;
    }
    if pid == 0 {
        f();
        sys_exit((helpers::fail_count() - before).min(255) as u64);
    }
    let mut st = 0i32;
    let r = loop {
        let r = sys_wait4(pid, &mut st, 0, 0);
        if r != EINTR {
            break r;
        }
    };
    if r != pid {
        group_fail(name, b"wait4", r);
        return;
    }
    helpers::add_fails(((st >> 8) & 0xff) as u32);
    if st & 0x7f != 0 {
        helpers::print(name);
        helpers::print(b"_GROUP:FAIL killed by signal ");
        helpers::print_num((st & 0x7f) as i64);
        helpers::println(b"");
    }
}

/// NAME_GROUP:FAIL what N: the group could not run or be waited for
fn group_fail(name: &[u8], what: &[u8], r: i64) {
    helpers::print(name);
    helpers::print(b"_GROUP:FAIL ");
    helpers::print(what);
    helpers::print(b" ");
    helpers::print_num(r);
    helpers::println(b"");
}

const EINTR: i64 = -4;

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
    fs::splice::run_tests();
    fs::deep_chain::run_tests();
    fs::anon_inode::run_tests();
    fs::etxtbsy::run_tests();
    fs::cpio_nodes::run_tests();
    signal::signals::run_tests();
    signal::signo::run_tests();
    signal::sigqueue::run_tests();
    signal::sigmask::run_tests();
    arch::fpu::run_tests();
    process::preempt::run_tests();
    signal::fault_signals::run_tests();
    isolated(b"SIGALTSTACK", signal::sigaltstack::run_tests);
    ipc::ipc::run_tests();
    ipc::shm_info::run_tests();
    mm::mmap::run_tests();
    mm::memfd::run_tests();
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
    isolated(b"EXEC_ARGS", exec::exec_args::run_tests);
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
    process::pidns::run_tests();
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
    fs::tmpfs::run_tests();
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
    process::pidfd_thread::run_tests();
    mm::swap::run_tests();
    isolated(b"BLK", fs::blk::run_tests);
    isolated(b"SWAPOUT", mm::swapout::run_tests);
    time::adjtimex::run_tests();
    isolated(b"SETTIME", time::settime::run_tests);
    isolated(b"SECCOMP", signal::seccomp::run_tests);
    isolated(b"UPTR_TOP", process::uptr_top::run_tests);
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
    signal::ptrace_exit::run_tests();
    process::wake_storm::run_tests();
    process::lock_fair::run_tests();
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
