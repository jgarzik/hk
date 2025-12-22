//! Process tests
//!
//! Tests 4-21 covering:
//! - getpid, nanosleep, clock_nanosleep
//! - getppid, getpgid, getsid, setsid
//! - clone, fork, vfork
//! - waitid, execve

use super::helpers::{print, println, print_num};
use crate::syscall::{
    sys_brk, sys_clock_getres, sys_clock_nanosleep, sys_clone, sys_execve, sys_exit, sys_fork,
    sys_getcpu, sys_getegid, sys_geteuid, sys_getgid, sys_getpgid, sys_getpid, sys_getppid,
    sys_getpriority, sys_getresgid, sys_getresuid, sys_getrusage, sys_getsid, sys_gettid,
    sys_getuid, sys_ioprio_get, sys_ioprio_set, sys_nanosleep, sys_sched_getaffinity,
    sys_sched_getparam, sys_sched_getscheduler, sys_sched_rr_get_interval, sys_sched_setaffinity,
    sys_sched_setparam, sys_sched_setscheduler, sys_set_tid_address, sys_setfsgid, sys_setfsuid,
    sys_setgid, sys_setpriority, sys_setregid, sys_setresgid, sys_setresuid, sys_setreuid,
    sys_setsid, sys_setuid, sys_sysinfo, sys_vfork, sys_wait4, sys_waitid, ioprio_prio_value,
    SchedParam, SigInfo, Timespec, CLOCK_MONOTONIC, CLOCK_REALTIME, CLONE_VM, IOPRIO_CLASS_BE,
    IOPRIO_WHO_PROCESS, P_ALL, P_PID, PRIO_PROCESS, SCHED_NORMAL, SCHED_RR, WEXITED,
};
#[cfg(target_arch = "x86_64")]
use crate::syscall::sys_time;
#[cfg(target_arch = "x86_64")]
use crate::syscall::{sys_arch_prctl, ARCH_SET_FS, ARCH_GET_FS};

/// Run all process tests
pub fn run_tests() {
    test_getpid();
    test_nanosleep();
    test_clock_nanosleep();
    test_getppid();
    test_getpgid();
    test_getsid();
    test_getpgid_explicit();
    test_getsid_explicit();
    test_getpgid_esrch();
    test_getsid_esrch();
    test_setsid_eperm();
    test_clone();
    test_fork();
    test_fork_memory_isolation();
    test_vfork();
    test_waitid();
    test_waitid_pall();
    test_execve();
    test_getuid();
    test_geteuid();
    test_getgid();
    test_getegid();
    test_clock_getres();
    #[cfg(target_arch = "x86_64")]
    test_time();
    test_getcpu();
    test_getcpu_null();
    test_getpriority();
    test_setpriority();
    test_getpriority_esrch();
    test_setuid();
    test_setgid();
    test_getresuid();
    test_getresgid();
    test_setresuid();
    test_setresgid();
    test_setreuid();
    test_setregid();
    test_setfsuid();
    test_setfsgid();
    // System information syscalls
    test_sysinfo();
    test_getrusage();
    test_getrusage_einval();
    // Scheduling syscalls
    test_sched_getscheduler();
    test_sched_getparam();
    test_sched_getaffinity();
    test_sched_setaffinity();
    test_sched_rr_get_interval();
    test_sched_getscheduler_esrch();
    // Memory management syscalls
    test_brk_query();
    test_brk_expand();
    test_brk_shrink();
    // I/O priority syscalls
    test_ioprio_get_set();
    // TLS syscalls
    #[cfg(target_arch = "x86_64")]
    test_arch_prctl();
    test_set_tid_address();
}

/// Test 4: getpid syscall
fn test_getpid() {
    let pid = sys_getpid();
    print(b"getpid() = ");
    print_num(pid);
    if pid == 1 {
        println(b"GETPID:OK");
    } else {
        println(b"GETPID:FAIL");
    }
}

/// Test 5: nanosleep syscall
fn test_nanosleep() {
    let req = Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000, // 100ms
    };
    let ret = sys_nanosleep(&req, core::ptr::null_mut());
    if ret == 0 {
        println(b"NANOSLEEP:OK");
    } else {
        print(b"NANOSLEEP:FAIL ");
        print_num(ret);
    }
}

/// Test 6: clock_nanosleep syscall
fn test_clock_nanosleep() {
    let req = Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000, // 100ms
    };
    let ret = sys_clock_nanosleep(CLOCK_MONOTONIC, 0, &req, core::ptr::null_mut());
    if ret == 0 {
        println(b"CLOCK_NANOSLEEP:OK");
    } else {
        print(b"CLOCK_NANOSLEEP:FAIL ");
        print_num(ret);
    }
}

/// Test 7: getppid syscall
fn test_getppid() {
    let ppid = sys_getppid();
    print(b"getppid() = ");
    print_num(ppid);
    // Init process (PID 1) should have ppid=0 (no parent)
    if ppid == 0 {
        println(b"GETPPID:OK");
    } else {
        println(b"GETPPID:FAIL");
    }
}

/// Test 8: getpgid syscall
fn test_getpgid() {
    let pgid = sys_getpgid(0);
    print(b"getpgid(0) = ");
    print_num(pgid);
    // Init process should be its own process group leader
    if pgid == 1 {
        println(b"GETPGID:OK");
    } else {
        println(b"GETPGID:FAIL");
    }
}

/// Test 9: getsid syscall
fn test_getsid() {
    let sid = sys_getsid(0);
    print(b"getsid(0) = ");
    print_num(sid);
    // Init process should be session leader
    if sid == 1 {
        println(b"GETSID:OK");
    } else {
        println(b"GETSID:FAIL");
    }
}

/// Test 10: getpgid with explicit PID
fn test_getpgid_explicit() {
    let pgid_explicit = sys_getpgid(1);
    print(b"getpgid(1) = ");
    print_num(pgid_explicit);
    if pgid_explicit == 1 {
        println(b"GETPGID_EXPLICIT:OK");
    } else {
        println(b"GETPGID_EXPLICIT:FAIL");
    }
}

/// Test 11: getsid with explicit PID
fn test_getsid_explicit() {
    let sid_explicit = sys_getsid(1);
    print(b"getsid(1) = ");
    print_num(sid_explicit);
    if sid_explicit == 1 {
        println(b"GETSID_EXPLICIT:OK");
    } else {
        println(b"GETSID_EXPLICIT:FAIL");
    }
}

/// Test 12: getpgid with invalid PID
fn test_getpgid_esrch() {
    let pgid_invalid = sys_getpgid(999);
    print(b"getpgid(999) = ");
    print_num(pgid_invalid);
    if pgid_invalid == -3 {
        // ESRCH
        println(b"GETPGID_ESRCH:OK");
    } else {
        println(b"GETPGID_ESRCH:FAIL");
    }
}

/// Test 13: getsid with invalid PID
fn test_getsid_esrch() {
    let sid_invalid = sys_getsid(999);
    print(b"getsid(999) = ");
    print_num(sid_invalid);
    if sid_invalid == -3 {
        // ESRCH
        println(b"GETSID_ESRCH:OK");
    } else {
        println(b"GETSID_ESRCH:FAIL");
    }
}

/// Test 14: setsid (should fail because init is already process group leader)
fn test_setsid_eperm() {
    let setsid_ret = sys_setsid();
    print(b"setsid() = ");
    print_num(setsid_ret);
    // setsid should fail with EPERM (-1)
    if setsid_ret == -1 {
        println(b"SETSID_EPERM:OK");
    } else {
        println(b"SETSID_EPERM:FAIL");
    }
}

/// Test 15: clone(CLONE_VM) - thread creation
fn test_clone() {

    // Static child stack (must be outside function stack frame)
    #[repr(C, align(16))]
    struct ChildStack([u8; 4096]);
    static mut CHILD_STACK: ChildStack = ChildStack([0; 4096]);
    let stack_base = core::ptr::addr_of_mut!(CHILD_STACK) as *mut u8;
    let stack_top = unsafe { stack_base.add(4096) as u64 };

    // Static variable for child to signal completion
    static mut CHILD_DONE: i32 = 0;
    let child_done_ptr = core::ptr::addr_of_mut!(CHILD_DONE);

    let parent_tid = sys_gettid();
    print(b"Parent TID: ");
    print_num(parent_tid);

    let clone_ret = sys_clone(CLONE_VM, stack_top, 0, 0, 0);
    if clone_ret < 0 {
        print(b"clone() failed: ");
        print_num(clone_ret);
        println(b"CLONE:FAIL");
    } else if clone_ret == 0 {
        // Child thread
        println(b"CHILD: Hello from child thread!");
        let child_tid = sys_gettid();
        print(b"CHILD: My TID is ");
        print_num(child_tid);

        unsafe {
            core::ptr::write_volatile(child_done_ptr, 42);
        }
        sys_exit(42);
    } else {
        // Parent
        print(b"Parent: clone() returned child TID=");
        print_num(clone_ret);

        let mut wstatus: i32 = 0;
        let wait_ret = sys_wait4(-1, &mut wstatus, 0, 0);
        print(b"Parent: wait4() returned ");
        print_num(wait_ret);
        print(b", wstatus=");
        print_num(wstatus as i64);

        let child_done = unsafe { core::ptr::read_volatile(child_done_ptr) };
        print(b"Parent: CHILD_DONE = ");
        print_num(child_done as i64);

        let exit_status = (wstatus >> 8) & 0xff;
        if wait_ret == clone_ret && exit_status == 42 && child_done == 42 {
            println(b"CLONE:OK");
        } else {
            println(b"CLONE:FAIL");
        }
    }
}

/// Test 16: fork() - process creation with separate address space
fn test_fork() {

    let fork_ret = sys_fork();
    if fork_ret < 0 {
        print(b"fork() failed: ");
        print_num(fork_ret);
        println(b"FORK:FAIL");
    } else if fork_ret == 0 {
        // Child process
        println(b"FORK_CHILD: Hello from forked child!");
        let child_pid = sys_getpid();
        print(b"FORK_CHILD: My PID is ");
        print_num(child_pid);
        let child_ppid = sys_getppid();
        print(b"FORK_CHILD: My parent PID is ");
        print_num(child_ppid);
        sys_exit(99);
    } else {
        // Parent
        print(b"Parent: fork() returned child PID=");
        print_num(fork_ret);

        let mut wstatus: i32 = 0;
        let wait_ret = sys_wait4(fork_ret, &mut wstatus, 0, 0);
        print(b"Parent: wait4() returned ");
        print_num(wait_ret);
        print(b", wstatus=");
        print_num(wstatus as i64);

        let exit_status = (wstatus >> 8) & 0xff;
        if wait_ret == fork_ret && exit_status == 99 {
            println(b"FORK:OK");
        } else {
            println(b"FORK:FAIL");
        }
    }
}

/// Test 17: fork() memory isolation
fn test_fork_memory_isolation() {

    static mut FORK_TEST_VAR: i32 = 100;
    let fork_test_var_ptr = core::ptr::addr_of_mut!(FORK_TEST_VAR);

    let fork_ret2 = sys_fork();
    if fork_ret2 < 0 {
        print(b"fork() failed: ");
        print_num(fork_ret2);
        println(b"FORK_MEMORY_ISOLATION_FAILED");
    } else if fork_ret2 == 0 {
        // Child process - modify memory
        unsafe {
            core::ptr::write_volatile(fork_test_var_ptr, 200);
        }
        let val = unsafe { core::ptr::read_volatile(fork_test_var_ptr) };
        print_num(val as i64);
        sys_exit(0);
    } else {
        // Parent - wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(fork_ret2, &mut wstatus, 0, 0);

        let parent_val = unsafe { core::ptr::read_volatile(fork_test_var_ptr) };
        print(b"Parent: FORK_TEST_VAR = ");
        print_num(parent_val as i64);

        if parent_val == 100 {
            println(b"FORK_MEMORY_ISOLATION_PASSED");
        } else {
            println(b"FORK_MEMORY_ISOLATION_FAILED");
        }
    }
}

/// Test 18: vfork() - process creation with shared address space until exec/exit
fn test_vfork() {

    let vfork_ret = sys_vfork();
    if vfork_ret < 0 {
        print(b"vfork() failed: ");
        print_num(vfork_ret);
        println(b"VFORK:FAIL");
    } else if vfork_ret == 0 {
        // Child process - must call _exit or exec immediately
        sys_exit(77);
    } else {
        // Parent (resumed after child exits or execs)
        print(b"Parent: vfork() returned child PID=");
        print_num(vfork_ret);

        let mut wstatus: i32 = 0;
        let wait_ret = sys_wait4(vfork_ret, &mut wstatus, 0, 0);
        print(b"Parent: wait4() returned ");
        print_num(wait_ret);
        print(b", wstatus=");
        print_num(wstatus as i64);

        let exit_status = (wstatus >> 8) & 0xff;
        if wait_ret == vfork_ret && exit_status == 77 {
            println(b"VFORK:OK");
        } else {
            println(b"VFORK:FAIL");
        }
    }
}

/// Test 19: waitid() - alternative wait interface
fn test_waitid() {

    let fork_ret3 = sys_fork();
    if fork_ret3 < 0 {
        print(b"fork() failed: ");
        print_num(fork_ret3);
        println(b"WAITID:FAIL");
    } else if fork_ret3 == 0 {
        // Child process
        println(b"WAITID_CHILD: Hello from child!");
        sys_exit(55);
    } else {
        // Parent - use waitid instead of wait4
        print(b"Parent: fork() returned child PID=");
        print_num(fork_ret3);

        let mut info = SigInfo {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            si_pid: 0,
            si_uid: 0,
            si_status: 0,
            _pad: [0; 128 - 28],
        };

        let waitid_ret = sys_waitid(P_PID, fork_ret3 as u64, &mut info, WEXITED);
        print(b"Parent: waitid() returned ");
        print_num(waitid_ret);

        if waitid_ret == 0 {
            print(b"  si_pid=");
            print_num(info.si_pid as i64);
            print(b"  si_status=");
            print_num(info.si_status as i64);

            if info.si_pid == fork_ret3 as i32 && info.si_status == 55 {
                println(b"WAITID:OK");
            } else {
                println(b"WAITID:FAIL");
            }
        } else {
            println(b"WAITID:FAIL");
        }
    }
}

/// Test 20: waitid with P_ALL - wait for any child
fn test_waitid_pall() {

    let fork_ret4 = sys_fork();
    if fork_ret4 < 0 {
        print(b"fork() failed: ");
        print_num(fork_ret4);
        println(b"WAITID_PALL:FAIL");
    } else if fork_ret4 == 0 {
        // Child process
        sys_exit(33);
    } else {
        // Parent - use waitid with P_ALL
        let mut info = SigInfo {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            si_pid: 0,
            si_uid: 0,
            si_status: 0,
            _pad: [0; 128 - 28],
        };

        let waitid_ret = sys_waitid(P_ALL, 0, &mut info, WEXITED);
        print(b"Parent: waitid(P_ALL) returned ");
        print_num(waitid_ret);

        if waitid_ret == 0 {
            print(b"  si_pid=");
            print_num(info.si_pid as i64);
            print(b"  si_status=");
            print_num(info.si_status as i64);

            if info.si_pid == fork_ret4 as i32 && info.si_status == 33 {
                println(b"WAITID_PALL:OK");
            } else {
                println(b"WAITID_PALL:FAIL");
            }
        } else {
            println(b"WAITID_PALL:FAIL");
        }
    }
}

/// Test 21: execve() - execute a new program
fn test_execve() {

    let fork_ret5 = sys_fork();
    if fork_ret5 < 0 {
        print(b"fork() failed: ");
        print_num(fork_ret5);
        println(b"EXECVE:FAIL");
    } else if fork_ret5 == 0 {
        // Child process - exec boot_tester2
        println(b"EXECVE_CHILD: About to exec /bin/boot_tester2");

        let pathname = b"/bin/boot_tester2\0";
        let arg0 = b"boot_tester2\0";
        let argv: [*const u8; 2] = [arg0.as_ptr(), core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];

        let exec_ret = sys_execve(pathname.as_ptr(), argv.as_ptr(), envp.as_ptr());

        // If we get here, execve failed
        print(b"EXECVE_CHILD: execve failed with ");
        print_num(exec_ret);
        sys_exit(1);
    } else {
        // Parent - wait for child
        print(b"Parent: fork() returned child PID=");
        print_num(fork_ret5);

        let mut wstatus: i32 = 0;
        let wait_ret = sys_wait4(fork_ret5, &mut wstatus, 0, 0);
        print(b"Parent: wait4() returned ");
        print_num(wait_ret);
        print(b", wstatus=");
        print_num(wstatus as i64);

        let exit_status = (wstatus >> 8) & 0xff;
        // boot_tester2 exits with status 123
        if wait_ret == fork_ret5 && exit_status == 123 {
            println(b"EXECVE:OK");
        } else {
            print(b"Expected exit status 123, got ");
            print_num(exit_status as i64);
            println(b"EXECVE:FAIL");
        }
    }
}

/// Test 22: getuid syscall
fn test_getuid() {
    let uid = sys_getuid();
    print(b"getuid() = ");
    print_num(uid);
    // All tasks run as root (uid=0)
    if uid == 0 {
        println(b"GETUID:OK");
    } else {
        println(b"GETUID:FAIL");
    }
}

/// Test 23: geteuid syscall
fn test_geteuid() {
    let euid = sys_geteuid();
    print(b"geteuid() = ");
    print_num(euid);
    // All tasks run as root (euid=0)
    if euid == 0 {
        println(b"GETEUID:OK");
    } else {
        println(b"GETEUID:FAIL");
    }
}

/// Test 24: getgid syscall
fn test_getgid() {
    let gid = sys_getgid();
    print(b"getgid() = ");
    print_num(gid);
    // All tasks run as root (gid=0)
    if gid == 0 {
        println(b"GETGID:OK");
    } else {
        println(b"GETGID:FAIL");
    }
}

/// Test 25: getegid syscall
fn test_getegid() {
    let egid = sys_getegid();
    print(b"getegid() = ");
    print_num(egid);
    // All tasks run as root (egid=0)
    if egid == 0 {
        println(b"GETEGID:OK");
    } else {
        println(b"GETEGID:FAIL");
    }
}

/// Test 26: clock_getres syscall
fn test_clock_getres() {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };

    // Test CLOCK_REALTIME
    let ret = sys_clock_getres(CLOCK_REALTIME, &mut ts);
    if ret != 0 || ts.tv_sec != 0 || ts.tv_nsec != 1 {
        println(b"CLOCK_GETRES_REALTIME:FAIL");
        return;
    }
    println(b"CLOCK_GETRES_REALTIME:OK");

    // Test CLOCK_MONOTONIC
    let ret = sys_clock_getres(CLOCK_MONOTONIC, &mut ts);
    if ret == 0 && ts.tv_sec == 0 && ts.tv_nsec == 1 {
        println(b"CLOCK_GETRES_MONOTONIC:OK");
    } else {
        println(b"CLOCK_GETRES_MONOTONIC:FAIL");
    }

    // Test NULL pointer (should succeed per POSIX - validates clock ID only)
    let ret = sys_clock_getres(CLOCK_REALTIME, core::ptr::null_mut());
    if ret == 0 {
        println(b"CLOCK_GETRES_NULL:OK");
    } else {
        println(b"CLOCK_GETRES_NULL:FAIL");
    }

    // Test invalid clock ID
    let ret = sys_clock_getres(999, &mut ts);
    if ret == -22 {
        // -EINVAL
        println(b"CLOCK_GETRES_EINVAL:OK");
    } else {
        println(b"CLOCK_GETRES_EINVAL:FAIL");
    }
}

/// Test 27: time() syscall (x86_64 only)
#[cfg(target_arch = "x86_64")]
fn test_time() {
    // Test with NULL pointer (just returns time)
    let ret = sys_time(core::ptr::null_mut());
    // Time should be positive and reasonable (after year 2020: > 1577836800)
    if ret > 1577836800 {
        println(b"TIME:OK");
    } else {
        print(b"TIME:FAIL: got ");
        print_num(ret);
        println(b"");
    }
}

/// Test 28: getcpu syscall - get CPU and NUMA node
fn test_getcpu() {
    let mut cpu: u32 = 0xFFFFFFFF;
    let mut node: u32 = 0xFFFFFFFF;

    // Test with both pointers
    let ret = sys_getcpu(&mut cpu, &mut node);
    // cpu should be < 16 (MAX_CPUS), node should be 0 (no NUMA support)
    if ret == 0 && cpu < 16 && node == 0 {
        println(b"GETCPU:OK");
    } else {
        print(b"GETCPU:FAIL ret=");
        print_num(ret);
        print(b" cpu=");
        print_num(cpu as i64);
        print(b" node=");
        print_num(node as i64);
        println(b"");
    }
}

/// Test 29: getcpu syscall with NULL pointers
fn test_getcpu_null() {
    // Test with NULL pointers (should succeed per Linux API)
    let ret = sys_getcpu(core::ptr::null_mut(), core::ptr::null_mut());
    if ret == 0 {
        println(b"GETCPU_NULL:OK");
    } else {
        print(b"GETCPU_NULL:FAIL ret=");
        print_num(ret);
        println(b"");
    }
}

/// Test 30: getpriority syscall - get current process priority
fn test_getpriority() {
    // Get priority of current process (who=0 means self)
    let prio = sys_getpriority(PRIO_PROCESS, 0);
    print(b"getpriority(PRIO_PROCESS, 0) = ");
    print_num(prio);

    // getpriority returns 20 - nice, where nice is 0 for default priority
    // So default priority returns 20
    // Allow range 1-40 which is valid for any nice value
    if prio > 0 && prio <= 40 {
        println(b"GETPRIORITY:OK");
    } else {
        println(b"GETPRIORITY:FAIL");
    }
}

/// Test 31: setpriority syscall - lower process priority (should succeed)
fn test_setpriority() {
    // First get current priority
    let old_prio = sys_getpriority(PRIO_PROCESS, 0);
    print(b"Old priority: ");
    print_num(old_prio);

    // Set to nice 5 (lower priority than default)
    // This should always succeed since we're lowering priority
    let ret = sys_setpriority(PRIO_PROCESS, 0, 5);
    if ret != 0 {
        print(b"setpriority failed: ");
        print_num(ret);
        println(b"SETPRIORITY:FAIL");
        return;
    }

    // Verify it changed - nice 5 -> getpriority returns 20 - 5 = 15
    let new_prio = sys_getpriority(PRIO_PROCESS, 0);
    print(b"New priority: ");
    print_num(new_prio);

    if new_prio == 15 {
        println(b"SETPRIORITY:OK");
    } else {
        print(b"Expected 15, got ");
        print_num(new_prio);
        println(b"SETPRIORITY:FAIL");
    }
}

/// Test 32: getpriority with invalid PID returns ESRCH
fn test_getpriority_esrch() {
    // Try to get priority of non-existent process
    let prio = sys_getpriority(PRIO_PROCESS, 99999);
    print(b"getpriority(PRIO_PROCESS, 99999) = ");
    print_num(prio);

    if prio == -3 {
        // -ESRCH
        println(b"GETPRIORITY_ESRCH:OK");
    } else {
        println(b"GETPRIORITY_ESRCH:FAIL");
    }
}

/// Test 33: setuid syscall - set user identity (as root, can change to any UID)
fn test_setuid() {
    // Fork to avoid dropping privileges in the parent
    let pid = sys_fork();
    if pid < 0 {
        print(b"SETUID:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child process - do the actual test
        let old_uid = sys_getuid();
        if old_uid != 0 {
            sys_exit(1); // Not root
        }

        // Change UID to 1000
        let ret = sys_setuid(1000);
        if ret != 0 {
            sys_exit(2); // setuid failed
        }

        // Verify UID changed
        let new_uid = sys_getuid();
        let new_euid = sys_geteuid();

        if new_uid == 1000 && new_euid == 1000 {
            sys_exit(0); // Success
        } else {
            sys_exit(3); // Verification failed
        }
    } else {
        // Parent - wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"SETUID:OK");
        } else {
            print(b"SETUID:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test 34: setgid syscall - set group identity (as root, can change to any GID)
fn test_setgid() {
    // Fork to avoid dropping privileges in the parent
    let pid = sys_fork();
    if pid < 0 {
        print(b"SETGID:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child process - do the actual test
        let old_gid = sys_getgid();
        if old_gid != 0 {
            sys_exit(1); // Not root group
        }

        // Change GID to 1000
        let ret = sys_setgid(1000);
        if ret != 0 {
            sys_exit(2); // setgid failed
        }

        // Verify GID changed
        let new_gid = sys_getgid();
        let new_egid = sys_getegid();

        if new_gid == 1000 && new_egid == 1000 {
            sys_exit(0); // Success
        } else {
            sys_exit(3); // Verification failed
        }
    } else {
        // Parent - wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"SETGID:OK");
        } else {
            print(b"SETGID:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test 35: getresuid syscall - get real, effective, and saved user IDs
fn test_getresuid() {
    let mut ruid: u32 = 0xdeadbeef;
    let mut euid: u32 = 0xdeadbeef;
    let mut suid: u32 = 0xdeadbeef;

    let ret = sys_getresuid(&mut ruid, &mut euid, &mut suid);
    if ret != 0 {
        print(b"GETRESUID:FAIL ret=");
        print_num(ret);
        println(b"");
    } else if ruid == 0 && euid == 0 && suid == 0 {
        // As root, all UIDs should be 0
        println(b"GETRESUID:OK");
    } else {
        print(b"GETRESUID:FAIL uid=");
        print_num(ruid as i64);
        print(b" euid=");
        print_num(euid as i64);
        print(b" suid=");
        print_num(suid as i64);
        println(b"");
    }
}

/// Test 36: getresgid syscall - get real, effective, and saved group IDs
fn test_getresgid() {
    let mut rgid: u32 = 0xdeadbeef;
    let mut egid: u32 = 0xdeadbeef;
    let mut sgid: u32 = 0xdeadbeef;

    let ret = sys_getresgid(&mut rgid, &mut egid, &mut sgid);
    if ret != 0 {
        print(b"GETRESGID:FAIL ret=");
        print_num(ret);
        println(b"");
    } else if rgid == 0 && egid == 0 && sgid == 0 {
        // As root, all GIDs should be 0
        println(b"GETRESGID:OK");
    } else {
        print(b"GETRESGID:FAIL gid=");
        print_num(rgid as i64);
        print(b" egid=");
        print_num(egid as i64);
        print(b" sgid=");
        print_num(sgid as i64);
        println(b"");
    }
}

/// Test 37: setresuid syscall - set real, effective, and saved user IDs
fn test_setresuid() {
    // Fork to avoid dropping privileges in the parent
    let pid = sys_fork();
    if pid < 0 {
        print(b"SETRESUID:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child process - test setresuid with -1 (no change) for some fields
        // Set only euid to 1000, leave uid and suid unchanged
        const NO_CHANGE: u32 = 0xFFFFFFFF;
        let ret = sys_setresuid(NO_CHANGE, 1000, NO_CHANGE);
        if ret != 0 {
            sys_exit(1); // setresuid failed
        }

        // Verify: uid should be 0, euid should be 1000, suid should be 0
        let mut ruid: u32 = 0;
        let mut euid: u32 = 0;
        let mut suid: u32 = 0;
        let ret2 = sys_getresuid(&mut ruid, &mut euid, &mut suid);
        if ret2 != 0 {
            sys_exit(2); // getresuid failed
        }

        if ruid == 0 && euid == 1000 && suid == 0 {
            sys_exit(0); // Success
        } else {
            sys_exit(3); // Verification failed
        }
    } else {
        // Parent - wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"SETRESUID:OK");
        } else {
            print(b"SETRESUID:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test 38: setresgid syscall - set real, effective, and saved group IDs
fn test_setresgid() {
    // Fork to avoid dropping privileges in the parent
    let pid = sys_fork();
    if pid < 0 {
        print(b"SETRESGID:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child process - test setresgid with -1 (no change) for some fields
        // Set only egid to 2000, leave gid and sgid unchanged
        const NO_CHANGE: u32 = 0xFFFFFFFF;
        let ret = sys_setresgid(NO_CHANGE, 2000, NO_CHANGE);
        if ret != 0 {
            sys_exit(1); // setresgid failed
        }

        // Verify: gid should be 0, egid should be 2000, sgid should be 0
        let mut rgid: u32 = 0;
        let mut egid: u32 = 0;
        let mut sgid: u32 = 0;
        let ret2 = sys_getresgid(&mut rgid, &mut egid, &mut sgid);
        if ret2 != 0 {
            sys_exit(2); // getresgid failed
        }

        if rgid == 0 && egid == 2000 && sgid == 0 {
            sys_exit(0); // Success
        } else {
            sys_exit(3); // Verification failed
        }
    } else {
        // Parent - wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"SETRESGID:OK");
        } else {
            print(b"SETRESGID:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test 39: setreuid syscall - set real and effective user IDs
fn test_setreuid() {
    // Fork to avoid dropping privileges in the parent
    let pid = sys_fork();
    if pid < 0 {
        print(b"SETREUID:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child process - test setreuid with -1 (no change) for ruid
        // Set only euid to 1000, leave ruid unchanged
        const NO_CHANGE: u32 = 0xFFFFFFFF;
        let ret = sys_setreuid(NO_CHANGE, 1000);
        if ret != 0 {
            sys_exit(1); // setreuid failed
        }

        // Verify: uid should be 0, euid should be 1000
        // suid should be 1000 (because euid changed to non-uid value)
        let mut ruid: u32 = 0;
        let mut euid: u32 = 0;
        let mut suid: u32 = 0;
        let ret2 = sys_getresuid(&mut ruid, &mut euid, &mut suid);
        if ret2 != 0 {
            sys_exit(2); // getresuid failed
        }

        if ruid == 0 && euid == 1000 && suid == 1000 {
            sys_exit(0); // Success
        } else {
            sys_exit(3); // Verification failed
        }
    } else {
        // Parent - wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"SETREUID:OK");
        } else {
            print(b"SETREUID:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test 40: setregid syscall - set real and effective group IDs
fn test_setregid() {
    // Fork to avoid dropping privileges in the parent
    let pid = sys_fork();
    if pid < 0 {
        print(b"SETREGID:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child process - test setregid with -1 (no change) for rgid
        // Set only egid to 2000, leave rgid unchanged
        const NO_CHANGE: u32 = 0xFFFFFFFF;
        let ret = sys_setregid(NO_CHANGE, 2000);
        if ret != 0 {
            sys_exit(1); // setregid failed
        }

        // Verify: gid should be 0, egid should be 2000
        // sgid should be 2000 (because egid changed to non-gid value)
        let mut rgid: u32 = 0;
        let mut egid: u32 = 0;
        let mut sgid: u32 = 0;
        let ret2 = sys_getresgid(&mut rgid, &mut egid, &mut sgid);
        if ret2 != 0 {
            sys_exit(2); // getresgid failed
        }

        if rgid == 0 && egid == 2000 && sgid == 2000 {
            sys_exit(0); // Success
        } else {
            sys_exit(3); // Verification failed
        }
    } else {
        // Parent - wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"SETREGID:OK");
        } else {
            print(b"SETREGID:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test 41: setfsuid syscall - set filesystem UID
fn test_setfsuid() {
    // setfsuid returns OLD value, not error code
    // Initial fsuid should be 0 (root)
    let old_fsuid = sys_setfsuid(1000);
    if old_fsuid != 0 {
        print(b"SETFSUID:FAIL expected old=0 got=");
        print_num(old_fsuid);
        println(b"");
        return;
    }

    // Now fsuid should be 1000, query returns 1000 (since we set it to 1000)
    let new_old = sys_setfsuid(0);
    if new_old != 1000 {
        print(b"SETFSUID:FAIL expected old=1000 got=");
        print_num(new_old);
        println(b"");
        return;
    }

    // Restore to 0 and verify
    let final_old = sys_setfsuid(0);
    if final_old != 0 {
        print(b"SETFSUID:FAIL restore expected old=0 got=");
        print_num(final_old);
        println(b"");
        return;
    }

    println(b"SETFSUID:OK");
}

/// Test 42: setfsgid syscall - set filesystem GID
fn test_setfsgid() {
    // setfsgid returns OLD value, not error code
    // Initial fsgid should be 0 (root)
    let old_fsgid = sys_setfsgid(2000);
    if old_fsgid != 0 {
        print(b"SETFSGID:FAIL expected old=0 got=");
        print_num(old_fsgid);
        println(b"");
        return;
    }

    // Now fsgid should be 2000, query returns 2000
    let new_old = sys_setfsgid(0);
    if new_old != 2000 {
        print(b"SETFSGID:FAIL expected old=2000 got=");
        print_num(new_old);
        println(b"");
        return;
    }

    // Restore to 0 and verify
    let final_old = sys_setfsgid(0);
    if final_old != 0 {
        print(b"SETFSGID:FAIL restore expected old=0 got=");
        print_num(final_old);
        println(b"");
        return;
    }

    println(b"SETFSGID:OK");
}

/// Test 43: sysinfo syscall - get system information
///
/// Linux sysinfo struct layout (112 bytes):
/// - offset 0: uptime (i64)
/// - offset 8: loads[3] (3 x u64)
/// - offset 32: totalram (u64)
/// - offset 40: freeram (u64)
/// - offset 48: sharedram (u64)
/// - offset 56: bufferram (u64)
/// - offset 64: totalswap (u64)
/// - offset 72: freeswap (u64)
/// - offset 80: procs (u16)
/// - offset 82: pad (u16)
/// - offset 84: [4 bytes implicit padding]
/// - offset 88: totalhigh (u64)
/// - offset 96: freehigh (u64)
/// - offset 104: mem_unit (u32)
/// - offset 108: [4 bytes implicit padding]
#[inline(never)]
fn test_sysinfo() {
    let mut buffer: [u8; 128] = [0; 128];
    let ret = sys_sysinfo(buffer.as_mut_ptr());
    if ret != 0 {
        println(b"SYSINFO:FAIL ret");
        return;
    }

    // Test 1: Read uptime
    let uptime = i64::from_ne_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3],
        buffer[4], buffer[5], buffer[6], buffer[7],
    ]);
    if uptime < 0 {
        println(b"SYSINFO:FAIL uptime");
        return;
    }

    // Test 2: Read procs (u16 at offset 80)
    let procs = u16::from_ne_bytes([buffer[80], buffer[81]]);
    if procs == 0 {
        println(b"SYSINFO:FAIL procs");
        return;
    }

    // Test 3: Read mem_unit (u32 at offset 104)
    let mem_unit = u32::from_ne_bytes([buffer[104], buffer[105], buffer[106], buffer[107]]);
    if mem_unit != 1 {
        println(b"SYSINFO:FAIL mem_unit");
        return;
    }

    println(b"SYSINFO:OK");
}

const RUSAGE_SELF: i32 = 0;

/// Test 44: getrusage syscall - get resource usage (RUSAGE_SELF)
///
/// Linux rusage struct layout (144 bytes):
/// - offset 0: ru_utime.tv_sec (i64)
/// - offset 8: ru_utime.tv_usec (i64)
/// - offset 16: ru_stime.tv_sec (i64)
/// - offset 24: ru_stime.tv_usec (i64)
/// - offset 32-136: various i64 resource counters (14 fields)
#[inline(never)]
fn test_getrusage() {
    // Use raw buffer of 160 bytes (more than 144 needed)
    let mut buffer: [u8; 160] = [0xff; 160]; // init to 0xff so we can detect changes

    let ret = sys_getrusage(RUSAGE_SELF, buffer.as_mut_ptr());
    if ret != 0 {
        print(b"GETRUSAGE:FAIL ret=");
        print_num(ret);
        println(b"");
        return;
    }

    // Verify ru_utime.tv_sec (i64 at offset 0) is >= 0
    let utime_sec = i64::from_ne_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3],
        buffer[4], buffer[5], buffer[6], buffer[7],
    ]);
    if utime_sec < 0 {
        println(b"GETRUSAGE:FAIL utime");
        return;
    }

    println(b"GETRUSAGE:OK");
}

/// Test 45: getrusage syscall - test EINVAL for invalid who
#[inline(never)]
fn test_getrusage_einval() {
    let mut buffer: [u8; 160] = [0; 160];

    // Invalid who value (not 0, -1, or 1)
    let ret = sys_getrusage(99, buffer.as_mut_ptr());
    if ret != -22 {
        // -22 = -EINVAL
        print(b"GETRUSAGE_EINVAL:FAIL expected -22 got=");
        print_num(ret);
        println(b"");
        return;
    }

    println(b"GETRUSAGE_EINVAL:OK");
}

// =============================================================================
// Scheduling syscall tests
// =============================================================================

/// Test 46: sched_getscheduler syscall - get scheduling policy
#[inline(never)]
fn test_sched_getscheduler() {
    // Get policy of current process (pid=0 means self)
    let policy = sys_sched_getscheduler(0);
    print(b"sched_getscheduler(0) = ");
    print_num(policy);

    // Default policy should be SCHED_NORMAL (0)
    if policy == SCHED_NORMAL as i64 {
        println(b"SCHED_GETSCHEDULER:OK");
    } else if policy < 0 {
        print(b"SCHED_GETSCHEDULER:FAIL errno=");
        print_num(-policy);
        println(b"");
    } else {
        println(b"SCHED_GETSCHEDULER:FAIL unexpected policy");
    }
}

/// Test 47: sched_getparam syscall - get scheduling parameters
#[inline(never)]
fn test_sched_getparam() {
    let mut param = SchedParam { sched_priority: -1 };

    // Get params of current process (pid=0 means self)
    let ret = sys_sched_getparam(0, &mut param);
    print(b"sched_getparam(0) = ");
    print_num(ret);
    print(b", priority=");
    print_num(param.sched_priority as i64);

    // For SCHED_NORMAL, priority should be 0
    if ret == 0 && param.sched_priority == 0 {
        println(b"SCHED_GETPARAM:OK");
    } else if ret < 0 {
        print(b"SCHED_GETPARAM:FAIL errno=");
        print_num(-ret);
        println(b"");
    } else {
        println(b"SCHED_GETPARAM:FAIL unexpected priority");
    }
}

/// Test 48: sched_getaffinity syscall - get CPU affinity mask
#[inline(never)]
fn test_sched_getaffinity() {
    let mut mask: u64 = 0;

    // Get affinity of current process (pid=0 means self)
    let ret = sys_sched_getaffinity(0, 8, &mut mask);
    print(b"sched_getaffinity(0) = ");
    print_num(ret);
    print(b", mask=");
    print_num(mask as i64);

    // Should return 8 (size of mask) and mask should have at least one CPU
    if ret == 8 && mask != 0 {
        println(b"SCHED_GETAFFINITY:OK");
    } else if ret < 0 {
        print(b"SCHED_GETAFFINITY:FAIL errno=");
        print_num(-ret);
        println(b"");
    } else {
        println(b"SCHED_GETAFFINITY:FAIL");
    }
}

/// Test 49: sched_setaffinity syscall - set CPU affinity mask
#[inline(never)]
fn test_sched_setaffinity() {
    // First get current affinity
    let mut original_mask: u64 = 0;
    let get_ret = sys_sched_getaffinity(0, 8, &mut original_mask);
    if get_ret < 0 {
        print(b"SCHED_SETAFFINITY:FAIL getaffinity errno=");
        print_num(-get_ret);
        println(b"");
        return;
    }

    // Set affinity to CPU 0 only
    let new_mask: u64 = 1;
    let set_ret = sys_sched_setaffinity(0, 8, &new_mask);
    if set_ret != 0 {
        print(b"SCHED_SETAFFINITY:FAIL setaffinity errno=");
        print_num(-set_ret);
        println(b"");
        return;
    }

    // Verify it changed
    let mut verify_mask: u64 = 0;
    let verify_ret = sys_sched_getaffinity(0, 8, &mut verify_mask);
    if verify_ret < 0 || verify_mask != 1 {
        println(b"SCHED_SETAFFINITY:FAIL verification");
        // Restore original
        sys_sched_setaffinity(0, 8, &original_mask);
        return;
    }

    // Restore original affinity
    sys_sched_setaffinity(0, 8, &original_mask);
    println(b"SCHED_SETAFFINITY:OK");
}

/// Test 50: sched_rr_get_interval syscall - get round-robin time quantum
#[inline(never)]
fn test_sched_rr_get_interval() {
    let mut ts = Timespec { tv_sec: -1, tv_nsec: -1 };

    // Get interval for current process (should return 0 for SCHED_NORMAL)
    let ret = sys_sched_rr_get_interval(0, &mut ts);
    print(b"sched_rr_get_interval(0) = ");
    print_num(ret);
    print(b", sec=");
    print_num(ts.tv_sec);
    print(b", nsec=");
    print_num(ts.tv_nsec);

    // For SCHED_NORMAL, interval should be 0
    if ret == 0 && ts.tv_sec == 0 && ts.tv_nsec == 0 {
        println(b"SCHED_RR_GET_INTERVAL:OK");
    } else if ret < 0 {
        print(b"SCHED_RR_GET_INTERVAL:FAIL errno=");
        print_num(-ret);
        println(b"");
    } else {
        println(b"SCHED_RR_GET_INTERVAL:FAIL unexpected interval");
    }
}

/// Test 51: sched_getscheduler with invalid PID returns ESRCH
#[inline(never)]
fn test_sched_getscheduler_esrch() {
    // Try to get scheduler of non-existent process
    let ret = sys_sched_getscheduler(99999);
    print(b"sched_getscheduler(99999) = ");
    print_num(ret);

    if ret == -3 {
        // -ESRCH
        println(b"SCHED_GETSCHEDULER_ESRCH:OK");
    } else {
        println(b"SCHED_GETSCHEDULER_ESRCH:FAIL");
    }
}

// =============================================================================
// Memory management syscall tests
// =============================================================================

/// Test 52: brk syscall - query current program break
#[inline(never)]
fn test_brk_query() {
    // brk(0) returns current program break
    let current = sys_brk(0);
    print(b"brk(0) = ");
    print_num(current);

    // Should return non-zero (initial brk set by ELF loader, typically > 2GB for PIE)
    if current > 0 {
        println(b"BRK_QUERY:OK");
    } else {
        println(b"BRK_QUERY:FAIL");
    }
}

/// Test 53: brk syscall - expand heap
#[inline(never)]
fn test_brk_expand() {
    // Get current brk
    let current = sys_brk(0);
    if current <= 0 {
        println(b"BRK_EXPAND:FAIL (query failed)");
        return;
    }

    // Try to expand by one page
    let new_brk = (current as u64) + 4096;
    let result = sys_brk(new_brk);
    print(b"brk(current + 4096) = ");
    print_num(result);

    if result == new_brk as i64 {
        // Write to the new memory to verify it works (will page fault and allocate)
        let test_addr = current as *mut u8;
        unsafe {
            core::ptr::write_volatile(test_addr, 42);
            let read_back = core::ptr::read_volatile(test_addr);
            if read_back == 42 {
                println(b"BRK_EXPAND:OK");
            } else {
                println(b"BRK_EXPAND:FAIL (write verification)");
            }
        }
    } else {
        println(b"BRK_EXPAND:FAIL");
    }
}

/// Test 54: brk syscall - shrink heap
#[inline(never)]
fn test_brk_shrink() {
    // Get current brk
    let original = sys_brk(0);
    if original <= 0 {
        println(b"BRK_SHRINK:FAIL (query failed)");
        return;
    }

    // Expand first
    let expanded = sys_brk((original as u64) + 8192);
    if expanded != (original as u64 + 8192) as i64 {
        println(b"BRK_SHRINK:FAIL (expand failed)");
        return;
    }

    // Shrink back to original
    let shrunk = sys_brk(original as u64);
    print(b"brk(original) = ");
    print_num(shrunk);

    if shrunk == original {
        println(b"BRK_SHRINK:OK");
    } else {
        println(b"BRK_SHRINK:FAIL");
    }
}

// =============================================================================
// I/O priority syscall tests
// =============================================================================

/// Test 55: ioprio_get/ioprio_set syscalls
#[inline(never)]
fn test_ioprio_get_set() {
    // Set I/O priority to IOPRIO_CLASS_BE with level 4
    let prio = ioprio_prio_value(IOPRIO_CLASS_BE, 4);
    let ret = sys_ioprio_set(IOPRIO_WHO_PROCESS, 0, prio as i32);
    if ret < 0 {
        print(b"IOPRIO:FAIL set ret=");
        print_num(ret);
        println(b"");
        return;
    }

    // Get I/O priority back
    let got = sys_ioprio_get(IOPRIO_WHO_PROCESS, 0);
    if got < 0 {
        print(b"IOPRIO:FAIL get ret=");
        print_num(got);
        println(b"");
        return;
    }

    // Verify it matches
    if got == prio as i64 {
        println(b"IOPRIO:OK");
    } else {
        print(b"IOPRIO:FAIL expected ");
        print_num(prio as i64);
        print(b" got ");
        print_num(got);
        println(b"");
    }
}

// =============================================================================
// TLS syscall tests
// =============================================================================

/// Test 56: arch_prctl syscall (x86_64 only) - set/get FS base
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn test_arch_prctl() {
    // Set FS base to a test value
    let test_addr: u64 = 0x12345678_ABCD0000;
    let ret = sys_arch_prctl(ARCH_SET_FS, test_addr);
    if ret != 0 {
        print(b"ARCH_PRCTL_SET:FAIL ret=");
        print_num(ret);
        println(b"");
        return;
    }
    println(b"ARCH_PRCTL_SET:OK");

    // Get FS base and verify
    let mut retrieved: u64 = 0;
    let ret = sys_arch_prctl(ARCH_GET_FS, &mut retrieved as *mut u64 as u64);
    if ret != 0 {
        print(b"ARCH_PRCTL_GET:FAIL ret=");
        print_num(ret);
        println(b"");
        return;
    }

    if retrieved == test_addr {
        println(b"ARCH_PRCTL_GET:OK");
    } else {
        print(b"ARCH_PRCTL_GET:FAIL expected ");
        print_num(test_addr as i64);
        print(b" got ");
        print_num(retrieved as i64);
        println(b"");
    }

    // Clear FS base before continuing
    sys_arch_prctl(ARCH_SET_FS, 0);
}

/// Test 57: set_tid_address syscall - set clear_child_tid pointer
///
/// This syscall sets the address that will receive 0 when the thread exits,
/// and returns the caller's TID.
#[inline(never)]
fn test_set_tid_address() {
    let mut tid_storage: i32 = -1;
    let ret = sys_set_tid_address(&mut tid_storage as *mut i32);

    // set_tid_address returns the current TID
    // For init (PID 1), TID should also be 1
    if ret > 0 {
        print(b"set_tid_address() returned TID=");
        print_num(ret);
        println(b"SET_TID_ADDRESS:OK");
    } else {
        print(b"SET_TID_ADDRESS:FAIL ret=");
        print_num(ret);
        println(b"");
    }
}
