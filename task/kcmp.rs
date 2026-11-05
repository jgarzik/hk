//! kcmp syscall - Compare kernel resources between processes
//!
//! The kcmp syscall allows comparing kernel resources between two processes,
//! returning whether they refer to the same kernel object. Used by container
//! runtimes (Docker, CRIU) and process inspection tools.
//!
//! Returns:
//! - 0 if resources are equal (same pointer)
//! - 1 if first < second (pointer comparison)
//! - 2 if first > second
//! - Negative errno on error

use alloc::sync::Arc;
use core::cmp::Ordering;

use crate::task::Task;
use crate::task::percpu::{TASKLIST, task_ref};
use crate::util::error::KernelError;

// KCMP comparison types
/// Compare file descriptors
pub const KCMP_FILE: i32 = 0;
/// Compare memory address spaces (mm_struct)
pub const KCMP_VM: i32 = 1;
/// Compare file descriptor tables
pub const KCMP_FILES: i32 = 2;
/// Compare filesystem context (cwd, root)
pub const KCMP_FS: i32 = 3;
/// Compare signal handlers
pub const KCMP_SIGHAND: i32 = 4;
/// Compare I/O context
pub const KCMP_IO: i32 = 5;
/// Compare SysV semaphore undo lists
pub const KCMP_SYSVSEM: i32 = 6;
/// Compare epoll target fds (not implemented)
pub const KCMP_EPOLL_TFD: i32 = 7;
/// Number of comparison types
pub const KCMP_TYPES: i32 = 8;

/// Obfuscation cookies for pointer comparison (Linux kcmp_cookies): an
/// XOR value and an odd multiplier per type, made once (Linux fills them
/// in an initcall; here the first kcmp, serialized by the Once) and never
/// changed, so every comparison uses the same pair
static COOKIES: spin::Once<[[u64; 2]; KCMP_TYPES as usize]> = spin::Once::new();

fn cookies() -> &'static [[u64; 2]; KCMP_TYPES as usize] {
    COOKIES.call_once(|| {
        let mut c = [[0u64; 2]; KCMP_TYPES as usize];
        for pair in c.iter_mut() {
            let mut buf = [0u8; 16];
            let _ = crate::random::get_random_bytes(&mut buf, 0);
            let (x, m) = buf.split_at(8);
            pair[0] = u64::from_ne_bytes(x.try_into().unwrap_or_default());
            // Odd, so the product is a bijection modulo 2^64
            pair[1] = u64::from_ne_bytes(m.try_into().unwrap_or_default()) | 1 | (1u64 << 63);
        }
        c
    })
}

/// Obfuscate a kernel pointer for comparison
///
/// This prevents userspace from learning actual kernel pointer values
/// while still providing consistent ordering for sorting.
fn kptr_obfuscate(ptr: u64, kcmp_type: i32) -> u64 {
    let [xor_val, mult] = cookies()[kcmp_type as usize];
    (ptr ^ xor_val).wrapping_mul(mult)
}

/// Compare two pointers, returning kcmp result
///
/// Returns:
/// - 0 if equal
/// - 1 if ptr1 < ptr2 (obfuscated)
/// - 2 if ptr1 > ptr2 (obfuscated)
fn kcmp_ptr(ptr1: u64, ptr2: u64, kcmp_type: i32) -> i64 {
    let t1 = kptr_obfuscate(ptr1, kcmp_type);
    let t2 = kptr_obfuscate(ptr2, kcmp_type);

    match t1.cmp(&t2) {
        Ordering::Equal => 0,
        Ordering::Less => 1,
        Ordering::Greater => 2,
    }
}

/// The address of an optional shared object
fn ptr_key<T>(o: Option<&Arc<T>>) -> Option<u64> {
    o.map(|a| Arc::as_ptr(a) as *const () as u64)
}

fn arc_key<T>(o: &Option<Arc<T>>) -> Option<u64> {
    ptr_key(o.as_ref())
}

/// Compare two optional object addresses
fn compare_key(k1: Option<u64>, k2: Option<u64>, kcmp_type: i32) -> i64 {
    match (k1, k2) {
        (Some(ptr1), Some(ptr2)) => kcmp_ptr(ptr1, ptr2, kcmp_type),
        (None, None) => 0,    // Both None = equal
        (None, Some(_)) => 1, // None < Some
        (Some(_), None) => 2, // Some > None
    }
}

/// The address of `t`'s task_lock resource of kind `kcmp_type`
fn lock_key(t: &Task, kcmp_type: i32) -> Option<u64> {
    let a = t.task_lock();
    match kcmp_type {
        KCMP_VM => ptr_key(a.mm().map(|m| m.arc())),
        KCMP_FILES => ptr_key(a.files()),
        KCMP_FS => ptr_key(a.fs()),
        _ => ptr_key(a.io_context()),
    }
}

/// The address of the file at descriptor `idx` of `t`
fn fd_key(t: &Task, idx: u64) -> Option<u64> {
    let files = t.task_lock().files().cloned()?;
    let f = files.lock().get(idx as i32)?;
    Some(Arc::as_ptr(&f) as u64)
}

/// kcmp syscall implementation
///
/// Compare resources between two processes.
///
/// # Arguments
/// * `pid1` - First process ID
/// * `pid2` - Second process ID
/// * `kcmp_type` - Type of comparison (KCMP_*)
/// * `idx1` - First index (fd number for KCMP_FILE, unused otherwise)
/// * `idx2` - Second index (fd number for KCMP_FILE, unused otherwise)
///
/// # Returns
/// * 0 if resources are equal
/// * 1 if first < second
/// * 2 if first > second
/// * Negative errno on error
pub fn sys_kcmp(pid1: i32, pid2: i32, kcmp_type: i32, idx1: u64, idx2: u64) -> i64 {
    // pid_t: a negative one names no task (Linux find_task_by_vpid)
    if pid1 <= 0 || pid2 <= 0 {
        return KernelError::NoProcess.sysret();
    }
    let (pid1, pid2) = (pid1 as u64, pid2 as u64);
    // Initialize cookies on first use

    // Validate type
    if !(0..KCMP_TYPES).contains(&kcmp_type) {
        return KernelError::InvalidArgument.sysret();
    }

    // KCMP_EPOLL_TFD is not supported (requires complex epoll internals)
    if kcmp_type == KCMP_EPOLL_TFD {
        return KernelError::OperationNotSupported.sysret();
    }

    // Look up both tasks; the signal handlers and undo lists are read
    // under TASKLIST, the task_lock resources under each task's lock
    let (t1, t2, sigs, sems) = {
        let table = TASKLIST.read();
        let Some(task1) = table.get(pid1) else {
            return KernelError::NoProcess.sysret();
        };
        let Some(task2) = table.get(pid2) else {
            return KernelError::NoProcess.sysret();
        };
        (
            task_ref(task1.task),
            task_ref(task2.task),
            (arc_key(&task1.sighand), arc_key(&task2.sighand)),
            (arc_key(&task1.sysvsem), arc_key(&task2.sysvsem)),
        )
    };
    // Linux: ptrace_may_access(PTRACE_MODE_READ_REALCREDS) on both
    if !crate::task::ptrace::may_access_tid(t1.tid(), false)
        || !crate::task::ptrace::may_access_tid(t2.tid(), false)
    {
        return KernelError::NotPermitted.sysret();
    }

    match kcmp_type {
        KCMP_FILE => {
            // Compare specific file descriptors; the tables are locked
            // after task_lock is dropped
            let ptr1 = match fd_key(&t1, idx1) {
                Some(p) => p,
                None => return KernelError::BadFd.sysret(),
            };
            let ptr2 = match fd_key(&t2, idx2) {
                Some(p) => p,
                None => return KernelError::BadFd.sysret(),
            };
            kcmp_ptr(ptr1, ptr2, KCMP_FILE)
        }

        KCMP_SIGHAND => compare_key(sigs.0, sigs.1, KCMP_SIGHAND),
        KCMP_SYSVSEM => compare_key(sems.0, sems.1, KCMP_SYSVSEM),

        KCMP_VM | KCMP_FILES | KCMP_FS | KCMP_IO => compare_key(
            lock_key(&t1, kcmp_type),
            lock_key(&t2, kcmp_type),
            kcmp_type,
        ),

        _ => KernelError::InvalidArgument.sysret(),
    }
}
