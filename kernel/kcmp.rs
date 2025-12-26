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
use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::task::percpu::TASK_TABLE;

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

// Error codes
const ESRCH: i64 = -3; // No such process
const EINVAL: i64 = -22; // Invalid argument
const EBADF: i64 = -9; // Bad file descriptor
const EOPNOTSUPP: i64 = -95; // Operation not supported

// Obfuscation cookies for pointer comparison (like Linux)
// Two cookies per type: XOR value and multiplier
static COOKIES: [[AtomicU64; 2]; KCMP_TYPES as usize] = [
    [AtomicU64::new(0), AtomicU64::new(0)],
    [AtomicU64::new(0), AtomicU64::new(0)],
    [AtomicU64::new(0), AtomicU64::new(0)],
    [AtomicU64::new(0), AtomicU64::new(0)],
    [AtomicU64::new(0), AtomicU64::new(0)],
    [AtomicU64::new(0), AtomicU64::new(0)],
    [AtomicU64::new(0), AtomicU64::new(0)],
    [AtomicU64::new(0), AtomicU64::new(0)],
];

static COOKIES_INITIALIZED: AtomicU64 = AtomicU64::new(0);

/// Initialize the obfuscation cookies using kernel random source
fn init_cookies() {
    if COOKIES_INITIALIZED.load(AtomicOrdering::Relaxed) != 0 {
        return;
    }

    // Use get_random_bytes to initialize cookies
    for cookie_pair in COOKIES.iter() {
        let mut buf = [0u8; 16];
        let _ = crate::random::get_random_bytes(&mut buf, 0);

        let xor_val = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
        let mut mult = u64::from_ne_bytes(buf[8..16].try_into().unwrap());

        // Ensure multiplier is odd (for unique products modulo 2^64)
        mult |= 1 | (1u64 << 63);

        cookie_pair[0].store(xor_val, AtomicOrdering::Relaxed);
        cookie_pair[1].store(mult, AtomicOrdering::Relaxed);
    }

    COOKIES_INITIALIZED.store(1, AtomicOrdering::Release);
}

/// Obfuscate a kernel pointer for comparison
///
/// This prevents userspace from learning actual kernel pointer values
/// while still providing consistent ordering for sorting.
fn kptr_obfuscate(ptr: u64, kcmp_type: i32) -> u64 {
    let idx = kcmp_type as usize;
    let xor_val = COOKIES[idx][0].load(AtomicOrdering::Relaxed);
    let mult = COOKIES[idx][1].load(AtomicOrdering::Relaxed);
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

/// Compare two Option<Arc<T>> pointers
fn compare_arc_option<T>(opt1: &Option<Arc<T>>, opt2: &Option<Arc<T>>, kcmp_type: i32) -> i64 {
    match (opt1, opt2) {
        (Some(arc1), Some(arc2)) => {
            let ptr1 = Arc::as_ptr(arc1) as *const () as u64;
            let ptr2 = Arc::as_ptr(arc2) as *const () as u64;
            kcmp_ptr(ptr1, ptr2, kcmp_type)
        }
        (None, None) => 0,    // Both None = equal
        (None, Some(_)) => 1, // None < Some
        (Some(_), None) => 2, // Some > None
    }
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
pub fn sys_kcmp(pid1: u64, pid2: u64, kcmp_type: i32, idx1: u64, idx2: u64) -> i64 {
    // Initialize cookies on first use
    init_cookies();

    // Validate type
    if !(0..KCMP_TYPES).contains(&kcmp_type) {
        return EINVAL;
    }

    // KCMP_EPOLL_TFD is not supported (requires complex epoll internals)
    if kcmp_type == KCMP_EPOLL_TFD {
        return EOPNOTSUPP;
    }

    // Look up both tasks and extract the resources we need
    let table = TASK_TABLE.lock();

    let task1 = match table.tasks.iter().find(|t| t.pid == pid1) {
        Some(t) => t,
        None => return ESRCH,
    };

    let task2 = match table.tasks.iter().find(|t| t.pid == pid2) {
        Some(t) => t,
        None => return ESRCH,
    };

    match kcmp_type {
        KCMP_FILE => {
            // Compare specific file descriptors
            let ptr1 = match &task1.files {
                Some(files) => {
                    let fd_table = files.lock();
                    match fd_table.get(idx1 as i32) {
                        Some(f) => Arc::as_ptr(&f) as u64,
                        None => return EBADF,
                    }
                }
                None => return EBADF,
            };

            let ptr2 = match &task2.files {
                Some(files) => {
                    let fd_table = files.lock();
                    match fd_table.get(idx2 as i32) {
                        Some(f) => Arc::as_ptr(&f) as u64,
                        None => return EBADF,
                    }
                }
                None => return EBADF,
            };

            kcmp_ptr(ptr1, ptr2, KCMP_FILE)
        }

        KCMP_VM => {
            // Compare memory address spaces
            compare_arc_option(&task1.mm, &task2.mm, KCMP_VM)
        }

        KCMP_FILES => {
            // Compare file descriptor tables
            compare_arc_option(&task1.files, &task2.files, KCMP_FILES)
        }

        KCMP_FS => {
            // Compare filesystem context
            compare_arc_option(&task1.fs, &task2.fs, KCMP_FS)
        }

        KCMP_SIGHAND => {
            // Compare signal handlers
            compare_arc_option(&task1.sighand, &task2.sighand, KCMP_SIGHAND)
        }

        KCMP_IO => {
            // Compare I/O context
            compare_arc_option(&task1.io_context, &task2.io_context, KCMP_IO)
        }

        KCMP_SYSVSEM => {
            // Compare SysV semaphore undo lists
            compare_arc_option(&task1.sysvsem, &task2.sysvsem, KCMP_SYSVSEM)
        }

        _ => EINVAL,
    }
}
