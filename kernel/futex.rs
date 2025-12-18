//! Minimal futex support for CLONE_CHILD_CLEARTID
//!
//! This provides just enough futex functionality to support pthread_join.
//! When a thread exits with CLONE_CHILD_CLEARTID set, we:
//! 1. Write 0 to the stored address
//! 2. Call futex_wake on that address to wake any pthread_join waiters
//!
//! A full futex implementation would include:
//! - FUTEX_WAIT: Block until address value changes
//! - FUTEX_WAKE: Wake waiters on address
//! - FUTEX_REQUEUE, FUTEX_PI variants, etc.
//!
//! For now, we only implement futex_wake since that's what CLONE_CHILD_CLEARTID needs.

use crate::waitqueue::WaitQueue;

/// Number of buckets in the futex wait hash table
const FUTEX_HASH_SIZE: usize = 256;

/// Global futex wait hash table
///
/// Maps futex addresses to wait queues. Uses a hash table for efficiency
/// rather than per-address wait queues.
static FUTEX_HASH_TABLE: [WaitQueue; FUTEX_HASH_SIZE] =
    [const { WaitQueue::new() }; FUTEX_HASH_SIZE];

/// Get the wait queue for a futex address
fn futex_wait_queue(uaddr: u64) -> &'static WaitQueue {
    let hash = uaddr as usize;
    let index = hash % FUTEX_HASH_SIZE;
    &FUTEX_HASH_TABLE[index]
}

/// Wake up to `num_wake` waiters on the futex at `uaddr`
///
/// This is called when a thread exits with CLONE_CHILD_CLEARTID to wake
/// any pthread_join waiters.
///
/// # Arguments
/// * `uaddr` - User address of the futex
/// * `num_wake` - Maximum number of waiters to wake (typically 1 for pthread_join)
///
/// # Returns
/// Number of waiters actually woken
pub fn futex_wake(uaddr: u64, num_wake: i32) -> i32 {
    if num_wake <= 0 {
        return 0;
    }

    let wq = futex_wait_queue(uaddr);

    // Wake up to num_wake waiters
    let mut woken = 0;
    for _ in 0..num_wake {
        if wq.wake_one() {
            woken += 1;
        } else {
            break;
        }
    }

    woken
}

/// Block waiting for a futex value change (not yet implemented)
///
/// This would be needed for full pthread_join support, where the waiting
/// thread calls futex(FUTEX_WAIT). For now, userspace may need to poll
/// or we can implement this later.
#[allow(dead_code)]
pub fn futex_wait(_uaddr: u64, _expected: i32, _timeout: Option<u64>) -> i32 {
    // TODO: Implement proper FUTEX_WAIT
    // For now, return -ENOSYS
    -38 // ENOSYS
}
