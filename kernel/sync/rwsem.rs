//! Sleeping reader/writer semaphore (Linux `struct rw_semaphore`)
//!
//! Many readers or one writer. Writer preference: once a writer waits,
//! new readers queue behind it, so a stream of readers cannot starve
//! writers. The count word is guarded by a short spin::Mutex (a leaf,
//! never held across a sleep); waiters sleep on one wait queue and are
//! all woken on release (their conditions differ, see LOCKING.md wait
//! queues).

use spin::Mutex as SpinMutex;

use super::{can_sleep, might_sleep};
use crate::waitqueue::WaitQueue;

#[derive(Default)]
struct Count {
    readers: u32,
    writer: bool,
    waiting_writers: u32,
}

/// Sleeping reader/writer lock (no data: guards what its owner says)
pub struct RwSem {
    count: SpinMutex<Count>,
    wq: WaitQueue,
}

impl Default for RwSem {
    fn default() -> Self {
        Self::new()
    }
}

impl RwSem {
    /// New unlocked semaphore
    pub const fn new() -> Self {
        Self {
            count: SpinMutex::new(Count {
                readers: 0,
                writer: false,
                waiting_writers: 0,
            }),
            wq: WaitQueue::new(),
        }
    }

    /// Sleep (or spin before scheduling) until `ok` might hold
    fn wait(&self, ok: impl Fn(&Count) -> bool) {
        if can_sleep() {
            self.wq.wait_event(|| ok(&self.count.lock()));
        } else {
            core::hint::spin_loop();
        }
    }

    /// Shared acquire (Linux down_read)
    pub fn down_read(&self) {
        might_sleep();
        let ok = |c: &Count| !c.writer && c.waiting_writers == 0;
        loop {
            {
                let mut c = self.count.lock();
                if ok(&c) {
                    c.readers += 1;
                    return;
                }
            }
            self.wait(ok);
        }
    }

    /// Release a shared hold (Linux up_read)
    ///
    /// # Safety
    /// The caller must hold the semaphore shared.
    pub unsafe fn up_read(&self) {
        let last = {
            let mut c = self.count.lock();
            c.readers -= 1;
            c.readers == 0
        };
        if last {
            self.wq.wake_all();
        }
    }

    /// Exclusive acquire (Linux down_write)
    pub fn down_write(&self) {
        might_sleep();
        let ok = |c: &Count| !c.writer && c.readers == 0;
        self.count.lock().waiting_writers += 1;
        loop {
            {
                let mut c = self.count.lock();
                if ok(&c) {
                    c.writer = true;
                    c.waiting_writers -= 1;
                    return;
                }
            }
            self.wait(ok);
        }
    }

    /// Release an exclusive hold (Linux up_write)
    ///
    /// # Safety
    /// The caller must hold the semaphore exclusively.
    pub unsafe fn up_write(&self) {
        self.count.lock().writer = false;
        self.wq.wake_all();
    }
}
