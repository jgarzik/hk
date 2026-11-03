//! Flip buffers (Linux drivers/tty/tty_buffer.c)
//!
//! A UART interrupt handler queues received bytes in its tty's flip
//! buffer (`Tty.flip`, an IrqSpinlock ring) and pushes them
//! (`tty_flip_buffer_push`): the `ttyflip` kernel thread then feeds them
//! to the line discipline in thread context, where echo may write the
//! UART and signals may be sent (neither is possible in the handler).
//! Linux queues per-port work on a workqueue instead; hk's queue_work
//! is not IRQ-safe and one thread serves the few serial ports.

use core::sync::atomic::{AtomicBool, Ordering};

use super::{Tty, n_tty};
use crate::sync::waitqueue::WaitQueue;

/// Flip ring size; input beyond it before the thread runs is dropped
const FLIP_SIZE: usize = 1024;

/// A tty's received bytes not yet given to the line discipline
pub struct Flip {
    buf: [u8; FLIP_SIZE],
    head: usize,
    len: usize,
}

impl Flip {
    pub const fn new() -> Self {
        Self {
            buf: [0; FLIP_SIZE],
            head: 0,
            len: 0,
        }
    }

    fn insert(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.len == FLIP_SIZE {
                return;
            }
            self.buf[(self.head + self.len) % FLIP_SIZE] = b;
            self.len += 1;
        }
    }

    fn take(&mut self, out: &mut [u8]) -> usize {
        let n = self.len.min(out.len());
        for o in &mut out[..n] {
            *o = self.buf[self.head];
            self.head = (self.head + 1) % FLIP_SIZE;
        }
        self.len -= n;
        n
    }
}

impl Default for Flip {
    fn default() -> Self {
        Self::new()
    }
}

/// Some flip buffer has input (set by handlers, cleared by the thread)
static PENDING: AtomicBool = AtomicBool::new(false);

/// The flip thread sleeps here
static FLIP_WAIT: WaitQueue = WaitQueue::new();

/// Bytes the driver received, from its interrupt handler (Linux
/// tty_insert_flip_string + tty_flip_buffer_push)
pub fn receive(tty: &Tty, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    tty.flip.lock().insert(bytes);
    PENDING.store(true, Ordering::Release);
    FLIP_WAIT.wake_all();
}

/// Feed `tty`'s flip buffer to the line discipline (Linux
/// flush_to_ldisc); the flip thread is its only caller, so input stays
/// in order
fn flush_to_ldisc(tty: &Tty) {
    let mut chunk = [0u8; 256];
    loop {
        let n = tty.flip.lock().take(&mut chunk);
        if n == 0 {
            return;
        }
        n_tty::receive_buf(tty, &chunk[..n]);
    }
}

fn flip_thread(_: usize) {
    loop {
        // Kernel threads get no signals: this only returns on input
        let _ = FLIP_WAIT.wait_event_interruptible(|| PENDING.load(Ordering::Acquire));
        PENDING.store(false, Ordering::Release);
        for &tty in super::all() {
            flush_to_ldisc(tty);
        }
    }
}

/// Start the flip thread
pub fn init() {
    if let Err(e) = crate::task::kthread::kthread_run("ttyflip", flip_thread, 0, None) {
        crate::printkln!("tty: no flip thread: {:?}", e);
    }
}
