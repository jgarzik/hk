//! Kernel printk with buffering
//!
//! Implements Linux-style printk that always works:
//! - Messages are stored in a ring buffer
//! - When console is attached, buffer is flushed and new messages go directly
//! - Buffer provides dmesg-like access to boot messages
//!
//! ## Console Integration
//!
//! Printk uses the console subsystem (kernel/core/console.rs):
//! - Messages always go to the ring buffer first
//! - If consoles are registered, messages are also written to all consoles
//! - Call `flush()` after registering a console to output buffered messages
//!
//! ## SMP Locking
//!
//! Two locks are used to avoid deadlock while ensuring message atomicity:
//! - PRINTK: Protects the ring buffer (short hold time)
//! - OUTPUT_LOCK: Serializes console/serial writes (held during I/O)
//!
//! The output lock ensures entire messages are written atomically,
//! preventing interleaved output from multiple CPUs.
//!
//! ## Panic-Safe Output
//!
//! During panic, the normal locking path can deadlock if the panicking CPU
//! already holds OUTPUT_LOCK. The OOPS_IN_PROGRESS flag switches to
//! try_lock() with direct serial fallback.

use ::core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

use super::console;
use crate::arch::IrqSpinlock;

/// Output lock - serializes all console/serial writes
///
/// This is separate from PRINTK to:
/// 1. Allow buffering while another CPU writes to console
/// 2. Prevent deadlock if console code needs to log
///
/// Uses IrqSpinlock (not spin::Mutex) to be IRQ-safe - this prevents
/// deadlock when printk is called from interrupt context while another
/// CPU holds the lock. Linux uses raw_spin_lock_irqsave().
static OUTPUT_LOCK: IrqSpinlock<()> = IrqSpinlock::new(());

/// Panic/oops in progress - use non-blocking output
///
/// When set, PrintkWriter uses try_lock() instead of lock() to avoid
/// deadlock if the panicking CPU already holds OUTPUT_LOCK.
static OOPS_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Enter panic mode - subsequent printk uses try_lock
///
/// Call this at the start of the panic handler before any printk calls.
/// Once set, it is never cleared (panic is a one-way trip).
pub fn set_oops_in_progress() {
    OOPS_IN_PROGRESS.store(true, Ordering::Release);
}

/// Ring buffer size (must be power of 2)
const PRINTK_BUFFER_SIZE: usize = 16384; // 16KB

/// Ring buffer for printk messages
struct RingBuffer {
    /// Buffer storage
    data: [u8; PRINTK_BUFFER_SIZE],
    /// Write position (next byte to write)
    head: usize,
    /// Read position (next byte to read for flush)
    tail: usize,
    /// Has the buffer wrapped (overwritten old data)?
    wrapped: bool,
}

impl RingBuffer {
    const fn new() -> Self {
        Self {
            data: [0; PRINTK_BUFFER_SIZE],
            head: 0,
            tail: 0,
            wrapped: false,
        }
    }

    /// Write a byte to the buffer
    fn write_byte(&mut self, byte: u8) {
        self.data[self.head] = byte;
        self.head = (self.head + 1) & (PRINTK_BUFFER_SIZE - 1);

        // If we caught up to tail, we've overwritten data
        if self.head == self.tail {
            self.tail = (self.tail + 1) & (PRINTK_BUFFER_SIZE - 1);
            self.wrapped = true;
        }
    }

    /// Write bytes to the buffer
    fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b);
        }
    }

    /// Read available bytes for flushing (advances tail)
    fn read_for_flush(&mut self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        while self.tail != self.head && count < buf.len() {
            buf[count] = self.data[self.tail];
            self.tail = (self.tail + 1) & (PRINTK_BUFFER_SIZE - 1);
            count += 1;
        }
        count
    }

    /// Get number of bytes available to read
    fn available(&self) -> usize {
        if self.head >= self.tail {
            self.head - self.tail
        } else {
            PRINTK_BUFFER_SIZE - self.tail + self.head
        }
    }

    /// Check if buffer has overflowed (lost messages)
    fn has_overflow(&self) -> bool {
        self.wrapped
    }

    /// Clear overflow flag
    fn clear_overflow(&mut self) {
        self.wrapped = false;
    }
}

/// Printk state
struct PrintkState {
    /// Ring buffer for messages
    buffer: RingBuffer,
    /// Has the buffer been flushed since console attach?
    flushed: bool,
}

impl PrintkState {
    const fn new() -> Self {
        Self {
            buffer: RingBuffer::new(),
            flushed: false, // Buffer needs flush when console is attached
        }
    }
}

/// Global printk state
///
/// Uses IrqSpinlock to be IRQ-safe - printk can be called from
/// interrupt context, and we must disable interrupts while holding
/// this lock to prevent deadlock. Linux uses raw_spin_lock_irqsave().
static PRINTK: IrqSpinlock<PrintkState> = IrqSpinlock::new(PrintkState::new());

/// Flush buffered messages to console
///
/// Call this after attaching a console to output any messages
/// that were buffered before the console was ready.
///
/// Note: This function is called before heap is initialized, so it
/// must not allocate. We write directly while holding both locks,
/// accepting that we block other CPUs during console writes.
/// This is acceptable for boot-time flush.
pub fn flush() {
    // Check if console is available (outside lock)
    if !console::has_console() {
        return;
    }

    // Take output lock first to serialize with other writers
    let _output = OUTPUT_LOCK.lock();
    let mut state = PRINTK.lock();

    if state.flushed {
        return;
    }

    // Check for overflow
    if state.buffer.has_overflow() {
        let overflow_msg = b"\n*** printk buffer overflow - some messages lost ***\n";
        console::console_write(overflow_msg);
        state.buffer.clear_overflow();
    }

    // Flush buffer in chunks - we must hold the lock here because we can't
    // allocate to copy the data, and this is called during early boot
    let mut chunk = [0u8; 256];
    loop {
        let n = state.buffer.read_for_flush(&mut chunk);
        if n == 0 {
            break;
        }
        console::console_write(&chunk[..n]);
    }

    state.flushed = true;
}

/// Write bytes to printk (internal) - must be called with OUTPUT_LOCK held
fn printk_write_locked(bytes: &[u8]) {
    // Buffer the message and get flushed state
    let should_write = {
        let mut state = PRINTK.lock();
        state.buffer.write_bytes(bytes);
        state.flushed
    };

    // If we're in flushed state (console attached and initial flush done),
    // write directly to console
    if should_write && console::has_console() {
        console::console_write(bytes);
    } else {
        // Fallback: write directly to serial when no console available
        // This is especially important for aarch64 which may not have console registered yet
        #[cfg(target_arch = "aarch64")]
        {
            if let Ok(s) = core::str::from_utf8(bytes) {
                crate::arch::aarch64::serial::write_str(s);
            }
        }
    }
}

/// Direct serial write - bypasses console subsystem for panic safety
///
/// Used when OUTPUT_LOCK cannot be acquired during panic.
fn direct_serial_write(bytes: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        // Use serial TTY driver directly
        if let Ok(s) = core::str::from_utf8(bytes) {
            for c in s.chars() {
                crate::tty::serial::write_byte_com1(c as u8);
            }
        } else {
            for &b in bytes {
                crate::tty::serial::write_byte_com1(b);
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Ok(s) = core::str::from_utf8(bytes) {
            crate::arch::aarch64::serial::write_str(s);
        } else {
            for &b in bytes {
                crate::arch::aarch64::serial::write_byte(b);
            }
        }
    }
}

/// Printk writer for fmt::Write
///
/// Holds OUTPUT_LOCK for the duration of all write_str calls,
/// ensuring entire formatted messages are written atomically.
///
/// In panic mode (OOPS_IN_PROGRESS), uses try_lock() with direct
/// serial fallback to avoid deadlock.
pub struct PrintkWriter {
    /// Lock guard (None if in panic mode and lock unavailable)
    /// Uses IrqSpinlockGuard for IRQ safety
    #[cfg(target_arch = "x86_64")]
    _guard: Option<crate::arch::x86_64::spinlock::IrqSpinlockGuard<'static, ()>>,
    #[cfg(target_arch = "aarch64")]
    _guard: Option<crate::arch::aarch64::spinlock::IrqSpinlockGuard<'static, ()>>,
}

impl PrintkWriter {
    /// Create a new PrintkWriter, acquiring the output lock
    ///
    /// In panic mode, uses try_lock() to avoid deadlock. If the lock
    /// cannot be acquired, writes go directly to serial.
    pub fn new() -> Self {
        if OOPS_IN_PROGRESS.load(Ordering::Acquire) {
            // Panic mode: try non-blocking lock
            Self {
                _guard: OUTPUT_LOCK.try_lock(),
            }
        } else {
            // Normal mode: blocking lock
            Self {
                _guard: Some(OUTPUT_LOCK.lock()),
            }
        }
    }
}

impl Default for PrintkWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for PrintkWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self._guard.is_some() {
            // Normal path: OUTPUT_LOCK is held
            printk_write_locked(s.as_bytes());
        } else {
            // Panic path: couldn't get lock, write directly to serial
            direct_serial_write(s.as_bytes());
        }
        Ok(())
    }
}

/// Print to kernel log (like Linux printk)
///
/// Messages are buffered and optionally sent to console.
/// Always succeeds - never blocks or fails.
/// The output lock is held for the entire format operation,
/// ensuring atomic output even for messages with multiple arguments.
#[macro_export]
macro_rules! printk {
    ($($arg:tt)*) => {{
        use ::core::fmt::Write;
        let mut writer = $crate::printk::PrintkWriter::new();
        let _ = write!(writer, $($arg)*);
        // writer dropped here, releasing OUTPUT_LOCK
    }};
}

/// Print to kernel log with newline
///
/// Uses a single writer for the message and newline to ensure atomicity.
#[macro_export]
macro_rules! printkln {
    () => {
        $crate::printk!("\n")
    };
    ($($arg:tt)*) => {{
        use ::core::fmt::Write;
        let mut writer = $crate::printk::PrintkWriter::new();
        let _ = write!(writer, $($arg)*);
        let _ = writer.write_str("\n");
        // writer dropped here, releasing OUTPUT_LOCK
    }};
}

/// Get printk buffer statistics
pub fn stats() -> (usize, usize, bool) {
    let state = PRINTK.lock();
    (
        state.buffer.available(),
        PRINTK_BUFFER_SIZE,
        state.buffer.has_overflow(),
    )
}
