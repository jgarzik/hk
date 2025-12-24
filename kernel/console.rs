//! Console Framework
//!
//! This module provides the console abstraction layer for kernel output.
//! Consoles are "where kernel messages go" via printk.
//!
//! ## Architecture (per tty.txt)
//!
//! The console is the top layer:
//! ```text
//! printk → console subsystem → one or more console drivers
//! ```
//!
//! Console drivers can be:
//! - Serial console (ttyS0)
//! - USB serial console (ttyUSB0)
//! - VT console (virtual terminals + VGA text / framebuffer)
//! - Null console (messages go to ring buffer only)
//!
//! ## Design
//!
//! - Messages are always buffered in printk's ring buffer first
//! - When a console is registered, buffered messages are flushed
//! - Multiple consoles can be active (all receive kernel messages)
//! - NullConsole is the default until a real console is attached
//!
//! ## Early Boot
//!
//! The console registry uses fixed-size arrays to avoid heap allocation,
//! allowing it to work before the heap is initialized.
//!
//! ## SMP Locking
//!
//! Uses IrqSpinlock for all registry operations to prevent deadlock when
//! console functions are called from interrupt context (e.g., printk from
//! a timer interrupt). Linux uses console_sem for similar protection.

use crate::arch::IrqSpinlock;

/// Maximum number of console drivers that can be registered
const MAX_CONSOLES: usize = 8;

/// Console driver trait - devices that can display kernel output
///
/// ConsoleDriver is distinct from CharDevice because:
/// 1. Console bypasses line discipline (raw output)
/// 2. Console is for kernel messages, not user I/O
/// 3. Console must work in restricted contexts (panics, early boot)
pub trait ConsoleDriver: Send + Sync {
    /// Console name for identification (e.g., "ttyS0", "ttyUSB0")
    fn name(&self) -> &str;

    /// Write bytes to the console
    ///
    /// This should be a simple, direct write. No buffering, no line
    /// discipline processing. Must be safe to call from panic context.
    fn write(&self, data: &[u8]);

    /// Flush any buffered output
    fn flush(&self) {}
}

/// Console priority - higher priority consoles are preferred
///
/// When multiple consoles are registered, the highest priority one
/// becomes the "primary" console for interactive use. All consoles
/// still receive kernel messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ConsolePriority {
    /// Fallback console (e.g., legacy serial when USB might be preferred)
    Fallback = 0,
    /// Normal priority (standard console)
    Normal = 1,
    /// Preferred console (user-specified or auto-detected best option)
    Preferred = 2,
}

bitflags::bitflags! {
    /// Console flags (matches Linux CON_* flags)
    ///
    /// These flags control console behavior during registration and output.
    /// Linux defines these in include/linux/console.h.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ConsoleFlags: u16 {
        /// Console is enabled and can print (CON_ENABLED)
        const ENABLED = 1 << 0;
        /// Boot console - auto-unregister when real console arrives (CON_BOOT)
        const BOOT = 1 << 1;
        /// Replay kernel log buffer to this console on registration (CON_PRINTBUFFER)
        const PRINTBUFFER = 1 << 2;
        /// This is the primary console (/dev/console target) (CON_CONSDEV)
        const CONSDEV = 1 << 3;
    }
}

/// Console registration entry
struct ConsoleEntry {
    console: Option<&'static dyn ConsoleDriver>,
    priority: ConsolePriority,
    flags: ConsoleFlags,
}

impl ConsoleEntry {
    const fn empty() -> Self {
        Self {
            console: None,
            priority: ConsolePriority::Fallback,
            flags: ConsoleFlags::empty(),
        }
    }
}

/// Global console registry
///
/// Manages registered console drivers and routes output to them.
/// Uses fixed-size arrays to avoid heap allocation during early boot.
pub struct ConsoleRegistry {
    /// Registered consoles with priorities (fixed-size array)
    consoles: [ConsoleEntry; MAX_CONSOLES],
    /// Number of registered consoles
    count: usize,
    /// Whether a flush is needed (new console registered)
    needs_flush: bool,
}

impl ConsoleRegistry {
    /// Create a new empty registry
    pub const fn new() -> Self {
        Self {
            consoles: [
                ConsoleEntry::empty(),
                ConsoleEntry::empty(),
                ConsoleEntry::empty(),
                ConsoleEntry::empty(),
                ConsoleEntry::empty(),
                ConsoleEntry::empty(),
                ConsoleEntry::empty(),
                ConsoleEntry::empty(),
            ],
            count: 0,
            needs_flush: false,
        }
    }

    /// Register a console driver
    ///
    /// Returns true if this is now the primary (highest priority) console.
    pub fn register(
        &mut self,
        console: &'static dyn ConsoleDriver,
        priority: ConsolePriority,
        flags: ConsoleFlags,
    ) -> bool {
        // Check if already registered
        for i in 0..self.count {
            if let Some(existing) = self.consoles[i].console
                && existing.name() == console.name()
            {
                return false;
            }
        }

        // Check capacity
        if self.count >= MAX_CONSOLES {
            return false;
        }

        let was_primary_name = self.primary().map(|c| c.name());

        // Add new entry with ENABLED flag set
        self.consoles[self.count] = ConsoleEntry {
            console: Some(console),
            priority,
            flags: flags | ConsoleFlags::ENABLED,
        };
        self.count += 1;
        self.needs_flush = true;

        // Sort by priority (highest first) - simple insertion sort
        for i in (1..self.count).rev() {
            if self.consoles[i].priority > self.consoles[i - 1].priority {
                self.consoles.swap(i, i - 1);
            } else {
                break;
            }
        }

        // Return true if this console is now primary
        self.primary().map(|c| c.name()) != was_primary_name
    }

    /// Unregister a console driver by name
    pub fn unregister(&mut self, name: &str) -> bool {
        let mut found = false;
        let mut write_idx = 0;

        for read_idx in 0..self.count {
            if let Some(console) = self.consoles[read_idx].console
                && console.name() == name
            {
                found = true;
                continue;
            }
            if write_idx != read_idx {
                self.consoles[write_idx] = ConsoleEntry {
                    console: self.consoles[read_idx].console,
                    priority: self.consoles[read_idx].priority,
                    flags: self.consoles[read_idx].flags,
                };
            }
            write_idx += 1;
        }

        if found {
            self.count = write_idx;
            // Clear remaining entries
            for i in write_idx..MAX_CONSOLES {
                self.consoles[i] = ConsoleEntry::empty();
            }
        }

        found
    }

    /// Get the primary console (highest priority)
    pub fn primary(&self) -> Option<&'static dyn ConsoleDriver> {
        if self.count > 0 {
            self.consoles[0].console
        } else {
            None
        }
    }

    /// Write to all registered consoles
    ///
    /// Only writes to consoles with ENABLED flag set.
    pub fn write_all(&self, data: &[u8]) {
        for i in 0..self.count {
            if let Some(console) = self.consoles[i].console
                && self.consoles[i].flags.contains(ConsoleFlags::ENABLED)
            {
                console.write(data);
            }
        }
    }

    /// Flush all consoles
    pub fn flush_all(&self) {
        for i in 0..self.count {
            if let Some(console) = self.consoles[i].console {
                console.flush();
            }
        }
    }

    /// Check if any consoles are registered
    pub fn has_console(&self) -> bool {
        self.count > 0
    }

    /// Get number of registered consoles
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check and clear the needs_flush flag
    pub fn take_needs_flush(&mut self) -> bool {
        let needs = self.needs_flush;
        self.needs_flush = false;
        needs
    }
}

impl Default for ConsoleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global console registry
///
/// Uses IrqSpinlock to be IRQ-safe - console functions can be called from
/// interrupt context via printk. Linux uses console_sem for serialization.
static CONSOLE_REGISTRY: IrqSpinlock<ConsoleRegistry> = IrqSpinlock::new(ConsoleRegistry::new());

/// Register a console driver globally
///
/// The priority is automatically elevated to Preferred if the console device
/// was specified on the kernel command line (console=).
///
/// Flags control console behavior:
/// - BOOT: Boot console, auto-unregistered when real console arrives
/// - PRINTBUFFER: Replay kernel log buffer to this console
/// - CONSDEV: This is the primary console (/dev/console target)
///
/// ENABLED is automatically set on registration.
///
/// Returns true if this console became the primary console.
pub fn register_console(
    console: &'static dyn ConsoleDriver,
    priority: ConsolePriority,
    flags: ConsoleFlags,
) -> bool {
    use crate::cmdline::is_cmdline_console;

    // Elevate priority if specified on command line
    let effective_priority = if is_cmdline_console(console.name()) {
        ConsolePriority::Preferred
    } else {
        priority
    };

    CONSOLE_REGISTRY
        .lock()
        .register(console, effective_priority, flags)
}

/// Unregister a console driver by name
pub fn unregister_console(name: &str) -> bool {
    CONSOLE_REGISTRY.lock().unregister(name)
}

/// Write to all registered consoles
pub fn console_write(data: &[u8]) {
    let registry = CONSOLE_REGISTRY.lock();
    if registry.has_console() {
        registry.write_all(data);
    } else {
        // Fallback: write directly to serial when no console available
        #[cfg(target_arch = "aarch64")]
        {
            if let Ok(s) = core::str::from_utf8(data) {
                crate::arch::aarch64::serial::write_str(s);
            } else {
                for &b in data {
                    crate::arch::aarch64::serial::write_byte(b);
                }
            }
        }
    }
}

/// Flush all registered consoles
pub fn console_flush() {
    CONSOLE_REGISTRY.lock().flush_all();
}

/// Check if any consoles are registered
pub fn has_console() -> bool {
    CONSOLE_REGISTRY.lock().has_console()
}

/// Get primary console name (if any)
pub fn primary_console_name() -> Option<&'static str> {
    CONSOLE_REGISTRY.lock().primary().map(|c| c.name())
}

/// Check and clear the needs_flush flag
///
/// This is used by printk to know when to flush the ring buffer
/// after a new console is registered.
pub fn console_take_needs_flush() -> bool {
    CONSOLE_REGISTRY.lock().take_needs_flush()
}

/// Null console - does nothing
///
/// Messages still go to printk ring buffer for later retrieval (dmesg).
/// This is used as the implicit default when no console is registered.
pub struct NullConsole;

impl ConsoleDriver for NullConsole {
    fn name(&self) -> &str {
        "null"
    }

    fn write(&self, _data: &[u8]) {
        // Do nothing - messages are already in printk ring buffer
    }
}

/// Static null console instance
pub static NULL_CONSOLE: NullConsole = NullConsole;
