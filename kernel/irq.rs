//! Generic IRQ-line bookkeeping shared by the arch dispatchers
//!
//! Unclaimed-interrupt accounting (Linux kernel/irq/spurious.c
//! note_interrupt): a line nobody claims - a device holding a shared
//! level-triggered line asserted with no driver for it - would storm
//! forever. Out of every 100,000 interrupts on a line, more than 99,900
//! unclaimed ones disable it ("nobody cared"). An unclaimed interrupt
//! more than 100 ms after the previous one restarts the unclaimed count,
//! so occasional strays on a busy line never add up.
//!
//! Locking: none of its own; each line's state lives under its arch
//! dispatcher's `IRQ_TABLE` lock.

/// Interrupts per accounting window (Linux note_interrupt)
const WINDOW: u32 = 100_000;

/// Unclaimed interrupts in a window that disable the line
const UNHANDLED_MAX: u32 = 99_900;

/// Gap after which an unclaimed interrupt restarts the count (Linux
/// HZ/10)
const UNHANDLED_GAP_NS: u64 = 100_000_000;

/// One line's unclaimed-interrupt state (Linux irq_desc irq_count,
/// irqs_unhandled, last_unhandled)
pub struct Spurious {
    count: u32,
    unhandled: u32,
    last_unhandled_ns: u64,
}

impl Spurious {
    pub const fn new() -> Self {
        Self {
            count: 0,
            unhandled: 0,
            last_unhandled_ns: 0,
        }
    }

    /// Start over (a handler was added)
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Account one interrupt at `now_ns`; true if the line must now be
    /// disabled (Linux note_interrupt)
    pub fn note(&mut self, handled: bool, now_ns: u64) -> bool {
        if !handled {
            if now_ns.saturating_sub(self.last_unhandled_ns) > UNHANDLED_GAP_NS {
                self.unhandled = 1;
            } else {
                self.unhandled += 1;
            }
            self.last_unhandled_ns = now_ns;
        }
        self.count += 1;
        if self.count < WINDOW {
            return false;
        }
        let bad = self.unhandled > UNHANDLED_MAX;
        self.count = 0;
        self.unhandled = 0;
        bad
    }
}

impl Default for Spurious {
    fn default() -> Self {
        Self::new()
    }
}

/// Report a line `note` disabled (Linux __report_bad_irq); called after
/// dropping `IRQ_TABLE`, which stays a leaf lock
pub fn report_nobody_cared(irq: u32) {
    crate::printkln!("irq {}: nobody cared, disabling it", irq);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stuck line, nothing claims it: disabled at the window's end
    #[test]
    fn storm_disabled() {
        let mut s = Spurious::new();
        for i in 1..WINDOW {
            assert!(!s.note(false, i as u64 * 1000));
        }
        assert!(s.note(false, WINDOW as u64 * 1000));
    }

    /// The old consecutive count never fired when a driver claimed one
    /// interrupt now and then; the window count does (more than 99.9%
    /// unclaimed)
    #[test]
    fn mostly_unclaimed_disabled() {
        let mut s = Spurious::new();
        let mut bad = false;
        for i in 0..WINDOW {
            bad |= s.note(i % 2000 == 0, i as u64 * 1000);
        }
        assert!(bad);
    }

    /// A busy line whose driver claims most interrupts stays on
    #[test]
    fn mostly_claimed_kept() {
        let mut s = Spurious::new();
        for i in 0..3 * WINDOW {
            assert!(!s.note(i % 10 != 0, i as u64 * 1000));
        }
    }

    /// Strays 100 ms apart never add up
    #[test]
    fn sparse_strays_kept() {
        let mut s = Spurious::new();
        for i in 0..2 * WINDOW as u64 {
            assert!(!s.note(false, i * (UNHANDLED_GAP_NS + 1)));
        }
    }
}
