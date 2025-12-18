//! 8254 Programmable Interval Timer (PIT) driver
//!
//! The 8254 PIT provides periodic timer interrupts for the scheduler.
//! It has a base frequency of 1.193182 MHz.

use super::io::outb;

/// PIT I/O ports
const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

/// PIT base frequency (Hz)
const PIT_FREQUENCY: u32 = 1193182;

/// Command byte for channel 0, access mode lo/hi, rate generator
const PIT_CMD_CHANNEL0: u8 = 0x00;
const PIT_CMD_ACCESS_LOHI: u8 = 0x30;
const PIT_CMD_MODE_RATE: u8 = 0x04; // Mode 2: rate generator

/// Initialize the PIT for periodic interrupts at the given frequency
pub fn init(frequency_hz: u32) {
    let divisor = if frequency_hz == 0 {
        0xFFFF // Maximum divisor for ~18.2 Hz
    } else {
        let div = PIT_FREQUENCY / frequency_hz;
        if div > 0xFFFF {
            0xFFFF
        } else if div < 1 {
            1
        } else {
            div as u16
        }
    };

    // Send command: channel 0, access mode lo/hi, mode 2 (rate generator)
    outb(
        PIT_COMMAND,
        PIT_CMD_CHANNEL0 | PIT_CMD_ACCESS_LOHI | PIT_CMD_MODE_RATE,
    );

    // Send divisor (low byte first, then high byte)
    outb(PIT_CHANNEL0, (divisor & 0xFF) as u8);
    outb(PIT_CHANNEL0, ((divisor >> 8) & 0xFF) as u8);
}
