//! 8254 PIT driver (Programmable Interval Timer)
//!
//! Platform bus driver for the Intel 8254 PIT.

use alloc::boxed::Box;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::io::outb;
use crate::bus::BusContext;
use crate::bus::driver::{Device, DriverError, Timer};
use crate::bus::platform::{PlatformBusDriver, PlatformDevice};
use crate::impl_platform_bus_driver;

/// Global tick counter (incremented by IRQ handler)
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// PIT I/O ports
const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

/// PIT base frequency (Hz)
const PIT_FREQUENCY: u32 = 1193182;

/// Command byte for channel 0, access mode lo/hi, rate generator (mode 2)
const PIT_CMD_CHANNEL0: u8 = 0x00;
const PIT_CMD_ACCESS_LOHI: u8 = 0x30;
const PIT_CMD_MODE_RATE: u8 = 0x04;

/// 8254 PIT platform bus driver
pub struct Pit8254PlatformDriver;

impl PlatformBusDriver for Pit8254PlatformDriver {
    fn name(&self) -> &str {
        "pit8254-driver"
    }

    fn compatible(&self) -> &'static [&'static str] {
        &["intel,8254"]
    }

    fn probe_platform(
        &self,
        _device: &PlatformDevice,
        _ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError> {
        Ok(Box::new(Pit8254::new(PIT_FREQUENCY)))
    }
}

impl_platform_bus_driver!(Pit8254PlatformDriver);

/// 8254 PIT device instance
pub struct Pit8254 {
    /// Base clock frequency
    clock_freq: u32,
}

impl Pit8254 {
    /// Create a new PIT instance
    pub fn new(clock_freq: u32) -> Self {
        Self { clock_freq }
    }
}

impl Device for Pit8254 {
    fn name(&self) -> &str {
        "pit8254"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Timer for Pit8254 {
    fn init(&self, frequency_hz: u32) {
        let divisor = if frequency_hz == 0 {
            0xFFFF
        } else {
            let div = self.clock_freq / frequency_hz;
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

    fn ticks(&self) -> u64 {
        TICK_COUNT.load(Ordering::Relaxed)
    }
}
