//! VGA Text Console Driver
//!
//! A simple VGA text-mode console for early boot debugging on x86-64.
//! This implements the ConsoleDriver trait and provides output to the
//! standard VGA text buffer at 0xB8000.
//!
//! ## Hardware Interface
//!
//! - VGA text buffer: 0xB8000 (80x25 characters, 2 bytes per cell)
//! - CRT Controller: I/O ports 0x3D4 (index) and 0x3D5 (data)
//! - Cursor position: CRT registers 14 (high) and 15 (low)

use crate::arch::IrqSpinlock;
use crate::console::{ConsoleDriver, ConsoleFlags, ConsolePriority, register_console};

use super::io::outb;

/// VGA text buffer physical address
const VGA_BUFFER_PHYS: u64 = 0xB8000;

/// Display dimensions
const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;

/// CRT Controller ports (color mode)
const VGA_CRTC_INDEX: u16 = 0x3D4;
const VGA_CRTC_DATA: u16 = 0x3D5;

/// CRT Controller register indices
const CRTC_CURSOR_START: u8 = 0x0A;
const CRTC_CURSOR_END: u8 = 0x0B;
const CRTC_CURSOR_HI: u8 = 0x0E;
const CRTC_CURSOR_LO: u8 = 0x0F;

/// Default text attribute: light gray on black
const DEFAULT_ATTR: u8 = 0x07;

/// Probe VGA buffer to verify hardware presence and wake it up
///
/// Uses complementary test patterns (Linux-style) to verify the VGA
/// buffer responds correctly. This also serves to "wake up" VGA
/// hardware that may be in a low-power state on some systems.
///
/// Returns true if VGA buffer is present and responsive.
fn probe_vga_buffer() -> bool {
    let p = VGA_BUFFER_PHYS as *mut u16;
    unsafe {
        // Save original values
        let saved1 = core::ptr::read_volatile(p);
        let saved2 = core::ptr::read_volatile(p.add(1));

        // Test pattern 1: 0xAA55 / 0x55AA
        core::ptr::write_volatile(p, 0xAA55);
        core::ptr::write_volatile(p.add(1), 0x55AA);
        let ok1 =
            core::ptr::read_volatile(p) == 0xAA55 && core::ptr::read_volatile(p.add(1)) == 0x55AA;

        // Test pattern 2: complementary (0x55AA / 0xAA55)
        core::ptr::write_volatile(p, 0x55AA);
        core::ptr::write_volatile(p.add(1), 0xAA55);
        let ok2 =
            core::ptr::read_volatile(p) == 0x55AA && core::ptr::read_volatile(p.add(1)) == 0xAA55;

        // Restore original values
        core::ptr::write_volatile(p, saved1);
        core::ptr::write_volatile(p.add(1), saved2);

        ok1 && ok2
    }
}

/// VGA text console state
struct VgaConState {
    /// Virtual address of VGA buffer (same as physical in identity-mapped region)
    buffer: *mut u16,
    /// Current cursor column (0-79)
    cursor_x: usize,
    /// Current cursor row (0-24)
    cursor_y: usize,
    /// Current text attribute
    attribute: u8,
    /// Whether the console is initialized
    initialized: bool,
}

// Safety: VGA buffer access is protected by IrqSpinlock
unsafe impl Send for VgaConState {}
unsafe impl Sync for VgaConState {}

impl VgaConState {
    /// Create uninitialized state
    const fn new() -> Self {
        Self {
            buffer: core::ptr::null_mut(),
            cursor_x: 0,
            cursor_y: 0,
            attribute: DEFAULT_ATTR,
            initialized: false,
        }
    }

    /// Initialize the VGA console state
    fn init(&mut self) {
        // VGA buffer at 0xB8000 is identity-mapped in our kernel
        self.buffer = VGA_BUFFER_PHYS as *mut u16;
        self.attribute = DEFAULT_ATTR;

        // Probe VGA buffer - this also "wakes up" VGA hardware that may
        // be in a low-power state on some systems (like Dell Optiplex 3020)
        if !probe_vga_buffer() {
            // VGA not present or not responding - don't initialize
            return;
        }

        // Initialize cursor hardware (scan lines for visibility)
        self.init_cursor_hardware();

        // Clear screen to known state
        self.clear_screen();

        // Set cursor to top-left
        self.cursor_x = 0;
        self.cursor_y = 0;
        self.update_cursor();

        self.initialized = true;
    }

    /// Initialize cursor hardware registers for visibility
    fn init_cursor_hardware(&self) {
        // Set cursor start scan line (register 0x0A)
        // Bit 5: cursor disabled (0 = enabled)
        // Bits 0-4: start scan line (14 for underline cursor)
        outb(VGA_CRTC_INDEX, CRTC_CURSOR_START);
        outb(VGA_CRTC_DATA, 0x0E);

        // Set cursor end scan line (register 0x0B)
        // Bits 0-4: end scan line (15 for underline cursor)
        outb(VGA_CRTC_INDEX, CRTC_CURSOR_END);
        outb(VGA_CRTC_DATA, 0x0F);
    }

    /// Clear the entire screen
    fn clear_screen(&mut self) {
        let blank = (self.attribute as u16) << 8 | 0x20u16; // Space with attribute
        unsafe {
            for i in 0..(VGA_WIDTH * VGA_HEIGHT) {
                core::ptr::write_volatile(self.buffer.add(i), blank);
            }
        }
    }

    /// Write a character at the current cursor position
    fn put_char(&mut self, c: u8) {
        if !self.initialized {
            return;
        }

        match c {
            b'\n' => {
                // Newline: move to start of next line
                self.cursor_x = 0;
                self.cursor_y += 1;
            }
            b'\r' => {
                // Carriage return: move to start of line
                self.cursor_x = 0;
            }
            b'\t' => {
                // Tab: move to next 8-column boundary
                self.cursor_x = (self.cursor_x + 8) & !7;
                if self.cursor_x >= VGA_WIDTH {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                }
            }
            0x08 => {
                // Backspace: move cursor back (don't erase)
                if self.cursor_x > 0 {
                    self.cursor_x -= 1;
                }
            }
            _ => {
                // Printable character
                let offset = self.cursor_y * VGA_WIDTH + self.cursor_x;
                let cell = (self.attribute as u16) << 8 | (c as u16);

                unsafe {
                    core::ptr::write_volatile(self.buffer.add(offset), cell);
                }

                self.cursor_x += 1;
                if self.cursor_x >= VGA_WIDTH {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                }
            }
        }

        // Scroll if needed
        if self.cursor_y >= VGA_HEIGHT {
            self.scroll_up();
            self.cursor_y = VGA_HEIGHT - 1;
        }
    }

    /// Scroll the screen up by one line
    fn scroll_up(&mut self) {
        if !self.initialized {
            return;
        }

        unsafe {
            // Move lines 1-24 to lines 0-23
            let src = self.buffer.add(VGA_WIDTH);
            let dst = self.buffer;
            let count = VGA_WIDTH * (VGA_HEIGHT - 1);

            core::ptr::copy(src, dst, count);

            // Clear the last line
            let blank = (self.attribute as u16) << 8 | (b' ' as u16);
            let last_line = self.buffer.add(VGA_WIDTH * (VGA_HEIGHT - 1));
            for i in 0..VGA_WIDTH {
                core::ptr::write_volatile(last_line.add(i), blank);
            }
        }
    }

    /// Update the hardware cursor position
    fn update_cursor(&self) {
        if !self.initialized {
            return;
        }

        let pos = (self.cursor_y * VGA_WIDTH + self.cursor_x) as u16;
        write_cursor_position(pos);
    }
}

/// Write cursor position to CRT controller
fn write_cursor_position(pos: u16) {
    // Write high byte (register 14)
    outb(VGA_CRTC_INDEX, CRTC_CURSOR_HI);
    outb(VGA_CRTC_DATA, (pos >> 8) as u8);

    // Write low byte (register 15)
    outb(VGA_CRTC_INDEX, CRTC_CURSOR_LO);
    outb(VGA_CRTC_DATA, (pos & 0xFF) as u8);
}

/// VGA console driver
///
/// Implements ConsoleDriver for VGA text mode output.
pub struct VgaCon {
    state: IrqSpinlock<VgaConState>,
}

impl VgaCon {
    /// Create a new VGA console (uninitialized)
    pub const fn new() -> Self {
        Self {
            state: IrqSpinlock::new(VgaConState::new()),
        }
    }

    /// Initialize the VGA console hardware
    pub fn init(&self) {
        let mut state = self.state.lock();
        state.init();
        state.update_cursor();
    }
}

impl ConsoleDriver for VgaCon {
    fn name(&self) -> &str {
        "vga0"
    }

    fn write(&self, data: &[u8]) {
        let mut state = self.state.lock();

        for &byte in data {
            state.put_char(byte);
        }

        state.update_cursor();
    }

    fn flush(&self) {
        // VGA writes are immediate, no buffering
    }
}

/// Static VGA console instance
pub static VGACON: VgaCon = VgaCon::new();

/// Initialize and register the VGA console
///
/// This should be called early in the x86-64 boot sequence.
/// The console preserves existing screen content and continues
/// from the current cursor position.
pub fn init_vgacon() {
    VGACON.init();

    register_console(
        &VGACON,
        ConsolePriority::Normal,
        ConsoleFlags::BOOT | ConsoleFlags::ENABLED,
    );
}
