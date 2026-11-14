//! DRM-based Text Console
//!
//! Provides a text console that renders to a DRM scanout surface.
//! This console implements the ConsoleDriver trait and can be registered
//! as a kernel console alongside serial.
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use core::ptr;

use crate::sync::IrqSpinlock;

use crate::console::{ConsoleDriver, ConsolePriority};
use crate::gfx::font::{DEFAULT_FONT, Font};
use crate::gfx::{Color, FramebufferInfo, PixelFormat};

/// Scanout surface - abstraction over the framebuffer
///
/// The console renders to this surface without knowing about
/// the underlying hardware (GOP, DRM, etc.).
///
/// # Invariants
/// `pitch * height` bytes at `buffer` are mapped framebuffer memory, and
/// a row's `width` pixels fit in `pitch`.
pub struct ScanoutSurface {
    /// CPU-accessible buffer pointer (ioremap'd)
    buffer: *mut u8,
    /// Width in pixels
    width: u32,
    /// Height in pixels
    height: u32,
    /// Bytes per scanline (pitch)
    pitch: u32,
    /// Pixel format
    format: PixelFormat,
}

// SAFETY: device memory reached only by volatile access through `&self`
// methods of the console, which serializes them (its state lock)
unsafe impl Send for ScanoutSurface {}
// SAFETY: as above
unsafe impl Sync for ScanoutSurface {}

impl ScanoutSurface {
    /// Create a new scanout surface from framebuffer info and mapped address
    ///
    /// # Safety
    /// The buffer must be a valid, mapped pointer to framebuffer memory
    /// with at least `fb_info.size` bytes accessible.
    pub unsafe fn new(fb_info: &FramebufferInfo, buffer: *mut u8) -> Self {
        // INVARIANT: the size the firmware reports bounds the rows used,
        // and a row's pixels fit its pitch (a bad mode shrinks, never
        // writes past the mapping)
        let bpp = fb_info.format.bytes_per_pixel().max(1);
        let pitch = fb_info.pitch.max(1);
        let rows = (fb_info.size / u64::from(pitch)).min(u64::from(u32::MAX)) as u32;
        Self {
            buffer,
            width: fb_info.width.min(pitch / bpp),
            height: fb_info.height.min(rows),
            pitch,
            format: fb_info.format,
        }
    }

    /// Get surface width in pixels
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Get surface height in pixels
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Get bytes per pixel for current format
    pub fn bytes_per_pixel(&self) -> u32 {
        self.format.bytes_per_pixel()
    }

    /// Write a single pixel at (x, y) with the given color
    #[inline]
    pub fn put_pixel(&mut self, x: u32, y: u32, color: Color) {
        if x >= self.width || y >= self.height {
            return;
        }

        let offset = (y * self.pitch) as usize + (x * self.bytes_per_pixel()) as usize;

        match self.format {
            PixelFormat::Xrgb8888 | PixelFormat::Xbgr8888 => {
                let pixel = color.to_pixel(self.format);
                unsafe {
                    let ptr = self.buffer.add(offset).cast::<u32>();
                    ptr::write_volatile(ptr, pixel);
                }
            }
            PixelFormat::Rgb565 => {
                let pixel = color.to_pixel(self.format) as u16;
                unsafe {
                    let ptr = self.buffer.add(offset).cast::<u16>();
                    ptr::write_volatile(ptr, pixel);
                }
            }
        }
    }

    /// Fill a rectangle with the given color
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: Color) {
        let pixel = color.to_pixel(self.format);
        let bpp = self.bytes_per_pixel();

        for row in y..y.saturating_add(h).min(self.height) {
            let row_offset = (row * self.pitch) as usize;
            for col in x..x.saturating_add(w).min(self.width) {
                let offset = row_offset + (col * bpp) as usize;
                match self.format {
                    PixelFormat::Xrgb8888 | PixelFormat::Xbgr8888 => unsafe {
                        let ptr = self.buffer.add(offset).cast::<u32>();
                        ptr::write_volatile(ptr, pixel);
                    },
                    PixelFormat::Rgb565 => unsafe {
                        let ptr = self.buffer.add(offset).cast::<u16>();
                        ptr::write_volatile(ptr, pixel as u16);
                    },
                }
            }
        }
    }

    /// Blit a glyph at character position (char_x, char_y) using the given font
    ///
    /// The glyph data is a bitmap where each byte represents one row,
    /// with bit 7 (MSB) being the leftmost pixel.
    pub fn blit_glyph(
        &mut self,
        char_x: u32,
        char_y: u32,
        font: &Font,
        glyph: &[u8],
        fg: Color,
        bg: Color,
    ) {
        let start_x = char_x * u32::from(font.width);
        let start_y = char_y * u32::from(font.height);
        let fg_pixel = fg.to_pixel(self.format);
        let bg_pixel = bg.to_pixel(self.format);
        let bpp = self.bytes_per_pixel();

        for (row_idx, &row_bits) in glyph.iter().enumerate() {
            let y = start_y + row_idx as u32;
            if y >= self.height {
                break;
            }

            let row_offset = (y * self.pitch) as usize;

            for bit_idx in 0..font.width {
                let x = start_x + u32::from(bit_idx);
                if x >= self.width {
                    break;
                }

                // Bit 7 is leftmost pixel
                let is_fg = (row_bits >> (7 - bit_idx)) & 1 == 1;
                let pixel = if is_fg { fg_pixel } else { bg_pixel };
                let offset = row_offset + (x * bpp) as usize;

                match self.format {
                    PixelFormat::Xrgb8888 | PixelFormat::Xbgr8888 => unsafe {
                        let ptr = self.buffer.add(offset).cast::<u32>();
                        ptr::write_volatile(ptr, pixel);
                    },
                    PixelFormat::Rgb565 => unsafe {
                        let ptr = self.buffer.add(offset).cast::<u16>();
                        ptr::write_volatile(ptr, pixel as u16);
                    },
                }
            }
        }
    }

    /// Scroll the entire surface up by one character row
    ///
    /// Uses memmove to shift content up, then clears the bottom row.
    pub fn scroll_up(&mut self, font_height: u32, bg: Color) {
        let scroll_bytes = (font_height * self.pitch) as usize;
        let total_bytes = (self.height * self.pitch) as usize;

        if scroll_bytes >= total_bytes {
            // Just clear the whole screen
            self.clear(bg);
            return;
        }

        // Move content up using memmove (handles overlapping regions)
        unsafe {
            ptr::copy(
                self.buffer.add(scroll_bytes),
                self.buffer,
                total_bytes - scroll_bytes,
            );
        }

        // Clear the bottom row(s)
        let clear_start_y = self.height - font_height;
        self.fill_rect(0, clear_start_y, self.width, font_height, bg);
    }

    /// Clear the entire surface with the given color
    pub fn clear(&mut self, color: Color) {
        self.fill_rect(0, 0, self.width, self.height, color);
    }
}

/// Graphics console state protected by a single lock
///
/// Combines surface and cursor position to ensure atomic updates.
/// This prevents SMP race conditions where cursor position could
/// become inconsistent with rendered content.
struct GfxConsoleState {
    /// Scanout surface for rendering
    surface: ScanoutSurface,
    /// Current cursor X position (in characters)
    cursor_x: u32,
    /// Current cursor Y position (in characters)
    cursor_y: u32,
}

/// DRM-based text console
///
/// Renders text to a ScanoutSurface and implements ConsoleDriver
/// for integration with the kernel's console subsystem.
pub struct GfxConsole {
    /// Console name
    name: &'static str,
    /// Console state (surface + cursor); IRQ-safe: console writes run in
    /// any context
    state: IrqSpinlock<GfxConsoleState>,
    /// Font to use for rendering
    font: &'static Font,
    /// Console width in characters
    cols: u32,
    /// Console height in characters
    rows: u32,
    /// Foreground color
    fg_color: Color,
    /// Background color
    bg_color: Color,
}

impl GfxConsole {
    /// Create a new DRM console on `surface` (its invariant holds)
    pub fn new(name: &'static str, surface: ScanoutSurface, font: &'static Font) -> Self {
        let cols = surface.width() / u32::from(font.width);
        let rows = surface.height() / u32::from(font.height);

        Self {
            name,
            state: IrqSpinlock::new(GfxConsoleState {
                surface,
                cursor_x: 0,
                cursor_y: 0,
            }),
            font,
            cols,
            rows,
            fg_color: Color::WHITE,
            bg_color: Color::BLACK,
        }
    }

    /// Get console dimensions in characters
    pub fn dimensions(&self) -> (u32, u32) {
        (self.cols, self.rows)
    }

    /// Clear the console and reset cursor
    pub fn clear(&self) {
        let mut state = self.state.lock();
        state.surface.clear(self.bg_color);
        state.cursor_x = 0;
        state.cursor_y = 0;
    }

    /// Put a single character at the current cursor position
    fn put_char(&self, state: &mut GfxConsoleState, ch: u8) {
        // Copy cursor position (avoid borrow conflict with surface)
        let cx = state.cursor_x;
        let cy = state.cursor_y;

        // Get glyph and render
        let glyph = self.font.glyph(ch);
        state
            .surface
            .blit_glyph(cx, cy, self.font, glyph, self.fg_color, self.bg_color);

        // Advance cursor
        state.cursor_x += 1;
        if state.cursor_x >= self.cols {
            state.cursor_x = 0;
            state.cursor_y += 1;
        }

        // Scroll if needed
        if state.cursor_y >= self.rows {
            state
                .surface
                .scroll_up(u32::from(self.font.height), self.bg_color);
            state.cursor_y = self.rows - 1;
        }
    }

    /// Handle newline
    fn newline(&self, state: &mut GfxConsoleState) {
        state.cursor_x = 0;
        state.cursor_y += 1;

        if state.cursor_y >= self.rows {
            state
                .surface
                .scroll_up(u32::from(self.font.height), self.bg_color);
            state.cursor_y = self.rows - 1;
        }
    }

    /// Handle tab
    fn tab(&self, state: &mut GfxConsoleState) {
        let tab_width = 8;
        let new_x = ((state.cursor_x / tab_width) + 1) * tab_width;
        state.cursor_x = new_x.min(self.cols - 1);
    }

    /// Write a byte to the console
    fn write_byte(&self, state: &mut GfxConsoleState, byte: u8) {
        match byte {
            b'\n' => self.newline(state),
            b'\r' => state.cursor_x = 0,
            b'\t' => self.tab(state),
            // Backspace, and Delete treated as one
            0x08 | 0x7F => state.cursor_x = state.cursor_x.saturating_sub(1),
            // Printable ASCII, and extended ASCII if the font has it
            0x20..=0x7E | 0x80..=0xFF => self.put_char(state, byte),
            // Ignore other control characters
            _ => {}
        }
    }
}

impl ConsoleDriver for GfxConsole {
    fn name(&self) -> &str {
        self.name
    }

    /// Render `data`, in any context (under printk's `OUTPUT_LOCK`).
    /// The state is only tried: held (a printk nested in this write, or
    /// a concurrent oops), the output is dropped (Linux
    /// vt_console_print's printing_lock trylock)
    fn write(&self, data: &[u8]) {
        let Some(mut state) = self.state.try_lock() else {
            return;
        };
        for &byte in data {
            self.write_byte(&mut state, byte);
        }
    }

    fn flush(&self) {
        // No buffering - writes go directly to framebuffer
    }
}

/// Global graphics console instance
static GRAPHICS_CONSOLE: spin::Once<GfxConsole> = spin::Once::new();

/// Initialize the graphics console if a boot framebuffer is available
///
/// # Safety
/// Must be called after ioremap is initialized.
/// The framebuffer must be properly reserved in the frame allocator.
pub unsafe fn init_graphics_console() -> bool {
    use crate::gfx::BOOT_FRAMEBUFFER;

    let Some(fb_info) = BOOT_FRAMEBUFFER.get() else {
        return false;
    };

    // Map the framebuffer
    // SAFETY: the firmware framebuffer, video memory outside the RAM
    // memblock hands out
    let Ok(fb_ptr) = (unsafe { crate::mm::ioremap::ioremap(fb_info.phys_addr, fb_info.size) })
    else {
        crate::printkln!("graphics: failed to map framebuffer");
        return false;
    };

    // Create the scanout surface
    // SAFETY: fb_ptr is a valid mapping of the framebuffer returned by ioremap
    let surface = unsafe { ScanoutSurface::new(fb_info, fb_ptr) };

    // Create the console
    let console = GfxConsole::new("gfx0", surface, &DEFAULT_FONT);
    let (cols, rows) = console.dimensions();

    // Clear the screen
    console.clear();

    // Store globally
    GRAPHICS_CONSOLE.call_once(|| console);

    crate::printkln!(
        "graphics: console initialized {}x{} ({}x{} pixels)",
        cols,
        rows,
        fb_info.width,
        fb_info.height
    );

    true
}

/// Register the graphics console with the console subsystem
///
/// Should be called after init_graphics_console().
/// Registered with CONSDEV flag indicating this is the primary interactive console.
pub fn register_graphics_console() {
    use crate::console::ConsoleFlags;

    if let Some(console) = GRAPHICS_CONSOLE.get() {
        // Register with Normal priority and CONSDEV flag
        // CONSDEV indicates this is the primary console (/dev/console target)
        // PRINTBUFFER requests replay of buffered messages (already done by printk)
        crate::console::register_console(
            console,
            ConsolePriority::Normal,
            ConsoleFlags::CONSDEV | ConsoleFlags::PRINTBUFFER,
        );
        crate::printkln!("graphics: console registered as {}", console.name());
    }
}

/// Check if graphics console is available
pub fn has_graphics_console() -> bool {
    GRAPHICS_CONSOLE.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn console(mem: &mut [u8]) -> GfxConsole {
        let fb = FramebufferInfo {
            phys_addr: 0,
            size: mem.len() as u64,
            width: 64,
            height: 32,
            pitch: 64 * 4,
            format: PixelFormat::Xrgb8888,
        };
        // SAFETY: `mem` is `fb.size` bytes, outliving the console
        let s = unsafe { ScanoutSurface::new(&fb, mem.as_mut_ptr()) };
        GfxConsole::new("t", s, &DEFAULT_FONT)
    }

    /// A write that finds the state held (a printk nested in a console
    /// write) drops its output instead of spinning on its own lock
    #[test]
    fn nested_write_drops() {
        let mut mem = vec![0u8; 64 * 4 * 32];
        let c = console(&mut mem);
        c.write(b"a");
        let held = c.state.lock();
        let x = held.cursor_x;
        c.write(b"bc");
        assert_eq!(held.cursor_x, x);
        drop(held);
        c.write(b"d\r");
        assert_eq!(c.state.lock().cursor_x, 0);
    }
}
