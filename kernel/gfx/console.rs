//! DRM-based Text Console
//!
//! Provides a text console that renders to a DRM scanout surface.
//! This console implements the ConsoleDriver trait and can be registered
//! as a kernel console alongside serial.

use core::ptr;

use spin::Mutex;

use super::font::{DEFAULT_FONT, Font};
use super::{Color, FramebufferInfo, PixelFormat};
use crate::console::{ConsoleDriver, ConsolePriority};

/// Scanout surface - abstraction over the framebuffer
///
/// The console renders to this surface without knowing about
/// the underlying hardware (GOP, DRM, etc.).
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

// SAFETY: The buffer pointer is only accessed through synchronized methods
unsafe impl Send for ScanoutSurface {}
unsafe impl Sync for ScanoutSurface {}

impl ScanoutSurface {
    /// Create a new scanout surface from framebuffer info and mapped address
    ///
    /// # Safety
    /// The buffer must be a valid, mapped pointer to framebuffer memory
    /// with at least `fb_info.size` bytes accessible.
    pub unsafe fn new(fb_info: &FramebufferInfo, buffer: *mut u8) -> Self {
        Self {
            buffer,
            width: fb_info.width,
            height: fb_info.height,
            pitch: fb_info.pitch,
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
                    let ptr = self.buffer.add(offset) as *mut u32;
                    ptr::write_volatile(ptr, pixel);
                }
            }
            PixelFormat::Rgb565 => {
                let pixel = color.to_pixel(self.format) as u16;
                unsafe {
                    let ptr = self.buffer.add(offset) as *mut u16;
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
                        let ptr = self.buffer.add(offset) as *mut u32;
                        ptr::write_volatile(ptr, pixel);
                    },
                    PixelFormat::Rgb565 => unsafe {
                        let ptr = self.buffer.add(offset) as *mut u16;
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
        let start_x = char_x * font.width as u32;
        let start_y = char_y * font.height as u32;
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
                let x = start_x + bit_idx as u32;
                if x >= self.width {
                    break;
                }

                // Bit 7 is leftmost pixel
                let is_fg = (row_bits >> (7 - bit_idx)) & 1 == 1;
                let pixel = if is_fg { fg_pixel } else { bg_pixel };
                let offset = row_offset + (x * bpp) as usize;

                match self.format {
                    PixelFormat::Xrgb8888 | PixelFormat::Xbgr8888 => unsafe {
                        let ptr = self.buffer.add(offset) as *mut u32;
                        ptr::write_volatile(ptr, pixel);
                    },
                    PixelFormat::Rgb565 => unsafe {
                        let ptr = self.buffer.add(offset) as *mut u16;
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
    /// Console state (surface + cursor) protected by single mutex
    state: Mutex<GfxConsoleState>,
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
    /// Create a new DRM console
    ///
    /// # Safety
    /// The surface must contain a valid, mapped framebuffer pointer.
    pub unsafe fn new(name: &'static str, surface: ScanoutSurface, font: &'static Font) -> Self {
        let cols = surface.width() / font.width as u32;
        let rows = surface.height() / font.height as u32;

        Self {
            name,
            state: Mutex::new(GfxConsoleState {
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
    fn put_char(&self, ch: u8) {
        let mut state = self.state.lock();

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
                .scroll_up(self.font.height as u32, self.bg_color);
            state.cursor_y = self.rows - 1;
        }
    }

    /// Handle newline
    fn newline(&self) {
        let mut state = self.state.lock();

        state.cursor_x = 0;
        state.cursor_y += 1;

        if state.cursor_y >= self.rows {
            state
                .surface
                .scroll_up(self.font.height as u32, self.bg_color);
            state.cursor_y = self.rows - 1;
        }
    }

    /// Handle carriage return
    fn carriage_return(&self) {
        self.state.lock().cursor_x = 0;
    }

    /// Handle tab
    fn tab(&self) {
        let mut state = self.state.lock();
        let tab_width = 8;
        let new_x = ((state.cursor_x / tab_width) + 1) * tab_width;
        state.cursor_x = new_x.min(self.cols - 1);
    }

    /// Handle backspace
    fn backspace(&self) {
        let mut state = self.state.lock();
        if state.cursor_x > 0 {
            state.cursor_x -= 1;
        }
    }

    /// Write a byte to the console
    fn write_byte(&self, byte: u8) {
        match byte {
            b'\n' => self.newline(),
            b'\r' => self.carriage_return(),
            b'\t' => self.tab(),
            0x08 => self.backspace(), // Backspace
            0x7F => self.backspace(), // Delete (treat as backspace)
            // Printable ASCII characters
            0x20..=0x7E => self.put_char(byte),
            // Extended ASCII (render if font has it)
            0x80..=0xFF => self.put_char(byte),
            // Ignore other control characters
            _ => {}
        }
    }
}

impl ConsoleDriver for GfxConsole {
    fn name(&self) -> &str {
        self.name
    }

    fn write(&self, data: &[u8]) {
        for &byte in data {
            self.write_byte(byte);
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
    use super::BOOT_FRAMEBUFFER;
    use crate::arch::CurrentArch;
    use crate::arch::IoremapOps;

    let Some(fb_info) = BOOT_FRAMEBUFFER.get() else {
        return false;
    };

    // Map the framebuffer
    let fb_ptr = match CurrentArch::ioremap(fb_info.phys_addr, fb_info.size) {
        Ok(ptr) => ptr,
        Err(_) => {
            crate::printkln!("graphics: failed to map framebuffer");
            return false;
        }
    };

    // Create the scanout surface
    // SAFETY: fb_ptr is a valid mapping of the framebuffer returned by ioremap
    let surface = unsafe { ScanoutSurface::new(fb_info, fb_ptr) };

    // Create the console
    // SAFETY: surface contains a valid mapped framebuffer pointer
    let console = unsafe { GfxConsole::new("gfx0", surface, &DEFAULT_FONT) };
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
