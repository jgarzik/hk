//! DRM Dumb Buffer Management
//!
//! Dumb buffers are simple, CPU-accessible pixel buffers used for
//! basic display operations. They don't require GPU acceleration
//! and are suitable for firmware framebuffers and simple displays.
//!
//! The "dumb buffer" API is the minimum required for basic KMS
//! functionality and is what libdrm uses for simple display apps.

/// Dumb buffer descriptor returned from CREATE_DUMB
#[derive(Debug, Clone, Copy)]
pub struct DumbBuffer {
    /// Handle for this buffer (used in subsequent operations)
    pub handle: u32,
    /// Pitch (bytes per scanline) - may be larger than width * bpp/8
    pub pitch: u32,
    /// Total buffer size in bytes
    pub size: u64,
    /// Physical address (for mmap)
    pub phys_addr: u64,
}

impl DumbBuffer {
    /// Create a new dumb buffer descriptor
    pub fn new(handle: u32, width: u32, height: u32, bpp: u32, phys_addr: u64) -> Self {
        // Calculate pitch (align to 64 bytes for efficiency)
        let bytes_per_pixel = bpp / 8;
        let min_pitch = width * bytes_per_pixel;
        let pitch = (min_pitch + 63) & !63;

        let size = (pitch as u64) * (height as u64);

        Self {
            handle,
            pitch,
            size,
            phys_addr,
        }
    }

    /// Create a dumb buffer with explicit pitch
    pub fn with_pitch(handle: u32, pitch: u32, height: u32, phys_addr: u64) -> Self {
        let size = (pitch as u64) * (height as u64);

        Self {
            handle,
            pitch,
            size,
            phys_addr,
        }
    }
}
