//! Direct Rendering Manager (DRM) Subsystem
//!
//! This module implements a minimal DRM/KMS subsystem for Linux userland ABI
//! compatibility. It provides the infrastructure for graphics drivers to expose
//! display hardware to userspace via /dev/dri/cardX.
//!
//! ## Architecture
//!
//! ```text
//! Firmware (GRUB/DTB) → FramebufferInfo
//!                         ↓
//! Userspace (libdrm) → /dev/dri/cardX
//!                         ↓
//!                   SimpleDRM Driver
//!                         ↓
//!                   DRM Text Console → ConsoleDriver
//!                         ↓
//!                   Screen Output
//! ```
//!
//! ## Minimum ioctls for dumb buffer path
//!
//! - GFX_IOCTL_VERSION
//! - GFX_IOCTL_GET_CAP
//! - GFX_IOCTL_MODE_GETRESOURCES
//! - GFX_IOCTL_MODE_GETCONNECTOR
//! - GFX_IOCTL_MODE_GETENCODER
//! - GFX_IOCTL_MODE_GETCRTC
//! - GFX_IOCTL_MODE_SETCRTC
//! - GFX_IOCTL_MODE_ADDFB
//! - GFX_IOCTL_MODE_RMFB
//! - GFX_IOCTL_MODE_CREATE_DUMB
//! - GFX_IOCTL_MODE_MAP_DUMB
//! - GFX_IOCTL_MODE_DESTROY_DUMB

extern crate alloc;

pub mod console;
pub mod dumb;
pub mod font;
pub mod ioctl;
pub mod mode;
pub mod simplegfx;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

use crate::chardev::{CharDevice, DevId, DeviceError};

/// DRM major device number (Linux convention)
pub const GFX_MAJOR: u16 = 226;

// Add DRI to chardev major module
pub mod gfx_major {
    /// DRI (Direct Rendering Infrastructure) major number
    pub const DRI: u16 = 226;
}

/// DRM driver error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfxError {
    /// Invalid argument
    InvalidArg,
    /// Resource not found
    NotFound,
    /// Out of memory
    NoMemory,
    /// Operation not supported
    NotSupported,
    /// Device busy
    Busy,
    /// Permission denied
    PermissionDenied,
    /// Invalid ioctl
    InvalidIoctl,
    /// No such connector/crtc/encoder/framebuffer
    NoSuchObject,
}

impl From<GfxError> for DeviceError {
    fn from(e: GfxError) -> Self {
        match e {
            GfxError::InvalidArg => DeviceError::InvalidArg,
            GfxError::NotFound => DeviceError::NotFound,
            GfxError::NoMemory => DeviceError::IoError,
            GfxError::NotSupported => DeviceError::NotSupported,
            GfxError::Busy => DeviceError::IoError,
            GfxError::PermissionDenied => DeviceError::IoError,
            GfxError::InvalidIoctl => DeviceError::NotSupported,
            GfxError::NoSuchObject => DeviceError::NotFound,
        }
    }
}

/// DRM driver trait
///
/// Drivers implement this trait to provide hardware-specific functionality.
/// The core DRM subsystem handles ioctl dispatch and object management.
pub trait GfxDriver: Send + Sync {
    /// Driver name (e.g., "simplegfx")
    fn name(&self) -> &str;

    /// Driver description
    fn desc(&self) -> &str;

    /// Driver version (major, minor, patchlevel)
    fn version(&self) -> (u32, u32, u32);

    /// Driver date string (e.g., "20231201")
    fn date(&self) -> &str;

    /// Get driver capabilities
    fn get_cap(&self, cap: u64) -> Result<u64, GfxError>;

    /// Get mode resources (connectors, crtcs, encoders, framebuffers)
    fn get_resources(&self) -> &mode::GfxModeResources;

    /// Get connector info by ID
    fn get_connector(&self, id: u32) -> Result<&mode::GfxConnector, GfxError>;

    /// Get encoder info by ID
    fn get_encoder(&self, id: u32) -> Result<&mode::GfxEncoder, GfxError>;

    /// Get CRTC info by ID
    fn get_crtc(&self, id: u32) -> Result<&mode::GfxCrtc, GfxError>;

    /// Set CRTC mode and framebuffer
    fn set_crtc(
        &self,
        crtc_id: u32,
        fb_id: u32,
        x: u32,
        y: u32,
        connectors: &[u32],
        mode: Option<&mode::GfxModeInfo>,
    ) -> Result<(), GfxError>;

    /// Add a framebuffer
    fn add_fb(
        &self,
        width: u32,
        height: u32,
        pitch: u32,
        bpp: u32,
        depth: u32,
        handle: u32,
    ) -> Result<u32, GfxError>;

    /// Remove a framebuffer
    fn rm_fb(&self, fb_id: u32) -> Result<(), GfxError>;

    /// Create a dumb buffer
    fn create_dumb(&self, width: u32, height: u32, bpp: u32) -> Result<dumb::DumbBuffer, GfxError>;

    /// Map a dumb buffer (returns offset for mmap)
    fn map_dumb(&self, handle: u32) -> Result<u64, GfxError>;

    /// Destroy a dumb buffer
    fn destroy_dumb(&self, handle: u32) -> Result<(), GfxError>;

    /// Get framebuffer physical address for mmap
    fn get_fb_mmap_info(&self, offset: u64) -> Option<(u64, u64)>;
}

/// DRM character device wrapper
///
/// Implements CharDevice for a DRM driver, providing ioctl dispatch.
pub struct GfxCharDevice {
    /// The underlying DRM driver
    driver: Arc<dyn GfxDriver>,
    /// Device minor number
    minor: u32,
    /// Device name (e.g., "card0")
    name: String,
}

impl GfxCharDevice {
    /// Create a new DRM character device
    pub fn new(driver: Arc<dyn GfxDriver>, minor: u32) -> Self {
        Self {
            driver,
            minor,
            name: alloc::format!("card{}", minor),
        }
    }

    /// Get the minor number
    pub fn minor(&self) -> u32 {
        self.minor
    }

    /// Handle DRM ioctl
    fn handle_ioctl(&self, cmd: u32, arg: u64) -> Result<i64, GfxError> {
        ioctl::dispatch_ioctl(&*self.driver, cmd, arg)
    }
}

impl CharDevice for GfxCharDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn read(&self, _buf: &mut [u8]) -> Result<usize, DeviceError> {
        // DRM devices don't support read
        Err(DeviceError::NotSupported)
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, DeviceError> {
        // DRM devices don't support write
        Err(DeviceError::NotSupported)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, DeviceError> {
        self.handle_ioctl(cmd, arg).map_err(|e| e.into())
    }
}

/// Global DRM device registry
static GFX_DEVICES: RwLock<Vec<Arc<GfxCharDevice>>> = RwLock::new(Vec::new());

/// Next available minor number
static NEXT_MINOR: Mutex<u32> = Mutex::new(0);

/// Register a DRM driver
///
/// Creates a character device /dev/dri/cardN and returns the minor number.
pub fn register_gfx_device(driver: Arc<dyn GfxDriver>) -> Result<u32, GfxError> {
    let minor = {
        let mut next = NEXT_MINOR.lock();
        let m = *next;
        *next += 1;
        m
    };

    let chardev = Arc::new(GfxCharDevice::new(driver, minor));
    let dev_id = DevId::new(GFX_MAJOR, minor as u16);

    // Register with character device subsystem
    crate::chardev::register_chardev(dev_id, chardev.clone()).map_err(|_| GfxError::NoMemory)?;

    // Add to our registry
    GFX_DEVICES.write().push(chardev);

    crate::printkln!(
        "gfx: registered {} (card{})",
        GFX_DEVICES.read().last().unwrap().driver.name(),
        minor
    );

    Ok(minor)
}

/// Get a DRM device by minor number
pub fn get_gfx_device(minor: u32) -> Option<Arc<GfxCharDevice>> {
    GFX_DEVICES
        .read()
        .iter()
        .find(|d| d.minor == minor)
        .cloned()
}

/// Initialize the DRM subsystem
pub fn init() {
    crate::printkln!("gfx: subsystem initialized");
}

// ============================================================================
// Framebuffer Types (from graphics module)
// ============================================================================

/// Pixel format enumeration
///
/// Describes the byte order and bit layout of pixels in the framebuffer.
/// These match common firmware framebuffer formats from UEFI GOP and
/// device tree simple-framebuffer nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit XRGB: 0x00RRGGBB (X ignored, then R, G, B)
    /// Most common format from UEFI GOP
    Xrgb8888,
    /// 32-bit XBGR: 0x00BBGGRR (X ignored, then B, G, R)
    Xbgr8888,
    /// 16-bit RGB565: RRRRRGGGGGGBBBBB
    Rgb565,
}

impl PixelFormat {
    /// Get bytes per pixel for this format
    pub const fn bytes_per_pixel(&self) -> u32 {
        match self {
            PixelFormat::Xrgb8888 | PixelFormat::Xbgr8888 => 4,
            PixelFormat::Rgb565 => 2,
        }
    }
}

/// Framebuffer information descriptor
///
/// Platform-agnostic representation of a firmware-provided framebuffer.
/// Can be populated from:
/// - Multiboot2 framebuffer tag (x86-64)
/// - Device tree simple-framebuffer node (aarch64)
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical base address of framebuffer memory
    pub phys_addr: u64,
    /// Total size in bytes
    pub size: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Pitch (bytes per scanline)
    /// NOTE: Never assume pitch == width * bytes_per_pixel
    pub pitch: u32,
    /// Pixel format
    pub format: PixelFormat,
}

impl FramebufferInfo {
    /// Create a new framebuffer info descriptor
    pub const fn new(
        phys_addr: u64,
        size: u64,
        width: u32,
        height: u32,
        pitch: u32,
        format: PixelFormat,
    ) -> Self {
        Self {
            phys_addr,
            size,
            width,
            height,
            pitch,
            format,
        }
    }

    /// Calculate console dimensions in characters for a given font size
    #[allow(dead_code)]
    pub const fn console_dimensions(&self, font_width: u32, font_height: u32) -> (u32, u32) {
        let cols = self.width / font_width;
        let rows = self.height / font_height;
        (cols, rows)
    }
}

/// Global boot framebuffer info
///
/// Set during early boot when parsing multiboot2 (x86-64) or device tree (aarch64).
/// Used by SimpleDRM and graphics console initialization.
pub static BOOT_FRAMEBUFFER: spin::Once<FramebufferInfo> = spin::Once::new();

/// Check if a boot framebuffer is available
#[allow(dead_code)]
pub fn has_boot_framebuffer() -> bool {
    BOOT_FRAMEBUFFER.get().is_some()
}

/// Get the boot framebuffer info if available
#[allow(dead_code)]
pub fn get_boot_framebuffer() -> Option<&'static FramebufferInfo> {
    BOOT_FRAMEBUFFER.get()
}

/// RGB color representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Standard VGA colors
    pub const BLACK: Color = Color::new(0, 0, 0);
    pub const WHITE: Color = Color::new(255, 255, 255);
    #[allow(dead_code)]
    pub const RED: Color = Color::new(255, 0, 0);
    #[allow(dead_code)]
    pub const GREEN: Color = Color::new(0, 255, 0);
    #[allow(dead_code)]
    pub const BLUE: Color = Color::new(0, 0, 255);
    #[allow(dead_code)]
    pub const CYAN: Color = Color::new(0, 255, 255);
    #[allow(dead_code)]
    pub const MAGENTA: Color = Color::new(255, 0, 255);
    #[allow(dead_code)]
    pub const YELLOW: Color = Color::new(255, 255, 0);

    /// Light variants for bright colors
    #[allow(dead_code)]
    pub const BRIGHT_BLACK: Color = Color::new(85, 85, 85);
    #[allow(dead_code)]
    pub const BRIGHT_WHITE: Color = Color::new(255, 255, 255);
    #[allow(dead_code)]
    pub const BRIGHT_RED: Color = Color::new(255, 85, 85);
    #[allow(dead_code)]
    pub const BRIGHT_GREEN: Color = Color::new(85, 255, 85);
    #[allow(dead_code)]
    pub const BRIGHT_BLUE: Color = Color::new(85, 85, 255);
    #[allow(dead_code)]
    pub const BRIGHT_CYAN: Color = Color::new(85, 255, 255);
    #[allow(dead_code)]
    pub const BRIGHT_MAGENTA: Color = Color::new(255, 85, 255);
    #[allow(dead_code)]
    pub const BRIGHT_YELLOW: Color = Color::new(255, 255, 85);

    /// Convert to pixel value for given format
    pub const fn to_pixel(&self, format: PixelFormat) -> u32 {
        match format {
            PixelFormat::Xrgb8888 => {
                ((self.r as u32) << 16) | ((self.g as u32) << 8) | (self.b as u32)
            }
            PixelFormat::Xbgr8888 => {
                ((self.b as u32) << 16) | ((self.g as u32) << 8) | (self.r as u32)
            }
            PixelFormat::Rgb565 => {
                (((self.r as u32) >> 3) << 11)
                    | (((self.g as u32) >> 2) << 5)
                    | ((self.b as u32) >> 3)
            }
        }
    }
}
