//! DRM Mode Setting Objects
//!
//! This module defines the KMS (Kernel Mode Setting) objects:
//! - Connector: physical display output (HDMI, DP, eDP, etc.)
//! - Encoder: converts pixel stream to connector-specific signal
//! - CRTC: scanout engine that reads framebuffer and drives encoder
//! - Framebuffer: pixel buffer for display

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Display mode information
#[derive(Debug, Clone)]
pub struct GfxModeInfo {
    /// Pixel clock in kHz
    pub clock: u32,
    /// Horizontal display size
    pub hdisplay: u32,
    /// Horizontal sync start
    pub hsync_start: u32,
    /// Horizontal sync end
    pub hsync_end: u32,
    /// Horizontal total (including blanking)
    pub htotal: u32,
    /// Vertical display size
    pub vdisplay: u32,
    /// Vertical sync start
    pub vsync_start: u32,
    /// Vertical sync end
    pub vsync_end: u32,
    /// Vertical total (including blanking)
    pub vtotal: u32,
    /// Refresh rate in Hz
    pub vrefresh: u32,
    /// Mode flags (interlace, doublescan, etc.)
    pub flags: u32,
    /// Mode type (preferred, driver, etc.)
    pub type_: u32,
    /// Mode name (e.g., "1920x1080")
    pub name: String,
}

impl GfxModeInfo {
    /// Create a new mode from basic parameters
    pub fn new(width: u32, height: u32, refresh: u32) -> Self {
        // Generate reasonable timing values for the mode
        // These are approximate and work for simple framebuffer display
        let hdisplay = width;
        let vdisplay = height;

        // Simple blanking estimates (not accurate for real hardware)
        let htotal = hdisplay + hdisplay / 10; // ~10% blanking
        let vtotal = vdisplay + vdisplay / 20; // ~5% blanking

        let hsync_start = hdisplay + 10;
        let hsync_end = hsync_start + 40;
        let vsync_start = vdisplay + 3;
        let vsync_end = vsync_start + 6;

        // Calculate pixel clock: pixels * refresh
        let clock = (htotal * vtotal * refresh) / 1000;

        // Generate mode name
        let name = alloc::format!("{}x{}", width, height);

        Self {
            clock,
            hdisplay,
            hsync_start,
            hsync_end,
            htotal,
            vdisplay,
            vsync_start,
            vsync_end,
            vtotal,
            vrefresh: refresh,
            flags: 0,
            type_: 1 << 3, // GFX_MODE_TYPE_PREFERRED
            name,
        }
    }
}

/// DRM Connector - represents a physical display output
#[derive(Debug, Clone)]
pub struct GfxConnector {
    /// Unique connector ID
    pub id: u32,
    /// Connector type (VGA, HDMI, DP, etc.)
    pub connector_type: u32,
    /// Connector type ID (for multiple connectors of same type)
    pub connector_type_id: u32,
    /// Connection status
    pub connection: u32,
    /// Currently attached encoder ID (0 if none)
    pub encoder_id: u32,
    /// List of compatible encoder IDs
    pub encoder_ids: Vec<u32>,
    /// Available display modes
    pub modes: Vec<GfxModeInfo>,
    /// Physical width in mm
    pub mm_width: u32,
    /// Physical height in mm
    pub mm_height: u32,
    /// Subpixel order
    pub subpixel: u32,
}

impl GfxConnector {
    /// Create a new connector
    pub fn new(id: u32, connector_type: u32, connector_type_id: u32) -> Self {
        Self {
            id,
            connector_type,
            connector_type_id,
            connection: super::ioctl::GFX_MODE_DISCONNECTED,
            encoder_id: 0,
            encoder_ids: Vec::new(),
            modes: Vec::new(),
            mm_width: 0,
            mm_height: 0,
            subpixel: 0, // GFX_MODE_SUBPIXEL_UNKNOWN
        }
    }

    /// Set connection status to connected with the given mode
    pub fn set_connected(&mut self, mode: GfxModeInfo) {
        self.connection = super::ioctl::GFX_MODE_CONNECTED;
        self.modes.clear();
        self.modes.push(mode);
    }

    /// Add a compatible encoder
    pub fn add_encoder(&mut self, encoder_id: u32) {
        if !self.encoder_ids.contains(&encoder_id) {
            self.encoder_ids.push(encoder_id);
        }
    }
}

/// DRM Encoder - converts pixel data to connector-specific format
#[derive(Debug, Clone)]
pub struct GfxEncoder {
    /// Unique encoder ID
    pub id: u32,
    /// Encoder type (DAC, TMDS, LVDS, etc.)
    pub encoder_type: u32,
    /// Currently attached CRTC ID (0 if none)
    pub crtc_id: u32,
    /// Bitmask of possible CRTCs
    pub possible_crtcs: u32,
    /// Bitmask of possible clone encoders
    pub possible_clones: u32,
}

impl GfxEncoder {
    /// Create a new encoder
    pub fn new(id: u32, encoder_type: u32) -> Self {
        Self {
            id,
            encoder_type,
            crtc_id: 0,
            possible_crtcs: 0,
            possible_clones: 0,
        }
    }
}

/// DRM CRTC - display controller that scans out framebuffer
#[derive(Debug, Clone)]
pub struct GfxCrtc {
    /// Unique CRTC ID
    pub id: u32,
    /// Currently displayed framebuffer ID (0 if none)
    pub fb_id: u32,
    /// X position in framebuffer
    pub x: u32,
    /// Y position in framebuffer
    pub y: u32,
    /// Gamma table size
    pub gamma_size: u32,
    /// Whether mode is valid
    pub mode_valid: bool,
    /// Current display mode
    pub mode: Option<GfxModeInfo>,
}

impl GfxCrtc {
    /// Create a new CRTC
    pub fn new(id: u32) -> Self {
        Self {
            id,
            fb_id: 0,
            x: 0,
            y: 0,
            gamma_size: 256,
            mode_valid: false,
            mode: None,
        }
    }

    /// Set the active mode and framebuffer
    pub fn set_mode(&mut self, fb_id: u32, mode: GfxModeInfo) {
        self.fb_id = fb_id;
        self.mode_valid = true;
        self.mode = Some(mode);
    }
}

/// DRM Framebuffer - pixel buffer for display
#[derive(Debug, Clone)]
pub struct GfxFramebuffer {
    /// Unique framebuffer ID
    pub id: u32,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bytes per scanline
    pub pitch: u32,
    /// Bits per pixel
    pub bpp: u32,
    /// Color depth
    pub depth: u32,
    /// Handle to backing buffer (GEM handle in real DRM)
    pub handle: u32,
    /// Physical address (for simplegfx)
    pub phys_addr: u64,
}

impl GfxFramebuffer {
    /// Create a new framebuffer
    pub fn new(
        id: u32,
        width: u32,
        height: u32,
        pitch: u32,
        bpp: u32,
        depth: u32,
        handle: u32,
    ) -> Self {
        Self {
            id,
            width,
            height,
            pitch,
            bpp,
            depth,
            handle,
            phys_addr: 0,
        }
    }
}

/// Mode resources - collection of all mode objects
#[derive(Debug, Clone, Default)]
pub struct GfxModeResources {
    /// List of connector IDs
    pub connector_ids: Vec<u32>,
    /// List of encoder IDs
    pub encoder_ids: Vec<u32>,
    /// List of CRTC IDs
    pub crtc_ids: Vec<u32>,
    /// List of framebuffer IDs
    pub fb_ids: Vec<u32>,
    /// Minimum supported width
    pub min_width: u32,
    /// Maximum supported width
    pub max_width: u32,
    /// Minimum supported height
    pub min_height: u32,
    /// Maximum supported height
    pub max_height: u32,
}

impl GfxModeResources {
    /// Create new empty mode resources
    pub fn new() -> Self {
        Self {
            connector_ids: Vec::new(),
            encoder_ids: Vec::new(),
            crtc_ids: Vec::new(),
            fb_ids: Vec::new(),
            min_width: 0,
            max_width: 8192,
            min_height: 0,
            max_height: 8192,
        }
    }
}
