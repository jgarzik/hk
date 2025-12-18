//! SimpleDRM Driver
//!
//! A minimal DRM driver for firmware-provided framebuffers (GOP, DTB simple-fb).
//! This driver assumes the display is already initialized by firmware and
//! simply exposes the framebuffer through the DRM API.
//!
//! ## Architecture
//!
//! SimpleDRM creates a minimal DRM device with:
//! - 1 connector (always connected - display is already active)
//! - 1 encoder (virtual)
//! - 1 CRTC (active with firmware mode)
//! - 1 dumb buffer (the firmware framebuffer itself)
//!
//! This allows userspace to discover the display and render to it
//! via standard DRM/KMS APIs without needing hardware-specific drivers.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

use super::dumb::DumbBuffer;
use super::ioctl::{
    GFX_CAP_DUMB_BUFFER, GFX_CAP_PRIME, GFX_CAP_TIMESTAMP_MONOTONIC, GFX_MODE_CONNECTOR_VIRTUAL,
    GFX_MODE_ENCODER_VIRTUAL,
};
use super::mode::{
    GfxConnector, GfxCrtc, GfxEncoder, GfxFramebuffer, GfxModeInfo, GfxModeResources,
};
use super::{FramebufferInfo, PixelFormat};
use super::{GfxDriver, GfxError};

/// SimpleDRM device state
struct SimpleGfxState {
    /// Mode resources (connectors, encoders, crtcs)
    resources: GfxModeResources,
    /// Single connector
    connector: GfxConnector,
    /// Single encoder
    encoder: GfxEncoder,
    /// Single CRTC
    crtc: GfxCrtc,
    /// Framebuffers (fb_id -> GfxFramebuffer)
    framebuffers: Vec<GfxFramebuffer>,
    /// Next framebuffer ID
    next_fb_id: u32,
    /// The firmware framebuffer info
    fb_info: FramebufferInfo,
    /// Dumb buffer handle counter (for future use)
    #[allow(dead_code)]
    next_handle: u32,
    /// Dumb buffers (handle -> DumbBuffer)
    dumb_buffers: Vec<(u32, DumbBuffer)>,
}

/// SimpleDRM driver for firmware framebuffers
pub struct SimpleGfxDevice {
    /// Driver state protected by mutex
    state: Mutex<SimpleGfxState>,
}

impl SimpleGfxDevice {
    /// Object IDs
    const CONNECTOR_ID: u32 = 1;
    const ENCODER_ID: u32 = 2;
    const CRTC_ID: u32 = 3;
    /// Initial framebuffer ID for the boot framebuffer
    const BOOT_FB_ID: u32 = 1;
    /// Initial dumb buffer handle for the boot framebuffer
    const BOOT_HANDLE: u32 = 1;

    /// Create a new SimpleDRM device from framebuffer info
    pub fn new(fb_info: FramebufferInfo) -> Arc<Self> {
        // Create the display mode from framebuffer info
        let mode = GfxModeInfo::new(fb_info.width, fb_info.height, 60);

        // Create connector (virtual, always connected)
        let mut connector = GfxConnector::new(Self::CONNECTOR_ID, GFX_MODE_CONNECTOR_VIRTUAL, 1);
        connector.set_connected(mode.clone());
        connector.add_encoder(Self::ENCODER_ID);
        connector.encoder_id = Self::ENCODER_ID;

        // Create encoder (virtual)
        let mut encoder = GfxEncoder::new(Self::ENCODER_ID, GFX_MODE_ENCODER_VIRTUAL);
        encoder.crtc_id = Self::CRTC_ID;
        encoder.possible_crtcs = 1; // Can connect to CRTC 0

        // Create CRTC with active mode
        let mut crtc = GfxCrtc::new(Self::CRTC_ID);
        crtc.set_mode(Self::BOOT_FB_ID, mode);

        // Create the boot framebuffer
        let bpp = fb_info.format.bytes_per_pixel() * 8;
        let depth = match fb_info.format {
            PixelFormat::Xrgb8888 | PixelFormat::Xbgr8888 => 24,
            PixelFormat::Rgb565 => 16,
        };
        let mut boot_fb = GfxFramebuffer::new(
            Self::BOOT_FB_ID,
            fb_info.width,
            fb_info.height,
            fb_info.pitch,
            bpp,
            depth,
            Self::BOOT_HANDLE,
        );
        boot_fb.phys_addr = fb_info.phys_addr;

        // Create the boot dumb buffer (represents the firmware framebuffer)
        let boot_dumb = DumbBuffer::with_pitch(
            Self::BOOT_HANDLE,
            fb_info.pitch,
            fb_info.height,
            fb_info.phys_addr,
        );

        // Build resources
        let mut resources = GfxModeResources::new();
        resources.connector_ids.push(Self::CONNECTOR_ID);
        resources.encoder_ids.push(Self::ENCODER_ID);
        resources.crtc_ids.push(Self::CRTC_ID);
        resources.fb_ids.push(Self::BOOT_FB_ID);
        resources.min_width = 1;
        resources.max_width = fb_info.width;
        resources.min_height = 1;
        resources.max_height = fb_info.height;

        let state = SimpleGfxState {
            resources,
            connector,
            encoder,
            crtc,
            framebuffers: vec![boot_fb],
            next_fb_id: Self::BOOT_FB_ID + 1,
            fb_info,
            next_handle: Self::BOOT_HANDLE + 1,
            dumb_buffers: vec![(Self::BOOT_HANDLE, boot_dumb)],
        };

        Arc::new(Self {
            state: Mutex::new(state),
        })
    }
}

impl GfxDriver for SimpleGfxDevice {
    fn name(&self) -> &str {
        "simplegfx"
    }

    fn desc(&self) -> &str {
        "Simple framebuffer DRM driver"
    }

    fn version(&self) -> (u32, u32, u32) {
        (1, 0, 0)
    }

    fn date(&self) -> &str {
        "20240101"
    }

    fn get_cap(&self, cap: u64) -> Result<u64, GfxError> {
        match cap {
            GFX_CAP_DUMB_BUFFER => Ok(1), // We support dumb buffers
            GFX_CAP_PRIME => Ok(0),       // No PRIME support
            GFX_CAP_TIMESTAMP_MONOTONIC => Ok(1),
            _ => Ok(0), // Unknown capability, return 0
        }
    }

    fn get_resources(&self) -> &GfxModeResources {
        // This is a bit awkward - we need to return a reference but
        // the state is behind a mutex. For simplicity, leak a copy.
        // In a real implementation, we'd use a different pattern.
        let state = self.state.lock();
        // SAFETY: This leaks memory, but for a simple driver it's acceptable
        // A real implementation would use Arc or similar
        let resources = state.resources.clone();
        Box::leak(Box::new(resources))
    }

    fn get_connector(&self, id: u32) -> Result<&GfxConnector, GfxError> {
        let state = self.state.lock();
        if id == Self::CONNECTOR_ID {
            // Same leak pattern as get_resources
            let connector = state.connector.clone();
            Ok(Box::leak(Box::new(connector)))
        } else {
            Err(GfxError::NoSuchObject)
        }
    }

    fn get_encoder(&self, id: u32) -> Result<&GfxEncoder, GfxError> {
        let state = self.state.lock();
        if id == Self::ENCODER_ID {
            let encoder = state.encoder.clone();
            Ok(Box::leak(Box::new(encoder)))
        } else {
            Err(GfxError::NoSuchObject)
        }
    }

    fn get_crtc(&self, id: u32) -> Result<&GfxCrtc, GfxError> {
        let state = self.state.lock();
        if id == Self::CRTC_ID {
            let crtc = state.crtc.clone();
            Ok(Box::leak(Box::new(crtc)))
        } else {
            Err(GfxError::NoSuchObject)
        }
    }

    fn set_crtc(
        &self,
        crtc_id: u32,
        fb_id: u32,
        x: u32,
        y: u32,
        _connectors: &[u32],
        mode: Option<&GfxModeInfo>,
    ) -> Result<(), GfxError> {
        let mut state = self.state.lock();

        if crtc_id != Self::CRTC_ID {
            return Err(GfxError::NoSuchObject);
        }

        // Verify framebuffer exists
        if fb_id != 0 && !state.framebuffers.iter().any(|fb| fb.id == fb_id) {
            return Err(GfxError::NoSuchObject);
        }

        state.crtc.fb_id = fb_id;
        state.crtc.x = x;
        state.crtc.y = y;

        if let Some(m) = mode {
            state.crtc.mode = Some(m.clone());
            state.crtc.mode_valid = true;
        }

        Ok(())
    }

    fn add_fb(
        &self,
        width: u32,
        height: u32,
        pitch: u32,
        bpp: u32,
        depth: u32,
        handle: u32,
    ) -> Result<u32, GfxError> {
        let mut state = self.state.lock();

        // Verify handle exists and get phys_addr
        let phys_addr = state
            .dumb_buffers
            .iter()
            .find(|(h, _)| *h == handle)
            .map(|(_, d)| d.phys_addr)
            .ok_or(GfxError::NoSuchObject)?;

        let fb_id = state.next_fb_id;
        state.next_fb_id += 1;

        let mut fb = GfxFramebuffer::new(fb_id, width, height, pitch, bpp, depth, handle);
        fb.phys_addr = phys_addr;

        state.framebuffers.push(fb);
        state.resources.fb_ids.push(fb_id);

        Ok(fb_id)
    }

    fn rm_fb(&self, fb_id: u32) -> Result<(), GfxError> {
        let mut state = self.state.lock();

        // Can't remove boot framebuffer
        if fb_id == Self::BOOT_FB_ID {
            return Err(GfxError::Busy);
        }

        let pos = state
            .framebuffers
            .iter()
            .position(|fb| fb.id == fb_id)
            .ok_or(GfxError::NoSuchObject)?;

        state.framebuffers.remove(pos);
        state.resources.fb_ids.retain(|&id| id != fb_id);

        Ok(())
    }

    fn create_dumb(&self, width: u32, height: u32, bpp: u32) -> Result<DumbBuffer, GfxError> {
        let state = self.state.lock();

        // SimpleDRM only supports one buffer - the firmware framebuffer
        // For MVP, we return the boot buffer if dimensions match
        if width == state.fb_info.width
            && height == state.fb_info.height
            && bpp == state.fb_info.format.bytes_per_pixel() * 8
        {
            // Return the boot buffer
            if let Some((_, dumb)) = state.dumb_buffers.first() {
                return Ok(*dumb);
            }
        }

        // For non-matching dimensions, we could allocate from heap
        // but for MVP, just fail
        Err(GfxError::NoMemory)
    }

    fn map_dumb(&self, handle: u32) -> Result<u64, GfxError> {
        let state = self.state.lock();

        let dumb = state
            .dumb_buffers
            .iter()
            .find(|(h, _)| *h == handle)
            .map(|(_, d)| d)
            .ok_or(GfxError::NoSuchObject)?;

        // Return the physical address as the mmap offset
        // The actual mmap implementation will use this to set up the mapping
        Ok(dumb.phys_addr)
    }

    fn destroy_dumb(&self, handle: u32) -> Result<(), GfxError> {
        let mut state = self.state.lock();

        // Can't destroy boot buffer
        if handle == Self::BOOT_HANDLE {
            return Err(GfxError::Busy);
        }

        let pos = state
            .dumb_buffers
            .iter()
            .position(|(h, _)| *h == handle)
            .ok_or(GfxError::NoSuchObject)?;

        state.dumb_buffers.remove(pos);
        Ok(())
    }

    fn get_fb_mmap_info(&self, offset: u64) -> Option<(u64, u64)> {
        let state = self.state.lock();

        // Find the dumb buffer with matching physical address
        for (_, dumb) in &state.dumb_buffers {
            if dumb.phys_addr == offset {
                return Some((dumb.phys_addr, dumb.size));
            }
        }

        None
    }
}

/// Initialize SimpleDRM with the boot framebuffer
///
/// Returns the minor number of the created device, or None if no framebuffer.
pub fn init_simplegfx() -> Option<u32> {
    use super::BOOT_FRAMEBUFFER;

    let fb_info = *BOOT_FRAMEBUFFER.get()?;

    crate::printkln!(
        "simplegfx: initializing with {}x{} framebuffer at {:#x}",
        fb_info.width,
        fb_info.height,
        fb_info.phys_addr
    );

    let device = SimpleGfxDevice::new(fb_info);
    let minor = super::register_gfx_device(device).ok()?;

    Some(minor)
}
