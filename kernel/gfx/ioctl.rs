//! DRM ioctl definitions and dispatch
//!
//! This module defines the DRM ioctl command numbers following the Linux ABI
//! and implements the dispatch logic for the dumb buffer path.

use alloc::string::ToString;

use super::mode::GfxModeInfo;
use super::{GfxDriver, GfxError};
use core::mem::size_of;

/// DRM ioctl base (from Linux)
const GFX_IOCTL_BASE: u8 = b'd';

/// Build a DRM ioctl number
#[allow(dead_code)]
const fn gfx_io(nr: u8) -> u32 {
    // _IO('d', nr)
    ((GFX_IOCTL_BASE as u32) << 8) | (nr as u32)
}

#[allow(dead_code)]
const fn gfx_ior<T>(nr: u8) -> u32 {
    // _IOR('d', nr, type) - direction bit 2 (read from kernel)
    let size = size_of::<T>() as u32;
    (2 << 30) | ((GFX_IOCTL_BASE as u32) << 8) | (nr as u32) | (size << 16)
}

#[allow(dead_code)]
const fn gfx_iow<T>(nr: u8) -> u32 {
    // _IOW('d', nr, type) - direction bit 1 (write to kernel)
    let size = size_of::<T>() as u32;
    (1 << 30) | ((GFX_IOCTL_BASE as u32) << 8) | (nr as u32) | (size << 16)
}

const fn gfx_iowr<T>(nr: u8) -> u32 {
    // _IOWR('d', nr, type) - direction bits 3 (read/write)
    let size = size_of::<T>() as u32;
    (3 << 30) | ((GFX_IOCTL_BASE as u32) << 8) | (nr as u32) | (size << 16)
}

// DRM ioctl command numbers (Linux ABI)

/// Get driver version
pub const GFX_IOCTL_VERSION: u32 = gfx_iowr::<GfxVersion>(0x00);

/// Get capabilities
pub const GFX_IOCTL_GET_CAP: u32 = gfx_iowr::<GfxGetCap>(0x0c);

/// Get mode resources
pub const GFX_IOCTL_MODE_GETRESOURCES: u32 = gfx_iowr::<GfxModeCardRes>(0xa0);

/// Get CRTC info
pub const GFX_IOCTL_MODE_GETCRTC: u32 = gfx_iowr::<GfxModeCrtc>(0xa1);

/// Set CRTC
pub const GFX_IOCTL_MODE_SETCRTC: u32 = gfx_iowr::<GfxModeCrtc>(0xa2);

/// Get encoder info
pub const GFX_IOCTL_MODE_GETENCODER: u32 = gfx_iowr::<GfxModeGetEncoder>(0xa6);

/// Get connector info
pub const GFX_IOCTL_MODE_GETCONNECTOR: u32 = gfx_iowr::<GfxModeGetConnector>(0xa7);

/// Add framebuffer
pub const GFX_IOCTL_MODE_ADDFB: u32 = gfx_iowr::<GfxModeFbCmd>(0xae);

/// Remove framebuffer
pub const GFX_IOCTL_MODE_RMFB: u32 = gfx_iowr::<u32>(0xaf);

/// Create dumb buffer
pub const GFX_IOCTL_MODE_CREATE_DUMB: u32 = gfx_iowr::<GfxModeCreateDumb>(0xb2);

/// Map dumb buffer
pub const GFX_IOCTL_MODE_MAP_DUMB: u32 = gfx_iowr::<GfxModeMapDumb>(0xb3);

/// Destroy dumb buffer
pub const GFX_IOCTL_MODE_DESTROY_DUMB: u32 = gfx_iowr::<GfxModeDestroyDumb>(0xb4);

// Capability constants
pub const GFX_CAP_DUMB_BUFFER: u64 = 0x1;
pub const GFX_CAP_PRIME: u64 = 0x5;
pub const GFX_CAP_TIMESTAMP_MONOTONIC: u64 = 0x6;

// Connector status
pub const GFX_MODE_CONNECTED: u32 = 1;
pub const GFX_MODE_DISCONNECTED: u32 = 2;
pub const GFX_MODE_UNKNOWNCONNECTION: u32 = 3;

// Connector types (names match Linux DRM header for ABI compatibility)
#[allow(non_upper_case_globals, dead_code)]
pub const GFX_MODE_CONNECTOR_Unknown: u32 = 0;
#[allow(dead_code)]
pub const GFX_MODE_CONNECTOR_VGA: u32 = 1;
#[allow(dead_code)]
pub const GFX_MODE_CONNECTOR_DVII: u32 = 2;
#[allow(dead_code)]
pub const GFX_MODE_CONNECTOR_DVID: u32 = 3;
#[allow(dead_code)]
pub const GFX_MODE_CONNECTOR_DVIA: u32 = 4;
#[allow(non_upper_case_globals, dead_code)]
pub const GFX_MODE_CONNECTOR_Composite: u32 = 5;
#[allow(dead_code)]
pub const GFX_MODE_CONNECTOR_SVIDEO: u32 = 6;
#[allow(dead_code)]
pub const GFX_MODE_CONNECTOR_LVDS: u32 = 7;
#[allow(non_upper_case_globals, dead_code)]
pub const GFX_MODE_CONNECTOR_Component: u32 = 8;
#[allow(non_upper_case_globals, dead_code)]
pub const GFX_MODE_CONNECTOR_9PinDIN: u32 = 9;
#[allow(non_upper_case_globals, dead_code)]
pub const GFX_MODE_CONNECTOR_DisplayPort: u32 = 10;
#[allow(dead_code)]
pub const GFX_MODE_CONNECTOR_HDMIA: u32 = 11;
#[allow(dead_code)]
pub const GFX_MODE_CONNECTOR_HDMIB: u32 = 12;
#[allow(dead_code)]
pub const GFX_MODE_CONNECTOR_TV: u32 = 13;
#[allow(non_upper_case_globals, dead_code)]
pub const GFX_MODE_CONNECTOR_eDP: u32 = 14;
pub const GFX_MODE_CONNECTOR_VIRTUAL: u32 = 15;

// Encoder types
#[allow(dead_code)]
pub const GFX_MODE_ENCODER_NONE: u32 = 0;
pub const GFX_MODE_ENCODER_DAC: u32 = 1;
pub const GFX_MODE_ENCODER_TMDS: u32 = 2;
pub const GFX_MODE_ENCODER_LVDS: u32 = 3;
pub const GFX_MODE_ENCODER_TVDAC: u32 = 4;
pub const GFX_MODE_ENCODER_VIRTUAL: u32 = 5;

/// DRM version structure (matches Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxVersion {
    pub version_major: i32,
    pub version_minor: i32,
    pub version_patchlevel: i32,
    pub name_len: u64,
    pub name: u64, // pointer
    pub date_len: u64,
    pub date: u64, // pointer
    pub desc_len: u64,
    pub desc: u64, // pointer
}

/// DRM get capability structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxGetCap {
    pub capability: u64,
    pub value: u64,
}

/// Mode info structure (matches Linux gfx_mode_modeinfo)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxModeModeinfo {
    pub clock: u32,
    pub hdisplay: u16,
    pub hsync_start: u16,
    pub hsync_end: u16,
    pub htotal: u16,
    pub hskew: u16,
    pub vdisplay: u16,
    pub vsync_start: u16,
    pub vsync_end: u16,
    pub vtotal: u16,
    pub vscan: u16,
    pub vrefresh: u32,
    pub flags: u32,
    pub type_: u32,
    pub name: [u8; 32],
}

impl From<&GfxModeInfo> for GfxModeModeinfo {
    fn from(m: &GfxModeInfo) -> Self {
        let mut name = [0u8; 32];
        let name_bytes = m.name.as_bytes();
        let copy_len = name_bytes.len().min(31);
        name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        Self {
            clock: m.clock,
            hdisplay: m.hdisplay as u16,
            hsync_start: m.hsync_start as u16,
            hsync_end: m.hsync_end as u16,
            htotal: m.htotal as u16,
            hskew: 0,
            vdisplay: m.vdisplay as u16,
            vsync_start: m.vsync_start as u16,
            vsync_end: m.vsync_end as u16,
            vtotal: m.vtotal as u16,
            vscan: 0,
            vrefresh: m.vrefresh,
            flags: m.flags,
            type_: m.type_,
            name,
        }
    }
}

/// Mode card resources structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxModeCardRes {
    pub fb_id_ptr: u64,
    pub crtc_id_ptr: u64,
    pub connector_id_ptr: u64,
    pub encoder_id_ptr: u64,
    pub count_fbs: u32,
    pub count_crtcs: u32,
    pub count_connectors: u32,
    pub count_encoders: u32,
    pub min_width: u32,
    pub max_width: u32,
    pub min_height: u32,
    pub max_height: u32,
}

/// Mode CRTC structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxModeCrtc {
    pub set_connectors_ptr: u64,
    pub count_connectors: u32,
    pub crtc_id: u32,
    pub fb_id: u32,
    pub x: u32,
    pub y: u32,
    pub gamma_size: u32,
    pub mode_valid: u32,
    pub mode: GfxModeModeinfo,
}

/// Mode get encoder structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxModeGetEncoder {
    pub encoder_id: u32,
    pub encoder_type: u32,
    pub crtc_id: u32,
    pub possible_crtcs: u32,
    pub possible_clones: u32,
}

/// Mode get connector structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxModeGetConnector {
    pub encoders_ptr: u64,
    pub modes_ptr: u64,
    pub props_ptr: u64,
    pub prop_values_ptr: u64,
    pub count_modes: u32,
    pub count_props: u32,
    pub count_encoders: u32,
    pub encoder_id: u32,
    pub connector_id: u32,
    pub connector_type: u32,
    pub connector_type_id: u32,
    pub connection: u32,
    pub mm_width: u32,
    pub mm_height: u32,
    pub subpixel: u32,
    pub pad: u32,
}

/// Framebuffer command structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxModeFbCmd {
    pub fb_id: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
    pub depth: u32,
    pub handle: u32,
}

/// Create dumb buffer structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxModeCreateDumb {
    pub height: u32,
    pub width: u32,
    pub bpp: u32,
    pub flags: u32,
    pub handle: u32,
    pub pitch: u32,
    pub size: u64,
}

/// Map dumb buffer structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxModeMapDumb {
    pub handle: u32,
    pub pad: u32,
    pub offset: u64,
}

/// Destroy dumb buffer structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GfxModeDestroyDumb {
    pub handle: u32,
}

/// Extract the ioctl number from a command
fn ioctl_nr(cmd: u32) -> u8 {
    (cmd & 0xff) as u8
}

/// Dispatch a DRM ioctl to the appropriate handler
pub fn dispatch_ioctl(driver: &dyn GfxDriver, cmd: u32, arg: u64) -> Result<i64, GfxError> {
    let nr = ioctl_nr(cmd);

    match nr {
        0x00 => handle_version(driver, arg),
        0x0c => handle_get_cap(driver, arg),
        0xa0 => handle_getresources(driver, arg),
        0xa1 => handle_getcrtc(driver, arg),
        0xa2 => handle_setcrtc(driver, arg),
        0xa6 => handle_getencoder(driver, arg),
        0xa7 => handle_getconnector(driver, arg),
        0xae => handle_addfb(driver, arg),
        0xaf => handle_rmfb(driver, arg),
        0xb2 => handle_create_dumb(driver, arg),
        0xb3 => handle_map_dumb(driver, arg),
        0xb4 => handle_destroy_dumb(driver, arg),
        _ => Err(GfxError::InvalidIoctl),
    }
}

/// Handle GFX_IOCTL_VERSION
fn handle_version(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxVersion;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let (major, minor, patch) = driver.version();

    // Read current struct to get buffer pointers
    let mut ver = unsafe { core::ptr::read(ptr) };

    ver.version_major = major as i32;
    ver.version_minor = minor as i32;
    ver.version_patchlevel = patch as i32;

    // Copy name if buffer provided
    let name = driver.name();
    if ver.name != 0 && ver.name_len > 0 {
        let copy_len = (ver.name_len as usize).min(name.len());
        unsafe {
            core::ptr::copy_nonoverlapping(name.as_ptr(), ver.name as *mut u8, copy_len);
        }
    }
    ver.name_len = name.len() as u64;

    // Copy date if buffer provided
    let date = driver.date();
    if ver.date != 0 && ver.date_len > 0 {
        let copy_len = (ver.date_len as usize).min(date.len());
        unsafe {
            core::ptr::copy_nonoverlapping(date.as_ptr(), ver.date as *mut u8, copy_len);
        }
    }
    ver.date_len = date.len() as u64;

    // Copy desc if buffer provided
    let desc = driver.desc();
    if ver.desc != 0 && ver.desc_len > 0 {
        let copy_len = (ver.desc_len as usize).min(desc.len());
        unsafe {
            core::ptr::copy_nonoverlapping(desc.as_ptr(), ver.desc as *mut u8, copy_len);
        }
    }
    ver.desc_len = desc.len() as u64;

    unsafe { core::ptr::write(ptr, ver) };
    Ok(0)
}

/// Handle GFX_IOCTL_GET_CAP
fn handle_get_cap(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxGetCap;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let mut cap = unsafe { core::ptr::read(ptr) };
    cap.value = driver.get_cap(cap.capability)?;
    unsafe { core::ptr::write(ptr, cap) };
    Ok(0)
}

/// Handle GFX_IOCTL_MODE_GETRESOURCES
fn handle_getresources(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxModeCardRes;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let resources = driver.get_resources();
    let mut res = unsafe { core::ptr::read(ptr) };

    // Copy connector IDs if buffer provided
    if res.connector_id_ptr != 0 && res.count_connectors > 0 {
        let copy_count = (res.count_connectors as usize).min(resources.connector_ids.len());
        let dst = res.connector_id_ptr as *mut u32;
        for i in 0..copy_count {
            unsafe { *dst.add(i) = resources.connector_ids[i] };
        }
    }
    res.count_connectors = resources.connector_ids.len() as u32;

    // Copy CRTC IDs if buffer provided
    if res.crtc_id_ptr != 0 && res.count_crtcs > 0 {
        let copy_count = (res.count_crtcs as usize).min(resources.crtc_ids.len());
        let dst = res.crtc_id_ptr as *mut u32;
        for i in 0..copy_count {
            unsafe { *dst.add(i) = resources.crtc_ids[i] };
        }
    }
    res.count_crtcs = resources.crtc_ids.len() as u32;

    // Copy encoder IDs if buffer provided
    if res.encoder_id_ptr != 0 && res.count_encoders > 0 {
        let copy_count = (res.count_encoders as usize).min(resources.encoder_ids.len());
        let dst = res.encoder_id_ptr as *mut u32;
        for i in 0..copy_count {
            unsafe { *dst.add(i) = resources.encoder_ids[i] };
        }
    }
    res.count_encoders = resources.encoder_ids.len() as u32;

    // Copy FB IDs if buffer provided
    if res.fb_id_ptr != 0 && res.count_fbs > 0 {
        let copy_count = (res.count_fbs as usize).min(resources.fb_ids.len());
        let dst = res.fb_id_ptr as *mut u32;
        for i in 0..copy_count {
            unsafe { *dst.add(i) = resources.fb_ids[i] };
        }
    }
    res.count_fbs = resources.fb_ids.len() as u32;

    res.min_width = resources.min_width;
    res.max_width = resources.max_width;
    res.min_height = resources.min_height;
    res.max_height = resources.max_height;

    unsafe { core::ptr::write(ptr, res) };
    Ok(0)
}

/// Handle GFX_IOCTL_MODE_GETCRTC
fn handle_getcrtc(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxModeCrtc;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let mut crtc_cmd = unsafe { core::ptr::read(ptr) };
    let crtc = driver.get_crtc(crtc_cmd.crtc_id)?;

    crtc_cmd.fb_id = crtc.fb_id;
    crtc_cmd.x = crtc.x;
    crtc_cmd.y = crtc.y;
    crtc_cmd.gamma_size = crtc.gamma_size;
    crtc_cmd.mode_valid = if crtc.mode_valid { 1 } else { 0 };

    if let Some(ref mode) = crtc.mode {
        crtc_cmd.mode = GfxModeModeinfo::from(mode);
    }

    unsafe { core::ptr::write(ptr, crtc_cmd) };
    Ok(0)
}

/// Handle GFX_IOCTL_MODE_SETCRTC
fn handle_setcrtc(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxModeCrtc;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let crtc_cmd = unsafe { core::ptr::read(ptr) };

    // Read connector IDs
    let mut connectors = alloc::vec::Vec::new();
    if crtc_cmd.count_connectors > 0 && crtc_cmd.set_connectors_ptr != 0 {
        let src = crtc_cmd.set_connectors_ptr as *const u32;
        for i in 0..crtc_cmd.count_connectors {
            connectors.push(unsafe { *src.add(i as usize) });
        }
    }

    // Convert mode if valid
    let mode = if crtc_cmd.mode_valid != 0 {
        Some(modeinfo_to_drmmode(&crtc_cmd.mode))
    } else {
        None
    };

    driver
        .set_crtc(
            crtc_cmd.crtc_id,
            crtc_cmd.fb_id,
            crtc_cmd.x,
            crtc_cmd.y,
            &connectors,
            mode.as_ref(),
        )
        .map(|()| 0)
}

/// Handle GFX_IOCTL_MODE_GETENCODER
fn handle_getencoder(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxModeGetEncoder;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let mut enc_cmd = unsafe { core::ptr::read(ptr) };
    let encoder = driver.get_encoder(enc_cmd.encoder_id)?;

    enc_cmd.encoder_type = encoder.encoder_type;
    enc_cmd.crtc_id = encoder.crtc_id;
    enc_cmd.possible_crtcs = encoder.possible_crtcs;
    enc_cmd.possible_clones = encoder.possible_clones;

    unsafe { core::ptr::write(ptr, enc_cmd) };
    Ok(0)
}

/// Handle GFX_IOCTL_MODE_GETCONNECTOR
fn handle_getconnector(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxModeGetConnector;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let mut conn_cmd = unsafe { core::ptr::read(ptr) };
    let connector = driver.get_connector(conn_cmd.connector_id)?;

    // Copy modes if buffer provided
    if conn_cmd.modes_ptr != 0 && conn_cmd.count_modes > 0 {
        let copy_count = (conn_cmd.count_modes as usize).min(connector.modes.len());
        let dst = conn_cmd.modes_ptr as *mut GfxModeModeinfo;
        for i in 0..copy_count {
            let mode_info = GfxModeModeinfo::from(&connector.modes[i]);
            unsafe { *dst.add(i) = mode_info };
        }
    }
    conn_cmd.count_modes = connector.modes.len() as u32;

    // Copy encoder IDs if buffer provided
    if conn_cmd.encoders_ptr != 0 && conn_cmd.count_encoders > 0 {
        let copy_count = (conn_cmd.count_encoders as usize).min(connector.encoder_ids.len());
        let dst = conn_cmd.encoders_ptr as *mut u32;
        for i in 0..copy_count {
            unsafe { *dst.add(i) = connector.encoder_ids[i] };
        }
    }
    conn_cmd.count_encoders = connector.encoder_ids.len() as u32;

    conn_cmd.encoder_id = connector.encoder_id;
    conn_cmd.connector_type = connector.connector_type;
    conn_cmd.connector_type_id = connector.connector_type_id;
    conn_cmd.connection = connector.connection;
    conn_cmd.mm_width = connector.mm_width;
    conn_cmd.mm_height = connector.mm_height;
    conn_cmd.subpixel = connector.subpixel;
    conn_cmd.count_props = 0; // No properties for now

    unsafe { core::ptr::write(ptr, conn_cmd) };
    Ok(0)
}

/// Handle GFX_IOCTL_MODE_ADDFB
fn handle_addfb(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxModeFbCmd;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let mut fb_cmd = unsafe { core::ptr::read(ptr) };
    let fb_id = driver.add_fb(
        fb_cmd.width,
        fb_cmd.height,
        fb_cmd.pitch,
        fb_cmd.bpp,
        fb_cmd.depth,
        fb_cmd.handle,
    )?;
    fb_cmd.fb_id = fb_id;

    unsafe { core::ptr::write(ptr, fb_cmd) };
    Ok(0)
}

/// Handle GFX_IOCTL_MODE_RMFB
fn handle_rmfb(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut u32;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let fb_id = unsafe { core::ptr::read(ptr) };
    driver.rm_fb(fb_id)?;
    Ok(0)
}

/// Handle GFX_IOCTL_MODE_CREATE_DUMB
fn handle_create_dumb(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxModeCreateDumb;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let mut create = unsafe { core::ptr::read(ptr) };
    let dumb = driver.create_dumb(create.width, create.height, create.bpp)?;

    create.handle = dumb.handle;
    create.pitch = dumb.pitch;
    create.size = dumb.size;

    unsafe { core::ptr::write(ptr, create) };
    Ok(0)
}

/// Handle GFX_IOCTL_MODE_MAP_DUMB
fn handle_map_dumb(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxModeMapDumb;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let mut map = unsafe { core::ptr::read(ptr) };
    map.offset = driver.map_dumb(map.handle)?;

    unsafe { core::ptr::write(ptr, map) };
    Ok(0)
}

/// Handle GFX_IOCTL_MODE_DESTROY_DUMB
fn handle_destroy_dumb(driver: &dyn GfxDriver, arg: u64) -> Result<i64, GfxError> {
    let ptr = arg as *mut GfxModeDestroyDumb;
    if ptr.is_null() {
        return Err(GfxError::InvalidArg);
    }

    let destroy = unsafe { core::ptr::read(ptr) };
    driver.destroy_dumb(destroy.handle)?;
    Ok(0)
}

/// Convert GfxModeModeinfo to GfxModeInfo
fn modeinfo_to_drmmode(info: &GfxModeModeinfo) -> GfxModeInfo {
    // Extract name as string
    let name_end = info.name.iter().position(|&c| c == 0).unwrap_or(32);
    let name = core::str::from_utf8(&info.name[..name_end])
        .unwrap_or("")
        .to_string();

    GfxModeInfo {
        clock: info.clock,
        hdisplay: info.hdisplay as u32,
        hsync_start: info.hsync_start as u32,
        hsync_end: info.hsync_end as u32,
        htotal: info.htotal as u32,
        vdisplay: info.vdisplay as u32,
        vsync_start: info.vsync_start as u32,
        vsync_end: info.vsync_end as u32,
        vtotal: info.vtotal as u32,
        vrefresh: info.vrefresh,
        flags: info.flags,
        type_: info.type_,
        name,
    }
}
