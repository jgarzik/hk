//! Multiboot2 information structure parsing
//!
//! Parses the multiboot2 info structure passed by the bootloader
//! to extract the memory map and other boot information.

use crate::arch::phys_to_virt;

/// Multiboot2 info header
#[repr(C)]
pub struct Multiboot2Info {
    pub total_size: u32,
    pub reserved: u32,
    // Tags follow...
}

/// Multiboot2 tag header
#[repr(C)]
pub struct TagHeader {
    pub tag_type: u32,
    pub size: u32,
}

/// Memory map tag (type 6)
#[repr(C)]
pub struct MemoryMapTag {
    pub header: TagHeader,
    pub entry_size: u32,
    pub entry_version: u32,
    // Entries follow...
}

/// Memory map entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryMapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub mem_type: u32, // 1 = available RAM
    pub reserved: u32,
}

/// Tag types
pub const TAG_END: u32 = 0;
pub const TAG_CMDLINE: u32 = 1;
pub const TAG_MODULE: u32 = 3;
pub const TAG_MEMORY_MAP: u32 = 6;
pub const TAG_FRAMEBUFFER: u32 = 8;

/// Memory types
pub const MEMORY_AVAILABLE: u32 = 1;

/// Tags of the info structure; the bootloader passes physical
/// addresses, read through the direct map
struct Tags {
    cur: *const u8,
    end: *const u8,
}

impl Iterator for Tags {
    type Item = *const TagHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur >= self.end {
            return None;
        }
        let tag = self.cur as *const TagHeader;
        let (kind, size) = unsafe { ((*tag).tag_type, (*tag).size) };
        if kind == TAG_END {
            return None;
        }
        self.cur = unsafe { self.cur.add(size.next_multiple_of(8) as usize) };
        Some(tag)
    }
}

/// # Safety
/// `info` is the physical address of a valid multiboot2 info structure
/// (or 0)
unsafe fn tags(info: u64) -> Tags {
    if info == 0 {
        let p = core::ptr::null();
        return Tags { cur: p, end: p };
    }
    let base = phys_to_virt(info) as *const u8;
    let total = unsafe { (*(base as *const Multiboot2Info)).total_size };
    Tags {
        cur: unsafe { base.add(8) },
        end: unsafe { base.add(total as usize) },
    }
}

/// First tag of a type
unsafe fn find(info: u64, kind: u32) -> Option<*const TagHeader> {
    unsafe { tags(info) }.find(|&t| unsafe { (*t).tag_type } == kind)
}

/// NUL-terminated string in the `len` bytes at `p`
unsafe fn cstr(p: *const u8, len: usize) -> Option<&'static str> {
    let n = (0..len).find(|&i| unsafe { *p.add(i) } == 0).unwrap_or(len);
    core::str::from_utf8(unsafe { core::slice::from_raw_parts(p, n) }).ok()
}

/// Call `f(base, length, type)` for every memory map entry
///
/// # Safety
/// `info` is the physical address of a valid multiboot2 info structure.
pub unsafe fn for_each_region(info: u64, mut f: impl FnMut(u64, u64, u32)) {
    let Some(tag) = (unsafe { find(info, TAG_MEMORY_MAP) }) else {
        return;
    };
    unsafe {
        let mt = tag as *const MemoryMapTag;
        let step = (*mt).entry_size as usize;
        let end = (tag as *const u8).add((*tag).size as usize);
        let mut p = (tag as *const u8).add(16);
        while p < end {
            let e = core::ptr::read_unaligned(p as *const MemoryMapEntry);
            f(e.base_addr, e.length, e.mem_type);
            p = p.add(step);
        }
    }
}

/// Extract the kernel command line from multiboot2 info
///
/// # Safety
/// `info` is the physical address of a valid multiboot2 info structure.
pub unsafe fn get_cmdline(info: u64) -> Option<&'static str> {
    let tag = unsafe { find(info, TAG_CMDLINE) }?;
    unsafe { cstr((tag as *const u8).add(8), (*tag).size as usize - 8) }
}

/// Find the largest usable memory region above a given address,
/// as physical (start, end); (0, 0) if none
///
/// # Safety
/// `info` is the physical address of a valid multiboot2 info structure.
pub unsafe fn find_largest_region_above(info: u64, min_addr: u64) -> (u64, u64) {
    let mut best = (0, 0);
    unsafe {
        for_each_region(info, |base, len, kind| {
            let (start, end) = (base.max(min_addr), base + len);
            if kind == MEMORY_AVAILABLE && end > start && end - start > best.1 - best.0 {
                best = (start, end);
            }
        });
    }
    best
}

/// Module tag fields: (physical start, physical end, cmdline)
unsafe fn module(tag: *const TagHeader) -> (u64, u64, Option<&'static str>) {
    unsafe {
        let p = tag as *const u8;
        let start = *(p.add(8) as *const u32) as u64;
        let end = *(p.add(12) as *const u32) as u64;
        (start, end, cstr(p.add(16), (*tag).size as usize - 16))
    }
}

/// Every physical range the bootloader placed in memory that the
/// kernel still reads: the info structure itself and each module
///
/// # Safety
/// `info` is the physical address of a valid multiboot2 info structure.
pub unsafe fn boot_ranges(info: u64, mut f: impl FnMut(&'static str, u64, u64)) {
    if info == 0 {
        return;
    }
    unsafe {
        let total = (*(phys_to_virt(info) as *const Multiboot2Info)).total_size;
        f("multiboot info", info, info + total as u64);
        for tag in tags(info).filter(|&t| (*t).tag_type == TAG_MODULE) {
            let (start, end, _) = module(tag);
            f("multiboot module", start, end);
        }
    }
}

/// Find a module loaded by the bootloader (GRUB `module2`) whose
/// command line contains `name`; its data through the direct map
///
/// # Safety
/// `info` is the physical address of a valid multiboot2 info structure;
/// the module memory must stay reserved.
pub unsafe fn find_module(info: u64, name: &str) -> Option<&'static [u8]> {
    unsafe {
        for tag in tags(info).filter(|&t| (*t).tag_type == TAG_MODULE) {
            let (start, end, cmdline) = module(tag);
            if cmdline.is_some_and(|c| c.contains(name)) {
                let p = phys_to_virt(start) as *const u8;
                return Some(core::slice::from_raw_parts(p, (end - start) as usize));
            }
        }
    }
    None
}

/// Framebuffer tag (type 8)
///
/// Provides information about the framebuffer set up by the bootloader.
/// The color_info field varies based on framebuffer_type:
/// - Type 0 (indexed): palette follows
/// - Type 1 (direct RGB): color mask info follows
/// - Type 2 (EGA text): no extra info
#[repr(C, packed)]
#[allow(dead_code)]
pub struct FramebufferTag {
    pub header: TagHeader,
    pub framebuffer_addr: u64,
    pub framebuffer_pitch: u32,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_bpp: u8,
    pub framebuffer_type: u8,
    pub reserved: u16,
    // For type 1 (direct RGB), color info follows:
    // red_field_position: u8,
    // red_mask_size: u8,
    // green_field_position: u8,
    // green_mask_size: u8,
    // blue_field_position: u8,
    // blue_mask_size: u8,
}

/// Framebuffer type constants
#[allow(dead_code)]
pub const FRAMEBUFFER_TYPE_INDEXED: u8 = 0;
pub const FRAMEBUFFER_TYPE_RGB: u8 = 1;
#[allow(dead_code)]
pub const FRAMEBUFFER_TYPE_EGA_TEXT: u8 = 2;

/// Parse framebuffer tag and return framebuffer info
///
/// Returns None if no framebuffer tag is present, info_ptr is 0,
/// or the framebuffer type is not supported (e.g., indexed color).
///
/// # Safety
/// The caller must ensure info_ptr points to valid multiboot2 info structure.
pub unsafe fn get_framebuffer(info_ptr: u64) -> Option<crate::gfx::FramebufferInfo> {
    use crate::gfx::{FramebufferInfo, PixelFormat};

    let fb_tag = unsafe { find(info_ptr, TAG_FRAMEBUFFER) }? as *const u8;
    unsafe {
        // Layout (packed): header(8) addr(8) pitch(4) width(4) height(4)
        // bpp(1) type(1) reserved(2), then for direct RGB the color info
        let addr = core::ptr::read_unaligned(fb_tag.add(8) as *const u64);
        let pitch = core::ptr::read_unaligned(fb_tag.add(16) as *const u32);
        let width = core::ptr::read_unaligned(fb_tag.add(20) as *const u32);
        let height = core::ptr::read_unaligned(fb_tag.add(24) as *const u32);
        let bpp = *fb_tag.add(28);
        let fb_type = *fb_tag.add(29);

        // Only support direct RGB framebuffer
        if fb_type != FRAMEBUFFER_TYPE_RGB {
            return None;
        }

        let color = fb_tag.add(32);
        let red_pos = *color;
        let red_size = *color.add(1);
        let green_pos = *color.add(2);
        let blue_pos = *color.add(4);

        // XRGB8888: R at 16, G at 8, B at 0 (common UEFI GOP format)
        // XBGR8888: B at 16, G at 8, R at 0
        let format = if bpp == 32 && red_size == 8 {
            if blue_pos == 16 && green_pos == 8 && red_pos == 0 {
                PixelFormat::Xbgr8888
            } else {
                PixelFormat::Xrgb8888
            }
        } else if bpp == 16 {
            PixelFormat::Rgb565
        } else {
            return None;
        };

        let size = (pitch as u64) * (height as u64);
        Some(FramebufferInfo::new(
            addr, size, width, height, pitch, format,
        ))
    }
}
