//! Multiboot2 information structure parsing
//!
//! Parses the multiboot2 info structure passed by the bootloader
//! to extract the memory map and other boot information.

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

/// Iterator over available memory regions from multiboot2 memory map
pub struct MemoryMapIter {
    current: *const MemoryMapEntry,
    end: *const u8,
    entry_size: u32,
}

impl Iterator for MemoryMapIter {
    type Item = (u64, u64); // (base_addr, length)

    fn next(&mut self) -> Option<Self::Item> {
        while (self.current as *const u8) < self.end {
            let entry = unsafe { &*self.current };

            // Move to next entry
            self.current = unsafe {
                (self.current as *const u8).add(self.entry_size as usize) as *const MemoryMapEntry
            };

            // Only return available memory regions
            if entry.mem_type == MEMORY_AVAILABLE {
                return Some((entry.base_addr, entry.length));
            }
        }
        None
    }
}

/// Parse multiboot2 info and return iterator over usable memory regions
///
/// Returns None if info_ptr is 0 or parsing fails.
///
/// # Safety
/// The caller must ensure info_ptr points to valid multiboot2 info structure.
pub unsafe fn parse_memory_map(info_ptr: u64) -> Option<MemoryMapIter> {
    if info_ptr == 0 {
        return None;
    }

    unsafe {
        let info = info_ptr as *const Multiboot2Info;
        let total_size = (*info).total_size;

        // Tags start after the header (8 bytes)
        let mut tag_ptr = (info_ptr + 8) as *const TagHeader;
        let info_end = info_ptr + total_size as u64;

        // Iterate through tags to find memory map
        while (tag_ptr as u64) < info_end {
            let tag = &*tag_ptr;

            // End tag
            if tag.tag_type == TAG_END {
                break;
            }

            // Found memory map tag
            if tag.tag_type == TAG_MEMORY_MAP {
                let mmap_tag = tag_ptr as *const MemoryMapTag;
                let entry_size = (*mmap_tag).entry_size;

                // Entries start after the tag header (16 bytes for MemoryMapTag)
                let entries_start = (mmap_tag as *const u8).add(16) as *const MemoryMapEntry;
                let entries_end = (tag_ptr as *const u8).add(tag.size as usize);

                return Some(MemoryMapIter {
                    current: entries_start,
                    end: entries_end,
                    entry_size,
                });
            }

            // Move to next tag (8-byte aligned)
            let next_offset = ((tag.size + 7) & !7) as usize;
            tag_ptr = (tag_ptr as *const u8).add(next_offset) as *const TagHeader;
        }

        None
    }
}

/// Extract the kernel command line from multiboot2 info
///
/// Returns None if no command line tag is present or info_ptr is 0.
///
/// # Safety
/// The caller must ensure info_ptr points to valid multiboot2 info structure.
pub unsafe fn get_cmdline(info_ptr: u64) -> Option<&'static str> {
    if info_ptr == 0 {
        return None;
    }

    unsafe {
        let info = info_ptr as *const Multiboot2Info;
        let total_size = (*info).total_size;

        let mut tag_ptr = (info_ptr + 8) as *const TagHeader;
        let info_end = info_ptr + total_size as u64;

        while (tag_ptr as u64) < info_end {
            let tag = &*tag_ptr;

            if tag.tag_type == TAG_END {
                break;
            }

            if tag.tag_type == TAG_CMDLINE {
                // String starts after the 8-byte tag header
                let str_ptr = (tag_ptr as *const u8).add(8);
                let str_len = tag.size as usize - 8; // Subtract header size

                // Find null terminator (string may be shorter than tag size due to padding)
                let mut actual_len = 0;
                while actual_len < str_len {
                    if *str_ptr.add(actual_len) == 0 {
                        break;
                    }
                    actual_len += 1;
                }

                let slice = ::core::slice::from_raw_parts(str_ptr, actual_len);
                return ::core::str::from_utf8(slice).ok();
            }

            // Move to next tag (8-byte aligned)
            let next_offset = ((tag.size + 7) & !7) as usize;
            tag_ptr = (tag_ptr as *const u8).add(next_offset) as *const TagHeader;
        }

        None
    }
}

/// Find the largest usable memory region above a given address
///
/// Returns (start, end) of the largest region, or (0, 0) if none found.
///
/// # Safety
/// The caller must ensure info_ptr points to valid multiboot2 info structure.
pub unsafe fn find_largest_region_above(info_ptr: u64, min_addr: u64) -> (u64, u64) {
    let mut best_start = 0u64;
    let mut best_end = 0u64;
    let mut best_size = 0u64;

    // SAFETY: parse_memory_map is unsafe but we're already in an unsafe context
    // with the same safety requirements (valid info_ptr)
    if let Some(iter) = unsafe { parse_memory_map(info_ptr) } {
        for (base, length) in iter {
            // Skip regions entirely below min_addr
            if base + length <= min_addr {
                continue;
            }

            // Adjust start if region starts below min_addr
            let adjusted_start = if base < min_addr { min_addr } else { base };
            let adjusted_length = length - (adjusted_start - base);
            let end = adjusted_start + adjusted_length;

            if adjusted_length > best_size {
                best_start = adjusted_start;
                best_end = end;
                best_size = adjusted_length;
            }
        }
    }

    (best_start, best_end)
}

/// Find a module loaded by the bootloader by its command line string
///
/// GRUB's `module2` command loads files as multiboot2 modules. Each module
/// has a command line string that can be used to identify it.
///
/// Returns a slice to the module data if found, None otherwise.
///
/// # Safety
/// The caller must ensure info_ptr points to valid multiboot2 info structure.
/// The returned slice is valid for the lifetime of the boot info structure
/// (i.e., as long as the physical memory is identity-mapped).
pub unsafe fn find_module(info_ptr: u64, name: &str) -> Option<&'static [u8]> {
    if info_ptr == 0 {
        return None;
    }

    unsafe {
        let info = info_ptr as *const Multiboot2Info;
        let total_size = (*info).total_size;

        let mut tag_ptr = (info_ptr + 8) as *const TagHeader;
        let info_end = info_ptr + total_size as u64;

        while (tag_ptr as u64) < info_end {
            let tag = &*tag_ptr;

            if tag.tag_type == TAG_END {
                break;
            }

            if tag.tag_type == TAG_MODULE {
                // Module tag layout:
                // - header (8 bytes): type, size
                // - mod_start (4 bytes): physical start address
                // - mod_end (4 bytes): physical end address
                // - cmdline (null-terminated string)
                let mod_start_ptr = (tag_ptr as *const u8).add(8) as *const u32;
                let mod_end_ptr = (tag_ptr as *const u8).add(12) as *const u32;
                let cmdline_ptr = (tag_ptr as *const u8).add(16);

                let mod_start = *mod_start_ptr as u64;
                let mod_end = *mod_end_ptr as u64;

                // Extract cmdline string (null-terminated)
                let cmdline_max_len = tag.size as usize - 16;
                let mut cmdline_len = 0;
                while cmdline_len < cmdline_max_len {
                    if *cmdline_ptr.add(cmdline_len) == 0 {
                        break;
                    }
                    cmdline_len += 1;
                }

                let cmdline_slice = ::core::slice::from_raw_parts(cmdline_ptr, cmdline_len);
                if let Ok(cmdline) = ::core::str::from_utf8(cmdline_slice) {
                    // Check if the cmdline matches or contains the name
                    if cmdline == name || cmdline.contains(name) {
                        let module_size = (mod_end - mod_start) as usize;
                        let module_data =
                            ::core::slice::from_raw_parts(mod_start as *const u8, module_size);
                        return Some(module_data);
                    }
                }
            }

            // Move to next tag (8-byte aligned)
            let next_offset = ((tag.size + 7) & !7) as usize;
            tag_ptr = (tag_ptr as *const u8).add(next_offset) as *const TagHeader;
        }

        None
    }
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

    if info_ptr == 0 {
        return None;
    }

    unsafe {
        let info = info_ptr as *const Multiboot2Info;
        let total_size = (*info).total_size;

        let mut tag_ptr = (info_ptr + 8) as *const TagHeader;
        let info_end = info_ptr + total_size as u64;

        while (tag_ptr as u64) < info_end {
            let tag = &*tag_ptr;

            if tag.tag_type == TAG_END {
                break;
            }

            if tag.tag_type == TAG_FRAMEBUFFER {
                let fb_tag = tag_ptr as *const u8;

                // Read fields manually using raw pointer arithmetic (structure is packed)
                // Layout: header(8) + addr(8) + pitch(4) + width(4) + height(4) + bpp(1) + type(1)
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

                // For direct RGB, color info follows the main structure at offset 32
                // (header:8 + addr:8 + pitch:4 + width:4 + height:4 + bpp:1 + type:1 + reserved:2 = 32)
                let color_info_ptr = fb_tag.add(32);
                let red_pos = *color_info_ptr;
                let red_size = *color_info_ptr.add(1);
                let green_pos = *color_info_ptr.add(2);
                let _green_size = *color_info_ptr.add(3);
                let blue_pos = *color_info_ptr.add(4);
                let _blue_size = *color_info_ptr.add(5);

                // Determine pixel format from color positions
                // XRGB8888: R at 16, G at 8, B at 0 (common UEFI GOP format)
                // XBGR8888: B at 16, G at 8, R at 0
                let format = if bpp == 32 && red_size == 8 {
                    if red_pos == 16 && green_pos == 8 && blue_pos == 0 {
                        PixelFormat::Xrgb8888
                    } else if blue_pos == 16 && green_pos == 8 && red_pos == 0 {
                        PixelFormat::Xbgr8888
                    } else {
                        // Unknown 32-bit format, try XRGB as fallback
                        PixelFormat::Xrgb8888
                    }
                } else if bpp == 16 {
                    PixelFormat::Rgb565
                } else {
                    // Unsupported bits per pixel
                    return None;
                };

                let size = (pitch as u64) * (height as u64);

                return Some(FramebufferInfo::new(
                    addr, size, width, height, pitch, format,
                ));
            }

            // Move to next tag (8-byte aligned)
            let next_offset = ((tag.size + 7) & !7) as usize;
            tag_ptr = (tag_ptr as *const u8).add(next_offset) as *const TagHeader;
        }

        None
    }
}
