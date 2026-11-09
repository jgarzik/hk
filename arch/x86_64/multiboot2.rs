//! Multiboot2 information structure parsing
//!
//! The bootloader passes the physical address of the info structure;
//! `set_boot` records it once, and everything else reads it as a byte
//! slice (through the direct map) with bounds-checked accesses.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::phys_to_virt;

/// Tag types
pub const TAG_END: u32 = 0;
pub const TAG_CMDLINE: u32 = 1;
pub const TAG_MODULE: u32 = 3;
pub const TAG_MEMORY_MAP: u32 = 6;
pub const TAG_FRAMEBUFFER: u32 = 8;

/// Memory types
pub const MEMORY_AVAILABLE: u32 = 1;

/// Framebuffer type: direct RGB (the only one supported)
pub const FRAMEBUFFER_TYPE_RGB: u8 = 1;

/// Physical address of the info structure (0: none)
static INFO_PHYS: AtomicU64 = AtomicU64::new(0);

/// Record the bootloader's info structure
///
/// # Safety
/// `pa` is 0, or the physical address of a multiboot2 info structure
/// readable through the direct map; it and every module it lists stay
/// reserved for the kernel's life (`boot_ranges`), but for the
/// initramfs, freed once unpacked (`initrd_range`).
pub unsafe fn set_boot(pa: u64) {
    INFO_PHYS.store(pa, Ordering::Relaxed);
}

/// The info structure's physical address (0: none)
pub fn boot_phys() -> u64 {
    INFO_PHYS.load(Ordering::Relaxed)
}

/// The info structure as bytes: `total_size` long, clamped to [8, 1MB]
/// (a bogus size never walks far past the structure)
fn info() -> Option<&'static [u8]> {
    let pa = boot_phys();
    if pa == 0 {
        return None;
    }
    let base = phys_to_virt(pa).cast_const();
    // SAFETY: the header's 8 bytes of the recorded structure (`set_boot`)
    let head = unsafe { core::slice::from_raw_parts(base, 8) };
    let total = (le32(head, 0)? as usize).clamp(8, 1 << 20);
    // SAFETY: the structure's `total` bytes (`set_boot`)
    Some(unsafe { core::slice::from_raw_parts(base, total) })
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// The tags, each as its bytes (header included)
fn tags() -> impl Iterator<Item = &'static [u8]> {
    let mut rest = info().map_or(&[][..], |b| &b[8..]);
    core::iter::from_fn(move || {
        let kind = le32(rest, 0)?;
        let size = le32(rest, 4)? as usize;
        // A tag holds its header and ends inside the structure (a short
        // or overlong size ends the walk)
        if kind == TAG_END || size < 8 || size > rest.len() {
            return None;
        }
        let tag = &rest[..size];
        rest = &rest[size.next_multiple_of(8).min(rest.len())..];
        Some(tag)
    })
}

/// The tags of one type
fn tags_of(kind: u32) -> impl Iterator<Item = &'static [u8]> {
    tags().filter(move |t| le32(t, 0) == Some(kind))
}

/// NUL-terminated UTF-8 string at the start of `b`
fn cstr(b: &'static [u8]) -> Option<&'static str> {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    core::str::from_utf8(&b[..n]).ok()
}

/// Call `f(base, length, type)` for every memory map entry
pub fn for_each_region(mut f: impl FnMut(u64, u64, u32)) {
    let Some(tag) = tags_of(TAG_MEMORY_MAP).next() else {
        return;
    };
    // Step by the tag's entry_size (GRUB, Linux), which must cover the
    // 24-byte entry read
    let Some(step) = le32(tag, 8).map(|s| s as usize).filter(|&s| s >= 24) else {
        return;
    };
    for e in tag.get(16..).unwrap_or(&[]).chunks(step) {
        if let (Some(base), Some(len), Some(kind)) = (le64(e, 0), le64(e, 8), le32(e, 16)) {
            f(base, len, kind);
        }
    }
}

/// The kernel command line
pub fn get_cmdline() -> Option<&'static str> {
    cstr(tags_of(TAG_CMDLINE).next()?.get(8..)?)
}

/// Module tag fields: (physical start, physical end, cmdline)
fn module(tag: &'static [u8]) -> Option<(u64, u64, Option<&'static str>)> {
    let start = u64::from(le32(tag, 8)?);
    let end = u64::from(le32(tag, 12)?);
    Some((start, end, tag.get(16..).and_then(cstr)))
}

/// Every physical range the bootloader placed in memory that the
/// kernel still reads: the info structure itself and each module
pub fn boot_ranges(mut f: impl FnMut(&'static str, u64, u64)) {
    let Some(b) = info() else {
        return;
    };
    let pa = boot_phys();
    f("multiboot info", pa, pa + b.len() as u64);
    for (start, end, _) in tags_of(TAG_MODULE).filter_map(module) {
        if start < end {
            f("multiboot module", start, end);
        }
    }
}

/// The physical range of the first module whose command line
/// contains `name`
fn module_range(name: &str) -> Option<(u64, u64)> {
    let (start, end, _) = tags_of(TAG_MODULE)
        .filter_map(module)
        .find(|&(s, e, c)| s < e && c.is_some_and(|c| c.contains(name)))?;
    Some((start, end))
}

/// The initramfs module's physical range [start, end): its pages are
/// freed once it is unpacked (`fs::cpio::Initrd`)
pub fn initrd_range() -> Option<(u64, u64)> {
    module_range(INITRD)
}

/// The command-line name of the initramfs module
const INITRD: &str = "initramfs";

/// Find a module loaded by the bootloader (GRUB `module2`) whose
/// command line contains `name`, other than the initramfs (freed after
/// boot, see `initrd_range`); its data through the direct map
pub fn find_module(name: &str) -> Option<&'static [u8]> {
    if name.contains(INITRD) {
        return None;
    }
    let (start, end) = module_range(name)?;
    if module_range(INITRD).is_some_and(|(s, e)| start < e && s < end) {
        return None;
    }
    let p = phys_to_virt(start).cast_const();
    // SAFETY: a module the info structure lists and not the initramfs,
    // reserved for good (`set_boot`), `end - start` bytes
    Some(unsafe { core::slice::from_raw_parts(p, (end - start) as usize) })
}

/// The framebuffer the bootloader set up, if it is direct RGB.
/// Tag layout: header(8) addr(8) pitch(4) width(4) height(4) bpp(1)
/// type(1) reserved(2), then the color info (positions and sizes).
pub fn get_framebuffer() -> Option<crate::gfx::FramebufferInfo> {
    use crate::gfx::{FramebufferInfo, PixelFormat};

    let t = tags_of(TAG_FRAMEBUFFER).next()?;
    let addr = le64(t, 8)?;
    let pitch = le32(t, 16)?;
    let width = le32(t, 20)?;
    let height = le32(t, 24)?;
    let (bpp, fb_type) = (*t.get(28)?, *t.get(29)?);
    if fb_type != FRAMEBUFFER_TYPE_RGB {
        return None;
    }
    let color = t.get(32..38)?;
    let (red_pos, red_size, green_pos, blue_pos) = (color[0], color[1], color[2], color[4]);

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
    let size = u64::from(pitch) * u64::from(height);
    Some(FramebufferInfo::new(
        addr, size, width, height, pitch, format,
    ))
}
