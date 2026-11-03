//! Memory-mapped device registers (doc/UNSAFE.md rules 2 and 8; Linux
//! readl/writel, Rust-for-Linux `kernel::io::Io`)
//!
//! An [`IoMem`] is a window of device memory: the base and length of an
//! ioremapped region. Every access is volatile, through a raw pointer
//! (never a Rust reference: the device changes the memory and reads may
//! have side effects), at an offset checked against the window and the
//! access width. Making one is the only unsafe step: the caller vouches
//! that the range is the device's registers, mapped for good.

use core::ptr::{NonNull, read_volatile, write_volatile};

use crate::arch::{CurrentArch, IoremapOps};

/// A mapped register window
///
/// # Invariants
/// `len` bytes at `base` are device memory, mapped for the kernel's life
/// (hk never unmaps an ioremap).
#[derive(Clone, Copy)]
pub struct IoMem {
    base: NonNull<u8>,
    len: usize,
}

// SAFETY: device memory reached only by volatile accesses at checked
// offsets; ordering between CPUs is the driver's lock's (as in Linux)
unsafe impl Send for IoMem {}
// SAFETY: as above
unsafe impl Sync for IoMem {}

impl IoMem {
    /// The window of `len` bytes at the mapped address `base`
    ///
    /// # Safety
    /// `len` bytes at `base` are device registers, mapped and never
    /// unmapped while this window or a copy of it exists.
    pub const unsafe fn new(base: NonNull<u8>, len: usize) -> Self {
        // INVARIANT: the caller's promise
        Self { base, len }
    }

    /// ioremap `len` bytes of device memory at physical `phys`
    ///
    /// # Safety
    /// [phys, phys + len) is a device's MMIO (a BAR, a firmware-described
    /// register block), not RAM: writes through the window must not
    /// change memory the kernel uses.
    pub unsafe fn ioremap(phys: u64, len: usize) -> Option<Self> {
        // SAFETY: the caller's MMIO range (this fn's contract)
        let p = unsafe { CurrentArch::ioremap(phys, len as u64) }.ok()?;
        // SAFETY: ioremap mapped `len` bytes of the caller's MMIO range,
        // and hk never unmaps it
        Some(unsafe { Self::new(NonNull::new(p)?, len) })
    }

    /// Bytes in the window
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// The window is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The window's address (for messages and DMA-free identity checks)
    #[inline]
    pub fn addr(&self) -> usize {
        self.base.as_ptr() as usize
    }

    /// The register of type `T` at `off`; panics past the window or if
    /// misaligned (a driver bug: offsets are constants or checked)
    #[inline]
    fn reg<T>(&self, off: usize) -> *mut T {
        let size = core::mem::size_of::<T>();
        assert!(
            off.is_multiple_of(size) && off.checked_add(size).is_some_and(|e| e <= self.len),
            "IoMem: register {off:#x} (width {size}) outside a {:#x}-byte window",
            self.len
        );
        // SAFETY: inside the window (checked)
        unsafe { self.base.as_ptr().add(off) }.cast::<T>()
    }

    /// The register at `off`, if it is inside the window and aligned
    #[inline]
    fn try_reg<T>(&self, off: usize) -> Option<*mut T> {
        let size = core::mem::size_of::<T>();
        (off.is_multiple_of(size) && off.checked_add(size).is_some_and(|e| e <= self.len))
            .then(|| self.reg::<T>(off))
    }

    /// A sub-window [off, off + len); None if it does not fit
    pub fn sub(&self, off: usize, len: usize) -> Option<Self> {
        if off.checked_add(len)? > self.len {
            return None;
        }
        // SAFETY: inside this window (checked)
        let base = unsafe { NonNull::new_unchecked(self.base.as_ptr().add(off)) };
        // INVARIANT: part of this window, mapped as long as it is
        Some(Self { base, len })
    }
}

macro_rules! access {
    ($($t:ty: $read:ident, $write:ident, $try_read:ident, $try_write:ident);* $(;)?) => {
        impl IoMem {$(
            /// Volatile read of the register at `off` (panics outside)
            #[inline]
            pub fn $read(&self, off: usize) -> $t {
                // SAFETY: an aligned register inside the mapped window
                unsafe { read_volatile(self.reg::<$t>(off)) }
            }

            /// Volatile write of the register at `off` (panics outside)
            #[inline]
            pub fn $write(&self, off: usize, v: $t) {
                // SAFETY: as above
                unsafe { write_volatile(self.reg::<$t>(off), v) }
            }

            /// The register at `off`, or None outside the window
            #[inline]
            pub fn $try_read(&self, off: usize) -> Option<$t> {
                // SAFETY: as above (checked by try_reg)
                self.try_reg::<$t>(off).map(|p| unsafe { read_volatile(p) })
            }

            /// Write the register at `off`; false (nothing written)
            /// outside the window
            #[inline]
            pub fn $try_write(&self, off: usize, v: $t) -> bool {
                match self.try_reg::<$t>(off) {
                    Some(p) => {
                        // SAFETY: as above (checked by try_reg)
                        unsafe { write_volatile(p, v) };
                        true
                    }
                    None => false,
                }
            }
        )*}
    };
}

access! {
    u8: read8, write8, try_read8, try_write8;
    u16: read16, write16, try_read16, try_write16;
    u32: read32, write32, try_read32, try_write32;
    u64: read64, write64, try_read64, try_write64;
}
