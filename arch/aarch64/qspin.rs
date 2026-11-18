//! The narrow accesses of the queued spin lock word (Linux
//! asm-generic/qspinlock.h and kernel/locking/qspinlock.h on arm64):
//! byte and halfword stores and a halfword exchange on parts of a
//! 32-bit lock word that other CPUs change with 32-bit atomics. Rust's
//! memory model has no mixed-size atomics; the hardware's (aligned
//! accesses single-copy atomic, exclusives on any aligned size) is what
//! Linux relies on, so these are instructions.

/// Store `v` to the byte at `p` with release ordering (Linux
/// smp_store_release on a u8: `stlrb`)
///
/// # Safety
/// `p` is a valid, aligned byte of a live lock word.
#[inline(always)]
pub unsafe fn store_release_u8(p: *mut u8, v: u8) {
    // SAFETY: the caller's pointer; stlrb orders every earlier access
    // before the store
    unsafe {
        core::arch::asm!(
            "stlrb {v:w}, [{p}]",
            p = in(reg) p,
            v = in(reg) u32::from(v),
            options(nostack, preserves_flags)
        )
    };
}

/// Store `v` to the byte at `p` (Linux WRITE_ONCE on a u8: `strb`)
///
/// # Safety
/// As [`store_release_u8`].
#[inline(always)]
pub unsafe fn store_u8(p: *mut u8, v: u8) {
    // SAFETY: the caller's pointer; one byte store
    unsafe {
        core::arch::asm!(
            "strb {v:w}, [{p}]",
            p = in(reg) p,
            v = in(reg) u32::from(v),
            options(nostack, preserves_flags)
        )
    };
}

/// Store `v` to the halfword at `p` (Linux WRITE_ONCE on a u16: `strh`)
///
/// # Safety
/// `p` is a valid, 2-aligned halfword of a live lock word.
#[inline(always)]
pub unsafe fn store_u16(p: *mut u16, v: u16) {
    // SAFETY: the caller's pointer; one aligned halfword store
    unsafe {
        core::arch::asm!(
            "strh {v:w}, [{p}]",
            p = in(reg) p,
            v = in(reg) u32::from(v),
            options(nostack, preserves_flags)
        )
    };
}

/// Exchange the halfword at `p` with `v`, its old value (Linux
/// xchg_relaxed on a u16: an exclusive load/store loop)
///
/// # Safety
/// As [`store_u16`].
#[inline(always)]
pub unsafe fn xchg_u16(p: *mut u16, v: u16) -> u16 {
    let old: u32;
    // SAFETY: the caller's pointer; ldxrh/stxrh retry until the
    // exchange is atomic
    unsafe {
        core::arch::asm!(
            "2:",
            "ldxrh {old:w}, [{p}]",
            "stxrh {tmp:w}, {v:w}, [{p}]",
            "cbnz {tmp:w}, 2b",
            p = in(reg) p,
            v = in(reg) u32::from(v),
            old = out(reg) old,
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        )
    };
    old as u16
}
