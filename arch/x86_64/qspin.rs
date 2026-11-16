//! The narrow accesses of the queued spin lock word (Linux
//! asm-generic/qspinlock.h and kernel/locking/qspinlock.h on x86): byte
//! and halfword stores and a halfword exchange on parts of a 32-bit
//! lock word that other CPUs change with 32-bit atomics. Rust's memory
//! model has no mixed-size atomics; the hardware's (x86 TSO, naturally
//! aligned accesses single-copy atomic) is what Linux relies on, so
//! these are instructions.

/// Store `v` to the byte at `p` with release ordering (Linux
/// smp_store_release on a u8: a plain store under TSO, a compiler
/// barrier before it)
///
/// # Safety
/// `p` is a valid, aligned byte of a live lock word.
#[inline(always)]
pub unsafe fn store_release_u8(p: *mut u8, v: u8) {
    // SAFETY: the caller's pointer; one byte store, ordered after every
    // earlier access by TSO and the compiler barrier (no `nomem`)
    unsafe {
        core::arch::asm!(
            "mov byte ptr [{p}], {v}",
            p = in(reg) p,
            v = in(reg_byte) v,
            options(nostack, preserves_flags)
        )
    };
}

/// Store `v` to the byte at `p` (Linux WRITE_ONCE on a u8)
///
/// # Safety
/// As [`store_release_u8`].
#[inline(always)]
pub unsafe fn store_u8(p: *mut u8, v: u8) {
    // SAFETY: as store_release_u8
    unsafe { store_release_u8(p, v) };
}

/// Store `v` to the halfword at `p` (Linux WRITE_ONCE on a u16)
///
/// # Safety
/// `p` is a valid, 2-aligned halfword of a live lock word.
#[inline(always)]
pub unsafe fn store_u16(p: *mut u16, v: u16) {
    // SAFETY: the caller's pointer; one aligned halfword store
    unsafe {
        core::arch::asm!(
            "mov word ptr [{p}], {v:x}",
            p = in(reg) p,
            v = in(reg) v,
            options(nostack, preserves_flags)
        )
    };
}

/// Exchange the halfword at `p` with `v`, its old value (Linux
/// xchg_relaxed on a u16: `xchg`, locked by the hardware)
///
/// # Safety
/// As [`store_u16`].
#[inline(always)]
pub unsafe fn xchg_u16(p: *mut u16, v: u16) -> u16 {
    let mut r = v;
    // SAFETY: the caller's pointer; xchg with memory is atomic
    unsafe {
        core::arch::asm!(
            "xchg word ptr [{p}], {r:x}",
            p = in(reg) p,
            r = inout(reg) r,
            options(nostack, preserves_flags)
        )
    };
    r
}
