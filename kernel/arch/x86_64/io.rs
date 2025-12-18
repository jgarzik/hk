//! x86-64 I/O port access
//!
//! Provides safe wrappers around the x86 IN and OUT instructions.

/// Write a byte to an I/O port
#[inline]
pub fn outb(port: u16, value: u8) {
    unsafe {
        ::core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Read a byte from an I/O port
#[inline]
pub fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        ::core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Write a 16-bit word to an I/O port
#[inline]
pub fn outw(port: u16, value: u16) {
    unsafe {
        ::core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Read a 16-bit word from an I/O port
#[inline]
#[allow(dead_code)]
pub fn inw(port: u16) -> u16 {
    let value: u16;
    unsafe {
        ::core::arch::asm!(
            "in ax, dx",
            in("dx") port,
            out("ax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Write a 32-bit dword to an I/O port
#[inline]
pub fn outl(port: u16, value: u32) {
    unsafe {
        ::core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Read a 32-bit dword from an I/O port
#[inline]
pub fn inl(port: u16) -> u32 {
    let value: u32;
    unsafe {
        ::core::arch::asm!(
            "in eax, dx",
            in("dx") port,
            out("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Small delay by doing I/O to unused port
#[inline]
pub fn io_wait() {
    outb(0x80, 0);
}
