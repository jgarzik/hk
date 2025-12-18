//! x86_64 user memory access primitives
//!
//! Implements the UaccessArch trait for x86_64, including:
//! - SMAP (Supervisor Mode Access Prevention) support
//! - Canonical address validation
//!
//! # SMAP Overview
//!
//! SMAP is a hardware security feature (Intel Haswell+, AMD Zen+) that prevents
//! the kernel from accidentally accessing user-space memory. When SMAP is enabled:
//! - Any supervisor-mode access to user pages causes a page fault
//! - The AC (Alignment Check) flag in RFLAGS can temporarily disable this protection
//! - `stac` instruction sets AC flag (enables user access)
//! - `clac` instruction clears AC flag (disables user access)
//!
//! # Canonical Addresses
//!
//! On x86_64, valid user addresses are in the range [0, 0x0000_7FFF_FFFF_FFFF].
//! The "canonical hole" (0x0000_8000_0000_0000 to 0xFFFF_7FFF_FFFF_FFFF) is invalid.
//! Kernel addresses are in [0xFFFF_8000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF].

use crate::uaccess::UaccessArch;

/// CR4 bit for SMAP enable
const CR4_SMAP: u64 = 1 << 21;

/// CR4 bit for SMEP enable
const CR4_SMEP: u64 = 1 << 20;

/// CPUID feature bit for SMAP (leaf 7, ebx bit 20)
const CPUID_SMAP: u32 = 1 << 20;

/// CPUID feature bit for SMEP (leaf 7, ebx bit 7)
const CPUID_SMEP: u32 = 1 << 7;

/// x86_64 user memory access implementation
pub struct X86_64Uaccess;

impl UaccessArch for X86_64Uaccess {
    /// User space starts at address 0 on x86_64
    /// (We allow access starting from page 1 to catch NULL pointer dereferences)
    const USER_START: u64 = 0x0000_0000_0000_1000; // Skip first page (NULL guard)

    /// User space ends at the canonical hole
    /// The highest valid user address is 0x0000_7FFF_FFFF_FFFF
    const USER_END: u64 = 0x0000_8000_0000_0000;

    /// Enable user memory access by setting AC flag (SMAP bypass)
    ///
    /// Executes `stac` if SMAP is available, otherwise no-op.
    #[inline(always)]
    unsafe fn user_access_begin() {
        // Always execute stac if we have SMAP - it's a no-op on CPUs without SMAP
        // when the instruction is available, and the kernel checks for SMAP support
        // at boot time.
        if smap_enabled() {
            unsafe {
                ::core::arch::asm!("stac", options(nomem, nostack, preserves_flags));
            }
        }
    }

    /// Disable user memory access by clearing AC flag
    ///
    /// Executes `clac` if SMAP is available, otherwise no-op.
    #[inline(always)]
    unsafe fn user_access_end() {
        if smap_enabled() {
            unsafe {
                ::core::arch::asm!("clac", options(nomem, nostack, preserves_flags));
            }
        }
    }
}

/// Check if SMAP is currently enabled
///
/// Returns true if SMAP is both supported by the CPU and enabled in CR4.
#[inline]
fn smap_enabled() -> bool {
    // Read CR4 and check SMAP bit
    let cr4: u64;
    unsafe {
        ::core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    cr4 & CR4_SMAP != 0
}

/// Check if CPU supports SMAP
pub fn cpu_has_smap() -> bool {
    let (_, ebx, _, _) = cpuid(7, 0);
    ebx & CPUID_SMAP != 0
}

/// Check if CPU supports SMEP
pub fn cpu_has_smep() -> bool {
    let (_, ebx, _, _) = cpuid(7, 0);
    ebx & CPUID_SMEP != 0
}

/// Enable SMAP if supported
///
/// Should be called during early kernel initialization.
/// Once enabled, any kernel access to user pages without explicit
/// `user_access_begin()`/`user_access_end()` will cause a page fault.
pub fn enable_smap() {
    if cpu_has_smap() {
        let mut cr4: u64;
        unsafe {
            ::core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            cr4 |= CR4_SMAP;
            ::core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
        }
    }
}

/// Enable SMEP if supported
///
/// Should be called during early kernel initialization.
/// Once enabled, any kernel execution of user pages will cause a page fault.
pub fn enable_smep() {
    if cpu_has_smep() {
        let mut cr4: u64;
        unsafe {
            ::core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            cr4 |= CR4_SMEP;
            ::core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
        }
    }
}

/// Execute CPUID instruction
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        ::core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            ebx_out = out(reg) ebx,
            lateout("edx") edx,
        );
    }
    (eax, ebx, ecx, edx)
}
