//! AArch64 CPU initialization and feature detection
//!
//! Handles early CPU setup including exception level detection,
//! feature verification, and basic CPU configuration.

use core::arch::asm;

/// Current Exception Level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionLevel {
    EL0, // User mode
    EL1, // Kernel mode
    EL2, // Hypervisor mode
    EL3, // Secure monitor mode
}

/// Read the current exception level
pub fn current_el() -> ExceptionLevel {
    let el: u64;
    unsafe {
        asm!("mrs {}, CurrentEL", out(reg) el);
    }
    match (el >> 2) & 0x3 {
        0 => ExceptionLevel::EL0,
        1 => ExceptionLevel::EL1,
        2 => ExceptionLevel::EL2,
        3 => ExceptionLevel::EL3,
        _ => unreachable!(),
    }
}

/// Read MPIDR_EL1 (Multiprocessor Affinity Register)
///
/// Returns the CPU's affinity values used to identify it in SMP systems.
pub fn read_mpidr() -> u64 {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) mpidr);
    }
    mpidr
}

/// Get the CPU ID from MPIDR (Aff0 field, bits [7:0])
///
/// This is typically the CPU number within a cluster.
pub fn cpu_id() -> u32 {
    (read_mpidr() & 0xFF) as u32
}

/// Initialize CPU features and configuration
///
/// Called early in boot before the MMU is enabled.
pub fn init() {
    // Verify we're running at EL1 (kernel mode)
    let el = current_el();
    if el != ExceptionLevel::EL1 {
        // We should be at EL1 after the bootloader hands off to us
        // If not, we'd need to drop from EL2 to EL1
        // For now, just continue - QEMU with -kernel starts us at EL1
    }

    // Enable floating point and SIMD (NEON)
    // CPACR_EL1.FPEN = 0b11 (bits [21:20])
    unsafe {
        let mut cpacr: u64;
        asm!("mrs {}, cpacr_el1", out(reg) cpacr);
        cpacr |= 0x3 << 20; // FPEN = full access
        asm!("msr cpacr_el1, {}", in(reg) cpacr);
        asm!("isb");
    }

    // Privileged Access Never (ARMv8.1+), if implemented
    super::uaccess::pan_init_cpu();
    if super::uaccess::pan_enabled() {
        crate::printkln!("CPU: PAN (Privileged Access Never) enabled");
    }
}

/// Halt the CPU until an interrupt arrives
#[inline]
pub fn halt() {
    unsafe {
        asm!("wfi", options(nomem, nostack));
    }
}

/// Enable interrupts (clear DAIF.I bit)
#[inline]
pub fn enable_interrupts() {
    unsafe {
        asm!("msr daifclr, #2", options(nostack));
    }
}

/// Disable interrupts (set DAIF.I bit)
#[inline]
pub fn disable_interrupts() {
    unsafe {
        asm!("msr daifset, #2", options(nostack));
    }
}

/// ELF auxv AT_HWCAP (Linux arch/arm64/include/uapi/asm/hwcap.h): FP and
/// ASIMD (always present here), plus the ID_AA64ISAR0_EL1 crypto, CRC32
/// and LSE atomics features. HWCAP_CPUID is not reported: EL0 reads of
/// ID registers are not emulated.
pub fn elf_hwcap() -> u64 {
    const FP: u64 = 1 << 0;
    const ASIMD: u64 = 1 << 1;
    const AES: u64 = 1 << 3;
    const PMULL: u64 = 1 << 4;
    const SHA1: u64 = 1 << 5;
    const SHA2: u64 = 1 << 6;
    const CRC32: u64 = 1 << 7;
    const ATOMICS: u64 = 1 << 8;
    let isar0: u64;
    unsafe {
        core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack))
    };
    let field = |shift: u32| (isar0 >> shift) & 0xf;
    let mut hwcap = FP | ASIMD;
    for (on, bit) in [
        (field(4) >= 1, AES),
        (field(4) >= 2, PMULL),
        (field(8) >= 1, SHA1),
        (field(12) >= 1, SHA2),
        (field(16) >= 1, CRC32),
        (field(20) >= 2, ATOMICS),
    ] {
        if on {
            hwcap |= bit;
        }
    }
    hwcap
}

/// ELF auxv AT_PLATFORM string
pub const ELF_PLATFORM: &[u8] = b"aarch64";

/// A hardware random seed (Linux arch_get_random_seed_longs): RNDRRS,
/// reseeded from the true source, when ID_AA64ISAR0_EL1.RNDR says it
/// exists; it reports failure in PSTATE.Z
pub fn arch_random_seed() -> Option<u64> {
    let isar0: u64;
    // SAFETY: an ID register read
    unsafe {
        core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack))
    };
    if (isar0 >> 60) & 0xf == 0 {
        return None;
    }
    for _ in 0..10 {
        let (v, fail): (u64, u64);
        // SAFETY: FEAT_RNG is present; s3_3_c2_c4_1 is RNDRRS
        unsafe {
            core::arch::asm!(
                "mrs {v}, s3_3_c2_c4_1",
                "cset {f}, eq",
                v = out(reg) v,
                f = out(reg) fail,
                options(nomem, nostack)
            )
        };
        if fail == 0 {
            return Some(v);
        }
    }
    None
}

/// A fast-changing counter to mix in as entropy (Linux
/// random_get_entropy: the virtual counter)
pub fn random_get_entropy() -> u64 {
    let c: u64;
    // SAFETY: CNTVCT_EL0 is readable at EL1
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) c, options(nomem, nostack)) };
    c
}
