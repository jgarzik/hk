//! CPUID and model-specific registers: the one place that runs these
//! instructions (doc/UNSAFE.md rule 2)
//!
//! `cpuid` and `rdmsr` are safe fns: neither touches memory, and a
//! missing MSR is a #GP (an oops, not undefined behaviour). `wrmsr` is
//! unsafe: MSRs such as EFER, PAT, LSTAR or the GS base change how the
//! kernel's memory is reached.

/// CPUID leaf `leaf`, subleaf `sub`: (eax, ebx, ecx, edx)
#[inline]
pub fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    // SAFETY: CPUID is present on every x86-64 CPU and only writes the
    // four registers; rbx (reserved by LLVM) is saved by hand
    unsafe {
        ::core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            inout("ecx") sub => ecx,
            ebx_out = out(reg) ebx,
            lateout("edx") edx,
        );
    }
    (eax, ebx, ecx, edx)
}

/// Read MSR `msr` (a missing one is a #GP)
#[inline]
pub fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: reads a register, touches no memory. No `nomem`: some MSR
    // reads order against memory (the x2APIC ones)
    unsafe {
        ::core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags)
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Write `v` to MSR `msr`
///
/// # Safety
/// The MSR exists, and the new value keeps the kernel's memory reachable
/// as the rest of the kernel assumes (EFER, PAT, LSTAR, GS base, ...).
#[inline]
pub unsafe fn wrmsr(msr: u32, v: u64) {
    // SAFETY: per the caller. No `nomem`: an MSR write may change how
    // memory is reached, so memory accesses must not move across it
    unsafe {
        ::core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") v as u32,
            in("edx") (v >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}
