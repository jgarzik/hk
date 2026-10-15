//! User FP/SIMD state (x87, SSE, AVX) for x86-64
//!
//! The kernel is built soft-float (`x86_64-unknown-none`): kernel code never
//! touches x87/XMM/YMM state, so while a task is in the kernel its user FP
//! state simply stays in the registers. It only has to be moved to memory
//! when another task is about to run:
//!
//! - `context_switch` saves the outgoing task's registers into an area on its
//!   own kernel stack and reloads them when that task is switched back in
//!   (eager save/restore, no lazy #NM trapping).
//! - fork/clone saves the parent's registers at the top of the child's
//!   kernel stack ([`CLONE_FPU_RESERVE`]); the child loads them in
//!   `clone_child_entry` before its first return to user mode.
//! - execve and the first entry to user mode load the initial state.
//! - signal delivery writes the registers to the user signal frame (Linux
//!   fpstate layout, `_fpx_sw_bytes` + FP_XSTATE_MAGIC2 when XSAVE is used)
//!   and gives the handler the initial state; rt_sigreturn validates the
//!   frame and loads it back.
//!
//! XSAVE/XRSTOR (standard format) are used when the CPU supports them, with
//! XCR0 = x87 | SSE (| AVX); otherwise FXSAVE/FXRSTOR (x87 + SSE only).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::cpu::cpuid;

/// Bytes reserved for one save area (XSAVE x87|SSE|AVX needs 832)
pub const FPU_AREA_SIZE: usize = 1024;

/// Bytes reserved at the top of a clone child's kernel stack for the
/// inherited FP state (above its trap frame); see `clone_child_entry`
pub const CLONE_FPU_RESERVE: u64 = FPU_AREA_SIZE as u64;

/// XCR0 feature bits
const XFEATURE_X87: u64 = 1 << 0;
const XFEATURE_SSE: u64 = 1 << 1;
const XFEATURE_AVX: u64 = 1 << 2;

/// CR4 bits
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_OSXSAVE: u64 = 1 << 18;

/// Offsets in the legacy (FXSAVE) region
const FXSAVE_MXCSR: usize = 24;
const FXSAVE_MXCSR_MASK: usize = 28;
/// Software-reserved bytes 464..512 hold `struct _fpx_sw_bytes` in signal frames
const FXSAVE_SW_BYTES: usize = 464;
/// XSAVE header (XSTATE_BV, XCOMP_BV, reserved) follows the legacy region
const XSAVE_HDR: usize = 512;
const XSAVE_HDR_SIZE: usize = 64;

/// Linux signal-frame magic numbers (arch/x86/include/uapi/asm/sigcontext.h)
pub const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
pub const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
pub const FP_XSTATE_MAGIC2_SIZE: usize = 4;

/// Initial MXCSR (all exceptions masked, round to nearest)
pub const MXCSR_DEFAULT: u32 = 0x1f80;
/// Initial x87 control word
const FCW_DEFAULT: u16 = 0x037f;

static USE_XSAVE: AtomicBool = AtomicBool::new(false);
/// XCR0 programmed on every CPU (0 without XSAVE)
static XCR0: AtomicU64 = AtomicU64::new(0);
/// Bytes of the standard-format XSAVE image for XCR0 (512 for FXSAVE)
static XSTATE_SIZE: AtomicU32 = AtomicU32::new(512);
/// Writable MXCSR bits (MXCSR_MASK)
static MXCSR_MASK: AtomicU32 = AtomicU32::new(0xffbf);

/// One FXSAVE/XSAVE image (64-byte aligned as XSAVE requires)
#[repr(C, align(64))]
#[derive(Clone)]
pub struct FpuArea(pub [u8; FPU_AREA_SIZE]);

impl FpuArea {
    /// The architectural initial state (FNINIT + MXCSR default, zero
    /// registers; XSTATE_BV = 0 makes XRSTOR initialize every component)
    pub const fn init() -> Self {
        let mut a = [0u8; FPU_AREA_SIZE];
        let fcw = FCW_DEFAULT.to_le_bytes();
        a[0] = fcw[0];
        a[1] = fcw[1];
        let m = MXCSR_DEFAULT.to_le_bytes();
        a[FXSAVE_MXCSR] = m[0];
        a[FXSAVE_MXCSR + 1] = m[1];
        Self(a)
    }

    fn u32_at(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.0[off..off + 4].try_into().unwrap())
    }

    fn u64_at(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.0[off..off + 8].try_into().unwrap())
    }

    fn set_u32(&mut self, off: usize, v: u32) {
        self.0[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn set_u64(&mut self, off: usize, v: u64) {
        self.0[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
}

static INIT_AREA: FpuArea = FpuArea::init();

fn read_cr4() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack)) };
    v
}

fn write_cr4(v: u64) {
    unsafe { core::arch::asm!("mov cr4, {}", in(reg) v, options(nomem, nostack)) };
}

fn xsetbv(xcr0: u64) {
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") xcr0 as u32,
            in("edx") (xcr0 >> 32) as u32,
            options(nomem, nostack)
        );
    }
}

/// Enable FP/SIMD for this CPU (CR0.MP, CR4.OSFXSR/OSXMMEXCPT[/OSXSAVE],
/// XCR0). The BSP (`bsp == true`) also probes the features and save size
/// used everywhere; APs must run this after the BSP did.
pub fn init_cpu(bsp: bool) {
    unsafe {
        let mut cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        cr0 &= !(1 << 2); // EM: no emulation
        cr0 &= !(1 << 3); // TS: no lazy #NM
        cr0 |= 1 << 1; // MP
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack));
    }
    let mut cr4 = read_cr4() | CR4_OSFXSR | CR4_OSXMMEXCPT;

    if bsp {
        let (_, _, ecx, _) = cpuid(1, 0);
        let has_xsave = ecx & (1 << 26) != 0;
        let has_avx = ecx & (1 << 28) != 0;
        if has_xsave {
            let (supported_lo, _, _, supported_hi) = cpuid(0xd, 0);
            let supported = ((supported_hi as u64) << 32) | supported_lo as u64;
            let mut xcr0 = XFEATURE_X87 | XFEATURE_SSE;
            if has_avx && supported & XFEATURE_AVX != 0 {
                xcr0 |= XFEATURE_AVX;
            }
            write_cr4(cr4 | CR4_OSXSAVE);
            xsetbv(xcr0);
            // EBX: size of the standard-format image for the enabled XCR0
            let (_, size, _, _) = cpuid(0xd, 0);
            if (size as usize) <= FPU_AREA_SIZE - FP_XSTATE_MAGIC2_SIZE {
                XCR0.store(xcr0, Ordering::Relaxed);
                XSTATE_SIZE.store(size, Ordering::Relaxed);
                USE_XSAVE.store(true, Ordering::Release);
            } else {
                xsetbv(XFEATURE_X87 | XFEATURE_SSE);
                write_cr4(cr4);
            }
        }
    }
    if USE_XSAVE.load(Ordering::Acquire) {
        cr4 |= CR4_OSXSAVE;
        write_cr4(cr4);
        xsetbv(XCR0.load(Ordering::Relaxed));
    } else {
        write_cr4(cr4);
    }
    unsafe { core::arch::asm!("fninit", options(nomem, nostack)) };

    if bsp {
        // MXCSR_MASK from an FXSAVE image (0 means the default 0xffbf)
        let mut a = FpuArea::init();
        unsafe {
            core::arch::asm!("fxsave64 [{}]", in(reg) a.0.as_mut_ptr(), options(nostack));
        }
        let mask = a.u32_at(FXSAVE_MXCSR_MASK);
        MXCSR_MASK.store(if mask == 0 { 0xffbf } else { mask }, Ordering::Relaxed);
    }
    restore(&INIT_AREA);
}

/// Whether XSAVE is in use
pub fn use_xsave() -> bool {
    USE_XSAVE.load(Ordering::Relaxed)
}

/// Enabled XSAVE features (XCR0; 0 without XSAVE)
pub fn xfeatures() -> u64 {
    XCR0.load(Ordering::Relaxed)
}

/// Size of a saved image (XSAVE standard format, or 512 for FXSAVE)
pub fn xstate_size() -> usize {
    XSTATE_SIZE.load(Ordering::Relaxed) as usize
}

/// Save this CPU's FP/SIMD registers into `area`
#[inline]
pub fn save(area: &mut FpuArea) {
    unsafe { save_raw(area) }
}

/// Load the FP/SIMD registers from `area` (a kernel-produced or validated image)
#[inline]
pub fn restore(area: &FpuArea) {
    unsafe { restore_raw(area) }
}

/// [`save`] into possibly uninitialized memory
///
/// # Safety
/// `area` must be valid for writes of an `FpuArea` and 64-byte aligned.
#[inline]
pub unsafe fn save_raw(area: *mut FpuArea) {
    let p = area as *mut u8;
    unsafe {
        if use_xsave() {
            // XSAVE writes only XSTATE_BV of the header: XCOMP_BV and the
            // reserved bytes must be zero or XRSTOR faults (#GP)
            core::ptr::write_bytes(p.add(XSAVE_HDR), 0, XSAVE_HDR_SIZE);
            core::arch::asm!(
                "xsave64 [{}]",
                in(reg) p,
                in("eax") u32::MAX,
                in("edx") u32::MAX,
                options(nostack)
            );
        } else {
            core::arch::asm!("fxsave64 [{}]", in(reg) p, options(nostack));
        }
    }
}

/// [`restore`] from a raw pointer
///
/// # Safety
/// `area` must point to an image produced by [`save`]/[`save_raw`] (or
/// validated by [`sanitize_sigframe`]), 64-byte aligned.
#[inline]
pub unsafe fn restore_raw(area: *const FpuArea) {
    let p = area as *const u8;
    unsafe {
        if use_xsave() {
            core::arch::asm!(
                "xrstor64 [{}]",
                in(reg) p,
                in("eax") u32::MAX,
                in("edx") u32::MAX,
                options(nostack)
            );
        } else {
            core::arch::asm!("fxrstor64 [{}]", in(reg) p, options(nostack));
        }
    }
}

/// Load the initial FP/SIMD state (execve, signal handler entry)
pub fn load_init_state() {
    restore(&INIT_AREA);
}

/// `clone_child_entry` helper: load the FP state the parent saved at `area`
///
/// # Safety
/// `area` must point to an `FpuArea` written by [`save`].
pub unsafe extern "C" fn restore_from_raw(area: *const FpuArea) {
    unsafe { restore_raw(area) };
}

/// Save the current (parent) FP state at the top of a clone child's kernel
/// stack (`kstack_top - CLONE_FPU_RESERVE`)
pub fn save_for_clone_child(kstack_top: u64) {
    let area = (kstack_top - CLONE_FPU_RESERVE) as *mut FpuArea;
    // Kernel stack top is page aligned, so the area is 64-byte aligned
    unsafe { save(&mut *area) };
}

/// Build the signal-frame image of the current FP state in `area`: the
/// registers plus Linux's `_fpx_sw_bytes` (XSAVE only). Returns the number
/// of bytes to copy to the user frame.
pub fn save_sigframe(area: &mut FpuArea) -> usize {
    save(area);
    if !use_xsave() {
        // Linux leaves the sw bytes zero for an FXSAVE frame
        area.0[FXSAVE_SW_BYTES..XSAVE_HDR].fill(0);
        return 512;
    }
    let size = xstate_size();
    let sw = FXSAVE_SW_BYTES;
    area.0[sw..XSAVE_HDR].fill(0);
    area.set_u32(sw, FP_XSTATE_MAGIC1);
    area.set_u32(sw + 4, (size + FP_XSTATE_MAGIC2_SIZE) as u32); // extended_size
    area.set_u64(sw + 8, xfeatures()); // xfeatures
    area.set_u32(sw + 16, size as u32); // xstate_size
    area.set_u32(size, FP_XSTATE_MAGIC2);
    size + FP_XSTATE_MAGIC2_SIZE
}

/// Bytes the signal frame reserves for the FP image
pub fn sigframe_size() -> usize {
    if use_xsave() {
        xstate_size() + FP_XSTATE_MAGIC2_SIZE
    } else {
        512
    }
}

/// Validate a user-supplied signal-frame image (copied into `area`, of
/// which the first `sigframe_size()` bytes are valid) and turn it into
/// something XRSTOR/FXRSTOR accepts. Returns false for a bad frame.
pub fn sanitize_sigframe(area: &mut FpuArea) -> bool {
    let mxcsr_mask = MXCSR_MASK.load(Ordering::Relaxed);
    if area.u32_at(FXSAVE_MXCSR) & !mxcsr_mask != 0 {
        return false;
    }
    if !use_xsave() {
        return true;
    }
    let size = xstate_size();
    let sw = FXSAVE_SW_BYTES;
    let extended = area.u32_at(sw) == FP_XSTATE_MAGIC1
        && area.u32_at(sw + 4) as usize == size + FP_XSTATE_MAGIC2_SIZE
        && area.u32_at(sw + 16) as usize == size
        && area.u32_at(size) == FP_XSTATE_MAGIC2;
    let xcr0 = xfeatures();
    if extended {
        // Only the features the frame claims, all of them enabled
        let frame_features = area.u64_at(sw + 8) & xcr0;
        let bv = area.u64_at(XSAVE_HDR) & frame_features;
        area.set_u64(XSAVE_HDR, bv);
    } else {
        // Plain FXSAVE image: x87 + SSE from the frame, the rest initial
        area.0[512..FPU_AREA_SIZE].fill(0);
        area.set_u64(XSAVE_HDR, XFEATURE_X87 | XFEATURE_SSE);
    }
    // XCOMP_BV and the reserved header bytes must be zero (else #GP)
    area.0[XSAVE_HDR + 8..XSAVE_HDR + XSAVE_HDR_SIZE].fill(0);
    true
}
