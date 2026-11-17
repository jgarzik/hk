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
//! - fork/clone saves the parent's registers just below the child's
//!   pt_regs (`save_for_clone_child`); the child loads them in
//!   `ret_from_fork` before its first return to user mode.
//! - execve and the first entry to user mode load the initial state.
//! - signal delivery saves the registers straight into the user signal
//!   frame (Linux fpstate layout, `_fpx_sw_bytes` + FP_XSTATE_MAGIC2 when
//!   XSAVE is used) and gives the handler the initial state; rt_sigreturn
//!   loads them straight from the frame, a malformed image trapping to
//!   the restore's fixup (a bad frame).
//!
//! XSAVE/XRSTOR (standard format) are used when the CPU supports them, with
//! XCR0 = x87 | SSE (| AVX); otherwise FXSAVE/FXRSTOR (x87 + SSE only).
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::cpu::cpuid;

/// Bytes reserved for one save area (XSAVE x87|SSE|AVX needs 832)
pub const FPU_AREA_SIZE: usize = 1024;

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
}

static INIT_AREA: FpuArea = FpuArea::init();

fn read_cr4() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack)) };
    v
}

fn write_cr4(v: u64) {
    unsafe { core::arch::asm!("mov cr4, {}", in(reg) v, options(nostack)) };
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
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nostack));
    }
    let mut cr4 = read_cr4() | CR4_OSFXSR | CR4_OSXMMEXCPT;

    if bsp {
        let (_, _, ecx, _) = cpuid(1, 0);
        let has_xsave = ecx & (1 << 26) != 0;
        let has_avx = ecx & (1 << 28) != 0;
        if has_xsave {
            let (supported_lo, _, _, supported_hi) = cpuid(0xd, 0);
            let supported = (u64::from(supported_hi) << 32) | u64::from(supported_lo);
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
    let p = area.cast::<u8>();
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
/// `area` must point to an image produced by [`save`]/[`save_raw`],
/// 64-byte aligned.
#[inline]
pub unsafe fn restore_raw(area: *const FpuArea) {
    let p = area.cast::<u8>();
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

/// Save the current (parent) FP state for a clone child, just below its
/// pt_regs at `regs` (64-byte aligned, as XSAVE wants); returns the area,
/// where the child's first switch frame ends (`ret_from_fork` loads it)
///
/// # Safety
/// `regs` is the TrapFrame address at the top of a kernel stack whose
/// task has not run yet, with room below it for the area.
pub unsafe fn save_for_clone_child(regs: u64) -> u64 {
    let area = (regs - FPU_AREA_SIZE as u64) & !63;
    // SAFETY: the child's kernel stack, not running yet (caller)
    unsafe { save(&mut *(area as *mut FpuArea)) };
    area
}

/// Save the registers straight into the user signal frame's FP image at
/// `buf` (64-byte aligned, [`sigframe_size`] bytes that passed
/// access_ok), page faults disabled: false at a fault, which the caller
/// resolves and retries (Linux copy_fpregs_to_sigframe)
pub fn save_to_user(buf: u64) -> bool {
    assert!(buf % 64 == 0, "FP signal image not 64-byte aligned");
    if !crate::uaccess::access_ok(buf, sigframe_size()) {
        return false;
    }
    crate::uaccess::pagefault_disable();
    // SAFETY: aligned and in user space (checked above); user access
    // open around it only
    let ok = unsafe {
        <super::uaccess::X86_64Uaccess as crate::uaccess::UaccessArch>::user_access_begin();
        let ok = super::uaccess::fpsave_user(buf, use_xsave(), xfeatures());
        <super::uaccess::X86_64Uaccess as crate::uaccess::UaccessArch>::user_access_end();
        ok
    };
    crate::uaccess::pagefault_enable();
    ok
}

/// Load the registers straight from the user signal frame's image at
/// `buf` with page faults disabled (Linux __restore_fpregs_from_user):
/// XRSTOR of the features in `xrestore`, or FXRSTOR for an image with
/// only the legacy part (`fx_only`, or no XSAVE), the other enabled
/// features then set to their initial state. Err: the number of the
/// trap that stopped it (14: a page fault, which the caller resolves
/// and retries)
pub fn restore_from_user(buf: u64, xrestore: u64, fx_only: bool) -> Result<(), u32> {
    if !crate::uaccess::access_ok(buf, sigframe_size()) {
        return Err(14);
    }
    crate::uaccess::pagefault_disable();
    // SAFETY: in user space (checked above); a misaligned or malformed
    // image traps to the fixup; user access open around it only
    let trap = unsafe {
        <super::uaccess::X86_64Uaccess as crate::uaccess::UaccessArch>::user_access_begin();
        let t = super::uaccess::fprestore_user(buf, use_xsave() && !fx_only, xrestore);
        <super::uaccess::X86_64Uaccess as crate::uaccess::UaccessArch>::user_access_end();
        t
    };
    crate::uaccess::pagefault_enable();
    if trap != 0 {
        return Err(trap);
    }
    let init = xfeatures() & !xrestore;
    if use_xsave() && init != 0 {
        // SAFETY: the initial image, XSTATE_BV 0: XRSTOR initializes
        // the features in `init`
        unsafe {
            core::arch::asm!(
                "xrstor64 [{}]",
                in(reg) INIT_AREA.0.as_ptr(),
                // Truncating on purpose: EDX:EAX halves of the mask
                in("eax") init as u32,
                in("edx") (init >> 32) as u32,
                options(nostack)
            );
        }
    }
    Ok(())
}

/// The XSAVE header's offset in an image, cleared before an XSAVE to
/// the user frame (Linux: so its reserved fields are zero)
pub const fn xsave_header() -> (usize, usize) {
    (XSAVE_HDR, XSAVE_HDR_SIZE)
}

/// Linux `_fpx_sw_bytes` of a signal frame's image, at its offset:
/// FP_XSTATE_MAGIC1, extended size, features and image size with XSAVE
/// (Linux save_sw_bytes); zero for an FXSAVE frame
pub fn sw_bytes() -> (usize, [u8; XSAVE_HDR - FXSAVE_SW_BYTES]) {
    let mut sw = [0u8; XSAVE_HDR - FXSAVE_SW_BYTES];
    if use_xsave() {
        let size = xstate_size();
        // extended_size and xstate_size fit u32 (FPU_AREA_SIZE bound)
        sw[0..4].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
        sw[4..8].copy_from_slice(&((size + FP_XSTATE_MAGIC2_SIZE) as u32).to_le_bytes());
        sw[8..16].copy_from_slice(&xfeatures().to_le_bytes());
        sw[16..20].copy_from_slice(&(size as u32).to_le_bytes());
    }
    (FXSAVE_SW_BYTES, sw)
}

/// x87 | SSE in XSTATE_BV, always set in a signal frame's image (Linux
/// save_xstate_epilog: XFEATURE_MASK_FPSSE)
pub const XFEATURE_MASK_FPSSE: u32 = (XFEATURE_X87 | XFEATURE_SSE) as u32;

/// Bytes the signal frame reserves for the FP image
pub fn sigframe_size() -> usize {
    if use_xsave() {
        xstate_size() + FP_XSTATE_MAGIC2_SIZE
    } else {
        512
    }
}
