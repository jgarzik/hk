//! User FP/SIMD state preservation tests
//!
//! Tests:
//! - FPU_CTXSW: two processes ping-pong over pipes (each read blocks, so the
//!   kernel switches tasks) with distinct values in every SIMD register,
//!   MXCSR/x87 control word (x86) or FPCR/FPSR (arm64); all must survive.
//!   On x86 with AVX enabled by the OS the upper YMM halves are checked too.
//! - FPU_FORK: a fork() child inherits the parent's SIMD registers.
//! - FPU_SIGNAL: a signal handler that clobbers every SIMD register does not
//!   corrupt the interrupted code; the frame holds the interrupted FP state
//!   (Linux layout: x86 fpstate / arm64 fpsimd_context) and rt_sigreturn
//!   restores it from the frame (an edit made by the handler takes effect).
//!   On x86 the handler starts with the default MXCSR (0x1f80).

use super::helpers::{print, print_num, println};
use hk_syscall::{
    SA_RESTORER, SA_SIGINFO, SIG_DFL, SIGUSR1, sys_close, sys_exit, sys_getpid, sys_pipe,
    sys_rt_sigaction, sys_wait4,
};

/// Number of SIMD registers tested
#[cfg(target_arch = "x86_64")]
const NREGS: usize = 16;
#[cfg(target_arch = "aarch64")]
const NREGS: usize = 32;

#[cfg(target_arch = "x86_64")]
const SYS_READ: u64 = 0;
#[cfg(target_arch = "x86_64")]
const SYS_WRITE: u64 = 1;
#[cfg(target_arch = "x86_64")]
const SYS_KILL: u64 = 62;
#[cfg(target_arch = "aarch64")]
const SYS_READ: u64 = 63;
#[cfg(target_arch = "aarch64")]
const SYS_WRITE: u64 = 64;
#[cfg(target_arch = "aarch64")]
const SYS_KILL: u64 = 129;

/// Non-default control state: x86 MXCSR (all exceptions masked, round toward
/// zero, FTZ) / arm64 FPCR (round toward +inf, FZ)
#[cfg(target_arch = "x86_64")]
const CTRL_A: u64 = 0x1f80 | 0x6000 | 0x8000;
#[cfg(target_arch = "x86_64")]
const CTRL_B: u64 = 0x1f80 | 0x2000;
#[cfg(target_arch = "aarch64")]
const CTRL_A: u64 = (1 << 22) | (1 << 24);
#[cfg(target_arch = "aarch64")]
const CTRL_B: u64 = 2 << 22;

/// Second control/status value: x87 control word (x86) / FPSR (arm64)
#[cfg(target_arch = "x86_64")]
const CTRL2_A: u64 = 0x0f7f; // RC = toward zero, PC = 64-bit, all masked
#[cfg(target_arch = "x86_64")]
const CTRL2_B: u64 = 0x077f; // RC = up
#[cfg(target_arch = "aarch64")]
const CTRL2_A: u64 = 0x0800_0011; // QC | IXC | IOC
#[cfg(target_arch = "aarch64")]
const CTRL2_B: u64 = 0x0000_0006; // OFC | DZC

/// Register image used by the asm blocks
#[repr(C, align(32))]
#[derive(Clone, Copy)]
struct FpImage {
    v: [[u64; 2]; NREGS],
    /// MXCSR / FPCR
    ctrl: u64,
    /// x87 FCW / FPSR
    ctrl2: u64,
    /// x87 st(0) integer (x86 only)
    x87: u64,
}

impl FpImage {
    const fn zero() -> Self {
        Self {
            v: [[0; 2]; NREGS],
            ctrl: 0,
            ctrl2: 0,
            x87: 0,
        }
    }

    fn pattern(tag: u64, iter: u64) -> Self {
        let mut img = Self::zero();
        for (k, r) in img.v.iter_mut().enumerate() {
            let lo = (tag << 56) | ((k as u64) << 40) | (iter << 8) | 0xa5;
            r[0] = lo;
            r[1] = !lo ^ (tag << 32);
        }
        let b = tag & 1 == 0;
        img.ctrl = if b { CTRL_B } else { CTRL_A };
        img.ctrl2 = if b { CTRL2_B } else { CTRL2_A };
        img.x87 = (tag << 32) | iter;
        img
    }

    /// First mismatching register index (NREGS = control, NREGS+1 = ctrl2,
    /// NREGS+2 = x87), or None
    fn diff(&self, other: &Self) -> Option<usize> {
        for k in 0..NREGS {
            if self.v[k] != other.v[k] {
                return Some(k);
            }
        }
        if self.ctrl != other.ctrl {
            return Some(NREGS);
        }
        if self.ctrl2 != other.ctrl2 {
            return Some(NREGS + 1);
        }
        #[cfg(target_arch = "x86_64")]
        if self.x87 != other.x87 {
            return Some(NREGS + 2);
        }
        None
    }
}

/// Load `inp` into the FP/SIMD registers, do two syscalls `nr1(a1, b, 1)`
/// and `nr2(a2, b, 1)`, then store the registers into `out`. Returns the
/// second syscall's result.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn fp_roundtrip(
    inp: &FpImage,
    out: &mut FpImage,
    nr1: u64,
    a1: u64,
    nr2: u64,
    a2: u64,
    b: u64,
) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "movdqu xmm0, [{i} + 0]",
            "movdqu xmm1, [{i} + 16]",
            "movdqu xmm2, [{i} + 32]",
            "movdqu xmm3, [{i} + 48]",
            "movdqu xmm4, [{i} + 64]",
            "movdqu xmm5, [{i} + 80]",
            "movdqu xmm6, [{i} + 96]",
            "movdqu xmm7, [{i} + 112]",
            "movdqu xmm8, [{i} + 128]",
            "movdqu xmm9, [{i} + 144]",
            "movdqu xmm10, [{i} + 160]",
            "movdqu xmm11, [{i} + 176]",
            "movdqu xmm12, [{i} + 192]",
            "movdqu xmm13, [{i} + 208]",
            "movdqu xmm14, [{i} + 224]",
            "movdqu xmm15, [{i} + 240]",
            "ldmxcsr [{i} + 256]",
            "fninit",
            "fldcw [{i} + 264]",
            "fild qword ptr [{i} + 272]",
            "mov rax, {nr1}",
            "mov rdi, {a1}",
            "mov rsi, {buf}",
            "mov edx, 1",
            "syscall",
            "mov rax, {nr2}",
            "mov rdi, {a2}",
            "mov rsi, {buf}",
            "mov edx, 1",
            "syscall",
            "movdqu [{o} + 0], xmm0",
            "movdqu [{o} + 16], xmm1",
            "movdqu [{o} + 32], xmm2",
            "movdqu [{o} + 48], xmm3",
            "movdqu [{o} + 64], xmm4",
            "movdqu [{o} + 80], xmm5",
            "movdqu [{o} + 96], xmm6",
            "movdqu [{o} + 112], xmm7",
            "movdqu [{o} + 128], xmm8",
            "movdqu [{o} + 144], xmm9",
            "movdqu [{o} + 160], xmm10",
            "movdqu [{o} + 176], xmm11",
            "movdqu [{o} + 192], xmm12",
            "movdqu [{o} + 208], xmm13",
            "movdqu [{o} + 224], xmm14",
            "movdqu [{o} + 240], xmm15",
            "stmxcsr [{o} + 256]",
            "fnstcw [{o} + 264]",
            "fistp qword ptr [{o} + 272]",
            // Back to the ABI defaults for compiled code
            "fninit",
            "mov dword ptr [{o} + 280], 0x1f80",
            "ldmxcsr [{o} + 280]",
            "mov dword ptr [{o} + 280], 0",
            i = in(reg) inp as *const FpImage,
            o = in(reg) out as *mut FpImage,
            buf = in(reg) b,
            nr1 = in(reg) nr1,
            a1 = in(reg) a1,
            nr2 = in(reg) nr2,
            a2 = in(reg) a2,
            out("rax") ret,
            out("rdi") _, out("rsi") _, out("rdx") _, out("rcx") _, out("r11") _,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
        );
    }
    out.ctrl &= 0xffff;
    out.ctrl2 &= 0xffff;
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(never)]
fn fp_roundtrip(
    inp: &FpImage,
    out: &mut FpImage,
    nr1: u64,
    a1: u64,
    nr2: u64,
    a2: u64,
    b: u64,
) -> i64 {
    let ret: i64;
    let fpcr: u64;
    let fpsr: u64;
    unsafe {
        core::arch::asm!(
            "ldp q0, q1, [{i}, #0]",
            "ldp q2, q3, [{i}, #32]",
            "ldp q4, q5, [{i}, #64]",
            "ldp q6, q7, [{i}, #96]",
            "ldp q8, q9, [{i}, #128]",
            "ldp q10, q11, [{i}, #160]",
            "ldp q12, q13, [{i}, #192]",
            "ldp q14, q15, [{i}, #224]",
            "ldp q16, q17, [{i}, #256]",
            "ldp q18, q19, [{i}, #288]",
            "ldp q20, q21, [{i}, #320]",
            "ldp q22, q23, [{i}, #352]",
            "ldp q24, q25, [{i}, #384]",
            "ldp q26, q27, [{i}, #416]",
            "ldp q28, q29, [{i}, #448]",
            "ldp q30, q31, [{i}, #480]",
            "ldr x0, [{i}, #512]",
            "msr fpcr, x0",
            "ldr x0, [{i}, #520]",
            "msr fpsr, x0",
            "mov x8, {nr1}",
            "mov x0, {a1}",
            "mov x1, {buf}",
            "mov x2, #1",
            "svc #0",
            "mov x8, {nr2}",
            "mov x0, {a2}",
            "mov x1, {buf}",
            "mov x2, #1",
            "svc #0",
            "stp q0, q1, [{o}, #0]",
            "stp q2, q3, [{o}, #32]",
            "stp q4, q5, [{o}, #64]",
            "stp q6, q7, [{o}, #96]",
            "stp q8, q9, [{o}, #128]",
            "stp q10, q11, [{o}, #160]",
            "stp q12, q13, [{o}, #192]",
            "stp q14, q15, [{o}, #224]",
            "stp q16, q17, [{o}, #256]",
            "stp q18, q19, [{o}, #288]",
            "stp q20, q21, [{o}, #320]",
            "stp q22, q23, [{o}, #352]",
            "stp q24, q25, [{o}, #384]",
            "stp q26, q27, [{o}, #416]",
            "stp q28, q29, [{o}, #448]",
            "stp q30, q31, [{o}, #480]",
            "mrs {fpcr}, fpcr",
            "mrs {fpsr}, fpsr",
            // Back to the ABI defaults for compiled code
            "msr fpcr, xzr",
            "msr fpsr, xzr",
            i = in(reg) inp as *const FpImage,
            o = in(reg) out as *mut FpImage,
            buf = in(reg) b,
            nr1 = in(reg) nr1,
            a1 = in(reg) a1,
            nr2 = in(reg) nr2,
            a2 = in(reg) a2,
            fpcr = out(reg) fpcr,
            fpsr = out(reg) fpsr,
            out("x0") ret,
            out("x1") _, out("x2") _, out("x8") _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            out("v24") _, out("v25") _, out("v26") _, out("v27") _,
            out("v28") _, out("v29") _, out("v30") _, out("v31") _,
        );
    }
    out.ctrl = fpcr;
    out.ctrl2 = fpsr;
    ret
}

/// AVX state usable by user code (CPUID.AVX + OSXSAVE and XCR0 has SSE|AVX)
#[cfg(target_arch = "x86_64")]
fn avx_usable() -> bool {
    let ecx = core::arch::x86_64::__cpuid(1).ecx;
    if ecx & (1 << 27) == 0 || ecx & (1 << 28) == 0 {
        return false;
    }
    let xcr0_lo: u32;
    unsafe {
        core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") xcr0_lo, out("edx") _);
    }
    xcr0_lo & 6 == 6
}

/// Like `fp_roundtrip` for the full 256-bit YMM0-15 (`inp`/`out` hold 16 x 32 bytes)
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn ymm_roundtrip(
    inp: &[u64; 64],
    out: &mut [u64; 64],
    nr1: u64,
    a1: u64,
    nr2: u64,
    a2: u64,
    b: u64,
) {
    unsafe {
        core::arch::asm!(
            "vmovdqu ymm0, [{i} + 0]",
            "vmovdqu ymm1, [{i} + 32]",
            "vmovdqu ymm2, [{i} + 64]",
            "vmovdqu ymm3, [{i} + 96]",
            "vmovdqu ymm4, [{i} + 128]",
            "vmovdqu ymm5, [{i} + 160]",
            "vmovdqu ymm6, [{i} + 192]",
            "vmovdqu ymm7, [{i} + 224]",
            "vmovdqu ymm8, [{i} + 256]",
            "vmovdqu ymm9, [{i} + 288]",
            "vmovdqu ymm10, [{i} + 320]",
            "vmovdqu ymm11, [{i} + 352]",
            "vmovdqu ymm12, [{i} + 384]",
            "vmovdqu ymm13, [{i} + 416]",
            "vmovdqu ymm14, [{i} + 448]",
            "vmovdqu ymm15, [{i} + 480]",
            "mov rax, {nr1}",
            "mov rdi, {a1}",
            "mov rsi, {buf}",
            "mov edx, 1",
            "syscall",
            "mov rax, {nr2}",
            "mov rdi, {a2}",
            "mov rsi, {buf}",
            "mov edx, 1",
            "syscall",
            "vmovdqu [{o} + 0], ymm0",
            "vmovdqu [{o} + 32], ymm1",
            "vmovdqu [{o} + 64], ymm2",
            "vmovdqu [{o} + 96], ymm3",
            "vmovdqu [{o} + 128], ymm4",
            "vmovdqu [{o} + 160], ymm5",
            "vmovdqu [{o} + 192], ymm6",
            "vmovdqu [{o} + 224], ymm7",
            "vmovdqu [{o} + 256], ymm8",
            "vmovdqu [{o} + 288], ymm9",
            "vmovdqu [{o} + 320], ymm10",
            "vmovdqu [{o} + 352], ymm11",
            "vmovdqu [{o} + 384], ymm12",
            "vmovdqu [{o} + 416], ymm13",
            "vmovdqu [{o} + 448], ymm14",
            "vmovdqu [{o} + 480], ymm15",
            "vzeroupper",
            i = in(reg) inp.as_ptr(),
            o = in(reg) out.as_mut_ptr(),
            buf = in(reg) b,
            nr1 = in(reg) nr1,
            a1 = in(reg) a1,
            nr2 = in(reg) nr2,
            a2 = in(reg) a2,
            out("rax") _, out("rdi") _, out("rsi") _, out("rdx") _, out("rcx") _, out("r11") _,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
        );
    }
}

/// Run all FP/SIMD tests
pub fn run_tests() {
    test_fpu_ctxsw();
    test_fpu_fork();
    test_fpu_signal();
}

const PINGPONG_ITERS: u64 = 40;

/// One side of the ping-pong. `first_write` decides the syscall order so the
/// two sides alternate. Returns 0 on success or 1 + index of the bad register.
fn pingpong_side(tag: u64, first_write: bool, rfd: u64, wfd: u64) -> u64 {
    let (nr1, a1, nr2, a2) = if first_write {
        (SYS_WRITE, wfd, SYS_READ, rfd)
    } else {
        (SYS_READ, rfd, SYS_WRITE, wfd)
    };
    let mut buf = [0u8; 8];
    #[cfg(target_arch = "x86_64")]
    let avx = avx_usable();
    for iter in 0..PINGPONG_ITERS {
        let inp = FpImage::pattern(tag, iter);
        let mut out = FpImage::zero();
        let r = fp_roundtrip(&inp, &mut out, nr1, a1, nr2, a2, buf.as_mut_ptr() as u64);
        if r != 1 {
            return 200;
        }
        if let Some(k) = inp.diff(&out) {
            return 1 + k as u64;
        }
        #[cfg(target_arch = "x86_64")]
        if avx {
            let mut yin = [0u64; 64];
            for (j, w) in yin.iter_mut().enumerate() {
                *w = (tag << 56) | ((j as u64) << 32) | (iter << 4) | 0x3;
            }
            let mut yout = [0u64; 64];
            ymm_roundtrip(&yin, &mut yout, nr1, a1, nr2, a2, buf.as_mut_ptr() as u64);
            if let Some(j) = (0..64).find(|&j| yin[j] != yout[j]) {
                return 100 + j as u64 / 4;
            }
        }
    }
    0
}

/// Test: FP/SIMD registers survive context switches between two processes
fn test_fpu_ctxsw() {
    let mut p2c = [0i32; 2];
    let mut c2p = [0i32; 2];
    if sys_pipe(p2c.as_mut_ptr()) != 0 || sys_pipe(c2p.as_mut_ptr()) != 0 {
        println(b"FPU_CTXSW:FAIL: pipe");
        return;
    }
    let pid = hk_syscall::sys_fork();
    if pid < 0 {
        println(b"FPU_CTXSW:FAIL: fork");
        return;
    }
    if pid == 0 {
        let bad = pingpong_side(0x77, false, p2c[0] as u64, c2p[1] as u64);
        sys_exit(bad);
    }
    let bad = pingpong_side(0x12, true, c2p[0] as u64, p2c[1] as u64);
    for fd in [p2c[0], p2c[1], c2p[0], c2p[1]] {
        sys_close(fd as u64);
    }
    let mut status: i32 = 0;
    sys_wait4(pid, &mut status, 0, 0);
    let child_bad = if status & 0x7f == 0 {
        ((status >> 8) & 0xff) as u64
    } else {
        255
    };
    if bad == 0 && child_bad == 0 {
        println(b"FPU_CTXSW:OK");
        #[cfg(target_arch = "x86_64")]
        if avx_usable() {
            // The YMM upper halves were part of the round trips
            println(b"FPU_CTXSW_AVX:OK");
        }
    } else {
        print(b"FPU_CTXSW:FAIL: parent reg ");
        print_num(bad as i64);
        print(b" child reg ");
        print_num(child_bad as i64);
        println(b"");
    }
}

/// Test: a fork() child inherits the parent's FP/SIMD registers
fn test_fpu_fork() {
    #[cfg(target_arch = "x86_64")]
    const SYS_FORK: u64 = 57;
    #[cfg(target_arch = "aarch64")]
    const SYS_FORK: u64 = 220; // clone(SIGCHLD, 0, ...)
    const SIGCHLD: u64 = 17;

    let inp = FpImage::pattern(0x5c, 9);
    let mut out = FpImage::zero();
    // First "syscall" is a harmless getpid (arg ignored); second is the fork
    #[cfg(target_arch = "x86_64")]
    let (nr1, a2) = (39u64, 0u64);
    #[cfg(target_arch = "aarch64")]
    let (nr1, a2) = (172u64, SIGCHLD);
    #[cfg(target_arch = "x86_64")]
    let _ = SIGCHLD;
    // clone's second argument (child stack) must be 0
    let pid = fp_roundtrip(&inp, &mut out, nr1, 0, SYS_FORK, a2, 0);
    let bad = inp.diff(&out);
    if pid == 0 {
        sys_exit(bad.map(|k| 1 + k as u64).unwrap_or(0));
    }
    if pid < 0 {
        println(b"FPU_FORK:FAIL: fork");
        return;
    }
    let mut status: i32 = 0;
    sys_wait4(pid, &mut status, 0, 0);
    let child_bad = if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        255
    };
    if bad.is_none() && child_bad == 0 {
        println(b"FPU_FORK:OK");
    } else {
        print(b"FPU_FORK:FAIL: parent ");
        print_num(bad.map(|k| k as i64).unwrap_or(-1));
        print(b" child ");
        print_num(child_bad as i64);
        println(b"");
    }
}

// ----------------------------------------------------------------------------
// FP state across a signal handler
// ----------------------------------------------------------------------------

/// Value the handler writes into the last vector register of the frame
const EDITED: [u64; 2] = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];

static mut SIG_SEEN: u64 = 0;
/// 0 = frame FP record ok, else an error code from the handler
static mut SIG_FRAME_ERR: u64 = 0;
/// MXCSR (x86) / FPCR (arm64) observed on handler entry
static mut SIG_HANDLER_CTRL: u64 = 0;
/// Expected value of vector register 0 in the frame
static mut SIG_EXPECT_V0: [u64; 2] = [0; 2];

/// Overwrite every SIMD register and the FP control state
#[inline(never)]
fn clobber_fp() {
    let junk = FpImage::pattern(0xee, 0xee);
    let mut sink = FpImage::zero();
    // getpid twice: no blocking, just executes the clobber
    #[cfg(target_arch = "x86_64")]
    fp_roundtrip(&junk, &mut sink, 39, 0, 39, 0, 0);
    #[cfg(target_arch = "aarch64")]
    fp_roundtrip(&junk, &mut sink, 172, 0, 172, 0, 0);
}

#[cfg(target_arch = "x86_64")]
fn read_fp_ctrl() -> u64 {
    let mut m: u32 = 0;
    unsafe { core::arch::asm!("stmxcsr [{}]", in(reg) &mut m) };
    m as u64
}

#[cfg(target_arch = "aarch64")]
fn read_fp_ctrl() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, fpcr", out(reg) v) };
    v
}

/// Locate the saved vector registers in the signal frame and check/edit them.
/// Returns 0 or an error code.
#[cfg(target_arch = "x86_64")]
unsafe fn frame_fp_check_edit(uc: *mut u8) -> u64 {
    // uc_mcontext at 40; sigcontext.fpstate at +184 (r8..cr2 = 23 words)
    let fpstate = unsafe { *(uc.add(40 + 184) as *const u64) } as *mut u8;
    if fpstate.is_null() {
        return 1;
    }
    // FXSAVE layout: MXCSR at 24, XMM0 at 160
    let mxcsr = unsafe { *(fpstate.add(24) as *const u32) } as u64;
    if mxcsr != CTRL_A & 0xffff {
        return 2;
    }
    let xmm = fpstate.wrapping_add(160) as *mut [u64; 2];
    if unsafe { *xmm } != unsafe { SIG_EXPECT_V0 } {
        return 3;
    }
    unsafe { *xmm.add(NREGS - 1) = EDITED };
    0
}

#[cfg(target_arch = "aarch64")]
unsafe fn frame_fp_check_edit(uc: *mut u8) -> u64 {
    // uc_mcontext at 176; __reserved at +288 (fault_address, regs[31], sp,
    // pc, pstate, then 16-byte alignment)
    let rec = uc.wrapping_add(176 + 288);
    let magic = unsafe { *(rec as *const u32) };
    let size = unsafe { *(rec.add(4) as *const u32) };
    if magic != 0x4650_8001 || size != 528 {
        return 1;
    }
    let fpcr = unsafe { *(rec.add(12) as *const u32) } as u64;
    if fpcr != CTRL_A {
        return 2;
    }
    let vregs = rec.wrapping_add(16) as *mut [u64; 2];
    if unsafe { *vregs } != unsafe { SIG_EXPECT_V0 } {
        return 3;
    }
    unsafe { *vregs.add(NREGS - 1) = EDITED };
    0
}

extern "C" fn fpu_sig_handler(_signo: i32, _info: *mut u8, uc: *mut u8) {
    let ctrl = read_fp_ctrl();
    let err = unsafe { frame_fp_check_edit(uc) };
    clobber_fp();
    unsafe {
        core::ptr::write_volatile(&raw mut SIG_HANDLER_CTRL, ctrl);
        core::ptr::write_volatile(&raw mut SIG_FRAME_ERR, err);
        core::ptr::write_volatile(&raw mut SIG_SEEN, 1);
    }
}

/// Test: a signal handler's FP use does not leak into the interrupted code
fn test_fpu_signal() {
    let action: [u64; 4] = [
        fpu_sig_handler as *const () as u64,
        SA_SIGINFO | SA_RESTORER,
        super::signals::restorer_addr(),
        0,
    ];
    if sys_rt_sigaction(SIGUSR1, action.as_ptr() as u64, 0, 8) != 0 {
        println(b"FPU_SIGNAL:FAIL: sigaction");
        return;
    }
    let inp = FpImage::pattern(0x31, 3);
    unsafe {
        SIG_SEEN = 0;
        SIG_FRAME_ERR = 99;
        SIG_EXPECT_V0 = inp.v[0];
    }
    let mut out = FpImage::zero();
    let pid = sys_getpid() as u64;
    // getpid, then kill(pid, SIGUSR1): the handler runs on the kill's way out
    #[cfg(target_arch = "x86_64")]
    let nr1 = 39;
    #[cfg(target_arch = "aarch64")]
    let nr1 = 172;
    let r = fp_roundtrip(&inp, &mut out, nr1, 0, SYS_KILL, pid, SIGUSR1 as u64);
    let dfl: [u64; 4] = [SIG_DFL, 0, 0, 0];
    sys_rt_sigaction(SIGUSR1, dfl.as_ptr() as u64, 0, 8);

    let mut expect = inp;
    expect.v[NREGS - 1] = EDITED;
    let seen = unsafe { core::ptr::read_volatile(&raw const SIG_SEEN) };
    let ferr = unsafe { core::ptr::read_volatile(&raw const SIG_FRAME_ERR) };
    let hctrl = unsafe { core::ptr::read_volatile(&raw const SIG_HANDLER_CTRL) };
    #[cfg(target_arch = "x86_64")]
    let ctrl_ok = hctrl & 0xffff == 0x1f80; // handler starts with init FP state
    #[cfg(target_arch = "aarch64")]
    let ctrl_ok = {
        let _ = hctrl;
        true
    };
    if r != 0 || seen != 1 {
        print(b"FPU_SIGNAL:FAIL: handler not run, kill=");
        print_num(r);
        println(b"");
    } else if let Some(k) = expect.diff(&out) {
        print(b"FPU_SIGNAL:FAIL: interrupted code reg ");
        print_num(k as i64);
        print(b" corrupted, frame check ");
        print_num(ferr as i64);
        println(b"");
    } else if ferr != 0 {
        print(b"FPU_SIGNAL:FAIL: frame FP record err ");
        print_num(ferr as i64);
        println(b"");
    } else if !ctrl_ok {
        print(b"FPU_SIGNAL:FAIL: handler MXCSR ");
        print_num(hctrl as i64);
        println(b"");
    } else {
        println(b"FPU_SIGNAL:OK");
    }
}
