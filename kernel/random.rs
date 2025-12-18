//! Kernel random number generator
//!
//! Provides random bytes via the getrandom syscall.
//!
//! ## Implementation
//!
//! Uses a xoshiro256** PRNG seeded from hardware entropy sources:
//! - x86_64: RDRAND instruction if available, otherwise TSC
//! - aarch64: Physical counter (CNTPCT_EL0)
//!
//! ## Linux Compatibility
//!
//! Implements getrandom() flags:
//! - GRND_NONBLOCK: Return -EAGAIN if pool not ready (we're always ready)
//! - GRND_RANDOM: Use /dev/random pool (treated same as urandom)
//! - GRND_INSECURE: Don't block even if CRNG not ready

use spin::Mutex;

/// Flags for getrandom syscall
pub const GRND_NONBLOCK: u32 = 0x0001;
pub const GRND_RANDOM: u32 = 0x0002;
pub const GRND_INSECURE: u32 = 0x0004;

/// Valid flags mask
const GRND_VALID_FLAGS: u32 = GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE;

/// Global CRNG state (protected by mutex like Linux)
static CRNG: Mutex<CrngState> = Mutex::new(CrngState::new());

/// CRNG state using xoshiro256** algorithm
struct CrngState {
    /// Whether the CRNG has been initialized
    initialized: bool,
    /// xoshiro256** state (4 x 64-bit)
    state: [u64; 4],
}

impl CrngState {
    /// Create new uninitialized state
    const fn new() -> Self {
        Self {
            initialized: false,
            state: [0; 4],
        }
    }

    /// Initialize from available entropy sources
    fn init(&mut self) {
        #[cfg(target_arch = "x86_64")]
        {
            // Try RDRAND first, fall back to TSC
            self.state[0] = rdrand_or_tsc();
            self.state[1] = rdrand_or_tsc() ^ 0x5555_5555_5555_5555;
            self.state[2] = rdrand_or_tsc() ^ 0xAAAA_AAAA_AAAA_AAAA;
            self.state[3] = rdrand_or_tsc();
        }

        #[cfg(target_arch = "aarch64")]
        {
            // Use physical counter
            self.state[0] = read_cntpct();
            self.state[1] = read_cntpct() ^ 0x5555_5555_5555_5555;
            self.state[2] = read_cntpct() ^ 0xAAAA_AAAA_AAAA_AAAA;
            self.state[3] = read_cntpct();
        }

        // Mix the initial state to improve distribution
        for _ in 0..16 {
            self.next_u64();
        }

        self.initialized = true;
    }

    /// Generate next 64-bit random value using xoshiro256**
    fn next_u64(&mut self) -> u64 {
        let result = self.state[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);

        let t = self.state[1] << 17;

        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];

        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);

        result
    }

    /// Fill buffer with random bytes
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut offset = 0;
        while offset < buf.len() {
            let val = self.next_u64();
            let bytes = val.to_le_bytes();
            let remaining = buf.len() - offset;
            let to_copy = remaining.min(8);
            buf[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);
            offset += to_copy;
        }
    }
}

/// Read cycle counter or RDRAND on x86_64
#[cfg(target_arch = "x86_64")]
fn rdrand_or_tsc() -> u64 {
    // Try RDRAND first (if supported)
    if let Some(val) = try_rdrand() {
        return val;
    }
    // Fall back to TSC
    crate::arch::x86_64::tsc::read_tsc()
}

/// Try to read from RDRAND instruction
#[cfg(target_arch = "x86_64")]
fn try_rdrand() -> Option<u64> {
    // Check if RDRAND is supported via CPUID
    // Note: rbx is reserved by LLVM, so we must preserve it around cpuid
    let has_rdrand = {
        let ecx: u32;
        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov eax, 1",
                "cpuid",
                "pop rbx",
                out("ecx") ecx,
                out("eax") _,
                out("edx") _,
                options(nomem),
            );
        }
        (ecx & (1 << 30)) != 0
    };

    if !has_rdrand {
        return None;
    }

    // Try RDRAND up to 10 times
    for _ in 0..10 {
        let val: u64;
        let success: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {0}",
                "setc {1}",
                out(reg) val,
                out(reg_byte) success,
            );
        }
        if success != 0 {
            return Some(val);
        }
    }

    None
}

/// Read physical counter on aarch64
#[cfg(target_arch = "aarch64")]
fn read_cntpct() -> u64 {
    let count: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) count);
    }
    count
}

/// Initialize the CRNG
///
/// Called early in kernel boot after timers are available.
pub fn init() {
    let mut crng = CRNG.lock();
    if !crng.initialized {
        crng.init();
    }
}

/// Fill buffer with random bytes
///
/// # Arguments
/// * `buf` - Buffer to fill with random bytes
/// * `flags` - getrandom flags (GRND_NONBLOCK, GRND_RANDOM, GRND_INSECURE)
///
/// # Returns
/// * `Ok(n)` - Number of bytes written
/// * `Err(errno)` - Negative errno on error
pub fn get_random_bytes(buf: &mut [u8], flags: u32) -> Result<usize, i32> {
    // Validate flags
    if flags & !GRND_VALID_FLAGS != 0 {
        return Err(-22); // EINVAL
    }

    if buf.is_empty() {
        return Ok(0);
    }

    let mut crng = CRNG.lock();

    // Initialize if needed
    if !crng.initialized {
        crng.init();
    }

    crng.fill_bytes(buf);
    Ok(buf.len())
}
