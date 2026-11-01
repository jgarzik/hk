//! Kernel random number generator (Linux drivers/char/random.c)
//!
//! A ChaCha20 CRNG with fast key erasure:
//! - The base CRNG holds a 256-bit key, seeded at boot and reseeded every
//!   [`RESEED_NS`] from the CPU's hardware RNG (RDSEED/RDRAND, arm64
//!   RNDRRS) when it has one, always mixed with cycle counters and time.
//!   Each reseed bumps its generation.
//! - Each CPU keeps its own key, taken from the base when the generation
//!   changes. A request turns that key into one ChaCha20 block: the first
//!   half replaces the CPU key (so earlier output cannot be recomputed),
//!   the second half keys the ChaCha20 stream the caller reads.
//!
//! Unlike Linux, there is no input pool of interrupt timings and no
//! entropy accounting: the CRNG counts as ready from its boot seed.
//!
//! ## Locking
//! Per-CPU state under `CPU_CRNG` (IrqSpinlock, IRQ-safe: network code
//! asks for numbers from softirq context), taken before `BASE`
//! (IrqSpinlock) when the CPU key is refreshed.
//!
//! ## getrandom flags
//! - GRND_NONBLOCK: Return -EAGAIN if pool not ready (always ready)
//! - GRND_RANDOM: The /dev/random pool (the same CRNG, as on Linux 5.6+)
//! - GRND_INSECURE: Don't block even if the CRNG is not ready

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::cpu::PerCpu;

/// Flags for getrandom syscall
pub const GRND_NONBLOCK: u32 = 0x0001;
pub const GRND_RANDOM: u32 = 0x0002;
pub const GRND_INSECURE: u32 = 0x0004;

/// Valid flags mask
const GRND_VALID_FLAGS: u32 = GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE;

/// Base reseed interval (Linux CRNG_RESEED_INTERVAL: 60 s)
const RESEED_NS: u64 = 60_000_000_000;

/// The ChaCha20 constant "expand 32-byte k"
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// One ChaCha20 block (RFC 7539 2.3) for `key`, block `counter` and
/// `nonce`
pub fn chacha20_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; 16] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&SIGMA);
    init[4..12].copy_from_slice(key);
    init[12] = counter;
    init[13..].copy_from_slice(nonce);
    let mut x = init;
    for _ in 0..10 {
        quarter(&mut x, 0, 4, 8, 12);
        quarter(&mut x, 1, 5, 9, 13);
        quarter(&mut x, 2, 6, 10, 14);
        quarter(&mut x, 3, 7, 11, 15);
        quarter(&mut x, 0, 5, 10, 15);
        quarter(&mut x, 1, 6, 11, 12);
        quarter(&mut x, 2, 7, 8, 13);
        quarter(&mut x, 3, 4, 9, 14);
    }
    for (o, i) in x.iter_mut().zip(init) {
        *o = o.wrapping_add(i);
    }
    x
}

fn quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// Overwrite a key so it does not linger in memory
fn wipe(k: &mut [u32]) {
    for w in k.iter_mut() {
        // SAFETY: a valid &mut u32
        unsafe { core::ptr::write_volatile(w, 0) };
    }
}

/// Fast key erasure: the block from `key` replaces `key` with its first
/// half and returns the second
fn erase_and_split(key: &mut [u32; 8]) -> [u32; 8] {
    let mut b = chacha20_block(key, 0, &[0; 3]);
    key.copy_from_slice(&b[..8]);
    let mut out = [0u32; 8];
    out.copy_from_slice(&b[8..]);
    wipe(&mut b);
    out
}

/// The base CRNG key
struct Base {
    key: [u32; 8],
}

static BASE: IrqSpinlock<Base> = IrqSpinlock::new(Base { key: [0; 8] });

/// When the base was last seeded (monotonic ns; 0 never): read without
/// the lock to decide whether to reseed, rechecked under it
static BIRTH_NS: AtomicU64 = AtomicU64::new(0);

/// The base key's generation: bumped by every reseed (0: not seeded)
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// One CPU's CRNG
struct CpuCrng {
    key: [u32; 8],
    generation: u64,
}

static CPU_CRNG: PerCpu<IrqSpinlock<CpuCrng>> = crate::percpu![IrqSpinlock::new(CpuCrng {
    key: [0; 8],
    generation: 0,
})];

/// Mix fresh seed material into the base key (Linux crng_reseed with
/// extract_entropy): the new key is a ChaCha20 block of the old key
/// XORed with hardware RNG output, cycle counters and the time
fn reseed(base: &mut Base, now: u64) {
    let mut seed = base.key;
    for (i, w) in seed.iter_mut().enumerate() {
        let hw = crate::arch::arch_random_seed().unwrap_or(0);
        let cycles = crate::arch::random_get_entropy();
        let mix = hw ^ cycles.rotate_left(i as u32 * 8) ^ now.rotate_left(i as u32 * 5 + 1);
        *w ^= (mix as u32) ^ ((mix >> 32) as u32);
    }
    let gen_ = GENERATION.load(Ordering::Relaxed).wrapping_add(1).max(1);
    let nonce = [gen_ as u32, (gen_ >> 32) as u32, 0x6873_6b20];
    let mut b = chacha20_block(&seed, 0, &nonce);
    base.key.copy_from_slice(&b[..8]);
    wipe(&mut b);
    wipe(&mut seed);
    BIRTH_NS.store(now.max(1), Ordering::Relaxed);
    GENERATION.store(gen_, Ordering::Release);
}

/// A fresh key for one request (Linux crng_make_state): this CPU's key,
/// refreshed from the base when the base was reseeded, through fast key
/// erasure
fn make_key() -> [u32; 8] {
    let now = crate::time::monotonic_ns();
    let mut cpu = CPU_CRNG.this().lock();
    let base_gen = GENERATION.load(Ordering::Acquire);
    if due(now) || cpu.generation != base_gen {
        let mut base = BASE.lock();
        if due(now) {
            reseed(&mut base, now);
        }
        cpu.key = erase_and_split(&mut base.key);
        cpu.generation = GENERATION.load(Ordering::Relaxed);
    }
    erase_and_split(&mut cpu.key)
}

/// Whether the base needs (re)seeding: never seeded, or seeded
/// RESEED_NS ago
fn due(now: u64) -> bool {
    let birth = BIRTH_NS.load(Ordering::Relaxed);
    birth == 0 || now.saturating_sub(birth) >= RESEED_NS
}

/// Fill `buf` from the CRNG: a ChaCha20 stream under a key used once
fn fill(buf: &mut [u8]) {
    let mut key = make_key();
    for (i, chunk) in buf.chunks_mut(64).enumerate() {
        let mut b = chacha20_block(&key, i as u32 + 1, &[0; 3]);
        for (dst, w) in chunk.chunks_mut(4).zip(b.iter()) {
            dst.copy_from_slice(&w.to_le_bytes()[..dst.len()]);
        }
        wipe(&mut b);
    }
    wipe(&mut key);
}

/// Stream `len` random bytes to `out` a block at a time under one
/// fresh key (Linux get_random_bytes_user): every page, give way to
/// other tasks and stop if a signal is pending. Returns the bytes
/// delivered; `out` returning false (a fault) stops early.
pub fn stream(len: usize, mut out: impl FnMut(usize, &[u8]) -> bool) -> usize {
    let mut key = make_key();
    let mut done = 0;
    let mut ctr = 1u32;
    while done < len {
        if done > 0 && done % 4096 == 0 {
            if crate::waitqueue::signal_pending() {
                break;
            }
            crate::task::percpu::cond_resched();
        }
        let mut b = chacha20_block(&key, ctr, &[0; 3]);
        ctr = ctr.wrapping_add(1);
        let mut bytes = [0u8; 64];
        for (dst, w) in bytes.chunks_mut(4).zip(b.iter()) {
            dst.copy_from_slice(&w.to_le_bytes());
        }
        wipe(&mut b);
        let n = (len - done).min(64);
        let ok = out(done, &bytes[..n]);
        bytes.fill(0);
        if !ok {
            break;
        }
        done += n;
    }
    wipe(&mut key);
    done
}

/// Mix caller-supplied bytes into the base key (Linux
/// add_device_randomness / write to /dev/random): never credited as
/// entropy, but they change every later key
pub fn add_device_randomness(data: &[u8]) {
    // One block per lock hold: a big write does not keep IRQs off long
    for chunk in data.chunks(32) {
        let mut base = BASE.lock();
        let mut key = base.key;
        for (i, b) in chunk.iter().enumerate() {
            key[i / 4] ^= (*b as u32) << (8 * (i % 4));
        }
        let mut blk = chacha20_block(&key, 0, &[0x6d69_7800, 0, 0]);
        base.key.copy_from_slice(&blk[..8]);
        wipe(&mut blk);
        wipe(&mut key);
    }
    // CPUs take a fresh key from the new base
    let g = GENERATION.load(Ordering::Relaxed).wrapping_add(1).max(1);
    GENERATION.store(g, Ordering::Release);
}

/// Seed the base CRNG (boot, after the clocks)
pub fn init() {
    let now = crate::time::monotonic_ns();
    let mut base = BASE.lock();
    if BIRTH_NS.load(Ordering::Relaxed) == 0 {
        reseed(&mut base, now);
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
    if flags & !GRND_VALID_FLAGS != 0 {
        return Err(-22); // EINVAL
    }
    // Linux: GRND_INSECURE with GRND_RANDOM is EINVAL
    if flags & (GRND_INSECURE | GRND_RANDOM) == GRND_INSECURE | GRND_RANDOM {
        return Err(-22);
    }
    if !buf.is_empty() {
        fill(buf);
    }
    Ok(buf.len())
}

/// Get a random 32-bit integer (e.g., for TCP initial sequence numbers)
pub fn get_random_u32() -> u32 {
    let mut buf = [0u8; 4];
    fill(&mut buf);
    u32::from_ne_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7539 2.3.2: key 00..1f, counter 1, nonce 000000090000004a00000000
    #[test]
    fn rfc7539_block() {
        let key: [u32; 8] = core::array::from_fn(|i| {
            u32::from_le_bytes([
                4 * i as u8,
                4 * i as u8 + 1,
                4 * i as u8 + 2,
                4 * i as u8 + 3,
            ])
        });
        let nonce = [0x0900_0000, 0x4a00_0000, 0];
        let out = chacha20_block(&key, 1, &nonce);
        let want: [u32; 16] = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
            0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
            0xe883d0cb, 0x4e3c50a2,
        ];
        assert_eq!(out, want);
    }

    /// Fast key erasure changes the key and never hands it out
    #[test]
    fn erasure() {
        let mut key = [7u32; 8];
        let first = erase_and_split(&mut key);
        assert_ne!(key, [7u32; 8]);
        assert_ne!(first, key);
        let second = erase_and_split(&mut key);
        assert_ne!(first, second);
    }
}
