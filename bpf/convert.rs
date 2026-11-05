//! Classic BPF to eBPF (Linux net/core/filter.c bpf_convert_filter)
//!
//! A checked classic program becomes an eBPF one with Linux's register
//! mapping (A = R0, X = R7, the context in R6, R2 scratch) and Linux's
//! encoding: two passes (the first sizes every instruction, the second
//! knows every target), a scratch register for compare constants of
//! 2^31 or more (eBPF immediates are sign-extended), every conditional
//! jump emitted even when both its targets are the next instruction, an
//! exit with 0 before a division by a zero X, 32-bit ALU throughout, and
//! M[k] in the stack word at -(4k + 4). A and X start at 0 (`mov32`, so
//! the verifier sees them written).
//!
//! What a classic program reads from outside goes through the same
//! `classic::Env` its interpreter uses: seccomp_data words are context
//! loads; packet bytes, the packet length and ancillary values are calls
//! to internal helpers (`helper::*`, not callable from bpf(2)) that
//! return -1 when a load is out of range, which ends the program with 0.
//! The result is checked by the verifier (`SECCOMP`, `SOCKET` kinds).
//!
//! No locks: pure functions over the caller's data.

use super::classic::{self, Insn, ad};
use super::insn::*;
use super::interp;
use super::verifier::{self, Kind};
use crate::util::error::KernelError;
use crate::util::kmem::KVec;

const A: u8 = BPF_REG_0;
const X: u8 = BPF_REG_7;
const TMP: u8 = BPF_REG_2;
const CTX: u8 = BPF_REG_6;
/// Holds A across a call that loads X
const SAVE: u8 = BPF_REG_8;

/// Internal helpers of converted programs
pub mod helper {
    /// Packet byte, halfword, word at R1 (big-endian), or -1
    pub const LD_B: i32 = -1;
    pub const LD_H: i32 = -2;
    pub const LD_W: i32 = -3;
    /// Ancillary value SKF_AD_OFF + R1
    pub const ANC: i32 = -4;
    /// Packet length
    pub const LEN: i32 = -5;
}

/// seccomp: the context is seccomp_data, no helpers
pub const SECCOMP: Kind = Kind {
    ctx_size: 64,
    helpers: &[],
    unreachable_ok: true,
};

/// Socket filters: everything through helpers, no context
pub const SOCKET: Kind = Kind {
    ctx_size: 0,
    helpers: &[
        (helper::LD_B, 1),
        (helper::LD_H, 1),
        (helper::LD_W, 1),
        (helper::ANC, 1),
        (helper::LEN, 0),
    ],
    unreachable_ok: true,
};

/// Longest conversion of one classic instruction
const MAX_EXPAND: usize = 12;

const fn ins(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> BpfInsn {
    BpfInsn::new(code, dst, src, off, imm)
}

const fn mov32(d: u8, imm: i32) -> BpfInsn {
    ins(BPF_ALU | BPF_MOV | BPF_K, d, 0, 0, imm)
}

const fn mov64x(d: u8, s: u8) -> BpfInsn {
    ins(BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0)
}

const fn call(id: i32) -> BpfInsn {
    ins(BPF_JMP | BPF_CALL, 0, 0, 0, id)
}

const EXIT: BpfInsn = ins(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);

/// The stack offset of M[k]
fn mem_off(k: u32) -> i16 {
    -((k as i16) * 4 + 4)
}

/// One classic instruction's expansion
struct Out {
    buf: [BpfInsn; MAX_EXPAND],
    n: usize,
}

impl Out {
    fn push(&mut self, i: BpfInsn) {
        self.buf[self.n] = i;
        self.n += 1;
    }

    /// `R0 = A = helper(id)`; a failed load (-1) ends the program with 0
    fn load_call(&mut self, id: i32) {
        self.push(call(id));
        self.push(ins(BPF_JMP | BPF_JSGE | BPF_K, A, 0, 2, 0));
        self.push(mov32(A, 0));
        self.push(EXIT);
    }
}

/// Where each classic instruction's expansion starts (pass 2), to
/// resolve jump `target` from position `at` of instruction `i`
struct Map<'a> {
    addrs: Option<&'a [usize]>,
}

impl Map<'_> {
    fn off(&self, i: usize, at: usize, target: usize) -> Result<i16, KernelError> {
        let Some(addrs) = self.addrs else {
            return Ok(0);
        };
        let off = addrs[target] as i64 - (addrs[i] + at) as i64 - 1;
        i16::try_from(off).map_err(|_| KernelError::InvalidArgument)
    }
}

fn helper_size(code: u16) -> i32 {
    match code & 0x18 {
        classic::W => helper::LD_W,
        classic::H => helper::LD_H,
        _ => helper::LD_B,
    }
}

/// A conditional jump (Linux's jt/jf cases)
fn jump(f: &Insn, i: usize, map: &Map, o: &mut Out) -> Result<(), KernelError> {
    let op = (f.code & 0xf0) as u8;
    let (src, s_reg, imm) = if f.code & classic::X != 0 {
        (BPF_X, X, 0)
    } else if (f.k as i32) < 0 {
        // Zero-extend the constant through TMP
        o.push(mov32(TMP, f.k as i32));
        (BPF_X, TMP, 0)
    } else {
        (BPF_K, 0, f.k as i32)
    };
    let (jt, jf) = (i + 1 + f.jt as usize, i + 1 + f.jf as usize);
    let cj = |op: u8, off| ins(BPF_JMP | op | src, A, s_reg, off, imm);
    if f.jf == 0 {
        let off = map.off(i, o.n, jt)?;
        o.push(cj(op, off));
        return Ok(());
    }
    let inv = match op {
        BPF_JEQ => Some(BPF_JNE),
        BPF_JGT => Some(BPF_JLE),
        BPF_JGE => Some(BPF_JLT),
        _ => None,
    };
    if let (0, Some(inv)) = (f.jt, inv) {
        let off = map.off(i, o.n, jf)?;
        o.push(cj(inv, off));
        return Ok(());
    }
    let off = map.off(i, o.n, jt)?;
    o.push(cj(op, off));
    let off = map.off(i, o.n, jf)?;
    o.push(ins(BPF_JMP | BPF_JA, 0, 0, off, 0));
    Ok(())
}

/// An LD|ABS at `k`: an ancillary value, or a packet load
fn ld_abs(f: &Insn, o: &mut Out) {
    if classic::anc_known(f.k) {
        let a = f.k.wrapping_sub(classic::SKF_AD_OFF as u32);
        if a == ad::ALU_XOR_X {
            o.push(ins(BPF_ALU | BPF_XOR | BPF_X, A, X, 0, 0));
        } else {
            o.push(mov32(BPF_REG_1, a as i32));
            o.push(call(helper::ANC));
        }
        return;
    }
    o.push(ins(
        BPF_ALU64 | BPF_MOV | BPF_K,
        BPF_REG_1,
        0,
        0,
        f.k as i32,
    ));
    o.load_call(helper_size(f.code));
}

/// Convert classic instruction `i`
fn one(f: &Insn, i: usize, map: &Map, o: &mut Out) -> Result<(), KernelError> {
    use classic::{
        ABS, ALU, DIV, IMM, IND, JA, JMP, LD, LDX, LDX_W_ABS, LEN, MEM, MISC, MOD, MSH, NEG, RET,
        ST, STX, TAX,
    };
    let reg = |c: u16| if c & 0x07 == LD { A } else { X };
    match f.code {
        c if c & 0x07 == ALU => {
            if c == ALU | DIV | classic::X || c == ALU | MOD | classic::X {
                o.push(ins(BPF_ALU | BPF_MOV | BPF_X, X, X, 0, 0));
                o.push(ins(BPF_JMP | BPF_JNE | BPF_K, X, 0, 2, 0));
                o.push(mov32(A, 0));
                o.push(EXIT);
            }
            let code = c as u8;
            o.push(if c == ALU | NEG {
                ins(code, A, 0, 0, 0)
            } else if c & classic::X != 0 {
                ins(code, A, X, 0, 0)
            } else {
                ins(code, A, 0, 0, f.k as i32)
            });
        }
        c if c & 0x07 == LD && c & 0xe0 == ABS => ld_abs(f, o),
        c if c & 0x07 == LD && c & 0xe0 == IND => {
            o.push(mov64x(BPF_REG_1, X));
            o.push(ins(BPF_ALU | BPF_ADD | BPF_K, BPF_REG_1, 0, 0, f.k as i32));
            o.load_call(helper_size(c));
        }
        c if c == LDX | classic::B | MSH => {
            // X = 4 * (pkt[k] & 0xf), A kept (Linux's sequence)
            o.push(mov64x(X, A));
            o.push(ins(
                BPF_ALU64 | BPF_MOV | BPF_K,
                BPF_REG_1,
                0,
                0,
                f.k as i32,
            ));
            o.load_call(helper::LD_B);
            o.push(ins(BPF_ALU | BPF_AND | BPF_K, A, 0, 0, 0xf));
            o.push(ins(BPF_ALU | BPF_LSH | BPF_K, A, 0, 0, 2));
            o.push(mov64x(TMP, X));
            o.push(mov64x(X, A));
            o.push(mov64x(A, TMP));
        }
        c if c == LD | classic::W | LEN => o.push(call(helper::LEN)),
        c if c == LDX | classic::W | LEN => {
            o.push(mov64x(SAVE, A));
            o.push(call(helper::LEN));
            o.push(mov64x(X, A));
            o.push(mov64x(A, SAVE));
        }
        LDX_W_ABS => o.push(ins(BPF_LDX | BPF_MEM | BPF_W, A, CTX, f.k as i16, 0)),
        c if c == LD | IMM || c == LDX | IMM => o.push(mov32(reg(c), f.k as i32)),
        c if c == LD | MEM || c == LDX | MEM => {
            o.push(ins(
                BPF_LDX | BPF_MEM | BPF_W,
                reg(c),
                BPF_REG_10,
                mem_off(f.k),
                0,
            ));
        }
        ST | STX => {
            let s = if f.code == ST { A } else { X };
            o.push(ins(
                BPF_STX | BPF_MEM | BPF_W,
                BPF_REG_10,
                s,
                mem_off(f.k),
                0,
            ));
        }
        c if c == JMP | JA => {
            let off = map.off(i, o.n, i + 1 + f.k as usize)?;
            o.push(ins(BPF_JMP | BPF_JA, 0, 0, off, 0));
        }
        c if c & 0x07 == JMP => jump(f, i, map, o)?,
        c if c == RET | classic::K => {
            o.push(mov32(A, f.k as i32));
            o.push(EXIT);
        }
        c if c == RET | classic::A => o.push(EXIT),
        c if c == MISC | TAX => o.push(mov64x(X, A)),
        c if c & 0x07 == MISC => o.push(mov64x(A, X)),
        _ => return Err(KernelError::InvalidArgument),
    }
    Ok(())
}

/// The prologue: A = X = 0, the context saved in R6
const PROLOGUE: [BpfInsn; 3] = [mov32(A, 0), mov32(X, 0), mov64x(CTX, BPF_REG_1)];

/// One pass: the program's length, and with `addrs` its instructions
fn pass(
    prog: &[Insn],
    addrs: Option<&[usize]>,
    starts: &mut KVec<usize>,
    out: Option<&mut KVec<BpfInsn>>,
) -> Result<usize, KernelError> {
    let map = Map { addrs };
    let mut out = out;
    let mut len = PROLOGUE.len();
    if let Some(o) = out.as_deref_mut() {
        o.try_extend_from_slice(&PROLOGUE)?;
    }
    for (i, f) in prog.iter().enumerate() {
        if addrs.is_none() {
            starts.try_push(len)?;
        }
        let mut o = Out {
            buf: [BpfInsn::default(); MAX_EXPAND],
            n: 0,
        };
        one(f, i, &map, &mut o)?;
        if let Some(out) = out.as_deref_mut() {
            out.try_extend_from_slice(&o.buf[..o.n])?;
        }
        len += o.n;
    }
    Ok(len)
}

/// Convert a checked classic program (Linux bpf_convert_filter), then
/// verify the result as a program of `kind`
pub fn convert(prog: &[Insn], kind: &Kind) -> Result<alloc::vec::Vec<BpfInsn>, KernelError> {
    let mut starts = KVec::try_with_capacity(prog.len())?;
    let len = pass(prog, None, &mut starts, None)?;
    let mut out = KVec::try_with_capacity(len)?;
    pass(
        prog,
        Some(starts.as_slice()),
        &mut KVec::new(),
        Some(&mut out),
    )?;
    // Defense in depth: a converter bug is refused here, not run. A
    // program too complex to verify is still safe to run (the
    // interpreter checks every access, and jumps only go forward)
    match verifier::verify(out.as_slice(), kind, usize::MAX) {
        Ok(_) | Err(KernelError::ArgListTooLong) | Err(KernelError::OutOfMemory) => {}
        Err(_) => return Err(KernelError::InvalidArgument),
    }
    Ok(out.into_vec())
}

/// What a converted program runs against: its context bytes and the
/// classic environment its helpers read
pub struct ClassicEnv<'a, E: classic::Env> {
    pub ctx: &'a [u8],
    pub env: &'a E,
}

impl<E: classic::Env> interp::Env for ClassicEnv<'_, E> {
    fn ctx(&self) -> &[u8] {
        self.ctx
    }

    fn call(&mut self, id: i32, a: [u64; 5]) -> Option<u64> {
        let load = |size| {
            let v = self.env.load(a[0] as i32, size);
            Some(v.map_or(u64::MAX, u64::from))
        };
        match id {
            helper::LD_B => load(1),
            helper::LD_H => load(2),
            helper::LD_W => load(4),
            helper::ANC => Some(u64::from(self.env.anc(a[0] as u32))),
            helper::LEN => Some(u64::from(self.env.pkt_len())),
            _ => None,
        }
    }
}

/// Run a converted program: its 32-bit result, 0 if it faulted
pub fn run<E: classic::Env>(prog: &[BpfInsn], ctx: &[u8], env: &E) -> u32 {
    let mut e = ClassicEnv { ctx, env };
    interp::run(prog, &mut e).map_or(0, |v| v as u32)
}
