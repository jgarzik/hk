//! Classic BPF (struct sock_filter): Linux's checker (net/core/filter.c
//! bpf_check_classic, check_load_and_stores) and the classic interpreter
//!
//! Socket filters and seccomp both start here. A program is checked once
//! when it is installed: known opcodes only, forward jumps inside the
//! program, scratch-memory indices below 16 and every slot stored before
//! it is loaded on all paths, no division by a zero constant, shifts
//! below 32, a RET last. Running it is then bounded by its length (jumps
//! only go forward).
//!
//! What a program reads besides A, X and M[] comes from an `Env`: the
//! packet (big-endian loads, the length, ancillary values) for sockets,
//! the seccomp_data words for seccomp. An out-of-range load or a
//! division by a zero X ends the program with 0.
//!
//! No locks: programs are immutable and runs keep state on the stack.

use crate::util::error::KernelError;

/// Most instructions in a program (Linux BPF_MAXINSNS)
pub const BPF_MAXINSNS: usize = 4096;
/// Scratch memory words (BPF_MEMWORDS)
pub const BPF_MEMWORDS: u32 = 16;

// Instruction classes and fields (uapi linux/bpf_common.h, filter.h)
pub const LD: u16 = 0x00;
pub const LDX: u16 = 0x01;
pub const ST: u16 = 0x02;
pub const STX: u16 = 0x03;
pub const ALU: u16 = 0x04;
pub const JMP: u16 = 0x05;
pub const RET: u16 = 0x06;
pub const MISC: u16 = 0x07;

pub const W: u16 = 0x00;
pub const H: u16 = 0x08;
pub const B: u16 = 0x10;

pub const IMM: u16 = 0x00;
pub const ABS: u16 = 0x20;
pub const IND: u16 = 0x40;
pub const MEM: u16 = 0x60;
pub const LEN: u16 = 0x80;
pub const MSH: u16 = 0xa0;

pub const ADD: u16 = 0x00;
pub const SUB: u16 = 0x10;
pub const MUL: u16 = 0x20;
pub const DIV: u16 = 0x30;
pub const OR: u16 = 0x40;
pub const AND: u16 = 0x50;
pub const LSH: u16 = 0x60;
pub const RSH: u16 = 0x70;
pub const NEG: u16 = 0x80;
pub const MOD: u16 = 0x90;
pub const XOR: u16 = 0xa0;

pub const JA: u16 = 0x00;
pub const JEQ: u16 = 0x10;
pub const JGT: u16 = 0x20;
pub const JGE: u16 = 0x30;
pub const JSET: u16 = 0x40;

pub const K: u16 = 0x00;
pub const X: u16 = 0x08;
pub const A: u16 = 0x10;

pub const TAX: u16 = 0x00;
pub const TXA: u16 = 0x80;

/// seccomp's internal "A = native word k of seccomp_data" (Linux
/// seccomp_check_filter rewrites LD|W|ABS to it; never valid from user)
pub const LDX_W_ABS: u16 = LDX | W | ABS;

/// Negative load offsets (uapi linux/filter.h)
pub const SKF_AD_OFF: i32 = -0x1000;
pub const SKF_NET_OFF: i32 = -0x100000;
pub const SKF_LL_OFF: i32 = -0x200000;

/// Ancillary data offsets (SKF_AD_*)
pub mod ad {
    pub const PROTOCOL: u32 = 0;
    pub const PKTTYPE: u32 = 4;
    pub const IFINDEX: u32 = 8;
    pub const NLATTR: u32 = 12;
    pub const NLATTR_NEST: u32 = 16;
    pub const MARK: u32 = 20;
    pub const QUEUE: u32 = 24;
    pub const HATYPE: u32 = 28;
    pub const RXHASH: u32 = 32;
    pub const CPU: u32 = 36;
    pub const ALU_XOR_X: u32 = 40;
    pub const VLAN_TAG: u32 = 44;
    pub const VLAN_TAG_PRESENT: u32 = 48;
    pub const PAY_OFFSET: u32 = 52;
    pub const RANDOM: u32 = 56;
    pub const VLAN_TPID: u32 = 60;
}

/// One classic instruction (struct sock_filter)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl Insn {
    /// Decode the 8-byte user representation
    pub fn from_bytes(b: &[u8; 8]) -> Self {
        Self {
            code: u16::from_ne_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// What a running program reads besides A, X and M[]
pub trait Env {
    /// Packet length (LD/LDX LEN)
    fn pkt_len(&self) -> u32 {
        0
    }
    /// `size` bytes at packet offset `off`, big-endian, if in range
    fn load(&self, off: i32, size: usize) -> Option<u32> {
        let _ = (off, size);
        None
    }
    /// Ancillary value SKF_AD_OFF + `ad` (not ALU_XOR_X)
    fn anc(&self, ad: u32) -> u32 {
        let _ = ad;
        0
    }
    /// Native-endian context word at offset `k` (LDX_W_ABS)
    fn word(&self, k: u32) -> Option<u32> {
        let _ = k;
        None
    }
}

// ============================================================================
// Checking (Linux bpf_check_basics_ok, bpf_check_classic)
// ============================================================================

fn code_allowed(code: u16) -> bool {
    let alu_op = code & 0xf0;
    match code & 0x07 {
        ALU => {
            matches!(
                alu_op,
                ADD | SUB | MUL | DIV | MOD | AND | OR | XOR | LSH | RSH
            ) && code & !0xf8 == ALU
                || code == ALU | NEG
        }
        LD => matches!(
            code,
            0x20 | 0x28 | 0x30 // W/H/B ABS
                | 0x80 // W LEN
                | 0x40 | 0x48 | 0x50 // W/H/B IND
                | 0x00 // IMM
                | 0x60 // MEM
        ),
        LDX => matches!(code, 0x81 | 0xb1 | 0x01 | 0x61),
        ST | STX => code == ST || code == STX,
        MISC => code == MISC | TAX || code == MISC | TXA,
        RET => code == RET | K || code == RET | A,
        JMP => {
            code == JMP | JA
                || (matches!(code & 0xf0, JEQ | JGT | JGE | JSET) && code & !0xf8 == JMP)
        }
        _ => false,
    }
}

/// A conditional jump (jt/jf), not JA
pub fn is_cond_jump(code: u16) -> bool {
    code & 0x07 == JMP && code != JMP | JA
}

/// Recognized ancillary load offset (Linux bpf_anc_helper)
pub fn anc_known(k: u32) -> bool {
    let off = k.wrapping_sub(SKF_AD_OFF as u32);
    k >= SKF_AD_OFF as u32 && off < 64 && off.is_multiple_of(4)
}

fn check_insn(pc: usize, f: &Insn, flen: usize) -> Result<(), ()> {
    if !code_allowed(f.code) {
        return Err(());
    }
    let (jt, jf) = (f.jt as usize, f.jf as usize);
    match f.code {
        c if c == ALU | DIV | K || c == ALU | MOD | K => {
            if f.k == 0 {
                return Err(());
            }
        }
        c if c == ALU | LSH | K || c == ALU | RSH | K => {
            if f.k >= 32 {
                return Err(());
            }
        }
        c if c == LD | MEM || c == LDX | MEM || c == ST || c == STX => {
            if f.k >= BPF_MEMWORDS {
                return Err(());
            }
        }
        c if c == JMP | JA => {
            if f.k as usize >= flen - pc - 1 {
                return Err(());
            }
        }
        c if is_cond_jump(c) => {
            if pc + jt + 1 >= flen || pc + jf + 1 >= flen {
                return Err(());
            }
        }
        c if (c == LD | W | ABS || c == LD | H | ABS || c == LD | B | ABS)
            && f.k >= SKF_AD_OFF as u32
            && !anc_known(f.k) =>
        {
            return Err(());
        }
        _ => {}
    }
    Ok(())
}

/// Every scratch slot is stored before it is loaded, on every path
fn check_mem(insns: &[Insn]) -> Result<(), KernelError> {
    let mut masks = crate::util::kmem::try_vec(insns.len(), u16::MAX)?;
    let mut valid: u16 = 0;
    for (pc, f) in insns.iter().enumerate() {
        valid &= masks[pc];
        match f.code {
            c if c == ST || c == STX => valid |= 1 << f.k,
            c if c == LD | MEM || c == LDX | MEM => {
                if valid & (1 << f.k) == 0 {
                    return Err(KernelError::InvalidArgument);
                }
            }
            c if c == JMP | JA => {
                masks[pc + 1 + f.k as usize] &= valid;
                valid = u16::MAX;
            }
            c if is_cond_jump(c) => {
                masks[pc + 1 + f.jt as usize] &= valid;
                masks[pc + 1 + f.jf as usize] &= valid;
                valid = u16::MAX;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Check a user program (Linux bpf_check_basics_ok + bpf_check_classic)
pub fn check(insns: &[Insn]) -> Result<(), KernelError> {
    let flen = insns.len();
    if flen == 0 || flen > BPF_MAXINSNS {
        return Err(KernelError::InvalidArgument);
    }
    for (pc, f) in insns.iter().enumerate() {
        check_insn(pc, f, flen).map_err(|()| KernelError::InvalidArgument)?;
    }
    let last = insns[flen - 1].code;
    if last != RET | K && last != RET | A {
        return Err(KernelError::InvalidArgument);
    }
    check_mem(insns)
}

// ============================================================================
// Interpreter
// ============================================================================

fn size_of(code: u16) -> usize {
    match code & 0x18 {
        W => 4,
        H => 2,
        _ => 1,
    }
}

fn alu(op: u16, a: u32, v: u32) -> Option<u32> {
    Some(match op {
        ADD => a.wrapping_add(v),
        SUB => a.wrapping_sub(v),
        MUL => a.wrapping_mul(v),
        DIV => a.checked_div(v)?,
        MOD => a.checked_rem(v)?,
        AND => a & v,
        OR => a | v,
        XOR => a ^ v,
        LSH => a.wrapping_shl(v),
        RSH => a.wrapping_shr(v),
        _ => a.wrapping_neg(),
    })
}

fn jump(op: u16, a: u32, v: u32) -> bool {
    match op {
        JEQ => a == v,
        JGT => a > v,
        JGE => a >= v,
        _ => a & v != 0,
    }
}

/// LD|ABS at `k`: an ancillary value or a packet load
fn ld_abs<E: Env>(env: &E, code: u16, k: u32, a: u32, x: u32) -> Option<u32> {
    if anc_known(k) {
        let ad = k.wrapping_sub(SKF_AD_OFF as u32);
        return Some(if ad == ad::ALU_XOR_X {
            a ^ x
        } else {
            env.anc(ad)
        });
    }
    env.load(k as i32, size_of(code))
}

/// What one instruction does to the program counter
enum Step {
    Next,
    Skip(usize),
    Ret(u32),
}

/// A, X and the scratch memory
#[derive(Default)]
struct Machine {
    a: u32,
    x: u32,
    mem: [u32; BPF_MEMWORDS as usize],
}

impl Machine {
    /// Execute `f`; None for a failed load or a division by zero
    fn exec<E: Env>(&mut self, f: &Insn, env: &E) -> Option<Step> {
        let src = if f.code & X != 0 { self.x } else { f.k };
        match f.code & 0x07 {
            LD => {
                self.a = match f.code & 0xe0 {
                    IMM => f.k,
                    MEM => self.mem[f.k as usize],
                    LEN => env.pkt_len(),
                    ABS => ld_abs(env, f.code, f.k, self.a, self.x)?,
                    IND => env.load(self.x.wrapping_add(f.k) as i32, size_of(f.code))?,
                    _ => return None,
                }
            }
            LDX if f.code == LDX_W_ABS => self.a = env.word(f.k)?,
            LDX => {
                self.x = match f.code & 0xe0 {
                    IMM => f.k,
                    MEM => self.mem[f.k as usize],
                    LEN => env.pkt_len(),
                    MSH => (env.load(f.k as i32, 1)? & 0xf) << 2,
                    _ => return None,
                }
            }
            ST => self.mem[f.k as usize] = self.a,
            STX => self.mem[f.k as usize] = self.x,
            ALU => self.a = alu(f.code & 0xf0, self.a, src)?,
            JMP if f.code == JMP | JA => return Some(Step::Skip(f.k as usize)),
            JMP => {
                let taken = jump(f.code & 0xf0, self.a, src);
                return Some(Step::Skip(if taken { f.jt } else { f.jf } as usize));
            }
            RET if f.code & A != 0 => return Some(Step::Ret(self.a)),
            RET => return Some(Step::Ret(f.k)),
            _ if f.code == MISC | TAX => self.x = self.a,
            _ => self.a = self.x,
        }
        Some(Step::Next)
    }
}

/// Run a checked program: its return value, 0 on a failed load
pub fn run<E: Env>(insns: &[Insn], env: &E) -> u32 {
    let mut m = Machine::default();
    let mut pc = 0;
    while let Some(f) = insns.get(pc) {
        pc += 1;
        match m.exec(f, env) {
            Some(Step::Next) => {}
            Some(Step::Skip(n)) => pc += n,
            Some(Step::Ret(v)) => return v,
            None => return 0,
        }
    }
    0
}
