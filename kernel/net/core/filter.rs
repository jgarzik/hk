//! Classic BPF socket filters (Linux net/core/filter.c: SO_ATTACH_FILTER,
//! bpf_check_classic, the classic interpreter semantics)
//!
//! A filter is validated once when attached, exactly like Linux: known
//! opcodes only, forward jumps inside the program, scratch-memory
//! indices below 16 and every slot stored before it is loaded on all
//! paths, no division by a zero constant, a RET last. Running it is
//! then bounded by its length (jumps only go forward).
//!
//! The program sees the packet as the socket will receive it (from the
//! link-layer header for SOCK_RAW packet sockets, from the network
//! header for SOCK_DGRAM), plus the SKF_NET_OFF / SKF_LL_OFF negative
//! offsets and the SKF_AD_* ancillary loads. An out-of-bounds load or a
//! division by zero ends the program with 0 (drop). The result is the
//! number of bytes to keep (0 = drop).
//!
//! No locks: a `Filter` is immutable and shared by `Arc`.

use alloc::vec::Vec;

use crate::error::KernelError;

/// Most instructions in a program (Linux BPF_MAXINSNS)
pub const BPF_MAXINSNS: usize = 4096;
/// Scratch memory words (BPF_MEMWORDS)
const BPF_MEMWORDS: u32 = 16;

// Instruction classes and fields (uapi linux/bpf_common.h, filter.h)
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ST: u16 = 0x02;
const STX: u16 = 0x03;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const MISC: u16 = 0x07;

const W: u16 = 0x00;
const H: u16 = 0x08;
const B: u16 = 0x10;

const IMM: u16 = 0x00;
const ABS: u16 = 0x20;
const IND: u16 = 0x40;
const MEM: u16 = 0x60;
const LEN: u16 = 0x80;
const MSH: u16 = 0xa0;

const ADD: u16 = 0x00;
const SUB: u16 = 0x10;
const MUL: u16 = 0x20;
const DIV: u16 = 0x30;
const OR: u16 = 0x40;
const AND: u16 = 0x50;
const LSH: u16 = 0x60;
const RSH: u16 = 0x70;
const NEG: u16 = 0x80;
const MOD: u16 = 0x90;
const XOR: u16 = 0xa0;

const JA: u16 = 0x00;
const JEQ: u16 = 0x10;
const JGT: u16 = 0x20;
const JGE: u16 = 0x30;
const JSET: u16 = 0x40;

const K: u16 = 0x00;
const X: u16 = 0x08;
const A: u16 = 0x10;

const TAX: u16 = 0x00;
const TXA: u16 = 0x80;

/// Negative load offsets (uapi linux/filter.h)
const SKF_AD_OFF: i32 = -0x1000;
const SKF_NET_OFF: i32 = -0x100000;
const SKF_LL_OFF: i32 = -0x200000;

/// Ancillary data offsets (SKF_AD_*)
mod ad {
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

/// What a program may inspect besides the packet bytes
#[derive(Clone, Copy, Debug, Default)]
pub struct Ctx<'a> {
    /// The packet as the socket sees it
    pub data: &'a [u8],
    /// The whole frame from its link-layer header (SKF_LL_OFF loads)
    pub frame: &'a [u8],
    /// Offset of the network header in `frame` (SKF_NET_OFF loads)
    pub net_off: usize,
    /// EtherType (host order), PACKET_* type, device index and type
    pub protocol: u16,
    pub pkt_type: u8,
    pub ifindex: u32,
    pub hatype: u16,
    pub mark: u32,
}

/// A validated classic BPF program
#[derive(Debug)]
pub struct Filter {
    insns: Vec<Insn>,
}

impl Filter {
    /// Validate a program (Linux bpf_check_basics_ok + bpf_check_classic)
    pub fn new(insns: Vec<Insn>) -> Result<Self, KernelError> {
        if insns.is_empty() || insns.len() > BPF_MAXINSNS {
            return Err(KernelError::InvalidArgument);
        }
        check(&insns).map_err(|()| KernelError::InvalidArgument)?;
        Ok(Self { insns })
    }

    pub fn len(&self) -> usize {
        self.insns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// Run the program: bytes of the packet to keep (0 = drop)
    pub fn run(&self, c: &Ctx) -> u32 {
        run(&self.insns, c)
    }
}

// ============================================================================
// Validation (Linux bpf_check_classic, check_load_and_stores)
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

fn is_cond_jump(code: u16) -> bool {
    code & 0x07 == JMP && code != JMP | JA
}

/// Recognized ancillary load (Linux bpf_anc_helper)
fn anc_known(k: u32) -> bool {
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
fn check_mem(insns: &[Insn]) -> Result<(), ()> {
    let mut masks = alloc::vec![u16::MAX; insns.len()];
    let mut valid: u16 = 0;
    for (pc, f) in insns.iter().enumerate() {
        valid &= masks[pc];
        match f.code {
            c if c == ST || c == STX => valid |= 1 << f.k,
            c if c == LD | MEM || c == LDX | MEM => {
                if valid & (1 << f.k) == 0 {
                    return Err(());
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

fn check(insns: &[Insn]) -> Result<(), ()> {
    let flen = insns.len();
    for (pc, f) in insns.iter().enumerate() {
        check_insn(pc, f, flen)?;
    }
    let last = insns[flen - 1].code;
    if last != RET | K && last != RET | A {
        return Err(());
    }
    check_mem(insns)
}

// ============================================================================
// Interpreter
// ============================================================================

/// `size` bytes at packet offset `off` (negative: SKF_NET_OFF/SKF_LL_OFF)
fn load(c: &Ctx, off: i32, size: usize) -> Option<u32> {
    let bytes = if off >= 0 {
        c.data
            .get(off as usize..(off as usize).checked_add(size)?)?
    } else if off >= SKF_NET_OFF {
        // SKF_AD_OFF range never reaches here for IND loads in Linux
        // either: those offsets are simply out of bounds
        if off >= SKF_AD_OFF {
            return None;
        }
        let o = c.net_off.checked_add((off - SKF_NET_OFF) as usize)?;
        c.frame.get(o..o.checked_add(size)?)?
    } else if off >= SKF_LL_OFF {
        let o = (off - SKF_LL_OFF) as usize;
        c.frame.get(o..o.checked_add(size)?)?
    } else {
        return None;
    };
    Some(bytes.iter().fold(0u32, |v, &b| (v << 8) | b as u32))
}

/// Ancillary value of LD ABS at `k` (`a`, `x` for ALU_XOR_X)
fn anc(c: &Ctx, k: u32, a: u32, x: u32) -> u32 {
    match k.wrapping_sub(SKF_AD_OFF as u32) {
        ad::PROTOCOL => c.protocol as u32,
        ad::PKTTYPE => c.pkt_type as u32,
        ad::IFINDEX => c.ifindex,
        ad::MARK => c.mark,
        ad::HATYPE => c.hatype as u32,
        ad::CPU => crate::task::percpu::current_cpu(),
        ad::ALU_XOR_X => a ^ x,
        ad::RANDOM => crate::random::get_random_u32(),
        // No netlink attributes, queues, hashes or VLAN tags here
        ad::NLATTR | ad::NLATTR_NEST | ad::QUEUE | ad::RXHASH | ad::PAY_OFFSET => 0,
        ad::VLAN_TAG | ad::VLAN_TAG_PRESENT | ad::VLAN_TPID => 0,
        _ => 0,
    }
}

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

/// Run a validated program
fn run(insns: &[Insn], c: &Ctx) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut mem = [0u32; BPF_MEMWORDS as usize];
    let mut pc = 0;
    while let Some(f) = insns.get(pc) {
        pc += 1;
        let src = if f.code & X != 0 { x } else { f.k };
        match f.code & 0x07 {
            LD => {
                a = match f.code & 0xe0 {
                    IMM => f.k,
                    MEM => mem[f.k as usize],
                    LEN => c.data.len() as u32,
                    ABS if anc_known(f.k) => anc(c, f.k, a, x),
                    ABS => match load(c, f.k as i32, size_of(f.code)) {
                        Some(v) => v,
                        None => return 0,
                    },
                    IND => match load(c, x.wrapping_add(f.k) as i32, size_of(f.code)) {
                        Some(v) => v,
                        None => return 0,
                    },
                    _ => return 0,
                }
            }
            LDX => {
                x = match f.code & 0xe0 {
                    IMM => f.k,
                    MEM => mem[f.k as usize],
                    LEN => c.data.len() as u32,
                    MSH => match load(c, f.k as i32, 1) {
                        Some(v) => (v & 0xf) << 2,
                        None => return 0,
                    },
                    _ => return 0,
                }
            }
            ST => mem[f.k as usize] = a,
            STX => mem[f.k as usize] = x,
            ALU => match alu(f.code & 0xf0, a, src) {
                Some(v) => a = v,
                None => return 0,
            },
            JMP if f.code == JMP | JA => pc += f.k as usize,
            JMP => {
                pc += if jump(f.code & 0xf0, a, src) {
                    f.jt as usize
                } else {
                    f.jf as usize
                };
            }
            RET => return if f.code & A != 0 { a } else { f.k },
            _ => {
                if f.code == MISC | TAX {
                    x = a;
                } else {
                    a = x;
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stmt(code: u16, k: u32) -> Insn {
        Insn {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jmp(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
        Insn { code, jt, jf, k }
    }

    /// busybox udhcpc's filter: UDP to port 68, not a fragment
    fn udhcpc() -> Vec<Insn> {
        alloc::vec![
            stmt(LD | B | ABS, 9),
            jmp(JMP | JEQ | K, 17, 0, 6),
            stmt(LD | H | ABS, 6),
            jmp(JMP | JSET | K, 0x1fff, 4, 0),
            stmt(LDX | B | MSH, 0),
            stmt(LD | H | IND, 2),
            jmp(JMP | JEQ | K, 68, 0, 1),
            stmt(RET | K, 0x7fff_ffff),
            stmt(RET | K, 0),
        ]
    }

    fn ip_udp(dport: u16, frag: u16) -> Vec<u8> {
        let mut p = alloc::vec![0u8; 28];
        p[0] = 0x45;
        p[6..8].copy_from_slice(&frag.to_be_bytes());
        p[9] = 17;
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }

    fn ctx(d: &[u8]) -> Ctx<'_> {
        Ctx {
            data: d,
            frame: d,
            ..Default::default()
        }
    }

    #[test]
    fn udhcpc_filter() {
        let f = Filter::new(udhcpc()).unwrap();
        assert_eq!(f.run(&ctx(&ip_udp(68, 0))), 0x7fff_ffff);
        assert_eq!(f.run(&ctx(&ip_udp(67, 0))), 0);
        assert_eq!(f.run(&ctx(&ip_udp(68, 0x0001))), 0);
        // Too short for the IND load: dropped
        assert_eq!(f.run(&ctx(&ip_udp(68, 0)[..21])), 0);
    }

    #[test]
    fn validation() {
        let bad = |v: Vec<Insn>| Filter::new(v).is_err();
        assert!(bad(alloc::vec![]));
        assert!(bad(alloc::vec![stmt(LD | IMM, 1)])); // no RET
        assert!(bad(alloc::vec![stmt(0xffff, 0), stmt(RET | K, 0)]));
        assert!(bad(alloc::vec![stmt(ALU | DIV | K, 0), stmt(RET | K, 0)]));
        assert!(bad(alloc::vec![stmt(ALU | LSH | K, 32), stmt(RET | K, 0)]));
        assert!(bad(alloc::vec![stmt(ST, 16), stmt(RET | K, 0)]));
        // Jump past the end
        assert!(bad(alloc::vec![stmt(JMP | JA, 1), stmt(RET | K, 0)]));
        assert!(bad(alloc::vec![
            jmp(JMP | JEQ | K, 0, 1, 0),
            stmt(RET | K, 0)
        ]));
        // Load of a never-stored slot, and of one stored on one path only
        assert!(bad(alloc::vec![stmt(LD | MEM, 0), stmt(RET | A, 0)]));
        assert!(bad(alloc::vec![
            jmp(JMP | JEQ | K, 0, 0, 1),
            stmt(ST, 3),
            stmt(LD | MEM, 3),
            stmt(RET | A, 0),
        ]));
        // Unknown ancillary offset
        assert!(bad(alloc::vec![
            stmt(LD | W | ABS, SKF_AD_OFF as u32 + 64),
            stmt(RET | A, 0)
        ]));
        assert!(
            Filter::new(alloc::vec![
                stmt(ST, 3),
                stmt(LD | MEM, 3),
                stmt(RET | A, 0)
            ])
            .is_ok()
        );
        assert!(Filter::new(alloc::vec![stmt(RET | K, 0); BPF_MAXINSNS + 1]).is_err());
    }

    #[test]
    fn alu_and_ancillary() {
        let d = [1u8, 2, 3, 4];
        let c = Ctx {
            data: &d,
            frame: &d,
            protocol: 0x0800,
            ..Default::default()
        };
        let prog = alloc::vec![
            stmt(LD | W | ABS, 0),
            stmt(ALU | RSH | K, 8),
            stmt(MISC | TAX, 0),
            stmt(LD | W | ABS, SKF_AD_OFF as u32 + ad::PROTOCOL),
            stmt(ALU | ADD | X, 0),
            stmt(RET | A, 0),
        ];
        assert_eq!(Filter::new(prog).unwrap().run(&c), 0x0800 + 0x010203);
        // Division by a zero X ends the program with 0
        let div = alloc::vec![stmt(LD | IMM, 7), stmt(ALU | DIV | X, 0), stmt(RET | K, 9)];
        assert_eq!(Filter::new(div).unwrap().run(&c), 0);
        // LEN and the link-layer negative offset
        let ll = alloc::vec![stmt(LD | B | ABS, SKF_LL_OFF as u32 + 3), stmt(RET | A, 0)];
        assert_eq!(Filter::new(ll).unwrap().run(&c), 4);
    }
}
