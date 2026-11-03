//! cBPF to eBPF converter
//!
//! This module converts classic BPF (sock_filter) programs to eBPF format.
//! This is used for seccomp(2) which accepts cBPF programs from userspace.

use alloc::vec::Vec;

use super::insn::*;

/// Classic BPF instruction (sock_filter)
///
/// This is the format used by seccomp(2) and socket filters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SockFilter {
    /// Opcode
    pub code: u16,
    /// Jump if true
    pub jt: u8,
    /// Jump if false
    pub jf: u8,
    /// Generic multiuse field (immediate, offset, etc.)
    pub k: u32,
}

// Note: SockFprog is defined in seccomp/filter.rs where it's used for
// reading from userspace. This module only needs SockFilter for conversion.

// cBPF uses these registers:
// A = accumulator (maps to eBPF R0)
// X = index register (maps to eBPF R7)
// M[0-15] = scratch memory (maps to eBPF stack)

const CBPF_REG_A: u8 = BPF_REG_0;
const CBPF_REG_X: u8 = BPF_REG_7;
const CBPF_REG_TMP: u8 = BPF_REG_8;

/// Convert a classic BPF program to eBPF
///
/// # Arguments
/// * `cbpf` - The classic BPF instructions
///
/// # Returns
/// A vector of eBPF instructions, or an error string
pub fn cbpf_to_ebpf(cbpf: &[SockFilter]) -> Result<Vec<BpfInsn>, &'static str> {
    if cbpf.is_empty() {
        return Err("empty program");
    }

    if cbpf.len() > BPF_MAXINSNS {
        return Err("program too large");
    }

    let mut ebpf = Vec::with_capacity(cbpf.len() * 2);

    // Map from cBPF instruction index to eBPF instruction index
    // Used for fixing up jump targets
    let mut insn_map = Vec::with_capacity(cbpf.len() + 1);

    for (i, cf) in cbpf.iter().enumerate() {
        insn_map.push(ebpf.len());

        let code = cf.code;
        let class = (code & 0x07) as u8;

        match class {
            0x00 => {
                // BPF_LD class
                convert_ld(&mut ebpf, cf)?;
            }
            0x01 => {
                // BPF_LDX class
                convert_ldx(&mut ebpf, cf)?;
            }
            0x02 => {
                // BPF_ST class
                convert_st(&mut ebpf, cf)?;
            }
            0x03 => {
                // BPF_STX class
                convert_stx(&mut ebpf, cf)?;
            }
            0x04 => {
                // BPF_ALU class
                convert_alu(&mut ebpf, cf)?;
            }
            0x05 => {
                // BPF_JMP class
                convert_jmp(&mut ebpf, cf, i, cbpf.len())?;
            }
            0x06 => {
                // BPF_RET class
                convert_ret(&mut ebpf, cf)?;
            }
            0x07 => {
                // BPF_MISC class
                convert_misc(&mut ebpf, cf)?;
            }
            _ => {
                return Err("unknown instruction class");
            }
        }
    }

    // Final instruction count for jump fixup
    insn_map.push(ebpf.len());

    // Fix up jump targets
    // cBPF jumps are relative to the next instruction
    // We need to convert them to eBPF offsets
    fixup_jumps(&mut ebpf, cbpf, &insn_map)?;

    Ok(ebpf)
}

fn convert_ld(ebpf: &mut Vec<BpfInsn>, cf: &SockFilter) -> Result<(), &'static str> {
    let mode = (cf.code >> 5) & 0x07;
    let size = (cf.code >> 3) & 0x03;

    match mode {
        0 => {
            // BPF_IMM: A = k
            ebpf.push(BpfInsn::new(
                BPF_ALU | BPF_MOV | BPF_K,
                CBPF_REG_A,
                0,
                0,
                cf.k as i32,
            ));
        }
        1 => {
            // BPF_ABS: A = *(type *)(ctx + k)
            let ebpf_size = match size {
                0 => BPF_W, // 32-bit
                1 => BPF_H, // 16-bit
                2 => BPF_B, // 8-bit
                _ => return Err("invalid LD size"),
            };
            ebpf.push(BpfInsn::new(
                BPF_LD | ebpf_size | BPF_ABS,
                CBPF_REG_A,
                0,
                0,
                cf.k as i32,
            ));
        }
        2 => {
            // BPF_IND: A = *(type *)(ctx + X + k)
            // Not commonly used in seccomp, but support it
            let ebpf_size = match size {
                0 => BPF_W,
                1 => BPF_H,
                2 => BPF_B,
                _ => return Err("invalid LD size"),
            };
            // Add X + k into temp, then load
            ebpf.push(BpfInsn::new(
                BPF_ALU64 | BPF_MOV | BPF_X,
                CBPF_REG_TMP,
                CBPF_REG_X,
                0,
                0,
            ));
            ebpf.push(BpfInsn::new(
                BPF_ALU64 | BPF_ADD | BPF_K,
                CBPF_REG_TMP,
                0,
                0,
                cf.k as i32,
            ));
            // ctx is in R1
            ebpf.push(BpfInsn::new(
                BPF_ALU64 | BPF_ADD | BPF_X,
                CBPF_REG_TMP,
                BPF_REG_1,
                0,
                0,
            ));
            ebpf.push(BpfInsn::new(
                BPF_LDX | ebpf_size | BPF_MEM,
                CBPF_REG_A,
                CBPF_REG_TMP,
                0,
                0,
            ));
        }
        3 => {
            // BPF_MEM: A = M[k]
            let offset = -(((cf.k & 0x0f) + 1) as i16 * 4);
            ebpf.push(BpfInsn::new(
                BPF_LDX | BPF_W | BPF_MEM,
                CBPF_REG_A,
                BPF_REG_10,
                offset,
                0,
            ));
        }
        4 => {
            // BPF_LEN: A = len (packet length, not used in seccomp)
            // For seccomp, this is the size of seccomp_data (64 bytes)
            ebpf.push(BpfInsn::new(
                BPF_ALU | BPF_MOV | BPF_K,
                CBPF_REG_A,
                0,
                0,
                64, // sizeof(seccomp_data)
            ));
        }
        _ => {
            return Err("unsupported LD mode");
        }
    }

    Ok(())
}

fn convert_ldx(ebpf: &mut Vec<BpfInsn>, cf: &SockFilter) -> Result<(), &'static str> {
    let mode = (cf.code >> 5) & 0x07;
    let size = (cf.code >> 3) & 0x03;

    match mode {
        0 => {
            // BPF_IMM: X = k
            ebpf.push(BpfInsn::new(
                BPF_ALU | BPF_MOV | BPF_K,
                CBPF_REG_X,
                0,
                0,
                cf.k as i32,
            ));
        }
        3 => {
            // BPF_MEM: X = M[k]
            let offset = -(((cf.k & 0x0f) + 1) as i16 * 4);
            ebpf.push(BpfInsn::new(
                BPF_LDX | BPF_W | BPF_MEM,
                CBPF_REG_X,
                BPF_REG_10,
                offset,
                0,
            ));
        }
        4 => {
            // BPF_LEN: X = len
            ebpf.push(BpfInsn::new(
                BPF_ALU | BPF_MOV | BPF_K,
                CBPF_REG_X,
                0,
                0,
                64,
            ));
        }
        5 => {
            // BPF_MSH: X = 4 * (*(ctx + k) & 0xf)
            // IP header length calculation - rarely used in seccomp
            let ebpf_size = match size {
                2 => BPF_B,
                _ => BPF_B,
            };
            ebpf.push(BpfInsn::new(
                BPF_LD | ebpf_size | BPF_ABS,
                CBPF_REG_X,
                0,
                0,
                cf.k as i32,
            ));
            ebpf.push(BpfInsn::new(
                BPF_ALU | BPF_AND | BPF_K,
                CBPF_REG_X,
                0,
                0,
                0x0f,
            ));
            ebpf.push(BpfInsn::new(BPF_ALU | BPF_LSH | BPF_K, CBPF_REG_X, 0, 0, 2));
        }
        _ => {
            return Err("unsupported LDX mode");
        }
    }

    Ok(())
}

fn convert_st(ebpf: &mut Vec<BpfInsn>, cf: &SockFilter) -> Result<(), &'static str> {
    // ST: M[k] = A
    let offset = -(((cf.k & 0x0f) + 1) as i16 * 4);
    ebpf.push(BpfInsn::new(
        BPF_STX | BPF_W | BPF_MEM,
        BPF_REG_10,
        CBPF_REG_A,
        offset,
        0,
    ));
    Ok(())
}

fn convert_stx(ebpf: &mut Vec<BpfInsn>, cf: &SockFilter) -> Result<(), &'static str> {
    // STX: M[k] = X
    let offset = -(((cf.k & 0x0f) + 1) as i16 * 4);
    ebpf.push(BpfInsn::new(
        BPF_STX | BPF_W | BPF_MEM,
        BPF_REG_10,
        CBPF_REG_X,
        offset,
        0,
    ));
    Ok(())
}

fn convert_alu(ebpf: &mut Vec<BpfInsn>, cf: &SockFilter) -> Result<(), &'static str> {
    let op = (cf.code >> 4) & 0x0f;
    let src = (cf.code >> 3) & 0x01;

    let ebpf_src = if src == 1 { BPF_X } else { BPF_K };
    let src_reg = if src == 1 { CBPF_REG_X } else { 0 };

    let ebpf_op = match op {
        0 => BPF_ADD,
        1 => BPF_SUB,
        2 => BPF_MUL,
        3 => BPF_DIV,
        4 => BPF_OR,
        5 => BPF_AND,
        6 => BPF_LSH,
        7 => BPF_RSH,
        8 => BPF_NEG,
        9 => BPF_MOD,
        10 => BPF_XOR,
        _ => return Err("unknown ALU op"),
    };

    if op == 8 {
        // NEG doesn't use source
        ebpf.push(BpfInsn::new(BPF_ALU | BPF_NEG, CBPF_REG_A, 0, 0, 0));
    } else {
        ebpf.push(BpfInsn::new(
            BPF_ALU | ebpf_op | ebpf_src,
            CBPF_REG_A,
            src_reg,
            0,
            cf.k as i32,
        ));
    }

    Ok(())
}

fn convert_jmp(
    ebpf: &mut Vec<BpfInsn>,
    cf: &SockFilter,
    _insn_idx: usize,
    _prog_len: usize,
) -> Result<(), &'static str> {
    let op = (cf.code >> 4) & 0x0f;
    let src = (cf.code >> 3) & 0x01;

    if op == 0 {
        // JA: unconditional jump
        // Offset will be fixed up later
        ebpf.push(BpfInsn::new(
            BPF_JMP | BPF_JA,
            0,
            0,
            cf.k as i16, // Placeholder, will be fixed up
            0,
        ));
        return Ok(());
    }

    // Conditional jumps
    let ebpf_src = if src == 1 { BPF_X } else { BPF_K };
    let src_reg = if src == 1 { CBPF_REG_X } else { 0 };

    let ebpf_op = match op {
        1 => BPF_JEQ,
        2 => BPF_JGT,
        3 => BPF_JGE,
        4 => BPF_JSET,
        _ => return Err("unknown JMP op"),
    };

    // cBPF conditional jumps have jt and jf offsets
    // We need to emit two jumps: one for true, one fallthrough, then unconditional for false

    if cf.jt == 0 && cf.jf == 0 {
        // Both targets are next instruction - no jump needed
        return Ok(());
    }

    if cf.jf == 0 {
        // Only true branch jumps, false falls through
        ebpf.push(BpfInsn::new(
            BPF_JMP | ebpf_op | ebpf_src,
            CBPF_REG_A,
            src_reg,
            cf.jt as i16, // Placeholder
            cf.k as i32,
        ));
    } else if cf.jt == 0 {
        // Only false branch jumps - invert condition
        let inv_op = match ebpf_op {
            BPF_JEQ => BPF_JNE,
            BPF_JGT => BPF_JLE,
            BPF_JGE => BPF_JLT,
            BPF_JSET => {
                // JSET inversion: if (A & K) == 0
                // We need to test and jump if zero
                // Emit: if (A & K) goto +1; goto jf;
                ebpf.push(BpfInsn::new(
                    BPF_JMP | BPF_JSET | ebpf_src,
                    CBPF_REG_A,
                    src_reg,
                    1, // Skip next instruction
                    cf.k as i32,
                ));
                ebpf.push(BpfInsn::new(
                    BPF_JMP | BPF_JA,
                    0,
                    0,
                    cf.jf as i16, // Placeholder
                    0,
                ));
                return Ok(());
            }
            _ => return Err("cannot invert jump"),
        };
        ebpf.push(BpfInsn::new(
            BPF_JMP | inv_op | ebpf_src,
            CBPF_REG_A,
            src_reg,
            cf.jf as i16, // Placeholder
            cf.k as i32,
        ));
    } else {
        // Both branches jump
        ebpf.push(BpfInsn::new(
            BPF_JMP | ebpf_op | ebpf_src,
            CBPF_REG_A,
            src_reg,
            cf.jt as i16, // Placeholder
            cf.k as i32,
        ));
        ebpf.push(BpfInsn::new(
            BPF_JMP | BPF_JA,
            0,
            0,
            cf.jf as i16, // Placeholder (jf - 1 because we added one insn)
            0,
        ));
    }

    Ok(())
}

fn convert_ret(ebpf: &mut Vec<BpfInsn>, cf: &SockFilter) -> Result<(), &'static str> {
    let src = (cf.code >> 4) & 0x01;

    if src == 1 {
        // Return A (already in R0)
        // No move needed since A is R0
    } else {
        // Return K
        ebpf.push(BpfInsn::new(
            BPF_ALU | BPF_MOV | BPF_K,
            BPF_REG_0,
            0,
            0,
            cf.k as i32,
        ));
    }

    ebpf.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));

    Ok(())
}

fn convert_misc(ebpf: &mut Vec<BpfInsn>, cf: &SockFilter) -> Result<(), &'static str> {
    let op = (cf.code >> 4) & 0x0f;

    match op {
        0 => {
            // TAX: X = A
            ebpf.push(BpfInsn::new(
                BPF_ALU | BPF_MOV | BPF_X,
                CBPF_REG_X,
                CBPF_REG_A,
                0,
                0,
            ));
        }
        8 => {
            // TXA: A = X
            ebpf.push(BpfInsn::new(
                BPF_ALU | BPF_MOV | BPF_X,
                CBPF_REG_A,
                CBPF_REG_X,
                0,
                0,
            ));
        }
        _ => {
            return Err("unknown MISC op");
        }
    }

    Ok(())
}

fn fixup_jumps(
    ebpf: &mut [BpfInsn],
    cbpf: &[SockFilter],
    insn_map: &[usize],
) -> Result<(), &'static str> {
    let mut ebpf_idx = 0;

    for (cbpf_idx, cf) in cbpf.iter().enumerate() {
        let class = (cf.code & 0x07) as u8;
        let op = (cf.code >> 4) & 0x0f;

        if class == 0x05 {
            // JMP class
            if op == 0 {
                // JA: unconditional
                let target_cbpf = cbpf_idx + 1 + cf.k as usize;
                if target_cbpf > cbpf.len() {
                    return Err("jump out of bounds");
                }
                let target_ebpf = insn_map[target_cbpf];
                let current_ebpf = ebpf_idx;
                // eBPF offset is relative to next instruction
                let offset = target_ebpf as i64 - current_ebpf as i64 - 1;
                if offset < i16::MIN as i64 || offset > i16::MAX as i64 {
                    return Err("jump offset too large");
                }
                ebpf[ebpf_idx].off = offset as i16;
                ebpf_idx += 1;
            } else {
                // Conditional jumps
                if cf.jf == 0 {
                    // Only true branch
                    let target_cbpf = cbpf_idx + 1 + cf.jt as usize;
                    if target_cbpf > cbpf.len() {
                        return Err("jump out of bounds");
                    }
                    let target_ebpf = insn_map[target_cbpf];
                    let current_ebpf = ebpf_idx;
                    let offset = target_ebpf as i64 - current_ebpf as i64 - 1;
                    if offset < i16::MIN as i64 || offset > i16::MAX as i64 {
                        return Err("jump offset too large");
                    }
                    ebpf[ebpf_idx].off = offset as i16;
                    ebpf_idx += 1;
                } else if cf.jt == 0 {
                    // Only false branch (inverted) - but JSET is special
                    if op == 4 {
                        // JSET with both branches
                        // Skip the JSET instruction
                        ebpf_idx += 1;
                        // Fix the JA
                        let target_cbpf = cbpf_idx + 1 + cf.jf as usize;
                        if target_cbpf > cbpf.len() {
                            return Err("jump out of bounds");
                        }
                        let target_ebpf = insn_map[target_cbpf];
                        let current_ebpf = ebpf_idx;
                        let offset = target_ebpf as i64 - current_ebpf as i64 - 1;
                        ebpf[ebpf_idx].off = offset as i16;
                        ebpf_idx += 1;
                    } else {
                        let target_cbpf = cbpf_idx + 1 + cf.jf as usize;
                        if target_cbpf > cbpf.len() {
                            return Err("jump out of bounds");
                        }
                        let target_ebpf = insn_map[target_cbpf];
                        let current_ebpf = ebpf_idx;
                        let offset = target_ebpf as i64 - current_ebpf as i64 - 1;
                        ebpf[ebpf_idx].off = offset as i16;
                        ebpf_idx += 1;
                    }
                } else {
                    // Both branches
                    // True branch
                    let target_cbpf_t = cbpf_idx + 1 + cf.jt as usize;
                    if target_cbpf_t > cbpf.len() {
                        return Err("jump out of bounds");
                    }
                    let target_ebpf_t = insn_map[target_cbpf_t];
                    let current_ebpf = ebpf_idx;
                    let offset_t = target_ebpf_t as i64 - current_ebpf as i64 - 1;
                    ebpf[ebpf_idx].off = offset_t as i16;
                    ebpf_idx += 1;

                    // False branch (JA)
                    let target_cbpf_f = cbpf_idx + 1 + cf.jf as usize;
                    if target_cbpf_f > cbpf.len() {
                        return Err("jump out of bounds");
                    }
                    let target_ebpf_f = insn_map[target_cbpf_f];
                    let current_ebpf = ebpf_idx;
                    let offset_f = target_ebpf_f as i64 - current_ebpf as i64 - 1;
                    ebpf[ebpf_idx].off = offset_f as i16;
                    ebpf_idx += 1;
                }
            }
        } else {
            // Count eBPF instructions for this cBPF instruction
            let next_cbpf_ebpf_idx = insn_map[cbpf_idx + 1];
            let insns_for_this = next_cbpf_ebpf_idx - insn_map[cbpf_idx];
            ebpf_idx += insns_for_this;
        }
    }

    Ok(())
}

/// Validate a classic BPF program
///
/// Checks for:
/// - Valid instruction classes and opcodes
/// - Jump targets within bounds
/// - Program ends with RET
pub fn validate_cbpf(cbpf: &[SockFilter]) -> Result<(), &'static str> {
    if cbpf.is_empty() {
        return Err("empty program");
    }

    if cbpf.len() > BPF_MAXINSNS {
        return Err("program too large");
    }

    for (i, cf) in cbpf.iter().enumerate() {
        let class = (cf.code & 0x07) as u8;

        match class {
            0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x07 => {
                // LD, LDX, ST, STX, ALU, MISC - valid
            }
            0x05 => {
                // JMP
                let op = (cf.code >> 4) & 0x0f;
                if op == 0 {
                    // JA
                    let target = i + 1 + cf.k as usize;
                    if target > cbpf.len() {
                        return Err("jump out of bounds");
                    }
                } else {
                    // Conditional
                    let target_t = i + 1 + cf.jt as usize;
                    let target_f = i + 1 + cf.jf as usize;
                    if target_t > cbpf.len() || target_f > cbpf.len() {
                        return Err("jump out of bounds");
                    }
                }
            }
            0x06 => {
                // RET - valid, marks end of execution path
            }
            _ => {
                return Err("invalid instruction class");
            }
        }
    }

    // Check last instruction is RET (simplified check)
    // A full check would trace all execution paths
    let last = &cbpf[cbpf.len() - 1];
    if (last.code & 0x07) != 0x06 {
        return Err("program must end with RET");
    }

    Ok(())
}
