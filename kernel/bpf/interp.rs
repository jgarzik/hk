//! eBPF interpreter
//!
//! This module implements the eBPF virtual machine that executes
//! BPF programs. For seccomp, the context is a `seccomp_data` struct.

use super::insn::*;

/// Execute an eBPF program
///
/// # Arguments
/// * `prog` - The eBPF program instructions
/// * `ctx` - Pointer to context data (e.g., seccomp_data)
/// * `ctx_len` - Length of context data in bytes
///
/// # Returns
/// The value in R0 when the program exits
///
/// # Safety
/// The caller must ensure `ctx` points to valid memory of at least `ctx_len` bytes.
pub unsafe fn bpf_run(prog: &[BpfInsn], ctx: *const u8, ctx_len: usize) -> u64 {
    // eBPF has 11 64-bit registers
    let mut regs = [0u64; MAX_BPF_REG];

    // R1 = context pointer
    regs[BPF_REG_1 as usize] = ctx as u64;

    // R10 = frame pointer (stack base) - we don't implement stack for seccomp
    regs[BPF_REG_10 as usize] = 0;

    // Stack for scratch memory (512 bytes)
    let mut stack = [0u8; BPF_STACK_SIZE];

    let mut pc: usize = 0;

    while pc < prog.len() {
        let insn = &prog[pc];
        let code = insn.code;
        let dst = insn.dst_reg() as usize;
        let src = insn.src_reg() as usize;
        let off = insn.off;
        let imm = insn.imm;

        let class = bpf_class(code);

        match class {
            BPF_ALU | BPF_ALU64 => {
                let is_64 = class == BPF_ALU64;
                let src_val = if bpf_src(code) == BPF_X {
                    regs[src]
                } else {
                    imm as i64 as u64
                };

                let dst_val = regs[dst];

                let result = match bpf_op(code) {
                    BPF_ADD => dst_val.wrapping_add(src_val),
                    BPF_SUB => dst_val.wrapping_sub(src_val),
                    BPF_MUL => dst_val.wrapping_mul(src_val),
                    BPF_DIV => {
                        if src_val == 0 {
                            0
                        } else {
                            dst_val / src_val
                        }
                    }
                    BPF_OR => dst_val | src_val,
                    BPF_AND => dst_val & src_val,
                    BPF_LSH => dst_val << (src_val & 0x3f),
                    BPF_RSH => dst_val >> (src_val & 0x3f),
                    BPF_NEG => (!dst_val).wrapping_add(1),
                    BPF_MOD => {
                        if src_val == 0 {
                            0
                        } else {
                            dst_val % src_val
                        }
                    }
                    BPF_XOR => dst_val ^ src_val,
                    BPF_MOV => src_val,
                    BPF_ARSH => ((dst_val as i64) >> (src_val & 0x3f)) as u64,
                    BPF_END => {
                        // Endianness conversion
                        match imm {
                            16 => {
                                if bpf_src(code) == BPF_K {
                                    // to little endian
                                    (dst_val as u16).to_le() as u64
                                } else {
                                    // to big endian
                                    (dst_val as u16).to_be() as u64
                                }
                            }
                            32 => {
                                if bpf_src(code) == BPF_K {
                                    (dst_val as u32).to_le() as u64
                                } else {
                                    (dst_val as u32).to_be() as u64
                                }
                            }
                            64 => {
                                if bpf_src(code) == BPF_K {
                                    dst_val.to_le()
                                } else {
                                    dst_val.to_be()
                                }
                            }
                            _ => dst_val,
                        }
                    }
                    _ => {
                        // Unknown ALU op - return 0 (kill for seccomp)
                        return 0;
                    }
                };

                // For 32-bit ALU, zero-extend the result
                regs[dst] = if is_64 { result } else { result as u32 as u64 };
            }

            BPF_JMP | BPF_JMP32 => {
                let is_64 = class == BPF_JMP;
                let op = bpf_op(code);

                if op == BPF_EXIT {
                    return regs[BPF_REG_0 as usize];
                }

                if op == BPF_CALL {
                    // Helper calls not supported for seccomp
                    return 0;
                }

                if op == BPF_JA {
                    pc = (pc as i64 + off as i64) as usize;
                    pc += 1;
                    continue;
                }

                // Conditional jumps
                let dst_val = if is_64 {
                    regs[dst]
                } else {
                    regs[dst] as u32 as u64
                };

                let src_val = if bpf_src(code) == BPF_X {
                    if is_64 {
                        regs[src]
                    } else {
                        regs[src] as u32 as u64
                    }
                } else {
                    imm as u64
                };

                let cond = match op {
                    BPF_JEQ => dst_val == src_val,
                    BPF_JNE => dst_val != src_val,
                    BPF_JGT => dst_val > src_val,
                    BPF_JGE => dst_val >= src_val,
                    BPF_JLT => dst_val < src_val,
                    BPF_JLE => dst_val <= src_val,
                    BPF_JSET => (dst_val & src_val) != 0,
                    BPF_JSGT => (dst_val as i64) > (src_val as i64),
                    BPF_JSGE => (dst_val as i64) >= (src_val as i64),
                    BPF_JSLT => (dst_val as i64) < (src_val as i64),
                    BPF_JSLE => (dst_val as i64) <= (src_val as i64),
                    _ => false,
                };

                if cond {
                    pc = (pc as i64 + off as i64) as usize;
                }
            }

            BPF_LD | BPF_LDX => {
                let mode = bpf_mode(code);
                let size = bpf_size(code);

                match mode {
                    BPF_IMM => {
                        // 64-bit immediate load (2 instructions)
                        if size == BPF_DW {
                            let lo = imm as u32 as u64;
                            // Next instruction contains high 32 bits
                            if pc + 1 < prog.len() {
                                let hi = prog[pc + 1].imm as u32 as u64;
                                regs[dst] = (hi << 32) | lo;
                                pc += 1;
                            } else {
                                regs[dst] = lo;
                            }
                        } else {
                            regs[dst] = imm as i64 as u64;
                        }
                    }
                    BPF_ABS => {
                        // Absolute load from context
                        let offset = imm as usize;
                        let load_size = match size {
                            BPF_B => 1,
                            BPF_H => 2,
                            BPF_W => 4,
                            BPF_DW => 8,
                            _ => return 0,
                        };

                        if offset + load_size > ctx_len {
                            // Out of bounds - return 0 (SECCOMP_RET_KILL)
                            return 0;
                        }

                        let ptr = unsafe { ctx.add(offset) };
                        regs[dst] = unsafe {
                            match size {
                                BPF_B => *ptr as u64,
                                BPF_H => u16::from_ne_bytes([*ptr, *ptr.add(1)]) as u64,
                                BPF_W => u32::from_ne_bytes([
                                    *ptr,
                                    *ptr.add(1),
                                    *ptr.add(2),
                                    *ptr.add(3),
                                ]) as u64,
                                BPF_DW => u64::from_ne_bytes([
                                    *ptr,
                                    *ptr.add(1),
                                    *ptr.add(2),
                                    *ptr.add(3),
                                    *ptr.add(4),
                                    *ptr.add(5),
                                    *ptr.add(6),
                                    *ptr.add(7),
                                ]),
                                _ => return 0,
                            }
                        };
                    }
                    BPF_MEM => {
                        // Memory load: dst = *(size *)(src + off)
                        let addr = (regs[src] as i64 + off as i64) as usize;

                        // For seccomp, we only allow loads from the context
                        // Check if address is within context
                        let ctx_start = ctx as usize;
                        let ctx_end = ctx_start + ctx_len;

                        let load_size = match size {
                            BPF_B => 1,
                            BPF_H => 2,
                            BPF_W => 4,
                            BPF_DW => 8,
                            _ => return 0,
                        };

                        if addr >= ctx_start && addr + load_size <= ctx_end {
                            let ptr = addr as *const u8;
                            regs[dst] = unsafe {
                                match size {
                                    BPF_B => *ptr as u64,
                                    BPF_H => u16::from_ne_bytes([*ptr, *ptr.add(1)]) as u64,
                                    BPF_W => u32::from_ne_bytes([
                                        *ptr,
                                        *ptr.add(1),
                                        *ptr.add(2),
                                        *ptr.add(3),
                                    ]) as u64,
                                    BPF_DW => u64::from_ne_bytes([
                                        *ptr,
                                        *ptr.add(1),
                                        *ptr.add(2),
                                        *ptr.add(3),
                                        *ptr.add(4),
                                        *ptr.add(5),
                                        *ptr.add(6),
                                        *ptr.add(7),
                                    ]),
                                    _ => return 0,
                                }
                            };
                        } else {
                            // Check if it's a stack access
                            let stack_base = stack.as_ptr() as usize;
                            let stack_end = stack_base + BPF_STACK_SIZE;

                            if addr >= stack_base && addr + load_size <= stack_end {
                                let offset = addr - stack_base;
                                regs[dst] = match size {
                                    BPF_B => stack[offset] as u64,
                                    BPF_H => u16::from_ne_bytes([stack[offset], stack[offset + 1]])
                                        as u64,
                                    BPF_W => u32::from_ne_bytes([
                                        stack[offset],
                                        stack[offset + 1],
                                        stack[offset + 2],
                                        stack[offset + 3],
                                    ]) as u64,
                                    BPF_DW => u64::from_ne_bytes([
                                        stack[offset],
                                        stack[offset + 1],
                                        stack[offset + 2],
                                        stack[offset + 3],
                                        stack[offset + 4],
                                        stack[offset + 5],
                                        stack[offset + 6],
                                        stack[offset + 7],
                                    ]),
                                    _ => return 0,
                                };
                            } else {
                                // Invalid memory access
                                return 0;
                            }
                        }
                    }
                    _ => {
                        // Unknown mode
                        return 0;
                    }
                }
            }

            BPF_ST | BPF_STX => {
                let mode = bpf_mode(code);
                let size = bpf_size(code);

                if mode == BPF_MEM {
                    // Memory store: *(size *)(dst + off) = src
                    let addr = (regs[dst] as i64 + off as i64) as usize;
                    let val = if class == BPF_STX {
                        regs[src]
                    } else {
                        imm as u64
                    };

                    // For seccomp, only allow stores to stack
                    let stack_base = stack.as_ptr() as usize;
                    let stack_end = stack_base + BPF_STACK_SIZE;

                    let store_size = match size {
                        BPF_B => 1,
                        BPF_H => 2,
                        BPF_W => 4,
                        BPF_DW => 8,
                        _ => return 0,
                    };

                    if addr >= stack_base && addr + store_size <= stack_end {
                        let offset = addr - stack_base;
                        match size {
                            BPF_B => stack[offset] = val as u8,
                            BPF_H => {
                                let bytes = (val as u16).to_ne_bytes();
                                stack[offset] = bytes[0];
                                stack[offset + 1] = bytes[1];
                            }
                            BPF_W => {
                                let bytes = (val as u32).to_ne_bytes();
                                stack[offset..offset + 4].copy_from_slice(&bytes);
                            }
                            BPF_DW => {
                                let bytes = val.to_ne_bytes();
                                stack[offset..offset + 8].copy_from_slice(&bytes);
                            }
                            _ => return 0,
                        }
                    } else {
                        // Invalid memory access
                        return 0;
                    }
                } else {
                    // Unknown store mode
                    return 0;
                }
            }

            _ => {
                // Unknown instruction class
                return 0;
            }
        }

        pc += 1;

        // Safety: prevent infinite loops
        if pc > BPF_MAXINSNS {
            return 0;
        }
    }

    // Fell through without EXIT - return R0
    regs[BPF_REG_0 as usize]
}
