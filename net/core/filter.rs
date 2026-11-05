//! Classic BPF socket filters (Linux net/core/filter.c: SO_ATTACH_FILTER)
//!
//! A filter is checked once when attached (`bpf::classic::check`),
//! converted to eBPF and verified (`bpf::convert`, Linux
//! bpf_migrate_filter), and runs on the eBPF interpreter. The
//! program sees the packet as the socket will receive it (from the
//! link-layer header for SOCK_RAW packet sockets, from the network
//! header for SOCK_DGRAM), plus the SKF_NET_OFF / SKF_LL_OFF negative
//! offsets and the SKF_AD_* ancillary loads. An out-of-bounds load or a
//! division by zero ends the program with 0 (drop). The result is the
//! number of bytes to keep (0 = drop).
//!
//! No locks: a `Filter` is immutable and shared by `Arc`.

use alloc::vec::Vec;

use crate::bpf::BpfInsn;
use crate::bpf::classic::{self, SKF_AD_OFF, SKF_LL_OFF, SKF_NET_OFF, ad};
pub use crate::bpf::classic::{BPF_MAXINSNS, Insn};
use crate::bpf::convert;
use crate::util::error::KernelError;

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

impl classic::Env for Ctx<'_> {
    fn pkt_len(&self) -> u32 {
        self.data.len() as u32
    }

    /// `size` bytes at packet offset `off` (negative: SKF_NET_OFF/SKF_LL_OFF)
    fn load(&self, off: i32, size: usize) -> Option<u32> {
        let bytes = if off >= 0 {
            self.data
                .get(off as usize..(off as usize).checked_add(size)?)?
        } else if off >= SKF_NET_OFF {
            // SKF_AD_OFF range never reaches here for IND loads in Linux
            // either: those offsets are simply out of bounds
            if off >= SKF_AD_OFF {
                return None;
            }
            let o = self.net_off.checked_add((off - SKF_NET_OFF) as usize)?;
            self.frame.get(o..o.checked_add(size)?)?
        } else if off >= SKF_LL_OFF {
            let o = (off - SKF_LL_OFF) as usize;
            self.frame.get(o..o.checked_add(size)?)?
        } else {
            return None;
        };
        Some(bytes.iter().fold(0u32, |v, &b| (v << 8) | u32::from(b)))
    }

    fn anc(&self, k: u32) -> u32 {
        match k {
            ad::PROTOCOL => u32::from(self.protocol),
            ad::PKTTYPE => u32::from(self.pkt_type),
            ad::IFINDEX => self.ifindex,
            ad::MARK => self.mark,
            ad::HATYPE => u32::from(self.hatype),
            ad::CPU => crate::cpu::this_id(),
            ad::RANDOM => crate::random::get_random_u32(),
            // No netlink attributes, queues, hashes or VLAN tags here
            _ => 0,
        }
    }
}

/// A socket filter: a checked classic program, converted to eBPF
#[derive(Debug)]
pub struct Filter {
    prog: Vec<BpfInsn>,
}

impl Filter {
    /// Check a program (Linux bpf_check_basics_ok + bpf_check_classic)
    /// and convert it (bpf_migrate_filter)
    pub fn new(insns: Vec<Insn>) -> Result<Self, KernelError> {
        classic::check(&insns)?;
        let prog = convert::convert(&insns, &convert::SOCKET)?;
        Ok(Self { prog })
    }

    /// Run the program: bytes of the packet to keep (0 = drop)
    pub fn run(&self, c: &Ctx) -> u32 {
        convert::run(&self.prog, &[], c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::classic::*;

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
