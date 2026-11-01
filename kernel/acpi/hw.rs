//! ACPI fixed hardware: ACPI mode and the legacy sleep sequence (Linux
//! ACPICA hwacpi.c acpi_hw_set_mode, hwsleep.c acpi_hw_legacy_sleep)
//!
//! Register blocks are I/O ports, from the FADT (the 32-bit block
//! fields; hk reads no GAS forms yet). Port access goes through `PortIo`
//! so host tests can drive a fake chipset.

use super::aml::SleepType;

/// 8- and 16-bit I/O port access
pub trait PortIo {
    fn inb(&mut self, port: u16) -> u8;
    fn outb(&mut self, port: u16, val: u8);
    fn inw(&mut self, port: u16) -> u16;
    fn outw(&mut self, port: u16, val: u16);
}

/// The FADT's power management register blocks (0: absent)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PmRegs {
    /// PM1a/PM1b event blocks: status registers, then enable registers,
    /// each `pm1_evt_len / 2` bytes
    pub pm1a_evt: u16,
    pub pm1b_evt: u16,
    pub pm1_evt_len: u8,
    /// PM1a/PM1b control registers
    pub pm1a_cnt: u16,
    pub pm1b_cnt: u16,
    /// GPE0/GPE1 blocks: status bytes, then enable bytes, each
    /// `len / 2` long
    pub gpe0: u16,
    pub gpe0_len: u8,
    pub gpe1: u16,
    pub gpe1_len: u8,
    /// SMI command port and the value that hands the fixed hardware to
    /// the OS (ACPI mode)
    pub smi_cmd: u16,
    pub acpi_enable: u8,
}

/// Where the FADT reset register lives (GAS address space IDs 0 and 1;
/// PCI configuration space is not supported)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Space {
    Mem,
    Io,
}

/// The FADT reset register and the value that resets the machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetReg {
    pub space: Space,
    pub addr: u64,
    pub value: u8,
}

/// PM1 control: SCI_EN (ACPI mode)
pub const SCI_EN: u16 = 1 << 0;
/// PM1 control: SLP_TYP field shift (3 bits)
pub const SLP_TYP_SHIFT: u16 = 10;
/// PM1 control: SLP_TYP field
const SLP_TYP: u16 = 7 << SLP_TYP_SHIFT;
/// PM1 control: SLP_EN
pub const SLP_EN: u16 = 1 << 13;
/// PM1 status: WAK_STS
pub const WAK_STS: u16 = 1 << 15;
/// PM1 status: every fixed event status bit (ACPICA
/// ACPI_BITMASK_ALL_FIXED_STATUS)
const ALL_FIXED_STATUS: u16 = 0xc731;
/// PM1 status: the ignored bit, written as zero (ACPICA
/// ACPI_PM1_STATUS_PRESERVED_BITS)
const PM1_STS_PRESERVED: u16 = 1 << 11;
/// PM1 control: GBL_RLS (a write raises an SMI to release the global
/// lock)
const GBL_RLS: u16 = 1 << 2;
/// PM1 control: write-only bits, masked out of every read (ACPICA
/// ACPI_PM1_CONTROL_WRITEONLY_BITS)
const PM1_CNT_WRITEONLY: u16 = SLP_EN | GBL_RLS;

/// The hardware did not enter ACPI mode: SCI_EN stayed clear after the
/// enable command, or there is no enable command to send
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnableTimeout;

/// Whether the fixed hardware is in ACPI mode (Linux acpi_hw_get_mode):
/// without SMI_CMD it always is
pub fn acpi_mode(io: &mut impl PortIo, regs: &PmRegs) -> bool {
    regs.smi_cmd == 0 || pm1_cnt_read(io, regs) & SCI_EN != 0
}

/// Put the fixed hardware in ACPI mode (Linux acpi_enable ->
/// acpi_hw_set_mode(ACPI_SYS_MODE_ACPI)): if SCI_EN is clear, write
/// ACPI_ENABLE to SMI_CMD and wait for SCI_EN, up to 3 s (Linux
/// acpi_enable's wait). With no ACPI_ENABLE value there is nothing to
/// send, and the hardware stays in legacy mode: an error, as in Linux
/// ("Hardware did not enter ACPI mode")
pub fn acpi_enable(
    io: &mut impl PortIo,
    regs: &PmRegs,
    clock: &mut impl crate::delay::Clock,
) -> Result<(), EnableTimeout> {
    if acpi_mode(io, regs) {
        return Ok(());
    }
    if regs.acpi_enable == 0 {
        return Err(EnableTimeout);
    }
    io.outb(regs.smi_cmd, regs.acpi_enable);
    crate::delay::poll_on(clock, 3_000_000, 100, || acpi_mode(io, regs)).map_err(|_| EnableTimeout)
}

/// Disable every fixed event and GPE and clear their status, so no SCI
/// fires until a handler asks for one (Linux acpi_ev_fixed_event_initialize
/// and the GPE block setup, acpi_ev_create_gpe_info_blocks)
pub fn disable_events(io: &mut impl PortIo, regs: &PmRegs) {
    pm1_en_write(io, regs, 0);
    gpe_disable_all(io, regs);
    clear_status(io, regs);
}

/// Enter S5 with `typ`, up to the SLP_EN write (Linux
/// acpi_hw_legacy_sleep): returns only if the machine is still running
pub fn enter_s5(io: &mut impl PortIo, regs: &PmRegs, typ: SleepType) {
    pm1_sts_write(io, regs, WAK_STS);
    gpe_disable_all(io, regs);
    clear_status(io, regs);
    let (a, b) = sleep_values(io, regs, typ);
    // Split SLP_TYP and SLP_EN writes, for poorly implemented hardware
    pm1_cnt_write(io, regs, a, b);
    pm1_cnt_write(io, regs, a | SLP_EN, b | SLP_EN);
}

/// Set SLP_EN again after `enter_s5` did not take, for chipsets that
/// poll PM1 control slowly (the retry in Linux acpi_hw_legacy_sleep,
/// which the caller makes after its 10 s wait). Linux writes SLP_EN
/// alone through acpi_hw_register_write, which zeroes SLP_TYP (not a
/// preserved bit); this keeps SLP_TYP, so it asks for S5 again rather
/// than S0.
pub fn sleep_retry(io: &mut impl PortIo, regs: &PmRegs, typ: SleepType) {
    let (a, b) = sleep_values(io, regs, typ);
    pm1_cnt_write(io, regs, a | SLP_EN, b | SLP_EN);
}

/// PM1a/PM1b control with SLP_TYP set to `typ` and SLP_EN clear, the
/// other bits (SCI_EN included) as read
fn sleep_values(io: &mut impl PortIo, regs: &PmRegs, typ: SleepType) -> (u16, u16) {
    let cnt = pm1_cnt_read(io, regs) & !(SLP_TYP | SLP_EN);
    let field = |t: u8| ((t as u16) << SLP_TYP_SHIFT) & SLP_TYP;
    (cnt | field(typ.a), cnt | field(typ.b))
}

/// Clear every fixed event and GPE status bit (Linux
/// acpi_hw_clear_acpi_status)
fn clear_status(io: &mut impl PortIo, regs: &PmRegs) {
    pm1_sts_write(io, regs, ALL_FIXED_STATUS);
    for (base, half) in gpe_blocks(regs) {
        for i in 0..half {
            io.outb(base + i, 0xff);
        }
    }
}

/// Zero every GPE enable register, a byte at a time (Linux
/// acpi_hw_disable_all_gpes; ACPI_GPE_REGISTER_WIDTH is 8)
fn gpe_disable_all(io: &mut impl PortIo, regs: &PmRegs) {
    for (base, half) in gpe_blocks(regs) {
        for i in 0..half {
            io.outb(base + half + i, 0);
        }
    }
}

/// The present GPE blocks: (base port, status/enable half length)
fn gpe_blocks(regs: &PmRegs) -> impl Iterator<Item = (u16, u16)> {
    [(regs.gpe0, regs.gpe0_len), (regs.gpe1, regs.gpe1_len)]
        .into_iter()
        .filter(|&(base, len)| base != 0 && len >= 2)
        .map(|(base, len)| (base, len as u16 / 2))
}

/// PM1 control, a and b ORed, write-only bits clear (Linux
/// acpi_hw_register_read: a read-modify-write never sets GBL_RLS)
fn pm1_cnt_read(io: &mut impl PortIo, regs: &PmRegs) -> u16 {
    let b = if regs.pm1b_cnt != 0 {
        io.inw(regs.pm1b_cnt)
    } else {
        0
    };
    (io.inw(regs.pm1a_cnt) | b) & !PM1_CNT_WRITEONLY
}

/// Write PM1a and PM1b control (Linux acpi_hw_write_pm1_control)
fn pm1_cnt_write(io: &mut impl PortIo, regs: &PmRegs, a: u16, b: u16) {
    io.outw(regs.pm1a_cnt, a);
    if regs.pm1b_cnt != 0 {
        io.outw(regs.pm1b_cnt, b);
    }
}

/// Write PM1 status, a and b (write-1-to-clear)
fn pm1_sts_write(io: &mut impl PortIo, regs: &PmRegs, val: u16) {
    pm1_evt_write(io, regs, 0, val & !PM1_STS_PRESERVED);
}

/// Write PM1 enable, a and b
fn pm1_en_write(io: &mut impl PortIo, regs: &PmRegs, val: u16) {
    pm1_evt_write(io, regs, regs.pm1_evt_len as u16 / 2, val);
}

/// Write the register at `off` in the PM1a and PM1b event blocks
fn pm1_evt_write(io: &mut impl PortIo, regs: &PmRegs, off: u16, val: u16) {
    for base in [regs.pm1a_evt, regs.pm1b_evt] {
        if base != 0 && regs.pm1_evt_len >= 4 {
            io.outw(base + off, val);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delay::tests::FakeClock;
    use alloc::vec::Vec;

    /// A PCH-like chipset: a port space, a log of writes, and SMI_CMD
    /// setting SCI_EN when told to (or not, `deaf`)
    struct FakeChipset {
        ports: [u8; 0x1000],
        writes: Vec<(u16, u16)>,
        regs: PmRegs,
        deaf: bool,
    }

    impl FakeChipset {
        fn new(regs: PmRegs) -> Self {
            Self {
                ports: [0; 0x1000],
                writes: Vec::new(),
                regs,
                deaf: false,
            }
        }
        fn w(&self, port: u16) -> u16 {
            u16::from_le_bytes([self.ports[port as usize], self.ports[port as usize + 1]])
        }
        fn setw(&mut self, port: u16, val: u16) {
            let b = val.to_le_bytes();
            self.ports[port as usize] = b[0];
            self.ports[port as usize + 1] = b[1];
        }
        fn writes_to(&self, port: u16) -> Vec<u16> {
            self.writes
                .iter()
                .filter(|w| w.0 == port)
                .map(|w| w.1)
                .collect()
        }
    }

    impl PortIo for FakeChipset {
        fn inb(&mut self, port: u16) -> u8 {
            self.ports[port as usize]
        }
        fn outb(&mut self, port: u16, val: u8) {
            self.writes.push((port, val as u16));
            if port == self.regs.smi_cmd && val == self.regs.acpi_enable && !self.deaf {
                let c = self.w(self.regs.pm1a_cnt);
                self.setw(self.regs.pm1a_cnt, c | SCI_EN);
            } else {
                self.ports[port as usize] = val;
            }
        }
        fn inw(&mut self, port: u16) -> u16 {
            self.w(port)
        }
        fn outw(&mut self, port: u16, val: u16) {
            self.writes.push((port, val));
            self.setw(port, val);
        }
    }

    /// Lynx Point's layout (PMBASE 0x400 scaled into the fake space)
    const LPT: PmRegs = PmRegs {
        pm1a_evt: 0x400,
        pm1b_evt: 0,
        pm1_evt_len: 4,
        pm1a_cnt: 0x404,
        pm1b_cnt: 0,
        gpe0: 0x480,
        gpe0_len: 0x20,
        gpe1: 0,
        gpe1_len: 0,
        smi_cmd: 0xb2,
        acpi_enable: 0xa0,
    };

    const S5: SleepType = SleepType { a: 7, b: 7 };

    #[test]
    fn enable_from_legacy_mode() {
        let mut hw = FakeChipset::new(LPT);
        let mut clock = FakeClock { now: 0, step: 1000 };
        assert_eq!(acpi_enable(&mut hw, &LPT, &mut clock), Ok(()));
        assert_eq!(hw.writes_to(LPT.smi_cmd), [LPT.acpi_enable as u16]);
        assert_ne!(hw.w(LPT.pm1a_cnt) & SCI_EN, 0);
    }

    #[test]
    fn enable_already_acpi() {
        let mut hw = FakeChipset::new(LPT);
        hw.setw(LPT.pm1a_cnt, SCI_EN);
        let mut clock = FakeClock { now: 0, step: 1000 };
        assert_eq!(acpi_enable(&mut hw, &LPT, &mut clock), Ok(()));
        assert!(hw.writes.is_empty());
    }

    /// No SMI_CMD (hardware-reduced or ACPI-only firmware): nothing to do
    #[test]
    fn enable_no_smi_cmd() {
        let regs = PmRegs { smi_cmd: 0, ..LPT };
        let mut hw = FakeChipset::new(regs);
        let mut clock = FakeClock { now: 0, step: 1000 };
        assert_eq!(acpi_enable(&mut hw, &regs, &mut clock), Ok(()));
        assert!(hw.writes.is_empty());
    }

    /// Legacy mode and no ACPI_ENABLE value: an error, nothing written
    #[test]
    fn enable_no_enable_value() {
        let regs = PmRegs {
            acpi_enable: 0,
            ..LPT
        };
        let mut hw = FakeChipset::new(regs);
        let mut clock = FakeClock { now: 0, step: 1000 };
        assert_eq!(acpi_enable(&mut hw, &regs, &mut clock), Err(EnableTimeout));
        assert!(hw.writes.is_empty());
    }

    /// Firmware that never sets SCI_EN: a timeout after about 3 s
    #[test]
    fn enable_times_out() {
        let mut hw = FakeChipset::new(LPT);
        hw.deaf = true;
        let mut clock = FakeClock { now: 0, step: 1000 };
        assert_eq!(acpi_enable(&mut hw, &LPT, &mut clock), Err(EnableTimeout));
        assert!(clock.now >= 3_000_000_000 && clock.now < 4_000_000_000);
    }

    /// The Linux sequence: wake status cleared, GPEs disabled, then
    /// PM1 control read-modify-written twice, SLP_TYP alone first,
    /// SCI_EN and the other bits kept, write-only GBL_RLS never set
    #[test]
    fn s5_sequence() {
        let mut hw = FakeChipset::new(LPT);
        hw.setw(
            LPT.pm1a_cnt,
            SCI_EN | GBL_RLS | (1 << 1) | (5 << SLP_TYP_SHIFT),
        );
        hw.setw(LPT.pm1a_evt, WAK_STS);
        for i in 0..LPT.gpe0_len as u16 {
            hw.ports[(LPT.gpe0 + i) as usize] = 0xff;
        }
        enter_s5(&mut hw, &LPT, S5);
        let keep = SCI_EN | (1 << 1);
        let typ = 7 << SLP_TYP_SHIFT;
        assert_eq!(
            hw.writes_to(LPT.pm1a_cnt),
            [keep | typ, keep | typ | SLP_EN]
        );
        // WAK_STS written 1 (cleared) before PM1 control
        let first_cnt = hw.writes.iter().position(|w| w.0 == LPT.pm1a_cnt).unwrap();
        let wak = hw
            .writes
            .iter()
            .position(|w| w.0 == LPT.pm1a_evt && w.1 & WAK_STS != 0);
        assert!(wak.is_some_and(|i| i < first_cnt), "{:x?}", hw.writes);
        // GPE0 enable half zeroed before PM1 control
        let half = LPT.gpe0_len as u16 / 2;
        for i in half..2 * half {
            assert_eq!(hw.ports[(LPT.gpe0 + i) as usize], 0, "GPE0_EN byte {i}");
            let at = hw.writes.iter().position(|w| w.0 == LPT.gpe0 + i);
            assert!(
                at.is_some_and(|a| a < first_cnt),
                "GPE0_EN byte {i} not written first"
            );
        }
    }

    /// PM1b gets SLP_TYPb, with the same split writes
    #[test]
    fn s5_pm1b() {
        let regs = PmRegs {
            pm1b_cnt: 0x504,
            ..LPT
        };
        let mut hw = FakeChipset::new(regs);
        hw.setw(regs.pm1a_cnt, SCI_EN);
        enter_s5(&mut hw, &regs, SleepType { a: 7, b: 3 });
        let b = 3 << SLP_TYP_SHIFT;
        assert_eq!(hw.writes_to(0x504), [SCI_EN | b, SCI_EN | b | SLP_EN]);
    }

    /// The retry sets SLP_EN again with SLP_TYP kept
    #[test]
    fn s5_retry() {
        let mut hw = FakeChipset::new(LPT);
        hw.setw(LPT.pm1a_cnt, SCI_EN);
        sleep_retry(&mut hw, &LPT, S5);
        assert_eq!(
            hw.writes_to(LPT.pm1a_cnt),
            [SCI_EN | 7 << SLP_TYP_SHIFT | SLP_EN]
        );
    }

    /// Fixed events and GPEs disabled, their status cleared
    #[test]
    fn events_disabled() {
        let mut hw = FakeChipset::new(LPT);
        hw.ports.fill(0xff);
        disable_events(&mut hw, &LPT);
        assert_eq!(hw.writes_to(LPT.pm1a_evt + 2), [0]);
        assert_eq!(hw.writes_to(LPT.pm1a_evt), [0xc731 & !(1 << 11)]);
        let half = LPT.gpe0_len as u16 / 2;
        for i in 0..half {
            assert_eq!(hw.writes_to(LPT.gpe0 + i), [0xff], "GPE0_STS byte {i}");
            assert_eq!(hw.writes_to(LPT.gpe0 + half + i), [0], "GPE0_EN byte {i}");
        }
    }
}
