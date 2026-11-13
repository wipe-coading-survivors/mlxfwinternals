// Источник битов: mstflint tools_layouts/reg_access_hca_layouts.h
// (reg_access_hca_mtrc_cap_reg_ext / mtrc_conf_reg_ext / mtrc_ctrl_reg_ext /
// string_db_parameters_ext) + adb-таблица tools_layouts/adb/prm/hca/ext/
// register_access_table.adb (enum MTRC_CAP=0x9040, MTRC_CONF=0x9041,
// MTRC_STDB=0x9042, MTRC_CTRL=0x9043). Нумерация битов adb «0xB.L» — LSB-
// нумерация BE-дворда (бит 31 = MSB byte0; бит 0 = LSB byte3), выверено по
// TX-фикстрам: trace_owner «0x0.31» → byte0=0x80; modify_field_select
// «0x0.0-0x0.16» → byte3=0x01; arm_event «0x0.27» → byte0=0x08; trace_status
// «0x0.30-0x0.32» → byte0&0x03. Wire-факты фикстр Task 1
// (testdata/wire/mtrc-set.txt, arm-прогон): TX-спан полей cap 0x50 / conf
// 0x0c / ctrl 0x10 (PRM-хвосты 0x84/0x80/0x40 не пишутся).

use deku::{DekuContainerRead, DekuContainerWrite, DekuUpdate, DekuWrite};

use crate::err::deku_err;
use crate::regs::Register;

/// Параметры секции strings DB (string_db_parameters_ext: base u32 @0,
/// size 24 бита @4, пад 8 бит). deku — MSB-first: base первым (старший
/// дворда), размер — вторым.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, deku::DekuRead, deku::DekuWrite)]
pub struct StringDbParam {
    #[deku(endian = "big")]
    pub address: u32,
    #[deku(pad_bits_before = "8", endian = "big", bits = "24")]
    pub size: u32,
}

/// MTRC_CAP (0x9040), спан полей 0x50 (PRM-хвост до 0x84 не пишется).
/// Порядок декларации — MSB-first; в скобках LSB-позиции adb: dword0 —
/// trace_owner (31), trace_to_memory (30), trc_ver (24..26), num_string_db
/// (0..4); dword1 — first_string_trace (24..32), num_string_trace (16..24);
/// dword2 — log_max_trace_buffer_size (0..8); string_db_param[8] @0x10.
#[derive(Debug, Clone, Default, PartialEq, Eq, deku::DekuRead, deku::DekuWrite)]
pub struct MtrcCapReg {
    #[deku(bits = "1")]
    pub trace_owner: bool,
    #[deku(bits = "1")]
    pub trace_to_memory: bool,
    #[deku(pad_bits_before = "4", bits = "2")]
    pub trc_ver: u8,
    #[deku(pad_bits_before = "20", bits = "4")]
    pub num_string_db: u8,
    pub first_string_trace: u8,
    pub num_string_trace: u8,
    #[deku(pad_bits_before = "40", bits = "8")]
    pub log_max_trace_buffer_size: u8,
    #[deku(pad_bits_before = "32")]
    pub string_db_param: [StringDbParam; 8],
}

/// MTRC_CONF (0x9041), спан полей 0x0c: dword0 — trace_mode (0..4);
/// dword1 — log_trace_buffer_size (0..8); dword2 — trace_mkey u32.
#[derive(Debug, Clone, Default, PartialEq, Eq, deku::DekuRead, deku::DekuWrite)]
pub struct MtrcConfReg {
    #[deku(pad_bits_before = "28", bits = "4", endian = "big")]
    pub trace_mode: u8,
    #[deku(pad_bits_before = "24", bits = "8", endian = "big")]
    pub log_trace_buffer_size: u8,
    #[deku(endian = "big")]
    pub trace_mkey: u32,
}

/// MTRC_CTRL (0x9043), спан 0x10: dword0 — trace_status (30..32),
/// arm_event (27), modify_field_select (0..16); dword2/3 —
/// current_timestamp_52_32 / current_timestamp_31_0 (timestamp_hi/lo).
#[derive(Debug, Clone, Default, PartialEq, Eq, deku::DekuRead, deku::DekuWrite)]
pub struct MtrcCtrlReg {
    #[deku(bits = "2", pad_bits_after = "2", endian = "big")]
    pub trace_status: u8,
    #[deku(bits = "1")]
    pub arm_event: bool,
    #[deku(pad_bits_before = "11", endian = "big")]
    pub modify_field_select: u16,
    #[deku(pad_bits_before = "32", endian = "big")]
    pub timestamp_hi: u32,
    #[deku(endian = "big")]
    pub timestamp_lo: u32,
}

impl Register for MtrcCapReg {
    const REGISTER_ID: u16 = 0x9040;

    fn encode(&self, buf: &mut Vec<u8>) -> crate::err::Result<()> {
        let bytes = self.to_bytes().map_err(deku_err)?;
        buf.extend_from_slice(&bytes);
        Ok(())
    }

    fn decode(data: &[u8]) -> crate::err::Result<Self> {
        let (_, reg) = Self::from_bytes((data, 0)).map_err(deku_err)?;
        Ok(reg)
    }
}

impl Register for MtrcConfReg {
    const REGISTER_ID: u16 = 0x9041;

    fn encode(&self, buf: &mut Vec<u8>) -> crate::err::Result<()> {
        let bytes = self.to_bytes().map_err(deku_err)?;
        buf.extend_from_slice(&bytes);
        Ok(())
    }

    fn decode(data: &[u8]) -> crate::err::Result<Self> {
        let (_, reg) = Self::from_bytes((data, 0)).map_err(deku_err)?;
        Ok(reg)
    }
}

impl Register for MtrcCtrlReg {
    const REGISTER_ID: u16 = 0x9043;

    fn encode(&self, buf: &mut Vec<u8>) -> crate::err::Result<()> {
        let bytes = self.to_bytes().map_err(deku_err)?;
        buf.extend_from_slice(&bytes);
        Ok(())
    }

    fn decode(data: &[u8]) -> crate::err::Result<Self> {
        let (_, reg) = Self::from_bytes((data, 0)).map_err(deku_err)?;
        Ok(reg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wiretest::{block, parse_wire};

    const FIX: &str = include_str!("../../testdata/wire/mtrc-set.txt");

    /// (в) Кодирование MTRC_CAP SET (trace_owner=1) байт-в-байт против
    /// TX-фикстуры arm-прогона (Review Focus: тихий мусор в битах).
    #[test]
    fn cap_set_encode_byte_exact_vs_arm_tx() {
        let blocks = parse_wire(FIX);
        let b = block(&blocks, "MTRC_CAP SET trace_owner=1 (");
        let reg = MtrcCapReg {
            trace_owner: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        reg.encode(&mut buf).unwrap();
        assert_eq!(buf, &b.tx[16..], "reg-данные против TX-фикстуры");
        assert_eq!(buf.len(), 0x50, "спан полей cap");
        assert_eq!(MtrcCapReg::REGISTER_ID, 0x9040);
    }

    #[test]
    fn cap_default_encodes_to_zero_span() {
        let mut buf = Vec::new();
        MtrcCapReg::default().encode(&mut buf).unwrap();
        assert_eq!(buf, vec![0u8; 0x50]);
    }

    /// Readback cap из RX (данные регистра с payload+8 = rx[16..]):
    /// полный набор полей по NOTE фикстуры (owner=1 вариант).
    #[test]
    fn cap_readback_decode_owner_granted() {
        let blocks = parse_wire(FIX);
        let b = block(&blocks, "MTRC_CAP SET trace_owner=1 (");
        let reg = MtrcCapReg::decode(&b.rx[16..]).unwrap();
        assert!(reg.trace_owner);
        assert!(reg.trace_to_memory);
        assert_eq!(reg.trc_ver, 1);
        assert_eq!(reg.num_string_db, 2);
        assert_eq!(reg.first_string_trace, 0xb0);
        assert_eq!(reg.num_string_trace, 0x0b);
        assert_eq!(reg.log_max_trace_buffer_size, 0x13);
        assert_eq!(reg.string_db_param[0].address, 0x00b4_6180);
        assert_eq!(reg.string_db_param[0].size, 0x4f700);
        assert_eq!(reg.string_db_param[1].address, 0x0103_b200);
        assert_eq!(reg.string_db_param[1].size, 0x3800);
        assert_eq!(reg.string_db_param[2], StringDbParam::default());
    }

    /// DENIED-вариант: readback trace_owner=0 (byte0 0x41 vs 0xc1).
    #[test]
    fn cap_readback_decode_denied_owner_zero() {
        let blocks = parse_wire(FIX);
        let b = block(&blocks, "DENIED variant");
        assert_eq!(b.rx[16], 0x41);
        let reg = MtrcCapReg::decode(&b.rx[16..]).unwrap();
        assert!(!reg.trace_owner);
        assert!(reg.trace_to_memory);
        assert_eq!(reg.log_max_trace_buffer_size, 0x13);
    }

    /// (в) MTRC_CONF SET (mode=1 log=2 mkey=0x4042) байт-в-байт.
    #[test]
    fn conf_set_encode_byte_exact_vs_arm_tx() {
        let blocks = parse_wire(FIX);
        let b = block(&blocks, "MTRC_CONF SET trace_mode=1");
        let reg = MtrcConfReg {
            trace_mode: 1,
            log_trace_buffer_size: 2,
            trace_mkey: 0x4042,
        };
        let mut buf = Vec::new();
        reg.encode(&mut buf).unwrap();
        assert_eq!(buf, &b.tx[16..]);
        assert_eq!(buf.len(), 0x0c, "спан полей conf");
        assert_eq!(MtrcConfReg::REGISTER_ID, 0x9041);
    }

    #[test]
    fn conf_readback_echo_decode() {
        let blocks = parse_wire(FIX);
        let b = block(&blocks, "MTRC_CONF SET trace_mode=1");
        let reg = MtrcConfReg::decode(&b.rx[16..]).unwrap();
        assert_eq!(reg.trace_mode, 1);
        assert_eq!(reg.log_trace_buffer_size, 2);
        assert_eq!(reg.trace_mkey, 0x4042);
    }

    /// (в) MTRC_CTRL SET arm/disarm байт-в-байт (arm_event bit27,
    /// trace_status биты 30-31, modify_field_select биты 0-15).
    #[test]
    fn ctrl_arm_and_disarm_encode_byte_exact_vs_arm_tx() {
        let blocks = parse_wire(FIX);
        let arm = block(&blocks, "MTRC_CTRL SET arm");
        let reg = MtrcCtrlReg {
            trace_status: 1,
            arm_event: true,
            modify_field_select: 1,
            ..Default::default()
        };
        let mut buf = Vec::new();
        reg.encode(&mut buf).unwrap();
        assert_eq!(buf, &arm.tx[16..]);
        assert_eq!(buf.len(), 0x10, "спан полей ctrl");

        let disarm = block(&blocks, "MTRC_CTRL SET disarm");
        let reg = MtrcCtrlReg {
            trace_status: 0,
            arm_event: false,
            modify_field_select: 1,
            ..Default::default()
        };
        let mut buf = Vec::new();
        reg.encode(&mut buf).unwrap();
        assert_eq!(buf, &disarm.tx[16..]);
        assert_eq!(MtrcCtrlReg::REGISTER_ID, 0x9043);
    }

    #[test]
    fn ctrl_readback_decode_arm_and_disarm() {
        let blocks = parse_wire(FIX);
        let arm = block(&blocks, "MTRC_CTRL SET arm");
        let reg = MtrcCtrlReg::decode(&arm.rx[16..]).unwrap();
        assert_eq!(reg.trace_status, 1);
        assert_eq!(reg.modify_field_select, 1);
        assert!(!reg.arm_event, "arm_event WO — в readback 0");
        assert_eq!(reg.timestamp_hi, 0);
        assert_eq!(reg.timestamp_lo, 0x626d_35a4);

        let disarm = block(&blocks, "MTRC_CTRL SET disarm");
        let reg = MtrcCtrlReg::decode(&disarm.rx[16..]).unwrap();
        assert_eq!(reg.trace_status, 0);
        assert_eq!(reg.timestamp_hi, 0x0000_0004);
        assert_eq!(reg.timestamp_lo, 0x147f_577d);
    }
}
