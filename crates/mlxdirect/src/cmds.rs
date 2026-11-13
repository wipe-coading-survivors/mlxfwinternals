// Источник: NIC-команды CREATE_MKEY/ALLOC_PD — PRM-макеты (см. mkey.rs /
// pd.rs); кадрирование мейнлбокса — Task 2 (mailbox.rs: opcode в кадре @0..2).

pub mod mkey;
pub mod pd;

use crate::err::{Error, Result};

/// Команда мейнлбокса: opcode (mailbox-кадр начинается с него), размер
/// out-буфера обмена и кодирование/декодирование (payload = out с офсета 8;
/// статус≠0 мапится Task-2 путём в exec_command — decode получает только
/// успешные payload).
pub trait Command {
    type Output;
    const OPCODE: u16;
    fn outlen(&self) -> usize;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<()>;
    fn decode(payload: &[u8]) -> Result<Self::Output>;
}

/// 24-битное BE-поле с байтового офсета (pd / mkey_index в out-телах).
pub(crate) fn be24_at(buf: &[u8], off: usize) -> Result<u32> {
    let b = buf.get(off..off + 3).ok_or_else(|| {
        Error::Size(format!(
            "payload короче 24-битного поля @{off}: {}",
            buf.len()
        ))
    })?;
    Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
}

#[cfg(test)]
mod tests {
    use super::mkey::{AccessMode, CreateMKey, MKeyContext};
    use super::pd::AllocPD;
    use crate::cmds::Command;
    use crate::wiretest::{block, parse_wire};

    const FIX: &str = include_str!("../testdata/wire/alloc-pd-mkey.txt");

    /// (а) Кодирование CreateMKey (MTT, 4 страницы) байт-в-байт против
    /// TX-фикстуры arm-прогона: поля из NOTE (pd=0x10, mkey=0x42,
    /// len=0x4000, translation_octword_size=2, log_entry_size=12,
    /// mtt_pages), lw/lr/qpn — канон mtrcdump-парити (arm.rs). Review Focus:
    /// тихий мусор в MTT → FW DMA по неверным адресам.
    #[test]
    fn create_mkey_mtt_encode_byte_exact_vs_arm_tx() {
        let blocks = parse_wire(FIX);
        let b = block(&blocks, "CreateMKey (MTT, 4 pages)");
        let cmd = CreateMKey {
            pg_access: false,
            umem_valid: false,
            context: MKeyContext {
                free: false,
                umr_en: false,
                a: false,
                rw: false,
                rr: false,
                lw: true,
                lr: true,
                access_mode: AccessMode::MTT,
                qpn: 0xffffff,
                mkey: 0x42,
                length64: false,
                pd: 0x10,
                start_addr: 0x0000,
                len: 0x4000,
                bsf_octword_size: 0,
                translation_octword_size: 2,
                log_entry_size: 12,
            },
            translation_octwords_actual_size: 2,
            translation_entries: vec![0x10a2e000, 0x10a2f000, 0x10a30000, 0x10a31000],
        };
        let mut frame = Vec::new();
        cmd.encode(&mut frame).unwrap();
        assert_eq!(frame, b.tx, "полный кадр против TX-фикстуры (304 B)");
        assert_eq!(CreateMKey::OPCODE, 0x0200);
        assert_eq!(cmd.outlen(), 16);
    }

    /// Output CreateMKey: mkey_index (24 бита BE) с payload+1.
    #[test]
    fn create_mkey_decode_mkey_index_from_rx() {
        let blocks = parse_wire(FIX);
        let b = block(&blocks, "CreateMKey (MTT, 4 pages)");
        let out = CreateMKey::decode(&b.rx[8..]).unwrap();
        assert_eq!(out.mkey_index, 0x40);
    }

    /// (б) AllocPD: кодирование (opcode 0x0800 + нули, 16 B) и decode
    /// pd=N (24 бита BE с payload+1) из RX-фикстуры.
    #[test]
    fn alloc_pd_encode_byte_exact_and_decode_pd() {
        let blocks = parse_wire(FIX);
        let b = block(&blocks, "AllocPD");
        let mut frame = Vec::new();
        AllocPD.encode(&mut frame).unwrap();
        assert_eq!(frame, b.tx);
        assert_eq!(AllocPD::OPCODE, 0x0800);
        assert_eq!(AllocPD.outlen(), 16);
        let out = AllocPD::decode(&b.rx[8..]).unwrap();
        assert_eq!(out.pd, 0x10);
    }
}
