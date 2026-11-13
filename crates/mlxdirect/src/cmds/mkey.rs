// Источник: ConnectX PRM (адаптация в ядре Linux — refs/src/linux/linux-7.2/
// include/linux/mlx5/mlx5_ifc.h: mlx5_ifc_create_mkey_in_bits — opcode 0x0200,
// pg_access@0x0c.0, mkey_umem_valid@0x0c.1, mkc@0x10 (64 B),
// translations_octword_actual_size@0x60, klm_pas_mtt[]@0x110 (BE u64, 8B
// stride); mlx5_ifc_mkc_bits — dword0: free@1, umr_en..lr@0x10-0x1c
// (byte2: umr_en 0x80, a 0x40, rw 0x20, rr 0x10, lw 0x08, lr 0x04),
// access_mode_1_0@0x16-0x18 (мл. 2 бита byte2; MTT=1 — MLX5_MKC_ACCESS_MODE_MTT),
// qpn@+4 (24 бита), mkey_7_0@+7, length64@0x0c.0, pd@0x0d (24 бита),
// start_addr@0x10, len@0x18, bsf_octword_size@0x20,
// translations_octword_size@0x34, log_page_size@0x3b (мл. 6 бит; в mtrcdump-
// парити именуем log_entry_size); MLX5_MKC_ACCESS_MODE_MTT=1 (mlx5_ifc.h:4509).
// Wire-факты фикстр Task 1 (testdata/wire/alloc-pd-mkey.txt): TX 304 B для
// 4 страниц (lw|lr|MTT → byte2=0x0d), mtt-страницы 0x10a2e000..0x10a31000,
// RX payload mkey_index=0x40 @ [1..4].

use deku::{DekuContainerWrite, DekuUpdate, DekuWrite};

use crate::cmds::Command;
use crate::cmds::be24_at;
use crate::err::deku_err;

#[derive(deku::DekuWrite)]
#[deku(type = "u8", bits = "2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    #[deku(id = "1")]
    MTT,
}

/// Memory Key Context (PRM mkc, 64 байта). Порядок декларации — MSB-first
/// (как битовый обход mlx5_ifc.h); зарезервированные промежутки — deku-пады;
/// много byte-поля — endian big per-field (контейнерный endian в deku 0.16
/// ломит ctx вложенных структур).
#[derive(deku::DekuWrite, Debug, Clone, PartialEq, Eq)]
pub struct MKeyContext {
    #[deku(pad_bits_before = "1")]
    #[deku(bits = "1")]
    pub free: bool,
    #[deku(pad_bits_before = "14")]
    #[deku(bits = "1")]
    pub umr_en: bool,
    #[deku(bits = "1")]
    pub a: bool,
    #[deku(bits = "1")]
    pub rw: bool,
    #[deku(bits = "1")]
    pub rr: bool,
    #[deku(bits = "1")]
    pub lw: bool,
    #[deku(bits = "1")]
    pub lr: bool,
    pub access_mode: AccessMode,
    #[deku(pad_bits_before = "8", bits = "24", endian = "big")]
    pub qpn: u32,
    pub mkey: u8,
    #[deku(pad_bits_before = "32")]
    #[deku(bits = "1")]
    pub length64: bool,
    #[deku(pad_bits_before = "7", bits = "24", endian = "big")]
    pub pd: u32,
    #[deku(endian = "big")]
    pub start_addr: u64,
    #[deku(endian = "big")]
    pub len: u64,
    #[deku(endian = "big")]
    pub bsf_octword_size: u32,
    #[deku(pad_bits_before = "128", endian = "big")]
    pub translation_octword_size: u32,
    #[deku(
        pad_bits_before = "26",
        bits = "6",
        pad_bits_after = "32",
        endian = "big"
    )]
    pub log_entry_size: u8,
}

/// CREATE_MKEY (0x0200): кадр = opcode (2 байта, пишет encode) + заголовок
/// 80 бит (uid/reserved/op_mod/reserved) + флаги + mkc + actual_size +
/// пад 1376 бит + MTT-страницы BE u64.
#[derive(deku::DekuWrite, Debug, Clone, PartialEq, Eq)]
pub struct CreateMKey {
    #[deku(pad_bits_before = "80")]
    #[deku(bits = "1")]
    pub pg_access: bool,
    #[deku(bits = "1")]
    pub umem_valid: bool,
    #[deku(pad_bits_before = "30")]
    pub context: MKeyContext,
    #[deku(pad_bits_before = "128", endian = "big")]
    pub translation_octwords_actual_size: u32,
    #[deku(pad_bits_before = "1376", endian = "big")]
    pub translation_entries: Vec<u64>,
}

/// Выход CREATE_MKEY: out-тело с payload+0 — reserved(8 бит) + mkey_index
/// (24 бита BE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateMKeyOutput {
    pub mkey_index: u32,
}

impl Command for CreateMKey {
    type Output = CreateMKeyOutput;
    const OPCODE: u16 = 0x0200;

    fn outlen(&self) -> usize {
        16
    }

    fn encode(&self, buf: &mut Vec<u8>) -> crate::err::Result<()> {
        buf.extend_from_slice(&Self::OPCODE.to_be_bytes());
        let bytes = self.to_bytes().map_err(deku_err)?;
        buf.extend_from_slice(&bytes);
        Ok(())
    }

    fn decode(payload: &[u8]) -> crate::err::Result<Self::Output> {
        Ok(CreateMKeyOutput {
            mkey_index: be24_at(payload, 1)?,
        })
    }
}
