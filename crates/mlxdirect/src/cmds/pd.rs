// Источник: ConnectX PRM (адаптация в ядре Linux — refs/src/linux/linux-7.2/
// include/linux/mlx5/mlx5_ifc.h: mlx5_ifc_alloc_pd_in/out_bits — opcode
// 0x0800, вход 16 байт (заголовок), out-тело reserved_at_40[8]+pd[24] с
// офсета 0x8 out-кадра); wire-факты фикстр Task 1
// (testdata/wire/alloc-pd-mkey.txt: TX 16 B, RX payload pd=0x10 @ [1..4]).

use crate::cmds::Command;
use crate::cmds::be24_at;
use crate::err::Result;

pub struct AllocPD;

impl Command for AllocPD {
    type Output = AllocPdOutput;
    const OPCODE: u16 = 0x0800;

    fn outlen(&self) -> usize {
        16
    }

    fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        buf.extend_from_slice(&Self::OPCODE.to_be_bytes());
        buf.extend_from_slice(&[0u8; 14]);
        Ok(())
    }

    fn decode(payload: &[u8]) -> Result<Self::Output> {
        Ok(AllocPdOutput {
            pd: be24_at(payload, 1)?,
        })
    }
}

/// Выход ALLOC_PD: out-тело с payload+0 — reserved(8 бит) + pd (24 бита BE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocPdOutput {
    pub pd: u32,
}
