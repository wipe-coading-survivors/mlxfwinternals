// Источник: реестры ACCESS_REGISTER — mstflint tools_layouts (см. mtrc.rs);
// идентификаторы реестров — register_access_table.adb (enum MTRC_*).

pub mod mtrc;

use crate::err::Result;

/// Реестр ACCESS_REGISTER: идентификатор (register_access_table.adb) +
/// кодирование/декодирование данных регистра (без 16-байтового заголовка
/// команды — его строит Direct::write_register).
pub trait Register: Sized {
    const REGISTER_ID: u16;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<()>;
    fn decode(data: &[u8]) -> Result<Self>;
}
