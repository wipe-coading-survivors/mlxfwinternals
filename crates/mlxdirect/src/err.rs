// Источник: mstflint cmdif/icmd_cif_common.h (enum GCIF_STATUS_*),
// mtcr_ul/mtcr_ul_icmd_cif.c (translate_status: 0x5 = busy; ME_ICMD_* коды),
// cmdif/icmd_cif_macros.h (SEND_ICMD_FLOW: rc → convert_rc).

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Маппинг ошибок deku (кодирование/декодирование команд и регистров).
pub(crate) fn deku_err(e: deku::DekuError) -> Error {
    Error::Io(format!("deku: {e}"))
}

/// Негативная комплитка icmd-команды: статус-байт + syndrome (BE из out[4..8]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmdStatusErr {
    pub status: u8,
    pub syndrome: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("icmd command failed: status={} syndrome=0x{:08x}", .0.status, .0.syndrome)]
    Command(CmdStatusErr),
    #[error("command timeout: no completion within poll budget")]
    Timeout,
    #[error("icmd busy: go bit already set before command")]
    Busy,
    #[error("cr-space semaphore busy: not free within {0} attempts")]
    SemaphoreTimeout(usize),
    #[error("icmd mailbox size violation: {0}")]
    Size(String),
    #[error("device or icmd unsupported: {0}")]
    Unsupported(String),
    #[error("vfio transport error: {0}")]
    Io(String),
}
