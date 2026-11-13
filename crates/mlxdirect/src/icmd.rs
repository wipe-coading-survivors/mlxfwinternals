// Источник: mstflint mtcr_ul/mtcr_ul_icmd_cif.c (icmd_init_cr:1047,1090-1098 —
// CX5(525)/BF(529) → semaphore_addr=SEMAPHORE_ADDR_CX5=0xe74e0 (:84),
// HW_ID_ADDR=0xf0014 (:297), read_device_id — mtcr_ul_com.c:5456-5474;
// icmd_take_semaphore_com:708-777 — BAR0-GW путь (is_gw_access=1,
// mtcr_ul.c:275-281; functional_vsec_supp=0 → expected_read_val=0, :788-799):
// читать семафор до 0, весь дворд — семафор (:275-276), >256 попыток →
// ME_ICMD_STATUS_SEMAPHORE_TO (:714-719), между попытками msleep(rand()%50) —
// ОПУЩЕНО: бюджет поллов вместо сна, прецедент mailbox.rs (MAX_GO_POLLS);
// icmd_clear_semaphore_com:627-657 — release = запись 0 (:653);
// icmd_send_command_com:814-905 — per-op: take → обмен → cleanup- release на
// ВСЕХ путях, вкл. ошибки ((void)icmd_clear_semaphore, :903-905); отклонение:
// при Ok(op)+сбое release возвращаем Err (mstflint игнорирует сбой release)).
// Наш живой эталон per-op-семафора и set_itrace-обмена —
// crates/mlxscope/src/trace/vsec.rs (VsecDev::sem_take/sem_release).

use crate::err::{Error, Result};
use crate::mtcr::Mtc;

/// Адрес CR-space семафора ICMD для CX5/BF (SEMAPHORE_ADDR_CX5).
const SEMAPHORE_ADDR_CX5: u32 = 0xe74e0;
/// HW_ID_ADDR (icmd_init_cr / read_device_id).
const HW_ID_ADDR: u32 = 0xf0014;
const CX5_HW_ID: u32 = 525;
const BF_HW_ID: u32 = 529;

/// Бюджет попыток take: mstflint (++retries > 256 → ME_ICMD_STATUS_SEMAPHORE_TO).
pub const MAX_SEM_ATTEMPTS: usize = 256;

/// ICMD-клиент поверх Mtc: per-op CR-семафор (take/release вокруг каждой
/// операции, НЕ на время жизни) + extension-точка для протоколов обмена
/// (Task 6: set_itrace из crates/mlxscope vsec.rs адаптируется через
/// run_exclusive — take → vsec-обмен → release).
pub struct Icmd<'a> {
    mtc: Mtc<'a>,
    semaphore_addr: u32,
}

impl<'a> Icmd<'a> {
    /// Discovery по icmd_init_cr: hw_id @ 0xf0014 (BE-дворд) & 0xffff;
    /// CX5/BF → семафор 0xe74e0; чужие id → Err(Unsupported).
    pub fn from_mtc(mtc: Mtc<'a>) -> Result<Self> {
        let hw_id = mtc.read_dword(HW_ID_ADDR)? & 0xffff;
        match hw_id {
            CX5_HW_ID | BF_HW_ID => Ok(Icmd {
                mtc,
                semaphore_addr: SEMAPHORE_ADDR_CX5,
            }),
            other => Err(Error::Unsupported(format!(
                "hw_id {other:#x} не семейство CX5/BF (нет адреса ICMD-семафора)"
            ))),
        }
    }

    /// Адрес CR-семафора (SEMAPHORE_ADDR_CX5 для CX5/BF).
    pub fn semaphore_addr(&self) -> u32 {
        self.semaphore_addr
    }

    /// Mtc-доступ для протокола обмена (extension-точка).
    pub fn mtc(&self) -> &Mtc<'a> {
        &self.mtc
    }

    /// Захват CR-семафора, BAR0-GW семантика mstflint: читать дворд семафора
    /// до значения 0 (чтение нуля = захват, gw-доступ — весь дворд); бюджет
    /// MAX_SEM_ATTEMPTS, исчерпан → Err(SemaphoreTimeout).
    pub fn take_semaphore(&self) -> Result<()> {
        for _ in 0..MAX_SEM_ATTEMPTS {
            let v = self.mtc.read_dword(self.semaphore_addr)?;
            if v == 0 {
                return Ok(());
            }
        }
        log::warn!(
            "ICMD-семафор не освободился за {MAX_SEM_ATTEMPTS} попыток (addr={:#x})",
            self.semaphore_addr
        );
        Err(Error::SemaphoreTimeout(MAX_SEM_ATTEMPTS))
    }

    /// Освобождение CR-семафора: запись 0 (icmd_clear_semaphore_com).
    pub fn release_semaphore(&self) -> Result<()> {
        self.mtc.write_dword(self.semaphore_addr, 0)
    }

    /// Операция под семафором: take → op(mtc) → release на ВСЕХ путях
    /// (включая ошибки op — mstflint cleanup, Review Focus 5). При ошибке op
    /// возвращается она (сбой release логируется, как (void) в mstflint);
    /// при успехе op и сбое release — Err(release).
    pub fn run_exclusive<T>(&self, op: impl FnOnce(&Mtc<'a>) -> Result<T>) -> Result<T> {
        self.take_semaphore()?;
        let res = op(&self.mtc);
        let rel = self.release_semaphore();
        match (res, rel) {
            (Ok(v), Ok(())) => Ok(v),
            (Err(e), rel_res) => {
                if rel_res.is_err() {
                    log::error!(
                        "release ICMD-семафора сбой после ошибки операции: {e} (карта может остаться захваченной)"
                    );
                }
                Err(e)
            }
            (Ok(_), Err(e)) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;
    use crate::err::{Error, Result};
    use crate::mailbox::Transport;
    use crate::mtcr::{AddressSpace, Mtc};

    const SEM_ADDR: usize = 0xe74e0;
    const HW_ID_ADDR: usize = 0xf0014;

    /// Мок CR-space (raw u32 = LE-load провода; Mtc поверх даст BE-дворды):
    /// raw-слово 0x0d02_0000 по 0xf0014 == hw_id CX5 (525).
    struct MockCr {
        mem: RefCell<Vec<u32>>,
        reads_at: Cell<usize>,
        watch: Cell<usize>,
        fail_write_at: Cell<Option<usize>>,
    }

    impl MockCr {
        fn new_cx5() -> Self {
            let m = MockCr {
                mem: RefCell::new(vec![0u32; 0xf0018 / 4]),
                reads_at: Cell::new(0),
                watch: Cell::new(usize::MAX),
                fail_write_at: Cell::new(None),
            };
            m.set_raw(HW_ID_ADDR, 0x0d02_0000);
            m
        }

        fn new_hw(raw_hw_id: u32) -> Self {
            let m = MockCr {
                mem: RefCell::new(vec![0u32; 0xf0018 / 4]),
                reads_at: Cell::new(0),
                watch: Cell::new(usize::MAX),
                fail_write_at: Cell::new(None),
            };
            m.set_raw(HW_ID_ADDR, raw_hw_id);
            m
        }

        fn raw(&self, off: usize) -> u32 {
            self.mem.borrow()[off / 4]
        }

        fn set_raw(&self, off: usize, v: u32) {
            self.mem.borrow_mut()[off / 4] = v;
        }

        /// Сырое слово, дающее BE-значение v (провод BE).
        fn set_be(&self, off: usize, v: u32) {
            self.set_raw(off, v.swap_bytes());
        }
    }

    impl Transport for MockCr {
        fn read32(&self, off: usize) -> Result<u32> {
            if off == self.watch.get() {
                self.reads_at.set(self.reads_at.get() + 1);
            }
            Ok(self.raw(off))
        }

        fn write32(&self, off: usize, v: u32) -> Result<()> {
            if self.fail_write_at.get() == Some(off) {
                return Err(Error::Io(format!("mock: scripted fail write32 @ {off:#x}")));
            }
            self.set_raw(off, v);
            Ok(())
        }
    }

    fn icmd<'a>(t: &'a MockCr) -> Icmd<'a> {
        Icmd::from_mtc(Mtc::from_transport(t)).unwrap()
    }

    #[test]
    fn from_mtc_accepts_cx5_and_bf_and_pins_cx5_semaphore_addr() {
        // icmd_init_cr (mtcr_ul_icmd_cif.c:1090-1098): CX5(525)/BF(529) →
        // SEMAPHORE_ADDR_CX5 = 0xe74e0 (:84).
        let cx5 = MockCr::new_cx5();
        assert_eq!(icmd(&cx5).semaphore_addr(), 0xe74e0);
        let bf = MockCr::new_hw(529u32.swap_bytes());
        assert_eq!(icmd(&bf).semaphore_addr(), 0xe74e0);
    }

    #[test]
    fn from_mtc_rejects_foreign_hw_id() {
        // Скоуп крейта — CX5/BF (как session::discover_icmd); CX4LX(523) и
        // мусорный id → Unsupported.
        let cx4lx = MockCr::new_hw(523u32.swap_bytes());
        assert!(matches!(
            Icmd::from_mtc(Mtc::from_transport(&cx4lx)),
            Err(Error::Unsupported(_))
        ));
        let junk = MockCr::new_hw(0xdead_beef);
        assert!(matches!(
            Icmd::from_mtc(Mtc::from_transport(&junk)),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn take_semaphore_succeeds_when_free() {
        // BAR0-GW путь (is_gw_access=1, functional_vsec_supp=0 → expected=0):
        // чтение семафора == 0 ⇒ захвачен, семафор — весь дворд.
        let mock = MockCr::new_cx5();
        let ic = icmd(&mock);
        mock.set_be(SEM_ADDR, 0);
        ic.take_semaphore().unwrap();
    }

    #[test]
    fn take_semaphore_busy_bounded_retry_then_error() {
        // icmd_take_semaphore_com (mtcr_ul_icmd_cif.c:714-719): >256 попыток →
        // ME_ICMD_STATUS_SEMAPHORE_TO; assert — ровно 256 чтений (бюджет
        // ограничен), затем семафор освобождён ⇒ take успешен.
        let mock = MockCr::new_cx5();
        let ic = icmd(&mock);
        mock.watch.set(SEM_ADDR);
        mock.set_be(SEM_ADDR, 0xffff_ffff);
        assert!(matches!(
            ic.take_semaphore(),
            Err(Error::SemaphoreTimeout(n)) if n == 256
        ));
        assert_eq!(mock.reads_at.get(), 256, "бюджет поллов ограничен (256)");
        mock.set_be(SEM_ADDR, 0);
        ic.take_semaphore().unwrap();
    }

    #[test]
    fn release_semaphore_writes_zero() {
        // icmd_clear_semaphore_com (mtcr_ul_icmd_cif.c:653): запись 0.
        let mock = MockCr::new_cx5();
        let ic = icmd(&mock);
        mock.set_be(SEM_ADDR, 0x1234_5678);
        ic.release_semaphore().unwrap();
        assert_eq!(mock.raw(SEM_ADDR), 0);
    }

    #[test]
    fn run_exclusive_passes_mtc_and_releases_on_success() {
        let mock = MockCr::new_cx5();
        let ic = icmd(&mock);
        let hw_id = ic
            .run_exclusive(|m| m.read_dword(HW_ID_ADDR as u32))
            .unwrap();
        assert_eq!(hw_id, 525);
        assert_eq!(
            mock.raw(SEM_ADDR),
            0,
            "semaфор освобождён после Ok-операции"
        );
        ic.take_semaphore().unwrap();
    }

    #[test]
    fn run_exclusive_releases_semaphore_on_op_error() {
        // Review Focus 5: сбой обмена под семафором → семафор ОБЯЗАН быть
        // освобождён (mstflint cleanup, mtcr_ul_icmd_cif.c:903-905), иначе
        // карта wedged для mstreg. После ошибки — повторный take успешен.
        let mock = MockCr::new_cx5();
        let ic = icmd(&mock);
        mock.fail_write_at.set(Some(0x100));
        let err = ic.run_exclusive(|m| {
            m.write_dword(0x100, 0x1)?; // обмен падает
            Ok(())
        });
        assert!(matches!(err, Err(Error::Io(_))), "ошибка op прокинута");
        assert_eq!(mock.raw(SEM_ADDR), 0, "semaфор освобождён на error-пути");
        ic.take_semaphore().unwrap();
    }

    #[test]
    fn run_exclusive_does_not_run_op_when_take_fails() {
        let mock = MockCr::new_cx5();
        let ic = icmd(&mock);
        mock.set_be(SEM_ADDR, 0xffff_ffff);
        let ran = Cell::new(false);
        let r: Result<()> = ic.run_exclusive(|_| {
            ran.set(true);
            Ok(())
        });
        assert!(matches!(r, Err(Error::SemaphoreTimeout(_))));
        assert!(!ran.get(), "op не выполняется без семафора");
    }

    #[test]
    fn change_address_space_via_mtc_of_icmd_follows_bar0_semantics() {
        let mock = MockCr::new_cx5();
        let ic = icmd(&mock);
        ic.mtc()
            .change_address_space(AddressSpace::CrSpace)
            .unwrap();
        assert!(matches!(
            ic.mtc().change_address_space(AddressSpace::Icmd),
            Err(Error::Unsupported(_))
        ));
    }
}
