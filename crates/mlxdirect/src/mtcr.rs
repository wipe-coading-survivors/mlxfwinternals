// Источник: mstflint mtcr_ul/mtcr_ul_com.c (mtcr_pcicr_mread4/mwrite4:643-702 —
// CR-space дворды big-endian на проводе, __be32_to_cpu/__cpu_to_be32;
// VSEC-офсеты и домены:769-797), include/mtcr_ul/mtcr_com_defs.h
// (address_space_t:377-395 — AS_CR_SPACE=0x2, AS_ICMD=0x3, AS_SEMAPHORE=0xa),
// mtcr_ul/mtcr_ul.c (mset_addr_space:289-302 — переключение пространств только
// для functional-VSEC транспорта; VSEC_SUPPORTED_UL — mtcr_com_defs.h:599).
// Наш живой эталон config-space VSEC-флейвора — crates/mlxscope/src/trace/vsec.rs
// (VsecDev: sem_take/change_address_space/read_dword/write_dword; там провод
// raw-LE — READ4_PCI mtcr_ul_com.c:799-830; наш транспорт — BAR0/pcicr, поэтому
// здесь BE-семантика mtcr_pcicr_*, а не raw pciconf).

use crate::err::Result;
use crate::mailbox::Transport;
use crate::session::Direct;

/// Адресные пространства VSEC-шлюза mtcr (mtcr_com_defs.h:377-395). Для
/// BAR0-транспорта реально доступен только CrSpace: на CX5 ICMD-мейнлбокс
/// (окно cmd_ptr) и CR-семафор (0xe74e0) лежат внутри самого CR-space.
/// Примечание (fix round 8): вариант NodnicInitSeg (0x4) из fix round 6
/// удалён — 0.4-view опровергнута живой попыткой 10 (не iseg-зеркало,
/// журнал task-07 §A10-2); мёртвое знание для этой карты не держим.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpace {
    /// AS_CR_SPACE = 0x2 — нативное пространство BAR0.
    CrSpace,
    /// AS_ICMD = 0x3 — только через functional-VSEC шлюз.
    Icmd,
    /// AS_SEMAPHORE = 0xa — только через functional-VSEC шлюз.
    Semaphore,
}

impl AddressSpace {
    /// Числовое значение по mstflint (address_space_t).
    pub fn raw(self) -> u16 {
        match self {
            AddressSpace::CrSpace => 0x2,
            AddressSpace::Icmd => 0x3,
            AddressSpace::Semaphore => 0xa,
        }
    }
}

/// Доступ к CR-space по дворям поверх транспорта сессии (mread4/mwrite4
/// mstflint, семантика pcicr/BAR0: значение = BE-нагрузка 4 байтов провода).
pub struct Mtc<'a> {
    t: &'a dyn Transport,
}

impl<'a> Mtc<'a> {
    /// Из прямой VFIO-сессии: BAR0-окно сессии и есть CR-space.
    pub fn from_direct(direct: &'a Direct) -> Result<Self> {
        Ok(Self::from_transport(direct.transport()))
    }

    /// Поверх произвольного транспорта (моки в тестах).
    pub(crate) fn from_transport(t: &'a dyn Transport) -> Self {
        Mtc { t }
    }

    /// Переключение адресного пространства: делегируется транспорту
    /// (functional-VSEC шлюз — mtcr_pciconf_set_addr_space; дефолт трейта —
    /// BAR0-семантика: CrSpace нативен, остальные Unsupported, как
    /// mset_addr_space для транспорта без functional-VSEC, mtcr_ul.c:289-302).
    pub fn change_address_space(&self, as_: AddressSpace) -> Result<()> {
        self.t.set_address_space(as_.raw())
    }

    /// Чтение DWORD: mtcr_pcicr_mread4 (mtcr_ul_com.c:643-679) — сырой дворд
    /// транспорта (LE-нагрузка провода) → BE-значение (__be32_to_cpu).
    pub fn read_dword(&self, addr: u32) -> Result<u32> {
        Ok(self.t.read32(addr as usize)?.swap_bytes())
    }

    /// Запись DWORD: mtcr_pcicr_mwrite4 (mtcr_ul_com.c:681-702) — значение →
    /// BE-байты на проводе (__cpu_to_be32 перед raw-store).
    pub fn write_dword(&self, addr: u32, v: u32) -> Result<()> {
        self.t.write32(addr as usize, v.swap_bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;
    use crate::err::Error;
    use crate::mailbox::Transport;

    /// Мок CR-space: сырой u32-массив (слово транспорта = LE-load 4 байтов
    /// провода, как VfioTransport), счётчик чтений по адресу, сценарный
    /// отказ записи по адресу.
    struct MockCr {
        mem: RefCell<Vec<u32>>,
        reads_at: Cell<usize>,
        watch: usize,
        fail_write_at: Cell<Option<usize>>,
    }

    impl MockCr {
        fn new() -> Self {
            MockCr {
                mem: RefCell::new(vec![0u32; 0xf0018 / 4]),
                reads_at: Cell::new(0),
                watch: usize::MAX,
                fail_write_at: Cell::new(None),
            }
        }

        fn raw(&self, off: usize) -> u32 {
            self.mem.borrow()[off / 4]
        }

        fn set_raw(&self, off: usize, v: u32) {
            self.mem.borrow_mut()[off / 4] = v;
        }
    }

    impl Transport for MockCr {
        fn read32(&self, off: usize) -> crate::err::Result<u32> {
            if off == self.watch {
                self.reads_at.set(self.reads_at.get() + 1);
            }
            Ok(self.raw(off))
        }

        fn write32(&self, off: usize, v: u32) -> crate::err::Result<()> {
            if self.fail_write_at.get() == Some(off) {
                return Err(Error::Io(format!("mock: scripted fail write32 @ {off:#x}")));
            }
            self.set_raw(off, v);
            Ok(())
        }
    }

    fn mtc<'a>(t: &'a dyn Transport) -> Mtc<'a> {
        Mtc::from_transport(t)
    }

    #[test]
    fn write_dword_puts_big_endian_word_on_wire() {
        // mtcr_pcicr_mwrite4 (mtcr_ul_com.c:681-702): __cpu_to_be32 перед
        // raw-store — на проводе BE-дворд: значение 0x9001_0000 → сырой
        // (LE-load) дворд 0x0000_0190.
        let mock = MockCr::new();
        mtc(&mock).write_dword(0x10, 0x9001_0000).unwrap();
        assert_eq!(mock.raw(0x10), 0x0000_0190);
        mtc(&mock).write_dword(0x14, 0xaabb_ccdd).unwrap();
        assert_eq!(mock.raw(0x14), 0xddcc_bbaa);
    }

    #[test]
    fn read_dword_returns_big_endian_interpretation() {
        // mtcr_pcicr_mread4 (mtcr_ul_com.c:643-679): __be32_to_cpu от raw.
        // hw_id CX5 (read_device_id, mtcr_ul_com.c:5456-5474): значение 525
        // → на проводе сырой дворд 0x0d02_0000.
        let mock = MockCr::new();
        mock.set_raw(0xf0014, 0x0d02_0000);
        assert_eq!(mtc(&mock).read_dword(0xf0014).unwrap(), 525);
        mock.set_raw(0x0, 0x0000_0190);
        assert_eq!(mtc(&mock).read_dword(0x0).unwrap(), 0x9001_0000);
    }

    #[test]
    fn dword_roundtrip_through_mock() {
        let mock = MockCr::new();
        for v in [0u32, 1, 525, 0x9001_0000, 0xaabb_ccdd, u32::MAX] {
            mtc(&mock).write_dword(0x20, v).unwrap();
            assert_eq!(mtc(&mock).read_dword(0x20).unwrap(), v, "v={v:#x}");
        }
    }

    #[test]
    fn transport_errors_propagate_from_dword_ops() {
        let mock = MockCr::new();
        mock.fail_write_at.set(Some(0x20));
        assert!(matches!(mtc(&mock).write_dword(0x20, 1), Err(Error::Io(_))));
    }

    #[test]
    fn bar0_transport_cannot_leave_cr_space() {
        // mset_addr_space (mtcr_ul.c:289-302) требует functional-VSEC; для
        // BAR0-транспорта переключения нет — CR-space нативен, остальные
        // unsupported.
        let mock = MockCr::new();
        let m = mtc(&mock);
        m.change_address_space(AddressSpace::CrSpace).unwrap();
        assert!(matches!(
            m.change_address_space(AddressSpace::Icmd),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            m.change_address_space(AddressSpace::Semaphore),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn address_space_raw_values_match_mstflint() {
        // include/mtcr_ul/mtcr_com_defs.h:379-385:
        // AS_CR_SPACE=0x2, AS_ICMD=0x3, AS_SEMAPHORE=0xa.
        assert_eq!(AddressSpace::CrSpace.raw(), 0x2);
        assert_eq!(AddressSpace::Icmd.raw(), 0x3);
        assert_eq!(AddressSpace::Semaphore.raw(), 0xa);
    }
}
