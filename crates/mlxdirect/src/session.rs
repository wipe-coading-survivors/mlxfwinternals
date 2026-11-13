// Источник: mstflint mtcr_ul/mtcr_ul_com.c (functional-VSEC шлюз pciconf:
// mtcr_pciconf_cap9_sem:1476-1512 — ticket-семафор cap+0xc/+0x8, release
// записью 0; mtcr_pciconf_wait_on_flag:1514-1541 — полл бита 31 адресного
// порта, IFC_MAX_RETRIES=2048 (:796), сон 1 мс каждые 16; mtcr_pciconf_
// set_addr_space:1557-1580 — RMW младших 16 бит ctrl-регистра + проверка
// статуса биты 29..32; mtcr_pciconf_rw:1692-1728 — обмен READ: адрес (бит 31
// = 0) → полл флага 1 → чтение данных, WRITE: данные → адрес (бит 31 = 1) →
// полл флага 0; mtcr_pciconf_send_pci_cmd_int:1730-1754 — cap9-семафор
// вокруг каждого обмена), живой канон config-space VSEC —
// crates/mlxscope/src/trace/vsec.rs (VsecDev). pci-driver 0.1.4:
// VfioPciDevice::open / PciDevice::reset (VFIO_DEVICE_RESET) /
// PciDevice::iommu (DMA-окно) / PciDevice::config (регион config).
// Живой гейт (Task 7): BAR0 карты — линейный 512 MiB, НЕ cr-space: весь
// cr-трафик идёт через VSEC-шлюз (находка гейта, fix round 2).
// Fix round 2 (живой гейт попытка 6; подтверждён обратно fix round 8 после
// опровержения 0.4-детура): домены доступов разведены: init
// segment/doorbell CMDQ — ТОЛЬКО линейный маппинг BAR0 (kernel main.c:894
// `dev->iseg = ioremap(dev->bar_addr, …)` — драйвер мапит init segment из
// BAR0; живой факт: gateway-CR 0x0 — регистр cmd_ptr (значение 0x2000
// читалось как fw_rev_major), НЕ init segment); VSEC-шлюз — только
// CR-space/tool-класс (hw_id, Mtc).
// Fix round 6 (breaker-adjudicated, попытки 7-9) — REFUTED live попыткой 10
// (журнал §A10-2): маршрут iseg-доступов через VSEC-шлюз в
// AS_NODNIC_INIT_SEG (0x4) даёт НЕ-iseg-зеркало: cmdq_addr_l_sz в 0.4-view
// декодируется как log_sz=11 (мусор), BAR0 того же регистра — валидное
// 0x10000056 (log_sz 5/stride 6); establishment валидно отказал до поста.
// 0.4-детур откачен полностью (fix round 8): InitSegGateway/AS-константа/
// вариант AddressSpace удалены — мёртвое знание для этой карты (§A10).
// Fix round 8: iseg-домен СНОВА линейный BAR0 (Bar0Transport, форма fix
// round 2) — единственный вид, когда-либо читавший валидный iseg.
// Источник: журнал task-07 §A8-A11 (наши живые факты), FIREWALL — vendored
// не открывался.
// Fix round 7 (root cause гейт-попыток 7-10, owner-authorized diagnostic
// comparison — журнал task-07 §A10+2): PCI Bus Master Enable при открытии.
// Generic PCI fact: без BME устройство не может ВЫДАВАТЬ DMA (Memory
// Read/Write TLP): после mlx5_core/unbind драйвер снимает BME, vfio-pci
// оставляет config userspace'у; FW видит doorbell (host→device MMIO BME
// не требует), но CMDQ-fetch блокируется в источнике — нет TLP, нет
// IOMMU-трансляции, нет IO_PAGE_FAULT: очередь нетронута, CQE не пишется,
// dmesg чист (полная картина попыток 7-10, вкл. неудачу «пост на
// OLD-инициализированном FW» и байт-тожественные iseg-дампы). Вендорский
// сетап ставит BME первым шагом (owner-authorized diagnostic comparison);
// наш фикс — open_device_io: BME ПОСЛЕ опционального FLR (FLR возвращает
// Command register к дефолту — BME=0) и СТРОГО ДО маппинга DMA-окна и
// establishment; pci-driver API: config().command().bus_master_enable()
// .write(true).
//
// Task 10: HCA-тракт переключён на CMDQ (единый транспорт, как у старого
// бинаря — эталон гейта): exec_command/try_exec_command/do_command/
// write_register и hca_init_chain идут через crate::cmdq (establishment из
// init segment ЛИНЕЙНОГО BAR0 (fix round 2, попытка 6), очередь и
// mailbox-цепочки — DMA-окно сессии, пост → doorbell → CQE-полл, inline
// ≤16B / блочные цепочки по размеру). Статус/syndrome — из САМОГО out-кадра
// CMDQ (байты 0 / 4..8; PRM command out-header; wire-пин триг-фикстры:
// rx[0]=0x03, rx[4..8]=0x001c2b78), НЕ из ctrl-reg — H-B-находка (статус из
// ctrl/syndrome-reg) была спецификой icmd-CR-флейвора, канал которого
// опровергнут (спека post-breaker: VCR ctrl — домен GCIF/tool-опкодов,
// HCA-опкод там → status=1 invalid opcode, живой гейт попытка 4; icmd-машина
// go-bit мейнлбокса остаётся в mailbox.rs как GCIF/tool-интерфейс, сессия
// её для HCA-обменов больше не использует). ICMD-семафор62 (VCR_SEMAPHORE62,
// AS_SEMAPHORE) вокруг CMDQ-обменов НЕ берётся (plan ruling: старый бинарник
// гонял CMDQ, параллельные mstreg GCIF-маркеры проходили ×5 сессий);
// cap9-семафор шлюза остаётся внутренним для операций шлюза (dword_rw).
// Discovery сокращён до семейного гвардёра hw_id @0xf0014 через шлюз:
// VCR max_cmd_size и icmd-версия/cmd_ptr CR-регистра больше не читаются
// (CMDQ парсит init segment сам; лимит max_cmd_size не нужен — команды
// любого размера едят блочными цепочками; чанкинг ManagePages удалён —
// wire-канон arm.log: 0xa27=2599 записей одним кадром 20808B, Task 9
// fixture block-list байт-точен против ровно этого кадра).

use std::cell::Cell;
use std::path::Path;

use pci_driver::backends::vfio::VfioPciDevice;
use pci_driver::device::PciDevice;
use pci_driver::regions::{AsPciSubregion, PciRegion};

use crate::cmdq::Cmdq;
use crate::cmds::Command;
use crate::dma::{AllocationGuard, DMA_PAGE_SIZE, DmaAlloc};
use crate::err::{CmdStatusErr, Error, Result};
use crate::mailbox::{STATUS_BUSY, Transport, wire_hex};
use crate::regs::Register;

/// HW_ID_ADDR (icmd_init_vcr_crspace_addr / read_device_id); CX5=525, BF=529.
const HW_ID_ADDR: u32 = 0xf0014;
const CX5_HW_ID: u32 = 525;
const BF_HW_ID: u32 = 529;

/// Офсеты портов VSEC-капабилити (mstflint PCI_*_OFFSET; canon vsec.rs).
const PCI_CTRL_OFFSET: u16 = 0x4;
const PCI_COUNTER_OFFSET: u16 = 0x8;
const PCI_SEMAPHORE_OFFSET: u16 = 0xc;
const PCI_ADDR_OFFSET: u16 = 0x10;
const PCI_DATA_OFFSET: u16 = 0x14;
/// PCI_FLAG_BIT_OFFS = 31, PCI_SPACE_BIT_OFFS = 0 (len 16),
/// PCI_STATUS_BIT_OFFS = 29 (len 3); IFC_MAX_RETRIES = 2048 (mtcr_ul_com.c).
const PCI_FLAG_BIT_OFF: u32 = 31;
const PCI_STATUS_BIT_OFF: u32 = 29;
const PCI_STATUS_BIT_LEN: u32 = 3;
const IFC_MAX_RETRIES: usize = 2048;
/// Cap id vendor-specific (VSEC для Mellanox).
const PCI_CAP_ID_VSEC: u8 = 0x09;

/// Абстракция доступа к config-space (для моков шлюза в тестах).
trait ConfigIo {
    fn cfg_read32(&self, off: u16) -> Result<u32>;
    fn cfg_write32(&self, off: u16, v: u32) -> Result<()>;
    fn cfg_read(&self, off: u16, buf: &mut [u8]) -> Result<()>;
}

/// Config-space VFIO-устройства через pci-driver (регион config).
struct PciConfigIo {
    region: pci_driver::regions::PciSubregion<'static>,
}

impl PciConfigIo {
    fn new(device: &'static VfioPciDevice) -> Self {
        PciConfigIo {
            region: device.config().subregion(..),
        }
    }
}

impl ConfigIo for PciConfigIo {
    fn cfg_read32(&self, off: u16) -> Result<u32> {
        self.region
            .read_le_u32(off as u64)
            .map_err(|e| Error::Io(format!("config read32 @ {off:#x}: {e}")))
    }

    fn cfg_write32(&self, off: u16, v: u32) -> Result<()> {
        self.region
            .write_le_u32(off as u64, v)
            .map_err(|e| Error::Io(format!("config write32 @ {off:#x} = {v:#x}: {e}")))
    }

    fn cfg_read(&self, off: u16, buf: &mut [u8]) -> Result<()> {
        self.region
            .read_bytes(off as u64, buf)
            .map_err(|e| Error::Io(format!("config read {off:#x}+{}: {e}", buf.len())))
    }
}

/// VSEC-шлюз: cr-space (и ICMD/SEMAPHORE-домены) через пару
/// адрес/данные капабилити 0x09 (механизм mtcr_pciconf_*, канон vsec.rs).
/// Транспортное слово = LE-нагрузка байтов провода: порт-дворд (значение
/// регистра) = слово.swap_bytes().
struct VsecTransport<C: ConfigIo> {
    cfg: C,
    vsec_base: u16,
    space: Cell<u16>,
}

impl<C: ConfigIo> VsecTransport<C> {
    /// Открытие: cap-walk config-space (id 0x09), исходное пространство CR.
    fn open(cfg: C) -> Result<Self> {
        let mut head = vec![0u8; 0x100];
        cfg.cfg_read(0, &mut head)?;
        let vsec_base = find_vsec_cap(&head)
            .ok_or_else(|| Error::Unsupported("VSEC capability 0x09 not found".into()))?;
        Ok(VsecTransport {
            cfg,
            vsec_base,
            space: Cell::new(0x2),
        })
    }

    fn reg(&self, off: u16) -> u16 {
        self.vsec_base + off
    }

    /// Ticket-семафор cap9 (mtcr_pciconf_cap9_sem(1)): читать семафор до 0,
    /// взять ticket из counter, записать в семафор, сверить.
    fn sem_take(&self) -> Result<()> {
        for _ in 0..IFC_MAX_RETRIES {
            let lock = self.cfg.cfg_read32(self.reg(PCI_SEMAPHORE_OFFSET))?;
            if lock != 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            let counter = self.cfg.cfg_read32(self.reg(PCI_COUNTER_OFFSET))?;
            self.cfg
                .cfg_write32(self.reg(PCI_SEMAPHORE_OFFSET), counter)?;
            let lock = self.cfg.cfg_read32(self.reg(PCI_SEMAPHORE_OFFSET))?;
            if lock == counter {
                return Ok(());
            }
        }
        Err(Error::Io("VSEC gateway semaphore busy".into()))
    }

    /// Release cap9-семафора записью 0 (mtcr_pciconf_cap9_sem(0)). Ошибку
    /// записи НЕ глотаем (fix round 5, pwrite-аудит): вызывающий решает —
    /// прокинуть (обмен прошёл) или залогировать (не маскируя исходный сбой).
    fn sem_release(&self) -> Result<()> {
        self.cfg
            .cfg_write32(self.reg(PCI_SEMAPHORE_OFFSET), 0)
            .map_err(|e| Error::Io(format!("VSEC gateway semaphore release: {e}")))
    }

    /// mtcr_pciconf_wait_on_flag: полл бита 31 адресного порта до expected.
    fn wait_on_flag(&self, expected: u32) -> Result<()> {
        for retries in 0..IFC_MAX_RETRIES {
            let flag = (self.cfg.cfg_read32(self.reg(PCI_ADDR_OFFSET))? >> PCI_FLAG_BIT_OFF) & 1;
            if flag == expected {
                return Ok(());
            }
            if (retries & 0xf) == 0xf {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        Err(Error::Timeout)
    }

    /// mtcr_pciconf_set_addr_space: RMW младших 16 бит ctrl, проверка
    /// записанного значения и битов статуса (29..32 ≠ 0).
    fn set_space_raw(&self, space: u16) -> Result<()> {
        let mut val = self.cfg.cfg_read32(self.reg(PCI_CTRL_OFFSET))?;
        val = (val & 0xffff_0000) | space as u32;
        self.cfg.cfg_write32(self.reg(PCI_CTRL_OFFSET), val)?;
        let read_val = self.cfg.cfg_read32(self.reg(PCI_CTRL_OFFSET))?;
        if read_val & 0xffff != val & 0xffff {
            return Err(Error::Unsupported(format!(
                "адресное пространство {space:#x} не поддержано (ctrl={read_val:#010x})"
            )));
        }
        if (read_val >> PCI_STATUS_BIT_OFF) & ((1 << PCI_STATUS_BIT_LEN) - 1) == 0 {
            return Err(Error::Unsupported(format!(
                "адресное пространство {space:#x} не поддержано (status=0, ctrl={read_val:#010x})"
            )));
        }
        Ok(())
    }

    /// Один обмен mtcr_pciconf_rw под семафором с установкой пространства
    /// (mtcr_pciconf_send_pci_cmd_int): READ — адрес (бит 31 = 0), полл
    /// флага 1, чтение данных; WRITE — данные, адрес (бит 31 = 1), полл 0.
    fn dword_rw(&self, off: u32, data: &mut u32, write: bool) -> Result<()> {
        self.sem_take()?;
        let r = (|| -> Result<()> {
            self.set_space_raw(self.space.get())?;
            let address = (off & 0x3fff_ffff) | if write { 1 << PCI_FLAG_BIT_OFF } else { 0 };
            if write {
                self.cfg.cfg_write32(self.reg(PCI_DATA_OFFSET), *data)?;
                self.cfg.cfg_write32(self.reg(PCI_ADDR_OFFSET), address)?;
                self.wait_on_flag(0)?;
            } else {
                self.cfg.cfg_write32(self.reg(PCI_ADDR_OFFSET), address)?;
                self.wait_on_flag(1)?;
                *data = self.cfg.cfg_read32(self.reg(PCI_DATA_OFFSET))?;
            }
            Ok(())
        })();
        // Fix round 5 (pwrite-аудит): сбой release семафора не глотаем —
        // прокидываем при успешном обмене; при сбойном обмене логируем,
        // не маскируя исходную ошибку.
        match (r, self.sem_release()) {
            (r, Ok(())) => r,
            (Ok(()), Err(e)) => Err(e),
            (Err(r), Err(rel)) => {
                log::error!("vsec: сбой обмена ({r}) и сбой release семафора ({rel})");
                Err(r)
            }
        }
    }
}

impl<C: ConfigIo> Transport for VsecTransport<C> {
    fn read32(&self, off: usize) -> Result<u32> {
        let mut v = 0u32;
        self.dword_rw(off as u32, &mut v, false)?;
        Ok(v.swap_bytes())
    }

    fn write32(&self, off: usize, v: u32) -> Result<()> {
        let mut data = v.swap_bytes();
        self.dword_rw(off as u32, &mut data, true)
    }

    fn set_address_space(&self, raw: u16) -> Result<()> {
        self.set_space_raw(raw)?;
        self.space.set(raw);
        Ok(())
    }
}

/// Cap-walk config-space по образцу заголовка: первая капабилить с id 0x09
/// (механизм vsec.rs find_cap_offset).
fn find_vsec_cap(config: &[u8]) -> Option<u16> {
    if config.len() < 0x40 {
        return None;
    }
    let mut next = config[0x34];
    for _ in 0..48 {
        if next == 0 || next < 0x40 || (next as usize + 2) > config.len() {
            return None;
        }
        let off = next as usize;
        let (id, n) = (config[off], config[off + 1]);
        if id == PCI_CAP_ID_VSEC {
            return Some(off as u16);
        }
        next = n;
    }
    None
}

/// Минимальный доступ к регистрам через ЛИНЕЙНЫЙ маппинг BAR0 — только для
/// CMDQ (init segment @0x0..0x1fc: fw_rev/cmdif_rev/cmdq_addr/doorbell;
/// fix round 2, живой гейт попытка 6: gateway-CR 0x0 — регистр cmd_ptr, не
/// init segment; kernel main.c:894 мапит iseg из BAR0 — facts кросс-чек).
/// Fix round 8: ВОССТАНОВЛЕН после опровержения 0.4-детура (fix round 6
/// REFUTED live попыткой 10 — журнал §A10-2: чтение cmdq_addr_l_sz через
/// AS_NODNIC_INIT_SEG даёт log_sz=11 (мусор), BAR0 того же регистра —
/// валидное 0x10000056 → log_sz 5/stride 6; 0.4-view НЕ iseg-зеркало).
/// CR-space/tool-регистры через него НЕ водятся (домен VSEC-шлюза).
/// Контракт Transport: слово транспорта = LE-нагрузка 4 байтов BAR
/// (BE-дворды регистров → значение = слово.swap_bytes(), как VsecTransport).
pub(crate) struct Bar0Transport<R> {
    region: R,
}

impl Bar0Transport<pci_driver::regions::OwningPciRegion> {
    /// Продовый конструктор: регион BAR0 устройства (PciDevice::bar —
    /// владение разделяемое, регион живёт сам по себе).
    pub(crate) fn open(device: &VfioPciDevice) -> Result<Self> {
        let region = device
            .bar(0)
            .ok_or_else(|| Error::Unsupported("BAR0 у устройства отсутствует".into()))?;
        Ok(Bar0Transport { region })
    }
}

impl<R: PciRegion> Transport for Bar0Transport<R> {
    fn read32(&self, off: usize) -> Result<u32> {
        self.region
            .read_le_u32(off as u64)
            .map_err(|e| Error::Io(format!("bar0 read32 @{off:#x}: {e}")))
    }

    fn write32(&self, off: usize, v: u32) -> Result<()> {
        self.region
            .write_le_u32(off as u64, v)
            .map_err(|e| Error::Io(format!("bar0 write32 @{off:#x}={v:#x}: {e}")))
    }
}

/// Упорядоченный сетап доступа устройства (fix round 7, журнал §A10+2):
/// (1) PCI Bus Master Enable — СТРОГО ДО (2) маппинга identity-окна DMA:
/// окно мапится под DMA, который без BME мёртв в источнике (TLP не
/// выдаётся) — попытки 7-10. Порядок пинуется тестом; вызывается из
/// [`Direct::open_from_sysfs`] ПОСЛЕ опционального FLR (FLR возвращает
/// Command register к дефолту — BME=0).
fn open_device_io(
    enable_bus_master: impl FnOnce() -> std::io::Result<()>,
    map_window: impl FnOnce() -> Result<DmaAlloc>,
) -> Result<DmaAlloc> {
    enable_bus_master().map_err(|e| Error::Io(format!("PCI bus master enable: {e}")))?;
    map_window()
}

/// Сессия прямого доступа (VFIO): HCA-обмены — CMDQ (cmdq.rs; init segment
/// и doorbell — через линейный BAR0 (Bar0Transport, fix round 2, восстановлен
/// fix round 8), очередь/mailbox — из DMA-окна), VSEC-шлюз — discovery
/// (hw_id) и CR-space/Mtc инструментальный класс.
pub struct Direct {
    /// Дамп TX/RX hex-строками в формате фикстр (stderr).
    pub dump_bufs: bool,
    /// DMA-аллокатор: identity-окно 0x1000_0000 (dma.rs); CMDQ-очередь и
    /// mailbox-цепочки выделяются из него.
    pub dma_allocator: DmaAlloc,
    /// VSEC-шлюз (process-lifetime, см. open_from_sysfs): CR-space/Mtc
    /// инструментальный класс (hw_id, Mtc-слова).
    transport: &'static VsecTransport<PciConfigIo>,
    /// Транспорт HCA-команд (Task 10): единый CMDQ, как у старого бинаря.
    cmdq: Cmdq<'static>,
    /// Страницы, отданные FW в HCA-init-цепочке (`init=true`): живут до конца
    /// сессии — FW держит их как ICM (guard'ы не дропаются до Drop Direct).
    hca_pages: Vec<AllocationGuard>,
}

impl Direct {
    /// Открытие VFIO-сессии по sysfs-пути устройства (например
    /// `/sys/bus/pci/devices/0000:81:00.0`). `flr` — function-level reset
    /// (VFIO_DEVICE_RESET) сразу после открытия; `init` — HCA-init-цепочка
    /// (EnableHCA/ISSI/pages/QueryHCACap/InitHCA поверх CMDQ — live-gate
    /// H-A: без неё FW после FLR игнорирует команды вне pre-init whitelist);
    /// `init=false` — CMDQ-очередь публикуется, init-цепочка не выполняется.
    /// Всегда: семейный гвардёр hw_id @0xf0014 + establishment CMDQ (при
    /// `flr` — wait initializing до парса: сразу после FLR регистры
    /// читаются мусором, task-07 попытка 1). Обмены — CMDQ (Task 10);
    /// шлюз — CR-space/Mtc. Устройство, шлюз и дескриптор DMA-окна для
    /// Cmdq интенионально живут до конца процесса (Box::leak): config-регион
    /// шлюза и Cmdq заимствуют их на 'static; исходный dma_allocator
    /// остаётся полем Direct (общий пул страниц, drop Direct — munmap окна).
    pub fn open_from_sysfs(dev: &Path, flr: bool, init: bool) -> Result<Self> {
        let device = VfioPciDevice::open(dev)
            .map_err(|e| Error::Io(format!("vfio open {}: {e}", dev.display())))?;
        if flr {
            device
                .reset()
                .map_err(|e| Error::Io(format!("flr reset {}: {e}", dev.display())))?;
        }
        // Fix round 7 (журнал §A10+2): BME до маппинга окна/establishment,
        // после опционального FLR (FLR сбрасывает Command register).
        let dma_allocator = open_device_io(
            || device.config().command().bus_master_enable().write(true),
            || DmaAlloc::map_window(&device.iommu()),
        )?;
        let device: &'static VfioPciDevice = Box::leak(Box::new(device));
        let transport: &'static VsecTransport<PciConfigIo> =
            Box::leak(Box::new(VsecTransport::open(PciConfigIo::new(device))?));
        check_hw_family(transport)?;
        let dma: &'static DmaAlloc = Box::leak(Box::new(dma_allocator.share()));
        // Init segment/doorbell CMDQ — линейный BAR0 (fix round 2,
        // восстановлен fix round 8: 0.4-детур опровергнут попыткой 10 —
        // журнал §A10-2); шлюз — CR/tool-класс.
        let bar0: &'static Bar0Transport<pci_driver::regions::OwningPciRegion> =
            Box::leak(Box::new(Bar0Transport::open(device)?));
        let cmdq = establish_cmdq(bar0, dma, flr)?;
        let mut direct = Direct {
            dump_bufs: false,
            dma_allocator,
            transport,
            cmdq,
            hca_pages: Vec::new(),
        };
        if init {
            let mut hca_pages = Vec::new();
            let window = &direct.dma_allocator;
            let mut take_pages = |n: usize| -> Result<Vec<u64>> {
                let guard = window.alloc(n).ok_or_else(|| {
                    Error::Io(format!("dma-окно: нет {n} смежных страниц для hca-init"))
                })?;
                let base = guard
                    .as_ptr()
                    .ok_or_else(|| Error::Io("dma-окно: ptr недоступен".into()))?
                    as usize as u64;
                hca_pages.push(guard);
                Ok((0..n).map(|i| base + (i * DMA_PAGE_SIZE) as u64).collect())
            };
            // dump=false: как и до Task 10 — на момент открытия флаг ещё
            // сброшен (выставляется вызывающим после open).
            let q = &direct.cmdq;
            hca_init_chain(
                &mut |frame: &[u8], outlen: u32| cmdq_exec(q, frame, outlen, false),
                &mut take_pages,
            )?;
            direct.hca_pages = hca_pages;
        }
        Ok(direct)
    }

    /// HCA-команда с проверкой статуса: статус≠0 → Err(Command), успех →
    /// payload из out-кадра (с офсета 8). Транспорт — CMDQ (Task 10): кадр
    /// идёт как есть (inline ≤16B / mailbox-цепочка), статус/syndrome — из
    /// out-кадра (байты 0/4..8, wire-пин фикстр). Без ICMD-семафора
    /// (plan ruling: старый бинарник гонял CMDQ параллельно mstreg-маркерам);
    /// poison CMDQ — fail-fast до re-open.
    pub fn exec_command(&self, input: &[u8], outlen: u32) -> Result<Vec<u8>> {
        cmdq_exec(&self.cmdq, input, outlen, self.dump_bufs)
    }

    /// HCA-команда без исключающего статуса: Ok((out, status_byte)) —
    /// статус-байт вторым элементом пары (Task 2), Err только для
    /// транспортных сбоев (вкл. poison fail-fast). Транспорт — CMDQ
    /// (как exec_command).
    pub fn try_exec_command(&self, frame: &[u8], outlen: u32) -> Result<(Vec<u8>, u8)> {
        cmdq_try_exec(&self.cmdq, frame, outlen, self.dump_bufs)
    }

    /// Транспорт CR-space сессии (для Mtc::from_direct, mtcr.rs).
    pub(crate) fn transport(&self) -> &dyn Transport {
        self.transport
    }

    /// База DMA-региона мейнлбокса (база identity-окна из dma.rs; vaddr == IOVA).
    pub fn dma_region_base(&self) -> Option<*mut u8> {
        Some(self.dma_allocator.window_base())
    }

    /// Типизированная команда: encode → exec_command (статус≠0 уже даёт
    /// Err(Command) — Task 2) → decode Output из payload.
    pub fn do_command<C: Command>(&self, cmd: C) -> Result<C::Output> {
        run_command(&cmd, |frame, outlen| self.exec_command(frame, outlen))
    }

    /// Реестр ACCESS_REGISTER (0x0805, write): register_id/argument в кадре,
    /// данные регистра с офсета 16; readback декодируется из payload с +8.
    pub fn write_register<R: Register>(&self, reg: R, argument: u32) -> Result<R> {
        run_register_write(&reg, argument, |frame, outlen| {
            self.exec_command(frame, outlen)
        })
    }
}

/// Discovery-остаток (Task 10): семейный гвардёр hw_id @ 0xf0014 в
/// AS_CR_SPACE через шлюз (порт-дворд → BE-значение, CX5 → raw 0x0d02_0000).
/// Прочее icmd-discovery (VCR max_cmd_size, icmd-версия/cmd_ptr CR) удалено:
/// CMDQ читает init segment сам, лимитов больше нет (блочные цепочки).
/// Чтение — без ICMD-семафора (обычный CR-дворд шлюза; cap9-семафор — внутри
/// dword_rw).
fn check_hw_family(t: &dyn Transport) -> Result<()> {
    let hw_id = t
        .read32(HW_ID_ADDR as usize)
        .map_err(|e| Error::Io(format!("discovery: hw_id read: {e}")))?
        .swap_bytes()
        & 0xffff;
    match hw_id {
        CX5_HW_ID | BF_HW_ID => Ok(()),
        other => Err(Error::Unsupported(format!(
            "hw_id {other:#x} не семейство CX5/BF"
        ))),
    }
}

/// CMDQ-ядро поверх BAR0-доступа сессии (Task 9 + fix round 2,
/// восстановлен fix round 8): init segment (регистры @0x0/0x4/0x10/0x14/
/// 0x18/0x1fc) — через линейный BAR0 (Bar0Transport; 0.4-детур fix round 6
/// опровергнут попыткой 10 — журнал §A10-2), очередь/mailbox — из окна
/// DmaAlloc сессии. flr_wait — пост-FLR wait initializing до парса.
pub(crate) fn establish_cmdq<'a>(
    t: &'a dyn Transport,
    dma: &'a DmaAlloc,
    flr_wait: bool,
) -> Result<crate::cmdq::Cmdq<'a>> {
    crate::cmdq::Cmdq::establish(t, dma, flr_wait)
}

/// Обмен HCA-команды поверх CMDQ без исключающего статуса: пост (inline
/// ≤16B / mailbox-цепочка) → CQE; ядро собирает out-кадр (out-inline +
/// out-цепочка). Статус-байт = out[0], syndrome (для Err(Command) в
/// cmdq_exec) = out[4..8] BE & 0x00ff_ffff — из САМОГО out-кадра (PRM
/// command out-header; wire-пин триг-фикстры), в отличие от icmd-CR-флейвора
/// (H-B: ctrl/syndrome-reg). busy (0x5) → ровно один повтор (паритет
/// icmd try_exec_full, mstflint translate_status). Poison/таймаут CQE/
/// delivery-ошибки — от ядра как есть (fail-fast до re-open).
pub(crate) fn cmdq_try_exec(
    q: &Cmdq,
    frame: &[u8],
    outlen: u32,
    dump: bool,
) -> Result<(Vec<u8>, u8)> {
    let mut attempt = 0;
    loop {
        let done = q.post(frame, outlen as usize)?;
        if dump {
            eprintln!("TX {}", wire_hex(frame));
            eprintln!("RX {}", wire_hex(&done.output));
        }
        let status = done.output.first().copied().unwrap_or(0);
        attempt += 1;
        if status != STATUS_BUSY || attempt > 1 {
            return Ok((done.output, status));
        }
        log::debug!("cmdq: busy (status 0x{STATUS_BUSY:x}), повторяю обмен (попытка 2)");
    }
}

/// Payload-вариант обмена поверх CMDQ: out[8..] при статусе 0; статус≠0 →
/// Err(Command) со статусом/syndrome из out-кадра (контракт Task 2 сохранён,
/// источник значений — фикстры).
pub(crate) fn cmdq_exec(q: &Cmdq, frame: &[u8], outlen: u32, dump: bool) -> Result<Vec<u8>> {
    let (out, status) = cmdq_try_exec(q, frame, outlen, dump)?;
    if status != 0 {
        let syndrome = out
            .get(4..8)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0)
            & 0x00ff_ffff;
        return Err(Error::Command(CmdStatusErr { status, syndrome }));
    }
    Ok(out.get(8..).map(<[u8]>::to_vec).unwrap_or_default())
}

/// ACCESS_REGISTER (PRM 0x0805): op_mod 0x0 = write (фикстры SET: байты
/// 4..6 = 0), register_id BE16 @0x0a, argument BE32 @0x0c, данные с 0x10.
const ACCESS_REGISTER_OPCODE: u16 = 0x0805;
const ACCESS_REGISTER_HEADER: usize = 16;
/// Out-буфер register-обмена (wire-факт: rx_len всех MTRC-блоков = 144).
pub(crate) const REGISTER_OUTLEN: usize = 144;

/// Обмен команды поверх абстрактного exec (моки в тестах; Direct::do_command
/// подставляет exec_command).
pub(crate) fn run_command<C: Command>(
    cmd: &C,
    exec: impl FnOnce(&[u8], u32) -> Result<Vec<u8>>,
) -> Result<C::Output> {
    let mut frame = Vec::new();
    cmd.encode(&mut frame)?;
    let payload = exec(&frame, cmd.outlen() as u32)?;
    C::decode(&payload)
}

/// Register-write через ACCESS_REGISTER поверх абстрактного exec; readback
/// регистра — с payload+8 (эхо status/syndrome out-кадра ACCESS_REGISTER,
/// нули при успехе; wire-факт фикстр mtrc-set: данные с rx[16]).
pub(crate) fn run_register_write<R: Register>(
    reg: &R,
    argument: u32,
    exec: impl FnOnce(&[u8], u32) -> Result<Vec<u8>>,
) -> Result<R> {
    let mut frame = vec![0u8; ACCESS_REGISTER_HEADER];
    frame[0..2].copy_from_slice(&ACCESS_REGISTER_OPCODE.to_be_bytes());
    frame[10..12].copy_from_slice(&R::REGISTER_ID.to_be_bytes());
    frame[12..16].copy_from_slice(&argument.to_be_bytes());
    reg.encode(&mut frame)?;
    let payload = exec(&frame, REGISTER_OUTLEN as u32)?;
    R::decode(payload.get(8..).unwrap_or(&[]))
}

// ---------- HCA-init-цепочка (fix round 4, live-gate H-A; Task 10: CMDQ) ----------
//
// После FLR/перезагрузки FW игнорирует команды вне pre-InitHCA whitelist
// (AllocPD/query_flow_table отбрасываются без out-кадра; ACCESS_REGISTER
// работает) — пока не выполнена драйверская init-цепочка. Последовательность
// и кадры — wire-факты Task 1 (захват старого бинарника RUST_LOG=trace,
// /tmp/opencode/wire/arm.log, arm2.log; фикстры testdata/wire/cmdq-init.txt):
// EnableHCA(0x0104) → QueryISSI(0x010a, out 112) → SetISSI(0x010b, issi=1) →
// QueryPages(0x0107, op_mod boot=1, 6 страниц) → ManagePages(0x0108, give,
// 6 записей) → QueryHCACap(0x0100, op_mod GET_CUR=1, out 4112) →
// QueryPages(op_mod init=2, 0xa27=2599) → ManagePages(give, 2599 записей
// ОДНИМ кадром 20808B — блочная цепочка CMDQ, арм.log:14330) → InitHCA
// (0x0102). Без re-query между фазами — wire-канон старого бинарника.
// Лейауты полей — kernel mlx5_ifc.h (refs/src/linux/linux): set_issi_in.
// current_issi u16@10, query_issi_out.supported_issi_dw0@104..112,
// query/manage_pages op_mod u16@6, manage_pages input_num_entries u32@12 +
// pas[] u64 с байта 16. Семантика страниц — kernel pagealloc.c
// (satisfy_startup_pages/give_pages); толерантность ISSI — как в ядре.

/// Оpcodes init-цепочки (wire-факты arm.log).
const OP_ENABLE_HCA: u16 = 0x0104;
const OP_QUERY_ISSI: u16 = 0x010a;
const OP_SET_ISSI: u16 = 0x010b;
const OP_QUERY_PAGES: u16 = 0x0107;
const OP_MANAGE_PAGES: u16 = 0x0108;
const OP_QUERY_HCA_CAP: u16 = 0x0100;
const OP_INIT_HCA: u16 = 0x0102;

/// query_pages op_mod (kernel pagealloc.c / wire): boot=1, init=2.
const PAGES_OP_MOD_BOOT: u16 = 1;
const PAGES_OP_MOD_INIT: u16 = 2;
/// manage_pages op_mod AllocationSuccess (kernel MLX5_PAGES_GIVE).
const PAGES_OP_MOD_GIVE: u16 = 1;
/// HCA_CAP_OPMOD_GET_CUR (mlx5_ifc.h enum mlx5_cap_mode) — op_mod старого
/// бинарника (wire: байты 6..8 = 00 01).
const CAP_OPMOD_GET_CUR: u16 = 1;

/// Out-размер QueryISSI — wire-факт старого бинарника (outlen=112).
const QUERY_ISSI_OUTLEN: usize = 112;
/// Out-размер QueryHCACap(GET_CUR) — wire-факт (outlen=4112 = 16 inline +
/// 8×512 out-цепочка; arm.log:821).
const QUERY_HCA_CAP_OUTLEN: usize = 4112;
/// Заголовок manage_pages_in: 16 байт до pas[] (mlx5_ifc.h).
const MANAGE_PAGES_HEADER: usize = 16;
/// Размер записи pas[]: u64 (mlx5_ifc.h pas[][0x40]).
const MANAGE_PAGES_ENTRY: usize = 8;

/// Команда с 16-байтовым кадром: opcode @0..2 + поле u16 @6..8 (op_mod).
fn frame16(opcode: u16, op_mod: u16) -> Vec<u8> {
    let mut f = vec![0u8; 16];
    f[0..2].copy_from_slice(&opcode.to_be_bytes());
    f[6..8].copy_from_slice(&op_mod.to_be_bytes());
    f
}

/// Фаза startup-страниц: QueryPages → ManagePages(give) — ВСЕ запрошенные
/// страницы одним кадром (wire arm.log: старый бинарник отдавал 0xa27=2599
/// записей разом через DMA-mailbox CMDQ-цепочкой; чанкинг по max_cmd_size
/// был артефактом icmd-мейнлбокса и удалён вместе с ним). num≤0 — фаза
/// удовлетворена. Без re-query после give — wire-канон (kernel
/// satisfy_startup_pages поллит до нуля, старый бинарник — один раунд).
fn give_startup_pages(
    exec: &mut dyn FnMut(&[u8], u32) -> Result<Vec<u8>>,
    op_mod: u16,
    alloc_pages: &mut dyn FnMut(usize) -> Result<Vec<u64>>,
) -> Result<()> {
    let payload = exec(&frame16(OP_QUERY_PAGES, op_mod), 16)?;
    // query_pages_out.num_pages s32 @ байты 12..16 → payload (с +8) [4..8].
    let num = payload
        .get(4..8)
        .map(|b| i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0);
    if num <= 0 {
        return Ok(());
    }
    let addrs = alloc_pages(num as usize)?;
    let mut frame = vec![0u8; MANAGE_PAGES_HEADER + num as usize * MANAGE_PAGES_ENTRY];
    frame[0..2].copy_from_slice(&OP_MANAGE_PAGES.to_be_bytes());
    frame[6..8].copy_from_slice(&PAGES_OP_MOD_GIVE.to_be_bytes());
    frame[12..16].copy_from_slice(&(num as u32).to_be_bytes());
    for (i, a) in addrs.iter().enumerate() {
        frame[MANAGE_PAGES_HEADER + i * MANAGE_PAGES_ENTRY
            ..MANAGE_PAGES_HEADER + (i + 1) * MANAGE_PAGES_ENTRY]
            .copy_from_slice(&a.to_be_bytes());
    }
    exec(&frame, 16)?;
    log::debug!("hca-init: фаза {op_mod} отдано {num} страниц (одним кадром)");
    Ok(())
}

/// HCA-init-цепочка для `init=true`: wire-последовательность старого
/// бинарника, поверх абстрактного exec (сессия подставляет CMDQ-обмен с
/// проверкой статуса). Строгие шаги — EnableHCA, страницы, InitHCA (сбой →
/// Err, FW остаётся pre-init); толерантные — ISSI-пара и QueryHCACap
/// (kernel-семантика: сбой query_issi не фатален, SetISSI пропускается).
/// Страницы выделяются колбэком alloc_pages (DMA-окно сессии) и должны
/// жить до конца сессии — FW держит их как ICM.
pub(crate) fn hca_init_chain(
    exec: &mut dyn FnMut(&[u8], u32) -> Result<Vec<u8>>,
    alloc_pages: &mut dyn FnMut(usize) -> Result<Vec<u64>>,
) -> Result<()> {
    // 1. EnableHCA — строгий (kernel: фатален при сбое).
    exec(&frame16(OP_ENABLE_HCA, 0), 16)?;

    // 2. QueryISSI → SetISSI(1) при поддержке — толерантная пара.
    match exec(&frame16(OP_QUERY_ISSI, 0), QUERY_ISSI_OUTLEN as u32) {
        Ok(payload) if payload.len() + 8 >= QUERY_ISSI_OUTLEN => {
            // supported_issi_dw0 BE u64 @ out 104..112 → payload [96..104];
            // бит 1 = ISSI v1 (wire: bitmap 0x02 → set_issi(1)).
            let supported = u64::from_be_bytes(payload[96..104].try_into().unwrap());
            if supported & (1 << 1) != 0 {
                let mut f = vec![0u8; 16];
                f[0..2].copy_from_slice(&OP_SET_ISSI.to_be_bytes());
                f[10..12].copy_from_slice(&1u16.to_be_bytes());
                if let Err(e) = exec(&f, 16) {
                    log::warn!("hca-init: set_issi(1) не удался, остаюсь на ISSI 0: {e}");
                }
            }
        }
        Ok(_) => log::warn!("hca-init: query_issi короткий payload, SetISSI пропущен"),
        Err(e) => log::warn!("hca-init: query_issi не удался, SetISSI пропущен: {e}"),
    }

    // 3. Boot-страницы — строгие.
    give_startup_pages(exec, PAGES_OP_MOD_BOOT, alloc_pages)?;

    // 4. QueryHCACap(GET_CUR) — толерантный (результат цепочкой не
    //    потребляется); out = полный cap-струк 4112B (wire arm.log:821) —
    //    CMDQ собирает его out-цепочкой.
    if let Err(e) = exec(
        &frame16(OP_QUERY_HCA_CAP, CAP_OPMOD_GET_CUR),
        QUERY_HCA_CAP_OUTLEN as u32,
    ) {
        log::warn!("hca-init: query_hca_cap не удался (продолжаю): {e}");
    }

    // 5. Init-страницы — строгие.
    give_startup_pages(exec, PAGES_OP_MOD_INIT, alloc_pages)?;

    // 6. InitHCA — строгий.
    exec(&frame16(OP_INIT_HCA, 0), 16)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, VecDeque};
    use std::rc::Rc;

    use super::*;
    use crate::cmdq::{
        CMDQ_ENTRY_SIZE, CMDQ_INLINE_SIZE, INITSEG_DBELL, MAILBOX_BLOCK_SIZE, MAILBOX_DATA_SIZE,
        decode_entry,
    };
    use crate::cmds::mkey::{AccessMode, CreateMKey, MKeyContext};
    use crate::cmds::pd::AllocPD;
    use crate::err::CmdStatusErr;
    use crate::regs::mtrc::{MtrcCapReg, MtrcConfReg};
    use crate::wiretest::{block, parse_wire};

    const MTRC_FIX: &str = include_str!("../testdata/wire/mtrc-set.txt");
    const ALLOC_FIX: &str = include_str!("../testdata/wire/alloc-pd-mkey.txt");
    const FLOWTABLE_FIX: &str = include_str!("../testdata/wire/flowtable.txt");
    const CMDQ_INIT_FIX: &str = include_str!("../testdata/wire/cmdq-init.txt");

    /// «Пространство BAR0» в regs-карте MockConfig (fix round 2,
    /// восстановлено fix round 8: init segment/doorbell живут в линейном
    /// BAR0, НЕ в шлюзе — 0.4-детур опровергнут попыткой 10, §A10-2; ключи
    /// 0x2/0x3/0xa заняты address_space_t).
    const MOCK_BAR0_SPACE: u16 = 0x0;

    /// Мок BAR0-linear доступа (fix round 2, fix round 8): iseg-регистры
    /// MockConfig в пространстве MOCK_BAR0_SPACE; doorbell-запись @0x18
    /// запускает модель CMDQ-устройства. Контракт Transport — как
    /// Bar0Transport (слово транспорта = LE-нагрузка → значение = swap).
    struct MockBar0<'a> {
        cfg: &'a MockConfig,
    }

    impl Transport for MockBar0<'_> {
        fn read32(&self, off: usize) -> Result<u32> {
            Ok(self.cfg.reg(MOCK_BAR0_SPACE, off as u32).swap_bytes())
        }

        fn write32(&self, off: usize, v: u32) -> Result<()> {
            let reg = v.swap_bytes();
            self.cfg.set_reg(MOCK_BAR0_SPACE, off as u32, reg);
            if off == INITSEG_DBELL {
                self.cfg.cmdq_on_doorbell();
            }
            Ok(())
        }
    }

    // ---------- Мок config-space для тестов VSEC-шлюза ----------

    /// Мок config-space: образ конфигурации + регистры устройства по
    /// (space, offset) + журнал операций. Адресный порт асинхронный:
    /// запись порождает операцию, первый полл завершает её — флаг 31
    /// (mtcr_pciconf: READ ждёт флаг 1, WRITE ждёт флаг 0).
    #[derive(Default)]
    struct MockConfig {
        cfg: RefCell<Vec<u32>>,
        regs: RefCell<HashMap<(u16, u32), u32>>,
        space: Cell<u16>,
        ops: RefCell<Vec<String>>,
        pending: Cell<Option<(u32, bool)>>,
        bad_status: Cell<bool>,
        // ---------- Модель CMDQ-устройства (Task 10) ----------
        /// Сценарные комплитки CMDQ (FIFO на doorbell): (delivery, output).
        completions: RefCell<VecDeque<(u8, Vec<u8>)>>,
        /// Не завершать команду: ownership остаётся у HW (тест POISONED).
        hold_owner: Cell<bool>,
        /// Собранные устройством input-кадры (TX-журнал) + outlen поста.
        tx_log: RefCell<Vec<(Vec<u8>, u32)>>,
        /// Число doorbell-срабатываний.
        doorbells: Cell<usize>,
    }

    impl MockConfig {
        fn new() -> Self {
            let mut cfg = vec![0u32; 0x100 / 4];
            // cap ptr @0x34 → VSEC @0x40 (id в байте 0x40 — младший байт слова)
            cfg[0x34 / 4] = 0x40;
            cfg[0x40 / 4] = 0x09;
            let m = MockConfig {
                cfg: RefCell::new(cfg),
                regs: RefCell::new(HashMap::new()),
                space: Cell::new(0),
                ops: RefCell::new(Vec::new()),
                pending: Cell::new(None),
                bad_status: Cell::new(false),
                completions: RefCell::new(VecDeque::new()),
                hold_owner: Cell::new(false),
                tx_log: RefCell::new(Vec::new()),
                doorbells: Cell::new(0),
            };
            m.set_cfg(0x40 + PCI_CTRL_OFFSET, 0x7 << PCI_STATUS_BIT_OFF); // статус ок
            m
        }

        fn set_cfg(&self, off: u16, v: u32) {
            self.cfg.borrow_mut()[off as usize / 4] = v;
        }

        fn cfg_word(&self, off: u16) -> u32 {
            self.cfg.borrow()[off as usize / 4]
        }

        fn set_reg(&self, space: u16, off: u32, v: u32) {
            self.regs.borrow_mut().insert((space, off), v);
        }

        fn reg(&self, space: u16, off: u32) -> u32 {
            *self.regs.borrow().get(&(space, off)).unwrap_or(&0)
        }

        fn ops(&self) -> Vec<String> {
            self.ops.borrow().clone()
        }

        fn push_completion(&self, delivery: u8, output: Vec<u8>) {
            self.completions.borrow_mut().push_back((delivery, output));
        }

        // ---------- Модель CMDQ-устройства (Task 10; fix round 2,
        // восстановлено fix round 8: init segment/doorbell — пространство
        // BAR0 (MOCK_BAR0_SPACE), НЕ CR-шлюз) ----------
        // На doorbell (запись @BAR0 0x18): очередь читается из окна (адрес —
        // из опубликованных @BAR0 0x10/0x14), input собирается из inline +
        // in-цепочки, output кладётся в out-inline/цепочку, ownership → SW
        // (бит 0 байта 63 = 0, delivery — биты 7:1).

        unsafe fn win_read(addr: u64, len: usize) -> Vec<u8> {
            unsafe {
                (0..len)
                    .map(|i| (addr as *const u8).add(i).read_volatile())
                    .collect()
            }
        }

        unsafe fn win_write(addr: u64, data: &[u8]) {
            unsafe {
                let p = addr as *mut u8;
                for (i, b) in data.iter().enumerate() {
                    p.add(i).write_volatile(*b);
                }
            }
        }

        fn cmdq_on_doorbell(&self) {
            self.doorbells.set(self.doorbells.get() + 1);
            let base = ((self.reg(MOCK_BAR0_SPACE, 0x10) as u64) << 32)
                | (self.reg(MOCK_BAR0_SPACE, 0x14) as u64 & 0xffff_f000);
            assert_ne!(base, 0, "doorbell без опубликованной очереди");
            let entry = unsafe { Self::win_read(base, CMDQ_ENTRY_SIZE) };
            let v = decode_entry(&entry);

            // Сбор input: inline + цепочка in-блоков по next-указателям.
            let mut input = Vec::with_capacity(v.inlen as usize);
            let inline = (v.inlen as usize).min(CMDQ_INLINE_SIZE);
            input.extend_from_slice(&v.in_inline[..inline]);
            let mut remaining = v.inlen as usize - inline;
            let mut ptr = v.in_ptr;
            while remaining > 0 {
                assert_ne!(ptr, 0, "input остался, а in-цепочка кончилась");
                let b = unsafe { Self::win_read(ptr, MAILBOX_BLOCK_SIZE) };
                let take = remaining.min(MAILBOX_DATA_SIZE);
                input.extend_from_slice(&b[..take]);
                remaining -= take;
                ptr = u64::from_be_bytes(b[0x230..0x238].try_into().unwrap());
            }
            self.tx_log.borrow_mut().push((input, v.outlen));
            if self.hold_owner.get() {
                return; // HW не ответил: ownership остаётся взведённым
            }
            let (delivery, output) = self
                .completions
                .borrow_mut()
                .pop_front()
                .expect("mock: нет CMDQ-комплитки");
            // Output: первые 16B — inline в entr, остальное — out-цепочка.
            let out_inline = output.len().min(CMDQ_INLINE_SIZE);
            unsafe { Self::win_write(base + 0x20, &output[..out_inline]) };
            let mut pos = out_inline;
            let mut ptr = v.out_ptr;
            while pos < output.len() {
                assert_ne!(ptr, 0, "output остался, а out-цепочки нет");
                let take = (output.len() - pos).min(MAILBOX_DATA_SIZE);
                unsafe { Self::win_write(ptr, &output[pos..pos + take]) };
                let b = unsafe { Self::win_read(ptr, 0x238) };
                ptr = u64::from_be_bytes(b[0x230..0x238].try_into().unwrap());
                pos += take;
            }
            let status_own = delivery << 1; // бит 0 (ownership) → 0 = SW
            unsafe { Self::win_write(base + 63, &[status_own]) };
        }
    }

    impl ConfigIo for MockConfig {
        fn cfg_read32(&self, off: u16) -> Result<u32> {
            self.ops.borrow_mut().push(format!("r:{off:#x}"));
            if off == 0x40 + PCI_ADDR_OFFSET {
                // Полл флага: первый полл завершает ожидающую операцию.
                if let Some((addr, write)) = self.pending.take() {
                    if write {
                        let data = self.cfg_word(0x40 + PCI_DATA_OFFSET);
                        self.regs
                            .borrow_mut()
                            .insert((self.space.get(), addr), data);
                        self.set_cfg(off, addr); // флаг 0 — запись завершена
                        Ok(addr)
                    } else {
                        let data = self.reg(self.space.get(), addr);
                        self.set_cfg(0x40 + PCI_DATA_OFFSET, data);
                        let readback = addr | (1 << PCI_FLAG_BIT_OFF); // флаг 1
                        self.set_cfg(off, readback);
                        Ok(readback)
                    }
                } else {
                    Ok(self.cfg_word(off))
                }
            } else {
                Ok(self.cfg_word(off))
            }
        }

        fn cfg_write32(&self, off: u16, v: u32) -> Result<()> {
            self.ops.borrow_mut().push(format!("w:{off:#x}={v:#x}"));
            if off == 0x40 + PCI_ADDR_OFFSET {
                let write = (v >> PCI_FLAG_BIT_OFF) & 1 == 1;
                self.pending.set(Some((v & 0x3fff_ffff, write)));
                // До завершения операции флаг в порту сброшен.
                self.set_cfg(off, v & !(1 << PCI_FLAG_BIT_OFF));
                return Ok(());
            }
            if off == 0x40 + PCI_CTRL_OFFSET {
                let status = if self.bad_status.get() {
                    0
                } else {
                    (self.cfg_word(off) >> PCI_STATUS_BIT_OFF) << PCI_STATUS_BIT_OFF
                };
                self.set_cfg(off, (v & 0xffff) | status);
                self.space.set((v & 0xffff) as u16);
                return Ok(());
            }
            self.set_cfg(off, v);
            Ok(())
        }

        fn cfg_read(&self, off: u16, buf: &mut [u8]) -> Result<()> {
            for (i, chunk) in buf.chunks_mut(4).enumerate() {
                let w = self.cfg_word(off + (i * 4) as u16).to_le_bytes();
                let n = chunk.len();
                chunk.copy_from_slice(&w[..n]);
            }
            Ok(())
        }
    }

    // ---------- Шлюз: механика обменов (без изменений Task 10) ----------

    #[test]
    fn gateway_read_is_address_then_data() {
        let mock = MockConfig::new();
        mock.set_reg(0x2, 0x1000, 0xaabb_ccdd);
        let g = VsecTransport::open(mock).unwrap();
        // Слово транспорта = LE-нагрузка: порт-дворд 0xaabb_ccdd → 0xddcc_bbaa.
        assert_eq!(g.read32(0x1000).unwrap(), 0xddcc_bbaa);
        let ops = g.cfg.ops();
        let addr_write = ops
            .iter()
            .position(|o| o == "w:0x50=0x1000")
            .expect("адрес записан");
        let data_read = ops
            .iter()
            .position(|o| o == "r:0x54")
            .expect("данные прочитаны");
        assert!(
            addr_write < data_read,
            "чтение: адрес раньше данных, ops={ops:?}"
        );
    }

    #[test]
    fn gateway_write_is_data_then_address_with_flag() {
        let mock = MockConfig::new();
        let g = VsecTransport::open(mock).unwrap();
        g.write32(0x2000, 0x1000_0093).unwrap();
        // Порт-дворд = swap слова транспорта: 0x1000_0093 → 0x9300_0010.
        assert_eq!(g.cfg.reg(0x2, 0x2000), 0x9300_0010);
        let ops = g.cfg.ops();
        let data_write = ops
            .iter()
            .position(|o| o == "w:0x54=0x93000010")
            .expect("данные записаны до адреса");
        let addr_write = ops
            .iter()
            .position(|o| o == "w:0x50=0x80002000")
            .expect("адрес с битом 31");
        assert!(
            data_write < addr_write,
            "запись: данные раньше адреса, ops={ops:?}"
        );
    }

    #[test]
    fn gateway_set_addr_space_unsupported_when_status_clear() {
        let mock = MockConfig::new();
        mock.bad_status.set(true);
        let g = VsecTransport::open(mock).unwrap();
        assert!(matches!(
            g.set_address_space(0x3),
            Err(Error::Unsupported(_))
        ));
    }

    // ---------- Discovery-остаток: hw_id семейный гвардёр ----------

    /// Discovery (Task 10) сокращён до hw_id @0xf0014 через шлюз: CX5/BF
    /// принимаются; VCR max_cmd_size / icmd-версия больше не читаются.
    #[test]
    fn hw_family_guard_accepts_cx5_and_bf_via_gateway() {
        let mock = MockConfig::new();
        mock.set_reg(0x2, 0xf0014, 525); // CX5: порт-дворд 525 → raw 0x0d02_0000
        let g = VsecTransport::open(mock).unwrap();
        check_hw_family(&g).unwrap();
        g.cfg.set_reg(0x2, 0xf0014, 529); // BF
        check_hw_family(&g).unwrap();
    }

    #[test]
    fn hw_family_guard_rejects_foreign_hw_id() {
        let mock = MockConfig::new();
        mock.set_reg(0x2, 0xf0014, 523); // CX4LX
        let g = VsecTransport::open(mock).unwrap();
        assert!(matches!(check_hw_family(&g), Err(Error::Unsupported(_))));
    }

    // ---------- (прежние тесты Task 5: mock_exec / run_command) ----------

    /// Мок exec_command: захватывает кадр, возвращает payload (= rx[8..]) или
    /// сценарный Err.
    fn mock_exec(
        rx: Option<Vec<u8>>,
    ) -> (
        Rc<RefCell<Vec<u8>>>,
        impl FnOnce(&[u8], u32) -> Result<Vec<u8>>,
    ) {
        let cap = Rc::new(RefCell::new(Vec::new()));
        let sink = Rc::clone(&cap);
        let f = move |frame: &[u8], _outlen: u32| {
            sink.borrow_mut().extend_from_slice(frame);
            match rx {
                Some(rx) => Ok(rx[8..].to_vec()),
                None => Err(Error::Command(CmdStatusErr {
                    status: 0x04,
                    syndrome: 0x6c64fe,
                })),
            }
        };
        (cap, f)
    }

    /// (г) do_command: кадр = TX-фикстура байт-в-байт, Output декодируется
    /// из payload (AllocPD → pd=0x10, CreateMKey → mkey_index=0x40).
    #[test]
    fn do_command_alloc_pd_sends_fixture_frame_and_decodes_pd() {
        let blocks = parse_wire(ALLOC_FIX);
        let b = block(&blocks, "AllocPD");
        let (cap, exec) = mock_exec(Some(b.rx.clone()));
        let out = run_command(&AllocPD, exec).unwrap();
        assert_eq!(cap.borrow().as_slice(), b.tx.as_slice());
        assert_eq!(out.pd, 0x10);
    }

    #[test]
    fn do_command_create_mkey_sends_fixture_frame_and_decodes_index() {
        let blocks = parse_wire(ALLOC_FIX);
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
        let (cap, exec) = mock_exec(Some(b.rx.clone()));
        let out = run_command(&cmd, exec).unwrap();
        assert_eq!(cap.borrow().as_slice(), b.tx.as_slice());
        assert_eq!(out.mkey_index, 0x40);
    }

    /// Статус≠0 уже мапится Task-2-путём (exec_command → Err(Command)) —
    /// do_command прокидывает без собственной декодировки статуса.
    #[test]
    fn do_command_propagates_command_status_error() {
        let (_, exec) = mock_exec(None);
        let err = run_command(&AllocPD, exec).unwrap_err();
        assert_eq!(
            err,
            Error::Command(CmdStatusErr {
                status: 0x04,
                syndrome: 0x6c64fe,
            })
        );
    }

    /// (г) write_register оборачивает ACCESS_REGISTER: opcode 0x0805 @0..2,
    /// op_mod=0 (write, PRM) @4..6, register_id @10..12, argument @12..16,
    /// reg-данные @16 — кадр байт-в-байт против TX-фикстуры cap SET;
    /// readback декодируется с payload+8.
    #[test]
    fn write_register_wraps_access_register_cap_fixture() {
        let blocks = parse_wire(MTRC_FIX);
        let b = block(&blocks, "MTRC_CAP SET trace_owner=1 (");
        let reg = MtrcCapReg {
            trace_owner: true,
            ..Default::default()
        };
        let (cap, exec) = mock_exec(Some(b.rx.clone()));
        let readback = run_register_write(&reg, 0, exec).unwrap();
        assert_eq!(cap.borrow().as_slice(), b.tx.as_slice());
        assert!(readback.trace_owner);
        assert_eq!(readback.log_max_trace_buffer_size, 0x13);
        assert_eq!(readback.string_db_param[0].address, 0x00b4_6180);
    }

    /// header-размещение полей ACCESS_REGISTER: register_id по трейту,
    /// argument BE @12..16, op_mod 0 @4..6 (conf: id 0x9041).
    #[test]
    fn write_register_header_layout_register_id_and_argument() {
        let (cap, exec) = mock_exec(Some(vec![0u8; 0x90]));
        let reg = MtrcConfReg {
            trace_mode: 1,
            log_trace_buffer_size: 2,
            trace_mkey: 0x4042,
        };
        run_register_write(&reg, 0xdead_beef, exec).unwrap();
        let frame = cap.borrow();
        assert_eq!(&frame[0..2], &0x0805u16.to_be_bytes());
        assert_eq!(&frame[4..6], &[0, 0], "op_mod=0 (write)");
        assert_eq!(&frame[10..12], &0x9041u16.to_be_bytes());
        assert_eq!(&frame[12..16], &0xdead_beefu32.to_be_bytes());
        assert_eq!(REGISTER_OUTLEN, 144, "outlen по rx_len фикстр MTRC");
    }

    /// DENIED-вариант conf (фикстура): статус 0x04 / синдром 0x6c64fe
    /// прокидывается как Err(Command) через Task-2 маппинг.
    #[test]
    fn write_register_propagates_denied_status_error() {
        let (_, exec) = mock_exec(None);
        let reg = MtrcConfReg {
            trace_mode: 1,
            log_trace_buffer_size: 2,
            trace_mkey: 0x4042,
        };
        let err = run_register_write(&reg, 0, exec).unwrap_err();
        assert_eq!(
            err,
            Error::Command(CmdStatusErr {
                status: 0x04,
                syndrome: 0x6c64fe,
            })
        );
    }

    // ---------- Маршрутизация HCA-обменов на CMDQ (Task 10) ----------

    /// Окно для тестов: анонимный mmap + munmap на drop (паттерн dma.rs).
    struct TestWindow {
        ptr: *mut u8,
        len: usize,
    }

    impl TestWindow {
        fn new(pages: usize) -> Self {
            let len = pages * DMA_PAGE_SIZE;
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(p, libc::MAP_FAILED);
            TestWindow { ptr: p.cast(), len }
        }
    }

    impl Drop for TestWindow {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.ptr.cast(), self.len) };
        }
    }

    /// Шлюз + окно + BAR0-iseg живой карты (fw 16.35.4030, 64 слота × 64B):
    /// паттерн establish-теста, окружение routing-тестов Task 10. Init
    /// segment скриптуется в БАРО-пространство мока (fix round 8 —
    /// восстановление fix round 2), iseg-доступы — через MockBar0, шлюз —
    /// только CR/tool (hw_id).
    fn cmdq_env(pages: usize) -> (TestWindow, DmaAlloc, VsecTransport<MockConfig>) {
        let w = TestWindow::new(pages);
        let dma = DmaAlloc::over_window(w.ptr, w.len);
        let mock = MockConfig::new();
        mock.set_reg(MOCK_BAR0_SPACE, 0x0, (35u32 << 16) | 16); // fw 16.35
        mock.set_reg(MOCK_BAR0_SPACE, 0x4, (5u32 << 16) | 4030); // cmdif 5, subminor
        mock.set_reg(MOCK_BAR0_SPACE, 0x14, (6u32 << 4) | 6); // log_sz=6, log_stride=6
        mock.set_reg(MOCK_BAR0_SPACE, 0x1fc, 0); // initializing = 0
        let g = VsecTransport::open(mock).unwrap();
        (w, dma, g)
    }

    /// Бар0-обёртка окружения (establish через BAR0-мок, fix round 8).
    fn bar0_of(g: &VsecTransport<MockConfig>) -> MockBar0<'_> {
        MockBar0 { cfg: &g.cfg }
    }

    /// Wiring транспортного трейта сессии (Task 9, fix round 8 — BAR0):
    /// парс init segment + публикация hi/lo адресов окна порт-двордами
    /// @0x10/0x14 в BAR0-пространстве мока.
    #[test]
    fn establish_cmdq_wires_session_transport_and_dma_window() {
        let (_w, dma, g) = cmdq_env(16);
        let bar0 = bar0_of(&g);
        let q = establish_cmdq(&bar0, &dma, false).unwrap();
        assert_eq!(q.establishment().fw_rev_major, 16);
        assert_eq!(q.establishment().entries, 64);
        assert_eq!(q.establishment().queue_iova, dma.window_base() as u64);
        assert!(!q.is_poisoned());
        // Публикация — в BAR0-пространстве мока (hi/lo адреса окна);
        // CR-шлюз iseg НЕ трогает (fix round 8).
        let base = dma.window_base() as u64;
        assert_eq!(g.cfg.reg(MOCK_BAR0_SPACE, 0x10), (base >> 32) as u32);
        assert_eq!(
            g.cfg.reg(MOCK_BAR0_SPACE, 0x14),
            (base & 0xffff_f000) as u32
        );
        assert!(
            g.cfg.reg(0x2, 0x10) == 0 && g.cfg.reg(0x2, 0x14) == 0,
            "iseg-регистры не публикуются в CR-шлюз"
        );
    }

    /// Продовый Bar0Transport поверх мок-маппинга BAR0 (fix round 2,
    /// восстановлен fix round 8): iseg скриптуется BE-двордами в линейной
    /// памяти (wire-раскладка), establishment парсит их и публикует адрес
    /// очереди в ту же память (hi @0x10 первым, lo @0x14 с нулями в битах
    /// 11:0); CR-шлюз не участвует (ops пуст).
    #[test]
    fn bar0_transport_reads_iseg_and_receives_queue_publication() {
        use pci_driver::regions::{PciMemoryRegion, Permissions};
        // Линейный «BAR0»: 1 страница, wire-дворды BE.
        let len = 0x1000;
        let m = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(m, libc::MAP_FAILED);
        let wire_dword = |off: usize, v: u32| unsafe {
            for (i, b) in v.to_be_bytes().iter().enumerate() {
                (m as *mut u8).add(off + i).write_volatile(*b);
            }
        };
        wire_dword(0x0, (35u32 << 16) | 16);
        wire_dword(0x4, (5u32 << 16) | 4030);
        wire_dword(0x14, (6u32 << 4) | 6);
        wire_dword(0x1fc, 0);
        let region = unsafe { PciMemoryRegion::new_raw(m.cast(), len, Permissions::ReadWrite) };
        let bar = Bar0Transport { region };

        let w = TestWindow::new(16);
        let dma = DmaAlloc::over_window(w.ptr, w.len);
        let q = establish_cmdq(&bar, &dma, false).unwrap();
        assert_eq!(q.establishment().fw_rev_major, 16);
        assert_eq!(q.establishment().cmdif_rev, 5);
        assert_eq!(q.establishment().entries, 64);
        // Публикация в BAR-памяти: BE-дворды hi/lo (значение = swap слова).
        let base = dma.window_base() as u64;
        assert_eq!(
            bar.read32(0x10).unwrap(),
            ((base >> 32) as u32).swap_bytes()
        );
        assert_eq!(
            bar.read32(0x14).unwrap(),
            ((base & 0xffff_f000) as u32).swap_bytes()
        );
        // Чтение iseg через Bar0Transport даёт BE-значения после swap.
        assert_eq!(bar.read32(0x0).unwrap().swap_bytes(), (35u32 << 16) | 16);
        unsafe { libc::munmap(m, len) };
    }

    /// Fix round 8: iseg-доступы CMDQ НЕ заходят в VSEC-шлюз (BAR0 —
    /// единственный iseg-домен; 0.4-детур fix round 6 опровергнут попыткой
    /// 10, журнал §A10-2): establishment + пост + doorbell оставляют ops
    /// шлюза ПУСТЫМИ; AS_SEMAPHORE (0xa) не выбирается.
    #[test]
    fn cmdq_iseg_access_never_enters_vsec_gateway() {
        let blocks = parse_wire(FLOWTABLE_FIX);
        let b = block(&blocks, "flowtable create");
        let (_w, dma, g) = cmdq_env(8);
        let bar0 = bar0_of(&g);
        let q = establish_cmdq(&bar0, &dma, false).unwrap();
        assert_eq!(q.establishment().fw_rev_major, 16);
        g.cfg.push_completion(0, b.rx.clone());
        cmdq_exec(&q, &b.tx, b.rx.len() as u32, false).unwrap();
        let ops = g.cfg.ops();
        assert!(
            !ops.iter().any(|o| o == "w:0x44=0xe000000a"),
            "AS_SEMAPHORE не выбирается: {ops:?}"
        );
        assert!(
            ops.is_empty(),
            "шлюз не участвует в iseg/CMDQ-обменах (BAR0-домен): {ops:?}"
        );
    }

    /// Fix round 7 (журнал §A10+2, root cause попыток 7-10): Bus Master
    /// Enable пишется СТРОГО ДО маппинга DMA-окна — окно мапится под DMA,
    /// который без BME мёртв в источнике (FW не может выдать fetch-TLP:
    /// нет IOMMU-fault, очередь нетронута, dmesg чист). Порядок важен:
    /// establishment/посты после open обязаны застить устройство уже
    /// способным к DMA. Пин против регрессии последовательности open.
    /// Сбой BME → чистый Err(Io), окно не маплится.
    #[test]
    fn bus_master_enabled_before_dma_window_map() {
        let w = TestWindow::new(2);
        let (wp, wl) = (w.ptr, w.len);
        let log = Rc::new(RefCell::new(Vec::new()));
        let l_bme = Rc::clone(&log);
        let l_map = Rc::clone(&log);
        let _dma = open_device_io(
            move || {
                l_bme.borrow_mut().push("bme");
                Ok(())
            },
            move || {
                l_map.borrow_mut().push("map");
                Ok(DmaAlloc::over_window(wp, wl))
            },
        )
        .unwrap();
        drop(_dma);
        assert_eq!(*log.borrow(), vec!["bme", "map"], "BME до маппинга окна");

        let log2 = Rc::new(RefCell::new(Vec::new()));
        let l_fail = Rc::clone(&log2);
        let l_never = Rc::clone(&log2);
        let err = open_device_io(
            move || {
                l_fail.borrow_mut().push("bme-fail");
                Err(std::io::Error::other("config write rejected"))
            },
            move || {
                l_never.borrow_mut().push("map");
                unreachable!("map не вызывается при сбое BME")
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Io(ref s) if s.to_lowercase().contains("bus master")),
            "сбой BME — Err(Io): {err}"
        );
        assert_eq!(*log2.borrow(), vec!["bme-fail"]);
    }

    /// exec/try_exec поверх CMDQ (routing): кадр flowtable create (64B:
    /// inline 16B + in-mailbox; rx 64B: out-inline + out-цепочка) доставлен
    /// устройству байт-точно; try_exec — (out-кадр целиком, статус = rx[0]);
    /// exec — payload rx[8..] (фикстура: table_id 0x28000000 @payload[0..4]).
    #[test]
    fn exec_over_cmdq_composes_fixture_rx_happy_path() {
        let blocks = parse_wire(FLOWTABLE_FIX);
        let b = block(&blocks, "flowtable create");
        let (_w, dma, g) = cmdq_env(8);
        let bar0 = bar0_of(&g);
        let q = establish_cmdq(&bar0, &dma, false).unwrap();
        g.cfg.push_completion(0, b.rx.clone());
        let (out, status) = cmdq_try_exec(&q, &b.tx, b.rx.len() as u32, false).unwrap();
        assert_eq!(status, 0x00);
        assert_eq!(out, b.rx);
        assert_eq!(
            g.cfg.tx_log.borrow()[0].0.as_slice(),
            b.tx.as_slice(),
            "TX-кадр доставлен байт-точно (inline + цепочка)"
        );
        g.cfg.push_completion(0, b.rx.clone());
        let payload = cmdq_exec(&q, &b.tx, b.rx.len() as u32, false).unwrap();
        assert_eq!(payload, b.rx[8..]);
        assert_eq!(&payload[..4], &[0x28, 0x00, 0x00, 0x00]);
    }

    /// Негативная комплитка (NONEXISTENT, фикстура): статус 0x03 / синдром
    /// 0x001c2b78 из out-кадра → Err(Command) в exec; try_exec — статус
    /// вторым элементом пары, out-кадр целиком (контракт Task 2 сохранён).
    #[test]
    fn exec_over_cmdq_error_status_maps_to_command_err_with_fixture_values() {
        let blocks = parse_wire(FLOWTABLE_FIX);
        let b = block(&blocks, "NONEXISTENT");
        let (_w, dma, g) = cmdq_env(8);
        let bar0 = bar0_of(&g);
        let q = establish_cmdq(&bar0, &dma, false).unwrap();
        g.cfg.push_completion(0, b.rx.clone());
        let err = cmdq_exec(&q, &b.tx, b.rx.len() as u32, false).unwrap_err();
        assert_eq!(
            err,
            Error::Command(CmdStatusErr {
                status: 0x03,
                syndrome: 0x001c_2b78,
            })
        );
        g.cfg.push_completion(0, b.rx.clone());
        let (out, status) = cmdq_try_exec(&q, &b.tx, b.rx.len() as u32, false).unwrap();
        assert_eq!(status, 0x03);
        assert_eq!(out, b.rx);
    }

    /// POISONED-распространение: таймаут CQE → все командные пути fail-fast
    /// («poisoned»), без нового doorbell — до re-open (правило Task 10;
    /// публичные методы делегируют этим же функциям).
    #[test]
    fn poisoned_cmdq_fail_fasts_exchanges_without_new_doorbell() {
        let blocks = parse_wire(FLOWTABLE_FIX);
        let b = block(&blocks, "flowtable create");
        let (_w, dma, g) = cmdq_env(8);
        let bar0 = bar0_of(&g);
        // Короткий инжектированный дедлайн (fix round 3: wall-clock, прод —
        // 60 с; тест не спит минуту).
        let q = crate::cmdq::Cmdq::establish_with_deadline(
            &bar0,
            &dma,
            false,
            std::time::Duration::from_millis(30),
        )
        .unwrap();
        g.cfg.hold_owner.set(true);
        assert!(matches!(
            cmdq_exec(&q, &b.tx, 16, false),
            Err(Error::Timeout)
        ));
        let bells = g.cfg.doorbells.get();
        let err = cmdq_exec(&q, &b.tx, 16, false).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("poisoned"), "{err}");
        let err2 = cmdq_try_exec(&q, &b.tx, 16, false).unwrap_err();
        assert!(
            err2.to_string().to_lowercase().contains("poisoned"),
            "{err2}"
        );
        assert_eq!(
            g.cfg.doorbells.get(),
            bells,
            "fail-fast без нового doorbell"
        );
    }

    /// Plan ruling (Task 10): вокруг CMDQ-обменов semaphore62 НЕ берётся
    /// (старый бинарник гонял CMDQ параллельно mstreg GCIF-маркерам, ×5
    /// сессий) — AS_SEMAPHORE (0xa) никогда не выбирается; остаётся только
    /// cap9-семафор шлюза (внутри dword_rw). Пин против регрессии
    /// (форма fix round 2, восстановлена fix round 8).
    #[test]
    fn cmdq_exchanges_never_enter_semaphore_space() {
        let blocks = parse_wire(FLOWTABLE_FIX);
        let b = block(&blocks, "flowtable create");
        let (_w, dma, g) = cmdq_env(8);
        let bar0 = bar0_of(&g);
        let q = establish_cmdq(&bar0, &dma, false).unwrap();
        g.cfg.push_completion(0, b.rx.clone());
        cmdq_exec(&q, &b.tx, b.rx.len() as u32, false).unwrap();
        let ops = g.cfg.ops();
        assert!(
            !ops.iter().any(|o| o == "w:0x44=0xe000000a"),
            "AS_SEMAPHORE не выбирается: {ops:?}"
        );
        assert!(
            ops.is_empty(),
            "CR-шлюз не участвует в CMDQ-обменах (iseg/doorbell — BAR0): {ops:?}"
        );
    }

    /// busy (0x5) → ровно один повтор (паритет icmd try_exec_full),
    /// затем итог как есть.
    #[test]
    fn exec_over_cmdq_retries_busy_once() {
        let blocks = parse_wire(FLOWTABLE_FIX);
        let b = block(&blocks, "flowtable create");
        let (_w, dma, g) = cmdq_env(8);
        let bar0 = bar0_of(&g);
        let q = establish_cmdq(&bar0, &dma, false).unwrap();
        let mut busy = vec![0u8; 16];
        busy[0] = STATUS_BUSY;
        g.cfg.push_completion(0, busy);
        g.cfg.push_completion(0, b.rx.clone());
        let payload = cmdq_exec(&q, &b.tx, b.rx.len() as u32, false).unwrap();
        assert_eq!(payload, b.rx[8..]);
        assert!(
            g.cfg.completions.borrow().is_empty(),
            "обе комплитки потреблены (ровно один retry)"
        );
        assert_eq!(g.cfg.doorbells.get(), 2, "ровно один retry");
    }

    // ---------- HCA-init-цепочка поверх CMDQ (Task 10) ----------

    /// Фейковый аллокатор страниц wire-канона arm.log: очередь — страница 0
    /// окна, boot-страницы с 0x10001000, init — с 0x10007000 (0x10001000 +
    /// 6×0x1000): адреса фикстр ManagePages воспроизводятся точно.
    fn wire_alloc() -> impl FnMut(usize) -> Result<Vec<u64>> {
        let mut next = 0x1000_1000u64;
        move |n: usize| -> Result<Vec<u64>> {
            let v = (0..n as u64).map(|i| next + i * 0x1000).collect();
            next += n as u64 * 0x1000;
            Ok(v)
        }
    }

    /// Полная цепочка поверх CMDQ: 9 кадров wire-последовательности arm.log
    /// БАЙТ-ТОЧНО против фикстр (вкл. ManagePages init 20808B = 2599 записей
    /// ОДНИМ кадром через блочную цепочку — icmd-чанкинг удалён), outlen-ы
    /// по wire (QueryISSI 112, QueryHCACap 4112 — out-цепочки).
    #[test]
    fn init_chain_over_cmdq_emits_wire_sequence_byte_exact() {
        let blocks = parse_wire(CMDQ_INIT_FIX);
        assert_eq!(blocks.len(), 9);
        let (_w, dma, g) = cmdq_env(64);
        let bar0 = bar0_of(&g);
        let q = establish_cmdq(&bar0, &dma, false).unwrap();
        for b in &blocks {
            g.cfg.push_completion(0, b.rx.clone());
        }
        let mut alloc = wire_alloc();
        hca_init_chain(
            &mut |frame: &[u8], outlen: u32| cmdq_exec(&q, frame, outlen, false),
            &mut alloc,
        )
        .unwrap();

        let log = g.cfg.tx_log.borrow();
        // wire-порядок: EnableHCA → QueryISSI → SetISSI → QueryPages(boot) →
        // ManagePages → QueryHCACap → QueryPages(init) → ManagePages →
        // InitHCA — без re-query между фазами и без чанков.
        let ops: Vec<u16> = log
            .iter()
            .map(|(f, _)| u16::from_be_bytes([f[0], f[1]]))
            .collect();
        assert_eq!(
            ops,
            [
                OP_ENABLE_HCA,
                OP_QUERY_ISSI,
                OP_SET_ISSI,
                OP_QUERY_PAGES,
                OP_MANAGE_PAGES,
                OP_QUERY_HCA_CAP,
                OP_QUERY_PAGES,
                OP_MANAGE_PAGES,
                OP_INIT_HCA,
            ],
            "wire-порядок без re-query и чанков"
        );
        for (i, b) in blocks.iter().enumerate() {
            assert_eq!(log[i].0, b.tx, "кадр #{i} ({}) байт-точно", b.ctx);
        }
        let outlens: Vec<u32> = log.iter().map(|(_, o)| *o).collect();
        assert_eq!(
            outlens,
            [16, 112, 16, 16, 16, 4112, 16, 16, 16],
            "outlen-ы по wire (QueryISSI 112, QueryHCACap 4112)"
        );
        assert_eq!(
            log[7].0.len(),
            MANAGE_PAGES_HEADER + 2599 * MANAGE_PAGES_ENTRY,
            "ManagePages init: 2599 записей одним кадром"
        );
    }

    /// Сбой строгого шага (EnableHCA статус 3 / синдром 0x001c2b78 — значения
    /// фикстры NONEXISTENT) → Err(Command), цепочка дальше не идёт.
    #[test]
    fn init_chain_enable_hca_failure_yields_command_err() {
        let (_w, dma, g) = cmdq_env(8);
        let bar0 = bar0_of(&g);
        let q = establish_cmdq(&bar0, &dma, false).unwrap();
        let mut neg = vec![0u8; 16];
        neg[0] = 0x03;
        neg[4..8].copy_from_slice(&0x001c_2b78u32.to_be_bytes());
        g.cfg.push_completion(0, neg);
        let mut alloc = wire_alloc();
        let err = hca_init_chain(
            &mut |frame: &[u8], outlen: u32| cmdq_exec(&q, frame, outlen, false),
            &mut alloc,
        )
        .unwrap_err();
        assert_eq!(
            err,
            Error::Command(CmdStatusErr {
                status: 0x03,
                syndrome: 0x001c_2b78,
            })
        );
        assert_eq!(g.cfg.tx_log.borrow().len(), 1, "только EnableHCA");
    }

    /// Толерантная пара ISSI: сбой QueryISSI → SetISSI пропущен, цепочка
    /// доходит до InitHCA (kernel-семантика pagealloc/init).
    #[test]
    fn init_chain_tolerates_issi_failure_and_reaches_init_hca() {
        let blocks = parse_wire(CMDQ_INIT_FIX);
        let (_w, dma, g) = cmdq_env(64);
        let bar0 = bar0_of(&g);
        let q = establish_cmdq(&bar0, &dma, false).unwrap();
        // EnableHCA ok; QueryISSI — негативная комплитка; далее wire-кадры
        // без SetISSI (с QueryPages(boot)).
        g.cfg.push_completion(0, blocks[0].rx.clone());
        let mut neg = vec![0u8; 16];
        neg[0] = 0x03;
        g.cfg.push_completion(0, neg);
        for b in &blocks[3..] {
            g.cfg.push_completion(0, b.rx.clone());
        }
        let mut alloc = wire_alloc();
        hca_init_chain(
            &mut |frame: &[u8], outlen: u32| cmdq_exec(&q, frame, outlen, false),
            &mut alloc,
        )
        .unwrap();
        let log = g.cfg.tx_log.borrow();
        let ops: Vec<u16> = log
            .iter()
            .map(|(f, _)| u16::from_be_bytes([f[0], f[1]]))
            .collect();
        assert!(
            !ops.contains(&OP_SET_ISSI),
            "SetISSI пропущен после сбоя query"
        );
        assert_eq!(ops.first(), Some(&OP_ENABLE_HCA));
        assert_eq!(ops.last(), Some(&OP_INIT_HCA));
    }
}
