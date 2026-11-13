// Источник: ConnectX PRM (refs/docs/ethernet-adapters-programming-manual.pdf)
// §7.14 Command Interface: Table 95/96 — layout полей 64B command queue
// entr (type=0x7 PCIe_cmd_if_transport, input_length, in/out mailbox pointer
// BE64, in/out inline data по 16B, output_length, token/signature/status/
// ownership в байте 3Ch; ownership: SW=1 при посте, HW сбрасывает в 0;
// status биты 7:1 — статус доставки, SW пишет 0); Table 97/98 — mailbox-блок
// 576B: data 512B @0x0, next_pointer BE64 @0x230 (0 = последний), block
// number BE32 @0x238 (последовательно с 0), token @0x23D, ctrl_signature
// @0x23E, signature @0x23F; §7.14.1.1.1 — подписи: ctrl_signature = ~xor
// байт 1C0h-1FFh, signature = ~xor всего блока без самого байта; для output-
// блоков SW считает ТОЛЬКО ctrl_signature; подпись entr — 8 бит xor без
// mailbox; первый 16B команды — inline в entr, остаток — в mailbox-цепочке;
// «If the mailbox data is larger than the size of the mailbox-data field,
// the first part of the data will be in the first mailbox block…» (блочный
// chaining); Table 7/8 Initialization Segment: fw_rev_minor[31:16]/
// fw_rev_major[15:0] @0x0, cmd_interface_rev[31:16]/fw_rev_subminor[15:0]
// @0x4, cmdq_phy_addr[63:32] @0x10, cmdq_phy_addr[31:12]|nic_interface|
// log_cmdq_size[7:4]|log_cmdq_stride[3:0] @0x14, command DoorBell vector
// @0x18 (WO, «Bit per command in the cmdq… bit 0 is related to the command
// in offset 0»), initializing бит 31 @0x1FC; §8.2 HCA Driver Start-up:
// очередь — «physically contiguous 4KB memory chunk aligned on its size»,
// публикация адреса «If using 32-bit writes, write the most significant
// word first», nic_interface/log_cmdq_size/log_cmdq_stride в lo-слове = 0;
// после записи адреса — «Read the initializing field… Repeat until it is
// cleared»; завершение — полл ownership-бита («SW can poll the ownership
// bit in the command»), EQ не создаём.
// Linux v7.2 (refs/src/linux/linux-7.2 — facts-only кросс-чек, GPL-выражение
// не переносится): include/linux/mlx5/device.h — struct mlx5_cmd_layout,
// mlx5_init_seg (cmd_dbell @0x18), mlx5_cmd_prot_block (data[512]+48+next+
// block_num+token/ctrl_sig/sig = 576B), MLX5_CMD_DATA_BLOCK_SIZE=512;
// mlx5_ifc.h — mlx5_ifc_initial_seg_bits (command_doorbell_vector),
// mlx5_ifc_cmd_if_box_bits (mailbox_data[512]); drivers/net/ethernet/
// mellanox/mlx5/core/cmd.c — mlx5_cmd_enable: log_sz=(cmdq_addr_l_sz&0xff)
// >>4, log_stride=&0xf (:2479-2484), публикация iowrite32be(cmd_h) затем
// iowrite32be(cmd_l) (:2523-2524); пост: memset entr → поля → status_own=HW
// → подпись → «ring doorbell after the descriptor is valid»
// iowrite32be(1<<idx, &iseg->cmd_dbell) (:1044-1073); полл ownership с
// ограничением (poll_timeout); mlx5_alloc_cmd_msg — цепочка блоков,
// block_num с 0, next=BE64 (:1463-1506); token инкрементируется, 0
// пропускается (alloc_token :150-162); checksum_disabled=1 в mlx5_cmd_init
// v7.2 (:2437) — подписи mailbox на драйвере опциональны, наш канон — PRM +
// wire; main.c — wait на initializing бит 31.
// Wire-артефакты Task 1 (/tmp/opencode/wire): trig-p0safe.log — CQE 64B
// @0x10000000 (BE-поля лейаута PRM Table 95; очередь старого бинарника — с
// базы DMA-окна), in_mb0/out_mb0 576B @0x10a2e000/0x10a2e400 (внутри окна,
// 0x400-выравнивание блоков), in_mb0 подписи совпадают с формулами PRM
// (ctrl_sig=0x78=~xor[1C0h:200h], sig=0xfa); arm.log/arm2.log — init-цепочка
// TX/RX и ManagePages 0xa27=2599 записей (20808B, arm2.log:19025) — вход за
// пределами inline обязан ехать блочным списком. Расхождение со старым
// бинарником (осознанное, по PRM): out-mailbox указатель только при
// outlen>16 (старый ставил out_mb0 всегда — trig CQE); token в entr и
// блоках по PRM одинаковый (в wire-захвате трига оба 0x00 — расхождения
// нет; итоговый header-декод: token @0x3c=0x00, sig @0x3d=0xf6).
// Fix round 3 (живой гейт попытка 7): CQE-ожидание — wall-clock дедлайн
// 60 с kernel-града (kernel poll_timeout: таймаут команды CMD 60 с + запас;
// бюджет 1000 поллов × 1мс ≈ 65 мс убивал первый EnableHCA), лесенка сна
// 1мс→10мс; на истечении — полная таймаут-диагностика (постед-entr hex,
// doorbell значение/регистр, cmdq_addr/initializing init segment, последний
// dword CQE) — артефакт разбора «FW не видел doorbell» vs «entr отвергнут»
// vs «медленно» для следующей живой попытки.
// Fix round 2 (живой гейт попытка 6): ДОМЕН init segment/doorbell —
// линейный BAR0 (kernel main.c:894 `dev->iseg = ioremap(dev->bar_addr, …)`;
// живой факт: gateway-CR 0.0 — регистр cmd_ptr (попытка 6 читала его
// значение 0x2000 как fw_rev_major), НЕ init segment). Transport для
// Cmdq — BAR0-доступ (сессия: Bar0Transport); VSEC-шлюз — только
// CR-space/tool-класс (подтверждён обратно fix round 8 после опровержения
// 0.4-детура).
// Fix round 6 (0.4-детур, breaker-adjudicated по попыткам 7-9) — REFUTED
// live попыткой 10, откачен fix round 8: чтение cmdq_addr_l_sz через
// AS_NODNIC_INIT_SEG (0x4) шлюза декодируется как log_sz=11 (мусор), BAR0
// того же регистра — валидное 0x10000056 (log_sz 5/stride 6) — журнал
// task-07 §A10-2: 0.4-view НЕ iseg-зеркало (иной лейаут/офсеты или
// FW-trapped семантика без iseg-регистров на тех же офсетах);
// establishment валидно отказал ДО поста (информации о самом doorbell
// 0.4-путь не дал; BAR0 — единственный вид, читавший валидный iseg).
// Fix round 8: iseg-домен СНОВА линейный BAR0 (Bar0Transport, форма fix
// round 2). Root cause нетронутой очереди (попытки 7-10) найден отдельно:
// PCI Bus Master Enable (fix round 7, журнал §A10+2) — без BME FW не может
// выдать CMDQ-fetch DMA TLP; BME-фикс действует (при open, после
// опционального FLR, до маппинга окна/establishment).
// Fix round 4 (разбор живой попытки 8): главный подозреваемый «initializing
// @0x1fc читается как 0x47 → бит 0 = FW грузится» ОПРОВЕРГНУТ сверкой с
// refs (verify-before-fix): (1) таймаут-диагностика печатает read32()
// .swap_bytes() = BE-ЗНАЧЕНИЕ регистра — живое 0x47000000 это значение
// (wire-байты 47 00 00 00), а не сырое слово; (2) initializing — бит 31
// BE-значения, НЕ бит 0: kernel main.c:133-134 wait_fw_init
// («fw_initializing = ioread32be(&dev->iseg->initializing); if
// (!(fw_initializing >> 31)) break;»), mlx5_ifc.h initial_seg_bits —
// initializing[0x1] сразу после reserved_at_e0[0xf00] = бит 0xfe0 =
// старший бит байта 0x1fc; хвост 0x47 живого значения —
// nic_interface_supported/reserved (ifc-биты fe1..fe8), steady-state;
// (3) «FW вечно initializing» противоречит OLD-бинарю, армящемуся в той
// же точке. wait_fw_ready и раньше проверял бит 31 в swap-домене —
// ложного pass не было. Реальные слабые места закрыты kernel-стилем:
// pre-parse initializing-wait теперь БЕЗУСЛОВЕН (kernel wait_fw_init
// ДО mlx5_cmd_enable, main.c:1104-1125), дедлайн wall-clock 120 с =
// kernel FW_PRE_INIT_TIMEOUT_MS (lib/tout.c:12; бюджет 1024 поллов
// ≈ 65 мс не пережил бы FW-init после FLR), дедлайн инжектируем
// (establish_with_timeouts), таймаут — чистый Err(Timeout)
// (establishment провален, очередь НЕ опубликована — POISON не нужен).
// Аудит iseg-доступов fix round 4 (raw/value-дисциплина: слово транспорта
// = LE-нагрузка wire, значение регистра = swap; iseg-дворды BE): чтения
// @0x0/@0x4/@0x14 — swap → BE-значение, поля из значения; публикация
// @0x10/@0x14 — write32(swap(значение)) = wire BE, hi→lo (PRM §8.2);
// doorbell @0x18 — значение 1<<slot, слово = swap(1) = wire BE. Других
// raw/value-ошибок аудит не нашёл.
// Fix round 5 (живой гейт: первый пост — entry валиден, очередь 60 с
// нетронута; расходимость с kernel/OLD-потоком не видна в текущей
// диагностике — делаем её ВИДИМОЙ): establishment и таймаут-диагностика
// печатают полный дамп init segment (0x000..0x200 = 128 двордов, 16 на
// строку, BE/wire-порядок — тот же вид, что dd if=/sys/.../resource0) и
// дамп первых 128B памяти очереди С НАШЕЙ стороны маппинга (queue header —
// что FW обязан видеть по опубликованному адресу). Чтения в диагностике
// толерантны (сбой дворда → «????????», байта → «??»: диагностика не
// маскирует Timeout и не паникует). Аудит region-I/O (fix round 5):
// PciRegion в pci-driver — all-or-Err (VFIO-бэкенд read_exact_at/
// write_all_at — короткого I/O не бывает), write_region/read_region cmdq
// проверяют каждую операцию, Bar0Transport — map_err на каждый доступ
// (fix round 8: iseg снова BAR0); единственный
// проглоченный WRITE-сбой — release cap9-семафора VSEC-шлюза (session.rs
// sem_release) — теперь прокидывается/логируется.
//
// POISONED-дисциплина: таймаут CQE-полла переводит Cmdq в poisoned — все
// последующие операции fail-fast до re-establish (re-open/FLR на уровне
// сессии, Task 10); командные/доставка-ошибки сессию не травят (чистый
// откат: FW вернул ownership, блоки возвращаются в пул Drop'ом guard'ов).

use std::cell::Cell;

use pci_driver::regions::PciRegion;

use crate::dma::{AllocationGuard, DMA_PAGE_SIZE, DmaAlloc};
use crate::err::{Error, Result};
use crate::mailbox::Transport;

/// Размер entr command queue: 64B (PRM Table 95; stride 1<<log_cmdq_stride ≥ этого).
pub const CMDQ_ENTRY_SIZE: usize = 64;
/// Mailbox-блок: 576B (PRM Table 97: data 512 + ctrl 64).
pub const MAILBOX_BLOCK_SIZE: usize = 576;
/// Данные mailbox-блока: 512B (PRM Table 98; MLX5_CMD_DATA_BLOCK_SIZE).
pub const MAILBOX_DATA_SIZE: usize = 512;
/// Inline-часть команды в entr: первые 16B (PRM §7.14.1).
pub const CMDQ_INLINE_SIZE: usize = 16;

/// Init segment (PRM Table 7/8; mlx5_ifc.h initial_seg; BE-дворды):
/// cmdq_phy_addr[63:32] — старшее слово адреса очереди.
pub const INITSEG_CMDQ_ADDR_H: usize = 0x10;
/// cmdq_phy_addr[31:12]|nic_interface|log_cmdq_size|log_cmdq_stride.
pub const INITSEG_CMDQ_ADDR_L_SZ: usize = 0x14;
/// command DoorBell vector (WO): бит на слот, бит 0 = команда @ offset 0.
pub const INITSEG_DBELL: usize = 0x18;
/// initializing — бит 31 BE-ЗНАЧЕНИЯ дворда @0x1fc (kernel main.c:133-134
/// wait_fw_init: `ioread32be(&iseg->initializing) >> 31`; mlx5_ifc.h
/// initial_seg_bits: initializing[0x1] = старший бит байта 0x1fc): 1 — FW
/// ещё грузится, 0 — готов принимать команды. В слове транспорта
/// (LE-нагрузка wire-байтов) этот бит живёт как бит 7 — raw-домен проверка
/// без swap даёт ложный pass (класс ошибки разбора попытки 8).
pub const INITSEG_INITIALIZING: usize = 0x1fc;

/// type = 0x7: PCIe_cmd_if_transport (PRM Table 96).
const CMD_TYPE_PCI_XPORT: u8 = 0x7;
/// Бит ownership: SW выставляет 1 при посте, HW сбрасывает в 0 (PRM Table 96).
const CMD_OWNER_HW: u8 = 0x1;
/// Дедлайн ожидания CQE ownership-бита (wall-clock): 60 с kernel-града
/// (kernel poll_timeout: таймаут команды CMD 60 с + 1 с запас; fix round 3,
/// живой гейт попытка 7: бюджет 1000 поллов × 1мс/16 ≈ 65 мс убивал первый
/// EnableHCA). Полл-интервал — лесенка 1мс (первые 16 поллов) → 10мс, чтобы
/// не молотить BAR. Дедлайн истёк → Err(Timeout) + POISON + диагностика.
pub const CMDQ_CQE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
/// Дедлайн initializing-wait (wall-clock, fix round 4): 120 с = kernel
/// FW_PRE_INIT_TIMEOUT_MS (lib/tout.c:12; kernel wait_fw_init — jiffies-дедлайн
/// в msleep-цикле; после FLR FW-init идёт секунды — бюджет поллов не жил бы).
/// Истёк → чистый Err(Timeout): establishment провален, очередь не
/// опубликована, POISON не нужен.
pub const CMDQ_INIT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);
/// Legacy (fix round 4): бюджет поллов initializing заменён wall-clock
/// дедлайном [`CMDQ_INIT_DEADLINE`]; константа оставлена для стабильности API.
pub const MAX_INIT_POLLS: usize = 1024;
/// Длина полного дампа init segment (fix round 5): 0x200 байт = 128 двордов
/// (PRM Table 7/8 целиком, включая initializing @0x1fc) — вид для побайтового
/// сравнения с `dd if=/sys/.../resource0`.
const ISEG_DUMP_LEN: usize = 0x200;
/// Дамп заголовка очереди на CQE-таймауте (fix round 5): первые 128B памяти
/// очереди с нашей стороны маппинга (2 слота × 64B: постед-entr + сосед).
const QUEUE_WINDOW_DUMP_LEN: usize = 128;
/// Лимит очереди: 1<<log_sz ≤ 256 слотов (256×64B = 16КБ = 4 страницы окна).
const MAX_LOG_CMDQ_SIZE: u32 = 8;

/// Результат establishment: разобранный init segment (PRM Table 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdqEstablishInfo {
    pub fw_rev_major: u16,
    pub fw_rev_minor: u16,
    pub fw_rev_subminor: u16,
    pub cmdif_rev: u16,
    pub log_cmdq_size: u32,
    pub log_cmdq_stride: u32,
    /// Слотов в очереди: 1 << log_cmdq_size.
    pub entries: usize,
    /// Шаг слота в байтах: 1 << log_cmdq_stride (≥ CMDQ_ENTRY_SIZE).
    pub stride: usize,
    /// Страниц DmaAlloc под очередь.
    pub queue_pages: usize,
    /// IOVA опубликованной очереди (vaddr identity-окна).
    pub queue_iova: u64,
}

/// Завершённая команда: собранный output (inline + out-цепочка, outlen байт),
/// token (из CQE — эхо поста) и статус доставки (биты 7:1 status_own).
/// Командный статус/syndrome — в output[0]/output[4..8], интерпретация —
/// слой сессии (как outbox icmd-мейнлбокса).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdqCompletion {
    pub output: Vec<u8>,
    pub token: u8,
    pub delivery: u8,
}

/// Декод 64B entr (PRM Table 95; все поля BE). Используется для чтения
/// комплитки из памяти очереди и как wire-пин лейаута в тестах (CQE-фикстры).
#[allow(dead_code)]
pub(crate) struct EntryView {
    pub entry_type: u8,
    pub inlen: u32,
    pub in_ptr: u64,
    pub in_inline: [u8; CMDQ_INLINE_SIZE],
    pub out_inline: [u8; CMDQ_INLINE_SIZE],
    pub out_ptr: u64,
    pub outlen: u32,
    pub token: u8,
    pub owner_hw: bool,
    /// Статус доставки: биты 7:1 status_own (0x0 = без ошибок).
    pub delivery: u8,
}

pub(crate) fn decode_entry(buf: &[u8]) -> EntryView {
    assert_eq!(buf.len(), CMDQ_ENTRY_SIZE, "entr = 64B");
    let mut in_inline = [0u8; CMDQ_INLINE_SIZE];
    in_inline.copy_from_slice(&buf[0x10..0x20]);
    let mut out_inline = [0u8; CMDQ_INLINE_SIZE];
    out_inline.copy_from_slice(&buf[0x20..0x30]);
    let status_own = buf[0x3f];
    EntryView {
        entry_type: buf[0],
        inlen: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
        in_ptr: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
        in_inline,
        out_inline,
        out_ptr: u64::from_be_bytes(buf[0x30..0x38].try_into().unwrap()),
        outlen: u32::from_be_bytes(buf[0x38..0x3c].try_into().unwrap()),
        token: buf[0x3c],
        owner_hw: status_own & CMD_OWNER_HW != 0,
        delivery: (status_own >> 1) & 0x7f,
    }
}

/// xor всех байтов (подписи PRM 7.14.1.1.1).
fn xor8(b: &[u8]) -> u8 {
    b.iter().fold(0u8, |a, x| a ^ x)
}

/// Собрать 576B mailbox-блок (PRM Table 97/98): data (добивается нулями до
/// 512B), next BE64, block_num BE32, token, ctrl_signature = ~xor(1C0h-1FFh),
/// signature = ~xor(блока без sig) — для output-блоков sig не считаем
/// (его пишет FW; PRM: SW считает ctrl_signature выходных блоков).
fn encode_block(
    data: &[u8],
    next: u64,
    block_num: u32,
    token: u8,
    out_block: bool,
) -> [u8; MAILBOX_BLOCK_SIZE] {
    let mut b = [0u8; MAILBOX_BLOCK_SIZE];
    b[..data.len().min(MAILBOX_DATA_SIZE)]
        .copy_from_slice(&data[..data.len().min(MAILBOX_DATA_SIZE)]);
    b[0x230..0x238].copy_from_slice(&next.to_be_bytes());
    b[0x238..0x23c].copy_from_slice(&block_num.to_be_bytes());
    b[0x23d] = token;
    b[0x23e] = !xor8(&b[0x1c0..0x200]);
    if !out_block {
        b[0x23f] = !xor8(&b[..0x23f]);
    }
    b
}

/// Живой блок цепочки: страница окна (0x1000-выравнивание ⊇ 1024-выравнивание
/// mailbox-указателей PRM «aligned to mailbox size», kernel dma_pool
/// roundup_pow_of_two(576)=1024; wire: in_mb0/out_mb0 @…000/…400) + адрес.
struct LiveBlock {
    guard: AllocationGuard,
    iova: u64,
}

/// Выделить цепочку из n блоков (по странице на блок) и записать данные:
/// data нарезается кусками по 512B, block_num последовательно с 0,
/// next-указатели связывают блоки (последний — 0), token в каждом блоке.
fn build_chain(dma: &DmaAlloc, data: &[u8], token: u8, out_block: bool) -> Result<Vec<LiveBlock>> {
    let n = data.len().div_ceil(MAILBOX_DATA_SIZE);
    let mut blocks = Vec::with_capacity(n);
    for _ in 0..n {
        let guard = dma.alloc(1).ok_or_else(|| {
            Error::Io("cmdq: dma-окно исчерпано (нужна страница mailbox-блока)".into())
        })?;
        let iova = guard
            .as_ptr()
            .ok_or_else(|| Error::Io("cmdq: dma-страница без указателя".into()))?
            as usize as u64;
        blocks.push(LiveBlock { guard, iova });
    }
    for (i, b) in blocks.iter().enumerate() {
        let end = ((i + 1) * MAILBOX_DATA_SIZE).min(data.len());
        let chunk = &data[i * MAILBOX_DATA_SIZE..end];
        let next = blocks.get(i + 1).map_or(0, |nb| nb.iova);
        let block = encode_block(chunk, next, i as u32, token, out_block);
        write_region(&b.guard, 0, &block)?;
    }
    Ok(blocks)
}

/// Запись байтов в DMA-регион (volatile, побайтно — у PciRegion нет
/// write_bytes; wire-порядок байтов сохраняется как есть).
fn write_region(g: &AllocationGuard, off: usize, data: &[u8]) -> Result<()> {
    for (i, b) in data.iter().enumerate() {
        g.write_u8((off + i) as u64, *b)
            .map_err(|e| Error::Io(format!("cmdq dma write @{off:#x}+{i}: {e}")))?;
    }
    Ok(())
}

/// Чтение байтов из DMA-региона.
fn read_region(g: &AllocationGuard, off: usize, len: usize) -> Result<Vec<u8>> {
    let mut v = Vec::with_capacity(len);
    for i in 0..len {
        let b = g
            .read_u8((off + i) as u64)
            .map_err(|e| Error::Io(format!("cmdq dma read @{off:#x}+{i}: {e}")))?;
        v.push(b);
    }
    Ok(v)
}

/// Полный дамп init segment (fix round 5): [`ISEG_DUMP_LEN`] байт сырыми
/// двордами, 16 на строку с метками офсетов. Печатается BE-ЗНАЧЕНИЕ дворда
/// ({:08x} от swap транспортного слова): цифры совпадают с побайтовым
/// hex-видом `dd if=/sys/.../resource0 | xxd` — wire-порядок. Чтения
/// толерантные (диагностика): сбой дворда → «????????», не паникует и не
/// маскирует исходную ошибку.
fn render_iseg_dump(seg: &dyn Transport) -> String {
    let mut lines = Vec::new();
    for line in 0..ISEG_DUMP_LEN / 4 / 16 {
        let base = line * 16 * 4;
        let dwords: Vec<String> = (0..16)
            .map(|i| {
                seg.read32(base + i * 4)
                    .map(|w| format!("{:08x}", w.swap_bytes()))
                    .unwrap_or_else(|_| "????????".to_string())
            })
            .collect();
        lines.push(format!("{base:03x}: {}", dwords.join(" ")));
    }
    lines.join("\n")
}

/// Дамп первых `len` байт памяти очереди с нашей стороны маппинга DMA-окна
/// (fix round 5): 16 байт на строку с метками офсетов — что FW обязан видеть
/// по опубликованному адресу (queue header). Толерантно: сбой байта → «??».
fn render_window_dump(g: &AllocationGuard, len: usize) -> String {
    let mut lines = Vec::new();
    for line in 0..len.div_ceil(16) {
        let base = line * 16;
        let bytes: Vec<String> = (0..16)
            .map(|i| {
                g.read_u8((base + i) as u64)
                    .map(|b| format!("{b:02x}"))
                    .unwrap_or_else(|_| "??".to_string())
            })
            .collect();
        lines.push(format!("{base:03x}: {}", bytes.join(" ")));
    }
    lines.join("\n")
}

/// CMDQ-ядро: establishment + пост (entry → doorbell → CQE-полл) поверх
/// init segment (Transport — линейный BAR0, Bar0Transport сессии; fix
/// round 2, восстановлен fix round 8 после опровержения 0.4-детура) и
/// identity-окна DmaAlloc. Синхронный per-op token, слот 0 (параллельные
/// tools — на семафоре сессии, semaphore62 CMDQ не трогает). POISONED
/// после таймаута.
pub struct Cmdq<'a> {
    seg: &'a dyn Transport,
    dma: &'a DmaAlloc,
    /// Страницы очереди (живут до конца Cmdq; PRM: адрес не менять после
    /// INIT_HCA — у нас до Drop).
    queue: AllocationGuard,
    info: CmdqEstablishInfo,
    token: Cell<u8>,
    poisoned: Cell<bool>,
    last_cqe_polls: Cell<usize>,
    /// Дедлайн CQE-полла (wall-clock; тесты инжектируют короткий).
    cqe_deadline: std::time::Duration,
}

impl<'a> std::fmt::Debug for Cmdq<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cmdq")
            .field("info", &self.info)
            .field("poisoned", &self.poisoned.get())
            .field("token", &self.token.get())
            .finish()
    }
}

impl<'a> Cmdq<'a> {
    /// Establishment по PRM §8.2 (+ kernel facts):
    /// initializing-wait ДО парса — БЕЗУСЛОВЕН (kernel wait_fw_init ДО
    /// mlx5_cmd_enable, main.c:1104-1125; после FLR регистры сначала отдают
    /// мусор — task-07 попытка 1; fix round 4: раньше только при
    /// flr_wait=true); парс fw_rev/cmdif_rev/log_sz/stride; очередь из окна
    /// DmaAlloc (wire: очередь старого бинарника @ 0x10000000 = база окна);
    /// обнулить слоты и провалидировать owner-состояние (все слоты SW);
    /// публикация адреса hi-словом ПЕРВЫМ, lo с нулями в битах 11:0;
    /// wait initializing=0 после публикации (PRM §8.2).
    pub fn establish(seg: &'a dyn Transport, dma: &'a DmaAlloc, flr_wait: bool) -> Result<Self> {
        Self::establish_with_timeouts(seg, dma, flr_wait, CMDQ_CQE_DEADLINE, CMDQ_INIT_DEADLINE)
    }

    /// Establish с инжектируемым дедлайном CQE-полла (тесты ускоряют;
    /// прод пользуется [`Cmdq::establish`] = [`CMDQ_CQE_DEADLINE`]).
    pub fn establish_with_deadline(
        seg: &'a dyn Transport,
        dma: &'a DmaAlloc,
        flr_wait: bool,
        cqe_deadline: std::time::Duration,
    ) -> Result<Self> {
        Self::establish_with_timeouts(seg, dma, flr_wait, cqe_deadline, CMDQ_INIT_DEADLINE)
    }

    /// Establish с инжектируемыми дедлайнами CQE-полла и initializing-wait
    /// (fix round 4; тесты ускоряют оба, прод — [`Cmdq::establish`]).
    pub fn establish_with_timeouts(
        seg: &'a dyn Transport,
        dma: &'a DmaAlloc,
        flr_wait: bool,
        cqe_deadline: std::time::Duration,
        init_deadline: std::time::Duration,
    ) -> Result<Self> {
        // Kernel-style: initializing-wait до парса — всегда (не только
        // post-FLR); flr_wait сохранён для стабильности публичного API,
        // поведенческой роли больше не имеет.
        let _ = flr_wait;
        wait_fw_ready(seg, init_deadline, "pre-parse")?;
        // iseg-чтения (аудит fix round 4): слово транспорта = LE-нагрузка
        // wire-байтов → swap = BE-значение регистра.
        let fw = seg
            .read32(0x0)
            .map_err(|e| Error::Io(format!("cmdq init segment: fw_rev: {e}")))?
            .swap_bytes();
        let rev = seg
            .read32(0x4)
            .map_err(|e| Error::Io(format!("cmdq init segment: cmdif_rev: {e}")))?
            .swap_bytes();
        let lsz = seg
            .read32(INITSEG_CMDQ_ADDR_L_SZ)
            .map_err(|e| Error::Io(format!("cmdq init segment: cmdq_addr_l_sz: {e}")))?
            .swap_bytes();
        let info_parse = CmdqEstablishInfo {
            fw_rev_major: (fw & 0xffff) as u16,
            fw_rev_minor: (fw >> 16) as u16,
            fw_rev_subminor: (rev & 0xffff) as u16,
            cmdif_rev: (rev >> 16) as u16,
            log_cmdq_size: (lsz >> 4) & 0xf,
            log_cmdq_stride: lsz & 0xf,
            entries: 0,
            stride: 0,
            queue_pages: 0,
            queue_iova: 0,
        };
        if info_parse.fw_rev_major == 0 || info_parse.cmdif_rev == 0 {
            return Err(Error::Unsupported(format!(
                "cmdq: init segment не отвечает (fw_rev_major={}, cmdif_rev={}) — FW не готов?",
                info_parse.fw_rev_major, info_parse.cmdif_rev
            )));
        }
        let stride = 1usize << info_parse.log_cmdq_stride;
        if stride < CMDQ_ENTRY_SIZE {
            return Err(Error::Unsupported(format!(
                "cmdq: log_cmdq_stride={} ({}B) меньше 64B entr",
                info_parse.log_cmdq_stride, stride
            )));
        }
        if !(1..=MAX_LOG_CMDQ_SIZE).contains(&info_parse.log_cmdq_size) {
            return Err(Error::Unsupported(format!(
                "cmdq: log_cmdq_size={} вне 1..={MAX_LOG_CMDQ_SIZE}",
                info_parse.log_cmdq_size
            )));
        }
        let entries = 1usize << info_parse.log_cmdq_size;
        let queue_pages = (entries * stride).div_ceil(DMA_PAGE_SIZE);
        let queue = dma.alloc(queue_pages).ok_or_else(|| {
            Error::Io(format!(
                "cmdq: dma-окно: нет {queue_pages} смежных страниц под очередь"
            ))
        })?;
        let base = queue
            .as_ptr()
            .ok_or_else(|| Error::Io("cmdq: dma-очередь без указателя".into()))?
            as usize as u64;
        if base & 0xfff != 0 {
            return Err(Error::Unsupported(format!(
                "cmdq: очередь @ {base:#x} не выровнена на 4KB (PRM §8.2)"
            )));
        }
        // Валидация owner-состояния ДО обнуления: страница из пула с чужой
        // HW-ownership (мусор предыдущей сессии сразу после FLR — живой гейт
        // task-07 попытка 1) — отказ, очередь не публикуется. Затем слоты
        // обнуляются (PRM: SW пишет 0 в status/reserved при посте).
        let zero = [0u8; CMDQ_ENTRY_SIZE];
        for i in 0..entries {
            let own = read_region(&queue, i * stride + CMDQ_ENTRY_SIZE - 1, 1)?[0];
            if own & CMD_OWNER_HW != 0 {
                return Err(Error::Io(format!(
                    "cmdq: слот {i} во HW-ownership до поста (мусор после сброса?) — очередь не публикуется"
                )));
            }
            write_region(&queue, i * stride, &zero)?;
        }
        // Публикация адреса: hi-слово ПЕРВЫМ (PRM §8.2 «write the most
        // significant word first»; kernel cmd.c :2523-2524), lo — адрес с
        // нулями в битах 11:0 (nic_interface/log_cmdq_size/stride = 0).
        // write32 принимает СЛОВО транспорта = swap(BE-значения) — на wire
        // ложится BE-дворд значения (аудит fix round 4).
        seg.write32(INITSEG_CMDQ_ADDR_H, ((base >> 32) as u32).swap_bytes())
            .map_err(|e| Error::Io(format!("cmdq: публикация cmdq_addr_h: {e}")))?;
        seg.write32(
            INITSEG_CMDQ_ADDR_L_SZ,
            ((base & 0xffff_f000) as u32).swap_bytes(),
        )
        .map_err(|e| Error::Io(format!("cmdq: публикация cmdq_addr_l_sz: {e}")))?;
        wait_fw_ready(seg, init_deadline, "post-publish")?;
        let info = CmdqEstablishInfo {
            entries,
            stride,
            queue_pages,
            queue_iova: base,
            ..info_parse
        };
        log::debug!(
            "cmdq: очередь @ {base:#x} ({entries} слотов × {stride}B, {queue_pages} стр), \
             fw {}.{}.{}, cmdif_rev {}",
            info.fw_rev_major,
            info.fw_rev_minor,
            info.fw_rev_subminor,
            info.cmdif_rev
        );
        // Fix round 5: полный дамп iseg на establishment — первичный артефакт
        // для побайтового свера с `dd if=/sys/.../resource0` (расходимость
        // с kernel/OLD-потоком должна стать видимой). Аргумент макроса
        // вычисляется только при включённом info-уровне (без логгера/уровня
        // reads по BAR не идут — no noise); в тестах без логгера путь молчит.
        log::info!(
            "cmdq: init segment dump 0x000..{ISEG_DUMP_LEN:#x} (raw dwords, BE/wire-порядок = \
             dd-resource0 view, 16 двордов/строку):\n{}",
            render_iseg_dump(seg)
        );
        Ok(Cmdq {
            seg,
            dma,
            queue,
            info,
            token: Cell::new(0),
            poisoned: Cell::new(false),
            last_cqe_polls: Cell::new(0),
            cqe_deadline,
        })
    }

    /// Разобранный init segment establishment'а.
    pub fn establishment(&self) -> &CmdqEstablishInfo {
        &self.info
    }

    /// Таймаут CQE-полла отравил сессию: операции fail-fast до re-open/FLR.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.get()
    }

    /// Число ownership-поллов последнего поста (диагностика/тесты бюджета).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn last_cqe_polls(&self) -> usize {
        self.last_cqe_polls.get()
    }

    /// Per-op token: 1..=255, 0 пропускается (kernel alloc_token).
    /// Таймаут-диагностика (fix round 3, артефакт разбора живого гейта):
    /// полный постед-64B entr (hex), значение doorbell и его регистр,
    /// состояние cmdq в init segment (cmdq_addr 0x10/0x14, initializing),
    /// последний прочитанный dword CQE (token/sig/rsvd/status_own @0x3c).
    /// Fix round 5: + полный дамп iseg 0x000..0x200 (raw dwords, dd-resource0
    /// view) и дамп первых 128B памяти очереди с нашей стороны маппинга
    /// (queue header — что FW обязан видеть по опубликованному адресу).
    /// Позволяет различить «FW не видел doorbell» / «entr отвергнут» /
    /// «медленно исполнялось» / «опубликованный адрес не тот».
    fn dump_timeout_diagnostics(
        &self,
        posted: &[u8; CMDQ_ENTRY_SIZE],
        polls: usize,
        elapsed: std::time::Duration,
    ) {
        // iseg-значения здесь печатаются как BE-ЗНАЧЕНИЯ (= raw.swap_bytes(),
        // аудит fix round 4: попытка-8 разобрала 0x47000000 как сырое слово).
        let iseg = |off: usize| self.seg.read32(off).map(|v| v.swap_bytes()).unwrap_or(0);
        let cqe_last_dword = read_region(&self.queue, 0x3c, 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0);
        // Дампы (fix round 5) — толерантные чтения (диагностика не паникует
        // и не маскирует Timeout).
        let window_dump = render_window_dump(&self.queue, QUEUE_WINDOW_DUMP_LEN);
        let iseg_dump = render_iseg_dump(self.seg);
        log::error!(
            "cmdq: CQE-таймаут — сессия POISONED. entry_posted={}\n  \
             doorbell: value=0x{:08x} reg=iseg+0x{:02x}\n  \
             iseg: cmdq_addr=0x{:08x}:0x{:08x} (regs 0x10/0x14, BE-значения, \
             queue_iova={:#x}) initializing=0x{:08x} (reg 0x1fc, BE-значение: бит 31)\n  \
             cqe_last_dword=0x{:08x} (token/sig/rsvd/status_own @0x3c, чтение памяти) \
             polls={polls} elapsed={elapsed:?} deadline={:?}\n  \
             dma_window @ queue_iova (наша сторона маппинга), первые {QUEUE_WINDOW_DUMP_LEN}B \
             queue header:\n{window_dump}\n  \
             iseg dump 0x000..{ISEG_DUMP_LEN:#x} (raw dwords, BE/wire-порядок = \
             dd-resource0 view):\n{iseg_dump}",
            crate::mailbox::wire_hex(posted),
            1u32 << 0,
            INITSEG_DBELL,
            iseg(INITSEG_CMDQ_ADDR_H),
            iseg(INITSEG_CMDQ_ADDR_L_SZ),
            self.info.queue_iova,
            iseg(INITSEG_INITIALIZING),
            cqe_last_dword,
            self.cqe_deadline,
        );
    }

    fn next_token(&self) -> u8 {
        let mut t = self.token.get().wrapping_add(1);
        if t == 0 {
            t = 1;
        }
        self.token.set(t);
        t
    }

    /// Один обмен: mailboxes (input[16..] / output[16..] при выходе за inline)
    /// → 64B entr слота 0 (BE, ownership=HW, подписи PRM) → doorbell
    /// (0x18 = 1<<0, единственная запись) → полл ownership-бита CQE →
    /// сбор output (out-inline + out-цепочка), статус доставки/token из CQE.
    /// Таймаут → Err(Timeout) + POISONED; delivery≠0 → Err (без отравления);
    /// командный статус остаётся в output (слой сессии).
    pub fn post(&self, input: &[u8], outlen: usize) -> Result<CmdqCompletion> {
        if self.poisoned.get() {
            return Err(Error::Io(
                "cmdq poisoned: предыдущая команда не завершилась (таймаут CQE); нужен re-open/FLR"
                    .into(),
            ));
        }
        if input.len() < 8 {
            return Err(Error::Size(format!(
                "cmdq: input {} < 8 байт (PRM Table 96: input len error)",
                input.len()
            )));
        }
        let token = self.next_token();

        // Данные за пределами inline едут mailbox-цепочкой из окна (по
        // размеру: ≤16B — без mailbox, указатель 0).
        let in_mail = input.len() > CMDQ_INLINE_SIZE;
        let in_blocks = if in_mail {
            build_chain(self.dma, &input[CMDQ_INLINE_SIZE..], token, false)?
        } else {
            Vec::new()
        };
        let out_blocks = if outlen > CMDQ_INLINE_SIZE {
            build_chain(self.dma, &vec![0u8; outlen - CMDQ_INLINE_SIZE], token, true)?
        } else {
            Vec::new()
        };

        // 64B entr (PRM Table 95/96, BE): inline input, указатели цепочек
        // (первый блок), out-inline нулями (PRM: SW пишет 0), token,
        // подпись, ownership=HW.
        let mut e = [0u8; CMDQ_ENTRY_SIZE];
        e[0] = CMD_TYPE_PCI_XPORT;
        e[4..8].copy_from_slice(&(input.len() as u32).to_be_bytes());
        let in_ptr = in_blocks.first().map_or(0, |b| b.iova);
        e[8..16].copy_from_slice(&in_ptr.to_be_bytes());
        let inline = input.len().min(CMDQ_INLINE_SIZE);
        e[0x10..0x10 + inline].copy_from_slice(&input[..inline]);
        let out_ptr = out_blocks.first().map_or(0, |b| b.iova);
        e[0x30..0x38].copy_from_slice(&out_ptr.to_be_bytes());
        e[0x38..0x3c].copy_from_slice(&(outlen as u32).to_be_bytes());
        e[0x3c] = token;
        e[0x3f] = CMD_OWNER_HW;
        let mut x = 0u8;
        for (i, b) in e.iter().enumerate() {
            if i != 0x3d {
                x ^= b;
            }
        }
        e[0x3d] = !x;
        write_region(&self.queue, 0, &e)?;

        // Doorbell: вектор @0x18, бит слота (0) — запись ПОСЛЕ валидного
        // entr (PRM Table 7: «When the bit is set… the command is moved to
        // HW ownership»; kernel: «ring doorbell after the descriptor is
        // valid»). Значение 1<<slot, слово = swap(1) — на wire BE-дворд
        // (аудит fix round 4).
        //
        // WATCH-item (Task 9 review): упорядоченность entr→doorbell — без
        // явного барьера памяти: volatile-сторы в WB-память окна и запись
        // doorbell упорядочены на x86-64 (TSO); на слабоупорядоченных
        // архитектурах перед doorbell понадобится барьер записи DMA (аналог
        // dma_wmb() ядра до iowrite32be doorbell). Примечание, семантики
        // не меняет.
        self.seg
            .write32(INITSEG_DBELL, 1u32.swap_bytes())
            .map_err(|e| Error::Io(format!("cmdq: doorbell: {e}")))?;

        // CQE-полл: ownership-бит слота (PRM §7.14.1: «SW can poll the
        // ownership bit in the command»), wall-clock дедлайн (60 с
        // kernel-града), лесенка сна 1мс→10мс.
        let started = std::time::Instant::now();
        let mut polls = 0usize;
        loop {
            let own = read_region(&self.queue, CMDQ_ENTRY_SIZE - 1, 1)?[0];
            if own & CMD_OWNER_HW == 0 {
                break;
            }
            polls += 1;
            if started.elapsed() >= self.cqe_deadline {
                self.last_cqe_polls.set(polls);
                self.poisoned.set(true);
                self.dump_timeout_diagnostics(&e, polls, started.elapsed());
                return Err(Error::Timeout);
            }
            let interval = if polls <= 16 { 1 } else { 10 };
            std::thread::sleep(std::time::Duration::from_millis(interval));
        }
        self.last_cqe_polls.set(polls);

        // Комплитка: entr из памяти очереди (FW писал out-inline/status).
        let entry = read_region(&self.queue, 0, CMDQ_ENTRY_SIZE)?;
        let v = decode_entry(&entry);
        if v.delivery != 0 {
            return Err(Error::Io(format!(
                "cmdq: статус доставки 0x{:02x} (token {}, PRM Table 96)",
                v.delivery, v.token
            )));
        }

        // Output: out-inline + out-цепочка. Блоки — наши страницы; чтение
        // по next-указателям из памяти (валидация цепочки: следующий блок
        // обязан быть одним из выделенных нами).
        let mut output = Vec::with_capacity(outlen);
        let inline_out = outlen.min(CMDQ_INLINE_SIZE);
        output.extend_from_slice(&v.out_inline[..inline_out]);
        let mut remaining = outlen - inline_out;
        let mut ptr = v.out_ptr;
        while remaining > 0 {
            let take = remaining.min(MAILBOX_DATA_SIZE);
            let blk = out_blocks.iter().find(|b| b.iova == ptr).ok_or_else(|| {
                Error::Io(format!(
                    "cmdq: out-цепочка битая: блок {ptr:#x} не из выделенных (осталось {remaining}B)"
                ))
            })?;
            let chunk = read_region(&blk.guard, 0, MAILBOX_BLOCK_SIZE)?;
            output.extend_from_slice(&chunk[..take]);
            remaining -= take;
            ptr = u64::from_be_bytes(chunk[0x230..0x238].try_into().unwrap());
        }
        drop(in_blocks);
        drop(out_blocks);
        Ok(CmdqCompletion {
            output,
            token: v.token,
            delivery: v.delivery,
        })
    }
}

/// Kernel-style wait initializing: бит 31 BE-ЗНАЧЕНИЯ дворда @0x1fc → 0
/// (kernel main.c:133-134 wait_fw_init: `ioread32be(&iseg->initializing)`
/// + `if (!(fw_initializing >> 31)) break;`; mlx5_ifc.h initializing[0x1] —
/// старший бит байта 0x1fc). Транспортный контракт: слово = LE-нагрузка
/// wire → значение регистра = swap; initializing в слове транспорта — бит 7,
/// raw-домен проверка без swap даёт ложный pass (fix round 4, разбор
/// попытки 8). Wall-clock дедлайн (kernel — jiffies), лесенка сна 1мс→10мс;
/// таймаут — чистый Err(Timeout) с диагностикой raw/value (establishment
/// провален, очередь не публикуется, POISON не нужен).
fn wait_fw_ready(seg: &dyn Transport, deadline: std::time::Duration, stage: &str) -> Result<()> {
    let started = std::time::Instant::now();
    let mut polls = 0usize;
    loop {
        let raw = seg
            .read32(INITSEG_INITIALIZING)
            .map_err(|e| Error::Io(format!("cmdq: initializing read: {e}")))?;
        let value = raw.swap_bytes();
        if value & (1 << 31) == 0 {
            return Ok(());
        }
        polls += 1;
        if started.elapsed() >= deadline {
            log::error!(
                "cmdq: initializing wait ({stage}) таймаут: raw={raw:#010x} \
                 value={value:#010x} (reg 0x1fc, BE-значение), polls={polls} \
                 elapsed={:?} deadline={deadline:?}",
                started.elapsed()
            );
            return Err(Error::Timeout);
        }
        let interval = if polls <= 16 { 1 } else { 10 };
        std::thread::sleep(std::time::Duration::from_millis(interval));
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, VecDeque};
    use std::ptr;

    use super::*;
    use crate::dma::{DMA_PAGE_SIZE, DmaAlloc};
    use crate::mailbox::Transport;
    use crate::wiretest::{block, parse_wire};

    const TRIG_FIX: &str = include_str!("../testdata/wire/cmdq-trig.txt");
    const INIT_FIX: &str = include_str!("../testdata/wire/cmdq-init.txt");

    // ---------- мок DMA-окна (как в dma.rs: анонимный mmap, munmap на drop) ----------

    struct MockWindow {
        ptr: *mut u8,
        len: usize,
    }

    impl MockWindow {
        fn new(pages: usize) -> Self {
            let len = pages * DMA_PAGE_SIZE;
            let p = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(p, libc::MAP_FAILED, "mock mmap");
            MockWindow { ptr: p.cast(), len }
        }
    }

    impl Drop for MockWindow {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.ptr.cast(), self.len) };
        }
    }

    // ---------- устройство: BAR0-linear (init segment, BE-дворды; fix
    // round 8 — восстановление fix round 2) + DMA-окно ----------

    struct MockCompletion {
        delivery: u8,
        output: Vec<u8>,
    }

    #[derive(Default)]
    struct MockBar {
        /// Init segment по дворам (BE-значения регистров), PRM Table 7/8.
        seg: RefCell<Vec<u32>>,
        /// Журнал операций: "r:off" / "w:off=val".
        events: RefCell<Vec<String>>,
        /// Первые N чтений 0x1fc возвращают initializing=1 (FW грузится).
        init_holds: Cell<usize>,
        init_reads: Cell<usize>,
        /// Сценарные комплитки (FIFO на doorbell).
        completions: RefCell<VecDeque<MockCompletion>>,
        /// Не завершать команду: owner остаётся у HW (тест таймаута).
        hold_owner: Cell<bool>,
        /// Опубликованный адрес очереди (из записи @0x10/@0x14).
        queue_base: Cell<u64>,
        /// Снимок 64B-entr на момент doorbell (entry обязан быть валиден ДО званка).
        seen_entry: RefCell<Vec<u8>>,
        /// Input, собранный устройством из inline + in-mailbox цепочки.
        seen_input: RefCell<Vec<u8>>,
        /// Меты in-блоков по цепочке: (next_ptr, block_num, token).
        seen_in_blocks: RefCell<Vec<(u64, u32, u8)>>,
    }

    impl MockBar {
        fn new() -> Self {
            MockBar {
                seg: RefCell::new(vec![0u32; 0x2000 / 4]),
                events: RefCell::new(Vec::new()),
                init_holds: Cell::new(0),
                init_reads: Cell::new(0),
                completions: RefCell::new(VecDeque::new()),
                hold_owner: Cell::new(false),
                queue_base: Cell::new(0),
                seen_entry: RefCell::new(Vec::new()),
                seen_input: RefCell::new(Vec::new()),
                seen_in_blocks: RefCell::new(Vec::new()),
            }
        }

        fn set_seg(&self, off: usize, v: u32) {
            self.seg.borrow_mut()[off / 4] = v;
        }

        fn events(&self) -> Vec<String> {
            self.events.borrow().clone()
        }

        fn count_writes(&self, off: usize) -> usize {
            self.events()
                .iter()
                .filter(|e| e.starts_with(&format!("w:{off:#x}=")))
                .count()
        }

        /// Доступ устройства к DMA-окну: IOVA == vaddr (identity), адрес —
        /// абсолютный указатель окна (как его видит HW по DMA).
        unsafe fn rd(&self, addr: u64, len: usize) -> Vec<u8> {
            unsafe {
                let p = addr as *mut u8;
                (0..len).map(|i| p.add(i).read_volatile()).collect()
            }
        }

        unsafe fn wr(&self, addr: u64, data: &[u8]) {
            unsafe {
                let p = addr as *mut u8;
                for (i, b) in data.iter().enumerate() {
                    p.add(i).write_volatile(*b);
                }
            }
        }

        /// Модель FW на doorbell-запись (вектор: бит на слот; мы — слот 0).
        /// Читает entr из DMA-памяти (валидность ДО званка — вход в модель),
        /// собирает input по цепочке, пишет output в out-inline/цепочку,
        /// возвращает ownership SW (кроме hold_owner).
        fn on_doorbell(&self) {
            let base = self.queue_base.get();
            assert_ne!(base, 0, "doorbell без опубликованной очереди");
            let entry = unsafe { self.rd(base, CMDQ_ENTRY_SIZE) };
            assert_eq!(
                entry[63] & 0x1,
                0x1,
                "doorbell до перевода entry в HW-ownership (последовательность поста)"
            );
            let v = decode_entry(&entry);
            *self.seen_entry.borrow_mut() = entry.clone();

            // Сбор input: inline + цепочка in-блоков по next-указателям.
            let mut input = Vec::with_capacity(v.inlen as usize);
            let inline = (v.inlen as usize).min(CMDQ_INLINE_SIZE);
            input.extend_from_slice(&v.in_inline[..inline]);
            let mut remaining = v.inlen as usize - inline;
            let mut ptr = v.in_ptr;
            let mut metas = Vec::new();
            while remaining > 0 {
                assert_ne!(ptr, 0, "input остался, а in-цепочка кончилась");
                let b = unsafe { self.rd(ptr, MAILBOX_BLOCK_SIZE) };
                let take = remaining.min(MAILBOX_DATA_SIZE);
                input.extend_from_slice(&b[..take]);
                let next = u64::from_be_bytes(b[0x230..0x238].try_into().unwrap());
                let num = u32::from_be_bytes(b[0x238..0x23c].try_into().unwrap());
                metas.push((next, num, b[0x23d]));
                remaining -= take;
                ptr = next;
            }
            *self.seen_input.borrow_mut() = input;
            *self.seen_in_blocks.borrow_mut() = metas;

            if self.hold_owner.get() {
                return; // HW так и не ответил: owner остаётся взведённым
            }
            let c = self
                .completions
                .borrow_mut()
                .pop_front()
                .expect("mock: нет сценариеванной комплитки");
            // Output: первые 16B — inline в entr, остальное — out-цепочка.
            let out_inline = (c.output.len()).min(CMDQ_INLINE_SIZE);
            let mut e = entry.clone();
            e[0x20..0x30].copy_from_slice(&c.output[..out_inline]);
            unsafe { self.wr(base + 0x20, &c.output[..out_inline]) };
            let mut rest = &c.output[out_inline..];
            let mut ptr = v.out_ptr;
            while !rest.is_empty() {
                assert_ne!(ptr, 0, "output остался, а out-цепочки нет");
                let take = rest.len().min(MAILBOX_DATA_SIZE);
                unsafe { self.wr(ptr, &rest[..take]) };
                let b = unsafe { self.rd(ptr, MAILBOX_BLOCK_SIZE) };
                ptr = u64::from_be_bytes(b[0x230..0x238].try_into().unwrap());
                rest = &rest[take..];
            }
            e[63] = c.delivery << 1; // ownership → SW (бит 0), статус доставки биты 7:1
            unsafe { self.wr(base + 63, &e[63..64]) };
        }
    }

    impl Transport for MockBar {
        /// Контракт Transport (как VsecTransport): слово транспорта = LE-нагрузка
        /// 4 байтов провода; значение регистра = слово.swap_bytes().
        fn read32(&self, off: usize) -> crate::err::Result<u32> {
            self.events.borrow_mut().push(format!("r:{off:#x}"));
            let mut v = self.seg.borrow()[off / 4];
            if off == INITSEG_INITIALIZING {
                let n = self.init_reads.replace(self.init_reads.get() + 1);
                if n < self.init_holds.get() {
                    v = 0x8000_0000; // initializing (бит 31), значение регистра
                }
            }
            Ok(v.swap_bytes())
        }

        fn write32(&self, off: usize, v: u32) -> crate::err::Result<()> {
            let reg = v.swap_bytes();
            self.events
                .borrow_mut()
                .push(format!("w:{off:#x}={reg:#x}"));
            match off {
                INITSEG_CMDQ_ADDR_H => {
                    let lo = self.queue_base.get() & 0xffff_ffff;
                    self.queue_base.set((u64::from(reg) << 32) | lo);
                }
                INITSEG_CMDQ_ADDR_L_SZ => {
                    let hi = self.queue_base.get() >> 32;
                    self.queue_base.set((hi << 32) | u64::from(reg));
                }
                INITSEG_DBELL => self.on_doorbell(),
                _ => self.seg.borrow_mut()[off / 4] = reg,
            }
            Ok(())
        }
    }

    // ---------- окружение: окно + init segment живой карты (fw 16.35.4030) ----------

    fn xor8(b: &[u8]) -> u8 {
        b.iter().fold(0u8, |a, x| a ^ x)
    }

    fn live_init_segment(bar: &MockBar) {
        // fw_rev: minor[31:16]=35 | major[15:0]=16 (PRM Table 8); карта 16.35.4030.
        bar.set_seg(0x0, (35u32 << 16) | 16);
        // cmd_interface_rev[31:16]=5 | fw_rev_subminor[15:0]=4030.
        bar.set_seg(0x4, (5u32 << 16) | 4030);
        // cmdq_addr_l_sz: log_cmdq_size=6 (64 слота) | log_cmdq_stride=6 (64B).
        bar.set_seg(INITSEG_CMDQ_ADDR_L_SZ, (6u32 << 4) | 6);
    }

    fn setup(pages: usize) -> (MockWindow, DmaAlloc, MockBar) {
        let w = MockWindow::new(pages);
        let dma = DmaAlloc::over_window(w.ptr, w.len);
        let bar = MockBar::new();
        live_init_segment(&bar);
        (w, dma, bar)
    }

    /// NOTE-строки фикстры → map (k=v; hex-значения не парсим тут).
    fn fixture_notes(text: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        for line in text.lines() {
            if let Some(kv) = line.strip_prefix("NOTE ") {
                if let Some((k, v)) = kv.split_once('=') {
                    m.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }
        m
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    // ---------- (а0) ESTABLISHMENT ----------

    /// Парс init segment (fw_rev, cmdif_rev, log_sz/stride) + публикация
    /// очереди из окна DmaAlloc: hi-слово адреса ПЕРВЫМ, затем lo с нулями
    /// в битах 11:0 (PRM §8.2; kernel cmd.c — факты). Очередь — с базы окна
    /// (старый бинарник: CQE @ 0x10000000 = база окна, arm.log:3).
    #[test]
    fn establishment_parses_init_segment_and_publishes_queue_from_window() {
        let (_w, dma, bar) = setup(64);
        let q = Cmdq::establish(&bar, &dma, false).unwrap();
        let info = q.establishment();
        assert_eq!(
            (info.fw_rev_major, info.fw_rev_minor, info.fw_rev_subminor),
            (16, 35, 4030)
        );
        assert_eq!(info.cmdif_rev, 5);
        assert_eq!((info.log_cmdq_size, info.log_cmdq_stride), (6, 6));
        assert_eq!((info.entries, info.stride), (64, 64));
        assert_eq!(info.queue_pages, 1, "64 слота × 64B = 4096 = 1 страница");
        assert_eq!(
            info.queue_iova,
            dma.window_base() as u64,
            "очередь с базы окна (wire-свидетельство старого бинарника)"
        );
        // Публикация: hi первым, lo с обнулёнными битами 11:0 (PRM §8.2).
        let ev = bar.events();
        let hi = ev.iter().position(|e| e.starts_with("w:0x10=")).unwrap();
        let lo = ev
            .iter()
            .position(|e| e.starts_with("w:0x14="))
            .expect("lo-слово опубликовано");
        assert!(hi < lo, "hi-слово первым (PRM §8.2): {ev:?}");
        let lo_val: u32 = ev[lo]
            .strip_prefix("w:0x14=0x")
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .unwrap();
        assert_eq!(
            lo_val & 0xfff,
            0,
            "nic_interface/log_sz/log_stride = 0 в lo-слове"
        );
        assert_eq!(
            lo_val,
            (dma.window_base() as u32) & 0xffff_f000,
            "lo-слово = адрес очереди (база окна)"
        );
        // Очередь обнулена и все слоты SW-owned.
        assert!(bar.seen_entry.borrow().is_empty(), "команд не было");
        unsafe {
            for i in 0..info.entries {
                let own = bar.rd(info.queue_iova + (i * info.stride) as u64 + 63, 1)[0];
                assert_eq!(own & 1, 0, "слот {i} SW-owned после establishment");
            }
        }
    }

    /// flr=true: ownership/FW-ready wait ДО парса (task-07 попытка 1: мусор в
    /// регистрах сразу после FLR) + повторный wait после публикации (PRM §8.2).
    #[test]
    fn establishment_after_flr_waits_ready_before_parse_and_after_publish() {
        let (_w, dma, bar) = setup(8);
        bar.init_holds.set(3);
        let q = Cmdq::establish(&bar, &dma, true).unwrap();
        assert_eq!(q.establishment().fw_rev_major, 16);
        let ev = bar.events();
        assert!(
            ev.iter().take(3).all(|e| e == "r:0x1fc"),
            "первые операции — поллы initializing, {:?}",
            &ev[..6.min(ev.len())]
        );
        let parse_at = ev
            .iter()
            .position(|e| e == "r:0x0" || e == "r:0x4" || e == "r:0x14")
            .expect("парс после ready-wait");
        assert!(
            parse_at >= 3,
            "парс только после сброса initializing: {ev:?}"
        );
        // PRM §8.2: wait initializing СРАЗУ после записи lo-слова адреса
        // (fix round 5: точечная проверка вместо ev.last() — establishment
        // теперь завершается iseg-дампом, читающим и 0x1fc).
        let pub_lo = ev
            .iter()
            .position(|e| e.starts_with("w:0x14="))
            .expect("публикация lo-слова");
        assert_eq!(
            ev[pub_lo + 1],
            "r:0x1fc",
            "wait initializing сразу после публикации"
        );
        assert_eq!(
            bar.init_reads.get(),
            5,
            "3 холда + готово (pre-parse) + пост-публикация (iseg-дамп — \
             аргумент log::info!, без логгера не вычисляется)"
        );
    }

    /// Fix round 4: pre-parse initializing-wait БЕЗУСЛОВЕН (kernel
    /// wait_fw_init до mlx5_cmd_enable, main.c:1104-1125) — не только при
    /// flr_wait=true: холды → wait циклится → сброс → парс и публикация.
    #[test]
    fn establishing_waits_fw_ready_before_parse_even_without_flr() {
        let (_w, dma, bar) = setup(8);
        bar.init_holds.set(2);
        let q = Cmdq::establish(&bar, &dma, false).unwrap();
        assert_eq!(q.establishment().fw_rev_major, 16);
        let ev = bar.events();
        assert!(
            ev.iter().take(2).all(|e| e == "r:0x1fc"),
            "первое — initializing-wait (флаг flr не нужен): {ev:?}"
        );
        let parse_at = ev
            .iter()
            .position(|e| e == "r:0x0" || e == "r:0x4" || e == "r:0x14")
            .expect("парс после ready-wait");
        assert!(
            parse_at >= 2,
            "парс только после сброса initializing: {ev:?}"
        );
        assert_eq!(
            bar.init_reads.get(),
            4,
            "2 холда + готово (pre-parse) + пост-публикация (iseg-дамп — \
             аргумент log::info!, без логгера не вычисляется)"
        );
    }

    /// Fix round 4 (б), регрессия класса попытки 8: wait декодирует
    /// BE-ЗНАЧЕНИЕ, а не сырое слово транспорта. initializing — бит 31
    /// значения (kernel main.c:133-134, mlx5_ifc.h initializing[0x1]) —
    /// в LE-слове этот бит живёт как бит 7: у сырого слова бит 31 ЧИСТ, и
    /// raw-домен проверка дала бы ложный pass (публикация/пост в
    /// инициализирующийся FW). Здесь значение = бит 31 + живой хвост 0x47
    /// (форма 0x…47 разбора попытки 8).
    #[test]
    fn initializing_wait_decodes_be_value_not_raw_transport_word() {
        let (_w, dma, bar) = setup(8);
        let be_value: u32 = 0x8000_0047;
        let raw_word = be_value.swap_bytes();
        assert_eq!(
            raw_word & (1 << 31),
            0,
            "сырое слово: бит 31 чист — raw-проверка ложно прошла бы"
        );
        bar.set_seg(INITSEG_INITIALIZING, be_value);
        let err = Cmdq::establish_with_timeouts(
            &bar,
            &dma,
            false,
            std::time::Duration::from_secs(60),
            std::time::Duration::from_millis(30),
        )
        .unwrap_err();
        assert_eq!(err, crate::err::Error::Timeout);
        let ev = bar.events();
        assert!(
            ev.iter().filter(|e| *e == "r:0x1fc").count() > 1,
            "wait циклился по BE-значению: {ev:?}"
        );
        assert!(
            !ev.iter()
                .any(|e| e == "r:0x0" || e == "r:0x4" || e == "r:0x14"),
            "парса init segment не было: {ev:?}"
        );
        assert_eq!(bar.count_writes(0x10), 0, "очередь не опубликована");
        assert_eq!(bar.count_writes(0x14), 0);
        assert_eq!(bar.count_writes(0x18), 0, "doorbell не звонился");
    }

    /// Fix round 4 (в): initializing не сбрасывается → чистый Err(Timeout)
    /// по wall-clock дедлайну (не бюджет поллов); публикация не состоялась.
    #[test]
    fn initializing_never_clears_fails_with_timeout_after_deadline() {
        let (_w, dma, bar) = setup(8);
        bar.set_seg(INITSEG_INITIALIZING, 0x8000_0000);
        let started = std::time::Instant::now();
        let err = Cmdq::establish_with_timeouts(
            &bar,
            &dma,
            true,
            std::time::Duration::from_secs(60),
            std::time::Duration::from_millis(30),
        )
        .unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(err, crate::err::Error::Timeout);
        assert!(
            elapsed >= std::time::Duration::from_millis(30)
                && elapsed < std::time::Duration::from_millis(1500),
            "дедлайн wall-clock (30мс), фактическое ожидание {elapsed:?}"
        );
        assert_eq!(bar.count_writes(0x10), 0, "очередь не опубликована");
        assert_eq!(bar.count_writes(0x14), 0);
    }

    /// Fix round 4 (г): декод полей init segment из BE wire-дворов
    /// байт-точно — значения полей собираются из SWAPPED слова (LE-нагрузка
    /// wire); без swap fw_rev_major был бы 0x2300, log_sz — 0xB. Lo-слово
    /// @0x14 с addr-хвостом в старших битах: публикация маскирует биты 11:0.
    #[test]
    fn init_segment_fields_decode_from_be_wire_words() {
        let (_w, dma, bar) = setup(8);
        bar.set_seg(0x0, (35u32 << 16) | 16);
        bar.set_seg(0x4, (5u32 << 16) | 4030);
        // log_sz=6/stride=6 в НИЗКОМ байте значения + addr-хвост 0xABCDE
        // в битах 31:12 (мусор от FW read-only полей — маскирование пин).
        bar.set_seg(INITSEG_CMDQ_ADDR_L_SZ, 0x0ABCDE066);
        let q = Cmdq::establish(&bar, &dma, false).unwrap();
        let i = q.establishment();
        assert_eq!(
            (
                i.fw_rev_major,
                i.fw_rev_minor,
                i.fw_rev_subminor,
                i.cmdif_rev
            ),
            (16, 35, 4030, 5)
        );
        assert_eq!((i.log_cmdq_size, i.log_cmdq_stride), (6, 6));
        // Публикация lo: только адрес, биты 11:0 нули (хвост @0x14 не течёт).
        let ev = bar.events();
        let lo_val: u32 = ev
            .iter()
            .find_map(|e| e.strip_prefix("w:0x14=0x"))
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .expect("lo-слово опубликовано");
        assert_eq!(lo_val & 0xfff, 0);
        assert_eq!(lo_val, (dma.window_base() as u32) & 0xffff_f000);
    }

    /// Мусорный/чужой owner в очереди → establishment отказ, очередь НЕ
    /// публикуется (валидация owner-состояния до первого поста).
    #[test]
    fn establishment_rejects_stale_hw_owned_queue_without_publishing() {
        let (w, dma, bar) = setup(8);
        unsafe { bar.wr(dma.window_base() as u64 + 63, &[0x01]) };
        let err = Cmdq::establish(&bar, &dma, false).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("owner"),
            "причина — owner-состояние: {err}"
        );
        assert_eq!(bar.count_writes(0x10), 0, "адрес не опубликован");
        assert_eq!(bar.count_writes(0x14), 0);
        drop(w);
    }

    // ---------- (а) POST: entry → doorbell → CQE ----------

    /// Пост EnableHCA (16B inline): 64B entr по PRM Table 95 (BE), ровно одна
    /// doorbell-запись (0x18 = 1<<slot) ПОСЛЕ записи entr, статуса/token из
    /// CQE; вход(bytes) = независимо собранный эталон.
    #[test]
    fn post_writes_prm_entry_rings_single_doorbell_and_completes() {
        let blocks = parse_wire(INIT_FIX);
        let enable = block(&blocks, "EnableHCA");
        let (_w, dma, bar) = setup(8);
        let q = Cmdq::establish(&bar, &dma, false).unwrap();
        bar.completions.borrow_mut().push_back(MockCompletion {
            delivery: 0,
            output: enable.rx.clone(),
        });
        let done = q.post(&enable.tx, enable.rx.len()).unwrap();
        assert_eq!(done.output, enable.rx);
        assert_eq!(done.delivery, 0);
        assert!((1..=255).contains(&done.token), "token 1..=255, skip 0");

        // Ровно одна doorbell-запись со значением 1<<0 (бит слота, PRM Table 7).
        let ev = bar.events();
        assert_eq!(
            bar.count_writes(0x18),
            1,
            "одна doorbell-запись на пост: {ev:?}"
        );
        assert!(
            ev.contains(&"w:0x18=0x1".to_string()),
            "содержимое doorbell = 1<<slot (бит слота 0, PRM Table 7): {ev:?}"
        );
        let dbell = ev.iter().position(|e| e.starts_with("w:0x18=")).unwrap();
        assert!(
            ev[..dbell].iter().any(|e| e.starts_with("w:0x14=")),
            " публикация очереди раньше doorbell"
        );

        // Entr на момент doorbell — байт-точный эталон PRM (независимая сборка).
        let seen = bar.seen_entry.borrow().clone();
        let mut e = [0u8; CMDQ_ENTRY_SIZE];
        e[0] = 0x07; // type = PCIe_cmd_if_transport (PRM Table 96)
        e[4..8].copy_from_slice(&(enable.tx.len() as u32).to_be_bytes());
        e[0x10..0x20].copy_from_slice(&enable.tx[..CMDQ_INLINE_SIZE]);
        e[0x38..0x3c].copy_from_slice(&(enable.rx.len() as u32).to_be_bytes());
        e[0x3c] = done.token;
        e[0x3f] = 0x01; // ownership → HW при посте
        let mut x = 0u8;
        for (i, b) in e.iter().enumerate() {
            if i != 0x3d {
                x ^= b;
            }
        }
        e[0x3d] = !x; // signature = ~xor(entry) (PRM Table 96: 8 бит, без mailbox)
        assert_eq!(seen, e.to_vec(), " entr байт-в-байт против PRM-эталона");

        // Вторая команда: token инкрементируется, слот переиспользуется.
        let set_issi = block(&blocks, "SetISSI");
        bar.completions.borrow_mut().push_back(MockCompletion {
            delivery: 0,
            output: set_issi.rx.clone(),
        });
        let done2 = q.post(&set_issi.tx, 16).unwrap();
        assert_eq!(done2.output, set_issi.rx);
        assert_eq!(done2.token, done.token + 1);
        assert_eq!(bar.count_writes(0x18), 2);
    }

    // ---------- (в) DMA-mailbox против триг-фикстры ----------

    /// Триг-команда (36B): inline 16B + in-mailbox 576B из окна DmaAlloc,
    /// out_ptr=0 при outlen≤16 (правило по размеру); негативная комплитка
    /// (status=3/syndrome 0x1c2b78) — из out-inline CQE.
    #[test]
    fn trig_post_rides_in_mailbox_and_returns_neg_completion() {
        let blocks = parse_wire(TRIG_FIX);
        let trig = &blocks[0];
        let notes = fixture_notes(TRIG_FIX);
        let (_w, dma, bar) = setup(16);
        let q = Cmdq::establish(&bar, &dma, false).unwrap();
        bar.completions.borrow_mut().push_back(MockCompletion {
            delivery: 0,
            output: trig.rx.clone(),
        });
        let done = q.post(&trig.tx, trig.rx.len()).unwrap();

        assert_eq!(bar.seen_input.borrow().as_slice(), trig.tx.as_slice());
        assert_eq!(done.output, trig.rx);
        assert_eq!(done.output[0], 0x03, "status из out-inline");
        assert_eq!(
            u32::from_be_bytes(done.output[4..8].try_into().unwrap()),
            0x001c_2b78
        );
        assert_eq!(done.delivery, 0);

        // In-mailbox: один блок из окна (страница после очереди).
        let v = decode_entry(&bar.seen_entry.borrow());
        assert_eq!(v.inlen, 0x24);
        assert_eq!(v.in_inline[..], trig.tx[..16]);
        let mb_iova = dma.window_base() as u64 + DMA_PAGE_SIZE as u64;
        assert_eq!(v.in_ptr, mb_iova, "первый in-блок — страница после очереди");
        assert_eq!(
            v.out_ptr, 0,
            "outlen≤16 → out-mailbox не нужен (по размеру)"
        );
        assert_eq!(v.outlen, 0x10);
        let mb = unsafe { bar.rd(mb_iova, MAILBOX_BLOCK_SIZE) };
        assert_eq!(
            &mb[..trig.tx.len() - 16],
            &trig.tx[16..],
            " data = input[16..]"
        );
        // Фикстровый in_mb0 (wire): первые 20 байт данных совпадают байт-точно.
        let fix_mb = unhex(&notes["in_mb0_576b"]);
        assert_eq!(&mb[..20], &fix_mb[..20], "wire-пин против trig-p0safe.log");
        // Хвост блока: next=0, block_num=0, token = токену команды, сигнатуры PRM.
        assert_eq!(u64::from_be_bytes(mb[0x230..0x238].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(mb[0x238..0x23c].try_into().unwrap()), 0);
        assert_eq!(
            mb[0x23d], done.token,
            "token блока = token entr (PRM Table 98)"
        );
        assert_eq!(
            mb[0x23e],
            !xor8(&mb[0x1c0..0x200]),
            "ctrl_sig (PRM 7.14.1.1.1)"
        );
        assert_eq!(mb[0x23f], !xor8(&mb[..0x23f]), "sig = ~xor(блока без sig)");
    }

    /// Wire-пин лейаута/endianness: декод 64B CQE из фикстры (сырые байты
    /// старого бинарника) против PRM Table 95 — все поля BE.
    #[test]
    fn trig_fixture_cqe_decodes_prm_wire_layout() {
        let blocks = parse_wire(TRIG_FIX);
        let trig = &blocks[0];
        let notes = fixture_notes(TRIG_FIX);
        let cqe = unhex(&notes["cqe_64b"]);
        assert_eq!(cqe.len(), 64);
        let v = decode_entry(&cqe);
        assert_eq!(v.entry_type, 0x07);
        assert_eq!(v.inlen, 0x24);
        assert_eq!(v.in_ptr, 0x10a2e000, "in_mb0 IOVA внутри DMA-окна");
        assert_eq!(v.in_inline[..], trig.tx[..16]);
        assert_eq!(v.out_inline[..], trig.rx[..]);
        assert_eq!(v.out_ptr, 0x10a2e400);
        assert_eq!(v.outlen, 0x10);
        assert_eq!(
            v.token, 0x00,
            "token entr (в wire — 0, совпадает с блоком in_mb0)"
        );
        assert!(!v.owner_hw, "завершённая команда — SW ownership");
        assert_eq!(v.delivery, 0);
    }

    // ---------- (б) таймаут → POISONED ----------

    /// CQE-owner полл ограничен; таймаут → Err(Timeout) + POISONED: следующие
    /// операции fail-fast, БЕЗ новой doorbell-записи (до re-open/FLR).
    #[test]
    fn timeout_poisons_session_and_fails_fast_without_new_doorbell() {
        let blocks = parse_wire(INIT_FIX);
        let enable = block(&blocks, "EnableHCA");
        let (_w, dma, bar) = setup(8);
        // Инжектированный короткий дедлайн (fix round 3: wall-clock, не бюджет
        // поллов; прод — 60 с, тесты не спят 60 с).
        let q =
            Cmdq::establish_with_deadline(&bar, &dma, false, std::time::Duration::from_millis(30))
                .unwrap();
        bar.hold_owner.set(true);
        let started = std::time::Instant::now();
        let err = q.post(&enable.tx, 16).unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(err, crate::err::Error::Timeout);
        assert!(
            elapsed >= std::time::Duration::from_millis(30)
                && elapsed < std::time::Duration::from_millis(1500),
            "дедлайн wall-clock (30мс), фактическое ожидание {elapsed:?}"
        );
        assert!(q.last_cqe_polls() > 0, "поллы шли до дедлайна");
        assert!(q.is_poisoned());

        let before = bar.count_writes(0x18);
        let err2 = q.post(&enable.tx, 16).unwrap_err();
        assert!(
            err2.to_string().to_lowercase().contains("poisoned"),
            "{err2}"
        );
        assert_eq!(
            bar.count_writes(0x18),
            before,
            "fail-fast без нового doorbell"
        );
    }

    /// Fix round 5: таймаут-диагностика (внутри поста) и рендеры дампов
    /// отрабатывают на моке БЕЗ паники; iseg-дамп = 8 строк × 16 двордов с
    /// метками офсетов 000..1c0 в wire/BE-виде (дворды fw_rev/initializing
    /// байт-точно), window-дамп = 8 строк × 16 байт и совпадает с памятью
    /// очереди по опубликованному адресу (наша сторона маппинга): постед-entr
    /// нетронут (hold_owner), слот 1 обнулён.
    #[test]
    fn timeout_diagnostics_render_iseg_and_window_dumps() {
        let blocks = parse_wire(INIT_FIX);
        let enable = block(&blocks, "EnableHCA");
        let (_w, dma, bar) = setup(8);
        let q =
            Cmdq::establish_with_deadline(&bar, &dma, false, std::time::Duration::from_millis(30))
                .unwrap();
        bar.hold_owner.set(true);
        // Пост доходит до таймаута: dump_timeout_diagnostics (с обоими
        // рендерами) уже выполнен на этом пути — без паники.
        assert_eq!(
            q.post(&enable.tx, 16).unwrap_err(),
            crate::err::Error::Timeout
        );

        // Iseg dump: сетка 8×16, метки 000/040/.../1c0, wire-вид двордов.
        let dump = render_iseg_dump(&bar);
        let lines: Vec<&str> = dump.lines().collect();
        assert_eq!(lines.len(), ISEG_DUMP_LEN / 4 / 16);
        for (i, line) in lines.iter().enumerate() {
            assert_eq!(
                line.split(": ").next(),
                Some(format!("{:03x}", i * 64).as_str()),
                "метка офсета строки {i}"
            );
            assert_eq!(line.split(' ').count(), 17, "метка + 16 двордов: {line}");
        }
        assert!(
            lines[0].starts_with("000: 00230010"),
            "дворд fw_rev в wire/BE-виде (16.35): {}",
            lines[0]
        );
        assert_eq!(
            lines[7].split(' ').next_back(),
            Some("00000000"),
            "дворд @0x1fc (initializing мока) — последняя ячейка дампа"
        );

        // Window dump: сетка 8×16 байт, байт-точно против памяти очереди по
        // опубликованному IOVA (что FW обязан был видеть).
        let win = render_window_dump(&q.queue, QUEUE_WINDOW_DUMP_LEN);
        let wlines: Vec<&str> = win.lines().collect();
        assert_eq!(wlines.len(), QUEUE_WINDOW_DUMP_LEN / 16);
        let hex = |b: &[u8]| -> String {
            b.iter()
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let entry = unsafe { bar.rd(q.establishment().queue_iova, CMDQ_ENTRY_SIZE) };
        assert_eq!(entry[63] & 1, 1, "постед-entr остаётся HW-owned");
        assert_eq!(wlines[0], format!("000: {}", hex(&entry[..16])));
        assert_eq!(wlines[1], format!("010: {}", hex(&entry[16..32])));
        assert_eq!(wlines[3], format!("030: {}", hex(&entry[48..64])));
        assert_eq!(
            wlines[4],
            format!("040: {}", hex(&[0u8; 16])),
            "слот 1 (stride 64B) обнулён establishment'ом"
        );
    }

    // ---------- (в') BLOCK-LIST chaining ----------

    /// ManagePages 0xa27=2599 записей (~20 KB, arm2.log:19025): input[16..]
    /// едет цепочкой выровненных на 0x1000 блоков (по 512B данных) из окна
    /// DmaAlloc с next-указателями (PRM Table 97); побайтово против фикстры.
    #[test]
    fn managepages_0xa27_rides_page_aligned_block_chain_byte_exact() {
        let blocks = parse_wire(INIT_FIX);
        let mp = block(&blocks, "block-list");
        assert_eq!(mp.tx.len(), 16 + 2599 * 8);
        let (_w, dma, bar) = setup(64);
        let q = Cmdq::establish(&bar, &dma, false).unwrap();
        bar.completions.borrow_mut().push_back(MockCompletion {
            delivery: 0,
            output: mp.rx.clone(),
        });
        let done = q.post(&mp.tx, 16).unwrap();
        assert_eq!(done.delivery, 0);

        // Устройство собрало input байт-точно (inline + цепочка по next).
        assert_eq!(bar.seen_input.borrow().as_slice(), mp.tx.as_slice());

        // Цепочка: 41 блок (ceil(20792/512)), block_num 0..=40 по порядку,
        // каждый блок — страница окна (+0x1000), last next=0, token общий.
        let metas = bar.seen_in_blocks.borrow().clone();
        assert_eq!(metas.len(), 41);
        let v = decode_entry(&bar.seen_entry.borrow());
        let mut addr = v.in_ptr;
        for (i, (next, num, tok)) in metas.iter().enumerate() {
            assert_eq!(
                *num, i as u32,
                "block_num последовательно с 0 (PRM Table 98)"
            );
            assert_eq!(*tok, done.token, "token общий с entr");
            assert_eq!(addr % 0x1000, 0, "блок выровнен на страницу");
            if i + 1 < metas.len() {
                assert_eq!(*next, addr + DMA_PAGE_SIZE as u64, "next → следующий блок");
            } else {
                assert_eq!(*next, 0, "последний блок: next=0");
            }
            addr = *next;
        }
        assert_eq!(v.inlen, mp.tx.len() as u32);
        assert_eq!(v.in_ptr, dma.window_base() as u64 + DMA_PAGE_SIZE as u64);
    }

    /// Выход > блока: QueryHCACap (outlen=4112 = 16 inline + 8×512) и
    /// QueryISSI (112 = 16 + 96): FW пишет в out-цепочку, ядро собирает
    /// output побайтово против фикстры.
    #[test]
    fn query_outputs_assemble_from_out_mailbox_chain() {
        let blocks = parse_wire(INIT_FIX);
        let (_w, dma, bar) = setup(64);
        let q = Cmdq::establish(&bar, &dma, false).unwrap();

        for (needle, outlen) in [("QueryHCACap", 4112usize), ("QueryISSI", 112)] {
            let b = block(&blocks, needle);
            assert_eq!(b.rx.len(), outlen);
            bar.completions.borrow_mut().push_back(MockCompletion {
                delivery: 0,
                output: b.rx.clone(),
            });
            let done = q.post(&b.tx, outlen).unwrap();
            assert_eq!(done.output, b.rx, "{needle}: output побайтово");
            let v = decode_entry(&bar.seen_entry.borrow());
            assert_eq!(v.outlen as usize, outlen);
            assert_ne!(v.out_ptr, 0, "{needle}: outlen>16 → out-mailbox");
            assert_eq!(
                bar.seen_in_blocks.borrow().len(),
                0,
                "{needle}: in-mailbox нет (16B вход)"
            );
            // FW раскладывал выход по out-цепочке — данные уже проверены equality.
        }
    }

    // ---------- (г) чистый откат ----------

    /// Ошибка доставки (delivery≠0) и командный статус≠0 НЕ травят транспорт:
    /// ownership возвращён, следующий пост работает (откат без POISON).
    #[test]
    fn delivery_and_command_errors_roll_back_cleanly() {
        let blocks = parse_wire(INIT_FIX);
        let enable = block(&blocks, "EnableHCA");
        let (_w, dma, bar) = setup(8);
        let q = Cmdq::establish(&bar, &dma, false).unwrap();

        // Delivery-ошибка (0x1 signature error): транспортный сбой → Err.
        bar.completions.borrow_mut().push_back(MockCompletion {
            delivery: 0x1,
            output: vec![0u8; 16],
        });
        let err = q.post(&enable.tx, 16).unwrap_err();
        assert!(
            matches!(err, crate::err::Error::Io(_)) && err.to_string().contains("0x01"),
            "delivery-ошибка как транспортный сбой: {err}"
        );
        assert!(!q.is_poisoned(), "delivery-ошибка не травит сессию");

        // Командный статус 3 (trig): комплитка ок, статус — в output.
        let trig_blocks = parse_wire(TRIG_FIX);
        bar.completions.borrow_mut().push_back(MockCompletion {
            delivery: 0,
            output: trig_blocks[0].rx.clone(),
        });
        let done = q.post(&enable.tx, 16).unwrap();
        assert_eq!(done.output[0], 0x03);
        assert_eq!(done.delivery, 0);
        assert!(!q.is_poisoned());

        // Слот переиспользуется: третий пост проходит.
        bar.completions.borrow_mut().push_back(MockCompletion {
            delivery: 0,
            output: vec![0u8; 16],
        });
        assert!(q.post(&enable.tx, 16).is_ok());
        assert_eq!(bar.count_writes(0x18), 3);
    }

    // ---------- in-блоки: лейаут против триг-фикстры (wire-пин) ----------

    /// In-блок 576B из фикстры (сырая память старого бинарника): подписи
    /// совпадают с формулами PRM 7.14.1.1.1 — пин наших вычислений на wire.
    #[test]
    fn fixture_in_mb0_signatures_match_prm_formulas() {
        let notes = fixture_notes(TRIG_FIX);
        let mb = unhex(&notes["in_mb0_576b"]);
        assert_eq!(mb.len(), MAILBOX_BLOCK_SIZE);
        assert_eq!(
            mb[0x23e],
            !xor8(&mb[0x1c0..0x200]),
            "ctrl_sig (байты 1C0h-1FFh)"
        );
        assert_eq!(mb[0x23f], !xor8(&mb[..0x23f]), "sig = ~xor(блока без sig)");
        // next=0/block_num=0 — единственный блок.
        assert_eq!(u64::from_be_bytes(mb[0x230..0x238].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(mb[0x238..0x23c].try_into().unwrap()), 0);
    }
}
