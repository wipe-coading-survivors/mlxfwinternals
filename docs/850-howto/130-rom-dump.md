# 130. ROM-дамп iRISC (flash / BootPages / shellcode) — how-to

> **ОТМЕТКА.** Дополнительное независимое исследование (см. `docs/250-re/110-signing/`), вне
> фаз ROADMAP. Цель — дамп буткода iRISC для ответа на вопросы root-of-trust
> из `docs/250-re/110-signing/030-root-of-trust.md`:
> - где ROM читает **lifecycle** (и зависит ли от него проверка подписи);
> - где **корневой ключ** — зашит в кремний (mask ROM) или читается с флеша;
> - почему при сбое верификации на CX-5 **нет recovery-PCIe** (карта
>   «молчит», в отличие от CX-6).
>
> Статус (2026-11): вендореный крейт `crates/mlx5cmd` удалён из mlxini (замена —
> `crates/mlxdirect`, live-гейт 6/6); этот howto остаётся рабочим рецептом против
> локального чекаута `refs/src/` (разбор исторический).

> Инструмент: `refs/src/irisc-research-syndicate_mlx5cmd` (rev `f0f095b`,
> Rust, cmdif/VFIO; канон пинов —
> `docs/150-external/000-pinned-revs.md`). Все офсеты/регистра
> ниже — из его исходников.

---

## 0. Что даёт каждый дамп (и что искать)

| Дамп | Как | Что даёт | Отвечает на |
|---|---|---|---|
| **A. Flash (16MB)** | `flash-access` (рег. `MFPA`/`MFBA`) | Весь SPI-флеш: весь FW-образ, boot-FW (если есть) | где в **флеше** верификация/ключ |
| **B. BootPages** | `QueryPages(BootPages)`+`ManagePages` | Страницы буткода, которые FW отдаёт драйверу при инициализации | код, исполняемый на старте |
| **C. Память iRISC** | `run-shellcode` (read-mem) | Содержимое адресного пространства iRISC, в т.ч. mask ROM (если отображён) | **mask ROM** (кремний), корневой ключ |

**Рекомендация:** начать с **A** (готовый бинарник, самый надёжный),
затем **B/C** для mask ROM. Всё грузить в Ghidra с iRISC-модулем (у вас есть,
статья iRISC Research Syndicate от 14.02.2025, сайт
`irisc-research-syndicate.github.io`).

---

## 1. Требования и безопасность

**Железо/СР:**
- Linux-хост, **root**, IOMMU (VT-d/AMD-Vi) включён.
- Карта **не в проде**: VFIO-привязка + reset отвяжет `mlx5_core` (сеть с
  этой карты пропадёт). Делать на выделенном хосте/запасной карте.
- **Сначала бэкап флеша** (пока связан `mlx5_core`):
  `mstflint -d <dev> ri backup_flash.bin` и `mstflint -d <dev> q > card_q.txt`
  (GUID/MAC/PSID/lifecycle).

**Риски:**
- `open_from_sysfs(.., reset=true, ..)` делает **PCI reset** устройства.
- `exec_shellcode` на secure-карте **может быть заблокирован** (закрытый
  cr-space). `flash-access` (`MFBA`) по комментарию mstflint
  (`image_layout_layouts.h:713` «cr-space not closed») должен работать и на
  secure — но проверить нужно.
- Всё read-only (дамп), записи во флеш не делаем.

---

## 2. Сборка mlx5cmd

```
cd refs/src/irisc-research-syndicate_mlx5cmd
cargo build --release
# бинарники: target/release/{flash-access, run-shellcode, dump-memory,
#                        init-mem-dump, playground}
```
Зависимости: `pci_driver` (VFIO), `deku`, `irisc_asm` (асsembler iRISC),
`clap`, `env_logger`. Если `irisc_asm` под git-зависимостью — проверить
`Cargo.toml` (может потребовать доступ в сеть/локальный вендор).

---

## 3. Привязка устройства к VFIO

Определить BDF и vendor:device:
```
lspci -nn | grep -i mellanox      # напр. 04:00.0 ... [15b3:1017]
```
Привязать к `vfio-pci` (репо уже содержит скрипты):
```
# refs/src/.../setup_vfio.sh (для CX-5 0x1017):
modprobe vfio_pci
echo 15b3 1017 > /sys/bus/pci/drivers/vfio-pci/new_id
# либо точечно (bind_vfio_driver.sh <BDF>):
echo 0000:04:00.0 > /sys/bus/pci/devices/0000:04:00.0/driver/unbind
echo 0000:04:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
```
> Если device_id не `1017` — подставить свой из `lspci -nn`. После привязки
> `mlx5_core` отвяжется. Вернуть обратно: unbind от vfio-pci, bind к
> mlx5_core (или reboot).

---

## 4. DUMP A — весь флеш (flash-access)  [рекомендовано первым]

```
cd target/release
sudo ./flash-access -d /sys/bus/pci/devices/0000:04:00.0
# -> создаёт файл ./flash_data (16 MiB)
```
Что делает (из `src/bin/flash-access/main.rs`):
1. `VfioCmdIf::open_from_sysfs(dev, reset=true, init=true)`.
2. `read_register(MFPA)` — параметры флеша (JEDEC id, sector/block size;
   рег. `MFPA` = `0x9010`, `src/registers/flash.rs`).
3. Цикл `address = 0..16MiB step 0x40`: `read_register(MFBA{size:0x40,
   address})` → `data[0x40]`; рег. `MFBA` = `0x9011`.
4. Собирает в `flash_data`.

**Дальше:** `flash_data` = та же область, что `mstflint ri`. Сверить:
`sxxd flash_data` против `backup_flash.bin` (должны совпасть по FW-образу).
Искать в Ghidra: boot-код, строки верификации («signature», «digest»,
«lifecycle»), таблицы хэшей секций, константы ключей.

---

## 5. DUMP B — BootPages (QueryPages/ManagePages)

Механика (из `src/commands/query_pages.rs`, `manage_pages.rs`,
`src/cmdif/vfio.rs:74-128`):
1. `QueryPages{op_mod: BootPages=0x1}` → `num_pages` (i32).
2. Для каждой страницы — выделить DMA-страницу (4KB), взять её физ. адрес.
3. `ManagePages{op_mod: AllocationSuccess=0x1, items=[адреса]}` → **FW
   записывает содержимое бут-страниц в эти DMA-буферы**.
4. Прочитать DMA-буферы → это и есть код.

`VfioCmdIf::initialize()` (`vfio.rs:114-128`) уже вызывает
`handle_page_request(BootPages)` (и `InitPages`) при `init=true`; страницы
кладутся в `cmdif.managed_pages: HashMap<u64, AllocationGuard>`.

**Скелет дампера** (новый бинарник; адаптировать под фактический API
`AllocationGuard`/`PciRegion::read_bytes` — см. `playground/main.rs:
write_region`):
```rust
use std::path::Path;
use mlx5cmd::cmdif::vfio::VfioCmdIf;
use mlx5cmd::cmdif::CmdIf;
use mlx5cmd::commands::{EnableHCA, QueryISSI, SetISSI, QueryPagesOpMod};
use pci_driver::regions::PciRegion;

fn snapshot(cmdif: &VfioCmdIf, name: &str) -> anyhow::Result<()> {
    let mut pages: Vec<(u64, &mlx5cmd::allocator::AllocationGuard)> =
        cmdif.managed_pages.iter().map(|(p, g)| (*p, g)).collect();
    pages.sort_by_key(|(p, _)| *p);            // порядок по физ. адресу
    let mut out = Vec::new();
    for (_, g) in &pages {
        let mut chunk = vec![0u8; 0x1000];
        (**g).read_bytes(0, &mut chunk)?;       // 4KB со страницы
        out.extend_from_slice(&chunk);
    }
    std::fs::write(name, &out)?;
    println!("{name}: {} bytes, {} pages", out.len(), pages.len());
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let dev = std::env::args().nth(1).unwrap();
    // init=false: делаем init вручную, чтобы отделить BootPages от InitPages
    let mut cmdif = VfioCmdIf::open_from_sysfs(Path::new(&dev), true, false)?;
    cmdif.do_command(EnableHCA(()))?;
    cmdif.do_command(QueryISSI(()))?;
    cmdif.do_command(SetISSI { current_issi: 1 })?;

    cmdif.handle_page_request(QueryPagesOpMod::BootPages)?;
    snapshot(&cmdif, "boot_pages.bin")?;        // <-- только BootPages

    // при желании продолжить init и снять InitPages/RegularPages отдельно:
    // cmdif.handle_page_request(QueryPagesOpMod::InitPages)?;
    // snapshot(&cmdif, "init_pages.bin")?;
    Ok(())
}
```
> **Нюанс:** `initialize()` (init=true) смешивает Boot+Init страницы в одном
> `managed_pages`. Для чистого разделения — как выше (init вручную). Порядок
> страниц восстанавливается сортировкой по физ. адресу (выделяются последо-
> вательно). Не факт, что `BootPages` == mask ROM: это *страницы, которые FW
> отдаёт при инициализации*. Если там не верификация — переходите к DUMP C.

---

## 6. DUMP C — память iRISC / mask ROM (run-shellcode)

Для mask ROM (кремний) нужен read произвольной памяти iRISC. Механика:
`ExecShellcode64` (магик `0x0932`, shellcode ≤ `0xa0` байт, `src/commands/
exec_shellcode.rs`) выполняет iRISC-код, который читает память и складывает
в выходной DMA-буфер (база — рег. `r4`; результат — `st.q`).

Готовые шаблоны в `shellcodes/`:
- `test_read_mem.asm` — прочитать 8 байт из `{{address}}`:
  ```
  lbl entry
      set32 r5, {{ address }}
      ld.q  r6, r5, 0
      st.q  r0, r4, r6, 0x18
      ret.d
  ```
- `test_load.asm` / `test_shellcode.asm` — другие инструкции.

**Запуск** (`src/bin/run-shellcode/main.rs`):
```
sudo ./run-shellcode -d /sys/bus/pci/devices/0000:04:00.0 \
     -p address=0x0-0x1000:0x1000 \
     shellcodes/test_read_mem.asm  dump_results.json
# -p name=lo-hi:step — картезианское произведение параметров
# output_buffer (по умолч. 16MiB) — DMA-буфер, куда складывает shellcode
```
**Что сделать для дампа области:** написать шаблон-цикл (счётчик адреса,
`ld.q` из `[src+off]`, `st.q` в `[r4+off]`, инкремент, до `N`), уложив в
`0xa0` байт; `src` = базовый адрес mask ROM в адресном пространстве iRISC
(узнать из Ghidra/статьи iRISC — куда отображён ROM; тип. низкие адреса).
Собрать дамп из `dump_results.json` (в нём `results:[u64;3]` на итерацию).

> **Ограничение:** shellcode ≤ 256 байт — только компактный цикл. Точный
> базовый адрес ROM и доступность чтения — **гипотеза**; подтверждается
> экспериментально (на запасной карте). Если `ExecShellcode` отклонён
> (secure) — путь C недоступен, опираться на A/B.

---

## 7. MTCR-разблокировка (если нужно для shellcode/trace)

`playground/main.rs` перед shellcode/itrace делает:
```
mtcr.change_address_space(AS_CR_SPACE);
mtcr.write_dword(0x23f0, 0xbadc0ffe);     // «badc0ffe unlock»
ICmd::from_mtcr(..).set_itrace(..);
check_badc0ffe_unlocked();
```
`flash-access` этого **не** делает (работает через `open_from_sysfs(..,
init=true)`). Если DUMP C не пускает — добавить разблокировку.

---

## 8. Ghidra (iRISC-модуль)

Канонический путь (2026-09-16): образ `mlxini-ghidra-irisc`
(`docker/ghidra-irisc.containerfile`: JDK 21 + Ghidra 12.1.3 + iRISC-модуль
+ скрипты `scripts/ghidra/`): `make ghidra-decode IMG=<fw-image>
SECTION=<0xNN>` (секция извлекается `mlxfwutil.py extract --raw`, base = 0x0 —
для iRISC не важен, адресов в коде нет); dev-цикл без пересборки образа —
`make ghidra-decode-dev` (скрипты из репо маунтом). Ручной разбор ниже —
fallback.

1. Импортировать `flash_data` / `boot_pages.bin` / дамп памяти как
   raw-binary (большинство — big-endian dword-ориентированные; попробовать
   BE, при нечитаемом коде — LE).
2. Применить **iRISC-модуль** (ваш, из статьи 14.02.2025) — даёт ISA,
   декодер, (при наличии) имена/карту памяти.
3. Базовый адрес = смещение, при котором код становится осмысленным
   (для флеша — смещение образа внутри 16MB; для BootPages — 0).

## 9. Чек-лист поиска (root-of-trust, docs/250-re/110-signing/030-root-of-trust.md)

- [ ] **Точка входа** буткода (вектор сброса / первый блок кода).
- [ ] **Чтение lifecycle**: регистр/поле (сопоставить с MGIR `life_cycle`,
      `docs/250-re/110-signing/065-secure-fw-bit.md`); ветвление `if lifecycle == SECURED { verify }`.
- [ ] **Корневой ключ**: константа в коде/данных (→ кремний) vs загрузка из
      флеша/секции (→ flash). Искать 512-байтные блоки, RSA-4096 параметры,
      UUID ключа (`c55d…` — см. docs/250-re/110-signing/005-mechanism.md).
- [ ] **Алгоритм верификации**: какой digest (SHA-256/512), над какими
      секциями/хэшами, как связан с ITOC-`sec_crc`.
- [ ] **Путь сбоя**: что происходит при неудаче — почему на CX-5 **нет**
      recovery-PCIe (сравнить с CX-6, где recovery-эндпоинт есть).
- [ ] **Связь с FNP**: как ROM определяет FNP/life-flash (пин/регистр) и что
      именно он отключает.

---

## 10. Быстрый путь (без реверса)

Если цель — просто «поднять 56+100», а не понять ROM: **docs/750-exp/150-hw-verify-100g56g** —
записать патченый образ (`patch_56g.py`) через FNP и включить. ROM-дамп
нужен, только если быстрый путь не даст загрузиться (и тогда — для точной
причины).
