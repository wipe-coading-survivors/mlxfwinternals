# 010. Syndicate: `mlx5fw` / `mlx5cmd` — карты репо

> **Статус (2026-11-09):** вендор удалён 2026-11 (крейт `mlxdirect`,
> live-гейт эквивалентности 6/6); разбор исторический.
>
> Источник: обход чекаутов `refs/src/irisc-research-syndicate_mlx5fw`,
> `…_mlx5cmd` (2026-11-07, журнал
> `docs/superpowers/journal/2026-11-07-restructure-external-task-02.md`);
> перенос 30 §2–3 (исходный статический разбор 2026-09-06). Назначение —
> навигация по чужим репо: структура и ключевые модули «где что лежит»;
> наши RE-факты форматов/подписи — в 250-re, здесь не дублируются.
> Pinned rev — `../000-pinned-revs.md`.
>
> Связи: mstflint walkthrough + таблица расхождений —
> `../100-mstflint/010-walkthrough.md`; FS4 ITOC/hwpointers —
> `docs/250-re/100-formats/030-fs4.md`; CRC — `…/025-crc.md`; FW-трасса и
> проба 0x0932 — `…/065-fw-trace.md`; сигн-секции —
> `docs/250-re/110-signing/015-key-sections.md`; root-of-trust/MTRC —
> `…/030-root-of-trust.md`; ROM-дамп через mlx5cmd —
> `docs/850-howto/130-rom-dump.md`; iRISC — `docs/010-roadmap/100-irisc.md`,
> Rust-тул — `docs/010-roadmap/160-mlxfw-rust.md`.

Роли в проекте: `mlx5fw` — **основа Rust-тула** (с поправками), `mlx5cmd` —
**основа фазы 5** (flash I/O без mstflint); вердикты — §5. Оба репо без
лицензии — статус и план в §4.

## 1. `mlx5fw` (rev `05378b4` @ 2024-11-09)

Rust-парсер FS4 на `deku` (декларативный бинарный парсинг). Компактное
репо: `Cargo.{toml,lock}`, `.gitignore` и только пять исходников —
`src/{main,crc,firmware}.rs`, `src/structures/{hwpointers,itoc}.rs`
(+ `src/structures.rs` — декларации модулей).

| Путь | Что содержит |
|---|---|
| `src/crc.rs` | `HW_CRC_TABLE [u16; 256]` :2; `calc_hwcrc` :21 — табличный HW-CRC; `calc_crc16` :28 — побитовый (poly `0x100b`, init/final XOR `0xffff`); `calc_crc16_words` :41 — по 32-бит словам (poly `0x100b`, +16 нулевых бит). Наши факты по вариантам CRC — `docs/250-re/100-formats/025-crc.md` |
| `src/firmware.rs` | `Firmware` (обёртка `Vec<u8>` c read/write) :8; `hwpointers()` — чтение @ `0x18` :45; `itoc()` — от `hwpointers.toc.ptr + 0x20` шагом `0x20` до линии `0xff` :54–66; `FirmwareStructure<T>` — кортеж `(offset, T)` c `Deref/DerefMut`, `read`/`write`/`write_bytes` :70–121 |
| `src/structures/hwpointers.rs` | `HwPointer = ptr[32] + crc[16]` (8B) :6; `HwPointers {boot_record, boot2, toc, tools}` :15; `Boot2` :24 |
| `src/structures/itoc.rs` | `ItocEntryType` — enum типов секций (`0x02`…`0xeb`, вкл. сигн-типы `0xa0/0xa1/0xa3/0xa4`) :13; `ItocEntry` :142 c `calc_itoc_entry_crc` :181 и `content()` :186. Лейаут записи — см. §3 |
| `src/main.rs` | clap-CLI: `show-sections`, `dump-sections`, `dump-code` (вырезка clcrc: чанки `0x44` → данные `0x40`), `replace-section` (запись секции + пересчёт section-CRC; clcrc-фрейминг `0x40` + `0000` + LE hwcrc) |

Куда смотреть по фактам: лейаут hwpointers/ITOC —
`docs/250-re/100-formats/030-fs4.md`; сигн-типы `0xA0…0xA4` —
`docs/250-re/110-signing/015-key-sections.md`; clcrc-фрейминг iRISC-секций —
`docs/250-re/120-irisc/025-boot-injection.md`.

## 2. `mlx5cmd` (HEAD `f0f095b`, ветка `wip-mlxini-mtrc-tools` поверх upstream `67617d1`)

Rust-доступ к карте из userspace через VFIO — без MFT/mstflint:
cmdif-обмен командами (ACCESS_REGISTER и др.), прямой mtcr/CR-space и
iRISC-шеллкоды. Крейт зависит от `irisc_asm` (assembling на лету в
бинках). Rev-детали (WIP-коммит mtrcdump/regdump, незакоммиченные правки) —
`../000-pinned-revs.md`.

| Путь | Что содержит |
|---|---|
| `src/registers/flash.rs` | **`MFPA`** :8, REGISTER_ID `0x9010` — параметры flash: `boot_address`, `jedec_id`, `block_size`/`sector_size`, `flash_num`, флаги erase/write-protect. **`MFBA`** :52, REGISTER_ID `0x9011` — доступ: `address` + `data[0x40]` — **64 байта на операцию** (поле `size` — 9 бит) |
| `src/registers/mtrc.rs` | Семейство MTRC trace-регистров: `MtrcCapReg` (REGISTER_ID `0x9040`: `trace_owner`, `trace_to_memory`, `num_string_db`, `string_db_param[8]`), `MtrcStdbReg` (string DB: `offset` + `data[64]`), `MtrcConfReg`, `MtrcCtrlReg`. По нашему RE MTRC — микрокодный TRACER (наблюдение, не memory-read) — `docs/250-re/110-signing/030-root-of-trust.md` |
| `src/mtcr.rs` | `MTCR` :25 — PCI-мост адресных пространств (`AS_CR_SPACE`, `AS_ICMD`, `AS_ICMD_EXT`, `AS_NODNIC_INIT_SEG`, `AS_EXPANSION_ROM`; `VCR_*`-адреса) поверх crate `pci_driver`; `ICmd` :92 — icmd-команды поверх mtcr |
| `src/cmdif.rs` | `trait CmdIf` :8 — `exec_command`/`do_command`, `read_register`/`write_register` через ACCESS_REGISTER |
| `src/cmdif/vfio.rs` | `VfioCmdIf` :22 — VFIO-транспорт: `open_from_sysfs`, `initialize` (HCA/pages/cmdq) |
| `src/commands/` | Обёртки icmd-команд: `exec_shellcode.rs` — `ExecShellcode`/`ExecShellcode64` (opcode `0x0932`, `shellcode[0xa0]`, args u32[6]/u64[3] + results); `access_register`, `query_hca_cap`, `manage_pages`, `create_mkey`, `uar`, `eq`, `pd`, `issi`, `hca`, `query_adapter`, `query_pages`, `set_driver_version`, `query_flow_table` |
| `src/{lib,error,init}.rs; src/{allocator,mailbox,cqe}.rs` | Каркас крейта; pages-аллокатор (`AllocationGuard`), mailbox, CQE-механика |
| `src/bin/` | CLI-утилиты: `flash-access` (MFPA/MFBA — флеш), `dump-memory`, `run-shellcode`, `init-mem-dump`; `mtrcdump` + `regdump` — наш WIP-коммит `f0f095b`; `playground`; `query-flow-table` (незакоммиченный WIP) |
| корень репо | `setup_vfio.sh`, `bind_vfio_driver.sh` (подготовка VFIO), `check_data.py`, `shellcodes/test_*.asm` — 11 iRISC-тест-шеллкодов (питание `docs/010-roadmap/100-irisc.md`) |

Куда смотреть по фактам: рецепт ROM-дампа на базе репо (сборка,
`flash-access`, `dump-memory`) — `docs/850-howto/130-rom-dump.md`;
root-of-trust-итоги (MTRC, ROM/boot) —
`docs/250-re/110-signing/030-root-of-trust.md`; проба `0x0932`
(ExecShellcode) — `docs/250-re/100-formats/065-fw-trace.md` §5.

## 3. Расхождение `ItocEntry` (30 §2.2)

`ItocEntry` (`src/structures/itoc.rs:142`) парсит поля не по
mstflint-лейауту: `size` 24 бита (mstflint — 22), `flash_addr` 32 бита без
маски (mstflint — 29 бит + маска бита 160); CRC записи — `calc_crc16(0x0000,
bytes[..0x1e])`, эквивалент init `0xffff` над 30 байтами (совпадает).
Решение: порт следует mstflint. Полная таблица расхождений (30 §7) —
приложение `../100-mstflint/010-walkthrough.md`.

## 4. Licensing-статус

- В обоих чекаутах файла лицензии нет (LICENSE/COPYING отсутствуют,
  проверено 2026-11-07; README тоже нет) — `../000-pinned-revs.md`.
- Upstream-вопрос открыт: irisc-research-syndicate/mlx5cmd issue #1
  (https://github.com/irisc-research-syndicate/mlx5cmd/issues/1).
- Clean-room-план и публикация — `roadmap-restructure.md` §6 (трек
  лицензий: vendored-без-лицензии не публикуемо; два пути — лицензия от
  синдиката либо clean-room).
- Crates-судьба для mlxini: вендор крейтов `irisc-asm`/`mlx5cmd` (были в
  `crates/`) **удалён 2026-11** — замена: чистый крейт `crates/mlxdirect`
  (live-гейт эквивалентности 6/6; публикация — отдельной спекой),
  ассемблер — Python `scripts/irisc/irisc_asm.py`. Замену `HW_CRC_TABLE`
  генератором и лиценз-трек см. `roadmap-restructure.md` §6.

## 5. Значение для mlxini (вердикты 30 §2.1/§3)

- `mlx5fw` — основа Rust-тула (фаза 3, карта
  `docs/010-roadmap/160-mlxfw-rust.md`, статус seed): ITOC-локация по
  hwpointers (`toc.ptr + 0x20`, не хардкод — устойчиво к Dell `@0x4000` и
  др.), `FirmwareStructure`-абстракция, CRC-ядро, `ItocEntryType`;
  `ItocEntry` — с поправкой под mstflint-лейаут (§3).
- `mlx5cmd` — основа фазы 5 (flash I/O без mstflint): чтение/запись флеша
  блоками 64B через `MFBA` + инициализация через `MFPA`; `exec_shellcode` —
  fallback, если регистры flash закрыты. Python-PoC на этапе 5 может
  ходить через `mstreg`/`mstflint` (медленнее, без root/VFIO), Rust —
  через этот путь.
