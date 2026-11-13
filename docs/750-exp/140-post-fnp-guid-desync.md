# 140. Post-FNP quirk: `mstflint q` Base GUID/MAC = N/A при целой NVRAM (MNVDA desync)

Статус: **CLOSED** (2026-09-11). Фикс: `--ignore_dev_data --nofs` burn образа
с GUID. Offline-инструмент: `mlxfwutil.py guides` (factory-образ + GUID/MAC →
bootable образ, `mstflint verify` green). Live-burn (Task 12) — **успешен**:
identity (GUID/MAC/PSID) не изменилась, порт Active 25G, откат не
потребовался — §8.8. Отклонение spec §4.1.3 (Task 11): mstflint-green на
slot-B-выходе (D1.bin) недопустим в file-режиме mstflint (magic @0x0) —
зафиксировано в плане (Global Constraints), решение владельцу на приёмке.

Связь: `docs/850-howto/100-cross-flash-ops` §9.1 (FNP-recovery), `docs/750-exp/110-dell-base-rework` §T15 (restore 1012-ADA),
`docs/750-exp/120-eda-ib-node` (EDA-IB node), `refs/src/mstflint` (source).

> **Практика (2026-09-23, чтобы не наступать снова):** чтобы не терять гуиды
> и не «танцевать с бубном» `mstflint --guid/--mac sg` после ребута —
> вшивайте GUID/MAC в образ **до** burn через mlxfwutil:
> `python3 mlxfwutil.py guides <img.bin> --guid 0x<реестр `CARD_CX5_25G_GUID`> --mac 0x<реестр `CARD_CX5_25G_MAC`> -o out.bin`
> (mDevInfo + MFG_INFO, self-verify), затем burn этого образа с
> `--nofs --ignore_dev_data`. Журналы: `2026-09-23-irisc-isa-fuzz-task-06/07`
> (инжект проверен live: netdev MAC поднялся сразу, zero-MAC не воспроизвёлся).

## 1. Симптом

После FNP-recovery-burn T15 (`mstflint -i <kg> -ocr -apc --nofs --ignore_dev_data -y b`)
на карте 01:00.0 (CX-5 Ex MCX512A-ADA, PSID MT_0000000361, 25GbE):

- `mstflint -d 01:00.0 q` → **Base GUID: N/A, Base MAC: N/A** (GuidsNumber=4 на месте).
- Фактическая идентичность **цела** (подтверждено независимо):
  - sysfs `node_guid` mlx5_7/8 = реестр `CARD_CX5_25G_GUID` / `_P1_GUID`;
  - MAC `enp1s0f0np0` = реестр `CARD_CX5_25G_MAC`, `enp1s0f1np1` = Base MAC + 1;
  - ibstat Node GUID = реестр `CARD_CX5_25G_GUID`, port0 Active LinkUp 25G.

Т.е. карта работает, идентичность на месте, но `mstflint q` её не видит.

## 2. Где NVRAM и что в ней (живой raw-дамп)

Живой дамп 01:00.0 (`mstflint rb 0x0 0x1000000`, 16MiB, конвертирован в бинарник —
`rb` отдаёт ASCII-слова `0xXXXXXXXX`, не бинарник; mstflint его не открывает):

| Область | pre-дамп (e0_pre) | живой дамп |
|---|---|---|
| Slot A magic (0x0) | MTFW | MTFW |
| Slot B magic (0x800000) | zeroed4 | **MTFW** |
| `mDevInfo` (0xfe0000) | GUID на месте | **GUID на месте** |
| Node GUID (0xfe0028) | реестр `CARD_CX5_25G_GUID` | **= pre** |
| GUID2 (0xfe003a) | реестр `CARD_CX5_25G_MAC` | **= pre** |
| `DTOC` (0xfff000) | таблица | **таблица** |

**Вывод: NVRAM (device-data/DTOC) не затёрта**, GUID физически на месте.
Port GUID (производный Base GUID + port#) в NVRAM не ищутся — производные (Node GUID + port#).

## 3. Откуда `mstflint q` читает Base GUID (source)

Путь: `q full` → `extractMacsGuids` (`fw_comps_mgr.cpp:1859`):

```cpp
runMNVDA(nvBaseMacGuidData, 64, NV_BASE_MAC_GUID_IDX, REG_ACCESS_METHOD_GET, false);
runMNVDA(nvBaseMacGuidCap,  64, NV_BASE_MAC_GUID_CAP_IDX, REG_ACCESS_METHOD_GET, false);
tools_open_nv_base_mac_guid_unpack(&currMacGuid, ...);
UID_EXTRACT(fwQuery->base_guid.uid, currMacGuid.base_guid);   // ← Base GUID
fwQuery->base_guid.num_allocated = currMacGuidCap.num_of_allocated_guids;
```

- Base GUID читается **не прямым чтением NVRAM/DTOC**, а через **FW-команду `MNVDA`**
  (Management NV Data Access) с индексом `NV_BASE_MAC_GUID_IDX`.
- Это **не access-реестр** — не читается `mstreg`/`mlxreg` (нет в ADB
  `register_access_table.adb`: «Can't find access register name: NV_BASE_MAC_GUID»).
- `sg` (set GUID) использует **ту же** команду `MNVDA` (`SET`, `fw_comps_mgr.cpp:1916`).

**Контраст путей:**

| Инструмент | Путь | 01:00.0 |
|---|---|---|
| ibstat / kernel mlx5 / sysfs | NVRAM/DTOC → состояние FW | GUID **есть** |
| raw-дамп NVRAM | 0xfe0028/0xfe003a | GUID **есть** |
| `mstflint q` | **FW-команда `MNVDA`** (`NV_BASE_MAC_GUID_IDX`) | **N/A** |

## 4. Что НЕ синхронизирует

| Действие | Результат |
|---|---|
| `sg` (норм. режим, `--guid/--mac`) | «Updating GUID section - OK», но `q` N/A |
| `sg -ocr` + warm-reboot (`shutdown -r`) | N/A (не изменилось) |
| cold power-cycle (из FNP, единственный выход) | N/A (по данным владельца) |
| **Re-burn `restore_1012ada.bin`** (штатный `b`, без `--ignore_dev_data`) + reboot | **N/A** |
| **Re-burn `e0_pre_raw.bin`** (FS4, 16.35.1012, GUID в образе верный) штатным `b` + reboot | **N/A** |
| `mstflint wb` (raw write 16MiB) | **FAIL**: "Flash erase 0x0: Register access bad parameter" |
| `mstflint e 0x0` (erase sector) | **FAIL**: та же ошибка |
| **`--ignore_dev_data --nofs`** burn `e0_pre_raw.bin` + reboot | **FIXED**: GUID/MAC на месте |

`sg` пишет (MNVDA SET «OK»), но `MNVDA` GET (`q`) по-прежнему N/A →
**рассинхрон между SET и GET внутри FW-пути `MNVDA`**, а не кэш (warm/cold-reboot не сбрасывает).

**Ключевой вывод 2026-09-11:** даже burn образа с **корректным Base GUID** в device-data
(`e0_pre_raw.bin`: `Base GUID:` реестр `CARD_CX5_25G_GUID`) **не пересоздаёт MNVDA GET-путь**.
Рассинхрон не в байтах на флэше — он во **внутреннем состоянии FW** (NV-data метаданные /
MNVDA TLV-стек), которое не инициализируется ни штатным burn, ни reboot.

## 5. Гипотеза корня

FNP-recovery-burn (`--nofs --ignore_dev_data`, запись через **cr-space**) оставил
NV-data-метаданные / `MNVDA`-путь в состоянии, которое:
- не сбрасывается warm/cold-reboot'ом;
- не перекрывается `sg` (MNVDA SET пишет в одно место, GET читает из несинхронного);
- **не пересоздаётся штатным burn** (подтверждено 2026-09-11: burn `restore_1012ada.bin`
  и `e0_pre_raw.bin` — оба N/A после reboot).

Вероятный механизм: `MNVDA` GET-путь в FW инициализируется из NV-data TLV-стека
(не из raw NVRAM-байтов). FNP-recovery-burn через cr-space (`--nofs`) записал raw-байты
NVRAM, но **не пересоздал TLV-стек** (или создал его в повреждённом виде). Штатный burn
также не пересоздаёт TLV-стек — он записывает FW-компоненты, а device-data (TLV-стек)
сохраняется из текущего состояния.

**Единственный путь, который мог бы пересоздать TLV-стек:** `--ignore_dev_data`
(factory reset device-data) — но это сбрасывает GUID на factory, и `sg` после него
**не восстанавливает** MNVDA GET (подтверждено выше).

**Подтверждённый фикс (2026-09-11):** `--ignore_dev_data --nofs` burn → **полный
overwrite flash** (включая NV-data метаданные / MNVDA TLV-стек) → MNVDA GET-путь
пересоздан → `q` показывает GUID/MAC.

**Вариант A (raw-дамп с GUID):**
```
mstflint -d 01:00.0 -i e0_pre_raw.bin --ignore_dev_data --nofs -y b
# reboot → q OK
```

**Вариант B (factory-образ + sg, без raw-дампа) — НЕПОЛНЫЙ:**
```
mstflint -d 01:00.0 -i restore_1012ada.bin --ignore_dev_data --nofs -y b
# reboot
mstflint -d 01:00.0 --guid 0x<реестр `CARD_CX5_25G_GUID`> --mac 0x<реестр `CARD_CX5_25G_MAC`> -y sg
# reboot → q OK, НО kernel MAC = 00:00:00:00:00:00
```
`sg` обновляет только MNVDA-путь, не raw NVRAM/DTOC. Kernel mlx5 читает MAC из
NVRAM → видит нули. **Вариант B не использовать.**

**Вариант A (raw-дамп) — единственный полный фикс.**

**Почему штатный `b` не работал, а `--ignore_dev_data --nofs` — работал:**
- Штатный `b` (MCC flow) записывает FW-компоненты, **device-data сохраняется** из
  текущего состояния (MNVDA TLV-стек не пересоздаётся).
- `--ignore_dev_data --nofs` (legacy flow) записывает **весь flash**, включая
  DToc + device area из образа (fs4_ops.cpp:2726) → MNVDA TLV-стек пересоздан.

## 6. План синхронизации

1. ~~**`strace` на `sg`**~~ — **done** (2026-09-11). Результат: `mstflint` ходит в
   PCI config space (fd 4), `pwrite64` только в 4 offset'а (196/204/208/212 = cr-space
   command interface), `MNVDA` reg ID `0x9024` в `pwrite64` не виден (несётся внутри
   TLV-структуры cr-space протокола). Полный разбор cr-space — отдельная задача.
2. ~~**Re-burn known-good 1012-ADA БЕЗ `--ignore_dev_data`**~~ — **done, N/A** (2026-09-11).
3. ~~**Re-burn `e0_pre_raw.bin`** (FS4, GUID в образе верный)~~ — **done, N/A** (2026-09-11).
4. ~~`wb` / `erase`~~ — **blocked**: FW в normal-state не принимает erase
   ("Register access bad parameter"). Нужен power-cycle → `wb` до загрузки FW.
5. ~~**Попробовать из FNP**~~ — **не нужно**: фикс найден (шаг 6).
6. ~~Откат — known-good 1012-ADA (`cd95e4fe…`)~~ — **не нужен**.
7. **FIXED** (2026-09-11): `--ignore_dev_data --nofs` burn `e0_pre_raw.bin` + reboot
   → `q` показывает Base GUID/MAC.

## 7. Журнал / результаты

- 2026-09-11 (утро): живой raw-дамп → NVRAM цела. `sg -ocr` + warm-reboot → N/A.
- 2026-09-11 (день):
  - `strace` на `sg`: 3.9M строк, `pwrite64` в 4 offset'а (196/204/208/212),
    `MNVDA` 0x9024 не виден в raw bytes (cr-space TLV-протокол). Лог:
    `root-mellanox:/tmp/sg_strace2.log`.
  - **Re-burn `restore_1012ada.bin`** (штатный `b`, без `--ignore_dev_data`) + reboot
    → `q` N/A. **Не помогло.**
  - **Re-burn `e0_pre_raw.bin`** (FS4 16.35.1012, `Base GUID:` реестр
    `CARD_CX5_25G_GUID` в самом образе) штатным `b` + reboot → `q` N/A. **Не помогло.**
  - `mstflint wb e0_pre_raw.bin 0x0` → FAIL "Flash erase 0x0: Register access
    bad parameter. FW image was already updated on flash, but not loaded."
  - `mstflint e 0x0` → тот же FAIL.
  - Source: `rb` = `mf_read` (всегда работает), `wb`/`e` = `erase_sector` →
    `mf_erase` (требует flash-state, в normal-runtime FW erase заблокирован).
  - **Вывод:** рассинхрон не в flash-контенте, а во внутреннем состоянии FW
    (MNVDA TLV-стек / NV-data метаданные). Штатный burn не пересоздаёт.
  - **`--ignore_dev_data --nofs`** burn `e0_pre_raw.bin` + reboot →
    **`q` показывает Base GUID/MAC = реестр `CARD_CX5_25G_GUID`/`_MAC`**.
    **FIXED.** Механизм: полный overwrite flash (DToc + device area из образа)
    пересоздал MNVDA TLV-стек.
  - **Вариант B (без raw-дампа):** factory burn `restore_1012ada.bin
    --ignore_dev_data --nofs` → reboot → `sg --guid --mac` → reboot →
    **`q` показывает GUID/MAC**. `sg` работает после пересоздания TLV-стека
    (не работал при рассинхроне). `Orig Base GUID/MAC: N/A`.
- Статус: **рассинхрон устранён.** FNP-тест не нужен.

## 8. A/B эксперимент: что именно пишет `sg` и что нужно для полного фикса

### 8.1. Методика

4 raw-дампа (16MiB, `mstflint rb 0x0 0x1000000 <file>`):

| Дамп | Состояние | Slot A | Slot B |
|---|---|---|---|
| D1 | factory ×2 burn + reboot (оба слота factory, GUID нет) | zeroed | MTFW |
| D2 | D1 + `sg` + reboot | zeroed | MTFW |
| D3 | D2 + factory burn #3 + reboot (A/B swap) | MTFW | zeroed |
| D4 | D3 + `sg` + reboot (working: FW + GUID) | MTFW | zeroed |

A/B swap подтверждён: D2→D3 слоты перешли (B→A). `sg` слоты не меняет.

### 8.2. Что пишет `sg` (D1 vs D2, 16371 dword)

Только 3 области, **32 байта реальных данных**:

```
0x00fb0000: 00000000 → 4d544346  "MTCF" magic
0x00fb0010: 00800030 → 01800030  valid flag (bit 24: 0→1)
0x00fb003c: 00000000 → 00006a84  TLV offset/size
0x00fb0c00: 00000000 → 80000010  TLV header (type=0x8000, len=0x10)
0x00fb0c04: 00000000 → 00000002  index = NV_BASE_MAC_GUID_IDX
0x00fb0c08: 00000000 → 00002079  flags
0x00fb0c0c: 00000000 → ⟨реестр `CARD_CX5_25G_MAC`[0:4]⟩  MAC[0:4]
0x00fb0c10: 00000000 → ⟨реестр `CARD_CX5_25G_MAC`[4:8]⟩  MAC[4:8]
0x00fb0c14: 00000000 → ⟨реестр `CARD_CX5_25G_GUID`[0:4]⟩  GUID[0:4]
0x00fb0c18: 00000000 → ⟨реестр `CARD_CX5_25G_GUID`[4:8]⟩  GUID[4:8]
```

Всё в секции **NV_DATA0** (DTOC addr=0xfb0000, size=0x10000, crcf=1 → no CRC).
Остальные 16361 dword — просто `00000000` → `ffffffff` (zeroed → erased flash).

### 8.3. D1 (factory) vs e0_pre_raw (working) — метаданные

Без кода FW и PXE-рома. Реальные данные:

| Адрес | D1 (factory) | REF (working) | Секция DTOC | CRC? |
|---|---|---|---|---|
| 0xfd0000 | `6d446576` ("mDev") | `00000000` | DEV_INFO #1 (crcf=2) | crcf=2 → INSECTION (только при валидной сигнатуре, §8.5) |
| 0xfe0000-0c | zeros | `6d446576 496e666f 2342cafa bacafe00` | DEV_INFO #2 (crcf=2) | crcf=2 → INSECTION (только при валидной сигнатуре, §8.5) |
| 0xfe0020 | `00000108` | `00000104` | DEV_INFO #2 | crcf=2 → INSECTION (только при валидной сигнатуре, §8.5) |
| 0xfe0028-2f | zeros | ⟨реестр `CARD_CX5_25G_GUID`⟩ (Node GUID) | DEV_INFO #2 | crcf=2 → INSECTION (только при валидной сигнатуре, §8.5) |
| 0xfe0030 | `00000108` | `00000104` | DEV_INFO #2 | crcf=2 → INSECTION (только при валидной сигнатуре, §8.5) |
| 0xfe0038-3f | zeros | ⟨реестр `CARD_CX5_25G_MAC`⟩ (Base MAC) | DEV_INFO #2 | crcf=2 → INSECTION (только при валидной сигнатуре, §8.5) |
| 0xff8008-0c | `"0036\0"` | `"0042\0"` + `35` | 0xE0 (crcf=**0**) | **Да** |
| 0xff8028-3c | zeros | GUID + MAC (копия) | 0xE0 (crcf=**0**) | **Да** |
| 0xfff0d8-fc | разное | разное | счётчики | — |

### 8.4. Структура mDevInfo (512B, `image_layout_device_info`)

```
0x00  signature0  = 0x6d446576 ("mDev")   ← фикс. magic
0x04  signature1  = 0x496e666f ("Info")   ← фикс. magic
0x08  signature2  = 0x2342cafa            ← фикс. magic
0x0c  signature3  = 0xbacafe00            ← фикс. magic
0x10  minor_version (8b) | major_version (16b)
0x20  guids: num_allocated(8b) step(8b) num_allocated_msb(8b) rsvd(8b)
0x28  guids.uid (64b) = Base GUID
0x30  macs: num_allocated(8b) step(8b) num_allocated_msb(8b) rsvd(8b)
0x38  macs.uid (64b) = Base MAC (upper 16b reserved)
0x6c  vsd_vendor_id = 0x15b3
0x70  vsd[209]
0x160 keys[4] (operation keys)
0x1fe crc (16b) — INSECTION CRC (см. ниже)
```

**CRC @0x1FE-0x1FF** (lower-16 последнего DW) = CRC-16 (алгоритм
`crc16_mlx`, docs/250-re/100-formats/025-crc.md) по первым 508B (127 DW) структуры. mstflint
проверяет её только при валидных 4 сигнатурах (INSECTION, crcf=2;
`fs4_ops.cpp:770-810,795`).

Разница factory vs working: reserved byte `0x08` → `0x04` (0x23, 0x33).

### 8.5. DTOC CRC-флаги (ключевое для `ww`/`wbne`)

| Секция | Тип | Адрес | crcf | CRC секции |
|---|---|---|---|---|
| NV_DATA0 (MTCF) | 0xE6 | 0xfb0000 | 1 | **NOCRC** — не проверяется |
| DEV_INFO #1 | 0xE1 | 0xfd0000 | 2 | **INSECTION** — только при валидной сигнатуре mDevInfo |
| DEV_INFO #2 | 0xE1 | 0xfe0000 | 2 | **INSECTION** — только при валидной сигнатуре mDevInfo |
| 0xE0 (GUID/MAC copy) | 0xE0 | 0xff8000 | **0** | **INITOCENTRY** (sec_crc в TOC-entry) |
| VPD_R0 | 0xE3 | 0xff8140 | **0** | **INITOCENTRY** (sec_crc в TOC-entry) |

`crcf`-значения (`CRCTYPE`, `fs4_ops.h:243-248`; проверка
`fs4_ops.cpp:770-810`):
- `crcf=0` (INITOCENTRY): sec_crc в TOC-entry = CRC-16 данных секции
  (`crc16_mlx`, docs/250-re/100-formats/025-crc.md);
- `crcf=1` (NOCRC): не проверяется;
- `crcf=2` (INSECTION): CRC **внутри секции** — CRC-16 по первым
  `size-1` DW, хранится в lower-16 последнего DW. Для DEV_INFO (0xE1)
  проверяется **только при валидной сигнатуре mDevInfo**
  (`fs4_ops.cpp:795`).

**Вывод:** запись в **валидный** DEV_INFO — **нужен пересчёт INSECTION CRC**
(последние 2 байта секции). Запись в 0xE0 (0xff8000) — **нужен пересчёт
sec_crc + entry_crc** в DTOC-entry. (До 2026-09-11 здесь было записано
«crcf=2 → нет CRC» — неверно.)

### 8.6. План восстановления без raw-дампа (offline)

1. Взять factory-образ (FS4, `Base GUID: N/A`)
2. В **существующий валидный** mDevInfo DEV_INFO #1 (0xfd0000; factory
   содержит ровно один валидный, GUID=0): guid @+0x28, mac @+0x38,
   пересчитать INSECTION CRC (последние 2 байта). DEV_INFO #2 (0xfe0000) —
   **не трогать** (сигнатура zeroed) — иначе «Two "DEV_INFO" info
   sections» (`fs4_ops.cpp:881-890`: ровно один валидный).
3. В 0xE0 (0xff8000): копия guid @+0x28, mac @+0x38 + пересчёт sec_crc + entry_crc.
4. Burn: `mstflint -i <patched> --ignore_dev_data --nofs -y b` + reboot
5. `sg` не нужен (GUID уже в flash)

Инструмент: `mlxfwutil.py guides <image> --guid 0x… --mac 0x… -o out`
(self-verify перед записью; `scripts/probes/inject_guids.py` — обёртка над ним).

### 8.7. Реальная причина «Bad CRC» (верифицировано 2026-09-11)

Воспроизведение: factory 1012-ADA `.bin` (md5
`cd95e4febf6b8bbe6768c66665aab3e7`) + старый `inject_guids.py` @ commit
`1d007d38` → `mstflint -i patched verify`:
`DEV_INFO /0x00fe0000/ - wrong CRC (exp:0xfa1, act:0x0)`.

Причины (верифицировано, см. docs/250-re/100-formats/035-fs4-hashes.md):
1. **INSECTION CRC mDevInfo** — старый скрипт писал второй mDevInfo
   @0xfe0000 без CRC внутри секции (crcf=2 → CRC в последних 2 байтах,
   проверяется при валидной сигнатуре, `fs4_ops.cpp:770-810,795`).
2. **Правило единственного валидного mDevInfo**
   (`fs4_ops.cpp:881-890`) — factory уже содержит валидный mDevInfo
   @0xfd0000 (GUID=0, CRC 0xD5B4); второй валидный → «Two "DEV_INFO"
   info sections».

Hashes table как причина **исключена**: `hashes_table_pointer` =
0xFFFFFFFF во всех локальных образах — mstflint проверку пропускает
(docs/250-re/100-formats/035-fs4-hashes.md, эмпирика 2026-09-11).

**Верифицированный рецепт** (2026-09-11, offline):
- factory `.bin` → патч mDevInfo @0xfd0000 (guid, mac, CRC → 0x0CA0) +
  0xE0 @0xff8000 (guid, mac, sec_crc → 0xE444, entry_crc) →
  `mstflint -i out verify`: «FW image verification succeeded. Image is
  bootable.»; `mstflint -i out q`: Base GUID/MAC = реестр
  `CARD_CX5_25G_GUID`/`_MAC`; PSID не тронут.

Статус: план §8.6 **исполняем**; инструмент — `mlxfwutil.py guides` (этот
репозиторий). Live-burn: результат — ниже (Task 12 плана
`docs/superpowers/plans/2026-09-11-fs4-hashes-table-devinfo.md`).

### 8.8. Live-burn guides-patched образа (Task 12, 2026-09-11, subagent)

Цель: прошивка **slot-A** образа, собранного из factory 1012-ADA через
`mlxfwutil.py guides` с **текущими** GUID/MAC карты (identity не меняется) —
валидация конвейера build→guides→burn→verify. Карта 01:00.0,
`root-mellanox`; mstflint 4.36.0 (f3a3dab) и на сервере, и на хосте
(docs/850-howto/100-cross-flash-ops §6: burn — только 4.34.0+). Журнал —
`docs/superpowers/journal/2026-09-11-fs4-hashes-table-devinfo-task-12.md`.

**Precheck + бэкап (docs/850-howto/100-cross-flash-ops §1):** дискриминатор совпал (`dc`:
`description = ConnectX-5 Ex EN network interface card; 25GbE dual-port
SFP28; PCIe3.0/4.0 x8`); текущая identity: Base GUID/MAC — реестр
`CARD_CX5_25G_GUID`/`_MAC`, PSID `MT_0000000361` (FW 16.35.1012, N/A в `q` нет
— состояние после фикса §7). Бэкап known-good: `ri` →
`/root/backup_01000.mlx` (16MiB, md5 `e00aa8e89470f64edd188144f860bd13`),
`mstflint -i … verify` → «Image is bootable». На сервере 9 функций Mellanox
→ в burn обязателен `-d 01:00.0`. SSH-путь ноды — `bond0`/`eno1` (не
карта) → reboot не рвёт доступ.

**Сборка (offline, хост):** factory `.bin` (md5 `cd95e4febf6b8bbe6768c66665aab3e7`)
→ `mlxfwutil.py guides … --guid/mac — реестр `CARD_CX5_25G_GUID`/`_MAC` -o
guides_burn.bin` → **md5 `bee171b6844a94e424bd6eb89296f181`** (побайтово
идентичен выводу Task 11 — детерминированность). Offline-гейт зелёный:
`mlxfwutil verify` → `RESULT: PASS`; `mstflint -i … verify` → «FW image
verification succeeded. Image is bootable.»; `mstflint -i … q` → Base
GUID/MAC = текущим, PSID `MT_0000000361` не тронут. scp на сервер, md5
совпал.

**Burn + reboot:**

```
mstflint -d 01:00.0 -i /root/guides_burn.bin --ignore_dev_data --nofs -y b
# → «Burning FW image without signatures - OK»
# → «Restoring signature - OK»   (обязательный выход, docs/850-howto/100-cross-flash-ops §6) — rc 0
reboot   # warm, node-level; нода вернулась ~3 мин (20:18:14 → 20:21:26 UTC)
```

**Верификация (после reboot):**

| Проверка | Результат |
|---|---|
| `mstflint -d 01:00.0 q` | Base GUID/MAC — реестр `CARD_CX5_25G_GUID`/`_MAC`, PSID `MT_0000000361` — **все = до burn**; N/A нет |
| sysfs `mlx5_7`/`mlx5_8` node_guid | реестр `CARD_CX5_25G_GUID` / `_P1_GUID` (как до burn, §1) |
| netdev `enp1s0f0np0` | MAC — реестр `CARD_CX5_25G_MAC`, **state=up** (UP/LOWER_UP, mtu 9000) — kernel MAC верный, не нули (Variant B §5 не воспроизведён); `enp1s0f1np1` down — port1 не заведён (как до burn) |
| Порт | `ethtool` → **25000Mb/s, Link detected: yes**; `vlan0071` UP (трафик) |
| Слот-стейт (пост-`ri`, md5 `5ffab2b8d4dfdc7fccc4dd83f5f2a0bd`) | MTFW @0x0 → **активен слот A**; @0x800000 zeroed (паттерн D3/D4 §8.1: второй слот после burn — zeroed, не erased); `verify` → «Image is bootable» |
| Флэш-контент device-data | DEV_INFO @0xfd0000 (0x200 B) и MFG_INFO @0xff8000 (0x140 B) **побайтово идентичны** сожжённому образу (`cmp` rc 0) — inject'нутый mDevInfo (guid/mac/INSECTION-CRC §8.4) записан ровно как собран |

Единственное расхождение пост-флэша с образом — незанятый хвост слота A
0x507E8C..0x7FFFFF (после последней ITOC-секции): zeroed (0x00) против 0xFF
в образе — штатный результат full-overwrite burn (`--nofs --ignore_dev_data`),
все секции verify OK.

**Откат: не потребовался** (карта поднялась, identity не изменилась, N/A
нет). known-good бэкап `/root/backup_01000.mlx` сохранён (откат по docs/850-howto/100-cross-flash-ops
§8 — перешить его тем же рецептом).

**Вывод:** конвейер `factory → mlxfwutil guides → mstflint burn
(--ignore_dev_data --nofs) → reboot` воспроизводит фикс §7/§8.6: MNVDA
GET-путь пересоздан (`q` показывает GUID/MAC), raw NVRAM/DTOC содержит
верный GUID/MAC (kernel MAC не нули) — без `sg` (план §8.6, шаг 5). Фикс
полностью задокументирован и воспроизведён; вопрос закрыт.

## 9. strace: cr-space интерфейс `mstflint`

`mstflint` (host, без `/dev/mstflint`) ходит в PCI config space:
- open `/sys/bus/pci/devices/0000:01:00.0/config` → fd 4
- `pwrite64(4, data, 4, offset)` — только 4 offset'а:

| Offset | Dec | Count | Назначение (гипотеза) |
|---|---|---|---|
| 196 | 0xC4 | 336 206 | cr-space cmd reg |
| 204 | 0xCC | 604 743 | cr-space data/status |
| 208 | 0xD0 | 428 556 | cr-space data |
| 212 | 0xD4 | 153 008 | cr-space data |

- `MNVDA` reg ID `0x9024` (`REG_ID_MNVDA`, `reg_access.c:59`),
  `NV_BASE_MAC_GUID_IDX = 0x02` (`fw_comps_mgr.cpp:561`).
- `0x9024` в raw `pwrite64` bytes не найден (ни BE, ни LE) → ID несётся внутри
  TLV-структуры cr-space протокола, а не как прямой dword в config space.
- `pread64` (2.4M) — поллинг FW до завершения `MNVDA`-команды.
- Полный разбор cr-space TLV-протокола — отдельная задача (source `mflash.c` /
  `mtcr_ul`).

## 10. Эксперимент «unbind mlx5 → erase/wbne ранящего слота» (2026-10-27, live)

Вопрос: влияет ли наличие bound-драйвера (mlx5_core) на политику flash FW
карты — §4/§7 зафиксировали отказ erase ранящего слота, но драйвер тогда
был bound. Карта к моменту эксперимента — в iD-бейзлайне (16.35.8008 /
MT_0000000080 + VPI, docs/050-hardware/100-inventory; **ранящий слот = B @0x800000**, slot A —
zeroed4). Протокол: control `e 0x800000` с bound-драйвером → unbind обеих
функций mlx5_core (mst-модулей на хосте нет) → no-op-проба
`wbne 0x800000 4 <текущий dword>` (AND-семантика: запись == нет
изменения) → решающий `e 0x800000` без драйвера → rebind + verify.

| Операция | Драйвер | Результат |
|---|---|---|
| `e 0x800000` (erase ранящего слота) | bound (mlx5_core) | **FAIL** — "Flash erase of address 0x800000 failed: Register access bad parameter" |
| `e 0x800000` (erase ранящего слота) | **unbound** (без mst-модуля) | **FAIL** — идентичная ошибка |
| `wbne 0x800000 4 0x4d544657` (не-erase-запись, AND, no-op) | unbound | **PASS** (контроль `rw` — значение не изменилось) |
| `rw 0x800000` (чтение) | оба | PASS |

Выводы:
- **Ядро/драйвер полностью исключены**: erase ранящего слота отклоняется FW
  карты независимо от bound-драйвера — ядро хоста ретранслятор, а не
  арбитр (§9 — запрос идёт из userspace прямо в cr-space).
- **FW защищает именно ERASE ранящего слота, а не любую запись**: не-erase-
  запись (wbne) в ранящий слот прошла без драйвера.
- Карта возвращена в исходное состояние; restore-ветка не срабатывала
  (erase не удавался ни разу).

Журнал: `docs/superpowers/journal/2026-10-27-unbind-wb-probe.md`
(раунд 1 — STOP (b): бриф был по устаревшему T15-бейзлайну; раунд 2 —
эксперимент); отчёт —
`docs/superpowers/reports/2026-10-27-mstflint-write-paths.md` §6.
Открыто: RE защиты в FW (TODO.md, 2026-10-27).
