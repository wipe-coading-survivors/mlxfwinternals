# 010. Встроенный ini: размещение 0x30 и маппинг в бинарный образ

> Источник: mstflint OSS `refs/src/mstflint` (`flint/subcommands.cpp`,
> `mlxfwops/lib/fs3_ops.cpp`); эмпирика образов `refs/fw/` (побайтовая
> сверка ini, 2026-09); бинарный маппинг — отчёт
> `docs/superpowers/reports/2026-10-15-mlxburn-ini-binary-mapping.md`;
> quirk inject — цикл repack-burn-safety (журнал
> `docs/superpowers/journal/2026-10-31-repack-burn-safety-task-05.md`).
> Это спецификация инструмента (mlxfwutil): только факты.
>
> Связи: патч-матрица секций/CRC — `020-patch-matrix.md`; ITOC-записи и
> типы секций — `docs/250-re/100-formats/020-fs3-sections.md`; CRC-16 —
> `…/025-crc.md`; FS2-структуры — `…/010-fs2.md`; чип→формат —
> `…/060-chip-map.md`.

## 1. Цепочка и размещение (секция 0x30 DBG_FW_INI)

Цепочка (доказана эмпирически):

```
.prs  →(iniprep)→  .ini (текст)  →(zlib)→  секция 0x30 DBG_FW_INI в образе
```

- Секция **0x30 (FS3_DBG_FW_INI)** содержит ini, сжатый **zlib**
  (RFC1950, маг `78 DA`), ASCII.
- `mstflint dc` (dump config) = `FwGetSection(FW_INI)` → `TOCPUn` →
  `zlib uncompress()` с retry-циклом (×40, max 32 итерации)
  (`flint/subcommands.cpp:1350-1388 unzipDataFile`).
- `FwGetSection` в OSS поддерживает **только** `FS3_DBG_FW_INI`
  (`fs3_ops.cpp:1702-1703`).
- При верификации данные 0x30 кэшируются в `_fwConfSect`
  (`fs3_ops.cpp:726-729`).
- `param0` записи 0x30 — по старой спецификации метод сжатия
  (0=none, 1=zlib, 2=LZMA), но в наших образах param0=0x0, а данные
  zlib — т.е. инструмент ориентируется на zlib-маг, не на param0.
- **Доказательство**: ini, извлечённый из образа MCX4121A ACA
  (0x30 @ 0x4CE400, 0x7CC байт = 0x1F3 DW по записи ITOC, zlib),
  **побайтово идентичен** дампу устройства `mstflint -d mlx5_N dc`
  (`cx-4/MCX4121A-ACA_Ax-dc.ini`).
- Заголовок ini указывает на источник:
  «Generated automatically by iniprep tool on … from
  ./cx4-lx_MCX4121A_2p_x8_25g.prs» — имя `.prs` кодирует конфигурацию
  (1p/2p, 25g/40_56g/50g).

## 2. PSID: двойное размещение (FS3) и зависимые поля

PSID в FS3 хранится в двух местах (для кросс-флеша):

- IMAGE_INFO (0x10): `image_info.psid` (`fs3_ops.cpp:350`);
- MFG_INFO (0xE0): `mfg_info.psid` (`fs3_ops.cpp:275,283`).

При burn с `--allow_psid_change` mstflint сам переписывает PSID/name/
description в IMAGE_INFO (`fs3_ops.cpp:1541-1544`). Пересчёт CRC обеих
секций при смене PSID — `020-patch-matrix.md` (строки 0x10/0xE0).

## 3. Quirk inject: 0x0D → 0x0A (universal newlines)

`inject` читает ini-файл через `Path.read_text` (universal-newlines):
одиночный байт **0x0D в векторе транслируется в 0x0A** — round-trip
(extract vs исходный файл) разъедется ровно на этих байтах. Ini-векторы
для inject не должны содержать 0x0D вне `\r\n`-пар (обход task-05:
замена 0x0D→0x0C в случайном хвосте вектора; журнал
`docs/superpowers/journal/2026-10-31-repack-burn-safety-task-05.md`,
«Находка»).

## 4. Где живёт маппинг key/val → бинарные поля

.ini — текстовая форма PRS-описания (цепочка §1). **Маппинг key/val →
бинарные поля образа НЕ в скриптах сборки** (`mlxburn`/`mlxburn_old`
только передают `-conf <ini>` в `mic`; сами читают из .ini лишь PSID для
авто-подбора и `psc_sku`/`emu_mode`/`debug_fw`/`encrypted_fw` для
security-веток). Он живёт **в самом .mlx-пакете**, секция
`TEMTParameters` (старый PERL-формат) / `FWParameters` (новый XML) —
perl-код с:

- bitfield-хэшами: `field => { 'word' => N, 'shft' => N, 'mask' => 0x… }`
  (key → слово/сдвиг/маска внутри бинарной области; маска уже сдвинута);
- `%offsetof` — пути CR-space → офсеты (PCI capability-списки, MSIX…);
- `<par name=… def= min= max= type="CR-SPACE" CRnames="<cr-path>">` —
  key .ini → путь регистра в scratchpad + дефолт (3625 пар у CX3Pro);
- `peval()` — вычисляемые поля (PLL-parity, PCI cap linked list, BAR…).

`mic` на билде: ini-переопределения + дефолты `<par>` → `peval()` →
запись слов в бинарные области. Т.е. **раскладка полей едет с пакетом**,
а не зашита в mic. Обратного live-маппинга нет: `dc`/`dh` — лишь
zlib-распаковка сохранённого ini-текста (§1), бинарные поля не
декодируются.

## 5. Где лежат значения (таблица)

Эталон — FS2/CX3Pro; для FS3+ области — именованные ITOC-секции
(`020-patch-matrix.md`):

| Секция .ini | Бинарное представление |
|---|---|
| `[PLL]` | FS2-заголовок: PLL0-3 @ 0x10, **BE**, бит 31 = even parity |
| `[ADAPTER]` PSID / adapter_dev_id / VSD / nv_config_sectors | IMG_INFO TLV (FS2) / IMG_INFO 0x10 (FS3+) |
| `[ADAPTER]` gpio_* и пр. | CNF-секция (scratchpad/CR-space, **BE**-слова, офсеты по CR-space-раскладке) |
| `[HCA]` hca_header_* / sriov / … | PCI config space в ROM-секции (capability list по `%offsetof`) |
| `[PS_INFO]` PRS_name | IMG_INFO.TLV `PSInfo` (имя .prs) |
| весь текст | FW_CONF (FS2) / 0x30 (FS3+): zlib-тень, runtime-незначима |

Конкретика, расчёты и сверки (PLL-слова байт-в-байт, IMG_INFO-TLV,
gpio-офсеты, ROM-секция) —
`docs/superpowers/reports/2026-10-15-mlxburn-ini-binary-mapping.md`.

## 6. Expansion ROM (FlexBoot)

В ROM-секции FS2 и в exp-rom CX4+ — FlexBoot = **legacy x86 PXE** option
ROM (на базе iPXE; в CX3Pro-образе UEFI/ARM нет). CX4+ несут и
UEFI-драйвер — `q` → Rom_Info: CX-4 `type=UEFI cpu=AMD64,AARCH64` +
`type=PXE cpu=AMD64`; CX-5 `type=UEFI cpu=AMD64` + `type=PXE
cpu=AMD64` (refs: `cx-4/…/query-*.txt`, `cx-5-6/…/query-*.txt`).
