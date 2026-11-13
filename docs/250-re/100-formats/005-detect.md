# 005. Детекция формата образа (FS2/FS3/FS4/FS5)

> Источник: статический разбор OSS mstflint (`refs/src/mstflint`, rev
> `a2b9858b`, `mlxfwops/lib/fw_ops.cpp` / `fw_ops.h`); эмпирика — образы
> `refs/fw/` (пробник `scripts/probes/toc_probe.py`), 2026-09-06.
> Аспекты форматов: FS2 → `010-fs2.md`, FS3 → `015-fs3.md` /
> `020-fs3-sections.md`, FS4 → `030-fs4.md`, FS5/PLDM → `055-fs5-pldm.md`,
> CRC → `025-crc.md`.

Термины: **ITOC** = Internal Table of Contents (основная TOC образа),
**DTOC** = Device TOC (данные устройства, только FS4), **GPH** = Global
Parameter Header (FS2), **DW** = dword (4 байта).

## 1. Цепочка детекции

`FwOperations::CheckFwFormat` (`mlxfwops/lib/fw_ops.cpp:733`), порядок:

1. **PLDM**: первые 16 байт = известный package-header identifier
   (`fw_ops.cpp:696-731`, таблица `pldm_utils/pldm_utils.h:84-93`).
2. **Кабель**: `"MTCF"` @ 0x00 (`fw_ops.cpp:672-681`).
3. **FS comps** (компонентная укладка): fingerprint 16B
   (`fw_ops.cpp:683-694`).
4. **FS4/FS5**: поиск FS4-мага по кандидатам начального смещения;
   версия @ `start + 0x10` (`fw_ops.cpp:618-645`,
   `fw_ops.h:510 FS4_BOOT_VERSION_OFFSET`).
5. **FS3/FS2**: поиск CNTX-мага; версия @ `start + 0x24`
   (`fw_ops.cpp:648-670`, `fw_ops.h:509 FS3_BOOT_VERSION_OFFSET`).
   Если версия не 3 — считается **FS2** (комментарий разработчика:
   «TODO: if the img format version is unknown we should fail…» —
   `fw_ops.cpp:665-666`).

## 2. Маги и кандидаты смещения

Маги (4 dword, `fw_ops.cpp:374-378`):

| Формат | Байты @ image start |
|---|---|
| FS4/FS5 | `4D 54 46 57  AB CD EF 00  FA DE 12 34  56 78 DE AD` ("MTFW") |
| FS2/FS3 | `4D 54 46 57  8C DF D0 00  DE AD 92 70  41 54 BE EF` ("MTFW") |

Быстрый дискриминатор — второй DW `d[4:8]`: `8C DF D0 00` = FS2/FS3,
`AB CD EF 00` = FS4/FS5.

Кандидаты начального смещения (`fw_ops.cpp:380` `_cntx_image_start_pos`):
`0, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000,
0x800000, 0x1000000, 0x2000000`. Во всех наших образах image start = 0x0.

## 3. Version word

Номера версий формата (`fw_ops.h:541-544`):

| константа | значение |
|---|---|
| `IMG_VER_FS2` | 0 |
| `IMG_VER_FS4` | 1 |
| `IMG_VER_FS5` | 2 |
| `IMG_VER_FS3` | 3 |

Поле — первый (старший) байт 32-битного «version word» бут-заголовка
(структура `image_layout_boot_version`, unpack `image_layout_layouts.c:1301`:
bits 0-7 = `image_format_version`, bits 16-23 = `major_version`,
bits 24-31 = `minor_version`; bits 8-15 структурой не используются;
нумерация битов MSB-first).

Смещение version word: **0x24** для FS2/FS3 (CNTX-маг), **0x10** для
FS4/FS5 (FS4-маг).

## Приложение: эмпирика по локальным образам (2026-09-06)

Пробник: чтение мага (16 байт @ 0) и version байта
(`python3 scripts/probes/toc_probe.py <bin>`).

| Образ | Маг | ver | Формат | Размер файла |
|---|---|---|---|---|
| CX-2 `firmware-image.bin` (HP-пакет) | CNTX | 0 @0x24 | **FS2** | 0xa47ac |
| CX-4 MCX456A ECA/FCA rel-12_28_4706 | CNTX | 3 @0x24 | **FS3** | 0xff8140 |
| CX-4Lx MCX4131A BCA/GCA rel-14_32_1912 | CNTX | 3 @0x24 | **FS3** | 0xff8140 |
| CX-4Lx MCX4121A ACA rel-14_32_1912 | CNTX | 3 @0x24 | **FS3** | 0xff8140 |
| CX-5 (545A/545B/546A/556A, Dell, HP) rel-16_xx | FS4 | 1 @0x10 | **FS4** | 0x1000000 |
| CX-5 Ex MCX512A rel-16_35_1012 | FS4 | 1 @0x10 | **FS4** | 0x1000000 |
| CX-6 MCX654105A rel-20_43_1014 | FS4 | 1 @0x10 | **FS4** | 0x2000000 |
| CX-6Dx MCX623435A E/C rel-22_50_1002 | FS4 | 1 @0x10 | **FS4** | 0x2000000 |
| CX-6Dx `.pldm` (оба) | PLDM rev1 | — | **FS_PLDM_1_0** | ~17МБ |

Выводы (образы `refs/fw/`):

- Формат определяется **чипом**, не продуктом: CX-4 и CX-4Lx — оба FS3;
  CX-5 (EN и Ex) — оба FS4.
- CX-3 и CX-3 Pro — тоже **FS2** (✓ штатным парсером mstflint: MCX354A-FCB
  rel-2_42_5000, PSID `MT_1090120019`; MCX353A-FCC rel-2_42_5000, PSID
  `MT_1100111019` — уточнение позже таблицы выше; полная карта чип→формат —
  `060-chip-map.md`).
- Файлы CX-4/CX-4Lx обрываются на 0xff8140 (до конца 16МБ-флеша пусто —
  файл заканчивается на конце последней секции, MFG_INFO+0x140).
- CX-2-образ — это **FS2** (ver=0), но с тем же CNTX-магом, что и FS3:
  разграничение FS2/FS3 — только по version байту.
