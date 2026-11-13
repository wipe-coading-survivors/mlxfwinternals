# 060. Маппинг чип → формат, device_id

> Источник: эмпирика по образам `refs/fw/` (пробник
> `scripts/probes/toc_probe.py`, 2026-09-06; сверка с
> `refs/src/Mellanox-ConnectX-5-PCIe-Gen-4-Enablement/cx5_gen4_enable.py`).
> Детекция формата и маги — `005-detect.md`.

| Чип | PCI device_id | Формат (проверен) | Образы в `refs/fw/` |
|---|---|---|---|
| CX-2 | MT26448 | FS2 (GPH) | HP `firmware-image.bin` |
| CX-3 | 0x1003 | **FS2 (GPH, ✓ штатным парсером)** | MCX354A-FCB rel-2_42_5000 (PSID `MT_1090120019`) |
| CX-3 Pro (Kestrel) | 0x1007 | **FS2 (GPH, ✓ штатным парсером)** | MCX353A-FCC rel-2_42_5000 (PSID `MT_1100111019`) |
| CX-4 | 0x1013 | FS3 (ver=3) | MCX456A E/F rel-12_28_4706 |
| CX-4Lx | 0x1015 | FS3 (ver=3) | MCX4131A B/G rel-14_32_1912, MCX4121A A |
| CX-5 | 0x1017 | FS4 (ver=1) | 545A/545B/546A/556A, Dell, HP, 8008-ACA/512F (rel-16_35_8008) |
| CX-5 Ex | 0x1019 | FS4 (ver=1) | MCX512A ADA rel-16_35_1012, **8008 546A Ex (MCX546A): CDAN (2×100G QSFP28, EN), BCAN (2×40GbE OCP)** |
| CX-6 | 0x101B | FS4 (ver=1) | MCX654105A rel-20_43_1014 |
| CX-6Dx | 0x101D | FS4 (ver=1) | MCX623435A E/C rel-22_50_1002 (+.pldm, +FB `ri.bin`) |

## 1. Наблюдения

- Формат определяется **чипом**, не продуктом: CX-4 и CX-4Lx — оба FS3;
  CX-5 (EN и Ex) — оба FS4 (`005-detect.md`, приложение).
- CX-3/CX-3 Pro = FS2 — уточнение позже исходной эмпирической таблицы
  2026-09-06 (✓ штатным парсером mstflint; см. `005-detect.md`).

## 2. Откуда в образе device_id / subsystem_id

- **FS2 (CX-2/CX-3/CX-3 Pro):** device_id и PSID — из `IMG_INFO`/`dc.ini`
  (`adapter_dev_id`, `PSID`), а **не** из `FW_BOOT_CFG` — структура и
  эмпирика в `010-fs2.md` (там же GPH-цепочка и CRC целого образа).
- **FS3/FS4:** device_id читается из образа: byte
  `FW_BOOT_CFG + 0x002D | 0x1000` (`cx5_gen4_enable.py:335`);
  subsystem_id — `FW_BOOT_CFG + 0x003D` (`:336`).

## Дополнение (из 00 §3.3)

Микро-данные `.ini`-дампов (2026-09-06), отсутствующие в таблице
`docs/850-howto/100-cross-flash-ops.md` §11 (остальные ячейки таблицы 00
§3.3 покрыты: device_id/формат — таблица этого файла; PSID/subsystem
0x0014/0x0012/0x0006/0x0124 и примечания — 850-howto §11):

| Карта | Поле | Значение |
|---|---|---|
| CX-6Dx MCX623435AC (SB SKU) | subsystem | **0x0070** |
| CX-4Lx MCX4121A (2×25G) | `Speed10/25Gb` | **1** |
| CX-4Lx MCX4121A (2×25G) | PCIe max gen (ini-поле) | **gen3 = `0x7`** |
| CX-5 Ex MCX512A (2×25G) | `Speed10/25Gb` | **1** |
| CX-5 Ex MCX512A (2×25G) | PCIe gen (ini-поле) | **gen4 = `0xf`** |

Hex — данные ini-полей/образов (не идентификаторы карт).
