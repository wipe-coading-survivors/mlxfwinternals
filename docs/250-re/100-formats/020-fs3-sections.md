# 020. FS3: ITOC-запись и типы секций

> Источник: mstflint `tools_layouts/cibfw_layouts.{h,c}`, `flint_base.h`,
> `mlxfwops/lib/fs3_ops.cpp`; эмпирика — MCX4131A BCA и 6 образов
> CX-4/CX-4Lx `refs/fw/` (журналы 2026-09-15, 2026-09-19-toc-meta-probe;
> пробник `scripts/probes/toc_probe.py`). Заголовки — `015-fs3.md`,
> CRC — `025-crc.md`.

## 1. ITOC-запись (32 байта, `cibfw_itoc_entry`)

Структура и unpack: `tools_layouts/cibfw_layouts.h:431`,
`cibfw_layouts.c` (битами, MSB-first). Карта байтов:

| Смещение | Поле | Биты | Примечание |
|---|---|---|---|
| 0x00 | type | 0-7 | тип секции (§2) |
| 0x01-0x03 | size | 8-29 | **22 бита, в DW** (×4 → байты) |
| 0x04 | zipped / cache_line_crc / param0[29:24] | 32/33 | bit7 = zipped, bit6 = per-line CRC (MAIN_CODE) |
| 0x05-0x07 | param0[23:0] | 34-63 | адрес загрузки (код); для 0x30 — метод сжатия (номинально) |
| 0x08-0x0B | param1 | 64-95 | BE u32, jump-адрес |
| 0x0C-0x13 | reserved | — | 8 байт |
| 0x14 | relative_addr / flash_addr[6:0] | 160 / 161-167 | bit7 = rel; адрес **в DW** |
| 0x15-0x17 | flash_addr[28:7] | 168-189 | суммарно 29 бит, ×4 → байты |
| 0x18 | reserved | — | |
| 0x19 | no_crc / device_data | 207/206 | bit7 = CRC секции не считается; bit6 = данные устройства |
| 0x1A-0x1B | section_crc | 208-223 | CRC-16 данных секции (0x0000 при no_crc) |
| 0x1C-0x1D | reserved | — | |
| 0x1E-0x1F | entry CRC | 240-255 | CRC-16 по первым 28 байтам записи |

Биты **30-31** (два младших бита байта 0x03) — **2-битный reserved-gap**:
не часть size (8-29) и не часть param0 (34-63); во всех наших TOC = 0
(журнал `2026-09-19-toc-meta-probe`, 112 TOC). Аналогично —
все прочие «reserved»-регионы записи и заголовка (биты 96-159, 190-205,
224-239; байты 0x0C-0x13, 0x18-нижние, 0x1C-0x1D) — **постоянно 0**,
скрытых данных нет.

**param0/param1**: mstflint их **не читает нигде**
(вне `tools_layouts/` 0 обращений — vestigial); эмпирика — ненулевые
**только у кодовых секций** 0x01-0x07 и 0x0d/0x0e (CCIR): param0 = RAM
load address, param1 = jump address (param0 + offset); у конфигов/ROM/
0x30/подписей/dev-данных = 0; совпадений с flash_addr (своей или чужой
секции) — 0 (значения 0x800000…0x30004000 — за пределами флэши, это RAM).

Конец списка — запись с `type = 0xFF` (FS3_END). Официальные описания
типов секций — в комментарии к enum (`flint_base.h:323-339`,
«Flash Programming App Note»).

## 2. Типы секций (enum `fs3_section_t`)

`flint_base.h:384-440` (общий для FS3 и FS4; имена —
`fs3_ops.cpp:83-130+`). Группы:

| Диапазон | Назначение | Примеры |
|---|---|---|
| 0x01-0x07 | код загрузки | BOOT_CODE, PCI_CODE, MAIN_CODE, PCIE_LINK_CODE, IRON_PREP_CODE, POST_IRON_BOOT, UPGRADE_CODE |
| 0x08-0x12 | конфиг | HW_BOOT_CFG, HW_MAIN_CFG, IMAGE_INFO, FW_BOOT_CFG, FW_MAIN_CFG |
| 0x0A-0x0D | PHY-код | PHY_UC_CODE, PHY_UC_CONSTS, PCIE_PHY_UC_CODE, CCIR_* |
| 0x18 | ROM_CODE | PXE/BoIB option ROM |
| 0x20-0x3A | прочее | RESET_INFO, PRE/POST_LINK_*, FS4_PROG_FW_META/BIN |
| **0x30** | **DBG_FW_INI** | **zlib-ini (ini-маппинг — `docs/550-poc/100-mlxfwutil/010-ini-mapping.md`)** |
| 0x32 | DBG_FW_PARAMS | |
| 0x40 | SLOT_DEPENDENT_INI | |
| 0xA0-0xA5 | подпись (v1) | SIG_256, PUB_KEYS_2048, FORBIDDEN_VERSIONS, SIG_512, PUB_KEYS_4096, HMAC_DIGEST |
| 0xA6-0xAD | подпись (v2, FS4) | FS4_RSA_PUB_KEY, FS4_RSA4096_SIGS, ENC_KEY_TRANS, PXIR_INI(1), NVDA_ROT_CERTS |
| 0xB0-0xD5 | FS4-доп. | EXCLKSYNC, MAIN_PAGES_HASHES(LOCKED), STRN_*, CPO_CAL, MAIN_DATA, DEBUG_DUMP(2), FS5_SECURITY_LOG |
| 0xE0-0xFB | данные устройства | MFG_INFO, DEV_INFO, NV_DATA1/2/0, VPD_R0, FW_NV_LOG, FS4_DEV_INFO1/2, CRDUMP_MASK, FW_INTERNAL_USAGE, PROG_HW_FW1/2, DIGITAL_CERT_*, LC_INI_*, CERT_CHAINS/ROOT_CERTS, TOOLS_AREA, HASHES_TABLE, HW_PTR |
| 0xFD-0xFF | служебные | ITOC, DTOC, END |

Карта частей (человеческие имена; фаза EDA→IB, 2026-09). ITOC (прошивка):

- **Код ASIC** (покрывается MCC-digest'ом; исполняется ASIC; один
  бинарник обслуживает и ETH, и IB — VPI): 0x01 BOOT_CODE, 0x02 PCI_CODE,
  0x03 MAIN_CODE, 0x04 PCIE_LINK_CODE, 0x05 IRON_PREP_CODE, 0x06
  POST_IRON_BOOT, 0x07 UPGRADE_CODE, 0x0a PHY_UC_CODE, 0x0b PHY_UC_CONSTS,
  0x0c PCIE_PHY_UC_CODE, 0x0d CCIR_*, 0x20 RESET_INFO.
- **Конфиг** (сменяем): 0x10 IMAGE_INFO (PSID/имя/description/device_id
  BE +0x1c/subsystem), 0x11 FW_BOOT_CFG (per-port VPI default_link_type и
  пр.), 0x12 FW_MAIN_CFG, 0x08 HW_BOOT_CFG (max PCIe speed и пр.), 0x09
  HW_MAIN_CFG (порт-типы/спиды/Gen, speed-таблицы), 0x30 DBG_FW_INI
  (zlib-ini = PRS, `dc`).
- **ROM** (0x18 ROM_CODE): PXE/BoIB (+UEFI) option ROM — сетевая загрузка
  до главной прошивки; сменяем; наименее «дорогая» часть.
- **Подпись** (0xA0–0xA5): SIG_256, PUB_KEYS_2048, FORBIDDEN_VERSIONS,
  SIG_512, PUB_KEYS_4096, HMAC_DIGEST — **только от базы** (не
  переподписываем; non-SB).
- **Сервисное** (не исследовано): 0x32 DBG_FW_PARAMS, 0xe9 CRDUMP_MASK,
  0xeb PROG_HW_FW1 (320КБ).

DTOC-части (device-data): в FS3 живут **внутри ITOC** с флагом dev=1
(эмпирика ниже); в FS4 вынесены в отдельный DTOC (`030-fs4.md`):
0xE0 MFG_INFO, 0xE1 DEV_INFO (mDevInfo: GUID/MAC — ×2 копии), NV_DATA
(0xE6 NV_DATA0: NV-журнал применённых overrides), 0xE3 VPD_R0, 0xE5
FW_NV_LOG, HASHES_TABLE (не активна), TOOLS_AREA.

**mDevInfo-single-valid в FS3: НЕТ** (журнал 2026-09-15, R1). `fs3_ops.cpp`
не проверяет «ровно один валидный mDevInfo» (правило — только FS4,
`fs4_ops.cpp:881-891`, `CheckDevInfoSignature` `fs4_ops.cpp:198-209`); FS3
`GetDevInfo` (`fs3_ops.cpp:432-462`) парсит 0xE1 только по major_version.
ДАННЫЕ 0xE1 содержат сигнатуру "mDevInfo#B…" @byte0, но mstflint её не
валидирует. `verify` FS3: достаточно CRC секции 0xE1 (no_crc=0 →
whole-section).

## Приложение A: эмпирика MCX4131A BCA (FS3, пробник toc_probe.py)

Маг CNTX @ 0x0; version word @ 0x24 = `03 17 01 01`; ITOC @ **0x2000**,
header CRC **OK**, version = 1; **31 запись, entry-CRC всех 31 — OK**.
Ключевые секции:

| type | Секция | Размер | Адрес |
|---|---|---|---|
| 0x05 | IRON_PREP_CODE | 0x10738 | 0x4000 |
| 0x02/0x03/0x04 | PCI_CODE, MAIN_CODE (clcrc=1 → per-line CRC), PCIE_LINK_CODE | — | — |
| 0x08/0x09 | HW_BOOT_CFG, HW_MAIN_CFG | — | — |
| 0x10/0x11 | IMAGE_INFO, FW_BOOT_CFG | — | — |
| 0x12 | FW_MAIN_CFG | 0xC00 | 0x16000 |
| 0x18 | ROM_CODE (PXE/BoIB ROM) | ~726KB | — |
| 0x30 | DBG_FW_INI (zlib-ini) | 0x6EC | 0x4CE400 |
| 0xA0-0xA4 | SIG_256, PUB_KEYS_2048, FORBIDDEN_VERSIONS, SIG_512, PUB_KEYS_4096 | — | — |
| 0xE1 (dev=1) | DEV_INFO | — | 0xFEE000 |
| 0xE0 (dev=1) | MFG_INFO | — | 0xFF8000 |
| 0xE3 (dev=1) | VPD_R0 | — | 0xFF8140 |
| 0xE2/E6 (dev=1) | NV_DATA; 0xE5 FW_NV_LOG | — | — |

## Приложение B: эмпирика 6 CX-4/CX-4Lx образов (журнал 2026-09-15; R2/R3/R5)

Все 6 `.bin` = 0xFF8140 байт (слот A, base=0); ITOC @0x2000, 31 запись + END.

**R3 — биты no_crc/dev/rel (единый паттерн по всем 6):**

| Бит | Значение |
|---|---|
| rel=1 | записи 0–24 (FW: код/конфиг/ROM/подписи 0xA0–0xA4, 0xE9, 0xEB); rel=0 — записи 25–30 (device-data, **абсолютные** адреса) |
| no_crc=1 | **только** 0xE6 NV_DATA0, 0xE4 NV_DATA2, 0xE5 FW_NV_LOG (не 0xA0–0xA4, не 0xE1, не 0xE0, не 0xE3) |
| dev=1 | **только** 0xE0, 0xE1, 0xE3, 0xE4, 0xE5, 0xE6 (подмножество 0xE0–0xEF); 0xE9/0xEB — dev=0, rel=1 |

Все section_crc OK (no_crc — skip), все entry_crc OK; VPD_R0 0xE3: size 0,
addr 0xFF8140 (=EOF). → `verify`: пропуск section-CRC только для
{0xE4,0xE5,0xE6}.

**R2 — MFG_INFO (0xE0) layout:** addr 0xFF8000, size 0x140, no_crc=0
(whole-section CRC в ITOC-entry; INSECTION-CRC в FS3 нет).

| Поле | Смещение | Значение (во всех 6) |
|---|---|---|
| PSID | байт 0x00 | "MT_2420110034" |
| major_version | 0x1C | 1 |
| minor_version | 0x1D | 0 |
| guids_override_en | 0x1F bit0 | 1 |
| guids | 0x20 (0x40 байт) | zeroed |

mstflint читает PSID с того же offset: `adb2c_calc_array_field_address(24,8,i,2560,1)`
→ psid[i]@байт i (для i=0 — 0, а не 24 — big-endian-array логика
`adb_to_c_utils.c`). IMAGE_INFO 0x10 PSID @0x24 (совпадает с `II_PSID`).
→ `psid` FS3 (двойная запись): 0xE0 @0x00 + 0x10 @0x24, у обеих
section_crc + entry_crc.
