# 070. VPD и secure-state: инструментальная поверхность

> Источник: цикл mstflint-vpd (2026-11-18, tasks 01–08; канон — задачи
>   1–7, финализация — task-08); аудит
>   `refs/src/mstflint@a2b9858b59196c0d9a2224ac8ebcd86292f9abef` (пин —
>   `150-external/000-pinned-revs.md`; все file:line ниже — по этому пину,
>   если не указано иное). Номер дока согласован с владельцем 2026-11-17.
>   Статус: **final** (цикл закрыт; дополнено исполнением спеки анлока —
>   §8, 2026-11-23). Состав: §1 «Инструментальная
>   поверхность» (Q1: реестр I1–I9, транспорт cfg-space, структурные
>   факты); §2 «Пути доступа × поколения» (Q2; матрица по коду + гипотезы
>   H-V1–H-V4 с live-дискриминаторами — сводка/передача в §6); §3 «Гейты»
>   (Q3; матрица G1–G22, классификация отказов по 050 §2, live vs image);
>   §4 «MTUSB/out-of-band I2C-бэкенд» (Q4, аудит-only; источник — журнал
>   task-04); §1.1 I2 — probe-verified image-семантика set_vpd (Q5б);
>   §5 «Инструменты цикла» (Q5а–Q5в); §6 «Передача» (handoff H-Vn спеке 2
>   + открытые пункты); §7 «Карта поколений VPD-механики и вердикты»
>   (арка C roadmap 200, 2026-11-21: data-locus/writers/readers по
>   поколениям, вердикты H-V1–H-V4, C2/065-вердикты); §8 «Исполнение
>   лестницы анлока» (цикл securefw-arc-c-unlock, 2026-11-22..23: физика
>   live set_vpd, delivery map, serving-гейт контент-класса, ресериализация,
>   content-semantic boot-гейт, слой-вердикт + эрратумы к §7). Журналы:
>   `superpowers/journal/2026-11-18-mstflint-vpd-task-01..08.md`;
>   арка C — `superpowers/journal/2026-11-21-securefw-arc-c-task-01..07.md`;
>   анлок — `superpowers/journal/2026-11-22-securefw-arc-c-unlock-task-01..10.md`.
>   Спека анлока — `superpowers/specs/2026-11-21-securefw-arc-c-unlock-design.md`.
  Связи: арка C — `010-roadmap/200-securefw-bypass.md`; спека цикла —
  `superpowers/specs/2026-11-17-mstflint-vpd-design.md`; спека цикла 2 —
  `superpowers/specs/2026-11-17-securefw-arc-c-design.md`; классификация
  secure-fw отказов — `050-spi-read-policy.md` §2; CRC-обвязка секций и
  прецедент VPD_R0 — `025-secure-boot.md`, `020-cli.md`; метод (write-пути
  flint) — `superpowers/reports/2026-10-27-mstflint-write-paths.md`,
  журнал `superpowers/journal/2026-09-28-flint-oem-hw-set-writeprotect-re.md`;
  mlxburn/mlxvpd — `superpowers/reports/2026-10-15-mlxburn-ini-binary-mapping.md`.

## 1. Инструментальная поверхность (Q1)

### 1.1 Реестр (стабильные ID)

ID потребляются задачами 2–4 и 6 цикла; переименование ID запрещено, изменения
реестра — только через дополнение (I<n+1>) или правку с пометкой в журнале.

| ID | Инструмент / поверхность | Операция | Вход / выход | Live vs image | Поколенческая матрица-кандидат (по коду) |
|----|--------------------------|----------|--------------|---------------|-------------------------------------------|
| I1 | `mstvpd` (CLI) — бинарь из `small_utils/vpd.c` (`small_utils/Makefile.am:42,58`) + парсер libmvpd (`mvpd/mvpd.c`; API `mvpd/mvpd.h:92-109`); man `man/mstvpd.md` | **read** | live-девайс (`mopen`, `small_utils/vpd.c:330`) или stdin `'-'` (:318-320); вывод — `KEY: value` построчно (print_field :57-70) или сырой дамп `-m` (:352-354); фильтр keyword (:362-375); `-n` без чексуммы (:356), `-r` только RO (:286-288), скрытый `-s` strict (:391-393) | live (или offline-парсинг stdin) | без поколенческих switch в туле; гейт только `dm_dev_is_hca` (`mvpd/mvpd.c:137,569`); транспорт — cfg-space VPD capability (см. §1.2, §2.2). Матрица поколений и гипотезы — §2.3/§2.5 (наблюдение roadmap 200: CX-3/4/4Lx/7 читаются, CX-5/6 нет) |
| I2 | `flint set_vpd` — `SetVpdSubCommand` (`flint/subcommands.cpp:6580-6614`); виртуал `FwSetVPD` (`mlxfwops/lib/fw_ops.h:227`) | **write** | `<vpd file>` — bin-файл VPD-блока (4-байтно выровнен); запись секции FS3_VPD_R0 (0xE3, `mlxfwops/lib/flint_base.h:405`) через `UpdateSection` (`fs3_ops.cpp:1930`); на образе — верификация после модификации (`fs3_ops.cpp:1935`). **Image-семантика (Q5б, probe-verified task-06, FS3, non-EXTERNAL 4.37.0-1.4):** вход **не парсится** (mvpd-API в mlxfwops отсутствует; единственный форматный гейт FS3-ветки — 4-байтная выровненность размера файла, `fs3_ops.cpp:2571-2574` — есть и в FS3, не только в G12-FS4 `fs4_ops.cpp:3274-3277`; блоб без VPD-структуры принимается); precondition на образ — наличие ITOC-записи 0xE3 (отсутствует → «ITOC entry type … not found», `fs3_ops.cpp:2330-2345`); запись данных **in place** по addr записи (addr не меняется), при size=0 (дистрибутив) — данные **дописываются в EOF**, файл растёт; в ITOC-записи меняются ровно size (DW из файла) + section_crc (=CRC новых данных) + itoc_entry_crc (=CRC записи [0:28]); при уменьшении размера хвост старых данных остаётся в файле за границей секции (не затирается); остальной ITOC и 0xA0 не меняются; `verify` после — PASS/bootable (встроенная + явная) | **live и image** (`_v = Wtv_Dev_Or_Img`, `subcommands.cpp:6595`; диспетч :6607-6608); live требует `-ocr` (`FAIL_NO_OCR`, `fs3_ops.h:72-79`, вызов `fs3_ops.cpp:1928`) | FS2 — отказ (`fs2_ops.cpp:2295-2301`); FS3 — да, рост до конца флеша (`Fs3UpdateVpdSection`, `fs3_ops.cpp:2562-2587`, граничное :2576-2582 — только flash, на образе лимита нет); FS4 — да, override `UpdateSection` (`fs4_ops.cpp:3709`, VPD-ветка :3851-3859, лимит 0x1000=4096 Б, `Fs4UpdateVpdSection` :3265-3291); FS5 — наследование (fs5_ops.h: Fs5Operations : Fs4Operations); comps/FSCTRL/PLDM — заглушки (`fs_comps_ops.cpp:140-143`, `fsctrl_ops.cpp:1072-1077`, `fs_pldm.cpp:417-420`). Гейт регистрации: `#ifndef EXTERNAL` (`flint/cmd_line_parser.cpp:96-101`, диспетч `flint/flint.cpp:158-160`); `-DEXTERNAL` безусловно в сток-билде (`flint/Makefile.am:57`) → требует non-EXTERNAL билда |
| I3 | `small_utils/vpd.c` — фронт-энд mstvpd | read | ≡ I1 | ≡ I1 | **Находка аудита:** не отдельный бинарь; `mstvpd_SOURCES = vpd.c` (`small_utils/Makefile.am:58`), линковка с libmvpd (:59). ID сохранён для стабильности, физически merged в I1 |
| I4 | mlxburn-обвязка (MFT, вне refs): режим `vpd` → `MLXVPD_PROGRAM=mlxvpd`; `mic -vpd_r <f>` при генерации образа | read (mlxvpd) / **inject-at-build** (mic) | vpd-режим обёртки уходит в закрытый бинарь mlxvpd; `-vpd_r <f>` — VPD_R-блок в образ на этапе сборки (`mlxburn_constants.py`: `MLXVPD_PROGRAM=mlxvpd`, отчёт 2026-10-15:16-23, 34-35) | live (mlxvpd) / image-build (mic) | закрытый MFT-тулинг (в refs отсутствует); OSS mstvpd подгоняет вывод под mlxvpd (`small_utils/vpd.c:59-65` «to match mlxvpd output»); поколенческая матрица — вне OSS-кода, не проверяемо по refs |
| I5 | ядерный модуль MFT `kernel/mst_vpd.c` — VPD-capability dword-API | **read + write** (API), read-only фактически (см.) | `pci_read4_vpd` (`kernel/mst_vpd.c:37-99`, EXPORT_SYMBOL :99), `pci_write4_vpd` (:101-163, EXPORT_SYMBOL :163); ioctls PCICONF_VPD_READ4/WRITE4 (`kernel/mst.h:186-196`; диспетч `kernel/mst_main.c:1984-2013,2025-2047`); cap-адрес — `pci_find_capability(PCI_CAP_ID_VPD)` (`kernel/mst_main.c:2239`) | live (только transport-слой) | любой PCI-девайс с VPD capability (без поколенческих условий в модуле); **write-ioctl не вызывается ни одним OSS-тулом** (потребителей в дереве нет) |
| I6 | `mlxfwupdate` — внутренний потребитель VPD | read | PN/SN из VPD_RO через libmvpd → `_uniqueId = pn + "_" + sn` (`mlxfwupdate/mlnx_dev.cpp:80-110`); линковка `mlxfwupdate/Makefile.am:93` | live | HCA-only (наследует гейт `dm_dev_is_hca` libmvpd) |
| I7 | `pci_library` `GetV3FieldFromVPD` + потребитель nvfwreset | read (V3 only) | `lspci -s <dbdf> -vvv` popen, grep строки `[V3]` (`pci_library/PCILibrary.cpp:103-142`); вызовы: nvfwreset HotResetManager (`nvfwreset/HotResetManager.cpp:468`), FindDirectNicDevice (`PCILibrary.cpp:167`) | live | без поколенческих условий (любой PCIe-девайс с [V3] в lspci); линковка libpci_library: nvfwreset/mlxlink/mft_sdk (`nvfwreset/Makefile.am:81` и др.) |
| I8 | `mstfwreset` (python): `get_V3_field_from_vpd` | read (V3 only) | `lspci -s <dbdf> -vvv` через cmdExec, парсинг `[V3]` (`small_utils/mlxfwresetlib/drivers_safety_check.py:586-600`); детект скрытых socket-direct-пар (:277-315, :612-625) | live | без поколенческих условий; V3-поле как маркер пары |
| I9 | рег-поверхность MQIS info_type 0x0 (FW-mediated VPD read) | read (регистр) | layout: «0x0: VPD — Read the PCI Vital Product Data capability content» (`tools_layouts/reg_access_hca_layouts.h:3251` + `.c`, adb-таблицы PRM); API `reg_access_mqis` (`reg_access/reg_access.c`) | live (reg-access) | **поверхность без OSS-потребителя**: in-tree вызовы MQIS используют только info_type 1/2 (efuse — MODEL_NAME `efuse/efuse.cpp:56,94`; mlxconfig — MODEL_NAME/DESCRIPTION `mlxconfig/mlxcfg_utils.cpp:589,593`). Кандидат для Q2/H-Vn: FW-mediated путь существует в layouts, тулингом не используется |

### 1.2 Транспорт чтения cfg-space (общий для I1/I6)

Цепочка libmvpd → mtcr: `my_vpd_read` (`mvpd/mvpd.c:84-119`, dword-цикл) →
`mvpd_read4` (`mtcr_ul/mtcr_ul.c:330-332`, декларация
`include/mtcr_ul/mtcr.h:189`) → `mvpd_read4_ul` (`mtcr_ul/mtcr_ul_com.c:5189-5209`,
dword-выравнивание) → `mvpd_read4_ul_int` (:5139-5187):

- через mst-драйвер: ioctl PCICONF_VPD_READ4 → I5 (`mst_driver_vpd_read4`,
  `mtcr_ul/mtcr_ul_com.c:427-446`);
- без драйвера: sysfs `/sys/bus/pci/devices/<BDF>/vpd` (fseek+fread,
  `mtcr_ul/mtcr_ul_com.c:5163-5185`).

FreeBSD-вариант — `mtcr_freebsd/mtcr_ul.c` (mvpd_read4); поле
`vpd_cap_addr` — `include/mtcr_ul/mtcr_mf.h:147`. Детальная механика
cap-поиска/ограничений — §2.2; развязка путей по поколениям — §2.3.

### 1.3 Структурные факты (образы)

- Секция VPD_R0 (0xE3) — device_data: ITOC/DTOC-бит «belongs to the device
  rather than to the FW image… Example for device_data section: VPD_R,
  GUIDs» (`tools_layouts/cibfw_layouts.h:489-491`,
  `tools_layouts/image_info_layouts.h:344-345`) — регулярное FW-update её не
  обновляет.
- Выбор ops-класса: live — от HW dev-id (`fw_ops.cpp:739-742` →
  `GetFwFormatFromHwDevID` `:2601-2628`: CX3/CX3Pro→FS2; CIB/SIB/CX4/CX4Lx/
  Spectrum/SIB2→FS3; CX5/CX6(DX,LX)/CX7/BF1-3/Quantum(2)/Spectrum2-5→FS4;
  QTM3/CX8/BF4/Arcus/CX9/NVLink6→FS5; Spectrum6→FS6 без кейса в фабрике
  `:1171-1174`); образ — по fingerprint (`IsFSCompsImage` `:683-694` и др.,
  `:746-759`).

### 1.4 Вне реестра (исключено аудитом — обоснования в журнале task-01)

Сборочно-документационные упоминания (top `Makefile.am:31,35`,
`configure.ac:1069`, `README:37-38,101-102,172`, `mstflint.spec.in:75`),
константа CAP_VPD без использования (`small_utils/mlxpci_lib.py:56`),
base64-совпадения в `mlxfwupdate/certificate/ca-bundle.crt`, layout-комментарии
device_data (§1.3).

## 2. Пути доступа × поколения (Q2, по коду)

### 2.1 Трассировки CLI → fw_ops/mtcr → транспорт (live и image — отдельными строками)

| ID / ветка | Цепочка (file:line) | Транспорт-класс |
|---|---|---|
| I1/I6 read, **live** | `mopen` (`small_utils/vpd.c:330`) → `mvpd_get_vpd_size` (`mvpd/mvpd.c:549-598`: гейт is_hca :569; tag-walk до END, неизвестный тег → `MVPD_FORMAT_ERR` :588-592; лимит 1<<15 :58) и `mvpd_get_raw_vpd` (:121-139) → `my_vpd_read` (:84-100, dword-цикл; ошибка → `MVPD_ACCESS_ERR` :96-97) → `mvpd_read4` (`mtcr_ul/mtcr_ul.c:330-332`) → `mvpd_read4_ul` (`mtcr_ul/mtcr_ul_com.c:5189-5209`) → `mvpd_read4_ul_int` (:5139-5187) → **(а)** mst-драйвер: `via_driver` :5148 → ioctl PCICONF_VPD_READ4 (`mst_driver_vpd_read4` :427-451; ядро `kernel/mst_main.c:1980`) / **(б)** без драйвера: sysfs `/sys/bus/pci/devices/<dbdf>/vpd` :5163-5185. Parse: `mvpd_parse_adv(..., strict, !n)` (`vpd.c:356`) — RV-чексумма по умолчанию (`-n` отключает) | **cfg-space VPD capability** (обслуживает ядро: mst-модуль или generic PCI core — механика §2.2) |
| I1 read, offline | stdin `'-'` (`vpd.c:318-326`) — только парсер, без транспорта | — |
| I2 write, **live, дефолт (MCC)** | `SetVpdSubCommand` (`flint/subcommands.cpp:6580-6614`, диспетч :6607-6608) → `FwOperationsCreate` (`fw_ops.cpp:955`, гейт :982 `!ignoreCacheRep && !noFwCtrl`) → `FwCompsMgr` (MCC) → `FS_FSCTRL_GEN` :1083 → `FsCtrlOperations::FwSetVPD` = `unsupportedOperation()` (`fsctrl_ops.cpp:1072-1077`) | FW-mediated **MCC/reg-access — реализации НЕТ** (заглушка) |
| I2 write, live, `-ocr`/`--no_fw_ctrl` (direct) | флаги из CLI (`subcommands.cpp:606,612`) → `FwAccessCreate` (`fw_ops.cpp:1089`, `:580-594` `new Flash` → mflash: CR-space flash-interface, поколенческие адреса — `mflash/mflash.c:3850-3902` и др.; эффект -ocr = `MFO_IGNORE_CASHE_REP_GUARD` `mflash.c:2818`) → `CheckFwFormat` :1099 по HW dev-id (:739-742) → `Fs3Operations::FwSetVPD` (`fs3_ops.cpp:1922-1940`, `FAIL_NO_OCR` :1928 / `fs3_ops.h:72-79`) → `UpdateSection` (:2770, VPD :2832-2839) или `Fs4Operations::UpdateSection` (`fs4_ops.cpp:3709`, VPD :3851-3859) → `Fs3ReburnItocSection` (:2711,:2728) / `Fs4ReburnSection` (:3293-3318) → `writeImage` (`fw_ops.cpp:1333`→`:1215`) → `_ioAccess->read_modify_write_phy` :1261 | **прямой flash** (mtcr mflash, CR-space flash-if) |
| I2 write, **image** | `FHT_FW_FILE` → `FImage` (`fw_ops.cpp:476-482`) → та же FwSetVPD-цепочка (без FAIL_NO_OCR-эффекта на образе); write — `(FImage*)_ioAccess->write` (`fw_ops.cpp:1292`); после записи — `VerifyImageAfterModifications` (`fs3_ops.cpp:1935`) | файл образа, секция 0xE3 (§1.3) |
| I2, FS2 (CX-3) | отказ «Setting VPD is not supported in FS2 image format.» (`fs2_ops.cpp:2295-2301`), обе ветки | — |
| I5, kernel | ioctls `kernel/mst_main.c:1980` (READ4) / `:2023` (WRITE4) → `pci_read4_vpd` (`kernel/mst_vpd.c:37-98`) / `pci_write4_vpd` (:101-163); F-протокол и лимиты — §2.2; write-ioctl без OSS-потребителя (§1.1) | **cfg-space напрямую** (ядро) |
| I7/I8 | `popen("lspci -s <dbdf> -vvv")` (`pci_library/PCILibrary.cpp:103-142`; `small_utils/mlxfwresetlib/drivers_safety_check.py:586-600`) — lspci сам читает sysfs vpd (generic PCI core, вне refs) | cfg-space через внешний инструмент ОС |
| I9 | `reg_access_mqis` (`reg_access/reg_access.c:537-540`, `REG_ID_MQIS 0x9064` :88) → mtcr reg-channel `mreg_send_wrapper` (`mtcr_ul/mtcr_ul_com.c:4892`): MAD при MST_IB :4896-4903; иначе ICMD :4905-4914 (`supports_icmd` :5035-5058 — CX3/CX3Pro исключены :5050-5052); для CX3 — tools-cmdif :5060-5082. Потребителей info_type 0x0 нет (§1.1 I9) | **reg-space, FW-mediated** (MQIS) |

### 2.2 Механика cfg-space: cap-поиск, лимиты, F-строка

- **Cap-поиска в userland нет**: `mvpd_read4_ul_int` (`mtcr_ul_com.c:5139-5187`)
  — гейт `mf->dinfo` :5143-5147 (EPERM); развилка `ul_ctx->via_driver` :5148
  (устанавливается только при открытии через ноды mst-драйвера/fwctl —
  `mtcr_driver_open` :1293, fwctl :1257; по умолчанию 0). Оба пути
  обслуживает ядро: mst-модуль или generic PCI core (sysfs).
- **Ядро (mst)**: `dev->vpd_cap_addr = pci_find_capability(pdev,
  PCI_CAP_ID_VPD)` (`kernel/mst_main.c:2239`) — общий create_device-путь
  (для PCICONF и PCICR/MEM одинаково). Cap отсутствует → 0 → отказ
  `-ENODEV` «not support Vital Product Data» (`mst_vpd.c:45-49,109-113`).
- **F-строка** (бит 15 / 0x8000 регистра VPD_ADDR): read — записать адрес
  с F=0 (`0x7fff & offset`, `mst_vpd.c:55`), поллить до F=1 (:68-84),
  снять dword с PCI_VPD_DATA (:90); write — dword в PCI_VPD_DATA (:119),
  адрес с F=1 (`0x8000 | (0x7ffff & offset)` :127), поллить до F=0
  (:139-156). Таймаут `MST_VPD_DEFAULT_TOUT` = 2000 мс
  (`kernel/mst_kernel.h:73`), затем `-ETIMEDOUT`.
- **Лимиты адреса/размера**: read-маска 0x7fff → окно 32767 Б; write-маска
  0x7ffff шире, но addr — uint16_t, биты ≥15 теряются → то же окно 32K.
  Согласовано с libmvpd (walk до 32K, `mvpd.c:58,575-593`). Буфер тула —
  4096 (`vpd.c:50,55`); клампа между lib-walk (32K) и буфером тула нет —
  VPD >4K переполнит буфер mstvpd (код-деталь). FS4 write-лимит 0x1000 =
  4096 Б «corresponds to VPD max size in mlx» (`fs4_ops.cpp:3280-3285`).
  Размер/валидность содержимого в sysfs-ветке контролирует generic-ядро
  (вне refs); код-деталь: `fread(value,1,4,f) < 1` (:5179) пропускает
  частичное чтение (хвост буфера не инициализируется).

### 2.3 Матрица поколений (по коду, без live-проб)

Группировка форматов: `GetFwFormatFromHwDevID` (`fw_ops.cpp:2601-2628`) =
`dm_dev_is_fs3/4/5/6` (`dev_mgt/tools_dev_types.c:1093-1114`).

| Поколение | FW-формат (live ops) | cfg-space read (I1/I6/I7/I8) | MQIS-поверхность (I9) | Live-ops дефолт (MCC?) | FwSetVPD write по коду |
|---|---|---|---|---|---|
| CX-3/3Pro | FS2 (:2604) | гейтов нет (только is_hca libmvpd) | ICMD исключён (`mtcr_ul_com.c:5050-5052`); tools-cmdif-канал есть (:5060-5082); сам MQIS-регистр для CX3 — вопрос к FW (код канал не запрещает) | MCC исключён статически (`fw_comps_mgr.cpp:1795-1798`) → всегда direct | отказ FS2 (`fs2_ops.cpp:2295-2301`) |
| CX-4/4LX (+CIB/SIB/Spectrum) | FS3 (:2608) | гейтов нет | ICMD-да (не исключён); MCAM-гейт | CX4/CX4LX не в стат. исключении → MCAM-runtime (код допускает MCC при caps) | FS3 рабочая: image всегда, live с -ocr; лимит — флеш («last piece of Data on the flash», `fs3_ops.cpp:2576-2582`) |
| CX-5/6/6DX(6LX) | FS4 (:2612-2614) | гейтов нет | да | да (MCAM) | цепочка рабочая (наследование FS3 + Fs4-override, DTOC, лимит 0x1000), но live-дефолт = MCC-заглушка; фактически на live — открыто (H-V4) |
| CX-7 | FS4 (:2612 — тот же класс, что CX5/6) | гейтов нет | да | да | как CX5/6 |
| справочно: CX8+/QTM3 → FS5 (:2618-2619); Spectrum6 → FS6 (:2623) | | гейтов нет | да | да | FS5 — own-реализаций нет, цепочка унаследована (§2.4); FS6 — нет кейса в фабрике (`fw_ops.cpp:1171-1174`), live ops не создаётся |

### 2.4 Ответ: есть ли FS4/FS5 FwSetVPD-реализации

- **FS4 — реализация есть**, составная: `Fs3Operations::FwSetVPD`
  (унаследован, `fs3_ops.cpp:1922-1940`) + override
  `Fs4Operations::UpdateSection` с VPD-веткой (`fs4_ops.cpp:3709`,
  :3851-3859) + `Fs4UpdateVpdSection` (:3265-3291: 4-байтная
  выровненность :3274-3277, лимит 0x1000 :3281-3285) + `WriteSection`
  (:3975). VPD_R0 — DTOC-секция (`isDTocSection` :3589-3617, :3595);
  на encrypted-образе DTOC обновлять разрешено (:3731-3742). Второй
  0x1000-гейт — в vector-overload `UpdateSection` (:4039, :4104-4107),
  отдельная точка входа, не путь set_vpd.
- **FS5 — own-реализаций нет** (поиск `vpd`/`UpdateSection` в
  `fs5_ops.{h,cpp}` — нуль попаданий; `Fs5Operations : Fs4Operations`,
  `fs5_ops.h:37`): цепочка целиком
  унаследована от FS4/FS3 и по коду функциональна. **Открыто**: фактическая
  применимость на живых FS5-девайсах (direct-доступ, наличие VPD_R0 в
  DTOC) кодом не видна.
- **FW-mediated (MCC) реализации FwSetVPD нет ни для одного формата** —
  единственная MCC-ветка это заглушка (`fsctrl_ops.cpp:1072-1077`);
  рабочие реализации пишут флеш напрямую (mflash). FW-mediated VPD-read
  существует только как поверхность MQIS info_type 0x0 (I9, без OSS-
  потребителя).

### 2.5 Гипотезы H-V1–H-V4 и сверка с наблюдением 2026-11-14 (сводка и передача — §6)

**Сверка** (наблюдение roadmap 200 от 2026-11-14: CX-3/4/4Lx/7 читаются,
CX-5/6 нет — вход, не пере-выводим): по коду CX-7 гомогенен CX-5/6 — один
FW-формат (FS4, `fw_ops.cpp:2612`), один read-путь (нуль поколенческих
гейтов в libmvpd/mtcr/mst_vpd), один MCC/ICMD-класс. Наблюдаемая граница
«5/6 против 7» **не совпадает ни с одной границей кода** (FS-формат, MCC,
ICMD, mflash-свитчи) → детерминант читаемости лежит ниже OSS-API
(экспозиция VPD cap / поведение FW конкретного чипа). Код не подтверждает
и не опровергает наблюдение; он исключает «форматные» объяснения.
Единственная обратная корреляция, встроенная в код, — write-сторона
(H-V4).

> Эрратум (арка C, 2026-11-21; улики — §7.2): часть наблюдения
> «CX-5/6 нет» в разрезе CX-6 на доступном экземпляре CX-6 Dx не
> воспроизводится — полный VPD 406 Б (GA SECURED, n=1); вероятно, исходная
> проба 2026-11-14 — CX-6 non-SB (root-localhost, вне топологии, не
> пере-выводима). Пусты — CX-5/5Ex (n=4). Live-вердикты по наблюдению —
> §7.2.

Гипотезы (формат {класс инструмента, класс поколений,
механизм-кандидат, улика, live-дискриминатор}):

- **H-V1** {инструменты cfg-space-чтения I1/I7/I8 (mstvpd/lspci);
  CX-5/6; механизм: VPD capability не экспонируется устройством или не
  обслуживается (пустые данные / F-таймаут); улика: в refs нет ни одного
  поколенческого гейта чтения (`mvpd.c:84-100,549-598`;
  `mtcr_ul_com.c:5139-5187`; `mst_vpd.c:37-163` — гейт только наличие
  cap: `mst_main.c:2239`, `mst_vpd.c:45-49`), т.е. CX5/6-специфика может
  приходить только извне OSS-кода; дискриминатор: live-матрица спеки 2 —
  `lspci -vv` (VPD в cap-list) × `mstvpd -m` (raw) на CX3/4/4Lx/5/6/7:
  cap нет у 5/6 → подтверждена; cap есть, данные пусты/таймаут → вариант
  «cap обслуживает FW не полностью»; полное чтение → опровергнута (→H-V2)}.
- **H-V2** {mstvpd parse-уровень (I1); CX-5/6; механизм: контент есть, но
  не парсится — нет валидного END в окне 32K (`mvpd.c:575-593` → FORMAT
  ERR) либо битая RV-чексумма (`vpd.c:356`, `-n` отключает; прецедент
  «~200K cards with inconsistent format» :391-393); sysfs-вариант: без
  END generic-ядро отдаёт пустой/усечённый файл (механика ядра — вне
  refs, предположение); дискриминатор: `mstvpd -m`/`-n` против дефолта на
  5/6: raw есть, parse падает → подтверждена; raw пуст → опровергнута
  (→H-V1)}.
- **H-V3** {FW-mediated чтение MQIS-0x0 (I9); CX-4+ (MCAM-обязательные);
  механизм: на части поколений «канонический» VPD-путь сместился в
  FW-регистр MQIS, а cfg-space cap не заполняется; улика: поверхность
  описана и обязательна для MCC (`REG_ID_MQIS` `reg_access.c:88`, API
  :537-540; layout `tools_layouts/reg_access_hca_layouts.h:3251`;
  mqisCap в обязательном наборе `fw_comps_mgr.cpp:1823,1849`), но
  OSS-тулингом не используется; дискриминатор: live — чтение MQIS
  info_type 0x0 (mstreg/mcra) на CX5/6 против CX7: валидный VPD через
  MQIS при пустом cfg-space → подтверждена; пусто в обоих → опровергнута}.
- **H-V4** {flint set_vpd write (I2); CX-4+/MCC-capable (вкл. 4/4Lx/5/6/
  6Dx/7); механизм: обратная корреляция на write встроена в код —
  live-дефолт = MCC → заглушка unsupported (`fsctrl_ops.cpp:1072-1077`;
  выбор MCC `fw_ops.cpp:982,1083-1084`), рабочий путь только direct
  (`-ocr`/`--no_fw_ctrl` → `:1089`), и его фактическая работоспособность
  на live CX5/6 (конкуренция с FW за flash, наличие VPD_R0 в DTOC) кодом
  не гарантирована; дискриминатор: спека 2 — set_vpd на **образе** CX5/6
  (ожидаемо работает) против live с -ocr: отказ семафора/DTOC → прямой
  путь тоже закрыт; успех → барьер только MCC-заглушка}.

## 3. Гейты (Q3, по коду)

Классификация отказов — 050 §2: **клиентский** (отказ формирует тул до/без обращения
к FW; FW-reported состояние может быть *условием* ветвления) vs **FW-отказ** (FW не
исполняет/отклоняет операцию). Гейты нумеруются G1–G22 (стабильные ID для задач 4+;
переименование запрещено, изменения — дополнением). Все file:line — по пину §1.

### 3.1 Матрица «гейт × инструмент (I-IDs) × поколение»

| ID | Гейт (file:line) | Инстр. | Поколения | Отказ (050 §2) | Суть / сообщение |
|----|------------------|--------|-----------|----------------|------------------|
| G1 | EXTERNAL-регистрация set_vpd (`cmd_line_parser.cpp:98`, диспетч `flint.cpp:160`, оба `#ifndef EXTERNAL`; `-DEXTERNAL` безусловно `flint/Makefile.am:57`) | I2 | все (build-level, не зависит от чипа) | **клиентский** | в сток-сборке команды нет вовсе (факт-правка roadmap 200: гейт по регистрации, не по verifyParams) |
| G2 | EXTERNAL-гейт hw: конструктор `subcommands.cpp:7247`/`:7269`, verifyParams `:7289` (external = только `query`) | — (референс; hw вне I-реестра) | все | **клиентский** | контраст к G1: `hw` регистрируется в обоих билдах (`cmd_line_parser.cpp:108`), гейт — по verifyParams |
| G3 | `Wtv_Dev_Or_Img` (`subcommands.cpp:803-812`) | I2 | все | **клиентский** | отказ только «dev+img» / «ни одного» (FLINT_DEVICE_AND_IMAGE_ERROR); ровно один вход — OK |
| G4 | MCC-стаб `FsCtrlOperations::FwSetVPD` (`fsctrl_ops.cpp:1072-1077`) → `unsupportedOperation()` (`:52-60`) | I2 **live-default** | CX4+ (MCC-capable по MCAM); CX3/3Pro — статически вне MCC (G7) | **клиентский**; условие ветвления — FW-reported `security_type` (`:233`) | secure_fw=1 → «Unsupported operation under Secure FW»; иначе → «Unsupported operation under Controlled FW, please retry with --no_fw_ctrl <command>» |
| G5 | `FAIL_NO_OCR("set VPD")` (`fs3_ops.h:72-79`, вызов `fs3_ops.cpp:1928`; условие `is_flash() && !ignoreCacheRep`) | I2 live direct | FS3/FS4/FS5 (FS2 отказывает раньше — G6) | **клиентский** | «-ocr flag must be specified for set VPD operation»; на образе не срабатывает (`is_flash()==0`); семейство: sg `:1750`, smg `:1842`, VSD `:2921`, cert fs4 `:3679` |
| G6 | FS2-отказ (`fs2_ops.cpp:2295-2301`) | I2 (live и image) | CX-3/3Pro | **клиентский** (форматный) | «Setting VPD is not supported in FS2 image format.» |
| G7 | MCC-доступность `getFwSupport` (`fw_comps_mgr.cpp:1795-1798` статич. искл. CX3/CX3Pro/SwitchIB(2); `:1821-1852` MCAM mcqs/mcqi/mcc/mcda/mqis/mgir + **MLOCK GET `_secureHostState != LOCKED`**) | I2 live-default (выбор ops-класса) | CX3 статич.; CX4+ — runtime MCAM | **клиентский** capability-чек | недоступен MCC → фолбэк на direct (`fw_ops.cpp:982-1089`); locked-secure-host тоже уводит в direct → G10 |
| G8 | cache-replacement guard (`mflash.c:2034-2090`, `flash_init_with_cache_guard :2574-2600`; direct-init пер-ген `:2781/:2791/:2808`, CX3 `:2818`) | I2 live (mflash init) | все live | **клиентский** выбор канала | без `-ocr` доступ через FW (cache replacement); с `-ocr` (MFO_IGNORE_CASHE_REP_GUARD, `:2041/:2050`) — direct; MLNXOS → MFE_OCR_NOT_SUPPORTED (`-ocr` запрещён, `:2041-2046`) |
| G9 | флеш-семафор MFE_SEM_LOCKED (`flint_io.cpp:425-433`) | I2 live direct | все live | FW-side **состояние**, репорт клиентский | «Can not obtain Flash semaphore… -clear_semaphore»; клиренс — только ребут (скилл flash-ops) |
| G10 | secure-host/mlock: CR_LOCK_HW_ID `0xbad0cafe` (`mflash.c:2968`, детект `:3061-3063`) + MLOCK GET mode≠0 (`:3070-3075`) → MFE_LOCKED_CRSPACE (`flint_io.cpp:440-444`) | I2 live direct (и весь mflash) | все; детект MLOCK — ICMD-capable (CX4+), CX3 — cmdif/tcif | **клиентский** детект FW-состояния | «HW access is disabled on the device… hw_access enable [key]»; открытие — MLOCK SET с ключом (`mf_secure_host_op` `mflash.c:5058-5078`; CIB → REG_NOT_SUPP `:5066-5069`; не-ICMD → tcif_hw_access `:5033-5048`); `set_key` = MLOCK SET lock (`fs3_ops.cpp:2934-2956`) |
| G11 | RDID 0xFF/0x00 → MFE_NO_FLASH_DETECTED (`mflash.c:665-672` → `:843/:863/:1671`) | I2 live direct (+весь direct-flash) | secure-fw карты (FW-глухота шлюза, 050 §1) | **FW-отказ** | прямой путь на secure-fw закрыт самим FW; клиентской диагностики в mstflint нет |
| G12 | Контентные: 4-байтная выровненность — FS3 и FS4 (`fs3_ops.cpp:2571-2575`, `fs4_ops.cpp:3274-3277`), лимит 0x1000=4096 Б — только FS4 (`:3279-3285`) | I2 (live и image, FS3/FS4-ветки) | CX-4/4LX (FS3 — выровненность), CX5/6/7 (FS4), FS5 (наследование) | **клиентский** | «Size of VPD file: %d is not 4-byte aligned!» / «VPD data size exceeds max VPD size: 0x1000 bytes» |
| G13 | FS3-лимит «до конца флеша» (`fs3_ops.cpp:2575-2582`) | I2 (live и image, FS3-ветка) | CX-4/4LX | **клиентский** | «VPD data exceeds flash size…» |
| G14 | encrypted-образ: ITOC запрещён / DTOC разрешён (`fs4_ops.cpp:3725-3742`) | I2 image | FS4+ | **клиентский** (по содержимому образа) | «Can't update ITOC section in case of encrypted image»; VPD_R0 — DTOC (§1.3), обновление разрешено |
| G15 | `dm_dev_is_hca` libmvpd (`mvpd.c:137`, `:565-571` → MVPD_FORMAT_ERR) | I1, I6 | все | **клиентский** (класс девайса) | «Device is not an HCA…»; единый «поколенческий» фильтр read-пути |
| G16 | EPERM-гейт `mf->dinfo` (`mtcr_ul_com.c:5143-5147`) | I1, I6 (ul-путь) | все | **клиентский** | device-info недоступен → errno EPERM |
| G17 | ядерный cap-гейт -ENODEV (`kernel/mst_vpd.c:45-49` read / `:105-113` write) | I5 (и I1 через mst-ноду) | все | **клиентский** (ядерный; наличие VPD cap — HW-конфиг) | «not support Vital Product Data»; cap-адрес — `mst_main.c:2239` |
| G18 | F-строка таймаут 2000 мс (`mst_kernel.h:73`, механика §2.2) | I5, I1-via-driver | все | **FW/HW-side** | -ETIMEDOUT: cap не обслуживается (кандидат-механизм H-V1) |
| G19 | ICMD-исключение CX3/CX3Pro (`mtcr_ul_com.c:5050-5055`) | I9 (канал reg-access) | CX3 → tools-cmdif (`:5060-5082`) | **клиентский** выбор канала | канал определяется до рег-запроса; сам MQIS для CX3 — вопрос к FW |
| G20 | рег-фильтр MQIS 0x9064 (050 §1: «pass always» доказан только для 0x9060-0x9063; MQIS — на границе диапазона 0x9020-0x9064) | I9 | secure-fw карты | **FW-side**, кодом не виден | open item: обработка MQIS роутером 0xc6dd4 не декодирована — живой проб (дискриминатор H-V3) |
| G21 | post-mod verify — только образ (`fs3_ops.cpp:1934-1935`, `VerifyImageAfterModifications :1935`) | I2 | все FS3+ | семантика, не отказ | на live пропускается «for performance reasons» |
| G22 | MLNXOS OCR-запрет MFE_OCR_NOT_SUPPORTED (`mflash.c:2041-2046`) | I2 live direct под mlnxOS | все (в MLNXOS-окружении) | **клиентский** | `-ocr` в MLNXOS запрещён; всегда FW-канал |

Гейт-открыватели (не гейты): `hw_access enable/disable [key]` (`subcommands.cpp:7062-7160`,
Wtv_Dev `:7079`) — MLOCK SET unlock/lock через Fs3/FsCtrl (`fs3_ops.cpp:2962-2972`,
`fsctrl_ops.cpp:1498-1540`); `set_key` — MLOCK SET lock (`fs3_ops.cpp:2934-2956`).
`nv_secure_host` в дереве отсутствует (rg без ext_libs — нуль): термин брифа покрывается
классом MLOCK/secure-host (`tools_open_mlock`, `tools_layouts/tools_open_layouts.h:1022`;
API `reg_access_secure_host` — `reg_access/reg_access.h:192`, `.c:772-774`).

### 3.2 «Unsupported operation under Secure FW» по инструментам

Единственная точка строки — `FsCtrlOperations::unsupportedOperation()` (`fsctrl_ops.cpp:52-60`);
через неё проходят все MCC-стабы: FwSetVPD (`:1076`), FwGetSection=dc (`:1084`, 050 §2),
FwReadRom/FwBurnRom/FwDeleteRom (`:573/:582/:589`), и др. Разложение по реестру:

- **I2 (set_vpd)** — единственный VPD-инструмент на этом гейте: live-default → отказ
  **клиентский** в обоих вариантах (Secure FW / Controlled FW); выбор варианта — по
  FW-reported security_type (`fsctrl_ops.cpp:233`). На secure-fw карте direct-путь
  закрывается независимо FW-отказом G11 → set_vpd недостижим на live secure-fw обоими
  путями (клиентский стаб + FW-глухота).
- **ri/dc** (не в I-реестре, кросс-050 §2): FwReadData — собственный текст «Read image
  is not supported» (`:547-553`), FwGetSection — через unsupportedOperation (`:1079-1085`);
  оба клиентские — совпадает с выводом 050 §2.
- Остальные I-реестра (I1/I5-I9) гейта не касаются: их пути не идут через FsCtrlOperations.

### 3.3 Live vs image-семантика I2 (один инструмент — два множества гейтов)

| Аспект | Live (default, MCC) | Live (`-ocr`/`--no_fw_ctrl`, direct) | Image (`-i`) |
|---|---|---|---|
| ops-класс | FsCtrlOperations (`fw_ops.cpp:982` → `:1083`) | Fs3/Fs4Operations (mflash, `:1089`) | Fs3/Fs4Operations (FImage, `fw_ops.cpp:476-482`) |
| входной гейт | G1, G3, G7 | G1, G3, G5, G8 | G1, G3 |
| transport-гейты | G4 (стаб) | G9 семафор, G10 mlock, G11 secure-blind | — (файл) |
| контентные гейты | G12/G13 (по ветке формата) | G12/G13 | G12/G13/G14 |
| post-verify | — (G21) | — (G21) | `VerifyImageAfterModifications` (`fs3_ops.cpp:1935`) |
| формат-выбор | HW dev-id (`fw_ops.cpp:739-742`) | тот же | fingerprint образа (`:746-759`) |

Итог: один и тот же CLI-инструмент на образе упирается только в контентные/форматные
гейты (G3, G6, G12-G14), на live — каскад транспортных (G4/G5, G8-G11); FAIL_NO_OCR и
семафор/mlock/secure-blind на образе неприменимы.

### 3.4 Сверка (журнал 2026-09-28, спека §1) и расхождения

- **Спека §1 — факты подтверждены пинами**: `-DEXTERNAL` безусловно (`flint/Makefile.am:57`);
  конструктор hw `#ifndef EXTERNAL`/`#else` (`subcommands.cpp:7247`/`:7269`), verifyParams
  `#ifdef EXTERNAL` (`:7289`); set_vpd EXTERNAL-гейтован **по регистрации**
  (`cmd_line_parser.cpp:98`, `flint.cpp:160`) — посылка спеки «не гейтован» ошибочна
  (факт-правка roadmap 200 уже в §1.1); `MFT_SDK_EXTERNAL` (`configure.ac:608`) ≠
  flint-EXTERNAL. Live-`-ocr`-условие (G5/G8) — проверено отдельно, как предписано.
- **Журнал 2026-09-28 (hw set chain) — расхождений нет**: конструктор `:7245`, `_v = Wtv_Dev`
  `:7279`, verifyParams `:7287`, executeCommand `:7582`, Wtv_Dev-кейс `:778-790`, порядок
  preFwAccess `:866-877`, OCR-warning `:830-833` + текст `err_msgs.h:187-188`,
  MFO_IGNORE_CASHE_REP_GUARD `:2041/:2050`, cache-guard `:2574`, secure_host decl `:144-145`,
  use `:3072`, error-string `:3711-3712` — всё совпало с текущим пином.
- **Отдельные строки расхождений**:
  1. Термин брифа/спеки `nv_secure_host` — в дереве отсутствует; фактический механизм —
     MLOCK-регистр/secure-host (G10). Не расхождение с журналом 2026-09-28 (журнал корректно
     пишет secure-host); помечено как терминологическая правка.
  2. 070 §2.3 (матрица Q2) формулировка «CX-3: MCC исключён статически → всегда direct» —
     уточнено G7: статическое исключение покрывает CX3/CX3Pro/**SwitchIB/SwitchIB2**
     (`fw_comps_mgr.cpp:1795-1798`); для VPD-цикла релевантен только CX3/3Pro (FS2 → G6).
  3. MQIS 0x9064 (I9): вывод 050 §1 «MC*C/MCDA/MCQS/MCQI проходят всегда» не переносится
     на MQIS (следующий reg-id) — FW-обработка MQIS на secure-fw карте не декодирована
     (G20, open item; влияет на применимость дискриминатора H-V3).

## 4. MTUSB/out-of-band I2C-бэкенд (Q4, аудит-only; детали — журнал task-04)

MTUSB в пине — вестige: интерфейс-тип SDK `MTUSB` мапится на легаси-флаг
`MDEVS_I2CM` (0x02, `mft_sdk/mft_sdk_discovery.cpp:248-250`), но энумерации с
этим флагом нет — `mdevices_v_ul` гейтит `if (!(mask & MDEVS_TAVOR_CR))
return 0` (`mtcr_ul/mtcr_ul_com.c:3392-3395`), info-слой парсит имена только
как PCI BDF (:3853-3860), а `updateDeviceInfo` отбрасывает non-PCIe
(`getDeviceIdentifierByType` → NOT_SUPPORTED, `mft_sdk_discovery.cpp:229-238`,
скип :534-537). Фактический out-of-band бэкенд — generic I2C: `/dev/i2c-N` →
`MST_DEV_I2C` (`mtcr_parse_name`, `mtcr_ul_com.c:3052-3057`) → `mtcr_i2c_open`
(:2799-2828: flags `MDEVS_DEV_I2C` 0x200, sec-addr 0x48, vtable
mread4/mwrite4 → i2c-ioctl `I2C_RDWR`, `#ifdef ENABLE_MST_DEV_I2C` — opt-in,
`configure.ac:88` `default_en_i2c="no"`); sec-addr 0x47 для secure-gen CX7+
(`change_i2c_secondary_address` :2939-3010, таблица :2830-2832 — CX5/6 в неё
не входят); override — flint `--i2c_secondary` (`flint/flint.cpp:280-285`) и
SDK `mstGetDeviceHandleWithI2cSecondary` (:581-593). VPD у I2C-девайса идёт
тем же libmvpd-кодом только до транспортного слоя: `mvpd_read4_ul_int` гейтит
`mf->dinfo` → EPERM (G16; dinfo заполняется только в PCI-путях,
`init_dev_info_ul` :4304 вызовы :1320/:1371/:2278/:4165) — собственного
I2C-VPD-пути нет, cfg-space VPD out-of-band недостижим; единственная
VPD-поверхность over-i2c — FW-mediated MQIS (I9) через ICMD поверх i2c-CR
(`icmd_open` → `icmd_init_cr`, `mtcr_ul/mtcr_ul_icmd_cif.c:1462-1467`; G20
в силе). **Вывод-кандидат для роадмапа 120:** out-of-band I2C-путь структурно
повторяет PCIe-direct — mflash flash-GW явно поддерживает i2c
(`mflash/mflash.c:1166-1172`, для i2c даже пропущен polling busy-бита), рег-
канал ICMD инициализируется поверх i2c-примитивов, и ни один гейт G1–G22 не
проверяет транспорт: клиентских secure-fw проверок на i2c в OSS-коде нет,
CX5/6-класс не попадает в secure-gen i2c-таблицу (остаётся на 0x48). Путь
обносит только транспорт-специфичные преграды (ОС-драйверы/BAR/fwctl-фильтры);
известные FW-гейты (G9/G10/G11) — состояния FW/HW, транспортно-нейтральные по
коду, и механизм, которым FW различал бы i2c- и PCIe-доступ к flash-GW, в
OSS не виден. Обносит или упирается — поведением FW/HW i2c-slave конкретной
карты, кодом не решается: live-дискриминатор для 120 (CH-341/347-транспорт —
там же). Развёрнуто и исключённое — журнал task-04. Развёрнутый протокольный
канон out-of-band I2C (проводной фрейминг CR/flash-GW/ICMD, sec-addr,
электрика/MTUSB-1, свитчи, офлайн-эмпирика) — `250-re/140-oob-i2c/100-protocol.md`
(цикл mtusb-i2c-re, 2026-11-19); транспортная спека —
`superpowers/specs/2026-11-19-mtusb-i2c-transport-design.md`.

## 5. Инструменты цикла (Q5)

Замыкает Q5 спеки цикла (`superpowers/specs/2026-11-17-mstflint-vpd-design.md`
§2); детали — журналы task-05..07.

- **Q5а — non-EXTERNAL билд flint (`hw set`/`hw query`).** Механика —
  снятие `-DEXTERNAL` с flint-цели (единственный define-сайт —
  `flint/Makefile.am:57`; G1/G2) патчем сиблинга `../mstflint-container`:
  `patches/mstflint-4.37.0-1.4-hw-set-nonexternal.patch` (сиблинг-коммит
  b803328, серия v4.37.0-1.4, build-SHA 1b8ac4b5 — потомок пина a2b9858b,
  см. `150-external/000-pinned-revs.md`). Все 7 препроцессорных
  EXTERNAL-сайтов flint/ переключаются разом (таблица в журнале task-05:
  регистрация smg/set_vpd/set_attestation_cert_chain/
  set_cpo_calibration_data/fix_img/extract_4mb_image, hw-ветки ctor/
  verifyParams, видимость allow_psid_change/apc в help, (oem)-маркер
  version). Smoke (офлайн, fake-BDF): `hw [query/set]` зарегистрирован,
  полный `_paramExp` в help (QuadEn, DummyCycles,
  Flash[0|1|2|3].WriteProtected, DriverStrength); `hw set QuadEn=1`
  проходит verifyParams — отказ только на open (MFE_CR_ERROR) — контраст
  с EXTERNAL-сборкой (отказ «you can use query» до open). Артефакты:
  `build/mstflint-4.37.0-1.4-x86_64.AppImage` + `build/manifest.txt`
  (манифест по прецеденту mstflint-tooling). Live-смоук — вне цикла
  (device-only инструмент, опция владельца; image-level hw не существует:
  `_v = Wtv_Dev` вне условной компиляции, `subcommands.cpp:7279`).
- **Q5б — `set_vpd` на образе.** Probe-verified (FS3-копии lx-дампа и
  дистрибутива, non-EXTERNAL 4.37.0-1.4; refs не тронуты, sha256 в
  журнале): семантика канонизирована в §1.1 I2 (вход не парсируется,
  4-байтная выровненность, in-place/EOF-рост, ITOC-поля size+sec_crc+
  entry_crc, post-verify PASS). Журнал task-06.
- **Q5в — mlxfwutil `vpd` (VPD_R0 0xE3, image-level).** CLI
  `mlxfwutil.py vpd <image> (--dump FILE | --set FILE -o OUT)`:
  FS3 — ITOC, FS4 — DTOC (`vpd_section`; хелпер `_rewrite_section`
  параметризован ITOC/DTOC — единый канон CRC-порядка 025 §6:
  sec_crc → entry_crc). Класс — replace same-size only (решение
  владельца): отказы {нет секции, size=0, size-mismatch} — внятные,
  до любых записей; hashes-table не трогается (FS4 VPD — DTOC-секция,
  вне покрытия hashes); self-verify после replace (прецедент
  cmd_patch). TDD: `tests/test_vpd.py` — fast-синтетика FS3+FS4 +
  slow roundtrip на refs (lx_c1 FS3 0x78 @0xff8140; e0_pre_raw FS4
  0xcc). Границы класса (inject/grow size=0, полный FS4-write) —
  открытые классы до C1-вердиктов спеки 2 (см. §6). Журнал task-07.

## 6. Передача: гипотезы H-Vn и открытые пункты (handoff)

H-Vn — гипотезы-кандидаты объяснения обратной корреляции (наблюдение
roadmap 200 от 2026-11-14: CX-3/4/4Lx/7 читаются, CX-5/6 нет),
порождённые аудитом кода. Инструментальная поверхность вердиктов не
даёт: код исключает «форматные» объяснения границы 5/6-vs-7 (§2.5), но
FW-механику карты не доказывает. Вердикты — только live-матрицей
**спеки 2** — `superpowers/specs/2026-11-17-securefw-arc-c-design.md`
(цикл 2 арки C: C1 build-vs-parse, C4 live-пробы); её план — отдельный
цикл. Сверенный список (полная форма {инструмент, поколения, механизм,
улика, дискриминатор} — §2.5):

| ID | Гипотеза (кратко) | Поколения | Live-дискриминатор (кратко) |
|----|-------------------|-----------|------------------------------|
| H-V1 | cfg-space VPD cap не экспонируется/не обслуживается устройством (I1/I7/I8) | CX-5/6 | `lspci -vv` (VPD в cap-list) × `mstvpd -m` (raw) по поколениям; полное чтение → опровергнута (→H-V2) |
| H-V2 | контент есть, parse падает: нет валидного END в 32K / битая RV-чексумма (I1) | CX-5/6 | `mstvpd -m`/`-n` против дефолта: raw есть, parse падает → подтверждена; raw пуст → опровергнута (→H-V1) |
| H-V3 | VPD-путь сместился в FW-регистр MQIS info_type 0x0 (I9), cfg-cap не заполняется | CX-4+ (MCAM-обязательные) | чтение MQIS 0x0 (mstreg/mcra) × cfg-space на 5/6 vs 7; валидный VPD через MQIS при пустом cfg → подтверждена; пусто в обоих → опровергнута |
| H-V4 | write-барьер: live-дефолт set_vpd = MCC-заглушка (G4), direct (`-ocr`) на live 5/6 не гарантирован | CX-4+/MCC-capable (4/4Lx/5/6/6Dx/7) | set_vpd на **образе** CX5/6 (ожидаемо работает — Q5б) против live с `-ocr`: отказ семафора/DTOC → прямой путь закрыт; успех → барьер только MCC-заглушка |

Вердикты live-матрицы арки C (2026-11-21) — **§7.2**.

Открытые пункты (вердикт-семантика: «открыто» — не «нет»):

- **G20**: обработка MQIS 0x9064 роутером secure-fw не декодирована
  (вывод 050 §1 на MQIS не переносится) — влияет на применимость
  дискриминатора H-V3; живой проб.
- **FS5**: собственных VPD-реализаций нет, цепочка унаследована от FS4
  (§2.4) — фактическая применимость на живых FS5-девайсах кодом не видна.
- **H-V4 live-ветка**: работоспособность direct-пути на live CX-5/6
  (семафор G9, DTOC-наличие, конкуренция с FW) — только live.
- **i2c out-of-band (§4)**: обносит ли путь FW-гейты — поведение
  i2c-slave конкретной карты, кодом не решается; live-дискриминатор —
  роадмап `010-roadmap/120-mtusb-i2c.md`.
- **Q5а live-смоук** `hw set` — не выполнялся (вне цикла, опция
  владельца; device-only).
- **Q5в inject/grow (size=0) и полный FS4-write** — открытые классы
  инструмента (развилка владельца: строить после C1-вердиктов спеки 2).

## 7. Карта поколений VPD-механики и вердикты (арка C, 2026-11-21)

> Источник: цикл securefw-arc-c — журналы `superpowers/journal/
> 2026-11-21-securefw-arc-c-task-01..07.md` (вердиктные таблицы T0-A/B/C,
> T2-A, T3-A, T4-A, T5-A, T6-A/B), спека `superpowers/specs/
> 2026-11-17-securefw-arc-c-design.md` §2. Только publish-трансформ
> (структура/длины/CRC/счётчики; без per-unit значений). Вердиктная
> семантика: «не найдено ≠ опровергнуто»; n-маркировка обязательна.
> Live-инструмент проб: lab AppImage mstflint/mstvpd/mstreg 4.37.0-1.4
> (§5 Q5а); as-of 2026-11-21T12:25–12:29+00:00.

### 7.1 Сводная таблица поколений (data-locus / кто пишет / кто читает / MAIN)

| Поколение | Где живёт контент (data-locus) | Кто пишет | Кто читает | MAIN-механика (0x03) | cfg-space экспозиция (live) |
|---|---|---|---|---|---|
| CX-3 (FS2) | формата 0xE3/ITOC нет (3/3 образца, вкл. HP-контроль; бинарный скан дистрибутивов — 0 хитов VPD-подписей); локус живых CX-3 **открыт** (V2-e; n=0: карта в топологии отсутствует as-of) | неизвестно (open) | неизвестно | нет (0 триггеров) | n=0 (недоступна as-of) |
| CX-4/4Lx (FS3) | слот 0xE3 @0xff8140 (вплотную к хвосту MFG_INFO) в **основной NOR-flash**: дистрибутивы 24/24 size=0 = пустой слот (файл ровно 0xff8140, sec_crc=0x0955 — константа пустой секции); живые карты n=2 — ровно 0x78 Б, writer-layout фиксированный | производство/board-integration (единственный наблюдаемый источник контента; SN per-unit); инструментально: `flint set_vpd` (live `-ocr` direct / image EOF-рост — §1.1 I2), `mlxfwutil vpd --set` (same-size); **FNP-burn переписывает device-data-класс → слот пуст/затёрт; plain/legacy-burn сохраняет** (прямая улика: lx_c1 3 состояния одного gen4-цикла побайтово идентичны) | FW карты: flash-слот → cfg-space VPD cap (побайтовое совпадение значений n=2); **served = проекция**: R-часть дословно + синтезированный END, VPD-W-хвост (3 Б) отсечен (n=2 flash × n=3 served); host-инструменты I1/I6/I7/I8 | нет (0 VPD-строк: corpus 14 образов + 24 дистрибутива) | полная: CX-4 HPE 253 Б (n=1), CX-4Lx 117 Б R-часть (n=1); parse OK обоими транспортами |
| CX-5/5Ex (FS4) | слот 0xE3: дистрибутивы size=0 (n=5 checked: 16.35.4030/8008, вкл. OEM `.signed`; кросс-якорь класса: FS3 24/24, CX-7 предрелизы 2/2); research-плата ACUT несла полный stored-VPD 204 Б (n=1 плата, 5 дампов, FW/MFG-циклы не меняют) | производство (минимальный MLX-набор PN/EC/V2/SN/V3/VA/V0); write-пути — как CX-4 (FNP-класс затирает) | FW: MAIN — parse-потребление кэша VPD 0x180 (ниже); serving в cfg-space **пуст** (данные не заполняются) | **parse**: кэш VPD 0x180 @rt 0xe1c0 → parse-кор (теги 0x82/0x90/0x91/0x78 + keywords, явная END-ветка) → VA-map needle-диспетчер (CSKU=/MODL=/MN= → ':'-извлечение, детектор «V2»-ссылок); build-элемент (TLV-запись + back-patch + MAC из CR 0x3263/0x3264) — вторичен, ре-сериализация уже-разобранного | cap[48] экспонируется, секция пуста (n=4: raw 0 Б ×3, 1×0x78 END ×1; двойной транспорт согласован) — **H-V1 proven** («cap есть, не обслуживается») |
| CX-6/6Dx/6Lx (FS4) | Dx: полный stored 0x180 (fb-ri, DTOC size=0x180) ↔ served 406 Б одной платы; дистрибутивы size=0 (n=4 checked + 2 own-сборки) | производство; write-пути те же; VPD_R0-контент **FW-update-инвариантен** (плата Dx: FB→VDA 2 состояния байт-идентично; ACUT CX-5-класс: ≥2 MFG-PSID-состояний) | FW: parse-механика гомологична CX-5 (VA-диспетчер + оркестратор + «UUID=V3»-сканер — FW знает формат V3↔UUID/MAC); serving на Dx полный; **VU — served-only поле** (n=1; значение = SN+«MLNXS0D0F0»; гипотеза FW-синтеза при serve — дискриминатор byte-compare, спека анлока V4a) | **parse** (все снятые версии: CX-6 20.39/20.43, Dx 22.47/22.50, Lx 26.50); VA-needle-набор **version-dependent** (22.32.x без MLX-needle при живом parse-коре, n=2 версии) | Dx полная (406 Б, n=1, GA SECURED); CX-6/6Lx live n=0 (вне топологии) |
| CX-7 (FS4) | data-locus живой fb-платы = **флеш**: VPD_R0 DTOC @0x1ff8140 size=0x180, полный VA-map-контент (n=1 плата; 4 полных raw-дампа — native/FNP-кросс-PSID/crossflash/burn-циклы — байт-идентичны); предрелизные дистрибутивы n=2: size=0 + окно all-FF (**«стёрт» = свойство дистрибутивного класса, не платы; DTOC-запись существует**); FB-дистрибутивы/ri/rb — device-области нет вовсе | провижининг **вне FW-update-цикла** (FNP/MCC device-область не трогают — прямые улики); производство | FW: полный parse-набор в MAIN **и IRON_PREP 0x05** (boot-цепочка; семантика boot-time vs библиотека — open); boot2/BOOT3/boot_record/APU — 0 следов; **served ≠ байт-копия flash** (RV 0x92↔0xa6, хвост `91 c0 03`↔END) → **гипотеза FW-ресериализации** (исполнитель main-FW vs ROM vs HW — open) | **parse** (полный набор без MLX-needle, 28.33.0751/0800) | live n=0 (не энумерирован as-of); наблюдение 2026-11-14 — читается |

Примечания:

1. Единственный MAIN-триггер всех поколений — `CSKU=` (ровно 1×/образ,
   всегда секция 03; corpus 190-A: cx5 21/22 образов, cx6 5/5, cx6dx
   12/12, cx6lx 1/1; полный refs-скан дистрибутивов: cx5 22/24, cx6 9/9,
   cx6dx 14/14, cx6lx 1/1; FB-ri 22.32.1224 и zip-only 22.32.2004 — без
   needle). `PCIeGen`/`MLX:MN` в MAIN
   **отсутствуют** (0/54 corpus + полный refs-скан; строки живут в
   E3/VPD_R0 flash-дампов). Исходные счётчики «cx5=59/cx6=15/cx6dx=36/
   cx6lx=3, все — секция 03» (замер 2026-11-14, roadmap 200)
   **невоспроизводимы** (вероятно framing-независимый grep со смешением
   MAIN/E3-областей дампов); качественная граница «механика есть у
   CX-5/6-класса, нет у CX-4/4Lx» — подтверждена (эрратум roadmap 200).
2. RV-конвенция «сумма байт от тега 0x82 до конца RV-данных == 0 mod 256»
   едина для writer'а и FW-ресериализатора (валидна во всех 6 first-hand
   блобах, вкл. served); длина RV вариативна {1,2,3} — парсер берёт len
   из тега.
3. Байт `0x78` = small-tag **END** (type 0xF, len 0) — стандартный
   терминатор PCI-VPD: у читаемых карт замыкает структуру; raw «ровно
   1×0x78» = пустой, но терминированный контейнер (контента нет вовсе).
4. Терминология локусов: «data-locus» — где контент физически хранится
   (флеш: proven CX-4/4Lx n=2, Dx n=1, CX-7 n=1); «serving» — кто
   заполняет cfg-space VPD capability (FW — рабочая гипотеза с уликами;
   исполнитель на FS4-классе не различим офлайн).

> Эрратум-дополнение (t0-addendum, 2026-11-21 позднее финализации; журнал
> `superpowers/journal/2026-11-21-securefw-arc-c-t0-addendum.md`, фазы 1–2;
> только publish-трансформ):
>
> 1. **CX-7, строка §7.1 «гипотеза FW-ресериализации … live n=0» —
>    superseded (addendum-1, as-of 14:13, карта в PCI): ресериализация
>    PROVEN на live-экземпляре** (n=1 плата / 2 функции / 1 FW-состояние):
>    7 контентных полей served байт-идентичны stored (384→408 Б), **VU
>    синтезируется per-function** (F0/F1 различаются ровно VU-цифрой и
>    RV-байтом; VU в flash-копии отсутствует вовсе), **RV пересчитан**
>    (0x92→0xa6/0xa5), хвост ре-фрейминг `91 c0 03`→END; «побайтовая
>    выдача flash-копии» опровергнута прямым артефактом (обе функции не
>    могут быть побайтовой выдачей одного блоба). Serving =
>    build-from-parse. Исполнитель (main-FW vs ROM) — по-прежнему open
>    (MAIN-улики task-03/04 в силе). H-V1 на CX-7 — excluded (полное
>    чтение 408 Б). As-of 14:29 карта снова вне PCI (свап владельцем).
> 2. **Контраст-строка поколения Dx (addendum-2, as-of 14:29, вторая Dx
>    платы на baz 04:00 — subsystem 0070, OUI e8ebd3, ≠ плата CDAE_FB):**
>
>    | Dx-плата | стейт | PSID / FW | security | stored VPD_R0 | served |
>    |---|---|---|---|---|---|
>    | VDA (board CDAE_FB, T0-A #7) | FB-плата → VDA-образ | MT_0000000457 / 22.50.1002 | secure-fw GA SECURED | 0x180 полный (fb-ri, 384 Б) | 406 Б полный |
>    | вторая Dx (addendum-2) | вендор-рефлеш (путь неизвестен, дамп утерян) | MT_0000000695 / 22.50.1002 (vendor CDA) | secure-fw GA SECURED (q full + MGIR: life_cycle=1, secured=1; **encryption=0** — контраст CX-7 encryption=1) | не читалось (DTOC в normal недоступен); **гипотеза: пуст** (дистрибутив-класс 22.50.1002 size=0, task-05 §4.1; image-wins-доставка DTOC) | **1×0x78** пуст-терминирован (cap[48] экспонирован; parse FAIL; класс «cap есть, данные пусты») |
>
>    Интерпретация — гипотеза с уликами, не вердикт (n=1 as-of состояние;
>    pre-reflash контент неизвестен; путь рефлеша неизвестен — plain-MCC
>    preserved-from-device [INT§5 D2] оставил бы DTOC платы): data-driven
>    serving (ресериализация proven, п.1) единообразно объясняет обе строки.
>    Следствие §7.3: обе Dx secure GA SECURED — served-полнота не
>    коррелирует с secure-state внутри поколения (клетка secure×пустой:
>    HPE CX-5 → + вторая Dx). Решающий тест stored-гипотезы — FNP-окно ri
>    (метод V4a спеки анлока), owner-gated.
> 3. **Топология as-of (addendum):** Dx VDA (T0-A #7) извлечена владельцем;
>    CX-7 в PCI 14:13 → вне PCI 14:29; на baz 04:00 — вторая Dx. Строки
>    T0-A/T6-A фиксируют свои as-of; топологические ячейки «live» этих
>    таблиц — исторические, факты строк в силе.

### 7.2 Вердикты H-V1–H-V4 (live-матрица T6-A/B, read-only)

| Гипотеза | Вердикт (класс) | n / улика |
|---|---|---|
| H-V1 (cap не экспонируется/не обслуживается) | **proven** в варианте «cap экспонируется, **не обслуживается** (данные пусты)» на CX-5/5Ex; подвриант «cap отсутствует» excluded; **excluded** на CX-4/CX-4Lx/CX-6Dx (полное чтение); **open** на CX-3/CX-7 (n=0, недоступны as-of) | CX-5/5Ex n=4 (cap[48] в cap-list на всех × raw 0 Б ×3 / 1 Б END ×1, rc=0; mstvpd × lspci согласованы); CX-4 n=1 (253 Б), CX-4Lx n=1 (117 Б), Dx n=1 (406 Б) — parse OK |
| H-V2 (контент есть, parse падает: END/RV) | **excluded** (улика) | n=7: на CX-5/5Ex raw пуст — «падать не на чём» (`-n` ≡ дефолту — не RV-чексумма); на читаемых parse OK; комбинация «raw есть + parse падает» не наблюдена нигде |
| H-V3 (VPD-канон сместился в MQIS 0x0) | **open (tool-gated)** | MQIS GET t=0x0 проходит на всех n=7 (вкл. secure CX-5 и GA SECURED Dx — G20-отказ не наблюден), но `info_length`=0x180 **константен** (не коррелирует с raw 0/1/117/253/406 Б; sanity t=0x1 → 0x40 — per-type осмысленность), контент недостижим mstreg GET (`read_length` не INDEX/OP); G20-семантика роутинга не декодирована |
| H-V4-live (write-барьер set_vpd на live) | **live-write-gated** (запись = арка C5, не исполнялась) | по коду §3.2 (secure-fw: MCC-стаб G4 + FW-глухота G11 — оба пути закрыты); image-ветка probe-verified (§1.1 I2, Q5б); non-secure live direct — открытый пункт §6 |

Граница читаемости cfg-VPD «CX-5/5Ex пусты, остальные снятые читаются»
подтверждена на доступной подвыборке (7 карт, as-of 2026-11-21); CX-3/CX-7
(n=0) и CX-6/6Lx non-Dx (вне топологии, refs-only) не проверяемы и критерий
IV не гейтят. Детерминант читаемости — не MAIN-строки (CX-7 несёт полный
parse-набор при наблюдаемой читаемости) и не FS-формат (§2.5) — кандидат:
экспозиция/обслуживание cfg-space cap конкретным FW/чипом (H-V1-класс).

### 7.3 Security-корреляты (C2) и постулат 065

- **Security-несущих VPD-полей не найдено** (C2, T5-A; «не найдено ≠
  опровергнуто»): ID-строка «…Secure Boot»-класса — per-SKU board-описание,
  не state-маркер (контрпример: Dell 09FTMY — secure-fw, ID без слов;
  **вне T0-A, n=1**; направление «слова → secure» не тестировано, n=0);
  флаговых keywords нет (0/9 first-hand+ссылочных профилей — все
  identity/структурные); RV-длина/бит-карта и V0 — механические/платные;
  пустота/полнота cfg-VPD — board-integration, не security (2×2 — ниже);
  VPD-контент FW-state-инвариантен (3 независимые линии: Dx-плата 2
  FW-состояния; CX-7 ≥4 состояния; CX-5 ACUT ≥5 дампов 2 MFG-PSID).
  Гэп: confirmed-non-secure с полным VPD в CX-5/6-классе в корпусе нет.
- **Постулат 065 — сужен прямыми уликами** (не закрыт; детали — 065
  «Постулаты», зеркало — 030 «Постулаты»): cfg-space VPD-плоскость
  исключена как коррелят/маркер secure-state (таблица 2×2 «security ×
  cfg-VPD-читаемость» заполнена всеми четырьмя клетками: secure×читаемый
  Dx n=1, secure×пустой HPE CX-5 n=1, non-secure×читаемый CX-4/4Lx n=2,
  non-secure×пустой CX-5 n=3); q-плоскость MGIR-lifecycle поколенчески
  гейтирована, не security-гейтирована (CX-5 n=4 вкл. secure — строк Life
  Cycle/SB в `q full` нет; Dx n=1 — полный ряд); MGIR-канал на CX-5
  доступен read-only `mstreg --reg_name MGIR -g` (n=2, вкл. secure;
  lifecycle-подполя читаются нулями — семантика не декодирована). Ядро
  (источник `MGIR.secured`: отражённый образ vs состояние чипа) открыто —
  разрешение запланировано спекой анлока `superpowers/specs/
  2026-11-21-securefw-arc-c-unlock-design.md` (лестница V1–V5, MGIR
  до/после + DTOC-дельта, owner-gated, исполнение вне арки).

> Эрратум (исполнение лестницы анлока, 2026-11-22..23; §8 ниже; журналы
> `superpowers/journal/2026-11-22-securefw-arc-c-unlock-task-07.md` и
> `-task-10.md` R13-нога + addendum):
>
> 1. **§7.1 (строка CX-5/5Ex, «serving в cfg-space пуст (данные не
>    заполняются)») и §7.2 H-V1 («cap есть, не обслуживается») —
>    superseded:** serving-гейт VPD на CX-5-классе **контент-классовый,
>    не генерационный и не security**. Минимальный валидный блоб 48 Б
>    (ID+V0+RV) не сервируется (пусто у обеих карт V3b, n=2), full-tag
>    204 Б (ACUT-класс PN/EC/V2/SN/V3/VA/V0/RV) сервируется: 41:00
>    secure 16.35.8008 → served 233 Б (n=1), 81:00 non-secure 16.35.4030
>    → served 234 Б после host-ребута (n=1). «Пустые» наблюдения §7.2
>    (n=4) — свойство контента (minimal/отсутствие stored), не «FW не
>    обслуживает плоскость». V3b-исход Б в формулировке «генерационный
>    FW-гейт» опровергнут (§8.4).
> 2. **§7.3 «гэп: confirmed-non-secure с полным VPD … нет» — закрыт**
>    (81:00 после R13/addendum, n=1); вывод §7.3 «пустота/полнота — не
>    security» — усилен контрпримером в обе стороны (см. п.1).
> 3. **§7.2 H-V4-live («live-write-gated») — закрыт исполнением**:
>    live `set_vpd -ocr` работает (FS3 non-secure c1:00 с WP-toggle,
>    CX-5Ex 81:00 без; n=1 каждая); на secure-картах в normal mode
>    direct-путь не открывается вовсе (MFE_NO_FLASH_DETECTED) — доставка
>    FNP-окном (§8.2).
> 4. **§7.1 Dx-строка «VU — гипотеза FW-синтеза, дискриминатор
>    byte-compare V4a» — решён:** ресериализация подтверждена на
>    терминале, VU-инъекция/RV-пересчёт/END-рефрейминг — механика
>    FW-ресериализатора; чистая функция (stored, FW) на измеренном
>    экземпляре (§8.5).
> 5. **Терминология writer-layout T2 §2.2 «reserved-байт 0x00 лежит
>    между len-байтом и данными» — эрратум терминологии (канон-правка, отложенная
>    task-06 №1):** этот байт — **len_hi-байт 3-байтового large-tag
>    заголовка** (tag+len_lo+len_hi), а не четвёртый посторонний байт;
>    keyword-TLV начинаются сразу после заголовка (парсер
>    `VPD_TAG_DATA` = data+3, mvpd.c:60-68; подтверждено блобами V1-C
>    118 Б и refs-окном). Объявленный len считает только keyword-TLV
>    («32+85+3» T2 — совпадает с наблюдением; расхождение было
>    терминологическим). Одновременно пин **scope RV-чексуммы**
>    (task-06 №2, по коду `check_checksum` mvpd.c:268-289): сумма
>    id_data **включая заголовок 0x82** + ro_data **до RV-байта
>    включительно**, END (0x78) **исключён** — суммирование через END
>    даёт ложный остаток 0x78; нотация вида «47+1 Б» (task-06 Step 2)
>    означает ровно это (байты [0..RV] включительно) и заменяется
>    канонической формулировкой. Согласовано с прим. 2 §7.1 (конвенция
>    sum-from-0x82 единая для writer'а и FW-ресериализатора).

## 8. Исполнение лестницы анлока (цикл securefw-arc-c-unlock, 2026-11-22..23)

> Источник: журналы `superpowers/journal/
> 2026-11-22-securefw-arc-c-unlock-task-01..10.md` (task-10 включает
> owner-ноги R12/R13/R14 и addendum), спека анлока §3 (ступени V1–V5).
> Только publish-трансформ; n-маркировка обязательна, перенос на
> поколения не делать. Инструмент as-of: baz mstflint 4.37.0-1.5,
> root-mellanox 4.37.0-1.4 (тот же Git SHA 1b8ac4b…; деплой baz -1.5 —
> owner-ruling as-of факт). Сводка «ступень × дискриминатор × исход» —
> журнал task-11 Step 1.

### 8.1 Канальная калибровка (V1)

`mstreg --reg_name MGIR -g` rc=0 на всех пяти ступеневых картах
(Dx 04:00, CX-4 42:00, CX-4Lx c1:00, CX-5 41:00 secure, CX-5Ex 81:00),
побитовая согласованность с q-плоскостью всюду, где сравнимо (task-01
§2.3–§2.7). Поколенческие display-гейты q lifecycle-строк
(IsLifeCycleSupported «CX6+», IsSecureBootSupported «CX6Dx+») —
сурс-верифицированы: на CX-4/4Lx/CX-5 канал lifecycle = mstreg-MGIR.
`--mcc_read` присутствует в обоих деплоях (-1.4/-1.5).

### 8.2 Физика live `set_vpd -ocr` (V2b, R12/R13 Phase-1, R14)

- **FS3 non-secure (c1:00 CX-4Lx): работает**, но первый live-write
  упёрся в **новый наблюдаемый гейт — flash-level WP (SR1/SR2 BP-биты)**:
  `Top,8-SubSectors` (BP[3:0]=0100, TBS=0) покрывает верхние 32 КБ
  (0xff8000–0xffffffff), включая субсектор с VPD_R0 @0xff8140 →
  `MFE_VERIFY_ERROR` на секторе 0xff8000; окно побайтово уцелело.
  Снятие/восстановление — `flint_oem -d <dev> -ocr hw set
  Flash0.WriteProtected=…` (идемпотентно; owner-GO). Первое наблюдаемое
  исключение из «на всех прожигаемых картах защита уже Disabled»
  (эрратум XF §1.2, docs/850-howto/100-cross-flash-ops.md): image-burn
  тело образа в top-зону не пишет → WP мог стоять с завода незамеченным
  (task-03 §3.3–§3.4, A1–A5).
- **Secure-карты в normal mode: direct-путь не открывается вовсе** —
  `MFE_NO_FLASH_DETECTED` на открытии девайса (до записи, WP-стейт
  неизмерим): 41:00 (n=1) и терминал Dx 04:00 (n=1) — зеркалит
  burn-физику `--no_fw_ctrl` (750-exp/170) на подкоманде set_vpd.
  Доставка VPD на secure-карту — только FNP-окном (R12/R13, n=2 окна).
- **Non-secure CX-5Ex 81:00 (FW 16.35.4030): non-FNP `set_vpd -ocr`
  работает** (direct-путь открыт, WP Disabled as-is) — CX-4Lx-класс
  физики, n=1 (task-10 R13 B-2/B-3).
- **WP c1:00 = `Disabled` — RESOLVED-BY-OWNER (коррекция владельца
  2026-11-23):** наблюдение R14 (WP `Disabled` после ≥4–5 BMC
  cold-циклов, несмотря на восстановленный в task-04 `Top,8-SubSectors`
  с re-query-подтверждением) первоначально фиксировано как гипотеза
  волатильности SR-битов — **снято владельцем: WP сознательно выставлен
  им (`Disabled`, «надоели пляски с enabled-disabled»)**, волатильности
  SR-битов НЕ подтверждено (случай «непроверенная гипотеза опровергнута
  владелец-информацией», не измерением). Следствие: WP-стейт карт —
  **owner-managed** as-of 2026-11-23 (карты ходят с WP=Disabled по
  решению владельца); исторический канон «WP живёт в SR1/SR2 и переживает
  reboot/replug/reflash» (журнал 2026-09-28) — не опровергнут; WP-query
  перед каждой записью обязателен (эрратум XF §1.2 — там).

### 8.3 Сервинг-источник и карта доставки image-VPD (V2b/V2c, R14)

- **served := flash-VPD-окно на момент FW-load.** Исход Б V2b
  («flash подтверждён, served не изменился») — артефакт границы
  измерения «без активации» (stale-кэш FW от хост-бута), не свойство
  источника: после каждой активации served == R-части flash-окна + END
  (ресинк; c1:00, n=3 активации — task-04 ноги i/iii; R14 повторил).
- **Delivery map image-VPD (live non-secure FS3, c1:00, все ноги n=1):**
  plain `-y burn` — **preserve** (девайс-секции берутся с устройства);
  `--no_fw_ctrl` — **preserve** (первый датум: direct-путь без
  `--ignore_dev_data` тоже сохраняет девайс-секции);
  `-ocr --nofs --ignore_dev_data` (+WP-toggle top-зоны) — **image-wins**,
  единственный наблюдённый путь доставки image-VPD. GUID-ловушка
  `--ignore_dev_data` закрывается guides-вшивкой (Rule 3).
- Побочный датум: однократная доставка running FW 14.32.1900→14.32.1912
  при первом carrier-burn (нога-флип по записи не пинится — измерительный
  пробел; помечено интерференцией, task-04 Corrigendum).

### 8.4 Serving-гейт VPD = контент-классовый (V3b → R13; эрратум к §7.1/§7.2)

- V3b (минимальный блоб 48 Б: ID+V0+RV): served **пуст** на обеих CX-5
  после верифицированной FNP-доставки (41:00 secure n=1, 81:00
  non-secure n=1; task-07) — по наблюдению исход Б спеки.
- R13 (full-tag 204 Б, ACUT-класс, sanitize-маркеры): 41:00
  (secure, 16.35.8008) — served **233 Б** полного контента после
  FNP `set_vpd` + mstfwreset (n=1); 81:00 (non-secure, 16.35.4030) —
  «Not readable» после mstfwreset (транзиент, ниже), served **234 Б**
  после host-ребута (n=1; addendum). Ресериализация — та же механика,
  что на Dx (VU-инъекция/RV-пересчёт/END-рефрейминг; на 4030 —
  trailing-space-вариант unpad VU).
- **Вердикт: serving = content-class-dependent на ОБЕИХ картах**
  (минимальный профиль не сервируется; full-tag сервируется);
  **генерационная формулировка V3b-Б опровергнута**; security не
  блокер сервинга (контрпример secure-нога, n=1). VPD-плоскость
  (как кандидат-носитель) reopen. ACUT-контрфакт подтверждён: решает
  контент-класс, не поколение. Кандидат-механизм (гипотеза): serving-ветка
  FW активируется только на полном тег-профиле (VA-map needle-диспетчер /
  PN-SN-V3-парсер, ср. §7.1 CX-5 parse-кор).
- **4030-квирк «Not readable»** (cap экспонирован, данные не драйвятся,
  оба транспорта; карта полностью функциональна) — **активационный
  транзиент** (n=1): `mstfwreset -l 3` оставил VPD-плоскость
  недрайвенной (>45 с, персистентно в том PCI-цикле), host reboot
  очистил. Механизм открыт (гипотеза: PCI-reset-путь не переинициализирует
  VPD-serving-тень при непустом stored). Датум activation-modality:
  mstfwreset -l 3 vs host reboot (task-10 B-5 + addendum).

### 8.5 Ресериализация (V4a + R12; канонический факт терминала)

- **stored 384 Б ↔ served 407 Б одной платы (Dx 04:00, FW 22.50.1002):
  все контентные поля идентичны; ровно 3 форм-дельты** — VU-инъекция
  (served-only keyword, значение = SN-без-паддинга + «MLNXS0D0F0»),
  RV-пересчёт (обе формы валидны по конвенции sum-from-0x82),
  END-рефрейминг (хвост `91 c0 03` → `78`). Арифметика: 407−384 =
  +25(VU) −3(W-хвост) +1(END). Байт-идентичность «served = проекция
  flash» опровергнута (n=1 терминал; независимо CX-7 — §7.1 эрратум-
  дополнение п.1, n=1/2 функции). Served = FW-ресериализация stored.
- **Чистая функция (R12, n=1):** восстановленный stored (оригинальный
  блоб 384 Б, FNP `set_vpd`) → served **байт-идентичен** t0-снимку
  (md5 совпал) — VU/RV/END воспроизводимы той же FW. Механика на
  CX-5-классе гомологична (R13, обе карты).
- **+stored-VPD FW-state-инвариантен (FB→VDA)** — первое прямое чтение
  stored в VDA-состоянии == FB-ri сайдкару (task-09 B-1.3).
- **Served мутационно зависит от stored** (data-driven serving): recovery
  image-wins → stored size=0 → served пуст; R12 restore → served полный
  (n=1 цикл, task-09 C-2 + task-10 R12).

### 8.6 Boot-гейт DTOC/VPD-контента — content-semantic (V4b + R12; пара проб на одной плате)

- **V4b** (носитель D0-класса: vendor-VDA `.signed` + guides + VPD_R0
  384 Б с V0-дельтой 13 Б): доставка доказана побайтово (ri-окно ==
  носителю; GUID/MAC зоны карточные; полный дифф readback↔image —
  единственная free-зона) → **boot NO, подтип absent** (карта не
  энумерирована вовсе — строже life-fish 0212/0580 прецедентов этой
  платы; root-port скрыт BIOS). Физслой/ресейт исключён FNP-энумерацией
  с джампером (линк жив). Recovery-d0 ×5 (эталон воспроизведён
  бит-в-бит). Центральный data-vs-OTP на ступени напрямую не разрешён:
  MGIR-канал на v4b-состоянии неизмерим (no-boot).
- **R12** (та же механика доставки `set_vpd`, оригинальный контент
  384 Б, DTOC-мутация 0→0x180 относительно as-found size=0) → **boot
  OK**, served восстановлен байт-идентично t0.
- **Вердикт: бут-гейт content-semantic** — «any-DTOC-mutation gate»
  опровергнут (мутация DTOC той же механики при оригинальном контенте
  грузится); гейт коррелирует с СЕМАНТИКОЙ контента VPD-окна
  (vendor-консистентный OK / V0-модифицированный NO), n=1 per arm,
  на этой плате. Механизм открыт (кандидаты: контент-хэш-гейт /
  CRC-vs-expected / семантика V0-значения) — content-semantic проверка
  в конвейере data→runtime.

### 8.7 Secure-state representation и слой-вердикт (V3a + V4b/R12 — критерий V)

- **V3a (41:00, SS-burn ss-8008-v3a, n=1): исход А** — secured/
  signed_fw/lifecycle-поля инвариантны через полный burn-цикл с нашей
  подписью/вольтом → datapoint чип/OTP-источника. Caveat: ключ-ротация
  как таковая вне цикла (вольт md5 идентичен до/после; вендор→наш
  переход 2026-10-29 зафиксирован базлайном V1-A). Caveat-2
  (provenance-маркер, эрратум чтения): build-ID ss-8008-v3a, сожжённый
  на 41:00, содержит токен `rsa_sign` («…probe, rsa_sign, own slot0…»),
  тогда как фактический путь подписания — `sign` (rsa_sign на этой базе
  невозможен, §180-эрратум; слово в маркере осталось от брифа до
  выяснения) — будущие `dc`-чтения 41:00 покажут вводящий в заблуждение
  provenance-токен; истина задокументирована трижды в журнале task-05
  (Step 3 п.6, «Исследовано и исключено» п.1, сводка). Caveat-3 (класс
  подписи, канон-фикс 2026-11-23, коррекция владельца): SS-класс образа
  = собственный вольт (0xA4 slot0 `6ffe10ef…2559`, вольт md5
  `eda1bc3a…` бит-в-бит == 2026-10-29) + SignForFwUpdate-подпись НАШИМ
  ключом (0xA3: наш uuid, вендор-подписи замещены — live-readback
  2026-10-29 task-08 W3-4; 0xA0 = 320B нулей — SHA-512-ветка); diff =
  {0xA0, 0xA3, 0xA4, 0x30} — подписи вендора НЕ intact, и именно
  own-подпись + own-вольт резолвятся MCC burn-гейтом по бегущему вольту
  (170 §6 H1) → «FNP once → plain onwards». Прецедент-оговорка: этот
  цикл не цитировать как «vendor-sigs-intact» (термин D0/D2-класса —
  вендор-база без re-sign); `rsa_sign` — только full-package
  SignForSecureBoot на базах с 0xA6/A7 (класс-оговорка 180 §1 п.4).
- **Терминал (n=1 цикл VPD-мутации): MGIR/GA SECURED инвариантны** на
  всех измеримых состояниях (vendor «до» / d0-recovery «после» / R12
  restore) — data-мутации VPD-плоскости (DTOC+data) не двигают
  representation.
- **Критерий V (слой-вердикт): арка закрыта результатом без анлока.**
  В пределах классов доставки, проходящих boot-гейт, representation
  (MGIR/lifecycle/GA SECURED) инвариантен к контролируемым мутациям
  подвижных данных (V3a SS-burn n=1; R12 VPD-мутация на терминале
  n=1). VPD-контент-класс DTOC-дельты не проходит boot-гейт (§8.6 —
  сам по себе датум) — прямой «после»-измерение этого класса
  недостижимо, формальная дискриминация data-vs-OTP на нём невозможна.
  OTP-вердикт = позитивное доказательство в пределах измеренного;
  перенос на поколения не делается (n-маркировка всюду).

### 8.8 V5 (owner-skipped) и открытые вопросы

- **FB-runtime-MGIR — открытый вопрос канона:** V5 пропущен решением
  владельца (2026-11-23). Offline-сравнение (task-10 Step 1):
  security-пересечение стейтов по бумаге не различается (обе стороны
  secure), но lifecycle-ряд FB-сайдкаром не наблюдаем (FNP/direct-сессия
  захвата; HwDevId 0x212) — runtime-наблюдения FB-стейта в корпусе нет.
- Прочие открытые: механизм content-semantic boot-гейта (§8.6);
  механизм 4030-активационного транзиента (§8.4); FW-ветка
  serving-диспетчера контент-класса (§8.4, кандидат-механизм).
  (WP-волатильность исключена из открытых — resolved-by-owner,
  §8.2.)

### 8.9 Диспозиция после цикла (identity-гигиена)

- c1:00 (CX-4Lx): восстановлен к стоку R14 — flash-окно и served
  побайтово == до-лестничным базлайнам; WP карты = `Disabled`
  (owner-managed, §8.2 — не заводской стейт).
- Терминал Dx 04:00: VPD-контент платы восстановлен (R12: stored
  оригинал 384 Б, served 407 Б байт-идентичен t0); GuidsNumber 4 в q —
  класс d0-носителя (описательное поле IMAGE_INFO, эффектов нет).
- 41:00/81:00: несут full-tag probe-контент (204 Б, sanitize-маркеры
  MLXINI-PROBE-SN-00 / 0123…CDEF; served 233/234 Б) — research-стейт,
  откат = set_vpd стокового блоба (для 41:00 — FNP-окном).
