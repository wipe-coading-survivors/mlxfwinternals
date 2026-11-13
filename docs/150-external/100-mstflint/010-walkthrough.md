# 010. mstflint: карта исходников (где что лежит)

> Источник: обход чекаута `refs/src/mstflint@a2b9858b` (2026-11-07, журнал
> `docs/superpowers/journal/2026-11-07-restructure-external-task-01.md`);
> перенос 30 §1. Назначение — навигация по чужому репо: пути и имена
> структур; факты форматов/подписи — в 250-re, здесь не дублируются.
> Pinned rev и вендор-патчи — `../000-pinned-revs.md`.
>
> Связи: OSS vs MFT — `020-oss-vs-mft.md`; детекция форматов —
> `docs/250-re/100-formats/005-detect.md`; FS3/FS4 бут/ITOC — `…/015-fs3.md`,
> `…/020-fs3-sections.md`, `…/030-fs4.md`; CRC — `…/025-crc.md`; подпись —
> `docs/250-re/110-signing/005-mechanism.md`; ini-секция 0x30 /
> `FwGetSection` — `docs/550-poc/100-mlxfwutil/010-ini-mapping.md`.

Роль в проекте: **референс, не зависимость** — в `mlxini` mstflint не
используется как зависимость, только как референс структур
(`tools_layouts/*.h`) и поведения; тул читает/пишет raw-байты напрямую.

## Карта (refs/src/mstflint@a2b9858b)

### `tools_layouts/` — layout-заголовки структур образов

- `image_layout_layouts.{c,h}` — FS3/FS4: hw-указатели
  (`image_layout_hw_pointer_entry` :382; boot_record/boot2/toc/tools/
  auth-start/auth-end/digest :598-622), бут-заголовок,
  `image_layout_itoc_entry` :862; к каждому типу —
  `…_pack/_unpack/_print/_dump` API (:1325+).
- `fs5_image_layout_layouts.{c,h}` — FS5.
- `cibfw_layouts.{c,h}`, `cx4fw_layouts.{c,h}`, `cx6fw_layouts.{c,h}` —
  per-чип образ-инфо/капабилити.
- Прочее: `cables_layouts`, `icmd_layouts`, `icmd_hca_layouts`,
  `reg_access_hca_layouts`, `mlxarchive_layouts`, `image_info_layouts`.

### `mlxfwops/lib/` — операции над образом (по поколениям)

- `fs2_ops / fs3_ops / fs4_ops / fs5_ops / fs_pldm` — парсинг/запись per
  формат (диспетчеризация — `mlxfwops.cpp`, `fw_ops.{h,cpp}`:
  `FwOperations::FwBurn/FwBurnAdvanced` :200-203, 206-208).
- `fsctrl_ops.cpp` — fw-control (MCC) путь — цель вендор-патчей
  -1.2/-1.3 (см. `../000-pinned-revs.md`).
- `signature_manager*`, `connectx6{,dx}_signature_manager*`,
  `bluefiled_signature_manager*`, `signature_manager_factory.h` —
  сигнатурные менеджеры.
- Прочее: `psid_utils`, `aux_tlv_ops`, `security_version_gw`,
  `flint_base/flint_io`, `fs_checks`.

### Смежные подсистемы

- `mlxsign_lib/` — RSA/SHA-примитивы (OpenSSL, PEM).
- `flint/` — CLI flint: `flint.cpp`, `flint_params`, `subcommands*`
  (в т.ч. burn), `cmd_line_parser`.
- `fw_comps_mgr/` — обновление компонентов через MCC
  (`fw_comps_mgr_{abstract,direct,dma}_access.*`).
- `mtcr_ul/`, `mtcr_py/`, `mtcr_freebsd/` — транспорт mtcr (доступ к
  регистрам карты); `mflash/` — прямой доступ к flash; `cmdif/` —
  icmd/tools CIF.
- Периферия: `libmfa/` (MFA-архивы), `cable_access/`, `pldm{gen,lib,_utils}/`,
  `adb_parser/`, `ext_libs/` (сторонние: iniParser/json/minixz/mini-yaml/
  muparser/sole/sqlite), `small_utils/` (mcra/mread/mwrite/mstfwreset/…),
  `mlxconfig/`, `mlxlink/`, `mlxreg/`, `mstdump/`, `resourcetools/`,
  `mlxfwupdate/`, `dev_mgt/`, `mlxdpa/`, `mlxtokengenerator/`, `tracers/`.

## Приложение: сводка расхождений сторонних тулов vs mstflint (из 30 §7)

Сверка перед портированием парсеров: irisc/py-скрипты против mstflint
(истина). Детали — по ссылкам «Связи» выше.

| # | Что | irisc / py-скрипты | mstflint (истина) | Решение |
|---|---|---|---|---|
| 1 | ITOC-локация | хардкод `0x5000` | из hwpointers (`toc.ptr+0x20`) | **hwpointers** |
| 2 | `size` записи ITOC | 24 бита | 22 бита | **22** |
| 3 | `flash_addr` записи | 32 бита (без маски) | 29 бит (маска `0x7f` bit160) | **29 + маска** |
| 4 | CRC записи | `calc_crc16(0, [0..0x1e])` | init `0xffff`, 30 байт | совпадает (OK) |
| 5 | формат | только FS4 | FS2/3/4/5 | **все** |
