# 055. FS5 и PLDM-упаковка

> Источник: статический разбор OSS mstflint (`refs/src/mstflint`, rev
> `a2b9858b`: `mlxfwops/lib/fw_ops.h`, `mlxfwops/lib/fs_pldm.h`,
> `pldm_utils/pldm_utils.h`, `pldm_utils/pldm_pkg.cpp`); эмпирика —
> `.pldm`-файлы CX-6Dx в `refs/fw/` (2026-09-06). Детекция формата —
> `005-detect.md`; карта чип→формат — `060-chip-map.md`.

## 1. FS5

- `IMG_VER_FS5 = 2` — тот же FS4-маг, версия 2 в version word
  (`fw_ops.h:543-544`).
- Обработчик — `FIT_PLDM`/`FS_PLDM_1_0` (`fw_ops.h:558`), `FIT_PLDM = 7`
  (`mlxfwops_com.h:658`).
- В наших материалах (`refs/fw/`) FS5-образов (version=2) **нет**;
  единственные PLDM — CX-6Dx (оба PSID), внутри, вероятно, FS4-образ.

## 2. PLDM-упаковка

- `.pldm` — **PLDM (DMTF) package**, обёртка над образом компонентов.
- Детекция — 16-байтовые identifiers (`pldm_utils.h:84-93`):
  - rev 1: `F0 18 87 8C CB 7D 49 43 98 00 A0 2F 05 9A CA 02`;
  - rev 3 (multi-component): `31 19 CE 2F E8 0A 4A 99 AF 6D 46 F8 B1 21 F6 BF`.
- Наши `.pldm` (CX-6Dx, оба PSID) = **rev 1** (xxd: первые 16 байт совпадают
  с identifier'ом rev 1); в теле видны строки метаданных `22.50.1002`,
  `rel-2…`.
- Контроль целостности пакета — `pldm_crc32` (`pldm_utils.h:101`).
- Парсинг/генерация: `pldmlib/` (`pldm_pkg_hdr.cpp`,
  `pldm_component_image.cpp`, `pldm_dev_id_record.cpp`); операции —
  `mlxfwops/lib/fs_pldm.h` (`FwType() = FIT_PLDM`, `GetComponentData(...)`),
  компоненты NIC_FW и пр. извлекает `pldmgen`/`pldmlib`
  (`pldm_pkg.cpp:138`).
