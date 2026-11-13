# 065. secure-fw — бит регистра MGIR (состояние живой карты)

> Источник: из 90 §2 (дополнительное независимое исследование, 2026-09-06);
> статический разбор OSS mstflint `refs/src/mstflint@a2b9858b`:
> `fw_comps_mgr/fw_comps_mgr.cpp:2028-2043` (маппинг MGIR → query),
> `flint/subcommands.cpp:4515` (вывод атрибута),
> `mlxfwops/lib/fw_ops.cpp:2981/:3031` (`getLifeCycle`); перепроверено по
> чекауту 2026-11-07.
> Связи: root-of-trust и вердикты по платформам → `030-root-of-trust.md`
> (§1, §3); флаги security-режима ОБРАЗА (IMAGE_INFO) → `015-key-sections.md`
> §4; NV-плоскость lifecycle-ключей и live-нюанс CX-5 → `060-nvconfig-securefw.md`
> (§3); чтение MGIR через iRISC/mlx5cmd → `docs/850-howto/130-rom-dump.md`;
> SB-формулы → `025-secure-boot.md`.

TL;DR (из 90 §0.2): `secure-fw` в выводе `mstflint q` — не свойство образа и
не «замок», а бит `mgir.fw_info.secured`: состояние **живой карты**,
считываемое read-only через `access_register(MGIR)`.

## 1. Маппинг MGIR → `q` (mstflint)

`FwCompsMgr::Query` (`fw_comps_mgr.cpp:2028-2043`, после `getGI(MGIR)`):

```c
memcpy(query->psid, mgir.fw_info.psid, PSID_LEN);
query->security_type.secure_fw  = mgir.fw_info.secured;
query->security_type.signed_fw  = mgir.fw_info.signed_fw;
query->security_type.debug_fw   = mgir.fw_info.debug;
query->security_type.dev_fw     = mgir.fw_info.dev;
query->life_cycle.value         = mgir.fw_info.life_cycle
                                  | (mgir.fw_info.life_cycle_msb << 2);
query->sec_boot                 = mgir.fw_info.sec_boot;
query->encryption               = mgir.fw_info.encryption;
```

Вывод атрибута — `flint/subcommands.cpp:4515` (`printSecurityAttrInfo`:
бит `SMM_SECURE_FW` → строка `secure-fw`).

Соседние поля того же регистра дают полную security-картину карты:
`signed_fw`, `debug`, `dev`, `life_cycle(+msb)`, `sec_boot`, `encryption`.

## 2. Следствие: read-only чтение security-состояния

Secure/lifecycle-состояние живой карты читается **read-only через
`access_register(MGIR)`** (iRISC-путь mlx5cmd — `docs/850-howto/130-rom-dump.md`),
не трогая флеш. Это снимает часть инференса `030-root-of-trust.md` (§1:
что проверяет карта — определяется устройством, а не образом).

Live-нюанс CX-5 (`060-nvconfig-securefw.md` §3): в `mstflint q` на CX-5
16.35 полей Life cycle/SB Capable нет вовсе — практическая доступность
MGIR-плоскости из `q` ограничена; канал — access_register.

## 3. `getLifeCycle` (CR-space): кейса CX-5 нет

CR-space-путь `CRSpaceRegisters::getLifeCycle()` (`fw_ops.cpp:2981`) —
switch по чипу:

```
CT_CONNECTX6                          → 0xf0060
CT_BLUEFIELD2 / CONNECTX6DX / 6LX     → 0xf0068
CT_CONNECTX7 / QUANTUM2 / BF3 / S4/S5 → 0xf0000
CT_CONNECTX8/9/…                      → 0xf0000
default → throw "life_cycle query is not implemented for the current device"
```

CR-space-адрес lifecycle **для CX-5 неизвестен** (кейса нет). Поэтому для
CX-5 единственный read-only способ снять lifecycle — `MGIR.fw_info.life_cycle`
(§1), а не CR-регистр (как `0xf0060` на CX-6).

## Постулаты / открытое

- [постулат] `MGIR.fw_info.*` может отражать и *отражённый из образа* флаг,
  и *состояние чипа* — не разрешено; где ROM берёт решение — покажет дамп
  mask ROM (`docs/850-howto/130-rom-dump.md`, чек-лист §9).
