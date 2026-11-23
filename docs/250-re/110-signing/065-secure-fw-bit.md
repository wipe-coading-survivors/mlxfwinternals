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
- [постулат — **сужен** прямыми read-only уликами (арка C roadmap 200,
  2026-11-21; live-матрица `superpowers/journal/
  2026-11-21-securefw-arc-c-task-06.md`, канон — `070-vpd-secure-state.md`
  §7.3)] Ядро постулата (отражённый из образа флаг vs состояние чипа)
  остаётся открытым; сужение:
  1. **cfg-space VPD-плоскость исключена как коррелят/маркер
     secure-state**: таблица 2×2 «security × cfg-VPD-читаемость» заполнена
     всеми четырьмя клетками — secure×читаемый (CX-6 Dx, 406 Б, n=1),
     secure×пустой (CX-5 HPE, 0 Б, n=1), non-secure×читаемый (CX-4/4Lx,
     n=2), non-secure×пустой (CX-5, n=3). Пустота cfg-VPD в той матрице —
     свойство stored-контента (data-driven serving: пусто при
     пустом/minimal flash-VPD_R0 — в т.ч. после `--nofs
     --ignore_dev_data`-прошивок VPD-less-образов, size=0), не поколения
     и не security-состояния. (Канон-правка 2026-11-23: стоявшая здесь
     атрибуция «свойство поколения (CX-5/5Ex, n=4)» опровергнута R13 —
     full-tag 204 Б сервируется живыми CX-5 8008 (233 Б, n=1) и CX-5Ex
     4030 (234 Б после host-ребута, n=1), минимальный 48-Б блоб — пусто
     у обеих (n=2); канон — 070 §8.4, журнал
     `superpowers/journal/2026-11-22-securefw-arc-c-unlock-task-10.md`
     R13+addendum.)
  2. **q-плоскость MGIR-lifecycle поколенчески гейтирована, не
     security-гейтирована**: на CX-5 (n=4, вкл. secure) строк Life
     Cycle/SB Capable в `q full` нет вовсе; на CX-6 Dx (n=1) — полный ряд.
     Канал lifecycle на CX-5 доступен read-only `mstreg --reg_name MGIR
     -g` (проба n=2, вкл. secure 41:00: биты secured/signed_fw побитово
     согласуются с `q`; lifecycle-подполя читаются нулями на обеих —
     GA-кодировка или непопуляция, семантика не декодирована).
  3. Кандидат арки C «runtime-источник `MGIR.secured` = VPD/dev-data»:
     cfg-space VPD-плоскость как носитель исключена (п.1); разрешение
     ядра — эксперимент спеки анлока `superpowers/specs/
     2026-11-21-securefw-arc-c-unlock-design.md` (MGIR до/после +
     DTOC-дельта; owner-gated, исполнение вне арки).
- [постулат — **сужен исполнением спеки анлока** (цикл
  securefw-arc-c-unlock, 2026-11-22..23; канон — `070-vpd-secure-state.md`
  §8.7, журналы `superpowers/journal/
  2026-11-22-securefw-arc-c-unlock-task-01..10.md`)] Ядро остаётся
  **открытым с уточнёнными границами** — позитивное доказательство
  OTP/чип-источника в пределах измеренного:
  1. **В пределах классов доставки, проходящих boot-гейт, representation
     (`MGIR.secured`/lifecycle/GA SECURED) инвариантен к контролируемым
     мутациям подвижных данных:** смена образа+подписи+вольта на secure
     CX-5 41:00 (V3a, SS-burn, n=1); VPD-мутация DTOC+data на терминале
     Dx GA SECURED (R12: FNP `set_vpd`, boot OK, MGIR/GA SECURED
     побитово == «до», n=1).
  2. **Контент-класс VPD-дельты (V0-модифицированный), бывший
     кандидатом data-носителя, не проходит boot-гейт** — content-semantic
     проверка в конвейере data→runtime (V4b исход В + R12-контроль,
     n=1 per arm, механизм открыт; «any-DTOC-mutation» опровергнут):
     прямой «после»-измерение MGIR на этом классе недостижимо, формальная
     дискриминация data-vs-OTP на нём невозможна.
  3. Границы открытости: FB-runtime-MGIR (V5) не измерен — skipped
     владельцем (open); перенос на поколения не делается (n-маркировка
     всюду).
