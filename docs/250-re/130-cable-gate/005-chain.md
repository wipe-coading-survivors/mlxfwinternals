# 005. Cable-speed gate: цепочка end-to-end (симптом → PDDR → хост)

> Источник: из 95 §2 (фаза A проекта «IB cable-speed gate», 2026-09-16/17:
> оффлайн-RE 8008 + live-разведка; главы 1–2 арки «Трансиверы под IB»,
> 2026-10-04..07). Журналы:
> `docs/superpowers/journal/2026-09-16-ib-cable-gate-patch-task-03.md`
> (локализация), `…-ib-cable-gate-re2.md` (зона/PDDR),
> `2026-10-04-transceiver-ib-bit-live.md` (сессии 4–5),
> `2026-10-07-transceiver-ib-ch1-dac-optics-task-{04r,05r,06r}.md` (гл. 1),
> `2026-10-06-qsfp28-edr-diag.md` + `…-task-01..03.md` (гл. 2),
> `2026-10-07-qsfp-ib-dac-dump.md`.
> Связи: карта гейта 4030 + патчи C4/C6/C7/C8/C12 → `002-transceiver-ib-gate.md`;
> EEPROM-форматы и теорема SFP28 → `../100-formats/070-transceiver-eeprom.md`;
> стена фазы A (почему оффлайн-RE 8008 остановился) → `010-wall.md`;
> итоги главы 3 и ретест 8008 → `025-ch3-results.md`; биты eth_speeds в
> FW_MAIN_CFG → `015-speed-bits.md`; программирование модулей →
> `docs/850-howto/110-transceiver-programming.md`.

TL;DR (из 95 §0.1): цепочка симптома end-to-end закрыта — 4 строки гейта в
MAIN_CODE (CS «Cable speed not enabled», iRISC-abs 0x3DA6F4) + PDDR-механизм;
live (root-mellanox, порт 1) `monitor_opcode=26` + `status_message` побайтово
идентичны `.bin @ 0x3DA6F4`, `cable_link_speed_cap=0x0`: FW **копирует строку
из этого образа** в PDDR → RE-объект = живой образ подтверждён.

## 0. Постановка и исчерпанные внешние обходы (из 95 §1)

- Цель проекта: снять FW-гейт «Cable speed not enabled» (PDDR opcode 26,
  `Supported Cable Speed 0x00000000`) для 25G EN-модулей на SFP28 IB-портах;
  итог — IB-линк c1:00.1 (CX-4Lx) ↔ 01:00.1 (CX-5, `CARD_CX5_25G`).
- RE-объект (первичный): CX-5 8008
  `refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX512A-ACA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin`
  — base as-found VPI-образа 01:00.x (as-found = VPI-patched iD, `010-wall.md`
  §10); live-валидация патча — на том же реверсированном образе (исключение
  конфаунда «неправильно расковыряли vs неправильно перенесли», решение
  владельца 2026-09-16).
- Симптом (до-факт, журнал `2026-09-15-cx4lx-ib`): все 7+ EN-кабелей/оптики
  SFP28-25G → PDDR opcode 26, speed 0x00; прошёл только QSFP28 SR4
  (SDR-рейтинг).
- **Внешние обходы исчерпаны**: PMMP-override отключён в 14.32.1900 и
  16.35.8008 (любые SET, включая no-op, отклоняются: `ICMD error 0x3,
  syndrome 0x89415F`); PHY/EXT loopback — нет; PAOS-тогл — нет.

## 1. Оффлайн (8008, MAIN_CODE 0x03)

Схема: **решение PHY-домена** (compliance-mismatch → speed-bitmap 0x00,
opcode 26) → **PDDR-хендлер** копирует строку результата в
`status_message[59]` (troubleshooting page, байт 0xc) + пишет
`monitor_opcode` (байт 0x0) → **хост** читает PDDR (ACCESS_REG_PDDR) →
`mstlink -m` рендерит «Cable speed not enabled».

**4 строки гейта** — 4 взаимоисключающих результата cable-диагностики. Пул
`0x3b0000..0x3c0000` (sect-rel); iRISC-abs = sect-rel + 0x1c748 (фаза A;
ретест 2026-10-15 переоткрыл адресацию — `025-ch3-results.md` §7):

| строка | sect-rel | iRISC-abs | текст |
|---|---|---|---|
| HighBER | 0x3bdeed | 0x3DA635 | «High BER detected on module that requires a change on its default operational rate…» |
| FDR10 | 0x3bdf74 | 0x3DA6BC | «FDR10 speed is not supported on non-Mellanox cable.» |
| **CS** | 0x3bdfac | **0x3DA6F4** | «Cable speed not enabled» |
| NoIssue | 0x3bdfc4 | 0x3DA70C | «No issue was observed.» |

Второй вариант «No issue was observed» (без точки) — iRISC-abs 0x39B552
(sect 0x37ee0a). Побайтовая форма CS-строки (live == .bin @0x3DA6F4) — **без
точки** (расхождение цитат в журналах re2/task-03 разрешено при консолидации
в пользу побайтовой).

- **Зона гейта** (по лог-строкам «function_name: message»): `ib_speed_nego_fsm`
  (0x3b2718, 0x3bde29, 0x3b985a…), `ib_speed_nego` (0x3bde90, 0x3bdeb1…),
  `speed_and_width` (0x3b57f7, 0x3b757b…), `module_management_init_sm` /
  `cable_module_read_write` (чтение EEPROM: 0x3b7869, 0x3b7928, 0x3be28d…).
  Поле PDDR «Supported Cable Speed» = **speed_enabled.ib**.
- **PDDR-механизм-строки:** `vs_diagnostic_page_num_to_pddr_page_select`
  @0x3b2d3a, `set_get_port_info` @0x3b2d6a, `g_pddr_page_size_in_bytes`
  @0x396bd6.
- **Родственные строки:** 0x3b4e9f «cable does not support any Infiniband
  speeds», 0x3b5830 «speed_enabled.ib=0x%x, width_enabled=0x%x», 0x3b57f7
  «speed_and_width (PTYS)», 0x3b7810 «Module memory invalid».
- **Лог-каталог** (записи `0x0094|lo16`, lo16→пул 0x3b0000):
  0x3c6044..0x3c6534; FDR10 — **index 162** @ 0x3c63f8 (слово 0x0094df74);
  CS/HighBER/NoIssue — вне каталога. (Ретест 2026-10-15 закрыл «каталог»
  как артефакт декода — `025-ch3-results.md` §7.)
- **words16-сайты** (локализация; метод over-matches): data-рефы 0x22b8dc
  (0x0000deed), 0x708dc (0x94ffdfac), 0x1d28f8 (0x0004dfac), 0x3c63f8
  (0x0094df74); ложные: 0x120518 (NOP `addi r0,r0,0xdfc4`), 0xad980
  (`call 0x25750`, lo16=REL24). `ld.b`-иммедиатов на строки — 0.

## 2. mstflint-исходники (refs/src/mstflint)

- **PDDR operation_info** `.cable_link_speed_cap` @ **байт 0x10** — **RO**
  (заполняет PHY/hardware, не MAIN_CODE), битмап «Cable support IB speed»
  (SDR/DDR/QDR/FDR10/FDR/EDR/HDR/NDR/XDR), **рендер хоста** (не чип).
- **PDDR troubleshooting** `.monitor_opcode` @ байт 0x0 + `.status_message[59]`
  @ байт 0xc — **RO, null-terminated ASCII, возвращаемый ЧИПОМ**
  (`troubInfoPage()` в `mlxlink_commander.cpp` читает DWORD-ами; строки
  «…not enabled» в mstflint-исходниках **НЕТ** — текст приходит от чипа).
- **opcode 26** по layout-описанию = «**Cable compliance code mismatch
  (protocol mismatch between cable and port)**», диапазон PHY FW 0–1023.
- **`.adb`** (`register_access_table`) = register-layout DB + mstconfig attr
  DB — **НЕ источник** Recommendation (Recommendation = `status_message` от
  чипа).

## 3. Live (root-mellanox, порт 1, local_port=1; 2026-09-16)

- `mstreg -a <adb> PDDR` (mstflint 4.36.0):
  - page_select=1 (troubleshooting): **monitor_opcode=0x1a (26)**,
    **status_message="Cable speed not enabled\0"**.
  - page_select=0 (operation_info): **cable_link_speed_cap=0x00000000**,
    phy_manager_link_proto_enabled=0x3f, neg_mode_active=4, proto_active=1,
    ib_phy_fsm_state=0, link_speed_active=0.
- **End-to-end (закрыто):** live `status_message` == `.bin` строка @ fileoff
  **0x3DA6F4** — **побайтово идентична**. Симптом: `speed_cap=0` → «Cable
  speed not enabled». FW копирует строку из этого образа в PDDR.

## 4. Live 2026-10-04..07 (сессии 4–5, глава 1 арки)

- **Сессия 4 (факт, журнал `2026-10-04-transceiver-ib-bit-live.md`):**
  перекодированный пассивный DAC (SFP28, IB-бит **A0h byte 3 = 0x01**
  «1X Copper Passive» доходит до обеих карт — SN/PN/OUI читаются верно и
  напрямую, и через QSA-переходник) на IB-портах **c1:00.1** (CX-4Lx
  14.32.1900) и **41:00.1** (CX-5 16.35.4030, `CARD_HPE_CX516A`):
  Supported Cable Speed **по-прежнему 0x0**, opcode **26** на обоих.
  Скоростные поля модуля: byte 12 = 0xff «смотри ext BR» + **ext BR
  (A2h 222–223) = 0** → «Nominal bit rate 0.000Gb/s». Вывод: **IB-бит в
  byte 3 — необходим, но недостаточен**: без определённого BR FW не строит
  speed bitmap. (Это же объясняет до-факт §0: EN SFP28 с корректным BR
  25G → 0x0 — 25G EN не маппится на SDR..EDR.)
- **Сессия 5:** запись ext BR в A2h in-band невозможна — `mstlink --cable
  --page 1` на этих FW алиасится в **A0h** (верифицировано записью-пробой с
  восстановлением; `docs/850-howto/110-transceiver-programming.md` §6).
  Патч перенесён в A0h[12] (BR nominal 0xff→0x64 = 10.0 Gb/s, QDR; CC_BASE
  пересчитан) на обоих концах; **переоценка гейта не состоялась — FW
  кеширует module info с plug-события** (opcode 26 / 0x0 держались 60+ с
  после записи; нужен re-plug).
- **Глава 1 (2026-10-07, программатор; гипотеза ext BR — REFUTED с
  контролями).** Журналы
  `2026-10-07-transceiver-ib-ch1-dac-optics-task-{04r,05r,06r}.md`.
  Write-путь программатора починен и доказан
  (`docs/850-howto/110-transceiver-programming.md` §7.2), ext BR QDR
  (100×0.1 Gb/s) записан в A2h и верифицирован read-back'ом во всех
  тестируемых конфигурациях — гейт c1:00.1 (та же FW 14.32.1900, IB, ELS
  0x1f; baseline сессии 6: SCS 0x0 / opcode 26 / Nominal 0.000) **не
  сдвинулся ни на одной ветке**:
  - DAC CU1M (byte 12=0x64): ext BR **BE** (222=00/223=64) — все
    поля == baseline; **LE** (222=64/223=00, оба конца) — то же. Для
    byte12=0x64 FW не строит bitmap из A2h ext BR ни в одном порядке.
  - Оптика A0005 (byte 12=0xff — входное условие «смотри A2h»; A2h
    разблокирован FF×8 и перекодирован BE): Nominal 0.000→26.000, но
    нетронутый сиблинг **A0006 даёт те же 26.000** → это классификация
    SFP28-оптики (25.78G→26.0), не эффект записи; SCS 0x0 / opcode 26 не
    двинулись. Дополнительно A0h byte 3=0x08 (IB 1x-QDR compliance,
    «google-рецепт») + CC_BASE 0x7c — ничего.
  - 10G-зонды (поиск positive control): genuine Intel FTLX8571D3BCV-IT,
    ONTi→OEM SFP-10G-SR, 10Gtek-корпус→**genuine Mellanox MMA2P00-AS
    (25G)** — все SCS 0x0 / opcode 26 на IB-порту (Nominal
    0.000/0.000/25.750 — из EEPROM модуля, с гейтом не коррелирует).

**Позитивные контроли** (тот же sweep):

| Порт | Карта / FW / режим | Модуль | Supported Cable Speed | Opcode |
|---|---|---|---|---|
| c1:00.0 | CX-4Lx 14.32.1900 **Eth** | OEM SFP-25G-SR (A0004) | **0x20002001 (25G,10G,1G)**, Active 25G | 0 |
| 41:00.1 | CX-5 16.35.4030 **IB** | genuine Mellanox **670759-B22** (IB FDR Cu DAC) | **0x1f (FDR..SDR)** | 0 |
| bazzite 03:00.0 | CX-4Lx 14.32.1912 **IB** (QSFP28) | 670759-B22 (owner-swap) | **0x1f (FDR..SDR)** | 0 |

→ та же FW 14.32.1900 на **Eth-порту** строит богатый bitmap из той же
OEM-оптики; **IB-порт** (CX-5) строит 0x1f из genuine IB DAC — «SCS только
для Cu DAC» опровергнуто в сильной форме. **Механизм-кандидат: IB-режим
SFP28-гейта CX-4Lx отвергает ВСЕ протестированные SFP28-модули, включая
genuine Mellanox-оптику** — ключ не A0h byte 3 и не A2h ext BR; похоже на
проверку genuineness/IB-signaling модуля + режим порта (Eth-комплаенс не
маппится на IB-маску ELS 0x1f → opcode 26). Точка входа — гл. 3 арки (RE
гейт-функции, спека
`docs/superpowers/specs/2026-10-04-transceiver-ib-arc-design.md`); решающий
live-тест 670759-B22 → c1:00.1 — **физически невозможен** (670759-B22 =
QSFP+, c1:00.1 = SFP28-клетка).

Примечания: (а) на bazzite 03:00.0 Active QDR 4X (QDR-свитч) давал QDR AOC
с SCS 0x0f; сам 670759-B22 на том же порту — SCS 0x1f / opcode 0 (гейт
открыт; журнал `2026-10-07-cx4lx-56-100g-task-04d.md`). (б) Cap порта
(владелец, параллельная сессия cx4lx): на кристалле CX-4Lx — **4 пары
TX/RX**; достижимые линк-режимы QSFP28 — **QDR (IB, 4×10G), 40GbE (4×10G),
50GbE (2×25G)**; недостижимые — FDR (4×14G), EDR/100GbE (4×25G), 56G (25G
на >2 ланях кристалл не держит). Bitmap может показывать 0x1f, но
фактический линк ограничен этими режимами; FDR-кабель остаётся Polling.

## 5. Live QSFP28 (2026-10-06, глава 2 арки — baseline)

- Baseline 41:00.1 (`CARD_HPE_CX516A`, 16.35.4030, QSFP28 DAC OEM
  QSFP-100G-CU1M SN QSFP100G-A, линк IB-QDR 4x): Supported Cable Speed =
  **0x0f** (FDR10/QDR/DDR/SDR), Status Opcode = **25** («Cable speed not
  enabled» — соседний код opcode 26 той же группы PHY FW, но на QSFP28/FW
  4030 — именно 25). Косвенно: bitmap строится из **byte 164** (IB bitmap,
  ADB register_access_table) при ext BR = 0 — в отличие от SFP28-кейса §4,
  где без BR bitmap не строился.
- Попытка верифицировать записью (byte 164 0x07→0x27 + CC_BASE Σ(128..190))
  **упёрлась в vendor WP**: оба живых OEM DAC (QSFP100G-A, QSFP100G-B)
  молча игнорируют запись всего A0h, включая password-entry area (STH-пароли
  неприменимы физически; `docs/850-howto/110-transceiver-programming.md`
  §7.1). Прямое соответствие byte 164 → bitmap осталось непроверенным
  (гл. 2); мёртвый сиблинг — аналоговая смерть при живом EEPROM.
- **Обновление 2026-10-07 (дамп 670759-B22, глава-1-хвост):** корреляционное
  подтверждение **164→SCS 3/3** — genuine 670759-B22 (дамп
  `build/qsfp-670759-page0.bin`, журнал `2026-10-07-qsfp-ib-dac-dump.md`):
  byte 164 = **0x0f** (SDR+DDR+QDR+FDR), OUI 00:02:C9, BR 0x8d/линия — и его
  SCS 0x1f на CX-5/CX-4Lx QSFP28 IB (единственный opcode 0); OEM CU1M
  164=0x07 (без FDR) → SCS 0x0f (без FDR); мёртвый сиблинг — аналогично.
  Битовая карта консистентна попарно (10G-класс: QDR↔QDR|FDR10). Каузальный
  A/B (запись byte 164 в OEM DAC) — закрыт гл. 3 (`002-transceiver-ib-gate.md`
  §2, `../100-formats/070-transceiver-eeprom.md` §2). Верхние страницы
  670759-B22 недоступны (0x51 NAK, page-select игнорируется) — low-page-only
  дамп.
