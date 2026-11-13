# 110. Переработка фазы Dell-база (лестница E0–E5 + A/B-расследование)

Дата: 2026-09-09. Спека: `docs/superpowers/specs/2026-09-09-dell-base-rework-design.md`.
План: `docs/superpowers/plans/2026-09-09-dell-base-rework.md`.

Источники A/B-офлайн-части (§A/B.1–4): `refs/src/mstflint` rev `a2b9858b`
(все file:line сверены с этим чекаутом) + референс-дампы `refs/fw/cx-5-6/dumps/`
(T3) + `build/dell_s1_newprio.bin` (md5 `61dfbd39fb7eb70809bfbb51bf627e57`).

## 0. Выводы

(Заполнено 2026-09-10, закрытие Task 16 плана dell-base-rework — сделано в
рамках другой задачи: фаза EDA → IB-узел, глава 1, `docs/750-exp/120-eda-ib-node` §1.)

1. **Лестница (что бутнуло):** E0 (1012-ADA) — PASS, 25G. E1 — SKIPPED
   (owner): mixed-CODE-образ (база 1012-ADA + код/ROM 8008-ACA, секции
   0x02–0x07) MCC (running FW) **отклоняет** digest-reject — не может иметь
   валидную подпись; отклонённый burn всё же записал ~4.3MiB в целевой слот A
   до MCC-проверки (A/B.1). E2 (8008-512F) — BOOT PASS / LINK DOWN (образ
   1G-KX, не 25G). E3-V1..V4 (8008-512A) — все 4 PASS, 25G: mixed-ROM (V3/V4)
   **прошиваются** — ~~MCC-проверка подписи не покрывает ROM 0x18 (в отличие
   от mixed-CODE E1); ROM сменяем, код — нет.~~ **ОПРОВЕРГНУТО (2026-10-28,
   цикл burn-digest):** E3-V3/V4 шли `plain + -apc` → `_mccSupported=false`
   (flint/subcommands.cpp:2590-2594) → прямой flash-путь, digest-гейт FW
   вообще не выполнялся. Гейт = безусловный content-digest всего образа
   (секционной дискриминации «код/ROM» нет); «дискриминация» — артефакт
   смешения путей: E1 шёл plain без `-apc` (совпадающий PSID → MCC → гейт),
   V3/V4 — кросс-PSID с `-apc` (direct). Реаттрибуция:
   `docs/superpowers/reports/2026-10-28-burn-digest-gate-results.md` §4.
   E4 (база 1012 + код/ROM 1012-EDA) —
   PASS, побайто == 1012-ADA: «код+ROM EDA ≡ ADA» (1012) верен. E5 (E4 +
   PSID 0009 + 4 IB-поля + swap 0x30) — **PASS** (первая попытка упала по
   конфликту с параллельной `mstflint rb` владельца; retry — OK, на уровне
   образа повторных итераций не потребовалось): 16.35.1012 /
   **MT_0000000009** / class **[0207] InfiniBand** / PCIe 16GT/s x8; IB-порт
   DOWN — физическое подключение было 25G Ethernet-свитч (не IB-фабрика)
   (§2, E5-prep).
2. **Root-cause no-boot S1:** не «stale boot-addr» и не интерлив — слот B S1
   был записан **неполным** (truncation @0x430000, целый ряд ITOC-секций
   потерян, §A/B.4), а ROM **отклоняет неполный слот** даже при целом magic
   (проверяет целостность образа, §A/B.5). boot-addr — не байт флеша, а
   cr-space-регистр 0xf00c0 (§A/B.3); в failsafe/FNP-пути не пишется вовсе.
   Триггер потери записи при burn — **открыто**: нужна точная burn-команда
   c178 (`--no-flash-verify`?), контролируемый re-burn с включённым verify,
   источник FNP-ROM (§A/B.4 «что нужно для решения»).
3. **A/B-модель:** «chunk-interleaved 128K» (docs/750-exp/100-dell-base-vpi-build §2.4) — **ошибка**;
   корректно — два **контигуальных 8MiB-слота, побайто 1:1** (`0x17` = hex
   23 → чанк 2^23 = 8MiB, §A/B.2). docs/750-exp/100-dell-base-vpi-build §2.4 исправлено отдельным коммитом.
4. **ROM-fallback (§A/B.5):** ROM **сканирует оба слота** и бута из того, что
   валидно и ЦЕЛО (не фиксированный boot-addr); валидный magic — необходимое,
   но **не достаточное** условие. Прямой эксперимент (инвалидация
   не-ранящего слота → power cycle) — только владелец, рецепт в §A/B.5;
   не выполнялся.
5. **Recovery-рецепт (§A/B.6):** диагностика (`rb` + `mlxfwutil ab`) → valid+intact
   слот → power cycle; оба слота биты → full burn known-good c verify
   (default, **не** `--no-flash-verify`); точечный ремонт magic — last resort.
   Полевой вердикт T15: write-protect off → burn `-ocr -apc --nofs
   --ignore_dev_data` → verify → `sg` GUID/MAC → снять strap. mstflint 4.32.0
   крашится на FNP-burn, 4.34/4.36 OK.
6. **E5 — IB-поля работают:** точечные сеты (PSID 0009, 0x11+0x2b7/0x2bb=07,
   0x11+0x3c=0002, 0x12+0xf8=31, swap 0x30) — карта стала IB-адаптером
   (class 0207, VPI-идентичность). Линк-проблема E5 (порт DOWN/25G) — **не в
   свитче/кабеле**: дискриминатор ch1 (`docs/750-exp/120-eda-ib-node` §1.2, 2026-09-10) — вендорный
   4030-VPI зацепился за IB на той же фабрике Inviniscale-IV (оба порта
   Active) **до любых перешивов** ⇒ любой сбой IB дальше = вопрос образа
   (конфиг/PHY).
7. **Финальное состояние полигона:** 1012-ADA восстановлен (T15,
   2026-09-09/10): 01:00.0/1 = 15b3:1019, 16.35.1012 / MT_0000000361, [0200],
   port0 25G UP, исходные GUID/MAC — реестр `CARD_CX5_25G_GUID`/`_MAC`,
   `dc` clean (§T15).

## 1. Образы лестницы

| Образ | md5 | Состав | Ожидаемая идентичность (mstflint -i q) |
|---|---|---|---|
| V1 (E3) | `1ea11b892e5951b31f1c99897a05a5e0` | 8008-ADA дословно (vendor) | FS4, 16.35.8008 / rel-16_35_8008, PSID MT_0000000361 |
| V2 (E3) | `7dce14844bb0aad995f9c4379836e0b7` | 8008-ACA дословно (vendor) | FS4, 16.35.8008 / rel-16_35_8008, PSID MT_0000000080 |
| V3 (E3) | `16e099da35f41c37e01e18183256d7bf` | base ADA + 0x18 из ACA | FS4, 16.35.8008 / rel-16_35_8008, PSID MT_0000000361 |
| V4 (E3) | `4d6c96a3d61264ed52517e70e9497e7d` | base ACA + 0x18 из ADA | FS4, 16.35.8008 / rel-16_35_8008, PSID MT_0000000080 |
| E1 | `a1d0110b4a1f5430a08c354082053a6b` | base 1012-ADA + {0x02,0x03,0x04,0x05,0x06,0x07,0x18} из 8008-ACA | FS4, 16.35.1012 / rel-16_35_1012, PSID MT_0000000361, dev 0x1019 — mstflint q OK (reflow used (R5); all ITOC < 0x800000; ROM UEFI 14.29.15 / PXE 3.6.902) |
| E4 | `cd95e4febf6b8bbe6768c66665aab3e7` | base 1012-ADA + {0x02,0x03,0x04,0x05,0x06,0x07,0x18} из 1012-EDA | FS4, 16.35.1012 / rel-16_35_1012, PSID MT_0000000361, dev 0x1019 — mstflint q OK |
| E5 | `e5b03e52bf7f1cb5bac86814db096772` | E4 + PSID MT_0000000009 (`psid`) + 0x30 из 1012-EDA (`repack --swap`) + 4 поля T5 (0x11+0x3c=0002, 0x11+0x2b7=07, 0x11+0x2bb=07, 0x12+0xf8=31) | FS4, 16.35.1012 / rel-16_35_1012, PSID MT_0000000009 (Orig MT_0000000361), dev 0x1019 — mstflint q OK |

Все три: `mlxfwutil.py verify` → **RESULT: PASS** (ITOC 25 + DTOC 7, all CRC OK);
md5 server-копий (scp → root-mellanox:/var/roothome/) == локальным; dev/sub/ver
— локальная деривация 0x10 (dev [0x1c:0x1e] BE, sub [0x20:0x22], PSID
[0x24:+17], ver [0x1c0:]), совпадает с mstflint q (e4/e5/e1).

**Канарейки (T7, 2026-09-09):**
- **E4: СОВПАДАЕТ** — md5 == `cd95e4febf6b8bbe6768c66665aab3e7`, E4 побайто
  == 1012-ADA. Офлайн-факт «код+ROM EDA ≡ ADA» (1012) верен.
- **E5: СОВПАДАЕТ** — md5 == `e5b03e52bf7f1cb5bac86814db096772` (независимый
  dry-run T5, §E5-prep «Драйв-ран»).

**Дефект E1 (layout; РАЗРЕШЁН R5, 2026-09-09, task 7b).** Собранный
`build/e1.bin` mstflint не читает: `-E- Failed to query image … Section - read
error (Reading 0x6fc28 bytes from physical address 0x91f4d0 is out of image
limits (0x1000000 bytes))`. Механика (по `refs/src/mstflint` rev a2b9858b):
секции 8008-ACA больше слотов 1012-ADA (0x05 +0x190, 0x03 +0x5430, 0x02 +0x100,
0x07 +0x20, 0x18 +0xc00) → `swap_repack` кладёт overflow в хвостовой gap
(старт `max(addr+size)` = 0x507e8c, конец 0xeb базы) — gap **пересекает
0x800000**: 0x02 @0x8ef6d0, 0x07 @0x91d810, 0x18 @0x91f4d0. mstflint читает
ITOC-секции из файла с 8MiB-half-конвертером (log2=23 из tools_area;
`FsVerifyAux` `fs4_ops.cpp:942`; `FImage::read` `flint_io.cpp:245`,
`cont2phys` `flint_io.h:211`): cont [0x800000,0x1000000) → phys
[0x1000000,0x1800000) — за 16MiB. Burn-путь тот же: `FsBurnAux`
(`fs4_ops.cpp:2840`) до `BurnFs4Image` гоняет полный verify образа
(`FsIntQueryAux` → `FsVerifyAux`) ⇒ **e1.bin не прошиётся mstflint** (abort
до записи). Sanity-check `swap_repack` проверяет `gap+len ≤ min(DTOC addr)`
(0xf90000) и 0xFF-ость, но не границу 0x800000.
**Реализуемость состава доказана**: reflow-прототип (тот же состав; все
ITOC-секции переупакованы от 0x7000, ITOC переписан; throwaway
`/tmp/opencode/reflow_e1.py`, не в репо) — md5
`a1d0110b4a1f5430a08c354082053a6b`, verify PASS, mstflint q OK:
FS4, 16.35.1012 / rel-16_35_1012, PSID MT_0000000361, ROM UEFI 14.29.15 /
PXE 3.6.902 (из 0x18 ACA — как и положено лестнице).
**Разрешение (R5, task 7b):** выбран вариант (a) — reflow встроен в
`swap_repack` (mlxfwutil.py: `HALF = 0x800000`, `gap_end_eff = min(gap_end, HALF)`;
если gap-fill не влезает ниже 0x800000 — автоматический полный reflow всех
ITOC-секций от минимального адреса секции, DTOC на месте; helper `_reflow`).
E1 пересобран тем же инструментом: md5 `a1d0110b4a1f5430a08c354082053a6b`
(== прототип побайтово), все ITOC < 0x800000 (конец 0x50e150), verify PASS,
mstflint q OK (см. таблицу). Канарейки не тронуты: E4 md5
`cd95e4febf6b8bbe6768c66665aab3e7` и E5 md5 `e5b03e52bf7f1cb5bac86814db096772`
не изменились (gap-fill, reflow не срабатывает). TDD: 4 новых теста в
`tests/test_mlxfwutil.py` (reflow-тесты падали до фикса, все зелёные после).
Журналы: `docs/superpowers/journal/2026-09-09-plan-task-07.md`,
`docs/superpowers/journal/2026-09-09-plan-task-07b.md`.

## 2. Лестница (строка на шаг)

| Шаг | Образ (md5) | burn | Вердикт бута (lspci/q/LnkSta/линк) | Темп (до/после) | A/B до→после |
|---|---|---|---|---|---|
| E0 | 1012-ADA `cd95e4fe…` | plain (без -apc), → слот B | **PASS**: 16.35.1012 / MT_0000000361 / 16GT/s x8 / port0 `enp1s0f0np0` UP | 60/61°C | A→B (A инвалидирован) |
| E1 | — | — | **SKIPPED** (owner): signature-blocked — MCC digest-reject (`task-09`); смешанный состав не может иметь валидную подпись | — | — (но отклонённый burn записал ~4.3MiB E1 в слот A до MCC-проверки) |
| E2 | 8008-512F `3a053d03…` | plain + `-apc` (361→183), → слот A | **BOOT PASS / LINK DOWN**: 16.35.8008 / MT_0000000183 / dev 0x1017 (GUID — реестр `CARD_CX5_25G`, сохранён) / линк DOWN — 1000baseKX-only (образ 1G-KX, не 25G) | 60/61°C | B→A (B инвалидирован) |
| E3-V1 | 8008-ADA `1ea11b89…` (vendor) | plain + `-apc` (183→361), → слот B | **PASS**: 16.35.8008 / MT_0000000361 / dev 0x1019 (ex) / порт0 UP **25G** | 61/61°C | A→B (A инвалидирован) |
| E3-V2 | 8008-ACA `7dce1484…` (vendor) | plain + `-apc` (361→080), → слот A | **PASS**: 16.35.8008 / MT_0000000080 / dev 0x1017 (non-ex) / порт0 UP **25G** | 61/61°C | B→A (B инвалидирован) |
| E3-V3 | ADA+ROM(ACA) `16e099da…` | plain + `-apc` (080→361), → слот B | **PASS** (mixed ROM — НЕ signature-blocked): 16.35.8008 / MT_0000000361 / dev 0x1019 / порт0 UP **25G** | 61/61°C | A→B (A инвалидирован) |
| E3-V4 | ACA+ROM(ADA) `4d6c96a3…` | plain + `-apc` (361→080), → слот A | **PASS** (mixed ROM — НЕ signature-blocked): 16.35.8008 / MT_0000000080 / dev 0x1017 / порт0 UP **25G** | 61/61°C | B→A (B инвалидирован) |

**E3-вывод:** все 4 варианта (512A) бутятся на **25G** (в отличие от E2/512F — 1G-KX). Mixed-ROM (V3/V4) **прошиваются** — ~~MCC-проверка подписи **не покрывает ROM 0x18** (E1 — mixed-CODE 0x02–0x07 — блокируется). Т.е. ROM можно менять между вариантами, код — нет.~~ **ОПРОВЕРГНУТО (2026-10-28, цикл burn-digest):** интерпретация неверна — V3/V4 шли `plain + -apc` (колонка «команда» выше) → `_mccSupported=false` (subcommands.cpp:2590-2594) → прямой путь, MCC-гейт не выполнялся вовсе; «код блокируется / ROM нет» = разница клиентских путей (E1 — plain MCC при совпадающем PSID → гейт → 0x2; V3/V4 — кросс-PSID `-apc` → direct). Гейт — безусловный дест всего образа: `docs/superpowers/reports/2026-10-28-burn-digest-gate-results.md` §4.

| E4 | build/e4 `cd95e4fe…` (canary) | plain + `-apc` (080→361), → слот B | **PASS (canary)**: 16.35.1012 / MT_0000000361 / dev 0x1019 (ADA-идентичность) / порт0 UP **25G** — побайто == E0 | 60/61°C | A→B (A инвалидирован) |

**E4-canary:** md5 `cd95e4fe…` == 1012-ADA vendor (EDA-код ≡ ADA-код подтверждено
офлайн); бут == E0-повторение (1012/361/0x1019, 25G). Переменная «EDA≡ADA» верна.

| E5 | build/e5 `e5b03e52…` (итог) | plain + `-apc` (361→0009), → слот A | **PASS (итог)**: 16.35.1012 / **MT_0000000009** (VPI) / dev 0x1019 / class **[0207] InfiniBand** (IB-поля) / PCIe LnkSta **16GT/s x8** (0x1084) / IB-порт DOWN-Disabled (физ. линк — Ethernet-свитч, не IB-фабрика) | 60/61°C | B→A (B инвалидирован) |

**E5-итог:** VPI-идентичность (PSID 0009) + IB-поля применились — карта стала
**InfiniBand** (class 0207, был Ethernet 0200). PCIe-линк 16GT/s x8 (Gen4). IB-порт
DOWN/Disabled: физическое подключение — 25G Ethernet-свитч (не IB), IB-линк не
устанавливается (ожидается). Первый burn упал («No valid FS4 image found») из-за
**конфликта с параллельной `mstflint rb` владельца**; retry — OK.

| restore (T15) | 1012-ADA `cd95e4fe…` | FNP-recovery burn `--nofs -ocr` (0009→361), из FNP, host mstflint 4.34 | **PASS (restore)**: 16.35.1012 / MT_0000000361 / dev 0x1019 / class [0200] / порт0 UP **25G** / исходные GUID/MAC — реестр `CARD_CX5_25G_GUID`/`_MAC` / `dc` clean (MCX512A-ADA) | — | бут из slot A (B zeroed — инференс по флагам, дампов нет; §T15) |

(лестница завершена: E0, E2, E3×4, E4, E5; E1 — SKIPPED; T15 restore — 1012-ADA
baseline, §T15)

## 3. A/B-переходы (raw-дампы)

| # | burn | pre raw (md5) | post raw (md5) | slot A | slot B | инвалидирован | boot-addr |
|---|---|---|---|---|---|---|---|
| 1 | E0 1012-ADA | `1fb9a172…` | `df93f310…` | intact(1012/361)→**zeroed** | zeroed(080)→**intact**(1012/361) | **A** (magic 4B @0x0-3→0x0) | не байт флеша; boot = валидный слот (B) |
| 2 | E2 8008-512F | `f8ec610f…` | `716e2e06…` | E1-garbage→**intact**(8008/183) | intact(1012/361)→**zeroed** | **B** (magic 4B @0x800000) | не байт флеша; boot = валидный слот (A) |
| 3 | E3-V1 8008-ADA | `716e2e06…` | `9f276951…` | intact(8008/183)→**zeroed** | zeroed→**intact**(8008/361) | **A** (magic 4B @0x0-3) | не байт флеша; boot = валидный слот (B) |
| 4 | E3-V2 8008-ACA | `9f276951…` | `2514445f…` | zeroed→**intact**(8008/080) | intact(8008/361)→**zeroed** | **B** (magic 4B @0x800000) | не байт флеша; boot = валидный слот (A) |
| 5 | E3-V3 ADA+ROM | `2514445f…` | `f24fb7bc…` | intact(8008/080)→**zeroed** | zeroed→**intact**(8008/361) | **A** (magic 4B @0x0-3) | не байт флеша; boot = валидный слот (B) |
| 6 | E3-V4 ACA+ROM | `f24fb7bc…` | `dfc3a40d…` | zeroed→**intact**(8008/080) | intact(8008/361)→**zeroed** | **B** (magic 4B @0x800000) | не байт флеша; boot = валидный слот (A) |
| 7 | E4 canary | `dfc3a40d…` | `24abaa67…` | intact(8008/080)→**zeroed** | zeroed→**intact**(1012/361) | **A** (magic 4B @0x0-3) | не байт флеша; boot = валидный слот (B) |
| 8 | E5 итог | `24abaa67…` | `69693872…` | zeroed→**intact**(1012/0009) | intact(1012/361)→**zeroed**(+36B dev-data/PSID-tail) | **B** (magic 4B @0x800000) | не байт флеша; boot = валидный слот (A) |
| 9 | restore 1012-ADA (FNP) | — (нет дампа: FNP, флеш unreadable) | — (нет дампа) | broken (после краха mstflint 4.32) → **intact**(1012/361) | broken → **zeroed** (инференс: nofs+`-ocr`, §A/B.1) | **B** (инференс) | не байт флеша; boot = валидный слот (A) |

(переход 9 — T15; pre/post-дампы не снимались: карта в FNP, флеш unreadable;
состояние слотов — инференс по флагам burn, §T15)

## A/B. Расследование

### A/B.1 Burn-путь (карта по мstflint-сурсу)

Цепочка вызова: `FwBurnAdvanced` → `Fs4Operations::Fs4Burn`/`FsBurnAux`
(`fs4_ops.cpp:2840`) → **`BurnFs4Image(imageOps, burnParams)`** (`fs4_ops.cpp:2613-2838`).
Всё, что ниже, — из `BurnFs4Image` и вызываемых им функций.

**Слот и конвертер.** `new_image_start = getNewImageStartAddress(imageOps,
burnParams.burnFailsafe)` (`fs3_ops.cpp:1175-1195`, вызов `fs4_ops.cpp:2639`).
Для CX-5 (`cntxLog2ChunkSize == 0x17`, и у образа тоже `0x17`):

| Текущий слот (`_fwImgInfo.imgStart`) | failsafe | `-ocr` | `new_image_start` | строка |
|---|---|---|---|---|
| A (0x0) | да | — | **B (0x800000)** | `fs3_ops.cpp:1186-1188` |
| A (0x0) | нет | да | **A (0x0)** | `fs3_ops.cpp:1181,1184` |
| A (0x0) | нет | нет | **B (0x800000)** | `fs3_ops.cpp:1186-1188` |
| B (0x800000) | (любой) | — | **A (0x0)** (A/B-swap) | `fs3_ops.cpp:1180,1184` |

Т.е. burn всегда кладёт новый образ в **другой** слот (чередование A→B→A);
`-ocr` в non-failsafe принудительно в A. Конвертер выставляется по
`new_image_start` (`fs4_ops.cpp:2641-2649`): `== 0x800000` →
`set_address_convertor(0x17, 1)` (`fs4_ops.cpp:2643`), иначе
`set_address_convertor(imageLog2, !is_curr_image_in_odd_chunks)`
(`fs4_ops.cpp:2648`). См. §A/B.2: `0x17` = 23 → **контигуальные 8MiB-половины**.

**Диапазон записи** (`BurnFs4Image`, `fs4_ops.cpp:2613-2837`), в порядке записи:

| # | Что | Адрес (cont) | Данные | строки |
|---|---|---|---|---|
| 1 | boot-секция + ITOC-массив (без сигн.) | `[FS3_FW_SIGNATURE_SIZE=0x10, ITOC+0x1000)` = `[0x10, 0x6000)` | `_imageCache` (изображение) | `fs4_ops.cpp:2683-2701` |
| 2 | все ITOC-секции, по `flash_addr<<2` | адреса из ITOC | `section_data` (изображение) | `fs4_ops.cpp:2706-2724` |
| 3 | (только `useImgDevData`) DTOC-массив + DTOC-секции, **phys** | `dtocArr.tocArrayAddr` … | `_imageCache`/`section_data` | `fs4_ops.cpp:2726-2776` |
| 4 | (CX6/CX6DX) `AddSignature` | — | — | `fs4_ops.cpp:2782-2826` (**CX-5 → `default:` `IsUpdateSignatures=false`, пропуск**) |
| 5 | 16B magic-сигнатура, **phys** | `new_image_start` | `_imageCache[0..0x10)` | `fs4_ops.cpp:2827-2834` |
| 6 | `DoAfterBurnJobs` (инвалидация + boot-addr) | — | — | `fs4_ops.cpp:2837` |

Каждая запись — `writeImageEx` → `Flash::write` (`flint_io.cpp:694-805`) чанками
`TRANS=4096` (`flint_io.h:534`) → `mf_write` (`mflash.c:2889`) → `write_chunks`
(`mflash.c:292-466`). `totalSz`/`alreadyWrittenSz` в `writeImageEx` — **только
прогресс**, не лимит объёма (цикл `while (towrite)` на `cnt`; `fw_ops.cpp:1240-1299`,
прогресс `fw_ops.cpp:1313-1314`).

**Инвалидация старого слота** — `DoAfterBurnJobs` (`fs3_ops.cpp:4532-4587`):
- **failsafe burn** — `write(0, &zeroes, 4, /*phys*/ true)`: нулями **первые 4 байта**
  magic того слота, из которого работает карта (`fs3_ops.cpp:4554-4574`, запись `:4570`).
- **nofs burn** — `invalidateOldFWImages` (`fs3_ops.cpp:4484-4509`, вызов `:4549`):
  `FindAllImageStart` → 4B-ноли на все найденные magic, кроме нового слота.

**boot-addr** — `bootAddrUpdate` (`fs3_ops.cpp:4511-4530`), вызов `:4540`:
- **failsafe** (ISFU-capable чип) → `Fs3IsfuActivateImage(new_image_start)`
  (`fs3_ops.cpp:4525`) — ISFU через **работающий** FW; в FNP невозможен →
  `boot_address_was_updated=false` → warn «Failed to update FW boot address»
  (`fs3_ops.cpp:4576-4579`).
- **nofs / `-ocr`** → `flash_access->update_boot_addr(new_image_start)`
  (`fs3_ops.cpp:4521`) → `mf_update_boot_addr` (`mflash.c:3905-4000`): прямой
  `mf_cr_write` в **cr-space 0xf00c0** (CX-5, `mflash.c:3927,3991`) +
  `mf_set_reset_flash_on_warm_reboot`.

**Режимы (сводка).**

| Режим | Слот | Диапазон записи | Инвалидация | boot-addr |
|---|---|---|---|---|
| **failsafe** (A/B; c178 — из FNP) | другой (A→B) | 1+2+5 (без DTOC: `useImgDevData=false`, `fs4_ops.cpp:2652`) | 4B magic working-слота (`:4570`) | ISFU → в FNP **не обновлён** (warn) |
| **nofs** (`--nofs`) | другой слот (чередование: из A → B, из B → A; в c178-последовательности B→A; `-ocr` → A) | 1+2 (+5 phys) | все magic кроме нового (`:4484`) | прямой cr-space 0xf00c0 (`mflash.c:3905`) |
| + **`-ocr`** | принуд. A (0x0) | как nofs | как nofs | как nofs |
| + **`--ignore_dev_data`** | (не меняет) | **+3** (DTOC-массив+секции из образа) | — | — |
| + **`-apc`** (`--allow_psid_change`) | (не меняет) | (не меняет) | (не меняет) | (не меняет) — только обход PSID-проверки |

**Случай c178 (fixed S1-new, failsafe, из FNP):** карта работала из **A**
(56G, `imgStart=0`) → `new_image_start=0x800000` (B) → конвертер `(0x17,1)` →
S1-new записан в **slot B 1:1** (cont→phys `+0x800000`); magic A (56G) стёрт
(`:4570`, 4B нули @0x0); DTOC-зона **не тронута** (`useImgDevData=false` → в slot B
осталось старое device-data 56G @0xF90000+); boot-addr **не обновлён** (ISFU в FNP).

**Эмпирика E1 (task-09/10): запись целевого слота ДО MCC-проверки подписи.**
Отклонённый E1-burn (MCC digest-reject, `task-09`) всё же записал ~4.3MiB
E1-данных в целевой слот A: ср. `e1_pre df93f310` → `e2_pre f8ec610f` — 4 555 579 B,
ВСЕ в слоте A (329589 range), рантающийся слот B — 0 B. Т.е. FS4-burn пишет
целевой слот, а MCC-проверка подписи идёт **ПОСЛЕ** записи; при отказе целевой
слот остаётся с (невалидным) образом, рантающийся слот не меняется. Фаза записи
mstflint подписывается «Burning FW image **without signatures**»
(`subcommands.cpp:503`) — это имя фазы, подпись восстанавливается в конце
(`Restoring signature - OK`, `:504`).

---

### A/B.2 Коррекция docs/750-exp/100-dell-base-vpi-build §2.4 (interleave → контигуальность)

**Суть ошибки.** В docs/750-exp/100-dell-base-vpi-build §2.4 flash описан как «chunk-interleaved 128K».
Источник: константа `0x17` (log2-размер чанка) прочитана как **decimal 17**
(→ чанк 2^17 = 128K → «interleave»). На деле `0x17` — **hex = 23** → чанк
2^23 = **8MiB** → раскладка **два контигуальных 8MiB-половины, 1:1**.

**Формула.** `cont2phys` (`flint_io.h:211-225`): при `log2_chunk_size = 0x17 = 23`
```
phys = (cont & 0x7FFFFF) | (is_odd << 23) | ((cont << 1) & 0x0F000000)
```
для образа `< 0x800000` (8MiB) третий член = 0, т.е. `phys = cont | (is_odd<<23)`:
`is_odd=0` → **slot A** = физ `0x0..0x7FFFFF`; `is_odd=1` → **slot B** = физ
`0x800000..0xFFFFF`. Каждый слот = **первые 8MiB файла образа побайтово 1:1**.
В failsafe-пути конвертер **хардкод** `(0x17, 1)` (`fs4_ops.cpp:2643`); в
не-failsafe-пути `log2` берётся из tools_area образа (`fs4_ops.cpp:2378-2397`,
`EXTRACT … bits16-8`, fallback `FS4_ENCRYPTED_LOG_CHUNK_SIZE = 24` @ `:69`) —
у наших образов оба пути дают `0x17`. Вторая 8MiB-половина файла (cont
`0x800000..0xFFFFF`: MTCF @0xF90000/0xFB0000, DTOC @0xFFF000) burn-ом **не
пишется**, кроме `useImgDevData` (тогда — в конец пишемого слота).

**Доказательства (эмпирика, сверено 2026-09-09 по `c178_s1new_fixed_raw.bin`
md5 `c178109a…` и `build/dell_s1_newprio.bin`):**
- ITOC-заголовок (`ITOC`) в raw: **0x5000** (slot A) и **0x805000** (slot B).
- **`raw[0x800000:0xC30000] == s1new[0x0:0x430000]`** побайтово (первый
  0x430000-байт slot B == первые 0x430000 байт файла; первое расхождение ровно
  на физ `0xC30000` = cont `0x430000`).
- MTCF `4d544346` @ **0xF90000** и **0xFB0000** (конец slot B) — остаток
  device-data 56G (в файле образа в этих офсетах `00`, т.к. failsafe DTOC не пишет).
- DTOC `44544f43` @ **0xFFF000** (конец slot B).
- magic slot B @0x800000 = `4d544657…` (`MTFW`) — цел (== magic файла);
  magic slot A @0x0 = `00000000` (4B стёрты burn-ом, см. §A/B.1).
- Код: `flint_io.h:211` (cont2phys), `fs4_ops.cpp:2643` (`set_address_convertor(0x17,1)`).

**Вывод:** «chunk-interleaved 128K» — ошибка; корректно — контигуальные половины
1:1. docs/750-exp/100-dell-base-vpi-build §2.4 исправлено (отдельный коммит).

---

### A/B.3 Персистенция boot-addr

**Вердикт (источник): boot-addr НЕ перистируется burn-ом во флеш — это
cr-space-регистр; в failsafe-пути (как c178) он вообще не пишется.**

- `flash_access->update_boot_addr` → `mf_update_boot_addr` (`mflash.c:3905-4000`,
  `flint_io.h:445`): для **CX-5** — `mf_cr_write(mfl, 0xf00c0, boot_addr)`
  (`mflash.c:3927` addr, `:3991` write) + `mf_set_reset_flash_on_warm_reboot`.
  **Это запись в cr-space (регистр устройства), не во флеш** — во флеш `update_boot_addr`
  ничего не пишет (`grep update_boot_addr/boot_addr mflash/mflash.c`: единственная
  точка записи — `mf_cr_write` @3991; альтернатива `mf_update_boot_addr_by_type` @3998 —
  только для UEFI/MLNXOS, через reg, тоже не флеш).
- **failsafe burn** (ISFU-capable чип, как CX-5): `bootAddrUpdate` идёт в ветку
  `Fs3IsfuActivateImage(new_image_start)` (`fs3_ops.cpp:4525`) — ISFU-команда
  **работающему** FW; в FNP (нет running FW) → `false` → warn «Failed to update FW
  boot address» (`fs3_ops.cpp:4576-4579`). Т.е. **ни cr-space, ни флеш не пишутся**
  в failsafe/FNP — boot-addr остаётся прежним.
- Прямой cr-space-запись (`update_boot_addr`→0xf00c0) в failsafe-пути **нет** — она
  только в non-failsafe/`-ocr` (`fs3_ops.cpp:4518-4521`).

**Куда перистируется cr-space 0xf00c0** (переживает ли cold power cycle) — из
`refs/src` не определяется (это поведение FNP-ROM/FW, источника нет). docs/750-exp/160-hpe-cx5-vpi-gen4-precheck:
после аналогичного 56G-burn «Failed to update FW boot address» было штатным, ROM
пересчитал слот после power cycle ⇒ персистенция/решение о боте — на стороне ROM.

**Для T8 (эмпирика pre/post raw-diff):** во флеше искать **нечего** — boot-addr
не является 4–8B-полем флеша. Ориентир raw-diff — **magic-байты слотов**:
`[0x0..0x4)` (slot A) и `[0x800000..0x800004)` (slot B): валидный слот =
`4d544657` (`MTFW`), стёртый = `00000000`. ROM-решение о боте выводится из
того, какой слот валиден (fallback-тест — §A/B.5/T14). Если всё же нужен
«boot-addr» как значение ∈ {0x0, 0x800000} — это адрес **валидного** magic-слота.

**Эмпирика E0 (T8, pre→post raw-diff):** подтверждает вердикт по источнику —
boot-addr-байта во флеше **нет**. Diff pre(`1fb9a172…`)→post(`df93f310…`):
slot A 4B @0x0-0x3 → 0x0 (инвалидация, значение 0x0), slot B 11562B (новый образ,
0x0–0x507ecb), всего 11566B. Единственное изменение **вне записанного слота (B)** —
magic слота A; байта, ставшего 0x800000, нет. ⇒ бут — по **валидности слота**
(intact magic), ROM выбирает валидный слот (A→B).

---

### A/B.4 Truncation @0x430000 (c178, slot B)

**Факт (эмпирика, сверено 2026-09-09).** Slot B c178 = S1-new, но **неполный**.
Первые 0x430000 байт (cont) — точный префикс файла; дальше — выборочно.
По ITOC-секциям (cont-адресы из ITOC файла):

| Секции **записаны** (flash == файл) | 0x05, 0x20, 0x03, 0x04, 0x06, 0x08, 0x0b, 0xa0–0xa4, 0x32, 0xeb, 0xe9 (+ boot/ITOC `[0x10,0x6000)`) |
|---|---|
| **0x02** — частичная | записано cont `[0x402548, 0x430000)` (0x2dab8 из 0x2e140), хвост `[0x430000,0x430688)` = `FF` |
| **0x18** — частичная | записано cont `[0x4443d8, 0x4b0000)` (0x6bc28 из 0x6fc28), хвост `[0x4b0000,0x4b4000)` = `FF` |
| Секции **стёрты** (flash = `FF`, в файле — реальные данные) | 0x07, 0x0a, 0x0c, 0x10, 0x11 (блок cont `[0x430688,0x43ee88)`), 0x30, 0x12, 0x09 |

Ключевое: в файле образа в «стёртых» секциях **реальные (не-FF) данные**
(проверено: 0x07 7095/7328, 0x0a 39188/39200, 0x10 1024/1024, 0x12 2998/3072,
0x09 4997/5504 и др. не-FF байт), а во флеше — чистый `FF`. Т.е. **данные были
в образе и не попали во флеш** (запись потеряна), а не «в файле было FF».
Границы частичных 0x02/0x18 — по 4K-границам (0x430000, 0x4b0000). Burn при этом
отработал «Burning OK» (без ошибки).

**Гипотезы (по сурсу):**

- **(a) `total_img_size`/`alreadyWrittenSz` ограничивают объём записи — ОТКЛОНЕНА.**
  В `writeImageEx` (`fw_ops.cpp:1215-1331`) эти параметры используются **только**
  для прогресс-процента (`:1313-1314`); цикл записи — `while (towrite)` на `cnt`
  (= `section_data.size()`), лимита объёма нет (`:1240-1299`). `fs4_ops.cpp:2665-2703`
  лишь считает `total_img_size` для того же прогресса. Запись каждой секции
  (`fs4_ops.cpp:2706-2724`) идёт на полный `section_data.size()`.

- **(b) verify-шаг (read-back) — abort по несовпадению.** `write_chunks`
  (`mflash.c:292-466`) после каждого блока делает read-back и при несовпадении
  возвращает `MFE_VERIFY_ERROR` → `writeImageEx` abort (`fw_ops.cpp:1284-1287`) →
  burn завершился бы ошибкой. **Но burn отработал «OK»** ⇒ либо потеря happened
  ниже уровня mflash-verify, либо **verify выключен**: read-back прогоняется
  только если `mfl->opts[MFO_NO_VERIFY] == 0` (`mflash.c:416`); `MFO_NO_VERIFY`
  ставится из `--no-flash-verify` (`flint_io.cpp:469,479-490`; флаг
  `flint/cmd_line_parser.cpp:197,706,1154`; по умолчанию `false`,
  `flint/flint_params.cpp:68`). Т.е. **чтобы потеря прошла незамеченной, verify
  должен был быть выключен** (`--no-flash-verify`) — ИЛИ потеря на уровне ниже
  read-back. **Нужно: точная burn-команда c178** (стоял ли `--no-flash-verify`).
  (Доп. оптимизация: all-`FF` блок не пишется вовсе — `mflash.c:379-389`; на
  «стёртых» секциях не влияет, т.к. данные не-FF.)

- **(c) FNP-специфика (cr-space/ISFU-путь) — наиболее правдоподобный механизм.**
  В FNP flash пишется через cr-space: `Flash::write` (`flint_io.cpp:694-805`) →
  `mf_write` (`mflash.c:2889`) → `write_chunks` → `f_write_blk` (cr-space → FNP-ROM
  прошивает flash). Частичные 0x02/0x18 обрываются **по 4K-границам** (размер
  чанка `TRANS=4096`, `flint_io.h:534`), а «стёртые» секции — целыми блоками:
  картина совместима с **потерей части cr-space-транзакций** при записи из FNP.
  Точный триггер (таймаут cr-space / окно буфера ROM / write-protect диапазон)
  **в `refs/src` не определяется** — исходников FNP-ROM там нет.

**Вердикт: ОТКРЫТО (+ что нужно для решения).** Потеря данных в slot B —
**факт** (данные в файле, во флеше `FF`, burn «OK»). (a) отклонена; (b) показывает,
что для незаметной потери verify был выключен (нужна команда); (c) — правдоподобный
механизм (FNP cr-space), но триггер не определяется по `refs/src`.
**Что нужно для решения:** (1) точная burn-команда c178 (флаг `--no-flash-verify`?);
(2) контролируемый re-burn того же образа **с включённым verify** (default) — abort
mflash подтвердил бы cr-space-потерю (требует карту, T8+); (3) поведение FNP-ROM
при flash-write (источник вне `refs/src`).

**Резолюция (2026-10-31, цикл repack-burn-safety): повреждения slot B —
сектор-erase, НЕ truncation.** Вся картина (стёртые секции, частичные
0x02/0x18, «границы обрыва») побайтово воспроизведена симуляцией
write-механики burn: `BurnFs4Image` пишет ITOC-секции в порядке записей
ITOC, при входе в новый 64KB-сектор — erase сектора **без RMW**; образ
dell_s1_newprio не монотонен (нарушен инвариант burn-order, docs/250-re/100-formats/050-fs4-burn-order.md)
— revisit-записи стирают ранее писавшиеся секции (разведка
`2026-10-31-repack-relocation-recon.md` §3.5; чекер `burn_order_check`,
11/11 повреждённых секций == симуляции, журнал task-01):

- **сектор [0x430000,0x440000)** стёрт revisit-записями ITOC[11] 0x11
  @0x43e9c8 и ITOC[13] 0x08 @0x43f808 (возвраты вниз после верхних записей
  0x12 #10 @0x50da54 / 0x09 #12 @0x50e654)
  → жертвы: хвост 0x02 [0x430000,0x430688), блок 0x07/0x0a/0x0c/0x10/0x11
  [0x430688,0x43ee88) — «truncation @0x430000» = граница 64K-сектора;
- **сектор [0x4b0000,0x4c0000)** стёрт записью ITOC[24] 0xeb @0x4bda54
  (возврат вниз после 0xe9 #23 @0x50fbd4) → жертвы: хвост 0x18
  [0x4b0000,0x4b4000), 0x30 @0x4b4000, 0x32 @0x4b4d1c;
- **сектор [0x500000,0x510000)** стёрт revisit-записями 0x09 (#12), 0xe9
  (#23) и финальным чанком 0xeb (#24) → жертвы 0x12 @0x50da54 и 0x09
  @0x50e654; 0xe9 не пострадала (её байты в этом секторе — 0xFF в файле,
  данные выше 0x510000).

Гипотеза (c) (FNP cr-space-потеря) — снята: «потери записи» нет, данные
уничтожены erase соседних секторов; (b) verify-off более не нужен для
объяснения — read-back-verify видит только текущий чанк, урон получают
чужие диапазоны (совместимо с burn «OK», docs/250-re/100-formats/050-fs4-burn-order.md). Пометка по 0x32:
таблица выше относит её к «записанным» — по симуляции она **стёрта**
(жертва сектора 0x4b0000; вероятная причина старой классификации — сверка
8B по сток-адресу 0x4fe928); дамп c178 утрачен, перекрёстная проверка
невозможна. Повторный эксперимент c verify (п.2 выше) для этого вопроса
более не требуется; защита — гейты mlxfwutil (verify FAIL / предзаписной
отказ, docs/250-re/100-formats/050-fs4-burn-order.md).

---

### A/B.5 Fallback-тест (сканирует ли ROM слоты)

**Вердикт: ROM сканирует ОБА слота (A и B) и бута из того, что валидно и ЦЕЛО —
не фиксированный boot-addr. Дополнительно: валидный magic — необходимое, но НЕ
достаточное условие; ROM проверяет целостность образа (truncated-слот отклоняется
даже с целым magic).**

Данные (сверено 2026-09-09 по дампам; magic `MTFW` = `4d544657`; A@0x0, B@0x800000):

| dump (md5) | slot A | slot B | бут |
|---|---|---|---|
| `205c6ec4…` good_ri | **VALID** (intact) | invalid `00000000` | **BOOT** (из A) |
| `4fbc…` after56g | invalid `ffffffff` | **VALID** (complete) | **BOOT** (из B) |
| `c178109a…` s1new_fixed | invalid `00000000` | VALID magic, но **truncated @0x430000** (§A/B.4) | **NO-BOOT** (FNP) |

Логика (каждое исключение с вердиктом):
- **good_ri** (A valid, B invalid → boot): опровергает «ROM бута только из B»
  (иначе при B invalid — no-boot; но бут прошёл из A).
- **4fbc** (A invalid, B valid → boot): опровергает «ROM бута только из A» (иначе
  при A invalid — no-boot; но бут прошёл из B).
- **good_ri + 4fbc** ⇒ ROM использует и A, и B ⇒ **сканирует оба слота** (не фикс.
  boot-addr). Коррелирует с §A/B.3: boot-addr — cr-space-регистр (0xf00c0), во
  флеш burn-ом **не** перистируется ⇒ ROM не может полагаться на персистентный
  boot-addr — вынужден сканировать magic-слоты.
- **c178 vs 4fbc** — чистый контроль: в обоих A invalid + B magic-valid, но 4fbc
  (B complete) → boot, c178 (B truncated) → no-boot. ⇒ **валидный magic сам по себе
  не даёт бут** — ROM проверяет целостность образа. Точный механизм (CRC секций /
  MCC-подпись / загрузка секций из ITOC) из `refs/src` **не определяется** (FNP-ROM
  там нет) — поведение: трону́тый/truncated слот отклоняется.

**Прямой эксперимент (сломать один слот → проверить бут) — ТОЛЬКО ВЛАДЕЛЕЦ**
(FNP/обесточивание — risky). Рецепт (записать в TODO): (1) на живой карте
raw-dump + `mlxfwutil ab`; (2) `flint wb` перезаписать magic **не-ранящего** слота в
`00`/`ff` (инвалидировать); (3) power cycle; (4) проверить, бута ли из другого
слота; (5) вернуть magic (или full burn). Не выполнять без явного одобрения владельца.

### A/B.6 Recovery-рецепт (карта в FNP / no-boot)

Если карта не бутается (FNP) — пошагово:

1. **Диагностика (read-only).** `flint -d <DEV> rb 0x0 0x1000000 /tmp/dump.bin`
   (raw-dump 16MiB, ~5–7 min — в фоне). Затем `mlxfwutil ab /tmp/dump.bin` (magic A@0x0,
   B@0x800000 == `4d544657` + per-slot целостность). Определить, какой слот
   valid + intact.
2. **Есть valid+intact слот** → power cycle; ROM сканирует и бута из него (§A/B.5).
3. **Оба слота corrupt/truncated** (ситуация c178) → full burn известного-good
   образа: `mstflint -d <DEV> -i <good-image> burn`. В FNP — failsafe-путь (пишет в
   не-ранящий слот, инвалидирует старый). После burn + power cycle ROM бута из
   нового valid слота.
4. **verify ОБЯЗАТЕЛЬНО ВКЛЮЧЁН (default)** — НЕ ставить `--no-flash-verify`.
   Урок c178: truncated write прошёл «Burning OK» только если verify выключен
   (§A/B.4 (b)); c verify — abort вместо тихого corruption.
5. **Точечный ремонт magic (last resort):** если слот intact по контенту, но стёрт
   magic — `flint wb` записать `4d544657` в @0x0 (A) или @0x800000 (B).
   Предпочтительнее full burn (полная верификация образа).
6. **PCI не хардкодить:** `<DEV>` = `lspci -nnd 15b3:` + `mstflint q` (PSID/GUID) —
   см. Топологию; на сервере несколько Mellanox-карт.
7. **FNP-recovery (полевой вердикт, T15)** — карта в FNP (`020d`), флеш unreadable
   (§T15):
   - `flint_oem -d <DEV> -ocr hw query` → если `Flash0.WriteProtected Enabled`:
     `flint_oem -d <DEV> -ocr hw set Flash0.WriteProtected=Disabled` (иначе:
     «Cannot burn device data sections, Flash is write protected» → образ без
     device-data).
   - Burn known-good: `mstflint -d <DEV> -i <good-image> -ocr -apc --nofs
     --ignore_dev_data -y b`. **Обязателен выход в `Restoring signature - OK`** —
     если mstflint упадёт раньше (4.32.0: C++ vector-assertion), флеш останется
     «No valid FS4 image found». Использовать современный mstflint (4.34.0+; сейчас
     4.36.0 `f3a3dab` — §T15).
   - Verify в FNP: `q` + `dc` clean → reboot → `mstflint -d <DEV> -ocr --guid <GUID>
     --mac <MAC-без-двоеточий> sg` → `q` (GUID/MAC set) → reboot (FNP сохраняется —
     strap) → poweroff + снять FNP (владелец) + power on → baseline: 15b3:1019,
     PSID, `dc` clean, netdev UP, исходный MAC (идентичность проверять по netdev +
     ibstat — `q` в нормальном режиме может показывать Base GUID N/A, §T15).

## T15. Restore 1012-ADA — FNP-recovery (2026-09-09/10)

Полигон после E5: 1012/0009 (slot A running, slot B zeroed — переход 8). Цель —
1012-ADA baseline: 16.35.1012 / MT_0000000361 / 15b3:1019 / [0200] / исходные
GUID/MAC — реестр `CARD_CX5_25G_GUID`/`_MAC` / clean `dc` / 25G. Образ:
`/var/roothome/restore_1012ada.bin` (md5 `cd95e4febf6b8bbe6768c66665aab3e7` ==
build/e4, T12).

### Последовательность попыток

**1. Обычный burn (по шаблону плана) — не прошёл.**
- `--nofs` → `Failed to align the device sections: FW_NV_LOG section was not found!`
- `-apc --no_flash_verify` → `Bad CRC` (docs/750-exp/100-dell-base-vpi-build: для этого класса FS4-проблем —
  failsafe Bad CRC / nofs align-fail)
- `flint wb` записал magic MTFW в slot B (точечный ремонт, §A/B.6.5); magic slot A
  стёрть не вышло (ранящий слот защищён). Reboot → ROM бутанул slot A (1012/0009;
  оба magic валидны — предпочтение A, ср. §A/B.5).

**2. FNP (владелец, hardware-strap) — первая recovery, образ неполный.** Владелец
ре-флешнул из FNP и снял strap: карта кратковременно показала baseline-идентичность
(1012/361, 25G, MAC — реестр `CARD_CX5_25G_MAC`), но образ оказался неполным: `dc` →
`No valid FS4 image found`, Base GUID N/A; `sg` GUID/MAC ставились, но не
запоминались (владелец). Картина — device-data-секции не записаны; согласуется с
`Flash0.WriteProtected=Enabled` (ошибка `Cannot burn device data sections, Flash is
write protected` задокументирована для FNP без снятия write-protect) — снятие
выполнено позже (попытка 3); точная корреляция — гипотеза, не верифицирована
пошагово.

**3. Write-protect снят.** `flint_oem -d 01:00.0 -ocr hw query` →
`Flash0.WriteProtected Enabled` → `flint_oem -d 01:00.0 -ocr hw set
Flash0.WriteProtected=Disabled` → `Flash0 parameter was set successfully`
(идемпотентно).

**4. Burn из t-adm (mstflint 4.32.0) — крах.** `mstflint -d 01:00.0 -i
/var/roothome/restore_1012ada.bin -ocr -apc --nofs --ignore_dev_data -y b` →
`Burning FW image without signatures - OK` → **крах**: `/usr/include/c++/15/bits/
stl_vector.h:1262: std::vector<unsigned char>::operator[]: Assertion '__n <
this->size()' failed` — **до** `Restoring signature`. Итог: `q`/`dc`/`sg` →
`No valid FS4 image found`; semaphore заклинило (`Can not obtain Flash semaphore`;
`flint -clear_semaphore` тоже не сработал, warning `Taking flash lock even though
semaphore is set`).

**5. Reboot хоста** — FNP сохранился (020d, strap не снят), флеш unreadable.

**6. Recovery (владелец, консоль, host mstflint 4.34.0) — успех.** Лог:
`fnp-log.txt` (корень репо, файл владельца — untracked), 2026-09-09 22:46–23:16 UTC:

| # | время (UTC) | действие | результат |
|---|---|---|---|
| 1 | 22:46 | reboot (карта в FNP) | `01:00.0 … [15b3:020d]`; `q` → `No valid FS4 image found` |
| 2 | 22:49 | `mstflint -d 1:0.0 -i /var/roothome/restore_1012ada.bin -ocr -apc --nofs --ignore_dev_data -y b` | `Burning FW image without signatures - OK` ×2 → **`Restoring signature - OK`**; `q`: FS4 16.35.1012 / MT_0000000361 (Base GUID N/A); `dc` clean (MCX512A-ADA_Ax_Bx, 25GbE dual-port) |
| 3 | 22:52→22:56 | reboot | `dc`/`q` clean (GUID пока N/A) |
| 4 | 22:56 | `mstflint -d 1:0.0 -ocr --guid <реестр `CARD_CX5_25G_GUID`> --mac <реестр `CARD_CX5_25G_MAC`> sg` | `Updating GUID section - OK`; `q`: Base GUID/Base MAC = реестр `CARD_CX5_25G_GUID`/`_MAC` |
| 5 | 22:57→23:02 | reboot | FNP по-прежнему (020d — strap); `q`/`dc` clean, GUID/MAC сохранились |
| 6 | 23:04→23:11 | `systemctl poweroff` + снять FNP + power on | `01:00.0/01:00.1 = 15b3:1019`; `dc` clean; `q`: FS4 1012/361 (Base GUID N/A — quirk, ниже); `enp1s0f0np0` UP, MAC — реестр `CARD_CX5_25G_MAC`; ibstat (t-adm): Node GUID — реестр `CARD_CX5_25G_GUID`, port0 Active LinkUp **25G** (port1 Down — не заведён) |

### `Restoring signature` и версия mstflint (root-cause упавшего burn)

- Write-фаза подписывается `Burning FW image **without signatures**`
  (`subcommands.cpp:503`); затем `Restoring signature - OK` (`:504`). Крах между
  ними = образ не финализирован → `No valid FS4 image found`.
- **Версии**: t-adm 4.32.0 — крах (assertion `vector::operator[]`) до
  `Restoring signature`; host 4.34.0 (Git SHA 0990c40) — та же команда дошла до
  конца. T13 (E5, normal mode, t-adm 4.32.0) `Restoring signature - OK` достиг
  штатно — крах 4.32.0 проявился именно на FNP-burn (запись через cr-space — ср.
  §A/B.4(c); FNP-специфичность — гипотеза).
- Владелец обновил mst* до **4.36.0 (Git SHA f3a3dab)**: host (`/usr/local/bin`) +
  t-adm + локально — версии совпали (проверено 2026-09-10: все три `mstflint
  --version` → `4.36.0, Git SHA Hash: f3a3dab`).
- Заклинивший semaphore (после краха 4.32.0) не заблокировал burn попытки 6 —
  mstflint взял lock с warning.

### Финальное состояние (проверено 2026-09-10)

- `01:00.0/01:00.1`: `15b3:1019` ConnectX-5 Ex, `[0200]`
- `q`: FS4, 16.35.1012, PSID `MT_0000000361`
- `dc`: clean (MCX512A-ADA_Ax_Bx, 25GbE dual-port SFP28)
- `enp1s0f0np0` UP, speed 25000, MAC — реестр `CARD_CX5_25G_MAC`
- Переход 9 (§3): pre/post-дампы не снимались (FNP / unreadable) — A/B-состояние
  post — инференс: slot A = 1012/361 (бута), slot B = zeroed (nofs+`-ocr` → новый
  слот A, инвалидация прочих magic — §A/B.1)

### Ноты (quirks)

- `mstflint q` после нормального бута (FNP off) показывает Base GUID/MAC **N/A**
  при корректной фактической идентичности (netdev MAC — реестр `CARD_CX5_25G_MAC`; ibstat
  Node GUID — реестр `CARD_CX5_25G_GUID`; тот же `q` в FNP — попытка 6, шаг 5 — показывал
  GUID/MAC set). Идентичность проверять по netdev + ibstat, не только по `q`.
- FNP = hardware-strap (пин): переживает warm-reboot; снимается только физическим
  выдергиванием (в окне обесточивания).
- `mstflint sg`: MAC без двоеточий (реестр `CARD_CX5_25G_MAC`) — двоеточная форма отклоняется.

## E5-prep. IB-дельта ADA↔EDA (1012)

Дата: 2026-09-09 (T5). Образы: 1012-ADA (EN, PSID `MT_0000000361`,
md5 `cd95e4fe…`) ↔ 1012-EDA (VPI, PSID `MT_0000000009`, md5 `fb3a2a00…`).
Команда: `python3 mlxfwutil.py diff <ADA> <EDA> --max-ranges 300`
(по умолчанию diff обрезает 0x09 на 24 range'ах); ini: `extract -s 0x30`
(decompressed). Код+ROM идентичны → дельта только в конфиг-секциях.

**Правило включения** (спека §2 E5): include — только IB-связанные (тип
линка IB/ETH, IB-режим, IB-скорость, тип порта, default link, VPI-маркеры);
exclude — PHY/скорости/ширина 2×25 SFP28/PCIe gen/width. Обязательный
exclusion-list: `0x08+0x23`, `0x09+0x245/0x285`, `0x09+0x404+`,
`0x12+0x2ab/0x2b7` + всё семантически PCIe gen/скорость/ширина.
Неясное → exclude + комментарий.

**Контрольная карта 1012-семейства** (7 образов; CDA = EN **и** QSFP28 —
опровергает любые «коннектор/скорость»-корреляции):

| Карта | Физика | EN/VPI | sub |
|---|---|---|---|
| ADA (наша) | 2×25G SFP28 x8 Gen3/4 | EN | 0x0120 |
| CDA | 2×100G QSFP28 x16 Gen4 | EN | 0x0008 |
| 545A / 545B | 1×100G QSFP28 x16 Gen3 OCP | VPI | 0x0193 / 0x0063 |
| EDAN | 2×100G QSFP28 x16 Gen4 OCP | VPI | 0x0041 |
| ECU | 2×100G QSFP28 x16 Gen3 | VPI | 0x0124 |
| EDA (источник) | 2×100G QSFP28 x16 Gen4 | VPI | 0x0002 |

### Таблица бинарных полей (47 range'ов: 0x08:1, 0x09:34, 0x11:8, 0x12:4)

Значения — hex побайтно (MSB first). «include» — попадает в --set-лист.

**0x08 HW_BOOT_CFG**

| офсет | B | ADA | EDA | вкл | обоснование |
|---|---|---|---|---|---|
| 0x22..0x23 | 2 | 008f | 010f | ✗ | PCIe: 0x23 = max PCIe speed (ANNOTATIONS; 0x8f=Gen3, 0x0f=Gen4), 0x22 = ширина/плата (ADA x8=0x00, x16=0x01, OCP=0x03) |

**0x09 HW_MAIN_CFG** — порт0-блок (12 range'ов, base 0x240):

| офсет | B | ADA | EDA | вкл | обоснование |
|---|---|---|---|---|---|
| 0x241 | 1 | 22 | 21 | ✗ | port0 PCIe/serdes-блок |
| 0x245 | 1 | 04 | 06 | ✗ | **port0 PCIe gen (ANNOTATIONS, обязат.)** |
| 0x24d | 1 | 00 | 01 | ✗ | port0 PCIe/serdes-блок |
| 0x250..0x251 | 2 | 0000 | 0401 | ✗ | port0 lane/serdes mapping |
| 0x253 | 1 | 7f | 00 | ✗ | port0 lane/serdes |
| 0x256..0x258 | 3 | 107f00 | 900004 | ✗ | port0 lane/serdes |
| 0x25b..0x25c | 2 | 7f04 | 0000 | ✗ | port0 lane/serdes |
| 0x25e | 1 | 80 | 00 | ✗ | port0 lane/serdes |
| 0x260 | 1 | 00 | 04 | ✗ | port0 lane/serdes |
| 0x262..0x263 | 2 | 087f | 8800 | ✗ | port0 lane/serdes |
| 0x265 | 1 | 00 | 01 | ✗ | port0 lane/serdes |
| 0x267..0x26b | 5 | 7f0000187f | 0004019800 | ✗ | port0 lane/serdes |

порт1-блок (9 range'ов, base 0x280; у однопортовых 545A/B — 0x00):

| офсет | B | ADA | EDA | вкл | обоснование |
|---|---|---|---|---|---|
| 0x281 | 1 | 42 | 41 | ✗ | port1 PCIe/serdes-блок |
| 0x285 | 1 | 04 | 06 | ✗ | **port1 PCIe gen (ANNOTATIONS, обязат.)** |
| 0x290..0x291 | 2 | 0000 | 0403 | ✗ | port1 lane/serdes mapping |
| 0x293 | 1 | 7f | 01 | ✗ | port1 lane/serdes |
| 0x295..0x299 | 5 | 00107f0000 | 0290010402 | ✗ | port1 lane/serdes |
| 0x29b..0x29e | 4 | 7f040380 | 01000200 | ✗ | port1 lane/serdes |
| 0x2a0..0x2a3 | 4 | 0000087f | 04028801 | ✗ | port1 lane/serdes |
| 0x2a5 | 1 | 00 | 03 | ✗ | port1 lane/serdes |
| 0x2a7..0x2ab | 5 | 7f0000187f | 0104039801 | ✗ | port1 lane/serdes |

PCIe-ширина-блок (6 range'ов; 0x344/0x3a0: x8=0x0f, x16=0x10; те же офсеты
патчит Dell-x8-профиль `cx5_gen4_enable.py`):

| офсет | B | ADA | EDA | вкл | обоснование |
|---|---|---|---|---|---|
| 0x343..0x347 | 5 | 280fff0fff | 21100b101e | ✗ | PCIe-ширина, per-card (все x16-карты ≠ ADA) |
| 0x36c..0x36f | 4 | 0fff0fff | 002b000e | ✗ | PCIe-ширина, per-card ({CDA,ECU,EDA} = 002b000e) |
| 0x373 | 1 | 29 | 06 | ✗ | PCIe-регион, per-card |
| 0x392..0x395 | 4 | 001e001f | 0fff0fff | ✗ | PCIe-ширина: ADA x8 = 001e001f, все x16 = 0fff0fff |
| 0x39f..0x3a3 | 5 | 270fff0fff | 20100c101f | ✗ | PCIe-ширина (0x3a0: 0x0f x8 / 0x10 x16) |
| 0x3ab | 1 | 2a | 0a | ✗ | PCIe-регион, per-card |

Speed-table-регион `0x404+` (6 range'ов; **ANNOTATIONS, обязат. exclude**;
значения группируются по картам: {CDA,ECU,EDA} идентичны, {545A,545B}
идентичны, ADA/EDAN — свои):

| офсет | B | ADA | EDA | вкл | обоснование |
|---|---|---|---|---|---|
| 0x542 | 1 | 9e | 9d | ✗ | speed table (0x404+) |
| 0x546 | 1 | 00 | 91 | ✗ | speed table |
| 0x54a..0x54c | 3 | 000000 | 989898 | ✗ | speed table |
| 0x54e | 1 | 00 | 01 | ✗ | speed table |
| 0x560..0x561 | 2 | 0000 | 9898 | ✗ | speed table |
| 0x567..0x56b | 5 | 9898919800 | 0000000091 | ✗ | speed table |

PHY-tuning (1 range):

| офсет | B | ADA | EDA | вкл | обоснование |
|---|---|---|---|---|---|
| 0x86c..0x86f | 4 | 35483548 | 62fc62fc | ✗ | PHY-tuning per-card ({CDA,EDA}=62fc62fc, {545A,545B,EDAN}=8ca07c38); Dell-OEM-профиль `cx5_gen4_enable.py` патчит ровно 0x086C..0x86F |

**0x11 FW_BOOT_CFG**

| офсет | B | ADA | EDA | вкл | обоснование |
|---|---|---|---|---|---|
| 0x3c..0x3d | 2 | 0120 | 0002 | ✓ | subsystem_id (BE; ini `...cfg_hdr.subsystem_id`, 0x10+0x20..0x21 — то же): PCI-идентичность EDA-продукта, VPI-маркер; на PHY/speed/width не влияет |
| 0x47 | 1 | 18 | 1a | ✗ | PCIe: {CDA,EDAN,EDA} (Gen4 x16) = 0x1a, остальные 0x18 |
| 0x120 | 1 | a0 | 20 | ✗ | SR-IOV: bit 0x80 = sriov_en — ненулевое только у ADA/EDAN (единственные карты с sriov_en=1 в ini) |
| 0x123 | 1 | 08 | 00 | ✗ | SR-IOV: total_vfs (ADA=8, EDAN=16 — совпадает с ini) |
| 0x127 | 1 | 05 | 45 | ✗ | PCI-конфиг-данные (0x45 = cap_index в доках 4030/6120); ADA-уникальное, не IB |
| 0x2b7 | 1 | 0a | 07 | ✓ | **port0 vpi link type**: 4 бита {b0=net_ib, b1=net_eth, b2=def_ib, b3=def_eth}: 0x0a=EN (eth-only, default eth), 0x07=VPI (ib+eth, default ib), 0x00=неисп. порт; побитно = ini `port[0].vpi.*` (ADA: ib=0,eth=1,def_ib=0,def_eth=1; EDA: ib=1,eth=1,def_ib=1,def_eth=0); кросс-релиз: 4030 VPI = 0x07 |
| 0x2bb | 1 | 0a | 07 | ✓ | **port1 vpi link type** (то же) |
| 0x2c0 | 1 | a7 | ff | ✗ | только EDA (ECU — та же карта — 0xa7); SKU-специфичное, не IB, не явно физическое → консервативно exclude |

**0x12 FW_MAIN_CFG**

| офсет | B | ADA | EDA | вкл | обоснование |
|---|---|---|---|---|---|
| 0x0f8 | 1 | 30 | 31 | ✓ | **глобальный VPI/IB-режим флаг**: EN {ADA,CDA}=0x30, все VPI {545A,545B,EDAN,ECU,EDA}=0x31, кросс-релиз 4030 (VPI)=0x31; корреляция с EN/VPI чистая (CDA=EN+QSFP28 → 0x30 опровергает «module type»/«коннектор»), с PCIe/шириной/скоростью — нет; контекст 0x0f4..0x0fb идентичен; ini-ключа нет (бинарный флаг). Ключевой случай: НЕ «включить для VPI, но также физическое» → STOP не срабатывает |
| 0x2ab | 1 | 0b | bb | ✗ | **lcl[0] speed mask (ANNOTATIONS, обязат.)**: 0x0b={1,10,25}G → 0xbb={1,10,25,40,50,100}G (биты — docs/250-re/130-cable-gate/015-speed-bits.md) |
| 0x2b7 | 1 | 0b | bb | ✗ | **lcl[1] speed mask (то же)** |
| 0x39f | 1 | 00 | 0a | ✗ | PCIe-ширина: ADA x8=0x00, все x16=0x0a |

**Вне таблицы (не конфиг-поля / не --set):** 0x10 IMAGE_INFO (10 range'ов /
120 B: subsystem 0x20..0x21, PSID 0x2e..0x30, description 0x1de..0x240, name
0x344..0x348, prs_name 0x388..0x39b, +0x12e..0x12f/0x1fd..0x200) —
идентичность; PSID ставит `psid`-сабкоманда, остальное остаётся ADA (тул
пишет только PSID). 0xa0 SIG_256 (32 B) — подпись, пересчитывается. DTOC
0xe0/0xe1 (5/4 B) — device-data, не конфиг.

### Таблица ini 0x30 (188 изменившихся строк: 184 key + 4 комментария)

Разбор key-уровня, whitespace-независимо (чистые перестановки/пробелы с
одинаковым значением — не считаются: `cache_flash_div 0x3→3`,
`external_boot_record`, `i2c_devices`, `pcie_max_speed_supported`).

**INCLUDE (11 key + 3 комментария = 14 строк):**

| секция | ключ | ADA → EDA |
|---|---|---|
| (шапка) | комментарий `Generated … from ./cx5_MCX5…` | `cx5_MCX512A_2p_x8_25g_hb.prs` → `cx5_MCX556A_2p_x16_pci4.prs` |
| (комментарий) | `;;Name = …` | `MCX512A-ADA_Ax_Bx` → `MCX556A-EDA_Ax_Bx` |
| (комментарий) | `;;Description = …` | EN-строка → `ConnectX-5 Ex VPI adapter card; EDR IB (100Gb/s) and 100GbE; dual-port QSFP28; PCIe4.0 x16; tall bracket; ROHS R6` |
| image_info | psid | `MT_0000000361` → `MT_0000000009` |
| image_info | name | `MCX512A-ADA_Ax_Bx` → `MCX556A-EDA_Ax_Bx` |
| image_info | description | EN → VPI (см. выше) |
| image_info | prs_name | `cx5_MCX512A_2p_x8_25g_hb.prs` → `cx5_MCX556A_2p_x16_pci4.prs` |
| fw_boot_config | `pcie_cfg_data.pci_cfg_space.cfg_hdr.subsystem_id` | `0x0120` → `0x0002` |
| fw_boot_config | `nv_config.port[0].vpi.network_link_type_ib` | `0x0` → `0x1` |
| fw_boot_config | `nv_config.port[0].vpi.default_link_type_ib` | `0x0` → `0x1` |
| fw_boot_config | `nv_config.port[0].vpi.default_link_type_eth` | `0x1` → `0x0` |
| fw_boot_config | `nv_config.port[1].vpi.network_link_type_ib` | `0x0` → `0x1` |
| fw_boot_config | `nv_config.port[1].vpi.default_link_type_ib` | `0x0` → `0x1` |
| fw_boot_config | `nv_config.port[1].vpi.default_link_type_eth` | `0x1` → `0x0` |

**EXCLUDE (173 key + 1 комментарий = 174 строки), по группам:**

| # | группа | ключи (все) |
|---|---|---|
| 83 | gpios — проводка платы (PRSNT/INT/RESET/OVER_TEMP/THERMAL/PWR_EN/LED) | changed: `functions.gpio_func[N].mapping` (+`reverse_polarity` для N∈{2,3,22,23,48,49}) N∈{1,2,3,22,23,25,47,48,49,53} (16); `configurations.gpios[N].{gpio_config_en,mode,pull_up,pull_en,functional_enable[,def_val]}` N∈{33,11,43,14,6,32,12,10} (43) + `gpios[2].mode` (1) = 60; removed: `gpios[N].*` N∈{39(5),40(5),41(6),42(5)} + `func[41/42].mapping` (2) = 23 |
| 57 | modules — физика модулей (SFP28→QSFP28, 1→4 lane, power level 4→6) | `num[0]`: type, m2l tx/rx lane[0] serdes, rx lane[0] polarity, lane[1..3] ×8 (tx/rx × serdes/polarity/local_lane/local_port), `module_power_level_supported` = 29; `num[1]`: то же минус tx lane[0] serdes (не меняется) = 28 |
| 8 | портовые скорости (обязат. exclude) | `phy_fw_main_config.phy_shomron.lcl[0/1].eth_speeds_supported.Speed{40,50,56,100}Gb` (added) |
| 5 | boot_record — core/PLL-калибровка | `core_f` 0xa→0x10, `core_r` 0xc→0x9, `core_bwadj` 0xa→0x10, `core_r_secondary` 0x3→0x1, `size` 0x100 (removed) |
| 4 | SR-IOV (PCIe-виртуализация) | removed: `nv_config.global.pci.settings.{sriov_en,total_vfs,log_vf_uar_bar_size}`; added: `pcie_cfg_data.pci_cfg_space.sriov.vf_device_id` |
| 3 | IBM CAPI host-фичи (PCIe coherent-host, не IB; бинарного соответствия в дельте нет — есть и у ECU) | added: `nv_config.hosts.host[0].pci_cap.ibm_{capi_supported,tunneled_atomic_supported,as_notify_supported}` |
| 3 | портовые скорости (mgmt) | added: `management.port_info.link_speed_{ext_ena,ext_sup,ena}` |
| 4 | ресурсы GUID/MAC | `guids.{guids,macs}.num_allocated` 4→8 в `mfg_info` и `device_info` |
| 2 | ширина портов PHY (обязат. exclude) | `phy_fw_main_config.phy_shomron.port{0,1}_width` 0→2 |
| 2 | питание/термо | `boards_management.board_power_consumption_{1p,2p}` 13640→25340 |
| 1 | PCIe width (обязат. exclude) | `pcie_cfg.pcie_max_width_supported` 0x8→0x10 |
| 1 | без изменения значения (нотация) | `fw_boot_config.cache_flash_div` `0x3`→`3` |
| 1 | комментарий | `;;high bin` (added, boot_record) |

### Completeness-control

- Бинарные: **47/47** range'ов классифицировано (0x08:1 + 0x09:34 + 0x11:8 +
  0x12:4); include = **4** (0x11+0x3c..0x3d, 0x11+0x2b7, 0x11+0x2bb,
  0x12+0x0f8), exclude = 43. «Непонятных» нет: 0x11+0x2c0 и 0x12+0x39f —
  исключены по консервативному дефолту с комментарием.
- Ini 0x30: **188/188** изменившихся строк классифицировано (184 key + 4
  комментария); include = **14**, exclude = 174. Сумма групп exclude:
  83+57+8+5+4+3+3+4+2+2+1+1 = 173 key + 1 комм. = 174. ✓
- Обязательный exclusion-list: `0x08+0x23` ✓ (в range 0x22..0x23),
  `0x09+0x245` ✓, `0x09+0x285` ✓, `0x09+0x404+` ✓ (0x542..0x56b),
  `0x12+0x2ab` ✓, `0x12+0x2b7` ✓.
- Перекрёстная проверка: включённые ini-ключи 1:1 соответствуют включённым
  бинарным полям (6 vpi ↔ 0x11+0x2b7/0x2bb побитно; subsystem_id ↔
  0x11+0x3c..0x3d); 0x12+0x0f8 и [image_info]-блок — бинарный флаг /
  текстовая идентичность (runtime читает бинарные секции, docs/250-re/100-formats/067-prs-zlib.md).

### Финальный --set-лист (для T7)

EDA-значения побайтно:

```
--set 0x11+0x3c=0002
--set 0x11+0x2b7=07
--set 0x11+0x2bb=07
--set 0x12+0xf8=31
```

PSID (существующий сабкоманд):

```
python3 mlxfwutil.py psid <e4> --psid MT_0000000009 -o <e5a>
```

**0x30 — fallback (не patch):** E5-ini = ADA-ini + 14 included-строк
(значения EDA) = 9678 B; zlib: level 1 → 2201 (0x899, загл. 7801), level 6
(default `zlib.compress`) → 1991 (0x7c7, загл. 789c), level 9 → 1978
(0x7ba, загл. 78da — как у оригинала). На **любом** уровне len > 0x79c
(1948) — даже неизменённая ADA-ини не возвращается в 0x79c Python-zlib
(1953; zlib-сборка Mellanox другая). Т.е. T7 делает swap вместо patch:

```
python3 mlxfwutil.py repack --base <e5b> --swap <1012-EDA>:0x30 -o <e5>
```

(Секция 0x30 — «текстовый артефакт сборки», runtime читает бинарные секции,
docs/250-re/100-formats/067-prs-zlib.md; swap везёт полный EDA-PRS — допустимо планом. Растущая секция
0x79c→0x964 переезжает в 0xFF-пропуск — механика верифицирована в T1-тестах.)

### Драйв-ран (локальная валидация списка, 2026-09-09)

E4 ≡ 1012-ADA побайтово → база = ADA. Прогон psid → patch → repack swap →
verify:

```
/tmp/e5a.bin: 0x10 sec_crc/entry_crc recomputed
/tmp/e5b.bin: 4 edit(s)
/tmp/e5c.bin: 16777216 bytes, md5 e5b03e52bf7f1cb5bac86814db096772
RESULT: PASS (ITOC 25 + DTOC 7 sections, all CRC OK)
```

Побайто: E5 vs ADA — 0x08/0x09 идентичны, 0x10 только PSID (0x2e..0x30),
0x11 только включённые 4 B, 0x12 только 0x0f8, 0x30 = EDA (переезд
0x4ae9b8→0x507e8c, строки ITOC обновлены, DTOC и прочий layout без изменений).
E5 vs EDA — только 43 excluded range'а (все с ADA-значениями) + 9
идентичностных range'ов 0x10. Включённые офсеты == EDA ✓.

## E3-prep. Merge-матрица 512A (8008)

(T6, 2026-09-09; журнал: `docs/superpowers/journal/2026-09-09-plan-task-06.md`)

### 1. Полевая дельта 8008-ADA (ex) ↔ 8008-ACA (non-ex)

Контроль плана: CODE 0x02..0x07 (и 0x0a/0x0b/0x0c/0x20/0x32/0xe9/0xeb/
0xa1..0xa4) идентичны побайтово ✓ — посылка плана верна.

Функциональная дельта = 2 фактора (гранулярность = целые ITOC-секции):

- **C** = конфиг-группа {0x08, 0x09, 0x11, 0x12} — связный 10-байтовый
  SKU-профиль: 0x08+0x23 (Gen4/Gen3 max speed), 0x09+0x86c..f (Gen4 PHY-tuning),
  0x11 (зеркало dev/sub 0x2d/0x3c, PCIe cap_index 0x93, бит 0x135),
  0x12+0x27b (бит 0x08, non-ex-маркер). Vendor-субкомбинаций внутри этих
  10 B нет → разбивка на подгруппы была бы синтетикой.
- **R** = ROM 0x18 (287 KB): ADA-уникальный; **ACA ≡ 512F побайтово**
  (md5 `a979bf074e02482f03f34f8feb010e42`, размер 0x6fc28 у всех трёх).

Метаданные/артефакты (функциональный фактор не дают, в swap не входят):

- 0x10 IMAGE_INFO — идентичность (PSID/dev/sub/name/desc); FW version
  `rel-16_35_8008` одинакова у всех трёх образов.
- 0x30 DBG_FW_INI — PRS-текст (размер 0x7a0/0x7dc): идентичность +
  boot_record-биннинг + `pcie_max_speed_supported` 0xf/0x7 + device_id
  4121/4119 + board_power — артефакт сборки, runtime читает бинарные секции
  (docs/250-re/100-formats/067-prs-zlib.md).
- Сигнатуры: 0xa0 (31 B) + boot_signature файла [0x0,0x200) (13 B) —
  mixed-вариант несёт базовые; полигон non-secure → бут не блокируют.
- Вне секций — только TOC-bookkeeping + хвост PSID в MFG_INFO;
  скрытых дельт нет.

### 2. Матрица (решение агента, T6)

Полное покрытие 2×2 по (C, R); off-diagonal клетки достроены **одним**
swap-ом 0x18 от vendor-базы — минимальное изменение: mixed-вариант
отличается от vendor-файла ровно одной секцией, приписываемость причины
при no-boot однозначна.

| V | md5 | Состав | (C, R) | Ожидаемая идентичность |
|---|---|---|---|---|
| V1 | `1ea11b892e5951b31f1c99897a05a5e0` | 8008-ADA дословно (vendor) | ex C, ex R | PSID MT_0000000361, dev 0x1019, FW 16.35.8008 |
| V2 | `7dce14844bb0aad995f9c4379836e0b7` | 8008-ACA дословно (vendor) | non-ex C, non-ex R | PSID MT_0000000080, dev 0x1017, FW 16.35.8008 |
| V3 | `16e099da35f41c37e01e18183256d7bf` | base ADA + swap **0x18** из ACA | ex C, non-ex R | как V1 (PSID 361, dev 0x1019) |
| V4 | `4d6c96a3d61264ed52517e70e9497e7d` | base ACA + swap **0x18** из ADA | non-ex C, ex R | как V2 (PSID 080, dev 0x1017) |

Обоснование:

- **V1** — ex-baseline (vendor-образ ex-карты на ex-полигоне; «restore»-состояние).
- **V2** — non-ex-baseline: целостный non-ex 512A на ex-железе (полный
  cross-SKU-флеш — ровно операция Dell-merge).
- **V3** — изолирует ROM в одну сторону: отличается от V1 ровно 0x18.
  V1 бутится, V3 нет → non-ex-ROM несовместим с ex-конфигуром/ex-железом
  (в т.ч. FNP-путь).
- **V4** — симметрично: отличается от V2 ровно 0x18 (ex-ROM на non-ex-базе).

Почему нет config-swap-варианта (base ACA + {0x08,0x09,0x11,0x12} из ADA):
2×2 по (C,R) уже полностью покрыт (дублей комбинаций нет); config-swap несёт
ту же (C,R)-комбинацию с другой идентичностью (0x10) — дубликат modulo меток
(идентичность = данные, а не код); 4 секции против 1 на тот же фактор; ROM —
крупнейший и наименее определённый компонент дельты (287 KB, FNP/recovery),
его изоляция в обе стороны — главная закладка для merge-методологии;
config-фактор прощупывается отдельно в E1 и в V2.

### 3. Верификация

- `mlxfwutil.py verify` V3/V4: **RESULT: PASS** (ITOC 25 + DTOC 7, all CRC OK).
- Change-set: V3 vs base ADA — только контент 0x18 + ITOC-entry 0x18
  (sec_crc/entry_crc); все остальные ITOC-секции побайтово == базе;
  V4 vs base ACA — симметрично.
- Идентичность: локальная деривация из 0x10 (dev [0x1c:0x1e] BE, sub
  [0x20:0x22], PSID [0x2e:+17], ver [0x1c0:]): V1=V3 → 361/0x1019,
  V2=V4 → 080/0x1017, все FW `rel-16_35_8008`. Кроссчек mstflint 4.32.0
  (`mstflint -i <file> q` на root-mellanox): все 4 образа парсятся без ошибок
  (FS4, UEFI 14.29.15/PXE 3.6.902, FW 16.35.8008), PSID совпадает с локальной
  деривацией; идентичность mixed-варианта следует за базой. Отклонение плана:
  «после E3-варианта V → 15b3:1019» — упрощение, V2/V4 отчитывают 0x1017/080.
- md5 server-копий после scp == локальным.

`build/e3_v3.bin`, `build/e3_v4.bin` — git-ignored артефакты, в коммит не
входят; потребляются T11 (burn).
