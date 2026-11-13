# 100. Кросс-флеш: операционный документ (процедура)

Дата: 2026-09-06.
Статус: **фаза 1 — процедура задокументирована**, не выполнена (выполнение —
фаза 4). Каждое утверждение — с источником: преамбула
(`Problem statement on mellanox FW.md`), mstflint rev `a2b9858b`
(`файл:строка`), docs/250-re/100-formats/, docs/250-re/110-signing/, docs/150-external/, или данные `docs/250-re/100-formats/060-chip-map.md` (§11 ниже).

Цель: самодостаточная процедура «вендорская/кастомная прошивка → карта»,
по которой задачу можно выполнить без повторного разбора.

---

## 0. TL;DR — workflow (преамбула + явные дополнения)

1. **Pre-flight**: идентифицировать карту, держать known-good-образ в
   доступе (бэкапов нет — `no-fw-backup`).
2. **Dump** `.ini` (конфиг) с вендорской карты (`mstflint dc`).
3. **Base** `.bin` — взять от **стоковой** прошивки (базы совпадают).
4. **Сборка**: `base.bin + custom.ini → patched.bin` (`mlxfwutil`; правила —
   скилл `mellanox-fw-build`: build-ID в 0x30, запрет релокации, вшивание
   GUID/MAC до burn; команды и pipeline — §4).
5. **PSID-шаг (явно)**: сменить PSID в образе/флагом
   (`--allow_psid_change`; пример `MT_2430110027→2430110032`).
6. **Burn**: `mstflint … -i patched.bin --allow_psid_change burn`.
7. **Verify**: `q`, `lspci`, `dc` (PSID/name/сигнатуры/скорости).

**Брик/no-boot (карта в FNP)** — recovery-процедура: §9.1 (полевая,
docs/750-exp/110-dell-base-rework §T15).

---

## 1. Pre-flight (обязательно)

```
# идентифицировать карту (PSID, device_id, FW, security)
mstflint -d <dev> q
lspci -nnd 15b3:            # device/subsystem
```

Бэкапы не создаются (AGENTS.md `no-fw-backup`): `ri`-дамп перед прошивкой
не делается. Откат — спросить владельца: делать ли откат вообще и из
какого образа (сток/вендор/known-good). Критерий «карта не потеряна»:
known-good-образ в доступе до каждого шага.

### 1.1 Raw-доступ (`ri`/`rb`/`rw`) — добавлено 2026-09-10 (ch1 T1.1)

- `ri <file>` — логическое чтение: активный слот → файл 16MiB (0x0).
- `rb <addr> <size> <file>` — физическое raw-чтение;
  `rb 0x0 0x1000000 <f>` = весь 16MiB флеш (два 8MiB-слота A@0x0 /
  B@0x800000, docs/750-exp/100-dell-base-vpi-build §2.4). Синтаксис — по mstflint-сурсу
  (`flint/subcommands.cpp`). ~3 мин на 16MiB (t-mlxflint, фаза dell-base).
- **Write-команды** (mstflint-сурс, 2026-10-27; детали — отчёт
  `docs/superpowers/reports/2026-10-27-mstflint-write-paths.md` §1):
  `ww <addr> <dword>` — чтение сектора целиком → **erase** → запись сектора
  (RMW); `wb <file> <addr>` — по каждому затронутому сектору:
  **erase_sector → write** (деструктивная граница — сектор, 4K/64K);
  `wwne`/`wbne` — запись **без erase** (побитовое AND данных с
  существующим содержимым, только 1→0); `e <addr>` — erase сектора;
  `rw <addr>` — чтение одного dword. Ошибка отказа приходит **от карты**
  (cr-space response), а не от клиента. Защита ранящего слота — docs/750-exp/140-post-fnp-guid-desync
  §10 (2026-10-27: erase ранящего слота отклоняется независимо от
  драйвера; wbne разрешена).
- Инструменты: host mstflint 4.36.0 (`/usr/local/bin`) и контейнер
  t-mlxflint (`flint`). Эквивалентность подтверждена 2026-09-10 (ch1 T1.1:
  md5 host-`rb` == container-`rb` на 4030-EDA; журнал
  `docs/superpowers/journal/2026-09-10-eda-ib-node-ch1-task-01.md`) —
  raw-операции фазы ch1 — host mstflint (fallback — t-mlxflint).
- `mst` на хосте нет — адресация `-d <BDF>` напрямую (подтв. 2026-09-20:
  `mstflint -d 0000:81:00.0 q` → FS4 16.19.1200, `/dev/mst` отсутствует).

### 1.2 Flash-операции: долго, НЕ убивать mstflint (2026-09-20)

Процедурные правила (фон nohup + контроль окончания, запрет kill, маркеры
завершения burn, чтение `\r`-лога) — скилл `mellanox-flash-ops`. Факты:

- `ri`/`rb` молчат до завершения; лог пишет только burn. Дамп/прожиг —
  минуты (16MiB `rb` ~3 мин, burn дольше).
- Kill/крах mstflint посреди flash-op заклинивает flash-семафор
  (`Can not obtain Flash semaphore`); нормальный доступ возвращает только
  reboot хоста (кейс ch1 dump-4). FNP-burn (cr-space) может пройти с
  warning; `-clear_semaphore` может не сработать, но wedged-семафор
  следующий burn не блокировал (T15).
- **`flint`/`flint_oem` — только ради `Flash0.WriteProtected`**, через
  контейнер t-mlxflint (`toolbox run -c t-mlxflint flint_oem …`). `hw` —
  device-only; `hw set`-параметры: `QuadEn, SRWD, SRP, SRL, DummyCycles,
  DriverStrength, Flash[0-3].WriteProtected` (mlxfwops/lib/flint_io.cpp:1353);
  secure_fw среди них нет — состояние карты (MGIR/CR-space, docs/250-re/110-signing/025-secure-boot.md).
  `Flash<n>.WriteProtected` живёт в SR1/SR2 SPI-NOR (BP/TB-биты), переживает
  reboot/replug/reflash; host mstflint 4.36 — external-сборка: `hw set`
  недоступен (только query; set — flint_oem). Детали: журнал
  `superpowers/journal/2026-09-28-flint-oem-hw-set-writeprotect-re.md`.
- По факту на всех прожигаемых картах защита уже Disabled.

---

## 2. Dump-конфиг с вендорской карты

```
mstflint -d <dev> dc > /root/vendor-<dev>.ini     # dump config (.ini)
```

`dc` = `FwGetSection(FW_INI) → TOCPUn → zlib uncompress`
(`flint/subcommands.cpp:1350-1388`), секция `0x30 DBG_FW_INI` (docs/550-poc/100-mlxfwutil/010-ini-mapping.md).
Опционально: сравнить с дампом стоковой прошивки (`.diff`-файлы в `refs/fw/` —
готовые «карты» отличий между вариантами: psid/name/desc/prs/параметры портов).

---

## 3. Base-файм от стока

Взять **основной** `.bin` от стоковой прошивки (преамбула: «они совпадают» —
базовый код/структура ITOC одинаковы, отличается конфиг). PSID/`device_id`/
`name`/`desc` в образе — в IMAGE_INFO (docs/550-poc/100-mlxfwutil/020-patch-matrix.md, docs/250-re/110-signing/015-key-sections.md). Базу берём
тот же chip/format/PSID-семейство, что и целевая карта (см. §7 матрицу).

---

## 4. Сборка `patched.bin` (base + ini) — mlxfwutil

Общие правила (build-ID, запрет релокации 0x30, вшивание GUID/MAC до burn,
оффлайн-гейты) — скилл `mellanox-fw-build`; ниже — проектные команды и
канонический pipeline. Механика формата/CRC — docs/550-poc/100-mlxfwutil/010-ini-mapping.md + 020-patch-matrix.md.

### 4.1 Команды mlxfwutil (из корня репо: `python3 mlxfwutil.py <cmd>`)

| Команда | Назначение |
|---|---|
| `info` | ITOC/DTOC-дамп (type/addr/size/CRC) — чек адреса/размера 0x30 до/после |
| `verify [--deep]` | CRC всех секций (+ per-line clcrc, hashes) |
| `extract <img> -s 0x30 -o <f>` | секция → файл (0x30: zlib → ini-текст) |
| `inject <img> <ini> -o <out>` | ini-текст → 0x30 (zlib lvl9, +CRC, self-verify); oversize без `--repack-force` — ошибка |
| `guides <img> --guid 0x.. --mac 0x.. -o <out>` | GUID/MAC → mDevInfo + MFG_INFO (self-verify) |
| `psid <img> --psid/--name/--description -o <out>` | IMAGE_INFO 0x10 (+ копия PSID в 0xE0 для FS3) |
| `patch <img> --set 0xNN+0xOFF=HEX -o <out>` | точечный байтовый патч ITOC-секций (+CRC) |
| `merge --base B --src S --spec 0xNN+0xOFF+LEN,...` | field-range перенос из SRC в BASE (+CRC) |
| `diff <a> <b>` | посекционный byte-diff двух образов |
| `ab <raw>` | raw-дамп 16/32MiB → слоты A/B (+diff) |
| `repack` | FS4: legacy merge (`--new/--old/--prio`) или section swap (`--base/--swap`) |

Константы: сигн-секции `0xA0/0xA3` — не трогать (CRC секции не считается,
`crcf=1`; docs/250-re/110-signing/020-cli.md); round-trip-критерий `extract(inject(base, ini_orig))
== ini_orig` на всех парах `refs/fw/` (тест TestInjectRoundTrip).

### 4.2 Канонический pipeline (сборка под конкретную карту)

1. `mstflint -d <BDF> q` → записать PSID / FW / **Base GUID / Base MAC**
   (MAC — hex без двоеточий).
2. База: стоковый `.bin` того же chip/PSID-семейства (§3, §11).
3. `extract` 0x30 → ini.
4. Правка конфигурации + **build-ID-коммент** строкой после
   `;; Mellanox Technologies LTD`:
   `; mlxini <build-name> (<yyyy-mm-dd>, <ref>): <что/зачем>` — ≤10-20 слов,
   синтаксис `;` (iniprep), НЕ `#`. Дискриминация на карте: `dc | head`.
5. **Бюджет 0x30**: compressed+DW-padded ≤ исходного размера секции
   (локальный zlib на НЕизменённом вендор-ini даёт +4..+12 B — 18/18
   refs-пар, 2026-10-10; т.е. trim нужен почти всегда). Trim — только
   вендорские `;;`-док-комменты: FW секцию 0x30 вообще не парсит
   (debug-копия; рабочий конфиг — бинарные секции 0x08/0x09/0x11/0x12);
   key=value не трогать. Запас ≥32 B. Релокация 0x30 — только осознанно
   (`--repack-force`; инцидент corruption — журнал 2026-09-21 §13).
6. `inject` + чеки: адрес 0x30 не изменился, размер ≤ исходного, round-trip
   `extract` == ini (`info` до/после).
7. `guides` — вшить GUID/MAC этой карты (burn с `--nofs`/
   `--ignore_dev_data` берёт identity из образа; «sg после ребута» — не
   план: post-FNP `q` даёт N/A при целой идентичности, docs/750-exp/140-post-fnp-guid-desync).
8. `psid` при смене SKU (или `--allow_psid_change` при burn, §5).
9. Гейты: `verify --deep` PASS; `mstflint -i <img> verify` → «Image is
   bootable»; `diff` vs base — только задуманные зоны.
10. Burn — §6 + скилл `mellanox-flash-ops`.

Доказательства: журнал `2026-09-21-irisc-fnp-burn-verify.md` §13-§15
(corruption от релокации; patched5 — in-place trim-рецепт, запас 32 B),
docs/550-poc/100-mlxfwutil/010-ini-mapping.md + 020-patch-matrix.md, docs/750-exp/140-post-fnp-guid-desync (GUID-практика, live-проверено).

---

## 5. PSID-шаг (явно)

PSID — в IMAGE_INFO (`image_info.psid` @0x24, docs/550-poc/100-mlxfwutil/020-patch-matrix.md). При burn c
различающимся PSID нужен `--allow_psid_change`:

```
mstflint -d <dev> -i patched.bin --allow_psid_change burn
```

**Пример** (CX-4Lx MCX4131A, BCA 40G → GCA 50G):
`MT_2430110027 → MT_2430110032` (§11).
Мстflint сам переписывает PSID/name/description в IMAGE_INFO при
`--allow_psid_change` (`fs3_ops.cpp:1541-1544`). Альтернатива — сменить PSID
**в образе** до burn (`set_psid`, аналог `fs2_update_ini.py:145`, docs/150-external/110-misc-tools/020-betep-scripts.md).

Важно: смена PSID **может привести к отказу устройства** (официальный текст
флага, `flint/cmd_line_parser.cpp:685-687`). Только на жертвенной/с known-good.

---

## 6. Burn + флаги

**Тайминг запуска (владелец, 2026-10-21):** без предварительного
`sleep`/паузы перед командой burn — burn запускать сразу (команда и так
синхронная, ~5 мин; `sleep 125;` в начале прожига — лишнее).

**Режимы (выбор первым делом):**

- **Живая карта, контент-модифицированный образ (наш стандартный случай:
  сток + патчи, сигнатуры не тронуты):**
  - **non-secure карта (`q` → `Security Attributes: N/A`) — канон plain
    `-y burn` (MCC-путь) при свежем 0xA0-десте.** Дест пересчитывается
    при сборке (`mlxfwutil.py sign`; бит-эквивалент `mstflint -i <img> sign`
    без ключей), pre-burn-чек на сервере — идемпотентность `mstflint sign`
    (md5 до/после; различие → STOP, «забыли sign при сборке?»). Стылый
    дест на plain burn **детерминированно падает**
    `-E- Burning FS4 image failed: The Digest in the signature is wrong`
    (MCC 0x2 — безусловный FW content-digest-гейт, docs/750-exp/170-securefw-live-gates.md;
    прецедент: v5r 2026-10-19, docs/850-howto/140-fw-upgrade §7). Live-доказательство — парный
    контроль B (стылый дест) 0x2 / A (пересчитан) PASS: отчёт
    `docs/superpowers/reports/2026-10-28-burn-digest-gate-results.md`.
    (История: owner-решение 2026-10-09 «v5r normal-mode burn =
    `--no_fw_ctrl`» — superseded циклом burn-digest 2026-10-28.)

    ```
    mstflint -d <dev> -i patched.bin -y burn
    ```
  - **`--no_fw_ctrl` — альтернатива на non-secure** (прямая запись во
    flash, «without signatures», неактивный банк + переключение;
    digest-гейт MCC не исполняется): прежний канон; теперь — режим, когда
    MCC-путь недоступен (рекомендация самого mstflint: "Unsupported
    operation under Controlled FW, please retry with --no_fw_ctrl").

    ```
    mstflint -d <dev> -i patched.bin --no_fw_ctrl -y burn
    ```
  - **secure карта (`q` → `secure-fw`/`signed-fw`) — канон (live-proven
    2026-10-29, цикл securefw-gates): self-signed образ + «FNP один раз →
    plain onwards».** Первый burn образа с нашим вольтом/ключом — только
    FNP (legacy-флаги §9.1: `-ocr -apc --nofs --ignore_dev_data -y b`;
    plain на вендорском вольте детерминированно даёт `The key is not
    applicable` — MCC 0x7, uuid-not-found: бегущий вольт не содержит наш
    ключ). После FNP-установки нашего вольта все последующие наши
    SS-образы льюются **plain `-y burn`** без обходных флагов (uuid
    резолвится по нашему бегущему вольту; вердикт H1 end-to-end).
    Сборка SS-образа (vault 4352B, слот-план наш=slot0 + вендор slot1/2,
    порядок set_public_keys→sign, гейты) — docs/850-howto/180-securefw-recipes.md; процедура
    FNP-установки + контрольного plain — docs/850-howto/180-securefw-recipes.md; хроника/RE —
    docs/750-exp/170-securefw-live-gates.md. `--no_fw_ctrl` на secure-карте по-прежнему мёртв
    (`MFE_NO_FLASH_DETECTED` — прямой SPI закрыт, docs/750-exp/170-securefw-live-gates.md).
    Pre-burn digest-чек (идемпотентность `mstflint sign`) к SS-образам
    НЕ применим — `sign` без ключей уничтожил бы RSA-подпись (docs/850-howto/180-securefw-recipes.md
    п.7); свежесть подписи гарантируется parity-гейтом сборки.

  GUID-ловушки нет в plain/`--no_fw_ctrl` путях (device-данные не берутся
  из образа); для FNP/legacy-путей (`--ignore_dev_data`) ловушка
  актуальна — Rule 3 (вшивка GUID/MAC) обязателен (см. ниже).

- **FNP-восстановление / кросс-PSID — legacy-флаги** (`--nofs`,
  `--ignore_dev_data`, `-ocr`, `--allow_psid_change`): только для этих
  классов; `--ignore_dev_data` несёт GUID-ловушку (Rule 3 обязателен).

  ```
  # базовый:
  mstflint -d <dev> -i patched.bin --allow_psid_change burn

  # расширенный (преамбула):
  mstflint -d <dev> -i patched.bin -ocr --nofs --allow_psid_change burn
  # или: flint_oem -d <dev> -i patched.bin -ocr --nofs --allow_psid_change \
  #         --ignore_dev_data --use_image_ps burn
  ```

Семантика флагов (mstflint rev `a2b9858b`, `flint/cmd_line_parser.cpp` +
`flint/subcommands.cpp:2624-2640`):

| Флаг | Действие | Источник |
|---|---|---|
| `--no_fw_ctrl` | прямой доступ к флешу в обход FW-контроля (MCC); пишет неактивный банк + переключает (§7.1); альтернатива для контент-модифицированных образов на живой non-secure карте (канон — plain + свежий 0xA0, см. режимы выше); на secure_fw — `MFE_NO_FLASH_DETECTED` (docs/750-exp/170-securefw-live-gates.md) | docs/850-howto/140-fw-upgrade §7, docs/750-exp/110-dell-base-rework T13/E5 |
| `--allow_psid_change` / `-apc` | разрешить другой PSID; принудительно **legacy flow** (прямой flash-доступ через FW, `_mccSupported=false`) | `cmd_line_parser.cpp:1138`, `subcommands.cpp:2590` |
| `--nofs` | burn **не в failsafe**-режиме (`burnFailsafe=!nofs`); тоже legacy flow | `cmd_line_parser.cpp:1134`, `subcommands.cpp:2624` |
| `--use_image_ps` | взять VSD **изображения**, не сохранять текущий VSD с флеша | `cmd_line_parser.cpp:1179` |
| `--ignore_dev_data` | секции device-данных берутся **изображения**, не с устройства; требует `--nofs`. **ГУИДЫ карта при этом НЕ сохраняет** — identity брать из образа: вшить GUID/MAC до burn (скилл `mellanox-fw-build` Rule 3; docs/750-exp/140-post-fnp-guid-desync практика, live-проверено) | `cmd_line_parser.cpp:1195`, `subcommands.cpp:2580` |
| `-ocr` | override cache replacement | `subcommands.cpp:2603` |
| `--no_devid_check` | пропустить проверку `device_id` | `subcommands.cpp:2635` |

**Legacy flow** (`_mccSupported=false`) — прямой доступ к флешу через FW,
в обход MCC-потока; нужен для кросс-PSID/`nofs`. Именно он задевает флеш
напрямую (см. docs/150-external/120-syndicate/010-mlx5fw-mlx5cmd.md: `MFPA`/`MFBA`).

**Механизм `--no_fw_ctrl` / `-ocr` (source, 2026-10-27; детали — отчёт
`docs/superpowers/reports/2026-10-27-mstflint-write-paths.md` §3/§4):**

- Диспач (mlxfwops/lib/fw_ops.cpp:982) — единственная точка входа в
  MCC-блок (`FwCompsMgr`): `(!fwParams.ignoreCacheRep && !fwParams.noFwCtrl
  && FHT_MST_DEV) || (FHT_UEFI_DEV && !uefiExtra.dev_info.no_fw_ctrl)` —
  **оба флага обходят MCC на уровне диспача** (эквивалентны); различаются
  mflash-опциями.
- `--no_fw_ctrl` → `MFO_NO_FW_CTRL` (mflash/mflash.c:3447) — читается
  только на 7th-gen пути (`seven_gen_flash_init`, :2756-2779); на 4th-gen
  (CX-5) пути **не читается** — выбор direct path происходит на уровне
  fw_ops.
- `-ocr` → `MFO_IGNORE_CASHE_REP_GUARD` (flint_io.cpp:512 →
  mflash.c:3434+). Без -ocr `check_cache_replacement_guard`
  (mflash.c:2034-2113) читает регистры cache replacement чипа
  (ген-специфичные офсеты, :2067-2098); если FW работает из внутреннего
  кэша (guard активен) → mflash обязан идти через FW-mediated access
  (MFBA, `flash_init_inband_access`, :2603-2647) вместо direct; -ocr →
  direct access (+ на части путей register-write
  `disable/restore_cache_replacement`, :1716-1735). Отсюда мановское
  предупреждение «may cause the firmware to hang».
- Сам mstflint рекомендует флаг, когда MCC не может выполнить операцию:
  "Unsupported operation under Controlled FW, please retry with
  --no_fw_ctrl" (mlxfwops/lib/fsctrl_ops.cpp:60, 610, 903).
- Перекрёстная ссылка: TODO «normal-mode flash-cache burn роняет хост»
  (2026-10-06), пункт (в) — по исходникам кандидат-ответ = `-ocr`
  (guard → direct); live-верификации не было.

**Фазы вывода burn (FS4).** `--no_fw_ctrl`-путь: write-фаза подписывается
`Burning FW image **without signatures** - OK` (строки нет в plain-пути).
Оба пути завершаются **`Restoring signature - OK`**
(`subcommands.cpp:503-504` — подпись восстанавливается в конце). **Выход в
`Restoring signature - OK` + ноль `-E-`-строк — критерий готовности burn**:
если mstflint упадёт раньше — флеш останется `No valid FS4 image found`
(образ не финализирован; `q`/`dc`/`sg` не работают). Полевой кейс (docs/750-exp/110-dell-base-rework §T15): **mstflint 4.32.0 падал на FNP-burn**
(C++ `vector::operator[]` assertion) **до** `Restoring signature`, а та же
команда на **4.34.0** доходила до конца (normal mode на 4.32.0 — штатно,
T13/E5). Сейчас **4.36.0 (Git SHA f3a3dab)** на host (`/usr/local/bin`) + t-adm +
локально (версии совпали, проверено 2026-09-10) — для burn использовать
современный mstflint (4.34.0+).

**Активация прошивки после burn — `mstfwreset` (live-урок 2026-10-24,
журнал `cx5-fwreset-gen4` task-03).** Канон:
`mstfwreset -d <полный-BDF-вида-0000:01:00.0> --level 3 -t 0 -y r`
(~15–20 с; level 3 = driver restart + PCI reset; `-t 0` = full chip
reset). **`--level 3` указывать явно**: на same-version шагах (running
FW == образу) без флага инструмент деградирует до level-0 live-patch,
который НЕ активирует advertisement/caps (LnkCap не меняется — ловушка
ложного «конфиг не работает»; verify-before-fix: level-0 → LnkCap 8,
явный level 3 → LnkCap 16 на тех же байтах). mst-сервис для mstfwreset
не нужен. Доказательная последовательность активации: `q`
(running FW version сменился) → lspci LnkCap/LnkSta → dmesg.

---

## 7. Verify

```
mstflint -d <dev> q                 # PSID, name, FW-ver, security attrs
mstflint -d <dev> dc > after.ini    # сверить конфиг (PSID, port, speed)
lspci -nnd 15b3: -vvv               # device/subsystem, PCIe gen/speed (для Gen4-сценария)
```

- PSID/name/`desc` совпадают с ожидаемым (docs/250-re/110-signing/025-secure-boot.md).
- Для Gen4-сценария: PCIe gen4 16GT/s (`lspci`), `cap_index`/`max_speed`
  (офсеты docs/150-external/110-misc-tools/010-cx5-gen4-tool.md).
- Скорости/порт-тип: `network_link_type_ib`/`_eth`, `Speed10/25Gb` (§7).
- **`q` в нормальном режиме (FNP off) может показывать Base GUID/MAC `N/A` при
  корректной фактической идентичности** (тот же `q` в FNP показывал GUID set —
  docs/750-exp/110-dell-base-rework §T15). Идентичность проверять по netdev MAC (`ip -d li`) + ibstat
  Node GUID, не только по `q`.

### 7.1 CX-4 Lx: двойной банк образов — верификация burn читает РАБОЧИЙ банк (2026-10-10)

Открытие task-03 (журнал `docs/superpowers/journal/2026-10-09-cx4lx-an-fsm-task-03.md` §5):
flash 16 MiB несёт ДВА банка образов — A @0x0 и B @0x800000 (тела
[0x0..0x7a0000) / [0x800000..0xfa0000); общий хвост с 0xfa0000 —
NV_DATA/DEV_INFO/MFG по одному экземпляру). `burn` (--no_fw_ctrl) пишет
НЕАКТИВНЫЙ банк и переключает активность; бут грузит активный банк.

- `rb`/точечные чтения по ЛОГИЧЕСКИМ офсетам образа попадают в физику
  банка A (логический офсет == физическому — только для банка A): после
  burn в банк B контроль по офсетам видит СТАРЫЙ банк A и выглядит как
  «burn не записался», хотя рантайм уже работает новым образом.
- Маркеры банков (task-03 §5): MTFW-магия на старте банка (напр. 0x800000),
  бут-векторы на 0x0 (dead9270/4154beef); пер-банк дискриминаторы —
  значения сайтов/литералов и clcrc строк со сдвигом +0x800000
  (0x34114c ↔ 0xb4114c; eT-таблица 0x4b61f0 ↔ 0xcb61f0, e36-слово
  0x4b6214 ↔ 0xcb6214).
- Правило: верифицировать burn по РАБОЧЕМУ банку — полный дамп
  `rb 0x0 0x1000000` и проверка обоих банковых офсетов (сайт ±0x800000),
  либо рантайм-дискриминаторы (ftrace/поведение) — но НЕ точечный rb по
  логическому офсету.

---

## 8. Known-good / откат

Бэкапы не создаются (AGENTS.md `no-fw-backup`): `ri`-дамп перед прошивкой
не делается. Откат — спросить владельца: делать ли откат вообще и из
какого образа.

| Этап | Действие |
|---|---|
| Перед | known-good-образ в доступе |
| После | `q` + `dc` + `lspci`; сверить |
| Откат | спросить владельца (делать ли, какой образ) → `mstflint -d <dev> -i <образ> burn` |
| Брик? | восстановимо: кейс §9 (без программатора) |

---

## 9. Доказательство восстановимости: CX6-Dx Facebook→stock (FNP)

Факт: **CX-6Dx перешился Facebook Custom → stock
через FNP; окирпичивалась на время, восстановлена без программатора.**

Вывод:
- кросс-SKU-перешив **возможен** и **восстановим** (есть путь back);
- **FNP** («Flash Not Present», вендорский канон) = аппаратный strap-пин
  (read-only, `reg_access_hca_layouts.h:313-316`). Первоисточник — MFT
  docs, «Booting HCA device in livefish mode»:
  <https://networking-docs.nvidia.com/mftswum/4.37.0/booting-hca-device-in-livefish-mode>
  (карта с отсутствующей/пустой флешей поднимается в livefish; в общинных
  материалах глосс «Factory New Product»). Открывает factory-операции
  (смена PSID / перепрограммирование), когда обычный `--allow_psid_change`
  недоступен (docs/850-howto/170-signing-practical.md);
- основной геморрой — **signed-прошивки** (docs/250-re/110-signing/): на SB-карте кастомный
  образ примется только с корректной подписью.

### 9.1 FNP-recovery, полевая (CX-5 Ex 1012-ADA, T15, 2026-09-09/10)

Процесс: docs/750-exp/110-dell-base-rework §T15 (+ лог владельца `fnp-log.txt`, корень репо). Ситуация:
карта в FNP (no-boot, `15b3:020d`), флеш unreadable
(`No valid FS4 image found`), known-good-образ в доступе
(`/var/roothome/restore_1012ada.bin`, md5 `cd95e4fe…` == 1012-ADA).

Инструменты в этой среде: `mstflint` — host (`/usr/local/bin`) + контейнер
t-adm (4.36.0 `f3a3dab`); `flint_oem`/`flint` — контейнер t-mlxflint;
команды — с хоста (консоль/ssh) либо `podman-remote -c root-mellanox exec
<контейнер>`. PCI не хардкодить: `lspci -nnd 15b3:` (+ `mstflint q`, если
работает).

1. **Precondition — write-protect (в FNP):**
   ```
   flint_oem -d <dev> -ocr hw query                      # Flash0.WriteProtected
   flint_oem -d <dev> -ocr hw set Flash0.WriteProtected=Disabled
   ```
   Без снятия: `Cannot burn device data sections, Flash is write protected` →
   образ **без device-data** (идентичность бута, но `dc` unreadable, GUID/MAC
   ставятся, но не запоминаются — полевой кейс T15-попытка 2). `hw get` —
   неверная команда; `hw query` / `hw set`. Снятие идемпотентно.
2. **Burn known-good:**
   ```
   mstflint -d <dev> -i <known-good.bin> -ocr -apc --nofs --ignore_dev_data -y b
   ```
   **Обязателен выход в `Restoring signature - OK`** (§6). В FNP `mstflint q`
   до burn может не работать (`Can not obtain Flash semaphore` / «No valid FS4
   image found»); `flint_oem hw query` — работает.
3. **Verify в FNP:** `mstflint -d <dev> q` (FS4, FW, PSID; Base GUID N/A до sg)
   + `mstflint -d <dev> dc` (clean).
4. **Reboot → GUID/MAC:**
   ```
   mstflint -d <dev> -ocr --guid <GUID> --mac <MAC> sg
   mstflint -d <dev> q                                  # Base GUID/MAC set
   ```
   MAC — **без двоеточий** (реестр `CARD_CX5_25G_MAC`); двоеточная форма отклоняется.
5. **Reboot** — FNP **сохраняется** (strap не снят, `020d`); проверить, что
   GUID/MAC сохранились (`q`).
6. **poweroff + снять FNP strap (владелец/консоль) + power on** → verify
   baseline: `lspci -nnd 15b3:` (device_id, не `020d`), `q` (PSID), `dc` (clean),
   netdev UP + исходный MAC, ibstat Node GUID + port Active (§7 — `q` может
   показывать Base GUID N/A).

Ключевые факты:
- **FNP = hardware-strap (пин)**: переживает warm-reboot; снимается только
  физическим выдергиванием (в окне обесточивания).
- **Версия mstflint критична для FNP-burn**: 4.32.0 — крах до
  `Restoring signature` (→ unreadable флеш), 4.34.0 — OK; сейчас 4.36.0
  (`f3a3dab`) на host/t-adm/локально (§6).
- **Заклинивший semaphore** (после краха mstflint: `Can not obtain Flash
  semaphore`; `flint -clear_semaphore` тоже не сработал, warning `Taking flash
  lock even though semaphore is set`) **не блокировал** следующий burn —
  mstflint взял lock с warning.
- FNP-burn пишет flash через **cr-space** (docs/750-exp/110-dell-base-rework §A/B.4(c)) — путь записи
  отличается от normal mode; verify (read-back) включён по умолчанию — не
  выключать (`--no-flash-verify`).

---

## 10. Риски кросс-флеша

| Риск | Комментарий / митигция |
|---|---|
| **LED/индикация** отваливается | вендорские образы настраивают LED; на сток-образе индикация может отличаться. Данные: **заполнить после живого LED-сравнения** stock vs HP/Dell CX-5 (фаза 4) |
| **SR-IOV-глюки** | вендорские кастомы отключают/меняют SR-IOV; проверить `mstconfig`/`mlxconfig` после burn |
| **Токи/мощность** | вендорские лимиты power/thermal могут отличаться; сверить после burn |
| **Secure-boot** | односторонний переход на signed; кастомный образ на SB-карте — только с подписью (docs/850-howto/170-signing-practical.md). Прогонять только на жертвенных |
| **PSID-несовпадение** | смена PSID → возможный отказ устройства (официально); known-good обязателен |

---

## 11. Матрица силикона (device_id)

| Карта | device_id | PSID (пример) | Формат | Примечание |
|---|---|---|---|---|
| CX-4 EN MCX456A | **0x1013** (4115) | — | FS3 | subsystem 0x0014/0x0012 |
| CX-4Lx MCX4131A | **0x1015** (4117) | `MT_2430110027`(40G)/`MT_2430110032`(50G) | FS3 | subsystem 0x0006 |
| CX-4Lx MCX4121A (2×25G) | **0x1015** (4117) | 14.32.1912 (image q) | FS3 | `ib=0/eth=1`, PCIe gen3 |
| CX-5 556A | **0x1017** (4119) | — | FS4 | subsystem 0x0124 |
| CX-5 Ex MCX512A (2×25G) | **0x1019** (4121) | `MT_0000000361` | FS4 | `ib=0/eth=1`, PCIe gen4 |
| CX-6 MCX654105A | **0x101b** | `MT_0000000226` | FS4 | non-SB (`Security Attributes: N/A`) |
| CX-6Dx 623435AC | **0x101D** (4125) | `MT_0000000695` | FS4 | SB SKU |

`device_id` в ini — PCIe-идентификатор из конфига, **не** прямое доказательство
силикона (§11.1).

### 11.1 Гипотеза «CX-4 ≠ CX-4Lx» (открытый)

Основания: разный `device_id` (0x1013/0x1015), lspci-семейства
**MT27700 vs MT27710** (проверено 2026-09-06), разные возможности (PCIe x8 gen3
у Lx, 40/50G, отсутствие IB-вариантов у Lx), аналогия с CX-3/Pro (не
кросс-флешаются). **Вывод — в фазу IB-эксперимента** (фаза 5): сверить `flint q`
на живых картах + `mfg_info`/`device_info` + поведение.

**РАЗРЕШЕНО (2026-09-15, фаза 5; журнал
`docs/superpowers/journal/2026-09-15-cx4lx-ib.md`): Lx-силикон ПОДДЕРЖИВАЕТ
IB.** Точечный config-патч FS3-образа MCX4121A-ACA 14.32.1900 (VPI-байт
`0x11+0x2b3=0x07` = port1 VPI def-IB; PSID/GUID/MAC не тронуты) +
`mstflint --no_fw_ctrl -y burn` → после reboot c1:00.1 = `[0207]`
InfiniBand controller: ibstat «Link layer: InfiniBand», mstconfig
`LINK_TYPE_P2 = IB(1)`, `Enabled Link Speed 0x1f (SDR..FDR, без EDR)`.
Гейт — конфиг (VPI-байт 0x11), не микрокод (IB-код в MAIN_CODE Lx-образа
присутствует — string-scan, там же). «CX-4 ≠ CX-4Lx» как silicon-факт
(device_id 0x1013/0x1015, MT27700/MT27710, PCIe x8 gen3) — сохраняется, но
**не является препятствием для IB**; IB-вариантов Lx нет только потому, что
вендор не шьёт Lx в IB-конфигурации (config-гейт), а не потому, что чип
не умеет. Максимум скорости Lx-IB-порта — FDR 1X (25G SerDes, EDR не
разрешён вендорским профилем).

---

## 12. Подпись (кратко → docs/250-re/110-signing/)

- **non-SB-карта** (`Security Attributes: N/A`, как CX-6): примет **и** digest-only
  (unsigned), **и** RSA-signed — подпись не проверяется. Кросс-флеш кастомного
  образа **возможен**.
- **SB-карта**: примет только образ с подписью корневого ключа (Mellanox,
  `keypair_uuid c55d54e8…`). Свой ключ — **не** примет.
- Кастомизация ini (docs/550-poc/100-mlxfwutil/010-ini-mapping.md, docs/850-howto/170-signing-practical.md) на non-SB — безопасна; на SB — ограничение.

---

## 13. Сценарии для фазы 4 (к выполнению)

| Сценарий | Что | Критерий |
|---|---|---|
| **A** | CX-5 Gen4-патч (base из `refs/fw/cx-5-6`) | `lspci` gen4 16GT/s, `mstflint q` |
| **B** | cross-flash с PSID-сменой (пара с разным PSID) | `flint q`: PSID, name |
| **C** | inject-образ в CX-6Dx (signed/unsigned пара) | зафиксировать поведение secure-карты (docs/250-re/110-signing/) |
| **LED** | stock vs HP/Dell CX-5 | данные → §10 |

---

## 14. Источники (сводка)

- Преамбула: `Problem statement on mellanox FW.md` (workflow, риски)
- mstflint rev `a2b9858b`: `flint/cmd_line_parser.cpp` (:683,:718,:742,:1134-1197),
  `flint/subcommands.cpp` (:1350-1388 `dc`, :2575-2640 burn), `fs3_ops.cpp`
  (:1541-1544 `--allow_psid_change`)
- `docs/250-re/100-formats/060-chip-map.md` — PSID/ini-данные, силикон (поглотил
  00-analysis §3.3–§3.4; растворён 2026-11 — git-история); CX6-Dx Facebook→stock — §9 выше
- `docs/550-poc/100-mlxfwutil/010-ini-mapping.md` (ini), `docs/550-poc/100-mlxfwutil/020-patch-matrix.md` (PSID), `docs/250-re/110-signing/030-root-of-trust.md`
  (root-of-trust), `docs/850-howto/170-signing-practical.md` (FNP), `docs/150-external/120-syndicate/010-mlx5fw-mlx5cmd.md` (flash I/O),
  `docs/150-external/110-misc-tools/010-cx5-gen4-tool.md` (CRC/офсеты)
- `docs/750-exp/110-dell-base-rework-dell-base-rework.md` §T15 (FNP-recovery полевая, 2026-09-09/10; лог
  `fnp-log.txt`), §A/B.1 (burn-путь/фазы), §A/B.4(c) (cr-space в FNP)

---

## 15. FNP-режим: вход и семантика (из 90 §1)

- **Вход**: замкнуть джампер **FNP** («Firmware Not Present»; есть на всех
  картах Mellanox, не всегда распаян) на включении → карта входит в
  *life-flash* (recovery): энумерируется как `15b3:020d [ConnectX-5 Flash
  Recovery]` — **флеш-устройство, не сетевая** (NIC в этом режиме не
  работает). Для карт без доступного FNP-хедера тот же recovery-стейт даёт
  замыкание SPI-пинов флеша 2+4 на буте (Gen4-тул
  `refs/src/Mellanox-ConnectX-5-PCIe-Gen-4-Enablement/README.md` §«Flashing —
  Signature Errors and FNP Recovery», `TECHNICAL.md` §«Secure Boot and FNP
  Recovery» там же; подтверждено владельцем).
- **Запись не заблокирована**: в recovery карта принимает **любую** прошивку
  (в т.ч. чужой PSID / сломанную подпись) — штатный способ прошива
  модифицированных образов. Отсутствие digest-гейта на FNP-ноге —
  `docs/550-poc/100-mlxfwutil/020-patch-matrix.md` §4; приём всех классов
  подписи — `docs/250-re/110-signing/055-cx6dx-signing.md` §5.
- **Семантика (уточнение)**: FNP — только *механизм записи*; он **не
  отключает** верификацию при *загрузке*. «This bypasses secure boot
  entirely» (Gen4-README) = обход защиты записи (нет `The Digest in the
  signature is wrong` при флеше), а не пропуск проверки на старте. После
  записи — джампер разомкнуть, холодный цикл → штатный путь загрузки, где
  верификация применяется как есть (что именно проверяет ROM —
  `docs/250-re/110-signing/030-root-of-trust.md` §2–§3).

---

## 16. VFIO→mlx5_core rebind на кастомных сборках (fuzz4): не полагаться

- Утверждение владельца (2026-11-08): на fuzz4-v1 обратный бинд на
  `mlx5_core` после унбинда от `vfio-pci` **ненадёжен** — протоколы live-работ
  не должны на него опираться.
- Эмпирика: после здоровых VFIO-прогонов рестор удавался (3×, журнал
  `2026-11-08-mlxdirect-replacement-task-01`), но известны отказы:
  - после wedged mailbox бинд падает probe `-110` («Firmware …
    pre-initializing 0xc7020000»); FLR и `mstfwreset` недостаточны, тёплый
    ребут виснет — лечит только **BMC cold cycle** (тот же журнал);
  - после fuzz-батареи rebind формально проходил, но `mlx5_core` уходил в
    `poll_health: device's health compromised` + «Health issue observed,
    firmware CRC» на sibling-функции (журнал
    `2026-10-25-irisc-fuzz4-task-05` Step 2w) — driver state после такого
    рестора не доверять.
- Правила: (а) планировать все VFIO-операции одного цикла в одном окне
  (карта остаётся на `vfio-pci`, сессии переоткрываются); (б) driver-зависимые
  проверки (mstreg и т.п.) — до входа в окно или после cold cycle;
  (в) восстановление при wedge/health — BMC cold power cycle (ipmi-ops);
  (г) после rebind обязательно проверять health (dmesg, mstreg) перед
  использованием driver-инструментов.

---

## 17. CX-7 GA SECURED: закрытые маршруты кросс-флеша (2026-11-10)

Плата: Meta OCP3.0 CX-7 (`CX71143DMC-CDBE_FB`, MODL CX71343DM; 100GbE,
1×QSFP112, multi-host 4 hosts, Crypto+Secure Boot), PSID `FB_0000000040`,
life-cycle secure-fw **GA SECURED**, FW 28.34.4000. Предмет: кросс-флеш на
ретейл-PSID (нативный FB_-контейнер публично не распространяется).

Матрица проверенных маршрутов:

| Маршрут | Исход |
|---|---|
| MCC + ретейл-контейнер as-is | PSID-гейт: отказ до передачи |
| MCC + контейнер с plaintext-патчем PSID | полный перенос компонента → FW verify **MCC 0x5 AUTH_FAILED** (RSA-mismatch) |
| MCC + same-PSID слот-дамп (ri) | FW internal error (`MLX5_CMD_STAT_INT_ERR`) на 1% boot-компонента |
| Recovery-path burn контейнера | контейнер на флеш **as-is** (без распаковки) → no-boot |
| Нативный FB_-доставочный контейнер | открыт (доступен только по каналам владельца платы) |

Факты (улики в журналах):

- Recovery-burn (режим MT2910 flash recovery) пишет доставочный контейнер
  as-is: без распаковки/расшифровки, без per-burn keystream → ROM не
  грузит (Image Boot Status −2050), карта в flash-recovery. Восстановление:
  known-good слепок + `--nofs --ignore_dev_data` (плейбук §9.1; журнал
  `2026-11-10-cx7-crossflash-incident`).
- PSID-патч подписанного контейнера: PSID-гейт проходит (образ
  «bootable», CRC секций обновлены), компонент передаётся на 100%, FW
  verify отвергает по подписи (MCC 0x5, ветка RSA-mismatch 0x1d30b8 —
  docs/250-re/110-signing/045 §1) → **подпись покрывает IMAGE_INFO**;
  plaintext-патч PSID на MCC-пути закрыт. Оговорка: IMAGE_INFO и MFG_INFO
  патчены одной пробой (12 B); причина ранжирована на IMAGE_INFO (только
  они внутри переданного компонента), сплит-проба не гонялась (журнал
  `2026-11-10-cx7-multiburn-keystream`).
- MCC-компонентный путь принимает только **доставочную форму**: слот-дамп
  (ri) тем же PSID отвергается на boot-компоненте. Per-burn перешифровка —
  свойство burn-трансформа MCC основного FW, не boot и не recovery-writer
  (docs/250-re/100-formats/051-fs4-cx7-encrypted.md §8).

Правила:

- Кросс-флеш GA SECURED платы возможен только нативным доставочным
  контейнером целевого PSID; plaintext-патч подписанного образа (`-apc`
  стиль §5) на secure-картах не работает — не пытаться.
- Recovery-режим — только для записи known-good **слепков** (полная
  флеш-копия), не доставочных контейнеров.
- После неудачного recovery-burn карта восстанавливается слепком
  + `--nofs --ignore_dev_data` (проверено, заводское состояние
  возвращается побайтово; GUID/MFG идентичность не страдает при
  `--ignore_dev_data`).
