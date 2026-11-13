# 110. Программирование/перекодировка трансиверов (SFP+/SFP28/QSFP28)

Статус: исследование 2026-10-04 (суб-агент, журнал
`docs/superpowers/journal/2026-10-04-transceivertool-ib-recoding.md`).
Офлайн-часть: анализ `refs/src/TransceiverTool` v0.0.6-2-g811da32.
Live-часть 2026-10-04, сессия 1 (журнал
`docs/superpowers/journal/2026-10-04-transceiver-ib-bit-live.md`):
дампы сняты, байт-мап и патч проверены, но **запись в EEPROM оптики
SFP-25G-SR in-band невозможна — hardware write-protect** (оба модуля; §4 шаг 6,
§6 п.3). Гейт на IB-порту live с перекодированным модулем — не проверялся.

Live-часть 2026-10-04, сессия 3 (тот же журнал, раздел «Сессия 3»):
верификация **обоих концов DAC** (оба SN CU1M, вендор шьёт оба
конца одинаково): IB-бит (byte 3 → 0x01) и CC_BASE от aligned-записей
сессии 2 достались обоим концам, но single-byte повреждения (OUI-хвост,
PN) — только концу, который был в порту при repair-записях; второй конец
дозаписан двумя aligned dword'ами (OUI 02 c9 и «G-C» PN восстановлены).
Финальное состояние обоих концов побайтово == recoded-образу
(md5 092e1f93…, CC_BASE 0xd8 == Σ). **Урок: DAC двухсторонний — после
горячих перетыканий проверять/чинить каждый конец отдельно, по SN через
ethtool -m конкретного порта; совпадение SN у двух клеток ≠ совпадение
состояния EEPROM.**

Live-часть 2026-10-04, сессии 4–5 (тот же журнал): с IB-битом byte 3 =
0x01 оба IB-порта (c1:00.1 CX-4Lx, 01:00.0 CX-5 через QSA) всё равно
держат opcode 26 / bitmap 0x0 — IB-бит необходим, но недостаточен:
BR-поля модуля пустые (byte 12 = 0xff + ext BR = 0). Патч ext BR (A2h
222–223) **не применён — A2h in-band недостижим**: `mstlink --cable
--page 1` на FW 14.32.1900/16.35.4030 алиасится в A0h (верифицировано
записью-пробой с восстановлением). Вместо ext BR пропатчен достижимый
**A0h byte 12: 0xff → 0x64** (BR nominal 10.0 Gb/s = QDR; CC_BASE
0xd8→0x3d) на обоих концах (QSA write-through), read-back верифицирован.
**Гейт после патча не переоценён: FW кеширует module info с момента
втыкания** (opcode 26 / 0x0 / «Nominal 0.000Gb/s» держались 60+ с;
ожидается plug-событие или port-toggle). Запасной образ: byte 12 = 0x8c
(FDR, CC 0x65).

Live-часть 2026-10-07 (глава 1 арки трансиверов, журналы
`2026-10-07-transceiver-ib-ch1-dac-optics-task-02..06r.md`): write-путь
программатора починен и доказан живым железом (два бага: OUT|N off-by-one
— 97db39e; 32Б-кадры без ZLP — ad98558); DAC A2h — blank-0xFF writable die;
оптика A0h записываема, A2h — SFF-8472 password-гейт, снимается FF×8.
Главная гипотеза «bitmap из ext BR A2h 222–223» опровергнута с контролями
(docs/250-re/130-cable-gate/005-chain.md). Записываемость/механика — §6 п.3, §7.2.

Live-часть 2026-10-10 (журнал
`docs/superpowers/journal/2026-10-10-qsa-sfp-ib-recode.md`): A0005
перекодирован в QSFP28-личину (byte 0=0x11, byte 164=0x0f, CC_BASE
0x7c→0x8a) — за QSA прошёл сток IB-гейт на QSFP-порту 41:00.1
(SCS 0x1f, IB-FDR 1x, фабрика;
`docs/250-re/100-formats/070-transceiver-eeprom.md` §3.1, рецепт — §5).
Уточнение
записываемости: A0h нижняя половина (0–127) writable без unlock,
верхняя (128–255) — за тем же A2h-паролем; FF×8-unlock **volatile**
(теряется после power cycle, повторный unlock работает).

Live-часть 2026-10-17 (цикл персона+идентичность, журналы
`docs/superpowers/journal/2026-10-17-transceiver-qsa-persona-identity-task-02.md`
(A0006) / `-task-03.md` (A0005)): A0005 — вендорская идентичность вшита в
8636-позиции (name 148–163 / OUI 165–167 / PN 168–183 / SN 196–211 из
собственных 8472-полей; 8636-CC 191=0x67 / 223=0x4f), персона 2026-10-10
не тронута (byte 0=0x11 / 164=0x0f / CC_BASE@63=0x8a); live в c1:00.0 —
дисплей ВАРИАНТ (а): 8636-вендорские поля ВИДНЫ в SFP28-слоте (SCS 0x1f,
Polling, Identifier QSFP28) — карта отдаёт полные 256 Б A0h. A0006 —
отрицательный результат: A0h write-ignored (обе половины) против всех 57
password-кандидатов (28 STH ×2 + FF×8) — модуль-специфичный лок, модуль не
изменён (byte-exact pre, идентичность SFP-25G-SR); A2h-гейт — pw-01b
`00 00 10 11` (FF×8 не снял). CH341: status-байт write-кадра не
доставляется (подтверждено post-fix тулингом) — open question §7.2 закрыт.
Детали — §6 п.3, §7.2.

## 1. Какие бывают задачи по трансиверам

Типовые задачи «перекодировки/настройки» EEPROM оптики:

| Задача | Где в EEPROM | Инструмент |
|---|---|---|
| Смена compliance-кодов (EN↔IB, другие скорости) | SFF-8472 A0h byte 3/36; SFF-8636 byte 164/192 | TransceiverTool (§3) |
| Вендор-поля: имя, OUI, PN, SN, rev, дата | A0h 20–91; QSFP 00h 148–221 | TransceiverTool |
| Rate/signaling поля (byte 12/13 SFF-8472) | A0h | TransceiverTool |
| Vendor Specific / пользовательская область | A0h 96–127 (base64 в JSON) | TransceiverTool |
| Диагностика/DDM-пороги (A2h), soft write-protect | A2h (вне покрытия TransceiverTool) | hex-правка / программатор |
| CMIS-модули (SFP-DD/QSFP-DD) | paging | вне TransceiverTool |
| Запись образа обратно в модуль | — | `ethtool -E` (проверить у mlx5) или внешний программатор (REVELPROG/FLEXBOX) |

Чтение дампа всегда доступно: `ethtool -m <if> raw > dump.bin`
(на mlx5 чтение работает — live-факт из журналов).

## 2. Главный риск: FW карты тоже читает EEPROM

Перекодировка меняет, что **рапортует** модуль, но не меняет силикон внутри.
Поведение хоста определяется пересечением трёх множеств:
rapорт EEPROM ∩ возможности силикона модуля ∩ проверки FW карты.
На ConnectX есть FW-гейт «Cable speed not enabled» (PDDR opcode 26,
mstlink «Supported Cable Speed 0x00000000») — см. `docs/250-re/130-cable-gate/005-chain.md`:
FW сверяет IB-compliance модуля с желаемым линком. Отсюда главный применимый
сценарий перекодировки — §5.

## 3. TransceiverTool: возможности и лимиты

`refs/src/TransceiverTool` (C++/CMake, SFF-8472 + SFF-8636). Вердикт
исследования: **пригоден полностью для офлайн-части** (parse → edit →
assemble → checksum → validate), не пригоден как writer к железу (и не
задумывался: `PRODUCT.md` — «does not directly program hardware», автор пишет
через REVELPROG).

CLI (`src/CLI.cpp`), все команды файловые (stdin/stdout или
`--from-file`/`--to-file`):

- `decode --binary-type 8472-128b|8636-128b|8636-256b` → JSON
  (для DAC удобно `--copper-mode` — меняет только читаемость JSON байтов
  14–19/60–61, на бинарь не влияет);
- `encode --binary-type ... [--validate]` → бинарь;
- `pretty-print-json`, `validate-json`, `roundtrip-test`.

Покрытие по нашим байтам — полное:
- SFF-8472 **byte 3 Infiniband Compliance Codes** — parse + assemble
  (`SFF-8472_Assembler.cpp:27-34`, JSON-ключ `"Infiniband Compliance Codes"`);
- SFF-8472 byte 36 Extended Compliance (enum SFF-8024, 74 значения);
- SFF-8636 **byte 164 Extended Module Codes (IB SDR…HDR)** — parse + assemble
  (`SFF-8636_Assembler.cpp:173-180`); byte 192 Extended Compliance;
- вендор-поля и Vendor Specific (base64) — round-trip стабильно;
- **контрольные суммы**: `decode` сериализует корректные CC_BASE/CC_EXT как
  строку `"auto"`, `encode` при `"auto"` пересчитывает сумму из собранного
  бинаря (SFF-8472: CC_BASE = Σ0..62 → byte 63, CC_EXT = Σ64..94 → byte 95;
  SFF-8636: 191/223). Валидатор отклоняет битые суммы и reserved-биты.

Лимиты:
- SFF-8472 — **только A0h lower page (128 Б)**. Не покрыто: A2h (там же soft
  write-protect/password byte 127), A0h upper pages 01h/02h;
- нет CMIS-парсинга (SFP-DD/QSFP-DD);
- нет доступа к железу.

## 4. Универсальный пайплайн перекодировки

```sh
# 1. Дамп (SFP = первые 128 Б A0h; QSFP28 = 256 Б page 00h)
ethtool -m <if> raw > dump.bin

# 2. В JSON
TransceiverTool decode --binary-type 8472-128b --from-file dump.bin \
  --json-to-file prog.json

# 3. Правка JSON (байты из §5); "CC_BASE"/"CC_EXT": "auto" не трогать

# 4. Сборка + валидация (суммы пересчитаются)
TransceiverTool encode --binary-type 8472-128b --from-file prog.json \
  --to-file recoded.bin --validate

# 5. Контроль: только ожидаемые байты изменились
TransceiverTool roundtrip-test ... ; hexdiff dump.bin recoded.bin

# 6. Запись в модуль — вне TransceiverTool (live-проверено 2026-10-04,
#    журнал 2026-10-04-transceiver-ib-bit-live, сессии 1-2):
#    - ethtool -E: НЕ работает (mlx5 не реализует set_eeprom; eeprom_len=0)
#    - netlink MODULE_EEPROM_SET: НЕ работает (в mlx5_core нет
#      set_module_eeprom — проверено /proc/kallsyms; ethtool 7.1 CLI
#      --set-module-eeprom отсутствует)
#    - mstlink --cable --write (FW MCIA): РАБОТАЕТ на не-WP модулях
#      (DAC OEM SFP28-25G-CU1M — записан и верифицирован, сессия 2),
#      но: (а) данные дополняются НУЛЯМИ до dword — однобайтовая запись
#      затирает соседние байты в dword (live-порча/восстановление OUI+PN);
#      писать ТОЛЬКО aligned dword'ы со всеми 4 байтами, включая соседей;
#      (б) на оптиках OEM SFP-25G-SR — SILENT NO-OP на обоих HCA (in-band
#      блок — со стороны FW; «hardware WP» НЕ подтвердился: A0h записываема
#      программатором, A2h закрыта SFF-8472-паролем (снимается FF×8), а
#      пароли сессии 2 до A2h физически не доходили — page 1 алиасится в
#      A0h; см. §6 п.3 и §7.2);
#      fallback для WP-модулей — внешний программатор
#    ethtool -E <if> magic 0x… offset 0 length 128 < recoded.bin
#    (поддержку set_eeprom у mlx5 надо live-верифицировать; иначе программатор)
```

## 5. Целевая задача: SFP+/SFP28, рапортующие IB (для VPI-проектов)

Цель: на VPI-портах CX-4/CX-5 (проекты IB на SFP28-адаптерах,
см. `docs/050-hardware/100-inventory.md`, журнал `2026-09-13-sfp28-vpi.md`)
EN-трансивер SFP+/SFP28 должен рапортовать IB-скорости, чтобы проходить
FW-гейт cable-speed и поднимать IB-линк.

Байт-мап (сверено с парсером TransceiverTool и тем, что читает FW по docs/250-re/130-cable-gate/005-chain.md):

| Модуль | Поле | Значение |
|---|---|---|
| SFP+/SFP28 | SFF-8472 **A0h byte 3, low nibble** | пассивный DAC → `1X Copper Passive` (bit 0); активный DAC/AOC → `1X Copper Active` (bit 1); оптика MMF → `1X SX` (bit 3); SM → `1X LX` (bit 2). EN-биты high nibble можно оставить |
| SFP+/SFP28 | byte 36 (Ext. Compliance) | **не трогать** — IB-кодов в SFF-8024 нет, EN-значение не мешает |
| SFP+/SFP28 | byte 12/13, 62 | по желанию под реальные возможности линка (25G SFP28 → EDR-рейтинг 1x) |
| SFP+/SFP28 | CC_BASE (byte 63) | пересчитать — крывает byte 3 (в TransceiverTool — бесплатно, "auto") |
| QSFP/QSFP28 | SFF-8636 **byte 164** Extended Module Codes | минимум SDR (bit 0); + DDR/QDR/FDR/EDR по реальным возможностям; CC_BASE@191/CC_EXT@223 — авто |

Инструмент живой перекодировки QSFP (byte 164) — `scripts/sfp_recode.py`
(запись через карту, eeprom-доступ mstflint): `0x07 → 0x0f` (включить
FDR-бит) + пересчёт CC. Контроль A/B на стоке —
`docs/250-re/100-formats/070-transceiver-eeprom.md` §2 (byte 164
`0x07↔0x0f` ↔ SCS `0x0f↔0x1f` бит-в-байт). Результат: SCS 0x1f, живой
IB-FDR.

SFP+ за QSA (QSFP-порт, 2026-10-10,
`docs/250-re/100-formats/070-transceiver-eeprom.md` §3.1): дополнительно
**byte 0 = 0x11** (QSFP28-идентификатор — QSFP-порт выбирает карту по
identifier) + **byte 164 = 0x0f** (верхняя половина A0h, вне покрытия
CC); CC_BASE@63 пересчитать (byte 0 в зоне 0–62): Σ(0..62), `0x7c→0x8a`.
Верхняя половина A0h (128–255) write-protected — сначала FF×8-unlock
A2h (volatile — повторный unlock после каждого power cycle, §7.2).

Прецедент: QSFP28 SR4 со **SDR-рейтингом** уже прошёл гейт (журнал 09-13:
mstlink «Supported Cable Speed: SDR», IB-линк поднялся) → достаточно
минимального IB-бита. Контроль после записи: `mstlink -d <dev> -m` —
«Supported Cable Speed» ≠ 0, PDDR opcode ≠ 26.

Косметика: opcode 25/26 «Cable speed not enabled» — **не блокер**: живой
FDR-линк с opcode 25 и QDR-AOC-линк с opcode 26 (прецедент CX-4 Lx
воспроизведён); после C12 opcode 26 ушёл в 0 сам (FW-гейт/C12 —
`docs/250-re/130-cable-gate/002-transceiver-ib-gate.md`).

QSFP→SFP переходники с собственной EEPROM («EN-only») упираются в
СТОК-конец линка (родной гейт партнёра), не в C12-порт. Собственная
EEPROM переходника (адрес 0x54, 256 Б) карте не видна — карта читает
только 0x50, т.е. видит модуль ЗА QSA (журнал
`docs/superpowers/journal/2026-10-10-qsa-eeprom-recon.md`).

## 6. Риски и открытые вопросы

1. **FW-маппинг compliance→speed не RE'ен до конца** (стена docs/250-re/130-cable-gate/010-wall.md).
   Перекодировка готовит модуль «по спецификации», но 100%-прохождение гейта
   подтвердит только live-тест. Возможно, FW смотрит и на другие поля
   (косвенный намёк — строка «FDR10 speed is not supported on non-Mellanox
   cable»: может проверяться vendor OUI).
2. **Активные кабели (AOC/retimer DAC)**: перекодировка A0h не меняет
   поведение силикона внутри кабеля — хост увидит IB-коды, но ретаймер может
   не вытянуть IB-скорости. Пассивный DAC честнее.
3. **Запись в EEPROM может быть закрыта: hardware WP-pin, soft
   write-protect/password (A2h byte 127 — вне покрытия TransceiverTool).
   Live 2026-10-04, сессия 1+2 (журнал `2026-10-04-transceiver-ib-bit-live.md`):**
   оптика OEM SFP-25G-SR (OUI 00:17:6a) — молча игнорирует запись через MCIA
   на обоих i2c-адресах и двух разных HCA; **все 28 известных паролей**
   (включая Finisar 9bb03dfa; запись в A2h 119-126 разрешена спекой даже на
   залоченном модуле) **не оживили запись** → у оптик **hardware WP**, не
   soft-lock. При этом **пассивный DAC OEM SFP28-25G-CU1M (OUI Mellanox)
   на том же CX-5 пишется свободно** → no-op — свойство модуля, не HCA/порта.
   Отсюда же live-факт: у этих OEM-модулей **не спековая CC-конвенция** —
   stored CC == Σ (не 2's-complement); FW mlx5 на неё не ругается.
   Механика writer'а: mstlink `--cable --write` дополняет нулями до dword и
   **затирает соседние байты того же dword** — однобайтовые записи портили
   OUI/PN DAC'а (восстановлены); писать только aligned dword'ы.
   Fallback для WP-модулей — внешний программатор.
   **Обновление 2026-10-07 (глава 1 арки, программатор):** вердикт
    «hardware WP оптики» снят — A0h записываема напрямую (живой дамп ==
    исходному после обратимой пробы), A2h закрыта **SFF-8472
    password-гейтом**, снимается паролем **FF×8** (§7.2). Вердикт сессии 2
    «28 паролей не помогли» невалиден: `mstlink --cable --page 1`
    алиасится в A0h (сессия 5), пароли до password-entry area A2h физически
    не доходили; повторная парольная работа программатором (6 кандидатов +
    FF×8) — журнал `2026-10-07-transceiver-ib-ch1-dac-optics-task-06r.md`.
    **Обновление 2026-10-10 (QSA-эксперимент, журнал
    `2026-10-10-qsa-sfp-ib-recode.md`):** записываемость A0h — половинная.
    Нижняя половина (0–127) — writable без unlock (гл. 1); верхняя
    (128–255) — write-ignored в locked-состоянии (тест 0x5A@164
    проигнорирован, тест 0x5A@100 закоммитился) — за тем же A2h
    password-гейтом. **FF×8-unlock volatile**: после power cycle
    pwd-area откатывается (`07 00 17 00…` → `03 00 17 00…`) и верхняя
    половина A0h залочивается снова; повторный unlock тем же FF×8
    работает.
    **Обновление 2026-10-17 (цикл персона+идентичность, журналы
    `2026-10-17-transceiver-qsa-persona-identity-task-02.md` /
    `-task-03.md`):** расхождение внутри одной детали (OEM SFP-25G-SR,
    OUI 00:17:6a) — A0005 vs A0006: A0005 A0h записывается (нижняя
    половина без unlock, верхняя — FF×8) и 8636-идентичность вшита;
    A0006 A0h **полностью write-ignored (обе половины, включая нижнюю)**
    против всех 57 password-кандидатов (28 STH ×2 варианта + FF×8) —
    **модуль-специфичный A0h-лок**, не связанный с A2h password-гейтом
    (тот у A0006 снят pw-01b `00 00 10 11`; FF×8 A2h A0006 НЕ снял).
    Вердикт «hardware WP оптики SFP-25G-SR» (2026-10-04) снимался
    программатором только для A0005 (2026-10-07); для A0006 он
    фактически в силе — не снимается известными отмычками (сервисный
    режим / другой программатор / замена модуля — решение владельца,
    TODO.md).
4. Физика: EN DAC 25G под IB QDR/FDR поднимет линк, только если SerDes модуля
   реально дотягивается до рейтинга.
5. `ethtool -E` на mlx5 — не работает (live 2026-10-04, см. §4 шаг 6);
   in-band writer отсутствует, MCIA-write уходит в WP → fallback — внешний
   программатор (единственный проверенный путь записи на данном железе).
6. Если live-гейт потребует полей вне A0h lower 128 Б (например, A2h/upper
   pages SFP28) — нужна hex-правка руками. **Live 2026-10-04, сессия 5:
   A2h in-band недостижим — `mstlink --cable --page 1` на FW 14.32.1900/
   16.35.4030 алиасится в A0h** (read И write; верифицировано: запись
   [00,00,64,00] @page1/offset220 легла в A0h[220..223], сосед A0h[223]
   0x91→0x00 затёрт, восстановлен [00,00,00,91]; зона 128–255 вне сумм).
   Трактовка сессии 2 «page 1 = i2c 0x51 = A2h» опровергнута → пароли
   сессии 2 писались фактически в A0h[119..126] (безвредно, оптика WP).
   Не проверяемо: не попадает ли page-1-запись одновременно в A2h.
   Отдельный live-факт сессии 5: **FW кеширует module info с plug-события**
   — после записи EEPROM гейт/PDDR переоцениваются только при перетыкании
   (или port-toggle), само за 60+ с не переопрашивается.
 7. Live-инвентарь SFP28-клеток root-mellanox (2026-10-04): 2× одинаковые
    оптики OEM SFP-25G-SR (SN A0003/A0004, CDR onboard, byte 3 =
    0x00, byte 36 = 0x02, **in-band не пишутся**; WP-диагноз снят 2026-10-07,
    см. п.3/§7.2) и **пассивный DAC OEM
   SFP28-25G-CU1M (SN CU1M, OUI 00:02:c9, byte 3 = 0x00, byte 60 =
   0x01, CC:=Σ — ПИШЕТСЯ свободно, перекодирован под IB 2026-10-04 сессией 2**:
    byte3 → 0x01, CC_BASE 0xd7→0xd8; **оба конца приведены к этому состоянию —
    сессия 3 верифицировала и дозаписала второй конец**; побайтовая
    верификация md5
   092e1f93d99116f5b5f0f2d7e5afc0fc; журнал
   `2026-10-04-transceiver-ib-bit-live.md` §«Сессия 2»; бэкапы и финальный
   дамп `/root/transceiver-ib-bit/dac-cu1m-*`). Видимые QSFP28 100G
   DAC — на 81:00.1/41:00.0. Для WP-оптик после внешнего программатора:
   патченный образ готов (byte3→0x08, CC_BASE 0x74→0x7C по конвенции CC:=Σ;
   спековый 2's-complement вариант 0x84 — запасной).

## 7. Внешний программатор: PACBTECH «SFP Code changing Board» (CH341A)

Bring-up 2026-10-04 (журнал `2026-10-04-ch341-programmer-bringup.md`):
плата-программатор с клетками QSFP/SFP/XFP, внутри CH341A
(`1a86:5512`, «EPP/MEM/I2C mode»). Вендорский софт — виндовый Qt5
поверх CH341DLL, смысла нет (запись за паролем из их pwd.db).

- **Драйвер ядра**: in-tree `spi-ch341` (kernel 7.2, `/lib/modules/.../spi/`)
  подселивает на устройство и мешает I2C. Отцепить обратимо:
  `echo '1-3:1.0' > /sys/bus/usb/drivers/spi-ch341/unbind`
  (именно `1-3:1.0`, интерфейс; вернуть — через `bind` с тем же аргументом).
- **I2C — userspace, pyusb**: `scripts/ch341i2c.py` в репо + контейнер
  `docker/ch341i2c.containerfile` (образ `mlxini-ch341i2c`, python3-pyusb).
  Запуск с хоста-станции (CRE из Makefile):
  `make ch341i2c-run ARGS="--addr 0x50 read 256 --decode-a0"`.
  Контейнер идёт с `--privileged` (не `--device`): rootless-podman не
  пускает usbfs-ноды (major 189) через device-cgroup даже при
  MODE=0666; на хосте — udev-rule `/etc/udev/rules.d/99-ch341-sfp.rules`
  (`SUBSYSTEM=="usb", ATTR{idVendor}=="1a86", ATTR{idProduct}=="5512",
  MODE="0666"`) и отцеплённый `spi-ch341`.
  Ключевой live-факт: I2C-стрим = **bulk OUT, первый байт 0xAA**
  (не 0x1A — с ним чип молчит; 0xAA подтверждён драйвером frank-zago
  и CH341DLL). Проба ACK: `OUT|0` + адрес → status-байт на bulk IN,
  бит 0x80 = NAK. SFP: A0h = 0x50, A2h = 0x51; скорость 100 кГц (SET|1).
  **Чтение**: `… read 256 --decode-a0`; **запись** (после добра
  координатора): `… write <образ>` (probe ACK → кадры по ≤9 Б данных /
  ≤16 Б на кадр — 32Б-кадры stall без ZLP, см. §7.2 → verify read-back).
  GPIO/питание клетки не управляются — вендорский
  софт тоже только `CH341StreamI2C`, плата «тупая» (I2C клеток
  напрямую на CH341).
- Live-статус bring-up: контейнер собран, smoke против живой платы
  прошёл (CH341 version 48.00, probe → корректный NAK на пустой
  клетке), **ожидает модуля в клетке**.

### 7.1. Список SFP/QSFP password-entry паролей (STH) и статусы применения

Источник-канон — STH-тред «Transceiver password collection»:
<https://forums.servethehome.com/index.php?threads/transceiver-password-collection.39458/>
(владелец давал ссылку дважды; список ниже идентичен треду).
Провенанс копии в репо: восстановлен из opencode-логов (исходный бриф
сессии 2, `msg_1064a5760001CXOP3ljKicqNfZ`, сессия `ses_ef9b5a8a2…`;
повторно восстановлен 2026-10-07 анализом логов — до этого списка НЕ
было ни в одном доке/журнале, только в сессионных логах).

28 четырёхбайтных паролей password-entry (SFF-8472 A2h 123–126 /
SFF-8636 page0 123–126; 8-байтовая запись в 119–126 = pwd + нули или
нули + pwd — оба варианта «a»/«b» готовятся):

```
01 00 00 10 11   default QSFP           15 09 05 02 07
02 9b b0 3d fa   Finisar                16 a0 a1 a2 a3
03 4f 43 50 00   Infinera/OPLINK        17 48 58 50 52   "HXPR"
04 78 56 34 12                          18 fc d3 a6 35
05 63 73 77 77   "csww" (Ubiquiti)      19 cf 45 4d 20
06 53 46 50 58   "SFPX" (Ubiquiti)      20 82 52 53 39
07 80 81 82 83   Ubiquiti QSFP28        21 46 45 53 55   "FESU"
08 51 53 46 50   "QSFP" (Ubiquiti)      22 f0 04 2a b9
09 22 24 28 27                          23 f0 02 0a ab
10 02 02 02 02                          24 41 6b 34 37   "Ak47"
11 58 47 52 44   "XGRD"                 25 f0 05 1a ba
12 80 00 00 03                          26 f0 51 7a b7
13 38 34 37 32   "8472"                 27 aa bb cc ad
14 38 34 37 33   "8473"                 28 c8 d9 ea fb
справочно: ff ff ff ff («без пароля»)
```

Готовые pw-файлы (по 8 Б, варианты a/b): `build/pw/pw-NN{a,b}.bin`
(генератор + драйвер: `/tmp/opencode/pw-brute.py`, mk_pw в журнале
task-03). Статусы применения (по состоянию на 2026-10-07):

- **OEM QSFP-100G-CU1M (SN QSFP100G-A / QSFP100G-B / мёртвый
  QSFP100G-DEAD)**: password-entry area (119–126) сама write-ignored —
  запись пароля отбрасывается (verify 2/8, read-back нули), т.е.
  парольная механика недоступна; вывод «hardware WP всего A0h» — но
  НЕ проверен ACK/NAK-статус транзакции записи (диагностика
  `scripts/diag_wr_ack.py` подготовлена и НЕ запускалась — квота
  агента; следующий дешёвый шаг: NAK на data-байтах vs ACK-and-drop).
  **КОРРЕКЦИЯ (2026-10-08, глава 1 арки):** статусы применения этого
  пункта писались pre-fix-тулингом — все записи гл. 2 шли кривыми
  кадрами OUT|N (well-formed запись не отправлялась ни разу; фиксы
  97db39e/ad98558, §7.2), вердикты programmer-записей недействительны.
  Ретест фиксированным тулингом — TODO (первый кандидат — FF×8, рабочая
  отмычка SFP-оптики). Read-дампы гл. 2 в силе.
- **OEM SFP-25G-SR (оптика A0003/A0004)**: все 28 не сняли no-op
  (сессия 2, in-band). Коррекция 2026-10-07: «hardware WP» снят — пароли
  до A2h не доходили (page-1 алиасинг), программатором A0h записываема,
  A2h = SFF-8472 password-гейт (FF×8, §7.2); in-band no-op сам по себе
  в силе.
- **OEM SFP28-25G-CU1M (DAC, SN — реестр `DAC_CU1M_SN`)**: пишется СВОБОДНО, без
  пароля (in-band mstlink MCIA, сессии 1–2) — пароли не требуются.
- **pwd.db вендорского софта PACBTECH/YxFiber**: SQLCipher
  (AES-256-CBC, PBKDF2-SHA1 64k), ключ захардкожен в exe:
  `ChenLaoShi_YxFiber@123`; customer-копия БД пуста (вендор затёр 20
  паролей до отгрузки). Расшифровка полной копи: `scripts/pwddb_full.py`.
  Журнал `2026-10-06-pwddb-re.md`.

### 7.2. Глава 1 арки (2026-10-07): записываемость модулей + механика write-пути

Журналы: `2026-10-07-transceiver-ib-ch1-dac-optics-task-{02,03,04,04r,05r,06,06r}.md`;
транспорт на сервере — `2026-10-07-ch341-recon.md`. Вердикт гейта —
docs/250-re/130-cable-gate/005-chain.md; здесь — EEPROM/write-факты.

**Write-путь (два бага найдены и закрыты на живом железе):**

- **OUT|N-токен считает ВСЕ байты на шине, включая адрес** (как в чтении):
  правильный токен `OUT|(len+2)`; `OUT|(len+1)` превращает первый байт
  данных в стрим-токен, STO/END уходят на шину как данные (порча хвоста
  страницы при следующем START; данные с ведущим 0x00 вообще не передаются
  — 0x00 = END рвёт стрим сразу после dummy write). Фикс — 97db39e.
- **32-байтовые USB-кадры без ZLP зависают** (CH341 stall; на станции
  валил адаптер насмерть до replug): кадр ограничен 9 байтами данных
  (кадр ≤16 Б) — фикс ad98558 (`make test-parallel` — 860 passed).
- **IN-drain после каждого кадра** обязателен; **статус-байт write-кадра
  не приходит ни разу за всю историю rig'а** (IN-timeout, толерантно;
  probe-статус при этом приходит стабильно) — истина это verify/read-back,
  не статус-байт. **Open question закрыт 2026-10-17** (журнал
  `2026-10-17-transceiver-qsa-persona-identity-task-02.md`, раздел
  «Диагностика write-ACK»; `scripts/diag_wr_ack.py`, post-fix тулинг):
  статус-байт write-кадра **не доставляется** — USBTimeoutError (bulk IN,
  2000 мс) единообразно и для A0h, и для разлоченного A2h (контроль: тот
  же write-путь к A2h — запись закоммитилась; к A0h — игнорирована) —
  свойство CH341 stream-протокола, не баг тулинга; «NAK-on-data vs
  ACK-and-drop» по status-байту неразделимо.
- Ловушка образа: entrypoint контейнера — запечённый PRE-fix
  `/usr/local/bin/ch341i2c`, монт `/work/scripts` им игнорируется; фиксовый
  код — только `--entrypoint python3 … /work/scripts/ch341i2c.py` (89d5058).
  Транспорт мигрировал на root-mellanox (podman, скрипты scp с md5-контролем)
  после kernel USB-wedge станции root-localhost (ждёт ребута владельца).

**Записываемость (live-вердикты):**

- **DAC SFP28-25G-CU1M (SN — реестр `DAC_CU1M_SN`), A2h** — blank-0xFF die, полностью
  **writable** (H1: verify OK 34 Б, побайтовый cmp, 30-с персистентность,
  оба конца). «Нули A2h» ethtool-дампов — фабрикация FW (модуль DDM-less);
  «transaction-hang = свойство модуля» (сессии 7–8) — артефакт кривых
  кадров. Оба конца сейчас LE-перекодированы (222=0x64 / 223=0x00 /
  CC@255=0xe7, md5 A2h 6dbd55cc…).
- **Оптика SFP-25G-SR (A0005)**: A0h — половинная (уточнение 2026-10-10):
  нижняя половина (0–127) writable без unlock (гл. 1; восстановление
  byte-exact, включая byte 3=0x08 + CC_BASE 0x7c), верхняя (128–255) — за
  тем же A2h password-гейтом (locked: write-ignored, тест 0x5A@164).
  **A2h — SFF-8472 password-гейт**: запись **FF×8** в password-entry area
  119–126 снимает его (unlock-тест 0x5A@250 коммитится, verify OK).
  **Unlock volatile** (2026-10-10): после power cycle pwd-area
  откатывается (`07 00 17 00…` → `03 00 17 00…`), верхняя половина A0h
  залочивается; повторный unlock тем же FF×8 работает. Семантика:
  **неверный пароль отбрасывается молча** — сигнатура неотличима от
  hard-WP (у всех неверных кандидатов verify-fail такой же, как у «весь
  A2h write-ignored»); **PWF write-only** — read-back pwd-area не
  отражает вход пароля даже при успехе (у рабочей отмычки FF×8 verify
  самой парольной записи 8/8 FAIL). После unlock модуль ведёт свою
  бухгалтерию в pwd-area (байты 119: 03→07, 126: 00→10 — оставлено как
  есть, процедуры re-lock нет). A2h recoded: 223=0x64 (ext BR QDR BE),
  CC_A2@255=0x61.
- **Состояние A0005 (2026-10-10, решение владельца — оставить):**
  QSFP28-личина — A0h byte 0=0x11, byte 164=0x0f, CC_BASE@63=0x8a
  (3 байта, verify OK, 30-с персистентность; pre/post md5
  044a31d2…/04bea220…, образы `build/a0005-pre-qsa-recode-20261010.bin` /
  `build/a0005-qsa-recode-post-20261010.bin`; restore = pre-образ, для
  верхней половины нужен FF×8-unlock). byte 3=0x08, SN, A2h не тронуты.
  Live: за QSA на стоке 41:00.1 — SCS 0x1f, opcode 25, IB-FDR 1x
  Active/LinkUp, фабрика поднялась
  (`docs/250-re/100-formats/070-transceiver-eeprom.md` §3.1).
- **Состояние A0005 (2026-10-17, цикл персона+идентичность, журнал
  `2026-10-17-transceiver-qsa-persona-identity-task-03.md`):** вендорская
  идентичность вшита в 8636-позиции (name 148–163, OUI 165–167, PN
  168–183, SN 196–211 — побайтовая копия собственных SFF-8472-полей; 8636-CC
  пересчитаны plain Σ: 191=0x67=Σ(128..190), 223=0x4f=Σ(192..222));
  QSFP28-персона (byte 0=0x11, 164=0x0f, CC_BASE@63=0x8a) —
  предшествующая (2026-10-10), не тронута (вне манифеста). pre/post md5:
  `ea50f96e211918dcb0591e79e282b291` → `af6aed04f4ada1eb05760c0ec06789b6`
  (post == persona byte-exact: verify 256/256 + 30-с персистентность);
  A2h `037e0f7387b889964b3d097885526094` → `2b97be38946c1f72b9a7058dd3bb55ce`
  (diff в allowed-наборе: pwd-бухгалтерия 119: 03→07, 126: 00→10 +
  real-time-дрейф diag-блока 0x60..0x6b). Unlock — FF×8 с первого раза
  (прецедент 2026-10-10 подтверждён). Live после возврата в c1:00.0 (карта —
  реестр `CARD_CX4LX_XCAT`): G4-здоровье (ГЕЙТ-5) PASS — модуль читаем, DDM жив
  (QSFP28-декод-сигнатура 0 / 822.4 / 41.050 / 0 — статична, побайтово
  идентична 2026-10-10), Polling, Identifier QSFP28, SCS 0x1f; дисплей
  **ВАРИАНТ (а)** — вендорские поля ВИДНЫ в SFP28-слоте (Vendor Name OEM /
  PN SFP-25G-SR / SN A0005; до записи — N/A) → карта отдаёт
  полные 256 Б A0h в SFP28-слоте (open question
  `docs/250-re/100-formats/070-transceiver-eeprom.md` §3.1 резолвлён).
- **Состояние A0006 (2026-10-17, отрицательный результат, журнал
  `2026-10-17-transceiver-qsa-persona-identity-task-02.md`):** модуль
  НЕ изменён — A0h == pre byte-exact (md5
  `0fdccdee105897f7411baee093f21410`; 3 независимых чтения), исходная
  идентичность SFP-25G-SR (byte 0=0x03), QSFP28-персона НЕ вшита (образ
  собран, не применён — md5 `98e33d3e090583a90662274c649d70d4`). **A0h
  write-ignored — обе половины, включая нижнюю (у A0005 writable без
  unlock) — против всех 57 password-кандидатов (28 STH ×2 варианта
  + FF×8) — модуль-специфичный A0h-лок**, не связанный с A2h
  password-гейтом (транспорт/тулинг здоровы: контроль тем же write-путём
  к разлоченному A2h — запись закоммитилась). A2h-гейт снят pw-01b
  `00 00 10 11` (default QSFP, вариант b, pwd @123–126 — spec-позиция
  SFF-8472); **FF×8 A0006 НЕ снял** (тест 0x5A@250 не закоммитился). A2h
  md5: pre `3e7e47ef4d6313f2246954d11f503716` → final
  `92dd81f183dbea1f3f281a4856cc22e6` (diff только allowed-набор: pwd-
  бухгалтерия — финально 119: 0x03→0x07, 126 вернулась к pre (0x00) после
  лестницы; + real-time-дрейф diag-блока 0x60..0x6B; @250 восстановлен
  0x00). Live после возврата в c1:00.1 (та же карта): G4-здоровье (ГЕЙТ-5)
  PASS — модуль читаем, DDM жив (Voltage 3351.3 мВ, Bias 6.966 мА×4, Tx −4
  dBm, Temp 40 °C — в номинале; Rx −40 dBm — floor «нет света», не сбой),
  Polling, Identifier SFP28/SFP+; отображение — исходная SFP-25G-SR
  (без изменений vs pre-state). Дальнейшие варианты (сервисный режим /
  другой программатор / замена модуля) — решение владельца (TODO.md).
- **CC-конвенции**: CC_BASE/CC_EXT — plain Σ (live-подтверждена многократно);
  **CC_A2@255 вендор не ведёт** — на живом контенте stored 0x00 при
  Σ(128..254)=0xfd (модуль при этом штатно работает — FW чтение A2h по
  CC_A2 не гейтит); при записи A2h пересчитывать Σ (после рекода 0x61==Σ).

## Ссылки

- `docs/250-re/130-cable-gate/005-chain.md` — RE FW-гейта cable-speed (opcode 26).
- `docs/superpowers/journal/2026-09-13-sfp28-vpi.md` — SFP28 VPI-эксперименты,
  прецедент QSFP28 SR4 со SDR-рейтингом.
- `docs/superpowers/journal/2026-10-04-transceivertool-ib-recoding.md` —
  журнал данного исследования (файлы/строки TransceiverTool).
- `refs/src/TransceiverTool` — инструмент (README.MD, schemas/, src/Standards/).
