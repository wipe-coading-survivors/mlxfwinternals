# 030. Root of trust: что и где карта проверяет

> Источник: офлайн-RE 9 образов + Ghidra-декод (журналы
> `2026-09-20-fw-iron-boot-chain`, `2026-09-20-ghidra-main-signing-re`);
> live `q` CX-6 (2026-09-18); VFIO-серия и разбор синдиката (журналы
> `2026-09-20-irisc-live-vfio-dump-2/-3/-4`); вердикты актуализированы
> циклами securefw-gates (2026-10-29), cx6dx-securefw (2026-10-30),
> cx6dx-introspection (2026-10-31) — отчёты `docs/superpowers/reports/`,
> реестр легенд `docs/superpowers/reports/2026-10-28-securefw-legends.md`.
> Связи: механизм/секции → `005-mechanism.md`/`015-key-sections.md`; SB-формулы
> → `025-secure-boot.md`; ключ-резолв burn-verify (CX-5) → `040-key-resolve.md`;
> CX-6Dx-якорь → `055-cx6dx-signing.md`; secure_fw-бит карты (MGIR) →
> `065-secure-fw-bit.md`; boot-injection PoC →
> `250-re/120-irisc/025-boot-injection.md`; live-гейты →
> `750-exp/170-securefw-live-gates.md`.

## 1. Что определяет проверку — устройство, а не образ

- Что проверяет карта — определяется **security-режимом устройства**
  (life-cycle / secure-boot), а не флагами образа (флаги IMAGE_INFO — не
  индикатор и не переключатель: `015-key-sections.md` §4). Life-cycle читается
  с карты: `getLifeCycle` (`fw_ops.cpp:2981`), `IsLifeCycleSecured`
  (`fw_ops.cpp:3040`): `version_field==1` → FS5 `PRE_PRODUCTION`/`PRODUCTION`,
  иначе `FS4_LC_GA_SECURED`.
- **Non-SB SKU**: `CARD_CX6_LOCALHOST` (04:00.0, PSID `MT_0000000226`,
  FW 20.43.4100) отчитывает **`Security Attributes: N/A`** — бутлоадер
  RSA-подпись **не проверяет**, образ принимается по совпадению
  PSID/device_id.
- **SB-карта**: бутлоадер сверяет RSA-подпись с корневым публичным ключом.
  Все легитимные signed-образы подписаны общим ключом `c55d54e8…`
  (`005-mechanism.md`, приложение) ⇒ инференс «root-of-trust = публичная
  половина этого keypair, зашитая в силиконе/OTP» (стандартная схема secure
  boot; сам код бутлоадера в репо отсутствует — часть прошивки). Исходный
  инференс актуализирован вердиктами §3: для CX-5 он опровергнут как
  источник MCC-verify-ключа и boot-гейт код-подписи, для CX-6Dx GA SECURED —
  подтверждён на уровне «якорь вне flash».

## 2. Модель бут-цепочки: HW-указатели и SHA-константы

**HW pointers** (carmel, 16×8B @0x18..0x98, имена `image_layout_layouts.h`;
AC-образ, сверено с флэш-адресами; журнал `2026-09-20-fw-iron-boot-chain`):

| pointer | значение | что указывает |
|---|---|---|
| boot_record | 0x100 | boot record (CRC-аутентификация, `docs/250-re/100-formats/030-fs4.md`) |
| boot2 | 0x1000 | payload 0x3f2c = (4+DW1)·4, DW1=0xfc7 (эрратум 2026-11-14: ранее «0x3f34» — fb-выемка с +8 B хвостом за регионом; CRC-верифицировано) — чёрный ящик OSS mstflint, CRC-only `CheckBoot2` |
| toc | 0x5000 | ITOC |
| tools | 0x500 | tools-блок |
| authentication_start / end | 0x0 / 0x6fff | **окно SB v1-подписи** |
| public_key_pointer | 0x6b4480 | секция **0xA6** FS4_RSA_PUB_KEY |
| digest_pointer | 0x6b5580 | секция **0xA7** FS4_RSA4096_SIGS |
| hashes_table | 0 | не активна (`docs/250-re/100-formats/035-fs4-hashes.md`) |

Окно SB v1 `[auth_start..auth_end]` = **[0x0..0x6fff]** = «iron image»
(magic + version + HW pointers + boot_record + tools + boot2 + ITOC): ROM-этап
подписывает/проверяет только boot-преамбулу; формулы и parity — `025-secure-boot.md`
§3. Рантайм-код (IRON_PREP/MAIN) через эти же указатели может читать публичный
ключ (0xA6) и подписи/десты (0xA7/0xA0/0xA3) из флэша.

**SHA-константы в кодовых секциях** (K256 = 64×4B, K512 = 80×8B, H512 = 8×8B;
K256 у всех 9 в MAIN_CODE; отдельной H256-таблицы нет — её 8 слов = старшие
32 бита слов H512):

| | K256 в 0x05 IRON_PREP | K256 в 0x03 MAIN | K512+H512 |
|---|---|---|---|
| CX-6Dx×2, CX-6 | да (в хвосте секции) | да | да (MAIN) |
| CX-5 16.35 (1012/8008/4030) | да | да | **нет** |
| CX-5 Dell 16.27 signed | нет | да | да (MAIN) |
| CX-4/CX-4Lx (FS3) | нет | да (de-clcrc-вид) | да (MAIN) |

Факты:

- Крипто-разделение этапов: SHA-512-таблицы есть только в MAIN_CODE ⇒ полная
  RSA-4096/SHA-512-проверка не может выполняться в IRON_PREP; ранний бут
  располагает только SHA-256 (digest-проверка v1-типа и/или измерение).
- SB v1 покрывает только boot-преамбулу [0x0..0x6fff]; содержимое MAIN_CODE —
  в подписи `non_critical` (остальные ITOC-секции) или hashes-table (v2).
- Гипотеза исходника «fw-update-подпись (RSA) проверяется на этапе, где есть
  SHA-512 — в MAIN_CODE или крипто-юните ROM» — **закрыта декодом**: софтовый
  RSA/SHA-512-verify находится в MAIN_CODE и вызывается только из MCC
  burn-verify (CX-5 8008: `040-key-resolve.md` §1-3; CX-6Dx: компаратор
  runtime-only, бут-пути нет — PROVEN, `055-cx6dx-signing.md` §6).
- Эмпирика: ROM/SB-бутлоадер грузит образ с битой RSA (FNP-кейс) → RSA — не
  блокатор ROM-этапа (CX-5); unsigned/чужой PSID — не грузится (проверка на
  этапе с SHA-256 либо в ROM).

### 2.1 Ghidra-RE: на K/H-таблицы нет ld.i-ссылок (негативный результат)

Ghidra 12.1.3 + iRISC-модуль, MAIN_CODE CX-6Dx AC 22.50 (de-clcrc, 5.7MB,
1 309 757 инструкций ~92% покрытия; журнал `2026-09-20-ghidra-main-signing-re`):
FIPS-таблицы полные, сверены байт-в-бит — K256 @0x565830 (64 слова), K512
@0x565930 (80 слов), H512 @0x565bb0 (8 слов). `getReferencesTo` по региону
[0x565800, 0x565c50) → **0 ссылок** (метод верифицирован на known-good цели);
IRON_PREP 0x05 (184KB, 40 312 insns ~87%, K256 @0x2d128) — та же картина,
NREF 0.

Ограничение метода: `ld.i r,IMM` — не единственный доступ к памяти; регистровые
`ld.d/ld.w/ld.b/ld.q.17/lw.r/st.*` (база-регистр + смещение) ссылок не строят ⇒
NREF 0 = «нет ld.i-ссылки», а не «таблицы не используются» (расширенный проход
RefTargets.java по хвосту MAIN [0x560000, 0x572780): 57 ref, все
CONDITIONAL_JUMP, ни одного READ/WRITE).

Актуализация исходных гипотез (a)–(d):

- (ii) «крипто в HW-юните» и (iii) «код в другой секции/недекодированной части» —
  **опровергнуты декодом**: verify — софтверный, в MAIN_CODE (CX-5 8008:
  rsa_verify 0x2b159c, customIV — константы imm в прологе transform, K512-таблицы
  в данных нет вовсе; CX-6Dx: якоря `055-cx6dx-signing.md` §2);
- (i) регистровый доступ — подтверждён косвенно (адресация слот-ридера/крипта
  регистровая);
- (iv) «таблицы = небут-функция/мёртвый код» для K512@0x565930 (CX-6Dx) — не
  разрешён окончательно (см. «Постулаты»).

## 3. Root-of-trust: вердикты (бывшие открытые вопросы №2/№3 + гипотеза H3)

**H3 «silicon-root — ключ установить нельзя в принципе» —
EXCLUDED** (гипотеза цикла securefw-gates, live, задача task-08 §11-12): контрольный
plain-burn нашего SS-образа после FNP-установки нашего вольта — PASS
(запуск/активация/линк) ⇒ верификация следует вольту, а не только кремнию;
silicon-root как единственный источник ключа отвергнут.

**№2 «root-of-trust = силикон» — закрыт с расщеплением по платформам**:

- **CX-5 secure_fw** (`CARD_HPE_CX516A`): для MCC-verify-ключа опровергнуто
  (H3 + H1: ключ резолвится из вольта **бегущего** образа — `040-key-resolve.md`);
  boot **код-подпись** с вендорским/кремниевым корнем не сверяет — live
  2026-10-29: наш self-signed образ (наш вольт + наша RSA) грузится в normal
  (реестр легенд №2 — ОПРОВЕРГНУТО live). Механизм самого
  secure-fw-**состояния** карты (как карта оказалась secure: mask ROM /
  заводской прожиг) — открыт
  (легенды №10: «нет fuse» — столь же недоказанная крайность, как «сертификат
  в силиконе»); NVRAM-гипотеза key-material опровергнута (`060-nvconfig-securefw.md`
  §3).
- **CX-6Dx GA SECURED**: бут-якорь **вне flash** — PROVEN confound-free
  (HB-b: VDA-тройка D1/a2d/a3c + FB-пара fbss/fbctl — `055-cx6dx-signing.md`
  §6); якорь пинит **вендорские ключи** на обоих boot-путях; локация —
  OTP/fuse/mask ROM, точный механизм не установлен (постулат ниже). На этом
  кремнии SS-доставка FW-модификаций закрыта по всем трём осям
  (digest/vault/certs).

**№3 «принимает ли SB-карта свой ключ» — закрыт с расщеплением**:

- **CX-5 secure_fw**: **да** на MCC-слое — после одной FNP-установки своего
  вольта все наши SS-образы льюются plain `-y burn` (H1 доказан end-to-end,
  «FNP once → plain onwards»; рецепт — `850-howto/180-securefw-recipes.md`).
- **CX-6Dx GA SECURED**: **нет** для бута: SS-образы устанавливаются во flash
  (FNP/recovery приём без reject-кодов), но не грузятся в normal; uuid-spoof
  (вендорский uuid + наш modulus) → burn REJECT 0x5 (`055-cx6dx-signing.md`
  §3); замена вольта/сертификаты/digest — не чинят (HB-b).
- Единый ответ на все поколения не выводится (legends №2: состояние CX-5 и
  CX-6Dx GA SECURED — разные механизмы).

## 4. Рантайм-наблюдение (вопрос №5): `0x0932` = QUERY_FLOW_TABLE, метод синдиката

- `0x0932` — **НЕ «ExecShellcode»**, а штатная PRM-команда **QUERY_FLOW_TABLE**
  (`mstflint/mtcr_ul/mlx5_ifc_stub.h:209`; PRM §12.14.5: input 16 B —
  opcode/op_mod/`table_type`@0x10/`table_id`@0x14, output 0x40). На непатченой
  GA-прошивке наш 0xC0B «shellcode»-пейлоад — невалидный QFT (лишний
  input_length, `table_type`=0, `table_id`=low32(args[0])) ⇒ фиксированный
  content-independent **BadParameter `0x1C2B78`** (подтверждён на 2 FW).
- Дискриминирующий тест (live 2026-09-20, журнал
  `2026-09-20-irisc-live-vfio-dump-4`): корректный QFT (16 B, `table_id`
  созданной таблицы, outlen 0x40) на 16.19.1200 → **status 0 + валидный
  flow-table context (0x40B)**; `0x930/0x931/0x932` дают разные корректные
  ответы ⇒ **скрытого exec-режима нет**; `badc0ffe@0x23f0` — sniffer-unlock
  (`ibdump.c:975-979`), к `0x0932` не относится.
- Метод синдиката (Pwnies/DIKU, Bornhack 2024, first-party): патч handler'а
  QFT в iRISC-миккоде («read command data to stack; call data on stack; write
  response from stack») + FNP-флеш патченого образа в жертвенную non-secure
  карту. **Воспроизведён** boot-injection PoC (2026-09-21, журналы
  `2026-09-21-irisc-fnp-burn-verify`, `2026-09-22+`; канон — аспект
  `250-re/120-irisc/025-boot-injection.md`): произвольное
  исполнение iRISC-кода на boot + host-видимый канал результата (marker
  `0xbadc0001` в CR 0x23f0, чтение через VSEC). Инструментарий: `irisc-asm`,
  CRC-тулзы, FNP; карта — `CARD_CX5_EDR100` (жертвенная, 81:00.0).
- **Live-воспроизведение на втором адаптере (2026-11-15, цикл cx5-rom):**
  FULL C1-композиция (QFT-детур + S2-v5l стаб, plain burn в non-secure
  карту `CARD_CX5_25G_BAZZITE` 03:00.0) — гейты G-boot/G-fallthrough/
  G-echo/G-exec **PASS**, канал ExecShellcode открыт; sampled-чтения RAM
  iRISC 24/24 (phase 2b), затем phase 3 (434 чтения, 14-регионная карта):
  код `0x800000..0xB97DC0` flash-EXACT; **mask ROM во всём достижимом
  32-битном пространстве НЕ найден** (пробы до 0xFFFF0000); лучшие
  кандидаты — runtime-only зоны A `0xB97E00..~0xCA8000` и B
  `0x1001000..~0x1078000` (LINK/HW_BOOT param0-зоны; не совпадают ни с
  одним байт-видом флеша — load-time-transform гипотеза); bulk-дамп зон
  был тогда заблокирован отсутствием egress (mode-B-POST live-опровергнут;
  закрыт фазой XIII — аддендум ниже). Журналы:
  `2026-11-15-cx5-rom-phase{1,2a,2b,3}.md`; рецепт: `850-howto/130-rom-dump.md`
  §6 live-статус.
- **Фаза XIII (2026-11-15/16, romdump-cx5): root-of-trust-вердикты по
  снятому материалу — mask ROM не наблюдаем; вопросы lifecycle/ключа
  остаются открытыми.** Съём: R-C3 echo-канал (перенос на bazzite-базу,
  echo ≠ чтение RAM) + reader-stub (адрес из input word0 → 10 слов/команда;
  40 872 команды, 0 wedge) + boot-проба (хук dc 0x1D594, CR-window сташ —
  канон-класс 0x23F0). Итог per материал:
  - **ROM не найден**: runtime — во всём достижимом 32-битном
    пространстве (пробы до 0xFFFF0000, зоны сняты целиком); boot — на 5
    кандидатах (вектор-окно 0x0, вход/головы зон B, голова A, апертура
    0xFFFF8000 — читается на boot без stall, значение 0). Ограниченное
    множество: «не найдено ≠ опровергнуто», silicon-only не утверждается.
  - **Кумулятив (2026-11-22, mtusb-i2c-hw O7): третий домен — out-of-band
    I2C CR — тоже ROM-невидим.** Livefish-сессия (CX-5 0x020d, FNP):
    13 кандидатов (бут-векторы 0x0/0x1000, головы зон A/B, апертура
    0xFFFF8000+соседи — перекрытие с boot-множеством XIII) — только
    сервисные паттерны декодера (счётчик addr>>2, филл f7f930f3, нули,
    алиасинг); I2C CR-интерфейс не декодирует ROM-апертуру. Итог трёх
    доменов: runtime + boot + i2c-CR — ROM нигде; декод-карта livefish —
    канон `140-oob-i2c/100-protocol.md` §4. Оставшиеся гипотезы без
    изменений: полный свип boot-окна, JTAG-класс, ITCM-поглощение
    (ROM не отображается ни на одну шину после бута).
   - **Зона A** (`0xB97E00..0xCA8000`, unique-runtime): голова зоны
     (слово @0xB97E00, однословная boot-проба RD-C v2) **== runtime уже
     ДО main-entry** — origin кода A = до-MAIN-стадия (вывод по голове,
     не по всей зоне); источник не установлен (ни одна из 73 byte-forms
     флеша не воспроизводит).
   - **Зона B** — составная: ч.1 unique-runtime loader-класс (голова
     @0x1001000 на boot-пробе — нуль: ч.1 заселяется после boot-точки
     пробы, не «после main-entry»), ч.2 байт-экзактная de-clcrc MAIN_CODE
     flash-копия [0..0x40000) @0x1040000 (staging/mirror — открытый
     RE-вопрос).
  - Implications (honest): **lifecycle-чтение и корневой ключ НЕ
    локализованы** (ROM-этап недоступен снятыми методами); boot≠runtime
    доказан (boot-стадия видит другое адресное пространство/контент) —
    до-MAIN загрузчик существует и работает вне наблюдаемого материала;
    путь сбоя CX-5 (нет recovery-PCIe) снятым материалом не прояснён.
    Что бы закрыло вопрос (формулировки, не план): систематический свип
    boot-окна инкрементальными CR-сташ циклами; внешние методы
    (JTAG-класс и т.п.). Журналы:
    `2026-11-1{5,6}-rom-dump-cx5-task-0{1,2,3,4}.md`; инвентарь/статус:
    `850-howto/130-rom-dump.md` §6.
- **Судьба вопроса №5 — закрыт**: канал рантайм-наблюдения существует
  (boot-injection), сама верификация декодирована статически (`040` — CX-5,
  `055` — CX-6Dx). Ранний вывод «entitlement-гейт / не обойти / dead-end» —
  ошибочен (снят 2026-09-20 по Bornhack-разбору + PRM).
- MTRC: iRISC-микрокодный **TRACER** (наблюдение, не memory-read),
  entitlement-закрыт на production/non-debug GA (MtrcCap write → `0x6C64FE`
  на 16.35.8008; 16.19.1200 закрытее `0x10300/0x6C4D48`) — мёртв (журнал
  `2026-09-16-ib-cable-gate-live-mtcr`).

## Постулаты / открытое

- [постулат] Механизм secure-fw-состояния CX-5 (mask ROM vs заводской прожиг;
  внешних чипов нет — legends №9; e-fuse-поверхность в тулчейне отсутствует,
  `060-nvconfig-securefw.md` §4).
- [постулат] Точный механизм бут-якоря CX-6Dx (OTP-fused modulus hash vs пин
  полной вендорской цепочки vs атрибут сертификата) — офлайн неразрешим
  (`055-cx6dx-signing.md` §7; отчёт `2026-10-30-cx6dx-securefw.md` §10).
- [постулат] Потребление K512-таблицы @0x565930 (CX-6Dx MAIN): ld.i-ссылок
  нет, регистровая адресация не трассирована (возможно мёртвые данные; §2.1).
- [уточнение (арка C roadmap 200, 2026-11-21; прямые read-only улики
  `superpowers/journal/2026-11-21-securefw-arc-c-task-06.md`, канон —
  `070-vpd-secure-state.md` §7.3)] Двухслойная модель (runtime-источник
  `MGIR.secured` поверх неизменного lifecycle-OTP): runtime-плоскости
  cfg-space VPD и q-lifecycle **исключены как корреляты secure-state**
  (2×2 «security × cfg-VPD-читаемость» — все клетки с пинами; q-lifecycle
  на CX-5 поколенчески гейтирована, n=4 вкл. secure). Источник
  `MGIR.secured` (образ vs чип) остаётся открытым — дискриминация
  запланирована спекой анлока `superpowers/specs/
  2026-11-21-securefw-arc-c-unlock-design.md` (owner-gated). На постулаты
  CX-6Dx-якоря (бут-якорь вне flash) не влияет.
- Следующий инструмент вскрытия ROM-этапа — дамп mask ROM:
  `docs/850-howto/130-rom-dump.md`.
