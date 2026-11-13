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
| boot2 | 0x1000 | payload 0x3f34 (чёрный ящик OSS mstflint, CRC-only `CheckBoot2`) |
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
- Следующий инструмент вскрытия ROM-этапа — дамп mask ROM:
  `docs/850-howto/130-rom-dump.md`.
