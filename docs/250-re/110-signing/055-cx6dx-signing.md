# 055. CX-6 Dx (FW 22.50): RE-якоря, burn-verify, бут-якорь вне flash

> Источник: цикл cx6dx-securefw (2026-10-30, offline-RE MAIN_CODE 22.50.1002 +
> live GA SECURED; отчёт `docs/superpowers/reports/2026-10-30-cx6dx-securefw.md`,
> журналы `2026-10-30-cx6dx-securefw-task-{01..10}` + uuidspoof) и цикл
> cx6dx-introspection (2026-10-31; отчёт
> `docs/superpowers/reports/2026-10-31-cx6dx-introspection.md`, журналы
> `2026-10-30-cx6dx-introspection-task-{01..08}`). Live-карта — CX-6Dx
> GA SECURED (bazzite 03:00.0, MT2892, PSID `MT_0000000457`); dc↔rt-калибровка
> — `docs/250-re/100-formats/045-fs4-dc-rt.md`.
> Связи: формулы V1 и VERSION_детект → `025-secure-boot.md`; вольты/слоты →
> `015-key-sections.md` (§3); root-of-trust / судьбы вопросов №2/№3 →
> `030-root-of-trust.md` §3; CX-5-вариант verify → `040-key-resolve.md`;
> рег-фильтр CX-5 → `050-spi-read-policy.md` §1; live-гейты →
> `750-exp/170-securefw-live-gates.md`.

## 1. Версия и формулы (CX-6Dx-специфика)

- **VERSION_1 активна на 22.50.1002** (детект и негатив-контроль V2 —
  `025-secure-boot.md` §1): hashes_table raw `0xFFFFFFFF` (→ 0x0 после fixup)
  = invalid; `getBootRecordSize` без кейса CX6DX — V2-путь mstflint на CX-6
  упал бы (MaskBootRecordCRC недостижим, V2 применяла бы только
  RemoveCRCsFromMainSection).
- **0xA3 (FW-update, RSA-4096/SHA-512)**: SHA-512 по [0..sizeOfImgData)
  (= max addr+size по ITOC, refs-база `0x792880`), маски FF: magic16 +
  ITOC-entry+data секций 0xA0 и 0xA3; **DTOC-масок НЕТ** (FS4 no-op);
  EM = PKCS#1 v1.5 DER DigestInfo(SHA-512).
- **0xA7 (SB V1)**: критический состав и parity — `025` §3. Обе подписи
  воспроизведены бит-в-бит (гейт `scripts/cx6secfw/parity_gate.py`). Вольты
  0xA4/0xA6/0xA7 входят в подписываемые данные 0xA3 ⇒ порядок сборки
  «вольт → подпись»; uuid в 0xA3.keypair_uuid — только из CLI `--key_uuid`.

## 2. RE-якоря (dc-пространство MAIN_CODE, rt = dc + 0x21000000)

| объект | dc |
|---|---|
| verify-компаратор (MCC VERIFY-стадия) | **0x404ad4** |
| rsa_verify_full (RSA-гейт, слот по device-индексу) | **0x4049cc** |
| 16-слотный uuid-скан (0xA1×8+0xA4×8) | **0x4047ac** (драйвер 0x40466c) |
| селектор банка вольта (device-state) | **0x24d708** (RAM[0xc110]/[0xc112]) |
| слот-ридер вольта | 0x3fe600 |
| крипто-ядро: rsa_verify / modexp / memcmp | 0x3fa18c / 0x3f9dc8 / 0x3f9d5c |
| DER DigestInfo SHA-256 / SHA-512 | **0x565800 / 0x565818** |
| K512-таблица (данные, не imm-квадруплеты) | **0x565930** |
| рег-фильтр MFPA/MFBA/MFBE: гейт / ACL / компаратор | **0x18e714 / 0x19290 / 0x192cc** |
| boot-прелоад 0xA6+0xA7 (гейт RAM[0xdafa] бит3) | **0x22624 → 0x2504b4** |

## 3. Burn-verify консультирует БЕГУЩИЙ вольт (static + live)

- Статически: селектор вольта = f(RAM[0xc110], RAM[0xc112]) — чисто
  device-state, 0 писателей в MAIN_CODE (boot-заполнение); входящий образ
  читается только по сиг-секциям 0xA0/0xA3 (селектор RAM[0xc32b]).
- Live (uuid-spoof): plain burn образа «вендорский root uuid + НАШ modulus +
  наши подписи» → полный download OK → **REJECT 0x5** «Rejected
  authentication» (резолв вендорского modulus в бегущем вольте, RSA-verify
  нашей подписи FAIL). **uuid-spoof НЕ обходит burn-verify** (uuid-whitelist
  опровергнут).
- Security-регион CR 0x70xxx/0x76xxx из normal-режима закрыт
  (poison `0xbadacce6`).

## 4. Рег-фильтр = RBAC по device devlevel (не биты образа)

Гейт 0x18e714 (окно {0x9010 MFPA, 0x9011 MFBA, 0x9012 MFBE}) → ACL 0x19290:
devlevel = RAM[0x1311]&0xf; deny при acl ≥u devlevel; класс RAM[0xd25a];
все слова device-driven (0 писателей), IMAGE_INFO не консультируется —
**эволюция от CX-5 signed_fw-бит-гейта** (`050` §1) к RBAC. Патч-слово
dc 0x18e770 (`0x21296ff0`→`0x21296fee`) сдвигает ACL-набор {0x9010-12}→
{0x9012-14} — MFPA/MFBA открыты, MFBE остаётся под ACL; **только offline**
(встроен в parity-чистую сборку, гейтами проверен), рантайм-эффективность
не доказана (ГИПОТЕЗА; доставка невозможна — §5).

## 5. Бут-якорь GA SECURED — ВНЕ flash; приём recovery ≠ boot

- Self-signed образы (наш вольт+наши подписи; и вариант с вендорским uuid
  под нашим modulus) устанавливаются во flash (SS-min — FNP-burn;
  uuid-спуф — оффлайн-прошивкой владельца), но **НЕ грузятся** в
  normal-режиме (ROM fallback → Flash Recovery life-fish `15b3:0212`).
  FNP-strap исключён физической проверкой; артефакты сборки исключены полным
  parity + strict-diff гейтами ⇒ бут-якорь пинит ключ (modulus) или полную
  вендорскую цепочку — НЕ uuid. Точный механизм (OTP-fused modulus hash vs
  полная цепочка vs атрибут сертификата) — ГИПОТЕЗА. **SS-путь доставки
  FW-модификаций на GA SECURED невозможен.**
- Приём recovery-burn ≠ boot-валидность: FNP (strap) принял SS-образ,
  life-fish (без strap) — вендорский; оба приёма без reject-кодов — доказано
  лишь, что FNP-приём не отвергает non-vendor подпись («recovery-burn
  сигнатуры не проверяет» — гипотеза механизма, усилена до STRONG-кандидата
  в introspection: FNP принял 4/4 образов всех классов подписи, life-fish —
  вендор ×3); бут-арбитраж решает ROM-якорь. (Общность приёма — см.
  «Постулаты».)
- **Модифицируемость секций — доказано только GUID**: GUID/MAC карты,
  вшитые в DEV_INFO/MFG_INFO (DTOC, вне подписанных диапазонов 0xA3/0xA7),
  с НЕпересчитанными вендорскими RSA — образ прошивается recovery-burn и
  ЗАГРУЖАЕТСЯ на GA SECURED (live-восстановление). ITOC-дельта (VPI-байт
  `0x11+0x2df`) доставляема любой ногой, но модифицированный контент НЕ
  грузится без валидной вендор-RSA (D1/D4 → plain MCC REJECT 0x5; единый
  наблюдаемый гейт = RSA, стёртая all-FF 0xA0 digest-гейтом не проверяется —
  коды D1==D4). Прочие поля DEV_INFO/MFG_INFO и конфиг-секции класса 0x30 —
  ГИПОТЕЗА (требует интроспекции).

## 6. Цикл cx6dx-introspection: сертификаты, консюмеры, DTOC-доставка, HB-b

- **Сертификатов в образах НЕТ** (task-01): все DTOC cert-секции (0xd0,
  0xf2/f4-f7, 0xee/0xf3) erased-FF/zeros на наборе из 7 образов
  (retail/OEM-secure/FB/non-secure); единственный populated элемент —
  **0xed DIG_CERT_PTR** (DW0=8 + 9 BE-u32 адресов на пустые 0xee-подслоты
  и 0xf2) — указательный каркас цифровой сертификационной области
  (provisioning post-factory); whole-image OID/DER-скан — 0. NB:
  формулировка «0xed erased» в
  `docs/250-re/100-formats/040-fs4-domains.md` неточна — populated
  указатели, erased адресаты. 0xd0 — безымянный DTOC-тип (0x40000
  @0xf80000 — открыто).
- **Вольты**: 4096-пара Mellanox-корней (`c55d54e8`+`f560c160`, оба
  auth=0xd8000004) константна на всех secure-образах (retail = FB = Dell =
  OEM) — вендор-специфичного end-key в образах НЕТ; non-secure — keyless
  (полная таблица — `015-key-sections.md` §3).
- **Консюмеры сертификатов — ноль** (task-03, обе RE-базы VDA+FB):
  адресный скан (imm-пары, raw-u32, типы у 9+2 TOC-примитивов) и
  16 OID/X.509-маркеров — 0 хитов; X.509-парсера в читаемом FW-коде нет.
  **Компаратор-кластер — runtime-only MCC burn-verify** (PROVEN by decode:
  единственная цепочка вверх — event-движок → командный процессор
  0x167b38 → внутренняя команда 0x8405; бут-пути нет; прелоад стейджит
  только 0xA6+0xA7, крипто-вызовов ноль). **Burn-verify modulus — из
  FLASH-вольта бегущего образа** (PROVEN: слот-ридер 0x3fe600 → TOC-резолв
  по типу 0x167f70 → флеш-чтение 0x1c48c→0x1aff8; CR/OTP на пути нет).
- **Доставка DTOC** (task-04, матрица подтверждена live в task-05/06):
  DTOC-классы (cert/NV/DEV/MFG/VPD) — preserved-from-device на plain MCC и
  на `--nofs`; taken-from-image ТОЛЬКО на `--nofs --ignore_dev_data`
  (FNP-канон); гранулярность по TOC, не по типу секции. «Принят ≠ доставлен»
  доказан live БАЙТОВО (fix-wave): D2 (MFG PSID-дельта) — plain MCC
  accept #2 → flash MFG-байт @0x1ff800c = 0x37 '7' (vendor) vs d2.bin
  0x39 '9' (erratum раннего readback: обычный q PSID = fw_info.psid, не
  fs3_info.orig_psid, subcommands.cpp:4916-4925); FNP-нога — доставлен.
  **Read-side симметрия**: normal-mode MCC-чтение ITOC-bounded
  (`--mcc_read ri` = 0x792880 B ровно; `rb` за границей отвергнут
  `out of flash limits` — MCC и direct; DTOC/MFG в normal нечитаемы вовсе)
  ⇒ MCC-интерфейс ITOC-bounded в ОБЕ стороны. Флага `--ignore_fw_data`
  не существует.
- **Бут-якорь: HB-b PROVEN confound-free, ДВЕ базы** (task-06/07, финальные
  окна — fix-wave): VDA-тройка — D1 (валидный fresh 0xA0 + стейл-вендор-RSA,
  доставка байтовая) NO-BOOT ⇒ «digest-only» опровергнуто; a2d (НАШ 0xA4
  slot0 + вендор-фоллбек slots 1/2 + НАШ 0xA1-2048 + наши 0xA3/0xA7 +
  валидный 0xA0, доставка байтовая) NO-BOOT ⇒ «vault-fixable» опровергнуто
  для slot0-класса замены; a3c (a2d + наша X.509-цепочка 0xee/0xf2 + DTOC
  entry-CRC; доставка бит-экзакт включая certs) NO-BOOT ⇒ «cert-assisted»
  опровергнуто. FB-контролируемая пара (база FB 22.32.1224): fbss (наш
  0xA4 slot0 + vendor fallback 1/2 + наш 0xA1 + наши сиги; бит-в-бит
  доставка, cmp=0) NO-BOOT vs fbctl (чистый FB-vendor + 4B guides,
  наш-uuid скан = 0 вхождений) BOOT — единственная дельта пары = класс
  ключей ⇒ анкор пинит вендорские ключи и на FB-пути. Root of trust ВНЕ
  flash (OTP/fuse/mask ROM — точный механизм не установлен); скоуп — на
  этом GA SECURED кремнии. Конфаунд прошлого цикла (0xA0=нули у
  SS-min/uuidspoof) снят. Self-signed boot-рецепт через flash-vault закрыт
  по всем трём осям (digest/vault/certs); FNP DTOC-delivery — рабочий
  инструмент доставки независимо от boot-вердикта.
- **FB-база** (task-02): MAIN_CODE FB 22.32-эры извлечён
  (`build/fb-main03-dc.bin`, 0x34e9c0 B), **rt = dc + 0x20800000**
  (НЕ 0x21000000 — смежные образы не делят load base). Все 5 классов
  гейтов §2 найдены структурно: компаратор 0x1a4d58 (слит с
  rsa_verify_full; rc {0,2,3,5}; свип-константы идентичны), uuid-скан
  0x1a5060, слот-ридер 0x1a2f68, селектор банка 0xdceac (формула и
  RAM-слова 0xc110/0xc112 идентичны VDA), рег-гейт 0xdb204 (окно 0x6ff0,
  набор {0x9010-12}). **RBAC §4 на FB отсутствует** (битовый гейт, биты
  14/15 RAM[0xd050]) — RBAC-слой новшество 22.50-эры. Device-state слова
  мигрировали: 0xc355→0xd87, 0xd840→0xd050; сохранены 0xc110/0xc112/0xc01a.
  Карта §2-§4 перепроверена на VDA повторным декодом — 0 расхождений.

## Постулаты / открытое

- [постулат] Механизм бут-якоря (OTP-fused modulus hash vs пин полной
  вендорской цепочки vs атрибут сертификата) — офлайн неразрешим
  (отчёт `2026-10-30-cx6dx-securefw.md` §10.4; закрытие — вендорские
  публичные ключи/типы сертификатов, следующий цикл).
- [постулат] Рантайм-эффективность патч-слова dc 0x18e770 (+ потолок
  capability-бит0 исполнителя 0x18980): доставка на этот кремний закрыта
  (HB-b), проверка невозможна.
- [постулат] Общность приёма recovery-burn (FNP/life-fish) для других
  образов/карт/поколений — усилена до STRONG-кандидата (4/4 FNP, 3×
  life-fish-вендор), но не доказана.
- [постулат] Модифицируемость полей DEV_INFO/MFG_INFO сверх GUID и
  конфиг-секций класса 0x30 — требует интроспекции.
