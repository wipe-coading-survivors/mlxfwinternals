# 040. Ключ-резолв burn-verify: RSA-ветка 16.35.8008 и парити-гейт

> Источник: цикл securefw-gates (2026-10-29), RE-декод MAIN_CODE 8008 +
> численный парити-гейт; журналы
> `docs/superpowers/journal/2026-10-29-securefw-gates-task-{01..08}.md`
> (task-03 кросс-карта/RSA-декод/PARITY, task-04 исправленная семантика,
> task-07 дискриминатор, task-08 контроль). Live-карта — `CARD_HPE_CX516A`
> (secure-fw, PSID `HPE0000000009`, BDF 41:00.0); адресация — `035-securefw-map.md` §1.
> Связи: payload/маски клиента → `010-payload.md`; вольты/слоты →
> `015-key-sections.md`; ветки ошибок → `045-error-branches.md`;
> secure-биты → `035` §3; CX-6Dx-вариант → `055-cx6dx-signing.md`.

## 1. Контекст компаратора и выбор ветки

Компаратор (главный гейт) 0x1d3114 (4030: 0x1d29f4): читает ITOC-секции целиком
в кадр; сиг-поля кадра: f[0x268]=0xA0+0x10 (keypair_uuid 16B),
f[0x278]=0xA0+0x20 (sig 256B), f[0x28]=0xA3+0x10, f[0x38]=0xA3+0x20.

Выбор RSA vs digest (task-04 §2.3, исправленная семантика):

- chkA0/chkB0 — биты 0x4000/0x8000 ЦЕЛЕВОГО компонента (IMAGE_INFO по base);
  chkA1/chkB1 — биты УСТРОЙСТВА (boot-кеш RAM[0xc980], imm 0x3260; заполняет
  ROM до кода образа — писателей в образе нет).
- Режимные инварианты (отказ 0xa @0x1d3294): на secure_fw-устройстве нельзя
  лить не-secure_fw образ; secure_fw образ обязан быть signed_fw.
- `alu.0x39` TEST @0x1d32f0: RSA-путь ⇔ device.signed_fw & target.signed_fw
  оба SET; иначе content-digest (CDA-путь — `010-payload.md` §2,
  `750-exp/170-securefw-live-gates.md`); ветка Unsigned 0x1d33a0 → event(f0,6).

## 2. Скан вольта: 16 слотов, бегущий образ (H1)

```
scan_base = (chkA1' != 0 || chkA0' == 0) ? desc : base
  base = RAM[0x40e8] — флеш-база ЦЕЛЕВОГО (залитого) компонента
  desc = хэндл УСТАНОВЛЕННОГО (бегущего) слота: CR 0x300c0 (imm 0xc030),
         пишется ПОСЛЕ успешного verify на activate (0x1d5584); разрешение —
         интерпретатор 0x1d7fe8 через регистры активного слота CR 0x30408/0x3040c
loop idx = 0..15:
  idx ≤ 7   → секция 0xA1 (PUB_KEYS_2048, слот 0x120), референс = uuid из 0xA0
  idx 8..15 → секция 0xA4 (PUB_KEYS_4096, слот 0x220), референс = uuid из 0xA3
  read_public_key_slot(0x1d7d20): find_itoc_entry(scan_base, 0xA1/0xA4) →
    uuid@+0x10, exp@+0xc, key@+0x20 (0x100/0x200 B)
  memcmp(slot.uuid, ref, 16) == 0 → found
not found → event(0xf0,7) → клиент 0x7 (live; 045)
found → t = auth_type (младший байт BE-dword auth_cfg, слот+3):
  t==4 → rsa_verify_0x2b159c(sig_0xA3_512, custom_digest, key, exp)
  t==3 → rsa_verify_0x2b159c(sig_0xA0_256, sha_digest, key, exp)
  t ∉ {3,4} → event(0xf0,5)
```

На `CARD_HPE_CX516A` (бегущий HPE secure, IMAGE_INFO dword0 `0x0003d9e0` —
биты 14/15 SET) scan_base = desc = БЕГУЩИЙ образ ⇒ вольт входящего образа не
участвует. Пары строгие: 0xA1-слот матчится только с uuid 0xA0 (SHA-256),
0xA4-слот — с uuid 0xA3 (SHA-512). Enable-биты (fw_en и пр.) в verify-ветви
НЕ проверяются — только auth_type ∈ {3,4}; exp обязана влезать в 32 бита
(используется только слово exp[0] — 65537 ок).

## 3. Формула FW-verify и ядро rsa_verify

Формула (FW ≡ клиентская `SignForFwUpdate`, парити §4): дайджест SHA-512 по
flash[target: [0, RAM[0x40a0]=sizeOfImgData)) с масками 0xFF =
{ITOC-entry(0xA0) 32B + данные 0xA0 0x140B + ITOC-entry(0xA3) 32B + данные
0xA3 0x240B}; magic16 у клиента уже 0xFF; **0xA4 целиком НЕ маскируется**
(⇒ порядок set_public_keys→sign обязателен). Маски накладываются кумулятивно
в буфере чанка digest_loop 0x1d2c94 (patch-зоны A/B → sha256-ctx; +C/D →
customIV-ctx).

rsa_verify 0x2b159c = textbook RSA PKCS#1 v1.5 type-01: sig^e mod n
(square-and-multiply), emsa_check 0x2b14e4 (EM[0]=00, EM[1]=01, PS=FF…,
разделитель 00, T-длина 0x53 SHA-512 / 0x33 SHA-256, DER-заголовок == блобам
@0x394c70/0x394c58, хвост T == digest). Класс 512/256 — по маркеру
RAM[0x4008] бит 13.

## 4. Парити-гейт (численный) и customIV ≡ SHA-512

Проверка вендорской подписи refs-8008 (ключ vault slot0 `c55d54e8`, exp
0x10001; скрипт `scripts/secfw/parity_gate.py`):

```
M = image[0 .. 0x50e6f0)   ; 0x50e6f0 = sizeOfImgData = max(addr+size) ITOC
  [0x0,0x10)             → 0xFF (boot magic 16B)
  ITOC-entry(0xA0)@0x5200 32B → 0xFF (таблица ITOC, не «перед данными» — питфолл
                                 addr−0x20, демонстрация parity_em_pitfall.py)
  данные 0xA0 @0x443268 0x140B → 0xFF
  ITOC-entry(0xA3)@0x5260 32B → 0xFF
  данные 0xA3 @0x443d38 0x240B → 0xFF
SHA512(M) = 3e8a8944d7ca7ab22a46f3180a431e89b893fd1b84e53200b64ac034e3cb4a65
             de484998bba143ba4f4b8cdc59afd12f6d7d672c57b5289e8d5224e356bc8266
EM = sig^65537 mod n → 00 01 FF…(428) 00 || 3051…0404 40 || hash — ТОЧНОЕ СОВПАДЕНИЕ
```

Негатив-контроль: снятие любой маски/диапазона ломает матч; devid1019-сборка
(лаб-GUID правки) — mismatch (= live-0x5 2026-10-24). Вердикт: **PARITY**
(эффективный FW-дайджест ≡ openssl SHA-512).

**customIV ≡ SHA-512** (0x2b28bc/0x2b2998/0x2b1f84/0x2b2aac): FIPS H512
init-константы; блок 0x80=128B; сдвиги ровно SHA-512 (σ0/σ1/Σ0/Σ1);
BE-битовая длина в паддинге; out 64B BE. K512: **77/80 точных imm-квадруплет**
в прологе transform; девианты [20]/[51]/[76] — по одному 16-битному
полуслову на слот кадра, ИДЕНТИЧНЫ в 8008 и 4030:

- K[20] `0x2DE92C6F…` (FIPS 0x2DE92F6F…, 2F6F→2C6F)
- K[51] `0x34B0BCB5E19B48A8` (FIPS …A19B…, A19B→E19B)
- K[76] `0x4CC5D4BECB3E42B6` (FIPS 0x4CC5D4CB…, D4CB→D4BE)

Перезаписи слотов до раундового цикла не найдены — необъяснённый статический
остаток; на паритет не влияет (якорь численный + live-приёмка вендорских
образов). K512-таблицы в данных НЕТ (константы в коде; сканер sha_anchor_scan
их не видит — ожидаемое ограничение).

## 5. Вердикты гипотез цикла (все, дословно)

| Гипотеза | Вердикт | Основание |
|---|---|---|
| **H1: uuid-lookup по БЕГУЩЕМУ вольту** | **CONFIRMED** | дискриминатор 0x7 (uuid в бегущем вольте отсутствует) + контрольный plain PASS после FNP-установки нашего вольта (task-08 §11); декод §2 |
| H2: вольт принятого (incoming) образа | FALSIFIED | наш uuid+ключ в образе (обе auth-профилей) → байт-идентичный 0x7; при H2 был бы PASS/иной исход (task-07 §5.1) |
| H1-fixed-slot: верификация «слотом-лидером» (вендорский ключ) | FALSIFIED | дал бы RSA-mismatch → 0x5, не наблюдалось (0x7) |
| 0x7 ← auth_cfg-биты слота (purpose/lifecycle) | FALSIFIED | итерация slot0 0x80000004 → 0xd8000004 (вендор-профиль), исход/лог байт-идентичны (task-07 §4) |

Примечание о силе различения (task-08 review Minor-2): W3-пробы сами по
себе H1 от H2 не различают (одинаковы при любом источнике вольта — running и
incoming совпадают после установки); различение держится на W1
(дискриминатор: running-вольт ≠ incoming-вольт) — потому пара
«дискриминатор + контроль» и является доказательством.

(H3 «silicon-root — ключ установить нельзя в принципе» — EXCLUDED; вердикт
вынесен в `030-root-of-trust.md` §3.)

## Постулаты / открытое

- [постулат] AND vs OR чтения 0x1d32f0 (без live-якоря).
- [постулат] Потребление K[20]/[51]/[76] в transform-цикле: перезаписи слотов
  не найдены; при будущем RE transform-цикла проверять потребление девиантов
  первым.
- Датум: verify на нашей FW 5.5 мин vs 40 с вендорской (гипотеза — стоимость
  RSA-резолва по нашему вольту; не разведено, на исход не влияет).
