# 035. RE-карта MAIN_CODE 16.35.8008: кросс-карта 8008↔4030, secure-биты

> Источник: цикл securefw-gates (2026-10-29) — RE-декод MAIN_CODE FW 16.35.8008
> (HPE, refs-8008) + кросс-карта со сток-4030; журналы
> `docs/superpowers/journal/2026-10-29-securefw-gates-task-{01..08}.md`, отчёт
> `docs/superpowers/reports/2026-10-29-securefw-gates.md`. Live-карта —
> `CARD_HPE_CX516A` (secure-fw, PSID `HPE0000000009`, BDF 41:00.0).
> Связи: ключ-резолв/парити-гейт → `040-key-resolve.md`; ветки ошибок →
> `045-error-branches.md`; SPI/read-политика → `050-spi-read-policy.md`;
> payload/маски → `010-payload.md`; dc↔rt-калибровка формата —
> `docs/250-re/100-formats/045-fs4-dc-rt.md`.

## 1. RE-база и формат адресов

`<dc>` = смещение в RE-базе `build/secfw-main03-dc.bin` (MAIN_CODE 0x03 cl=1
из refs-8008, 0x398980 B, md5 `476c5ec835c43e8efb9f51fc5c3e1734`; выгрузка —
`scripts/secfw/extract_main03.py`). 4030-CDA-эквивалент в скобках. RAM-адреса
физические (`ld.i imm<<2`, калибровка task-04 §0.3).

## 2. Кросс-карта MAIN_CODE 8008 ↔ 4030-CDA

Код побайтно НЕ идентичен: релокация почти всех call/jump + 119 зон
вставок/удалений (суммарно +0xBC0 B), 4226 малых зон подстановки (0x68040 слов
— релоцированные rt-ссылки). Структурная эквивалентность — нормализованным
дизасмом (65.1% слов код-региона [0..~0x349e30), хвост-данные 82.7%).
Инструменты: `scripts/secfw/{fulldis,relomap_code,relomap_tail,reloc_anchors,
reloc_anchors_long,wdis}.py`.

Кластерные сдвиги якорей (стабильны внутри кластеров):

| кластер | сдвиг 8008−4030 |
|---|---|
| fw_burn-модуль (компаратор/RSA/FSM/ini-чеки) | **+0x720** |
| крипто-модуль 0x2b1xxx–0x2b2xxx | **+0x794** |
| хелперы 0x18xxx–0x19xxx | +0x24 |
| entry-search 0x107bd8 / desc-init 0x1079dc | +0x6e8 |
| memcmp | +0x738 |
| K256-таблица (данные) | **+0xbe0** |

Таблица якорей (RE-база 8008; 4030-эквивалент в скобках):

| объект | 8008 dc | (4030 dc) |
|---|---|---|
| initialize_verify_parameters | 0x1d295c | (0x1d223c) |
| verify_params_lookup | 0x1d2844 | (0x1d2124) |
| itoc_scan | 0x195a0 | (0x1957c) |
| itoc_entry_search | 0x1082c0 | (0x107bd8) |
| desc-handle get/set | 0x1080c4 | (0x1079dc) |
| fw_burn_is_secure | 0x1cf5e0 | (0x1ceec0) |
| secure_chk (бит 0x4000) | 0x1d0030 | (0x1cf910) |
| mode_chk (бит 0x8000) | 0x1d017c | (0x1cfa5c) |
| patch_gate ini | 0x1cfe6c | (0x1cf74c) |
| ini_enum / row_present / row(0xd,0xb) / row(0xc,2) | 0x1cf90c / 0x1cfb38 / 0x1cfd88 / 0x1cfdac | (0x1cf1ec/0x1cf418/0x1cf668/0x1cf68c) |
| **digest_loop** (маски/хеш) | 0x1d2c94 | (0x1d2574) |
| **rsa_verify_full (RSA-ветка)** | **0x1d2ed8** | (0x1d27b8) |
| **digest_compare (главный гейт)** | **0x1d3114** | (0x1d29f4) |
| выход RSA-ветки / plain-memcmp / match | 0x1d332c / 0x1d3340 / 0x1d3368 | (0x1d2c0c/0x1d2c20/0x1d2c48) |
| hash_init_both / digest_compute_both / digest_verify_driver | 0x1d33c4 / 0x1d3414 / 0x1d34e8 | (0x1d2ca4/0x1d2cf4/0x1d2dc8) |
| verify_image | 0x1d4e64 | (0x1d4744) |
| fw_burn_fsm / state4 / state5 / state84 | 0x1d5b78 / 0x1d61b0 / 0x1d61f4 / 0x1d63f0 | (0x1d5458/0x1d5a90/0x1d5ad4/0x1d5cd0) |
| read_itoc | 0x1d7a58 | (0x1d7338) |
| read_public_key_slot (слот-ридер вольта) | 0x1d7d20 | (~0x1d7600) |
| find_itoc_entry | 0x1d8280 | — |
| интерпретатор баз / active-slot | 0x1d7fe8 / 0x1d7fd0 | — |
| sha256 transform/update/final/init | 0x2b1b44/0x2b1ab0/0x2b1d68/0x2b1e84 | (0x2b13b0/0x2b131c/0x2b15d4/0x2b16f0) |
| **customIV init/update/final** | 0x2b28bc / 0x2b2998 / 0x2b2aac | (0x2b2128/0x2b2204/0x2b2318) |
| customIV transform (K512-imm) | 0x2b1f84 | (~0x2b17f0) |
| **rsa_verify (RSA/PKCS#1 ядро)** | **0x2b159c** | (0x2b0e08) |
| memcmp | 0x2ae46c | (0x2add34) |
| K256-таблица (данные) | 0x394c88 | (0x3940a8) |
| DigestInfo DER SHA-256 / SHA-512 | 0x394c58 / 0x394c70 | — |
| таблица progress→handler (MCC) | 0x38efd8 | (0x38e3f8) |
| send_verify_status (диспетчер) / постер | 0x1b8640 / 0x1b8588 | (0x1b7dc8-семья) |

## 3. Secure-биты и вершина «verify обязателен»

Источник битов — **IMAGE_INFO (ITOC 0x10) dword0**, не ini 0x30:

| бит | имя | FW-потребитель |
|---|---|---|
| 8 | mcc_en | гейт MCDA/MCC-цепочки 0x122554 |
| 13 | debug_fw | билдер атрибутов |
| 14 | signed_fw | secure_chk 0x1d0070; гейт MFPA/MFBA/MFBE 0x1064fc |
| 15 | secure_fw («cr-space closed») | mode_chk 0x1d01b4; гейт 0x1064cc |
| 5 | windbond_flash_support (HPE-only) | FW нигде не читает |

Устройство = boot-кеш dword0 в RAM[0xc980] (imm 0x3260; заполняет ROM/аппаратура
до IRON_PREP — в образе писателей нет, читатель уже в sec05:0xf56c); цель =
прямое чтение ITOC (0x1cf548). Значения: HPE-8008 `0x0003d9e0`,
Dell-09FTMY (`CARD_DELL_CX5EX`) `0x0003d9c0`, CDA-4030 `0x00030160`
(HPE xor Dell = бит 5). Ini-токены `signed_fw`/`secure_fw`/`secure_fw_hpcs` —
сборочная документация (hpcs FW-гейта не имеет).

Апексы обязательности verify: вызов verify_image **0x1d61c4** (state 4
прогресс-машины, безусловно; в графе FSM нет перехода DOWNLOAD→ACTIVATE в
обход VERIFY) + режимные инварианты **0x1d3294**. Все коды
0x2/0x4/0x5/0x6/0x7/0xa рождаются внутри verify — стадию можно только
провалить (ветки — `045-error-branches.md`).

## Постулаты / открытое

- [постулат] 4030-эквиваленты со знаком `~` (read_public_key_slot ~0x1d7600,
  customIV transform ~0x2b17f0) — приближения, не вычислены точно.
- [постулат] `find_itoc_entry` 0x1d8280 и интерпретатор баз/active-slot
  (0x1d7fe8/0x1d7fd0) — без 4030-эквивалента (в стоке отсутствуют/не найдены).

## Приложение: md5-артефакты цикла securefw-gates (2026-10-29)

| Объект | md5 |
|---|---|
| RE-база `build/secfw-main03-dc.bin` (0x398980 B, gitignored) | `476c5ec835c43e8efb9f51fc5c3e1734` |
| сток-4030 MAIN_CODE (эталон кросс-карты, /tmp) | `1b73520497bd20f49fe4e5200a6c86dd` |
| база SS-min `hpe-872726-8008-gen4-56g-vpi-devid1019.bin` | `0279d2ee85686f451c940897766cce65` |
| база SS-8008 `hpe-872726-8008-gen4-56g-vpi.bin` | `78ad5bf5c874f1d6ae05f223630cce02` |
| **SS-min** `build/ss-min.bin` (slot0 auth 0x80000004) | `94e2e4aa0d9931c6593c234a0d7ebb87` |
| **SS-min-a7** `build/ss-min-a7.bin` (slot0 auth 0xd8000004; FNP-установлен) | `1cbcbe82c74d51d235e2a41f4fc35383` |
| **SS-8008** `build/ss-8008.bin` (продукт; терминальное состояние карты) | `bfe8625cbc0edc079423585b89e2ade6` |
| вольт-80 `hpe_ss_vault_a4.bin` (SS-min/SS-8008; **терминальный вольт карты** — flash-proof ITOC de49a0c6…, task-08 §12) | `eda1bc3a5d5f9de63b9f8a11def9ce37` |
| вольт-д8 `hpe_ss_vault_a4_d8.bin` (ss-min-a7; на карте в окне W3, до контрольного burn) | `4e09eaf656f0ade247c726959704e1b0` |
| стоковый 0xA4 баз (источник вендор-слотов) | `6444478ce6385b64731cecc73f6541ab` |
| live ITOC ss-8008 (flash-slot proof, rb 0x5000) | `de49a0c61e1b2ffd147009498a9858d5` |
| 0xA3 SS-min / SS-8008 | `f212557fac010955b3925209c2d1edd5` / `5b447df0e3ed8f59f674b5e62413df67` |
| 0xA0 (оба SS, 320B нулей) | `04dbc66d8e4559769bb38a92cd6f7d9d` |
| pub key DER 800B / uuid (публичные отпечатки) | `4788e6157d06b958ac15e77695376afe` / `6ffe10efc73945e3571af65dda7f2559` |
| логи 0x7-исходов (дискриминатор == итерация, байт-в-байт) | `7b58a97c3873a4a56ea79b8836a90a57` |

Терминальное состояние (2026-10-29): карта `CARD_HPE_CX516A` (GuidsNumber 8),
41:00.0 normal (`[15b3:1019]`), ss-8008 на флеше и в рантайме, наш вольт
(slot0 `6ffe10ef`, auth `0x80000004` + вендор slot1/2), secure-fw. Порт: при
закрытии цикла (task-08, ibstat mlx5_2) — Active/100; при round-trip
securefw-read task-05 оба порта Down/10 до и после — состояние линка зависит
от стенда/соседа, не от FW (журнал
`docs/superpowers/journal/2026-10-29-securefw-read-task-05.md` §1.4/§3.5).
