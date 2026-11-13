# 180. Secure-fw карта: рецепты (self-signed, FNP-once, чтение, откат)

> Источник: цикл securefw-gates (2026-10-29, live-proven, `CARD_HPE_CX516A`
> 41:00.0 secure-fw; журналы `docs/superpowers/journal/2026-10-29-securefw-gates-task-{06,07,08}.md`,
> отчёт `docs/superpowers/reports/2026-10-29-securefw-gates.md`); чтение —
> цикл securefw-read (2026-10-29, журналы `…-securefw-read-task-{04,05,06}.md`).
> Канон сборки — скилл `mellanox-fw-build` (Rule 6; ini — Rule 1/2).
> Связи: вольты/слоты → `docs/250-re/110-signing/015-key-sections.md`;
> ключ-резолв burn-verify → `docs/250-re/110-signing/040-key-resolve.md`;
> read-семантика MCDA → `docs/250-re/110-signing/050-spi-read-policy.md`;
> вердикты live-гейтов →
> `docs/750-exp/170-securefw-live-gates.md`; FNP-механика →
> `100-cross-flash-ops.md` §9.1; подпись-справочник → `170-signing-practical.md`.

## 1. Self-signed сборка (live-proven)

База: OEM-семейство целевой secure-карты (`100-cross-flash-ops.md` §3;
GUID/MAC базы — идентичность карты).

1. Ключ/uuid: `openssl genrsa 4096` (ключ не коммитится/не цитируется);
   uuid = 16 случайных байт, используется как hex-строка.
2. Вольт 0xA4 = ровно 4352B (8 слотов × 0x220; слот: auth_cfg BE @0x0,
   reserved @0x4..0xC нули, exp BE @0xC (65537), keypair_uuid 16B @0x10,
   modulus 512B BE @0x20). План слотов: **наш = slot0**, вендорские —
   slot1/slot2 байт-в-байт из стокового 0xA4 (клиентский канон «первый
   fw_en-слот замещается», fs4_ops.cpp:4719-4834). auth_cfg нашего слота:
   минимум `0x80000004` (RSA-4096 + fw_en) или вендор-профиль
   `0xd8000004` — на исход не влияет (0x7-итерация шла с d8, контрольный
   plain PASS — с 80; FW проверяет только auth_type ∈ {3,4}).
3. Ini build-ID (Rule 1) + бюджет 0x30 (Rule 2, тримминг док-комментов).
4. **Порядок обязателен**: `mstflint -i <img> set_public_keys <vault.bin>`
   (4352B, сырая замена; warning «run sign command» — ожидаем) →
   `mstflint -i <img> --private_key k.pem --public_key pub.bin
   --key_uuid <32-hex-строка> rsa_sign` (RSA-4096 → SHA-512; 0xA4 в
   подписываемых данных).
   **Питфолл `sign` vs `rsa_sign`** (cx6dx-introspection task-07,
   parity-гейт поймал): `sign` подписывает ТОЛЬКО FW-update (0xA3,
   SignForFwUpdate, subcommands.cpp:1828) и молча оставляет 0xA7 стейл
   (rc=0, никакого -E-); `rsa_sign` (:2283) делает SignForSecureBoot
   (0xA7: StoreImagePublicKey + подпись boot/critical/non-critical) +
   SignForFwUpdate. Для full-package SS-образов — только `rsa_sign`.
5. **Питфолл `--key_uuid`**: значение — hex-СТРОКА (32 hex-цифры,
   extractUUIDFromString fs3_ops.cpp:3133); raw-16B-файл падает с
   маскирующим errmsg «Failed to insert secured FW signature».
6. Пост-состояние: 0xA0 = 320B нулей (SHA-512-ветка обнуляет младшую
   сиг-секцию — Fs3MemSetSignature), 0xA3: uuid@0x10 + подпись 512B@0x20.
7. Гейты: `mlxfwutil.py verify --deep` PASS; `mstflint -i <img> verify` →
   bootable; diff vs база = только {0xA0, 0xA3, 0xA4, 0x30}; parity-гейт
   (по образцу scripts/secfw/parity_gate.py) match=True;
   `mlxfwutil.py sign --check` rc=2 (`0xA0: empty`) — ожидаемо для RSA-пути
   (digest-гейт non-secure — `docs/750-exp/170-securefw-live-gates.md` §5 —
   к SS-образам НЕ применим; `sign` без ключей уничтожил бы подпись —
   запрещено).

## 2. FNP один раз → plain onwards (live-proven)

Карта: secure-fw, вендорский вольт бегущего образа без нашего uuid. Первый
burn SS-образа — только FNP (plain даст 0x7 после полного download):

1. FNP-джампер в окне обесточивания → power on (BMC) → ssh-wait → проверка:
   `lspci -nnd 15b3:` → цель в `15b3:020d` (life-fish, class 0580).
2. Write-protect: `flint_oem -d <BDF> -ocr hw query`; при Enabled →
   `… hw set Flash0.WriteProtected=Disabled` (`100-cross-flash-ops.md`
   §9.1 п.1).
3. md5 образа на ОБОИХ концах.
4. Burn (`100-cross-flash-ops.md` §9.1 п.2): `mstflint -d <BDF> -i <ss.bin>
   -ocr -apc --nofs --ignore_dev_data -y b` → гейты:
   `Restoring signature - OK` + 0 `-E-`-строк (маркер
   `Burning FW image without signatures - OK` — штатный no-sig-путь).
   GUID-ловушка `--ignore_dev_data` закрыта Rule 3 (identity уже в образе).
   mstflint ≥ 4.34 на хосте.
5. Post-verify в FNP: `q` + `dc | grep mlxini` (наш build-ID).
6. Джампер снять в окне обесточивания → power on → boot-чек: dev id ≠ 020d,
   `q` == образу, порт Active.
7. Далее все наши SS-образы (тот же ключ/uuid): **plain
   `mstflint -d <BDF> -i <ss2.bin> -y burn`** — без обходных флагов;
   критерий PASS = `Restoring signature - OK`, 0 `-E-`; активация
   `mstfwreset -d <BDF> --level 3 -t 0 -y r` (same-version → `-l 3` явно).

Датум: verify на нашей FW 5.5 мин vs 40 с вендорской (гипотеза — стоимость
RSA-резолва по нашему вольту; не разведено, на исход не влияет).

## 3. Аварийный откат (кирпич/no-boot)

Канон `100-cross-flash-ops.md` §9.1: known-good
`build/hpe-872726-8008-gen4-56g-vpi-devid1019.bin` (md5 0279d2ee…)
FNP-burn'ом (джампер + шаги §2 п.1-6) + вызов владельца.

## 4. Чтение secure-карты (ri/dc патченым тулингом, live-proven)

Stock-тулингом `ri`/`dc` на secure-карте блокируются клиентскими гвардами
ДО FW (`docs/250-re/110-signing/050-spi-read-policy.md` §2); патченный
mstflint 4.37.0-1.2
(состав патчей и пин — `docs/150-external/000-pinned-revs.md`)
читает через MCC — write-гварды и burn-путь не тронуты.
Семантика MCDA/ri (плоский read, логический образ) —
`docs/250-re/110-signing/050-spi-read-policy.md` §3.

- Ожидаем: stderr-маркеры `-W- mlxini secure-read: section read served
  via MCC (Secure FW)` (dc) / `…image read served via MCC (Secure FW)`
  (ri) + `-I- full image read via MCC may take minutes`.
- Тайминги — минуты-класс: полный образ ~5 MiB подаётся порциями ≤128B
  (max_xfer класс 4); окно 600 с, таймаут операции ≥10 мин; молчаливое
  ожидание — норма (ri/dc логируют мало до завершения).
- `bdc` оживает автоматически (тот же `FwReadData`-путь); вердикт
  сравнения при size-mismatch НЕ гарантирован — live-сверка отдельно,
  не гейт.
- Гейты (live-доказательства, цикл securefw-read): ri-дамп == running
  image байт-в-байт (диапазон 0x50e6f0, ITOC 0 bad entries, task-04);
  round-trip plain burn дампа PASS, карта в исходном состоянии (task-05);
  регрессия non-secure 01:00.0 — q-diff пуст, dc/ri md5 == baseline
  сток-тулинга (task-06).
