# 170. Live-гейты secure-fw: burn-верификация и boot-гейт (итоги)

> Источник: live-циклы на `CARD_HPE_CX516A` (41:00.0, secure-fw) и
> non-secure CX-5 (01:00.0) — burn-инцидент 2026-10-24; офлайн-исследование
> `docs/superpowers/journal/2026-10-24-secure-fw-nofnp-burn-research.md`;
> циклы burn-digest (2026-10-28, отчёты
> `docs/superpowers/reports/2026-10-28-burn-digest-gate-results.md`,
> `…-upgrade-code-pseudo.md`), securefw-gates (2026-10-29, отчёт
> `…/2026-10-29-securefw-gates.md`, журналы task-01..08), boot-гейт
> (2026-10-27, отчёт `…/2026-10-27-securefw-boot-gate-experiments.md`).
> Здесь — сжатые итоги (вердикты/факты); RE-механика — аспекты кластера
> `docs/250-re/110-signing/`, рецепты — `docs/850-howto/180-securefw-recipes.md`.
> Связи: ветки ошибок → `docs/250-re/110-signing/045-error-branches.md`;
> ключ-резолв → `docs/250-re/110-signing/040-key-resolve.md`; read/SPI →
> `…/050-spi-read-policy.md`; RE-карта → `…/035-securefw-map.md`;
> root-of-trust → `…/030-root-of-trust.md`.

## 1. `Rejected authentication` — FW-код 0x5, верифицирует бегущая iRISC (MCC FSM)

- Строка — клиентское отображение кода FW
  `MCC_ERRCODE_REJECTED_AUTH_FAILED = 0x5` (`fw_comps_mgr.cpp:2136-2137`,
  `fw_comps_mgr.h:266`); ядро `mlxfw` лишь ретранслирует FSM-стейт
  (`mlxfw_fsm.c:23,59-61`) — не верифицирует.
- Burn-флоу (`burnComponents`, `fw_comps_mgr.cpp:1527-1651`): LOCK →
  INITIALIZE (0x2, стирание целевого НЕактивного слота) → DOWNLOAD (0x3,
  MCDA-блоки пишет FW; это «Writing Boot image component - OK») →
  **VERIFY_COMPONENT (0x4) — здесь reject** → ACTIVATE (0x6, финализация
  FW-side) → RELEASE.
- **Отказ не трогает running-слот**: неактивный слот к моменту отказа уже
  стёрт и записан «полуобразом» (полный компонент без ACTIVATE; ~4.2 MiB
  residue, эмпирика E1/T2.2) — карта продолжает ботить со старого слота
  (наблюдение 2026-10-24: трафик не прерывался). Каждый прогон = полный
  download ~4.2 MiB (минуты).
- Полный набор кодов MCC (`fw_comps_mgr.h:256-309`): 0x2 DIGEST_ERR («The
  Digest in the signature is wrong»), 0x3 NOT_APPLICABLE, 0x4 UNKNOWN_KEY,
  0x5 AUTH_FAILED, 0x6 UNSIGNED, 0x7 KEY_NOT_APPLICABLE («The key is not
  applicable»), 0xA NOT_A_SECURED_FW, 0x19 INVALID_SECURITY_VERSION, 0x28
  FLASH_WRITE_PROTECTED.
- **Коррекция маппинга (live 2026-10-29)**: ключ по `keypair_uuid` ищется
  в БЕГУЩЕМ вольте (16 слотов 0xA1+0xA4) → не найден: **0x7
  KEY_NOT_APPLICABLE, не 0x4** (двойной прогон, логи байт-идентичны — md5
  7b58a97c…); «ключ валиден, но непригоден по lifecycle» как источник 0x7 —
  опровергнут live-итерацией (slot0 auth 0x80000004→0xd8000004, исход без
  изменений); 0x4 в живых исходах не наблюдался. Проводка event→MCQS —
  `docs/250-re/110-signing/045-error-branches.md` §2.

## 2. MCC — единственный live write-путь на secure-fw; прямой SPI заблокирован

- `burn --no_fw_ctrl` пропускает MCC (`fw_ops.cpp:982`) и идёт в прямой
  SPI: на live secure-карте HCR flash-gateway не отвечает (RDID 0xFF/0x00)
  → `MFE_NO_FLASH_DETECTED` (`mflash.c:857-863`; live ×3, 2026-10-24).
  Причина: бегущая secure FW владеет SPI. Не CR-lock (MLOCK чист), не 0x28
  write-protect.
- `q`/`rb`/`verify` работают (FW-mediated MCC/MCDA); `ri`/`dc` блокирует
  сам КЛИЕНТ до FW: «Read image is not supported»
  (`fsctrl_ops.cpp:547-553`) / «Unsupported operation under Secure FW»
  (`:1079-1085`) — воспроизведены live дословно. Патченым 4.37.0-1.2 —
  читаются (рецепт `850-howto/180-securefw-recipes.md` §4; семантика —
  `docs/250-re/110-signing/050-spi-read-policy.md` §3).
- Софтверного триггера recovery без FNP-джампера нет: recovery — решение
  ROM при boot (FNP или битая/пустая флеша; детект — life-fish dev ID,
  `tools_dev_types.c:968`). Прочие пути закрыты с пруфами: flash
  write-protect (тот же blocked SPI), unbind mlx5 (FW продолжает владеть
  SPI), валидная подпись Mellanox (нет приватного ключа), пропуск стадии
  FSM (обязательна).

## 3. Self-signed образ — единственный non-FNP write-вектор

- Механика (HPE 8008): вольт стока — 0xA0 RSA-2048 `a04a92ed…` (HPE OEM),
  0xA1 slot0 `2c635b71…`, 0xA3 RSA-4096 `c55d54e8…` (Mellanox common
  root), 0xA4 8 слотов × 544B (slot0 `c55d54e8…`, auth 0xD8000004);
  0xA5/0xA6/0xA7 отсутствуют. **Аномалия**: ключ 0xA0-подписи отсутствует
  в 0xA1 → FW-auth цепочка = 4096-путь (0xA3↔0xA4). Слот-формат —
  `docs/250-re/110-signing/015-key-sections.md` §3.
- Процедура: сначала `set_public_keys` (файл = ровно 4352B, сырой BE),
  потом `sign --private_key --key_uuid` (0xA4 входит в подписываемые
  данные) — пошагово с гейтами `850-howto/180-securefw-recipes.md` §1.
- **Дискриминатор закрыт (live 2026-10-29): H1 — uuid-lookup по БЕГУЩЕМУ
  вольту**; вольт входящего образа НЕ консультируется (H2 опровергнут),
  «слот-лидер» не верифицирует (был бы 0x5, наблюдался 0x7), silicon-root
  исключён контрольным plain PASS после установки нашего вольта. RE-декод
  и паритет — `docs/250-re/110-signing/040-key-resolve.md`.
- Гипотеза «первый burn self-signed — через FNP, далее plain» —
  **подтверждена** (§6).

## 4. devlink — второй клиент того же FW FSM, не обход

- `devlink dev flash pci/<bdf> file <mfa2>` → ядренная `mlxfw` → MCC-регистры
  (MCC/MCDA/MCQI через mlx5-mailbox) — тот же FW FSM с VERIFY-стадией,
  что у mstflint plain burn (`mlx5/core/fw.c:440-760`, `mlxfw_fsm.c:345-429`).
- Ограничения: только MFA2-архивы + match PSID; строго in-band (нужен
  bound mlx5); FNP devlink недоступен (recovery-карта — life-fish dev ID,
  mlx5 не биндится). Raw-операций flash в `mlxfw` нет (`mlxfw.h:72-99`).
- MFT-модуль ядра (`/dev/mstflint`) — чистый passthrough (ioctls →
  pci_write/iowrite32, `mst_main.c:1324-1803`), без политики записи.
- Вывод: ядро хоста (mlx5/mlxfw/MFT) — ретранслятор, а не арбитр записи;
  верификация всегда FW-side (live-подтверждение —
  `140-post-fnp-guid-desync.md` §10).

## 5. Digest-гейт plain-burn на non-secure (код 0x2) — механика декодирована

- Код 0x2 на non-secure CX-5 (01:00.0, CDA-путь) = **безусловная
  content-digest проверка type-7 компонента** на VERIFY_COMPONENT: FW
  считает SHA-256 по маске/диапазону ≡ клиентскому `mstflint sign`
  (магия 16B→0xFF; ITOC-entry(0xA0) 32B→0xFF; данные 0xA0→0xFF; диапазон
  [0, max(addr+size) по ITOC)), сравнивает с 0xA0-данными образа @+0x20.
  Детектора «меняется ли код» и секционной дискриминации нет.
- Весь гейт — программный SHA-256+memcmp в MAIN_CODE (dc: компаратор
  0x1d29f4, memcmp 0x1d2c20, digest-цикл 0x1d2574, K256 @0x3940a8);
  strict default (ini CDA-SKU без mcc_en/signed_fw/secure_fw). One-word
  патч гейта (@dc 0x1d2c48) — live-демо стылый дест PASS, но для
  secure_fw (RSA-ветка 0x1d27b8) — НЕ решение.
- **Следствие: контент-модифицированному образу достаточно пересчитать
  0xA0** (`mstflint -i <img> sign` без ключей; `mlxfwutil.py sign`) — plain
  burn пройдёт (live-доказано парным контролем стылый=0x2 / fresh=PASS).
  Plain burn + свежий дест — канон для non-secure карт
  (`850-howto/100-cross-flash-ops.md` §6).

## 6. RSA-ветка декодирована; вердикт H1; «FNP один раз → plain» доказан

- RE-декод (16.35.8008): ключ-резолв = uuid-lookup по 16 слотам 0xA1+0xA4
  по `scan_base` (на secure-устройстве — БЕГУЩИЙ образ); verify = SHA-512
  [0, sizeOfImgData) с масками magic16+0xA0+0xA3 → RSA PKCS#1 v1.5
  DigestInfo(SHA-512); паритет с клиентской SignForFwUpdate доказан
  численно (`docs/250-re/110-signing/040-key-resolve.md`).
- Дискриминатор: plain burn SS-образа (наш вольт в образе, вендорский
  бегущий) → полный download OK → **0x7**; итерация slot0 auth
  0x80000004→0xd8000004 — 0x7 байт-идентичный (md5 логов равны) ⇒ H2 /
  H1-fixed-slot / auth-биты опровергнуты.
- FNP-ветка: FNP-burn SS-min-a7 (`-ocr -apc --nofs --ignore_dev_data -y b`)
  — `Restoring signature - OK`, 0 `-E-`; после снятия джампера — boot в
  normal (dev 1019).
- Контроль: plain burn SS-8008 (продукт, литерально `-y burn`) — **PASS**
  (полный FSM, активация `mstfwreset -l 3`, порт Active/100). **Вердикт H1
  доказан end-to-end: «FNP один раз → далее plain»** (uuid резолвится по
  НАШЕМУ бегущему вольту). Терминальное состояние и md5-артефакты —
  приложение `docs/250-re/110-signing/035-securefw-map.md`.

## 7. Boot-гейт secure_fw карты: generic-образ не бутается

- Пересадка программатором сырого флеш-дампа non-secure карты (generic
  `MT_` PSID, flags 0x01, digest-only) в secure_fw карту — normal-boot не
  поднимается (нет PCIe-устройства); FNP/recovery тот же флеш читает.
- Серия FNP-burn generic-баз (ECA 8008; +flags 0xC1; +flags 0xd9 с
  пересадкой полного сиг-блока 0xA0/0xA1/0xA3/0xA4 от OEM-стока; + полный
  OEM identity-блок IMAGE_INFO) — **все не бутаются**. Исключены:
  device_id, флаги, наличие RSA-секций, identity-строки/id.
- **Криптопроверка на boot исключена**: образ с битой RSA грузится штатно
  при правильной сборке (`160-hpe-cx5-vpi-gen4-precheck.md` §10.5). Контроль:
  восстановление исходного думпа — карта работает ⇒ гейт — против
  содержимого generic-образа (код/конфиг/ROM), не против карты. Не
  тестированы SKU-конфиги (0x08/0x09/0x11/0x12), ROM, ini.
- Практический вывод: на secure_fw карте — база OEM-семейства;
  нестандартный конфиг — graft на OEM-базу (`100-dell-base-vpi-build.md`),
  не generic-база.
- **Датум (2026-10-29): наш SS-образ ГРУЗИТСЯ** (собственный вольт slot0 +
  вендор slot1/2, подпись нашим ключом, FNP-установленный) — dev id 1019,
  `q` == образу, порт Active/100: boot-гейт пускает образ с полностью
  нашим сиг-блоком. Оговорка-Exp-ROM: warning «FW is for device 4121, but
  Exp-ROM is for device 4119» (база собрана под CX-5 0x1017, FW — под
  CX-5 Ex 0x1019) — буту/линку не мешает, PXE/UEFI Exp-ROM не проверялись.
